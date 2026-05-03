use crate::api::{ApiClient, VerifyRequest};
use crate::commands::audit::{self, record_audit_event, AuditAction};
use crate::crypto;
use crate::vault::VaultItem;
use crate::{normalize_server_url, AppState};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{AppHandle, State};
use vela_crypto::aead::{decrypt, encrypt};
use vela_crypto::oram::CHUNK_SIZE;

const LEGACY_VAULT_MAIN_CHUNK_ID: &str = "vault-main";
const VAULT_CHUNK_PREFIX: &str = "vault-data-";
const VAULT_CHUNK_PLAINTEXT_SIZE: usize = CHUNK_SIZE - 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub syncing: bool,
    pub last_synced: Option<DateTime<Utc>>,
    pub conflicts: Vec<ConflictItem>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictItem {
    pub item_id: String,
    pub local_version: VaultItem,
    pub server_version: VaultItem,
    pub conflict_detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalSyncMeta {
    chunks: HashMap<String, LocalChunkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalChunkMeta {
    version: i64,
    lamport_clock: i64,
}

fn load_local_sync_meta(state: &AppState) -> LocalSyncMeta {
    let meta_path = state.store.store_path().join("sync_meta.json");
    if let Ok(json) = std::fs::read_to_string(&meta_path) {
        if let Ok(meta) = serde_json::from_str::<LocalSyncMeta>(&json) {
            return meta;
        }
    }
    LocalSyncMeta {
        chunks: HashMap::new(),
    }
}

fn save_local_sync_meta(state: &AppState, meta: &LocalSyncMeta) -> Result<(), String> {
    let store = &state.store;
    let meta_path = store.store_path().join("sync_meta.json");
    let json = serde_json::to_string(meta).map_err(|e| e.to_string())?;
    std::fs::write(meta_path, json).map_err(|e| e.to_string())?;
    Ok(())
}

fn chunk_key_bytes(state: &AppState, chunk_id: &str) -> Result<[u8; 32], String> {
    let crypto_guard = state.crypto.read();
    let crypto = crypto_guard
        .as_ref()
        .ok_or_else(|| "Crypto not initialized".to_string())?;
    Ok(*crypto.chunk_key(chunk_id.as_bytes()).as_bytes())
}

fn log_sync_audit(state: &AppState, chunk_count: usize) {
    record_audit_event(state, AuditAction::VaultSync { chunk_count });
}

fn get_device_name() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Mac".to_string())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Desktop".to_string())
    }
}

async fn authenticate_for_sync(
    state: &AppState,
    client: &ApiClient,
    device_id: &str,
) -> Result<String, String> {
    let identity_keys = state
        .store
        .load_identity_keys()
        .map_err(|e| format!("Failed to load identity keys: {e}"))?
        .ok_or_else(|| {
            "No server identity keys found. Re-enroll this vault or create it with a server URL configured.".to_string()
        })?;

    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|e| format!("Invalid challenge format: {e}"))?;

    let (proof, committed_hash) = crypto::create_auth_proof(
        &identity_keys.cyclo_pk,
        &identity_keys.cyclo_sk,
        &challenge_bytes,
        device_id,
    )
    .map_err(|e| format!("Failed to create auth proof: {e}"))?;

    let verify_resp = client
        .verify_proof(&VerifyRequest {
            device_id: device_id.to_string(),
            challenge: challenge_resp.challenge,
            committed_hash,
            proof,
            device_name: Some(get_device_name()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Failed to verify proof: {e}"))?;

    state
        .store
        .save_device_id_with_user_id(device_id, &verify_resp.user_id)
        .map_err(|e| format!("Failed to save server user ID: {e}"))?;
    {
        let mut session = state.session.write();
        session.user_id = Some(verify_resp.user_id);
        session.set_server_token(verify_resp.token.clone());
    }

    Ok(verify_resp.token)
}

/// How long tombstones are retained before pruning.
const TOMBSTONE_RETENTION_DAYS: i64 = 30;

/// Merge server vault into the local vault, honouring tombstones so that
/// deletions propagate across devices.
fn merge_server_vaults(
    local: &mut crate::vault::VaultStore,
    server: crate::vault::VaultStore,
    device_id: &str,
) -> Vec<ConflictItem> {
    use crate::vault::Tombstone;

    let mut conflicts = Vec::new();

    // ── 1. Build the set of all tombstoned IDs (both sides) ────────────────
    let mut tombstone_map: HashMap<String, DateTime<Utc>> = HashMap::new();
    for t in &local.tombstones {
        tombstone_map.insert(t.id.clone(), t.deleted_at);
    }
    for t in &server.tombstones {
        tombstone_map
            .entry(t.id.clone())
            .and_modify(|d| *d = (*d).max(t.deleted_at))
            .or_insert(t.deleted_at);
    }
    // ── 2. Detect conflicts for items that exist on both sides ──────────────
    let server_map: HashMap<String, crate::vault::VaultItem> = server
        .items
        .into_iter()
        .map(|item| (item.id().to_string(), item))
        .collect();

    for local_item in &local.items {
        let id = local_item.id().to_string();
        if let Some(server_item) = server_map.get(&id) {
            let local_updated = local_item.updated_at();
            let server_updated = server_item.updated_at();

            if server_updated > local_updated {
                let local_modified = local_item.last_modified_device();
                if local_modified.is_some() && local_modified != Some(device_id) {
                    conflicts.push(ConflictItem {
                        item_id: id.clone(),
                        local_version: local_item.clone(),
                        server_version: server_item.clone(),
                        conflict_detected_at: Utc::now(),
                    });
                }
            }
        }
    }

    // ── 3. Merge items, filtering out tombstoned IDs ───────────────────────
    let mut final_items: HashMap<String, crate::vault::VaultItem> = local
        .items
        .drain(..)
        .filter(|item| {
            tombstone_map
                .get(item.id())
                .map(|deleted_at| *deleted_at >= item.updated_at())
                .unwrap_or(false)
                == false
        })
        .map(|item| (item.id().to_string(), item))
        .collect();

    for (id, server_item) in server_map {
        if tombstone_map
            .get(&id)
            .map(|deleted_at| *deleted_at >= server_item.updated_at())
            .unwrap_or(false)
        {
            continue; // deleted item stays deleted
        }
        if let Some(existing) = final_items.get(&id) {
            if server_item.updated_at() > existing.updated_at() {
                final_items.insert(id, server_item);
            }
        } else {
            final_items.insert(id, server_item);
        }
    }

    local.items = final_items.into_values().collect();

    // ── 4. Merge tombstones, keeping newest timestamp per ID ────────────────
    let mut merged_tombstones: HashMap<String, Tombstone> = HashMap::new();
    for t in local.tombstones.drain(..) {
        merged_tombstones.insert(t.id.clone(), t);
    }
    for t in server.tombstones {
        merged_tombstones
            .entry(t.id.clone())
            .and_modify(|existing| {
                if t.deleted_at > existing.deleted_at {
                    *existing = t.clone();
                }
            })
            .or_insert(t);
    }
    local.tombstones = merged_tombstones.into_values().collect();

    // ── 5. Prune old tombstones to prevent unbounded growth ────────────────
    local.prune_tombstones(chrono::Duration::days(TOMBSTONE_RETENTION_DAYS));

    conflicts
}

fn is_vault_data_chunk(chunk_id: &str) -> bool {
    chunk_id.starts_with(VAULT_CHUNK_PREFIX)
}

fn vault_chunk_id(index: usize) -> String {
    format!("{VAULT_CHUNK_PREFIX}{index:06}")
}

fn ordered_vault_chunk_ids(manifest: &crate::api::SyncManifest) -> Vec<String> {
    let mut ids: Vec<String> = manifest
        .chunks
        .iter()
        .filter(|entry| is_vault_data_chunk(&entry.chunk_id))
        .map(|entry| entry.chunk_id.clone())
        .collect();
    ids.sort();
    ids
}

fn manifest_versions(manifest: &crate::api::SyncManifest) -> HashMap<String, LocalChunkMeta> {
    manifest
        .chunks
        .iter()
        .map(|entry| {
            (
                entry.chunk_id.clone(),
                LocalChunkMeta {
                    version: entry.version,
                    lamport_clock: entry.lamport_clock,
                },
            )
        })
        .collect()
}

fn split_plaintext_chunks(plaintext: &[u8]) -> Vec<Vec<u8>> {
    if plaintext.is_empty() {
        return vec![Vec::new()];
    }

    plaintext
        .chunks(VAULT_CHUNK_PLAINTEXT_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect()
}

fn save_conflicts(state: &AppState, conflicts: &[ConflictItem]) -> Result<(), String> {
    let conflicts_path = state.store.store_path().join("sync_conflicts.json");
    if conflicts.is_empty() {
        if conflicts_path.exists() {
            let _ = std::fs::remove_file(conflicts_path);
        }
        return Ok(());
    }

    let json = serde_json::to_string(conflicts).map_err(|e| e.to_string())?;
    std::fs::write(conflicts_path, json).map_err(|e| e.to_string())
}

async fn download_vault_from_manifest(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    manifest: &crate::api::SyncManifest,
) -> Result<Option<(crate::vault::VaultStore, i64)>, String> {
    let ids = ordered_vault_chunk_ids(manifest);
    let ids = if ids.is_empty()
        && manifest
            .chunks
            .iter()
            .any(|entry| entry.chunk_id == LEGACY_VAULT_MAIN_CHUNK_ID)
    {
        vec![LEGACY_VAULT_MAIN_CHUNK_ID.to_string()]
    } else {
        ids
    };

    if ids.is_empty() {
        return Ok(None);
    }

    let mut plaintext = Vec::new();
    let mut max_lamport = 0;

    for chunk_id in ids {
        let key = chunk_key_bytes(state, &chunk_id)?;
        let (ciphertext, _version, lamport, new_tok) = client
            .get_chunk(token, &chunk_id)
            .await
            .map_err(|e| format!("Failed to download chunk {chunk_id}: {e}"))?;
        if let Some(t) = new_tok {
            *token = t;
        }
        max_lamport = max_lamport.max(lamport);
        let mut chunk = decrypt(&key, &ciphertext)
            .map_err(|e| format!("Failed to decrypt chunk {chunk_id}: {e}"))?;
        plaintext.append(&mut chunk);
    }

    let vault: crate::vault::VaultStore = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Failed to deserialize synced vault: {e}"))?;
    Ok(Some((vault, max_lamport)))
}

async fn upload_vault_chunks(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    manifest: &crate::api::SyncManifest,
    local_meta: &mut LocalSyncMeta,
    plaintext: &[u8],
    base_lamport: i64,
) -> Result<usize, String> {
    let chunks = split_plaintext_chunks(plaintext);
    let manifest_meta = manifest_versions(manifest);
    let mut next_meta = HashMap::new();
    let mut lamport = base_lamport;

    for (idx, chunk) in chunks.iter().enumerate() {
        let chunk_id = vault_chunk_id(idx);
        let version = manifest_meta.get(&chunk_id).map(|m| m.version).unwrap_or(0);
        let previous_lamport = manifest_meta
            .get(&chunk_id)
            .map(|m| m.lamport_clock)
            .or_else(|| local_meta.chunks.get(&chunk_id).map(|m| m.lamport_clock))
            .unwrap_or(0);
        lamport = lamport.max(previous_lamport) + 1;

        let key = chunk_key_bytes(state, &chunk_id)?;
        let ciphertext =
            encrypt(&key, chunk).map_err(|e| format!("Failed to encrypt chunk {chunk_id}: {e}"))?;

        let (new_version, new_tok) = client
            .put_chunk(token, &chunk_id, version, ciphertext, lamport)
            .await
            .map_err(|e| format!("Failed to upload chunk {chunk_id}: {e}"))?;
        if let Some(t) = new_tok {
            *token = t;
        }

        next_meta.insert(
            chunk_id,
            LocalChunkMeta {
                version: new_version,
                lamport_clock: lamport,
            },
        );
    }

    for entry in manifest
        .chunks
        .iter()
        .filter(|entry| is_vault_data_chunk(&entry.chunk_id))
    {
        let Some(index_str) = entry.chunk_id.strip_prefix(VAULT_CHUNK_PREFIX) else {
            continue;
        };
        let Ok(index) = index_str.parse::<usize>() else {
            continue;
        };
        if index < chunks.len() {
            continue;
        }
        match client
            .delete_chunk(token, &entry.chunk_id, entry.version)
            .await
        {
            Ok(new_tok) => {
                if let Some(t) = new_tok {
                    *token = t;
                }
            }
            Err(e) => tracing::warn!(
                "Failed to delete stale sync chunk {}: {}",
                entry.chunk_id,
                e
            ),
        }
    }

    local_meta.chunks = next_meta;
    Ok(chunks.len())
}

async fn sync_audit_chunk(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    manifest: &crate::api::SyncManifest,
) {
    let Some(plaintext) = audit::serialize_audit_plaintext(state) else {
        return;
    };

    if let Some(entry) = manifest
        .chunks
        .iter()
        .find(|entry| entry.chunk_id == audit::AUDIT_CHUNK_ID)
    {
        if let Ok(key) = chunk_key_bytes(state, audit::AUDIT_CHUNK_ID) {
            match client.get_chunk(token, audit::AUDIT_CHUNK_ID).await {
                Ok((ciphertext, _, _, new_tok)) => {
                    if let Some(t) = new_tok {
                        *token = t;
                    }
                    if let Ok(server_plaintext) = decrypt(&key, &ciphertext) {
                        let _ = audit::replace_audit_from_plaintext(state, &server_plaintext);
                    }
                }
                Err(e) => tracing::warn!("Failed to pull audit chunk: {}", e),
            }
        }

        if let Ok(key) = chunk_key_bytes(state, audit::AUDIT_CHUNK_ID) {
            if let Some(updated_plaintext) = audit::serialize_audit_plaintext(state) {
                match encrypt(&key, &updated_plaintext) {
                    Ok(ciphertext) => {
                        let _ = client
                            .put_chunk(
                                token,
                                audit::AUDIT_CHUNK_ID,
                                entry.version,
                                ciphertext,
                                entry.lamport_clock + 1,
                            )
                            .await
                            .map(|(_, new_tok)| {
                                if let Some(t) = new_tok {
                                    *token = t;
                                }
                            })
                            .map_err(|e| tracing::warn!("Failed to push audit chunk: {}", e));
                    }
                    Err(e) => tracing::warn!("Failed to encrypt audit chunk: {}", e),
                }
            }
        }
    } else if let Ok(key) = chunk_key_bytes(state, audit::AUDIT_CHUNK_ID) {
        match encrypt(&key, &plaintext) {
            Ok(ciphertext) => {
                let _ = client
                    .put_chunk(token, audit::AUDIT_CHUNK_ID, 0, ciphertext, 1)
                    .await
                    .map(|(_, new_tok)| {
                        if let Some(t) = new_tok {
                            *token = t;
                        }
                    })
                    .map_err(|e| tracing::warn!("Failed to create audit chunk: {}", e));
            }
            Err(e) => tracing::warn!("Failed to encrypt audit chunk: {}", e),
        }
    }
}

#[tauri::command]
pub async fn trigger_sync(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<SyncStatus, String> {
    let session_active = {
        let session = state.session.read();
        session.active
    };

    if !session_active {
        return Err("Session not active".to_string());
    }

    {
        let mut session = state.session.write();
        session.refresh();
    }

    let device_id = {
        let session = state.session.read();
        session.get_device_id().unwrap_or("unknown").to_string()
    };

    let server_url = normalize_server_url(&state.server_url.read());
    if server_url.is_empty() {
        return Ok(SyncStatus {
            syncing: false,
            last_synced: None,
            conflicts: vec![],
            error: Some("No server URL configured. Add one in Settings to enable sync.".into()),
        });
    }

    let client = ApiClient::with_url(server_url);

    let mut token = match state.get_session_token() {
        Some(token) => token,
        None => match authenticate_for_sync(&state, &client, &device_id).await {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!("Sync: server authentication failed: {}", e);
                return Ok(SyncStatus {
                    syncing: false,
                    last_synced: None,
                    conflicts: vec![],
                    error: Some(format!("Server authentication failed: {e}")),
                });
            }
        },
    };

    let manifest = match client.get_sync_manifest(&token).await {
        Ok((m, new_tok)) => {
            if let Some(t) = new_tok {
                state.session.write().set_server_token(t.clone());
                token = t;
            }
            m
        }
        Err(e) => {
            tracing::warn!("Sync: server unavailable, using local vault: {}", e);
            return Ok(SyncStatus {
                syncing: false,
                last_synced: Some(Utc::now()),
                conflicts: vec![],
                error: Some(format!(
                    "Server unavailable: {}. Using local vault only.",
                    e
                )),
            });
        }
    };

    let mut merged_conflicts: Vec<ConflictItem> = Vec::new();
    let mut max_server_lamport = 0;

    if let Some((server_vault, server_lamport)) =
        download_vault_from_manifest(&state, &client, &mut token, &manifest).await?
    {
        max_server_lamport = max_server_lamport.max(server_lamport);
        let mut local_vault = {
            let vault = state.vault.read();
            vault.clone()
        };

        let conflicts = merge_server_vaults(&mut local_vault, server_vault, &device_id);
        merged_conflicts.extend(conflicts);

        {
            let mut vault = state.vault.write();
            *vault = local_vault;
        }

        {
            let crypto_guard = state.crypto.read();
            if let Some(crypto) = crypto_guard.as_ref() {
                let vault_snapshot = state.vault.read().clone();
                let _ = state.store.save_vault(&vault_snapshot, crypto);
            }
        }
    }

    let mut current_meta = load_local_sync_meta(&state);
    let local_vault_snapshot = state.vault.read().clone();
    let local_count = local_vault_snapshot.items.len();

    // Safety guard: never upload an empty vault when the server has data.
    // This prevents overwriting server vault with empty data in the rare case
    // where the local vault is corrupt but sync metadata is stale.
    if local_count == 0 && !current_meta.chunks.is_empty() {
        tracing::warn!(
            "Sync: refusing to upload empty vault (sync meta has {} chunks). \
             Server data may be intact — re-sync or re-enroll to recover.",
            current_meta.chunks.len()
        );
        return Ok(SyncStatus {
            syncing: false,
            last_synced: Some(Utc::now()),
            conflicts: merged_conflicts,
            error: Some(
                "Local vault is empty but server may have data. \
                         Please re-enroll or trigger a force-pull to recover."
                    .into(),
            ),
        });
    }

    let plaintext = serde_json::to_vec(&local_vault_snapshot)
        .map_err(|e| format!("Failed to serialize vault: {}", e))?;

    tracing::info!(
        "Sync: uploading vault as chunked trivial ORAM payload ({} bytes)",
        plaintext.len()
    );

    let uploaded_chunks = match upload_vault_chunks(
        &state,
        &client,
        &mut token,
        &manifest,
        &mut current_meta,
        &plaintext,
        max_server_lamport,
    )
    .await
    {
        Ok(count) => {
            save_local_sync_meta(&state, &current_meta)?;
            count
        }
        Err(e) => {
            tracing::error!("Sync: failed to upload vault chunks: {}", e);
            return Ok(SyncStatus {
                syncing: false,
                last_synced: Some(Utc::now()),
                conflicts: merged_conflicts,
                error: Some(format!("Upload failed: {}", e)),
            });
        }
    };

    save_conflicts(&state, &merged_conflicts)?;
    log_sync_audit(&state, uploaded_chunks);
    let _ = crate::commands::sharing::refresh_linked_shares_inner(&state).await;
    sync_audit_chunk(&state, &client, &mut token, &manifest).await;
    state.session.write().set_server_token(token);

    tracing::info!(
        "Sync complete: {} items, {} uploaded chunks, {} conflicts",
        state.vault.read().items.len(),
        uploaded_chunks,
        merged_conflicts.len()
    );

    crate::commands::vault::emit_vault_items_changed(&app);

    Ok(SyncStatus {
        syncing: false,
        last_synced: Some(Utc::now()),
        conflicts: merged_conflicts,
        error: None,
    })
}

#[tauri::command]
pub async fn get_sync_status(state: State<'_, Arc<AppState>>) -> Result<SyncStatus, String> {
    let meta = load_local_sync_meta(&state);
    let has_meta = !meta.chunks.is_empty();

    let last_synced_path = state.store.store_path().join("sync_meta.json");
    let last_synced = if has_meta {
        std::fs::metadata(&last_synced_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| DateTime::<Utc>::from(t))
    } else {
        None
    };

    let conflicts_path = state.store.store_path().join("sync_conflicts.json");
    let conflicts: Vec<ConflictItem> = if conflicts_path.exists() {
        std::fs::read_to_string(&conflicts_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    } else {
        vec![]
    };

    Ok(SyncStatus {
        syncing: false,
        last_synced,
        conflicts,
        error: None,
    })
}

#[tauri::command]
pub async fn resolve_conflict(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item_id: String,
    use_local: bool,
) -> Result<(), String> {
    if use_local {
        tracing::info!(
            "Conflict resolved for item {}: keeping local version",
            item_id
        );
    } else {
        let server_url = state.server_url.read().clone();
        let client = ApiClient::with_url(server_url);

        let mut token = state
            .get_session_token()
            .ok_or("No session token available")?;

        let (manifest, new_tok) = client
            .get_sync_manifest(&token)
            .await
            .map_err(|e| format!("Failed to fetch sync manifest: {}", e))?;
        if let Some(t) = new_tok {
            token = t;
        }
        let Some((server_vault, _)) =
            download_vault_from_manifest(&state, &client, &mut token, &manifest).await?
        else {
            return Err("Server vault is empty".to_string());
        };
        state.session.write().set_server_token(token);

        if let Some(server_item) = server_vault.items.iter().find(|i| i.id() == item_id) {
            let mut vault = state.vault.write();
            if let Some(local_item) = vault.items.iter_mut().find(|i| i.id() == item_id) {
                let resolved = server_item.clone().with_updated_at(Utc::now());
                *local_item = resolved;
            } else {
                vault.items.push(server_item.clone());
            }
            drop(vault);

            let crypto_guard = state.crypto.read();
            if let Some(crypto) = crypto_guard.as_ref() {
                let _ = state.store.save_vault(&state.vault.read(), crypto);
            }
            drop(crypto_guard);
        }

        tracing::info!(
            "Conflict resolved for item {}: using server version",
            item_id
        );
    }

    let conflicts_path = state.store.store_path().join("sync_conflicts.json");
    let mut conflicts: Vec<ConflictItem> = if conflicts_path.exists() {
        std::fs::read_to_string(&conflicts_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    } else {
        vec![]
    };
    conflicts.retain(|conflict| conflict.item_id.as_str() != item_id);

    if !conflicts.is_empty() {
        let json = serde_json::to_string(&conflicts).map_err(|e| e.to_string())?;
        std::fs::write(&conflicts_path, json).map_err(|e| e.to_string())?;
    } else if conflicts_path.exists() {
        let _ = std::fs::remove_file(&conflicts_path);
    }

    crate::commands::vault::emit_vault_items_changed(&app);

    Ok(())
}

#[tauri::command]
pub async fn set_server_url(state: State<'_, Arc<AppState>>, url: String) -> Result<(), String> {
    let url = normalize_server_url(&url);
    {
        let mut server_url = state.server_url.write();
        *server_url = url.clone();
    }
    if let Ok(mut settings) = state.store.load_settings() {
        settings.server_url = url;
        let _ = state.store.save_settings(&settings);
    }
    Ok(())
}
