use crate::api::ApiClient;
use crate::AppState;
use crate::commands::audit::{AuditAction, record_audit_event};
use crate::vault::VaultItem;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::State;
use vela_crypto::aead::{decrypt, encrypt};

const VAULT_MAIN_CHUNK_ID: &str = "vault-main";
const VAULT_DATA_PREFIX: &str = "vault-data-";

/// Resolve the vault chunk ID from the sync manifest.
/// Returns `"vault-main"` if present (backward-compatible),
/// otherwise falls back to the first chunk with a `"vault-data-"` prefix.
fn resolve_vault_chunk_id(manifest: &crate::api::SyncManifest) -> Option<String> {
    // Prefer the canonical name.
    if manifest.chunks.iter().any(|c| c.chunk_id == VAULT_MAIN_CHUNK_ID) {
        return Some(VAULT_MAIN_CHUNK_ID.to_string());
    }
    // Fall back to the first ORAM-style vault-data-* chunk.
    manifest
        .chunks
        .iter()
        .find(|c| c.chunk_id.starts_with(VAULT_DATA_PREFIX))
        .map(|c| c.chunk_id.clone())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub syncing: bool,
    pub last_synced: Option<DateTime<Utc>>,
    pub conflicts: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictItem {
    pub item_id: String,
    pub local_version: serde_json::Value,
    pub server_version: serde_json::Value,
    pub conflict_detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalSyncMeta {
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
    LocalSyncMeta { version: 0, lamport_clock: 0 }
}

fn save_local_sync_meta(state: &AppState, meta: &LocalSyncMeta) -> Result<(), String> {
    let store = &state.store;
    let meta_path = store.store_path().join("sync_meta.json");
    let json = serde_json::to_string(meta).map_err(|e| e.to_string())?;
    std::fs::write(meta_path, json).map_err(|e| e.to_string())?;
    Ok(())
}

fn log_sync_audit(state: &AppState, chunk_count: usize) {
    record_audit_event(state, AuditAction::VaultSync { chunk_count });
}

/// How long tombstones are retained before pruning.
const TOMBSTONE_RETENTION_DAYS: i64 = 30;

/// Merge server vault into the local vault, honouring tombstones so that
/// deletions propagate across devices.
fn merge_server_vaults(
    local: &mut crate::vault::VaultStore,
    server: crate::vault::VaultStore,
    device_id: &str,
) -> Vec<String> {
    use crate::vault::Tombstone;
    use std::collections::HashSet;

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
    let tombstoned_ids: HashSet<String> = tombstone_map.keys().cloned().collect();

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
                    conflicts.push(id.clone());
                }
            }
        }
    }

    // ── 3. Merge items, filtering out tombstoned IDs ───────────────────────
    let mut final_items: HashMap<String, crate::vault::VaultItem> = local
        .items
        .drain(..)
        .filter(|item| !tombstoned_ids.contains(item.id()))
        .map(|item| (item.id().to_string(), item))
        .collect();

    for (id, server_item) in server_map {
        if tombstoned_ids.contains(&id) {
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

#[tauri::command]
pub async fn trigger_sync(state: State<'_, Arc<AppState>>) -> Result<SyncStatus, String> {
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

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let mut token = state.get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let local_meta = load_local_sync_meta(&state);

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
                error: Some(format!("Server unavailable: {}. Using local vault only.", e)),
            });
        }
    };

    let vault_chunk_id = resolve_vault_chunk_id(&manifest)
        .unwrap_or_else(|| VAULT_MAIN_CHUNK_ID.to_string());

    let chunk_key_bytes: [u8; 32] = {
        let crypto_guard = state.crypto.read();
        let crypto = crypto_guard.as_ref().ok_or_else(|| "Crypto not initialized".to_string())?;
        *crypto.chunk_key(vault_chunk_id.as_bytes()).as_bytes()
    };

    tracing::info!(
        "Sync: using vault chunk '{}', manifest has {} chunks",
        vault_chunk_id,
        manifest.chunks.len()
    );

    let mut merged_conflicts: Vec<String> = Vec::new();

    for entry in &manifest.chunks {
        if entry.chunk_id != vault_chunk_id {
            continue;
        }

        if entry.version <= local_meta.version {
            let local_count = { state.vault.read().items.len() };
            // Heuristic: if the local vault is empty but the sync metadata says
            // we are up-to-date, the local state is likely corrupt (e.g. after a
            // failed enrollment import).  Force a download to recover.
            if local_count == 0 && entry.version > 0 {
                tracing::warn!(
                    "Sync: local vault is empty but meta v{} >= server v{} — forcing download",
                    local_meta.version,
                    entry.version
                );
                // Fall through to download below.
            } else {
                tracing::info!(
                    "Sync: skipping download chunk {} (server v{} <= local v{}, local has {} items)",
                    entry.chunk_id,
                    entry.version,
                    local_meta.version,
                    local_count
                );
                continue;
            }
        }

        tracing::info!(
            "Sync: downloading chunk {} (server v{}, local v{})",
            entry.chunk_id,
            entry.version,
            local_meta.version
        );

        let (ciphertext, server_version, server_lamport) = match client.get_chunk(&token, &entry.chunk_id).await {
            Ok((data, version, lamport, new_tok)) => {
                if let Some(t) = new_tok {
                    state.session.write().set_server_token(t.clone());
                    token = t;
                }
                (data, version, lamport)
            }
            Err(e) => {
                tracing::error!("Sync: failed to download chunk {}: {}", entry.chunk_id, e);
                continue;
            }
        };

        let plaintext = match decrypt(&chunk_key_bytes, &ciphertext) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Sync: failed to decrypt chunk {}: {}", entry.chunk_id, e);
                continue;
            }
        };

        let server_vault: crate::vault::VaultStore = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Sync: failed to deserialize chunk {}: {}", entry.chunk_id, e);
                continue;
            }
        };

        let server_item_count = server_vault.items.len();
        let server_tombstone_count = server_vault.tombstones.len();

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

        tracing::info!(
            "Sync: merged chunk {} (v{}, lamport {}, {} server items → {} local items)",
            entry.chunk_id,
            server_version,
            server_lamport,
            server_item_count,
            state.vault.read().items.len()
        );

        let new_lamport = local_meta.lamport_clock.max(server_lamport) + 1;
        let updated_meta = LocalSyncMeta {
            version: server_version,
            lamport_clock: new_lamport,
        };
        save_local_sync_meta(&state, &updated_meta)?;

        let crypto_guard = state.crypto.read();
        if let Some(crypto) = crypto_guard.as_ref() {
            let vault_snapshot = state.vault.read().clone();
            let _ = state.store.save_vault(&vault_snapshot, crypto);
        }
        drop(crypto_guard);

        tracing::info!(
            "Sync: merged chunk {} (v{}, lamport {})",
            entry.chunk_id,
            server_version,
            new_lamport
        );
    }

    let current_meta = load_local_sync_meta(&state);

    let local_vault_snapshot = state.vault.read().clone();
    let local_count = local_vault_snapshot.items.len();

    // Safety guard: never upload an empty vault when the server has data.
    // This prevents overwriting server vault with empty data in the rare case
    // where the local vault is corrupt but sync metadata is stale.
    if local_count == 0 && current_meta.version > 0 {
        tracing::warn!(
            "Sync: refusing to upload empty vault (meta v{} > 0). \
             Server data may be intact — re-sync or re-enroll to recover.",
            current_meta.version
        );
        return Ok(SyncStatus {
            syncing: false,
            last_synced: Some(Utc::now()),
            conflicts: merged_conflicts,
            error: Some("Local vault is empty but server may have data. \
                         Please re-enroll or trigger a force-pull to recover.".into()),
        });
    }

    let plaintext = serde_json::to_vec(&local_vault_snapshot)
        .map_err(|e| format!("Failed to serialize vault: {}", e))?;

    let ciphertext = encrypt(&chunk_key_bytes, &plaintext)
        .map_err(|e| format!("Failed to encrypt vault chunk: {}", e))?;

    let new_lamport = current_meta.lamport_clock + 1;

    tracing::info!(
        "Sync: uploading chunk '{}' ({} bytes, {} items, version {}, lamport {})",
        vault_chunk_id,
        ciphertext.len(),
        local_count,
        current_meta.version,
        new_lamport
    );

    let upload_result = client.put_chunk(&token, &vault_chunk_id, current_meta.version, ciphertext, new_lamport).await;

    match upload_result {
        Ok((new_version, new_tok)) => {
            if let Some(t) = new_tok {
                state.session.write().set_server_token(t);
            }
            let updated_meta = LocalSyncMeta {
                version: new_version,
                lamport_clock: new_lamport,
            };
            save_local_sync_meta(&state, &updated_meta)?;

            tracing::info!("Sync: uploaded chunk '{}', new version {}", vault_chunk_id, new_version);
        }
        Err(e) => {
            let err_msg = e.to_string();
            tracing::warn!("Sync: upload failed ({}), re-fetching server vault and retrying", err_msg);

            // Re-fetch manifest and force-download server vault to reconcile.
            let manifest2 = match client.get_sync_manifest(&token).await {
                Ok((m, new_tok)) => {
                    if let Some(t) = new_tok {
                        state.session.write().set_server_token(t.clone());
                        token = t;
                    }
                    m
                }
                Err(e2) => {
                    tracing::error!("Sync: re-fetch manifest failed: {}", e2);
                    return Ok(SyncStatus {
                        syncing: false,
                        last_synced: Some(Utc::now()),
                        conflicts: merged_conflicts.clone(),
                        error: Some(format!("Upload failed: {}. Re-fetch also failed: {}", err_msg, e2)),
                    });
                }
            };

            tracing::info!(
                "Sync: re-fetched manifest with {} chunks: {:?}",
                manifest2.chunks.len(),
                manifest2.chunks.iter().map(|c| &c.chunk_id).collect::<Vec<_>>()
            );

            let mut remerged = false;
            for entry in &manifest2.chunks {
                if entry.chunk_id != vault_chunk_id {
                    tracing::info!(
                        "Sync: skipping chunk {} != {} in retry merge",
                        entry.chunk_id, vault_chunk_id
                    );
                    continue;
                }

                tracing::info!(
                    "Sync: force-downloading chunk {} (server v{}) for retry",
                    entry.chunk_id,
                    entry.version
                );

                let (ciphertext2, server_version, server_lamport) = match client.get_chunk(&token, &entry.chunk_id).await {
                    Ok((data, version, lamport, new_tok)) => {
                        if let Some(t) = new_tok {
                            state.session.write().set_server_token(t.clone());
                            token = t;
                        }
                        (data, version, lamport)
                    }
                    Err(e2) => {
                        tracing::error!("Sync: re-download failed: {}", e2);
                        return Ok(SyncStatus {
                            syncing: false,
                            last_synced: Some(Utc::now()),
                            conflicts: merged_conflicts.clone(),
                            error: Some(format!("Upload failed: {}. Re-download also failed: {}", err_msg, e2)),
                        });
                    }
                };

                let plaintext2 = match decrypt(&chunk_key_bytes, &ciphertext2) {
                    Ok(p) => p,
                    Err(e2) => {
                        tracing::error!("Sync: re-decrypt failed: {}", e2);
                        return Ok(SyncStatus {
                            syncing: false,
                            last_synced: Some(Utc::now()),
                            conflicts: merged_conflicts.clone(),
                            error: Some(format!("Upload failed: {}. Re-decrypt also failed: {}", err_msg, e2)),
                        });
                    }
                };

                let server_vault2: crate::vault::VaultStore = match serde_json::from_slice(&plaintext2) {
                    Ok(v) => v,
                    Err(e2) => {
                        tracing::error!("Sync: re-deserialize failed: {}", e2);
                        return Ok(SyncStatus {
                            syncing: false,
                            last_synced: Some(Utc::now()),
                            conflicts: merged_conflicts.clone(),
                            error: Some(format!("Upload failed: {}. Re-deserialize also failed: {}", err_msg, e2)),
                        });
                    }
                };

                let server_item_count2 = server_vault2.items.len();
                tracing::info!(
                    "Sync: re-downloaded chunk {} (v{}, {} server items, {} tombstones)",
                    entry.chunk_id,
                    server_version,
                    server_item_count2,
                    server_vault2.tombstones.len()
                );

                let mut local_vault2 = {
                    let vault = state.vault.read();
                    vault.clone()
                };

                let conflicts2 = merge_server_vaults(&mut local_vault2, server_vault2, &device_id);
                merged_conflicts.extend(conflicts2);

                {
                    let mut vault = state.vault.write();
                    *vault = local_vault2;
                }

                let new_lamport2 = current_meta.lamport_clock.max(server_lamport) + 1;
                let updated_meta = LocalSyncMeta {
                    version: server_version,
                    lamport_clock: new_lamport2,
                };
                save_local_sync_meta(&state, &updated_meta)?;

                let crypto_guard = state.crypto.read();
                if let Some(crypto) = crypto_guard.as_ref() {
                    let vault_snapshot = state.vault.read().clone();
                    let _ = state.store.save_vault(&vault_snapshot, crypto);
                }
                drop(crypto_guard);

                remerged = true;
                tracing::info!(
                    "Sync: re-merged chunk {} (v{}, lamport {})",
                    entry.chunk_id,
                    server_version,
                    new_lamport2
                );
            }

            if !remerged {
                return Ok(SyncStatus {
                    syncing: false,
                    last_synced: Some(Utc::now()),
                    conflicts: merged_conflicts,
                    error: Some(format!("Upload failed: {}. No matching chunk found on server for retry.", err_msg)),
                });
            }

            // Retry upload with the reconciled vault.
            let retry_meta = load_local_sync_meta(&state);
            let retry_vault_snapshot = state.vault.read().clone();
            let retry_count = retry_vault_snapshot.items.len();
            let retry_plaintext = serde_json::to_vec(&retry_vault_snapshot)
                .map_err(|e| format!("Failed to serialize vault: {}", e))?;
            let retry_ciphertext = encrypt(&chunk_key_bytes, &retry_plaintext)
                .map_err(|e| format!("Failed to encrypt vault chunk: {}", e))?;
            let retry_lamport = retry_meta.lamport_clock + 1;

            tracing::info!(
                "Sync: retrying upload chunk '{}' ({} bytes, {} items, version {}, lamport {})",
                vault_chunk_id,
                retry_ciphertext.len(),
                retry_count,
                retry_meta.version,
                retry_lamport
            );

            match client.put_chunk(&token, &vault_chunk_id, retry_meta.version, retry_ciphertext, retry_lamport).await {
                Ok((retry_version, retry_tok)) => {
                    if let Some(t) = retry_tok {
                        state.session.write().set_server_token(t);
                    }
                    let final_meta = LocalSyncMeta {
                        version: retry_version,
                        lamport_clock: retry_lamport,
                    };
                    save_local_sync_meta(&state, &final_meta)?;
                    tracing::info!("Sync: retry upload succeeded, new version {}", retry_version);
                }
                Err(e2) => {
                    tracing::error!("Sync: retry upload also failed: {}", e2);
                    return Ok(SyncStatus {
                        syncing: false,
                        last_synced: Some(Utc::now()),
                        conflicts: merged_conflicts,
                        error: Some(format!("Upload failed after retry: {}", e2)),
                    });
                }
            }
        }
    }

    let crypto_guard = state.crypto.read();
    if let Some(crypto) = crypto_guard.as_ref() {
        let vault_snapshot = state.vault.read().clone();
        let _ = state.store.save_vault(&vault_snapshot, crypto);
    }
    drop(crypto_guard);

    log_sync_audit(&state, manifest.chunks.len());

    tracing::info!(
        "Sync complete: {} items, {} server chunks, {} conflicts",
        state.vault.read().items.len(),
        manifest.chunks.len(),
        merged_conflicts.len()
    );

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
    let has_meta = meta.version > 0;

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
    let conflicts: Vec<String> = if conflicts_path.exists() {
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
    state: State<'_, Arc<AppState>>,
    item_id: String,
    use_local: bool,
) -> Result<(), String> {
    if use_local {
        tracing::info!("Conflict resolved for item {}: keeping local version", item_id);
    } else {
        let session = state.session.read();
        let _device_id = session.get_device_id().unwrap_or("unknown").to_string();
        drop(session);

        let crypto_guard = state.crypto.read();
        let crypto = crypto_guard.as_ref().ok_or("Crypto not initialized")?;
        let _chunk_key_bytes: [u8; 32] = *crypto.chunk_key(VAULT_MAIN_CHUNK_ID.as_bytes()).as_bytes();
        drop(crypto_guard);

        let server_url = state.server_url.read().clone();
        let client = ApiClient::with_url(server_url);

        let token = state.get_session_token()
            .ok_or("No session token available")?;

        let (ciphertext, _version, _lamport, new_tok) = client
            .get_chunk(&token, VAULT_MAIN_CHUNK_ID)
            .await
            .map_err(|e| format!("Failed to download server vault: {}", e))?;
        if let Some(t) = new_tok {
            state.session.write().set_server_token(t);
        }

        let plaintext = decrypt(&_chunk_key_bytes, &ciphertext)
            .map_err(|e| format!("Failed to decrypt server vault: {}", e))?;

        let server_vault: crate::vault::VaultStore = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Failed to deserialize server vault: {}", e))?;

        if let Some(server_item) = server_vault.items.iter().find(|i| i.id() == item_id) {
            let mut vault = state.vault.write();
            if let Some(local_item) = vault.items.iter_mut().find(|i| i.id() == item_id) {
                let resolved = server_item
                    .clone()
                    .with_updated_at(Utc::now());
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

        tracing::info!("Conflict resolved for item {}: using server version", item_id);
    }

    let conflicts_path = state.store.store_path().join("sync_conflicts.json");
    let mut conflicts: Vec<String> = if conflicts_path.exists() {
        std::fs::read_to_string(&conflicts_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    } else {
        vec![]
    };
    conflicts.retain(|id| id != &item_id);

    if !conflicts.is_empty() {
        let json = serde_json::to_string(&conflicts).map_err(|e| e.to_string())?;
        std::fs::write(&conflicts_path, json).map_err(|e| e.to_string())?;
    } else if conflicts_path.exists() {
        let _ = std::fs::remove_file(&conflicts_path);
    }

    Ok(())
}

#[tauri::command]
pub async fn set_server_url(state: State<'_, Arc<AppState>>, url: String) -> Result<(), String> {
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
