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

fn merge_server_items(
    local_items: &mut Vec<VaultItem>,
    server_items: Vec<VaultItem>,
    device_id: &str,
) -> Vec<String> {
    let mut conflicts = Vec::new();
    let mut server_map: HashMap<String, VaultItem> = server_items
        .into_iter()
        .map(|item| (item.id().to_string(), item))
        .collect();

    for local_item in local_items.iter() {
        let id = local_item.id().to_string();
        if let Some(server_item) = server_map.remove(&id) {
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

    let mut final_items: HashMap<String, VaultItem> = local_items
        .drain(..)
        .map(|item| (item.id().to_string(), item))
        .collect();

    for (id, server_item) in server_map {
        if let Some(existing) = final_items.get(&id) {
            if server_item.updated_at() > existing.updated_at() {
                final_items.insert(id, server_item);
            }
        } else {
            final_items.insert(id, server_item);
        }
    }

    *local_items = final_items.into_values().collect();
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

    let _chunk_key_bytes: [u8; 32] = {
        let crypto_guard = state.crypto.read();
        let crypto = crypto_guard.as_ref().ok_or_else(|| "Crypto not initialized".to_string())?;
        let key = *crypto.chunk_key(VAULT_MAIN_CHUNK_ID.as_bytes()).as_bytes();
        key
    };

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let token = state.get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let local_meta = load_local_sync_meta(&state);

    let manifest = match client.get_sync_manifest(&token).await {
        Ok(m) => m,
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

    let mut merged_conflicts: Vec<String> = Vec::new();

    for entry in &manifest.chunks {
        if entry.chunk_id != VAULT_MAIN_CHUNK_ID {
            continue;
        }

        if entry.version <= local_meta.version {
            tracing::info!(
                "Sync: server chunk {} version {} <= local {}, skipping download",
                entry.chunk_id,
                entry.version,
                local_meta.version
            );
            continue;
        }

        tracing::info!(
            "Sync: downloading chunk {} (server version {}, local version {})",
            entry.chunk_id,
            entry.version,
            local_meta.version
        );

        let (ciphertext, server_version, server_lamport) = match client.get_chunk(&token, &entry.chunk_id).await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Sync: failed to download chunk {}: {}", entry.chunk_id, e);
                continue;
            }
        };

        let plaintext = match decrypt(&_chunk_key_bytes, &ciphertext) {
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

        let mut local_items = {
            let vault = state.vault.read();
            vault.items.clone()
        };

        let conflicts = merge_server_items(&mut local_items, server_vault.items, &device_id);
        merged_conflicts.extend(conflicts);

        {
            let mut vault = state.vault.write();
            vault.items = local_items;
        }

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

    let local_items = {
        let vault = state.vault.read();
        vault.items.clone()
    };

    let plaintext = serde_json::to_vec(&crate::vault::VaultStore { items: local_items })
        .map_err(|e| format!("Failed to serialize vault: {}", e))?;

    let ciphertext = encrypt(&_chunk_key_bytes, &plaintext)
        .map_err(|e| format!("Failed to encrypt vault chunk: {}", e))?;

    let new_lamport = current_meta.lamport_clock + 1;

    tracing::info!(
        "Sync: uploading vault-main ({} bytes, version {}, lamport {})",
        ciphertext.len(),
        current_meta.version,
        new_lamport
    );

    match client.put_chunk(&token, VAULT_MAIN_CHUNK_ID, current_meta.version, ciphertext, new_lamport).await {
        Ok(new_version) => {
            let updated_meta = LocalSyncMeta {
                version: new_version,
                lamport_clock: new_lamport,
            };
            save_local_sync_meta(&state, &updated_meta)?;

            tracing::info!("Sync: uploaded vault-main, new version {}", new_version);
        }
        Err(e) => {
            tracing::error!("Sync: failed to upload vault-main: {}", e);
            return Ok(SyncStatus {
                syncing: false,
                last_synced: Some(Utc::now()),
                conflicts: merged_conflicts,
                error: Some(format!("Upload failed: {}", e)),
            });
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

        let (ciphertext, _version, _lamport) = client
            .get_chunk(&token, VAULT_MAIN_CHUNK_ID)
            .await
            .map_err(|e| format!("Failed to download server vault: {}", e))?;

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
    let mut server_url = state.server_url.write();
    *server_url = url;
    Ok(())
}
