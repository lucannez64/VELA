use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, State};
use uuid::Uuid;

use crate::api::ApiClient;
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::AppState;

const SHARES_FILE: &str = "shares.enc";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub id: String,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    pub direction: ShareDirection,
    pub from: String,
    pub to: Option<String>,
    pub shared_at: DateTime<Utc>,
    pub accepted: Option<bool>,
    pub allow_edit: bool,
    pub encrypted_payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ShareDirection {
    Received,
    Sent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendShareRequest {
    pub item_id: String,
    pub recipient: String,
    pub allow_edit: bool,
    pub notify_on_accept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShareStore {
    sent_shares: Vec<Share>,
    received_shares: Vec<Share>,
}

impl Default for ShareStore {
    fn default() -> Self {
        Self {
            sent_shares: Vec::new(),
            received_shares: Vec::new(),
        }
    }
}

impl ShareStore {
    fn add_sent_share(&mut self, share: Share) {
        self.sent_shares.push(share);
    }

    fn add_received_share(&mut self, share: Share) {
        self.received_shares.push(share);
    }

    fn update_share_status(&mut self, share_id: &str, accepted: bool) {
        if let Some(share) = self.received_shares.iter_mut().find(|s| s.id == share_id) {
            share.accepted = Some(accepted);
        }
    }

    fn remove_share(&mut self, share_id: &str) {
        self.sent_shares.retain(|s| s.id != share_id);
        self.received_shares.retain(|s| s.id != share_id);
    }

    fn get_all_shares(&self) -> Vec<Share> {
        let mut all = Vec::with_capacity(self.sent_shares.len() + self.received_shares.len());
        all.extend(self.sent_shares.clone());
        all.extend(self.received_shares.clone());
        all.sort_by(|a, b| b.shared_at.cmp(&a.shared_at));
        all
    }
}

fn load_share_store(state: &AppState) -> Option<ShareStore> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref()?;

    let shares_path = state.store.store_path().join(SHARES_FILE);
    if !shares_path.exists() {
        return Some(ShareStore::default());
    }

    let ciphertext = std::fs::read(&shares_path).ok()?;
    let plaintext = crypto.decrypt_vault(&ciphertext).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

fn save_share_store(state: &AppState, store: &ShareStore) -> Result<(), String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Crypto not initialized")?;

    let plaintext = serde_json::to_vec(store).map_err(|e| e.to_string())?;
    let ciphertext = crypto
        .encrypt_vault(&plaintext)
        .map_err(|e| e.to_string())?;

    let shares_path = state.store.store_path().join(SHARES_FILE);
    std::fs::write(shares_path, ciphertext).map_err(|e| e.to_string())?;

    Ok(())
}

fn current_user_id(state: &AppState) -> String {
    {
        let session = state.session.read();
        if let Some(user_id) = session.get_user_id() {
            return user_id.to_string();
        }
    }
    state
        .store
        .load_user_id()
        .unwrap_or_else(|_| "unknown".to_string())
}

fn sync_received_linked_items(state: &AppState, store: &ShareStore) -> Result<(), String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Crypto not initialized")?;

    let mut vault = state.vault.write();
    let mut changed = false;

    for share in store
        .received_shares
        .iter()
        .filter(|s| s.accepted == Some(true))
    {
        let Some(payload) = &share.encrypted_payload else {
            continue;
        };
        let Ok(decrypted) = crypto.decrypt_vault(payload) else {
            continue;
        };
        let Ok(item) = serde_json::from_slice::<crate::vault::VaultItem>(&decrypted) else {
            continue;
        };

        if let Some(existing) = vault.get_item(&share.item_id).cloned() {
            if item.updated_at() > existing.updated_at() {
                let refreshed = item
                    .with_id(share.item_id.clone())
                    .with_shared_status(true, None);
                vault.update_item(refreshed);
                changed = true;
            }
        }
    }

    drop(vault);
    drop(crypto);

    if changed {
        if let Some(crypto) = state.crypto.read().as_ref() {
            let vault_snapshot = state.vault.read().clone();
            state
                .store
                .save_vault(&vault_snapshot, crypto)
                .map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

pub(crate) async fn push_sent_share_update_inner(
    state: &AppState,
    item: &crate::vault::VaultItem,
) -> Result<(), String> {
    let mut store = load_share_store(state).unwrap_or_default();
    let Some(share) = store
        .sent_shares
        .iter_mut()
        .find(|s| s.item_id == item.id())
    else {
        return Ok(());
    };

    let encrypted_payload = {
        let crypto_guard = state.crypto.read();
        let crypto = crypto_guard.as_ref().ok_or("Session not unlocked")?;
        let item_json = serde_json::to_vec(item).map_err(|e| e.to_string())?;
        crypto
            .encrypt_vault(&item_json)
            .map_err(|e| e.to_string())?
    };

    let token = match state.get_session_token() {
        Some(token) => token,
        None => return Ok(()),
    };
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let capsule_b64 = B64.encode(&encrypted_payload);
    let new_tok = client
        .update_linked_share(&token, &share.id, &capsule_b64)
        .await
        .map_err(|e| format!("Failed to update linked share: {e}"))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }

    share.encrypted_payload = Some(encrypted_payload);
    share.shared_at = Utc::now();
    save_share_store(state, &store)?;
    Ok(())
}

pub(crate) async fn refresh_linked_shares_inner(state: &AppState) -> Result<(), String> {
    let mut store = load_share_store(state).unwrap_or_default();
    let token = match state.get_session_token() {
        Some(token) => token,
        None => return Ok(()),
    };

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let (linked_items, new_tok) = client
        .get_linked_shares(&token)
        .await
        .map_err(|e| format!("Failed to fetch linked shares: {e}"))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }

    let user_id = current_user_id(state);

    for linked in linked_items {
        let payload = B64.decode(&linked.capsule).unwrap_or_default();
        if linked.sender_user_id == user_id {
            if let Some(existing) = store.sent_shares.iter_mut().find(|s| s.id == linked.id) {
                existing.encrypted_payload = Some(payload.clone());
                existing.shared_at = linked.updated_at.parse().unwrap_or_else(|_| Utc::now());
            }
        } else if linked.recipient_user_id == user_id {
            if let Some(existing) = store.received_shares.iter_mut().find(|s| s.id == linked.id) {
                existing.encrypted_payload = Some(payload.clone());
                existing.shared_at = linked.updated_at.parse().unwrap_or_else(|_| Utc::now());
            } else {
                let (item_name, item_type) = {
                    let crypto = state.crypto.read();
                    if let Some(crypto) = crypto.as_ref() {
                        if let Ok(plaintext) = crypto.decrypt_vault(&payload) {
                            if let Ok(item) =
                                serde_json::from_slice::<crate::vault::VaultItem>(&plaintext)
                            {
                                (
                                    item.name().to_string(),
                                    format!("{:?}", item.item_type()).to_lowercase(),
                                )
                            } else {
                                ("Shared item".to_string(), "login".to_string())
                            }
                        } else {
                            ("Shared item".to_string(), "login".to_string())
                        }
                    } else {
                        ("Shared item".to_string(), "login".to_string())
                    }
                };

                store.received_shares.push(Share {
                    id: linked.id.clone(),
                    item_id: linked.id.clone(),
                    item_name,
                    item_type,
                    direction: ShareDirection::Received,
                    from: linked.sender_user_id,
                    to: None,
                    shared_at: linked.updated_at.parse().unwrap_or_else(|_| Utc::now()),
                    accepted: None,
                    allow_edit: false,
                    encrypted_payload: Some(payload.clone()),
                });
            }
        }
    }

    sync_received_linked_items(state, &store)?;
    save_share_store(state, &store)?;
    Ok(())
}

#[tauri::command]
pub async fn get_shares(state: State<'_, Arc<AppState>>) -> Result<Vec<Share>, String> {
    let _ = refresh_linked_shares_inner(&state).await;
    let mut store = load_share_store(&state).unwrap_or_default();

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        match client.get_inbox(&token).await {
            Ok((inbox_items, new_tok)) => {
                if let Some(t) = new_tok {
                    state.session.write().set_server_token(t);
                }
                for inbox_item in inbox_items {
                    if store.received_shares.iter().any(|s| s.id == inbox_item.id) {
                        continue;
                    }
                    // Decode the base64 capsule — the name/type come from decrypting it.
                    let capsule_bytes = B64.decode(&inbox_item.capsule).unwrap_or_default();
                    let (item_name, item_type) = {
                        let crypto = state.crypto.read();
                        if let Some(crypto) = crypto.as_ref() {
                            if let Ok(plaintext) = crypto.decrypt_vault(&capsule_bytes) {
                                if let Ok(item) =
                                    serde_json::from_slice::<crate::vault::VaultItem>(&plaintext)
                                {
                                    (
                                        item.name().to_string(),
                                        format!("{:?}", item.item_type()).to_lowercase(),
                                    )
                                } else {
                                    ("Shared item".to_string(), "login".to_string())
                                }
                            } else {
                                ("Shared item".to_string(), "login".to_string())
                            }
                        } else {
                            ("Shared item".to_string(), "login".to_string())
                        }
                    };
                    let share = Share {
                        id: inbox_item.id.clone(),
                        item_id: inbox_item.id.clone(), // inbox_id as surrogate until accepted
                        item_name,
                        item_type,
                        direction: ShareDirection::Received,
                        from: inbox_item.sender_user_id,
                        to: None,
                        shared_at: inbox_item.created_at.parse().unwrap_or_else(|_| Utc::now()),
                        accepted: None,
                        allow_edit: false,
                        encrypted_payload: Some(capsule_bytes),
                    };
                    store.received_shares.push(share);
                }
                let _ = save_share_store(&state, &store);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch inbox from server (returning local shares): {}",
                    e
                );
            }
        }
    }

    Ok(store.get_all_shares())
}

#[tauri::command]
pub async fn send_share(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    request: SendShareRequest,
) -> Result<Share, String> {
    let (item_json, encrypted_payload, device_id) = {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Session not unlocked")?;

        let vault = state.vault.read();
        let item = vault
            .get_item(&request.item_id)
            .ok_or("Item not found")?
            .clone();
        drop(vault);

        let item_json = serde_json::to_vec(&item).map_err(|e| e.to_string())?;
        let encrypted_payload = crypto
            .encrypt_vault(&item_json)
            .map_err(|e| e.to_string())?;

        let device_id = state
            .store
            .load_device_id()
            .unwrap_or_else(|_| "unknown".to_string());

        (item_json, encrypted_payload, device_id)
    };

    let item: crate::vault::VaultItem =
        serde_json::from_slice(&item_json).map_err(|e| e.to_string())?;

    let share = Share {
        id: String::new(),
        item_id: request.item_id.clone(),
        item_name: item.name().to_string(),
        item_type: format!("{:?}", item.item_type()).to_lowercase(),
        direction: ShareDirection::Sent,
        from: format!("user-{}", &device_id[..8]),
        to: Some(request.recipient.clone()),
        shared_at: Utc::now(),
        accepted: None,
        allow_edit: request.allow_edit,
        encrypted_payload: Some(encrypted_payload.clone()),
    };

    let mut store = load_share_store(&state).unwrap_or_default();

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        let capsule_b64 = B64.encode(&encrypted_payload);
        match client
            .send_share(&token, &request.recipient, &capsule_b64)
            .await
        {
            Ok((resp, new_tok)) => {
                if let Some(t) = new_tok {
                    state.session.write().set_server_token(t);
                }
                let _ = resp.inbox_id;
                let mut share = share.clone();
                share.id = resp.share_id;
                tracing::info!(
                    "Share delivered to server: {} to {}",
                    share.item_name,
                    request.recipient
                );
                // Mark the original vault item as shared so the vault list shows the indicator.
                {
                    let mut vault = state.vault.write();
                    if let Some(existing) = vault.get_item(&request.item_id).cloned() {
                        let marked =
                            existing.with_shared_status(true, Some(request.recipient.clone()));
                        vault.update_item(marked);
                    }
                }
                if let Some(crypto) = state.crypto.read().as_ref() {
                    let vault_snapshot = state.vault.read().clone();
                    let _ = state.store.save_vault(&vault_snapshot, crypto);
                }

                store.add_sent_share(share.clone());
                save_share_store(&state, &store)?;

                tracing::info!("Share sent: {} to {}", share.item_name, request.recipient);
                record_audit_event(
                    &state,
                    AuditAction::ShareSent {
                        recipient_user_id: request.recipient.clone(),
                    },
                );
                crate::commands::vault::emit_vault_items_changed(&app);
                return Ok(share);
            }
            Err(e) => {
                tracing::warn!("Share send to server failed: {}", e);
                return Err(format!(
                    "Could not deliver share: {e}. Check the recipient's user ID."
                ));
            }
        }
    } else {
        return Err("Not authenticated — please unlock your vault and try again.".to_string());
    }
}

#[tauri::command]
pub async fn accept_share(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    let mut store = load_share_store(&state).ok_or("Failed to load share store")?;
    let mut received_item_id: Option<String> = None;

    let share = store
        .received_shares
        .iter()
        .find(|s| s.id == share_id)
        .ok_or("Share not found")?
        .clone();

    if let Some(encrypted_payload) = &share.encrypted_payload {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Session not unlocked")?;

        let decrypted = crypto
            .decrypt_vault(encrypted_payload)
            .map_err(|e| e.to_string())?;

        let item: crate::vault::VaultItem =
            serde_json::from_slice(&decrypted).map_err(|e| e.to_string())?;

        let _ = crypto;

        // Always give the received copy a fresh ID so it is a distinct vault item,
        // even when the sender and recipient are the same user.
        let received_item = item
            .with_id(Uuid::new_v4().to_string())
            .with_shared_status(true, None);
        received_item_id = Some(received_item.id().to_string());
        {
            let mut vault = state.vault.write();
            vault.add_item(received_item);
        }
        if let Some(crypto) = state.crypto.read().as_ref() {
            let vault_store = state.vault.read();
            state
                .store
                .save_vault(&vault_store, crypto)
                .map_err(|e| e.to_string())?;
        }
    }

    // Remove from server inbox and local store — inbox is cleared after accepting.
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        if let Ok(new_tok) = client.delete_inbox_item(&token, &share_id).await {
            if let Some(t) = new_tok {
                state.session.write().set_server_token(t);
            }
        }
    }

    if let Some(existing) = store.received_shares.iter_mut().find(|s| s.id == share_id) {
        existing.accepted = Some(true);
        if let Some(item_id) = received_item_id {
            existing.item_id = item_id;
        }
    }
    save_share_store(&state, &store)?;
    record_audit_event(
        &state,
        AuditAction::ShareReceived {
            sender_user_id: share.from.clone(),
        },
    );

    tracing::info!("Share accepted: {}", share_id);

    crate::commands::vault::emit_vault_items_changed(&app);

    Ok(())
}

#[tauri::command]
pub async fn decline_share(
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    let mut store = load_share_store(&state).ok_or("Failed to load share store")?;

    // Delete from server inbox and remove from local store entirely.
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        if let Ok(new_tok) = client.delete_inbox_item(&token, &share_id).await {
            if let Some(t) = new_tok {
                state.session.write().set_server_token(t);
            }
        }
    }

    store.remove_share(&share_id);
    save_share_store(&state, &store)?;

    tracing::info!("Share declined: {}", share_id);

    Ok(())
}

#[tauri::command]
pub async fn delete_share(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    let mut store = load_share_store(&state).ok_or("Failed to load share store")?;

    let is_received = store.received_shares.iter().any(|s| s.id == share_id);
    if is_received {
        let server_url = state.server_url.read().clone();
        let client = ApiClient::with_url(server_url);
        if let Some(token) = state.get_session_token() {
            match client.delete_inbox_item(&token, &share_id).await {
                Ok(new_tok) => {
                    if let Some(t) = new_tok {
                        state.session.write().set_server_token(t);
                    }
                }
                Err(e) => tracing::warn!("Failed to delete inbox item on server: {}", e),
            }
        }
    } else {
        // Revoking a sent share — clear the shared flag on the vault item.
        if let Some(sent) = store.sent_shares.iter().find(|s| s.id == share_id).cloned() {
            let server_url = state.server_url.read().clone();
            let client = ApiClient::with_url(server_url);
            if let Some(token) = state.get_session_token() {
                match client.delete_linked_share(&token, &share_id).await {
                    Ok(new_tok) => {
                        if let Some(t) = new_tok {
                            state.session.write().set_server_token(t);
                        }
                    }
                    Err(e) => tracing::warn!("Failed to delete linked share on server: {}", e),
                }
            }

            let revoked_payload = sent.encrypted_payload.clone();

            let device_id = {
                let session = state.session.read();
                session.get_device_id().map(|s| s.to_string())
            };

            let mut vault = state.vault.write();
            if let Some(existing) = vault.get_item(&sent.item_id).cloned() {
                let unmarked = existing.with_shared_status(false, None);
                vault.update_item(unmarked);
            }

            if let Some(received_index) = store
                .received_shares
                .iter()
                .position(|s| s.accepted == Some(true) && s.encrypted_payload == revoked_payload)
            {
                let received_share = store.received_shares[received_index].clone();
                vault.delete_item(&received_share.item_id, device_id.as_deref());
                store.received_shares.remove(received_index);
            } else {
                store
                    .received_shares
                    .retain(|s| s.encrypted_payload != revoked_payload);
            }

            drop(vault);
            if let Some(crypto) = state.crypto.read().as_ref() {
                let vault_snapshot = state.vault.read().clone();
                let _ = state.store.save_vault(&vault_snapshot, crypto);
            }
        }
    }

    store.remove_share(&share_id);
    save_share_store(&state, &store)?;

    tracing::info!("Share deleted: {}", share_id);

    crate::commands::vault::emit_vault_items_changed(&app);

    Ok(())
}
