use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::api::ApiClient;
use crate::AppState;
use crate::commands::audit::{AuditAction, record_audit_event};

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
    let ciphertext = crypto.encrypt_vault(&plaintext).map_err(|e| e.to_string())?;
    
    let shares_path = state.store.store_path().join(SHARES_FILE);
    std::fs::write(shares_path, ciphertext).map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
pub async fn get_shares(state: State<'_, Arc<AppState>>) -> Result<Vec<Share>, String> {
    let mut store = load_share_store(&state).unwrap_or_default();
    
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        match client.get_inbox(&token).await {
            Ok(inbox_items) => {
                let crypto = state.crypto.read();
                if let Some(crypto) = crypto.as_ref() {
                    for inbox_item in inbox_items {
                        let decrypted = crypto.decrypt_vault(&inbox_item.encrypted_payload);
                        if let Ok(plaintext) = decrypted {
                            if let Ok(item) = serde_json::from_slice::<crate::vault::VaultItem>(&plaintext) {
                                let share = Share {
                                    id: inbox_item.id.clone(),
                                    item_id: inbox_item.item_id,
                                    item_name: inbox_item.item_name,
                                    item_type: format!("{:?}", item.item_type()).to_lowercase(),
                                    direction: ShareDirection::Received,
                                    from: inbox_item.from,
                                    to: None,
                                    shared_at: inbox_item.shared_at.parse().unwrap_or_else(|_| Utc::now()),
                                    accepted: None,
                                    allow_edit: inbox_item.allow_edit,
                                    encrypted_payload: Some(inbox_item.encrypted_payload),
                                };
                                if !store.received_shares.iter().any(|s| s.id == share.id) {
                                    store.received_shares.push(share);
                                }
                            }
                        }
                    }
                    drop(crypto);
                }
                let _ = save_share_store(&state, &store);
            }
            Err(e) => {
                tracing::warn!("Failed to fetch inbox from server (returning local shares): {}", e);
            }
        }
    }
    
    Ok(store.get_all_shares())
}

#[tauri::command]
pub async fn send_share(
    state: State<'_, Arc<AppState>>,
    request: SendShareRequest,
) -> Result<Share, String> {
    let (item_json, encrypted_payload, device_id) = {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Session not unlocked")?;

        let vault = state.vault.read();
        let item = vault.get_item(&request.item_id)
            .ok_or("Item not found")?
            .clone();
        drop(vault);

        let item_json = serde_json::to_vec(&item).map_err(|e| e.to_string())?;
        let encrypted_payload = crypto.encrypt_vault(&item_json).map_err(|e| e.to_string())?;

        let device_id = state.store.load_device_id().unwrap_or_else(|_| "unknown".to_string());

        (item_json, encrypted_payload, device_id)
    };

    let item: crate::vault::VaultItem = serde_json::from_slice(&item_json)
        .map_err(|e| e.to_string())?;

    let share = Share {
        id: Uuid::new_v4().to_string(),
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
    store.add_sent_share(share.clone());
    save_share_store(&state, &store)?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        if let Err(e) = client.send_share(&token, &request.item_id, &request.recipient, request.allow_edit, encrypted_payload).await {
            tracing::warn!("Failed to send share to server (local share saved): {}", e);
        }
    }

    tracing::info!("Share sent: {} to {}", share.item_name, request.recipient);
    record_audit_event(&state, AuditAction::ShareSent {
        recipient_user_id: request.recipient.clone(),
    });

    Ok(share)
}

#[tauri::command]
pub async fn accept_share(
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    let mut store = load_share_store(&state).ok_or("Failed to load share store")?;
    
    let share = store.received_shares.iter()
        .find(|s| s.id == share_id)
        .ok_or("Share not found")?
        .clone();
    
    if let Some(encrypted_payload) = &share.encrypted_payload {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Session not unlocked")?;
        
        let decrypted = crypto.decrypt_vault(encrypted_payload)
            .map_err(|e| e.to_string())?;
        
        let item: crate::vault::VaultItem = serde_json::from_slice(&decrypted)
            .map_err(|e| e.to_string())?;
        
        let _ = crypto;
        
        let mut vault = state.vault.write();
        let shared_item = item.with_shared_status(true, share.to.clone());
        vault.add_item(shared_item);
        
        drop(vault);
        
        if let Some(crypto) = state.crypto.read().as_ref() {
            let vault_store = state.vault.read();
            state.store.save_vault(&vault_store, crypto).map_err(|e| e.to_string())?;
        }
    }
    
    store.update_share_status(&share_id, true);
    save_share_store(&state, &store)?;
    record_audit_event(&state, AuditAction::ShareReceived {
        sender_user_id: share.from.clone(),
    });
    
    tracing::info!("Share accepted: {}", share_id);
    
    Ok(())
}

#[tauri::command]
pub async fn decline_share(
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    let mut store = load_share_store(&state).ok_or("Failed to load share store")?;
    store.update_share_status(&share_id, false);
    save_share_store(&state, &store)?;
    
    tracing::info!("Share declined: {}", share_id);
    
    Ok(())
}

#[tauri::command]
pub async fn delete_share(
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    let mut store = load_share_store(&state).ok_or("Failed to load share store")?;
    
    let is_received = store.received_shares.iter().any(|s| s.id == share_id);
    if is_received {
        let server_url = state.server_url.read().clone();
        let client = ApiClient::with_url(server_url);
        if let Some(token) = state.get_session_token() {
            if let Err(e) = client.delete_inbox_item(&token, &share_id).await {
                tracing::warn!("Failed to delete inbox item on server: {}", e);
            }
        }
    }
    
    store.remove_share(&share_id);
    save_share_store(&state, &store)?;
    
    tracing::info!("Share deleted: {}", share_id);
    
    Ok(())
}
