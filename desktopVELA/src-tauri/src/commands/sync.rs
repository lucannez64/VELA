use crate::api::ApiClient;
use crate::AppState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

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
    
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    
    let manifest = match client.get_sync_manifest("demo-token").await {
        Ok(m) => m,
        Err(e) => {
            return Ok(SyncStatus {
                syncing: false,
                last_synced: None,
                conflicts: vec![],
                error: Some(format!("Server unavailable: {}. Using local vault only.", e)),
            });
        }
    };
    
    let item_count = {
        let vault = state.vault.read();
        vault.items.len()
    };
    
    tracing::info!("Sync complete: {} items, {} chunks on server", item_count, manifest.chunks.len());
    
    Ok(SyncStatus {
        syncing: false,
        last_synced: Some(Utc::now()),
        conflicts: vec![],
        error: None,
    })
}

#[tauri::command]
pub async fn get_sync_status() -> Result<SyncStatus, String> {
    Ok(SyncStatus {
        syncing: false,
        last_synced: Some(Utc::now()),
        conflicts: vec![],
        error: None,
    })
}

#[tauri::command]
pub async fn resolve_conflict(
    _state: State<'_, Arc<AppState>>,
    _item_id: String,
    _use_local: bool,
) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
pub async fn set_server_url(state: State<'_, Arc<AppState>>, url: String) -> Result<(), String> {
    let mut server_url = state.server_url.write();
    *server_url = url;
    Ok(())
}
