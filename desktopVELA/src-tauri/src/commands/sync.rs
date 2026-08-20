//! `#[tauri::command]` wrappers for vault sync.
//!
//! The protocol — chunking, Lamport clocks, the rollback guard, tombstone-
//! aware merging and conflict capture — lives in [`vela_desktop_core::sync`].
//! These wrappers add the `vault-items-changed` event the webview needs after
//! a sync or a conflict resolution changes the item list.

use std::sync::Arc;

use tauri::{AppHandle, State};

use crate::AppState;

pub use vela_desktop_core::sync::{ConflictItem, SyncStatus};

#[tauri::command]
pub async fn trigger_sync(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<SyncStatus, String> {
    let status = vela_desktop_core::sync::trigger_sync(&state).await?;
    crate::commands::vault::emit_vault_items_changed(&app);
    Ok(status)
}

#[tauri::command]
pub async fn get_sync_status(state: State<'_, Arc<AppState>>) -> Result<SyncStatus, String> {
    vela_desktop_core::sync::get_sync_status(&state).await
}

#[tauri::command]
pub async fn resolve_conflict(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item_id: String,
    use_local: bool,
) -> Result<(), String> {
    vela_desktop_core::sync::resolve_conflict(&state, item_id, use_local).await?;
    crate::commands::vault::emit_vault_items_changed(&app);
    Ok(())
}

#[tauri::command]
pub async fn set_server_url(
    state: State<'_, Arc<AppState>>,
    url: String,
) -> Result<(), String> {
    vela_desktop_core::sync::set_server_url(&state, url)
}
