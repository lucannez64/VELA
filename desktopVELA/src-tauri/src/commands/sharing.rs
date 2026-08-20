//! `#[tauri::command]` wrappers for item sharing.
//!
//! The share store, KEM sealing, inbox reconciliation and linked-share
//! updates all live in [`vela_desktop_core::sharing`]. What is genuinely
//! Tauri-only stays here: [`SendShareRequest`] (the renderer's argument
//! shape) and the `vault-items-changed` event that tells the webview to
//! re-fetch — gpui has no renderer to notify, so it re-reads state directly
//! once the awaited call returns.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::AppState;

pub use vela_desktop_core::sharing::{Share, ShareDirection};

/// The renderer's `send_share` argument. `notify_on_accept` is accepted for
/// wire compatibility with the existing frontend call and, as before, not
/// acted on — there is no notification channel to act on it with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendShareRequest {
    pub item_id: String,
    pub recipient: String,
    pub allow_edit: bool,
    pub notify_on_accept: bool,
}

#[tauri::command]
pub async fn get_shares(state: State<'_, Arc<AppState>>) -> Result<Vec<Share>, String> {
    vela_desktop_core::sharing::get_shares(&state).await
}

#[tauri::command]
pub async fn send_share(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    request: SendShareRequest,
) -> Result<Share, String> {
    let share = vela_desktop_core::sharing::send_share(
        &state,
        &request.item_id,
        &request.recipient,
        request.allow_edit,
    )
    .await?;
    crate::commands::vault::emit_vault_items_changed(&app);
    Ok(share)
}

#[tauri::command]
pub async fn accept_share(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    vela_desktop_core::sharing::accept_share(&state, &share_id).await?;
    crate::commands::vault::emit_vault_items_changed(&app);
    Ok(())
}

#[tauri::command]
pub async fn decline_share(
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    vela_desktop_core::sharing::decline_share(&state, &share_id).await
}

#[tauri::command]
pub async fn delete_share(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    share_id: String,
) -> Result<(), String> {
    vela_desktop_core::sharing::delete_share(&state, &share_id).await?;
    crate::commands::vault::emit_vault_items_changed(&app);
    Ok(())
}
