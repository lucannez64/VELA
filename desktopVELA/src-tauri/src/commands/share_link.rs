//! `#[tauri::command]` wrappers for one-off share links.
//!
//! All logic lives in [`vela_desktop_core::share_link`]; the Tauri layer only
//! adapts the renderer's argument shape.

use std::sync::Arc;

use tauri::State;

use crate::AppState;

pub use vela_desktop_core::share_link::{
    CreateShareLinkRequest, ShareLinkCreated, ShareLinkRecord,
};

#[tauri::command]
pub async fn create_share_link(
    state: State<'_, Arc<AppState>>,
    request: CreateShareLinkRequest,
) -> Result<ShareLinkCreated, String> {
    vela_desktop_core::share_link::create_share_link(&state, request).await
}

#[tauri::command]
pub async fn get_share_links(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<ShareLinkRecord>, String> {
    vela_desktop_core::share_link::list_share_links(&state)
}

#[tauri::command]
pub async fn revoke_share_link(
    state: State<'_, Arc<AppState>>,
    link_id: String,
) -> Result<(), String> {
    vela_desktop_core::share_link::revoke_share_link(&state, &link_id).await
}
