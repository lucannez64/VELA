//! `#[tauri::command]` wrappers for ephemeral web access.
//!
//! The protocol — QR parsing, fingerprint check, capsule sealing, audit —
//! lives in [`vela_desktop_core::commands::web_session`], which is what the
//! gpui build calls directly. Nothing here but argument shapes.

use std::sync::Arc;

use tauri::State;

use crate::api::WebSessionInfo;
use crate::AppState;

pub use vela_desktop_core::commands::web_session::{rw_capsule_envelope, GrantResult};

#[tauri::command]
pub async fn grant_web_session(
    state: State<'_, Arc<AppState>>,
    qr_payload: String,
    mode: String,
    ttl_secs: i64,
) -> Result<GrantResult, String> {
    vela_desktop_core::commands::web_session::grant_web_session(&state, &qr_payload, &mode, ttl_secs)
        .await
}

#[tauri::command]
pub async fn list_web_sessions(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<WebSessionInfo>, String> {
    vela_desktop_core::commands::web_session::list_web_sessions(&state).await
}

#[tauri::command]
pub async fn revoke_web_session(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> Result<(), String> {
    vela_desktop_core::commands::web_session::revoke_web_session(&state, &session_id).await
}
