//! `#[tauri::command]` wrappers for the Windows system-wide passkey provider.
//!
//! Core logic lives in [`vela_desktop_core::commands::provider`]; these are
//! the RPC shims the React settings page invokes.

use std::sync::Arc;
use tauri::{command, State};

use crate::AppState;
pub use vela_desktop_core::commands::provider::ProviderSummary;

#[command]
pub async fn passkey_provider_register() -> Result<ProviderSummary, String> {
    vela_desktop_core::commands::provider::register()
}

#[command]
pub async fn passkey_provider_unregister() -> Result<(), String> {
    vela_desktop_core::commands::provider::unregister()
}

#[command]
pub async fn passkey_provider_status() -> Result<Option<ProviderSummary>, String> {
    Ok(vela_desktop_core::commands::provider::status())
}

#[command]
pub async fn passkey_provider_sync(
    state: State<'_, Arc<AppState>>,
) -> Result<usize, String> {
    vela_desktop_core::commands::provider::sync_credentials(&state)
}
