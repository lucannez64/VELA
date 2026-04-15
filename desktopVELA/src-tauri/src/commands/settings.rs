use serde::{Deserialize, Serialize};
use tauri::{command, State};
use std::sync::Arc;

use crate::AppState;
use crate::commands::audit::{AuditAction, record_audit_event};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
    pub require_biometric_on_reveal: bool,
    pub sync_on_startup: bool,
    pub background_sync_minutes: u32,
    pub theme: Theme,
    pub compact_list: bool,
    pub user_id: String,
    pub server_url: String,
    pub extension_connected: bool,
    pub extension_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    System,
    Dark,
    Light,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 30,
            require_biometric_on_reveal: false,
            sync_on_startup: true,
            background_sync_minutes: 5,
            theme: Theme::System,
            compact_list: false,
            user_id: String::new(),
            server_url: String::new(),
            extension_connected: false,
            extension_version: None,
        }
    }
}

#[command]
pub async fn get_settings(state: State<'_, Arc<AppState>>) -> Result<Settings, String> {
    let mut settings = state.store.load_settings().map_err(|e| e.to_string())?;
    // Prefer the live session user_id (set after server auth), fall back to store.
    let user_id = {
        let session = state.session.read();
        session.get_user_id().map(|s| s.to_string())
    };
    settings.user_id = user_id
        .or_else(|| state.store.load_user_id().ok())
        .unwrap_or_default();
    settings.server_url = state.server_url.read().clone();
    settings.extension_connected = state.is_extension_connected();
    Ok(settings)
}

#[command]
pub async fn update_settings(state: State<'_, Arc<AppState>>, settings: Settings) -> Result<(), String> {
    if !settings.server_url.is_empty() {
        *state.server_url.write() = settings.server_url.clone();
    }
    state.store.save_settings(&settings).map_err(|e| e.to_string())?;
    record_audit_event(&state, AuditAction::SettingsChanged);
    Ok(())
}

#[command]
pub async fn send_recovery_invite(email: String) -> Result<(), String> {
    tracing::info!("Sending recovery invite to: {}", email);
    Ok(())
}
