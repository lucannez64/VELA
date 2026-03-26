use serde::{Deserialize, Serialize};
use tauri::{command, State};
use std::sync::Arc;

use crate::AppState;

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
            user_id: "vela://abc123...".to_string(),
            extension_connected: false,
            extension_version: None,
        }
    }
}

#[command]
pub async fn get_settings(state: State<'_, Arc<AppState>>) -> Result<Settings, String> {
    state.store.load_settings().map_err(|e| e.to_string())
}

#[command]
pub async fn update_settings(state: State<'_, Arc<AppState>>, settings: Settings) -> Result<(), String> {
    state.store.save_settings(&settings).map_err(|e| e.to_string())
}

#[command]
pub async fn send_recovery_invite(email: String) -> Result<(), String> {
    tracing::info!("Sending recovery invite to: {}", email);
    Ok(())
}
