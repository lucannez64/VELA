use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{command, State};
use uuid::Uuid;

use crate::api::{ApiClient, RecoveryRecoverRequest};
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::{normalize_server_url, AppState};

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
    let server_url = normalize_server_url(&state.server_url.read());
    *state.server_url.write() = server_url.clone();
    settings.server_url = server_url;
    settings.extension_connected = state.is_extension_connected();
    Ok(settings)
}

#[command]
pub async fn update_settings(
    state: State<'_, Arc<AppState>>,
    settings: Settings,
) -> Result<(), String> {
    let mut settings = settings;
    settings.server_url = normalize_server_url(&settings.server_url);
    *state.server_url.write() = settings.server_url.clone();
    state
        .store
        .save_settings(&settings)
        .map_err(|e| e.to_string())?;
    record_audit_event(&state, AuditAction::SettingsChanged);
    Ok(())
}

#[command]
pub async fn send_recovery_invite(
    state: State<'_, Arc<AppState>>,
    email: String,
) -> Result<(), String> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 {
        return Err("Enter a valid recovery contact email address".to_string());
    }

    #[derive(Serialize, Deserialize)]
    struct RecoveryInvite {
        id: String,
        email: String,
        created_at: DateTime<Utc>,
        status: String,
    }

    let invites_path = state.store.store_path().join("recovery_invites.json");
    let mut invites: Vec<RecoveryInvite> = if invites_path.exists() {
        std::fs::read_to_string(&invites_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    invites.push(RecoveryInvite {
        id: Uuid::new_v4().to_string(),
        email: email.clone(),
        created_at: Utc::now(),
        status: "pending".to_string(),
    });

    let json = serde_json::to_string_pretty(&invites).map_err(|e| e.to_string())?;
    std::fs::write(invites_path, json).map_err(|e| e.to_string())?;

    record_audit_event(&state, AuditAction::SettingsChanged);
    tracing::info!("Recovery invite queued for: {}", email);
    Ok(())
}

#[command]
pub async fn start_recovery_webauthn_registration(
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let (response, new_token) = client
        .start_recovery_webauthn_registration(&token, None, Some("VELA recovery key"))
        .await
        .map_err(|e| format!("Failed to start WebAuthn recovery setup: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    Ok(response.public_key)
}

#[command]
pub async fn finish_recovery_webauthn_registration(
    state: State<'_, Arc<AppState>>,
    credential: serde_json::Value,
) -> Result<bool, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let (response, new_token) = client
        .finish_recovery_webauthn_registration(&token, credential)
        .await
        .map_err(|e| format!("Failed to finish WebAuthn recovery setup: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    Ok(response.registered)
}

#[command]
pub async fn initiate_account_recovery(
    state: State<'_, Arc<AppState>>,
    user_id: String,
) -> Result<serde_json::Value, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let response = client
        .initiate_recovery(&user_id)
        .await
        .map_err(|e| format!("Failed to initiate account recovery: {e}"))?;
    Ok(response.public_key)
}

#[command]
pub async fn finish_account_recovery(
    state: State<'_, Arc<AppState>>,
    user_id: String,
    credential: serde_json::Value,
) -> Result<String, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let response = client
        .recover_account(&RecoveryRecoverRequest {
            user_id,
            credential,
        })
        .await
        .map_err(|e| format!("Failed to finish account recovery: {e}"))?;
    Ok(response.share)
}
