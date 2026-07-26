use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use tauri::{command, AppHandle, State};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};
use uuid::Uuid;

use crate::api::ApiClient;
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::{normalize_server_url, AppState};
pub use vela_desktop_core::settings::{
    normalize_quick_search_shortcut, Settings, Theme, DEFAULT_QUICK_SEARCH_SHORTCUT,
};

pub fn register_quick_search_shortcut(app: &AppHandle, shortcut: &str) -> Result<(), String> {
    let shortcut = normalize_quick_search_shortcut(shortcut);
    let parsed = Shortcut::from_str(&shortcut)
        .map_err(|e| format!("Invalid quick search shortcut '{shortcut}': {e}"))?;

    let app_handle = app.clone();
    app.global_shortcut()
        .on_shortcut(parsed, move |_app, _shortcut, _event| {
            tracing::info!("Global shortcut triggered: Quick search overlay");
            crate::commands::window::open_quick_search_window(&app_handle);
        })
        .map_err(|e| format!("Failed to register quick search shortcut '{shortcut}': {e}"))
}

fn quick_search_uses_portal() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::wayland_shortcut::is_wayland_session()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// How the quick-search shortcut is delivered on this system: `"portal"`
/// (Wayland, via the XDG GlobalShortcuts portal — the compositor owns the
/// actual keybind) or `"plugin"` (X11/Windows/macOS key grab).
#[command]
pub async fn get_shortcut_backend() -> Result<String, String> {
    Ok(if quick_search_uses_portal() {
        "portal".to_string()
    } else {
        "plugin".to_string()
    })
}

fn reconfigure_quick_search_shortcut(
    app: &AppHandle,
    previous_shortcut: &str,
    shortcut: &str,
) -> Result<(), String> {
    app.global_shortcut()
        .unregister_all()
        .map_err(|e| format!("Failed to clear existing shortcuts: {e}"))?;
    if let Err(e) = register_quick_search_shortcut(app, shortcut) {
        let _ = register_quick_search_shortcut(app, previous_shortcut);
        return Err(e);
    }

    Ok(())
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
    settings.quick_search_shortcut =
        normalize_quick_search_shortcut(&settings.quick_search_shortcut);
    settings.extension_connected = state.is_extension_connected();
    Ok(settings)
}

#[command]
pub async fn update_settings(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    settings: Settings,
) -> Result<(), String> {
    let previous_settings = state.store.load_settings().unwrap_or_default();
    let mut settings = settings;
    settings.server_url = crate::validate_server_url(&settings.server_url)?;
    settings.quick_search_shortcut =
        normalize_quick_search_shortcut(&settings.quick_search_shortcut);

    if normalize_quick_search_shortcut(&previous_settings.quick_search_shortcut)
        != settings.quick_search_shortcut
    {
        if quick_search_uses_portal() {
            // The portal binding was created at startup with the previous
            // preferred trigger; the new one is picked up on next launch
            // (Hyprland ignores it either way — the compositor keybind rules).
            tracing::info!(
                shortcut = %settings.quick_search_shortcut,
                "Wayland session: quick search shortcut preference stored; applies at next launch"
            );
        } else {
            reconfigure_quick_search_shortcut(
                &app,
                &previous_settings.quick_search_shortcut,
                &settings.quick_search_shortcut,
            )?;
        }
    }

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

    if response.registered {
        // The recovery passkey is now registered server-side — immediately
        // hand it the share it's meant to gate (Share 2 of the 2-of-3
        // split; see SPEC.md §4.3 and commands/recovery.rs). Registering the
        // credential without ever storing a share behind it would leave
        // "security key recovery" enabled in the UI but functionally inert.
        let current_token = state
            .get_session_token()
            .ok_or_else(|| "No session token available".to_string())?;
        crate::commands::recovery::deliver_security_key_share(&state, &current_token).await?;
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
    Ok(serde_json::json!({
        "recovery_id": response.recovery_id,
        "public_key": response.public_key,
    }))
}

#[command]
pub async fn get_auto_lock_minutes(state: State<'_, Arc<AppState>>) -> Result<u32, String> {
    let settings = state.store.load_settings().map_err(|e| e.to_string())?;
    Ok(settings.auto_lock_minutes)
}

#[command]
pub async fn set_auto_lock_minutes(
    state: State<'_, Arc<AppState>>,
    minutes: u32,
) -> Result<(), String> {
    if !(1..=24 * 60).contains(&minutes) {
        return Err("auto_lock_minutes must be between 1 and 1440".to_string());
    }
    let mut settings = state.store.load_settings().unwrap_or_default();
    settings.auto_lock_minutes = minutes;
    state
        .store
        .save_settings(&settings)
        .map_err(|e| e.to_string())?;
    record_audit_event(&state, AuditAction::SettingsChanged);
    Ok(())
}
