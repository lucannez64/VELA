//! Toolkit-agnostic core of `src-tauri/src/commands/settings.rs`'s
//! `get_settings`/`update_settings`. Deliberately excludes the Tauri-specific
//! global-shortcut re-registration side effect (`reconfigure_quick_search_
//! shortcut` needs an `AppHandle` + `tauri_plugin_global_shortcut`, neither
//! of which exists in the gpui build yet) — a changed shortcut is persisted
//! but only takes effect after a restart, same as the Wayland-portal path
//! already does in the Tauri build.

use std::sync::Arc;

use crate::audit::{record_audit_event, AuditAction};
use crate::settings::{normalize_quick_search_shortcut, Settings};
use crate::{normalize_server_url, validate_server_url, AppState};

pub fn get_settings(state: &Arc<AppState>) -> Result<Settings, String> {
    let mut settings = state.store.load_settings().map_err(|e| e.to_string())?;
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

pub fn update_settings(state: &Arc<AppState>, mut settings: Settings) -> Result<(), String> {
    settings.server_url = validate_server_url(&settings.server_url)?;
    settings.quick_search_shortcut =
        normalize_quick_search_shortcut(&settings.quick_search_shortcut);

    *state.server_url.write() = settings.server_url.clone();
    state
        .store
        .save_settings(&settings)
        .map_err(|e| e.to_string())?;
    record_audit_event(state, AuditAction::SettingsChanged);
    Ok(())
}
