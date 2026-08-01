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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    fn state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&Crypto::generate_rms());
        (dir, state)
    }

    #[test]
    fn get_settings_returns_defaults_with_state_overlays() {
        let (_dir, state) = state();
        let settings = get_settings(&state).unwrap();
        assert_eq!(settings.auto_lock_minutes, 5);
        assert_eq!(settings.user_id, "test-user", "session user wins");
        assert_eq!(settings.server_url, "");
        assert!(!settings.extension_connected);
    }

    #[test]
    fn update_settings_persists_and_normalizes() {
        let (_dir, state) = state();
        let settings = Settings {
            auto_lock_minutes: 15,
            server_url: "  https://vault.example.com ".into(),
            quick_search_shortcut: "  ".into(),
            ..Default::default()
        };

        update_settings(&state, settings).unwrap();

        // State server_url updated (normalized: trimmed).
        assert_eq!(state.server_url.read().as_str(), "https://vault.example.com");

        let loaded = get_settings(&state).unwrap();
        assert_eq!(loaded.auto_lock_minutes, 15);
        assert_eq!(loaded.server_url, "https://vault.example.com");
        // Blank shortcut falls back to the default.
        assert_eq!(
            loaded.quick_search_shortcut,
            crate::settings::DEFAULT_QUICK_SEARCH_SHORTCUT
        );
    }

    #[test]
    fn update_settings_rejects_insecure_url_without_persisting() {
        let (_dir, state) = state();
        let settings = Settings {
            server_url: "http://evil.example.com".into(),
            auto_lock_minutes: 99,
            ..Default::default()
        };

        let err = update_settings(&state, settings).unwrap_err();
        assert!(err.contains("Insecure"), "{err}");

        // Rejected update must not leak into state or disk.
        assert_eq!(state.server_url.read().as_str(), "");
        assert_eq!(state.store.load_settings().unwrap().auto_lock_minutes, 5);
    }
}
