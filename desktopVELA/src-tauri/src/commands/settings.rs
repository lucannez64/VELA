//! `#[tauri::command]` wrappers for settings, plus the one piece that is
//! irreducibly Tauri: the global quick-search shortcut, which on X11 /
//! Windows / macOS is a key grab owned by `tauri_plugin_global_shortcut`.
//!
//! Persistence, validation and the recovery/WebAuthn calls live in
//! [`vela_desktop_core::commands::settings`] and
//! [`vela_desktop_core::recovery`].

use std::str::FromStr;
use std::sync::Arc;
use tauri::{command, AppHandle, State};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};

use crate::AppState;
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
    vela_desktop_core::commands::settings::shortcut_backend() == "portal"
}

/// How the quick-search shortcut is delivered on this system: `"portal"`
/// (Wayland, via the XDG GlobalShortcuts portal — the compositor owns the
/// actual keybind) or `"plugin"` (X11/Windows/macOS key grab).
#[command]
pub async fn get_shortcut_backend() -> Result<String, String> {
    Ok(vela_desktop_core::commands::settings::shortcut_backend().to_string())
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
    vela_desktop_core::commands::settings::get_settings(&state)
}

/// Persist settings, re-grabbing the global shortcut if it changed.
///
/// Order matters and is preserved from before the split: the URL is validated
/// and the new shortcut is grabbed *before* anything is written, so a
/// rejected URL or an unregisterable accelerator leaves the stored settings
/// untouched instead of saving a binding that will never fire.
#[command]
pub async fn update_settings(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    settings: Settings,
) -> Result<(), String> {
    let mut settings = settings;
    settings.server_url = crate::validate_server_url(&settings.server_url)?;
    settings.quick_search_shortcut =
        normalize_quick_search_shortcut(&settings.quick_search_shortcut);

    let previous_settings = state.store.load_settings().unwrap_or_default();
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

    vela_desktop_core::commands::settings::update_settings(&state, settings)
}

#[command]
pub async fn get_auto_lock_minutes(state: State<'_, Arc<AppState>>) -> Result<u32, String> {
    vela_desktop_core::commands::settings::get_auto_lock_minutes(&state)
}

#[command]
pub async fn set_auto_lock_minutes(
    state: State<'_, Arc<AppState>>,
    minutes: u32,
) -> Result<(), String> {
    vela_desktop_core::commands::settings::set_auto_lock_minutes(&state, minutes)
}

// ── recovery setup (server-side halves) ──────────────────────────────────

#[command]
pub async fn send_recovery_invite(
    state: State<'_, Arc<AppState>>,
    email: String,
) -> Result<(), String> {
    vela_desktop_core::recovery::send_recovery_invite(&state, &email).await
}

#[command]
pub async fn start_recovery_webauthn_registration(
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    vela_desktop_core::recovery::start_recovery_webauthn_registration(&state).await
}

#[command]
pub async fn finish_recovery_webauthn_registration(
    state: State<'_, Arc<AppState>>,
    credential: serde_json::Value,
) -> Result<bool, String> {
    vela_desktop_core::recovery::finish_recovery_webauthn_registration(&state, credential).await
}

#[command]
pub async fn initiate_account_recovery(
    state: State<'_, Arc<AppState>>,
    user_id: String,
) -> Result<serde_json::Value, String> {
    vela_desktop_core::recovery::initiate_account_recovery(&state, &user_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shortcut the user configures is handed to
    // `tauri_plugin_global_shortcut::Shortcut::from_str` at registration time;
    // these guard the strings we produce against what the plugin accepts.
    #[test]
    fn default_shortcut_parses_as_plugin_accelerator() {
        assert!(Shortcut::from_str(DEFAULT_QUICK_SEARCH_SHORTCUT).is_ok());
    }

    #[test]
    fn common_shortcut_spellings_parse() {
        for shortcut in ["Ctrl+Alt+Q", "Shift+Super+Space", "CmdOrCtrl+K", "F12"] {
            assert!(
                Shortcut::from_str(shortcut).is_ok(),
                "{shortcut} should be a valid accelerator"
            );
        }
    }

    #[test]
    fn garbage_shortcut_is_rejected() {
        assert!(Shortcut::from_str("").is_err());
    }

    #[test]
    fn normalized_shortcut_always_parses_or_is_default() {
        // normalize → empty falls back to the default, which parses.
        let normalized = normalize_quick_search_shortcut("   ");
        assert_eq!(normalized, DEFAULT_QUICK_SEARCH_SHORTCUT);
        assert!(Shortcut::from_str(&normalized).is_ok());

        let normalized = normalize_quick_search_shortcut(" Ctrl+Alt+V ");
        assert!(Shortcut::from_str(&normalized).is_ok());
    }
}
