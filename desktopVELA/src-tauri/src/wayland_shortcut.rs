//! Wayland global-shortcut support via the XDG Desktop Portal
//! `org.freedesktop.portal.GlobalShortcuts` interface.
//!
//! `tauri-plugin-global-shortcut` grabs keys through X11, which Wayland
//! compositors do not allow, so on a Wayland session the quick-search
//! shortcut is bound through the portal instead. KDE and GNOME honour the
//! preferred trigger (showing a confirmation dialog on first bind);
//! Hyprland ignores it and expects the user to map the shortcut in
//! hyprland.conf, e.g.:
//!
//! ```text
//! bind = CTRL ALT, V, global, com.vela.vault:quick-search
//! ```
//!
//! (`hyprctl globalshortcuts` lists the exact `appid:id` pair once VELA is
//! running.)

use ashpd::desktop::global_shortcuts::{BindShortcutsOptions, GlobalShortcuts, NewShortcut};
use ashpd::desktop::CreateSessionOptions;
use futures_util::StreamExt;
use tauri::{AppHandle, Emitter, Manager};
use tracing::{error, info, warn};

pub const QUICK_SEARCH_SHORTCUT_ID: &str = "quick-search";

pub fn is_wayland_session() -> bool {
    std::env::var("XDG_SESSION_TYPE")
        .map(|v| v.eq_ignore_ascii_case("wayland"))
        .unwrap_or(false)
        || std::env::var("WAYLAND_DISPLAY").is_ok()
}

/// Convert a stored accelerator such as `Ctrl+Alt+V` into the trigger format
/// of the shortcuts XDG specification (`CTRL+ALT+v`), used for the portal's
/// `preferred_trigger` hint.
pub fn to_portal_trigger(shortcut: &str) -> String {
    shortcut
        .split('+')
        .map(|part| {
            let part = part.trim();
            match part.to_ascii_lowercase().as_str() {
                "ctrl" | "control" | "commandorcontrol" | "cmdorctrl" => "CTRL".to_string(),
                "alt" | "option" => "ALT".to_string(),
                "shift" => "SHIFT".to_string(),
                "super" | "meta" | "cmd" | "command" | "logo" => "LOGO".to_string(),
                key => key.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("+")
}

/// Bind the quick-search shortcut through the portal and dispatch its
/// activations for the lifetime of the app. Runs as a background task; on
/// failure (no portal, or a portal without GlobalShortcuts support) it logs
/// and exits, leaving the app otherwise functional.
pub async fn run(app: AppHandle, preferred_trigger: String) {
    match bind_and_listen(&app, &preferred_trigger).await {
        Ok(()) => warn!("Portal global-shortcut stream ended"),
        Err(e) => error!(
            "Quick search global shortcut unavailable ({e}). Your desktop portal may not \
             implement GlobalShortcuts; on Hyprland make sure xdg-desktop-portal-hyprland is \
             running, then bind the shortcut in hyprland.conf: \
             `bind = CTRL ALT, V, global, com.vela.vault:{QUICK_SEARCH_SHORTCUT_ID}`"
        ),
    }
}

async fn bind_and_listen(app: &AppHandle, preferred_trigger: &str) -> ashpd::Result<()> {
    // Host (non-sandboxed) apps have no app id the portal can discover, and
    // portal backends reject GlobalShortcuts sessions without one ("An app id
    // is required"). Claim ours via org.freedesktop.host.portal.Registry —
    // this must happen before any other call on the portal connection, and
    // it only succeeds when a matching `<identifier>.desktop` entry is
    // installed on the host.
    let identifier = app.config().identifier.clone();
    match ashpd::AppID::try_from(identifier.as_str()) {
        Ok(app_id) => {
            if let Err(e) = ashpd::register_host_app(app_id).await {
                warn!(
                    "Could not register '{identifier}' with the desktop portal ({e}); \
                     the global shortcut needs a `{identifier}.desktop` entry installed \
                     (e.g. in ~/.local/share/applications/)"
                );
            }
        }
        Err(e) => warn!("App identifier '{identifier}' is not a valid portal app id: {e}"),
    }

    let global_shortcuts = GlobalShortcuts::new().await?;
    let session = global_shortcuts
        .create_session(CreateSessionOptions::default())
        .await?;

    let shortcut = NewShortcut::new(QUICK_SEARCH_SHORTCUT_ID, "Open the VELA quick search overlay")
        .preferred_trigger(preferred_trigger);
    let response = global_shortcuts
        .bind_shortcuts(&session, &[shortcut], None, BindShortcutsOptions::default())
        .await?
        .response()?;

    let triggers: Vec<String> = response
        .shortcuts()
        .iter()
        .map(|s| format!("{} ({})", s.id(), s.trigger_description()))
        .collect();
    info!(shortcuts = ?triggers, "Global shortcuts bound via XDG portal");

    let mut activations = global_shortcuts.receive_activated().await?;
    // Keep `session` alive for as long as we listen — dropping it would end
    // the portal session and unbind the shortcut.
    while let Some(activation) = activations.next().await {
        if activation.shortcut_id() != QUICK_SEARCH_SHORTCUT_ID {
            continue;
        }
        info!("Portal global shortcut triggered: Quick search overlay");
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.set_focus();
            let _ = window.emit("open-quick-search", ());
        }
    }
    drop(session);
    Ok(())
}
