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
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::host::Host;

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
pub async fn run(host: Arc<dyn Host>, preferred_trigger: String) {
    match bind_and_listen(&host, &preferred_trigger).await {
        Ok(()) => warn!("Portal global-shortcut stream ended"),
        Err(e) => error!(
            "Quick search global shortcut unavailable ({e}). Your desktop portal may not \
             implement GlobalShortcuts; on Hyprland make sure xdg-desktop-portal-hyprland is \
             running, then bind the shortcut in hyprland.conf: \
             `bind = CTRL ALT, V, global, com.vela.vault:{QUICK_SEARCH_SHORTCUT_ID}`"
        ),
    }
}

/// Claim our app id with `org.freedesktop.host.portal.Registry`.
///
/// **Must be called before anything else in the process makes a portal call.**
/// `ashpd` caches one process-wide session-bus connection (`static SESSION:
/// OnceLock<zbus::Connection>` in its `proxy.rs`), and xdg-desktop-portal
/// binds an app id to a *connection*, once — a second attempt fails with
/// "Connection already associated with an application ID". Host
/// (non-sandboxed) apps have no app id the portal can discover on its own,
/// and portal backends reject GlobalShortcuts sessions without one ("An app
/// id is required"), so losing this race silently costs the global shortcut.
///
/// This bit the gpui build specifically: `gpui_linux`'s
/// `xdg_desktop_portal.rs` opens `org.freedesktop.portal.Settings` during
/// platform init (to watch color-scheme/cursor-theme) — that is a portal call
/// on the shared connection, and it happens before any code inside the
/// `Application::run` closure gets to run. Hence: call this from `main()`
/// *before* starting the gpui application, not from the shortcut task.
///
/// Also requires a matching `<identifier>.desktop` entry installed on the
/// host (e.g. in `~/.local/share/applications/`).
pub async fn register_app_id(identifier: &str) {
    match ashpd::AppID::try_from(identifier) {
        Ok(app_id) => match ashpd::register_host_app(app_id).await {
            Ok(()) => info!("Registered '{identifier}' with the desktop portal"),
            Err(e) => warn!(
                "Could not register '{identifier}' with the desktop portal ({e}); \
                 the global shortcut needs a `{identifier}.desktop` entry installed \
                 (e.g. in ~/.local/share/applications/), and this must run before any \
                 other portal call in the process"
            ),
        },
        Err(e) => warn!("App identifier '{identifier}' is not a valid portal app id: {e}"),
    }
}

async fn bind_and_listen(host: &Arc<dyn Host>, preferred_trigger: &str) -> ashpd::Result<()> {
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
        // A dedicated popup window rather than the main one: a newly mapped
        // window appears on the active workspace, so the popup opens where
        // the user is instead of dragging the whole app there.
        host.open_quick_search();
    }
    drop(session);
    Ok(())
}
