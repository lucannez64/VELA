use std::sync::Arc;

use crate::AppState;

/// Callbacks the toolkit-agnostic core needs from whatever UI toolkit hosts
/// it (Tauri today, gpui-ce eventually) — window focus and event
/// notification, which have no toolkit-neutral representation. Implemented
/// once per binary; the local autofill IPC bridge and the Wayland
/// global-shortcut portal client are written against this trait instead of
/// against `tauri::AppHandle` so they need no changes to move between
/// binaries.
pub trait Host: Send + Sync + 'static {
    fn state(&self) -> &Arc<AppState>;

    /// Bring the main window to the foreground (e.g. a locked-vault autofill
    /// request, or the extension's "open vault" action).
    fn focus_main_window(&self);

    /// The portal-facing app identifier (Tauri's `app.config().identifier`),
    /// used to register with `org.freedesktop.host.portal.Registry`.
    fn app_identifier(&self) -> String;

    /// Open (or focus) the quick-search popup, triggered by the global
    /// shortcut.
    fn open_quick_search(&self);

    /// Notify the UI that vault items changed on disk (autofill save, sync,
    /// import, ...) so any open list view can refresh.
    fn notify_vault_items_changed(&self);
}
