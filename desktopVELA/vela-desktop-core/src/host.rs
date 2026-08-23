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

    /// Show a non-blocking notification in the app's own UI (a saved
    /// credential was just handed to a caller over IPC: "filled github.com
    /// for firefox"). Part of the #149 blast-radius limits — a drain should
    /// be visible while it happens, not discoverable afterwards.
    ///
    /// Must not block and must not require interaction; a host that cannot
    /// show anything right now may drop the message.
    fn show_toast(&self, message: &str);

    /// Put a blocking yes/no question to the user in the app's own window, and
    /// report what they said.
    ///
    /// `title` names the action being confirmed (the dialog's caption);
    /// `prompt` is the question body. A dialog always titled like a passkey
    /// request would let somebody clicking through captions approve a vault
    /// wipe without ever reading it.
    ///
    /// `None` means this host cannot ask at all — no window, no UI thread — and
    /// is distinct from `Some(false)`: a refusal is an answer, an inability to
    /// ask is not. [`crate::presence`] is the caller that cares, because a
    /// passkey ceremony must not proceed on an assumption where the platform
    /// has no biometric factor to offer.
    ///
    /// Blocking, and called off the async runtime — it waits for a human.
    fn confirm_presence(&self, title: &str, prompt: &str) -> Option<bool>;
}
