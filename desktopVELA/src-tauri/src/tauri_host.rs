use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager};
use vela_desktop_core::host::Host;
use vela_desktop_core::AppState;

use crate::commands;

/// `Host` implementation bridging `vela-desktop-core`'s toolkit-agnostic
/// autofill-IPC and Wayland-portal-shortcut code to Tauri's `AppHandle`.
#[derive(Clone)]
pub struct TauriHost(pub AppHandle);

impl Host for TauriHost {
    fn state(&self) -> &Arc<AppState> {
        self.0.state::<Arc<AppState>>().inner()
    }

    fn focus_main_window(&self) {
        if let Some(window) = self.0.get_webview_window("main") {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
    }

    fn app_identifier(&self) -> String {
        self.0.config().identifier.clone()
    }

    fn open_quick_search(&self) {
        commands::window::open_quick_search_window(&self.0);
    }

    fn notify_vault_items_changed(&self) {
        commands::vault::emit_vault_items_changed(&self.0);
    }

    /// A non-blocking toast in the app's own window: the React side listens
    /// for `backend-toast` and routes the payload through its usual toast
    /// state, so this looks like any other notification the UI raises.
    fn show_toast(&self, message: &str) {
        let _ = self.0.emit("backend-toast", message.to_string());
    }

    /// A native modal, deliberately not a web-view one.
    ///
    /// The question is "is a human at this machine right now", and a dialog
    /// drawn inside the page the request came from would be answerable by the
    /// same thing that made the request. A native dialog is at least drawn
    /// outside the requester's reach.
    ///
    /// It is not unforgeable, though: where the user can write `/dev/uinput`
    /// — common, and true on the machine this was tested on — a same-UID
    /// process can synthesize the click. See the module docs on
    /// `vela_desktop_core::presence` for what that costs.
    ///
    /// The buttons are labelled with the action rather than "OK"/"Cancel":
    /// somebody clicking through prompts should at least have had to click one
    /// that said "Approve".
    fn confirm_presence(&self, prompt: &str) -> Option<bool> {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

        Some(
            self.0
                .dialog()
                .message(prompt)
                .title("VELA — passkey request")
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom(
                    "Approve".to_string(),
                    "Deny".to_string(),
                ))
                .blocking_show(),
        )
    }
}
