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
}
