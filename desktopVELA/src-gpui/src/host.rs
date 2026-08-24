//! `vela_desktop_core::host::Host` implementation for the gpui binary — the
//! counterpart to `src-tauri/src/tauri_host.rs`'s `TauriHost`.
//!
//! Two subsystems in the core are written against this trait rather than
//! against a specific toolkit: the local autofill IPC bridge (`ipc.rs`,
//! serving the browser extension) and the Wayland portal global-shortcut
//! client (`wayland_shortcut.rs`). Both run on their own threads, off gpui's
//! foreground executor.
//!
//! That threading is the whole design constraint here. `Host`'s callbacks
//! (`focus_main_window`, `open_quick_search`, `notify_vault_items_changed`)
//! all want to touch `Window`/`App` state, but gpui-ce's `ForegroundExecutor`
//! is explicitly `!Send` (`not_send: PhantomData<Rc<()>>`) and the crate
//! exposes no public "run this closure on the main thread" primitive to
//! bridge from an arbitrary thread. So this type does what every other
//! cross-thread hop in this codebase does (the ksni tray, see `tray.rs`):
//! sends a plain `std::sync::mpsc` message that `main.rs` drains from a
//! `cx.spawn` poll loop running on gpui's own executor.

use std::sync::mpsc::Sender;
use std::sync::Arc;

use gpui::{App, Global};
use vela_desktop_core::host::Host;
use vela_desktop_core::AppState;

/// Bumped whenever vault items changed outside the UI's own knowledge. Views
/// that show item lists `cx.observe_global::<VaultItemsVersion>(...)` and
/// reload — the gpui-native stand-in for the Tauri build's
/// `app.emit("vault-items-changed")`, which the React side listens for the
/// same way.
#[derive(Default)]
pub struct VaultItemsVersion(pub u64);
impl Global for VaultItemsVersion {}

pub fn notify_vault_items_changed(cx: &mut App) {
    let next = cx.default_global::<VaultItemsVersion>().0.wrapping_add(1);
    cx.set_global(VaultItemsVersion(next));
}

/// Matches `src-tauri/tauri.conf.json`'s `identifier` — the portal registry
/// (`org.freedesktop.host.portal.Registry`) keys off this, and the installed
/// `com.vela.vault.desktop` entry has to line up with it for the Wayland
/// global shortcut to bind at all.
pub const APP_IDENTIFIER: &str = "com.vela.vault";

/// Work that has to happen on gpui's foreground executor, requested from a
/// non-gpui thread.
pub enum HostCommand {
    FocusMainWindow,
    OpenQuickSearch,
    /// Vault items changed on disk underneath us (an autofill save from the
    /// browser extension, most commonly) — whatever list view is open should
    /// reload rather than keep showing stale rows. The Tauri build emits a
    /// `vault-items-changed` event for exactly this.
    VaultItemsChanged,
    /// A non-blocking notification in the app's own UI (a credential was just
    /// filled into a browser: "Filled github.com for firefox"). The gpui
    /// build's answer to the Tauri build's `backend-toast` event.
    ShowToast(String),
    /// Ask the human to approve or deny a presence-sensitive action (an in-core
    /// login, a passkey use, a vault reset or key rotation). Carries the
    /// action's title (the modal caption) plus a reply channel back to the
    /// caller, which blocks on it — the gpui build's answer to the Tauri
    /// app's modal.
    ConfirmPresence {
        title: String,
        prompt: String,
        reply: std::sync::mpsc::Sender<Option<bool>>,
    },
}

/// One pending presence-confirmation, shown as a modal over the whole window.
#[derive(Clone)]
pub struct PresencePrompt {
    pub title: String,
    pub prompt: String,
    pub reply: std::sync::mpsc::Sender<Option<bool>>,
}

/// The channel to the window: set by `main.rs`'s command-drain loop when a
/// `ConfirmPresence` arrives, cleared by the modal's buttons when they answer.
#[derive(Default)]
pub struct PresencePromptGlobal(pub Option<PresencePrompt>);
impl Global for PresencePromptGlobal {}

pub struct GpuiHost {
    app_state: Arc<AppState>,
    tx: Sender<HostCommand>,
}

impl GpuiHost {
    pub fn new(app_state: Arc<AppState>, tx: Sender<HostCommand>) -> Self {
        Self { app_state, tx }
    }
}

impl Host for GpuiHost {
    fn state(&self) -> &Arc<AppState> {
        &self.app_state
    }

    fn focus_main_window(&self) {
        let _ = self.tx.send(HostCommand::FocusMainWindow);
    }

    fn app_identifier(&self) -> String {
        APP_IDENTIFIER.to_string()
    }

    fn open_quick_search(&self) {
        let _ = self.tx.send(HostCommand::OpenQuickSearch);
    }

    fn notify_vault_items_changed(&self) {
        let _ = self.tx.send(HostCommand::VaultItemsChanged);
    }

    fn show_toast(&self, message: &str) {
        let _ = self.tx.send(HostCommand::ShowToast(message.to_string()));
    }

    /// Ask the human to approve or deny, and wait for the answer.
    ///
    /// The prompt is handed to the window through the command channel and
    /// rendered as a modal; this call blocks the requesting thread (the IPC
    /// server's) until the human clicks Approve or Deny. A failed send — the
    /// window is gone — reads as "no way to ask", which
    /// [`vela_desktop_core::presence`] refuses.
    fn confirm_presence(&self, title: &str, prompt: &str) -> Option<bool> {
        let (tx, rx) = std::sync::mpsc::channel();
        if self
            .tx
            .send(HostCommand::ConfirmPresence {
                title: title.to_string(),
                prompt: prompt.to_string(),
                reply: tx,
            })
            .is_err()
        {
            return None;
        }
        rx.recv().ok().flatten()
    }
}
