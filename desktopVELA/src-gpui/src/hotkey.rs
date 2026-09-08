//! Windows global shortcut for the quick-search popup, via the
//! `global-hotkey` crate — the same `RegisterHotKey` engine the Tauri build's
//! `tauri-plugin-global-shortcut` ("plugin" backend) uses underneath, so the
//! binding behaves exactly like the shipped Tauri app's.
//!
//! Runs on its own thread because `RegisterHotKey` is bound to the message
//! queue of the thread that registered it: the docs require the manager to
//! be created on a thread pumping Win32 messages, and gpui's main loop is
//! not that thread. This module owns such a thread: it creates the manager,
//! runs a blocking `GetMessageW` loop, and forwards activations to the UI
//! through the same `Host` → `HostCommand` channel-plus-poll-loop hop the
//! IPC server and the Wayland portal shortcut client use — see `host.rs`.

use std::sync::Arc;

use global_hotkey::hotkey::HotKey;
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
use tracing::{error, info};

use vela_desktop_core::host::Host;

/// Register the quick-search shortcut and dispatch its activations for the
/// lifetime of the app, on a dedicated thread. Never joined; failures are
/// logged and non-fatal, exactly like the Wayland portal path — the app runs
/// without a global shortcut rather than failing to start.
pub fn spawn(host: Arc<dyn Host>, shortcut: String) {
    std::thread::Builder::new()
        .name("global-hotkey".into())
        .spawn(move || {
            if let Err(e) = run(&*host, &shortcut) {
                error!(
                    "Quick search global shortcut unavailable ({e}). The app continues \
                     without it; check the configured shortcut in Settings."
                );
            }
        })
        .expect("failed to spawn global hotkey thread");
}

fn run(host: &dyn Host, shortcut: &str) -> Result<(), String> {
    // The crate's parser accepts the stored accelerator format directly
    // ("Ctrl+Alt+V", including the CmdOrCtrl/Option aliases) — no translation
    // step needed, unlike the Wayland portal's trigger format.
    let hotkey: HotKey = shortcut
        .parse()
        .map_err(|e| format!("'{shortcut}' is not a usable accelerator: {e}"))?;
    let manager =
        GlobalHotKeyManager::new().map_err(|e| format!("creating the hotkey manager: {e}"))?;
    manager
        .register(hotkey)
        .map_err(|e| format!("registering '{shortcut}': {e}"))?;
    info!("Global quick-search shortcut registered: {shortcut}");

    let receiver = GlobalHotKeyEvent::receiver();
    let mut msg: windows_sys::Win32::UI::WindowsAndMessaging::MSG = unsafe { std::mem::zeroed() };
    loop {
        // The crate's window proc runs on this thread during
        // `DispatchMessageW` below and pushes events onto the process-wide
        // channel, so draining right after each dispatch cannot miss one.
        while let Ok(event) = receiver.try_recv() {
            if event.id == hotkey.id() && event.state() == HotKeyState::Pressed {
                info!("Global shortcut triggered: Quick search overlay");
                // A dedicated popup window rather than the main one, same as
                // the Wayland path — the popup opens where the user is
                // instead of dragging the whole app to the front.
                host.open_quick_search();
            }
        }

        // Block on the Win32 message queue: wakes only for a real message
        // (WM_HOTKEY arrives through the window proc registered by the
        // manager), so this idles at zero CPU.
        let result = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::GetMessageW(
                &mut msg,
                std::ptr::null_mut(),
                0,
                0,
            )
        };
        if result <= 0 {
            // 0 = WM_QUIT (nobody posts one to this thread), -1 = error.
            // Either way there is no message queue left to serve, so the
            // shortcut can never fire again. Park forever rather than
            // returning: dropping the `manager` would unregister the hotkey
            // while the rest of the app (and its Settings screen) still
            // believes it is live.
            if result < 0 {
                error!(
                    "Win32 message loop failed (GetMessageW error); the global \
                     shortcut is dead for this session"
                );
            }
            loop {
                std::thread::park();
            }
        }
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
            windows_sys::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_shortcut_parses() {
        let hotkey: HotKey = "Ctrl+Alt+V".parse().expect("default should parse");
        assert_eq!(hotkey.id(), "Ctrl+Alt+V".parse::<HotKey>().unwrap().id());
    }

    #[test]
    fn stored_shortcut_formats_parse() {
        for shortcut in [
            "Ctrl+Alt+V",
            "Ctrl+Shift+F",
            "Alt+F9",
            "Ctrl+Shift+Alt+P",
            "Super+Space",
            "CmdOrCtrl+K",
        ] {
            assert!(
                shortcut.parse::<HotKey>().is_ok(),
                "{shortcut} should parse"
            );
        }
    }

    #[test]
    fn different_shortcuts_get_different_ids() {
        let a: HotKey = "Ctrl+Alt+V".parse().unwrap();
        let b: HotKey = "Ctrl+Alt+B".parse().unwrap();
        assert_ne!(a.id(), b.id());
    }
}
