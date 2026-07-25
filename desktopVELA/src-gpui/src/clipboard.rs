//! Shared clipboard helper. On Linux (X11 and Wayland), clipboard content is
//! "hosted" by whichever process last set it — that process is expected to
//! keep serving paste requests from other apps for as long as its content
//! should remain pasteable. Creating a fresh `arboard::Clipboard` per copy
//! and dropping it immediately after `set_text()` (as every call site here
//! originally did) releases that hosting role right away, even though our
//! app process keeps running — so copies appeared to succeed (real
//! `Ok(())`) but nothing was actually left to paste anywhere.
//!
//! Keeping a single `Clipboard` alive for the app's lifetime (thread-local,
//! since `arboard::Clipboard` isn't `Send`/`Sync` and all copies happen on
//! the main UI thread anyway) fixes this without needing arboard's
//! `SetExtLinux::wait()` daemon-forking pattern, which is meant for
//! short-lived CLI tools that exit immediately after copying — not a
//! long-running GUI app like this one.

use std::cell::RefCell;

thread_local! {
    static CLIPBOARD: RefCell<Option<arboard::Clipboard>> = RefCell::new(None);
}

pub fn copy(label: &str, value: &str) {
    CLIPBOARD.with(|cell| {
        let mut cell = cell.borrow_mut();
        if cell.is_none() {
            *cell = arboard::Clipboard::new().ok();
        }
        match cell.as_mut() {
            Some(clipboard) => match clipboard.set_text(value.to_string()) {
                Ok(()) => tracing::info!("Copied {label} to clipboard"),
                Err(e) => tracing::warn!("Failed to copy {label} to clipboard: {e}"),
            },
            None => tracing::warn!("Failed to open system clipboard to copy {label}"),
        }
    });
}
