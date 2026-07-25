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
//!
//! Auto-clear ports `src/hooks/useClipboard.ts`: a copy schedules a clear
//! `clipboard_clear_seconds` later, and a *new* copy cancels the pending
//! clear rather than letting the old timer wipe the new value early (the
//! original does this by keeping the timer handle in `AppContext` rather
//! than a per-component ref, for exactly the same reason — here the
//! equivalent shared home is a gpui `Global`).

use std::cell::RefCell;
use std::time::Duration;

use gpui::{App, Global, Task};

use crate::toast::{self, ToastKind};

thread_local! {
    static CLIPBOARD: RefCell<Option<arboard::Clipboard>> = RefCell::new(None);
}

/// Fallback matching `useClipboard.ts`'s `?? 30` when settings haven't been
/// loaded yet.
const DEFAULT_CLEAR_SECONDS: u32 = 30;

#[derive(Default)]
struct ClipboardState {
    /// Mirrors the real `Settings::clipboard_clear_seconds`, refreshed by
    /// [`set_clear_seconds`] at startup and on every settings save, so a copy
    /// doesn't have to re-read settings off disk.
    clear_seconds: Option<u32>,
    /// Dropping this cancels a pending clear — that's how a new copy
    /// supersedes the previous one's timer.
    _clear_task: Option<Task<()>>,
}
impl Global for ClipboardState {}

/// `0` disables auto-clear entirely (the original's Settings screen offers a
/// "Never" option, which stores 0).
pub fn set_clear_seconds(cx: &mut App, seconds: u32) {
    cx.default_global::<ClipboardState>().clear_seconds = Some(seconds);
}

fn write_text(label: &str, value: &str) -> bool {
    CLIPBOARD.with(|cell| {
        let mut cell = cell.borrow_mut();
        if cell.is_none() {
            *cell = arboard::Clipboard::new().ok();
        }
        match cell.as_mut() {
            Some(clipboard) => match clipboard.set_text(value.to_string()) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!("Failed to copy {label} to clipboard: {e}");
                    false
                }
            },
            None => {
                tracing::warn!("Failed to open system clipboard to copy {label}");
                false
            }
        }
    })
}

pub fn copy(cx: &mut App, label: &str, value: &str) {
    if !write_text(label, value) {
        toast::show(cx, "Failed to copy", ToastKind::Error);
        return;
    }
    tracing::info!("Copied {label} to clipboard");

    let seconds = cx
        .default_global::<ClipboardState>()
        .clear_seconds
        .unwrap_or(DEFAULT_CLEAR_SECONDS);

    if seconds == 0 {
        toast::show(cx, format!("{label} copied"), ToastKind::Success);
        // Still cancel any *previous* copy's pending clear — otherwise an
        // earlier timer would wipe this newly-copied value out from under
        // the user.
        cx.global_mut::<ClipboardState>()._clear_task = None;
        return;
    }

    toast::show(cx, format!("{label} copied (clears in {seconds}s)"), ToastKind::Success);

    let task = cx.spawn(async move |cx| {
        cx.background_executor().timer(Duration::from_secs(seconds as u64)).await;
        cx.update(|cx| {
            if write_text("clipboard", "") {
                tracing::info!("Clipboard auto-cleared");
                toast::show(cx, "Clipboard cleared", ToastKind::Info);
            }
            cx.global_mut::<ClipboardState>()._clear_task = None;
        });
    });
    cx.global_mut::<ClipboardState>()._clear_task = Some(task);
}

/// Immediate clear + cancel of any pending timer — ports `useClipboard.ts`'s
/// `clearClipboard`, called when the session locks so a copied secret can't
/// outlive the unlocked session.
pub fn clear(cx: &mut App) {
    // Only clear if *we* put something there and it's still pending — with no
    // pending timer there's nothing of ours on the clipboard, and wiping it
    // anyway would stomp on whatever the user copied from another app in the
    // meantime.
    let has_pending = cx
        .try_global::<ClipboardState>()
        .is_some_and(|state| state._clear_task.is_some());
    if !has_pending {
        return;
    }
    cx.global_mut::<ClipboardState>()._clear_task = None;
    if write_text("clipboard", "") {
        tracing::info!("Clipboard cleared on lock");
    }
}
