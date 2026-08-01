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
//! That still wasn't enough on Wayland, because arboard was writing to the
//! wrong clipboard entirely: with default features it has no Wayland backend
//! at all (`wayland-data-control` is opt-in), so every copy went to
//! Xwayland's X11 selection. wlroots-style compositors (Hyprland, sway) only
//! mirror the X11 selection onto the Wayland clipboard while an *Xwayland*
//! surface has keyboard focus — and this app's own window is a native
//! Wayland surface, so at the moment of a copy the mirror is off: the value
//! reaches Xwayland (another X11 client can read it back), `set_text()`
//! returns `Ok(())`, the toast and the log both say "copied", and yet no
//! Wayland app can paste it. Hence the primary path here is gpui's own
//! clipboard, which speaks whichever protocol the platform window is
//! actually using — the same one `gpui_elements`' text fields copy through.
//!
//! gpui's Wayland backend can only set the selection while one of our
//! windows holds focus (a Wayland client needs a serial from an input event
//! it received to do so). Copies are always click- or key-driven, so that
//! holds for them — but the clear-on-lock path can fire while the window is
//! unfocused (idle auto-lock, the tray's Lock item), which is exactly when a
//! copied secret most needs wiping. arboard stays as the fallback for that
//! case only, now built with `wayland-data-control`: the data-control
//! protocol is what clipboard managers use and is deliberately
//! focus-independent.
//!
//! Auto-clear ports `src/hooks/useClipboard.ts`: a copy schedules a clear
//! `clipboard_clear_seconds` later, and a *new* copy cancels the pending
//! clear rather than letting the old timer wipe the new value early (the
//! original does this by keeping the timer handle in `AppContext` rather
//! than a per-component ref, for exactly the same reason — here the
//! equivalent shared home is a gpui `Global`).

use std::cell::RefCell;
use std::time::Duration;

use gpui::{App, ClipboardItem, Global, Task};

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
    /// The last value *we* placed on the clipboard. Lets `clear()` wipe a
    /// copied secret on lock even when auto-clear is "Never" (no pending
    /// timer), and lets both `clear()` and the auto-clear timer avoid
    /// stomping content the user has since copied from another app: the wipe
    /// only happens when the clipboard still holds exactly this value.
    last_value: Option<String>,
}
impl Global for ClipboardState {}

/// `0` disables auto-clear entirely (the original's Settings screen offers a
/// "Never" option, which stores 0).
pub fn set_clear_seconds(cx: &mut App, seconds: u32) {
    cx.default_global::<ClipboardState>().clear_seconds = Some(seconds);
}

fn write_text(cx: &mut App, label: &str, value: &str) -> bool {
    // `active_window()` is the Wayland backend's own `keyboard_focused_window`
    // — i.e. exactly the condition under which its `write_to_clipboard` does
    // anything at all. Checking it here is what turns that silent no-op into
    // a fall-through to the focus-independent backend below.
    if cx.active_window().is_some() {
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        return true;
    }
    write_text_unfocused(label, value)
}

/// arboard fallback for writes made with no focused window — see the module
/// doc. On X11 and on compositors without a data-control protocol this is the
/// same X11 selection write as before; on wlroots-style Wayland it goes
/// through `wayland-data-control` and works regardless of focus.
fn write_text_unfocused(label: &str, value: &str) -> bool {
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
    if !write_text(cx, label, value) {
        toast::show(cx, "Failed to copy", ToastKind::Error);
        return;
    }
    tracing::info!("Copied {label} to clipboard");

    {
        let state = cx.global_mut::<ClipboardState>();
        state.last_value = Some(value.to_string());
        // Any previous copy's pending clear is superseded below (or right
        // here for "Never") — otherwise an earlier timer would wipe this
        // newly-copied value out from under the user.
        state._clear_task = None;
    }

    let seconds = cx
        .default_global::<ClipboardState>()
        .clear_seconds
        .unwrap_or(DEFAULT_CLEAR_SECONDS);

    if seconds == 0 {
        toast::show(cx, format!("{label} copied"), ToastKind::Success);
        return;
    }

    toast::show(cx, format!("{label} copied (clears in {seconds}s)"), ToastKind::Success);

    let task = cx.spawn(async move |cx| {
        cx.background_executor().timer(Duration::from_secs(seconds as u64)).await;
        cx.update(|cx| {
            if clear_if_ours(cx) {
                tracing::info!("Clipboard auto-cleared");
                toast::show(cx, "Clipboard cleared", ToastKind::Info);
            }
            cx.global_mut::<ClipboardState>()._clear_task = None;
        });
    });
    cx.global_mut::<ClipboardState>()._clear_task = Some(task);
}

/// Wipe the clipboard only if it still holds exactly what we last copied —
/// never stomp content the user has since copied from another app. Returns
/// true when a wipe happened. Clears `last_value` either way: after this,
/// whatever is on the clipboard is no longer ours to track.
fn clear_if_ours(cx: &mut App) -> bool {
    let Some(last_value) = cx.global_mut::<ClipboardState>().last_value.take() else {
        return false;
    };
    // A read failure means we can't prove the content moved on — fail closed
    // and wipe (a copied secret must not linger because of a clipboard quirk).
    // Reading through gpui matters as much as writing through it: read and
    // write have to name the same clipboard, or every check here would compare
    // against whatever unrelated value Xwayland's selection happens to hold.
    let still_ours = read_text(cx).map_or(true, |current| current == last_value);
    still_ours && write_text(cx, "clipboard", "")
}

fn read_text(cx: &App) -> Option<String> {
    cx.read_from_clipboard().and_then(|item| item.text())
}

/// Immediate clear + cancel of any pending timer — ports `useClipboard.ts`'s
/// `clearClipboard`, called when the session locks so a copied secret can't
/// outlive the unlocked session.
pub fn clear(cx: &mut App) {
    cx.global_mut::<ClipboardState>()._clear_task = None;
    if clear_if_ours(cx) {
        tracing::info!("Clipboard cleared on lock");
    }
}
