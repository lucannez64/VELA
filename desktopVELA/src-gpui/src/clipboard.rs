//! Clipboard copies, with the auto-clear timer and toasts that go with them.
//!
//! The platform side of this — which clipboard to write, and how to keep a
//! copied secret out of the OS clipboard history — lives in
//! [`vela_desktop_core::clipboard`], shared with the Tauri build. What stays
//! here is the part that is genuinely gpui's: the timer that supersedes the
//! previous copy's pending clear (a `Task` in a `Global`, mirroring how the
//! original keeps the handle in `AppContext` rather than a per-component ref),
//! the toasts, and one fallback described below.
//!
//! The fallback exists because arboard cannot reach the Wayland clipboard on
//! a compositor without the data-control protocol (Mutter); it falls back to
//! Xwayland's X11 selection, which wlroots-style compositors mirror onto the
//! real clipboard only while an Xwayland window has focus — never, when the
//! copy came from our own native Wayland window. That was the original
//! "copied successfully, nothing to paste" bug. Where core reports it cannot
//! do a focus-independent write, we use gpui's own clipboard instead, which
//! speaks whatever protocol the platform window is actually using. Its
//! Wayland backend can only set the selection while one of our windows holds
//! focus (a Wayland client needs a serial from an input event to do so),
//! which every click-driven copy has — but a clear triggered by idle
//! auto-lock does not, hence the warning rather than a silent no-op.
//!
//! Auto-clear ports `src/hooks/useClipboard.ts`: a copy schedules a clear
//! `clipboard_clear_seconds` later, and a *new* copy cancels the pending
//! clear rather than letting the old timer wipe the new value early.

use std::time::Duration;

use gpui::{App, ClipboardItem, Global, Task};
use vela_desktop_core::clipboard as sys;

use crate::toast::{self, ToastKind};

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
    /// The last value we wrote *through gpui* — only the fallback path below
    /// needs this. Core tracks what it wrote itself, but it cannot track (or
    /// later read back) a value that went through gpui's clipboard instead of
    /// arboard's, so the fallback keeps its own copy to compare against.
    fallback_last_value: Option<String>,
}
impl Global for ClipboardState {}

/// `0` disables auto-clear entirely (the original's Settings screen offers a
/// "Never" option, which stores 0).
pub fn set_clear_seconds(cx: &mut App, seconds: u32) {
    cx.default_global::<ClipboardState>().clear_seconds = Some(seconds);
}

fn write_text(cx: &mut App, label: &str, value: &str) -> bool {
    if sys::supports_focus_independent_write() {
        // Core remembers what it wrote, so `clear_if_ours` needs nothing here.
        return match sys::write_secret(value) {
            Ok(sys::Conceal::Concealed) => true,
            Ok(sys::Conceal::Plain) => {
                tracing::debug!("Copied {label} without a clipboard-history exclusion marker");
                true
            }
            Err(e) => {
                tracing::warn!("Failed to copy {label} to clipboard: {e}");
                false
            }
        };
    }
    if cx.active_window().is_some() {
        // No concealment available on this path — gpui's data source offers
        // the text MIME types only, so a clipboard manager here will record
        // the value.
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        cx.default_global::<ClipboardState>().fallback_last_value =
            Some(value.to_string()).filter(|v| !v.is_empty());
        return true;
    }
    tracing::warn!("Cannot write {label} to the clipboard with no focused window");
    false
}

fn read_text(cx: &App) -> Option<String> {
    if sys::supports_focus_independent_write() {
        return sys::read();
    }
    cx.read_from_clipboard().and_then(|item| item.text())
}

pub fn copy(cx: &mut App, label: &str, value: &str) {
    if !write_text(cx, label, value) {
        toast::show(cx, "Failed to copy", ToastKind::Error);
        return;
    }
    tracing::info!("Copied {label} to clipboard");

    // Any previous copy's pending clear is superseded below (or right here for
    // "Never") — otherwise an earlier timer would wipe this newly-copied value
    // out from under the user.
    cx.global_mut::<ClipboardState>()._clear_task = None;

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
    if sys::supports_focus_independent_write() {
        return sys::clear_if_ours();
    }
    let Some(last_value) = cx.global_mut::<ClipboardState>().fallback_last_value.take() else {
        return false;
    };
    // A read failure means we can't prove the content moved on — fail closed
    // and wipe (a copied secret must not linger because of a clipboard quirk).
    let still_ours = read_text(cx).is_none_or(|current| current == last_value);
    still_ours && write_text(cx, "clipboard", "")
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
