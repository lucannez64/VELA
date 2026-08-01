//! System clipboard, shared by both desktop front ends.
//!
//! This lives in core rather than in either UI crate for one reason: keeping
//! a copied password out of the OS clipboard *history* takes a different
//! incantation on every platform, and neither front end should have to know
//! them. A password manager that copies a secret the normal way leaks it into
//! Windows' Win+V history (and, with cloud clipboard on, into the user's
//! Microsoft account), into KDE's Klipper, and into whatever `wl-paste
//! --watch` recorder the user runs — cliphist keeps a plaintext database of
//! every clipboard entry it ever saw, and our own auto-clear cannot reach in
//! there to delete anything. Marking the copy as concealed is the only way to
//! stop it being recorded in the first place:
//!
//! * Linux: the `x-kde-passwordManagerHint: secret` MIME type on the offer.
//!   `wl-paste --watch` turns it into `CLIPBOARD_STATE=sensitive` for the
//!   command it spawns, which is what makes cliphist skip storing it.
//! * Windows: the `ExcludeClipboardContentFromMonitorProcessing`,
//!   `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` formats.
//! * macOS: `org.nspasteboard.ConcealedType`, which arboard does not
//!   implement — [`write_secret`] reports [`Conceal::Plain`] there so callers
//!   can tell the difference rather than assume a guarantee they don't have.
//!
//! What deliberately stays out of here: the auto-clear *timers*. Cancelling a
//! pending clear when a new copy supersedes it is the front ends' job (a gpui
//! `Task` in one, a `setTimeout` handle in the other), and both already own
//! that state.

use std::sync::Mutex;

use arboard::Clipboard;
use once_cell::sync::Lazy;
use zeroize::Zeroizing;

/// Whether the clipboard write actually carried a "don't record this" marker.
/// Callers that treat concealment as a security property (rather than a
/// nicety) can log or surface the difference instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conceal {
    /// The platform's clipboard-history exclusion marker was applied.
    Concealed,
    /// Written without a marker — the platform has no convention we can use
    /// (macOS), so a clipboard manager may record it.
    Plain,
}

/// `arboard::Clipboard` is `Send + Sync`, and one long-lived instance is what
/// keeps the copied value pasteable: on Linux the process that last set the
/// clipboard is expected to keep serving paste requests, so dropping the
/// handle right after a copy (as a per-call `Clipboard::new()` would) can
/// release the content while the app is still running. Tauri commands run on
/// arbitrary runtime threads, so this is a process-global rather than a
/// thread-local.
static CLIPBOARD: Lazy<Mutex<Option<Clipboard>>> = Lazy::new(|| Mutex::new(None));

fn with_clipboard<T>(f: impl FnOnce(&mut Clipboard) -> T) -> Option<T> {
    let mut guard = CLIPBOARD.lock().ok()?;
    if guard.is_none() {
        match Clipboard::new() {
            Ok(clipboard) => *guard = Some(clipboard),
            Err(e) => {
                tracing::warn!("Failed to open the system clipboard: {e}");
                return None;
            }
        }
    }
    guard.as_mut().map(f)
}

/// The last value *we* put on the clipboard, so that a later clear can tell
/// our own secret apart from whatever the user has copied from another app
/// since. Kept here rather than in each front end because the comparison rule
/// below is the security-relevant half, and one copy of it is enough — the
/// Tauri side in particular has no other way to know what to expect when the
/// clear comes from the lock button rather than from the copy that scheduled
/// it.
static LAST_WRITTEN: Lazy<Mutex<Option<Zeroizing<String>>>> = Lazy::new(|| Mutex::new(None));

/// Copy a secret, excluded from clipboard history wherever the platform has a
/// convention for that. Returns whether the exclusion actually applied.
pub fn write_secret(text: &str) -> Result<Conceal, String> {
    let concealed = with_clipboard({
        let text = text.to_string();
        move |clipboard| write_concealed(clipboard, text)
    })
    .unwrap_or_else(|| Err("The system clipboard is unavailable".to_string()))?;

    if let Ok(mut last) = LAST_WRITTEN.lock() {
        *last = Some(Zeroizing::new(text.to_string()));
    }
    Ok(concealed)
}

#[cfg(target_os = "linux")]
fn write_concealed(clipboard: &mut Clipboard, text: String) -> Result<Conceal, String> {
    use arboard::SetExtLinux;
    clipboard
        .set()
        .exclude_from_history()
        .text(std::borrow::Cow::Owned(text))
        .map(|()| Conceal::Concealed)
        .map_err(|e| e.to_string())
}

#[cfg(windows)]
fn write_concealed(clipboard: &mut Clipboard, text: String) -> Result<Conceal, String> {
    use arboard::SetExtWindows;
    // `exclude_from_monitoring` covers third-party clipboard managers that
    // watch the clipboard chain; the other two are what keep the secret out of
    // Win+V history and out of cloud clipboard sync to the user's account.
    clipboard
        .set()
        .exclude_from_monitoring()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(std::borrow::Cow::Owned(text))
        .map(|()| Conceal::Concealed)
        .map_err(|e| e.to_string())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn write_concealed(clipboard: &mut Clipboard, text: String) -> Result<Conceal, String> {
    // macOS: arboard has no `org.nspasteboard.ConcealedType` support, so this
    // is an ordinary copy and the caller is told so.
    clipboard
        .set_text(text)
        .map(|()| Conceal::Plain)
        .map_err(|e| e.to_string())
}

/// Current clipboard text, or `None` when it is empty, non-text, or
/// unreadable.
pub fn read() -> Option<String> {
    with_clipboard(|clipboard| clipboard.get_text().ok()).flatten()
}

/// Wipe the clipboard, but only if it still holds the secret we last copied —
/// it must not outlive its auto-clear deadline or the session lock, yet wiping
/// unconditionally would throw away whatever the user copied from another app
/// in the meantime. Returns whether a wipe happened.
///
/// A failed read is treated as "still ours" on purpose: not being able to
/// prove the secret is gone is not a reason to leave it sitting there.
///
/// Forgets the tracked value either way — after this, whatever is on the
/// clipboard is no longer ours to wipe.
pub fn clear_if_ours() -> bool {
    let Some(expected) = LAST_WRITTEN.lock().ok().and_then(|mut last| last.take()) else {
        return false;
    };
    let still_ours = read().is_none_or(|current| current == *expected);
    still_ours && write_text_plain("")
}

fn write_text_plain(text: &str) -> bool {
    let text = text.to_string();
    with_clipboard(move |clipboard| match clipboard.set_text(text) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("Failed to write to the system clipboard: {e}");
            false
        }
    })
    .unwrap_or(false)
}

/// Whether this platform's clipboard can be written without one of our
/// windows holding input focus.
///
/// Only Wayland says no, and only sometimes: `arboard` reaches the Wayland
/// clipboard through the data-control protocol, and on a compositor that
/// doesn't implement it (Mutter, notably) it silently falls back to writing
/// Xwayland's X11 selection — which wlroots-style compositors mirror onto the
/// real clipboard *only* while an Xwayland window has focus, i.e. never, when
/// the copy came from a native Wayland window. A caller that has its own
/// toolkit clipboard (gpui does) should use that instead when this is false.
pub fn supports_focus_independent_write() -> bool {
    #[cfg(target_os = "linux")]
    {
        use once_cell::sync::Lazy as OnceLazy;
        // One compositor roundtrip, cached: the answer cannot change without
        // the session restarting.
        static SUPPORTED: OnceLazy<bool> = OnceLazy::new(probe_data_control);
        return *SUPPORTED;
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

#[cfg(target_os = "linux")]
fn probe_data_control() -> bool {
    use wl_clipboard_rs::utils::{is_primary_selection_supported, PrimarySelectionCheckError};

    // Not a Wayland session: arboard uses the X11 selection, which needs no
    // focus.
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return true;
    }
    // This asks about *primary* selection, but what we actually need out of it
    // is whether a data-control manager was found at all: `Ok(_)` means one
    // was, and so does `NoSeats` (raised only after the manager is bound).
    // `MissingProtocol` is the case that matters — no ext-data-control and no
    // wlr-data-control, so arboard's Wayland backend can't be used.
    let supported = matches!(
        is_primary_selection_supported(),
        Ok(_) | Err(PrimarySelectionCheckError::NoSeats)
    );
    if !supported {
        tracing::info!(
            "No Wayland data-control protocol: clipboard writes need a focused window"
        );
    }
    supported
}
