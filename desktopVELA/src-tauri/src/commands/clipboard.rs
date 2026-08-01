//! Clipboard commands, replacing `@tauri-apps/plugin-clipboard-manager`.
//!
//! The plugin writes text and nothing else, which means a copied password
//! lands in the OS clipboard *history* — Win+V and cloud clipboard on
//! Windows, Klipper or a `wl-paste --watch` recorder on Linux — where our
//! auto-clear can never reach it again. Going through
//! [`vela_desktop_core::clipboard`] instead marks the copy concealed with
//! whatever convention the platform has, and shares the "only wipe it if the
//! clipboard still holds our secret" rule with the gpui build.

use vela_desktop_core::clipboard;

/// Copy a secret, excluded from clipboard history where the platform allows
/// it. Returns whether the exclusion actually applied, so the UI can tell the
/// difference rather than promise something the platform doesn't do.
#[tauri::command]
pub fn copy_secret(text: String) -> Result<bool, String> {
    clipboard::write_secret(&text).map(|conceal| conceal == clipboard::Conceal::Concealed)
}

/// Wipe the clipboard if it still holds the secret we last copied. Returns
/// whether anything was wiped, which is what the UI reports as "Clipboard
/// cleared".
#[tauri::command]
pub fn clear_clipboard() -> bool {
    clipboard::clear_if_ours()
}
