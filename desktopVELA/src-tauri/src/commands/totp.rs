use std::sync::Arc;
use tauri::{command, State};
use vela_desktop_core::AppState;
pub use vela_desktop_core::totp::TotpCode;

/// Both commands refuse while the vault is locked.
///
/// They take the secret from the caller, so they leak nothing by themselves —
/// but a locked vault should not be lending its process out as a TOTP oracle to
/// whatever can reach the IPC, and the only legitimate caller is the item
/// detail view, which is unreachable while locked.
fn require_unlocked(state: &Arc<AppState>) -> Result<(), String> {
    if state.is_unlocked() {
        Ok(())
    } else {
        Err("Vault is locked".to_string())
    }
}

#[command]
pub async fn generate_totp(
    state: State<'_, Arc<AppState>>,
    secret: String,
) -> Result<TotpCode, String> {
    require_unlocked(&state)?;
    vela_desktop_core::totp::generate_totp(secret)
}

#[command]
pub async fn verify_totp(
    state: State<'_, Arc<AppState>>,
    secret: String,
    code: String,
) -> Result<bool, String> {
    require_unlocked(&state)?;
    vela_desktop_core::totp::verify_totp(secret, code)
}
