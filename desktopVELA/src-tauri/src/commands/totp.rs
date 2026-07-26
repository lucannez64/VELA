use tauri::command;
pub use vela_desktop_core::totp::TotpCode;

#[command]
pub async fn generate_totp(secret: String) -> Result<TotpCode, String> {
    vela_desktop_core::totp::generate_totp(secret)
}

#[command]
pub async fn verify_totp(secret: String, code: String) -> Result<bool, String> {
    vela_desktop_core::totp::verify_totp(secret, code)
}
