use crate::biometric::{
    authenticate as do_auth, authenticate_with_password as do_auth_password,
    check_enrollment as do_check, store_password_encrypted, BiometricAuthResult,
    BiometricEnrollmentStatus,
};
use tauri::command;

#[command]
pub async fn authenticate() -> Result<BiometricAuthResult, String> {
    tokio::task::spawn_blocking(|| do_auth())
        .await
        .map_err(|e| format!("Authenticate task panicked: {}", e))
}

#[command]
pub async fn authenticate_password(password: String) -> Result<BiometricAuthResult, String> {
    tokio::task::spawn_blocking(move || match do_auth_password(&password) {
        Some(_) => Ok(BiometricAuthResult {
            success: true,
            error_message: None,
            retry_count: None,
            uses_password: true,
        }),
        None => Ok(BiometricAuthResult {
            success: false,
            error_message: Some("Invalid password or credential not found".to_string()),
            retry_count: None,
            uses_password: true,
        }),
    })
    .await
    .map_err(|e| format!("Password auth task panicked: {}", e))?
}

#[command]
pub async fn check_enrollment() -> Result<BiometricEnrollmentStatus, String> {
    tokio::task::spawn_blocking(|| do_check())
        .await
        .map_err(|e| format!("Check enrollment task panicked: {}", e))
}

#[command]
pub async fn enroll() -> Result<BiometricEnrollmentStatus, String> {
    Ok(BiometricEnrollmentStatus {
        enrolled: true,
        provider: crate::biometric::BiometricProvider::WindowsHello,
    })
}

#[command]
pub async fn setup_password_recovery(password: String, rms: Vec<u8>) -> Result<(), String> {
    let rms_array: [u8; 32] = rms.try_into().map_err(|_| "RMS must be 32 bytes")?;
    tokio::task::spawn_blocking(move || {
        store_password_encrypted(&rms_array, &password)
            .map_err(|e| format!("Failed to store password recovery: {}", e))
    })
    .await
    .map_err(|e| format!("Password recovery task panicked: {}", e))?
}
