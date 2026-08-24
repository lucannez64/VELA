//! `#[tauri::command]` wrappers for recovery setup and account recovery.
//!
//! The 2-of-3 Shamir split and all three delivery channels — cloud backup,
//! the server share behind a WebAuthn credential, and the trusted-contact
//! share — live in [`vela_desktop_core::recovery`].

use std::sync::Arc;

use tauri::State;

use crate::AppState;

pub use vela_desktop_core::recovery::{CloudRecoveryShare, RecoveryStatus};

#[tauri::command]
pub async fn list_cloud_backup_remotes() -> Result<Vec<String>, String> {
    vela_desktop_core::recovery::list_cloud_backup_remotes().await
}

#[tauri::command]
pub async fn setup_cloud_backup_recovery(
    state: State<'_, Arc<AppState>>,
    remote: String,
) -> Result<(), String> {
    vela_desktop_core::recovery::setup_cloud_backup_recovery(&state, remote).await
}

#[tauri::command]
pub async fn get_trusted_contact_share(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    vela_desktop_core::recovery::get_trusted_contact_share(&state).await
}

#[tauri::command]
pub async fn acknowledge_trusted_contact_share(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    vela_desktop_core::recovery::acknowledge_trusted_contact_share(&state).await
}

#[tauri::command]
pub async fn get_recovery_setup_status(
    state: State<'_, Arc<AppState>>,
) -> Result<RecoveryStatus, String> {
    vela_desktop_core::recovery::get_recovery_setup_status(&state)
}

#[tauri::command]
pub async fn finalize_recovery_setup(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    vela_desktop_core::recovery::finalize_recovery_setup(&state).await
}

#[tauri::command]
pub async fn fetch_cloud_recovery_shares(
    remote: String,
) -> Result<Vec<CloudRecoveryShare>, String> {
    vela_desktop_core::recovery::fetch_cloud_recovery_shares(remote).await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn complete_account_recovery(
    state: State<'_, Arc<AppState>>,
    user_id: String,
    share1_b64: String,
    share1_key_epoch: i64,
    credential: serde_json::Value,
    recovery_id: Option<String>,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    vela_desktop_core::recovery::complete_account_recovery_with_credential(
        &state,
        user_id,
        share1_b64,
        share1_key_epoch,
        credential,
        recovery_id,
        password,
        device_name,
    )
    .await
}
