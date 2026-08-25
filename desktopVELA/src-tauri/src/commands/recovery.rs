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
pub async fn seal_trusted_contact_share(
    state: State<'_, Arc<AppState>>,
    contact_public_key_b64: String,
) -> Result<vela_desktop_core::recovery::ContactShareHandoff, String> {
    vela_desktop_core::recovery::seal_trusted_contact_share(&state, &contact_public_key_b64).await
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
pub fn discard_recovery_setup(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    vela_desktop_core::recovery::discard_recovery_setup(&state)
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
    share1_split_id: Option<String>,
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
        share1_split_id,
        credential,
        recovery_id,
        password,
        device_name,
    )
    .await
}

#[tauri::command]
pub fn generate_recovery_request(
) -> Result<vela_desktop_core::recovery::RecoveryRequest, String> {
    vela_desktop_core::recovery::generate_recovery_request()
}

/// M18 trusted-contact recovery: reconstruct from any first-share channel +
/// an authenticated contact response envelope, prove RMS possession, enroll.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn complete_account_recovery_with_contact(
    state: State<'_, Arc<AppState>>,
    user_id: String,
    first_share_b64: String,
    first_share_key_epoch: i64,
    first_share_split_id: Option<String>,
    first_share_channel: vela_desktop_core::recovery::RecoveryShareChannelParam,
    request_secret_key_b64: String,
    contact_response_json: String,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    vela_desktop_core::recovery::complete_account_recovery_with_contact(
        &state,
        user_id,
        first_share_b64,
        first_share_key_epoch,
        first_share_split_id,
        first_share_channel,
        request_secret_key_b64,
        contact_response_json,
        password,
        device_name,
    )
    .await
}
