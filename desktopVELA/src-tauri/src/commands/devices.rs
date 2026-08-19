//! `#[tauri::command]` wrappers for device management and enrollment.
//!
//! Both enrollment generations live in `vela_desktop_core` — v2 in
//! [`vela_desktop_core::commands::devices`], v3 in
//! [`vela_desktop_core::commands::enrollment_v3`] — so the gpui build runs
//! exactly the same code. In particular neither the correct fingerprint nor
//! any private key is reachable from this layer: the frontend receives a
//! shuffled list of candidates and answers by value.
//!
//! The v2 commands stay registered alongside v3. Enrollment codes are
//! ephemeral, so nothing stored needs migrating, but installs mix: a v2
//! primary and a v3 joiner have to keep working until old builds age out.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;

pub use vela_desktop_core::commands::devices::{Device, DeviceType};

/// The renderer's `revoke_device` argument. `confirm` exists so that a
/// mis-routed IPC call cannot revoke a device without the UI having asked;
/// it is checked here rather than in core because it guards *this* boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub device_id: String,
    pub confirm: bool,
}

// ── devices ──────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_devices(state: State<'_, Arc<AppState>>) -> Result<Vec<Device>, String> {
    vela_desktop_core::commands::devices::get_devices(&state).await
}

#[tauri::command]
pub async fn revoke_device(
    state: State<'_, Arc<AppState>>,
    request: RevokeRequest,
) -> Result<(), String> {
    if !request.confirm {
        return Err("Revocation must be confirmed".to_string());
    }
    vela_desktop_core::commands::devices::revoke_device(&state, &request.device_id).await
}

// ── enrollment v2 ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn generate_enrollment_code(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    vela_desktop_core::commands::devices::generate_enrollment_code(&state).await
}

#[tauri::command]
pub fn enrollment_verification_code(code: String) -> String {
    vela_desktop_core::commands::devices::enrollment_verification_code(&code)
}

#[tauri::command]
pub async fn import_enrollment_code(
    state: State<'_, Arc<AppState>>,
    code: String,
    password: String,
) -> Result<(), String> {
    vela_desktop_core::commands::devices::import_enrollment_code(&state, code, password).await
}

// ── enrollment v3 (audit P-1) ────────────────────────────────────────────

/// Primary: open a grant and return the code to display as a QR.
#[tauri::command]
pub async fn open_enrollment_invite(
    state: State<'_, Arc<AppState>>,
) -> Result<vela_desktop_core::commands::enrollment_v3::EnrollmentInvite, String> {
    vela_desktop_core::commands::enrollment_v3::open_enrollment_invite(&state).await
}

/// Primary: has a device claimed the code yet? `None` means not yet.
///
/// Once one has, this returns the same candidate list on every call — it is
/// computed once and cached, so polling cannot reshuffle the choices under the
/// user's finger.
#[tauri::command]
pub async fn poll_enrollment_claim(
    state: State<'_, Arc<AppState>>,
    grant_id: String,
) -> Result<Option<vela_desktop_core::commands::enrollment_v3::ClaimedDevice>, String> {
    vela_desktop_core::commands::enrollment_v3::poll_enrollment_claim(&state, &grant_id).await
}

/// Primary: the user picked `chosen` from the candidates. If it is the one the
/// joining device is really showing, enrol it; otherwise the enrollment is
/// cancelled outright rather than offering another guess.
#[tauri::command]
pub async fn confirm_enrollment(
    state: State<'_, Arc<AppState>>,
    grant_id: String,
    chosen: String,
) -> Result<String, String> {
    vela_desktop_core::commands::enrollment_v3::confirm_enrollment(&state, &grant_id, &chosen).await
}

#[tauri::command]
pub fn cancel_enrollment(state: State<'_, Arc<AppState>>) {
    vela_desktop_core::commands::enrollment_v3::cancel_enrollment(&state)
}

/// Joining: generate this device's keypair, claim the grant with its public
/// half, and return the fingerprint to display.
///
/// That fingerprint is computed in-process from the key just generated. The
/// frontend must render what this returns and never a value from elsewhere.
#[tauri::command]
pub async fn begin_enrollment_join(
    state: State<'_, Arc<AppState>>,
    code: String,
) -> Result<vela_desktop_core::commands::enrollment_v3::JoinRequest, String> {
    vela_desktop_core::commands::enrollment_v3::begin_enrollment_join(&state, &code).await
}

/// Joining: has the primary confirmed yet?
#[tauri::command]
pub async fn poll_enrollment_join(
    state: State<'_, Arc<AppState>>,
    grant_id: String,
) -> Result<vela_desktop_core::commands::enrollment_v3::JoinStatus, String> {
    vela_desktop_core::commands::enrollment_v3::poll_enrollment_join(&state, &grant_id).await
}

/// Joining: open the capsule sealed to this device and bring the vault down.
#[tauri::command]
pub async fn finish_enrollment_join(
    state: State<'_, Arc<AppState>>,
    grant_id: String,
    password: String,
) -> Result<(), String> {
    vela_desktop_core::commands::enrollment_v3::finish_enrollment_join(&state, &grant_id, password)
        .await
}

#[tauri::command]
pub fn cancel_enrollment_join(state: State<'_, Arc<AppState>>) {
    vela_desktop_core::commands::enrollment_v3::cancel_enrollment_join(&state)
}

/// Whether a scanned or pasted code is a v3 one, so the frontend knows which
/// flow to run. Both are live until old installs age out.
#[tauri::command]
pub fn is_v3_enrollment_code(code: String) -> bool {
    vela_desktop_core::commands::enrollment_v3::is_v3_enrollment_code(&code)
}
