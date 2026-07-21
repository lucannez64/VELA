//! Post-recovery device enrollment (SPEC.md §4.3).
//!
//! Normal device enrollment (`/device/enroll`) requires an already-authorized
//! device to sign the new device's key material (§4.2) — but a device going
//! through account recovery has, by definition, no other enrolled device
//! available. Authorization here instead comes from the single-use
//! `recovery_grant` issued by `/recovery/recover`, which only exists after
//! this caller passed a WebAuthn-gated assertion for `user_id`. The new
//! device already reconstructed the RMS locally from Share 1 + Share 2, so
//! unlike `/device/enroll` there is no `rms_capsule` to deliver — this
//! endpoint only needs to register the device's identity key so it can
//! authenticate normally afterwards via `/auth/challenge` + `/auth/verify`.

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    state::AppState,
};

const HYBRID_EK_LEN: usize = 1568 + 32;
const HYBRID_VK_LEN: usize = 2592 + 32;

#[derive(Deserialize)]
pub struct EnrollDeviceRequest {
    pub user_id: Uuid,
    pub recovery_grant: Uuid,
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Serialize)]
pub struct EnrollDeviceResponse {
    pub device_id: Uuid,
}

pub async fn post_enroll_device(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<EnrollDeviceRequest>,
) -> Result<Json<EnrollDeviceResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::check(&state.store, &format!("rl:recover:enroll:ip:{ip}"), 10, 3600)?;
    rate_limit::check(
        &state.store,
        &format!("rl:recover:enroll:user:{}", body.user_id),
        5,
        3600,
    )?;

    // Consumes the grant — a second call with the same grant fails here,
    // so a recovering user can only ever mint one new device per successful
    // WebAuthn-gated recovery.
    crate::recovery::recover::take_enroll_grant(&state, body.user_id, body.recovery_grant)?;

    let hybrid_ek = B64
        .decode(&body.hybrid_ek)
        .map_err(|_| AppError::BadRequest("hybrid_ek is not valid base64".into()))?;
    let hybrid_vk = B64
        .decode(&body.hybrid_vk)
        .map_err(|_| AppError::BadRequest("hybrid_vk is not valid base64".into()))?;

    if hybrid_ek.len() != HYBRID_EK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_ek must be {HYBRID_EK_LEN} bytes"
        )));
    }
    if hybrid_vk.len() != HYBRID_VK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_vk must be {HYBRID_VK_LEN} bytes"
        )));
    }

    // The grant already proved `user_id` exists and completed recovery, but
    // a deleted-account race between /recovery/recover and this call is
    // still possible in principle — fail closed rather than orphan a device
    // row under a FK that no longer resolves.
    let user_rows = state
        .db
        .query(
            "SELECT id FROM users WHERE id = $1",
            stoolap::params![body.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if user_rows.into_iter().next().is_none() {
        return Err(AppError::NotFound("account no longer exists".into()));
    }

    let new_device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let device_name = body
        .device_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Recovered Device".to_string());
    let device_type = body
        .device_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    state
        .db
        .execute(
            "INSERT INTO devices
             (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
             VALUES ($1, $2, $3, $4, NULL, $5, $6, NULL, $7)",
            stoolap::params![
                new_device_id.to_string(),
                body.user_id.to_string(),
                device_name,
                device_type,
                crate::db::encode_b64(&hybrid_ek),
                crate::db::encode_b64(&hybrid_vk),
                now,
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(
        new_device_id = %new_device_id,
        user_id = %body.user_id,
        "device enrolled via account recovery"
    );

    Ok(Json(EnrollDeviceResponse {
        device_id: new_device_id,
    }))
}
