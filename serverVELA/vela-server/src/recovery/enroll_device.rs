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
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

const HYBRID_EK_LEN: usize = 1568 + 32;
const HYBRID_VK_LEN: usize = 2592 + 32;
const ENROLL_GRANT_TTL_SECS: u64 = 600;

fn enroll_grant_key(user_id: Uuid, grant: Uuid) -> String {
    format!("recovery:enroll_grant:{user_id}:{grant}")
}

fn restore_enroll_grant(state: &AppState, user_id: Uuid, grant: Uuid) -> Result<()> {
    state.store.set_ex(
        &enroll_grant_key(user_id, grant),
        b"1",
        ENROLL_GRANT_TTL_SECS,
    )
}

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
    // Keyed on the caller as well as the target (red-team RT-1) — see the note
    // in `recover.rs`. This check also runs before the grant is verified, so the
    // per-user-only form was spendable with a garbage body.
    rate_limit::recovery_enroll_by_ip_user(&state.store, &ip, &body.user_id.to_string())?;
    rate_limit::recovery_enroll_by_user(&state.store, &body.user_id.to_string())?;

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

    // Do not reveal account or rotation state unless the caller possesses the
    // unguessable grant. This is only a non-consuming proof; redemption below
    // remains atomic and single-use.
    if !state
        .store
        .exists(&enroll_grant_key(body.user_id, body.recovery_grant))?
    {
        return Err(AppError::Unauthorized(
            "recovery grant expired or already used".into(),
        ));
    }

    // The grant already proved `user_id` exists and completed recovery, but
    // a deleted-account race between /recovery/recover and this call is
    // still possible in principle — fail closed rather than orphan a device
    // row under a FK that no longer resolves.
    let user_rows = state
        .sqldb
        .query(
            "SELECT rekey_state FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if user_rows.first().is_none() {
        return Err(AppError::NotFound("account no longer exists".into()));
    }
    if user_rows.first().and_then(|row| row.text(0)).is_some() {
        return Err(AppError::Conflict(
            "device enrollment is paused during vault key rotation".into(),
        ));
    }

    // Consume only after validation and the fast rotation check. The guarded
    // insert below remains the authority for a concurrent rotation; if that
    // race is lost, the grant is restored so the user can retry afterwards.
    crate::recovery::recover::take_enroll_grant(&state, body.user_id, body.recovery_grant)?;

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

    let inserted = state
        .sqldb
        .execute(
            "INSERT INTO devices
             (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
             SELECT ?, ?, ?, ?, NULL, ?, ?, NULL, ?
             WHERE EXISTS (
                 SELECT 1 FROM users WHERE id = ? AND rekey_state IS NULL
             )",
            vec![
                TursoValue::Text(new_device_id.to_string()),
                TursoValue::Text(body.user_id.to_string()),
                TursoValue::Text(device_name),
                TursoValue::Text(device_type),
                TursoValue::Text(crate::db::encode_b64(&hybrid_ek)),
                TursoValue::Text(crate::db::encode_b64(&hybrid_vk)),
                TursoValue::Text(now),
                TursoValue::Text(body.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if inserted == 0 {
        restore_enroll_grant(&state, body.user_id, body.recovery_grant)?;
        return Err(AppError::Conflict(
            "device enrollment is paused during vault key rotation".into(),
        ));
    }

    tracing::info!(
        new_device_id = %new_device_id,
        user_id = %body.user_id,
        "device enrolled via account recovery"
    );

    Ok(Json(EnrollDeviceResponse {
        device_id: new_device_id,
    }))
}
