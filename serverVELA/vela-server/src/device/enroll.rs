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
use vela_rekey_policy::{MutationAuthority, MutationDecision, MutationKind, MutationRequest};

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

/// One message for every "this device did not authenticate" case.
///
/// `/auth/verify` and `/device/enroll` both used to answer "no such device" and
/// "that signature is wrong" differently, which told an anonymous caller whether
/// a device id exists. `/auth/verify` had already collapsed its not-found arm to
/// this wording — the three possibilities are named deliberately — but the
/// signature arm returned the helper's own message and undid it, so the
/// hardening was half applied on one endpoint and absent on the other.
///
/// This does not close the timing side of the same question: a miss returns
/// after one lookup, a hit after an ML-DSA-87 verification. Equalising that
/// means verifying against a dummy key on the miss path, which buys an
/// unauthenticated caller a signature verification per request — a poor trade
/// against an oracle that only confirms a UUIDv4 the caller already holds.
pub(crate) const DEVICE_AUTH_FAILED: &str = "invalid device, challenge or signature";

/// Rewrite an auth-signature rejection to [`DEVICE_AUTH_FAILED`].
///
/// Only the `Unauthorized` arm: a `BadRequest` is about the shape of what the
/// caller sent and tells them nothing about the device, and an `Internal` is a
/// fault on our side that must not be disguised as an authentication failure.
pub(crate) fn unify_device_auth_error(error: AppError) -> AppError {
    match error {
        AppError::Unauthorized(_) => AppError::Unauthorized(DEVICE_AUTH_FAILED.into()),
        other => other,
    }
}

#[derive(Deserialize)]
pub struct NewDevicePayload {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub rms_capsule: String,
    /// Authenticated local epoch of the RMS sealed into `rms_capsule`.
    pub key_epoch: i64,
    pub signature: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub enrolling_device_id: Uuid,
    pub challenge: String,
    pub auth_signature: String,
    pub new_device: NewDevicePayload,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
}

pub async fn post_enroll(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enroll_by_ip(&state.store, &ip)?;

    let enrolling_device_id_str = body.enrolling_device_id.to_string();
    let challenge_key = format!("challenge:{}", body.challenge);
    let consumed = state.store.get_del(&challenge_key)?;
    if consumed.is_none() {
        return Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        ));
    }

    let rows = state
        .sqldb
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = ? AND revoked = 0",
            vec![TursoValue::Text(enrolling_device_id_str.clone())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let device_a = rows
        .first()
        .map(|r| crate::db::parse_device_row_turso(r))
        .transpose()?
        .ok_or_else(|| AppError::Unauthorized(DEVICE_AUTH_FAILED.into()))?;

    let challenge_bytes = B64
        .decode(&body.challenge)
        .map_err(|_| AppError::BadRequest("invalid challenge encoding".into()))?;

    // Same answer whether the device was missing or the signature was wrong.
    // Internal errors keep their own identity — collapsing those would hide a
    // real fault behind an auth failure, which is the opposite trade.
    verify_auth_signature(
        &device_a.hybrid_vk,
        &challenge_bytes,
        &enrolling_device_id_str,
        &body.auth_signature,
    )
    .map_err(unify_device_auth_error)?;

    let new_hybrid_ek = B64
        .decode(&body.new_device.hybrid_ek)
        .map_err(|_| AppError::BadRequest("hybrid_ek is not valid base64".into()))?;
    let new_hybrid_vk_bytes = B64
        .decode(&body.new_device.hybrid_vk)
        .map_err(|_| AppError::BadRequest("hybrid_vk is not valid base64".into()))?;
    let rms_capsule = B64
        .decode(&body.new_device.rms_capsule)
        .map_err(|_| AppError::BadRequest("rms_capsule is not valid base64".into()))?;
    let signature_bytes = B64
        .decode(&body.new_device.signature)
        .map_err(|_| AppError::BadRequest("signature is not valid base64".into()))?;

    const HYBRID_EK_LEN: usize = 1568 + 32;
    const HYBRID_VK_LEN: usize = 2592 + 32;
    const HYBRID_SIG_LEN: usize = 4627 + 64;

    if new_hybrid_ek.len() != HYBRID_EK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_ek must be {HYBRID_EK_LEN} bytes"
        )));
    }
    if new_hybrid_vk_bytes.len() != HYBRID_VK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_vk must be {HYBRID_VK_LEN} bytes"
        )));
    }
    if signature_bytes.len() != HYBRID_SIG_LEN {
        return Err(AppError::BadRequest(format!(
            "signature must be {HYBRID_SIG_LEN} bytes"
        )));
    }

    verify_enrollment_signature(
        &device_a.hybrid_vk,
        &new_hybrid_ek,
        &new_hybrid_vk_bytes,
        &rms_capsule,
        &signature_bytes,
    )?;

    if body.new_device.key_epoch < 1 {
        return Err(AppError::BadRequest("key_epoch must be positive".into()));
    }
    let permit = match vela_rekey_policy::plan_active_mutation(MutationRequest {
        declared_epoch: body.new_device.key_epoch,
        authority_epoch: body.new_device.key_epoch,
        kind: MutationKind::Enrollment,
        authority: MutationAuthority::Device,
    }) {
        MutationDecision::Permit(permit) => permit,
        MutationDecision::Reject => {
            return Err(AppError::BadRequest(
                "device enrollment requires a positive device-authority epoch".into(),
            ));
        }
    };

    let new_device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let device_name = body
        .new_device
        .device_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Desktop Device".to_string());
    let device_type = body
        .new_device
        .device_type
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "desktop".to_string());

    let inserted = state.sqldb.execute(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
         )",
        vec![
            TursoValue::Text(new_device_id.to_string()),
            TursoValue::Text(device_a.user_id.to_string()),
            TursoValue::Text(device_name),
            TursoValue::Text(device_type),
            TursoValue::Text(crate::db::encode_b64(&new_hybrid_ek)),
            TursoValue::Text(crate::db::encode_b64(&new_hybrid_vk_bytes)),
            TursoValue::Text(enrolling_device_id_str),
            TursoValue::Text(crate::db::encode_b64(&rms_capsule)),
            TursoValue::Text(now),
            TursoValue::Text(device_a.user_id.to_string()),
            TursoValue::Integer(permit.epoch()),
        ],
    ).await.map_err(|e| AppError::Internal(e.to_string()))?;
    if inserted == 0 {
        return Err(AppError::Conflict(
            "device enrollment key epoch changed or rotation is in progress".into(),
        ));
    }

    tracing::info!(
        new_device_id = %new_device_id,
        enrolled_by   = %body.enrolling_device_id,
        user_id       = %device_a.user_id,
        "device enrolled"
    );

    Ok(Json(EnrollResponse {
        device_id: new_device_id,
    }))
}

pub fn verify_auth_signature(
    hybrid_vk_bytes: &[u8],
    challenge: &[u8],
    device_id: &str,
    signature_b64: &str,
) -> Result<()> {
    if challenge.len() != 32 {
        return Err(AppError::BadRequest("challenge must be 32 bytes".into()));
    }
    let signature_bytes = B64
        .decode(signature_b64)
        .map_err(|_| AppError::BadRequest("signature is not valid base64".into()))?;
    let message = vela_crypto::signing::auth_message(device_id, challenge);
    verify_hybrid_signature(
        hybrid_vk_bytes,
        &message,
        &signature_bytes,
        "authentication signature invalid",
    )
}

pub(crate) fn verify_enrollment_signature(
    device_a_vk_bytes: &[u8],
    hybrid_ek: &[u8],
    hybrid_vk: &[u8],
    rms_capsule: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    let message = vela_crypto::signing::enrollment_message(hybrid_ek, hybrid_vk, rms_capsule);
    verify_hybrid_signature(
        device_a_vk_bytes,
        &message,
        signature_bytes,
        "enrolling device signature over enrollment payload is invalid",
    )
}

/// Prove the caller holds the private half of the key that claimed `grant_id`.
///
/// This is what stands in for a session on the joining device's side: it has no
/// identity yet, so it authenticates by signing under the very key it presented
/// at claim time. Someone who only saw the enrollment code cannot produce this.
pub(crate) fn verify_enrollment_result_signature(
    claimed_vk_bytes: &[u8],
    grant_id: &str,
    signature_bytes: &[u8],
) -> Result<()> {
    let message = vela_crypto::signing::enrollment_result_message(grant_id);
    verify_hybrid_signature(
        claimed_vk_bytes,
        &message,
        signature_bytes,
        "signature does not match the key this grant was claimed with",
    )
}

pub(crate) fn verify_hybrid_signature(
    verifying_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    unauthorized_message: &str,
) -> Result<()> {
    use vela_crypto::signing::{
        HybridSignature, HybridVerifyingKey, HYBRID_SIG_LEN, HYBRID_VK_LEN,
    };

    let vk_arr: &[u8; HYBRID_VK_LEN] = verifying_key_bytes
        .try_into()
        .map_err(|_| AppError::Internal("stored hybrid_vk has wrong length".into()))?;
    let sig_arr: &[u8; HYBRID_SIG_LEN] = signature_bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("signature has wrong length".into()))?;

    let vk = HybridVerifyingKey::from_bytes(vk_arr)
        .map_err(|e| AppError::Internal(format!("vk decode: {e}")))?;
    let sig = HybridSignature::from_bytes(sig_arr)
        .map_err(|e| AppError::BadRequest(format!("signature decode: {e}")))?;

    let ok = vela_crypto::signing::verify(&vk, message, &sig)
        .map_err(|e| AppError::Internal(format!("signature verify: {e}")))?;

    if !ok {
        return Err(AppError::Unauthorized(unauthorized_message.into()));
    }
    Ok(())
}
