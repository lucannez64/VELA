use crate::{
    auth::token::TokenService,
    device::enroll::verify_cyclo_proof,
    error::{AppError, Result},
    rate_limit,
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub device_id: uuid::Uuid,
    pub challenge: String,
    pub committed_hash: String,
    pub proof: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub token: String,
    pub user_id: String,
}

pub async fn post_verify(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    let ip = addr
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let device_id_str = body.device_id.to_string();

    rate_limit::verify_by_ip(&state.store, &ip)?;
    rate_limit::check_verify_backoff(&state.store, &device_id_str)?;

    let challenge_key = format!("challenge:{}", body.challenge);
    let consumed = state.store.get_del(&challenge_key)?;
    if consumed.is_none() {
        return Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        ));
    }

    let rows = state
        .db
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk, cyclo_pk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = $1 AND revoked = FALSE",
            stoolap::params![body.device_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Unauthorized("device not found or revoked".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let device = crate::db::parse_device_row(&row)?;

    let challenge_bytes = B64
        .decode(&body.challenge)
        .map_err(|_| AppError::BadRequest("invalid challenge encoding".into()))?;

    // Validate committed_hash = SHA256(challenge_bytes || device_id).
    // This binds the proof to the specific challenge issued by the server and
    // prevents cross-device replay of captured proofs.
    let mut hasher = Sha256::new();
    hasher.update(&challenge_bytes);
    hasher.update(device_id_str.as_bytes());
    let expected_hash_hex = hex::encode(hasher.finalize());

    if body.committed_hash != expected_hash_hex {
        return Err(AppError::BadRequest(
            "committed_hash does not match challenge".into(),
        ));
    }

    // Verify the Cyclo ZK proof.
    // Public inputs: cyclo_pk (128 u64s LE) || committed_hash (4 u64s LE) = 132 u64s.
    if let Err(e) = verify_cyclo_proof(&device.cyclo_pk, &body.committed_hash, &body.proof) {
        let _ = rate_limit::record_verify_failure(&state.store, &device_id_str);
        rate_limit::verify_fail_by_device(&state.store, &device_id_str)?;
        return Err(e);
    }

    rate_limit::reset_verify_streak(&state.store, &device_id_str)?;
    let _ = state.db.execute(
        "UPDATE devices SET last_active = $1 WHERE id = $2",
        stoolap::params![chrono::Utc::now().to_rfc3339(), device_id_str.clone()],
    );

    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let (token, jti) = ts.issue(device.user_id, device.id, None)?;

    rate_limit::track_device_jti(&state.store, &device_id_str, &jti)?;

    Ok(Json(VerifyResponse {
        token,
        user_id: device.user_id.to_string(),
    }))
}
