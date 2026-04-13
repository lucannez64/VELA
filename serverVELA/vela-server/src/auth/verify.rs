//! POST /auth/verify
//!
//! Accepts a Cyclo ZKP proof and returns a PASETO v4 session token.
//!
//! ## Verification flow
//!
//! 1. Consume the challenge nonce from sled (single-use, 60 s TTL).
//! 2. Look up the device's `cyclo_pk` (128 × u64 LE) from PostgreSQL.
//! 3. Decode `committed_hash` → 4 × u64 LE.
//! 4. Call `vela_crypto::cyclo::verify(pub_inputs, proof)`.
//! 5. On success, issue a PASETO v4 token and reset the failure streak.
//!
//! ## Rate limits (SPEC §6)
//!
//! * 10 attempts / min per IP (checked before proof verification).
//! * 5 failed proofs / min per `device_id` (checked/recorded after failure).
//! * Exponential backoff after 3 consecutive failures.

use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{
    auth::token::TokenService,
    error::{AppError, Result},
    rate_limit,
    state::AppState,
};

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub device_id:      uuid::Uuid,
    /// Base64-encoded 32-byte challenge nonce (echo of what /auth/challenge returned).
    pub challenge:      String,
    /// Hex-encoded 32-byte BLAKE3(sk ‖ challenge).
    pub committed_hash: String,
    /// Base64-encoded Cyclo proof bytes.
    pub proof:          String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub token: String,
}

pub async fn post_verify(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    let ip = addr.ip().to_string();
    let device_id_str = body.device_id.to_string();

    // ── Rate limits (IP, per-device backoff) ──────────────────────────────────
    rate_limit::verify_by_ip(&state.store, &ip)?;
    rate_limit::check_verify_backoff(&state.store, &device_id_str)?;

    // ── Consume the challenge nonce (single-use) ──────────────────────────────
    let challenge_key = format!("challenge:{}", body.challenge);
    let consumed = state.store.get_del(&challenge_key)?;
    if consumed.is_none() {
        return Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        ));
    }

    // ── Fetch device record ────────────────────────────────────────────────────
    let device = sqlx::query_as::<_, crate::db::DeviceRow>(
        r#"SELECT id, user_id, hybrid_ek, hybrid_vk, cyclo_pk,
                  enrolled_by, rms_capsule, revoked,
                  revoked_at, revoked_by, created_at
           FROM devices
           WHERE id = $1 AND revoked = FALSE"#,
    )
    .bind(body.device_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("device not found or revoked".into()))?;

    // ── Build Cyclo public inputs ─────────────────────────────────────────────
    let cyclo_pk_u64s = le_bytes_to_u64_slice(&device.cyclo_pk)
        .ok_or_else(|| AppError::Internal("corrupt cyclo_pk in database".into()))?;

    let hash_bytes = hex::decode(&body.committed_hash)
        .map_err(|_| AppError::BadRequest("committed_hash is not valid hex".into()))?;
    if hash_bytes.len() != 32 {
        return Err(AppError::BadRequest("committed_hash must be 32 bytes".into()));
    }
    let hash_u64s = le_bytes_to_u64_slice(&hash_bytes)
        .ok_or_else(|| AppError::BadRequest("committed_hash length not a multiple of 8".into()))?;

    let mut public_inputs: Vec<u64> = Vec::with_capacity(cyclo_pk_u64s.len() + hash_u64s.len());
    public_inputs.extend_from_slice(&cyclo_pk_u64s);
    public_inputs.extend_from_slice(&hash_u64s);

    // ── Decode proof ──────────────────────────────────────────────────────────
    let proof_bytes = B64
        .decode(&body.proof)
        .map_err(|_| AppError::BadRequest("proof is not valid base64".into()))?;
    let proof = vela_crypto::cyclo::CycloProof::from_bytes(proof_bytes);

    // ── Cyclo verify ──────────────────────────────────────────────────────────
    let ok = vela_crypto::cyclo::verify(&public_inputs, &proof).map_err(|e| {
        tracing::warn!(device_id = %body.device_id, error = %e, "Cyclo verify internal error");
        AppError::Internal(format!("ZKP verification error: {e}"))
    })?;

    if !ok {
        let _ = rate_limit::record_verify_failure(&state.store, &device_id_str);
        rate_limit::verify_fail_by_device(&state.store, &device_id_str)?;
        return Err(AppError::Unauthorized("Cyclo proof verification failed".into()));
    }

    // ── Success ───────────────────────────────────────────────────────────────
    rate_limit::reset_verify_streak(&state.store, &device_id_str)?;

    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let (token, jti) = ts.issue(device.user_id, device.id, None)?;

    rate_limit::track_device_jti(&state.store, &device_id_str, &jti)?;

    Ok(Json(VerifyResponse { token }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Interpret a byte slice as a sequence of little-endian u64 values.
/// Returns `None` if `bytes.len()` is not a multiple of 8.
fn le_bytes_to_u64_slice(bytes: &[u8]) -> Option<Vec<u64>> {
    if bytes.len() % 8 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect(),
    )
}
