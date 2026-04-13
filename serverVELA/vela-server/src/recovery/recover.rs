//! POST /recovery/recover
//!
//! Retrieves the encrypted Share 2 blob for a user who has lost all devices
//! and needs to bootstrap a new device via the 2-of-3 Shamir recovery scheme
//! (SPEC §4.3).
//!
//! ## Rate limiting
//!
//! 5 attempts per hour per user to prevent brute-force attacks on the
//! recovery proof.

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    rate_limit,
    state::AppState,
};

const MAX_PROOF_BYTES: usize = 128;

#[derive(Deserialize)]
pub struct RecoverRequest {
    pub user_id: Uuid,
    pub challenge: String,
    pub proof: String,
}

#[derive(Serialize)]
pub struct RecoverResponse {
    pub share: String,
}

pub async fn post_recover(
    State(state): State<AppState>,
    Json(body): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>> {
    // ── Rate limit: 5 attempts per hour per user ─────────────────────────
    rate_limit::check(
        &state.store,
        &format!("rl:recover:user:{}", body.user_id),
        5,
        3600,
    )?;

    // ── Verify challenge nonce (single-use, 60s TTL) ────────────────────
    let challenge_key = format!("recovery:challenge:{}", body.challenge);
    let stored_user_id = state.store.get_del(&challenge_key)?;

    match stored_user_id {
        Some(uid) if String::from_utf8_lossy(&uid) == body.user_id.to_string() => {}
        Some(_) => {
            return Err(AppError::BadRequest(
                "challenge does not match user_id".into(),
            ))
        }
        None => {
            return Err(AppError::BadRequest(
                "challenge expired or already used".into(),
            ))
        }
    }

    // ── Fetch encrypted share + recovery auth hash ───────────────────────
    #[derive(sqlx::FromRow)]
    struct Row {
        recovery_share: Option<Vec<u8>>,
        recovery_auth_hash: Option<Vec<u8>>,
    }

    let row = sqlx::query_as::<_, Row>(
        "SELECT recovery_share, recovery_auth_hash FROM users WHERE id = $1",
    )
    .bind(body.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let share_bytes = row.recovery_share.ok_or_else(|| {
        AppError::NotFound("no recovery share stored for this user".into())
    })?;

    let auth_hash = row.recovery_auth_hash.ok_or_else(|| {
        AppError::BadRequest(
            "recovery not set up — no auth hash on file".into(),
        )
    })?;

    // ── Verify proof ─────────────────────────────────────────────────────
    let proof_bytes = B64
        .decode(&body.proof)
        .map_err(|_| AppError::BadRequest("proof is not valid base64".into()))?;

    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(AppError::BadRequest(format!(
            "proof exceeds maximum size of {MAX_PROOF_BYTES} bytes"
        )));
    }

    let computed_hash = blake3::hash(&proof_bytes);
    if computed_hash.as_bytes() != auth_hash.as_slice() {
        tracing::warn!(
            user_id = %body.user_id,
            "recovery proof verification failed"
        );
        return Err(AppError::Unauthorized(
            "recovery proof verification failed".into(),
        ));
    }

    tracing::info!(user_id = %body.user_id, "recovery share released");

    Ok(Json(RecoverResponse {
        share: B64.encode(&share_bytes),
    }))
}
