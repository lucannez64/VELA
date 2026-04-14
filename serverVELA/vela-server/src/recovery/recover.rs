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
    rate_limit::check(
        &state.store,
        &format!("rl:recover:user:{}", body.user_id),
        5,
        3600,
    )?;

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

    let rows = state.db.query(
        "SELECT recovery_share, recovery_auth_hash FROM users WHERE id = $1",
        stoolap::params![body.user_id.to_string()],
    ).map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows.into_iter().next()
        .ok_or_else(|| AppError::NotFound("user not found".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let v0 = crate::db::row_val(&row, 0)?;
    let v1 = crate::db::row_val(&row, 1)?;

    let share_b64 = if v0.is_null() { None } else { v0.as_str().map(|s| s.to_string()) };
    let auth_hash_b64 = if v1.is_null() { None } else { v1.as_str().map(|s| s.to_string()) };

    let share_bytes = crate::db::decode_b64(
        &share_b64.ok_or_else(|| {
            AppError::NotFound("no recovery share stored for this user".into())
        })?
    )?;

    let auth_hash = crate::db::decode_b64(
        &auth_hash_b64.ok_or_else(|| {
            AppError::BadRequest(
                "recovery not set up — no auth hash on file".into(),
            )
        })?
    )?;

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
