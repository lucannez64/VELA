//! POST /recovery/initiate
//!
//! Generates a challenge nonce for the recovery flow. The client must then
//! present this challenge along with their proof to `POST /recovery/recover`
//! to retrieve their encrypted Share 2.

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    state::AppState,
};

#[derive(Deserialize)]
pub struct InitiateRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct InitiateResponse {
    pub challenge: String,
}

pub async fn post_initiate(
    State(state): State<AppState>,
    Json(body): Json<InitiateRequest>,
) -> Result<Json<InitiateResponse>> {
    // ── Verify user exists and has a recovery share ──────────────────────
    #[derive(sqlx::FromRow)]
    struct Row {
        recovery_share: Option<Vec<u8>>,
    }

    let row = sqlx::query_as::<_, Row>(
        "SELECT recovery_share FROM users WHERE id = $1",
    )
    .bind(body.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    if row.recovery_share.is_none() {
        return Err(AppError::NotFound(
            "no recovery share stored for this user".into(),
        ));
    }

    // ── Generate and store challenge nonce ───────────────────────────────
    let mut nonce_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce_b64 = B64.encode(nonce_bytes);

    let key = format!("recovery:challenge:{nonce_b64}");
    state.store.set_ex(&key, body.user_id.to_string().as_bytes(), 60)?;

    Ok(Json(InitiateResponse {
        challenge: nonce_b64,
    }))
}
