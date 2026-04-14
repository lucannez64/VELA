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
    let rows = state.db.query(
        "SELECT recovery_share FROM users WHERE id = $1",
        stoolap::params![body.user_id.to_string()],
    ).map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows.into_iter().next()
        .ok_or_else(|| AppError::NotFound("user not found".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let v = crate::db::row_val(&row, 0)?;
    if v.is_null() {
        return Err(AppError::NotFound(
            "no recovery share stored for this user".into(),
        ));
    }

    let mut nonce_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce_b64 = B64.encode(nonce_bytes);

    let key = format!("recovery:challenge:{nonce_b64}");
    state.store.set_ex(&key, body.user_id.to_string().as_bytes(), 60)?;

    Ok(Json(InitiateResponse {
        challenge: nonce_b64,
    }))
}
