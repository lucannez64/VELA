pub mod initiate;
pub mod recover;
pub mod webauthn;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

const MAX_SHARE_BYTES: usize = 4096;

#[derive(Deserialize)]
pub struct PutShareRequest {
    pub share: String,
}

#[derive(Serialize)]
pub struct PutShareResponse {
    pub stored: bool,
}

pub async fn put_share(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<PutShareRequest>,
) -> Result<(HeaderMap, Json<PutShareResponse>)> {
    let share_bytes = B64
        .decode(&body.share)
        .map_err(|_| AppError::BadRequest("share is not valid base64".into()))?;

    if share_bytes.len() > MAX_SHARE_BYTES {
        return Err(AppError::BadRequest(format!(
            "share exceeds maximum size of {MAX_SHARE_BYTES} bytes"
        )));
    }

    state
        .db
        .execute(
            "UPDATE users SET recovery_share = $1, recovery_auth_hash = NULL WHERE id = $2",
            stoolap::params![
                crate::db::encode_b64(&share_bytes),
                session.user_id.to_string(),
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(user_id = %session.user_id, bytes = share_bytes.len(), "recovery share stored");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(PutShareResponse { stored: true })))
}

#[derive(Serialize)]
pub struct GetShareResponse {
    pub share: String,
}

pub async fn get_share(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<GetShareResponse>)> {
    let rows = state
        .db
        .query(
            "SELECT recovery_share FROM users WHERE id = $1",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound("user not found".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let v = crate::db::row_val(&row, 0)?;
    let share_b64 = if v.is_null() {
        None
    } else {
        v.as_str().map(|s| s.to_string())
    };

    let share_b64 = share_b64
        .ok_or_else(|| AppError::NotFound("no recovery share stored for this user".into()))?;

    let share_bytes = crate::db::decode_b64(&share_b64)?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(GetShareResponse {
            share: B64.encode(&share_bytes),
        }),
    ))
}

pub async fn delete_share(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, StatusCode)> {
    state
        .db
        .execute(
            "UPDATE users SET recovery_share = NULL, recovery_auth_hash = NULL WHERE id = $1",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(user_id = %session.user_id, "recovery share deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}
