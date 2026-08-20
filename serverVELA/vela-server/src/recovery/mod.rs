pub mod enroll_device;
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
    middleware::{maybe_append_new_token, DeviceSession},
    sqldb::{Db as _, TursoValue},
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
    session: DeviceSession,
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
        .sqldb
        .execute(
            "UPDATE users SET recovery_share = ?, recovery_auth_hash = NULL WHERE id = ?",
            vec![
                TursoValue::Text(crate::db::encode_b64(&share_bytes)),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
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
    session: DeviceSession,
) -> Result<(HeaderMap, Json<GetShareResponse>)> {
    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share FROM users WHERE id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let share_b64 = rows
        .first()
        .and_then(|r| match r.get(0) {
            Some(TursoValue::Text(s)) => Some(s.clone()),
            _ => None,
        })
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
    session: DeviceSession,
) -> Result<(HeaderMap, StatusCode)> {
    state
        .sqldb
        .execute(
            "UPDATE users SET recovery_share = NULL, recovery_auth_hash = NULL WHERE id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(user_id = %session.user_id, "recovery share deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}
