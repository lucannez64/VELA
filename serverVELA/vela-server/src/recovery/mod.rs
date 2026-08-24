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
    /// Key epoch of the RMS which produced this Shamir share.
    pub key_epoch: i64,
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
    if body.key_epoch < 1 {
        return Err(AppError::BadRequest("key_epoch must be positive".into()));
    }

    // The epoch check belongs in the UPDATE, not in a preceding SELECT: a
    // rotation may commit between two statements. `rekey_state IS NULL` also
    // refuses setup while the account is frozen, so an old share cannot land
    // after commit and resurrect recovery for the retired RMS.
    let updated = state
        .sqldb
        .execute(
            "UPDATE users SET recovery_share = ?, recovery_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            vec![
                TursoValue::Text(crate::db::encode_b64(&share_bytes)),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(body.key_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated != 1 {
        return Err(AppError::Rekeyed(
            "vault epoch changed during recovery setup; adopt the current key and retry".into(),
        ));
    }

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
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode)> {
    let key_epoch = headers
        .get("x-vela-epoch")
        .ok_or_else(|| AppError::BadRequest("X-Vela-Epoch header is required".into()))?
        .to_str()
        .ok()
        .and_then(|raw| raw.parse::<i64>().ok())
        .filter(|epoch| *epoch >= 1)
        .ok_or_else(|| AppError::BadRequest("X-Vela-Epoch must be a positive integer".into()))?;

    let updated = state
        .sqldb
        .execute(
            "UPDATE users SET recovery_share = NULL, recovery_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            vec![
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(key_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated != 1 {
        return Err(AppError::Rekeyed(
            "vault epoch changed during recovery setup; adopt the current key and retry".into(),
        ));
    }

    tracing::info!(user_id = %session.user_id, "recovery share deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}
