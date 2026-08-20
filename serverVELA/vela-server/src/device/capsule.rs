use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    sqldb::TursoValue,
    state::AppState,
};

#[derive(serde::Serialize)]
pub struct CapsuleResponse {
    pub capsule: String,
}

pub async fn get_capsule(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<CapsuleResponse>)> {
    // Read-then-clear must be atomic: two concurrent requests must never both
    // observe the same capsule. Do both inside one transaction pinned to a
    // single connection, and only decode/return the capsule after `commit()`
    // actually succeeds — if a concurrent request raced us to the same row, the
    // write conflict surfaces here and we report 409 instead of handing the
    // secret to the loser of the race.
    let tx = state
        .sqldb
        .tx()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let rows = tx
        .query(
            "SELECT rms_capsule FROM devices
             WHERE id = ? AND user_id = ? AND revoked = 0 AND rms_capsule IS NOT NULL",
            vec![
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let capsule_b64 = match rows.first().and_then(|r| r.get(0)) {
        Some(TursoValue::Text(s)) => s.clone(),
        _ => {
            return Err(AppError::NotFound(
                "no capsule available — device may be the first device, \
                 or the capsule has already been downloaded"
                    .into(),
            ));
        }
    };

    tx.execute(
        "UPDATE devices SET rms_capsule = NULL WHERE id = ? AND user_id = ?",
        vec![
            TursoValue::Text(session.device_id.to_string()),
            TursoValue::Text(session.user_id.to_string()),
        ],
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.commit().await.map_err(|e| {
        AppError::Conflict(format!(
            "capsule delivery raced with a concurrent request, please retry: {e}"
        ))
    })?;

    let capsule_bytes = crate::db::decode_b64(&capsule_b64)?;

    tracing::info!(
        device_id = %session.device_id,
        user_id   = %session.user_id,
        "RMS capsule downloaded and cleared"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(CapsuleResponse {
            capsule: B64.encode(&capsule_bytes),
        }),
    ))
}
