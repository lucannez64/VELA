use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, DeviceSession},
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

#[derive(serde::Serialize)]
pub struct CapsuleResponse {
    pub capsule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
}

#[derive(serde::Deserialize)]
pub struct CapsuleAck {
    pub epoch: i64,
}

pub async fn get_capsule(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<CapsuleResponse>)> {
    // Enrollment delivery remains atomic read-then-clear, so two concurrent
    // join polls cannot both consume the one-time capsule. Epoch-tagged re-key
    // capsules deliberately stay readable until `post_capsule_ack` confirms
    // that the adopter persisted its new RMS.
    let tx = state
        .sqldb
        .tx()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let rows = tx
        .query(
            "SELECT rms_capsule, rms_capsule_epoch FROM devices
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
    let capsule_epoch = rows.first().and_then(|r| r.i64(1));

    // Enrollment capsules retain their historical read-once behavior. Rekey
    // capsules carry an epoch and remain retryable until the adopter confirms
    // that local files and the platform RMS were durably migrated.
    if capsule_epoch.is_none() {
        tx.execute(
            "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
             WHERE id = ? AND user_id = ?",
            vec![
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    tx.commit().await.map_err(|e| {
        AppError::Conflict(format!(
            "capsule delivery raced with a concurrent request, please retry: {e}"
        ))
    })?;

    let capsule_bytes = crate::db::decode_b64(&capsule_b64)?;

    tracing::info!(
        device_id = %session.device_id,
        user_id   = %session.user_id,
        epoch = ?capsule_epoch,
        "RMS capsule downloaded"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(CapsuleResponse {
            capsule: B64.encode(&capsule_bytes),
            epoch: capsule_epoch,
        }),
    ))
}

pub async fn post_capsule_ack(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<CapsuleAck>,
) -> Result<(HeaderMap, axum::http::StatusCode)> {
    let updated = state
        .sqldb
        .execute(
            "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
             WHERE id = ? AND user_id = ? AND revoked = 0 AND rms_capsule_epoch = ?",
            vec![
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(body.epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated != 1 {
        return Err(AppError::Conflict(
            "no matching re-key capsule is awaiting acknowledgement".into(),
        ));
    }
    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, axum::http::StatusCode::NO_CONTENT))
}
