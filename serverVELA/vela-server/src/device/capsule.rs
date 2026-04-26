use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

#[derive(serde::Serialize)]
pub struct CapsuleResponse {
    pub capsule: String,
}

pub async fn get_capsule(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<CapsuleResponse>)> {
    let rows = state
        .db
        .query(
            "SELECT rms_capsule FROM devices
         WHERE id = $1 AND user_id = $2 AND revoked = FALSE AND rms_capsule IS NOT NULL",
            stoolap::params![session.device_id.to_string(), session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = match rows.into_iter().next() {
        Some(r) => r.map_err(|e| AppError::Internal(e.to_string()))?,
        None => {
            return Err(AppError::NotFound(
                "no capsule available — device may be the first device, \
                 or the capsule has already been downloaded"
                    .into(),
            ));
        }
    };

    let v = crate::db::row_val(&row, 0)?;
    let capsule_b64 = if v.is_null() {
        None
    } else {
        v.as_str().map(|s| s.to_string())
    };

    let capsule_b64 = capsule_b64.ok_or_else(|| {
        AppError::NotFound(
            "no capsule available — device may be the first device, \
         or the capsule has already been downloaded"
                .into(),
        )
    })?;

    state
        .db
        .execute(
            "UPDATE devices SET rms_capsule = NULL WHERE id = $1 AND user_id = $2",
            stoolap::params![session.device_id.to_string(), session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

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
