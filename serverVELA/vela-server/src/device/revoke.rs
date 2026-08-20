use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::DeviceSession,
    rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub target_device_id: Uuid,
}

#[derive(Serialize)]
pub struct RevokeResponse {
    pub revoked: Uuid,
}

pub async fn post_revoke(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>> {
    let rows = state
        .sqldb
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = ?",
            vec![TursoValue::Text(body.target_device_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let target = rows
        .first()
        .map(|r| crate::db::parse_device_row_turso(r))
        .transpose()?
        .ok_or_else(|| AppError::NotFound("device not found".into()))?;

    if target.user_id != session.user_id {
        return Err(AppError::Forbidden(
            "cannot revoke a device belonging to a different user".into(),
        ));
    }
    if target.revoked {
        return Err(AppError::BadRequest("device is already revoked".into()));
    }

    let device_id_str = body.target_device_id.to_string();

    // Stop the device *before* recording that it is stopped.
    //
    // The auth middleware gates on the sled sentinel and the per-JTI markers,
    // not on the SQL `revoked` column, so writing SQL first left a window —
    // short, but real, and exactly during the seconds someone is revoking a
    // device because they believe it is compromised — where the row said
    // revoked and every existing token still worked. Doing it in this order
    // fails the safe way instead: if the SQL update below fails, the device is
    // already locked out and the row can be reconciled, whereas the reverse
    // leaves a device marked revoked that still has access.
    rate_limit::revoke_all_device_jtis(&state.store, &device_id_str)?;

    let sentinel_key = format!("device:revoked:{}", body.target_device_id);
    state
        .store
        .set_ex(&sentinel_key, &[1u8], rate_limit::TOKEN_MAX_LIFETIME_SECS)?;

    let now = Utc::now().to_rfc3339();
    state
        .sqldb
        .execute(
            "UPDATE devices SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE id = ?",
            vec![
                TursoValue::Text(now),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(body.target_device_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(
        target_device = %body.target_device_id,
        revoked_by    = %session.device_id,
        user_id       = %session.user_id,
        "device revoked"
    );

    Ok(Json(RevokeResponse {
        revoked: body.target_device_id,
    }))
}
