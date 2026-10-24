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
        // Repeat the web-session cascade so a revoke whose cascade failed
        // part-way is finished by a retry.
        revoke_web_sessions_approved_by(&state, session.user_id, body.target_device_id).await?;
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

    // Browser sessions this device approved inherit its trust, so they end
    // with it. This runs after the SQL row says revoked: a concurrent grant
    // by the device either committed before that (and is found here) or is
    // refused by the grant's `revoked = 0` guard.
    revoke_web_sessions_approved_by(&state, session.user_id, body.target_device_id).await?;

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

/// End every live web session that `device_id` approved: reject its issued
/// RW tokens first (sled sentinel, as `DELETE /web-session/:id` does), then
/// mark the rows revoked and drop their capsules.
async fn revoke_web_sessions_approved_by(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<()> {
    let rows = state
        .sqldb
        .query(
            "SELECT id FROM web_sessions
             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    for row in &rows {
        if let Some(id) = row.text(0) {
            state.store.set_ex(
                &format!("device:revoked:{id}"),
                &[1u8],
                crate::web_session::MAX_TTL_SECS as u64,
            )?;
            rate_limit::revoke_all_device_jtis(&state.store, id)?;
        }
    }
    state
        .sqldb
        .execute(
            "UPDATE web_sessions SET status = 'revoked', capsule = NULL
             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !rows.is_empty() {
        tracing::info!(
            approving_device = %device_id,
            sessions = rows.len(),
            "web sessions revoked with their approving device"
        );
    }
    Ok(())
}
