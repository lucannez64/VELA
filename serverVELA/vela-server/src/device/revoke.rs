//! POST /device/revoke
//!
//! Marks a device as revoked and invalidates all active JTIs for that device.
//!
//! ## Request body
//!
//! ```json
//! { "target_device_id": "<uuid>" }
//! ```
//!
//! The revoking session must belong to the same user as the target device.
//! A device can revoke itself (logout) or any sibling device.
//!
//! ## Cascade (SPEC §6)
//!
//! 1. Mark the device as revoked in PostgreSQL.
//! 2. Call `rate_limit::revoke_all_device_jtis` which enumerates the
//!    `device:jtis:{id}` Redis Set (populated on every token issuance) and
//!    writes `jti:revoked:{jti}` for each entry — giving the middleware exact,
//!    per-token revocation with no grace period.
//! 3. Write a `device:revoked:{id}` sentinel as a backstop for any JTIs
//!    issued concurrently or before Redis tracking was in place.

use axum::{extract::State, Json};
use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::AuthSession,
    rate_limit,
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
    session: AuthSession,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>> {
    // ── Fetch target device ───────────────────────────────────────────────────
    #[derive(sqlx::FromRow)]
    struct DeviceBasic { user_id: uuid::Uuid, revoked: bool }

    let target = sqlx::query_as::<_, DeviceBasic>(
        "SELECT user_id, revoked FROM devices WHERE id = $1",
    )
    .bind(body.target_device_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("device not found".into()))?;

    if target.user_id != session.user_id {
        return Err(AppError::Forbidden(
            "cannot revoke a device belonging to a different user".into(),
        ));
    }
    if target.revoked {
        return Err(AppError::BadRequest("device is already revoked".into()));
    }

    // ── Mark revoked in PostgreSQL ────────────────────────────────────────────
    let now = Utc::now();
    sqlx::query(
        "UPDATE devices SET revoked = TRUE, revoked_at = $1, revoked_by = $2 WHERE id = $3",
    )
    .bind(now)
    .bind(session.device_id)
    .bind(body.target_device_id)
    .execute(&state.db)
    .await?;

    let mut redis = state.redis.clone();
    let device_id_str = body.target_device_id.to_string();

    // ── Revoke every tracked JTI for the device (SPEC §6 cascade) ────────────
    // Enumerates the device:jtis:{id} set and writes jti:revoked:{jti} for each.
    rate_limit::revoke_all_device_jtis(&mut redis, &device_id_str).await?;

    // ── Write device-revoked sentinel as a backstop ───────────────────────────
    // Catches any JTIs that were issued before tracking began (e.g. after a
    // Redis flush) or issued concurrently with this revocation request.
    let sentinel_key = format!("device:revoked:{}", body.target_device_id);
    let _: () = redis
        .set_ex(&sentinel_key, 1_u8, rate_limit::TOKEN_MAX_LIFETIME_SECS)
        .await
        .map_err(AppError::Redis)?;

    tracing::info!(
        target_device = %body.target_device_id,
        revoked_by    = %session.device_id,
        user_id       = %session.user_id,
        "device revoked"
    );

    Ok(Json(RevokeResponse { revoked: body.target_device_id }))
}
