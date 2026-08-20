use crate::{
    auth::token::TokenService,
    device::enroll::verify_auth_signature,
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub device_id: uuid::Uuid,
    pub challenge: String,
    pub signature: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub token: String,
    pub user_id: String,
}

pub async fn post_verify(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    let device_id_str = body.device_id.to_string();

    rate_limit::verify_by_ip(&state.store, &ip)?;
    rate_limit::check_verify_backoff(&state.store, &ip, &device_id_str)?;

    let challenge_key = format!("challenge:{}", body.challenge);
    let consumed = state.store.get_del(&challenge_key)?;
    if consumed.is_none() {
        return Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        ));
    }

    let rows = state
        .sqldb
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
             FROM devices
             WHERE id = ? AND revoked = 0",
            vec![TursoValue::Text(body.device_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let device = rows
        .first()
        .map(|r| crate::db::parse_device_row_turso(r))
        .transpose()?
        .ok_or_else(|| AppError::Unauthorized(crate::device::enroll::DEVICE_AUTH_FAILED.into()))?;

    let challenge_bytes = B64
        .decode(&body.challenge)
        .map_err(|_| AppError::BadRequest("invalid challenge encoding".into()))?;

    if let Err(e) = verify_auth_signature(
        &device.hybrid_vk,
        &challenge_bytes,
        &device_id_str,
        &body.signature,
    ) {
        // This sets/extends the exponential backoff — it must never fail
        // silently, or a transient store hiccup lets an attacker's failed
        // attempt skip counting toward it. Log loudly so it's alertable;
        // `verify_fail_by_device` below still applies its own (weaker,
        // fixed-window) limit as a fallback regardless of this outcome.
        if let Err(record_err) =
            rate_limit::record_verify_failure(&state.store, &ip, &device_id_str)
        {
            tracing::error!(
                device_id = %device_id_str,
                error = %record_err,
                "failed to record verify failure — exponential backoff not updated"
            );
        }
        rate_limit::verify_fail_by_device(&state.store, &ip, &device_id_str)?;
        // Same answer as "no such device" above. Returning the helper's own
        // message here is what told an anonymous caller which device ids exist,
        // despite the not-found arm having been collapsed for exactly that
        // reason.
        return Err(crate::device::enroll::unify_device_auth_error(e));
    }

    rate_limit::reset_verify_streak(&state.store, &ip, &device_id_str)?;
    let now = chrono::Utc::now().to_rfc3339();
    let requested_name = body
        .device_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let requested_type = body
        .device_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if requested_name.is_some() || requested_type.is_some() {
        let next_name = requested_name.unwrap_or(&device.device_name);
        let next_type = requested_type.unwrap_or(&device.device_type);
        let _ = state.sqldb
            .execute(
                "UPDATE devices SET last_active = ?, device_name = ?, device_type = ? WHERE id = ?",
                vec![
                    TursoValue::Text(now.clone()),
                    TursoValue::Text(next_name.to_string()),
                    TursoValue::Text(next_type.to_string()),
                    TursoValue::Text(device_id_str.clone()),
                ],
            )
            .await;
    } else {
        let _ = state.sqldb
            .execute(
                "UPDATE devices SET last_active = ? WHERE id = ?",
                vec![TursoValue::Text(now), TursoValue::Text(device_id_str.clone())],
            )
            .await;
    }

    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let (token, jti) = ts.issue(device.user_id, device.id, None)?;

    rate_limit::track_device_jti(&state.store, &device_id_str, &jti)?;

    Ok(Json(VerifyResponse {
        token,
        user_id: device.user_id.to_string(),
    }))
}
