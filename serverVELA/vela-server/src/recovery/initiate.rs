use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, RequestChallengeResponse};

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

const AUTH_STATE_TTL_SECS: u64 = 300;

/// Uniform error for every "this account can't be recovered" case so the
/// endpoint can't be used to distinguish a non-existent user from one without a
/// recovery share or WebAuthn credential.
pub(crate) const RECOVERY_UNAVAILABLE: &str = "recovery is not available for this account";

#[derive(Deserialize)]
pub struct InitiateRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct InitiateResponse {
    /// Server-generated id binding the stored WebAuthn state to this attempt.
    /// Echo it back in `/recovery/recover` so concurrent initiations cannot
    /// clobber each other.
    pub recovery_id: Uuid,
    pub public_key: RequestChallengeResponse,
}

pub async fn post_initiate(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<InitiateRequest>,
) -> Result<Json<InitiateResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::recovery_initiate_by_ip(&state.store, &ip)?;
    // Per-victim throttle, keyed on the source as well as the target: `user_id`
    // is unauthenticated request-body data, so a cap on it alone let anyone burn
    // a victim's hourly budget from any IP and lock them out of recovery
    // (audit S-3). The per-user cap below is a distributed-churn backstop set
    // high enough that a legitimate user cannot hit it.
    rate_limit::recovery_initiate_by_ip_user(&state.store, &ip, &body.user_id.to_string())?;
    rate_limit::recovery_initiate_by_user(&state.store, &body.user_id.to_string())?;

    ensure_recovery_share_exists(&state, body.user_id).await?;
    let passkey = crate::recovery::webauthn::recovery_passkey_for_user(&state, body.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound(RECOVERY_UNAVAILABLE.into()))?;

    let (challenge, auth_state) = state
        .webauthn
        .start_passkey_authentication(&[passkey])
        .map_err(|e| AppError::BadRequest(format!("failed to start WebAuthn recovery: {e:?}")))?;

    let recovery_id = Uuid::new_v4();
    store_auth_state(&state, body.user_id, recovery_id, &auth_state)?;

    Ok(Json(InitiateResponse {
        recovery_id,
        public_key: challenge,
    }))
}

pub(crate) async fn ensure_recovery_share_exists(state: &AppState, user_id: Uuid) -> Result<()> {
    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share FROM users WHERE id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound(RECOVERY_UNAVAILABLE.into()))?;
    if matches!(row.get(0), Some(TursoValue::Null) | None) {
        return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
    }
    Ok(())
}

pub(crate) fn store_auth_state(
    state: &AppState,
    user_id: Uuid,
    recovery_id: Uuid,
    auth_state: &PasskeyAuthentication,
) -> Result<()> {
    let bytes = serde_json::to_vec(auth_state)
        .map_err(|e| AppError::Internal(format!("failed to serialize WebAuthn auth state: {e}")))?;
    state.store.set_ex(
        &format!("recovery:webauthn:auth:{user_id}:{recovery_id}"),
        &bytes,
        AUTH_STATE_TTL_SECS,
    )
}

/// Consume the stored auth state exactly once. When `recovery_id` is present
/// (new clients) the attempt-specific key is used; otherwise fall back to the
/// legacy per-user key so old clients keep working.
pub(crate) fn take_auth_state(
    state: &AppState,
    user_id: Uuid,
    recovery_id: Option<Uuid>,
) -> Result<PasskeyAuthentication> {
    let key = match recovery_id {
        Some(id) => format!("recovery:webauthn:auth:{user_id}:{id}"),
        None => format!("recovery:webauthn:auth:{user_id}"),
    };
    let bytes = state
        .store
        .get_del(&key)?
        .ok_or_else(|| AppError::BadRequest("recovery challenge expired or already used".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid recovery challenge state: {e}")))
}
