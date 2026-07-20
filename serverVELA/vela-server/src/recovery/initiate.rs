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
    // Per-user cap (5/hour) so a distributed attacker cannot churn the victim's
    // recovery state even from many IPs.
    rate_limit::check(
        &state.store,
        &format!("rl:recover:init:user:{}", body.user_id),
        5,
        3600,
    )?;

    ensure_recovery_share_exists(&state, body.user_id)?;
    let passkey = crate::recovery::webauthn::recovery_passkey_for_user(&state, body.user_id)?
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

pub(crate) fn ensure_recovery_share_exists(state: &AppState, user_id: Uuid) -> Result<()> {
    let rows = state
        .db
        .query(
            "SELECT recovery_share FROM users WHERE id = $1",
            stoolap::params![user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound(RECOVERY_UNAVAILABLE.into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if crate::db::row_val(&row, 0)?.is_null() {
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
