use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, RequestChallengeResponse};

use crate::{
    error::{AppError, Result},
    state::AppState,
};

const AUTH_STATE_TTL_SECS: u64 = 300;

#[derive(Deserialize)]
pub struct InitiateRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct InitiateResponse {
    pub public_key: RequestChallengeResponse,
}

pub async fn post_initiate(
    State(state): State<AppState>,
    Json(body): Json<InitiateRequest>,
) -> Result<Json<InitiateResponse>> {
    ensure_recovery_share_exists(&state, body.user_id)?;
    let passkey = crate::recovery::webauthn::recovery_passkey_for_user(&state, body.user_id)?
        .ok_or_else(|| AppError::NotFound("no WebAuthn recovery credential registered".into()))?;

    let (challenge, auth_state) = state
        .webauthn
        .start_passkey_authentication(&[passkey])
        .map_err(|e| AppError::BadRequest(format!("failed to start WebAuthn recovery: {e:?}")))?;

    store_auth_state(&state, body.user_id, &auth_state)?;

    Ok(Json(InitiateResponse {
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
        .ok_or_else(|| AppError::NotFound("user not found".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if crate::db::row_val(&row, 0)?.is_null() {
        return Err(AppError::NotFound(
            "no recovery share stored for this user".into(),
        ));
    }
    Ok(())
}

pub(crate) fn store_auth_state(
    state: &AppState,
    user_id: Uuid,
    auth_state: &PasskeyAuthentication,
) -> Result<()> {
    let bytes = serde_json::to_vec(auth_state)
        .map_err(|e| AppError::Internal(format!("failed to serialize WebAuthn auth state: {e}")))?;
    state.store.set_ex(
        &format!("recovery:webauthn:auth:{user_id}"),
        &bytes,
        AUTH_STATE_TTL_SECS,
    )
}

pub(crate) fn take_auth_state(state: &AppState, user_id: Uuid) -> Result<PasskeyAuthentication> {
    let bytes = state
        .store
        .get_del(&format!("recovery:webauthn:auth:{user_id}"))?
        .ok_or_else(|| AppError::BadRequest("recovery challenge expired or already used".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid recovery challenge state: {e}")))
}
