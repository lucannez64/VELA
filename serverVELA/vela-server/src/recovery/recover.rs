use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::{
    error::{AppError, Result},
    rate_limit,
    state::AppState,
};

#[derive(Deserialize)]
pub struct RecoverRequest {
    pub user_id: Uuid,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct RecoverResponse {
    pub share: String,
}

pub async fn post_recover(
    State(state): State<AppState>,
    Json(body): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>> {
    rate_limit::check(
        &state.store,
        &format!("rl:recover:user:{}", body.user_id),
        5,
        3600,
    )?;

    crate::recovery::initiate::ensure_recovery_share_exists(&state, body.user_id)?;
    let mut passkey = crate::recovery::webauthn::recovery_passkey_for_user(&state, body.user_id)?
        .ok_or_else(|| {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        })?;
    let auth_state = crate::recovery::initiate::take_auth_state(&state, body.user_id)?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&body.credential, &auth_state)
        .map_err(|e| AppError::Unauthorized(format!("WebAuthn recovery failed: {e:?}")))?;

    if !auth_result.user_verified() {
        return Err(AppError::Unauthorized(
            "WebAuthn recovery requires user verification".into(),
        ));
    }

    if auth_result.needs_update() {
        if passkey.update_credential(&auth_result).is_some() {
            crate::recovery::webauthn::update_recovery_passkey(&state, body.user_id, &passkey)?;
        }
    }

    let rows = state
        .db
        .query(
            "SELECT recovery_share FROM users WHERE id = $1",
            stoolap::params![body.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let share_b64 = crate::db::row_val(&row, 0)?
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        })?;
    let share_bytes = crate::db::decode_b64(&share_b64)?;

    tracing::info!(user_id = %body.user_id, "recovery share released after WebAuthn assertion");

    Ok(Json(RecoverResponse {
        share: B64.encode(&share_bytes),
    }))
}
