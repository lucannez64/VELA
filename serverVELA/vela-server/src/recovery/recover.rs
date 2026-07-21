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

/// How long a post-recovery device-enrollment grant stays redeemable. Short
/// enough to bound the window where a stolen grant is useful, long enough to
/// cover a slow "combine shares, generate a device keypair" step on a new
/// device before it calls `/recovery/enroll-device`.
const ENROLL_GRANT_TTL_SECS: u64 = 600;

#[derive(Deserialize)]
pub struct RecoverRequest {
    pub user_id: Uuid,
    /// Attempt id returned by `/recovery/initiate`. Optional: when absent the
    /// legacy per-user state key is used (old clients).
    #[serde(default)]
    pub recovery_id: Option<Uuid>,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct RecoverResponse {
    pub share: String,
    /// Single-use proof that this caller just passed WebAuthn-gated recovery
    /// for `user_id`. Redeemable exactly once at `/recovery/enroll-device`
    /// within `ENROLL_GRANT_TTL_SECS`, since a recovering device has no prior
    /// enrolled device available to authorize it the normal way (§4.2).
    pub recovery_grant: Uuid,
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
    let auth_state =
        crate::recovery::initiate::take_auth_state(&state, body.user_id, body.recovery_id)?;

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

    let recovery_grant = Uuid::new_v4();
    store_enroll_grant(&state, body.user_id, recovery_grant)?;

    tracing::info!(user_id = %body.user_id, "recovery share released after WebAuthn assertion");

    Ok(Json(RecoverResponse {
        share: B64.encode(&share_bytes),
        recovery_grant,
    }))
}

fn store_enroll_grant(state: &AppState, user_id: Uuid, grant: Uuid) -> Result<()> {
    state.store.set_ex(
        &format!("recovery:enroll_grant:{user_id}:{grant}"),
        b"1",
        ENROLL_GRANT_TTL_SECS,
    )
}

/// Consume a grant issued by `post_recover`. Returns an error if it's missing,
/// expired, or already redeemed — grants are single-use.
pub(crate) fn take_enroll_grant(state: &AppState, user_id: Uuid, grant: Uuid) -> Result<()> {
    let key = format!("recovery:enroll_grant:{user_id}:{grant}");
    state
        .store
        .get_del(&key)?
        .ok_or_else(|| AppError::Unauthorized("recovery grant expired or already used".into()))?;
    Ok(())
}
