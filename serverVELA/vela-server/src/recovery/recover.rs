use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

use std::net::SocketAddr;

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
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
    /// Epoch of both this server share and the RMS it reconstructs. Clients
    /// must require their independently fetched cloud share to match it.
    pub key_epoch: i64,
    /// Single-use proof that this caller just passed WebAuthn-gated recovery
    /// for `user_id`. Redeemable exactly once at `/recovery/enroll-device`
    /// within `ENROLL_GRANT_TTL_SECS`, since a recovering device has no prior
    /// enrolled device available to authorize it the normal way (§4.2).
    pub recovery_grant: Uuid,
}

pub async fn post_recover(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>> {
    // Keyed on the caller as well as the target (red-team RT-1). `user_id` is
    // request-body data on an unauthenticated endpoint, and this check runs
    // before the WebAuthn assertion is verified — so a per-user-only budget let
    // anyone who knew a user id lock that user out of recovery from a single IP,
    // without ever presenting a credential.
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::recovery_recover_by_ip_user(&state.store, &ip, &body.user_id.to_string())?;
    rate_limit::recovery_recover_by_user(&state.store, &body.user_id.to_string())?;

    crate::recovery::initiate::ensure_recovery_share_exists(&state, body.user_id).await?;
    let mut passkey = crate::recovery::webauthn::recovery_passkey_for_user(&state, body.user_id)
        .await?
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
            crate::recovery::webauthn::update_recovery_passkey(&state, body.user_id, &passkey)
                .await?;
        }
    }

    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share, key_epoch, rekey_state FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows.first().ok_or_else(|| {
        AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
    })?;
    if row.text(2).is_some() {
        return Err(AppError::Conflict(
            "account recovery is paused during vault key rotation".into(),
        ));
    }
    let share_b64 = row
        .text(0)
        .map(String::from)
        .ok_or_else(|| {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        })?;
    let share_bytes = crate::db::decode_b64(&share_b64)?;
    let key_epoch = row.i64(1).unwrap_or(1).max(1);

    let recovery_grant = Uuid::new_v4();
    store_enroll_grant(&state, body.user_id, recovery_grant, key_epoch)?;

    tracing::info!(user_id = %body.user_id, "recovery share released after WebAuthn assertion");

    Ok(Json(RecoverResponse {
        share: B64.encode(&share_bytes),
        key_epoch,
        recovery_grant,
    }))
}

fn enroll_grant_key(user_id: Uuid, grant: Uuid) -> String {
    format!("recovery:enroll_grant:{user_id}:{grant}")
}

fn decode_enroll_grant_epoch(value: &[u8]) -> Result<i64> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|epoch| *epoch >= 1)
        .ok_or_else(|| AppError::Unauthorized("recovery grant is invalid".into()))
}

fn store_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
    key_epoch: i64,
) -> Result<()> {
    state.store.set_ex(
        &enroll_grant_key(user_id, grant),
        key_epoch.to_string().as_bytes(),
        ENROLL_GRANT_TTL_SECS,
    )
}

/// Read the epoch without consuming the grant, so callers can reject rotation
/// state without spending a valid same-epoch recovery ceremony.
pub(crate) fn load_enroll_grant_epoch(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
) -> Result<i64> {
    let value = state
        .store
        .get(&enroll_grant_key(user_id, grant))?
        .ok_or_else(|| AppError::Unauthorized("recovery grant expired or already used".into()))?;
    decode_enroll_grant_epoch(&value)
}

/// Consume a grant issued by `post_recover`. Returns an error if it's missing,
/// expired, or already redeemed — grants are single-use.
pub(crate) fn take_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
) -> Result<i64> {
    let value = state
        .store
        .get_del(&enroll_grant_key(user_id, grant))?
        .ok_or_else(|| AppError::Unauthorized("recovery grant expired or already used".into()))?;
    decode_enroll_grant_epoch(&value)
}

pub(crate) fn restore_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
    key_epoch: i64,
) -> Result<()> {
    store_enroll_grant(state, user_id, grant, key_epoch)
}
