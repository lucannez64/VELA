use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;
use vela_recovery_policy::{
    initiate_facts, plan_initiation, InitiateDecision, InitiateObservation,
};
use webauthn_rs::prelude::{PasskeyAuthentication, RequestChallengeResponse};

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

const AUTH_STATE_TTL_SECS: u64 = 300;

/// Everything an assertion must still match at redemption time. In
/// particular, carrying the credential id makes replacing/revoking a recovery
/// passkey invalidate every challenge issued for the old credential.
#[derive(Serialize, Deserialize)]
pub(crate) struct RecoveryAuthState {
    pub user_id: Uuid,
    pub recovery_id: Uuid,
    pub credential_id: String,
    pub auth_state: PasskeyAuthentication,
}

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

    let availability = observe_recovery_share(&state, body.user_id).await?;
    if !availability.account_present || !availability.share_present {
        return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
    }
    let passkey_opt =
        crate::recovery::webauthn::recovery_passkey_for_user(&state, body.user_id).await?;
    let credential_present = passkey_opt.is_some();
    let passkey = passkey_opt.ok_or_else(|| AppError::NotFound(RECOVERY_UNAVAILABLE.into()))?;
    let credential_id = B64.encode(passkey.cred_id().as_slice());

    let (challenge, auth_state) = state
        .webauthn
        .start_passkey_authentication(&[passkey])
        .map_err(|e| AppError::BadRequest(format!("failed to start WebAuthn recovery: {e:?}")))?;

    let recovery_id = Uuid::new_v4();
    // The generated id is fresh only if the store has no attempt state under
    // it. This is a real store observation; a collision fails closed instead
    // of silently overwriting another attempt.
    let attempt_id_fresh = !state
        .store
        .exists(&auth_state_key(body.user_id, recovery_id))?;
    let permit = match plan_initiation(initiate_facts(InitiateObservation {
        account_present: availability.account_present,
        share_present: availability.share_present,
        credential_present,
        attempt_id_fresh,
        ttl_secs: AUTH_STATE_TTL_SECS,
    })) {
        InitiateDecision::Start(permit) => permit,
        InitiateDecision::Reject => {
            return Err(AppError::Internal(
                "verified recovery policy rejected a valid initiation".into(),
            ));
        }
    };
    debug_assert!(permit.binds_user_attempt_and_credential());
    let envelope = RecoveryAuthState {
        user_id: body.user_id,
        recovery_id,
        credential_id,
        auth_state,
    };
    store_auth_state(&state, &envelope)?;

    Ok(Json(InitiateResponse {
        recovery_id,
        public_key: challenge,
    }))
}

/// Raw availability of the recovery share for one account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryShareObservation {
    pub account_present: bool,
    pub share_present: bool,
}

/// Observe the account row and its `recovery_share` column without collapsing
/// either into a hard-coded fact. The caller decides which error, if any, the
/// absence corresponds to.
pub(crate) async fn observe_recovery_share(
    state: &AppState,
    user_id: Uuid,
) -> Result<RecoveryShareObservation> {
    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share FROM users WHERE id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(match rows.first() {
        Some(row) => RecoveryShareObservation {
            account_present: true,
            share_present: !matches!(row.get(0), Some(TursoValue::Null) | None),
        },
        None => RecoveryShareObservation {
            account_present: false,
            share_present: false,
        },
    })
}

pub(crate) async fn ensure_recovery_share_exists(state: &AppState, user_id: Uuid) -> Result<()> {
    let observation = observe_recovery_share(state, user_id).await?;
    if !observation.account_present || !observation.share_present {
        return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
    }
    Ok(())
}

fn auth_state_key(user_id: Uuid, recovery_id: Uuid) -> String {
    format!("recovery:webauthn:auth:{user_id}:{recovery_id}")
}

pub(crate) fn store_auth_state(state: &AppState, envelope: &RecoveryAuthState) -> Result<()> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|e| AppError::Internal(format!("failed to serialize WebAuthn auth state: {e}")))?;
    state.store.set_ex(
        &auth_state_key(envelope.user_id, envelope.recovery_id),
        &bytes,
        AUTH_STATE_TTL_SECS,
    )
}

/// Consume the exact attempt state once. `Ok(None)` means no state matched;
/// `Ok(Some(_))` means this call removed the stored challenge. The old
/// per-user fallback could not distinguish concurrent initiations and
/// therefore cannot meet the M14 attempt-binding or replay properties;
/// callers must return `recovery_id`.
pub(crate) fn take_auth_state(
    state: &AppState,
    user_id: Uuid,
    recovery_id: Uuid,
) -> Result<Option<RecoveryAuthState>> {
    let key = auth_state_key(user_id, recovery_id);
    let Some(bytes) = state.store.get_del(&key)? else {
        return Ok(None);
    };
    let envelope: RecoveryAuthState = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid recovery challenge state: {e}")))?;
    if envelope.user_id != user_id || envelope.recovery_id != recovery_id {
        return Err(AppError::Unauthorized(
            "recovery challenge binding does not match this attempt".into(),
        ));
    }
    Ok(Some(envelope))
}
