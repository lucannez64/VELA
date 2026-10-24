use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::{
    credential_update_facts, plan_credential_update, plan_recovery, recover_facts,
    CredentialUpdateDecision, CredentialUpdateObservation, RecoverDecision, RecoverObservation,
    RecoveryAttemptSource,
};
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
    /// Attempt id returned by `/recovery/initiate`. Deserialized as optional so
    /// old request bodies receive a precise 400 rather than a schema error, but
    /// M14 requires it: a per-user fallback cannot bind concurrent attempts.
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
    /// Identifies the finalized Shamir polynomial. `None` is reserved for
    /// recovery records created before the M16 two-phase publication protocol.
    pub split_id: Option<String>,
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
    let recovery_id = body.recovery_id.ok_or_else(|| {
        AppError::BadRequest("recovery_id from /recovery/initiate is required".into())
    })?;
    let taken = crate::recovery::initiate::take_auth_state(&state, body.user_id, recovery_id)?;
    let attempt_source = if taken.is_some() {
        RecoveryAttemptSource::Consumed
    } else {
        RecoveryAttemptSource::Missing
    };
    let auth_state = taken
        .ok_or_else(|| AppError::BadRequest("recovery challenge expired or already used".into()))?;
    let current_credential_id = B64.encode(passkey.cred_id().as_slice());
    let challenge_credential_matches_current = current_credential_id == auth_state.credential_id;
    if !challenge_credential_matches_current {
        return Err(AppError::Unauthorized(
            "recovery credential was replaced after this challenge was issued".into(),
        ));
    }

    let assertion_result = state
        .webauthn
        .finish_passkey_authentication(&body.credential, &auth_state.auth_state);
    let assertion_valid = assertion_result.is_ok();
    let auth_result = match assertion_result {
        Ok(result) => result,
        Err(e) => {
            return Err(AppError::Unauthorized(format!(
                "WebAuthn recovery failed: {e:?}"
            )));
        }
    };

    let user_verified = auth_result.user_verified();
    if !user_verified {
        return Err(AppError::Unauthorized(
            "WebAuthn recovery requires user verification".into(),
        ));
    }

    let assertion_credential_matches =
        B64.encode(auth_result.cred_id().as_slice()) == auth_state.credential_id;
    let update_decision =
        plan_credential_update(credential_update_facts(CredentialUpdateObservation {
            assertion_valid,
            credential_matches_current: assertion_credential_matches,
            needs_update: auth_result.needs_update(),
        }));
    match update_decision {
        CredentialUpdateDecision::Reject => {
            return Err(AppError::Unauthorized(
                "WebAuthn assertion used a different recovery credential".into(),
            ));
        }
        CredentialUpdateDecision::Update => {
            if passkey.update_credential(&auth_result).is_none()
                || !crate::recovery::webauthn::update_recovery_passkey_if_current(
                    &state,
                    body.user_id,
                    &auth_state.credential_id,
                    &passkey,
                )
                .await?
            {
                return Err(AppError::Unauthorized(
                    "recovery credential changed while authenticating".into(),
                ));
            }
        }
        CredentialUpdateDecision::Keep => {}
    }

    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share, key_epoch, rekey_state,
                    recovery_webauthn_cred_id, recovery_split_id
             FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Retain every row observation so the policy, not a hard-coded fact,
    // decides release and the handler can still return the original error.
    let row = rows.first();
    let row_present = row.is_some();
    let account_epoch_active = row.map(|row| row.text(2).is_none()).unwrap_or(false);
    let stored_credential_matches_attempt = row
        .map(|row| row.text(3) == Some(auth_state.credential_id.as_str()))
        .unwrap_or(false);
    let share_present = row.map(|row| row.text(0).is_some()).unwrap_or(false);
    let stored_epoch = row.and_then(|row| row.i64(1));
    let credential_matches_current = challenge_credential_matches_current
        && assertion_credential_matches
        && stored_credential_matches_attempt;

    let release_permit = match plan_recovery(recover_facts(RecoverObservation {
        attempt_source,
        user_matches: auth_state.user_id == body.user_id,
        attempt_matches: auth_state.recovery_id == recovery_id,
        credential_matches_current,
        assertion_valid,
        user_verified,
        share_present,
        account_epoch_active,
        stored_epoch,
    })) {
        RecoverDecision::Release(permit) => permit,
        // Preserve the original status classes, messages and precedence now
        // that the policy sees every observation instead of hard-coded facts.
        RecoverDecision::Reject if !row_present => {
            return Err(AppError::NotFound(
                crate::recovery::initiate::RECOVERY_UNAVAILABLE.into(),
            ));
        }
        RecoverDecision::Reject if !account_epoch_active => {
            return Err(AppError::Conflict(
                "account recovery is paused during vault key rotation".into(),
            ));
        }
        RecoverDecision::Reject if !stored_credential_matches_attempt => {
            return Err(AppError::Unauthorized(
                "recovery credential changed while authenticating".into(),
            ));
        }
        RecoverDecision::Reject if !share_present => {
            return Err(AppError::NotFound(
                crate::recovery::initiate::RECOVERY_UNAVAILABLE.into(),
            ));
        }
        RecoverDecision::Reject => {
            return Err(AppError::Unauthorized(
                "verified recovery policy rejected share release".into(),
            ));
        }
    };
    debug_assert!(release_permit.issues_single_use_grant());

    let row = row.expect("release policy admits only a present share row");
    let share_b64 = row.text(0).map(String::from).ok_or_else(|| {
        AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
    })?;
    let share_bytes = crate::db::decode_b64(&share_b64)?;
    let split_id = row.text(4).map(String::from);

    let recovery_grant = Uuid::new_v4();
    store_credential_grant(
        &state,
        body.user_id,
        recovery_grant,
        release_permit.epoch(),
        &auth_state.credential_id,
    )?;

    tracing::info!(user_id = %body.user_id, "recovery share released after WebAuthn assertion");

    Ok(Json(RecoverResponse {
        share: B64.encode(&share_bytes),
        key_epoch: release_permit.epoch(),
        split_id,
        recovery_grant,
    }))
}

fn enroll_grant_key(user_id: Uuid, grant: Uuid) -> String {
    format!("recovery:enroll_grant:{user_id}:{grant}")
}

/// Credential-id sentinel carried by grants issued from an RMS-possession
/// proof (M18). Such grants are bound to no WebAuthn credential; enrollment
/// instead requires the staged possession commitment to still be present.
pub(crate) const POSSESSION_GRANT_CREDENTIAL_ID: &str = "rms-possession-v1";

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub(crate) struct RecoveryEnrollGrant {
    pub key_epoch: i64,
    pub credential_id: String,
    /// True when this grant came from a possession proof rather than a
    /// WebAuthn assertion. `#[serde(default)]` keeps pre-M18 grants decoding
    /// as credential-bound.
    #[serde(default)]
    pub possession: bool,
}

impl RecoveryEnrollGrant {
    pub(crate) fn credential_bound(key_epoch: i64, credential_id: &str) -> Self {
        Self {
            key_epoch,
            credential_id: credential_id.to_string(),
            possession: false,
        }
    }

    pub(crate) fn from_possession_proof(key_epoch: i64) -> Self {
        Self {
            key_epoch,
            credential_id: POSSESSION_GRANT_CREDENTIAL_ID.to_string(),
            possession: true,
        }
    }
}

fn decode_enroll_grant(value: &[u8]) -> Result<RecoveryEnrollGrant> {
    let grant: RecoveryEnrollGrant = serde_json::from_slice(value)
        .map_err(|_| AppError::Unauthorized("recovery grant is invalid".into()))?;
    if grant.key_epoch < 1 || grant.credential_id.is_empty() {
        return Err(AppError::Unauthorized("recovery grant is invalid".into()));
    }
    Ok(grant)
}

fn store_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
    value: &RecoveryEnrollGrant,
) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| AppError::Internal(format!("failed to serialize recovery grant: {e}")))?;
    state.store.set_ex(&enroll_grant_key(user_id, grant), &bytes, ENROLL_GRANT_TTL_SECS)
}

/// Grant issued after a WebAuthn-gated share release.
pub(crate) fn store_credential_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
    key_epoch: i64,
    credential_id: &str,
) -> Result<()> {
    store_enroll_grant(
        state,
        user_id,
        grant,
        &RecoveryEnrollGrant::credential_bound(key_epoch, credential_id),
    )
}

/// Grant issued from an RMS-possession proof; releases no server share and is
/// bound to no credential.
pub(crate) fn store_possession_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
    key_epoch: i64,
) -> Result<()> {
    store_enroll_grant(
        state,
        user_id,
        grant,
        &RecoveryEnrollGrant::from_possession_proof(key_epoch),
    )
}

/// Read the epoch without consuming the grant, so callers can reject rotation
/// state without spending a valid same-epoch recovery ceremony.
pub(crate) fn load_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
) -> Result<RecoveryEnrollGrant> {
    let value = state
        .store
        .get(&enroll_grant_key(user_id, grant))?
        .ok_or_else(|| AppError::Unauthorized("recovery grant expired or already used".into()))?;
    decode_enroll_grant(&value)
}

/// Consume a grant issued by `post_recover`. Returns an error if it's missing,
/// expired, or already redeemed — grants are single-use.
pub(crate) fn take_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
) -> Result<RecoveryEnrollGrant> {
    let value = state
        .store
        .get_del(&enroll_grant_key(user_id, grant))?
        .ok_or_else(|| AppError::Unauthorized("recovery grant expired or already used".into()))?;
    decode_enroll_grant(&value)
}

pub(crate) fn restore_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
    grant_value: &RecoveryEnrollGrant,
) -> Result<()> {
    store_enroll_grant(state, user_id, grant, grant_value)
}
