use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::webauthn_driver::{
    begin_auth_finish, on_auth_account_observed, on_auth_assertion_observed,
    on_auth_attempt_consumed, on_auth_credential_updated, on_auth_finish_attempt_counted,
    on_auth_finish_context_observed, on_auth_grant_stored, on_auth_share_observed,
    AssertionObservation, AttemptBudgetObservation, AuthAccountObservation, AuthAttemptConsumptionObservation,
    AuthFinishContextObservation, AuthFinishEffect, AuthFinishFailure, CredentialUpdateStoreObservation,
    GrantStoreObservation, ShareDecodeObservation,
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
    let limited = match rate_limit::recovery_recover_by_ip_user(
        &state.store,
        &ip,
        &body.user_id.to_string(),
    ) {
        Ok(()) => rate_limit::recovery_recover_by_user(&state.store, &body.user_id.to_string()).err(),
        Err(error) => Some(error),
    };
    let start = begin_auth_finish();
    debug_assert_eq!(start.effect, AuthFinishEffect::CountAttempt);
    let budget = if limited.is_some() {
        AttemptBudgetObservation::Limited
    } else {
        AttemptBudgetObservation::Admitted
    };
    let transition = on_auth_finish_attempt_counted(start.driver, budget);
    let mut driver = transition.driver;
    match (transition.effect, limited) {
        (AuthFinishEffect::ObserveContext, None) => {}
        (AuthFinishEffect::Fail(AuthFinishFailure::AttemptLimited), Some(error)) => {
            return Err(error)
        }
        _ => {
            return Err(AppError::Internal(
                "WebAuthn recovery driver produced an unexpected budget effect".into(),
            ))
        }
    }

    // Effect: observe the share, the stored credential and whether the request
    // carried the attempt id. The challenge is not spent until all of them are
    // usable.
    let availability = crate::recovery::initiate::observe_recovery_share(&state, body.user_id)
        .await?;
    let credential = crate::recovery::webauthn::observe_recovery_credential(&state, body.user_id)
        .await?;
    let transition = on_auth_finish_context_observed(
        driver,
        AuthFinishContextObservation {
            account_present: availability.account_present,
            share_present: availability.share_present,
            credential: credential.credential,
            attempt_id_present: body.recovery_id.is_some(),
        },
    );
    driver = transition.driver;
    match transition.effect {
        AuthFinishEffect::ConsumeAttempt => {}
        AuthFinishEffect::Fail(failure) => {
            return Err(auth_finish_context_failure(failure, credential.decode_error))
        }
        _ => {
            return Err(AppError::Internal(
                "WebAuthn recovery driver produced an unexpected context effect".into(),
            ))
        }
    }
    let recovery_id = body.recovery_id.ok_or_else(|| {
        AppError::Internal("WebAuthn recovery driver admitted a missing attempt id".into())
    })?;
    let mut passkey = credential.passkey.ok_or_else(|| {
        AppError::Internal("WebAuthn recovery driver admitted a missing credential".into())
    })?;
    let current_credential_id = B64.encode(passkey.cred_id().as_slice());

    // Effect: consume the exact attempt state once.
    let (observation, auth_state, attempt_error) =
        match crate::recovery::initiate::observe_auth_state(&state, body.user_id, recovery_id)? {
            crate::recovery::initiate::StoredAuthAttempt::Missing => {
                (AuthAttemptConsumptionObservation::Missing, None, None)
            }
            crate::recovery::initiate::StoredAuthAttempt::Corrupt(error) => {
                (AuthAttemptConsumptionObservation::Corrupt, None, Some(error))
            }
            crate::recovery::initiate::StoredAuthAttempt::Present {
                state,
                user_matches,
                attempt_matches,
            } => (
                AuthAttemptConsumptionObservation::Present {
                    user_matches,
                    attempt_matches,
                    credential_matches: current_credential_id == state.credential_id,
                },
                Some(state),
                None,
            ),
        };
    let transition = on_auth_attempt_consumed(driver, observation);
    driver = transition.driver;
    match transition.effect {
        AuthFinishEffect::VerifyAssertion => {}
        AuthFinishEffect::Fail(AuthFinishFailure::AttemptMissing) => {
            return Err(AppError::BadRequest(
                "recovery challenge expired or already used".into(),
            ))
        }
        AuthFinishEffect::Fail(AuthFinishFailure::AttemptCorrupt) => {
            return Err(attempt_error.unwrap_or_else(|| {
                AppError::BadRequest("invalid recovery challenge state".into())
            }))
        }
        AuthFinishEffect::Fail(AuthFinishFailure::BindingMismatch) => {
            return Err(AppError::Unauthorized(
                "recovery challenge binding does not match this attempt".into(),
            ))
        }
        AuthFinishEffect::Fail(AuthFinishFailure::ChallengeCredentialReplaced) => {
            return Err(AppError::Unauthorized(
                "recovery credential was replaced after this challenge was issued".into(),
            ))
        }
        _ => {
            return Err(AppError::Internal(
                "WebAuthn recovery driver produced an unexpected consumption effect".into(),
            ))
        }
    }
    let auth_state = auth_state.ok_or_else(|| {
        AppError::Internal("WebAuthn recovery driver admitted an undecoded attempt".into())
    })?;

    // Effect: verify the assertion. The cryptographic outcome is an observation
    // (assumed), not a proof.
    let assertion_result = state
        .webauthn
        .finish_passkey_authentication(&body.credential, &auth_state.auth_state);
    let (observation, auth_result, assertion_error) = match assertion_result {
        Ok(auth_result) => {
            let assertion_matches =
                B64.encode(auth_result.cred_id().as_slice()) == auth_state.credential_id;
            (
                AssertionObservation {
                    assertion_valid: true,
                    user_verified: auth_result.user_verified(),
                    credential_matches: assertion_matches,
                    needs_update: auth_result.needs_update(),
                },
                Some(auth_result),
                None,
            )
        }
        Err(e) => (
            AssertionObservation {
                assertion_valid: false,
                user_verified: false,
                credential_matches: false,
                needs_update: false,
            },
            None,
            Some(AppError::Unauthorized(format!(
                "WebAuthn recovery failed: {e:?}"
            ))),
        ),
    };
    let transition = on_auth_assertion_observed(driver, observation);
    driver = transition.driver;
    match transition.effect {
        AuthFinishEffect::UpdateCredential => {
            let auth_result = auth_result.as_ref().ok_or_else(|| {
                AppError::Internal("WebAuthn recovery driver admitted an unverified assertion".into())
            })?;
            if passkey.update_credential(auth_result).is_none() {
                let transition = on_auth_credential_updated(
                    driver,
                    CredentialUpdateStoreObservation::Changed,
                );
                debug_assert_eq!(
                    transition.effect,
                    AuthFinishEffect::Fail(AuthFinishFailure::CredentialUpdateMismatch)
                );
                return Err(AppError::Unauthorized(
                    "recovery credential changed while authenticating".into(),
                ));
            }
            let updated = crate::recovery::webauthn::update_recovery_passkey_if_current(
                &state,
                body.user_id,
                &auth_state.credential_id,
                &passkey,
            )
            .await?;
            let observation = if updated {
                CredentialUpdateStoreObservation::Updated
            } else {
                CredentialUpdateStoreObservation::Changed
            };
            let transition = on_auth_credential_updated(driver, observation);
            driver = transition.driver;
            if !matches!(transition.effect, AuthFinishEffect::QueryAccount) {
                return Err(AppError::Unauthorized(
                    "recovery credential changed while authenticating".into(),
                ));
            }
        }
        AuthFinishEffect::QueryAccount => {}
        AuthFinishEffect::Fail(AuthFinishFailure::AssertionInvalid) => {
            return Err(assertion_error.unwrap_or_else(|| {
                AppError::Unauthorized("WebAuthn recovery failed".into())
            }))
        }
        AuthFinishEffect::Fail(AuthFinishFailure::UserVerificationRequired) => {
            return Err(AppError::Unauthorized(
                "WebAuthn recovery requires user verification".into(),
            ))
        }
        AuthFinishEffect::Fail(AuthFinishFailure::AssertionCredentialMismatch) => {
            return Err(AppError::Unauthorized(
                "WebAuthn assertion used a different recovery credential".into(),
            ))
        }
        _ => {
            return Err(AppError::Internal(
                "WebAuthn recovery driver produced an unexpected assertion effect".into(),
            ))
        }
    }

    // Effect: query the live row. Every field is retained as an observation so
    // the checked policy, not a hard-coded fact, decides release and the
    // handler can still return the original error.
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
    let row = rows.first();
    let observation = AuthAccountObservation {
        account_present: row.is_some(),
        account_epoch_active: row.map(|row| row.text(2).is_none()).unwrap_or(false),
        share_present: row.map(|row| row.text(0).is_some()).unwrap_or(false),
        stored_credential_matches: row
            .map(|row| row.text(3) == Some(auth_state.credential_id.as_str()))
            .unwrap_or(false),
        stored_epoch: row.and_then(|row| row.i64(1)),
    };
    let transition = on_auth_account_observed(driver, observation);
    driver = transition.driver;
    let permit = match transition.effect {
        AuthFinishEffect::ReleaseGrant(permit) => permit,
        AuthFinishEffect::Fail(failure) => return Err(auth_finish_account_failure(failure)),
        _ => {
            return Err(AppError::Internal(
                "WebAuthn recovery driver produced an unexpected account effect".into(),
            ))
        }
    };
    debug_assert!(permit.epoch >= vela_recovery_policy::INITIAL_EPOCH);

    let row = row.expect("release policy admits only a present share row");
    let share_b64 = row.text(0).map(String::from).ok_or_else(|| {
        AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
    })?;
    let share = crate::db::decode_b64(&share_b64);
    let observation = if share.is_ok() {
        ShareDecodeObservation::Decoded
    } else {
        ShareDecodeObservation::Corrupt
    };
    let transition = on_auth_share_observed(driver, observation);
    driver = transition.driver;
    let share_bytes = match (transition.effect, share) {
        (AuthFinishEffect::StoreGrant, Ok(bytes)) => bytes,
        (AuthFinishEffect::Fail(AuthFinishFailure::ShareCorrupt), Err(error)) => return Err(error),
        (_, Ok(_)) => {
            return Err(AppError::Internal(
                "WebAuthn recovery driver produced an unexpected share effect".into(),
            ))
        }
        (_, Err(error)) => return Err(error),
    };
    let split_id = row.text(4).map(String::from);

    let recovery_grant = Uuid::new_v4();
    let stored = store_credential_grant(
        &state,
        body.user_id,
        recovery_grant,
        permit.epoch,
        &auth_state.credential_id,
    );
    let observation = if stored.is_ok() {
        GrantStoreObservation::Stored
    } else {
        GrantStoreObservation::Failed
    };
    let transition = on_auth_grant_stored(driver, observation);
    match (transition.effect, stored) {
        (AuthFinishEffect::Complete, Ok(())) => {}
        (AuthFinishEffect::Fail(AuthFinishFailure::GrantStorage), Err(error)) => return Err(error),
        _ => {
            return Err(AppError::Internal(
                "WebAuthn recovery driver produced an unexpected grant effect".into(),
            ))
        }
    }

    tracing::info!(user_id = %body.user_id, "recovery share released after WebAuthn assertion");

    Ok(Json(RecoverResponse {
        share: B64.encode(&share_bytes),
        key_epoch: permit.epoch,
        split_id,
        recovery_grant,
    }))
}

/// Render a pre-consumption context failure with the handler's historical
/// status/message precedence.
fn auth_finish_context_failure(
    failure: AuthFinishFailure,
    decode_error: Option<AppError>,
) -> AppError {
    match failure {
        AuthFinishFailure::AccountUnavailable
        | AuthFinishFailure::ShareMissing
        | AuthFinishFailure::CredentialMissing => {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        }
        AuthFinishFailure::CredentialCorrupt => decode_error.unwrap_or_else(|| {
            AppError::Internal("invalid stored WebAuthn credential".into())
        }),
        AuthFinishFailure::AttemptIdMissing => {
            AppError::BadRequest("recovery_id from /recovery/initiate is required".into())
        }
        _ => AppError::Internal("unexpected WebAuthn recovery context failure".into()),
    }
}

/// Render a live-row policy rejection with the handler's historical status and
/// message.
fn auth_finish_account_failure(failure: AuthFinishFailure) -> AppError {
    match failure {
        AuthFinishFailure::AccountAbsent | AuthFinishFailure::ShareMissing => {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        }
        AuthFinishFailure::RotationPaused => AppError::Conflict(
            "account recovery is paused during vault key rotation".into(),
        ),
        AuthFinishFailure::StoredCredentialMismatch => AppError::Unauthorized(
            "recovery credential changed while authenticating".into(),
        ),
        _ => AppError::Unauthorized(
            "verified recovery policy rejected share release".into(),
        ),
    }
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
    let bytes = serde_json::to_vec(value)
        .map_err(|e| AppError::Internal(format!("failed to serialize recovery grant: {e}")))?;
    state.store.set_ex(
        &enroll_grant_key(user_id, grant),
        &bytes,
        ENROLL_GRANT_TTL_SECS,
    )
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

/// Read the grant without consuming it, so callers can reject rotation state
/// without spending a valid same-epoch recovery ceremony. `None` means the
/// key is absent; a decoded-invalid grant remains an error.
pub(crate) fn observe_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
) -> Result<Option<RecoveryEnrollGrant>> {
    let Some(value) = state.store.get(&enroll_grant_key(user_id, grant))? else {
        return Ok(None);
    };
    decode_enroll_grant(&value).map(Some)
}

/// Consume a grant issued by `post_recover`. `None` means it was missing,
/// expired or already redeemed; grants are single-use.
pub(crate) fn take_enroll_grant_observed(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
) -> Result<Option<RecoveryEnrollGrant>> {
    let Some(value) = state.store.get_del(&enroll_grant_key(user_id, grant))? else {
        return Ok(None);
    };
    decode_enroll_grant(&value).map(Some)
}

pub(crate) fn restore_enroll_grant(
    state: &AppState,
    user_id: Uuid,
    grant: Uuid,
    grant_value: &RecoveryEnrollGrant,
) -> Result<()> {
    store_enroll_grant(state, user_id, grant, grant_value)
}
