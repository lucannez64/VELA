use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::webauthn_driver::{
    AssertionObservation, AttemptBudgetObservation, AuthAccountObservation,
    AuthAttemptConsumptionObservation, AuthFinishContextObservation, AuthFinishEffect,
    AuthFinishFailure, AuthFinishGrantPermit, CredentialUpdateStoreObservation,
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

    // Every post-preflight decision and effect goes through the proved
    // `auth_finish_interpreter!` loop: count, observe context, consume the
    // attempt, verify the assertion, update the credential metadata, query the
    // live row, release the share and store the grant. This handler only
    // supplies the I/O and renders the terminal effect.
    let mut io = RecoverIo {
        state: &state,
        ip,
        user_id: body.user_id,
        recovery_id: body.recovery_id,
        credential: body.credential,
        limited_error: None,
        passkey: None,
        decode_error: None,
        auth_state: None,
        credential_id: None,
        attempt_error: None,
        auth_result: None,
        assertion_error: None,
        share_text: None,
        split_id: None,
        share_bytes: None,
        share_error: None,
        permit_epoch: None,
        recovery_grant: None,
        grant_error: None,
        error: None,
    };
    let Some(transition) = vela_recovery_policy::auth_finish_interpreter!(io, await) else {
        return Err(io.error.take().unwrap_or_else(|| {
            AppError::Internal("WebAuthn recovery aborted without an error".into())
        }));
    };
    match transition.effect {
        AuthFinishEffect::Complete => {
            let share_bytes = io.share_bytes.take().ok_or_else(|| {
                AppError::Internal("WebAuthn recovery completed without a share".into())
            })?;
            let key_epoch = io.permit_epoch.ok_or_else(|| {
                AppError::Internal("WebAuthn recovery completed without an epoch".into())
            })?;
            let recovery_grant = io.recovery_grant.ok_or_else(|| {
                AppError::Internal("WebAuthn recovery completed without a grant".into())
            })?;
            tracing::info!(user_id = %body.user_id, "recovery share released after WebAuthn assertion");
            Ok(Json(RecoverResponse {
                share: B64.encode(&share_bytes),
                key_epoch,
                split_id: io.split_id.take(),
                recovery_grant,
            }))
        }
        AuthFinishEffect::Fail(failure) => Err(auth_finish_failure(failure, &mut io)),
        _ => Err(AppError::Internal(
            "WebAuthn recovery driver reached no verdict".into(),
        )),
    }
}

/// Render a terminal authentication-finish failure, preferring the original
/// error captured by the effect.
fn auth_finish_failure(failure: AuthFinishFailure, io: &mut RecoverIo<'_>) -> AppError {
    match failure {
        AuthFinishFailure::AttemptLimited => io.limited_error.take().unwrap_or_else(|| {
            AppError::Internal("WebAuthn recovery attempt was limited".into())
        }),
        AuthFinishFailure::AccountUnavailable
        | AuthFinishFailure::ShareMissing
        | AuthFinishFailure::CredentialMissing => {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        }
        AuthFinishFailure::CredentialCorrupt => io.decode_error.take().unwrap_or_else(|| {
            AppError::Internal("invalid stored WebAuthn credential".into())
        }),
        AuthFinishFailure::AttemptIdMissing => AppError::BadRequest(
            "recovery_id from /recovery/initiate is required".into(),
        ),
        AuthFinishFailure::AttemptMissing => AppError::BadRequest(
            "recovery challenge expired or already used".into(),
        ),
        AuthFinishFailure::AttemptCorrupt => io.attempt_error.take().unwrap_or_else(|| {
            AppError::BadRequest("invalid recovery challenge state".into())
        }),
        AuthFinishFailure::BindingMismatch => AppError::Unauthorized(
            "recovery challenge binding does not match this attempt".into(),
        ),
        AuthFinishFailure::ChallengeCredentialReplaced => AppError::Unauthorized(
            "recovery credential was replaced after this challenge was issued".into(),
        ),
        AuthFinishFailure::AssertionInvalid => io.assertion_error.take().unwrap_or_else(|| {
            AppError::Unauthorized("WebAuthn recovery failed".into())
        }),
        AuthFinishFailure::UserVerificationRequired => AppError::Unauthorized(
            "WebAuthn recovery requires user verification".into(),
        ),
        AuthFinishFailure::AssertionCredentialMismatch => AppError::Unauthorized(
            "WebAuthn assertion used a different recovery credential".into(),
        ),
        AuthFinishFailure::CredentialUpdateMismatch => AppError::Unauthorized(
            "recovery credential changed while authenticating".into(),
        ),
        AuthFinishFailure::AccountAbsent => {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        }
        AuthFinishFailure::RotationPaused => AppError::Conflict(
            "account recovery is paused during vault key rotation".into(),
        ),
        AuthFinishFailure::StoredCredentialMismatch => AppError::Unauthorized(
            "recovery credential changed while authenticating".into(),
        ),
        AuthFinishFailure::PolicyRejected => AppError::Unauthorized(
            "verified recovery policy rejected share release".into(),
        ),
        AuthFinishFailure::ShareCorrupt => io.share_error.take().unwrap_or_else(|| {
            AppError::Internal("recovery share did not decode".into())
        }),
        AuthFinishFailure::GrantStorage => io.grant_error.take().unwrap_or_else(|| {
            AppError::Internal("failed to store the recovery grant".into())
        }),
    }
}

/// The I/O behind each authentication-finish effect. The driver decides which
/// method runs and when (through the shared `auth_finish_interpreter!` loop,
/// proved in F* as `run_auth_finish`); each method only performs its effect and
/// reports the observation. `None` aborts with `error`.
struct RecoverIo<'a> {
    state: &'a AppState,
    ip: String,
    user_id: Uuid,
    recovery_id: Option<Uuid>,
    credential: PublicKeyCredential,
    limited_error: Option<AppError>,
    passkey: Option<webauthn_rs::prelude::Passkey>,
    decode_error: Option<AppError>,
    auth_state: Option<crate::recovery::initiate::RecoveryAuthState>,
    credential_id: Option<String>,
    attempt_error: Option<AppError>,
    auth_result: Option<webauthn_rs::prelude::AuthenticationResult>,
    assertion_error: Option<AppError>,
    share_text: Option<String>,
    split_id: Option<String>,
    share_bytes: Option<Vec<u8>>,
    share_error: Option<AppError>,
    permit_epoch: Option<i64>,
    recovery_grant: Option<Uuid>,
    grant_error: Option<AppError>,
    error: Option<AppError>,
}

impl RecoverIo<'_> {
    /// Count one attempt; the limiter's own error is kept for the response.
    async fn auth_finish_count(&mut self) -> Option<AttemptBudgetObservation> {
        let limited = match rate_limit::recovery_recover_by_ip_user(
            &self.state.store,
            &self.ip,
            &self.user_id.to_string(),
        ) {
            Ok(()) => {
                rate_limit::recovery_recover_by_user(&self.state.store, &self.user_id.to_string())
                    .err()
            }
            Err(error) => Some(error),
        };
        let observation = if limited.is_some() {
            AttemptBudgetObservation::Limited
        } else {
            AttemptBudgetObservation::Admitted
        };
        self.limited_error = limited;
        Some(observation)
    }

    /// Observe share/credential availability and whether the request carried
    /// the attempt id. The challenge is not spent until all of them are usable.
    async fn auth_finish_context(&mut self) -> Option<AuthFinishContextObservation> {
        let availability =
            match crate::recovery::initiate::observe_recovery_share(self.state, self.user_id).await
            {
                Ok(availability) => availability,
                Err(error) => {
                    self.error = Some(error);
                    return None;
                }
            };
        let credential =
            match crate::recovery::webauthn::observe_recovery_credential(self.state, self.user_id)
                .await
            {
                Ok(credential) => credential,
                Err(error) => {
                    self.error = Some(error);
                    return None;
                }
            };
        self.passkey = credential.passkey;
        self.decode_error = credential.decode_error;
        Some(AuthFinishContextObservation {
            account_present: availability.account_present,
            share_present: availability.share_present,
            credential: credential.credential,
            attempt_id_present: self.recovery_id.is_some(),
        })
    }

    /// Consume the exact attempt state once.
    async fn auth_finish_consume(&mut self) -> Option<AuthAttemptConsumptionObservation> {
        let (Some(recovery_id), Some(passkey)) = (self.recovery_id, self.passkey.as_ref()) else {
            self.error = Some(AppError::Internal(
                "WebAuthn recovery driver admitted an incomplete attempt".into(),
            ));
            return None;
        };
        let current_credential_id = B64.encode(passkey.cred_id().as_slice());
        let observed = match crate::recovery::initiate::observe_auth_state(
            self.state,
            self.user_id,
            recovery_id,
        ) {
            Ok(observed) => observed,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        let observation = match observed {
            crate::recovery::initiate::StoredAuthAttempt::Missing => {
                AuthAttemptConsumptionObservation::Missing
            }
            crate::recovery::initiate::StoredAuthAttempt::Corrupt(error) => {
                self.attempt_error = Some(error);
                AuthAttemptConsumptionObservation::Corrupt
            }
            crate::recovery::initiate::StoredAuthAttempt::Present {
                state,
                user_matches,
                attempt_matches,
            } => {
                let observation = AuthAttemptConsumptionObservation::Present {
                    user_matches,
                    attempt_matches,
                    credential_matches: current_credential_id == state.credential_id,
                };
                self.credential_id = Some(state.credential_id.clone());
                self.auth_state = Some(state);
                observation
            }
        };
        Some(observation)
    }

    /// Verify the assertion against the consumed challenge.
    async fn auth_finish_verify(&mut self) -> Option<AssertionObservation> {
        let Some(auth_state) = self.auth_state.as_ref() else {
            self.error = Some(AppError::Internal(
                "WebAuthn recovery driver admitted an undecoded attempt".into(),
            ));
            return None;
        };
        let assertion_result = self
            .state
            .webauthn
            .finish_passkey_authentication(&self.credential, &auth_state.auth_state);
        match assertion_result {
            Ok(auth_result) => {
                let assertion_matches =
                    B64.encode(auth_result.cred_id().as_slice()) == auth_state.credential_id;
                let observation = AssertionObservation {
                    assertion_valid: true,
                    user_verified: auth_result.user_verified(),
                    credential_matches: assertion_matches,
                    needs_update: auth_result.needs_update(),
                };
                self.auth_result = Some(auth_result);
                Some(observation)
            }
            Err(error) => {
                self.assertion_error = Some(AppError::Unauthorized(format!(
                    "WebAuthn recovery failed: {error:?}"
                )));
                Some(AssertionObservation {
                    assertion_valid: false,
                    user_verified: false,
                    credential_matches: false,
                    needs_update: false,
                })
            }
        }
    }

    /// Persist the authenticator's updated credential metadata.
    async fn auth_finish_update(&mut self) -> Option<CredentialUpdateStoreObservation> {
        let Some(auth_result) = self.auth_result.take() else {
            self.error = Some(AppError::Internal(
                "WebAuthn recovery driver admitted an unverified assertion".into(),
            ));
            return None;
        };
        let (Some(passkey), Some(credential_id)) =
            (self.passkey.as_mut(), self.credential_id.clone())
        else {
            self.error = Some(AppError::Internal(
                "WebAuthn recovery driver admitted an incomplete attempt".into(),
            ));
            return None;
        };
        if passkey.update_credential(&auth_result).is_none() {
            return Some(CredentialUpdateStoreObservation::Changed);
        }
        let updated = match crate::recovery::webauthn::update_recovery_passkey_if_current(
            self.state,
            self.user_id,
            &credential_id,
            passkey,
        )
        .await
        {
            Ok(updated) => updated,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        Some(if updated {
            CredentialUpdateStoreObservation::Updated
        } else {
            CredentialUpdateStoreObservation::Changed
        })
    }

    /// Query the live row. Every field is retained as an observation so the
    /// checked policy decides release and the handler can still return the
    /// original error.
    async fn auth_finish_account(&mut self) -> Option<AuthAccountObservation> {
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT recovery_share, key_epoch, rekey_state,
                        recovery_webauthn_cred_id, recovery_split_id
                 FROM users WHERE id = ?",
                vec![TursoValue::Text(self.user_id.to_string())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let row = rows.first();
        let credential_id = self.credential_id.clone().unwrap_or_default();
        let observation = AuthAccountObservation {
            account_present: row.is_some(),
            account_epoch_active: row.map(|row| row.text(2).is_none()).unwrap_or(false),
            share_present: row.map(|row| row.text(0).is_some()).unwrap_or(false),
            stored_credential_matches: row
                .map(|row| row.text(3) == Some(credential_id.as_str()))
                .unwrap_or(false),
            stored_epoch: row.and_then(|row| row.i64(1)),
        };
        self.share_text = row.and_then(|row| row.text(0).map(String::from));
        self.split_id = row.and_then(|row| row.text(4).map(String::from));
        Some(observation)
    }

    /// Decode the staged share the driver authorized releasing.
    async fn auth_finish_release(&mut self, permit: AuthFinishGrantPermit) -> Option<ShareDecodeObservation> {
        self.permit_epoch = Some(permit.epoch);
        let Some(share_b64) = self.share_text.clone() else {
            self.error = Some(AppError::NotFound(
                crate::recovery::initiate::RECOVERY_UNAVAILABLE.into(),
            ));
            return None;
        };
        match crate::db::decode_b64(&share_b64) {
            Ok(bytes) => {
                self.share_bytes = Some(bytes);
                Some(ShareDecodeObservation::Decoded)
            }
            Err(error) => {
                self.share_error = Some(error);
                Some(ShareDecodeObservation::Corrupt)
            }
        }
    }

    /// Store exactly one single-use enrollment grant.
    async fn auth_finish_store_grant(&mut self) -> Option<GrantStoreObservation> {
        let (Some(key_epoch), Some(credential_id)) =
            (self.permit_epoch, self.credential_id.clone())
        else {
            self.error = Some(AppError::Internal(
                "WebAuthn recovery driver admitted an incomplete release".into(),
            ));
            return None;
        };
        let recovery_grant = Uuid::new_v4();
        let stored = store_credential_grant(
            self.state,
            self.user_id,
            recovery_grant,
            key_epoch,
            &credential_id,
        );
        let observation = if stored.is_ok() {
            GrantStoreObservation::Stored
        } else {
            GrantStoreObservation::Failed
        };
        self.recovery_grant = Some(recovery_grant);
        if let Err(error) = stored {
            self.grant_error = Some(error);
        }
        Some(observation)
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
