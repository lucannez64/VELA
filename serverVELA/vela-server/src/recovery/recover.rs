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
use vela_recovery_policy::webauthn_store::{self, CredentialGrantView};
use webauthn_rs::prelude::PublicKeyCredential;

use std::net::SocketAddr;

use super::sql::{
    credential_row, finish_account_row_view, run_webauthn_read, run_webauthn_write,
    store_credential_grant, take_auth_state, webauthn_share_row_view, PoolSql, RecoveryKv,
    RecoverySql, StoreKv,
};
use crate::{
    error::{AppError, Result},
    net, rate_limit,
    state::AppState,
};

/// How long a post-recovery device-enrollment grant stays redeemable. Short
/// enough to bound the window where a stolen grant is useful, long enough to
/// cover a slow "combine shares, generate a device keypair" step on a new
/// device before it calls `/recovery/enroll-device`.
pub(crate) const ENROLL_GRANT_TTL_SECS: u64 = 600;
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
        sql: PoolSql(&state.sqldb),
        kv: StoreKv(&state.store),
        ip,
        user_id: body.user_id,
        recovery_id: body.recovery_id,
        credential: body.credential,
        limited_error: None,
        passkey: None,
        decode_error: None,
        observed_credential_id: None,
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
        drawn_grant: None,
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

/// Construction and side-channel access for the bounded real-database
/// conformance test (`recovery/conformance.rs`).
#[cfg(test)]
impl<'a, S, K> RecoverIo<'a, S, K> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn for_conformance(
        state: &'a AppState,
        sql: S,
        kv: K,
        user_id: Uuid,
        recovery_id: Option<Uuid>,
        observed_credential_id: Option<String>,
        credential_id: Option<String>,
        share_text: Option<String>,
        permit_epoch: Option<i64>,
        drawn_grant: Option<Uuid>,
    ) -> Self {
        Self {
            state,
            sql,
            kv,
            ip: "127.0.0.1".into(),
            user_id,
            recovery_id,
            credential: PublicKeyCredential {
                id: "unused".into(),
                raw_id: Default::default(),
                response: webauthn_rs_core::proto::AuthenticatorAssertionResponseRaw {
                    authenticator_data: Default::default(),
                    client_data_json: Default::default(),
                    signature: Default::default(),
                    user_handle: None,
                },
                type_: "public-key".into(),
                extensions: Default::default(),
            },
            limited_error: None,
            passkey: None,
            decode_error: None,
            observed_credential_id,
            auth_state: None,
            credential_id,
            attempt_error: None,
            auth_result: None,
            assertion_error: None,
            share_text,
            split_id: None,
            share_bytes: None,
            share_error: None,
            permit_epoch,
            recovery_grant: None,
            drawn_grant,
            grant_error: None,
            error: None,
        }
    }

    pub(super) fn error_is_set(&self) -> bool {
        self.error.is_some()
    }

    pub(super) fn split_id(&self) -> Option<String> {
        self.split_id.clone()
    }

    pub(super) fn share_bytes(&self) -> Option<Vec<u8>> {
        self.share_bytes.clone()
    }

    pub(super) fn recovery_grant(&self) -> Option<Uuid> {
        self.recovery_grant
    }

}

/// Render a terminal authentication-finish failure, preferring the original
/// error captured by the effect.
fn auth_finish_failure<S, K>(failure: AuthFinishFailure, io: &mut RecoverIo<'_, S, K>) -> AppError {
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
pub(super) struct RecoverIo<'a, S, K> {
    state: &'a AppState,
    sql: S,
    kv: K,
    ip: String,
    user_id: Uuid,
    recovery_id: Option<Uuid>,
    credential: PublicKeyCredential,
    limited_error: Option<AppError>,
    passkey: Option<webauthn_rs::prelude::Passkey>,
    decode_error: Option<AppError>,
    /// The credential id of the live stored credential, observed before the
    /// challenge is spent.
    observed_credential_id: Option<String>,
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
    /// A fixed grant id for the conformance test; `None` draws a fresh v4 id
    /// exactly when the grant is issued, as the handler always has.
    drawn_grant: Option<Uuid>,
    grant_error: Option<AppError>,
    error: Option<AppError>,
}

impl<S: RecoverySql, K: RecoveryKv> RecoverIo<'_, S, K> {
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
    pub(super) async fn auth_finish_context(&mut self) -> Option<AuthFinishContextObservation> {
        let share_stmt = webauthn_store::plan_select_share(self.user_id.to_string());
        let share_rows = match run_webauthn_read(&mut self.sql, &share_stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let share = webauthn_share_row_view(&share_rows);
        let credential_stmt = webauthn_store::plan_select_credential(self.user_id.to_string());
        let credential_rows = match run_webauthn_read(&mut self.sql, &credential_stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let credential = match credential_row(&credential_rows) {
            Ok(credential) => credential,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        self.observed_credential_id = credential
            .passkey
            .as_ref()
            .map(crate::recovery::webauthn::cred_id_b64);
        self.passkey = credential.passkey;
        self.decode_error = credential.decode_error;
        Some(webauthn_store::classify_finish_context(
            &share,
            &credential.view,
            self.recovery_id.is_some(),
        ))
    }

    /// Consume the exact attempt state once.
    pub(super) async fn auth_finish_consume(&mut self) -> Option<AuthAttemptConsumptionObservation> {
        let (Some(recovery_id), Some(observed_credential_id)) =
            (self.recovery_id, self.observed_credential_id.clone())
        else {
            self.error = Some(AppError::Internal(
                "WebAuthn recovery driver admitted an incomplete attempt".into(),
            ));
            return None;
        };
        let stmt = webauthn_store::plan_take_auth_state(webauthn_store::auth_state_key(
            &self.user_id.to_string(),
            &recovery_id.to_string(),
        ));
        let bytes = match take_auth_state(&mut self.kv, &stmt) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        let taken = match crate::recovery::initiate::decode_auth_attempt(bytes) {
            crate::recovery::initiate::StoredAuthAttempt::Missing => {
                webauthn_store::AuthStateTake::Missing
            }
            crate::recovery::initiate::StoredAuthAttempt::Corrupt(error) => {
                self.attempt_error = Some(error);
                webauthn_store::AuthStateTake::Corrupt
            }
            crate::recovery::initiate::StoredAuthAttempt::Present { view, envelope } => {
                self.credential_id = Some(envelope.credential_id.clone());
                self.auth_state = Some(envelope);
                webauthn_store::AuthStateTake::Present(view)
            }
        };
        Some(webauthn_store::classify_take_auth_state(
            &taken,
            &self.user_id.to_string(),
            &recovery_id.to_string(),
            &observed_credential_id,
        ))
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
            return Some(webauthn_store::classify_credential_update(0));
        }
        let credential = match serde_json::to_string(passkey) {
            Ok(credential) => credential,
            Err(error) => {
                self.error = Some(AppError::Internal(format!(
                    "failed to serialize passkey: {error}"
                )));
                return None;
            }
        };
        let credential_id_now = crate::recovery::webauthn::cred_id_b64(passkey);
        self.write_updated_credential(credential_id, credential, credential_id_now)
            .await
    }

    /// The guarded write half of `auth_finish_update`: replace the stored
    /// credential only while `expected_credential_id` is still current.
    pub(super) async fn write_updated_credential(
        &mut self,
        expected_credential_id: String,
        credential: String,
        credential_id: String,
    ) -> Option<CredentialUpdateStoreObservation> {
        let stmt = webauthn_store::plan_update_credential_if_current(
            self.user_id.to_string(),
            expected_credential_id,
            credential,
            credential_id,
        );
        let rows = match run_webauthn_write(&mut self.sql, &stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        Some(webauthn_store::classify_credential_update(rows))
    }

    /// Query the live row. Every field is retained as an observation so the
    /// checked policy decides release and the handler can still return the
    /// original error.
    pub(super) async fn auth_finish_account(&mut self) -> Option<AuthAccountObservation> {
        let stmt = webauthn_store::plan_finish_account(self.user_id.to_string());
        let rows = match run_webauthn_read(&mut self.sql, &stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let row = finish_account_row_view(&rows);
        let credential_id = self.credential_id.clone().unwrap_or_default();
        let observation = webauthn_store::classify_finish_account(row.clone(), &credential_id);
        self.share_text = row.as_ref().and_then(|row| row.share.clone());
        self.split_id = webauthn_store::finish_account_split(&row);
        Some(observation)
    }

    /// Decode the staged share the driver authorized releasing.
    pub(super) async fn auth_finish_release(
        &mut self,
        permit: AuthFinishGrantPermit,
    ) -> Option<ShareDecodeObservation> {
        self.permit_epoch = Some(permit.epoch);
        let Some(share_b64) = self.share_text.clone() else {
            self.error = Some(AppError::NotFound(
                crate::recovery::initiate::RECOVERY_UNAVAILABLE.into(),
            ));
            return None;
        };
        let decoded = crate::db::decode_b64(&share_b64);
        let observation = webauthn_store::classify_share_release(true, decoded.is_ok())?;
        match decoded {
            Ok(bytes) => self.share_bytes = Some(bytes),
            Err(error) => self.share_error = Some(error),
        }
        Some(observation)
    }

    /// Store exactly one single-use enrollment grant.
    pub(super) async fn auth_finish_store_grant(&mut self) -> Option<GrantStoreObservation> {
        let (Some(key_epoch), Some(credential_id)) =
            (self.permit_epoch, self.credential_id.clone())
        else {
            self.error = Some(AppError::Internal(
                "WebAuthn recovery driver admitted an incomplete release".into(),
            ));
            return None;
        };
        let recovery_grant = self.drawn_grant.unwrap_or_else(Uuid::new_v4);
        let grant = RecoveryEnrollGrant::credential_bound(key_epoch, &credential_id);
        let value = match serde_json::to_string(&grant) {
            Ok(value) => value,
            Err(error) => {
                self.recovery_grant = Some(recovery_grant);
                self.grant_error = Some(AppError::Internal(format!(
                    "failed to serialize recovery grant: {error}"
                )));
                return Some(webauthn_store::classify_grant_store(false));
            }
        };
        let stmt = webauthn_store::plan_store_credential_grant(
            enroll_grant_key(self.user_id, recovery_grant),
            value,
            CredentialGrantView {
                key_epoch,
                credential_id: credential_id.clone(),
                possession: false,
            },
            ENROLL_GRANT_TTL_SECS,
        );
        let observation = match store_credential_grant(&mut self.kv, &stmt) {
            Ok(()) => webauthn_store::classify_grant_store(true),
            Err(error) => {
                self.grant_error = Some(error);
                webauthn_store::classify_grant_store(false)
            }
        };
        self.recovery_grant = Some(recovery_grant);
        Some(observation)
    }
}

pub(crate) fn enroll_grant_key(user_id: Uuid, grant: Uuid) -> String {
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

pub(crate) fn decode_enroll_grant(value: &[u8]) -> Result<RecoveryEnrollGrant> {
    let grant: RecoveryEnrollGrant = serde_json::from_slice(value)
        .map_err(|_| AppError::Unauthorized("recovery grant is invalid".into()))?;
    if grant.key_epoch < 1 || grant.credential_id.is_empty() {
        return Err(AppError::Unauthorized("recovery grant is invalid".into()));
    }
    Ok(grant)
}

/// Grant issued from an RMS-possession proof; releases no server share and is
/// bound to no credential. The possession executor now stores it through its
/// extracted `PutEnrollmentGrant` plan, so only the grant value itself is
/// shared here.
pub(crate) fn possession_grant(key_epoch: i64) -> RecoveryEnrollGrant {
    RecoveryEnrollGrant::from_possession_proof(key_epoch)
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
