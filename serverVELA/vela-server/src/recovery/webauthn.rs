use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::webauthn_driver::{
    AttemptBudgetObservation, CeremonyStartObservation, ChallengeStoreObservation,
    CredentialPersistObservation, CredentialUniquenessObservation, RegistrationEffect,
    RegistrationFailure, RegistrationStartEffect, RegistrationStartFailure,
    RegistrationStartObservation, RegistrationStateObservation,
    RegistrationVerificationObservation,
};
use vela_recovery_policy::webauthn_store::{self, CredentialHolderView, RegistrationStateTake, SetOutcome};
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyRegistration,
    RegisterPublicKeyCredential,
};

use super::sql::{
    credential_row, holder_view, run_webauthn_read, run_webauthn_writes,
    store_registration_state, take_registration_state, PoolSql, RecoveryKv, RecoverySql, StoreKv,
};
use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, DeviceSession},
    rate_limit,
    sqldb::{Db as _, TursoDb, TursoValue},
    state::AppState,
};

pub(crate) fn cred_id_b64(passkey: &Passkey) -> String {
    B64.encode(passkey.cred_id().as_slice())
}

const REGISTER_STATE_TTL_SECS: u64 = 300;

#[derive(Serialize)]
pub struct WebauthnConfigResponse {
    pub rp_id: String,
    pub rp_origin: String,
}

/// Publicly exposes the server's configured WebAuthn relying-party id/origin
/// (`WEBAUTHN_RP_ID`/`WEBAUTHN_RP_ORIGIN`) so native clients — which have no
/// browser "page origin" of their own to derive this from — can construct a
/// `clientDataJSON` that this server's `webauthn-rs` verifier will actually
/// accept, without requiring the user to hand-configure a value that must
/// match this deployment's own server-side setting exactly. Neither value is
/// a secret: `rp_id` is echoed back in every registration/assertion
/// challenge already, and `rp_origin` is comparable to a public redirect URI
/// in OAuth — deployment metadata, not an authorization credential.
pub async fn get_webauthn_config(State(state): State<AppState>) -> Json<WebauthnConfigResponse> {
    Json(WebauthnConfigResponse {
        rp_id: state.config.webauthn_rp_id.clone(),
        rp_origin: state.config.webauthn_rp_origin.clone(),
    })
}

#[derive(Deserialize)]
pub struct RegisterStartRequest {
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterStartResponse {
    pub public_key: CreationChallengeResponse,
}

#[derive(Serialize)]
pub struct RegisterFinishResponse {
    pub registered: bool,
}

/// One-time startup backfill: populate `recovery_webauthn_cred_id` for rows
/// that only have the legacy `recovery_webauthn_credential` JSON blob (i.e.
/// registered before the indexed column existed), so the duplicate-credential
/// check below covers them too instead of silently skipping pre-migration
/// passkeys. Cheap after the first run since the WHERE clause then matches
/// nothing.
pub(crate) async fn backfill_webauthn_cred_ids(db: &TursoDb) -> anyhow::Result<()> {
    let rows = db
        .query(
            "SELECT id, recovery_webauthn_credential FROM users
             WHERE recovery_webauthn_credential IS NOT NULL AND recovery_webauthn_cred_id IS NULL",
            vec![],
        )
        .await?;

    for row in &rows {
        let Some(id) = row.text(0) else {
            continue;
        };
        let Some(passkey_json) = row.text(1) else {
            continue;
        };
        let id = id.to_string();
        let passkey: Passkey = match serde_json::from_str(passkey_json) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!(
                    user_id = %id,
                    error = %e,
                    "skipping unparseable legacy WebAuthn credential during backfill"
                );
                continue;
            }
        };
        let cred_id = cred_id_b64(&passkey);
        if let Err(e) = db
            .execute(
                "UPDATE users SET recovery_webauthn_cred_id = ? WHERE id = ?",
                vec![TursoValue::Text(cred_id), TursoValue::Text(id.clone())],
            )
            .await
        {
            tracing::warn!(
                user_id = %id,
                error = %e,
                "failed to backfill recovery_webauthn_cred_id"
            );
        }
    }
    Ok(())
}

pub async fn post_register_start(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<RegisterStartRequest>,
) -> Result<(HeaderMap, Json<RegisterStartResponse>)> {
    // Effect: observe the currently stored credential, start the registration
    // ceremony and store its state. Every post-preflight decision and effect
    // goes through the proved `registration_start_interpreter!` loop; this
    // handler only supplies the I/O and renders the terminal effect.
    let mut io = RegisterStartIo {
        state: &state,
        sql: PoolSql(&state.sqldb),
        kv: StoreKv(&state.store),
        user_id: session.user_id,
        user_name: body.user_name,
        user_display_name: body.user_display_name,
        passkey: None,
        decode_error: None,
        challenge: None,
        reg_state: None,
        ceremony_error: None,
        store_error: None,
        error: None,
    };
    let Some(transition) = vela_recovery_policy::registration_start_interpreter!(io, await) else {
        return Err(io.error.take().unwrap_or_else(|| {
            AppError::Internal("registration-start aborted without an error".into())
        }));
    };
    match transition.effect {
        RegistrationStartEffect::Complete => {}
        RegistrationStartEffect::Fail(RegistrationStartFailure::CeremonyFailed) => {
            return Err(io.ceremony_error.take().unwrap_or_else(|| {
                AppError::BadRequest("failed to start WebAuthn registration".into())
            }))
        }
        RegistrationStartEffect::Fail(RegistrationStartFailure::StateStorage) => {
            return Err(io.store_error.take().unwrap_or_else(|| {
                AppError::Internal("failed to store registration state".into())
            }))
        }
        RegistrationStartEffect::Fail(failure) => {
            return Err(registration_start_failure(failure, io.decode_error.take()))
        }
        _ => {
            return Err(AppError::Internal(
                "registration-start driver reached no verdict".into(),
            ))
        }
    }
    let challenge = io.challenge.take().ok_or_else(|| {
        AppError::Internal("registration-start completed without a challenge".into())
    })?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(RegisterStartResponse {
            public_key: challenge,
        }),
    ))
}

/// The I/O behind each registration-start effect. The driver decides which
/// method runs and when (through the shared `registration_start_interpreter!`
/// loop, proved in F* as `run_registration_start`); each method only performs
/// its effect and reports the observation. `None` aborts with `error`.
pub(super) struct RegisterStartIo<'a, S, K> {
    state: &'a AppState,
    sql: S,
    kv: K,
    user_id: Uuid,
    user_name: Option<String>,
    user_display_name: Option<String>,
    passkey: Option<Passkey>,
    decode_error: Option<AppError>,
    challenge: Option<CreationChallengeResponse>,
    reg_state: Option<PasskeyRegistration>,
    ceremony_error: Option<AppError>,
    store_error: Option<AppError>,
    error: Option<AppError>,
}

impl<S: RecoverySql, K: RecoveryKv> RegisterStartIo<'_, S, K> {
    /// Observe the currently stored recovery credential (or its absence).
    pub(super) async fn registration_start_observe(&mut self) -> Option<RegistrationStartObservation> {
        let stmt = webauthn_store::plan_select_credential(self.user_id.to_string());
        let rows = match run_webauthn_read(&mut self.sql, &stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let observed = match credential_row(&rows) {
            Ok(observed) => observed,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        self.passkey = observed.passkey;
        self.decode_error = observed.decode_error;
        Some(webauthn_store::classify_registration_start(&observed.view))
    }

    /// Start the registration ceremony, excluding the observed credential.
    async fn registration_start_ceremony(&mut self) -> Option<CeremonyStartObservation> {
        let exclude_credentials: Option<Vec<CredentialID>> =
            self.passkey.take().map(|pk| vec![pk.cred_id().clone()]);
        let user_name = self
            .user_name
            .take()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| self.user_id.to_string());
        let user_display_name = self
            .user_display_name
            .take()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "VELA recovery key".to_string());
        let ceremony = self.state.webauthn.start_passkey_registration(
            self.user_id,
            &user_name,
            &user_display_name,
            exclude_credentials,
        );
        match ceremony {
            Ok((challenge, reg_state)) => {
                self.challenge = Some(challenge);
                self.reg_state = Some(reg_state);
                Some(CeremonyStartObservation::Started)
            }
            Err(error) => {
                self.ceremony_error = Some(AppError::BadRequest(format!(
                    "failed to start WebAuthn registration: {error:?}"
                )));
                Some(CeremonyStartObservation::Failed)
            }
        }
    }

    /// Write the registration state with `set_ex`.
    async fn registration_start_store(&mut self) -> Option<ChallengeStoreObservation> {
        let Some(reg_state) = self.reg_state.take() else {
            self.error = Some(AppError::Internal(
                "registration-start driver admitted an incomplete ceremony".into(),
            ));
            return None;
        };
        let value = match serde_json::to_string(&reg_state) {
            Ok(value) => value,
            Err(e) => {
                self.error = Some(AppError::Internal(format!(
                    "failed to serialize registration state: {e}"
                )));
                return None;
            }
        };
        self.write_registration_state(value).await
    }

    /// The write half of `registration_start_store`: write exactly one
    /// ceremony state at the account's registration key.
    pub(super) async fn write_registration_state(&mut self, value: String) -> Option<ChallengeStoreObservation> {
        let stmt = webauthn_store::plan_store_registration_state(
            webauthn_store::registration_state_key(&self.user_id.to_string()),
            value,
            REGISTER_STATE_TTL_SECS,
        );
        let outcome = match store_registration_state(&mut self.kv, &stmt) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.store_error = Some(error);
                SetOutcome::Failed
            }
        };
        Some(webauthn_store::classify_store_registration_state(&outcome))
    }
}

/// Construction and side-channel access for the bounded real-database
/// conformance test (`recovery/conformance.rs`).
#[cfg(test)]
impl<'a, S, K> RegisterStartIo<'a, S, K> {
    pub(super) fn for_conformance(
        state: &'a AppState,
        sql: S,
        kv: K,
        user_id: Uuid,
    ) -> Self {
        Self {
            state,
            sql,
            kv,
            user_id,
            user_name: None,
            user_display_name: None,
            passkey: None,
            decode_error: None,
            challenge: None,
            reg_state: None,
            ceremony_error: None,
            store_error: None,
            error: None,
        }
    }

    pub(super) fn error_is_set(&self) -> bool {
        self.error.is_some()
    }
}

/// Render a registration-start failure with the handler's historical status and
/// message. The corrupt-credential class carries the original decode error.
fn registration_start_failure(
    failure: RegistrationStartFailure,
    decode_error: Option<AppError>,
) -> AppError {
    match failure {
        RegistrationStartFailure::AccountUnavailable => {
            AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into())
        }
        RegistrationStartFailure::CredentialCorrupt => decode_error.unwrap_or_else(|| {
            AppError::Internal("invalid stored WebAuthn credential".into())
        }),
        RegistrationStartFailure::CeremonyFailed => {
            AppError::BadRequest("failed to start WebAuthn registration".into())
        }
        RegistrationStartFailure::StateStorage => {
            AppError::Internal("failed to store registration state".into())
        }
    }
}

pub async fn post_register_finish(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Result<(HeaderMap, Json<RegisterFinishResponse>)> {
    // Registration ceremonies are rare in normal use (one per recovery-key
    // setup). Count the attempt, consume the state, verify the ceremony, check
    // credential uniqueness and persist. Every post-preflight decision and
    // effect goes through the proved `registration_interpreter!` loop; this
    // handler only supplies the I/O and renders the terminal effect.
    let mut io = RegisterFinishIo {
        state: &state,
        sql: PoolSql(&state.sqldb),
        kv: StoreKv(&state.store),
        user_id: session.user_id,
        credential,
        limited_error: None,
        reg_state: None,
        state_error: None,
        passkey: None,
        verification_error: None,
        uniqueness_error: None,
        persist_error: None,
        error: None,
    };
    let Some(transition) = vela_recovery_policy::registration_interpreter!(io, await) else {
        return Err(io.error.take().unwrap_or_else(|| {
            AppError::Internal("registration aborted without an error".into())
        }));
    };
    match transition.effect {
        RegistrationEffect::Complete => {}
        RegistrationEffect::Fail(failure) => return Err(registration_failure_error(failure, &mut io)),
        _ => {
            return Err(AppError::Internal(
                "registration driver reached no verdict".into(),
            ))
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(RegisterFinishResponse { registered: true })))
}

#[cfg(test)]
impl<'a, S, K> RegisterFinishIo<'a, S, K> {
    pub(super) fn for_conformance(
        state: &'a AppState,
        sql: S,
        kv: K,
        user_id: Uuid,
    ) -> Self {
        Self {
            state,
            sql,
            kv,
            user_id,
            credential: RegisterPublicKeyCredential {
                id: "unused".into(),
                raw_id: Default::default(),
                response: webauthn_rs_core::proto::AuthenticatorAttestationResponseRaw {
                    attestation_object: Default::default(),
                    client_data_json: Default::default(),
                    transports: None,
                },
                type_: "public-key".into(),
                extensions: Default::default(),
            },
            limited_error: None,
            reg_state: None,
            state_error: None,
            passkey: None,
            verification_error: None,
            uniqueness_error: None,
            persist_error: None,
            error: None,
        }
    }

    pub(super) fn set_passkey(&mut self, passkey: Passkey) {
        self.passkey = Some(passkey);
    }

    pub(super) fn persist_error_is_set(&self) -> bool {
        self.persist_error.is_some()
    }
}

/// Render a registration failure with the handler's historical status and
/// message, preferring the original error captured by the effect.
fn registration_failure_error<S, K>(
    failure: RegistrationFailure,
    io: &mut RegisterFinishIo<'_, S, K>,
) -> AppError {
    match failure {
        RegistrationFailure::AttemptLimited => io.limited_error.take().unwrap_or_else(|| {
            AppError::Internal("registration attempt was limited".into())
        }),
        RegistrationFailure::StateUnavailable => AppError::BadRequest(
            "registration challenge expired or already used".into(),
        ),
        RegistrationFailure::StateCorrupt => io.state_error.take().unwrap_or_else(|| {
            AppError::BadRequest("invalid registration state".into())
        }),
        RegistrationFailure::VerificationFailed => {
            io.verification_error.take().unwrap_or_else(|| {
                AppError::Unauthorized("WebAuthn registration failed".into())
            })
        }
        RegistrationFailure::UniquenessConflict => AppError::Conflict(
            "WebAuthn credential is already registered to another account".into(),
        ),
        RegistrationFailure::UniquenessStorage => {
            io.uniqueness_error.take().unwrap_or_else(|| {
                AppError::Internal("failed to check credential uniqueness".into())
            })
        }
        RegistrationFailure::AccountGone => {
            AppError::NotFound("account no longer exists".into())
        }
        RegistrationFailure::PersistEncoding => io.persist_error.take().unwrap_or_else(|| {
            AppError::Internal("failed to serialize recovery passkey".into())
        }),
        RegistrationFailure::PersistStorage => io.persist_error.take().unwrap_or_else(|| {
            AppError::Internal("failed to store the recovery passkey".into())
        }),
        RegistrationFailure::PolicyRejected => AppError::Internal(
            "verified recovery policy rejected credential registration".into(),
        ),
    }
}

/// The I/O behind each registration-finish effect. The driver decides which
/// method runs and when (through the shared `registration_interpreter!` loop,
/// proved in F* as `run_registration`); each method only performs its effect
/// and reports the observation. `None` aborts with `error`.
pub(super) struct RegisterFinishIo<'a, S, K> {
    state: &'a AppState,
    sql: S,
    kv: K,
    user_id: Uuid,
    credential: RegisterPublicKeyCredential,
    limited_error: Option<AppError>,
    reg_state: Option<PasskeyRegistration>,
    state_error: Option<AppError>,
    passkey: Option<Passkey>,
    verification_error: Option<AppError>,
    uniqueness_error: Option<AppError>,
    persist_error: Option<AppError>,
    error: Option<AppError>,
}

impl<S: RecoverySql, K: RecoveryKv> RegisterFinishIo<'_, S, K> {
    /// Count one attempt against the registration limiter.
    async fn registration_count_attempt(&mut self) -> Option<AttemptBudgetObservation> {
        let limited = rate_limit::webauthn_register_by_user(
            &self.state.store,
            &self.user_id.to_string(),
        )
        .err();
        let observation = if limited.is_some() {
            AttemptBudgetObservation::Limited
        } else {
            AttemptBudgetObservation::Admitted
        };
        self.limited_error = limited;
        Some(observation)
    }

    /// Perform the atomic single-use `get_del` of the registration state.
    pub(super) async fn registration_consume_state(&mut self) -> Option<RegistrationStateObservation> {
        let stmt = webauthn_store::plan_take_registration_state(
            webauthn_store::registration_state_key(&self.user_id.to_string()),
        );
        let bytes = match take_registration_state(&mut self.kv, &stmt) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        let taken = match bytes {
            None => RegistrationStateTake::Missing,
            Some(bytes) => match serde_json::from_slice::<PasskeyRegistration>(&bytes) {
                Ok(reg_state) => {
                    self.reg_state = Some(reg_state);
                    RegistrationStateTake::Present
                }
                Err(e) => {
                    self.state_error = Some(AppError::BadRequest(format!(
                        "invalid registration state: {e}"
                    )));
                    RegistrationStateTake::Corrupt
                }
            },
        };
        Some(webauthn_store::classify_registration_state(&taken))
    }

    /// Verify the presented registration ceremony.
    async fn registration_verify(&mut self) -> Option<RegistrationVerificationObservation> {
        let Some(reg_state) = self.reg_state.as_ref() else {
            self.error = Some(AppError::Internal(
                "registration driver admitted an undecoded state".into(),
            ));
            return None;
        };
        match self
            .state
            .webauthn
            .finish_passkey_registration(&self.credential, reg_state)
        {
            Ok(passkey) => {
                self.passkey = Some(passkey);
                Some(RegistrationVerificationObservation {
                    credential_valid: true,
                })
            }
            Err(error) => {
                self.verification_error = Some(AppError::Unauthorized(format!(
                    "WebAuthn registration failed: {error:?}"
                )));
                Some(RegistrationVerificationObservation {
                    credential_valid: false,
                })
            }
        }
    }

    /// Look the credential up across accounts.
    pub(super) async fn registration_check_uniqueness(&mut self) -> Option<CredentialUniquenessObservation> {
        let Some(passkey) = self.passkey.as_ref() else {
            self.error = Some(AppError::Internal(
                "registration driver admitted an unverified credential".into(),
            ));
            return None;
        };
        let stmt = webauthn_store::plan_credential_holders(cred_id_b64(passkey));
        let view = match run_webauthn_read(&mut self.sql, &stmt).await {
            Ok(rows) => {
                let (view, error) = holder_view(&rows, &self.user_id.to_string());
                if let Some(error) = error {
                    self.uniqueness_error = Some(error);
                }
                view
            }
            Err(error) => {
                self.uniqueness_error = Some(AppError::Internal(error.to_string()));
                CredentialHolderView::Unreadable
            }
        };
        Some(webauthn_store::classify_uniqueness(&view))
    }

    /// Serialize and write the credential after the checked policy permit.
    async fn registration_persist(&mut self) -> Option<CredentialPersistObservation> {
        let Some(passkey) = self.passkey.as_ref() else {
            self.error = Some(AppError::Internal(
                "registration driver admitted an unverified credential".into(),
            ));
            return None;
        };
        match serde_json::to_string(passkey) {
            Err(error) => {
                self.persist_error =
                    Some(AppError::Internal(format!("failed to serialize passkey: {error}")));
                Some(webauthn_store::classify_persist_credential(false, &[]))
            }
            Ok(passkey_json) => {
                let cred_id = cred_id_b64(passkey);
                self.persist_credential_json(passkey_json, cred_id).await
            }
        }
    }

    /// The write half of `registration_persist`: exactly one guarded `UPDATE`.
    pub(super) async fn persist_credential_json(
        &mut self,
        credential: String,
        credential_id: String,
    ) -> Option<CredentialPersistObservation> {
        let stmt = webauthn_store::plan_persist_credential(
            self.user_id.to_string(),
            credential,
            credential_id,
        );
        let (outcomes, error) = run_webauthn_writes(&mut self.sql, std::slice::from_ref(&stmt)).await;
        if let Some(error) = error {
            self.persist_error = Some(AppError::Internal(error.to_string()));
        }
        Some(webauthn_store::classify_persist_credential(true, &outcomes))
    }
}
