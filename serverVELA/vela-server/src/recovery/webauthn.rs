use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::webauthn_driver::{
    AttemptBudgetObservation, CeremonyStartObservation, ChallengeStoreObservation,
    CredentialPersistObservation, CredentialUniquenessObservation, RegistrationEffect,
    RegistrationFailure, RegistrationStartEffect, RegistrationStartFailure,
    RegistrationStartObservation, RegistrationStateObservation,
    RegistrationVerificationObservation, StoredCredentialObservation,
};
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyRegistration,
    RegisterPublicKeyCredential,
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

/// The stored recovery credential as an observation rather than an error.
/// Account absence and JSON corruption are distinct facts the pure driver
/// classifies; only a storage error short-circuits here.
pub(crate) struct RecoveryCredentialObservation {
    pub account_present: bool,
    pub credential: StoredCredentialObservation,
    pub passkey: Option<Passkey>,
    pub decode_error: Option<AppError>,
}

pub(crate) async fn observe_recovery_credential(
    state: &AppState,
    user_id: Uuid,
) -> Result<RecoveryCredentialObservation> {
    let rows = state
        .sqldb
        .query(
            "SELECT recovery_webauthn_credential FROM users WHERE id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(row) = rows.first() else {
        return Ok(RecoveryCredentialObservation {
            account_present: false,
            credential: StoredCredentialObservation::Missing,
            passkey: None,
            decode_error: None,
        });
    };
    Ok(match row.get(0) {
        Some(TursoValue::Null) | None => RecoveryCredentialObservation {
            account_present: true,
            credential: StoredCredentialObservation::Missing,
            passkey: None,
            decode_error: None,
        },
        Some(TursoValue::Text(passkey_json)) => match serde_json::from_str(passkey_json) {
            Ok(passkey) => RecoveryCredentialObservation {
                account_present: true,
                credential: StoredCredentialObservation::Present,
                passkey: Some(passkey),
                decode_error: None,
            },
            Err(e) => RecoveryCredentialObservation {
                account_present: true,
                credential: StoredCredentialObservation::Corrupt,
                passkey: None,
                decode_error: Some(AppError::Internal(format!(
                    "invalid stored WebAuthn credential: {e}"
                ))),
            },
        },
        _ => {
            return Err(AppError::Internal(
                "expected WebAuthn credential JSON".into(),
            ))
        }
    })
}

pub(crate) async fn update_recovery_passkey_if_current(
    state: &AppState,
    user_id: Uuid,
    expected_cred_id: &str,
    passkey: &Passkey,
) -> Result<bool> {
    let passkey_json = serde_json::to_string(passkey)
        .map_err(|e| AppError::Internal(format!("failed to serialize passkey: {e}")))?;
    let cred_id = cred_id_b64(passkey);
    let updated = state
        .sqldb
        .execute(
            "UPDATE users SET recovery_webauthn_credential = ?, recovery_webauthn_cred_id = ?
             WHERE id = ? AND recovery_webauthn_cred_id = ?",
            vec![
                TursoValue::Text(passkey_json),
                TursoValue::Text(cred_id),
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(expected_cred_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(updated == 1)
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
struct RegisterStartIo<'a> {
    state: &'a AppState,
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

impl RegisterStartIo<'_> {
    /// Observe the currently stored recovery credential (or its absence).
    async fn registration_start_observe(&mut self) -> Option<RegistrationStartObservation> {
        let observed = match observe_recovery_credential(self.state, self.user_id).await {
            Ok(observed) => observed,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        self.passkey = observed.passkey;
        self.decode_error = observed.decode_error;
        Some(RegistrationStartObservation {
            account_present: observed.account_present,
            credential: observed.credential,
        })
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
        let write = store_register_state(self.state, self.user_id, &reg_state);
        let observation = if write.is_ok() {
            ChallengeStoreObservation::Stored
        } else {
            ChallengeStoreObservation::StorageFailed
        };
        self.store_error = write.err();
        Some(observation)
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

/// Render a registration failure with the handler's historical status and
/// message, preferring the original error captured by the effect.
fn registration_failure_error(failure: RegistrationFailure, io: &mut RegisterFinishIo<'_>) -> AppError {
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
struct RegisterFinishIo<'a> {
    state: &'a AppState,
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

impl RegisterFinishIo<'_> {
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
    async fn registration_consume_state(&mut self) -> Option<RegistrationStateObservation> {
        let observed = match take_register_state(self.state, self.user_id) {
            Ok(observed) => observed,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        let observation = match observed {
            StoredRegisterState::Missing => RegistrationStateObservation::Missing,
            StoredRegisterState::Corrupt(error) => {
                self.state_error = Some(error);
                RegistrationStateObservation::Corrupt
            }
            StoredRegisterState::Present(reg_state) => {
                self.reg_state = Some(reg_state);
                RegistrationStateObservation::Present
            }
        };
        Some(observation)
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
    async fn registration_check_uniqueness(&mut self) -> Option<CredentialUniquenessObservation> {
        let Some(passkey) = self.passkey.as_ref() else {
            self.error = Some(AppError::Internal(
                "registration driver admitted an unverified credential".into(),
            ));
            return None;
        };
        match assert_credential_not_registered_elsewhere(self.state, self.user_id, passkey).await {
            Ok(()) => Some(CredentialUniquenessObservation::Unique),
            Err(AppError::Conflict(_)) => {
                Some(CredentialUniquenessObservation::RegisteredElsewhere)
            }
            Err(error) => {
                self.uniqueness_error = Some(error);
                Some(CredentialUniquenessObservation::LookupFailed)
            }
        }
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
                Some(CredentialPersistObservation::EncodingFailed)
            }
            Ok(passkey_json) => {
                let cred_id = cred_id_b64(passkey);
                match self
                    .state
                    .sqldb
                    .execute(
                        "UPDATE users SET recovery_webauthn_credential = ?, recovery_webauthn_cred_id = ? WHERE id = ?",
                        vec![
                            TursoValue::Text(passkey_json),
                            TursoValue::Text(cred_id),
                            TursoValue::Text(self.user_id.to_string()),
                        ],
                    )
                    .await
                {
                    Err(error) => {
                        self.persist_error = Some(AppError::Internal(error.to_string()));
                        Some(CredentialPersistObservation::StorageFailed)
                    }
                    Ok(1) => Some(CredentialPersistObservation::Persisted),
                    Ok(_) => Some(CredentialPersistObservation::AccountGone),
                }
            }
        }
    }
}

fn store_register_state(
    state: &AppState,
    user_id: Uuid,
    reg_state: &PasskeyRegistration,
) -> Result<()> {
    let state_json = serde_json::to_vec(reg_state)
        .map_err(|e| AppError::Internal(format!("failed to serialize registration state: {e}")))?;
    state.store.set_ex(
        &format!("recovery:webauthn:register:{user_id}"),
        &state_json,
        REGISTER_STATE_TTL_SECS,
    )
}

/// One run of the registration-state observation. A decode failure consumed the
/// state: the driver records corruption rather than pretending nothing matched.
pub(crate) enum StoredRegisterState {
    Missing,
    Corrupt(AppError),
    Present(PasskeyRegistration),
}

fn take_register_state(state: &AppState, user_id: Uuid) -> Result<StoredRegisterState> {
    let Some(bytes) = state
        .store
        .get_del(&format!("recovery:webauthn:register:{user_id}"))?
    else {
        return Ok(StoredRegisterState::Missing);
    };
    match serde_json::from_slice(&bytes) {
        Ok(reg_state) => Ok(StoredRegisterState::Present(reg_state)),
        Err(e) => Ok(StoredRegisterState::Corrupt(AppError::BadRequest(
            format!("invalid registration state: {e}"),
        ))),
    }
}

async fn assert_credential_not_registered_elsewhere(
    state: &AppState,
    user_id: Uuid,
    passkey: &Passkey,
) -> Result<()> {
    let cred_id = cred_id_b64(passkey);
    let rows = state
        .sqldb
        .query(
            "SELECT id FROM users WHERE recovery_webauthn_cred_id = ?",
            vec![TursoValue::Text(cred_id)],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    for row in &rows {
        let id = row
            .text(0)
            .map(String::from)
            .ok_or_else(|| AppError::Internal("expected user id".into()))?;
        if id != user_id.to_string() {
            return Err(AppError::Conflict(
                "WebAuthn credential is already registered to another account".into(),
            ));
        }
    }
    Ok(())
}
