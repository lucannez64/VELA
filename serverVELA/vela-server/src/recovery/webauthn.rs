use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::webauthn_driver::{
    begin_registration, begin_registration_start, on_credential_looked_up,
    on_credential_persisted, on_registration_attempt_counted, on_registration_ceremony_started,
    on_registration_start_observed, on_registration_start_stored, on_registration_state_consumed,
    on_registration_verified, AttemptBudgetObservation, CeremonyStartObservation,
    ChallengeStoreObservation, CredentialPersistObservation, CredentialUniquenessObservation,
    RegistrationEffect, RegistrationFailure, RegistrationStartEffect,
    RegistrationStartFailure, RegistrationStartObservation, RegistrationStateObservation,
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
    // Effect: observe the currently stored credential (or its absence).
    let observed = observe_recovery_credential(&state, session.user_id).await?;

    let start = begin_registration_start();
    debug_assert_eq!(start.effect, RegistrationStartEffect::Observe);
    let transition = on_registration_start_observed(
        start.driver,
        RegistrationStartObservation {
            account_present: observed.account_present,
            credential: observed.credential,
        },
    );
    match transition.effect {
        RegistrationStartEffect::StartCeremony => {}
        RegistrationStartEffect::Fail(failure) => {
            return Err(registration_start_failure(failure, observed.decode_error))
        }
        _ => {
            return Err(AppError::Internal(
                "registration-start driver produced an unexpected observation effect".into(),
            ))
        }
    }
    let exclude_credentials: Option<Vec<CredentialID>> =
        observed.passkey.map(|pk| vec![pk.cred_id().clone()]);
    let user_name = body
        .user_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| session.user_id.to_string());
    let user_display_name = body
        .user_display_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "VELA recovery key".to_string());

    let ceremony = state.webauthn.start_passkey_registration(
        session.user_id,
        &user_name,
        &user_display_name,
        exclude_credentials,
    );
    let (challenge, reg_state) = match ceremony {
        Ok(value) => value,
        Err(e) => {
            let failed = on_registration_ceremony_started(
                transition.driver,
                CeremonyStartObservation::Failed,
            );
            debug_assert_eq!(
                failed.effect,
                RegistrationStartEffect::Fail(RegistrationStartFailure::CeremonyFailed)
            );
            return Err(AppError::BadRequest(format!(
                "failed to start WebAuthn registration: {e:?}"
            )));
        }
    };
    let transition = on_registration_ceremony_started(
        transition.driver,
        CeremonyStartObservation::Started,
    );
    if !matches!(transition.effect, RegistrationStartEffect::StoreState) {
        return Err(AppError::Internal(
            "registration-start driver produced an unexpected ceremony effect".into(),
        ));
    }

    let write = store_register_state(&state, session.user_id, &reg_state);
    let observation = if write.is_ok() {
        ChallengeStoreObservation::Stored
    } else {
        ChallengeStoreObservation::StorageFailed
    };
    let transition = on_registration_start_stored(transition.driver, observation);
    match transition.effect {
        RegistrationStartEffect::Complete => {}
        RegistrationStartEffect::Fail(RegistrationStartFailure::StateStorage) => {
            return Err(write.err().unwrap_or_else(|| {
                AppError::Internal("failed to store registration state".into())
            }))
        }
        _ => {
            return Err(AppError::Internal(
                "registration-start driver produced an unexpected store effect".into(),
            ))
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(RegisterStartResponse {
            public_key: challenge,
        }),
    ))
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
    // setup); this bounds how often any single account can drive the
    // duplicate-credential lookup below, independent of the generic
    // per-JTI request limiter.
    let limited = rate_limit::webauthn_register_by_user(&state.store, &session.user_id.to_string())
        .err();
    let start = begin_registration();
    debug_assert_eq!(start.effect, RegistrationEffect::CountAttempt);
    let budget = if limited.is_some() {
        AttemptBudgetObservation::Limited
    } else {
        AttemptBudgetObservation::Admitted
    };
    let transition = on_registration_attempt_counted(start.driver, budget);
    let mut driver = transition.driver;
    match (transition.effect, limited) {
        (RegistrationEffect::ConsumeState, None) => {}
        (RegistrationEffect::Fail(RegistrationFailure::AttemptLimited), Some(error)) => {
            return Err(error)
        }
        _ => {
            return Err(AppError::Internal(
                "registration driver produced an unexpected budget effect".into(),
            ))
        }
    }

    let (observation, reg_state, state_error) = match take_register_state(&state, session.user_id)? {
        StoredRegisterState::Missing => (RegistrationStateObservation::Missing, None, None),
        StoredRegisterState::Corrupt(error) => {
            (RegistrationStateObservation::Corrupt, None, Some(error))
        }
        StoredRegisterState::Present(reg_state) => {
            (RegistrationStateObservation::Present, Some(reg_state), None)
        }
    };
    let transition = on_registration_state_consumed(driver, observation);
    driver = transition.driver;
    match transition.effect {
        RegistrationEffect::VerifyRegistration => {}
        RegistrationEffect::Fail(RegistrationFailure::StateUnavailable) => {
            return Err(AppError::BadRequest(
                "registration challenge expired or already used".into(),
            ))
        }
        RegistrationEffect::Fail(RegistrationFailure::StateCorrupt) => {
            return Err(state_error.unwrap_or_else(|| {
                AppError::BadRequest("invalid registration state".into())
            }))
        }
        _ => {
            return Err(AppError::Internal(
                "registration driver produced an unexpected consumption effect".into(),
            ))
        }
    }
    let reg_state = reg_state.ok_or_else(|| {
        AppError::Internal("registration driver admitted an undecoded state".into())
    })?;

    let verification = state
        .webauthn
        .finish_passkey_registration(&credential, &reg_state);
    let (passkey, verification_error) = match verification {
        Ok(passkey) => (Some(passkey), None),
        Err(e) => (
            None,
            Some(AppError::Unauthorized(format!(
                "WebAuthn registration failed: {e:?}"
            ))),
        ),
    };
    let transition = on_registration_verified(
        driver,
        RegistrationVerificationObservation {
            credential_valid: passkey.is_some(),
        },
    );
    driver = transition.driver;
    match transition.effect {
        RegistrationEffect::CheckCredentialUniqueness => {}
        RegistrationEffect::Fail(RegistrationFailure::VerificationFailed) => {
            return Err(verification_error.unwrap_or_else(|| {
                AppError::Unauthorized("WebAuthn registration failed".into())
            }))
        }
        _ => {
            return Err(AppError::Internal(
                "registration driver produced an unexpected verification effect".into(),
            ))
        }
    }
    let passkey = passkey.ok_or_else(|| {
        AppError::Internal("registration driver admitted an unverified credential".into())
    })?;

    let (observation, uniqueness_error) =
        match assert_credential_not_registered_elsewhere(&state, session.user_id, &passkey).await {
            Ok(()) => (CredentialUniquenessObservation::Unique, None),
            Err(AppError::Conflict(message)) => {
                let _ = message;
                (CredentialUniquenessObservation::RegisteredElsewhere, None)
            }
            Err(error) => (CredentialUniquenessObservation::LookupFailed, Some(error)),
        };
    let transition = on_credential_looked_up(driver, observation);
    driver = transition.driver;
    match transition.effect {
        RegistrationEffect::PersistCredential => {}
        RegistrationEffect::Fail(RegistrationFailure::UniquenessConflict) => {
            return Err(AppError::Conflict(
                "WebAuthn credential is already registered to another account".into(),
            ))
        }
        RegistrationEffect::Fail(RegistrationFailure::UniquenessStorage) => {
            return Err(uniqueness_error.unwrap_or_else(|| {
                AppError::Internal("failed to check credential uniqueness".into())
            }))
        }
        _ => {
            return Err(AppError::Internal(
                "registration driver produced an unexpected uniqueness effect".into(),
            ))
        }
    }

    // Effect: serialize and write the credential. Serialization failure, a
    // storage error and a zero-row update are observations the driver
    // classifies; the original error is rendered unchanged.
    let (observation, persist_error) = match serde_json::to_string(&passkey) {
        Err(e) => (
            CredentialPersistObservation::EncodingFailed,
            Some(AppError::Internal(format!("failed to serialize passkey: {e}"))),
        ),
        Ok(passkey_json) => {
            let cred_id = cred_id_b64(&passkey);
            match state
                .sqldb
                .execute(
                    "UPDATE users SET recovery_webauthn_credential = ?, recovery_webauthn_cred_id = ? WHERE id = ?",
                    vec![
                        TursoValue::Text(passkey_json),
                        TursoValue::Text(cred_id),
                        TursoValue::Text(session.user_id.to_string()),
                    ],
                )
                .await
            {
                Err(e) => (
                    CredentialPersistObservation::StorageFailed,
                    Some(AppError::Internal(e.to_string())),
                ),
                Ok(1) => (CredentialPersistObservation::Persisted, None),
                Ok(_) => (CredentialPersistObservation::AccountGone, None),
            }
        }
    };
    let transition = on_credential_persisted(driver, observation);
    match transition.effect {
        RegistrationEffect::Complete => {}
        RegistrationEffect::Fail(RegistrationFailure::AccountGone) => {
            return Err(AppError::NotFound("account no longer exists".into()))
        }
        RegistrationEffect::Fail(RegistrationFailure::PersistEncoding) => {
            return Err(persist_error.unwrap_or_else(|| {
                AppError::Internal("failed to serialize recovery passkey".into())
            }))
        }
        RegistrationEffect::Fail(RegistrationFailure::PersistStorage) => {
            return Err(persist_error.unwrap_or_else(|| {
                AppError::Internal("failed to store the recovery passkey".into())
            }))
        }
        _ => {
            return Err(AppError::Internal(
                "registration driver produced an unexpected persist effect".into(),
            ))
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(RegisterFinishResponse { registered: true })))
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
