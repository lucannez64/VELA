use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;
use vela_recovery_policy::webauthn_driver::{
    AuthStartEffect, AuthStartFailure, AuthStartObservation, CeremonyStartObservation,
    ChallengeStoreObservation,
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

    // Effect: observe availability, decode the stored credential, probe the
    // generated attempt slot, start the authentication ceremony and store the
    // attempt state. Every post-preflight decision and effect goes through the
    // proved `auth_start_interpreter!` loop; this handler only supplies the I/O
    // and renders the terminal effect.
    let mut io = InitiateIo {
        state: &state,
        user_id: body.user_id,
        recovery_id: None,
        passkey: None,
        decode_error: None,
        challenge: None,
        auth_state: None,
        credential_id: None,
        ceremony_error: None,
        store_error: None,
        error: None,
    };
    let Some(transition) = vela_recovery_policy::auth_start_interpreter!(io, await) else {
        return Err(io.error.take().unwrap_or_else(|| {
            AppError::Internal("authentication-start aborted without an error".into())
        }));
    };
    match transition.effect {
        AuthStartEffect::Complete => {}
        AuthStartEffect::Fail(AuthStartFailure::CeremonyFailed) => {
            return Err(io.ceremony_error.take().unwrap_or_else(|| {
                AppError::BadRequest("failed to start WebAuthn recovery".into())
            }))
        }
        AuthStartEffect::Fail(AuthStartFailure::StateStorage) => {
            return Err(io.store_error.take().unwrap_or_else(|| {
                AppError::Internal("failed to store recovery challenge state".into())
            }))
        }
        AuthStartEffect::Fail(failure) => {
            return Err(auth_start_failure(failure, io.decode_error.take()))
        }
        _ => {
            return Err(AppError::Internal(
                "authentication-start driver reached no verdict".into(),
            ))
        }
    }
    let recovery_id = io.recovery_id.ok_or_else(|| {
        AppError::Internal("authentication-start completed without an attempt id".into())
    })?;
    let challenge = io.challenge.take().ok_or_else(|| {
        AppError::Internal("authentication-start completed without a challenge".into())
    })?;

    Ok(Json(InitiateResponse {
        recovery_id,
        public_key: challenge,
    }))
}

/// The I/O behind each authentication-start effect. The driver decides which
/// method runs and when (through the shared `auth_start_interpreter!` loop,
/// proved in F* as `run_auth_start`); each method only performs its effect and
/// reports the observation. `None` aborts with `error`.
struct InitiateIo<'a> {
    state: &'a AppState,
    user_id: Uuid,
    recovery_id: Option<Uuid>,
    passkey: Option<webauthn_rs::prelude::Passkey>,
    decode_error: Option<AppError>,
    challenge: Option<RequestChallengeResponse>,
    auth_state: Option<PasskeyAuthentication>,
    credential_id: Option<String>,
    ceremony_error: Option<AppError>,
    store_error: Option<AppError>,
    error: Option<AppError>,
}

impl InitiateIo<'_> {
    /// Observe availability and the stored credential, then probe the freshly
    /// generated attempt slot. A storage error has no observation.
    async fn auth_start_observe(&mut self) -> Option<AuthStartObservation> {
        let availability = match observe_recovery_share(self.state, self.user_id).await {
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
        let recovery_id = Uuid::new_v4();
        // Observe freshness for the policy. Storage checks it atomically again:
        // another insertion may win after this preflight observation.
        let attempt_id_fresh = match self
            .state
            .store
            .exists(&auth_state_key(self.user_id, recovery_id))
        {
            Ok(occupied) => !occupied,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        self.recovery_id = Some(recovery_id);
        self.passkey = credential.passkey;
        self.decode_error = credential.decode_error;
        Some(AuthStartObservation {
            account_present: availability.account_present,
            share_present: availability.share_present,
            credential: credential.credential,
            attempt_id_fresh,
            ttl_secs: AUTH_STATE_TTL_SECS,
        })
    }

    /// Start the authentication ceremony for the observed credential.
    async fn auth_start_ceremony(&mut self) -> Option<CeremonyStartObservation> {
        let Some(passkey) = self.passkey.take() else {
            self.error = Some(AppError::Internal(
                "authentication-start driver admitted a missing credential".into(),
            ));
            return None;
        };
        let credential_id = B64.encode(passkey.cred_id().as_slice());
        let ceremony = self.state.webauthn.start_passkey_authentication(&[passkey]);
        match ceremony {
            Ok((challenge, auth_state)) => {
                self.challenge = Some(challenge);
                self.auth_state = Some(auth_state);
                self.credential_id = Some(credential_id);
                Some(CeremonyStartObservation::Started)
            }
            Err(error) => {
                self.ceremony_error = Some(AppError::BadRequest(format!(
                    "failed to start WebAuthn recovery: {error:?}"
                )));
                Some(CeremonyStartObservation::Failed)
            }
        }
    }

    /// Atomically store the attempt state with `set_ex_nx`.
    async fn auth_start_store(&mut self) -> Option<ChallengeStoreObservation> {
        let (Some(recovery_id), Some(auth_state), Some(credential_id)) = (
            self.recovery_id,
            self.auth_state.take(),
            self.credential_id.take(),
        ) else {
            self.error = Some(AppError::Internal(
                "authentication-start driver admitted an incomplete ceremony".into(),
            ));
            return None;
        };
        let envelope = RecoveryAuthState {
            user_id: self.user_id,
            recovery_id,
            credential_id,
            auth_state,
        };
        let written = store_auth_state(self.state, &envelope);
        let observation = match &written {
            Ok(()) => ChallengeStoreObservation::Stored,
            Err(AppError::Conflict(_)) => ChallengeStoreObservation::Lost,
            Err(_) => ChallengeStoreObservation::StorageFailed,
        };
        self.store_error = written.err();
        Some(observation)
    }
}

/// Render an initiation failure with the handler's historical status and
/// message. The corrupt-credential class carries the original decode error.
fn auth_start_failure(failure: AuthStartFailure, decode_error: Option<AppError>) -> AppError {
    match failure {
        AuthStartFailure::AccountUnavailable
        | AuthStartFailure::ShareMissing
        | AuthStartFailure::CredentialMissing => {
            AppError::NotFound(RECOVERY_UNAVAILABLE.into())
        }
        AuthStartFailure::CredentialCorrupt => decode_error.unwrap_or_else(|| {
            AppError::Internal("invalid stored WebAuthn credential".into())
        }),
        AuthStartFailure::AttemptCollision => {
            AppError::Conflict("recovery challenge id is already in use".into())
        }
        AuthStartFailure::CeremonyFailed => {
            AppError::BadRequest("failed to start WebAuthn recovery".into())
        }
        AuthStartFailure::PolicyRejected => AppError::Internal(
            "verified recovery policy rejected a valid initiation".into(),
        ),
        AuthStartFailure::StateStorage => {
            AppError::Internal("failed to store recovery challenge state".into())
        }
    }
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

fn auth_state_key(user_id: Uuid, recovery_id: Uuid) -> String {
    format!("recovery:webauthn:auth:{user_id}:{recovery_id}")
}

pub(crate) fn store_auth_state(state: &AppState, envelope: &RecoveryAuthState) -> Result<()> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|e| AppError::Internal(format!("failed to serialize WebAuthn auth state: {e}")))?;
    store_auth_state_bytes(&state.store, envelope.user_id, envelope.recovery_id, &bytes)
}

/// Commit only while this exact user/attempt slot is free. The earlier
/// observation is not an authorization to overwrite a concurrent insertion.
fn store_auth_state_bytes(
    store: &crate::store::Store,
    user_id: Uuid,
    recovery_id: Uuid,
    bytes: &[u8],
) -> Result<()> {
    if store.set_ex_nx(
        &auth_state_key(user_id, recovery_id),
        bytes,
        AUTH_STATE_TTL_SECS,
    )? {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "recovery challenge id is already in use".into(),
        ))
    }
}

/// What the atomic single-use `get_del` of one attempt-bound challenge
/// observed. A decode failure still removed the state, so it is reported
/// separately from "nothing matched"; the driver decides that corruption is
/// terminal rather than assuming the store returned nothing.
pub(crate) enum StoredAuthAttempt {
    Missing,
    Corrupt(AppError),
    Present {
        state: RecoveryAuthState,
        user_matches: bool,
        attempt_matches: bool,
    },
}

/// Consume the exact attempt state once. `Missing` means no state matched. The
/// binding comparison is returned as an observation; the checked driver decides
/// that a mismatch is terminal without re-arming the consumed challenge.
pub(crate) fn observe_auth_state(
    state: &AppState,
    user_id: Uuid,
    recovery_id: Uuid,
) -> Result<StoredAuthAttempt> {
    let key = auth_state_key(user_id, recovery_id);
    let Some(bytes) = state.store.get_del(&key)? else {
        return Ok(StoredAuthAttempt::Missing);
    };
    match serde_json::from_slice::<RecoveryAuthState>(&bytes) {
        Ok(envelope) => Ok(StoredAuthAttempt::Present {
            user_matches: envelope.user_id == user_id,
            attempt_matches: envelope.recovery_id == recovery_id,
            state: envelope,
        }),
        Err(e) => Ok(StoredAuthAttempt::Corrupt(AppError::BadRequest(format!(
            "invalid recovery challenge state: {e}"
        )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_freshness_observations_cannot_replace_the_winning_challenge() {
        let store = crate::store::Store::open_temp().unwrap();
        let user_id = Uuid::new_v4();
        let recovery_id = Uuid::new_v4();
        let key = auth_state_key(user_id, recovery_id);
        // Two requests may both see an empty slot before either writes.
        assert!(!store.exists(&key).unwrap());
        assert!(!store.exists(&key).unwrap());
        store_auth_state_bytes(&store, user_id, recovery_id, b"original challenge").unwrap();
        assert!(matches!(
            store_auth_state_bytes(&store, user_id, recovery_id, b"replacement challenge"),
            Err(AppError::Conflict(_))
        ));
        assert_eq!(store.get(&key).unwrap().unwrap(), b"original challenge");
    }
}
