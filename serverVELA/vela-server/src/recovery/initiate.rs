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
use vela_recovery_policy::webauthn_store::{self, SetNxOutcome};
use webauthn_rs::prelude::{PasskeyAuthentication, RequestChallengeResponse};

use super::sql::{
    auth_state_view, credential_row, probe_auth_slot, run_webauthn_read, store_auth_state,
    webauthn_share_row_view, PoolSql, RecoveryKv, RecoverySql, StoreKv,
};
use crate::{
    error::{AppError, Result},
    net, rate_limit,
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
        sql: PoolSql(&state.sqldb),
        kv: StoreKv(&state.store),
        user_id: body.user_id,
        recovery_id: None,
        drawn_recovery_id: None,
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
pub(super) struct InitiateIo<'a, S, K> {
    state: &'a AppState,
    sql: S,
    kv: K,
    user_id: Uuid,
    recovery_id: Option<Uuid>,
    /// A fixed attempt id for the conformance test; `None` draws a fresh v4 id
    /// exactly when the observation runs, as the handler always has.
    drawn_recovery_id: Option<Uuid>,
    passkey: Option<webauthn_rs::prelude::Passkey>,
    decode_error: Option<AppError>,
    challenge: Option<RequestChallengeResponse>,
    auth_state: Option<PasskeyAuthentication>,
    credential_id: Option<String>,
    ceremony_error: Option<AppError>,
    store_error: Option<AppError>,
    error: Option<AppError>,
}

impl<S: RecoverySql, K: RecoveryKv> InitiateIo<'_, S, K> {
    /// Observe availability and the stored credential, then probe the freshly
    /// generated attempt slot. A storage error has no observation.
    pub(super) async fn auth_start_observe(&mut self) -> Option<AuthStartObservation> {
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
        let recovery_id = self.drawn_recovery_id.unwrap_or_else(Uuid::new_v4);
        // Observe freshness for the policy. Storage checks it atomically again:
        // another insertion may win after this preflight observation.
        let slot_stmt = webauthn_store::plan_auth_slot(webauthn_store::auth_state_key(
            &self.user_id.to_string(),
            &recovery_id.to_string(),
        ));
        let occupied = match probe_auth_slot(&mut self.kv, &slot_stmt) {
            Ok(occupied) => occupied,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        self.recovery_id = Some(recovery_id);
        self.passkey = credential.passkey;
        self.decode_error = credential.decode_error;
        Some(webauthn_store::classify_auth_start(
            &share,
            &credential.view,
            occupied,
            AUTH_STATE_TTL_SECS,
        ))
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
            credential_id: credential_id.clone(),
            auth_state,
        };
        let value = match serde_json::to_string(&envelope) {
            Ok(value) => value,
            Err(e) => {
                self.error = Some(AppError::Internal(format!(
                    "failed to serialize WebAuthn auth state: {e}"
                )));
                return None;
            }
        };
        let view = auth_state_view(self.user_id, recovery_id, &credential_id);
        self.write_auth_state(value, view).await
    }

    /// The write half of `auth_start_store`: commit exactly one envelope at the
    /// exact user/attempt key.
    pub(super) async fn write_auth_state(
        &mut self,
        value: String,
        state: vela_recovery_policy::webauthn_store::AuthStateView,
    ) -> Option<ChallengeStoreObservation> {
        let recovery_id = self.recovery_id?;
        let stmt = webauthn_store::plan_store_auth_state(
            webauthn_store::auth_state_key(
                &self.user_id.to_string(),
                &recovery_id.to_string(),
            ),
            value,
            state,
            AUTH_STATE_TTL_SECS,
        );
        let outcome = match store_auth_state(&mut self.kv, &stmt) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.store_error = Some(error);
                SetNxOutcome::Failed
            }
        };
        if matches!(outcome, SetNxOutcome::Occupied) {
            self.store_error = Some(AppError::Conflict(
                "recovery challenge id is already in use".into(),
            ));
        }
        Some(webauthn_store::classify_store_auth_state(&outcome))
    }
}

/// Construction and side-channel access for the bounded real-database
/// conformance test (`recovery/conformance.rs`).
#[cfg(test)]
impl<'a, S, K> InitiateIo<'a, S, K> {
    pub(super) fn for_conformance(
        state: &'a AppState,
        sql: S,
        kv: K,
        user_id: Uuid,
        drawn_recovery_id: Uuid,
    ) -> Self {
        Self {
            state,
            sql,
            kv,
            user_id,
            recovery_id: None,
            drawn_recovery_id: Some(drawn_recovery_id),
            passkey: None,
            decode_error: None,
            challenge: None,
            auth_state: None,
            credential_id: None,
            ceremony_error: None,
            store_error: None,
            error: None,
        }
    }

    pub(super) fn error_is_set(&self) -> bool {
        self.error.is_some()
    }

    pub(super) fn recovery_id(&self) -> Option<Uuid> {
        self.recovery_id
    }

    pub(super) fn set_recovery_id(&mut self, recovery_id: Uuid) {
        self.recovery_id = Some(recovery_id);
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

/// What the atomic `get_del` of one attempt-bound challenge observed. A decode
/// failure still removed the state, so it is reported separately from "nothing
/// matched"; the driver decides that corruption is terminal rather than
/// assuming the store returned nothing.
pub(crate) enum StoredAuthAttempt {
    Missing,
    Corrupt(AppError),
    Present {
        view: vela_recovery_policy::webauthn_store::AuthStateView,
        envelope: RecoveryAuthState,
    },
}

/// Decode one consumed attempt envelope into the observation the driver sees.
pub(crate) fn decode_auth_attempt(bytes: Option<Vec<u8>>) -> StoredAuthAttempt {
    let Some(bytes) = bytes else {
        return StoredAuthAttempt::Missing;
    };
    match serde_json::from_slice::<RecoveryAuthState>(&bytes) {
        Ok(envelope) => StoredAuthAttempt::Present {
            view: vela_recovery_policy::webauthn_store::AuthStateView {
                user: envelope.user_id.to_string(),
                attempt: envelope.recovery_id.to_string(),
                credential_id: envelope.credential_id.clone(),
            },
            envelope,
        },
        Err(e) => StoredAuthAttempt::Corrupt(AppError::BadRequest(format!(
            "invalid recovery challenge state: {e}"
        ))),
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
        let key = webauthn_store::auth_state_key(
            &user_id.to_string(),
            &recovery_id.to_string(),
        );
        // Two requests may both see an empty slot before either writes.
        assert!(!store.exists(&key).unwrap());
        assert!(!store.exists(&key).unwrap());
        let view = auth_state_view(user_id, recovery_id, "cred");
        let first = webauthn_store::plan_store_auth_state(
            key.clone(),
            "original challenge".into(),
            view.clone(),
            AUTH_STATE_TTL_SECS,
        );
        assert!(matches!(
            store_auth_state(&mut StoreKv(&store), &first),
            Ok(SetNxOutcome::Wrote)
        ));
        let second = webauthn_store::plan_store_auth_state(
            key.clone(),
            "replacement challenge".into(),
            view,
            AUTH_STATE_TTL_SECS,
        );
        assert!(matches!(
            store_auth_state(&mut StoreKv(&store), &second),
            Ok(SetNxOutcome::Occupied)
        ));
        assert_eq!(store.get(&key).unwrap().unwrap(), b"original challenge");
    }
}
