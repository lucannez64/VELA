pub mod delete;

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    auth::session_store::{
        keep_error, run_read, run_sql_in_tx_named, run_sql_named, run_store, DbSql, PasetoTokens,
        SessionSql, SessionStore, SessionTokens, SledStore,
    },
    auth::token::TokenService,
    error::{AppError, Result},
    net,
    state::AppState,
};

use vela_session_policy::store::{self, CountOutcome, StoreOutcome, WriteOutcome};
use vela_session_policy::registration_driver::{
    BudgetObservation, CommitObservation, InsertObservation, RateLimitObservation,
    RegistrationEffect, RegistrationFailure, RegistrationRequestObservation, TokenObservation,
    TrackObservation, TransactionObservation,
};

const HYBRID_EK_LEN: usize = 1568 + 32;
const HYBRID_VK_LEN: usize = 2592 + 32;
const SHARE_EK_LEN: usize = 1568 + 32; // ML-KEM-1024 EK (1568) + X25519 PK (32)

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    /// M19: only accepted together with a binding signature under the
    /// presented `hybrid_vk` — an unsigned share key can no longer be
    /// provisioned at all, so substitution always requires a device's
    /// private identity key.
    #[serde(default)]
    pub share_ek: Option<String>,
    #[serde(default)]
    pub share_ek_signed_at: Option<String>,
    #[serde(default)]
    pub share_ek_signature: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub device_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// The request-side key observations, computed in the handler's historical
/// order (identity encryption key, identity verification key, then the
/// optional signed share key). The first error keeps its exact message; the
/// driver only learns whether each key is valid.
pub(crate) struct ParsedKeys {
    pub identity_ek: Option<Vec<u8>>,
    pub identity_vk: Option<Vec<u8>>,
    pub share_ek_b64: String,
    pub identity_ek_valid: bool,
    pub identity_vk_valid: bool,
    pub share_ek_valid: bool,
    pub error: Option<AppError>,
}

fn observe_keys(body: &RegisterRequest) -> ParsedKeys {
    let mut parsed = ParsedKeys {
        identity_ek: None,
        identity_vk: None,
        share_ek_b64: String::new(),
        identity_ek_valid: false,
        identity_vk_valid: false,
        share_ek_valid: false,
        error: None,
    };

    let hybrid_ek = match decode_b64_exact(&body.hybrid_ek, HYBRID_EK_LEN, "hybrid_ek") {
        Ok(bytes) => bytes,
        Err(error) => {
            parsed.error = Some(error);
            return parsed;
        }
    };
    parsed.identity_ek = Some(hybrid_ek);
    parsed.identity_ek_valid = true;

    let hybrid_vk = match decode_b64_exact(&body.hybrid_vk, HYBRID_VK_LEN, "hybrid_vk") {
        Ok(bytes) => bytes,
        Err(error) => {
            parsed.error = Some(error);
            return parsed;
        }
    };
    parsed.identity_vk = Some(hybrid_vk.clone());
    parsed.identity_vk_valid = true;

    // M19: an initial share key must be signed by the very identity key this
    // account is being created with. Unsigned provisioning is refused so
    // every registered share key traces to a device signature.
    let share_ek_b64 = match body.share_ek.as_deref() {
        Some(s) => {
            let ek = match decode_b64_exact(s, SHARE_EK_LEN, "share_ek") {
                Ok(bytes) => bytes,
                Err(error) => {
                    parsed.error = Some(error);
                    return parsed;
                }
            };
            let signed_at = match body
                .share_ek_signed_at
                .as_deref()
                .filter(|t| !t.is_empty() && (20..=64).contains(&t.len()))
            {
                Some(signed_at) => signed_at,
                None => {
                    parsed.error = Some(AppError::BadRequest(
                        "share_ek_signed_at (RFC 3339) is required with share_ek".into(),
                    ));
                    return parsed;
                }
            };
            let signature = match B64
                .decode(
                    match body.share_ek_signature.as_deref() {
                        Some(signature) => signature,
                        None => {
                            parsed.error = Some(AppError::BadRequest(
                                "share_ek_signature is required with share_ek".into(),
                            ));
                            return parsed;
                        }
                    }
                    .as_bytes(),
                )
                .map_err(|_| AppError::BadRequest("share_ek_signature is not valid base64".into()))
            {
                Ok(signature) => signature,
                Err(error) => {
                    parsed.error = Some(error);
                    return parsed;
                }
            };
            let message = vela_crypto::signing::share_ek_binding_message(&ek, signed_at);
            if let Err(error) = crate::device::enroll::verify_hybrid_signature(
                &hybrid_vk,
                &message,
                &signature,
                "share-key binding signature invalid",
            ) {
                parsed.error = Some(error);
                return parsed;
            }
            s.to_string()
        }
        None => String::new(),
    };
    parsed.share_ek_b64 = share_ek_b64;
    parsed.share_ek_valid = true;
    parsed
}

/// The I/O behind each registration effect. The driver decides which method
/// runs and when (through the shared `registration_interpreter!` loop, proved
/// in F* as `run_registration`); each method only performs its effect — one
/// typed plan from `vela_session_policy::store`, run and classified — and
/// reports the outcome. The first storage error is kept so the response
/// carries the original message.
pub(crate) struct RegisterIo<S: SessionSql, K: SessionStore, T: SessionTokens> {
    pub sql: S,
    pub store: K,
    pub tokens: T,
    pub ip: String,
    pub body: RegisterRequest,
    pub keys: ParsedKeys,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub now: String,
    pub device_name: String,
    pub device_type: String,
    pub token: Option<String>,
    pub jti: Option<String>,
    pub error: Option<AppError>,
}

impl<S: SessionSql, K: SessionStore, T: SessionTokens> RegisterIo<S, K, T> {
    fn fail(&mut self, error: impl ToString) {
        if self.error.is_none() {
            self.error = Some(AppError::Internal(error.to_string()));
        }
    }

    pub(crate) async fn check_rate_limit(&mut self) -> RateLimitObservation {
        let plan = store::plan_registration_rate_limit(self.ip.clone());
        let (outcomes, error) = run_store(&mut self.store, &plan);
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        let outcome = outcomes.first().copied().unwrap_or(StoreOutcome::Failed);
        store::classify_registration_rate_limit(&outcome)
    }

    pub(crate) async fn check_account_budget(&mut self) -> BudgetObservation {
        let (rows, error) = run_read(&mut self.sql, store::plan_account_count()).await;
        match rows {
            Some(rows) => {
                let count = rows.first().and_then(|row| row.i64(0)).unwrap_or(0);
                store::classify_account_count(&CountOutcome::Count(count))
            }
            None => {
                if let Some(error) = error {
                    keep_error(&mut self.error, error);
                }
                store::classify_account_count(&CountOutcome::Failed)
            }
        }
    }

    pub(crate) async fn begin_transaction(&mut self) -> TransactionObservation {
        match self.sql.begin().await {
            Ok(()) => store::classify_registration_transaction(&WriteOutcome::Applied(0)),
            Err(error) => {
                keep_error(&mut self.error, error);
                store::classify_registration_transaction(&WriteOutcome::Failed)
            }
        }
    }

    pub(crate) async fn insert_account(&mut self) -> InsertObservation {
        let share_ek_since = self
            .body
            .share_ek
            .as_deref()
            .map(|_| self.now.clone())
            .unwrap_or_default();
        let plan = [store::plan_insert_account(
            self.user_id.to_string(),
            self.now.clone(),
            self.keys.share_ek_b64.clone(),
            share_ek_since,
        )];
        let (outcomes, error) =
            run_sql_in_tx_named(&mut self.sql, &plan, "registration transaction is not open")
                .await;
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        let outcome = outcomes.first().copied().unwrap_or(WriteOutcome::Failed);
        store::classify_insert(&outcome)
    }

    pub(crate) async fn insert_device(&mut self) -> InsertObservation {
        let (Some(hybrid_ek), Some(hybrid_vk)) =
            (self.keys.identity_ek.as_ref(), self.keys.identity_vk.as_ref())
        else {
            self.fail("registration keys are not available");
            return store::classify_insert(&WriteOutcome::Failed);
        };
        let plan = [store::plan_insert_device(
            self.device_id.to_string(),
            self.user_id.to_string(),
            self.device_name.clone(),
            self.device_type.clone(),
            self.now.clone(),
            crate::db::encode_b64(hybrid_ek),
            crate::db::encode_b64(hybrid_vk),
        )];
        let (outcomes, error) =
            run_sql_in_tx_named(&mut self.sql, &plan, "registration transaction is not open")
                .await;
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        let outcome = outcomes.first().copied().unwrap_or(WriteOutcome::Failed);
        store::classify_insert(&outcome)
    }

    pub(crate) async fn commit(&mut self) -> CommitObservation {
        let (outcomes, error) = run_sql_named(
            &mut self.sql,
            &[store::plan_commit()],
            "registration transaction is not open",
        )
        .await;
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        let outcome = outcomes.first().copied().unwrap_or(WriteOutcome::Failed);
        store::classify_registration_commit(&outcome)
    }

    pub(crate) async fn issue_token(&mut self) -> TokenObservation {
        match self.tokens.issue_device(self.user_id, self.device_id) {
            Ok((token, jti)) => {
                self.token = Some(token);
                self.jti = Some(jti);
                TokenObservation::Issued
            }
            Err(error) => {
                keep_error(&mut self.error, error);
                TokenObservation::Failed
            }
        }
    }

    pub(crate) async fn track_token(&mut self) -> TrackObservation {
        let Some(jti) = self.jti.clone() else {
            self.fail("registration token is not available");
            return store::classify_registration_track(&StoreOutcome::Failed);
        };
        let plan = store::plan_track_jti(self.device_id.to_string(), jti);
        let (outcomes, error) = run_store(&mut self.store, &plan);
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        let outcome = outcomes.first().copied().unwrap_or(StoreOutcome::Failed);
        store::classify_registration_track(&outcome)
    }
}

fn registration_failure_error(
    failure: RegistrationFailure,
    error: Option<AppError>,
) -> AppError {
    if let Some(error) = error {
        return error;
    }
    match failure {
        RegistrationFailure::RateLimited => {
            AppError::RateLimited("registration rate limit exceeded".into())
        }
        RegistrationFailure::InvalidRequest => {
            AppError::BadRequest("invalid registration key".into())
        }
        RegistrationFailure::AccountLimit => {
            AppError::BadRequest("this server is not accepting new accounts".into())
        }
        RegistrationFailure::AccountCountStorage => {
            AppError::Internal("account count failed".into())
        }
        RegistrationFailure::TransactionStorage => {
            AppError::Internal("registration transaction failed".into())
        }
        RegistrationFailure::AccountInsertStorage => {
            AppError::Internal("account insert failed".into())
        }
        RegistrationFailure::DeviceInsertStorage => {
            AppError::Internal("device insert failed".into())
        }
        RegistrationFailure::CommitStorage => {
            AppError::Internal("registration commit failed".into())
        }
        RegistrationFailure::TokenIssue => {
            AppError::Internal("token issue failed".into())
        }
        RegistrationFailure::TrackStorage => {
            AppError::Internal("token tracking failed".into())
        }
    }
}

pub async fn post_register(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    let keys = observe_keys(&body);
    let max_accounts = state.config.max_accounts;
    let request = RegistrationRequestObservation {
        has_account_limit: max_accounts.is_some(),
        account_limit: max_accounts
            .map(|limit| limit.min(i64::MAX as u64) as i64)
            .unwrap_or(0),
        identity_ek_valid: keys.identity_ek_valid,
        identity_vk_valid: keys.identity_vk_valid,
        share_ek_valid: keys.share_ek_valid,
    };

    let device_name = body
        .device_name
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "Desktop Device".to_string());
    let device_type = body
        .device_type
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "desktop".to_string());
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut io = RegisterIo {
        sql: DbSql {
            pool: &state.sqldb,
            tx: None,
        },
        store: SledStore(&state.store),
        tokens: PasetoTokens(TokenService::new(
            state.paseto_sk.clone(),
            state.paseto_pk.clone(),
        )),
        ip,
        body,
        keys,
        user_id,
        device_id,
        now,
        device_name,
        device_type,
        token: None,
        jti: None,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_session_policy::registration_interpreter!(io, request, await);
    // Dropping an uncommitted transaction rolls back the account row.
    io.sql.rollback();

    match transition.effect {
        RegistrationEffect::Complete => {
            tracing::info!(user_id = %io.user_id, device_id = %io.device_id, "account registered");
            Ok(Json(RegisterResponse {
                user_id: io.user_id,
                device_id: io.device_id,
                token: io.token.take(),
            }))
        }
        RegistrationEffect::Fail(failure) => {
            Err(registration_failure_error(failure, io.error.take()))
        }
        _ => Err(AppError::Internal(
            "registration driver reached no verdict".into(),
        )),
    }
}

fn decode_b64_exact(encoded: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    let bytes = B64
        .decode(encoded)
        .map_err(|_| AppError::BadRequest(format!("{field} is not valid base64")))?;
    if bytes.len() != expected_len {
        return Err(AppError::BadRequest(format!(
            "{field} must be {expected_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_body() -> RegisterRequest {
        RegisterRequest {
            hybrid_ek: B64.encode(vec![0u8; HYBRID_EK_LEN]),
            hybrid_vk: B64.encode(vec![0u8; HYBRID_VK_LEN]),
            device_name: None,
            device_type: None,
            share_ek: None,
            share_ek_signed_at: None,
            share_ek_signature: None,
        }
    }

    #[test]
    fn unsigned_share_key_is_refused_with_its_historical_message() {
        let mut body = valid_body();
        body.share_ek = Some(B64.encode(vec![0u8; SHARE_EK_LEN]));
        let parsed = observe_keys(&body);
        assert!(!parsed.share_ek_valid);
        let error = parsed.error.expect("share_ek_signed_at must be required");
        assert_eq!(
            error.to_string(),
            "bad request: share_ek_signed_at (RFC 3339) is required with share_ek"
        );
    }

    #[test]
    fn short_identity_key_keeps_its_exact_length_message() {
        let mut body = valid_body();
        body.hybrid_ek = B64.encode(vec![0u8; 10]);
        let parsed = observe_keys(&body);
        assert!(!parsed.identity_ek_valid);
        assert_eq!(
            parsed.error.expect("short key must be refused").to_string(),
            "bad request: hybrid_ek must be 1600 bytes, got 10"
        );
    }

    #[test]
    fn absent_share_key_is_valid() {
        let parsed = observe_keys(&valid_body());
        assert!(parsed.identity_ek_valid && parsed.identity_vk_valid && parsed.share_ek_valid);
        assert!(parsed.error.is_none());
    }
}
