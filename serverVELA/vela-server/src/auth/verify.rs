//! `POST /auth/verify` — device challenge/response login.
//!
//! Every post-validation decision lives in the pure
//! [`vela_session_policy::login_driver`] driver: whether the single-use
//! challenge may be accepted, whether the device row was observed, whether the
//! verifier accepted the proof, whether the failure side effects ran, whether
//! the streak/backoff reset succeeded, whether a token may be issued, and
//! whether its JTI was tracked before responding. This handler only performs
//! the returned effect and maps a terminal driver failure back to the
//! historical status and message.
//!
//! The handler expands [`vela_session_policy::login_interpreter!`] with
//! `await`: the same loop text the policy crate expands into the synchronous
//! `run_login` that hax extracts and F* checks. Only the effect the driver just
//! emitted is performed, and nothing after its verdict.
//!
//! The per-IP limiter and the backoff precheck stay outside the macro: they run
//! before the challenge take, i.e. before the driver begins. The best-effort
//! `last_active` update is performed by the executor's `reset_backoff` method,
//! which is the effect that precedes issuance, so the observable order is
//! unchanged.

use crate::{
    auth::session_store::{
        keep_error, run_read, run_sql, run_store, run_take, DbSql, PasetoTokens, SessionSql,
        SessionStore, SessionTokens, SledStore,
    },
    auth::token::TokenService,
    device::enroll::{unify_device_auth_error, verify_auth_signature, DEVICE_AUTH_FAILED},
    error::{AppError, Result},
    net, rate_limit,
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use vela_session_policy::login_driver::{
    BackoffResetObservation, ChallengeObservation, DeviceObservation,
    FailureRecordObservation, LoginEffect, LoginFailure, TokenIssueObservation,
    TokenTrackObservation, VerifierObservation,
};

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub device_id: uuid::Uuid,
    pub challenge: String,
    pub signature: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub token: String,
    pub user_id: String,
}

/// The I/O behind each login effect. The driver decides which method runs and
/// when (through the shared `login_interpreter!` loop, proved in F* as
/// `run_login`); each method only performs its effect and reports the outcome.
/// The first storage error is kept so the response carries the original
/// message, exactly as the hand-written handler returned it.
///
/// Every method is the proved thin loop from `vela_session_policy::store`:
/// plan → render/run → classify. The conformance harness drives this struct
/// with a failing `SessionSql`/`SessionStore` and a fake issuer.
pub(crate) struct VerifyIo<S: SessionSql, K: SessionStore, T: SessionTokens> {
    pub sql: S,
    pub store: K,
    pub tokens: T,
    pub ip: String,
    pub device_id_str: String,
    pub challenge: String,
    pub signature: String,
    pub requested_name: Option<String>,
    pub requested_type: Option<String>,
    pub device: Option<crate::db::DeviceRow>,
    pub token: Option<(String, String)>,
    /// The raw error of the effect that failed (challenge take, device query,
    /// device parse, streak reset, token issuance or JTI tracking).
    pub error: Option<AppError>,
    /// The verifier's rejection, kept until the failure side effects ran.
    pub verifier_error: Option<AppError>,
    /// The request-level fallback limiter's error; it wins over the verifier
    /// rejection when the counter could not be consumed.
    pub counter_error: Option<AppError>,
}

impl<S: SessionSql, K: SessionStore, T: SessionTokens> VerifyIo<S, K, T> {
    /// ── Consume the login nonce ─────────────────────────────────────────
    pub(crate) async fn consume_challenge(&mut self) -> ChallengeObservation {
        let plan = vela_session_policy::store::plan_take_challenge(self.challenge.clone());
        let outcome = match plan.first() {
            Some(stmt) => {
                let (outcome, error) = run_take(&mut self.store, stmt);
                if let Some(error) = error {
                    keep_error(&mut self.error, error);
                }
                outcome
            }
            None => {
                self.error = Some(AppError::Internal(
                    "login challenge plan is empty".into(),
                ));
                vela_session_policy::store::TakeOutcome::Failed
            }
        };
        vela_session_policy::store::classify_login_challenge(
            &outcome,
            &vela_session_policy::store::challenge_tag_text(
                vela_session_policy::challenge::ChallengePurpose::Login,
            ),
        )
    }

    /// ── Observe the unrevoked device row ────────────────────────────────
    pub(crate) async fn observe_device(&mut self) -> DeviceObservation {
        let stmt = vela_session_policy::store::plan_login_device(self.device_id_str.clone());
        let (rows, error) = run_read(&mut self.sql, stmt).await;
        let outcome = match (rows, error) {
            (Some(rows), None) => match rows.first() {
                None => {
                    self.error = Some(AppError::Unauthorized(DEVICE_AUTH_FAILED.into()));
                    vela_session_policy::store::DeviceReadOutcome::Missing
                }
                Some(row) => match crate::db::parse_device_row_turso(row) {
                    Ok(device) => {
                        self.device = Some(device);
                        vela_session_policy::store::DeviceReadOutcome::Row
                    }
                    Err(error) => {
                        self.error = Some(error);
                        vela_session_policy::store::DeviceReadOutcome::Undecodable
                    }
                },
            },
            (_, Some(error)) => {
                self.error = Some(AppError::Internal(error.to_string()));
                vela_session_policy::store::DeviceReadOutcome::Failed
            }
            (None, None) => {
                self.error = Some(AppError::Internal(
                    "device lookup returned no row and no error".into(),
                ));
                vela_session_policy::store::DeviceReadOutcome::Failed
            }
        };
        vela_session_policy::store::classify_login_device(&outcome)
    }

    /// ── Decode the nonce and run the actual verifier ────────────────────
    ///
    /// The base64 decode happens before the verifier and, exactly as before,
    /// does not touch the failure counter.
    pub(crate) async fn verify_signature(&mut self) -> VerifierObservation {
        let challenge_bytes = match B64.decode(&self.challenge) {
            Ok(bytes) => bytes,
            Err(_) => return VerifierObservation::ChallengeDecodeFailed,
        };
        let Some(device) = self.device.as_ref() else {
            // The driver only emits `VerifySignature` after a present device.
            self.error = Some(AppError::Internal(
                "login driver requested the verifier without a device".into(),
            ));
            return VerifierObservation::RejectedInternal;
        };
        let signature = verify_auth_signature(
            &device.hybrid_vk,
            &challenge_bytes,
            &self.device_id_str,
            &self.signature,
        );
        match signature {
            Ok(()) => VerifierObservation::Valid,
            Err(error) => {
                let observation = match &error {
                    AppError::Unauthorized(_) => VerifierObservation::RejectedUnauthorized,
                    AppError::BadRequest(_) => VerifierObservation::RejectedBadRequest,
                    _ => VerifierObservation::RejectedInternal,
                };
                self.verifier_error = Some(error);
                observation
            }
        }
    }

    /// ── Record the failed proof and consume the request-level budget ────
    ///
    /// The exponential-backoff record is log-only: a store hiccup must not let
    /// a failed proof skip the request-level fallback limiter.
    pub(crate) async fn record_verification_failure(&mut self) -> FailureRecordObservation {
        let plan = vela_session_policy::store::plan_backoff_record(
            self.ip.clone(),
            self.device_id_str.clone(),
        );
        if let Some(record_err) = run_store(&mut self.store, &plan).1 {
            tracing::error!(
                device_id = %self.device_id_str,
                error = %record_err,
                "failed to record verify failure — exponential backoff not updated"
            );
        }
        let plan = vela_session_policy::store::plan_failure_counter(
            self.ip.clone(),
            self.device_id_str.clone(),
        );
        let (outcomes, counter_error) = run_store(&mut self.store, &plan);
        self.counter_error = None;
        if let Some(error) = counter_error {
            keep_error(&mut self.counter_error, error);
        }
        vela_session_policy::store::classify_failure_counter(&outcomes)
    }

    /// ── Reset the success streak/backoff ────────────────────────────────
    ///
    /// A failed reset is terminal and returns the store's own error. A
    /// successful reset is followed by the historical best-effort
    /// `last_active` update (and, when the request renamed or retyped the
    /// device, that update too); its failure is ignored, as it always was.
    pub(crate) async fn reset_backoff(&mut self) -> BackoffResetObservation {
        let plan = vela_session_policy::store::plan_reset_login_streak(
            self.ip.clone(),
            self.device_id_str.clone(),
        );
        let (_, error) = run_store(&mut self.store, &plan);
        if let Some(error) = error {
            keep_error(&mut self.error, error);
            return BackoffResetObservation::StorageFailed;
        }
        let now = chrono::Utc::now().to_rfc3339();
        let device = self.device.as_ref();
        // Only a request that renamed or retyped the device touches the name
        // and type columns; otherwise the historical plain stamp runs.
        let (next_name, next_type) =
            if self.requested_name.is_some() || self.requested_type.is_some() {
                (
                    self.requested_name
                        .clone()
                        .or_else(|| device.map(|d| d.device_name.clone())),
                    self.requested_type
                        .clone()
                        .or_else(|| device.map(|d| d.device_type.clone())),
                )
            } else {
                (None, None)
            };
        // The historical code stamped only when the request asked for neither a
        // rename nor a retype (plain stamp), or when both resolved (named
        // stamp); a rename it could not complete wrote nothing.
        let requested = self.requested_name.is_some() || self.requested_type.is_some();
        let both_resolved = next_name.is_some() && next_type.is_some();
        if !requested || both_resolved {
            let stmt = vela_session_policy::store::plan_login_last_active(
                self.device_id_str.clone(),
                now,
                next_name,
                next_type,
            );
            let _ = run_sql(&mut self.sql, &[stmt]).await;
        }
        BackoffResetObservation::Reset
    }

    /// ── Issue the token (the existing verified device-token policy) ─────
    pub(crate) async fn issue_token(&mut self) -> TokenIssueObservation {
        let Some(device) = self.device.as_ref() else {
            self.error = Some(AppError::Internal(
                "login driver requested issuance without a device".into(),
            ));
            return TokenIssueObservation::Failed;
        };
        match self.tokens.issue_device(device.user_id, device.id) {
            Ok(value) => {
                self.token = Some(value);
                TokenIssueObservation::Issued
            }
            Err(error) => {
                keep_error(&mut self.error, error);
                TokenIssueObservation::Failed
            }
        }
    }

    /// ── Track the JTI before any response ───────────────────────────────
    pub(crate) async fn track_token(&mut self) -> TokenTrackObservation {
        let Some((_, jti)) = self.token.as_ref() else {
            self.error = Some(AppError::Internal(
                "login driver requested tracking without a token".into(),
            ));
            return TokenTrackObservation::Failed;
        };
        let plan = vela_session_policy::store::plan_track_jti(
            self.device_id_str.clone(),
            jti.clone(),
        );
        let (outcomes, error) = run_store(&mut self.store, &plan);
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        let outcome = outcomes
            .first()
            .copied()
            .unwrap_or(vela_session_policy::store::StoreOutcome::Failed);
        vela_session_policy::store::classify_track_jti(&outcome)
    }
}

pub async fn post_verify(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    let device_id_str = body.device_id.to_string();

    // The IP limiter and the backoff precheck remain handler glue: they run
    // before any challenge is taken, exactly as before. The pure driver starts
    // at the single-use challenge take.
    rate_limit::verify_by_ip(&state.store, &ip)?;
    rate_limit::check_verify_backoff(&state.store, &ip, &device_id_str)?;

    let requested_name = body
        .device_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let requested_type = body
        .device_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let mut io = VerifyIo {
        sql: DbSql { pool: &state.sqldb, tx: None },
        store: SledStore(&state.store),
        tokens: PasetoTokens(TokenService::new(
            state.paseto_sk.clone(),
            state.paseto_pk.clone(),
        )),
        ip,
        device_id_str,
        challenge: body.challenge,
        signature: body.signature,
        requested_name,
        requested_type,
        device: None,
        token: None,
        error: None,
        verifier_error: None,
        counter_error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_session_policy::login_interpreter!(io, await);

    match transition.effect {
        LoginEffect::Respond => {
            let (token, _jti) = io.token.take().ok_or_else(|| {
                AppError::Internal("login driver responded without a token".into())
            })?;
            let device = io.device.take().ok_or_else(|| {
                AppError::Internal("login driver responded without a device".into())
            })?;
            Ok(Json(VerifyResponse {
                token,
                user_id: device.user_id.to_string(),
            }))
        }
        LoginEffect::Fail(LoginFailure::ChallengeMissing) => Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        )),
        LoginEffect::Fail(LoginFailure::ChallengeWrongPurpose) => Err(AppError::Unauthorized(
            "challenge was issued for a different purpose".into(),
        )),
        LoginEffect::Fail(LoginFailure::ChallengeDecode) => {
            Err(AppError::BadRequest("invalid challenge encoding".into()))
        }
        LoginEffect::Fail(LoginFailure::FailureCounterStorage) if io.counter_error.is_some() => {
            Err(io.counter_error.take().expect("checked above"))
        }
        LoginEffect::Fail(
            LoginFailure::VerifierUnauthorized
            | LoginFailure::VerifierBadRequest
            | LoginFailure::VerifierInternal,
        ) if io.verifier_error.is_some() => Err(unify_device_auth_error(
            io.verifier_error.take().expect("checked above"),
        )),
        LoginEffect::Fail(_) if io.error.is_some() => Err(io.error.take().expect("checked above")),
        LoginEffect::Fail(failure) => Err(AppError::Internal(format!(
            "unexpected login driver failure: {failure:?}"
        ))),
        _ => Err(AppError::Internal(
            "login driver reached no verdict".into(),
        )),
    }
}
