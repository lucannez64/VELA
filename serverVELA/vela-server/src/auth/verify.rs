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
    auth::challenge::ChallengePurpose,
    auth::token::TokenService,
    device::enroll::{unify_device_auth_error, verify_auth_signature, DEVICE_AUTH_FAILED},
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
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
struct VerifyIo<'a> {
    state: &'a AppState,
    ip: String,
    device_id_str: String,
    challenge: String,
    signature: String,
    requested_name: Option<String>,
    requested_type: Option<String>,
    device: Option<crate::db::DeviceRow>,
    token: Option<(String, String)>,
    /// The raw error of the effect that failed (challenge take, device query,
    /// device parse, streak reset, token issuance or JTI tracking).
    error: Option<AppError>,
    /// The verifier's rejection, kept until the failure side effects ran.
    verifier_error: Option<AppError>,
    /// The request-level fallback limiter's error; it wins over the verifier
    /// rejection when the counter could not be consumed.
    counter_error: Option<AppError>,
}

impl VerifyIo<'_> {
    /// ── Consume the login nonce ─────────────────────────────────────────
    async fn consume_challenge(&mut self) -> ChallengeObservation {
        match crate::auth::challenge::take_challenge(
            self.state,
            &self.challenge,
            ChallengePurpose::Login,
        ) {
            Ok(consumed) => ChallengeObservation::Observed(consumed),
            Err(error) => {
                self.error = Some(error);
                ChallengeObservation::StorageFailed
            }
        }
    }

    /// ── Observe the unrevoked device row ────────────────────────────────
    async fn observe_device(&mut self) -> DeviceObservation {
        let query_result = self
            .state
            .sqldb
            .query(
                "SELECT id, user_id, device_name, device_type, last_active,
                    hybrid_ek, hybrid_vk,
                    enrolled_by, rms_capsule, revoked,
                    revoked_at, revoked_by, created_at
                 FROM devices
                 WHERE id = ? AND revoked = 0",
                vec![TursoValue::Text(self.device_id_str.clone())],
            )
            .await;
        match query_result {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                DeviceObservation::QueryFailed
            }
            Ok(rows) => match rows.first() {
                None => {
                    self.error = Some(AppError::Unauthorized(DEVICE_AUTH_FAILED.into()));
                    DeviceObservation::Absent
                }
                Some(row) => match crate::db::parse_device_row_turso(row) {
                    Ok(device) => {
                        self.device = Some(device);
                        DeviceObservation::Present
                    }
                    Err(error) => {
                        self.error = Some(error);
                        DeviceObservation::ParseFailed
                    }
                },
            },
        }
    }

    /// ── Decode the nonce and run the actual verifier ────────────────────
    ///
    /// The base64 decode happens before the verifier and, exactly as before,
    /// does not touch the failure counter.
    async fn verify_signature(&mut self) -> VerifierObservation {
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
    async fn record_verification_failure(&mut self) -> FailureRecordObservation {
        if let Err(record_err) =
            rate_limit::record_verify_failure(&self.state.store, &self.ip, &self.device_id_str)
        {
            tracing::error!(
                device_id = %self.device_id_str,
                error = %record_err,
                "failed to record verify failure — exponential backoff not updated"
            );
        }
        let counter_result =
            rate_limit::verify_fail_by_device(&self.state.store, &self.ip, &self.device_id_str);
        let fallback_counter_ok = counter_result.is_ok();
        self.counter_error = counter_result.err();
        FailureRecordObservation { fallback_counter_ok }
    }

    /// ── Reset the success streak/backoff ────────────────────────────────
    ///
    /// A failed reset is terminal and returns the store's own error. A
    /// successful reset is followed by the historical best-effort
    /// `last_active` update (and, when the request renamed or retyped the
    /// device, that update too); its failure is ignored, as it always was.
    async fn reset_backoff(&mut self) -> BackoffResetObservation {
        let reset_result =
            rate_limit::reset_verify_streak(&self.state.store, &self.ip, &self.device_id_str);
        if let Err(error) = reset_result {
            self.error = Some(error);
            return BackoffResetObservation::StorageFailed;
        }
        let now = chrono::Utc::now().to_rfc3339();
        let device = self.device.as_ref();
        if self.requested_name.is_some() || self.requested_type.is_some() {
            let next_name = self
                .requested_name
                .as_deref()
                .or_else(|| device.map(|d| d.device_name.as_str()));
            let next_type = self
                .requested_type
                .as_deref()
                .or_else(|| device.map(|d| d.device_type.as_str()));
            if let (Some(next_name), Some(next_type)) = (next_name, next_type) {
                let _ = self
                    .state
                    .sqldb
                    .execute(
                        "UPDATE devices SET last_active = ?, device_name = ?, device_type = ? WHERE id = ?",
                        vec![
                            TursoValue::Text(now),
                            TursoValue::Text(next_name.to_string()),
                            TursoValue::Text(next_type.to_string()),
                            TursoValue::Text(self.device_id_str.clone()),
                        ],
                    )
                    .await;
            }
        } else {
            let _ = self
                .state
                .sqldb
                .execute(
                    "UPDATE devices SET last_active = ? WHERE id = ?",
                    vec![
                        TursoValue::Text(now),
                        TursoValue::Text(self.device_id_str.clone()),
                    ],
                )
                .await;
        }
        BackoffResetObservation::Reset
    }

    /// ── Issue the token (the existing verified device-token policy) ─────
    async fn issue_token(&mut self) -> TokenIssueObservation {
        let Some(device) = self.device.as_ref() else {
            self.error = Some(AppError::Internal(
                "login driver requested issuance without a device".into(),
            ));
            return TokenIssueObservation::Failed;
        };
        let ts = TokenService::new(self.state.paseto_sk.clone(), self.state.paseto_pk.clone());
        match ts.issue(device.user_id, device.id, None) {
            Ok(value) => {
                self.token = Some(value);
                TokenIssueObservation::Issued
            }
            Err(error) => {
                self.error = Some(error);
                TokenIssueObservation::Failed
            }
        }
    }

    /// ── Track the JTI before any response ───────────────────────────────
    async fn track_token(&mut self) -> TokenTrackObservation {
        let Some((_, jti)) = self.token.as_ref() else {
            self.error = Some(AppError::Internal(
                "login driver requested tracking without a token".into(),
            ));
            return TokenTrackObservation::Failed;
        };
        match rate_limit::track_device_jti(&self.state.store, &self.device_id_str, jti) {
            Ok(()) => TokenTrackObservation::Tracked,
            Err(error) => {
                self.error = Some(error);
                TokenTrackObservation::Failed
            }
        }
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
        state: &state,
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
