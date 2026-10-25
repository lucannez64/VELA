use crate::{
    auth::challenge::ChallengePurpose,
    auth::token::TokenService,
    device::enroll::verify_auth_signature,
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
    self, BackoffResetObservation, ChallengeObservation, DeviceObservation,
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

    let mut driver = login_driver::begin_login().driver;

    // ── Consume the login nonce ─────────────────────────────────────────────
    let challenge =
        crate::auth::challenge::take_challenge(&state, &body.challenge, ChallengePurpose::Login);
    let challenge_observation = match &challenge {
        Ok(consumed) => ChallengeObservation::Observed(*consumed),
        Err(_) => ChallengeObservation::StorageFailed,
    };
    let transition = login_driver::on_challenge_taken(driver, challenge_observation);
    driver = transition.driver;
    match transition.effect {
        LoginEffect::ObserveDevice => {}
        LoginEffect::Fail(failure) => {
            return match (failure, challenge) {
                (LoginFailure::ChallengeStorage, Err(error)) => Err(error),
                (LoginFailure::ChallengeMissing, _) => Err(AppError::Unauthorized(
                    "challenge not found or already used".into(),
                )),
                (LoginFailure::ChallengeWrongPurpose, _) => Err(AppError::Unauthorized(
                    "challenge was issued for a different purpose".into(),
                )),
                (other, _) => Err(AppError::Internal(format!(
                    "unexpected challenge driver failure: {other:?}"
                ))),
            };
        }
        other => {
            return Err(AppError::Internal(format!(
                "unexpected challenge driver effect: {other:?}"
            )))
        }
    }

    // ── Observe the unrevoked device row ────────────────────────────────────
    let query_result = state
        .sqldb
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
             FROM devices
             WHERE id = ? AND revoked = 0",
            vec![TursoValue::Text(body.device_id.to_string())],
        )
        .await;
    let (device_observation, device_result) = match query_result {
        Err(error) => (
            DeviceObservation::QueryFailed,
            Err(AppError::Internal(error.to_string())),
        ),
        Ok(rows) => match rows.first() {
            None => (
                DeviceObservation::Absent,
                Err(AppError::Unauthorized(
                    crate::device::enroll::DEVICE_AUTH_FAILED.into(),
                )),
            ),
            Some(row) => match crate::db::parse_device_row_turso(row) {
                Ok(device) => (DeviceObservation::Present, Ok(device)),
                Err(error) => (DeviceObservation::ParseFailed, Err(error)),
            },
        },
    };
    let transition = login_driver::on_device_looked_up(driver, device_observation);
    driver = transition.driver;
    let device = match device_result {
        Ok(device) => device,
        Err(error) => {
            debug_assert!(matches!(transition.effect, LoginEffect::Fail(_)));
            return Err(error);
        }
    };
    debug_assert!(matches!(transition.effect, LoginEffect::VerifySignature));

    // ── Decode the nonce and run the actual verifier ────────────────────────
    let challenge_bytes = B64.decode(&body.challenge);
    let challenge_bytes = match challenge_bytes {
        Ok(bytes) => bytes,
        Err(_) => {
            let transition = login_driver::on_verifier_finished(
                driver,
                VerifierObservation::ChallengeDecodeFailed,
            );
            debug_assert!(matches!(
                transition.effect,
                LoginEffect::Fail(LoginFailure::ChallengeDecode)
            ));
            return Err(AppError::BadRequest("invalid challenge encoding".into()));
        }
    };

    match verify_auth_signature(
        &device.hybrid_vk,
        &challenge_bytes,
        &device_id_str,
        &body.signature,
    ) {
        Ok(()) => {
            let transition = login_driver::on_verifier_finished(driver, VerifierObservation::Valid);
            driver = transition.driver;
            debug_assert!(matches!(transition.effect, LoginEffect::ResetBackoff));
        }
        Err(error) => {
            let observation = match &error {
                AppError::Unauthorized(_) => VerifierObservation::RejectedUnauthorized,
                AppError::BadRequest(_) => VerifierObservation::RejectedBadRequest,
                _ => VerifierObservation::RejectedInternal,
            };
            let transition = login_driver::on_verifier_finished(driver, observation);
            driver = transition.driver;
            debug_assert!(matches!(
                transition.effect,
                LoginEffect::RecordVerificationFailure
            ));

            // The exponential-backoff record is log-only: a store hiccup must
            // not let a failed proof skip the request-level fallback limiter.
            if let Err(record_err) =
                rate_limit::record_verify_failure(&state.store, &ip, &device_id_str)
            {
                tracing::error!(
                    device_id = %device_id_str,
                    error = %record_err,
                    "failed to record verify failure — exponential backoff not updated"
                );
            }
            let counter_result =
                rate_limit::verify_fail_by_device(&state.store, &ip, &device_id_str);
            let record_observation = FailureRecordObservation {
                fallback_counter_ok: counter_result.is_ok(),
            };
            let failure_transition =
                login_driver::on_failure_record_observed(driver, record_observation);
            debug_assert!(matches!(failure_transition.effect, LoginEffect::Fail(_)));
            return match counter_result {
                // Preserve the historical status/message precedence: the
                // fallback limiter's own error wins; otherwise the verifier
                // error is returned, with Unauthorized collapsed to the
                // uniform device-authentication message.
                Ok(()) => Err(crate::device::enroll::unify_device_auth_error(error)),
                Err(counter_error) => Err(counter_error),
            };
        }
    }

    // ── Reset the success streak/backoff ────────────────────────────────────
    let reset_result = rate_limit::reset_verify_streak(&state.store, &ip, &device_id_str);
    let reset_observation = if reset_result.is_ok() {
        BackoffResetObservation::Reset
    } else {
        BackoffResetObservation::StorageFailed
    };
    let transition = login_driver::on_backoff_reset_observed_event(driver, reset_observation);
    driver = transition.driver;
    if let Err(error) = reset_result {
        debug_assert!(matches!(
            transition.effect,
            LoginEffect::Fail(LoginFailure::BackoffResetStorage)
        ));
        return Err(error);
    }
    debug_assert!(matches!(transition.effect, LoginEffect::IssueToken));

    // ── Best-effort device activity update (unchanged handler glue) ─────────
    let now = chrono::Utc::now().to_rfc3339();
    let requested_name = body
        .device_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let requested_type = body
        .device_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if requested_name.is_some() || requested_type.is_some() {
        let next_name = requested_name.unwrap_or(&device.device_name);
        let next_type = requested_type.unwrap_or(&device.device_type);
        let _ = state
            .sqldb
            .execute(
                "UPDATE devices SET last_active = ?, device_name = ?, device_type = ? WHERE id = ?",
                vec![
                    TursoValue::Text(now.clone()),
                    TursoValue::Text(next_name.to_string()),
                    TursoValue::Text(next_type.to_string()),
                    TursoValue::Text(device_id_str.clone()),
                ],
            )
            .await;
    } else {
        let _ = state
            .sqldb
            .execute(
                "UPDATE devices SET last_active = ? WHERE id = ?",
                vec![
                    TursoValue::Text(now),
                    TursoValue::Text(device_id_str.clone()),
                ],
            )
            .await;
    }

    // ── Issue the token (the existing verified device-token policy) ─────────
    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let issue_result = ts.issue(device.user_id, device.id, None);
    let issue_observation = if issue_result.is_ok() {
        TokenIssueObservation::Issued
    } else {
        TokenIssueObservation::Failed
    };
    let transition = login_driver::on_token_issue_observed(driver, issue_observation);
    driver = transition.driver;
    let (token, jti) = match issue_result {
        Ok(value) => value,
        Err(error) => {
            debug_assert!(matches!(
                transition.effect,
                LoginEffect::Fail(LoginFailure::TokenIssueFailed)
            ));
            return Err(error);
        }
    };
    debug_assert!(matches!(transition.effect, LoginEffect::TrackToken));

    // ── Track the JTI before any response ───────────────────────────────────
    let track_result = rate_limit::track_device_jti(&state.store, &device_id_str, &jti);
    let track_observation = if track_result.is_ok() {
        TokenTrackObservation::Tracked
    } else {
        TokenTrackObservation::Failed
    };
    let transition = login_driver::on_token_track_observed(driver, track_observation);
    match track_result {
        Ok(()) => {
            debug_assert!(matches!(transition.effect, LoginEffect::Respond));
            Ok(Json(VerifyResponse {
                token,
                user_id: device.user_id.to_string(),
            }))
        }
        Err(error) => {
            debug_assert!(matches!(
                transition.effect,
                LoginEffect::Fail(LoginFailure::TrackingFailed)
            ));
            // The issued token is discarded: no response without tracking.
            Err(error)
        }
    }
}
