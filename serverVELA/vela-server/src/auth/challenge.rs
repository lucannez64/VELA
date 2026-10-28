//! GET /auth/challenge
//!
//! Returns a single-use 32-byte random nonce (base64-encoded) for use in an
//! authentication signature. The nonce is stored in sled with a 60-second TTL and is
//! consumed on first use.
//!
//! Each nonce is bound to one purpose (`?purpose=login|enroll|web_token`,
//! default `login`). A consumer only accepts a nonce issued for its own
//! purpose, and a nonce presented anywhere is spent, so a login nonce cannot
//! be redeemed at `/device/enroll` or `/web-session/:id/token`.
//!
//! Rate limit: 20 requests / minute per IP.
//!
//! Every post-parse decision lives in the pure
//! [`vela_session_policy::challenge_issue_driver`] driver: whether the limiter
//! allowed the request, whether the random source returned exactly 32 bytes,
//! whether the key was fresh, and therefore whether one challenge is issued.
//! The handler expands the same `challenge_issue_interpreter!` loop the policy
//! crate extracts and proves. The write is first-writer-wins (`set_ex_nx`): a
//! nonce collision never overwrites another live challenge, and a store failure
//! issues nothing.

use axum::{
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    state::AppState,
};
use vela_session_policy::challenge::{
    classify_taken_challenge, purpose_tag_bytes, ChallengeConsumption,
};
use vela_session_policy::challenge_issue_driver::{
    IssueEffect, IssueFailure, NonceObservation, PurposeObservation, RateLimitObservation,
    StoreObservation, NONCE_LEN,
};

const CHALLENGE_TTL_SECS: u64 = 60;

/// What a challenge may be redeemed for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengePurpose {
    /// `POST /auth/verify`.
    Login,
    /// `POST /device/enroll`.
    Enroll,
    /// `POST /web-session/:id/token`.
    WebToken,
}

impl ChallengePurpose {
    /// The value stored under the nonce key.
    fn tag(self) -> &'static [u8] {
        purpose_tag_bytes(self.policy())
    }

    fn policy(self) -> vela_session_policy::challenge::ChallengePurpose {
        match self {
            Self::Login => vela_session_policy::challenge::ChallengePurpose::Login,
            Self::Enroll => vela_session_policy::challenge::ChallengePurpose::Enroll,
            Self::WebToken => vela_session_policy::challenge::ChallengePurpose::WebToken,
        }
    }

    fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("login") {
            "login" => Ok(Self::Login),
            "enroll" => Ok(Self::Enroll),
            "web_token" => Ok(Self::WebToken),
            _ => Err(AppError::BadRequest(
                "purpose must be login, enroll or web_token".into(),
            )),
        }
    }
}

#[derive(Deserialize)]
pub struct ChallengeQuery {
    pub purpose: Option<String>,
}

/// Atomically take `challenge_b64` and classify the exact stored bytes against
/// the pure purpose policy. The take removes the value whatever its purpose, so
/// a present but non-matching value is spent. The caller still owns the
/// `get_del` error and its original status/message; the pure conversion of the
/// returned value and the decision live in
/// `vela_session_policy::challenge::classify_taken_challenge`.
pub(crate) fn take_challenge(
    state: &AppState,
    challenge_b64: &str,
    purpose: ChallengePurpose,
) -> Result<ChallengeConsumption> {
    let consumed = state.store.get_del(&format!("challenge:{challenge_b64}"))?;
    Ok(classify_taken_challenge(&consumed, purpose.policy()))
}

/// Spend `challenge_b64` and accept it only if it was issued for `purpose`.
///
/// The nonce is removed whatever its purpose, so presenting it at the wrong
/// endpoint burns it instead of leaving it redeemable elsewhere.
pub(crate) fn consume_challenge(
    state: &AppState,
    challenge_b64: &str,
    purpose: ChallengePurpose,
) -> Result<()> {
    match take_challenge(state, challenge_b64, purpose)? {
        ChallengeConsumption::Accepted => Ok(()),
        ChallengeConsumption::Missing => Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        )),
        ChallengeConsumption::WrongPurpose => Err(AppError::Unauthorized(
            "challenge was issued for a different purpose".into(),
        )),
    }
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    /// Base64-encoded 32-byte nonce.
    pub challenge: String,
}

/// The I/O behind each issue effect. The driver decides which method runs and
/// when (through the shared `challenge_issue_interpreter!` loop, proved in F*
/// as `run_issue`); each method only performs its effect and reports the
/// outcome. The first failure keeps the handler's original error so the
/// response carries the same status and message.
struct ChallengeIssueIo<'a> {
    state: &'a AppState,
    ip: String,
    nonce: Option<[u8; NONCE_LEN]>,
    challenge_b64: Option<String>,
    error: Option<AppError>,
}

impl ChallengeIssueIo<'_> {
    /// Record the first error; later methods never replace the original.
    fn fail(&mut self, error: AppError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    async fn check_rate_limit(&mut self) -> RateLimitObservation {
        match rate_limit::challenge_by_ip(&self.state.store, &self.ip) {
            Ok(()) => RateLimitObservation::Allowed,
            Err(error) => {
                self.fail(error);
                RateLimitObservation::Denied
            }
        }
    }

    async fn generate_nonce(&mut self) -> NonceObservation {
        let mut nonce = [0u8; NONCE_LEN];
        match getrandom::getrandom(&mut nonce) {
            Ok(()) => {
                self.nonce = Some(nonce);
                NonceObservation::Generated { len: NONCE_LEN }
            }
            Err(error) => {
                self.fail(AppError::Internal(format!(
                    "OS random source unavailable: {error}"
                )));
                NonceObservation::Unavailable
            }
        }
    }

    async fn store_nonce(
        &mut self,
        purpose: vela_session_policy::challenge::ChallengePurpose,
    ) -> StoreObservation {
        let Some(nonce) = self.nonce else {
            self.fail(AppError::Internal(
                "challenge nonce is not available".into(),
            ));
            return StoreObservation::Failed;
        };
        let nonce_b64 = B64.encode(nonce);
        match self.state.store.set_ex_nx(
            &format!("challenge:{nonce_b64}"),
            purpose_tag_bytes(purpose),
            CHALLENGE_TTL_SECS,
        ) {
            Ok(true) => {
                self.challenge_b64 = Some(nonce_b64);
                StoreObservation::Inserted
            }
            Ok(false) => {
                // A fresh 32-byte nonce already had a live challenge under its
                // key. Never overwrite it: nothing is issued for this request.
                self.fail(AppError::Internal("challenge nonce collision".into()));
                StoreObservation::KeyExists
            }
            Err(error) => {
                self.fail(error);
                StoreObservation::Failed
            }
        }
    }
}

fn issue_failure_error(
    failure: IssueFailure,
    error: Option<AppError>,
) -> AppError {
    if let Some(error) = error {
        return error;
    }
    match failure {
        IssueFailure::RateLimited => {
            AppError::RateLimited("challenge rate limit exceeded".into())
        }
        IssueFailure::InvalidPurpose => {
            AppError::BadRequest("purpose must be login, enroll or web_token".into())
        }
        IssueFailure::RandomUnavailable => {
            AppError::Internal("OS random source unavailable".into())
        }
        IssueFailure::NonceLength => {
            AppError::Internal("OS random source returned the wrong nonce length".into())
        }
        IssueFailure::Collision => {
            AppError::Internal("challenge nonce collision".into())
        }
        IssueFailure::Storage => AppError::Internal("challenge store failed".into()),
    }
}

pub async fn get_challenge(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    // The driver owns the parse decision (`Invalid` is a terminal 400 with no
    // limiter, random or store effect); the exact message stays in the slot.
    let (purpose, parse_error) = match ChallengePurpose::parse(query.purpose.as_deref()) {
        Ok(purpose) => (PurposeObservation::Requested(purpose.policy()), None),
        Err(error) => (PurposeObservation::Invalid, Some(error)),
    };
    let mut io = ChallengeIssueIo {
        state: &state,
        ip,
        nonce: None,
        challenge_b64: None,
        error: parse_error,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_session_policy::challenge_issue_interpreter!(io, purpose, await);

    match transition.effect {
        IssueEffect::Issue => {
            let challenge = io.challenge_b64.take().ok_or_else(|| {
                AppError::Internal("challenge issue driver issued no nonce".into())
            })?;
            Ok(Json(ChallengeResponse { challenge }))
        }
        IssueEffect::Fail(failure) => Err(issue_failure_error(failure, io.error.take())),
        _ => Err(AppError::Internal(
            "challenge issue driver reached no verdict".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_purpose_maps_to_its_policy_tag() {
        for (purpose, policy) in [
            (ChallengePurpose::Login, vela_session_policy::challenge::ChallengePurpose::Login),
            (ChallengePurpose::Enroll, vela_session_policy::challenge::ChallengePurpose::Enroll),
            (
                ChallengePurpose::WebToken,
                vela_session_policy::challenge::ChallengePurpose::WebToken,
            ),
        ] {
            assert_eq!(purpose.policy(), policy);
            assert_eq!(purpose.tag(), purpose_tag_bytes(policy));
        }
    }

    #[test]
    fn the_default_purpose_is_login_and_unknown_purposes_are_refused() {
        assert_eq!(ChallengePurpose::parse(None).unwrap(), ChallengePurpose::Login);
        assert!(ChallengePurpose::parse(Some("admin")).is_err());
    }
}
