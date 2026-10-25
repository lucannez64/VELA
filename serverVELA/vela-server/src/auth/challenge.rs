//! GET /auth/challenge
//!
//! Returns a single-use 32-byte random nonce (base64-encoded) for use in a
//! authentication signature. The nonce is stored in sled with a 60-second TTL and is
//! consumed on first use.
//!
//! Each nonce is bound to one purpose (`?purpose=login|enroll|web_token`,
//! default `login`). A consumer only accepts a nonce issued for its own
//! purpose, and a nonce presented anywhere is spent, so a login nonce cannot
//! be redeemed at `/device/enroll` or `/web-session/:id/token`.
//!
//! Rate limit: 20 requests / minute per IP.

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

pub async fn get_challenge(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeResponse>> {
    let purpose = ChallengePurpose::parse(query.purpose.as_deref())?;
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);

    // ── Rate limit ────────────────────────────────────────────────────────────
    rate_limit::challenge_by_ip(&state.store, &ip)?;

    // ── Generate nonce ────────────────────────────────────────────────────────
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| {
        crate::error::AppError::Internal(format!("OS random source unavailable: {e}"))
    })?;
    let nonce_b64 = B64.encode(nonce);

    // ── Store in sled (single-use, 60 s TTL) ──────────────────────────────────
    let store_key = format!("challenge:{nonce_b64}");
    state
        .store
        .set_ex(&store_key, purpose.tag(), CHALLENGE_TTL_SECS)?;

    Ok(Json(ChallengeResponse {
        challenge: nonce_b64,
    }))
}
