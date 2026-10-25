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
        match self {
            Self::Login => b"login",
            Self::Enroll => b"enroll",
            Self::WebToken => b"web_token",
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

/// Spend `challenge_b64` and accept it only if it was issued for `purpose`.
///
/// The nonce is removed whatever its purpose, so presenting it at the wrong
/// endpoint burns it instead of leaving it redeemable elsewhere.
pub(crate) fn consume_challenge(
    state: &AppState,
    challenge_b64: &str,
    purpose: ChallengePurpose,
) -> Result<()> {
    let consumed = state.store.get_del(&format!("challenge:{challenge_b64}"))?;
    match consumed {
        Some(tag) if tag == purpose.tag() => Ok(()),
        Some(_) => Err(AppError::Unauthorized(
            "challenge was issued for a different purpose".into(),
        )),
        None => Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
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
