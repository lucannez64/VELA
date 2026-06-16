//! GET /auth/challenge
//!
//! Returns a single-use 32-byte random nonce (base64-encoded) for use in a
//! authentication signature. The nonce is stored in sled with a 60-second TTL and is
//! consumed on first use.
//!
//! Rate limit: 20 requests / minute per IP.

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::Serialize;
use std::net::SocketAddr;

use crate::{error::Result, net, rate_limit, state::AppState};

const CHALLENGE_TTL_SECS: u64 = 60;

#[derive(Serialize)]
pub struct ChallengeResponse {
    /// Base64-encoded 32-byte nonce.
    pub challenge: String,
}

pub async fn get_challenge(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<ChallengeResponse>> {
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
    state.store.set_ex(&store_key, &[1u8], CHALLENGE_TTL_SECS)?;

    Ok(Json(ChallengeResponse {
        challenge: nonce_b64,
    }))
}
