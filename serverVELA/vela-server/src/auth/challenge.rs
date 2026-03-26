//! GET /auth/challenge
//!
//! Returns a single-use 32-byte random nonce (base64-encoded) for use in a
//! Cyclo ZKP proof.  The nonce is stored in Redis with a 60-second TTL and is
//! consumed on first use.
//!
//! Rate limit: 20 requests / minute per IP (Redis sliding window).

use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use redis::AsyncCommands;
use serde::Serialize;
use std::net::SocketAddr;

use crate::{error::Result, rate_limit, state::AppState};

const CHALLENGE_TTL_SECS: u64 = 60;

#[derive(Serialize)]
pub struct ChallengeResponse {
    /// Base64-encoded 32-byte nonce.
    pub challenge: String,
}

pub async fn get_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<ChallengeResponse>> {
    let ip = addr.ip().to_string();
    let mut redis = state.redis.clone();

    // ── Rate limit ────────────────────────────────────────────────────────────
    rate_limit::challenge_by_ip(&mut redis, &ip).await?;

    // ── Generate nonce ────────────────────────────────────────────────────────
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_b64 = B64.encode(nonce);

    // ── Store in Redis (single-use, 60 s TTL) ─────────────────────────────────
    let redis_key = format!("challenge:{nonce_b64}");
    let _: () = redis
        .set_ex(&redis_key, 1_u8, CHALLENGE_TTL_SECS)
        .await
        .map_err(crate::error::AppError::Redis)?;

    Ok(Json(ChallengeResponse { challenge: nonce_b64 }))
}
