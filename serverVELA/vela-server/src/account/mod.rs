//! POST /account/register
//!
//! Bootstrap endpoint — creates a new user record and registers their first
//! device in a single atomic operation.  No prior authentication is required
//! because this is the entry point into the system.
//!
//! ## Why this endpoint exists
//!
//! `POST /device/enroll` requires an already-enrolled Device A to authorize
//! Device B via a Cyclo ZKP.  That presupposes at least one device already
//! exists.  This endpoint handles the cold-start case: user has no account yet.
//!
//! ## Request body
//!
//! ```json
//! {
//!   "hybrid_ek": "<base64 1600-byte>",  // ML-KEM-1024 EK ‖ X25519 PK
//!   "hybrid_vk": "<base64 2624-byte>",  // ML-DSA-87 VK ‖ Ed25519 VK
//!   "cyclo_pk":  "<base64 1024-byte>"   // Cyclo ZKP public key (128 × u64 LE)
//! }
//! ```
//!
//! The first device generates the RMS locally and stores it in its own hardware
//! enclave; it is never sent to the server.
//!
//! ## Response
//!
//! ```json
//! { "user_id": "<uuid>", "device_id": "<uuid>" }
//! ```
//!
//! After registration the client must go through `/auth/challenge` →
//! `/auth/verify` to obtain a PASETO v4 session token.
//!
//! ## Rate limit
//!
//! 5 registrations per hour per IP (Redis sliding window, 3600 s window).
//! This is enforced before any DB work to prevent abuse.

pub mod delete;

use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    rate_limit,
    state::AppState,
};

// ── Key-length constants (mirrors vela-crypto::signing / vela-crypto::kem) ──

const HYBRID_EK_LEN: usize = 1568 + 32;  // ML-KEM-1024 EK + X25519 PK
const HYBRID_VK_LEN: usize = 2592 + 32;  // ML-DSA-87 VK + Ed25519 VK
const CYCLO_PK_LEN:  usize = 128 * 8;    // 128 × u64 LE

// ── Wire types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub cyclo_pk:  String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id:   Uuid,
    pub device_id: Uuid,
}

// ── Handler ────────────────────────────────────────────────────────────────

pub async fn post_register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    let ip = addr.ip().to_string();

    // ── Rate limit: 5 registrations / hour per IP ─────────────────────────
    rate_limit::check(&state.store, &format!("rl:register:ip:{ip}"), 5, 3600)?;

    // ── Decode and validate key material ──────────────────────────────────
    let hybrid_ek = decode_b64_exact(&body.hybrid_ek, HYBRID_EK_LEN, "hybrid_ek")?;
    let hybrid_vk = decode_b64_exact(&body.hybrid_vk, HYBRID_VK_LEN, "hybrid_vk")?;
    let cyclo_pk  = decode_b64_exact(&body.cyclo_pk,  CYCLO_PK_LEN,  "cyclo_pk")?;

    // ── Insert user + device atomically ───────────────────────────────────
    let user_id   = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    let mut tx = state.db.begin().await?;

    sqlx::query("INSERT INTO users (id) VALUES ($1)")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO devices (id, user_id, hybrid_ek, hybrid_vk, cyclo_pk)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(hybrid_ek)
    .bind(hybrid_vk)
    .bind(cyclo_pk)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(user_id = %user_id, device_id = %device_id, "account registered");

    Ok(Json(RegisterResponse { user_id, device_id }))
}

// ── Helper ─────────────────────────────────────────────────────────────────

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
