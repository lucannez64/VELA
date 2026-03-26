//! Recovery share endpoints (§4.3 Master Passwordless Recovery).
//!
//! VELA uses a 2-of-3 Shamir Secret Sharing scheme to allow recovery when all
//! devices are lost:
//!
//! - **Share 1** — client's cloud provider (iCloud / Google Drive).
//! - **Share 2** — stored here on the VELA server.  Encrypted client-side
//!   under a key derived from the user's FIDO2 / passkey hardware credential,
//!   so the server cannot decrypt it.
//! - **Share 3** — held by a trusted contact via `/share/send`.
//!
//! ## Endpoints
//!
//! | Method | Route             | Description                              |
//! |--------|-------------------|------------------------------------------|
//! | PUT    | /recovery/share   | Store (or replace) Share 2 for this user |
//! | GET    | /recovery/share   | Retrieve Share 2 for this user           |
//! | DELETE | /recovery/share   | Wipe Share 2 (e.g. on account deletion)  |
//!
//! All three require a valid PASETO v4 session token.
//!
//! ## Security note
//!
//! The server stores the share as an opaque blob.  Even a full server
//! compromise does not allow recovery of the RMS — the attacker would also
//! need the user's physical FIDO2 hardware key.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

/// Maximum size for an encrypted recovery share blob (generous upper bound).
/// A Shamir share of a 32-byte RMS after AEAD encryption is tiny; this limit
/// prevents abuse of the storage endpoint.
const MAX_SHARE_BYTES: usize = 4096;

// ── PUT /recovery/share ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PutShareRequest {
    /// Base64-encoded encrypted Share 2 blob.
    pub share: String,
}

#[derive(Serialize)]
pub struct PutShareResponse {
    pub stored: bool,
}

/// Store (or replace) the encrypted recovery share for the authenticated user.
pub async fn put_share(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<PutShareRequest>,
) -> Result<(HeaderMap, Json<PutShareResponse>)> {
    let share_bytes = B64
        .decode(&body.share)
        .map_err(|_| AppError::BadRequest("share is not valid base64".into()))?;

    if share_bytes.len() > MAX_SHARE_BYTES {
        return Err(AppError::BadRequest(format!(
            "share exceeds maximum size of {MAX_SHARE_BYTES} bytes"
        )));
    }

    sqlx::query(
        "UPDATE users SET recovery_share = $1 WHERE id = $2",
    )
    .bind(&share_bytes)
    .bind(session.user_id)
    .execute(&state.db)
    .await?;

    tracing::info!(user_id = %session.user_id, bytes = share_bytes.len(), "recovery share stored");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(PutShareResponse { stored: true })))
}

// ── GET /recovery/share ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct GetShareResponse {
    /// Base64-encoded encrypted Share 2 blob.
    pub share: String,
}

/// Retrieve the encrypted recovery share for the authenticated user.
///
/// Returns `404` if no share has been stored yet.
pub async fn get_share(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<GetShareResponse>)> {
    #[derive(sqlx::FromRow)]
    struct Row { recovery_share: Option<Vec<u8>> }

    let row = sqlx::query_as::<_, Row>(
        "SELECT recovery_share FROM users WHERE id = $1",
    )
    .bind(session.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let share_bytes = row.recovery_share
        .ok_or_else(|| AppError::NotFound("no recovery share stored for this user".into()))?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(GetShareResponse { share: B64.encode(&share_bytes) })))
}

// ── DELETE /recovery/share ────────────────────────────────────────────────────

/// Wipe the stored recovery share (e.g. on account deletion or FIDO2 rotation).
pub async fn delete_share(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, StatusCode)> {
    sqlx::query("UPDATE users SET recovery_share = NULL WHERE id = $1")
        .bind(session.user_id)
        .execute(&state.db)
        .await?;

    tracing::info!(user_id = %session.user_id, "recovery share deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}
