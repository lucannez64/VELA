//! Ephemeral web sessions — temporary, revocable, no-install browser access to a
//! vault (see `EPHEMERAL_WEB_ACCESS_DESIGN.md`).
//!
//! Flow: a browser `POST /web-session/start` (unauthenticated) with its ephemeral
//! hybrid public keys, shows a QR, and polls `GET /web-session/:id`. An enrolled
//! device scans the QR and `POST /web-session/:id/grant`s — choosing **mode**
//! (`ro` snapshot / `rw` live) and **TTL** — sealing a capsule (RO snapshot or the
//! RW RMS) to the ephemeral KEM key. For RW the browser then proves possession of
//! its ephemeral signing key at `POST /web-session/:id/token` and receives a
//! PASETO whose absolute ceiling is the session expiry. Any device can revoke via
//! `DELETE /web-session/:id`.
//!
//! The session is self-contained: `session_id` is used as the token `device_id`,
//! so revocation reuses the existing sled `device:revoked:` mechanism and no
//! `devices` row is created.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    auth::token::TokenService,
    device::enroll::verify_auth_signature,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    net, rate_limit,
    state::AppState,
};

/// ML-KEM-1024 EK (1568) + X25519 PK (32).
const EPHEMERAL_PK_LEN: usize = 1568 + 32;
/// ML-DSA-87 vk (2592) + Ed25519 vk (32).
const WEB_VK_LEN: usize = 2592 + 32;
const LINK_NONCE_LEN: usize = 32;

const DEFAULT_TTL_SECS: i64 = 30 * 60; // 30 minutes
const MIN_TTL_SECS: i64 = 60;
const MAX_TTL_SECS: i64 = 24 * 60 * 60; // 24 hours
/// A pending (never granted) session is reaped after this long.
const PENDING_TTL_SECS: i64 = 5 * 60;
/// RO snapshots seal the whole decrypted vault, so allow a generous ceiling.
const MAX_CAPSULE_BYTES: usize = 16 * 1024 * 1024;

fn clamp_ttl(requested: Option<i64>) -> i64 {
    requested.unwrap_or(DEFAULT_TTL_SECS).clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}

fn decode_exact(b64: &str, len: usize, what: &str) -> Result<()> {
    let bytes = B64
        .decode(b64.as_bytes())
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64")))?;
    if bytes.len() != len {
        return Err(AppError::BadRequest(format!(
            "{what} must be exactly {len} bytes"
        )));
    }
    Ok(())
}

// ── POST /web-session/start ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StartRequest {
    /// Ephemeral hybrid KEM public key (b64, 1600 B) the approver seals to.
    pub ephemeral_pk: String,
    /// Ephemeral hybrid signing verification key (b64, 2624 B) used to mint an RW
    /// token. Optional: a browser that only ever wants RO may omit it.
    #[serde(default)]
    pub web_vk: Option<String>,
    /// Random nonce binding the scanned QR to this session (b64, 32 B).
    pub link_nonce: String,
}

#[derive(Serialize)]
pub struct StartResponse {
    pub session_id: Uuid,
}

pub async fn post_start(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<StartRequest>,
) -> Result<Json<StartResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::web_session_start_by_ip(&state.store, &ip)?;

    decode_exact(&body.ephemeral_pk, EPHEMERAL_PK_LEN, "ephemeral_pk")?;
    decode_exact(&body.link_nonce, LINK_NONCE_LEN, "link_nonce")?;
    if let Some(ref vk) = body.web_vk {
        decode_exact(vk, WEB_VK_LEN, "web_vk")?;
    }

    let id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    state
        .db
        .execute(
            "INSERT INTO web_sessions
                (id, user_id, ephemeral_pk, web_vk, link_nonce, mode, status, capsule, approved_by, created_at, expires_at)
             VALUES ($1, NULL, $2, $3, $4, NULL, 'pending', NULL, NULL, $5, NULL)",
            stoolap::params![
                id.to_string(),
                body.ephemeral_pk,
                body.web_vk.as_deref().unwrap_or(""), // empty = no RW signing key
                body.link_nonce,
                now,
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(session_id = %id, "web session started (pending)");
    Ok(Json(StartResponse { session_id: id }))
}

// ── GET /web-session/:id (browser polls) ────────────────────────────────────────

#[derive(Serialize)]
pub struct PollResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// The sealed capsule, returned **once** then dropped (one-shot, §5.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

struct SessionRow {
    user_id: Option<Uuid>,
    web_vk: Option<String>,
    mode: Option<String>,
    status: String,
    capsule: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

fn load_session(state: &AppState, id: Uuid) -> Result<SessionRow> {
    let rows = state
        .db
        .query(
            "SELECT user_id, web_vk, mode, status, capsule, expires_at
             FROM web_sessions WHERE id = $1",
            stoolap::params![id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound("web session not found".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let user_id = crate::db::row_val(&row, 0)?
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok());
    let web_vk = crate::db::row_val(&row, 1)?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let mode = crate::db::row_val(&row, 2)?.as_str().map(|s| s.to_string());
    let status = crate::db::row_val(&row, 3)?
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("status missing".into()))?;
    let capsule = crate::db::row_val(&row, 4)?.as_str().map(|s| s.to_string());
    let expires_at = crate::db::row_val(&row, 5)?.as_timestamp();

    Ok(SessionRow {
        user_id,
        web_vk,
        mode,
        status,
        capsule,
        expires_at,
    })
}

fn is_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    expires_at.map(|e| Utc::now() > e).unwrap_or(false)
}

pub async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PollResponse>> {
    let session = load_session(&state, id)?;

    if session.status == "granted" && is_expired(session.expires_at) {
        return Ok(Json(PollResponse {
            status: "expired".into(),
            mode: None,
            capsule: None,
            expires_at: session.expires_at,
        }));
    }

    if session.status != "granted" {
        return Ok(Json(PollResponse {
            status: session.status,
            mode: None,
            capsule: None,
            expires_at: None,
        }));
    }

    // One-shot capsule delivery: hand it over once, then drop it server-side.
    if session.capsule.is_some() {
        let _ = state.db.execute(
            "UPDATE web_sessions SET capsule = NULL WHERE id = $1",
            stoolap::params![id.to_string()],
        );
    }

    Ok(Json(PollResponse {
        status: "granted".into(),
        mode: session.mode,
        capsule: session.capsule,
        expires_at: session.expires_at,
    }))
}

// ── POST /web-session/:id/grant (approver) ──────────────────────────────────────

#[derive(Deserialize)]
pub struct GrantRequest {
    /// `"ro"` (snapshot) or `"rw"` (live).
    pub mode: String,
    /// Capsule sealed to the session's ephemeral KEM key: the RO snapshot or the
    /// RW RMS (b64).
    pub capsule: String,
    /// Requested lifetime in seconds; defaults to 30 min, capped at 24 h.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

#[derive(Serialize)]
pub struct GrantResponse {
    pub granted: bool,
    pub expires_at: DateTime<Utc>,
}

pub async fn post_grant(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
    Json(body): Json<GrantRequest>,
) -> Result<(HeaderMap, Json<GrantResponse>)> {
    let mode = match body.mode.as_str() {
        "ro" | "rw" => body.mode.as_str(),
        _ => return Err(AppError::BadRequest("mode must be 'ro' or 'rw'".into())),
    };

    let capsule_bytes = B64
        .decode(body.capsule.as_bytes())
        .map_err(|_| AppError::BadRequest("capsule is not valid base64".into()))?;
    if capsule_bytes.is_empty() || capsule_bytes.len() > MAX_CAPSULE_BYTES {
        return Err(AppError::BadRequest(format!(
            "capsule must be 1..={MAX_CAPSULE_BYTES} bytes"
        )));
    }

    let existing = load_session(&state, id)?;
    if existing.status != "pending" {
        return Err(AppError::Conflict(
            "web session is not pending (already granted or revoked)".into(),
        ));
    }
    if mode == "rw" && existing.web_vk.is_none() {
        return Err(AppError::BadRequest(
            "rw grant requires the browser to have registered web_vk at start".into(),
        ));
    }

    let ttl = clamp_ttl(body.ttl_secs);
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

    let n: i64 = state
        .db
        .execute(
            "UPDATE web_sessions
             SET user_id = $1, mode = $2, status = 'granted', capsule = $3,
                 approved_by = $4, expires_at = $5
             WHERE id = $6 AND status = 'pending'",
            stoolap::params![
                session.user_id.to_string(),
                mode,
                body.capsule,
                session.device_id.to_string(),
                expires_at.to_rfc3339(),
                id.to_string(),
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if n == 0 {
        return Err(AppError::Conflict("web session was not pending".into()));
    }

    tracing::info!(session_id = %id, user_id = %session.user_id, mode, ttl, "web session granted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(GrantResponse { granted: true, expires_at })))
}

// ── POST /web-session/:id/token (browser, RW) ───────────────────────────────────

#[derive(Deserialize)]
pub struct TokenRequest {
    pub challenge: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn post_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<TokenRequest>,
) -> Result<Json<TokenResponse>> {
    rate_limit::web_session_token_by_session(&state.store, &id.to_string())?;

    let session = load_session(&state, id)?;
    if session.status != "granted" {
        return Err(AppError::Unauthorized("web session is not active".into()));
    }
    if session.mode.as_deref() != Some("rw") {
        return Err(AppError::BadRequest("session is read-only".into()));
    }
    if is_expired(session.expires_at) {
        return Err(AppError::Unauthorized("web session expired".into()));
    }
    let expires_at = session
        .expires_at
        .ok_or_else(|| AppError::Internal("granted session missing expiry".into()))?;
    let user_id = session
        .user_id
        .ok_or_else(|| AppError::Internal("granted session missing user".into()))?;
    let web_vk_b64 = session
        .web_vk
        .ok_or_else(|| AppError::Unauthorized("session has no signing key".into()))?;
    let web_vk = B64
        .decode(web_vk_b64.as_bytes())
        .map_err(|e| AppError::Internal(format!("web_vk decode: {e}")))?;

    // Single-use challenge (issued by /auth/challenge), consumed here.
    let consumed = state
        .store
        .get_del(&format!("challenge:{}", body.challenge))?;
    if consumed.is_none() {
        return Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        ));
    }

    let challenge_bytes = B64
        .decode(&body.challenge)
        .map_err(|_| AppError::BadRequest("invalid challenge encoding".into()))?;

    verify_auth_signature(&web_vk, &challenge_bytes, &id.to_string(), &body.signature)?;

    // device_id = session_id; hard_cap = session expiry, so renewals never outlive
    // the granted TTL and revocation via `device:revoked:<session_id>` applies.
    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let (token, jti) = ts.issue(user_id, id, Some(expires_at))?;
    rate_limit::track_device_jti(&state.store, &id.to_string(), &jti)?;

    tracing::info!(session_id = %id, user_id = %user_id, "web session rw token issued");
    Ok(Json(TokenResponse {
        token,
        user_id: user_id.to_string(),
        expires_at,
    }))
}

// ── DELETE /web-session/:id (revoke) ────────────────────────────────────────────

pub async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let existing = load_session(&state, id)?;
    // Only the owner (granting user) may revoke a granted session.
    if existing.user_id != Some(session.user_id) {
        return Err(AppError::NotFound("web session not found".into()));
    }

    state
        .db
        .execute(
            "UPDATE web_sessions SET status = 'revoked', capsule = NULL WHERE id = $1",
            stoolap::params![id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Reject any already-issued RW token (device_id == session_id) for up to the
    // maximum possible remaining lifetime.
    let _ = state.store.set_ex(
        &format!("device:revoked:{}", id),
        &[1u8],
        MAX_TTL_SECS as u64,
    );

    tracing::info!(session_id = %id, user_id = %session.user_id, "web session revoked");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "revoked": true }))))
}

// ── Background cleanup ──────────────────────────────────────────────────────────

/// Periodically prune revoked sessions, granted sessions past their expiry, and
/// pending sessions that were never granted.
pub async fn cleanup_task(db: stoolap::Database) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10 * 60));
    loop {
        interval.tick().await;
        let now = Utc::now();
        let pending_cutoff = (now - chrono::Duration::seconds(PENDING_TTL_SECS)).to_rfc3339();
        let now_str = now.to_rfc3339();

        let revoked = db.execute("DELETE FROM web_sessions WHERE status = 'revoked'", ());
        let expired = db.execute(
            "DELETE FROM web_sessions WHERE expires_at IS NOT NULL AND expires_at < $1",
            stoolap::params![now_str],
        );
        let stale_pending = db.execute(
            "DELETE FROM web_sessions WHERE status = 'pending' AND created_at < $1",
            stoolap::params![pending_cutoff],
        );

        let n = [revoked, expired, stale_pending]
            .into_iter()
            .filter_map(|r| r.ok())
            .sum::<i64>();
        if n > 0 {
            tracing::info!(purged = n, "web session cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_clamps_to_bounds() {
        assert_eq!(clamp_ttl(None), DEFAULT_TTL_SECS);
        assert_eq!(clamp_ttl(Some(10)), MIN_TTL_SECS); // below floor
        assert_eq!(clamp_ttl(Some(999_999)), MAX_TTL_SECS); // above ceiling
        assert_eq!(clamp_ttl(Some(3600)), 3600); // within range
    }

    #[test]
    fn expiry_check() {
        assert!(!is_expired(None));
        assert!(!is_expired(Some(Utc::now() + chrono::Duration::minutes(5))));
        assert!(is_expired(Some(Utc::now() - chrono::Duration::minutes(5))));
    }
}
