//! Ephemeral web sessions — temporary, revocable, no-install browser access to a
//! vault (see `EPHEMERAL_WEB_ACCESS_DESIGN.md`).
//!
//! Flow: a browser `POST /web-session/start` (unauthenticated) with its ephemeral
//! hybrid public keys, **the account id it wants access to** and the hash of a
//! **poll secret only it holds**, shows a QR, and polls `GET /web-session/:id`
//! (presenting that secret). An enrolled device of *that account* scans the QR
//! and `POST /web-session/:id/grant`s — choosing **mode**
//! (`ro` snapshot / `rw` live) and **TTL** — sealing a capsule (RO snapshot or the
//! RW per-chunk vault keys) to the ephemeral KEM key. For RW the browser then proves possession of
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
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    auth::token::{TokenScope, TokenService},
    device::enroll::verify_auth_signature,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, DeviceSession},
    net, rate_limit,
    sqldb::{Db as _, TursoDb, TursoValue},
    state::AppState,
};

/// ML-KEM-1024 EK (1568) + X25519 PK (32).
const EPHEMERAL_PK_LEN: usize = 1568 + 32;
/// ML-DSA-87 vk (2592) + Ed25519 vk (32).
const WEB_VK_LEN: usize = 2592 + 32;
const LINK_NONCE_LEN: usize = 32;
/// SHA-256 digest of the browser's poll secret.
const POLL_SECRET_HASH_LEN: usize = 32;
/// Header carrying the raw poll secret on `GET /web-session/:id`.
const POLL_SECRET_HEADER: &str = "x-web-session-secret";

const DEFAULT_TTL_SECS: i64 = 30 * 60; // 30 minutes
const MIN_TTL_SECS: i64 = 60;
pub(crate) const MAX_TTL_SECS: i64 = 24 * 60 * 60; // 24 hours
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

/// Constant-time byte-slice equality (length leaks only via early length check).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    /// The account this browser wants access to — typed by the user from their
    /// app's Settings → Account. Only this user may read the session keys or
    /// grant it, so seeing the QR is no longer enough to hijack the session.
    pub approver_user_id: Uuid,
    /// SHA-256 (b64, 32 B) of a secret only this browser holds. It must present
    /// the secret to collect the capsule, so learning the `session_id` alone no
    /// longer lets anyone race the browser for it.
    pub poll_secret_hash: String,
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
    decode_exact(&body.poll_secret_hash, POLL_SECRET_HASH_LEN, "poll_secret_hash")?;
    if let Some(ref vk) = body.web_vk {
        decode_exact(vk, WEB_VK_LEN, "web_vk")?;
    }

    // The committed approver is stored verbatim and never checked against the
    // `users` table: this endpoint is unauthenticated, so confirming that an
    // account exists would turn it into a user-enumeration oracle. A typo simply
    // yields a session nobody can grant, which expires in 5 minutes.
    let id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    state
        .sqldb
        .execute(
            "INSERT INTO web_sessions
                (id, user_id, approver_user_id, poll_secret_hash, ephemeral_pk, web_vk, link_nonce, mode, status, capsule, approved_by, created_at, expires_at)
             VALUES (?, NULL, ?, ?, ?, ?, ?, NULL, 'pending', NULL, NULL, ?, NULL)",
            vec![
                TursoValue::Text(id.to_string()),
                TursoValue::Text(body.approver_user_id.to_string()),
                TursoValue::Text(body.poll_secret_hash),
                TursoValue::Text(body.ephemeral_pk),
                TursoValue::Text(body.web_vk.as_deref().unwrap_or("").to_string()), // empty = no RW signing key
                TursoValue::Text(body.link_nonce),
                TursoValue::Text(now),
            ],
        )
        .await
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
    /// The account the browser committed to at `start` (the only user allowed to
    /// grant). `None` only for rows written before the binding existed.
    approver_user_id: Option<Uuid>,
    /// SHA-256 of the browser's poll secret (b64). `None` only for rows written
    /// before the check existed.
    poll_secret_hash: Option<String>,
    web_vk: Option<String>,
    link_nonce: Option<String>,
    mode: Option<String>,
    status: String,
    capsule: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    /// Epoch whose chunk keys were sealed into this grant's capsule.
    key_epoch: Option<i64>,
}

async fn load_session(state: &AppState, id: Uuid) -> Result<SessionRow> {
    let rows = state
        .sqldb
        .query(
            "SELECT user_id, web_vk, link_nonce, mode, status, capsule, expires_at,
                    approver_user_id, poll_secret_hash, key_epoch
             FROM web_sessions WHERE id = ?",
            vec![TursoValue::Text(id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound("web session not found".into()))?;

    let text = |i: usize| row.text(i).filter(|s| !s.is_empty());
    let user_id = row.uuid(0);
    let web_vk = text(1).map(String::from);
    let link_nonce = text(2).map(String::from);
    let mode = row.text(3).map(String::from);
    let status = row
        .text(4)
        .map(String::from)
        .ok_or_else(|| AppError::Internal("status missing".into()))?;
    let capsule = row.text(5).map(String::from);
    let expires_at = row.timestamp(6);
    let approver_user_id = row.uuid(7);
    let poll_secret_hash = text(8).map(String::from);
    let key_epoch = row.i64(9).filter(|epoch| *epoch >= 1);

    Ok(SessionRow {
        user_id,
        approver_user_id,
        poll_secret_hash,
        web_vk,
        link_nonce,
        mode,
        status,
        capsule,
        expires_at,
        key_epoch,
    })
}

fn is_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    expires_at.map(|e| Utc::now() > e).unwrap_or(false)
}

/// Verify the caller is the browser that started this session.
///
/// The poll endpoint is unauthenticated by design (the browser has no account),
/// so possession of the secret registered at `start` is what stands in for
/// identity. It never travels in the QR, so learning the `session_id` — from a
/// URL, a log, a referrer — no longer lets anyone collect (and thereby destroy)
/// the one-shot capsule. Same error for every failure, so nothing distinguishes
/// a wrong secret from a session that does not exist.
fn check_poll_secret(session: &SessionRow, headers: &HeaderMap) -> Result<()> {
    use sha2::{Digest, Sha256};

    let unauthorized = || AppError::Unauthorized("web session not found".into());
    let expected = session
        .poll_secret_hash
        .as_deref()
        .and_then(|s| B64.decode(s.as_bytes()).ok())
        .ok_or_else(unauthorized)?;
    let presented = headers
        .get(POLL_SECRET_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| B64.decode(v.as_bytes()).ok())
        .ok_or_else(unauthorized)?;

    if !ct_eq(Sha256::digest(&presented).as_slice(), &expected) {
        return Err(unauthorized());
    }
    Ok(())
}

pub async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<PollResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::web_session_poll_by_ip(&state.store, &ip)?;

    // A missing session and a wrong secret must be indistinguishable, or the
    // 404 itself confirms that a `session_id` is live.
    let session = match load_session(&state, id).await {
        Ok(session) => session,
        Err(AppError::NotFound(_)) => {
            return Err(AppError::Unauthorized("web session not found".into()))
        }
        Err(e) => return Err(e),
    };
    check_poll_secret(&session, &headers)?;

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
    //
    // Two things had to change here (red-team follow-up).
    //
    // The clear is now the thing that *decides* who gets the capsule, rather
    // than a cleanup that happens alongside serving it. `WHERE capsule IS NOT
    // NULL` plus the affected-row count makes exactly one caller the winner:
    // previously both halves of a concurrent poll read a non-NULL capsule and
    // both were served it, so "one-shot" held only when nobody raced. Only the
    // holder of the poll secret can reach this, so that race was not an
    // attacker's to win — but one-shot delivery exists precisely to bound the
    // damage if that secret leaks, and a property that evaporates under
    // concurrency does not bound anything.
    //
    // And the result is no longer discarded. `let _ =` meant a failing UPDATE
    // still served the capsule and left it in the row, so a persistently failing
    // write turned a one-shot into an unlimited one — strictly worse than the
    // race it sat next to. Failing closed costs the user a retry.
    let capsule = match session.capsule {
        None => None,
        Some(capsule) => {
            let cleared = state
                .sqldb
                .execute(
                    "UPDATE web_sessions SET capsule = NULL WHERE id = ? AND capsule IS NOT NULL",
                    vec![TursoValue::Text(id.to_string())],
                )
                .await
                .map_err(|e| AppError::Internal(format!("capsule clear failed: {e}")))?;
            if cleared < 1 {
                // Someone else took it in the meantime. Report the session as
                // granted with nothing attached rather than serving a capsule
                // we could not retract.
                tracing::warn!(session_id = %id, "capsule already collected; not serving it twice");
                None
            } else {
                Some(capsule)
            }
        }
    };

    Ok(Json(PollResponse {
        status: "granted".into(),
        mode: session.mode,
        capsule,
        expires_at: session.expires_at,
    }))
}

// ── GET /web-session/:id/keys (approver) ────────────────────────────────────────

#[derive(Serialize)]
pub struct KeysResponse {
    /// Ephemeral hybrid KEM public key (b64, 1600 B) the approver seals to.
    pub ephemeral_pk: String,
    /// Ephemeral signing verification key (b64, 2624 B), empty for RO-only.
    pub web_vk: String,
}

/// Return the browser's registered ephemeral public keys for a pending session.
///
/// Lets the link QR carry only the (short) `session_id` instead of the ~2 KB
/// public key — the approver fetches the key here, keeping the QR scannable. The
/// keys are public, but the lookup is scoped to the account the browser
/// committed to at `start`: anyone else gets the same 404 as a nonexistent
/// session, so a stray `session_id` reveals nothing about a pending link.
pub async fn get_keys(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<KeysResponse>)> {
    rate_limit::web_session_keys_by_user(&state.store, &session.user_id.to_string())?;

    let rows = state
        .sqldb
        .query(
            "SELECT ephemeral_pk, web_vk, status FROM web_sessions
             WHERE id = ? AND approver_user_id = ?",
            vec![
                TursoValue::Text(id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound("web session not found".into()))?;

    let ephemeral_pk = row
        .text(0)
        .map(String::from)
        .ok_or_else(|| AppError::Internal("ephemeral_pk missing".into()))?;
    let web_vk = row.text(1).unwrap_or_default().to_string();
    let status = row.text(2).unwrap_or_default().to_string();
    if status != "pending" {
        return Err(AppError::Conflict(
            "web session is no longer pending".into(),
        ));
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(KeysResponse { ephemeral_pk, web_vk })))
}

// ── POST /web-session/:id/grant (approver) ──────────────────────────────────────

#[derive(Deserialize)]
pub struct GrantRequest {
    /// `"ro"` (snapshot) or `"rw"` (live).
    pub mode: String,
    /// Capsule sealed to the session's ephemeral KEM key: the RO snapshot or the
    /// RW per-chunk vault keys (b64).
    pub capsule: String,
    /// Anti-phishing binding: the 32-byte link nonce (b64) the browser showed in
    /// the QR. Must match the nonce registered at `/web-session/start`.
    pub link_nonce: String,
    /// Exact vault-key epoch used to seal the capsule. The grant CAS binds this
    /// to the account so a concurrent rotation cannot mislabel old key material.
    pub key_epoch: i64,
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
    session: DeviceSession,
    Json(body): Json<GrantRequest>,
) -> Result<(HeaderMap, Json<GrantResponse>)> {
    let mode = match body.mode.as_str() {
        "ro" | "rw" => body.mode.as_str(),
        _ => return Err(AppError::BadRequest("mode must be 'ro' or 'rw'".into())),
    };
    if body.key_epoch < 1 {
        return Err(AppError::BadRequest("key_epoch must be positive".into()));
    }

    let capsule_bytes = B64
        .decode(body.capsule.as_bytes())
        .map_err(|_| AppError::BadRequest("capsule is not valid base64".into()))?;
    if capsule_bytes.is_empty() || capsule_bytes.len() > MAX_CAPSULE_BYTES {
        return Err(AppError::BadRequest(format!(
            "capsule must be 1..={MAX_CAPSULE_BYTES} bytes"
        )));
    }

    let existing = load_session(&state, id).await?;
    if existing.status != "pending" {
        return Err(AppError::Conflict(
            "web session is not pending (already granted or revoked)".into(),
        ));
    }

    // Authorization binding: the browser named the account it wants access to at
    // `start`, and only that account may grant. Without this, the bearer token of
    // *any* VELA user who saw the QR (shoulder-surf, screen share, leaked URL)
    // was enough to hand the browser an attacker-controlled vault or RMS.
    if existing.approver_user_id != Some(session.user_id) {
        return Err(AppError::Forbidden(
            "this web request was started for a different VELA account".into(),
        ));
    }

    // Anti-phishing binding: the QR the approver scanned must carry the same
    // link nonce the browser registered at start. Compared in constant time;
    // any failure yields the same error so an attacker cannot tell a missing
    // session from a nonce mismatch.
    let given_nonce = B64.decode(body.link_nonce.as_bytes()).map_err(|_| {
        AppError::Unauthorized("link_nonce mismatch — scanned QR does not match this session".into())
    })?;
    let stored_nonce = existing
        .link_nonce
        .as_deref()
        .and_then(|s| B64.decode(s.as_bytes()).ok())
        .ok_or_else(|| {
            AppError::Unauthorized(
                "link_nonce mismatch — scanned QR does not match this session".into(),
            )
        })?;
    if given_nonce.len() != LINK_NONCE_LEN || !ct_eq(&given_nonce, &stored_nonce) {
        return Err(AppError::Unauthorized(
            "link_nonce mismatch — scanned QR does not match this session".into(),
        ));
    }

    if mode == "rw" && existing.web_vk.is_none() {
        return Err(AppError::BadRequest(
            "rw grant requires the browser to have registered web_vk at start".into(),
        ));
    }

    let ttl = clamp_ttl(body.ttl_secs);
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

    let n = state
        .sqldb
        .execute(
            // `approver_user_id` is re-checked here so the binding also holds
            // against a concurrent grant, not just the read above.
            "UPDATE web_sessions
             SET user_id = ?, mode = ?, status = 'granted', capsule = ?,
                 approved_by = ?, expires_at = ?,
                 key_epoch = ?
             WHERE id = ? AND status = 'pending' AND approver_user_id = ?
               AND EXISTS (
                   SELECT 1 FROM users
                   WHERE id = ? AND rekey_state IS NULL AND key_epoch = ?
               )",
            vec![
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Text(mode.to_string()),
                TursoValue::Text(body.capsule),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(expires_at.to_rfc3339()),
                TursoValue::Integer(body.key_epoch),
                TursoValue::Text(id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(body.key_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if n == 0 {
        return Err(AppError::Conflict(
            "web session was not pending or its vault key epoch changed".into(),
        ));
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
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<TokenRequest>,
) -> Result<Json<TokenResponse>> {
    // Both the budget and the backoff are scoped to the caller, not to the
    // session (red-team RT-2). The session id is in the QR and this endpoint
    // does not require the poll secret, so a shared scope let an onlooker's
    // three bad proofs lock the real browser out for the session's lifetime.
    // The per-session cap stays behind it as a distributed-grind backstop.
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::web_session_token_by_ip_session(&state.store, &ip, &id.to_string())?;
    rate_limit::web_session_token_by_session(&state.store, &id.to_string())?;
    // The flat rate limit let a guesser keep trying the ephemeral-key proof at a
    // steady rate indefinitely. `/auth/verify` has had exponential backoff on
    // consecutive failures since the spec asked for it; this proof is the same
    // shape and now gets the same treatment — keyed the same way too, on
    // (ip, id) rather than on id alone.
    let backoff_scope = format!("websession:token:{ip}:{id}");
    rate_limit::check_backoff(&state.store, &backoff_scope)?;

    let session = load_session(&state, id).await?;
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

    if let Err(e) = verify_auth_signature(&web_vk, &challenge_bytes, &id.to_string(), &body.signature)
    {
        rate_limit::record_backoff_failure(&state.store, &backoff_scope)?;
        return Err(e);
    }
    rate_limit::reset_backoff(&state.store, &backoff_scope)?;

    // device_id = session_id; hard_cap = session expiry, so renewals never outlive
    // the granted TTL and revocation via `device:revoked:<session_id>` applies.
    //
    // Scoped `WebSession` (red-team RT-4). Without that claim this token was
    // byte-for-byte as authoritative as an enrolled laptop's: it could rotate
    // the recovery share, register the attacker's recovery passkey, revoke the
    // user's real devices, and delete the account. The design calls this session
    // temporary and non-enrolling; the scope is what makes that true rather than
    // merely stated.
    // Bind the token to the epoch whose keys were sealed into this grant's
    // capsule. Using the epoch at token-exchange time would let a pre-rotation
    // grant redeemed after commit masquerade as current.
    let key_epoch = session.key_epoch.unwrap_or(1);
    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let (token, jti) = ts.issue_scoped_at_epoch(
        user_id,
        id,
        Some(expires_at),
        TokenScope::WebSession,
        Some(key_epoch),
    )?;
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
    session: DeviceSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let existing = load_session(&state, id).await?;
    // Only the owner may revoke: the granting user for a granted session, or the
    // committed approver for one still pending (declining the request).
    let owner = existing.user_id.or(existing.approver_user_id);
    if owner != Some(session.user_id) {
        return Err(AppError::NotFound("web session not found".into()));
    }

    // Reject any already-issued RW token (device_id == session_id) before the
    // SQL audit row says the session is revoked. If SQL subsequently fails,
    // the safe partial state is locked-out-but-visible, not marked-but-live.
    state.store.set_ex(
        &format!("device:revoked:{}", id),
        &[1u8],
        MAX_TTL_SECS as u64,
    )?;

    state
        .sqldb
        .execute(
            "UPDATE web_sessions SET status = 'revoked', capsule = NULL WHERE id = ?",
            vec![TursoValue::Text(id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(session_id = %id, user_id = %session.user_id, "web session revoked");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "revoked": true }))))
}

// ── GET /web-sessions (list user's active sessions) ─────────────────────────────

#[derive(Serialize)]
pub struct WebSessionInfo {
    pub id: String,
    pub mode: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct SessionsListResponse {
    pub sessions: Vec<WebSessionInfo>,
}

pub async fn get_sessions_list(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<SessionsListResponse>)> {
    let rows = state
        .sqldb
        .query(
            "SELECT id, mode, status, created_at, expires_at
             FROM web_sessions
             WHERE user_id = ? AND status = 'granted'
             ORDER BY created_at DESC
             LIMIT 1000",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let now = Utc::now();
    let mut sessions = Vec::new();
    for row in &rows {
        let id = row.text(0).map(String::from).unwrap_or_default();
        let mode = row.text(1).map(String::from).unwrap_or_default();
        let status = row.text(2).map(String::from).unwrap_or_default();
        let created_at = row.text(3).map(String::from).unwrap_or_default();
        let expires_at = row.timestamp(4);

        // Skip expired sessions (cleanup task handles deletion asynchronously).
        if expires_at.map(|e| now > e).unwrap_or(false) {
            continue;
        }

        sessions.push(WebSessionInfo {
            id,
            mode,
            status,
            created_at,
            expires_at,
        });
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(SessionsListResponse { sessions })))
}

// ── Background cleanup ──────────────────────────────────────────────────────────

/// Periodically prune revoked sessions, granted sessions past their expiry, and
/// pending sessions that were never granted.
pub async fn cleanup_task(db: Arc<TursoDb>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10 * 60));
    loop {
        interval.tick().await;
        let now = Utc::now();
        let pending_cutoff = (now - chrono::Duration::seconds(PENDING_TTL_SECS)).to_rfc3339();
        let now_str = now.to_rfc3339();

        let revoked = db
            .execute("DELETE FROM web_sessions WHERE status = 'revoked'", vec![])
            .await;
        let expired = db
            .execute(
                "DELETE FROM web_sessions WHERE expires_at IS NOT NULL AND expires_at < ?",
                vec![TursoValue::Text(now_str)],
            )
            .await;
        let stale_pending = db
            .execute(
                "DELETE FROM web_sessions WHERE status = 'pending' AND created_at < ?",
                vec![TursoValue::Text(pending_cutoff)],
            )
            .await;

        let n = [revoked, expired, stale_pending]
            .into_iter()
            .filter_map(|r| r.ok())
            .sum::<u64>();
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
