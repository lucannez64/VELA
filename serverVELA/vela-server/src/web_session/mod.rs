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
use vela_session_policy::{
    websession_driver::{
        DeleteEffect, DeleteFailure, DeleteLookupObservation,
        DeleteRecordObservation, DeleteSentinelObservation, GrantActorObservation, GrantEffect,
        GrantFailure, GrantLookupObservation, GrantUpdate, GrantUpdateObservation,
        StartEffect, StartFailure, StartInsertObservation, StartLimitObservation,
        StartValidationObservation, TokenChallengeObservation, TokenClaimObservation,
        TokenEffect, TokenFailure, TokenFailureRecordObservation, TokenIssueObservation,
        TokenLimitObservation, TokenLookupObservation, TokenResetObservation,
        TokenSessionObservation, TokenSignatureObservation,
    },
    GrantObservation, SessionMode as PolicyMode, SessionPhase as PolicyPhase,
};

use crate::{
    auth::token::TokenService,
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

// Production TTLs live in the verified policy layer (vela-session-policy);
// these remain as the documented reference values the policy clamps to, and
// the tests below pin the clamp against them.
#[cfg(test)]
const DEFAULT_TTL_SECS: i64 = 30 * 60; // 30 minutes
#[cfg(test)]
const MIN_TTL_SECS: i64 = 60;
pub(crate) const MAX_TTL_SECS: i64 = 24 * 60 * 60; // 24 hours
/// A pending (never granted) session is reaped after this long.
const PENDING_TTL_SECS: i64 = 5 * 60;
/// RO snapshots seal the whole decrypted vault, so allow a generous ceiling.
const MAX_CAPSULE_BYTES: usize = 16 * 1024 * 1024;

/// M25: the clamp lives in the verified policy layer. (Tests pin the policy
/// constants; production always calls the policy function directly.)
#[cfg(test)]
fn clamp_ttl(requested: Option<i64>) -> i64 {
    vela_session_policy::clamp_web_ttl(requested)
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

/// The I/O behind each start effect. The driver decides which method runs and
/// when (through the shared `websession_start_interpreter!` loop, proved in F*
/// as `run_start`); each method only performs its effect and reports the
/// outcome.
struct StartIo<'a> {
    state: &'a AppState,
    body: StartRequest,
    ip: String,
    session_id: Option<Uuid>,
    error: Option<AppError>,
}

impl StartIo<'_> {
    async fn check_rate_limit(&mut self) -> StartLimitObservation {
        match rate_limit::web_session_start_by_ip(&self.state.store, &self.ip) {
            Ok(()) => StartLimitObservation::Allowed,
            Err(error) => {
                self.error = Some(error);
                StartLimitObservation::Limited
            }
        }
    }

    async fn validate_start(&mut self) -> StartValidationObservation {
        let fail = |this: &mut Self, error: AppError| {
            this.error = Some(error);
            StartValidationObservation::Invalid
        };
        if let Err(error) = decode_exact(&self.body.ephemeral_pk, EPHEMERAL_PK_LEN, "ephemeral_pk")
        {
            return fail(self, error);
        }
        if let Err(error) = decode_exact(&self.body.link_nonce, LINK_NONCE_LEN, "link_nonce") {
            return fail(self, error);
        }
        if let Err(error) = decode_exact(
            &self.body.poll_secret_hash,
            POLL_SECRET_HASH_LEN,
            "poll_secret_hash",
        ) {
            return fail(self, error);
        }
        if let Some(ref vk) = self.body.web_vk {
            if let Err(error) = decode_exact(vk, WEB_VK_LEN, "web_vk") {
                return fail(self, error);
            }
        }
        StartValidationObservation::Valid
    }

    /// The committed approver is stored verbatim and never checked against the
    /// `users` table: this endpoint is unauthenticated, so confirming that an
    /// account exists would turn it into a user-enumeration oracle. A typo
    /// simply yields a session nobody can grant, which expires in 5 minutes.
    async fn insert_pending(&mut self) -> StartInsertObservation {
        let id = Uuid::new_v4();
        let now = Utc::now().to_rfc3339();
        match self
            .state
            .sqldb
            .execute(
                "INSERT INTO web_sessions
                    (id, user_id, approver_user_id, poll_secret_hash, ephemeral_pk, web_vk, link_nonce, mode, status, capsule, approved_by, created_at, expires_at)
                 VALUES (?, NULL, ?, ?, ?, ?, ?, NULL, 'pending', NULL, NULL, ?, NULL)",
                vec![
                    TursoValue::Text(id.to_string()),
                    TursoValue::Text(self.body.approver_user_id.to_string()),
                    TursoValue::Text(self.body.poll_secret_hash.clone()),
                    TursoValue::Text(self.body.ephemeral_pk.clone()),
                    TursoValue::Text(self.body.web_vk.as_deref().unwrap_or("").to_string()),
                    TursoValue::Text(self.body.link_nonce.clone()),
                    TursoValue::Text(now),
                ],
            )
            .await
        {
            Ok(_) => {
                self.session_id = Some(id);
                StartInsertObservation::Inserted
            }
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                StartInsertObservation::Failed
            }
        }
    }
}

fn start_failure_error(failure: StartFailure, io: &mut StartIo<'_>) -> AppError {
    match failure {
        StartFailure::RateLimited | StartFailure::Validation | StartFailure::InsertStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("web session start failed".into())),
    }
}

pub async fn post_start(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<StartRequest>,
) -> Result<Json<StartResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    let mut io = StartIo {
        state: &state,
        body,
        ip,
        session_id: None,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed.
    let transition = vela_session_policy::websession_start_interpreter!(io, await);

    match transition.effect {
        StartEffect::Complete => {
            let id = io
                .session_id
                .ok_or_else(|| AppError::Internal("web session start lost its id".into()))?;
            tracing::info!(session_id = %id, "web session started (pending)");
            Ok(Json(StartResponse { session_id: id }))
        }
        StartEffect::Fail(failure) => Err(start_failure_error(failure, &mut io)),
        _ => Err(AppError::Internal(
            "web session start driver reached no verdict".into(),
        )),
    }
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

/// M25: the expiry decision lives in the verified policy layer; the
/// handler converts the stored timestamp to unix seconds.
fn is_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    vela_session_policy::web_session_expired(
        Utc::now().timestamp(),
        expires_at.map(|e| e.timestamp()),
    )
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
    Ok((
        headers,
        Json(KeysResponse {
            ephemeral_pk,
            web_vk,
        }),
    ))
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

/// The I/O behind each grant effect. The driver decides which method runs and
/// when (through the shared `websession_grant_interpreter!` loop, proved in F*
/// as `run_grant`); each method only performs its effect and reports the
/// outcome.
struct GrantIo<'a> {
    state: &'a AppState,
    id: Uuid,
    session: DeviceSession,
    body: GrantRequest,
    expires_at: Option<DateTime<Utc>>,
    error: Option<AppError>,
}

impl GrantIo<'_> {
    async fn validate_grant(&mut self) -> vela_session_policy::websession_driver::GrantValidationObservation {
        use vela_session_policy::websession_driver::GrantValidationObservation;
        let invalid = |this: &mut Self, error: AppError| {
            this.error = Some(error);
            GrantValidationObservation::Invalid
        };
        match self.body.mode.as_str() {
            "ro" | "rw" => {}
            _ => {
                return invalid(
                    self,
                    AppError::BadRequest("mode must be 'ro' or 'rw'".into()),
                )
            }
        }
        if self.body.key_epoch < 1 {
            return invalid(
                self,
                AppError::BadRequest("key_epoch must be positive".into()),
            );
        }
        let capsule_bytes = match B64.decode(self.body.capsule.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                return invalid(
                    self,
                    AppError::BadRequest("capsule is not valid base64".into()),
                )
            }
        };
        if capsule_bytes.is_empty() || capsule_bytes.len() > MAX_CAPSULE_BYTES {
            return invalid(
                self,
                AppError::BadRequest(format!(
                    "capsule must be 1..={MAX_CAPSULE_BYTES} bytes"
                )),
            );
        }
        GrantValidationObservation::Valid
    }

    async fn grant_load_session(&mut self) -> GrantLookupObservation {
        let existing = match load_session(self.state, self.id).await {
            Ok(existing) => existing,
            Err(AppError::NotFound(_)) => return GrantLookupObservation::Absent,
            Err(error) => {
                self.error = Some(error);
                return GrantLookupObservation::QueryFailed;
            }
        };
        // The nonce comparison is the handler's existing constant-time check.
        // A missing or malformed nonce is represented as a zero-length,
        // unequal observation, which the checked policy refuses.
        let given_nonce = B64
            .decode(self.body.link_nonce.as_bytes())
            .unwrap_or_default();
        let stored_nonce = existing
            .link_nonce
            .as_deref()
            .and_then(|s| B64.decode(s.as_bytes()).ok());
        let nonce_equal = match stored_nonce {
            Some(stored) => given_nonce.len() == LINK_NONCE_LEN && ct_eq(&given_nonce, &stored),
            None => false,
        };
        GrantLookupObservation::Present(GrantObservation {
            phase: match existing.status.as_str() {
                "pending" => PolicyPhase::Pending,
                "granted" => PolicyPhase::Granted,
                "revoked" => PolicyPhase::Revoked,
                _ => PolicyPhase::Expired,
            },
            mode: if self.body.mode == "rw" {
                PolicyMode::ReadWrite
            } else {
                PolicyMode::ReadOnly
            },
            approver_user: existing.approver_user_id.map(|user| user.as_u128()),
            authenticated_user: self.session.user_id.as_u128(),
            nonce_length: given_nonce.len(),
            nonce_equal,
            has_web_vk: existing.web_vk.is_some(),
            declared_epoch: self.body.key_epoch,
        })
    }

    async fn update_grant(&mut self, update: GrantUpdate) -> GrantUpdateObservation {
        let verified_mode = match update.mode {
            PolicyMode::ReadOnly => "ro",
            PolicyMode::ReadWrite => "rw",
        };
        let expires_at = Utc::now() + chrono::Duration::seconds(update.ttl_secs);
        let user = self.session.user_id.to_string();
        let device = self.session.device_id.to_string();
        let n = self
            .state
            .sqldb
            .execute(
                // `approver_user_id` is re-checked here so the binding also
                // holds against a concurrent grant, not just the read above.
                "UPDATE web_sessions
                 SET user_id = ?, mode = ?, status = 'granted', capsule = ?,
                     approved_by = ?, expires_at = ?,
                     key_epoch = ?
                 WHERE id = ? AND status = 'pending' AND approver_user_id = ?
                   AND EXISTS (
                       SELECT 1 FROM users
                       WHERE id = ? AND rekey_state IS NULL AND key_epoch = ?
                   )
                   -- A device being revoked cannot slip a grant past the
                   -- revocation cascade (see device::revoke).
                   AND EXISTS (
                       SELECT 1 FROM devices
                       WHERE id = ? AND user_id = ? AND revoked = 0
                   )",
                vec![
                    TursoValue::Text(user.clone()),
                    TursoValue::Text(verified_mode.to_string()),
                    TursoValue::Text(self.body.capsule.clone()),
                    TursoValue::Text(device.clone()),
                    TursoValue::Text(expires_at.to_rfc3339()),
                    TursoValue::Integer(update.epoch),
                    TursoValue::Text(self.id.to_string()),
                    TursoValue::Text(user.clone()),
                    TursoValue::Text(user.clone()),
                    TursoValue::Integer(update.epoch),
                    TursoValue::Text(device),
                    TursoValue::Text(user),
                ],
            )
            .await;
        match n {
            Ok(0) => GrantUpdateObservation::Conflict,
            Ok(_) => {
                self.expires_at = Some(expires_at);
                GrantUpdateObservation::Updated
            }
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                GrantUpdateObservation::Failed
            }
        }
    }
}

fn grant_failure_error(failure: GrantFailure, io: &mut GrantIo<'_>) -> AppError {
    match failure {
        GrantFailure::Unauthenticated => AppError::Forbidden(
            "web session grant capability facts are inconsistent".into(),
        ),
        GrantFailure::Validation => io
            .error
            .take()
            .unwrap_or_else(|| AppError::BadRequest("invalid grant request".into())),
        GrantFailure::NotFound => AppError::NotFound("web session not found".into()),
        GrantFailure::LookupStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("web session lookup failed".into())),
        GrantFailure::NotPending => AppError::Conflict(
            "web session is not pending (already granted or revoked)".into(),
        ),
        GrantFailure::CrossAccount => AppError::Forbidden(
            "this web request was started for a different VELA account".into(),
        ),
        GrantFailure::NonceMismatch => AppError::Unauthorized(
            "link_nonce mismatch — scanned QR does not match this session".into(),
        ),
        GrantFailure::MissingWebVk => AppError::BadRequest(
            "rw grant requires the browser to have registered web_vk at start".into(),
        ),
        GrantFailure::InconsistentFacts => AppError::Forbidden(
            "web session grant capability facts are inconsistent".into(),
        ),
        GrantFailure::Conflict => AppError::Conflict(
            "web session was not pending, its vault key epoch changed, or the approving device was revoked".into(),
        ),
        GrantFailure::UpdateStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("web session grant failed".into())),
    }
}

pub async fn post_grant(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: DeviceSession,
    Json(body): Json<GrantRequest>,
) -> Result<(HeaderMap, Json<GrantResponse>)> {
    let actor = GrantActorObservation {
        authenticated: true,
        device_active: true,
    };
    let requested_ttl = body.ttl_secs;
    let mut io = GrantIo {
        state: &state,
        id,
        session,
        body,
        expires_at: None,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed.
    let transition =
        vela_session_policy::websession_grant_interpreter!(io, actor, requested_ttl, await);

    match transition.effect {
        GrantEffect::Complete => {
            let expires_at = io
                .expires_at
                .ok_or_else(|| AppError::Internal("web session grant lost its expiry".into()))?;
            tracing::info!(
                session_id = %id,
                user_id = %io.session.user_id,
                mode = %io.body.mode,
                ttl = %transition.driver.ttl_secs,
                "web session granted"
            );
            let mut headers = HeaderMap::new();
            maybe_append_new_token(&mut headers, &io.session);
            Ok((
                headers,
                Json(GrantResponse {
                    granted: true,
                    expires_at,
                }),
            ))
        }
        GrantEffect::Fail(failure) => Err(grant_failure_error(failure, &mut io)),
        _ => Err(AppError::Internal(
            "web session grant driver reached no verdict".into(),
        )),
    }
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

/// The I/O behind each token effect. The driver decides which method runs and
/// when (through the shared `websession_token_interpreter!` loop, proved in F*
/// as `run_token`); each method only performs its effect and reports the
/// outcome.
struct TokenIo<'a> {
    state: &'a AppState,
    id: Uuid,
    id_str: String,
    ip: String,
    body: TokenRequest,
    user_id: Option<Uuid>,
    web_vk: Option<Vec<u8>>,
    session_expires_at: Option<DateTime<Utc>>,
    token: Option<String>,
    jti: Option<String>,
    error: Option<AppError>,
}

impl TokenIo<'_> {
    async fn check_token_limits(&mut self) -> TokenLimitObservation {
        // Both the budget and the backoff are scoped to the caller, not to the
        // session (red-team RT-2). The session id is in the QR and this
        // endpoint does not require the poll secret, so a shared scope let an
        // onlooker's three bad proofs lock the real browser out for the
        // session's lifetime. The per-session cap stays behind it as a
        // distributed-grind backstop.
        let result = rate_limit::web_session_token_by_ip_session(
            &self.state.store,
            &self.ip,
            &self.id_str,
        )
        .and_then(|()| {
            rate_limit::web_session_token_by_session(&self.state.store, &self.id_str)
        })
        .and_then(|()| {
            // The flat rate limit let a guesser keep trying the ephemeral-key
            // proof at a steady rate indefinitely. `/auth/verify` has had
            // exponential backoff on consecutive failures since the spec asked
            // for it; this proof is the same shape and now gets the same
            // treatment — keyed the same way too, on (ip, id) rather than on
            // id alone.
            let backoff_scope = format!("websession:token:{}:{}", self.ip, self.id_str);
            rate_limit::check_backoff(&self.state.store, &backoff_scope)
        });
        match result {
            Ok(()) => TokenLimitObservation::Allowed,
            Err(error) => {
                self.error = Some(error);
                TokenLimitObservation::Limited
            }
        }
    }

    async fn token_load_session(&mut self) -> TokenLookupObservation {
        let session = match load_session(self.state, self.id).await {
            Ok(session) => session,
            Err(AppError::NotFound(_)) => return TokenLookupObservation::Absent,
            Err(error) => {
                self.error = Some(error);
                return TokenLookupObservation::QueryFailed;
            }
        };
        let now = Utc::now().timestamp();
        let phase = match session.status.as_str() {
            "pending" => PolicyPhase::Pending,
            "granted" => PolicyPhase::Granted,
            "revoked" => PolicyPhase::Revoked,
            _ => PolicyPhase::Expired,
        };
        let mode = match session.mode.as_deref() {
            Some("rw") => PolicyMode::ReadWrite,
            _ => PolicyMode::ReadOnly,
        };
        let expires_at = session.expires_at.map(|e| e.timestamp());
        let eligible = matches!(phase, PolicyPhase::Granted)
            && matches!(mode, PolicyMode::ReadWrite)
            && expires_at.map(|expires| now < expires).unwrap_or(false)
            && session.user_id.is_some()
            && session.web_vk.is_some();
        // Decode the registered key only where the handler historically did:
        // after the status/mode/expiry/user checks and before the challenge
        // take. A malformed key is an internal error that must not spend the
        // nonce.
        if eligible {
            if let Some(ref web_vk_b64) = session.web_vk {
                match B64.decode(web_vk_b64.as_bytes()) {
                    Ok(bytes) => self.web_vk = Some(bytes),
                    Err(error) => {
                        self.error = Some(AppError::Internal(format!("web_vk decode: {error}")));
                        return TokenLookupObservation::Malformed;
                    }
                }
            }
        }
        self.user_id = session.user_id;
        self.session_expires_at = session.expires_at;
        TokenLookupObservation::Present(TokenSessionObservation {
            phase,
            mode,
            granted_user: session.user_id.map(|user| user.as_u128()),
            approver_user: session.approver_user_id.map(|user| user.as_u128()),
            nonce_present: session.link_nonce.is_some(),
            web_vk_present: session.web_vk.is_some(),
            key_epoch: session.key_epoch.unwrap_or(1),
            now,
            expires_at,
        })
    }

    async fn consume_web_token_challenge(&mut self) -> TokenChallengeObservation {
        // Single-use challenge issued by `/auth/challenge?purpose=web_token`.
        // `take_challenge` removes the nonce whatever its purpose, so a
        // wrong-purpose presentation spends it.
        match crate::auth::challenge::take_challenge(
            self.state,
            &self.body.challenge,
            crate::auth::challenge::ChallengePurpose::WebToken,
        ) {
            Ok(consumption) => {
                TokenChallengeObservation::Observed(consumption)
            }
            Err(error) => {
                self.error = Some(error);
                TokenChallengeObservation::StorageFailed
            }
        }
    }

    async fn verify_web_signature(&mut self) -> TokenSignatureObservation {
        let challenge_bytes = match B64.decode(&self.body.challenge) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest(
                    "invalid challenge encoding".into(),
                ));
                return TokenSignatureObservation::InvalidChallengeEncoding;
            }
        };
        let Some(ref web_vk) = self.web_vk else {
            self.error = Some(AppError::Internal(
                "granted session lost its signing key".into(),
            ));
            return TokenSignatureObservation::Rejected;
        };
        match verify_auth_signature(
            web_vk,
            &challenge_bytes,
            &self.id_str,
            &self.body.signature,
        ) {
            Ok(()) => TokenSignatureObservation::Valid,
            Err(error) => {
                self.error = Some(error);
                TokenSignatureObservation::Rejected
            }
        }
    }

    async fn record_token_failure(&mut self) -> TokenFailureRecordObservation {
        let backoff_scope = format!("websession:token:{}:{}", self.ip, self.id_str);
        match rate_limit::record_backoff_failure(&self.state.store, &backoff_scope) {
            Ok(()) => TokenFailureRecordObservation::Recorded,
            Err(error) => {
                self.error = Some(error);
                TokenFailureRecordObservation::StorageFailed
            }
        }
    }

    async fn reset_token_backoff(&mut self) -> TokenResetObservation {
        let backoff_scope = format!("websession:token:{}:{}", self.ip, self.id_str);
        match rate_limit::reset_backoff(&self.state.store, &backoff_scope) {
            Ok(()) => TokenResetObservation::Reset {
                now: Utc::now().timestamp(),
            },
            Err(error) => {
                self.error = Some(error);
                TokenResetObservation::StorageFailed
            }
        }
    }

    /// First-writer-wins claim of the one token this grant may issue. A second
    /// valid proof with a fresh `web_token` nonce therefore cannot mint a
    /// second token for the same granted session.
    async fn claim_token(&mut self) -> TokenClaimObservation {
        match self.state.store.set_ex_nx(
            &format!("web_session:token_issued:{}", self.id_str),
            &[1u8],
            MAX_TTL_SECS as u64,
        ) {
            Ok(true) => TokenClaimObservation::Claimed,
            Ok(false) => TokenClaimObservation::AlreadyClaimed,
            Err(error) => {
                self.error = Some(error);
                TokenClaimObservation::StorageFailed
            }
        }
    }

    async fn issue_token(
        &mut self,
        plan: vela_session_policy::TokenPlan,
    ) -> TokenIssueObservation {
        let Some(user_id) = self.user_id else {
            self.error = Some(AppError::Internal(
                "granted session lost its account".into(),
            ));
            return TokenIssueObservation::Failed;
        };
        let ts = TokenService::new(self.state.paseto_sk.clone(), self.state.paseto_pk.clone());
        // device_id = session_id; hard_cap = session expiry, so renewals never
        // outlive the granted TTL and revocation via
        // `device:revoked:<session_id>` applies.
        match ts.issue_from_plan(user_id, self.id, plan) {
            Ok((token, jti)) => {
                // `DELETE /web-session/:id` and the approving-device
                // revocation cascade write `device:revoked:<session_id>`
                // *before* the SQL row flips. An exchange that observed the
                // granted row before that lockout must not release a token
                // after it: re-check the sentinel at the point of issue and
                // fail closed on a storage error too. This is the
                // composition proof's issue-time lockout guard.
                match self.state.store.exists(&format!("device:revoked:{}", self.id)) {
                    Ok(false) => {}
                    Ok(true) => {
                        self.error = Some(AppError::Unauthorized(
                            "web session was revoked during token issuance".into(),
                        ));
                        return TokenIssueObservation::Failed;
                    }
                    Err(error) => {
                        self.error = Some(error);
                        return TokenIssueObservation::Failed;
                    }
                }
                // Track the JTI before the driver may respond. A tracking
                // failure is a failed exchange, exactly as the historical
                // separate step was.
                match rate_limit::track_device_jti(&self.state.store, &self.id_str, &jti) {
                    Ok(()) => {
                        self.token = Some(token);
                        self.jti = Some(jti);
                        TokenIssueObservation::Issued
                    }
                    Err(error) => {
                        self.error = Some(error);
                        TokenIssueObservation::Failed
                    }
                }
            }
            Err(error) => {
                self.error = Some(error);
                TokenIssueObservation::Failed
            }
        }
    }
}

fn token_failure_error(failure: TokenFailure, io: &mut TokenIo<'_>) -> AppError {
    match failure {
        TokenFailure::RateLimited => io
            .error
            .take()
            .unwrap_or_else(|| AppError::RateLimited("too many attempts".into())),
        TokenFailure::NotFound => AppError::NotFound("web session not found".into()),
        TokenFailure::LookupStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("web session lookup failed".into())),
        TokenFailure::NotGranted => {
            AppError::Unauthorized("web session is not active".into())
        }
        TokenFailure::ReadOnly => AppError::BadRequest("session is read-only".into()),
        TokenFailure::Expired => AppError::Unauthorized("web session expired".into()),
        TokenFailure::MissingExpiry => {
            AppError::Internal("granted session missing expiry".into())
        }
        TokenFailure::MissingUser => {
            AppError::Internal("granted session missing user".into())
        }
        TokenFailure::MissingSigningKey => {
            AppError::Unauthorized("session has no signing key".into())
        }
        TokenFailure::MissingGrantFields => AppError::Unauthorized(
            "web session capability facts are inconsistent".into(),
        ),
        TokenFailure::MalformedSession => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("web session row could not be decoded".into())),
        TokenFailure::ChallengeMissing => {
            AppError::Unauthorized("challenge not found or already used".into())
        }
        TokenFailure::ChallengeWrongPurpose => AppError::Unauthorized(
            "challenge was issued for a different purpose".into(),
        ),
        TokenFailure::ChallengeStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("challenge lookup failed".into())),
        TokenFailure::InvalidChallengeEncoding => io
            .error
            .take()
            .unwrap_or_else(|| AppError::BadRequest("invalid challenge encoding".into())),
        TokenFailure::SignatureRejected => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Unauthorized("signature verification failed".into())),
        TokenFailure::FailureRecordStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("failure counter update failed".into())),
        TokenFailure::BackoffResetStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("backoff reset failed".into())),
        TokenFailure::AlreadyIssued => AppError::Conflict(
            "web session has already issued the token for this grant".into(),
        ),
        TokenFailure::ClaimStorage => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("token claim failed".into())),
        TokenFailure::IssueFailed => io
            .error
            .take()
            .unwrap_or_else(|| AppError::Internal("token issuance failed".into())),
        TokenFailure::InconsistentFacts => AppError::Unauthorized(
            "web session capability facts are inconsistent".into(),
        ),
    }
}

pub async fn post_token(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<TokenRequest>,
) -> Result<Json<TokenResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    let mut io = TokenIo {
        state: &state,
        id,
        id_str: id.to_string(),
        ip,
        body,
        user_id: None,
        web_vk: None,
        session_expires_at: None,
        token: None,
        jti: None,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed.
    let transition = vela_session_policy::websession_token_interpreter!(io, await);

    match transition.effect {
        TokenEffect::Complete => {
            let token = io
                .token
                .take()
                .ok_or_else(|| AppError::Internal("web session token lost its token".into()))?;
            let user_id = io
                .user_id
                .ok_or_else(|| AppError::Internal("web session token lost its user".into()))?;
            let expires_at = io.session_expires_at.ok_or_else(|| {
                AppError::Internal("granted session missing expiry".into())
            })?;
            tracing::info!(session_id = %id, user_id = %user_id, "web session rw token issued");
            Ok(Json(TokenResponse {
                token,
                user_id: user_id.to_string(),
                expires_at,
            }))
        }
        TokenEffect::Fail(failure) => Err(token_failure_error(failure, &mut io)),
        _ => Err(AppError::Internal(
            "web session token driver reached no verdict".into(),
        )),
    }
}

// ── DELETE /web-session/:id (revoke) ────────────────────────────────────────────

/// The I/O behind each delete effect. The driver decides which method runs and
/// when (through the shared `websession_delete_interpreter!` loop, proved in F*
/// as `run_delete`); each method only performs its effect and reports the
/// outcome.
struct DeleteSessionIo<'a> {
    state: &'a AppState,
    id: Uuid,
    error: Option<AppError>,
}

impl DeleteSessionIo<'_> {
    async fn delete_load_session(&mut self) -> DeleteLookupObservation {
        match load_session(self.state, self.id).await {
            Ok(session) => DeleteLookupObservation::Present(
                vela_session_policy::websession_driver::DeleteSessionFacts {
                    session_user: session.user_id.map(|user| user.as_u128()),
                    approver_user: session.approver_user_id.map(|user| user.as_u128()),
                },
            ),
            Err(AppError::NotFound(_)) => DeleteLookupObservation::Absent,
            Err(error) => {
                self.error = Some(error);
                DeleteLookupObservation::QueryFailed
            }
        }
    }

    /// Reject any already-issued RW token (device_id == session_id) before the
    /// SQL audit row says the session is revoked. If SQL subsequently fails,
    /// the safe partial state is locked-out-but-visible, not marked-but-live.
    async fn lockout_session(&mut self) -> DeleteSentinelObservation {
        match self.state.store.set_ex(
            &format!("device:revoked:{}", self.id),
            &[1u8],
            MAX_TTL_SECS as u64,
        ) {
            Ok(()) => DeleteSentinelObservation::Applied,
            Err(error) => {
                self.error = Some(error);
                DeleteSentinelObservation::StorageFailed
            }
        }
    }

    async fn record_revocation(&mut self) -> DeleteRecordObservation {
        match self
            .state
            .sqldb
            .execute(
                "UPDATE web_sessions SET status = 'revoked', capsule = NULL WHERE id = ?",
                vec![TursoValue::Text(self.id.to_string())],
            )
            .await
        {
            Ok(_) => DeleteRecordObservation::Updated,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                DeleteRecordObservation::Failed
            }
        }
    }
}

fn delete_failure_error(failure: DeleteFailure, io: &mut DeleteSessionIo<'_>) -> AppError {
    match failure {
        DeleteFailure::Unauthenticated => AppError::Unauthorized("unauthorized".into()),
        DeleteFailure::NotFound => AppError::NotFound("web session not found".into()),
        DeleteFailure::LookupStorage | DeleteFailure::LockoutStorage | DeleteFailure::RecordStorage => {
            io.error
                .take()
                .unwrap_or_else(|| AppError::Internal("web session revocation failed".into()))
        }
    }
}

pub async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let actor_user = session.user_id.as_u128();
    let mut io = DeleteSessionIo {
        state: &state,
        id,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed.
    let transition = vela_session_policy::websession_delete_interpreter!(
        io,
        vela_session_policy::websession_driver::DeleteActorObservation {
            authenticated: true,
            user: actor_user,
        },
        await
    );

    match transition.effect {
        DeleteEffect::Complete => {
            tracing::info!(session_id = %id, user_id = %session.user_id, "web session revoked");
            let mut headers = HeaderMap::new();
            maybe_append_new_token(&mut headers, &session);
            Ok((headers, Json(serde_json::json!({ "revoked": true }))))
        }
        DeleteEffect::Fail(failure) => Err(delete_failure_error(failure, &mut io)),
        _ => Err(AppError::Internal(
            "web session delete driver reached no verdict".into(),
        )),
    }
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
