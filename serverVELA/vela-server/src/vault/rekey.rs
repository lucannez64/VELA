//! Vault re-keying endpoints — the server half of RMS rotation.
//!
//! Spec: `docs/VAULT_REKEYING_DESIGN.md`. The server's role is deliberately
//! small and blind: it tracks a per-account **key epoch** and a two-phase
//! rotation state, enforces which epoch may write where, relays KEM-sealed
//! capsules it cannot open, and sweeps superseded shadow rows at commit. It
//! never sees a seed or any derived key.
//!
//! State machine (`users.rekey_state`):
//!
//! ```text
//!                     start                commit
//!   ACTIVE(N) ───────────────▶ FREEZING(N+1) ───────▶ ACTIVE(N+1)
//!       ▲                          │
//!       └──── abort / timeout ─────┘
//! ```
//!
//! Every handler takes [`DeviceSession`], not `AuthSession`: rotation changes
//! account authority, so an ephemeral web-session token must never reach it —
//! that includes the scoped token this same rotation will invalidate
//! (red-team RT-5/RT-6).
//!
//! While `FREEZING`, writes are accepted only at epoch N+1 (the initiator's
//! re-keyed copies landing as shadow rows alongside the untouched epoch-N
//! rows); reads keep serving epoch N, because nobody has adopted yet. Commit
//! flips the epoch with an atomic completeness-checked compare-and-swap, then
//! sweeps rows which immediately became unreachable; abort/timeout uses the
//! competing CAS. Either way the account is never observable mid-mixed.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

/// How long an account may sit in `FREEZING` before the next state-observing
/// call rolls it back (design doc §5). Generous: a large vault re-encrypts at
/// network speed and the initiator may be on a slow uplink.
const REKEY_TIMEOUT_SECS: i64 = 900;

/// A row of the chunk inventory returned by `start`: everything the initiator
/// needs to download and re-encrypt one chunk.
#[derive(serde::Serialize)]
pub struct InventoryChunk {
    pub chunk_id: String,
    pub version: i64,
    pub lamport_clock: i64,
}

#[derive(serde::Serialize)]
pub struct EpochResponse {
    pub epoch: i64,
    /// `"active"` or `"freezing"`.
    pub state: &'static str,
}

#[derive(serde::Serialize)]
pub struct StartResponse {
    /// The epoch the caller must seal re-keyed chunks under.
    pub epoch: i64,
    /// Unique nonce for this particular N -> N+1 attempt. Every mutating
    /// request must echo it so delayed traffic from an aborted attempt cannot
    /// be accepted by a later attempt at the same epoch.
    pub rotation_id: String,
    pub chunks: Vec<InventoryChunk>,
}

#[derive(Deserialize)]
pub struct CapsulesRequest {
    /// `device_id -> base64(RMS capsule sealed to that device's hybrid_ek)`.
    pub capsules: HashMap<String, String>,
}

// ── state helpers ──────────────────────────────────────────────────────────────

struct KeyState {
    epoch: i64,
    freezing: bool,
    started_at: Option<String>,
    starter: Option<String>,
    rotation_id: Option<String>,
    last_rekey_id: Option<String>,
    last_rekey_epoch: Option<i64>,
}

async fn load_key_state(state: &AppState, user_id: &str) -> Result<KeyState> {
    let rows = state
        .sqldb
        .query(
            "SELECT key_epoch, rekey_state, rekey_started_at, rekey_starter, rekey_id,
                    last_rekey_id, last_rekey_epoch
             FROM users WHERE id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound("account not found".into()))?;
    let text = |col: usize| -> Option<String> {
        match row.get(col) {
            Some(TursoValue::Text(s)) => Some(s.clone()),
            _ => None,
        }
    };
    Ok(KeyState {
        epoch: row.i64(0).unwrap_or(1).max(1),
        freezing: text(1).as_deref() == Some("freezing"),
        started_at: text(2),
        starter: text(3),
        rotation_id: text(4),
        last_rekey_id: text(5),
        last_rekey_epoch: row.i64(6),
    })
}

/// Lazily roll back a `FREEZING` account whose initiator went silent past the
/// timeout. Called on every state-observing path, so no scheduler exists:
/// the next touch of the account cleans it up (design doc §5).
async fn maybe_rollback(state: &AppState, user_id: &str, ks: &KeyState) -> Result<KeyState> {
    if !ks.freezing {
        return Ok(KeyState {
            epoch: ks.epoch,
            freezing: false,
            started_at: ks.started_at.clone(),
            starter: ks.starter.clone(),
            rotation_id: ks.rotation_id.clone(),
            last_rekey_id: ks.last_rekey_id.clone(),
            last_rekey_epoch: ks.last_rekey_epoch,
        });
    }
    let expired = ks
        .started_at
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| (Utc::now().signed_duration_since(t)).num_seconds() > REKEY_TIMEOUT_SECS)
        .unwrap_or(true);
    if !expired {
        return Ok(ks.clone_state());
    }
    tracing::warn!(user_id = %user_id, "re-key timed out; rolling back to epoch {}", ks.epoch);
    let rotation_id = ks.rotation_id.as_deref().unwrap_or_default();
    if !rollback_rekey(state, user_id, ks.epoch, rotation_id).await? {
        // A commit or explicit abort won the transition while this request was
        // deciding the timeout. Return the state which actually won.
        return load_key_state(state, user_id).await;
    }
    Ok(KeyState {
        epoch: ks.epoch,
        freezing: false,
        started_at: None,
        starter: None,
        rotation_id: None,
        last_rekey_id: ks.last_rekey_id.clone(),
        last_rekey_epoch: ks.last_rekey_epoch,
    })
}

impl KeyState {
    fn clone_state(&self) -> KeyState {
        KeyState {
            epoch: self.epoch,
            freezing: self.freezing,
            started_at: self.started_at.clone(),
            starter: self.starter.clone(),
            rotation_id: self.rotation_id.clone(),
            last_rekey_id: self.last_rekey_id.clone(),
            last_rekey_epoch: self.last_rekey_epoch,
        }
    }
}

/// Atomically win the transition out of FREEZING before deleting shadows.
/// This is shared by explicit abort and lazy timeout rollback so neither can
/// race a successful commit and delete the newly-authoritative epoch.
async fn rollback_rekey(
    state: &AppState,
    user_id: &str,
    epoch: i64,
    rotation_id: &str,
) -> Result<bool> {
    // Keep the state transition and shadow cleanup on one pinned transaction.
    // Otherwise a new `start` can enter FREEZING after the UPDATE and have its
    // fresh N+1 shadows deleted by the previous abort's cleanup statement.
    let tx = state
        .sqldb
        .tx()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let updated = tx
        .execute(
            "UPDATE users SET rekey_state = NULL, rekey_started_at = NULL,
                    rekey_starter = NULL, rekey_id = NULL
                 WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
                   AND rekey_id = ?",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Integer(epoch),
                TursoValue::Text(rotation_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated == 1 {
        tx.execute(
            "DELETE FROM vault_chunks WHERE user_id = ? AND epoch > ?",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Integer(epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        // Capsules are attempt output too. Removing them in the same
        // transition prevents their epoch tag from satisfying the next
        // attempt's completeness check at the same N -> N+1 boundary.
        tx.execute(
            "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
             WHERE user_id = ? AND rms_capsule_epoch = ?",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Integer(epoch + 1),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(updated == 1)
}

/// The write-side guard (`PUT /vault/chunk`, ORAM writes): resolve which epoch
/// this request's ciphertext belongs in, rejecting anything else (§5).
///
/// Returns `(write_epoch, read_epoch)` — they differ only while freezing, when
/// reads still serve the pre-rotation world to devices that have not adopted.
///
/// A missing header reads as the current active epoch while the fleet upgrades;
/// once clients universally send it, the tolerance can be dropped by flipping
/// the `legacy_ok` branch to an error.
pub async fn resolve_write_epoch(
    state: &AppState,
    user_id: &str,
    declared: Option<i64>,
) -> Result<(i64, i64)> {
    let ks = maybe_rollback(state, user_id, &load_key_state(state, user_id).await?).await?;
    if ks.freezing {
        // Shadow writes only: the re-keyed copy of a chunk at the NEXT epoch.
        match declared {
            Some(e) if e == ks.epoch + 1 => Ok((ks.epoch + 1, ks.epoch)),
            _ => Err(AppError::Rekeyed(format!(
                "a re-key is in progress; writes require epoch {}",
                ks.epoch + 1
            ))),
        }
    } else {
        match declared {
            Some(e) if e == ks.epoch => Ok((ks.epoch, ks.epoch)),
            // Headerless writes are tolerated only for pre-rekey accounts.
            // After epoch 1 they are indistinguishable from an offline client
            // encrypting with a retired RMS, so accepting them would let stale
            // ciphertext overwrite the rotated vault.
            None if ks.epoch == 1 => Ok((ks.epoch, ks.epoch)),
            _ => Err(AppError::Rekeyed(format!(
                "epoch mismatch: account is at {}; re-sync and adopt before writing",
                ks.epoch
            ))),
        }
    }
}

/// Shadow ciphertext is account-authority work, not ordinary vault access.
/// Only the real device which started the freeze may populate or replace it;
/// in particular, an outstanding RW web-session token must not be able to
/// poison rows which commit will make authoritative.
pub async fn ensure_shadow_writer(
    state: &AppState,
    session: &AuthSession,
    write_epoch: i64,
    read_epoch: i64,
    rotation_id: Option<&str>,
) -> Result<()> {
    if write_epoch == read_epoch {
        return Ok(());
    }
    if session.scope != crate::auth::token::TokenScope::Device {
        return Err(AppError::Forbidden(
            "temporary web sessions cannot write re-key shadows".into(),
        ));
    }
    if rotation_id.is_none() {
        return Err(AppError::BadRequest(
            "X-Vela-Rekey-Id header is required for shadow writes".into(),
        ));
    }
    let ks = load_key_state(state, &session.user_id.to_string()).await?;
    if !ks.freezing
        || ks.epoch + 1 != write_epoch
        || ks.starter.as_deref() != Some(session.device_id.to_string().as_str())
        || ks.rotation_id.as_deref() != rotation_id
    {
        return Err(AppError::Forbidden(
            "only the device which started this re-key may write shadows".into(),
        ));
    }
    Ok(())
}

/// Refresh the inactivity deadline after a shadow write actually succeeded.
/// Failed or deliberately malformed requests must not keep an account frozen.
pub async fn record_shadow_activity(
    state: &AppState,
    session: &AuthSession,
    write_epoch: i64,
    read_epoch: i64,
    rotation_id: Option<&str>,
) -> Result<()> {
    if write_epoch == read_epoch {
        return Ok(());
    }
    let refreshed = state
        .sqldb
        .execute(
            "UPDATE users SET rekey_started_at = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
               AND rekey_starter = ? AND rekey_id = ?",
            vec![
                TursoValue::Text(Utc::now().to_rfc3339()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(read_epoch),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(rotation_id.unwrap_or_default().to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if refreshed != 1 {
        tracing::debug!(
            user_id = %session.user_id,
            "shadow write completed as the re-key transition ended"
        );
    }
    Ok(())
}

/// The read-side filter: chunks at or below the served epoch exist; callers
/// filter their queries with this value.
pub async fn read_epoch(state: &AppState, user_id: &str) -> Result<i64> {
    let ks = maybe_rollback(state, user_id, &load_key_state(state, user_id).await?).await?;
    Ok(ks.epoch)
}

fn ensure_starter(ks: &KeyState, session: &AuthSession) -> Result<()> {
    if ks.starter.as_deref() != Some(session.device_id.to_string().as_str()) {
        return Err(AppError::Forbidden(
            "this re-key was started by another device".into(),
        ));
    }
    Ok(())
}

fn require_rotation_id<'a>(headers: &'a HeaderMap, ks: &KeyState) -> Result<&'a str> {
    let supplied = headers
        .get("x-vela-rekey-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("X-Vela-Rekey-Id header is required".into()))?;
    if ks.rotation_id.as_deref() != Some(supplied) {
        return Err(AppError::Conflict(
            "this request belongs to a different re-key attempt".into(),
        ));
    }
    Ok(supplied)
}

// ── GET /vault/epoch ───────────────────────────────────────────────────────────

pub async fn get_epoch(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<EpochResponse>)> {
    let user_id = session.user_id.to_string();
    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(EpochResponse {
            epoch: ks.epoch,
            state: if ks.freezing { "freezing" } else { "active" },
        }),
    ))
}

// ── POST /vault/rekey/start ────────────────────────────────────────────────────

pub async fn post_start(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<StartResponse>)> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    if ks.freezing {
        return Err(AppError::Conflict(
            "a re-key is already in progress for this account".into(),
        ));
    }

    // This implementation rotates chunked vault data only. Existing ORAM
    // buckets are RMS-derived too, so advancing the account epoch without
    // migrating them would make every bucket disappear from reads. Refuse the
    // operation until an ORAM shadow/migration protocol exists.
    let oram = state
        .sqldb
        .query(
            "SELECT 1 FROM oram_buckets WHERE user_id = ? LIMIT 1",
            vec![TursoValue::Text(user_id.clone())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !oram.is_empty() {
        return Err(AppError::Conflict(
            "vault key rotation is unavailable while ORAM buckets exist".into(),
        ));
    }

    // A capsule is useful only when its target retained the matching private
    // key and has an adoption implementation. Unknown/legacy devices default
    // false and block rotation rather than being permanently stranded.
    let incapable = state
        .sqldb
        .query(
            "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0 AND rekey_capable = 0 LIMIT 1",
            vec![TursoValue::Text(user_id.clone())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !incapable.is_empty() {
        return Err(AppError::Conflict(
            "vault key rotation requires every active device to sync once with a re-key-capable client; re-enroll legacy devices first".into(),
        ));
    }

    let next = ks.epoch + 1;

    // The inventory must be captured inside the same transaction as the
    // freeze CAS. Taken separately, a concurrent same-account write could
    // land between them: a new chunk would get no shadow (wedging commit's
    // completeness check until abort) and an updated chunk would be
    // re-encrypted from its stale version and swept at commit — an
    // acknowledged write silently lost.
    let tx = state
        .sqldb
        .tx()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let inventory = tx
        .query(
            "SELECT chunk_id, version, lamport_clock FROM vault_chunks
             WHERE user_id = ? AND epoch = ? ORDER BY chunk_id",
            vec![
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(ks.epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut chunks = Vec::new();
    for row in inventory.iter() {
        chunks.push(InventoryChunk {
            chunk_id: match row.get(0) {
                Some(TursoValue::Text(s)) => s.clone(),
                _ => continue,
            },
            version: row.i64(1).unwrap_or(1),
            lamport_clock: row.i64(2).unwrap_or(0),
        });
    }

    let rotation_id = uuid::Uuid::new_v4().to_string();
    let updated = tx
        .execute(
            "UPDATE users SET rekey_state = 'freezing', rekey_started_at = ?,
                rekey_starter = ?, rekey_id = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM oram_buckets WHERE user_id = users.id
               )",
            vec![
                TursoValue::Text(Utc::now().to_rfc3339()),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(rotation_id.clone()),
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(ks.epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated != 1 {
        return Err(AppError::Conflict(
            "a re-key was started concurrently for this account".into(),
        ));
    }
    // Cleanup must happen only after this transaction wins the freeze CAS.
    // A pre-CAS delete based on stale state can race a concurrent commit and
    // erase the epoch that just became authoritative.
    tx.execute(
        "DELETE FROM vault_chunks WHERE user_id = ? AND epoch != ?",
        vec![
            TursoValue::Text(user_id.clone()),
            TursoValue::Integer(ks.epoch),
        ],
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(
        user_id = %user_id,
        from_epoch = ks.epoch,
        to_epoch = next,
        chunks = chunks.len(),
        "re-key started"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(StartResponse {
            epoch: next,
            rotation_id,
            chunks,
        }),
    ))
}

// ── POST /vault/rekey/capsules ─────────────────────────────────────────────────

pub async fn post_capsules(
    State(state): State<AppState>,
    session: DeviceSession,
    headers: HeaderMap,
    Json(body): Json<CapsulesRequest>,
) -> Result<(HeaderMap, StatusCode)> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    if !ks.freezing {
        return Err(AppError::Conflict("no re-key is in progress".into()));
    }
    ensure_starter(&ks, &session)?;
    require_rotation_id(&headers, &ks)?;
    if body.capsules.len() > 64 {
        return Err(AppError::BadRequest("too many capsules".into()));
    }

    for (device_id, capsule_b64) in &body.capsules {
        let capsule = crate::db::decode_b64(capsule_b64)?;
        if capsule.is_empty() || capsule.len() > 64 * 1024 {
            return Err(AppError::BadRequest(format!(
                "capsule for {device_id} has an invalid size"
            )));
        }
        let rows = state
            .sqldb
            .execute(
                "UPDATE devices SET rms_capsule = ?, rms_capsule_epoch = ?
                 WHERE id = ? AND user_id = ? AND revoked = 0
                   AND EXISTS (
                     SELECT 1 FROM users
                      WHERE users.id = devices.user_id
                        AND users.key_epoch = ?
                        AND users.rekey_state = 'freezing'
                        AND users.rekey_starter = ?
                        AND users.rekey_id = ?
                   )",
                vec![
                    TursoValue::Text(capsule_b64.clone()),
                    TursoValue::Integer(ks.epoch + 1),
                    TursoValue::Text(device_id.clone()),
                    TursoValue::Text(user_id.clone()),
                    TursoValue::Integer(ks.epoch),
                    TursoValue::Text(session.device_id.to_string()),
                    TursoValue::Text(
                        ks.rotation_id.as_deref().unwrap_or_default().to_string(),
                    ),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if rows == 0 {
            // Unknown, foreign, or revoked device: refuse rather than silently
            // skip — a silently missing capsule strands that device at the old
            // epoch with no way to adopt.
            return Err(AppError::BadRequest(format!(
                "capsule target is not an active device of this account: {device_id}"
            )));
        }
    }

    tracing::info!(
        user_id = %user_id,
        capsules = body.capsules.len(),
        "re-key capsules stored"
    );
    Ok(no_content(&session))
}

// ── POST /vault/rekey/commit ───────────────────────────────────────────────────

pub async fn post_commit(
    State(state): State<AppState>,
    session: DeviceSession,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode)> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    let new_epoch = ks.epoch + 1;
    if !ks.freezing {
        // Idempotent replay: if the caller targets the *current* epoch, its
        // commit already succeeded and only the response was lost. Answer
        // success instead of an error indistinguishable from "your rotation
        // failed", so crash recovery is unambiguous.
        let target_epoch = headers
            .get("X-Vela-Epoch")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok());
        let replay_id = headers
            .get("X-Vela-Rekey-Id")
            .and_then(|v| v.to_str().ok());
        if target_epoch == Some(ks.epoch)
            && ks.last_rekey_epoch == Some(ks.epoch)
            && replay_id.is_some()
            && replay_id == ks.last_rekey_id.as_deref()
        {
            tracing::info!(
                user_id = %user_id,
                epoch = ks.epoch,
                "re-key commit replayed after a lost response"
            );
            return Ok(no_content(&session));
        }
        return Err(AppError::Conflict(
            "no re-key is in progress".into(),
        ));
    }
    ensure_starter(&ks, &session)?;
    let rotation_id = require_rotation_id(&headers, &ks)?;

    // Never make N+1 authoritative unless it contains exactly one replacement
    // for every live N chunk and every active device has a capsule. The server
    // is blind to plaintext but can still enforce completeness structurally.
    let missing_chunks = state
        .sqldb
        .query(
            "SELECT 1 FROM vault_chunks old
             WHERE old.user_id = ? AND old.epoch = ?
               AND NOT EXISTS (
                 SELECT 1 FROM vault_chunks new
                 WHERE new.user_id = old.user_id
                   AND new.chunk_id = old.chunk_id
                   AND new.epoch = ?
               )
             LIMIT 1",
            vec![
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(ks.epoch),
                TursoValue::Integer(new_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !missing_chunks.is_empty() {
        return Err(AppError::Conflict(
            "cannot commit re-key: one or more chunk shadows are missing".into(),
        ));
    }
    let missing_capsules = state
        .sqldb
        .query(
            "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0
               AND (rekey_capable = 0 OR rms_capsule IS NULL OR rms_capsule_epoch != ?)
             LIMIT 1",
            vec![
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(new_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !missing_capsules.is_empty() {
        return Err(AppError::Conflict(
            "cannot commit re-key: one or more active devices has no capsule".into(),
        ));
    }

    // One atomic compare-and-swap both validates completeness and flips the
    // served epoch. A concurrent abort can only win or lose this statement;
    // it can never clear the state between validation and the flip.
    let updated = state
        .sqldb
        .execute(
            "UPDATE users SET key_epoch = ?, rekey_state = NULL,
             rekey_started_at = NULL, rekey_starter = NULL, rekey_id = NULL,
             last_rekey_id = ?, last_rekey_epoch = ?,
             recovery_share = NULL, recovery_auth_hash = NULL
         WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
           AND rekey_starter = ? AND rekey_id = ?
           AND NOT EXISTS (
             SELECT 1 FROM vault_chunks old
             WHERE old.user_id = users.id AND old.epoch = ?
               AND NOT EXISTS (
                 SELECT 1 FROM vault_chunks new
                 WHERE new.user_id = old.user_id
                   AND new.chunk_id = old.chunk_id AND new.epoch = ?
               )
           )
           AND NOT EXISTS (
             SELECT 1 FROM devices
             WHERE user_id = users.id AND revoked = 0
               AND (rekey_capable = 0 OR rms_capsule IS NULL OR rms_capsule_epoch != ?)
           )",
            vec![
                TursoValue::Integer(new_epoch),
                TursoValue::Text(rotation_id.to_string()),
                TursoValue::Integer(new_epoch),
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(ks.epoch),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(rotation_id.to_string()),
                TursoValue::Integer(ks.epoch),
                TursoValue::Integer(new_epoch),
                TursoValue::Integer(new_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated != 1 {
        return Err(AppError::Conflict(
            "re-key was aborted or committed concurrently".into(),
        ));
    }
    // Readers filter by users.key_epoch, so old rows became unreachable at the
    // CAS above. Cleanup is best-effort; failure wastes space but cannot expose
    // mixed epochs or make a successful commit look failed to the client.
    if let Err(e) = state
        .sqldb
        .execute(
            "DELETE FROM vault_chunks WHERE user_id = ? AND epoch < ?",
            vec![
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(new_epoch),
            ],
        )
        .await
    {
        tracing::warn!(user_id = %user_id, epoch = new_epoch, "failed to sweep superseded re-key rows: {e}");
    }

    tracing::info!(user_id = %user_id, epoch = new_epoch, "re-key committed");
    Ok(no_content(&session))
}

// ── POST /vault/rekey/abort ────────────────────────────────────────────────────

pub async fn post_abort(
    State(state): State<AppState>,
    session: DeviceSession,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode)> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    if !ks.freezing {
        return Err(AppError::Conflict("no re-key is in progress".into()));
    }
    ensure_starter(&ks, &session)?;
    let rotation_id = require_rotation_id(&headers, &ks)?;

    if !rollback_rekey(
        &state,
        &user_id,
        ks.epoch,
        rotation_id,
    )
    .await?
    {
        return Err(AppError::Conflict(
            "re-key was committed or aborted concurrently".into(),
        ));
    }

    tracing::info!(user_id = %user_id, epoch = ks.epoch, "re-key aborted");
    Ok(no_content(&session))
}

/// Modest per-account pacing for the rotation endpoints themselves. The heavy
/// traffic (chunk re-uploads) is already bounded by the ordinary chunk-write
/// limits; these calls are cheap but must not be free to spam.
fn rate_limit(state: &AppState, user_id: &str) -> Result<()> {
    crate::rate_limit::check(&state.store, &format!("rl:rekey:{user_id}"), 30, 3600)
}

fn no_content(session: &AuthSession) -> (HeaderMap, StatusCode) {
    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, session);
    (headers, StatusCode::NO_CONTENT)
}
