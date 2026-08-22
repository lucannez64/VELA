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
//! While `FREEZING`, writes are accepted only at epoch N+1 (the initiator's
//! re-keyed copies landing as shadow rows alongside the untouched epoch-N
//! rows); reads keep serving epoch N, because nobody has adopted yet. Commit
//! flips the epoch and sweeps in one transaction; abort/timeout drops the
//! shadows. Either way the account is never observable mid-mixed.

use axum::{
    extract::{State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
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
}

async fn load_key_state(state: &AppState, user_id: &str) -> Result<KeyState> {
    let rows = state
        .sqldb
        .query(
            "SELECT key_epoch, rekey_state, rekey_started_at, rekey_starter
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
    drop_shadow_rows(state, user_id, ks.epoch).await?;
    clear_rekey_state(state, user_id).await?;
    Ok(KeyState {
        epoch: ks.epoch,
        freezing: false,
        started_at: None,
        starter: None,
    })
}

impl KeyState {
    fn clone_state(&self) -> KeyState {
        KeyState {
            epoch: self.epoch,
            freezing: self.freezing,
            started_at: self.started_at.clone(),
            starter: self.starter.clone(),
        }
    }
}

async fn drop_shadow_rows(state: &AppState, user_id: &str, epoch: i64) -> Result<()> {
    state
        .sqldb
        .execute(
            "DELETE FROM vault_chunks WHERE user_id = ? AND epoch > ?",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Integer(epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

async fn clear_rekey_state(state: &AppState, user_id: &str) -> Result<()> {
    state
        .sqldb
        .execute(
            "UPDATE users SET rekey_state = NULL, rekey_started_at = NULL, rekey_starter = NULL
             WHERE id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
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
            None => Ok((ks.epoch, ks.epoch)),
            _ => Err(AppError::Rekeyed(format!(
                "epoch mismatch: account is at {}; re-sync and adopt before writing",
                ks.epoch
            ))),
        }
    }
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

// ── GET /vault/epoch ───────────────────────────────────────────────────────────

pub async fn get_epoch(
    State(state): State<AppState>,
    session: AuthSession,
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
    session: AuthSession,
) -> Result<(HeaderMap, Json<StartResponse>)> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    if ks.freezing {
        return Err(AppError::Conflict(
            "a re-key is already in progress for this account".into(),
        ));
    }

    let next = ks.epoch + 1;
    let inventory = state
        .sqldb
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

    state
        .sqldb
        .execute(
            "UPDATE users SET rekey_state = 'freezing', rekey_started_at = ?, rekey_starter = ?
             WHERE id = ? AND key_epoch = ?",
            vec![
                TursoValue::Text(Utc::now().to_rfc3339()),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(ks.epoch),
            ],
        )
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
    Ok((headers, Json(StartResponse { epoch: next, chunks })))
}

// ── POST /vault/rekey/capsules ─────────────────────────────────────────────────

pub async fn post_capsules(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<CapsulesRequest>,
) -> Result<StatusCode> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    if !ks.freezing {
        return Err(AppError::Conflict("no re-key is in progress".into()));
    }
    ensure_starter(&ks, &session)?;
    if body.capsules.len() > 64 {
        return Err(AppError::BadRequest("too many capsules".into()));
    }

    for (device_id, capsule_b64) in &body.capsules {
        let rows = state
            .sqldb
            .execute(
                "UPDATE devices SET rms_capsule = ?
                 WHERE id = ? AND user_id = ? AND revoked = 0",
                vec![
                    TursoValue::Text(capsule_b64.clone()),
                    TursoValue::Text(device_id.clone()),
                    TursoValue::Text(user_id.clone()),
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
    Ok(StatusCode::NO_CONTENT)
}

// ── POST /vault/rekey/commit ───────────────────────────────────────────────────

pub async fn post_commit(State(state): State<AppState>, session: AuthSession) -> Result<StatusCode> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    if !ks.freezing {
        return Err(AppError::Conflict("no re-key is in progress".into()));
    }
    ensure_starter(&ks, &session)?;
    let new_epoch = ks.epoch + 1;

    // One transaction: flip the epoch and sweep the superseded rows together,
    // so no reader ever observes the mixed state the sweep prevents.
    let tx = state
        .sqldb
        .tx()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    tx.execute(
        "UPDATE users SET key_epoch = ?, rekey_state = NULL,
             rekey_started_at = NULL, rekey_starter = NULL
         WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'",
        vec![
            TursoValue::Integer(new_epoch),
            TursoValue::Text(user_id.clone()),
            TursoValue::Integer(ks.epoch),
        ],
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    tx.execute(
        "DELETE FROM vault_chunks WHERE user_id = ? AND epoch < ?",
        vec![
            TursoValue::Text(user_id.clone()),
            TursoValue::Integer(new_epoch),
        ],
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(user_id = %user_id, epoch = new_epoch, "re-key committed");
    Ok(StatusCode::NO_CONTENT)
}

// ── POST /vault/rekey/abort ────────────────────────────────────────────────────

pub async fn post_abort(State(state): State<AppState>, session: AuthSession) -> Result<StatusCode> {
    let user_id = session.user_id.to_string();
    rate_limit(&state, &user_id)?;

    let ks = maybe_rollback(&state, &user_id, &load_key_state(&state, &user_id).await?).await?;
    if !ks.freezing {
        return Err(AppError::Conflict("no re-key is in progress".into()));
    }
    ensure_starter(&ks, &session)?;

    drop_shadow_rows(&state, &user_id, ks.epoch).await?;
    clear_rekey_state(&state, &user_id).await?;

    tracing::info!(user_id = %user_id, epoch = ks.epoch, "re-key aborted");
    Ok(StatusCode::NO_CONTENT)
}

/// Modest per-account pacing for the rotation endpoints themselves. The heavy
/// traffic (chunk re-uploads) is already bounded by the ordinary chunk-write
/// limits; these calls are cheap but must not be free to spam.
fn rate_limit(state: &AppState, user_id: &str) -> Result<()> {
    crate::rate_limit::check(&state.store, &format!("rl:rekey:{user_id}"), 30, 3600)
}
