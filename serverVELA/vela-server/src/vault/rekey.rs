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
use vela_rekey_policy::{
    AttemptAuthority, Phase as PolicyPhase, RekeyState as PolicyState, TimeoutDecision, TimeoutFacts, WriteDecision,
};

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
    let timeout = TimeoutFacts {
        expired,
        rotation_id_present: ks.rotation_id.is_some(),
    };
    let TimeoutDecision::Rollback(after) =
        vela_rekey_policy::plan_timeout(ks.policy_state(), timeout)
    else {
        return Ok(ks.clone_state());
    };
    let Some(rotation_id) = ks.rotation_id.as_deref() else {
        return Ok(ks.clone_state());
    };
    tracing::warn!(user_id = %user_id, "re-key timed out; rolling back to epoch {}", after.epoch);
    if !rollback_rekey(state, user_id, after.epoch, rotation_id).await? {
        // A commit or explicit abort won the transition while this request was
        // deciding the timeout. Return the state which actually won.
        return load_key_state(state, user_id).await;
    }
    Ok(KeyState {
        epoch: after.epoch,
        freezing: false,
        started_at: None,
        starter: None,
        rotation_id: None,
        last_rekey_id: ks.last_rekey_id.clone(),
        last_rekey_epoch: ks.last_rekey_epoch,
    })
}

impl KeyState {
    fn policy_state(&self) -> PolicyState {
        PolicyState {
            epoch: self.epoch,
            phase: if self.freezing {
                PolicyPhase::Freezing
            } else {
                PolicyPhase::Active
            },
        }
    }

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
        if let Some(target_epoch) = vela_rekey_policy::next_epoch(epoch) {
            tx.execute(
                "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
                 WHERE user_id = ? AND rms_capsule_epoch = ?",
                vec![
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Integer(target_epoch),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        }
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
    match vela_rekey_policy::resolve_write_epoch(ks.policy_state(), declared) {
        WriteDecision::Accept(route) => Ok((route.write_epoch, route.read_epoch)),
        WriteDecision::Reject if ks.freezing => {
            let required = vela_rekey_policy::next_epoch(ks.epoch)
                .map(|epoch| epoch.to_string())
                .unwrap_or_else(|| "no representable successor".to_string());
            Err(AppError::Rekeyed(format!(
                "a re-key is in progress; writes require epoch {required}"
            )))
        }
        WriteDecision::Reject => Err(AppError::Rekeyed(format!(
            "epoch mismatch: account is at {}; re-sync and adopt before writing",
            ks.epoch
        ))),
    }
}

/// Shadow ciphertext is account-authority work, not ordinary vault access.
/// Only the real device which started the freeze may populate or replace it;
/// in particular, an outstanding RW web-session token must not be able to
/// poison rows which commit will make authoritative.
///
/// This function only *observes* the authenticated attempt facts; the
/// extracted `vela_rekey_policy::vault_upload_driver` owns the decision.
pub(crate) async fn shadow_authority(
    state: &AppState,
    session: &AuthSession,
    rotation_id: Option<&str>,
) -> Result<AttemptAuthority> {
    let ks = load_key_state(state, &session.user_id.to_string()).await?;
    Ok(attempt_authority(&ks, session, rotation_id))
}

/// Refresh the inactivity deadline after a shadow write actually succeeded.
/// Failed or deliberately malformed requests must not keep an account frozen.
/// Returns `true` when the guarded refresh matched the live attempt and
/// `false` when the rotation ended first; the extracted driver classifies both
/// as non-fatal.
pub async fn record_shadow_activity(
    state: &AppState,
    session: &AuthSession,
    write_epoch: i64,
    read_epoch: i64,
    rotation_id: Option<&str>,
) -> Result<bool> {
    if write_epoch == read_epoch {
        return Ok(true);
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
        Ok(false)
    } else {
        Ok(true)
    }
}

/// The read-side filter: chunks at or below the served epoch exist; callers
/// filter their queries with this value.
pub async fn read_epoch(state: &AppState, user_id: &str) -> Result<i64> {
    let ks = maybe_rollback(state, user_id, &load_key_state(state, user_id).await?).await?;
    Ok(ks.epoch)
}

fn attempt_authority(
    ks: &KeyState,
    session: &AuthSession,
    rotation_id: Option<&str>,
) -> AttemptAuthority {
    AttemptAuthority {
        device_scope: session.scope == crate::auth::token::TokenScope::Device,
        starter_matches: ks.starter.as_deref() == Some(session.device_id.to_string().as_str()),
        rotation_id_present: rotation_id.is_some(),
        rotation_id_matches: ks.rotation_id.as_deref() == rotation_id,
    }
}

// ── Shared I/O for the four rotation entry points ───────────────────────────

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The I/O behind all four rotation handlers. The extracted driver decides
/// which method runs and in which order; each method only performs its effect
/// and reports the observation, keeping the original error for the response.
struct RekeyIo<'a> {
    state: &'a AppState,
    session: &'a DeviceSession,
    headers: &'a HeaderMap,
    capsules: Vec<(String, String)>,
    key: Option<KeyState>,
    tx: Option<crate::sqldb::TxGuard>,
    inventory: Vec<InventoryChunk>,
    rotation_id: Option<String>,
    error: Option<AppError>,
}

impl RekeyIo<'_> {
    fn device_id(&self) -> String {
        self.session.device_id.to_string()
    }

    fn user_id(&self) -> String {
        self.session.user_id.to_string()
    }

    fn expired(ks: &KeyState) -> bool {
        if !ks.freezing {
            return false;
        }
        ks.started_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| (Utc::now().signed_duration_since(t)).num_seconds() > REKEY_TIMEOUT_SECS)
            .unwrap_or(true)
    }

    fn observation(&self) -> vela_rekey_policy::rekey_driver::KeyStateObs {
        let ks = self
            .key
            .as_ref()
            .expect("key-state observation requires a loaded row");
        let supplied = header_str(self.headers, "x-vela-rekey-id");
        vela_rekey_policy::rekey_driver::KeyStateObs {
            epoch: ks.epoch,
            freezing: ks.freezing,
            starter_matches: ks.starter.as_deref() == Some(self.device_id().as_str()),
            rotation_id_present: ks.rotation_id.is_some(),
            header_present: supplied.is_some(),
            header_matches: ks.rotation_id.as_deref() == supplied,
            replay_target: header_str(self.headers, "X-Vela-Epoch")
                .and_then(|v| v.parse::<i64>().ok()),
            replay_recorded: ks.last_rekey_epoch,
            replay_id_matches: supplied.is_some() && supplied == ks.last_rekey_id.as_deref(),
            expired: Self::expired(ks),
        }
    }

    async fn rate_limit(&mut self) -> vela_rekey_policy::rekey_driver::RateLimitObservation {
        use vela_rekey_policy::rekey_driver::RateLimitObservation as O;
        match rate_limit(self.state, &self.user_id()) {
            Ok(()) => O::Allowed,
            Err(error) => {
                self.error = Some(error);
                O::Limited
            }
        }
    }

    async fn load_state(&mut self) -> vela_rekey_policy::rekey_driver::StateObservation {
        use vela_rekey_policy::rekey_driver::StateObservation as O;
        match load_key_state(self.state, &self.user_id()).await {
            Ok(ks) => {
                self.key = Some(ks);
                O::Loaded(self.observation())
            }
            Err(error) => {
                let observation = if matches!(error, AppError::NotFound(_)) {
                    O::NotFound
                } else {
                    O::Storage
                };
                self.error = Some(error);
                observation
            }
        }
    }

    async fn timeout_rollback(
        &mut self,
    ) -> vela_rekey_policy::rekey_driver::TimeoutObservation {
        use vela_rekey_policy::rekey_driver::TimeoutObservation as O;
        let Some(ks) = self.key.as_ref() else {
            return O::Storage;
        };
        let epoch = ks.epoch;
        let Some(rotation_id) = ks.rotation_id.clone() else {
            return O::Storage;
        };
        match rollback_rekey(self.state, &self.user_id(), epoch, &rotation_id).await {
            Ok(true) => {
                tracing::warn!(user_id = %self.session.user_id, "re-key timed out; rolling back to epoch {}", epoch);
                if let Some(ks) = self.key.as_mut() {
                    ks.freezing = false;
                    ks.started_at = None;
                    ks.starter = None;
                    ks.rotation_id = None;
                }
                O::RolledBack
            }
            Ok(false) => {
                // A commit or explicit abort won the transition while this
                // request was deciding the timeout. Return the state which
                // actually won.
                match load_key_state(self.state, &self.user_id()).await {
                    Ok(ks) => {
                        self.key = Some(ks);
                        O::Raced(self.observation())
                    }
                    Err(error) => {
                        self.error = Some(error);
                        O::Storage
                    }
                }
            }
            Err(error) => {
                self.error = Some(error);
                O::Storage
            }
        }
    }

    async fn check_oram(&mut self) -> vela_rekey_policy::rekey_driver::ProbeObservation {
        use vela_rekey_policy::rekey_driver::ProbeObservation as O;
        self.probe(
            "SELECT 1 FROM oram_buckets WHERE user_id = ? LIMIT 1",
            vec![TursoValue::Text(self.user_id())],
        )
        .await
        .map(|empty| if empty { O::Empty } else { O::Found })
        .unwrap_or(O::Storage)
    }

    async fn check_capable(&mut self) -> vela_rekey_policy::rekey_driver::ProbeObservation {
        use vela_rekey_policy::rekey_driver::ProbeObservation as O;
        self.probe(
            "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0 AND rekey_capable = 0 LIMIT 1",
            vec![TursoValue::Text(self.user_id())],
        )
        .await
        .map(|empty| if empty { O::Empty } else { O::Found })
        .unwrap_or(O::Storage)
    }

    async fn check_acknowledged(&mut self) -> vela_rekey_policy::rekey_driver::ProbeObservation {
        use vela_rekey_policy::rekey_driver::ProbeObservation as O;
        self.probe(
            "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0 AND rms_capsule_epoch IS NOT NULL
             LIMIT 1",
            vec![TursoValue::Text(self.user_id())],
        )
        .await
        .map(|empty| if empty { O::Empty } else { O::Found })
        .unwrap_or(O::Storage)
    }

    async fn probe(
        &mut self,
        sql: &str,
        params: Vec<TursoValue>,
    ) -> Option<bool> {
        match self.state.sqldb.query(sql, params).await {
            Ok(rows) => Some(rows.is_empty()),
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                None
            }
        }
    }

    async fn begin_freeze_transaction(
        &mut self,
    ) -> vela_rekey_policy::rekey_driver::TransactionObservation {
        use vela_rekey_policy::rekey_driver::TransactionObservation as O;
        match self.state.sqldb.tx().await {
            Ok(tx) => {
                self.tx = Some(tx);
                O::Committed
            }
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Failed
            }
        }
    }

    async fn read_inventory(
        &mut self,
    ) -> vela_rekey_policy::rekey_driver::InventoryObservation {
        use vela_rekey_policy::rekey_driver::InventoryObservation as O;
        let Some(ks) = self.key.as_ref() else {
            return O::Failed;
        };
        let from_epoch = ks.epoch;
        let Some(tx) = self.tx.as_ref() else {
            return O::Failed;
        };
        let inventory = tx
            .query(
                "SELECT chunk_id, version, lamport_clock FROM vault_chunks
             WHERE user_id = ? AND epoch = ? ORDER BY chunk_id",
                vec![
                    TursoValue::Text(self.user_id()),
                    TursoValue::Integer(from_epoch),
                ],
            )
            .await;
        match inventory {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Failed
            }
            Ok(rows) => {
                let mut chunks = Vec::new();
                for row in rows.iter() {
                    chunks.push(InventoryChunk {
                        chunk_id: match row.get(0) {
                            Some(TursoValue::Text(s)) => s.clone(),
                            _ => continue,
                        },
                        version: row.i64(1).unwrap_or(1),
                        lamport_clock: row.i64(2).unwrap_or(0),
                    });
                }
                self.inventory = chunks;
                O::Read
            }
        }
    }

    async fn freeze_cas(
        &mut self,
        from_epoch: i64,
        _to_epoch: i64,
    ) -> vela_rekey_policy::rekey_driver::CasObservation {
        use vela_rekey_policy::rekey_driver::CasObservation as O;
        let rotation_id = uuid::Uuid::new_v4().to_string();
        let Some(tx) = self.tx.as_ref() else {
            return O::Storage;
        };
        let updated = tx
            .execute(
                "UPDATE users SET rekey_state = 'freezing', rekey_started_at = ?,
                rekey_starter = ?, rekey_id = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM oram_buckets WHERE user_id = users.id
               )
               AND NOT EXISTS (
                 SELECT 1 FROM devices
                  WHERE user_id = users.id AND revoked = 0
                    AND rekey_capable = 0
               )
               AND NOT EXISTS (
                 SELECT 1 FROM devices
                  WHERE user_id = users.id AND revoked = 0
                    AND rms_capsule_epoch IS NOT NULL
               )",
                vec![
                    TursoValue::Text(Utc::now().to_rfc3339()),
                    TursoValue::Text(self.device_id()),
                    TursoValue::Text(rotation_id.clone()),
                    TursoValue::Text(self.user_id()),
                    TursoValue::Integer(from_epoch),
                ],
            )
            .await;
        match updated {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Storage
            }
            Ok(1) => {
                self.rotation_id = Some(rotation_id);
                O::Updated
            }
            Ok(_) => O::Skipped,
        }
    }

    async fn cleanup_chunks(
        &mut self,
        from_epoch: i64,
    ) -> vela_rekey_policy::rekey_driver::CleanupObservation {
        use vela_rekey_policy::rekey_driver::CleanupObservation as O;
        let Some(tx) = self.tx.as_ref() else {
            return O::Storage;
        };
        match tx
            .execute(
                "DELETE FROM vault_chunks WHERE user_id = ? AND epoch != ?",
                vec![
                    TursoValue::Text(self.user_id()),
                    TursoValue::Integer(from_epoch),
                ],
            )
            .await
        {
            Ok(_) => O::Done,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Storage
            }
        }
    }

    async fn commit_freeze_transaction(
        &mut self,
    ) -> vela_rekey_policy::rekey_driver::TransactionObservation {
        use vela_rekey_policy::rekey_driver::TransactionObservation as O;
        let Some(tx) = self.tx.take() else {
            return O::Failed;
        };
        match tx.commit().await {
            Ok(()) => O::Committed,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Failed
            }
        }
    }

    async fn write_capsule(
        &mut self,
        index: i64,
    ) -> vela_rekey_policy::rekey_driver::CapsuleObservation {
        use vela_rekey_policy::rekey_driver::CapsuleObservation as O;
        let Some((device_id, capsule_b64)) = self.capsules.get(index as usize).cloned() else {
            return O::NotTarget;
        };
        let capsule = match crate::db::decode_b64(&capsule_b64) {
            Ok(capsule) => capsule,
            Err(error) => {
                self.error = Some(error);
                return O::Invalid;
            }
        };
        if capsule.is_empty() || capsule.len() > 64 * 1024 {
            self.error = Some(AppError::BadRequest(format!(
                "capsule for {device_id} has an invalid size"
            )));
            return O::Invalid;
        }
        let Some(ks) = self.key.as_ref() else {
            return O::Storage;
        };
        let Some(capsule_epoch) = vela_rekey_policy::next_epoch(ks.epoch) else {
            return O::Invalid;
        };
        let rows = self
            .state
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
                    TursoValue::Text(capsule_b64),
                    TursoValue::Integer(capsule_epoch),
                    TursoValue::Text(device_id.clone()),
                    TursoValue::Text(self.user_id()),
                    TursoValue::Integer(ks.epoch),
                    TursoValue::Text(self.device_id()),
                    TursoValue::Text(ks.rotation_id.as_deref().unwrap_or_default().to_string()),
                ],
            )
            .await;
        match rows {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Storage
            }
            Ok(0) => {
                self.error = Some(AppError::BadRequest(format!(
                    "capsule target is not an active device of this account: {device_id}"
                )));
                O::NotTarget
            }
            Ok(_) => O::Stored,
        }
    }

    async fn check_chunk_shadows(
        &mut self,
    ) -> vela_rekey_policy::rekey_driver::ProbeObservation {
        use vela_rekey_policy::rekey_driver::ProbeObservation as O;
        let Some(ks) = self.key.as_ref() else {
            return O::Storage;
        };
        let Some(new_epoch) = vela_rekey_policy::next_epoch(ks.epoch) else {
            return O::Storage;
        };
        self.probe(
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
                TursoValue::Text(self.user_id()),
                TursoValue::Integer(ks.epoch),
                TursoValue::Integer(new_epoch),
            ],
        )
        .await
        .map(|empty| if empty { O::Empty } else { O::Found })
        .unwrap_or(O::Storage)
    }

    async fn check_device_capsules(
        &mut self,
    ) -> vela_rekey_policy::rekey_driver::ProbeObservation {
        use vela_rekey_policy::rekey_driver::ProbeObservation as O;
        let Some(ks) = self.key.as_ref() else {
            return O::Storage;
        };
        let Some(new_epoch) = vela_rekey_policy::next_epoch(ks.epoch) else {
            return O::Storage;
        };
        self.probe(
            "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0
               AND (rekey_capable = 0 OR rms_capsule IS NULL OR rms_capsule_epoch != ?)
             LIMIT 1",
            vec![
                TursoValue::Text(self.user_id()),
                TursoValue::Integer(new_epoch),
            ],
        )
        .await
        .map(|empty| if empty { O::Empty } else { O::Found })
        .unwrap_or(O::Storage)
    }

    async fn commit_cas(
        &mut self,
        from_epoch: i64,
        to_epoch: i64,
    ) -> vela_rekey_policy::rekey_driver::CasObservation {
        use vela_rekey_policy::rekey_driver::CasObservation as O;
        let rotation_id = header_str(self.headers, "x-vela-rekey-id").unwrap_or_default();
        let updated = self
            .state
            .sqldb
            .execute(
                "UPDATE users SET key_epoch = ?, rekey_state = NULL,
             rekey_started_at = NULL, rekey_starter = NULL, rekey_id = NULL,
             last_rekey_id = ?, last_rekey_epoch = ?,
             recovery_share = NULL, recovery_split_id = NULL,
             recovery_pending_share = NULL, recovery_pending_split_id = NULL,
             recovery_pending_epoch = NULL, recovery_auth_hash = NULL,
             recovery_pending_auth_hash = NULL
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
                    TursoValue::Integer(to_epoch),
                    TursoValue::Text(rotation_id.to_string()),
                    TursoValue::Integer(to_epoch),
                    TursoValue::Text(self.user_id()),
                    TursoValue::Integer(from_epoch),
                    TursoValue::Text(self.device_id()),
                    TursoValue::Text(rotation_id.to_string()),
                    TursoValue::Integer(from_epoch),
                    TursoValue::Integer(to_epoch),
                    TursoValue::Integer(to_epoch),
                ],
            )
            .await;
        match updated {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Storage
            }
            Ok(1) => O::Updated,
            Ok(_) => O::Skipped,
        }
    }

    async fn sweep_old_chunks(
        &mut self,
        new_epoch: i64,
    ) -> vela_rekey_policy::rekey_driver::SweepObservation {
        use vela_rekey_policy::rekey_driver::SweepObservation as O;
        match self
            .state
            .sqldb
            .execute(
                "DELETE FROM vault_chunks WHERE user_id = ? AND epoch < ?",
                vec![
                    TursoValue::Text(self.user_id()),
                    TursoValue::Integer(new_epoch),
                ],
            )
            .await
        {
            Ok(_) => O::Done,
            Err(error) => {
                tracing::warn!(user_id = %self.session.user_id, epoch = new_epoch, "failed to sweep superseded re-key rows: {error}");
                O::Failed
            }
        }
    }

    async fn publish_epoch(&mut self, epoch: i64) {
        self.state.vault_events.publish(
            self.session.user_id,
            self.session.device_id,
            epoch,
            crate::vault::events::VaultChangeKind::Epoch,
        );
    }

    async fn rollback_attempt(
        &mut self,
        epoch: i64,
    ) -> vela_rekey_policy::rekey_driver::RollbackObservation {
        use vela_rekey_policy::rekey_driver::RollbackObservation as O;
        let rotation_id = header_str(self.headers, "x-vela-rekey-id").unwrap_or_default();
        match rollback_rekey(self.state, &self.user_id(), epoch, rotation_id).await {
            Ok(true) => O::RolledBack,
            Ok(false) => O::Raced,
            Err(error) => {
                self.error = Some(error);
                O::Storage
            }
        }
    }
}

fn rekey_failure_error(
    failure: vela_rekey_policy::rekey_driver::RekeyFailure,
    recorded: Option<AppError>,
    _driver: &vela_rekey_policy::rekey_driver::RekeyDriver,
) -> AppError {
    use vela_rekey_policy::rekey_driver::RekeyFailure as F;
    if let Some(error) = recorded {
        return error;
    }
    match failure {
        F::Unauthenticated => AppError::Unauthorized("not authenticated".into()),
        F::WebSessionForbidden => AppError::Forbidden(
            "a temporary web session cannot change account authority".into(),
        ),
        F::RateLimited => AppError::RateLimited("re-key rate limit exceeded".into()),
        F::StateStorage => AppError::Internal("re-key state lookup failed".into()),
        F::AccountNotFound => AppError::NotFound("account not found".into()),
        F::InvalidEpoch => AppError::Internal("invalid vault key epoch".into()),
        F::AlreadyInProgress => {
            AppError::Conflict("a re-key is already in progress for this account".into())
        }
        F::NoRekeyInProgress => AppError::Conflict("no re-key is in progress".into()),
        F::OramPresent => AppError::Conflict(
            "vault key rotation is unavailable while ORAM buckets exist".into(),
        ),
        F::CapabilityRequired => AppError::Conflict(
            "vault key rotation requires every active device to sync once with a re-key-capable client; re-enroll legacy devices first".into(),
        ),
        F::AdoptionRequired => AppError::Conflict(
            "vault key rotation requires every active device to adopt and acknowledge the current epoch first".into(),
        ),
        F::TransactionStorage => AppError::Internal("re-key transaction failed".into()),
        F::InventoryStorage => AppError::Internal("re-key inventory query failed".into()),
        F::ConcurrentStart => {
            AppError::Conflict("a re-key was started concurrently for this account".into())
        }
        F::CleanupStorage => AppError::Internal("re-key cleanup failed".into()),
        F::TxCommitStorage => AppError::Internal("re-key transaction commit failed".into()),
        F::StarterRequired => {
            AppError::Forbidden("this re-key was started by another device".into())
        }
        F::RotationIdRequired => {
            AppError::BadRequest("X-Vela-Rekey-Id header is required".into())
        }
        F::RotationIdMismatch => {
            AppError::Conflict("this request belongs to a different re-key attempt".into())
        }
        F::NotAuthorized => {
            AppError::Forbidden("request is not authorized for this re-key attempt".into())
        }
        F::NoSuccessor => AppError::Conflict(
            "vault key epoch cannot advance to a representable successor".into(),
        ),
        F::TooManyCapsules => AppError::BadRequest("too many capsules".into()),
        F::CapsuleTargetInvalid => {
            AppError::BadRequest("capsule target is not an active device of this account".into())
        }
        F::ChunkShadowsIncomplete => AppError::Conflict(
            "cannot commit re-key: one or more chunk shadows are missing".into(),
        ),
        F::DeviceCapsulesIncomplete => AppError::Conflict(
            "cannot commit re-key: one or more active devices has no capsule".into(),
        ),
        F::CommitNotAuthorized => {
            AppError::Conflict("re-key is not authorized to commit".into())
        }
        F::ConcurrentCommit => {
            AppError::Conflict("re-key was aborted or committed concurrently".into())
        }
        F::ConcurrentRollback => {
            AppError::Conflict("re-key was committed or aborted concurrently".into())
        }
        F::ChunkProbeStorage => AppError::Internal("chunk-shadow query failed".into()),
        F::CapsuleProbeStorage => AppError::Internal("device-capsule query failed".into()),
        F::RollbackStorage => AppError::Internal("re-key rollback failed".into()),
    }
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
    use vela_rekey_policy::rekey_driver::{RekeyEffect, RekeyRequest};
    let user_id = session.user_id.to_string();
    let headers_in = HeaderMap::new();
    let mut io = RekeyIo {
        state: &state,
        session: &session,
        headers: &headers_in,
        capsules: Vec::new(),
        key: None,
        tx: None,
        inventory: Vec::new(),
        rotation_id: None,
        error: None,
    };
    let transition = vela_rekey_policy::rekey_start_interpreter!(
        io,
        RekeyRequest {
            authenticated: true,
            device_scope: true,
            capsule_count: 0,
        },
        await
    );
    match transition.effect {
        RekeyEffect::Complete => {
            tracing::info!(
                user_id = %user_id,
                from_epoch = transition.driver.from_epoch,
                to_epoch = transition.driver.to_epoch,
                chunks = io.inventory.len(),
                "re-key started"
            );
            let mut headers = HeaderMap::new();
            maybe_append_new_token(&mut headers, &session);
            Ok((
                headers,
                Json(StartResponse {
                    epoch: transition.driver.to_epoch,
                    rotation_id: io.rotation_id.unwrap_or_default(),
                    chunks: io.inventory,
                }),
            ))
        }
        RekeyEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(rekey_failure_error(failure, recorded, &transition.driver))
        }
        _ => Err(AppError::Internal(
            "re-key start did not reach a terminal decision".into(),
        )),
    }
}

// ── POST /vault/rekey/capsules ─────────────────────────────────────────────────

pub async fn post_capsules(
    State(state): State<AppState>,
    session: DeviceSession,
    headers: HeaderMap,
    Json(body): Json<CapsulesRequest>,
) -> Result<(HeaderMap, StatusCode)> {
    use vela_rekey_policy::rekey_driver::{RekeyEffect, RekeyRequest};
    let user_id = session.user_id.to_string();
    let capsules: Vec<(String, String)> = body
        .capsules
        .iter()
        .map(|(device, capsule)| (device.clone(), capsule.clone()))
        .collect();
    let capsule_count = capsules.len() as i64;
    let mut io = RekeyIo {
        state: &state,
        session: &session,
        headers: &headers,
        capsules,
        key: None,
        tx: None,
        inventory: Vec::new(),
        rotation_id: None,
        error: None,
    };
    let transition = vela_rekey_policy::rekey_capsules_interpreter!(
        io,
        RekeyRequest {
            authenticated: true,
            device_scope: true,
            capsule_count,
        },
        await
    );
    match transition.effect {
        RekeyEffect::Complete => {
            tracing::info!(
                user_id = %user_id,
                capsules = capsule_count,
                "re-key capsules stored"
            );
            Ok(no_content(&session))
        }
        RekeyEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(rekey_failure_error(failure, recorded, &transition.driver))
        }
        _ => Err(AppError::Internal(
            "re-key capsules did not reach a terminal decision".into(),
        )),
    }
}

// ── POST /vault/rekey/commit ───────────────────────────────────────────────────

pub async fn post_commit(
    State(state): State<AppState>,
    session: DeviceSession,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode)> {
    use vela_rekey_policy::rekey_driver::{RekeyEffect, RekeyRequest};
    let user_id = session.user_id.to_string();
    let mut io = RekeyIo {
        state: &state,
        session: &session,
        headers: &headers,
        capsules: Vec::new(),
        key: None,
        tx: None,
        inventory: Vec::new(),
        rotation_id: None,
        error: None,
    };
    let transition = vela_rekey_policy::rekey_commit_interpreter!(
        io,
        RekeyRequest {
            authenticated: true,
            device_scope: true,
            capsule_count: 0,
        },
        await
    );
    match transition.effect {
        RekeyEffect::CompleteReplay => {
            tracing::info!(
                user_id = %user_id,
                epoch = transition.driver.epoch,
                "re-key commit replayed after a lost response"
            );
            Ok(no_content(&session))
        }
        RekeyEffect::Complete => {
            tracing::info!(user_id = %user_id, epoch = transition.driver.epoch, "re-key committed");
            Ok(no_content(&session))
        }
        RekeyEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(rekey_failure_error(failure, recorded, &transition.driver))
        }
        _ => Err(AppError::Internal(
            "re-key commit did not reach a terminal decision".into(),
        )),
    }
}

// ── POST /vault/rekey/abort ────────────────────────────────────────────────────

pub async fn post_abort(
    State(state): State<AppState>,
    session: DeviceSession,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode)> {
    use vela_rekey_policy::rekey_driver::{RekeyEffect, RekeyRequest};
    let user_id = session.user_id.to_string();
    let mut io = RekeyIo {
        state: &state,
        session: &session,
        headers: &headers,
        capsules: Vec::new(),
        key: None,
        tx: None,
        inventory: Vec::new(),
        rotation_id: None,
        error: None,
    };
    let transition = vela_rekey_policy::rekey_abort_interpreter!(
        io,
        RekeyRequest {
            authenticated: true,
            device_scope: true,
            capsule_count: 0,
        },
        await
    );
    match transition.effect {
        RekeyEffect::Complete => {
            tracing::info!(user_id = %user_id, epoch = transition.driver.epoch, "re-key aborted");
            Ok(no_content(&session))
        }
        RekeyEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(rekey_failure_error(failure, recorded, &transition.driver))
        }
        _ => Err(AppError::Internal(
            "re-key abort did not reach a terminal decision".into(),
        )),
    }
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
