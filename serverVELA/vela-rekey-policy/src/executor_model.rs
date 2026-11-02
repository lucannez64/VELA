//! Rust mirror of the F* executor store model in
//! `proofs/fstar/executor-lemmas/Vela_rekey_policy_executor_model.fst`.
//!
//! The server's conformance test runs the real executors against a real
//! database and compares every touched table and store key, plus the
//! observation, with what this model predicts. The F* module proves the plans
//! and classifiers against the same semantics. Each function here has a
//! namesake there with the same case order; keep them in step.
//! `tests::shared_vectors` checks the concrete runs the F* `vector_*` lemmas
//! prove from the general theorems.
//!
//! Only the columns the executor statements read or write are modelled. Every
//! table row is keyed by its `UNIQUE` key, so a missing key is a missing row
//! and an `INSERT` of a present key fails. The sled schema floor is one key.

use std::collections::BTreeMap;

use crate::executor::{
    CapsuleClearObservation, CapsuleReadObservation, CapsuleView, ChunkRowView,
    DeviceListObservation, DeviceListRowView, InventoryRowView, KeyStateObservation, KeyStateView,
    OramReadObservation, OramRowView, PendingRowView, ProjectedUsageObservation, ReadOutcome,
    SchemaFloorObservation, SyncObservation, SyncRowView, UsageObservation, VaultStmt,
    WriteOutcome,
};

/// A `vault_chunks` row; keyed by `(user_id, chunk_id, epoch)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkRow {
    pub user_id: String,
    pub chunk_id: String,
    pub epoch: i64,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<String>,
    pub ciphertext: String,
    pub created_at: String,
    pub updated_at: String,
}

/// The rotation columns of a `users` row the executors read or write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRow {
    pub key_epoch: i64,
    /// `None` is ACTIVE, `Some("freezing")` is FREEZING.
    pub rekey_state: Option<String>,
    pub rekey_started_at: Option<String>,
    pub rekey_starter: Option<String>,
    pub rekey_id: Option<String>,
    pub last_rekey_id: Option<String>,
    pub last_rekey_epoch: Option<i64>,
}

/// The device columns the executors read or write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRow {
    pub user_id: String,
    pub revoked: i64,
    pub rekey_capable: i64,
    pub rms_capsule: Option<String>,
    pub rms_capsule_epoch: Option<i64>,
    /// The remaining listing columns (`list_devices` selects them all).
    pub device_name: String,
    pub device_type: String,
    pub last_active: Option<String>,
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub enrolled_by: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
    pub created_at: String,
}

/// An `oram_buckets` row; keyed by `(user_id, tree_id, bucket_index, epoch)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OramRow {
    pub user_id: String,
    pub tree_id: String,
    pub bucket_index: i64,
    pub epoch: i64,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<String>,
    pub ciphertext: String,
    pub created_at: String,
    pub updated_at: String,
}

/// The modelled state: four tables and the sled store.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Db {
    /// `(user_id, chunk_id, epoch)`
    pub chunks: BTreeMap<(String, String, i64), ChunkRow>,
    pub users: BTreeMap<String, UserRow>,
    pub devices: BTreeMap<String, DeviceRow>,
    /// `(user_id, tree_id, bucket_index, epoch)`
    pub oram: BTreeMap<(String, String, i64, i64), OramRow>,
    pub kv: BTreeMap<String, String>,
    /// The fixed-window pacing counters (`rl:rekey:{user}`): key -> count.
    /// A missing key is zero, exactly as the sled counter reads it.
    pub counters: BTreeMap<String, u64>,
}

fn is_freezing(user: Option<&UserRow>) -> bool {
    matches!(user, Some(row) if row.rekey_state.as_deref() == Some("freezing"))
}

/// `users[id]` is ACTIVE at `epoch`.
fn active_at(db: &Db, user: &str, epoch: i64) -> bool {
    matches!(db.users.get(user), Some(row) if row.key_epoch == epoch && row.rekey_state.is_none())
}

/// The users guard `key_epoch = ? AND rekey_state = 'freezing' AND
/// rekey_starter = ? AND rekey_id = ?`.
fn freezing_attempt(db: &Db, user: &str, epoch: i64, starter: &str, rotation_id: &str) -> bool {
    matches!(
        db.users.get(user),
        Some(row)
            if row.key_epoch == epoch
                && is_freezing(Some(row))
                && row.rekey_starter.as_deref() == Some(starter)
                && row.rekey_id.as_deref() == Some(rotation_id)
    )
}

/// Any ORAM bucket of the account: the freeze guard's first `NOT EXISTS`.
pub fn any_oram(db: &Db, user: &str) -> bool {
    db.oram.keys().any(|key| key.0 == user)
}

/// An active device that has not attested rekey capability.
pub fn any_incapable(db: &Db, user: &str) -> bool {
    db.devices
        .values()
        .any(|row| row.user_id == user && row.revoked == 0 && row.rekey_capable == 0)
}

/// An active device still holding a pending capsule.
pub fn any_pending_capsule(db: &Db, user: &str) -> bool {
    db.devices
        .values()
        .any(|row| row.user_id == user && row.revoked == 0 && row.rms_capsule_epoch.is_some())
}

/// An old chunk row without its shadow at `to_epoch`.
pub fn any_missing_shadow(db: &Db, user: &str, from_epoch: i64, to_epoch: i64) -> bool {
    db.chunks
        .keys()
        .any(|(owner, chunk_id, epoch)| {
            owner == user
                && *epoch == from_epoch
                && !db
                    .chunks
                    .contains_key(&(user.to_string(), chunk_id.clone(), to_epoch))
        })
}

/// An active device without a complete capsule at `to_epoch`.
pub fn any_incomplete_device(db: &Db, user: &str, to_epoch: i64) -> bool {
    db.devices.values().any(|row| {
        row.user_id == user
            && row.revoked == 0
            && (row.rekey_capable == 0
                || row.rms_capsule.is_none()
                || row.rms_capsule_epoch != Some(to_epoch))
    })
}

fn faulted(fault: Option<usize>, k: usize) -> bool {
    fault == Some(k)
}

/// One write statement on a working state: `Some((rows changed, new state))`,
/// or `None` when the statement itself errors. F*: `exec`.
pub fn exec(db: &Db, stmt: &VaultStmt) -> Option<(u64, Db)> {
    let mut next = db.clone();
    match stmt {
        VaultStmt::InsertChunkCreate {
            chunk_id,
            user,
            lamport_clock,
            last_writer,
            ciphertext,
            epoch,
            now,
            permit_epoch,
        } => {
            if !active_at(db, user, *permit_epoch) {
                return Some((0, next));
            }
            let key = (user.clone(), chunk_id.clone(), *epoch);
            if db.chunks.contains_key(&key) {
                return None;
            }
            next.chunks.insert(
                key,
                ChunkRow {
                    user_id: user.clone(),
                    chunk_id: chunk_id.clone(),
                    epoch: *epoch,
                    version: 1,
                    lamport_clock: *lamport_clock,
                    last_writer: Some(last_writer.clone()),
                    ciphertext: ciphertext.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                },
            );
            Some((1, next))
        }
        VaultStmt::InsertChunkShadow {
            chunk_id,
            user,
            lamport_clock,
            last_writer,
            ciphertext,
            epoch,
            now,
            read_epoch,
            starter,
            rotation_id,
        } => {
            if !freezing_attempt(db, user, *read_epoch, starter, rotation_id) {
                return Some((0, next));
            }
            let key = (user.clone(), chunk_id.clone(), *epoch);
            match db.chunks.get(&key) {
                Some(row) => {
                    let mut row = row.clone();
                    row.version += 1;
                    row.lamport_clock = *lamport_clock;
                    row.last_writer = Some(last_writer.clone());
                    row.ciphertext = ciphertext.clone();
                    row.updated_at = now.clone();
                    next.chunks.insert(key, row);
                }
                None => {
                    next.chunks.insert(
                        key,
                        ChunkRow {
                            user_id: user.clone(),
                            chunk_id: chunk_id.clone(),
                            epoch: *epoch,
                            version: 1,
                            lamport_clock: *lamport_clock,
                            last_writer: Some(last_writer.clone()),
                            ciphertext: ciphertext.clone(),
                            created_at: now.clone(),
                            updated_at: now.clone(),
                        },
                    );
                }
            }
            Some((1, next))
        }
        VaultStmt::UpdateChunkCas {
            chunk_id,
            user,
            version,
            lamport_clock,
            last_writer,
            ciphertext,
            epoch,
            now,
            permit_epoch,
        } => {
            let key = (user.clone(), chunk_id.clone(), *epoch);
            match db.chunks.get(&key) {
                Some(row)
                    if row.version == *version && active_at(db, user, *permit_epoch) =>
                {
                    let mut row = row.clone();
                    row.version += 1;
                    row.lamport_clock = *lamport_clock;
                    row.last_writer = Some(last_writer.clone());
                    row.ciphertext = ciphertext.clone();
                    row.updated_at = now.clone();
                    next.chunks.insert(key, row);
                    Some((1, next))
                }
                _ => Some((0, next)),
            }
        }
        VaultStmt::DeleteChunkCas {
            chunk_id,
            user,
            epoch,
        } => {
            let key = (user.clone(), chunk_id.clone(), *epoch);
            if db.chunks.contains_key(&key) && active_at(db, user, *epoch) {
                next.chunks.remove(&key);
                Some((1, next))
            } else {
                Some((0, next))
            }
        }
        VaultStmt::DeleteChunksNotEpoch { user, epoch } => {
            let doomed: Vec<_> = db
                .chunks
                .keys()
                .filter(|(owner, _, at)| owner == user && at != epoch)
                .cloned()
                .collect();
            let count = doomed.len() as u64;
            for key in doomed {
                next.chunks.remove(&key);
            }
            Some((count, next))
        }
        VaultStmt::DeleteChunksAboveEpoch { user, epoch } => {
            let doomed: Vec<_> = db
                .chunks
                .keys()
                .filter(|(owner, _, at)| owner == user && at > epoch)
                .cloned()
                .collect();
            let count = doomed.len() as u64;
            for key in doomed {
                next.chunks.remove(&key);
            }
            Some((count, next))
        }
        VaultStmt::DeleteChunksBelowEpoch { user, epoch } => {
            let doomed: Vec<_> = db
                .chunks
                .keys()
                .filter(|(owner, _, at)| owner == user && at < epoch)
                .cloned()
                .collect();
            let count = doomed.len() as u64;
            for key in doomed {
                next.chunks.remove(&key);
            }
            Some((count, next))
        }
        VaultStmt::FreezeCas {
            user,
            from_epoch,
            now,
            starter,
            rotation_id,
        } => match db.users.get(user) {
            Some(row)
                if row.key_epoch == *from_epoch
                    && row.rekey_state.is_none()
                    && !any_oram(db, user)
                    && !any_incapable(db, user)
                    && !any_pending_capsule(db, user) =>
            {
                next.users.insert(
                    user.clone(),
                    UserRow {
                        rekey_state: Some("freezing".into()),
                        rekey_started_at: Some(now.clone()),
                        rekey_starter: Some(starter.clone()),
                        rekey_id: Some(rotation_id.clone()),
                        ..row.clone()
                    },
                );
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        VaultStmt::CommitCas {
            user,
            from_epoch,
            to_epoch,
            starter,
            rotation_id,
        } => match db.users.get(user) {
            Some(row)
                if row.key_epoch == *from_epoch
                    && is_freezing(Some(row))
                    && row.rekey_starter.as_deref() == Some(starter.as_str())
                    && row.rekey_id.as_deref() == Some(rotation_id.as_str())
                    && !any_missing_shadow(db, user, *from_epoch, *to_epoch)
                    && !any_incomplete_device(db, user, *to_epoch) =>
            {
                let mut row = row.clone();
                row.key_epoch = *to_epoch;
                row.rekey_state = None;
                row.rekey_started_at = None;
                row.rekey_starter = None;
                row.rekey_id = None;
                row.last_rekey_id = Some(rotation_id.clone());
                row.last_rekey_epoch = Some(*to_epoch);
                next.users.insert(user.clone(), row);
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        VaultStmt::RollbackCas {
            user,
            epoch,
            rotation_id,
        } => match db.users.get(user) {
            Some(row)
                if row.key_epoch == *epoch
                    && is_freezing(Some(row))
                    && row.rekey_id.as_deref() == Some(rotation_id.as_str()) =>
            {
                next.users.insert(
                    user.clone(),
                    UserRow {
                        rekey_state: None,
                        rekey_started_at: None,
                        rekey_starter: None,
                        rekey_id: None,
                        ..row.clone()
                    },
                );
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        VaultStmt::RefreshShadowActivity {
            user,
            read_epoch,
            starter,
            rotation_id,
            now,
        } => match db.users.get(user) {
            Some(row)
                if row.key_epoch == *read_epoch
                    && is_freezing(Some(row))
                    && row.rekey_starter.as_deref() == Some(starter.as_str())
                    && row.rekey_id.as_deref() == Some(rotation_id.as_str()) =>
            {
                next.users.insert(
                    user.clone(),
                    UserRow {
                        rekey_started_at: Some(now.clone()),
                        ..row.clone()
                    },
                );
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        VaultStmt::ClearAttemptCapsules { user, epoch } => {
            let mut count = 0;
            for (key, row) in &db.devices {
                if row.user_id == *user && row.rms_capsule_epoch == Some(*epoch) {
                    count += 1;
                    next.devices.insert(
                        key.clone(),
                        DeviceRow {
                            rms_capsule: None,
                            rms_capsule_epoch: None,
                            ..row.clone()
                        },
                    );
                }
            }
            Some((count, next))
        }
        VaultStmt::WriteDeviceCapsule {
            device,
            user,
            capsule,
            capsule_epoch,
            from_epoch,
            starter,
            rotation_id,
        } => match db.devices.get(device) {
            Some(row)
                if row.user_id == *user
                    && row.revoked == 0
                    && freezing_attempt(db, user, *from_epoch, starter, rotation_id) =>
            {
                next.devices.insert(
                    device.clone(),
                    DeviceRow {
                        rms_capsule: Some(capsule.clone()),
                        rms_capsule_epoch: Some(*capsule_epoch),
                        ..row.clone()
                    },
                );
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        VaultStmt::AckDeviceCapsule {
            device,
            user,
            epoch,
        } => match db.devices.get(device) {
            Some(row)
                if row.user_id == *user
                    && row.revoked == 0
                    && row.rms_capsule_epoch == Some(*epoch) =>
            {
                next.devices.insert(
                    device.clone(),
                    DeviceRow {
                        rms_capsule: None,
                        rms_capsule_epoch: None,
                        ..row.clone()
                    },
                );
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        VaultStmt::AttestCapable { device, user } => match db.devices.get(device) {
            Some(row) if row.user_id == *user && row.revoked == 0 => {
                next.devices.insert(
                    device.clone(),
                    DeviceRow {
                        rekey_capable: 1,
                        ..row.clone()
                    },
                );
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        VaultStmt::InsertOramBucket {
            user,
            tree_id,
            bucket_index,
            lamport_clock,
            last_writer,
            ciphertext,
            epoch,
            now,
        } => {
            if !active_at(db, user, *epoch) {
                return Some((0, next));
            }
            let key = (user.clone(), tree_id.clone(), *bucket_index, *epoch);
            if db.oram.contains_key(&key) {
                return None;
            }
            next.oram.insert(
                key,
                OramRow {
                    user_id: user.clone(),
                    tree_id: tree_id.clone(),
                    bucket_index: *bucket_index,
                    epoch: *epoch,
                    version: 1,
                    lamport_clock: *lamport_clock,
                    last_writer: Some(last_writer.clone()),
                    ciphertext: ciphertext.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                },
            );
            Some((1, next))
        }
        VaultStmt::UpdateOramBucketCas {
            user,
            tree_id,
            bucket_index,
            version,
            lamport_clock,
            last_writer,
            ciphertext,
            epoch,
            now,
        } => {
            let key = (user.clone(), tree_id.clone(), *bucket_index, *epoch);
            match db.oram.get(&key) {
                Some(row) if row.version == *version && active_at(db, user, *epoch) => {
                    let mut row = row.clone();
                    row.version += 1;
                    row.lamport_clock = *lamport_clock;
                    row.last_writer = Some(last_writer.clone());
                    row.ciphertext = ciphertext.clone();
                    row.updated_at = now.clone();
                    next.oram.insert(key, row);
                    Some((1, next))
                }
                _ => Some((0, next)),
            }
        }
        VaultStmt::SchemaFloorSet { key } => {
            next.kv.insert(key.clone(), "2".into());
            Some((0, next))
        }
        VaultStmt::RateLimitIncr {
            key,
            limit: _,
            window_secs: _,
        } => {
            let count = db
                .counters
                .get(key)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            next.counters.insert(key.clone(), count);
            // The applied value of a counter statement is its new count, not a
            // row count; the classifier reads it against the budget.
            Some((count, next))
        }
        VaultStmt::ClearEnrollmentCapsule { device, user } => match db.devices.get(device) {
            Some(row) if row.user_id == *user => {
                next.devices.insert(
                    device.clone(),
                    DeviceRow {
                        rms_capsule: None,
                        rms_capsule_epoch: None,
                        ..row.clone()
                    },
                );
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        _ => None,
    }
}

// ── Runs ───────────────────────────────────────────────────────────────────

/// A plan run statement by statement on the pool, each statement its own
/// transaction, stopping at the first failure. F*: `run_auto`.
pub fn run_autocommit(
    pre: &Db,
    plan: &[VaultStmt],
    fault: Option<usize>,
) -> (Vec<WriteOutcome>, Db) {
    let mut db = pre.clone();
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, db);
        }
        match exec(&db, stmt) {
            Some((rows, next)) => {
                outcomes.push(WriteOutcome::Applied(rows));
                db = next;
            }
            None => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, db);
            }
        }
    }
    (outcomes, db)
}

/// A plan run inside an open transaction, stopping at the first failure.
/// Writes go to a working state; `Commit` publishes it. A failure, or a plan
/// that ends without committing, leaves the state the transaction began from.
/// F*: `run_tx`.
pub fn run_transaction(
    pre: &Db,
    plan: &[VaultStmt],
    fault: Option<usize>,
) -> (Vec<WriteOutcome>, Db) {
    let mut base = pre.clone();
    let mut work = pre.clone();
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, base);
        }
        if let VaultStmt::Commit = stmt {
            outcomes.push(WriteOutcome::Applied(0));
            base = work.clone();
            continue;
        }
        match exec(&work, stmt) {
            Some((rows, next)) => {
                outcomes.push(WriteOutcome::Applied(rows));
                work = next;
            }
            None => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, base);
            }
        }
    }
    (outcomes, base)
}

/// The freeze half of `POST /vault/rekey/start`: the CAS, then (only when it
/// changed the row) the cleanup, then the commit. F*: `run_freeze_tx`.
pub fn run_freeze_tx(
    pre: &Db,
    cash: &VaultStmt,
    cleanup: &VaultStmt,
    fault: Option<usize>,
) -> (Vec<WriteOutcome>, Db) {
    let mut outcomes = Vec::new();
    if faulted(fault, 0) {
        return (vec![WriteOutcome::Failed], pre.clone());
    }
    let (rows, work) = match exec(pre, cash) {
        Some(applied) => applied,
        None => return (vec![WriteOutcome::Failed], pre.clone()),
    };
    outcomes.push(WriteOutcome::Applied(rows));
    if rows == 0 {
        return (outcomes, pre.clone());
    }
    if faulted(fault, 1) {
        outcomes.push(WriteOutcome::Failed);
        return (outcomes, pre.clone());
    }
    let work = match exec(&work, cleanup) {
        Some((changed, next)) => {
            outcomes.push(WriteOutcome::Applied(changed));
            next
        }
        None => {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, pre.clone());
        }
    };
    if faulted(fault, 2) {
        outcomes.push(WriteOutcome::Failed);
        return (outcomes, pre.clone());
    }
    outcomes.push(WriteOutcome::Applied(0));
    (outcomes, work)
}

/// The abort/timeout transaction: the CAS, then (only when it changed the
/// row) the chunk and capsule cleanup, then the commit. F*: `run_rollback_tx`.
pub fn run_rollback_tx(
    pre: &Db,
    cash: &VaultStmt,
    delete_chunks: &VaultStmt,
    clear_capsules: &VaultStmt,
    fault: Option<usize>,
) -> (Vec<WriteOutcome>, Db) {
    let mut outcomes = Vec::new();
    if faulted(fault, 0) {
        return (vec![WriteOutcome::Failed], pre.clone());
    }
    let (rows, work) = match exec(pre, cash) {
        Some(applied) => applied,
        None => return (vec![WriteOutcome::Failed], pre.clone()),
    };
    outcomes.push(WriteOutcome::Applied(rows));
    if rows == 0 {
        return (outcomes, pre.clone());
    }
    let mut work = work;
    for (offset, stmt) in [(1, delete_chunks), (2, clear_capsules)].into_iter() {
        if faulted(fault, offset) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, pre.clone());
        }
        match exec(&work, stmt) {
            Some((changed, next)) => {
                outcomes.push(WriteOutcome::Applied(changed));
                work = next;
            }
            None => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, pre.clone());
            }
        }
    }
    if faulted(fault, 3) {
        outcomes.push(WriteOutcome::Failed);
        return (outcomes, pre.clone());
    }
    outcomes.push(WriteOutcome::Applied(0));
    (outcomes, work)
}

// ── Reads ──────────────────────────────────────────────────────────────────

/// `SelectChunkVersion` on a state; `failed` injects a read error.
pub fn read_chunk_version(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Option<i64>> {
    match stmt {
        VaultStmt::SelectChunkVersion {
            chunk_id,
            user,
            epoch,
        } if !failed => ReadOutcome::Rows(
            db.chunks
                .get(&(user.clone(), chunk_id.clone(), *epoch))
                .map(|row| row.version),
        ),
        _ => ReadOutcome::Failed,
    }
}

/// `SelectChunkRow` on a state; `failed` injects a read error.
pub fn read_chunk_row(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Option<ChunkRowView>> {
    match stmt {
        VaultStmt::SelectChunkRow {
            chunk_id,
            user,
            epoch,
        } if !failed => ReadOutcome::Rows(
            db.chunks
                .get(&(user.clone(), chunk_id.clone(), *epoch))
                .map(|row| ChunkRowView {
                    chunk_id: Some(row.chunk_id.clone()),
                    user_id: Some(row.user_id.clone()),
                    version: Some(row.version),
                    lamport_clock: Some(row.lamport_clock),
                    last_writer: row.last_writer.clone(),
                    ciphertext: Some(row.ciphertext.clone()),
                    epoch: Some(row.epoch),
                }),
        ),
        _ => ReadOutcome::Failed,
    }
}

/// The inventory rows of one account at one epoch, as the query returns them.
/// Mirrors `inventory_rows` in the F* model: the set of rows is a function of
/// the state; the SQL `ORDER BY chunk_id` fixes the wire order.
pub fn inventory_row_set(db: &Db, user: &str, epoch: i64) -> Vec<InventoryRowView> {
    db.chunks
        .values()
        .filter(|row| row.user_id == *user && row.epoch == epoch)
        .map(|row| InventoryRowView {
            chunk_id: Some(row.chunk_id.clone()),
            version: Some(row.version),
            lamport_clock: Some(row.lamport_clock),
        })
        .collect()
}

/// `SelectInventory` on a state; `failed` injects a read error.
pub fn read_inventory(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Vec<InventoryRowView>> {
    match stmt {
        VaultStmt::SelectInventory { user, epoch } if !failed => {
            ReadOutcome::Rows(inventory_row_set(db, user, *epoch))
        }
        _ => ReadOutcome::Failed,
    }
}

/// `SelectPendingCapsule` on a state; `failed` injects a read error.
pub fn read_pending(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Option<PendingRowView>> {
    match stmt {
        VaultStmt::SelectPendingCapsule { device, user } if !failed => {
            ReadOutcome::Rows(db.devices.get(device).and_then(|row| {
                if row.user_id == *user && row.revoked == 0 {
                    Some(PendingRowView {
                        epoch: row.rms_capsule_epoch,
                    })
                } else {
                    None
                }
            }))
        }
        _ => ReadOutcome::Failed,
    }
}

/// The existence reads (`SelectChunkExists`, `SelectOramBucket` and the five
/// probes). `failed` injects a read error.
pub fn read_exists(db: &Db, stmt: &VaultStmt, failed: bool) -> ReadOutcome<bool> {
    if failed {
        return ReadOutcome::Failed;
    }
    match stmt {
        VaultStmt::SelectChunkExists {
            chunk_id,
            user,
            epoch,
        } => ReadOutcome::Rows(
            db.chunks
                .contains_key(&(user.clone(), chunk_id.clone(), *epoch)),
        ),
        VaultStmt::SelectOramBucket {
            user,
            tree_id,
            bucket_index,
            epoch,
        } => ReadOutcome::Rows(
            db.oram
                .contains_key(&(user.clone(), tree_id.clone(), *bucket_index, *epoch)),
        ),
        VaultStmt::ProbeOram { user } => ReadOutcome::Rows(any_oram(db, user)),
        VaultStmt::ProbeCapable { user } => ReadOutcome::Rows(any_incapable(db, user)),
        VaultStmt::ProbeAcknowledged { user } => {
            ReadOutcome::Rows(any_pending_capsule(db, user))
        }
        VaultStmt::ProbeChunkShadows {
            user,
            from_epoch,
            to_epoch,
        } => ReadOutcome::Rows(any_missing_shadow(db, user, *from_epoch, *to_epoch)),
        VaultStmt::ProbeDeviceCapsules { user, to_epoch } => {
            ReadOutcome::Rows(any_incomplete_device(db, user, *to_epoch))
        }
        _ => ReadOutcome::Failed,
    }
}

// ── Handler I/O outside executor methods (F-1 wave 2) ─────────────────────

/// The stored rotation state of one account, as `SelectKeyState` returns it.
pub fn key_state_view(db: &Db, user: &str) -> Option<KeyStateView> {
    db.users.get(user).map(|row| KeyStateView {
        key_epoch: Some(row.key_epoch),
        rekey_state: row.rekey_state.clone(),
        rekey_started_at: row.rekey_started_at.clone(),
        rekey_starter: row.rekey_starter.clone(),
        rekey_id: row.rekey_id.clone(),
        last_rekey_id: row.last_rekey_id.clone(),
        last_rekey_epoch: row.last_rekey_epoch,
    })
}

/// `SelectKeyState` on a state; `failed` injects a read error.
pub fn read_key_state(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Option<KeyStateView>> {
    match stmt {
        VaultStmt::SelectKeyState { user } if !failed => {
            ReadOutcome::Rows(key_state_view(db, user))
        }
        _ => ReadOutcome::Failed,
    }
}

/// The `LENGTH` SQL returns for a stored ciphertext: it is base64 ASCII, so
/// its character count is its byte count.
fn text_len(text: &str) -> i64 {
    text.chars().count() as i64
}

/// The account's served epoch, if the account exists.
fn served_epoch(db: &Db, user: &str) -> Option<i64> {
    db.users.get(user).map(|row| row.key_epoch)
}

/// `SUM(LENGTH(ciphertext))` over the account's current-epoch chunk rows.
pub fn chunk_usage(db: &Db, user: &str) -> i64 {
    let Some(epoch) = served_epoch(db, user) else {
        return 0;
    };
    db.chunks
        .values()
        .filter(|row| row.user_id == user && row.epoch == epoch)
        .map(|row| text_len(&row.ciphertext))
        .sum()
}

/// `SUM(LENGTH(ciphertext))` over the account's current-epoch ORAM rows.
pub fn oram_usage(db: &Db, user: &str) -> i64 {
    let Some(epoch) = served_epoch(db, user) else {
        return 0;
    };
    db.oram
        .values()
        .filter(|row| row.user_id == user && row.epoch == epoch)
        .map(|row| text_len(&row.ciphertext))
        .sum()
}

/// `SUM(LENGTH(ciphertext))` over every ORAM row of the account.
pub fn oram_total(db: &Db, user: &str) -> i64 {
    db.oram
        .values()
        .filter(|row| row.user_id == user)
        .map(|row| text_len(&row.ciphertext))
        .sum()
}

/// The projected stored bytes after a rotation replaces `chunk_id` at `epoch`.
pub fn projected_usage(db: &Db, user: &str, epoch: i64, chunk_id: &str) -> i64 {
    let chunks: i64 = db
        .chunks
        .values()
        .filter(|row| row.user_id == user && row.epoch == epoch && row.chunk_id != chunk_id)
        .map(|row| text_len(&row.ciphertext))
        .sum();
    chunks + oram_total(db, user)
}

/// `SelectUsageChunks`: the query's total, accepted only when it is the
/// model's sum over the state.
pub fn read_usage_chunks(
    db: &Db,
    stmt: &VaultStmt,
    total: i64,
    failed: bool,
) -> ReadOutcome<i64> {
    match stmt {
        VaultStmt::SelectUsageChunks { user } if !failed => {
            if total == chunk_usage(db, user) {
                ReadOutcome::Rows(total)
            } else {
                ReadOutcome::Failed
            }
        }
        _ => ReadOutcome::Failed,
    }
}

/// `SelectUsageOram`: the query's total, accepted only when it is the model's
/// sum over the state.
pub fn read_usage_oram(
    db: &Db,
    stmt: &VaultStmt,
    total: i64,
    failed: bool,
) -> ReadOutcome<i64> {
    match stmt {
        VaultStmt::SelectUsageOram { user } if !failed => {
            if total == oram_usage(db, user) {
                ReadOutcome::Rows(total)
            } else {
                ReadOutcome::Failed
            }
        }
        _ => ReadOutcome::Failed,
    }
}

/// `SelectRekeyProjection`: the query's total, accepted only when it is the
/// model's projected usage.
pub fn read_rekey_projection(
    db: &Db,
    stmt: &VaultStmt,
    total: i64,
    failed: bool,
) -> ReadOutcome<i64> {
    match stmt {
        VaultStmt::SelectRekeyProjection {
            user,
            epoch,
            chunk_id,
        } if !failed => {
            if total == projected_usage(db, user, *epoch, chunk_id) {
                ReadOutcome::Rows(total)
            } else {
                ReadOutcome::Failed
            }
        }
        _ => ReadOutcome::Failed,
    }
}

/// `SelectOramRow` on a state; `failed` injects a read error.
pub fn read_oram_row(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Option<OramRowView>> {
    match stmt {
        VaultStmt::SelectOramRow {
            user,
            tree_id,
            bucket_index,
            epoch,
        } if !failed => ReadOutcome::Rows(
            db.oram
                .get(&(user.clone(), tree_id.clone(), *bucket_index, *epoch))
                .map(|row| OramRowView {
                    version: Some(row.version),
                    lamport_clock: Some(row.lamport_clock),
                    last_writer: row.last_writer.clone(),
                    ciphertext: Some(row.ciphertext.clone()),
                }),
        ),
        _ => ReadOutcome::Failed,
    }
}

/// One `SelectSyncManifest` row.
pub fn sync_row(row: &ChunkRow) -> SyncRowView {
    SyncRowView {
        chunk_id: Some(row.chunk_id.clone()),
        version: Some(row.version),
        lamport_clock: Some(row.lamport_clock),
        last_writer: row.last_writer.clone(),
    }
}

/// The manifest rows of one account at one epoch, in the query's
/// `ORDER BY chunk_id` order.
pub fn sync_row_set(db: &Db, user: &str, epoch: i64) -> Vec<SyncRowView> {
    db.chunks
        .values()
        .filter(|row| row.user_id == *user && row.epoch == epoch)
        .map(sync_row)
        .collect()
}

/// `SelectSyncManifest`: the rows the query returned are accepted only when
/// they are exactly the account's rows at `epoch` computed from the state.
pub fn read_sync(
    db: &Db,
    stmt: &VaultStmt,
    rows: &[SyncRowView],
    failed: bool,
) -> ReadOutcome<Vec<SyncRowView>> {
    match stmt {
        VaultStmt::SelectSyncManifest { user, epoch } if !failed => {
            if rows == sync_row_set(db, user, *epoch).as_slice() {
                ReadOutcome::Rows(rows.to_vec())
            } else {
                ReadOutcome::Failed
            }
        }
        _ => ReadOutcome::Failed,
    }
}

/// `SchemaFloorGet`: the stored value, computed from the model's store.
pub fn read_schema_floor(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Option<String>> {
    match stmt {
        VaultStmt::SchemaFloorGet { key } if !failed => {
            ReadOutcome::Rows(db.kv.get(key).cloned())
        }
        _ => ReadOutcome::Failed,
    }
}

/// The pending capsule an account's device holds, as `SelectCapsule` returns
/// it: only an unrevoked device of the account holding a capsule, with the
/// recorded rotation id when the epoch matches the account's last commit.
pub fn capsule_view(db: &Db, device: &str, user: &str) -> Option<CapsuleView> {
    let row = db.devices.get(device)?;
    if row.user_id != user || row.revoked != 0 {
        return None;
    }
    let capsule = row.rms_capsule.clone()?;
    let account = db.users.get(user)?;
    // SQL compares the two cells: a NULL on either side is not a match.
    let rotation_id = match (row.rms_capsule_epoch, account.last_rekey_epoch) {
        (Some(capsule_epoch), Some(rekey_epoch)) if capsule_epoch == rekey_epoch => {
            account.last_rekey_id.clone()
        }
        _ => None,
    };
    Some(CapsuleView {
        capsule: Some(capsule),
        capsule_epoch: row.rms_capsule_epoch,
        rotation_id,
    })
}

/// `SelectCapsule` on a state; `failed` injects a read error.
pub fn read_capsule(
    db: &Db,
    stmt: &VaultStmt,
    failed: bool,
) -> ReadOutcome<Option<CapsuleView>> {
    match stmt {
        VaultStmt::SelectCapsule { device, user } if !failed => {
            ReadOutcome::Rows(capsule_view(db, device, user))
        }
        _ => ReadOutcome::Failed,
    }
}

/// One `SelectDeviceList` row.
pub fn device_list_view(id: &str, row: &DeviceRow) -> DeviceListRowView {
    DeviceListRowView {
        id: Some(id.to_string()),
        user_id: Some(row.user_id.clone()),
        device_name: Some(row.device_name.clone()),
        device_type: Some(row.device_type.clone()),
        last_active: row.last_active.clone(),
        hybrid_ek: Some(row.hybrid_ek.clone()),
        hybrid_vk: Some(row.hybrid_vk.clone()),
        enrolled_by: row.enrolled_by.clone(),
        rms_capsule: row.rms_capsule.clone(),
        revoked: Some(row.revoked),
        revoked_at: row.revoked_at.clone(),
        revoked_by: row.revoked_by.clone(),
        created_at: Some(row.created_at.clone()),
        rekey_capable: Some(row.rekey_capable),
    }
}

/// The account's devices in the listing's order, capped at the query's
/// `LIMIT 1000`.
pub fn device_list_row_set(db: &Db, user: &str) -> Vec<DeviceListRowView> {
    db.devices
        .iter()
        .filter(|(_, row)| row.user_id == user)
        .take(1000)
        .map(|(id, row)| device_list_view(id, row))
        .collect()
}

/// `SelectDeviceList`: the rows the query returned are accepted only when they
/// are exactly the account's devices computed from the state.
pub fn read_device_list(
    db: &Db,
    stmt: &VaultStmt,
    rows: &[DeviceListRowView],
    failed: bool,
) -> ReadOutcome<Vec<DeviceListRowView>> {
    match stmt {
        VaultStmt::SelectDeviceList { user } if !failed => {
            if rows == device_list_row_set(db, user).as_slice() {
                ReadOutcome::Rows(rows.to_vec())
            } else {
                ReadOutcome::Failed
            }
        }
        _ => ReadOutcome::Failed,
    }
}

/// The transaction begin: one statement, no state change; a failed begin
/// changes nothing either.
pub fn begin_transaction(db: &Db, plan: &[VaultStmt], fault: Option<usize>) -> (Vec<WriteOutcome>, Db) {
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, db.clone());
        }
        if matches!(stmt, VaultStmt::BeginTransaction) {
            outcomes.push(WriteOutcome::Applied(0));
        } else {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, db.clone());
        }
    }
    (outcomes, db.clone())
}

// ── The executors: plan, run, classify ─────────────────────────────────────

/// `DeleteChunkIo::delete_row`.
pub fn delete_chunk(
    db: &Db,
    chunk_id: &str,
    user: &str,
    epoch: i64,
    fault: Option<usize>,
) -> (crate::vault_mutation_driver::DeleteObservation, Db) {
    let plan = crate::executor::plan_delete_chunk(
        chunk_id.to_string(),
        user.to_string(),
        epoch,
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (crate::executor::classify_delete(&outcomes), post)
}

/// `DeleteChunkIo::read_version`.
pub fn read_version(
    db: &Db,
    chunk_id: &str,
    user: &str,
    epoch: i64,
    fault: Option<usize>,
) -> crate::vault_mutation_driver::VersionObservation {
    let stmt = crate::executor::plan_read_version(
        chunk_id.to_string(),
        user.to_string(),
        epoch,
    );
    crate::executor::classify_version(&read_chunk_version(db, &stmt, fault == Some(0)))
}

/// `PutChunkIo::reread_version`.
pub fn reread_version(
    db: &Db,
    chunk_id: &str,
    user: &str,
    epoch: i64,
    fault: Option<usize>,
) -> crate::vault_upload_driver::RereadObservation {
    let stmt = crate::executor::plan_reread_version(
        chunk_id.to_string(),
        user.to_string(),
        epoch,
    );
    crate::executor::classify_reread(&read_chunk_version(db, &stmt, fault == Some(0)))
}

/// `GetChunkIo::lookup_chunk`.
#[allow(clippy::too_many_arguments)]
pub fn lookup_chunk(
    db: &Db,
    caller: &str,
    chunk_id: &str,
    read_epoch: i64,
    decode_failed: bool,
    fault: Option<usize>,
) -> crate::vault_upload_driver::ReadLookupObservation {
    let stmt = crate::executor::plan_read_chunk(
        chunk_id.to_string(),
        caller.to_string(),
        read_epoch,
    );
    crate::executor::classify_chunk_read(
        &caller.to_string(),
        read_epoch,
        decode_failed,
        &read_chunk_row(db, &stmt, fault == Some(0)),
    )
}

/// `PutChunkIo::guarded_write` for `If-Match: 0` on an ACTIVE account.
#[allow(clippy::too_many_arguments)]
pub fn chunk_create(
    db: &Db,
    chunk_id: &str,
    user: &str,
    lamport_clock: i64,
    last_writer: &str,
    ciphertext: &str,
    epoch: i64,
    now: &str,
    permit_epoch: i64,
    duplicate: bool,
    fault: Option<usize>,
) -> (crate::vault_upload_driver::WriteObservation, Db) {
    let probe = crate::executor::plan_chunk_exists(
        chunk_id.to_string(),
        user.to_string(),
        epoch,
    );
    let probe = read_exists(db, &probe, fault == Some(0));
    let plan = crate::executor::plan_chunk_create(
        chunk_id.to_string(),
        user.to_string(),
        lamport_clock,
        last_writer.to_string(),
        ciphertext.to_string(),
        epoch,
        now.to_string(),
        permit_epoch,
    );
    let skipped = matches!(probe, ReadOutcome::Rows(true));
    let (outcomes, post) = if skipped {
        (Vec::new(), db.clone())
    } else {
        run_autocommit(db, &plan, fault.map(|k| k.saturating_sub(1)))
    };
    (
        crate::executor::classify_chunk_create(&probe, duplicate, &outcomes),
        post,
    )
}

/// `PutChunkIo::guarded_write` for `If-Match: 0` on a FREEZING account.
#[allow(clippy::too_many_arguments)]
pub fn chunk_shadow(
    db: &Db,
    chunk_id: &str,
    user: &str,
    lamport_clock: i64,
    last_writer: &str,
    ciphertext: &str,
    epoch: i64,
    now: &str,
    read_epoch: i64,
    starter: &str,
    rotation_id: &str,
    fault: Option<usize>,
) -> (crate::vault_upload_driver::WriteObservation, Db) {
    let plan = crate::executor::plan_chunk_shadow(
        chunk_id.to_string(),
        user.to_string(),
        lamport_clock,
        last_writer.to_string(),
        ciphertext.to_string(),
        epoch,
        now.to_string(),
        read_epoch,
        starter.to_string(),
        rotation_id.to_string(),
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (crate::executor::classify_chunk_shadow(&outcomes), post)
}

/// `PutChunkIo::guarded_write` for `If-Match: version`.
#[allow(clippy::too_many_arguments)]
pub fn chunk_update(
    db: &Db,
    chunk_id: &str,
    user: &str,
    version: i64,
    lamport_clock: i64,
    last_writer: &str,
    ciphertext: &str,
    epoch: i64,
    now: &str,
    permit_epoch: i64,
    fault: Option<usize>,
) -> (crate::vault_upload_driver::WriteObservation, Db) {
    let plan = crate::executor::plan_chunk_update(
        chunk_id.to_string(),
        user.to_string(),
        version,
        lamport_clock,
        last_writer.to_string(),
        ciphertext.to_string(),
        epoch,
        now.to_string(),
        permit_epoch,
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (crate::executor::classify_chunk_update(&outcomes), post)
}

/// `RekeyIo::read_inventory`.
pub fn inventory(
    db: &Db,
    user: &str,
    epoch: i64,
    fault: Option<usize>,
) -> crate::rekey_driver::InventoryObservation {
    let stmt = crate::executor::plan_read_inventory(user.to_string(), epoch);
    crate::executor::classify_inventory(&read_inventory(db, &stmt, fault == Some(0)))
}

/// The freeze transaction's three observations and the state it publishes.
#[allow(clippy::too_many_arguments)]
pub fn freeze_transaction(
    db: &Db,
    user: &str,
    from_epoch: i64,
    now: &str,
    starter: &str,
    rotation_id: &str,
    fault: Option<usize>,
) -> (
    crate::rekey_driver::CasObservation,
    crate::rekey_driver::CleanupObservation,
    crate::rekey_driver::TransactionObservation,
    Db,
) {
    use crate::rekey_driver::{CasObservation, CleanupObservation, TransactionObservation};
    let cash = crate::executor::plan_freeze_cas(
        user.to_string(),
        from_epoch,
        now.to_string(),
        starter.to_string(),
        rotation_id.to_string(),
    );
    let cleanup = crate::executor::plan_freeze_cleanup(user.to_string(), from_epoch);
    let (outcomes, post) = run_freeze_tx(db, &cash[0], &cleanup[0], fault);
    let cas = match outcomes.first() {
        Some(WriteOutcome::Applied(0)) => CasObservation::Skipped,
        Some(WriteOutcome::Applied(_)) => CasObservation::Updated,
        _ => CasObservation::Storage,
    };
    let cleanup_obs = if matches!(cas, CasObservation::Updated) {
        match outcomes.get(1) {
            Some(WriteOutcome::Applied(_)) => CleanupObservation::Done,
            _ => CleanupObservation::Storage,
        }
    } else {
        CleanupObservation::Storage
    };
    let commit = if outcomes.len() == 3 && matches!(outcomes[2], WriteOutcome::Applied(_)) {
        TransactionObservation::Committed
    } else {
        TransactionObservation::Failed
    };
    (cas, cleanup_obs, commit, post)
}

/// The commit CAS, then (only on a row) the sweep. Two autocommit statements,
/// so a failed sweep is reported but does not undo the commit.
#[allow(clippy::too_many_arguments)]
pub fn commit_and_sweep(
    db: &Db,
    user: &str,
    from_epoch: i64,
    to_epoch: i64,
    starter: &str,
    rotation_id: &str,
    fault: Option<usize>,
) -> (
    crate::rekey_driver::CasObservation,
    crate::rekey_driver::SweepObservation,
    Db,
) {
    use crate::executor::{classify_freeze_cas, classify_sweep};
    let cash = crate::executor::plan_commit_cas(
        user.to_string(),
        from_epoch,
        to_epoch,
        starter.to_string(),
        rotation_id.to_string(),
    );
    let (outcomes, post) = run_autocommit(db, &cash, fault);
    let cas = classify_freeze_cas(&outcomes);
    if !matches!(cas, crate::rekey_driver::CasObservation::Updated) {
        return (cas, crate::rekey_driver::SweepObservation::Failed, post);
    }
    let sweep = crate::executor::plan_sweep_old_chunks(user.to_string(), to_epoch);
    let (outcomes, post) = run_autocommit(&post, &sweep, fault.map(|k| k.saturating_sub(1)));
    (cas, classify_sweep(&outcomes), post)
}

/// The abort/timeout transaction.
#[allow(clippy::too_many_arguments)]
pub fn rollback_transaction(
    db: &Db,
    user: &str,
    epoch: i64,
    target_epoch: i64,
    rotation_id: &str,
    fault: Option<usize>,
) -> (crate::rekey_driver::RollbackObservation, Db) {
    use crate::executor::classify_rollback;
    let cash = crate::executor::plan_rollback_cas(
        user.to_string(),
        epoch,
        rotation_id.to_string(),
    );
    let cleanup = crate::executor::plan_rollback_cleanup(
        user.to_string(),
        epoch,
        target_epoch,
    );
    let (outcomes, post) = run_rollback_tx(db, &cash[0], &cleanup[0], &cleanup[1], fault);
    (classify_rollback(&outcomes), post)
}

/// `record_shadow_activity`.
#[allow(clippy::too_many_arguments)]
pub fn shadow_activity(
    db: &Db,
    user: &str,
    read_epoch: i64,
    starter: &str,
    rotation_id: &str,
    now: &str,
    write_epoch: i64,
    fault: Option<usize>,
) -> (crate::vault_upload_driver::ActivityObservation, Db) {
    if write_epoch == read_epoch {
        return (crate::vault_upload_driver::ActivityObservation::Refreshed, db.clone());
    }
    let plan = crate::executor::plan_shadow_activity(
        user.to_string(),
        read_epoch,
        starter.to_string(),
        rotation_id.to_string(),
        now.to_string(),
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (
        crate::executor::classify_shadow_activity(&outcomes),
        post,
    )
}

/// One of the five completeness probes.
pub fn probe(
    db: &Db,
    stmt: &VaultStmt,
    fault: Option<usize>,
) -> crate::rekey_driver::ProbeObservation {
    crate::executor::classify_probe(&read_exists(db, stmt, fault == Some(0)))
}

/// `RekeyIo::write_capsule`.
#[allow(clippy::too_many_arguments)]
pub fn write_capsule(
    db: &Db,
    device: &str,
    user: &str,
    capsule: &str,
    capsule_epoch: i64,
    from_epoch: i64,
    starter: &str,
    rotation_id: &str,
    fault: Option<usize>,
) -> (crate::rekey_driver::CapsuleObservation, Db) {
    let plan = crate::executor::plan_write_capsule(
        device.to_string(),
        user.to_string(),
        capsule.to_string(),
        capsule_epoch,
        from_epoch,
        starter.to_string(),
        rotation_id.to_string(),
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (
        crate::executor::classify_capsule_write(&outcomes),
        post,
    )
}

/// `CapsuleAckIo::acknowledge`.
pub fn acknowledge(
    db: &Db,
    device: &str,
    user: &str,
    epoch: i64,
    fault: Option<usize>,
) -> (crate::vault_mutation_driver::AckObservation, Db) {
    let plan = crate::executor::plan_ack_capsule(
        device.to_string(),
        user.to_string(),
        epoch,
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (crate::executor::classify_ack(&outcomes), post)
}

/// `CapsuleAckIo::inspect_pending`.
pub fn pending(
    db: &Db,
    device: &str,
    user: &str,
    fault: Option<usize>,
) -> crate::vault_mutation_driver::PendingObservation {
    let stmt = crate::executor::plan_pending_capsule(device.to_string(), user.to_string());
    crate::executor::classify_pending(&read_pending(db, &stmt, fault == Some(0)))
}

/// `CapableIo::attest`.
pub fn attest(
    db: &Db,
    device: &str,
    user: &str,
    fault: Option<usize>,
) -> (crate::vault_mutation_driver::AttestObservation, Db) {
    let plan = crate::executor::plan_attest_capable(device.to_string(), user.to_string());
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (crate::executor::classify_attest(&outcomes), post)
}

/// `ActivateIo::write_floor`.
pub fn schema_floor(
    db: &Db,
    key: &str,
    fault: Option<usize>,
) -> (crate::vault_mutation_driver::SchemaWriteObservation, Db) {
    let plan = crate::executor::plan_schema_floor(key.to_string());
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (
        crate::executor::classify_schema_write(&outcomes),
        post,
    )
}

/// `PutOramIo::write_bucket`.
#[allow(clippy::too_many_arguments)]
pub fn oram_write(
    db: &Db,
    user: &str,
    tree_id: &str,
    bucket_index: i64,
    if_match: i64,
    lamport_clock: i64,
    last_writer: &str,
    ciphertext: &str,
    epoch: i64,
    now: &str,
    fault: Option<usize>,
) -> (crate::vault_mutation_driver::BucketObservation, Db) {
    if if_match == 0 {
        let probe =
            crate::executor::plan_oram_exists(user.to_string(), tree_id.to_string(), bucket_index, epoch);
        let probe = read_exists(db, &probe, fault == Some(0));
        let plan = crate::executor::plan_oram_insert(
            user.to_string(),
            tree_id.to_string(),
            bucket_index,
            lamport_clock,
            last_writer.to_string(),
            ciphertext.to_string(),
            epoch,
            now.to_string(),
        );
        let skipped = matches!(probe, ReadOutcome::Rows(true));
        let (outcomes, post) = if skipped {
            (Vec::new(), db.clone())
        } else {
            run_autocommit(db, &plan, fault.map(|k| k.saturating_sub(1)))
        };
        (crate::executor::classify_oram_create(&probe, &outcomes), post)
    } else {
        let plan = crate::executor::plan_oram_update(
            user.to_string(),
            tree_id.to_string(),
            bucket_index,
            if_match,
            lamport_clock,
            last_writer.to_string(),
            ciphertext.to_string(),
            epoch,
            now.to_string(),
        );
        let (outcomes, post) = run_autocommit(db, &plan, fault);
        (crate::executor::classify_oram_update(&outcomes), post)
    }
}

// ── The handler I/O: plan, run, classify (F-1 wave 2) ─────────────────────

/// `rekey::load_key_state`.
pub fn key_state(db: &Db, user: &str, fault: Option<usize>) -> KeyStateObservation {
    let stmt = crate::executor::plan_load_key_state(user.to_string());
    crate::executor::classify_key_state(read_key_state(db, &stmt, fault == Some(0)))
}

/// `vault::current_usage_bytes`: the chunk read is statement 0, the ORAM read
/// statement 1.
pub fn usage(db: &Db, user: &str, fault: Option<usize>) -> UsageObservation {
    let chunks = read_usage_chunks(
        db,
        &crate::executor::plan_usage_chunks(user.to_string()),
        chunk_usage(db, user),
        fault == Some(0),
    );
    let oram = read_usage_oram(
        db,
        &crate::executor::plan_usage_oram(user.to_string()),
        oram_usage(db, user),
        fault == Some(1),
    );
    crate::executor::classify_usage(&chunks, &oram)
}

/// `vault::enforce_rekey_shadow_quota`.
pub fn projection(
    db: &Db,
    user: &str,
    epoch: i64,
    chunk_id: &str,
    fault: Option<usize>,
) -> ProjectedUsageObservation {
    let stmt = crate::executor::plan_rekey_projection(
        user.to_string(),
        epoch,
        chunk_id.to_string(),
    );
    crate::executor::classify_projected_usage(&read_rekey_projection(
        db,
        &stmt,
        projected_usage(db, user, epoch, chunk_id),
        fault == Some(0),
    ))
}

/// `oram::get_path`'s per-bucket read.
pub fn oram_read(
    db: &Db,
    user: &str,
    tree_id: &str,
    bucket_index: i64,
    epoch: i64,
    fault: Option<usize>,
) -> OramReadObservation {
    let stmt = crate::executor::plan_read_oram_bucket(
        user.to_string(),
        tree_id.to_string(),
        bucket_index,
        epoch,
    );
    crate::executor::classify_oram_read(read_oram_row(db, &stmt, fault == Some(0)))
}

/// `sync::get_sync`.
pub fn sync(
    db: &Db,
    user: &str,
    epoch: i64,
    fault: Option<usize>,
) -> SyncObservation {
    let stmt = crate::executor::plan_read_sync(user.to_string(), epoch);
    let rows = sync_row_set(db, user, epoch);
    crate::executor::classify_sync(&read_sync(db, &stmt, &rows, fault == Some(0)))
}

/// `schema::minimum`.
pub fn schema_floor_read(db: &Db, key: &str, fault: Option<usize>) -> SchemaFloorObservation {
    let stmt = crate::executor::plan_read_schema_floor(key.to_string());
    crate::executor::classify_schema_floor(read_schema_floor(db, &stmt, fault == Some(0)))
}

/// `device::capsule::get_capsule`'s read.
pub fn capsule_read(
    db: &Db,
    device: &str,
    user: &str,
    fault: Option<usize>,
) -> CapsuleReadObservation {
    let stmt = crate::executor::plan_read_capsule(device.to_string(), user.to_string());
    crate::executor::classify_capsule_read(read_capsule(db, &stmt, fault == Some(0)))
}

/// `device::capsule::get_capsule`'s read-once clear.
pub fn capsule_clear(
    db: &Db,
    device: &str,
    user: &str,
    fault: Option<usize>,
) -> (CapsuleClearObservation, Db) {
    let plan = crate::executor::plan_clear_enrollment_capsule(
        device.to_string(),
        user.to_string(),
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (crate::executor::classify_capsule_clear(&outcomes), post)
}

/// `device::list::list_devices`.
pub fn device_list(db: &Db, user: &str, fault: Option<usize>) -> DeviceListObservation {
    let stmt = crate::executor::plan_read_devices(user.to_string());
    let rows = device_list_row_set(db, user);
    crate::executor::classify_device_list(&read_device_list(db, &stmt, &rows, fault == Some(0)))
}

/// The per-account re-key pacing limiter (`rate_limit::check` on
/// `rl:rekey:{user}`): the plan's one counter increment runs, then the
/// extracted classifier decides from its new value. F*: `rekey_rate_limit`.
pub fn rekey_rate_limit(
    db: &Db,
    key: &str,
    window_secs: i64,
    limit: u64,
    fault: Option<usize>,
) -> (
    crate::rekey_driver::RateLimitObservation,
    Db,
) {
    let plan = crate::executor::plan_rate_limit(key.to_string(), limit, window_secs);
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (
        crate::executor::classify_rekey_rate_limit(&outcomes, limit),
        post,
    )
}

/// The transaction begin behind `POST /vault/rekey/start` and
/// `GET /device/capsule`.
pub fn begin(
    db: &Db,
    fault: Option<usize>,
) -> (crate::rekey_driver::TransactionObservation, Db) {
    let plan = crate::executor::plan_begin_transaction();
    let (outcomes, post) = begin_transaction(db, &plan, fault);
    (crate::executor::classify_transaction(&outcomes), post)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{
        plan_ack_capsule, plan_attest_capable, plan_delete_chunk, plan_schema_floor,
        CapsuleClearObservation, CapsuleReadObservation, CapsuleView, DeviceListObservation,
        KeyStateObservation, OramReadObservation, OramRowView, ProjectedUsageObservation,
        SchemaFloorObservation, SyncObservation, UsageObservation,
    };
    use crate::rekey_driver::CasObservation;
    use crate::vault_mutation_driver::{
        AckObservation, AttestObservation, BucketObservation, DeleteObservation,
        SchemaWriteObservation, VersionObservation,
    };
    use crate::vault_upload_driver::{ReadLookupObservation, WriteObservation};

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn user_row(epoch: i64) -> UserRow {
        UserRow {
            key_epoch: epoch,
            rekey_state: None,
            rekey_started_at: None,
            rekey_starter: None,
            rekey_id: None,
            last_rekey_id: None,
            last_rekey_epoch: None,
        }
    }

    fn device_row(user: &str, revoked: i64) -> DeviceRow {
        DeviceRow {
            user_id: s(user),
            revoked,
            rekey_capable: 1,
            rms_capsule: None,
            rms_capsule_epoch: None,
            device_name: s("laptop"),
            device_type: s("desktop"),
            last_active: None,
            hybrid_ek: s("ek"),
            hybrid_vk: s("vk"),
            enrolled_by: None,
            revoked_at: None,
            revoked_by: None,
            created_at: s("t0"),
        }
    }

    fn chunk_row(user: &str, id: &str, epoch: i64, version: i64) -> ChunkRow {
        ChunkRow {
            user_id: s(user),
            chunk_id: s(id),
            epoch,
            version,
            lamport_clock: 5,
            last_writer: Some(s("dev")),
            ciphertext: s("ct"),
            created_at: s("t0"),
            updated_at: s("t0"),
        }
    }

    /// One small state: an ACTIVE user at epoch 1 with a live chunk.
    fn base() -> Db {
        let mut db = Db::default();
        db.users.insert(s("u"), user_row(1));
        db.devices.insert(s("dev"), device_row("u", 0));
        db.chunks
            .insert((s("u"), s("c"), 1), chunk_row("u", "c", 1, 1));
        db
    }

    // The F* `vector_*` lemmas prove the same concrete runs.

    #[test]
    fn shared_vectors() {
        let pre = base();

        // vector_delete_active: the live row is deleted.
        let (obs, post) = delete_chunk(&pre, "c", "u", 1, None);
        assert_eq!(obs, DeleteObservation::Deleted);
        assert!(post.chunks.is_empty());

        // vector_delete_wrong_epoch: a mismatched epoch deletes nothing.
        let (obs, post) = delete_chunk(&pre, "c", "u", 2, None);
        assert_eq!(obs, DeleteObservation::Skipped);
        assert_eq!(post, pre);

        // vector_read_version.
        assert_eq!(
            read_version(&pre, "c", "u", 1, None),
            VersionObservation::Found { version: 1 }
        );

        // vector_lookup_active.
        assert_eq!(
            lookup_chunk(&pre, "u", "c", 1, false, None),
            ReadLookupObservation::Found {
                account_matches: true,
                epoch_matches: true,
                version: 1,
                lamport_clock: 5,
            }
        );

        // vector_create_fresh: a new chunk at the active epoch.
        let (obs, post) = chunk_create(&pre, "new", "u", 9, "dev", "ct2", 1, "t1", 1, false, None);
        assert_eq!(obs, WriteObservation::Inserted);
        assert_eq!(post.chunks[&(s("u"), s("new"), 1)].version, 1);

        // vector_create_existing: the probe reports the row.
        let (obs, post) = chunk_create(&pre, "c", "u", 9, "dev", "ct2", 1, "t1", 1, false, None);
        assert_eq!(obs, WriteObservation::Existing);
        assert_eq!(post, pre);

        // vector_update_cas.
        let (obs, post) = chunk_update(&pre, "c", "u", 1, 9, "dev", "ct3", 1, "t1", 1, None);
        assert_eq!(obs, WriteObservation::Updated);
        assert_eq!(post.chunks[&(s("u"), s("c"), 1)].version, 2);

        // vector_ack_matching / vector_ack_other.
        let mut with_capsule = pre.clone();
        with_capsule.devices.insert(
            s("dev"),
            DeviceRow {
                rms_capsule: Some(s("cap")),
                rms_capsule_epoch: Some(2),
                ..device_row("u", 0)
            },
        );
        let (obs, post) = acknowledge(&with_capsule, "dev", "u", 2, None);
        assert_eq!(obs, AckObservation::Cleared);
        assert_eq!(post.devices[&s("dev")].rms_capsule_epoch, None);
        let (obs, post) = acknowledge(&with_capsule, "dev", "u", 3, None);
        assert_eq!(obs, AckObservation::Missed);
        assert_eq!(post, with_capsule);

        // vector_attest.
        let (obs, post) = attest(&pre, "dev", "u", None);
        assert_eq!(obs, AttestObservation::Attested);
        assert_eq!(post.devices[&s("dev")].rekey_capable, 1);
        let (obs, _) = attest(&pre, "missing", "u", None);
        assert_eq!(obs, AttestObservation::Missing);

        // vector_schema_floor.
        let (obs, post) = schema_floor(&pre, "vault-schema:u", None);
        assert_eq!(obs, SchemaWriteObservation::Written);
        assert_eq!(post.kv[&s("vault-schema:u")], "2");

        // vector_freeze.
        let (cas, cleanup, commit, post) =
            freeze_transaction(&pre, "u", 1, "t1", "dev", "r", None);
        assert_eq!(cas, CasObservation::Updated);
        assert_eq!(cleanup, crate::rekey_driver::CleanupObservation::Done);
        assert_eq!(commit, crate::rekey_driver::TransactionObservation::Committed);
        assert_eq!(post.users[&s("u")].rekey_state.as_deref(), Some("freezing"));

        // vector_oram_update.
        let mut with_bucket = pre.clone();
        with_bucket
            .oram
            .insert((s("u"), s("t"), 1, 1), OramRow {
                user_id: s("u"),
                tree_id: s("t"),
                bucket_index: 1,
                epoch: 1,
                version: 1,
                lamport_clock: 1,
                last_writer: Some(s("dev")),
                ciphertext: s("ct"),
                created_at: s("t0"),
                updated_at: s("t0"),
            });
        let (obs, post) = oram_write(
            &with_bucket, "u", "t", 1, 1, 9, "dev", "ct2", 1, "t1", None,
        );
        assert_eq!(obs, BucketObservation::Written);
        assert_eq!(post.oram[&(s("u"), s("t"), 1, 1)].version, 2);

        // The plans are the ones the classifiers were proved against.
        assert_eq!(plan_delete_chunk(s("c"), s("u"), 1).len(), 1);
        assert_eq!(plan_ack_capsule(s("dev"), s("u"), 2).len(), 1);
        assert_eq!(plan_attest_capable(s("dev"), s("u")).len(), 1);
        assert_eq!(plan_schema_floor(s("vault-schema:u")).len(), 1);
    }

    /// The handler-I/O vectors the F* `vector_*` lemmas prove.
    #[test]
    fn handler_vectors() {
        let pre = base();

        assert_eq!(
            key_state(&pre, "u", None),
            KeyStateObservation::Loaded(KeyStateView {
                key_epoch: Some(1),
                rekey_state: None,
                rekey_started_at: None,
                rekey_starter: None,
                rekey_id: None,
                last_rekey_id: None,
                last_rekey_epoch: None,
            })
        );
        assert_eq!(key_state(&pre, "missing", None), KeyStateObservation::NotFound);
        assert_eq!(key_state(&pre, "u", Some(0)), KeyStateObservation::Storage);

        assert_eq!(
            usage(&pre, "u", None),
            UsageObservation::Measured {
                chunks: 2,
                oram: 0
            }
        );
        assert_eq!(usage(&pre, "u", Some(1)), UsageObservation::Storage);

        assert_eq!(
            projection(&pre, "u", 1, "c", None),
            ProjectedUsageObservation::Measured(0)
        );

        let mut with_bucket = pre.clone();
        with_bucket.oram.insert(
            (s("u"), s("t"), 1, 1),
            OramRow {
                user_id: s("u"),
                tree_id: s("t"),
                bucket_index: 1,
                epoch: 1,
                version: 1,
                lamport_clock: 1,
                last_writer: Some(s("dev")),
                ciphertext: s("bucket"),
                created_at: s("t0"),
                updated_at: s("t0"),
            },
        );
        assert_eq!(
            usage(&with_bucket, "u", None),
            UsageObservation::Measured {
                chunks: 2,
                oram: 6
            }
        );
        assert_eq!(
            projection(&with_bucket, "u", 1, "c", None),
            ProjectedUsageObservation::Measured(6)
        );
        assert_eq!(
            oram_read(&with_bucket, "u", "t", 1, 1, None),
            OramReadObservation::Found(OramRowView {
                version: Some(1),
                lamport_clock: Some(1),
                last_writer: Some(s("dev")),
                ciphertext: Some(s("bucket")),
            })
        );
        assert_eq!(
            oram_read(&with_bucket, "u", "t", 2, 1, None),
            OramReadObservation::Missing
        );

        assert_eq!(sync(&pre, "u", 1, None), SyncObservation::Read);
        assert_eq!(sync(&pre, "u", 2, None), SyncObservation::Read);
        assert_eq!(
            schema_floor_read(&pre, "vault-schema:u", None),
            SchemaFloorObservation::Stored(None)
        );
        let mut with_floor = pre.clone();
        with_floor.kv.insert(s("vault-schema:u"), s("2"));
        assert_eq!(
            schema_floor_read(&with_floor, "vault-schema:u", None),
            SchemaFloorObservation::Stored(Some(s("2")))
        );

        // The base device has no capsule.
        assert_eq!(capsule_read(&pre, "dev", "u", None), CapsuleReadObservation::Missing);
        let mut with_capsule = pre.clone();
        with_capsule.devices.insert(
            s("dev"),
            DeviceRow {
                rms_capsule: Some(s("cap")),
                rms_capsule_epoch: Some(2),
                ..device_row("u", 0)
            },
        );
        assert_eq!(
            capsule_read(&with_capsule, "dev", "u", None),
            CapsuleReadObservation::Found(CapsuleView {
                capsule: Some(s("cap")),
                capsule_epoch: Some(2),
                rotation_id: None,
            })
        );
        let (obs, post) = capsule_clear(&with_capsule, "dev", "u", None);
        assert_eq!(obs, CapsuleClearObservation::Cleared);
        assert_eq!(post.devices[&s("dev")].rms_capsule, None);

        assert_eq!(device_list(&pre, "u", None), DeviceListObservation::Read);
        assert_eq!(device_list(&pre, "u", Some(0)), DeviceListObservation::Failed);

        let (obs, post) = begin(&pre, None);
        assert_eq!(obs, crate::rekey_driver::TransactionObservation::Committed);
        assert_eq!(post, pre);
        let (obs, post) = begin(&pre, Some(0));
        assert_eq!(obs, crate::rekey_driver::TransactionObservation::Failed);
        assert_eq!(post, pre);
    }

    /// The re-key limiter vectors the F* `vector_rekey_rate_*` lemmas prove.
    #[test]
    fn rate_limit_vectors() {
        use crate::rekey_driver::RateLimitObservation;
        use crate::executor::{REKEY_RATE_LIMIT, REKEY_RATE_WINDOW_SECS};

        let pre = base();
        let key = "rl:rekey:u";

        // The last allowed request: 29 -> 30.
        let mut at_budget = pre.clone();
        at_budget.counters.insert(s(key), 29);
        let (obs, post) =
            rekey_rate_limit(&at_budget, key, REKEY_RATE_WINDOW_SECS, REKEY_RATE_LIMIT, None);
        assert_eq!(obs, RateLimitObservation::Allowed);
        assert_eq!(post.counters.get(key).copied(), Some(30));
        assert_eq!(post.users, pre.users);
        assert_eq!(post.kv, pre.kv);

        // The first refused request: 30 -> 31, still counted.
        let mut exhausted = pre.clone();
        exhausted.counters.insert(s(key), 30);
        let (obs, post) =
            rekey_rate_limit(&exhausted, key, REKEY_RATE_WINDOW_SECS, REKEY_RATE_LIMIT, None);
        assert_eq!(obs, RateLimitObservation::Limited);
        assert_eq!(post.counters.get(key).copied(), Some(31));

        // A failed store call records nothing and reports a refusal.
        let (obs, post) = rekey_rate_limit(
            &exhausted,
            key,
            REKEY_RATE_WINDOW_SECS,
            REKEY_RATE_LIMIT,
            Some(0),
        );
        assert_eq!(obs, RateLimitObservation::Limited);
        assert_eq!(post, exhausted);
    }
}


