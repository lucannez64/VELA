//! The SQL and store operations behind the vault executors, split so the
//! observation each executor returns can be proved against a store model (F-1).
//!
//! Every executor method in `vela-server/src/vault/*.rs` and
//! `vela-server/src/device/{capsule,list}.rs` is
//!
//! 1. a pure `plan_*` function from the method's inputs to typed statements
//!    ([`VaultStmt`]);
//! 2. [`render`], from each statement to the exact SQL text and parameters the
//!    handler has always sent (pinned byte for byte by the unit tests below);
//! 3. a pure `classify_*` function from the per-statement outcomes to the
//!    observation the driver receives.
//!
//! The server runs a thin loop in `vela-server/src/vault/sql.rs`: plan, render
//! and run each statement in order, stop at the first failure, classify. hax
//! extracts the plans and classifiers; `proofs/fstar/executor-lemmas` proves
//! them against a model of the tables and store keys these statements touch,
//! for every starting database and every failing statement.
//! [`crate::executor_model`] is the Rust mirror of that model, used by the
//! server's conformance test against a real database.

use crate::rekey_driver::{
    CapsuleObservation, CasObservation, CleanupObservation, InventoryObservation,
    ProbeObservation, RollbackObservation, SweepObservation, TransactionObservation,
};
use crate::vault_mutation_driver::{
    AckObservation, AttestObservation, BucketObservation, DeleteObservation,
    PendingObservation, SchemaWriteObservation, VersionObservation,
};
use crate::vault_upload_driver::{
    ActivityObservation, ReadLookupObservation, RereadObservation, WriteObservation,
};

/// One statement an executor may run. Field names follow the bound
/// parameters; [`render`] fixes their order and their SQL types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultStmt {
    /// `SELECT version FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?`
    SelectChunkVersion { chunk_id: String, user: String, epoch: i64 },
    /// The whole current-epoch row `GET /vault/chunk/:id` serves.
    SelectChunkRow { chunk_id: String, user: String, epoch: i64 },
    /// `SELECT 1 FROM vault_chunks ...`: the create path's uniqueness probe.
    SelectChunkExists { chunk_id: String, user: String, epoch: i64 },
    /// The create path: insert exactly when the account is ACTIVE at
    /// `permit_epoch`.
    InsertChunkCreate {
        chunk_id: String,
        user: String,
        lamport_clock: i64,
        last_writer: String,
        ciphertext: String,
        epoch: i64,
        now: String,
        permit_epoch: i64,
    },
    /// The shadow path: upsert exactly when this account is FREEZING at
    /// `read_epoch` under the same starter and rotation id.
    InsertChunkShadow {
        chunk_id: String,
        user: String,
        lamport_clock: i64,
        last_writer: String,
        ciphertext: String,
        epoch: i64,
        now: String,
        read_epoch: i64,
        starter: String,
        rotation_id: String,
    },
    /// The replace path: a version CAS on the account's current-epoch row.
    UpdateChunkCas {
        chunk_id: String,
        user: String,
        version: i64,
        lamport_clock: i64,
        last_writer: String,
        ciphertext: String,
        epoch: i64,
        now: String,
        permit_epoch: i64,
    },
    /// `DELETE` a chunk row, guarded by the account still being ACTIVE at
    /// `epoch`.
    DeleteChunkCas { chunk_id: String, user: String, epoch: i64 },
    /// The chunk inventory `POST /vault/rekey/start` returns.
    SelectInventory { user: String, epoch: i64 },
    /// The freeze transaction's cleanup: every chunk row not at `epoch`.
    DeleteChunksNotEpoch { user: String, epoch: i64 },
    /// The abort/timeout rollback's cleanup: every chunk row above `epoch`.
    DeleteChunksAboveEpoch { user: String, epoch: i64 },
    /// The commit's sweep: every chunk row below `new_epoch`.
    DeleteChunksBelowEpoch { user: String, epoch: i64 },
    /// The freeze CAS: ACTIVE(`from_epoch`) → FREEZING(`from_epoch + 1`), only
    /// when the account has no ORAM buckets and every active device is
    /// capable and unacknowledged.
    FreezeCas {
        user: String,
        from_epoch: i64,
        now: String,
        starter: String,
        rotation_id: String,
    },
    /// The commit CAS: FREEZING(`from_epoch`) → ACTIVE(`to_epoch`), only with
    /// the attempt's starter and rotation id and both completeness checks.
    CommitCas {
        user: String,
        from_epoch: i64,
        to_epoch: i64,
        starter: String,
        rotation_id: String,
    },
    /// The abort/timeout CAS: FREEZING(`epoch`) → ACTIVE(`epoch`).
    RollbackCas { user: String, epoch: i64, rotation_id: String },
    /// Refresh the rotation deadline after a successful shadow write.
    RefreshShadowActivity {
        user: String,
        read_epoch: i64,
        starter: String,
        rotation_id: String,
        now: String,
    },
    /// Kick the attempt's capsules out of every device at `epoch`.
    ClearAttemptCapsules { user: String, epoch: i64 },
    /// Store one device's sealed RMS capsule for the freezing attempt.
    WriteDeviceCapsule {
        device: String,
        user: String,
        capsule: String,
        capsule_epoch: i64,
        from_epoch: i64,
        starter: String,
        rotation_id: String,
    },
    /// The pending-epoch probe behind a capsule acknowledgement.
    SelectPendingCapsule { device: String, user: String },
    /// The acknowledgement's guarded clear.
    AckDeviceCapsule { device: String, user: String, epoch: i64 },
    /// The capability attestation's guarded write.
    AttestCapable { device: String, user: String },
    /// `SELECT 1 FROM oram_buckets WHERE user_id = ? LIMIT 1`.
    ProbeOram { user: String },
    /// `SELECT 1 FROM devices ... rekey_capable = 0`.
    ProbeCapable { user: String },
    /// `SELECT 1 FROM devices ... rms_capsule_epoch IS NOT NULL`.
    ProbeAcknowledged { user: String },
    /// `SELECT 1 FROM vault_chunks old ...`: an old row without its shadow.
    ProbeChunkShadows { user: String, from_epoch: i64, to_epoch: i64 },
    /// `SELECT 1 FROM devices ...`: an active device without its capsule.
    ProbeDeviceCapsules { user: String, to_epoch: i64 },
    /// `SELECT 1 FROM oram_buckets`: the create path's uniqueness probe.
    SelectOramBucket { user: String, tree_id: String, bucket_index: i64, epoch: i64 },
    /// The ORAM create path: insert exactly when the account is ACTIVE at
    /// `epoch`.
    InsertOramBucket {
        user: String,
        tree_id: String,
        bucket_index: i64,
        lamport_clock: i64,
        last_writer: String,
        ciphertext: String,
        epoch: i64,
        now: String,
    },
    /// The ORAM replace path: a version CAS on the bucket row.
    UpdateOramBucketCas {
        user: String,
        tree_id: String,
        bucket_index: i64,
        version: i64,
        lamport_clock: i64,
        last_writer: String,
        ciphertext: String,
        epoch: i64,
        now: String,
    },
    /// The one durable key-value write behind `POST /vault/schema`.
    SchemaFloorSet { key: String },
    /// Commit the open transaction.
    Commit,
}

/// What one write statement (or the commit) returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// It ran; the number of rows it changed (0 for the commit or a store
    /// write).
    Applied(u64),
    /// It returned an error.
    Failed,
}

/// What one read statement returned: its rows, or an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadOutcome<R> {
    Rows(R),
    Failed,
}

/// The cells of a `SelectChunkRow` row, as the handler decodes them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkRowView {
    pub chunk_id: Option<String>,
    pub user_id: Option<String>,
    pub version: Option<i64>,
    pub lamport_clock: Option<i64>,
    pub last_writer: Option<String>,
    pub ciphertext: Option<String>,
    pub epoch: Option<i64>,
}

/// One `SelectInventory` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryRowView {
    pub chunk_id: Option<String>,
    pub version: Option<i64>,
    pub lamport_clock: Option<i64>,
}

/// The `SelectPendingCapsule` row: its `rms_capsule_epoch` cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingRowView {
    pub epoch: Option<i64>,
}

/// The `SelectOramBucket` probe: whether the bucket row exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistsView {
    pub found: bool,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// `DeleteChunkIo::delete_row`: one guarded delete (autocommit).
pub fn plan_delete_chunk(chunk_id: String, user: String, epoch: i64) -> Vec<VaultStmt> {
    vec![VaultStmt::DeleteChunkCas { chunk_id, user, epoch }]
}

/// `DeleteChunkIo::read_version`.
pub fn plan_read_version(chunk_id: String, user: String, epoch: i64) -> VaultStmt {
    VaultStmt::SelectChunkVersion { chunk_id, user, epoch }
}

/// `PutChunkIo::reread_version`.
pub fn plan_reread_version(chunk_id: String, user: String, epoch: i64) -> VaultStmt {
    VaultStmt::SelectChunkVersion { chunk_id, user, epoch }
}

/// `GetChunkIo::lookup_chunk`.
pub fn plan_read_chunk(chunk_id: String, user: String, epoch: i64) -> VaultStmt {
    VaultStmt::SelectChunkRow { chunk_id, user, epoch }
}

/// The create path's uniqueness probe.
pub fn plan_chunk_exists(chunk_id: String, user: String, epoch: i64) -> VaultStmt {
    VaultStmt::SelectChunkExists { chunk_id, user, epoch }
}

/// `PutChunkIo::guarded_write` for `If-Match: 0`, ACTIVE account.
#[allow(clippy::too_many_arguments)]
pub fn plan_chunk_create(
    chunk_id: String,
    user: String,
    lamport_clock: i64,
    last_writer: String,
    ciphertext: String,
    epoch: i64,
    now: String,
    permit_epoch: i64,
) -> Vec<VaultStmt> {
    vec![VaultStmt::InsertChunkCreate {
        chunk_id,
        user,
        lamport_clock,
        last_writer,
        ciphertext,
        epoch,
        now,
        permit_epoch,
    }]
}

/// `PutChunkIo::guarded_write` for `If-Match: 0`, shadow (`FREEZING`).
#[allow(clippy::too_many_arguments)]
pub fn plan_chunk_shadow(
    chunk_id: String,
    user: String,
    lamport_clock: i64,
    last_writer: String,
    ciphertext: String,
    epoch: i64,
    now: String,
    read_epoch: i64,
    starter: String,
    rotation_id: String,
) -> Vec<VaultStmt> {
    vec![VaultStmt::InsertChunkShadow {
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
    }]
}

/// `PutChunkIo::guarded_write` for `If-Match: version`.
#[allow(clippy::too_many_arguments)]
pub fn plan_chunk_update(
    chunk_id: String,
    user: String,
    version: i64,
    lamport_clock: i64,
    last_writer: String,
    ciphertext: String,
    epoch: i64,
    now: String,
    permit_epoch: i64,
) -> Vec<VaultStmt> {
    vec![VaultStmt::UpdateChunkCas {
        chunk_id,
        user,
        version,
        lamport_clock,
        last_writer,
        ciphertext,
        epoch,
        now,
        permit_epoch,
    }]
}

/// `RekeyIo::read_inventory`.
pub fn plan_read_inventory(user: String, epoch: i64) -> VaultStmt {
    VaultStmt::SelectInventory { user, epoch }
}

/// `RekeyIo::freeze_cas`.
pub fn plan_freeze_cas(
    user: String,
    from_epoch: i64,
    now: String,
    starter: String,
    rotation_id: String,
) -> Vec<VaultStmt> {
    vec![VaultStmt::FreezeCas {
        user,
        from_epoch,
        now,
        starter,
        rotation_id,
    }]
}

/// The freeze transaction after its CAS reported a row: drop every other
/// epoch's chunks.
pub fn plan_freeze_cleanup(user: String, epoch: i64) -> Vec<VaultStmt> {
    vec![VaultStmt::DeleteChunksNotEpoch { user, epoch }]
}

/// The transaction's own commit statement.
pub fn plan_commit_transaction() -> Vec<VaultStmt> {
    vec![VaultStmt::Commit]
}

/// `RekeyIo::commit_cas`.
pub fn plan_commit_cas(
    user: String,
    from_epoch: i64,
    to_epoch: i64,
    starter: String,
    rotation_id: String,
) -> Vec<VaultStmt> {
    vec![VaultStmt::CommitCas {
        user,
        from_epoch,
        to_epoch,
        starter,
        rotation_id,
    }]
}

/// The post-commit sweep of superseded rows (autocommit).
pub fn plan_sweep_old_chunks(user: String, new_epoch: i64) -> Vec<VaultStmt> {
    vec![VaultStmt::DeleteChunksBelowEpoch {
        user,
        epoch: new_epoch,
    }]
}

/// `RekeyIo::rollback_attempt`, the CAS half.
pub fn plan_rollback_cas(user: String, epoch: i64, rotation_id: String) -> Vec<VaultStmt> {
    vec![VaultStmt::RollbackCas {
        user,
        epoch,
        rotation_id,
    }]
}

/// The rollback transaction after its CAS reported a row: drop this attempt's
/// chunks and capsules.
pub fn plan_rollback_cleanup(user: String, epoch: i64, target_epoch: i64) -> Vec<VaultStmt> {
    vec![
        VaultStmt::DeleteChunksAboveEpoch {
            user: user.clone(),
            epoch,
        },
        VaultStmt::ClearAttemptCapsules {
            user,
            epoch: target_epoch,
        },
    ]
}

/// `record_shadow_activity`: the guarded deadline refresh.
pub fn plan_shadow_activity(
    user: String,
    read_epoch: i64,
    starter: String,
    rotation_id: String,
    now: String,
) -> Vec<VaultStmt> {
    vec![VaultStmt::RefreshShadowActivity {
        user,
        read_epoch,
        starter,
        rotation_id,
        now,
    }]
}

/// `RekeyIo::check_oram`.
pub fn plan_probe_oram(user: String) -> VaultStmt {
    VaultStmt::ProbeOram { user }
}

/// `RekeyIo::check_capable`.
pub fn plan_probe_capable(user: String) -> VaultStmt {
    VaultStmt::ProbeCapable { user }
}

/// `RekeyIo::check_acknowledged`.
pub fn plan_probe_acknowledged(user: String) -> VaultStmt {
    VaultStmt::ProbeAcknowledged { user }
}

/// `RekeyIo::check_chunk_shadows`.
pub fn plan_probe_chunk_shadows(user: String, from_epoch: i64, to_epoch: i64) -> VaultStmt {
    VaultStmt::ProbeChunkShadows {
        user,
        from_epoch,
        to_epoch,
    }
}

/// `RekeyIo::check_device_capsules`.
pub fn plan_probe_device_capsules(user: String, to_epoch: i64) -> VaultStmt {
    VaultStmt::ProbeDeviceCapsules { user, to_epoch }
}

/// `RekeyIo::write_capsule`: one guarded device write.
#[allow(clippy::too_many_arguments)]
pub fn plan_write_capsule(
    device: String,
    user: String,
    capsule: String,
    capsule_epoch: i64,
    from_epoch: i64,
    starter: String,
    rotation_id: String,
) -> Vec<VaultStmt> {
    vec![VaultStmt::WriteDeviceCapsule {
        device,
        user,
        capsule,
        capsule_epoch,
        from_epoch,
        starter,
        rotation_id,
    }]
}

/// `CapsuleAckIo::acknowledge`.
pub fn plan_ack_capsule(device: String, user: String, epoch: i64) -> Vec<VaultStmt> {
    vec![VaultStmt::AckDeviceCapsule {
        device,
        user,
        epoch,
    }]
}

/// `CapsuleAckIo::inspect_pending`.
pub fn plan_pending_capsule(device: String, user: String) -> VaultStmt {
    VaultStmt::SelectPendingCapsule { device, user }
}

/// `CapableIo::attest`.
pub fn plan_attest_capable(device: String, user: String) -> Vec<VaultStmt> {
    vec![VaultStmt::AttestCapable { device, user }]
}

/// `ActivateIo::write_floor`: the one durable store write, for `key`.
pub fn plan_schema_floor(key: String) -> Vec<VaultStmt> {
    vec![VaultStmt::SchemaFloorSet { key }]
}

/// The ORAM create path's uniqueness probe.
pub fn plan_oram_exists(
    user: String,
    tree_id: String,
    bucket_index: i64,
    epoch: i64,
) -> VaultStmt {
    VaultStmt::SelectOramBucket {
        user,
        tree_id,
        bucket_index,
        epoch,
    }
}

/// `PutOramIo::write_bucket` for `if_match == 0`.
#[allow(clippy::too_many_arguments)]
pub fn plan_oram_insert(
    user: String,
    tree_id: String,
    bucket_index: i64,
    lamport_clock: i64,
    last_writer: String,
    ciphertext: String,
    epoch: i64,
    now: String,
) -> Vec<VaultStmt> {
    vec![VaultStmt::InsertOramBucket {
        user,
        tree_id,
        bucket_index,
        lamport_clock,
        last_writer,
        ciphertext,
        epoch,
        now,
    }]
}

/// `PutOramIo::write_bucket` for `if_match == version`.
#[allow(clippy::too_many_arguments)]
pub fn plan_oram_update(
    user: String,
    tree_id: String,
    bucket_index: i64,
    version: i64,
    lamport_clock: i64,
    last_writer: String,
    ciphertext: String,
    epoch: i64,
    now: String,
) -> Vec<VaultStmt> {
    vec![VaultStmt::UpdateOramBucketCas {
        user,
        tree_id,
        bucket_index,
        version,
        lamport_clock,
        last_writer,
        ciphertext,
        epoch,
        now,
    }]
}

// ── Classification ─────────────────────────────────────────────────────────

/// `read_version`/`reread_version`: the stored version, missing, or storage.
pub fn classify_version(outcome: &ReadOutcome<Option<i64>>) -> VersionObservation {
    match outcome {
        ReadOutcome::Failed => VersionObservation::Storage,
        ReadOutcome::Rows(Some(version)) => VersionObservation::Found {
            version: *version,
        },
        ReadOutcome::Rows(None) => VersionObservation::Missing,
    }
}

/// `reread_version`: the version the guarded write committed.
pub fn classify_reread(outcome: &ReadOutcome<Option<i64>>) -> RereadObservation {
    match outcome {
        ReadOutcome::Failed => RereadObservation::Failed,
        ReadOutcome::Rows(Some(version)) => RereadObservation::Read {
            version: *version,
        },
        ReadOutcome::Rows(None) => RereadObservation::Missing,
    }
}

/// `delete_row`: deleted only when the one guarded statement changed a row.
pub fn classify_delete(outcomes: &[WriteOutcome]) -> DeleteObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(1) => DeleteObservation::Deleted,
            WriteOutcome::Applied(_) => DeleteObservation::Skipped,
            WriteOutcome::Failed => DeleteObservation::Storage,
        }
    } else {
        DeleteObservation::Storage
    }
}

/// `lookup_chunk`: the observation the read driver consumes. The row cells are
/// the stored truth; `decode_failed` is the handler's row-decoding verdict.
#[allow(clippy::ptr_arg)]
pub fn classify_chunk_read(
    caller: &String,
    read_epoch: i64,
    decode_failed: bool,
    outcome: &ReadOutcome<Option<ChunkRowView>>,
) -> ReadLookupObservation {
    match outcome {
        ReadOutcome::Failed => ReadLookupObservation::QueryFailed,
        ReadOutcome::Rows(None) => ReadLookupObservation::Missing,
        ReadOutcome::Rows(Some(row)) if decode_failed => ReadLookupObservation::Malformed,
        ReadOutcome::Rows(Some(row)) => ReadLookupObservation::Found {
            account_matches: match &row.user_id {
                Some(owner) => owner == caller,
                None => false,
            },
            epoch_matches: row.epoch == Some(read_epoch),
            version: row.version.unwrap_or(0),
            lamport_clock: row.lamport_clock.unwrap_or(0),
        },
    }
}

/// The create path: the uniqueness probe runs first, then the guarded insert.
/// A constraint error after the probe is the concurrent-create conflict.
pub fn classify_chunk_create(
    probe: &ReadOutcome<bool>,
    duplicate: bool,
    outcomes: &[WriteOutcome],
) -> WriteObservation {
    match probe {
        ReadOutcome::Failed => WriteObservation::Failed,
        ReadOutcome::Rows(true) => WriteObservation::Existing,
        ReadOutcome::Rows(false) => {
            if outcomes.len() == 1 {
                match outcomes[0] {
                    WriteOutcome::Applied(1) => WriteObservation::Inserted,
                    WriteOutcome::Applied(_) => WriteObservation::Skipped,
                    WriteOutcome::Failed if duplicate => WriteObservation::Duplicate,
                    WriteOutcome::Failed => WriteObservation::Failed,
                }
            } else {
                WriteObservation::Failed
            }
        }
    }
}

/// The shadow path: the upsert changed its one row, or reported nothing.
pub fn classify_chunk_shadow(outcomes: &[WriteOutcome]) -> WriteObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(1) => WriteObservation::Inserted,
            WriteOutcome::Applied(_) => WriteObservation::Skipped,
            WriteOutcome::Failed => WriteObservation::Failed,
        }
    } else {
        WriteObservation::Failed
    }
}

/// The replace path: a version CAS that changed a row updated it.
pub fn classify_chunk_update(outcomes: &[WriteOutcome]) -> WriteObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(0) => WriteObservation::Skipped,
            WriteOutcome::Applied(_) => WriteObservation::Updated,
            WriteOutcome::Failed => WriteObservation::Failed,
        }
    } else {
        WriteObservation::Failed
    }
}

/// `read_inventory`: the rows at the account's epoch.
pub fn classify_inventory(
    outcome: &ReadOutcome<Vec<InventoryRowView>>,
) -> InventoryObservation {
    match outcome {
        ReadOutcome::Failed => InventoryObservation::Failed,
        ReadOutcome::Rows(_) => InventoryObservation::Read,
    }
}

/// A completeness probe: whether it found a blocking row.
pub fn classify_probe(outcome: &ReadOutcome<bool>) -> ProbeObservation {
    match outcome {
        ReadOutcome::Failed => ProbeObservation::Storage,
        ReadOutcome::Rows(true) => ProbeObservation::Found,
        ReadOutcome::Rows(false) => ProbeObservation::Empty,
    }
}

/// The freeze CAS.
pub fn classify_freeze_cas(outcomes: &[WriteOutcome]) -> CasObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(1) => CasObservation::Updated,
            WriteOutcome::Applied(_) => CasObservation::Skipped,
            WriteOutcome::Failed => CasObservation::Storage,
        }
    } else {
        CasObservation::Storage
    }
}

/// A transaction's commit.
pub fn classify_transaction(outcomes: &[WriteOutcome]) -> TransactionObservation {
    if outcomes.len() == 0 {
        TransactionObservation::Failed
    } else {
        match outcomes[outcomes.len() - 1] {
            WriteOutcome::Applied(_) => TransactionObservation::Committed,
            WriteOutcome::Failed => TransactionObservation::Failed,
        }
    }
}

/// The freeze transaction's cleanup.
pub fn classify_cleanup(outcomes: &[WriteOutcome]) -> CleanupObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(_) => CleanupObservation::Done,
            WriteOutcome::Failed => CleanupObservation::Storage,
        }
    } else {
        CleanupObservation::Storage
    }
}

/// The post-commit sweep.
pub fn classify_sweep(outcomes: &[WriteOutcome]) -> SweepObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(_) => SweepObservation::Done,
            WriteOutcome::Failed => SweepObservation::Failed,
        }
    } else {
        SweepObservation::Failed
    }
}

/// The abort/timeout transaction: four statements (the CAS, the chunk delete,
/// the capsule clear and the commit). Rolled back only when the CAS changed the
/// account row and the cleanup and commit followed.
pub fn classify_rollback(outcomes: &[WriteOutcome]) -> RollbackObservation {
    if outcomes.is_empty() {
        return RollbackObservation::Storage;
    }
    match outcomes[0] {
        WriteOutcome::Failed => RollbackObservation::Storage,
        WriteOutcome::Applied(0) => RollbackObservation::Raced,
        WriteOutcome::Applied(_) => {
            if outcomes.len() == 4 {
                match outcomes[1] {
                    WriteOutcome::Failed => RollbackObservation::Storage,
                    WriteOutcome::Applied(_) => match outcomes[2] {
                        WriteOutcome::Failed => RollbackObservation::Storage,
                        WriteOutcome::Applied(_) => match outcomes[3] {
                            WriteOutcome::Applied(_) => RollbackObservation::RolledBack,
                            WriteOutcome::Failed => RollbackObservation::Storage,
                        },
                    },
                }
            } else {
                RollbackObservation::Storage
            }
        }
    }
}

/// `record_shadow_activity`: refreshed only when the guarded refresh matched.
pub fn classify_shadow_activity(outcomes: &[WriteOutcome]) -> ActivityObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(1) => ActivityObservation::Refreshed,
            WriteOutcome::Applied(_) => ActivityObservation::Ended,
            WriteOutcome::Failed => ActivityObservation::Failed,
        }
    } else {
        ActivityObservation::Failed
    }
}

/// `write_capsule`: stored only when the guarded device update matched.
pub fn classify_capsule_write(outcomes: &[WriteOutcome]) -> CapsuleObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(0) => CapsuleObservation::NotTarget,
            WriteOutcome::Applied(_) => CapsuleObservation::Stored,
            WriteOutcome::Failed => CapsuleObservation::Storage,
        }
    } else {
        CapsuleObservation::Storage
    }
}

/// `inspect_pending`: a missing row, a pending epoch, or a replay.
pub fn classify_pending(outcome: &ReadOutcome<Option<PendingRowView>>) -> PendingObservation {
    match outcome {
        ReadOutcome::Failed => PendingObservation::Storage,
        ReadOutcome::Rows(None) => PendingObservation::Missing,
        ReadOutcome::Rows(Some(row)) if row.epoch.is_some() => PendingObservation::Pending,
        ReadOutcome::Rows(Some(_)) => PendingObservation::Replay,
    }
}

/// `acknowledge`: cleared only when the guarded clear matched the epoch.
pub fn classify_ack(outcomes: &[WriteOutcome]) -> AckObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(1) => AckObservation::Cleared,
            WriteOutcome::Applied(_) => AckObservation::Missed,
            WriteOutcome::Failed => AckObservation::Storage,
        }
    } else {
        AckObservation::Storage
    }
}

/// `attest`: attested only when the guarded update matched the live device.
pub fn classify_attest(outcomes: &[WriteOutcome]) -> AttestObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(1) => AttestObservation::Attested,
            WriteOutcome::Applied(_) => AttestObservation::Missing,
            WriteOutcome::Failed => AttestObservation::Storage,
        }
    } else {
        AttestObservation::Storage
    }
}

/// `write_floor`: the one durable store write.
pub fn classify_schema_write(outcomes: &[WriteOutcome]) -> SchemaWriteObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(_) => SchemaWriteObservation::Written,
            WriteOutcome::Failed => SchemaWriteObservation::Storage,
        }
    } else {
        SchemaWriteObservation::Storage
    }
}

/// The ORAM create path: the uniqueness probe, then the guarded insert.
pub fn classify_oram_create(
    probe: &ReadOutcome<bool>,
    outcomes: &[WriteOutcome],
) -> BucketObservation {
    match probe {
        ReadOutcome::Failed => BucketObservation::Storage,
        ReadOutcome::Rows(true) => BucketObservation::Existing,
        ReadOutcome::Rows(false) => {
            if outcomes.len() == 1 {
                match outcomes[0] {
                    WriteOutcome::Applied(1) => BucketObservation::Written,
                    WriteOutcome::Applied(_) => BucketObservation::Skipped,
                    WriteOutcome::Failed => BucketObservation::Storage,
                }
            } else {
                BucketObservation::Storage
            }
        }
    }
}

/// The ORAM replace path: a version CAS on the bucket row.
pub fn classify_oram_update(outcomes: &[WriteOutcome]) -> BucketObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(0) => BucketObservation::Skipped,
            WriteOutcome::Applied(_) => BucketObservation::Written,
            WriteOutcome::Failed => BucketObservation::Storage,
        }
    } else {
        BucketObservation::Storage
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

/// A bound parameter, with its SQL type.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlParam {
    Text(String),
    Int(i64),
}

/// One statement as the database or store receives it.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rendered {
    /// A read (`query`).
    Query {
        sql: &'static str,
        params: Vec<SqlParam>,
    },
    /// A write (`execute`).
    Execute {
        sql: &'static str,
        params: Vec<SqlParam>,
    },
    /// A durable key-value write in the sled store.
    KvSet {
        key: String,
        value: &'static [u8],
    },
    /// `COMMIT` on the open transaction.
    Commit,
}

/// The exact SQL text and parameters each statement has always used.
#[cfg(not(hax))]
pub fn render(stmt: &VaultStmt) -> Rendered {
    use SqlParam::{Int, Text};
    match stmt {
        VaultStmt::SelectChunkVersion {
            chunk_id,
            user,
            epoch,
        } => Rendered::Query {
            sql: "SELECT version FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            params: vec![Text(chunk_id.clone()), Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::SelectChunkRow {
            chunk_id,
            user,
            epoch,
        } => Rendered::Query {
            sql: "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch
         FROM vault_chunks
         WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            params: vec![Text(chunk_id.clone()), Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::SelectChunkExists {
            chunk_id,
            user,
            epoch,
        } => Rendered::Query {
            sql: "SELECT 1 FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            params: vec![Text(chunk_id.clone()), Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::InsertChunkCreate {
            chunk_id,
            user,
            lamport_clock,
            last_writer,
            ciphertext,
            epoch,
            now,
            permit_epoch,
        } => Rendered::Execute {
            sql: "INSERT INTO vault_chunks
             (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
             SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            params: vec![
                Text(chunk_id.clone()),
                Text(user.clone()),
                Int(*lamport_clock),
                Text(last_writer.clone()),
                Text(ciphertext.clone()),
                Int(*epoch),
                Text(now.clone()),
                Text(now.clone()),
                Text(user.clone()),
                Int(*permit_epoch),
            ],
        },
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
        } => Rendered::Execute {
            sql: "INSERT INTO vault_chunks
                 (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
                 SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
                 WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
                   AND rekey_starter = ? AND rekey_id = ?
                 ON CONFLICT(user_id, chunk_id, epoch) DO UPDATE SET
                     version       = version + 1,
                     lamport_clock = excluded.lamport_clock,
                     last_writer   = excluded.last_writer,
                     ciphertext    = excluded.ciphertext,
                     updated_at    = excluded.updated_at",
            params: vec![
                Text(chunk_id.clone()),
                Text(user.clone()),
                Int(*lamport_clock),
                Text(last_writer.clone()),
                Text(ciphertext.clone()),
                Int(*epoch),
                Text(now.clone()),
                Text(now.clone()),
                Text(user.clone()),
                Int(*read_epoch),
                Text(starter.clone()),
                Text(rotation_id.clone()),
            ],
        },
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
        } => Rendered::Execute {
            sql: "UPDATE vault_chunks
             SET version       = version + 1,
                 lamport_clock = ?,
                 last_writer   = ?,
                 ciphertext    = ?,
                 updated_at    = ?
             WHERE chunk_id = ?
               AND user_id  = ?
               AND version  = ?
               AND epoch    = ?
               AND EXISTS (
                 SELECT 1 FROM users
                 WHERE users.id = vault_chunks.user_id
                   AND users.key_epoch = ? AND users.rekey_state IS NULL
               )",
            params: vec![
                Int(*lamport_clock),
                Text(last_writer.clone()),
                Text(ciphertext.clone()),
                Text(now.clone()),
                Text(chunk_id.clone()),
                Text(user.clone()),
                Int(*version),
                Int(*epoch),
                Int(*permit_epoch),
            ],
        },
        VaultStmt::DeleteChunkCas {
            chunk_id,
            user,
            epoch,
        } => Rendered::Execute {
            sql: "DELETE FROM vault_chunks
             WHERE chunk_id = ? AND user_id = ? AND epoch = ?
               AND EXISTS (
                 SELECT 1 FROM users
                 WHERE users.id = vault_chunks.user_id
                   AND users.key_epoch = ? AND users.rekey_state IS NULL
               )",
            params: vec![
                Text(chunk_id.clone()),
                Text(user.clone()),
                Int(*epoch),
                Int(*epoch),
            ],
        },
        VaultStmt::SelectInventory { user, epoch } => Rendered::Query {
            sql: "SELECT chunk_id, version, lamport_clock FROM vault_chunks
             WHERE user_id = ? AND epoch = ? ORDER BY chunk_id",
            params: vec![Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::DeleteChunksNotEpoch { user, epoch } => Rendered::Execute {
            sql: "DELETE FROM vault_chunks WHERE user_id = ? AND epoch != ?",
            params: vec![Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::DeleteChunksAboveEpoch { user, epoch } => Rendered::Execute {
            sql: "DELETE FROM vault_chunks WHERE user_id = ? AND epoch > ?",
            params: vec![Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::DeleteChunksBelowEpoch { user, epoch } => Rendered::Execute {
            sql: "DELETE FROM vault_chunks WHERE user_id = ? AND epoch < ?",
            params: vec![Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::FreezeCas {
            user,
            from_epoch,
            now,
            starter,
            rotation_id,
        } => Rendered::Execute {
            sql: "UPDATE users SET rekey_state = 'freezing', rekey_started_at = ?,
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
            params: vec![
                Text(now.clone()),
                Text(starter.clone()),
                Text(rotation_id.clone()),
                Text(user.clone()),
                Int(*from_epoch),
            ],
        },
        VaultStmt::CommitCas {
            user,
            from_epoch,
            to_epoch,
            starter,
            rotation_id,
        } => Rendered::Execute {
            sql: "UPDATE users SET key_epoch = ?, rekey_state = NULL,
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
            params: vec![
                Int(*to_epoch),
                Text(rotation_id.clone()),
                Int(*to_epoch),
                Text(user.clone()),
                Int(*from_epoch),
                Text(starter.clone()),
                Text(rotation_id.clone()),
                Int(*from_epoch),
                Int(*to_epoch),
                Int(*to_epoch),
            ],
        },
        VaultStmt::RollbackCas {
            user,
            epoch,
            rotation_id,
        } => Rendered::Execute {
            sql: "UPDATE users SET rekey_state = NULL, rekey_started_at = NULL,
                    rekey_starter = NULL, rekey_id = NULL
                 WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
                   AND rekey_id = ?",
            params: vec![
                Text(user.clone()),
                Int(*epoch),
                Text(rotation_id.clone()),
            ],
        },
        VaultStmt::RefreshShadowActivity {
            user,
            read_epoch,
            starter,
            rotation_id,
            now,
        } => Rendered::Execute {
            sql: "UPDATE users SET rekey_started_at = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
               AND rekey_starter = ? AND rekey_id = ?",
            params: vec![
                Text(now.clone()),
                Text(user.clone()),
                Int(*read_epoch),
                Text(starter.clone()),
                Text(rotation_id.clone()),
            ],
        },
        VaultStmt::ClearAttemptCapsules { user, epoch } => Rendered::Execute {
            sql: "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
                 WHERE user_id = ? AND rms_capsule_epoch = ?",
            params: vec![Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::WriteDeviceCapsule {
            device,
            user,
            capsule,
            capsule_epoch,
            from_epoch,
            starter,
            rotation_id,
        } => Rendered::Execute {
            sql: "UPDATE devices SET rms_capsule = ?, rms_capsule_epoch = ?
                 WHERE id = ? AND user_id = ? AND revoked = 0
                   AND EXISTS (
                     SELECT 1 FROM users
                      WHERE users.id = devices.user_id
                        AND users.key_epoch = ?
                        AND users.rekey_state = 'freezing'
                        AND users.rekey_starter = ?
                        AND users.rekey_id = ?
                   )",
            params: vec![
                Text(capsule.clone()),
                Int(*capsule_epoch),
                Text(device.clone()),
                Text(user.clone()),
                Int(*from_epoch),
                Text(starter.clone()),
                Text(rotation_id.clone()),
            ],
        },
        VaultStmt::SelectPendingCapsule { device, user } => Rendered::Query {
            sql: "SELECT rms_capsule_epoch FROM devices
                 WHERE id = ? AND user_id = ? AND revoked = 0",
            params: vec![Text(device.clone()), Text(user.clone())],
        },
        VaultStmt::AckDeviceCapsule {
            device,
            user,
            epoch,
        } => Rendered::Execute {
            sql: "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
             WHERE id = ? AND user_id = ? AND revoked = 0 AND rms_capsule_epoch = ?",
            params: vec![Text(device.clone()), Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::AttestCapable { device, user } => Rendered::Execute {
            sql: "UPDATE devices SET rekey_capable = 1
             WHERE id = ? AND user_id = ? AND revoked = 0",
            params: vec![Text(device.clone()), Text(user.clone())],
        },
        VaultStmt::ProbeOram { user } => Rendered::Query {
            sql: "SELECT 1 FROM oram_buckets WHERE user_id = ? LIMIT 1",
            params: vec![Text(user.clone())],
        },
        VaultStmt::ProbeCapable { user } => Rendered::Query {
            sql: "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0 AND rekey_capable = 0 LIMIT 1",
            params: vec![Text(user.clone())],
        },
        VaultStmt::ProbeAcknowledged { user } => Rendered::Query {
            sql: "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0 AND rms_capsule_epoch IS NOT NULL
             LIMIT 1",
            params: vec![Text(user.clone())],
        },
        VaultStmt::ProbeChunkShadows {
            user,
            from_epoch,
            to_epoch,
        } => Rendered::Query {
            sql: "SELECT 1 FROM vault_chunks old
             WHERE old.user_id = ? AND old.epoch = ?
               AND NOT EXISTS (
                 SELECT 1 FROM vault_chunks new
                 WHERE new.user_id = old.user_id
                   AND new.chunk_id = old.chunk_id
                   AND new.epoch = ?
               )
             LIMIT 1",
            params: vec![Text(user.clone()), Int(*from_epoch), Int(*to_epoch)],
        },
        VaultStmt::ProbeDeviceCapsules { user, to_epoch } => Rendered::Query {
            sql: "SELECT 1 FROM devices
             WHERE user_id = ? AND revoked = 0
               AND (rekey_capable = 0 OR rms_capsule IS NULL OR rms_capsule_epoch != ?)
             LIMIT 1",
            params: vec![Text(user.clone()), Int(*to_epoch)],
        },
        VaultStmt::SelectOramBucket {
            user,
            tree_id,
            bucket_index,
            epoch,
        } => Rendered::Query {
            sql: "SELECT 1 FROM oram_buckets
                 WHERE user_id = ? AND tree_id = ? AND bucket_index = ? AND epoch = ?",
            params: vec![
                Text(user.clone()),
                Text(tree_id.clone()),
                Int(*bucket_index),
                Int(*epoch),
            ],
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
        } => Rendered::Execute {
            sql: "INSERT INTO oram_buckets
                 (user_id, tree_id, bucket_index, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
                 SELECT ?, ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
                 WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            params: vec![
                Text(user.clone()),
                Text(tree_id.clone()),
                Int(*bucket_index),
                Int(*lamport_clock),
                Text(last_writer.clone()),
                Text(ciphertext.clone()),
                Int(*epoch),
                Text(now.clone()),
                Text(now.clone()),
                Text(user.clone()),
                Int(*epoch),
            ],
        },
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
        } => Rendered::Execute {
            sql: "UPDATE oram_buckets
                 SET version = version + 1,
                     lamport_clock = ?,
                     last_writer = ?,
                     ciphertext = ?,
                     updated_at = ?
                 WHERE user_id = ?
                   AND tree_id = ?
                   AND bucket_index = ?
                   AND version = ?
                   AND epoch = ?
                   AND EXISTS (
                     SELECT 1 FROM users
                     WHERE users.id = oram_buckets.user_id
                       AND users.key_epoch = ? AND users.rekey_state IS NULL
                   )",
            params: vec![
                Int(*lamport_clock),
                Text(last_writer.clone()),
                Text(ciphertext.clone()),
                Text(now.clone()),
                Text(user.clone()),
                Text(tree_id.clone()),
                Int(*bucket_index),
                Int(*version),
                Int(*epoch),
                Int(*epoch),
            ],
        },
        VaultStmt::SchemaFloorSet { key } => Rendered::KvSet {
            key: key.clone(),
            value: b"2",
        },
        VaultStmt::Commit => Rendered::Commit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn exec(stmt: &VaultStmt) -> (&'static str, Vec<SqlParam>) {
        match render(stmt) {
            Rendered::Execute { sql, params } => (sql, params),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    fn query(stmt: &VaultStmt) -> (&'static str, Vec<SqlParam>) {
        match render(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    fn t(x: &str) -> SqlParam {
        SqlParam::Text(s(x))
    }

    // The expected strings are byte-for-byte copies of the literals the
    // handlers used before the split, including line breaks and indentation.

    #[test]
    fn chunk_plans_render_the_historical_statements() {
        let delete = plan_delete_chunk(s("c"), s("u"), 3);
        assert_eq!(delete.len(), 1);
        assert_eq!(
            exec(&delete[0]),
            (
                "DELETE FROM vault_chunks\n             WHERE chunk_id = ? AND user_id = ? AND epoch = ?\n               AND EXISTS (\n                 SELECT 1 FROM users\n                 WHERE users.id = vault_chunks.user_id\n                   AND users.key_epoch = ? AND users.rekey_state IS NULL\n               )",
                vec![t("c"), t("u"), SqlParam::Int(3), SqlParam::Int(3)]
            )
        );
        assert_eq!(
            query(&plan_read_version(s("c"), s("u"), 3)),
            (
                "SELECT version FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                vec![t("c"), t("u"), SqlParam::Int(3)]
            )
        );
        assert_eq!(
            query(&plan_read_chunk(s("c"), s("u"), 3)),
            (
                "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch\n         FROM vault_chunks\n         WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                vec![t("c"), t("u"), SqlParam::Int(3)]
            )
        );
        assert_eq!(
            query(&plan_chunk_exists(s("c"), s("u"), 3)),
            (
                "SELECT 1 FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                vec![t("c"), t("u"), SqlParam::Int(3)]
            )
        );
    }

    #[test]
    fn chunk_writes_render_the_historical_statements() {
        let create = plan_chunk_create(
            s("c"),
            s("u"),
            7,
            s("d"),
            s("ct"),
            3,
            s("now"),
            3,
        );
        assert_eq!(
            exec(&create[0]),
            (
                "INSERT INTO vault_chunks\n             (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)\n             SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users\n             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
                vec![
                    t("c"),
                    t("u"),
                    SqlParam::Int(7),
                    t("d"),
                    t("ct"),
                    SqlParam::Int(3),
                    t("now"),
                    t("now"),
                    t("u"),
                    SqlParam::Int(3)
                ]
            )
        );
        let shadow = plan_chunk_shadow(
            s("c"),
            s("u"),
            7,
            s("d"),
            s("ct"),
            4,
            s("now"),
            3,
            s("d"),
            s("r"),
        );
        assert_eq!(
            exec(&shadow[0]),
            (
                "INSERT INTO vault_chunks\n                 (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)\n                 SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users\n                 WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'\n                   AND rekey_starter = ? AND rekey_id = ?\n                 ON CONFLICT(user_id, chunk_id, epoch) DO UPDATE SET\n                     version       = version + 1,\n                     lamport_clock = excluded.lamport_clock,\n                     last_writer   = excluded.last_writer,\n                     ciphertext    = excluded.ciphertext,\n                     updated_at    = excluded.updated_at",
                vec![
                    t("c"),
                    t("u"),
                    SqlParam::Int(7),
                    t("d"),
                    t("ct"),
                    SqlParam::Int(4),
                    t("now"),
                    t("now"),
                    t("u"),
                    SqlParam::Int(3),
                    t("d"),
                    t("r")
                ]
            )
        );
        let update = plan_chunk_update(
            s("c"),
            s("u"),
            2,
            7,
            s("d"),
            s("ct"),
            3,
            s("now"),
            3,
        );
        assert_eq!(
            exec(&update[0]),
            (
                "UPDATE vault_chunks\n             SET version       = version + 1,\n                 lamport_clock = ?,\n                 last_writer   = ?,\n                 ciphertext    = ?,\n                 updated_at    = ?\n             WHERE chunk_id = ?\n               AND user_id  = ?\n               AND version  = ?\n               AND epoch    = ?\n               AND EXISTS (\n                 SELECT 1 FROM users\n                 WHERE users.id = vault_chunks.user_id\n                   AND users.key_epoch = ? AND users.rekey_state IS NULL\n               )",
                vec![
                    SqlParam::Int(7),
                    t("d"),
                    t("ct"),
                    t("now"),
                    t("c"),
                    t("u"),
                    SqlParam::Int(2),
                    SqlParam::Int(3),
                    SqlParam::Int(3)
                ]
            )
        );
    }

    #[test]
    fn rekey_plans_render_the_historical_statements() {
        let freeze = plan_freeze_cas(s("u"), 3, s("now"), s("d"), s("r"));
        assert_eq!(freeze.len(), 1);
        assert_eq!(
            exec(&freeze[0]).0,
            "UPDATE users SET rekey_state = 'freezing', rekey_started_at = ?,\n                rekey_starter = ?, rekey_id = ?\n             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL\n               AND NOT EXISTS (\n                 SELECT 1 FROM oram_buckets WHERE user_id = users.id\n               )\n               AND NOT EXISTS (\n                 SELECT 1 FROM devices\n                  WHERE user_id = users.id AND revoked = 0\n                    AND rekey_capable = 0\n               )\n               AND NOT EXISTS (\n                 SELECT 1 FROM devices\n                  WHERE user_id = users.id AND revoked = 0\n                    AND rms_capsule_epoch IS NOT NULL\n               )"
        );
        let commit = plan_commit_cas(s("u"), 3, 4, s("d"), s("r"));
        assert_eq!(
            exec(&commit[0]).0,
            "UPDATE users SET key_epoch = ?, rekey_state = NULL,\n             rekey_started_at = NULL, rekey_starter = NULL, rekey_id = NULL,\n             last_rekey_id = ?, last_rekey_epoch = ?,\n             recovery_share = NULL, recovery_split_id = NULL,\n             recovery_pending_share = NULL, recovery_pending_split_id = NULL,\n             recovery_pending_epoch = NULL, recovery_auth_hash = NULL,\n             recovery_pending_auth_hash = NULL\n         WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'\n           AND rekey_starter = ? AND rekey_id = ?\n           AND NOT EXISTS (\n             SELECT 1 FROM vault_chunks old\n             WHERE old.user_id = users.id AND old.epoch = ?\n               AND NOT EXISTS (\n                 SELECT 1 FROM vault_chunks new\n                 WHERE new.user_id = old.user_id\n                   AND new.chunk_id = old.chunk_id AND new.epoch = ?\n               )\n           )\n           AND NOT EXISTS (\n             SELECT 1 FROM devices\n             WHERE user_id = users.id AND revoked = 0\n               AND (rekey_capable = 0 OR rms_capsule IS NULL OR rms_capsule_epoch != ?)\n           )"
        );
        let rollback = plan_rollback_cas(s("u"), 3, s("r"));
        assert_eq!(
            exec(&rollback[0]).0,
            "UPDATE users SET rekey_state = NULL, rekey_started_at = NULL,\n                    rekey_starter = NULL, rekey_id = NULL\n                 WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'\n                   AND rekey_id = ?"
        );
        assert_eq!(
            exec(&plan_sweep_old_chunks(s("u"), 4)[0]).0,
            "DELETE FROM vault_chunks WHERE user_id = ? AND epoch < ?"
        );
        assert_eq!(
            exec(&plan_freeze_cleanup(s("u"), 3)[0]).0,
            "DELETE FROM vault_chunks WHERE user_id = ? AND epoch != ?"
        );
        assert_eq!(
            exec(&plan_rollback_cleanup(s("u"), 3, 4)[0]).0,
            "DELETE FROM vault_chunks WHERE user_id = ? AND epoch > ?"
        );
        assert_eq!(render(&plan_commit_transaction()[0]), Rendered::Commit);
        assert_eq!(
            query(&plan_read_inventory(s("u"), 3)).0,
            "SELECT chunk_id, version, lamport_clock FROM vault_chunks\n             WHERE user_id = ? AND epoch = ? ORDER BY chunk_id"
        );
        assert_eq!(
            exec(&plan_shadow_activity(s("u"), 3, s("d"), s("r"), s("now"))[0]).0,
            "UPDATE users SET rekey_started_at = ?\n             WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'\n               AND rekey_starter = ? AND rekey_id = ?"
        );
    }

    #[test]
    fn probes_render_the_historical_statements() {
        assert_eq!(
            query(&plan_probe_oram(s("u"))).0,
            "SELECT 1 FROM oram_buckets WHERE user_id = ? LIMIT 1"
        );
        assert_eq!(
            query(&plan_probe_capable(s("u"))).0,
            "SELECT 1 FROM devices\n             WHERE user_id = ? AND revoked = 0 AND rekey_capable = 0 LIMIT 1"
        );
        assert_eq!(
            query(&plan_probe_acknowledged(s("u"))).0,
            "SELECT 1 FROM devices\n             WHERE user_id = ? AND revoked = 0 AND rms_capsule_epoch IS NOT NULL\n             LIMIT 1"
        );
        assert_eq!(
            query(&plan_probe_chunk_shadows(s("u"), 3, 4)).0,
            "SELECT 1 FROM vault_chunks old\n             WHERE old.user_id = ? AND old.epoch = ?\n               AND NOT EXISTS (\n                 SELECT 1 FROM vault_chunks new\n                 WHERE new.user_id = old.user_id\n                   AND new.chunk_id = old.chunk_id\n                   AND new.epoch = ?\n               )\n             LIMIT 1"
        );
        assert_eq!(
            query(&plan_probe_device_capsules(s("u"), 4)).0,
            "SELECT 1 FROM devices\n             WHERE user_id = ? AND revoked = 0\n               AND (rekey_capable = 0 OR rms_capsule IS NULL OR rms_capsule_epoch != ?)\n             LIMIT 1"
        );
    }

    #[test]
    fn capsule_capable_and_oram_plans_render_the_historical_statements() {
        let ack = plan_ack_capsule(s("d"), s("u"), 4);
        assert_eq!(
            exec(&ack[0]),
            (
                "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL\n             WHERE id = ? AND user_id = ? AND revoked = 0 AND rms_capsule_epoch = ?",
                vec![t("d"), t("u"), SqlParam::Int(4)]
            )
        );
        assert_eq!(
            query(&plan_pending_capsule(s("d"), s("u"))).0,
            "SELECT rms_capsule_epoch FROM devices\n                 WHERE id = ? AND user_id = ? AND revoked = 0"
        );
        assert_eq!(
            exec(&plan_attest_capable(s("d"), s("u"))[0]).0,
            "UPDATE devices SET rekey_capable = 1\n             WHERE id = ? AND user_id = ? AND revoked = 0"
        );
        let capsule = plan_write_capsule(s("d"), s("u"), s("cap"), 4, 3, s("d"), s("r"));
        assert_eq!(
            exec(&capsule[0]).0,
            "UPDATE devices SET rms_capsule = ?, rms_capsule_epoch = ?\n                 WHERE id = ? AND user_id = ? AND revoked = 0\n                   AND EXISTS (\n                     SELECT 1 FROM users\n                      WHERE users.id = devices.user_id\n                        AND users.key_epoch = ?\n                        AND users.rekey_state = 'freezing'\n                        AND users.rekey_starter = ?\n                        AND users.rekey_id = ?\n                   )"
        );
        assert_eq!(
            query(&plan_oram_exists(s("u"), s("t"), 5, 3)).0,
            "SELECT 1 FROM oram_buckets\n                 WHERE user_id = ? AND tree_id = ? AND bucket_index = ? AND epoch = ?"
        );
        assert_eq!(
            exec(&plan_oram_insert(s("u"), s("t"), 5, 9, s("d"), s("ct"), 3, s("now"))[0]).0,
            "INSERT INTO oram_buckets\n                 (user_id, tree_id, bucket_index, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)\n                 SELECT ?, ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users\n                 WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL"
        );
        assert_eq!(
            exec(&plan_oram_update(s("u"), s("t"), 5, 2, 9, s("d"), s("ct"), 3, s("now"))[0]).0,
            "UPDATE oram_buckets\n                 SET version = version + 1,\n                     lamport_clock = ?,\n                     last_writer = ?,\n                     ciphertext = ?,\n                     updated_at = ?\n                 WHERE user_id = ?\n                   AND tree_id = ?\n                   AND bucket_index = ?\n                   AND version = ?\n                   AND epoch = ?\n                   AND EXISTS (\n                     SELECT 1 FROM users\n                     WHERE users.id = oram_buckets.user_id\n                       AND users.key_epoch = ? AND users.rekey_state IS NULL\n                   )"
        );
        assert_eq!(
            render(&plan_schema_floor(s("vault-schema:u"))[0]),
            Rendered::KvSet {
                key: s("vault-schema:u"),
                value: b"2"
            }
        );
    }

    #[test]
    fn classifiers_keep_the_historical_observations() {
        use WriteOutcome::{Applied, Failed};
        assert_eq!(
            classify_delete(&[Applied(1)]),
            DeleteObservation::Deleted
        );
        assert_eq!(classify_delete(&[Applied(0)]), DeleteObservation::Skipped);
        assert_eq!(classify_delete(&[Failed]), DeleteObservation::Storage);
        assert_eq!(
            classify_version(&ReadOutcome::Rows(Some(5))),
            VersionObservation::Found { version: 5 }
        );
        assert_eq!(
            classify_version(&ReadOutcome::Rows(None)),
            VersionObservation::Missing
        );
        assert_eq!(
            classify_version(&ReadOutcome::Failed),
            VersionObservation::Storage
        );
        // The create path: probe first, then the insert.
        assert_eq!(
            classify_chunk_create(&ReadOutcome::Rows(true), false, &[]),
            WriteObservation::Existing
        );
        assert_eq!(
            classify_chunk_create(&ReadOutcome::Rows(false), false, &[Applied(1)]),
            WriteObservation::Inserted
        );
        assert_eq!(
            classify_chunk_create(&ReadOutcome::Rows(false), false, &[Applied(0)]),
            WriteObservation::Skipped
        );
        assert_eq!(
            classify_chunk_create(&ReadOutcome::Rows(false), true, &[Failed]),
            WriteObservation::Duplicate
        );
        assert_eq!(
            classify_chunk_create(&ReadOutcome::Rows(false), false, &[Failed]),
            WriteObservation::Failed
        );
        assert_eq!(
            classify_chunk_shadow(&[Applied(1)]),
            WriteObservation::Inserted
        );
        assert_eq!(
            classify_chunk_update(&[Applied(0)]),
            WriteObservation::Skipped
        );
        assert_eq!(
            classify_chunk_update(&[Applied(1)]),
            WriteObservation::Updated
        );
        assert_eq!(
            classify_ack(&[Applied(1)]),
            AckObservation::Cleared
        );
        assert_eq!(classify_ack(&[Applied(0)]), AckObservation::Missed);
        assert_eq!(classify_attest(&[Applied(0)]), AttestObservation::Missing);
        assert_eq!(
            classify_attest(&[Applied(1)]),
            AttestObservation::Attested
        );
        assert_eq!(
            classify_pending(&ReadOutcome::Rows(None)),
            PendingObservation::Missing
        );
        assert_eq!(
            classify_pending(&ReadOutcome::Rows(Some(PendingRowView { epoch: Some(4) }))),
            PendingObservation::Pending
        );
        assert_eq!(
            classify_pending(&ReadOutcome::Rows(Some(PendingRowView { epoch: None }))),
            PendingObservation::Replay
        );
        assert_eq!(
            classify_schema_write(&[Applied(0)]),
            SchemaWriteObservation::Written
        );
        assert_eq!(
            classify_freeze_cas(&[Applied(1)]),
            CasObservation::Updated
        );
        assert_eq!(classify_freeze_cas(&[Applied(0)]), CasObservation::Skipped);
        assert_eq!(
            classify_rollback(&[Applied(1), Applied(2), Applied(1), Applied(0)]),
            RollbackObservation::RolledBack
        );
        // The rollback transaction is four statements; a shorter list is not
        // the transaction the server runs.
        assert_eq!(
            classify_rollback(&[Applied(1), Applied(2), Applied(0)]),
            RollbackObservation::Storage
        );
        assert_eq!(
            classify_rollback(&[Applied(0)]),
            RollbackObservation::Raced
        );
        assert_eq!(
            classify_capsule_write(&[Applied(1)]),
            CapsuleObservation::Stored
        );
        assert_eq!(
            classify_capsule_write(&[Applied(0)]),
            CapsuleObservation::NotTarget
        );
        assert_eq!(
            classify_oram_create(&ReadOutcome::Rows(true), &[]),
            BucketObservation::Existing
        );
        assert_eq!(
            classify_oram_create(&ReadOutcome::Rows(false), &[Applied(1)]),
            BucketObservation::Written
        );
        assert_eq!(
            classify_oram_update(&[Applied(0)]),
            BucketObservation::Skipped
        );
        assert_eq!(
            classify_probe(&ReadOutcome::Rows(true)),
            ProbeObservation::Found
        );
        assert_eq!(
            classify_probe(&ReadOutcome::Rows(false)),
            ProbeObservation::Empty
        );
        assert_eq!(
            classify_shadow_activity(&[Applied(0)]),
            ActivityObservation::Ended
        );
    }
}
