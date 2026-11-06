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
    ProbeObservation, RateLimitObservation, RollbackObservation, SweepObservation,
    TransactionObservation,
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
    /// F-1 wave 2: the key-state row `load_key_state` reads. It backs
    /// `load_state`, `maybe_rollback`, `resolve_write_epoch`, `read_epoch`,
    /// `shadow_authority`, and through them the upload and ORAM rechecks.
    SelectKeyState { user: String },
    /// `current_usage_bytes`: the stored chunk ciphertext bytes at the
    /// account's served epoch.
    SelectUsageChunks { user: String },
    /// `current_usage_bytes`: the stored ORAM ciphertext bytes at the
    /// account's served epoch.
    SelectUsageOram { user: String },
    /// `enforce_rekey_shadow_quota`: the projected stored bytes after a
    /// rotation replaces `chunk_id` at `epoch`.
    SelectRekeyProjection {
        user: String,
        epoch: i64,
        chunk_id: String,
    },
    /// `get_path`'s per-bucket read.
    SelectOramRow {
        user: String,
        tree_id: String,
        bucket_index: i64,
        epoch: i64,
    },
    /// `get_sync`'s chunk manifest at the served epoch.
    SelectSyncManifest { user: String, epoch: i64 },
    /// `schema::minimum`'s store read of the account's compatibility floor.
    SchemaFloorGet { key: String },
    /// Open the pinned transaction (`POST /vault/rekey/start` and
    /// `GET /device/capsule`).
    BeginTransaction,
    /// `get_capsule`'s device-and-account read of a pending RMS capsule.
    SelectCapsule { device: String, user: String },
    /// `get_capsule`'s read-once clear of an enrollment capsule.
    ClearEnrollmentCapsule { device: String, user: String },
    /// F-1 wave 2: one fixed-window counter increment for the per-account
    /// re-key pacing limiter (`rate_limit::check`): the store grows the count
    /// at `key` by one and the request is refused once the new count exceeds
    /// `limit`. The window is the store's scheduler choice.
    RateLimitIncr {
        key: String,
        limit: u64,
        window_secs: i64,
    },
    /// `list_devices`' device listing.
    SelectDeviceList { user: String },
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

/// The seven rotation cells of a `users` row `load_key_state` reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyStateView {
    pub key_epoch: Option<i64>,
    pub rekey_state: Option<String>,
    pub rekey_started_at: Option<String>,
    pub rekey_starter: Option<String>,
    pub rekey_id: Option<String>,
    pub last_rekey_id: Option<String>,
    pub last_rekey_epoch: Option<i64>,
}

/// `load_key_state`: the account's live rotation row, no such account, or a
/// failed read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyStateObservation {
    Loaded(KeyStateView),
    NotFound,
    Storage,
}

/// `current_usage_bytes`: the two stored byte totals, or a failed read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageObservation {
    Measured { chunks: i64, oram: i64 },
    Storage,
}

/// `enforce_rekey_shadow_quota`: the projected stored bytes, or a failed read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectedUsageObservation {
    Measured(i64),
    Storage,
}

/// The cells of a `SelectOramRow` row.
#[derive(Debug, Eq, PartialEq)]
pub struct OramRowView {
    pub version: Option<i64>,
    pub lamport_clock: Option<i64>,
    pub last_writer: Option<String>,
    pub ciphertext: Option<String>,
}

/// `get_path`'s per-bucket observation: the stored bucket, no bucket at that
/// key, or a failed read.
#[derive(Debug, Eq, PartialEq)]
pub enum OramReadObservation {
    Found(OramRowView),
    Missing,
    Storage,
}

/// One `SelectSyncManifest` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncRowView {
    pub chunk_id: Option<String>,
    pub version: Option<i64>,
    pub lamport_clock: Option<i64>,
    pub last_writer: Option<String>,
}

/// `get_sync`: the manifest rows the query returned, or a failed read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncObservation {
    Read,
    Failed,
}

/// `schema::minimum`: the value the store holds (absent, or the stored text),
/// or a failed read. The floor interpretation is the handler's policy over
/// this observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaFloorObservation {
    Stored(Option<String>),
    Storage,
}

/// 30 rotation requests per hour per account (`rate_limit::check`).
pub const REKEY_RATE_LIMIT: u64 = 30;
/// The re-key limiter's fixed window, in seconds.
pub const REKEY_RATE_WINDOW_SECS: i64 = 3600;

/// The three cells of a `SelectCapsule` row.
#[derive(Debug, Eq, PartialEq)]
pub struct CapsuleView {
    pub capsule: Option<String>,
    pub capsule_epoch: Option<i64>,
    pub rotation_id: Option<String>,
}

/// `get_capsule`: the pending capsule, no eligible row, or a failed read.
#[derive(Debug, Eq, PartialEq)]
pub enum CapsuleReadObservation {
    Found(CapsuleView),
    Missing,
    Storage,
}

/// `get_capsule`'s read-once clear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleClearObservation {
    Cleared,
    Missed,
    Storage,
}

/// One `SelectDeviceList` row: the fourteen columns the listing selects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceListRowView {
    pub id: Option<String>,
    pub user_id: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub last_active: Option<String>,
    pub hybrid_ek: Option<String>,
    pub hybrid_vk: Option<String>,
    pub enrolled_by: Option<String>,
    pub rms_capsule: Option<String>,
    pub revoked: Option<i64>,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
    pub created_at: Option<String>,
    pub rekey_capable: Option<i64>,
}

/// `list_devices`: the rows the query returned, or a failed read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceListObservation {
    Read,
    Failed,
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

/// `RekeyIo::begin_freeze_transaction` and `get_capsule`: open the pinned
/// transaction.
pub fn plan_begin_transaction() -> Vec<VaultStmt> {
    vec![VaultStmt::BeginTransaction]
}

// ── Handler I/O outside executor methods (F-1 wave 2) ──────────────────────
//
// `load_key_state`; the two usage reads and the projected-storage read; the
// ORAM path bucket read; the sync manifest; the schema-floor store read; the
// capsule delivery's begin, read and read-once clear; and the device listing.
// Same shape as the executor methods: an extracted plan, the pinned rendering
// and an extracted classifier.

/// `rekey::load_key_state`.
pub fn plan_load_key_state(user: String) -> VaultStmt {
    VaultStmt::SelectKeyState { user }
}

/// `current_usage_bytes`, chunk half.
pub fn plan_usage_chunks(user: String) -> VaultStmt {
    VaultStmt::SelectUsageChunks { user }
}

/// `current_usage_bytes`, ORAM half.
pub fn plan_usage_oram(user: String) -> VaultStmt {
    VaultStmt::SelectUsageOram { user }
}

/// `enforce_rekey_shadow_quota`: the projected stored bytes for a rotation
/// replacing `chunk_id` at `epoch`.
pub fn plan_rekey_projection(user: String, epoch: i64, chunk_id: String) -> VaultStmt {
    VaultStmt::SelectRekeyProjection {
        user,
        epoch,
        chunk_id,
    }
}

/// `get_path`'s per-bucket read on `oram_buckets`.
pub fn plan_read_oram_bucket(
    user: String,
    tree_id: String,
    bucket_index: i64,
    epoch: i64,
) -> VaultStmt {
    VaultStmt::SelectOramRow {
        user,
        tree_id,
        bucket_index,
        epoch,
    }
}

/// `get_sync`'s manifest read.
pub fn plan_read_sync(user: String, epoch: i64) -> VaultStmt {
    VaultStmt::SelectSyncManifest { user, epoch }
}

/// `schema::minimum`'s store read: the key `vault-schema:{user}`.
pub fn plan_read_schema_floor(key: String) -> VaultStmt {
    VaultStmt::SchemaFloorGet { key }
}

/// `get_capsule`'s device-and-account read.
pub fn plan_read_capsule(device: String, user: String) -> VaultStmt {
    VaultStmt::SelectCapsule { device, user }
}

/// `get_capsule`'s read-once clear of an enrollment capsule.
pub fn plan_clear_enrollment_capsule(device: String, user: String) -> Vec<VaultStmt> {
    vec![VaultStmt::ClearEnrollmentCapsule { device, user }]
}

/// `list_devices`' listing.
pub fn plan_read_devices(user: String) -> VaultStmt {
    VaultStmt::SelectDeviceList { user }
}

/// One fixed-window counter increment at the exact key, budget and window.
/// Extracted, so the proof speaks about the key it is handed.
pub fn plan_rate_limit(key: String, limit: u64, window_secs: i64) -> Vec<VaultStmt> {
    vec![VaultStmt::RateLimitIncr {
        key,
        limit,
        window_secs,
    }]
}

/// The per-account re-key pacing limiter that `rekey.rs` has always applied:
/// `rl:rekey:{user}`, 30 requests per hour. The key format is pinned by the
/// unit test below; the generic plan above is the extracted statement.
#[cfg(not(hax))]
pub fn plan_rekey_rate_limit(user: &str) -> Vec<VaultStmt> {
    plan_rate_limit(
        format!("rl:rekey:{user}"),
        REKEY_RATE_LIMIT,
        REKEY_RATE_WINDOW_SECS,
    )
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

// ── Handler I/O classifiers (F-1 wave 2) ──────────────────────────────────

/// `load_key_state`: the stored row, no row, or a failed read. The handler
/// normalizes the row (epoch floor, `freezing` test) after the read; that
/// normalization is policy, not I/O.
pub fn classify_key_state(outcome: ReadOutcome<Option<KeyStateView>>) -> KeyStateObservation {
    match outcome {
        ReadOutcome::Failed => KeyStateObservation::Storage,
        ReadOutcome::Rows(None) => KeyStateObservation::NotFound,
        ReadOutcome::Rows(Some(view)) => KeyStateObservation::Loaded(view),
    }
}

/// `current_usage_bytes`: both reads must have returned their total.
pub fn classify_usage(
    chunks: &ReadOutcome<i64>,
    oram: &ReadOutcome<i64>,
) -> UsageObservation {
    match (chunks, oram) {
        (ReadOutcome::Rows(chunks), ReadOutcome::Rows(oram)) => UsageObservation::Measured {
            chunks: *chunks,
            oram: *oram,
        },
        _ => UsageObservation::Storage,
    }
}

/// `enforce_rekey_shadow_quota`: the projected stored bytes.
pub fn classify_projected_usage(outcome: &ReadOutcome<i64>) -> ProjectedUsageObservation {
    match outcome {
        ReadOutcome::Rows(projected) => ProjectedUsageObservation::Measured(*projected),
        ReadOutcome::Failed => ProjectedUsageObservation::Storage,
    }
}

/// `get_path`'s per-bucket observation.
pub fn classify_oram_read(outcome: ReadOutcome<Option<OramRowView>>) -> OramReadObservation {
    match outcome {
        ReadOutcome::Failed => OramReadObservation::Storage,
        ReadOutcome::Rows(None) => OramReadObservation::Missing,
        ReadOutcome::Rows(Some(view)) => OramReadObservation::Found(view),
    }
}

/// `get_sync`: the manifest rows were read, or the query failed.
pub fn classify_sync(outcome: &ReadOutcome<Vec<SyncRowView>>) -> SyncObservation {
    match outcome {
        ReadOutcome::Rows(_) => SyncObservation::Read,
        ReadOutcome::Failed => SyncObservation::Failed,
    }
}

/// `schema::minimum`: the stored value, computed from the store read.
pub fn classify_schema_floor(outcome: ReadOutcome<Option<String>>) -> SchemaFloorObservation {
    match outcome {
        ReadOutcome::Failed => SchemaFloorObservation::Storage,
        ReadOutcome::Rows(value) => SchemaFloorObservation::Stored(value),
    }
}

/// `get_capsule`: the pending capsule, no eligible row, or a failed read.
pub fn classify_capsule_read(
    outcome: ReadOutcome<Option<CapsuleView>>,
) -> CapsuleReadObservation {
    match outcome {
        ReadOutcome::Failed => CapsuleReadObservation::Storage,
        ReadOutcome::Rows(None) => CapsuleReadObservation::Missing,
        ReadOutcome::Rows(Some(view)) => CapsuleReadObservation::Found(view),
    }
}

/// `get_capsule`'s read-once clear: a cleared row, no matching row, or a
/// failed statement.
pub fn classify_capsule_clear(outcomes: &[WriteOutcome]) -> CapsuleClearObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(1) => CapsuleClearObservation::Cleared,
            WriteOutcome::Applied(_) => CapsuleClearObservation::Missed,
            WriteOutcome::Failed => CapsuleClearObservation::Storage,
        }
    } else {
        CapsuleClearObservation::Storage
    }
}

/// `list_devices`: the listing rows were read, or the query failed.
pub fn classify_device_list(
    outcome: &ReadOutcome<Vec<DeviceListRowView>>,
) -> DeviceListObservation {
    match outcome {
        ReadOutcome::Rows(_) => DeviceListObservation::Read,
        ReadOutcome::Failed => DeviceListObservation::Failed,
    }
}

/// The per-account re-key pacing limiter: `Allowed` exactly when its one
/// counter statement ran and the counter's new value is within the budget.
/// An over-limit count is `Limited` (it still grew before refusing), and a
/// failed store call is `Limited` too — the handler records the error and
/// refuses, exactly as `rate_limit::check` always did.
pub fn classify_rekey_rate_limit(
    outcomes: &[WriteOutcome],
    limit: u64,
) -> RateLimitObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(count) if count <= limit => RateLimitObservation::Allowed,
            _ => RateLimitObservation::Limited,
        }
    } else {
        RateLimitObservation::Limited
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
    /// A durable key-value read in the sled store.
    KvGet { key: String },
    /// A fixed-window counter increment in the sled store.
    KvIncr {
        key: String,
        delta: u64,
        window_secs: i64,
    },
    /// `COMMIT` on the open transaction.
    Commit,
    /// Open a pinned transaction.
    Begin,
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
        VaultStmt::SelectKeyState { user } => Rendered::Query {
            sql: "SELECT key_epoch, rekey_state, rekey_started_at, rekey_starter, rekey_id,
                    last_rekey_id, last_rekey_epoch
             FROM users WHERE id = ?",
            params: vec![Text(user.clone())],
        },
        VaultStmt::SelectUsageChunks { user } => Rendered::Query {
            sql: "SELECT COALESCE(SUM(LENGTH(t.ciphertext)), 0) FROM vault_chunks t
                     JOIN users u ON u.id = t.user_id
                     WHERE t.user_id = ? AND t.epoch = u.key_epoch",
            params: vec![Text(user.clone())],
        },
        VaultStmt::SelectUsageOram { user } => Rendered::Query {
            sql: "SELECT COALESCE(SUM(LENGTH(t.ciphertext)), 0) FROM oram_buckets t
                     JOIN users u ON u.id = t.user_id
                     WHERE t.user_id = ? AND t.epoch = u.key_epoch",
            params: vec![Text(user.clone())],
        },
        VaultStmt::SelectRekeyProjection {
            user,
            epoch,
            chunk_id,
        } => Rendered::Query {
            sql: "SELECT
                (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0)
                   FROM vault_chunks
                  WHERE user_id = ? AND epoch = ? AND chunk_id != ?) +
                (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0)
                   FROM oram_buckets WHERE user_id = ?)",
            params: vec![
                Text(user.clone()),
                Int(*epoch),
                Text(chunk_id.clone()),
                Text(user.clone()),
            ],
        },
        VaultStmt::SelectOramRow {
            user,
            tree_id,
            bucket_index,
            epoch,
        } => Rendered::Query {
            sql: "SELECT version, lamport_clock, last_writer, ciphertext
             FROM oram_buckets
             WHERE user_id = ? AND tree_id = ? AND bucket_index = ? AND epoch = ?",
            params: vec![
                Text(user.clone()),
                Text(tree_id.clone()),
                Int(*bucket_index),
                Int(*epoch),
            ],
        },
        VaultStmt::SelectSyncManifest { user, epoch } => Rendered::Query {
            sql: "SELECT chunk_id, version, lamport_clock, last_writer
         FROM vault_chunks
         WHERE user_id = ? AND epoch = ?
         ORDER BY chunk_id",
            params: vec![Text(user.clone()), Int(*epoch)],
        },
        VaultStmt::SchemaFloorGet { key } => Rendered::KvGet { key: key.clone() },
        VaultStmt::RateLimitIncr {
            key,
            limit: _,
            window_secs,
        } => Rendered::KvIncr {
            key: key.clone(),
            delta: 1,
            window_secs: *window_secs,
        },
        VaultStmt::BeginTransaction => Rendered::Begin,
        VaultStmt::SelectCapsule { device, user } => Rendered::Query {
            sql: "SELECT devices.rms_capsule, devices.rms_capsule_epoch,
                    CASE WHEN devices.rms_capsule_epoch = users.last_rekey_epoch
                         THEN users.last_rekey_id ELSE NULL END
             FROM devices JOIN users ON users.id = devices.user_id
             WHERE devices.id = ? AND devices.user_id = ?
               AND devices.revoked = 0 AND devices.rms_capsule IS NOT NULL",
            params: vec![Text(device.clone()), Text(user.clone())],
        },
        VaultStmt::ClearEnrollmentCapsule { device, user } => Rendered::Execute {
            sql: "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
             WHERE id = ? AND user_id = ?",
            params: vec![Text(device.clone()), Text(user.clone())],
        },
        VaultStmt::SelectDeviceList { user } => Rendered::Query {
            sql: "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at,
                rekey_capable
             FROM devices
             WHERE user_id = ?
             ORDER BY created_at ASC
             LIMIT 1000",
            params: vec![Text(user.clone())],
        },
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

    #[test]
    fn handler_io_plans_render_the_historical_statements() {
        assert_eq!(
            query(&plan_load_key_state(s("u"))),
            (
                "SELECT key_epoch, rekey_state, rekey_started_at, rekey_starter, rekey_id,\n                    last_rekey_id, last_rekey_epoch\n             FROM users WHERE id = ?",
                vec![t("u")]
            )
        );
        assert_eq!(
            query(&plan_usage_chunks(s("u"))),
            (
                "SELECT COALESCE(SUM(LENGTH(t.ciphertext)), 0) FROM vault_chunks t\n                     JOIN users u ON u.id = t.user_id\n                     WHERE t.user_id = ? AND t.epoch = u.key_epoch",
                vec![t("u")]
            )
        );
        assert_eq!(
            query(&plan_usage_oram(s("u"))),
            (
                "SELECT COALESCE(SUM(LENGTH(t.ciphertext)), 0) FROM oram_buckets t\n                     JOIN users u ON u.id = t.user_id\n                     WHERE t.user_id = ? AND t.epoch = u.key_epoch",
                vec![t("u")]
            )
        );
        assert_eq!(
            query(&plan_rekey_projection(s("u"), 4, s("c"))),
            (
                "SELECT\n                (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0)\n                   FROM vault_chunks\n                  WHERE user_id = ? AND epoch = ? AND chunk_id != ?) +\n                (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0)\n                   FROM oram_buckets WHERE user_id = ?)",
                vec![t("u"), SqlParam::Int(4), t("c"), t("u")]
            )
        );
        assert_eq!(
            query(&plan_read_oram_bucket(s("u"), s("tr"), 5, 4)),
            (
                "SELECT version, lamport_clock, last_writer, ciphertext\n             FROM oram_buckets\n             WHERE user_id = ? AND tree_id = ? AND bucket_index = ? AND epoch = ?",
                vec![t("u"), t("tr"), SqlParam::Int(5), SqlParam::Int(4)]
            )
        );
        assert_eq!(
            query(&plan_read_sync(s("u"), 4)),
            (
                "SELECT chunk_id, version, lamport_clock, last_writer\n         FROM vault_chunks\n         WHERE user_id = ? AND epoch = ?\n         ORDER BY chunk_id",
                vec![t("u"), SqlParam::Int(4)]
            )
        );
        assert_eq!(
            render(&plan_read_schema_floor(s("vault-schema:u"))),
            Rendered::KvGet {
                key: s("vault-schema:u")
            }
        );
        assert_eq!(render(&plan_begin_transaction()[0]), Rendered::Begin);
        assert_eq!(
            query(&plan_read_capsule(s("d"), s("u"))),
            (
                "SELECT devices.rms_capsule, devices.rms_capsule_epoch,\n                    CASE WHEN devices.rms_capsule_epoch = users.last_rekey_epoch\n                         THEN users.last_rekey_id ELSE NULL END\n             FROM devices JOIN users ON users.id = devices.user_id\n             WHERE devices.id = ? AND devices.user_id = ?\n               AND devices.revoked = 0 AND devices.rms_capsule IS NOT NULL",
                vec![t("d"), t("u")]
            )
        );
        let clear = plan_clear_enrollment_capsule(s("d"), s("u"));
        assert_eq!(clear.len(), 1);
        assert_eq!(
            exec(&clear[0]),
            (
                "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL\n             WHERE id = ? AND user_id = ?",
                vec![t("d"), t("u")]
            )
        );
        assert_eq!(
            query(&plan_read_devices(s("u"))),
            (
                "SELECT id, user_id, device_name, device_type, last_active,\n                hybrid_ek, hybrid_vk,\n                enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at,\n                rekey_capable\n             FROM devices\n             WHERE user_id = ?\n             ORDER BY created_at ASC\n             LIMIT 1000",
                vec![t("u")]
            )
        );
    }

    #[test]
    fn handler_io_classifiers_keep_the_historical_observations() {
        use WriteOutcome::{Applied, Failed};
        // The epoch floor: a stored zero or absent epoch reads as one.
        let view = KeyStateView {
            key_epoch: Some(0),
            rekey_state: Some(s("freezing")),
            rekey_started_at: Some(s("t")),
            rekey_starter: Some(s("d")),
            rekey_id: Some(s("r")),
            last_rekey_id: Some(s("lr")),
            last_rekey_epoch: Some(3),
        };
        assert_eq!(
            classify_key_state(ReadOutcome::Rows(Some(view))),
            KeyStateObservation::Loaded(KeyStateView {
                key_epoch: Some(0),
                rekey_state: Some(s("freezing")),
                rekey_started_at: Some(s("t")),
                rekey_starter: Some(s("d")),
                rekey_id: Some(s("r")),
                last_rekey_id: Some(s("lr")),
                last_rekey_epoch: Some(3),
            })
        );
        assert_eq!(
            classify_key_state(ReadOutcome::Rows(None)),
            KeyStateObservation::NotFound
        );
        assert_eq!(
            classify_key_state(ReadOutcome::Failed),
            KeyStateObservation::Storage
        );
        assert_eq!(
            classify_usage(&ReadOutcome::Rows(7), &ReadOutcome::Rows(9)),
            UsageObservation::Measured {
                chunks: 7,
                oram: 9
            }
        );
        assert_eq!(
            classify_usage(&ReadOutcome::Rows(7), &ReadOutcome::Failed),
            UsageObservation::Storage
        );
        assert_eq!(
            classify_projected_usage(&ReadOutcome::Rows(11)),
            ProjectedUsageObservation::Measured(11)
        );
        assert_eq!(
            classify_projected_usage(&ReadOutcome::Failed),
            ProjectedUsageObservation::Storage
        );
        let row = OramRowView {
            version: Some(2),
            lamport_clock: Some(5),
            last_writer: Some(s("d")),
            ciphertext: Some(s("ct")),
        };
        assert_eq!(
            classify_oram_read(ReadOutcome::Rows(Some(OramRowView {
                version: Some(2),
                lamport_clock: Some(5),
                last_writer: Some(s("d")),
                ciphertext: Some(s("ct")),
            }))),
            OramReadObservation::Found(row)
        );
        assert_eq!(
            classify_oram_read(ReadOutcome::Rows(None)),
            OramReadObservation::Missing
        );
        assert_eq!(
            classify_oram_read(ReadOutcome::Failed),
            OramReadObservation::Storage
        );
        assert_eq!(
            classify_sync(&ReadOutcome::Rows(Vec::new())),
            SyncObservation::Read
        );
        assert_eq!(classify_sync(&ReadOutcome::Failed), SyncObservation::Failed);
        assert_eq!(
            classify_schema_floor(ReadOutcome::Rows(None)),
            SchemaFloorObservation::Stored(None)
        );
        assert_eq!(
            classify_schema_floor(ReadOutcome::Rows(Some(s("2")))),
            SchemaFloorObservation::Stored(Some(s("2")))
        );
        assert_eq!(
            classify_schema_floor(ReadOutcome::Failed),
            SchemaFloorObservation::Storage
        );
        let capsule = CapsuleView {
            capsule: Some(s("cap")),
            capsule_epoch: Some(2),
            rotation_id: Some(s("r")),
        };
        assert_eq!(
            classify_capsule_read(ReadOutcome::Rows(Some(CapsuleView {
                capsule: Some(s("cap")),
                capsule_epoch: Some(2),
                rotation_id: Some(s("r")),
            }))),
            CapsuleReadObservation::Found(capsule)
        );
        assert_eq!(
            classify_capsule_read(ReadOutcome::Rows(None)),
            CapsuleReadObservation::Missing
        );
        assert_eq!(
            classify_capsule_read(ReadOutcome::Failed),
            CapsuleReadObservation::Storage
        );
        assert_eq!(
            classify_capsule_clear(&[Applied(1)]),
            CapsuleClearObservation::Cleared
        );
        assert_eq!(
            classify_capsule_clear(&[Applied(0)]),
            CapsuleClearObservation::Missed
        );
        assert_eq!(
            classify_capsule_clear(&[Failed]),
            CapsuleClearObservation::Storage
        );
        assert_eq!(
            classify_device_list(&ReadOutcome::Rows(Vec::new())),
            DeviceListObservation::Read
        );
        assert_eq!(
            classify_device_list(&ReadOutcome::Failed),
            DeviceListObservation::Failed
        );
        // The transaction begin is classified by the existing transaction
        // observation: one applied statement is a commit.
        assert_eq!(
            classify_transaction(&[Applied(0)]),
            TransactionObservation::Committed
        );
        assert_eq!(classify_transaction(&[]), TransactionObservation::Failed);
    }

    #[test]
    fn rekey_rate_limit_renders_and_classifies_the_historical_limiter() {
        // The historical call was
        // `rate_limit::check(&state.store, &format!("rl:rekey:{user_id}"), 30, 3600)`.
        let plan = plan_rekey_rate_limit("user-1");
        assert_eq!(plan.len(), 1);
        match &plan[0] {
            VaultStmt::RateLimitIncr {
                key,
                limit,
                window_secs,
            } => {
                assert_eq!(key, "rl:rekey:user-1");
                assert_eq!(*limit, 30);
                assert_eq!(*window_secs, 3600);
            }
            other => panic!("expected a rate-limit increment, got {other:?}"),
        }
        assert_eq!(
            render(&plan[0]),
            Rendered::KvIncr {
                key: s("rl:rekey:user-1"),
                delta: 1,
                window_secs: 3600,
            }
        );
        // The 30th request in the window is allowed, the 31st is refused.
        assert_eq!(
            classify_rekey_rate_limit(&[WriteOutcome::Applied(30)], REKEY_RATE_LIMIT),
            RateLimitObservation::Allowed
        );
        assert_eq!(
            classify_rekey_rate_limit(&[WriteOutcome::Applied(31)], REKEY_RATE_LIMIT),
            RateLimitObservation::Limited
        );
        // A store failure is a refusal, and the handler keeps the error.
        assert_eq!(
            classify_rekey_rate_limit(&[WriteOutcome::Failed], REKEY_RATE_LIMIT),
            RateLimitObservation::Limited
        );
        assert_eq!(
            classify_rekey_rate_limit(&[], REKEY_RATE_LIMIT),
            RateLimitObservation::Limited
        );
    }
}
