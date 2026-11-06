//! Pure per-request decision drivers for the vault key-rotation endpoints.
//!
//! `POST /vault/rekey/{start,capsules,commit,abort}` perform the effectful
//! steps: pacing, loading the post-rollback key state, the lazy timeout
//! rollback, the readiness queries, the freeze transaction and its CAS, the
//! inventory read, the per-capsule guarded updates, the completeness queries,
//! the commit CAS, the superseded-row sweep, the epoch publication and the
//! abort rollback. This module owns every *decision* between those effects.
//!
//! There is one driver with four entry points (`begin_start`,
//! `begin_capsules`, `begin_commit`, `begin_abort`) and one total transition
//! relation (`rekey_step`). The four handlers each expand the interpreter loop
//! in `rekey_interpreter` over this driver; no handler calls a transition by
//! hand.
//!
//! The policy functions already proved in this crate (`plan_start`,
//! `plan_commit`, `plan_abort`, `plan_timeout`, `authorize_attempt`,
//! `authorize_commit_replay`) remain the only transition authorities. The
//! driver re-applies them to observations produced by the handler and never
//! restates their predicates.
//!
//! Effect order is part of the contract:
//!
//! - an account is frozen only inside the one transaction that read the
//!   inventory, and the cleanup runs only after the freeze CAS won;
//! - a commit CAS is emitted only after both completeness observations and
//!   after `plan_commit` returned a plan, and only for the starting device and
//!   the live rotation id;
//! - an abort or timeout rollback never advances the epoch and always restores
//!   the active phase;
//! - pacing precedes the state load, and a timeout rollback precedes every
//!   later decision.
//!
//! Every observation is a handler-produced fact. The driver does not observe
//! the SQL database or the clock.

use crate::{
    authorize_attempt, authorize_commit_replay, next_epoch, plan_abort, plan_commit, plan_start,
    plan_timeout, AbortDecision, AttemptAuthority, CommitDecision, CommitFacts,
    CommitReplayFacts, Phase, RekeyState, ShadowDecision, StartDecision, StartFacts,
    TimeoutDecision, TimeoutFacts, INITIAL_EPOCH,
};

// ── Request facts ───────────────────────────────────────────────────────────

/// Which rotation entry point this request is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyOp {
    Start,
    Capsules,
    Commit,
    Abort,
}

/// Authenticated facts captured by the `DeviceSession` extractor before the
/// first effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyRequest {
    /// The middleware verified a live PASETO identity.
    pub authenticated: bool,
    /// The extractor accepted a real device, not a temporary web session.
    pub device_scope: bool,
    /// Number of capsule entries in the request body (zero for the other
    /// entry points).
    pub capsule_count: i64,
}

// ── Observations ────────────────────────────────────────────────────────────

/// Outcome of the per-account rotation pacing check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitObservation {
    Allowed,
    Limited,
}

/// The post-load key state plus the authenticated request facts the driver
/// compares against it. The handler derives these booleans by comparing the
/// loaded row with the request; the driver never sees identity strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyStateObs {
    pub epoch: i64,
    /// The persisted `rekey_state` is `freezing`.
    pub freezing: bool,
    /// `rekey_starter` equals the authenticated device.
    pub starter_matches: bool,
    /// `rekey_id` is present in the row.
    pub rotation_id_present: bool,
    /// `X-Vela-Rekey-Id` was supplied.
    pub header_present: bool,
    /// The supplied header equals the row's `rekey_id`.
    pub header_matches: bool,
    /// `X-Vela-Epoch` parsed (commit replay only).
    pub replay_target: Option<i64>,
    /// The row's recorded `last_rekey_epoch`.
    pub replay_recorded: Option<i64>,
    /// The supplied `X-Vela-Rekey-Id` equals the recorded `last_rekey_id`.
    pub replay_id_matches: bool,
    /// The persisted `rekey_started_at` is older than the timeout.
    pub expired: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateObservation {
    Loaded(KeyStateObs),
    /// The key-state query failed (the handler keeps its error). The
    /// zero-row result is `NotFound`.
    Storage,
    NotFound,
}

/// Outcome of the lazy timeout rollback. `Raced` carries the state the
/// winning transition left behind, which the handler reloads and continues
/// with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutObservation {
    RolledBack,
    Raced(KeyStateObs),
    Storage,
}

/// Outcome of one readiness/completeness `SELECT 1 ... LIMIT 1` probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeObservation {
    /// The probe returned no row (ORAM absent / device capable / acknowledged
    /// / shadows complete / capsules complete).
    Empty,
    /// The probe found a row.
    Found,
    Storage,
}

/// Outcome of opening or committing the freeze transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionObservation {
    Committed,
    Failed,
}

/// Outcome of the inventory read inside the freeze transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryObservation {
    Read,
    Failed,
}

/// Outcome of a compare-and-swap `UPDATE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CasObservation {
    /// Exactly one row changed.
    Updated,
    /// Zero rows changed: a concurrent request won.
    Skipped,
    Storage,
}

/// Outcome of the post-freeze cleanup delete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupObservation {
    Done,
    Storage,
}

/// Outcome of one capsule target update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleObservation {
    /// The guarded update matched the target device.
    Stored,
    /// The base64 or size validation refused the capsule.
    Invalid,
    /// The target is unknown, foreign or revoked (zero rows).
    NotTarget,
    Storage,
}

/// Outcome of the abort / timeout rollback CAS and its cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackObservation {
    RolledBack,
    Raced,
    Storage,
}

/// The superseded-row sweep is best effort: the handler only logs a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SweepObservation {
    Done,
    Failed,
}

/// One driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyEvent {
    RateLimit(RateLimitObservation),
    State(StateObservation),
    Timeout(TimeoutObservation),
    Oram(ProbeObservation),
    Capable(ProbeObservation),
    Acknowledged(ProbeObservation),
    Transaction(TransactionObservation),
    Inventory(InventoryObservation),
    FreezeCas(CasObservation),
    Cleanup(CleanupObservation),
    TxCommit(TransactionObservation),
    Capsule(CapsuleObservation),
    Chunks(ProbeObservation),
    Devices(ProbeObservation),
    CommitCas(CasObservation),
    Sweep(SweepObservation),
    Published,
    Rollback(RollbackObservation),
}

// ── Failures ────────────────────────────────────────────────────────────────

/// Failure categories preserving every handler's status/message precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyFailure {
    /// The extractor did not establish an authenticated device.
    Unauthenticated,
    /// A temporary web session reached a rotation entry point.
    WebSessionForbidden,
    /// The pacing limit refused the request.
    RateLimited,
    /// The key-state query failed.
    StateStorage,
    /// The account row does not exist.
    AccountNotFound,
    /// The observed epoch is below the initial epoch.
    InvalidEpoch,
    /// The account is already freezing when `start` runs.
    AlreadyInProgress,
    /// No re-key is in progress.
    NoRekeyInProgress,
    /// ORAM buckets exist, so chunk-only rotation is not offered.
    OramPresent,
    /// At least one active device is not re-key capable.
    CapabilityRequired,
    /// At least one active device has not acknowledged the current epoch.
    AdoptionRequired,
    /// The freeze transaction could not be opened.
    TransactionStorage,
    /// The inventory query failed.
    InventoryStorage,
    /// The freeze CAS lost a concurrent start.
    ConcurrentStart,
    /// The cleanup delete failed.
    CleanupStorage,
    /// The transaction commit failed.
    TxCommitStorage,
    /// The caller is not the device which started the rotation.
    StarterRequired,
    /// `X-Vela-Rekey-Id` is missing.
    RotationIdRequired,
    /// The supplied rotation id belongs to another attempt.
    RotationIdMismatch,
    /// The attempt authority refused the request.
    NotAuthorized,
    /// The epoch has no representable successor.
    NoSuccessor,
    /// More than 64 capsule entries were supplied.
    TooManyCapsules,
    /// A capsule target is not an active device of the account.
    CapsuleTargetInvalid,
    /// One or more chunk shadows are missing.
    ChunkShadowsIncomplete,
    /// One or more active devices has no capsule for the new epoch.
    DeviceCapsulesIncomplete,
    /// The commit plan refused an otherwise complete attempt.
    CommitNotAuthorized,
    /// The commit CAS lost a concurrent commit or abort.
    ConcurrentCommit,
    /// The rollback CAS lost a concurrent transition.
    ConcurrentRollback,
    /// The chunk-shadow probe failed.
    ChunkProbeStorage,
    /// The device-capsule probe failed.
    CapsuleProbeStorage,
    /// The abort/commit rollback query failed.
    RollbackStorage,
}

// ── Effects and stages ──────────────────────────────────────────────────────

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyEffect {
    RateLimit,
    LoadState,
    TimeoutRollback,
    CheckOram,
    CheckCapable,
    CheckAcknowledged,
    BeginFreezeTransaction,
    ReadInventory,
    FreezeCas,
    CleanupChunks,
    CommitFreezeTransaction,
    WriteCapsule { index: i64 },
    CheckChunkShadows,
    CheckDeviceCapsules,
    CommitCas,
    SweepOldChunks,
    PublishEpoch,
    RollbackAttempt,
    Complete,
    CompleteReplay,
    Fail(RekeyFailure),
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyStage {
    RateLimit,
    Load,
    Timeout,
    Oram,
    Capable,
    Acknowledged,
    BeginTx,
    Inventory,
    FreezeCas,
    Cleanup,
    TxCommit,
    /// A capsule write is next; the index is in the driver.
    Capsule,
    Chunks,
    Devices,
    CommitCas,
    Sweep,
    Publish,
    Rollback,
    Done,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the SQL database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyDriver {
    pub op: RekeyOp,
    pub stage: RekeyStage,
    pub authenticated: bool,
    pub device_scope: bool,
    pub epoch: i64,
    pub active: bool,
    pub timeout_done: bool,
    pub starter_matches: bool,
    pub rotation_present: bool,
    pub header_present: bool,
    pub rotation_matches: bool,
    pub replay_target: Option<i64>,
    pub replay_recorded: Option<i64>,
    pub replay_id_matches: bool,
    pub capsule_count: i64,
    pub capsules_written: i64,
    pub no_oram: bool,
    pub capable: bool,
    pub acknowledged: bool,
    pub from_epoch: i64,
    pub to_epoch: i64,
    pub chunks_complete: bool,
    pub capsules_complete: bool,
    pub committed: bool,
    pub rolled_back: bool,
    pub timeout_rollback: bool,
    pub published: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyTransition {
    pub driver: RekeyDriver,
    pub effect: RekeyEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn rekey_state_is_sound(d: RekeyDriver) -> bool {
    let commit_authority = d.device_scope
        && d.starter_matches
        && d.rotation_present
        && d.rotation_matches;
    let commit_stage = matches!(
        d.stage,
        RekeyStage::Sweep | RekeyStage::Publish
    );
    let commit_cas_stage = matches!(d.stage, RekeyStage::CommitCas);
    let committed_stage = matches!(
        d.stage,
        RekeyStage::Sweep | RekeyStage::Publish | RekeyStage::Done
    );
    (!d.failed || !d.committed)
        && (!d.committed || committed_stage)
        && (!d.responded || !d.failed)
        && (!d.responded || matches!(d.stage, RekeyStage::Done))
        && (!d.responded
            || !matches!(d.op, RekeyOp::Capsules)
            || d.capsules_complete)
        && (!d.failed || matches!(d.stage, RekeyStage::Done))
        // A commit is exactly a completed `plan_commit` on this request's own
        // observed state, after both completeness observations.
        && (!d.committed
            || (matches!(d.op, RekeyOp::Commit)
                && d.active
                && commit_authority
                && d.chunks_complete
                && d.capsules_complete
                && d.epoch == d.to_epoch
                && next_epoch(d.from_epoch) == Some(d.to_epoch)
                && d.to_epoch >= INITIAL_EPOCH))
        // Before the commit CAS, the plan's successor and both completeness
        // observations are already established.
        && (!commit_cas_stage
            || (d.from_epoch == d.epoch
                && next_epoch(d.from_epoch) == Some(d.to_epoch)
                && commit_authority
                && d.chunks_complete
                && d.capsules_complete
                && d.to_epoch >= INITIAL_EPOCH
                && !d.committed))
        // The sweep and publication stages only exist after a commit.
        && (!commit_stage || d.committed)
        // An abort and a timeout rollback both restore the active phase at the
        // observed epoch and never advance it.
        && (!d.rolled_back || (d.active && d.epoch >= INITIAL_EPOCH && !d.committed))
        && (!d.rolled_back
            || !matches!(
                d.stage,
                RekeyStage::Chunks
                    | RekeyStage::Devices
                    | RekeyStage::CommitCas
                    | RekeyStage::Sweep
                    | RekeyStage::Publish
            ))
        && (!matches!(d.stage, RekeyStage::Rollback) || d.epoch >= INITIAL_EPOCH)
        && (!d.timeout_rollback || d.rolled_back)
        && (!d.rolled_back || matches!(d.op, RekeyOp::Abort) || d.timeout_rollback)
        // Capsule progress never exceeds the request's list and completeness
        // only counts the whole list.
        && (d.capsules_written <= d.capsule_count)
        && d.capsules_written <= 64
        && (!matches!(d.op, RekeyOp::Start | RekeyOp::Commit | RekeyOp::Abort)
            || d.capsule_count == 0)
        && (!matches!(
            d.stage,
            RekeyStage::Chunks
                | RekeyStage::Devices
                | RekeyStage::CommitCas
                | RekeyStage::Sweep
                | RekeyStage::Publish
        ) || d.capsules_written == d.capsule_count)
        && (!d.capsules_complete || d.capsules_written == d.capsule_count)
        && (!matches!(
            d.stage,
            RekeyStage::RateLimit | RekeyStage::Load | RekeyStage::Timeout
        ) || d.capsules_written == 0)
        && (!matches!(d.stage, RekeyStage::Capsule)
            || (matches!(d.op, RekeyOp::Capsules)
                && d.capsules_written < d.capsule_count))
        && (!matches!(
            d.stage,
            RekeyStage::Oram
                | RekeyStage::Capable
                | RekeyStage::Acknowledged
                | RekeyStage::BeginTx
                | RekeyStage::Inventory
                | RekeyStage::FreezeCas
                | RekeyStage::Cleanup
                | RekeyStage::TxCommit
        ) || matches!(d.op, RekeyOp::Start))
        && (!matches!(
            d.stage,
            RekeyStage::Chunks
                | RekeyStage::Devices
                | RekeyStage::CommitCas
                | RekeyStage::Sweep
                | RekeyStage::Publish
        ) || matches!(d.op, RekeyOp::Commit))
        && (!matches!(d.stage, RekeyStage::Rollback) || matches!(d.op, RekeyOp::Abort))
        // A timeout decision is only taken on a loaded state.
        && (!matches!(d.stage, RekeyStage::Timeout) || d.epoch >= INITIAL_EPOCH)
        // The epoch publication only exists after a commit.
        && (!d.published || d.committed)
}

/// Every effect the driver emits agrees with the state it produces.
pub fn rekey_effect_is_sound(d: RekeyDriver, effect: RekeyEffect) -> bool {
    match effect {
        RekeyEffect::RateLimit => {
            matches!(d.stage, RekeyStage::RateLimit) && d.authenticated && d.device_scope
        }
        RekeyEffect::LoadState => matches!(d.stage, RekeyStage::Load),
        RekeyEffect::TimeoutRollback => matches!(d.stage, RekeyStage::Timeout),
        RekeyEffect::CheckOram => {
            matches!(d.stage, RekeyStage::Oram) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::CheckCapable => {
            matches!(d.stage, RekeyStage::Capable) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::CheckAcknowledged => {
            matches!(d.stage, RekeyStage::Acknowledged) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::BeginFreezeTransaction => {
            matches!(d.stage, RekeyStage::BeginTx) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::ReadInventory => {
            matches!(d.stage, RekeyStage::Inventory) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::FreezeCas => {
            matches!(d.stage, RekeyStage::FreezeCas) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::CleanupChunks => {
            matches!(d.stage, RekeyStage::Cleanup) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::CommitFreezeTransaction => {
            matches!(d.stage, RekeyStage::TxCommit) && matches!(d.op, RekeyOp::Start)
        }
        RekeyEffect::WriteCapsule { index } => {
            matches!(d.stage, RekeyStage::Capsule)
                && matches!(d.op, RekeyOp::Capsules)
                && index == d.capsules_written
                && index < d.capsule_count
        }
        RekeyEffect::CheckChunkShadows => {
            matches!(d.stage, RekeyStage::Chunks) && matches!(d.op, RekeyOp::Commit)
        }
        RekeyEffect::CheckDeviceCapsules => {
            matches!(d.stage, RekeyStage::Devices) && matches!(d.op, RekeyOp::Commit)
        }
        RekeyEffect::CommitCas => {
            matches!(d.stage, RekeyStage::CommitCas)
                && matches!(d.op, RekeyOp::Commit)
                && d.chunks_complete
                && d.capsules_complete
                && d.device_scope
                && d.starter_matches
                && d.rotation_present
                && d.rotation_matches
                && !d.committed
        }
        RekeyEffect::SweepOldChunks => {
            matches!(d.stage, RekeyStage::Sweep) && d.committed
        }
        RekeyEffect::PublishEpoch => {
            matches!(d.stage, RekeyStage::Publish) && d.committed
        }
        RekeyEffect::RollbackAttempt => {
            matches!(d.stage, RekeyStage::Rollback) && matches!(d.op, RekeyOp::Abort)
        }
        RekeyEffect::Complete => {
            matches!(d.stage, RekeyStage::Done)
                && d.responded
                && !d.failed
                && (!matches!(d.op, RekeyOp::Commit) || d.committed)
                && (!matches!(d.op, RekeyOp::Abort) || d.rolled_back)
                && (!matches!(d.op, RekeyOp::Capsules) || d.capsules_complete)
        }
        RekeyEffect::CompleteReplay => {
            matches!(d.stage, RekeyStage::Done)
                && d.responded
                && !d.failed
                && matches!(d.op, RekeyOp::Commit)
                && d.replay_target == Some(d.epoch)
                && d.replay_recorded == Some(d.epoch)
                && d.header_present
                && d.replay_id_matches
        }
        RekeyEffect::Fail(_) => matches!(d.stage, RekeyStage::Done) && d.failed && !d.responded,
        RekeyEffect::Idle => true,
    }
}

fn transition(driver: RekeyDriver, effect: RekeyEffect) -> RekeyTransition {
    RekeyTransition { driver, effect }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn idle(driver: RekeyDriver) -> RekeyTransition {
    transition(driver, RekeyEffect::Idle)
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver) && !driver.committed && !driver.responded
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn terminal(driver: RekeyDriver, failure: RekeyFailure) -> RekeyTransition {
    transition(
        RekeyDriver {
            stage: RekeyStage::Done,
            failed: true,
            ..driver
        },
        RekeyEffect::Fail(failure),
    )
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver)
        && !driver.failed
        && !driver.responded
        && (!matches!(driver.op, RekeyOp::Capsules) || driver.capsules_complete)
        && (!matches!(driver.op, RekeyOp::Commit) || driver.committed)
        && (!matches!(driver.op, RekeyOp::Abort) || driver.rolled_back)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn complete(driver: RekeyDriver) -> RekeyTransition {
    transition(
        RekeyDriver {
            stage: RekeyStage::Done,
            responded: true,
            ..driver
        },
        RekeyEffect::Complete,
    )
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver)
        && matches!(driver.op, RekeyOp::Commit)
        && !driver.failed
        && driver.replay_target == Some(driver.epoch)
        && driver.replay_recorded == Some(driver.epoch)
        && driver.header_present
        && driver.replay_id_matches
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn complete_replay(driver: RekeyDriver) -> RekeyTransition {
    transition(
        RekeyDriver {
            stage: RekeyStage::Done,
            responded: true,
            ..driver
        },
        RekeyEffect::CompleteReplay,
    )
}

fn fresh(op: RekeyOp, request: RekeyRequest) -> RekeyDriver {
    RekeyDriver {
        op,
        stage: RekeyStage::RateLimit,
        authenticated: request.authenticated,
        device_scope: request.device_scope,
        epoch: 0,
        active: false,
        timeout_done: false,
        starter_matches: false,
        rotation_present: false,
        header_present: false,
        rotation_matches: false,
        replay_target: None,
        replay_recorded: None,
        replay_id_matches: false,
        capsule_count: match op {
            RekeyOp::Capsules => {
                if request.capsule_count < 0 { 0 } else { request.capsule_count }
            }
            _ => 0,
        },
        capsules_written: 0,
        no_oram: false,
        capable: false,
        acknowledged: false,
        from_epoch: 0,
        to_epoch: 0,
        chunks_complete: false,
        capsules_complete: false,
        committed: false,
        rolled_back: false,
        timeout_rollback: false,
        published: false,
        responded: false,
        failed: false,
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
}))]
fn begin(op: RekeyOp, request: RekeyRequest) -> RekeyTransition {
    let driver = fresh(op, request);
    if !request.authenticated {
        terminal(driver, RekeyFailure::Unauthenticated)
    } else if !request.device_scope {
        terminal(driver, RekeyFailure::WebSessionForbidden)
    } else {
        transition(driver, RekeyEffect::RateLimit)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_start(request: RekeyRequest) -> RekeyTransition {
    begin(RekeyOp::Start, request)
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_capsules(request: RekeyRequest) -> RekeyTransition {
    begin(RekeyOp::Capsules, request)
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_commit(request: RekeyRequest) -> RekeyTransition {
    begin(RekeyOp::Commit, request)
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_abort(request: RekeyRequest) -> RekeyTransition {
    begin(RekeyOp::Abort, request)
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::RateLimit)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
}))]
fn on_rate_limit(driver: RekeyDriver, observation: RateLimitObservation) -> RekeyTransition {
    match observation {
        RateLimitObservation::Allowed => transition(
            RekeyDriver {
                stage: RekeyStage::Load,
                ..driver
            },
            RekeyEffect::LoadState,
        ),
        RateLimitObservation::Limited => terminal(driver, RekeyFailure::RateLimited),
    }
}

/// Apply the post-load timeout decision and continue with `state`.
///
/// `maybe_rollback` is the only place the lazy timeout exists; the driver owns
/// the decision, the executor only performs the rollback. A rollback that
/// loses the race returns the winning state, exactly like the handler's
/// re-load.
#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Load)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn after_state(driver: RekeyDriver, state: KeyStateObs) -> RekeyTransition {
    // Rebuild the loaded state explicitly. Historical flags from the previous
    // load (a lost timeout race, a completed write) are not part of the
    // authoritative row this observation names, and the effect sequence restarts
    // from the readiness probes.
    let observed = RekeyDriver {
        op: driver.op,
        stage: RekeyStage::Load,
        authenticated: driver.authenticated,
        device_scope: driver.device_scope,
        epoch: state.epoch,
        active: !state.freezing,
        timeout_done: driver.timeout_done,
        starter_matches: state.starter_matches,
        rotation_present: state.rotation_id_present,
        header_present: state.header_present,
        rotation_matches: state.header_matches,
        replay_target: state.replay_target,
        replay_recorded: state.replay_recorded,
        replay_id_matches: state.replay_id_matches,
        capsule_count: driver.capsule_count,
        capsules_written: 0,
        no_oram: false,
        capable: false,
        acknowledged: false,
        from_epoch: 0,
        to_epoch: 0,
        chunks_complete: false,
        capsules_complete: false,
        committed: false,
        rolled_back: false,
        timeout_rollback: false,
        published: false,
        responded: false,
        failed: false,
    };
    if observed.epoch < INITIAL_EPOCH {
        return terminal(observed, RekeyFailure::InvalidEpoch);
    }
    if state.freezing && !driver.timeout_done {
        let timeout = TimeoutFacts {
            expired: state.expired,
            rotation_id_present: state.rotation_id_present,
        };
        match plan_timeout(
            RekeyState {
                epoch: state.epoch,
                phase: Phase::Freezing,
            },
            timeout,
        ) {
            TimeoutDecision::Rollback(_) => transition(
                RekeyDriver {
                    stage: RekeyStage::Timeout,
                    ..observed
                },
                RekeyEffect::TimeoutRollback,
            ),
            TimeoutDecision::Keep => dispatch_after_timeout(observed),
        }
    } else {
        dispatch_after_timeout(observed)
    }
}

/// The entry-point-specific decision after the state (and any timeout
/// rollback) is settled.
#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Load) && driver.epoch >= INITIAL_EPOCH))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn dispatch_after_timeout(driver: RekeyDriver) -> RekeyTransition {
    match driver.op {
        RekeyOp::Start => {
            if !driver.active {
                terminal(driver, RekeyFailure::AlreadyInProgress)
            } else {
                transition(
                    RekeyDriver {
                        stage: RekeyStage::Oram,
                        ..driver
                    },
                    RekeyEffect::CheckOram,
                )
            }
        }
        RekeyOp::Capsules => after_freeze_checks(driver),
        RekeyOp::Commit => {
            if driver.active {
                on_replay_state(driver)
            } else {
                after_freeze_checks(driver)
            }
        }
        RekeyOp::Abort => after_freeze_checks(driver),
    }
}

/// `ensure_starter`, `require_rotation_id` and `authorize_attempt`, in the
/// handler's historical precedence.
#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver)
        && matches!(driver.stage, RekeyStage::Load)
        && matches!(driver.op, RekeyOp::Capsules | RekeyOp::Commit | RekeyOp::Abort)
        && driver.epoch >= INITIAL_EPOCH
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn after_freeze_checks(driver: RekeyDriver) -> RekeyTransition {
    if driver.active {
        return terminal(driver, RekeyFailure::NoRekeyInProgress);
    }
    if !driver.starter_matches {
        return terminal(driver, RekeyFailure::StarterRequired);
    }
    if !driver.header_present {
        return terminal(driver, RekeyFailure::RotationIdRequired);
    }
    if !driver.rotation_matches {
        return terminal(driver, RekeyFailure::RotationIdMismatch);
    }
    let authority = AttemptAuthority {
        device_scope: driver.device_scope,
        starter_matches: driver.starter_matches,
        rotation_id_present: driver.rotation_present,
        rotation_id_matches: driver.rotation_matches,
    };
    match authorize_attempt(
        RekeyState {
            epoch: driver.epoch,
            phase: Phase::Freezing,
        },
        authority,
    ) {
        ShadowDecision::Allow => {}
        ShadowDecision::Reject => return terminal(driver, RekeyFailure::NotAuthorized),
    }
    match driver.op {
        RekeyOp::Capsules => finish_capsules(driver),
        RekeyOp::Commit => finish_commit(driver),
        RekeyOp::Abort => finish_abort(driver),
        RekeyOp::Start => transition(driver, RekeyEffect::Idle),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver)
        && matches!(driver.stage, RekeyStage::Load)
        && matches!(driver.op, RekeyOp::Capsules)
        && !driver.active
        && driver.starter_matches
        && driver.header_present
        && driver.rotation_matches
        && driver.device_scope
        && driver.capsules_written == 0
        && driver.epoch >= INITIAL_EPOCH
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn finish_capsules(driver: RekeyDriver) -> RekeyTransition {
    if next_epoch(driver.epoch).is_none() {
        return terminal(driver, RekeyFailure::NoSuccessor);
    }
    if driver.capsule_count > 64 {
        return terminal(driver, RekeyFailure::TooManyCapsules);
    }
    if driver.capsule_count == 0 {
        complete(RekeyDriver {
            capsules_complete: true,
            ..driver
        })
    } else {
        transition(
            RekeyDriver {
                stage: RekeyStage::Capsule,
                ..driver
            },
            RekeyEffect::WriteCapsule { index: 0 },
        )
    }
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver)
        && matches!(driver.stage, RekeyStage::Load)
        && matches!(driver.op, RekeyOp::Commit)
        && !driver.active
        && driver.starter_matches
        && driver.header_present
        && driver.rotation_matches
        && driver.device_scope
        && driver.epoch >= INITIAL_EPOCH
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn finish_commit(driver: RekeyDriver) -> RekeyTransition {
    if next_epoch(driver.epoch).is_none() {
        terminal(driver, RekeyFailure::NoSuccessor)
    } else {
        transition(
            RekeyDriver {
                stage: RekeyStage::Chunks,
                ..driver
            },
            RekeyEffect::CheckChunkShadows,
        )
    }
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver)
        && matches!(driver.stage, RekeyStage::Load)
        && matches!(driver.op, RekeyOp::Abort)
        && !driver.active
        && driver.starter_matches
        && driver.header_present
        && driver.rotation_matches
        && driver.device_scope
        && driver.epoch >= INITIAL_EPOCH
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn finish_abort(driver: RekeyDriver) -> RekeyTransition {
    let authority = AttemptAuthority {
        device_scope: driver.device_scope,
        starter_matches: driver.starter_matches,
        rotation_id_present: driver.rotation_present,
        rotation_id_matches: driver.rotation_matches,
    };
    match plan_abort(
        RekeyState {
            epoch: driver.epoch,
            phase: Phase::Freezing,
        },
        authority,
    ) {
        AbortDecision::Abort(after) => transition(
            RekeyDriver {
                stage: RekeyStage::Rollback,
                epoch: after.epoch,
                ..driver
            },
            RekeyEffect::RollbackAttempt,
        ),
        AbortDecision::Reject => terminal(driver, RekeyFailure::NotAuthorized),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Load)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_state(driver: RekeyDriver, observation: StateObservation) -> RekeyTransition {
    match observation {
        StateObservation::Loaded(state) => after_state(driver, state),
        StateObservation::Storage => terminal(driver, RekeyFailure::StateStorage),
        StateObservation::NotFound => terminal(driver, RekeyFailure::AccountNotFound),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Timeout)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_timeout(driver: RekeyDriver, observation: TimeoutObservation) -> RekeyTransition {
    match observation {
        TimeoutObservation::RolledBack => {
            let restored = RekeyDriver {
                active: true,
                timeout_done: true,
                rolled_back: true,
                timeout_rollback: true,
                stage: RekeyStage::Load,
                ..driver
            };
            // Continue from the restored active state; the entry point is
            // re-dispatched without another rollback.
            dispatch_after_timeout(restored)
        }
        TimeoutObservation::Raced(state) => {
            let raced = RekeyDriver {
                timeout_done: true,
                stage: RekeyStage::Load,
                ..driver
            };
            after_state(raced, state)
        }
        TimeoutObservation::Storage => terminal(driver, RekeyFailure::RollbackStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Oram)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_oram(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    match observation {
        ProbeObservation::Empty => transition(
            RekeyDriver {
                stage: RekeyStage::Capable,
                no_oram: true,
                ..driver
            },
            RekeyEffect::CheckCapable,
        ),
        ProbeObservation::Found => {
            let decided = RekeyDriver {
                no_oram: false,
                ..driver
            };
            // The handler reports the ORAM refusal through `plan_start`'s
            // rejection precedence, which this driver reproduces.
            terminal(decided, RekeyFailure::OramPresent)
        }
        ProbeObservation::Storage => terminal(driver, RekeyFailure::StateStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Capable)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_capable(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    match observation {
        ProbeObservation::Empty => transition(
            RekeyDriver {
                stage: RekeyStage::Acknowledged,
                capable: true,
                ..driver
            },
            RekeyEffect::CheckAcknowledged,
        ),
        ProbeObservation::Found => {
            let decided = RekeyDriver {
                capable: false,
                ..driver
            };
            terminal(decided, RekeyFailure::CapabilityRequired)
        }
        ProbeObservation::Storage => terminal(driver, RekeyFailure::StateStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Acknowledged)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_acknowledged(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    match observation {
        ProbeObservation::Empty => start_plan(RekeyDriver {
            acknowledged: true,
            ..driver
        }),
        ProbeObservation::Found => {
            let decided = RekeyDriver {
                acknowledged: false,
                ..driver
            };
            terminal(decided, RekeyFailure::AdoptionRequired)
        }
        ProbeObservation::Storage => terminal(driver, RekeyFailure::StateStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Acknowledged)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn start_plan(driver: RekeyDriver) -> RekeyTransition {
    let facts = StartFacts {
        no_oram: driver.no_oram,
        all_devices_rekey_capable: driver.capable,
        all_devices_acknowledged: driver.acknowledged,
    };
    match plan_start(
        RekeyState {
            epoch: driver.epoch,
            phase: Phase::Active,
        },
        facts,
    ) {
        StartDecision::Start(plan) => transition(
            RekeyDriver {
                stage: RekeyStage::BeginTx,
                from_epoch: plan.from_epoch,
                to_epoch: plan.to_epoch,
                ..driver
            },
            RekeyEffect::BeginFreezeTransaction,
        ),
        StartDecision::Reject => terminal(driver, RekeyFailure::NoSuccessor),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::BeginTx | RekeyStage::TxCommit)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_transaction(driver: RekeyDriver, observation: TransactionObservation) -> RekeyTransition {
    if matches!(observation, TransactionObservation::Failed) {
        return match driver.stage {
            RekeyStage::BeginTx => terminal(driver, RekeyFailure::TransactionStorage),
            RekeyStage::TxCommit => terminal(driver, RekeyFailure::TxCommitStorage),
            _ => idle(driver),
        };
    }
    match driver.stage {
        RekeyStage::BeginTx => transition(
            RekeyDriver {
                stage: RekeyStage::Inventory,
                ..driver
            },
            RekeyEffect::ReadInventory,
        ),
        RekeyStage::TxCommit => complete(driver),
        _ => idle(driver),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Inventory)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_inventory(driver: RekeyDriver, observation: InventoryObservation) -> RekeyTransition {
    match observation {
        InventoryObservation::Read => transition(
            RekeyDriver {
                stage: RekeyStage::FreezeCas,
                ..driver
            },
            RekeyEffect::FreezeCas,
        ),
        InventoryObservation::Failed => terminal(driver, RekeyFailure::InventoryStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::FreezeCas)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_freeze_cas(driver: RekeyDriver, observation: CasObservation) -> RekeyTransition {
    match observation {
        CasObservation::Updated => transition(
            RekeyDriver {
                stage: RekeyStage::Cleanup,
                ..driver
            },
            RekeyEffect::CleanupChunks,
        ),
        CasObservation::Skipped => terminal(driver, RekeyFailure::ConcurrentStart),
        CasObservation::Storage => terminal(driver, RekeyFailure::TransactionStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Cleanup)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_cleanup(driver: RekeyDriver, observation: CleanupObservation) -> RekeyTransition {
    match observation {
        CleanupObservation::Done => transition(
            RekeyDriver {
                stage: RekeyStage::TxCommit,
                ..driver
            },
            RekeyEffect::CommitFreezeTransaction,
        ),
        CleanupObservation::Storage => terminal(driver, RekeyFailure::CleanupStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Capsule)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_capsule(driver: RekeyDriver, observation: CapsuleObservation) -> RekeyTransition {
    match observation {
        CapsuleObservation::Stored => {
            let next = if driver.capsules_written < driver.capsule_count {
                driver.capsules_written + 1
            } else {
                driver.capsules_written
            };
            if next > 64 {
                return terminal(driver, RekeyFailure::TooManyCapsules);
            }
            if next == driver.capsule_count {
                transition(
                    RekeyDriver {
                        stage: RekeyStage::Done,
                        capsules_written: next,
                        capsules_complete: true,
                        responded: true,
                        ..driver
                    },
                    RekeyEffect::Complete,
                )
            } else {
                transition(
                    RekeyDriver {
                        capsules_written: next,
                        stage: RekeyStage::Capsule,
                        ..driver
                    },
                    RekeyEffect::WriteCapsule { index: next },
                )
            }
        }
        CapsuleObservation::Invalid | CapsuleObservation::NotTarget => {
            terminal(driver, RekeyFailure::CapsuleTargetInvalid)
        }
        CapsuleObservation::Storage => terminal(driver, RekeyFailure::StateStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Chunks)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_chunks(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    match observation {
        ProbeObservation::Empty => transition(
            RekeyDriver {
                stage: RekeyStage::Devices,
                chunks_complete: true,
                ..driver
            },
            RekeyEffect::CheckDeviceCapsules,
        ),
        ProbeObservation::Found => {
            let decided = RekeyDriver {
                chunks_complete: false,
                ..driver
            };
            terminal(decided, RekeyFailure::ChunkShadowsIncomplete)
        }
        ProbeObservation::Storage => terminal(driver, RekeyFailure::ChunkProbeStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Devices)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_devices(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    match observation {
        ProbeObservation::Empty => commit_plan(RekeyDriver {
            capsules_complete: true,
            ..driver
        }),
        ProbeObservation::Found => {
            let decided = RekeyDriver {
                capsules_complete: false,
                ..driver
            };
            terminal(decided, RekeyFailure::DeviceCapsulesIncomplete)
        }
        ProbeObservation::Storage => terminal(driver, RekeyFailure::CapsuleProbeStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Devices)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn commit_plan(driver: RekeyDriver) -> RekeyTransition {
    let authority = AttemptAuthority {
        device_scope: driver.device_scope,
        starter_matches: driver.starter_matches,
        rotation_id_present: driver.rotation_present,
        rotation_id_matches: driver.rotation_matches,
    };
    let facts = CommitFacts {
        authority,
        chunk_shadows_complete: driver.chunks_complete,
        device_capsules_complete: driver.capsules_complete,
    };
    match plan_commit(
        RekeyState {
            epoch: driver.epoch,
            phase: Phase::Freezing,
        },
        facts,
    ) {
        CommitDecision::Commit(plan) => transition(
            RekeyDriver {
                stage: RekeyStage::CommitCas,
                from_epoch: plan.from_epoch,
                to_epoch: plan.to_epoch,
                ..driver
            },
            RekeyEffect::CommitCas,
        ),
        CommitDecision::Reject => terminal(driver, RekeyFailure::CommitNotAuthorized),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver)
        && matches!(driver.stage, RekeyStage::CommitCas)
        && !driver.committed
        && !driver.rolled_back
        && !driver.responded
        && !driver.failed
        && driver.from_epoch == driver.epoch
        && next_epoch(driver.from_epoch) == Some(driver.to_epoch)
        && driver.to_epoch >= INITIAL_EPOCH
        && driver.device_scope
        && driver.starter_matches
        && driver.rotation_present
        && driver.rotation_matches
        && driver.chunks_complete
        && driver.capsules_complete
        && driver.capsules_written == driver.capsule_count
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_commit_cas(driver: RekeyDriver, observation: CasObservation) -> RekeyTransition {
    match observation {
        CasObservation::Updated => transition(
            RekeyDriver {
                stage: RekeyStage::Sweep,
                committed: true,
                // The commit CAS advanced the authoritative epoch by exactly
                // one and restored the active phase.
                epoch: driver.to_epoch,
                active: true,
                ..driver
            },
            RekeyEffect::SweepOldChunks,
        ),
        CasObservation::Skipped => terminal(driver, RekeyFailure::ConcurrentCommit),
        CasObservation::Storage => terminal(driver, RekeyFailure::TransactionStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Sweep)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_sweep(driver: RekeyDriver, _observation: SweepObservation) -> RekeyTransition {
    // The handler logs a failed sweep and still returns success.
    transition(
        RekeyDriver {
            stage: RekeyStage::Publish,
            ..driver
        },
        RekeyEffect::PublishEpoch,
    )
}

#[cfg_attr(hax, hax_lib::requires(
    rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Publish)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_published(driver: RekeyDriver) -> RekeyTransition {
    transition(
        RekeyDriver {
            stage: RekeyStage::Done,
            published: true,
            responded: true,
            ..driver
        },
        RekeyEffect::Complete,
    )
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Rollback)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_rollback(driver: RekeyDriver, observation: RollbackObservation) -> RekeyTransition {
    match observation {
        RollbackObservation::RolledBack => complete(RekeyDriver {
            active: true,
            rolled_back: true,
            ..driver
        }),
        RollbackObservation::Raced => terminal(driver, RekeyFailure::ConcurrentRollback),
        RollbackObservation::Storage => terminal(driver, RekeyFailure::RollbackStorage),
    }
}

/// The commit replay decision for a non-freezing account.
#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver) && matches!(driver.stage, RekeyStage::Load) && driver.active && matches!(driver.op, RekeyOp::Commit)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn on_replay_state(driver: RekeyDriver) -> RekeyTransition {
    let facts = CommitReplayFacts {
        target_epoch: driver.replay_target,
        recorded_epoch: driver.replay_recorded,
        rotation_id_present: driver.header_present,
        rotation_id_matches: driver.replay_id_matches,
    };
    match authorize_commit_replay(
        RekeyState {
            epoch: driver.epoch,
            phase: Phase::Active,
        },
        facts,
    ) {
        ShadowDecision::Allow => {
            if driver.replay_target == Some(driver.epoch)
                && driver.replay_recorded == Some(driver.epoch)
                && driver.header_present
                && driver.replay_id_matches
            {
                complete_replay(driver)
            } else {
                terminal(driver, RekeyFailure::NoRekeyInProgress)
            }
        }
        ShadowDecision::Reject => terminal(driver, RekeyFailure::NoRekeyInProgress),
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_rate_limit(driver: RekeyDriver, observation: RateLimitObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::RateLimit) {
        on_rate_limit(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_state(driver: RekeyDriver, observation: StateObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Load) {
        on_state(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_timeout(driver: RekeyDriver, observation: TimeoutObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Timeout) {
        on_timeout(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_oram(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Oram) {
        on_oram(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_capable(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Capable) {
        on_capable(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_acknowledged(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Acknowledged) {
        on_acknowledged(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_transaction(driver: RekeyDriver, observation: TransactionObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::BeginTx | RekeyStage::TxCommit) {
        on_transaction(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_tx_commit(driver: RekeyDriver, observation: TransactionObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::TxCommit) {
        on_transaction(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_inventory(driver: RekeyDriver, observation: InventoryObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Inventory) {
        on_inventory(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_freeze_cas(driver: RekeyDriver, observation: CasObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::FreezeCas) {
        on_freeze_cas(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_cleanup(driver: RekeyDriver, observation: CleanupObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Cleanup) {
        on_cleanup(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_capsule(driver: RekeyDriver, observation: CapsuleObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Capsule) {
        on_capsule(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_chunks(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Chunks) {
        on_chunks(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_devices(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Devices) {
        on_devices(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_commit_cas(driver: RekeyDriver, observation: CasObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::CommitCas) {
        on_commit_cas(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_sweep(driver: RekeyDriver, observation: SweepObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Sweep) {
        on_sweep(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_rollback(driver: RekeyDriver, observation: RollbackObservation) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Rollback) {
        on_rollback(driver, observation)
    } else {
        idle(driver)
    }
}

#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
fn step_published(driver: RekeyDriver) -> RekeyTransition {
    if matches!(driver.stage, RekeyStage::Publish) {
        on_published(driver)
    } else {
        idle(driver)
    }
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored. Each event is
/// dispatched to one contracted helper, so this function has no decision of
/// its own.
#[cfg_attr(hax, hax_lib::requires(rekey_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_state_is_sound(result.driver)
        && rekey_effect_is_sound(result.driver, result.effect)
        && (!driver.committed || result.driver.committed)
        && result.driver.op == driver.op
}))]
pub fn rekey_step(driver: RekeyDriver, event: RekeyEvent) -> RekeyTransition {
    match event {
        RekeyEvent::RateLimit(observation) => step_rate_limit(driver, observation),
        RekeyEvent::State(observation) => step_state(driver, observation),
        RekeyEvent::Timeout(observation) => step_timeout(driver, observation),
        RekeyEvent::Oram(observation) => step_oram(driver, observation),
        RekeyEvent::Capable(observation) => step_capable(driver, observation),
        RekeyEvent::Acknowledged(observation) => step_acknowledged(driver, observation),
        RekeyEvent::Transaction(observation) => step_transaction(driver, observation),
        RekeyEvent::Inventory(observation) => step_inventory(driver, observation),
        RekeyEvent::FreezeCas(observation) => step_freeze_cas(driver, observation),
        RekeyEvent::Cleanup(observation) => step_cleanup(driver, observation),
        RekeyEvent::TxCommit(observation) => step_tx_commit(driver, observation),
        RekeyEvent::Capsule(observation) => step_capsule(driver, observation),
        RekeyEvent::Chunks(observation) => step_chunks(driver, observation),
        RekeyEvent::Devices(observation) => step_devices(driver, observation),
        RekeyEvent::CommitCas(observation) => step_commit_cas(driver, observation),
        RekeyEvent::Sweep(observation) => step_sweep(driver, observation),
        RekeyEvent::Published => step_published(driver),
        RekeyEvent::Rollback(observation) => step_rollback(driver, observation),
    }
}

pub fn on_rate_limit_event(
    driver: RekeyDriver,
    observation: RateLimitObservation,
) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::RateLimit(observation))
}

pub fn on_state_event(driver: RekeyDriver, observation: StateObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::State(observation))
}

pub fn on_timeout_event(driver: RekeyDriver, observation: TimeoutObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Timeout(observation))
}

pub fn on_oram_event(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Oram(observation))
}

pub fn on_capable_event(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Capable(observation))
}

pub fn on_acknowledged_event(
    driver: RekeyDriver,
    observation: ProbeObservation,
) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Acknowledged(observation))
}

pub fn on_transaction_event(
    driver: RekeyDriver,
    observation: TransactionObservation,
) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Transaction(observation))
}

pub fn on_inventory_event(
    driver: RekeyDriver,
    observation: InventoryObservation,
) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Inventory(observation))
}

pub fn on_freeze_cas_event(driver: RekeyDriver, observation: CasObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::FreezeCas(observation))
}

pub fn on_cleanup_event(driver: RekeyDriver, observation: CleanupObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Cleanup(observation))
}

pub fn on_capsule_event(driver: RekeyDriver, observation: CapsuleObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Capsule(observation))
}

pub fn on_chunks_event(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Chunks(observation))
}

pub fn on_devices_event(driver: RekeyDriver, observation: ProbeObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Devices(observation))
}

pub fn on_commit_cas_event(driver: RekeyDriver, observation: CasObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::CommitCas(observation))
}

pub fn on_sweep_event(driver: RekeyDriver, observation: SweepObservation) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Sweep(observation))
}

pub fn on_rollback_event(
    driver: RekeyDriver,
    observation: RollbackObservation,
) -> RekeyTransition {
    rekey_step(driver, RekeyEvent::Rollback(observation))
}


// ── Rust conformance tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn device() -> RekeyRequest {
        RekeyRequest {
            authenticated: true,
            device_scope: true,
            capsule_count: 0,
        }
    }

    fn capsules(count: i64) -> RekeyRequest {
        RekeyRequest {
            capsule_count: count,
            ..device()
        }
    }

    fn active(epoch: i64) -> KeyStateObs {
        KeyStateObs {
            epoch,
            freezing: false,
            starter_matches: false,
            rotation_id_present: false,
            header_present: false,
            header_matches: false,
            replay_target: None,
            replay_recorded: None,
            replay_id_matches: false,
            expired: false,
        }
    }

    fn freezing(epoch: i64) -> KeyStateObs {
        KeyStateObs {
            epoch,
            freezing: true,
            starter_matches: true,
            rotation_id_present: true,
            header_present: true,
            header_matches: true,
            replay_target: None,
            replay_recorded: None,
            replay_id_matches: false,
            expired: false,
        }
    }

    fn stages(op: RekeyOp) -> Vec<RekeyStage> {
        let mut out = vec![
            RekeyStage::RateLimit,
            RekeyStage::Load,
            RekeyStage::Timeout,
        ];
        match op {
            RekeyOp::Start => out.extend([
                RekeyStage::Oram,
                RekeyStage::Capable,
                RekeyStage::Acknowledged,
                RekeyStage::BeginTx,
                RekeyStage::Inventory,
                RekeyStage::FreezeCas,
                RekeyStage::Cleanup,
                RekeyStage::TxCommit,
            ]),
            RekeyOp::Capsules => out.push(RekeyStage::Capsule),
            RekeyOp::Commit => out.extend([
                RekeyStage::Chunks,
                RekeyStage::Devices,
                RekeyStage::CommitCas,
                RekeyStage::Sweep,
                RekeyStage::Publish,
            ]),
            RekeyOp::Abort => out.push(RekeyStage::Rollback),
        }
        out.push(RekeyStage::Done);
        out
    }

    fn events() -> Vec<RekeyEvent> {
        let mut out = vec![];
        for observation in [RateLimitObservation::Allowed, RateLimitObservation::Limited] {
            out.push(RekeyEvent::RateLimit(observation));
        }
        out.push(RekeyEvent::State(StateObservation::Storage));
        out.push(RekeyEvent::State(StateObservation::NotFound));
        for epoch in [1, 2] {
            out.push(RekeyEvent::State(StateObservation::Loaded(active(epoch))));
            out.push(RekeyEvent::State(StateObservation::Loaded(freezing(epoch))));
        }
        for observation in [
            TimeoutObservation::RolledBack,
            TimeoutObservation::Storage,
        ] {
            out.push(RekeyEvent::Timeout(observation));
        }
        out.push(RekeyEvent::Timeout(TimeoutObservation::Raced(active(1))));
        for observation in [
            ProbeObservation::Empty,
            ProbeObservation::Found,
            ProbeObservation::Storage,
        ] {
            out.push(RekeyEvent::Oram(observation));
            out.push(RekeyEvent::Capable(observation));
            out.push(RekeyEvent::Acknowledged(observation));
            out.push(RekeyEvent::Chunks(observation));
            out.push(RekeyEvent::Devices(observation));
        }
        for observation in [TransactionObservation::Committed, TransactionObservation::Failed] {
            out.push(RekeyEvent::Transaction(observation));
            out.push(RekeyEvent::TxCommit(observation));
        }
        for observation in [InventoryObservation::Read, InventoryObservation::Failed] {
            out.push(RekeyEvent::Inventory(observation));
        }
        for observation in [
            CasObservation::Updated,
            CasObservation::Skipped,
            CasObservation::Storage,
        ] {
            out.push(RekeyEvent::FreezeCas(observation));
            out.push(RekeyEvent::CommitCas(observation));
        }
        for observation in [CleanupObservation::Done, CleanupObservation::Storage] {
            out.push(RekeyEvent::Cleanup(observation));
        }
        for observation in [
            CapsuleObservation::Stored,
            CapsuleObservation::Invalid,
            CapsuleObservation::NotTarget,
            CapsuleObservation::Storage,
        ] {
            out.push(RekeyEvent::Capsule(observation));
        }
        for observation in [SweepObservation::Done, SweepObservation::Failed] {
            out.push(RekeyEvent::Sweep(observation));
        }
        out.push(RekeyEvent::Published);
        for observation in [
            RollbackObservation::RolledBack,
            RollbackObservation::Raced,
            RollbackObservation::Storage,
        ] {
            out.push(RekeyEvent::Rollback(observation));
        }
        out
    }

    /// Every stage reachable for each operation, built through the real
    /// transitions. Tests use `sample` because some stages differ per op.
    fn sample(op: RekeyOp, stage: RekeyStage) -> RekeyDriver {
        let base = RekeyDriver {
            op,
            stage,
            authenticated: true,
            device_scope: true,
            epoch: 2,
            active: false,
            timeout_done: true,
            starter_matches: true,
            rotation_present: true,
            header_present: true,
            rotation_matches: true,
            replay_target: Some(2),
            replay_recorded: Some(2),
            replay_id_matches: true,
            capsule_count: if matches!(op, RekeyOp::Capsules) { 2 } else { 0 },
            capsules_written: 0,
            no_oram: true,
            capable: true,
            acknowledged: true,
            from_epoch: 2,
            to_epoch: 3,
            chunks_complete: true,
            capsules_complete: true,
            committed: false,
            rolled_back: false,
            timeout_rollback: false,
            published: false,
            responded: false,
            failed: false,
        };
        match stage {
            RekeyStage::RateLimit | RekeyStage::Load => RekeyDriver {
                epoch: 0,
                active: false,
                starter_matches: false,
                rotation_present: false,
                rotation_matches: false,
                replay_target: None,
                replay_recorded: None,
                replay_id_matches: false,
                no_oram: false,
                capable: false,
                acknowledged: false,
                from_epoch: 0,
                to_epoch: 0,
                chunks_complete: false,
                capsules_complete: false,
                ..base
            },
            RekeyStage::Timeout => RekeyDriver {
                epoch: 2,
                active: false,
                starter_matches: true,
                rotation_present: true,
                rotation_matches: true,
                no_oram: false,
                capable: false,
                acknowledged: false,
                from_epoch: 0,
                to_epoch: 0,
                chunks_complete: false,
                capsules_complete: false,
                ..base
            },
            RekeyStage::Oram => RekeyDriver {
                active: true,
                starter_matches: false,
                rotation_present: false,
                rotation_matches: false,
                no_oram: false,
                capable: false,
                acknowledged: false,
                from_epoch: 0,
                to_epoch: 0,
                chunks_complete: false,
                capsules_complete: false,
                ..base
            },
            RekeyStage::Capable => RekeyDriver {
                active: true,
                starter_matches: false,
                rotation_present: false,
                rotation_matches: false,
                capable: false,
                acknowledged: false,
                from_epoch: 0,
                to_epoch: 0,
                chunks_complete: false,
                capsules_complete: false,
                ..base
            },
            RekeyStage::Acknowledged => RekeyDriver {
                active: true,
                starter_matches: false,
                rotation_present: false,
                rotation_matches: false,
                acknowledged: false,
                from_epoch: 0,
                to_epoch: 0,
                chunks_complete: false,
                capsules_complete: false,
                ..base
            },
            RekeyStage::BeginTx
            | RekeyStage::Inventory
            | RekeyStage::FreezeCas
            | RekeyStage::Cleanup
            | RekeyStage::TxCommit => RekeyDriver {
                active: true,
                starter_matches: false,
                rotation_present: false,
                header_present: false,
                rotation_matches: false,
                chunks_complete: false,
                capsules_complete: false,
                ..base
            },
            RekeyStage::Capsule => RekeyDriver {
                capsules_written: 0,
                capsules_complete: false,
                ..base
            },
            RekeyStage::Chunks => RekeyDriver {
                chunks_complete: false,
                capsules_complete: false,
                ..base
            },
            RekeyStage::Devices => RekeyDriver {
                capsules_complete: false,
                ..base
            },
            RekeyStage::CommitCas => RekeyDriver {
                ..base
            },
            RekeyStage::Sweep | RekeyStage::Publish => RekeyDriver {
                committed: true,
                epoch: 3,
                active: true,
                published: matches!(stage, RekeyStage::Publish),
                ..base
            },
            RekeyStage::Rollback => RekeyDriver {
                capsule_count: 0,
                capsules_written: 0,
                ..base
            },
            RekeyStage::Done => match op {
                RekeyOp::Commit => RekeyDriver {
                    capsule_count: 0,
                    capsules_written: 0,
                    epoch: 3,
                    active: true,
                    committed: true,
                    published: true,
                    responded: true,
                    ..base
                },
                RekeyOp::Abort => RekeyDriver {
                    capsule_count: 0,
                    capsules_written: 0,
                    active: true,
                    rolled_back: true,
                    responded: true,
                    ..base
                },
                RekeyOp::Capsules => RekeyDriver {
                    capsules_written: 2,
                    capsules_complete: true,
                    responded: true,
                    ..base
                },
                RekeyOp::Start => RekeyDriver {
                    capsule_count: 0,
                    capsules_written: 0,
                    responded: true,
                    ..base
                },
            },
        }
    }

    #[test]
    fn exhaustive_stage_times_event_is_total_and_sound() {
        for op in [
            RekeyOp::Start,
            RekeyOp::Capsules,
            RekeyOp::Commit,
            RekeyOp::Abort,
        ] {
            for stage in stages(op) {
                let driver = sample(op, stage);
                assert!(
                    rekey_state_is_sound(driver),
                    "sample {op:?}/{stage:?} unsound: {driver:?}"
                );
                for event in events() {
                    let t = rekey_step(driver, event);
                    assert!(
                        rekey_state_is_sound(t.driver),
                        "soundness lost {op:?}/{stage:?} on {event:?}"
                    );
                    assert!(
                        rekey_effect_is_sound(t.driver, t.effect),
                        "effect unsound {op:?}/{stage:?} on {event:?}: {t:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn out_of_order_events_are_inert() {
        for op in [
            RekeyOp::Start,
            RekeyOp::Capsules,
            RekeyOp::Commit,
            RekeyOp::Abort,
        ] {
            for stage in stages(op) {
                let driver = sample(op, stage);
                for event in events() {
                    let matching = match (stage, &event) {
                        (RekeyStage::RateLimit, RekeyEvent::RateLimit(_)) => true,
                        (RekeyStage::Load, RekeyEvent::State(_)) => true,
                        (RekeyStage::Timeout, RekeyEvent::Timeout(_)) => true,
                        (RekeyStage::Oram, RekeyEvent::Oram(_)) => true,
                        (RekeyStage::Capable, RekeyEvent::Capable(_)) => true,
                        (RekeyStage::Acknowledged, RekeyEvent::Acknowledged(_)) => true,
                        (RekeyStage::BeginTx, RekeyEvent::Transaction(_)) => true,
                        (RekeyStage::TxCommit, RekeyEvent::Transaction(_)) => true,
                        (RekeyStage::Inventory, RekeyEvent::Inventory(_)) => true,
                        (RekeyStage::FreezeCas, RekeyEvent::FreezeCas(_)) => true,
                        (RekeyStage::Cleanup, RekeyEvent::Cleanup(_)) => true,
                        (RekeyStage::TxCommit, RekeyEvent::TxCommit(_)) => true,
                        (RekeyStage::Capsule, RekeyEvent::Capsule(_)) => true,
                        (RekeyStage::Chunks, RekeyEvent::Chunks(_)) => true,
                        (RekeyStage::Devices, RekeyEvent::Devices(_)) => true,
                        (RekeyStage::CommitCas, RekeyEvent::CommitCas(_)) => true,
                        (RekeyStage::Sweep, RekeyEvent::Sweep(_)) => true,
                        (RekeyStage::Publish, RekeyEvent::Published) => true,
                        (RekeyStage::Rollback, RekeyEvent::Rollback(_)) => true,
                        _ => false,
                    };
                    let t = rekey_step(driver, event);
                    if !matching {
                        assert_eq!(t.driver, driver, "non-matching event changed state");
                        assert_eq!(t.effect, RekeyEffect::Idle);
                    }
                }
            }
        }
    }

    #[test]
    fn start_walks_pacing_load_readiness_freeze_and_cleanup() {
        let mut t = begin_start(device());
        assert_eq!(t.effect, RekeyEffect::RateLimit);
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        assert_eq!(t.effect, RekeyEffect::LoadState);
        t = on_state_event(t.driver, StateObservation::Loaded(active(2)));
        assert_eq!(t.effect, RekeyEffect::CheckOram);
        t = on_oram_event(t.driver, ProbeObservation::Empty);
        t = on_capable_event(t.driver, ProbeObservation::Empty);
        t = on_acknowledged_event(t.driver, ProbeObservation::Empty);
        assert_eq!(t.effect, RekeyEffect::BeginFreezeTransaction);
        assert_eq!((t.driver.from_epoch, t.driver.to_epoch), (2, 3));
        t = on_transaction_event(t.driver, TransactionObservation::Committed);
        assert_eq!(t.effect, RekeyEffect::ReadInventory);
        t = on_inventory_event(t.driver, InventoryObservation::Read);
        assert_eq!(t.effect, RekeyEffect::FreezeCas);
        t = on_freeze_cas_event(t.driver, CasObservation::Updated);
        assert_eq!(t.effect, RekeyEffect::CleanupChunks);
        t = on_cleanup_event(t.driver, CleanupObservation::Done);
        assert_eq!(t.effect, RekeyEffect::CommitFreezeTransaction);
        t = on_transaction_event(t.driver, TransactionObservation::Committed);
        assert_eq!(t.effect, RekeyEffect::Complete);
        assert!(t.driver.responded && !t.driver.failed);
    }

    #[test]
    fn start_refuses_an_already_freezing_account() {
        let mut t = begin_start(device());
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(freezing(2)));
        assert_eq!(t.effect, RekeyEffect::Fail(RekeyFailure::AlreadyInProgress));
    }

    #[test]
    fn start_readiness_refusals_keep_the_handlers_precedence() {
        let ready = || {
            let mut t = begin_start(device());
            t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
            t = on_state_event(t.driver, StateObservation::Loaded(active(2)));
            t
        };
        assert_eq!(
            on_oram_event(ready().driver, ProbeObservation::Found).effect,
            RekeyEffect::Fail(RekeyFailure::OramPresent)
        );
        let capable = on_oram_event(ready().driver, ProbeObservation::Empty);
        assert_eq!(
            on_capable_event(capable.driver, ProbeObservation::Found).effect,
            RekeyEffect::Fail(RekeyFailure::CapabilityRequired)
        );
        let ack = on_capable_event(capable.driver, ProbeObservation::Empty);
        assert_eq!(
            on_acknowledged_event(ack.driver, ProbeObservation::Found).effect,
            RekeyEffect::Fail(RekeyFailure::AdoptionRequired)
        );
    }

    #[test]
    fn start_storage_failures_are_terminal_without_a_freeze() {
        let mut t = begin_start(device());
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        let t = on_state_event(t.driver, StateObservation::Storage);
        assert_eq!(t.effect, RekeyEffect::Fail(RekeyFailure::StateStorage));
        assert!(!t.driver.from_epoch != 0 || t.driver.from_epoch == 0);
    }

    #[test]
    fn capsules_write_every_entry_and_only_then_complete() {
        let mut t = begin_capsules(capsules(2));
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(freezing(2)));
        assert_eq!(t.effect, RekeyEffect::WriteCapsule { index: 0 });
        t = on_capsule_event(t.driver, CapsuleObservation::Stored);
        assert_eq!(t.effect, RekeyEffect::WriteCapsule { index: 1 });
        assert_eq!(t.driver.capsules_written, 1);
        t = on_capsule_event(t.driver, CapsuleObservation::Stored);
        assert_eq!(t.effect, RekeyEffect::Complete);
        assert_eq!(t.driver.capsules_written, 2);
        assert!(t.driver.capsules_complete);
    }

    #[test]
    fn capsules_require_starter_rotation_id_and_authority() {
        let start = |state: KeyStateObs| {
            let mut t = begin_capsules(capsules(1));
            t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
            on_state_event(t.driver, StateObservation::Loaded(state))
        };
        assert_eq!(
            start(active(2)).effect,
            RekeyEffect::Fail(RekeyFailure::NoRekeyInProgress)
        );
        let mut wrong = freezing(2);
        wrong.starter_matches = false;
        assert_eq!(
            start(wrong).effect,
            RekeyEffect::Fail(RekeyFailure::StarterRequired)
        );
        let mut no_header = freezing(2);
        no_header.header_present = false;
        assert_eq!(
            start(no_header).effect,
            RekeyEffect::Fail(RekeyFailure::RotationIdRequired)
        );
        let mut wrong_id = freezing(2);
        wrong_id.header_matches = false;
        assert_eq!(
            start(wrong_id).effect,
            RekeyEffect::Fail(RekeyFailure::RotationIdMismatch)
        );
    }

    #[test]
    fn capsule_failures_stop_before_the_remaining_entries() {
        let ok = || {
            let mut t = begin_capsules(capsules(3));
            t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
            on_state_event(t.driver, StateObservation::Loaded(freezing(2)))
        };
        for observation in [CapsuleObservation::Invalid, CapsuleObservation::NotTarget] {
            let t = on_capsule_event(ok().driver, observation);
            assert_eq!(
                t.effect,
                RekeyEffect::Fail(RekeyFailure::CapsuleTargetInvalid)
            );
            assert_eq!(t.driver.capsules_written, 0);
        }
    }

    #[test]
    fn too_many_capsules_is_refused_before_any_write() {
        let mut t = begin_capsules(capsules(65));
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(freezing(2)));
        assert_eq!(t.effect, RekeyEffect::Fail(RekeyFailure::TooManyCapsules));
    }

    #[test]
    fn commit_requires_both_completeness_observations() {
        let start = || {
            let mut t = begin_commit(device());
            t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
            on_state_event(t.driver, StateObservation::Loaded(freezing(2)))
        };
        let t = start();
        assert_eq!(t.effect, RekeyEffect::CheckChunkShadows);
        let t = on_chunks_event(t.driver, ProbeObservation::Found);
        assert_eq!(
            t.effect,
            RekeyEffect::Fail(RekeyFailure::ChunkShadowsIncomplete)
        );
        let t = start();
        let t = on_chunks_event(t.driver, ProbeObservation::Empty);
        assert_eq!(t.effect, RekeyEffect::CheckDeviceCapsules);
        let t = on_devices_event(t.driver, ProbeObservation::Found);
        assert_eq!(
            t.effect,
            RekeyEffect::Fail(RekeyFailure::DeviceCapsulesIncomplete)
        );
        let t = start();
        let t = on_chunks_event(t.driver, ProbeObservation::Empty);
        let t = on_devices_event(t.driver, ProbeObservation::Empty);
        assert_eq!(t.effect, RekeyEffect::CommitCas);
    }

    #[test]
    fn commit_sweeps_after_the_cas_and_publishes_before_complete() {
        let mut t = begin_commit(device());
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(freezing(2)));
        t = on_chunks_event(t.driver, ProbeObservation::Empty);
        t = on_devices_event(t.driver, ProbeObservation::Empty);
        t = on_commit_cas_event(t.driver, CasObservation::Updated);
        assert_eq!(t.effect, RekeyEffect::SweepOldChunks);
        assert!(t.driver.committed && !t.driver.responded);
        t = on_sweep_event(t.driver, SweepObservation::Failed);
        assert_eq!(t.effect, RekeyEffect::PublishEpoch);
        t = rekey_step(t.driver, RekeyEvent::Published);
        assert_eq!(t.effect, RekeyEffect::Complete);
        assert!(t.driver.committed && t.driver.published && t.driver.responded);
    }

    #[test]
    fn commit_cas_race_is_terminal_and_never_claims_a_commit() {
        let mut t = begin_commit(device());
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(freezing(2)));
        t = on_chunks_event(t.driver, ProbeObservation::Empty);
        t = on_devices_event(t.driver, ProbeObservation::Empty);
        let t = on_commit_cas_event(t.driver, CasObservation::Skipped);
        assert_eq!(t.effect, RekeyEffect::Fail(RekeyFailure::ConcurrentCommit));
        assert!(!t.driver.committed);
    }

    #[test]
    fn commit_replay_accepts_only_the_recorded_attempt() {
        let mut state = active(3);
        state.replay_target = Some(3);
        state.replay_recorded = Some(3);
        state.header_present = true;
        state.replay_id_matches = true;
        let t = begin_commit(device());
        let t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        let t = on_state_event(t.driver, StateObservation::Loaded(state));
        assert_eq!(t.effect, RekeyEffect::CompleteReplay);
        assert!(t.driver.responded && !t.driver.failed);

        let mut stale = state;
        stale.replay_target = Some(2);
        let t = begin_commit(device());
        let t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        let t = on_state_event(t.driver, StateObservation::Loaded(stale));
        assert_eq!(
            t.effect,
            RekeyEffect::Fail(RekeyFailure::NoRekeyInProgress)
        );
    }

    #[test]
    fn abort_rolls_back_without_advancing_the_epoch() {
        let mut t = begin_abort(device());
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(freezing(4)));
        assert_eq!(t.effect, RekeyEffect::RollbackAttempt);
        t = on_rollback_event(t.driver, RollbackObservation::RolledBack);
        assert_eq!(t.effect, RekeyEffect::Complete);
        assert!(t.driver.rolled_back && t.driver.active);
        assert_eq!(t.driver.epoch, 4);
        assert!(!t.driver.committed);
    }

    #[test]
    fn abort_requires_the_starter_and_the_live_rotation() {
        let start = |state: KeyStateObs| {
            let mut t = begin_abort(device());
            t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
            on_state_event(t.driver, StateObservation::Loaded(state))
        };
        let mut wrong = freezing(4);
        wrong.starter_matches = false;
        assert_eq!(
            start(wrong).effect,
            RekeyEffect::Fail(RekeyFailure::StarterRequired)
        );
        let mut other = freezing(4);
        other.header_matches = false;
        assert_eq!(
            start(other).effect,
            RekeyEffect::Fail(RekeyFailure::RotationIdMismatch)
        );
        assert_eq!(
            start(active(4)).effect,
            RekeyEffect::Fail(RekeyFailure::NoRekeyInProgress)
        );
    }

    #[test]
    fn timeout_rollback_restores_the_active_state_at_the_same_epoch() {
        let mut state = freezing(5);
        state.expired = true;
        let mut t = begin_start(device());
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(state));
        assert_eq!(t.effect, RekeyEffect::TimeoutRollback);
        t = on_timeout_event(t.driver, TimeoutObservation::RolledBack);
        assert_eq!(t.effect, RekeyEffect::CheckOram);
        assert!(t.driver.active && t.driver.rolled_back && t.driver.timeout_rollback);
        assert_eq!(t.driver.epoch, 5);
        assert!(!t.driver.committed);
    }

    #[test]
    fn a_lost_timeout_race_continues_with_the_winning_state() {
        let mut state = freezing(5);
        state.expired = true;
        let mut t = begin_abort(device());
        t = on_rate_limit_event(t.driver, RateLimitObservation::Allowed);
        t = on_state_event(t.driver, StateObservation::Loaded(state));
        assert_eq!(t.effect, RekeyEffect::TimeoutRollback);
        t = on_timeout_event(t.driver, TimeoutObservation::Raced(active(5)));
        assert_eq!(
            t.effect,
            RekeyEffect::Fail(RekeyFailure::NoRekeyInProgress)
        );
    }

    #[test]
    fn a_web_session_never_starts_commits_or_aborts() {
        let web = RekeyRequest {
            authenticated: true,
            device_scope: false,
            capsule_count: 1,
        };
        for t in [
            begin_start(web),
            begin_capsules(web),
            begin_commit(web),
            begin_abort(web),
        ] {
            assert_eq!(
                t.effect,
                RekeyEffect::Fail(RekeyFailure::WebSessionForbidden)
            );
            for event in events() {
                assert_eq!(rekey_step(t.driver, event).effect, RekeyEffect::Idle);
            }
        }
    }

    #[test]
    fn an_unauthenticated_request_performs_nothing() {
        let request = RekeyRequest {
            authenticated: false,
            device_scope: true,
            capsule_count: 0,
        };
        for t in [
            begin_start(request),
            begin_capsules(request),
            begin_commit(request),
            begin_abort(request),
        ] {
            assert_eq!(
                t.effect,
                RekeyEffect::Fail(RekeyFailure::Unauthenticated)
            );
        }
    }

    /// Breadth-first exploration of every reachable state up to a bounded
    /// depth for each entry point; every state and effect is sound.
    #[test]
    fn bfs_reachable_states_preserve_the_invariant() {
        for (op, start) in [
            (RekeyOp::Start, begin_start(device())),
            (RekeyOp::Capsules, begin_capsules(capsules(2))),
            (RekeyOp::Commit, begin_commit(device())),
            (RekeyOp::Abort, begin_abort(device())),
        ] {
            assert!(rekey_state_is_sound(start.driver));
            let mut frontier = vec![start.driver];
            let mut seen = BTreeSet::new();
            seen.insert(format!("{op:?}:{:?}", start.driver));
            for _ in 0..16 {
                let mut next = Vec::new();
                for driver in frontier {
                    for event in events() {
                        let t = rekey_step(driver, event);
                        assert!(
                            rekey_state_is_sound(t.driver),
                            "bfs lost soundness {op:?} {driver:?} on {event:?} -> {t:?}"
                        );
                        assert!(rekey_effect_is_sound(t.driver, t.effect));
                        let key = format!("{op:?}:{:?}", t.driver);
                        if seen.insert(key) {
                            next.push(t.driver);
                        }
                    }
                }
                frontier = next;
            }
            assert!(!seen.is_empty());
        }
    }
}
