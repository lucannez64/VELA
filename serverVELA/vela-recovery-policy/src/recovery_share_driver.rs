//! Pure per-request decision driver for the recovery-share lifecycle.
//!
//! The four handlers in `vela-server/src/recovery/mod.rs` perform the
//! effectful steps (the guarded `users` update that stages a candidate, the
//! guarded update that promotes the exact staged split, the guarded delete that
//! clears both the active share and the staged split, and the read query).
//! This module owns every *decision* between those effects:
//!
//! - whether the authenticated actor is an active device of its own account
//!   (and, for the mutating operations, whether the rekey policy issued a
//!   device-authority permit at the declared epoch);
//! - whether the checked publication policy authorizes staging the requested
//!   split at the declared epoch, promoting the requested split, or deleting
//!   the share;
//! - how a zero-row guarded update is classified: a changed epoch or an active
//!   rotation is the historical `Rekeyed` failure, a surviving exact candidate
//!   is the historical idempotent success, and any other candidate is the
//!   historical `Conflict`;
//! - that a delete clears the active share and the staged split together;
//! - that a read only succeeds when the row still has a share.
//!
//! Every transition relation is total: events that do not answer the effect
//! the driver just emitted (and every event after `Done`) are [`ShareEffect::Idle`].
//!
//! The driver is a per-request value. It does not observe the database itself
//! and does not coordinate concurrent requests; every input is an observation
//! produced by the handler, and every effect is an instruction, not a claim
//! that the SQL statement matched a row. The composition proof in
//! `proofs/fstar/recovery-share-driver-composition` connects it to the shared
//! account share state read by the WebAuthn and possession drivers.

use crate::{
    plan_publication_finalize, plan_publication_stage, plan_share_deletion,
    PublicationFinalizeDecision, PublicationFinalizeRequest, PublicationStageDecision,
    PublicationStageRequest, ShareDeletionDecision, ShareDeletionRequest,
    INITIAL_EPOCH,
};

/// Which recovery-share handler this request is running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareOperation {
    /// `PUT /recovery/share`: stage a candidate split.
    Stage,
    /// `POST /recovery/share/finalize`: promote the exact staged split.
    Finalize,
    /// `DELETE /recovery/share`: clear the active share and the staged split.
    Delete,
    /// `GET /recovery/share`: return the active share to its own device.
    Read,
}

/// Actor facts established by the authenticated `DeviceSession` extractor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareActorObservation {
    /// The middleware verified the PASETO identity.
    pub authenticated: bool,
    /// The middleware's durable `devices.revoked = 0` check.
    pub device_active: bool,
    /// Every SQL predicate and store read of this request is scoped to the one
    /// account the verified session names. The shipped handlers use a single
    /// `session.user_id`, so this is true; the driver still refuses a request
    /// that is not, so a rewired caller cannot act on another account.
    pub scoped_to_session_account: bool,
}

/// The request facts the driver needs. `split` is a deterministic token derived
/// from the request's split id; it is used only to keep the driver's own
/// publication identity coherent and never changes the SQL text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareRequestObservation {
    pub operation: ShareOperation,
    pub actor: ShareActorObservation,
    /// The epoch the request declares (the `key_epoch` body field or the
    /// `X-Vela-Epoch` header). Ignored by `Read`.
    pub declared_epoch: i64,
    /// The mutating request carried a split id and a non-empty share.
    pub split_id_present: bool,
    /// The mutating request carried a non-empty server share.
    pub share_present: bool,
    /// The rekey policy issued a device-authority permit at `declared_epoch`.
    /// Always true for `Read`, which is not a vault mutation.
    pub device_authority: bool,
    /// Deterministic token of the request split id (`0` for delete/read).
    pub split: i64,
}

/// Outcome of the guarded update that stages a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageUpdateObservation {
    /// Exactly one row was updated: the candidate is staged.
    Staged,
    /// Zero rows: the handler must inspect the live row.
    NotStaged,
}

/// Live-row observation after a zero-row stage update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageAccountObservation {
    pub account_present: bool,
    /// `users.key_epoch` as stored; `None` means the column is absent.
    pub stored_epoch: Option<i64>,
    /// `users.rekey_state` is non-null (freezing or rotation in progress).
    pub rotation_active: bool,
    /// The live `recovery_share` text equals the exact staged share text.
    pub active_share_matches: bool,
    /// The live `recovery_split_id` equals the staged split id.
    pub active_split_matches: bool,
}

/// Outcome of the guarded update that promotes the exact staged split.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizeUpdateObservation {
    /// Exactly one row was updated: the staged split is now active.
    Promoted,
    /// Zero rows: the handler must inspect the live row.
    NotPromoted,
}

/// Live-row observation after a zero-row finalize update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizeAccountObservation {
    pub account_present: bool,
    pub stored_epoch: Option<i64>,
    pub rotation_active: bool,
    /// The live `recovery_split_id` equals the requested split id.
    pub active_split_matches: bool,
}

/// Outcome of the guarded delete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteUpdateObservation {
    /// Exactly one row was updated: both the share and the staged split are
    /// cleared by the same statement.
    Deleted,
    /// Zero rows: the epoch moved or a rotation started.
    NotDeleted,
}

/// Outcome of the read query and the share-text decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadObservation {
    /// A `users` row exists for the session account.
    pub account_present: bool,
    /// The row's `recovery_share` column is non-null.
    pub share_present: bool,
}

/// Where the lifecycle request is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareStage {
    /// The handler may perform the stage update.
    Stage,
    /// A zero-row stage update: inspect the live row.
    StageAccount,
    /// The handler may perform the finalize update.
    Finalize,
    /// A zero-row finalize update: inspect the live row.
    FinalizeAccount,
    /// The handler may perform the delete update.
    Delete,
    /// The handler may perform the read query.
    Read,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// One driver event. The handler feeds exactly the observation it obtained from
/// the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareEvent {
    StageUpdate(StageUpdateObservation),
    StageAccount(StageAccountObservation),
    FinalizeUpdate(FinalizeUpdateObservation),
    FinalizeAccount(FinalizeAccountObservation),
    DeleteUpdate(DeleteUpdateObservation),
    ReadObserved(ReadObservation),
}

/// Failure categories, preserving the handlers' historical statuses/messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareFailure {
    /// The actor was not an authenticated, active device. Terminal, no effect.
    Unauthenticated,
    /// The request was not scoped to the account its session names. Terminal,
    /// no effect.
    CrossAccount,
    /// The checked publication/deletion policy rejected the request.
    PolicyRejected,
    /// The `users` row no longer exists after a zero-row update or read.
    AccountMissing,
    /// The epoch moved or a rotation is active. The handlers report `Rekeyed`
    /// with their operation-specific message.
    Rekeyed,
    /// A different split is active (or a different candidate survived); the
    /// handlers report their operation-specific conflict.
    Conflict,
    /// The read found no active share.
    ShareMissing,
}

/// Authority to stage one split at one epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareStagePermit {
    epoch: i64,
    split: i64,
    binds_split_and_share: bool,
}

impl ShareStagePermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn split(self) -> i64 {
        self.split
    }

    pub const fn binds_split_and_share(self) -> bool {
        self.binds_split_and_share
    }
}

/// Authority to promote exactly one staged split at one epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareFinalizePermit {
    epoch: i64,
    split: i64,
    exact_pending_required: bool,
    empty_active_required: bool,
}

impl ShareFinalizePermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn split(self) -> i64 {
        self.split
    }

    pub const fn requires_exact_pending(self) -> bool {
        self.exact_pending_required
    }

    pub const fn requires_empty_active(self) -> bool {
        self.empty_active_required
    }
}

/// Authority to clear both the active share and the staged split.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareDeletePermit {
    epoch: i64,
    clears_share_and_pending: bool,
}

impl ShareDeletePermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn clears_share_and_pending(self) -> bool {
        self.clears_share_and_pending
    }
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareEffect {
    /// Whether the candidate can be staged: run the guarded stage update.
    StageShare(ShareStagePermit),
    /// Inspect the live row after a zero-row stage update.
    StageQueryAccount,
    /// Promote the exact staged split with the guarded update.
    PromoteStagedSplit(ShareFinalizePermit),
    /// Inspect the live row after a zero-row finalize update.
    FinalizeQueryAccount,
    /// Clear the active share and the staged split with the guarded delete.
    DeleteShare(ShareDeletePermit),
    /// Read the active share of the session account.
    ReadShare,
    /// Terminal success.
    Complete,
    /// Terminal failure. No SQL statement follows it.
    Fail(ShareFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request lifecycle state. Every field is a decision fact established by a
/// prior transition, never a claim about the database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareLifecycleDriver {
    pub stage: ShareStage,
    pub operation: ShareOperation,
    /// The middleware verified an authenticated device.
    pub actor_active: bool,
    /// Every effect is scoped to the session's own account.
    pub same_account: bool,
    /// The permit epoch for the mutating operation.
    pub epoch: i64,
    /// The request split token (stage/finalize).
    pub split: i64,
    /// The mutating request carried a split id.
    pub split_id_present: bool,
    /// The driver instructed the (stage/finalize/delete) update.
    pub update_attempted: bool,
    /// The update observation reported exactly one row.
    pub update_applied: bool,
    /// The live row was inspected after a zero-row update.
    pub account_checked: bool,
    /// The live row confirmed the exact already-finalized split.
    pub active_confirmed: bool,
    /// The read query confirmed a present share.
    pub read_confirmed: bool,
    /// The delete instruction clears the active share.
    pub deletes_share: bool,
    /// The delete instruction clears the staged split.
    pub deletes_pending: bool,
    /// A success response was authorized.
    pub responded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareTransition {
    pub driver: ShareLifecycleDriver,
    pub effect: ShareEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn share_lifecycle_state_is_sound(d: ShareLifecycleDriver) -> bool {
    let initial = !d.update_attempted
        && !d.update_applied
        && !d.account_checked
        && !d.active_confirmed
        && !d.read_confirmed
        && !d.responded
        && !d.failed;
    let awaiting_account = d.update_attempted
        && !d.update_applied
        && !d.account_checked
        && !d.active_confirmed
        && !d.read_confirmed
        && !d.responded
        && !d.failed;
    let done_ok = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded
            || match d.operation {
                ShareOperation::Stage | ShareOperation::Finalize => {
                    d.update_applied || d.active_confirmed
                }
                ShareOperation::Delete => {
                    d.update_applied && d.deletes_share && d.deletes_pending
                }
                ShareOperation::Read => d.read_confirmed,
            })
        && (!d.failed || (!d.update_applied && !d.read_confirmed));
    (!matches!(d.stage, ShareStage::Stage)
        || (matches!(d.operation, ShareOperation::Stage) && initial))
        && (!matches!(d.stage, ShareStage::StageAccount)
            || (matches!(d.operation, ShareOperation::Stage) && awaiting_account))
        && (!matches!(d.stage, ShareStage::Finalize)
            || (matches!(d.operation, ShareOperation::Finalize) && initial))
        && (!matches!(d.stage, ShareStage::FinalizeAccount)
            || (matches!(d.operation, ShareOperation::Finalize) && awaiting_account))
        && (!matches!(d.stage, ShareStage::Delete)
            || (matches!(d.operation, ShareOperation::Delete)
                && initial
                && d.deletes_share
                && d.deletes_pending))
        && (!matches!(d.stage, ShareStage::Read)
            || (matches!(d.operation, ShareOperation::Read)
                && !d.update_attempted
                && !d.update_applied
                && !d.account_checked
                && !d.active_confirmed
                && !d.read_confirmed
                && !d.responded
                && !d.failed))
        && (!matches!(d.stage, ShareStage::Done) || done_ok)
        && (!d.same_account || d.actor_active)
        && (matches!(d.stage, ShareStage::Done) || (d.actor_active && d.same_account))
        && (!d.update_attempted
            || (d.actor_active
                && d.same_account
                && matches!(
                    d.operation,
                    ShareOperation::Stage | ShareOperation::Finalize | ShareOperation::Delete
                )))
        && (!d.update_applied || (d.update_attempted && d.responded))
        && (!d.account_checked || (d.update_attempted && !matches!(d.operation, ShareOperation::Read)))
        && (!d.active_confirmed || (d.account_checked && d.responded))
        && (!d.read_confirmed || (matches!(d.operation, ShareOperation::Read) && d.responded))
        && (!d.deletes_share || matches!(d.operation, ShareOperation::Delete))
        && (!d.deletes_pending || matches!(d.operation, ShareOperation::Delete))
        && (!(d.deletes_share || d.deletes_pending) || (d.deletes_share && d.deletes_pending))
        && (!d.responded || matches!(d.stage, ShareStage::Done))
        && (!d.failed || matches!(d.stage, ShareStage::Done))
}

/// Every effect the driver emits agrees with the state it produces.
pub fn share_lifecycle_effect_is_sound(
    d: ShareLifecycleDriver,
    effect: ShareEffect,
) -> bool {
    let active = d.actor_active && d.same_account && !d.failed;
    match effect {
        ShareEffect::StageShare(permit) => {
            active
                && matches!(d.stage, ShareStage::Stage)
                && matches!(d.operation, ShareOperation::Stage)
                && !d.update_attempted
                && d.split_id_present
                && permit.epoch == d.epoch
                && permit.split == d.split
                && permit.binds_split_and_share
        }
        ShareEffect::StageQueryAccount => {
            active
                && matches!(d.stage, ShareStage::StageAccount)
                && matches!(d.operation, ShareOperation::Stage)
                && d.update_attempted
                && !d.update_applied
                && !d.account_checked
        }
        ShareEffect::PromoteStagedSplit(permit) => {
            active
                && matches!(d.stage, ShareStage::Finalize)
                && matches!(d.operation, ShareOperation::Finalize)
                && !d.update_attempted
                && d.split_id_present
                && permit.epoch == d.epoch
                && permit.split == d.split
                && permit.exact_pending_required
                && permit.empty_active_required
        }
        ShareEffect::FinalizeQueryAccount => {
            active
                && matches!(d.stage, ShareStage::FinalizeAccount)
                && matches!(d.operation, ShareOperation::Finalize)
                && d.update_attempted
                && !d.update_applied
                && !d.account_checked
        }
        ShareEffect::DeleteShare(permit) => {
            active
                && matches!(d.stage, ShareStage::Delete)
                && matches!(d.operation, ShareOperation::Delete)
                && !d.update_attempted
                && permit.epoch == d.epoch
                && permit.epoch >= INITIAL_EPOCH
                && permit.clears_share_and_pending
                && d.deletes_share
                && d.deletes_pending
        }
        ShareEffect::ReadShare => {
            active
                && matches!(d.stage, ShareStage::Read)
                && matches!(d.operation, ShareOperation::Read)
                && !d.read_confirmed
                && !d.responded
        }
        ShareEffect::Complete => {
            matches!(d.stage, ShareStage::Done)
                && d.responded
                && !d.failed
                && match d.operation {
                    ShareOperation::Stage | ShareOperation::Finalize => {
                        d.update_applied || d.active_confirmed
                    }
                    ShareOperation::Delete => {
                        d.update_applied && d.deletes_share && d.deletes_pending
                    }
                    ShareOperation::Read => d.read_confirmed,
                }
        }
        ShareEffect::Fail(_) => {
            matches!(d.stage, ShareStage::Done)
                && d.failed
                && !d.responded
                && !d.update_applied
                && !d.read_confirmed
        }
        ShareEffect::Idle => true,
    }
}

fn transition(driver: ShareLifecycleDriver, effect: ShareEffect) -> ShareTransition {
    ShareTransition { driver, effect }
}

fn idle(driver: ShareLifecycleDriver) -> ShareTransition {
    transition(driver, ShareEffect::Idle)
}

fn terminal(driver: ShareLifecycleDriver, failure: ShareFailure) -> ShareTransition {
    transition(
        ShareLifecycleDriver {
            stage: ShareStage::Done,
            failed: true,
            ..driver
        },
        ShareEffect::Fail(failure),
    )
}

fn base_driver(
    observation: ShareRequestObservation,
    stage: ShareStage,
    epoch: i64,
) -> ShareLifecycleDriver {
    ShareLifecycleDriver {
        stage,
        operation: observation.operation,
        actor_active: true,
        same_account: true,
        epoch,
        split: observation.split,
        split_id_present: observation.split_id_present,
        update_attempted: false,
        update_applied: false,
        account_checked: false,
        active_confirmed: false,
        read_confirmed: false,
        deletes_share: false,
        deletes_pending: false,
        responded: false,
        failed: false,
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(
    observation.operation,
    ShareOperation::Stage
)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_state_is_sound(result.driver)
        && share_lifecycle_effect_is_sound(result.driver, result.effect)
}))]
fn begin_stage(observation: ShareRequestObservation) -> ShareTransition {
    let request = PublicationStageRequest {
        declared_epoch: observation.declared_epoch,
        split_id_present: observation.split_id_present,
        server_share_present: observation.share_present,
        device_authority: observation.device_authority,
    };
    match plan_publication_stage(request) {
        PublicationStageDecision::Stage(permit) => {
            let d = base_driver(observation, ShareStage::Stage, permit.epoch());
            transition(
                d,
                ShareEffect::StageShare(ShareStagePermit {
                    epoch: permit.epoch(),
                    split: observation.split,
                    binds_split_and_share: permit.binds_split_and_share(),
                }),
            )
        }
        PublicationStageDecision::Reject => {
            let d = base_driver(observation, ShareStage::Done, observation.declared_epoch);
            terminal(d, ShareFailure::PolicyRejected)
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(
    observation.operation,
    ShareOperation::Finalize
)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_state_is_sound(result.driver)
        && share_lifecycle_effect_is_sound(result.driver, result.effect)
}))]
fn begin_finalize(observation: ShareRequestObservation) -> ShareTransition {
    let request = PublicationFinalizeRequest {
        declared_epoch: observation.declared_epoch,
        split_id_present: observation.split_id_present,
        device_authority: observation.device_authority,
    };
    match plan_publication_finalize(request) {
        PublicationFinalizeDecision::Finalize(permit) => {
            let d = base_driver(observation, ShareStage::Finalize, permit.epoch());
            transition(
                d,
                ShareEffect::PromoteStagedSplit(ShareFinalizePermit {
                    epoch: permit.epoch(),
                    split: observation.split,
                    exact_pending_required: permit.requires_exact_pending(),
                    empty_active_required: permit.requires_empty_active(),
                }),
            )
        }
        PublicationFinalizeDecision::Reject => {
            let d = base_driver(observation, ShareStage::Done, observation.declared_epoch);
            terminal(d, ShareFailure::PolicyRejected)
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(
    observation.operation,
    ShareOperation::Delete
)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_state_is_sound(result.driver)
        && share_lifecycle_effect_is_sound(result.driver, result.effect)
}))]
fn begin_delete(observation: ShareRequestObservation) -> ShareTransition {
    let request = ShareDeletionRequest {
        declared_epoch: observation.declared_epoch,
        device_authority: observation.device_authority,
    };
    match plan_share_deletion(request) {
        ShareDeletionDecision::Delete(permit) => {
            let mut d = base_driver(observation, ShareStage::Delete, permit.epoch());
            d.deletes_share = true;
            d.deletes_pending = true;
            transition(
                d,
                ShareEffect::DeleteShare(ShareDeletePermit {
                    epoch: permit.epoch(),
                    clears_share_and_pending: permit.clears_share_and_pending(),
                }),
            )
        }
        ShareDeletionDecision::Reject => {
            let d = base_driver(observation, ShareStage::Done, observation.declared_epoch);
            terminal(d, ShareFailure::PolicyRejected)
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(
    observation.operation,
    ShareOperation::Read
)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_state_is_sound(result.driver)
        && share_lifecycle_effect_is_sound(result.driver, result.effect)
}))]
fn begin_read(observation: ShareRequestObservation) -> ShareTransition {
    let d = base_driver(observation, ShareStage::Read, observation.declared_epoch);
    transition(d, ShareEffect::ReadShare)
}

/// Start a per-request recovery-share lifecycle operation. An actor the
/// middleware did not verify as an authenticated, active device — or a request
/// whose effects are not scoped to the session's own account — produces a
/// terminal failure without any effect.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_state_is_sound(result.driver)
        && share_lifecycle_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_share_lifecycle(observation: ShareRequestObservation) -> ShareTransition {
    let actor_active = observation.actor.authenticated && observation.actor.device_active;
    if !actor_active {
        let mut d = base_driver(observation, ShareStage::Done, observation.declared_epoch);
        d.actor_active = false;
        d.same_account = false;
        return terminal(d, ShareFailure::Unauthenticated);
    }
    if !observation.actor.scoped_to_session_account {
        let mut d = base_driver(observation, ShareStage::Done, observation.declared_epoch);
        d.same_account = false;
        return terminal(d, ShareFailure::CrossAccount);
    }
    match observation.operation {
        ShareOperation::Stage => begin_stage(observation),
        ShareOperation::Finalize => begin_finalize(observation),
        ShareOperation::Delete => begin_delete(observation),
        ShareOperation::Read => begin_read(observation),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    share_lifecycle_state_is_sound(driver)
        && matches!(driver.stage, ShareStage::Stage)
        && matches!(driver.operation, ShareOperation::Stage)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
fn apply_on_stage_update(
    driver: ShareLifecycleDriver,
    observation: StageUpdateObservation,
) -> ShareTransition {
    match observation {
        StageUpdateObservation::Staged => transition(
            ShareLifecycleDriver {
                stage: ShareStage::Done,
                update_attempted: true,
                update_applied: true,
                responded: true,
                ..driver
            },
            ShareEffect::Complete,
        ),
        StageUpdateObservation::NotStaged => transition(
            ShareLifecycleDriver {
                stage: ShareStage::StageAccount,
                update_attempted: true,
                ..driver
            },
            ShareEffect::StageQueryAccount,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    share_lifecycle_state_is_sound(driver)
        && matches!(driver.stage, ShareStage::StageAccount)
        && matches!(driver.operation, ShareOperation::Stage)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
fn apply_on_stage_account(
    driver: ShareLifecycleDriver,
    observation: StageAccountObservation,
) -> ShareTransition {
    if !observation.account_present {
        return terminal(
            ShareLifecycleDriver {
                account_checked: true,
                ..driver
            },
            ShareFailure::AccountMissing,
        );
    }
    if observation.stored_epoch != Some(driver.epoch) || observation.rotation_active {
        return terminal(
            ShareLifecycleDriver {
                account_checked: true,
                ..driver
            },
            ShareFailure::Rekeyed,
        );
    }
    if observation.active_share_matches && observation.active_split_matches {
        return transition(
            ShareLifecycleDriver {
                stage: ShareStage::Done,
                account_checked: true,
                active_confirmed: true,
                responded: true,
                ..driver
            },
            ShareEffect::Complete,
        );
    }
    terminal(
        ShareLifecycleDriver {
            account_checked: true,
            ..driver
        },
        ShareFailure::Conflict,
    )
}

#[cfg_attr(hax, hax_lib::requires(
    share_lifecycle_state_is_sound(driver)
        && matches!(driver.stage, ShareStage::Finalize)
        && matches!(driver.operation, ShareOperation::Finalize)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
fn apply_on_finalize_update(
    driver: ShareLifecycleDriver,
    observation: FinalizeUpdateObservation,
) -> ShareTransition {
    match observation {
        FinalizeUpdateObservation::Promoted => transition(
            ShareLifecycleDriver {
                stage: ShareStage::Done,
                update_attempted: true,
                update_applied: true,
                responded: true,
                ..driver
            },
            ShareEffect::Complete,
        ),
        FinalizeUpdateObservation::NotPromoted => transition(
            ShareLifecycleDriver {
                stage: ShareStage::FinalizeAccount,
                update_attempted: true,
                ..driver
            },
            ShareEffect::FinalizeQueryAccount,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    share_lifecycle_state_is_sound(driver)
        && matches!(driver.stage, ShareStage::FinalizeAccount)
        && matches!(driver.operation, ShareOperation::Finalize)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
fn apply_on_finalize_account(
    driver: ShareLifecycleDriver,
    observation: FinalizeAccountObservation,
) -> ShareTransition {
    if !observation.account_present {
        return terminal(
            ShareLifecycleDriver {
                account_checked: true,
                ..driver
            },
            ShareFailure::AccountMissing,
        );
    }
    if observation.stored_epoch != Some(driver.epoch) || observation.rotation_active {
        return terminal(
            ShareLifecycleDriver {
                account_checked: true,
                ..driver
            },
            ShareFailure::Rekeyed,
        );
    }
    if observation.active_split_matches {
        return transition(
            ShareLifecycleDriver {
                stage: ShareStage::Done,
                account_checked: true,
                active_confirmed: true,
                responded: true,
                ..driver
            },
            ShareEffect::Complete,
        );
    }
    terminal(
        ShareLifecycleDriver {
            account_checked: true,
            ..driver
        },
        ShareFailure::Conflict,
    )
}

#[cfg_attr(hax, hax_lib::requires(
    share_lifecycle_state_is_sound(driver)
        && matches!(driver.stage, ShareStage::Delete)
        && matches!(driver.operation, ShareOperation::Delete)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
fn apply_on_delete_update(
    driver: ShareLifecycleDriver,
    observation: DeleteUpdateObservation,
) -> ShareTransition {
    match observation {
        DeleteUpdateObservation::Deleted => transition(
            ShareLifecycleDriver {
                stage: ShareStage::Done,
                update_attempted: true,
                update_applied: true,
                responded: true,
                ..driver
            },
            ShareEffect::Complete,
        ),
        DeleteUpdateObservation::NotDeleted => terminal(
            ShareLifecycleDriver {
                update_attempted: true,
                ..driver
            },
            ShareFailure::Rekeyed,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    share_lifecycle_state_is_sound(driver)
        && matches!(driver.stage, ShareStage::Read)
        && matches!(driver.operation, ShareOperation::Read)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
fn apply_on_read(
    driver: ShareLifecycleDriver,
    observation: ReadObservation,
) -> ShareTransition {
    if !observation.account_present || !observation.share_present {
        return terminal(driver, ShareFailure::ShareMissing);
    }
    transition(
        ShareLifecycleDriver {
            stage: ShareStage::Done,
            read_confirmed: true,
            responded: true,
            ..driver
        },
        ShareEffect::Complete,
    )
}

/// The complete, total transition relation. Events that do not answer the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(share_lifecycle_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
pub fn step_share_lifecycle(
    driver: ShareLifecycleDriver,
    event: ShareEvent,
) -> ShareTransition {
    match event {
        ShareEvent::StageUpdate(observation) => {
            if matches!(driver.stage, ShareStage::Stage) {
                apply_on_stage_update(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::StageAccount(observation) => {
            if matches!(driver.stage, ShareStage::StageAccount) {
                apply_on_stage_account(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::FinalizeUpdate(observation) => {
            if matches!(driver.stage, ShareStage::Finalize) {
                apply_on_finalize_update(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::FinalizeAccount(observation) => {
            if matches!(driver.stage, ShareStage::FinalizeAccount) {
                apply_on_finalize_account(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::DeleteUpdate(observation) => {
            if matches!(driver.stage, ShareStage::Delete) {
                apply_on_delete_update(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::ReadObserved(observation) => {
            if matches!(driver.stage, ShareStage::Read) {
                apply_on_read(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(share_lifecycle_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
pub fn on_stage_update(
    driver: ShareLifecycleDriver,
    observation: StageUpdateObservation,
) -> ShareTransition {
    step_share_lifecycle(driver, ShareEvent::StageUpdate(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_lifecycle_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
pub fn on_stage_account(
    driver: ShareLifecycleDriver,
    observation: StageAccountObservation,
) -> ShareTransition {
    step_share_lifecycle(driver, ShareEvent::StageAccount(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_lifecycle_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
pub fn on_finalize_update(
    driver: ShareLifecycleDriver,
    observation: FinalizeUpdateObservation,
) -> ShareTransition {
    step_share_lifecycle(driver, ShareEvent::FinalizeUpdate(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_lifecycle_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
pub fn on_finalize_account(
    driver: ShareLifecycleDriver,
    observation: FinalizeAccountObservation,
) -> ShareTransition {
    step_share_lifecycle(driver, ShareEvent::FinalizeAccount(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_lifecycle_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
pub fn on_delete_update(
    driver: ShareLifecycleDriver,
    observation: DeleteUpdateObservation,
) -> ShareTransition {
    step_share_lifecycle(driver, ShareEvent::DeleteUpdate(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_lifecycle_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_lifecycle_effect_is_sound(result.driver, result.effect)
        && (!share_lifecycle_state_is_sound(driver) || share_lifecycle_state_is_sound(result.driver))
}))]
pub fn on_read_observed(
    driver: ShareLifecycleDriver,
    observation: ReadObservation,
) -> ShareTransition {
    step_share_lifecycle(driver, ShareEvent::ReadObserved(observation))
}
