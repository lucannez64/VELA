//! Pure post-preflight enrollment-redemption transition driver.
//!
//! The HTTP handler in `vela-server` performs the effectful steps (the atomic
//! `get_del` of the enrollment grant, the guarded device `INSERT`, the live
//! authority recheck and any grant restoration). This module owns every
//! *decision* between those effects: whether a missing, replaced or matched
//! grant is terminal or retryable, whether the final enrollment/rekey permits
//! authorize an insert, how an insert success/zero/error is classified, and
//! which live-recheck outcome restores the grant versus terminally revokes it.
//!
//! It also owns the U-24 replay decision. A request whose preflight finds no
//! live grant (the grant was consumed by a request whose reply was lost) may
//! ask the store whether this exact grant already created a device. The
//! `Replay` ceremony answers `Complete` only for a device row that this grant
//! created and whose stored key material equals the request's, so a replay
//! returns exactly the device the first request created, never a second one.
//!
//! The driver is a per-request value: it does not coordinate concurrent HTTP
//! requests and it does not observe the SQL/store state itself. Every input is
//! an observation produced by the handler. In particular a `RestoreAndFail`
//! decision records what the handler is instructed to do, not whether the
//! store restoration succeeded. `InsertObservation::Failed` is compatible
//! with an INSERT that actually committed before the error surfaced, so it is
//! terminal: the grant is restored only after a definite zero-row insert.
//!
//! The transition relation is deliberately total. Invalid or out-of-order
//! events are ignored (`RedemptionEffect::Idle`), which makes the unbounded
//! trace induction in `proofs/fstar/driver-lemmas` a statement about every
//! event sequence, not only the handler's intended order.

use crate::{
    enrollment_facts, plan_enrollment, EnrollmentDecision, EnrollmentObservation, ReadyToConsume,
};

/// Where the redemption is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionStage {
    /// The handler may attempt the atomic single-use grant consumption.
    Consume,
    /// A matched grant was consumed; the final enrollment/rekey decision is
    /// still outstanding.
    FinalPolicy,
    /// The final enrollment and rekey permits were issued; the handler may
    /// attempt exactly one guarded device insert.
    Insert,
    /// The insert observed zero rows; the handler must query live authority
    /// and report the result.
    Recheck,
    /// U-24: the preflight found no live grant, so the handler may look up the
    /// device row this exact grant created (once) and answer from it.
    Replay,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// The grant value removed by the atomic `get_del`, as observed by the
/// handler. `matches_observed_grant` is the decoded-value equality with the
/// non-consuming preflight lookup (including the credential id); the driver
/// checks the epoch and possession fields against its own preflight permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumedGrantObservation {
    pub key_epoch: i64,
    pub possession: bool,
    pub matches_observed_grant: bool,
}

/// Outcome of the single-use grant redemption observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumptionObservation {
    /// `get_del` returned no live grant (missing, expired or already redeemed).
    Missing,
    /// `get_del` returned a decoded grant.
    Present(ConsumedGrantObservation),
}

/// The actual `vela_rekey_policy::plan_active_mutation` decision, passed
/// through the driver so only a permit whose epoch equals the enrollment
/// permit can authorize the insert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyObservation {
    Permit { epoch: i64 },
    Reject,
}

/// The final policy observation. The driver calls the real
/// `enrollment_facts`/`plan_enrollment` policy; the handler does not
/// separately fabricate an enrollment permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalPolicyObservation {
    pub enrollment: EnrollmentObservation,
    pub rekey: RekeyObservation,
}

/// Result of the guarded device insert, as observed by the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertObservation {
    /// The insert reported at least one inserted row.
    Inserted,
    /// The insert reported zero rows (the SQL guard refused it).
    Skipped,
    /// The insert returned an error. This is an observation, not proof that no
    /// row was committed: an ambiguous commit/connection error can land here.
    Failed,
}

/// Live authority recheck performed only after an insert observed zero rows.
/// The order below is the handler's historical status/message precedence:
/// account absence, then credential/commitment revocation, then the
/// retryable rotation conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRecheckObservation {
    QueryFailed,
    AccountAbsent,
    /// A possession grant's staged commitment is missing or empty.
    CommitmentRevoked,
    /// A credential-bound grant's exact credential is no longer current.
    CredentialReplaced,
    /// Authority is still present; the zero-row insert was the rotation guard.
    StillRotating,
}

/// What the U-24 replay lookup observed. It runs only after the preflight
/// found no live grant, and reads the device row this exact grant created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayObservation {
    /// A device row carries this grant id for this user. `key_matches` is the
    /// exact key-material equality with the row's stored keys; a request that
    /// presents a different key cannot collect another key's device.
    Enrolled { key_matches: bool },
    /// No device row carries this grant id for this user.
    Absent,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionEvent {
    Consumed(ConsumptionObservation),
    FinalPolicy(FinalPolicyObservation),
    Insert(InsertObservation),
    Recheck(AuthorityRecheckObservation),
    /// U-24 replay: the result of the device-row lookup after a missing grant.
    Replayed(ReplayObservation),
}

/// How a redemption request starts. `Redeem` is the ordinary path: the
/// checked preflight produced its permit, so the grant may be consumed.
/// `Replay` is the lost-reply path: the preflight found no live grant, so
/// only the non-consuming device-row lookup may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionStart {
    Redeem(ReadyToConsume),
    Replay,
}

/// Failure categories, preserving the handler's historical status/message
/// precedence. `GrantChanged` is the shared retryable "changed while
/// redeeming" class used by the consumed-value mismatch and rekey rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionFailure {
    /// No live grant was removed. Terminal; nothing is restored.
    GrantUnavailable,
    /// A grant was removed but did not match the preflight permit. Restore.
    GrantChanged,
    /// The final enrollment policy rejected the actual consumption. Terminal.
    PolicyRejected,
    /// The insert returned an error. Terminal: the row may have committed.
    InsertStorage,
    /// The live-recheck query returned an error. Restore.
    RecheckStorage,
    /// The live account row disappeared. Restore.
    AccountAbsent,
    /// Recovery setup deletion revoked a possession grant. Terminal.
    CommitmentRevoked,
    /// Credential replacement revoked a credential grant. Terminal.
    CredentialReplaced,
    /// Authority is unchanged; the zero-row insert was a rotation guard. Restore.
    Rotating,
}
/// The effect the handler must perform next. A `RestoreAndFail` requires the
/// handler to restore the consumed grant before returning the failure; a
/// `Fail` requires no restoration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionEffect {
    /// Begin: attempt the atomic consumption.
    Consume,
    /// A matched grant was consumed: build and submit the final policy
    /// observation.
    FinalPolicy,
    /// Perform exactly one guarded insert with this permit.
    Insert(RedemptionInsertPermit),
    /// Query live authority after a zero-row insert.
    Recheck,
    /// U-24: perform the non-consuming device-row lookup for this grant.
    Replay,
    /// Terminal success. No later driver transition emits any effect.
    Complete,
    /// Terminal failure without restoration.
    Fail(RedemptionFailure),
    /// Restore the consumed grant, then return the failure.
    RestoreAndFail(RedemptionFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// The insert authority emitted by the driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedemptionInsertPermit {
    pub epoch: i64,
    pub possession: bool,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedemptionDriver {
    pub stage: RedemptionStage,
    /// Epoch observed in the preflight `ReadyToConsume` permit.
    pub epoch: i64,
    /// Grant type observed in the preflight `ReadyToConsume` permit.
    pub possession: bool,
    /// The atomic consumption returned the exact grant the preflight permit
    /// described (full value, epoch and possession type).
    pub consumed_matched: bool,
    /// The final `plan_enrollment` and rekey decisions both permitted the
    /// insert at `epoch`.
    pub permit_issued: bool,
    /// The driver has emitted `Insert` at most once for this request.
    pub insert_attempted: bool,
    /// The insert observation was `Inserted`.
    pub insert_succeeded: bool,
    /// The driver has instructed a grant restoration.
    pub restored: bool,
    /// This request is the U-24 replay of an already-consumed grant. A replay
    /// driver never consumes, inserts or restores anything.
    pub replay: bool,
    /// The replay lookup effect was emitted (at most once).
    pub replay_attempted: bool,
    /// The replay lookup found the device row whose stored keys equal the
    /// request's, so the request may answer with that device.
    pub replay_succeeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedemptionTransition {
    pub driver: RedemptionDriver,
    pub effect: RedemptionEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn redemption_state_is_sound(driver: RedemptionDriver) -> bool {
    let consume_clean = !driver.consumed_matched
        && !driver.permit_issued
        && !driver.insert_attempted
        && !driver.insert_succeeded
        && !driver.restored
        && !driver.replay;
    let policy_clean = driver.consumed_matched
        && !driver.permit_issued
        && !driver.insert_attempted
        && !driver.insert_succeeded
        && !driver.restored
        && !driver.replay;
    let insert_clean = driver.consumed_matched
        && driver.permit_issued
        && driver.insert_attempted
        && !driver.insert_succeeded
        && !driver.restored
        && !driver.replay;
    let replay_clean = driver.replay
        && driver.replay_attempted
        && !driver.replay_succeeded
        && !driver.consumed_matched
        && !driver.permit_issued
        && !driver.insert_attempted
        && !driver.insert_succeeded
        && !driver.restored;
    (!matches!(driver.stage, RedemptionStage::Consume) || consume_clean)
        && (!matches!(driver.stage, RedemptionStage::FinalPolicy) || policy_clean)
        && (!matches!(driver.stage, RedemptionStage::Insert) || insert_clean)
        && (!matches!(driver.stage, RedemptionStage::Recheck) || insert_clean)
        && (!matches!(driver.stage, RedemptionStage::Replay) || replay_clean)
        && (!driver.insert_attempted || (driver.consumed_matched && driver.permit_issued))
        && (!driver.insert_succeeded
            || (driver.insert_attempted
                && driver.consumed_matched
                && driver.permit_issued
                && matches!(driver.stage, RedemptionStage::Done)
                && !driver.restored
                && !driver.replay))
        && (!driver.restored
            || (matches!(driver.stage, RedemptionStage::Done)
                && !driver.insert_succeeded
                && !driver.replay))
        && (!driver.replay
            || (!driver.consumed_matched
                && !driver.permit_issued
                && !driver.insert_attempted
                && !driver.insert_succeeded
                && !driver.restored))
        && (!driver.replay_attempted || driver.replay)
        && (!driver.replay_succeeded
            || (driver.replay
                && driver.replay_attempted
                && matches!(driver.stage, RedemptionStage::Done)
                && !driver.insert_succeeded
                && !driver.restored))
}

/// Every effect the driver emits agrees with the state it produces. In
/// particular an `Insert` effect leaves the driver in `Insert` with a matched
/// consumption and both permits recorded, and no restoration effect can be
/// produced from an insert success.
pub fn redemption_effect_is_sound(driver: RedemptionDriver, effect: RedemptionEffect) -> bool {
    match effect {
        RedemptionEffect::Consume => {
            matches!(driver.stage, RedemptionStage::Consume)
                && !driver.consumed_matched
                && !driver.insert_attempted
                && !driver.replay
        }
        RedemptionEffect::FinalPolicy => {
            matches!(driver.stage, RedemptionStage::FinalPolicy)
                && driver.consumed_matched
                && !driver.permit_issued
                && !driver.insert_attempted
                && !driver.replay
        }
        RedemptionEffect::Insert(permit) => {
            matches!(driver.stage, RedemptionStage::Insert)
                && driver.consumed_matched
                && driver.permit_issued
                && driver.insert_attempted
                && !driver.insert_succeeded
                && !driver.restored
                && !driver.replay
                && permit.epoch == driver.epoch
                && permit.possession == driver.possession
        }
        RedemptionEffect::Recheck => {
            matches!(driver.stage, RedemptionStage::Recheck)
                && driver.consumed_matched
                && driver.permit_issued
                && driver.insert_attempted
                && !driver.insert_succeeded
                && !driver.restored
                && !driver.replay
        }
        RedemptionEffect::Replay => {
            matches!(driver.stage, RedemptionStage::Replay)
                && driver.replay
                && driver.replay_attempted
                && !driver.replay_succeeded
                && !driver.consumed_matched
                && !driver.permit_issued
                && !driver.insert_attempted
                && !driver.insert_succeeded
                && !driver.restored
        }
        RedemptionEffect::Complete => {
            matches!(driver.stage, RedemptionStage::Done)
                && !driver.restored
                && if driver.replay {
                    driver.replay_attempted && driver.replay_succeeded && !driver.insert_succeeded
                } else {
                    driver.insert_succeeded
                }
        }
        RedemptionEffect::Fail(_) => {
            matches!(driver.stage, RedemptionStage::Done)
                && !driver.insert_succeeded
                && !driver.replay_succeeded
        }
        RedemptionEffect::RestoreAndFail(_) => {
            matches!(driver.stage, RedemptionStage::Done)
                && driver.restored
                && !driver.insert_succeeded
                && !driver.replay
        }
        RedemptionEffect::Idle => true,
    }
}

fn transition(driver: RedemptionDriver, effect: RedemptionEffect) -> RedemptionTransition {
    RedemptionTransition { driver, effect }
}

fn idle(driver: RedemptionDriver) -> RedemptionTransition {
    transition(driver, RedemptionEffect::Idle)
}

fn terminal(driver: RedemptionDriver, failure: RedemptionFailure) -> RedemptionTransition {
    transition(
        RedemptionDriver {
            stage: RedemptionStage::Done,
            ..driver
        },
        RedemptionEffect::Fail(failure),
    )
}

fn restore_then_fail(driver: RedemptionDriver, failure: RedemptionFailure) -> RedemptionTransition {
    transition(
        RedemptionDriver {
            stage: RedemptionStage::Done,
            restored: true,
            ..driver
        },
        RedemptionEffect::RestoreAndFail(failure),
    )
}

/// Start a per-request redemption after the checked preflight produced its
/// `ReadyToConsume` permit. Only the atomic consumption may be attempted.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_state_is_sound(result.driver)
        && redemption_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, RedemptionStage::Consume)
        && !result.driver.consumed_matched
        && !result.driver.permit_issued
        && !result.driver.insert_attempted
        && !result.driver.insert_succeeded
        && !result.driver.restored
}))]
pub fn begin_redemption(ready: ReadyToConsume) -> RedemptionTransition {
    transition(
        RedemptionDriver {
            stage: RedemptionStage::Consume,
            epoch: ready.epoch(),
            possession: ready.possession(),
            consumed_matched: false,
            permit_issued: false,
            insert_attempted: false,
            insert_succeeded: false,
            restored: false,
            replay: false,
            replay_attempted: false,
            replay_succeeded: false,
        },
        RedemptionEffect::Consume,
    )
}

/// Start the U-24 replay ceremony: the checked preflight found no live grant,
/// so the only permitted effect is the non-consuming lookup of the device row
/// this exact grant created. No begin state of this ceremony can consume,
/// insert or restore anything.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_state_is_sound(result.driver)
        && redemption_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, RedemptionStage::Replay)
        && result.driver.replay
        && result.driver.replay_attempted
        && !result.driver.replay_succeeded
        && !result.driver.consumed_matched
        && !result.driver.permit_issued
        && !result.driver.insert_attempted
        && !result.driver.insert_succeeded
        && !result.driver.restored
}))]
pub fn begin_redemption_replay() -> RedemptionTransition {
    transition(
        RedemptionDriver {
            stage: RedemptionStage::Replay,
            epoch: crate::INITIAL_EPOCH,
            possession: false,
            consumed_matched: false,
            permit_issued: false,
            insert_attempted: false,
            insert_succeeded: false,
            restored: false,
            replay: true,
            replay_attempted: true,
            replay_succeeded: false,
        },
        RedemptionEffect::Replay,
    )
}

/// The single entry point the interpreter uses: a request either redeems a
/// live grant or replays the lost-reply lookup. It never does both, because
/// the two starts are disjoint and neither driver can reach the other's
/// stages.
#[cfg_attr(hax, hax_lib::requires(true))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_state_is_sound(result.driver)
        && redemption_effect_is_sound(result.driver, result.effect)
        && (matches!(result.driver.stage, RedemptionStage::Consume)
            || matches!(result.driver.stage, RedemptionStage::Replay))
        && !result.driver.consumed_matched
        && !result.driver.permit_issued
        && !result.driver.insert_attempted
        && !result.driver.insert_succeeded
        && !result.driver.restored
}))]
pub fn begin_redemption_from(start: RedemptionStart) -> RedemptionTransition {
    match start {
        RedemptionStart::Redeem(ready) => begin_redemption(ready),
        RedemptionStart::Replay => begin_redemption_replay(),
    }
}

fn on_consumed(
    driver: RedemptionDriver,
    observation: ConsumptionObservation,
) -> RedemptionTransition {
    match observation {
        ConsumptionObservation::Missing => terminal(driver, RedemptionFailure::GrantUnavailable),
        ConsumptionObservation::Present(consumed) => {
            let matched = consumed.matches_observed_grant
                && consumed.key_epoch == driver.epoch
                && consumed.possession == driver.possession;
            if matched {
                transition(
                    RedemptionDriver {
                        stage: RedemptionStage::FinalPolicy,
                        consumed_matched: true,
                        ..driver
                    },
                    RedemptionEffect::FinalPolicy,
                )
            } else {
                restore_then_fail(driver, RedemptionFailure::GrantChanged)
            }
        }
    }
}

fn on_final_policy(
    driver: RedemptionDriver,
    observation: FinalPolicyObservation,
) -> RedemptionTransition {
    match plan_enrollment(enrollment_facts(observation.enrollment)) {
        EnrollmentDecision::Enroll(permit) => {
            let permit_epoch = permit.epoch();
            let rekey_matches = match observation.rekey {
                RekeyObservation::Permit { epoch } => epoch == permit_epoch,
                RekeyObservation::Reject => false,
            };
            if permit_epoch == driver.epoch && rekey_matches && driver.consumed_matched {
                transition(
                    RedemptionDriver {
                        stage: RedemptionStage::Insert,
                        permit_issued: true,
                        insert_attempted: true,
                        ..driver
                    },
                    RedemptionEffect::Insert(RedemptionInsertPermit {
                        epoch: permit_epoch,
                        possession: driver.possession,
                    }),
                )
            } else {
                restore_then_fail(driver, RedemptionFailure::GrantChanged)
            }
        }
        // Terminal: the final policy denial is not a storage failure and the
        // handler must not re-arm the consumed grant.
        EnrollmentDecision::Reject => terminal(driver, RedemptionFailure::PolicyRejected),
    }
}

fn on_insert(driver: RedemptionDriver, observation: InsertObservation) -> RedemptionTransition {
    match observation {
        InsertObservation::Inserted => transition(
            RedemptionDriver {
                stage: RedemptionStage::Done,
                insert_succeeded: true,
                ..driver
            },
            RedemptionEffect::Complete,
        ),
        InsertObservation::Skipped => transition(
            RedemptionDriver {
                stage: RedemptionStage::Recheck,
                ..driver
            },
            RedemptionEffect::Recheck,
        ),
        // An INSERT error is ambiguous: the row may have committed before the
        // error surfaced. Restoring the grant would let a second request
        // enroll another device with it, so the failure is terminal.
        InsertObservation::Failed => terminal(driver, RedemptionFailure::InsertStorage),
    }
}

fn on_recheck(
    driver: RedemptionDriver,
    observation: AuthorityRecheckObservation,
) -> RedemptionTransition {
    match observation {
        AuthorityRecheckObservation::QueryFailed => {
            restore_then_fail(driver, RedemptionFailure::RecheckStorage)
        }
        AuthorityRecheckObservation::AccountAbsent => {
            restore_then_fail(driver, RedemptionFailure::AccountAbsent)
        }
        AuthorityRecheckObservation::CommitmentRevoked => {
            terminal(driver, RedemptionFailure::CommitmentRevoked)
        }
        AuthorityRecheckObservation::CredentialReplaced => {
            terminal(driver, RedemptionFailure::CredentialReplaced)
        }
        AuthorityRecheckObservation::StillRotating => {
            restore_then_fail(driver, RedemptionFailure::Rotating)
        }
    }
}

/// The U-24 replay verdict. Only an `Enrolled` observation whose stored keys
/// equal the request's may answer with a device; the row was written by this
/// exact grant, so the answer is the device the first request created. A
/// different key and an absent row are the same uniform grant-unavailable
/// refusal the missing-grant path has always returned.
fn on_replayed(driver: RedemptionDriver, observation: ReplayObservation) -> RedemptionTransition {
    match observation {
        ReplayObservation::Enrolled { key_matches: true } => transition(
            RedemptionDriver {
                stage: RedemptionStage::Done,
                replay_succeeded: true,
                ..driver
            },
            RedemptionEffect::Complete,
        ),
        ReplayObservation::Enrolled { key_matches: false } => {
            terminal(driver, RedemptionFailure::GrantUnavailable)
        }
        ReplayObservation::Absent => terminal(driver, RedemptionFailure::GrantUnavailable),
    }
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(redemption_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_effect_is_sound(result.driver, result.effect)
        && (!redemption_state_is_sound(driver) || redemption_state_is_sound(result.driver))
}))]
pub fn step(driver: RedemptionDriver, event: RedemptionEvent) -> RedemptionTransition {
    match event {
        RedemptionEvent::Consumed(observation) => {
            if matches!(driver.stage, RedemptionStage::Consume) {
                on_consumed(driver, observation)
            } else {
                idle(driver)
            }
        }
        RedemptionEvent::FinalPolicy(observation) => {
            if matches!(driver.stage, RedemptionStage::FinalPolicy) {
                on_final_policy(driver, observation)
            } else {
                idle(driver)
            }
        }
        RedemptionEvent::Insert(observation) => {
            if matches!(driver.stage, RedemptionStage::Insert) {
                on_insert(driver, observation)
            } else {
                idle(driver)
            }
        }
        RedemptionEvent::Recheck(observation) => {
            if matches!(driver.stage, RedemptionStage::Recheck) {
                on_recheck(driver, observation)
            } else {
                idle(driver)
            }
        }
        RedemptionEvent::Replayed(observation) => {
            if matches!(driver.stage, RedemptionStage::Replay) && driver.replay {
                on_replayed(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(redemption_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_effect_is_sound(result.driver, result.effect)
        && (!redemption_state_is_sound(driver) || redemption_state_is_sound(result.driver))
}))]
pub fn on_grant_consumed(
    driver: RedemptionDriver,
    observation: ConsumptionObservation,
) -> RedemptionTransition {
    step(driver, RedemptionEvent::Consumed(observation))
}

#[cfg_attr(hax, hax_lib::requires(redemption_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_effect_is_sound(result.driver, result.effect)
        && (!redemption_state_is_sound(driver) || redemption_state_is_sound(result.driver))
}))]
pub fn on_final_policy_observed(
    driver: RedemptionDriver,
    observation: FinalPolicyObservation,
) -> RedemptionTransition {
    step(driver, RedemptionEvent::FinalPolicy(observation))
}

#[cfg_attr(hax, hax_lib::requires(redemption_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_effect_is_sound(result.driver, result.effect)
        && (!redemption_state_is_sound(driver) || redemption_state_is_sound(result.driver))
}))]
pub fn on_insert_completed(
    driver: RedemptionDriver,
    observation: InsertObservation,
) -> RedemptionTransition {
    step(driver, RedemptionEvent::Insert(observation))
}

#[cfg_attr(hax, hax_lib::requires(redemption_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_effect_is_sound(result.driver, result.effect)
        && (!redemption_state_is_sound(driver) || redemption_state_is_sound(result.driver))
}))]
pub fn on_authority_rechecked(
    driver: RedemptionDriver,
    observation: AuthorityRecheckObservation,
) -> RedemptionTransition {
    step(driver, RedemptionEvent::Recheck(observation))
}

#[cfg_attr(hax, hax_lib::requires(redemption_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    redemption_effect_is_sound(result.driver, result.effect)
        && (!redemption_state_is_sound(driver) || redemption_state_is_sound(result.driver))
}))]
pub fn on_replay_completed(
    driver: RedemptionDriver,
    observation: ReplayObservation,
) -> RedemptionTransition {
    step(driver, RedemptionEvent::Replayed(observation))
}
