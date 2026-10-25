//! Pure post-preflight possession-proof recovery drivers.
//!
//! The two HTTP handlers in `vela-server` perform the effectful steps
//! (rate-limit counters, the atomic `get_del` of the single-use proof state, the
//! `users` row query, decoding the staged commitment, the hybrid proof
//! verification, the proof-state `set_ex_nx` and the single-use grant store).
//! This module owns every *decision* between those effects:
//!
//! - [`InitiationDriver`] decides whether an initiation observation authorizes
//!   writing a fresh challenge at the generated attempt id (and how a lost
//!   `set_ex_nx` race is classified);
//! - [`ProofRecoverDriver`] decides whether the counted attempt may consume
//!   the proof state, whether the consumed binding and live row authorize proof
//!   verification, and whether a verified proof at the current epoch may issue
//!   a grant. It never releases the server share: there is no such effect.
//!
//! The drivers only call the existing pure policy functions in [`crate`]
//! (`proof_initiate_facts`/`plan_proof_initiation` and
//! `possession_recover_facts`/`plan_possession_recovery`); they do not
//! reimplement any of their predicates.
//!
//! Both transition relations are deliberately total. Invalid or out-of-order
//! events are ignored ([`InitiateEffect::Idle`] / [`ProofRecoverEffect::Idle`]),
//! so the unbounded trace induction in
//! `proofs/fstar/possession-driver-lemmas` is a statement about every event
//! sequence, not only the handler's intended order.
//!
//! The driver is a per-request value. It does not observe the store or SQL
//! database itself, and it does not coordinate concurrent requests. Every
//! input is an observation produced by the handler, and the effects it returns
//! are instructions, not claims that the effect succeeded.

use crate::{
    observed_recovery_epoch, plan_possession_recovery, plan_proof_initiation,
    possession_recover_facts, proof_initiate_facts, PossessionRecoverObservation,
    ProofInitiateDecision, ProofInitiateObservation, RecoveryAttemptSource,
};

// ── Initiation ──────────────────────────────────────────────────────────────

/// Where the challenge initiation is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitiateStage {
    /// The handler may query the live row and build the observation.
    Observe,
    /// The observation authorized a fresh challenge; the handler may draw and
    /// atomically store it with `set_ex_nx`.
    Store,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// State of the staged commitment column as observed by the handler. `Missing`
/// is a NULL/absent column (the handler's historical unavailable error);
/// `Corrupt` is a text cell that is not valid base64 (the historical internal
/// decode error).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentObservation {
    Missing,
    Present { len: usize },
    Corrupt,
}

/// Raw observations from the initiation row query and the fresh-slot probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitiateObservation {
    pub account_present: bool,
    pub share_present: bool,
    pub commitment: CommitmentObservation,
    pub rotation_active: bool,
    /// The generated attempt id did not already occupy the store slot.
    pub attempt_id_fresh: bool,
    pub ttl_secs: u64,
}

/// The atomic `set_ex_nx` outcome for the freshly drawn challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeStoreObservation {
    /// This request wrote the challenge.
    Stored,
    /// Another writer won the slot first.
    Lost,
}

/// One initiation driver event. The handler feeds exactly the observation it
/// obtained from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitiateEvent {
    Observed(InitiateObservation),
    Stored(ChallengeStoreObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitiateFailure {
    /// No `users` row for the requested account.
    AccountUnavailable,
    /// `users.rekey_state` is set; initiation is paused.
    RotationPaused,
    /// The staged commitment column is NULL or absent.
    CommitmentMissing,
    /// The staged commitment text is not valid base64.
    CommitmentCorrupt,
    /// The `recovery_share` column is NULL or absent.
    ShareMissing,
    /// The generated attempt id is already occupied (probe or lost race).
    AttemptCollision,
    /// The checked policy rejected an observation that looked available.
    PolicyRejected,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitiateEffect {
    /// The handler may query the live row, decode the commitment and build the
    /// initiation observation.
    Observe,
    /// Draw a fresh challenge and store it with `set_ex_nx` exactly once.
    StoreChallenge,
    /// Terminal success: the challenge was stored.
    Complete,
    /// Terminal failure without storing anything.
    Fail(InitiateFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request initiation state. Every field is a decision fact established by
/// a prior transition, never a claim about the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitiationDriver {
    pub stage: InitiateStage,
    /// The observation authorized storing a challenge.
    pub authorized: bool,
    /// The challenge store observation reported a write.
    pub stored: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitiateTransition {
    pub driver: InitiationDriver,
    pub effect: InitiateEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn initiation_state_is_sound(driver: InitiationDriver) -> bool {
    let observe_clean = !driver.authorized && !driver.stored;
    let store_clean = driver.authorized && !driver.stored;
    (!matches!(driver.stage, InitiateStage::Observe) || observe_clean)
        && (!matches!(driver.stage, InitiateStage::Store) || store_clean)
        && (!driver.stored || matches!(driver.stage, InitiateStage::Done))
}

/// Every initiation effect agrees with the state it produces.
pub fn initiation_effect_is_sound(driver: InitiationDriver, effect: InitiateEffect) -> bool {
    match effect {
        InitiateEffect::Observe => {
            matches!(driver.stage, InitiateStage::Observe) && !driver.authorized && !driver.stored
        }
        InitiateEffect::StoreChallenge => {
            matches!(driver.stage, InitiateStage::Store) && driver.authorized && !driver.stored
        }
        InitiateEffect::Complete => matches!(driver.stage, InitiateStage::Done) && driver.stored,
        InitiateEffect::Fail(_) => matches!(driver.stage, InitiateStage::Done) && !driver.stored,
        InitiateEffect::Idle => true,
    }
}

fn initiate_transition(driver: InitiationDriver, effect: InitiateEffect) -> InitiateTransition {
    InitiateTransition { driver, effect }
}

fn initiate_idle(driver: InitiationDriver) -> InitiateTransition {
    initiate_transition(driver, InitiateEffect::Idle)
}

fn initiate_terminal(driver: InitiationDriver, failure: InitiateFailure) -> InitiateTransition {
    initiate_transition(
        InitiationDriver {
            stage: InitiateStage::Done,
            ..driver
        },
        InitiateEffect::Fail(failure),
    )
}

/// The first rejection in the handler's historical status/message precedence,
/// or `None` when every preceding guard admitted the observation. The checked
/// policy is the authority; this helper only names the observed guard that
/// failed so the handler can render the original status and message.
fn initiate_rejection(obs: InitiateObservation) -> Option<InitiateFailure> {
    if !obs.account_present {
        Some(InitiateFailure::AccountUnavailable)
    } else if obs.rotation_active {
        Some(InitiateFailure::RotationPaused)
    } else {
        match obs.commitment {
            // The handler historically decoded after the rotation check and
            // treated a missing column as the uniform unavailable error.
            CommitmentObservation::Missing => Some(InitiateFailure::CommitmentMissing),
            CommitmentObservation::Corrupt => Some(InitiateFailure::CommitmentCorrupt),
            CommitmentObservation::Present { .. } => {
                if !obs.share_present {
                    Some(InitiateFailure::ShareMissing)
                } else if !obs.attempt_id_fresh {
                    // The policy checks freshness before the empty-commitment
                    // arm, so a collision must win over `len == 0`.
                    Some(InitiateFailure::AttemptCollision)
                } else if matches!(obs.commitment, CommitmentObservation::Present { len: 0 }) {
                    Some(InitiateFailure::CommitmentMissing)
                } else {
                    None
                }
            }
        }
    }
}

/// Start a per-request challenge initiation. The handler may perform the live
/// row effect next.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    initiation_state_is_sound(result.driver)
        && initiation_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, InitiateStage::Observe)
        && !result.driver.authorized
        && !result.driver.stored
        && matches!(result.effect, InitiateEffect::Observe)
}))]
pub fn begin_initiation() -> InitiateTransition {
    initiate_transition(
        InitiationDriver {
            stage: InitiateStage::Observe,
            authorized: false,
            stored: false,
        },
        InitiateEffect::Observe,
    )
}

fn apply_initiation_observed(
    driver: InitiationDriver,
    observation: InitiateObservation,
) -> InitiateTransition {
    let commitment_len = match observation.commitment {
        CommitmentObservation::Present { len } => len,
        CommitmentObservation::Missing | CommitmentObservation::Corrupt => 0,
    };
    let facts = proof_initiate_facts(ProofInitiateObservation {
        account_present: observation.account_present,
        share_present: observation.share_present,
        commitment_len,
        rotation_active: observation.rotation_active,
        attempt_id_fresh: observation.attempt_id_fresh,
        ttl_secs: observation.ttl_secs,
    });
    match plan_proof_initiation(facts) {
        ProofInitiateDecision::Start => initiate_transition(
            InitiationDriver {
                stage: InitiateStage::Store,
                authorized: true,
                ..driver
            },
            InitiateEffect::StoreChallenge,
        ),
        ProofInitiateDecision::Reject => {
            // The policy is the authority. The raw observation only names the
            // historical guard/message; a policy rejection with no named guard
            // is the fail-closed internal classification.
            let failure =
                initiate_rejection(observation).unwrap_or(InitiateFailure::PolicyRejected);
            initiate_terminal(driver, failure)
        }
    }
}

fn apply_challenge_stored(
    driver: InitiationDriver,
    observation: ChallengeStoreObservation,
) -> InitiateTransition {
    match observation {
        ChallengeStoreObservation::Stored => initiate_transition(
            InitiationDriver {
                stage: InitiateStage::Done,
                stored: true,
                ..driver
            },
            InitiateEffect::Complete,
        ),
        // An observed-free slot is not authorization to overwrite another
        // writer's challenge; a lost race is the historical conflict.
        ChallengeStoreObservation::Lost => {
            initiate_terminal(driver, InitiateFailure::AttemptCollision)
        }
    }
}

/// The complete, total initiation transition relation. Events that do not
/// match the current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(initiation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    initiation_effect_is_sound(result.driver, result.effect)
        && (!initiation_state_is_sound(driver) || initiation_state_is_sound(result.driver))
}))]
pub fn step_initiation(driver: InitiationDriver, event: InitiateEvent) -> InitiateTransition {
    match event {
        InitiateEvent::Observed(observation) => {
            if matches!(driver.stage, InitiateStage::Observe) {
                apply_initiation_observed(driver, observation)
            } else {
                initiate_idle(driver)
            }
        }
        InitiateEvent::Stored(observation) => {
            if matches!(driver.stage, InitiateStage::Store) {
                apply_challenge_stored(driver, observation)
            } else {
                initiate_idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(initiation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    initiation_effect_is_sound(result.driver, result.effect)
        && (!initiation_state_is_sound(driver) || initiation_state_is_sound(result.driver))
}))]
pub fn on_initiation_observed(
    driver: InitiationDriver,
    observation: InitiateObservation,
) -> InitiateTransition {
    step_initiation(driver, InitiateEvent::Observed(observation))
}

#[cfg_attr(hax, hax_lib::requires(initiation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    initiation_effect_is_sound(result.driver, result.effect)
        && (!initiation_state_is_sound(driver) || initiation_state_is_sound(result.driver))
}))]
pub fn on_challenge_stored(
    driver: InitiationDriver,
    observation: ChallengeStoreObservation,
) -> InitiateTransition {
    step_initiation(driver, InitiateEvent::Stored(observation))
}

// ── Possession proof recovery ───────────────────────────────────────────────

/// Where the possession-proof redemption is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofRecoverStage {
    /// The handler must count the attempt against the rate-limit budget.
    Attempt,
    /// The attempt was admitted; the handler may perform the atomic single-use
    /// `get_del` of the proof state.
    Consume,
    /// A present attempt was consumed and its binding matched; the handler may
    /// query the live row and decode the staged commitment.
    Live,
    /// The live row authorized verification; the handler may verify the
    /// presented proof against the decoded commitment.
    Verify,
    /// A verified proof at the current epoch authorized one grant; the handler
    /// may store it.
    Issue,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Outcome of the rate-limit attempt count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptBudgetObservation {
    Admitted,
    Limited,
}

/// Outcome of the atomic single-use proof-state consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptConsumptionObservation {
    /// `get_del` returned no live proof state (missing, expired or used).
    Missing,
    /// The state was removed but its envelope did not decode.
    Corrupt,
    /// The state was removed and decoded. The match flags are the binding
    /// comparison with the request's user and attempt ids.
    Present {
        user_matches: bool,
        attempt_matches: bool,
        key_epoch: i64,
    },
}

/// Live `users` row observation after a matched attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofAccountObservation {
    pub account_present: bool,
    /// `users.rekey_state` is clear (no freezing/rotation in progress).
    pub account_epoch_active: bool,
    pub commitment: CommitmentObservation,
    /// `users.key_epoch` as stored; `None` means the column is absent.
    pub stored_epoch: Option<i64>,
}

/// Authenticated outcome of the hybrid proof verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofObservation {
    pub verified: bool,
}

/// Outcome of the single-use grant store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantStoreObservation {
    Stored,
    Failed,
}

/// One proof-recovery driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofRecoverEvent {
    AttemptCounted(AttemptBudgetObservation),
    AttemptConsumed(AttemptConsumptionObservation),
    AccountObserved(ProofAccountObservation),
    ProofObserved(ProofObservation),
    GrantStored(GrantStoreObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofRecoverFailure {
    /// The rate-limit budget refused the attempt.
    AttemptLimited,
    /// No live proof state matched the user/attempt key.
    AttemptMissing,
    /// The removed proof state did not decode.
    AttemptCorrupt,
    /// The decoded state is bound to another user or attempt id.
    BindingMismatch,
    /// The `users` row disappeared after the attempt was consumed.
    AccountAbsent,
    /// `users.rekey_state` is set: freezing/rotation pauses recovery.
    RotationPaused,
    /// No staged commitment exists to verify against.
    CommitmentMissing,
    /// The staged commitment text is not valid base64.
    CommitmentCorrupt,
    /// The checked possession policy rejected the verified observation.
    ProofRejected,
    /// Writing the single-use grant failed.
    GrantStorage,
}

/// The grant authority emitted by the driver. It carries only the epoch the
/// stored grant is bound to; the server share is never part of it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofGrantPermit {
    pub epoch: i64,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofRecoverEffect {
    /// Count one attempt against the rate-limit budget.
    CountAttempt,
    /// Perform the atomic single-use `get_del` of the proof state.
    ConsumeAttempt,
    /// Query the live `users` row and decode the commitment.
    QueryAccount,
    /// Verify the presented proof against the decoded commitment.
    VerifyProof,
    /// Store exactly one single-use grant at this epoch.
    IssueGrant(ProofGrantPermit),
    /// Terminal success: the grant was stored.
    Complete,
    /// Terminal failure without storing a grant.
    Fail(ProofRecoverFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request proof-recovery state. Every field is a decision fact established
/// by a prior transition, never a claim about the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofRecoverDriver {
    pub stage: ProofRecoverStage,
    /// An attempt was counted against the budget.
    pub budget_counted: bool,
    /// The single-use proof state was removed by this request.
    pub attempt_consumed: bool,
    /// The decoded attempt's user id matched the request.
    pub user_matches: bool,
    /// The decoded attempt's id matched the request.
    pub attempt_matches: bool,
    /// Epoch recorded in the consumed attempt envelope.
    pub attempt_epoch: i64,
    /// The live `users` row exists.
    pub account_present: bool,
    /// `users.rekey_state` is clear.
    pub account_epoch_active: bool,
    /// A staged commitment exists (a decoded text cell, possibly empty).
    pub commitment_present: bool,
    /// Decoded length of the staged commitment.
    pub commitment_len: usize,
    /// `users.key_epoch` as stored.
    pub stored_epoch: Option<i64>,
    /// The proof verified against the staged commitment.
    pub proof_verified: bool,
    /// The driver issued the grant authority.
    pub grant_issued: bool,
    /// The grant store reported success.
    pub grant_stored: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofRecoverTransition {
    pub driver: ProofRecoverDriver,
    pub effect: ProofRecoverEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn proof_recover_state_is_sound(driver: ProofRecoverDriver) -> bool {
    let attempt_clean = !driver.budget_counted
        && !driver.attempt_consumed
        && !driver.proof_verified
        && !driver.grant_issued
        && !driver.grant_stored;
    let consume_clean = driver.budget_counted
        && !driver.attempt_consumed
        && !driver.proof_verified
        && !driver.grant_issued
        && !driver.grant_stored;
    let live_clean = driver.budget_counted
        && driver.attempt_consumed
        && driver.user_matches
        && driver.attempt_matches
        && !driver.proof_verified
        && !driver.grant_issued
        && !driver.grant_stored;
    let verify_clean = live_clean
        && driver.account_present
        && driver.account_epoch_active
        && driver.commitment_present;
    let issue_clean = driver.budget_counted
        && driver.attempt_consumed
        && driver.user_matches
        && driver.attempt_matches
        && driver.account_present
        && driver.account_epoch_active
        && driver.commitment_present
        && driver.proof_verified
        && driver.grant_issued
        && !driver.grant_stored;
    (!matches!(driver.stage, ProofRecoverStage::Attempt) || attempt_clean)
        && (!matches!(driver.stage, ProofRecoverStage::Consume) || consume_clean)
        && (!matches!(driver.stage, ProofRecoverStage::Live) || live_clean)
        && (!matches!(driver.stage, ProofRecoverStage::Verify) || verify_clean)
        && (!matches!(driver.stage, ProofRecoverStage::Issue) || issue_clean)
        && (!driver.attempt_consumed || driver.budget_counted)
        && (!(driver.user_matches || driver.attempt_matches) || driver.attempt_consumed)
        && (!driver.proof_verified
            || (driver.attempt_consumed && driver.user_matches && driver.attempt_matches))
        && (!driver.grant_issued
            || (driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && driver.proof_verified
                && driver.account_present
                && driver.account_epoch_active
                && driver.commitment_present
                && driver.commitment_len > 0
                && driver.attempt_epoch == observed_recovery_epoch(driver.stored_epoch)
                && (matches!(driver.stage, ProofRecoverStage::Issue)
                    || matches!(driver.stage, ProofRecoverStage::Done))))
        && (!driver.grant_stored
            || (driver.grant_issued && matches!(driver.stage, ProofRecoverStage::Done)))
}

/// Every effect the driver emits agrees with the state it produces. In
/// particular an `IssueGrant` effect leaves the driver authorized at the
/// attempt's current epoch, and no effect can release the server share.
pub fn proof_recover_effect_is_sound(
    driver: ProofRecoverDriver,
    effect: ProofRecoverEffect,
) -> bool {
    match effect {
        ProofRecoverEffect::CountAttempt => {
            matches!(driver.stage, ProofRecoverStage::Attempt)
                && !driver.budget_counted
                && !driver.attempt_consumed
                && !driver.grant_issued
        }
        ProofRecoverEffect::ConsumeAttempt => {
            matches!(driver.stage, ProofRecoverStage::Consume)
                && driver.budget_counted
                && !driver.attempt_consumed
                && !driver.grant_issued
        }
        ProofRecoverEffect::QueryAccount => {
            matches!(driver.stage, ProofRecoverStage::Live)
                && driver.budget_counted
                && driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && !driver.proof_verified
                && !driver.grant_issued
        }
        ProofRecoverEffect::VerifyProof => {
            matches!(driver.stage, ProofRecoverStage::Verify)
                && driver.budget_counted
                && driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && driver.account_present
                && driver.account_epoch_active
                && driver.commitment_present
                && !driver.proof_verified
                && !driver.grant_issued
        }
        ProofRecoverEffect::IssueGrant(permit) => {
            matches!(driver.stage, ProofRecoverStage::Issue)
                && driver.budget_counted
                && driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && driver.proof_verified
                && driver.account_present
                && driver.account_epoch_active
                && driver.commitment_present
                && driver.commitment_len > 0
                && driver.grant_issued
                && !driver.grant_stored
                && permit.epoch == observed_recovery_epoch(driver.stored_epoch)
                && permit.epoch == driver.attempt_epoch
        }
        ProofRecoverEffect::Complete => {
            matches!(driver.stage, ProofRecoverStage::Done)
                && driver.grant_issued
                && driver.grant_stored
        }
        ProofRecoverEffect::Fail(_) => {
            matches!(driver.stage, ProofRecoverStage::Done) && !driver.grant_stored
        }
        ProofRecoverEffect::Idle => true,
    }
}

/// No driver effect can release the server's recovery share. This is the
/// end-to-end statement for the possession path: the share is not merely
/// omitted from the handler response, it has no representation in the effect
/// language at all.
pub fn proof_recover_effect_releases_share(effect: ProofRecoverEffect) -> bool {
    match effect {
        // The permit itself can never authorize a release: the checked policy
        // constructs it with `releases_server_share() == false`.
        ProofRecoverEffect::IssueGrant(_) => false,
        _ => false,
    }
}

fn proof_recover_transition(
    driver: ProofRecoverDriver,
    effect: ProofRecoverEffect,
) -> ProofRecoverTransition {
    ProofRecoverTransition { driver, effect }
}

fn proof_recover_idle(driver: ProofRecoverDriver) -> ProofRecoverTransition {
    proof_recover_transition(driver, ProofRecoverEffect::Idle)
}

fn proof_recover_terminal(
    driver: ProofRecoverDriver,
    failure: ProofRecoverFailure,
) -> ProofRecoverTransition {
    proof_recover_transition(
        ProofRecoverDriver {
            stage: ProofRecoverStage::Done,
            ..driver
        },
        ProofRecoverEffect::Fail(failure),
    )
}

/// Start a per-request possession-proof redemption. The handler must count the
/// attempt before touching the single-use proof state.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    proof_recover_state_is_sound(result.driver)
        && proof_recover_effect_is_sound(result.driver, result.effect)
        && !proof_recover_effect_releases_share(result.effect)
        && matches!(result.driver.stage, ProofRecoverStage::Attempt)
        && !result.driver.budget_counted
        && !result.driver.attempt_consumed
        && !result.driver.proof_verified
        && !result.driver.grant_issued
        && !result.driver.grant_stored
        && matches!(result.effect, ProofRecoverEffect::CountAttempt)
}))]
pub fn begin_proof_recover() -> ProofRecoverTransition {
    proof_recover_transition(
        ProofRecoverDriver {
            stage: ProofRecoverStage::Attempt,
            budget_counted: false,
            attempt_consumed: false,
            user_matches: false,
            attempt_matches: false,
            attempt_epoch: 0,
            account_present: false,
            account_epoch_active: false,
            commitment_present: false,
            commitment_len: 0,
            stored_epoch: None,
            proof_verified: false,
            grant_issued: false,
            grant_stored: false,
        },
        ProofRecoverEffect::CountAttempt,
    )
}

fn apply_attempt_counted(
    driver: ProofRecoverDriver,
    observation: AttemptBudgetObservation,
) -> ProofRecoverTransition {
    match observation {
        AttemptBudgetObservation::Admitted => proof_recover_transition(
            ProofRecoverDriver {
                stage: ProofRecoverStage::Consume,
                budget_counted: true,
                ..driver
            },
            ProofRecoverEffect::ConsumeAttempt,
        ),
        AttemptBudgetObservation::Limited => {
            proof_recover_terminal(driver, ProofRecoverFailure::AttemptLimited)
        }
    }
}

fn apply_attempt_consumed(
    driver: ProofRecoverDriver,
    observation: AttemptConsumptionObservation,
) -> ProofRecoverTransition {
    match observation {
        AttemptConsumptionObservation::Missing => {
            proof_recover_terminal(driver, ProofRecoverFailure::AttemptMissing)
        }
        AttemptConsumptionObservation::Corrupt => {
            proof_recover_terminal(driver, ProofRecoverFailure::AttemptCorrupt)
        }
        AttemptConsumptionObservation::Present {
            user_matches,
            attempt_matches,
            key_epoch,
        } => {
            let consumed = ProofRecoverDriver {
                attempt_consumed: true,
                user_matches,
                attempt_matches,
                attempt_epoch: key_epoch,
                ..driver
            };
            if user_matches && attempt_matches {
                proof_recover_transition(
                    ProofRecoverDriver {
                        stage: ProofRecoverStage::Live,
                        ..consumed
                    },
                    ProofRecoverEffect::QueryAccount,
                )
            } else {
                // The binding mismatch consumed the proof state anyway; the
                // terminal failure must not re-arm it.
                proof_recover_terminal(consumed, ProofRecoverFailure::BindingMismatch)
            }
        }
    }
}

fn apply_account_observed(
    driver: ProofRecoverDriver,
    observation: ProofAccountObservation,
) -> ProofRecoverTransition {
    if !observation.account_present {
        return proof_recover_terminal(driver, ProofRecoverFailure::AccountAbsent);
    }
    if !observation.account_epoch_active {
        // Freezing/rotation pauses recovery before the commitment is examined;
        // this is the historical 409 precedence.
        return proof_recover_terminal(driver, ProofRecoverFailure::RotationPaused);
    }
    match observation.commitment {
        CommitmentObservation::Missing => {
            proof_recover_terminal(driver, ProofRecoverFailure::CommitmentMissing)
        }
        CommitmentObservation::Corrupt => {
            proof_recover_terminal(driver, ProofRecoverFailure::CommitmentCorrupt)
        }
        CommitmentObservation::Present { len } => proof_recover_transition(
            ProofRecoverDriver {
                stage: ProofRecoverStage::Verify,
                account_present: true,
                account_epoch_active: true,
                commitment_present: true,
                commitment_len: len,
                stored_epoch: observation.stored_epoch,
                ..driver
            },
            ProofRecoverEffect::VerifyProof,
        ),
    }
}

fn apply_proof_observed(
    driver: ProofRecoverDriver,
    observation: ProofObservation,
) -> ProofRecoverTransition {
    // Every value is a fact from the consumed envelope and the live observation;
    // the checked policy decides. The driver never fabricates verification.
    let facts = possession_recover_facts(PossessionRecoverObservation {
        attempt_source: RecoveryAttemptSource::Consumed,
        account_present: true,
        user_matches: driver.user_matches,
        attempt_matches: driver.attempt_matches,
        proof_verified: observation.verified,
        account_epoch_active: true,
        commitment_len: driver.commitment_len,
        commitment_epoch: driver.attempt_epoch,
        stored_epoch: driver.stored_epoch,
    });
    match plan_possession_recovery(facts) {
        crate::PossessionRecoverDecision::Grant(permit) => {
            debug_assert!(!permit.releases_server_share());
            proof_recover_transition(
                ProofRecoverDriver {
                    stage: ProofRecoverStage::Issue,
                    proof_verified: true,
                    grant_issued: true,
                    ..driver
                },
                ProofRecoverEffect::IssueGrant(ProofGrantPermit {
                    epoch: permit.epoch(),
                }),
            )
        }
        crate::PossessionRecoverDecision::Reject => proof_recover_transition(
            ProofRecoverDriver {
                stage: ProofRecoverStage::Done,
                proof_verified: observation.verified,
                ..driver
            },
            ProofRecoverEffect::Fail(ProofRecoverFailure::ProofRejected),
        ),
    }
}

fn apply_grant_stored(
    driver: ProofRecoverDriver,
    observation: GrantStoreObservation,
) -> ProofRecoverTransition {
    match observation {
        GrantStoreObservation::Stored => proof_recover_transition(
            ProofRecoverDriver {
                stage: ProofRecoverStage::Done,
                grant_stored: true,
                ..driver
            },
            ProofRecoverEffect::Complete,
        ),
        GrantStoreObservation::Failed => {
            proof_recover_terminal(driver, ProofRecoverFailure::GrantStorage)
        }
    }
}

/// The complete, total proof-recovery transition relation. Events that do not
/// match the current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(proof_recover_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    proof_recover_effect_is_sound(result.driver, result.effect)
        && !proof_recover_effect_releases_share(result.effect)
        && (!proof_recover_state_is_sound(driver) || proof_recover_state_is_sound(result.driver))
}))]
pub fn step_proof_recover(
    driver: ProofRecoverDriver,
    event: ProofRecoverEvent,
) -> ProofRecoverTransition {
    match event {
        ProofRecoverEvent::AttemptCounted(observation) => {
            if matches!(driver.stage, ProofRecoverStage::Attempt) {
                apply_attempt_counted(driver, observation)
            } else {
                proof_recover_idle(driver)
            }
        }
        ProofRecoverEvent::AttemptConsumed(observation) => {
            if matches!(driver.stage, ProofRecoverStage::Consume) {
                apply_attempt_consumed(driver, observation)
            } else {
                proof_recover_idle(driver)
            }
        }
        ProofRecoverEvent::AccountObserved(observation) => {
            if matches!(driver.stage, ProofRecoverStage::Live) {
                apply_account_observed(driver, observation)
            } else {
                proof_recover_idle(driver)
            }
        }
        ProofRecoverEvent::ProofObserved(observation) => {
            if matches!(driver.stage, ProofRecoverStage::Verify) {
                apply_proof_observed(driver, observation)
            } else {
                proof_recover_idle(driver)
            }
        }
        ProofRecoverEvent::GrantStored(observation) => {
            if matches!(driver.stage, ProofRecoverStage::Issue) {
                apply_grant_stored(driver, observation)
            } else {
                proof_recover_idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(proof_recover_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    proof_recover_effect_is_sound(result.driver, result.effect)
        && !proof_recover_effect_releases_share(result.effect)
        && (!proof_recover_state_is_sound(driver) || proof_recover_state_is_sound(result.driver))
}))]
pub fn on_attempt_counted(
    driver: ProofRecoverDriver,
    observation: AttemptBudgetObservation,
) -> ProofRecoverTransition {
    step_proof_recover(driver, ProofRecoverEvent::AttemptCounted(observation))
}

#[cfg_attr(hax, hax_lib::requires(proof_recover_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    proof_recover_effect_is_sound(result.driver, result.effect)
        && !proof_recover_effect_releases_share(result.effect)
        && (!proof_recover_state_is_sound(driver) || proof_recover_state_is_sound(result.driver))
}))]
pub fn on_attempt_consumed(
    driver: ProofRecoverDriver,
    observation: AttemptConsumptionObservation,
) -> ProofRecoverTransition {
    step_proof_recover(driver, ProofRecoverEvent::AttemptConsumed(observation))
}

#[cfg_attr(hax, hax_lib::requires(proof_recover_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    proof_recover_effect_is_sound(result.driver, result.effect)
        && !proof_recover_effect_releases_share(result.effect)
        && (!proof_recover_state_is_sound(driver) || proof_recover_state_is_sound(result.driver))
}))]
pub fn on_account_observed(
    driver: ProofRecoverDriver,
    observation: ProofAccountObservation,
) -> ProofRecoverTransition {
    step_proof_recover(driver, ProofRecoverEvent::AccountObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(proof_recover_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    proof_recover_effect_is_sound(result.driver, result.effect)
        && !proof_recover_effect_releases_share(result.effect)
        && (!proof_recover_state_is_sound(driver) || proof_recover_state_is_sound(result.driver))
}))]
pub fn on_proof_observed(
    driver: ProofRecoverDriver,
    observation: ProofObservation,
) -> ProofRecoverTransition {
    step_proof_recover(driver, ProofRecoverEvent::ProofObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(proof_recover_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    proof_recover_effect_is_sound(result.driver, result.effect)
        && !proof_recover_effect_releases_share(result.effect)
        && (!proof_recover_state_is_sound(driver) || proof_recover_state_is_sound(result.driver))
}))]
pub fn on_grant_stored(
    driver: ProofRecoverDriver,
    observation: GrantStoreObservation,
) -> ProofRecoverTransition {
    step_proof_recover(driver, ProofRecoverEvent::GrantStored(observation))
}
