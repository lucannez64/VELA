//! Pure post-validation WebAuthn recovery drivers.
//!
//! The HTTP handlers in `vela-server` perform the effectful steps (rate-limit
//! counters, the `users` row and recovery-credential queries, the WebAuthn
//! ceremony start/finish, the atomic single-use `get_del` of the attempt-bound
//! challenge, the conditional credential update, the single-use grant store and
//! the share read). This module owns every *decision* between those effects for
//! the four WebAuthn recovery requests:
//!
//! - [`RegistrationStartDriver`] decides whether a recovery-credential
//!   registration ceremony may start and how the non-atomic `set_ex` state
//!   write is classified;
//! - [`RegistrationDriver`] decides whether a verified registration ceremony
//!   may overwrite the account's recovery credential, and how a lost challenge,
//!   an invalid ceremony, a duplicate credential, a policy rejection and a
//!   missing account row are classified;
//! - [`AuthStartDriver`] decides whether an authentication ceremony may start
//!   and how the atomic `set_ex_nx` attempt store is classified;
//! - [`AuthFinishDriver`] decides whether the consumed challenge may verify an
//!   assertion, whether the authenticator metadata update may run, and whether
//!   the live row authorizes the share release plus the single-use enrollment
//!   grant.
//!
//! The drivers only call the existing pure policy functions in [`crate`]
//! (`initiate_facts`/`plan_initiation`, `plan_registration`,
//! `credential_update_facts`/`plan_credential_update` and
//! `recover_facts`/`plan_recovery`); they do not reimplement any of their
//! predicates.
//!
//! Every transition relation is deliberately total. Invalid or out-of-order
//! events are ignored (`*Effect::Idle`), so the unbounded trace induction in
//! `proofs/fstar/webauthn-driver-lemmas` is a statement about every event
//! sequence, not only the handler's intended order.
//!
//! The drivers are per-request values. They do not observe the store or SQL
//! database themselves, and they do not coordinate concurrent requests. Every
//! input is an observation produced by the handler, and the effects it returns
//! are instructions, not claims that the effect succeeded.
//!
//! ## Share release
//!
//! This path is the one recovery flow whose *purpose* is to release Share 2;
//! unlike the possession-proof path, the server share is genuinely an effect
//! here. The driver therefore emits one indivisible `ReleaseGrant` effect that
//! authorizes reading the observed share **and** storing the single-use
//! enrollment grant at the policy's epoch. It carries no share bytes: the
//! handler re-reads the row. No other effect can release the share, and the
//! share is never returned unless the driver reaches `Complete` after a
//! successful grant store.

use crate::{
    credential_update_facts, initiate_facts, observed_recovery_epoch, plan_credential_update,
    plan_initiation, plan_recovery, plan_registration, recover_facts,
    CredentialUpdateDecision, CredentialUpdateObservation, InitiateDecision, InitiateObservation,
    RecoverDecision, RecoverObservation, RecoveryAttemptSource, RegistrationDecision,
    RegistrationFacts,
};

// ── Observations shared by registration and authentication ─────────────────

/// The account's currently stored recovery credential, as observed by the
/// handler. `Missing` is a NULL column (no credential registered yet);
/// `Corrupt` is a text cell whose JSON does not decode (the handler's
/// historical internal error).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredCredentialObservation {
    Missing,
    Present,
    Corrupt,
}

/// Outcome of the challenge-state write. `Stored` means this request wrote the
/// slot, `Lost` means another writer won an `set_ex_nx` slot first, and
/// `StorageFailed` means the store call itself returned an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeStoreObservation {
    Stored,
    Lost,
    StorageFailed,
}

/// Outcome of the rate-limit attempt count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptBudgetObservation {
    Admitted,
    Limited,
}

/// Outcome of the single-use grant store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantStoreObservation {
    Stored,
    Failed,
}

// ── Registration start ──────────────────────────────────────────────────────

/// Where the registration-ceremony start is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStartStage {
    /// The handler may query the currently stored credential.
    Observe,
    /// The credential observation authorized a fresh ceremony; the handler may
    /// start it.
    Ceremony,
    /// A ceremony was produced; the handler may write the registration state.
    Store,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Raw observation from the stored-credential lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationStartObservation {
    pub account_present: bool,
    pub credential: StoredCredentialObservation,
}

/// Outcome of `start_passkey_registration`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyStartObservation {
    Started,
    Failed,
}

/// One registration-start driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStartEvent {
    Observed(RegistrationStartObservation),
    CeremonyStarted(CeremonyStartObservation),
    Stored(ChallengeStoreObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStartFailure {
    /// No `users` row for the authenticated account.
    AccountUnavailable,
    /// The stored credential JSON did not decode.
    CredentialCorrupt,
    /// `start_passkey_registration` rejected the request.
    CeremonyFailed,
    /// The registration-state write failed.
    StateStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStartEffect {
    /// Query the stored recovery credential.
    Observe,
    /// Start the registration ceremony, excluding the observed credential.
    StartCeremony,
    /// Write the registration state with `set_ex`.
    StoreState,
    /// Terminal success: the state was stored.
    Complete,
    /// Terminal failure without storing anything.
    Fail(RegistrationStartFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request registration-start state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationStartDriver {
    pub stage: RegistrationStartStage,
    /// The credential observation authorized starting the ceremony.
    pub authorized: bool,
    /// The registration state write reported success.
    pub stored: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationStartTransition {
    pub driver: RegistrationStartDriver,
    pub effect: RegistrationStartEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn registration_start_state_is_sound(driver: RegistrationStartDriver) -> bool {
    let observe_clean = !driver.authorized && !driver.stored;
    let ceremony_clean = driver.authorized && !driver.stored;
    (!matches!(driver.stage, RegistrationStartStage::Observe) || observe_clean)
        && (!matches!(driver.stage, RegistrationStartStage::Ceremony) || ceremony_clean)
        && (!matches!(driver.stage, RegistrationStartStage::Store) || ceremony_clean)
        && (!driver.stored || driver.authorized)
        && (!driver.stored || matches!(driver.stage, RegistrationStartStage::Done))
}

/// Every registration-start effect agrees with the state it produces.
pub fn registration_start_effect_is_sound(
    driver: RegistrationStartDriver,
    effect: RegistrationStartEffect,
) -> bool {
    match effect {
        RegistrationStartEffect::Observe => {
            matches!(driver.stage, RegistrationStartStage::Observe)
                && !driver.authorized
                && !driver.stored
        }
        RegistrationStartEffect::StartCeremony => {
            matches!(driver.stage, RegistrationStartStage::Ceremony)
                && driver.authorized
                && !driver.stored
        }
        RegistrationStartEffect::StoreState => {
            matches!(driver.stage, RegistrationStartStage::Store)
                && driver.authorized
                && !driver.stored
        }
        RegistrationStartEffect::Complete => {
            matches!(driver.stage, RegistrationStartStage::Done) && driver.stored
        }
        RegistrationStartEffect::Fail(_) => {
            matches!(driver.stage, RegistrationStartStage::Done) && !driver.stored
        }
        RegistrationStartEffect::Idle => true,
    }
}

fn registration_start_transition(
    driver: RegistrationStartDriver,
    effect: RegistrationStartEffect,
) -> RegistrationStartTransition {
    RegistrationStartTransition { driver, effect }
}

fn registration_start_idle(driver: RegistrationStartDriver) -> RegistrationStartTransition {
    registration_start_transition(driver, RegistrationStartEffect::Idle)
}

fn registration_start_terminal(
    driver: RegistrationStartDriver,
    failure: RegistrationStartFailure,
) -> RegistrationStartTransition {
    registration_start_transition(
        RegistrationStartDriver {
            stage: RegistrationStartStage::Done,
            ..driver
        },
        RegistrationStartEffect::Fail(failure),
    )
}

/// Start a per-request recovery-credential registration. The handler may query
/// the currently stored credential next.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_start_state_is_sound(result.driver)
        && registration_start_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, RegistrationStartStage::Observe)
        && !result.driver.authorized
        && !result.driver.stored
        && matches!(result.effect, RegistrationStartEffect::Observe)
}))]
pub fn begin_registration_start() -> RegistrationStartTransition {
    registration_start_transition(
        RegistrationStartDriver {
            stage: RegistrationStartStage::Observe,
            authorized: false,
            stored: false,
        },
        RegistrationStartEffect::Observe,
    )
}

fn apply_registration_start_observed(
    driver: RegistrationStartDriver,
    observation: RegistrationStartObservation,
) -> RegistrationStartTransition {
    if !observation.account_present {
        return registration_start_terminal(driver, RegistrationStartFailure::AccountUnavailable);
    }
    match observation.credential {
        StoredCredentialObservation::Corrupt => {
            registration_start_terminal(driver, RegistrationStartFailure::CredentialCorrupt)
        }
        // A missing credential is the ordinary first-registration case; an
        // existing one only becomes the ceremony's exclusion list.
        StoredCredentialObservation::Missing | StoredCredentialObservation::Present => {
            registration_start_transition(
                RegistrationStartDriver {
                    stage: RegistrationStartStage::Ceremony,
                    authorized: true,
                    ..driver
                },
                RegistrationStartEffect::StartCeremony,
            )
        }
    }
}

fn apply_registration_ceremony_started(
    driver: RegistrationStartDriver,
    observation: CeremonyStartObservation,
) -> RegistrationStartTransition {
    match observation {
        CeremonyStartObservation::Started => registration_start_transition(
            RegistrationStartDriver {
                stage: RegistrationStartStage::Store,
                ..driver
            },
            RegistrationStartEffect::StoreState,
        ),
        CeremonyStartObservation::Failed => {
            registration_start_terminal(driver, RegistrationStartFailure::CeremonyFailed)
        }
    }
}

fn apply_registration_start_stored(
    driver: RegistrationStartDriver,
    observation: ChallengeStoreObservation,
) -> RegistrationStartTransition {
    match observation {
        ChallengeStoreObservation::Stored => registration_start_transition(
            RegistrationStartDriver {
                stage: RegistrationStartStage::Done,
                stored: true,
                ..driver
            },
            RegistrationStartEffect::Complete,
        ),
        // `set_ex` is not insert-if-absent, but a store error still means no
        // trustworthy state was written by this request.
        ChallengeStoreObservation::Lost | ChallengeStoreObservation::StorageFailed => {
            registration_start_terminal(driver, RegistrationStartFailure::StateStorage)
        }
    }
}

/// The complete, total registration-start transition relation. Events that do
/// not match the current stage (and every event after `Done`) are ignored.
#[cfg_attr(
    hax,
    hax_lib::requires(registration_start_state_is_sound(driver))
)]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_start_effect_is_sound(result.driver, result.effect)
        && (!registration_start_state_is_sound(driver)
            || registration_start_state_is_sound(result.driver))
}))]
pub fn step_registration_start(
    driver: RegistrationStartDriver,
    event: RegistrationStartEvent,
) -> RegistrationStartTransition {
    match event {
        RegistrationStartEvent::Observed(observation) => {
            if matches!(driver.stage, RegistrationStartStage::Observe) {
                apply_registration_start_observed(driver, observation)
            } else {
                registration_start_idle(driver)
            }
        }
        RegistrationStartEvent::CeremonyStarted(observation) => {
            if matches!(driver.stage, RegistrationStartStage::Ceremony) {
                apply_registration_ceremony_started(driver, observation)
            } else {
                registration_start_idle(driver)
            }
        }
        RegistrationStartEvent::Stored(observation) => {
            if matches!(driver.stage, RegistrationStartStage::Store) {
                apply_registration_start_stored(driver, observation)
            } else {
                registration_start_idle(driver)
            }
        }
    }
}

#[cfg_attr(
    hax,
    hax_lib::requires(registration_start_state_is_sound(driver))
)]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_start_effect_is_sound(result.driver, result.effect)
        && (!registration_start_state_is_sound(driver)
            || registration_start_state_is_sound(result.driver))
}))]
pub fn on_registration_start_observed(
    driver: RegistrationStartDriver,
    observation: RegistrationStartObservation,
) -> RegistrationStartTransition {
    step_registration_start(driver, RegistrationStartEvent::Observed(observation))
}

#[cfg_attr(
    hax,
    hax_lib::requires(registration_start_state_is_sound(driver))
)]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_start_effect_is_sound(result.driver, result.effect)
        && (!registration_start_state_is_sound(driver)
            || registration_start_state_is_sound(result.driver))
}))]
pub fn on_registration_ceremony_started(
    driver: RegistrationStartDriver,
    observation: CeremonyStartObservation,
) -> RegistrationStartTransition {
    step_registration_start(driver, RegistrationStartEvent::CeremonyStarted(observation))
}

#[cfg_attr(
    hax,
    hax_lib::requires(registration_start_state_is_sound(driver))
)]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_start_effect_is_sound(result.driver, result.effect)
        && (!registration_start_state_is_sound(driver)
            || registration_start_state_is_sound(result.driver))
}))]
pub fn on_registration_start_stored(
    driver: RegistrationStartDriver,
    observation: ChallengeStoreObservation,
) -> RegistrationStartTransition {
    step_registration_start(driver, RegistrationStartEvent::Stored(observation))
}

// ── Registration finish ─────────────────────────────────────────────────────

/// Where the registration finish is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStage {
    /// The handler must count the attempt against the registration limiter.
    Attempt,
    /// The attempt was admitted; the handler may consume the registration state.
    Consume,
    /// The registration state was consumed; the handler may verify the
    /// ceremony.
    Verify,
    /// The ceremony verified; the handler may check credential uniqueness.
    Uniqueness,
    /// The checked policy issued a registration permit; the handler may write
    /// the credential.
    Persist,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Outcome of the atomic single-use registration-state consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStateObservation {
    /// No state matched (missing or already used).
    Missing,
    /// The state was removed but its JSON envelope did not decode.
    Corrupt,
    /// The exact state was removed and decoded.
    Present,
}

/// Authenticated outcome of `finish_passkey_registration`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationVerificationObservation {
    pub credential_valid: bool,
}

/// Outcome of the cross-account duplicate-credential lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialUniquenessObservation {
    Unique,
    RegisteredElsewhere,
    LookupFailed,
}

/// Outcome of the guarded credential write. `AccountGone` is a zero-row
/// `UPDATE`; `EncodingFailed` is a serialization failure before the write;
/// `StorageFailed` is a database error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPersistObservation {
    Persisted,
    AccountGone,
    EncodingFailed,
    StorageFailed,
}

/// One registration-finish driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationEvent {
    AttemptCounted(AttemptBudgetObservation),
    StateConsumed(RegistrationStateObservation),
    RegistrationVerified(RegistrationVerificationObservation),
    CredentialLookedUp(CredentialUniquenessObservation),
    CredentialPersisted(CredentialPersistObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationFailure {
    /// The registration rate limiter refused the request.
    AttemptLimited,
    /// No live registration state matched (expired or already used).
    StateUnavailable,
    /// The removed state did not decode.
    StateCorrupt,
    /// WebAuthn registration verification failed.
    VerificationFailed,
    /// The credential is registered to another account.
    UniquenessConflict,
    /// The duplicate-credential lookup failed.
    UniquenessStorage,
    /// The checked policy rejected an otherwise observed registration.
    PolicyRejected,
    /// The account row disappeared before the credential write.
    AccountGone,
    /// The credential could not be serialized.
    PersistEncoding,
    /// The credential write failed.
    PersistStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationEffect {
    /// Count one attempt against the registration limiter.
    CountAttempt,
    /// Perform the atomic single-use `get_del` of the registration state.
    ConsumeState,
    /// Verify the presented registration ceremony.
    VerifyRegistration,
    /// Look up the credential across accounts.
    CheckCredentialUniqueness,
    /// Persist exactly one credential after the checked policy permit.
    PersistCredential,
    /// Terminal success: the credential was written.
    Complete,
    /// Terminal failure without writing a credential.
    Fail(RegistrationFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request registration-finish state. Every field is a decision fact
/// established by a prior transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationDriver {
    pub stage: RegistrationStage,
    /// An attempt was counted against the limiter.
    pub budget_counted: bool,
    /// The single-use registration state was removed by this request.
    pub state_consumed: bool,
    /// The ceremony's credential verified.
    pub credential_valid: bool,
    /// The credential is not registered to another account.
    pub credential_unique: bool,
    /// The checked policy issued a registration permit.
    pub permit_issued: bool,
    /// The credential write reported success.
    pub credential_stored: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationTransition {
    pub driver: RegistrationDriver,
    pub effect: RegistrationEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn registration_state_is_sound(driver: RegistrationDriver) -> bool {
    let attempt_clean = !driver.budget_counted
        && !driver.state_consumed
        && !driver.credential_valid
        && !driver.credential_unique
        && !driver.permit_issued
        && !driver.credential_stored;
    let consume_clean = driver.budget_counted
        && !driver.state_consumed
        && !driver.credential_valid
        && !driver.credential_unique
        && !driver.permit_issued
        && !driver.credential_stored;
    let verify_clean = driver.budget_counted
        && driver.state_consumed
        && !driver.credential_valid
        && !driver.credential_unique
        && !driver.permit_issued
        && !driver.credential_stored;
    let uniqueness_clean = driver.budget_counted
        && driver.state_consumed
        && driver.credential_valid
        && !driver.credential_unique
        && !driver.permit_issued
        && !driver.credential_stored;
    let persist_clean = driver.budget_counted
        && driver.state_consumed
        && driver.credential_valid
        && driver.credential_unique
        && driver.permit_issued
        && !driver.credential_stored;
    (!matches!(driver.stage, RegistrationStage::Attempt) || attempt_clean)
        && (!matches!(driver.stage, RegistrationStage::Consume) || consume_clean)
        && (!matches!(driver.stage, RegistrationStage::Verify) || verify_clean)
        && (!matches!(driver.stage, RegistrationStage::Uniqueness) || uniqueness_clean)
        && (!matches!(driver.stage, RegistrationStage::Persist) || persist_clean)
        && (!driver.state_consumed || driver.budget_counted)
        && (!driver.credential_valid || driver.state_consumed)
        && (!driver.credential_unique || driver.credential_valid)
        && (!driver.permit_issued || (driver.credential_valid && driver.credential_unique))
        && (!driver.credential_stored
            || (driver.permit_issued && matches!(driver.stage, RegistrationStage::Done)))
}

/// Every registration effect agrees with the state it produces. In particular
/// `PersistCredential` is only emitted after the checked policy's permit.
pub fn registration_effect_is_sound(
    driver: RegistrationDriver,
    effect: RegistrationEffect,
) -> bool {
    match effect {
        RegistrationEffect::CountAttempt => {
            matches!(driver.stage, RegistrationStage::Attempt)
                && !driver.budget_counted
                && !driver.state_consumed
                && !driver.permit_issued
        }
        RegistrationEffect::ConsumeState => {
            matches!(driver.stage, RegistrationStage::Consume)
                && driver.budget_counted
                && !driver.state_consumed
        }
        RegistrationEffect::VerifyRegistration => {
            matches!(driver.stage, RegistrationStage::Verify)
                && driver.state_consumed
                && !driver.credential_valid
                && !driver.permit_issued
        }
        RegistrationEffect::CheckCredentialUniqueness => {
            matches!(driver.stage, RegistrationStage::Uniqueness)
                && driver.credential_valid
                && !driver.credential_unique
                && !driver.permit_issued
        }
        RegistrationEffect::PersistCredential => {
            matches!(driver.stage, RegistrationStage::Persist)
                && driver.budget_counted
                && driver.state_consumed
                && driver.credential_valid
                && driver.credential_unique
                && driver.permit_issued
                && !driver.credential_stored
        }
        RegistrationEffect::Complete => {
            matches!(driver.stage, RegistrationStage::Done) && driver.credential_stored
        }
        RegistrationEffect::Fail(_) => {
            matches!(driver.stage, RegistrationStage::Done) && !driver.credential_stored
        }
        RegistrationEffect::Idle => true,
    }
}

fn registration_transition(
    driver: RegistrationDriver,
    effect: RegistrationEffect,
) -> RegistrationTransition {
    RegistrationTransition { driver, effect }
}

fn registration_idle(driver: RegistrationDriver) -> RegistrationTransition {
    registration_transition(driver, RegistrationEffect::Idle)
}

fn registration_terminal(
    driver: RegistrationDriver,
    failure: RegistrationFailure,
) -> RegistrationTransition {
    registration_transition(
        RegistrationDriver {
            stage: RegistrationStage::Done,
            ..driver
        },
        RegistrationEffect::Fail(failure),
    )
}

/// Start a per-request registration finish. The handler must count the attempt
/// before touching the single-use registration state.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_state_is_sound(result.driver)
        && registration_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, RegistrationStage::Attempt)
        && !result.driver.budget_counted
        && !result.driver.state_consumed
        && !result.driver.credential_stored
        && matches!(result.effect, RegistrationEffect::CountAttempt)
}))]
pub fn begin_registration() -> RegistrationTransition {
    registration_transition(
        RegistrationDriver {
            stage: RegistrationStage::Attempt,
            budget_counted: false,
            state_consumed: false,
            credential_valid: false,
            credential_unique: false,
            permit_issued: false,
            credential_stored: false,
        },
        RegistrationEffect::CountAttempt,
    )
}

fn apply_registration_attempt_counted(
    driver: RegistrationDriver,
    observation: AttemptBudgetObservation,
) -> RegistrationTransition {
    match observation {
        AttemptBudgetObservation::Admitted => registration_transition(
            RegistrationDriver {
                stage: RegistrationStage::Consume,
                budget_counted: true,
                ..driver
            },
            RegistrationEffect::ConsumeState,
        ),
        AttemptBudgetObservation::Limited => {
            registration_terminal(driver, RegistrationFailure::AttemptLimited)
        }
    }
}

fn apply_registration_state_consumed(
    driver: RegistrationDriver,
    observation: RegistrationStateObservation,
) -> RegistrationTransition {
    match observation {
        RegistrationStateObservation::Missing => {
            registration_terminal(driver, RegistrationFailure::StateUnavailable)
        }
        RegistrationStateObservation::Corrupt => {
            registration_terminal(driver, RegistrationFailure::StateCorrupt)
        }
        RegistrationStateObservation::Present => registration_transition(
            RegistrationDriver {
                stage: RegistrationStage::Verify,
                state_consumed: true,
                ..driver
            },
            RegistrationEffect::VerifyRegistration,
        ),
    }
}

fn apply_registration_verified(
    driver: RegistrationDriver,
    observation: RegistrationVerificationObservation,
) -> RegistrationTransition {
    if !observation.credential_valid {
        return registration_terminal(driver, RegistrationFailure::VerificationFailed);
    }
    registration_transition(
        RegistrationDriver {
            stage: RegistrationStage::Uniqueness,
            credential_valid: true,
            ..driver
        },
        RegistrationEffect::CheckCredentialUniqueness,
    )
}

fn apply_credential_looked_up(
    driver: RegistrationDriver,
    observation: CredentialUniquenessObservation,
) -> RegistrationTransition {
    match observation {
        CredentialUniquenessObservation::LookupFailed => {
            registration_terminal(driver, RegistrationFailure::UniquenessStorage)
        }
        CredentialUniquenessObservation::RegisteredElsewhere => {
            registration_terminal(driver, RegistrationFailure::UniquenessConflict)
        }
        CredentialUniquenessObservation::Unique => {
            // The checked policy is the authority. Every fact is a prior driver
            // decision: device scope and account identity come from the
            // authenticated session this handler is mounted behind, and the
            // one-shot challenge is the state this request actually consumed.
            match plan_registration(RegistrationFacts {
                device_scope: true,
                account_matches: true,
                challenge_pending: driver.state_consumed,
                challenge_consumed: driver.state_consumed,
                credential_valid: driver.credential_valid,
                credential_unique: true,
            }) {
                RegistrationDecision::Register(_permit) => registration_transition(
                    RegistrationDriver {
                        stage: RegistrationStage::Persist,
                        credential_unique: true,
                        permit_issued: true,
                        ..driver
                    },
                    RegistrationEffect::PersistCredential,
                ),
                RegistrationDecision::Reject => {
                    registration_terminal(driver, RegistrationFailure::PolicyRejected)
                }
            }
        }
    }
}

fn apply_credential_persisted(
    driver: RegistrationDriver,
    observation: CredentialPersistObservation,
) -> RegistrationTransition {
    match observation {
        CredentialPersistObservation::Persisted => registration_transition(
            RegistrationDriver {
                stage: RegistrationStage::Done,
                credential_stored: true,
                ..driver
            },
            RegistrationEffect::Complete,
        ),
        CredentialPersistObservation::AccountGone => {
            registration_terminal(driver, RegistrationFailure::AccountGone)
        }
        CredentialPersistObservation::EncodingFailed => {
            registration_terminal(driver, RegistrationFailure::PersistEncoding)
        }
        CredentialPersistObservation::StorageFailed => {
            registration_terminal(driver, RegistrationFailure::PersistStorage)
        }
    }
}

/// The complete, total registration-finish transition relation. Events that do
/// not match the current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver) || registration_state_is_sound(result.driver))
}))]
pub fn step_registration(
    driver: RegistrationDriver,
    event: RegistrationEvent,
) -> RegistrationTransition {
    match event {
        RegistrationEvent::AttemptCounted(observation) => {
            if matches!(driver.stage, RegistrationStage::Attempt) {
                apply_registration_attempt_counted(driver, observation)
            } else {
                registration_idle(driver)
            }
        }
        RegistrationEvent::StateConsumed(observation) => {
            if matches!(driver.stage, RegistrationStage::Consume) {
                apply_registration_state_consumed(driver, observation)
            } else {
                registration_idle(driver)
            }
        }
        RegistrationEvent::RegistrationVerified(observation) => {
            if matches!(driver.stage, RegistrationStage::Verify) {
                apply_registration_verified(driver, observation)
            } else {
                registration_idle(driver)
            }
        }
        RegistrationEvent::CredentialLookedUp(observation) => {
            if matches!(driver.stage, RegistrationStage::Uniqueness) {
                apply_credential_looked_up(driver, observation)
            } else {
                registration_idle(driver)
            }
        }
        RegistrationEvent::CredentialPersisted(observation) => {
            if matches!(driver.stage, RegistrationStage::Persist) {
                apply_credential_persisted(driver, observation)
            } else {
                registration_idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver) || registration_state_is_sound(result.driver))
}))]
pub fn on_registration_attempt_counted(
    driver: RegistrationDriver,
    observation: AttemptBudgetObservation,
) -> RegistrationTransition {
    step_registration(driver, RegistrationEvent::AttemptCounted(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver) || registration_state_is_sound(result.driver))
}))]
pub fn on_registration_state_consumed(
    driver: RegistrationDriver,
    observation: RegistrationStateObservation,
) -> RegistrationTransition {
    step_registration(driver, RegistrationEvent::StateConsumed(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver) || registration_state_is_sound(result.driver))
}))]
pub fn on_registration_verified(
    driver: RegistrationDriver,
    observation: RegistrationVerificationObservation,
) -> RegistrationTransition {
    step_registration(driver, RegistrationEvent::RegistrationVerified(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver) || registration_state_is_sound(result.driver))
}))]
pub fn on_credential_looked_up(
    driver: RegistrationDriver,
    observation: CredentialUniquenessObservation,
) -> RegistrationTransition {
    step_registration(driver, RegistrationEvent::CredentialLookedUp(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver) || registration_state_is_sound(result.driver))
}))]
pub fn on_credential_persisted(
    driver: RegistrationDriver,
    observation: CredentialPersistObservation,
) -> RegistrationTransition {
    step_registration(driver, RegistrationEvent::CredentialPersisted(observation))
}

// ── Authentication start (challenge initiation) ─────────────────────────────

/// Where the authentication-challenge initiation is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthStartStage {
    /// The handler may query availability, decode the credential and probe the
    /// attempt slot.
    Observe,
    /// The observation authorized a challenge; the handler may start the
    /// authentication ceremony.
    Ceremony,
    /// The ceremony produced a challenge; the handler may atomically store the
    /// attempt state with `set_ex_nx`.
    Store,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Raw observations from the availability query, the credential decode and the
/// fresh-slot probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthStartObservation {
    pub account_present: bool,
    pub share_present: bool,
    pub credential: StoredCredentialObservation,
    /// The generated attempt id did not already occupy the store slot.
    pub attempt_id_fresh: bool,
    pub ttl_secs: u64,
}

/// One authentication-start driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthStartEvent {
    Observed(AuthStartObservation),
    CeremonyStarted(CeremonyStartObservation),
    Stored(ChallengeStoreObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthStartFailure {
    /// No `users` row for the requested account.
    AccountUnavailable,
    /// The `recovery_share` column is NULL or absent.
    ShareMissing,
    /// No recovery credential is registered.
    CredentialMissing,
    /// The stored credential JSON did not decode.
    CredentialCorrupt,
    /// The generated attempt id is already occupied (probe or lost race).
    AttemptCollision,
    /// `start_passkey_authentication` rejected the request.
    CeremonyFailed,
    /// The checked policy rejected an observation that looked available.
    PolicyRejected,
    /// The attempt-state write failed for a storage reason.
    StateStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthStartEffect {
    /// Query availability and the credential, and probe the attempt slot.
    Observe,
    /// Start the authentication ceremony for the observed credential.
    StartCeremony,
    /// Draw and atomically store the attempt state with `set_ex_nx`.
    StoreChallenge,
    /// Terminal success: the challenge was stored.
    Complete,
    /// Terminal failure without storing anything.
    Fail(AuthStartFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request authentication-start state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthStartDriver {
    pub stage: AuthStartStage,
    /// The observation authorized storing a challenge.
    pub authorized: bool,
    /// The attempt-state write reported success.
    pub stored: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthStartTransition {
    pub driver: AuthStartDriver,
    pub effect: AuthStartEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn auth_start_state_is_sound(driver: AuthStartDriver) -> bool {
    let observe_clean = !driver.authorized && !driver.stored;
    let authorized_clean = driver.authorized && !driver.stored;
    (!matches!(driver.stage, AuthStartStage::Observe) || observe_clean)
        && (!matches!(driver.stage, AuthStartStage::Ceremony) || authorized_clean)
        && (!matches!(driver.stage, AuthStartStage::Store) || authorized_clean)
        && (!driver.stored || driver.authorized)
        && (!driver.stored || matches!(driver.stage, AuthStartStage::Done))
}

/// Every authentication-start effect agrees with the state it produces.
pub fn auth_start_effect_is_sound(driver: AuthStartDriver, effect: AuthStartEffect) -> bool {
    match effect {
        AuthStartEffect::Observe => {
            matches!(driver.stage, AuthStartStage::Observe)
                && !driver.authorized
                && !driver.stored
        }
        AuthStartEffect::StartCeremony => {
            matches!(driver.stage, AuthStartStage::Ceremony)
                && driver.authorized
                && !driver.stored
        }
        AuthStartEffect::StoreChallenge => {
            matches!(driver.stage, AuthStartStage::Store)
                && driver.authorized
                && !driver.stored
        }
        AuthStartEffect::Complete => {
            matches!(driver.stage, AuthStartStage::Done) && driver.stored
        }
        AuthStartEffect::Fail(_) => {
            matches!(driver.stage, AuthStartStage::Done) && !driver.stored
        }
        AuthStartEffect::Idle => true,
    }
}

fn auth_start_transition(
    driver: AuthStartDriver,
    effect: AuthStartEffect,
) -> AuthStartTransition {
    AuthStartTransition { driver, effect }
}

fn auth_start_idle(driver: AuthStartDriver) -> AuthStartTransition {
    auth_start_transition(driver, AuthStartEffect::Idle)
}

fn auth_start_terminal(
    driver: AuthStartDriver,
    failure: AuthStartFailure,
) -> AuthStartTransition {
    auth_start_transition(
        AuthStartDriver {
            stage: AuthStartStage::Done,
            ..driver
        },
        AuthStartEffect::Fail(failure),
    )
}

/// The first rejection in the handler's historical status/message precedence,
/// or `None` when every preceding guard admitted the observation. The checked
/// policy is the authority; this helper only names the observed guard that
/// failed so the handler can render the original status and message.
fn auth_start_rejection(observation: AuthStartObservation) -> Option<AuthStartFailure> {
    if !observation.account_present {
        Some(AuthStartFailure::AccountUnavailable)
    } else if !observation.share_present {
        Some(AuthStartFailure::ShareMissing)
    } else {
        match observation.credential {
            StoredCredentialObservation::Corrupt => Some(AuthStartFailure::CredentialCorrupt),
            StoredCredentialObservation::Missing => Some(AuthStartFailure::CredentialMissing),
            StoredCredentialObservation::Present => {
                if !observation.attempt_id_fresh {
                    Some(AuthStartFailure::AttemptCollision)
                } else {
                    None
                }
            }
        }
    }
}

/// Start a per-request authentication challenge. The handler may perform the
/// availability/credential/slot observation next.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_start_state_is_sound(result.driver)
        && auth_start_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, AuthStartStage::Observe)
        && !result.driver.authorized
        && !result.driver.stored
        && matches!(result.effect, AuthStartEffect::Observe)
}))]
pub fn begin_auth_start() -> AuthStartTransition {
    auth_start_transition(
        AuthStartDriver {
            stage: AuthStartStage::Observe,
            authorized: false,
            stored: false,
        },
        AuthStartEffect::Observe,
    )
}

fn apply_auth_start_observed(
    driver: AuthStartDriver,
    observation: AuthStartObservation,
) -> AuthStartTransition {
    let credential_present =
        matches!(observation.credential, StoredCredentialObservation::Present);
    // The credential is decoded before the policy runs; a corrupt cell is not
    // "absent", it is the handler's historical internal error.
    let facts = initiate_facts(InitiateObservation {
        account_present: observation.account_present,
        share_present: observation.share_present,
        credential_present,
        attempt_id_fresh: observation.attempt_id_fresh,
        ttl_secs: observation.ttl_secs,
    });
    match plan_initiation(facts) {
        InitiateDecision::Start(_permit) => auth_start_transition(
            AuthStartDriver {
                stage: AuthStartStage::Ceremony,
                authorized: true,
                ..driver
            },
            AuthStartEffect::StartCeremony,
        ),
        InitiateDecision::Reject => {
            // The policy is the authority. The raw observation only names the
            // historical guard/message; a policy rejection with no named guard
            // is the fail-closed internal classification.
            let failure =
                auth_start_rejection(observation).unwrap_or(AuthStartFailure::PolicyRejected);
            auth_start_terminal(driver, failure)
        }
    }
}

fn apply_auth_ceremony_started(
    driver: AuthStartDriver,
    observation: CeremonyStartObservation,
) -> AuthStartTransition {
    match observation {
        CeremonyStartObservation::Started => auth_start_transition(
            AuthStartDriver {
                stage: AuthStartStage::Store,
                ..driver
            },
            AuthStartEffect::StoreChallenge,
        ),
        CeremonyStartObservation::Failed => {
            auth_start_terminal(driver, AuthStartFailure::CeremonyFailed)
        }
    }
}

fn apply_auth_start_stored(
    driver: AuthStartDriver,
    observation: ChallengeStoreObservation,
) -> AuthStartTransition {
    match observation {
        ChallengeStoreObservation::Stored => auth_start_transition(
            AuthStartDriver {
                stage: AuthStartStage::Done,
                stored: true,
                ..driver
            },
            AuthStartEffect::Complete,
        ),
        // An observed-free slot is not authorization to overwrite another
        // writer's challenge; a lost race is the historical conflict.
        ChallengeStoreObservation::Lost => {
            auth_start_terminal(driver, AuthStartFailure::AttemptCollision)
        }
        ChallengeStoreObservation::StorageFailed => {
            auth_start_terminal(driver, AuthStartFailure::StateStorage)
        }
    }
}

/// The complete, total authentication-start transition relation. Events that
/// do not match the current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(auth_start_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_start_effect_is_sound(result.driver, result.effect)
        && (!auth_start_state_is_sound(driver) || auth_start_state_is_sound(result.driver))
}))]
pub fn step_auth_start(
    driver: AuthStartDriver,
    event: AuthStartEvent,
) -> AuthStartTransition {
    match event {
        AuthStartEvent::Observed(observation) => {
            if matches!(driver.stage, AuthStartStage::Observe) {
                apply_auth_start_observed(driver, observation)
            } else {
                auth_start_idle(driver)
            }
        }
        AuthStartEvent::CeremonyStarted(observation) => {
            if matches!(driver.stage, AuthStartStage::Ceremony) {
                apply_auth_ceremony_started(driver, observation)
            } else {
                auth_start_idle(driver)
            }
        }
        AuthStartEvent::Stored(observation) => {
            if matches!(driver.stage, AuthStartStage::Store) {
                apply_auth_start_stored(driver, observation)
            } else {
                auth_start_idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(auth_start_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_start_effect_is_sound(result.driver, result.effect)
        && (!auth_start_state_is_sound(driver) || auth_start_state_is_sound(result.driver))
}))]
pub fn on_auth_start_observed(
    driver: AuthStartDriver,
    observation: AuthStartObservation,
) -> AuthStartTransition {
    step_auth_start(driver, AuthStartEvent::Observed(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_start_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_start_effect_is_sound(result.driver, result.effect)
        && (!auth_start_state_is_sound(driver) || auth_start_state_is_sound(result.driver))
}))]
pub fn on_auth_ceremony_started(
    driver: AuthStartDriver,
    observation: CeremonyStartObservation,
) -> AuthStartTransition {
    step_auth_start(driver, AuthStartEvent::CeremonyStarted(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_start_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_start_effect_is_sound(result.driver, result.effect)
        && (!auth_start_state_is_sound(driver) || auth_start_state_is_sound(result.driver))
}))]
pub fn on_auth_start_stored(
    driver: AuthStartDriver,
    observation: ChallengeStoreObservation,
) -> AuthStartTransition {
    step_auth_start(driver, AuthStartEvent::Stored(observation))
}

// ── Authentication finish (share release and enrollment grant) ──────────────

/// Where the authentication finish is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthFinishStage {
    /// The handler must count the attempt against the rate-limit budget.
    Attempt,
    /// The attempt was admitted; the handler may observe share/credential
    /// availability before spending the challenge.
    Context,
    /// The account is recovery-ready; the handler may perform the atomic
    /// single-use `get_del` of the attempt-bound challenge.
    Consume,
    /// A matching challenge was consumed; the handler may verify the assertion.
    Verify,
    /// The authenticator signalled updated metadata; the handler may persist it.
    Update,
    /// The assertion was accepted; the handler may query the live row.
    Account,
    /// The live row authorized release; the handler may read the share.
    Release,
    /// The share decoded; the handler may store the single-use grant.
    Store,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Pre-consumption availability observations. The credential is decoded here so
/// the challenge's credential binding can be compared with the live column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthFinishContextObservation {
    pub account_present: bool,
    pub share_present: bool,
    pub credential: StoredCredentialObservation,
    /// The request carried an attempt id.
    pub attempt_id_present: bool,
}

/// Outcome of the atomic single-use attempt consumption. `Present` carries the
/// request/attempt binding comparison and the comparison between the
/// challenge-bound credential id and the live column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAttemptConsumptionObservation {
    /// `get_del` returned no live attempt state.
    Missing,
    /// The state was removed but its envelope did not decode.
    Corrupt,
    /// The state was removed and decoded.
    Present {
        user_matches: bool,
        attempt_matches: bool,
        credential_matches: bool,
    },
}

/// Authenticated outcome of `finish_passkey_authentication`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssertionObservation {
    pub assertion_valid: bool,
    pub user_verified: bool,
    /// The assertion's credential id equals the challenge-bound credential id.
    pub credential_matches: bool,
    /// The authenticator signalled updated credential metadata.
    pub needs_update: bool,
}

/// Outcome of the conditional credential update. `Changed` covers both a
/// `Passkey::update_credential` that produced no change and a guarded SQL
/// update that matched no row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialUpdateStoreObservation {
    Updated,
    Changed,
}

/// Live `users` row observation after the assertion was accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthAccountObservation {
    pub account_present: bool,
    /// `users.rekey_state` is clear (no freezing/rotation in progress).
    pub account_epoch_active: bool,
    /// The row's `recovery_share` column is non-null.
    pub share_present: bool,
    /// The row's stored credential id equals the challenge-bound credential id.
    pub stored_credential_matches: bool,
    /// `users.key_epoch` as stored; `None` means the column is absent.
    pub stored_epoch: Option<i64>,
}

/// Outcome of decoding the staged share text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareDecodeObservation {
    Decoded,
    Corrupt,
}

/// One authentication-finish driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthFinishEvent {
    AttemptCounted(AttemptBudgetObservation),
    ContextObserved(AuthFinishContextObservation),
    AttemptConsumed(AuthAttemptConsumptionObservation),
    AssertionObserved(AssertionObservation),
    CredentialUpdated(CredentialUpdateStoreObservation),
    AccountObserved(AuthAccountObservation),
    ShareObserved(ShareDecodeObservation),
    GrantStored(GrantStoreObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthFinishFailure {
    /// The rate-limit budget refused the attempt.
    AttemptLimited,
    /// No `users` row for the requested account.
    AccountUnavailable,
    /// The `recovery_share` column is NULL or absent.
    ShareMissing,
    /// No recovery credential is registered.
    CredentialMissing,
    /// The stored credential JSON did not decode.
    CredentialCorrupt,
    /// The request did not carry the attempt id.
    AttemptIdMissing,
    /// No live attempt state matched.
    AttemptMissing,
    /// The removed attempt state did not decode.
    AttemptCorrupt,
    /// The decoded state is bound to another user or attempt id.
    BindingMismatch,
    /// The challenge was issued for a credential that is no longer current.
    ChallengeCredentialReplaced,
    /// WebAuthn verification returned no authentication result.
    AssertionInvalid,
    /// The authenticator did not perform user verification.
    UserVerificationRequired,
    /// The assertion used a different recovery credential.
    AssertionCredentialMismatch,
    /// The credential changed while the metadata update was being persisted.
    CredentialUpdateMismatch,
    /// The live account row disappeared after the assertion.
    AccountAbsent,
    /// `users.rekey_state` is set: freezing/rotation pauses recovery.
    RotationPaused,
    /// The live row no longer holds the challenge-bound credential.
    StoredCredentialMismatch,
    /// The checked recovery policy rejected the live observation.
    PolicyRejected,
    /// The staged share text did not decode.
    ShareCorrupt,
    /// Writing the single-use grant failed.
    GrantStorage,
}

/// The grant authority emitted by the driver. It carries only the epoch the
/// released share and the stored grant are bound to; no share bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthFinishGrantPermit {
    pub epoch: i64,
}

/// The effect the handler must perform next. `ReleaseGrant` is the single
/// indivisible authorization to read the observed share and store one
/// single-use enrollment grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthFinishEffect {
    /// Count one attempt against the rate-limit budget.
    CountAttempt,
    /// Observe share/credential availability and the request attempt id.
    ObserveContext,
    /// Perform the atomic single-use `get_del` of the attempt-bound challenge.
    ConsumeAttempt,
    /// Verify the presented assertion against the consumed challenge.
    VerifyAssertion,
    /// Persist the authenticator's updated credential metadata.
    UpdateCredential,
    /// Query the live `users` row.
    QueryAccount,
    /// Release the observed share and store exactly one single-use grant at
    /// this epoch.
    ReleaseGrant(AuthFinishGrantPermit),
    /// Store exactly one single-use grant after the share decoded.
    StoreGrant,
    /// Terminal success: the grant was stored and the share may be returned.
    Complete,
    /// Terminal failure without returning a share or storing a grant.
    Fail(AuthFinishFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request authentication-finish state. Every field is a decision fact
/// established by a prior transition, never a claim about the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthFinishDriver {
    pub stage: AuthFinishStage,
    /// An attempt was counted against the budget.
    pub budget_counted: bool,
    /// The account was observed recovery-ready before the challenge was spent.
    pub context_observed: bool,
    /// The single-use attempt state was removed by this request.
    pub attempt_consumed: bool,
    /// The decoded attempt's user id matched the request.
    pub user_matches: bool,
    /// The decoded attempt's id matched the request.
    pub attempt_matches: bool,
    /// The challenge-bound credential id is still the live credential.
    pub challenge_credential_matches: bool,
    /// The assertion verified.
    pub assertion_valid: bool,
    /// The authenticator reported user verification.
    pub user_verified: bool,
    /// The assertion used the challenge-bound credential.
    pub assertion_credential_matches: bool,
    /// The authenticator signalled updated metadata.
    pub credential_update_needed: bool,
    /// The conditional metadata update reported success.
    pub credential_updated: bool,
    /// The live `users` row exists.
    pub account_present: bool,
    /// `users.rekey_state` is clear.
    pub account_epoch_active: bool,
    /// A staged share exists.
    pub share_present: bool,
    /// The live row still holds the challenge-bound credential.
    pub stored_credential_matches: bool,
    /// `users.key_epoch` as stored.
    pub stored_epoch: Option<i64>,
    /// The driver issued the release/grant authority.
    pub grant_issued: bool,
    /// The staged share text decoded.
    pub share_decoded: bool,
    /// The grant store reported success.
    pub grant_stored: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthFinishTransition {
    pub driver: AuthFinishDriver,
    pub effect: AuthFinishEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn auth_finish_state_is_sound(driver: AuthFinishDriver) -> bool {
    let attempt_clean = !driver.budget_counted
        && !driver.context_observed
        && !driver.attempt_consumed
        && !driver.user_matches
        && !driver.attempt_matches
        && !driver.challenge_credential_matches
        && !driver.assertion_valid
        && !driver.user_verified
        && !driver.assertion_credential_matches
        && !driver.credential_update_needed
        && !driver.credential_updated
        && !driver.account_present
        && !driver.account_epoch_active
        && !driver.share_present
        && !driver.stored_credential_matches
        && !driver.grant_issued
        && !driver.share_decoded
        && !driver.grant_stored;
    let context_clean = driver.budget_counted
        && !driver.context_observed
        && !driver.attempt_consumed
        && !driver.user_matches
        && !driver.attempt_matches
        && !driver.challenge_credential_matches
        && !driver.assertion_valid
        && !driver.user_verified
        && !driver.assertion_credential_matches
        && !driver.credential_update_needed
        && !driver.credential_updated
        && !driver.account_present
        && !driver.account_epoch_active
        && !driver.share_present
        && !driver.stored_credential_matches
        && !driver.grant_issued
        && !driver.share_decoded
        && !driver.grant_stored;
    let consume_clean = driver.budget_counted
        && driver.context_observed
        && !driver.attempt_consumed
        && !driver.user_matches
        && !driver.attempt_matches
        && !driver.challenge_credential_matches
        && !driver.assertion_valid
        && !driver.user_verified
        && !driver.assertion_credential_matches
        && !driver.credential_update_needed
        && !driver.credential_updated
        && !driver.account_present
        && !driver.account_epoch_active
        && !driver.share_present
        && !driver.stored_credential_matches
        && !driver.grant_issued
        && !driver.share_decoded
        && !driver.grant_stored;
    let verify_clean = driver.budget_counted
        && driver.context_observed
        && driver.attempt_consumed
        && driver.user_matches
        && driver.attempt_matches
        && driver.challenge_credential_matches
        && !driver.assertion_valid
        && !driver.user_verified
        && !driver.assertion_credential_matches
        && !driver.credential_update_needed
        && !driver.credential_updated
        && !driver.account_present
        && !driver.account_epoch_active
        && !driver.share_present
        && !driver.stored_credential_matches
        && !driver.grant_issued
        && !driver.share_decoded
        && !driver.grant_stored;
    let update_clean = driver.budget_counted
        && driver.context_observed
        && driver.attempt_consumed
        && driver.user_matches
        && driver.attempt_matches
        && driver.challenge_credential_matches
        && driver.assertion_valid
        && driver.user_verified
        && driver.assertion_credential_matches
        && driver.credential_update_needed
        && !driver.credential_updated
        && !driver.account_present
        && !driver.account_epoch_active
        && !driver.share_present
        && !driver.stored_credential_matches
        && !driver.grant_issued
        && !driver.share_decoded
        && !driver.grant_stored;
    let account_clean = driver.budget_counted
        && driver.context_observed
        && driver.attempt_consumed
        && driver.user_matches
        && driver.attempt_matches
        && driver.challenge_credential_matches
        && driver.assertion_valid
        && driver.user_verified
        && driver.assertion_credential_matches
        && (!driver.credential_update_needed || driver.credential_updated)
        && !driver.grant_issued
        && !driver.share_decoded
        && !driver.grant_stored;
    let release_clean = driver.budget_counted
        && driver.context_observed
        && driver.attempt_consumed
        && driver.user_matches
        && driver.attempt_matches
        && driver.challenge_credential_matches
        && driver.assertion_valid
        && driver.user_verified
        && driver.assertion_credential_matches
        && (!driver.credential_update_needed || driver.credential_updated)
        && driver.account_present
        && driver.account_epoch_active
        && driver.share_present
        && driver.stored_credential_matches
        && driver.grant_issued
        && !driver.share_decoded
        && !driver.grant_stored;
    let store_clean = driver.budget_counted
        && driver.context_observed
        && driver.attempt_consumed
        && driver.user_matches
        && driver.attempt_matches
        && driver.challenge_credential_matches
        && driver.assertion_valid
        && driver.user_verified
        && driver.assertion_credential_matches
        && (!driver.credential_update_needed || driver.credential_updated)
        && driver.account_present
        && driver.account_epoch_active
        && driver.share_present
        && driver.stored_credential_matches
        && driver.grant_issued
        && driver.share_decoded
        && !driver.grant_stored;
    (!matches!(driver.stage, AuthFinishStage::Attempt) || attempt_clean)
        && (!matches!(driver.stage, AuthFinishStage::Context) || context_clean)
        && (!matches!(driver.stage, AuthFinishStage::Consume) || consume_clean)
        && (!matches!(driver.stage, AuthFinishStage::Verify) || verify_clean)
        && (!matches!(driver.stage, AuthFinishStage::Update) || update_clean)
        && (!matches!(driver.stage, AuthFinishStage::Account) || account_clean)
        && (!matches!(driver.stage, AuthFinishStage::Release) || release_clean)
        && (!matches!(driver.stage, AuthFinishStage::Store) || store_clean)
        && (!driver.context_observed || driver.budget_counted)
        && (!driver.attempt_consumed || driver.context_observed)
        && (!(driver.user_matches || driver.attempt_matches || driver.challenge_credential_matches)
            || driver.attempt_consumed)
        && (!driver.assertion_valid
            || (driver.attempt_consumed && driver.user_matches && driver.attempt_matches))
        && (!driver.user_verified || driver.assertion_valid)
        && (!driver.assertion_credential_matches || driver.assertion_valid)
        && (!driver.credential_updated || driver.credential_update_needed)
        && (!(driver.account_present
            || driver.account_epoch_active
            || driver.share_present
            || driver.stored_credential_matches)
            || driver.attempt_consumed)
        && (!driver.grant_issued
            || (driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && driver.challenge_credential_matches
                && driver.assertion_valid
                && driver.user_verified
                && driver.assertion_credential_matches
                && (!driver.credential_update_needed || driver.credential_updated)
                && driver.account_present
                && driver.account_epoch_active
                && driver.share_present
                && driver.stored_credential_matches
                && observed_recovery_epoch(driver.stored_epoch) >= crate::INITIAL_EPOCH
                && (matches!(driver.stage, AuthFinishStage::Release)
                    || matches!(driver.stage, AuthFinishStage::Store)
                    || matches!(driver.stage, AuthFinishStage::Done))))
        && (!driver.share_decoded || driver.grant_issued)
        && (!driver.grant_stored
            || (driver.share_decoded && matches!(driver.stage, AuthFinishStage::Done)))
}

/// Every effect the driver emits agrees with the state it produces. In
/// particular `ReleaseGrant` leaves the driver authorized at the live epoch
/// with every release fact recorded, and `Complete` is the only success.
pub fn auth_finish_effect_is_sound(
    driver: AuthFinishDriver,
    effect: AuthFinishEffect,
) -> bool {
    match effect {
        AuthFinishEffect::CountAttempt => {
            matches!(driver.stage, AuthFinishStage::Attempt)
                && !driver.budget_counted
                && !driver.context_observed
                && !driver.attempt_consumed
                && !driver.grant_issued
        }
        AuthFinishEffect::ObserveContext => {
            matches!(driver.stage, AuthFinishStage::Context)
                && driver.budget_counted
                && !driver.context_observed
                && !driver.attempt_consumed
        }
        AuthFinishEffect::ConsumeAttempt => {
            matches!(driver.stage, AuthFinishStage::Consume)
                && driver.context_observed
                && !driver.attempt_consumed
        }
        AuthFinishEffect::VerifyAssertion => {
            matches!(driver.stage, AuthFinishStage::Verify)
                && driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && driver.challenge_credential_matches
                && !driver.assertion_valid
                && !driver.grant_issued
        }
        AuthFinishEffect::UpdateCredential => {
            matches!(driver.stage, AuthFinishStage::Update)
                && driver.assertion_valid
                && driver.user_verified
                && driver.assertion_credential_matches
                && driver.credential_update_needed
                && !driver.credential_updated
        }
        AuthFinishEffect::QueryAccount => {
            matches!(driver.stage, AuthFinishStage::Account)
                && driver.budget_counted
                && driver.context_observed
                && driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && driver.challenge_credential_matches
                && driver.assertion_valid
                && driver.user_verified
                && driver.assertion_credential_matches
                && (!driver.credential_update_needed || driver.credential_updated)
                && !driver.grant_issued
        }
        AuthFinishEffect::ReleaseGrant(permit) => {
            matches!(driver.stage, AuthFinishStage::Release)
                && driver.budget_counted
                && driver.context_observed
                && driver.attempt_consumed
                && driver.user_matches
                && driver.attempt_matches
                && driver.challenge_credential_matches
                && driver.assertion_valid
                && driver.user_verified
                && driver.assertion_credential_matches
                && (!driver.credential_update_needed || driver.credential_updated)
                && driver.account_present
                && driver.account_epoch_active
                && driver.share_present
                && driver.stored_credential_matches
                && driver.grant_issued
                && !driver.share_decoded
                && permit.epoch == observed_recovery_epoch(driver.stored_epoch)
                && permit.epoch >= crate::INITIAL_EPOCH
        }
        AuthFinishEffect::StoreGrant => {
            matches!(driver.stage, AuthFinishStage::Store)
                && driver.grant_issued
                && driver.share_decoded
                && !driver.grant_stored
        }
        AuthFinishEffect::Complete => {
            matches!(driver.stage, AuthFinishStage::Done) && driver.grant_stored
        }
        AuthFinishEffect::Fail(_) => {
            matches!(driver.stage, AuthFinishStage::Done) && !driver.grant_stored
        }
        AuthFinishEffect::Idle => true,
    }
}

/// `ReleaseGrant` is the only effect that releases the recovered server share.
/// The WebAuthn path genuinely releases Share 2 (unlike the possession path);
/// this predicate is what lets the proofs state that no other driver decision
/// can do so, including a registration, initiation or metadata-update effect on
/// the same recovered account.
pub fn auth_finish_effect_releases_share(effect: AuthFinishEffect) -> bool {
    matches!(effect, AuthFinishEffect::ReleaseGrant(_))
}

fn auth_finish_transition(
    driver: AuthFinishDriver,
    effect: AuthFinishEffect,
) -> AuthFinishTransition {
    AuthFinishTransition { driver, effect }
}

fn auth_finish_idle(driver: AuthFinishDriver) -> AuthFinishTransition {
    auth_finish_transition(driver, AuthFinishEffect::Idle)
}

fn auth_finish_terminal(
    driver: AuthFinishDriver,
    failure: AuthFinishFailure,
) -> AuthFinishTransition {
    auth_finish_transition(
        AuthFinishDriver {
            stage: AuthFinishStage::Done,
            ..driver
        },
        AuthFinishEffect::Fail(failure),
    )
}

/// The first rejection in the handler's historical status/message precedence,
/// or `None` when every preceding guard admitted the observation.
fn auth_finish_context_rejection(
    observation: AuthFinishContextObservation,
) -> Option<AuthFinishFailure> {
    if !observation.account_present {
        Some(AuthFinishFailure::AccountUnavailable)
    } else if !observation.share_present {
        Some(AuthFinishFailure::ShareMissing)
    } else {
        match observation.credential {
            StoredCredentialObservation::Corrupt => Some(AuthFinishFailure::CredentialCorrupt),
            StoredCredentialObservation::Missing => Some(AuthFinishFailure::CredentialMissing),
            StoredCredentialObservation::Present => {
                if !observation.attempt_id_present {
                    Some(AuthFinishFailure::AttemptIdMissing)
                } else {
                    None
                }
            }
        }
    }
}

/// Start a per-request WebAuthn recovery. The handler must count the attempt
/// before observing the account and before spending the challenge.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_state_is_sound(result.driver)
        && auth_finish_effect_is_sound(result.driver, result.effect)
        && !auth_finish_effect_releases_share(result.effect)
        && matches!(result.driver.stage, AuthFinishStage::Attempt)
        && !result.driver.budget_counted
        && !result.driver.attempt_consumed
        && !result.driver.grant_issued
        && !result.driver.grant_stored
        && matches!(result.effect, AuthFinishEffect::CountAttempt)
}))]
pub fn begin_auth_finish() -> AuthFinishTransition {
    auth_finish_transition(
        AuthFinishDriver {
            stage: AuthFinishStage::Attempt,
            budget_counted: false,
            context_observed: false,
            attempt_consumed: false,
            user_matches: false,
            attempt_matches: false,
            challenge_credential_matches: false,
            assertion_valid: false,
            user_verified: false,
            assertion_credential_matches: false,
            credential_update_needed: false,
            credential_updated: false,
            account_present: false,
            account_epoch_active: false,
            share_present: false,
            stored_credential_matches: false,
            stored_epoch: None,
            grant_issued: false,
            share_decoded: false,
            grant_stored: false,
        },
        AuthFinishEffect::CountAttempt,
    )
}

fn apply_auth_finish_attempt_counted(
    driver: AuthFinishDriver,
    observation: AttemptBudgetObservation,
) -> AuthFinishTransition {
    match observation {
        AttemptBudgetObservation::Admitted => auth_finish_transition(
            AuthFinishDriver {
                stage: AuthFinishStage::Context,
                budget_counted: true,
                ..driver
            },
            AuthFinishEffect::ObserveContext,
        ),
        AttemptBudgetObservation::Limited => {
            auth_finish_terminal(driver, AuthFinishFailure::AttemptLimited)
        }
    }
}

fn apply_auth_finish_context_observed(
    driver: AuthFinishDriver,
    observation: AuthFinishContextObservation,
) -> AuthFinishTransition {
    if !observation.account_present
        || !observation.share_present
        || !matches!(
            observation.credential,
            StoredCredentialObservation::Present
        )
        || !observation.attempt_id_present
    {
        let failure =
            auth_finish_context_rejection(observation).unwrap_or(AuthFinishFailure::PolicyRejected);
        return auth_finish_terminal(driver, failure);
    }
    auth_finish_transition(
        AuthFinishDriver {
            stage: AuthFinishStage::Consume,
            context_observed: true,
            ..driver
        },
        AuthFinishEffect::ConsumeAttempt,
    )
}

fn apply_auth_attempt_consumed(
    driver: AuthFinishDriver,
    observation: AuthAttemptConsumptionObservation,
) -> AuthFinishTransition {
    match observation {
        AuthAttemptConsumptionObservation::Missing => {
            auth_finish_terminal(driver, AuthFinishFailure::AttemptMissing)
        }
        AuthAttemptConsumptionObservation::Corrupt => {
            // The state was removed even though it did not decode.
            auth_finish_terminal(
                AuthFinishDriver {
                    attempt_consumed: true,
                    ..driver
                },
                AuthFinishFailure::AttemptCorrupt,
            )
        }
        AuthAttemptConsumptionObservation::Present {
            user_matches,
            attempt_matches,
            credential_matches,
        } => {
            let consumed = AuthFinishDriver {
                attempt_consumed: true,
                user_matches,
                attempt_matches,
                challenge_credential_matches: credential_matches,
                ..driver
            };
            if user_matches && attempt_matches {
                if credential_matches {
                    auth_finish_transition(
                        AuthFinishDriver {
                            stage: AuthFinishStage::Verify,
                            ..consumed
                        },
                        AuthFinishEffect::VerifyAssertion,
                    )
                } else {
                    // The challenge was issued for a credential that has since
                    // been replaced. Consumed, terminal, no verification.
                    auth_finish_terminal(consumed, AuthFinishFailure::ChallengeCredentialReplaced)
                }
            } else {
                // The binding mismatch consumed the challenge anyway.
                auth_finish_terminal(consumed, AuthFinishFailure::BindingMismatch)
            }
        }
    }
}

fn apply_auth_assertion_observed(
    driver: AuthFinishDriver,
    observation: AssertionObservation,
) -> AuthFinishTransition {
    if !observation.assertion_valid {
        return auth_finish_terminal(driver, AuthFinishFailure::AssertionInvalid);
    }
    let verified = AuthFinishDriver {
        assertion_valid: true,
        user_verified: observation.user_verified,
        ..driver
    };
    if !observation.user_verified {
        return auth_finish_terminal(verified, AuthFinishFailure::UserVerificationRequired);
    }
    // The checked metadata-update policy is the authority. The raw observation
    // only names the historical guard/message on rejection.
    let update_facts = credential_update_facts(CredentialUpdateObservation {
        assertion_valid: true,
        credential_matches_current: observation.credential_matches,
        needs_update: observation.needs_update,
    });
    match plan_credential_update(update_facts) {
        CredentialUpdateDecision::Reject => auth_finish_terminal(
            AuthFinishDriver {
                assertion_credential_matches: false,
                credential_update_needed: observation.needs_update,
                ..verified
            },
            AuthFinishFailure::AssertionCredentialMismatch,
        ),
        CredentialUpdateDecision::Update => auth_finish_transition(
            AuthFinishDriver {
                stage: AuthFinishStage::Update,
                assertion_credential_matches: true,
                credential_update_needed: true,
                ..verified
            },
            AuthFinishEffect::UpdateCredential,
        ),
        CredentialUpdateDecision::Keep => auth_finish_transition(
            AuthFinishDriver {
                stage: AuthFinishStage::Account,
                assertion_credential_matches: true,
                credential_update_needed: false,
                ..verified
            },
            AuthFinishEffect::QueryAccount,
        ),
    }
}

fn apply_auth_credential_updated(
    driver: AuthFinishDriver,
    observation: CredentialUpdateStoreObservation,
) -> AuthFinishTransition {
    match observation {
        CredentialUpdateStoreObservation::Updated => auth_finish_transition(
            AuthFinishDriver {
                stage: AuthFinishStage::Account,
                credential_updated: true,
                ..driver
            },
            AuthFinishEffect::QueryAccount,
        ),
        CredentialUpdateStoreObservation::Changed => {
            auth_finish_terminal(driver, AuthFinishFailure::CredentialUpdateMismatch)
        }
    }
}

fn apply_auth_account_observed(
    driver: AuthFinishDriver,
    observation: AuthAccountObservation,
) -> AuthFinishTransition {
    // The row's absence is the handler's first rejection class and is checked
    // before the policy sees the (necessarily inconsistent) share/epoch facts.
    if !observation.account_present {
        return auth_finish_terminal(driver, AuthFinishFailure::AccountAbsent);
    }
    let credential_matches_current = driver.challenge_credential_matches
        && driver.assertion_credential_matches
        && observation.stored_credential_matches;
    let facts = recover_facts(RecoverObservation {
        attempt_source: RecoveryAttemptSource::Consumed,
        user_matches: driver.user_matches,
        attempt_matches: driver.attempt_matches,
        credential_matches_current,
        assertion_valid: driver.assertion_valid,
        user_verified: driver.user_verified,
        share_present: observation.share_present,
        account_epoch_active: observation.account_epoch_active,
        stored_epoch: observation.stored_epoch,
    });
    match plan_recovery(facts) {
        RecoverDecision::Release(permit) => {
            debug_assert!(permit.issues_single_use_grant());
            auth_finish_transition(
                AuthFinishDriver {
                    stage: AuthFinishStage::Release,
                    account_present: true,
                    account_epoch_active: true,
                    share_present: true,
                    stored_credential_matches: true,
                    stored_epoch: observation.stored_epoch,
                    grant_issued: true,
                    ..driver
                },
                AuthFinishEffect::ReleaseGrant(AuthFinishGrantPermit {
                    epoch: permit.epoch(),
                }),
            )
        }
        RecoverDecision::Reject => {
            // The policy is the authority. The raw observation only names the
            // historical guard/message, in the handler's status precedence.
            if !observation.account_epoch_active {
                auth_finish_terminal(driver, AuthFinishFailure::RotationPaused)
            } else if !observation.stored_credential_matches {
                auth_finish_terminal(driver, AuthFinishFailure::StoredCredentialMismatch)
            } else if !observation.share_present {
                auth_finish_terminal(driver, AuthFinishFailure::ShareMissing)
            } else {
                auth_finish_terminal(driver, AuthFinishFailure::PolicyRejected)
            }
        }
    }
}

fn apply_share_observed(
    driver: AuthFinishDriver,
    observation: ShareDecodeObservation,
) -> AuthFinishTransition {
    match observation {
        ShareDecodeObservation::Decoded => auth_finish_transition(
            AuthFinishDriver {
                stage: AuthFinishStage::Store,
                share_decoded: true,
                ..driver
            },
            AuthFinishEffect::StoreGrant,
        ),
        ShareDecodeObservation::Corrupt => {
            auth_finish_terminal(driver, AuthFinishFailure::ShareCorrupt)
        }
    }
}

fn apply_auth_grant_stored(
    driver: AuthFinishDriver,
    observation: GrantStoreObservation,
) -> AuthFinishTransition {
    match observation {
        GrantStoreObservation::Stored => auth_finish_transition(
            AuthFinishDriver {
                stage: AuthFinishStage::Done,
                grant_stored: true,
                ..driver
            },
            AuthFinishEffect::Complete,
        ),
        GrantStoreObservation::Failed => {
            auth_finish_terminal(driver, AuthFinishFailure::GrantStorage)
        }
    }
}

/// The complete, total authentication-finish transition relation. Events that
/// do not match the current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn step_auth_finish(
    driver: AuthFinishDriver,
    event: AuthFinishEvent,
) -> AuthFinishTransition {
    match event {
        AuthFinishEvent::AttemptCounted(observation) => {
            if matches!(driver.stage, AuthFinishStage::Attempt) {
                apply_auth_finish_attempt_counted(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
        AuthFinishEvent::ContextObserved(observation) => {
            if matches!(driver.stage, AuthFinishStage::Context) {
                apply_auth_finish_context_observed(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
        AuthFinishEvent::AttemptConsumed(observation) => {
            if matches!(driver.stage, AuthFinishStage::Consume) {
                apply_auth_attempt_consumed(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
        AuthFinishEvent::AssertionObserved(observation) => {
            if matches!(driver.stage, AuthFinishStage::Verify) {
                apply_auth_assertion_observed(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
        AuthFinishEvent::CredentialUpdated(observation) => {
            if matches!(driver.stage, AuthFinishStage::Update) {
                apply_auth_credential_updated(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
        AuthFinishEvent::AccountObserved(observation) => {
            if matches!(driver.stage, AuthFinishStage::Account) {
                apply_auth_account_observed(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
        AuthFinishEvent::ShareObserved(observation) => {
            if matches!(driver.stage, AuthFinishStage::Release) {
                apply_share_observed(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
        AuthFinishEvent::GrantStored(observation) => {
            if matches!(driver.stage, AuthFinishStage::Store) {
                apply_auth_grant_stored(driver, observation)
            } else {
                auth_finish_idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_finish_attempt_counted(
    driver: AuthFinishDriver,
    observation: AttemptBudgetObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::AttemptCounted(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_finish_context_observed(
    driver: AuthFinishDriver,
    observation: AuthFinishContextObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::ContextObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_attempt_consumed(
    driver: AuthFinishDriver,
    observation: AuthAttemptConsumptionObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::AttemptConsumed(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_assertion_observed(
    driver: AuthFinishDriver,
    observation: AssertionObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::AssertionObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_credential_updated(
    driver: AuthFinishDriver,
    observation: CredentialUpdateStoreObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::CredentialUpdated(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_account_observed(
    driver: AuthFinishDriver,
    observation: AuthAccountObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::AccountObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_share_observed(
    driver: AuthFinishDriver,
    observation: ShareDecodeObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::ShareObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(auth_finish_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    auth_finish_effect_is_sound(result.driver, result.effect)
        && (!auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(result.driver))
}))]
pub fn on_auth_grant_stored(
    driver: AuthFinishDriver,
    observation: GrantStoreObservation,
) -> AuthFinishTransition {
    step_auth_finish(driver, AuthFinishEvent::GrantStored(observation))
}
