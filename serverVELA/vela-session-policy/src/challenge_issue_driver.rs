//! Pure `GET /auth/challenge` issue driver.
//!
//! `get_challenge` in `vela-server` performs the effectful steps: the per-IP
//! challenge limiter, OS randomness, the `sled` write under
//! `challenge:<nonce>` and the response. This module owns every *decision*
//! between those effects:
//!
//! 1. the requested purpose string must parse to exactly one of the three
//!    bound purposes (`login`, `enroll`, `web_token`);
//! 2. the per-IP limiter must allow the request;
//! 3. the OS random source must yield exactly 32 bytes;
//! 4. the nonce key must be absent before the write, so the issued key is
//!    fresh and cannot replace another live challenge;
//! 5. only then is the single issue effect authorized.
//!
//! The transition relation is total: an event that does not match the current
//! stage (and every event after `Done`) is ignored, so the unbounded trace
//! induction in `proofs/fstar/challenge-issue-driver-lemmas` is a statement
//! about every event list.
//!
//! The driver is a per-request value. It does not observe sled, does not
//! coordinate concurrent consumers and does not claim that two independent
//! requests use different random bytes; freshness here means the atomic
//! `Store::set_ex_nx` observation reported that the key was absent when this
//! request wrote it. Single use of an issued key is the composition module's
//! theorem (`proofs/fstar/challenge-issue-composition`).

use crate::challenge::ChallengePurpose;

/// Byte length of an issued nonce.
pub const NONCE_LEN: usize = 32;

/// The parsed purpose query. `Invalid` is the handler's `400`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurposeObservation {
    Requested(ChallengePurpose),
    Invalid,
}

/// Outcome of the per-IP challenge limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitObservation {
    Allowed,
    Denied,
}

/// Outcome of the OS random call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceObservation {
    /// The source filled the requested buffer; `len` is the number of bytes
    /// the handler will store. The driver requires exactly [`NONCE_LEN`].
    Generated { len: usize },
    Unavailable,
}

/// Outcome of the first-writer-wins store write (`set_ex_nx`). `Inserted` is
/// the only observation that proves the key was absent and is now ours.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreObservation {
    Inserted,
    /// The key already existed: a random collision, so nothing new was issued
    /// (the existing challenge is left untouched for its own consumer).
    KeyExists,
    Failed,
}

/// Where the issue is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueStage {
    /// Apply the per-IP challenge limiter.
    RateLimit,
    /// Ask the OS for [`NONCE_LEN`] random bytes.
    GenerateNonce,
    /// Write the purpose tag under the fresh key.
    StoreNonce,
    /// The response was authorized.
    Done,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueEvent {
    RateLimitObserved(RateLimitObservation),
    NonceObserved(NonceObservation),
    StoreObserved(StoreObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence where the driver fixes the class. `InvalidPurpose` and
/// `RandomUnavailable` keep the handler's original error text in its `error`
/// slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueFailure {
    /// `400 purpose must be login, enroll or web_token`.
    InvalidPurpose,
    /// The per-IP limiter refused the request.
    RateLimited,
    /// The OS random source failed.
    RandomUnavailable,
    /// The random source produced the wrong number of bytes.
    NonceLength,
    /// The key already existed; nothing was overwritten.
    Collision,
    /// The `sled` write failed.
    Storage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueEffect {
    /// Apply the per-IP challenge limiter.
    CheckRateLimit,
    /// Fill a [`NONCE_LEN`]-byte buffer from the OS.
    GenerateNonce,
    /// Write `purpose_tag_bytes(purpose)` under `challenge:<nonce>` with the
    /// 60-second TTL using the atomic first-writer-wins store operation.
    StoreNonce,
    /// Return the base64 nonce. This is the only effect that authorizes a
    /// response.
    Issue,
    /// Terminal failure without a response.
    Fail(IssueFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about sled or the OS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssueDriver {
    pub stage: IssueStage,
    /// The parsed request purpose. It is the default `Login` only when parsing
    /// failed, in which case `purpose_valid` is false and no store is ever
    /// authorized.
    pub purpose: ChallengePurpose,
    /// The query parsed to a bound purpose.
    pub purpose_valid: bool,
    /// The limiter allowed this request.
    pub rate_allowed: bool,
    /// The random source returned exactly [`NONCE_LEN`] bytes.
    pub nonce_valid: bool,
    /// The store reported that the key was absent and is now ours.
    pub stored_fresh: bool,
    /// The response was authorized.
    pub issued: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssueTransition {
    pub driver: IssueDriver,
    pub effect: IssueEffect,
}

/// Structural purpose equality, independent of derived `PartialEq` for hax.
fn same_issue_purpose(a: ChallengePurpose, b: ChallengePurpose) -> bool {
    matches!(
        (a, b),
        (ChallengePurpose::Login, ChallengePurpose::Login)
            | (ChallengePurpose::Enroll, ChallengePurpose::Enroll)
            | (ChallengePurpose::WebToken, ChallengePurpose::WebToken)
    )
}

/// Position of the stage in the fixed issue order. A step never moves it
/// backwards; a terminal verdict moves it to `Done`.
pub fn issue_stage_index(d: IssueDriver) -> usize {
    match d.stage {
        IssueStage::RateLimit => 0,
        IssueStage::GenerateNonce => 1,
        IssueStage::StoreNonce => 2,
        IssueStage::Done => 3,
    }
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn issue_state_is_sound(d: IssueDriver) -> bool {
    let rate = matches!(d.stage, IssueStage::RateLimit);
    let generate = matches!(d.stage, IssueStage::GenerateNonce);
    let store = matches!(d.stage, IssueStage::StoreNonce);
    let done = matches!(d.stage, IssueStage::Done);
    let purpose_bound = d.purpose_valid;
    (!rate
        || (d.purpose_valid
            && !d.rate_allowed
            && !d.nonce_valid
            && !d.stored_fresh
            && !d.issued
            && !d.failed))
        && (!generate
            || (d.purpose_valid
                && d.rate_allowed
                && !d.nonce_valid
                && !d.stored_fresh
                && !d.issued
                && !d.failed))
        && (!store
            || (d.purpose_valid
                && d.rate_allowed
                && d.nonce_valid
                && !d.stored_fresh
                && !d.issued
                && !d.failed))
        && (!done
            || (d.issued || d.failed)
            && !(d.issued && d.failed)
            && (!d.issued
                || (purpose_bound && d.rate_allowed && d.nonce_valid && d.stored_fresh)))
        && (!d.nonce_valid || d.rate_allowed)
        && (!d.stored_fresh || (d.rate_allowed && d.nonce_valid))
        && (!d.issued || (d.stored_fresh && purpose_bound))
        && (!d.stored_fresh || purpose_bound)
        && (!d.failed || !d.issued)
}

/// Every effect the driver emits agrees with the state it produces. In
/// particular `StoreNonce` names the parsed purpose, is emitted only after the
/// limiter, a 32-byte nonce and the absence check, and is emitted at most once
/// because the next state is terminal.
pub fn issue_effect_is_sound(d: IssueDriver, effect: IssueEffect) -> bool {
    match effect {
        IssueEffect::CheckRateLimit => {
            matches!(d.stage, IssueStage::RateLimit)
                && !d.rate_allowed
                && !d.nonce_valid
                && !d.stored_fresh
                && !d.issued
                && !d.failed
        }
        IssueEffect::GenerateNonce => {
            matches!(d.stage, IssueStage::GenerateNonce)
                && d.rate_allowed
                && !d.nonce_valid
                && !d.stored_fresh
                && !d.issued
                && !d.failed
        }
        IssueEffect::StoreNonce => {
            matches!(d.stage, IssueStage::StoreNonce)
                && d.rate_allowed
                && d.nonce_valid
                && !d.stored_fresh
                && !d.issued
                && !d.failed
                && d.purpose_valid
        }
        IssueEffect::Issue => {
            matches!(d.stage, IssueStage::Done)
                && d.issued
                && d.rate_allowed
                && d.nonce_valid
                && d.stored_fresh
                && !d.failed
                && d.purpose_valid
        }
        IssueEffect::Fail(_) => {
            matches!(d.stage, IssueStage::Done) && d.failed && !d.issued && !d.stored_fresh
        }
        IssueEffect::Idle => true,
    }
}

fn transition(driver: IssueDriver, effect: IssueEffect) -> IssueTransition {
    IssueTransition { driver, effect }
}

fn idle(driver: IssueDriver) -> IssueTransition {
    transition(driver, IssueEffect::Idle)
}

fn terminal(driver: IssueDriver, failure: IssueFailure) -> IssueTransition {
    transition(
        IssueDriver {
            stage: IssueStage::Done,
            failed: true,
            ..driver
        },
        IssueEffect::Fail(failure),
    )
}

/// The empty request state before the first effect.
fn request_state(purpose: ChallengePurpose, purpose_valid: bool) -> IssueDriver {
    IssueDriver {
        stage: IssueStage::RateLimit,
        purpose,
        purpose_valid,
        rate_allowed: false,
        nonce_valid: false,
        stored_fresh: false,
        issued: false,
        failed: false,
    }
}

/// Start a per-request challenge issue. An unparseable purpose is a terminal
/// `400` with no limiter, random or store effect.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_state_is_sound(result.driver)
        && issue_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_issue(purpose: PurposeObservation) -> IssueTransition {
    match purpose {
        PurposeObservation::Invalid => terminal(
            request_state(ChallengePurpose::Login, false),
            IssueFailure::InvalidPurpose,
        ),
        PurposeObservation::Requested(purpose) => {
            transition(request_state(purpose, true), IssueEffect::CheckRateLimit)
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(
    issue_state_is_sound(driver)
        && matches!(driver.stage, IssueStage::RateLimit)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_effect_is_sound(result.driver, result.effect)
        && (!issue_state_is_sound(driver) || issue_state_is_sound(result.driver))
}))]
fn on_rate_limit(driver: IssueDriver, observation: RateLimitObservation) -> IssueTransition {
    match observation {
        RateLimitObservation::Allowed => transition(
            IssueDriver {
                stage: IssueStage::GenerateNonce,
                rate_allowed: true,
                ..driver
            },
            IssueEffect::GenerateNonce,
        ),
        RateLimitObservation::Denied => terminal(driver, IssueFailure::RateLimited),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    issue_state_is_sound(driver)
        && matches!(driver.stage, IssueStage::GenerateNonce)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_effect_is_sound(result.driver, result.effect)
        && (!issue_state_is_sound(driver) || issue_state_is_sound(result.driver))
}))]
fn on_nonce(driver: IssueDriver, observation: NonceObservation) -> IssueTransition {
    match observation {
        NonceObservation::Generated { len } if len == NONCE_LEN => transition(
            IssueDriver {
                stage: IssueStage::StoreNonce,
                nonce_valid: true,
                ..driver
            },
            IssueEffect::StoreNonce,
        ),
        NonceObservation::Generated { .. } => terminal(driver, IssueFailure::NonceLength),
        NonceObservation::Unavailable => terminal(driver, IssueFailure::RandomUnavailable),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    issue_state_is_sound(driver)
        && matches!(driver.stage, IssueStage::StoreNonce)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_effect_is_sound(result.driver, result.effect)
        && (!issue_state_is_sound(driver) || issue_state_is_sound(result.driver))
}))]
fn on_store(driver: IssueDriver, observation: StoreObservation) -> IssueTransition {
    match observation {
        StoreObservation::Inserted => transition(
            IssueDriver {
                stage: IssueStage::Done,
                stored_fresh: true,
                issued: true,
                ..driver
            },
            IssueEffect::Issue,
        ),
        StoreObservation::KeyExists => terminal(driver, IssueFailure::Collision),
        StoreObservation::Failed => terminal(driver, IssueFailure::Storage),
    }
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(issue_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_effect_is_sound(result.driver, result.effect)
        && (!issue_state_is_sound(driver) || issue_state_is_sound(result.driver))
        && issue_stage_index(result.driver) >= issue_stage_index(driver)
        && same_issue_purpose(result.driver.purpose, driver.purpose)
        && (!matches!(result.effect, IssueEffect::GenerateNonce)
            || matches!(driver.stage, IssueStage::RateLimit))
        && (!matches!(result.effect, IssueEffect::StoreNonce)
            || matches!(driver.stage, IssueStage::GenerateNonce))
        && (!matches!(result.effect, IssueEffect::Issue)
            || matches!(driver.stage, IssueStage::StoreNonce))
}))]
pub fn step(driver: IssueDriver, event: IssueEvent) -> IssueTransition {
    match event {
        IssueEvent::RateLimitObserved(observation) => {
            if matches!(driver.stage, IssueStage::RateLimit) {
                on_rate_limit(driver, observation)
            } else {
                idle(driver)
            }
        }
        IssueEvent::NonceObserved(observation) => {
            if matches!(driver.stage, IssueStage::GenerateNonce) {
                on_nonce(driver, observation)
            } else {
                idle(driver)
            }
        }
        IssueEvent::StoreObserved(observation) => {
            if matches!(driver.stage, IssueStage::StoreNonce) {
                on_store(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(issue_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_effect_is_sound(result.driver, result.effect)
        && (!issue_state_is_sound(driver) || issue_state_is_sound(result.driver))
}))]
pub fn on_rate_limit_event(
    driver: IssueDriver,
    observation: RateLimitObservation,
) -> IssueTransition {
    step(driver, IssueEvent::RateLimitObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(issue_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_effect_is_sound(result.driver, result.effect)
        && (!issue_state_is_sound(driver) || issue_state_is_sound(result.driver))
}))]
pub fn on_nonce_event(driver: IssueDriver, observation: NonceObservation) -> IssueTransition {
    step(driver, IssueEvent::NonceObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(issue_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    issue_effect_is_sound(result.driver, result.effect)
        && (!issue_state_is_sound(driver) || issue_state_is_sound(result.driver))
}))]
pub fn on_store_event(driver: IssueDriver, observation: StoreObservation) -> IssueTransition {
    step(driver, IssueEvent::StoreObserved(observation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events() -> Vec<IssueEvent> {
        let mut out = Vec::new();
        for observation in [RateLimitObservation::Allowed, RateLimitObservation::Denied] {
            out.push(IssueEvent::RateLimitObserved(observation));
        }
        for observation in [
            NonceObservation::Generated { len: NONCE_LEN },
            NonceObservation::Generated { len: 0 },
            NonceObservation::Generated { len: 31 },
            NonceObservation::Unavailable,
        ] {
            out.push(IssueEvent::NonceObserved(observation));
        }
        for observation in [
            StoreObservation::Inserted,
            StoreObservation::KeyExists,
            StoreObservation::Failed,
        ] {
            out.push(IssueEvent::StoreObserved(observation));
        }
        out
    }

    fn driver_at(stage: IssueStage) -> IssueDriver {
        let mut driver = begin_issue(PurposeObservation::Requested(ChallengePurpose::Login)).driver;
        let mut guard = 0;
        while driver.stage != stage {
            let next = match driver.stage {
                IssueStage::RateLimit => {
                    on_rate_limit(driver, RateLimitObservation::Allowed)
                }
                IssueStage::GenerateNonce => {
                    on_nonce(driver, NonceObservation::Generated { len: NONCE_LEN })
                }
                IssueStage::StoreNonce => on_store(driver, StoreObservation::Inserted),
                IssueStage::Done => break,
            };
            driver = next.driver;
            guard += 1;
            assert!(guard < 8, "did not reach {stage:?}");
        }
        driver
    }

    #[test]
    fn every_state_and_effect_is_sound_exhaustively() {
        for stage in [
            IssueStage::RateLimit,
            IssueStage::GenerateNonce,
            IssueStage::StoreNonce,
            IssueStage::Done,
        ] {
            let driver = driver_at(stage);
            assert!(issue_state_is_sound(driver), "{stage:?}: {driver:?}");
            for event in events() {
                let t = step(driver, event);
                assert!(issue_state_is_sound(t.driver), "{stage:?} {event:?}");
                assert!(issue_effect_is_sound(t.driver, t.effect));
            }
        }
    }

    #[test]
    fn invalid_purpose_and_limiter_refusal_perform_nothing() {
        let invalid = begin_issue(PurposeObservation::Invalid);
        assert_eq!(invalid.effect, IssueEffect::Fail(IssueFailure::InvalidPurpose));
        assert_eq!(invalid.driver.stage, IssueStage::Done);
        assert!(!invalid.driver.stored_fresh);

        let refused = on_rate_limit(
            begin_issue(PurposeObservation::Requested(ChallengePurpose::Enroll)).driver,
            RateLimitObservation::Denied,
        );
        assert_eq!(refused.effect, IssueEffect::Fail(IssueFailure::RateLimited));
        assert!(!refused.driver.stored_fresh && !refused.driver.issued);
    }

    #[test]
    fn a_failed_store_issues_nothing_and_a_collision_overwrites_nothing() {
        for observation in [StoreObservation::KeyExists, StoreObservation::Failed] {
            let t = on_store(driver_at(IssueStage::StoreNonce), observation);
            assert!(matches!(t.effect, IssueEffect::Fail(_)));
            assert!(
                !t.driver.issued && !t.driver.stored_fresh,
                "a failed store still claimed freshness or an issue"
            );
            for event in events() {
                assert_eq!(step(t.driver, event).effect, IssueEffect::Idle);
            }
        }
    }

    #[test]
    fn wrong_nonce_length_fails_before_any_store() {
        for len in [0usize, 31, 33] {
            let t = on_nonce(
                driver_at(IssueStage::GenerateNonce),
                NonceObservation::Generated { len },
            );
            assert_eq!(t.effect, IssueEffect::Fail(IssueFailure::NonceLength));
            assert!(!t.driver.nonce_valid && !t.driver.stored_fresh);
        }
    }

    #[test]
    fn success_stores_exactly_one_purpose_once() {
        let start = begin_issue(PurposeObservation::Requested(ChallengePurpose::WebToken));
        assert_eq!(start.effect, IssueEffect::CheckRateLimit);
        let t = on_rate_limit(start.driver, RateLimitObservation::Allowed);
        assert_eq!(t.effect, IssueEffect::GenerateNonce);
        let t = on_nonce(t.driver, NonceObservation::Generated { len: NONCE_LEN });
        assert_eq!(t.effect, IssueEffect::StoreNonce);
        assert_eq!(t.driver.purpose, ChallengePurpose::WebToken);
        assert!(t.driver.purpose_valid);
        let t = on_store(t.driver, StoreObservation::Inserted);
        assert_eq!(t.effect, IssueEffect::Issue);
        assert!(t.driver.issued && t.driver.stored_fresh && !t.driver.failed);
        for event in events() {
            assert_eq!(step(t.driver, event).effect, IssueEffect::Idle);
        }
    }
}
