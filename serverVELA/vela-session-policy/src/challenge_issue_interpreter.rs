//! The one loop that connects `GET /auth/challenge` to its driver.
//!
//! The handler does not call the driver by hand. It expands
//! [`challenge_issue_interpreter!`](crate::challenge_issue_interpreter), the
//! same macro this module expands into the synchronous [`run_issue`]. hax
//! extracts `run_issue` and F* proves, for every [`ChallengeIssueIo`]
//! implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects;
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is `run_from_purpose purpose evs` for the observations
//!   the executor actually returned, so every per-request issue theorem holds
//!   for the real handler.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::challenge::ChallengePurpose;
use crate::challenge_issue_driver::{
    IssueEffect, IssueTransition, NonceObservation, PurposeObservation, RateLimitObservation,
    StoreObservation,
};

/// Most effects one request performs: the limiter, the random read and the
/// store write. A terminal effect needs no further turn.
pub const ISSUE_MAX_EFFECTS: usize = 3;

/// The driver has decided: nothing more may be performed.
pub fn issue_effect_is_terminal(effect: IssueEffect) -> bool {
    matches!(effect, IssueEffect::Issue | IssueEffect::Fail(_) | IssueEffect::Idle)
}

executor_trait! {
    /// The I/O behind each non-terminal effect. Each method returns only the
    /// observation its effect expects.
    pub trait ChallengeIssueIo {
        fn check_rate_limit(&mut self) -> RateLimitObservation;
        fn generate_nonce(&mut self) -> NonceObservation;
        fn store_nonce(&mut self, purpose: ChallengePurpose) -> StoreObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_issue`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call.
#[macro_export]
macro_rules! challenge_issue_interpreter {
    ($io:ident, $purpose:expr $(, $aw:ident)?) => {{
        use $crate::challenge_issue_driver::{
            step as __step, IssueEffect as __E, IssueEvent as __V,
        };
        let mut transition = $crate::challenge_issue_driver::begin_issue($purpose);
        for _ in 0..$crate::challenge_issue_interpreter::ISSUE_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::challenge_issue_driver::issue_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::CheckRateLimit => __step(
                    transition.driver,
                    __V::RateLimitObserved($io.check_rate_limit()$(.$aw)?),
                ),
                __E::GenerateNonce => __step(
                    transition.driver,
                    __V::NonceObserved($io.generate_nonce()$(.$aw)?),
                ),
                __E::StoreNonce => __step(
                    transition.driver,
                    __V::StoreObserved(
                        $io.store_nonce(transition.driver.purpose)$(.$aw)?,
                    ),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Issue | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`challenge_issue_interpreter!`]: the artifact
/// hax extracts and F* checks.
pub fn run_issue<Io: ChallengeIssueIo>(
    io: &mut Io,
    purpose: PurposeObservation,
) -> IssueTransition {
    crate::challenge_issue_interpreter!(io, purpose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge_issue_driver::{
        begin_issue, step, IssueEvent, IssueFailure, NONCE_LEN,
    };

    struct Scripted {
        nonce: NonceObservation,
        store: StoreObservation,
        calls: Vec<IssueEffect>,
    }

    impl ChallengeIssueIo for Scripted {
        fn check_rate_limit(&mut self) -> RateLimitObservation {
            self.calls.push(IssueEffect::CheckRateLimit);
            RateLimitObservation::Allowed
        }
        fn generate_nonce(&mut self) -> NonceObservation {
            self.calls.push(IssueEffect::GenerateNonce);
            self.nonce
        }
        fn store_nonce(&mut self, _purpose: ChallengePurpose) -> StoreObservation {
            self.calls.push(IssueEffect::StoreNonce);
            self.store
        }
    }

    fn run(purpose: PurposeObservation, nonce: NonceObservation, store: StoreObservation) -> (IssueTransition, Vec<IssueEffect>) {
        let mut io = Scripted { nonce, store, calls: vec![] };
        let result = run_issue(&mut io, purpose);
        (result, io.calls)
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects() {
        let (t, calls) = run(
            PurposeObservation::Requested(ChallengePurpose::Enroll),
            NonceObservation::Generated { len: NONCE_LEN },
            StoreObservation::Inserted,
        );
        assert_eq!(
            calls,
            vec![
                IssueEffect::CheckRateLimit,
                IssueEffect::GenerateNonce,
                IssueEffect::StoreNonce
            ]
        );
        assert_eq!(t.effect, IssueEffect::Issue);
        assert!(t.driver.issued && t.driver.stored_fresh && t.driver.purpose_valid);
    }

    #[test]
    fn every_failure_stops_before_the_store() {
        let (t, calls) = run(
            PurposeObservation::Invalid,
            NonceObservation::Generated { len: NONCE_LEN },
            StoreObservation::Inserted,
        );
        assert!(calls.is_empty());
        assert_eq!(t.effect, IssueEffect::Fail(IssueFailure::InvalidPurpose));

        let (t, calls) = run(
            PurposeObservation::Requested(ChallengePurpose::Login),
            NonceObservation::Generated { len: 31 },
            StoreObservation::Inserted,
        );
        assert_eq!(calls, vec![IssueEffect::CheckRateLimit, IssueEffect::GenerateNonce]);
        assert_eq!(t.effect, IssueEffect::Fail(IssueFailure::NonceLength));

        for store in [StoreObservation::KeyExists, StoreObservation::Failed] {
            let (t, calls) = run(
                PurposeObservation::Requested(ChallengePurpose::Login),
                NonceObservation::Generated { len: NONCE_LEN },
                store,
            );
            assert_eq!(calls.len(), 3);
            assert!(matches!(t.effect, IssueEffect::Fail(_)));
            assert!(!t.driver.issued);
        }
    }

    #[test]
    fn replaying_the_recorded_events_through_the_driver_agrees() {
        let purpose = PurposeObservation::Requested(ChallengePurpose::WebToken);
        let (result, calls) = run(
            purpose,
            NonceObservation::Generated { len: NONCE_LEN },
            StoreObservation::Inserted,
        );
        let mut t = begin_issue(purpose);
        let events = [
            IssueEvent::RateLimitObserved(RateLimitObservation::Allowed),
            IssueEvent::NonceObserved(NonceObservation::Generated { len: NONCE_LEN }),
            IssueEvent::StoreObserved(StoreObservation::Inserted),
        ];
        for (i, event) in events.iter().enumerate() {
            assert_eq!(calls[i], t.effect);
            t = step(t.driver, *event);
        }
        assert_eq!(t, result);
    }
}
