//! The one loop that connects `POST /account/register` to its driver.
//!
//! The handler does not call the driver by hand. It expands
//! [`registration_interpreter!`](crate::registration_interpreter), the same
//! macro this module expands into the synchronous [`run_registration`]. hax
//! extracts `run_registration` and F* proves, for every [`RegistrationIo`]
//! implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects;
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is `run_from_observation observation evs` for the
//!   observations the executor actually returned, so every per-request
//!   registration theorem holds for the real handler.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::registration_driver::{
    BudgetObservation, CommitObservation, InsertObservation, RateLimitObservation,
    RegistrationEffect, RegistrationRequestObservation, RegistrationTransition, TokenObservation,
    TrackObservation, TransactionObservation,
};

/// Most effects one request performs: limiter, optional budget, transaction
/// begin, two inserts, commit, token issue and JTI tracking.
pub const REGISTRATION_MAX_EFFECTS: usize = 8;

/// The driver has decided: nothing more may be performed.
pub fn registration_effect_is_terminal(effect: RegistrationEffect) -> bool {
    matches!(
        effect,
        RegistrationEffect::Complete
            | RegistrationEffect::Fail(_)
            | RegistrationEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind each non-terminal effect. Each method returns only the
    /// observation its effect expects.
    pub trait RegistrationIo {
        fn check_rate_limit(&mut self) -> RateLimitObservation;
        fn check_account_budget(&mut self) -> BudgetObservation;
        fn begin_transaction(&mut self) -> TransactionObservation;
        fn insert_account(&mut self) -> InsertObservation;
        fn insert_device(&mut self) -> InsertObservation;
        fn commit(&mut self) -> CommitObservation;
        fn issue_token(&mut self) -> TokenObservation;
        fn track_token(&mut self) -> TrackObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_registration`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call.
#[macro_export]
macro_rules! registration_interpreter {
    ($io:ident, $observation:expr $(, $aw:ident)?) => {{
        use $crate::registration_driver::{
            step as __step, RegistrationEffect as __E, RegistrationEvent as __V,
        };
        let mut transition = $crate::registration_driver::begin_registration($observation);
        for _ in 0..$crate::registration_interpreter::REGISTRATION_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::registration_driver::registration_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::CheckRateLimit => __step(
                    transition.driver,
                    __V::RateLimitObserved($io.check_rate_limit()$(.$aw)?),
                ),
                __E::CheckAccountBudget => __step(
                    transition.driver,
                    __V::BudgetObserved($io.check_account_budget()$(.$aw)?),
                ),
                __E::BeginTransaction => __step(
                    transition.driver,
                    __V::TransactionObserved($io.begin_transaction()$(.$aw)?),
                ),
                __E::InsertAccount => __step(
                    transition.driver,
                    __V::AccountInserted($io.insert_account()$(.$aw)?),
                ),
                __E::InsertDevice => __step(
                    transition.driver,
                    __V::DeviceInserted($io.insert_device()$(.$aw)?),
                ),
                __E::CommitTransaction => {
                    __step(transition.driver, __V::CommitObserved($io.commit()$(.$aw)?))
                }
                __E::IssueToken => {
                    __step(transition.driver, __V::TokenObserved($io.issue_token()$(.$aw)?))
                }
                __E::TrackToken => {
                    __step(transition.driver, __V::TrackObserved($io.track_token()$(.$aw)?))
                }
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`registration_interpreter!`]: the artifact
/// hax extracts and F* checks.
pub fn run_registration<Io: RegistrationIo>(
    io: &mut Io,
    observation: RegistrationRequestObservation,
) -> RegistrationTransition {
    crate::registration_interpreter!(io, observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration_driver::{
        begin_registration, step, RegistrationEvent, RegistrationFailure,
    };

    struct Scripted {
        script: Vec<u8>,
        calls: Vec<RegistrationEffect>,
        events: Vec<RegistrationEvent>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: RegistrationEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
    }

    impl RegistrationIo for Scripted {
        fn check_rate_limit(&mut self) -> RateLimitObservation {
            let o = [RateLimitObservation::Allowed, RateLimitObservation::Denied]
                [(self.record(RegistrationEffect::CheckRateLimit) % 2) as usize];
            self.events.push(RegistrationEvent::RateLimitObserved(o));
            o
        }
        fn check_account_budget(&mut self) -> BudgetObservation {
            let o = [BudgetObservation::Counted { count: 0 }, BudgetObservation::QueryFailed]
                [(self.record(RegistrationEffect::CheckAccountBudget) % 2) as usize];
            self.events.push(RegistrationEvent::BudgetObserved(o));
            o
        }
        fn begin_transaction(&mut self) -> TransactionObservation {
            let o = [TransactionObservation::Begun, TransactionObservation::Failed]
                [(self.record(RegistrationEffect::BeginTransaction) % 2) as usize];
            self.events.push(RegistrationEvent::TransactionObserved(o));
            o
        }
        fn insert_account(&mut self) -> InsertObservation {
            let o = [InsertObservation::Inserted, InsertObservation::Failed]
                [(self.record(RegistrationEffect::InsertAccount) % 2) as usize];
            self.events.push(RegistrationEvent::AccountInserted(o));
            o
        }
        fn insert_device(&mut self) -> InsertObservation {
            let o = [InsertObservation::Inserted, InsertObservation::Failed]
                [(self.record(RegistrationEffect::InsertDevice) % 2) as usize];
            self.events.push(RegistrationEvent::DeviceInserted(o));
            o
        }
        fn commit(&mut self) -> CommitObservation {
            let o = [CommitObservation::Committed, CommitObservation::Failed]
                [(self.record(RegistrationEffect::CommitTransaction) % 2) as usize];
            self.events.push(RegistrationEvent::CommitObserved(o));
            o
        }
        fn issue_token(&mut self) -> TokenObservation {
            let o = [TokenObservation::Issued, TokenObservation::Failed]
                [(self.record(RegistrationEffect::IssueToken) % 2) as usize];
            self.events.push(RegistrationEvent::TokenObserved(o));
            o
        }
        fn track_token(&mut self) -> TrackObservation {
            let o = [TrackObservation::Tracked, TrackObservation::Failed]
                [(self.record(RegistrationEffect::TrackToken) % 2) as usize];
            self.events.push(RegistrationEvent::TrackObserved(o));
            o
        }
    }

    fn request(with_limit: bool) -> RegistrationRequestObservation {
        RegistrationRequestObservation {
            has_account_limit: with_limit,
            account_limit: 10,
            identity_ek_valid: true,
            identity_vk_valid: true,
            share_ek_valid: true,
        }
    }

    fn check(observation: RegistrationRequestObservation, script: Vec<u8>) -> RegistrationEffect {
        let mut io = Scripted { script, calls: vec![], events: vec![] };
        let result = run_registration(&mut io, observation);
        let mut t = begin_registration(observation);
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!registration_effect_is_terminal(t.effect));
            t = step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(registration_effect_is_terminal(result.effect));
        assert!(io.calls.len() <= REGISTRATION_MAX_EFFECTS);
        result.effect
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects() {
        assert_eq!(check(request(false), vec![0; 8]), RegistrationEffect::Complete);
        assert_eq!(check(request(true), vec![0; 8]), RegistrationEffect::Complete);
        for position in 0..REGISTRATION_MAX_EFFECTS {
            for kind in 1..=2u8 {
                let mut script = vec![0u8; REGISTRATION_MAX_EFFECTS];
                script[position] = kind;
                let effect = check(request(true), script);
                assert!(
                    matches!(effect, RegistrationEffect::Complete | RegistrationEffect::Fail(_)),
                    "no verdict: {effect:?}"
                );
            }
        }
    }

    #[test]
    fn a_device_insert_failure_stops_before_commit_and_token() {
        // Calls: limiter (0), budget (1), begin (2), account (3), device (4).
        let mut script = vec![0u8; 8];
        script[4] = 1;
        assert_eq!(
            check(request(true), script),
            RegistrationEffect::Fail(RegistrationFailure::DeviceInsertStorage)
        );
    }

    #[test]
    fn invalid_keys_never_open_a_transaction() {
        let observation = RegistrationRequestObservation {
            identity_ek_valid: false,
            ..request(false)
        };
        let mut io = Scripted { script: vec![], calls: vec![], events: vec![] };
        let result = run_registration(&mut io, observation);
        assert_eq!(
            result.effect,
            RegistrationEffect::Fail(RegistrationFailure::InvalidRequest)
        );
        assert_eq!(io.calls, vec![RegistrationEffect::CheckRateLimit]);
    }
}
