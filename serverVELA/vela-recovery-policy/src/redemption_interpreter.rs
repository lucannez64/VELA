//! The one loop that connects `POST /recovery/enroll-device` to its driver.
//!
//! The handler does not call the redemption driver by hand. It expands
//! [`redemption_interpreter!`](crate::redemption_interpreter), the same macro
//! this module expands into the synchronous [`run_redemption`]. hax extracts
//! `run_redemption` and F* proves, for every [`RedemptionIo`] implementation,
//! that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects;
//! - a failed effect (or a failed grant restoration) stops the loop before
//!   any later effect, and the handler renders the recorded error unchanged;
//! - the loop stops at the first terminal effect and performs nothing after it
//!   (a `RestoreAndFail` performs its one restoration, then stops);
//! - the final driver is `run_from_ready ready events` for the observations the
//!   executor actually returned, so every per-request redemption theorem holds
//!   for the real handler.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::driver::{
    AuthorityRecheckObservation, ConsumptionObservation, FinalPolicyObservation,
    InsertObservation, RedemptionEffect, RedemptionInsertPermit, RedemptionTransition,
};
use crate::ReadyToConsume;

use crate::interpreter_support::executor_trait;

/// Most turns one request takes: consume, final policy, insert, optional
/// authority recheck, and the optional grant restoration.
pub const REDEMPTION_MAX_EFFECTS: usize = 5;

/// The driver has decided: nothing more may be performed (a `RestoreAndFail`
/// still performs its one recorded restoration first).
pub fn redemption_effect_is_terminal(effect: RedemptionEffect) -> bool {
    matches!(
        effect,
        RedemptionEffect::Complete
            | RedemptionEffect::Fail(_)
            | RedemptionEffect::RestoreAndFail(_)
            | RedemptionEffect::Idle
    )
}

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
pub fn redemption_transition_is_sound(transition: RedemptionTransition) -> bool {
    crate::driver::redemption_state_is_sound(transition.driver)
        && crate::driver::redemption_effect_is_sound(transition.driver, transition.effect)
}

executor_trait! {
    /// The I/O behind each non-terminal effect. Each method returns only the
    /// observation its effect expects; `None` aborts the request with the
    /// error the executor recorded.
    pub trait RedemptionIo {
        fn consume_grant(&mut self) -> Option<ConsumptionObservation>;
        fn final_policy(&mut self) -> Option<FinalPolicyObservation>;
        fn insert_device(&mut self, permit: RedemptionInsertPermit) -> Option<InsertObservation>;
        fn recheck_authority(&mut self) -> Option<AuthorityRecheckObservation>;
        fn restore_grant(&mut self) -> Option<()>;
    }
}

/// The interpreter body, shared verbatim by [`run_redemption`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call.
#[macro_export]
macro_rules! redemption_interpreter {
    ($io:ident, $ready:expr $(, $aw:ident)?) => {{
        use $crate::driver::{
            begin_redemption as __begin, step as __step, RedemptionEffect as __E,
            RedemptionEvent as __V,
        };
        let mut transition = __begin($ready);
        let mut restore_done = false;
        let mut aborted = false;
        for _ in 0..$crate::redemption_interpreter::REDEMPTION_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::redemption_interpreter::redemption_transition_is_sound(transition)
            });
            if !aborted && !restore_done {
                transition = match transition.effect {
                    __E::Consume => match $io.consume_grant()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Consumed(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::FinalPolicy => match $io.final_policy()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::FinalPolicy(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::Insert(permit) => match $io.insert_device(permit)$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Insert(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::Recheck => match $io.recheck_authority()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Recheck(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::RestoreAndFail(_) => {
                        match $io.restore_grant()$(.$aw)? {
                            Some(_) => restore_done = true,
                            None => aborted = true,
                        }
                        transition
                    }
                    // The driver has decided: perform nothing, keep the verdict.
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

/// The synchronous expansion of [`redemption_interpreter!`]: the artifact hax
/// extracts and F* checks.
pub fn run_redemption<Io: RedemptionIo>(
    io: &mut Io,
    ready: ReadyToConsume,
) -> Option<RedemptionTransition> {
    crate::redemption_interpreter!(io, ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{
        begin_redemption, step, ConsumedGrantObservation, RedemptionEvent, RedemptionFailure,
    };

    fn matching_consumed_grant(epoch: i64, possession: bool) -> ConsumedGrantObservation {
        ConsumedGrantObservation {
            key_epoch: epoch,
            possession,
            matches_observed_grant: true,
        }
    }

    /// Plays a fixed script of outcomes and records every call.
    struct Scripted {
        /// Which outcome to return for the n-th call (0 = success, 1 = first
        /// failure kind, 2 = second failure kind where one exists).
        script: Vec<u8>,
        calls: Vec<RedemptionEffect>,
        events: Vec<RedemptionEvent>,
        /// The preflight permit the consumed grant must match.
        epoch: i64,
        possession: bool,
        /// Whether `restore_grant` also fails.
        restore_fails: bool,
        /// Whether the ordinary calls abort instead of returning an observation.
        abort_at: Option<usize>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: RedemptionEffect) -> Option<u8> {
            self.calls.push(effect);
            if self.abort_at == Some(self.calls.len() - 1) {
                return None;
            }
            Some(self.pick())
        }
    }

    fn ready(epoch: i64, possession: bool) -> ReadyToConsume {
        // The only constructor is the checked preflight; build it from the
        // policy so the test cannot fabricate a permit the policy would reject.
        use crate::{
            plan_enrollment_preflight, EnrollmentAccountObservation, EnrollmentGrantFacts,
            EnrollmentPreflightDecision, EnrollmentPreflightObservation,
        };
        let decision = plan_enrollment_preflight(EnrollmentPreflightObservation {
            grant: Some(EnrollmentGrantFacts { epoch, possession }),
            account: EnrollmentAccountObservation::Present(crate::EnrollmentAccountFacts {
                stored_epoch: Some(epoch),
                epoch_active: true,
                credential_id_matches: !possession,
                commitment_len: if possession { 32 } else { 0 },
            }),
        });
        match decision {
            EnrollmentPreflightDecision::Ready(ready) => ready,
            EnrollmentPreflightDecision::Reject(_) => panic!("test preflight rejected"),
        }
    }

    impl RedemptionIo for Scripted {
        fn consume_grant(&mut self) -> Option<ConsumptionObservation> {
            let n = self.record(RedemptionEffect::Consume)? % 2;
            let observation = if n == 0 {
                ConsumptionObservation::Present(matching_consumed_grant(
                    self.epoch,
                    self.possession,
                ))
            } else {
                ConsumptionObservation::Missing
            };
            self.events.push(RedemptionEvent::Consumed(observation));
            Some(observation)
        }

        fn final_policy(&mut self) -> Option<FinalPolicyObservation> {
            let possession = self.possession;
            let n = self.record(RedemptionEffect::FinalPolicy)? % 2;
            let observation = FinalPolicyObservation {
                enrollment: crate::EnrollmentObservation {
                    grant_present: true,
                    grant_consumed: true,
                    consumed_matches_observed: true,
                    account_present: true,
                    grant_possession: possession,
                    grant_epoch: self.epoch,
                    stored_epoch: Some(self.epoch),
                    account_epoch_active: true,
                    credential_id_matches: !possession,
                    commitment_len: if possession { 32 } else { 0 },
                    hybrid_ek_len: crate::HYBRID_EK_LEN,
                    hybrid_vk_len: crate::HYBRID_VK_LEN,
                },
                rekey: if n == 0 {
                    crate::driver::RekeyObservation::Permit { epoch: self.epoch }
                } else {
                    crate::driver::RekeyObservation::Reject
                },
            };
            self.events.push(RedemptionEvent::FinalPolicy(observation));
            Some(observation)
        }

        fn insert_device(&mut self, permit: RedemptionInsertPermit) -> Option<InsertObservation> {
            assert_eq!(permit.epoch, self.epoch);
            assert_eq!(permit.possession, self.possession);
            let n = self.record(RedemptionEffect::Insert(permit))? % 3;
            let observation = match n {
                0 => InsertObservation::Inserted,
                1 => InsertObservation::Skipped,
                _ => InsertObservation::Failed,
            };
            self.events.push(RedemptionEvent::Insert(observation));
            Some(observation)
        }

        fn recheck_authority(&mut self) -> Option<AuthorityRecheckObservation> {
            let observations = [
                AuthorityRecheckObservation::StillRotating,
                AuthorityRecheckObservation::AccountAbsent,
                AuthorityRecheckObservation::QueryFailed,
                AuthorityRecheckObservation::CommitmentRevoked,
                AuthorityRecheckObservation::CredentialReplaced,
            ];
            let n = (self.record(RedemptionEffect::Recheck)? as usize) % observations.len();
            let observation = observations[n];
            self.events.push(RedemptionEvent::Recheck(observation));
            Some(observation)
        }

        fn restore_grant(&mut self) -> Option<()> {
            self.calls.push(RedemptionEffect::RestoreAndFail(
                RedemptionFailure::GrantChanged,
            ));
            if self.restore_fails {
                None
            } else {
                Some(())
            }
        }
    }

    /// Replays the recorded events through the driver by hand and checks the
    /// interpreter called exactly the emitted effects, in order, performed the
    /// restoration at most once, and stopped at the verdict.
    fn check(script: Vec<u8>, abort_at: Option<usize>, restore_fails: bool) -> Option<RedemptionEffect> {
        check_with(ready(7, false), script, abort_at, restore_fails)
    }

    fn check_with(
        permit: ReadyToConsume,
        script: Vec<u8>,
        abort_at: Option<usize>,
        restore_fails: bool,
    ) -> Option<RedemptionEffect> {
        let epoch = permit.epoch();
        let possession = permit.possession();
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
            epoch,
            possession,
            restore_fails,
            abort_at,
        };
        let result = run_redemption(&mut io, permit);
        let mut t = begin_redemption(permit);
        let mut event_index = 0;
        let mut restored = false;
        for (index, call) in io.calls.iter().enumerate() {
            if abort_at == Some(index) {
                break;
            }
            match *call {
                RedemptionEffect::RestoreAndFail(_) => {
                    assert!(
                        matches!(t.effect, RedemptionEffect::RestoreAndFail(_)),
                        "restore was not requested by the driver"
                    );
                    assert!(!restored, "restoration performed twice");
                    restored = true;
                }
                effect => {
                    assert_eq!(effect, t.effect, "call was not the emitted effect");
                    assert!(!redemption_effect_is_terminal(t.effect));
                    let event = io.events[event_index];
                    event_index += 1;
                    t = step(t.driver, event);
                }
            }
        }
        assert_eq!(event_index, io.events.len());
        assert!(io.calls.len() <= REDEMPTION_MAX_EFFECTS);
        if abort_at.is_some() || (restore_fails && restored) {
            assert!(result.is_none(), "an aborted effect must not produce a verdict");
        } else {
            let result = result.expect("no abort, so a verdict must be reached");
            assert_eq!(t, result, "interpreter result differs from the replayed driver");
            assert!(
                redemption_effect_is_terminal(result.effect),
                "no verdict within {REDEMPTION_MAX_EFFECTS} effects"
            );
            return Some(result.effect);
        }
        None
    }

    /// The insert path reaches `Complete`; the zero-row path reaches the
    /// authority recheck; every other observation kind reaches a verdict.
    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        for possession in [false, true] {
            let permit = ready(7, possession);
            let mut io = Scripted {
                script: vec![0; REDEMPTION_MAX_EFFECTS],
                calls: vec![],
                events: vec![],
                epoch: 7,
                possession,
                restore_fails: false,
                abort_at: None,
            };
            let result = run_redemption(&mut io, permit).expect("inserted grant completes");
            assert_eq!(result.effect, RedemptionEffect::Complete);
            assert_eq!(io.calls.len(), 3);
        }

        // Failure at each position, with every observation kind.
        let mut verdicts = std::collections::BTreeSet::new();
        for position in 0..REDEMPTION_MAX_EFFECTS {
            for kind in 1..=4u8 {
                let mut script = vec![0u8; REDEMPTION_MAX_EFFECTS];
                script[position] = kind;
                if let Some(effect) = check(script, None, false) {
                    verdicts.insert(format!("{effect:?}"));
                }
            }
        }
        assert!(verdicts.iter().any(|v| v.starts_with("RestoreAndFail")));
        assert!(verdicts.iter().any(|v| v.starts_with("Fail")));
        assert!(verdicts.iter().any(|v| v == "Complete"));

        // The zero-row insert detours through the authority recheck.
        let mut io = Scripted {
            script: vec![0, 0, 1, 3, 0],
            calls: vec![],
            events: vec![],
            epoch: 7,
            possession: true,
            restore_fails: false,
            abort_at: None,
        };
        let result = run_redemption(&mut io, ready(7, true)).expect("recheck reaches a verdict");
        assert_eq!(io.calls.len(), 4);
        assert_eq!(io.calls[3], RedemptionEffect::Recheck);
        assert!(redemption_effect_is_terminal(result.effect));
    }

    #[test]
    fn a_failed_effect_stops_the_loop_and_a_terminal_effect_performs_nothing() {
        for position in 0..3 {
            assert_eq!(check(vec![0; REDEMPTION_MAX_EFFECTS], Some(position), false), None);
        }
        // The authority recheck is only reached after a zero-row insert.
        assert_eq!(check(vec![0, 0, 1, 0, 0], Some(3), false), None);
        // A lost rotation race requests a restoration; a failed restoration
        // aborts with the store error instead of a verdict.
        assert_eq!(check(vec![0, 1, 0, 0, 0], None, true), None);
        assert!(matches!(
            check(vec![0, 1, 0, 0, 0], None, false),
            Some(RedemptionEffect::RestoreAndFail(_))
        ));
        // `Fail(GrantUnavailable)` from a missing grant is terminal at once.
        let mut io = Scripted {
            script: vec![1, 0, 0, 0, 0],
            calls: vec![],
            events: vec![],
            epoch: 7,
            possession: false,
            restore_fails: false,
            abort_at: None,
        };
        let result = run_redemption(&mut io, ready(7, false)).unwrap();
        assert!(matches!(
            result.effect,
            RedemptionEffect::Fail(RedemptionFailure::GrantUnavailable)
        ));
        assert_eq!(io.calls, vec![RedemptionEffect::Consume]);
    }
}
