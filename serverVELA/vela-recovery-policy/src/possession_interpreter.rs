//! The two loops that connect the possession-proof handlers to their drivers.
//!
//! `POST /recovery/recover/proof/initiate` and `POST /recovery/recover/proof`
//! do not call their drivers by hand. Each handler expands one of the macros
//! below; this module expands the same text into the synchronous
//! [`run_possession_initiation`] and [`run_possession_recover`], which hax
//! extracts and F* checks. For every executor implementation the proofs show
//! that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and returns the observation kind that
//!   effect expects;
//! - a failed effect stops the loop before any later effect, and the handler
//!   renders the recorded error unchanged;
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is the driver's `run_*_from_begin` over the observations
//!   the executor actually returned, so every per-request possession theorem
//!   holds for the real handler.
//!
//! The server's expansions differ only by `.await` after each executor call.

use crate::possession_driver::{
    AttemptBudgetObservation, AttemptConsumptionObservation, ChallengeStoreObservation,
    GrantStoreObservation, InitiateEffect, InitiateObservation, InitiateTransition,
    ProofAccountObservation, ProofGrantPermit, ProofObservation, ProofRecoverEffect,
    ProofRecoverTransition,
};

use crate::interpreter_support::executor_trait;

// ── Challenge initiation ────────────────────────────────────────────────────

/// Most effects one initiation performs: observe, store the challenge, verdict.
pub const POSSESSION_INITIATION_MAX_EFFECTS: usize = 3;

/// The driver has decided: nothing more may be performed.
pub fn initiation_effect_is_terminal(effect: InitiateEffect) -> bool {
    matches!(
        effect,
        InitiateEffect::Complete | InitiateEffect::Fail(_) | InitiateEffect::Idle
    )
}

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
pub fn initiation_transition_is_sound(transition: InitiateTransition) -> bool {
    crate::possession_driver::initiation_state_is_sound(transition.driver)
        && crate::possession_driver::initiation_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

executor_trait! {
    /// The I/O behind each non-terminal initiation effect. `None` aborts the
    /// request with the error the executor recorded.
    pub trait PossessionInitiationIo {
        fn observe(&mut self) -> Option<InitiateObservation>;
        fn store_challenge(&mut self) -> Option<ChallengeStoreObservation>;
    }
}

/// The initiation interpreter body, shared verbatim by
/// [`run_possession_initiation`] and the async handler.
#[macro_export]
macro_rules! possession_initiation_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::possession_driver::{
            begin_initiation as __begin, step_initiation as __step, InitiateEffect as __E,
            InitiateEvent as __V,
        };
        let mut transition = __begin();
        let mut aborted = false;
        for _ in 0..$crate::possession_interpreter::POSSESSION_INITIATION_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::possession_interpreter::initiation_transition_is_sound(transition)
            });
            if !aborted {
                transition = match transition.effect {
                    __E::Observe => match $io.observe()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Observed(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::StoreChallenge => match $io.store_challenge()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Stored(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    // The driver has decided: perform nothing, keep the verdict.
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

/// The synchronous expansion of [`possession_initiation_interpreter!`].
pub fn run_possession_initiation<Io: PossessionInitiationIo>(
    io: &mut Io,
) -> Option<InitiateTransition> {
    crate::possession_initiation_interpreter!(io)
}

// ── Possession proof recovery ───────────────────────────────────────────────

/// Most effects one proof recovery performs: count, consume, query, verify,
/// issue, verdict.
pub const POSSESSION_RECOVER_MAX_EFFECTS: usize = 6;

/// The driver has decided: nothing more may be performed.
pub fn proof_recover_effect_is_terminal(effect: ProofRecoverEffect) -> bool {
    matches!(
        effect,
        ProofRecoverEffect::Complete | ProofRecoverEffect::Fail(_) | ProofRecoverEffect::Idle
    )
}

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
pub fn proof_recover_transition_is_sound(transition: ProofRecoverTransition) -> bool {
    crate::possession_driver::proof_recover_state_is_sound(transition.driver)
        && crate::possession_driver::proof_recover_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

executor_trait! {
    /// The I/O behind each non-terminal proof-recovery effect. `None` aborts
    /// the request with the error the executor recorded.
    pub trait PossessionRecoverIo {
        fn count_attempt(&mut self) -> Option<AttemptBudgetObservation>;
        fn consume_attempt(&mut self) -> Option<AttemptConsumptionObservation>;
        fn query_account(&mut self) -> Option<ProofAccountObservation>;
        fn verify_proof(&mut self) -> Option<ProofObservation>;
        fn issue_grant(&mut self, permit: ProofGrantPermit) -> Option<GrantStoreObservation>;
    }
}

/// The proof-recovery interpreter body, shared verbatim by
/// [`run_possession_recover`] and the async handler.
#[macro_export]
macro_rules! possession_recover_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::possession_driver::{
            begin_proof_recover as __begin, step_proof_recover as __step, ProofRecoverEffect as __E,
            ProofRecoverEvent as __V,
        };
        let mut transition = __begin();
        let mut aborted = false;
        for _ in 0..$crate::possession_interpreter::POSSESSION_RECOVER_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::possession_interpreter::proof_recover_transition_is_sound(transition)
            });
            if !aborted {
                transition = match transition.effect {
                    __E::CountAttempt => match $io.count_attempt()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AttemptCounted(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::ConsumeAttempt => match $io.consume_attempt()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AttemptConsumed(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::QueryAccount => match $io.query_account()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AccountObserved(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::VerifyProof => match $io.verify_proof()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::ProofObserved(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::IssueGrant(permit) => match $io.issue_grant(permit)$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::GrantStored(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    // The driver has decided: perform nothing, keep the verdict.
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

/// The synchronous expansion of [`possession_recover_interpreter!`].
pub fn run_possession_recover<Io: PossessionRecoverIo>(
    io: &mut Io,
) -> Option<ProofRecoverTransition> {
    crate::possession_recover_interpreter!(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::possession_driver::{
        InitiateEvent, ProofRecoverEvent,
        begin_initiation, begin_proof_recover, step_initiation, step_proof_recover,
        CommitmentObservation, ProofRecoverFailure,
    };

    // ── Initiation ──────────────────────────────────────────────────────────

    struct ScriptedInitiation {
        /// Observation kind per call (0 = start, 1 = reject, 2 = store lost).
        script: Vec<u8>,
        calls: Vec<InitiateEffect>,
        events: Vec<InitiateEvent>,
        abort_at: Option<usize>,
    }

    impl PossessionInitiationIo for ScriptedInitiation {
        fn observe(&mut self) -> Option<InitiateObservation> {
            let index = self.calls.len();
            self.calls.push(InitiateEffect::Observe);
            if self.abort_at == Some(index) {
                return None;
            }
            let kind = self.script.get(index).copied().unwrap_or(0);
            let observation = InitiateObservation {
                account_present: true,
                share_present: true,
                commitment: CommitmentObservation::Present { len: 32 },
                rotation_active: false,
                attempt_id_fresh: kind != 1,
                ttl_secs: 300,
            };
            self.events.push(InitiateEvent::Observed(observation));
            Some(observation)
        }

        fn store_challenge(&mut self) -> Option<ChallengeStoreObservation> {
            let index = self.calls.len();
            self.calls.push(InitiateEffect::StoreChallenge);
            if self.abort_at == Some(index) {
                return None;
            }
            let observation = if self.script.get(index).copied().unwrap_or(0) == 2 {
                ChallengeStoreObservation::Lost
            } else {
                ChallengeStoreObservation::Stored
            };
            self.events.push(InitiateEvent::Stored(observation));
            Some(observation)
        }
    }

    fn check_initiation(script: Vec<u8>, abort_at: Option<usize>) -> Option<InitiateEffect> {
        let mut io = ScriptedInitiation { script, calls: vec![], events: vec![], abort_at };
        let result = run_possession_initiation(&mut io);
        let mut t = begin_initiation();
        for (index, call) in io.calls.iter().enumerate() {
            if abort_at == Some(index) {
                break;
            }
            assert_eq!(*call, t.effect, "call was not the emitted effect");
            assert!(!initiation_effect_is_terminal(t.effect));
            t = step_initiation(t.driver, io.events[index]);
        }
        assert!(io.calls.len() <= POSSESSION_INITIATION_MAX_EFFECTS);
        if abort_at.is_some() {
            assert!(result.is_none());
            return None;
        }
        let result = result.expect("no abort, so a verdict must be reached");
        assert_eq!(t, result);
        assert!(initiation_effect_is_terminal(result.effect));
        Some(result.effect)
    }

    #[test]
    fn initiation_performs_exactly_the_driver_effects() {
        assert_eq!(check_initiation(vec![0, 0, 0], None), Some(InitiateEffect::Complete));
        assert!(matches!(
            check_initiation(vec![1, 0, 0], None),
            Some(InitiateEffect::Fail(_))
        ));
        assert!(matches!(
            check_initiation(vec![0, 2, 0], None),
            Some(InitiateEffect::Fail(_))
        ));
        assert_eq!(check_initiation(vec![0, 0, 0], Some(0)), None);
        assert_eq!(check_initiation(vec![0, 0, 0], Some(1)), None);
    }

    // ── Proof recovery ──────────────────────────────────────────────────────

    struct ScriptedRecover {
        /// Observation kinds per call: budget 1 = limited, consumption 1 =
        /// missing, account 1 = absent, proof 1 = rejected, grant 1 = failed.
        script: Vec<u8>,
        calls: Vec<ProofRecoverEffect>,
        events: Vec<ProofRecoverEvent>,
        abort_at: Option<usize>,
    }

    impl ScriptedRecover {
        fn record(&mut self, effect: ProofRecoverEffect) -> Option<u8> {
            let index = self.calls.len();
            self.calls.push(effect);
            if self.abort_at == Some(index) {
                return None;
            }
            Some(self.script.get(index).copied().unwrap_or(0))
        }
    }

    impl PossessionRecoverIo for ScriptedRecover {
        fn count_attempt(&mut self) -> Option<AttemptBudgetObservation> {
            let kind = self.record(ProofRecoverEffect::CountAttempt)? % 2;
            let observation = if kind == 0 {
                AttemptBudgetObservation::Admitted
            } else {
                AttemptBudgetObservation::Limited
            };
            self.events.push(ProofRecoverEvent::AttemptCounted(observation));
            Some(observation)
        }

        fn consume_attempt(&mut self) -> Option<AttemptConsumptionObservation> {
            let kind = self.record(ProofRecoverEffect::ConsumeAttempt)? % 2;
            let observation = if kind == 0 {
                AttemptConsumptionObservation::Present {
                    user_matches: true,
                    attempt_matches: true,
                    key_epoch: 4,
                }
            } else {
                AttemptConsumptionObservation::Missing
            };
            self.events
                .push(ProofRecoverEvent::AttemptConsumed(observation));
            Some(observation)
        }

        fn query_account(&mut self) -> Option<ProofAccountObservation> {
            let kind = self.record(ProofRecoverEffect::QueryAccount)? % 2;
            let observation = if kind == 0 {
                ProofAccountObservation {
                    account_present: true,
                    account_epoch_active: true,
                    commitment: CommitmentObservation::Present { len: 32 },
                    stored_epoch: Some(4),
                }
            } else {
                ProofAccountObservation {
                    account_present: false,
                    account_epoch_active: false,
                    commitment: CommitmentObservation::Missing,
                    stored_epoch: None,
                }
            };
            self.events
                .push(ProofRecoverEvent::AccountObserved(observation));
            Some(observation)
        }

        fn verify_proof(&mut self) -> Option<ProofObservation> {
            let kind = self.record(ProofRecoverEffect::VerifyProof)? % 2;
            let observation = ProofObservation { verified: kind == 0 };
            self.events.push(ProofRecoverEvent::ProofObserved(observation));
            Some(observation)
        }

        fn issue_grant(&mut self, permit: ProofGrantPermit) -> Option<GrantStoreObservation> {
            assert_eq!(permit.epoch, 4);
            let kind = self.record(ProofRecoverEffect::IssueGrant(permit))? % 2;
            let observation = if kind == 0 {
                GrantStoreObservation::Stored
            } else {
                GrantStoreObservation::Failed
            };
            self.events.push(ProofRecoverEvent::GrantStored(observation));
            Some(observation)
        }
    }

    fn check_recover(script: Vec<u8>, abort_at: Option<usize>) -> Option<ProofRecoverEffect> {
        let mut io = ScriptedRecover { script, calls: vec![], events: vec![], abort_at };
        let result = run_possession_recover(&mut io);
        let mut t = begin_proof_recover();
        for (index, call) in io.calls.iter().enumerate() {
            if abort_at == Some(index) {
                break;
            }
            assert_eq!(*call, t.effect, "call was not the emitted effect");
            assert!(!proof_recover_effect_is_terminal(t.effect));
            t = step_proof_recover(t.driver, io.events[index]);
        }
        assert!(io.calls.len() <= POSSESSION_RECOVER_MAX_EFFECTS);
        if abort_at.is_some() {
            assert!(result.is_none());
            return None;
        }
        let result = result.expect("no abort, so a verdict must be reached");
        assert_eq!(t, result);
        assert!(proof_recover_effect_is_terminal(result.effect));
        Some(result.effect)
    }

    #[test]
    fn recover_performs_exactly_the_driver_effects_for_every_outcome() {
        assert_eq!(
            check_recover(vec![0, 0, 0, 0, 0], None),
            Some(ProofRecoverEffect::Complete)
        );
        assert!(matches!(
            check_recover(vec![1, 0, 0, 0, 0], None),
            Some(ProofRecoverEffect::Fail(
                ProofRecoverFailure::AttemptLimited
            ))
        ));
        assert!(matches!(
            check_recover(vec![0, 1, 0, 0, 0], None),
            Some(ProofRecoverEffect::Fail(
                ProofRecoverFailure::AttemptMissing
            ))
        ));
        assert!(matches!(
            check_recover(vec![0, 0, 1, 0, 0], None),
            Some(ProofRecoverEffect::Fail(
                ProofRecoverFailure::AccountAbsent
            ))
        ));
        assert!(matches!(
            check_recover(vec![0, 0, 0, 1, 0], None),
            Some(ProofRecoverEffect::Fail(
                ProofRecoverFailure::ProofRejected
            ))
        ));
        assert!(matches!(
            check_recover(vec![0, 0, 0, 0, 1], None),
            Some(ProofRecoverEffect::Fail(
                ProofRecoverFailure::GrantStorage
            ))
        ));
        for position in 0..5 {
            assert_eq!(check_recover(vec![0; 5], Some(position)), None);
        }
    }
}
