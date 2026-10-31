//! The four loops that connect the WebAuthn recovery handlers to their
//! drivers.
//!
//! `POST /recovery/register/start`, `POST /recovery/register/finish`,
//! `POST /recovery/initiate` and `POST /recovery/recover` do not call their
//! drivers by hand. Each handler expands one of the macros below; this module
//! expands the same text into one synchronous `run_*` function per request,
//! which hax extracts and F* checks.
//!
//! For every executor implementation the proofs show that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and returns the observation kind that
//!   effect expects (including the effect's permit argument);
//! - a failed effect stops the loop before any later effect, and the handler
//!   renders the recorded error unchanged;
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is the driver's `run_*_from_begin` over the observations
//!   the executor actually returned, so every per-request WebAuthn theorem
//!   holds for the real handler.
//!
//! The server's expansions differ only by `.await` after each executor call.

use crate::webauthn_driver::{
    AssertionObservation, AttemptBudgetObservation, AuthAccountObservation,
    AuthAttemptConsumptionObservation, AuthFinishContextObservation, AuthFinishEffect,
    AuthFinishGrantPermit, AuthFinishTransition, AuthStartEffect, AuthStartObservation,
    AuthStartTransition, CeremonyStartObservation,
    ChallengeStoreObservation, CredentialPersistObservation, CredentialUniquenessObservation,
    CredentialUpdateStoreObservation, GrantStoreObservation, RegistrationEffect,
    RegistrationStartEffect, RegistrationStartObservation, RegistrationStartTransition,
    RegistrationStateObservation,
    RegistrationTransition, RegistrationVerificationObservation, ShareDecodeObservation,
};

use crate::interpreter_support::executor_trait;

// ── Registration start ──────────────────────────────────────────────────────

/// Most effects one registration start performs: registration_start_observe, start the ceremony,
/// store the state, verdict.
pub const REGISTRATION_START_MAX_EFFECTS: usize = 3;

pub fn registration_start_effect_is_terminal(effect: RegistrationStartEffect) -> bool {
    matches!(
        effect,
        RegistrationStartEffect::Complete | RegistrationStartEffect::Fail(_) | RegistrationStartEffect::Idle
    )
}

pub fn registration_start_transition_is_sound(transition: RegistrationStartTransition) -> bool {
    crate::webauthn_driver::registration_start_state_is_sound(transition.driver)
        && crate::webauthn_driver::registration_start_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

executor_trait! {
    /// The I/O behind each non-terminal registration-start effect. `None`
    /// aborts the request with the error the executor recorded.
    pub trait RegistrationStartIo {
        fn registration_start_observe(&mut self) -> Option<RegistrationStartObservation>;
        fn registration_start_ceremony(&mut self) -> Option<CeremonyStartObservation>;
        fn registration_start_store(&mut self) -> Option<ChallengeStoreObservation>;
    }
}

#[macro_export]
macro_rules! registration_start_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::webauthn_driver::{
            begin_registration_start as __begin, step_registration_start as __step,
            RegistrationStartEffect as __E, RegistrationStartEvent as __V,
        };
        let mut transition = __begin();
        let mut aborted = false;
        for _ in 0..$crate::webauthn_interpreter::REGISTRATION_START_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::webauthn_interpreter::registration_start_transition_is_sound(transition)
            });
            if !aborted {
                transition = match transition.effect {
                    __E::Observe => match $io.registration_start_observe()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Observed(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::StartCeremony => match $io.registration_start_ceremony()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::CeremonyStarted(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::StoreState => match $io.registration_start_store()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Stored(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

pub fn run_registration_start<Io: RegistrationStartIo>(
    io: &mut Io,
) -> Option<RegistrationStartTransition> {
    crate::registration_start_interpreter!(io)
}

// ── Registration finish ─────────────────────────────────────────────────────

/// Most effects one registration finish performs: count, consume, verify, look
/// up uniqueness, persist, verdict.
pub const REGISTRATION_MAX_EFFECTS: usize = 5;

pub fn registration_effect_is_terminal(effect: RegistrationEffect) -> bool {
    matches!(
        effect,
        RegistrationEffect::Complete | RegistrationEffect::Fail(_) | RegistrationEffect::Idle
    )
}

pub fn registration_transition_is_sound(transition: RegistrationTransition) -> bool {
    crate::webauthn_driver::registration_state_is_sound(transition.driver)
        && crate::webauthn_driver::registration_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

executor_trait! {
    /// The I/O behind each non-terminal registration-finish effect.
    pub trait RegistrationIo {
        fn registration_count_attempt(&mut self) -> Option<AttemptBudgetObservation>;
        fn registration_consume_state(&mut self) -> Option<RegistrationStateObservation>;
        fn registration_verify(&mut self) -> Option<RegistrationVerificationObservation>;
        fn registration_check_uniqueness(&mut self) -> Option<CredentialUniquenessObservation>;
        fn registration_persist(&mut self) -> Option<CredentialPersistObservation>;
    }
}

#[macro_export]
macro_rules! registration_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::webauthn_driver::{
            begin_registration as __begin, step_registration as __step, RegistrationEffect as __E,
            RegistrationEvent as __V,
        };
        let mut transition = __begin();
        let mut aborted = false;
        for _ in 0..$crate::webauthn_interpreter::REGISTRATION_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::webauthn_interpreter::registration_transition_is_sound(transition)
            });
            if !aborted {
                transition = match transition.effect {
                    __E::CountAttempt => match $io.registration_count_attempt()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AttemptCounted(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::ConsumeState => match $io.registration_consume_state()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::StateConsumed(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::VerifyRegistration => match $io.registration_verify()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::RegistrationVerified(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::CheckCredentialUniqueness => {
                        match $io.registration_check_uniqueness()$(.$aw)? {
                            Some(observation) => {
                                __step(transition.driver, __V::CredentialLookedUp(observation))
                            }
                            None => {
                                aborted = true;
                                transition
                            }
                        }
                    }
                    __E::PersistCredential => match $io.registration_persist()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::CredentialPersisted(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

pub fn run_registration<Io: RegistrationIo>(io: &mut Io) -> Option<RegistrationTransition> {
    crate::registration_interpreter!(io)
}

// ── Authentication start ────────────────────────────────────────────────────

/// Most effects one authentication start performs: auth_start_observe, start the
/// ceremony, store the challenge, verdict.
pub const AUTH_START_MAX_EFFECTS: usize = 3;

pub fn auth_start_effect_is_terminal(effect: AuthStartEffect) -> bool {
    matches!(
        effect,
        AuthStartEffect::Complete | AuthStartEffect::Fail(_) | AuthStartEffect::Idle
    )
}

pub fn auth_start_transition_is_sound(transition: AuthStartTransition) -> bool {
    crate::webauthn_driver::auth_start_state_is_sound(transition.driver)
        && crate::webauthn_driver::auth_start_effect_is_sound(transition.driver, transition.effect)
}

executor_trait! {
    /// The I/O behind each non-terminal authentication-start effect.
    pub trait AuthStartIo {
        fn auth_start_observe(&mut self) -> Option<AuthStartObservation>;
        fn auth_start_ceremony(&mut self) -> Option<CeremonyStartObservation>;
        fn auth_start_store(&mut self) -> Option<ChallengeStoreObservation>;
    }
}

#[macro_export]
macro_rules! auth_start_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::webauthn_driver::{
            begin_auth_start as __begin, step_auth_start as __step, AuthStartEffect as __E,
            AuthStartEvent as __V,
        };
        let mut transition = __begin();
        let mut aborted = false;
        for _ in 0..$crate::webauthn_interpreter::AUTH_START_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::webauthn_interpreter::auth_start_transition_is_sound(transition)
            });
            if !aborted {
                transition = match transition.effect {
                    __E::Observe => match $io.auth_start_observe()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Observed(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::StartCeremony => match $io.auth_start_ceremony()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::CeremonyStarted(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::StoreChallenge => match $io.auth_start_store()$(.$aw)? {
                        Some(observation) => __step(transition.driver, __V::Stored(observation)),
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

pub fn run_auth_start<Io: AuthStartIo>(io: &mut Io) -> Option<AuthStartTransition> {
    crate::auth_start_interpreter!(io)
}

// ── Authentication finish ───────────────────────────────────────────────────

/// Most effects one authentication finish performs: count, observe context,
/// consume, verify, update, query, release, store, verdict.
pub const AUTH_FINISH_MAX_EFFECTS: usize = 8;

pub fn auth_finish_effect_is_terminal(effect: AuthFinishEffect) -> bool {
    matches!(
        effect,
        AuthFinishEffect::Complete | AuthFinishEffect::Fail(_) | AuthFinishEffect::Idle
    )
}

pub fn auth_finish_transition_is_sound(transition: AuthFinishTransition) -> bool {
    crate::webauthn_driver::auth_finish_state_is_sound(transition.driver)
        && crate::webauthn_driver::auth_finish_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

executor_trait! {
    /// The I/O behind each non-terminal authentication-finish effect.
    pub trait AuthFinishIo {
        fn auth_finish_count(&mut self) -> Option<AttemptBudgetObservation>;
        fn auth_finish_context(&mut self) -> Option<AuthFinishContextObservation>;
        fn auth_finish_consume(&mut self) -> Option<AuthAttemptConsumptionObservation>;
        fn auth_finish_verify(&mut self) -> Option<AssertionObservation>;
        fn auth_finish_update(&mut self) -> Option<CredentialUpdateStoreObservation>;
        fn auth_finish_account(&mut self) -> Option<AuthAccountObservation>;
        fn auth_finish_release(&mut self, permit: AuthFinishGrantPermit)
            -> Option<ShareDecodeObservation>;
        fn auth_finish_store_grant(&mut self) -> Option<GrantStoreObservation>;
    }
}

#[macro_export]
macro_rules! auth_finish_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::webauthn_driver::{
            begin_auth_finish as __begin, step_auth_finish as __step, AuthFinishEffect as __E,
            AuthFinishEvent as __V,
        };
        let mut transition = __begin();
        let mut aborted = false;
        for _ in 0..$crate::webauthn_interpreter::AUTH_FINISH_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::webauthn_interpreter::auth_finish_transition_is_sound(transition)
            });
            if !aborted {
                transition = match transition.effect {
                    __E::CountAttempt => match $io.auth_finish_count()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AttemptCounted(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::ObserveContext => match $io.auth_finish_context()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::ContextObserved(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::ConsumeAttempt => match $io.auth_finish_consume()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AttemptConsumed(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::VerifyAssertion => match $io.auth_finish_verify()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AssertionObserved(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::UpdateCredential => match $io.auth_finish_update()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::CredentialUpdated(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::QueryAccount => match $io.auth_finish_account()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::AccountObserved(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::ReleaseGrant(permit) => match $io.auth_finish_release(permit)$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::ShareObserved(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::StoreGrant => match $io.auth_finish_store_grant()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::GrantStored(observation))
                        }
                        None => { aborted = true; transition }
                    },
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

pub fn run_auth_finish<Io: AuthFinishIo>(io: &mut Io) -> Option<AuthFinishTransition> {
    crate::auth_finish_interpreter!(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn_driver::{
        begin_auth_finish, begin_auth_start, begin_registration, begin_registration_start,
        AuthFinishEvent, AuthStartEvent, RegistrationEvent, RegistrationStartEvent,
        step_auth_finish, step_auth_start, step_registration, step_registration_start,
        StoredCredentialObservation,
    };

    /// One scripted executor for all four traits: `script[n]` selects the
    /// outcome kind of the n-th call.
    struct Scripted {
        script: Vec<u8>,
        calls: Vec<String>,
        abort_at: Option<usize>,
    }

    impl Scripted {
        fn new(script: Vec<u8>, abort_at: Option<usize>) -> Self {
            Self { script, calls: vec![], abort_at }
        }
        fn record(&mut self, name: &str) -> Option<u8> {
            let index = self.calls.len();
            self.calls.push(name.to_string());
            if self.abort_at == Some(index) {
                return None;
            }
            Some(self.script.get(index).copied().unwrap_or(0))
        }
    }

    impl RegistrationStartIo for Scripted {
        fn registration_start_observe(&mut self) -> Option<RegistrationStartObservation> {
            let kind = self.record("registration_start_observe")? % 2;
            let observation = RegistrationStartObservation {
                account_present: true,
                credential: if kind == 0 {
                    StoredCredentialObservation::Missing
                } else {
                    StoredCredentialObservation::Corrupt
                },
            };
            Some(observation)
        }
        fn registration_start_ceremony(&mut self) -> Option<CeremonyStartObservation> {
            let kind = self.record("ceremony")? % 2;
            let observation = if kind == 0 {
                CeremonyStartObservation::Started
            } else {
                CeremonyStartObservation::Failed
            };
            Some(observation)
        }
        fn registration_start_store(&mut self) -> Option<ChallengeStoreObservation> {
            let kind = self.record("store")? % 2;
            let observation = if kind == 0 {
                ChallengeStoreObservation::Stored
            } else {
                ChallengeStoreObservation::StorageFailed
            };
            Some(observation)
        }
    }

    #[test]
    fn registration_start_performs_exactly_the_driver_effects() {
        let cases: [(&[u8], bool); 4] = [
            (&[0, 0, 0], true),
            (&[1, 0, 0], false),
            (&[0, 1, 0], false),
            (&[0, 0, 1], false),
        ];
        for (script, completes) in cases {
            let mut io = Scripted::new(script.to_vec(), None);
            let result = run_registration_start(&mut io).expect("no abort");
            let mut t = begin_registration_start();
            for name in &io.calls {
                let expected = match t.effect {
                    RegistrationStartEffect::Observe => "registration_start_observe",
                    RegistrationStartEffect::StartCeremony => "ceremony",
                    RegistrationStartEffect::StoreState => "store",
                    _ => panic!("call after the verdict"),
                };
                assert_eq!(name, expected, "call was not the emitted effect");
                t = match t.effect {
                    RegistrationStartEffect::Observe => step_registration_start(
                        t.driver,
                        RegistrationStartEvent::Observed(if script[0] == 0 {
                            RegistrationStartObservation {
                                account_present: true,
                                credential: StoredCredentialObservation::Missing,
                            }
                        } else {
                            RegistrationStartObservation {
                                account_present: true,
                                credential: StoredCredentialObservation::Corrupt,
                            }
                        }),
                    ),
                    RegistrationStartEffect::StartCeremony => step_registration_start(
                        t.driver,
                        RegistrationStartEvent::CeremonyStarted(if script[1] == 0 {
                            CeremonyStartObservation::Started
                        } else {
                            CeremonyStartObservation::Failed
                        }),
                    ),
                    _ => step_registration_start(
                        t.driver,
                        RegistrationStartEvent::Stored(if script[2] == 0 {
                            ChallengeStoreObservation::Stored
                        } else {
                            ChallengeStoreObservation::StorageFailed
                        }),
                    ),
                };
            }
            assert_eq!(t, result);
            assert!(registration_start_effect_is_terminal(result.effect));
            assert_eq!(matches!(result.effect, RegistrationStartEffect::Complete), completes);
        }
        for position in 0..3 {
            let mut io = Scripted::new(vec![0; 3], Some(position));
            assert!(run_registration_start(&mut io).is_none());
        }
    }

    impl RegistrationIo for Scripted {
        fn registration_count_attempt(&mut self) -> Option<AttemptBudgetObservation> {
            let kind = self.record("count")? % 2;
            let observation = if kind == 0 {
                AttemptBudgetObservation::Admitted
            } else {
                AttemptBudgetObservation::Limited
            };
            Some(observation)
        }
        fn registration_consume_state(&mut self) -> Option<RegistrationStateObservation> {
            let observation = match self.record("consume")? % 3 {
                0 => RegistrationStateObservation::Present,
                1 => RegistrationStateObservation::Missing,
                _ => RegistrationStateObservation::Corrupt,
            };
            Some(observation)
        }
        fn registration_verify(&mut self) -> Option<RegistrationVerificationObservation> {
            let kind = self.record("verify")? % 2;
            let observation = RegistrationVerificationObservation {
                credential_valid: kind == 0,
            };
            Some(observation)
        }
        fn registration_check_uniqueness(&mut self) -> Option<CredentialUniquenessObservation> {
            let observation = match self.record("unique")? % 3 {
                0 => CredentialUniquenessObservation::Unique,
                1 => CredentialUniquenessObservation::RegisteredElsewhere,
                _ => CredentialUniquenessObservation::LookupFailed,
            };
            Some(observation)
        }
        fn registration_persist(&mut self) -> Option<CredentialPersistObservation> {
            let observation = match self.record("persist")? % 4 {
                0 => CredentialPersistObservation::Persisted,
                1 => CredentialPersistObservation::AccountGone,
                2 => CredentialPersistObservation::EncodingFailed,
                _ => CredentialPersistObservation::StorageFailed,
            };
            Some(observation)
        }
    }

    #[test]
    fn registration_performs_exactly_the_driver_effects() {
        let mut io = Scripted::new(vec![0; 5], None);
        let result = run_registration(&mut io).expect("no abort");
        assert_eq!(result.effect, RegistrationEffect::Complete);
        assert_eq!(io.calls.len(), 5);
        let mut t = begin_registration();
        let events = [
            RegistrationEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
            RegistrationEvent::StateConsumed(RegistrationStateObservation::Present),
            RegistrationEvent::RegistrationVerified(RegistrationVerificationObservation {
                credential_valid: true,
            }),
            RegistrationEvent::CredentialLookedUp(CredentialUniquenessObservation::Unique),
            RegistrationEvent::CredentialPersisted(CredentialPersistObservation::Persisted),
        ];
        for event in events {
            assert!(!registration_effect_is_terminal(t.effect));
            t = step_registration(t.driver, event);
        }
        assert_eq!(t, result);
        for position in 0..5 {
            let mut io = Scripted::new(vec![0; 5], Some(position));
            assert!(run_registration(&mut io).is_none());
        }
    }

    impl AuthStartIo for Scripted {
        fn auth_start_observe(&mut self) -> Option<AuthStartObservation> {
            let kind = self.record("auth_start_observe")? % 2;
            let observation = AuthStartObservation {
                account_present: true,
                share_present: true,
                credential: if kind == 0 {
                    StoredCredentialObservation::Present
                } else {
                    StoredCredentialObservation::Missing
                },
                attempt_id_fresh: true,
                ttl_secs: 300,
            };
            Some(observation)
        }
        fn auth_start_ceremony(&mut self) -> Option<CeremonyStartObservation> {
            let kind = self.record("ceremony")? % 2;
            let observation = if kind == 0 {
                CeremonyStartObservation::Started
            } else {
                CeremonyStartObservation::Failed
            };
            Some(observation)
        }
        fn auth_start_store(&mut self) -> Option<ChallengeStoreObservation> {
            let kind = self.record("store")? % 3;
            let observation = match kind {
                0 => ChallengeStoreObservation::Stored,
                1 => ChallengeStoreObservation::Lost,
                _ => ChallengeStoreObservation::StorageFailed,
            };
            Some(observation)
        }
    }

    #[test]
    fn auth_start_performs_exactly_the_driver_effects() {
        let cases: [(&[u8], bool); 4] = [
            (&[0, 0, 0], true),
            (&[1, 0, 0], false),
            (&[0, 1, 0], false),
            (&[0, 0, 1], false),
        ];
        for (script, completes) in cases {
            let mut io = Scripted::new(script.to_vec(), None);
            let result = run_auth_start(&mut io).expect("no abort");
            let mut t = begin_auth_start();
            for name in &io.calls {
                let expected = match t.effect {
                    AuthStartEffect::Observe => "auth_start_observe",
                    AuthStartEffect::StartCeremony => "ceremony",
                    AuthStartEffect::StoreChallenge => "store",
                    _ => panic!("call after the verdict"),
                };
                assert_eq!(name, expected, "call was not the emitted effect");
                t = match t.effect {
                    AuthStartEffect::Observe => step_auth_start(
                        t.driver,
                        AuthStartEvent::Observed(AuthStartObservation {
                            account_present: true,
                            share_present: true,
                            credential: if script[0] == 0 {
                                StoredCredentialObservation::Present
                            } else {
                                StoredCredentialObservation::Missing
                            },
                            attempt_id_fresh: true,
                            ttl_secs: 300,
                        }),
                    ),
                    AuthStartEffect::StartCeremony => step_auth_start(
                        t.driver,
                        AuthStartEvent::CeremonyStarted(if script[1] == 0 {
                            CeremonyStartObservation::Started
                        } else {
                            CeremonyStartObservation::Failed
                        }),
                    ),
                    _ => step_auth_start(
                        t.driver,
                        AuthStartEvent::Stored(match script[2] {
                            0 => ChallengeStoreObservation::Stored,
                            1 => ChallengeStoreObservation::Lost,
                            _ => ChallengeStoreObservation::StorageFailed,
                        }),
                    ),
                };
            }
            assert_eq!(t, result);
            assert!(auth_start_effect_is_terminal(result.effect));
            assert_eq!(matches!(result.effect, AuthStartEffect::Complete), completes);
        }
        for position in 0..3 {
            let mut io = Scripted::new(vec![0; 3], Some(position));
            assert!(run_auth_start(&mut io).is_none());
        }
    }

    impl AuthFinishIo for Scripted {
        fn auth_finish_count(&mut self) -> Option<AttemptBudgetObservation> {
            let kind = self.record("count")? % 2;
            let observation = if kind == 0 {
                AttemptBudgetObservation::Admitted
            } else {
                AttemptBudgetObservation::Limited
            };
            Some(observation)
        }
        fn auth_finish_context(&mut self) -> Option<AuthFinishContextObservation> {
            let kind = self.record("context")? % 2;
            let observation = AuthFinishContextObservation {
                account_present: true,
                share_present: true,
                credential: if kind == 0 {
                    StoredCredentialObservation::Present
                } else {
                    StoredCredentialObservation::Missing
                },
                attempt_id_present: true,
            };
            Some(observation)
        }
        fn auth_finish_consume(&mut self) -> Option<AuthAttemptConsumptionObservation> {
            let kind = self.record("consume")? % 3;
            let observation = match kind {
                0 => AuthAttemptConsumptionObservation::Present {
                    user_matches: true,
                    attempt_matches: true,
                    credential_matches: true,
                },
                1 => AuthAttemptConsumptionObservation::Missing,
                _ => AuthAttemptConsumptionObservation::Corrupt,
            };
            Some(observation)
        }
        fn auth_finish_verify(&mut self) -> Option<AssertionObservation> {
            let kind = self.record("assert")? % 4;
            let observation = match kind {
                0 | 3 => AssertionObservation {
                    assertion_valid: true,
                    user_verified: true,
                    credential_matches: true,
                    needs_update: kind == 3,
                },
                1 => AssertionObservation {
                    assertion_valid: false,
                    user_verified: false,
                    credential_matches: false,
                    needs_update: false,
                },
                _ => AssertionObservation {
                    assertion_valid: true,
                    user_verified: false,
                    credential_matches: true,
                    needs_update: false,
                },
            };
            Some(observation)
        }
        fn auth_finish_update(&mut self) -> Option<CredentialUpdateStoreObservation> {
            let kind = self.record("update")? % 2;
            let observation = if kind == 0 {
                CredentialUpdateStoreObservation::Updated
            } else {
                CredentialUpdateStoreObservation::Changed
            };
            Some(observation)
        }
        fn auth_finish_account(&mut self) -> Option<AuthAccountObservation> {
            let kind = self.record("account")? % 2;
            let observation = if kind == 0 {
                AuthAccountObservation {
                    account_present: true,
                    account_epoch_active: true,
                    share_present: true,
                    stored_credential_matches: true,
                    stored_epoch: Some(4),
                }
            } else {
                AuthAccountObservation {
                    account_present: false,
                    account_epoch_active: false,
                    share_present: false,
                    stored_credential_matches: false,
                    stored_epoch: None,
                }
            };
            Some(observation)
        }
        fn auth_finish_release(
            &mut self,
            permit: AuthFinishGrantPermit,
        ) -> Option<ShareDecodeObservation> {
            assert_eq!(permit.epoch, 4);
            let kind = self.record("release")? % 2;
            let observation = if kind == 0 {
                ShareDecodeObservation::Decoded
            } else {
                ShareDecodeObservation::Corrupt
            };
            Some(observation)
        }
        fn auth_finish_store_grant(&mut self) -> Option<GrantStoreObservation> {
            let kind = self.record("grant")? % 2;
            let observation = if kind == 0 {
                GrantStoreObservation::Stored
            } else {
                GrantStoreObservation::Failed
            };
            Some(observation)
        }
    }

    #[test]
    fn auth_finish_performs_exactly_the_driver_effects() {
        // Success, then one failure kind at each reachable position.
        let mut io = Scripted::new(vec![0, 0, 0, 3, 0, 0, 0, 0], None);
        let result = run_auth_finish(&mut io).expect("no abort");
        assert_eq!(result.effect, AuthFinishEffect::Complete);
        assert_eq!(io.calls.len(), 8, "calls: {:?}", io.calls);
        let mut t = begin_auth_finish();
        let events = [
            AuthFinishEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
            AuthFinishEvent::ContextObserved(AuthFinishContextObservation {
                account_present: true,
                share_present: true,
                credential: StoredCredentialObservation::Present,
                attempt_id_present: true,
            }),
            AuthFinishEvent::AttemptConsumed(AuthAttemptConsumptionObservation::Present {
                user_matches: true,
                attempt_matches: true,
                credential_matches: true,
            }),
            AuthFinishEvent::AssertionObserved(AssertionObservation {
                assertion_valid: true,
                user_verified: true,
                credential_matches: true,
                needs_update: true,
            }),
            AuthFinishEvent::CredentialUpdated(CredentialUpdateStoreObservation::Updated),
            AuthFinishEvent::AccountObserved(AuthAccountObservation {
                account_present: true,
                account_epoch_active: true,
                share_present: true,
                stored_credential_matches: true,
                stored_epoch: Some(4),
            }),
            AuthFinishEvent::ShareObserved(ShareDecodeObservation::Decoded),
            AuthFinishEvent::GrantStored(GrantStoreObservation::Stored),
        ];
        for event in events {
            assert!(!auth_finish_effect_is_terminal(t.effect));
            t = step_auth_finish(t.driver, event);
        }
        assert_eq!(t, result);

        for position in 0..8 {
            let mut script = vec![0u8, 0, 0, 3, 0, 0, 0, 0];
            script[position] = 1;
            let mut io = Scripted::new(script, None);
            let result = run_auth_finish(&mut io).expect("no abort");
            assert!(auth_finish_effect_is_terminal(result.effect));
        }
        for position in 0..8 {
            let mut io = Scripted::new(vec![0, 0, 0, 3, 0, 0, 0, 0], Some(position));
            assert!(run_auth_finish(&mut io).is_none());
        }
    }
}
