//! The one loop that connects `POST /device/enroll` to its driver.
//!
//! The handler does not call the enrollment driver by hand. It expands
//! [`enroll_interpreter!`](crate::enroll_interpreter), the same macro this
//! module expands into the synchronous [`run_enroll`]. hax extracts
//! `run_enroll` and F* proves, for every [`EnrollIo`] implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects (the types allow nothing else);
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is `run_from_enroll evs` for the observations the
//!   executor actually returned, so every per-request enrollment theorem holds
//!   for the real handler.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::enroll_driver::{
    AccountObservation, ChallengeObservation, DeviceObservation, EnrollEffect, EnrollTransition,
    EnrollmentObservation, InsertObservation,
};

/// Most effects one request performs: consume the challenge, check the device,
/// prepare the key material, check the epoch/rekey permit, insert the row.
pub const ENROLL_MAX_EFFECTS: usize = 5;

/// The driver has decided: nothing more may be performed.
pub fn enroll_effect_is_terminal(effect: EnrollEffect) -> bool {
    matches!(
        effect,
        EnrollEffect::Complete | EnrollEffect::Fail(_) | EnrollEffect::Idle
    )
}

/// Declares an executor trait from one list of method signatures. Under hax
/// every method gets `requires(true)` (the proof assumes nothing about the
/// executor); ordinary builds get the same trait without the attributes, so
/// `hax-lib` stays a hax-only dependency.
macro_rules! executor_trait {
    (
        $(#[$doc:meta])*
        pub trait $name:ident {
            $(fn $method:ident(&mut self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*
        }
    ) => {
        $(#[$doc])*
        #[cfg(hax)]
        #[hax_lib::attributes]
        pub trait $name {
            $(
                #[hax_lib::requires(true)]
                fn $method(&mut self $(, $arg: $ty)*) -> $ret;
            )*
        }

        $(#[$doc])*
        #[cfg(not(hax))]
        pub trait $name {
            $(fn $method(&mut self $(, $arg: $ty)*) -> $ret;)*
        }
    };
}

executor_trait! {
    /// The I/O behind each non-terminal effect. Each method returns only the
    /// observation its effect expects; the handler keeps the original error in
    /// its own slot.
    pub trait EnrollIo {
        fn consume_challenge(&mut self) -> ChallengeObservation;
        fn check_device(&mut self) -> DeviceObservation;
        fn prepare_enrollment(&mut self) -> EnrollmentObservation;
        fn check_account(&mut self) -> AccountObservation;
        fn insert_device(&mut self) -> InsertObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_enroll`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call. `$start` is the begin transition.
#[macro_export]
macro_rules! enroll_interpreter {
    ($io:ident, $start:expr $(, $aw:ident)?) => {{
        use $crate::enroll_driver::{step as __step, EnrollEffect as __E, EnrollEvent as __V};
        let mut transition = $start;
        for _ in 0..$crate::enroll_interpreter::ENROLL_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::enroll_driver::enroll_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::ConsumeChallenge => __step(
                    transition.driver,
                    __V::ChallengeConsumed($io.consume_challenge()$(.$aw)?),
                ),
                __E::CheckDevice => __step(
                    transition.driver,
                    __V::DeviceChecked($io.check_device()$(.$aw)?),
                ),
                __E::PrepareEnrollment => __step(
                    transition.driver,
                    __V::EnrollmentPrepared($io.prepare_enrollment()$(.$aw)?),
                ),
                __E::CheckAccount => __step(
                    transition.driver,
                    __V::AccountChecked($io.check_account()$(.$aw)?),
                ),
                __E::InsertDevice => __step(
                    transition.driver,
                    __V::DeviceInserted($io.insert_device()$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`enroll_interpreter!`]: the artifact hax
/// extracts and F* checks.
#[cfg_attr(hax, hax_lib::requires(crate::enroll_driver::enroll_state_is_sound(start.driver)))]
pub fn run_enroll<Io: EnrollIo>(io: &mut Io, start: EnrollTransition) -> EnrollTransition {
    crate::enroll_interpreter!(io, start)
}

/// The handler-facing entry point: the driver's begin decision, unchanged.
/// Handlers may not call the driver's `begin_enroll` directly.
pub fn start_enroll() -> EnrollTransition {
    crate::enroll_driver::begin_enroll()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll_driver::{
        begin_enroll, step, EnrollEvent, EnrollFailure, EnrollStage,
    };

    /// Plays a fixed script of outcomes and records every call.
    struct Scripted {
        script: Vec<u8>,
        calls: Vec<EnrollEffect>,
        events: Vec<EnrollEvent>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: EnrollEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
    }

    impl EnrollIo for Scripted {
        fn consume_challenge(&mut self) -> ChallengeObservation {
            let o = [ChallengeObservation::Consumed, ChallengeObservation::Rejected]
                [(self.record(EnrollEffect::ConsumeChallenge) % 2) as usize];
            self.events.push(EnrollEvent::ChallengeConsumed(o));
            o
        }
        fn check_device(&mut self) -> DeviceObservation {
            let o = [
                DeviceObservation::Verified,
                DeviceObservation::Unavailable,
                DeviceObservation::MalformedChallenge,
                DeviceObservation::AuthSignatureRejected,
                DeviceObservation::Error,
            ][(self.record(EnrollEffect::CheckDevice) % 5) as usize];
            self.events.push(EnrollEvent::DeviceChecked(o));
            o
        }
        fn prepare_enrollment(&mut self) -> EnrollmentObservation {
            let o = [
                EnrollmentObservation::Verified,
                EnrollmentObservation::DecodeFailed,
                EnrollmentObservation::EkLengthInvalid,
                EnrollmentObservation::VkLengthInvalid,
                EnrollmentObservation::SignatureLengthInvalid,
                EnrollmentObservation::SignatureRejected,
                EnrollmentObservation::Error,
            ][(self.record(EnrollEffect::PrepareEnrollment) % 7) as usize];
            self.events.push(EnrollEvent::EnrollmentPrepared(o));
            o
        }
        fn check_account(&mut self) -> AccountObservation {
            let o = [
                AccountObservation::Permitted,
                AccountObservation::EpochInvalid,
                AccountObservation::RekeyRejected,
            ][(self.record(EnrollEffect::CheckAccount) % 3) as usize];
            self.events.push(EnrollEvent::AccountChecked(o));
            o
        }
        fn insert_device(&mut self) -> InsertObservation {
            let o = [
                InsertObservation::Inserted,
                InsertObservation::EpochMismatch,
                InsertObservation::Failed,
            ][(self.record(EnrollEffect::InsertDevice) % 3) as usize];
            self.events.push(EnrollEvent::DeviceInserted(o));
            o
        }
    }

    fn check(start: EnrollTransition, script: Vec<u8>) -> EnrollEffect {
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
        };
        let result = run_enroll(&mut io, start);
        let mut t = start;
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!enroll_effect_is_terminal(t.effect));
            t = step(t.driver, *event);
            assert!(crate::enroll_driver::enroll_state_is_sound(t.driver));
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            enroll_effect_is_terminal(result.effect),
            "no verdict within {ENROLL_MAX_EFFECTS} effects"
        );
        assert!(io.calls.len() <= ENROLL_MAX_EFFECTS);
        result.effect
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        let start = begin_enroll();
        assert_eq!(
            check(start, vec![0u8; ENROLL_MAX_EFFECTS]),
            EnrollEffect::Complete
        );
        for position in 0..ENROLL_MAX_EFFECTS {
            for kind in 1..=8u8 {
                let mut script = vec![0u8; ENROLL_MAX_EFFECTS];
                script[position] = kind;
                check(start, script);
            }
        }
    }

    #[test]
    fn a_rejected_challenge_performs_nothing_else() {
        let mut io = Scripted {
            script: vec![1],
            calls: vec![],
            events: vec![],
        };
        let result = run_enroll(&mut io, begin_enroll());
        assert_eq!(io.calls, vec![EnrollEffect::ConsumeChallenge]);
        assert!(matches!(
            result.effect,
            EnrollEffect::Fail(EnrollFailure::ChallengeRejected)
        ));
        assert!(!result.driver.inserted);
    }

    #[test]
    fn an_ambiguous_insert_error_is_terminal() {
        let mut script = vec![0u8; ENROLL_MAX_EFFECTS];
        script[4] = 2;
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
        };
        let result = run_enroll(&mut io, begin_enroll());
        assert_eq!(
            result.effect,
            EnrollEffect::Fail(EnrollFailure::InsertStorage)
        );
        assert!(result.driver.failed && !result.driver.inserted);
        assert_eq!(io.calls.len(), 5);
        assert_eq!(result.driver.stage, EnrollStage::Done);
    }
}
