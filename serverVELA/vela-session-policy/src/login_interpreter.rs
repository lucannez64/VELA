//! The one loop that connects `/auth/verify` to its driver.
//!
//! The handler does not call the driver by hand. It expands
//! [`login_interpreter!`](crate::login_interpreter), the same macro this module
//! expands into the synchronous [`run_login`]. hax extracts `run_login` and F*
//! proves, for every [`LoginIo`] implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects (the types allow nothing else);
//! - the loop stops at the first terminal effect (`Respond`, `Fail`, `Idle`)
//!   and performs nothing after it;
//! - the final driver is `run_from_begin evs` for the observations the executor
//!   actually returned, so every per-request login theorem holds for the real
//!   handler.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly. The `/auth/verify`
//! handler also keeps its pre-driver glue (the per-IP limiter and the backoff
//! precheck) and its success-path `last_active` update before the driver's
//! begin; the update is performed inside the executor's `reset_backoff`, which
//! is the effect that precedes issuance, so the observable order is unchanged.

use crate::login_driver::{
    BackoffResetObservation, ChallengeObservation, DeviceObservation,
    FailureRecordObservation, LoginEffect, TokenIssueObservation,
    TokenTrackObservation, VerifierObservation,
};

/// Most effects one request performs: the challenge take, the device lookup,
/// the verifier, the success-path reset, issuance and the JTI track. The
/// failure-record path replaces the reset, so six turns is the longest path.
pub const LOGIN_MAX_EFFECTS: usize = 6;

/// The driver has decided: nothing more may be performed.
pub fn login_effect_is_terminal(effect: LoginEffect) -> bool {
    matches!(
        effect,
        LoginEffect::Respond | LoginEffect::Fail(_) | LoginEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind each non-terminal effect. Each method returns only the
    /// observation its effect expects.
    pub trait LoginIo {
        fn consume_challenge(&mut self) -> ChallengeObservation;
        fn observe_device(&mut self) -> DeviceObservation;
        fn verify_signature(&mut self) -> VerifierObservation;
        fn record_verification_failure(&mut self) -> FailureRecordObservation;
        fn reset_backoff(&mut self) -> BackoffResetObservation;
        fn issue_token(&mut self) -> TokenIssueObservation;
        fn track_token(&mut self) -> TokenTrackObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_login`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call.
#[macro_export]
macro_rules! login_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::login_driver::{step as __step, LoginEffect as __E, LoginEvent as __V};
        let mut transition = $crate::login_driver::begin_login();
        for _ in 0..$crate::login_interpreter::LOGIN_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::login_driver::login_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::ConsumeChallenge => __step(
                    transition.driver,
                    __V::ChallengeObserved($io.consume_challenge()$(.$aw)?),
                ),
                __E::ObserveDevice => {
                    __step(transition.driver, __V::DeviceObserved($io.observe_device()$(.$aw)?))
                }
                __E::VerifySignature => {
                    __step(transition.driver, __V::VerifierObserved($io.verify_signature()$(.$aw)?))
                }
                __E::RecordVerificationFailure => __step(
                    transition.driver,
                    __V::FailureRecorded($io.record_verification_failure()$(.$aw)?),
                ),
                __E::ResetBackoff => __step(
                    transition.driver,
                    __V::BackoffResetObserved($io.reset_backoff()$(.$aw)?),
                ),
                __E::IssueToken => {
                    __step(transition.driver, __V::TokenIssued($io.issue_token()$(.$aw)?))
                }
                __E::TrackToken => {
                    __step(transition.driver, __V::TokenTracked($io.track_token()$(.$aw)?))
                }
                // The driver has decided: perform nothing, keep the verdict.
                __E::Respond | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`login_interpreter!`]: the artifact hax
/// extracts and F* checks.
pub fn run_login<Io: LoginIo>(io: &mut Io) -> crate::login_driver::LoginTransition {
    crate::login_interpreter!(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login_driver::{begin_login, step, LoginDriver, LoginEvent};

    /// Plays a fixed script of outcomes and records every call.
    struct Scripted {
        /// Which outcome to return for the n-th call (0 = success, then one per
        /// failure kind).
        script: Vec<u8>,
        calls: Vec<LoginEffect>,
        events: Vec<LoginEvent>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: LoginEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
    }

    const SCAN: [ChallengeObservation; 4] = [
        ChallengeObservation::Observed(crate::challenge::ChallengeConsumption::Accepted),
        ChallengeObservation::Observed(crate::challenge::ChallengeConsumption::Missing),
        ChallengeObservation::Observed(crate::challenge::ChallengeConsumption::WrongPurpose),
        ChallengeObservation::StorageFailed,
    ];
    const DEVICES: [DeviceObservation; 4] = [
        DeviceObservation::Present,
        DeviceObservation::Absent,
        DeviceObservation::QueryFailed,
        DeviceObservation::ParseFailed,
    ];
    const VERIFIERS: [VerifierObservation; 5] = [
        VerifierObservation::Valid,
        VerifierObservation::RejectedUnauthorized,
        VerifierObservation::RejectedBadRequest,
        VerifierObservation::RejectedInternal,
        VerifierObservation::ChallengeDecodeFailed,
    ];
    const RECORDS: [FailureRecordObservation; 2] = [
        FailureRecordObservation { fallback_counter_ok: true },
        FailureRecordObservation { fallback_counter_ok: false },
    ];
    const RESETS: [BackoffResetObservation; 2] =
        [BackoffResetObservation::Reset, BackoffResetObservation::StorageFailed];
    const ISSUES: [TokenIssueObservation; 2] =
        [TokenIssueObservation::Issued, TokenIssueObservation::Failed];
    const TRACKS: [TokenTrackObservation; 2] =
        [TokenTrackObservation::Tracked, TokenTrackObservation::Failed];

    impl LoginIo for Scripted {
        fn consume_challenge(&mut self) -> ChallengeObservation {
            let o = SCAN[(self.record(LoginEffect::ConsumeChallenge) as usize) % SCAN.len()];
            self.events.push(LoginEvent::ChallengeObserved(o));
            o
        }
        fn observe_device(&mut self) -> DeviceObservation {
            let o = DEVICES[(self.record(LoginEffect::ObserveDevice) as usize) % DEVICES.len()];
            self.events.push(LoginEvent::DeviceObserved(o));
            o
        }
        fn verify_signature(&mut self) -> VerifierObservation {
            let o = VERIFIERS[(self.record(LoginEffect::VerifySignature) as usize) % VERIFIERS.len()];
            self.events.push(LoginEvent::VerifierObserved(o));
            o
        }
        fn record_verification_failure(&mut self) -> FailureRecordObservation {
            let o =
                RECORDS[(self.record(LoginEffect::RecordVerificationFailure) as usize) % RECORDS.len()];
            self.events.push(LoginEvent::FailureRecorded(o));
            o
        }
        fn reset_backoff(&mut self) -> BackoffResetObservation {
            let o = RESETS[(self.record(LoginEffect::ResetBackoff) as usize) % RESETS.len()];
            self.events.push(LoginEvent::BackoffResetObserved(o));
            o
        }
        fn issue_token(&mut self) -> TokenIssueObservation {
            let o = ISSUES[(self.record(LoginEffect::IssueToken) as usize) % ISSUES.len()];
            self.events.push(LoginEvent::TokenIssued(o));
            o
        }
        fn track_token(&mut self) -> TokenTrackObservation {
            let o = TRACKS[(self.record(LoginEffect::TrackToken) as usize) % TRACKS.len()];
            self.events.push(LoginEvent::TokenTracked(o));
            o
        }
    }

    /// Replays the recorded events through the driver by hand and checks the
    /// interpreter called exactly the emitted effects, in order, and stopped
    /// at the verdict.
    fn check(script: Vec<u8>) -> LoginEffect {
        let mut io = Scripted { script, calls: vec![], events: vec![] };
        let result = run_login(&mut io);
        let mut t = begin_login();
        // The verdict effect of the driver is built from the same events; the
        // loop must have stopped before it performed anything after it.
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!login_effect_is_terminal(t.effect), "a call followed the verdict");
            t = step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            login_effect_is_terminal(result.effect),
            "no verdict within {LOGIN_MAX_EFFECTS} effects: {:?}",
            result.effect
        );
        assert!(io.calls.len() <= LOGIN_MAX_EFFECTS);
        result.effect
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        // Success everywhere.
        assert_eq!(check(vec![0; LOGIN_MAX_EFFECTS]), LoginEffect::Respond);
        // One non-success outcome at every position, with every kind.
        for position in 0..LOGIN_MAX_EFFECTS {
            for kind in 1..=8u8 {
                let mut script = vec![0u8; LOGIN_MAX_EFFECTS];
                script[position] = kind;
                let verdict = check(script);
                assert!(matches!(verdict, LoginEffect::Respond | LoginEffect::Fail(_)));
            }
        }
        // Every observation kind at the two positions where the driver branches
        // into the failure-record path and into issuance.
        for kind in 1..=4u8 {
            let mut script = vec![0u8; LOGIN_MAX_EFFECTS];
            script[2] = kind;
            let verdict = check(script);
            // A verifier rejection records the failure and never responds.
            if (1..=3).contains(&kind) {
                assert!(matches!(verdict, LoginEffect::Fail(_)), "{kind}: {verdict:?}");
            }
        }
    }

    #[test]
    fn a_challenge_refusal_performs_nothing_else() {
        let mut io = Scripted { script: vec![1], calls: vec![], events: vec![] };
        let result = run_login(&mut io);
        assert_eq!(io.calls, vec![LoginEffect::ConsumeChallenge]);
        assert_eq!(
            result.effect,
            LoginEffect::Fail(crate::login_driver::LoginFailure::ChallengeMissing)
        );
    }

    #[test]
    fn a_failed_track_never_reaches_respond() {
        let mut script = vec![0u8; LOGIN_MAX_EFFECTS];
        // The track effect is the sixth (index 5) call on the success path.
        script[5] = 1;
        assert_eq!(
            check(script),
            LoginEffect::Fail(crate::login_driver::LoginFailure::TrackingFailed)
        );
    }

    /// The loop's driver state is the one the trace theorems quantify over:
    /// the hand-replayed final driver equals the interpreter's.
    #[test]
    fn final_driver_matches_the_replayed_trace() {
        let mut script = vec![0u8; LOGIN_MAX_EFFECTS];
        script[4] = 1; // issuance fails
        let mut io = Scripted { script, calls: vec![], events: vec![] };
        let result = run_login(&mut io);
        let mut d: LoginDriver = begin_login().driver;
        for event in &io.events {
            d = step(d, *event).driver;
        }
        assert_eq!(result.driver, d);
    }
}
