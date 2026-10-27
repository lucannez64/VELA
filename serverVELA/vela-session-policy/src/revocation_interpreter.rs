//! The loops that connect `/device/revoke` and `/auth/logout` to their drivers.
//!
//! Neither handler calls its driver by hand. Each expands one macro from this
//! module — the same macro text this module expands into the synchronous
//! [`run_revocation`] and [`run_logout`]. hax extracts both and F* proves, for
//! every executor implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects (the types allow nothing else);
//! - the loop stops at the first terminal effect (`Complete`, `Fail`, `Idle`)
//!   and performs nothing after it;
//! - the final driver is `run_from_actor actor evs` (revocation) or
//!   `logout_run_from_begin observations` (logout) for the observations the
//!   executor actually returned, so every per-request theorem holds for the
//!   real handler.
//!
//! The server's expansions differ only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::revocation_driver::{
    CascadeObservation, DeviceLookupObservation, LockoutObservation, LogoutDriver, LogoutEffect,
    LogoutObservation, LogoutTransition, RecordObservation, RevocationDriver, RevocationEffect,
    RevocationTransition,
};

/// The two transition records in [`crate::revocation_driver`] share the field
/// names `driver` and `effect`. hax keeps the projections, and F* cannot infer
/// a record type from a bare `transition.effect` when two records declare that
/// field, so the extracted loop reaches both through these typed functions.
/// They are pure accessors; nothing else depends on them.
pub fn revocation_driver_of(transition: RevocationTransition) -> RevocationDriver {
    transition.driver
}

pub fn revocation_effect_of(transition: RevocationTransition) -> RevocationEffect {
    transition.effect
}

pub fn logout_driver_of(transition: LogoutTransition) -> LogoutDriver {
    transition.driver
}

pub fn logout_effect_of(transition: LogoutTransition) -> LogoutEffect {
    transition.effect
}

/// Most effects one revocation performs: the target lookup, the device
/// lockout, the SQL record and the approved-web-session cascade. The
/// already-revoked retry repeats the lockout and cascade instead of recording,
/// so four turns is the longest path.
pub const REVOCATION_MAX_EFFECTS: usize = 4;

/// The revocation driver has decided: nothing more may be performed.
pub fn revocation_effect_is_terminal(effect: RevocationEffect) -> bool {
    matches!(
        effect,
        RevocationEffect::Complete | RevocationEffect::Fail(_) | RevocationEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind each non-terminal revocation effect. Each method returns
    /// only the observation its effect expects.
    pub trait RevocationIo {
        fn lookup_target(&mut self) -> DeviceLookupObservation;
        fn lockout_device(&mut self) -> LockoutObservation;
        fn record_revocation(&mut self) -> RecordObservation;
        fn cascade_web_sessions(&mut self) -> CascadeObservation;
    }
}

/// The revocation interpreter body, shared verbatim by [`run_revocation`] and
/// `post_revoke`. `$io` names a mutable executor; pass `await` as the last
/// argument to await each executor call.
#[macro_export]
macro_rules! revocation_interpreter {
    ($io:ident, $actor:expr $(, $aw:ident)?) => {{
        use $crate::revocation_driver::{
            step as __step, RevocationEffect as __E, RevocationEvent as __V,
        };
        use $crate::revocation_interpreter::{revocation_driver_of as __driver, revocation_effect_of as __effect};
        let mut transition = $crate::revocation_driver::begin_revocation($actor);
        for _ in 0..$crate::revocation_interpreter::REVOCATION_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::revocation_driver::revocation_state_is_sound(__driver(transition))
            });
            transition = match __effect(transition) {
                __E::LookupTarget => __step(
                    __driver(transition),
                    __V::TargetObserved($io.lookup_target()$(.$aw)?),
                ),
                __E::LockoutDevice => __step(
                    __driver(transition),
                    __V::LockoutObserved($io.lockout_device()$(.$aw)?),
                ),
                __E::RecordRevocation => __step(
                    __driver(transition),
                    __V::RecordObserved($io.record_revocation()$(.$aw)?),
                ),
                __E::CascadeWebSessions => __step(
                    __driver(transition),
                    __V::CascadeObserved($io.cascade_web_sessions()$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`revocation_interpreter!`]: the artifact hax
/// extracts and F* checks.
pub fn run_revocation<Io: RevocationIo>(
    io: &mut Io,
    actor: crate::revocation_driver::ActorObservation,
) -> crate::revocation_driver::RevocationTransition {
    crate::revocation_interpreter!(io, actor)
}

/// Most effects one logout performs: the single JTI marker write.
pub const LOGOUT_MAX_EFFECTS: usize = 1;

/// The logout driver has decided: nothing more may be performed.
pub fn logout_effect_is_terminal(effect: LogoutEffect) -> bool {
    matches!(
        effect,
        LogoutEffect::Complete | LogoutEffect::Fail(_) | LogoutEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind the one non-terminal logout effect.
    pub trait LogoutIo {
        fn revoke_jti(&mut self) -> LogoutObservation;
    }
}

/// The logout interpreter body, shared verbatim by [`run_logout`] and
/// `post_logout`. `$io` names a mutable executor; pass `await` as the last
/// argument to await the executor call.
#[macro_export]
macro_rules! logout_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::revocation_driver::{logout_step as __step, LogoutEffect as __E};
        use $crate::revocation_interpreter::{logout_driver_of as __driver, logout_effect_of as __effect};
        let mut transition = $crate::revocation_driver::begin_logout();
        for _ in 0..$crate::revocation_interpreter::LOGOUT_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::revocation_driver::logout_state_is_sound(__driver(transition))
            });
            transition = match __effect(transition) {
                __E::RevokeJti => __step(__driver(transition), $io.revoke_jti()$(.$aw)?),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`logout_interpreter!`]: the artifact hax
/// extracts and F* checks.
pub fn run_logout<Io: LogoutIo>(io: &mut Io) -> crate::revocation_driver::LogoutTransition {
    crate::logout_interpreter!(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation_driver::{
        begin_logout, begin_revocation, logout_step, step, ActorObservation, LogoutStage,
        RevocationEvent, RevocationFailure, RevocationTransition, TargetObservation,
    };

    const ACTOR: ActorObservation = ActorObservation {
        authenticated: true,
        device_active: true,
    };

    /// Plays fixed outcomes and records every call.
    struct Scripted {
        target: DeviceLookupObservation,
        lockout: LockoutObservation,
        record: RecordObservation,
        cascade: CascadeObservation,
        calls: Vec<RevocationEffect>,
        events: Vec<RevocationEvent>,
    }

    impl Scripted {
        fn new(
            target: DeviceLookupObservation,
            lockout: LockoutObservation,
            record: RecordObservation,
            cascade: CascadeObservation,
        ) -> Self {
            Self { target, lockout, record, cascade, calls: vec![], events: vec![] }
        }
    }

    impl RevocationIo for Scripted {
        fn lookup_target(&mut self) -> DeviceLookupObservation {
            self.calls.push(RevocationEffect::LookupTarget);
            self.events
                .push(RevocationEvent::TargetObserved(self.target));
            self.target
        }
        fn lockout_device(&mut self) -> LockoutObservation {
            self.calls.push(RevocationEffect::LockoutDevice);
            self.events
                .push(RevocationEvent::LockoutObserved(self.lockout));
            self.lockout
        }
        fn record_revocation(&mut self) -> RecordObservation {
            self.calls.push(RevocationEffect::RecordRevocation);
            self.events
                .push(RevocationEvent::RecordObserved(self.record));
            self.record
        }
        fn cascade_web_sessions(&mut self) -> CascadeObservation {
            self.calls.push(RevocationEffect::CascadeWebSessions);
            self.events
                .push(RevocationEvent::CascadeObserved(self.cascade));
            self.cascade
        }
    }

    fn targets() -> Vec<DeviceLookupObservation> {
        let mut targets = vec![
            DeviceLookupObservation::Absent,
            DeviceLookupObservation::QueryFailed,
            DeviceLookupObservation::Malformed,
            DeviceLookupObservation::Present(TargetObservation {
                same_account: false,
                already_revoked: false,
            }),
        ];
        for already_revoked in [false, true] {
            targets.push(DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked,
            }));
        }
        targets
    }

    /// Replays the recorded events through the driver by hand and checks the
    /// interpreter called exactly the emitted effects, in order, and stopped
    /// at the verdict.
    fn check(
        target: DeviceLookupObservation,
        lockout: LockoutObservation,
        record: RecordObservation,
        cascade: CascadeObservation,
    ) -> RevocationTransition {
        let mut io = Scripted::new(target, lockout, record, cascade);
        let result = run_revocation(&mut io, ACTOR);
        let mut t = begin_revocation(ACTOR);
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!revocation_effect_is_terminal(t.effect));
            t = step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            revocation_effect_is_terminal(result.effect),
            "no verdict within {REVOCATION_MAX_EFFECTS} effects: {:?}",
            result.effect
        );
        assert!(io.calls.len() <= REVOCATION_MAX_EFFECTS);
        result
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        for target in targets() {
            for lockout in [
                LockoutObservation::Applied,
                LockoutObservation::StorageFailed,
            ] {
                for record in [RecordObservation::Updated, RecordObservation::Failed] {
                    for cascade in [
                        CascadeObservation::Completed,
                        CascadeObservation::StorageFailed,
                    ] {
                        check(target, lockout, record, cascade);
                    }
                }
            }
        }
    }

    #[test]
    fn a_fresh_revoke_performs_every_effect_in_order() {
        let result = check(
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: false,
            }),
            LockoutObservation::Applied,
            RecordObservation::Updated,
            CascadeObservation::Completed,
        );
        assert_eq!(result.effect, RevocationEffect::Complete);
        assert!(result.driver.recorded && result.driver.cascade_done);
    }

    #[test]
    fn an_already_revoked_retry_skips_the_sql_record() {
        let mut io = Scripted::new(
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: true,
            }),
            LockoutObservation::Applied,
            RecordObservation::Updated,
            CascadeObservation::Completed,
        );
        let result = run_revocation(&mut io, ACTOR);
        assert_eq!(
            io.calls,
            vec![
                RevocationEffect::LookupTarget,
                RevocationEffect::LockoutDevice,
                RevocationEffect::CascadeWebSessions,
            ]
        );
        assert_eq!(
            result.effect,
            RevocationEffect::Fail(RevocationFailure::AlreadyRevoked)
        );
    }

    #[test]
    fn a_refused_actor_performs_nothing() {
        for (authenticated, device_active) in [(false, false), (true, false), (false, true)] {
            let mut io = Scripted::new(
                DeviceLookupObservation::Absent,
                LockoutObservation::Applied,
                RecordObservation::Updated,
                CascadeObservation::Completed,
            );
            let result = run_revocation(
                &mut io,
                ActorObservation {
                    authenticated,
                    device_active,
                },
            );
            assert!(io.calls.is_empty());
            assert_eq!(
                result.effect,
                RevocationEffect::Fail(RevocationFailure::Unauthenticated)
            );
        }
    }

    struct ScriptedLogout {
        observation: LogoutObservation,
        calls: Vec<LogoutEffect>,
    }

    impl LogoutIo for ScriptedLogout {
        fn revoke_jti(&mut self) -> LogoutObservation {
            self.calls.push(LogoutEffect::RevokeJti);
            self.observation
        }
    }

    #[test]
    fn logout_writes_exactly_one_marker_then_stops() {
        for (observation, expected) in [
            (
                LogoutObservation::Applied,
                LogoutEffect::Complete,
            ),
            (
                LogoutObservation::StorageFailed,
                LogoutEffect::Fail(crate::revocation_driver::LogoutFailure::Storage),
            ),
        ] {
            let mut io = ScriptedLogout { observation, calls: vec![] };
            let result = run_logout(&mut io);
            assert_eq!(io.calls, vec![LogoutEffect::RevokeJti]);
            assert_eq!(result.effect, expected);
            assert_eq!(result.driver.stage, LogoutStage::Done);
            assert_eq!(logout_step(begin_logout().driver, observation), result);
            // Nothing after the verdict.
            let again = logout_step(result.driver, LogoutObservation::Applied);
            assert_eq!(again.effect, LogoutEffect::Idle);
            assert!(logout_effect_is_terminal(result.effect));
        }
    }
}
