//! Pure `/device/revoke`, `/auth/logout` and admission decision drivers.
//!
//! The HTTP handlers in `vela-server` perform the effectful steps: the target
//! `devices` row lookup, the sled JTI/sentinel writes, the durable SQL
//! `revoked = 1` update and the approved-web-session cascade. This module owns
//! every *decision* between those effects:
//!
//! 1. whether the authenticated actor may revoke anything at all;
//! 2. how a missing, malformed or matched target row is classified;
//! 3. whether the target belongs to the caller and is not already revoked;
//! 4. which effect comes next — device lockout, SQL record, web-session
//!    cascade, or a terminal response;
//! 5. how each effect outcome is classified, including the already-revoked
//!    retry that repeats the lockout and cascade but not the SQL record.
//!
//! The order of effects is part of the contract, not an implementation detail:
//! the device is locked out (every tracked JTI plus the `device:revoked:`
//! sentinel) *before* the SQL `revoked = 1` record, so a failed record leaves a
//! device that is already stopped rather than one marked revoked but still
//! usable. The state invariant and `revocation_effect_is_sound` encode that
//! order and `proofs/fstar/revocation-driver-lemmas` proves it over every
//! event list.
//!
//! The same module carries the pure admission decision the middleware uses to
//! reject revoked JTIs and devices, and the one-effect logout driver. The
//! decision function keeps the historical precedence: JTI marker, then device
//! sentinel, then account existence, then the active device row.
//!
//! The drivers are per-request values: they do not observe the store or SQL
//! database and do not coordinate concurrent requests. Every input is an
//! observation produced by the handler; store/SQL linearizability, the clock
//! and the response rendering remain outside this crate.

/// Actor facts established by the authenticated `DeviceSession` extractor.
/// `authenticated` is the verified PASETO identity; `device_active` is the
/// middleware's durable `devices.revoked = 0` check for device-scoped tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActorObservation {
    pub authenticated: bool,
    pub device_active: bool,
}

/// The target device row as observed by the lookup query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetObservation {
    /// The row's `user_id` equals the authenticated caller.
    pub same_account: bool,
    /// The row's `revoked` column is already set.
    pub already_revoked: bool,
}

/// Outcome of the target lookup. `Malformed` is a row that the handler could
/// not decode; the handler still holds the original error for rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceLookupObservation {
    /// The query returned no row.
    Absent,
    /// The query itself failed.
    QueryFailed,
    /// A row came back but could not be decoded.
    Malformed,
    /// A decoded row.
    Present(TargetObservation),
}

/// Outcome of the device lockout effect (`revoke_all_device_jtis` plus the
/// `device:revoked:` sentinel).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockoutObservation {
    Applied,
    StorageFailed,
}

/// Outcome of the durable `UPDATE devices SET revoked = 1` effect. `Failed` is
/// an observation, not proof that no row was committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordObservation {
    Updated,
    Failed,
}

/// Outcome of the approved-web-session cascade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CascadeObservation {
    Completed,
    StorageFailed,
}

/// Where the revocation is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationStage {
    /// The handler may query the target device row.
    Observe,
    /// A same-account, not-yet-revoked target was observed; lock it out.
    Lockout,
    /// The lockout was applied; record the durable SQL revocation.
    Record,
    /// The SQL row is revoked; end the web sessions it approved.
    Cascade,
    /// An already-revoked same-account target; repeat the lockout effects.
    RepeatLockout,
    /// The repeated lockout was applied; repeat the web-session cascade.
    RepeatCascade,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationEvent {
    TargetObserved(DeviceLookupObservation),
    LockoutObserved(LockoutObservation),
    RecordObserved(RecordObservation),
    CascadeObserved(CascadeObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationFailure {
    /// The actor was not an authenticated, active device. Terminal, no effect.
    Unauthenticated,
    /// No device row exists for the requested id.
    TargetNotFound,
    /// The target belongs to a different account.
    CrossAccount,
    /// The target row is already revoked; the retry path returns this after
    /// repeating the lockout and cascade.
    AlreadyRevoked,
    /// The target lookup query failed.
    TargetQueryStorage,
    /// The target row could not be decoded.
    TargetParseStorage,
    /// The JTI/sentinel lockout failed.
    LockoutStorage,
    /// The durable `revoked = 1` update failed (it may have committed).
    RecordStorage,
    /// The approved-web-session cascade failed.
    CascadeStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationEffect {
    /// Query the target device row.
    LookupTarget,
    /// Revoke every tracked JTI and write the `device:revoked:` sentinel.
    LockoutDevice,
    /// Flip the durable SQL row (`revoked = 1`).
    RecordRevocation,
    /// Revoke every web session approved by the target device.
    CascadeWebSessions,
    /// Terminal success.
    Complete,
    /// Terminal failure without further effects.
    Fail(RevocationFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationDriver {
    pub stage: RevocationStage,
    /// The actor was authenticated and its device was active when the request
    /// began.
    pub actor_active: bool,
    /// The target row belongs to the actor's account.
    pub same_account: bool,
    /// The target row's `revoked` column was already set.
    pub already_revoked: bool,
    /// The driver has instructed the device lockout.
    pub locked_out: bool,
    /// The lockout was observed as applied.
    pub lockout_done: bool,
    /// The durable SQL record was observed as updated.
    pub recorded: bool,
    /// The approved-web-session cascade was observed as completed.
    pub cascade_done: bool,
    /// A success response was authorized.
    pub responded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationTransition {
    pub driver: RevocationDriver,
    pub effect: RevocationEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn revocation_state_is_sound(d: RevocationDriver) -> bool {
    let untouched = !d.same_account
        && !d.already_revoked
        && !d.locked_out
        && !d.lockout_done
        && !d.recorded
        && !d.cascade_done
        && !d.responded
        && !d.failed;
    let observe_clean = d.actor_active && untouched;
    let lockout_clean = d.actor_active
        && d.same_account
        && !d.already_revoked
        && d.locked_out
        && !d.lockout_done
        && !d.recorded
        && !d.cascade_done
        && !d.responded
        && !d.failed;
    let record_clean = d.actor_active
        && d.same_account
        && !d.already_revoked
        && d.locked_out
        && d.lockout_done
        && !d.recorded
        && !d.cascade_done
        && !d.responded
        && !d.failed;
    let cascade_clean = d.actor_active
        && d.same_account
        && !d.already_revoked
        && d.locked_out
        && d.lockout_done
        && d.recorded
        && !d.cascade_done
        && !d.responded
        && !d.failed;
    let repeat_lockout_clean = d.actor_active
        && d.same_account
        && d.already_revoked
        && d.locked_out
        && !d.lockout_done
        && !d.recorded
        && !d.cascade_done
        && !d.responded
        && !d.failed;
    let repeat_cascade_clean = d.actor_active
        && d.same_account
        && d.already_revoked
        && d.locked_out
        && d.lockout_done
        && !d.recorded
        && !d.cascade_done
        && !d.responded
        && !d.failed;
    let done_clean = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded
            || (d.actor_active
                && d.same_account
                && !d.already_revoked
                && d.locked_out
                && d.lockout_done
                && d.recorded
                && d.cascade_done));
    (!matches!(d.stage, RevocationStage::Observe) || observe_clean)
        && (!matches!(d.stage, RevocationStage::Lockout) || lockout_clean)
        && (!matches!(d.stage, RevocationStage::Record) || record_clean)
        && (!matches!(d.stage, RevocationStage::Cascade) || cascade_clean)
        && (!matches!(d.stage, RevocationStage::RepeatLockout) || repeat_lockout_clean)
        && (!matches!(d.stage, RevocationStage::RepeatCascade) || repeat_cascade_clean)
        && (!matches!(d.stage, RevocationStage::Done) || done_clean)
        && (!d.same_account || d.actor_active)
        && (!d.locked_out || d.actor_active)
        && (!d.already_revoked || d.same_account)
        // Effect-order invariant: the SQL record is only reachable after the
        // lockout was both instructed and observed.
        && (!d.recorded || (d.locked_out && d.lockout_done))
        // The cascade always follows a successful or repeated revoke.
        && (!d.cascade_done || (d.locked_out && d.lockout_done))
        && (!d.cascade_done || d.recorded || d.already_revoked)
        && (!d.recorded || (d.same_account && !d.already_revoked))
        && (!d.responded || (d.recorded && d.cascade_done))
        && (!d.lockout_done || d.locked_out)
}

/// Every effect the driver emits agrees with the state it produces.
pub fn revocation_effect_is_sound(d: RevocationDriver, effect: RevocationEffect) -> bool {
    let common = d.actor_active && d.same_account && d.locked_out && !d.responded && !d.failed;
    match effect {
        RevocationEffect::LookupTarget => {
            matches!(d.stage, RevocationStage::Observe)
                && d.actor_active
                && !d.same_account
                && !d.already_revoked
                && !d.locked_out
                && !d.lockout_done
                && !d.recorded
                && !d.cascade_done
                && !d.responded
                && !d.failed
        }
        RevocationEffect::LockoutDevice => {
            common
                && !d.lockout_done
                && !d.recorded
                && !d.cascade_done
                && ((matches!(d.stage, RevocationStage::Lockout) && !d.already_revoked)
                    || (matches!(d.stage, RevocationStage::RepeatLockout) && d.already_revoked))
        }
        RevocationEffect::RecordRevocation => {
            common
                && d.lockout_done
                && !d.recorded
                && !d.cascade_done
                && !d.already_revoked
                && matches!(d.stage, RevocationStage::Record)
        }
        RevocationEffect::CascadeWebSessions => {
            common
                && d.lockout_done
                && !d.cascade_done
                && ((matches!(d.stage, RevocationStage::Cascade) && d.recorded)
                    || (matches!(d.stage, RevocationStage::RepeatCascade)
                        && d.already_revoked
                        && !d.recorded))
        }
        RevocationEffect::Complete => {
            matches!(d.stage, RevocationStage::Done)
                && d.actor_active
                && d.same_account
                && !d.already_revoked
                && d.locked_out
                && d.lockout_done
                && d.recorded
                && d.cascade_done
                && d.responded
                && !d.failed
        }
        RevocationEffect::Fail(_) => {
            matches!(d.stage, RevocationStage::Done) && d.failed && !d.responded
        }
        RevocationEffect::Idle => true,
    }
}

fn transition(driver: RevocationDriver, effect: RevocationEffect) -> RevocationTransition {
    RevocationTransition { driver, effect }
}

fn idle(driver: RevocationDriver) -> RevocationTransition {
    transition(driver, RevocationEffect::Idle)
}

fn terminal(driver: RevocationDriver, failure: RevocationFailure) -> RevocationTransition {
    transition(
        RevocationDriver {
            stage: RevocationStage::Done,
            failed: true,
            ..driver
        },
        RevocationEffect::Fail(failure),
    )
}

/// Start a per-request revocation. An actor the middleware did not verify as an
/// authenticated, active device produces a terminal failure without any
/// effect, so a revoked actor can never reach the lockout or SQL record.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    revocation_state_is_sound(result.driver)
        && revocation_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_revocation(actor: ActorObservation) -> RevocationTransition {
    if actor.authenticated && actor.device_active {
        transition(
            RevocationDriver {
                stage: RevocationStage::Observe,
                actor_active: true,
                same_account: false,
                already_revoked: false,
                locked_out: false,
                lockout_done: false,
                recorded: false,
                cascade_done: false,
                responded: false,
                failed: false,
            },
            RevocationEffect::LookupTarget,
        )
    } else {
        transition(
            RevocationDriver {
                stage: RevocationStage::Done,
                actor_active: false,
                same_account: false,
                already_revoked: false,
                locked_out: false,
                lockout_done: false,
                recorded: false,
                cascade_done: false,
                responded: false,
                failed: true,
            },
            RevocationEffect::Fail(RevocationFailure::Unauthenticated),
        )
    }
}

fn on_target_observed(
    driver: RevocationDriver,
    observation: DeviceLookupObservation,
) -> RevocationTransition {
    match observation {
        DeviceLookupObservation::Absent => terminal(driver, RevocationFailure::TargetNotFound),
        DeviceLookupObservation::QueryFailed => {
            terminal(driver, RevocationFailure::TargetQueryStorage)
        }
        DeviceLookupObservation::Malformed => {
            terminal(driver, RevocationFailure::TargetParseStorage)
        }
        DeviceLookupObservation::Present(target) => {
            if !target.same_account {
                terminal(driver, RevocationFailure::CrossAccount)
            } else if target.already_revoked {
                transition(
                    RevocationDriver {
                        stage: RevocationStage::RepeatLockout,
                        same_account: true,
                        already_revoked: true,
                        locked_out: true,
                        ..driver
                    },
                    RevocationEffect::LockoutDevice,
                )
            } else {
                transition(
                    RevocationDriver {
                        stage: RevocationStage::Lockout,
                        same_account: true,
                        locked_out: true,
                        ..driver
                    },
                    RevocationEffect::LockoutDevice,
                )
            }
        }
    }
}

fn on_lockout_observed(
    driver: RevocationDriver,
    observation: LockoutObservation,
) -> RevocationTransition {
    match observation {
        LockoutObservation::Applied => {
            if driver.already_revoked {
                transition(
                    RevocationDriver {
                        stage: RevocationStage::RepeatCascade,
                        lockout_done: true,
                        ..driver
                    },
                    RevocationEffect::CascadeWebSessions,
                )
            } else {
                transition(
                    RevocationDriver {
                        stage: RevocationStage::Record,
                        lockout_done: true,
                        ..driver
                    },
                    RevocationEffect::RecordRevocation,
                )
            }
        }
        LockoutObservation::StorageFailed => terminal(driver, RevocationFailure::LockoutStorage),
    }
}

fn on_record_observed(
    driver: RevocationDriver,
    observation: RecordObservation,
) -> RevocationTransition {
    match observation {
        RecordObservation::Updated => transition(
            RevocationDriver {
                stage: RevocationStage::Cascade,
                recorded: true,
                ..driver
            },
            RevocationEffect::CascadeWebSessions,
        ),
        RecordObservation::Failed => terminal(driver, RevocationFailure::RecordStorage),
    }
}

fn on_cascade_observed(
    driver: RevocationDriver,
    observation: CascadeObservation,
) -> RevocationTransition {
    match observation {
        CascadeObservation::Completed => {
            if driver.already_revoked {
                // The retry path repeats the effects but still reports the
                // target as already revoked.
                transition(
                    RevocationDriver {
                        stage: RevocationStage::Done,
                        cascade_done: true,
                        failed: true,
                        ..driver
                    },
                    RevocationEffect::Fail(RevocationFailure::AlreadyRevoked),
                )
            } else {
                transition(
                    RevocationDriver {
                        stage: RevocationStage::Done,
                        cascade_done: true,
                        responded: true,
                        ..driver
                    },
                    RevocationEffect::Complete,
                )
            }
        }
        CascadeObservation::StorageFailed => terminal(driver, RevocationFailure::CascadeStorage),
    }
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(revocation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    revocation_effect_is_sound(result.driver, result.effect)
        && (!revocation_state_is_sound(driver) || revocation_state_is_sound(result.driver))
}))]
pub fn step(driver: RevocationDriver, event: RevocationEvent) -> RevocationTransition {
    match event {
        RevocationEvent::TargetObserved(observation) => {
            if matches!(driver.stage, RevocationStage::Observe) {
                on_target_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        RevocationEvent::LockoutObserved(observation) => {
            if matches!(
                driver.stage,
                RevocationStage::Lockout | RevocationStage::RepeatLockout
            ) {
                on_lockout_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        RevocationEvent::RecordObserved(observation) => {
            if matches!(driver.stage, RevocationStage::Record) {
                on_record_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        RevocationEvent::CascadeObserved(observation) => {
            if matches!(
                driver.stage,
                RevocationStage::Cascade | RevocationStage::RepeatCascade
            ) {
                on_cascade_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(revocation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    revocation_effect_is_sound(result.driver, result.effect)
        && (!revocation_state_is_sound(driver) || revocation_state_is_sound(result.driver))
}))]
pub fn on_target_looked_up(
    driver: RevocationDriver,
    observation: DeviceLookupObservation,
) -> RevocationTransition {
    step(driver, RevocationEvent::TargetObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(revocation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    revocation_effect_is_sound(result.driver, result.effect)
        && (!revocation_state_is_sound(driver) || revocation_state_is_sound(result.driver))
}))]
pub fn on_lockout_completed(
    driver: RevocationDriver,
    observation: LockoutObservation,
) -> RevocationTransition {
    step(driver, RevocationEvent::LockoutObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(revocation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    revocation_effect_is_sound(result.driver, result.effect)
        && (!revocation_state_is_sound(driver) || revocation_state_is_sound(result.driver))
}))]
pub fn on_record_completed(
    driver: RevocationDriver,
    observation: RecordObservation,
) -> RevocationTransition {
    step(driver, RevocationEvent::RecordObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(revocation_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    revocation_effect_is_sound(result.driver, result.effect)
        && (!revocation_state_is_sound(driver) || revocation_state_is_sound(result.driver))
}))]
pub fn on_cascade_completed(
    driver: RevocationDriver,
    observation: CascadeObservation,
) -> RevocationTransition {
    step(driver, RevocationEvent::CascadeObserved(observation))
}

// ── Logout ──────────────────────────────────────────────────────────────────

/// Where the logout is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutStage {
    /// The handler may write the JTI revocation marker.
    Apply,
    /// A terminal response or failure was decided.
    Done,
}

/// Outcome of the JTI revocation write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutObservation {
    Applied,
    StorageFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutFailure {
    Storage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutEffect {
    /// Write `jti:revoked:{jti}` with the remaining-lifetime TTL.
    RevokeJti,
    /// Terminal success.
    Complete,
    /// Terminal failure without further effects.
    Fail(LogoutFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogoutDriver {
    pub stage: LogoutStage,
    /// The JTI marker was observed as written.
    pub jti_revoked: bool,
    /// A success response was authorized.
    pub responded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogoutTransition {
    pub driver: LogoutDriver,
    pub effect: LogoutEffect,
}

pub fn logout_state_is_sound(d: LogoutDriver) -> bool {
    let apply_clean = !d.jti_revoked && !d.responded && !d.failed;
    let done_clean =
        (d.responded || d.failed) && !(d.responded && d.failed) && (!d.responded || d.jti_revoked);
    (!matches!(d.stage, LogoutStage::Apply) || apply_clean)
        && (!matches!(d.stage, LogoutStage::Done) || done_clean)
        && (!d.responded || d.jti_revoked)
        && (!d.failed || !d.responded)
}

pub fn logout_effect_is_sound(d: LogoutDriver, effect: LogoutEffect) -> bool {
    match effect {
        LogoutEffect::RevokeJti => {
            matches!(d.stage, LogoutStage::Apply) && !d.jti_revoked && !d.responded && !d.failed
        }
        LogoutEffect::Complete => {
            matches!(d.stage, LogoutStage::Done) && d.jti_revoked && d.responded && !d.failed
        }
        LogoutEffect::Fail(_) => matches!(d.stage, LogoutStage::Done) && d.failed && !d.responded,
        LogoutEffect::Idle => true,
    }
}

/// Start a per-request logout. Only the JTI marker may be attempted.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    logout_state_is_sound(result.driver)
        && logout_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, LogoutStage::Apply)
        && matches!(result.effect, LogoutEffect::RevokeJti)
}))]
pub fn begin_logout() -> LogoutTransition {
    LogoutTransition {
        driver: LogoutDriver {
            stage: LogoutStage::Apply,
            jti_revoked: false,
            responded: false,
            failed: false,
        },
        effect: LogoutEffect::RevokeJti,
    }
}

fn on_logout_observed(driver: LogoutDriver, observation: LogoutObservation) -> LogoutTransition {
    match observation {
        LogoutObservation::Applied => LogoutTransition {
            driver: LogoutDriver {
                stage: LogoutStage::Done,
                jti_revoked: true,
                responded: true,
                failed: false,
            },
            effect: LogoutEffect::Complete,
        },
        LogoutObservation::StorageFailed => LogoutTransition {
            driver: LogoutDriver {
                stage: LogoutStage::Done,
                failed: true,
                ..driver
            },
            effect: LogoutEffect::Fail(LogoutFailure::Storage),
        },
    }
}

/// The complete, total logout transition relation.
#[cfg_attr(hax, hax_lib::requires(logout_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    logout_effect_is_sound(result.driver, result.effect)
        && (!logout_state_is_sound(driver) || logout_state_is_sound(result.driver))
}))]
pub fn logout_step(driver: LogoutDriver, observation: LogoutObservation) -> LogoutTransition {
    if matches!(driver.stage, LogoutStage::Apply) {
        on_logout_observed(driver, observation)
    } else {
        LogoutTransition {
            driver,
            effect: LogoutEffect::Idle,
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(logout_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    logout_effect_is_sound(result.driver, result.effect)
        && (!logout_state_is_sound(driver) || logout_state_is_sound(result.driver))
}))]
pub fn on_logout_completed(
    driver: LogoutDriver,
    observation: LogoutObservation,
) -> LogoutTransition {
    logout_step(driver, observation)
}

// ── Token admission ─────────────────────────────────────────────────────────

/// The observations that decide whether an authenticated request proceeds.
/// The middleware reads them in the same order it historically did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionObservation {
    pub jti_revoked: bool,
    pub device_revoked: bool,
    pub account_present: bool,
    pub device_row_active: bool,
    /// True for device-scoped tokens; web sessions have no `devices` row.
    pub device_scoped: bool,
}

/// Why an authenticated request was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRefusal {
    JtiRevoked,
    DeviceRevoked,
    AccountAbsent,
    DeviceRowRevoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Admit,
    Reject(AdmissionRefusal),
}

pub fn admission_is_authorized(o: AdmissionObservation) -> bool {
    !o.jti_revoked
        && !o.device_revoked
        && o.account_present
        && (!o.device_scoped || o.device_row_active)
}

/// The independent, historical-precedence specification of the admission
/// decision: a JTI marker wins over a device sentinel, which wins over account
/// absence, which wins over the durable device-row guard.
pub fn admission_decision_matches_spec(
    o: AdmissionObservation,
    decision: AdmissionDecision,
) -> bool {
    match decision {
        AdmissionDecision::Admit => admission_is_authorized(o),
        AdmissionDecision::Reject(refusal) => match refusal {
            AdmissionRefusal::JtiRevoked => o.jti_revoked,
            AdmissionRefusal::DeviceRevoked => !o.jti_revoked && o.device_revoked,
            AdmissionRefusal::AccountAbsent => {
                !o.jti_revoked && !o.device_revoked && !o.account_present
            }
            AdmissionRefusal::DeviceRowRevoked => {
                !o.jti_revoked
                    && !o.device_revoked
                    && o.account_present
                    && o.device_scoped
                    && !o.device_row_active
            }
        },
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    admission_decision_matches_spec(observation, decision)
}))]
pub fn plan_admission(observation: AdmissionObservation) -> AdmissionDecision {
    if observation.jti_revoked {
        AdmissionDecision::Reject(AdmissionRefusal::JtiRevoked)
    } else if observation.device_revoked {
        AdmissionDecision::Reject(AdmissionRefusal::DeviceRevoked)
    } else if !observation.account_present {
        AdmissionDecision::Reject(AdmissionRefusal::AccountAbsent)
    } else if observation.device_scoped && !observation.device_row_active {
        AdmissionDecision::Reject(AdmissionRefusal::DeviceRowRevoked)
    } else {
        AdmissionDecision::Admit
    }
}

/// Direct theorem used by the F* gate: a revoked JTI is never admitted,
/// regardless of the other observations.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_jti_can_be_admitted(mut observation: AdmissionObservation) -> bool {
    observation.jti_revoked = true;
    matches!(plan_admission(observation), AdmissionDecision::Admit)
}

/// Direct theorem used by the F* gate: a device sentinel refuses admission,
/// regardless of the other observations.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_device_can_be_admitted(mut observation: AdmissionObservation) -> bool {
    observation.jti_revoked = false;
    observation.device_revoked = true;
    matches!(plan_admission(observation), AdmissionDecision::Admit)
}

/// Direct theorem used by the F* gate: the durable device-row guard refuses a
/// device-scoped token even when both revocation markers are clear.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_device_row_can_be_admitted(mut observation: AdmissionObservation) -> bool {
    observation.jti_revoked = false;
    observation.device_revoked = false;
    observation.account_present = true;
    observation.device_scoped = true;
    observation.device_row_active = false;
    matches!(plan_admission(observation), AdmissionDecision::Admit)
}

// ── Rust conformance tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const STAGES: [RevocationStage; 7] = [
        RevocationStage::Observe,
        RevocationStage::Lockout,
        RevocationStage::Record,
        RevocationStage::Cascade,
        RevocationStage::RepeatLockout,
        RevocationStage::RepeatCascade,
        RevocationStage::Done,
    ];

    fn events() -> Vec<RevocationEvent> {
        let mut out = Vec::new();
        for observation in [
            DeviceLookupObservation::Absent,
            DeviceLookupObservation::QueryFailed,
            DeviceLookupObservation::Malformed,
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: false,
            }),
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: true,
            }),
            DeviceLookupObservation::Present(TargetObservation {
                same_account: false,
                already_revoked: false,
            }),
        ] {
            out.push(RevocationEvent::TargetObserved(observation));
        }
        for observation in [
            LockoutObservation::Applied,
            LockoutObservation::StorageFailed,
        ] {
            out.push(RevocationEvent::LockoutObserved(observation));
        }
        for observation in [RecordObservation::Updated, RecordObservation::Failed] {
            out.push(RevocationEvent::RecordObserved(observation));
        }
        for observation in [
            CascadeObservation::Completed,
            CascadeObservation::StorageFailed,
        ] {
            out.push(RevocationEvent::CascadeObserved(observation));
        }
        out
    }

    fn sample_driver(stage: RevocationStage) -> RevocationDriver {
        let base = RevocationDriver {
            stage,
            actor_active: true,
            same_account: false,
            already_revoked: false,
            locked_out: false,
            lockout_done: false,
            recorded: false,
            cascade_done: false,
            responded: false,
            failed: false,
        };
        match stage {
            RevocationStage::Observe => base,
            RevocationStage::Lockout => RevocationDriver {
                same_account: true,
                locked_out: true,
                ..base
            },
            RevocationStage::Record => RevocationDriver {
                same_account: true,
                locked_out: true,
                lockout_done: true,
                ..base
            },
            RevocationStage::Cascade => RevocationDriver {
                same_account: true,
                locked_out: true,
                lockout_done: true,
                recorded: true,
                ..base
            },
            RevocationStage::RepeatLockout => RevocationDriver {
                same_account: true,
                already_revoked: true,
                locked_out: true,
                ..base
            },
            RevocationStage::RepeatCascade => RevocationDriver {
                same_account: true,
                already_revoked: true,
                locked_out: true,
                lockout_done: true,
                ..base
            },
            RevocationStage::Done => RevocationDriver {
                failed: true,
                ..base
            },
        }
    }

    #[test]
    fn exhaustive_stage_times_event_is_total_and_sound() {
        for stage in STAGES {
            let driver = sample_driver(stage);
            assert!(
                revocation_state_is_sound(driver),
                "sample driver for {stage:?} is unsound"
            );
            for event in events() {
                let t = step(driver, event);
                assert!(
                    revocation_state_is_sound(t.driver),
                    "soundness lost from {stage:?} on {event:?}"
                );
                assert!(
                    revocation_effect_is_sound(t.driver, t.effect),
                    "effect soundness lost from {stage:?} on {event:?}"
                );
            }
        }
    }

    #[test]
    fn out_of_order_events_are_inert() {
        for stage in STAGES {
            let driver = sample_driver(stage);
            for event in events() {
                let expected = match (stage, &event) {
                    (RevocationStage::Observe, RevocationEvent::TargetObserved(_)) => false,
                    (
                        RevocationStage::Lockout | RevocationStage::RepeatLockout,
                        RevocationEvent::LockoutObserved(_),
                    ) => false,
                    (RevocationStage::Record, RevocationEvent::RecordObserved(_)) => false,
                    (
                        RevocationStage::Cascade | RevocationStage::RepeatCascade,
                        RevocationEvent::CascadeObserved(_),
                    ) => false,
                    _ => true,
                };
                let t = step(driver, event);
                if expected {
                    assert_eq!(t.driver, driver, "non-matching event changed state");
                    assert_eq!(t.effect, RevocationEffect::Idle);
                }
            }
        }
    }

    #[test]
    fn done_is_inert_for_every_event() {
        let mut driver = sample_driver(RevocationStage::Done);
        driver.failed = true;
        for event in events() {
            let t = step(driver, event);
            assert_eq!(t.driver, driver);
            assert_eq!(t.effect, RevocationEffect::Idle);
        }
    }

    #[test]
    fn fresh_revoke_orders_lockout_before_record_before_cascade() {
        let start = begin_revocation(ActorObservation {
            authenticated: true,
            device_active: true,
        });
        assert_eq!(start.effect, RevocationEffect::LookupTarget);

        let t = on_target_looked_up(
            start.driver,
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: false,
            }),
        );
        assert_eq!(t.effect, RevocationEffect::LockoutDevice);
        assert!(!t.driver.recorded);

        let t = on_lockout_completed(t.driver, LockoutObservation::Applied);
        assert_eq!(t.effect, RevocationEffect::RecordRevocation);
        assert!(t.driver.locked_out && t.driver.lockout_done && !t.driver.recorded);

        let t = on_record_completed(t.driver, RecordObservation::Updated);
        assert_eq!(t.effect, RevocationEffect::CascadeWebSessions);
        assert!(t.driver.recorded && !t.driver.cascade_done);

        let t = on_cascade_completed(t.driver, CascadeObservation::Completed);
        assert_eq!(t.effect, RevocationEffect::Complete);
        assert!(t.driver.responded && t.driver.cascade_done && !t.driver.failed);
    }

    #[test]
    fn already_revoked_retry_repeats_lockout_and_cascade_without_record() {
        let start = begin_revocation(ActorObservation {
            authenticated: true,
            device_active: true,
        });
        let t = on_target_looked_up(
            start.driver,
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: true,
            }),
        );
        assert_eq!(t.driver.stage, RevocationStage::RepeatLockout);
        assert_eq!(t.effect, RevocationEffect::LockoutDevice);

        let t = on_lockout_completed(t.driver, LockoutObservation::Applied);
        assert_eq!(t.driver.stage, RevocationStage::RepeatCascade);
        assert_eq!(t.effect, RevocationEffect::CascadeWebSessions);
        assert!(!t.driver.recorded);

        let t = on_cascade_completed(t.driver, CascadeObservation::Completed);
        assert_eq!(
            t.effect,
            RevocationEffect::Fail(RevocationFailure::AlreadyRevoked)
        );
        assert!(t.driver.failed && t.driver.cascade_done && !t.driver.recorded);
    }

    #[test]
    fn cross_account_target_is_refused_without_effects() {
        let start = begin_revocation(ActorObservation {
            authenticated: true,
            device_active: true,
        });
        let t = on_target_looked_up(
            start.driver,
            DeviceLookupObservation::Present(TargetObservation {
                same_account: false,
                already_revoked: false,
            }),
        );
        assert_eq!(
            t.effect,
            RevocationEffect::Fail(RevocationFailure::CrossAccount)
        );
        assert!(!t.driver.locked_out && !t.driver.recorded && !t.driver.cascade_done);
    }

    #[test]
    fn revoked_actor_never_reaches_an_effect() {
        let start = begin_revocation(ActorObservation {
            authenticated: true,
            device_active: false,
        });
        assert_eq!(
            start.effect,
            RevocationEffect::Fail(RevocationFailure::Unauthenticated)
        );
        assert!(!start.driver.actor_active);
        for event in events() {
            let t = step(start.driver, event);
            assert_eq!(t.effect, RevocationEffect::Idle);
        }
    }

    #[test]
    fn every_storage_failure_is_terminal_without_a_record() {
        let start = begin_revocation(ActorObservation {
            authenticated: true,
            device_active: true,
        });
        let lockout_stage = on_target_looked_up(
            start.driver,
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: false,
            }),
        );
        let t = on_lockout_completed(lockout_stage.driver, LockoutObservation::StorageFailed);
        assert_eq!(
            t.effect,
            RevocationEffect::Fail(RevocationFailure::LockoutStorage)
        );
        assert!(!t.driver.recorded);

        let record_stage = on_lockout_completed(lockout_stage.driver, LockoutObservation::Applied);
        let t = on_record_completed(record_stage.driver, RecordObservation::Failed);
        assert_eq!(
            t.effect,
            RevocationEffect::Fail(RevocationFailure::RecordStorage)
        );
        assert!(t.driver.locked_out && t.driver.lockout_done && !t.driver.recorded);

        let cascade_stage = on_record_completed(record_stage.driver, RecordObservation::Updated);
        let t = on_cascade_completed(cascade_stage.driver, CascadeObservation::StorageFailed);
        assert_eq!(
            t.effect,
            RevocationEffect::Fail(RevocationFailure::CascadeStorage)
        );
        assert!(t.driver.recorded && !t.driver.cascade_done);
    }

    /// Breadth-first exploration of every reachable driver state up to a
    /// bounded depth; every reachable state and emitted effect is sound.
    #[test]
    fn bfs_reachable_states_preserve_the_invariant() {
        let start = begin_revocation(ActorObservation {
            authenticated: true,
            device_active: true,
        });
        assert!(revocation_state_is_sound(start.driver));
        let mut frontier = vec![start.driver];
        let mut seen = BTreeSet::new();
        seen.insert(format!("{:?}", start.driver));
        for _ in 0..6 {
            let mut next = Vec::new();
            for driver in frontier {
                for event in events() {
                    let t = step(driver, event);
                    assert!(revocation_state_is_sound(t.driver));
                    assert!(revocation_effect_is_sound(t.driver, t.effect));
                    let key = format!("{:?}", t.driver);
                    if seen.insert(key) {
                        next.push(t.driver);
                    }
                }
            }
            frontier = next;
        }
        assert!(!seen.is_empty());
    }

    #[test]
    fn logout_writes_one_marker_and_is_terminal() {
        let start = begin_logout();
        assert_eq!(start.effect, LogoutEffect::RevokeJti);
        let t = on_logout_completed(start.driver, LogoutObservation::Applied);
        assert_eq!(t.effect, LogoutEffect::Complete);
        assert!(t.driver.jti_revoked && t.driver.responded);
        let t = on_logout_completed(t.driver, LogoutObservation::StorageFailed);
        assert_eq!(t.effect, LogoutEffect::Idle);

        let start = begin_logout();
        let t = on_logout_completed(start.driver, LogoutObservation::StorageFailed);
        assert_eq!(t.effect, LogoutEffect::Fail(LogoutFailure::Storage));
        assert!(!t.driver.jti_revoked && t.driver.failed);
    }

    fn observation() -> AdmissionObservation {
        AdmissionObservation {
            jti_revoked: false,
            device_revoked: false,
            account_present: true,
            device_row_active: true,
            device_scoped: true,
        }
    }

    #[test]
    fn admission_is_exhaustive_and_precedence_is_fixed() {
        for mask in 0u8..32 {
            let observation = AdmissionObservation {
                jti_revoked: mask & 1 != 0,
                device_revoked: mask & 2 != 0,
                account_present: mask & 4 == 0,
                device_row_active: mask & 8 == 0,
                device_scoped: mask & 16 == 0,
            };
            let decision = plan_admission(observation);
            assert!(admission_decision_matches_spec(observation, decision));
            if observation.jti_revoked {
                assert_eq!(
                    decision,
                    AdmissionDecision::Reject(AdmissionRefusal::JtiRevoked)
                );
            } else if observation.device_revoked {
                assert_eq!(
                    decision,
                    AdmissionDecision::Reject(AdmissionRefusal::DeviceRevoked)
                );
            } else if !observation.account_present {
                assert_eq!(
                    decision,
                    AdmissionDecision::Reject(AdmissionRefusal::AccountAbsent)
                );
            } else if observation.device_scoped && !observation.device_row_active {
                assert_eq!(
                    decision,
                    AdmissionDecision::Reject(AdmissionRefusal::DeviceRowRevoked)
                );
            } else {
                assert_eq!(decision, AdmissionDecision::Admit);
            }
        }
        assert!(!revoked_jti_can_be_admitted(observation()));
        assert!(!revoked_device_can_be_admitted(observation()));
        assert!(!revoked_device_row_can_be_admitted(observation()));
        assert_eq!(plan_admission(observation()), AdmissionDecision::Admit);
    }
}
