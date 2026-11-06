//! Pure `/auth/verify` decision driver.
//!
//! `post_verify` in `vela-server` performs the effectful steps: the per-IP
//! limiter and backoff precheck, the atomic challenge `get_del`, the device row
//! query, base64 decoding, the hybrid signature verification, the failure
//! counter/backoff side effects, the streak reset, the `last_active` update,
//! PASETO issuance and JTI tracking. This module owns every *decision* between
//! those effects:
//!
//! 1. the challenge take must be a matching `login` tag (the actual pure
//!    classifier in [`crate::challenge`] is the authority);
//! 2. an unrevoked device row must have been observed;
//! 3. the actual verifier result must be valid;
//! 4. the backoff reset observation must have succeeded;
//! 5. a token may be issued;
//! 6. the issued token must be tracked before any response;
//! 7. a response is emitted at most once and never after a terminal failure.
//!
//! The transition relation is total: invalid or out-of-order events are
//! ignored (`LoginEffect::Idle`), so the unbounded trace induction in
//! `proofs/fstar/login-driver-lemmas` quantifies over every event list, not
//! only the handler's intended order.
//!
//! The driver is a per-request value. It does not observe the store or SQL
//! database itself, and it does not coordinate concurrent requests. The
//! `get_del` atomicity, the SQL row/guard semantics, the verifier and PASETO
//! cryptography, the clock and the store effects remain explicit trusted
//! observations/effects outside this module. In particular this driver does
//! not claim device-revocation or token-issuance linearization.

use crate::challenge::ChallengeConsumption;

/// Where the login is in its decision sequence. Each stage names the effect
/// the handler may perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginStage {
    /// Take the challenge and classify its stored tag.
    Challenge,
    /// Query the unrevoked device row.
    Device,
    /// Decode the challenge and run the actual verifier.
    Verify,
    /// The verifier rejected; perform the failure-counter/backoff side effects.
    RecordFailure,
    /// Reset the success streak/backoff.
    Reset,
    /// Issue the PASETO token.
    Issue,
    /// Track the issued JTI before responding.
    Track,
    /// A terminal response or failure was decided. Later events are ignored.
    Done,
}

/// Observation from the atomic challenge take. `StorageFailed` is the
/// `get_del` error; the handler still holds the original error for rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeObservation {
    Observed(ChallengeConsumption),
    StorageFailed,
}

/// Observation from the device lookup. `Present` means the query returned a
/// row with `revoked = 0` and it decoded into a device. `Absent` is the
/// historical uniform authentication failure; the other two preserve the
/// handler's internal-error precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceObservation {
    Present,
    Absent,
    QueryFailed,
    ParseFailed,
}

/// The verifier failure class, retained until the failure side effects have
/// been observed. `None` means no verifier rejection is pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierFailure {
    None,
    Unauthorized,
    BadRequest,
    Internal,
}

/// Observation from the actual verifier. `Valid` is the only successful
/// result. `ChallengeDecodeFailed` is the handler's base64 decode failure,
/// which occurs before the verifier and does not touch the failure counter
/// (matching the historical order). The three rejection classes preserve the
/// handler's status/message precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierObservation {
    Valid,
    RejectedUnauthorized,
    RejectedBadRequest,
    RejectedInternal,
    ChallengeDecodeFailed,
}

/// Observation after the handler performed the rejection side effects.
/// `record_verify_failure` is attempted and its error is only logged, so it
/// cannot change the decision; `fallback_counter_ok` is the result of the
/// request-level `verify_fail_by_device` limiter, which the handler still
/// propagates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureRecordObservation {
    pub fallback_counter_ok: bool,
}

/// Observation from the success-streak/backoff reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackoffResetObservation {
    Reset,
    StorageFailed,
}

/// Observation from PASETO issuance. Issuance itself is the existing
/// `TokenService::issue`, which uses the verified `plan_device_token` policy;
/// the driver treats the result as a trusted observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenIssueObservation {
    Issued,
    Failed,
}

/// Observation from JTI tracking. A failed track must not produce a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenTrackObservation {
    Tracked,
    Failed,
}

/// One driver event. The handler feeds exactly the observation it obtained from
/// the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginEvent {
    ChallengeObserved(ChallengeObservation),
    DeviceObserved(DeviceObservation),
    VerifierObserved(VerifierObservation),
    FailureRecorded(FailureRecordObservation),
    BackoffResetObserved(BackoffResetObservation),
    TokenIssued(TokenIssueObservation),
    TokenTracked(TokenTrackObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders each category with the original error where
/// the error text is not a fixed authentication message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginFailure {
    ChallengeMissing,
    ChallengeWrongPurpose,
    ChallengeStorage,
    DeviceUnavailable,
    DeviceQueryStorage,
    DeviceParseStorage,
    ChallengeDecode,
    VerifierUnauthorized,
    VerifierBadRequest,
    VerifierInternal,
    FailureCounterStorage,
    BackoffResetStorage,
    TokenIssueFailed,
    TrackingFailed,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginEffect {
    /// Perform the atomic challenge take and classify it.
    ConsumeChallenge,
    /// Query the unrevoked device row.
    ObserveDevice,
    /// Decode the challenge and run the actual verifier.
    VerifySignature,
    /// Record the failed proof (log-only exponential backoff) and apply the
    /// request-level failure limiter.
    RecordVerificationFailure,
    /// Reset the success streak and backoff.
    ResetBackoff,
    /// Issue the PASETO token.
    IssueToken,
    /// Track the issued JTI.
    TrackToken,
    /// Return the token response. This is the only effect that authorizes a
    /// response.
    Respond,
    /// Terminal failure without a response.
    Fail(LoginFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store, SQL row or verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoginDriver {
    pub stage: LoginStage,
    /// The challenge take accepted this consumer's purpose.
    pub challenge_accepted: bool,
    /// The device query observed a present, unrevoked, decoded device row.
    pub device_present: bool,
    /// The actual verifier returned success.
    pub verifier_valid: bool,
    /// The pending verifier rejection class while the failure side effects are
    /// outstanding; `None` otherwise.
    pub verifier_failure: VerifierFailure,
    /// The success-streak/backoff reset succeeded.
    pub backoff_reset: bool,
    /// PASETO issuance succeeded.
    pub token_issued: bool,
    /// The issued JTI was tracked.
    pub token_tracked: bool,
    /// A response was authorized.
    pub responded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoginTransition {
    pub driver: LoginDriver,
    pub effect: LoginEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn login_state_is_sound(d: LoginDriver) -> bool {
    let no_pending_verifier_failure = matches!(d.verifier_failure, VerifierFailure::None);
    let challenge_clean = !d.challenge_accepted
        && !d.device_present
        && !d.verifier_valid
        && no_pending_verifier_failure
        && !d.backoff_reset
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let device_clean = d.challenge_accepted
        && !d.device_present
        && !d.verifier_valid
        && no_pending_verifier_failure
        && !d.backoff_reset
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let verify_clean = d.challenge_accepted
        && d.device_present
        && !d.verifier_valid
        && no_pending_verifier_failure
        && !d.backoff_reset
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let record_clean = d.challenge_accepted
        && d.device_present
        && !d.verifier_valid
        && !no_pending_verifier_failure
        && !d.backoff_reset
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let reset_clean = d.challenge_accepted
        && d.device_present
        && d.verifier_valid
        && no_pending_verifier_failure
        && !d.backoff_reset
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let issue_clean = d.challenge_accepted
        && d.device_present
        && d.verifier_valid
        && no_pending_verifier_failure
        && d.backoff_reset
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let track_clean = d.challenge_accepted
        && d.device_present
        && d.verifier_valid
        && no_pending_verifier_failure
        && d.backoff_reset
        && d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let done_clean = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded
            || (d.challenge_accepted
                && d.device_present
                && d.verifier_valid
                && no_pending_verifier_failure
                && d.backoff_reset
                && d.token_issued
                && d.token_tracked));
    (!matches!(d.stage, LoginStage::Challenge) || challenge_clean)
        && (!matches!(d.stage, LoginStage::Device) || device_clean)
        && (!matches!(d.stage, LoginStage::Verify) || verify_clean)
        && (!matches!(d.stage, LoginStage::RecordFailure) || record_clean)
        && (!matches!(d.stage, LoginStage::Reset) || reset_clean)
        && (!matches!(d.stage, LoginStage::Issue) || issue_clean)
        && (!matches!(d.stage, LoginStage::Track) || track_clean)
        && (!matches!(d.stage, LoginStage::Done) || done_clean)
        && (!d.device_present || d.challenge_accepted)
        && (!d.verifier_valid || d.device_present)
        && (!d.backoff_reset || d.verifier_valid)
        && (!d.token_issued || d.backoff_reset)
        && (!d.token_tracked || d.token_issued)
        && (!d.responded || d.token_tracked)
        && (!d.failed || !d.responded)
        && (no_pending_verifier_failure || !d.verifier_valid)
}

/// Every effect agrees with the state it produces. In particular `Respond`
/// requires a tracked token, an accepted matching-purpose challenge, a present
/// device, a valid verifier result and a successful backoff reset.
pub fn login_effect_is_sound(d: LoginDriver, effect: LoginEffect) -> bool {
    let no_pending_verifier_failure = matches!(d.verifier_failure, VerifierFailure::None);
    match effect {
        LoginEffect::ConsumeChallenge => {
            matches!(d.stage, LoginStage::Challenge)
                && !d.challenge_accepted
                && !d.device_present
                && !d.verifier_valid
                && no_pending_verifier_failure
                && !d.backoff_reset
                && !d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        LoginEffect::ObserveDevice => {
            matches!(d.stage, LoginStage::Device)
                && d.challenge_accepted
                && !d.device_present
                && !d.verifier_valid
                && no_pending_verifier_failure
                && !d.backoff_reset
                && !d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        LoginEffect::VerifySignature => {
            matches!(d.stage, LoginStage::Verify)
                && d.challenge_accepted
                && d.device_present
                && !d.verifier_valid
                && no_pending_verifier_failure
                && !d.backoff_reset
                && !d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        LoginEffect::RecordVerificationFailure => {
            matches!(d.stage, LoginStage::RecordFailure)
                && d.challenge_accepted
                && d.device_present
                && !d.verifier_valid
                && !no_pending_verifier_failure
                && !d.backoff_reset
                && !d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        LoginEffect::ResetBackoff => {
            matches!(d.stage, LoginStage::Reset)
                && d.challenge_accepted
                && d.device_present
                && d.verifier_valid
                && no_pending_verifier_failure
                && !d.backoff_reset
                && !d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        LoginEffect::IssueToken => {
            matches!(d.stage, LoginStage::Issue)
                && d.challenge_accepted
                && d.device_present
                && d.verifier_valid
                && no_pending_verifier_failure
                && d.backoff_reset
                && !d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        LoginEffect::TrackToken => {
            matches!(d.stage, LoginStage::Track)
                && d.challenge_accepted
                && d.device_present
                && d.verifier_valid
                && no_pending_verifier_failure
                && d.backoff_reset
                && d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        LoginEffect::Respond => {
            matches!(d.stage, LoginStage::Done)
                && d.challenge_accepted
                && d.device_present
                && d.verifier_valid
                && no_pending_verifier_failure
                && d.backoff_reset
                && d.token_issued
                && d.token_tracked
                && d.responded
                && !d.failed
        }
        LoginEffect::Fail(_) => matches!(d.stage, LoginStage::Done) && d.failed && !d.responded,
        LoginEffect::Idle => true,
    }
}

fn transition(driver: LoginDriver, effect: LoginEffect) -> LoginTransition {
    LoginTransition { driver, effect }
}

fn idle(driver: LoginDriver) -> LoginTransition {
    transition(driver, LoginEffect::Idle)
}

fn terminal(driver: LoginDriver, failure: LoginFailure) -> LoginTransition {
    transition(
        LoginDriver {
            stage: LoginStage::Done,
            failed: true,
            ..driver
        },
        LoginEffect::Fail(failure),
    )
}

/// The pending verifier class. `None` is unreachable from `RecordFailure`
/// (the state invariant excludes it); mapping it to `VerifierInternal` keeps
/// the total transition relation total without weakening the checked path.
fn pending_verifier_failure(value: VerifierFailure) -> LoginFailure {
    match value {
        VerifierFailure::Unauthorized => LoginFailure::VerifierUnauthorized,
        VerifierFailure::BadRequest => LoginFailure::VerifierBadRequest,
        VerifierFailure::Internal | VerifierFailure::None => LoginFailure::VerifierInternal,
    }
}

/// Start a per-request login. Only the challenge take may be attempted.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_state_is_sound(result.driver)
        && login_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, LoginStage::Challenge)
        && !result.driver.challenge_accepted
        && !result.driver.device_present
        && !result.driver.verifier_valid
        && !result.driver.backoff_reset
        && !result.driver.token_issued
        && !result.driver.token_tracked
        && !result.driver.responded
        && !result.driver.failed
}))]
pub fn begin_login() -> LoginTransition {
    transition(
        LoginDriver {
            stage: LoginStage::Challenge,
            challenge_accepted: false,
            device_present: false,
            verifier_valid: false,
            verifier_failure: VerifierFailure::None,
            backoff_reset: false,
            token_issued: false,
            token_tracked: false,
            responded: false,
            failed: false,
        },
        LoginEffect::ConsumeChallenge,
    )
}

fn on_challenge_observed(
    driver: LoginDriver,
    observation: ChallengeObservation,
) -> LoginTransition {
    match observation {
        ChallengeObservation::Observed(ChallengeConsumption::Accepted) => transition(
            LoginDriver {
                stage: LoginStage::Device,
                challenge_accepted: true,
                ..driver
            },
            LoginEffect::ObserveDevice,
        ),
        ChallengeObservation::Observed(ChallengeConsumption::Missing) => {
            terminal(driver, LoginFailure::ChallengeMissing)
        }
        ChallengeObservation::Observed(ChallengeConsumption::WrongPurpose) => {
            terminal(driver, LoginFailure::ChallengeWrongPurpose)
        }
        ChallengeObservation::StorageFailed => terminal(driver, LoginFailure::ChallengeStorage),
    }
}

fn on_device_observed(driver: LoginDriver, observation: DeviceObservation) -> LoginTransition {
    match observation {
        DeviceObservation::Present => transition(
            LoginDriver {
                stage: LoginStage::Verify,
                device_present: true,
                ..driver
            },
            LoginEffect::VerifySignature,
        ),
        DeviceObservation::Absent => terminal(driver, LoginFailure::DeviceUnavailable),
        DeviceObservation::QueryFailed => terminal(driver, LoginFailure::DeviceQueryStorage),
        DeviceObservation::ParseFailed => terminal(driver, LoginFailure::DeviceParseStorage),
    }
}

fn on_verifier_observed(driver: LoginDriver, observation: VerifierObservation) -> LoginTransition {
    match observation {
        VerifierObservation::Valid => transition(
            LoginDriver {
                stage: LoginStage::Reset,
                verifier_valid: true,
                verifier_failure: VerifierFailure::None,
                ..driver
            },
            LoginEffect::ResetBackoff,
        ),
        VerifierObservation::RejectedUnauthorized => transition(
            LoginDriver {
                stage: LoginStage::RecordFailure,
                verifier_valid: false,
                verifier_failure: VerifierFailure::Unauthorized,
                ..driver
            },
            LoginEffect::RecordVerificationFailure,
        ),
        VerifierObservation::RejectedBadRequest => transition(
            LoginDriver {
                stage: LoginStage::RecordFailure,
                verifier_valid: false,
                verifier_failure: VerifierFailure::BadRequest,
                ..driver
            },
            LoginEffect::RecordVerificationFailure,
        ),
        VerifierObservation::RejectedInternal => transition(
            LoginDriver {
                stage: LoginStage::RecordFailure,
                verifier_valid: false,
                verifier_failure: VerifierFailure::Internal,
                ..driver
            },
            LoginEffect::RecordVerificationFailure,
        ),
        VerifierObservation::ChallengeDecodeFailed => {
            terminal(driver, LoginFailure::ChallengeDecode)
        }
    }
}

fn on_failure_recorded(
    driver: LoginDriver,
    observation: FailureRecordObservation,
) -> LoginTransition {
    if observation.fallback_counter_ok {
        terminal(driver, pending_verifier_failure(driver.verifier_failure))
    } else {
        terminal(driver, LoginFailure::FailureCounterStorage)
    }
}

fn on_backoff_reset_observed(
    driver: LoginDriver,
    observation: BackoffResetObservation,
) -> LoginTransition {
    match observation {
        BackoffResetObservation::Reset => transition(
            LoginDriver {
                stage: LoginStage::Issue,
                backoff_reset: true,
                ..driver
            },
            LoginEffect::IssueToken,
        ),
        BackoffResetObservation::StorageFailed => {
            terminal(driver, LoginFailure::BackoffResetStorage)
        }
    }
}

fn on_token_issued(driver: LoginDriver, observation: TokenIssueObservation) -> LoginTransition {
    match observation {
        TokenIssueObservation::Issued => transition(
            LoginDriver {
                stage: LoginStage::Track,
                token_issued: true,
                ..driver
            },
            LoginEffect::TrackToken,
        ),
        TokenIssueObservation::Failed => terminal(driver, LoginFailure::TokenIssueFailed),
    }
}

fn on_token_tracked(driver: LoginDriver, observation: TokenTrackObservation) -> LoginTransition {
    match observation {
        TokenTrackObservation::Tracked => transition(
            LoginDriver {
                stage: LoginStage::Done,
                token_tracked: true,
                responded: true,
                ..driver
            },
            LoginEffect::Respond,
        ),
        TokenTrackObservation::Failed => terminal(driver, LoginFailure::TrackingFailed),
    }
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn step(driver: LoginDriver, event: LoginEvent) -> LoginTransition {
    match event {
        LoginEvent::ChallengeObserved(observation) => {
            if matches!(driver.stage, LoginStage::Challenge) {
                on_challenge_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        LoginEvent::DeviceObserved(observation) => {
            if matches!(driver.stage, LoginStage::Device) {
                on_device_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        LoginEvent::VerifierObserved(observation) => {
            if matches!(driver.stage, LoginStage::Verify) {
                on_verifier_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        LoginEvent::FailureRecorded(observation) => {
            if matches!(driver.stage, LoginStage::RecordFailure) {
                on_failure_recorded(driver, observation)
            } else {
                idle(driver)
            }
        }
        LoginEvent::BackoffResetObserved(observation) => {
            if matches!(driver.stage, LoginStage::Reset) {
                on_backoff_reset_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        LoginEvent::TokenIssued(observation) => {
            if matches!(driver.stage, LoginStage::Issue) {
                on_token_issued(driver, observation)
            } else {
                idle(driver)
            }
        }
        LoginEvent::TokenTracked(observation) => {
            if matches!(driver.stage, LoginStage::Track) {
                on_token_tracked(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn on_challenge_taken(
    driver: LoginDriver,
    observation: ChallengeObservation,
) -> LoginTransition {
    step(driver, LoginEvent::ChallengeObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn on_device_looked_up(driver: LoginDriver, observation: DeviceObservation) -> LoginTransition {
    step(driver, LoginEvent::DeviceObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn on_verifier_finished(
    driver: LoginDriver,
    observation: VerifierObservation,
) -> LoginTransition {
    step(driver, LoginEvent::VerifierObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn on_failure_record_observed(
    driver: LoginDriver,
    observation: FailureRecordObservation,
) -> LoginTransition {
    step(driver, LoginEvent::FailureRecorded(observation))
}

#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn on_backoff_reset_observed_event(
    driver: LoginDriver,
    observation: BackoffResetObservation,
) -> LoginTransition {
    step(driver, LoginEvent::BackoffResetObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn on_token_issue_observed(
    driver: LoginDriver,
    observation: TokenIssueObservation,
) -> LoginTransition {
    step(driver, LoginEvent::TokenIssued(observation))
}

#[cfg_attr(hax, hax_lib::requires(login_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    login_effect_is_sound(result.driver, result.effect)
        && (!login_state_is_sound(driver) || login_state_is_sound(result.driver))
}))]
pub fn on_token_track_observed(
    driver: LoginDriver,
    observation: TokenTrackObservation,
) -> LoginTransition {
    step(driver, LoginEvent::TokenTracked(observation))
}
