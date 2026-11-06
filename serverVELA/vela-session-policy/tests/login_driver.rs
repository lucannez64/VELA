//! Exhaustive transition tests for the pure `/auth/verify` decision driver.
//!
//! These tests exercise decision coverage, not the effectful HTTP handler.
//! Handler integration remains in `vela-server/tests`.

use vela_session_policy::challenge::ChallengeConsumption;
use vela_session_policy::login_driver::{
    begin_login, login_effect_is_sound, login_state_is_sound, on_backoff_reset_observed_event,
    on_challenge_taken, on_device_looked_up, on_failure_record_observed, on_token_issue_observed,
    on_token_track_observed, on_verifier_finished, BackoffResetObservation, ChallengeObservation,
    DeviceObservation, FailureRecordObservation, LoginDriver, LoginEffect, LoginEvent,
    LoginFailure, LoginStage, TokenIssueObservation, TokenTrackObservation, VerifierObservation,
};

fn advance(mut driver: LoginDriver, events: &[LoginEvent]) -> (LoginDriver, LoginEffect) {
    let mut effect = LoginEffect::Idle;
    for event in events {
        let transition = match event {
            LoginEvent::ChallengeObserved(observation) => on_challenge_taken(driver, *observation),
            LoginEvent::DeviceObserved(observation) => on_device_looked_up(driver, *observation),
            LoginEvent::VerifierObserved(observation) => on_verifier_finished(driver, *observation),
            LoginEvent::FailureRecorded(observation) => {
                on_failure_record_observed(driver, *observation)
            }
            LoginEvent::BackoffResetObserved(observation) => {
                on_backoff_reset_observed_event(driver, *observation)
            }
            LoginEvent::TokenIssued(observation) => on_token_issue_observed(driver, *observation),
            LoginEvent::TokenTracked(observation) => on_token_track_observed(driver, *observation),
        };
        assert!(
            login_effect_is_sound(transition.driver, transition.effect),
            "step emitted an effect unsupported by its pre-state: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !login_state_is_sound(driver) || login_state_is_sound(transition.driver),
            "step broke the soundness invariant: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn to_device() -> LoginDriver {
    let (driver, effect) = advance(
        begin_login().driver,
        &[LoginEvent::ChallengeObserved(
            ChallengeObservation::Observed(ChallengeConsumption::Accepted),
        )],
    );
    assert_eq!(effect, LoginEffect::ObserveDevice);
    driver
}

fn to_verify() -> LoginDriver {
    let (driver, effect) = advance(
        to_device(),
        &[LoginEvent::DeviceObserved(DeviceObservation::Present)],
    );
    assert_eq!(effect, LoginEffect::VerifySignature);
    driver
}

fn to_record_failure(observation: VerifierObservation) -> LoginDriver {
    let (driver, effect) = advance(to_verify(), &[LoginEvent::VerifierObserved(observation)]);
    assert_eq!(effect, LoginEffect::RecordVerificationFailure);
    driver
}

fn to_reset() -> LoginDriver {
    let (driver, effect) = advance(
        to_verify(),
        &[LoginEvent::VerifierObserved(VerifierObservation::Valid)],
    );
    assert_eq!(effect, LoginEffect::ResetBackoff);
    driver
}

fn to_issue() -> LoginDriver {
    let (driver, effect) = advance(
        to_reset(),
        &[LoginEvent::BackoffResetObserved(
            BackoffResetObservation::Reset,
        )],
    );
    assert_eq!(effect, LoginEffect::IssueToken);
    driver
}

fn to_track() -> LoginDriver {
    let (driver, effect) = advance(
        to_issue(),
        &[LoginEvent::TokenIssued(TokenIssueObservation::Issued)],
    );
    assert_eq!(effect, LoginEffect::TrackToken);
    driver
}

fn success_events() -> Vec<LoginEvent> {
    vec![
        LoginEvent::ChallengeObserved(ChallengeObservation::Observed(
            ChallengeConsumption::Accepted,
        )),
        LoginEvent::DeviceObserved(DeviceObservation::Present),
        LoginEvent::VerifierObserved(VerifierObservation::Valid),
        LoginEvent::BackoffResetObserved(BackoffResetObservation::Reset),
        LoginEvent::TokenIssued(TokenIssueObservation::Issued),
        LoginEvent::TokenTracked(TokenTrackObservation::Tracked),
    ]
}

#[test]
fn begin_requests_the_challenge_take() {
    let transition = begin_login();
    assert_eq!(transition.effect, LoginEffect::ConsumeChallenge);
    assert_eq!(transition.driver.stage, LoginStage::Challenge);
    assert!(login_state_is_sound(transition.driver));
    assert!(!transition.driver.challenge_accepted);
    assert!(!transition.driver.responded);
    assert!(!transition.driver.failed);
}

#[test]
fn successful_login_reaches_exactly_one_response() {
    let (driver, effect) = advance(begin_login().driver, &success_events());
    assert_eq!(effect, LoginEffect::Respond);
    assert!(driver.responded);
    assert!(!driver.failed);
    assert!(driver.challenge_accepted);
    assert!(driver.device_present);
    assert!(driver.verifier_valid);
    assert!(driver.backoff_reset);
    assert!(driver.token_issued);
    assert!(driver.token_tracked);
    assert_eq!(driver.stage, LoginStage::Done);

    // The finished driver is inert for every event, including another success.
    for event in success_events() {
        let (after, effect) = advance(driver, &[event]);
        assert_eq!(after, driver);
        assert_eq!(effect, LoginEffect::Idle);
    }
}

#[test]
fn wrong_purpose_and_missing_challenges_are_terminal_refusals() {
    for (observation, failure) in [
        (
            ChallengeObservation::Observed(ChallengeConsumption::WrongPurpose),
            LoginFailure::ChallengeWrongPurpose,
        ),
        (
            ChallengeObservation::Observed(ChallengeConsumption::Missing),
            LoginFailure::ChallengeMissing,
        ),
        (
            ChallengeObservation::StorageFailed,
            LoginFailure::ChallengeStorage,
        ),
    ] {
        let (driver, effect) = advance(
            begin_login().driver,
            &[LoginEvent::ChallengeObserved(observation)],
        );
        assert_eq!(effect, LoginEffect::Fail(failure));
        assert_eq!(driver.stage, LoginStage::Done);
        assert!(driver.failed);
        assert!(!driver.responded);
        assert!(!driver.challenge_accepted);

        let (after, effect) = advance(driver, &success_events());
        assert_eq!(after, driver);
        assert_eq!(effect, LoginEffect::Idle);
    }
}

#[test]
fn absent_or_undecodable_devices_are_terminal_refusals() {
    for (observation, failure) in [
        (DeviceObservation::Absent, LoginFailure::DeviceUnavailable),
        (
            DeviceObservation::QueryFailed,
            LoginFailure::DeviceQueryStorage,
        ),
        (
            DeviceObservation::ParseFailed,
            LoginFailure::DeviceParseStorage,
        ),
    ] {
        let (driver, effect) = advance(to_device(), &[LoginEvent::DeviceObserved(observation)]);
        assert_eq!(effect, LoginEffect::Fail(failure));
        assert!(driver.failed);
        assert!(!driver.responded);
        assert!(!driver.device_present);
    }
}

#[test]
fn challenge_decode_failure_does_not_touch_the_failure_counter() {
    let (driver, effect) = advance(
        to_verify(),
        &[LoginEvent::VerifierObserved(
            VerifierObservation::ChallengeDecodeFailed,
        )],
    );
    assert_eq!(effect, LoginEffect::Fail(LoginFailure::ChallengeDecode));
    assert!(driver.failed);
    assert!(!driver.responded);
}

#[test]
fn verifier_rejection_requires_the_failure_side_effects_and_never_responds() {
    for (observation, failure) in [
        (
            VerifierObservation::RejectedUnauthorized,
            LoginFailure::VerifierUnauthorized,
        ),
        (
            VerifierObservation::RejectedBadRequest,
            LoginFailure::VerifierBadRequest,
        ),
        (
            VerifierObservation::RejectedInternal,
            LoginFailure::VerifierInternal,
        ),
    ] {
        let (driver, effect) = advance(to_verify(), &[LoginEvent::VerifierObserved(observation)]);
        assert_eq!(effect, LoginEffect::RecordVerificationFailure);
        assert_eq!(driver.stage, LoginStage::RecordFailure);
        assert!(!driver.verifier_valid);

        let (driver, effect) = advance(
            driver,
            &[LoginEvent::FailureRecorded(FailureRecordObservation {
                fallback_counter_ok: true,
            })],
        );
        assert_eq!(effect, LoginEffect::Fail(failure));
        assert!(driver.failed);
        assert!(!driver.responded);
        assert!(!driver.verifier_valid);

        let (after, effect) = advance(driver, &success_events());
        assert_eq!(after, driver);
        assert_eq!(effect, LoginEffect::Idle);
    }
}

#[test]
fn failure_counter_storage_error_is_terminal_and_keeps_precedence() {
    let (driver, effect) = advance(
        to_record_failure(VerifierObservation::RejectedUnauthorized),
        &[LoginEvent::FailureRecorded(FailureRecordObservation {
            fallback_counter_ok: false,
        })],
    );
    assert_eq!(
        effect,
        LoginEffect::Fail(LoginFailure::FailureCounterStorage)
    );
    assert!(driver.failed);
    assert!(!driver.responded);
}

#[test]
fn backoff_reset_and_token_issue_failures_are_terminal_refusals() {
    let (driver, effect) = advance(
        to_reset(),
        &[LoginEvent::BackoffResetObserved(
            BackoffResetObservation::StorageFailed,
        )],
    );
    assert_eq!(effect, LoginEffect::Fail(LoginFailure::BackoffResetStorage));
    assert!(driver.failed);
    assert!(!driver.responded);

    let (driver, effect) = advance(
        to_issue(),
        &[LoginEvent::TokenIssued(TokenIssueObservation::Failed)],
    );
    assert_eq!(effect, LoginEffect::Fail(LoginFailure::TokenIssueFailed));
    assert!(driver.failed);
    assert!(!driver.responded);
    assert!(!driver.token_issued);
}

#[test]
fn tracking_failure_never_responds_even_though_the_token_was_issued() {
    let (driver, effect) = advance(
        to_track(),
        &[LoginEvent::TokenTracked(TokenTrackObservation::Failed)],
    );
    assert_eq!(effect, LoginEffect::Fail(LoginFailure::TrackingFailed));
    assert!(driver.failed);
    assert!(driver.token_issued);
    assert!(!driver.token_tracked);
    assert!(!driver.responded);

    // A later Tracked event cannot rescue the token into a response.
    let (after, effect) = advance(
        driver,
        &[LoginEvent::TokenTracked(TokenTrackObservation::Tracked)],
    );
    assert_eq!(after, driver);
    assert_eq!(effect, LoginEffect::Idle);
}

#[test]
fn out_of_order_events_are_ignored_and_do_not_change_the_driver() {
    let driver = begin_login().driver;
    let events = [
        LoginEvent::DeviceObserved(DeviceObservation::Present),
        LoginEvent::VerifierObserved(VerifierObservation::Valid),
        LoginEvent::BackoffResetObserved(BackoffResetObservation::Reset),
        LoginEvent::TokenIssued(TokenIssueObservation::Issued),
        LoginEvent::TokenTracked(TokenTrackObservation::Tracked),
        LoginEvent::FailureRecorded(FailureRecordObservation {
            fallback_counter_ok: true,
        }),
    ];
    for event in events {
        let (after, effect) = advance(driver, &[event]);
        assert_eq!(after, driver, "{event:?}");
        assert_eq!(effect, LoginEffect::Idle, "{event:?}");
    }
}

#[test]
fn every_stage_is_sound_and_every_event_is_classified() {
    let states = [
        begin_login().driver,
        to_device(),
        to_verify(),
        to_record_failure(VerifierObservation::RejectedUnauthorized),
        to_reset(),
        to_issue(),
        to_track(),
        advance(begin_login().driver, &success_events()).0,
    ];
    let events = [
        LoginEvent::ChallengeObserved(ChallengeObservation::Observed(
            ChallengeConsumption::Accepted,
        )),
        LoginEvent::ChallengeObserved(ChallengeObservation::Observed(
            ChallengeConsumption::WrongPurpose,
        )),
        LoginEvent::ChallengeObserved(ChallengeObservation::StorageFailed),
        LoginEvent::DeviceObserved(DeviceObservation::Present),
        LoginEvent::DeviceObserved(DeviceObservation::Absent),
        LoginEvent::DeviceObserved(DeviceObservation::QueryFailed),
        LoginEvent::DeviceObserved(DeviceObservation::ParseFailed),
        LoginEvent::VerifierObserved(VerifierObservation::Valid),
        LoginEvent::VerifierObserved(VerifierObservation::RejectedUnauthorized),
        LoginEvent::VerifierObserved(VerifierObservation::RejectedBadRequest),
        LoginEvent::VerifierObserved(VerifierObservation::RejectedInternal),
        LoginEvent::VerifierObserved(VerifierObservation::ChallengeDecodeFailed),
        LoginEvent::FailureRecorded(FailureRecordObservation {
            fallback_counter_ok: true,
        }),
        LoginEvent::FailureRecorded(FailureRecordObservation {
            fallback_counter_ok: false,
        }),
        LoginEvent::BackoffResetObserved(BackoffResetObservation::Reset),
        LoginEvent::BackoffResetObserved(BackoffResetObservation::StorageFailed),
        LoginEvent::TokenIssued(TokenIssueObservation::Issued),
        LoginEvent::TokenIssued(TokenIssueObservation::Failed),
        LoginEvent::TokenTracked(TokenTrackObservation::Tracked),
        LoginEvent::TokenTracked(TokenTrackObservation::Failed),
    ];
    for driver in states {
        assert!(login_state_is_sound(driver), "{driver:?}");
        for event in events {
            let (after, effect) = advance(driver, &[event]);
            assert!(
                login_effect_is_sound(after, effect),
                "{driver:?} / {event:?} -> {after:?} / {effect:?}"
            );
            assert!(
                login_state_is_sound(after),
                "{driver:?} / {event:?} -> {after:?}"
            );
        }
    }
}

#[test]
fn a_wrong_purpose_cannot_be_mutated_into_a_success() {
    // Same observations as the successful trace, except the challenge was
    // issued for another purpose. The driver must stop before the device step.
    let mut events = success_events();
    events[0] = LoginEvent::ChallengeObserved(ChallengeObservation::Observed(
        ChallengeConsumption::WrongPurpose,
    ));
    let (driver, effect) = advance(begin_login().driver, &events[..1]);
    assert_eq!(
        effect,
        LoginEffect::Fail(LoginFailure::ChallengeWrongPurpose)
    );
    assert!(!driver.responded);
    assert!(!driver.challenge_accepted);
    assert!(!driver.device_present);
    let (after, effect) = advance(driver, &events[1..]);
    assert_eq!(after, driver);
    assert_eq!(effect, LoginEffect::Idle);
}

#[test]
fn an_invalid_verifier_cannot_be_mutated_into_a_success() {
    // Same observations as the successful trace, except the actual verifier
    // returned a rejection. The driver must enter the failure side effects and
    // never reach issuance, tracking or a response.
    let mut events = success_events();
    events[2] = LoginEvent::VerifierObserved(VerifierObservation::RejectedUnauthorized);
    events.insert(
        3,
        LoginEvent::FailureRecorded(FailureRecordObservation {
            fallback_counter_ok: true,
        }),
    );
    let (driver, effect) = advance(begin_login().driver, &events);
    assert_eq!(effect, LoginEffect::Idle);
    assert!(driver.failed);
    assert!(!driver.responded);
    assert!(!driver.verifier_valid);
    assert!(!driver.token_issued);
    assert!(!driver.token_tracked);
}
