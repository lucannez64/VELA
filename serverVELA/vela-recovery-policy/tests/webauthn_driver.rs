//! Exhaustive transition tests for the pure WebAuthn recovery drivers.
//!
//! These tests exercise decision coverage, not the effectful HTTP handlers.
//! Handler/database conformance remains in `vela-server/tests`.

use vela_recovery_policy::observed_recovery_epoch;
use vela_recovery_policy::webauthn_driver::{
    auth_finish_effect_is_sound, auth_finish_effect_releases_share,
    auth_finish_state_is_sound, auth_start_effect_is_sound, auth_start_state_is_sound,
    begin_auth_finish, begin_auth_start, begin_registration, begin_registration_start,
    on_auth_account_observed, on_auth_assertion_observed, on_auth_attempt_consumed,
    on_auth_ceremony_started, on_auth_credential_updated, on_auth_finish_attempt_counted,
    on_auth_finish_context_observed, on_auth_grant_stored, on_auth_share_observed,
    on_auth_start_observed, on_auth_start_stored, on_credential_looked_up,
    on_credential_persisted, on_registration_attempt_counted, on_registration_ceremony_started,
    on_registration_start_observed, on_registration_start_stored, on_registration_state_consumed,
    on_registration_verified, registration_effect_is_sound, registration_start_effect_is_sound,
    registration_start_state_is_sound, registration_state_is_sound,
    AssertionObservation, AttemptBudgetObservation, AuthAccountObservation,
    AuthAttemptConsumptionObservation, AuthFinishContextObservation, AuthFinishDriver,
    AuthFinishEffect, AuthFinishEvent, AuthFinishFailure, AuthFinishStage,
    AuthStartEffect, AuthStartEvent, AuthStartFailure, AuthStartObservation, AuthStartStage,
    CeremonyStartObservation, ChallengeStoreObservation, CredentialPersistObservation,
    CredentialUniquenessObservation, CredentialUpdateStoreObservation, GrantStoreObservation,
    RegistrationDriver, RegistrationEffect, RegistrationEvent, RegistrationFailure,
    RegistrationStage, RegistrationStartDriver, RegistrationStartEffect, RegistrationStartEvent,
    RegistrationStartFailure, RegistrationStartObservation, RegistrationStartStage,
    RegistrationStateObservation, RegistrationVerificationObservation, ShareDecodeObservation,
    StoredCredentialObservation,
};

// ── Registration start ──────────────────────────────────────────────────────

fn available_start() -> RegistrationStartObservation {
    RegistrationStartObservation {
        account_present: true,
        credential: StoredCredentialObservation::Missing,
    }
}

fn registration_start_events() -> Vec<RegistrationStartEvent> {
    vec![
        RegistrationStartEvent::Observed(available_start()),
        RegistrationStartEvent::Observed(RegistrationStartObservation {
            account_present: false,
            ..available_start()
        }),
        RegistrationStartEvent::Observed(RegistrationStartObservation {
            credential: StoredCredentialObservation::Present,
            ..available_start()
        }),
        RegistrationStartEvent::Observed(RegistrationStartObservation {
            credential: StoredCredentialObservation::Corrupt,
            ..available_start()
        }),
        RegistrationStartEvent::CeremonyStarted(CeremonyStartObservation::Started),
        RegistrationStartEvent::CeremonyStarted(CeremonyStartObservation::Failed),
        RegistrationStartEvent::Stored(ChallengeStoreObservation::Stored),
        RegistrationStartEvent::Stored(ChallengeStoreObservation::Lost),
        RegistrationStartEvent::Stored(ChallengeStoreObservation::StorageFailed),
    ]
}

fn advance_registration_start(
    mut driver: RegistrationStartDriver,
    events: &[RegistrationStartEvent],
) -> (RegistrationStartDriver, RegistrationStartEffect) {
    let mut effect = RegistrationStartEffect::Idle;
    for event in events {
        let transition = match event {
            RegistrationStartEvent::Observed(observation) => {
                on_registration_start_observed(driver, *observation)
            }
            RegistrationStartEvent::CeremonyStarted(observation) => {
                on_registration_ceremony_started(driver, *observation)
            }
            RegistrationStartEvent::Stored(observation) => {
                on_registration_start_stored(driver, *observation)
            }
        };
        assert!(
            registration_start_effect_is_sound(transition.driver, transition.effect),
            "registration-start step emitted an unsupported effect: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !registration_start_state_is_sound(driver)
                || registration_start_state_is_sound(transition.driver),
            "registration-start step broke soundness: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

#[test]
fn registration_start_observes_then_starts_exactly_one_ceremony() {
    let begin = begin_registration_start();
    assert_eq!(begin.effect, RegistrationStartEffect::Observe);
    assert_eq!(begin.driver.stage, RegistrationStartStage::Observe);

    let (driver, effect) = advance_registration_start(
        begin.driver,
        &[RegistrationStartEvent::Observed(available_start())],
    );
    assert_eq!(effect, RegistrationStartEffect::StartCeremony);
    assert_eq!(driver.stage, RegistrationStartStage::Ceremony);

    let (driver, effect) = advance_registration_start(
        driver,
        &[RegistrationStartEvent::CeremonyStarted(
            CeremonyStartObservation::Started,
        )],
    );
    assert_eq!(effect, RegistrationStartEffect::StoreState);
    assert_eq!(driver.stage, RegistrationStartStage::Store);

    let (driver, effect) = advance_registration_start(
        driver,
        &[RegistrationStartEvent::Stored(ChallengeStoreObservation::Stored)],
    );
    assert_eq!(effect, RegistrationStartEffect::Complete);
    assert_eq!(driver.stage, RegistrationStartStage::Done);
    assert!(driver.stored && driver.authorized);
}

#[test]
fn registration_start_rejections_are_terminal_without_authority() {
    for (observation, failure) in [
        (
            RegistrationStartObservation {
                account_present: false,
                ..available_start()
            },
            RegistrationStartFailure::AccountUnavailable,
        ),
        (
            RegistrationStartObservation {
                credential: StoredCredentialObservation::Corrupt,
                ..available_start()
            },
            RegistrationStartFailure::CredentialCorrupt,
        ),
    ] {
        let (driver, effect) = advance_registration_start(
            begin_registration_start().driver,
            &[RegistrationStartEvent::Observed(observation)],
        );
        assert_eq!(
            effect,
            RegistrationStartEffect::Fail(failure),
            "{observation:?}"
        );
        assert_eq!(driver.stage, RegistrationStartStage::Done);
        assert!(!driver.authorized && !driver.stored);
    }
}

#[test]
fn registration_start_or_store_failure_never_claims_success() {
    let (ready, _) = advance_registration_start(
        begin_registration_start().driver,
        &[
            RegistrationStartEvent::Observed(available_start()),
            RegistrationStartEvent::CeremonyStarted(CeremonyStartObservation::Started),
        ],
    );
    for observation in [
        ChallengeStoreObservation::Lost,
        ChallengeStoreObservation::StorageFailed,
    ] {
        let (driver, effect) = advance_registration_start(
            ready,
            &[RegistrationStartEvent::Stored(observation)],
        );
        assert_eq!(
            effect,
            RegistrationStartEffect::Fail(RegistrationStartFailure::StateStorage)
        );
        assert!(!driver.stored);
    }

    let (ceremony_ready, _) = advance_registration_start(
        begin_registration_start().driver,
        &[RegistrationStartEvent::Observed(available_start())],
    );
    let (driver, effect) = advance_registration_start(
        ceremony_ready,
        &[RegistrationStartEvent::CeremonyStarted(
            CeremonyStartObservation::Failed,
        )],
    );
    assert_eq!(
        effect,
        RegistrationStartEffect::Fail(RegistrationStartFailure::CeremonyFailed)
    );
    assert!(!driver.stored);
}

#[test]
fn every_registration_start_stage_ignores_every_out_of_order_event() {
    let (ceremony, _) = advance_registration_start(
        begin_registration_start().driver,
        &[RegistrationStartEvent::Observed(available_start())],
    );
    let (store, _) = advance_registration_start(
        ceremony,
        &[RegistrationStartEvent::CeremonyStarted(
            CeremonyStartObservation::Started,
        )],
    );
    let (done, _) = advance_registration_start(
        store,
        &[RegistrationStartEvent::Stored(ChallengeStoreObservation::Stored)],
    );
    let drivers = [
        begin_registration_start().driver,
        ceremony,
        store,
        done,
    ];
    let expected = [
        RegistrationStartStage::Observe,
        RegistrationStartStage::Ceremony,
        RegistrationStartStage::Store,
        RegistrationStartStage::Done,
    ];
    assert_eq!(
        drivers
            .iter()
            .map(|driver| driver.stage)
            .collect::<Vec<_>>(),
        expected
    );

    for driver in drivers {
        for event in registration_start_events() {
            let in_stage = match (&event, driver.stage) {
                (RegistrationStartEvent::Observed(_), RegistrationStartStage::Observe) => true,
                (RegistrationStartEvent::CeremonyStarted(_), RegistrationStartStage::Ceremony) => {
                    true
                }
                (RegistrationStartEvent::Stored(_), RegistrationStartStage::Store) => true,
                _ => false,
            };
            let transition = match &event {
                RegistrationStartEvent::Observed(observation) => {
                    on_registration_start_observed(driver, *observation)
                }
                RegistrationStartEvent::CeremonyStarted(observation) => {
                    on_registration_ceremony_started(driver, *observation)
                }
                RegistrationStartEvent::Stored(observation) => {
                    on_registration_start_stored(driver, *observation)
                }
            };
            if !in_stage {
                assert_eq!(
                    transition.effect,
                    RegistrationStartEffect::Idle,
                    "{driver:?} / {event:?}"
                );
                assert_eq!(transition.driver, driver, "{driver:?} / {event:?}");
            }
            assert!(
                registration_start_effect_is_sound(transition.driver, transition.effect),
                "{driver:?} / {event:?} -> {transition:?}"
            );
        }
    }
}

// ── Registration finish ─────────────────────────────────────────────────────

fn advance_registration(
    mut driver: RegistrationDriver,
    events: &[RegistrationEvent],
) -> (RegistrationDriver, RegistrationEffect) {
    let mut effect = RegistrationEffect::Idle;
    for event in events {
        let transition = match event {
            RegistrationEvent::AttemptCounted(observation) => {
                on_registration_attempt_counted(driver, *observation)
            }
            RegistrationEvent::StateConsumed(observation) => {
                on_registration_state_consumed(driver, *observation)
            }
            RegistrationEvent::RegistrationVerified(observation) => {
                on_registration_verified(driver, *observation)
            }
            RegistrationEvent::CredentialLookedUp(observation) => {
                on_credential_looked_up(driver, *observation)
            }
            RegistrationEvent::CredentialPersisted(observation) => {
                on_credential_persisted(driver, *observation)
            }
        };
        assert!(
            registration_effect_is_sound(transition.driver, transition.effect),
            "registration step emitted an unsupported effect: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !registration_state_is_sound(driver) || registration_state_is_sound(transition.driver),
            "registration step broke soundness: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn to_registration_verified() -> RegistrationDriver {
    let (driver, effect) = advance_registration(
        begin_registration().driver,
        &[
            RegistrationEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
            RegistrationEvent::StateConsumed(RegistrationStateObservation::Present),
            RegistrationEvent::RegistrationVerified(RegistrationVerificationObservation {
                credential_valid: true,
            }),
        ],
    );
    assert_eq!(effect, RegistrationEffect::CheckCredentialUniqueness);
    driver
}

fn to_registration_persist() -> RegistrationDriver {
    let (driver, effect) = advance_registration(
        to_registration_verified(),
        &[RegistrationEvent::CredentialLookedUp(
            CredentialUniquenessObservation::Unique,
        )],
    );
    assert_eq!(effect, RegistrationEffect::PersistCredential);
    driver
}

fn registration_events() -> Vec<RegistrationEvent> {
    vec![
        RegistrationEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
        RegistrationEvent::AttemptCounted(AttemptBudgetObservation::Limited),
        RegistrationEvent::StateConsumed(RegistrationStateObservation::Missing),
        RegistrationEvent::StateConsumed(RegistrationStateObservation::Corrupt),
        RegistrationEvent::StateConsumed(RegistrationStateObservation::Present),
        RegistrationEvent::RegistrationVerified(RegistrationVerificationObservation {
            credential_valid: true,
        }),
        RegistrationEvent::RegistrationVerified(RegistrationVerificationObservation {
            credential_valid: false,
        }),
        RegistrationEvent::CredentialLookedUp(CredentialUniquenessObservation::Unique),
        RegistrationEvent::CredentialLookedUp(CredentialUniquenessObservation::RegisteredElsewhere),
        RegistrationEvent::CredentialLookedUp(CredentialUniquenessObservation::LookupFailed),
        RegistrationEvent::CredentialPersisted(CredentialPersistObservation::Persisted),
        RegistrationEvent::CredentialPersisted(CredentialPersistObservation::AccountGone),
        RegistrationEvent::CredentialPersisted(CredentialPersistObservation::EncodingFailed),
        RegistrationEvent::CredentialPersisted(CredentialPersistObservation::StorageFailed),
    ]
}

#[test]
fn registration_counts_before_consuming_and_limits_terminally() {
    let (driver, effect) = advance_registration(
        begin_registration().driver,
        &[RegistrationEvent::AttemptCounted(
            AttemptBudgetObservation::Limited,
        )],
    );
    assert_eq!(
        effect,
        RegistrationEffect::Fail(RegistrationFailure::AttemptLimited)
    );
    assert!(!driver.state_consumed && !driver.credential_stored);
}

#[test]
fn registration_state_failures_never_persist() {
    for (observation, failure) in [
        (
            RegistrationStateObservation::Missing,
            RegistrationFailure::StateUnavailable,
        ),
        (
            RegistrationStateObservation::Corrupt,
            RegistrationFailure::StateCorrupt,
        ),
    ] {
        let (driver, _) = advance_registration(
            begin_registration().driver,
            &[RegistrationEvent::AttemptCounted(
                AttemptBudgetObservation::Admitted,
            )],
        );
        let (driver, effect) = advance_registration(
            driver,
            &[RegistrationEvent::StateConsumed(observation)],
        );
        assert_eq!(effect, RegistrationEffect::Fail(failure));
        assert!(!driver.credential_stored);
    }
}

#[test]
fn registration_rejections_preserve_historical_precedence() {
    let (verify_ready, _) = advance_registration(
        begin_registration().driver,
        &[
            RegistrationEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
            RegistrationEvent::StateConsumed(RegistrationStateObservation::Present),
        ],
    );
    let (driver, effect) = advance_registration(
        verify_ready,
        &[RegistrationEvent::RegistrationVerified(
            RegistrationVerificationObservation {
                credential_valid: false,
            },
        )],
    );
    assert_eq!(
        effect,
        RegistrationEffect::Fail(RegistrationFailure::VerificationFailed)
    );
    assert!(!driver.credential_valid && !driver.credential_stored);

    for (observation, failure) in [
        (
            CredentialUniquenessObservation::RegisteredElsewhere,
            RegistrationFailure::UniquenessConflict,
        ),
        (
            CredentialUniquenessObservation::LookupFailed,
            RegistrationFailure::UniquenessStorage,
        ),
    ] {
        let (driver, effect) = advance_registration(
            to_registration_verified(),
            &[RegistrationEvent::CredentialLookedUp(observation)],
        );
        assert_eq!(effect, RegistrationEffect::Fail(failure), "{observation:?}");
        assert!(!driver.permit_issued && !driver.credential_stored);
    }
}

#[test]
fn registration_persist_requires_the_checked_policy_and_is_terminal() {
    let driver = to_registration_persist();
    assert_eq!(driver.stage, RegistrationStage::Persist);
    assert!(driver.permit_issued && driver.credential_valid && driver.credential_unique);

    let (driver, effect) = advance_registration(
        driver,
        &[RegistrationEvent::CredentialPersisted(
            CredentialPersistObservation::Persisted,
        )],
    );
    assert_eq!(effect, RegistrationEffect::Complete);
    assert!(driver.credential_stored && driver.stage == RegistrationStage::Done);

    for event in registration_events() {
        let (after, effect) = advance_registration(driver, &[event]);
        assert_eq!(effect, RegistrationEffect::Idle, "{event:?}");
        assert_eq!(after, driver, "{event:?}");
    }
}

#[test]
fn registration_persist_failures_never_report_success() {
    for (observation, failure) in [
        (
            CredentialPersistObservation::AccountGone,
            RegistrationFailure::AccountGone,
        ),
        (
            CredentialPersistObservation::EncodingFailed,
            RegistrationFailure::PersistEncoding,
        ),
        (
            CredentialPersistObservation::StorageFailed,
            RegistrationFailure::PersistStorage,
        ),
    ] {
        let (driver, effect) = advance_registration(
            to_registration_persist(),
            &[RegistrationEvent::CredentialPersisted(observation)],
        );
        assert_eq!(effect, RegistrationEffect::Fail(failure), "{observation:?}");
        assert!(!driver.credential_stored);
    }
}

#[test]
fn no_reachable_registration_transition_persists_without_a_policy_permit() {
    let mut frontier = vec![begin_registration().driver];
    let events = registration_events();
    let mut persists = Vec::new();
    for _ in 0..10 {
        let mut next = Vec::new();
        for driver in &frontier {
            for event in &events {
                let transition = match event {
                    RegistrationEvent::AttemptCounted(observation) => {
                        on_registration_attempt_counted(*driver, *observation)
                    }
                    RegistrationEvent::StateConsumed(observation) => {
                        on_registration_state_consumed(*driver, *observation)
                    }
                    RegistrationEvent::RegistrationVerified(observation) => {
                        on_registration_verified(*driver, *observation)
                    }
                    RegistrationEvent::CredentialLookedUp(observation) => {
                        on_credential_looked_up(*driver, *observation)
                    }
                    RegistrationEvent::CredentialPersisted(observation) => {
                        on_credential_persisted(*driver, *observation)
                    }
                };
                if let RegistrationEffect::PersistCredential = transition.effect {
                    assert!(
                        transition.driver.state_consumed
                            && transition.driver.budget_counted
                            && transition.driver.credential_valid
                            && transition.driver.credential_unique
                            && transition.driver.permit_issued
                            && transition.driver.stage == RegistrationStage::Persist,
                        "persist without a checked policy permit: {driver:?}"
                    );
                    persists.push(transition.driver);
                }
                if !next.contains(&transition.driver) {
                    next.push(transition.driver);
                }
            }
        }
        frontier = next;
    }
    assert!(!persists.is_empty(), "the persist path was never reachable");
}

// ── Authentication start ────────────────────────────────────────────────────

fn available_auth_start() -> AuthStartObservation {
    AuthStartObservation {
        account_present: true,
        share_present: true,
        credential: StoredCredentialObservation::Present,
        attempt_id_fresh: true,
        ttl_secs: 300,
    }
}

fn advance_auth_start(
    mut driver: vela_recovery_policy::webauthn_driver::AuthStartDriver,
    events: &[AuthStartEvent],
) -> (
    vela_recovery_policy::webauthn_driver::AuthStartDriver,
    AuthStartEffect,
) {
    let mut effect = AuthStartEffect::Idle;
    for event in events {
        let transition = match event {
            AuthStartEvent::Observed(observation) => on_auth_start_observed(driver, *observation),
            AuthStartEvent::CeremonyStarted(observation) => {
                on_auth_ceremony_started(driver, *observation)
            }
            AuthStartEvent::Stored(observation) => on_auth_start_stored(driver, *observation),
        };
        assert!(
            auth_start_effect_is_sound(transition.driver, transition.effect),
            "auth-start step emitted an unsupported effect: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !auth_start_state_is_sound(driver) || auth_start_state_is_sound(transition.driver),
            "auth-start step broke soundness: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn auth_start_events() -> Vec<AuthStartEvent> {
    vec![
        AuthStartEvent::Observed(available_auth_start()),
        AuthStartEvent::Observed(AuthStartObservation {
            account_present: false,
            ..available_auth_start()
        }),
        AuthStartEvent::Observed(AuthStartObservation {
            share_present: false,
            ..available_auth_start()
        }),
        AuthStartEvent::Observed(AuthStartObservation {
            credential: StoredCredentialObservation::Missing,
            ..available_auth_start()
        }),
        AuthStartEvent::Observed(AuthStartObservation {
            credential: StoredCredentialObservation::Corrupt,
            ..available_auth_start()
        }),
        AuthStartEvent::Observed(AuthStartObservation {
            attempt_id_fresh: false,
            ..available_auth_start()
        }),
        AuthStartEvent::Observed(AuthStartObservation {
            ttl_secs: 0,
            ..available_auth_start()
        }),
        AuthStartEvent::CeremonyStarted(CeremonyStartObservation::Started),
        AuthStartEvent::CeremonyStarted(CeremonyStartObservation::Failed),
        AuthStartEvent::Stored(ChallengeStoreObservation::Stored),
        AuthStartEvent::Stored(ChallengeStoreObservation::Lost),
        AuthStartEvent::Stored(ChallengeStoreObservation::StorageFailed),
    ]
}

#[test]
fn auth_start_rejections_preserve_historical_precedence() {
    for (observation, failure) in [
        (
            AuthStartObservation {
                account_present: false,
                ..available_auth_start()
            },
            AuthStartFailure::AccountUnavailable,
        ),
        (
            AuthStartObservation {
                share_present: false,
                ..available_auth_start()
            },
            AuthStartFailure::ShareMissing,
        ),
        (
            AuthStartObservation {
                credential: StoredCredentialObservation::Missing,
                ..available_auth_start()
            },
            AuthStartFailure::CredentialMissing,
        ),
        (
            AuthStartObservation {
                credential: StoredCredentialObservation::Corrupt,
                ..available_auth_start()
            },
            AuthStartFailure::CredentialCorrupt,
        ),
        (
            AuthStartObservation {
                attempt_id_fresh: false,
                ..available_auth_start()
            },
            AuthStartFailure::AttemptCollision,
        ),
        (
            AuthStartObservation {
                ttl_secs: 0,
                ..available_auth_start()
            },
            AuthStartFailure::PolicyRejected,
        ),
    ] {
        let (driver, effect) = advance_auth_start(
            begin_auth_start().driver,
            &[AuthStartEvent::Observed(observation)],
        );
        assert_eq!(effect, AuthStartEffect::Fail(failure), "{observation:?}");
        assert_eq!(driver.stage, AuthStartStage::Done);
        assert!(!driver.authorized && !driver.stored);
    }
}

#[test]
fn auth_start_success_and_races_never_claim_a_second_challenge() {
    let (driver, effect) = advance_auth_start(
        begin_auth_start().driver,
        &[AuthStartEvent::Observed(available_auth_start())],
    );
    assert_eq!(effect, AuthStartEffect::StartCeremony);
    let (driver, effect) = advance_auth_start(
        driver,
        &[AuthStartEvent::CeremonyStarted(
            CeremonyStartObservation::Started,
        )],
    );
    assert_eq!(effect, AuthStartEffect::StoreChallenge);
    for (observation, failure) in [
        (
            ChallengeStoreObservation::Lost,
            AuthStartFailure::AttemptCollision,
        ),
        (
            ChallengeStoreObservation::StorageFailed,
            AuthStartFailure::StateStorage,
        ),
    ] {
        let (after, effect) =
            advance_auth_start(driver, &[AuthStartEvent::Stored(observation)]);
        assert_eq!(effect, AuthStartEffect::Fail(failure));
        assert!(!after.stored);
    }
    let (after, effect) = advance_auth_start(
        driver,
        &[AuthStartEvent::Stored(ChallengeStoreObservation::Stored)],
    );
    assert_eq!(effect, AuthStartEffect::Complete);
    assert!(after.stored);
    for event in auth_start_events() {
        let (idle, effect) = advance_auth_start(after, &[event]);
        assert_eq!(effect, AuthStartEffect::Idle, "{event:?}");
        assert_eq!(idle, after, "{event:?}");
    }
}

// ── Authentication finish ───────────────────────────────────────────────────

fn available_context() -> AuthFinishContextObservation {
    AuthFinishContextObservation {
        account_present: true,
        share_present: true,
        credential: StoredCredentialObservation::Present,
        attempt_id_present: true,
    }
}

fn matched_attempt() -> AuthAttemptConsumptionObservation {
    AuthAttemptConsumptionObservation::Present {
        user_matches: true,
        attempt_matches: true,
        credential_matches: true,
    }
}

fn verified_assertion() -> AssertionObservation {
    AssertionObservation {
        assertion_valid: true,
        user_verified: true,
        credential_matches: true,
        needs_update: false,
    }
}

fn active_account() -> AuthAccountObservation {
    AuthAccountObservation {
        account_present: true,
        account_epoch_active: true,
        share_present: true,
        stored_credential_matches: true,
        stored_epoch: Some(3),
    }
}

fn advance_auth_finish(
    mut driver: AuthFinishDriver,
    events: &[AuthFinishEvent],
) -> (AuthFinishDriver, AuthFinishEffect) {
    let mut effect = AuthFinishEffect::Idle;
    for event in events {
        let transition = match event {
            AuthFinishEvent::AttemptCounted(observation) => {
                on_auth_finish_attempt_counted(driver, *observation)
            }
            AuthFinishEvent::ContextObserved(observation) => {
                on_auth_finish_context_observed(driver, *observation)
            }
            AuthFinishEvent::AttemptConsumed(observation) => {
                on_auth_attempt_consumed(driver, *observation)
            }
            AuthFinishEvent::AssertionObserved(observation) => {
                on_auth_assertion_observed(driver, *observation)
            }
            AuthFinishEvent::CredentialUpdated(observation) => {
                on_auth_credential_updated(driver, *observation)
            }
            AuthFinishEvent::AccountObserved(observation) => {
                on_auth_account_observed(driver, *observation)
            }
            AuthFinishEvent::ShareObserved(observation) => {
                on_auth_share_observed(driver, *observation)
            }
            AuthFinishEvent::GrantStored(observation) => on_auth_grant_stored(driver, *observation),
        };
        assert!(
            auth_finish_effect_is_sound(transition.driver, transition.effect),
            "auth-finish step emitted an unsupported effect: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !auth_finish_state_is_sound(driver) || auth_finish_state_is_sound(transition.driver),
            "auth-finish step broke soundness: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn to_auth_verify() -> AuthFinishDriver {
    let (driver, effect) = advance_auth_finish(
        begin_auth_finish().driver,
        &[
            AuthFinishEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
            AuthFinishEvent::ContextObserved(available_context()),
            AuthFinishEvent::AttemptConsumed(matched_attempt()),
        ],
    );
    assert_eq!(effect, AuthFinishEffect::VerifyAssertion);
    driver
}

fn to_auth_account() -> AuthFinishDriver {
    let (driver, effect) =
        advance_auth_finish(to_auth_verify(), &[AuthFinishEvent::AssertionObserved(
            verified_assertion(),
        )]);
    assert_eq!(effect, AuthFinishEffect::QueryAccount);
    driver
}

fn to_auth_update() -> AuthFinishDriver {
    let (driver, effect) = advance_auth_finish(
        to_auth_verify(),
        &[AuthFinishEvent::AssertionObserved(AssertionObservation {
            needs_update: true,
            ..verified_assertion()
        })],
    );
    assert_eq!(effect, AuthFinishEffect::UpdateCredential);
    driver
}

fn to_auth_release() -> AuthFinishDriver {
    let (driver, effect) = advance_auth_finish(
        to_auth_account(),
        &[AuthFinishEvent::AccountObserved(active_account())],
    );
    assert!(matches!(effect, AuthFinishEffect::ReleaseGrant(_)));
    driver
}

fn to_auth_store() -> AuthFinishDriver {
    let (driver, effect) = advance_auth_finish(
        to_auth_release(),
        &[AuthFinishEvent::ShareObserved(
            ShareDecodeObservation::Decoded,
        )],
    );
    assert_eq!(effect, AuthFinishEffect::StoreGrant);
    driver
}

fn auth_finish_events() -> Vec<AuthFinishEvent> {
    vec![
        AuthFinishEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
        AuthFinishEvent::AttemptCounted(AttemptBudgetObservation::Limited),
        AuthFinishEvent::ContextObserved(available_context()),
        AuthFinishEvent::ContextObserved(AuthFinishContextObservation {
            account_present: false,
            ..available_context()
        }),
        AuthFinishEvent::ContextObserved(AuthFinishContextObservation {
            share_present: false,
            ..available_context()
        }),
        AuthFinishEvent::ContextObserved(AuthFinishContextObservation {
            credential: StoredCredentialObservation::Missing,
            ..available_context()
        }),
        AuthFinishEvent::ContextObserved(AuthFinishContextObservation {
            credential: StoredCredentialObservation::Corrupt,
            ..available_context()
        }),
        AuthFinishEvent::ContextObserved(AuthFinishContextObservation {
            attempt_id_present: false,
            ..available_context()
        }),
        AuthFinishEvent::AttemptConsumed(AuthAttemptConsumptionObservation::Missing),
        AuthFinishEvent::AttemptConsumed(AuthAttemptConsumptionObservation::Corrupt),
        AuthFinishEvent::AttemptConsumed(AuthAttemptConsumptionObservation::Present {
            user_matches: false,
            attempt_matches: true,
            credential_matches: true,
        }),
        AuthFinishEvent::AttemptConsumed(AuthAttemptConsumptionObservation::Present {
            user_matches: true,
            attempt_matches: true,
            credential_matches: false,
        }),
        AuthFinishEvent::AttemptConsumed(matched_attempt()),
        AuthFinishEvent::AssertionObserved(verified_assertion()),
        AuthFinishEvent::AssertionObserved(AssertionObservation {
            assertion_valid: false,
            ..verified_assertion()
        }),
        AuthFinishEvent::AssertionObserved(AssertionObservation {
            user_verified: false,
            ..verified_assertion()
        }),
        AuthFinishEvent::AssertionObserved(AssertionObservation {
            credential_matches: false,
            ..verified_assertion()
        }),
        AuthFinishEvent::AssertionObserved(AssertionObservation {
            needs_update: true,
            ..verified_assertion()
        }),
        AuthFinishEvent::CredentialUpdated(CredentialUpdateStoreObservation::Updated),
        AuthFinishEvent::CredentialUpdated(CredentialUpdateStoreObservation::Changed),
        AuthFinishEvent::AccountObserved(active_account()),
        AuthFinishEvent::AccountObserved(AuthAccountObservation {
            account_present: false,
            ..active_account()
        }),
        AuthFinishEvent::AccountObserved(AuthAccountObservation {
            account_epoch_active: false,
            ..active_account()
        }),
        AuthFinishEvent::AccountObserved(AuthAccountObservation {
            share_present: false,
            ..active_account()
        }),
        AuthFinishEvent::AccountObserved(AuthAccountObservation {
            stored_credential_matches: false,
            ..active_account()
        }),
        AuthFinishEvent::AccountObserved(AuthAccountObservation {
            stored_epoch: Some(4),
            ..active_account()
        }),
        AuthFinishEvent::ShareObserved(ShareDecodeObservation::Decoded),
        AuthFinishEvent::ShareObserved(ShareDecodeObservation::Corrupt),
        AuthFinishEvent::GrantStored(GrantStoreObservation::Stored),
        AuthFinishEvent::GrantStored(GrantStoreObservation::Failed),
    ]
}

#[test]
fn auth_finish_begins_by_counting_the_attempt() {
    let begin = begin_auth_finish();
    assert_eq!(begin.effect, AuthFinishEffect::CountAttempt);
    assert_eq!(begin.driver.stage, AuthFinishStage::Attempt);
    assert!(auth_finish_state_is_sound(begin.driver));
    assert!(auth_finish_effect_is_sound(begin.driver, begin.effect));
    assert!(!auth_finish_effect_releases_share(begin.effect));
}

#[test]
fn auth_finish_requires_an_admitted_attempt_before_consuming() {
    let (driver, effect) = advance_auth_finish(
        begin_auth_finish().driver,
        &[AuthFinishEvent::AttemptCounted(
            AttemptBudgetObservation::Limited,
        )],
    );
    assert_eq!(
        effect,
        AuthFinishEffect::Fail(AuthFinishFailure::AttemptLimited)
    );
    assert!(!driver.budget_counted && !driver.attempt_consumed);

    let (driver, effect) = advance_auth_finish(
        begin_auth_finish().driver,
        &[AuthFinishEvent::AttemptCounted(
            AttemptBudgetObservation::Admitted,
        )],
    );
    assert_eq!(effect, AuthFinishEffect::ObserveContext);
    assert_eq!(driver.stage, AuthFinishStage::Context);
    assert!(driver.budget_counted && !driver.context_observed);
}

#[test]
fn auth_finish_context_rejections_preserve_historical_precedence() {
    let (budgeted, _) = advance_auth_finish(
        begin_auth_finish().driver,
        &[AuthFinishEvent::AttemptCounted(
            AttemptBudgetObservation::Admitted,
        )],
    );
    for (observation, failure) in [
        (
            AuthFinishContextObservation {
                account_present: false,
                ..available_context()
            },
            AuthFinishFailure::AccountUnavailable,
        ),
        (
            AuthFinishContextObservation {
                share_present: false,
                ..available_context()
            },
            AuthFinishFailure::ShareMissing,
        ),
        (
            AuthFinishContextObservation {
                credential: StoredCredentialObservation::Missing,
                ..available_context()
            },
            AuthFinishFailure::CredentialMissing,
        ),
        (
            AuthFinishContextObservation {
                credential: StoredCredentialObservation::Corrupt,
                ..available_context()
            },
            AuthFinishFailure::CredentialCorrupt,
        ),
        (
            AuthFinishContextObservation {
                attempt_id_present: false,
                ..available_context()
            },
            AuthFinishFailure::AttemptIdMissing,
        ),
    ] {
        let (driver, effect) = advance_auth_finish(
            budgeted,
            &[AuthFinishEvent::ContextObserved(observation)],
        );
        assert_eq!(effect, AuthFinishEffect::Fail(failure), "{observation:?}");
        assert!(!driver.attempt_consumed && !driver.grant_issued);
    }
}

#[test]
fn auth_finish_consumption_failures_are_terminal_and_never_rearm() {
    for (observation, failure) in [
        (
            AuthAttemptConsumptionObservation::Missing,
            AuthFinishFailure::AttemptMissing,
        ),
        (
            AuthAttemptConsumptionObservation::Corrupt,
            AuthFinishFailure::AttemptCorrupt,
        ),
        (
            AuthAttemptConsumptionObservation::Present {
                user_matches: false,
                attempt_matches: true,
                credential_matches: true,
            },
            AuthFinishFailure::BindingMismatch,
        ),
        (
            AuthAttemptConsumptionObservation::Present {
                user_matches: true,
                attempt_matches: true,
                credential_matches: false,
            },
            AuthFinishFailure::ChallengeCredentialReplaced,
        ),
    ] {
        let (driver, effect) = advance_auth_finish(
            {
                let (driver, _) = advance_auth_finish(
                    begin_auth_finish().driver,
                    &[
                        AuthFinishEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
                        AuthFinishEvent::ContextObserved(available_context()),
                    ],
                );
                driver
            },
            &[AuthFinishEvent::AttemptConsumed(observation)],
        );
        assert_eq!(effect, AuthFinishEffect::Fail(failure), "{observation:?}");
        assert_eq!(driver.stage, AuthFinishStage::Done);
        assert!(!driver.grant_issued);
    }
}

#[test]
fn auth_finish_assertion_rejections_never_reach_the_live_row() {
    for (observation, failure) in [
        (
            AssertionObservation {
                assertion_valid: false,
                ..verified_assertion()
            },
            AuthFinishFailure::AssertionInvalid,
        ),
        (
            AssertionObservation {
                user_verified: false,
                ..verified_assertion()
            },
            AuthFinishFailure::UserVerificationRequired,
        ),
        (
            AssertionObservation {
                credential_matches: false,
                ..verified_assertion()
            },
            AuthFinishFailure::AssertionCredentialMismatch,
        ),
    ] {
        let (driver, effect) =
            advance_auth_finish(to_auth_verify(), &[AuthFinishEvent::AssertionObserved(observation)]);
        assert_eq!(effect, AuthFinishEffect::Fail(failure), "{observation:?}");
        assert_eq!(driver.stage, AuthFinishStage::Done);
        assert!(!driver.account_present && !driver.grant_issued);
    }
}

#[test]
fn auth_finish_metadata_update_must_complete_before_the_row() {
    let (driver, effect) = advance_auth_finish(
        to_auth_update(),
        &[AuthFinishEvent::CredentialUpdated(
            CredentialUpdateStoreObservation::Updated,
        )],
    );
    assert_eq!(effect, AuthFinishEffect::QueryAccount);
    assert!(driver.credential_updated && driver.credential_update_needed);
    assert_eq!(driver.stage, AuthFinishStage::Account);

    let (driver, effect) = advance_auth_finish(
        to_auth_update(),
        &[AuthFinishEvent::CredentialUpdated(
            CredentialUpdateStoreObservation::Changed,
        )],
    );
    assert_eq!(
        effect,
        AuthFinishEffect::Fail(AuthFinishFailure::CredentialUpdateMismatch)
    );
    assert!(!driver.credential_updated && !driver.grant_issued);
}

#[test]
fn auth_finish_release_requires_every_live_fact() {
    for (observation, failure) in [
        (
            AuthAccountObservation {
                account_present: false,
                ..active_account()
            },
            AuthFinishFailure::AccountAbsent,
        ),
        (
            AuthAccountObservation {
                account_epoch_active: false,
                ..active_account()
            },
            AuthFinishFailure::RotationPaused,
        ),
        (
            AuthAccountObservation {
                stored_credential_matches: false,
                ..active_account()
            },
            AuthFinishFailure::StoredCredentialMismatch,
        ),
        (
            AuthAccountObservation {
                share_present: false,
                ..active_account()
            },
            AuthFinishFailure::ShareMissing,
        ),
    ] {
        let (driver, effect) = advance_auth_finish(
            to_auth_account(),
            &[AuthFinishEvent::AccountObserved(observation)],
        );
        assert_eq!(effect, AuthFinishEffect::Fail(failure), "{observation:?}");
        assert!(!driver.grant_issued);
    }

    // A verified assertion at a non-positive stored epoch is normalized to the
    // initial epoch and may still release; the permit carries that epoch.
    let (driver, effect) = advance_auth_finish(
        to_auth_account(),
        &[AuthFinishEvent::AccountObserved(AuthAccountObservation {
            stored_epoch: Some(0),
            ..active_account()
        })],
    );
    match effect {
        AuthFinishEffect::ReleaseGrant(permit) => {
            assert_eq!(permit.epoch, 1);
            assert_eq!(permit.epoch, observed_recovery_epoch(Some(0)));
        }
        other => panic!("expected a release, got {other:?}"),
    }
    assert!(driver.grant_issued);
}

#[test]
fn auth_finish_release_carries_the_live_epoch_and_never_share_bytes() {
    let (driver, effect) = advance_auth_finish(
        to_auth_account(),
        &[AuthFinishEvent::AccountObserved(active_account())],
    );
    match effect {
        AuthFinishEffect::ReleaseGrant(permit) => {
            assert_eq!(permit.epoch, 3);
            assert_eq!(
                permit.epoch,
                observed_recovery_epoch(driver.stored_epoch)
            );
        }
        other => panic!("expected a release, got {other:?}"),
    }
    assert!(driver.grant_issued);
    assert!(auth_finish_effect_releases_share(effect));
    // Only the release effect is share-carrying.
    for effect in [
        AuthFinishEffect::CountAttempt,
        AuthFinishEffect::ObserveContext,
        AuthFinishEffect::ConsumeAttempt,
        AuthFinishEffect::VerifyAssertion,
        AuthFinishEffect::UpdateCredential,
        AuthFinishEffect::QueryAccount,
        AuthFinishEffect::StoreGrant,
        AuthFinishEffect::Complete,
        AuthFinishEffect::Fail(AuthFinishFailure::PolicyRejected),
        AuthFinishEffect::Idle,
    ] {
        assert!(!auth_finish_effect_releases_share(effect), "{effect:?}");
    }
}

#[test]
fn auth_finish_share_and_grant_outcomes_are_terminal_success_or_failure() {
    let (driver, effect) = advance_auth_finish(
        to_auth_release(),
        &[AuthFinishEvent::ShareObserved(
            ShareDecodeObservation::Corrupt,
        )],
    );
    assert_eq!(
        effect,
        AuthFinishEffect::Fail(AuthFinishFailure::ShareCorrupt)
    );
    assert!(driver.grant_issued && !driver.share_decoded && !driver.grant_stored);

    let (driver, effect) = advance_auth_finish(
        to_auth_store(),
        &[AuthFinishEvent::GrantStored(GrantStoreObservation::Stored)],
    );
    assert_eq!(effect, AuthFinishEffect::Complete);
    assert!(driver.grant_stored && driver.stage == AuthFinishStage::Done);
    for event in auth_finish_events() {
        let (after, effect) = advance_auth_finish(driver, &[event]);
        assert_eq!(effect, AuthFinishEffect::Idle, "{event:?}");
        assert_eq!(after, driver, "{event:?}");
    }

    let (driver, effect) = advance_auth_finish(
        to_auth_store(),
        &[AuthFinishEvent::GrantStored(GrantStoreObservation::Failed)],
    );
    assert_eq!(
        effect,
        AuthFinishEffect::Fail(AuthFinishFailure::GrantStorage)
    );
    assert!(driver.grant_issued && !driver.grant_stored);
}

#[test]
fn every_auth_finish_stage_ignores_every_out_of_order_event() {
    let drivers = [
        begin_auth_finish().driver,
        {
            let (driver, _) = advance_auth_finish(
                begin_auth_finish().driver,
                &[AuthFinishEvent::AttemptCounted(
                    AttemptBudgetObservation::Admitted,
                )],
            );
            driver
        },
        {
            let (driver, _) = advance_auth_finish(
                begin_auth_finish().driver,
                &[
                    AuthFinishEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
                    AuthFinishEvent::ContextObserved(available_context()),
                ],
            );
            driver
        },
        to_auth_verify(),
        to_auth_update(),
        to_auth_account(),
        to_auth_release(),
        to_auth_store(),
        {
            let (driver, _) = advance_auth_finish(
                to_auth_store(),
                &[AuthFinishEvent::GrantStored(GrantStoreObservation::Stored)],
            );
            driver
        },
    ];
    let expected = [
        AuthFinishStage::Attempt,
        AuthFinishStage::Context,
        AuthFinishStage::Consume,
        AuthFinishStage::Verify,
        AuthFinishStage::Update,
        AuthFinishStage::Account,
        AuthFinishStage::Release,
        AuthFinishStage::Store,
        AuthFinishStage::Done,
    ];
    assert_eq!(
        drivers
            .iter()
            .map(|driver| driver.stage)
            .collect::<Vec<_>>(),
        expected
    );

    for driver in drivers {
        for event in auth_finish_events() {
            let in_stage = match (&event, driver.stage) {
                (AuthFinishEvent::AttemptCounted(_), AuthFinishStage::Attempt) => true,
                (AuthFinishEvent::ContextObserved(_), AuthFinishStage::Context) => true,
                (AuthFinishEvent::AttemptConsumed(_), AuthFinishStage::Consume) => true,
                (AuthFinishEvent::AssertionObserved(_), AuthFinishStage::Verify) => true,
                (AuthFinishEvent::CredentialUpdated(_), AuthFinishStage::Update) => true,
                (AuthFinishEvent::AccountObserved(_), AuthFinishStage::Account) => true,
                (AuthFinishEvent::ShareObserved(_), AuthFinishStage::Release) => true,
                (AuthFinishEvent::GrantStored(_), AuthFinishStage::Store) => true,
                _ => false,
            };
            let transition = match &event {
                AuthFinishEvent::AttemptCounted(observation) => {
                    on_auth_finish_attempt_counted(driver, *observation)
                }
                AuthFinishEvent::ContextObserved(observation) => {
                    on_auth_finish_context_observed(driver, *observation)
                }
                AuthFinishEvent::AttemptConsumed(observation) => {
                    on_auth_attempt_consumed(driver, *observation)
                }
                AuthFinishEvent::AssertionObserved(observation) => {
                    on_auth_assertion_observed(driver, *observation)
                }
                AuthFinishEvent::CredentialUpdated(observation) => {
                    on_auth_credential_updated(driver, *observation)
                }
                AuthFinishEvent::AccountObserved(observation) => {
                    on_auth_account_observed(driver, *observation)
                }
                AuthFinishEvent::ShareObserved(observation) => {
                    on_auth_share_observed(driver, *observation)
                }
                AuthFinishEvent::GrantStored(observation) => {
                    on_auth_grant_stored(driver, *observation)
                }
            };
            if !in_stage {
                assert_eq!(
                    transition.effect,
                    AuthFinishEffect::Idle,
                    "{driver:?} / {event:?}"
                );
                assert_eq!(transition.driver, driver, "{driver:?} / {event:?}");
            }
            assert!(
                auth_finish_effect_is_sound(transition.driver, transition.effect),
                "{driver:?} / {event:?} -> {transition:?}"
            );
        }
    }
}

#[test]
fn no_reachable_transition_releases_without_a_verified_current_credential() {
    let mut frontier = vec![begin_auth_finish().driver];
    let events = auth_finish_events();
    let mut releases = Vec::new();
    for _ in 0..14 {
        let mut next = Vec::new();
        for driver in &frontier {
            for event in &events {
                let transition = match event {
                    AuthFinishEvent::AttemptCounted(observation) => {
                        on_auth_finish_attempt_counted(*driver, *observation)
                    }
                    AuthFinishEvent::ContextObserved(observation) => {
                        on_auth_finish_context_observed(*driver, *observation)
                    }
                    AuthFinishEvent::AttemptConsumed(observation) => {
                        on_auth_attempt_consumed(*driver, *observation)
                    }
                    AuthFinishEvent::AssertionObserved(observation) => {
                        on_auth_assertion_observed(*driver, *observation)
                    }
                    AuthFinishEvent::CredentialUpdated(observation) => {
                        on_auth_credential_updated(*driver, *observation)
                    }
                    AuthFinishEvent::AccountObserved(observation) => {
                        on_auth_account_observed(*driver, *observation)
                    }
                    AuthFinishEvent::ShareObserved(observation) => {
                        on_auth_share_observed(*driver, *observation)
                    }
                    AuthFinishEvent::GrantStored(observation) => {
                        on_auth_grant_stored(*driver, *observation)
                    }
                };
                if let AuthFinishEffect::ReleaseGrant(permit) = transition.effect {
                    assert!(
                        transition.driver.attempt_consumed
                            && transition.driver.user_matches
                            && transition.driver.attempt_matches
                            && transition.driver.challenge_credential_matches
                            && transition.driver.assertion_valid
                            && transition.driver.user_verified
                            && transition.driver.assertion_credential_matches
                            && (!transition.driver.credential_update_needed
                                || transition.driver.credential_updated)
                            && transition.driver.account_present
                            && transition.driver.account_epoch_active
                            && transition.driver.share_present
                            && transition.driver.stored_credential_matches
                            && transition.driver.stage == AuthFinishStage::Release,
                        "release without a verified current credential: {driver:?}"
                    );
                    assert_eq!(
                        permit.epoch,
                        observed_recovery_epoch(transition.driver.stored_epoch)
                    );
                    releases.push(transition.driver);
                }
                if !next.contains(&transition.driver) {
                    next.push(transition.driver);
                }
            }
        }
        frontier = next;
    }
    assert!(!releases.is_empty(), "the release path was never reachable");
    // No later release: from a released state the only success is a stored
    // grant, and every event after it is inert.
    for driver in releases {
        let (after, effect) = advance_auth_finish(
            driver,
            &[AuthFinishEvent::ShareObserved(
                ShareDecodeObservation::Decoded,
            )],
        );
        assert_eq!(effect, AuthFinishEffect::StoreGrant);
        let (after, effect) = advance_auth_finish(
            after,
            &[AuthFinishEvent::GrantStored(GrantStoreObservation::Stored)],
        );
        assert_eq!(effect, AuthFinishEffect::Complete);
        for event in auth_finish_events() {
            let (_, effect) = advance_auth_finish(after, &[event]);
            assert_eq!(effect, AuthFinishEffect::Idle);
        }
    }
}
