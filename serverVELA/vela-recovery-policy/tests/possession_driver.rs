//! Exhaustive transition tests for the pure possession-proof recovery drivers.
//!
//! These tests exercise decision coverage, not the effectful HTTP handlers.
//! Handler/database conformance remains in `vela-server/tests`.

use vela_recovery_policy::possession_driver::{
    begin_initiation, begin_proof_recover, initiation_effect_is_sound, initiation_state_is_sound,
    on_account_observed, on_attempt_consumed, on_attempt_counted, on_challenge_stored,
    on_grant_stored, on_initiation_observed, on_proof_observed, proof_recover_effect_is_sound,
    proof_recover_effect_releases_share, proof_recover_state_is_sound, AttemptBudgetObservation,
    AttemptConsumptionObservation, ChallengeStoreObservation, CommitmentObservation,
    GrantStoreObservation, InitiateEffect, InitiateEvent, InitiateFailure, InitiateObservation,
    InitiateStage, InitiationDriver, ProofAccountObservation, ProofObservation, ProofRecoverDriver,
    ProofRecoverEffect, ProofRecoverEvent, ProofRecoverFailure, ProofRecoverStage,
};

// ── Initiation helpers ──────────────────────────────────────────────────────

fn available_commitment() -> CommitmentObservation {
    CommitmentObservation::Present { len: 32 }
}

fn available_initiation() -> InitiateObservation {
    InitiateObservation {
        account_present: true,
        share_present: true,
        commitment: available_commitment(),
        rotation_active: false,
        attempt_id_fresh: true,
        ttl_secs: 300,
    }
}

fn initiation_events() -> Vec<InitiateEvent> {
    vec![
        InitiateEvent::Observed(available_initiation()),
        InitiateEvent::Observed(InitiateObservation {
            account_present: false,
            ..available_initiation()
        }),
        InitiateEvent::Observed(InitiateObservation {
            share_present: false,
            ..available_initiation()
        }),
        InitiateEvent::Observed(InitiateObservation {
            commitment: CommitmentObservation::Missing,
            ..available_initiation()
        }),
        InitiateEvent::Observed(InitiateObservation {
            commitment: CommitmentObservation::Corrupt,
            ..available_initiation()
        }),
        InitiateEvent::Observed(InitiateObservation {
            commitment: CommitmentObservation::Present { len: 0 },
            ..available_initiation()
        }),
        InitiateEvent::Observed(InitiateObservation {
            rotation_active: true,
            ..available_initiation()
        }),
        InitiateEvent::Observed(InitiateObservation {
            attempt_id_fresh: false,
            ..available_initiation()
        }),
        InitiateEvent::Observed(InitiateObservation {
            ttl_secs: 0,
            ..available_initiation()
        }),
        InitiateEvent::Stored(ChallengeStoreObservation::Stored),
        InitiateEvent::Stored(ChallengeStoreObservation::Lost),
    ]
}

fn advance_initiation(
    mut driver: InitiationDriver,
    events: &[InitiateEvent],
) -> (InitiationDriver, InitiateEffect) {
    let mut effect = InitiateEffect::Idle;
    for event in events {
        let transition = match event {
            InitiateEvent::Observed(observation) => on_initiation_observed(driver, *observation),
            InitiateEvent::Stored(observation) => on_challenge_stored(driver, *observation),
        };
        assert!(
            initiation_effect_is_sound(transition.driver, transition.effect),
            "initiation step emitted an unsupported effect: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !initiation_state_is_sound(driver) || initiation_state_is_sound(transition.driver),
            "initiation step broke soundness: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn initiation_store_ready() -> InitiationDriver {
    let (driver, effect) = advance_initiation(
        begin_initiation().driver,
        &[InitiateEvent::Observed(available_initiation())],
    );
    assert_eq!(effect, InitiateEffect::StoreChallenge);
    driver
}

#[test]
fn initiation_begins_by_observing_and_carries_no_authority() {
    let transition = begin_initiation();
    assert_eq!(transition.effect, InitiateEffect::Observe);
    assert_eq!(transition.driver.stage, InitiateStage::Observe);
    assert!(!transition.driver.authorized);
    assert!(!transition.driver.stored);
    assert!(initiation_state_is_sound(transition.driver));
    assert!(initiation_effect_is_sound(
        transition.driver,
        transition.effect
    ));
}

#[test]
fn complete_initiation_observation_authorizes_exactly_one_store() {
    let driver = initiation_store_ready();
    assert_eq!(driver.stage, InitiateStage::Store);
    assert!(driver.authorized && !driver.stored);

    let (driver, effect) = advance_initiation(
        driver,
        &[InitiateEvent::Stored(ChallengeStoreObservation::Stored)],
    );
    assert_eq!(effect, InitiateEffect::Complete);
    assert_eq!(driver.stage, InitiateStage::Done);
    assert!(driver.stored);
}

#[test]
fn initiation_rejections_preserve_historical_precedence() {
    for (observation, failure) in [
        (
            InitiateObservation {
                account_present: false,
                ..available_initiation()
            },
            InitiateFailure::AccountUnavailable,
        ),
        (
            InitiateObservation {
                rotation_active: true,
                share_present: false,
                ..available_initiation()
            },
            InitiateFailure::RotationPaused,
        ),
        (
            InitiateObservation {
                share_present: false,
                ..available_initiation()
            },
            InitiateFailure::ShareMissing,
        ),
        (
            InitiateObservation {
                commitment: CommitmentObservation::Missing,
                ..available_initiation()
            },
            InitiateFailure::CommitmentMissing,
        ),
        (
            InitiateObservation {
                commitment: CommitmentObservation::Corrupt,
                ..available_initiation()
            },
            InitiateFailure::CommitmentCorrupt,
        ),
        (
            InitiateObservation {
                commitment: CommitmentObservation::Present { len: 0 },
                ..available_initiation()
            },
            InitiateFailure::CommitmentMissing,
        ),
        (
            InitiateObservation {
                attempt_id_fresh: false,
                ..available_initiation()
            },
            InitiateFailure::AttemptCollision,
        ),
        (
            InitiateObservation {
                ttl_secs: 0,
                ..available_initiation()
            },
            InitiateFailure::PolicyRejected,
        ),
    ] {
        let (driver, effect) = advance_initiation(
            begin_initiation().driver,
            &[InitiateEvent::Observed(observation)],
        );
        assert_eq!(effect, InitiateEffect::Fail(failure), "{observation:?}");
        assert_eq!(driver.stage, InitiateStage::Done);
        assert!(!driver.stored, "{observation:?}");
    }
}

#[test]
fn a_lost_store_race_is_terminal_and_does_not_claim_success() {
    let (driver, effect) = advance_initiation(
        initiation_store_ready(),
        &[InitiateEvent::Stored(ChallengeStoreObservation::Lost)],
    );
    assert_eq!(
        effect,
        InitiateEffect::Fail(InitiateFailure::AttemptCollision)
    );
    assert_eq!(driver.stage, InitiateStage::Done);
    assert!(!driver.stored);
}

// ── Proof-recovery helpers ──────────────────────────────────────────────────

fn begin_consuming() -> ProofRecoverDriver {
    let (driver, effect) = advance_proof_recover(
        begin_proof_recover().driver,
        &[ProofRecoverEvent::AttemptCounted(
            AttemptBudgetObservation::Admitted,
        )],
    );
    assert_eq!(effect, ProofRecoverEffect::ConsumeAttempt);
    driver
}

fn matched_attempt() -> AttemptConsumptionObservation {
    AttemptConsumptionObservation::Present {
        user_matches: true,
        attempt_matches: true,
        key_epoch: 3,
    }
}

fn active_account() -> ProofAccountObservation {
    ProofAccountObservation {
        account_present: true,
        account_epoch_active: true,
        commitment: CommitmentObservation::Present { len: 2624 },
        stored_epoch: Some(3),
    }
}

fn advance_proof_recover(
    mut driver: ProofRecoverDriver,
    events: &[ProofRecoverEvent],
) -> (ProofRecoverDriver, ProofRecoverEffect) {
    let mut effect = ProofRecoverEffect::Idle;
    for event in events {
        let transition = match event {
            ProofRecoverEvent::AttemptCounted(observation) => {
                on_attempt_counted(driver, *observation)
            }
            ProofRecoverEvent::AttemptConsumed(observation) => {
                on_attempt_consumed(driver, *observation)
            }
            ProofRecoverEvent::AccountObserved(observation) => {
                on_account_observed(driver, *observation)
            }
            ProofRecoverEvent::ProofObserved(observation) => {
                on_proof_observed(driver, *observation)
            }
            ProofRecoverEvent::GrantStored(observation) => on_grant_stored(driver, *observation),
        };
        assert!(
            proof_recover_effect_is_sound(transition.driver, transition.effect),
            "proof step emitted an unsupported effect: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !proof_recover_effect_releases_share(transition.effect),
            "proof step attempted to release the server share: {transition:?}"
        );
        assert!(
            !proof_recover_state_is_sound(driver)
                || proof_recover_state_is_sound(transition.driver),
            "proof step broke soundness: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn to_live() -> ProofRecoverDriver {
    let (driver, effect) = advance_proof_recover(
        begin_consuming(),
        &[ProofRecoverEvent::AttemptConsumed(matched_attempt())],
    );
    assert_eq!(effect, ProofRecoverEffect::QueryAccount);
    driver
}

fn to_verify() -> ProofRecoverDriver {
    let (driver, effect) = advance_proof_recover(
        to_live(),
        &[ProofRecoverEvent::AccountObserved(active_account())],
    );
    assert_eq!(effect, ProofRecoverEffect::VerifyProof);
    driver
}

fn to_issue() -> ProofRecoverDriver {
    let (driver, effect) = advance_proof_recover(
        to_verify(),
        &[ProofRecoverEvent::ProofObserved(ProofObservation {
            verified: true,
        })],
    );
    assert!(matches!(effect, ProofRecoverEffect::IssueGrant(_)));
    driver
}

fn proof_recover_events() -> Vec<ProofRecoverEvent> {
    vec![
        ProofRecoverEvent::AttemptCounted(AttemptBudgetObservation::Admitted),
        ProofRecoverEvent::AttemptCounted(AttemptBudgetObservation::Limited),
        ProofRecoverEvent::AttemptConsumed(AttemptConsumptionObservation::Missing),
        ProofRecoverEvent::AttemptConsumed(AttemptConsumptionObservation::Corrupt),
        ProofRecoverEvent::AttemptConsumed(AttemptConsumptionObservation::Present {
            user_matches: false,
            attempt_matches: true,
            key_epoch: 3,
        }),
        ProofRecoverEvent::AttemptConsumed(AttemptConsumptionObservation::Present {
            user_matches: true,
            attempt_matches: false,
            key_epoch: 3,
        }),
        ProofRecoverEvent::AttemptConsumed(matched_attempt()),
        ProofRecoverEvent::AccountObserved(active_account()),
        ProofRecoverEvent::AccountObserved(ProofAccountObservation {
            account_present: false,
            ..active_account()
        }),
        ProofRecoverEvent::AccountObserved(ProofAccountObservation {
            account_epoch_active: false,
            ..active_account()
        }),
        ProofRecoverEvent::AccountObserved(ProofAccountObservation {
            commitment: CommitmentObservation::Missing,
            ..active_account()
        }),
        ProofRecoverEvent::AccountObserved(ProofAccountObservation {
            commitment: CommitmentObservation::Corrupt,
            ..active_account()
        }),
        ProofRecoverEvent::AccountObserved(ProofAccountObservation {
            commitment: CommitmentObservation::Present { len: 0 },
            ..active_account()
        }),
        ProofRecoverEvent::AccountObserved(ProofAccountObservation {
            stored_epoch: Some(4),
            ..active_account()
        }),
        ProofRecoverEvent::ProofObserved(ProofObservation { verified: true }),
        ProofRecoverEvent::ProofObserved(ProofObservation { verified: false }),
        ProofRecoverEvent::GrantStored(GrantStoreObservation::Stored),
        ProofRecoverEvent::GrantStored(GrantStoreObservation::Failed),
    ]
}

#[test]
fn proof_recover_begins_by_counting_the_attempt() {
    let transition = begin_proof_recover();
    assert_eq!(transition.effect, ProofRecoverEffect::CountAttempt);
    assert_eq!(transition.driver.stage, ProofRecoverStage::Attempt);
    assert!(!transition.driver.budget_counted);
    assert!(!transition.driver.attempt_consumed);
    assert!(proof_recover_state_is_sound(transition.driver));
    assert!(proof_recover_effect_is_sound(
        transition.driver,
        transition.effect
    ));
}

#[test]
fn an_admitted_attempt_is_required_before_the_single_use_consume() {
    let (driver, effect) = advance_proof_recover(
        begin_proof_recover().driver,
        &[ProofRecoverEvent::AttemptCounted(
            AttemptBudgetObservation::Admitted,
        )],
    );
    assert_eq!(effect, ProofRecoverEffect::ConsumeAttempt);
    assert_eq!(driver.stage, ProofRecoverStage::Consume);
    assert!(driver.budget_counted && !driver.attempt_consumed);

    let (driver, effect) = advance_proof_recover(
        begin_proof_recover().driver,
        &[ProofRecoverEvent::AttemptCounted(
            AttemptBudgetObservation::Limited,
        )],
    );
    assert_eq!(
        effect,
        ProofRecoverEffect::Fail(ProofRecoverFailure::AttemptLimited)
    );
    assert_eq!(driver.stage, ProofRecoverStage::Done);
    assert!(!driver.budget_counted && !driver.attempt_consumed);
}

#[test]
fn missing_corrupt_and_mismatched_attempts_are_terminal_without_a_grant() {
    for (observation, failure) in [
        (
            AttemptConsumptionObservation::Missing,
            ProofRecoverFailure::AttemptMissing,
        ),
        (
            AttemptConsumptionObservation::Corrupt,
            ProofRecoverFailure::AttemptCorrupt,
        ),
        (
            AttemptConsumptionObservation::Present {
                user_matches: false,
                attempt_matches: true,
                key_epoch: 3,
            },
            ProofRecoverFailure::BindingMismatch,
        ),
        (
            AttemptConsumptionObservation::Present {
                user_matches: true,
                attempt_matches: false,
                key_epoch: 3,
            },
            ProofRecoverFailure::BindingMismatch,
        ),
    ] {
        let (driver, effect) = advance_proof_recover(
            begin_consuming(),
            &[ProofRecoverEvent::AttemptConsumed(observation)],
        );
        assert_eq!(effect, ProofRecoverEffect::Fail(failure), "{observation:?}");
        assert_eq!(driver.stage, ProofRecoverStage::Done);
        assert!(!driver.proof_verified && !driver.grant_issued);
    }
}

#[test]
fn a_matched_attempt_only_asks_for_the_live_account_observation() {
    let (driver, effect) = advance_proof_recover(
        begin_consuming(),
        &[ProofRecoverEvent::AttemptConsumed(matched_attempt())],
    );
    assert_eq!(effect, ProofRecoverEffect::QueryAccount);
    assert_eq!(driver.stage, ProofRecoverStage::Live);
    assert!(driver.attempt_consumed && driver.user_matches && driver.attempt_matches);
    assert!(!driver.proof_verified && !driver.grant_issued);
}

#[test]
fn freezing_revocation_and_absence_are_terminal_before_verification() {
    for (observation, failure) in [
        (
            ProofAccountObservation {
                account_present: false,
                ..active_account()
            },
            ProofRecoverFailure::AccountAbsent,
        ),
        (
            ProofAccountObservation {
                account_epoch_active: false,
                ..active_account()
            },
            ProofRecoverFailure::RotationPaused,
        ),
        (
            ProofAccountObservation {
                commitment: CommitmentObservation::Missing,
                ..active_account()
            },
            ProofRecoverFailure::CommitmentMissing,
        ),
        (
            ProofAccountObservation {
                commitment: CommitmentObservation::Corrupt,
                ..active_account()
            },
            ProofRecoverFailure::CommitmentCorrupt,
        ),
    ] {
        let (driver, effect) = advance_proof_recover(
            to_live(),
            &[ProofRecoverEvent::AccountObserved(observation)],
        );
        assert_eq!(effect, ProofRecoverEffect::Fail(failure), "{observation:?}");
        assert_eq!(driver.stage, ProofRecoverStage::Done);
        assert!(!driver.proof_verified && !driver.grant_issued);
    }
}

#[test]
fn a_live_commitment_only_asks_for_verification() {
    let (driver, effect) = advance_proof_recover(
        to_live(),
        &[ProofRecoverEvent::AccountObserved(active_account())],
    );
    assert_eq!(effect, ProofRecoverEffect::VerifyProof);
    assert_eq!(driver.stage, ProofRecoverStage::Verify);
    assert!(driver.account_present && driver.account_epoch_active);
    assert!(driver.commitment_present && driver.commitment_len > 0);
    assert!(!driver.proof_verified && !driver.grant_issued);
}

#[test]
fn a_verified_current_epoch_proof_issues_exactly_one_grant_authority() {
    let (driver, effect) = advance_proof_recover(
        to_verify(),
        &[ProofRecoverEvent::ProofObserved(ProofObservation {
            verified: true,
        })],
    );
    assert_eq!(
        effect,
        ProofRecoverEffect::IssueGrant(vela_recovery_policy::possession_driver::ProofGrantPermit {
            epoch: 3
        })
    );
    assert_eq!(driver.stage, ProofRecoverStage::Issue);
    assert!(driver.grant_issued && driver.proof_verified && driver.attempt_consumed);
    assert!(!driver.grant_stored);
    assert!(!proof_recover_effect_releases_share(effect));
}

#[test]
fn an_unverified_or_stale_epoch_proof_is_rejected_without_a_grant() {
    for (driver, observation) in [
        (to_verify(), ProofObservation { verified: false }),
        // The attempt's envelope epoch is not the live stored epoch.
        (
            advance_proof_recover(
                to_live(),
                &[ProofRecoverEvent::AccountObserved(
                    ProofAccountObservation {
                        stored_epoch: Some(4),
                        ..active_account()
                    },
                )],
            )
            .0,
            ProofObservation { verified: true },
        ),
        // An empty staged commitment can never verify.
        (
            advance_proof_recover(
                to_live(),
                &[ProofRecoverEvent::AccountObserved(
                    ProofAccountObservation {
                        commitment: CommitmentObservation::Present { len: 0 },
                        ..active_account()
                    },
                )],
            )
            .0,
            ProofObservation { verified: true },
        ),
    ] {
        let (driver, effect) =
            advance_proof_recover(driver, &[ProofRecoverEvent::ProofObserved(observation)]);
        assert_eq!(
            effect,
            ProofRecoverEffect::Fail(ProofRecoverFailure::ProofRejected),
            "{observation:?}"
        );
        assert_eq!(driver.stage, ProofRecoverStage::Done);
        assert!(!driver.grant_issued && !driver.grant_stored);
    }
}

#[test]
fn a_stored_grant_is_the_only_success_and_is_terminal() {
    let (driver, effect) = advance_proof_recover(
        to_issue(),
        &[ProofRecoverEvent::GrantStored(
            GrantStoreObservation::Stored,
        )],
    );
    assert_eq!(effect, ProofRecoverEffect::Complete);
    assert_eq!(driver.stage, ProofRecoverStage::Done);
    assert!(driver.grant_issued && driver.grant_stored);

    for event in proof_recover_events() {
        let (after, effect) = advance_proof_recover(driver, &[event]);
        assert_eq!(effect, ProofRecoverEffect::Idle, "{event:?}");
        assert_eq!(after, driver, "{event:?}");
    }
}

#[test]
fn a_failed_grant_store_is_terminal_and_issues_no_second_grant() {
    let (driver, effect) = advance_proof_recover(
        to_issue(),
        &[ProofRecoverEvent::GrantStored(
            GrantStoreObservation::Failed,
        )],
    );
    assert_eq!(
        effect,
        ProofRecoverEffect::Fail(ProofRecoverFailure::GrantStorage)
    );
    assert_eq!(driver.stage, ProofRecoverStage::Done);
    assert!(driver.grant_issued && !driver.grant_stored);
    for event in proof_recover_events() {
        let (after, effect) = advance_proof_recover(driver, &[event]);
        assert_eq!(effect, ProofRecoverEffect::Idle, "{event:?}");
        assert_eq!(after, driver, "{event:?}");
    }
}

#[test]
fn every_stage_ignores_every_out_of_order_event() {
    let drivers = [
        begin_proof_recover().driver,
        begin_consuming(),
        to_live(),
        to_verify(),
        to_issue(),
        advance_proof_recover(
            to_issue(),
            &[ProofRecoverEvent::GrantStored(
                GrantStoreObservation::Stored,
            )],
        )
        .0,
    ];
    let expected = [
        ProofRecoverStage::Attempt,
        ProofRecoverStage::Consume,
        ProofRecoverStage::Live,
        ProofRecoverStage::Verify,
        ProofRecoverStage::Issue,
        ProofRecoverStage::Done,
    ];
    assert_eq!(
        drivers
            .iter()
            .map(|driver| driver.stage)
            .collect::<Vec<_>>(),
        expected
    );

    for driver in drivers {
        for event in proof_recover_events() {
            let in_stage = match (&event, driver.stage) {
                (ProofRecoverEvent::AttemptCounted(_), ProofRecoverStage::Attempt) => true,
                (ProofRecoverEvent::AttemptConsumed(_), ProofRecoverStage::Consume) => true,
                (ProofRecoverEvent::AccountObserved(_), ProofRecoverStage::Live) => true,
                (ProofRecoverEvent::ProofObserved(_), ProofRecoverStage::Verify) => true,
                (ProofRecoverEvent::GrantStored(_), ProofRecoverStage::Issue) => true,
                _ => false,
            };
            let transition = match &event {
                ProofRecoverEvent::AttemptCounted(observation) => {
                    on_attempt_counted(driver, *observation)
                }
                ProofRecoverEvent::AttemptConsumed(observation) => {
                    on_attempt_consumed(driver, *observation)
                }
                ProofRecoverEvent::AccountObserved(observation) => {
                    on_account_observed(driver, *observation)
                }
                ProofRecoverEvent::ProofObserved(observation) => {
                    on_proof_observed(driver, *observation)
                }
                ProofRecoverEvent::GrantStored(observation) => {
                    on_grant_stored(driver, *observation)
                }
            };
            if !in_stage {
                assert_eq!(
                    transition.effect,
                    ProofRecoverEffect::Idle,
                    "{driver:?} / {event:?}"
                );
                assert_eq!(transition.driver, driver, "{driver:?} / {event:?}");
            }
            assert!(
                proof_recover_effect_is_sound(transition.driver, transition.effect),
                "{driver:?} / {event:?} -> {transition:?}"
            );
        }
    }
}

#[test]
fn initiation_stages_ignore_every_out_of_order_event() {
    let drivers = [
        begin_initiation().driver,
        initiation_store_ready(),
        advance_initiation(
            initiation_store_ready(),
            &[InitiateEvent::Stored(ChallengeStoreObservation::Stored)],
        )
        .0,
    ];
    let expected = [
        InitiateStage::Observe,
        InitiateStage::Store,
        InitiateStage::Done,
    ];
    assert_eq!(
        drivers
            .iter()
            .map(|driver| driver.stage)
            .collect::<Vec<_>>(),
        expected
    );

    for driver in drivers {
        for event in initiation_events() {
            let in_stage = match (&event, driver.stage) {
                (InitiateEvent::Observed(_), InitiateStage::Observe) => true,
                (InitiateEvent::Stored(_), InitiateStage::Store) => true,
                _ => false,
            };
            let transition = match &event {
                InitiateEvent::Observed(observation) => {
                    on_initiation_observed(driver, *observation)
                }
                InitiateEvent::Stored(observation) => on_challenge_stored(driver, *observation),
            };
            if !in_stage {
                assert_eq!(
                    transition.effect,
                    InitiateEffect::Idle,
                    "{driver:?} / {event:?}"
                );
                assert_eq!(transition.driver, driver, "{driver:?} / {event:?}");
            }
            assert!(
                initiation_effect_is_sound(transition.driver, transition.effect),
                "{driver:?} / {event:?} -> {transition:?}"
            );
        }
    }
}

#[test]
fn no_reachable_transition_issues_a_grant_without_a_verified_current_epoch_proof() {
    // Breadth-first exploration of the proof-recovery state graph.
    let mut frontier = vec![begin_proof_recover().driver];
    let events = proof_recover_events();
    let mut grants = Vec::new();
    for _ in 0..10 {
        let mut next = Vec::new();
        for driver in &frontier {
            for event in &events {
                let transition = match event {
                    ProofRecoverEvent::AttemptCounted(observation) => {
                        on_attempt_counted(*driver, *observation)
                    }
                    ProofRecoverEvent::AttemptConsumed(observation) => {
                        on_attempt_consumed(*driver, *observation)
                    }
                    ProofRecoverEvent::AccountObserved(observation) => {
                        on_account_observed(*driver, *observation)
                    }
                    ProofRecoverEvent::ProofObserved(observation) => {
                        on_proof_observed(*driver, *observation)
                    }
                    ProofRecoverEvent::GrantStored(observation) => {
                        on_grant_stored(*driver, *observation)
                    }
                };
                if let ProofRecoverEffect::IssueGrant(permit) = transition.effect {
                    assert!(
                        transition.driver.attempt_consumed
                            && transition.driver.user_matches
                            && transition.driver.attempt_matches
                            && transition.driver.proof_verified
                            && transition.driver.account_present
                            && transition.driver.account_epoch_active
                            && transition.driver.commitment_len > 0
                            && transition.driver.stage == ProofRecoverStage::Issue,
                        "grant issued without a verified current-epoch proof: {driver:?}"
                    );
                    assert_eq!(
                        permit.epoch,
                        vela_recovery_policy::observed_recovery_epoch(
                            transition.driver.stored_epoch
                        )
                    );
                    grants.push(transition.driver);
                }
                if let ProofRecoverEffect::Complete = transition.effect {
                    assert!(
                        transition.driver.grant_issued
                            && transition.driver.grant_stored
                            && transition.driver.stage == ProofRecoverStage::Done
                    );
                }
                if !next.contains(&transition.driver) {
                    next.push(transition.driver);
                }
            }
        }
        frontier = next;
    }
    assert!(!grants.is_empty(), "the grant path was never reachable");
    // Every reachable grant-issued state is terminal for further grants: the
    // only stage that can emit a grant is `Issue`, reached once.
    for driver in grants {
        let (after, effect) = advance_proof_recover(
            driver,
            &[ProofRecoverEvent::GrantStored(
                GrantStoreObservation::Stored,
            )],
        );
        assert_eq!(effect, ProofRecoverEffect::Complete);
        for event in proof_recover_events() {
            let (_, effect) = advance_proof_recover(after, &[event]);
            assert_eq!(effect, ProofRecoverEffect::Idle);
        }
    }
}
