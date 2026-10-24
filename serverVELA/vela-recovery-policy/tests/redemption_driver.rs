//! Exhaustive transition tests for the pure post-preflight redemption driver.
//!
//! These tests exercise decision coverage, not the effectful HTTP handler.
//! Handler integration remains in `vela-server/tests`.

use vela_recovery_policy::driver::{
    begin_redemption, on_authority_rechecked, on_final_policy_observed, on_grant_consumed,
    on_insert_completed, redemption_effect_is_sound, redemption_state_is_sound,
    AuthorityRecheckObservation, ConsumedGrantObservation, ConsumptionObservation,
    FinalPolicyObservation, InsertObservation, RedemptionDriver, RedemptionEffect, RedemptionEvent,
    RedemptionFailure, RedemptionStage, RekeyObservation,
};
use vela_recovery_policy::{
    plan_enrollment_preflight, EnrollmentAccountFacts, EnrollmentAccountObservation,
    EnrollmentGrantFacts, EnrollmentObservation, EnrollmentPreflightDecision,
    EnrollmentPreflightObservation, HYBRID_EK_LEN, HYBRID_VK_LEN,
};

fn credential_ready() -> vela_recovery_policy::ReadyToConsume {
    match plan_enrollment_preflight(EnrollmentPreflightObservation {
        grant: Some(EnrollmentGrantFacts {
            epoch: 3,
            possession: false,
        }),
        account: EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
            stored_epoch: Some(3),
            epoch_active: true,
            credential_id_matches: true,
            commitment_len: 0,
        }),
    }) {
        EnrollmentPreflightDecision::Ready(ready) => ready,
        other => panic!("expected credential preflight readiness, got {other:?}"),
    }
}

fn possession_ready() -> vela_recovery_policy::ReadyToConsume {
    match plan_enrollment_preflight(EnrollmentPreflightObservation {
        grant: Some(EnrollmentGrantFacts {
            epoch: 3,
            possession: true,
        }),
        account: EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
            stored_epoch: Some(3),
            epoch_active: true,
            credential_id_matches: false,
            commitment_len: 32,
        }),
    }) {
        EnrollmentPreflightDecision::Ready(ready) => ready,
        other => panic!("expected possession preflight readiness, got {other:?}"),
    }
}

fn matched_consumption(possession: bool) -> ConsumptionObservation {
    ConsumptionObservation::Present(ConsumedGrantObservation {
        key_epoch: 3,
        possession,
        matches_observed_grant: true,
    })
}

fn enrollment_observation(possession: bool) -> EnrollmentObservation {
    EnrollmentObservation {
        grant_present: true,
        grant_consumed: true,
        consumed_matches_observed: true,
        account_present: true,
        grant_possession: possession,
        grant_epoch: 3,
        stored_epoch: Some(3),
        account_epoch_active: true,
        credential_id_matches: !possession,
        commitment_len: if possession { 32 } else { 0 },
        hybrid_ek_len: HYBRID_EK_LEN,
        hybrid_vk_len: HYBRID_VK_LEN,
    }
}

fn permitted_final_policy(possession: bool) -> FinalPolicyObservation {
    FinalPolicyObservation {
        enrollment: enrollment_observation(possession),
        rekey: RekeyObservation::Permit { epoch: 3 },
    }
}

fn advance(
    mut driver: RedemptionDriver,
    events: &[RedemptionEvent],
) -> (RedemptionDriver, RedemptionEffect) {
    let mut effect = RedemptionEffect::Idle;
    for event in events {
        let transition = match event {
            RedemptionEvent::Consumed(observation) => on_grant_consumed(driver, *observation),
            RedemptionEvent::FinalPolicy(observation) => {
                on_final_policy_observed(driver, *observation)
            }
            RedemptionEvent::Insert(observation) => on_insert_completed(driver, *observation),
            RedemptionEvent::Recheck(observation) => on_authority_rechecked(driver, *observation),
        };
        assert!(
            redemption_effect_is_sound(transition.driver, transition.effect),
            "step emitted an effect unsupported by its pre-state: {driver:?} / {event:?} -> {transition:?}"
        );
        assert!(
            !redemption_state_is_sound(driver) || redemption_state_is_sound(transition.driver),
            "step broke the soundness invariant: {driver:?} / {event:?} -> {transition:?}"
        );
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn to_insert(possession: bool) -> RedemptionDriver {
    let (driver, effect) = advance(
        begin_redemption(if possession {
            possession_ready()
        } else {
            credential_ready()
        })
        .driver,
        &[
            RedemptionEvent::Consumed(matched_consumption(possession)),
            RedemptionEvent::FinalPolicy(permitted_final_policy(possession)),
        ],
    );
    assert!(matches!(effect, RedemptionEffect::Insert(_)));
    driver
}

fn to_recheck(possession: bool) -> RedemptionDriver {
    let (driver, effect) = advance(
        to_insert(possession),
        &[RedemptionEvent::Insert(InsertObservation::Skipped)],
    );
    assert_eq!(effect, RedemptionEffect::Recheck);
    driver
}

#[test]
fn begin_requests_consumption_and_carries_the_preflight_epoch_and_type() {
    for (ready, possession) in [(credential_ready(), false), (possession_ready(), true)] {
        let transition = begin_redemption(ready);
        assert_eq!(transition.effect, RedemptionEffect::Consume);
        assert_eq!(transition.driver.stage, RedemptionStage::Consume);
        assert_eq!(transition.driver.epoch, 3);
        assert_eq!(transition.driver.possession, possession);
        assert!(redemption_state_is_sound(transition.driver));
    }
}

#[test]
fn missing_consumption_is_terminal_without_restoration() {
    let (_, effect) = advance(
        begin_redemption(credential_ready()).driver,
        &[RedemptionEvent::Consumed(ConsumptionObservation::Missing)],
    );
    assert_eq!(
        effect,
        RedemptionEffect::Fail(RedemptionFailure::GrantUnavailable)
    );
}

#[test]
fn replaced_or_mismatched_consumption_restores_the_grant() {
    for observation in [
        ConsumptionObservation::Present(ConsumedGrantObservation {
            key_epoch: 3,
            possession: false,
            matches_observed_grant: false,
        }),
        // The value matched the preflight lookup but the permit was for another
        // epoch; no insert may follow.
        ConsumptionObservation::Present(ConsumedGrantObservation {
            key_epoch: 4,
            possession: false,
            matches_observed_grant: true,
        }),
        ConsumptionObservation::Present(ConsumedGrantObservation {
            key_epoch: 3,
            possession: true,
            matches_observed_grant: true,
        }),
    ] {
        let (driver, effect) = advance(
            begin_redemption(credential_ready()).driver,
            &[RedemptionEvent::Consumed(observation)],
        );
        assert_eq!(
            effect,
            RedemptionEffect::RestoreAndFail(RedemptionFailure::GrantChanged),
            "{observation:?}"
        );
        assert!(driver.restored);
        assert!(!driver.insert_attempted);
    }
}

#[test]
fn matched_consumption_alone_does_not_authorize_an_insert() {
    let (driver, effect) = advance(
        begin_redemption(credential_ready()).driver,
        &[RedemptionEvent::Consumed(matched_consumption(false))],
    );
    assert_eq!(effect, RedemptionEffect::FinalPolicy);
    assert_eq!(driver.stage, RedemptionStage::FinalPolicy);
    assert!(driver.consumed_matched);
    assert!(!driver.permit_issued);
    assert!(!driver.insert_attempted);
}

#[test]
fn final_policy_denial_is_terminal_and_does_not_restore() {
    let (driver, effect) = advance(
        begin_redemption(credential_ready()).driver,
        &[RedemptionEvent::Consumed(matched_consumption(false))],
    );
    assert_eq!(effect, RedemptionEffect::FinalPolicy);

    // Account row disappeared between preflight and final policy.
    let mut enrollment = enrollment_observation(false);
    enrollment.account_present = false;
    let (driver, effect) = advance(
        driver,
        &[RedemptionEvent::FinalPolicy(FinalPolicyObservation {
            enrollment,
            rekey: RekeyObservation::Permit { epoch: 3 },
        })],
    );
    assert_eq!(
        effect,
        RedemptionEffect::Fail(RedemptionFailure::PolicyRejected)
    );
    assert!(!driver.restored, "policy denial is terminal, not retryable");
}

#[test]
fn rekey_rejection_or_epoch_mismatch_restores() {
    for rekey in [
        RekeyObservation::Reject,
        RekeyObservation::Permit { epoch: 4 },
    ] {
        let (_, effect) = advance(
            begin_redemption(credential_ready()).driver,
            &[
                RedemptionEvent::Consumed(matched_consumption(false)),
                RedemptionEvent::FinalPolicy(FinalPolicyObservation {
                    enrollment: enrollment_observation(false),
                    rekey,
                }),
            ],
        );
        assert_eq!(
            effect,
            RedemptionEffect::RestoreAndFail(RedemptionFailure::GrantChanged),
            "{rekey:?}"
        );
    }
}

#[test]
fn matching_enrollment_and_rekey_permits_issue_the_exact_insert_authority() {
    for possession in [false, true] {
        let (driver, effect) = advance(
            begin_redemption(if possession {
                possession_ready()
            } else {
                credential_ready()
            })
            .driver,
            &[
                RedemptionEvent::Consumed(matched_consumption(possession)),
                RedemptionEvent::FinalPolicy(permitted_final_policy(possession)),
            ],
        );
        assert_eq!(
            effect,
            RedemptionEffect::Insert(vela_recovery_policy::driver::RedemptionInsertPermit {
                epoch: 3,
                possession,
            })
        );
        assert_eq!(driver.stage, RedemptionStage::Insert);
        assert!(driver.consumed_matched && driver.permit_issued && driver.insert_attempted);
        assert!(!driver.insert_succeeded && !driver.restored);
    }
}

#[test]
fn insert_success_is_terminal_and_no_later_event_restores_or_succeeds_again() {
    let (driver, effect) = advance(
        to_insert(false),
        &[RedemptionEvent::Insert(InsertObservation::Inserted)],
    );
    assert_eq!(effect, RedemptionEffect::Complete);
    assert!(driver.insert_succeeded);
    assert_eq!(driver.stage, RedemptionStage::Done);
    assert!(!driver.restored);

    // Every event, including another claimed success or a failure, is inert
    // after success. This is the per-request at-most-one-success property.
    let events = all_events();
    for event in &events {
        let transition = match event {
            RedemptionEvent::Consumed(observation) => on_grant_consumed(driver, *observation),
            RedemptionEvent::FinalPolicy(observation) => {
                on_final_policy_observed(driver, *observation)
            }
            RedemptionEvent::Insert(observation) => on_insert_completed(driver, *observation),
            RedemptionEvent::Recheck(observation) => on_authority_rechecked(driver, *observation),
        };
        assert_eq!(transition.effect, RedemptionEffect::Idle, "{event:?}");
        assert_eq!(transition.driver, driver, "{event:?}");
        assert!(!matches!(
            transition.effect,
            RedemptionEffect::RestoreAndFail(_)
        ));
    }
}

#[test]
fn insert_error_instructs_restoration_but_does_not_claim_the_insert_did_not_commit() {
    let (driver, effect) = advance(
        to_insert(false),
        &[RedemptionEvent::Insert(InsertObservation::Failed)],
    );
    assert_eq!(
        effect,
        RedemptionEffect::RestoreAndFail(RedemptionFailure::InsertStorage)
    );
    assert!(driver.restored);
    assert!(!driver.insert_succeeded);
    // The driver observed `Failed`; it cannot distinguish a rolled-back insert
    // from an ambiguous commit. Tests pin only the decision, not SQL outcome.
}

#[test]
fn zero_row_insert_requires_the_live_recheck_in_historical_precedence() {
    let driver = to_recheck(false);
    assert_eq!(driver.stage, RedemptionStage::Recheck);
    assert!(driver.insert_attempted && !driver.insert_succeeded);

    for (observation, effect, restored) in [
        (
            AuthorityRecheckObservation::QueryFailed,
            RedemptionEffect::RestoreAndFail(RedemptionFailure::RecheckStorage),
            true,
        ),
        (
            AuthorityRecheckObservation::AccountAbsent,
            RedemptionEffect::RestoreAndFail(RedemptionFailure::AccountAbsent),
            true,
        ),
        (
            AuthorityRecheckObservation::CommitmentRevoked,
            RedemptionEffect::Fail(RedemptionFailure::CommitmentRevoked),
            false,
        ),
        (
            AuthorityRecheckObservation::CredentialReplaced,
            RedemptionEffect::Fail(RedemptionFailure::CredentialReplaced),
            false,
        ),
        (
            AuthorityRecheckObservation::StillRotating,
            RedemptionEffect::RestoreAndFail(RedemptionFailure::Rotating),
            true,
        ),
    ] {
        let (driver, actual) = advance(driver, &[RedemptionEvent::Recheck(observation)]);
        assert_eq!(actual, effect, "{observation:?}");
        assert_eq!(driver.restored, restored, "{observation:?}");
        assert!(!driver.insert_succeeded);
    }
}

#[test]
fn every_stage_ignores_every_out_of_order_event() {
    let drivers = [
        begin_redemption(credential_ready()).driver,
        advance(
            begin_redemption(credential_ready()).driver,
            &[RedemptionEvent::Consumed(matched_consumption(false))],
        )
        .0,
        to_insert(false),
        to_recheck(false),
        advance(
            to_insert(false),
            &[RedemptionEvent::Insert(InsertObservation::Inserted)],
        )
        .0,
    ];
    let expected_stage = [
        RedemptionStage::Consume,
        RedemptionStage::FinalPolicy,
        RedemptionStage::Insert,
        RedemptionStage::Recheck,
        RedemptionStage::Done,
    ];
    assert_eq!(
        drivers
            .iter()
            .map(|driver| driver.stage)
            .collect::<Vec<_>>(),
        expected_stage
    );

    for driver in drivers {
        for event in all_events() {
            let in_stage = match (&event, driver.stage) {
                (RedemptionEvent::Consumed(_), RedemptionStage::Consume) => true,
                (RedemptionEvent::FinalPolicy(_), RedemptionStage::FinalPolicy) => true,
                (RedemptionEvent::Insert(_), RedemptionStage::Insert) => true,
                (RedemptionEvent::Recheck(_), RedemptionStage::Recheck) => true,
                _ => false,
            };
            let transition = match &event {
                RedemptionEvent::Consumed(observation) => on_grant_consumed(driver, *observation),
                RedemptionEvent::FinalPolicy(observation) => {
                    on_final_policy_observed(driver, *observation)
                }
                RedemptionEvent::Insert(observation) => on_insert_completed(driver, *observation),
                RedemptionEvent::Recheck(observation) => {
                    on_authority_rechecked(driver, *observation)
                }
            };
            if !in_stage {
                assert_eq!(
                    transition.effect,
                    RedemptionEffect::Idle,
                    "{driver:?} / {event:?}"
                );
                assert_eq!(transition.driver, driver, "{driver:?} / {event:?}");
            }
            assert!(
                redemption_effect_is_sound(transition.driver, transition.effect),
                "{driver:?} / {event:?} -> {transition:?}"
            );
            if redemption_state_is_sound(driver) {
                assert!(
                    redemption_state_is_sound(transition.driver),
                    "{driver:?} / {event:?} -> {transition:?}"
                );
            }
        }
    }
}

#[test]
fn failed_insert_then_a_fresh_redemption_can_succeed_if_the_grant_is_restored() {
    // Decision-level characterization of the retry/ambiguity issue: the failed
    // insert observation only instructs a restore. Nothing in the driver
    // (or in the handler's error path) establishes that the INSERT did not
    // commit before returning the error, so a fresh driver instance fed the
    // restored grant can reach Complete. The single-use store `get_del` blocks
    // ordinary concurrent double consumption, but the unconditional restore
    // after an ambiguous commit can re-arm the same grant for a second insert.
    let (first, first_effect) = advance(
        to_insert(false),
        &[RedemptionEvent::Insert(InsertObservation::Failed)],
    );
    assert_eq!(
        first_effect,
        RedemptionEffect::RestoreAndFail(RedemptionFailure::InsertStorage)
    );
    assert!(first.restored && !first.insert_succeeded);

    let (second, second_effect) = advance(
        begin_redemption(credential_ready()).driver,
        &[
            RedemptionEvent::Consumed(matched_consumption(false)),
            RedemptionEvent::FinalPolicy(permitted_final_policy(false)),
            RedemptionEvent::Insert(InsertObservation::Inserted),
        ],
    );
    assert_eq!(second_effect, RedemptionEffect::Complete);
    assert!(second.insert_succeeded);
}

#[test]
fn no_reachable_transition_authorizes_an_insert_without_both_permits() {
    // Breadth-first exploration of the driver state graph with a canonical
    // event alphabet. The invariants are also checked after every step.
    let mut frontier = vec![begin_redemption(credential_ready()).driver];
    let events = all_events();
    for _ in 0..8 {
        let mut next = Vec::new();
        for driver in &frontier {
            for event in &events {
                let transition = match event {
                    RedemptionEvent::Consumed(observation) => {
                        on_grant_consumed(*driver, *observation)
                    }
                    RedemptionEvent::FinalPolicy(observation) => {
                        on_final_policy_observed(*driver, *observation)
                    }
                    RedemptionEvent::Insert(observation) => {
                        on_insert_completed(*driver, *observation)
                    }
                    RedemptionEvent::Recheck(observation) => {
                        on_authority_rechecked(*driver, *observation)
                    }
                };
                if let RedemptionEffect::Insert(permit) = transition.effect {
                    assert!(
                        transition.driver.consumed_matched
                            && transition.driver.permit_issued
                            && transition.driver.stage == RedemptionStage::Insert,
                        "insert emitted without both authority facts: {driver:?}"
                    );
                    assert_eq!(permit.epoch, transition.driver.epoch);
                    assert_eq!(permit.possession, transition.driver.possession);
                }
                if let RedemptionEffect::Complete = transition.effect {
                    assert!(
                        transition.driver.consumed_matched
                            && transition.driver.permit_issued
                            && transition.driver.stage == RedemptionStage::Done
                            && transition.driver.insert_succeeded,
                        "success emitted without both authority facts: {driver:?}"
                    );
                }
                if let RedemptionEffect::RestoreAndFail(_) = transition.effect {
                    assert!(!driver.insert_succeeded);
                }
                if !next.contains(&transition.driver) {
                    next.push(transition.driver);
                }
            }
        }
        frontier = next;
    }
}

fn all_events() -> Vec<RedemptionEvent> {
    vec![
        RedemptionEvent::Consumed(ConsumptionObservation::Missing),
        RedemptionEvent::Consumed(ConsumptionObservation::Present(ConsumedGrantObservation {
            key_epoch: 3,
            possession: false,
            matches_observed_grant: true,
        })),
        RedemptionEvent::Consumed(ConsumptionObservation::Present(ConsumedGrantObservation {
            key_epoch: 3,
            possession: false,
            matches_observed_grant: false,
        })),
        RedemptionEvent::FinalPolicy(permitted_final_policy(false)),
        RedemptionEvent::FinalPolicy(FinalPolicyObservation {
            enrollment: enrollment_observation(false),
            rekey: RekeyObservation::Reject,
        }),
        RedemptionEvent::FinalPolicy(FinalPolicyObservation {
            enrollment: enrollment_observation(false),
            rekey: RekeyObservation::Permit { epoch: 4 },
        }),
        RedemptionEvent::Insert(InsertObservation::Inserted),
        RedemptionEvent::Insert(InsertObservation::Skipped),
        RedemptionEvent::Insert(InsertObservation::Failed),
        RedemptionEvent::Recheck(AuthorityRecheckObservation::QueryFailed),
        RedemptionEvent::Recheck(AuthorityRecheckObservation::AccountAbsent),
        RedemptionEvent::Recheck(AuthorityRecheckObservation::CommitmentRevoked),
        RedemptionEvent::Recheck(AuthorityRecheckObservation::CredentialReplaced),
        RedemptionEvent::Recheck(AuthorityRecheckObservation::StillRotating),
    ]
}
