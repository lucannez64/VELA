//! Exhaustive bounded checks for the recovery observation → fact mappings.
//!
//! The hax/F* postconditions state each fact exactly in terms of its raw
//! observation. This test enumerates every Boolean combination, both attempt
//! sources, a small epoch range and zero/positive TTLs, then checks the
//! mapping, the composed authorization predicate and every negative theorem
//! against the same values. It is ordinary Rust CI, not a substitute for the
//! F* check.

use vela_recovery_policy::{
    absent_account_can_start_possession_proof, absent_enrollment_account_can_enroll,
    absent_possession_account_can_recover, colliding_possession_attempt_id_can_start,
    commitmentless_account_can_start_possession_proof,
    commitmentless_possession_observation_can_enroll,
    cross_user_possession_observation_can_recover, enrollment_facts, enrollment_facts_authorize,
    enrollment_is_authorized, expired_possession_initiate_ttl_can_start,
    invalid_public_keys_observation_can_enroll,
    mismatched_possession_attempt_observation_can_recover,
    missing_enrollment_grant_observation_can_enroll, missing_possession_attempt_can_recover,
    missing_possession_commitment_can_recover, missing_share_can_start_possession_proof,
    possession_recover_facts, possession_recover_facts_authorize,
    possession_recovery_is_authorized, proof_initiate_facts, proof_initiate_facts_authorize,
    proof_initiation_is_authorized, rekeying_enrollment_observation_can_enroll,
    rekeying_possession_observation_can_recover, replaced_credential_observation_can_enroll,
    replaced_enrollment_grant_observation_can_enroll, rotated_commitment_observation_can_recover,
    rotated_enrollment_observation_can_enroll, rotating_account_can_start_possession_proof,
    unconsumed_enrollment_grant_observation_can_enroll,
    unverified_possession_observation_can_recover, EnrollmentObservation,
    PossessionRecoverObservation, ProofInitiateObservation,
};
use vela_recovery_policy::{
    all_applicable_guards_imply_ready, commitment_missing_and_credential_replaced_are_disjoint,
    enrollment_preflight_decision_matches_independent_spec, enrollment_preflight_guards,
    enrollment_preflight_is_ready, enrollment_preflight_ordering_is_checked,
    enrollment_preflight_readiness, enrollment_preflight_rejection,
    enrollment_preflight_spec_rejection, epoch_mismatch_precedes_commitment_missing,
    epoch_mismatch_precedes_credential_replaced, epoch_mismatch_precedes_rotation_paused,
    missing_grant_precedes_account_rejection, plan_enrollment_preflight,
    ready_preflight_implies_guards_and_fields, ready_preflight_matches_independent_readiness,
    rotation_paused_precedes_commitment_missing, rotation_paused_precedes_credential_replaced,
    EnrollmentAccountFacts, EnrollmentAccountObservation, EnrollmentGrantFacts,
    EnrollmentPreflightDecision, EnrollmentPreflightObservation, EnrollmentPreflightRejection,
};
use vela_recovery_policy::{
    colliding_attempt_id_can_initiate, credential_update_decision_matches_spec,
    credential_update_facts, credentialless_account_can_initiate,
    cross_user_recover_observation_can_release, expired_initiate_ttl_can_start, initiate_facts,
    initiate_facts_authorize, initiation_is_authorized, mismatched_attempt_observation_can_release,
    missing_attempt_can_release, missing_observed_share_can_release,
    missing_recovery_share_can_initiate, observed_recovery_epoch,
    observed_recovery_epoch_is_active, plan_credential_update, recover_facts,
    recover_facts_authorize, recovery_is_authorized, rekeying_observed_account_can_release,
    replaced_observed_credential_can_release, stale_assertion_credential_can_update,
    unverified_assertion_can_update_credential, unverified_observation_user_can_release,
    unverified_observed_assertion_can_release, CredentialUpdateDecision,
    CredentialUpdateObservation, InitiateObservation, RecoverObservation, RecoveryAttemptSource,
    RecoveryPhase, INITIAL_EPOCH,
};
use vela_recovery_policy::{
    plan_enrollment, plan_possession_recovery, plan_proof_initiation, EnrollmentDecision,
    PossessionRecoverDecision, ProofInitiateDecision,
};

fn expected_epoch(stored_epoch: Option<i64>) -> i64 {
    match stored_epoch {
        None => INITIAL_EPOCH,
        Some(value) if value < INITIAL_EPOCH => INITIAL_EPOCH,
        Some(value) => value,
    }
}

fn observe_recovery(
    attempt_source: RecoveryAttemptSource,
    mask: u8,
    stored_epoch: Option<i64>,
) -> RecoverObservation {
    RecoverObservation {
        attempt_source,
        user_matches: mask & 1 != 0,
        attempt_matches: mask & 2 != 0,
        credential_matches_current: mask & 4 != 0,
        assertion_valid: mask & 8 != 0,
        user_verified: mask & 16 != 0,
        share_present: mask & 32 != 0,
        account_epoch_active: mask & 64 != 0,
        stored_epoch,
    }
}

#[test]
fn initiate_facts_are_exactly_the_account_share_credential_and_store_observations() {
    for &account_present in &[false, true] {
        for &share_present in &[false, true] {
            for &credential_present in &[false, true] {
                for &attempt_id_fresh in &[false, true] {
                    for &ttl_secs in &[0_u64, 1, 300] {
                        let obs = InitiateObservation {
                            account_present,
                            share_present,
                            credential_present,
                            attempt_id_fresh,
                            ttl_secs,
                        };
                        let facts = initiate_facts(obs);
                        let available = account_present && share_present && credential_present;

                        assert_eq!(
                            matches!(facts.phase, RecoveryPhase::Ready),
                            available,
                            "{obs:?}"
                        );
                        assert_eq!(
                            matches!(facts.phase, RecoveryPhase::Unavailable),
                            !available,
                            "{obs:?}"
                        );
                        assert_eq!(facts.account_exists, account_present);
                        assert_eq!(facts.share_present, share_present);
                        assert_eq!(facts.credential_present, credential_present);
                        assert_eq!(facts.attempt_id_fresh, attempt_id_fresh);
                        assert_eq!(facts.ttl_positive, ttl_secs > 0);

                        let expected = available && attempt_id_fresh && ttl_secs > 0;
                        assert_eq!(initiation_is_authorized(facts), expected, "{obs:?}");
                        assert_eq!(initiate_facts_authorize(obs), expected, "{obs:?}");

                        assert!(!missing_recovery_share_can_initiate(obs));
                        assert!(!credentialless_account_can_initiate(obs));
                        assert!(!colliding_attempt_id_can_initiate(obs));
                        assert!(!expired_initiate_ttl_can_start(obs));
                    }
                }
            }
        }
    }
}

#[test]
fn credential_update_facts_are_exactly_the_assertion_and_metadata_observations() {
    for &assertion_valid in &[false, true] {
        for &credential_matches_current in &[false, true] {
            for &needs_update in &[false, true] {
                let obs = CredentialUpdateObservation {
                    assertion_valid,
                    credential_matches_current,
                    needs_update,
                };
                let facts = credential_update_facts(obs);
                assert_eq!(facts.assertion_valid, assertion_valid);
                assert_eq!(facts.credential_matches_current, credential_matches_current);
                assert_eq!(facts.needs_update, needs_update);

                let decision = plan_credential_update(facts);
                let expected = if !assertion_valid || !credential_matches_current {
                    CredentialUpdateDecision::Reject
                } else if needs_update {
                    CredentialUpdateDecision::Update
                } else {
                    CredentialUpdateDecision::Keep
                };
                assert_eq!(decision, expected, "{obs:?}");
                assert!(credential_update_decision_matches_spec(facts, decision));

                assert!(!unverified_assertion_can_update_credential(obs));
                assert!(!stale_assertion_credential_can_update(obs));
            }
        }
    }
}

#[test]
fn recover_facts_are_exactly_the_attempt_assertion_and_row_observations() {
    let sources = [
        RecoveryAttemptSource::Missing,
        RecoveryAttemptSource::Consumed,
    ];
    let epochs = [None, Some(-1), Some(0), Some(INITIAL_EPOCH), Some(2)];

    for &attempt_source in &sources {
        for mask in 0_u8..128 {
            for &stored_epoch in &epochs {
                let obs = observe_recovery(attempt_source, mask, stored_epoch);
                let facts = recover_facts(obs);
                let consumed = matches!(attempt_source, RecoveryAttemptSource::Consumed);

                assert_eq!(
                    matches!(facts.phase, RecoveryPhase::ChallengePending),
                    consumed,
                    "{obs:?}"
                );
                assert_eq!(
                    matches!(facts.phase, RecoveryPhase::Expired),
                    !consumed,
                    "{obs:?}"
                );
                assert_eq!(facts.user_matches, obs.user_matches);
                assert_eq!(facts.attempt_matches, obs.attempt_matches);
                assert_eq!(facts.challenge_consumed, consumed);
                assert_eq!(
                    facts.credential_matches_current,
                    obs.credential_matches_current
                );
                assert_eq!(facts.assertion_valid, obs.assertion_valid);
                assert_eq!(facts.user_verified, obs.user_verified);
                assert_eq!(facts.share_present, obs.share_present);
                assert_eq!(facts.account_epoch_active, obs.account_epoch_active);
                assert_eq!(facts.epoch, expected_epoch(stored_epoch));
                assert_eq!(
                    facts.epoch,
                    observed_recovery_epoch(stored_epoch),
                    "{obs:?}"
                );
                assert!(observed_recovery_epoch_is_active(stored_epoch));
                assert!(facts.epoch >= INITIAL_EPOCH);

                let expected = consumed
                    && obs.user_matches
                    && obs.attempt_matches
                    && obs.credential_matches_current
                    && obs.assertion_valid
                    && obs.user_verified
                    && obs.share_present
                    && obs.account_epoch_active
                    && expected_epoch(stored_epoch) >= INITIAL_EPOCH;
                assert_eq!(recovery_is_authorized(facts), expected, "{obs:?}");
                assert_eq!(recover_facts_authorize(obs), expected, "{obs:?}");

                assert!(!missing_attempt_can_release(obs));
                assert!(!cross_user_recover_observation_can_release(obs));
                assert!(!mismatched_attempt_observation_can_release(obs));
                assert!(!replaced_observed_credential_can_release(obs));
                assert!(!unverified_observed_assertion_can_release(obs));
                assert!(!unverified_observation_user_can_release(obs));
                assert!(!missing_observed_share_can_release(obs));
                assert!(!rekeying_observed_account_can_release(obs));
            }
        }
    }
}

#[test]
fn proof_initiate_facts_are_exactly_the_decoded_account_share_commitment_and_store_observations() {
    for &account_present in &[false, true] {
        for &share_present in &[false, true] {
            for &commitment_len in &[0_usize, 32, 2624] {
                for &rotation_active in &[false, true] {
                    for &attempt_id_fresh in &[false, true] {
                        for &ttl_secs in &[0_u64, 1, 300] {
                            let obs = ProofInitiateObservation {
                                account_present,
                                share_present,
                                commitment_len,
                                rotation_active,
                                attempt_id_fresh,
                                ttl_secs,
                            };
                            let facts = proof_initiate_facts(obs);
                            let available = account_present
                                && share_present
                                && commitment_len > 0
                                && !rotation_active;

                            assert_eq!(
                                matches!(facts.phase, RecoveryPhase::Ready),
                                available,
                                "{obs:?}"
                            );
                            assert_eq!(
                                matches!(facts.phase, RecoveryPhase::Unavailable),
                                !available,
                                "{obs:?}"
                            );
                            assert_eq!(facts.account_exists, account_present);
                            assert_eq!(facts.share_present, share_present);
                            assert_eq!(facts.possession_hash_present, commitment_len > 0);
                            assert_eq!(facts.attempt_id_fresh, attempt_id_fresh);
                            assert_eq!(facts.ttl_positive, ttl_secs > 0);

                            let expected = available && attempt_id_fresh && ttl_secs > 0;
                            assert_eq!(proof_initiation_is_authorized(facts), expected, "{obs:?}");
                            assert_eq!(proof_initiate_facts_authorize(obs), expected, "{obs:?}");
                            assert_eq!(
                                matches!(
                                    plan_proof_initiation(facts),
                                    ProofInitiateDecision::Start
                                ),
                                expected,
                                "{obs:?}"
                            );

                            assert!(!absent_account_can_start_possession_proof(obs));
                            assert!(!missing_share_can_start_possession_proof(obs));
                            assert!(!commitmentless_account_can_start_possession_proof(obs));
                            assert!(!rotating_account_can_start_possession_proof(obs));
                            assert!(!colliding_possession_attempt_id_can_start(obs));
                            assert!(!expired_possession_initiate_ttl_can_start(obs));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn possession_recover_facts_are_exactly_the_attempt_identity_commitment_and_epoch_observations() {
    let sources = [
        RecoveryAttemptSource::Missing,
        RecoveryAttemptSource::Consumed,
    ];
    let epochs = [None, Some(-1), Some(0), Some(INITIAL_EPOCH), Some(4)];

    for &attempt_source in &sources {
        for mask in 0_u8..32 {
            for &commitment_len in &[0_usize, 32, 2624] {
                for &commitment_epoch in &[0_i64, 1, 4, 5] {
                    for &stored_epoch in &epochs {
                        let obs = PossessionRecoverObservation {
                            attempt_source,
                            account_present: mask & 1 != 0,
                            user_matches: mask & 2 != 0,
                            attempt_matches: mask & 4 != 0,
                            proof_verified: mask & 8 != 0,
                            account_epoch_active: mask & 16 != 0,
                            commitment_len,
                            commitment_epoch,
                            stored_epoch,
                        };
                        let facts = possession_recover_facts(obs);
                        let consumed = matches!(attempt_source, RecoveryAttemptSource::Consumed);
                        let epoch = expected_epoch(stored_epoch);

                        assert_eq!(
                            matches!(facts.phase, RecoveryPhase::ChallengePending),
                            consumed,
                            "{obs:?}"
                        );
                        assert_eq!(
                            matches!(facts.phase, RecoveryPhase::Expired),
                            !consumed,
                            "{obs:?}"
                        );
                        assert_eq!(facts.account_present, obs.account_present);
                        assert_eq!(facts.user_matches, obs.user_matches);
                        assert_eq!(facts.attempt_matches, obs.attempt_matches);
                        assert_eq!(facts.challenge_consumed, consumed);
                        assert_eq!(facts.proof_verified, obs.proof_verified);
                        assert_eq!(facts.account_epoch_active, obs.account_epoch_active);
                        assert_eq!(facts.commitment_present, commitment_len > 0);
                        assert_eq!(facts.commitment_epoch_matches, commitment_epoch == epoch);
                        assert_eq!(facts.epoch, epoch);

                        let expected = consumed
                            && obs.account_present
                            && obs.user_matches
                            && obs.attempt_matches
                            && obs.proof_verified
                            && obs.account_epoch_active
                            && commitment_len > 0
                            && commitment_epoch == epoch
                            && epoch >= INITIAL_EPOCH;
                        assert_eq!(
                            possession_recovery_is_authorized(facts),
                            expected,
                            "{obs:?}"
                        );
                        assert_eq!(possession_recover_facts_authorize(obs), expected, "{obs:?}");
                        assert_eq!(
                            matches!(
                                plan_possession_recovery(facts),
                                PossessionRecoverDecision::Grant(_)
                            ),
                            expected,
                            "{obs:?}"
                        );

                        assert!(!missing_possession_attempt_can_recover(obs));
                        assert!(!absent_possession_account_can_recover(obs));
                        assert!(!cross_user_possession_observation_can_recover(obs));
                        assert!(!mismatched_possession_attempt_observation_can_recover(obs));
                        assert!(!unverified_possession_observation_can_recover(obs));
                        assert!(!rekeying_possession_observation_can_recover(obs));
                        assert!(!missing_possession_commitment_can_recover(obs));
                        assert!(!rotated_commitment_observation_can_recover(obs));
                    }
                }
            }
        }
    }
}

#[test]
fn enrollment_facts_are_exactly_the_grant_consumption_credential_commitment_and_epoch_observations()
{
    let epochs = [None, Some(0), Some(INITIAL_EPOCH), Some(4)];

    for &grant_present in &[false, true] {
        for &grant_consumed in &[false, true] {
            for &consumed_matches_observed in &[false, true] {
                for &account_present in &[false, true] {
                    for &grant_possession in &[false, true] {
                        for &credential_id_matches in &[false, true] {
                            for &commitment_len in &[0_usize, 32, 2624] {
                                for &public_keys_valid in &[false, true] {
                                    for &account_epoch_active in &[false, true] {
                                        for &grant_epoch in &[0_i64, 1, 4, 5] {
                                            for &stored_epoch in &epochs {
                                                let obs = EnrollmentObservation {
                                                    grant_present,
                                                    grant_consumed,
                                                    consumed_matches_observed,
                                                    account_present,
                                                    grant_possession,
                                                    grant_epoch,
                                                    stored_epoch,
                                                    account_epoch_active,
                                                    credential_id_matches,
                                                    commitment_len,
                                                    hybrid_ek_len: if public_keys_valid {
                                                        vela_recovery_policy::HYBRID_EK_LEN
                                                    } else {
                                                        0
                                                    },
                                                    hybrid_vk_len: if public_keys_valid {
                                                        vela_recovery_policy::HYBRID_VK_LEN
                                                    } else {
                                                        0
                                                    },
                                                };
                                                let facts = enrollment_facts(obs);
                                                let consumed =
                                                    grant_consumed && consumed_matches_observed;
                                                let epoch = expected_epoch(stored_epoch);

                                                assert_eq!(
                                                    matches!(
                                                        facts.phase,
                                                        RecoveryPhase::GrantIssued
                                                    ),
                                                    grant_present && consumed,
                                                    "{obs:?}"
                                                );
                                                assert_eq!(
                                                    matches!(facts.phase, RecoveryPhase::Expired),
                                                    !grant_present,
                                                    "{obs:?}"
                                                );
                                                assert_eq!(
                                                    matches!(facts.phase, RecoveryPhase::Revoked),
                                                    grant_present && !consumed,
                                                    "{obs:?}"
                                                );
                                                assert_eq!(facts.account_present, account_present);
                                                assert_eq!(facts.user_matches, grant_present);
                                                assert_eq!(facts.grant_live, grant_present);
                                                assert_eq!(facts.grant_consumed, consumed);
                                                assert_eq!(
                                                    facts.credential_matches_current,
                                                    credential_id_matches
                                                );
                                                assert_eq!(
                                                    facts.possession_grant,
                                                    grant_possession
                                                );
                                                assert_eq!(
                                                    facts.possession_hash_present,
                                                    commitment_len > 0
                                                );
                                                assert_eq!(
                                                    facts.public_keys_valid,
                                                    public_keys_valid
                                                );
                                                assert_eq!(
                                                    facts.account_epoch_active,
                                                    account_epoch_active
                                                );
                                                assert_eq!(facts.grant_epoch, grant_epoch);
                                                assert_eq!(facts.account_epoch, epoch);

                                                let authority = if grant_possession {
                                                    commitment_len > 0
                                                } else {
                                                    credential_id_matches
                                                };
                                                let expected = grant_present
                                                    && consumed
                                                    && account_present
                                                    && authority
                                                    && public_keys_valid
                                                    && account_epoch_active
                                                    && grant_epoch >= INITIAL_EPOCH
                                                    && grant_epoch == epoch;
                                                assert_eq!(
                                                    enrollment_is_authorized(facts),
                                                    expected,
                                                    "{obs:?}"
                                                );
                                                assert_eq!(
                                                    enrollment_facts_authorize(obs),
                                                    expected,
                                                    "{obs:?}"
                                                );
                                                assert_eq!(
                                                    matches!(
                                                        plan_enrollment(facts),
                                                        EnrollmentDecision::Enroll(_)
                                                    ),
                                                    expected,
                                                    "{obs:?}"
                                                );

                                                assert!(
                                                    !missing_enrollment_grant_observation_can_enroll(
                                                        obs
                                                    )
                                                );
                                                assert!(
                                                    !unconsumed_enrollment_grant_observation_can_enroll(
                                                        obs
                                                    )
                                                );
                                                assert!(
                                                    !replaced_enrollment_grant_observation_can_enroll(
                                                        obs
                                                    )
                                                );
                                                assert!(!absent_enrollment_account_can_enroll(obs));
                                                assert!(
                                                    !rekeying_enrollment_observation_can_enroll(
                                                        obs
                                                    )
                                                );
                                                assert!(
                                                    !replaced_credential_observation_can_enroll(
                                                        obs
                                                    )
                                                );
                                                assert!(
                                                    !commitmentless_possession_observation_can_enroll(
                                                        obs
                                                    )
                                                );
                                                assert!(
                                                    !rotated_enrollment_observation_can_enroll(obs)
                                                );
                                                assert!(
                                                    !invalid_public_keys_observation_can_enroll(
                                                        obs
                                                    )
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Independent oracle for the preflight ordering. This is a ranked table and a
/// first-true fold, written from the observation and the declared precedence
/// rather than from the production predicate. It is intentionally not the
/// crate's `enrollment_preflight_spec_rejection` function: the test compares
/// the production predicate, the crate specification and this oracle.
fn oracle_preflight_guards(obs: EnrollmentPreflightObservation) -> [bool; 7] {
    match (obs.grant, obs.account) {
        (None, _) => [true, false, false, false, false, false, false],
        (Some(_), EnrollmentAccountObservation::NotQueried) => {
            [false, true, false, false, false, false, false]
        }
        (Some(_), EnrollmentAccountObservation::Absent) => {
            [false, false, true, false, false, false, false]
        }
        (Some(grant), EnrollmentAccountObservation::Present(account)) => [
            false,
            false,
            false,
            expected_epoch(account.stored_epoch) != grant.epoch,
            !account.epoch_active,
            grant.possession && account.commitment_len == 0,
            !grant.possession && !account.credential_id_matches,
        ],
    }
}

fn oracle_preflight_rejection(
    obs: EnrollmentPreflightObservation,
) -> Option<EnrollmentPreflightRejection> {
    let guards = oracle_preflight_guards(obs);
    let table = [
        (guards[0], EnrollmentPreflightRejection::GrantUnavailable),
        (guards[1], EnrollmentPreflightRejection::AccountUnavailable),
        (guards[2], EnrollmentPreflightRejection::AccountAbsent),
        (guards[3], EnrollmentPreflightRejection::EpochMismatch),
        (guards[4], EnrollmentPreflightRejection::RotationPaused),
        (guards[5], EnrollmentPreflightRejection::CommitmentMissing),
        (guards[6], EnrollmentPreflightRejection::CredentialReplaced),
    ];
    table
        .into_iter()
        .find(|(applies, _)| *applies)
        .map(|(_, rejection)| rejection)
}

fn oracle_preflight_ready(obs: EnrollmentPreflightObservation) -> bool {
    !oracle_preflight_guards(obs).into_iter().any(|guard| guard)
}

#[test]
fn preflight_decides_each_rejection_reason_in_handler_precedence_order() {
    let stored_epochs = [None, Some(0), Some(INITIAL_EPOCH), Some(4), Some(5)];
    let grants = [
        None,
        Some(EnrollmentGrantFacts {
            epoch: 1,
            possession: false,
        }),
        Some(EnrollmentGrantFacts {
            epoch: 1,
            possession: true,
        }),
        Some(EnrollmentGrantFacts {
            epoch: 4,
            possession: false,
        }),
        Some(EnrollmentGrantFacts {
            epoch: 4,
            possession: true,
        }),
    ];

    let mut accounts = vec![
        EnrollmentAccountObservation::NotQueried,
        EnrollmentAccountObservation::Absent,
    ];
    for &stored_epoch in &stored_epochs {
        for &epoch_active in &[false, true] {
            for &credential_id_matches in &[false, true] {
                for &commitment_len in &[0_usize, 1, 2624] {
                    accounts.push(EnrollmentAccountObservation::Present(
                        EnrollmentAccountFacts {
                            stored_epoch,
                            epoch_active,
                            credential_id_matches,
                            commitment_len,
                        },
                    ));
                }
            }
        }
    }

    for grant in grants {
        for account in &accounts {
            let obs = EnrollmentPreflightObservation {
                grant,
                account: *account,
            };
            let guards = enrollment_preflight_guards(obs);
            let oracle_guards = oracle_preflight_guards(obs);
            assert_eq!(
                [
                    guards.grant_unavailable,
                    guards.account_unavailable,
                    guards.account_absent,
                    guards.epoch_mismatch,
                    guards.rotation_paused,
                    guards.commitment_missing,
                    guards.credential_replaced,
                ],
                oracle_guards,
                "{obs:?}"
            );

            let expected = oracle_preflight_rejection(obs);
            assert_eq!(
                enrollment_preflight_spec_rejection(obs),
                expected,
                "{obs:?}"
            );
            assert_eq!(enrollment_preflight_rejection(obs), expected, "{obs:?}");
            assert_eq!(
                enrollment_preflight_is_ready(obs),
                oracle_preflight_ready(obs),
                "{obs:?}"
            );
            assert!(enrollment_preflight_ordering_is_checked(obs), "{obs:?}");
            assert!(
                ready_preflight_matches_independent_readiness(obs),
                "{obs:?}"
            );
            assert!(ready_preflight_implies_guards_and_fields(obs), "{obs:?}");
            assert!(all_applicable_guards_imply_ready(obs), "{obs:?}");
            assert!(missing_grant_precedes_account_rejection(*account));

            let decision = plan_enrollment_preflight(obs);
            assert!(
                enrollment_preflight_decision_matches_independent_spec(obs, decision),
                "{obs:?}"
            );
            let readiness = enrollment_preflight_readiness(obs);
            assert_eq!(readiness.grant_present, grant.is_some(), "{obs:?}");
            assert_eq!(
                readiness.account_observed,
                grant.is_some() && matches!(account, EnrollmentAccountObservation::Present(_)),
                "{obs:?}"
            );
            if let (Some(grant), EnrollmentAccountObservation::Present(account)) = (grant, account)
            {
                assert_eq!(
                    readiness.epoch_matches,
                    expected_epoch(account.stored_epoch) == grant.epoch,
                    "{obs:?}"
                );
                assert_eq!(readiness.rotation_active, account.epoch_active, "{obs:?}");
                assert_eq!(
                    readiness.authority_present,
                    if grant.possession {
                        account.commitment_len > 0
                    } else {
                        account.credential_id_matches
                    },
                    "{obs:?}"
                );
                assert!(epoch_mismatch_precedes_rotation_paused(grant, *account));
                assert!(epoch_mismatch_precedes_commitment_missing(grant, *account));
                assert!(epoch_mismatch_precedes_credential_replaced(grant, *account));
                assert!(rotation_paused_precedes_commitment_missing(grant, *account));
                assert!(rotation_paused_precedes_credential_replaced(
                    grant, *account
                ));
                assert!(commitment_missing_and_credential_replaced_are_disjoint(
                    grant, *account
                ));
            }

            match decision {
                EnrollmentPreflightDecision::Ready(permit) => {
                    let Some(grant) = grant else {
                        panic!("ready without a grant: {obs:?}");
                    };
                    assert_eq!(expected, None, "{obs:?}");
                    assert_eq!(permit.epoch(), grant.epoch, "{obs:?}");
                    assert_eq!(permit.possession(), grant.possession, "{obs:?}");
                }
                EnrollmentPreflightDecision::Reject(reason) => {
                    assert_eq!(Some(reason), expected, "{obs:?}");
                }
            }
        }
    }
}

#[test]
fn enrollment_checks_each_decoded_key_length() {
    assert_eq!(vela_recovery_policy::HYBRID_EK_LEN, 1600);
    assert_eq!(vela_recovery_policy::HYBRID_VK_LEN, 2624);
    let valid = EnrollmentObservation {
        grant_present: true,
        grant_consumed: true,
        consumed_matches_observed: true,
        account_present: true,
        grant_possession: true,
        grant_epoch: 4,
        stored_epoch: Some(4),
        account_epoch_active: true,
        credential_id_matches: false,
        commitment_len: 2624,
        hybrid_ek_len: 1600,
        hybrid_vk_len: 2624,
    };
    for ek_len in [0, 1599, 1600, 1601] {
        for vk_len in [0, 2623, 2624, 2625] {
            let obs = EnrollmentObservation {
                hybrid_ek_len: ek_len,
                hybrid_vk_len: vk_len,
                ..valid
            };
            assert_eq!(
                matches!(
                    plan_enrollment(enrollment_facts(obs)),
                    EnrollmentDecision::Enroll(_)
                ),
                ek_len == 1600 && vk_len == 2624
            );
        }
    }
}
