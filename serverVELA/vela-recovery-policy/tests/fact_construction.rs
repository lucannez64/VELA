//! Exhaustive bounded checks for the recovery observation → fact mappings.
//!
//! The hax/F* postconditions state each fact exactly in terms of its raw
//! observation. This test enumerates every Boolean combination, both attempt
//! sources, a small epoch range and zero/positive TTLs, then checks the
//! mapping, the composed authorization predicate and every negative theorem
//! against the same values. It is ordinary Rust CI, not a substitute for the
//! F* check.

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
