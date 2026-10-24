//! Exhaustive bounded checks for the enrollment observation → fact mappings.
//!
//! The hax/F* postconditions state each fact exactly in terms of its raw
//! observation. This test enumerates every Boolean combination, the three key
//! length classes plus zero, the three result sources and a small epoch range,
//! then checks both the mapping and every negative theorem against the same
//! values. It is ordinary Rust CI, not a substitute for the F* check.

use vela_enrollment_policy::{
    claim_facts, claim_is_authorized, completion_facts, completion_is_authorized,
    expired_grant_can_open, foreign_device_can_complete_observed_ceremony, inspect_facts,
    inspection_is_authorized, invalid_public_key_length_can_be_claimed,
    invalid_result_signature_can_return_result, missing_claim_can_be_inspected,
    missing_claim_can_complete_observed_ceremony, missing_claimed_key_can_return_result,
    missing_grant_can_be_claimed, open_facts, open_is_authorized,
    other_device_can_inspect_observed_claim, request_supplied_claim_can_complete, result_facts,
    result_is_authorized, revoked_opener_can_complete, stale_epoch_can_complete,
    unclaimed_ceremony_can_return_result, unverified_signature_can_complete,
    web_session_can_open_enrollment_grant, CeremonyPhase, ClaimKeySource, ClaimObservation,
    CompletionObservation, InspectObservation, OpenObservation, ResultObservation, ResultSource,
    HYBRID_EK_LEN, HYBRID_VK_LEN,
};

const EK_LENGTHS: [usize; 4] = [0, HYBRID_EK_LEN - 1, HYBRID_EK_LEN, HYBRID_EK_LEN + 1];
const VK_LENGTHS: [usize; 4] = [0, HYBRID_VK_LEN - 1, HYBRID_VK_LEN, HYBRID_VK_LEN + 1];
const EPOCHS: [i64; 3] = [0, 1, 2];

#[test]
fn open_facts_are_exactly_the_session_observations() {
    for &scope_is_device in &[false, true] {
        for &user_id_present in &[false, true] {
            for &device_id_present in &[false, true] {
                for &ttl_secs in &[0_u64, 1, 300] {
                    let obs = OpenObservation {
                        scope_is_device,
                        user_id_present,
                        device_id_present,
                        ttl_secs,
                    };
                    let facts = open_facts(obs);

                    assert_eq!(facts.device_scope, scope_is_device);
                    assert_eq!(facts.user_bound, user_id_present);
                    assert_eq!(facts.opener_bound, device_id_present);
                    assert_eq!(facts.ttl_positive, ttl_secs > 0);
                    assert_eq!(
                        open_is_authorized(facts),
                        scope_is_device && user_id_present && device_id_present && ttl_secs > 0
                    );

                    assert!(!web_session_can_open_enrollment_grant(obs));
                    assert!(!expired_grant_can_open(obs));
                }
            }
        }
    }
}

#[test]
fn claim_facts_are_exactly_the_grant_store_and_lengths() {
    for &grant_live in &[false, true] {
        for &claim_exists in &[false, true] {
            for &hybrid_ek_len in &EK_LENGTHS {
                for &hybrid_vk_len in &VK_LENGTHS {
                    let obs = ClaimObservation {
                        grant_live,
                        claim_exists,
                        hybrid_ek_len,
                        hybrid_vk_len,
                    };
                    let facts = claim_facts(obs);

                    assert_eq!(
                        matches!(facts.phase, CeremonyPhase::Claimed),
                        claim_exists,
                        "{obs:?}"
                    );
                    assert_eq!(
                        matches!(facts.phase, CeremonyPhase::Open),
                        !claim_exists,
                        "{obs:?}"
                    );
                    assert_eq!(facts.grant_live, grant_live);
                    assert_eq!(facts.no_existing_claim, !claim_exists);
                    assert_eq!(
                        facts.public_keys_valid,
                        hybrid_ek_len == HYBRID_EK_LEN && hybrid_vk_len == HYBRID_VK_LEN
                    );
                    assert_eq!(
                        claim_is_authorized(facts),
                        !claim_exists
                            && grant_live
                            && hybrid_ek_len == HYBRID_EK_LEN
                            && hybrid_vk_len == HYBRID_VK_LEN
                    );

                    assert!(!missing_grant_can_be_claimed(obs));
                    assert!(!invalid_public_key_length_can_be_claimed(obs));
                }
            }
        }
    }
}

#[test]
fn inspect_facts_are_exactly_the_claim_and_session_bindings() {
    for &claim_present in &[false, true] {
        for &user_matches in &[false, true] {
            for &opener_matches in &[false, true] {
                let obs = InspectObservation {
                    claim_present,
                    user_matches,
                    opener_matches,
                };
                let facts = inspect_facts(obs);

                assert_eq!(
                    matches!(facts.phase, CeremonyPhase::Claimed),
                    claim_present,
                    "{obs:?}"
                );
                assert_eq!(
                    matches!(facts.phase, CeremonyPhase::Open),
                    !claim_present,
                    "{obs:?}"
                );
                assert_eq!(facts.user_matches, user_matches);
                assert_eq!(facts.opener_matches, opener_matches);
                assert_eq!(facts.claim_present, claim_present);
                assert_eq!(
                    inspection_is_authorized(facts),
                    claim_present && user_matches && opener_matches
                );

                assert!(!missing_claim_can_be_inspected(obs));
                assert!(!other_device_can_inspect_observed_claim(obs));
            }
        }
    }
}

#[test]
fn completion_facts_are_exactly_the_store_sql_epoch_and_signature_observations() {
    for &claim_present in &[false, true] {
        for &user_matches in &[false, true] {
            for &opener_matches in &[false, true] {
                for &opener_active in &[false, true] {
                    for &signature_verified in &[false, true] {
                        for &claim_key_source in
                            &[ClaimKeySource::StoredClaim, ClaimKeySource::RequestSupplied]
                        {
                            for &account_epoch in &EPOCHS {
                                for &declared_epoch in &EPOCHS {
                                    for &rotation_in_progress in &[false, true] {
                                        let obs = CompletionObservation {
                                            claim_present,
                                            user_matches,
                                            opener_matches,
                                            opener_active,
                                            signature_verified,
                                            claim_key_source,
                                            account_epoch,
                                            declared_epoch,
                                            rotation_in_progress,
                                        };
                                        let facts = completion_facts(obs);
                                        let stored =
                                            matches!(claim_key_source, ClaimKeySource::StoredClaim);
                                        let account_epoch_active = declared_epoch >= 1
                                            && account_epoch == declared_epoch
                                            && !rotation_in_progress;

                                        assert_eq!(
                                            matches!(facts.phase, CeremonyPhase::Claimed),
                                            claim_present,
                                            "{obs:?}"
                                        );
                                        assert_eq!(
                                            matches!(facts.phase, CeremonyPhase::Open),
                                            !claim_present,
                                            "{obs:?}"
                                        );
                                        assert_eq!(facts.user_matches, user_matches);
                                        assert_eq!(facts.opener_matches, opener_matches);
                                        assert_eq!(facts.opener_active, opener_active);
                                        assert_eq!(facts.claim_present, claim_present);
                                        assert_eq!(
                                            facts.displayed_claim_is_stored_claim,
                                            claim_present && stored
                                        );
                                        assert_eq!(
                                            facts.signature_covers_stored_claim,
                                            signature_verified && claim_present && stored
                                        );
                                        assert_eq!(
                                            facts.account_epoch_active,
                                            account_epoch_active
                                        );
                                        assert_eq!(
                                            completion_is_authorized(facts),
                                            claim_present
                                                && user_matches
                                                && opener_matches
                                                && opener_active
                                                && stored
                                                && signature_verified
                                                && account_epoch_active
                                        );

                                        assert!(!revoked_opener_can_complete(obs));
                                        assert!(!foreign_device_can_complete_observed_ceremony(
                                            obs
                                        ));
                                        assert!(!unverified_signature_can_complete(obs));
                                        assert!(!missing_claim_can_complete_observed_ceremony(obs));
                                        assert!(!request_supplied_claim_can_complete(obs));
                                        assert!(!stale_epoch_can_complete(obs));
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

#[test]
fn result_facts_are_exactly_the_store_key_and_signature_observations() {
    for &source in &[
        ResultSource::CompletedResult,
        ResultSource::ClaimedClaim,
        ResultSource::NoRecord,
    ] {
        for &claimed_key_len in &VK_LENGTHS {
            for &signature_verified in &[false, true] {
                let obs = ResultObservation {
                    source,
                    claimed_key_len,
                    signature_verified,
                };
                let facts = result_facts(obs);

                match source {
                    ResultSource::CompletedResult => {
                        assert!(matches!(facts.phase, CeremonyPhase::Completed));
                    }
                    ResultSource::ClaimedClaim => {
                        assert!(matches!(facts.phase, CeremonyPhase::Claimed));
                    }
                    ResultSource::NoRecord => {
                        assert!(matches!(facts.phase, CeremonyPhase::Expired));
                    }
                }
                let claimed_key_present = claimed_key_len > 0;
                assert_eq!(facts.claimed_key_present, claimed_key_present);
                assert_eq!(
                    facts.claimed_key_proof_valid,
                    claimed_key_present && signature_verified
                );
                assert_eq!(
                    result_is_authorized(facts),
                    matches!(
                        source,
                        ResultSource::CompletedResult | ResultSource::ClaimedClaim
                    ) && claimed_key_present
                        && signature_verified
                );

                assert!(!invalid_result_signature_can_return_result(obs));
                assert!(!missing_claimed_key_can_return_result(obs));
                assert!(!unclaimed_ceremony_can_return_result(obs));
            }
        }
    }
}
