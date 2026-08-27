//! Exhaustive bounded refinement checks for the M13 enrollment policy.
//!
//! Tamarin quantifies over unbounded protocol traces and hax/F* verifies the
//! pure constructors. This test enumerates every finite fact combination the
//! HTTP boundary can hand those constructors, catching wiring drift in normal
//! Rust CI without requiring the formal toolchain.

use vela_enrollment_policy::{
    authorize_inspection, authorize_result, claim_is_authorized, completion_is_authorized,
    inspection_is_authorized, open_is_authorized, plan_claim, plan_completion, plan_open,
    result_is_authorized, CeremonyPhase, ClaimDecision, ClaimFacts, CompletionDecision,
    CompletionFacts, InspectDecision, InspectFacts, OpenDecision, OpenFacts, ResultDecision,
    ResultFacts, ResultKind,
};

const PHASES: [CeremonyPhase; 5] = [
    CeremonyPhase::Open,
    CeremonyPhase::Claimed,
    CeremonyPhase::Completed,
    CeremonyPhase::Revoked,
    CeremonyPhase::Expired,
];

fn bit(mask: u16, index: u16) -> bool {
    mask & (1 << index) != 0
}

#[test]
fn every_bounded_open_claim_and_inspection_matches_m13() {
    for mask in 0..16 {
        let facts = OpenFacts {
            device_scope: bit(mask, 0),
            user_bound: bit(mask, 1),
            opener_bound: bit(mask, 2),
            ttl_positive: bit(mask, 3),
        };
        assert_eq!(
            matches!(plan_open(facts), OpenDecision::Open(_)),
            open_is_authorized(facts)
        );
    }

    for phase in PHASES {
        for mask in 0..8 {
            let facts = ClaimFacts {
                phase,
                grant_live: bit(mask, 0),
                no_existing_claim: bit(mask, 1),
                public_keys_valid: bit(mask, 2),
            };
            assert_eq!(
                matches!(plan_claim(facts), ClaimDecision::Claim(_)),
                claim_is_authorized(facts)
            );
        }
        for mask in 0..8 {
            let facts = InspectFacts {
                phase,
                user_matches: bit(mask, 0),
                opener_matches: bit(mask, 1),
                claim_present: bit(mask, 2),
            };
            assert_eq!(
                matches!(authorize_inspection(facts), InspectDecision::Inspect(_)),
                inspection_is_authorized(facts)
            );
        }
    }
}

#[test]
fn every_bounded_completion_matches_m13() {
    for phase in PHASES {
        for mask in 0..128 {
            let facts = CompletionFacts {
                phase,
                user_matches: bit(mask, 0),
                opener_matches: bit(mask, 1),
                opener_active: bit(mask, 2),
                claim_present: bit(mask, 3),
                displayed_claim_is_stored_claim: bit(mask, 4),
                signature_covers_stored_claim: bit(mask, 5),
                account_epoch_active: bit(mask, 6),
            };
            assert_eq!(
                matches!(
                    plan_completion(facts),
                    CompletionDecision::Complete(permit)
                        if permit.consumes_grant_and_claim()
                ),
                completion_is_authorized(facts),
                "completion mismatch for {facts:?}"
            );
        }
    }
}

#[test]
fn every_bounded_result_decision_matches_m13() {
    for phase in PHASES {
        for mask in 0..4 {
            let facts = ResultFacts {
                phase,
                claimed_key_present: bit(mask, 0),
                claimed_key_proof_valid: bit(mask, 1),
            };
            match authorize_result(facts) {
                ResultDecision::Return(permit) => {
                    assert!(result_is_authorized(facts));
                    let expected = if phase == CeremonyPhase::Claimed {
                        ResultKind::Pending
                    } else {
                        ResultKind::Enrolled
                    };
                    assert_eq!(permit.kind(), expected);
                }
                ResultDecision::Reject => assert!(!result_is_authorized(facts)),
            }
        }
    }
}
