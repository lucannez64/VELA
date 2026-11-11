//! Exhaust the Boolean fact space (with representative revisions) and check
//! the decision against the spec and every negative theorem.

use vela_client_share_policy::*;

fn all_facts() -> Vec<ShareAdmissionFacts> {
    let revisions = [0u64, 1, 2, 5, u64::MAX - 1, u64::MAX];
    let mut out = Vec::new();
    for bits in 0u32..(1 << 6) {
        let b = |i: u32| bits & (1 << i) != 0;
        for &pinned in &revisions {
            for &candidate in &revisions {
                out.push(ShareAdmissionFacts {
                    envelope_authenticated: b(0),
                    addressed_to_recipient: b(1),
                    sender_matches_attribution: b(2),
                    has_pin: b(3),
                    signer_matches_pin: b(4),
                    lineage_matches_pin: b(5),
                    pinned_revision: pinned,
                    candidate_revision: candidate,
                });
            }
        }
    }
    out
}

#[test]
fn decisions_match_the_spec_everywhere() {
    for facts in all_facts() {
        let decision = plan_share_admission(facts);
        assert!(admission_matches_spec(facts, decision), "{facts:?} -> {decision:?}");
    }
}

#[test]
fn negative_theorems_hold_everywhere() {
    for facts in all_facts() {
        assert!(!unauthenticated_share_can_be_admitted(facts));
        assert!(!misaddressed_share_can_be_admitted(facts));
        assert!(!misattributed_share_can_be_admitted(facts));
        assert!(!foreign_signer_update_can_be_applied(facts));
        assert!(!cross_lineage_update_can_be_applied(facts));
        assert!(!stale_revision_update_can_be_applied(facts));
        assert!(!pinned_share_can_restart_as_first_contact(facts));
    }
}
