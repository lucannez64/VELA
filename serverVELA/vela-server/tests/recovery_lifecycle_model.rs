//! Exhaustive bounded refinement checks for the M14 recovery policy.

use vela_recovery_policy::{
    credential_update_decision_matches_spec, enrollment_is_authorized, initiation_is_authorized,
    plan_credential_update, plan_enrollment, plan_initiation, plan_recovery, plan_registration,
    recovery_is_authorized, registration_is_authorized, CredentialUpdateFacts, EnrollmentDecision,
    EnrollmentFacts, InitiateDecision, InitiateFacts, RecoverDecision, RecoverFacts, RecoveryPhase,
    RegistrationDecision, RegistrationFacts,
};

const PHASES: [RecoveryPhase; 7] = [
    RecoveryPhase::Unavailable,
    RecoveryPhase::Ready,
    RecoveryPhase::ChallengePending,
    RecoveryPhase::GrantIssued,
    RecoveryPhase::Completed,
    RecoveryPhase::Revoked,
    RecoveryPhase::Expired,
];
const EPOCHS: [i64; 4] = [-1, 0, 1, 2];

fn bit(mask: u16, index: u16) -> bool {
    mask & (1 << index) != 0
}

#[test]
fn every_bounded_initiation_and_registration_matches_m14() {
    for phase in PHASES {
        for mask in 0..32 {
            let facts = InitiateFacts {
                phase,
                account_exists: bit(mask, 0),
                share_present: bit(mask, 1),
                credential_present: bit(mask, 2),
                attempt_id_fresh: bit(mask, 3),
                ttl_positive: bit(mask, 4),
            };
            assert_eq!(
                matches!(plan_initiation(facts), InitiateDecision::Start(_)),
                initiation_is_authorized(facts)
            );
        }
    }

    for mask in 0..64 {
        let facts = RegistrationFacts {
            device_scope: bit(mask, 0),
            account_matches: bit(mask, 1),
            challenge_pending: bit(mask, 2),
            challenge_consumed: bit(mask, 3),
            credential_valid: bit(mask, 4),
            credential_unique: bit(mask, 5),
        };
        assert_eq!(
            matches!(plan_registration(facts), RegistrationDecision::Register(_)),
            registration_is_authorized(facts)
        );
    }
}

#[test]
fn every_bounded_share_release_and_credential_update_matches_m14() {
    for phase in PHASES {
        for epoch in EPOCHS {
            for mask in 0..256 {
                let facts = RecoverFacts {
                    phase,
                    user_matches: bit(mask, 0),
                    attempt_matches: bit(mask, 1),
                    challenge_consumed: bit(mask, 2),
                    credential_matches_current: bit(mask, 3),
                    assertion_valid: bit(mask, 4),
                    user_verified: bit(mask, 5),
                    share_present: bit(mask, 6),
                    account_epoch_active: bit(mask, 7),
                    epoch,
                };
                assert_eq!(
                    matches!(plan_recovery(facts), RecoverDecision::Release(_)),
                    recovery_is_authorized(facts),
                    "recovery mismatch for {facts:?}"
                );
            }
        }
    }

    for mask in 0..8 {
        let facts = CredentialUpdateFacts {
            assertion_valid: bit(mask, 0),
            credential_matches_current: bit(mask, 1),
            needs_update: bit(mask, 2),
        };
        let decision = plan_credential_update(facts);
        assert!(credential_update_decision_matches_spec(facts, decision));
    }
}

#[test]
fn every_bounded_recovered_device_enrollment_matches_m14() {
    for phase in PHASES {
        for grant_epoch in EPOCHS {
            for account_epoch in EPOCHS {
                for mask in 0..256 {
                    let facts = EnrollmentFacts {
                        phase,
                        user_matches: bit(mask, 0),
                        grant_live: bit(mask, 1),
                        grant_consumed: bit(mask, 2),
                        credential_matches_current: bit(mask, 3),
                        possession_grant: bit(mask, 4),
                        possession_hash_present: bit(mask, 5),
                        public_keys_valid: bit(mask, 6),
                        account_epoch_active: bit(mask, 7),
                        grant_epoch,
                        account_epoch,
                    };
                    assert_eq!(
                        matches!(plan_enrollment(facts), EnrollmentDecision::Enroll(_)),
                        enrollment_is_authorized(facts),
                        "enrollment mismatch for {facts:?}"
                    );
                }
            }
        }
    }
}
