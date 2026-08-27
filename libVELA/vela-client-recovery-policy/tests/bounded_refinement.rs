use vela_client_recovery_policy::{
    adoption_decision_matches_spec, plan_adoption, plan_publication_resume, plan_reconstruction,
    publication_abort_is_authorized, publication_action_is_authorized,
    publication_plan_matches_spec, reconstruction_is_authorized, AdoptionDecision, AdoptionFacts,
    PublicationAction, PublicationFacts, ReconstructionDecision, ReconstructionFacts,
};

const EPOCHS: [i64; 4] = [-1, 0, 1, 2];

fn bit(mask: u16, index: u16) -> bool {
    mask & (1 << index) != 0
}

#[test]
fn every_bounded_publication_plan_matches_the_policy() {
    for journal_epoch in EPOCHS {
        for current_epoch in EPOCHS {
            for mask in 0..1024u16 {
                let facts = PublicationFacts {
                    journal_present: bit(mask, 0),
                    account_matches: bit(mask, 1),
                    split_id_present: bit(mask, 2),
                    cloud_share_present: bit(mask, 3),
                    server_share_present: bit(mask, 4),
                    journal_epoch,
                    current_epoch,
                    account_epoch_active: bit(mask, 5),
                    server_staged: bit(mask, 6),
                    cloud_candidate_durable: bit(mask, 7),
                    server_finalized: bit(mask, 8),
                    cloud_active: bit(mask, 9),
                };
                let action = plan_publication_resume(facts);
                assert!(publication_plan_matches_spec(facts, action));
                if matches!(
                    action,
                    PublicationAction::Retire | PublicationAction::Reject
                ) {
                    for external in [
                        PublicationAction::StageServer,
                        PublicationAction::UploadCloudCandidate,
                        PublicationAction::FinalizeServer,
                        PublicationAction::PromoteCloudActive,
                    ] {
                        assert!(!publication_action_is_authorized(facts, external));
                    }
                }
                if facts.server_finalized || facts.cloud_active {
                    assert!(!publication_abort_is_authorized(facts));
                }
            }
        }
    }
}

#[test]
fn every_bounded_reconstruction_decision_matches_the_policy() {
    use vela_client_recovery_policy::{BoundShareFacts, PairSelectionFacts, RecoveryChannel};
    const CHANNELS: [RecoveryChannel; 3] = [
        RecoveryChannel::Cloud,
        RecoveryChannel::Server,
        RecoveryChannel::TrustedContact,
    ];
    let mut checked = 0u64;
    for first_channel in CHANNELS {
        for second_channel in CHANNELS {
            for first_epoch in EPOCHS {
                for second_epoch in EPOCHS {
                    // 12 bounded bits: requested account, per-share account
                    // match / split presence / authentication / recipient
                    // binding, split-id match, and a 2-bit coordinate pair.
                    for mask in 0..4096u16 {
                        let coordinate_pair = (mask >> 10) & 0b11;
                        let (first_x, second_x) = match coordinate_pair {
                            0 => (1, 1),
                            1 => (1, 2),
                            2 => (3, 2),
                            _ => (200, 201),
                        };
                        let facts = PairSelectionFacts {
                            requested_account_present: bit(mask, 0),
                            split_ids_match: bit(mask, 5),
                            first: BoundShareFacts {
                                account_matches: bit(mask, 1),
                                channel: first_channel,
                                epoch: first_epoch,
                                split_id_present: bit(mask, 6),
                                share_authenticated: bit(mask, 7),
                                recipient_bound: bit(mask, 3),
                                coordinate: first_x,
                            },
                            second: BoundShareFacts {
                                account_matches: bit(mask, 2),
                                channel: second_channel,
                                epoch: second_epoch,
                                split_id_present: bit(mask, 9),
                                share_authenticated: bit(mask, 8),
                                recipient_bound: bit(mask, 4),
                                coordinate: second_x,
                            },
                        };
                        assert_eq!(
                            matches!(
                                plan_reconstruction(facts),
                                ReconstructionDecision::Reconstruct(_)
                            ),
                            reconstruction_is_authorized(facts),
                            "reconstruction mismatch for {facts:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    assert!(checked > 100_000);
}

#[test]
fn every_bounded_adoption_decision_matches_the_policy() {
    use vela_client_recovery_policy::{BoundShareFacts, PairSelectionFacts, RecoveryChannel};
    let share = |channel: RecoveryChannel, coordinate: u8| BoundShareFacts {
        account_matches: true,
        channel,
        epoch: 2,
        split_id_present: true,
        share_authenticated: true,
        recipient_bound: channel == RecoveryChannel::TrustedContact,
        coordinate,
    };
    let valid = PairSelectionFacts {
        requested_account_present: true,
        split_ids_match: true,
        first: share(RecoveryChannel::Cloud, 1),
        second: share(RecoveryChannel::Server, 2),
    };
    let ReconstructionDecision::Reconstruct(permit) = plan_reconstruction(valid) else {
        panic!("valid reconstruction rejected");
    };
    for target_epoch in EPOCHS {
        for mask in 0..4 {
            let facts = AdoptionFacts {
                shares_authenticated_together: bit(mask, 0),
                reconstructed_rms_is_32_bytes: bit(mask, 1),
                target_epoch,
            };
            let decision = plan_adoption(permit, facts);
            assert!(adoption_decision_matches_spec(permit, facts, decision));
            assert_eq!(
                matches!(decision, AdoptionDecision::Adopt(_)),
                facts.shares_authenticated_together
                    && facts.reconstructed_rms_is_32_bytes
                    && target_epoch == 2
            );
        }
    }
}
