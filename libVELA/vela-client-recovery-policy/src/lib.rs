//! Pure policy for reconstructing and adopting an RMS on a recovered client.
//!
//! Parsing, Shamir interpolation, share MAC verification, storage, and HTTP
//! stay outside this crate. Clients turn those observations into facts and can
//! obtain a private permit only for an exact account/epoch pair drawn from two
//! *distinct* channels (cloud + server, cloud + trusted contact, or server +
//! trusted contact) with authenticated, recipient-bound, distinct shares.

pub const INITIAL_EPOCH: i64 = 1;

/// Durable observations for publishing one freshly generated recovery split.
///
/// The journal containing these facts must be committed before any external
/// write.  The four progress bits are committed only after their corresponding
/// idempotent operation succeeds.  If a process dies between those two events,
/// the planner simply returns the same operation after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationFacts {
    pub journal_present: bool,
    pub account_matches: bool,
    pub split_id_present: bool,
    pub cloud_share_present: bool,
    pub server_share_present: bool,
    pub journal_epoch: i64,
    pub current_epoch: i64,
    pub account_epoch_active: bool,
    pub server_staged: bool,
    pub cloud_candidate_durable: bool,
    pub server_finalized: bool,
    pub cloud_active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationAction {
    StageServer,
    UploadCloudCandidate,
    FinalizeServer,
    PromoteCloudActive,
    Complete,
    Retire,
    Reject,
}

pub fn publication_state_is_well_formed(facts: PublicationFacts) -> bool {
    (!facts.server_finalized || (facts.server_staged && facts.cloud_candidate_durable))
        && (!facts.cloud_active || facts.server_finalized)
}

pub fn publication_journal_is_bound(facts: PublicationFacts) -> bool {
    facts.journal_present
        && facts.account_matches
        && facts.split_id_present
        && facts.cloud_share_present
        && facts.server_share_present
        && facts.journal_epoch >= INITIAL_EPOCH
        && publication_state_is_well_formed(facts)
}

pub fn publication_is_current(facts: PublicationFacts) -> bool {
    publication_journal_is_bound(facts)
        && facts.current_epoch >= INITIAL_EPOCH
        && facts.journal_epoch == facts.current_epoch
        && facts.account_epoch_active
}

pub fn publication_plan_matches_spec(facts: PublicationFacts, action: PublicationAction) -> bool {
    if !publication_journal_is_bound(facts) {
        action == PublicationAction::Reject
    } else if facts.current_epoch < INITIAL_EPOCH
        || facts.journal_epoch != facts.current_epoch
        || !facts.account_epoch_active
    {
        action == PublicationAction::Retire
    } else if facts.cloud_active {
        action == PublicationAction::Complete
    } else if facts.server_finalized {
        action == PublicationAction::PromoteCloudActive
    } else if !facts.server_staged {
        action == PublicationAction::StageServer
    } else if !facts.cloud_candidate_durable {
        action == PublicationAction::UploadCloudCandidate
    } else {
        action == PublicationAction::FinalizeServer
    }
}

/// Return the single operation that should be retried for this journal.
#[cfg_attr(hax, hax_lib::ensures(|action| {
    publication_plan_matches_spec(facts, action)
}))]
pub fn plan_publication_resume(facts: PublicationFacts) -> PublicationAction {
    if !publication_journal_is_bound(facts) {
        PublicationAction::Reject
    } else if facts.current_epoch < INITIAL_EPOCH
        || facts.journal_epoch != facts.current_epoch
        || !facts.account_epoch_active
    {
        PublicationAction::Retire
    } else if facts.cloud_active {
        PublicationAction::Complete
    } else if facts.server_finalized {
        PublicationAction::PromoteCloudActive
    } else if !facts.server_staged {
        PublicationAction::StageServer
    } else if !facts.cloud_candidate_durable {
        PublicationAction::UploadCloudCandidate
    } else {
        PublicationAction::FinalizeServer
    }
}

/// Authorize an operation selected by a UI.  Staging and candidate upload are
/// intentionally independent, so desktop users may complete those ceremonies
/// in either order.  Finalization and promotion remain strictly ordered.
pub fn publication_action_is_authorized(
    facts: PublicationFacts,
    action: PublicationAction,
) -> bool {
    if !publication_is_current(facts) {
        return false;
    }
    match action {
        PublicationAction::StageServer => !facts.server_finalized && !facts.cloud_active,
        PublicationAction::UploadCloudCandidate => !facts.server_finalized && !facts.cloud_active,
        PublicationAction::FinalizeServer => {
            facts.server_staged && facts.cloud_candidate_durable && !facts.cloud_active
        }
        PublicationAction::PromoteCloudActive => facts.server_finalized,
        PublicationAction::Complete => facts.cloud_active,
        PublicationAction::Retire | PublicationAction::Reject => false,
    }
}

/// A setup may be discarded only while both externally published copies are
/// still candidates.  Once the server winner is final, restart must finish the
/// active cloud pointer instead of abandoning a half-published recovery set.
pub fn publication_abort_is_authorized(facts: PublicationFacts) -> bool {
    publication_is_current(facts) && !facts.server_finalized && !facts.cloud_active
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rotated_journal_can_write_external(mut facts: PublicationFacts) -> bool {
    facts.current_epoch = if facts.journal_epoch == i64::MAX {
        facts.journal_epoch - 1
    } else {
        facts.journal_epoch + 1
    };
    publication_action_is_authorized(facts, PublicationAction::StageServer)
        || publication_action_is_authorized(facts, PublicationAction::UploadCloudCandidate)
        || publication_action_is_authorized(facts, PublicationAction::FinalizeServer)
        || publication_action_is_authorized(facts, PublicationAction::PromoteCloudActive)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn finalized_publication_can_abort(mut facts: PublicationFacts) -> bool {
    facts.server_staged = true;
    facts.cloud_candidate_durable = true;
    facts.server_finalized = true;
    publication_abort_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn malformed_journal_can_complete(mut facts: PublicationFacts) -> bool {
    facts.split_id_present = false;
    publication_action_is_authorized(facts, PublicationAction::Complete)
}

/// The three custodian channels of the 2-of-3 split (SPEC.md §4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryChannel {
    Cloud,
    Server,
    TrustedContact,
}

/// Durable observations about one candidate share of a recovery pair.
///
/// Every share must be bound to the same account, epoch, and Shamir split as
/// its partner. `recipient_bound` may only be claimed for a share that was
/// opened out of an authenticated envelope addressed to this exact recipient —
/// raw key material copied by hand can never carry it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundShareFacts {
    pub account_matches: bool,
    pub channel: RecoveryChannel,
    pub epoch: i64,
    pub split_id_present: bool,
    pub share_authenticated: bool,
    pub recipient_bound: bool,
    pub coordinate: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairSelectionFacts {
    pub requested_account_present: bool,
    /// True iff both shares carry the same split identifier (or neither
    /// carries one — pre-M16 legacy shares). Presence itself is expressed per
    /// share in `BoundShareFacts`.
    pub split_ids_match: bool,
    pub first: BoundShareFacts,
    pub second: BoundShareFacts,
}

/// Kept for callers that speak of "the reconstruction facts"; this is exactly
/// the generic two-share pair-selection input.
pub type ReconstructionFacts = PairSelectionFacts;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconstructionPermit {
    epoch: i64,
    exact_account_and_epoch: bool,
}

impl ReconstructionPermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn binds_exact_account_and_epoch(self) -> bool {
        self.exact_account_and_epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionDecision {
    Reconstruct(ReconstructionPermit),
    Reject,
}

/// M18 pair-selection policy: any two *distinct* channels of the same exact
/// account/epoch/split context reconstruct, provided both shares are
/// authenticated, address distinct Shamir coordinates, and trusted-contact
/// shares arrived through a recipient-bound authenticated envelope.
pub fn reconstruction_is_authorized(facts: ReconstructionFacts) -> bool {
    let (first, second) = (&facts.first, &facts.second);
    facts.requested_account_present
        && first.account_matches
        && second.account_matches
        // Two shares from the same channel are one custodian speaking twice.
        && first.channel != second.channel
        && first.epoch >= INITIAL_EPOCH
        && first.epoch == second.epoch
        && ((!first.split_id_present && !second.split_id_present)
            || (first.split_id_present && second.split_id_present && facts.split_ids_match))
        && first.share_authenticated
        && second.share_authenticated
        // Only a share opened out of an authenticated envelope addressed to
        // this exact recipient may enter on the trusted-contact channel.
        && (first.channel != RecoveryChannel::TrustedContact || first.recipient_bound)
        && (second.channel != RecoveryChannel::TrustedContact || second.recipient_bound)
        && first.coordinate != second.coordinate
}

pub fn reconstruction_decision_matches_spec(
    facts: ReconstructionFacts,
    decision: ReconstructionDecision,
) -> bool {
    match decision {
        ReconstructionDecision::Reconstruct(permit) => {
            reconstruction_is_authorized(facts)
                && permit.epoch == facts.first.epoch
                && permit.exact_account_and_epoch
        }
        ReconstructionDecision::Reject => !reconstruction_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    reconstruction_decision_matches_spec(facts, decision)
}))]
pub fn plan_reconstruction(facts: ReconstructionFacts) -> ReconstructionDecision {
    if reconstruction_is_authorized(facts) {
        ReconstructionDecision::Reconstruct(ReconstructionPermit {
            epoch: facts.first.epoch,
            exact_account_and_epoch: true,
        })
    } else {
        ReconstructionDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdoptionFacts {
    pub shares_authenticated_together: bool,
    pub reconstructed_rms_is_32_bytes: bool,
    pub target_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdoptionPermit {
    epoch: i64,
}

impl AdoptionPermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionDecision {
    Adopt(AdoptionPermit),
    Reject,
}

pub fn adoption_is_authorized(reconstruction: ReconstructionPermit, facts: AdoptionFacts) -> bool {
    reconstruction.exact_account_and_epoch
        && reconstruction.epoch >= INITIAL_EPOCH
        && facts.shares_authenticated_together
        && facts.reconstructed_rms_is_32_bytes
        && facts.target_epoch == reconstruction.epoch
}

pub fn adoption_decision_matches_spec(
    reconstruction: ReconstructionPermit,
    facts: AdoptionFacts,
    decision: AdoptionDecision,
) -> bool {
    match decision {
        AdoptionDecision::Adopt(permit) => {
            adoption_is_authorized(reconstruction, facts) && permit.epoch == reconstruction.epoch
        }
        AdoptionDecision::Reject => !adoption_is_authorized(reconstruction, facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    adoption_decision_matches_spec(reconstruction, facts, decision)
}))]
pub fn plan_adoption(
    reconstruction: ReconstructionPermit,
    facts: AdoptionFacts,
) -> AdoptionDecision {
    if adoption_is_authorized(reconstruction, facts) {
        AdoptionDecision::Adopt(AdoptionPermit {
            epoch: reconstruction.epoch,
        })
    } else {
        AdoptionDecision::Reject
    }
}

#[cfg(test)]
fn valid_pair() -> (BoundShareFacts, BoundShareFacts) {
    (
        BoundShareFacts {
            account_matches: true,
            channel: RecoveryChannel::Cloud,
            epoch: 7,
            split_id_present: true,
            share_authenticated: true,
            recipient_bound: false,
            coordinate: 1,
        },
        BoundShareFacts {
            account_matches: true,
            channel: RecoveryChannel::Server,
            epoch: 7,
            split_id_present: true,
            share_authenticated: true,
            recipient_bound: false,
            coordinate: 2,
        },
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn cross_account_shares_can_reconstruct(mut facts: ReconstructionFacts) -> bool {
    facts.first.account_matches = false;
    reconstruction_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn mixed_epoch_shares_can_reconstruct(mut facts: ReconstructionFacts) -> bool {
    facts.second.epoch = if facts.first.epoch == i64::MAX {
        facts.first.epoch - 1
    } else {
        facts.first.epoch + 1
    };
    reconstruction_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn untagged_shares_can_reconstruct(mut facts: ReconstructionFacts) -> bool {
    facts.first.share_authenticated = false;
    reconstruction_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn mismatched_split_ids_can_reconstruct(mut facts: ReconstructionFacts) -> bool {
    // Both shares carry a split id but the values differ.
    facts.first.split_id_present = true;
    facts.second.split_id_present = true;
    facts.split_ids_match = false;
    reconstruction_is_authorized(facts)
}

/// Two shares from the *same* channel are one custodian speaking twice — even
/// at distinct coordinates they must never count as a 2-of-3 quorum.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn same_channel_shares_can_reconstruct(mut facts: ReconstructionFacts) -> bool {
    facts.second.channel = facts.first.channel;
    reconstruction_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn duplicate_coordinates_can_reconstruct(mut facts: ReconstructionFacts) -> bool {
    facts.second.coordinate = facts.first.coordinate;
    reconstruction_is_authorized(facts)
}

/// A trusted-contact share that did not arrive through an authenticated
/// envelope addressed to this exact recipient is raw copied material and must
/// never reconstruct.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unbound_contact_share_can_reconstruct(mut facts: ReconstructionFacts) -> bool {
    facts.second.channel = RecoveryChannel::TrustedContact;
    facts.second.recipient_bound = false;
    reconstruction_is_authorized(facts)
}

// ── Trusted-contact delivery and retirement (M18) ──────────────────────────

/// Durable observations for handing Share 3 to its trusted contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactDeliveryFacts {
    pub journal_bound: bool,
    pub journal_is_current: bool,
    pub split_id_present: bool,
    pub share_present: bool,
    /// A KEM public key for the intended recipient was recorded with this
    /// setup. Sealing without one would reintroduce the manual copy flow.
    pub recipient_key_present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactDeliveryAction {
    Seal,
    Retire,
    Reject,
}

pub fn contact_delivery_plan_matches_spec(
    facts: ContactDeliveryFacts,
    action: ContactDeliveryAction,
) -> bool {
    if !facts.journal_bound {
        action == ContactDeliveryAction::Reject
    } else if !facts.journal_is_current || !facts.share_present {
        action == ContactDeliveryAction::Retire
    } else if facts.split_id_present && facts.recipient_key_present {
        action == ContactDeliveryAction::Seal
    } else {
        action == ContactDeliveryAction::Reject
    }
}

/// Decide what may happen to the cached trusted-contact share: seal it into
/// an authenticated envelope for the recorded recipient, retire it because
/// its epoch no longer matches (RMS rotation), or reject a malformed journal.
#[cfg_attr(hax, hax_lib::ensures(|action| {
    contact_delivery_plan_matches_spec(facts, action)
}))]
pub fn plan_contact_delivery(facts: ContactDeliveryFacts) -> ContactDeliveryAction {
    if !facts.journal_bound {
        ContactDeliveryAction::Reject
    } else if !facts.journal_is_current || !facts.share_present {
        ContactDeliveryAction::Retire
    } else if facts.split_id_present && facts.recipient_key_present {
        ContactDeliveryAction::Seal
    } else {
        ContactDeliveryAction::Reject
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rotated_contact_journal_can_seal(mut facts: ContactDeliveryFacts) -> bool {
    facts.journal_is_current = false;
    contact_delivery_plan_matches_spec(facts, ContactDeliveryAction::Seal)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn keyless_contact_delivery_can_seal(mut facts: ContactDeliveryFacts) -> bool {
    facts.recipient_key_present = false;
    contact_delivery_plan_matches_spec(facts, ContactDeliveryAction::Seal)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unauthenticated_secret_can_be_adopted(
    reconstruction: ReconstructionPermit,
    mut facts: AdoptionFacts,
) -> bool {
    facts.shares_authenticated_together = false;
    adoption_is_authorized(reconstruction, facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn wrong_epoch_secret_can_be_adopted(
    reconstruction: ReconstructionPermit,
    mut facts: AdoptionFacts,
) -> bool {
    facts.target_epoch = if reconstruction.epoch == i64::MAX {
        reconstruction.epoch - 1
    } else {
        reconstruction.epoch + 1
    };
    adoption_is_authorized(reconstruction, facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair_facts(first: BoundShareFacts, second: BoundShareFacts) -> ReconstructionFacts {
        ReconstructionFacts {
            requested_account_present: true,
            split_ids_match: true,
            first,
            second,
        }
    }

    fn valid() -> ReconstructionFacts {
        let (first, second) = valid_pair();
        pair_facts(first, second)
    }

    fn contact_pair() -> ReconstructionFacts {
        let (mut first, mut second) = valid_pair();
        first.channel = RecoveryChannel::Cloud;
        first.recipient_bound = false;
        second.channel = RecoveryChannel::TrustedContact;
        second.recipient_bound = true;
        pair_facts(first, second)
    }

    fn server_contact_pair() -> ReconstructionFacts {
        let (mut first, mut second) = valid_pair();
        first.channel = RecoveryChannel::Server;
        second.channel = RecoveryChannel::TrustedContact;
        second.recipient_bound = true;
        pair_facts(first, second)
    }

    #[test]
    fn exact_context_reconstructs_and_adopts() {
        for facts in [valid(), contact_pair(), server_contact_pair()] {
            let ReconstructionDecision::Reconstruct(permit) = plan_reconstruction(facts) else {
                panic!("valid context rejected");
            };
            assert_eq!(permit.epoch(), 7);
            assert!(permit.binds_exact_account_and_epoch());
            assert!(matches!(
                plan_adoption(
                    permit,
                    AdoptionFacts {
                        shares_authenticated_together: true,
                        reconstructed_rms_is_32_bytes: true,
                        target_epoch: 7,
                    }
                ),
                AdoptionDecision::Adopt(_)
            ));
        }
    }

    #[test]
    fn every_pair_dimension_is_mandatory() {
        // Bit-flip each boolean fact and perturb each numeric binding; the
        // policy must reject all of them.
        let base = valid();
        let mutations: &[Box<dyn Fn(&mut ReconstructionFacts)>] = &[
            Box::new(|f: &mut ReconstructionFacts| f.requested_account_present = false),
            Box::new(|f: &mut ReconstructionFacts| f.first.account_matches = false),
            Box::new(|f: &mut ReconstructionFacts| f.second.account_matches = false),
            Box::new(|f: &mut ReconstructionFacts| {
                f.second.channel = f.first.channel
            }),
            Box::new(|f: &mut ReconstructionFacts| f.first.epoch = 0),
            Box::new(|f: &mut ReconstructionFacts| f.second.epoch += 1),
            Box::new(|f: &mut ReconstructionFacts| {
                f.split_ids_match = false
            }),
            Box::new(|f: &mut ReconstructionFacts| f.first.split_id_present = false),
            Box::new(|f: &mut ReconstructionFacts| f.second.share_authenticated = false),
            Box::new(|f: &mut ReconstructionFacts| f.second.coordinate = f.first.coordinate),
            Box::new(|f: &mut ReconstructionFacts| {
                f.second.channel = RecoveryChannel::TrustedContact;
                f.second.recipient_bound = false;
            }),
        ];
        for mutate in mutations {
            let mut facts = base;
            mutate(&mut facts);
            assert_eq!(plan_reconstruction(facts), ReconstructionDecision::Reject);
        }
    }

    #[test]
    fn negative_theorems_hold() {
        assert!(!cross_account_shares_can_reconstruct(valid()));
        assert!(!mixed_epoch_shares_can_reconstruct(valid()));
        assert!(!untagged_shares_can_reconstruct(valid()));
        assert!(!mismatched_split_ids_can_reconstruct(valid()));
        assert!(!same_channel_shares_can_reconstruct(valid()));
        assert!(!duplicate_coordinates_can_reconstruct(valid()));
        assert!(!unbound_contact_share_can_reconstruct(contact_pair()));
    }

    fn delivery_valid() -> ContactDeliveryFacts {
        ContactDeliveryFacts {
            journal_bound: true,
            journal_is_current: true,
            split_id_present: true,
            share_present: true,
            recipient_key_present: true,
        }
    }

    #[test]
    fn contact_delivery_seals_only_current_bound_setups() {
        assert_eq!(
            plan_contact_delivery(delivery_valid()),
            ContactDeliveryAction::Seal
        );
        let mut rotated = delivery_valid();
        rotated.journal_is_current = false;
        assert_eq!(
            plan_contact_delivery(rotated),
            ContactDeliveryAction::Retire
        );
        let mut unbound = delivery_valid();
        unbound.journal_bound = false;
        assert_eq!(
            plan_contact_delivery(unbound),
            ContactDeliveryAction::Reject
        );
        let mut keyless = delivery_valid();
        keyless.recipient_key_present = false;
        assert_eq!(
            plan_contact_delivery(keyless),
            ContactDeliveryAction::Reject
        );
        assert!(!rotated_contact_journal_can_seal(rotated));
        assert!(!keyless_contact_delivery_can_seal(keyless));
    }
}
