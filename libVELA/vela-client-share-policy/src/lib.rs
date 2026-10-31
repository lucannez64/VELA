//! Pure admission policy for items another user shared with this device.
//!
//! A shared item arrives as a sealed, signed envelope (`vela-crypto`
//! `share_envelope`). Decryption, signature verification and parsing stay
//! outside this crate. The client turns what it observed into
//! [`ShareAdmissionFacts`] and gets back one decision:
//!
//! * **First contact** (an inbox item, or a linked share this device has not
//!   accepted yet): the envelope must be signed, addressed to this recipient's
//!   user id and share key, and claim the same sender the server attributed it
//!   to. Accepting it *pins* the signing key, the share lineage, and the
//!   revision.
//! * **Update** (a newer capsule for a share already accepted): additionally
//!   signed by the *pinned* key, in the *pinned* lineage, with a revision
//!   strictly above the pinned one.
//!
//! The pin is what makes updates independent of the server: after first
//! contact, nothing the server says (sender attribution, timestamps, which
//! capsule is current) can make this device apply content that the original
//! sender's device did not sign, or roll back to an older revision.
//!
//! Model: `security/formal/m19c_share_sender_authentication.spthy`.

/// Revisions start at 1. Zero is never a valid revision.
pub const INITIAL_REVISION: u64 = 1;

/// What the client observed about one received envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareAdmissionFacts {
    /// The capsule opened under this device's share key, parsed as a v2
    /// envelope, and its signature verified under the key it names.
    pub envelope_authenticated: bool,
    /// The signed recipient user id is this account, and the signed recipient
    /// key digest is the digest of this device's share key.
    pub addressed_to_recipient: bool,
    /// The signed sender user id equals the sender the server attributed this
    /// capsule to.
    pub sender_matches_attribution: bool,
    /// A pin exists for this share (it was accepted earlier).
    pub has_pin: bool,
    /// The signing key and sender user id equal the pinned ones.
    pub signer_matches_pin: bool,
    /// The signed lineage id equals the pinned one.
    pub lineage_matches_pin: bool,
    /// Revision recorded in the pin (ignored without a pin).
    pub pinned_revision: u64,
    /// Revision carried in the signed envelope.
    pub candidate_revision: u64,
}

/// Proof that the policy admitted an envelope. Fields are private: only this
/// crate can mint one, so callers cannot skip the decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharePinPermit {
    revision: u64,
}

impl SharePinPermit {
    /// The revision the caller must record in its pin.
    pub fn revision(self) -> u64 {
        share_permit_revision(self)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == permit.revision))]
pub fn share_permit_revision(permit: SharePinPermit) -> u64 {
    permit.revision
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareAdmissionDecision {
    /// Show as a new received share; pin on acceptance.
    AcceptFirstContact(SharePinPermit),
    /// Replace the held copy and advance the pin.
    ApplyUpdate(SharePinPermit),
    Reject,
}

/// Conditions shared by both paths.
pub fn envelope_is_bound(facts: ShareAdmissionFacts) -> bool {
    facts.envelope_authenticated
        && facts.addressed_to_recipient
        && facts.sender_matches_attribution
        && facts.candidate_revision >= INITIAL_REVISION
}

pub fn first_contact_is_admissible(facts: ShareAdmissionFacts) -> bool {
    !facts.has_pin && envelope_is_bound(facts)
}

pub fn update_is_admissible(facts: ShareAdmissionFacts) -> bool {
    facts.has_pin
        && envelope_is_bound(facts)
        && facts.signer_matches_pin
        && facts.lineage_matches_pin
        && facts.candidate_revision > facts.pinned_revision
}

pub fn admission_matches_spec(
    facts: ShareAdmissionFacts,
    decision: ShareAdmissionDecision,
) -> bool {
    match decision {
        ShareAdmissionDecision::AcceptFirstContact(permit) => {
            first_contact_is_admissible(facts) && permit.revision == facts.candidate_revision
        }
        ShareAdmissionDecision::ApplyUpdate(permit) => {
            update_is_admissible(facts) && permit.revision == facts.candidate_revision
        }
        ShareAdmissionDecision::Reject => {
            !first_contact_is_admissible(facts) && !update_is_admissible(facts)
        }
    }
}

/// Decide what to do with one received envelope.
#[cfg_attr(hax, hax_lib::ensures(|decision| admission_matches_spec(facts, decision)))]
pub fn plan_share_admission(facts: ShareAdmissionFacts) -> ShareAdmissionDecision {
    if first_contact_is_admissible(facts) {
        ShareAdmissionDecision::AcceptFirstContact(SharePinPermit {
            revision: facts.candidate_revision,
        })
    } else if update_is_admissible(facts) {
        ShareAdmissionDecision::ApplyUpdate(SharePinPermit {
            revision: facts.candidate_revision,
        })
    } else {
        ShareAdmissionDecision::Reject
    }
}

pub fn is_admitted(decision: ShareAdmissionDecision) -> bool {
    match decision {
        ShareAdmissionDecision::Reject => false,
        _ => true,
    }
}

// ── Negative theorems ────────────────────────────────────────────────────────
//
// Each takes arbitrary facts, falsifies one required observation, and targets a
// hax → F* proof that it is never admitted. See assurance logs for status.

/// An envelope whose signature did not verify (or that did not parse as v2 —
/// a legacy unsigned capsule) is never admitted.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unauthenticated_share_can_be_admitted(mut facts: ShareAdmissionFacts) -> bool {
    facts.envelope_authenticated = false;
    is_admitted(plan_share_admission(facts))
}

/// A signed envelope addressed to someone else (forwarded or retargeted) is
/// never admitted.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn misaddressed_share_can_be_admitted(mut facts: ShareAdmissionFacts) -> bool {
    facts.addressed_to_recipient = false;
    is_admitted(plan_share_admission(facts))
}

/// An envelope whose signed sender differs from the server's attribution is
/// never admitted.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn misattributed_share_can_be_admitted(mut facts: ShareAdmissionFacts) -> bool {
    facts.sender_matches_attribution = false;
    is_admitted(plan_share_admission(facts))
}

/// Once pinned, an update signed by any other key is never applied — even if
/// the server vouches for it.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn foreign_signer_update_can_be_applied(mut facts: ShareAdmissionFacts) -> bool {
    facts.has_pin = true;
    facts.signer_matches_pin = false;
    is_admitted(plan_share_admission(facts))
}

/// Once pinned, an envelope from another lineage (another share by the same
/// sender) never replaces this one.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn cross_lineage_update_can_be_applied(mut facts: ShareAdmissionFacts) -> bool {
    facts.has_pin = true;
    facts.lineage_matches_pin = false;
    is_admitted(plan_share_admission(facts))
}

/// Once pinned, a replayed or older revision is never applied.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn stale_revision_update_can_be_applied(mut facts: ShareAdmissionFacts) -> bool {
    facts.has_pin = true;
    if facts.candidate_revision > facts.pinned_revision {
        facts.candidate_revision = facts.pinned_revision;
    }
    is_admitted(plan_share_admission(facts))
}

/// A pinned share is never re-admitted as a first contact (which would let a
/// server reset the pin to a key of its choosing).
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn pinned_share_can_restart_as_first_contact(mut facts: ShareAdmissionFacts) -> bool {
    facts.has_pin = true;
    match plan_share_admission(facts) {
        ShareAdmissionDecision::AcceptFirstContact(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> ShareAdmissionFacts {
        ShareAdmissionFacts {
            envelope_authenticated: true,
            addressed_to_recipient: true,
            sender_matches_attribution: true,
            has_pin: false,
            signer_matches_pin: false,
            lineage_matches_pin: false,
            pinned_revision: 0,
            candidate_revision: 1,
        }
    }

    #[test]
    fn first_contact_pins_the_signed_revision() {
        assert_eq!(
            plan_share_admission(bound()),
            ShareAdmissionDecision::AcceptFirstContact(SharePinPermit { revision: 1 })
        );
    }

    #[test]
    fn update_requires_pin_lineage_and_a_newer_revision() {
        let update = ShareAdmissionFacts {
            has_pin: true,
            signer_matches_pin: true,
            lineage_matches_pin: true,
            pinned_revision: 3,
            candidate_revision: 4,
            ..bound()
        };
        assert_eq!(
            plan_share_admission(update),
            ShareAdmissionDecision::ApplyUpdate(SharePinPermit { revision: 4 })
        );
        for broken in [
            ShareAdmissionFacts {
                candidate_revision: 3,
                ..update
            },
            ShareAdmissionFacts {
                signer_matches_pin: false,
                ..update
            },
            ShareAdmissionFacts {
                lineage_matches_pin: false,
                ..update
            },
        ] {
            assert_eq!(plan_share_admission(broken), ShareAdmissionDecision::Reject);
        }
    }

    #[test]
    fn revision_zero_is_never_admitted() {
        let zero = ShareAdmissionFacts {
            candidate_revision: 0,
            ..bound()
        };
        assert_eq!(plan_share_admission(zero), ShareAdmissionDecision::Reject);
    }
}

// ── Durable sharing state decisions ───────────────────────────────────────
// These functions are called by desktop sharing.rs. They prove decisions over
// supplied observations, not the disk operations or comparisons supplying them.

#[cfg_attr(hax, hax_lib::ensures(|result| result == (!accepted && !has_pin && has_payload)))]
pub fn initial_acceptance_is_authorized(accepted: bool, has_pin: bool, has_payload: bool) -> bool {
    !accepted && !has_pin && has_payload
}

pub fn store_generation_matches_spec(
    current: u64,
    snapshot: u64,
    pending: bool,
    result: Option<u64>,
) -> bool {
    match result {
        Some(next) => {
            current == snapshot
                && !pending
                && current < u64::MAX
                && next == current + 1
                && next > current
        }
        None => current != snapshot || pending || current == u64::MAX,
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| store_generation_matches_spec(current, snapshot, pending, result)))]
pub fn next_store_generation(current: u64, snapshot: u64, pending: bool) -> Option<u64> {
    if current != snapshot || pending || current == u64::MAX {
        None
    } else {
        Some(current + 1)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn stale_snapshot_can_commit(current: u64, snapshot: u64) -> bool {
    if current == snapshot {
        false
    } else {
        match next_store_generation(current, snapshot, false) {
            Some(_) => true,
            None => false,
        }
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn pending_commit_can_be_overwritten(current: u64, snapshot: u64) -> bool {
    match next_store_generation(current, snapshot, true) {
        Some(_) => true,
        None => false,
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn exhausted_generation_can_commit() -> bool {
    match next_store_generation(u64::MAX, u64::MAX, false) {
        Some(_) => true,
        None => false,
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == (matches_before && (current_present || !tombstoned))))]
pub fn recovery_should_apply(
    matches_before: bool,
    current_present: bool,
    tombstoned: bool,
) -> bool {
    matches_before && (current_present || !tombstoned)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn local_edit_can_be_overwritten(current_present: bool, tombstoned: bool) -> bool {
    recovery_should_apply(false, current_present, tombstoned)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn deleted_item_can_be_restored(matches_before: bool) -> bool {
    recovery_should_apply(matches_before, false, true)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn existing_pin_can_restart_acceptance(accepted: bool, has_payload: bool) -> bool {
    initial_acceptance_is_authorized(accepted, true, has_payload)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_payload_can_be_accepted(accepted: bool, has_pin: bool) -> bool {
    initial_acceptance_is_authorized(accepted, has_pin, false)
}
