//! Pure policy for the cross-user item-sharing channel (M19).
//!
//! WebAuthn-free by construction: the decisions here cover share-key
//! registration (the EK substitution defense), capsule send, and linked-item
//! update/revocation. Signatures, clocks, SQL, and HTTP stay outside this
//! crate — the server converts their authenticated observations into facts
//! and can only act from the private permits constructed here. hax extracts
//! these exact decisions to F*.

pub const INITIAL_SEQ: i64 = 1;

// ── Share-EK registration ───────────────────────────────────────────────────

/// Facts observed when a device registers or updates its share encapsulation
/// key. The cryptographic signature check itself stays outside this crate;
/// `signature_verified` carries its authenticated outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EkRegistrationFacts {
    pub ek_size_valid: bool,
    pub signature_verified: bool,
    /// The signing device belongs to the authenticated caller.
    pub device_owned_by_caller: bool,
    /// The signing device is enrolled and not revoked.
    pub device_active: bool,
    /// RFC 3339 timestamps compare lexicographically, so strictly-greater is
    /// a total order on bindings: replays of an older binding are rejected.
    pub signed_at_is_fresher: bool,
    pub seq: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EkRegistrationPermit {
    seq: i64,
    binds_device_signature: bool,
}

impl EkRegistrationPermit {
    pub const fn seq(self) -> i64 {
        self.seq
    }

    pub const fn binds_device_signature(self) -> bool {
        self.binds_device_signature
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EkRegistrationDecision {
    Register(EkRegistrationPermit),
    Reject,
}

pub fn ek_registration_is_authorized(facts: EkRegistrationFacts) -> bool {
    facts.ek_size_valid
        && facts.signature_verified
        && facts.device_owned_by_caller
        && facts.device_active
        && facts.signed_at_is_fresher
        && facts.seq >= INITIAL_SEQ
}

pub fn ek_registration_decision_matches_spec(
    facts: EkRegistrationFacts,
    decision: EkRegistrationDecision,
) -> bool {
    match decision {
        EkRegistrationDecision::Register(permit) => {
            ek_registration_is_authorized(facts)
                && permit.seq == facts.seq
                && permit.binds_device_signature
        }
        EkRegistrationDecision::Reject => !ek_registration_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    ek_registration_decision_matches_spec(facts, decision)
}))]
pub fn plan_ek_registration(facts: EkRegistrationFacts) -> EkRegistrationDecision {
    if ek_registration_is_authorized(facts) {
        EkRegistrationDecision::Register(EkRegistrationPermit {
            seq: facts.seq,
            binds_device_signature: true,
        })
    } else {
        EkRegistrationDecision::Reject
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn forged_ek_binding_can_register(mut facts: EkRegistrationFacts) -> bool {
    facts.signature_verified = false;
    ek_registration_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn replayed_ek_binding_can_register(mut facts: EkRegistrationFacts) -> bool {
    facts.signed_at_is_fresher = false;
    ek_registration_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn foreign_device_ek_can_register(mut facts: EkRegistrationFacts) -> bool {
    facts.device_owned_by_caller = false;
    ek_registration_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_device_ek_can_register(mut facts: EkRegistrationFacts) -> bool {
    facts.device_active = false;
    ek_registration_is_authorized(facts)
}

// ── Binding-timestamp freshness (M25) ──────────────────────────────────────

/// Minimum plausible length for a canonical RFC 3339 UTC rendering
/// (`YYYY-MM-DDTHH:MM:SSZ` = 20 chars); the handler caps at 64.
pub fn timestamp_format_plausible(len: usize) -> bool {
    // Plain comparisons: range-`contains` has no hax F* prelude encoding.
    len >= 20 && len <= 64
}

/// Strictly-fresh binding timestamp (M25).
///
/// Comparison is bytewise over the canonical RFC 3339 rendering: fixed-width
/// big-endian fields make lexicographic byte order coincide with chrono-
/// logical order, so acceptance forms a strict total order over bindings —
/// update sequences cannot cycle, and a replay of the currently registered
/// timestamp always loses (`identical_timestamp_can_be_fresher`).
pub fn timestamp_is_fresher(candidate: &[u8], current: Option<&[u8]>) -> bool {
    match current {
        Some(current) => candidate > current,
        None => true,
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn identical_timestamp_can_be_fresher(candidate: &[u8]) -> bool {
    timestamp_is_fresher(candidate, Some(candidate))
}

// ── Capsule send ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendCapsuleFacts {
    pub sender_authenticated: bool,
    pub recipient_registered: bool,
    pub capsule_size_valid: bool,
    pub inbox_has_capacity: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendDecision {
    Deliver,
    Reject,
}

pub fn send_is_authorized(facts: SendCapsuleFacts) -> bool {
    facts.sender_authenticated
        && facts.recipient_registered
        && facts.capsule_size_valid
        && facts.inbox_has_capacity
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    matches!(decision, SendDecision::Deliver) == send_is_authorized(facts)
}))]
pub fn plan_send(facts: SendCapsuleFacts) -> SendDecision {
    if send_is_authorized(facts) {
        SendDecision::Deliver
    } else {
        SendDecision::Reject
    }
}

// ── Linked-item update / revocation ─────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkMutationFacts {
    /// The caller is the sender who originally shared this item.
    pub caller_is_sender: bool,
    pub item_exists: bool,
    /// Revoked items are immutable tombstones; nothing un-revokes them.
    pub not_already_revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkMutationDecision {
    Apply,
    Reject,
}

pub fn link_mutation_is_authorized(facts: LinkMutationFacts) -> bool {
    facts.caller_is_sender && facts.item_exists && facts.not_already_revoked
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    matches!(decision, LinkMutationDecision::Apply) == link_mutation_is_authorized(facts)
}))]
pub fn plan_link_mutation(facts: LinkMutationFacts) -> LinkMutationDecision {
    if link_mutation_is_authorized(facts) {
        LinkMutationDecision::Apply
    } else {
        LinkMutationDecision::Reject
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn non_sender_can_mutate_link(mut facts: LinkMutationFacts) -> bool {
    facts.caller_is_sender = false;
    link_mutation_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_link_can_mutate(mut facts: LinkMutationFacts) -> bool {
    facts.not_already_revoked = false;
    link_mutation_is_authorized(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ek_registration_requires_every_binding_condition() {
        let valid = EkRegistrationFacts {
            ek_size_valid: true,
            signature_verified: true,
            device_owned_by_caller: true,
            device_active: true,
            signed_at_is_fresher: true,
            seq: 4,
        };
        let EkRegistrationDecision::Register(permit) = plan_ek_registration(valid) else {
            panic!("valid registration rejected");
        };
        assert_eq!(permit.seq(), 4);
        assert!(permit.binds_device_signature());
        assert!(!forged_ek_binding_can_register(valid));
        assert!(!replayed_ek_binding_can_register(valid));
        assert!(!foreign_device_ek_can_register(valid));
        assert!(!revoked_device_ek_can_register(valid));

        let mut one_bit_off = valid;
        one_bit_off.ek_size_valid = false;
        assert_eq!(
            plan_ek_registration(one_bit_off),
            EkRegistrationDecision::Reject
        );
    }

    #[test]
    fn timestamp_freshness_is_strict_and_first_registration_always_fresh() {
        assert!(timestamp_format_plausible("2026-01-01T00:00:00Z".len()));
        assert!(!timestamp_format_plausible(3));

        assert!(timestamp_is_fresher(b"2026-02-01T00:00:00Z", None));
        assert!(timestamp_is_fresher(
            b"2026-02-01T00:00:00Z",
            Some(b"2026-01-01T00:00:00Z")
        ));
        // Equal loses; going backwards loses.
        assert!(!timestamp_is_fresher(
            b"2026-01-01T00:00:00Z",
            Some(b"2026-01-01T00:00:00Z")
        ));
        assert!(!timestamp_is_fresher(
            b"2025-12-31T23:59:59Z",
            Some(b"2026-01-01T00:00:00Z")
        ));
        assert!(!identical_timestamp_can_be_fresher(b"2026-01-01T00:00:00Z"));
    }

    #[test]
    fn send_requires_recipient_capacity_and_authentication() {
        let valid = SendCapsuleFacts {
            sender_authenticated: true,
            recipient_registered: true,
            capsule_size_valid: true,
            inbox_has_capacity: true,
        };
        assert_eq!(plan_send(valid), SendDecision::Deliver);
        for bit in 0..4 {
            let mut facts = valid;
            match bit {
                0 => facts.sender_authenticated = false,
                1 => facts.recipient_registered = false,
                2 => facts.capsule_size_valid = false,
                _ => facts.inbox_has_capacity = false,
            }
            assert_eq!(plan_send(facts), SendDecision::Reject);
        }
    }

    #[test]
    fn link_mutations_require_sender_authority_over_live_items() {
        let valid = LinkMutationFacts {
            caller_is_sender: true,
            item_exists: true,
            not_already_revoked: true,
        };
        assert_eq!(plan_link_mutation(valid), LinkMutationDecision::Apply);
        assert!(!non_sender_can_mutate_link(valid));
        assert!(!revoked_link_can_mutate(valid));

        let mut missing = valid;
        missing.item_exists = false;
        assert_eq!(
            plan_link_mutation(missing),
            LinkMutationDecision::Reject
        );
    }
}
