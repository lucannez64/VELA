//! Pure policy for the cross-user item-sharing channel (M19).
//!
//! WebAuthn-free by construction: the decisions here cover share-key
//! registration (the EK substitution defense), capsule send, and linked-item
//! update/revocation. Signatures, clocks, SQL, and HTTP stay outside this
//! crate — the server converts their authenticated observations into facts
//! and can only act from the private permits constructed here. hax extracts
//! these exact decisions to F*.

pub mod driver;

pub const INITIAL_SEQ: i64 = 1;

/// Decoded length of a hybrid share encapsulation key (`ML-KEM` + `X25519`).
pub const SHARE_EK_LEN: usize = 1568 + 32;

/// Largest capsule the send handler accepts, in decoded bytes.
pub const MAX_CAPSULE_BYTES: i64 = 1024 * 1024;

/// Largest total pending capsule payload a recipient inbox may hold.
pub const MAX_RECIPIENT_INBOX_BYTES: i64 = 32 * 1024 * 1024;

// ── Share-EK registration ───────────────────────────────────────────────────

/// Raw observations from the share-EK registration request, the device row
/// and the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EkRegistrationObservation {
    /// Decoded byte length of the presented share EK.
    pub ek_len: usize,
    /// The binding signature verified under the row's identity key.
    pub signature_verified: bool,
    /// A `devices` row came back for this device id and caller id.
    pub device_row_present: bool,
    /// That row's `user_id` equals the authenticated caller.
    pub device_user_matches: bool,
    /// The row's `revoked` column is clear.
    pub device_active: bool,
    /// The candidate instant is strictly fresher than the stored binding.
    pub signed_at_is_fresher: bool,
    /// The account already has a registered share-EK binding instant.
    pub binding_exists: bool,
}

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

/// Turn raw request/device-row/store observations into the registration facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    facts.ek_size_valid == (obs.ek_len == SHARE_EK_LEN)
        && facts.signature_verified == obs.signature_verified
        && facts.device_owned_by_caller
            == (obs.device_row_present && obs.device_user_matches)
        && facts.device_active == obs.device_active
        && facts.signed_at_is_fresher == obs.signed_at_is_fresher
        && facts.seq == (if obs.binding_exists { 2 } else { 1 })
}))]
pub fn ek_registration_facts(obs: EkRegistrationObservation) -> EkRegistrationFacts {
    EkRegistrationFacts {
        ek_size_valid: obs.ek_len == SHARE_EK_LEN,
        signature_verified: obs.signature_verified,
        device_owned_by_caller: obs.device_row_present && obs.device_user_matches,
        device_active: obs.device_active,
        signed_at_is_fresher: obs.signed_at_is_fresher,
        seq: if obs.binding_exists { 2 } else { 1 },
    }
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

/// Raw observations from the send request, the recipient row and the inbox
/// quota queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendObservation {
    /// The authenticated session names a user id.
    pub session_user_id_present: bool,
    /// The recipient's `users` row carries a non-empty share EK.
    pub recipient_has_share_ek: bool,
    /// Decoded capsule length in bytes.
    pub capsule_len: i64,
    /// Pending capsule bytes in the recipient's inbox before this send.
    pub existing_inbox_bytes: i64,
}

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

/// Turn raw session/recipient/capsule/inbox observations into the send facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    facts.sender_authenticated == obs.session_user_id_present
        && facts.recipient_registered == obs.recipient_has_share_ek
        && facts.capsule_size_valid
            == (obs.capsule_len > 0 && obs.capsule_len <= MAX_CAPSULE_BYTES)
        && facts.inbox_has_capacity
            == (obs.existing_inbox_bytes >= 0
                && obs.capsule_len >= 0
                && (obs.existing_inbox_bytes as i128) + (obs.capsule_len as i128)
                    <= MAX_RECIPIENT_INBOX_BYTES as i128)
}))]
pub fn send_facts(obs: SendObservation) -> SendCapsuleFacts {
    SendCapsuleFacts {
        sender_authenticated: obs.session_user_id_present,
        recipient_registered: obs.recipient_has_share_ek,
        capsule_size_valid: obs.capsule_len > 0 && obs.capsule_len <= MAX_CAPSULE_BYTES,
        // Bound the subtrahend first, so every i64 observation is safe.
        // Negative database counters fail closed rather than adding capacity.
        inbox_has_capacity: obs.existing_inbox_bytes >= 0
            && obs.capsule_len >= 0
            && obs.capsule_len <= MAX_RECIPIENT_INBOX_BYTES
            && obs.existing_inbox_bytes <= MAX_RECIPIENT_INBOX_BYTES - obs.capsule_len,
    }
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

/// Raw observations from the linked-share row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkMutationObservation {
    /// A `shared_items` row with the requested id exists.
    pub item_present: bool,
    /// The row's `sender_user_id` equals the authenticated caller.
    pub caller_matches_sender: bool,
    /// The row's `revoked` column is clear.
    pub item_not_revoked: bool,
}

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

/// Turn raw linked-row observations into the mutation facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    facts.caller_is_sender == (obs.item_present && obs.caller_matches_sender)
        && facts.item_exists == obs.item_present
        && facts.not_already_revoked == (obs.item_present && obs.item_not_revoked)
}))]
pub fn link_mutation_facts(obs: LinkMutationObservation) -> LinkMutationFacts {
    LinkMutationFacts {
        caller_is_sender: obs.item_present && obs.caller_matches_sender,
        item_exists: obs.item_present,
        not_already_revoked: obs.item_present && obs.item_not_revoked,
    }
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

// ── Negative theorems over the real observation constructors ───────────────

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unauthenticated_sender_can_send_observed(mut obs: SendObservation) -> bool {
    obs.session_user_id_present = false;
    send_is_authorized(send_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unregistered_recipient_can_receive_observed(mut obs: SendObservation) -> bool {
    obs.recipient_has_share_ek = false;
    send_is_authorized(send_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn empty_capsule_can_be_sent_observed(mut obs: SendObservation) -> bool {
    obs.capsule_len = 0;
    send_is_authorized(send_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn full_inbox_can_receive_observed(mut obs: SendObservation) -> bool {
    obs.existing_inbox_bytes = MAX_RECIPIENT_INBOX_BYTES;
    send_is_authorized(send_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unverified_signature_can_register_observed(mut obs: EkRegistrationObservation) -> bool {
    obs.signature_verified = false;
    ek_registration_is_authorized(ek_registration_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn foreign_device_ek_can_register_observed(mut obs: EkRegistrationObservation) -> bool {
    obs.device_user_matches = false;
    ek_registration_is_authorized(ek_registration_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_device_ek_can_register_observed(mut obs: EkRegistrationObservation) -> bool {
    obs.device_active = false;
    ek_registration_is_authorized(ek_registration_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn replayed_ek_binding_can_register_observed(mut obs: EkRegistrationObservation) -> bool {
    obs.signed_at_is_fresher = false;
    ek_registration_is_authorized(ek_registration_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn non_sender_can_mutate_observed_link(mut obs: LinkMutationObservation) -> bool {
    obs.caller_matches_sender = false;
    link_mutation_is_authorized(link_mutation_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_link_can_mutate_observed(mut obs: LinkMutationObservation) -> bool {
    obs.item_not_revoked = false;
    link_mutation_is_authorized(link_mutation_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_link_can_mutate_observed(mut obs: LinkMutationObservation) -> bool {
    obs.item_present = false;
    link_mutation_is_authorized(link_mutation_facts(obs))
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
        assert_eq!(plan_link_mutation(missing), LinkMutationDecision::Reject);
    }
}
