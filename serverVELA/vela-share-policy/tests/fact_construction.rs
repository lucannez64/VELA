//! Exhaustive bounded checks for the share observation → fact mappings.
//!
//! The hax/F* postconditions state each fact exactly in terms of its raw
//! observation. This test enumerates every Boolean combination, the capsule and
//! inbox bound classes, the exact share-EK length plus its neighbours, and
//! every linked-row combination, then checks both the mapping and every
//! observation-based negative theorem against the same values. It is ordinary
//! Rust CI, not a substitute for the F* check.

use vela_share_policy::{
    ek_registration_facts, ek_registration_is_authorized, empty_capsule_can_be_sent_observed,
    foreign_device_ek_can_register_observed, full_inbox_can_receive_observed, link_mutation_facts,
    link_mutation_is_authorized, missing_link_can_mutate_observed,
    non_sender_can_mutate_observed_link, replayed_ek_binding_can_register_observed,
    revoked_device_ek_can_register_observed, revoked_link_can_mutate_observed, send_facts,
    send_is_authorized, unauthenticated_sender_can_send_observed,
    unregistered_recipient_can_receive_observed, unverified_signature_can_register_observed,
    EkRegistrationObservation, LinkMutationObservation, SendObservation, MAX_CAPSULE_BYTES,
    MAX_RECIPIENT_INBOX_BYTES, SHARE_EK_LEN,
};

const CAPSULE_LENGTHS: [i64; 7] = [
    i64::MIN,
    -1,
    0,
    1,
    MAX_CAPSULE_BYTES,
    MAX_CAPSULE_BYTES + 1,
    i64::MAX,
];
const INBOX_BYTES: [i64; 7] = [
    i64::MIN,
    -1,
    0,
    1,
    MAX_RECIPIENT_INBOX_BYTES - MAX_CAPSULE_BYTES,
    MAX_RECIPIENT_INBOX_BYTES,
    i64::MAX,
];
const EK_LENGTHS: [usize; 4] = [0, SHARE_EK_LEN - 1, SHARE_EK_LEN, SHARE_EK_LEN + 1];

#[test]
fn send_facts_are_exactly_the_session_recipient_capsule_and_inbox() {
    for &session_user_id_present in &[false, true] {
        for &recipient_has_share_ek in &[false, true] {
            for &capsule_len in &CAPSULE_LENGTHS {
                for &existing_inbox_bytes in &INBOX_BYTES {
                    let obs = SendObservation {
                        session_user_id_present,
                        recipient_has_share_ek,
                        capsule_len,
                        existing_inbox_bytes,
                    };
                    let facts = send_facts(obs);
                    let capsule_size_valid = capsule_len > 0 && capsule_len <= MAX_CAPSULE_BYTES;
                    let inbox_has_capacity = existing_inbox_bytes >= 0
                        && capsule_len >= 0
                        && i128::from(existing_inbox_bytes) + i128::from(capsule_len)
                            <= i128::from(MAX_RECIPIENT_INBOX_BYTES);

                    assert_eq!(
                        facts.sender_authenticated, session_user_id_present,
                        "{obs:?}"
                    );
                    assert_eq!(
                        facts.recipient_registered, recipient_has_share_ek,
                        "{obs:?}"
                    );
                    assert_eq!(facts.capsule_size_valid, capsule_size_valid, "{obs:?}");
                    assert_eq!(facts.inbox_has_capacity, inbox_has_capacity, "{obs:?}");
                    assert_eq!(
                        send_is_authorized(facts),
                        session_user_id_present
                            && recipient_has_share_ek
                            && capsule_size_valid
                            && inbox_has_capacity,
                        "{obs:?}"
                    );

                    assert!(!unauthenticated_sender_can_send_observed(obs));
                    assert!(!unregistered_recipient_can_receive_observed(obs));
                    assert!(!empty_capsule_can_be_sent_observed(obs));
                    assert!(!full_inbox_can_receive_observed(obs));
                }
            }
        }
    }
}

#[test]
fn ek_registration_facts_are_exactly_the_request_device_row_and_store() {
    for &ek_len in &EK_LENGTHS {
        for &signature_verified in &[false, true] {
            for &device_row_present in &[false, true] {
                for &device_user_matches in &[false, true] {
                    for &device_active in &[false, true] {
                        for &signed_at_is_fresher in &[false, true] {
                            for &binding_exists in &[false, true] {
                                let obs = EkRegistrationObservation {
                                    ek_len,
                                    signature_verified,
                                    device_row_present,
                                    device_user_matches,
                                    device_active,
                                    signed_at_is_fresher,
                                    binding_exists,
                                };
                                let facts = ek_registration_facts(obs);
                                let device_owned_by_caller =
                                    device_row_present && device_user_matches;
                                let seq = if binding_exists { 2 } else { 1 };

                                assert_eq!(facts.ek_size_valid, ek_len == SHARE_EK_LEN, "{obs:?}");
                                assert_eq!(facts.signature_verified, signature_verified, "{obs:?}");
                                assert_eq!(
                                    facts.device_owned_by_caller, device_owned_by_caller,
                                    "{obs:?}"
                                );
                                assert_eq!(facts.device_active, device_active, "{obs:?}");
                                assert_eq!(
                                    facts.signed_at_is_fresher, signed_at_is_fresher,
                                    "{obs:?}"
                                );
                                assert_eq!(facts.seq, seq, "{obs:?}");
                                assert_eq!(
                                    ek_registration_is_authorized(facts),
                                    ek_len == SHARE_EK_LEN
                                        && signature_verified
                                        && device_owned_by_caller
                                        && device_active
                                        && signed_at_is_fresher
                                        && seq >= 1,
                                    "{obs:?}"
                                );

                                assert!(!unverified_signature_can_register_observed(obs));
                                assert!(!foreign_device_ek_can_register_observed(obs));
                                assert!(!revoked_device_ek_can_register_observed(obs));
                                assert!(!replayed_ek_binding_can_register_observed(obs));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn link_mutation_facts_are_exactly_the_linked_row_observations() {
    for &item_present in &[false, true] {
        for &caller_matches_sender in &[false, true] {
            for &item_not_revoked in &[false, true] {
                let obs = LinkMutationObservation {
                    item_present,
                    caller_matches_sender,
                    item_not_revoked,
                };
                let facts = link_mutation_facts(obs);
                let caller_is_sender = item_present && caller_matches_sender;
                let not_already_revoked = item_present && item_not_revoked;

                assert_eq!(facts.caller_is_sender, caller_is_sender, "{obs:?}");
                assert_eq!(facts.item_exists, item_present, "{obs:?}");
                assert_eq!(facts.not_already_revoked, not_already_revoked, "{obs:?}");
                assert_eq!(
                    link_mutation_is_authorized(facts),
                    caller_is_sender && item_present && not_already_revoked,
                    "{obs:?}"
                );

                assert!(!non_sender_can_mutate_observed_link(obs));
                assert!(!revoked_link_can_mutate_observed(obs));
                assert!(!missing_link_can_mutate_observed(obs));
            }
        }
    }
}
