//! Signed, recipient-bound envelopes for items shared between users (v2).
//!
//! # Why
//!
//! v1 share capsules were `kem::seal_share(recipient_share_ek, item_json)`:
//! anonymous public-key encryption to a key anyone can fetch. Nothing in the
//! capsule said who made it, so whoever controlled delivery (a malicious or
//! compromised server) could seal a fresh capsule with any content and any
//! `updated_at`, and the recipient would apply it as an edit from the sender.
//!
//! # Format
//!
//! The KEM-sealed plaintext is
//!
//! ```text
//! "VSE2" ‖ lp(sender_user_id) ‖ lp(sender_device_id) ‖ lp(sender_vk)
//!        ‖ lp(recipient_user_id) ‖ recipient_ek_digest (32 B)
//!        ‖ lp(lineage_id) ‖ revision (u64 BE) ‖ lp(item) ‖ lp(signature)
//! ```
//!
//! where `lp(x) = u64 BE length ‖ x` and `signature` is a hybrid
//! ML-DSA-87 + Ed25519 signature by the sending device over
//! [`signing_transcript`] (the same fields, prefixed by
//! [`SHARE_ITEM_CONTEXT`]). The recipient key digest is
//! `SHA-256(recipient share_ek)`, so a signed envelope cannot be re-sealed to
//! another recipient (forwarding) without failing verification.
//!
//! # Admission
//!
//! Opening verifies the signature and the recipient binding. Whether to show,
//! accept, or apply the result is decided by
//! `vela_client_share_policy::plan_share_admission`, which pins the signing
//! key, lineage, and revision at first contact and requires updates to match
//! the pin with a strictly higher revision. [`admit`] wires the two together.
//!
//! Model: `security/formal/m19c_share_sender_authentication.spthy`.

use sha2::{Digest, Sha256};
use vela_client_share_policy::{
    plan_share_admission, ShareAdmissionDecision, ShareAdmissionFacts, SharePinPermit,
};

use crate::error::{Result, VelaError};
use crate::{kem, signing};

/// Prefix of the sealed plaintext.
pub const SHARE_ENVELOPE_MAGIC: &[u8; 4] = b"VSE2";
/// Domain separation for the sender's signature.
pub const SHARE_ITEM_CONTEXT: &[u8] = b"vela share item v2";

/// Everything the sender signs besides the item itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareHeader {
    pub sender_user_id: String,
    pub sender_device_id: String,
    /// The sending device's hybrid verifying key (2624 B).
    pub sender_vk: Vec<u8>,
    pub recipient_user_id: String,
    /// `SHA-256` of the recipient's share encapsulation key bytes.
    pub recipient_ek_digest: [u8; 32],
    /// Chosen by the sender at first send; constant across updates.
    pub lineage_id: String,
    /// 1 at first send, then strictly increasing.
    pub revision: u64,
}

/// A verified envelope: the signature checked out under `header.sender_vk`
/// and the recipient key digest matches the key that opened it.
///
/// Safe callers cannot construct a witness from unchecked fields:
/// ```compile_fail
/// use vela_crypto::share_envelope::{OpenedShare, ShareHeader};
/// fn forge(header: ShareHeader, item: Vec<u8>) -> OpenedShare {
///     OpenedShare { header, item }
/// }
/// ```
/// Nor can they mutate its authenticated plaintext:
/// ```compile_fail
/// use vela_crypto::share_envelope::OpenedShare;
/// fn change(share: &mut OpenedShare) { share.item.clear(); }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedShare {
    header: ShareHeader,
    item: Vec<u8>,
}

impl OpenedShare {
    /// Authenticated fields are exposed immutably; construction stays local to
    /// successful opening, so safe callers cannot forge or mutate this witness.
    pub fn header(&self) -> &ShareHeader {
        opened_share_header(self)
    }

    pub fn item(&self) -> &[u8] {
        opened_share_item(self)
    }

    pub fn into_item(self) -> Vec<u8> {
        into_opened_share_item(self)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|header| {
    header.sender_user_id.as_str() == share.header.sender_user_id.as_str()
        && header.sender_device_id.as_str() == share.header.sender_device_id.as_str()
        && header.sender_vk == share.header.sender_vk
        && header.recipient_user_id.as_str() == share.header.recipient_user_id.as_str()
        && header.recipient_ek_digest == share.header.recipient_ek_digest
        && header.lineage_id.as_str() == share.header.lineage_id.as_str()
        && header.revision == share.header.revision
}))]
pub fn opened_share_header(share: &OpenedShare) -> &ShareHeader {
    &share.header
}

#[cfg_attr(hax, hax_lib::ensures(|bytes| bytes == share.item.as_slice()))]
pub fn opened_share_item(share: &OpenedShare) -> &[u8] {
    share.item.as_slice()
}

#[cfg_attr(hax, hax_lib::ensures(|bytes| bytes.as_slice() == share.item.as_slice()))]
pub fn into_opened_share_item(share: OpenedShare) -> Vec<u8> {
    share.item
}

/// What a recipient remembers about a share it accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePin {
    pub sender_user_id: String,
    pub sender_vk: Vec<u8>,
    pub lineage_id: String,
    pub revision: u64,
}

/// What the recipient knows independently of the envelope.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionContext<'a> {
    /// This account's user id.
    pub recipient_user_id: &'a str,
    /// The sender user id the server attributed the capsule to.
    pub attributed_sender_user_id: &'a str,
    /// The pin recorded when this share was accepted, if it was.
    pub pin: Option<&'a SharePin>,
}

/// An envelope the policy admitted, with the pin to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedShare {
    pub opened: OpenedShare,
    /// `true` for first contact, `false` for an update to a pinned share.
    pub first_contact: bool,
    pub pin: SharePin,
}

/// `SHA-256(share_ek)`, as bound into every envelope.
pub fn recipient_ek_digest(share_ek: &[u8]) -> [u8; 32] {
    Sha256::digest(share_ek).into()
}

fn push_lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&crate::wire::encode_u64_be(value.len() as u64));
    out.extend_from_slice(value);
}

fn push_header(out: &mut Vec<u8>, header: &ShareHeader) {
    push_lp(out, header.sender_user_id.as_bytes());
    push_lp(out, header.sender_device_id.as_bytes());
    push_lp(out, &header.sender_vk);
    push_lp(out, header.recipient_user_id.as_bytes());
    out.extend_from_slice(&header.recipient_ek_digest);
    push_lp(out, header.lineage_id.as_bytes());
    out.extend_from_slice(&crate::wire::encode_u64_be(header.revision));
}

/// The exact bytes the sending device signs.
pub fn signing_transcript(header: &ShareHeader, item: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(SHARE_ITEM_CONTEXT.len() + header.sender_vk.len() + item.len() + 256);
    out.extend_from_slice(SHARE_ITEM_CONTEXT);
    push_header(&mut out, header);
    push_lp(&mut out, item);
    out
}

/// Sign and seal `item` for one recipient.
///
/// `header.sender_vk` must be the verifying key of `signing_key`, and
/// `header.recipient_ek_digest` must be the digest of `recipient`; both are
/// checked so a caller cannot produce an envelope its recipient would reject.
pub fn seal_signed_item(
    signing_key: &signing::HybridSigningKey,
    header: &ShareHeader,
    recipient: &kem::HybridPublicKey,
    item: &[u8],
) -> Result<Vec<u8>> {
    if header.sender_vk.as_slice() != signing_key.verifying_key().to_bytes().as_slice() {
        return Err(VelaError::InvalidParameter(
            "share header names a different signing key".into(),
        ));
    }
    if header.recipient_ek_digest != recipient_ek_digest(&recipient.to_bytes()) {
        return Err(VelaError::InvalidParameter(
            "share header is bound to a different recipient key".into(),
        ));
    }
    if header.revision == 0 {
        return Err(VelaError::InvalidParameter(
            "share revisions start at 1".into(),
        ));
    }
    let signature = signing::sign(signing_key, &signing_transcript(header, item))?;

    let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(
        SHARE_ENVELOPE_MAGIC.len() + header.sender_vk.len() + item.len() + 4_900,
    ));
    plaintext.extend_from_slice(SHARE_ENVELOPE_MAGIC);
    push_header(&mut plaintext, header);
    push_lp(&mut plaintext, item);
    push_lp(&mut plaintext, &signature.to_bytes());
    kem::seal_share(recipient, &plaintext)
}

/// Pure prefix parser used by the real signed-envelope reader. Under the
/// trusted slice semantics, success returns exactly the requested prefix and
/// suffix; failure consumes nothing and never indexes outside the input.
#[cfg_attr(hax, hax_lib::ensures(|result| match result {
    Some((prefix, suffix)) => n <= input.len()
        && prefix == &input[..n] && suffix == &input[n..],
    None => input.len() < n,
}))]
pub fn split_envelope_prefix(input: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    if input.len() < n {
        None
    } else {
        Some((&input[..n], &input[n..]))
    }
}

/// Borrowed syntactic fields. Authentication and UTF-8 validation occur after
/// this framing step; no field is trusted merely because parsing succeeded.
#[derive(Clone, Copy, Debug)]
pub struct ShareFrame<'a> {
    pub sender_user_id: &'a [u8],
    pub sender_device_id: &'a [u8],
    pub sender_vk: &'a [u8],
    pub recipient_user_id: &'a [u8],
    pub recipient_ek_digest: &'a [u8],
    pub lineage_id: &'a [u8],
    pub revision: u64,
    pub item: &'a [u8],
    pub signature: &'a [u8],
}

/// Cursor operation used by the concrete frame parser.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    match split_envelope_prefix(input, n) {
        Some((head, tail)) => result == Some(head) && *future(input) == tail,
        None => matches!(result, None) && *future(input) == *input,
    }
}))]
pub fn take_frame_prefix<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, tail) = split_envelope_prefix(input, n)?;
    *input = tail;
    Some(head)
}

/// Functional byte grammar used as the specification of the stateful parser.
/// Each LP production expands to the separately checked exact slice contract.
pub fn share_frame_spec(input: &[u8]) -> Option<ShareFrame<'_>> {
    let digest_len: usize = 32;
    let (prefix, rest) = split_envelope_prefix(input, 4)?;
    if prefix != SHARE_ENVELOPE_MAGIC {
        return None;
    }
    let (((sender_user_id, sender_device_id), (sender_vk, recipient_user_id)), rest) =
        crate::wire::split_lp_four(rest)?;
    let (recipient_ek_digest, rest) = split_envelope_prefix(rest, digest_len)?;
    let (lineage_id, rest) = crate::wire::split_length_prefixed(rest)?;
    let (revision, rest) = crate::wire::split_u64_prefix(rest)?;
    let ((item, signature), rest) = crate::wire::split_lp_pair(rest)?;
    if !rest.is_empty()
        || sender_vk.len() != signing::HYBRID_VK_LEN
        || signature.len() != signing::HYBRID_SIG_LEN
    {
        return None;
    }
    Some(ShareFrame {
        sender_user_id,
        sender_device_id,
        sender_vk,
        recipient_user_id,
        recipient_ek_digest,
        lineage_id,
        revision,
        item,
        signature,
    })
}

/// Explicit structural comparison avoids an opaque derived-equality assumption.
pub fn frame_results_equal(left: Option<ShareFrame<'_>>, right: Option<ShareFrame<'_>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.sender_user_id == right.sender_user_id
                && left.sender_device_id == right.sender_device_id
                && left.sender_vk == right.sender_vk
                && left.recipient_user_id == right.recipient_user_id
                && left.recipient_ek_digest == right.recipient_ek_digest
                && left.lineage_id == right.lineage_id
                && left.revision == right.revision
                && left.item == right.item
                && left.signature == right.signature
        }
        _ => false,
    }
}

/// Concrete stateful parser refines the complete byte grammar, including all
/// rejection cases and exact field values. This does not prove authentication.
#[cfg_attr(hax, hax_lib::fstar::options("--fuel 2 --ifuel 2"))]
#[cfg_attr(hax, hax_lib::ensures(|result| frame_results_equal(result, share_frame_spec(input))))]
pub fn parse_share_frame(input: &[u8]) -> Option<ShareFrame<'_>> {
    let digest_len: usize = 32;
    let mut rest = input;
    if take_frame_prefix(&mut rest, 4)? != SHARE_ENVELOPE_MAGIC {
        return None;
    }
    let ((sender_user_id, sender_device_id), (sender_vk, recipient_user_id)) =
        crate::wire::take_lp_four(&mut rest)?;
    let recipient_ek_digest = take_frame_prefix(&mut rest, digest_len)?;
    let lineage_id = crate::wire::take_length_prefixed(&mut rest)?;
    let revision = crate::wire::take_u64(&mut rest)?;
    let (item, signature) = crate::wire::take_lp_pair(&mut rest)?;
    if !rest.is_empty()
        || sender_vk.len() != signing::HYBRID_VK_LEN
        || signature.len() != signing::HYBRID_SIG_LEN
    {
        return None;
    }
    Some(ShareFrame {
        sender_user_id,
        sender_device_id,
        sender_vk,
        recipient_user_id,
        recipient_ek_digest,
        lineage_id,
        revision,
        item,
        signature,
    })
}

/// Open a capsule with this device's share key, parse the v2 envelope, and
/// verify its signature and recipient binding.
///
/// Fails for v1 (unsigned) capsules: there is no way to tell who made them.
pub fn open_signed_item(
    recipient_sk: &kem::HybridSecretKey,
    capsule: &[u8],
) -> Result<OpenedShare> {
    let plaintext = zeroize::Zeroizing::new(kem::open_share(recipient_sk, capsule)?);
    let frame = parse_share_frame(&plaintext).ok_or_else(|| {
        VelaError::InvalidParameter("share envelope has invalid v2 framing".into())
    })?;
    let string = |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec())
            .map_err(|_| VelaError::InvalidParameter("share envelope field is not UTF-8".into()))
    };
    let header = ShareHeader {
        sender_user_id: string(frame.sender_user_id)?,
        sender_device_id: string(frame.sender_device_id)?,
        sender_vk: frame.sender_vk.to_vec(),
        recipient_user_id: string(frame.recipient_user_id)?,
        recipient_ek_digest: frame.recipient_ek_digest.try_into().expect("32 bytes"),
        lineage_id: string(frame.lineage_id)?,
        revision: frame.revision,
    };
    let item = frame.item.to_vec();
    let signature = frame.signature;

    let vk_bytes: &[u8; signing::HYBRID_VK_LEN] =
        header.sender_vk.as_slice().try_into().map_err(|_| {
            VelaError::InvalidParameter("share sender key has the wrong length".into())
        })?;
    let sig_bytes: &[u8; signing::HYBRID_SIG_LEN] = signature
        .try_into()
        .map_err(|_| VelaError::InvalidParameter("share signature has the wrong length".into()))?;
    let vk = signing::HybridVerifyingKey::from_bytes(vk_bytes)?;
    let sig = signing::HybridSignature::from_bytes(sig_bytes)?;
    if !signing::verify(&vk, &signing_transcript(&header, &item), &sig)? {
        return Err(VelaError::InvalidParameter(
            "share signature does not verify".into(),
        ));
    }
    if header.recipient_ek_digest != recipient_ek_digest(&recipient_sk.public_key().to_bytes()) {
        return Err(VelaError::InvalidParameter(
            "share envelope was signed for a different recipient key".into(),
        ));
    }
    Ok(OpenedShare { header, item })
}

/// Open, verify, and run the admission policy.
///
/// A capsule that fails to open or verify is reported to the policy as
/// unauthenticated, so the rejection still goes through the verified decision.
pub fn admit(
    recipient_sk: &kem::HybridSecretKey,
    capsule: &[u8],
    context: AdmissionContext<'_>,
) -> Result<AdmittedShare> {
    let opened = open_signed_item(recipient_sk, capsule);
    let decision = plan_observed_share(opened.as_ref().ok(), &context);
    let (permit, first_contact): (SharePinPermit, bool) = match decision {
        ShareAdmissionDecision::AcceptFirstContact(permit) => (permit, true),
        ShareAdmissionDecision::ApplyUpdate(permit) => (permit, false),
        ShareAdmissionDecision::Reject => {
            let facts = admission_facts(opened.as_ref().ok(), &context);
            return Err(match opened {
                Err(error) => error,
                Ok(_) => VelaError::InvalidParameter(rejection_reason(&facts).into()),
            });
        }
    };
    let opened = opened.expect("the policy admits only authenticated envelopes");
    let pin = SharePin {
        sender_user_id: opened.header.sender_user_id.clone(),
        sender_vk: opened.header.sender_vk.clone(),
        lineage_id: opened.header.lineage_id.clone(),
        revision: permit.revision(),
    };
    Ok(AdmittedShare {
        opened,
        first_contact,
        pin,
    })
}

/// Turn observations into policy facts. Public so tests and bridges can
/// check the mapping itself.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    facts.envelope_authenticated == opened.is_some()
        && facts.has_pin == context.pin.is_some()
        && facts.pinned_revision == context.pin.map_or(0, |pin| pin.revision)
        && facts.candidate_revision == opened.map_or(0, |value| value.header.revision)
        && match opened {
            Some(value) => facts.addressed_to_recipient == (value.header.recipient_user_id.as_str() == context.recipient_user_id)
                && facts.sender_matches_attribution == (value.header.sender_user_id.as_str() == context.attributed_sender_user_id)
                && facts.signer_matches_pin == context.pin.is_some_and(|pin| pin.sender_vk == value.header.sender_vk && pin.sender_user_id == value.header.sender_user_id)
                && facts.lineage_matches_pin == context.pin.is_some_and(|pin| pin.lineage_id == value.header.lineage_id),
            None => !facts.addressed_to_recipient && !facts.sender_matches_attribution
                && !facts.signer_matches_pin && !facts.lineage_matches_pin,
        }
}))]
pub fn admission_facts(
    opened: Option<&OpenedShare>,
    context: &AdmissionContext<'_>,
) -> ShareAdmissionFacts {
    let Some(opened) = opened else {
        return ShareAdmissionFacts {
            envelope_authenticated: false,
            addressed_to_recipient: false,
            sender_matches_attribution: false,
            has_pin: context.pin.is_some(),
            signer_matches_pin: false,
            lineage_matches_pin: false,
            pinned_revision: context.pin.map_or(0, |p| p.revision),
            candidate_revision: 0,
        };
    };
    let h = &opened.header;
    ShareAdmissionFacts {
        envelope_authenticated: true,
        // The recipient key digest was already checked by `open_signed_item`.
        addressed_to_recipient: h.recipient_user_id.as_str() == context.recipient_user_id,
        sender_matches_attribution: h.sender_user_id.as_str() == context.attributed_sender_user_id,
        has_pin: context.pin.is_some(),
        signer_matches_pin: context
            .pin
            .is_some_and(|p| p.sender_vk == h.sender_vk && p.sender_user_id == h.sender_user_id),
        lineage_matches_pin: context.pin.is_some_and(|p| p.lineage_id == h.lineage_id),
        pinned_revision: context.pin.map_or(0, |p| p.revision),
        candidate_revision: h.revision,
    }
}

/// Exact authorization contract over decoded observations, rather than a facts
/// struct supplied by the caller. Cryptographic opening is a separate boundary.
pub fn observed_admission_matches_spec(
    opened: Option<&OpenedShare>,
    context: &AdmissionContext<'_>,
    decision: ShareAdmissionDecision,
) -> bool {
    let Some(opened) = opened else {
        return matches!(decision, ShareAdmissionDecision::Reject);
    };
    let h = &opened.header;
    let bound = h.recipient_user_id.as_str() == context.recipient_user_id
        && h.sender_user_id.as_str() == context.attributed_sender_user_id
        && h.revision >= 1;
    match decision {
        ShareAdmissionDecision::AcceptFirstContact(permit) => {
            context.pin.is_none()
                && bound
                && vela_client_share_policy::share_permit_revision(permit) == h.revision
        }
        ShareAdmissionDecision::ApplyUpdate(permit) => match context.pin {
            Some(pin) => {
                bound
                    && pin.sender_user_id == h.sender_user_id
                    && pin.sender_vk == h.sender_vk
                    && pin.lineage_id == h.lineage_id
                    && h.revision > pin.revision
                    && vela_client_share_policy::share_permit_revision(permit) == h.revision
            }
            None => false,
        },
        ShareAdmissionDecision::Reject => {
            !bound
                || match context.pin {
                    None => false,
                    Some(pin) => {
                        pin.sender_user_id != h.sender_user_id
                            || pin.sender_vk != h.sender_vk
                            || pin.lineage_id != h.lineage_id
                            || h.revision <= pin.revision
                    }
                }
        }
    }
}

/// Production composition: decoded fields -> facts -> verified policy.
#[cfg_attr(hax, hax_lib::ensures(|decision| observed_admission_matches_spec(opened, context, decision)))]
pub fn plan_observed_share(
    opened: Option<&OpenedShare>,
    context: &AdmissionContext<'_>,
) -> ShareAdmissionDecision {
    plan_share_admission(admission_facts(opened, context))
}

fn rejection_reason(facts: &ShareAdmissionFacts) -> &'static str {
    if !facts.addressed_to_recipient {
        "shared item is addressed to a different account"
    } else if !facts.sender_matches_attribution {
        "shared item is signed by a different sender than the server reported"
    } else if facts.has_pin && !facts.signer_matches_pin {
        "update is not signed by the device that originally shared this item"
    } else if facts.has_pin && !facts.lineage_matches_pin {
        "update belongs to a different share"
    } else if facts.has_pin {
        "update is not newer than the copy already held"
    } else {
        "shared item was rejected"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Party {
        vk: Vec<u8>,
        sk: signing::HybridSigningKey,
    }

    fn device() -> Party {
        let (vk, sk) = signing::generate_keypair().unwrap();
        Party {
            vk: vk.to_bytes().to_vec(),
            sk,
        }
    }

    fn header(sender: &Party, recipient: &kem::HybridPublicKey, revision: u64) -> ShareHeader {
        ShareHeader {
            sender_user_id: "alice".into(),
            sender_device_id: "alice-laptop".into(),
            sender_vk: sender.vk.clone(),
            recipient_user_id: "bob".into(),
            recipient_ek_digest: recipient_ek_digest(&recipient.to_bytes()),
            lineage_id: "lineage-1".into(),
            revision,
        }
    }

    fn ctx<'a>(pin: Option<&'a SharePin>) -> AdmissionContext<'a> {
        AdmissionContext {
            recipient_user_id: "bob",
            attributed_sender_user_id: "alice",
            pin,
        }
    }

    #[test]
    fn reader_prefix_failure_preserves_input_and_success_consumes_exactly() {
        let input = b"signed-envelope-field";
        for n in [input.len() + 1, usize::MAX] {
            let mut cursor = input.as_slice();
            assert!(take_frame_prefix(&mut cursor, n).is_none());
            assert_eq!(cursor, input);
        }
        for n in 0..=input.len() {
            let mut cursor = input.as_slice();
            assert_eq!(take_frame_prefix(&mut cursor, n).unwrap(), &input[..n]);
            assert_eq!(cursor, &input[n..]);
        }
    }

    #[test]
    fn byte_frame_matches_sender_fields_and_rejects_trailing_or_missing_bytes() {
        let alice = device();
        let (bob_pk, bob_sk) = kem::generate_keypair();
        let expected = header(&alice, &bob_pk, 0x0102_0304_0506_0708);
        let capsule = seal_signed_item(&alice.sk, &expected, &bob_pk, b"payload").unwrap();
        let mut plaintext = kem::open_share(&bob_sk, &capsule).unwrap();
        let frame = parse_share_frame(&plaintext).unwrap();
        assert_eq!(frame.sender_user_id, expected.sender_user_id.as_bytes());
        assert_eq!(frame.sender_device_id, expected.sender_device_id.as_bytes());
        assert_eq!(frame.sender_vk, expected.sender_vk.as_slice());
        assert_eq!(
            frame.recipient_user_id,
            expected.recipient_user_id.as_bytes()
        );
        assert_eq!(
            frame.recipient_ek_digest,
            expected.recipient_ek_digest.as_slice()
        );
        assert_eq!(frame.lineage_id, expected.lineage_id.as_bytes());
        assert_eq!(frame.revision, expected.revision);
        assert_eq!(frame.item, b"payload");
        assert_eq!(frame.signature.len(), signing::HYBRID_SIG_LEN);
        assert!(parse_share_frame(&plaintext[..plaintext.len() - 1]).is_none());
        plaintext.push(0);
        assert!(parse_share_frame(&plaintext).is_none());
        plaintext[4..12].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse_share_frame(&plaintext).is_none());
    }

    #[test]
    fn first_contact_then_newer_update_is_admitted() {
        let alice = device();
        let (bob_pk, bob_sk) = kem::generate_keypair();
        let first =
            seal_signed_item(&alice.sk, &header(&alice, &bob_pk, 1), &bob_pk, b"v1").unwrap();
        let admitted = admit(&bob_sk, &first, ctx(None)).unwrap();
        assert!(admitted.first_contact);
        assert_eq!(admitted.opened.item, b"v1");
        assert_eq!(admitted.pin.revision, 1);

        let second =
            seal_signed_item(&alice.sk, &header(&alice, &bob_pk, 2), &bob_pk, b"v2").unwrap();
        let updated = admit(&bob_sk, &second, ctx(Some(&admitted.pin))).unwrap();
        assert!(!updated.first_contact);
        assert_eq!(updated.opened.item, b"v2");
        assert_eq!(updated.pin.revision, 2);

        // Replaying the first capsule after the update is rejected.
        assert!(admit(&bob_sk, &first, ctx(Some(&updated.pin))).is_err());
    }

    /// The attack v1 allowed: anyone holding Bob's public share key (the
    /// server, or any user) seals new content and claims it is Alice's edit.
    #[test]
    fn a_forged_update_from_another_key_is_rejected_after_pinning() {
        let alice = device();
        let mallory = device();
        let (bob_pk, bob_sk) = kem::generate_keypair();
        let first =
            seal_signed_item(&alice.sk, &header(&alice, &bob_pk, 1), &bob_pk, b"real").unwrap();
        let pin = admit(&bob_sk, &first, ctx(None)).unwrap().pin;

        // Mallory signs with her own key but claims Alice's identity and a
        // much newer revision.
        let forged_header = ShareHeader {
            sender_vk: mallory.vk.clone(),
            revision: 1_000,
            ..header(&alice, &bob_pk, 1)
        };
        let forged = seal_signed_item(&mallory.sk, &forged_header, &bob_pk, b"phish").unwrap();
        let err = admit(&bob_sk, &forged, ctx(Some(&pin))).unwrap_err();
        assert!(
            err.to_string().contains("not signed by the device"),
            "{err}"
        );
    }

    #[test]
    fn v1_unsigned_capsules_are_rejected() {
        let (bob_pk, bob_sk) = kem::generate_keypair();
        let v1 = kem::seal_share(&bob_pk, br#"{"item_type":"login"}"#).unwrap();
        assert!(open_signed_item(&bob_sk, &v1).is_err());
        assert!(admit(&bob_sk, &v1, ctx(None)).is_err());
    }

    #[test]
    fn an_envelope_cannot_be_forwarded_to_another_recipient() {
        let alice = device();
        let (bob_pk, bob_sk) = kem::generate_keypair();
        let (carol_pk, carol_sk) = kem::generate_keypair();
        let to_bob =
            seal_signed_item(&alice.sk, &header(&alice, &bob_pk, 1), &bob_pk, b"x").unwrap();
        // Bob decrypts and re-seals Alice's signed plaintext to Carol.
        let plaintext = kem::open_share(&bob_sk, &to_bob).unwrap();
        let forwarded = kem::seal_share(&carol_pk, &plaintext).unwrap();
        assert!(open_signed_item(&carol_sk, &forwarded).is_err());
    }

    #[test]
    fn misaddressed_and_misattributed_envelopes_are_rejected() {
        let alice = device();
        let (bob_pk, bob_sk) = kem::generate_keypair();
        let capsule =
            seal_signed_item(&alice.sk, &header(&alice, &bob_pk, 1), &bob_pk, b"x").unwrap();
        let wrong_recipient = AdmissionContext {
            recipient_user_id: "carol",
            ..ctx(None)
        };
        assert!(admit(&bob_sk, &capsule, wrong_recipient).is_err());
        let wrong_sender = AdmissionContext {
            attributed_sender_user_id: "mallory",
            ..ctx(None)
        };
        assert!(admit(&bob_sk, &capsule, wrong_sender).is_err());
    }

    #[test]
    fn tampering_with_any_signed_field_breaks_the_signature() {
        let alice = device();
        let (bob_pk, bob_sk) = kem::generate_keypair();
        let h = header(&alice, &bob_pk, 1);
        let signature = signing::sign(&alice.sk, &signing_transcript(&h, b"item")).unwrap();
        for tampered in [
            ShareHeader {
                sender_user_id: "eve".into(),
                ..h.clone()
            },
            ShareHeader {
                sender_device_id: "eve-phone".into(),
                ..h.clone()
            },
            ShareHeader {
                recipient_user_id: "carol".into(),
                ..h.clone()
            },
            ShareHeader {
                lineage_id: "lineage-2".into(),
                ..h.clone()
            },
            ShareHeader {
                revision: 2,
                ..h.clone()
            },
            ShareHeader {
                recipient_ek_digest: [0u8; 32],
                ..h.clone()
            },
        ] {
            let vk =
                signing::HybridVerifyingKey::from_bytes(alice.vk.as_slice().try_into().unwrap())
                    .unwrap();
            assert!(
                !signing::verify(&vk, &signing_transcript(&tampered, b"item"), &signature)
                    .unwrap_or(false)
            );
        }
        assert!(!signing::verify(
            &signing::HybridVerifyingKey::from_bytes(alice.vk.as_slice().try_into().unwrap())
                .unwrap(),
            &signing_transcript(&h, b"other item"),
            &signature
        )
        .unwrap_or(false));
        let _ = bob_sk;
    }

    #[test]
    fn sealing_refuses_mismatched_headers() {
        let alice = device();
        let other = device();
        let (bob_pk, _) = kem::generate_keypair();
        let (carol_pk, _) = kem::generate_keypair();
        assert!(seal_signed_item(&other.sk, &header(&alice, &bob_pk, 1), &bob_pk, b"x").is_err());
        assert!(seal_signed_item(&alice.sk, &header(&alice, &bob_pk, 1), &carol_pk, b"x").is_err());
        assert!(seal_signed_item(&alice.sk, &header(&alice, &bob_pk, 0), &bob_pk, b"x").is_err());
    }
}
