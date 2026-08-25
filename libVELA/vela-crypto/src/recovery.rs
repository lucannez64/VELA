//! Account/epoch-bound recovery reconstruction shared by every client.
//!
//! M18: any *pair* of distinct custodian channels reconstructs — cloud +
//! server, cloud + trusted contact, or server + trusted contact — through one
//! hax-verified pair-selection policy (`vela-client-recovery-policy`). Every
//! share is bound to the same account, epoch, Shamir split id, channel, and a
//! distinct polynomial coordinate, and trusted-contact shares are only ever
//! accepted out of an authenticated envelope sealed to the recipient's KEM
//! key (no more raw copied share text).

use crate::{
    error::{Result, VelaError},
    shamir::{self, Share},
};
use vela_client_recovery_policy::{
    AdoptionDecision, AdoptionFacts, BoundShareFacts, ReconstructionDecision, ReconstructionFacts,
    RecoveryChannel,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryShareChannel {
    Cloud,
    Server,
    TrustedContact,
}

impl From<RecoveryShareChannel> for RecoveryChannel {
    fn from(channel: RecoveryShareChannel) -> Self {
        match channel {
            RecoveryShareChannel::Cloud => RecoveryChannel::Cloud,
            RecoveryShareChannel::Server => RecoveryChannel::Server,
            RecoveryShareChannel::TrustedContact => RecoveryChannel::TrustedContact,
        }
    }
}

pub struct BoundRecoveryShare<'a> {
    pub account_id: &'a str,
    pub key_epoch: i64,
    pub split_id: Option<&'a str>,
    pub channel: RecoveryShareChannel,
    /// True only when this share was opened out of an authenticated envelope
    /// addressed to *this* recipient's KEM key. Raw material copied by hand
    /// can never claim it; the verified policy requires it for every
    /// trusted-contact share.
    pub recipient_bound: bool,
    pub share: &'a Share,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructedRms {
    pub rms: [u8; 32],
    pub key_epoch: i64,
}

/// Reconstruct an RMS from any two distinct recovery channels of the exact
/// account and epoch.
///
/// Both shares must use the authenticated v2 Shamir representation. Successful
/// interpolation therefore also verifies both share MACs under the same
/// reconstructed secret, rejecting relabelled envelopes and shares from a
/// different account, epoch, or split. Duplicate coordinates, duplicate
/// channels, mixed epochs, cross-account pairs, and unbound contact shares all
/// fail closed in the verified policy before interpolation runs.
pub fn reconstruct_account_recovery(
    requested_account_id: &str,
    first: BoundRecoveryShare<'_>,
    second: BoundRecoveryShare<'_>,
) -> Result<ReconstructedRms> {
    let decision = vela_client_recovery_policy::plan_reconstruction(ReconstructionFacts {
        requested_account_present: !requested_account_id.is_empty(),
        split_ids_match: first.split_id == second.split_id,
        first: bound_share_facts(&first, requested_account_id),
        second: bound_share_facts(&second, requested_account_id),
    });
    let permit = match decision {
        ReconstructionDecision::Reconstruct(permit) => permit,
        ReconstructionDecision::Reject => {
            return Err(VelaError::InvalidParameter(
                "recovery shares must be two authenticated shares from distinct channels \
                 bound to the exact account, epoch, and split"
                    .into(),
            ));
        }
    };

    let secret = shamir::reconstruct(&[first.share.clone(), second.share.clone()], 32)?;
    let rms: [u8; 32] = secret.try_into().map_err(|_| {
        VelaError::InvalidParameter("reconstructed RMS must be exactly 32 bytes".into())
    })?;

    let adoption = vela_client_recovery_policy::plan_adoption(
        permit,
        AdoptionFacts {
            // `shamir::reconstruct` verifies every present share MAC and both
            // shares were required above to carry one.
            shares_authenticated_together: true,
            reconstructed_rms_is_32_bytes: true,
            target_epoch: first.key_epoch,
        },
    );
    let adoption = match adoption {
        AdoptionDecision::Adopt(adoption) => adoption,
        AdoptionDecision::Reject => {
            return Err(VelaError::InvalidParameter(
                "verified client recovery policy rejected RMS adoption".into(),
            ));
        }
    };

    Ok(ReconstructedRms {
        rms,
        key_epoch: adoption.epoch(),
    })
}

fn bound_share_facts<'a>(
    bound: &'a BoundRecoveryShare<'a>,
    requested_account_id: &str,
) -> BoundShareFacts {
    BoundShareFacts {
        account_matches: bound.account_id == requested_account_id,
        channel: bound.channel.into(),
        epoch: bound.key_epoch,
        split_id_present: bound.split_id.is_some(),
        share_authenticated: bound.share.mac.is_some(),
        recipient_bound: bound.recipient_bound,
        coordinate: bound.share.x,
    }
}

// ── Authenticated, recipient-bound trusted-contact envelopes ────────────────

const CONTACT_ENVELOPE_VERSION: u8 = 1;
/// Setup → contact handoff. Only the recorded recipient can open it.
const CONTACT_DELIVERY_DOMAIN: &[u8] = b"vela contact-share delivery v1";
/// Contact → recovering-device response. The direction domains are distinct so
/// a delivery envelope can never be replayed as a response (or vice versa).
const CONTACT_RESPONSE_DOMAIN: &[u8] = b"vela contact-share response v1";

/// The identity a contact envelope is sealed under. Both sides must agree on
/// these values byte-for-byte: they ride the AEAD additional data, so any
/// relabelling of account, epoch, split, or coordinate fails authentication
/// instead of yielding a wrong share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactShareContext<'a> {
    pub account_id: &'a str,
    pub key_epoch: i64,
    pub split_id: Option<&'a str>,
    pub coordinate: u8,
}

impl<'a> ContactShareContext<'a> {
    /// Canonical byte encoding used as AEAD associated data.
    fn to_aad(&self, domain: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            domain.len() + self.account_id.len() + 2 * std::mem::size_of::<i64>() + 3,
        );
        aad.extend_from_slice(&(domain.len() as u32).to_le_bytes());
        aad.extend_from_slice(domain);
        aad.extend_from_slice(&(self.account_id.len() as u32).to_le_bytes());
        aad.extend_from_slice(self.account_id.as_bytes());
        aad.extend_from_slice(&self.key_epoch.to_le_bytes());
        match self.split_id {
            Some(split_id) => {
                aad.push(1);
                aad.extend_from_slice(&(split_id.len() as u32).to_le_bytes());
                aad.extend_from_slice(split_id.as_bytes());
            }
            None => aad.push(0),
        }
        aad.push(self.coordinate);
        aad
    }
}

fn seal_for_recipient(
    domain: &[u8],
    recipient: &crate::kem::HybridPublicKey,
    context: &ContactShareContext<'_>,
    share: &Share,
) -> Result<Vec<u8>> {
    if share.mac.is_none() {
        return Err(VelaError::InvalidParameter(
            "contact envelopes require authenticated (v2) shares".into(),
        ));
    }
    if share.x != context.coordinate {
        return Err(VelaError::InvalidParameter(
            "share coordinate does not match the envelope context".into(),
        ));
    }
    let (capsule, shared_secret) = crate::kem::encapsulate(recipient)?;
    let ciphertext = crate::aead::seal(
        shared_secret.as_bytes(),
        &share.to_bytes(),
        &context.to_aad(domain),
    )?;
    let mut out = Vec::with_capacity(1 + crate::kem::HybridCapsule::WIRE_LEN + ciphertext.len());
    out.push(CONTACT_ENVELOPE_VERSION);
    out.extend_from_slice(&capsule.to_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_for_recipient(
    domain: &[u8],
    recipient_sk: &crate::kem::HybridSecretKey,
    context: &ContactShareContext<'_>,
    blob: &[u8],
) -> Result<Share> {
    let header = 1 + crate::kem::HybridCapsule::WIRE_LEN;
    if blob.len() <= header {
        return Err(VelaError::InvalidParameter("contact envelope too short".into()));
    }
    if blob[0] != CONTACT_ENVELOPE_VERSION {
        return Err(VelaError::InvalidParameter(format!(
            "unsupported contact envelope version {}",
            blob[0]
        )));
    }
    let capsule = crate::kem::HybridCapsule::from_bytes(&blob[1..header])?;
    let shared_secret = crate::kem::decapsulate(recipient_sk, &capsule)?;
    let plaintext = crate::aead::open(
        shared_secret.as_bytes(),
        &blob[header..],
        &context.to_aad(domain),
    )?;
    let share = Share::from_bytes(&plaintext)?;
    if share.mac.is_none() {
        return Err(VelaError::InvalidParameter(
            "contact envelope carried a legacy unauthenticated share".into(),
        ));
    }
    if share.x != context.coordinate {
        return Err(VelaError::InvalidParameter(
            "contact envelope carried a different Shamir coordinate than its context".into(),
        ));
    }
    Ok(share)
}

/// Seal Share 3 into an envelope for its trusted contact (setup side).
///
/// This replaces the manual copy flow: the output is useless to everyone
/// except the holder of the recipient KEM secret key, is bound to this exact
/// account/epoch/split/coordinate, and cannot be redirected by modifying its
/// context fields (they are authenticated).
pub fn seal_contact_share(
    recipient: &crate::kem::HybridPublicKey,
    context: &ContactShareContext<'_>,
    share: &Share,
) -> Result<Vec<u8>> {
    seal_for_recipient(CONTACT_DELIVERY_DOMAIN, recipient, context, share)
}

/// Open a delivery envelope received from the account owner (contact side).
pub fn open_contact_share(
    recipient_sk: &crate::kem::HybridSecretKey,
    context: &ContactShareContext<'_>,
    blob: &[u8],
) -> Result<Share> {
    open_for_recipient(CONTACT_DELIVERY_DOMAIN, recipient_sk, context, blob)
}

/// Re-seal a held contact share to a recovery requester's ephemeral key
/// (contact side of a recovery ceremony).
pub fn seal_contact_share_response(
    requester: &crate::kem::HybridPublicKey,
    context: &ContactShareContext<'_>,
    share: &Share,
) -> Result<Vec<u8>> {
    seal_for_recipient(CONTACT_RESPONSE_DOMAIN, requester, context, share)
}

/// Open a contact-share response produced for this device's ephemeral request
/// key (recovering-device side).
pub fn open_contact_share_response(
    request_sk: &crate::kem::HybridSecretKey,
    context: &ContactShareContext<'_>,
    blob: &[u8],
) -> Result<Share> {
    open_for_recipient(CONTACT_RESPONSE_DOMAIN, request_sk, context, blob)
}

// ── RMS possession proof (server enrollment without WebAuthn) ────────────────

/// Blind commitment to the reconstructed RMS, staged next to the server share.
///
/// Lets the server issue a post-recovery enrollment grant after seeing only a
/// challenge-bound proof — no WebAuthn assertion required, because possession
/// of *any* two shares already implies possession of the RMS. The RMS is a
/// random 32-byte value, so the hash leaks nothing usable offline; verification
/// is online-only and rate-limited like every other recovery endpoint.
pub fn rms_possession_hash(rms: &[u8; 32]) -> [u8; 32] {
    crate::kdf::derive("vela rms possession v1", rms).0
}

/// Prove possession of the RMS for one specific recovery attempt.
///
/// `challenge` comes from `/recovery/initiate-proof`, so a captured proof is
/// worthless outside its single-use attempt.
pub fn rms_possession_proof(
    possession_hash: &[u8; 32],
    user_id: &str,
    recovery_id: &str,
    challenge: &[u8],
    key_epoch: i64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(possession_hash);
    hasher.update(b"vela recovery possession proof v1");
    hasher.update(&(user_id.len() as u32).to_le_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(&(recovery_id.len() as u32).to_le_bytes());
    hasher.update(recovery_id.as_bytes());
    hasher.update(&(challenge.len() as u32).to_le_bytes());
    hasher.update(challenge);
    hasher.update(&key_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Constant-time equality for possession proofs compared server-side.
pub fn possession_proofs_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "11111111-1111-1111-1111-111111111111";
    const SPLIT: &str = "22222222-2222-2222-2222-222222222222";

    fn bound<'a>(
        share: &'a Share,
        account: &'a str,
        epoch: i64,
        channel: RecoveryShareChannel,
    ) -> BoundRecoveryShare<'a> {
        BoundRecoveryShare {
            account_id: account,
            key_epoch: epoch,
            split_id: Some(SPLIT),
            channel,
            recipient_bound: channel == RecoveryShareChannel::TrustedContact,
            share,
        }
    }

    #[test]
    fn every_valid_pair_reconstructs() {
        let rms = [7u8; 32];
        let shares = shamir::split(&rms, 2, 3).unwrap();
        for (first_channel, second_channel) in [
            (RecoveryShareChannel::Cloud, RecoveryShareChannel::Server),
            (
                RecoveryShareChannel::Cloud,
                RecoveryShareChannel::TrustedContact,
            ),
            (
                RecoveryShareChannel::Server,
                RecoveryShareChannel::TrustedContact,
            ),
            // Order within the pair must not matter either.
            (RecoveryShareChannel::Server, RecoveryShareChannel::Cloud),
            (
                RecoveryShareChannel::TrustedContact,
                RecoveryShareChannel::Cloud,
            ),
        ] {
            let recovered = reconstruct_account_recovery(
                ACCOUNT,
                bound(&shares[0], ACCOUNT, 4, first_channel),
                bound(&shares[1], ACCOUNT, 4, second_channel),
            )
            .unwrap_or_else(|e| panic!("{first_channel:?}+{second_channel:?} rejected: {e}"));
            assert_eq!(recovered.rms, rms);
            assert_eq!(recovered.key_epoch, 4);
        }
    }

    #[test]
    fn cross_account_mixed_epoch_and_duplicate_coordinates_fail_closed() {
        let shares = shamir::split(&[8u8; 32], 2, 3).unwrap();
        // Cross-account.
        assert!(reconstruct_account_recovery(
            ACCOUNT,
            bound(&shares[0], "other", 4, RecoveryShareChannel::Cloud),
            bound(&shares[1], ACCOUNT, 4, RecoveryShareChannel::Server),
        )
        .is_err());
        // Mixed epoch.
        assert!(reconstruct_account_recovery(
            ACCOUNT,
            bound(&shares[0], ACCOUNT, 3, RecoveryShareChannel::Cloud),
            bound(&shares[1], ACCOUNT, 4, RecoveryShareChannel::Server),
        )
        .is_err());
        // Same channel twice.
        assert!(reconstruct_account_recovery(
            ACCOUNT,
            bound(&shares[0], ACCOUNT, 4, RecoveryShareChannel::Cloud),
            bound(&shares[1], ACCOUNT, 4, RecoveryShareChannel::Cloud),
        )
        .is_err());
        // Same coordinate twice.
        let mut duplicate = shares[1].clone();
        duplicate.x = shares[0].x;
        assert!(reconstruct_account_recovery(
            ACCOUNT,
            bound(&shares[0], ACCOUNT, 4, RecoveryShareChannel::Cloud),
            bound(&duplicate, ACCOUNT, 4, RecoveryShareChannel::Server),
        )
        .is_err());
        // Different splits.
        let other_split_split = shamir::split(&shares[0].y, 2, 3).unwrap();
        let mut mismatched = bound(
            &other_split_split[1],
            ACCOUNT,
            4,
            RecoveryShareChannel::Server,
        );
        mismatched.split_id = Some("33333333-3333-3333-3333-333333333333");
        assert!(reconstruct_account_recovery(
            ACCOUNT,
            bound(&shares[0], ACCOUNT, 4, RecoveryShareChannel::Cloud),
            mismatched,
        )
        .is_err());
    }

    #[test]
    fn unbound_or_legacy_shares_fail_closed() {
        let shares = shamir::split(&[9u8; 32], 2, 3).unwrap();
        // A trusted-contact share that was never inside an addressed envelope.
        let mut raw_contact = bound(
            &shares[1],
            ACCOUNT,
            2,
            RecoveryShareChannel::TrustedContact,
        );
        raw_contact.recipient_bound = false;
        assert!(reconstruct_account_recovery(
            ACCOUNT,
            bound(&shares[0], ACCOUNT, 2, RecoveryShareChannel::Cloud),
            raw_contact,
        )
        .is_err());

        let legacy = Share {
            x: shares[0].x,
            y: shares[0].y.clone(),
            mac: None,
        };
        assert!(reconstruct_account_recovery(
            ACCOUNT,
            BoundRecoveryShare {
                account_id: ACCOUNT,
                key_epoch: 2,
                split_id: Some(SPLIT),
                channel: RecoveryShareChannel::Cloud,
                recipient_bound: false,
                share: &legacy,
            },
            bound(&shares[1], ACCOUNT, 2, RecoveryShareChannel::Server),
        )
        .is_err());
    }

    #[test]
    fn contact_envelope_roundtrip_is_recipient_bound_and_context_locked() {
        let shares = shamir::split(&[11u8; 32], 2, 3).unwrap();
        let (owner_of_copy, contact_sk) = crate::kem::generate_keypair();
        let context = ContactShareContext {
            account_id: ACCOUNT,
            key_epoch: 6,
            split_id: Some(SPLIT),
            coordinate: shares[2].x,
        };
        let envelope = seal_contact_share(&owner_of_copy, &context, &shares[2]).unwrap();

        // The right recipient opens it.
        let opened = open_contact_share(&contact_sk, &context, &envelope).unwrap();
        assert_eq!(opened.x, shares[2].x);
        assert_eq!(opened.y, shares[2].y);

        // A different secret key learns nothing.
        let (_other_pk, other_sk) = crate::kem::generate_keypair();
        assert!(open_contact_share(&other_sk, &context, &envelope).is_err());

        // Relabelled contexts fail authentication instead of yielding a share.
        for tampered in [
            ContactShareContext {
                account_id: "99999999-9999-9999-9999-999999999999",
                key_epoch: 6,
                split_id: Some(SPLIT),
                coordinate: shares[2].x,
            },
            ContactShareContext {
                account_id: ACCOUNT,
                key_epoch: 7,
                split_id: Some(SPLIT),
                coordinate: shares[2].x,
            },
            ContactShareContext {
                account_id: ACCOUNT,
                key_epoch: 6,
                split_id: None,
                coordinate: shares[2].x,
            },
            ContactShareContext {
                account_id: ACCOUNT,
                key_epoch: 6,
                split_id: Some(SPLIT),
                coordinate: 42,
            },
        ] {
            assert!(open_contact_share(&contact_sk, &tampered, &envelope).is_err());
        }

        // A flipped ciphertext byte is rejected.
        let mut corrupt = envelope.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x01;
        assert!(open_contact_share(&contact_sk, &context, &corrupt).is_err());
    }

    #[test]
    fn delivery_envelopes_cannot_be_replayed_as_responses() {
        let shares = shamir::split(&[12u8; 32], 2, 3).unwrap();
        let (request_pk, request_sk) = crate::kem::generate_keypair();
        let context = ContactShareContext {
            account_id: ACCOUNT,
            key_epoch: 3,
            split_id: Some(SPLIT),
            coordinate: shares[1].x,
        };
        let response = seal_contact_share_response(&request_pk, &context, &shares[1]).unwrap();
        assert!(open_contact_share_response(&request_sk, &context, &response).is_ok());
        // Direction confusion: a delivery envelope is not a valid response.
        let delivery = seal_contact_share(&request_pk, &context, &shares[1]).unwrap();
        assert!(open_contact_share_response(&request_sk, &context, &delivery).is_err());
    }

    #[test]
    fn possession_proofs_bind_attempt_and_epoch() {
        let rms = [13u8; 32];
        let hash = rms_possession_hash(&rms);
        let proof = rms_possession_proof(&hash, ACCOUNT, "attempt-1", b"challenge", 5);
        assert!(possession_proofs_equal(
            &proof,
            &rms_possession_proof(&hash, ACCOUNT, "attempt-1", b"challenge", 5)
        ));
        assert!(!possession_proofs_equal(
            &proof,
            &rms_possession_proof(&hash, ACCOUNT, "attempt-2", b"challenge", 5)
        ));
        assert!(!possession_proofs_equal(
            &proof,
            &rms_possession_proof(&hash, ACCOUNT, "attempt-1", b"other", 5)
        ));
        assert!(!possession_proofs_equal(
            &proof,
            &rms_possession_proof(&hash, ACCOUNT, "attempt-1", b"challenge", 6)
        ));
        let other_hash = rms_possession_hash(&[14u8; 32]);
        assert!(!possession_proofs_equal(
            &proof,
            &rms_possession_proof(&other_hash, ACCOUNT, "attempt-1", b"challenge", 5)
        ));
    }
}
