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
use ed25519_dalek::{
    Signer as _, SigningKey as Ed25519Sk, Verifier as _, VerifyingKey as Ed25519Vk,
};
use fips204::ml_dsa_87::{self, PrivateKey as MlDsaSk, PublicKey as MlDsaVk};
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
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
        return Err(VelaError::InvalidParameter(
            "contact envelope too short".into(),
        ));
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

/// Length of the staged possession commitment: a hybrid verifying key
/// (`ML-DSA-87 vk (2592 B) ‖ Ed25519 vk (32 B)`).
pub const POSSESSION_COMMITMENT_LEN: usize = crate::signing::HYBRID_VK_LEN;
/// Length of a possession proof: a hybrid signature.
pub const POSSESSION_PROOF_LEN: usize = crate::signing::HYBRID_SIG_LEN;

/// Deterministic CSPRNG whose output stream is derived from a single 32-byte
/// seed via BLAKE3 (counter-mode key re-chaining).
///
/// Used only for ML-DSA-87 *key generation*: FIPS 204 keygen is randomized, but
/// the possession keypair must be reproducible from the RMS alone, so we feed
/// keygen from this stream instead of OS entropy. The resulting ML-DSA-87 key
/// pair is an ordinary FIPS 204 key pair; its post-quantum security depends on
/// ML-DSA, not on this wrapper.
struct KdfStreamRng {
    seed: [u8; 32],
    block: [u8; 32],
    offset: usize,
    counter: u64,
}

impl KdfStreamRng {
    fn new(seed: [u8; 32]) -> Self {
        let mut rng = Self {
            seed,
            block: [0u8; 32],
            offset: usize::MAX,
            counter: 0,
        };
        rng.refill();
        rng
    }

    fn refill(&mut self) {
        self.counter = self.counter.wrapping_add(1);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vela rms possession ml-dsa keygen v1");
        hasher.update(&self.seed);
        hasher.update(&self.counter.to_le_bytes());
        self.block.copy_from_slice(hasher.finalize().as_bytes());
        self.offset = 0;
    }
}

impl rand_core::RngCore for KdfStreamRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.offset >= self.block.len() {
                self.refill();
            }
            *byte = self.block[self.offset];
            self.offset += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for KdfStreamRng {}

/// Derive the deterministic hybrid signing key for one account's RMS.
///
/// Both components come from the RMS via BLAKE3 domain-separated derivation:
/// the Ed25519 component from a directly derived seed, and the ML-DSA-87
/// component through `KdfStreamRng` key generation. Distinct derivation
/// contexts prevent any cross-component key reuse.
fn possession_keys(rms: &[u8; 32]) -> (MlDsaSk, MlDsaVk, Ed25519Sk) {
    let ml_seed = crate::kdf::derive("vela rms possession ml-dsa v1", rms).0;
    let ed_seed = crate::kdf::derive("vela rms possession ed25519 v1", rms).0;
    let mut rng = KdfStreamRng::new(ml_seed);
    // Keygen consumes only our deterministic stream; the Infallible-style error
    // arm is unreachable for well-formed RNG output.
    let (ml_vk, ml_sk) =
        ml_dsa_87::KG::try_keygen_with_rng(&mut rng).expect("deterministic ML-DSA keygen");
    let ed_sk = Ed25519Sk::from_bytes(&ed_seed);
    let ed_vk = ed_sk.verifying_key();
    let _ = ed_vk;
    (ml_sk, ml_vk, ed_sk)
}

/// Public verifying commitment to the reconstructed RMS, staged next to the
/// server share.
///
/// Lets the server issue a post-recovery enrollment grant after seeing only a
/// challenge-bound proof — no WebAuthn assertion required, because possession
/// of *any* two shares already implies possession of the RMS.
///
/// The commitment is the PUBLIC hybrid (post-quantum + classical) verifying key
/// of a keypair deterministically derived from the RMS — ML-DSA-87 plus
/// Ed25519, mirroring every other identity signature in VELA. It can only be
/// used to VERIFY proofs, never to produce them: a database reader holding
/// `recovery_auth_hash` learns nothing that lets them forge a valid proof under
/// either algorithm. Verification remains online-only and rate-limited like
/// every other recovery endpoint.
pub fn rms_possession_commitment(rms: &[u8; 32]) -> [u8; POSSESSION_COMMITMENT_LEN] {
    let (_, ml_vk, ed_sk) = possession_keys(rms);
    let mut out = [0u8; POSSESSION_COMMITMENT_LEN];
    out[..crate::signing::ML_DSA_VK_LEN].copy_from_slice(&ml_vk.into_bytes());
    out[crate::signing::ML_DSA_VK_LEN..].copy_from_slice(ed_sk.verifying_key().as_bytes());
    out
}

/// Proof-message binding for one specific recovery attempt.
fn possession_message(
    user_id: &str,
    recovery_id: &str,
    challenge: &[u8],
    key_epoch: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(48 + user_id.len() + recovery_id.len() + challenge.len());
    message.extend_from_slice(b"vela recovery possession proof v2");
    message.extend_from_slice(&(user_id.len() as u32).to_le_bytes());
    message.extend_from_slice(user_id.as_bytes());
    message.extend_from_slice(&(recovery_id.len() as u32).to_le_bytes());
    message.extend_from_slice(recovery_id.as_bytes());
    message.extend_from_slice(&(challenge.len() as u32).to_le_bytes());
    message.extend_from_slice(challenge);
    message.extend_from_slice(&key_epoch.to_le_bytes());
    message
}

const POSSESSION_MLDSA_CTX: &[u8] = b"vela recovery possession v1";

/// Prove possession of the RMS for one specific recovery attempt.
///
/// Signs with both components of the RMS-derived hybrid key. `challenge` comes
/// from `/recovery/initiate-proof`, so a captured proof is worthless outside
/// its single-use attempt.
pub fn rms_possession_sign(
    rms: &[u8; 32],
    user_id: &str,
    recovery_id: &str,
    challenge: &[u8],
    key_epoch: i64,
) -> [u8; POSSESSION_PROOF_LEN] {
    let (ml_sk, _, ed_sk) = possession_keys(rms);
    let message = possession_message(user_id, recovery_id, challenge, key_epoch);
    let mut sig = [0u8; POSSESSION_PROOF_LEN];
    let ml_sig = ml_sk
        .try_sign(&message, POSSESSION_MLDSA_CTX)
        .expect("ML-DSA sign");
    sig[..crate::signing::ML_DSA_SIG_LEN].copy_from_slice(&ml_sig);
    sig[crate::signing::ML_DSA_SIG_LEN..].copy_from_slice(&ed_sk.sign(&message).to_bytes());
    sig
}

/// Verify a presented possession proof against the stored public commitment.
///
/// The commitment length selects the scheme version:
///
/// - **v1 (legacy, 32 bytes)** — the pre-hybrid keyed-hash commitment. These
///   were staged by clients that shipped before the hybrid redesign; they are
///   verifiable here so accounts mid-recovery are not stranded, but a v1
///   commitment is itself the proof key and therefore offers no protection
///   against a database reader. v1 remains forgeable-by-design until the
///   account re-stages recovery; it must never be *produced* again.
/// - **v2 (current, 2624 bytes)** — hybrid ML-DSA-87 ‖ Ed25519 verifying key.
pub fn rms_possession_verify(
    commitment: &[u8],
    user_id: &str,
    recovery_id: &str,
    challenge: &[u8],
    key_epoch: i64,
    presented: &[u8],
) -> bool {
    if commitment.len() == 32 {
        // Legacy v1: keyed-hash proof over the same attempt bindings.
        let mut expected = blake3::Hasher::new_keyed(&{
            let mut k = [0u8; 32];
            k.copy_from_slice(commitment);
            k
        });
        expected.update(b"vela recovery possession proof v1");
        expected.update(&(user_id.len() as u32).to_le_bytes());
        expected.update(user_id.as_bytes());
        expected.update(&(recovery_id.len() as u32).to_le_bytes());
        expected.update(recovery_id.as_bytes());
        expected.update(&(challenge.len() as u32).to_le_bytes());
        expected.update(challenge);
        expected.update(&key_epoch.to_le_bytes());
        return presented.len() == 32
            && constant_time_eq(presented, expected.finalize().as_bytes());
    }

    if commitment.len() != POSSESSION_COMMITMENT_LEN || presented.len() != POSSESSION_PROOF_LEN {
        return false;
    }
    let message = possession_message(user_id, recovery_id, challenge, key_epoch);

    let ml_vk = match MlDsaVk::try_from_bytes(
        commitment[..crate::signing::ML_DSA_VK_LEN]
            .try_into()
            .expect("length checked above"),
    ) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // ML-DSA-87 component (post-quantum): must verify on its own.
    let ml_sig: [u8; crate::signing::ML_DSA_SIG_LEN] = presented[..crate::signing::ML_DSA_SIG_LEN]
        .try_into()
        .expect("length checked above");
    if !ml_vk.verify(&message, &ml_sig, POSSESSION_MLDSA_CTX) {
        return false;
    }

    // Classical component: must also verify independently.
    let ed_sig = match <&[u8; 32]>::try_from(&commitment[crate::signing::ML_DSA_VK_LEN..])
        .ok()
        .and_then(|b| Ed25519Vk::from_bytes(b).ok())
    {
        Some(vk) => vk,
        None => return false,
    };
    use ed25519_dalek::Signature as Ed25519Sig;
    let ed_sig_bytes: [u8; crate::signing::ED25519_SIG_LEN] = presented
        [crate::signing::ML_DSA_SIG_LEN..]
        .try_into()
        .expect("length checked above");
    ed_sig
        .verify(&message, &Ed25519Sig::from_bytes(&ed_sig_bytes))
        .is_ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
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
        let mut raw_contact = bound(&shares[1], ACCOUNT, 2, RecoveryShareChannel::TrustedContact);
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
        let commitment = rms_possession_commitment(&rms);
        let proof = rms_possession_sign(&rms, ACCOUNT, "attempt-1", b"challenge", 5);
        assert!(rms_possession_verify(
            &commitment,
            ACCOUNT,
            "attempt-1",
            b"challenge",
            5,
            &proof
        ));
        // Binding: another attempt id, challenge, or epoch fails verification.
        assert!(!rms_possession_verify(
            &commitment,
            ACCOUNT,
            "attempt-2",
            b"challenge",
            5,
            &proof
        ));
        assert!(!rms_possession_verify(
            &commitment,
            ACCOUNT,
            "attempt-1",
            b"other",
            5,
            &proof
        ));
        assert!(!rms_possession_verify(
            &commitment,
            ACCOUNT,
            "attempt-1",
            b"challenge",
            6,
            &proof
        ));
        // A different RMS produces a different commitment and proof.
        let other_commitment = rms_possession_commitment(&[14u8; 32]);
        let other_proof = rms_possession_sign(&[14u8; 32], ACCOUNT, "attempt-1", b"challenge", 5);
        assert_ne!(commitment, other_commitment);
        assert_ne!(proof, other_proof);
        assert!(!rms_possession_verify(
            &other_commitment,
            ACCOUNT,
            "attempt-1",
            b"challenge",
            5,
            &proof
        ));
        // A different RMS produces a different commitment and proof.
        let other_commitment = rms_possession_commitment(&[14u8; 32]);
        let other_proof = rms_possession_sign(&[14u8; 32], ACCOUNT, "attempt-1", b"challenge", 5);
        assert_ne!(commitment, other_commitment);
        assert_ne!(proof, other_proof);
        assert!(!rms_possession_verify(
            &other_commitment,
            ACCOUNT,
            "attempt-1",
            b"challenge",
            5,
            &proof
        ));
        // The commitment itself cannot produce a valid proof (DB-read safety).
        assert!(!rms_possession_verify(
            &commitment,
            ACCOUNT,
            "attempt-1",
            b"challenge",
            5,
            &{
                let mut p = [0u8; POSSESSION_PROOF_LEN];
                p[..POSSESSION_COMMITMENT_LEN.min(POSSESSION_PROOF_LEN)].copy_from_slice(
                    &commitment[..POSSESSION_COMMITMENT_LEN.min(POSSESSION_PROOF_LEN)],
                );
                p
            }
        ));
    }

    #[test]
    fn possession_keys_are_derived_deterministically() {
        let rms = [21u8; 32];
        // Key derivation is deterministic (same verifying key every time);
        // signatures are not compared byte-for-byte because ML-DSA signing
        // deliberately randomizes its rejection-sampling loop.
        assert_eq!(
            rms_possession_commitment(&rms),
            rms_possession_commitment(&rms)
        );
        let commitment = rms_possession_commitment(&rms);
        for attempt in [("a", b"c".as_slice(), 1i64), ("b", b"d".as_slice(), 2)] {
            let proof = rms_possession_sign(&rms, ACCOUNT, attempt.0, attempt.1, attempt.2);
            assert!(rms_possession_verify(
                &commitment,
                ACCOUNT,
                attempt.0,
                attempt.1,
                attempt.2,
                &proof
            ));
        }
    }

    #[test]
    fn legacy_v1_possession_still_verifies() {
        // Accounts staged before the hybrid redesign hold a 32-byte keyed-hash
        // commitment; their in-flight proofs must keep verifying.
        let possession_hash = blake3::derive_key("vela rms possession v1", &[99u8; 32]);
        let mut expected = blake3::Hasher::new_keyed(&possession_hash);
        expected.update(b"vela recovery possession proof v1");
        expected.update(&(ACCOUNT.len() as u32).to_le_bytes());
        expected.update(ACCOUNT.as_bytes());
        expected.update(&("recovery_id".len() as u32).to_le_bytes());
        expected.update(b"recovery_id");
        expected.update(&(b"chal".len() as u32).to_le_bytes());
        expected.update(b"chal");
        expected.update(&7i64.to_le_bytes());
        let proof = *expected.finalize().as_bytes();
        assert!(rms_possession_verify(
            &possession_hash,
            ACCOUNT,
            "recovery_id",
            b"chal",
            7,
            &proof
        ));
        assert!(!rms_possession_verify(
            &possession_hash,
            ACCOUNT,
            "recovery_id",
            b"chal",
            8,
            &proof
        ));
    }
}
