//! Hybrid KEM: ML-KEM-1024 + X25519, combined via HKDF-SHA256.
//!
//! Security rationale: if either the lattice assumption (ML-KEM) or the
//! discrete-log assumption (X25519) holds, the hybrid shared secret is
//! computationally indistinguishable from random.
//!
//! # Combiner v2 (current)
//!
//! ```text
//! shared_secret = HKDF-SHA256(
//!     salt = b"vela hybrid kem v2",
//!     ikm  = mlkem_ss ‖ x25519_ss ‖ x25519_epk ‖ x25519_pk
//!            ‖ SHA-256(mlkem_ct) ‖ SHA-256(mlkem_ek),
//!     info = b"vela hybrid kem v2",
//!     len  = 32,
//! )
//! ```
//!
//! The secret is bound to the whole transcript: both ciphertexts and both
//! recipient public keys. X25519 is not IND-CCA on its own, so a combiner that
//! hashes only the two shared secrets keeps CCA security only while ML-KEM
//! holds. Binding the X25519 ephemeral and recipient keys is what X-Wing
//! (Barbosa et al., 2024) does to make the classical half stand on its own.
//! We also bind the ML-KEM ciphertext and key (by hash) instead of relying on
//! ML-KEM's ciphertext-binding property, as in the generic combiners of
//! Giacon, Heuer and Poettering (PKC 2018). Non-contributory X25519 results
//! (low-order points) are rejected.
//!
//! # Combiner v1 (legacy)
//!
//! `HKDF-SHA256(salt = b"vela hybrid kem v1", ikm = mlkem_ss ‖ x25519_ss,
//! info = b"")`. It is only reachable through [`decapsulate_legacy_v1`], for
//! long-lived ciphertexts written before v2 (trusted-contact envelopes). Nothing
//! seals under it any more.
//!
//! # Sealed blobs
//!
//! [`seal_share`] writes `SEALED_V2_MAGIC ‖ capsule (1600 B) ‖ XChaCha20-Poly1305`.
//! [`open_share`] accepts only that format. The magic makes the combiner
//! version explicit instead of something a decryptor has to guess.

use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    ml_kem_1024::{
        Ciphertext as MlKemCt, DecapsulationKey as MlKemDk, EncapsulationKey as MlKemEk,
    },
    Kem, KeyExport, KeyInit, MlKem1024, TryKeyInit,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Result, VelaError};

const HKDF_SALT_V1: &[u8] = b"vela hybrid kem v1";
const COMBINER_V2_LABEL: &[u8] = b"vela hybrid kem v2";

/// Prefix of every blob [`seal_share`] produces: names the format and the
/// combiner version.
pub const SEALED_V2_MAGIC: &[u8; 4] = b"VKM2";

/// A hybrid public key bundle (encapsulation side).
pub struct HybridPublicKey {
    pub mlkem_ek: MlKemEk,
    pub x25519_pk: X25519PublicKey,
}

/// A hybrid secret key bundle (decapsulation side).
///
/// Note: `ml_kem::DecapsulationKey` does not implement `Zeroize` in rc.0, so we
/// rely on drop semantics for the ML-KEM key.  The X25519 static secret implements
/// `ZeroizeOnDrop` natively via `x25519-dalek`.
pub struct HybridSecretKey {
    pub mlkem_dk: MlKemDk,
    pub x25519_sk: StaticSecret,
}

/// The wire-format capsule sent to the recipient.
pub struct HybridCapsule {
    pub mlkem_ct: MlKemCt,
    pub x25519_epk: X25519PublicKey,
}

/// A 32-byte shared secret, zeroized on drop.
pub struct SharedSecret(pub [u8; 32]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // Manual zeroize since we cannot derive it here without the feature.
        for b in &mut self.0 {
            // Use a volatile write to prevent the compiler from optimizing this away.
            unsafe { std::ptr::write_volatile(b as *mut u8, 0) };
        }
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

/// Generate a fresh hybrid keypair.
pub fn generate_keypair() -> (HybridPublicKey, HybridSecretKey) {
    let (mlkem_dk, mlkem_ek) = MlKem1024::generate_keypair();
    let x25519_sk = StaticSecret::random_from_rng(OsRng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    let pk = HybridPublicKey {
        mlkem_ek,
        x25519_pk,
    };
    let sk = HybridSecretKey {
        mlkem_dk,
        x25519_sk,
    };
    (pk, sk)
}

/// Encapsulate a fresh shared secret for the given public key (combiner v2).
///
/// Returns the capsule to transmit to the recipient and the shared secret
/// for the sender's own use (e.g., to encrypt the RMS before sending).
pub fn encapsulate(pk: &HybridPublicKey) -> Result<(HybridCapsule, SharedSecret)> {
    // ML-KEM encapsulation
    let (mlkem_ct, mlkem_ss) = pk.mlkem_ek.encapsulate();

    // X25519 ephemeral DH
    let x25519_esk = EphemeralSecret::random_from_rng(OsRng);
    let x25519_epk = X25519PublicKey::from(&x25519_esk);
    let x25519_ss = x25519_esk.diffie_hellman(&pk.x25519_pk);
    if !x25519_ss.was_contributory() {
        return Err(VelaError::InvalidParameter(
            "recipient X25519 key is a low-order point".into(),
        ));
    }

    let capsule = HybridCapsule {
        mlkem_ct,
        x25519_epk,
    };
    let shared = combine_v2(
        AsRef::<[u8]>::as_ref(&mlkem_ss),
        x25519_ss.as_bytes(),
        &capsule,
        pk,
    )?;
    Ok((capsule, shared))
}

/// Decapsulate a received capsule using our secret key (combiner v2).
pub fn decapsulate(sk: &HybridSecretKey, capsule: &HybridCapsule) -> Result<SharedSecret> {
    let mlkem_ss = sk.mlkem_dk.decapsulate(&capsule.mlkem_ct);
    let x25519_ss = sk.x25519_sk.diffie_hellman(&capsule.x25519_epk);
    if !x25519_ss.was_contributory() {
        return Err(VelaError::KemError);
    }
    combine_v2(
        AsRef::<[u8]>::as_ref(&mlkem_ss),
        x25519_ss.as_bytes(),
        capsule,
        &sk.public_key(),
    )
}

/// Decapsulate a capsule produced by the v1 combiner.
///
/// Only for long-lived ciphertexts written before combiner v2 existed (the
/// trusted-contact envelope, version byte 1). Do not use for anything new.
pub fn decapsulate_legacy_v1(sk: &HybridSecretKey, capsule: &HybridCapsule) -> Result<SharedSecret> {
    let mlkem_ss = sk.mlkem_dk.decapsulate(&capsule.mlkem_ct);
    let x25519_ss = sk.x25519_sk.diffie_hellman(&capsule.x25519_epk);
    combine_v1(AsRef::<[u8]>::as_ref(&mlkem_ss), x25519_ss.as_bytes())
}

/// Test-only: produce a capsule the way pre-v2 clients did, so legacy-read
/// paths can be exercised.
#[cfg(test)]
pub(crate) fn encapsulate_legacy_v1(pk: &HybridPublicKey) -> Result<(HybridCapsule, SharedSecret)> {
    let (mlkem_ct, mlkem_ss) = pk.mlkem_ek.encapsulate();
    let x25519_esk = EphemeralSecret::random_from_rng(OsRng);
    let x25519_epk = X25519PublicKey::from(&x25519_esk);
    let x25519_ss = x25519_esk.diffie_hellman(&pk.x25519_pk);
    let shared = combine_v1(AsRef::<[u8]>::as_ref(&mlkem_ss), x25519_ss.as_bytes())?;
    Ok((HybridCapsule { mlkem_ct, x25519_epk }, shared))
}

fn combine_v2(
    mlkem_ss: &[u8],
    x25519_ss: &[u8; 32],
    capsule: &HybridCapsule,
    recipient: &HybridPublicKey,
) -> Result<SharedSecret> {
    let ct_hash = Sha256::digest(capsule.mlkem_ct.as_ref() as &[u8]);
    let ek_hash = Sha256::digest(recipient.mlkem_ek.to_bytes().as_ref() as &[u8]);

    let mut ikm = Zeroizing::new(Vec::with_capacity(mlkem_ss.len() + 4 * 32 + 32));
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(capsule.x25519_epk.as_bytes());
    ikm.extend_from_slice(recipient.x25519_pk.as_bytes());
    ikm.extend_from_slice(&ct_hash);
    ikm.extend_from_slice(&ek_hash);

    let hk = Hkdf::<Sha256>::new(Some(COMBINER_V2_LABEL), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(COMBINER_V2_LABEL, &mut okm)
        .map_err(|_| VelaError::KemError)?;
    Ok(SharedSecret(okm))
}

fn combine_v1(mlkem_ss: &[u8], x25519_ss: &[u8]) -> Result<SharedSecret> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(mlkem_ss.len() + 32));
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_V1), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"", &mut okm).map_err(|_| VelaError::KemError)?;

    Ok(SharedSecret(okm))
}

// ── Serialization ─────────────────────────────────────────────────────────────

/// ML-KEM-1024 encapsulation key byte length (FIPS 203 §7, Table 2).
pub const ML_KEM_EK_LEN: usize = 1568;
/// ML-KEM-1024 decapsulation key serialized length.
///
/// ml-kem 0.3 stores the decapsulation key as its 64-byte generation seed
/// (`KeyExport`/`KeyInit` operate on the seed), reconstructing the expanded key
/// deterministically. This is the recommended, compact storage form.
pub const ML_KEM_DK_SEED_LEN: usize = 64;

impl HybridPublicKey {
    /// Wire size: ML-KEM-1024 EK (1568 B) ‖ X25519 PK (32 B) = 1600 B.
    pub const BYTES_LEN: usize = ML_KEM_EK_LEN + 32;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES_LEN);
        out.extend_from_slice(&self.mlkem_ek.to_bytes());
        out.extend_from_slice(self.x25519_pk.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::BYTES_LEN {
            return Err(VelaError::InvalidParameter(format!(
                "hybrid public key must be {} bytes, got {}",
                Self::BYTES_LEN,
                bytes.len()
            )));
        }
        let mlkem_ek = MlKemEk::new_from_slice(&bytes[..ML_KEM_EK_LEN])
            .map_err(|_| VelaError::InvalidParameter("invalid ML-KEM ek bytes".into()))?;
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&bytes[ML_KEM_EK_LEN..]);
        Ok(Self {
            mlkem_ek,
            x25519_pk: X25519PublicKey::from(pk_arr),
        })
    }
}

impl HybridSecretKey {
    /// Wire size: ML-KEM-1024 DK seed (64 B) ‖ X25519 SK (32 B) = 96 B.
    pub const BYTES_LEN: usize = ML_KEM_DK_SEED_LEN + 32;

    /// Recompute the public half.
    ///
    /// Lets a caller hold only the secret key and still publish the key others
    /// seal to, instead of storing (and moving around) both halves.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            mlkem_ek: self.mlkem_dk.encapsulation_key().clone(),
            x25519_pk: X25519PublicKey::from(&self.x25519_sk),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES_LEN);
        // `to_bytes` returns the 64-byte seed for seed-backed keys (always the
        // case for keys produced by `generate_keypair`).
        out.extend_from_slice(&self.mlkem_dk.to_bytes());
        out.extend_from_slice(self.x25519_sk.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::BYTES_LEN {
            return Err(VelaError::InvalidParameter(format!(
                "hybrid secret key must be {} bytes, got {}",
                Self::BYTES_LEN,
                bytes.len()
            )));
        }
        let mlkem_dk = MlKemDk::new_from_slice(&bytes[..ML_KEM_DK_SEED_LEN])
            .map_err(|_| VelaError::InvalidParameter("invalid ML-KEM dk seed".into()))?;
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&bytes[ML_KEM_DK_SEED_LEN..]);
        Ok(Self {
            mlkem_dk,
            x25519_sk: StaticSecret::from(sk_arr),
        })
    }
}

/// Encrypt `plaintext` for a recipient's share public key.
///
/// Wire format: `SEALED_V2_MAGIC (4 B) ‖ KEM capsule (1600 B) ‖ XChaCha20-Poly1305 ct`.
pub fn seal_share(pk: &HybridPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (capsule, ss) = encapsulate(pk)?;
    let ct = crate::aead::encrypt(ss.as_bytes(), plaintext)?;
    let mut out = Vec::with_capacity(SEALED_V2_MAGIC.len() + HybridCapsule::WIRE_LEN + ct.len());
    out.extend_from_slice(SEALED_V2_MAGIC);
    out.extend_from_slice(&capsule.to_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob produced by [`seal_share`] using the recipient's secret key.
///
/// Blobs without the v2 prefix (written by the v1 combiner) are rejected:
/// every caller of this function handles short-lived material that a current
/// client re-creates on demand.
pub fn open_share(sk: &HybridSecretKey, data: &[u8]) -> Result<Vec<u8>> {
    let header = SEALED_V2_MAGIC.len() + HybridCapsule::WIRE_LEN;
    if data.len() <= header {
        return Err(VelaError::InvalidParameter("share data too short".into()));
    }
    if &data[..SEALED_V2_MAGIC.len()] != SEALED_V2_MAGIC {
        return Err(VelaError::InvalidParameter(
            "sealed blob is not in the v2 format (written by an outdated client?)".into(),
        ));
    }
    let capsule = HybridCapsule::from_bytes(&data[SEALED_V2_MAGIC.len()..header])?;
    let ss = decapsulate(sk, &capsule)?;
    let pt = crate::aead::decrypt(ss.as_bytes(), &data[header..])?;
    Ok(pt.to_vec())
}

impl HybridCapsule {
    /// ML-KEM-1024 ciphertext byte length.
    pub const MLKEM_CT_LEN: usize = 1568;
    /// Wire size = ML-KEM ct + X25519 epk.
    pub const WIRE_LEN: usize = Self::MLKEM_CT_LEN + 32;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(self.mlkem_ct.as_ref());
        out.extend_from_slice(self.x25519_epk.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return Err(VelaError::InvalidParameter(format!(
                "capsule must be {} bytes, got {}",
                Self::WIRE_LEN,
                bytes.len()
            )));
        }
        let (ct_bytes, epk_bytes) = bytes.split_at(Self::MLKEM_CT_LEN);
        let mlkem_ct: MlKemCt = ct_bytes
            .try_into()
            .map_err(|_| VelaError::InvalidParameter("invalid ML-KEM ciphertext".into()))?;
        let mut epk_arr = [0u8; 32];
        epk_arr.copy_from_slice(epk_bytes);
        let x25519_epk = X25519PublicKey::from(epk_arr);
        Ok(Self {
            mlkem_ct,
            x25519_epk,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_roundtrip() {
        let (pk, sk) = generate_keypair();
        let (capsule, ss_sender) = encapsulate(&pk).unwrap();
        let ss_recv = decapsulate(&sk, &capsule).unwrap();
        assert_eq!(ss_sender.0, ss_recv.0);
    }

    #[test]
    fn wrong_key_produces_different_secret() {
        let (pk, _sk) = generate_keypair();
        let (_, sk2) = generate_keypair();
        let (capsule, ss_sender) = encapsulate(&pk).unwrap();
        // ML-KEM uses implicit rejection — wrong key gives deterministic
        // pseudorandom output, not an error.
        let ss_wrong = decapsulate(&sk2, &capsule).unwrap();
        assert_ne!(ss_sender.0, ss_wrong.0);
    }

    #[test]
    fn capsule_serialization_roundtrip() {
        let (pk, sk) = generate_keypair();
        let (capsule, ss_orig) = encapsulate(&pk).unwrap();
        let bytes = capsule.to_bytes();
        assert_eq!(bytes.len(), HybridCapsule::WIRE_LEN);
        let capsule2 = HybridCapsule::from_bytes(&bytes).unwrap();
        let ss_recovered = decapsulate(&sk, &capsule2).unwrap();
        assert_eq!(ss_orig.0, ss_recovered.0);
    }

    #[test]
    fn hybrid_public_key_serialization_roundtrip() {
        let (pk, _sk) = generate_keypair();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), HybridPublicKey::BYTES_LEN);
        let pk2 = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.x25519_pk.as_bytes(), pk2.x25519_pk.as_bytes());
    }

    #[test]
    fn hybrid_secret_key_serialization_roundtrip() {
        let (pk, sk) = generate_keypair();
        let sk_bytes = sk.to_bytes();
        assert_eq!(sk_bytes.len(), HybridSecretKey::BYTES_LEN);
        let sk2 = HybridSecretKey::from_bytes(&sk_bytes).unwrap();
        // Verify the reconstructed key works: encap with pk, decap with sk2
        let (capsule, ss_sender) = encapsulate(&pk).unwrap();
        let ss_recv = decapsulate(&sk2, &capsule).unwrap();
        assert_eq!(ss_sender.0, ss_recv.0);
    }

    #[test]
    fn seal_open_share_roundtrip() {
        let (pk, sk) = generate_keypair();
        let plaintext = b"github.com password: hunter2";
        let blob = seal_share(&pk, plaintext).unwrap();
        assert!(blob.len() > SEALED_V2_MAGIC.len() + HybridCapsule::WIRE_LEN);
        assert_eq!(&blob[..4], SEALED_V2_MAGIC);
        let recovered = open_share(&sk, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn open_share_wrong_key_fails() {
        let (pk, _sk) = generate_keypair();
        let (_, sk2) = generate_keypair();
        let blob = seal_share(&pk, b"secret").unwrap();
        // ML-KEM uses implicit rejection — decap succeeds but gives garbage,
        // so AEAD decryption will fail with an authentication error.
        assert!(open_share(&sk2, &blob).is_err());
    }

    /// A capsule decapsulated under the v1 combiner yields a different key,
    /// so the two versions can never be confused for one another.
    #[test]
    fn v1_and_v2_combiners_disagree() {
        let (pk, sk) = generate_keypair();
        let (capsule, ss) = encapsulate(&pk).unwrap();
        let legacy = decapsulate_legacy_v1(&sk, &capsule).unwrap();
        assert_ne!(ss.0, legacy.0);
    }

    /// The v2 secret is bound to the X25519 ephemeral key: substituting a
    /// different ephemeral (a mix-and-match capsule) changes the key even
    /// though the ML-KEM half is untouched.
    #[test]
    fn swapping_the_x25519_ephemeral_changes_the_secret() {
        let (pk, sk) = generate_keypair();
        let (capsule, ss) = encapsulate(&pk).unwrap();
        let (other, _) = encapsulate(&pk).unwrap();
        let mixed = HybridCapsule {
            mlkem_ct: capsule.mlkem_ct.clone(),
            x25519_epk: other.x25519_epk,
        };
        let mixed_ss = decapsulate(&sk, &mixed).unwrap();
        assert_ne!(ss.0, mixed_ss.0);
    }

    /// The v2 secret is bound to the recipient's key: the same capsule bytes
    /// decapsulated by a key with the same X25519 half but another ML-KEM half
    /// do not agree.
    #[test]
    fn the_secret_is_bound_to_the_recipient_key() {
        let (pk, sk) = generate_keypair();
        let (capsule, ss) = encapsulate(&pk).unwrap();
        let (_, other_sk) = generate_keypair();
        let franken = HybridSecretKey {
            mlkem_dk: other_sk.mlkem_dk,
            x25519_sk: sk.x25519_sk.clone(),
        };
        let ss2 = decapsulate(&franken, &capsule).unwrap();
        assert_ne!(ss.0, ss2.0);
    }

    #[test]
    fn low_order_x25519_points_are_rejected() {
        let (pk, sk) = generate_keypair();
        let (capsule, _) = encapsulate(&pk).unwrap();
        let low_order = HybridCapsule {
            mlkem_ct: capsule.mlkem_ct,
            x25519_epk: X25519PublicKey::from([0u8; 32]),
        };
        assert!(decapsulate(&sk, &low_order).is_err());

        let bad_pk = HybridPublicKey {
            mlkem_ek: pk.mlkem_ek,
            x25519_pk: X25519PublicKey::from([0u8; 32]),
        };
        assert!(encapsulate(&bad_pk).is_err());
    }

    #[test]
    fn blobs_without_the_v2_prefix_are_rejected() {
        let (pk, sk) = generate_keypair();
        let mut blob = seal_share(&pk, b"secret").unwrap();
        blob[0] ^= 1;
        assert!(open_share(&sk, &blob).is_err());
    }
}
