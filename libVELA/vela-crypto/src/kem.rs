//! Hybrid KEM: ML-KEM-1024 + X25519, combined via HKDF-SHA256.
//!
//! Security rationale: if either the lattice assumption (ML-KEM) or the
//! discrete-log assumption (X25519) holds, the hybrid shared secret is
//! computationally indistinguishable from random.
//!
//! Shared secret derivation:
//!   shared_secret = HKDF-SHA256(
//!       ikm  = mlkem_ss || x25519_ss,
//!       salt = b"vela hybrid kem v1",
//!       info = b"",
//!       len  = 32,
//!   )

use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    ml_kem_1024::{
        Ciphertext as MlKemCt, DecapsulationKey as MlKemDk, EncapsulationKey as MlKemEk,
    },
    Kem, KeyExport, KeyInit, MlKem1024, TryKeyInit,
};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Result, VelaError};

const HKDF_SALT: &[u8] = b"vela hybrid kem v1";

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

/// Encapsulate a fresh shared secret for the given public key.
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

    let shared = combine_secrets(AsRef::<[u8]>::as_ref(&mlkem_ss), x25519_ss.as_bytes())?;

    let capsule = HybridCapsule {
        mlkem_ct,
        x25519_epk,
    };
    Ok((capsule, shared))
}

/// Decapsulate a received capsule using our secret key.
pub fn decapsulate(sk: &HybridSecretKey, capsule: &HybridCapsule) -> Result<SharedSecret> {
    let mlkem_ss = sk.mlkem_dk.decapsulate(&capsule.mlkem_ct);
    let x25519_ss = sk.x25519_sk.diffie_hellman(&capsule.x25519_epk);
    combine_secrets(AsRef::<[u8]>::as_ref(&mlkem_ss), x25519_ss.as_bytes())
}

fn combine_secrets(mlkem_ss: &[u8], x25519_ss: &[u8]) -> Result<SharedSecret> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(mlkem_ss.len() + 32));
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
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
/// Wire format: `[1600 B KEM capsule ‖ XChaCha20-Poly1305 ct]`.
pub fn seal_share(pk: &HybridPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (capsule, ss) = encapsulate(pk)?;
    let ct = crate::aead::encrypt(ss.as_bytes(), plaintext)?;
    let mut out = capsule.to_bytes(); // 1600 B
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a share blob produced by [`seal_share`] using the recipient's secret key.
pub fn open_share(sk: &HybridSecretKey, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() <= HybridCapsule::WIRE_LEN {
        return Err(VelaError::InvalidParameter("share data too short".into()));
    }
    let capsule = HybridCapsule::from_bytes(&data[..HybridCapsule::WIRE_LEN])?;
    let ss = decapsulate(sk, &capsule)?;
    let pt = crate::aead::decrypt(ss.as_bytes(), &data[HybridCapsule::WIRE_LEN..])?;
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
        assert!(blob.len() > HybridCapsule::WIRE_LEN);
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
}
