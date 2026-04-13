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
    ml_kem_1024::{
        Ciphertext as MlKemCt, DecapsulationKey as MlKemDk, EncapsulationKey as MlKemEk,
    },
    kem::{Decapsulate, Encapsulate},
    Kem, MlKem1024,
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

    let pk = HybridPublicKey { mlkem_ek, x25519_pk };
    let sk = HybridSecretKey { mlkem_dk, x25519_sk };
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

    let capsule = HybridCapsule { mlkem_ct, x25519_epk };
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
        Ok(Self { mlkem_ct, x25519_epk })
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
}
