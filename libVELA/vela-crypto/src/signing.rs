//! Hybrid device identity signing: ML-DSA-87 (FIPS 204) + Ed25519.
//!
//! ## Algorithm selection rationale
//!
//! The spec mandates hybrid post-quantum security at the same level as the KEM
//! (ML-KEM-1024 = NIST Level 5).  The signing scheme mirrors that pattern:
//!
//! | Role       | KEM              | Signing           |
//! |------------|------------------|-------------------|
//! | PQC (L5)   | ML-KEM-1024      | **ML-DSA-87**     |
//! | Classical  | X25519           | **Ed25519**       |
//! | Standard   | NIST FIPS 203    | NIST FIPS 204     |
//!
//! Both components must verify; either alone suffices against a partial
//! adversary.  Ed25519 is the signing analog of X25519 (same Curve25519
//! family) and is natively supported by hardware enclaves (Secure Enclave,
//! Android Keystore, TPM 2.0 firmware).  ML-DSA-87 is software-only today
//! but stored encrypted inside the enclave alongside vault keys.
//!
//! `ml-dsa` (RustCrypto) carries RUSTSEC-2025-0144 (timing side-channel in
//! the decomposition step) through v0.0.4.  This module uses `fips204` which
//! is constant-time and carries no known advisories.
//!
//! ## Wire formats
//!
//! ```text
//! HybridVerifyingKey  = ml_dsa_87_vk (2592 B) ‖ ed25519_vk (32 B)  → 2624 B
//! HybridSignature     = ml_dsa_87_sig (4627 B) ‖ ed25519_sig (64 B) → 4691 B
//! ```
//!
//! The signing key is never serialised — it lives in the hardware enclave or
//! is zeroized immediately after use.

use crate::{Result, VelaError};
use ed25519_dalek::{
    Signature as Ed25519Sig, Signer as _, SigningKey as Ed25519Sk, Verifier as _,
    VerifyingKey as Ed25519Vk,
};
use fips204::ml_dsa_87::{self, PrivateKey as MlDsaSk, PublicKey as MlDsaVk};
use fips204::traits::{SerDes, Signer as _, Verifier as _};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

// ── Byte-length constants (FIPS 204, Table 1; Curve25519 spec) ───────────────

/// ML-DSA-87 public-key length.
pub const ML_DSA_VK_LEN: usize = 2592;
/// ML-DSA-87 signature length (as produced by fips204 v0.4.x).
pub const ML_DSA_SIG_LEN: usize = 4627;

/// Ed25519 public-key length.
pub const ED25519_VK_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;

/// Total hybrid verifying-key wire length.
pub const HYBRID_VK_LEN: usize = ML_DSA_VK_LEN + ED25519_VK_LEN; // 2624
/// Total hybrid signature wire length.
pub const HYBRID_SIG_LEN: usize = ML_DSA_SIG_LEN + ED25519_SIG_LEN; // 4659

/// Domain-separation context passed to ML-DSA-87's context string parameter.
const ML_DSA_CTX: &[u8] = b"vela device identity v1";

// ── Key types ─────────────────────────────────────────────────────────────────

/// The combined signing key (ML-DSA-87 + Ed25519).
///
/// Zeroized on drop.  Never serialised to disk — lives in the secure enclave
/// or is reconstructed ephemerally from enclave-protected seed material.
#[derive(ZeroizeOnDrop)]
pub struct HybridSigningKey {
    ml_dsa: MlDsaSk,
    ed25519: Ed25519Sk,
}

/// The combined verifying (public) key, suitable for transmission and storage.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    ml_dsa: MlDsaVk,
    ed25519: Ed25519Vk,
}

/// A hybrid signature: both components must verify.
#[derive(Clone)]
pub struct HybridSignature {
    ml_dsa: [u8; ML_DSA_SIG_LEN],
    ed25519: Ed25519Sig,
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a fresh hybrid device identity key pair.
///
/// Both key components are generated with fresh randomness from the OS CSPRNG.
pub fn generate_keypair() -> Result<(HybridVerifyingKey, HybridSigningKey)> {
    // ML-DSA-87 keygen (uses OsRng internally via fips204)
    let (ml_dsa_vk, ml_dsa_sk) =
        ml_dsa_87::try_keygen().map_err(|e| VelaError::SigningError(format!("ML-DSA keygen: {e:?}")))?;

    // Ed25519 keygen
    let ed25519_sk = Ed25519Sk::generate(&mut OsRng);
    let ed25519_vk = ed25519_sk.verifying_key();

    let vk = HybridVerifyingKey { ml_dsa: ml_dsa_vk, ed25519: ed25519_vk };
    let sk = HybridSigningKey { ml_dsa: ml_dsa_sk, ed25519: ed25519_sk };
    Ok((vk, sk))
}

// ── Sign / Verify ─────────────────────────────────────────────────────────────

/// Sign `message` with both key components.
///
/// Both signatures are required for the counterpart [`verify`] to succeed.
pub fn sign(sk: &HybridSigningKey, message: &[u8]) -> Result<HybridSignature> {
    let ml_dsa_sig = sk
        .ml_dsa
        .try_sign(message, ML_DSA_CTX)
        .map_err(|e| VelaError::SigningError(format!("ML-DSA sign: {e:?}")))?;

    let ed25519_sig: Ed25519Sig = sk.ed25519.sign(message);

    Ok(HybridSignature { ml_dsa: ml_dsa_sig, ed25519: ed25519_sig })
}

/// Verify a hybrid signature.
///
/// Returns `Ok(true)` only when **both** components verify independently.
/// Returns `Ok(false)` if either component fails verification.
pub fn verify(vk: &HybridVerifyingKey, message: &[u8], sig: &HybridSignature) -> Result<bool> {
    let ml_dsa_ok = vk.ml_dsa.verify(message, &sig.ml_dsa, ML_DSA_CTX);

    if !ml_dsa_ok {
        return Ok(false);
    }

    let ed25519_ok = vk.ed25519.verify(message, &sig.ed25519).is_ok();
    Ok(ed25519_ok)
}

// ── Serialisation ─────────────────────────────────────────────────────────────

impl HybridVerifyingKey {
    /// Serialise to `[ml_dsa_vk (2592 B) ‖ ed25519_vk (32 B)]`.
    pub fn to_bytes(&self) -> [u8; HYBRID_VK_LEN] {
        let mut out = [0u8; HYBRID_VK_LEN];
        out[..ML_DSA_VK_LEN].copy_from_slice(&self.ml_dsa.clone().into_bytes());
        out[ML_DSA_VK_LEN..].copy_from_slice(self.ed25519.as_bytes());
        out
    }

    /// Deserialise from bytes produced by [`HybridVerifyingKey::to_bytes`].
    pub fn from_bytes(bytes: &[u8; HYBRID_VK_LEN]) -> Result<Self> {
        let vk_arr: &[u8; ML_DSA_VK_LEN] = bytes[..ML_DSA_VK_LEN]
            .try_into()
            .map_err(|_| VelaError::SigningError("ML-DSA vk slice length mismatch".into()))?;
        let ml_dsa = MlDsaVk::try_from_bytes(*vk_arr)
            .map_err(|e| VelaError::SigningError(format!("ML-DSA vk decode: {e:?}")))?;

        let mut ed_arr = [0u8; ED25519_VK_LEN];
        ed_arr.copy_from_slice(&bytes[ML_DSA_VK_LEN..]);
        let ed25519 = Ed25519Vk::from_bytes(&ed_arr)
            .map_err(|e| VelaError::SigningError(format!("Ed25519 vk decode: {e}")))?;

        Ok(Self { ml_dsa, ed25519 })
    }
}

impl HybridSignature {
    /// Serialise to `[ml_dsa_sig (4595 B) ‖ ed25519_sig (64 B)]`.
    pub fn to_bytes(&self) -> [u8; HYBRID_SIG_LEN] {
        let mut out = [0u8; HYBRID_SIG_LEN];
        out[..ML_DSA_SIG_LEN].copy_from_slice(&self.ml_dsa);
        out[ML_DSA_SIG_LEN..].copy_from_slice(&self.ed25519.to_bytes());
        out
    }

    /// Deserialise from bytes produced by [`HybridSignature::to_bytes`].
    pub fn from_bytes(bytes: &[u8; HYBRID_SIG_LEN]) -> Result<Self> {
        let mut ml_dsa = [0u8; ML_DSA_SIG_LEN];
        ml_dsa.copy_from_slice(&bytes[..ML_DSA_SIG_LEN]);

        let mut ed_arr = [0u8; ED25519_SIG_LEN];
        ed_arr.copy_from_slice(&bytes[ML_DSA_SIG_LEN..]);
        let ed25519 = Ed25519Sig::from_bytes(&ed_arr);

        Ok(Self { ml_dsa, ed25519 })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ML-DSA-87 key generation and signing allocate ~57 KB of polynomial arrays
    // on the stack (matrix A = k×ℓ×n coefficients at 4 B each).  The default
    // Rust test thread stack (1 MB) is too small in unoptimised debug builds.
    // Spawn each cryptographic test in an 8 MB thread.
    fn run_in_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn sign_verify_roundtrip() {
        run_in_large_stack(|| {
            let (vk, sk) = generate_keypair().unwrap();
            let msg = b"device B public key bytes go here";
            let sig = sign(&sk, msg).unwrap();
            assert!(verify(&vk, msg, &sig).unwrap());
        });
    }

    #[test]
    fn wrong_message_fails() {
        run_in_large_stack(|| {
            let (vk, sk) = generate_keypair().unwrap();
            let sig = sign(&sk, b"correct message").unwrap();
            assert!(!verify(&vk, b"wrong message", &sig).unwrap());
        });
    }

    #[test]
    fn wrong_key_fails() {
        run_in_large_stack(|| {
            let (_, sk) = generate_keypair().unwrap();
            let (vk2, _) = generate_keypair().unwrap();
            let sig = sign(&sk, b"message").unwrap();
            assert!(!verify(&vk2, b"message", &sig).unwrap());
        });
    }

    #[test]
    fn verifying_key_serialisation_roundtrip() {
        run_in_large_stack(|| {
            let (vk, sk) = generate_keypair().unwrap();
            let bytes = vk.to_bytes();
            assert_eq!(bytes.len(), HYBRID_VK_LEN);
            let vk2 = HybridVerifyingKey::from_bytes(&bytes).unwrap();
            let msg = b"vk serialisation test";
            let sig = sign(&sk, msg).unwrap();
            assert!(verify(&vk, msg, &sig).unwrap());
            // Deserialised key must produce the same result as the original.
            assert!(verify(&vk2, msg, &sig).unwrap());
        });
    }

    #[test]
    fn signature_serialisation_roundtrip() {
        run_in_large_stack(|| {
            let (vk, sk) = generate_keypair().unwrap();
            let msg = b"roundtrip test";
            let sig = sign(&sk, msg).unwrap();
            let bytes = sig.to_bytes();
            assert_eq!(bytes.len(), HYBRID_SIG_LEN);
            let sig2 = HybridSignature::from_bytes(&bytes).unwrap();
            assert!(verify(&vk, msg, &sig2).unwrap());
        });
    }

    #[test]
    fn wire_lengths_are_correct() {
        assert_eq!(HYBRID_VK_LEN, 2624);
        assert_eq!(HYBRID_SIG_LEN, 4691);
    }
}
