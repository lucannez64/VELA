//! BLAKE3 key derivation (VELA KDF layer).
//!
//! All keys in VELA are derived from the Root Master Seed (RMS) using BLAKE3's
//! native KDF mode with domain-separated context strings.

use blake3::derive_key;
use zeroize::ZeroizeOnDrop;

/// A 32-byte derived key, zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKey([REDACTED])")
    }
}

/// Well-known context strings used across the VELA protocol.
/// These are fixed — never change them after deployment.
pub mod contexts {
    pub const VAULT_ENCRYPTION: &str = "vela vault encryption v1";
    pub const CHUNK_KEY: &str = "vela chunk key v1";
    pub const AUDIT_LOG: &str = "vela audit log v1";
    pub const DEVICE_IDENTITY: &str = "vela device identity v1";
    pub const IDENTITY_SIGNING: &str = "vela identity signing v1";
    pub const MAC_KEY: &str = "vela mac key v1";
    pub const SHARE_ENCRYPTION: &str = "vela share encryption v1";
    pub const ORAM_POSITION_MAP: &str = "vela oram position map v1";
}

/// Derive a 32-byte key from the RMS using the given context string.
///
/// Wraps `blake3::derive_key(context, key_material)`.
pub fn derive(context: &str, rms: &[u8]) -> DerivedKey {
    DerivedKey(derive_key(context, rms))
}

/// Derive the vault encryption key from the RMS.
pub fn vault_encryption_key(rms: &[u8]) -> DerivedKey {
    derive(contexts::VAULT_ENCRYPTION, rms)
}

/// Derive the audit log encryption key from the RMS.
pub fn audit_log_key(rms: &[u8]) -> DerivedKey {
    derive(contexts::AUDIT_LOG, rms)
}

/// Derive a per-chunk encryption key from the RMS.
///
/// Uses context "vela chunk key v1" with the chunk ID appended for domain separation.
pub fn chunk_key(rms: &[u8], chunk_id: &[u8]) -> DerivedKey {
    let context = format!("{} || {:?}", contexts::CHUNK_KEY, chunk_id);
    derive(&context, rms)
}

/// Derive the MAC key from the RMS (HMAC-style integrity checks on vault metadata).
pub fn mac_key(rms: &[u8]) -> DerivedKey {
    derive(contexts::MAC_KEY, rms)
}

/// Derive an ORAM position-map encryption key from the RMS.
pub fn oram_position_map_key(rms: &[u8]) -> DerivedKey {
    derive(contexts::ORAM_POSITION_MAP, rms)
}

/// Derive the share encryption key from the RMS (used when sending vault items to other users).
pub fn share_encryption_key(rms: &[u8]) -> DerivedKey {
    derive(contexts::SHARE_ENCRYPTION, rms)
}

/// Derive the device identity key seed from the RMS.
///
/// This seed is used to deterministically expand into the device signing key pair
/// (ML-DSA-87 + Ed25519).  The actual key material is generated inside the
/// hardware secure enclave and never exported; this function derives only the
/// seed that bootstraps the in-enclave key generation.
pub fn device_identity_key_seed(rms: &[u8]) -> DerivedKey {
    derive(contexts::DEVICE_IDENTITY, rms)
}

/// Derive the identity signing key from the RMS.
///
/// This seed is used as the Ed25519 private key for device enrollment signatures.
/// The identity signing key is stored in the device's Hardware Secure Enclave
/// alongside the RMS and is never transmitted.
pub fn identity_signing_key_seed(rms: &[u8]) -> DerivedKey {
    derive(contexts::IDENTITY_SIGNING, rms)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_RMS: &[u8] = b"this-is-a-fake-32-byte-rms-seed!";

    #[test]
    fn derive_is_deterministic() {
        let k1 = derive(contexts::VAULT_ENCRYPTION, FAKE_RMS);
        let k2 = derive(contexts::VAULT_ENCRYPTION, FAKE_RMS);
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let k1 = derive(contexts::VAULT_ENCRYPTION, FAKE_RMS);
        let k2 = derive(contexts::AUDIT_LOG, FAKE_RMS);
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn vault_key_and_audit_key_helpers_match_derive() {
        let rms = FAKE_RMS;
        assert_eq!(
            vault_encryption_key(rms).0,
            derive(contexts::VAULT_ENCRYPTION, rms).0
        );
        assert_eq!(audit_log_key(rms).0, derive(contexts::AUDIT_LOG, rms).0);
    }
}
