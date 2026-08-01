//! VELA core cryptographic operations using vela-crypto.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vela_crypto::{
    aead::{decrypt, encrypt},
    kdf::{self, DerivedKey},
    kem,
    shamir::{self, Share},
    signing,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const VAULT_KEY_CONTEXT: &str = "vela vault encryption v1";
const CHUNK_KEY_CONTEXT: &str = "vela chunk key v1";
const IDENTITY_KEY_CONTEXT: &str = "vela device identity v1";
const IDENTITY_SIGNING_KEY_CONTEXT: &str = "vela identity signing v1";
const AUDIT_KEY_CONTEXT: &str = "vela audit log v1";
const MAC_KEY_CONTEXT: &str = "vela mac key v1";
const SHARE_KEY_CONTEXT: &str = "vela share encryption v1";
const ORAM_KEY_CONTEXT: &str = "vela oram position map v1";

#[derive(Clone)]
pub struct IdentityKeypair {
    pub hybrid_ek: Vec<u8>,
    pub hybrid_vk: Vec<u8>,
    pub hybrid_sk: Vec<u8>,
    pub share_ek: Vec<u8>,
    pub share_dk: Vec<u8>,
}

pub fn generate_identity_keypair() -> Result<IdentityKeypair, String> {
    // `hybrid_ek` must be a real KEM public key, not filler bytes: it is
    // signed (via sign_enrollment) and transmitted to the server as part of
    // this device's identity, so storing/attesting to random noise here
    // means the signed enrollment payload contains fake key material. The
    // matching secret key is intentionally not persisted anywhere — nothing
    // in the current protocol encapsulates under hybrid_ek (the RMS capsule
    // is sealed with a symmetric transfer_key instead, see
    // crypto::create_rms_capsule), so there is nothing to decrypt with it
    // yet. A public key with no stored private counterpart is inert, not
    // insecure: it just can't be used until that capability exists.
    let (hybrid_ek_pk, _unused_hybrid_ek_sk) = kem::generate_keypair();
    let hybrid_ek = hybrid_ek_pk.to_bytes();

    let (signing_vk, signing_sk) = signing::generate_keypair()
        .map_err(|e| format!("Failed to generate signing keypair: {}", e))?;
    let hybrid_vk = signing_vk.to_bytes().to_vec();
    let hybrid_sk = signing_sk.into_bytes();

    let (share_pk, share_sk) = kem::generate_keypair();

    Ok(IdentityKeypair {
        hybrid_ek,
        hybrid_vk,
        hybrid_sk,
        share_ek: share_pk.to_bytes(),
        share_dk: share_sk.to_bytes(),
    })
}

/// Generate only a fresh share keypair `(share_ek, share_dk)`. Used to backfill
/// share keys for identities created before sharing existed, without disturbing
/// the device-auth hybrid keys.
pub fn generate_share_keypair() -> (Vec<u8>, Vec<u8>) {
    let (share_pk, share_sk) = kem::generate_keypair();
    (share_pk.to_bytes(), share_sk.to_bytes())
}

/// Encrypt a vault item for a recipient using their share public key.
pub fn seal_share(share_ek_bytes: &[u8], item_json: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pk = kem::HybridPublicKey::from_bytes(share_ek_bytes)?;
    Ok(kem::seal_share(&pk, item_json)?)
}

/// Decrypt a share capsule using our share secret key.
pub fn open_share(share_dk_bytes: &[u8], capsule: &[u8]) -> anyhow::Result<Vec<u8>> {
    let sk = kem::HybridSecretKey::from_bytes(share_dk_bytes)?;
    Ok(kem::open_share(&sk, capsule)?)
}

/// Sign the security-relevant enrollment payload with the enrolling device's key.
/// Returns the hybrid signature bytes (4691 B).
pub fn sign_enrollment(
    hybrid_sk_bytes: &[u8],
    hybrid_ek: &[u8],
    hybrid_vk: &[u8],
    rms_capsule: &[u8],
) -> Result<Vec<u8>, String> {
    let sk = signing::HybridSigningKey::from_bytes(hybrid_sk_bytes)
        .map_err(|e| format!("Failed to decode signing key: {e}"))?;
    let message = signing::enrollment_message(hybrid_ek, hybrid_vk, rms_capsule);
    let sig = signing::sign(&sk, &message)
        .map_err(|e| format!("Failed to sign enrollment payload: {e}"))?;
    Ok(sig.to_bytes().to_vec())
}

/// AEAD-encrypt `rms` using `transfer_key`.  The resulting capsule is stored
/// on the server and downloaded by the new device after authentication.
pub fn create_rms_capsule(transfer_key: &[u8; 32], rms: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    Ok(vela_crypto::aead::encrypt(transfer_key, rms)?)
}

/// Decrypt an RMS capsule previously created by [`create_rms_capsule`].
pub fn decrypt_rms_capsule(transfer_key: &[u8; 32], capsule: &[u8]) -> Result<[u8; 32], String> {
    let plaintext = vela_crypto::aead::decrypt(transfer_key, capsule)
        .map_err(|e| format!("Failed to decrypt RMS capsule: {e}"))?;
    if plaintext.len() < 32 {
        return Err(format!(
            "Decrypted capsule too short: {} bytes",
            plaintext.len()
        ));
    }
    let mut rms = [0u8; 32];
    rms.copy_from_slice(&plaintext[..32]);
    Ok(rms)
}

/// Sign a server-issued challenge for authentication.
pub fn create_auth_signature(
    hybrid_sk: &[u8],
    challenge: &[u8],
    device_id: &str,
) -> Result<String, String> {
    let sk = signing::HybridSigningKey::from_bytes(hybrid_sk)
        .map_err(|e| format!("Failed to decode signing key: {e}"))?;
    let message = signing::auth_message(device_id, challenge);
    let signature = signing::sign(&sk, &message)
        .map_err(|e| format!("Failed to sign authentication challenge: {e}"))?;
    Ok(B64.encode(signature.to_bytes()))
}

#[derive(ZeroizeOnDrop)]
pub struct Crypto {
    rms: [u8; 32],
}

impl Crypto {
    pub fn new(rms: &[u8; 32]) -> Self {
        Self { rms: *rms }
    }

    pub fn generate_rms() -> [u8; 32] {
        let mut rms = [0u8; 32];
        getrandom::getrandom(&mut rms).expect("OS random source unavailable");
        rms
    }

    /// The raw Root Master Seed. Only used to seal an RW ephemeral web session
    /// capsule to a browser's ephemeral key (`EPHEMERAL_WEB_ACCESS_DESIGN.md`).
    pub fn rms(&self) -> [u8; 32] {
        self.rms
    }

    pub fn vault_key(&self) -> DerivedKey {
        kdf::derive(VAULT_KEY_CONTEXT, &self.rms)
    }

    pub fn chunk_key(&self, chunk_id: &[u8]) -> DerivedKey {
        let context = format!("{} || {:?}", CHUNK_KEY_CONTEXT, chunk_id);
        kdf::derive(&context, &self.rms)
    }

    pub fn identity_key(&self) -> DerivedKey {
        kdf::derive(IDENTITY_KEY_CONTEXT, &self.rms)
    }

    pub fn identity_signing_key(&self) -> DerivedKey {
        kdf::derive(IDENTITY_SIGNING_KEY_CONTEXT, &self.rms)
    }

    pub fn audit_key(&self) -> DerivedKey {
        kdf::derive(AUDIT_KEY_CONTEXT, &self.rms)
    }

    pub fn mac_key(&self) -> DerivedKey {
        kdf::derive(MAC_KEY_CONTEXT, &self.rms)
    }

    pub fn share_key(&self) -> DerivedKey {
        kdf::derive(SHARE_KEY_CONTEXT, &self.rms)
    }

    pub fn oram_key(&self) -> DerivedKey {
        kdf::derive(ORAM_KEY_CONTEXT, &self.rms)
    }

    pub fn encrypt_vault(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(encrypt(self.vault_key().as_bytes(), plaintext)?)
    }

    pub fn decrypt_vault(&self, ciphertext: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        Ok(decrypt(self.vault_key().as_bytes(), ciphertext)?)
    }

    pub fn rms_as_bytes(&self) -> [u8; 32] {
        self.rms
    }

    pub fn split_recovery(&self, threshold: u8, n: u8) -> anyhow::Result<Vec<Share>> {
        Ok(shamir::split(&self.rms, threshold, n)?)
    }

    pub fn reconstruct_recovery(shares: &[Share]) -> anyhow::Result<[u8; 32]> {
        let secret = shamir::reconstruct(shares, 32)?;
        let mut rms = [0u8; 32];
        rms.copy_from_slice(&secret);
        Ok(rms)
    }
}

pub fn compute_challenge_response(challenge: &[u8], device_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(device_id.as_bytes());
    let result = hasher.finalize();
    let mut response = [0u8; 32];
    response.copy_from_slice(&result);
    response
}

pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn derive_device_id(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let result = hasher.finalize();
    Uuid::from_bytes(result[..16].try_into().unwrap()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rms_capsule_roundtrip() {
        let transfer_key = [3u8; 32];
        let rms = Crypto::generate_rms();
        let capsule = create_rms_capsule(&transfer_key, &rms).unwrap();
        assert_ne!(capsule, rms, "capsule is ciphertext");
        assert_eq!(decrypt_rms_capsule(&transfer_key, &capsule).unwrap(), rms);
        // Wrong transfer key cannot open it.
        assert!(decrypt_rms_capsule(&[9u8; 32], &capsule).is_err());
    }

    #[test]
    fn share_seal_open_roundtrip() {
        let (share_ek, share_dk) = generate_share_keypair();
        let item_json = br#"{"secret":"value"}"#;
        let capsule = seal_share(&share_ek, item_json).unwrap();
        let opened = open_share(&share_dk, &capsule).unwrap();
        assert_eq!(opened, item_json);

        // A different recipient key cannot open it.
        let (_other_ek, other_dk) = generate_share_keypair();
        assert!(open_share(&other_dk, &capsule).is_err());
    }

    #[test]
    fn identity_keypair_has_all_key_material() {
        let keys = generate_identity_keypair().unwrap();
        assert!(!keys.hybrid_ek.is_empty());
        assert!(!keys.hybrid_vk.is_empty());
        assert!(!keys.hybrid_sk.is_empty());
        assert!(!keys.share_ek.is_empty());
        assert!(!keys.share_dk.is_empty());
        // Two keypairs are independent.
        let other = generate_identity_keypair().unwrap();
        assert_ne!(keys.hybrid_vk, other.hybrid_vk);
        assert_ne!(keys.share_ek, other.share_ek);
    }

    #[test]
    fn sign_enrollment_produces_hybrid_signature() {
        let keys = generate_identity_keypair().unwrap();
        let sig = sign_enrollment(&keys.hybrid_sk, &keys.hybrid_ek, &keys.hybrid_vk, b"capsule")
            .unwrap();
        // Hybrid sig = ML-DSA-87 (4627 B) ‖ Ed25519 (64 B).
        assert_eq!(sig.len(), 4627 + 64);
        // Garbage key material is rejected, not panicky.
        assert!(sign_enrollment(b"short", b"ek", b"vk", b"cap").is_err());
    }

    #[test]
    fn challenge_response_is_deterministic_sha256() {
        let a = compute_challenge_response(b"challenge", "device-1");
        let b = compute_challenge_response(b"challenge", "device-1");
        assert_eq!(a, b);
        // Domain-separated by device id.
        let c = compute_challenge_response(b"challenge", "device-2");
        assert_ne!(a, c);

        // Matches a hand-rolled SHA-256(challenge ‖ device_id).
        let mut hasher = Sha256::new();
        hasher.update(b"challenge");
        hasher.update(b"device-1");
        assert_eq!(a.as_slice(), hasher.finalize().as_slice());
    }

    #[test]
    fn derive_device_id_is_stable_uuid() {
        let id = derive_device_id(b"public-key-bytes");
        assert_eq!(id, derive_device_id(b"public-key-bytes"));
        assert!(Uuid::parse_str(&id).is_ok(), "device id is a UUID: {id}");
        assert_ne!(id, derive_device_id(b"other-key"));
    }

    #[test]
    fn auth_signature_is_base64() {
        let keys = generate_identity_keypair().unwrap();
        let sig = create_auth_signature(&keys.hybrid_sk, b"challenge", "device-1").unwrap();
        assert!(B64.decode(&sig).is_ok());
    }

    #[test]
    fn vault_key_derivation_is_context_separated() {
        let crypto = Crypto::new(&[42u8; 32]);
        // Different contexts → different keys (no cross-protocol reuse).
        assert_ne!(crypto.vault_key().as_bytes(), crypto.audit_key().as_bytes());
        assert_ne!(crypto.vault_key().as_bytes(), crypto.mac_key().as_bytes());
        assert_ne!(crypto.chunk_key(b"a").as_bytes(), crypto.chunk_key(b"b").as_bytes());
        // Deterministic for the same RMS.
        let same = Crypto::new(&[42u8; 32]);
        assert_eq!(crypto.vault_key().as_bytes(), same.vault_key().as_bytes());
    }
}
