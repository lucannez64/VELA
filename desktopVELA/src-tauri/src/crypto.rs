//! VELA core cryptographic operations using vela-crypto.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
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

const HYBRID_EK_LEN: usize = 1600;

#[derive(Clone)]
pub struct IdentityKeypair {
    pub hybrid_ek: Vec<u8>,
    pub hybrid_vk: Vec<u8>,
    pub hybrid_sk: Vec<u8>,
}

pub fn generate_identity_keypair() -> Result<IdentityKeypair, String> {
    let (_kem_pk, _kem_sk) = kem::generate_keypair();
    let hybrid_ek = serialize_hybrid_ek(&[]);

    let (signing_vk, signing_sk) = signing::generate_keypair()
        .map_err(|e| format!("Failed to generate signing keypair: {}", e))?;
    let hybrid_vk = signing_vk.to_bytes().to_vec();
    let hybrid_sk = signing_sk.into_bytes();

    Ok(IdentityKeypair {
        hybrid_ek,
        hybrid_vk,
        hybrid_sk,
    })
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

fn serialize_hybrid_ek(_kem_pk: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; HYBRID_EK_LEN];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
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
        rand::rngs::OsRng.fill_bytes(&mut rms);
        rms
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
