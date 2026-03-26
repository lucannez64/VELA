//! VELA core cryptographic operations using vela-crypto.

use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vela_crypto::{
    aead::{decrypt, encrypt},
    kdf::{self, DerivedKey},
    shamir::{self, Share},
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

pub fn derive_device_id(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let result = hasher.finalize();
    Uuid::from_bytes(result[..16].try_into().unwrap()).to_string()
}
