//! VELA core cryptographic operations using vela-crypto.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vela_crypto::{
    aead::{decrypt, encrypt},
    cyclo,
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
const HYBRID_VK_LEN: usize = 2624;
const CYCLO_PK_LEN: usize = 1024;
const CYCLO_KEY_CONTEXT: &str = "vela cyclo zkp key v1";

#[derive(Clone)]
pub struct IdentityKeypair {
    pub hybrid_ek: Vec<u8>,
    pub hybrid_vk: Vec<u8>,
    pub cyclo_pk: Vec<u8>,
    pub cyclo_sk: Vec<u8>,
    pub hybrid_sk: Vec<u8>,
}

pub fn generate_identity_keypair() -> Result<IdentityKeypair, String> {
    let (_kem_pk, _kem_sk) = kem::generate_keypair();
    let hybrid_ek = serialize_hybrid_ek(&[]);

    let (signing_vk, signing_sk) = signing::generate_keypair()
        .map_err(|e| format!("Failed to generate signing keypair: {}", e))?;
    let hybrid_vk = signing_vk.to_bytes().to_vec();
    let hybrid_sk = signing_sk.into_bytes();

    // cyclo_pk: 128 u64 values in [0, CYCLO_Q) — the public device label.
    let mut cyclo_pk = Vec::with_capacity(CYCLO_PK_LEN);
    for _ in 0..128 {
        let mut buf = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let v = u64::from_le_bytes(buf) % CYCLO_Q;
        cyclo_pk.extend_from_slice(&v.to_le_bytes());
    }

    // cyclo_sk: 128 u64 values in [0, B_SIS) — the short witness satisfying the
    // Cyclo lattice norm bound (PRESET_128 B_sis = 2^20).
    let mut cyclo_sk = Vec::with_capacity(CYCLO_PK_LEN);
    for _ in 0..128 {
        let mut buf = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let coeff = (u32::from_le_bytes(buf) & 0xFFFFF) as u64; // [0, 2^20)
        cyclo_sk.extend_from_slice(&coeff.to_le_bytes());
    }

    Ok(IdentityKeypair {
        hybrid_ek,
        hybrid_vk,
        cyclo_pk,
        cyclo_sk,
        hybrid_sk,
    })
}

/// Sign a new device's `hybrid_vk` bytes using the enrolling device's signing key.
/// Returns the hybrid signature bytes (4691 B).
pub fn sign_new_device_vk(hybrid_sk_bytes: &[u8], new_hybrid_vk: &[u8]) -> Result<Vec<u8>, String> {
    let sk = signing::HybridSigningKey::from_bytes(hybrid_sk_bytes)
        .map_err(|e| format!("Failed to decode signing key: {e}"))?;
    let sig = signing::sign(&sk, new_hybrid_vk)
        .map_err(|e| format!("Failed to sign new device vk: {e}"))?;
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
        return Err(format!("Decrypted capsule too short: {} bytes", plaintext.len()));
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

pub fn derive_cyclo_keys(rms: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let pk_context = format!("{} pk", CYCLO_KEY_CONTEXT);
    let sk_context = format!("{} sk", CYCLO_KEY_CONTEXT);
    let pk_seed = kdf::derive(&pk_context, rms);
    let sk_seed = kdf::derive(&sk_context, rms);

    // cyclo_pk: 128 u64 values in [0, CYCLO_Q) expanded from the KDF seed.
    let mut cyclo_pk = Vec::with_capacity(CYCLO_PK_LEN);
    for i in 0u64..128 {
        let mut h = Sha256::new();
        h.update(pk_seed.as_bytes());
        h.update(&i.to_le_bytes());
        let hash = h.finalize();
        let v = u64::from_le_bytes(hash[..8].try_into().unwrap()) % CYCLO_Q;
        cyclo_pk.extend_from_slice(&v.to_le_bytes());
    }

    // cyclo_sk: 128 u64 values in [0, B_SIS) expanded from the KDF seed.
    // Each coefficient is masked to 20 bits so |coeff| ≤ B_SIS = 2^20,
    // satisfying the PRESET_128 witness norm bound.
    let mut cyclo_sk = Vec::with_capacity(CYCLO_PK_LEN);
    for i in 0u64..128 {
        let mut h = Sha256::new();
        h.update(sk_seed.as_bytes());
        h.update(&i.to_le_bytes());
        let hash = h.finalize();
        let coeff = (u32::from_le_bytes(hash[..4].try_into().unwrap()) & 0xFFFFF) as u64;
        cyclo_sk.extend_from_slice(&coeff.to_le_bytes());
    }

    (cyclo_pk, cyclo_sk)
}

const CYCLO_Q: u64 = 1125899906839937;

/// Generate a Cyclo ZK proof for authentication and return
/// `(proof_base64, committed_hash_hex)`.
///
/// Public inputs  (132 u64s): cyclo_pk (128 u64s LE) ‖ SHA256(challenge ‖ device_id) (4 u64s LE)
/// Private inputs (128 u64s): cyclo_sk (short witness, each coefficient < B_SIS)
pub fn create_auth_proof(
    cyclo_pk: &[u8],
    cyclo_sk: &[u8],
    challenge: &[u8],
    device_id: &str,
) -> Result<(String, String), String> {
    if cyclo_pk.len() != CYCLO_PK_LEN {
        return Err(format!("cyclo_pk must be {} bytes, got {}", CYCLO_PK_LEN, cyclo_pk.len()));
    }
    if cyclo_sk.len() != CYCLO_PK_LEN {
        return Err(format!("cyclo_sk must be {} bytes, got {}", CYCLO_PK_LEN, cyclo_sk.len()));
    }

    // committed_hash = SHA256(challenge || device_id) — binds proof to this session.
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(device_id.as_bytes());
    let committed_hash_bytes: [u8; 32] = hasher.finalize().into();
    let committed_hash_hex = hex::encode(committed_hash_bytes);

    // Public inputs: cyclo_pk (128 u64s LE) || committed_hash (4 u64s LE) = 132 u64s.
    let mut public_inputs: Vec<u64> = Vec::with_capacity(132);
    for chunk in cyclo_pk.chunks_exact(8) {
        public_inputs.push(u64::from_le_bytes(chunk.try_into().unwrap()));
    }
    for chunk in committed_hash_bytes.chunks_exact(8) {
        public_inputs.push(u64::from_le_bytes(chunk.try_into().unwrap()));
    }

    // Private inputs: cyclo_sk (128 u64s LE, short witness).
    let private_inputs: Vec<u64> = cyclo_sk
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();

    let proof = cyclo::prove(&public_inputs, &private_inputs)
        .map_err(|e| format!("Cyclo prove failed: {}", e))?;

    Ok((B64.encode(proof.as_bytes()), committed_hash_hex))
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
