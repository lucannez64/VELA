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
    /// The private half of `hybrid_ek`. Enrollment v3 seals the RMS capsule to
    /// `hybrid_ek`, so this is what opens it (audit P-1); before v3 nothing
    /// encapsulated under that key and it was discarded at generation.
    pub hybrid_dk: Vec<u8>,
    pub hybrid_vk: Vec<u8>,
    pub hybrid_sk: Vec<u8>,
    pub share_ek: Vec<u8>,
    pub share_dk: Vec<u8>,
}

pub fn generate_identity_keypair() -> Result<IdentityKeypair, String> {
    // `hybrid_ek` must be a real KEM public key, not filler bytes: it is
    // signed (via sign_enrollment) and transmitted to the server as part of
    // this device's identity, so storing/attesting to random noise here
    // means the signed enrollment payload contains fake key material.
    //
    // The matching secret used to be discarded, because nothing encapsulated
    // under `hybrid_ek` — v2 sealed the RMS capsule under a symmetric
    // transfer_key instead. Enrollment v3 is the capability that comment
    // anticipated: the capsule is now KEM-sealed to `hybrid_ek`, so a device
    // that threw this key away would enrol and then find its own capsule
    // unopenable (audit P-1).
    let (hybrid_ek_pk, hybrid_ek_sk) = kem::generate_keypair();
    let hybrid_ek = hybrid_ek_pk.to_bytes();
    let hybrid_dk = hybrid_ek_sk.to_bytes();

    let (signing_vk, signing_sk) = signing::generate_keypair()
        .map_err(|e| format!("Failed to generate signing keypair: {}", e))?;
    let hybrid_vk = signing_vk.to_bytes().to_vec();
    let hybrid_sk = signing_sk.into_bytes();

    let (share_pk, share_sk) = kem::generate_keypair();

    Ok(IdentityKeypair {
        hybrid_ek,
        hybrid_dk,
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

/// Sign the grant id, to collect the outcome of this device's own enrollment.
///
/// The joining device has no session yet — the `device_id` it is asking for is
/// what a session would need — so this signature stands in for one. It proves
/// possession of the private half of the key that claimed the grant, which
/// someone who merely photographed the enrollment code does not have.
pub fn sign_enrollment_result(hybrid_sk_bytes: &[u8], grant_id: &str) -> Result<String, String> {
    let sk = signing::HybridSigningKey::from_bytes(hybrid_sk_bytes)
        .map_err(|e| format!("Failed to decode signing key: {e}"))?;
    let message = signing::enrollment_result_message(grant_id);
    let signature =
        signing::sign(&sk, &message).map_err(|e| format!("Failed to sign grant id: {e}"))?;
    Ok(B64.encode(signature.to_bytes()))
}

/// AEAD-encrypt `rms` using `transfer_key`.  The resulting capsule is stored
/// on the server and downloaded by the new device after authentication.
pub fn create_rms_capsule(transfer_key: &[u8; 32], rms: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    Ok(vela_crypto::aead::encrypt(transfer_key, rms)?)
}

/// Seal the RMS to a joining device's public KEM key (enrollment v3).
///
/// v2 sealed it under a symmetric `transfer_key` that travelled inside the
/// enrollment code, so reading the code was enough to open the capsule. Here it
/// is KEM-sealed to a key whose private half never left the joining device, so
/// the capsule is worthless to anyone else even if they intercept both the code
/// and the capsule (audit P-1).
pub fn seal_rms_to_device(hybrid_ek_bytes: &[u8], rms: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let pk = kem::HybridPublicKey::from_bytes(hybrid_ek_bytes)?;
    Ok(kem::seal_share(&pk, rms)?)
}

/// Open a capsule sealed by [`seal_rms_to_device`], using this device's own
/// KEM secret key.
///
/// The argument is `hybrid_dk` — the private half of the device's `hybrid_ek` —
/// and not `hybrid_sk`, which is the *signing* key. The two are different
/// keypairs of similar-looking names, and passing the wrong one fails at decode
/// rather than silently, which is the reason this is spelled out.
pub fn open_rms_from_capsule(hybrid_dk_bytes: &[u8], capsule: &[u8]) -> Result<[u8; 32], String> {
    let sk = kem::HybridSecretKey::from_bytes(hybrid_dk_bytes)
        .map_err(|e| format!("invalid device key: {e}"))?;
    let plaintext = kem::open_share(&sk, capsule).map_err(|e| format!("capsule did not open: {e}"))?;
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| "capsule did not contain a 32-byte root seed".to_string())?;
    Ok(bytes)
}

const REKEY_CAPSULE_V1_MAGIC: &[u8] = b"vela rekey capsule v1\0";
const REKEY_CAPSULE_BINDING_CONTEXT: &str = "vela rekey capsule binding v1";

/// Seal a versioned RMS-rotation payload to a device.
///
/// Unlike an enrollment capsule, a re-key capsule is retained and delivered by
/// an untrusted sync server. The epoch and attempt id therefore live inside a
/// previous-RMS-authenticated payload, which is then KEM-sealed to its device,
/// so the server cannot forge, replay, or relabel a root transition.
pub fn seal_rekey_capsule(
    hybrid_ek_bytes: &[u8],
    previous_rms: &[u8; 32],
    rms: &[u8; 32],
    epoch: i64,
    rotation_id: &str,
) -> anyhow::Result<Vec<u8>> {
    vela_crypto::rekey::seal_rekey_capsule(hybrid_ek_bytes, previous_rms, rms, epoch, rotation_id)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Open and validate a versioned RMS-rotation capsule.
///
/// Both comparisons happen before the RMS is returned, making it impossible
/// for an adoption caller to forget the authenticated inner metadata check.
pub fn open_rekey_capsule(
    hybrid_dk_bytes: &[u8],
    capsule: &[u8],
    previous_rms: &[u8; 32],
    expected_epoch: i64,
    expected_rotation_id: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    vela_crypto::rekey::open_rekey_capsule(
        hybrid_dk_bytes, capsule, previous_rms,
        expected_epoch, expected_rotation_id,
    )
    .map_err(|e| e.to_string())
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
/// Sign a share-key binding (M19): authorizes registering `share_ek` at
/// `signed_at` under this device's hybrid identity key.
///
/// IMPORTANT: `signed_at` must be produced by [`canonical_binding_timestamp`].
/// The server rejects anything but second-precision canonical UTC
/// (`YYYY-MM-DDTHH:MM:SSZ`, 20 chars) — a timestamp with fractional seconds
/// or an offset suffix fails verification on the server, because the
/// signature covers this exact string.
pub fn sign_share_ek_binding(
    hybrid_sk: &[u8],
    share_ek: &[u8],
    signed_at: &str,
) -> Result<String, String> {
    let sk = signing::HybridSigningKey::from_bytes(hybrid_sk)
        .map_err(|e| format!("Failed to decode signing key: {e}"))?;
    let message = signing::share_ek_binding_message(share_ek, signed_at);
    let signature = signing::sign(&sk, &message)
        .map_err(|e| format!("Failed to sign share-key binding: {e}"))?;
    Ok(B64.encode(signature.to_bytes()))
}

/// Canonical M19 share-key binding timestamp: second-precision UTC
/// (`YYYY-MM-DDTHH:MM:SSZ`, exactly 20 chars). Every client MUST mint the
/// binding timestamp through this function — `Utc::now().to_rfc3339()` alone
/// emits fractional seconds and an offset suffix that the server rejects.
pub fn canonical_binding_timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod timestamp_tests {
    #[test]
    fn binding_timestamp_is_server_canonical() {
        let t = super::canonical_binding_timestamp();
        assert_eq!(t.len(), 20, "must be exactly YYYY-MM-DDTHH:MM:SSZ: {t}");
        assert!(t.ends_with('Z'), "must be UTC-Z form: {t}");
        // RFC3339-parseable with seconds precision (no fraction accepted).
        let parsed =
            chrono::DateTime::parse_from_rfc3339(&t).expect("must be valid RFC 3339");
        assert_eq!(parsed.timestamp_subsec_nanos(), 0);
        // Re-formatting must round-trip byte-for-byte.
        assert_eq!(
            parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            t,
            "timestamp must already be in canonical form"
        );
    }
}

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

    /// Raw AEAD access for `Store::rekey_secret_files`: the identity-keys file
    /// is sealed under its own derivation off the identity key, not under the
    /// vault key, so re-keying it needs the key handed in rather than derived
    /// from the seed the way every other file's is.
    pub(crate) fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(encrypt(key, plaintext)?)
    }

    pub(crate) fn decrypt_with_key(key: &[u8; 32], ct: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        Ok(decrypt(key, ct)?)
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
mod v3_capsule_tests {
    use super::*;

    /// The capsule is worth nothing without the joining device's private key —
    /// which is the entire difference from v2, where the key to open it
    /// travelled inside the enrollment code (audit P-1).
    #[test]
    fn a_capsule_opens_only_with_the_device_that_was_sealed_to() {
        let (ek, sk) = generate_share_keypair();
        let (other_ek, other_sk) = generate_share_keypair();
        assert_ne!(ek, other_ek);

        let rms = [42u8; 32];
        let capsule = seal_rms_to_device(&ek, &rms).unwrap();

        assert_eq!(open_rms_from_capsule(&sk, &capsule).unwrap(), rms);
        assert!(
            open_rms_from_capsule(&other_sk, &capsule).is_err(),
            "another device's key must not open it"
        );
    }

    #[test]
    fn a_tampered_capsule_does_not_open() {
        let (ek, sk) = generate_share_keypair();
        let mut capsule = seal_rms_to_device(&ek, &[7u8; 32]).unwrap();
        let last = capsule.len() - 1;
        capsule[last] ^= 1;
        assert!(open_rms_from_capsule(&sk, &capsule).is_err());
    }

    #[test]
    fn rekey_capsules_bind_rms_epoch_and_rotation_attempt() {
        let (ek, sk) = generate_share_keypair();
        let rms = [19u8; 32];
        let previous_rms = [18u8; 32];
        let capsule =
            seal_rekey_capsule(&ek, &previous_rms, &rms, 3, "rotation-current").unwrap();

        assert_eq!(
            open_rekey_capsule(&sk, &capsule, &previous_rms, 3, "rotation-current")
                .unwrap()
                .as_ref(),
            &rms
        );
        assert!(
            open_rekey_capsule(&sk, &capsule, &previous_rms, 3, "rotation-other").is_err()
        );
        assert!(
            open_rekey_capsule(&sk, &capsule, &[17u8; 32], 3, "rotation-current").is_err(),
            "the relay cannot construct a transition without the current RMS"
        );
    }

    #[test]
    fn stale_rekey_capsule_cannot_be_relabelled_with_current_epoch() {
        let (ek, sk) = generate_share_keypair();
        let previous_rms = [18u8; 32];
        let retired_rms = [20u8; 32];
        let stale =
            seal_rekey_capsule(&ek, &previous_rms, &retired_rms, 2, "rotation-old").unwrap();

        let error = open_rekey_capsule(&sk, &stale, &previous_rms, 3, "rotation-current")
            .expect_err("outer current-epoch metadata must not authorize a stale capsule");
        assert!(error.contains("inner epoch"), "{error}");

        // A second attempt can target the same epoch after an abort. Binding
        // the attempt id prevents that abandoned RMS from being adopted too.
        let abandoned = seal_rekey_capsule(
            &ek,
            &previous_rms,
            &retired_rms,
            3,
            "rotation-aborted",
        )
        .unwrap();
        assert!(
            open_rekey_capsule(&sk, &abandoned, &previous_rms, 3, "rotation-current")
                .is_err()
        );

        // Historical enrollment capsules contain only the RMS and are never a
        // valid substitute for the versioned re-key format.
        let legacy = seal_rms_to_device(&ek, &retired_rms).unwrap();
        assert!(
            open_rekey_capsule(&sk, &legacy, &previous_rms, 3, "rotation-current").is_err()
        );
    }
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
