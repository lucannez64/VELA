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

/// The derivation context for a chunk key.
///
/// Spelled out rather than `format!("{:?}", chunk_id)`. `Debug` is a
/// programmer-facing convenience with no stability guarantee — if its output for
/// `&[u8]` ever changed, every existing chunk key would change with it and every
/// vault on disk would stop opening. This produces the identical bytes
/// (`… || [118, 97, …]`), so nothing is re-keyed; it just stops the derivation
/// depending on a contract nobody promised (audit crypto M4).
fn chunk_key_context(chunk_id: &[u8]) -> String {
    let mut context = String::with_capacity(contexts::CHUNK_KEY.len() + 6 + chunk_id.len() * 5);
    context.push_str(contexts::CHUNK_KEY);
    context.push_str(" || [");
    for (index, byte) in chunk_id.iter().enumerate() {
        if index > 0 {
            context.push_str(", ");
        }
        context.push_str(itoa(*byte).as_str());
    }
    context.push(']');
    context
}

/// `u8` → decimal, without pulling in a formatting machinery whose output could
/// itself drift.
fn itoa(value: u8) -> String {
    let mut out = String::with_capacity(3);
    if value >= 100 {
        out.push((b'0' + value / 100) as char);
    }
    if value >= 10 {
        out.push((b'0' + (value / 10) % 10) as char);
    }
    out.push((b'0' + value % 10) as char);
    out
}

/// Derive a per-chunk encryption key from the RMS.
///
/// Uses context "vela chunk key v1" with the chunk ID appended for domain separation.
pub fn chunk_key(rms: &[u8], chunk_id: &[u8]) -> DerivedKey {
    derive(&chunk_key_context(chunk_id), rms)
}

/// How many `vault-data-NNNNNN` chunks a read-write web session is handed keys
/// for. ~1 MiB of vault JSON each, so 32 covers any realistic vault while
/// bounding both the capsule size and what a leaked capsule can ever decrypt.
pub const WEB_SESSION_DATA_CHUNKS: u32 = 32;

/// The chunk ids a read-write web session is granted keys for: the two legacy
/// single-chunk ids other clients may still have written, plus the first
/// [`WEB_SESSION_DATA_CHUNKS`] data chunks.
pub fn web_session_chunk_ids() -> Vec<String> {
    let mut ids = vec!["vault-main".to_string(), "vault".to_string()];
    ids.extend((0..WEB_SESSION_DATA_CHUNKS).map(|i| format!("vault-data-{i:06}")));
    ids
}

/// Per-chunk vault keys for a read-write web session, as `(chunk_id, key)`.
///
/// The browser gets these instead of the RMS (audit D-2). It can read and rewrite
/// the vault for the session's lifetime, but never holds the root of the key
/// hierarchy — no identity, share, audit, MAC, ORAM or recovery key can be
/// derived from what it received, and nothing outside these chunk ids.
pub fn web_session_chunk_keys(rms: &[u8]) -> Vec<(String, DerivedKey)> {
    web_session_chunk_ids()
        .into_iter()
        .map(|id| {
            let key = chunk_key(rms, id.as_bytes());
            (id, key)
        })
        .collect()
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

    /// The context must be byte-identical to what `{:?}` produced, or every
    /// vault already on disk stops opening. Compared against the exact
    /// expression that was replaced — so if `Debug` for `&[u8]` ever changes,
    /// this fails loudly instead of silently re-keying someone's vault.
    #[test]
    fn chunk_key_context_is_byte_identical_to_the_debug_format() {
        let cases: [&[u8]; 7] = [
            b"",
            b"vault",
            b"vault-main",
            b"vault-data-000000",
            b"vault-data-999999",
            &[0, 1, 9, 10, 99, 100, 255],
            "chunk-é-\u{1F512}".as_bytes(),
        ];
        for chunk_id in cases {
            let expected = format!("{} || {:?}", contexts::CHUNK_KEY, chunk_id);
            assert_eq!(chunk_key_context(chunk_id), expected, "context for {chunk_id:?}");
            assert_eq!(
                chunk_key(FAKE_RMS, chunk_id).0,
                derive(&expected, FAKE_RMS).0,
                "derived key for {chunk_id:?}"
            );
        }
    }

    #[test]
    fn web_session_chunk_keys_match_the_per_chunk_derivation() {
        let ids = web_session_chunk_ids();
        assert_eq!(ids.len() as u32, WEB_SESSION_DATA_CHUNKS + 2);
        assert_eq!(ids[0], "vault-main");
        assert_eq!(ids[2], "vault-data-000000"); // zero-padded to 6 digits

        // Each granted key must be exactly the key that client writes chunks
        // with, or the browser cannot read what the apps wrote.
        for (id, key) in web_session_chunk_keys(FAKE_RMS) {
            assert_eq!(key.0, chunk_key(FAKE_RMS, id.as_bytes()).0);
        }
    }

    #[test]
    fn web_session_keys_reveal_nothing_about_the_other_derivations() {
        let granted: Vec<[u8; 32]> = web_session_chunk_keys(FAKE_RMS)
            .into_iter()
            .map(|(_, k)| k.0)
            .collect();
        for other in [
            vault_encryption_key(FAKE_RMS).0,
            audit_log_key(FAKE_RMS).0,
            mac_key(FAKE_RMS).0,
            share_encryption_key(FAKE_RMS).0,
            oram_position_map_key(FAKE_RMS).0,
            identity_signing_key_seed(FAKE_RMS).0,
            device_identity_key_seed(FAKE_RMS).0,
            chunk_key(FAKE_RMS, b"vault-data-000032").0, // outside the window
        ] {
            assert!(!granted.contains(&other));
        }
    }
}
