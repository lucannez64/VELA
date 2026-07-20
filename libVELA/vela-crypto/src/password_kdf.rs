//! Password-based key derivation (Argon2id) and versioned password-sealed blobs.
//!
//! Master passwords must never go through a fast hash: the sealed RMS blob
//! (`rms_software.enc` / OS-credential blobs) is an offline brute-force target,
//! so all new blobs use Argon2id with a per-blob random salt.
//!
//! Blob format (versioned, self-describing):
//!
//! ```text
//! "VRMS" (4B magic) ‖ version (1B) ‖ salt (16B) ‖ XChaCha20-Poly1305 ciphertext
//! ```
//!
//! Legacy blobs (plain BLAKE3 KDF, with or without a used salt) have no magic
//! header and are detected by the caller, which must re-seal them with
//! [`seal_with_password`] after a successful legacy open (lazy migration).

use crate::aead;
use crate::error::{Result, VelaError};
use crate::kdf::DerivedKey;
use argon2::{Algorithm, Argon2, Params, Version};

/// Magic prefix identifying the current (versioned) blob format.
pub const BLOB_MAGIC: &[u8; 4] = b"VRMS";
/// Blob version: Argon2id KDF.
pub const BLOB_VERSION_ARGON2ID: u8 = 2;
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

// OWASP-recommended Argon2id parameters for interactive authentication:
// 19 MiB memory, 2 iterations, 1 lane.
const ARGON2_M_COST_KIB: u32 = 19 * 1024;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

fn argon2id() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(32),
    )
    .map_err(|e| VelaError::KdfError(format!("invalid Argon2id params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a 32-byte key from a password and salt using Argon2id.
pub fn derive_argon2id(password: &[u8], salt: &[u8]) -> Result<DerivedKey> {
    let mut out = [0u8; 32];
    argon2id()?
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| VelaError::KdfError(format!("Argon2id derivation failed: {e}")))?;
    Ok(DerivedKey(out))
}

/// Returns true if `blob` uses the current versioned format.
pub fn is_current_format(blob: &[u8]) -> bool {
    blob.len() > BLOB_MAGIC.len() && &blob[..BLOB_MAGIC.len()] == BLOB_MAGIC
}

/// Seal `plaintext` under a key derived from `password` with Argon2id and a
/// fresh random salt. Returns the self-describing versioned blob.
pub fn seal_with_password(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt)
        .map_err(|e| VelaError::KdfError(format!("OS random source unavailable: {e}")))?;

    let key = derive_argon2id(password, &salt)?;
    let ciphertext = aead::encrypt(key.as_bytes(), plaintext)?;

    let mut blob = Vec::with_capacity(BLOB_MAGIC.len() + 1 + SALT_LEN + ciphertext.len());
    blob.extend_from_slice(BLOB_MAGIC);
    blob.push(BLOB_VERSION_ARGON2ID);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Open a blob produced by [`seal_with_password`]. Rejects any other format —
/// callers handle legacy formats separately and then migrate.
pub fn open_with_password(password: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if !is_current_format(blob) {
        return Err(VelaError::KdfError(
            "not a versioned password blob".to_string(),
        ));
    }
    let version = blob[BLOB_MAGIC.len()];
    if version != BLOB_VERSION_ARGON2ID {
        return Err(VelaError::KdfError(format!(
            "unsupported password blob version: {version}"
        )));
    }
    let rest = &blob[BLOB_MAGIC.len() + 1..];
    if rest.len() < SALT_LEN + 1 {
        return Err(VelaError::KdfError("password blob too small".to_string()));
    }
    let salt = &rest[..SALT_LEN];
    let ciphertext = &rest[SALT_LEN..];

    let key = derive_argon2id(password, salt)?;
    Ok(aead::decrypt(key.as_bytes(), ciphertext)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let blob = seal_with_password(b"correct horse", b"0123456789abcdef0123456789abcdef")
            .expect("seal");
        assert!(is_current_format(&blob));
        let opened = open_with_password(b"correct horse", &blob).expect("open");
        assert_eq!(opened, b"0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn wrong_password_fails() {
        let blob = seal_with_password(b"right", b"secret-secret-secret-secret-secre").unwrap();
        assert!(open_with_password(b"wrong", &blob).is_err());
    }

    #[test]
    fn same_password_different_salts_different_blobs() {
        let a = seal_with_password(b"pw", b"0123456789abcdef0123456789abcdef").unwrap();
        let b = seal_with_password(b"pw", b"0123456789abcdef0123456789abcdef").unwrap();
        assert_ne!(a, b, "fresh salt per seal must randomize the blob");
        assert_eq!(open_with_password(b"pw", &a).unwrap(), open_with_password(b"pw", &b).unwrap());
    }

    #[test]
    fn legacy_blob_is_not_current_format() {
        // Legacy layout: 16B salt ‖ ciphertext, no magic header.
        let mut legacy = vec![0u8; 16];
        legacy.extend_from_slice(&[7u8; 60]);
        assert!(!is_current_format(&legacy));
        assert!(open_with_password(b"pw", &legacy).is_err());
    }
}
