//! Password-based key derivation (Argon2id) and versioned password-sealed blobs.
//!
//! Master passwords must never go through a fast hash: the sealed RMS blob
//! (`rms_software.enc` / OS-credential blobs) is an offline brute-force target,
//! so all new blobs use Argon2id with a per-blob random salt.
//!
//! Blob format (versioned, self-describing):
//!
//! ```text
//! v3: "VRMS" ‖ 3 ‖ m_cost:u32 ‖ t_cost:u32 ‖ p_cost:u32 ‖ salt (16B) ‖ ciphertext
//! v2: "VRMS" ‖ 2 ‖ salt (16B) ‖ ciphertext          (parameters were implicit)
//! ```
//!
//! v3 records the Argon2id parameters it was sealed with. v2 did not, so the
//! cost could never be raised without a flag day: every existing blob had to be
//! read with exactly the compiled-in numbers. Recording them means old blobs
//! keep opening with the cost they were written at while new ones use the
//! current default, and [`needs_reseal`] tells the caller when to upgrade one.
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
/// Blob version: Argon2id KDF with implicit (compiled-in) parameters.
pub const BLOB_VERSION_ARGON2ID: u8 = 2;
/// Blob version: Argon2id KDF with the parameters recorded in the blob.
pub const BLOB_VERSION_ARGON2ID_PARAMS: u8 = 3;
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Cost {
    /// What new blobs are sealed with.
    ///
    /// The previous 19 MiB / t=2 / p=1 is OWASP's *floor* for interactive
    /// authentication, and this blob is an offline brute-force target: it sits
    /// on disk and opening it is the whole attack. 64 MiB / t=3 raises the cost
    /// per guess by roughly an order of magnitude for well under a second of
    /// unlock latency on hardware from the last decade.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// What v2 blobs were sealed with, before the parameters were recorded.
    pub const V2_IMPLICIT: Self = Self {
        m_cost_kib: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    /// Reject absurd parameters read out of a blob.
    ///
    /// The blob is not authenticated before the KDF runs — that is the point of
    /// the KDF — so anything able to rewrite it on disk could otherwise ask for
    /// a 4 GiB allocation and turn unlock into an out-of-memory kill.
    fn validated(self) -> Result<Self> {
        const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
        const MAX_T_COST: u32 = 16;
        const MAX_P_COST: u32 = 16;
        if self.m_cost_kib < 8
            || self.m_cost_kib > MAX_M_COST_KIB
            || self.t_cost == 0
            || self.t_cost > MAX_T_COST
            || self.p_cost == 0
            || self.p_cost > MAX_P_COST
        {
            return Err(VelaError::KdfError(format!(
                "password blob asks for implausible Argon2id cost                  (m={} KiB, t={}, p={})",
                self.m_cost_kib, self.t_cost, self.p_cost
            )));
        }
        Ok(self)
    }
}

fn argon2id(cost: Argon2Cost) -> Result<Argon2<'static>> {
    let params = Params::new(cost.m_cost_kib, cost.t_cost, cost.p_cost, Some(32))
        .map_err(|e| VelaError::KdfError(format!("invalid Argon2id params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a 32-byte key from a password and salt using Argon2id at `cost`.
pub fn derive_argon2id_with(password: &[u8], salt: &[u8], cost: Argon2Cost) -> Result<DerivedKey> {
    let mut out = [0u8; 32];
    argon2id(cost)?
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| VelaError::KdfError(format!("Argon2id derivation failed: {e}")))?;
    Ok(DerivedKey(out))
}

/// Derive at the current default cost.
pub fn derive_argon2id(password: &[u8], salt: &[u8]) -> Result<DerivedKey> {
    derive_argon2id_with(password, salt, Argon2Cost::DEFAULT)
}

/// Returns true if `blob` uses the current versioned format.
pub fn is_current_format(blob: &[u8]) -> bool {
    blob.len() > BLOB_MAGIC.len() && &blob[..BLOB_MAGIC.len()] == BLOB_MAGIC
}

/// Seal `plaintext` under a key derived from `password` with Argon2id and a
/// fresh random salt. Returns the self-describing versioned blob.
pub fn seal_with_password(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cost = Argon2Cost::DEFAULT;
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt)
        .map_err(|e| VelaError::KdfError(format!("OS random source unavailable: {e}")))?;

    let key = derive_argon2id_with(password, &salt, cost)?;
    let ciphertext = aead::encrypt(key.as_bytes(), plaintext)?;

    let mut blob = Vec::with_capacity(BLOB_MAGIC.len() + 1 + 12 + SALT_LEN + ciphertext.len());
    blob.extend_from_slice(BLOB_MAGIC);
    blob.push(BLOB_VERSION_ARGON2ID_PARAMS);
    blob.extend_from_slice(&cost.m_cost_kib.to_le_bytes());
    blob.extend_from_slice(&cost.t_cost.to_le_bytes());
    blob.extend_from_slice(&cost.p_cost.to_le_bytes());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// True when `blob` is readable but was sealed at an older version/cost, so the
/// caller should re-seal it after a successful open.
pub fn needs_reseal(blob: &[u8]) -> bool {
    is_current_format(blob) && blob[BLOB_MAGIC.len()] == BLOB_VERSION_ARGON2ID
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
    let rest = &blob[BLOB_MAGIC.len() + 1..];

    let (cost, rest) = match version {
        BLOB_VERSION_ARGON2ID => (Argon2Cost::V2_IMPLICIT, rest),
        BLOB_VERSION_ARGON2ID_PARAMS => {
            if rest.len() < 12 {
                return Err(VelaError::KdfError("password blob too small".to_string()));
            }
            let read = |offset: usize| {
                u32::from_le_bytes(rest[offset..offset + 4].try_into().expect("4 bytes"))
            };
            let cost = Argon2Cost {
                m_cost_kib: read(0),
                t_cost: read(4),
                p_cost: read(8),
            }
            .validated()?;
            (cost, &rest[12..])
        }
        other => {
            return Err(VelaError::KdfError(format!(
                "unsupported password blob version: {other}"
            )))
        }
    };

    if rest.len() < SALT_LEN + 1 {
        return Err(VelaError::KdfError("password blob too small".to_string()));
    }
    let salt = &rest[..SALT_LEN];
    let ciphertext = &rest[SALT_LEN..];

    let key = derive_argon2id_with(password, salt, cost)?;
    Ok(aead::decrypt(key.as_bytes(), ciphertext)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob written before the parameters were recorded must keep opening —
    /// it is the only copy of someone's vault key.
    #[test]
    fn v2_blobs_still_open_at_their_original_cost() {
        // Rebuild a v2 blob exactly as the previous version wrote it.
        let salt = [9u8; SALT_LEN];
        let key = derive_argon2id_with(b"pw", &salt, Argon2Cost::V2_IMPLICIT).unwrap();
        let ciphertext = aead::encrypt(key.as_bytes(), b"the rms").unwrap();
        let mut v2 = Vec::new();
        v2.extend_from_slice(BLOB_MAGIC);
        v2.push(BLOB_VERSION_ARGON2ID);
        v2.extend_from_slice(&salt);
        v2.extend_from_slice(&ciphertext);

        assert_eq!(open_with_password(b"pw", &v2).unwrap(), b"the rms");
        assert!(needs_reseal(&v2), "and the caller is told to upgrade it");
        assert!(open_with_password(b"wrong", &v2).is_err());
    }

    #[test]
    fn v3_records_the_cost_it_was_sealed_with() {
        let blob = seal_with_password(b"pw", b"the rms").unwrap();
        assert_eq!(blob[BLOB_MAGIC.len()], BLOB_VERSION_ARGON2ID_PARAMS);
        assert!(!needs_reseal(&blob));

        let read = |offset: usize| {
            let start = BLOB_MAGIC.len() + 1 + offset;
            u32::from_le_bytes(blob[start..start + 4].try_into().unwrap())
        };
        assert_eq!(read(0), Argon2Cost::DEFAULT.m_cost_kib);
        assert_eq!(read(4), Argon2Cost::DEFAULT.t_cost);
        assert_eq!(read(8), Argon2Cost::DEFAULT.p_cost);

        // Raising the default later must not orphan this blob: it opens at the
        // cost recorded inside it, whatever the current default becomes.
        assert_eq!(open_with_password(b"pw", &blob).unwrap(), b"the rms");
    }

    /// The blob is not authenticated before the KDF runs, so a rewritten cost
    /// field must not be able to turn unlock into an out-of-memory kill.
    #[test]
    fn implausible_recorded_cost_is_refused() {
        let mut blob = seal_with_password(b"pw", b"the rms").unwrap();
        let m_cost_at = BLOB_MAGIC.len() + 1;
        blob[m_cost_at..m_cost_at + 4].copy_from_slice(&(4u32 * 1024 * 1024).to_le_bytes());

        let error = open_with_password(b"pw", &blob).expect_err("must refuse");
        assert!(format!("{error}").contains("implausible"), "{error}");
    }

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
