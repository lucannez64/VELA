//! One-off "share link" payloads.
//!
//! A link share goes to someone with no VELA identity, so there is no KEM
//! public key to seal to. Instead the sender generates a random 256-bit *link
//! key*, encrypts the secret with it, and puts the key in the URL fragment
//! (`…/send.html?id=<id>#<key>`). Browsers never put the fragment on the wire,
//! so the server stores and serves only ciphertext it cannot open.
//!
//! An optional passphrase is folded in: the recipient must present both the
//! fragment key and the passphrase to reconstruct the AEAD key. The passphrase
//! is stretched with Argon2id over a per-link salt the server stores; the
//! derived material never leaves the clients.

use crate::aead;
use crate::error::Result;
use crate::kdf::{self, DerivedKey};
use crate::password_kdf;
use zeroize::Zeroizing;

/// Length of the random link key placed in the URL fragment.
pub const LINK_KEY_LEN: usize = 32;
/// Length of the Argon2id salt stored alongside the ciphertext when a
/// passphrase is used.
pub const LINK_SALT_LEN: usize = 16;

const NO_PASSPHRASE_CONTEXT: &str = "vela link key v1";
const PASSPHRASE_CONTEXT: &str = "vela link passphrase v1";
/// Domain separator for the AEAD. Binds every link ciphertext to this use so a
/// blob can never be opened through an unrelated code path.
const LINK_AAD: &[u8] = b"vela link payload v1";

/// Generate a fresh random link key.
pub fn generate_link_key() -> [u8; LINK_KEY_LEN] {
    let mut key = [0u8; LINK_KEY_LEN];
    getrandom::getrandom(&mut key).expect("OS random source unavailable");
    key
}

/// Generate a fresh random Argon2id salt.
pub fn generate_salt() -> [u8; LINK_SALT_LEN] {
    let mut salt = [0u8; LINK_SALT_LEN];
    getrandom::getrandom(&mut salt).expect("OS random source unavailable");
    salt
}

/// Combine the fragment key with an optional passphrase into the AEAD key.
///
/// Without a passphrase the fragment key is the whole secret. With one, the
/// passphrase is stretched with Argon2id and mixed in, so neither half opens
/// the link alone.
fn derive_link_key(
    link_key: &[u8; LINK_KEY_LEN],
    passphrase: Option<&[u8]>,
    salt: &[u8],
) -> Result<DerivedKey> {
    match passphrase {
        Some(passphrase) if !passphrase.is_empty() => {
            let pass = password_kdf::derive_argon2id(passphrase, salt)?;
            let mut material = Zeroizing::new(Vec::with_capacity(LINK_KEY_LEN + 32));
            material.extend_from_slice(link_key);
            material.extend_from_slice(pass.as_bytes());
            Ok(kdf::derive(PASSPHRASE_CONTEXT, &material))
        }
        _ => Ok(kdf::derive(NO_PASSPHRASE_CONTEXT, link_key)),
    }
}

/// Seal `plaintext` for a link. `salt` is ignored when `passphrase` is `None`.
pub fn seal_link(
    link_key: &[u8; LINK_KEY_LEN],
    passphrase: Option<&[u8]>,
    salt: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = derive_link_key(link_key, passphrase, salt)?;
    aead::seal(key.as_bytes(), plaintext, LINK_AAD)
}

/// Open a link payload. Fails if the key, the passphrase, or either is wrong.
pub fn open_link(
    link_key: &[u8; LINK_KEY_LEN],
    passphrase: Option<&[u8]>,
    salt: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = derive_link_key(link_key, passphrase, salt)?;
    aead::open(key.as_bytes(), blob, LINK_AAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_without_passphrase() {
        let key = generate_link_key();
        let salt = generate_salt();
        let blob = seal_link(&key, None, &salt, b"hunter2").unwrap();
        let opened = open_link(&key, None, &salt, &blob).unwrap();
        assert_eq!(opened.as_slice(), b"hunter2");
    }

    #[test]
    fn roundtrip_with_passphrase() {
        let key = generate_link_key();
        let salt = generate_salt();
        let blob = seal_link(&key, Some(b"correct horse"), &salt, b"s3cret").unwrap();
        let opened = open_link(&key, Some(b"correct horse"), &salt, &blob).unwrap();
        assert_eq!(opened.as_slice(), b"s3cret");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let key = generate_link_key();
        let salt = generate_salt();
        let blob = seal_link(&key, Some(b"right"), &salt, b"s3cret").unwrap();
        assert!(open_link(&key, Some(b"wrong"), &salt, &blob).is_err());
    }

    #[test]
    fn passphrase_link_needs_the_passphrase() {
        let key = generate_link_key();
        let salt = generate_salt();
        let blob = seal_link(&key, Some(b"right"), &salt, b"s3cret").unwrap();
        // The fragment key alone must not open a passphrase-protected link.
        assert!(open_link(&key, None, &salt, &blob).is_err());
    }

    #[test]
    fn wrong_link_key_fails() {
        let key = generate_link_key();
        let salt = generate_salt();
        let blob = seal_link(&key, None, &salt, b"s3cret").unwrap();
        let other = generate_link_key();
        assert!(open_link(&other, None, &salt, &blob).is_err());
    }

    #[test]
    fn a_tampered_blob_fails() {
        let key = generate_link_key();
        let salt = generate_salt();
        let mut blob = seal_link(&key, None, &salt, b"s3cret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(open_link(&key, None, &salt, &blob).is_err());
    }

    #[test]
    fn fresh_salt_changes_the_derived_key() {
        let key = generate_link_key();
        let sealed_a = seal_link(&key, Some(b"pw"), &[1u8; LINK_SALT_LEN], b"x").unwrap();
        let sealed_b = seal_link(&key, Some(b"pw"), &[2u8; LINK_SALT_LEN], b"x").unwrap();
        // Different salt ⇒ different AEAD key; the other salt cannot open it.
        assert!(open_link(&key, Some(b"pw"), &[2u8; LINK_SALT_LEN], &sealed_a).is_err());
        assert!(open_link(&key, Some(b"pw"), &[1u8; LINK_SALT_LEN], &sealed_b).is_err());
    }
}
