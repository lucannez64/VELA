//! XChaCha20-Poly1305 AEAD for vault chunk encryption.
//!
//! All vault blobs are encrypted with a fresh random 192-bit nonce prepended
//! to the ciphertext so that the nonce travels with the ciphertext.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Result, VelaError};

/// Overhead added per ciphertext: 24-byte nonce + 16-byte Poly1305 tag.
pub const OVERHEAD: usize = 24 + 16;

/// Encrypt `plaintext` under `key` (32 bytes).
///
/// Returns `nonce || ciphertext || tag` (nonce prepended for easy storage).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| VelaError::AeadError)?;

    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt`].
///
/// Expects `nonce || ciphertext || tag` as produced by `encrypt`.
pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < OVERHEAD {
        return Err(VelaError::AeadError);
    }

    let (nonce_slice, ct) = blob.split_at(24);
    let mut nonce_arr = [0u8; 24];
    nonce_arr.copy_from_slice(nonce_slice);
    let nonce = XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new(key.into());

    let plaintext = cipher
        .decrypt(&nonce, ct)
        .map_err(|_| VelaError::AeadError)?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypt using a [`crate::kdf::DerivedKey`] reference.
pub fn encrypt_with_derived(key: &crate::kdf::DerivedKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt(key.as_bytes(), plaintext)
}

/// Decrypt using a [`crate::kdf::DerivedKey`] reference.
pub fn decrypt_with_derived(
    key: &crate::kdf::DerivedKey,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt(key.as_bytes(), blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8; 32] = b"an example very very secret key!";

    #[test]
    fn roundtrip() {
        let plaintext = b"hello, vault!";
        let blob = encrypt(KEY, plaintext).unwrap();
        let recovered = decrypt(KEY, &blob).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn nonce_is_random_each_time() {
        let ct1 = encrypt(KEY, b"same plaintext").unwrap();
        let ct2 = encrypt(KEY, b"same plaintext").unwrap();
        assert_ne!(ct1, ct2, "nonce must differ between encryptions");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = encrypt(KEY, b"data").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(decrypt(KEY, &blob).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = encrypt(KEY, b"data").unwrap();
        let bad_key = b"a different very very secret key";
        assert!(decrypt(bad_key, &blob).is_err());
    }

    #[test]
    fn blob_too_short_returns_error() {
        assert!(decrypt(KEY, &[0u8; 10]).is_err());
    }
}
