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

/// Magic prefix on ciphertexts sealed with associated data.
///
/// Self-describing on purpose: a reader can tell a sealed blob from a legacy
/// one without being told out of band, which is what lets old and new clients
/// coexist while the fleet upgrades.
pub const SEALED_MAGIC: &[u8; 4] = b"VAE1";

/// True when `blob` was produced by [`seal`] rather than [`encrypt`].
pub fn is_sealed(blob: &[u8]) -> bool {
    blob.len() > SEALED_MAGIC.len() && &blob[..SEALED_MAGIC.len()] == SEALED_MAGIC
}

/// Canonical associated data for a vault chunk.
///
/// Binds a ciphertext to *which* chunk it is and *which revision* — the two
/// things a storage server can otherwise swap underneath a client. Fields are
/// length-prefixed so `("ab", 1)` and `("a", 0xb1)` cannot serialize alike.
pub fn vault_chunk_aad(chunk_id: &str, lamport_clock: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + chunk_id.len() + 8);
    aad.extend_from_slice(b"vela chunk v1");
    aad.extend_from_slice(&(chunk_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(chunk_id.as_bytes());
    aad.extend_from_slice(&lamport_clock.to_le_bytes());
    aad
}

/// Open a vault chunk written in either format.
///
/// Step 2 of the C-2 rollout: every client must *read* both shapes before any
/// client starts writing the sealed one, or the first device to upgrade writes
/// chunks its owner's other devices cannot open. Sealed blobs are self-describing
/// (`VAE1`), so this needs no flag — it just tries the binding when it is there.
///
/// `lamport_clock` is the revision the server claimed for this chunk. For a
/// sealed blob it is verified: a relabelled or replayed ciphertext fails to
/// open. For a legacy blob it is unused, which is exactly the gap the rollout
/// closes.
pub fn open_vault_chunk(
    key: &[u8; 32],
    blob: &[u8],
    chunk_id: &str,
    lamport_clock: i64,
) -> Result<Zeroizing<Vec<u8>>> {
    if is_sealed(blob) {
        open(key, blob, &vault_chunk_aad(chunk_id, lamport_clock))
    } else {
        decrypt(key, blob)
    }
}

/// Encrypt with associated data bound to the ciphertext.
///
/// The AEAD tag covers `aad`, so a ciphertext that arrives labelled as a
/// different chunk — or a different revision of the same chunk — fails to open
/// instead of decrypting into something the caller then trusts (audit C-2).
/// `aad` itself is not stored: the reader reconstructs it from the labels the
/// server supplied, which is exactly what makes a mislabelled blob detectable.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VelaError::AeadError)?;

    let mut out = Vec::with_capacity(SEALED_MAGIC.len() + 24 + ciphertext.len());
    out.extend_from_slice(SEALED_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`], verifying `aad`.
pub fn open(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !is_sealed(blob) {
        return Err(VelaError::AeadError);
    }
    let rest = &blob[SEALED_MAGIC.len()..];
    if rest.len() < 24 + 16 {
        return Err(VelaError::AeadError);
    }
    let (nonce_bytes, ciphertext) = rest.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VelaError::AeadError)?;
    Ok(Zeroizing::new(plaintext))
}

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

    const AAD_KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn sealed_blobs_bind_their_associated_data() {
        let aad = vault_chunk_aad("vault-data-000003", 42);
        let sealed = seal(&AAD_KEY, b"vault contents", &aad).unwrap();

        assert!(is_sealed(&sealed));
        assert_eq!(open(&AAD_KEY, &sealed, &aad).unwrap().as_slice(), b"vault contents");

        // The two substitutions a storage server can make: same blob served as
        // a different chunk, or as a different revision of the same chunk.
        let other_chunk = vault_chunk_aad("vault-data-000004", 42);
        assert!(open(&AAD_KEY, &sealed, &other_chunk).is_err());

        let older_revision = vault_chunk_aad("vault-data-000003", 41);
        assert!(open(&AAD_KEY, &sealed, &older_revision).is_err());
    }

    #[test]
    fn aad_fields_cannot_be_confused_with_each_other() {
        // Length-prefixed, so no pair of (id, clock) inputs collides.
        assert_ne!(vault_chunk_aad("ab", 1), vault_chunk_aad("a", 0x62_00_00_00_01));
        assert_ne!(vault_chunk_aad("a", 1), vault_chunk_aad("a", 2));
        assert_eq!(vault_chunk_aad("a", 1), vault_chunk_aad("a", 1));
    }

    /// Old and new ciphertexts have to coexist while every client upgrades, so
    /// a reader must be able to tell them apart without being told.
    #[test]
    fn legacy_and_sealed_ciphertexts_are_distinguishable() {
        let legacy = encrypt(&AAD_KEY, b"vault contents").unwrap();
        let sealed = seal(&AAD_KEY, b"vault contents", &vault_chunk_aad("vault", 1)).unwrap();

        assert!(!is_sealed(&legacy));
        assert!(is_sealed(&sealed));

        // And neither opens through the other's path.
        assert!(open(&AAD_KEY, &legacy, &vault_chunk_aad("vault", 1)).is_err());
        assert!(decrypt(&AAD_KEY, &sealed).is_err());
    }

    /// Both formats have to open through one call, or the fleet cannot upgrade
    /// one client at a time.
    #[test]
    fn open_vault_chunk_reads_both_formats() {
        let legacy = encrypt(&AAD_KEY, b"old chunk").unwrap();
        let sealed = seal(
            &AAD_KEY,
            b"new chunk",
            &vault_chunk_aad("vault-data-000000", 12),
        )
        .unwrap();

        assert_eq!(
            open_vault_chunk(&AAD_KEY, &legacy, "vault-data-000000", 12)
                .unwrap()
                .as_slice(),
            b"old chunk"
        );
        assert_eq!(
            open_vault_chunk(&AAD_KEY, &sealed, "vault-data-000000", 12)
                .unwrap()
                .as_slice(),
            b"new chunk"
        );

        // A legacy blob ignores the labels — that is the gap the rollout
        // closes — but a sealed one holds the server to them.
        assert!(open_vault_chunk(&AAD_KEY, &legacy, "vault-data-000009", 1).is_ok());
        assert!(open_vault_chunk(&AAD_KEY, &sealed, "vault-data-000009", 12).is_err());
        assert!(open_vault_chunk(&AAD_KEY, &sealed, "vault-data-000000", 11).is_err());
    }

    #[test]
    fn a_tampered_sealed_blob_fails() {
        let aad = vault_chunk_aad("vault", 9);
        let mut sealed = seal(&AAD_KEY, b"vault contents", &aad).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&AAD_KEY, &sealed, &aad).is_err());

        assert!(open(&[9u8; 32], &seal(&AAD_KEY, b"x", &aad).unwrap(), &aad).is_err());
    }

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
