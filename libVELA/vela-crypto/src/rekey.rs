//! Vault re-keying — rotating the Root Master Seed (`EPHEMERAL_WEB_ACCESS_DESIGN.md`
//! §9.3, audit S-1/D-2 residual).
//!
//! Every key VELA derives comes from one 32-byte RMS via BLAKE3 domain
//! separation ([`crate::kdf`]). That is what makes rotation *possible* —
//! re-derive under a new seed and every key moves at once — and what makes it
//! *meaningful*: a leaked RMS (or any long-lived key handed to an RW web
//! session, audit D-2) stops being worth anything the moment the seed rotates,
//! because nothing encrypted under its derivations exists anymore.
//!
//! This module holds only the pure, synchronous core of the operation:
//!
//! - [`rotate`]          — mint a fresh seed;
//! - [`rekey_blob`]      — carry one context-separated blob across the rotation;
//! - [`epoch_aad`], [`seal_epoch_chunk`], [`open_epoch_chunk`] — bind chunks to
//!   the account's key epoch so a write from before a rotation can never be
//!   mistaken for one from after it (the guard rail that keeps an offline
//!   device's late push from landing in a vault nobody can decrypt);
//! - [`rekey_recovery_shares`], [`shares_reconstruct_to`] — recovery-share
//!   rotation. Old shares need no explicit invalidation mechanism: they
//!   reconstruct the OLD seed only, so they die by construction the moment the
//!   seed changes. New shares must be minted and uploaded over the old backup,
//!   which is what [`rekey_recovery_shares`] produces.
//!
//! Deliberately NOT here: orchestration. Which device runs the loop, how the
//! server freezes writes between epochs, how other devices learn the new seed
//! (KEM-sealed capsules — the enrollment-v3 path), crash resumption — those are
//! protocol concerns, specified in the re-keying design document. The crypto
//! layer exposes stateless pieces so the protocol layer has no crypto decisions
//! left to get wrong.

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::aead::{self, OVERHEAD};
use crate::error::Result;
use crate::kdf;
use crate::shamir;

/// Generate a fresh Root Master Seed.
///
/// The whole security model rests on this being 32 bytes the world has never
/// seen, straight from the OS RNG — same source [`crate::kdf`] consumers trust.
/// Returned in `Zeroizing` like everything else in this module: a raw seed
/// should never sit in an un-zeroized array just because the API made the
/// caller wrap it.
pub fn rotate() -> Result<Zeroizing<[u8; 32]>> {
    let mut rms = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(rms.as_mut());
    Ok(rms)
}

/// Re-encrypt a blob across a seed rotation.
///
/// `ciphertext` must be in the nonce-prepended format [`crate::aead::encrypt`]
/// produces (the format of `vault.enc`, `audit.enc`, `identity_keys.enc`,
/// `shares.enc`, ...), sealed under the key `kdf::derive(context, old_rms)`.
/// The result is sealed under the same context derived from `new_rms`, with a
/// fresh nonce — never reuse the old ciphertext bytes, even though the AEAD
/// would allow reusing the nonce under a different key: distinct nonces cost
/// nothing and remove a class of "same ciphertext, two epochs" confusion.
///
/// The plaintext exists only inside a `Zeroizing` buffer for the duration of
/// the call and both derived keys zeroize on drop.
pub fn rekey_blob(
    old_rms: &[u8; 32],
    new_rms: &[u8; 32],
    context: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let old_key = kdf::derive(context, old_rms);
    let plaintext = crate::aead::decrypt(old_key.as_bytes(), ciphertext)?;
    drop(old_key);

    let new_key = kdf::derive(context, new_rms);
    crate::aead::encrypt(new_key.as_bytes(), &plaintext)
}

/// Canonical associated data binding a chunk to the account's **key epoch**.
///
/// Wraps the C-2 chunk AAD (chunk id + revision) in an epoch prefix. A chunk
/// sealed here opens only under the same epoch number at read time, so:
///
/// - a ciphertext written before a rotation cannot ride through the rotation
///   disguised as current — it fails to open instead of decrypting into
///   something the caller then syncs back;
/// - the offline-device race ("my push landed after the snapshot") degrades
///   from silent corruption to a detectable, retryable mismatch.
///
/// Epochs start at 1; epoch 0 is reserved so it can never collide with a real
/// account state.
pub fn epoch_aad(epoch: u64, chunk_id: &str, lamport_clock: i64) -> Vec<u8> {
    // "vela epoch v1" (13) + epoch (8) + the inner AAD: tag (13) + chunk-id
    // length (4) + chunk_id + lamport clock (8).
    let mut aad = Vec::with_capacity(13 + 8 + 13 + 4 + chunk_id.len() + 8);
    aad.extend_from_slice(b"vela epoch v1");
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(aead::vault_chunk_aad(chunk_id, lamport_clock).as_slice());
    aad
}

/// Encrypt a vault chunk bound to its chunk id, revision **and** key epoch.
pub fn seal_epoch_chunk(
    key: &[u8; 32],
    plaintext: &[u8],
    epoch: u64,
    chunk_id: &str,
    lamport_clock: i64,
) -> Result<Vec<u8>> {
    aead::seal(key, plaintext, &epoch_aad(epoch, chunk_id, lamport_clock))
}

/// Open a vault chunk written under `epoch`.
///
/// Falls back to the un-epoched shapes ([`aead::open_vault_chunk`]) when the
/// blob carries no epoch binding, so devices that have not yet learned the
/// account's epoch can still read pre-re-keying data during rollout. Returns
/// the epoch the blob was actually bound to: `None` means legacy (no epoch),
/// which lets the caller enforce policy — accept-and-migrate locally, refuse to
/// serve, whatever the protocol layer decides — rather than having this layer
/// hide the distinction.
pub fn open_epoch_chunk(
    key: &[u8; 32],
    blob: &[u8],
    epoch: u64,
    chunk_id: &str,
    lamport_clock: i64,
) -> Result<(Option<u64>, Zeroizing<Vec<u8>>)> {
    // An epoched blob is strictly longer than a legacy sealed one by the AAD we
    // added, but the only reliable discriminator is trying the tags: try the
    // current epoch first, then the legacy bindings.
    if let Ok(pt) = aead::open(key, blob, &epoch_aad(epoch, chunk_id, lamport_clock)) {
        return Ok((Some(epoch), pt));
    }
    match aead::open_vault_chunk(key, blob, chunk_id, lamport_clock) {
        Ok(pt) => Ok((None, pt)),
        Err(e) => Err(e),
    }
}

/// Split the NEW seed into fresh recovery shares.
///
/// Old backup shares require no tombstone: they are shares of the old secret,
/// authenticated under a MAC key derived from that secret ([`shamir`]), so they
/// reconstruct exactly the value the rotation just retired — worthless by
/// construction. What must happen is what this function supports: mint shares
/// of the new seed and upload them over the old cloud backup, then destroy the
/// local copies per the sharing protocol.
pub fn rekey_recovery_shares(
    new_rms: &[u8; 32],
    threshold: u8,
    n: u8,
) -> Result<Vec<shamir::Share>> {
    shamir::split(new_rms, threshold, n)
}

/// True when `shares` reconstruct to exactly `expected`.
///
/// The rotation UI uses this twice: to confirm the fresh shares really recover
/// the new seed BEFORE the old backup is overwritten (overwriting first would
/// make a bug unrecoverable), and later, when a recovered device wants to know
/// whether the shares it was handed are pre-rotation relics.
pub fn shares_reconstruct_to(shares: &[shamir::Share], expected: &[u8; 32]) -> bool {
    shamir::reconstruct(shares, expected.len())
        .map(|secret| {
            if secret.len() != expected.len() {
                return false;
            }
            secret
                .iter()
                .zip(expected.iter())
                .fold(0u8, |different, (actual, wanted)| {
                    different | (actual ^ wanted)
                })
                == 0
        })
        .unwrap_or(false)
}

/// Size a caller should expect from [`rekey_blob`]: input length plus overhead.
pub fn rekeyed_len(input_len: usize) -> usize {
    input_len + OVERHEAD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn rotate_produces_distinct_32byte_seeds() {
        let a = rotate().unwrap();
        let b = rotate().unwrap();
        assert_ne!(*a, *b, "two rotations must never agree");
        // Uniformity is the RNG's job; uniqueness of successive draws is ours.
        assert_ne!(*a, seed(0));
    }

    #[test]
    fn rekeyed_blob_opens_under_the_new_seed_only() {
        let old = seed(1);
        let new = rotate().unwrap();
        let ctx = kdf::contexts::VAULT_ENCRYPTION;
        let plaintext = b"the vault contents";
        let ct = crate::aead::encrypt(kdf::derive(ctx, &old).as_bytes(), plaintext).unwrap();

        let rekeyed = rekey_blob(&old, &new, ctx, &ct).unwrap();

        // Opens under the new derivation, to the original bytes.
        let opened = crate::aead::decrypt(kdf::derive(ctx, &*new).as_bytes(), &rekeyed).unwrap();
        assert_eq!(&opened[..], plaintext);
        // And no longer under the old one.
        assert!(crate::aead::decrypt(kdf::derive(ctx, &old).as_bytes(), &rekeyed).is_err());

        // Fresh nonce: re-keying the same blob twice yields different bytes.
        let again = rekey_blob(&old, &new, ctx, &ct).unwrap();
        assert_ne!(
            rekeyed, again,
            "nonce reuse across epochs is pointless risk"
        );
    }

    #[test]
    fn rekey_with_the_wrong_old_seed_fails_closed() {
        let old = seed(1);
        let new = rotate().unwrap();
        let ctx = kdf::contexts::AUDIT_LOG;
        let ct = crate::aead::encrypt(kdf::derive(ctx, &old).as_bytes(), b"audit").unwrap();

        let mut wrong = old;
        wrong[0] ^= 1;
        assert!(rekey_blob(&wrong, &new, ctx, &ct).is_err());
        // Wrong context is equally fatal: derivations are domain-separated.
        assert!(rekey_blob(&old, &new, kdf::contexts::VAULT_ENCRYPTION, &ct).is_err());
    }

    #[test]
    fn epoch_binding_refuses_the_wrong_epoch_and_survives_roundtrip() {
        let key = kdf::derive(kdf::contexts::CHUNK_KEY, &seed(7));
        let pt = b"chunk body";
        let blob = seal_epoch_chunk(key.as_bytes(), pt, 5, "vault-main", 12).unwrap();

        let (got_epoch, opened) =
            open_epoch_chunk(key.as_bytes(), &blob, 5, "vault-main", 12).unwrap();
        assert_eq!(got_epoch, Some(5));
        assert_eq!(&opened[..], pt);

        // A different epoch — the post-rotation reader meeting a pre-rotation
        // chunk — must not open at all: it is neither bound to this epoch nor
        // genuinely legacy, so it is an error rather than a silent fallback.
        assert!(open_epoch_chunk(key.as_bytes(), &blob, 6, "vault-main", 12).is_err());

        // Nor a relabelled chunk id or revision (C-2 binding carried through).
        assert!(open_epoch_chunk(key.as_bytes(), &blob, 5, "vault-other", 12).is_err());
        assert!(open_epoch_chunk(key.as_bytes(), &blob, 5, "vault-main", 13).is_err());
    }

    #[test]
    fn legacy_chunks_still_open_and_report_no_epoch() {
        let key = kdf::derive(kdf::contexts::CHUNK_KEY, &seed(9));
        let legacy = crate::aead::encrypt(key.as_bytes(), b"old world").unwrap();

        let (epoch, opened) =
            open_epoch_chunk(key.as_bytes(), &legacy, 42, "vault-data-000001", 0).unwrap();
        assert_eq!(epoch, None, "pre-epoch blobs report None");
        assert_eq!(&opened[..], b"old world");

        // Same for the C-2 sealed-but-un-epoched intermediate shape.
        let sealed = crate::aead::seal(
            key.as_bytes(),
            b"mid world",
            &crate::aead::vault_chunk_aad("vault-data-000002", 3),
        )
        .unwrap();
        let (epoch, opened) =
            open_epoch_chunk(key.as_bytes(), &sealed, 42, "vault-data-000002", 3).unwrap();
        assert_eq!(epoch, None);
        assert_eq!(&opened[..], b"mid world");
    }

    #[test]
    fn fresh_shares_recover_the_new_seed_and_old_shares_do_not() {
        let old = seed(3);
        let new = rotate().unwrap();

        let old_shares = shamir::split(&old, 2, 3).unwrap();
        let new_shares = rekey_recovery_shares(&new, 2, 3).unwrap();

        assert!(shares_reconstruct_to(&new_shares[0..2], &new));
        assert!(!shares_reconstruct_to(&new_shares[0..2], &old));

        // THE invalidation claim: the retired shares still work perfectly —
        // for the retired seed only. No tombstone needed; the seed moved.
        assert!(shares_reconstruct_to(&old_shares[0..2], &old));
        assert!(
            !shares_reconstruct_to(&old_shares[0..2], &new),
            "pre-rotation shares must never reconstruct the new seed"
        );
        // Mixing shares across epochs reconstructs neither (distinct polynomials).
        let mixed = vec![new_shares[0].clone(), old_shares[1].clone()];
        assert!(!shares_reconstruct_to(&mixed, &new));
        assert!(!shares_reconstruct_to(&mixed, &old));
    }

    #[test]
    fn verify_before_overwrite_is_expressible() {
        // The order the UI must follow: prove the new backup recovers, THEN
        // overwrite the old one. This pins the tool that makes that order possible.
        let new = rotate().unwrap();
        let shares = rekey_recovery_shares(&new, 3, 5).unwrap();
        // Below threshold: refuses rather than guessing.
        assert!(!shares_reconstruct_to(&shares[0..2], &new));
        // At threshold: verified.
        assert!(shares_reconstruct_to(&shares[0..3], &new));
    }

    #[test]
    fn rekeyed_len_accounts_for_aead_overhead() {
        let old = seed(4);
        let new = rotate().unwrap();
        let ctx = kdf::contexts::VAULT_ENCRYPTION;
        for pt_len in [0usize, 1, 100] {
            let pt = vec![7u8; pt_len];
            let ct = crate::aead::encrypt(kdf::derive(ctx, &old).as_bytes(), &pt).unwrap();
            let out = rekey_blob(&old, &new, ctx, &ct).unwrap();
            // Same wire format as the input, so the size prediction must hold
            // exactly — not just "at least the overhead".
            assert_eq!(out.len(), ct.len(), "same format, same overhead shape");
            assert_eq!(
                out.len(),
                rekeyed_len(pt_len),
                "predicted size for {pt_len}-byte plaintext"
            );
        }
    }
}
