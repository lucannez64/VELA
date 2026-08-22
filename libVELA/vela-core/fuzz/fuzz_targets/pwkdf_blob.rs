//! Fuzz the versioned password-sealed blob reader.
//!
//! `open_with_password` parses a self-describing blob (magic, version,
//! recorded Argon2id cost) that an attacker with write access to the vault
//! file can rewrite at will. The recorded cost is unauthenticated by design —
//! that is what `Argon2Cost::validated` is for. Nothing here may panic, and a
//! hostile cost must be *refused*, not merely slow.
//!
//! Input: password token + blob bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_crypto::password_kdf;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 8192 {
        return;
    }
    // First byte: how many bytes of the rest are the "password".
    let pw_len = (data[0] as usize % data.len().saturating_sub(1)).max(1);
    let (pw_bytes, blob) = data[1..].split_at(pw_len.min(64));

    match password_kdf::open_with_password(pw_bytes, blob) {
        Ok(plaintext) => {
            // Only reachable for honestly sealed blobs: verify the round trip
            // against a fresh seal with the same password.
            let resealed = password_kdf::seal_with_password(pw_bytes, &plaintext).unwrap();
            assert_eq!(
                password_kdf::open_with_password(pw_bytes, &resealed).unwrap(),
                plaintext
            );
        }
        Err(err) => {
            // A blob claiming an out-of-bounds Argon2 cost must fail with the
            // implausible-cost refusal, not burn CPU deriving first. The
            // bounds mirror `Argon2Cost::validated` (private): m in
            // [8 KiB, 1 GiB], t/p in [1, 16].
            if blob.len() > 17 && &blob[..4] == password_kdf::BLOB_MAGIC && blob[4] == 3 {
                let m = u32::from_le_bytes(blob[5..9].try_into().unwrap());
                let t = u32::from_le_bytes(blob[9..13].try_into().unwrap());
                let p = u32::from_le_bytes(blob[13..17].try_into().unwrap());
                let hostile = !(8..=1024 * 1024).contains(&m)
                    || t == 0
                    || t > 16
                    || p == 0
                    || p > 16;
                if hostile {
                    let msg = format!("{err}");
                    assert!(
                        msg.contains("implausible") || msg.contains("too small"),
                        "hostile cost {m}/{t}/{p} slipped past validation: {msg}"
                    );
                }
            }
        }
    }
    let _ = password_kdf::is_current_format(blob);
    let _ = password_kdf::needs_reseal(blob);
});
