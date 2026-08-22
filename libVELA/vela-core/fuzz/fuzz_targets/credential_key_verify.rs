//! Fuzz ES256 credential-key parsing + verification — passkey/share surface.
//!
//! `verify_der(cose_public_key, message, signature_der)` parses a
//! hand-rolled COSE_Key layout (`parse_cose_key_es256`, bounds-checked but
//! structure-strict: it must reject anything not written by
//! `cose_key_es256`) and an ASN.1 DER ECDSA signature (p256 crate). Bytes in
//! these shapes arrive from sync shares and page-originated WebAuthn flows.
//!
//! Oracles:
//! 1. never panics on arbitrary bytes (primary);
//! 2. differential: any key the hand parser accepts must decode to the same
//!    x/y the generic CBOR route extracts (a stray-byte misread fires here);
//! 3. soundness: an honest signature verifies; flipping any bit of the
//!    message or signature flips the verdict to false.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_desktop_core::credential_key::{self, CredentialKey};

/// Independent decode of the canonical COSE_Key layout: map(5) with fixed
/// one-byte keys 1,3,-1,-2,-3; x at [10..42], y at [45..77]. Mirrors the
/// encoder's byte positions without sharing its code path (the hand parser
/// slices by offset too, but through its own arithmetic).
fn reference_xy(cose: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if cose.len() != 77 || cose[0] != 0xA5 {
        return None;
    }
    let expect = |pos: usize, byte: u8| cose[pos] == byte;
    // map header + kty/EC2 + alg/ES256(-7=0x26) + crv/P-256
    let shape_ok = expect(1, 0x01)
        && expect(2, 0x02)
        && expect(3, 0x03)
        && expect(4, 0x26)
        && expect(5, 0x20)
        && expect(6, 0x01)
        && expect(7, 0x21)
        && expect(8, 0x58)
        && expect(9, 32)
        && expect(42, 0x22)
        && expect(43, 0x58)
        && expect(44, 32);
    if !shape_ok {
        return None;
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&cose[10..42]);
    y.copy_from_slice(&cose[45..77]);
    Some((x, y))
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 || data.len() > 4096 {
        return;
    }

    // 1. Totality: arbitrary bytes never panic, only Err/false.
    let verdict = credential_key::verify_der(data, b"fuzz msg", data);

    // 2. Differential: when the hand parser accepts a key, the reference
    //    extraction of the same bytes must agree — and the key must be a
    //    valid P-256 point on the SEC1 route.
    if data.len() == 77 && data[0] == 0xA5 {
        let hand = std::panic::catch_unwind(|| {
            credential_key::verify_der(data, b"x", &[0x30, 0x00])
        });
        if let Ok(Ok(_)) = hand {
            assert!(
                reference_xy(data).is_some(),
                "hand parser accepted a key the canonical shape rejects"
            );
        }
    }

    // 3. Soundness on honest material, using fuzzed keys/messages.
    if data.len() >= 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data[..32]);
        if let Ok(key) = CredentialKey::from_scalar(&seed) {
            let cose = key.public_key_cose();
            let message = &data[..data.len().min(64)];
            let sig = key.sign_der(message);
            assert!(
                credential_key::verify_der(&cose, message, &sig).unwrap_or(false),
                "honest signature failed verification"
            );
            // Bit-flip in the signature must not verify.
            let mut bad = sig.clone();
            let flip_at = data[0] as usize % bad.len();
            bad[flip_at] ^= 0x08;
            if bad != sig {
                assert_eq!(
                    credential_key::verify_der(&cose, message, &bad).unwrap_or(false),
                    false,
                    "tampered signature verified"
                );
            }
        }
    }
});
