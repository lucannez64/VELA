//! Out-of-band short verification codes.
//!
//! Device enrollment transmits a locator string (`VELA-ENROLL:v2:...`) out of
//! band — as a QR code or pasted text — from an already-enrolled device to a
//! new device. That locator is not authenticated: it points the new device at
//! a server URL, a token, and a decryption key, all chosen by whoever
//! generated it. Nothing in the protocol lets the *new* device establish
//! trust in the locator's origin on its own — there is no pre-existing trust
//! root to verify a signature against at enrollment time, since this is the
//! trust-bootstrap moment itself.
//!
//! What both devices *can* do is compute the same short digest of the exact
//! locator string and have the user visually compare it on both screens
//! before the new device commits to importing anything — the same
//! short-authentication-string (SAS) pattern used by Signal's safety numbers,
//! WhatsApp's linked-device confirmation, and Bluetooth Secure Simple
//! Pairing. If an attacker substitutes the transmitted code (a tampered QR,
//! a spoofed clipboard, or simply tricking the user into scanning an
//! unrelated code), the two devices are hashing different content and the
//! codes will not match.
//!
//! This is *not* a substitute for the user's own attention: it only helps if
//! they actually compare the two codes before confirming. It is a mitigation
//! for automated/passive substitution, not a cryptographic proof of origin.
//!
//! ## Why 18 digits, not fewer
//!
//! Unlike Bluetooth Secure Simple Pairing or ZRTP, there is no interactive
//! commit-then-reveal step here that forces an attacker to commit to their
//! substitute locator *before* seeing the digest they need to match — the
//! locator is a static string a device can compute against offline, as many
//! times as it wants, before ever showing anything to a user. That means the
//! attacker's cost to find a colliding substitute is a straight preimage
//! search over the code space, not a birthday-bounded, time-boxed one. A
//! 30-bit code (the previous size here) is only ~10^9 BLAKE3 evaluations —
//! seconds on a single modern CPU, let alone a GPU. 18 decimal digits gives
//! ~60 bits (10^18), which is far beyond what's recoverable by brute force
//! in the time it takes a human to scan a QR code and tap "confirm", while
//! still being renderable as a short, grouped, glanceable numeric string.
const VERIFICATION_CODE_DIGITS: u32 = 18;

/// Derive an 18-digit, human-comparable verification code from an enrollment
/// code string. Both the generating device (right after creating the code)
/// and the importing device (right after scanning/pasting it, *before*
/// importing) call this on the exact same string and the user confirms the
/// two rendered codes match.
///
/// Uses BLAKE3 (already a workspace dependency), truncated to a 128-bit
/// value (so the `% 10^18` reduction below has negligible modulo bias) and
/// then reduced to 18 decimal digits — see the module docs for the
/// reasoning behind that size and the limits of what this can and can't
/// prove.
pub fn enrollment_verification_code(code: &str) -> String {
    let digest = blake3::hash(code.trim().as_bytes());
    let bytes = digest.as_bytes();
    let mut wide = [0u8; 16];
    wide.copy_from_slice(&bytes[..16]);
    let modulus = 10u128.pow(VERIFICATION_CODE_DIGITS);
    let n = u128::from_be_bytes(wide) % modulus;
    let digits = format!("{n:0width$}", width = VERIFICATION_CODE_DIGITS as usize);
    digits
        .as_bytes()
        .chunks(3)
        .map(|c| std::str::from_utf8(c).expect("ASCII digits"))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_input() {
        let code = "VELA-ENROLL:v2:abc123";
        assert_eq!(
            enrollment_verification_code(code),
            enrollment_verification_code(code)
        );
    }

    #[test]
    fn differs_for_different_input() {
        let a = enrollment_verification_code("VELA-ENROLL:v2:abc123");
        let b = enrollment_verification_code("VELA-ENROLL:v2:abc124");
        assert_ne!(a, b, "different locators must not collide in practice");
    }

    #[test]
    fn ignores_surrounding_whitespace() {
        let a = enrollment_verification_code("VELA-ENROLL:v2:abc123");
        let b = enrollment_verification_code("  VELA-ENROLL:v2:abc123\n");
        assert_eq!(a, b, "pasted codes often pick up incidental whitespace");
    }

    #[test]
    fn format_is_six_groups_of_three_digits() {
        let code = enrollment_verification_code("anything");
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 6, "expected 6 groups, got: {code}");
        for part in parts {
            assert_eq!(part.len(), 3, "expected 3-digit group, got: {part}");
            assert!(part.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn code_has_eighteen_digits() {
        let code = enrollment_verification_code("anything");
        let digit_count = code.chars().filter(|c| c.is_ascii_digit()).count();
        assert_eq!(digit_count, 18, "expected 18 digits, got: {code}");
    }

    #[test]
    fn distribution_is_reasonably_spread() {
        // Sanity check that truncation doesn't collapse the output space:
        // across many distinct inputs, codes should mostly be distinct.
        use std::collections::HashSet;
        let codes: HashSet<String> = (0..2000)
            .map(|i| enrollment_verification_code(&format!("VELA-ENROLL:v2:{i}")))
            .collect();
        assert!(
            codes.len() > 1990,
            "expected near-unique codes across 2000 distinct inputs, got {}",
            codes.len()
        );
    }
}
