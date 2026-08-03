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

// ── Enrollment v3: comparing keys, not locators ─────────────────────────────

/// A comparable fingerprint of the joining device's public signing key.
///
/// v2 hashed the locator string, because the locator was the thing that could
/// be substituted. v3 has nothing secret in the locator, so what matters is
/// whether the key the server is about to enrol is the key belonging to the
/// device in the user's hand — so the fingerprint is over the key itself
/// (audit P-1).
///
/// That also narrows what an attacker would have to do. They cannot see the
/// legitimate device's public key: only the device that opened the grant may
/// read a claim, and a grant admits exactly one claim. So making their own
/// fingerprint match would mean colliding with a value they never observe,
/// rather than matching a locator they were shown. The 18 digits are kept
/// anyway — they cost nothing and the reasoning above about offline preimage
/// search still applies to anyone who does obtain the key.
pub fn enrollment_fingerprint(hybrid_vk: &[u8]) -> String {
    // Domain-separated from the v2 locator digest so the two can never be
    // confused for one another, in a log or by a client that mixes versions.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vela enrollment device fingerprint v3");
    hasher.update(hybrid_vk);
    format_digits(hasher.finalize().as_bytes())
}

/// Smallest and largest number of choices worth offering.
///
/// Two is the point at which blind tapping stops being free. Above five the
/// list stops being glanceable and people start pattern-matching the first two
/// groups instead of reading, which quietly undoes the whole thing.
pub const MIN_FINGERPRINT_CHOICES: usize = 2;
pub const MAX_FINGERPRINT_CHOICES: usize = 5;

/// `actual` plus indistinguishable decoys, shuffled.
///
/// A yes/no "do these match?" prompt fails **open**: the habitual answer is
/// yes, and a user who is not really looking confirms whatever is in front of
/// them. Asking them to *pick* the code their other device is showing makes not
/// looking fail (n-1)/n of the time instead of succeeding — the difference
/// between the comparison being a step and being decoration.
///
/// The decoys therefore have to be indistinguishable from the real one, and the
/// real one's position has to be uniform: if it were ever biased — always
/// first, or never last — the guess would stop being a guess.
pub fn enrollment_fingerprint_choices(actual: &str, count: usize) -> Vec<String> {
    let count = count.clamp(MIN_FINGERPRINT_CHOICES, MAX_FINGERPRINT_CHOICES);
    let mut choices = Vec::with_capacity(count);
    choices.push(actual.to_string());

    while choices.len() < count {
        let mut bytes = [0u8; 32];
        if getrandom::getrandom(&mut bytes).is_err() {
            // Without a random source we cannot generate decoys that are not
            // guessable, and a predictable decoy set is worse than none: it
            // would look like a real check without being one. Offer the single
            // true value and let the caller fall back to a plain comparison.
            return vec![actual.to_string()];
        }
        let decoy = format_digits(&bytes);
        // A decoy equal to the answer would silently turn an n-way choice into
        // an (n-1)-way one with two correct answers.
        if decoy != actual && !choices.contains(&decoy) {
            choices.push(decoy);
        }
    }

    shuffle(&mut choices);
    choices
}

/// Reduce a digest to the same grouped 18-digit shape used above.
fn format_digits(bytes: &[u8]) -> String {
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

/// Fisher-Yates with rejection-sampled indices.
///
/// `% n` on a random word is biased whenever `n` does not divide the word
/// range, and here that bias would land directly on where the correct answer
/// appears — the one place a lopsided distribution is worth something to an
/// attacker.
fn shuffle(items: &mut [String]) {
    for i in (1..items.len()).rev() {
        match random_below(i + 1) {
            Some(j) => items.swap(i, j),
            // No randomness: leaving the order alone is safe here only because
            // the caller above already refuses to build a decoy set without it.
            None => return,
        }
    }
}

/// Uniform in `[0, n)`, or `None` if the OS random source fails.
fn random_below(n: usize) -> Option<usize> {
    if n <= 1 {
        return Some(0);
    }
    let n = n as u32;
    let limit = u32::MAX - (u32::MAX % n) - 1;
    loop {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).ok()?;
        let value = u32::from_le_bytes(buf);
        if value <= limit {
            return Some((value % n) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── v3 fingerprint + choice ─────────────────────────────────────────────

    #[test]
    fn fingerprint_is_deterministic_and_key_specific() {
        let a = vec![7u8; 2624];
        let mut b = a.clone();
        b[2000] ^= 1; // one bit
        assert_eq!(enrollment_fingerprint(&a), enrollment_fingerprint(&a));
        assert_ne!(
            enrollment_fingerprint(&a),
            enrollment_fingerprint(&b),
            "a one-bit key difference must be visible to the user"
        );
    }

    #[test]
    fn fingerprint_is_domain_separated_from_the_v2_code() {
        // The two are different things over different inputs; a client that
        // mixed them up must not silently agree.
        let key = b"VELA-ENROLL:v2:abc123";
        assert_ne!(
            enrollment_fingerprint(key),
            enrollment_verification_code("VELA-ENROLL:v2:abc123")
        );
    }

    #[test]
    fn choices_contain_the_answer_exactly_once() {
        let actual = enrollment_fingerprint(&[1u8; 2624]);
        let choices = enrollment_fingerprint_choices(&actual, 4);
        assert_eq!(choices.len(), 4);
        assert_eq!(
            choices.iter().filter(|c| **c == actual).count(),
            1,
            "two correct answers would halve the cost of guessing"
        );
    }

    #[test]
    fn decoys_are_indistinguishable_from_the_answer() {
        // If a decoy were shaped differently, picking correctly would not
        // require reading the other device's screen.
        let actual = enrollment_fingerprint(&[2u8; 2624]);
        for choice in enrollment_fingerprint_choices(&actual, 5) {
            let groups: Vec<&str> = choice.split('-').collect();
            assert_eq!(groups.len(), 6, "wrong shape: {choice}");
            for group in groups {
                assert_eq!(group.len(), 3);
                assert!(group.chars().all(|c| c.is_ascii_digit()));
            }
        }
    }

    #[test]
    fn choices_are_distinct() {
        let actual = enrollment_fingerprint(&[3u8; 2624]);
        let choices = enrollment_fingerprint_choices(&actual, 5);
        let unique: std::collections::HashSet<&String> = choices.iter().collect();
        assert_eq!(unique.len(), choices.len(), "duplicates: {choices:?}");
    }

    #[test]
    fn the_answers_position_is_uniform() {
        // The whole point of offering a choice is that not looking fails
        // (n-1)/n of the time. A biased position — always first, never last —
        // would give a blind tapper somewhere to aim, so this asserts the
        // distribution rather than merely that a shuffle happens.
        const N: usize = 4;
        const ROUNDS: usize = 4000;
        let actual = enrollment_fingerprint(&[4u8; 2624]);
        let mut counts = [0usize; N];

        for _ in 0..ROUNDS {
            let choices = enrollment_fingerprint_choices(&actual, N);
            let at = choices.iter().position(|c| *c == actual).expect("answer present");
            counts[at] += 1;
        }

        let expected = ROUNDS / N;
        for (index, count) in counts.iter().enumerate() {
            // ±25% of expected: wide enough not to flake, far tighter than any
            // bias worth exploiting.
            assert!(
                *count > expected * 3 / 4 && *count < expected * 5 / 4,
                "position {index} appeared {count} times, expected about {expected}: {counts:?}"
            );
        }
    }

    #[test]
    fn the_number_of_choices_is_bounded() {
        let actual = enrollment_fingerprint(&[5u8; 2624]);
        // One choice is not a choice; a hundred is not glanceable, and a list
        // nobody reads is the failure this exists to prevent.
        assert_eq!(enrollment_fingerprint_choices(&actual, 0).len(), MIN_FINGERPRINT_CHOICES);
        assert_eq!(enrollment_fingerprint_choices(&actual, 1).len(), MIN_FINGERPRINT_CHOICES);
        assert_eq!(enrollment_fingerprint_choices(&actual, 99).len(), MAX_FINGERPRINT_CHOICES);
    }

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
