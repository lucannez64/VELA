//! Fuzz the enrollment verification-code helpers.
//!
//! `enrollment_verification_code` renders an 18-digit grouped code from any
//! string a user scans/pastes; `enrollment_fingerprint` fingerprints the key
//! being enrolled; `enrollment_fingerprint_choices` builds the pick-one decoy
//! set. All take untrusted strings and all have soundness properties worth
//! checking on every input: fixed shape, uniqueness of the true answer in the
//! choice list, and uniformity can't be asserted per-run but shape can.
//!
//! Input: one or two tokens — code, optional count.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_crypto::verification::{
    enrollment_fingerprint, enrollment_fingerprint_choices, enrollment_verification_code,
    MAX_FINGERPRINT_CHOICES,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let (code, count_arg) = match text.split_once(char::is_whitespace) {
        Some((a, b)) => (
            a.to_string(),
            b.trim().parse::<usize>().unwrap_or(3).min(64),
        ),
        None => (text.to_string(), 3),
    };

    // Verification code: always exactly 18 digits in 3-digit groups.
    let rendered = enrollment_verification_code(&code);
    let compact: String = rendered.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(compact.len(), 18, "code shape broke for {code:?}");
    assert_eq!(
        rendered.split('-').map(|g| g.len()).collect::<Vec<_>>(),
        vec![3, 3, 3, 3, 3, 3],
        "grouping broke for {code:?}"
    );

    // Deterministic: same input, same code.
    assert_eq!(enrollment_verification_code(&code), rendered);

    // Fingerprint: same shape guarantees over arbitrary key bytes.
    let fingerprint = enrollment_fingerprint(data);
    assert_eq!(
        fingerprint.chars().filter(|c| c.is_ascii_digit()).count(),
        18
    );

    // Choice sets: right size, actual present exactly once, all distinct.
    let choices = enrollment_fingerprint_choices(&rendered, count_arg);
    let expected = (count_arg.clamp(2, MAX_FINGERPRINT_CHOICES)).min(MAX_FINGERPRINT_CHOICES);
    assert!(
        (2..=MAX_FINGERPRINT_CHOICES).contains(&choices.len())
            && choices.len() == expected.max(choices.len()),
        "choice count {} for requested {count_arg}",
        choices.len()
    );
    let actual_hits = choices.iter().filter(|c| **c == rendered).count();
    assert_eq!(actual_hits, 1, "answer must appear exactly once");
    let unique: std::collections::HashSet<&String> = choices.iter().collect();
    assert_eq!(unique.len(), choices.len(), "decoys collided with each other");
});
