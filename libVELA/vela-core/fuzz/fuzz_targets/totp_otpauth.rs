//! Fuzz the TOTP `otpauth://` parser and code pipeline.
//!
//! `parse_otpauth` hand-rolls query parsing with byte slicing (`find`,
//! string indexing) over strings that arrive from the vault (a site's stored
//! TOTP field) — i.e. attacker-influenced via sync. Nothing here may panic:
//! no out-of-bound slices, no `10^digits` overflow, no absurd allocation.
//!
//! Input: one token — the secret field as stored.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_desktop_core::totp;

fn clean(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let input = clean(data);

    // generate_totp_code returns Option and must never panic.
    let _ = totp::generate_totp_code(&input);

    // The full code path: Result either way, never a panic.
    if let Ok(code) = totp::generate_totp(input.clone()) {
        let digits = code.code.len();
        assert!(
            (6..=8).contains(&digits),
            "generated code width {digits} outside RFC bounds for {input:?}"
        );
        // verify_totp on the just-generated code must accept it.
        let verdict = totp::verify_totp(input, code.code).unwrap_or(false);
        assert!(verdict, "freshly generated code must verify");
    }
});
