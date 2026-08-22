//! Fuzz password generation from untrusted options.
//!
//! The Tauri command handler accepts `PasswordGeneratorOptions` straight from
//! the webview; only the UI slider caps `length`. A compromised or buggy page
//! can send any JSON — so huge lengths must fail cleanly or stay bounded, and
//! entropy scoring must not panic on any generated output.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_core::password::{
    calculate_password_strength, generate_password, PasswordGeneratorOptions,
};

fn flag(byte: u8) -> bool {
    byte & 1 == 1
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 || data.len() > 512 {
        return;
    }
    // length: 0..=1_000_000 — covers 0, empty-charset, and absurd sizes.
    let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize % 1_000_001;
    let options = PasswordGeneratorOptions {
        length,
        uppercase: flag(data[4]),
        lowercase: flag(data[5]),
        numbers: flag(data[6]),
        symbols: flag(data[7]),
        easy_to_type: flag(data[8]),
        pronounceable: flag(data[9]),
    };

    match generate_password(&options) {
        Ok((password, strength)) => {
            // Every charset char is ASCII, so char count == byte count == length.
            debug_assert_eq!(password.len(), length);
            // Strength verdict must agree with the entropy it was derived from.
            let recomputed = calculate_password_strength(&password);
            assert_eq!(recomputed.score, strength.score);
            let (expected_score, _) =
                vela_core::password::strength_verdict(recomputed.entropy);
            assert_eq!(recomputed.score, expected_score);
        }
        Err(_) => {} // clean failure is fine
    }

    // Entropy estimator itself takes raw strings from the vault too.
    let s = String::from_utf8_lossy(&data[10..]);
    let _ = calculate_password_strength(&s);
});
