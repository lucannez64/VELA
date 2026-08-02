use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub easy_to_type: bool,
    pub pronounceable: bool,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            easy_to_type: false,
            pronounceable: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordStrength {
    pub entropy: f64,
    pub score: String,
    pub crack_time: String,
}

pub fn calculate_password_strength(password: &str) -> PasswordStrength {
    let charset_size = if password.chars().any(|c| c.is_ascii_lowercase()) {
        26
    } else {
        0
    } + if password.chars().any(|c| c.is_ascii_uppercase()) {
        26
    } else {
        0
    } + if password.chars().any(|c| c.is_ascii_digit()) {
        10
    } else {
        0
    } + if password.chars().any(|c| !c.is_alphanumeric()) {
        32
    } else {
        0
    };

    let entropy = if charset_size > 0 {
        (password.len() as f64) * (charset_size as f64).log2()
    } else {
        0.0
    };

    let (score, crack_time) = if entropy < 28.0 {
        ("weak", "instant")
    } else if entropy < 36.0 {
        ("fair", "minutes")
    } else if entropy < 60.0 {
        ("good", "months")
    } else {
        ("strong", "centuries")
    };

    PasswordStrength {
        entropy,
        score: score.to_string(),
        crack_time: crack_time.to_string(),
    }
}

/// Why generation can fail: the OS random source is the only thing this needs
/// from the outside, and there is no safe way to continue without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    RandomSourceUnavailable,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the OS random source is unavailable")
    }
}

impl std::error::Error for PasswordError {}

/// Map a random 32-bit draw onto `0..n`, or `None` if the draw falls in the
/// biased tail and must be redrawn.
///
/// `value % n` alone favours the low indices whenever `n` does not divide 2^32 —
/// small, but free to remove, and this is a password generator. Everything at or
/// above the largest multiple of `n` is rejected instead.
fn index_from(value: u32, n: u32) -> Option<u32> {
    // 2^32 draws are possible, one more than `u32::MAX`; computing the bound in
    // u64 keeps that off-by-one from rejecting a perfectly good draw when `n`
    // divides evenly (a 2-, 16- or 32-character charset).
    const SPAN: u64 = 1 << 32;
    let bound = SPAN - (SPAN % n as u64);
    ((value as u64) < bound).then(|| value % n)
}

fn uniform_index(n: usize) -> Result<usize, PasswordError> {
    let n = n as u32;
    loop {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).map_err(|_| PasswordError::RandomSourceUnavailable)?;
        if let Some(index) = index_from(u32::from_le_bytes(buf), n) {
            return Ok(index as usize);
        }
    }
}

pub fn generate_password(
    options: &PasswordGeneratorOptions,
) -> Result<(String, PasswordStrength), PasswordError> {
    let mut charset = String::new();

    if options.uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if options.lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if options.numbers {
        charset.push_str("0123456789");
    }
    if options.symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
    }

    if options.easy_to_type {
        charset = charset.replace(|c: char| !c.is_alphanumeric(), "");
    }

    if charset.is_empty() {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }

    let charset: Vec<char> = charset.chars().collect();

    // Returned rather than panicked: this runs behind `extern "C"` bridges,
    // where unwinding is undefined behaviour (audit L2).
    let mut password = String::with_capacity(options.length);
    for _ in 0..options.length {
        password.push(charset[uniform_index(charset.len())?]);
    }

    let strength = calculate_password_strength(&password);
    Ok((password, strength))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit hardening: `value % n` favours low indices unless `n` divides
    /// 2^32. The tail that would cause it is rejected instead.
    #[test]
    fn index_from_rejects_the_biased_tail() {
        let n = 3u32; // does not divide 2^32, so the bias is real
        // Largest multiple of n that fits in the 2^32 possible draws.
        let bound = ((1u64 << 32) - ((1u64 << 32) % n as u64)) as u32;

        assert_eq!(index_from(bound - 1, n), Some((bound - 1) % n));
        assert_eq!(index_from(bound, n), None, "the biased tail is redrawn");

        // Every index stays reachable, and nothing escapes the range.
        let mut seen = [false; 3];
        for value in 0..300u32 {
            let index = index_from(value, n).expect("small values are accepted");
            assert!(index < n);
            seen[index as usize] = true;
        }
        assert!(seen.iter().all(|hit| *hit));

        // A power-of-two charset divides evenly: nothing is ever rejected.
        assert_eq!(index_from(u32::MAX, 2), Some(1));
    }

    #[test]
    fn strength_thresholds_match_desktop_behavior() {
        assert_eq!(calculate_password_strength("abc").score, "weak");
        assert_eq!(calculate_password_strength("abcdefgh").score, "good");
        assert_eq!(calculate_password_strength("Abcdefgh123").score, "strong");
    }

    #[test]
    fn generated_password_respects_easy_to_type() {
        let options = PasswordGeneratorOptions {
            length: 64,
            easy_to_type: true,
            ..PasswordGeneratorOptions::default()
        };
        let (password, strength) = generate_password(&options).expect("OS RNG");
        assert_eq!(password.len(), 64);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(strength.score, "strong");
    }
}
