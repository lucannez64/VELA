use rand::RngCore;
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

pub fn generate_password(options: &PasswordGeneratorOptions) -> (String, PasswordStrength) {
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
    let mut rng = rand::rngs::OsRng;

    let password: String = (0..options.length)
        .map(|_| {
            let mut buf = [0u8; 4];
            rng.fill_bytes(&mut buf);
            let idx = u32::from_le_bytes(buf) as usize % charset.len();
            charset[idx]
        })
        .collect();

    let strength = calculate_password_strength(&password);
    (password, strength)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (password, strength) = generate_password(&options);
        assert_eq!(password.len(), 64);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(strength.score, "strong");
    }
}
