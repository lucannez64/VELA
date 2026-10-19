use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

/// HMAC hash backing the HOTP construction. RFC 6238 defines SHA-1, SHA-256
/// and SHA-512 variants, and authenticator apps in the wild use all three, so
/// an otpauth URI's `algorithm` parameter has to be honored rather than
/// assumed to be SHA-1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn from_label(label: &str) -> Self {
        match label.trim().to_ascii_uppercase().as_str() {
            "SHA256" | "SHA-256" => Algorithm::Sha256,
            "SHA512" | "SHA-512" => Algorithm::Sha512,
            _ => Algorithm::Sha1,
        }
    }
}

const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u32 = 6;
// Practical bounds, matching the browser extension's otpauth parser so the
// code is identical whichever side computes it: 6–10 digits, 5–300 s period.
// Values outside these ranges are rejected rather than computed (10^digits
// overflows u64-era assumptions and huge allocations/format widths are a DoS
// vector).
const MIN_PERIOD: u64 = 5;
const MAX_PERIOD: u64 = 300;
const MIN_DIGITS: u32 = 6;
const MAX_DIGITS: u32 = 10;

#[derive(Serialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining_secs: u64,
    pub period: u64,
}

#[derive(Clone)]
struct TotpParams {
    secret: String,
    period: u64,
    digits: u32,
    algorithm: Algorithm,
}

impl TotpParams {
    fn validate(&self) -> Result<(), String> {
        if self.digits < MIN_DIGITS || self.digits > MAX_DIGITS {
            return Err(format!(
                "TOTP digits must be between {MIN_DIGITS} and {MAX_DIGITS}"
            ));
        }
        if self.period < MIN_PERIOD || self.period > MAX_PERIOD {
            return Err(format!(
                "TOTP period must be between {MIN_PERIOD} and {MAX_PERIOD} seconds"
            ));
        }
        Ok(())
    }
}

fn parse_otpauth(input: &str) -> TotpParams {
    let mut period = DEFAULT_PERIOD;
    let mut digits = DEFAULT_DIGITS;
    let mut algorithm = Algorithm::Sha1;

    if input.starts_with("otpauth://") {
        if let Some(query_start) = input.find('?') {
            let query = &input[query_start + 1..];
            for param in query.split('&') {
                if let Some(eq) = param.find('=') {
                    let key = &param[..eq];
                    let value = &param[eq + 1..];
                    match key {
                        "period" => period = value.parse().unwrap_or(DEFAULT_PERIOD),
                        "digits" => digits = value.parse().unwrap_or(DEFAULT_DIGITS),
                        "algorithm" => algorithm = Algorithm::from_label(value),
                        _ => {}
                    }
                }
            }
        }
    }

    TotpParams {
        secret: extract_secret(input),
        period,
        digits,
        algorithm,
    }
}

pub fn generate_totp_code(secret: &str) -> Option<String> {
    let params = parse_otpauth(secret);
    params.validate().ok()?;
    let secret_bytes = base32_decode(&params.secret)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let counter = now.as_secs() / params.period;
    Some(compute_hotp(&secret_bytes, counter, params.digits, params.algorithm))
}

fn extract_secret(input: &str) -> String {
    if input.starts_with("otpauth://") {
        if let Some(secret_start) = input.find("secret=") {
            let secret_part = &input[secret_start + 7..];
            let secret_end = secret_part.find('&').unwrap_or(secret_part.len());
            return secret_part[..secret_end].to_string();
        }
    }
    input.to_string()
}

fn base32_decode(secret: &str) -> Option<Vec<u8>> {
    let secret_upper = secret.to_uppercase().replace(" ", "").replace("-", "");
    let clean: String = secret_upper
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let padding = (8 - clean.len() % 8) % 8;
    let padded = format!("{}{}", clean, "=".repeat(padding));
    BASE32.decode(padded.as_bytes()).ok()
}

fn compute_hotp(secret: &[u8], counter: u64, digits: u32, algorithm: Algorithm) -> String {
    let counter_bytes = counter.to_be_bytes();

    // One arm per hash: the HMAC key is the decoded shared secret, and the
    // message is always the 8-byte big-endian counter.
    let hash: Vec<u8> = match algorithm {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC initialization failed");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).expect("HMAC initialization failed");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(secret).expect("HMAC initialization failed");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;

    let code = ((hash[offset] as u64 & 0x7f) << 24)
        | ((hash[offset + 1] as u64) << 16)
        | ((hash[offset + 2] as u64) << 8)
        | (hash[offset + 3] as u64);

    let otp = code % 10u64.pow(digits);
    format!("{:0width$}", otp, width = digits as usize)
}

pub fn generate_totp(secret: String) -> Result<TotpCode, String> {
    let params = parse_otpauth(&secret);
    params.validate()?;
    let secret_bytes =
        base32_decode(&params.secret).ok_or_else(|| "Invalid base32 secret".to_string())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs();

    let period = params.period;
    let counter = now / period;
    let remaining = period - (now % period);
    let digits = params.digits;

    let code = compute_hotp(&secret_bytes, counter, digits, params.algorithm);

    Ok(TotpCode {
        code,
        remaining_secs: remaining,
        period,
    })
}

pub fn verify_totp(secret: String, code: String) -> Result<bool, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs();
    verify_totp_at(&secret, &code, now)
}

/// Verify against a ±1 time-step window, not just the current step.
///
/// A code generated in the final second of a window must still verify in the
/// next window (and vice versa) — otherwise autofill rejects perfectly valid
/// codes whenever the counter rolls over between generation and verification
/// (found by fuzzing: the crash reproduced only at exact period boundaries).
/// `counter + 1` is accepted for callers that pre-computed a code just before
/// a rollover; matching any window is still constant-time per candidate.
fn verify_totp_at(secret: &str, code: &str, now: u64) -> Result<bool, String> {
    let params = parse_otpauth(secret);
    params.validate()?;
    let secret_bytes =
        base32_decode(&params.secret).ok_or_else(|| "Invalid base32 secret".to_string())?;

    let current = now / params.period;
    let code_trimmed = code.trim();

    // Constant-time comparison so the code can't be narrowed down byte-by-byte
    // via response timing, matching the capability check in ipc.rs.
    use subtle::ConstantTimeEq;
    let matched = [current.wrapping_sub(1), current, current + 1]
        .into_iter()
        .map(|counter| compute_hotp(&secret_bytes, counter, params.digits, params.algorithm))
        .any(|expected| bool::from(expected.as_bytes().ct_eq(code_trimmed.as_bytes())));
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226/6238 shared test secret: ASCII "12345678901234567890".
    const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn rfc_secret_bytes() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                compute_hotp(&rfc_secret_bytes(), counter as u64, 6, Algorithm::Sha1),
                *code,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn hotp_matches_rfc6238_sha1_8digit_vectors() {
        // RFC 6238 Appendix B (SHA-1): T=59 → counter 1, T=1111111109 →
        // counter 0x23523EC, T=1234567890 → counter 0x273EF07.
        assert_eq!(compute_hotp(&rfc_secret_bytes(), 1, 8, Algorithm::Sha1), "94287082");
        assert_eq!(compute_hotp(&rfc_secret_bytes(), 0x23523EC, 8, Algorithm::Sha1), "07081804");
        assert_eq!(compute_hotp(&rfc_secret_bytes(), 0x273EF07, 8, Algorithm::Sha1), "89005924");
    }

    #[test]
    fn hotp_matches_rfc6238_sha256_and_sha512_vectors() {
        // RFC 6238 Appendix B uses a longer seed for the SHA-2 variants:
        // 32 bytes for SHA-256 and 64 bytes for SHA-512.
        let sha256_secret = b"12345678901234567890123456789012";
        let sha512_secret =
            b"1234567890123456789012345678901234567890123456789012345678901234";

        // (counter, SHA-256 8-digit, SHA-512 8-digit)
        let vectors = [
            (1u64, "46119246", "90693936"),
            (0x23523EC, "68084774", "25091201"),
            (0x23523ED, "67062674", "99943326"),
            (0x273EF07, "91819424", "93441116"),
            (0x3F940AA, "90698825", "38618901"),
            (0x27BC86AA, "77737706", "47863826"),
        ];
        for (counter, sha256_code, sha512_code) in vectors {
            assert_eq!(
                compute_hotp(sha256_secret, counter, 8, Algorithm::Sha256),
                sha256_code,
                "SHA-256 counter {counter}"
            );
            assert_eq!(
                compute_hotp(sha512_secret, counter, 8, Algorithm::Sha512),
                sha512_code,
                "SHA-512 counter {counter}"
            );
        }
    }

    #[test]
    fn parse_otpauth_honors_algorithm_parameter() {
        let params = parse_otpauth("otpauth://totp/A?secret=ABC&algorithm=SHA256");
        assert_eq!(params.algorithm, Algorithm::Sha256);
        let params = parse_otpauth("otpauth://totp/A?secret=ABC&algorithm=SHA512");
        assert_eq!(params.algorithm, Algorithm::Sha512);
        // Unknown or absent algorithm falls back to SHA-1, never an error.
        let params = parse_otpauth("otpauth://totp/A?secret=ABC&algorithm=MD5");
        assert_eq!(params.algorithm, Algorithm::Sha1);
        let params = parse_otpauth("otpauth://totp/A?secret=ABC");
        assert_eq!(params.algorithm, Algorithm::Sha1);
    }

    #[test]
    fn base32_decode_handles_rfc_secret_and_sloppy_input() {
        assert_eq!(base32_decode(RFC_SECRET_B32).unwrap(), rfc_secret_bytes());
        // Lowercase, spaces and dashes are normalized away.
        assert_eq!(
            base32_decode("gezdgnbv-gy3t qojq gezdgnbvgy3tqojq").unwrap(),
            rfc_secret_bytes()
        );
        // Unpadded input is padded internally (16 chars → 10 bytes).
        assert_eq!(base32_decode("GEZDGNBVGY3TQOJQ").unwrap(), b"1234567890");
        // Alphanumeric but outside the base32 alphabet (0/1/8/9) must fail.
        assert!(base32_decode("0189ABCD").is_none());
    }

    #[test]
    fn parse_otpauth_uri_extracts_all_params() {
        let params = parse_otpauth("otpauth://totp/Alice?secret=ABC&period=60&digits=8");
        assert_eq!(params.secret, "ABC");
        assert_eq!(params.period, 60);
        assert_eq!(params.digits, 8);
    }

    #[test]
    fn parse_otpauth_defaults_and_garbage_fallbacks() {
        let params = parse_otpauth("otpauth://totp/Alice?secret=ABC");
        assert_eq!(params.period, DEFAULT_PERIOD);
        assert_eq!(params.digits, DEFAULT_DIGITS);

        let params = parse_otpauth("otpauth://totp/Alice?secret=ABC&period=abc&digits=x");
        assert_eq!(params.period, DEFAULT_PERIOD);
        assert_eq!(params.digits, DEFAULT_DIGITS);

        // A bare secret is used as-is.
        let params = parse_otpauth(RFC_SECRET_B32);
        assert_eq!(params.secret, RFC_SECRET_B32);
        assert_eq!(params.period, DEFAULT_PERIOD);
    }

    #[test]
    fn params_validate_enforces_rfc_bounds() {
        let ok = TotpParams { secret: String::new(), period: 30, digits: 6, algorithm: Algorithm::Sha1 };
        assert!(ok.validate().is_ok());

        for digits in [5, 11] {
            let p = TotpParams { secret: String::new(), period: 30, digits, algorithm: Algorithm::Sha1 };
            assert!(p.validate().is_err(), "digits {digits} must be rejected");
        }
        for digits in [6, 7, 8, 9, 10] {
            let p = TotpParams { secret: String::new(), period: 30, digits, algorithm: Algorithm::Sha1 };
            assert!(p.validate().is_ok(), "digits {digits} must be accepted");
        }
        for period in [4, 301] {
            let p = TotpParams { secret: String::new(), period, digits: 6, algorithm: Algorithm::Sha1 };
            assert!(p.validate().is_err(), "period {period} must be rejected");
        }
        for period in [5, 30, 120, 300] {
            let p = TotpParams { secret: String::new(), period, digits: 6, algorithm: Algorithm::Sha1 };
            assert!(p.validate().is_ok(), "period {period} must be accepted");
        }
    }

    #[test]
    fn generate_totp_rejects_out_of_bounds_params() {
        let err = generate_totp(
            "otpauth://totp/A?secret=GEZDGNBVGY3TQOJQ&digits=11".to_string(),
        );
        assert!(err.is_err());
        let err = generate_totp(
            "otpauth://totp/A?secret=GEZDGNBVGY3TQOJQ&period=3600".to_string(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn generate_totp_rejects_invalid_base32() {
        assert!(generate_totp("0189ABCD".to_string()).is_err());
        assert!(generate_totp_code("0189ABCD").is_none());
    }

    // Fuzzer-found regression: a code from the last second of a window must
    // still verify after the counter rolls over (±1-step tolerance).
    #[test]
    fn verify_totp_tolerates_one_step_rollover() {
        let now: u64 = 1_800_000_000; // any value; not necessarily a boundary
        let params = parse_otpauth(RFC_SECRET_B32);
        params.validate().expect("RFC secret is valid");
        let secret_bytes = base32_decode(&params.secret).unwrap();

        let code_prev = compute_hotp(&secret_bytes, now / 30 - 1, 6, Algorithm::Sha1);
        let code_cur = compute_hotp(&secret_bytes, now / 30, 6, Algorithm::Sha1);
        let code_next = compute_hotp(&secret_bytes, now / 30 + 1, 6, Algorithm::Sha1);

        assert!(verify_totp_at(RFC_SECRET_B32, &code_prev, now).unwrap());
        assert!(verify_totp_at(RFC_SECRET_B32, &code_cur, now).unwrap());
        assert!(verify_totp_at(RFC_SECRET_B32, &code_next, now).unwrap());

        // Two steps away must still be rejected.
        let code_far = compute_hotp(&secret_bytes, now / 30 + 2, 6, Algorithm::Sha1);
        assert!(!verify_totp_at(RFC_SECRET_B32, &code_far, now).unwrap());
        assert!(!verify_totp_at(RFC_SECRET_B32, &code_prev, now - 90).unwrap());
    }

    #[test]
    fn generate_totp_returns_code_with_period_metadata() {
        let totp = generate_totp(RFC_SECRET_B32.to_string()).expect("valid secret");
        assert_eq!(totp.code.len(), 6);
        assert!(totp.code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(totp.period, 30);
        assert!(totp.remaining_secs >= 1 && totp.remaining_secs <= 30);

        let totp8 = generate_totp(format!(
            "otpauth://totp/A?secret={RFC_SECRET_B32}&period=60&digits=8"
        ))
        .expect("valid uri");
        assert_eq!(totp8.code.len(), 8);
        assert_eq!(totp8.period, 60);
        assert!(totp8.remaining_secs >= 1 && totp8.remaining_secs <= 60);
    }

    #[test]
    fn verify_totp_accepts_current_code_and_rejects_wrong() {
        let code = generate_totp(RFC_SECRET_B32.to_string()).unwrap().code;
        assert!(verify_totp(RFC_SECRET_B32.to_string(), code.clone()).unwrap());
        // Whitespace around the code is tolerated.
        assert!(verify_totp(RFC_SECRET_B32.to_string(), format!(" {code} ")).unwrap());

        let wrong = if code == "000000" { "111111" } else { "000000" };
        assert!(!verify_totp(RFC_SECRET_B32.to_string(), wrong.to_string()).unwrap());
    }
}
