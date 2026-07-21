use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::command;

type HmacSha1 = Hmac<Sha1>;

const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u32 = 6;
// RFC 6238/4226 practical bounds: 6–8 digits, 15–120 s period. Values outside
// these ranges are rejected rather than computed (10^digits overflows u32-era
// assumptions and huge allocations/format widths are a DoS vector).
const MIN_PERIOD: u64 = 15;
const MAX_PERIOD: u64 = 120;
const MIN_DIGITS: u32 = 6;
const MAX_DIGITS: u32 = 8;

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
    }
}

pub fn generate_totp_code(secret: &str) -> Option<String> {
    let params = parse_otpauth(secret);
    params.validate().ok()?;
    let secret_bytes = base32_decode(&params.secret)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let counter = now.as_secs() / params.period;
    Some(compute_hotp(&secret_bytes, counter, params.digits))
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

fn compute_hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC initialization failed");
    mac.update(&counter_bytes);
    let result = mac.finalize();
    let hash = result.into_bytes();

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;

    let code = ((hash[offset] as u64 & 0x7f) << 24)
        | ((hash[offset + 1] as u64) << 16)
        | ((hash[offset + 2] as u64) << 8)
        | (hash[offset + 3] as u64);

    let otp = code % 10u64.pow(digits);
    format!("{:0width$}", otp, width = digits as usize)
}

#[command]
pub async fn generate_totp(secret: String) -> Result<TotpCode, String> {
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

    let code = compute_hotp(&secret_bytes, counter, digits);

    Ok(TotpCode {
        code,
        remaining_secs: remaining,
        period,
    })
}

#[command]
pub async fn verify_totp(secret: String, code: String) -> Result<bool, String> {
    let params = parse_otpauth(&secret);
    params.validate()?;
    let secret_bytes =
        base32_decode(&params.secret).ok_or_else(|| "Invalid base32 secret".to_string())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs();

    let counter = now / params.period;
    let expected = compute_hotp(&secret_bytes, counter, params.digits);
    let code_trimmed = code.trim();

    // Constant-time comparison so the code can't be narrowed down byte-by-byte
    // via response timing, matching the capability check in ipc.rs.
    use subtle::ConstantTimeEq;
    Ok(bool::from(
        expected.as_bytes().ct_eq(code_trimmed.as_bytes()),
    ))
}
