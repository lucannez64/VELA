use data_encoding::BASE32;
use serde::{Deserialize, Serialize};
use tauri::command;
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha1::Sha1;

const TOTP_PERIOD: u64 = 30;

#[derive(Serialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining_secs: u64,
    pub period: u64,
}

pub fn generate_totp_code(secret: &str) -> Option<String> {
    let secret_bytes = base32_decode(secret)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let counter = now.as_secs() / TOTP_PERIOD;
    Some(compute_hotp(&secret_bytes, counter))
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
    let extracted = extract_secret(secret);
    let secret_upper = extracted.to_uppercase().replace(" ", "").replace("-", "");
    let clean: String = secret_upper.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let padding = (8 - clean.len() % 8) % 8;
    let padded = format!("{}{}", clean, "=".repeat(padding));
    BASE32.decode(padded.as_bytes()).ok()
}

fn compute_hotp(secret: &[u8], counter: u64) -> String {
    type HmacSha1 = Hmac<Sha1>;
    
    let counter_bytes = counter.to_be_bytes();
    
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC initialization failed");
    mac.update(&counter_bytes);
    let result = mac.finalize();
    let hash = result.into_bytes();
    
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    
    let code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    
    let otp = code % 1_000_000;
    format!("{:06}", otp)
}

#[command]
pub async fn generate_totp(secret: String) -> Result<TotpCode, String> {
    let secret_bytes = base32_decode(&secret)
        .ok_or_else(|| "Invalid base32 secret".to_string())?;
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs();
    
    let counter = now / TOTP_PERIOD;
    let remaining = TOTP_PERIOD - (now % TOTP_PERIOD);
    
    let code = compute_hotp(&secret_bytes, counter);
    
    Ok(TotpCode {
        code,
        remaining_secs: remaining,
        period: TOTP_PERIOD,
    })
}

#[command]
pub async fn verify_totp(secret: String, code: String) -> Result<bool, String> {
    let secret_bytes = base32_decode(&secret)
        .ok_or_else(|| "Invalid base32 secret".to_string())?;
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs();
    
    let counter = now / TOTP_PERIOD;
    let expected = compute_hotp(&secret_bytes, counter);
    let code_trimmed = code.trim();
    
    Ok(expected == code_trimmed)
}