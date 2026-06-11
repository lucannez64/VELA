use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::{Zeroize, ZeroizeOnDrop};

const TOKEN_EXPIRY_SECS: i64 = 15 * 60;
const MAX_TOKEN_AGE_SECS: i64 = 8 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasetoToken {
    pub jti: String,
    pub device_id: String,
    pub user_id: String,
    pub iat: DateTime<Utc>,
    pub exp: DateTime<Utc>,
}

impl PasetoToken {
    pub fn new(device_id: String, user_id: String) -> Self {
        let now = Utc::now();
        let jti = generate_jti();
        Self {
            jti,
            device_id,
            user_id,
            iat: now,
            exp: now + chrono::Duration::seconds(TOKEN_EXPIRY_SECS),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.exp
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    pub fn age_secs(&self) -> i64 {
        Utc::now()
            .signed_duration_since(self.iat)
            .num_seconds()
            .max(0)
    }

    pub fn should_refresh(&self) -> bool {
        let time_until_expiry = self.exp - Utc::now();
        time_until_expiry.num_minutes() < 5 && !self.is_expired()
    }
}

fn generate_jti() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS random source unavailable");
    data_encoding::BASE64URL.encode(&bytes)
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    key: [u8; 32],
}

impl SecretKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("OS random source unavailable");
        Self { key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { key: *bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub jti: String,
    pub device_id: String,
    pub user_id: String,
    pub iat: String,
    pub exp: String,
}

pub fn create_local_token(
    device_id: &str,
    user_id: &str,
    secret_key: &SecretKey,
) -> Result<String, anyhow::Error> {
    let token = PasetoToken::new(device_id.to_string(), user_id.to_string());

    let claims = TokenClaims {
        jti: token.jti.clone(),
        device_id: token.device_id.clone(),
        user_id: token.user_id.clone(),
        iat: token.iat.to_rfc3339(),
        exp: token.exp.to_rfc3339(),
    };

    let header = json!({
        "typ": "v4-local",
        "alg": "loc"
    });

    let json_payload = json!({
        "jti": claims.jti,
        "device_id": claims.device_id,
        "user_id": claims.user_id,
        "iat": claims.iat,
        "exp": claims.exp
    });

    let mut message = serde_json::to_string(&header)?;
    message.push('.');
    message.push_str(&serde_json::to_string(&json_payload)?);

    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())?;
    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();

    let signature = data_encoding::BASE64URL.encode(&result);

    message.push('.');
    message.push_str(&signature);

    Ok(message)
}

pub fn validate_local_token(
    token: &str,
    secret_key: &SecretKey,
) -> Result<PasetoToken, anyhow::Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid token format");
    }

    let message = format!("{}.{}", parts[0], parts[1]);

    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())?;
    mac.update(message.as_bytes());

    let expected_sig = data_encoding::BASE64URL.decode(parts[2].as_bytes())?;
    mac.verify_slice(&expected_sig)?;

    let payload: serde_json::Value = serde_json::from_str(parts[1])?;

    let jti = payload["jti"].as_str().unwrap_or_default().to_string();
    let device_id = payload["device_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let user_id = payload["user_id"].as_str().unwrap_or_default().to_string();
    let iat = DateTime::parse_from_rfc3339(payload["iat"].as_str().unwrap_or_default())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let exp = DateTime::parse_from_rfc3339(payload["exp"].as_str().unwrap_or_default())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let token = PasetoToken {
        jti,
        device_id,
        user_id,
        iat,
        exp,
    };

    if token.is_expired() {
        anyhow::bail!("Token has expired");
    }

    if token.age_secs() > MAX_TOKEN_AGE_SECS {
        anyhow::bail!("Token exceeds maximum age");
    }

    Ok(token)
}

#[derive(Debug, Clone)]
pub struct TokenStore {
    revoked_tokens: std::collections::HashSet<String>,
    tokens_by_device: std::collections::HashMap<String, Vec<String>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            revoked_tokens: std::collections::HashSet::new(),
            tokens_by_device: std::collections::HashMap::new(),
        }
    }

    pub fn revoke_token(&mut self, jti: &str, device_id: &str) {
        self.revoked_tokens.insert(jti.to_string());
        if let Some(tokens) = self.tokens_by_device.get_mut(device_id) {
            tokens.retain(|t| t != jti);
        }
    }

    pub fn revoke_device_tokens(&mut self, device_id: &str) {
        if let Some(tokens) = self.tokens_by_device.remove(device_id) {
            for jti in tokens {
                self.revoked_tokens.insert(jti);
            }
        }
    }

    pub fn is_token_revoked(&self, jti: &str) -> bool {
        self.revoked_tokens.contains(jti)
    }

    pub fn add_token(&mut self, device_id: &str, jti: String) {
        self.tokens_by_device
            .entry(device_id.to_string())
            .or_insert_with(Vec::new)
            .push(jti);
    }

    pub fn cleanup_expired(&mut self) {
        self.revoked_tokens.retain(|_| false);
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}
