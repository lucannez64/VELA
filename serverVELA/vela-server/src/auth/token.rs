//! PASETO v4 public token issuance and validation.
//!
//! ## Token payload (JSON)
//!
//! ```json
//! {
//!   "iss": "vela-server",
//!   "sub": "<user_uuid>",
//!   "jti": "<uuid-v4>",
//!   "iat": "<RFC3339>",
//!   "nbf": "<RFC3339>",
//!   "exp": "<RFC3339>",    // iat + 15 min  (sliding — renewed if <5 min remain)
//!   "device_id": "<uuid>",
//!   "hard_cap":  "<RFC3339>" // iat + 8 h  (absolute session ceiling)
//! }
//! ```

use chrono::{DateTime, Duration, Utc};
use pasetors::{
    claims::{Claims, ClaimsValidationRules},
    keys::{AsymmetricPublicKey, AsymmetricSecretKey},
    public,
    token::UntrustedToken,
    version4::V4,
    Public,
};
use uuid::Uuid;

use crate::error::{AppError, Result};

const ISSUER: &str = "vela-server";
const TOKEN_LIFE: i64 = 15 * 60; // 15 min in seconds
const HARD_CAP_SECS: i64 = 8 * 60 * 60; // 8 h in seconds

/// Parsed, validated claims extracted from a PASETO token.
#[derive(Debug, Clone)]
pub struct VelaClaims {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub jti: String,
    pub exp: DateTime<Utc>,
    pub hard_cap: DateTime<Utc>,
}

/// Token service — thin wrapper around the PASETO library.
#[derive(Clone)]
pub struct TokenService {
    sk: AsymmetricSecretKey<V4>,
    pk: AsymmetricPublicKey<V4>,
}

impl TokenService {
    pub fn new(sk: AsymmetricSecretKey<V4>, pk: AsymmetricPublicKey<V4>) -> Self {
        Self { sk, pk }
    }

    /// Issue a new 15-minute PASETO v4 public token.
    ///
    /// Returns `(token_string, jti)`.  The caller **must** register the JTI
    /// with sled via `rate_limit::track_device_jti` so that device revocation
    /// can enumerate and invalidate all active tokens (SPEC §6).
    ///
    /// `hard_cap` carries the original timestamp across renewals so the
    /// 8-hour session ceiling is always enforced.
    pub fn issue(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        hard_cap: Option<DateTime<Utc>>,
    ) -> Result<(String, String)> {
        let now = Utc::now();
        let hcap = hard_cap.unwrap_or_else(|| now + Duration::seconds(HARD_CAP_SECS));
        // Never let a token outlive its session ceiling. For permanent devices the
        // 8 h cap is far away so this is a no-op; for ephemeral web sessions the
        // ceiling is the granted TTL, so a short-lived session gets a short exp.
        let exp = (now + Duration::seconds(TOKEN_LIFE)).min(hcap);
        let jti = Uuid::new_v4().to_string();

        let mut claims =
            Claims::new().map_err(|e| AppError::Internal(format!("claims init: {e:?}")))?;

        claims
            .issuer(ISSUER)
            .map_err(|e| AppError::Internal(format!("issuer: {e:?}")))?;
        claims
            .subject(&user_id.to_string())
            .map_err(|e| AppError::Internal(format!("subject: {e:?}")))?;
        claims
            .token_identifier(&jti)
            .map_err(|e| AppError::Internal(format!("jti: {e:?}")))?;
        claims
            .issued_at(&now.to_rfc3339())
            .map_err(|e| AppError::Internal(format!("iat: {e:?}")))?;
        claims
            .not_before(&now.to_rfc3339())
            .map_err(|e| AppError::Internal(format!("nbf: {e:?}")))?;
        claims
            .expiration(&exp.to_rfc3339())
            .map_err(|e| AppError::Internal(format!("exp: {e:?}")))?;
        claims
            .add_additional("device_id", serde_json::json!(device_id.to_string()))
            .map_err(|e| AppError::Internal(format!("device_id claim: {e:?}")))?;
        claims
            .add_additional("hard_cap", serde_json::json!(hcap.to_rfc3339()))
            .map_err(|e| AppError::Internal(format!("hard_cap claim: {e:?}")))?;

        let token = public::sign(&self.sk, &claims, None, None)
            .map_err(|e| AppError::Internal(format!("PASETO sign: {e:?}")))?;
        Ok((token, jti))
    }

    /// Verify a PASETO v4 public token and return parsed claims.
    pub fn verify(&self, token_str: &str) -> Result<VelaClaims> {
        let mut rules = ClaimsValidationRules::new();
        rules.validate_issuer_with(ISSUER);
        // Expiration and not-before are validated by default in pasetors.

        let untrusted = UntrustedToken::<Public, V4>::try_from(token_str)
            .map_err(|e| AppError::Unauthorized(format!("malformed token: {e:?}")))?;

        let trusted = public::verify(&self.pk, &untrusted, &rules, None, None)
            .map_err(|e| AppError::Unauthorized(format!("token verification failed: {e:?}")))?;

        let p = trusted
            .payload_claims()
            .ok_or_else(|| AppError::Unauthorized("no claims in token".into()))?;

        let user_id = p
            .get_claim("sub")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| AppError::Unauthorized("missing sub claim".into()))?;

        let device_id: Uuid = p
            .get_claim("device_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| AppError::Unauthorized("missing device_id claim".into()))?;

        let jti = p
            .get_claim("jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| AppError::Unauthorized("missing jti claim".into()))?;

        let exp: DateTime<Utc> = p
            .get_claim("exp")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .ok_or_else(|| AppError::Unauthorized("missing exp claim".into()))?;

        let hard_cap: DateTime<Utc> = p
            .get_claim("hard_cap")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .ok_or_else(|| AppError::Unauthorized("missing hard_cap claim".into()))?;

        Ok(VelaClaims {
            user_id,
            device_id,
            jti,
            exp,
            hard_cap,
        })
    }
}
