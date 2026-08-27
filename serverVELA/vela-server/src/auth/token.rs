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

use chrono::{DateTime, Utc};
use pasetors::{
    claims::{Claims, ClaimsValidationRules},
    keys::{AsymmetricPublicKey, AsymmetricSecretKey},
    public,
    token::UntrustedToken,
    version4::V4,
    Public,
};
use uuid::Uuid;
use vela_session_policy::{CapabilityScope, ScopeClaim, ScopeDecision, TokenDecision, TokenPlan};

use crate::error::{AppError, Result};

const ISSUER: &str = "vela-server";
pub use vela_session_policy::CapabilityScope as TokenScope;

/// Parsed, validated claims extracted from a PASETO token.
#[derive(Debug, Clone)]
pub struct VelaClaims {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub jti: String,
    pub exp: DateTime<Utc>,
    pub hard_cap: DateTime<Utc>,
    pub scope: TokenScope,
    /// Account key epoch at which an ephemeral web session was granted.
    pub key_epoch: Option<i64>,
}

/// What kind of caller a token speaks for (red-team RT-4).
///
/// Before this existed, the PASETO issued to an ephemeral browser was
/// indistinguishable from an enrolled device's: same `sub`, a `device_id` that
/// happened to be the session id, and nothing to tell the two apart. So a
/// session that `EPHEMERAL_WEB_ACCESS_DESIGN.md` §2 promises is "temporary",
/// "revocable at any time" and "no permanent device enrollment" could rotate the
/// recovery share, register the attacker's recovery passkey, revoke the real
/// devices that would have revoked *it*, and delete the account outright.
///
/// The boundary that promise describes is an authorization boundary, not just an
/// expiry one — so it has to be written into the token and checked at the routes
/// that outlive the session.
fn scope_name(scope: TokenScope) -> &'static str {
    match scope {
        TokenScope::Device => "device",
        TokenScope::WebSession => "web_session",
    }
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
    /// Issue a token for a real enrolled device.
    pub fn issue(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        hard_cap: Option<DateTime<Utc>>,
    ) -> Result<(String, String)> {
        let now = Utc::now().timestamp();
        let decision =
            vela_session_policy::plan_device_token(now, hard_cap.map(|cap| cap.timestamp()));
        let TokenDecision::Issue(plan) = decision else {
            return Err(AppError::Internal("invalid device token lifetime".into()));
        };
        self.issue_from_plan(user_id, device_id, plan)
    }

    /// Sign only claims produced by the formally verified capability policy.
    pub fn issue_from_plan(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        plan: TokenPlan,
    ) -> Result<(String, String)> {
        let now = Utc::now();
        let hcap = DateTime::<Utc>::from_timestamp(plan.hard_cap(), 0)
            .ok_or_else(|| AppError::Internal("token hard cap is out of range".into()))?;
        let exp = DateTime::<Utc>::from_timestamp(plan.expires_at(), 0)
            .ok_or_else(|| AppError::Internal("token expiry is out of range".into()))?;
        if exp <= now || hcap <= now || exp > hcap {
            return Err(AppError::Internal("token plan is no longer live".into()));
        }
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
        claims
            .add_additional("scope", serde_json::json!(scope_name(plan.scope())))
            .map_err(|e| AppError::Internal(format!("scope claim: {e:?}")))?;
        if let Some(epoch) = plan.key_epoch() {
            claims
                .add_additional("key_epoch", serde_json::json!(epoch))
                .map_err(|e| AppError::Internal(format!("key_epoch claim: {e:?}")))?;
        }

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

        let raw_scope = p.get_claim("scope").and_then(|v| v.as_str());
        let scope_claim = match raw_scope {
            None => ScopeClaim::MissingLegacy,
            Some("device") => ScopeClaim::Device,
            Some("web_session") => ScopeClaim::WebSession,
            Some(_) => ScopeClaim::Unknown,
        };
        let scope = match vela_session_policy::parse_scope_claim(scope_claim) {
            ScopeDecision::Accept(scope) => scope,
            ScopeDecision::Reject => {
                return Err(AppError::Unauthorized("unknown token scope".into()));
            }
        };
        let key_epoch = p
            .get_claim("key_epoch")
            .and_then(|v| v.as_i64())
            .filter(|epoch| *epoch >= 1);

        let policy_claims = vela_session_policy::TokenClaims {
            scope: match scope {
                TokenScope::Device => CapabilityScope::Device,
                TokenScope::WebSession => CapabilityScope::WebSession,
            },
            key_epoch,
            expires_at: exp.timestamp(),
            hard_cap: hard_cap.timestamp(),
        };
        if !vela_session_policy::renewal_input_is_valid(policy_claims, Utc::now().timestamp()) {
            return Err(AppError::Unauthorized(
                "token capability claims are inconsistent".into(),
            ));
        }

        Ok(VelaClaims {
            user_id,
            device_id,
            jti,
            exp,
            hard_cap,
            scope,
            key_epoch,
        })
    }
}
