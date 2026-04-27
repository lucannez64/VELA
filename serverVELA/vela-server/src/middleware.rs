//! Axum middleware and extractors.
//!
//! ## `RequireAuth` extractor
//!
//! Parses and validates the `Authorization: Bearer <paseto-token>` header on
//! every authenticated route.  It:
//!   1. Validates the PASETO v4 public token signature.
//!   2. Checks the `exp` / `nbf` / `hcap` claims.
//!   3. Verifies the JTI is not in the sled revocation set.
//!   4. Runs the 300 req/min per-JTI rate limit.
//!   5. Optionally renews the token (issued when <5 min remain on current token)
//!      via the `X-New-Token` response header.

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap, HeaderValue},
};
use chrono::Utc;

use crate::{auth::token::TokenService, error::AppError, rate_limit, state::AppState};

/// Authenticated session extracted from the `Authorization: Bearer` header.
#[derive(Clone, Debug)]
pub struct AuthSession {
    pub user_id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub jti: String,
    /// Set when the token is close to expiry and has been refreshed.
    pub new_token: Option<String>,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // ── 1. Extract bearer token ──────────────────────────────────────────
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))?;

        let token_str = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("Authorization must be Bearer scheme".into()))?;

        // ── 2. Verify signature & standard claims ────────────────────────────
        let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
        let claims = ts.verify(token_str)?;

        // ── 3. Check hard-cap (8-hour max session) ───────────────────────────
        let now = Utc::now();
        if now > claims.hard_cap {
            return Err(AppError::Unauthorized("session hard cap exceeded".into()));
        }

        // ── 4. JTI and device revocation check ──────────────────────────────
        let store = &state.store;

        let jti_revoked = store.exists(&format!("jti:revoked:{}", claims.jti))?;
        if jti_revoked {
            return Err(AppError::Unauthorized("token has been revoked".into()));
        }

        let device_revoked = store.exists(&format!("device:revoked:{}", claims.device_id))?;
        if device_revoked {
            return Err(AppError::Unauthorized("device has been revoked".into()));
        }

        // ── 5. Per-JTI rate limit (300 req/min) ──────────────────────────────
        rate_limit::authenticated_by_jti(store, &claims.jti)?;

        // ── 6. Token renewal (if expiry is ≤5 min away) ──────────────────────
        let renewal_threshold = claims.exp - chrono::Duration::minutes(5);
        let new_token = if now >= renewal_threshold {
            let remaining_secs = (claims.hard_cap - now).num_seconds().max(0) as u64;
            let old_ttl_secs = (claims.exp - now).num_seconds().max(0) as u64;

            if old_ttl_secs > 0 {
                let _ = store.set_ex(&format!("jti:revoked:{}", claims.jti), &[1u8], old_ttl_secs);
            }

            if remaining_secs > 0 {
                let (refreshed, new_jti) =
                    ts.issue(claims.user_id, claims.device_id, Some(claims.hard_cap))?;
                let _ =
                    rate_limit::track_device_jti(store, &claims.device_id.to_string(), &new_jti);
                Some(refreshed)
            } else {
                None
            }
        } else {
            None
        };

        Ok(AuthSession {
            user_id: claims.user_id,
            device_id: claims.device_id,
            jti: claims.jti,
            new_token,
        })
    }
}

/// Append the `X-New-Token` header to a response when the session was renewed.
pub fn maybe_append_new_token(headers: &mut HeaderMap, session: &AuthSession) {
    if let Some(ref tok) = session.new_token {
        if let Ok(v) = HeaderValue::from_str(tok) {
            headers.insert("X-New-Token", v);
        }
    }
}
