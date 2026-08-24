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

use crate::{
    auth::token::{TokenScope, TokenService},
    error::AppError,
    rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

/// Authenticated session extracted from the `Authorization: Bearer` header.
#[derive(Clone, Debug)]
pub struct AuthSession {
    pub user_id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub jti: String,
    /// Epoch at which this authority was granted. Permanent device tokens may
    /// omit it; web-session tokens are pinned to it so rotation retires their
    /// ability to mutate the vault even when commit races request extraction.
    pub key_epoch: Option<i64>,
    /// Set when the token is close to expiry and has been refreshed.
    pub new_token: Option<String>,
    /// What kind of caller this is (red-team RT-4). Routes whose effects
    /// outlive a web session must extract [`DeviceSession`] instead of this,
    /// which refuses anything but [`TokenScope::Device`].
    pub scope: TokenScope,
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

        // ── 5b. User existence check ─────────────────────────────────────────
        // Web-session RW tokens use session_id as device_id and carry no
        // devices row, so device-revocation alone cannot kill them when the
        // account is deleted. One indexed lookup per request closes that gap.
        let user_rows = state
            .sqldb
            .query(
                "SELECT key_epoch FROM users WHERE id = ?",
                vec![TursoValue::Text(claims.user_id.to_string())],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let Some(user_row) = user_rows.first() else {
            return Err(AppError::Unauthorized("account no longer exists".into()));
        };
        let current_key_epoch = user_row.i64(0).unwrap_or(1).max(1);
        if claims.scope == TokenScope::WebSession
            && claims.key_epoch.unwrap_or(1) != current_key_epoch
        {
            return Err(AppError::Unauthorized(
                "web session expired after vault key rotation".into(),
            ));
        }

        // ── 6. Token renewal (if expiry is ≤5 min away) ──────────────────────
        let renewal_threshold = claims.exp - chrono::Duration::minutes(5);
        let new_token = if now >= renewal_threshold {
            let remaining_secs = (claims.hard_cap - now).num_seconds().max(0) as u64;
            let old_ttl_secs = (claims.exp - now).num_seconds().max(0) as u64;

            // Once `exp` is already pinned at the session's hard cap, issuing
            // again produces an identical exp with a fresh jti — pure churn
            // (a revoke + issue + track write on every single request for the
            // rest of the session) with no extension benefit. Skip it; the
            // current token rides out to the hard cap unchanged.
            if remaining_secs > 0 && claims.exp < claims.hard_cap {
                // Issue the replacement token BEFORE revoking the current
                // one: if issuance fails, the client keeps its still-valid
                // token instead of being locked out (old jti revoked with no
                // replacement, forcing a full re-auth).
                // `issue_scoped`, not `issue`: renewing with the default scope
                // would launder an ephemeral web-session token into a device
                // token every 10 minutes, quietly undoing the RT-4 boundary.
                let (refreshed, new_jti) = ts.issue_scoped_at_epoch(
                    claims.user_id,
                    claims.device_id,
                    Some(claims.hard_cap),
                    claims.scope,
                    claims.key_epoch,
                )?;
                let _ =
                    rate_limit::track_device_jti(store, &claims.device_id.to_string(), &new_jti);
                if old_ttl_secs > 0 {
                    let _ =
                        store.set_ex(&format!("jti:revoked:{}", claims.jti), &[1u8], old_ttl_secs);
                }
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
            key_epoch: claims.key_epoch,
            new_token,
            scope: claims.scope,
        })
    }
}

impl AuthSession {
    /// Return the epoch which must still be current at a vault mutation's SQL
    /// boundary. A legacy web token is epoch 1; device tokens follow the
    /// request's already-resolved epoch (including device-only shadow writes).
    pub fn write_epoch_authority(&self, resolved_epoch: i64) -> Result<i64, AppError> {
        if self.scope != TokenScope::WebSession {
            return Ok(resolved_epoch);
        }
        let token_epoch = self.key_epoch.unwrap_or(1);
        if token_epoch != resolved_epoch {
            return Err(AppError::Rekeyed(format!(
                "web session was granted at vault epoch {token_epoch}, not write epoch {resolved_epoch}"
            )));
        }
        Ok(token_epoch)
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

/// An [`AuthSession`] that is definitely a real enrolled device (red-team RT-4).
///
/// Extract this instead of `AuthSession` on any route whose effect outlives the
/// caller — anything touching recovery material, device revocation, permanent
/// enrollment, or the account itself. An ephemeral web session is granted access
/// to a *vault*, not authority over the *account*, and
/// `EPHEMERAL_WEB_ACCESS_DESIGN.md` §2 says so in as many words: "temporary",
/// "revocable at any time", "no permanent device enrollment". Those are
/// authorization claims, and until this existed nothing enforced them — the
/// browser's token was byte-for-byte as powerful as a laptop's.
///
/// It derefs to `AuthSession`, so handlers use it exactly as before.
#[derive(Clone, Debug)]
pub struct DeviceSession(pub AuthSession);

impl std::ops::Deref for DeviceSession {
    type Target = AuthSession;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[axum::async_trait]
impl FromRequestParts<AppState> for DeviceSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = AuthSession::from_request_parts(parts, state).await?;
        if session.scope != TokenScope::Device {
            tracing::warn!(
                user_id = %session.user_id,
                session_id = %session.device_id,
                "web-session token refused on a device-only route"
            );
            return Err(AppError::Forbidden(
                "this action requires one of your own devices; a temporary web session cannot perform it"
                    .into(),
            ));
        }
        Ok(DeviceSession(session))
    }
}
