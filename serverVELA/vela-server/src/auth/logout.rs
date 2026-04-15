//! POST /auth/logout
//!
//! Revokes the caller's current JTI so the token cannot be reused.
//! The client should discard the token locally after calling this endpoint.
//!
//! ## Spec reference (§6 Session Lifecycle)
//!
//! > "On device revocation or explicit logout, the token's `jti` is added to
//! > the revocation set with a TTL equal to the token's remaining lifetime."

use axum::{extract::State, http::HeaderMap};

use crate::{
    error::Result,
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

pub async fn post_logout(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, &'static str)> {
    state
        .store
        .set_ex(&format!("jti:revoked:{}", session.jti), &[1u8], 15 * 60)?;

    tracing::info!(
        user_id = %session.user_id,
        device_id = %session.device_id,
        jti = %session.jti,
        "explicit logout — JTI revoked"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, "logged out"))
}
