//! POST /auth/logout
//!
//! Revokes the caller's current JTI so the token cannot be reused.
//! The client should discard the token locally after calling this endpoint.
//!
//! ## Spec reference (§6 Session Lifecycle)
//!
//! > "On device revocation or explicit logout, the token's `jti` is added to
//! > the revocation set with a TTL equal to the token's remaining lifetime."
//!
//! The decision (write exactly one JTI marker; a successful write authorizes
//! the response and a failed write is terminal) lives in the pure
//! [`vela_session_policy::revocation_driver::logout_step`] driver. This handler
//! only performs the returned effect.

use axum::{extract::State, http::HeaderMap};
use vela_session_policy::revocation_driver::{
    begin_logout, on_logout_completed, LogoutEffect, LogoutFailure, LogoutObservation,
};

use crate::{
    error::{AppError, Result},
    middleware::AuthSession,
    state::AppState,
};

pub async fn post_logout(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, &'static str)> {
    let start = begin_logout();
    debug_assert!(matches!(start.effect, LogoutEffect::RevokeJti));

    let write = state
        .store
        .set_ex(&format!("jti:revoked:{}", session.jti), &[1u8], 15 * 60);
    let observation = match &write {
        Ok(()) => LogoutObservation::Applied,
        Err(_) => LogoutObservation::StorageFailed,
    };
    let transition = on_logout_completed(start.driver, observation);
    if let Err(error) = write {
        debug_assert!(matches!(
            transition.effect,
            LogoutEffect::Fail(LogoutFailure::Storage)
        ));
        return Err(error);
    }

    match transition.effect {
        LogoutEffect::Complete => {}
        LogoutEffect::Fail(_) => {
            return Err(AppError::Internal("logout marker was not written".into()))
        }
        _ => {
            return Err(AppError::Internal(
                "logout driver produced an unexpected effect".into(),
            ))
        }
    }

    tracing::info!(
        user_id = %session.user_id,
        device_id = %session.device_id,
        jti = %session.jti,
        "explicit logout — JTI revoked"
    );

    // Logout must never advertise a replacement credential. The extractor
    // suppresses renewal on this route as well.
    Ok((HeaderMap::new(), "logged out"))
}
