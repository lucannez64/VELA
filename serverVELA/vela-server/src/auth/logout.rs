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
//! expands [`vela_session_policy::logout_interpreter!`] with `await`: the same
//! loop text the policy crate expands into the synchronous `run_logout` that
//! hax extracts and F* checks.

use axum::{extract::State, http::HeaderMap};
use vela_session_policy::revocation_driver::{LogoutEffect, LogoutFailure, LogoutObservation};

use crate::{
    error::{AppError, Result},
    middleware::AuthSession,
    state::AppState,
};

/// The I/O behind the one logout effect: the `jti:revoked:` marker with the
/// remaining-lifetime TTL. The original error is kept so the response carries
/// it, exactly as the hand-written handler returned it.
struct LogoutJtiIo<'a> {
    state: &'a AppState,
    jti: String,
    error: Option<AppError>,
}

impl LogoutJtiIo<'_> {
    async fn revoke_jti(&mut self) -> LogoutObservation {
        match self
            .state
            .store
            .set_ex(&format!("jti:revoked:{}", self.jti), &[1u8], 15 * 60)
        {
            Ok(()) => LogoutObservation::Applied,
            Err(error) => {
                self.error = Some(error);
                LogoutObservation::StorageFailed
            }
        }
    }
}

pub async fn post_logout(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, &'static str)> {
    let mut io = LogoutJtiIo {
        state: &state,
        jti: session.jti.clone(),
        error: None,
    };
    // The proved loop: exactly one marker write, then the verdict.
    let transition = vela_session_policy::logout_interpreter!(io, await);

    match transition.effect {
        LogoutEffect::Complete => {}
        LogoutEffect::Fail(LogoutFailure::Storage) if io.error.is_some() => {
            return Err(io.error.take().expect("checked above"))
        }
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
