//! `POST /device/revoke` (SPEC §6).
//!
//! Every post-validation decision lives in the pure
//! [`vela_session_policy::revocation_driver`] driver: whether the actor may act,
//! how the target row is classified, the same-account and already-revoked
//! branches, and the effect order. This handler only performs the returned
//! effect and maps a terminal driver failure back to the historical status and
//! message.
//!
//! The order is a security property, not an implementation detail: the target
//! is locked out (every tracked JTI plus the `device:revoked:` sentinel)
//! *before* the durable SQL `revoked = 1` record. If the update fails, the
//! device is already stopped and the row can be reconciled; the reverse order
//! would leave a device marked revoked whose existing tokens still work.
//!
//! The handler expands [`vela_session_policy::revocation_interpreter!`] with
//! `await`: the same loop text the policy crate expands into the synchronous
//! `run_revocation` that hax extracts and F* checks. Only the effect the driver
//! just emitted is performed, and nothing after its verdict.

use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_session_policy::revocation_driver::{
    ActorObservation, CascadeObservation, DeviceLookupObservation, LockoutObservation,
    RecordObservation, RevocationEffect, RevocationFailure, TargetObservation,
};

use crate::{
    error::{AppError, Result},
    middleware::DeviceSession,
    rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub target_device_id: Uuid,
}

#[derive(Serialize)]
pub struct RevokeResponse {
    pub revoked: Uuid,
}

fn revocation_failure_error(failure: RevocationFailure) -> AppError {
    match failure {
        RevocationFailure::Unauthenticated => {
            AppError::Unauthorized("device has been revoked".into())
        }
        RevocationFailure::TargetNotFound => AppError::NotFound("device not found".into()),
        RevocationFailure::CrossAccount => {
            AppError::Forbidden("cannot revoke a device belonging to a different user".into())
        }
        RevocationFailure::AlreadyRevoked => {
            AppError::BadRequest("device is already revoked".into())
        }
        RevocationFailure::TargetQueryStorage => AppError::Internal("device lookup failed".into()),
        RevocationFailure::TargetParseStorage => {
            AppError::Internal("device row could not be decoded".into())
        }
        RevocationFailure::LockoutStorage => AppError::Internal("device lockout failed".into()),
        RevocationFailure::RecordStorage => {
            AppError::Internal("device revocation record failed".into())
        }
        RevocationFailure::CascadeStorage => {
            AppError::Internal("web-session revocation failed".into())
        }
    }
}

/// The I/O behind each revocation effect. The driver decides which method runs
/// and when (through the shared `revocation_interpreter!` loop, proved in F* as
/// `run_revocation`); each method only performs its effect and reports the
/// outcome. Storage errors are kept so the response carries the original error,
/// exactly as the hand-written handler returned it.
struct RevokeDeviceIo<'a> {
    state: &'a AppState,
    /// The authenticated caller's account and device.
    actor_user_id: Uuid,
    actor_device_id: Uuid,
    target_device_id: Uuid,
    device_id_str: String,
    sentinel_key: String,
    error: Option<AppError>,
}

impl RevokeDeviceIo<'_> {
    fn fail(&mut self, error: impl ToString) {
        if self.error.is_none() {
            self.error = Some(AppError::Internal(error.to_string()));
        }
    }

    /// ── The target `devices` row ────────────────────────────────────────
    async fn lookup_target(&mut self) -> DeviceLookupObservation {
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT id, user_id, device_name, device_type, last_active,
                    hybrid_ek, hybrid_vk,
                    enrolled_by, rms_capsule, revoked,
                    revoked_at, revoked_by, created_at
             FROM devices
             WHERE id = ?",
                vec![TursoValue::Text(self.device_id_str.clone())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.fail(error);
                return DeviceLookupObservation::QueryFailed;
            }
        };
        match rows.first() {
            None => DeviceLookupObservation::Absent,
            Some(row) => match crate::db::parse_device_row_turso(row) {
                Ok(target) => DeviceLookupObservation::Present(TargetObservation {
                    same_account: target.user_id == self.actor_user_id,
                    already_revoked: target.revoked,
                }),
                Err(error) => {
                    self.error = Some(error);
                    DeviceLookupObservation::Malformed
                }
            },
        }
    }

    /// ── Stop the device before recording that it is stopped ─────────────
    ///
    /// Both writes are one logical lockout effect. A failed JTI enumeration
    /// skips the sentinel, exactly as before.
    async fn lockout_device(&mut self) -> LockoutObservation {
        let lockout = match rate_limit::revoke_all_device_jtis(
            &self.state.store,
            &self.device_id_str,
        ) {
            Ok(()) => self.state.store.set_ex(
                &self.sentinel_key,
                &[1u8],
                rate_limit::TOKEN_MAX_LIFETIME_SECS,
            ),
            Err(error) => Err(error),
        };
        match lockout {
            Ok(()) => LockoutObservation::Applied,
            Err(error) => {
                self.error = Some(error);
                LockoutObservation::StorageFailed
            }
        }
    }

    /// ── The durable SQL row ─────────────────────────────────────────────
    async fn record_revocation(&mut self) -> RecordObservation {
        let now = Utc::now().to_rfc3339();
        let record = self
            .state
            .sqldb
            .execute(
                "UPDATE devices SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE id = ?",
                vec![
                    TursoValue::Text(now),
                    TursoValue::Text(self.actor_device_id.to_string()),
                    TursoValue::Text(self.target_device_id.to_string()),
                ],
            )
            .await;
        match record {
            Ok(_) => RecordObservation::Updated,
            Err(error) => {
                self.fail(error);
                RecordObservation::Failed
            }
        }
    }

    /// ── End the web sessions the target approved ────────────────────────
    ///
    /// Browser sessions this device approved inherit its trust, so they end
    /// with it. This runs after the SQL row says revoked: a concurrent grant by
    /// the device either committed before that (and is found here) or is
    /// refused by the grant's `revoked = 0` guard.
    async fn cascade_web_sessions(&mut self) -> CascadeObservation {
        match revoke_web_sessions_approved_by(
            self.state,
            self.actor_user_id,
            self.target_device_id,
        )
        .await
        {
            Ok(()) => CascadeObservation::Completed,
            Err(error) => {
                self.error = Some(error);
                CascadeObservation::StorageFailed
            }
        }
    }
}

pub async fn post_revoke(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>> {
    // The extractor already verified the PASETO and the active device row. The
    // driver re-checks both facts so a rewired or future caller cannot skip
    // them; a revoked actor gets no effect at all.
    let actor = ActorObservation {
        authenticated: true,
        device_active: true,
    };
    let mut io = RevokeDeviceIo {
        state: &state,
        actor_user_id: session.user_id,
        actor_device_id: session.device_id,
        target_device_id: body.target_device_id,
        device_id_str: body.target_device_id.to_string(),
        sentinel_key: format!("device:revoked:{}", body.target_device_id),
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_session_policy::revocation_interpreter!(io, actor, await);

    match transition.effect {
        RevocationEffect::Complete => {
            tracing::info!(
                target_device = %body.target_device_id,
                revoked_by    = %session.device_id,
                user_id       = %session.user_id,
                "device revoked"
            );

            Ok(Json(RevokeResponse {
                revoked: body.target_device_id,
            }))
        }
        RevocationEffect::Fail(
            RevocationFailure::TargetQueryStorage
            | RevocationFailure::TargetParseStorage
            | RevocationFailure::LockoutStorage
            | RevocationFailure::RecordStorage
            | RevocationFailure::CascadeStorage,
        ) if io.error.is_some() => Err(io.error.take().expect("checked above")),
        RevocationEffect::Fail(failure) => Err(revocation_failure_error(failure)),
        _ => Err(AppError::Internal(
            "revocation driver reached no verdict".into(),
        )),
    }
}

/// End every live web session that `device_id` approved: reject its issued
/// RW tokens first (sled sentinel, as `DELETE /web-session/:id` does), then
/// mark the rows revoked and drop their capsules.
async fn revoke_web_sessions_approved_by(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<()> {
    let rows = state
        .sqldb
        .query(
            "SELECT id FROM web_sessions
             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    for row in &rows {
        if let Some(id) = row.text(0) {
            state.store.set_ex(
                &format!("device:revoked:{id}"),
                &[1u8],
                crate::web_session::MAX_TTL_SECS as u64,
            )?;
            rate_limit::revoke_all_device_jtis(&state.store, id)?;
        }
    }
    state
        .sqldb
        .execute(
            "UPDATE web_sessions SET status = 'revoked', capsule = NULL
             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !rows.is_empty() {
        tracing::info!(
            approving_device = %device_id,
            sessions = rows.len(),
            "web sessions revoked with their approving device"
        );
    }
    Ok(())
}
