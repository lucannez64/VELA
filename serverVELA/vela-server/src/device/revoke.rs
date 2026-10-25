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

use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_session_policy::revocation_driver::{
    begin_revocation, on_cascade_completed, on_lockout_completed, on_record_completed,
    on_target_looked_up, ActorObservation, CascadeObservation, DeviceLookupObservation,
    LockoutObservation, RecordObservation, RevocationEffect, RevocationFailure, TargetObservation,
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

pub async fn post_revoke(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>> {
    // The extractor already verified the PASETO and the active device row. The
    // driver re-checks both facts so a rewired or future caller cannot skip
    // them; a revoked actor gets no effect at all.
    let start = begin_revocation(ActorObservation {
        authenticated: true,
        device_active: true,
    });
    debug_assert!(matches!(start.effect, RevocationEffect::LookupTarget));
    let mut driver = start.driver;

    let rows = match state
        .sqldb
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = ?",
            vec![TursoValue::Text(body.target_device_id.to_string())],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            let transition = on_target_looked_up(driver, DeviceLookupObservation::QueryFailed);
            debug_assert!(matches!(
                transition.effect,
                RevocationEffect::Fail(RevocationFailure::TargetQueryStorage)
            ));
            return Err(AppError::Internal(error.to_string()));
        }
    };

    let target = match rows.first() {
        None => {
            let transition = on_target_looked_up(driver, DeviceLookupObservation::Absent);
            return match transition.effect {
                RevocationEffect::Fail(failure) => Err(revocation_failure_error(failure)),
                _ => Err(AppError::Internal(
                    "revocation driver produced an unexpected lookup effect".into(),
                )),
            };
        }
        Some(row) => match crate::db::parse_device_row_turso(row) {
            Ok(target) => target,
            Err(error) => {
                let transition = on_target_looked_up(driver, DeviceLookupObservation::Malformed);
                debug_assert!(matches!(
                    transition.effect,
                    RevocationEffect::Fail(RevocationFailure::TargetParseStorage)
                ));
                return Err(error);
            }
        },
    };

    let transition = on_target_looked_up(
        driver,
        DeviceLookupObservation::Present(TargetObservation {
            same_account: target.user_id == session.user_id,
            already_revoked: target.revoked,
        }),
    );
    driver = transition.driver;

    match transition.effect {
        RevocationEffect::LockoutDevice => {}
        RevocationEffect::Fail(failure) => return Err(revocation_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "revocation driver produced an unexpected target effect".into(),
            ));
        }
    }

    let device_id_str = body.target_device_id.to_string();
    let sentinel_key = format!("device:revoked:{}", body.target_device_id);

    // Stop the device *before* recording that it is stopped. Both writes are
    // one logical lockout effect; the driver has already refused an
    // unauthenticated actor, a missing/cross-account target and a terminal
    // prior state.
    let lockout = match rate_limit::revoke_all_device_jtis(&state.store, &device_id_str) {
        Ok(()) => state
            .store
            .set_ex(&sentinel_key, &[1u8], rate_limit::TOKEN_MAX_LIFETIME_SECS),
        Err(error) => Err(error),
    };
    let lockout_observation = match &lockout {
        Ok(()) => LockoutObservation::Applied,
        Err(_) => LockoutObservation::StorageFailed,
    };
    let transition = on_lockout_completed(driver, lockout_observation);
    driver = transition.driver;
    if let Err(error) = lockout {
        debug_assert!(matches!(
            transition.effect,
            RevocationEffect::Fail(RevocationFailure::LockoutStorage)
        ));
        return Err(error);
    }

    match transition.effect {
        RevocationEffect::RecordRevocation => {
            let now = Utc::now().to_rfc3339();
            let record = state
                .sqldb
                .execute(
                    "UPDATE devices SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE id = ?",
                    vec![
                        TursoValue::Text(now),
                        TursoValue::Text(session.device_id.to_string()),
                        TursoValue::Text(body.target_device_id.to_string()),
                    ],
                )
                .await;
            let record_observation = match &record {
                Ok(_) => RecordObservation::Updated,
                Err(_) => RecordObservation::Failed,
            };
            let transition = on_record_completed(driver, record_observation);
            driver = transition.driver;
            if let Err(error) = record {
                debug_assert!(matches!(
                    transition.effect,
                    RevocationEffect::Fail(RevocationFailure::RecordStorage)
                ));
                return Err(AppError::Internal(error.to_string()));
            }
            match transition.effect {
                RevocationEffect::CascadeWebSessions => {}
                _ => {
                    return Err(AppError::Internal(
                        "revocation driver produced an unexpected record effect".into(),
                    ));
                }
            }
        }
        RevocationEffect::CascadeWebSessions => {
            // Already-revoked retry: repeat the cascade but skip the SQL
            // record, exactly as the historical branch did.
        }
        RevocationEffect::Fail(failure) => return Err(revocation_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "revocation driver produced an unexpected lockout effect".into(),
            ));
        }
    }

    // Browser sessions this device approved inherit its trust, so they end
    // with it. This runs after the SQL row says revoked: a concurrent grant by
    // the device either committed before that (and is found here) or is
    // refused by the grant's `revoked = 0` guard.
    let cascade =
        revoke_web_sessions_approved_by(&state, session.user_id, body.target_device_id).await;
    let cascade_observation = match &cascade {
        Ok(()) => CascadeObservation::Completed,
        Err(_) => CascadeObservation::StorageFailed,
    };
    let transition = on_cascade_completed(driver, cascade_observation);
    if let Err(error) = cascade {
        debug_assert!(matches!(
            transition.effect,
            RevocationEffect::Fail(RevocationFailure::CascadeStorage)
        ));
        return Err(error);
    }

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
        RevocationEffect::Fail(failure) => Err(revocation_failure_error(failure)),
        _ => Err(AppError::Internal(
            "revocation driver produced an unexpected cascade effect".into(),
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
