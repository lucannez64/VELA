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
    RecordObservation, RevocationEffect, RevocationFailure,
};

use crate::{
    auth::session_store::{
        id_rows, keep_error, run_read, run_sql, run_store, DbSql, SessionSql, SessionStore,
        SledStore,
    },
    error::{AppError, Result},
    middleware::DeviceSession,
    state::AppState,
};
use vela_session_policy::store::{ReadOutcome, WriteOutcome};

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
pub(crate) struct RevokeDeviceIo<S: SessionSql, K: SessionStore> {
    pub(crate) sql: S,
    pub(crate) store: K,
    /// The authenticated caller's account and device.
    pub(crate) actor_user_id: Uuid,
    pub(crate) actor_device_id: Uuid,
    pub(crate) device_id_str: String,
    pub(crate) error: Option<AppError>,
}

impl<S: SessionSql, K: SessionStore> RevokeDeviceIo<S, K> {
    /// ── The target `devices` row ────────────────────────────────────────
    pub(crate) async fn lookup_target(&mut self) -> DeviceLookupObservation {
        let plan = vela_session_policy::store::plan_target_lookup(self.device_id_str.clone());
        let (rows, error) = run_read(&mut self.sql, plan).await;
        let caller = self.actor_user_id.to_string();
        let Some(rows) = rows else {
            if let Some(error) = error {
                keep_error(&mut self.error, error);
            }
            return vela_session_policy::store::classify_target(&caller, &ReadOutcome::Failed);
        };
        match rows.first() {
            None => vela_session_policy::store::classify_target(&caller, &ReadOutcome::Row(None)),
            Some(row) => match crate::db::parse_device_row_turso(row) {
                Ok(target) => vela_session_policy::store::classify_target(
                    &caller,
                    &ReadOutcome::Row(Some(crate::auth::session_store::target_row_view(&target))),
                ),
                Err(error) => {
                    self.error = Some(error);
                    DeviceLookupObservation::Malformed
                }
            },
        }
    }

    /// ── Stop the device before recording that it is stopped ─────────────
    ///
    /// Both writes are one logical lockout effect: every tracked JTI, then the
    /// sentinel. A failed JTI sweep skips the sentinel, exactly as before.
    pub(crate) async fn lockout_device(&mut self) -> LockoutObservation {
        let plan = vela_session_policy::store::plan_lockout_device(self.device_id_str.clone());
        let (outcomes, error) = run_store(&mut self.store, &plan);
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        vela_session_policy::store::classify_lockout_device(&outcomes)
    }

    /// ── The durable SQL row ─────────────────────────────────────────────
    pub(crate) async fn record_revocation(&mut self) -> RecordObservation {
        let now = Utc::now().to_rfc3339();
        let plan = vela_session_policy::store::plan_revoke_record(
            self.device_id_str.clone(),
            now,
            self.actor_device_id.to_string(),
        );
        let (outcomes, error) = run_sql(&mut self.sql, &[plan]).await;
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        let outcome = outcomes.first().copied().unwrap_or(WriteOutcome::Failed);
        vela_session_policy::store::classify_record(&outcome)
    }

    /// ── End the web sessions the target approved ────────────────────────
    ///
    /// Browser sessions this device approved inherit its trust, so they end
    /// with it. This runs after the SQL row says revoked: a concurrent grant by
    /// the device either committed before that (and is found here) or is
    /// refused by the grant's `revoked = 0` guard.
    pub(crate) async fn cascade_web_sessions(&mut self) -> CascadeObservation {
        let read = vela_session_policy::store::plan_cascade_read(
            self.device_id_str.clone(),
            self.actor_user_id.to_string(),
        );
        let (rows, error) = run_read(&mut self.sql, read).await;
        let Some(rows) = rows else {
            if let Some(error) = error {
                keep_error(&mut self.error, error);
            }
            return vela_session_policy::store::classify_cascade(false);
        };
        let ids = id_rows(&rows);
        let mut ok = true;
        for id in &ids {
            let plan = vela_session_policy::store::plan_lockout_web_session(id.clone());
            let (_, lock_error) = run_store(&mut self.store, &plan);
            if let Some(error) = lock_error {
                keep_error(&mut self.error, error);
                ok = false;
                break;
            }
        }
        if ok {
            let update = vela_session_policy::store::plan_cascade_update(
                self.device_id_str.clone(),
                self.actor_user_id.to_string(),
            );
            let (_, update_error) = run_sql(&mut self.sql, &[update]).await;
            if let Some(error) = update_error {
                keep_error(&mut self.error, error);
                ok = false;
            }
        }
        if ok && !ids.is_empty() {
            tracing::info!(
                approving_device = %self.device_id_str,
                sessions = ids.len(),
                "web sessions revoked with their approving device"
            );
        }
        vela_session_policy::store::classify_cascade(ok)
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
        sql: DbSql { pool: &state.sqldb, tx: None },
        store: SledStore(&state.store),
        actor_user_id: session.user_id,
        actor_device_id: session.device_id,
        device_id_str: body.target_device_id.to_string(),
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
