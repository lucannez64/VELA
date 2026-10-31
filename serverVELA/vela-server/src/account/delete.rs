//! `DELETE /account` (permanent account deletion).
//!
//! Every post-validation decision lives in the pure
//! [`vela_session_policy::deletion_driver`] driver: whether the session may
//! delete at all, whether the two row scans succeeded, that a store-side
//! lockout failure does not abort the deletion while a scan or SQL failure
//! does, which table is deleted next, whether the `users` row existed, and
//! therefore whether to commit or to roll back. This handler only performs the
//! returned effect and maps a terminal driver failure back to the historical
//! status and message.
//!
//! The order is a security property, not an implementation detail:
//!
//! 1. every device's tracked JTIs are revoked and its `device:revoked:`
//!    sentinel written, then the same for every web session the account owns or
//!    approved. These only ever lock out, so they are safe to leave in place if
//!    the SQL transaction rolls back;
//! 2. one SQL transaction deletes `web_sessions`, `share_inbox`,
//!    `shared_items`, `sends`, `vault_chunks`, `oram_buckets` and `devices`;
//! 3. the `DELETE FROM users` row count is the account-existence signal (a
//!    web-session-only account has no `devices` row): zero rows means the
//!    account was already gone, and the transaction is rolled back with
//!    `404 account not found`;
//! 4. only then is the transaction committed.

use axum::{extract::State, http::HeaderMap, Json};
use vela_session_policy::deletion_driver::{
    CommitObservation, DeletionActorObservation, DeletionEffect, DeletionFailure, DeletionTable,
    LockoutObservation, ScanObservation, TableDeleteObservation, TransactionObservation,
    UsersDeleteObservation,
};

use crate::{
    auth::session_store::{
        id_rows, keep_error, run_read, run_sql, run_sql_in_tx, run_store, DbSql, SessionSql,
        SessionStore, SledStore,
    },
    error::{AppError, Result},
    middleware::DeviceSession,
    state::AppState,
};
use vela_session_policy::store::IdsOutcome;

/// Statuses and messages for the driver failures that are not a raw SQL error.
fn deletion_failure_error(failure: DeletionFailure) -> AppError {
    match failure {
        DeletionFailure::Unauthenticated => AppError::Unauthorized("unauthorized".into()),
        DeletionFailure::CrossAccount => {
            AppError::Forbidden("cannot delete another account".into())
        }
        DeletionFailure::AccountNotFound => AppError::NotFound("account not found".into()),
        DeletionFailure::DeviceScanStorage => {
            AppError::Internal("device lookup failed".into())
        }
        DeletionFailure::WebSessionScanStorage => {
            AppError::Internal("web-session lookup failed".into())
        }
        DeletionFailure::TransactionStorage => {
            AppError::Internal("account deletion transaction failed".into())
        }
        DeletionFailure::TableStorage => AppError::Internal("account deletion failed".into()),
        DeletionFailure::UsersStorage => AppError::Internal("account deletion failed".into()),
        DeletionFailure::CommitStorage => {
            AppError::Internal("account deletion commit failed".into())
        }
    }
}

/// The I/O behind each deletion effect. The driver decides which method runs
/// and when (through the shared `deletion_interpreter!` loop, proved in F* as
/// `run_deletion`); each method only performs its effect and reports the
/// outcome. The first storage error is kept so the response carries the
/// original message.
pub(crate) struct DeleteAccountIo<S: SessionSql, K: SessionStore> {
    pub(crate) sql: S,
    pub(crate) store: K,
    pub(crate) account: String,
    pub(crate) device_ids: Vec<String>,
    pub(crate) web_session_ids: Vec<String>,
    pub(crate) error: Option<AppError>,
}

impl<S: SessionSql, K: SessionStore> DeleteAccountIo<S, K> {
    async fn scan_ids(&mut self, plan: vela_session_policy::store::SqlStmt) -> (ScanObservation, Vec<String>) {
        let (rows, error) = run_read(&mut self.sql, plan).await;
        match rows {
            Some(rows) => {
                let ids = id_rows(&rows);
                (
                    vela_session_policy::store::classify_scan(&IdsOutcome::Ids(ids.clone())),
                    ids,
                )
            }
            None => {
                if let Some(error) = error {
                    keep_error(&mut self.error, error);
                }
                (
                    vela_session_policy::store::classify_scan(&IdsOutcome::Failed),
                    Vec::new(),
                )
            }
        }
    }

    // ── 1. Lock every device out before touching the database ──────────────

    pub(crate) async fn scan_devices(&mut self) -> ScanObservation {
        let plan = vela_session_policy::store::plan_scan_devices(self.account.clone());
        let (observation, ids) = self.scan_ids(plan).await;
        self.device_ids = ids;
        observation
    }

    /// A store error is ignored, as it always was: the rows are about to be
    /// deleted, so a failed lockout can only shorten the window in which a
    /// stolen token still works.
    pub(crate) async fn lockout_devices(&mut self) -> LockoutObservation {
        for id in &self.device_ids {
            let plan = vela_session_policy::store::plan_lockout_device(id.clone());
            let _ = run_store(&mut self.store, &plan);
        }
        vela_session_policy::store::classify_lockout_ignored(&[])
    }

    // ── 2. Lock every web session out (owned or approved) ──────────────────

    pub(crate) async fn scan_web_sessions(&mut self) -> ScanObservation {
        let plan = vela_session_policy::store::plan_scan_web_sessions(self.account.clone());
        let (observation, ids) = self.scan_ids(plan).await;
        self.web_session_ids = ids;
        observation
    }

    pub(crate) async fn lockout_web_sessions(&mut self) -> LockoutObservation {
        for id in &self.web_session_ids {
            let plan = vela_session_policy::store::plan_lockout_web_session(id.clone());
            let _ = run_store(&mut self.store, &plan);
        }
        vela_session_policy::store::classify_lockout_ignored(&[])
    }

    // ── 3. One SQL transaction for every deletion ──────────────────────────

    pub(crate) async fn begin_transaction(&mut self) -> TransactionObservation {
        match self.sql.begin().await {
            Ok(()) => vela_session_policy::store::classify_transaction(
                &vela_session_policy::store::WriteOutcome::Applied(0),
            ),
            Err(error) => {
                keep_error(&mut self.error, error);
                vela_session_policy::store::classify_transaction(
                    &vela_session_policy::store::WriteOutcome::Failed,
                )
            }
        }
    }

    pub(crate) async fn delete_table(&mut self, table: DeletionTable) -> TableDeleteObservation {
        let plan = vela_session_policy::store::plan_delete_table(self.account.clone(), table);
        let (outcomes, error) = run_sql_in_tx(&mut self.sql, &[plan]).await;
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        vela_session_policy::store::classify_table_delete(
            outcomes
                .first()
                .unwrap_or(&vela_session_policy::store::WriteOutcome::Failed),
        )
    }

    /// Web-session-only accounts legitimately have zero rows in `devices` (a
    /// web-session RW token uses session_id as device_id and carries no devices
    /// row — see the comment in middleware.rs), so device count is not a valid
    /// existence signal. The `users` delete's own affected-row count is the
    /// account record.
    pub(crate) async fn delete_users(&mut self) -> UsersDeleteObservation {
        let plan = vela_session_policy::store::plan_delete_users(self.account.clone());
        let (outcomes, error) = run_sql_in_tx(&mut self.sql, &[plan]).await;
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        vela_session_policy::store::classify_users_delete(
            outcomes
                .first()
                .unwrap_or(&vela_session_policy::store::WriteOutcome::Failed),
        )
    }

    pub(crate) async fn commit(&mut self) -> CommitObservation {
        let plan = vela_session_policy::store::plan_commit();
        let (outcomes, error) = run_sql(&mut self.sql, &[plan]).await;
        if let Some(error) = error {
            keep_error(&mut self.error, error);
        }
        vela_session_policy::store::classify_commit(
            outcomes
                .first()
                .unwrap_or(&vela_session_policy::store::WriteOutcome::Failed),
        )
    }
}

pub async fn delete_account(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    // One account id scopes the device scan, the web-session scan, all eight
    // deletes and the existence check. The driver re-checks the actor facts and
    // the single-account scope so a rewired caller cannot authorize an effect
    // for a second account; a revoked actor gets no effect at all.
    let actor = DeletionActorObservation {
        authenticated: true,
        device_active: true,
        scoped_to_session_account: true,
    };
    let mut io = DeleteAccountIo {
        sql: DbSql { pool: &state.sqldb, tx: None },
        store: SledStore(&state.store),
        account: session.user_id.to_string(),
        device_ids: Vec::new(),
        web_session_ids: Vec::new(),
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_session_policy::deletion_interpreter!(io, actor, await);
    // Dropping an uncommitted transaction rolls it back.
    io.sql.rollback();

    match transition.effect {
        DeletionEffect::Complete => {
            tracing::warn!(
                user_id = %session.user_id,
                "account permanently deleted"
            );
            Ok((
                HeaderMap::new(),
                Json(serde_json::json!({
                    "deleted": true,
                    "user_id": session.user_id.to_string(),
                })),
            ))
        }
        DeletionEffect::Fail(
            DeletionFailure::DeviceScanStorage
            | DeletionFailure::WebSessionScanStorage
            | DeletionFailure::TransactionStorage
            | DeletionFailure::TableStorage
            | DeletionFailure::UsersStorage
            | DeletionFailure::CommitStorage,
        ) if io.error.is_some() => Err(io.error.take().expect("checked above")),
        DeletionEffect::Fail(failure) => Err(deletion_failure_error(failure)),
        _ => Err(AppError::Internal(
            "account deletion driver reached no verdict".into(),
        )),
    }
}
