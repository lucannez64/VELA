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
    error::{AppError, Result},
    middleware::DeviceSession,
    rate_limit,
    sqldb::{Db as _, TursoValue, TxGuard},
    state::AppState,
};

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
struct DeleteAccountIo<'a> {
    state: &'a AppState,
    account: String,
    device_ids: Vec<String>,
    web_session_ids: Vec<String>,
    tx: Option<TxGuard>,
    error: Option<AppError>,
}

impl DeleteAccountIo<'_> {
    fn fail(&mut self, error: impl ToString) {
        if self.error.is_none() {
            self.error = Some(AppError::Internal(error.to_string()));
        }
    }

    async fn scan_ids(&mut self, sql: &str, params: Vec<TursoValue>) -> (ScanObservation, Vec<String>) {
        match self.state.sqldb.query(sql, params).await {
            Ok(rows) => (
                ScanObservation::Rows,
                rows.iter().filter_map(|row| row.text(0).map(String::from)).collect(),
            ),
            Err(error) => {
                self.fail(error);
                (ScanObservation::QueryFailed, Vec::new())
            }
        }
    }

    // ── 1. Lock every device out before touching the database ──────────────

    async fn scan_devices(&mut self) -> ScanObservation {
        let params = vec![TursoValue::Text(self.account.clone())];
        let (observation, ids) = self.scan_ids("SELECT id FROM devices WHERE user_id = ?", params).await;
        self.device_ids = ids;
        observation
    }

    /// A store error is ignored, as it always was: the rows are about to be
    /// deleted, so a failed lockout can only shorten the window in which a
    /// stolen token still works.
    async fn lockout_devices(&mut self) -> LockoutObservation {
        for id in &self.device_ids {
            let _ = rate_limit::revoke_all_device_jtis(&self.state.store, id);
        }
        LockoutObservation::Applied
    }

    // ── 2. Lock every web session out (owned or approved) ──────────────────
    //
    // Pending sessions started from a browser have `user_id = NULL` and only
    // name the account in `approver_user_id` (POST /web-session/start is
    // unauthenticated). They can never be granted once the account is gone, so
    // they are part of the account's footprint too — otherwise a deleted user
    // id lingers in the table for the pending TTL.

    async fn scan_web_sessions(&mut self) -> ScanObservation {
        let params = vec![
            TursoValue::Text(self.account.clone()),
            TursoValue::Text(self.account.clone()),
        ];
        let (observation, ids) = self
            .scan_ids(
                "SELECT id FROM web_sessions WHERE user_id = ? OR approver_user_id = ?",
                params,
            )
            .await;
        self.web_session_ids = ids;
        observation
    }

    async fn lockout_web_sessions(&mut self) -> LockoutObservation {
        for id in &self.web_session_ids {
            let _ = self.state.store.set_ex(
                &format!("device:revoked:{id}"),
                &[1u8],
                crate::web_session::MAX_TTL_SECS as u64,
            );
            let _ = rate_limit::revoke_all_device_jtis(&self.state.store, id);
        }
        LockoutObservation::Applied
    }

    // ── 3. One SQL transaction for every deletion ──────────────────────────
    //
    // A crash or database error part-way leaves the account intact instead of
    // partly deleted. The store-side revocations above run first and only ever
    // lock out, so they are safe to leave in place if this transaction rolls
    // back (dropping `tx` rolls it back).

    async fn begin_transaction(&mut self) -> TransactionObservation {
        match self.state.sqldb.tx().await {
            Ok(tx) => {
                self.tx = Some(tx);
                TransactionObservation::Begun
            }
            Err(error) => {
                self.fail(error);
                TransactionObservation::Failed
            }
        }
    }

    async fn delete_table(&mut self, table: DeletionTable) -> TableDeleteObservation {
        let sql = match table {
            DeletionTable::WebSessions => {
                "DELETE FROM web_sessions WHERE user_id = ? OR approver_user_id = ?"
            }
            DeletionTable::ShareInbox => {
                "DELETE FROM share_inbox WHERE recipient_user_id = ? OR sender_user_id = ?"
            }
            DeletionTable::SharedItems => {
                "DELETE FROM shared_items WHERE recipient_user_id = ? OR sender_user_id = ?"
            }
            DeletionTable::Sends => "DELETE FROM sends WHERE owner_user_id = ?",
            DeletionTable::VaultChunks => "DELETE FROM vault_chunks WHERE user_id = ?",
            DeletionTable::OramBuckets => "DELETE FROM oram_buckets WHERE user_id = ?",
            DeletionTable::Devices => "DELETE FROM devices WHERE user_id = ?",
        };
        // The three two-sided tables name the account in both columns.
        let params = match table {
            DeletionTable::WebSessions | DeletionTable::ShareInbox | DeletionTable::SharedItems => {
                vec![
                    TursoValue::Text(self.account.clone()),
                    TursoValue::Text(self.account.clone()),
                ]
            }
            _ => vec![TursoValue::Text(self.account.clone())],
        };
        let Some(tx) = self.tx.as_ref() else {
            self.fail("account deletion transaction is not open");
            return TableDeleteObservation::Failed;
        };
        match tx.execute(sql, params).await {
            Ok(_) => TableDeleteObservation::Deleted,
            Err(error) => {
                self.fail(error);
                TableDeleteObservation::Failed
            }
        }
    }

    /// Web-session-only accounts legitimately have zero rows in `devices` (a
    /// web-session RW token uses session_id as device_id and carries no devices
    /// row — see the comment in middleware.rs), so device count is not a valid
    /// existence signal. The `users` delete's own affected-row count is the
    /// account record.
    async fn delete_users(&mut self) -> UsersDeleteObservation {
        let Some(tx) = self.tx.as_ref() else {
            self.fail("account deletion transaction is not open");
            return UsersDeleteObservation::Failed;
        };
        match tx
            .execute(
                "DELETE FROM users WHERE id = ?",
                vec![TursoValue::Text(self.account.clone())],
            )
            .await
        {
            Ok(0) => UsersDeleteObservation::Absent,
            Ok(_) => UsersDeleteObservation::Deleted,
            Err(error) => {
                self.fail(error);
                UsersDeleteObservation::Failed
            }
        }
    }

    async fn commit(&mut self) -> CommitObservation {
        let Some(tx) = self.tx.take() else {
            self.fail("account deletion transaction is not open");
            return CommitObservation::Failed;
        };
        match tx.commit().await {
            Ok(()) => CommitObservation::Committed,
            Err(error) => {
                self.fail(error);
                CommitObservation::Failed
            }
        }
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
        state: &state,
        account: session.user_id.to_string(),
        device_ids: Vec::new(),
        web_session_ids: Vec::new(),
        tx: None,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_session_policy::deletion_interpreter!(io, actor, await);
    // Dropping an uncommitted transaction rolls it back.
    drop(io.tx.take());

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
