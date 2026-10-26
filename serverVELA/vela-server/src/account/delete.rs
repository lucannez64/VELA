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
    begin_deletion, on_commit_event, on_device_lockout_event, on_devices_scanned_event,
    on_table_deleted_event, on_transaction_observed_event, on_users_deleted_event,
    on_web_session_lockout_event, on_web_sessions_scanned_event, CommitObservation,
    DeletionActorObservation, DeletionDriver, DeletionEffect, DeletionFailure, DeletionStage,
    DeletionTable, LockoutObservation, ScanObservation, TableDeleteObservation,
    TransactionObservation, UsersDeleteObservation,
};

use crate::{
    error::{AppError, Result},
    middleware::DeviceSession,
    rate_limit,
    sqldb::{Db as _, TursoValue},
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

/// Perform the effect the driver returned, or return the driver's terminal
/// failure. `driver` is threaded through so an out-of-order effect can never be
/// executed.
fn next_step(driver: DeletionDriver, effect: DeletionEffect) -> Result<DeletionDriver> {
    match effect {
        DeletionEffect::Idle => Err(AppError::Internal(
            "account deletion driver produced no effect".into(),
        )),
        DeletionEffect::Fail(failure) => Err(deletion_failure_error(failure)),
        _ => Ok(driver),
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
    let start = begin_deletion(DeletionActorObservation {
        authenticated: true,
        device_active: true,
        scoped_to_session_account: true,
    });
    debug_assert!(matches!(start.effect, DeletionEffect::ScanDevices));
    let mut driver = next_step(start.driver, start.effect)?;

    let account = session.user_id.to_string();

    // ── 1. Lock every device out before touching the database ──────────────
    let device_rows = match state
        .sqldb
        .query(
            "SELECT id FROM devices WHERE user_id = ?",
            vec![TursoValue::Text(account.clone())],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            let transition = on_devices_scanned_event(driver, ScanObservation::QueryFailed);
            debug_assert!(matches!(
                transition.effect,
                DeletionEffect::Fail(DeletionFailure::DeviceScanStorage)
            ));
            return Err(AppError::Internal(error.to_string()));
        }
    };
    let transition = on_devices_scanned_event(driver, ScanObservation::Rows);
    driver = next_step(transition.driver, transition.effect)?;

    // Both writes are one logical lockout. A store error is ignored, as it
    // always was: the rows are about to be deleted, so a failed lockout can
    // only shorten the window in which a stolen token still works.
    for row in &device_rows {
        if let Some(id) = row.text(0) {
            let _ = rate_limit::revoke_all_device_jtis(&state.store, id);
        }
    }
    let transition = on_device_lockout_event(driver, LockoutObservation::Applied);
    driver = next_step(transition.driver, transition.effect)?;

    // ── 2. Lock every web session out (owned or approved) ──────────────────
    //
    // Pending sessions started from a browser have `user_id = NULL` and only
    // name the account in `approver_user_id` (POST /web-session/start is
    // unauthenticated). They can never be granted once the account is gone, so
    // they are part of the account's footprint too — otherwise a deleted user
    // id lingers in the table for the pending TTL.
    let web_session_rows = match state
        .sqldb
        .query(
            "SELECT id FROM web_sessions WHERE user_id = ? OR approver_user_id = ?",
            vec![
                TursoValue::Text(account.clone()),
                TursoValue::Text(account.clone()),
            ],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            let transition = on_web_sessions_scanned_event(driver, ScanObservation::QueryFailed);
            debug_assert!(matches!(
                transition.effect,
                DeletionEffect::Fail(DeletionFailure::WebSessionScanStorage)
            ));
            return Err(AppError::Internal(error.to_string()));
        }
    };
    let transition = on_web_sessions_scanned_event(driver, ScanObservation::Rows);
    driver = next_step(transition.driver, transition.effect)?;

    for row in &web_session_rows {
        if let Some(id) = row.text(0) {
            let _ = state.store.set_ex(
                &format!("device:revoked:{id}"),
                &[1u8],
                crate::web_session::MAX_TTL_SECS as u64,
            );
            let _ = rate_limit::revoke_all_device_jtis(&state.store, id);
        }
    }
    let transition = on_web_session_lockout_event(driver, LockoutObservation::Applied);
    driver = next_step(transition.driver, transition.effect)?;

    // ── 3. One SQL transaction for every deletion ──────────────────────────
    //
    // A crash or database error part-way leaves the account intact instead of
    // partly deleted. The store-side revocations above run first and only ever
    // lock out, so they are safe to leave in place if this transaction rolls
    // back.
    let tx = match state.sqldb.tx().await {
        Ok(tx) => tx,
        Err(error) => {
            let transition = on_transaction_observed_event(driver, TransactionObservation::Failed);
            debug_assert!(matches!(
                transition.effect,
                DeletionEffect::Fail(DeletionFailure::TransactionStorage)
            ));
            return Err(AppError::Internal(error.to_string()));
        }
    };
    let transition = on_transaction_observed_event(driver, TransactionObservation::Begun);
    driver = next_step(transition.driver, transition.effect)?;

    loop {
        let table = match driver.stage {
            DeletionStage::DeleteTable(table) => table,
            _ => break,
        };
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
        // The four two-sided tables name the account in both columns.
        let params = match table {
            DeletionTable::WebSessions
            | DeletionTable::ShareInbox
            | DeletionTable::SharedItems => vec![
                TursoValue::Text(account.clone()),
                TursoValue::Text(account.clone()),
            ],
            _ => vec![TursoValue::Text(account.clone())],
        };
        let delete = tx.execute(sql, params).await;
        let observation = match &delete {
            Ok(_) => TableDeleteObservation::Deleted,
            Err(_) => TableDeleteObservation::Failed,
        };
        let transition = on_table_deleted_event(driver, observation);
        driver = transition.driver;
        if let Err(error) = delete {
            debug_assert!(matches!(
                transition.effect,
                DeletionEffect::Fail(DeletionFailure::TableStorage)
            ));
            return Err(AppError::Internal(error.to_string()));
        }
        if let DeletionEffect::Fail(failure) = transition.effect {
            return Err(deletion_failure_error(failure));
        }
    }

    // Web-session-only accounts legitimately have zero rows in `devices` (a
    // web-session RW token uses session_id as device_id and carries no devices
    // row — see the comment in middleware.rs), so device count is not a valid
    // existence signal: it previously reported "account not found" for such
    // accounts even though the delete above just genuinely deleted them. The
    // `users` delete's own affected-row count is the account record.
    if !matches!(driver.stage, DeletionStage::DeleteUsers) {
        return Err(AppError::Internal(
            "account deletion driver produced an unexpected table sequence".into(),
        ));
    }
    let users_n = match tx
        .execute(
            "DELETE FROM users WHERE id = ?",
            vec![TursoValue::Text(account.clone())],
        )
        .await
    {
        Ok(n) => n,
        Err(error) => {
            let transition = on_users_deleted_event(driver, UsersDeleteObservation::Failed);
            debug_assert!(matches!(
                transition.effect,
                DeletionEffect::Fail(DeletionFailure::UsersStorage)
            ));
            return Err(AppError::Internal(error.to_string()));
        }
    };
    let observation = if users_n == 0 {
        UsersDeleteObservation::Absent
    } else {
        UsersDeleteObservation::Deleted
    };
    let transition = on_users_deleted_event(driver, observation);
    driver = transition.driver;
    match transition.effect {
        DeletionEffect::CommitTransaction => {}
        DeletionEffect::Fail(failure) => {
            // Dropping `tx` rolls the transaction back.
            return Err(deletion_failure_error(failure));
        }
        _ => {
            return Err(AppError::Internal(
                "account deletion driver produced an unexpected users effect".into(),
            ));
        }
    }

    let commit = tx.commit().await;
    let observation = match &commit {
        Ok(()) => CommitObservation::Committed,
        Err(_) => CommitObservation::Failed,
    };
    let transition = on_commit_event(driver, observation);
    if let Err(error) = commit {
        debug_assert!(matches!(
            transition.effect,
            DeletionEffect::Fail(DeletionFailure::CommitStorage)
        ));
        return Err(AppError::Internal(error.to_string()));
    }
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
        DeletionEffect::Fail(failure) => Err(deletion_failure_error(failure)),
        _ => Err(AppError::Internal(
            "account deletion driver produced an unexpected commit effect".into(),
        )),
    }
}
