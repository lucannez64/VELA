//! The thin loop behind every session executor method (F-1).
//!
//! An executor method builds a typed plan with `vela_session_policy::store`,
//! runs it here (render each statement, run it, stop at the first failure)
//! and hands the per-statement outcomes to the matching `classify_*`. The
//! plans and classifiers are proved in F* against a store model; this module
//! is the part that model trusts, and `session_conformance.rs` checks it, with
//! injected failures, against a real turso database and a real sled store.

use vela_session_policy::store::{
    render_sql, render_store, Rendered, RenderedStore, SqlStmt, StoreOp, StoreOutcome, StoreStmt,
    WriteOutcome,
};

use crate::error::AppError;
use crate::rate_limit;
use crate::sqldb::{Db as _, TursoDb, TursoValue, TxGuard, VelaRow};
use crate::store::Store;

/// Where an executor's SQL statements run. When a transaction is open every
/// statement runs on it; `begin` opens one and `commit` publishes it.
pub(crate) trait SessionSql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>>;
    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64>;
    /// Like `execute`, but fails unless the handler's transaction is open (the
    /// deletion handler's historical guard).
    async fn execute_in_tx(
        &mut self,
        sql: &str,
        params: Vec<TursoValue>,
    ) -> anyhow::Result<u64>;
    async fn begin(&mut self) -> anyhow::Result<()>;
    async fn commit(&mut self) -> anyhow::Result<()>;
    /// Drops an open transaction, rolling it back.
    fn rollback(&mut self);
}

/// The connection pool plus, once the handler opens it, its transaction.
pub(crate) struct DbSql<'a> {
    pub pool: &'a TursoDb,
    pub tx: Option<TxGuard>,
}

impl SessionSql for DbSql<'_> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        match self.tx.as_ref() {
            Some(tx) => tx.query(sql, params).await,
            None => self.pool.query(sql, params).await,
        }
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        match self.tx.as_ref() {
            Some(tx) => tx.execute(sql, params).await,
            None => self.pool.execute(sql, params).await,
        }
    }

    async fn execute_in_tx(
        &mut self,
        sql: &str,
        params: Vec<TursoValue>,
    ) -> anyhow::Result<u64> {
        match self.tx.as_ref() {
            Some(tx) => tx.execute(sql, params).await,
            None => Err(anyhow::anyhow!(
                "account deletion transaction is not open"
            )),
        }
    }

    async fn begin(&mut self) -> anyhow::Result<()> {
        self.tx = Some(self.pool.tx().await?);
        Ok(())
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        match self.tx.take() {
            Some(tx) => tx.commit().await,
            None => Err(anyhow::anyhow!(
                "account deletion transaction is not open"
            )),
        }
    }

    fn rollback(&mut self) {
        drop(self.tx.take());
    }
}

/// The key-value operations a session executor performs.
pub(crate) trait SessionStore {
    fn set_ex(&mut self, key: &str, value: u8, ttl: u64) -> anyhow::Result<()>;
    /// `rate_limit::revoke_all_device_jtis`: every tracked JTI of `device` is
    /// written to `jti:revoked:` and the tracking set is dropped.
    fn revoke_jtis(&mut self, device: &str) -> anyhow::Result<()>;
}

/// The production sled store.
pub(crate) struct SledStore<'a>(pub &'a Store);

impl SessionStore for SledStore<'_> {
    fn set_ex(&mut self, key: &str, value: u8, ttl: u64) -> anyhow::Result<()> {
        self.0.set_ex(key, &[value], ttl)?;
        Ok(())
    }

    fn revoke_jtis(&mut self, device: &str) -> anyhow::Result<()> {
        rate_limit::revoke_all_device_jtis(self.0, device)?;
        Ok(())
    }
}

fn text_params(values: Vec<String>) -> Vec<TursoValue> {
    values.into_iter().map(TursoValue::Text).collect()
}

/// Runs one SQL plan in order, stopping at the first failure. Returns one
/// outcome per statement run and the error that stopped it, if any.
pub(crate) async fn run_sql<S: SessionSql>(
    sql: &mut S,
    plan: &[SqlStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render_sql(stmt) {
            Rendered::Query { sql: text, params } => {
                sql.query(text, text_params(params)).await.map(|rows| rows.len() as u64)
            }
            Rendered::Execute { sql: text, params } => {
                sql.execute(text, text_params(params)).await
            }
            Rendered::Commit => sql.commit().await.map(|()| 0),
        };
        match result {
            Ok(rows) => outcomes.push(WriteOutcome::Applied(rows)),
            Err(error) => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, Some(error));
            }
        }
    }
    (outcomes, None)
}

/// Runs the one read statement of a plan, returning its rows.
pub(crate) async fn run_read<S: SessionSql>(
    sql: &mut S,
    stmt: SqlStmt,
) -> (Option<Vec<VelaRow>>, Option<anyhow::Error>) {
    match render_sql(&stmt) {
        Rendered::Query { sql: text, params } => {
            match sql.query(text, text_params(params)).await {
                Ok(rows) => (Some(rows), None),
                Err(error) => (None, Some(error)),
            }
        }
        _ => (
            None,
            Some(anyhow::anyhow!("a write statement in a read plan")),
        ),
    }
}

/// Runs one SQL plan where every statement must run on the open transaction.
pub(crate) async fn run_sql_in_tx<S: SessionSql>(
    sql: &mut S,
    plan: &[SqlStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render_sql(stmt) {
            Rendered::Execute { sql: text, params } => {
                sql.execute_in_tx(text, text_params(params)).await
            }
            Rendered::Query { sql: text, params } => {
                sql.query(text, text_params(params)).await.map(|rows| rows.len() as u64)
            }
            Rendered::Commit => sql.commit().await.map(|()| 0),
        };
        match result {
            Ok(rows) => outcomes.push(WriteOutcome::Applied(rows)),
            Err(error) => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, Some(error));
            }
        }
    }
    (outcomes, None)
}

/// Runs one store plan in order, stopping at the first failure.
pub(crate) fn run_store<K: SessionStore>(
    store: &mut K,
    plan: &[StoreStmt],
) -> (Vec<StoreOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render_store(stmt) {
            RenderedStore {
                op: StoreOp::SetEx,
                key,
                value,
                ttl,
            } => store.set_ex(&key, value, ttl),
            RenderedStore {
                op: StoreOp::RevokeJtis,
                key,
                ..
            } => store.revoke_jtis(&key),
        };
        match result {
            Ok(()) => outcomes.push(StoreOutcome::Applied),
            Err(error) => {
                outcomes.push(StoreOutcome::Failed);
                return (outcomes, Some(error));
            }
        }
    }
    (outcomes, None)
}

/// The first row's id column, as the id scans read it.
pub(crate) fn id_rows(rows: &[VelaRow]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| row.text(0).map(String::from))
        .collect()
}

/// The first row decoded as the target lookup's view (the caller keeps the
/// parse error for `Malformed`).
pub(crate) fn target_row_view(target: &crate::db::DeviceRow) -> vela_session_policy::store::TargetRowView {
    vela_session_policy::store::TargetRowView {
        user_id: Some(target.user_id.to_string()),
        revoked: Some(if target.revoked { 1 } else { 0 }),
    }
}

/// The exact historical `AppError` an effect failed with (a store or SQL error
/// is re-wrapped as `Internal` with the same message the handler returned).
pub(crate) fn keep_error(slot: &mut Option<AppError>, error: anyhow::Error) {
    if slot.is_none() {
        *slot = Some(match error.downcast::<AppError>() {
            Ok(error) => error,
            Err(error) => AppError::Internal(error.to_string()),
        });
    }
}
