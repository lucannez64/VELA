//! The thin loop behind every session executor method (F-1).
//!
//! An executor method builds a typed plan with `vela_session_policy::store`,
//! runs it here (render each statement, run it, stop at the first failure)
//! and hands the per-statement outcomes to the matching `classify_*`. The
//! plans and classifiers are proved in F* against a store model; this module
//! is the part that model trusts, and `session_conformance.rs` checks it, with
//! injected failures, against a real turso database and a real sled store.

use vela_session_policy::store::{
    render_sql, render_store, NxOutcome, Rendered, RenderedStore, SqlStmt, StoreOp, StoreOutcome,
    StoreStmt, TakeOutcome, WriteOutcome,
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
    /// Like `execute`, but fails with `closed` unless the handler's
    /// transaction is open (each handler's historical guard, and message).
    async fn execute_in_tx_named(
        &mut self,
        sql: &str,
        params: Vec<TursoValue>,
        closed: &'static str,
    ) -> anyhow::Result<u64>;
    async fn begin(&mut self) -> anyhow::Result<()>;
    async fn commit(&mut self) -> anyhow::Result<()>;
    /// Like `commit`, but fails with `closed` when no transaction is open.
    async fn commit_named(&mut self, closed: &'static str) -> anyhow::Result<()>;
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

    async fn execute_in_tx_named(
        &mut self,
        sql: &str,
        params: Vec<TursoValue>,
        closed: &'static str,
    ) -> anyhow::Result<u64> {
        match self.tx.as_ref() {
            Some(tx) => tx.execute(sql, params).await,
            None => Err(anyhow::anyhow!(closed)),
        }
    }

    async fn begin(&mut self) -> anyhow::Result<()> {
        self.tx = Some(self.pool.tx().await?);
        Ok(())
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        self.commit_named("account deletion transaction is not open").await
    }

    async fn commit_named(&mut self, closed: &'static str) -> anyhow::Result<()> {
        match self.tx.take() {
            Some(tx) => tx.commit().await,
            None => Err(anyhow::anyhow!(closed)),
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
    /// `Store::get_del`: the key's value, removed.
    fn take(&mut self, key: &str) -> anyhow::Result<Option<String>>;
    /// One fixed-window counter increment (`rate_limit::check`).
    fn incr(&mut self, key: &str, limit: u64, ttl: u64) -> anyhow::Result<()>;
    /// `rate_limit::record_backoff_failure`, on the exact streak and backoff
    /// keys the plan named.
    fn backoff_failure(&mut self, streak_key: &str, backoff_key: &str) -> anyhow::Result<()>;
    /// `rate_limit::reset_backoff`, on the exact keys the plan named.
    fn reset_backoff(&mut self, streak_key: &str, backoff_key: &str) -> anyhow::Result<()>;
    /// `rate_limit::track_device_jti`: add `member` to the `key` set.
    fn add_member(&mut self, key: &str, member: &str, ttl: u64) -> anyhow::Result<()>;
    /// `Store::set_ex_nx`: write only when the key is absent; `true` when this
    /// call inserted it.
    fn set_ex_nx(&mut self, key: &str, value: &[u8], ttl: u64) -> anyhow::Result<bool>;
}

/// The token issuer behind an executor's `issue_token` method.
///
/// Issuance itself is the verified `plan_device_token` / web-token policy; the
/// executor treats its result as an observation, exactly as the driver does.
pub(crate) trait SessionTokens {
    fn issue_device(
        &self,
        user: uuid::Uuid,
        device: uuid::Uuid,
    ) -> anyhow::Result<(String, String)>;
}

/// The production issuer: the existing PASETO service.
pub(crate) struct PasetoTokens(pub crate::auth::token::TokenService);

impl SessionTokens for PasetoTokens {
    fn issue_device(
        &self,
        user: uuid::Uuid,
        device: uuid::Uuid,
    ) -> anyhow::Result<(String, String)> {
        Ok(self.0.issue(user, device, None)?)
    }
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

    fn take(&mut self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .0
            .get_del(key)?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn incr(&mut self, key: &str, limit: u64, ttl: u64) -> anyhow::Result<()> {
        rate_limit::check(self.0, key, limit, ttl as i64)?;
        Ok(())
    }

    fn backoff_failure(&mut self, streak_key: &str, backoff_key: &str) -> anyhow::Result<()> {
        rate_limit::record_backoff_failure_keys(self.0, streak_key, backoff_key)?;
        Ok(())
    }

    fn reset_backoff(&mut self, streak_key: &str, backoff_key: &str) -> anyhow::Result<()> {
        rate_limit::reset_backoff_keys(self.0, streak_key, backoff_key)?;
        Ok(())
    }

    fn add_member(&mut self, key: &str, member: &str, ttl: u64) -> anyhow::Result<()> {
        self.0.sadd(key, member, ttl as i64)?;
        Ok(())
    }

    fn set_ex_nx(&mut self, key: &str, value: &[u8], ttl: u64) -> anyhow::Result<bool> {
        Ok(self.0.set_ex_nx(key, value, ttl)?)
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

/// Runs the one first-writer-wins statement of a plan (`set_ex_nx`).
pub(crate) fn run_nonce<K: SessionStore>(
    store: &mut K,
    stmt: &StoreStmt,
) -> (NxOutcome, Option<anyhow::Error>) {
    match render_store(stmt) {
        RenderedStore {
            op: StoreOp::SetExNx,
            key,
            ttl,
            member,
            ..
        } => match store.set_ex_nx(&key, member.as_bytes(), ttl) {
            Ok(true) => (NxOutcome::Inserted, None),
            Ok(false) => (NxOutcome::KeyExists, None),
            Err(error) => (NxOutcome::Failed, Some(error)),
        },
        _ => (
            NxOutcome::Failed,
            Some(anyhow::anyhow!("a non-nonce statement in a nonce plan")),
        ),
    }
}

/// Runs the one take statement of a plan, returning the value it removed.
pub(crate) fn run_take<K: SessionStore>(
    store: &mut K,
    stmt: &StoreStmt,
) -> (TakeOutcome, Option<anyhow::Error>) {

    match render_store(stmt) {
        RenderedStore {
            op: StoreOp::Take,
            key,
            ..
        } => match store.take(&key) {
            Ok(value) => (TakeOutcome::Taken(value), None),
            Err(error) => (TakeOutcome::Failed, Some(error)),
        },
        _ => (
            TakeOutcome::Failed,
            Some(anyhow::anyhow!("a write statement in a take plan")),
        ),
    }
}

/// Runs one SQL plan where every statement must run on the open transaction.
pub(crate) async fn run_sql_in_tx<S: SessionSql>(
    sql: &mut S,
    plan: &[SqlStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    run_sql_in_tx_named(sql, plan, "account deletion transaction is not open").await
}

/// Runs one SQL plan where every write must run on the open transaction,
/// failing with `closed` when the handler has not opened it (each handler has
/// always kept its own message).
pub(crate) async fn run_sql_in_tx_named<S: SessionSql>(
    sql: &mut S,
    plan: &[SqlStmt],
    closed: &'static str,
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render_sql(stmt) {
            Rendered::Execute { sql: text, params } => {
                sql.execute_in_tx_named(text, text_params(params), closed).await
            }
            Rendered::Query { sql: text, params } => {
                sql.query(text, text_params(params)).await.map(|rows| rows.len() as u64)
            }
            Rendered::Commit => sql.commit_named(closed).await.map(|()| 0),
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

/// Runs one SQL plan with a handler-specific closed-transaction message.
pub(crate) async fn run_sql_named<S: SessionSql>(
    sql: &mut S,
    plan: &[SqlStmt],
    closed: &'static str,
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
            Rendered::Commit => sql.commit_named(closed).await.map(|()| 0),
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
                ..
            } => store.set_ex(&key, value, ttl),
            RenderedStore {
                op: StoreOp::RevokeJtis,
                key,
                ..
            } => store.revoke_jtis(&key),
            RenderedStore {
                op: StoreOp::Incr,
                key,
                limit,
                ttl,
                ..
            } => store.incr(&key, limit, ttl),
            RenderedStore {
                op: StoreOp::BackoffFailure,
                key,
                member,
                ..
            } => store.backoff_failure(&key, &member),
            RenderedStore {
                op: StoreOp::ResetBackoff,
                key,
                member,
                ..
            } => store.reset_backoff(&key, &member),
            RenderedStore {
                op: StoreOp::AddMember,
                key,
                member,
                ttl,
                ..
            } => store.add_member(&key, &member, ttl),
            RenderedStore {
                op: StoreOp::Take, ..
            } => Err(anyhow::anyhow!("a take statement in a write plan")),
            RenderedStore {
                op: StoreOp::SetExNx, ..
            } => Err(anyhow::anyhow!("a nonce statement in a write plan")),
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
