//! The thin loop behind the vault, rekey, capsule, ORAM and schema executors
//! (F-1).
//!
//! An executor method builds a typed plan with `vela_rekey_policy::executor`,
//! runs it here (render each statement, run it, stop at the first failure) and
//! hands the per-statement outcomes to the matching `classify_*`. The plans and
//! classifiers are proved in F* against a store model; this module is the part
//! that model trusts, and `conformance.rs` checks it, with injected failures,
//! against a real database.

use vela_rekey_policy::executor::{
    render, ChunkRowView, InventoryRowView, PendingRowView, Rendered, SqlParam, VaultStmt,
    WriteOutcome,
};

use crate::error::AppError;
use crate::sqldb::{Db as _, TursoValue, TxGuard, VelaRow};
use crate::state::AppState;

/// Where an executor's statements run.
pub(crate) trait VaultSql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>>;
    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64>;
    async fn commit(&mut self) -> anyhow::Result<()>;
    /// The one durable store write (`POST /vault/schema`).
    fn kv_set(&mut self, key: &str, value: &[u8]) -> Result<(), AppError>;
}

/// The connection pool: each statement commits on its own.
pub(crate) struct PoolSql<'a>(pub &'a AppState);

impl VaultSql for PoolSql<'_> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.0.sqldb.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.0.sqldb.execute(sql, params).await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("no open transaction to commit"))
    }

    fn kv_set(&mut self, key: &str, value: &[u8]) -> Result<(), AppError> {
        self.0.store.set_durable(key, value)
    }
}

/// The transaction a handler opened. Dropping it uncommitted rolls it back.
pub(crate) struct TxSql(pub Option<TxGuard>);

impl TxSql {
    fn guard(&self) -> anyhow::Result<&TxGuard> {
        self.0
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("transaction already finished"))
    }
}

impl VaultSql for TxSql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.guard()?.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.guard()?.execute(sql, params).await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        match self.0.take() {
            Some(guard) => guard.commit().await,
            None => Err(anyhow::anyhow!("transaction already finished")),
        }
    }

    fn kv_set(&mut self, _key: &str, _value: &[u8]) -> Result<(), AppError> {
        Err(AppError::Internal("no store inside a transaction".into()))
    }
}

fn params(values: Vec<SqlParam>) -> Vec<TursoValue> {
    values
        .into_iter()
        .map(|value| match value {
            SqlParam::Text(text) => TursoValue::Text(text),
            SqlParam::Int(number) => TursoValue::Integer(number),
        })
        .collect()
}

/// The failure that stopped a run, as the executor's error side channel.
#[derive(Debug)]
pub(crate) enum RunError {
    /// A SQL statement failed; the historical handlers wrapped its text in
    /// `AppError::Internal`.
    Sql(anyhow::Error),
    /// The store refused the write with its own error.
    Store(AppError),
}

impl RunError {
    pub(crate) fn into_internal(self) -> AppError {
        match self {
            RunError::Sql(error) => AppError::Internal(error.to_string()),
            RunError::Store(error) => error,
        }
    }
}

/// Runs a write plan in order, stopping at the first failure. Returns one
/// outcome per statement run and the error that stopped it, if any.
pub(crate) async fn run_writes<S: VaultSql>(
    sql: &mut S,
    plan: &[VaultStmt],
) -> (Vec<WriteOutcome>, Option<RunError>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render(stmt) {
            Rendered::Execute { sql: text, params: values } => {
                sql.execute(text, params(values)).await.map_err(RunError::Sql)
            }
            Rendered::Commit => sql.commit().await.map(|()| 0).map_err(RunError::Sql),
            Rendered::KvSet { key, value } => {
                sql.kv_set(&key, value).map(|()| 0).map_err(RunError::Store)
            }
            Rendered::Query { .. } => Err(RunError::Sql(anyhow::anyhow!(
                "a read statement in a write plan"
            ))),
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

/// Runs one read statement.
pub(crate) async fn run_read<S: VaultSql>(
    sql: &mut S,
    stmt: &VaultStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match render(stmt) {
        Rendered::Query { sql: text, params: values } => sql.query(text, params(values)).await,
        _ => Err(anyhow::anyhow!("a write statement in a read plan")),
    }
}

/// The first `SelectChunkVersion` row's version.
pub(crate) fn version_view(rows: &[VelaRow]) -> Option<i64> {
    rows.first().and_then(|row| row.i64(0))
}

/// The first `SelectChunkRow` row, as the handler decodes it.
pub(crate) fn chunk_row_view(rows: &[VelaRow]) -> Option<ChunkRowView> {
    rows.first().map(|row| ChunkRowView {
        chunk_id: row.text(0).map(String::from),
        user_id: row.text(1).map(String::from),
        version: row.i64(2),
        lamport_clock: row.i64(3),
        last_writer: row.text(4).map(String::from),
        ciphertext: row.text(5).map(String::from),
        epoch: row.i64(6),
    })
}

/// Whether an existence query returned a row.
pub(crate) fn exists_view(rows: &[VelaRow]) -> bool {
    rows.first().is_some()
}

/// The first `SelectPendingCapsule` row's epoch cell.
pub(crate) fn pending_row_view(rows: &[VelaRow]) -> Option<PendingRowView> {
    rows.first().map(|row| PendingRowView {
        epoch: row.i64(0),
    })
}

/// Every `SelectInventory` row.
pub(crate) fn inventory_rows(rows: &[VelaRow]) -> Vec<InventoryRowView> {
    rows.iter()
        .map(|row| InventoryRowView {
            chunk_id: row.text(0).map(String::from),
            version: row.i64(1),
            lamport_clock: row.i64(2),
        })
        .collect()
}
