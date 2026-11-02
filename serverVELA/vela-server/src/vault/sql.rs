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
    render, CapsuleView, ChunkRowView, DeviceListRowView, InventoryRowView, KeyStateView,
    OramRowView, PendingRowView, Rendered, SqlParam, SyncRowView, VaultStmt, WriteOutcome,
};

use crate::error::AppError;
use crate::sqldb::{Db as _, TursoValue, TxGuard, VelaRow};
use crate::state::AppState;

/// Where an executor's statements run.
pub(crate) trait VaultSql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>>;
    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64>;
    async fn commit(&mut self) -> anyhow::Result<()>;
    /// Open a pinned transaction.
    async fn begin(&mut self) -> anyhow::Result<TxGuard>;
    /// The one durable store write (`POST /vault/schema`).
    fn kv_set(&mut self, key: &str, value: &[u8]) -> Result<(), AppError>;
    /// The one durable store read (`GET /vault/schema`, the capsule writer).
    fn kv_get(&mut self, key: &str) -> Result<Option<Vec<u8>>, AppError>;
    /// One fixed-window counter increment (`rate_limit::check`).
    fn kv_incr(&mut self, key: &str, delta: u64, window_secs: i64) -> Result<u64, AppError>;
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

    async fn begin(&mut self) -> anyhow::Result<TxGuard> {
        self.0.sqldb.tx().await
    }

    fn kv_set(&mut self, key: &str, value: &[u8]) -> Result<(), AppError> {
        self.0.store.set_durable(key, value)
    }

    fn kv_get(&mut self, key: &str) -> Result<Option<Vec<u8>>, AppError> {
        self.0.store.get(key)
    }

    fn kv_incr(&mut self, key: &str, delta: u64, window_secs: i64) -> Result<u64, AppError> {
        self.0.store.incr_fixed_window(key, delta, window_secs)
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

    async fn begin(&mut self) -> anyhow::Result<TxGuard> {
        Err(anyhow::anyhow!("a transaction is already open"))
    }

    fn kv_set(&mut self, _key: &str, _value: &[u8]) -> Result<(), AppError> {
        Err(AppError::Internal("no store inside a transaction".into()))
    }

    fn kv_get(&mut self, _key: &str) -> Result<Option<Vec<u8>>, AppError> {
        Err(AppError::Internal("no store inside a transaction".into()))
    }

    fn kv_incr(&mut self, _key: &str, _delta: u64, _window_secs: i64) -> Result<u64, AppError> {
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
            Rendered::KvIncr {
                key,
                delta,
                window_secs,
            } => sql
                .kv_incr(&key, delta, window_secs)
                .map_err(RunError::Store),
            Rendered::Query { .. } => Err(RunError::Sql(anyhow::anyhow!(
                "a read statement in a write plan"
            ))),
            Rendered::Begin => Err(RunError::Sql(anyhow::anyhow!(
                "a transaction begin in a write plan"
            ))),
            Rendered::KvGet { .. } => Err(RunError::Sql(anyhow::anyhow!(
                "a store read in a write plan"
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

/// Runs one store read statement.
pub(crate) fn kv_read<S: VaultSql>(
    sql: &mut S,
    stmt: &VaultStmt,
) -> Result<Option<Vec<u8>>, RunError> {
    match render(stmt) {
        Rendered::KvGet { key } => sql.kv_get(&key).map_err(RunError::Store),
        _ => Err(RunError::Sql(anyhow::anyhow!(
            "a non-store-read statement in a store read"
        ))),
    }
}

/// Runs a begin plan: the one `BEGIN` statement, returning the open guard so
/// the caller's later statements run inside it. The caller drops the guard
/// without committing to roll back.
pub(crate) async fn run_begin<S: VaultSql>(
    sql: &mut S,
    plan: &[VaultStmt],
) -> (Vec<WriteOutcome>, Option<RunError>, Option<TxGuard>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render(stmt) {
            Rendered::Begin => sql.begin().await.map_err(RunError::Sql),
            _ => Err(RunError::Sql(anyhow::anyhow!(
                "a non-begin statement in a begin plan"
            ))),
        };
        match result {
            Ok(guard) => {
                outcomes.push(WriteOutcome::Applied(0));
                return (outcomes, None, Some(guard));
            }
            Err(error) => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, Some(error), None);
            }
        }
    }
    (outcomes, None, None)
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

// ── Handler-I/O views (F-1 wave 2) ────────────────────────────────────────

/// The first `SelectKeyState` row, as `load_key_state` decodes it.
pub(crate) fn key_state_view(rows: &[VelaRow]) -> Option<KeyStateView> {
    rows.first().map(|row| KeyStateView {
        key_epoch: row.i64(0),
        rekey_state: row.text(1).map(String::from),
        rekey_started_at: row.text(2).map(String::from),
        rekey_starter: row.text(3).map(String::from),
        rekey_id: row.text(4).map(String::from),
        last_rekey_id: row.text(5).map(String::from),
        last_rekey_epoch: row.i64(6),
    })
}

/// A one-cell `SUM(...)` / `COALESCE(SUM(...), 0)` read, as the quota paths
/// decode it: a missing cell reads as zero and a negative total as zero.
pub(crate) fn scalar_view(rows: &[VelaRow]) -> i64 {
    let value = rows.first().and_then(|row| row.i64(0)).unwrap_or(0);
    if value > 0 {
        value
    } else {
        0
    }
}

/// The first `SelectOramRow` row.
pub(crate) fn oram_row_view(rows: &[VelaRow]) -> Option<OramRowView> {
    rows.first().map(|row| OramRowView {
        version: row.i64(0),
        lamport_clock: row.i64(1),
        last_writer: row.text(2).map(String::from),
        ciphertext: row.text(3).map(String::from),
    })
}

/// Every `SelectSyncManifest` row.
pub(crate) fn sync_rows_view(rows: &[VelaRow]) -> Vec<SyncRowView> {
    rows.iter()
        .map(|row| SyncRowView {
            chunk_id: row.text(0).map(String::from),
            version: row.i64(1),
            lamport_clock: row.i64(2),
            last_writer: row.text(3).map(String::from),
        })
        .collect()
}

/// The first `SelectCapsule` row.
pub(crate) fn capsule_view(rows: &[VelaRow]) -> Option<CapsuleView> {
    rows.first().map(|row| CapsuleView {
        capsule: row.text(0).map(String::from),
        capsule_epoch: row.i64(1),
        rotation_id: row.text(2).map(String::from),
    })
}

/// Every `SelectDeviceList` row.
pub(crate) fn device_list_rows_view(rows: &[VelaRow]) -> Vec<DeviceListRowView> {
    rows.iter()
        .map(|row| DeviceListRowView {
            id: row.text(0).map(String::from),
            user_id: row.text(1).map(String::from),
            device_name: row.text(2).map(String::from),
            device_type: row.text(3).map(String::from),
            last_active: row.text(4).map(String::from),
            hybrid_ek: row.text(5).map(String::from),
            hybrid_vk: row.text(6).map(String::from),
            enrolled_by: row.text(7).map(String::from),
            rms_capsule: row.text(8).map(String::from),
            revoked: row.i64(9),
            revoked_at: row.text(10).map(String::from),
            revoked_by: row.text(11).map(String::from),
            created_at: row.text(12).map(String::from),
            rekey_capable: row.i64(13),
        })
        .collect()
}

/// A store value as the model's text: the schema key holds UTF-8 text.
pub(crate) fn kv_text(value: Option<Vec<u8>>) -> Option<String> {
    value.map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}
