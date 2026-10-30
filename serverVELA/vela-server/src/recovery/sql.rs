//! The thin loop behind the recovered-device enrollment executor (F-1).
//!
//! An executor method builds a typed plan with
//! `vela_recovery_policy::redemption_store`, runs it here (render each
//! statement, run it against turso or the key-value store, stop at the first
//! failure) and hands the per-statement outcomes to the matching `classify_*`.
//! The plans and classifiers are proved in F* against a store model; this
//! module is the part that model trusts, and `conformance.rs` checks it, with
//! injected failures, against a real database and store.

use vela_recovery_policy::redemption_store::{
    self, AuthorityRowView, Param, Rendered, RedemptionStmt, WriteOutcome,
};

use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};
use crate::error::Result;

/// Where an executor's SQL statements run. The enrollment path uses the pool:
/// each statement commits on its own.
pub(super) trait RecoverySql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>>;
    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64>;
}

/// The connection pool: each statement commits on its own.
pub(super) struct PoolSql<'a>(pub &'a TursoDb);

impl RecoverySql for PoolSql<'_> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.0.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.0.execute(sql, params).await
    }
}

/// Where an executor's enrollment-grant operations run.
pub(super) trait RecoveryKv {
    fn take(&mut self, key: &str) -> Result<Option<Vec<u8>>>;
    fn put(&mut self, key: &str, value: &[u8]) -> Result<()>;
}

/// The sled-backed store the recovery grants live in.
pub(super) struct StoreKv<'a>(pub &'a crate::store::Store);

impl RecoveryKv for StoreKv<'_> {
    fn take(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        self.0.get_del(key)
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.0
            .set_ex(key, value, super::recover::ENROLL_GRANT_TTL_SECS)
    }
}

fn turso_params(params: Vec<Param>) -> Vec<TursoValue> {
    params
        .into_iter()
        .map(|param| match param {
            Param::Text(text) => TursoValue::Text(text),
            Param::Int(value) => TursoValue::Integer(value),
        })
        .collect()
}

/// Runs a write plan in order, stopping at the first failure. Returns one
/// outcome per statement run and the error that stopped it, if any.
pub(super) async fn run_writes<S: RecoverySql>(
    sql: &mut S,
    plan: &[RedemptionStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match redemption_store::render(stmt) {
            Rendered::Execute { sql: text, params } => sql.execute(text, turso_params(params)).await,
            Rendered::Query { .. } => Err(anyhow::anyhow!("a read statement in a write plan")),
            Rendered::KvTake { .. } | Rendered::KvPut { .. } => {
                Err(anyhow::anyhow!("a store statement in a SQL write plan"))
            }
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
pub(super) async fn run_read<S: RecoverySql>(
    sql: &mut S,
    stmt: &RedemptionStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match redemption_store::render(stmt) {
        Rendered::Query { sql: text, params } => sql.query(text, turso_params(params)).await,
        _ => Err(anyhow::anyhow!("a non-read statement in a read plan")),
    }
}

/// Runs one atomic grant take.
pub(super) fn take_grant<K: RecoveryKv>(
    kv: &mut K,
    stmt: &RedemptionStmt,
) -> Result<Option<Vec<u8>>> {
    match redemption_store::render(stmt) {
        Rendered::KvTake { key } => kv.take(&key),
        _ => Err(crate::error::AppError::Internal(
            "a non-take statement in a take plan".into(),
        )),
    }
}

/// Runs one grant restoration.
pub(super) fn put_grant<K: RecoveryKv>(kv: &mut K, stmt: &RedemptionStmt) -> Result<()> {
    match redemption_store::render(stmt) {
        Rendered::KvPut { key, value } => kv.put(&key, &value),
        _ => Err(crate::error::AppError::Internal(
            "a non-put statement in a put plan".into(),
        )),
    }
}

/// The first `SelectAuthority` row. An empty `recovery_auth_hash` is reported
/// as no commitment, exactly as the insert guard's `<> ''` treats it.
pub(super) fn authority_row_view(rows: &[VelaRow]) -> Option<AuthorityRowView> {
    rows.first().map(|row| AuthorityRowView {
        credential_id: row.text(0).map(String::from),
        auth_hash: row.text(1).filter(|hash| !hash.is_empty()).map(String::from),
    })
}
