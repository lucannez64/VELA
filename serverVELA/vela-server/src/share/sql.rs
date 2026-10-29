//! The thin loop behind every sharing executor method (F-1).
//!
//! An executor method builds a typed plan with `vela_share_policy::store`,
//! runs it here (render each statement, run it, stop at the first failure)
//! and hands the per-statement outcomes to the matching `classify_*`. The
//! plans and classifiers are proved in F* against a store model; this module
//! is the part that model trusts, and `conformance.rs` checks it, with
//! injected failures, against a real database.

use vela_share_policy::store::{
    render, DeviceRowView, LinkRowView, Rendered, ShareStmt, WriteOutcome,
};

use crate::sqldb::{Db as _, TursoDb, TursoValue, TxGuard, VelaRow};

/// Where an executor's statements run.
pub(super) trait ShareSql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>>;
    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64>;
    async fn commit(&mut self) -> anyhow::Result<()>;
}

/// The connection pool: each statement commits on its own.
pub(super) struct PoolSql<'a>(pub &'a TursoDb);

impl ShareSql for PoolSql<'_> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.0.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.0.execute(sql, params).await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("no open transaction to commit"))
    }
}

/// The transaction a handler opened. Dropping it uncommitted rolls it back.
pub(super) struct TxSql(pub Option<TxGuard>);

impl TxSql {
    fn guard(&self) -> anyhow::Result<&TxGuard> {
        self.0
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("transaction already finished"))
    }
}

impl ShareSql for TxSql {
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
}

fn text_params(values: Vec<String>) -> Vec<TursoValue> {
    values.into_iter().map(TursoValue::Text).collect()
}

/// Runs a write plan in order, stopping at the first failure. Returns one
/// outcome per statement run and the error that stopped it, if any.
pub(super) async fn run_writes<S: ShareSql>(
    sql: &mut S,
    plan: &[ShareStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render(stmt) {
            Rendered::Execute { sql: text, params } => sql.execute(text, text_params(params)).await,
            Rendered::Commit => sql.commit().await.map(|()| 0),
            Rendered::Query { .. } => Err(anyhow::anyhow!("a read statement in a write plan")),
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
pub(super) async fn run_read<S: ShareSql>(
    sql: &mut S,
    stmt: &ShareStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match render(stmt) {
        Rendered::Query { sql: text, params } => sql.query(text, text_params(params)).await,
        _ => Err(anyhow::anyhow!("a write statement in a read plan")),
    }
}

/// The first `SelectLink` row: a text `sender_user_id`, an integer `revoked`.
pub(super) fn link_row_view(rows: &[VelaRow]) -> Option<LinkRowView> {
    rows.first().map(|row| LinkRowView {
        sender: row.text(0).map(String::from),
        revoked: row.i64(1),
    })
}

/// The first `SelectDevice` row. `revoked` keeps the handler's historical
/// reading: an integer cell as is, the text `"1"` as 1, anything else unread.
pub(super) fn device_row_view(rows: &[VelaRow]) -> Option<DeviceRowView> {
    rows.first().map(|row| DeviceRowView {
        hybrid_vk: row.text(0).map(String::from),
        revoked: match row.get(1) {
            Some(TursoValue::Integer(value)) => Some(*value),
            Some(TursoValue::Text(value)) if value == "1" => Some(1),
            _ => None,
        },
        share_ek_since: row.text(2).map(String::from),
        user_id: row.text(3).map(String::from),
    })
}
