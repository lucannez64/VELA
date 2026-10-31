//! The thin loop behind the one-off share-link executors (F-1).
//!
//! An executor method builds a typed plan with `vela_share_policy::store`,
//! runs it here (render each statement, run it, stop at the first failure) and
//! hands the per-statement outcomes to the matching `classify_send_*`. The
//! plans and classifiers are proved in F* against a store model; this module
//! is the part that model trusts, and `conformance.rs` checks it, with
//! injected failures, against a real database.
//!
//! Every statement here is autocommit: the send-link handlers hold no
//! transaction.

use vela_share_policy::store::{
    render_handler, render_send, HandlerRendered, HandlerStmt, SendRendered, SendRowView, SendStmt,
    SqlParam, WriteOutcome,
};

use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};

/// Where an executor's statements run.
pub(super) trait SendSql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>>;
    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64>;
}

/// The connection pool: each statement commits on its own.
pub(super) struct PoolSql<'a>(pub &'a TursoDb);

impl SendSql for PoolSql<'_> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.0.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.0.execute(sql, params).await
    }
}

/// The bound parameters as turso values: text, integers and NULL.
pub(super) fn bound(values: Vec<SqlParam>) -> Vec<TursoValue> {
    values
        .into_iter()
        .map(|value| match value {
            SqlParam::Text(text) => TursoValue::Text(text),
            SqlParam::Int(number) => TursoValue::Integer(number),
            SqlParam::Null => TursoValue::Null,
        })
        .collect()
}

/// Runs a write plan in order, stopping at the first failure. Returns one
/// outcome per statement run and the error that stopped it, if any.
pub(super) async fn run_writes<S: SendSql>(
    sql: &mut S,
    plan: &[SendStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match render_send(stmt) {
            SendRendered::Execute { sql: text, params } => sql.execute(text, bound(params)).await,
            SendRendered::Query { .. } => Err(anyhow::anyhow!("a read statement in a write plan")),
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
pub(super) async fn run_read<S: SendSql>(
    sql: &mut S,
    stmt: &SendStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match render_send(stmt) {
        SendRendered::Query { sql: text, params } => sql.query(text, bound(params)).await,
        SendRendered::Execute { .. } => Err(anyhow::anyhow!("a write statement in a read plan")),
    }
}

/// The first `SelectSend` row. `expires_at` is the handler's decoded
/// timestamp: the column text is parsed as RFC3339 and carried in canonical
/// form, so an unparsable cell is `None` exactly like a missing one, and the
/// response re-serializes the same instant as before.
pub(super) fn send_row_view(rows: &[VelaRow]) -> Option<SendRowView> {
    rows.first().map(|row| SendRowView {
        ciphertext: row.text(0).map(String::from),
        has_passphrase: row.i64(1),
        kdf_salt: row.text(2).map(String::from),
        view_once: row.i64(3),
        max_views: row.i64(4),
        view_count: row.i64(5),
        expires_at: row.timestamp(6).map(|at| at.to_rfc3339()),
    })
}

// ── Handler statements (F-1 wave 2) ────────────────────────────────────────
//
// The same thin loop for the I/O `send.rs` runs outside an executor method:
// the owner listing and the expiry sweep.

/// Runs one handler read.
pub(super) async fn run_handler_read<S: SendSql>(
    sql: &mut S,
    stmt: &HandlerStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match render_handler(stmt) {
        HandlerRendered::Query { sql: text, params } => sql.query(text, bound(params)).await,
        _ => Err(anyhow::anyhow!("a write statement in a read plan")),
    }
}

/// Runs one handler write.
pub(super) async fn run_handler_write<S: SendSql>(
    sql: &mut S,
    stmt: &HandlerStmt,
) -> anyhow::Result<u64> {
    match render_handler(stmt) {
        HandlerRendered::Execute { sql: text, params } => sql.execute(text, bound(params)).await,
        _ => Err(anyhow::anyhow!("a read statement in a write plan")),
    }
}
