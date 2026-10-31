//! The thin loop behind the device-enrollment executors (F-1).
//!
//! An executor method builds a typed plan with `vela_enrollment_policy::executor`,
//! runs it here (render each statement, run it, stop at the first failure) and
//! hands the per-statement outcomes to the matching `classify_*`. The plans and
//! classifiers are proved in F* against a store model; this module is the part
//! that model trusts, and `executor_conformance.rs` checks it, with injected
//! failures, against a real turso database and a real sled store.

use vela_enrollment_policy::executor::{
    render, PairingStmt, Rendered, TakeOutcome, WriteOutcome,
};

use crate::error::AppError;
use crate::sqldb::{Db as _, TursoValue, VelaRow};
use crate::state::AppState;
use crate::store::GuardedSetOutcome;

/// A statement error, kept in the shape the handler has always rendered: SQL
/// errors become an internal error with the driver's text, store errors keep
/// their original [`AppError`].
pub(crate) enum ExecError {
    Sql(anyhow::Error),
    Store(AppError),
}

impl ExecError {
    /// The error the historical handler retained for this statement.
    pub(crate) fn into_app(self) -> AppError {
        match self {
            ExecError::Sql(error) => AppError::Internal(error.to_string()),
            ExecError::Store(error) => error,
        }
    }
}

/// What one read statement produced, before the executor decodes it.
pub(crate) enum RawRead {
    /// The statement returned an error.
    Failed,
    /// A SQL row set (possibly empty).
    Rows(Vec<VelaRow>),
    /// A store value (`None`: the key was absent).
    Value(Option<Vec<u8>>),
    /// A store presence check.
    Exists(bool),
}

/// The I/O behind one request. `fail_at` injects a failure at the k-th
/// statement (from 0) without running it; the conformance test uses it.
pub(crate) struct ExecIo<'a> {
    state: &'a AppState,
    fail_at: Option<usize>,
    calls: usize,
}

impl<'a> ExecIo<'a> {
    pub(crate) fn new(state: &'a AppState) -> Self {
        Self {
            state,
            fail_at: None,
            calls: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn faulty(state: &'a AppState, fail_at: Option<usize>) -> Self {
        Self {
            state,
            fail_at,
            calls: 0,
        }
    }

    /// The k-th statement is the injected failure.
    fn hit(&mut self) -> Result<(), ExecError> {
        let k = self.calls;
        self.calls += 1;
        if self.fail_at == Some(k) {
            Err(ExecError::Sql(anyhow::anyhow!(
                "injected failure at statement {k}"
            )))
        } else {
            Ok(())
        }
    }

    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> Result<Vec<VelaRow>, ExecError> {
        self.hit()?;
        self.state
            .sqldb
            .query(sql, params)
            .await
            .map_err(ExecError::Sql)
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> Result<u64, ExecError> {
        self.hit()?;
        self.state
            .sqldb
            .execute(sql, params)
            .await
            .map_err(ExecError::Sql)
    }

    fn set_ex(&mut self, key: &str, value: &[u8], ttl: u64) -> Result<(), ExecError> {
        self.hit()?;
        self.state.store.set_ex(key, value, ttl).map_err(ExecError::Store)
    }

    fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, ExecError> {
        self.hit()?;
        self.state.store.get(key).map_err(ExecError::Store)
    }

    fn get_del(&mut self, key: &str) -> Result<Option<Vec<u8>>, ExecError> {
        self.hit()?;
        self.state.store.get_del(key).map_err(ExecError::Store)
    }

    fn exists(&mut self, key: &str) -> Result<bool, ExecError> {
        self.hit()?;
        self.state.store.exists(key).map_err(ExecError::Store)
    }

    fn set_ex_nx_if_live(
        &mut self,
        guard: &str,
        key: &str,
        value: &[u8],
        ttl: u64,
    ) -> Result<GuardedSetOutcome, ExecError> {
        self.hit()?;
        self.state
            .store
            .set_ex_nx_if_live(guard, key, value, ttl)
            .map_err(ExecError::Store)
    }

    fn take_live_pair(
        &mut self,
        first: &str,
        second: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, ExecError> {
        self.hit()?;
        self.state
            .store
            .take_live_pair(first, second)
            .map_err(ExecError::Store)
    }

    /// Runs a write plan in order, stopping at the first failure.
    pub(crate) async fn run_writes(
        &mut self,
        plan: &[PairingStmt],
    ) -> (Vec<WriteOutcome>, Option<ExecError>) {
        let mut outcomes = Vec::with_capacity(plan.len());
        for stmt in plan {
            let result = match render(stmt) {
                Rendered::Execute { sql, params } => {
                    match self.execute(sql, text_params(params)).await {
                        Ok(rows) => Ok(WriteOutcome::Applied(rows)),
                        Err(error) => Err(error),
                    }
                }
                Rendered::ExecuteEpoch { sql, params, epoch } => {
                    let mut bound = text_params(params);
                    bound.push(TursoValue::Integer(epoch));
                    match self.execute(sql, bound).await {
                        Ok(rows) => Ok(WriteOutcome::Applied(rows)),
                        Err(error) => Err(error),
                    }
                }
                Rendered::StoreSet { key, value, ttl } => {
                    self.set_ex(&key, &value, ttl).map(|()| WriteOutcome::Applied(1))
                }
                Rendered::StoreSetIfLive {
                    guard,
                    key,
                    value,
                    ttl,
                } => match self.set_ex_nx_if_live(&guard, &key, &value, ttl) {
                    Ok(GuardedSetOutcome::Inserted) => Ok(WriteOutcome::Inserted),
                    Ok(GuardedSetOutcome::GuardMissing) => Ok(WriteOutcome::GuardMissing),
                    Ok(GuardedSetOutcome::KeyExists) => Ok(WriteOutcome::KeyExists),
                    Err(error) => Err(error),
                },
                _ => Err(ExecError::Sql(anyhow::anyhow!(
                    "a read statement in a write plan"
                ))),
            };
            match result {
                Ok(outcome) => outcomes.push(outcome),
                Err(error) => {
                    outcomes.push(WriteOutcome::Failed);
                    return (outcomes, Some(error));
                }
            }
        }
        (outcomes, None)
    }

    /// Runs a read plan in order, stopping at the first failure.
    pub(crate) async fn run_reads(
        &mut self,
        plan: &[PairingStmt],
    ) -> (Vec<RawRead>, Option<ExecError>) {
        let mut reads = Vec::with_capacity(plan.len());
        for stmt in plan {
            let result = match render(stmt) {
                Rendered::Query { sql, params } => {
                    self.query(sql, text_params(params)).await.map(RawRead::Rows)
                }
                Rendered::StoreGet { key } => self.get(&key).map(RawRead::Value),
                Rendered::StoreExists { key } => self.exists(&key).map(RawRead::Exists),
                _ => Err(ExecError::Sql(anyhow::anyhow!(
                    "a write statement in a read plan"
                ))),
            };
            match result {
                Ok(read) => reads.push(read),
                Err(error) => {
                    reads.push(RawRead::Failed);
                    return (reads, Some(error));
                }
            }
        }
        (reads, None)
    }

    /// Runs a destructive single-key read.
    pub(crate) async fn run_take(
        &mut self,
        plan: &[PairingStmt],
    ) -> (TakeOutcome, Option<Vec<u8>>, Option<ExecError>) {
        let Some(stmt) = plan.first() else {
            return (TakeOutcome::Failed, None, None);
        };
        match render(stmt) {
            Rendered::StoreTake { key } => match self.get_del(&key) {
                Ok(value) => (
                    if value.is_some() {
                        TakeOutcome::Present
                    } else {
                        TakeOutcome::Missing
                    },
                    value,
                    None,
                ),
                Err(error) => (TakeOutcome::Failed, None, Some(error)),
            },
            _ => (
                TakeOutcome::Failed,
                None,
                Some(ExecError::Sql(anyhow::anyhow!(
                    "a non-take statement in a take plan"
                ))),
            ),
        }
    }

    /// Runs the atomic two-key take.
    pub(crate) async fn run_take_pair(
        &mut self,
        plan: &[PairingStmt],
    ) -> (
        TakeOutcome,
        Option<(Vec<u8>, Vec<u8>)>,
        Option<ExecError>,
    ) {
        let Some(stmt) = plan.first() else {
            return (TakeOutcome::Failed, None, None);
        };
        match render(stmt) {
            Rendered::StoreTakePair { first, second } => {
                match self.take_live_pair(&first, &second) {
                    Ok(pair) => (
                        if pair.is_some() {
                            TakeOutcome::Present
                        } else {
                            TakeOutcome::Missing
                        },
                        pair,
                        None,
                    ),
                    Err(error) => (TakeOutcome::Failed, None, Some(error)),
                }
            }
            _ => (
                TakeOutcome::Failed,
                None,
                Some(ExecError::Sql(anyhow::anyhow!(
                    "a non-pair statement in a take-pair plan"
                ))),
            ),
        }
    }
}

fn text_params(values: Vec<String>) -> Vec<TursoValue> {
    values.into_iter().map(TursoValue::Text).collect()
}
