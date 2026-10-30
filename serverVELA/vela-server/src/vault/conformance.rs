//! Bounded conformance of the vault, rekey, capsule, ORAM and schema executors
//! against a real database (F-1).
//!
//! The F* proofs in `vela-rekey-policy/proofs/fstar/executor-lemmas` show that
//! each plan and classifier is honest *in the store model*. This test checks
//! the model against turso and the sled store: for every small starting state,
//! every target, and every fault point (no fault, or a failure injected at each
//! statement in turn, including a commit and the store write), it runs the real
//! plan/render/run/classify path (`vault::sql`, the same loop the executors
//! call) through [`Faulty`], and compares every touched table and store key,
//! plus the observation, with the Rust mirror of the model
//! (`vela_rekey_policy::executor_model`).
//!
//! A schema check pins the columns and types the model uses.

use vela_rekey_policy::executor::{self as policy, ChunkRowView, ReadOutcome, WriteOutcome};
use vela_rekey_policy::executor_model::{
    self as model, ChunkRow, Db as Model, DeviceRow, OramRow, UserRow,
};
use vela_rekey_policy::rekey_driver::{
    CasObservation, CleanupObservation, SweepObservation, TransactionObservation,
};

use vela_rekey_policy::vault_upload_driver::ActivityObservation;

use super::sql::{
    chunk_row_view, exists_view, inventory_rows, pending_row_view, run_read, run_writes,
    version_view, RunError, VaultSql,
};
use crate::sqldb::{Db as _, TursoDb, TursoValue, TxGuard, VelaRow};
use crate::store::Store;

/// The pool: statements run on the shared connection, each its own transaction.
struct Pool<'a> {
    db: &'a TursoDb,
    store: &'a Store,
}

impl VaultSql for Pool<'_> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.db.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.db.execute(sql, params).await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("no open transaction to commit"))
    }

    fn kv_set(&mut self, key: &str, value: &[u8]) -> Result<(), crate::error::AppError> {
        self.store.set_durable(key, value)
    }
}

/// One pinned transaction.
struct Tx {
    guard: Option<TxGuard>,
}

impl VaultSql for Tx {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        match self.guard.as_ref() {
            Some(guard) => guard.query(sql, params).await,
            None => Err(anyhow::anyhow!("transaction already finished")),
        }
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        match self.guard.as_ref() {
            Some(guard) => guard.execute(sql, params).await,
            None => Err(anyhow::anyhow!("transaction already finished")),
        }
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        match self.guard.take() {
            Some(guard) => guard.commit().await,
            None => Err(anyhow::anyhow!("transaction already finished")),
        }
    }

    fn kv_set(&mut self, _key: &str, _value: &[u8]) -> Result<(), crate::error::AppError> {
        Err(crate::error::AppError::Internal(
            "no store inside a transaction".into(),
        ))
    }
}

/// Fails the k-th statement (from 0) an executor sends, without sending it.
struct Faulty<S> {
    inner: S,
    fail_at: Option<usize>,
    message: &'static str,
    calls: usize,
}

impl<S> Faulty<S> {
    fn new(inner: S, fail_at: Option<usize>) -> Self {
        Self {
            inner,
            fail_at,
            message: "injected failure",
            calls: 0,
        }
    }

    fn with_message(mut self, message: &'static str) -> Self {
        self.message = message;
        self
    }

    fn hit(&mut self) -> anyhow::Result<()> {
        let k = self.calls;
        self.calls += 1;
        if self.fail_at == Some(k) {
            Err(anyhow::anyhow!("{} at statement {k}", self.message))
        } else {
            Ok(())
        }
    }
}

impl<S: VaultSql> VaultSql for Faulty<S> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.hit()?;
        self.inner.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.hit()?;
        self.inner.execute(sql, params).await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.commit().await
    }

    fn kv_set(&mut self, key: &str, value: &[u8]) -> Result<(), crate::error::AppError> {
        match self.hit() {
            Ok(()) => self.inner.kv_set(key, value),
            Err(error) => Err(crate::error::AppError::Internal(error.to_string())),
        }
    }
}

const NOW: &str = "2026-10-29T12:00:00+00:00";
const T0: &str = "2026-01-01T00:00:00+00:00";

fn s(x: &str) -> String {
    x.to_string()
}

fn user(n: u8) -> String {
    format!("user-{n}")
}

fn device(n: u8) -> String {
    format!("device-{n}")
}

fn item(n: u8) -> String {
    format!("chunk-{n}")
}

fn tree() -> String {
    s("tree")
}

async fn temp_db() -> TursoDb {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "{}/vela-vault-conformance-{}-{}.db",
        std::env::temp_dir().display(),
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    TursoDb::open(&path, 1).await.unwrap()
}

/// Waits until any rollback spawned by a dropped transaction has finished.
async fn settle(db: &TursoDb) {
    db.tx().await.unwrap().rollback().await.unwrap();
}

fn opt(value: &Option<String>) -> TursoValue {
    match value {
        Some(text) => TursoValue::Text(text.clone()),
        None => TursoValue::Null,
    }
}

fn opt_i64(value: Option<i64>) -> TursoValue {
    match value {
        Some(number) => TursoValue::Integer(number),
        None => TursoValue::Null,
    }
}

async fn load(db: &TursoDb, store: &Store, state: &Model) {
    db.execute_batch(
        "DELETE FROM vault_chunks; DELETE FROM oram_buckets; DELETE FROM users; DELETE FROM devices;",
    )
    .await
    .unwrap();
    for (id, row) in &state.users {
        db.execute(
            "INSERT INTO users (id, created_at, key_epoch, rekey_state, rekey_started_at, \
             rekey_starter, rekey_id, last_rekey_id, last_rekey_epoch) \
             VALUES (?, 't', ?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Integer(row.key_epoch),
                opt(&row.rekey_state),
                opt(&row.rekey_started_at),
                opt(&row.rekey_starter),
                opt(&row.rekey_id),
                opt(&row.last_rekey_id),
                opt_i64(row.last_rekey_epoch),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.devices {
        db.execute(
            "INSERT INTO devices (id, user_id, hybrid_ek, hybrid_vk, revoked, rekey_capable, \
             rms_capsule, rms_capsule_epoch, created_at) VALUES (?, ?, 'ek', 'vk', ?, ?, ?, ?, 't')",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.user_id.clone()),
                TursoValue::Integer(row.revoked),
                TursoValue::Integer(row.rekey_capable),
                opt(&row.rms_capsule),
                opt_i64(row.rms_capsule_epoch),
            ],
        )
        .await
        .unwrap();
    }
    for ((user_id, chunk_id, epoch), row) in &state.chunks {
        db.execute(
            "INSERT INTO vault_chunks (chunk_id, user_id, version, lamport_clock, last_writer, \
             ciphertext, epoch, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(chunk_id.clone()),
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(row.version),
                TursoValue::Integer(row.lamport_clock),
                opt(&row.last_writer),
                TursoValue::Text(row.ciphertext.clone()),
                TursoValue::Integer(*epoch),
                TursoValue::Text(row.created_at.clone()),
                TursoValue::Text(row.updated_at.clone()),
            ],
        )
        .await
        .unwrap();
    }
    for ((user_id, tree_id, index, epoch), row) in &state.oram {
        db.execute(
            "INSERT INTO oram_buckets (user_id, tree_id, bucket_index, version, lamport_clock, \
             last_writer, ciphertext, epoch, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(user_id.clone()),
                TursoValue::Text(tree_id.clone()),
                TursoValue::Integer(*index),
                TursoValue::Integer(row.version),
                TursoValue::Integer(row.lamport_clock),
                opt(&row.last_writer),
                TursoValue::Text(row.ciphertext.clone()),
                TursoValue::Integer(*epoch),
                TursoValue::Text(row.created_at.clone()),
                TursoValue::Text(row.updated_at.clone()),
            ],
        )
        .await
        .unwrap();
    }
    for (key, value) in &state.kv {
        store.set_durable(key, value.as_bytes()).unwrap();
    }
}

fn text(row: &VelaRow, i: usize) -> String {
    row.text(i)
        .unwrap_or_else(|| panic!("column {i} is not text"))
        .to_string()
}

/// The modelled columns of all four tables and the schema key.
async fn snapshot(db: &TursoDb, store: &Store, keys: &[String]) -> Model {
    let mut state = Model::default();
    for row in db
        .query(
            "SELECT id, key_epoch, rekey_state, rekey_started_at, rekey_starter, rekey_id, \
             last_rekey_id, last_rekey_epoch FROM users",
            vec![],
        )
        .await
        .unwrap()
    {
        state.users.insert(
            text(&row, 0),
            UserRow {
                key_epoch: row.i64(1).expect("key_epoch is an integer"),
                rekey_state: row.text(2).map(String::from),
                rekey_started_at: row.text(3).map(String::from),
                rekey_starter: row.text(4).map(String::from),
                rekey_id: row.text(5).map(String::from),
                last_rekey_id: row.text(6).map(String::from),
                last_rekey_epoch: row.i64(7),
            },
        );
    }
    for row in db
        .query(
            "SELECT id, user_id, revoked, rekey_capable, rms_capsule, rms_capsule_epoch \
             FROM devices",
            vec![],
        )
        .await
        .unwrap()
    {
        state.devices.insert(
            text(&row, 0),
            DeviceRow {
                user_id: text(&row, 1),
                revoked: row.i64(2).expect("revoked is an integer"),
                rekey_capable: row.i64(3).expect("rekey_capable is an integer"),
                rms_capsule: row.text(4).map(String::from),
                rms_capsule_epoch: row.i64(5),
            },
        );
    }
    for row in db
        .query(
            "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, \
             epoch, created_at, updated_at FROM vault_chunks",
            vec![],
        )
        .await
        .unwrap()
    {
        let chunk_id = text(&row, 0);
        let user_id = text(&row, 1);
        let epoch = row.i64(6).expect("epoch is an integer");
        state.chunks.insert(
            (user_id.clone(), chunk_id.clone(), epoch),
            ChunkRow {
                user_id,
                chunk_id,
                epoch,
                version: row.i64(2).expect("version is an integer"),
                lamport_clock: row.i64(3).expect("lamport_clock is an integer"),
                last_writer: row.text(4).map(String::from),
                ciphertext: text(&row, 5),
                created_at: text(&row, 7),
                updated_at: text(&row, 8),
            },
        );
    }
    for row in db
        .query(
            "SELECT user_id, tree_id, bucket_index, version, lamport_clock, last_writer, \
             ciphertext, epoch, created_at, updated_at FROM oram_buckets",
            vec![],
        )
        .await
        .unwrap()
    {
        let user_id = text(&row, 0);
        let tree_id = text(&row, 1);
        let index = row.i64(2).expect("bucket_index is an integer");
        let epoch = row.i64(7).expect("epoch is an integer");
        state.oram.insert(
            (user_id.clone(), tree_id.clone(), index, epoch),
            OramRow {
                user_id,
                tree_id,
                bucket_index: index,
                epoch,
                version: row.i64(3).expect("version is an integer"),
                lamport_clock: row.i64(4).expect("lamport_clock is an integer"),
                last_writer: row.text(5).map(String::from),
                ciphertext: text(&row, 6),
                created_at: text(&row, 8),
                updated_at: text(&row, 9),
            },
        );
    }
    for key in keys {
        if let Some(bytes) = store.get(key).unwrap() {
            state
                .kv
                .insert(key.clone(), String::from_utf8(bytes).unwrap());
        }
    }
    state
}

fn faults(n: usize) -> impl Iterator<Item = Option<usize>> {
    std::iter::once(None).chain((0..n).map(Some))
}

fn write_outcomes(
    plan_len: usize,
    (outcomes, error): (Vec<WriteOutcome>, Option<RunError>),
) -> Vec<WriteOutcome> {
    assert_eq!(error.is_some(), outcomes.last() == Some(&WriteOutcome::Failed));
    assert!(outcomes.len() <= plan_len);
    outcomes
}

#[derive(Default)]
struct Counts {
    states: usize,
    cases: usize,
    faulted: usize,
}

impl Counts {
    fn case(&mut self, fault: Option<usize>) {
        self.cases += 1;
        if fault.is_some() {
            self.faulted += 1;
        }
    }
}

/// One user ACTIVE at epoch 1, one at epoch 2 with a frozen attempt, one
/// missing (to exercise not-found paths); four devices; two chunk slots.
fn base_state(freezing: bool) -> Model {
    let mut state = Model::default();
    state.users.insert(
        user(0),
        UserRow {
            key_epoch: 1,
            rekey_state: None,
            rekey_started_at: None,
            rekey_starter: None,
            rekey_id: None,
            last_rekey_id: None,
            last_rekey_epoch: None,
        },
    );
    state.users.insert(
        user(1),
        UserRow {
            key_epoch: 1,
            rekey_state: if freezing { Some(s("freezing")) } else { None },
            rekey_started_at: Some(s(T0)),
            rekey_starter: Some(device(1)),
            rekey_id: if freezing { Some(s("rot-1")) } else { None },
            last_rekey_id: None,
            last_rekey_epoch: None,
        },
    );
    for (n, owner, revoked, capable, capsule, capsule_epoch) in [
        (0, 0, 0, 1, None, None),
        (1, 1, 0, 1, None, None),
        (2, 0, 1, 0, None, None),
        (3, 1, 0, 1, Some("cap"), Some(2)),
    ] {
        state.devices.insert(
            device(n),
            DeviceRow {
                user_id: user(owner),
                revoked,
                rekey_capable: capable,
                rms_capsule: capsule.map(s),
                rms_capsule_epoch: capsule_epoch,
            },
        );
    }
    state.chunks.insert(
        (user(0), item(0), 1),
        ChunkRow {
            user_id: user(0),
            chunk_id: item(0),
            epoch: 1,
            version: 2,
            lamport_clock: 5,
            last_writer: Some(device(0)),
            ciphertext: s("ct-0"),
            created_at: s(T0),
            updated_at: s(T0),
        },
    );
    state.chunks.insert(
        (user(1), item(1), 2),
        ChunkRow {
            user_id: user(1),
            chunk_id: item(1),
            epoch: 2,
            version: 1,
            lamport_clock: 1,
            last_writer: Some(device(1)),
            ciphertext: s("ct-1"),
            created_at: s(T0),
            updated_at: s(T0),
        },
    );
    state.oram.insert(
        (user(0), tree(), 1, 1),
        OramRow {
            user_id: user(0),
            tree_id: tree(),
            bucket_index: 1,
            epoch: 1,
            version: 1,
            lamport_clock: 1,
            last_writer: Some(device(0)),
            ciphertext: s("bucket"),
            created_at: s(T0),
            updated_at: s(T0),
        },
    );
    state.kv.insert(s("vault-schema:user-0"), s("2"));
    state
}

const KEYS: [&str; 4] = [
    "vault-schema:user-0",
    "vault-schema:user-1",
    "vault-schema:user-2",
    "vault-schema:user-8",
];

fn keys() -> Vec<String> {
    KEYS.iter().map(|key| s(key)).collect()
}

#[tokio::test]
async fn schema_has_the_modelled_columns() {
    let db = temp_db().await;
    let expected: [(&str, &[(&str, &str)]); 4] = [
        (
            "vault_chunks",
            &[
                ("chunk_id", "TEXT NOT NULL"),
                ("user_id", "TEXT NOT NULL"),
                ("version", "INTEGER NOT NULL DEFAULT 1"),
                ("lamport_clock", "INTEGER NOT NULL DEFAULT 0"),
                ("last_writer", "TEXT"),
                ("ciphertext", "TEXT NOT NULL"),
                ("epoch", "INTEGER NOT NULL DEFAULT 1"),
                ("created_at", "TEXT NOT NULL"),
                ("updated_at", "TEXT NOT NULL"),
            ],
        ),
        (
            "users",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("key_epoch", "INTEGER NOT NULL DEFAULT 1"),
                ("rekey_state", "TEXT"),
                ("rekey_started_at", "TEXT"),
                ("rekey_starter", "TEXT"),
                ("rekey_id", "TEXT"),
                ("last_rekey_id", "TEXT"),
                ("last_rekey_epoch", "INTEGER"),
            ],
        ),
        (
            "devices",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("user_id", "TEXT NOT NULL"),
                ("revoked", "INTEGER NOT NULL DEFAULT 0"),
                ("rekey_capable", "INTEGER NOT NULL DEFAULT 0"),
                ("rms_capsule", "TEXT"),
                ("rms_capsule_epoch", "INTEGER"),
            ],
        ),
        (
            "oram_buckets",
            &[
                ("user_id", "TEXT NOT NULL"),
                ("tree_id", "TEXT NOT NULL"),
                ("bucket_index", "INTEGER NOT NULL"),
                ("version", "INTEGER NOT NULL DEFAULT 1"),
                ("lamport_clock", "INTEGER NOT NULL DEFAULT 0"),
                ("last_writer", "TEXT"),
                ("ciphertext", "TEXT NOT NULL"),
                ("epoch", "INTEGER NOT NULL DEFAULT 1"),
                ("created_at", "TEXT NOT NULL"),
                ("updated_at", "TEXT NOT NULL"),
            ],
        ),
    ];
    for (table, columns) in expected {
        let rows = db
            .query(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                vec![TursoValue::Text(table.into())],
            )
            .await
            .unwrap();
        let ddl = rows
            .first()
            .and_then(|r| r.text(0))
            .unwrap_or_else(|| panic!("no table {table}"));
        // Turso may render declaration fragments in any whitespace layout.
        let normal = ddl.split_whitespace().collect::<Vec<_>>().join(" ");
        for (column, declaration) in columns {
            let wanted = format!("{column} {declaration}");
            let found = normal.match_indices(&wanted).any(|(at, _)| {
                let after = normal[at + wanted.len()..].chars().next();
                matches!(after, Some(',') | Some(')'))
            });
            assert!(found, "{table}.{column} is not declared `{declaration}` in: {normal}");
        }
    }
    // The model keys chunks by (user_id, chunk_id, epoch): a duplicate fails.
    let store = Store::open_temp().unwrap();
    let mut state = base_state(false);
    load(&db, &store, &state).await;
    let duplicate = db
        .execute(
            "INSERT INTO vault_chunks (chunk_id, user_id, version, lamport_clock, last_writer, \
             ciphertext, epoch, created_at, updated_at) \
             VALUES (?, ?, 1, 1, 'd', 'c', 1, 't', 't')",
            vec![TursoValue::Text(item(0)), TursoValue::Text(user(0))],
        )
        .await;
    assert!(duplicate.is_err(), "vault_chunks accepted a duplicate key");
    state.chunks.clear();
    load(&db, &store, &state).await;
}

#[tokio::test]
async fn chunk_executors_match_the_store_model() {
    let db = temp_db().await;
    let store = Store::open_temp().unwrap();
    let mut counts = Counts::default();
    let states = [base_state(false), base_state(true)];
    let targets = [item(0), item(1), item(2), s("missing")];
    let epochs = [1i64, 2, 3];

    for pre in &states {
        counts.states += 1;
        for caller in [user(0), user(1), user(2)] {
            for id in &targets {
                for epoch in epochs {
                    // read_version
                    for fault in faults(1) {
                        load(&db, &store, pre).await;
                        let plan = policy::plan_read_version(id.clone(), caller.clone(), epoch);
                        let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                        let observed = match run_read(&mut sql, &plan).await {
                            Err(_) => {
                                policy::classify_version(&ReadOutcome::Failed)
                            }
                            Ok(rows) => policy::classify_version(&ReadOutcome::Rows(
                                version_view(&rows),
                            )),
                        };
                        let expected = model::read_version(pre, id, &caller, epoch, fault);
                        assert_eq!(observed, expected, "read_version {id} {caller} {epoch} {fault:?}");
                        assert_eq!(
                            snapshot(&db, &store, &keys()).await,
                            pre.clone(),
                            "read_version changed state"
                        );
                        counts.case(fault);
                    }

                    // reread_version
                    for fault in faults(1) {
                        load(&db, &store, pre).await;
                        let plan = policy::plan_reread_version(id.clone(), caller.clone(), epoch);
                        let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                        let observed = match run_read(&mut sql, &plan).await {
                            Err(_) => policy::classify_reread(&ReadOutcome::Failed),
                            Ok(rows) => policy::classify_reread(&ReadOutcome::Rows(
                                version_view(&rows),
                            )),
                        };
                        let expected = model::reread_version(pre, id, &caller, epoch, fault);
                        assert_eq!(observed, expected, "reread {id} {caller} {epoch} {fault:?}");
                        counts.case(fault);
                    }

                    // lookup_chunk (decode failures are outside the model)
                    for fault in faults(1) {
                        load(&db, &store, pre).await;
                        let stmt = policy::plan_read_chunk(id.clone(), caller.clone(), epoch);
                        let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                        let view: ReadOutcome<Option<ChunkRowView>> =
                            match run_read(&mut sql, &stmt).await {
                                Err(_) => ReadOutcome::Failed,
                                Ok(rows) => ReadOutcome::Rows(chunk_row_view(&rows)),
                            };
                        let observed =
                            policy::classify_chunk_read(&caller, epoch, false, &view);
                        let expected = model::lookup_chunk(pre, &caller, id, epoch, false, fault);
                        assert_eq!(observed, expected, "lookup {id} {caller} {epoch} {fault:?}");
                        counts.case(fault);
                    }

                    // delete_chunk
                    let plan = policy::plan_delete_chunk(id.clone(), caller.clone(), epoch);
                    for fault in faults(plan.len()) {
                        load(&db, &store, pre).await;
                        let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                        let outcomes = write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                        let observed = policy::classify_delete(&outcomes);
                        let (expected, expected_post) =
                            model::delete_chunk(pre, id, &caller, epoch, fault);
                        let case = format!("delete {id} {caller} {epoch} {fault:?}");
                        assert_eq!(observed, expected, "{case}");
                        assert_eq!(snapshot(&db, &store, &keys()).await, expected_post, "{case}");
                        counts.case(fault);
                    }

                    // chunk_update
                    for version in [1i64, 2, 3] {
                        let plan = policy::plan_chunk_update(
                            id.clone(),
                            caller.clone(),
                            version,
                            9,
                            device(0),
                            s("new-ct"),
                            epoch,
                            s(NOW),
                            epoch,
                        );
                        for fault in faults(plan.len()) {
                            load(&db, &store, pre).await;
                            let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                            let outcomes =
                                write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                            let observed = policy::classify_chunk_update(&outcomes);
                            let (expected, expected_post) = model::chunk_update(
                                pre, id, &caller, version, 9, &device(0), "new-ct", epoch, NOW,
                                epoch, fault,
                            );
                            let case = format!("update {id} {caller} {epoch} v{version} {fault:?}");
                            assert_eq!(observed, expected, "{case}");
                            assert_eq!(
                                snapshot(&db, &store, &keys()).await,
                                expected_post,
                                "{case}"
                            );
                            counts.case(fault);
                        }
                    }

                    // chunk_create: probe then insert
                    for duplicate in [false, true] {
                        let plan = policy::plan_chunk_create(
                            id.clone(),
                            caller.clone(),
                            9,
                            device(0),
                            s("new-ct"),
                            epoch,
                            s(NOW),
                            epoch,
                        );
                        for fault in faults(2) {
                            load(&db, &store, pre).await;
                            let probe_stmt =
                                policy::plan_chunk_exists(id.clone(), caller.clone(), epoch);
                            let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                            let probe = match run_read(&mut sql, &probe_stmt).await {
                                Err(_) => ReadOutcome::Failed,
                                Ok(rows) => ReadOutcome::Rows(exists_view(&rows)),
                            };
                            let outcomes = if matches!(probe, ReadOutcome::Rows(false)) {
                                let mut insert_sql = Faulty::new(
                                    Pool { db: &db, store: &store },
                                    fault.map(|k| k.saturating_sub(1)),
                                );
                                // Skip the probe statement the pool already ran.
                                let (mut outcomes, error) =
                                    run_writes(&mut insert_sql, &plan).await;
                                if duplicate && error.is_some() {
                                    outcomes = vec![WriteOutcome::Failed];
                                }
                                outcomes
                            } else {
                                Vec::new()
                            };
                            let duplicate_error = duplicate && fault == Some(1);
                            let observed =
                                policy::classify_chunk_create(&probe, duplicate_error, &outcomes);
                            let (expected, expected_post) = model::chunk_create(
                                pre, id, &caller, 9, &device(0), "new-ct", epoch, NOW, epoch,
                                duplicate && fault == Some(1), fault,
                            );
                            let case = format!("create {id} {caller} {epoch} dup={duplicate} {fault:?}");
                            assert_eq!(observed, expected, "{case}");
                            assert_eq!(
                                snapshot(&db, &store, &keys()).await,
                                expected_post,
                                "{case}"
                            );
                            counts.case(fault);
                        }
                    }

                    // chunk_shadow: an ACTIVE account skips, the frozen one applies
                    for (starter, rotation) in
                        [(device(1), s("rot-1")), (device(0), s("rot-2"))]
                    {
                        let plan = policy::plan_chunk_shadow(
                            id.clone(),
                            user(1).clone(),
                            9,
                            device(1),
                            s("shadow-ct"),
                            epoch,
                            s(NOW),
                            1,
                            starter.clone(),
                            rotation.clone(),
                        );
                        for fault in faults(plan.len()) {
                            load(&db, &store, pre).await;
                            let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                            let outcomes =
                                write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                            let observed = policy::classify_chunk_shadow(&outcomes);
                            let (expected, expected_post) = model::chunk_shadow(
                                pre,
                                id,
                                &user(1),
                                9,
                                &device(1),
                                "shadow-ct",
                                epoch,
                                NOW,
                                1,
                                &starter,
                                &rotation,
                                fault,
                            );
                            let case = format!("shadow {id} {starter} {rotation} {fault:?}");
                            assert_eq!(observed, expected, "{case}");
                            assert_eq!(
                                snapshot(&db, &store, &keys()).await,
                                expected_post,
                                "{case}"
                            );
                            counts.case(fault);
                        }
                    }
                }
            }
        }
    }
    eprintln!(
        "vault executor conformance (chunks): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn rotation_executors_match_the_store_model() {
    let db = temp_db().await;
    let store = Store::open_temp().unwrap();
    let mut counts = Counts::default();
    let states = [
        base_state(false),
        base_state(true),
        {
            // The frozen attempt rotated id, so the CAS cannot match it.
            let mut state = base_state(true);
            state.users.get_mut(&user(1)).unwrap().rekey_id = Some(s("rot-9"));
            state
        },
        {
            // No ORAM, every active device capable and acknowledged: a freeze
            // is ready only after the capsule clear.
            let mut state = base_state(false);
            state.oram.clear();
            for (id, row) in state.devices.iter_mut() {
                row.rms_capsule_epoch = None;
                row.rms_capsule = None;
                if id == &device(2) {
                    row.rekey_capable = 1;
                }
            }
            state
        },
    ];

    for pre in &states {
        counts.states += 1;
        for from_epoch in [1i64, 2] {
            for to_epoch in [2i64, 3] {
                for (starter, rotation) in
                    [(device(1), s("rot-1")), (device(0), s("rot-1")), (device(1), s("rot-9"))]
                {
                    // freeze transaction: CAS, cleanup, commit
                    for fault in faults(3) {
                        load(&db, &store, pre).await;
                        let guard = db.tx().await.unwrap();
                        let mut sql = Faulty::new(Tx { guard: Some(guard) }, fault);
                        let cas_plan =
                            policy::plan_freeze_cas(user(1).clone(), from_epoch, s(NOW), starter.clone(), rotation.clone());
                        let (cas, cas_error) = run_writes(&mut sql, &cas_plan).await;
                        let mut outcomes = cas.clone();
                        let cleanup = if matches!(cas.first(), Some(WriteOutcome::Applied(1))) {
                            let (cleanup_outcomes, _) = run_writes(
                                &mut sql,
                                &policy::plan_freeze_cleanup(user(1).clone(), from_epoch),
                            )
                            .await;
                            outcomes.extend(cleanup_outcomes.clone());
                            Some(policy::classify_cleanup(&cleanup_outcomes))
                        } else {
                            None
                        };
                        let commit = if cleanup == Some(CleanupObservation::Done) {
                            let (commit_outcomes, _) =
                                run_writes(&mut sql, &policy::plan_commit_transaction()).await;
                            outcomes.extend(commit_outcomes.clone());
                            policy::classify_transaction(&commit_outcomes)
                        } else {
                            TransactionObservation::Failed
                        };
                        drop(sql);
                        settle(&db).await;
                        let cas_obs = policy::classify_freeze_cas(&cas);
                        let (expected_cas, expected_cleanup, expected_commit, expected_post) =
                            model::freeze_transaction(
                                pre,
                                &user(1),
                                from_epoch,
                                NOW,
                                &starter,
                                &rotation,
                                fault,
                            );
                        let case = format!(
                            "freeze from {from_epoch} {starter} {rotation} {fault:?} pre {pre:?}"
                        );
                        assert_eq!(cas_obs, expected_cas, "{case}");
                        assert_eq!(
                            cleanup.unwrap_or(CleanupObservation::Storage),
                            expected_cleanup,
                            "{case}"
                        );
                        assert_eq!(commit, expected_commit, "{case}");
                        assert_eq!(
                            snapshot(&db, &store, &keys()).await,
                            expected_post,
                            "{case}"
                        );
                        assert_eq!(cas_error.is_some(), fault == Some(0), "{case}");
                        counts.case(fault);
                    }

                    // commit CAS + sweep
                    for fault in faults(2) {
                        load(&db, &store, pre).await;
                        let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                        let cas_plan = policy::plan_commit_cas(
                            user(1).clone(),
                            from_epoch,
                            to_epoch,
                            starter.clone(),
                            rotation.clone(),
                        );
                        let (cas_outcomes, _) = run_writes(&mut sql, &cas_plan).await;
                        let cas_obs = policy::classify_freeze_cas(&cas_outcomes);
                        let (sweep, _) = if matches!(cas_obs, CasObservation::Updated) {
                            let (sweep_outcomes, _) = run_writes(
                                &mut sql,
                                &policy::plan_sweep_old_chunks(user(1).clone(), to_epoch),
                            )
                            .await;
                            (policy::classify_sweep(&sweep_outcomes), ())
                        } else {
                            (SweepObservation::Failed, ())
                        };
                        let (expected_cas, expected_sweep, expected_post) =
                            model::commit_and_sweep(
                                pre,
                                &user(1),
                                from_epoch,
                                to_epoch,
                                &starter,
                                &rotation,
                                fault,
                            );
                        let case = format!(
                            "commit {from_epoch}->{to_epoch} {starter} {rotation} {fault:?}"
                        );
                        assert_eq!(cas_obs, expected_cas, "{case}");
                        assert_eq!(sweep, expected_sweep, "{case}");
                        assert_eq!(
                            snapshot(&db, &store, &keys()).await,
                            expected_post,
                            "{case}"
                        );
                        counts.case(fault);
                    }

                    // abort/timeout transaction: CAS, chunk delete, capsule
                    // clear, commit
                    for fault in faults(4) {
                        load(&db, &store, pre).await;
                        let guard = db.tx().await.unwrap();
                        let mut sql = Faulty::new(Tx { guard: Some(guard) }, fault);
                        let cash = policy::plan_rollback_cas(
                            user(1).clone(),
                            from_epoch,
                            rotation.clone(),
                        );
                        let (cas_outcomes, cas_error) = run_writes(&mut sql, &cash).await;
                        let mut outcomes = cas_outcomes.clone();
                        let mut failed = cas_error.is_some();
                        if !failed
                            && matches!(cas_outcomes.first(), Some(WriteOutcome::Applied(1)))
                        {
                            let (cleanup_outcomes, cleanup_error) = run_writes(
                                &mut sql,
                                &policy::plan_rollback_cleanup(
                                    user(1).clone(),
                                    from_epoch,
                                    from_epoch + 1,
                                ),
                            )
                            .await;
                            failed = cleanup_error.is_some();
                            outcomes.extend(cleanup_outcomes);
                        }
                        // The server drops the transaction on any failure; it
                        // only commits after a clean CAS (and its cleanup).
                        if !failed {
                            let (commit_outcomes, _) =
                                run_writes(&mut sql, &policy::plan_commit_transaction()).await;
                            outcomes.extend(commit_outcomes);
                        }
                        drop(sql);
                        settle(&db).await;
                        let observed = policy::classify_rollback(&outcomes);
                        let (expected, expected_post) = model::rollback_transaction(
                            pre,
                            &user(1),
                            from_epoch,
                            from_epoch + 1,
                            &rotation,
                            fault,
                        );
                        let case = format!("rollback {from_epoch} {rotation} {fault:?}");
                        assert_eq!(observed, expected, "{case}");
                        assert_eq!(
                            snapshot(&db, &store, &keys()).await,
                            expected_post,
                            "{case}"
                        );
                        counts.case(fault);
                    }
                }
            }
        }

        // completeness probes
        for (from_epoch, to_epoch) in [(1i64, 2i64), (2, 3)] {
            for (name, stmt) in [
                ("oram", policy::plan_probe_oram(user(1).clone())),
                ("capable", policy::plan_probe_capable(user(1).clone())),
                ("ack", policy::plan_probe_acknowledged(user(1).clone())),
                (
                    "shadows",
                    policy::plan_probe_chunk_shadows(user(1).clone(), from_epoch, to_epoch),
                ),
                (
                    "capsules",
                    policy::plan_probe_device_capsules(user(1).clone(), to_epoch),
                ),
            ] {
                for fault in faults(1) {
                    load(&db, &store, pre).await;
                    let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                    let observed = match run_read(&mut sql, &stmt).await {
                        Err(_) => policy::classify_probe(&ReadOutcome::Failed),
                        Ok(rows) => policy::classify_probe(&ReadOutcome::Rows(exists_view(&rows))),
                    };
                    let expected = model::probe(pre, &stmt, fault);
                    assert_eq!(observed, expected, "probe {name} {fault:?}");
                    counts.case(fault);
                }
            }
        }

        // inventory rows
        for epoch in [1i64, 2, 3] {
            for fault in faults(1) {
                load(&db, &store, pre).await;
                let stmt = policy::plan_read_inventory(user(1).clone(), epoch);
                let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                let observed = match run_read(&mut sql, &stmt).await {
                    Err(_) => policy::classify_inventory(&ReadOutcome::Failed),
                    Ok(rows) => policy::classify_inventory(&ReadOutcome::Rows(inventory_rows(
                        &rows,
                    ))),
                };
                let expected = model::inventory(pre, &user(1), epoch, fault);
                assert_eq!(observed, expected, "inventory {epoch} {fault:?}");
                counts.case(fault);
            }
        }

        // shadow activity refresh
        for (read_epoch, write_epoch) in [(1i64, 2i64), (1, 1)] {
            let plan = policy::plan_shadow_activity(
                user(1).clone(),
                read_epoch,
                device(1),
                s("rot-1"),
                s(NOW),
            );
            for fault in faults(plan.len()) {
                load(&db, &store, pre).await;
                let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                let observed = if write_epoch == read_epoch {
                    ActivityObservation::Refreshed
                } else {
                    let outcomes = write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                    policy::classify_shadow_activity(&outcomes)
                };
                let (expected, expected_post) = model::shadow_activity(
                    pre,
                    &user(1),
                    read_epoch,
                    &device(1),
                    "rot-1",
                    NOW,
                    write_epoch,
                    fault,
                );
                assert_eq!(observed, expected, "activity {read_epoch}/{write_epoch} {fault:?}");
                assert_eq!(snapshot(&db, &store, &keys()).await, expected_post);
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "vault executor conformance (rotation): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn device_oram_and_schema_executors_match_the_store_model() {
    let db = temp_db().await;
    let store = Store::open_temp().unwrap();
    let mut counts = Counts::default();
    let states = [base_state(false), base_state(true)];

    for pre in &states {
        counts.states += 1;
        for caller in [user(0), user(1), user(2)] {
            for device_id in [device(0), device(1), device(2), device(3), s("missing")] {
                // capsule acknowledgement
                for epoch in [1i64, 2, 3] {
                    let plan = policy::plan_ack_capsule(device_id.clone(), caller.clone(), epoch);
                    for fault in faults(plan.len()) {
                        load(&db, &store, pre).await;
                        let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                        let outcomes = write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                        let observed = policy::classify_ack(&outcomes);
                        let (expected, expected_post) =
                            model::acknowledge(pre, &device_id, &caller, epoch, fault);
                        let case = format!("ack {device_id} {caller} {epoch} {fault:?}");
                        assert_eq!(observed, expected, "{case}");
                        assert_eq!(
                            snapshot(&db, &store, &keys()).await,
                            expected_post,
                            "{case}"
                        );
                        counts.case(fault);
                    }
                }

                // pending-epoch probe
                for fault in faults(1) {
                    load(&db, &store, pre).await;
                    let stmt = policy::plan_pending_capsule(device_id.clone(), caller.clone());
                    let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                    let observed = match run_read(&mut sql, &stmt).await {
                        Err(_) => policy::classify_pending(&ReadOutcome::Failed),
                        Ok(rows) => policy::classify_pending(&ReadOutcome::Rows(
                            pending_row_view(&rows),
                        )),
                    };
                    let expected = model::pending(pre, &device_id, &caller, fault);
                    assert_eq!(observed, expected, "pending {device_id} {caller} {fault:?}");
                    counts.case(fault);
                }

                // capability attestation
                let plan = policy::plan_attest_capable(device_id.clone(), caller.clone());
                for fault in faults(plan.len()) {
                    load(&db, &store, pre).await;
                    let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                    let outcomes = write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                    let observed = policy::classify_attest(&outcomes);
                    let (expected, expected_post) =
                        model::attest(pre, &device_id, &caller, fault);
                    let case = format!("attest {device_id} {caller} {fault:?}");
                    assert_eq!(observed, expected, "{case}");
                    assert_eq!(snapshot(&db, &store, &keys()).await, expected_post, "{case}");
                    counts.case(fault);
                }
            }

            // capsule write for the rotation
            let plan = policy::plan_write_capsule(
                device(1),
                caller.clone(),
                s("new-cap"),
                2,
                1,
                device(1),
                s("rot-1"),
            );
            for fault in faults(plan.len()) {
                load(&db, &store, pre).await;
                let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                let outcomes = write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                let observed = policy::classify_capsule_write(&outcomes);
                let (expected, expected_post) = model::write_capsule(
                    pre,
                    &device(1),
                    &caller,
                    "new-cap",
                    2,
                    1,
                    &device(1),
                    "rot-1",
                    fault,
                );
                let case = format!("capsule {caller} {fault:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(snapshot(&db, &store, &keys()).await, expected_post, "{case}");
                counts.case(fault);
            }

            // ORAM buckets: create (probe then insert) and version CAS
            for index in [1i64, 2] {
                for epoch in [1i64, 2] {
                    let key = (caller.clone(), tree(), index, epoch);
                    for if_match in [0i64, 1, 2] {
                        for fault in faults(2) {
                            load(&db, &store, pre).await;
                            let observed = if if_match == 0 {
                                let probe_stmt = policy::plan_oram_exists(
                                    caller.clone(),
                                    tree(),
                                    index,
                                    epoch,
                                );
                                let mut sql =
                                    Faulty::new(Pool { db: &db, store: &store }, fault);
                                let probe = match run_read(&mut sql, &probe_stmt).await {
                                    Err(_) => ReadOutcome::Failed,
                                    Ok(rows) => {
                                        ReadOutcome::Rows(exists_view(&rows))
                                    }
                                };
                                let outcomes = if matches!(probe, ReadOutcome::Rows(false)) {
                                    let mut insert_sql = Faulty::new(
                                        Pool { db: &db, store: &store },
                                        fault.map(|k| k.saturating_sub(1)),
                                    );
                                    run_writes(
                                        &mut insert_sql,
                                        &policy::plan_oram_insert(
                                            caller.clone(),
                                            tree(),
                                            index,
                                            9,
                                            device(0),
                                            s("bucket-ct"),
                                            epoch,
                                            s(NOW),
                                        ),
                                    )
                                    .await
                                    .0
                                } else {
                                    Vec::new()
                                };
                                policy::classify_oram_create(&probe, &outcomes)
                            } else {
                                let plan = policy::plan_oram_update(
                                    caller.clone(),
                                    tree(),
                                    index,
                                    if_match,
                                    9,
                                    device(0),
                                    s("bucket-ct"),
                                    epoch,
                                    s(NOW),
                                );
                                let mut sql =
                                    Faulty::new(Pool { db: &db, store: &store }, fault);
                                let outcomes =
                                    write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                                policy::classify_oram_update(&outcomes)
                            };
                            let (expected, expected_post) = model::oram_write(
                                pre,
                                &caller,
                                &tree(),
                                index,
                                if_match,
                                9,
                                &device(0),
                                "bucket-ct",
                                epoch,
                                NOW,
                                fault,
                            );
                            let case = format!(
                                "oram {caller} {index} {epoch} if_match {if_match} {fault:?} key {:?}",
                                key
                            );
                            assert_eq!(observed, expected, "{case}");
                            assert_eq!(
                                snapshot(&db, &store, &keys()).await,
                                expected_post,
                                "{case}"
                            );
                            counts.case(fault);
                        }
                    }
                }
            }

            // The one durable schema key writes. A fresh store per case: the
            // sled store has no delete, and the model's key set is exact.
            let key = format!("vault-schema:{caller}");
            let plan = policy::plan_schema_floor(key.clone());
            for fault in faults(plan.len()) {
                let store = Store::open_temp().unwrap();
                load(&db, &store, pre).await;
                let mut sql = Faulty::new(Pool { db: &db, store: &store }, fault);
                let outcomes = write_outcomes(plan.len(), run_writes(&mut sql, &plan).await);
                let observed = policy::classify_schema_write(&outcomes);
                let (expected, expected_post) = model::schema_floor(pre, &key, fault);
                let case = format!("schema {caller} {fault:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(snapshot(&db, &store, &keys()).await, expected_post, "{case}");
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "vault executor conformance (devices/oram/schema): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}
