//! Bounded conformance of the session executors against a real database and
//! a real sled store (F-1).
//!
//! The F* proofs in `vela-session-policy/proofs/fstar/store-lemmas` show that
//! each executor's plan and classifier are honest *in the store model*. This
//! test checks the model against turso and sled: for every small starting
//! state, every executor method and every fault point (no fault, or a failure
//! injected at each logical statement in turn), it runs the real executor
//! (plan, rendered SQL or store call, row decoding, classification) through
//! [`Faulty`] and compares the resulting tables, keys and observation with the
//! Rust mirror of the model (`vela_session_policy::store_model`).
//!
//! A schema check pins the columns the model uses.

use std::collections::BTreeSet;

use vela_session_policy::deletion_driver::DeletionTable;
use vela_session_policy::revocation_driver::RecordObservation;
use vela_session_policy::store_model::{
    self as model, Db as Model, DeviceRow, MailRow, OwnedRow, SessionRow, Store as ModelStore,
    UserRow,
};

use super::session_store::{DbSql, SessionSql, SessionStore, SledStore};
use crate::account::delete::DeleteAccountIo;
use crate::auth::logout::LogoutJtiIo;
use crate::device::revoke::RevokeDeviceIo;
use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};
use crate::store::Store;

/// Fails the k-th statement (from 0) an executor sends, without sending it.
pub(crate) struct Faulty<T> {
    pub inner: T,
    pub fail_at: Option<usize>,
    pub calls: usize,
}

impl<T> Faulty<T> {
    pub fn new(inner: T, fail_at: Option<usize>) -> Self {
        Self { inner, fail_at, calls: 0 }
    }

    fn hit(&mut self) -> anyhow::Result<()> {
        let k = self.calls;
        self.calls += 1;
        if self.fail_at == Some(k) {
            Err(anyhow::anyhow!("injected failure at statement {k}"))
        } else {
            Ok(())
        }
    }
}

impl<T: SessionSql> SessionSql for Faulty<T> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.hit()?;
        self.inner.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.hit()?;
        self.inner.execute(sql, params).await
    }

    async fn execute_in_tx(
        &mut self,
        sql: &str,
        params: Vec<TursoValue>,
    ) -> anyhow::Result<u64> {
        self.hit()?;
        self.inner.execute_in_tx(sql, params).await
    }

    async fn begin(&mut self) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.begin().await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.commit().await
    }

    fn rollback(&mut self) {
        self.inner.rollback();
    }
}

impl<T: SessionStore> SessionStore for Faulty<T> {
    fn set_ex(&mut self, key: &str, value: u8, ttl: u64) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.set_ex(key, value, ttl)
    }

    fn revoke_jtis(&mut self, device: &str) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.revoke_jtis(device)
    }
}

const NOW: &str = "2026-10-29T12:00:00+00:00";

fn s(x: &str) -> String {
    x.to_string()
}

async fn temp_db() -> TursoDb {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "{}/vela-session-conformance-{}-{}.db",
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

async fn load(db: &TursoDb, state: &Model) {
    db.execute_batch(
        "DELETE FROM shared_items; DELETE FROM share_inbox; DELETE FROM users;
         DELETE FROM devices; DELETE FROM web_sessions; DELETE FROM sends;
         DELETE FROM vault_chunks; DELETE FROM oram_buckets;",
    )
    .await
    .unwrap();
    for (id, row) in &state.users {
        db.execute(
            "INSERT INTO users (id, created_at, share_ek, share_ek_since) VALUES (?, 't', ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.share_ek.clone()),
                TursoValue::Text(row.share_ek_since.clone()),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.devices {
        db.execute(
            "INSERT INTO devices (id, user_id, device_name, device_type, hybrid_ek, hybrid_vk, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.user_id.clone()),
                TursoValue::Text(row.name.clone()),
                TursoValue::Text(row.kind.clone()),
                TursoValue::Text(crate::db::encode_b64(b"ek")),
                TursoValue::Text(row.hybrid_vk.clone()),
                TursoValue::Integer(row.revoked),
                TursoValue::Text(NOW.into()),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.sessions {
        db.execute(
            "INSERT INTO web_sessions (id, user_id, approver_user_id, ephemeral_pk, link_nonce, status, capsule, approved_by, created_at) VALUES (?, ?, ?, 'pk', 'nonce', ?, ?, ?, 't')",
            vec![
                TursoValue::Text(id.clone()),
                opt(&row.user_id),
                opt(&row.approver_user_id),
                TursoValue::Text(row.status.clone()),
                opt(&row.capsule),
                opt(&row.approved_by),
            ],
        )
        .await
        .unwrap();
    }
    for (table, rows) in [("share_inbox", &state.inbox), ("shared_items", &state.items)] {
        for (id, row) in rows {
            let sql = if table == "share_inbox" {
                "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at) VALUES (?, ?, ?, 'c', 't')"
            } else {
                "INSERT INTO shared_items (id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked) VALUES (?, ?, ?, 'c', 't', 't', 0)"
            };
            db.execute(
                sql,
                vec![
                    TursoValue::Text(id.clone()),
                    TursoValue::Text(row.sender.clone()),
                    TursoValue::Text(row.recipient.clone()),
                ],
            )
            .await
            .unwrap();
        }
    }
    for (id, row) in &state.sends {
        db.execute(
            "INSERT INTO sends (id, owner_user_id, ciphertext, created_at, expires_at) VALUES (?, ?, 'c', 't', 't')",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.user.clone()),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.chunks {
        db.execute(
            "INSERT INTO vault_chunks (chunk_id, user_id, ciphertext, created_at, updated_at) VALUES (?, ?, 'c', 't', 't')",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.user.clone()),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.buckets {
        db.execute(
            "INSERT INTO oram_buckets (user_id, tree_id, bucket_index, ciphertext, created_at, updated_at) VALUES (?, ?, ?, 'c', 't', 't')",
            vec![
                TursoValue::Text(row.user.clone()),
                TursoValue::Text(id.clone()),
                TursoValue::Integer(0),
            ],
        )
        .await
        .unwrap();
    }
}

fn text(row: &VelaRow, i: usize) -> String {
    row.text(i)
        .unwrap_or_else(|| panic!("column {i} is not text"))
        .to_string()
}

fn text_opt(row: &VelaRow, i: usize) -> Option<String> {
    row.text(i).map(String::from)
}

/// The modelled columns of all eight tables.
async fn snapshot(db: &TursoDb) -> Model {
    let mut state = Model::default();
    for row in db
        .query("SELECT id, share_ek, share_ek_since FROM users", vec![])
        .await
        .unwrap()
    {
        state.users.insert(
            text(&row, 0),
            UserRow {
                share_ek: text_opt(&row, 1).unwrap_or_default(),
                share_ek_since: text_opt(&row, 2).unwrap_or_default(),
            },
        );
    }
    for row in db
        .query(
            "SELECT id, user_id, revoked, hybrid_vk, last_active, device_name, device_type, revoked_at, revoked_by FROM devices",
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
                hybrid_vk: text_opt(&row, 3).unwrap_or_default(),
                last_active: text_opt(&row, 4),
                name: text_opt(&row, 5).unwrap_or_default(),
                kind: text_opt(&row, 6).unwrap_or_default(),
                revoked_at: text_opt(&row, 7),
                revoked_by: text_opt(&row, 8),
            },
        );
    }
    for row in db
        .query(
            "SELECT id, user_id, approver_user_id, status, capsule, approved_by FROM web_sessions",
            vec![],
        )
        .await
        .unwrap()
    {
        state.sessions.insert(
            text(&row, 0),
            SessionRow {
                user_id: text_opt(&row, 1),
                approver_user_id: text_opt(&row, 2),
                status: text_opt(&row, 3).unwrap_or_default(),
                capsule: text_opt(&row, 4),
                approved_by: text_opt(&row, 5),
            },
        );
    }
    for row in db
        .query("SELECT id, sender_user_id, recipient_user_id FROM share_inbox", vec![])
        .await
        .unwrap()
    {
        state
            .inbox
            .insert(text(&row, 0), MailRow { sender: text(&row, 1), recipient: text(&row, 2) });
    }
    for row in db
        .query("SELECT id, sender_user_id, recipient_user_id FROM shared_items", vec![])
        .await
        .unwrap()
    {
        state
            .items
            .insert(text(&row, 0), MailRow { sender: text(&row, 1), recipient: text(&row, 2) });
    }
    for row in db
        .query("SELECT id, owner_user_id FROM sends", vec![])
        .await
        .unwrap()
    {
        state
            .sends
            .insert(text(&row, 0), OwnedRow { user: text(&row, 1) });
    }
    for row in db
        .query("SELECT chunk_id, user_id FROM vault_chunks", vec![])
        .await
        .unwrap()
    {
        state
            .chunks
            .insert(text(&row, 0), OwnedRow { user: text(&row, 1) });
    }
    for row in db
        .query("SELECT tree_id, user_id FROM oram_buckets", vec![])
        .await
        .unwrap()
    {
        state
            .buckets
            .insert(text(&row, 0), OwnedRow { user: text(&row, 1) });
    }
    state
}

/// The fault points of a plan of `n` statements: none, then each statement.
fn faults(n: usize) -> impl Iterator<Item = Option<usize>> {
    std::iter::once(None).chain((0..n).map(Some))
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

fn user(n: u128) -> String {
    format!("00000000-0000-0000-0000-{:012x}", 0x1000 + n)
}
fn device(n: u128) -> String {
    format!("00000000-0000-0000-0000-{:012x}", 0x3000 + n)
}
fn session_id(n: u128) -> String {
    format!("00000000-0000-0000-0000-{:012x}", 0x4000 + n)
}

fn active_device(owner: u128) -> DeviceRow {
    DeviceRow {
        user_id: user(owner),
        revoked: 0,
        hybrid_vk: s("dms="),
        last_active: None,
        name: s("name"),
        kind: s("desktop"),
        revoked_at: None,
        revoked_by: None,
    }
}

fn base_state() -> Model {
    let mut state = Model::default();
    for n in 0..3 {
        state.users.insert(
            user(n),
            UserRow { share_ek: format!("ek-{n}"), share_ek_since: s("t0") },
        );
    }
    state.devices.insert(device(0), active_device(0));
    let mut revoked = active_device(0);
    revoked.revoked = 1;
    state.devices.insert(device(1), revoked);
    state.devices.insert(device(2), active_device(1));
    // The target account's footprint in every table, plus other accounts'.
    state.sessions.insert(
        session_id(0),
        SessionRow {
            user_id: Some(user(0)),
            approver_user_id: Some(user(1)),
            status: s("granted"),
            capsule: Some(s("cap")),
            approved_by: Some(device(0)),
        },
    );
    state.sessions.insert(
        session_id(1),
        SessionRow {
            user_id: None,
            approver_user_id: Some(user(0)),
            status: s("pending"),
            capsule: None,
            approved_by: None,
        },
    );
    state.sessions.insert(
        session_id(2),
        SessionRow {
            user_id: Some(user(0)),
            approver_user_id: Some(user(0)),
            status: s("granted"),
            capsule: Some(s("cap")),
            approved_by: Some(device(1)),
        },
    );
    state.sessions.insert(
        session_id(3),
        SessionRow {
            user_id: Some(user(1)),
            approver_user_id: Some(user(1)),
            status: s("revoked"),
            capsule: None,
            approved_by: Some(device(1)),
        },
    );
    state.inbox.insert(s("i0"), MailRow { sender: user(0), recipient: user(1) });
    state.inbox.insert(s("i1"), MailRow { sender: user(2), recipient: user(0) });
    state.items.insert(s("i0"), MailRow { sender: user(0), recipient: user(1) });
    state.items.insert(s("i1"), MailRow { sender: user(2), recipient: user(0) });
    state.sends.insert(s("x0"), OwnedRow { user: user(0) });
    state.sends.insert(s("x1"), OwnedRow { user: user(1) });
    state.chunks.insert(s("c0"), OwnedRow { user: user(0) });
    state.chunks.insert(s("c1"), OwnedRow { user: user(1) });
    state.buckets.insert(s("b0"), OwnedRow { user: user(0) });
    state.buckets.insert(s("b1"), OwnedRow { user: user(2) });
    state
}

fn states() -> Vec<Model> {
    let mut out = vec![base_state()];
    // The target account has no `users` row (an orphan footprint).
    let mut absent = base_state();
    absent.users.remove(&user(0));
    out.push(absent);
    // No sessions approved by any device.
    let mut no_cascade = base_state();
    no_cascade.sessions.clear();
    out.push(no_cascade);
    out
}

/// Seeds `device:jtis:` sets so the lockout has JTIs to revoke.
fn seed_jtis(store: &Store, ids: &[String]) {
    for (n, id) in ids.iter().enumerate() {
        if n % 2 == 0 {
            store.sadd(&format!("device:jtis:{id}"), "jti-a", 3600).unwrap();
            store.sadd(&format!("device:jtis:{id}"), "jti-b", 3600).unwrap();
        }
    }
}

fn model_store(ids: &[String]) -> ModelStore {
    let mut store = ModelStore::default();
    for (n, id) in ids.iter().enumerate() {
        if n % 2 == 0 {
            store
                .sets
                .insert(id.clone(), BTreeSet::from([s("jti-a"), s("jti-b")]));
        }
    }
    store
}

/// Every candidate lockout key the model may write, and every JTI it may
/// revoke.
fn check_store(store: &Store, expected: &ModelStore, ids: &[String]) {
    for id in ids {
        let key = format!("device:revoked:{id}");
        let want = expected.kv.get(&key).map(|v| v == "1").unwrap_or(false);
        assert_eq!(
            store.exists(&key).unwrap(),
            want,
            "sentinel {key} should be {want}"
        );
        let members = store.smembers(&format!("device:jtis:{id}")).unwrap();
        let want_members = expected.sets.get(id).cloned().unwrap_or_default();
        assert_eq!(
            members.into_iter().collect::<BTreeSet<_>>(),
            want_members,
            "jti set of {id}"
        );
    }
    for jti in ["jti-a", "jti-b"] {
        let key = format!("jti:revoked:{jti}");
        let want = expected.revoked.contains(jti);
        assert_eq!(store.get(&key).unwrap().is_some(), want, "marker {key}");
    }
}

#[tokio::test]
async fn schema_has_the_modelled_columns() {
    let db = temp_db().await;
    let expected: [(&str, &[(&str, &str)]); 8] = [
        (
            "users",
            &[("id", "TEXT UNIQUE NOT NULL"), ("share_ek", "TEXT"), ("share_ek_since", "TEXT")],
        ),
        (
            "devices",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("user_id", "TEXT NOT NULL"),
                ("revoked", "INTEGER NOT NULL DEFAULT 0"),
                ("revoked_at", "TEXT"),
                ("revoked_by", "TEXT"),
            ],
        ),
        (
            "web_sessions",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("user_id", "TEXT"),
                ("approver_user_id", "TEXT"),
                ("status", "TEXT NOT NULL"),
                ("capsule", "TEXT"),
                ("approved_by", "TEXT"),
            ],
        ),
        (
            "share_inbox",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("sender_user_id", "TEXT NOT NULL"),
                ("recipient_user_id", "TEXT NOT NULL"),
            ],
        ),
        (
            "shared_items",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("sender_user_id", "TEXT NOT NULL"),
                ("recipient_user_id", "TEXT NOT NULL"),
            ],
        ),
        (
            "sends",
            &[("id", "TEXT UNIQUE NOT NULL"), ("owner_user_id", "TEXT NOT NULL")],
        ),
        ("vault_chunks", &[("chunk_id", "TEXT NOT NULL"), ("user_id", "TEXT NOT NULL")]),
        ("oram_buckets", &[("user_id", "TEXT NOT NULL"), ("tree_id", "TEXT NOT NULL")]),
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
        let normal = ddl.split_whitespace().collect::<Vec<_>>().join(" ");
        for (column, declaration) in columns {
            let wanted = format!("{column} {declaration}");
            let found = normal.match_indices(&wanted).any(|(at, _)| {
                let before = normal[..at].chars().last();
                let after = normal[at + wanted.len()..].chars().next();
                matches!(before, Some('(') | Some(' ') | Some(','))
                    && matches!(after, Some(',') | Some(')'))
            });
            assert!(found, "{table}.{column} is not declared `{declaration}` in: {normal}");
        }
    }
    // The model keys every table by its id: a duplicate insert fails.
    let state = base_state();
    load(&db, &state).await;
    let duplicate = db
        .execute(
            "INSERT INTO shared_items (id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked) VALUES ('i0', 'a', 'b', 'c', 't', 't', 0)",
            vec![],
        )
        .await;
    assert!(duplicate.is_err(), "shared_items accepted a duplicate id");
}

#[tokio::test]
async fn logout_executor_matches_the_store_model() {
    let mut counts = Counts::default();
    for pre_keys in [false, true] {
        counts.states += 1;
        let mut pre = ModelStore::default();
        if pre_keys {
            pre.kv.insert(s("jti:revoked:j"), s("1"));
        }
        for fault in faults(1) {
            let store = Store::open_temp().unwrap();
            if pre_keys {
                store.set_ex("jti:revoked:j", &[1], 900).unwrap();
            }
            let mut io = LogoutJtiIo {
                store: Faulty::new(SledStore(&store), fault),
                jti: s("j"),
                error: None,
            };
            let observed = io.revoke_jti().await;
            let (expected, expected_store) = model::logout(&pre, "j", fault);
            let case = format!("logout fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error.is_some(), fault.is_some(), "{case} {:?}", io.error.as_ref().map(|e| e.to_string()));
            assert_eq!(
                store.get("jti:revoked:j").unwrap().is_some(),
                expected_store.kv.contains_key("jti:revoked:j"),
                "{case}"
            );
            counts.case(fault);
        }
    }
    assert_eq!(counts.states, 2);
    eprintln!(
        "session executor conformance (logout): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn revocation_executors_match_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    let scratch = Store::open_temp().unwrap();
    for pre in states() {
        counts.states += 1;
        let caller = user(0);

        // lookup_target
        for target in [device(0), device(1), device(2), device(9)] {
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = RevokeDeviceIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                    store: SledStore(&scratch),
                    actor_user_id: uuid::Uuid::parse_str(&caller).unwrap(),
                    actor_device_id: uuid::Uuid::parse_str(&device(0)).unwrap(),
                    device_id_str: target.clone(),
                    error: None,
                };
                let observed = io.lookup_target().await;
                let expected = model::revoke_observe(&pre, &caller, &target, fault);
                let case = format!("lookup {target} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                assert_eq!(snapshot(&db).await, pre, "{case}");
                counts.case(fault);
            }
        }

        // lockout_device
        let ids = vec![device(0)];
        let pre_store = model_store(&ids);
        for fault in faults(2) {
            let store = Store::open_temp().unwrap();
            seed_jtis(&store, &ids);
            load(&db, &pre).await;
            let mut io = RevokeDeviceIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                store: Faulty::new(SledStore(&store), fault),
                actor_user_id: uuid::Uuid::parse_str(&caller).unwrap(),
                actor_device_id: uuid::Uuid::parse_str(&device(0)).unwrap(),
                device_id_str: device(0),
                error: None,
            };
            let observed = io.lockout_device().await;
            let (expected, expected_store) = model::lockout_device(&pre_store, &device(0), fault);
            let case = format!("lockout fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
            check_store(&store, &expected_store, &ids);
            counts.case(fault);
        }

        // record_revocation
        for target in [device(0), device(1), device(9)] {
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = RevokeDeviceIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                    store: SledStore(&scratch),
                    actor_user_id: uuid::Uuid::parse_str(&caller).unwrap(),
                    actor_device_id: uuid::Uuid::parse_str(&device(0)).unwrap(),
                    device_id_str: target.clone(),
                    error: None,
                };
                let observed = io.record_revocation().await;
                let case = format!("record {target} fault {fault:?} pre {pre:?}");
                let actual = snapshot(&db).await;
                // The handler stamps the current time; the model takes the
                // stamp as an input, so feed the row's own value back.
                let stamp = actual
                    .devices
                    .get(&target)
                    .and_then(|row| row.revoked_at.clone())
                    .unwrap_or_else(|| NOW.into());
                let (expected, mut want) =
                    model::revoke_record(&pre, &target, &stamp, &device(0), fault);
                assert_eq!(observed, expected, "{case}");
                assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                if expected == RecordObservation::Updated {
                    if let Some(row) = want.devices.get_mut(&target) {
                        row.revoked_at = Some(stamp.clone());
                    }
                }
                assert_eq!(actual, want, "{case}");
                counts.case(fault);
            }
        }

        // cascade_web_sessions
        let approved: Vec<String> = pre
            .sessions
            .iter()
            .filter(|(_, r)| {
                r.approved_by.as_deref() == Some(&device(0)) && r.status != "revoked"
            })
            .map(|(id, _)| id.clone())
            .collect();
        // Two SQL statements (the read and the update); the per-session
        // store lockouts are covered by the lockout tests above.
        let sql_points = 2;
        for fault in (0..sql_points).map(Some).chain(std::iter::once(None)) {
            let store = Store::open_temp().unwrap();
            seed_jtis(&store, &approved);
            load(&db, &pre).await;
            let mut io = RevokeDeviceIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                store: SledStore(&store),
                actor_user_id: uuid::Uuid::parse_str(&caller).unwrap(),
                actor_device_id: uuid::Uuid::parse_str(&device(0)).unwrap(),
                device_id_str: device(0),
                error: None,
            };
            // A SQL fault before the cascade's update leaves the rows alone.
            let observed = io.cascade_web_sessions().await;
            let (_, want_db) = if fault.is_none() {
                (model::revoke_record(&pre, &device(0), NOW, &device(0), None).0,
                 pre.st_revoke_approved(&device(0), &caller))
            } else {
                (RecordObservation::Failed, pre.clone())
            };
            let case = format!("cascade fault {fault:?} pre {pre:?}");
            let want_obs = if fault.is_none() {
                vela_session_policy::store::classify_cascade(true)
            } else {
                vela_session_policy::store::classify_cascade(false)
            };
            assert_eq!(observed, want_obs, "{case}");
            assert_eq!(snapshot(&db).await, want_db, "{case}");
            counts.case(fault);
        }
    }
    eprintln!(
        "session executor conformance (revocation): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn deletion_executors_match_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    let scratch = Store::open_temp().unwrap();
    for pre in states() {
        counts.states += 1;
        let acct = user(0);
        let device_ids = model::scan_devices(&pre, &acct, false).1;
        let session_ids = model::scan_web_sessions(&pre, &acct, false).1;
        let mut all_ids = device_ids.clone();
        all_ids.extend(session_ids.clone());

        // scan_devices / scan_web_sessions
        for (name, plan_scan) in [("devices", 0), ("sessions", 1)] {
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = DeleteAccountIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                    store: SledStore(&scratch),
                    account: acct.clone(),
                    device_ids: Vec::new(),
                    web_session_ids: Vec::new(),
                    error: None,
                };
                let observed = if plan_scan == 0 {
                    io.scan_devices().await
                } else {
                    io.scan_web_sessions().await
                };
                let (expected, expected_ids) = if plan_scan == 0 {
                    model::scan_devices(&pre, &acct, fault.is_some())
                } else {
                    model::scan_web_sessions(&pre, &acct, fault.is_some())
                };
                let case = format!("scan {name} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                let got = if plan_scan == 0 { &io.device_ids } else { &io.web_session_ids };
                assert_eq!(got.clone(), expected_ids, "{case}");
                assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                counts.case(fault);
            }
        }

        // lockout_devices / lockout_web_sessions
        for (name, sessions) in [("devices", false), ("sessions", true)] {
            for fault in faults(2 * all_ids.len()) {
                let store = Store::open_temp().unwrap();
                seed_jtis(&store, &device_ids);
                load(&db, &pre).await;
                let mut io = DeleteAccountIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                    store: Faulty::new(SledStore(&store), fault),
                    account: acct.clone(),
                    device_ids: if sessions { Vec::new() } else { all_ids.clone() },
                    web_session_ids: if sessions { all_ids.clone() } else { Vec::new() },
                    error: None,
                };
                let observed = if sessions {
                    io.lockout_web_sessions().await
                } else {
                    io.lockout_devices().await
                };
                let case = format!("lockout {name} fault {fault:?} pre {pre:?}");
                assert_eq!(
                    observed,
                    vela_session_policy::deletion_driver::LockoutObservation::Applied,
                    "{case}"
                );
                if fault.is_none() {
                    for id in &all_ids {
                        assert!(
                            store.exists(&format!("device:revoked:{id}")).unwrap(),
                            "{case}: sentinel of {id}"
                        );
                    }
                }
                counts.case(fault);
            }
        }

        // begin_transaction, each table delete, delete_users, commit
        let tables = [
            DeletionTable::WebSessions,
            DeletionTable::ShareInbox,
            DeletionTable::SharedItems,
            DeletionTable::Sends,
            DeletionTable::VaultChunks,
            DeletionTable::OramBuckets,
            DeletionTable::Devices,
        ];
        for fault in faults(1) {
            load(&db, &pre).await;
            let mut io = DeleteAccountIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                store: SledStore(&scratch),
                account: acct.clone(),
                device_ids: Vec::new(),
                web_session_ids: Vec::new(),
                error: None,
            };
            let observed = io.begin_transaction().await;
            let (expected, _) = model::begin_tx(&pre, fault);
            assert_eq!(observed, expected, "begin fault {fault:?}");
            counts.case(fault);
        }
        for table in tables {
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = DeleteAccountIo {
                    // `begin` is the first statement of this wrapper; the
                    // delete is the second.
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault.map(|k| k + 1)),
                    store: SledStore(&scratch),
                    account: acct.clone(),
                    device_ids: Vec::new(),
                    web_session_ids: Vec::new(),
                    error: None,
                };
                // Open the transaction the handler would have opened.
                io.begin_transaction().await;
                let observed = io.delete_table(table).await;
                let (expected, expected_db) = model::delete_table(&pre, &acct, table, fault);
                let case = format!("delete {table:?} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                if fault.is_none() {
                    // Publish the one-statement transaction so the table state
                    // is observable.
                    io.sql.commit().await.unwrap();
                } else {
                    io.sql.rollback();
                }
                settle(&db).await;
                if fault.is_none() {
                    let mut want = expected_db;
                    // `begin` is not a write; the model's state is the delete's.
                    want.users = pre.users.clone();
                    assert_eq!(snapshot(&db).await, want, "{case}");
                } else {
                    assert_eq!(snapshot(&db).await, pre, "{case}");
                }
                counts.case(fault);
            }
        }
        for fault in faults(1) {
            load(&db, &pre).await;
            let mut io = DeleteAccountIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault.map(|k| k + 1)),
                store: SledStore(&scratch),
                account: acct.clone(),
                device_ids: Vec::new(),
                web_session_ids: Vec::new(),
                error: None,
            };
            io.begin_transaction().await;
            let observed = io.delete_users().await;
            let (expected, expected_db) = model::delete_users(&pre, &acct, fault);
            let case = format!("delete users fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
            if fault.is_none() {
                io.sql.commit().await.unwrap();
            } else {
                io.sql.rollback();
            }
            settle(&db).await;
            if fault.is_some() {
                assert_eq!(snapshot(&db).await, pre, "{case}");
            } else {
                let mut want = expected_db;
                want.devices = pre.devices.clone();
                want.sessions = pre.sessions.clone();
                want.inbox = pre.inbox.clone();
                want.items = pre.items.clone();
                want.sends = pre.sends.clone();
                want.chunks = pre.chunks.clone();
                want.buckets = pre.buckets.clone();
                assert_eq!(snapshot(&db).await, want, "{case}");
            }
            counts.case(fault);
        }

        // The whole transaction, as the driver orders it.
        for fault in faults(10) {
            load(&db, &pre).await;
            let mut io = DeleteAccountIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                store: SledStore(&scratch),
                account: acct.clone(),
                device_ids: Vec::new(),
                web_session_ids: Vec::new(),
                error: None,
            };
            let begun = io.begin_transaction().await;
            let mut committed = false;
            if begun == vela_session_policy::deletion_driver::TransactionObservation::Begun {
                let mut failed = false;
                for table in tables {
                    let observation = io.delete_table(table).await;
                    if observation != vela_session_policy::deletion_driver::TableDeleteObservation::Deleted {
                        failed = true;
                        break;
                    }
                }
                if !failed {
                    let users = io.delete_users().await;
                    if users == vela_session_policy::deletion_driver::UsersDeleteObservation::Deleted {
                        committed = io.commit().await
                            == vela_session_policy::deletion_driver::CommitObservation::Committed;
                    }
                }
            }
            io.sql.rollback();
            settle(&db).await;
            let want = if committed { model::deleted_account(&pre, &acct) } else { pre.clone() };
            let case = format!("delete account fault {fault:?} pre {pre:?}");
            assert_eq!(snapshot(&db).await, want, "{case}");
            counts.case(fault);
        }
    }
    eprintln!(
        "session executor conformance (deletion): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}
