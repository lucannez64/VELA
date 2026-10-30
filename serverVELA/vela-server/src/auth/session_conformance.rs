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
use vela_session_policy::websession_driver::{
    DeleteRecordObservation, DeleteSentinelObservation, GrantUpdateObservation,
    TokenClaimObservation, TokenIssueObservation,
};

use super::challenge::ChallengeIssueIo;
use super::session_store::{DbSql, SessionSql, SessionStore, SessionTokens, SledStore};
use crate::account::{ParsedKeys, RegisterIo, RegisterRequest};
use super::verify::VerifyIo;
use crate::account::delete::DeleteAccountIo;
use crate::auth::logout::LogoutJtiIo;
use crate::device::revoke::RevokeDeviceIo;
use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};
use crate::state::{AppState, AppStateInner};
use crate::store::Store;
use crate::web_session::{DeleteSessionIo, GrantIo, GrantRequest, StartIo, StartRequest, TokenIo, TokenRequest};

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

    async fn execute_in_tx_named(
        &mut self,
        sql: &str,
        params: Vec<TursoValue>,
        closed: &'static str,
    ) -> anyhow::Result<u64> {
        self.hit()?;
        self.inner.execute_in_tx_named(sql, params, closed).await
    }

    async fn begin(&mut self) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.begin().await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.commit().await
    }

    async fn commit_named(&mut self, closed: &'static str) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.commit_named(closed).await
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

    fn take(&mut self, key: &str) -> anyhow::Result<Option<String>> {
        self.hit()?;
        self.inner.take(key)
    }

    fn incr(&mut self, key: &str, limit: u64, ttl: u64) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.incr(key, limit, ttl)
    }

    fn backoff_failure(&mut self, streak_key: &str, backoff_key: &str) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.backoff_failure(streak_key, backoff_key)
    }

    fn reset_backoff(&mut self, streak_key: &str, backoff_key: &str) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.reset_backoff(streak_key, backoff_key)
    }

    fn add_member(&mut self, key: &str, member: &str, ttl: u64) -> anyhow::Result<()> {
        self.hit()?;
        self.inner.add_member(key, member, ttl)
    }

    fn set_ex_nx(&mut self, key: &str, value: &[u8], ttl: u64) -> anyhow::Result<bool> {
        self.hit()?;
        self.inner.set_ex_nx(key, value, ttl)
    }

    fn exists(&mut self, key: &str) -> anyhow::Result<bool> {
        self.hit()?;
        self.inner.exists(key)
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
            "INSERT INTO users (id, created_at, share_ek, share_ek_since, key_epoch, rekey_state) VALUES (?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.created_at.clone()),
                TursoValue::Text(row.share_ek.clone()),
                TursoValue::Text(row.share_ek_since.clone()),
                TursoValue::Integer(row.key_epoch),
                opt(&row.rekey_state),
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
                TursoValue::Text(row.hybrid_ek.clone()),
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
            "INSERT INTO web_sessions (id, user_id, approver_user_id, ephemeral_pk, link_nonce, mode, status, capsule, approved_by, key_epoch, created_at, expires_at) VALUES (?, ?, ?, 'pk', 'nonce', ?, ?, ?, ?, ?, 't', ?)",
            vec![
                TursoValue::Text(id.clone()),
                opt(&row.user_id),
                opt(&row.approver_user_id),
                opt(&row.mode),
                TursoValue::Text(row.status.clone()),
                opt(&row.capsule),
                opt(&row.approved_by),
                match row.key_epoch {
                    Some(epoch) => TursoValue::Integer(epoch),
                    None => TursoValue::Null,
                },
                opt(&row.expires_at),
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
        .query(
            "SELECT id, share_ek, share_ek_since, created_at, key_epoch, rekey_state FROM users",
            vec![],
        )
        .await
        .unwrap()
    {
        state.users.insert(
            text(&row, 0),
            UserRow {
                share_ek: text_opt(&row, 1).unwrap_or_default(),
                share_ek_since: text_opt(&row, 2).unwrap_or_default(),
                created_at: text_opt(&row, 3).unwrap_or_default(),
                key_epoch: row.i64(4).expect("key_epoch is an integer"),
                rekey_state: text_opt(&row, 5),
            },
        );
    }
    for row in db
        .query(
            "SELECT id, user_id, revoked, hybrid_ek, hybrid_vk, last_active, device_name, device_type, revoked_at, revoked_by FROM devices",
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
                hybrid_ek: text_opt(&row, 3).unwrap_or_default(),
                hybrid_vk: text_opt(&row, 4).unwrap_or_default(),
                last_active: text_opt(&row, 5),
                name: text_opt(&row, 6).unwrap_or_default(),
                kind: text_opt(&row, 7).unwrap_or_default(),
                revoked_at: text_opt(&row, 8),
                revoked_by: text_opt(&row, 9),
            },
        );
    }
    for row in db
        .query(
            "SELECT id, user_id, approver_user_id, status, capsule, approved_by, mode, key_epoch, expires_at FROM web_sessions",
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
                mode: text_opt(&row, 6),
                key_epoch: row.i64(7),
                expires_at: text_opt(&row, 8),
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
        hybrid_ek: s("eks="),
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
            UserRow {
                share_ek: format!("ek-{n}"),
                share_ek_since: s("t0"),
                created_at: s("t0"),
                rekey_state: None,
                key_epoch: 1,
            },
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
            mode: Some(s("rw")),
            key_epoch: Some(1),
            expires_at: Some(s("t")),
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
            mode: None,
            key_epoch: None,
            expires_at: None,
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
            mode: Some(s("ro")),
            key_epoch: Some(1),
            expires_at: Some(s("t")),
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
            mode: None,
            key_epoch: None,
            expires_at: None,
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

/// The test issuer: token issuance is a trusted input (its policy is proved
/// elsewhere), so login conformance only needs a deterministic value.
struct FakeTokens;

impl SessionTokens for FakeTokens {
    fn issue_device(
        &self,
        _user: uuid::Uuid,
        _device: uuid::Uuid,
    ) -> anyhow::Result<(String, String)> {
        Ok((s("token"), s("jti")))
    }

    fn issue_web(
        &self,
        _user: uuid::Uuid,
        _session: uuid::Uuid,
        _plan: vela_session_policy::TokenPlan,
    ) -> anyhow::Result<(String, String)> {
        Ok((s("token"), s("jti")))
    }
}

/// The web-token issuer: issuance is a trusted input, and `ok` lets the
/// conformance drive the executor's failure path.
struct FakeWebTokens {
    ok: bool,
}

impl SessionTokens for FakeWebTokens {
    fn issue_device(
        &self,
        _user: uuid::Uuid,
        _device: uuid::Uuid,
    ) -> anyhow::Result<(String, String)> {
        Ok((s("token"), s("jti")))
    }

    fn issue_web(
        &self,
        _user: uuid::Uuid,
        _session: uuid::Uuid,
        _plan: vela_session_policy::TokenPlan,
    ) -> anyhow::Result<(String, String)> {
        if self.ok {
            Ok((s("token"), s("jti")))
        } else {
            Err(anyhow::anyhow!("injected issuer failure"))
        }
    }
}

/// A state for the executors that are given one; only their own handles
/// (sql, store, tokens) are exercised.
async fn web_state() -> AppState {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "{}/vela-websession-conformance-{}-{}.db",
        std::env::temp_dir().display(),
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    let turso = std::sync::Arc::new(TursoDb::open(&path, 1).await.unwrap());
    let store = Store::open_temp().unwrap();
    let cfg = crate::config::Config::from_env().expect("default config");
    std::sync::Arc::new(AppStateInner::new(turso, store, cfg).await.unwrap())
}

const LOGIN_IP: &str = "203.0.113.7";

fn login_store() -> ModelStore {
    ModelStore::default()
}

#[tokio::test]
async fn login_executors_match_the_store_model() {
    use vela_session_policy::login_driver::DeviceObservation;

    let db = temp_db().await;
    let mut counts = Counts::default();
    let scratch = Store::open_temp().unwrap();
    for pre in states() {
        counts.states += 1;

        // consume_challenge: an absent key, this purpose's tag, another one.
        for (seed, tag) in [(None, "login"), (Some("login"), "login"), (Some("enroll"), "login")] {
            for fault in faults(1) {
                let store = Store::open_temp().unwrap();
                let mut ms = login_store();
                if let Some(value) = seed {
                    store.set_ex("challenge:c", value.as_bytes(), 60).unwrap();
                    ms.kv.insert(s("challenge:c"), s(value));
                }
                load(&db, &pre).await;
                let mut io = VerifyIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                    store: Faulty::new(SledStore(&store), fault),
                    tokens: FakeTokens,
                    ip: s(LOGIN_IP),
                    device_id_str: device(0),
                    challenge: s("c"),
                    signature: s("sig"),
                    requested_name: None,
                    requested_type: None,
                    device: None,
                    token: None,
                    error: None,
                    verifier_error: None,
                    counter_error: None,
                };
                let observed = io.consume_challenge().await;
                let (expected, expected_store) = model::login_challenge(&ms, "c", tag, fault);
                let case = format!("challenge {seed:?} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                assert_eq!(
                    store.get("challenge:c").unwrap().is_some(),
                    expected_store.kv.contains_key("challenge:c"),
                    "{case}"
                );
                counts.case(fault);
            }
        }

        // observe_device: present, revoked, absent, and an undecodable row.
        for (target, corrupt) in [
            (device(0), false),
            (device(1), false),
            (device(9), false),
            (device(0), true),
        ] {
            for fault in faults(1) {
                load(&db, &pre).await;
                if corrupt {
                    db.execute(
                        "UPDATE devices SET created_at = 'not-a-timestamp' WHERE id = ?",
                        vec![TursoValue::Text(target.clone())],
                    )
                    .await
                    .unwrap();
                }
                let mut io = VerifyIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                    store: SledStore(&scratch),
                    tokens: FakeTokens,
                    ip: s(LOGIN_IP),
                    device_id_str: target.clone(),
                    challenge: s("c"),
                    signature: s("sig"),
                    requested_name: None,
                    requested_type: None,
                    device: None,
                    token: None,
                    error: None,
                    verifier_error: None,
                    counter_error: None,
                };
                let observed = io.observe_device().await;
                let expected = model::observe_device(&pre, &target, fault.is_some(), corrupt);
                let case = format!("device {target} corrupt {corrupt} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(io.error.is_some(), observed != DeviceObservation::Present, "{case}");
                counts.case(fault);
            }
        }

        // record_verification_failure: fresh and exhausted counters, plus a
        // fault at either of its two store calls.
        for preseed in [0u64, 5] {
            for fault in (0..2).map(Some).chain(std::iter::once(None)) {
                let store = Store::open_temp().unwrap();
                let mut ms = login_store();
                let key = format!("rl:verify:fail:dev:{LOGIN_IP}:{}", device(0));
                if preseed > 0 {
                    for _ in 0..preseed {
                        store.incr_fixed_window(&key, 1, 60).unwrap();
                    }
                    ms.counters.insert(key.clone(), preseed);
                }
                let mut io = VerifyIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                    store: Faulty::new(SledStore(&store), fault),
                    tokens: FakeTokens,
                    ip: s(LOGIN_IP),
                    device_id_str: device(0),
                    challenge: s("c"),
                    signature: s("sig"),
                    requested_name: None,
                    requested_type: None,
                    device: None,
                    token: None,
                    error: None,
                    verifier_error: None,
                    counter_error: None,
                };
                let observed = io.record_verification_failure().await;
                let (expected, expected_store) =
                    model::login_failure_record(&ms, LOGIN_IP, &device(0), fault);
                let case = format!("failure preseed {preseed} fault {fault:?}");
                assert_eq!(observed.fallback_counter_ok, expected.fallback_counter_ok, "{case}");
                let count = store.incr_fixed_window(&key, 0, 60).unwrap();
                assert_eq!(
                    count,
                    expected_store.counters.get(&key).copied().unwrap_or(0),
                    "{case}"
                );
                assert_eq!(io.counter_error.is_some(), !observed.fallback_counter_ok, "{case}");
                counts.case(fault);
            }
        }

        // reset_backoff: the streak/backoff reset, then the best-effort stamp.
        for (requested, store_fault, sql_fault) in [
            (None, None, None),
            (Some(("new", "tablet")), None, None),
            (None, Some(0), None),
            (None, None, Some(0)),
        ] {
            let store = Store::open_temp().unwrap();
            let streak = format!("rl:streak:verify:{LOGIN_IP}:{}", device(0));
            let backoff = format!("rl:backoff:verify:{LOGIN_IP}:{}", device(0));
            store.set_ex(&streak, b"3", 300).unwrap();
            store.set_ex(&backoff, b"1", 30).unwrap();
            let mut ms = login_store();
            ms.streaks.insert(streak.clone(), 3);
            ms.kv.insert(backoff.clone(), s("1"));
            let db = temp_db().await;
            load(&db, &pre).await;
            let (name, kind) = match requested {
                Some((name, kind)) => (Some(s(name)), Some(s(kind))),
                None => (None, None),
            };
            let mut io = VerifyIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, sql_fault),
                store: Faulty::new(SledStore(&store), store_fault),
                tokens: FakeTokens,
                ip: s(LOGIN_IP),
                device_id_str: device(0),
                challenge: s("c"),
                signature: s("sig"),
                requested_name: name.clone(),
                requested_type: kind.clone(),
                device: Some(crate::db::DeviceRow {
                    id: uuid::Uuid::parse_str(&device(0)).unwrap(),
                    user_id: uuid::Uuid::parse_str(&user(0)).unwrap(),
                    hybrid_ek: Vec::new(),
                    revoked: false,
                    hybrid_vk: Vec::new(),
                    last_active: None,
                    device_name: s("old"),
                    device_type: s("desktop"),
                    revoked_at: None,
                    revoked_by: None,
                    enrolled_by: None,
                    rms_capsule: None,
                    created_at: chrono::Utc::now(),
                }),
                token: None,
                error: None,
                verifier_error: None,
                counter_error: None,
            };
            let observed = io.reset_backoff().await;
            let expected_obs = if store_fault.is_some() {
                vela_session_policy::login_driver::BackoffResetObservation::StorageFailed
            } else {
                vela_session_policy::login_driver::BackoffResetObservation::Reset
            };
            assert_eq!(observed, expected_obs, "reset pre {pre:?}");
            assert_eq!(io.error.is_some(), store_fault.is_some(), "reset pre {pre:?}");
            if store_fault.is_none() {
                assert!(!store.exists(&streak).unwrap());
                assert!(!store.exists(&backoff).unwrap());
            }
            // The stamp is the executor's own clock: read it back, then check
            // the model's row update against it.
            let actual = snapshot(&db).await;
            let stamp = actual
                .devices
                .get(&device(0))
                .and_then(|row| row.last_active.clone())
                .unwrap_or_else(|| NOW.into());
            let model_fault = match (store_fault, sql_fault) {
                (Some(_), _) => Some(0),
                (None, Some(_)) => Some(1),
                _ => None,
            };
            let (_, expected_store, expected_db) = model::login_reset(
                &ms,
                &pre,
                LOGIN_IP,
                &device(0),
                &stamp,
                name.as_deref(),
                kind.as_deref(),
                model_fault,
            );
            if store_fault.is_none() {
                assert!(
                    !expected_store.streaks.contains_key(&streak),
                    "model fault {model_fault:?} streaks {:?}",
                    expected_store.streaks
                );
            }
            if sql_fault.is_some() || store_fault.is_some() {
                assert_eq!(expected_db, pre, "model fault db pre {pre:?}");
                assert_eq!(actual.users, pre.users, "users");
                assert_eq!(actual.devices, pre.devices, "devices");
                assert_eq!(actual.sessions, pre.sessions, "sessions");
                assert_eq!(actual.inbox, pre.inbox, "inbox");
                assert_eq!(actual.items, pre.items, "items");
                assert_eq!(actual.sends, pre.sends, "sends");
                assert_eq!(actual.chunks, pre.chunks, "chunks");
                assert_eq!(actual.buckets, pre.buckets, "buckets");
            } else {
                let mut want = expected_db;
                if let Some(row) = want.devices.get_mut(&device(0)) {
                    row.last_active = Some(stamp.clone());
                }
                if name.is_some() {
                    assert_eq!(
                        actual.devices.get(&device(0)).map(|r| &r.name),
                        Some(&s("new")),
                        "rename pre {pre:?}"
                    );
                }
                assert_eq!(
                    actual, want,
                    "reset db pre {pre:?} actual {:?} want {:?}",
                    actual.devices, want.devices
                );
            }
            counts.case(None);
        }

        // track_token: one set add, injected fault at the one statement.
        for fault in faults(1) {
            let store = Store::open_temp().unwrap();
            let mut io = VerifyIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                store: Faulty::new(SledStore(&store), fault),
                tokens: FakeTokens,
                ip: s(LOGIN_IP),
                device_id_str: device(0),
                challenge: s("c"),
                signature: s("sig"),
                requested_name: None,
                requested_type: None,
                device: None,
                token: Some((s("token"), s("jti"))),
                error: None,
                verifier_error: None,
                counter_error: None,
            };
            let observed = io.track_token().await;
            let expected = model::login_track(&login_store(), &device(0), "jti", fault);
            let case = format!("track fault {fault:?}");
            assert_eq!(observed, expected.0, "{case}");
            let members = store.smembers(&format!("device:jtis:{}", device(0))).unwrap();
            assert_eq!(
                members.into_iter().collect::<BTreeSet<_>>(),
                expected
                    .1
                    .sets
                    .get(&format!("device:jtis:{}", device(0)))
                    .cloned()
                    .unwrap_or_default(),
                "{case}"
            );
            assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
            counts.case(fault);
        }
    }
    eprintln!(
        "session executor conformance (login): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

const CHALLENGE_IP: &str = "198.51.100.9";
const REGISTER_IP: &str = "198.51.100.10";

fn register_request() -> RegisterRequest {
    RegisterRequest {
        hybrid_ek: s("ek"),
        hybrid_vk: s("vk"),
        device_name: None,
        device_type: None,
        share_ek: Some(s("share")),
        share_ek_signed_at: None,
        share_ek_signature: None,
    }
}

fn parsed_keys() -> ParsedKeys {
    ParsedKeys {
        identity_ek: Some(vec![1u8, 2, 3, 4]),
        identity_vk: Some(vec![5u8, 6, 7, 8]),
        share_ek_b64: s("share-ek"),
        identity_ek_valid: true,
        identity_vk_valid: true,
        share_ek_valid: true,
        error: None,
    }
}

#[tokio::test]
async fn challenge_executors_match_the_store_model() {
    let mut counts = Counts::default();
    use vela_session_policy::challenge_issue_driver::StoreObservation;

    // check_rate_limit: a fresh window and one at its limit, each fault point.
    for preseed in [0u64, 20] {
        counts.states += 1;
        for fault in faults(1) {
            let store = Store::open_temp().unwrap();
            let key = format!("rl:challenge:ip:{CHALLENGE_IP}");
            for _ in 0..preseed {
                store.incr_fixed_window(&key, 1, 60).unwrap();
            }
            let mut ms = ModelStore::default();
            if preseed > 0 {
                ms.counters.insert(key.clone(), preseed);
            }
            let mut io = ChallengeIssueIo {
                store: Faulty::new(SledStore(&store), fault),
                ip: s(CHALLENGE_IP),
                nonce: None,
                challenge_b64: None,
                error: None,
            };
            let observed = io.check_rate_limit().await;
            let (expected, expected_store) =
                model::challenge_rate_limit(&ms, CHALLENGE_IP, fault);
            let case = format!("challenge limit preseed {preseed} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            // A refusal over the limit is the limiter's own error, exactly as
            // a store failure is; either one sets the handler's slot.
            assert_eq!(
                io.error.is_some(),
                fault.is_some()
                    || observed
                        == vela_session_policy::challenge_issue_driver::RateLimitObservation::Denied,
                "{case}"
            );
            let count = store.incr_fixed_window(&key, 0, 60).unwrap();
            assert_eq!(
                count,
                expected_store.counters.get(&key).copied().unwrap_or(0),
                "{case}"
            );
            counts.case(fault);
        }
    }

    // store_nonce: an absent key, a live key, and this purpose's own tag.
    let nonce = [7u8; 32];
    let b64 = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(nonce)
    };
    for (seed, tag) in [(None, "login"), (Some("enroll"), "login"), (Some("login"), "login")] {
        for fault in faults(1) {
            let store = Store::open_temp().unwrap();
            let mut ms = ModelStore::default();
            let key = format!("challenge:{b64}");
            if let Some(value) = seed {
                store.set_ex(&key, value.as_bytes(), 60).unwrap();
                ms.kv.insert(key.clone(), s(value));
            }
            let mut io = ChallengeIssueIo {
                store: Faulty::new(SledStore(&store), fault),
                ip: s(CHALLENGE_IP),
                nonce: Some(nonce),
                challenge_b64: None,
                error: None,
            };
            let observed = io
                .store_nonce(vela_session_policy::challenge::ChallengePurpose::Login)
                .await;
            let (expected, expected_store) = model::challenge_nonce(&ms, &b64, tag, fault);
            let case = format!("challenge store {seed:?} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(
                io.challenge_b64.is_some(),
                observed == StoreObservation::Inserted,
                "{case}"
            );
            assert_eq!(
                io.error.is_some(),
                fault.is_some() || observed == StoreObservation::KeyExists,
                "{case}"
            );
            assert_eq!(
                store.get(&key).unwrap(),
                expected_store.kv.get(&key).map(|v| v.as_bytes().to_vec()),
                "{case}"
            );
            counts.case(fault);
        }
    }
    eprintln!(
        "session executor conformance (challenge): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn registration_executors_match_the_store_model() {
    use vela_session_policy::registration_driver::{
        CommitObservation, InsertObservation, TransactionObservation,
    };

    let db = temp_db().await;
    let mut counts = Counts::default();
    let scratch = Store::open_temp().unwrap();
    for pre in states() {
        counts.states += 1;
        let keys = parsed_keys();
        let dek = crate::db::encode_b64(keys.identity_ek.as_ref().unwrap());
        let dvk = crate::db::encode_b64(keys.identity_vk.as_ref().unwrap());

        // check_rate_limit
        for preseed in [0u64, 5] {
            for fault in faults(1) {
                let store = Store::open_temp().unwrap();
                let key = format!("rl:register:ip:{REGISTER_IP}");
                for _ in 0..preseed {
                    store.incr_fixed_window(&key, 1, 3600).unwrap();
                }
                let mut ms = ModelStore::default();
                if preseed > 0 {
                    ms.counters.insert(key.clone(), preseed);
                }
                load(&db, &pre).await;
                let mut io = RegisterIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                    store: Faulty::new(SledStore(&store), fault),
                    tokens: FakeTokens,
                    ip: s(REGISTER_IP),
                    body: register_request(),
                    keys: parsed_keys(),
                    user_id: uuid::Uuid::parse_str(&user(9)).unwrap(),
                    device_id: uuid::Uuid::parse_str(&device(9)).unwrap(),
                    now: s(NOW),
                    device_name: s("name"),
                    device_type: s("desktop"),
                    token: None,
                    jti: None,
                    error: None,
                };
                let observed = io.check_rate_limit().await;
                let (expected, expected_store) =
                    model::registration_rate_limit(&ms, REGISTER_IP, fault);
                let case = format!("registration limit preseed {preseed} fault {fault:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(
                    io.error.is_some(),
                    fault.is_some()
                        || observed
                            == vela_session_policy::registration_driver::RateLimitObservation::Denied,
                    "{case}"
                );
                let count = store.incr_fixed_window(&key, 0, 3600).unwrap();
                assert_eq!(
                    count,
                    expected_store.counters.get(&key).copied().unwrap_or(0),
                    "{case}"
                );
                counts.case(fault);
            }
        }

        // check_account_budget
        for fault in faults(1) {
            load(&db, &pre).await;
            let mut io = RegisterIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                store: SledStore(&scratch),
                tokens: FakeTokens,
                ip: s(REGISTER_IP),
                body: register_request(),
                keys: parsed_keys(),
                user_id: uuid::Uuid::parse_str(&user(9)).unwrap(),
                device_id: uuid::Uuid::parse_str(&device(9)).unwrap(),
                now: s(NOW),
                device_name: s("name"),
                device_type: s("desktop"),
                token: None,
                jti: None,
                error: None,
            };
            let observed = io.check_account_budget().await;
            let (expected, count) = model::account_count(&pre, fault.is_some());
            let case = format!("budget fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
            if fault.is_none() {
                assert_eq!(
                    observed,
                    vela_session_policy::registration_driver::BudgetObservation::Counted {
                        count
                    },
                    "{case}"
                );
            }
            counts.case(fault);
        }

        // begin_transaction
        for fault in faults(1) {
            load(&db, &pre).await;
            let mut io = RegisterIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                store: SledStore(&scratch),
                tokens: FakeTokens,
                ip: s(REGISTER_IP),
                body: register_request(),
                keys: parsed_keys(),
                user_id: uuid::Uuid::parse_str(&user(9)).unwrap(),
                device_id: uuid::Uuid::parse_str(&device(9)).unwrap(),
                now: s(NOW),
                device_name: s("name"),
                device_type: s("desktop"),
                token: None,
                jti: None,
                error: None,
            };
            let observed = io.begin_transaction().await;
            let (expected, _) = model::registration_begin(&pre, fault);
            let case = format!("begin fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
            io.sql.rollback();
            settle(&db).await;
            assert_eq!(snapshot(&db).await, pre, "{case}");
            counts.case(fault);
        }

        // insert_account: a taken id and a fresh one.
        for (name, target) in [("taken", user(0)), ("fresh", user(9))] {
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = RegisterIo {
                    // `begin` is the first statement of this wrapper; the
                    // insert is the second.
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault.map(|k| k + 1)),
                    store: SledStore(&scratch),
                    tokens: FakeTokens,
                    ip: s(REGISTER_IP),
                    body: register_request(),
                    keys: parsed_keys(),
                    user_id: uuid::Uuid::parse_str(&target).unwrap(),
                    device_id: uuid::Uuid::parse_str(&device(9)).unwrap(),
                    now: s(NOW),
                    device_name: s("name"),
                    device_type: s("desktop"),
                    token: None,
                    jti: None,
                    error: None,
                };
                io.begin_transaction().await;
                let observed = io.insert_account().await;
                let (expected, expected_db) = model::insert_account(
                    &pre,
                    &target,
                    NOW,
                    &keys.share_ek_b64,
                    NOW,
                    fault,
                );
                let case = format!("insert account {name} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                // A duplicate id is a real SQL error, exactly as an injected
                // failure is: both set the handler's error slot.
                assert_eq!(
                    io.error.is_some(),
                    observed == InsertObservation::Failed,
                    "{case}"
                );
                if observed == InsertObservation::Inserted {
                    assert_eq!(io.commit().await, CommitObservation::Committed, "{case}");
                } else {
                    io.sql.rollback();
                }
                settle(&db).await;
                if observed == InsertObservation::Inserted {
                    assert_eq!(snapshot(&db).await, expected_db, "{case}");
                } else {
                    assert_eq!(snapshot(&db).await, pre, "{case}");
                }
                counts.case(fault);
            }
        }

        // insert_device: a taken id and a fresh one.
        for (name, target) in [("taken", device(0)), ("fresh", device(9))] {
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = RegisterIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault.map(|k| k + 1)),
                    store: SledStore(&scratch),
                    tokens: FakeTokens,
                    ip: s(REGISTER_IP),
                    body: register_request(),
                    keys: parsed_keys(),
                    user_id: uuid::Uuid::parse_str(&user(9)).unwrap(),
                    device_id: uuid::Uuid::parse_str(&target).unwrap(),
                    now: s(NOW),
                    device_name: s("name"),
                    device_type: s("desktop"),
                    token: None,
                    jti: None,
                    error: None,
                };
                io.begin_transaction().await;
                let observed = io.insert_device().await;
                let (expected, expected_db) = model::insert_device(
                    &pre,
                    &target,
                    &user(9),
                    "name",
                    "desktop",
                    NOW,
                    &dek,
                    &dvk,
                    fault,
                );
                let case = format!("insert device {name} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(
                    io.error.is_some(),
                    observed == InsertObservation::Failed,
                    "{case}"
                );
                if observed == InsertObservation::Inserted {
                    assert_eq!(io.commit().await, CommitObservation::Committed, "{case}");
                } else {
                    io.sql.rollback();
                }
                settle(&db).await;
                if observed == InsertObservation::Inserted {
                    assert_eq!(snapshot(&db).await, expected_db, "{case}");
                } else {
                    assert_eq!(snapshot(&db).await, pre, "{case}");
                }
                counts.case(fault);
            }
        }

        // commit alone
        for fault in faults(1) {
            load(&db, &pre).await;
            let mut io = RegisterIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault.map(|k| k + 1)),
                store: SledStore(&scratch),
                tokens: FakeTokens,
                ip: s(REGISTER_IP),
                body: register_request(),
                keys: parsed_keys(),
                user_id: uuid::Uuid::parse_str(&user(9)).unwrap(),
                device_id: uuid::Uuid::parse_str(&device(9)).unwrap(),
                now: s(NOW),
                device_name: s("name"),
                device_type: s("desktop"),
                token: None,
                jti: None,
                error: None,
            };
            io.begin_transaction().await;
            let observed = io.commit().await;
            let (expected, _) = model::registration_commit(&pre, fault);
            let case = format!("commit fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
            io.sql.rollback();
            settle(&db).await;
            assert_eq!(snapshot(&db).await, pre, "{case}");
            counts.case(fault);
        }

        // track_token
        for fault in faults(1) {
            let store = Store::open_temp().unwrap();
            let mut io = RegisterIo {
                sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                store: Faulty::new(SledStore(&store), fault),
                tokens: FakeTokens,
                ip: s(REGISTER_IP),
                body: register_request(),
                keys: parsed_keys(),
                user_id: uuid::Uuid::parse_str(&user(9)).unwrap(),
                device_id: uuid::Uuid::parse_str(&device(0)).unwrap(),
                now: s(NOW),
                device_name: s("name"),
                device_type: s("desktop"),
                token: Some(s("token")),
                jti: Some(s("jti")),
                error: None,
            };
            let observed = io.track_token().await;
            let (expected, expected_store) =
                model::registration_track(&ModelStore::default(), &device(0), "jti", fault);
            let case = format!("registration track fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
            let key = format!("device:jtis:{}", device(0));
            let members = store.smembers(&key).unwrap();
            assert_eq!(
                members.into_iter().collect::<BTreeSet<_>>(),
                expected_store.sets.get(&key).cloned().unwrap_or_default(),
                "{case}"
            );
            counts.case(fault);
        }
    }

    // The whole transaction, as the driver orders it: a taken account id, a
    // taken device id and a fresh pair, each fault point.
    for pre in states() {
        for (name, target_user, target_device) in [
            ("taken-user", user(0), device(9)),
            ("taken-device", user(9), device(0)),
            ("fresh", user(9), device(9)),
        ] {
            for fault in faults(3) {
                load(&db, &pre).await;
                let keys = parsed_keys();
                let dek = crate::db::encode_b64(keys.identity_ek.as_ref().unwrap());
                let dvk = crate::db::encode_b64(keys.identity_vk.as_ref().unwrap());
                let mut io = RegisterIo {
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault.map(|k| k + 1)),
                    store: SledStore(&scratch),
                    tokens: FakeTokens,
                    ip: s(REGISTER_IP),
                    body: register_request(),
                    keys,
                    user_id: uuid::Uuid::parse_str(&target_user).unwrap(),
                    device_id: uuid::Uuid::parse_str(&target_device).unwrap(),
                    now: s(NOW),
                    device_name: s("name"),
                    device_type: s("desktop"),
                    token: None,
                    jti: None,
                    error: None,
                };
                let should_commit = fault.is_none()
                    && !pre.users.contains_key(&target_user)
                    && !pre.devices.contains_key(&target_device);
                let begun = io.begin_transaction().await == TransactionObservation::Begun;
                let mut committed = false;
                if begun {
                    if io.insert_account().await == InsertObservation::Inserted
                        && io.insert_device().await == InsertObservation::Inserted
                    {
                        committed =
                            io.commit().await == CommitObservation::Committed;
                    }
                }
                io.sql.rollback();
                settle(&db).await;
                let (_, want) = model::registration_transaction(
                    &pre,
                    &target_user,
                    &target_device,
                    NOW,
                    &s("share-ek"),
                    NOW,
                    "name",
                    "desktop",
                    &dek,
                    &dvk,
                    fault,
                );
                let case = format!("registration tx {name} fault {fault:?} pre {pre:?}");
                assert_eq!(committed, should_commit, "{case}");
                assert_eq!(snapshot(&db).await, want, "{case}");
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "session executor conformance (registration): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

// ── Web sessions: start, grant, token and delete executors ─────────────────

/// A pending session for `user(0)` approved by the device it will grant with,
/// plus one variant per guard in the grant CAS.
fn web_states() -> Vec<Model> {
    let base = || {
        let mut state = base_state();
        state.sessions.insert(
            session_id(4),
            SessionRow {
                user_id: None,
                approver_user_id: Some(user(0)),
                status: s("pending"),
                capsule: None,
                approved_by: None,
                mode: None,
                key_epoch: None,
                expires_at: None,
            },
        );
        state
    };
    let mut out = vec![base()];

    let mut state = base();
    state.users.get_mut(&user(0)).unwrap().rekey_state = Some(s("rotating"));
    out.push(state); // 1: a rekey is in progress

    let mut state = base();
    state.users.get_mut(&user(0)).unwrap().key_epoch = 2;
    out.push(state); // 2: the account's epoch moved

    let mut state = base();
    state.devices.get_mut(&device(0)).unwrap().revoked = 1;
    out.push(state); // 3: the approving device is revoked

    let mut state = base();
    state.devices.get_mut(&device(0)).unwrap().user_id = user(1);
    out.push(state); // 4: the approving device belongs to another account

    let mut state = base();
    state.devices.remove(&device(0));
    out.push(state); // 5: no device row

    let mut state = base();
    state.sessions.get_mut(&session_id(4)).unwrap().status = s("granted");
    out.push(state); // 6: already granted

    let mut state = base();
    state.sessions.get_mut(&session_id(4)).unwrap().approver_user_id = Some(user(1));
    out.push(state); // 7: committed to another approver

    let mut state = base();
    state.sessions.remove(&session_id(4));
    out.push(state); // 8: no session row

    let mut state = base();
    state.users.remove(&user(0));
    out.push(state); // 9: no account row

    out
}

fn web_start_request() -> StartRequest {
    StartRequest {
        ephemeral_pk: s("epk"),
        web_vk: Some(s("vk")),
        link_nonce: s("nonce"),
        approver_user_id: uuid::Uuid::parse_str(&user(0)).unwrap(),
        poll_secret_hash: s("hash"),
    }
}

fn web_device_session() -> crate::middleware::DeviceSession {
    crate::middleware::DeviceSession(crate::middleware::AuthSession {
        user_id: uuid::Uuid::parse_str(&user(0)).unwrap(),
        device_id: uuid::Uuid::parse_str(&device(0)).unwrap(),
        jti: s("jti"),
        key_epoch: Some(1),
        new_token: None,
        scope: crate::auth::token::TokenScope::Device,
    })
}

fn web_token_plan() -> vela_session_policy::TokenPlan {
    use vela_session_policy::{
        plan_web_session_token, SessionMode, SessionPhase, TokenDecision, WebTokenFacts,
    };
    let now = chrono::Utc::now().timestamp();
    let facts = WebTokenFacts {
        phase: SessionPhase::Granted,
        mode: SessionMode::ReadWrite,
        approver_bound: true,
        nonce_bound: true,
        challenge_consumed: true,
        signature_valid: true,
    };
    match plan_web_session_token(facts, now, now + 3600, 1) {
        TokenDecision::Issue(plan) => plan,
        TokenDecision::Reject => panic!("the conformance token facts must be authorized"),
    }
}

#[tokio::test]
async fn web_session_executors_match_the_store_model() {
    let db = temp_db().await;
    let state = web_state().await;
    let mut counts = Counts::default();

    // StartIo::insert_pending. The executor draws a fresh v4 id, so the model
    // is given the id the executor reports; a duplicate id (the SQL UNIQUE
    // failure) is proved in the model and pinned by the schema check.
    for pre in web_states() {
        counts.states += 1;
        for fault in faults(1) {
            load(&db, &pre).await;
            let mut io = StartIo {
                state: &state,
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                body: web_start_request(),
                ip: s("203.0.113.9"),
                session_id: None,
                error: None,
            };
            let observed = io.insert_pending().await;
            let id = io.session_id.map(|id| id.to_string()).unwrap_or_default();
            let (expected, want) = model::insert_pending(
                &pre,
                &id,
                &user(0),
                "hash",
                "epk",
                "vk",
                "nonce",
                NOW,
                fault,
            );
            let case = format!("insert pending fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(
                io.error.is_some(),
                fault.is_some(),
                "{case}: {:?}",
                io.error.as_ref().map(|e| e.to_string())
            );
            assert_eq!(snapshot(&db).await, want, "{case}");
            counts.case(fault);
        }
    }

    // GrantIo::update_grant: every guard variant, two declared epochs, and
    // every fault point.
    for pre in web_states() {
        counts.states += 1;
        for epoch in [1i64, 2] {
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = GrantIo {
                    state: &state,
                    sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                    id: uuid::Uuid::parse_str(&session_id(4)).unwrap(),
                    session: web_device_session(),
                    body: GrantRequest {
                        mode: s("rw"),
                        capsule: s("cap"),
                        link_nonce: s("nonce"),
                        key_epoch: epoch,
                        ttl_secs: Some(600),
                    },
                    expires_at: None,
                    error: None,
                };
                let observed = io
                    .update_grant(vela_session_policy::websession_driver::GrantUpdate {
                        mode: vela_session_policy::SessionMode::ReadWrite,
                        epoch,
                        ttl_secs: 600,
                    })
                    .await;
                let exp = io
                    .expires_at
                    .map(|at| at.to_rfc3339())
                    .unwrap_or_else(|| s("unused"));
                let (expected, want) = model::grant_update(
                    &pre,
                    &session_id(4),
                    &user(0),
                    &device(0),
                    "rw",
                    "cap",
                    &exp,
                    epoch,
                    fault,
                );
                let case = format!("grant epoch {epoch} fault {fault:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(
                    io.error.is_some(),
                    observed == GrantUpdateObservation::Failed,
                    "{case}"
                );
                assert_eq!(snapshot(&db).await, want, "{case}");
                counts.case(fault);
            }
        }
    }

    // TokenIo::claim_token: an absent marker and one already claimed.
    for seed in [false, true] {
        counts.states += 1;
        for fault in faults(1) {
            let store = Store::open_temp().unwrap();
            let mut ms = ModelStore::default();
            if seed {
                store
                    .set_ex_nx(&format!("web_session:token_issued:{}", session_id(4)), &[1], 86_400)
                    .unwrap();
                ms.kv.insert(
                    model::claim_key(&session_id(4)),
                    s("1"),
                );
            }
            let mut io = TokenIo {
                state: &state,
                store: Faulty::new(SledStore(&store), fault),
                tokens: FakeWebTokens { ok: true },
                id: uuid::Uuid::parse_str(&session_id(4)).unwrap(),
                id_str: session_id(4),
                ip: s("203.0.113.9"),
                body: TokenRequest {
                    challenge: s("challenge"),
                    signature: s("signature"),
                },
                user_id: Some(uuid::Uuid::parse_str(&user(0)).unwrap()),
                web_vk: None,
                session_expires_at: None,
                token: None,
                jti: None,
                error: None,
            };
            let observed = io.claim_token().await;
            let (expected, want) = model::token_claim(&ms, &session_id(4), fault);
            let case = format!("claim seed {seed} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(
                io.error.is_some(),
                observed == TokenClaimObservation::StorageFailed,
                "{case}"
            );
            assert_eq!(
                store
                    .exists(&format!("web_session:token_issued:{}", session_id(4)))
                    .unwrap(),
                want.kv.contains_key(&model::claim_key(&session_id(4))),
                "{case}"
            );
            counts.case(fault);
        }
    }

    // TokenIo::issue_token: the issue-time sentinel and the JTI track.
    let plan = web_token_plan();
    for (seed, paseto_ok) in [(false, true), (true, true), (false, false)] {
        counts.states += 1;
        for fault in faults(2) {
            let store = Store::open_temp().unwrap();
            let mut ms = ModelStore::default();
            if seed {
                store.set_ex(&format!("device:revoked:{}", session_id(4)), &[1], 86_400).unwrap();
                ms.kv.insert(model::sentinel_key(&session_id(4)), s("1"));
            }
            let mut io = TokenIo {
                state: &state,
                store: Faulty::new(SledStore(&store), fault),
                tokens: FakeWebTokens { ok: paseto_ok },
                id: uuid::Uuid::parse_str(&session_id(4)).unwrap(),
                id_str: session_id(4),
                ip: s("203.0.113.9"),
                body: TokenRequest {
                    challenge: s("challenge"),
                    signature: s("signature"),
                },
                user_id: Some(uuid::Uuid::parse_str(&user(0)).unwrap()),
                web_vk: None,
                session_expires_at: None,
                token: None,
                jti: None,
                error: None,
            };
            let observed = io.issue_token(plan).await;
            let (expected, want) =
                model::token_issue(&ms, &session_id(4), "jti", paseto_ok, fault);
            let case = format!("issue seed {seed} paseto {paseto_ok} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(
                io.error.is_some(),
                observed == TokenIssueObservation::Failed,
                "{case}"
            );
            assert_eq!(io.token.is_some(), observed == TokenIssueObservation::Issued, "{case}");
            assert_eq!(
                store.smembers(&format!("device:jtis:{}", session_id(4)))
                    .unwrap()
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                want.sets
                    .get(&format!("device:jtis:{}", session_id(4)))
                    .cloned()
                    .unwrap_or_default(),
                "{case}"
            );
            counts.case(fault);
        }
    }

    // DeleteSessionIo::lockout_session: an absent sentinel and a live one.
    for seed in [false, true] {
        counts.states += 1;
        for fault in faults(1) {
            let store = Store::open_temp().unwrap();
            let mut ms = ModelStore::default();
            if seed {
                store.set_ex(&format!("device:revoked:{}", session_id(4)), &[1], 86_400).unwrap();
                ms.kv.insert(model::sentinel_key(&session_id(4)), s("1"));
            }
            let mut io = DeleteSessionIo {
                state: &state,
                sql: Faulty::new(DbSql { pool: &db, tx: None }, None),
                store: Faulty::new(SledStore(&store), fault),
                id: uuid::Uuid::parse_str(&session_id(4)).unwrap(),
                error: None,
            };
            let observed = io.lockout_session().await;
            let (expected, want) = model::lockout_session(&ms, &session_id(4), fault);
            let case = format!("lockout seed {seed} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(
                io.error.is_some(),
                observed == DeleteSentinelObservation::StorageFailed,
                "{case}"
            );
            assert_eq!(
                store
                    .exists(&format!("device:revoked:{}", session_id(4)))
                    .unwrap(),
                want.kv.contains_key(&model::sentinel_key(&session_id(4))),
                "{case}"
            );
            counts.case(fault);
        }
    }

    // DeleteSessionIo::record_revocation: a live target, a granted one and an
    // absent one.
    for pre in web_states() {
        counts.states += 1;
        let scratch = Store::open_temp().unwrap();
        for fault in faults(1) {
            load(&db, &pre).await;
            let mut io = DeleteSessionIo {
                state: &state,
                sql: Faulty::new(DbSql { pool: &db, tx: None }, fault),
                store: Faulty::new(SledStore(&scratch), None),
                id: uuid::Uuid::parse_str(&session_id(4)).unwrap(),
                error: None,
            };
            let observed = io.record_revocation().await;
            let (expected, want) = model::revoke_session(&pre, &session_id(4), fault);
            let case = format!("revoke record fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(
                io.error.is_some(),
                observed == DeleteRecordObservation::Failed,
                "{case}"
            );
            assert_eq!(snapshot(&db).await, want, "{case}");
            counts.case(fault);
        }
    }

    eprintln!(
        "session executor conformance (web sessions): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}
