//! Bounded conformance of the one-off share-link executors against a real
//! database (F-1).
//!
//! The F* proofs in `vela-share-policy/proofs/fstar/send-store-lemmas` show
//! that each `sends` executor's plan and classifier are honest *in the store
//! model*. This test checks the model against turso: for every small starting
//! state of the `sends` table, every executor method, every target and caller,
//! and every fault point (no fault, or a failure injected at the statement),
//! it runs the real executor (plan, rendered SQL, row decoding,
//! classification) through [`Faulty`] and compares the resulting table and
//! observation with the Rust mirror of the model
//! (`vela_share_policy::store_model`).
//!
//! A schema check pins the columns and types the model uses.

use chrono::{Duration, TimeZone, Utc};
use uuid::Uuid;
use vela_share_policy::send_driver::{
    begin_create, begin_delete, CreateObservation, ReadObservation, SendEffect,
};
use vela_share_policy::store;
use vela_share_policy::store_model::{self as model, Db as Model, SendRow};

use super::sql::{PoolSql, SendSql};
use super::{CreateSendIo, DeleteSendIo, FetchSendIo};
use crate::db;
use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};

/// Fails the k-th statement (from 0) an executor sends, without sending it.
struct Faulty<S> {
    inner: S,
    fail_at: Option<usize>,
    calls: usize,
}

impl<S> Faulty<S> {
    fn new(inner: S, fail_at: Option<usize>) -> Self {
        Self {
            inner,
            fail_at,
            calls: 0,
        }
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

impl<S: SendSql> SendSql for Faulty<S> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.hit()?;
        self.inner.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.hit()?;
        self.inner.execute(sql, params).await
    }
}

/// The moment every modelled expiry is compared against.
const NOW: &str = "2026-10-29T12:00:00+00:00";
/// After every link the states below mark live.
const LATER: &str = "2026-11-01T00:00:00+00:00";

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 29, 12, 0, 0).unwrap()
}

async fn temp_db() -> TursoDb {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "{}/vela-send-conformance-{}-{}.db",
        std::env::temp_dir().display(),
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    TursoDb::open(&path, 1).await.unwrap()
}

async fn load(db: &TursoDb, state: &Model) {
    db.execute_batch("DELETE FROM sends;").await.unwrap();
    for (id, row) in &state.sends {
        db.execute(
            "INSERT INTO sends (id, owner_user_id, ciphertext, has_passphrase, kdf_salt, label,
             view_once, max_views, view_count, created_at, expires_at, revoked)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.owner.clone()),
                TursoValue::Text(row.ciphertext.clone()),
                TursoValue::Integer(row.has_passphrase),
                opt(&row.kdf_salt),
                opt(&row.label),
                TursoValue::Integer(row.view_once),
                row.max_views
                    .map(TursoValue::Integer)
                    .unwrap_or(TursoValue::Null),
                TursoValue::Integer(row.view_count),
                TursoValue::Text(row.created_at.clone()),
                TursoValue::Text(row.expires_at.clone()),
                TursoValue::Integer(row.revoked),
            ],
        )
        .await
        .unwrap();
    }
}

fn opt(value: &Option<String>) -> TursoValue {
    match value {
        Some(text) => TursoValue::Text(text.clone()),
        None => TursoValue::Null,
    }
}

fn text(row: &VelaRow, i: usize) -> String {
    row.text(i)
        .unwrap_or_else(|| panic!("column {i} is not text"))
        .to_string()
}

/// The modelled columns of `sends` (the only table these executors touch).
async fn snapshot(db: &TursoDb) -> Model {
    let mut state = Model::default();
    for row in db
        .query(
            "SELECT id, owner_user_id, ciphertext, has_passphrase, kdf_salt, label,
             view_once, max_views, view_count, created_at, expires_at, revoked FROM sends",
            vec![],
        )
        .await
        .unwrap()
    {
        let previous = state.sends.insert(
            text(&row, 0),
            SendRow {
                owner: text(&row, 1),
                ciphertext: text(&row, 2),
                has_passphrase: row.i64(3).expect("has_passphrase is an integer"),
                kdf_salt: row.text(4).map(String::from),
                label: row.text(5).map(String::from),
                view_once: row.i64(6).expect("view_once is an integer"),
                max_views: row.i64(7),
                view_count: row.i64(8).expect("view_count is an integer"),
                created_at: text(&row, 9),
                expires_at: text(&row, 10),
                revoked: row.i64(11).expect("revoked is an integer"),
            },
        );
        assert!(previous.is_none(), "duplicate sends id");
    }
    state
}

/// The fault points of a plan of `n` statements: none, then each statement.
fn faults(n: usize) -> impl Iterator<Item = Option<usize>> {
    std::iter::once(None).chain((0..n).map(Some))
}

fn link(n: u128) -> String {
    Uuid::from_u128(0x7000 + n).to_string()
}

fn owner(n: u128) -> String {
    Uuid::from_u128(0x8000 + n).to_string()
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Slot {
    Absent,
    /// Unexpired, views remaining.
    Live,
    /// Every allowed view consumed.
    Exhausted,
    /// No view cap at all.
    Unbounded,
    /// Expired before `NOW`.
    Expired,
    /// Revoked.
    Revoked,
}

fn put_slot(state: &mut Model, id: &str, slot: Slot) {
    let row = |view_count: i64, max_views: Option<i64>, expires: &str, revoked: i64| SendRow {
        owner: owner(0),
        ciphertext: format!("ct-{id}"),
        has_passphrase: 0,
        kdf_salt: None,
        label: Some(format!("label-{id}")),
        view_once: 0,
        max_views,
        view_count,
        created_at: "2026-01-01T00:00:00+00:00".into(),
        expires_at: expires.into(),
        revoked,
    };
    match slot {
        Slot::Absent => {}
        Slot::Live => {
            state.sends.insert(id.into(), row(0, Some(2), LATER, 0));
        }
        Slot::Exhausted => {
            state.sends.insert(id.into(), row(2, Some(2), LATER, 0));
        }
        Slot::Unbounded => {
            state.sends.insert(id.into(), row(0, None, LATER, 0));
        }
        Slot::Expired => {
            state
                .sends
                .insert(id.into(), row(0, Some(2), "2026-01-01T00:00:00+00:00", 0));
        }
        Slot::Revoked => {
            state.sends.insert(id.into(), row(0, Some(2), LATER, 1));
        }
    }
}

/// Every `sends` state: the first slot takes every shape, the second is absent
/// or live, and a third id is always absent.
fn send_states() -> Vec<Model> {
    use Slot::*;
    let mut states = Vec::new();
    for a in [Absent, Live, Exhausted, Unbounded, Expired, Revoked] {
        for b in [Absent, Live] {
            let mut state = Model::default();
            put_slot(&mut state, &link(0), a);
            put_slot(&mut state, &link(1), b);
            states.push(state);
        }
    }
    states
}

/// The create permit the driver emits for a create request, so the insert uses
/// exactly the bounds the driver owns.
fn create_permit(
    view_once: bool,
    max_views: Option<i64>,
    ttl_secs: i64,
) -> vela_share_policy::send_driver::CreatePermit {
    let observation = CreateObservation {
        owner_present: true,
        ciphertext_decode_failed: false,
        ciphertext_len: 3,
        has_passphrase: false,
        kdf_salt_present: false,
        kdf_salt_decode_failed: false,
        kdf_salt_len: 0,
        has_ttl: true,
        ttl_secs,
        has_max_views: max_views.is_some(),
        max_views: max_views.unwrap_or(0),
        view_once,
    };
    match begin_create(observation).effect {
        SendEffect::InsertSend(permit) => permit,
        other => panic!("create request refused: {other:?}"),
    }
}

fn delete_permit() -> vela_share_policy::send_driver::DeletePermit {
    match begin_delete(true).effect {
        SendEffect::DeleteLink(permit) => permit,
        other => panic!("delete request refused: {other:?}"),
    }
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

#[tokio::test]
async fn schema_has_the_modelled_columns() {
    let db = temp_db().await;
    let expected: &[(&str, &str)] = &[
        ("id", "TEXT UNIQUE NOT NULL"),
        ("owner_user_id", "TEXT NOT NULL"),
        ("ciphertext", "TEXT NOT NULL"),
        ("has_passphrase", "INTEGER NOT NULL DEFAULT 0"),
        ("kdf_salt", "TEXT"),
        ("label", "TEXT"),
        ("view_once", "INTEGER NOT NULL DEFAULT 0"),
        ("max_views", "INTEGER"),
        ("view_count", "INTEGER NOT NULL DEFAULT 0"),
        ("created_at", "TEXT NOT NULL"),
        ("expires_at", "TEXT NOT NULL"),
        ("revoked", "INTEGER NOT NULL DEFAULT 0"),
    ];
    let rows = db
        .query(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sends'",
            vec![],
        )
        .await
        .unwrap();
    let ddl = rows
        .first()
        .and_then(|r| r.text(0))
        .expect("no sends table");
    let normal = ddl.split_whitespace().collect::<Vec<_>>().join(" ");
    for (column, declaration) in expected {
        let wanted = format!("{column} {declaration}");
        let found = normal.match_indices(&wanted).any(|(at, _)| {
            let before = normal[..at].chars().last();
            let after = normal[at + wanted.len()..].chars().next();
            matches!(before, Some('(') | Some(' ') | Some(','))
                && matches!(after, Some(',') | Some(')'))
        });
        assert!(
            found,
            "sends.{column} is not declared `{declaration}` in: {normal}"
        );
    }
    // The model keys the table by id: a second row with the same id fails.
    let mut state = Model::default();
    put_slot(&mut state, &link(0), Slot::Live);
    load(&db, &state).await;
    let duplicate = db
        .execute(
            "INSERT INTO sends (id, owner_user_id, ciphertext, has_passphrase, view_once, view_count, created_at, expires_at, revoked)
             VALUES (?, 'o', 'c', 0, 0, 0, 't', 't', 0)",
            vec![TursoValue::Text(link(0))],
        )
        .await;
    assert!(duplicate.is_err(), "sends accepted a duplicate id");
}

#[tokio::test]
async fn send_executors_match_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    // (view_once, max_views, has_passphrase, kdf_salt, label)
    let create_specs: [(bool, Option<i64>, bool, Option<&str>, Option<&str>); 2] = [
        (false, None, false, None, None),
        (true, Some(5), true, Some("salt"), Some("label")),
    ];

    for pre in send_states() {
        counts.states += 1;

        // CreateSendIo::insert_send.
        for (id, owner_id, spec) in [
            (link(2), owner(0), 0usize),
            (link(2), owner(1), 1),
            (link(0), owner(0), 0),
            (link(0), owner(1), 1),
        ] {
            let (view_once, max_views, has_passphrase, salt, label) = create_specs[spec];
            let salt = salt.map(str::to_string);
            let label = label.map(str::to_string);
            let permit = create_permit(view_once, max_views, 3600);
            let bytes = format!("send-{id}").into_bytes();
            let created = now();
            let expires = created + Duration::seconds(permit.ttl_secs());
            let plan = store::plan_send_create(
                id.clone(),
                owner_id.clone(),
                db::encode_b64(&bytes),
                has_passphrase,
                salt.clone(),
                label.clone(),
                permit.view_once(),
                if permit.max_views_present() {
                    Some(permit.max_views())
                } else {
                    None
                },
                created.to_rfc3339(),
                expires.to_rfc3339(),
            );
            for fault in faults(plan.len()) {
                load(&db, &pre).await;
                let mut io = CreateSendIo {
                    sql: Faulty::new(PoolSql(&db), fault),
                    owner_user_id: uuid(&owner_id),
                    ciphertext: bytes.clone(),
                    has_passphrase,
                    kdf_salt: salt.clone(),
                    label: label.clone(),
                    id: uuid(&id),
                    now: created,
                    expires_at: created,
                    error: None,
                };
                let observed = io.insert_send(permit).await;
                let (outcomes, expected_post) = model::run_send_autocommit(&pre, &plan, fault);
                let case = format!("create {id} as {owner_id} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, store::classify_send_create(&outcomes), "{case}");
                assert_eq!(snapshot(&db).await, expected_post, "{case}");
                assert_eq!(io.error.is_some(), observed.failed, "{case}");
                counts.case(fault);
            }
        }

        for id in [link(0), link(1), link(9)] {
            // FetchSendIo::consume_view.
            let plan = store::plan_send_consume(id.clone(), NOW.into());
            for fault in faults(plan.len()) {
                load(&db, &pre).await;
                let mut io = FetchSendIo {
                    sql: Faulty::new(PoolSql(&db), fault),
                    id: uuid(&id),
                    ciphertext: None,
                    has_passphrase: false,
                    kdf_salt: None,
                    view_once: false,
                    max_views: None,
                    view_count: 0,
                    expires_at: None,
                    error: None,
                };
                let observed = io.consume_view().await;
                let (outcomes, expected_post) = model::run_send_autocommit(&pre, &plan, fault);
                let case = format!("consume {id} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, store::classify_send_consume(&outcomes), "{case}");
                assert_eq!(snapshot(&db).await, expected_post, "{case}");
                assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                counts.case(fault);
            }

            // FetchSendIo::read_send.
            let plan = store::plan_send_read(id.clone());
            for fault in faults(1) {
                load(&db, &pre).await;
                let mut io = FetchSendIo {
                    sql: Faulty::new(PoolSql(&db), fault),
                    id: uuid(&id),
                    ciphertext: None,
                    has_passphrase: false,
                    kdf_salt: None,
                    view_once: false,
                    max_views: None,
                    view_count: 0,
                    expires_at: None,
                    error: None,
                };
                let observed = io.read_send().await;
                let expected =
                    store::classify_send_read(&model::read_send(&pre, &plan, fault.is_some()));
                let case = format!("read {id} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected.read, "{case}");
                assert_eq!(io.ciphertext, expected.ciphertext, "{case}");
                assert_eq!(io.has_passphrase, expected.has_passphrase, "{case}");
                assert_eq!(io.kdf_salt, expected.kdf_salt, "{case}");
                assert_eq!(io.view_once, expected.view_once, "{case}");
                assert_eq!(io.max_views, expected.max_views, "{case}");
                assert_eq!(io.view_count, expected.view_count, "{case}");
                assert_eq!(
                    io.expires_at,
                    expected
                        .expires_at
                        .as_deref()
                        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
                        .map(|at| at.with_timezone(&Utc)),
                    "{case}"
                );
                assert_eq!(
                    io.error.is_some(),
                    expected.missing_cell.is_some() || fault.is_some(),
                    "{case}"
                );
                assert_eq!(snapshot(&db).await, pre, "{case}");
                counts.case(fault);
            }

            // FetchSendIo::remove_fetched.
            let plan = store::plan_send_remove(id.clone());
            for fault in faults(plan.len()) {
                load(&db, &pre).await;
                let mut io = FetchSendIo {
                    sql: Faulty::new(PoolSql(&db), fault),
                    id: uuid(&id),
                    ciphertext: None,
                    has_passphrase: false,
                    kdf_salt: None,
                    view_once: false,
                    max_views: None,
                    view_count: 0,
                    expires_at: None,
                    error: None,
                };
                let observed = io.remove_fetched().await;
                let (outcomes, expected_post) = model::run_send_autocommit(&pre, &plan, fault);
                let case = format!("remove {id} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, store::classify_send_remove(&outcomes), "{case}");
                assert_eq!(snapshot(&db).await, expected_post, "{case}");
                // The handler ignores the cleanup outcome, so it never errors.
                assert!(io.error.is_none(), "{case}");
                counts.case(fault);
            }

            // DeleteSendIo::delete_link, for the owner and for a stranger.
            for caller in [owner(0), owner(1)] {
                let plan = store::plan_send_delete(id.clone(), caller.clone());
                for fault in faults(plan.len()) {
                    load(&db, &pre).await;
                    let mut io = DeleteSendIo {
                        sql: Faulty::new(PoolSql(&db), fault),
                        id: uuid(&id),
                        owner_user_id: uuid(&caller),
                        error: None,
                    };
                    let observed = io.delete_link(delete_permit()).await;
                    let (outcomes, expected_post) = model::run_send_autocommit(&pre, &plan, fault);
                    let case = format!("delete {id} as {caller} fault {fault:?} pre {pre:?}");
                    assert_eq!(observed, store::classify_send_delete(&outcomes), "{case}");
                    assert_eq!(snapshot(&db).await, expected_post, "{case}");
                    assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                    counts.case(fault);
                }
            }
        }
    }
    eprintln!(
        "send executor conformance: {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

/// A stored cell the handler cannot parse is a missing one: the read reports
/// `Unreadable` and the historical message, and the row is untouched.
#[tokio::test]
async fn an_unparsable_expiry_makes_the_row_unreadable() {
    let db = temp_db().await;
    let mut pre = Model::default();
    pre.sends.insert(
        link(0),
        SendRow {
            owner: owner(0),
            ciphertext: "ct".into(),
            has_passphrase: 1,
            kdf_salt: Some("salt".into()),
            label: None,
            view_once: 0,
            max_views: None,
            view_count: 3,
            created_at: "2026-01-01T00:00:00+00:00".into(),
            expires_at: "not-a-timestamp".into(),
            revoked: 0,
        },
    );
    load(&db, &pre).await;
    let mut io = FetchSendIo {
        sql: PoolSql(&db),
        id: uuid(&link(0)),
        ciphertext: None,
        has_passphrase: false,
        kdf_salt: None,
        view_once: false,
        max_views: None,
        view_count: 0,
        expires_at: None,
        error: None,
    };
    assert_eq!(io.read_send().await, ReadObservation::Unreadable);
    let message = format!("{}", io.error.as_ref().expect("an error"));
    assert!(message.contains("send row missing expires_at"), "{message}");
    // The cells read before the expiry check are kept, as before.
    assert_eq!(io.ciphertext.as_deref(), Some("ct"));
    assert!(io.has_passphrase);
    assert_eq!(io.kdf_salt.as_deref(), Some("salt"));
    assert_eq!(io.view_count, 3);
    assert!(io.expires_at.is_none());
    assert_eq!(snapshot(&db).await, pre);
}
