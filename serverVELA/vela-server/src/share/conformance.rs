//! Bounded conformance of the sharing executors against a real database
//! (F-1).
//!
//! The F* proofs in `vela-share-policy/proofs/fstar/store-lemmas` show that
//! each executor's plan and classifier are honest *in the store model*. This
//! test checks the model against turso: for every small starting state (at
//! most three users and three linked items, plus their inbox rows and
//! devices), every executor method, every caller and target, and every fault
//! point (no fault, or a failure injected at each statement in turn,
//! including the commit), it runs the real executor (plan, rendered SQL,
//! row decoding, classification) on a real database through [`Faulty`], and
//! compares the resulting tables and observation with the Rust mirror of the
//! model (`vela_share_policy::store_model`).
//!
//! A schema check pins the columns and types the model uses.

use std::collections::BTreeMap;

use uuid::Uuid;
use vela_share_policy::driver::{InboxDeletePermit, LinkUpdatePermit, SendInsertPermit};
use vela_share_policy::store::{self, DeviceVerdicts, ShareStmt};
use vela_share_policy::store_model::{
    self as model, Db as Model, DeviceRow, InboxRow, ItemRow, UserRow,
};
use vela_share_policy::{
    ek_registration_facts, plan_ek_registration, EkRegistrationDecision,
    EkRegistrationObservation, EkRegistrationPermit, SHARE_EK_LEN,
};

use super::executor::ShareExecutor;
use super::sql::{PoolSql, ShareSql, TxSql};
use super::{InboxDeleteIo, LinkRevokeIo, LinkUpdateIo, SendIo, ShareEkIo};
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

impl<S: ShareSql> ShareSql for Faulty<S> {
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
}

const NOW: &str = "2026-10-29T12:00:00+00:00";

fn fixed_now() -> String {
    NOW.into()
}

fn user(n: u128) -> Uuid {
    Uuid::from_u128(0x1000 + n)
}

fn item(n: u128) -> Uuid {
    Uuid::from_u128(0x2000 + n)
}

fn device(n: u128) -> Uuid {
    Uuid::from_u128(0x3000 + n)
}

fn s(id: Uuid) -> String {
    id.to_string()
}

fn opt(value: &Option<String>) -> TursoValue {
    match value {
        Some(text) => TursoValue::Text(text.clone()),
        None => TursoValue::Null,
    }
}

async fn temp_db() -> TursoDb {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "{}/vela-share-conformance-{}-{}.db",
        std::env::temp_dir().display(),
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    // One pooled and one transaction connection: waiting for the transaction
    // slot is then a barrier behind any rollback a dropped transaction spawned.
    TursoDb::open(&path, 1).await.unwrap()
}

/// Waits until any rollback spawned by a dropped transaction has finished.
async fn settle(db: &TursoDb) {
    db.tx().await.unwrap().rollback().await.unwrap();
}

async fn load(db: &TursoDb, state: &Model) {
    db.execute_batch(
        "DELETE FROM shared_items; DELETE FROM share_inbox; DELETE FROM users; DELETE FROM devices;",
    )
    .await
    .unwrap();
    for (id, row) in &state.users {
        db.execute(
            "INSERT INTO users (id, created_at, share_ek, share_ek_since, share_ek_device_id) VALUES (?, 't', ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                opt(&row.share_ek),
                opt(&row.share_ek_since),
                opt(&row.share_ek_device_id),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.devices {
        db.execute(
            "INSERT INTO devices (id, user_id, hybrid_ek, hybrid_vk, revoked, created_at) VALUES (?, ?, 'ek', ?, ?, 't')",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.user_id.clone()),
                TursoValue::Text(row.hybrid_vk.clone()),
                TursoValue::Integer(row.revoked),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.items {
        db.execute(
            "INSERT INTO shared_items (id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.sender.clone()),
                TursoValue::Text(row.recipient.clone()),
                TursoValue::Text(row.capsule.clone()),
                TursoValue::Text(row.created_at.clone()),
                TursoValue::Text(row.updated_at.clone()),
                TursoValue::Integer(row.revoked),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.inbox {
        db.execute(
            "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at) VALUES (?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.sender.clone()),
                TursoValue::Text(row.recipient.clone()),
                TursoValue::Text(row.capsule.clone()),
                TursoValue::Text(row.created_at.clone()),
            ],
        )
        .await
        .unwrap();
    }
}

fn text(row: &VelaRow, i: usize) -> String {
    row.text(i).unwrap_or_else(|| panic!("column {i} is not text")).to_string()
}

/// The modelled columns of all four tables.
async fn snapshot(db: &TursoDb) -> Model {
    let mut state = Model::default();
    for row in db
        .query("SELECT id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked FROM shared_items", vec![])
        .await
        .unwrap()
    {
        let previous = state.items.insert(
            text(&row, 0),
            ItemRow {
                sender: text(&row, 1),
                recipient: text(&row, 2),
                capsule: text(&row, 3),
                created_at: text(&row, 4),
                updated_at: text(&row, 5),
                revoked: match row.get(6) {
                    Some(TursoValue::Integer(value)) => *value,
                    other => panic!("revoked is not an integer: {other:?}"),
                },
            },
        );
        assert!(previous.is_none(), "duplicate shared_items id");
    }
    for row in db
        .query("SELECT id, sender_user_id, recipient_user_id, capsule, created_at FROM share_inbox", vec![])
        .await
        .unwrap()
    {
        let previous = state.inbox.insert(
            text(&row, 0),
            InboxRow {
                sender: text(&row, 1),
                recipient: text(&row, 2),
                capsule: text(&row, 3),
                created_at: text(&row, 4),
            },
        );
        assert!(previous.is_none(), "duplicate share_inbox id");
    }
    for row in db
        .query("SELECT id, share_ek, share_ek_since, share_ek_device_id FROM users", vec![])
        .await
        .unwrap()
    {
        state.users.insert(
            text(&row, 0),
            UserRow {
                share_ek: row.text(1).map(String::from),
                share_ek_since: row.text(2).map(String::from),
                share_ek_device_id: row.text(3).map(String::from),
            },
        );
    }
    for row in db
        .query("SELECT id, user_id, hybrid_vk, revoked FROM devices", vec![])
        .await
        .unwrap()
    {
        state.devices.insert(
            text(&row, 0),
            DeviceRow {
                user_id: text(&row, 1),
                hybrid_vk: text(&row, 2),
                revoked: row.i64(3).expect("revoked is an integer"),
            },
        );
    }
    state
}

/// The fault points of a plan of `n` statements: none, then each statement.
fn faults(n: usize) -> impl Iterator<Item = Option<usize>> {
    std::iter::once(None).chain((0..n).map(Some))
}

#[derive(Clone, Copy, Debug)]
enum Slot {
    Absent,
    /// u0 → u1, live, with its pending inbox copy.
    LiveWithInbox,
    /// u0 → u1, revoked, inbox copy cleaned up.
    Revoked,
    /// u1 → u0, live, already fetched (no inbox copy).
    LiveReverse,
    /// Only an inbox row, u2 → u0.
    OrphanInbox,
}

fn put_slot(state: &mut Model, id: Uuid, slot: Slot) {
    let row = |sender: Uuid, recipient: Uuid, revoked: i64| ItemRow {
        sender: s(sender),
        recipient: s(recipient),
        capsule: format!("cap-{id}"),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        revoked,
    };
    let inbox = |sender: Uuid, recipient: Uuid| InboxRow {
        sender: s(sender),
        recipient: s(recipient),
        capsule: format!("cap-{id}"),
        created_at: "2026-01-01T00:00:00+00:00".into(),
    };
    match slot {
        Slot::Absent => {}
        Slot::LiveWithInbox => {
            state.items.insert(s(id), row(user(0), user(1), 0));
            state.inbox.insert(s(id), inbox(user(0), user(1)));
        }
        Slot::Revoked => {
            state.items.insert(s(id), row(user(0), user(1), 1));
        }
        Slot::LiveReverse => {
            state.items.insert(s(id), row(user(1), user(0), 0));
        }
        Slot::OrphanInbox => {
            state.inbox.insert(s(id), inbox(user(2), user(0)));
        }
    }
}

fn base_users() -> BTreeMap<String, UserRow> {
    (0..3)
        .map(|n| {
            (
                s(user(n)),
                UserRow {
                    share_ek: Some(format!("ek-{n}")),
                    share_ek_since: None,
                    share_ek_device_id: None,
                },
            )
        })
        .collect()
}

/// Every item/inbox state: slots 0 and 1 take every shape, slot 2 is absent
/// or a live item with its inbox copy.
fn item_states() -> Vec<Model> {
    use Slot::*;
    let all = [Absent, LiveWithInbox, Revoked, LiveReverse, OrphanInbox];
    let mut states = Vec::new();
    for a in all {
        for b in all {
            for c in [Absent, LiveWithInbox] {
                let mut state = Model {
                    users: base_users(),
                    ..Model::default()
                };
                put_slot(&mut state, item(0), a);
                put_slot(&mut state, item(1), b);
                put_slot(&mut state, item(2), c);
                states.push(state);
            }
        }
    }
    states
}

/// Every users/devices state: each of three users is absent, present without
/// a binding, or present with one; four devices with fixed owners, one
/// revoked, one owned by u2.
fn device_states() -> Vec<Model> {
    let shapes = [
        None,
        Some(UserRow { share_ek: None, share_ek_since: None, share_ek_device_id: None }),
        Some(UserRow {
            share_ek: Some("ek-old".into()),
            share_ek_since: Some("2026-01-01T00:00:00Z".into()),
            share_ek_device_id: Some(s(device(0))),
        }),
    ];
    let mut devices = BTreeMap::new();
    for (n, owner, revoked) in [(0, 0, 0), (1, 0, 1), (2, 1, 0), (3, 2, 1)] {
        devices.insert(
            s(device(n)),
            DeviceRow { user_id: s(user(owner)), hybrid_vk: format!("vk-{n}"), revoked },
        );
    }
    let mut states = Vec::new();
    for a in &shapes {
        for b in &shapes {
            for c in &shapes {
                let mut state = Model { devices: devices.clone(), ..Model::default() };
                for (n, shape) in [a, b, c].into_iter().enumerate() {
                    if let Some(row) = shape {
                        state.users.insert(s(user(n as u128)), row.clone());
                    }
                }
                states.push(state);
            }
        }
    }
    states
}

fn authorizing_permit() -> EkRegistrationPermit {
    match plan_ek_registration(ek_registration_facts(EkRegistrationObservation {
        ek_len: SHARE_EK_LEN,
        signature_verified: true,
        device_row_present: true,
        device_user_matches: true,
        device_active: true,
        signed_at_is_fresher: true,
        binding_exists: false,
    })) {
        EkRegistrationDecision::Register(permit) => permit,
        EkRegistrationDecision::Reject => panic!("authorizing observation rejected"),
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
    let expected: [(&str, &[(&str, &str)]); 4] = [
        (
            "shared_items",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("sender_user_id", "TEXT NOT NULL"),
                ("recipient_user_id", "TEXT NOT NULL"),
                ("capsule", "TEXT NOT NULL"),
                ("created_at", "TEXT NOT NULL"),
                ("updated_at", "TEXT NOT NULL"),
                ("revoked", "INTEGER NOT NULL DEFAULT 0"),
            ],
        ),
        (
            "share_inbox",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("sender_user_id", "TEXT NOT NULL"),
                ("recipient_user_id", "TEXT NOT NULL"),
                ("capsule", "TEXT NOT NULL"),
                ("created_at", "TEXT NOT NULL"),
            ],
        ),
        (
            "users",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("share_ek", "TEXT"),
                ("share_ek_since", "TEXT"),
                ("share_ek_device_id", "TEXT"),
            ],
        ),
        (
            "devices",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("user_id", "TEXT NOT NULL"),
                ("hybrid_vk", "TEXT NOT NULL"),
                ("revoked", "INTEGER NOT NULL DEFAULT 0"),
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
        let ddl = rows.first().and_then(|r| r.text(0)).unwrap_or_else(|| panic!("no table {table}"));
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
    // The model keys every table by id: a second row with the same id fails.
    let mut state = Model { users: base_users(), ..Model::default() };
    put_slot(&mut state, item(0), Slot::LiveWithInbox);
    load(&db, &state).await;
    let duplicate = db
        .execute(
            "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at) VALUES (?, 'a', 'b', 'c', 't')",
            vec![TursoValue::Text(s(item(0)))],
        )
        .await;
    assert!(duplicate.is_err(), "share_inbox accepted a duplicate id");
}

#[tokio::test]
async fn link_and_inbox_executors_match_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    let callers = [user(0), user(1), user(2)];
    let targets = [item(0), item(1), item(2)];
    let new_capsule = b"replacement".to_vec();

    for pre in item_states() {
        counts.states += 1;

        // SendIo::insert_capsule, inside the handler's transaction.
        for (sender, recipient) in [(user(0), user(1)), (user(2), user(0))] {
            for id in targets {
                let bytes = format!("send-{id}").into_bytes();
                let plan = store::plan_send_insert(s(id), s(sender), s(recipient), db::encode_b64(&bytes), NOW.into());
                for fault in faults(plan.len()) {
                    load(&db, &pre).await;
                    let guard = db.tx().await.unwrap();
                    let mut io = SendIo {
                        recipient_user_id: recipient,
                        sender_user_id: sender,
                        capsule_bytes: bytes.clone(),
                        inbox_id: id,
                        now: NOW.into(),
                        tx: Some(Faulty::new(TxSql(Some(guard)), fault)),
                        insert_error: None,
                        commit_error: None,
                    };
                    let observed = io.insert_capsule(SendInsertPermit { capsule_len: bytes.len() as i64 }).await;
                    settle(&db).await;
                    let (outcomes, expected_post) = model::run_transaction(&pre, &plan, fault);
                    let expected = store::classify_send(&outcomes);
                    let case = format!("send {id} {sender}->{recipient} fault {fault:?} pre {pre:?}");
                    assert_eq!(observed, expected, "{case}");
                    assert_eq!(snapshot(&db).await, expected_post, "{case}");
                    let failed = !matches!(outcomes.last(), Some(store::WriteOutcome::Applied(_)));
                    assert_eq!(io.insert_error.is_some() || io.commit_error.is_some(), failed, "{case}");
                    assert_eq!(io.commit_error.is_some(), expected == vela_share_policy::driver::SendResultObservation::CommitConflict, "{case}");
                    counts.case(fault);
                }
            }
        }

        for caller in callers {
            for id in targets {
                // LinkUpdateIo::observe_link (LinkRevokeIo shares the code).
                for fault in faults(1) {
                    load(&db, &pre).await;
                    let mut io = LinkUpdateIo {
                        sql: Faulty::new(PoolSql(&db), fault),
                        id,
                        user_id: caller,
                        capsule_bytes: new_capsule.clone(),
                        clock: fixed_now,
                        error: None,
                    };
                    let observed = io.observe_link().await;
                    let expected = store::classify_link(
                        &s(caller),
                        &model::read_link(&pre, &store::plan_link_read(s(id)), fault == Some(0)),
                    );
                    let case = format!("observe link {id} as {caller} fault {fault:?} pre {pre:?}");
                    assert_eq!(observed, expected, "{case}");
                    assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                    assert_eq!(snapshot(&db).await, pre, "{case}");
                    counts.case(fault);
                }

                // LinkUpdateIo::update_linked_item.
                let plan = store::plan_link_update(s(id), s(caller), db::encode_b64(&new_capsule), NOW.into());
                for fault in faults(plan.len()) {
                    load(&db, &pre).await;
                    let mut io = LinkUpdateIo {
                        sql: Faulty::new(PoolSql(&db), fault),
                        id,
                        user_id: caller,
                        capsule_bytes: new_capsule.clone(),
                        clock: fixed_now,
                        error: None,
                    };
                    let observed = io.update_linked_item(LinkUpdatePermit { capsule_len: new_capsule.len() as i64 }).await;
                    let (outcomes, expected_post) = model::run_autocommit(&pre, &plan, fault);
                    let case = format!("update {id} as {caller} fault {fault:?} pre {pre:?}");
                    assert_eq!(observed, store::classify_rows(&outcomes), "{case}");
                    assert_eq!(snapshot(&db).await, expected_post, "{case}");
                    assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                    counts.case(fault);
                }

                // LinkRevokeIo::revoke_linked_item.
                let plan = store::plan_link_revoke(s(id), s(caller), NOW.into());
                for fault in faults(plan.len()) {
                    load(&db, &pre).await;
                    let mut io = LinkRevokeIo {
                        sql: Faulty::new(PoolSql(&db), fault),
                        id,
                        user_id: caller,
                        clock: fixed_now,
                        error: None,
                    };
                    let observed = io.revoke_linked_item().await;
                    let (outcomes, expected_post) = model::run_autocommit(&pre, &plan, fault);
                    let case = format!("revoke {id} as {caller} fault {fault:?} pre {pre:?}");
                    assert_eq!(observed, store::classify_rows(&outcomes), "{case}");
                    assert_eq!(snapshot(&db).await, expected_post, "{case}");
                    assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                    counts.case(fault);
                }

                // InboxDeleteIo::delete_inbox_item.
                let plan = store::plan_inbox_delete(s(id), s(caller));
                for fault in faults(plan.len()) {
                    load(&db, &pre).await;
                    let mut io = InboxDeleteIo {
                        sql: Faulty::new(PoolSql(&db), fault),
                        id,
                        user_id: caller,
                        error: None,
                    };
                    let observed = io.delete_inbox_item(InboxDeletePermit { recipient_scoped: true }).await;
                    let (outcomes, expected_post) = model::run_autocommit(&pre, &plan, fault);
                    let case = format!("inbox delete {id} as {caller} fault {fault:?} pre {pre:?}");
                    assert_eq!(observed, store::classify_rows(&outcomes), "{case}");
                    assert_eq!(snapshot(&db).await, expected_post, "{case}");
                    assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                    counts.case(fault);
                }
            }
        }

        // LinkRevokeIo::delete_linked_inbox.
        for id in targets {
            let plan = store::plan_linked_inbox_cleanup(s(id));
            for fault in faults(plan.len()) {
                load(&db, &pre).await;
                let mut io = LinkRevokeIo {
                    sql: Faulty::new(PoolSql(&db), fault),
                    id,
                    user_id: user(0),
                    clock: fixed_now,
                    error: None,
                };
                let observed = io.delete_linked_inbox().await;
                let (outcomes, expected_post) = model::run_autocommit(&pre, &plan, fault);
                let case = format!("cleanup {id} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, store::classify_cleanup(&outcomes), "{case}");
                assert_eq!(snapshot(&db).await, expected_post, "{case}");
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "share executor conformance (link/inbox/send): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn share_key_executors_match_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    let permit = authorizing_permit();
    let signed_at = "2026-06-01T00:00:00Z".to_string();

    for pre in device_states() {
        counts.states += 1;
        for caller in [user(0), user(1), user(2)] {
            // ShareEkIo::observe_device, for owned, foreign, revoked and
            // missing devices.
            for device_id in [device(0), device(1), device(2), device(3), device(9)] {
                for fault in faults(1) {
                    load(&db, &pre).await;
                    let mut io = ShareEkIo {
                        sql: Faulty::new(PoolSql(&db), fault),
                        user_id: caller,
                        device_id,
                        share_ek: "new-ek".into(),
                        signature: "not base64!".into(),
                        ek_bytes: vec![7; SHARE_EK_LEN],
                        canonical_signed_at: signed_at.clone(),
                        error: None,
                        stored_vk_error: None,
                        signature_decode_error: None,
                    };
                    let observed = io.observe_device().await;
                    // The verdicts are crypto and freshness results outside the
                    // model; the row-derived fields are compared.
                    let verdicts = DeviceVerdicts {
                        signature_verified: observed.registration.signature_verified,
                        stored_vk_decode_failed: observed.stored_identity_vk_decode_failed,
                        signature_decode_failed: observed.signature_decode_failed,
                        signed_at_is_fresher: observed.registration.signed_at_is_fresher,
                    };
                    let read: ShareStmt = store::plan_device_read(s(device_id), s(caller));
                    let expected = store::classify_device(
                        &s(caller),
                        SHARE_EK_LEN,
                        &model::read_device(&pre, &read, fault == Some(0)),
                        verdicts,
                    );
                    let case = format!("observe device {device_id} as {caller} fault {fault:?} pre {pre:?}");
                    assert_eq!(observed, expected, "{case}");
                    assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                    assert_eq!(snapshot(&db).await, pre, "{case}");
                    counts.case(fault);
                }
            }

            // ShareEkIo::update_share_ek.
            let plan = store::plan_share_ek_update(s(caller), "new-ek".into(), signed_at.clone(), s(device(0)));
            for fault in faults(plan.len()) {
                load(&db, &pre).await;
                let mut io = ShareEkIo {
                    sql: Faulty::new(PoolSql(&db), fault),
                    user_id: caller,
                    device_id: device(0),
                    share_ek: "new-ek".into(),
                    signature: String::new(),
                    ek_bytes: vec![7; SHARE_EK_LEN],
                    canonical_signed_at: signed_at.clone(),
                    error: None,
                    stored_vk_error: None,
                    signature_decode_error: None,
                };
                let observed = io.update_share_ek(permit).await;
                let (outcomes, expected_post) = model::run_autocommit(&pre, &plan, fault);
                let case = format!("share-ek update as {caller} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, store::classify_rows(&outcomes), "{case}");
                assert_eq!(snapshot(&db).await, expected_post, "{case}");
                assert_eq!(io.error.is_some(), fault.is_some(), "{case}");
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "share executor conformance (share key): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}
