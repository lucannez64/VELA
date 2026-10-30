//! Bounded conformance of the recovered-device enrollment and recovery-share
//! executors against a real database and store (F-1).
//!
//! The F* proofs in `vela-recovery-policy/proofs/fstar/redemption-lemmas` and
//! `share-lemmas` show that each `EnrollDeviceIo` and `PutShareIo` /
//! `FinalizeShareIo` / `GetShareIo` / `DeleteShareIo` method's plan and
//! classifier are honest *in the store model*. This test checks the models
//! against turso and sled: for every small starting state (each `users` shape,
//! a fresh and an already used device id, every enrollment-grant shape and
//! every recovery-share row shape), every guard, every caller/credential and
//! every fault point (no fault, or a failure injected at the statement), it
//! runs the real executor (plan, rendered SQL or key-value operation, row
//! decoding, classification) through [`Faulty`] and compares the resulting
//! tables, grant keys, share row and observation with the Rust mirror of the
//! model (`vela_recovery_policy::redemption_model`).
//!
//! A schema check pins the columns and types the model uses.

use uuid::Uuid;
use vela_recovery_policy::driver::{
    AuthorityRecheckObservation, ConsumptionObservation, InsertObservation, RedemptionInsertPermit,
};
use vela_recovery_policy::redemption_model::{self as model, Db as Model, DeviceRow, ShareDb, ShareUserRow, UserRow};
use vela_recovery_policy::redemption_store::{self, GrantGuard, GrantView};
use vela_recovery_policy::recovery_share_driver::{
    begin_share_lifecycle, ShareActorObservation, ShareEffect, ShareOperation,
    ShareRequestObservation,
};

use super::enroll_device::EnrollDeviceIo;
use super::recover::RecoveryEnrollGrant;
use super::sql::{PoolSql, RecoveryKv, RecoverySql, StoreKv};
use crate::error::{AppError, Result};
use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};

/// Fails the k-th SQL statement (from 0) an executor sends, without sending it.
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

impl<S: RecoverySql> RecoverySql for Faulty<S> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.hit()?;
        self.inner.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.hit()?;
        self.inner.execute(sql, params).await
    }
}

/// Fails the k-th store operation (from 0) an executor sends.
struct FaultyKv<K> {
    inner: K,
    fail_at: Option<usize>,
    calls: usize,
}

impl<K> FaultyKv<K> {
    fn new(inner: K, fail_at: Option<usize>) -> Self {
        Self { inner, fail_at, calls: 0 }
    }

    fn hit(&mut self) -> Result<()> {
        let k = self.calls;
        self.calls += 1;
        if self.fail_at == Some(k) {
            Err(AppError::Internal(format!("injected store failure at operation {k}")))
        } else {
            Ok(())
        }
    }
}

impl<K: RecoveryKv> RecoveryKv for FaultyKv<K> {
    fn take(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        self.hit()?;
        self.inner.take(key)
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.hit()?;
        self.inner.put(key, value)
    }
}

const NOW: &str = "2026-10-30T12:00:00+00:00";
const DERIVED_EK: &str = "AQID"; // base64 of [1, 2, 3]
const DERIVED_VK: &str = "BAUG"; // base64 of [4, 5, 6]

fn user(n: u128) -> Uuid {
    Uuid::from_u128(0x1000 + n)
}

fn grant(n: u128) -> Uuid {
    Uuid::from_u128(0x2000 + n)
}

fn device(n: u128) -> Uuid {
    Uuid::from_u128(0x3000 + n)
}

fn s(id: Uuid) -> String {
    id.to_string()
}

fn t(value: &str) -> String {
    value.to_string()
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
        "{}/vela-recovery-conformance-{}-{}.db",
        std::env::temp_dir().display(),
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    TursoDb::open(&path, 1).await.unwrap()
}

fn temp_store() -> crate::store::Store {
    crate::store::Store::open_temp().unwrap()
}

fn grant_json(grant: &GrantView) -> Vec<u8> {
    serde_json::to_vec(&RecoveryEnrollGrant {
        key_epoch: grant.key_epoch,
        credential_id: grant.credential_id.clone(),
        possession: grant.possession,
    })
    .unwrap()
}

fn grant_of_store(value: &[u8]) -> GrantView {
    let grant = super::recover::decode_enroll_grant(value).expect("stored grant decodes");
    GrantView {
        key_epoch: grant.key_epoch,
        credential_id: grant.credential_id,
        possession: grant.possession,
    }
}

async fn load(db: &TursoDb, store: &crate::store::Store, state: &Model, keys: &[String]) {
    db.execute_batch("DELETE FROM users; DELETE FROM devices;")
        .await
        .unwrap();
    for (id, row) in &state.users {
        db.execute(
            "INSERT INTO users (id, created_at, key_epoch, rekey_state, recovery_webauthn_cred_id, recovery_auth_hash)
             VALUES (?, 't', ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Integer(row.epoch),
                if row.rekey {
                    TursoValue::Text("rotating".into())
                } else {
                    TursoValue::Null
                },
                opt(&row.credential_id),
                opt(&row.auth_hash),
            ],
        )
        .await
        .unwrap();
    }
    for (id, row) in &state.devices {
        db.execute(
            "INSERT INTO devices (id, user_id, device_name, device_type, hybrid_ek, hybrid_vk, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(row.user.clone()),
                TursoValue::Text(row.name.clone()),
                TursoValue::Text(row.kind.clone()),
                TursoValue::Text(row.hybrid_ek.clone()),
                TursoValue::Text(row.hybrid_vk.clone()),
                TursoValue::Text(row.created_at.clone()),
            ],
        )
        .await
        .unwrap();
    }
    for key in keys {
        store.del(key).unwrap();
        if let Some(value) = state.grants.get(key) {
            store.set(key, &grant_json(value)).unwrap();
        }
    }
}

fn text(row: &VelaRow, i: usize) -> String {
    row.text(i).unwrap_or_else(|| panic!("column {i} is not text")).to_string()
}

async fn snapshot(db: &TursoDb, store: &crate::store::Store, keys: &[String]) -> Model {
    let mut state = Model::default();
    for row in db
        .query(
            "SELECT id, key_epoch, rekey_state, recovery_webauthn_cred_id, recovery_auth_hash FROM users",
            vec![],
        )
        .await
        .unwrap()
    {
        let previous = state.users.insert(
            text(&row, 0),
            UserRow {
                epoch: row.i64(1).expect("key_epoch is an integer"),
                rekey: row.text(2).is_some(),
                credential_id: row.text(3).map(String::from),
                // The model normalizes an empty commitment to absence, exactly
                // as the executor's read view does.
                auth_hash: row.text(4).filter(|hash| !hash.is_empty()).map(String::from),
            },
        );
        assert!(previous.is_none(), "duplicate users id");
    }
    for row in db
        .query(
            "SELECT id, user_id, device_name, device_type, hybrid_ek, hybrid_vk, created_at FROM devices",
            vec![],
        )
        .await
        .unwrap()
    {
        let previous = state.devices.insert(
            text(&row, 0),
            DeviceRow {
                user: text(&row, 1),
                name: text(&row, 2),
                kind: text(&row, 3),
                hybrid_ek: text(&row, 4),
                hybrid_vk: text(&row, 5),
                created_at: text(&row, 6),
            },
        );
        assert!(previous.is_none(), "duplicate devices id");
    }
    for key in keys {
        if let Some(value) = store.get(key).unwrap() {
            state.grants.insert(key.clone(), grant_of_store(&value));
        }
    }
    state
}

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

/// Every `users` shape the executor can meet.
fn user_states() -> Vec<Option<UserRow>> {
    let shape = |epoch: i64, rekey: bool, credential: Option<&str>, auth: Option<&str>| {
        Some(UserRow {
            epoch,
            rekey,
            credential_id: credential.map(String::from),
            auth_hash: auth.map(String::from),
        })
    };
    vec![
        None,
        shape(7, false, Some("c"), Some("h")),
        shape(7, false, Some("c"), None),
        shape(7, false, Some("x"), Some("h")),
        shape(7, false, None, Some("h")),
        shape(8, false, Some("c"), Some("h")),
        shape(1, false, Some("c"), Some("h")),
        shape(7, true, Some("c"), Some("h")),
    ]
}

fn credential_preflight() -> RecoveryEnrollGrant {
    RecoveryEnrollGrant::credential_bound(7, "c")
}

fn possession_preflight() -> RecoveryEnrollGrant {
    RecoveryEnrollGrant::from_possession_proof(7)
}

fn grant_view_of(grant: &RecoveryEnrollGrant) -> GrantView {
    GrantView {
        key_epoch: grant.key_epoch,
        credential_id: grant.credential_id.clone(),
        possession: grant.possession,
    }
}

#[tokio::test]
async fn schema_has_the_modelled_columns() {
    let db = temp_db().await;
    let expected: [(&str, &[(&str, &str)]); 2] = [
        (
            "users",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("key_epoch", "INTEGER NOT NULL DEFAULT 1"),
                ("rekey_state", "TEXT"),
                ("recovery_webauthn_cred_id", "TEXT"),
                ("recovery_auth_hash", "TEXT"),
            ],
        ),
        (
            "devices",
            &[
                ("id", "TEXT UNIQUE NOT NULL"),
                ("user_id", "TEXT NOT NULL"),
                ("device_name", "TEXT NOT NULL DEFAULT 'Desktop Device'"),
                ("device_type", "TEXT NOT NULL DEFAULT 'desktop'"),
                ("hybrid_ek", "TEXT NOT NULL"),
                ("hybrid_vk", "TEXT NOT NULL"),
                ("created_at", "TEXT NOT NULL"),
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
                matches!(before, Some('(') | Some(' '))
                    && matches!(after, Some(',') | Some(')'))
            });
            assert!(found, "{table}.{column} is not declared `{declaration}` in: {normal}");
        }
    }
    // The model keys devices by id: a second row with the same id fails.
    db.execute(
        "INSERT INTO devices (id, user_id, device_name, device_type, hybrid_ek, hybrid_vk, created_at)
         VALUES ('d', 'u', 'n', 'k', 'ek', 'vk', 't')",
        vec![],
    )
    .await
    .unwrap();
    let duplicate = db
        .execute(
            "INSERT INTO devices (id, user_id, device_name, device_type, hybrid_ek, hybrid_vk, created_at)
             VALUES ('d', 'u', 'n', 'k', 'ek', 'vk', 't')",
            vec![],
        )
        .await;
    assert!(duplicate.is_err(), "devices accepted a duplicate id");
}

#[tokio::test]
async fn grant_consumption_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let key = redemption_store::grant_key(&s(user(0)), &s(grant(0)));
    let keys = vec![key.clone()];

    let grant_states: Vec<Option<GrantView>> = vec![
        None,
        Some(GrantView { key_epoch: 7, credential_id: t("c"), possession: false }),
        Some(GrantView { key_epoch: 7, credential_id: t("c"), possession: true }),
        Some(GrantView { key_epoch: 8, credential_id: t("c"), possession: false }),
        Some(GrantView { key_epoch: 7, credential_id: t("x"), possession: false }),
        Some(grant_view_of(&possession_preflight())),
    ];
    for stored in grant_states {
        counts.states += 1;
        let mut state = Model::default();
        if let Some(grant) = &stored {
            state.grants.insert(key.clone(), grant.clone());
        }
        for preflight in [credential_preflight(), possession_preflight()] {
            for fault in faults(1) {
                load(&db, &store, &state, &keys).await;
                let mut io = EnrollDeviceIo::for_conformance(
                    PoolSql(&db),
                    FaultyKv::new(StoreKv(&store), fault),
                    user(0),
                    grant(0),
                    preflight.clone(),
                    None,
                );
                let observed = io.consume_grant().await;
                let Our { observation: expected, post, observed_grant } =
                    expected_take(&state, &key, &preflight, fault);
                let case = format!("take {stored:?} {preflight:?} fault {fault:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(snapshot(&db, &store, &keys).await, post, "{case}");
                assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
                assert_eq!(
                    io.consumed_grant().map(grant_view_of),
                    observed_grant,
                    "{case}"
                );
                let matched = observed_grant.as_ref() == Some(&grant_view_of(&preflight));
                assert_eq!(io.grant_consumed(), observed_grant.is_some(), "{case}");
                assert_eq!(io.consumed_matches_observed(), matched, "{case}");
                counts.case(fault);
            }
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

struct Our {
    observation: Option<ConsumptionObservation>,
    post: Model,
    observed_grant: Option<GrantView>,
}

fn expected_take(
    state: &Model,
    key: &str,
    preflight: &RecoveryEnrollGrant,
    fault: Option<usize>,
) -> Our {
    let taken = model::take_grant(state, key, &grant_view_of(preflight), fault);
    match taken {
        None => Our {
            observation: None,
            post: state.clone(),
            observed_grant: None,
        },
        Some((observation, post)) => {
            let observed_grant = match &observation {
                ConsumptionObservation::Missing => None,
                ConsumptionObservation::Present(_) => state.grants.get(key).cloned(),
            };
            Our { observation: Some(observation), post, observed_grant }
        }
    }
}

#[tokio::test]
async fn guarded_insert_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let key = redemption_store::grant_key(&s(user(0)), &s(grant(0)));
    let keys = vec![key];

    for users in user_states() {
        counts.states += 1;
        let mut state = Model::default();
        if let Some(row) = users {
            state.users.insert(s(user(0)), row);
        }
        for used in [false, true] {
            let mut pre = state.clone();
            if used {
                pre.devices.insert(
                    s(device(9)),
                    DeviceRow {
                        user: s(user(1)),
                        name: "existing".into(),
                        kind: "existing".into(),
                        hybrid_ek: "ek".into(),
                        hybrid_vk: "vk".into(),
                        created_at: "t".into(),
                    },
                );
            }
            for (preflight, guard) in [
                (credential_preflight(), GrantGuard::Credential { credential_id: t("c") }),
                (possession_preflight(), GrantGuard::Commitment),
            ] {
                for fault in faults(1) {
                    load(&db, &store, &pre, &keys).await;
                    let mut io = EnrollDeviceIo::for_conformance(
                        Faulty::new(PoolSql(&db), fault),
                        StoreKv(&store),
                        user(0),
                        grant(0),
                        preflight.clone(),
                        Some(preflight.clone()),
                    );
                    let observed = io
                        .insert_device(RedemptionInsertPermit {
                            epoch: preflight.key_epoch,
                            possession: preflight.possession,
                        })
                        .await;
                    let device_id = s(io.new_device_id().expect("insert generated an id"));
                    let (expected, post) = model::insert_device(
                        &pre,
                        &device_id,
                        &s(user(0)),
                        "conformance-device",
                        "conformance",
                        DERIVED_EK,
                        DERIVED_VK,
                        NOW,
                        preflight.key_epoch,
                        &guard,
                        fault,
                    );
                    let case = format!(
                        "insert users {pre:?} used {used} guard {guard:?} fault {fault:?}"
                    );
                    assert_eq!(observed, Some(expected), "{case}");
                    assert_eq!(snapshot(&db, &store, &keys).await, post, "{case}");
                    assert_eq!(
                        io.insert_error_is_set(),
                        expected == InsertObservation::Failed,
                        "{case}"
                    );
                    counts.case(fault);
                }
            }
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn authority_recheck_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let key = redemption_store::grant_key(&s(user(0)), &s(grant(0)));
    let keys = vec![key];

    for users in user_states() {
        counts.states += 1;
        let mut state = Model::default();
        if let Some(row) = users {
            state.users.insert(s(user(0)), row);
        }
        for possession in [false, true] {
            let credential = if possession { "rms-possession-v1" } else { "c" };
            let consumed = if possession {
                possession_preflight()
            } else {
                credential_preflight()
            };
            for fault in faults(1) {
                load(&db, &store, &state, &keys).await;
                let mut io = EnrollDeviceIo::for_conformance(
                    Faulty::new(PoolSql(&db), fault),
                    StoreKv(&store),
                    user(0),
                    grant(0),
                    consumed.clone(),
                    Some(consumed.clone()),
                );
                let observed = io.recheck_authority().await;
                let expected = model::recheck_authority(
                    &state,
                    &s(user(0)),
                    possession,
                    credential,
                    fault,
                );
                let case = format!("recheck users {state:?} possession {possession} fault {fault:?}");
                assert_eq!(observed, Some(expected), "{case}");
                assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
                counts.case(fault);
            }
        }
    }

    // An empty stored commitment is no commitment, exactly as `<> ''`.
    let mut state = Model::default();
    state.users.insert(
        s(user(0)),
        UserRow {
            epoch: 7,
            rekey: false,
            credential_id: Some(t("c")),
            auth_hash: None,
        },
    );
    load(&db, &store, &state, &keys).await;
    db.execute(
        "UPDATE users SET recovery_auth_hash = '' WHERE id = ?",
        vec![TursoValue::Text(s(user(0)))],
    )
    .await
    .unwrap();
    let mut io = EnrollDeviceIo::for_conformance(
        PoolSql(&db),
        StoreKv(&store),
        user(0),
        grant(0),
        possession_preflight(),
        Some(possession_preflight()),
    );
    assert_eq!(
        io.recheck_authority().await,
        Some(AuthorityRecheckObservation::CommitmentRevoked)
    );
    let mut io = EnrollDeviceIo::for_conformance(
        PoolSql(&db),
        StoreKv(&store),
        user(0),
        grant(0),
        possession_preflight(),
        Some(possession_preflight()),
    );
    assert_eq!(
        io.insert_device(RedemptionInsertPermit { epoch: 7, possession: true }).await,
        Some(InsertObservation::Skipped)
    );
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn grant_restoration_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let key = redemption_store::grant_key(&s(user(0)), &s(grant(0)));
    let keys = vec![key.clone()];

    for stored in [false, true] {
        counts.states += 1;
        let mut state = Model::default();
        let restored = grant_view_of(&credential_preflight());
        if stored {
            state
                .grants
                .insert(key.clone(), grant_view_of(&possession_preflight()));
        }
        for fault in faults(1) {
            load(&db, &store, &state, &keys).await;
            let mut io = EnrollDeviceIo::for_conformance(
                PoolSql(&db),
                FaultyKv::new(StoreKv(&store), fault),
                user(0),
                grant(0),
                credential_preflight(),
                Some(credential_preflight()),
            );
            let observed = io.restore_grant().await;
            let expected_post = model::restore_grant(
                &state,
                &key,
                "",
                &restored,
                fault,
            );
            let case = format!("restore stored {stored} fault {fault:?}");
            assert_eq!(observed.is_some(), expected_post.is_some(), "{case}");
            assert_eq!(
                snapshot(&db, &store, &keys).await,
                expected_post.unwrap_or_else(|| state.clone()),
                "{case}"
            );
            assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
            counts.case(fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

// ── Recovery-share lifecycle conformance ───────────────────────────────────

fn share_actor() -> ShareActorObservation {
    ShareActorObservation {
        authenticated: true,
        device_active: true,
        scoped_to_session_account: true,
    }
}

fn share_request(operation: ShareOperation, epoch: i64) -> ShareRequestObservation {
    ShareRequestObservation {
        operation,
        actor: share_actor(),
        declared_epoch: epoch,
        split_id_present: true,
        share_present: true,
        device_authority: true,
        split: 11,
    }
}

fn stage_permit(epoch: i64) -> vela_recovery_policy::recovery_share_driver::ShareStagePermit {
    match begin_share_lifecycle(share_request(ShareOperation::Stage, epoch)).effect {
        ShareEffect::StageShare(permit) => permit,
        other => panic!("expected a stage permit, got {other:?}"),
    }
}

fn finalize_permit(epoch: i64) -> vela_recovery_policy::recovery_share_driver::ShareFinalizePermit {
    match begin_share_lifecycle(share_request(ShareOperation::Finalize, epoch)).effect {
        ShareEffect::PromoteStagedSplit(permit) => permit,
        other => panic!("expected a finalize permit, got {other:?}"),
    }
}

fn delete_permit(epoch: i64) -> vela_recovery_policy::recovery_share_driver::ShareDeletePermit {
    match begin_share_lifecycle(share_request(ShareOperation::Delete, epoch)).effect {
        ShareEffect::DeleteShare(permit) => permit,
        other => panic!("expected a delete permit, got {other:?}"),
    }
}

fn share_row(
    epoch: i64,
    rekey: bool,
    share: Option<&str>,
    split: Option<&str>,
    pending_share: Option<&str>,
    pending_split: Option<&str>,
    pending_epoch: Option<i64>,
    auth: Option<&str>,
    pending_auth: Option<&str>,
) -> ShareUserRow {
    ShareUserRow {
        epoch,
        rekey,
        share: share.map(String::from),
        split: split.map(String::from),
        pending_share: pending_share.map(String::from),
        pending_split: pending_split.map(String::from),
        pending_epoch,
        auth: auth.map(String::from),
        pending_auth: pending_auth.map(String::from),
    }
}

async fn load_share(db: &TursoDb, state: &ShareDb) {
    db.execute_batch("DELETE FROM users;").await.unwrap();
    for (id, row) in &state.users {
        db.execute(
            "INSERT INTO users (id, created_at, key_epoch, rekey_state,
                 recovery_share, recovery_split_id, recovery_pending_share,
                 recovery_pending_split_id, recovery_pending_epoch,
                 recovery_auth_hash, recovery_pending_auth_hash)
             VALUES (?, 't', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Integer(row.epoch),
                if row.rekey {
                    TursoValue::Text("rotating".into())
                } else {
                    TursoValue::Null
                },
                opt(&row.share),
                opt(&row.split),
                opt(&row.pending_share),
                opt(&row.pending_split),
                row.pending_epoch.map(TursoValue::Integer).unwrap_or(TursoValue::Null),
                opt(&row.auth),
                opt(&row.pending_auth),
            ],
        )
        .await
        .unwrap();
    }
}

async fn snapshot_share(db: &TursoDb) -> ShareDb {
    let mut state = ShareDb::default();
    for row in db
        .query(
            "SELECT id, key_epoch, rekey_state, recovery_share, recovery_split_id,
                    recovery_pending_share, recovery_pending_split_id,
                    recovery_pending_epoch, recovery_auth_hash,
                    recovery_pending_auth_hash
             FROM users",
            vec![],
        )
        .await
        .unwrap()
    {
        let previous = state.users.insert(
            text(&row, 0),
            ShareUserRow {
                epoch: row.i64(1).expect("key_epoch is an integer"),
                rekey: row.text(2).is_some(),
                share: row.text(3).map(String::from),
                split: row.text(4).map(String::from),
                pending_share: row.text(5).map(String::from),
                pending_split: row.text(6).map(String::from),
                pending_epoch: row.i64(7),
                auth: row.text(8).map(String::from),
                pending_auth: row.text(9).map(String::from),
            },
        );
        assert!(previous.is_none(), "duplicate users id");
    }
    state
}

const SHARE: &str = "c2hhcmU=";
const SPLIT: &str = "2";
const AUTH: &str = "YXV0aA==";

fn share_states() -> Vec<Option<ShareUserRow>> {
    vec![
        None,
        Some(share_row(7, false, None, None, None, None, None, None, None)),
        Some(share_row(8, false, None, None, None, None, None, None, None)),
        Some(share_row(7, true, None, None, None, None, None, None, None)),
        Some(share_row(7, false, Some(SHARE), None, None, None, None, Some(AUTH), None)),
        Some(share_row(7, false, None, Some(SPLIT), None, None, None, None, None)),
        Some(share_row(7, false, None, None, Some(SHARE), Some(SPLIT), Some(7), None, Some(AUTH))),
        Some(share_row(7, false, None, None, Some(SHARE), Some("3"), Some(7), None, Some(AUTH))),
        Some(share_row(7, false, None, None, Some(SHARE), Some(SPLIT), Some(8), None, Some(AUTH))),
        Some(share_row(7, false, None, None, None, Some(SPLIT), Some(7), None, Some(AUTH))),
        Some(share_row(7, false, None, None, Some(SHARE), Some(SPLIT), Some(7), None, None)),
        Some(share_row(7, false, Some(SHARE), Some(SPLIT), Some(SHARE), Some(SPLIT), Some(7), Some(AUTH), Some(AUTH))),
    ]
}

fn share_model(states: &[Option<ShareUserRow>]) -> Vec<ShareDb> {
    states
        .iter()
        .map(|stored| {
            let mut state = ShareDb::default();
            if let Some(row) = stored {
                state.users.insert(s(user(0)), row.clone());
            }
            state
        })
        .collect()
}

#[tokio::test]
async fn share_stage_matches_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    for state in share_model(&share_states()) {
        counts.states += 1;
        for fault in faults(1) {
            load_share(&db, &state).await;
            let mut io = super::PutShareIo::for_conformance(
                Faulty::new(PoolSql(&db), fault),
                s(user(0)),
                t(SHARE),
                t(SPLIT),
                t(AUTH),
            );
            let observed = io.stage_share(stage_permit(7)).await;
            let expected = model::stage_share(
                &state,
                &s(user(0)),
                SHARE,
                SPLIT,
                7,
                AUTH,
                fault,
            );
            let (expected_obs, expected_post) = match expected {
                Some((obs, post)) => (Some(obs), post),
                None => (None, state.clone()),
            };
            let case = format!("stage {state:?} fault {fault:?}");
            assert_eq!(observed, expected_obs, "{case}");
            assert_eq!(snapshot_share(&db).await, expected_post, "{case}");
            assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
            counts.case(fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn share_stage_account_matches_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    for state in share_model(&share_states()) {
        counts.states += 1;
        for fault in faults(1) {
            load_share(&db, &state).await;
            let mut io = super::PutShareIo::for_conformance(
                Faulty::new(PoolSql(&db), fault),
                s(user(0)),
                t(SHARE),
                t(SPLIT),
                t(AUTH),
            );
            let observed = io.stage_query_account().await;
            let expected = model::stage_account(&state, &s(user(0)), SHARE, SPLIT, fault.is_some());
            let case = format!("stage account {state:?} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
            counts.case(fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn share_finalize_matches_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    for state in share_model(&share_states()) {
        counts.states += 1;
        for fault in faults(1) {
            load_share(&db, &state).await;
            let mut io = super::FinalizeShareIo::for_conformance(
                Faulty::new(PoolSql(&db), fault),
                s(user(0)),
                t(SPLIT),
            );
            let observed = io.promote_staged_split(finalize_permit(7)).await;
            let expected = model::promote_staged_split(&state, &s(user(0)), 7, SPLIT, fault);
            let (expected_obs, expected_post) = match expected {
                Some((obs, post)) => (Some(obs), post),
                None => (None, state.clone()),
            };
            let case = format!("finalize {state:?} fault {fault:?}");
            assert_eq!(observed, expected_obs, "{case}");
            assert_eq!(snapshot_share(&db).await, expected_post, "{case}");
            assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
            counts.case(fault);
        }
        for fault in faults(1) {
            load_share(&db, &state).await;
            let mut io = super::FinalizeShareIo::for_conformance(
                Faulty::new(PoolSql(&db), fault),
                s(user(0)),
                t(SPLIT),
            );
            let observed = io.finalize_query_account().await;
            let expected =
                model::finalize_account(&state, &s(user(0)), SPLIT, fault.is_some());
            let case = format!("finalize account {state:?} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
            counts.case(fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn share_delete_matches_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    for state in share_model(&share_states()) {
        counts.states += 1;
        for fault in faults(1) {
            load_share(&db, &state).await;
            let mut io = super::DeleteShareIo::for_conformance(
                Faulty::new(PoolSql(&db), fault),
                s(user(0)),
            );
            let observed = io.delete_share(delete_permit(7)).await;
            let expected = model::delete_share(&state, &s(user(0)), 7, fault);
            let (expected_obs, expected_post) = match expected {
                Some((obs, post)) => (Some(obs), post),
                None => (None, state.clone()),
            };
            let case = format!("delete {state:?} fault {fault:?}");
            assert_eq!(observed, expected_obs, "{case}");
            assert_eq!(snapshot_share(&db).await, expected_post, "{case}");
            assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
            counts.case(fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn share_read_matches_the_store_model() {
    let db = temp_db().await;
    let mut counts = Counts::default();
    for state in share_model(&share_states()) {
        counts.states += 1;
        for fault in faults(1) {
            load_share(&db, &state).await;
            let mut io = super::GetShareIo::for_conformance(
                Faulty::new(PoolSql(&db), fault),
                s(user(0)),
            );
            let observed = io.read_share().await;
            let expected = model::read_share(&state, &s(user(0)), fault.is_some());
            let case = format!("read {state:?} fault {fault:?}");
            assert_eq!(observed, expected, "{case}");
            if fault.is_none() {
                let row = state.users.get(&s(user(0)));
                match row.and_then(|row| row.share.as_ref()) {
                    Some(share) => {
                        assert_eq!(io.share_bytes().to_vec(), crate::db::decode_b64(share).unwrap(), "{case}");
                        assert_eq!(io.split_id(), row.and_then(|row| row.split.as_ref()), "{case}");
                        assert_eq!(io.key_epoch(), row.map(|row| row.epoch.max(1)).unwrap_or(1), "{case}");
                    }
                    None => {
                        assert!(io.share_bytes().is_empty(), "{case}");
                        assert!(io.split_id().is_none(), "{case}");
                        assert_eq!(io.key_epoch(), 1, "{case}");
                    }
                }
            }
            assert_eq!(io.error_is_set(), fault.is_some(), "{case}");
            counts.case(fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}
