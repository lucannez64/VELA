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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};
use vela_recovery_policy::driver::{
    AuthorityRecheckObservation, ConsumptionObservation, InsertObservation, RedemptionInsertPermit,
};
use vela_recovery_policy::possession_driver::{
    CommitmentObservation, ProofGrantPermit,
};
use vela_recovery_policy::possession_store::{EnrollmentGrantView, ProofAttemptView};
use vela_recovery_policy::redemption_model::{
    self as model, AttemptCell, Db as Model, DeviceRow, PossessionDb, PossessionUserRow, ShareDb,
    ShareUserRow, UserRow,
};
use vela_recovery_policy::redemption_store::{self, GrantGuard, GrantView};
use vela_recovery_policy::webauthn_store::CredentialGrantView;
use vela_recovery_policy::recovery_share_driver::{
    begin_share_lifecycle, ShareActorObservation, ShareEffect, ShareOperation,
    ShareRequestObservation,
};

use super::enroll_device::EnrollDeviceIo;
use super::recover::RecoveryEnrollGrant;
use super::sql::{PoolSql, RecoveryKv, RecoverySql, StoreKv};
use crate::error::{AppError, Result};
use crate::state::AppState;
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

    fn exists(&mut self, key: &str) -> Result<bool> {
        self.hit()?;
        self.inner.exists(key)
    }

    fn set_nx(&mut self, key: &str, value: &[u8], ttl_secs: u64) -> Result<bool> {
        self.hit()?;
        self.inner.set_nx(key, value, ttl_secs)
    }

    fn set_ex(&mut self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        self.hit()?;
        self.inner.set_ex(key, value, ttl_secs)
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

// ── Possession executor conformance ────────────────────────────────────────

fn possession_commitment(value: Option<&str>) -> CommitmentObservation {
    match value {
        Some(text) => match crate::db::decode_b64(text) {
            Ok(bytes) => CommitmentObservation::Present { len: bytes.len() },
            Err(_) => CommitmentObservation::Corrupt,
        },
        None => CommitmentObservation::Missing,
    }
}

async fn snapshot_possession(
    db: &TursoDb,
    store: &crate::store::Store,
    slots: &[String],
    grant_keys: &[String],
) -> PossessionDb {
    let mut state = PossessionDb::default();
    for row in db
        .query(
            "SELECT id, key_epoch, rekey_state, recovery_share, recovery_auth_hash FROM users",
            vec![],
        )
        .await
        .unwrap()
    {
        state.users.insert(
            text(&row, 0),
            PossessionUserRow {
                share: row.text(3).is_some(),
                commitment: possession_commitment(row.text(4)),
                epoch: row.i64(1),
                rekey: row.text(2).is_some(),
            },
        );
    }
    for key in slots {
        if let Some(bytes) = store.get(key).unwrap() {
            state.challenges.insert(
                key.clone(),
                match serde_json::from_slice::<super::possess::PossessionProofState>(&bytes) {
                    Ok(envelope) => AttemptCell::Valid(ProofAttemptView {
                        user: envelope.user_id.to_string(),
                        attempt: envelope.recovery_id.to_string(),
                        key_epoch: envelope.key_epoch,
                    }),
                    Err(_) => AttemptCell::Undecodable,
                },
            );
        }
    }
    for key in grant_keys {
        if let Some(bytes) = store.get(key).unwrap() {
            let grant = super::recover::decode_enroll_grant(&bytes).expect("stored grant decodes");
            state
                .grants
                .insert(key.clone(), EnrollmentGrantView { key_epoch: grant.key_epoch });
        }
    }
    state
}

async fn load_possession(
    db: &TursoDb,
    store: &crate::store::Store,
    state: &PossessionDb,
    slots: &[String],
    grant_keys: &[String],
) {
    db.execute_batch("DELETE FROM users;").await.unwrap();
    for (id, row) in &state.users {
        db.execute(
            "INSERT INTO users (id, created_at, key_epoch, rekey_state, recovery_share, recovery_auth_hash)
             VALUES (?, 't', ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                row.epoch.map(TursoValue::Integer).unwrap_or(TursoValue::Null),
                if row.rekey {
                    TursoValue::Text("rotating".into())
                } else {
                    TursoValue::Null
                },
                if row.share {
                    TursoValue::Text("c2hhcmU=".into())
                } else {
                    TursoValue::Null
                },
                match row.commitment {
                    CommitmentObservation::Missing => TursoValue::Null,
                    CommitmentObservation::Present { .. } => TursoValue::Text("AQID".into()),
                    CommitmentObservation::Corrupt => TursoValue::Text("!!!".into()),
                },
            ],
        )
        .await
        .unwrap();
    }
    for key in slots {
        store.del(key).unwrap();
        if let Some(cell) = state.challenges.get(key) {
            let bytes = match cell {
                AttemptCell::Valid(view) => serde_json::to_vec(&super::possess::PossessionProofState {
                    user_id: Uuid::parse_str(&view.user).expect("seeded user id"),
                    recovery_id: Uuid::parse_str(&view.attempt).expect("seeded attempt id"),
                    challenge: vec![9u8; 32],
                    key_epoch: view.key_epoch,
                })
                .unwrap(),
                AttemptCell::Undecodable => b"not a proof state".to_vec(),
            };
            store.set_ex(key, &bytes, 300).unwrap();
        }
    }
    for key in grant_keys {
        store.del(key).unwrap();
        if let Some(grant) = state.grants.get(key) {
            let bytes = serde_json::to_vec(&super::recover::RecoveryEnrollGrant::from_possession_proof(
                grant.key_epoch,
            ))
            .unwrap();
            store.set(key, &bytes).unwrap();
        }
    }
}

fn possession_user(
    share: bool,
    commitment: CommitmentObservation,
    epoch: i64,
    rekey: bool,
) -> PossessionUserRow {
    PossessionUserRow {
        share,
        commitment,
        epoch: Some(epoch),
        rekey,
    }
}

fn possession_user_states() -> Vec<Option<PossessionUserRow>> {
    vec![
        None,
        Some(possession_user(true, CommitmentObservation::Present { len: 3 }, 7, false)),
        Some(possession_user(true, CommitmentObservation::Present { len: 3 }, 8, false)),
        Some(possession_user(true, CommitmentObservation::Present { len: 3 }, 7, true)),
        Some(possession_user(false, CommitmentObservation::Present { len: 3 }, 7, false)),
        Some(possession_user(true, CommitmentObservation::Missing, 7, false)),
        Some(possession_user(true, CommitmentObservation::Corrupt, 7, false)),
    ]
}

fn possession_db(
    user_row: &Option<PossessionUserRow>,
    challenge: Option<AttemptCell>,
    grant: Option<EnrollmentGrantView>,
) -> PossessionDb {
    let mut state = PossessionDb::default();
    if let Some(row) = user_row {
        state.users.insert(s(user(0)), row.clone());
    }
    if let Some(cell) = challenge {
        state.challenges.insert(slot_key(), cell);
    }
    if let Some(value) = grant {
        state.grants.insert(grant_key_text(), value);
    }
    state
}

fn slot_key() -> String {
    format!("recovery:possession:{}:{}", s(user(0)), s(recovery_id()))
}

fn grant_key_text() -> String {
    format!("recovery:enroll_grant:{}:{}", s(user(0)), s(grant(0)))
}

fn recovery_id() -> Uuid {
    Uuid::from_u128(0x4000)
}

fn proof_attempt(user: &str, attempt: &str, epoch: i64) -> ProofAttemptView {
    ProofAttemptView {
        user: t(user),
        attempt: t(attempt),
        key_epoch: epoch,
    }
}

#[tokio::test]
async fn possession_initiation_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let slots = vec![slot_key()];
    let grants = vec![grant_key_text()];

    for row_state in possession_user_states() {
        counts.states += 1;
        for challenge in [None, Some(AttemptCell::Valid(proof_attempt(&s(user(0)), &s(recovery_id()), 7)))] {
            for sql_fault in faults(1) {
                for kv_fault in faults(1) {
                    let state = possession_db(&row_state, challenge.clone(), None);
                    load_possession(&db, &store, &state, &slots, &grants).await;
                    let mut io = super::possess::InitiateProofIo::for_conformance(
                        Faulty::new(PoolSql(&db), sql_fault),
                        FaultyKv::new(StoreKv(&store), kv_fault),
                        user(0),
                        recovery_id(),
                        1,
                    );
                    let observed = io.observe().await;
                    let expected = model::initiate_observation(
                        &state,
                        &s(user(0)),
                        &slot_key(),
                        300,
                        sql_fault,
                        kv_fault,
                    );
                    let case = format!(
                        "possession initiate {state:?} sql {sql_fault:?} kv {kv_fault:?}"
                    );
                    assert_eq!(
                        observed,
                        expected.as_ref().map(|(obs, _)| *obs),
                        "{case}"
                    );
                    assert_eq!(
                        snapshot_possession(&db, &store, &slots, &grants).await,
                        expected.clone().map(|(_, post)| post).unwrap_or_else(|| state.clone()),
                        "{case}"
                    );
                    assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
                    assert_eq!(
                        io.key_epoch(),
                        model::initiate_epoch_of(&state, &s(user(0)), sql_fault.is_some()),
                        "{case}"
                    );
                    counts.case(sql_fault.or(kv_fault));
                }
            }
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn possession_challenge_store_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let slots = vec![slot_key()];
    let grants = vec![grant_key_text()];
    let drawn = proof_attempt(&s(user(0)), &s(recovery_id()), 7);

    for challenge in [
        None,
        Some(AttemptCell::Valid(proof_attempt(&s(user(0)), &s(recovery_id()), 7))),
        Some(AttemptCell::Undecodable),
    ] {
        counts.states += 1;
        for kv_fault in faults(1) {
            let state = possession_db(&None, challenge.clone(), None);
            load_possession(&db, &store, &state, &slots, &grants).await;
            let mut io = super::possess::InitiateProofIo::for_conformance(
                Faulty::new(PoolSql(&db), None),
                FaultyKv::new(StoreKv(&store), kv_fault),
                user(0),
                recovery_id(),
                7,
            );
            let observed = io.store_challenge().await;
            let expected = model::store_challenge(
                &state,
                &slot_key(),
                "{\"challenge\":[9,9,9]}",
                &drawn,
                300,
                kv_fault,
            );
            let case = format!("possession challenge {state:?} kv {kv_fault:?}");
            assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
            assert_eq!(
                snapshot_possession(&db, &store, &slots, &grants).await,
                expected.clone().map(|(_, post)| post).unwrap_or_else(|| state.clone()),
                "{case}"
            );
            assert_eq!(io.error_is_set(), kv_fault.is_some(), "{case}");
            assert_eq!(io.challenge().is_some(), kv_fault.is_none(), "{case}");
            counts.case(kv_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn possession_attempt_consumption_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let slots = vec![slot_key()];
    let grants = vec![grant_key_text()];

    let challenges = [
        None,
        Some(AttemptCell::Valid(proof_attempt(&s(user(0)), &s(recovery_id()), 7))),
        Some(AttemptCell::Valid(proof_attempt(&s(user(0)), &s(recovery_id()), 8))),
        Some(AttemptCell::Valid(proof_attempt(&s(user(1)), &s(recovery_id()), 7))),
        Some(AttemptCell::Valid(proof_attempt(
            &s(user(0)),
            &s(Uuid::from_u128(0x5000)),
            7,
        ))),
        Some(AttemptCell::Undecodable),
    ];
    for challenge in challenges {
        counts.states += 1;
        for kv_fault in faults(1) {
            let state = possession_db(&None, challenge.clone(), None);
            load_possession(&db, &store, &state, &slots, &grants).await;
            let mut io = super::possess::RecoverProofIo::for_conformance(
                &store,
                Faulty::new(PoolSql(&db), None),
                FaultyKv::new(StoreKv(&store), kv_fault),
                user(0),
                recovery_id(),
                "AAAA".into(),
            );
            let observed = io.consume_attempt().await;
            let expected = model::take_attempt(
                &state,
                &slot_key(),
                &s(user(0)),
                &s(recovery_id()),
                kv_fault,
            );
            let case = format!("possession attempt {state:?} kv {kv_fault:?}");
            assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
            assert_eq!(
                snapshot_possession(&db, &store, &slots, &grants).await,
                expected.clone().map(|(_, post)| post).unwrap_or_else(|| state.clone()),
                "{case}"
            );
            assert_eq!(io.error_is_set(), kv_fault.is_some(), "{case}");
            assert_eq!(
                io.attempt_decode_error_is_set(),
                matches!(challenge, Some(AttemptCell::Undecodable)) && kv_fault.is_none(),
                "{case}"
            );
            counts.case(kv_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn possession_proof_account_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let slots = vec![slot_key()];
    let grants = vec![grant_key_text()];

    for row_state in possession_user_states() {
        counts.states += 1;
        for sql_fault in faults(1) {
            let state = possession_db(&row_state, None, None);
            load_possession(&db, &store, &state, &slots, &grants).await;
            let mut io = super::possess::RecoverProofIo::for_conformance(
                &store,
                Faulty::new(PoolSql(&db), sql_fault),
                FaultyKv::new(StoreKv(&store), None),
                user(0),
                recovery_id(),
                "AAAA".into(),
            );
            let observed = io.query_account().await;
            let expected = model::proof_account(&state, &s(user(0)), sql_fault);
            let case = format!("possession account {state:?} sql {sql_fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error_is_set(), sql_fault.is_some(), "{case}");
            assert_eq!(
                io.commitment_bytes().is_some(),
                expected.is_some_and(|obs| {
                    obs.commitment == CommitmentObservation::Present { len: 3 }
                }),
                "{case}"
            );
            counts.case(sql_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn possession_grant_store_matches_the_store_model() {
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let slots = vec![slot_key()];
    let grants = vec![grant_key_text()];
    let issued = EnrollmentGrantView { key_epoch: 7 };
    let state = possession_db(&None, None, None);

    for stored in [false, true] {
        counts.states += 1;
        for kv_fault in faults(1) {
            let mut pre = state.clone();
            if stored {
                pre.grants
                    .insert(grant_key_text(), EnrollmentGrantView { key_epoch: 3 });
            }
            load_possession(&db, &store, &pre, &slots, &grants).await;
            let mut io = super::possess::RecoverProofIo::for_conformance(
                &store,
                Faulty::new(PoolSql(&db), None),
                FaultyKv::new(StoreKv(&store), kv_fault),
                user(0),
                recovery_id(),
                "AAAA".into(),
            );
            let observed = io
                .issue_grant(ProofGrantPermit { epoch: 7 })
                .await;
            let (expected, post) = model::issue_grant(
                &pre,
                &grant_key_text(),
                "",
                &issued,
                600,
                kv_fault,
            );
            let case = format!("possession grant stored {stored} kv {kv_fault:?}");
            assert_eq!(observed, Some(expected), "{case}");
            assert_eq!(
                snapshot_possession(&db, &store, &slots, &grants).await,
                post,
                "{case}"
            );
            assert_eq!(io.grant_error_is_set(), kv_fault.is_some(), "{case}");
            counts.case(kv_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

// ── WebAuthn executor conformance ──────────────────────────────────────────

/// A fixed attempt id so the exact challenge slot is predictable.
fn attempt_id() -> Uuid {
    Uuid::from_u128(0x4000)
}

/// A base64 credential id the `users.recovery_webauthn_credential` cell can
/// decode to.
fn cred_id(n: u8) -> String {
    B64.encode([n; 16])
}

/// A real `Passkey` whose credential id is exactly `credential_id`, built from
/// the public credential types so the stored JSON decodes through the same
/// path the handlers use.
fn build_credential(credential_id: &str) -> webauthn_rs_core::proto::Credential {
    use webauthn_rs::prelude::{
        COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, CredentialID, ECDSACurve,
        ParsedAttestation, ParsedAttestationData,
    };
    let raw = B64.decode(credential_id).expect("seeded credential id is base64");
    webauthn_rs_core::proto::Credential {
        cred_id: CredentialID::from(raw),
        cred: COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: CredentialID::from(vec![2u8; 32]),
                y: CredentialID::from(vec![3u8; 32]),
            }),
        },
        counter: 0,
        transports: None,
        user_verified: true,
        backup_eligible: false,
        backup_state: false,
        registration_policy: webauthn_rs_core::proto::UserVerificationPolicy::Required,
        extensions: webauthn_rs_core::proto::RegisteredExtensions::none(),
        attestation: ParsedAttestation {
            data: ParsedAttestationData::None,
            metadata: webauthn_rs_core::proto::AttestationMetadata::None,
        },
        attestation_format: webauthn_rs::prelude::AttestationFormat::None,
    }
}

fn stored_passkey(credential_id: &str) -> Passkey {
    let credential = serde_json::to_value(build_credential(credential_id)).unwrap();
    serde_json::from_value(serde_json::json!({ "cred": credential }))
        .expect("a built credential deserialises as a passkey")
}

/// A real authentication state bound to the seeded credential.
fn stored_auth_state(app: &AppState, credential_id: &str) -> PasskeyAuthentication {
    app.webauthn
        .start_passkey_authentication(&[stored_passkey(credential_id)])
        .expect("the seeded credential starts an authentication ceremony")
        .1
}

/// A real registration ceremony state.
fn stored_registration_state(app: &AppState) -> PasskeyRegistration {
    app.webauthn
        .start_passkey_registration(user(0), "conformance", "conformance", None)
        .expect("a registration ceremony starts")
        .1
}

/// A standalone `AppState` for the handlers' ceremony and limiter fields; the
/// conformance test always injects its own faulted SQL and store handles.
async fn temp_app_state() -> AppState {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "{}/vela-recovery-webauthn-{}-{}.db",
        std::env::temp_dir().display(),
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    let turso = std::sync::Arc::new(TursoDb::open(&path, 1).await.unwrap());
    let store = crate::store::Store::open_temp().unwrap();
    let cfg = crate::config::Config::from_env().expect("default config");
    std::sync::Arc::new(crate::state::AppStateInner::new(turso, store, cfg).await.unwrap())
}

fn webauthn_attempt_key() -> String {
    vela_recovery_policy::webauthn_store::auth_state_key(&s(user(0)), &s(attempt_id()))
}

fn webauthn_registration_key() -> String {
    vela_recovery_policy::webauthn_store::registration_state_key(&s(user(0)))
}

fn webauthn_grant_key() -> String {
    super::recover::enroll_grant_key(user(0), grant(0))
}

fn webauthn_attempt_view(credential_id: &str) -> vela_recovery_policy::webauthn_store::AuthStateView {
    vela_recovery_policy::webauthn_store::AuthStateView {
        user: s(user(0)),
        attempt: s(attempt_id()),
        credential_id: credential_id.to_string(),
    }
}

fn webauthn_user_row(
    share: Option<&str>,
    credential: model::CredentialCell,
    credential_id: Option<&str>,
    epoch: Option<i64>,
    rekey: bool,
    split: Option<&str>,
) -> model::WebAuthnUserRow {
    model::WebAuthnUserRow {
        share: share.map(t),
        credential,
        credential_id: credential_id.map(t),
        epoch,
        rekey,
        split: split.map(t),
    }
}

fn webauthn_user_states() -> Vec<Option<model::WebAuthnUserRow>> {
    let cred = cred_id(0);
    let other = cred_id(1);
    vec![
        None,
        Some(webauthn_user_row(
            Some("c2hhcmU="),
            model::CredentialCell::Valid(cred.clone()),
            Some(&cred),
            Some(7),
            false,
            Some("split"),
        )),
        Some(webauthn_user_row(
            None,
            model::CredentialCell::Valid(cred.clone()),
            Some(&cred),
            Some(7),
            false,
            None,
        )),
        Some(webauthn_user_row(
            Some("c2hhcmU="),
            model::CredentialCell::Absent,
            None,
            Some(7),
            false,
            None,
        )),
        Some(webauthn_user_row(
            Some("c2hhcmU="),
            model::CredentialCell::Undecodable,
            None,
            Some(7),
            false,
            None,
        )),
        Some(webauthn_user_row(
            Some("c2hhcmU="),
            model::CredentialCell::Valid(other),
            Some(&cred),
            Some(7),
            false,
            None,
        )),
        Some(webauthn_user_row(
            Some("c2hhcmU="),
            model::CredentialCell::Valid(cred.clone()),
            Some(&cred),
            Some(7),
            true,
            None,
        )),
        Some(webauthn_user_row(
            Some("c2hhcmU="),
            model::CredentialCell::Valid(cred.clone()),
            Some(&cred),
            Some(8),
            false,
            None,
        )),
        Some(webauthn_user_row(
            Some("!!!"),
            model::CredentialCell::Valid(cred),
            Some(&cred_id(0)),
            Some(7),
            false,
            None,
        )),
    ]
}

fn webauthn_db(
    user_row: &Option<model::WebAuthnUserRow>,
    attempt: Option<model::WebAuthnAttemptCell>,
    registration: Option<model::WebAuthnRegistrationCell>,
    grant: Option<CredentialGrantView>,
) -> model::WebAuthnDb {
    let mut state = model::WebAuthnDb::default();
    if let Some(row) = user_row {
        state.users.insert(s(user(0)), row.clone());
        if let Some(credential_id) = &row.credential_id {
            state.holders.insert(credential_id.clone(), s(user(0)));
        }
    }
    if let Some(cell) = attempt {
        state.attempts.insert(webauthn_attempt_key(), cell);
    }
    if let Some(cell) = registration {
        state.registrations.insert(webauthn_registration_key(), cell);
    }
    if let Some(value) = grant {
        state.grants.insert(webauthn_grant_key(), value);
    }
    state
}

async fn load_webauthn(
    app: &AppState,
    db: &TursoDb,
    store: &crate::store::Store,
    state: &model::WebAuthnDb,
) {
    db.execute_batch("DELETE FROM users;").await.unwrap();
    for (id, row) in &state.users {
        let (credential, stored_id) = match &row.credential {
            model::CredentialCell::Absent => (TursoValue::Null, opt(&row.credential_id)),
            model::CredentialCell::Valid(credential_id) => (
                TursoValue::Text(
                    serde_json::to_string(&stored_passkey(credential_id)).unwrap(),
                ),
                opt(&row.credential_id),
            ),
            model::CredentialCell::Undecodable => (
                TursoValue::Text("not a stored passkey".into()),
                opt(&row.credential_id),
            ),
        };
        db.execute(
            "INSERT INTO users (id, created_at, recovery_share, recovery_webauthn_credential,
                                recovery_webauthn_cred_id, key_epoch, rekey_state, recovery_split_id)
             VALUES (?, 't', ?, ?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(id.clone()),
                opt(&row.share),
                credential,
                stored_id,
                row.epoch.map(TursoValue::Integer).unwrap_or(TursoValue::Null),
                if row.rekey {
                    TursoValue::Text("rotating".into())
                } else {
                    TursoValue::Null
                },
                opt(&row.split),
            ],
        )
        .await
        .unwrap();
    }
    let key = webauthn_attempt_key();
    store.del(&key).unwrap();
    if let Some(cell) = state.attempts.get(&key) {
        let bytes = match cell {
            model::WebAuthnAttemptCell::Valid(view) => {
                let envelope = super::initiate::RecoveryAuthState {
                    user_id: Uuid::parse_str(&view.user).expect("seeded user id"),
                    recovery_id: Uuid::parse_str(&view.attempt).expect("seeded attempt id"),
                    credential_id: view.credential_id.clone(),
                    auth_state: stored_auth_state(app, &view.credential_id),
                };
                serde_json::to_vec(&envelope).unwrap()
            }
            model::WebAuthnAttemptCell::Undecodable => b"not an attempt envelope".to_vec(),
            model::WebAuthnAttemptCell::Absent => Vec::new(),
        };
        if !matches!(cell, model::WebAuthnAttemptCell::Absent) {
            store.set_ex(&key, &bytes, 300).unwrap();
        }
    }
    let key = webauthn_registration_key();
    store.del(&key).unwrap();
    if let Some(cell) = state.registrations.get(&key) {
        let bytes = match cell {
            model::WebAuthnRegistrationCell::Valid => {
                serde_json::to_vec(&stored_registration_state(app)).unwrap()
            }
            model::WebAuthnRegistrationCell::Undecodable => b"not a registration state".to_vec(),
            model::WebAuthnRegistrationCell::Absent => Vec::new(),
        };
        if !matches!(cell, model::WebAuthnRegistrationCell::Absent) {
            store.set_ex(&key, &bytes, 300).unwrap();
        }
    }
    let key = webauthn_grant_key();
    store.del(&key).unwrap();
    if let Some(grant) = state.grants.get(&key) {
        store
            .set(
                &key,
                &serde_json::to_vec(&super::recover::RecoveryEnrollGrant {
                    key_epoch: grant.key_epoch,
                    credential_id: grant.credential_id.clone(),
                    possession: grant.possession,
                })
                .unwrap(),
            )
            .unwrap();
    }
}

async fn snapshot_webauthn(
    db: &TursoDb,
    store: &crate::store::Store,
) -> model::WebAuthnDb {
    let mut state = model::WebAuthnDb::default();
    for row in db
        .query(
            "SELECT id, recovery_share, recovery_webauthn_credential,
                    recovery_webauthn_cred_id, key_epoch, rekey_state, recovery_split_id
             FROM users",
            vec![],
        )
        .await
        .unwrap()
    {
        let id = text(&row, 0);
        let credential = match row.get(2) {
            Some(TursoValue::Null) | None => model::CredentialCell::Absent,
            Some(TursoValue::Text(passkey_json)) => {
                match serde_json::from_str::<Passkey>(passkey_json) {
                    Ok(passkey) => model::CredentialCell::Valid(super::webauthn::cred_id_b64(&passkey)),
                    Err(_) => model::CredentialCell::Undecodable,
                }
            }
            _ => model::CredentialCell::Undecodable,
        };
        let credential_id = row.text(3).map(String::from);
        if let Some(credential_id) = &credential_id {
            state.holders.insert(credential_id.clone(), id.clone());
        }
        state.users.insert(
            id,
            model::WebAuthnUserRow {
                share: row.text(1).map(String::from),
                credential,
                credential_id,
                epoch: row.i64(4),
                rekey: row.text(5).is_some(),
                split: row.text(6).map(String::from),
            },
        );
    }
    let key = webauthn_attempt_key();
    let cell = match store.get(&key).unwrap() {
        None => model::WebAuthnAttemptCell::Absent,
        Some(bytes) => match serde_json::from_slice::<super::initiate::RecoveryAuthState>(&bytes) {
            Ok(envelope) => model::WebAuthnAttemptCell::Valid(
                vela_recovery_policy::webauthn_store::AuthStateView {
                    user: envelope.user_id.to_string(),
                    attempt: envelope.recovery_id.to_string(),
                    credential_id: envelope.credential_id.clone(),
                },
            ),
            Err(_) => model::WebAuthnAttemptCell::Undecodable,
        },
    };
    if !matches!(cell, model::WebAuthnAttemptCell::Absent) {
        state.attempts.insert(key, cell);
    }
    let key = webauthn_registration_key();
    let cell = match store.get(&key).unwrap() {
        None => model::WebAuthnRegistrationCell::Absent,
        Some(bytes) => match serde_json::from_slice::<PasskeyRegistration>(&bytes) {
            Ok(_) => model::WebAuthnRegistrationCell::Valid,
            Err(_) => model::WebAuthnRegistrationCell::Undecodable,
        },
    };
    if !matches!(cell, model::WebAuthnRegistrationCell::Absent) {
        state.registrations.insert(key, cell);
    }
    let key = webauthn_grant_key();
    if let Some(bytes) = store.get(&key).unwrap() {
        let grant = super::recover::decode_enroll_grant(&bytes).expect("stored grant decodes");
        state.grants.insert(
            key,
            CredentialGrantView {
                key_epoch: grant.key_epoch,
                credential_id: grant.credential_id.clone(),
                possession: grant.possession,
            },
        );
    }
    state
}

/// `snapshot_webauthn` records the full model; a single-method test only
/// changes the keys it touches, so compare those.
fn webauthn_grant_of(db: &model::WebAuthnDb) -> Option<CredentialGrantView> {
    db.grants.get(&webauthn_grant_key()).cloned()
}

#[tokio::test]
async fn webauthn_initiation_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let drawn = attempt_id();

    for row_state in webauthn_user_states() {
        counts.states += 1;
        for attempt in [
            None,
            Some(model::WebAuthnAttemptCell::Valid(webauthn_attempt_view(
                &cred_id(0),
            ))),
            Some(model::WebAuthnAttemptCell::Undecodable),
        ] {
            for sql_fault in faults(2) {
                for kv_fault in faults(1) {
                    let state = webauthn_db(&row_state, attempt.clone(), None, None);
                    load_webauthn(&app, &db, &store, &state).await;
                    let mut io = super::initiate::InitiateIo::for_conformance(
                        &app,
                        Faulty::new(PoolSql(&db), sql_fault),
                        FaultyKv::new(StoreKv(&store), kv_fault),
                        user(0),
                        drawn,
                    );
                    let observed = io.auth_start_observe().await;
                    let expected = model::auth_start_observe(
                        &state,
                        &s(user(0)),
                        &webauthn_attempt_key(),
                        300,
                        sql_fault,
                        kv_fault,
                    );
                    let case =
                        format!("webauthn initiate {state:?} sql {sql_fault:?} kv {kv_fault:?}");
                    assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
                    assert_eq!(
                        snapshot_webauthn(&db, &store).await,
                        expected
                            .clone()
                            .map(|(_, post)| post)
                            .unwrap_or_else(|| state.clone()),
                        "{case}"
                    );
                    assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
                    assert_eq!(
                        io.recovery_id(),
                        expected.as_ref().map(|_| drawn),
                        "{case}"
                    );
                    counts.case(sql_fault.or(kv_fault));
                }
            }
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn webauthn_challenge_store_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let view = webauthn_attempt_view(&cred_id(0));

    for attempt in [
        None,
        Some(model::WebAuthnAttemptCell::Valid(webauthn_attempt_view(
            &cred_id(0),
        ))),
        Some(model::WebAuthnAttemptCell::Undecodable),
    ] {
        counts.states += 1;
        for kv_fault in faults(1) {
            let state = webauthn_db(&None, attempt.clone(), None, None);
            load_webauthn(&app, &db, &store, &state).await;
            let mut io = super::initiate::InitiateIo::for_conformance(
                &app,
                Faulty::new(PoolSql(&db), None),
                FaultyKv::new(StoreKv(&store), kv_fault),
                user(0),
                attempt_id(),
            );
            io.set_recovery_id(attempt_id());
            let value = serde_json::to_string(&super::initiate::RecoveryAuthState {
                user_id: user(0),
                recovery_id: attempt_id(),
                credential_id: cred_id(0),
                auth_state: stored_auth_state(&app, &cred_id(0)),
            })
            .unwrap();
            let observed = io.write_auth_state(value.clone(), view.clone()).await;
            let expected = model::store_auth_state(
                &state,
                &webauthn_attempt_key(),
                &value,
                &view,
                300,
                kv_fault,
            );
            let case = format!("webauthn store {state:?} kv {kv_fault:?}");
            assert_eq!(observed, Some(expected.0), "{case}");
            assert_eq!(snapshot_webauthn(&db, &store).await, expected.1, "{case}");
            counts.case(kv_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn webauthn_context_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();

    for row_state in webauthn_user_states() {
        counts.states += 1;
        for attempt_present in [false, true] {
            for sql_fault in faults(2) {
                let state = webauthn_db(&row_state, None, None, None);
                load_webauthn(&app, &db, &store, &state).await;
                let mut io = super::recover::RecoverIo::for_conformance(
                    &app,
                    Faulty::new(PoolSql(&db), sql_fault),
                    FaultyKv::new(StoreKv(&store), None),
                    user(0),
                    attempt_present.then(attempt_id),
                    Some(cred_id(0)),
                    None,
                    None,
                    None,
                    None,
                );
                let observed = io.auth_finish_context().await;
                let expected = model::finish_context(
                    &state,
                    &s(user(0)),
                    attempt_present,
                    sql_fault,
                );
                let case = format!("webauthn context {state:?} sql {sql_fault:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
                counts.case(sql_fault);
            }
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn webauthn_attempt_consumption_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();

    for attempt in [
        None,
        Some(model::WebAuthnAttemptCell::Valid(webauthn_attempt_view(
            &cred_id(0),
        ))),
        Some(model::WebAuthnAttemptCell::Valid(webauthn_attempt_view(
            &cred_id(1),
        ))),
        Some(model::WebAuthnAttemptCell::Undecodable),
    ] {
        counts.states += 1;
        for observed_credential in [cred_id(0), cred_id(1)] {
            for kv_fault in faults(1) {
                let state = webauthn_db(&None, attempt.clone(), None, None);
                load_webauthn(&app, &db, &store, &state).await;
                let mut io = super::recover::RecoverIo::for_conformance(
                    &app,
                    Faulty::new(PoolSql(&db), None),
                    FaultyKv::new(StoreKv(&store), kv_fault),
                    user(0),
                    Some(attempt_id()),
                    Some(observed_credential.clone()),
                    None,
                    None,
                    None,
                    None,
                );
                let observed = io.auth_finish_consume().await;
                let expected = model::take_auth_state(
                    &state,
                    &webauthn_attempt_key(),
                    &s(user(0)),
                    &s(attempt_id()),
                    &observed_credential,
                    kv_fault,
                );
                let case = format!(
                    "webauthn consume {state:?} credential {observed_credential} kv {kv_fault:?}"
                );
                assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
                assert_eq!(
                    snapshot_webauthn(&db, &store).await,
                    expected
                        .clone()
                        .map(|(_, post)| post)
                        .unwrap_or_else(|| state.clone()),
                    "{case}"
                );
                assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
                counts.case(kv_fault);
            }
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn webauthn_credential_update_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let new_id = cred_id(2);

    for row_state in webauthn_user_states() {
        counts.states += 1;
        for expected_id in [cred_id(0), cred_id(1)] {
            for sql_fault in faults(1) {
                let state = webauthn_db(&row_state, None, None, None);
                load_webauthn(&app, &db, &store, &state).await;
                let mut io = super::recover::RecoverIo::for_conformance(
                    &app,
                    Faulty::new(PoolSql(&db), sql_fault),
                    FaultyKv::new(StoreKv(&store), None),
                    user(0),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                );
                let credential = serde_json::to_string(&stored_passkey(&new_id)).unwrap();
                let observed = io
                    .write_updated_credential(expected_id.clone(), credential, new_id.clone())
                    .await;
                let expected = model::update_credential(
                    &state,
                    &s(user(0)),
                    &expected_id,
                    "{}",
                    &new_id,
                    sql_fault,
                );
                let case =
                    format!("webauthn update {state:?} expected {expected_id} sql {sql_fault:?}");
                assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
                assert_eq!(
                    snapshot_webauthn(&db, &store).await,
                    expected
                        .clone()
                        .map(|(_, post)| post)
                        .unwrap_or_else(|| state.clone()),
                    "{case}"
                );
                assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
                counts.case(sql_fault);
            }
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn webauthn_account_and_release_match_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();

    for row_state in webauthn_user_states() {
        counts.states += 1;
        for credential_id in [cred_id(0), cred_id(1)] {
            for sql_fault in faults(1) {
                let state = webauthn_db(&row_state, None, None, None);
                load_webauthn(&app, &db, &store, &state).await;
                let mut io = super::recover::RecoverIo::for_conformance(
                    &app,
                    Faulty::new(PoolSql(&db), sql_fault),
                    FaultyKv::new(StoreKv(&store), None),
                    user(0),
                    None,
                    None,
                    Some(credential_id.clone()),
                    None,
                    Some(1),
                    None,
                );
                let observed = io.auth_finish_account().await;
                let expected = model::finish_account(
                    &state,
                    &s(user(0)),
                    &credential_id,
                    sql_fault,
                );
                let case =
                    format!("webauthn account {state:?} credential {credential_id} sql {sql_fault:?}");
                assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
                assert_eq!(
                    io.split_id(),
                    expected.as_ref().and_then(|(_, split)| split.clone()),
                    "{case}"
                );
                assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
                counts.case(sql_fault);
            }
        }

        // Release the same live share the row carries.
        let state = webauthn_db(&row_state, None, None, None);
        load_webauthn(&app, &db, &store, &state).await;
        let share = row_state.as_ref().and_then(|row| row.share.clone());
        let decoded = share
            .as_deref()
            .map(crate::db::decode_b64)
            .map(|result| result.is_ok());
        let share_for_bytes = share.clone();
        let mut io = super::recover::RecoverIo::for_conformance(
            &app,
            Faulty::new(PoolSql(&db), None),
            FaultyKv::new(StoreKv(&store), None),
            user(0),
            None,
            None,
            None,
            share,
            Some(1),
            None,
        );
        let observed = io
            .auth_finish_release(vela_recovery_policy::webauthn_driver::AuthFinishGrantPermit {
                epoch: 1,
            })
            .await;
        let expected = model::release_share(
            &state,
            &s(user(0)),
            decoded.unwrap_or(false),
        );
        let case = format!("webauthn release {state:?}");
        assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
        assert_eq!(snapshot_webauthn(&db, &store).await, state, "{case}");
        assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
        assert_eq!(
            io.share_bytes(),
            share_for_bytes
                .as_deref()
                .and_then(|text| crate::db::decode_b64(text).ok()),
            "{case}"
        );
        if let Some((_, post)) = expected {
            assert_eq!(post, state);
        }
        counts.case(None);
    }
    assert!(counts.states > 0 && counts.cases > 0);
}

#[tokio::test]
async fn webauthn_grant_store_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();

    for row_state in [None, Some(webauthn_user_states()[1].clone().unwrap())] {
        counts.states += 1;
        for kv_fault in faults(1) {
            let state = webauthn_db(&row_state, None, None, None);
            load_webauthn(&app, &db, &store, &state).await;
            let mut io = super::recover::RecoverIo::for_conformance(
                &app,
                Faulty::new(PoolSql(&db), None),
                FaultyKv::new(StoreKv(&store), kv_fault),
                user(0),
                None,
                None,
                Some(cred_id(0)),
                None,
                Some(7),
                Some(grant(0)),
            );
            let observed = io.auth_finish_store_grant().await;
            let expected = model::store_credential_grant(
                &state,
                &webauthn_grant_key(),
                "{\"key_epoch\":7}",
                &CredentialGrantView {
                    key_epoch: 7,
                    credential_id: cred_id(0),
                    possession: false,
                },
                600,
                kv_fault,
            );
            let case = format!("webauthn grant {state:?} kv {kv_fault:?}");
            assert_eq!(observed, Some(expected.0), "{case}");
            assert_eq!(
                webauthn_grant_of(&snapshot_webauthn(&db, &store).await),
                expected.1.grants.get(&webauthn_grant_key()).cloned(),
                "{case}"
            );
            assert_eq!(io.recovery_grant(), Some(grant(0)), "{case}");
            counts.case(kv_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn webauthn_registration_start_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();

    for row_state in webauthn_user_states() {
        counts.states += 1;
        for sql_fault in faults(1) {
            let state = webauthn_db(&row_state, None, None, None);
            load_webauthn(&app, &db, &store, &state).await;
            let mut io = super::webauthn::RegisterStartIo::for_conformance(
                &app,
                Faulty::new(PoolSql(&db), sql_fault),
                FaultyKv::new(StoreKv(&store), None),
                user(0),
            );
            let observed = io.registration_start_observe().await;
            let expected = model::registration_start_observe(&state, &s(user(0)), sql_fault);
            let case = format!("webauthn registration start {state:?} sql {sql_fault:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(io.error_is_set(), expected.is_none(), "{case}");
            counts.case(sql_fault);
        }
        for kv_fault in faults(1) {
            let state = webauthn_db(&row_state, None, None, None);
            load_webauthn(&app, &db, &store, &state).await;
            let mut io = super::webauthn::RegisterStartIo::for_conformance(
                &app,
                Faulty::new(PoolSql(&db), None),
                FaultyKv::new(StoreKv(&store), kv_fault),
                user(0),
            );
            let value = serde_json::to_string(&stored_registration_state(&app)).unwrap();
            let observed = io.write_registration_state(value.clone()).await;
            let expected = model::store_registration_state(
                &state,
                &webauthn_registration_key(),
                &value,
                300,
                kv_fault,
            );
            let case = format!("webauthn registration store {state:?} kv {kv_fault:?}");
            assert_eq!(observed, Some(expected.0), "{case}");
            assert_eq!(snapshot_webauthn(&db, &store).await, expected.1, "{case}");
            counts.case(kv_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn webauthn_registration_finish_matches_the_store_model() {
    let app = temp_app_state().await;
    let db = temp_db().await;
    let store = temp_store();
    let mut counts = Counts::default();
    let new_id = cred_id(2);

    for registration in [
        None,
        Some(model::WebAuthnRegistrationCell::Valid),
        Some(model::WebAuthnRegistrationCell::Undecodable),
    ] {
        counts.states += 1;
        for kv_fault in faults(1) {
            let state = webauthn_db(&None, None, registration.clone(), None);
            load_webauthn(&app, &db, &store, &state).await;
            let mut io = super::webauthn::RegisterFinishIo::for_conformance(
                &app,
                Faulty::new(PoolSql(&db), None),
                FaultyKv::new(StoreKv(&store), kv_fault),
                user(0),
            );
            let observed = io.registration_consume_state().await;
            let expected =
                model::take_registration_state(&state, &webauthn_registration_key(), kv_fault);
            let case = format!("webauthn registration consume {state:?} kv {kv_fault:?}");
            assert_eq!(observed, expected.as_ref().map(|(obs, _)| *obs), "{case}");
            assert_eq!(
                snapshot_webauthn(&db, &store).await,
                expected
                    .clone()
                    .map(|(_, post)| post)
                    .unwrap_or_else(|| state.clone()),
                "{case}"
            );
            counts.case(kv_fault);
        }
    }

    // The uniqueness lookup and the credential write.
    for row_state in webauthn_user_states() {
        counts.states += 1;
        for (holder, other_account) in [
            (cred_id(0), false),
            (cred_id(1), false),
            (cred_id(1), true),
        ] {
            for sql_fault in faults(1) {
                let mut state = webauthn_db(&row_state, None, None, None);
                if other_account {
                    let row = webauthn_user_row(
                        Some("c2hhcmU="),
                        model::CredentialCell::Valid(holder.clone()),
                        Some(&holder),
                        Some(7),
                        false,
                        None,
                    );
                    state.users.insert(s(user(1)), row);
                    state.holders.insert(holder.clone(), s(user(1)));
                }
                load_webauthn(&app, &db, &store, &state).await;
                let mut io = super::webauthn::RegisterFinishIo::for_conformance(
                    &app,
                    Faulty::new(PoolSql(&db), sql_fault),
                    FaultyKv::new(StoreKv(&store), None),
                    user(0),
                );
                io.set_passkey(stored_passkey(&holder));
                let observed = io.registration_check_uniqueness().await;
                let expected =
                    model::check_uniqueness(&state, &holder, &s(user(0)), sql_fault);
                let case = format!("webauthn uniqueness {state:?} holder {holder} sql {sql_fault:?}");
                assert_eq!(observed, Some(expected), "{case}");
                counts.case(sql_fault);
            }
        }
        for sql_fault in faults(1) {
            let state = webauthn_db(&row_state, None, None, None);
            load_webauthn(&app, &db, &store, &state).await;
            let mut io = super::webauthn::RegisterFinishIo::for_conformance(
                &app,
                Faulty::new(PoolSql(&db), sql_fault),
                FaultyKv::new(StoreKv(&store), None),
                user(0),
            );
            let credential = serde_json::to_string(&stored_passkey(&new_id)).unwrap();
            let observed = io.persist_credential_json(credential.clone(), new_id.clone()).await;
            let expected = model::persist_credential(
                &state,
                &s(user(0)),
                &credential,
                &new_id,
                true,
                sql_fault,
            );
            let case = format!("webauthn persist {state:?} sql {sql_fault:?}");
            assert_eq!(observed, Some(expected.0), "{case}");
            assert_eq!(
                snapshot_webauthn(&db, &store).await,
                expected.1,
                "{case}"
            );
            if expected.0 != vela_recovery_policy::webauthn_driver::CredentialPersistObservation::Persisted {
                assert_eq!(io.persist_error_is_set(), sql_fault.is_some(), "{case}");
            }
            counts.case(sql_fault);
        }
    }
    assert!(counts.states > 0 && counts.cases > 0 && counts.faulted > 0);
}

#[tokio::test]
async fn schema_has_the_webauthn_columns() {
    let db = temp_db().await;
    for column in [
        "recovery_share",
        "recovery_webauthn_credential",
        "recovery_webauthn_cred_id",
        "recovery_split_id",
        "key_epoch",
        "rekey_state",
    ] {
        db.query(&format!("SELECT {column} FROM users"), vec![])
            .await
            .unwrap_or_else(|error| panic!("users.{column} is missing: {error}"));
    }
    // The credential-id index is unique, so at most one account holds an id.
    db.execute(
        "INSERT INTO users (id, created_at, recovery_webauthn_cred_id) VALUES (?, 't', 'shared')",
        vec![TursoValue::Text(user(100).to_string())],
    )
    .await
    .unwrap();
    let duplicate = db
        .execute(
            "INSERT INTO users (id, created_at, recovery_webauthn_cred_id) VALUES (?, 't', 'shared')",
            vec![TursoValue::Text(user(102).to_string())],
        )
        .await;
    assert!(duplicate.is_err(), "recovery_webauthn_cred_id must be unique");
}
