//! Bounded conformance of the device-enrollment executors against a real
//! database and a real sled store (F-1).
//!
//! The F* proofs in `vela-enrollment-policy/proofs/fstar/executor-lemmas` show
//! that each executor's plan and classifier are honest *in the store model*.
//! This test checks the model against turso and sled: for every small starting
//! state, every executor method, every caller and target, and every fault point
//! (no fault, or a failure injected at each statement in turn), it runs the
//! real executor (plan, rendered SQL, real stores, row decoding, classification)
//! through [`ExecIo`]'s fault injection and compares the resulting tables, store
//! keys and observation with the Rust mirror of the model
//! (`vela_enrollment_policy::executor_model`).
//!
//! A schema check pins the columns and types the model uses.

use std::collections::BTreeMap;

use uuid::Uuid;
use vela_enrollment_policy::executor_model::{
    self as model, ClaimRow, Db as Model, DeviceRow, GrantRow, ResultRow, UserRow,
};
use vela_enrollment_policy::executor::{
    package_key, claim_key, grant_key, result_key, challenge_key, CollectorVerdicts,
    CompletionVerdicts, EnrollAuthVerdict, PairingStmt,
};
use vela_enrollment_policy::pairing_driver::{
    ClaimReadObservation, DeviceInsertObservation, RedeemObservation, ResultReadObservation,
    TakeObservation,
};

use super::enroll::{enroll_io_for_test, EnrollRequest, NewDevicePayload};
use super::invitation::{redeem_package_for_test, store_package_for_test};
use super::pairing_executor::PairingExecutor;
use super::rendezvous::{
    claim_io_for_test, complete_io_for_test, open_grant_io_for_test, result_io_for_test,
    ClaimRequest, CompleteRequest,
};
use crate::config;
use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};
use crate::state::{AppState, AppStateInner};
use crate::store::Store;

const NOW: &str = "2026-10-30T12:00:00+00:00";
const TOKEN: &str = "tok";
const GRANT: &str = "grant";
const CHALLENGE: &str = "nonce";
/// 32 zero bytes, base64: a challenge that reaches the signature check.
const VALID_CHALLENGE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn user(n: u128) -> String {
    Uuid::from_u128(0x1000 + n).to_string()
}

fn device(n: u128) -> String {
    Uuid::from_u128(0x3000 + n).to_string()
}

fn s(x: Uuid) -> String {
    x.to_string()
}

fn opt(value: &Option<String>) -> TursoValue {
    match value {
        Some(text) => TursoValue::Text(text.clone()),
        None => TursoValue::Null,
    }
}

async fn temp_state() -> AppState {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let path = format!(
        "{}/vela-enroll-conformance-{}-{}.db",
        std::env::temp_dir().display(),
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    let turso = std::sync::Arc::new(TursoDb::open(&path, 1).await.unwrap());
    let store = Store::open_temp().unwrap();
    let cfg = config::Config::from_env().expect("default config");
    std::sync::Arc::new(AppStateInner::new(turso, store, cfg).await.unwrap())
}

// ── Store records (the pinned rendering of the plans) ──────────────────────

fn grant_bytes(row: &GrantRow) -> Vec<u8> {
    format!(r#"{{"user_id":{},"device_id":{}}}"#, json(&row.user_id), json(&row.device_id))
        .into_bytes()
}

fn claim_bytes(row: &ClaimRow) -> Vec<u8> {
    format!(
        r#"{{"hybrid_ek":{},"hybrid_vk":{},"device_name":{},"device_type":{}}}"#,
        json(&row.hybrid_ek),
        json(&row.hybrid_vk),
        json(&row.device_name.clone().unwrap_or_default()),
        json(&row.device_type.clone().unwrap_or_default()),
    )
    .into_bytes()
}

fn result_bytes(row: &ResultRow) -> Vec<u8> {
    format!(r#"{{"device_id":{},"hybrid_vk":{}}}"#, json(&row.device_id), json(&row.hybrid_vk)).into_bytes()
}

fn json(text: &str) -> String {
    serde_json::to_string(text).unwrap()
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    serde_json::from_slice(bytes).expect("stored record decodes")
}

#[derive(serde::Deserialize)]
struct StoredGrant {
    user_id: String,
    device_id: String,
}

#[derive(serde::Deserialize)]
struct StoredClaim {
    hybrid_ek: String,
    hybrid_vk: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    device_type: Option<String>,
}

#[derive(serde::Deserialize)]
struct StoredResult {
    device_id: String,
    hybrid_vk: String,
}

// ── Loading and snapshotting ───────────────────────────────────────────────

fn all_store_keys() -> Vec<String> {
    vec![
        package_key(TOKEN),
        package_key("invalid-utf8"),
        grant_key(GRANT),
        claim_key(GRANT),
        result_key(GRANT),
        challenge_key(CHALLENGE),
        challenge_key("login-nonce"),
        challenge_key("other"),
    ]
}

async fn load(state: &AppState, pre: &Model) {
    state
        .sqldb
        .execute_batch("DELETE FROM devices; DELETE FROM users;")
        .await
        .unwrap();
    for key in all_store_keys() {
        let _ = state.store.del(&key);
    }
    for (id, row) in &pre.users {
        state
            .sqldb
            .execute(
                "INSERT INTO users (id, created_at, key_epoch, rekey_state) VALUES (?, 't', ?, ?)",
                vec![
                    TursoValue::Text(id.clone()),
                    TursoValue::Integer(row.key_epoch),
                    opt(&row.rekey_state),
                ],
            )
            .await
            .unwrap();
    }
    for (id, row) in &pre.devices {
        state
            .sqldb
            .execute(
                "INSERT INTO devices (id, user_id, device_name, device_type, hybrid_ek, hybrid_vk, enrolled_by, enrollment_grant_id, rms_capsule, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    TursoValue::Text(id.clone()),
                    TursoValue::Text(row.user_id.clone()),
                    TursoValue::Text(row.device_name.clone()),
                    TursoValue::Text(row.device_type.clone()),
                    TursoValue::Text(row.hybrid_ek.clone()),
                    TursoValue::Text(row.hybrid_vk.clone()),
                    TursoValue::Text(row.enrolled_by.clone()),
                    opt(&row.enrollment_grant_id),
                    TursoValue::Text(row.rms_capsule.clone()),
                    TursoValue::Text(row.created_at.clone()),
                    TursoValue::Integer(row.revoked),
                ],
            )
            .await
            .unwrap();
    }
    for (token, value) in &pre.packages {
        state.store.set_ex(&package_key(token), value.as_bytes(), 900).unwrap();
    }
    for (nonce, value) in &pre.challenges {
        state.store.set_ex(&challenge_key(nonce), value.as_bytes(), 60).unwrap();
    }
    for (id, row) in &pre.grants {
        state.store.set_ex(&grant_key(id), &grant_bytes(row), 300).unwrap();
    }
    for (id, row) in &pre.claims {
        state.store.set_ex(&claim_key(id), &claim_bytes(row), 300).unwrap();
    }
    for (id, row) in &pre.results {
        state.store.set_ex(&result_key(id), &result_bytes(row), 300).unwrap();
    }
}

fn text(row: &VelaRow, i: usize) -> String {
    row.text(i).unwrap_or_else(|| panic!("column {i} is not text")).to_string()
}

fn nullable(row: &VelaRow, i: usize) -> Option<String> {
    row.text(i).map(String::from)
}

/// The modelled columns of `users` and `devices`, plus every modelled store key.
async fn snapshot(state: &AppState) -> Model {
    let mut out = Model::default();
    for row in state
        .sqldb
        .query("SELECT id, key_epoch, rekey_state FROM users", vec![])
        .await
        .unwrap()
    {
        out.users.insert(
            text(&row, 0),
            UserRow {
                key_epoch: row.i64(1).expect("key_epoch is an integer"),
                rekey_state: nullable(&row, 2),
            },
        );
    }
    for row in state
        .sqldb
        .query(
            "SELECT id, user_id, device_name, device_type, hybrid_ek, hybrid_vk, enrolled_by, enrollment_grant_id, rms_capsule, created_at, revoked FROM devices",
            vec![],
        )
        .await
        .unwrap()
    {
        let id = text(&row, 0);
        let grant = nullable(&row, 7);
        if let Some(grant) = &grant {
            out.grant_index.insert(grant.clone(), id.clone());
        }
        out.devices.insert(
            id,
            DeviceRow {
                user_id: text(&row, 1),
                device_name: text(&row, 2),
                device_type: text(&row, 3),
                hybrid_ek: text(&row, 4),
                hybrid_vk: text(&row, 5),
                enrolled_by: text(&row, 6),
                enrollment_grant_id: grant,
                rms_capsule: text(&row, 8),
                created_at: text(&row, 9),
                revoked: row.i64(10).expect("revoked is an integer"),
            },
        );
    }
    if let Some(bytes) = state.store.get(&package_key(TOKEN)).unwrap() {
        out.packages.insert(TOKEN.into(), String::from_utf8(bytes).unwrap());
    }
    for (name, key) in [
        (CHALLENGE, challenge_key(CHALLENGE)),
        ("login-nonce", challenge_key("login-nonce")),
    ] {
        if let Some(bytes) = state.store.get(&key).unwrap() {
            out.challenges.insert(name.into(), String::from_utf8(bytes).unwrap());
        }
    }
    if let Some(bytes) = state.store.get(&grant_key(GRANT)).unwrap() {
        let row: StoredGrant = parse(&bytes);
        out.grants.insert(
            GRANT.into(),
            GrantRow { user_id: row.user_id, device_id: row.device_id },
        );
    }
    if let Some(bytes) = state.store.get(&claim_key(GRANT)).unwrap() {
        let row: StoredClaim = parse(&bytes);
        out.claims.insert(
            GRANT.into(),
            ClaimRow {
                hybrid_ek: row.hybrid_ek,
                hybrid_vk: row.hybrid_vk,
                device_name: row.device_name.filter(|x| !x.is_empty()),
                device_type: row.device_type.filter(|x| !x.is_empty()),
            },
        );
    }
    if let Some(bytes) = state.store.get(&result_key(GRANT)).unwrap() {
        let row: StoredResult = parse(&bytes);
        out.results.insert(
            GRANT.into(),
            ResultRow { device_id: row.device_id, hybrid_vk: row.hybrid_vk },
        );
    }
    out
}

/// The stored device `created_at` is chosen by the executor's clock, which the
/// model treats as opaque; every other field is compared.
fn normalize(mut state: Model) -> Model {
    for row in state.devices.values_mut() {
        row.created_at = String::new();
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

// ── States ─────────────────────────────────────────────────────────────────

fn base_users() -> BTreeMap<String, UserRow> {
    let mut users = BTreeMap::new();
    users.insert(user(0), UserRow { key_epoch: 3, rekey_state: None });
    users.insert(user(1), UserRow { key_epoch: 2, rekey_state: None });
    users.insert(user(2), UserRow { key_epoch: 3, rekey_state: Some("freezing".into()) });
    users
}

fn device_row(owner: u128, revoked: i64, grant: Option<&str>) -> DeviceRow {
    DeviceRow {
        user_id: user(owner),
        device_name: "Primary".into(),
        device_type: "desktop".into(),
        hybrid_ek: "ZWs=".into(),
        hybrid_vk: "dms=".into(),
        enrolled_by: String::new(),
        enrollment_grant_id: grant.map(String::from),
        rms_capsule: String::new(),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        revoked,
    }
}

/// The invitation/challenge keys are always present; grant, claim and result
/// take every combination.
fn kv_states() -> Vec<Model> {
    let mut states = Vec::new();
    for grant in [false, true] {
        for claim in [false, true] {
            for result in [false, true] {
                let mut state = Model {
                    users: base_users(),
                    ..Model::default()
                };
                state.packages.insert(TOKEN.into(), "ciphertext".into());
                state.challenges.insert(CHALLENGE.into(), "enroll".into());
                state.challenges.insert("login-nonce".into(), "login".into());
                if grant {
                    state.grants.insert(
                        GRANT.into(),
                        GrantRow { user_id: user(0), device_id: device(0) },
                    );
                }
                if claim {
                    state.claims.insert(
                        GRANT.into(),
                        ClaimRow {
                            hybrid_ek: "ZWs=".into(),
                            hybrid_vk: "dms=".into(),
                            device_name: Some("Phone".into()),
                            device_type: None,
                        },
                    );
                }
                if result {
                    state.results.insert(
                        GRANT.into(),
                        ResultRow { device_id: device(9), hybrid_vk: "dms=".into() },
                    );
                }
                states.push(state);
            }
        }
    }
    states
}

/// Every account shape the completion preflight can read.
fn account_states() -> Vec<Model> {
    let shapes = [
        None,
        Some(UserRow { key_epoch: 3, rekey_state: None }),
        Some(UserRow { key_epoch: 2, rekey_state: None }),
        Some(UserRow { key_epoch: 3, rekey_state: Some("freezing".into()) }),
    ];
    shapes
        .into_iter()
        .enumerate()
        .map(|(n, shape)| {
            let mut state = Model::default();
            if let Some(row) = shape {
                state.users.insert(user(n as u128), row);
            }
            state
        })
        .collect()
}

fn device_states() -> Vec<Model> {
    let rows = [
        ("absent", None, None),
        ("active", Some(0), None),
        ("revoked", Some(0), Some(1)),
        ("foreign", Some(1), None),
        ("grant", Some(0), None),
    ];
    rows.into_iter()
        .enumerate()
        .map(|(n, (kind, owner, revoked))| {
            let mut state = Model { users: base_users(), ..Model::default() };
            if let Some(owner) = owner {
                state
                    .devices
                    .insert(device(0), device_row(owner, revoked.unwrap_or(0), None));
            }
            if kind == "grant" {
                state
                    .devices
                    .insert(device(1), device_row(0, 0, Some(GRANT)));
                state.grant_index.insert(GRANT.into(), device(1));
            }
            let _ = n;
            state
        })
        .collect()
}

// ── Cases ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn store_and_take_executors_match_the_model() {
    let state = temp_state().await;
    let mut counts = Counts::default();
    for pre in kv_states() {
        counts.states += 1;

        // StorePackageIo::store_package.
        for fault in faults(1) {
            load(&state, &pre).await;
            let mut io = store_package_for_test(
                &state,
                fault,
                TOKEN.into(),
                "ciphertext".into(),
            );
            let observed = io.store_package().await;
            let (expected, expected_post) = model::store_package(
                &pre,
                TOKEN.into(),
                "ciphertext".into(),
                fault,
            );
            let case = format!("store package fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
            counts.case(fault);
        }

        // RedeemPackageIo::redeem_package: present, missing, and a stored
        // value that is not UTF-8.
        for (present, utf8) in [(TOKEN.to_string(), true), ("absent".into(), false)] {
            for fault in faults(1) {
                load(&state, &pre).await;
                let mut io = redeem_package_for_test(&state, fault, present.clone());
                let observed = io.redeem_package().await;
                let (expected, expected_post) =
                    model::redeem_package(&pre, present.clone(), utf8, fault);
                let case = format!("redeem {present} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
                counts.case(fault);
            }
        }
        if pre.packages.contains_key(TOKEN) {
            load(&state, &pre).await;
            state
                .store
                .set_ex(&package_key("invalid-utf8"), &[0xff, 0xfe], 900)
                .unwrap();
            let mut io = redeem_package_for_test(&state, None, "invalid-utf8".into());
            let observed = io.redeem_package().await;
            assert_eq!(observed, RedeemObservation::Present { utf8_valid: false });
            let mut plain = pre.clone();
            plain.packages.insert("invalid-utf8".into(), String::new());
            let (_, expected_post) = model::redeem_package(&plain, "invalid-utf8".into(), false, None);
            assert_eq!(normalize(snapshot(&state).await), normalize(expected_post));
            counts.case(None);
        }

        // OpenGrantIo::store_grant.
        for fault in faults(1) {
            load(&state, &pre).await;
            let mut io = open_grant_io_for_test(
                &state,
                fault,
                GRANT.into(),
                user(1),
                device(1),
            );
            let observed = io.store_grant().await;
            let (expected, expected_post) =
                model::store_grant(&pre, GRANT.into(), user(1), device(1), fault);
            let case = format!("store grant fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
            counts.case(fault);
        }

        // EnrollIo::consume_challenge: matching, wrong-purpose and missing
        // nonces.
        for (nonce, matches) in [
            (CHALLENGE.to_string(), true),
            ("login-nonce".into(), false),
            ("other".into(), false),
        ] {
            for fault in faults(1) {
                load(&state, &pre).await;
                let body = EnrollRequest {
                    enrolling_device_id: Uuid::from_u128(0x9000),
                    challenge: nonce.clone(),
                    auth_signature: String::new(),
                    new_device: NewDevicePayload {
                        hybrid_ek: String::new(),
                        hybrid_vk: String::new(),
                        rms_capsule: String::new(),
                        key_epoch: 1,
                        signature: String::new(),
                        device_name: None,
                        device_type: None,
                    },
                };
                let mut io = enroll_io_for_test(
                    &state,
                    fault,
                    body,
                    Uuid::from_u128(0x9000).to_string(),
                    Uuid::from_u128(0x9100),
                    None,
                    0,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                );
                let observed = io.consume_challenge().await;
                let (expected, expected_post) =
                    model::challenge_take(&pre, nonce.clone(), matches, fault);
                let case = format!("challenge {nonce} fault {fault:?} pre {pre:?}");
                assert_eq!(
                    observed == vela_enrollment_policy::enroll_driver::ChallengeObservation::Consumed,
                    expected,
                    "{case}"
                );
                assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "enrollment executor conformance (store/take): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn claim_and_ceremony_executors_match_the_model() {
    let state = temp_state().await;
    let mut counts = Counts::default();
    for pre in kv_states() {
        counts.states += 1;

        // ClaimIo::check_claim.
        for fault in faults(1) {
            load(&state, &pre).await;
            let mut io = claim_io_for_test(
                &state,
                fault,
                GRANT.into(),
                pre.grants.contains_key(GRANT),
                ClaimRequest {
                    hybrid_ek: "ZWs=".into(),
                    hybrid_vk: "dms=".into(),
                    device_name: None,
                    device_type: None,
                },
            );
            let observed = io.check_claim().await;
            let (expected, expected_post) = model::claim_check_for(
                &pre,
                GRANT.into(),
                pre.grants.contains_key(GRANT),
                2,
                2,
                fault,
            );
            let case = format!("claim check fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
            counts.case(fault);

            // ClaimIo::write_claim after that check (the check consumed one
            // statement, so the write's own fault point is 1).
            for write_fault in faults(1) {
                load(&state, &pre).await;
                let mut io = claim_io_for_test(
                    &state,
                    write_fault.map(|k| k + 1),
                    GRANT.into(),
                    pre.grants.contains_key(GRANT),
                    ClaimRequest {
                        hybrid_ek: "ZWs=".into(),
                        hybrid_vk: "dms=".into(),
                        device_name: Some("Phone".into()),
                        device_type: None,
                    },
                );
                let _ = io.check_claim().await;
                let observed = io.write_claim().await;
                let (expected, expected_post) = model::claim_write(
                    &pre,
                    GRANT.into(),
                    "ZWs=".into(),
                    "dms=".into(),
                    Some("Phone".into()),
                    None,
                    write_fault,
                );
                let case = format!("claim write fault {write_fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(
                    normalize(snapshot(&state).await),
                    normalize(expected_post),
                    "{case}"
                );
                counts.case(write_fault);
            }
        }

        // CompleteIo::take_ceremony with the validated claim snapshot the
        // preflight recorded.
        let claim_snapshot = pre.claims.get(GRANT).map(claim_bytes);
        for fault in faults(1) {
            for expected_claim in [claim_snapshot.clone()] {
                load(&state, &pre).await;
                let mut io = complete_io_for_test(
                    &state,
                    fault,
                    GRANT.into(),
                    user(0),
                    device(0),
                    grant_bytes(&pre.grants.get(GRANT).cloned().unwrap_or(GrantRow {
                        user_id: String::new(),
                        device_id: String::new(),
                    })),
                    expected_claim,
                    CompleteRequest {
                        rms_capsule: "Y2Fw".into(),
                        signature: String::new(),
                        key_epoch: 3,
                    },
                );
                let observed = io.take_ceremony().await;
                let (expected, expected_post) =
                    model::take_ceremony(&pre, GRANT.into(), true, true, fault);
                let case = format!("take ceremony fault {fault:?} pre {pre:?}");
                // The snapshot comparison decides the match verdicts; the
                // model is given the verdicts the executor computed from the
                // stored bytes (true here: the snapshot is the stored record).
                match (observed, expected) {
                    (TakeObservation::Missing, TakeObservation::Missing) => {}
                    (TakeObservation::Taken { .. }, TakeObservation::Taken { .. }) => {}
                    other => panic!("{case}: {other:?}"),
                }
                if pre.claims.contains_key(GRANT) && pre.grants.contains_key(GRANT) && fault.is_none() {
                    assert!(
                        matches!(
                            observed,
                            TakeObservation::Taken { grant_matches: true, claim_matches: true }
                        ),
                        "{case}"
                    );
                }
                assert_eq!(
                    normalize(snapshot(&state).await),
                    normalize(expected_post),
                    "{case}"
                );
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "enrollment executor conformance (claim/ceremony): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn completion_executors_match_the_model() {
    let state = temp_state().await;
    let mut counts = Counts::default();

    for pre in account_states() {
        counts.states += 1;
        for target in [user(0), user(1), user(2)] {
            for fault in faults(1) {
                load(&state, &pre).await;
                let mut io = complete_io_for_test(
                    &state,
                    fault,
                    GRANT.into(),
                    target.clone(),
                    device(0),
                    Vec::new(),
                    None,
                    CompleteRequest {
                        rms_capsule: "Y2Fw".into(),
                        signature: String::new(),
                        key_epoch: 3,
                    },
                );
                let observed = io.check_account().await;
                let (expected, fields, expected_post) =
                    model::account_read(&pre, target.clone(), true, true, fault);
                let case = format!("account {target} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
                let _ = fields;
                counts.case(fault);
            }
        }
    }

    for pre in kv_states() {
        counts.states += 1;
        // CompleteIo::prepare_completion. The stored claim decodes; the
        // capsule and signature fields are invalid; no signature verifies.
        for fault in faults(2) {
            load(&state, &pre).await;
            let mut io = complete_io_for_test(
                &state,
                fault.map(|k| k + 1),
                GRANT.into(),
                user(0),
                device(0),
                Vec::new(),
                None,
                CompleteRequest {
                    rms_capsule: "!!!".into(),
                    signature: "!!!".into(),
                    key_epoch: 3,
                },
            );
            // The handler reads the account first; then the preflight.
            let _ = io.check_account().await;
            let observed = io.prepare_completion().await;
            let verdicts = CompletionVerdicts {
                claim_keys_usable: true,
                capsule_valid: false,
                signature_field_valid: false,
                opener_key_decodes: false,
                signature_verified: false,
                account_epoch: 3,
                declared_epoch: 3,
                rotation_in_progress: false,
                account_epoch_active: true,
            };
            let (expected, expected_post) = model::completion_preflight(
                &pre,
                GRANT.into(),
                device(0),
                user(0),
                verdicts,
                fault,
            );
            let case = format!("preflight fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
            counts.case(fault);
        }
    }

    for pre in device_states() {
        counts.states += 1;
        // CompleteIo::insert_device after the real preflight read the stored
        // claim. The executor picks its own new device id, so the model is
        // given the id the insert actually used.
        let claim = ClaimRow {
            hybrid_ek: "ZWs=".into(),
            hybrid_vk: "dms=".into(),
            device_name: Some("Phone".into()),
            device_type: None,
        };
        for guard_epoch in [3i64, 2] {
            let mut with_claim = pre.clone();
            with_claim.claims.insert(GRANT.into(), claim.clone());
            for fault in faults(1) {
                load(&state, &with_claim).await;
                let mut io = complete_io_for_test(
                    &state,
                    fault.map(|k| k + 3),
                    GRANT.into(),
                    user(0),
                    device(0),
                    Vec::new(),
                    None,
                    CompleteRequest {
                        rms_capsule: "Y2Fw".into(),
                        signature: String::new(),
                        key_epoch: guard_epoch,
                    },
                );
                // The handler reads the account, then the preflight, then
                // inserts; the insert's own statement is the third.
                let _ = io.check_account().await;
                let _ = io.prepare_completion().await;
                let observed = io.insert_device().await;
                let after = snapshot(&state).await;
                let inserted = matches!(observed, DeviceInsertObservation::Inserted);
                let new_id = if inserted {
                    after
                        .devices
                        .iter()
                        .find(|(id, row)| {
                            !pre.devices.contains_key(*id)
                                && row.enrollment_grant_id.as_deref() == Some(GRANT)
                        })
                        .map(|(id, _)| id.clone())
                        .unwrap_or_else(|| "new-device-unused".to_string())
                } else {
                    "new-device-unused".to_string()
                };
                let statement = PairingStmt::InsertCompletionDevice {
                    new_device_id: new_id,
                    user_id: user(0),
                    device_name: "Phone".into(),
                    device_type: "unknown".into(),
                    hybrid_ek: "ZWs=".into(),
                    hybrid_vk: "dms=".into(),
                    enrolled_by: device(0),
                    grant_id: GRANT.into(),
                    rms_capsule: "Y2Fw".into(),
                    now: String::new(),
                    guard_user: user(0),
                    guard_epoch,
                };
                let (expected, expected_post) =
                    model::completion_insert(&with_claim, statement, fault);
                let case = format!(
                    "completion insert fault {fault:?} guard {guard_epoch} pre {pre:?}"
                );
                assert_eq!(observed, expected, "{case}");
                assert_eq!(
                    normalize(snapshot(&state).await),
                    normalize(expected_post),
                    "{case}"
                );
                counts.case(fault);
            }
        }
    }

    for pre in kv_states() {
        counts.states += 1;
        // CompleteIo::write_result, after the preflight read a usable claim.
        if !pre.claims.contains_key(GRANT) {
            continue;
        }
        for fault in faults(1) {
            load(&state, &pre).await;
            let mut io = complete_io_for_test(
                &state,
                fault.map(|k| k + 2),
                GRANT.into(),
                user(0),
                device(0),
                Vec::new(),
                None,
                CompleteRequest {
                    rms_capsule: "Y2Fw".into(),
                    signature: String::new(),
                    key_epoch: 3,
                },
            );
            let _ = io.prepare_completion().await;
            io.set_new_device_id_for_test(Uuid::from_u128(0x9400));
            let observed = io.write_result().await;
            let (expected, expected_post) = model::result_write(
                &pre,
                GRANT.into(),
                s(Uuid::from_u128(0x9400)),
                "dms=".into(),
                fault,
            );
            let case = format!("result write fault {fault:?} pre {pre:?}");
            assert_eq!(observed, expected, "{case}");
            assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
            counts.case(fault);
        }
    }

    eprintln!(
        "enrollment executor conformance (completion): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn result_executors_match_the_model() {
    let state = temp_state().await;
    let mut counts = Counts::default();
    for pre in kv_states() {
        counts.states += 1;

        let verdicts = CollectorVerdicts {
            key_decodes: true,
            key_len: 2,
            signature_verified: false,
        };
        for (method, fault_points) in [("result", 1usize), ("claim", 1usize), ("device", 1usize)] {
            for fault in faults(fault_points) {
                load(&state, &pre).await;
                let mut io = result_io_for_test(&state, fault, GRANT.into(), Vec::new());
                let case = format!("{method} read fault {fault:?} pre {pre:?}");
                match method {
                    "result" => {
                        let observed = io.read_result().await;
                        let (expected, expected_post) =
                            model::result_read(&pre, GRANT.into(), verdicts, fault);
                        assert_eq!(observed, expected, "{case}");
                        assert_eq!(
                            normalize(snapshot(&state).await),
                            normalize(expected_post),
                            "{case}"
                        );
                        assert_eq!(
                            matches!(observed, ResultReadObservation::Unreadable),
                            fault.is_some(),
                            "{case}"
                        );
                    }
                    "claim" => {
                        let observed = io.read_claim().await;
                        let (expected, expected_post) =
                            model::claim_read(&pre, GRANT.into(), verdicts, fault);
                        assert_eq!(observed, expected, "{case}");
                        assert_eq!(
                            normalize(snapshot(&state).await),
                            normalize(expected_post),
                            "{case}"
                        );
                        assert_eq!(
                            matches!(observed, ClaimReadObservation::Unreadable),
                            fault.is_some(),
                            "{case}"
                        );
                    }
                    _ => {
                        let observed = io.read_enrolled_device().await;
                        let (expected, expected_post) =
                            model::enrolled_device(&pre, GRANT.into(), verdicts, fault);
                        assert_eq!(observed, expected, "{case}");
                        assert_eq!(
                            normalize(snapshot(&state).await),
                            normalize(expected_post),
                            "{case}"
                        );
                    }
                }
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "enrollment executor conformance (result): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn enroll_executors_match_the_model() {
    let state = temp_state().await;
    let mut counts = Counts::default();
    for pre in device_states() {
        counts.states += 1;

        // EnrollIo::check_device for the stored, revoked, foreign and missing
        // device ids.
        for target in [device(0), device(1), device(2)] {
            for fault in faults(1) {
                load(&state, &pre).await;
                let body = EnrollRequest {
                    enrolling_device_id: Uuid::from_u128(0x9000),
                    challenge: VALID_CHALLENGE.into(),
                    auth_signature: String::new(),
                    new_device: NewDevicePayload {
                        hybrid_ek: String::new(),
                        hybrid_vk: String::new(),
                        rms_capsule: String::new(),
                        key_epoch: 1,
                        signature: String::new(),
                        device_name: None,
                        device_type: None,
                    },
                };
                let mut io = enroll_io_for_test(
                    &state,
                    fault,
                    body,
                    target.clone(),
                    Uuid::from_u128(0x9100),
                    None,
                    0,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                );
                let observed = io.check_device().await;
                let (expected, expected_post) =
                    model::active_device(&pre, target.clone(), EnrollAuthVerdict::Rejected, fault);
                let case = format!("active device {target} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(normalize(snapshot(&state).await), normalize(expected_post), "{case}");
                counts.case(fault);
            }
        }

        // EnrollIo::insert_device for a live and a stale account epoch.
        for (owner, epoch) in [(0u128, 3i64), (1, 2), (2, 3)] {
            let new_id = Uuid::from_u128(0x9300);
            for fault in faults(1) {
                load(&state, &pre).await;
                let body = EnrollRequest {
                    enrolling_device_id: Uuid::from_u128(0x9000),
                    challenge: String::new(),
                    auth_signature: String::new(),
                    new_device: NewDevicePayload {
                        hybrid_ek: String::new(),
                        hybrid_vk: String::new(),
                        rms_capsule: String::new(),
                        key_epoch: epoch,
                        signature: String::new(),
                        device_name: Some("Desktop Device".into()),
                        device_type: Some("desktop".into()),
                    },
                };
                let mut io = enroll_io_for_test(
                    &state,
                    fault,
                    body,
                    device(0),
                    new_id,
                    Some(Uuid::from_u128(0x1000 + owner)),
                    epoch,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                );
                let observed = io.insert_device().await;
                let statement = PairingStmt::InsertEnrollDevice {
                    new_device_id: s(new_id),
                    user_id: user(owner),
                    device_name: "Desktop Device".into(),
                    device_type: "desktop".into(),
                    hybrid_ek: String::new(),
                    hybrid_vk: String::new(),
                    enrolled_by: device(0),
                    rms_capsule: String::new(),
                    now: String::new(),
                    guard_user: user(owner),
                    guard_epoch: epoch,
                };
                let (expected, expected_post) = model::enroll_insert(&pre, statement, fault);
                let case = format!("enroll insert owner {owner} fault {fault:?} pre {pre:?}");
                assert_eq!(observed, expected, "{case}");
                assert_eq!(
                    normalize(snapshot(&state).await),
                    normalize(expected_post),
                    "{case}"
                );
                counts.case(fault);
            }
        }
    }
    eprintln!(
        "enrollment executor conformance (enroll): {} states, {} cases, {} with an injected failure",
        counts.states, counts.cases, counts.faulted
    );
}

#[tokio::test]
async fn schema_has_the_modelled_columns() {
    let state = temp_state().await;
    let expected: [(&str, &[(&str, &str)]); 2] = [
        (
            "users",
            &[("id", "TEXT UNIQUE NOT NULL"), ("key_epoch", "INTEGER NOT NULL DEFAULT 1"), ("rekey_state", "TEXT")],
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
                ("enrolled_by", "TEXT"),
                ("enrollment_grant_id", "TEXT"),
                ("rms_capsule", "TEXT"),
                ("revoked", "INTEGER NOT NULL DEFAULT 0"),
                ("created_at", "TEXT NOT NULL"),
            ],
        ),
    ];
    for (table, columns) in expected {
        let rows = state
            .sqldb
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
    // A device id is unique: the model keys the table by id.
    let mut pre = Model { users: base_users(), ..Model::default() };
    pre.devices.insert(device(0), device_row(0, 0, None));
    load(&state, &pre).await;
    let duplicate = state
        .sqldb
        .execute(
            "INSERT INTO devices (id, user_id, hybrid_ek, hybrid_vk, created_at) VALUES (?, 'u', 'a', 'b', 't')",
            vec![TursoValue::Text(device(0))],
        )
        .await;
    assert!(duplicate.is_err(), "devices accepted a duplicate id");
    // A grant id is unique too: the model's guarded insert relies on it.
    let mut pre = Model { users: base_users(), ..Model::default() };
    pre.devices.insert(device(0), device_row(0, 0, Some(GRANT)));
    load(&state, &pre).await;
    let duplicate_grant = state
        .sqldb
        .execute(
            "INSERT INTO devices (id, user_id, hybrid_ek, hybrid_vk, enrollment_grant_id, created_at) VALUES ('new', ?, 'a', 'b', ?, 't')",
            vec![TursoValue::Text(user(0)), TursoValue::Text(GRANT.into())],
        )
        .await;
    assert!(duplicate_grant.is_err(), "devices accepted a duplicate enrollment_grant_id");
}
