//! A Rust mirror of `proofs/fstar/executor-lemmas/Vela_enrollment_policy_executor_model.fst`.
//!
//! The F* model gives each typed statement its database or store meaning and
//! runs the extracted plans against it with a failure at any statement. This
//! module mirrors it function for function, so the server's conformance test
//! can compare a real executor (plan, rendered SQL, real turso/sled, row
//! decoding, classifier) with the model's answer on the same starting state
//! and the same fault point.
//!
//! A table is a map from its unique id to a row; the store is one map from a
//! key to a text value. TTLs are not modelled: a key is live for the length of
//! the request (the conformance store is populated just before each case).

use std::collections::BTreeMap;

use crate::executor::{
    account_fields, classify_account, classify_challenge_take, classify_claim_check,
    classify_claim_read, classify_claim_write, classify_completion_preflight,
    classify_device_check, classify_enrolled_device, classify_insert_completion,
    classify_insert_enroll, classify_redeem, classify_result_read, classify_store,
    classify_take_ceremony, plan_account_read, plan_active_device_read, plan_challenge_take,
    plan_claim_check, plan_claim_read, plan_claim_write, plan_completion_preflight,
    plan_device_by_grant, plan_redeem_package, plan_result_read, plan_result_write,
    plan_store_grant, plan_store_package, plan_take_ceremony, AccountRowView, ClaimRowView,
    CollectorVerdicts,
    CompletionVerdicts, DeviceRowView, EnrollAuthVerdict, PairingStmt, ReadOutcome, ResultRowView,
    TakeOutcome, WriteOutcome,
};
use crate::pairing_driver::{
    ClaimReadObservation, ClaimWriteObservation, CompletionAccountObservation,
    CompletionPreflightObservation, DeviceGrantObservation, DeviceInsertObservation,
    RedeemObservation, ResultReadObservation, StoreObservation, TakeObservation,
};

// ── Rows ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct GrantRow {
    pub user_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ClaimRow {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ResultRow {
    pub device_id: String,
    pub hybrid_vk: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UserRow {
    pub key_epoch: i64,
    pub rekey_state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DeviceRow {
    pub user_id: String,
    pub device_name: String,
    pub device_type: String,
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub enrolled_by: String,
    pub enrollment_grant_id: Option<String>,
    pub rms_capsule: String,
    pub created_at: String,
    pub revoked: i64,
}

/// Every table and store key the enrollment executors touch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Db {
    pub grants: BTreeMap<String, GrantRow>,
    pub claims: BTreeMap<String, ClaimRow>,
    pub results: BTreeMap<String, ResultRow>,
    pub packages: BTreeMap<String, String>,
    pub challenges: BTreeMap<String, String>,
    pub users: BTreeMap<String, UserRow>,
    pub devices: BTreeMap<String, DeviceRow>,
    /// `devices.enrollment_grant_id`, indexed: grant id -> device id.
    pub grant_index: BTreeMap<String, String>,
}

// ── Statement semantics ────────────────────────────────────────────────────

fn view_claim(row: &ClaimRow) -> ClaimRowView {
    ClaimRowView {
        hybrid_ek: Some(row.hybrid_ek.clone()),
        hybrid_vk: Some(row.hybrid_vk.clone()),
        device_name: row.device_name.clone(),
        device_type: row.device_type.clone(),
    }
}

fn view_result(row: &ResultRow) -> ResultRowView {
    ResultRowView {
        device_id: Some(row.device_id.clone()),
        hybrid_vk: Some(row.hybrid_vk.clone()),
    }
}

fn view_account(row: &UserRow) -> AccountRowView {
    AccountRowView {
        key_epoch: Some(row.key_epoch),
        rekey_state: row.rekey_state.clone(),
    }
}

fn view_device(id: &str, row: &DeviceRow) -> DeviceRowView {
    DeviceRowView {
        device_id: Some(id.to_string()),
        hybrid_vk: Some(row.hybrid_vk.clone()),
        revoked: Some(row.revoked),
        user_id: Some(row.user_id.clone()),
        enrollment_grant_id: row.enrollment_grant_id.clone(),
    }
}

/// A guard the two device inserts share: the user row must exist, be at the
/// statement's epoch and not be rotating.
fn epoch_guard(d: &Db, user: &str, epoch: i64) -> bool {
    match d.users.get(user) {
        Some(row) => row.key_epoch == epoch && row.rekey_state.is_none(),
        None => false,
    }
}

/// One write statement's SQL or store meaning. `None` is a statement error.
pub fn write_step(d: &Db, stmt: &PairingStmt) -> Option<(WriteOutcome, Db)> {
    let mut next = d.clone();
    match stmt {
        PairingStmt::StorePackage { token, ciphertext } => {
            next.packages.insert(token.clone(), ciphertext.clone());
            Some((WriteOutcome::Applied(1), next))
        }
        PairingStmt::StoreGrant {
            grant_id,
            user_id,
            device_id,
        } => {
            next.grants.insert(
                grant_id.clone(),
                GrantRow {
                    user_id: user_id.clone(),
                    device_id: device_id.clone(),
                },
            );
            Some((WriteOutcome::Applied(1), next))
        }
        PairingStmt::WriteClaim {
            grant_id,
            hybrid_ek,
            hybrid_vk,
            device_name,
            device_type,
        } => {
            if !d.grants.contains_key(grant_id) {
                return Some((WriteOutcome::GuardMissing, next));
            }
            if d.claims.contains_key(grant_id) {
                return Some((WriteOutcome::KeyExists, next));
            }
            next.claims.insert(
                grant_id.clone(),
                ClaimRow {
                    hybrid_ek: hybrid_ek.clone(),
                    hybrid_vk: hybrid_vk.clone(),
                    device_name: device_name.clone(),
                    device_type: device_type.clone(),
                },
            );
            Some((WriteOutcome::Inserted, next))
        }
        PairingStmt::StoreResult {
            grant_id,
            device_id,
            hybrid_vk,
        } => {
            next.results.insert(
                grant_id.clone(),
                ResultRow {
                    device_id: device_id.clone(),
                    hybrid_vk: hybrid_vk.clone(),
                },
            );
            Some((WriteOutcome::Applied(1), next))
        }
        PairingStmt::InsertCompletionDevice {
            new_device_id,
            user_id,
            device_name,
            device_type,
            hybrid_ek,
            hybrid_vk,
            enrolled_by,
            grant_id,
            rms_capsule,
            now,
            guard_user,
            guard_epoch,
        } => {
            if !epoch_guard(d, guard_user, *guard_epoch) {
                return Some((WriteOutcome::Applied(0), next));
            }
            if d.devices.contains_key(new_device_id) || d.grant_index.contains_key(grant_id) {
                return None;
            }
            next.devices.insert(
                new_device_id.clone(),
                DeviceRow {
                    user_id: user_id.clone(),
                    device_name: device_name.clone(),
                    device_type: device_type.clone(),
                    hybrid_ek: hybrid_ek.clone(),
                    hybrid_vk: hybrid_vk.clone(),
                    enrolled_by: enrolled_by.clone(),
                    enrollment_grant_id: Some(grant_id.clone()),
                    rms_capsule: rms_capsule.clone(),
                    created_at: now.clone(),
                    revoked: 0,
                },
            );
            next.grant_index.insert(grant_id.clone(), new_device_id.clone());
            Some((WriteOutcome::Applied(1), next))
        }
        PairingStmt::InsertEnrollDevice {
            new_device_id,
            user_id,
            device_name,
            device_type,
            hybrid_ek,
            hybrid_vk,
            enrolled_by,
            rms_capsule,
            now,
            guard_user,
            guard_epoch,
        } => {
            if !epoch_guard(d, guard_user, *guard_epoch) {
                return Some((WriteOutcome::Applied(0), next));
            }
            if d.devices.contains_key(new_device_id) {
                return None;
            }
            next.devices.insert(
                new_device_id.clone(),
                DeviceRow {
                    user_id: user_id.clone(),
                    device_name: device_name.clone(),
                    device_type: device_type.clone(),
                    hybrid_ek: hybrid_ek.clone(),
                    hybrid_vk: hybrid_vk.clone(),
                    enrolled_by: enrolled_by.clone(),
                    enrollment_grant_id: None,
                    rms_capsule: rms_capsule.clone(),
                    created_at: now.clone(),
                    revoked: 0,
                },
            );
            Some((WriteOutcome::Applied(1), next))
        }
        _ => panic!("not a write statement: {stmt:?}"),
    }
}

/// One read statement's SQL or store meaning.
pub fn read_step(d: &Db, stmt: &PairingStmt) -> Option<ReadOutcome> {
    match stmt {
        PairingStmt::ClaimExists { grant_id } => {
            Some(ReadOutcome::ClaimExists(d.claims.contains_key(grant_id)))
        }
        PairingStmt::ReadClaim { grant_id } => Some(ReadOutcome::Claim(
            d.claims.get(grant_id).map(view_claim),
        )),
        PairingStmt::SelectAccount { user_id } => {
            Some(ReadOutcome::Account(d.users.get(user_id).map(view_account)))
        }
        PairingStmt::SelectOpener { device_id, user_id } => Some(ReadOutcome::Opener(
            d.devices
                .get(device_id)
                .filter(|row| &row.user_id == user_id)
                .map(|row| view_device(device_id, row)),
        )),
        PairingStmt::SelectActiveDevice { device_id } => Some(ReadOutcome::ActiveDevice(
            d.devices
                .get(device_id)
                .filter(|row| row.revoked == 0)
                .map(|row| view_device(device_id, row)),
        )),
        PairingStmt::SelectDeviceByGrant { grant_id } => {
            let found = d
                .grant_index
                .get(grant_id)
                .and_then(|id| d.devices.get(id).map(|row| view_device(id, row)));
            Some(ReadOutcome::DeviceByGrant(found))
        }
        PairingStmt::ReadResult { grant_id } => Some(ReadOutcome::Result(
            d.results.get(grant_id).map(view_result),
        )),
        _ => panic!("not a read statement: {stmt:?}"),
    }
}

/// The k-th operation is the injected failure.
fn faulted(fault: Option<usize>, k: usize) -> bool {
    fault == Some(k)
}

/// A plan inside a request: writes, stopping at the first failure.
pub fn run_writes(d: &Db, plan: &[PairingStmt], fault: Option<usize>) -> (Vec<WriteOutcome>, Db) {
    let mut outcomes = Vec::new();
    let mut state = d.clone();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, d.clone());
        }
        match write_step(&state, stmt) {
            Some((outcome, next)) => {
                outcomes.push(outcome);
                state = next;
            }
            None => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, d.clone());
            }
        }
    }
    (outcomes, state)
}

/// A plan inside a request: reads, stopping at the first failure. Reads change
/// nothing.
pub fn run_reads(d: &Db, plan: &[PairingStmt], fault: Option<usize>) -> (Vec<ReadOutcome>, Db) {
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(ReadOutcome::Failed);
            return (outcomes, d.clone());
        }
        match read_step(d, stmt) {
            Some(outcome) => outcomes.push(outcome),
            None => {
                outcomes.push(ReadOutcome::Failed);
                return (outcomes, d.clone());
            }
        }
    }
    (outcomes, d.clone())
}

/// A destructive single-key read.
pub fn run_take(d: &Db, plan: &[PairingStmt], fault: Option<usize>) -> (TakeOutcome, Db) {
    assert_eq!(plan.len(), 1, "a take plan is one statement");
    if faulted(fault, 0) {
        return (TakeOutcome::Failed, d.clone());
    }
    let mut next = d.clone();
    let present = match &plan[0] {
        PairingStmt::TakePackage { token } => next.packages.remove(token).is_some(),
        PairingStmt::TakeChallenge { challenge } => next.challenges.remove(challenge).is_some(),
        other => panic!("not a single-key take: {other:?}"),
    };
    let outcome = if present {
        TakeOutcome::Present
    } else {
        TakeOutcome::Missing
    };
    (outcome, next)
}

/// The atomic two-key take.
pub fn run_take_pair(d: &Db, plan: &[PairingStmt], fault: Option<usize>) -> (TakeOutcome, Db) {
    assert_eq!(plan.len(), 1, "a pair take is one statement");
    if faulted(fault, 0) {
        return (TakeOutcome::Failed, d.clone());
    }
    let PairingStmt::TakeCeremony { grant_id } = &plan[0] else {
        panic!("not a pair take");
    };
    let mut next = d.clone();
    if next.grants.contains_key(grant_id) && next.claims.contains_key(grant_id) {
        next.grants.remove(grant_id);
        next.claims.remove(grant_id);
        (TakeOutcome::Present, next)
    } else {
        (TakeOutcome::Missing, next)
    }
}

// ── The executables: plan, run, classify ───────────────────────────────────

pub fn store_package(
    d: &Db,
    token: String,
    ciphertext: String,
    fault: Option<usize>,
) -> (StoreObservation, Db) {
    let (outcomes, post) = run_writes(d, &plan_store_package(token, ciphertext), fault);
    (classify_store(&outcomes), post)
}

pub fn redeem_package(
    d: &Db,
    token: String,
    utf8_valid: bool,
    fault: Option<usize>,
) -> (RedeemObservation, Db) {
    let (outcome, post) = run_take(d, &plan_redeem_package(token), fault);
    (classify_redeem(&outcome, utf8_valid), post)
}

pub fn store_grant(
    d: &Db,
    grant_id: String,
    user_id: String,
    device_id: String,
    fault: Option<usize>,
) -> (StoreObservation, Db) {
    let (outcomes, post) = run_writes(d, &plan_store_grant(grant_id, user_id, device_id), fault);
    (classify_store(&outcomes), post)
}

pub fn claim_check_for(
    d: &Db,
    grant_id: String,
    grant_live: bool,
    ek_len: usize,
    vk_len: usize,
    fault: Option<usize>,
) -> (crate::ClaimObservation, Db) {
    let (outcomes, post) = run_reads(d, &plan_claim_check(grant_id), fault);
    (
        classify_claim_check(grant_live, ek_len, vk_len, &outcomes),
        post,
    )
}

pub fn claim_write(
    d: &Db,
    grant_id: String,
    hybrid_ek: String,
    hybrid_vk: String,
    device_name: Option<String>,
    device_type: Option<String>,
    fault: Option<usize>,
) -> (ClaimWriteObservation, Db) {
    let (outcomes, post) = run_writes(
        d,
        &plan_claim_write(grant_id, hybrid_ek, hybrid_vk, device_name, device_type),
        fault,
    );
    (classify_claim_write(&outcomes), post)
}

pub fn account_read(
    d: &Db,
    user_id: String,
    declared_epoch_positive: bool,
    rekey_permitted: bool,
    fault: Option<usize>,
) -> (CompletionAccountObservation, (i64, bool), Db) {
    let (outcomes, post) = run_reads(d, &plan_account_read(user_id), fault);
    (
        classify_account(&outcomes, declared_epoch_positive, rekey_permitted),
        account_fields(&outcomes),
        post,
    )
}

pub fn completion_preflight(
    d: &Db,
    grant_id: String,
    device_id: String,
    user_id: String,
    verdicts: CompletionVerdicts,
    fault: Option<usize>,
) -> (CompletionPreflightObservation, Db) {
    let (outcomes, post) = run_reads(
        d,
        &plan_completion_preflight(grant_id, device_id, user_id),
        fault,
    );
    (classify_completion_preflight(&outcomes, verdicts), post)
}

pub fn take_ceremony(
    d: &Db,
    grant_id: String,
    grant_matches: bool,
    claim_matches: bool,
    fault: Option<usize>,
) -> (TakeObservation, Db) {
    let (outcome, post) = run_take_pair(d, &plan_take_ceremony(grant_id), fault);
    (
        classify_take_ceremony(&[outcome], grant_matches, claim_matches),
        post,
    )
}

pub fn completion_insert(
    d: &Db,
    stmt: PairingStmt,
    fault: Option<usize>,
) -> (DeviceInsertObservation, Db) {
    let plan = plan_from(stmt);
    let (outcomes, post) = run_writes(d, &plan, fault);
    (classify_insert_completion(&outcomes), post)
}

pub fn enroll_insert(
    d: &Db,
    stmt: PairingStmt,
    fault: Option<usize>,
) -> (crate::enroll_driver::InsertObservation, Db) {
    let plan = plan_from(stmt);
    let (outcomes, post) = run_writes(d, &plan, fault);
    (classify_insert_enroll(&outcomes), post)
}

/// A plan wrapper for the insert methods, whose statement is built by the
/// caller (the device row's fields are the method's inputs).
fn plan_from(stmt: PairingStmt) -> Vec<PairingStmt> {
    vec![stmt]
}

pub fn result_write(
    d: &Db,
    grant_id: String,
    device_id: String,
    hybrid_vk: String,
    fault: Option<usize>,
) -> (StoreObservation, Db) {
    let (outcomes, post) = run_writes(d, &plan_result_write(grant_id, device_id, hybrid_vk), fault);
    (classify_store(&outcomes), post)
}

pub fn result_read(
    d: &Db,
    grant_id: String,
    verdicts: CollectorVerdicts,
    fault: Option<usize>,
) -> (ResultReadObservation, Db) {
    let (outcomes, post) = run_reads(d, &plan_result_read(grant_id), fault);
    (classify_result_read(&outcomes, verdicts), post)
}

pub fn claim_read(
    d: &Db,
    grant_id: String,
    verdicts: CollectorVerdicts,
    fault: Option<usize>,
) -> (ClaimReadObservation, Db) {
    let (outcomes, post) = run_reads(d, &plan_claim_read(grant_id), fault);
    (classify_claim_read(&outcomes, verdicts), post)
}

pub fn enrolled_device(
    d: &Db,
    grant_id: String,
    verdicts: CollectorVerdicts,
    fault: Option<usize>,
) -> (DeviceGrantObservation, Db) {
    let (outcomes, post) = run_reads(d, &plan_device_by_grant(grant_id), fault);
    (classify_enrolled_device(&outcomes, verdicts), post)
}

pub fn active_device(
    d: &Db,
    device_id: String,
    verdict: EnrollAuthVerdict,
    fault: Option<usize>,
) -> (crate::enroll_driver::DeviceObservation, Db) {
    let (outcomes, post) = run_reads(d, &plan_active_device_read(device_id), fault);
    (classify_device_check(&outcomes, verdict), post)
}

pub fn challenge_take(
    d: &Db,
    challenge: String,
    purpose_matches: bool,
    fault: Option<usize>,
) -> (bool, Db) {
    let (outcome, post) = run_take(d, &plan_challenge_take(challenge), fault);
    (
        classify_challenge_take(&outcome, purpose_matches),
        post,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn base() -> Db {
        let mut d = Db::default();
        d.grants.insert(
            s("g"),
            GrantRow {
                user_id: s("u"),
                device_id: s("d"),
            },
        );
        d.claims.insert(
            s("g"),
            ClaimRow {
                hybrid_ek: s("ek"),
                hybrid_vk: s("vk"),
                device_name: Some(s("Phone")),
                device_type: None,
            },
        );
        d.results.insert(
            s("g"),
            ResultRow {
                device_id: s("dev"),
                hybrid_vk: s("vk"),
            },
        );
        d.users.insert(
            s("u"),
            UserRow {
                key_epoch: 3,
                rekey_state: None,
            },
        );
        d
    }

    /// The four vectors the F* module states as lemmas
    /// (`Vela_enrollment_policy_executor_lemmas.vector_*`).
    #[test]
    fn shared_vectors() {
        let d = base();
        // A claim lands while the grant is live.
        let mut fresh = d.clone();
        fresh.claims.clear();
        let (obs, post) = claim_write(&fresh, s("g"), s("ek2"), s("vk2"), None, None, None);
        assert_eq!(obs, ClaimWriteObservation::Inserted);
        assert_eq!(post.claims[&s("g")].hybrid_ek, s("ek2"));
        // A second claim loses.
        let (obs, post) = claim_write(&d, s("g"), s("ek3"), s("vk3"), None, None, None);
        assert_eq!(obs, ClaimWriteObservation::KeyExists);
        assert_eq!(post, d);
        // Without the grant, the guarded write refuses and writes nothing.
        let mut empty = d.clone();
        empty.grants.clear();
        let (obs, post) = claim_write(&empty, s("g"), s("ek"), s("vk"), None, None, None);
        assert_eq!(obs, ClaimWriteObservation::GuardMissing);
        assert_eq!(post, empty);
        // The ceremony take is all-or-nothing.
        let (obs, post) = take_ceremony(&d, s("g"), true, true, None);
        assert_eq!(
            obs,
            TakeObservation::Taken {
                grant_matches: true,
                claim_matches: true
            }
        );
        assert!(!post.grants.contains_key(&s("g")));
        assert!(!post.claims.contains_key(&s("g")));
        let (obs, post) = take_ceremony(&empty, s("g"), true, true, None);
        assert_eq!(obs, TakeObservation::Missing);
        assert_eq!(post, empty);
    }
}
