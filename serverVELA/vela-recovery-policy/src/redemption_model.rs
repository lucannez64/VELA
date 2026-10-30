//! Rust mirror of the F* model in
//! `proofs/fstar/redemption-lemmas/Vela_recovery_policy_redemption_model.fst`.
//!
//! The server's conformance test runs the real enrollment executor against a
//! real database and a real key-value store and compares the tables, the
//! grant keys and the observation with what this model predicts. The F*
//! module proves the plans and classifiers against the same semantics. Each
//! function here has a namesake there with the same case order; keep them in
//! step. `tests::shared_vectors` checks the concrete runs the F* `vector_*`
//! lemmas prove from the general theorems.
//!
//! Only the columns and keys the redemption statements read or write are
//! modelled. `users` and `devices` are keyed by their `UNIQUE` id column and
//! the enrollment-grant store by its key, so a missing key is a missing row.
//! An empty `recovery_auth_hash` is modelled as an absent commitment: both
//! the insert guard and the authority recheck treat `''` as no commitment.

use std::collections::BTreeMap;

use crate::driver::{AuthorityRecheckObservation, ConsumptionObservation, InsertObservation};
use crate::redemption_store::{
    self, AuthorityRowView, GrantGuard, GrantTake, GrantView, ReadOutcome, RedemptionStmt,
    WriteOutcome,
};

/// The modelled columns of a `users` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRow {
    pub epoch: i64,
    pub rekey: bool,
    /// `recovery_webauthn_cred_id`.
    pub credential_id: Option<String>,
    /// `recovery_auth_hash`, normalized: `Some` exactly when non-empty.
    pub auth_hash: Option<String>,
}

/// The columns a recovered-device insert writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRow {
    pub user: String,
    pub name: String,
    pub kind: String,
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub created_at: String,
}

/// The modelled state: `users`, `devices` and the enrollment-grant store.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Db {
    pub users: BTreeMap<String, UserRow>,
    pub devices: BTreeMap<String, DeviceRow>,
    pub grants: BTreeMap<String, GrantView>,
}

/// The SQL guard of the recovered-device insert: the user row exists, its
/// epoch matches, no rotation is active, and the grant's live authority is
/// still present.
pub fn insert_guard(db: &Db, user: &str, epoch: i64, guard: &GrantGuard) -> bool {
    match db.users.get(user) {
        None => false,
        Some(row) => {
            row.epoch == epoch
                && !row.rekey
                && match guard {
                    GrantGuard::Credential { credential_id } => {
                        row.credential_id.as_deref() == Some(credential_id.as_str())
                    }
                    GrantGuard::Commitment => row.auth_hash.is_some(),
                }
        }
    }
}

/// One write statement on a state, or `None` when it errors (a duplicate
/// device id, or a read/take passed where a write is expected). F*: `exec`.
pub fn exec(db: &Db, stmt: &RedemptionStmt) -> Option<(u64, Db)> {
    let mut next = db.clone();
    match stmt {
        RedemptionStmt::PutGrant { key, grant, .. } => {
            next.grants.insert(key.clone(), grant.clone());
            Some((1, next))
        }
        RedemptionStmt::InsertDevice {
            device_id,
            user,
            device_name,
            device_type,
            hybrid_ek,
            hybrid_vk,
            created_at,
            epoch,
            guard,
        } => {
            if db.devices.contains_key(device_id) {
                return None;
            }
            if insert_guard(db, user, *epoch, guard) {
                next.devices.insert(
                    device_id.clone(),
                    DeviceRow {
                        user: user.clone(),
                        name: device_name.clone(),
                        kind: device_type.clone(),
                        hybrid_ek: hybrid_ek.clone(),
                        hybrid_vk: hybrid_vk.clone(),
                        created_at: created_at.clone(),
                    },
                );
                Some((1, next))
            } else {
                Some((0, next))
            }
        }
        RedemptionStmt::TakeGrant { .. } | RedemptionStmt::SelectAuthority { .. } => None,
    }
}

fn faulted(fault: Option<usize>, k: usize) -> bool {
    fault == Some(k)
}

/// The atomic single-use take: `Some((taken, post))`, or `None` when the
/// injected fault fires before the store runs. F*: `run_take`.
pub fn run_take(db: &Db, stmt: &RedemptionStmt, fault: Option<usize>) -> Option<(GrantTake, Db)> {
    if faulted(fault, 0) {
        return None;
    }
    match stmt {
        RedemptionStmt::TakeGrant { key } => match db.grants.get(key).cloned() {
            Some(grant) => {
                let mut next = db.clone();
                next.grants.remove(key);
                Some((GrantTake::Taken(grant), next))
            }
            None => Some((GrantTake::Missing, db.clone())),
        },
        _ => None,
    }
}

/// A plan run statement by statement on the pool, stopping at the first
/// failure. F*: `run_autocommit`.
pub fn run_autocommit(
    pre: &Db,
    plan: &[RedemptionStmt],
    fault: Option<usize>,
) -> (Vec<WriteOutcome>, Db) {
    let mut db = pre.clone();
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, db);
        }
        match exec(&db, stmt) {
            Some((rows, next)) => {
                outcomes.push(WriteOutcome::Applied(rows));
                db = next;
            }
            None => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, db);
            }
        }
    }
    (outcomes, db)
}

/// `SelectAuthority` on a state; `failed` injects a read error. F*:
/// `read_authority`.
pub fn read_authority(
    db: &Db,
    stmt: &RedemptionStmt,
    failed: bool,
) -> ReadOutcome<AuthorityRowView> {
    match stmt {
        RedemptionStmt::SelectAuthority { user } if !failed => ReadOutcome::Row(db.users.get(user).map(
            |row| AuthorityRowView {
                credential_id: row.credential_id.clone(),
                auth_hash: row.auth_hash.clone(),
            },
        )),
        _ => ReadOutcome::Failed,
    }
}

/// `EnrollDeviceIo::consume_grant`. F*: `take_grant`.
pub fn take_grant(
    db: &Db,
    key: &str,
    preflight: &GrantView,
    fault: Option<usize>,
) -> Option<(ConsumptionObservation, Db)> {
    let (taken, post) = run_take(db, &redemption_store::plan_take_grant(key.to_string()), fault)?;
    Some((redemption_store::classify_take(&taken, preflight), post))
}

/// `EnrollDeviceIo::insert_device`. F*: `insert_device`.
#[allow(clippy::too_many_arguments)]
pub fn insert_device(
    db: &Db,
    device_id: &str,
    user: &str,
    name: &str,
    kind: &str,
    hybrid_ek: &str,
    hybrid_vk: &str,
    created_at: &str,
    epoch: i64,
    guard: &GrantGuard,
    fault: Option<usize>,
) -> (InsertObservation, Db) {
    let plan = redemption_store::plan_insert_device(
        device_id.to_string(),
        user.to_string(),
        name.to_string(),
        kind.to_string(),
        hybrid_ek.to_string(),
        hybrid_vk.to_string(),
        created_at.to_string(),
        epoch,
        guard.clone(),
    );
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    (redemption_store::classify_insert(&outcomes), post)
}

/// `EnrollDeviceIo::recheck_authority`. F*: `recheck_authority`.
pub fn recheck_authority(
    db: &Db,
    user: &str,
    possession: bool,
    credential_id: &str,
    fault: Option<usize>,
) -> AuthorityRecheckObservation {
    redemption_store::classify_authority(
        &read_authority(
            db,
            &redemption_store::plan_authority_read(user.to_string()),
            faulted(fault, 0),
        ),
        possession,
        &credential_id.to_string(),
    )
}

/// `EnrollDeviceIo::restore_grant`: `Some(post)`, or `None` when the injected
/// fault fires. F*: `restore_grant`.
pub fn restore_grant(
    db: &Db,
    key: &str,
    value: &str,
    grant: &GrantView,
    fault: Option<usize>,
) -> Option<Db> {
    let plan =
        redemption_store::plan_restore_grant(key.to_string(), value.to_string(), grant.clone());
    let (outcomes, post) = run_autocommit(db, &plan, fault);
    match outcomes.first() {
        Some(WriteOutcome::Applied(_)) => Some(post),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn user_row(epoch: i64, credential: Option<&str>, auth: Option<&str>) -> UserRow {
        UserRow {
            epoch,
            rekey: false,
            credential_id: credential.map(s),
            auth_hash: auth.map(s),
        }
    }

    /// The F* lemmas `vector_take_*`, `vector_insert_*` and `vector_authority_*`
    /// prove the same runs.
    #[test]
    fn shared_vectors() {
        let mut pre = Db::default();
        pre.users.insert(s("u"), user_row(7, Some("c"), Some("h")));
        pre.grants.insert(
            s("k"),
            GrantView { key_epoch: 7, credential_id: s("c"), possession: false },
        );
        let preflight = GrantView { key_epoch: 7, credential_id: s("c"), possession: false };

        // vector_take_present: the exact live grant is removed and matches.
        let (obs, post) = take_grant(&pre, "k", &preflight, None).unwrap();
        assert_eq!(
            obs,
            ConsumptionObservation::Present(crate::driver::ConsumedGrantObservation {
                key_epoch: 7,
                possession: false,
                matches_observed_grant: true,
            })
        );
        assert!(post.grants.is_empty());
        // vector_take_missing: no live grant.
        let (obs, post) = take_grant(&pre, "other", &preflight, None).unwrap();
        assert_eq!(obs, ConsumptionObservation::Missing);
        assert_eq!(post, pre);

        // vector_insert_credential: the guard holds, one row lands.
        let (obs, post) = insert_device(
            &pre,
            "d",
            "u",
            "name",
            "kind",
            "ek",
            "vk",
            "t",
            7,
            &GrantGuard::Credential { credential_id: s("c") },
            None,
        );
        assert_eq!(obs, InsertObservation::Inserted);
        assert_eq!(post.devices.len(), 1);
        // vector_insert_stale_epoch: a stale epoch skips the insert.
        let (obs, post) = insert_device(
            &pre,
            "d",
            "u",
            "name",
            "kind",
            "ek",
            "vk",
            "t",
            8,
            &GrantGuard::Credential { credential_id: s("c") },
            None,
        );
        assert_eq!(obs, InsertObservation::Skipped);
        assert_eq!(post, pre);

        // vector_authority_rotating / vector_authority_absent.
        assert_eq!(
            recheck_authority(&pre, "u", false, "c", None),
            AuthorityRecheckObservation::StillRotating
        );
        assert_eq!(
            recheck_authority(&pre, "missing", false, "c", None),
            AuthorityRecheckObservation::AccountAbsent
        );

        // vector_restore_grant.
        let empty = Db::default();
        let post = restore_grant(&empty, "k", "{\"key_epoch\":7}", &preflight, None).unwrap();
        assert_eq!(post.grants.get("k"), Some(&preflight));
    }
}
