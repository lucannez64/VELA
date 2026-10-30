//! Rust mirror of the F* models in
//! `proofs/fstar/redemption-lemmas/Vela_recovery_policy_redemption_model.fst`
//! and `proofs/fstar/share-lemmas/Vela_recovery_policy_share_model.fst`.
//!
//! The server's conformance test runs the real enrollment and recovery-share
//! executors against a real database and a real key-value store and compares
//! the tables, the grant keys, the share row and the observation with what
//! these models predict. The F* modules prove the plans and classifiers
//! against the same semantics. Each function here has a namesake there with the
//! same case order; keep them in step. `tests::shared_vectors` and
//! `tests::shared_share_vectors` check the concrete runs the F* `vector_*`
//! lemmas prove from the general theorems.
//!
//! Only the columns and keys the redemption statements read or write are
//! modelled. `users` and `devices` are keyed by their `UNIQUE` id column and
//! the enrollment-grant store by its key, so a missing key is a missing row.
//! An empty `recovery_auth_hash` is modelled as an absent commitment: both
//! the insert guard and the authority recheck treat `''` as no commitment.

use std::collections::BTreeMap;

use crate::driver::{AuthorityRecheckObservation, ConsumptionObservation, InsertObservation};
use crate::recovery_share_driver::{
    DeleteUpdateObservation, FinalizeAccountObservation, FinalizeUpdateObservation, ReadObservation,
    StageAccountObservation, StageUpdateObservation,
};
use crate::redemption_store::{
    self, AuthorityRowView, GrantGuard, GrantTake, GrantView, ReadOutcome, RedemptionStmt,
    WriteOutcome,
};
use crate::share_store::{
    self, FinalizeAccountRowView, ShareRowView, ShareStmt, StageAccountRowView,
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

// ── Recovery share model ───────────────────────────────────────────────────

/// The modelled columns of a `users` row for the recovery-share lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareUserRow {
    pub epoch: i64,
    pub rekey: bool,
    /// `recovery_share`.
    pub share: Option<String>,
    /// `recovery_split_id`.
    pub split: Option<String>,
    /// `recovery_pending_share`.
    pub pending_share: Option<String>,
    /// `recovery_pending_split_id`.
    pub pending_split: Option<String>,
    /// `recovery_pending_epoch`.
    pub pending_epoch: Option<i64>,
    /// `recovery_auth_hash`.
    pub auth: Option<String>,
    /// `recovery_pending_auth_hash`.
    pub pending_auth: Option<String>,
}

/// The modelled state for the recovery-share lifecycle: one `users` table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareDb {
    pub users: BTreeMap<String, ShareUserRow>,
}

/// The stage update's SQL guard: the row exists, its epoch matches, no rotation
/// is active and neither the active share nor its split is published.
pub fn stage_guard(db: &ShareDb, user: &str, epoch: i64) -> bool {
    match db.users.get(user) {
        None => false,
        Some(row) => row.epoch == epoch && !row.rekey && row.share.is_none() && row.split.is_none(),
    }
}

/// The promote update's SQL guard: the exact staged split is present with its
/// share and commitment, at the current epoch, outside rotation, with no
/// active share or split.
pub fn promote_guard(db: &ShareDb, user: &str, epoch: i64, split_id: &str) -> bool {
    match db.users.get(user) {
        None => false,
        Some(row) => {
            row.epoch == epoch
                && !row.rekey
                && row.pending_epoch == Some(epoch)
                && row.pending_split.as_deref() == Some(split_id)
                && row.pending_share.is_some()
                && row.pending_auth.is_some()
                && row.share.is_none()
                && row.split.is_none()
        }
    }
}

/// The delete update's SQL guard: the row exists at the current epoch with no
/// rotation active.
pub fn delete_guard(db: &ShareDb, user: &str, epoch: i64) -> bool {
    match db.users.get(user) {
        None => false,
        Some(row) => row.epoch == epoch && !row.rekey,
    }
}

/// One write statement on a share state. Reads are not writes. F*: `share_exec`.
pub fn share_exec(db: &ShareDb, stmt: &ShareStmt) -> Option<(u64, ShareDb)> {
    let mut next = db.clone();
    match stmt {
        ShareStmt::StageShare { user, share, split_id, epoch, auth_hash } => {
            let Some(row) = db.users.get(user) else {
                return Some((0, next));
            };
            if !stage_guard(db, user, *epoch) {
                return Some((0, next));
            }
            let mut staged = row.clone();
            staged.pending_share = Some(share.clone());
            staged.pending_split = Some(split_id.clone());
            staged.pending_epoch = Some(*epoch);
            staged.pending_auth = Some(auth_hash.clone());
            next.users.insert(user.clone(), staged);
            Some((1, next))
        }
        ShareStmt::PromoteStagedSplit { user, epoch, split_id } => {
            let Some(row) = db.users.get(user) else {
                return Some((0, next));
            };
            if !promote_guard(db, user, *epoch, split_id) {
                return Some((0, next));
            }
            let mut promoted = row.clone();
            promoted.share = row.pending_share.clone();
            promoted.split = row.pending_split.clone();
            promoted.auth = row.pending_auth.clone();
            promoted.pending_share = None;
            promoted.pending_split = None;
            promoted.pending_epoch = None;
            promoted.pending_auth = None;
            next.users.insert(user.clone(), promoted);
            Some((1, next))
        }
        ShareStmt::DeleteShare { user, epoch } => {
            let Some(row) = db.users.get(user) else {
                return Some((0, next));
            };
            if !delete_guard(db, user, *epoch) {
                return Some((0, next));
            }
            let mut cleared = row.clone();
            cleared.share = None;
            cleared.split = None;
            cleared.pending_share = None;
            cleared.pending_split = None;
            cleared.pending_epoch = None;
            cleared.auth = None;
            cleared.pending_auth = None;
            next.users.insert(user.clone(), cleared);
            Some((1, next))
        }
        _ => None,
    }
}

/// A share write plan run statement by statement, stopping at the first
/// failure. F*: `run_share_autocommit`.
pub fn run_share_autocommit(
    pre: &ShareDb,
    plan: &[ShareStmt],
    fault: Option<usize>,
) -> (Vec<WriteOutcome>, ShareDb) {
    let mut db = pre.clone();
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, db);
        }
        match share_exec(&db, stmt) {
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

/// `PutShareIo::stage_share`. F*: `stage_share`.
pub fn stage_share(
    db: &ShareDb,
    user: &str,
    share: &str,
    split_id: &str,
    epoch: i64,
    auth_hash: &str,
    fault: Option<usize>,
) -> Option<(StageUpdateObservation, ShareDb)> {
    let plan = share_store::plan_stage_share(
        user.to_string(),
        share.to_string(),
        split_id.to_string(),
        epoch,
        auth_hash.to_string(),
    );
    let (outcomes, post) = run_share_autocommit(db, &plan, fault);
    match outcomes.first() {
        Some(WriteOutcome::Failed) => None,
        _ => Some((share_store::classify_stage_update(&outcomes), post)),
    }
}

/// `FinalizeShareIo::promote_staged_split`. F*: `promote_staged_split`.
pub fn promote_staged_split(
    db: &ShareDb,
    user: &str,
    epoch: i64,
    split_id: &str,
    fault: Option<usize>,
) -> Option<(FinalizeUpdateObservation, ShareDb)> {
    let plan = share_store::plan_promote_staged_split(
        user.to_string(),
        epoch,
        split_id.to_string(),
    );
    let (outcomes, post) = run_share_autocommit(db, &plan, fault);
    match outcomes.first() {
        Some(WriteOutcome::Failed) => None,
        _ => Some((share_store::classify_finalize_update(&outcomes), post)),
    }
}

/// `DeleteShareIo::delete_share`. F*: `delete_share`.
pub fn delete_share(
    db: &ShareDb,
    user: &str,
    epoch: i64,
    fault: Option<usize>,
) -> Option<(DeleteUpdateObservation, ShareDb)> {
    let plan = share_store::plan_delete_share(user.to_string(), epoch);
    let (outcomes, post) = run_share_autocommit(db, &plan, fault);
    match outcomes.first() {
        Some(WriteOutcome::Failed) => None,
        _ => Some((share_store::classify_delete_update(&outcomes), post)),
    }
}

/// `PutShareIo::stage_query_account`. F*: `stage_account`.
pub fn stage_account(
    db: &ShareDb,
    user: &str,
    share: &str,
    split_id: &str,
    failed: bool,
) -> Option<StageAccountObservation> {
    if failed {
        return None;
    }
    let row = db.users.get(user).map(|row| StageAccountRowView {
        stored_epoch: Some(row.epoch),
        rotation_active: row.rekey,
        active_share: row.share.clone(),
        active_split: row.split.clone(),
    });
    Some(share_store::classify_stage_account(row, &share.to_string(), &split_id.to_string()))
}

/// `FinalizeShareIo::finalize_query_account`. F*: `finalize_account`.
pub fn finalize_account(
    db: &ShareDb,
    user: &str,
    split_id: &str,
    failed: bool,
) -> Option<FinalizeAccountObservation> {
    if failed {
        return None;
    }
    let row = db.users.get(user).map(|row| FinalizeAccountRowView {
        stored_epoch: Some(row.epoch),
        rotation_active: row.rekey,
        active_split: row.split.clone(),
    });
    Some(share_store::classify_finalize_account(row, &split_id.to_string()))
}

/// `GetShareIo::read_share`. F*: `read_share`.
pub fn read_share(db: &ShareDb, user: &str, failed: bool) -> Option<ReadObservation> {
    if failed {
        return None;
    }
    let row = db.users.get(user).map(|row| ShareRowView {
        share: row.share.clone(),
        split_id: row.split.clone(),
        epoch: Some(row.epoch),
    });
    Some(share_store::classify_read_share(row))
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

    fn share_row(epoch: i64, rekey: bool) -> ShareUserRow {
        ShareUserRow {
            epoch,
            rekey,
            share: None,
            split: None,
            pending_share: None,
            pending_split: None,
            pending_epoch: None,
            auth: None,
            pending_auth: None,
        }
    }

    /// The F* lemmas `vector_share_*` prove the same runs.
    #[test]
    fn shared_share_vectors() {
        let mut pre = ShareDb::default();
        pre.users.insert(s("u"), share_row(7, false));

        // vector_share_stage: the guard holds and the candidate is staged.
        let (obs, staged) = stage_share(&pre, "u", "sh", "sp", 7, "au", None).unwrap();
        assert_eq!(obs, StageUpdateObservation::Staged);
        let row = staged.users.get("u").unwrap();
        assert_eq!(row.pending_share.as_deref(), Some("sh"));
        assert_eq!(row.pending_split.as_deref(), Some("sp"));
        assert_eq!(row.pending_epoch, Some(7));
        assert_eq!(row.pending_auth.as_deref(), Some("au"));
        assert!(row.share.is_none());

        // vector_share_promote: the staged split becomes active.
        let (obs, promoted) = promote_staged_split(&staged, "u", 7, "sp", None).unwrap();
        assert_eq!(obs, FinalizeUpdateObservation::Promoted);
        let row = promoted.users.get("u").unwrap();
        assert_eq!(row.share.as_deref(), Some("sh"));
        assert_eq!(row.split.as_deref(), Some("sp"));
        assert_eq!(row.auth.as_deref(), Some("au"));
        assert!(row.pending_share.is_none());

        // vector_share_delete: everything is cleared.
        let (obs, cleared) = delete_share(&promoted, "u", 7, None).unwrap();
        assert_eq!(obs, DeleteUpdateObservation::Deleted);
        let row = cleared.users.get("u").unwrap();
        assert!(row.share.is_none() && row.split.is_none() && row.auth.is_none());

        // vector_share_stale_epoch: the stage update refuses.
        let (obs, post) = stage_share(&pre, "u", "sh", "sp", 8, "au", None).unwrap();
        assert_eq!(obs, StageUpdateObservation::NotStaged);
        assert_eq!(post, pre);

        // vector_share_read: a stored share is visible.
        let mut stored = pre.clone();
        stored.users.get_mut("u").unwrap().share = Some(s("sh"));
        assert_eq!(
            read_share(&stored, "u", false),
            Some(ReadObservation { account_present: true, share_present: true })
        );
        assert_eq!(
            read_share(&pre, "missing", false),
            Some(ReadObservation { account_present: false, share_present: false })
        );

        // vector_share_stage_account.
        let observation = stage_account(&stored, "u", "sh", "sp", false).unwrap();
        assert!(observation.account_present && observation.active_share_matches);
        assert!(!observation.active_split_matches);
    }
}
