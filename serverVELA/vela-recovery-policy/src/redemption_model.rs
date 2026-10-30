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
use crate::possession_driver::{
    AttemptConsumptionObservation, ChallengeStoreObservation, CommitmentObservation,
    GrantStoreObservation, InitiateObservation, ProofAccountObservation,
};
use crate::possession_store::{
    self, EnrollmentGrantView, InitiateRowView, PossessionStmt, ProofAccountRowView,
    ProofAttemptTake, ProofAttemptView,
};
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
use crate::webauthn_driver::{
    AuthAccountObservation, AuthAttemptConsumptionObservation, AuthFinishContextObservation,
    AuthStartObservation, ChallengeStoreObservation as WebAuthnChallengeStoreObservation,
    CredentialPersistObservation, CredentialUniquenessObservation,
    CredentialUpdateStoreObservation, GrantStoreObservation as WebAuthnGrantStoreObservation,
    RegistrationStartObservation, RegistrationStateObservation, ShareDecodeObservation,
    StoredCredentialObservation,
};
use crate::webauthn_store::{
    self, AuthStateTake, AuthStateView, CredentialGrantView, CredentialHolderView,
    CredentialRowView, FinishAccountRowView, RegistrationStateTake, SetNxOutcome, SetOutcome,
    ShareRowView as WebAuthnShareRowView,
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

// ── Possession-proof model ─────────────────────────────────────────────────

/// The modelled `users` row for the possession executors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PossessionUserRow {
    /// `recovery_share` is present and non-NULL.
    pub share: bool,
    /// `recovery_auth_hash`, already decoded.
    pub commitment: CommitmentObservation,
    /// `key_epoch` as stored; `None` when the column is absent.
    pub epoch: Option<i64>,
    /// `rekey_state` is set.
    pub rekey: bool,
}

/// One challenge-slot value: a decoded attempt, or bytes that do not decode.
/// Absence is the second map's missing key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptCell {
    Valid(ProofAttemptView),
    Undecodable,
}

/// The modelled state: the `users` row, the single-use proof-attempt slots and
/// the enrollment-grant store.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PossessionDb {
    pub users: BTreeMap<String, PossessionUserRow>,
    pub challenges: BTreeMap<String, AttemptCell>,
    pub grants: BTreeMap<String, EnrollmentGrantView>,
}

fn possession_user<'a>(db: &'a PossessionDb, user: &str) -> Option<&'a PossessionUserRow> {
    db.users.get(user)
}

/// Whether the exact proof-slot key is occupied. F*: `slot_occupied`.
pub fn slot_occupied(db: &PossessionDb, key: &str) -> bool {
    db.challenges.contains_key(key)
}

/// `InitiateProofIo::observe`'s account read. F*: `read_initiate_account`.
pub fn read_initiate_account(
    db: &PossessionDb,
    stmt: &PossessionStmt,
    failed: bool,
) -> ReadOutcome<InitiateRowView> {
    match stmt {
        PossessionStmt::SelectInitiateAccount { user } if !failed => ReadOutcome::Row(
            possession_user(db, user).map(|row| InitiateRowView {
                share_present: row.share,
                commitment: row.commitment,
                key_epoch: row.epoch,
                rotation_active: row.rekey,
            }),
        ),
        _ => ReadOutcome::Failed,
    }
}

/// `InitiateProofIo::observe`'s slot probe. F*: `probe_slot`.
pub fn probe_slot(
    db: &PossessionDb,
    stmt: &PossessionStmt,
    failed: bool,
) -> ReadOutcome<bool> {
    match stmt {
        PossessionStmt::ProofSlotExists { key } if !failed => {
            ReadOutcome::Row(Some(slot_occupied(db, key)))
        }
        _ => ReadOutcome::Failed,
    }
}

/// `InitiateProofIo::observe`. F*: `initiate_observation`.
pub fn initiate_observation(
    db: &PossessionDb,
    user: &str,
    key: &str,
    ttl_secs: u64,
    sql_fault: Option<usize>,
    kv_fault: Option<usize>,
) -> Option<(InitiateObservation, PossessionDb)> {
    let row = match read_initiate_account(
        db,
        &possession_store::plan_initiate_account(user.to_string()),
        faulted(sql_fault, 0),
    ) {
        ReadOutcome::Row(row) => row,
        ReadOutcome::Failed => return None,
    };
    let occupied = match probe_slot(
        db,
        &possession_store::plan_proof_slot(key.to_string()),
        faulted(kv_fault, 0),
    ) {
        ReadOutcome::Row(Some(occupied)) => occupied,
        _ => return None,
    };
    Some((
        possession_store::classify_initiate(row, occupied, ttl_secs),
        db.clone(),
    ))
}

/// `InitiateProofIo::observe`'s epoch side channel. F*: `initiate_epoch_of`.
pub fn initiate_epoch_of(
    db: &PossessionDb,
    user: &str,
    failed: bool,
) -> i64 {
    let row = match read_initiate_account(
        db,
        &possession_store::plan_initiate_account(user.to_string()),
        failed,
    ) {
        ReadOutcome::Row(row) => row,
        ReadOutcome::Failed => None,
    };
    possession_store::initiate_epoch(&row)
}

/// `InitiateProofIo::store_challenge`. F*: `store_challenge`.
pub fn store_challenge(
    db: &PossessionDb,
    key: &str,
    value: &str,
    attempt: &ProofAttemptView,
    ttl_secs: u64,
    kv_fault: Option<usize>,
) -> Option<(ChallengeStoreObservation, PossessionDb)> {
    match possession_store::plan_store_challenge(
        key.to_string(),
        value.to_string(),
        attempt.clone(),
        ttl_secs,
    ) {
        PossessionStmt::StoreProofChallenge { key, attempt, .. } => {
            if faulted(kv_fault, 0) {
                return None;
            }
            let mut next = db.clone();
            if slot_occupied(db, &key) {
                Some((possession_store::classify_store_challenge(false), next))
            } else {
                next.challenges.insert(key, AttemptCell::Valid(attempt));
                Some((possession_store::classify_store_challenge(true), next))
            }
        }
        _ => None,
    }
}

/// `RecoverProofIo::consume_attempt`. F*: `take_attempt`.
pub fn take_attempt(
    db: &PossessionDb,
    key: &str,
    user: &str,
    attempt: &str,
    kv_fault: Option<usize>,
) -> Option<(AttemptConsumptionObservation, PossessionDb)> {
    match possession_store::plan_take_attempt(key.to_string()) {
        PossessionStmt::TakeProofAttempt { key } => {
            if faulted(kv_fault, 0) {
                return None;
            }
            let mut next = db.clone();
            let taken = match db.challenges.get(&key) {
                None => ProofAttemptTake::Missing,
                Some(AttemptCell::Undecodable) => ProofAttemptTake::Corrupt,
                Some(AttemptCell::Valid(state)) => ProofAttemptTake::Present(state.clone()),
            };
            next.challenges.remove(&key);
            Some((
                possession_store::classify_attempt(&taken, &user.to_string(), &attempt.to_string()),
                next,
            ))
        }
        _ => None,
    }
}

/// `RecoverProofIo::query_account`. F*: `proof_account`.
pub fn proof_account(
    db: &PossessionDb,
    user: &str,
    sql_fault: Option<usize>,
) -> Option<ProofAccountObservation> {
    match possession_store::plan_proof_account(user.to_string()) {
        PossessionStmt::SelectProofAccount { user } => {
            if faulted(sql_fault, 0) {
                return None;
            }
            let row = possession_user(db, &user).map(|row| ProofAccountRowView {
                commitment: row.commitment,
                stored_epoch: row.epoch,
                rotation_active: row.rekey,
            });
            Some(possession_store::classify_proof_account(row))
        }
        _ => None,
    }
}

/// `RecoverProofIo::issue_grant`. F*: `issue_grant`.
pub fn issue_grant(
    db: &PossessionDb,
    key: &str,
    value: &str,
    grant: &EnrollmentGrantView,
    ttl_secs: u64,
    kv_fault: Option<usize>,
) -> (GrantStoreObservation, PossessionDb) {
    match possession_store::plan_issue_grant(
        key.to_string(),
        value.to_string(),
        grant.clone(),
        ttl_secs,
    ) {
        PossessionStmt::PutEnrollmentGrant { key, grant, .. } => {
            if faulted(kv_fault, 0) {
                return (possession_store::classify_grant_store(false), db.clone());
            }
            let mut next = db.clone();
            next.grants.insert(key, grant);
            (possession_store::classify_grant_store(true), next)
        }
        _ => (possession_store::classify_grant_store(false), db.clone()),
    }
}


// ── WebAuthn recovery model ────────────────────────────────────────────────
//
// Mirrors `proofs/fstar/webauthn-lemmas/Vela_recovery_policy_webauthn_model.fst`
// function for function; `tests::shared_webauthn_vectors` checks the same
// concrete runs the F* `vector_webauthn_*` lemmas prove from the general
// theorems.

/// A stored credential cell: absent, a decoded credential id, or
/// present-but-undecodable JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialCell {
    Absent,
    Valid(String),
    Undecodable,
}

/// The modelled `users` columns the WebAuthn executors read or write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAuthnUserRow {
    pub share: Option<String>,
    pub credential: CredentialCell,
    pub credential_id: Option<String>,
    pub epoch: Option<i64>,
    pub rekey: bool,
    pub split: Option<String>,
}

/// One attempt slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebAuthnAttemptCell {
    Absent,
    Valid(AuthStateView),
    Undecodable,
}

/// One registration slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebAuthnRegistrationCell {
    Absent,
    Valid,
    Undecodable,
}

/// The modelled state of the WebAuthn executors.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WebAuthnDb {
    pub users: BTreeMap<String, WebAuthnUserRow>,
    pub attempts: BTreeMap<String, WebAuthnAttemptCell>,
    pub registrations: BTreeMap<String, WebAuthnRegistrationCell>,
    pub grants: BTreeMap<String, CredentialGrantView>,
    /// credential id -> the account holding it.
    pub holders: BTreeMap<String, String>,
}

fn wfault(fault: Option<usize>, k: usize) -> bool {
    fault == Some(k)
}

/// A stored credential cell as the handler's row view reports it.
pub fn credential_observation(cell: &CredentialCell) -> StoredCredentialObservation {
    match cell {
        CredentialCell::Absent => StoredCredentialObservation::Missing,
        CredentialCell::Valid(_) => StoredCredentialObservation::Present,
        CredentialCell::Undecodable => StoredCredentialObservation::Corrupt,
    }
}

/// The `recovery_share` row view.
pub fn webauthn_share_view(db: &WebAuthnDb, user: &str) -> WebAuthnShareRowView {
    match db.users.get(user) {
        None => WebAuthnShareRowView {
            account_present: false,
            share_present: false,
        },
        Some(row) => WebAuthnShareRowView {
            account_present: true,
            share_present: row.share.is_some(),
        },
    }
}

/// The stored-credential row view.
pub fn credential_view(db: &WebAuthnDb, user: &str) -> CredentialRowView {
    match db.users.get(user) {
        None => CredentialRowView {
            account_present: false,
            credential: StoredCredentialObservation::Missing,
        },
        Some(row) => CredentialRowView {
            account_present: true,
            credential: credential_observation(&row.credential),
        },
    }
}

/// Whether the exact attempt slot is occupied.
pub fn webauthn_slot_occupied(db: &WebAuthnDb, key: &str) -> bool {
    !matches!(
        db.attempts.get(key),
        None | Some(WebAuthnAttemptCell::Absent)
    )
}

/// The guarded credential update's SQL guard.
pub fn update_guard(db: &WebAuthnDb, user: &str, expected: &str) -> bool {
    db.users
        .get(user)
        .map(|row| row.credential_id.as_deref() == Some(expected))
        .unwrap_or(false)
}

/// Whether another account holds the credential id.
pub fn holder_other(db: &WebAuthnDb, credential_id: &str, user: &str) -> bool {
    db.holders
        .get(credential_id)
        .map(|owner| owner != user)
        .unwrap_or(false)
}

fn row_share_present(db: &WebAuthnDb, user: &str) -> bool {
    db.users.get(user).map(|row| row.share.is_some()).unwrap_or(false)
}

fn row_credential_matches(db: &WebAuthnDb, user: &str, credential_id: &str) -> bool {
    db.users
        .get(user)
        .map(|row| row.credential_id.as_deref() == Some(credential_id))
        .unwrap_or(false)
}

fn row_epoch(db: &WebAuthnDb, user: &str) -> Option<i64> {
    db.users.get(user).and_then(|row| row.epoch)
}

fn row_rekeying(db: &WebAuthnDb, user: &str) -> bool {
    db.users.get(user).map(|row| row.rekey).unwrap_or(false)
}

fn row_split(db: &WebAuthnDb, user: &str) -> Option<String> {
    db.users.get(user).and_then(|row| row.split.clone())
}

fn row_credential_id(db: &WebAuthnDb, user: &str) -> Option<String> {
    db.users.get(user).and_then(|row| row.credential_id.clone())
}

fn finish_account_view(row: &WebAuthnUserRow) -> FinishAccountRowView {
    FinishAccountRowView {
        share: row.share.clone(),
        stored_epoch: row.epoch,
        rotation_active: row.rekey,
        stored_credential_id: row.credential_id.clone(),
        split_id: row.split.clone(),
    }
}

fn rebind(holders: &mut BTreeMap<String, String>, owner: &str, old: Option<&str>, new_id: &str) {
    if let Some(old) = old {
        holders.remove(old);
    }
    holders.insert(new_id.to_string(), owner.to_string());
}

/// `InitiateIo::auth_start_observe`.
pub fn auth_start_observe(
    db: &WebAuthnDb,
    user: &str,
    slot: &str,
    ttl: u64,
    sql_fault: Option<usize>,
    kv_fault: Option<usize>,
) -> Option<(AuthStartObservation, WebAuthnDb)> {
    if wfault(sql_fault, 0) {
        return None;
    }
    let share = webauthn_share_view(db, user);
    if wfault(sql_fault, 1) {
        return None;
    }
    let credential = credential_view(db, user);
    if wfault(kv_fault, 0) {
        return None;
    }
    Some((
        webauthn_store::classify_auth_start(
            &share,
            &credential,
            webauthn_slot_occupied(db, slot),
            ttl,
        ),
        db.clone(),
    ))
}

/// `InitiateIo::auth_start_store`.
pub fn store_auth_state(
    db: &WebAuthnDb,
    key: &str,
    _value: &str,
    state: &AuthStateView,
    _ttl: u64,
    kv_fault: Option<usize>,
) -> (WebAuthnChallengeStoreObservation, WebAuthnDb) {
    if wfault(kv_fault, 0) {
        return (
            webauthn_store::classify_store_auth_state(&SetNxOutcome::Failed),
            db.clone(),
        );
    }
    if webauthn_slot_occupied(db, key) {
        return (
            webauthn_store::classify_store_auth_state(&SetNxOutcome::Occupied),
            db.clone(),
        );
    }
    let mut post = db.clone();
    post.attempts
        .insert(key.to_string(), WebAuthnAttemptCell::Valid(state.clone()));
    (
        webauthn_store::classify_store_auth_state(&SetNxOutcome::Wrote),
        post,
    )
}

/// `RecoverIo::auth_finish_context`.
pub fn finish_context(
    db: &WebAuthnDb,
    user: &str,
    attempt_id_present: bool,
    sql_fault: Option<usize>,
) -> Option<AuthFinishContextObservation> {
    if wfault(sql_fault, 0) {
        return None;
    }
    let share = webauthn_share_view(db, user);
    if wfault(sql_fault, 1) {
        return None;
    }
    let credential = credential_view(db, user);
    Some(webauthn_store::classify_finish_context(
        &share,
        &credential,
        attempt_id_present,
    ))
}

/// `RecoverIo::auth_finish_consume`.
pub fn take_auth_state(
    db: &WebAuthnDb,
    key: &str,
    user: &str,
    attempt: &str,
    observed_credential_id: &str,
    kv_fault: Option<usize>,
) -> Option<(AuthAttemptConsumptionObservation, WebAuthnDb)> {
    if wfault(kv_fault, 0) {
        return None;
    }
    let cell = db
        .attempts
        .get(key)
        .cloned()
        .unwrap_or(WebAuthnAttemptCell::Absent);
    let taken = match &cell {
        WebAuthnAttemptCell::Absent => AuthStateTake::Missing,
        WebAuthnAttemptCell::Undecodable => AuthStateTake::Corrupt,
        WebAuthnAttemptCell::Valid(state) => AuthStateTake::Present(state.clone()),
    };
    let mut post = db.clone();
    if !matches!(cell, WebAuthnAttemptCell::Absent) {
        post.attempts.remove(key);
    }
    Some((
        webauthn_store::classify_take_auth_state(
            &taken,
            &user.to_string(),
            &attempt.to_string(),
            &observed_credential_id.to_string(),
        ),
        post,
    ))
}

/// `RecoverIo::auth_finish_update`'s guarded write.
pub fn update_credential(
    db: &WebAuthnDb,
    user: &str,
    expected: &str,
    _credential: &str,
    credential_id: &str,
    sql_fault: Option<usize>,
) -> Option<(CredentialUpdateStoreObservation, WebAuthnDb)> {
    if wfault(sql_fault, 0) {
        return None;
    }
    if !update_guard(db, user, expected) {
        return Some((webauthn_store::classify_credential_update(0), db.clone()));
    }
    let mut post = db.clone();
    if let Some(row) = post.users.get_mut(user) {
        row.credential = CredentialCell::Valid(credential_id.to_string());
        row.credential_id = Some(credential_id.to_string());
    }
    rebind(&mut post.holders, user, Some(expected), credential_id);
    Some((webauthn_store::classify_credential_update(1), post))
}

/// `RecoverIo::auth_finish_account`, with its split-id side channel.
pub fn finish_account(
    db: &WebAuthnDb,
    user: &str,
    credential_id: &str,
    sql_fault: Option<usize>,
) -> Option<(AuthAccountObservation, Option<String>)> {
    if wfault(sql_fault, 0) {
        return None;
    }
    let row = db.users.get(user);
    let view = row.map(finish_account_view);
    Some((
        webauthn_store::classify_finish_account(view, &credential_id.to_string()),
        row.and_then(|row| row.split.clone()),
    ))
}

/// `RecoverIo::auth_finish_release`.
pub fn release_share(
    db: &WebAuthnDb,
    user: &str,
    decoded: bool,
) -> Option<(ShareDecodeObservation, WebAuthnDb)> {
    webauthn_store::classify_share_release(row_share_present(db, user), decoded)
        .map(|observation| (observation, db.clone()))
}

/// `RecoverIo::auth_finish_store_grant`.
pub fn store_credential_grant(
    db: &WebAuthnDb,
    key: &str,
    _value: &str,
    grant: &CredentialGrantView,
    _ttl: u64,
    kv_fault: Option<usize>,
) -> (WebAuthnGrantStoreObservation, WebAuthnDb) {
    if wfault(kv_fault, 0) {
        return (webauthn_store::classify_grant_store(false), db.clone());
    }
    let mut post = db.clone();
    post.grants.insert(key.to_string(), grant.clone());
    (webauthn_store::classify_grant_store(true), post)
}

/// `RegisterStartIo::registration_start_observe`.
pub fn registration_start_observe(
    db: &WebAuthnDb,
    user: &str,
    sql_fault: Option<usize>,
) -> Option<RegistrationStartObservation> {
    if wfault(sql_fault, 0) {
        return None;
    }
    Some(webauthn_store::classify_registration_start(&credential_view(
        db, user,
    )))
}

/// `RegisterStartIo::registration_start_store`.
pub fn store_registration_state(
    db: &WebAuthnDb,
    key: &str,
    _value: &str,
    _ttl: u64,
    kv_fault: Option<usize>,
) -> (WebAuthnChallengeStoreObservation, WebAuthnDb) {
    if wfault(kv_fault, 0) {
        return (
            webauthn_store::classify_store_registration_state(&SetOutcome::Failed),
            db.clone(),
        );
    }
    let mut post = db.clone();
    post.registrations
        .insert(key.to_string(), WebAuthnRegistrationCell::Valid);
    (
        webauthn_store::classify_store_registration_state(&SetOutcome::Wrote),
        post,
    )
}

/// `RegisterFinishIo::registration_consume_state`.
pub fn take_registration_state(
    db: &WebAuthnDb,
    key: &str,
    kv_fault: Option<usize>,
) -> Option<(RegistrationStateObservation, WebAuthnDb)> {
    if wfault(kv_fault, 0) {
        return None;
    }
    let cell = db
        .registrations
        .get(key)
        .copied()
        .unwrap_or(WebAuthnRegistrationCell::Absent);
    let taken = match cell {
        WebAuthnRegistrationCell::Absent => RegistrationStateTake::Missing,
        WebAuthnRegistrationCell::Undecodable => RegistrationStateTake::Corrupt,
        WebAuthnRegistrationCell::Valid => RegistrationStateTake::Present,
    };
    let mut post = db.clone();
    if !matches!(cell, WebAuthnRegistrationCell::Absent) {
        post.registrations.remove(key);
    }
    Some((
        webauthn_store::classify_registration_state(&taken),
        post,
    ))
}

/// `RegisterFinishIo::registration_check_uniqueness`.
pub fn check_uniqueness(
    db: &WebAuthnDb,
    credential_id: &str,
    user: &str,
    sql_fault: Option<usize>,
) -> CredentialUniquenessObservation {
    let view = if wfault(sql_fault, 0) {
        CredentialHolderView::Unreadable
    } else if holder_other(db, credential_id, user) {
        CredentialHolderView::OtherAccount
    } else {
        CredentialHolderView::OnlyCaller
    };
    webauthn_store::classify_uniqueness(&view)
}

/// `RegisterFinishIo::registration_persist`.
pub fn persist_credential(
    db: &WebAuthnDb,
    user: &str,
    _credential: &str,
    credential_id: &str,
    encoded: bool,
    sql_fault: Option<usize>,
) -> (CredentialPersistObservation, WebAuthnDb) {
    if !encoded {
        return (
            webauthn_store::classify_persist_credential(false, &[]),
            db.clone(),
        );
    }
    if wfault(sql_fault, 0) {
        return (
            webauthn_store::classify_persist_credential(true, &[WriteOutcome::Failed]),
            db.clone(),
        );
    }
    match db.users.get(user) {
        None => (
            webauthn_store::classify_persist_credential(true, &[WriteOutcome::Applied(0)]),
            db.clone(),
        ),
        Some(row) => {
            let old = row.credential_id.clone();
            let mut post = db.clone();
            if let Some(row) = post.users.get_mut(user) {
                row.credential = CredentialCell::Valid(credential_id.to_string());
                row.credential_id = Some(credential_id.to_string());
            }
            rebind(&mut post.holders, user, old.as_deref(), credential_id);
            (
                webauthn_store::classify_persist_credential(true, &[WriteOutcome::Applied(1)]),
                post,
            )
        }
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

    fn possession_row(
        share: bool,
        commitment: CommitmentObservation,
        epoch: Option<i64>,
        rekey: bool,
    ) -> PossessionUserRow {
        PossessionUserRow { share, commitment, epoch, rekey }
    }

    /// The F* lemmas `vector_possession_*` prove the same runs.
    #[test]
    fn shared_possession_vectors() {
        let attempt = ProofAttemptView {
            user: s("u"),
            attempt: s("a"),
            key_epoch: 7,
        };
        let mut pre = PossessionDb::default();
        pre.users.insert(
            s("u"),
            possession_row(
                true,
                CommitmentObservation::Present { len: 32 },
                Some(7),
                false,
            ),
        );

        // vector_possession_initiate: the row and the free slot are observed.
        let (obs, post) = initiate_observation(&pre, "u", "slot", 300, None, None).unwrap();
        assert!(obs.account_present && obs.share_present && obs.attempt_id_fresh);
        assert_eq!(obs.commitment, CommitmentObservation::Present { len: 32 });
        assert_eq!(obs.ttl_secs, 300);
        assert_eq!(post, pre);
        // vector_possession_initiate_absent: no row, still a fresh slot.
        let (obs, post) = initiate_observation(&pre, "missing", "slot", 300, None, None).unwrap();
        assert!(!obs.account_present && obs.attempt_id_fresh);
        assert_eq!(
            obs.commitment,
            CommitmentObservation::Missing
        );
        assert_eq!(post, pre);
        // vector_possession_epoch: the observed epoch is the row's.
        assert_eq!(initiate_epoch_of(&pre, "u", false), 7);
        assert_eq!(initiate_epoch_of(&pre, "missing", false), 1);

        // vector_possession_store: the free slot takes the drawn challenge.
        let (obs, stored) =
            store_challenge(&pre, "slot", "{\"k\":7}", &attempt, 300, None).unwrap();
        assert_eq!(obs, ChallengeStoreObservation::Stored);
        assert_eq!(
            stored.challenges.get("slot"),
            Some(&AttemptCell::Valid(attempt.clone()))
        );
        // vector_possession_store_lost: a second writer does not replace it.
        let (obs, lost) =
            store_challenge(&stored, "slot", "{\"k\":8}", &attempt, 300, None).unwrap();
        assert_eq!(obs, ChallengeStoreObservation::Lost);
        assert_eq!(lost, stored);

        // vector_possession_take: the exact state is removed and matches.
        let (obs, taken) = take_attempt(&stored, "slot", "u", "a", None).unwrap();
        assert_eq!(
            obs,
            AttemptConsumptionObservation::Present {
                user_matches: true,
                attempt_matches: true,
                key_epoch: 7,
            }
        );
        assert!(taken.challenges.is_empty());
        // vector_possession_take_missing: nothing matched.
        let (obs, post) = take_attempt(&taken, "slot", "u", "a", None).unwrap();
        assert_eq!(obs, AttemptConsumptionObservation::Missing);
        assert_eq!(post, taken);
        // vector_possession_take_corrupt still consumed the slot.
        let mut corrupt = pre.clone();
        corrupt.challenges.insert(s("slot"), AttemptCell::Undecodable);
        let (obs, post) = take_attempt(&corrupt, "slot", "u", "a", None).unwrap();
        assert_eq!(obs, AttemptConsumptionObservation::Corrupt);
        assert!(post.challenges.is_empty());

        // vector_possession_account: the live row's fields.
        let obs = proof_account(&pre, "u", None).unwrap();
        assert!(obs.account_present && obs.account_epoch_active);
        assert_eq!(obs.commitment, CommitmentObservation::Present { len: 32 });
        assert_eq!(obs.stored_epoch, Some(7));
        let obs = proof_account(&pre, "missing", None).unwrap();
        assert!(!obs.account_present && !obs.account_epoch_active);

        // vector_possession_grant: the grant lands at its key.
        let grant = EnrollmentGrantView { key_epoch: 7 };
        let (obs, issued) = issue_grant(&pre, "g", "{\"key_epoch\":7}", &grant, 600, None);
        assert_eq!(obs, GrantStoreObservation::Stored);
        assert_eq!(issued.grants.get("g"), Some(&grant));
        // vector_possession_grant_failed: a store error changes nothing.
        let (obs, post) = issue_grant(&pre, "g", "{\"key_epoch\":7}", &grant, 600, Some(0));
        assert_eq!(obs, GrantStoreObservation::Failed);
        assert_eq!(post, pre);
    }

    fn webauthn_row() -> WebAuthnUserRow {
        WebAuthnUserRow {
            share: Some(s("c2hhcmU=")),
            credential: CredentialCell::Valid(s("cred")),
            credential_id: Some(s("cred")),
            epoch: Some(7),
            rekey: false,
            split: Some(s("split")),
        }
    }

    fn webauthn_db() -> WebAuthnDb {
        let mut db = WebAuthnDb::default();
        db.users.insert(s("u"), webauthn_row());
        db.holders.insert(s("cred"), s("u"));
        db
    }

    fn attempt() -> AuthStateView {
        AuthStateView {
            user: s("u"),
            attempt: s("a"),
            credential_id: s("cred"),
        }
    }

    /// The F* lemmas `vector_webauthn_*` prove the same runs.
    #[test]
    fn shared_webauthn_vectors() {
        let pre = webauthn_db();

        // vector_webauthn_start / _absent / _occupied.
        let (obs, post) =
            auth_start_observe(&pre, "u", "slot", 300, None, None).unwrap();
        assert!(obs.account_present && obs.share_present && obs.attempt_id_fresh);
        assert_eq!(obs.credential, StoredCredentialObservation::Present);
        assert_eq!(obs.ttl_secs, 300);
        assert_eq!(post, pre);
        let (obs, post) =
            auth_start_observe(&pre, "missing", "slot", 300, None, None).unwrap();
        assert!(!obs.account_present && !obs.share_present && obs.attempt_id_fresh);
        assert_eq!(obs.credential, StoredCredentialObservation::Missing);
        assert_eq!(post, pre);
        let mut occupied = pre.clone();
        occupied
            .attempts
            .insert(s("slot"), WebAuthnAttemptCell::Valid(attempt()));
        let (obs, post) =
            auth_start_observe(&occupied, "u", "slot", 300, None, None).unwrap();
        assert!(!obs.attempt_id_fresh);
        assert_eq!(post, occupied);

        // vector_webauthn_store / _lost / _failed.
        let state = attempt();
        let (obs, stored) =
            store_auth_state(&pre, "slot", "v", &state, 300, None);
        assert_eq!(obs, WebAuthnChallengeStoreObservation::Stored);
        assert_eq!(
            stored.attempts.get("slot"),
            Some(&WebAuthnAttemptCell::Valid(state.clone()))
        );
        let (obs, lost) =
            store_auth_state(&occupied, "slot", "v", &state, 300, None);
        assert_eq!(obs, WebAuthnChallengeStoreObservation::Lost);
        assert_eq!(lost, occupied);
        let (obs, failed) =
            store_auth_state(&pre, "slot", "v", &state, 300, Some(0));
        assert_eq!(obs, WebAuthnChallengeStoreObservation::StorageFailed);
        assert_eq!(failed, pre);

        // vector_webauthn_context.
        let obs = finish_context(&pre, "u", true, None).unwrap();
        assert!(obs.account_present && obs.share_present && obs.attempt_id_present);
        assert_eq!(obs.credential, StoredCredentialObservation::Present);

        // vector_webauthn_take / _missing / _corrupt.
        let (obs, taken) =
            take_auth_state(&occupied, "slot", "u", "a", "cred", None).unwrap();
        assert_eq!(
            obs,
            AuthAttemptConsumptionObservation::Present {
                user_matches: true,
                attempt_matches: true,
                credential_matches: true,
            }
        );
        assert!(taken.attempts.is_empty());
        let (obs, post) = take_auth_state(&pre, "slot", "u", "a", "cred", None).unwrap();
        assert_eq!(obs, AuthAttemptConsumptionObservation::Missing);
        assert_eq!(post, pre);
        let mut corrupt = pre.clone();
        corrupt
            .attempts
            .insert(s("slot"), WebAuthnAttemptCell::Undecodable);
        let (obs, post) =
            take_auth_state(&corrupt, "slot", "u", "a", "cred", None).unwrap();
        assert_eq!(obs, AuthAttemptConsumptionObservation::Corrupt);
        assert!(post.attempts.is_empty());

        // vector_webauthn_update / _stale.
        let (obs, updated) =
            update_credential(&pre, "u", "cred", "{}", "cred2", None).unwrap();
        assert_eq!(obs, CredentialUpdateStoreObservation::Updated);
        assert_eq!(updated.holders.get("cred2").map(String::as_str), Some("u"));
        assert_eq!(updated.holders.get("cred"), None);
        let (obs, post) =
            update_credential(&pre, "u", "other", "{}", "cred2", None).unwrap();
        assert_eq!(obs, CredentialUpdateStoreObservation::Changed);
        assert_eq!(post, pre);

        // vector_webauthn_account / _absent.
        let (obs, split) = finish_account(&pre, "u", "cred", None).unwrap();
        assert!(obs.account_present && obs.account_epoch_active && obs.share_present);
        assert!(obs.stored_credential_matches);
        assert_eq!(obs.stored_epoch, Some(7));
        assert_eq!(split, Some(s("split")));
        let (obs, split) = finish_account(&pre, "missing", "cred", None).unwrap();
        assert!(!obs.account_present && !obs.account_epoch_active && !obs.share_present);
        assert_eq!(split, None);

        // vector_webauthn_release / _corrupt / _missing.
        let (obs, post) = release_share(&pre, "u", true).unwrap();
        assert_eq!(obs, ShareDecodeObservation::Decoded);
        assert_eq!(post, pre);
        let (obs, post) = release_share(&pre, "u", false).unwrap();
        assert_eq!(obs, ShareDecodeObservation::Corrupt);
        assert_eq!(post, pre);
        assert!(release_share(&pre, "missing", true).is_none());

        // vector_webauthn_grant / _failed.
        let grant = CredentialGrantView {
            key_epoch: 7,
            credential_id: s("cred"),
            possession: false,
        };
        let (obs, issued) =
            store_credential_grant(&pre, "g", "v", &grant, 600, None);
        assert_eq!(obs, WebAuthnGrantStoreObservation::Stored);
        assert_eq!(issued.grants.get("g"), Some(&grant));
        let (obs, post) =
            store_credential_grant(&pre, "g", "v", &grant, 600, Some(0));
        assert_eq!(obs, WebAuthnGrantStoreObservation::Failed);
        assert_eq!(post, pre);

        // vector_webauthn_registration_start / _store / _take.
        let obs = registration_start_observe(&pre, "u", None).unwrap();
        assert!(obs.account_present);
        assert_eq!(obs.credential, StoredCredentialObservation::Present);
        let (obs, stored) = store_registration_state(&pre, "r", "{}", 300, None);
        assert_eq!(obs, WebAuthnChallengeStoreObservation::Stored);
        assert_eq!(
            stored.registrations.get("r"),
            Some(&WebAuthnRegistrationCell::Valid)
        );
        let (obs, taken) = take_registration_state(&stored, "r", None).unwrap();
        assert_eq!(obs, RegistrationStateObservation::Present);
        assert_eq!(taken.registrations.get("r"), None);
        let (obs, post) = take_registration_state(&pre, "r", None).unwrap();
        assert_eq!(obs, RegistrationStateObservation::Missing);
        assert_eq!(post, pre);

        // vector_webauthn_uniqueness / _elsewhere / _failed.
        assert_eq!(
            check_uniqueness(&pre, "cred", "u", None),
            CredentialUniquenessObservation::Unique
        );
        assert_eq!(
            check_uniqueness(&pre, "cred", "other", None),
            CredentialUniquenessObservation::RegisteredElsewhere
        );
        assert_eq!(
            check_uniqueness(&pre, "cred", "u", Some(0)),
            CredentialUniquenessObservation::LookupFailed
        );

        // vector_webauthn_persist / _gone / _encoding.
        let (obs, post) =
            persist_credential(&pre, "u", "{}", "cred2", true, None);
        assert_eq!(obs, CredentialPersistObservation::Persisted);
        assert_eq!(post.holders.get("cred2").map(String::as_str), Some("u"));
        assert_eq!(post.holders.get("cred"), None);
        let (obs, post) =
            persist_credential(&pre, "missing", "{}", "cred2", true, None);
        assert_eq!(obs, CredentialPersistObservation::AccountGone);
        assert_eq!(post, pre);
        let (obs, post) =
            persist_credential(&pre, "u", "{}", "cred2", false, None);
        assert_eq!(obs, CredentialPersistObservation::EncodingFailed);
        assert_eq!(post, pre);
    }
}
