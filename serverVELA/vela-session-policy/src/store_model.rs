//! Rust mirror of the F* store model in
//! `proofs/fstar/store-lemmas/Vela_session_policy_store_model.fst`.
//!
//! The server's conformance test runs every session executor against a real
//! turso database and a real sled store and compares the tables, keys and the
//! observation with what this model predicts. Each function here has a
//! namesake there with the same case order; keep them in step.
//! `tests::shared_vectors` checks the concrete runs the F* `vector_*` lemmas
//! prove from the general theorems.
//!
//! Only the columns the session statements read or write are modelled. Every
//! table is keyed by its `UNIQUE` id column, so a missing key is a missing
//! row. A delete by column removes exactly the matching rows; an update by id
//! rewrites the one matching row or none.

use std::collections::{BTreeMap, BTreeSet};

use crate::deletion_driver::{
    CommitObservation, DeletionTable, LockoutObservation as DeletionLockoutObservation,
    ScanObservation, TableDeleteObservation, TransactionObservation, UsersDeleteObservation,
};
use crate::login_driver::{
    BackoffResetObservation, ChallengeObservation, DeviceObservation, FailureRecordObservation,
    TokenTrackObservation,
};
use crate::revocation_driver::{
    CascadeObservation, DeviceLookupObservation, LockoutObservation, RecordObservation,
    TargetObservation,
};
use crate::store::{
    classify_backoff_reset, classify_cascade, classify_commit, classify_failure_counter,
    classify_lockout_device, classify_lockout_ignored, classify_login_challenge,
    classify_login_device, classify_logout, classify_record, classify_scan, classify_table_delete,
    classify_track_jti, classify_transaction, classify_users_delete, DeviceReadOutcome, IdsOutcome,
    ReadOutcome, SqlStmt, StoreOutcome, StoreStmt, TakeOutcome, TargetRowView, WriteOutcome,
};

/// A `String` from a literal, for the model's own plan construction.
fn s(x: &str) -> String {
    x.to_string()
}

/// A `users` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRow {
    pub share_ek: String,
    pub share_ek_since: String,
}

/// A `devices` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRow {
    pub user_id: String,
    pub revoked: i64,
    pub hybrid_vk: String,
    pub last_active: Option<String>,
    pub name: String,
    pub kind: String,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
}

/// A `web_sessions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRow {
    pub user_id: Option<String>,
    pub approver_user_id: Option<String>,
    pub status: String,
    pub capsule: Option<String>,
    pub approved_by: Option<String>,
}

/// A `share_inbox` or `shared_items` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailRow {
    pub sender: String,
    pub recipient: String,
}

/// A `sends`, `vault_chunks` or `oram_buckets` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedRow {
    pub user: String,
}

/// The eight tables, each keyed by its id.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Db {
    pub users: BTreeMap<String, UserRow>,
    pub devices: BTreeMap<String, DeviceRow>,
    pub sessions: BTreeMap<String, SessionRow>,
    pub inbox: BTreeMap<String, MailRow>,
    pub items: BTreeMap<String, MailRow>,
    pub sends: BTreeMap<String, OwnedRow>,
    pub chunks: BTreeMap<String, OwnedRow>,
    pub buckets: BTreeMap<String, OwnedRow>,
}

/// The store: the `set_ex` map, the `device:jtis:` sets, every JTI the
/// lockout helper has revoked, and the counters behind the login limiters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Store {
    pub kv: BTreeMap<String, String>,
    pub sets: BTreeMap<String, BTreeSet<String>>,
    pub revoked: BTreeSet<String>,
    pub counters: BTreeMap<String, u64>,
    pub streaks: BTreeMap<String, u64>,
}

/// What a write statement's row count means to the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteResult {
    Wrote,
    WroteOne,
    WroteAbsent,
}

impl WriteResult {
    fn outcome(self) -> WriteOutcome {
        match self {
            WriteResult::Wrote | WriteResult::WroteOne => WriteOutcome::Applied(1),
            WriteResult::WroteAbsent => WriteOutcome::Applied(0),
        }
    }
}

fn delete_where<T: Clone>(table: &BTreeMap<String, T>, pred: impl Fn(&T) -> bool) -> BTreeMap<String, T> {
    table
        .iter()
        .filter(|(_, row)| !pred(row))
        .map(|(k, v)| (k.clone(), (*v).clone()))
        .collect()
}

fn ids_where<T>(table: &BTreeMap<String, T>, pred: impl Fn(&T) -> bool) -> Vec<String> {
    table
        .iter()
        .filter(|(_, row)| pred(row))
        .map(|(k, _)| k.clone())
        .collect()
}

impl Db {
    fn update_devices(&mut self, dev: &str, now: &str, revoker: &str) {
        if let Some(row) = self.devices.get_mut(dev) {
            row.revoked = 1;
            row.revoked_at = Some(now.to_string());
            row.revoked_by = Some(revoker.to_string());
        }
    }

    /// F*: `st_web_sessions`.
    pub fn st_web_sessions(&self, acct: &str) -> Db {
        Db {
            sessions: delete_where(&self.sessions, |r| {
                r.user_id.as_deref() == Some(acct) || r.approver_user_id.as_deref() == Some(acct)
            }),
            ..self.clone()
        }
    }

    /// F*: `st_share_inbox`.
    pub fn st_share_inbox(&self, acct: &str) -> Db {
        Db {
            inbox: delete_where(&self.inbox, |r| r.recipient == acct || r.sender == acct),
            ..self.clone()
        }
    }

    /// F*: `st_shared_items`.
    pub fn st_shared_items(&self, acct: &str) -> Db {
        Db {
            items: delete_where(&self.items, |r| r.recipient == acct || r.sender == acct),
            ..self.clone()
        }
    }

    /// F*: `st_sends`.
    pub fn st_sends(&self, acct: &str) -> Db {
        Db { sends: delete_where(&self.sends, |r| r.user == acct), ..self.clone() }
    }

    /// F*: `st_vault_chunks`.
    pub fn st_vault_chunks(&self, acct: &str) -> Db {
        Db { chunks: delete_where(&self.chunks, |r| r.user == acct), ..self.clone() }
    }

    /// F*: `st_oram_buckets`.
    pub fn st_oram_buckets(&self, acct: &str) -> Db {
        Db { buckets: delete_where(&self.buckets, |r| r.user == acct), ..self.clone() }
    }

    /// F*: `st_devices_of_user`.
    pub fn st_devices_of_user(&self, acct: &str) -> Db {
        Db { devices: delete_where(&self.devices, |r| r.user_id == acct), ..self.clone() }
    }

    /// F*: `st_delete_user`.
    pub fn st_delete_user(&self, acct: &str) -> Db {
        let mut next = self.clone();
        next.users.remove(acct);
        next
    }

    /// F*: `st_revoke_device`.
    pub fn st_revoke_device(&self, dev: &str, now: &str, revoker: &str) -> Db {
        let mut next = self.clone();
        next.update_devices(dev, now, revoker);
        next
    }

    /// F*: `st_login_last_active`.
    pub fn st_login_last_active(
        &self,
        dev: &str,
        now: &str,
        name: Option<&str>,
        kind: Option<&str>,
    ) -> Db {
        let mut next = self.clone();
        if let Some(row) = next.devices.get_mut(dev) {
            row.last_active = Some(now.to_string());
            if let (Some(name), Some(kind)) = (name, kind) {
                row.name = name.to_string();
                row.kind = kind.to_string();
            }
        }
        next
    }

    /// F*: `st_revoke_approved`.
    pub fn st_revoke_approved(&self, dev: &str, usr: &str) -> Db {
        let mut next = self.clone();
        for row in next.sessions.values_mut() {
            if row.approved_by.as_deref() == Some(dev)
                && row.user_id.as_deref() == Some(usr)
                && row.status != "revoked"
            {
                row.status = "revoked".to_string();
                row.capsule = None;
            }
        }
        next
    }

    /// F*: the state one table's account delete leaves behind.
    pub fn delete_table_state(&self, acct: &str, table: DeletionTable) -> Db {
        match table {
            DeletionTable::WebSessions => self.st_web_sessions(acct),
            DeletionTable::ShareInbox => self.st_share_inbox(acct),
            DeletionTable::SharedItems => self.st_shared_items(acct),
            DeletionTable::Sends => self.st_sends(acct),
            DeletionTable::VaultChunks => self.st_vault_chunks(acct),
            DeletionTable::OramBuckets => self.st_oram_buckets(acct),
            DeletionTable::Devices => self.st_devices_of_user(acct),
        }
    }
}

/// F*: `exec_stmt`.
pub fn exec_stmt(db: &Db, stmt: &SqlStmt) -> Option<(WriteResult, Db)> {
    match stmt {
        SqlStmt::SelectDeviceIdsByUser { .. }
        | SqlStmt::SelectWebSessionIdsByUser { .. }
        | SqlStmt::SelectDeviceById { .. }
        | SqlStmt::SelectWebSessionIdsApprovedBy { .. }
        | SqlStmt::SelectUnrevokedDeviceById { .. }
        | SqlStmt::Commit => None,
        SqlStmt::DeleteWebSessionsByUser { user } => {
            Some((WriteResult::Wrote, db.st_web_sessions(user)))
        }
        SqlStmt::DeleteShareInboxByUser { user } => {
            Some((WriteResult::Wrote, db.st_share_inbox(user)))
        }
        SqlStmt::DeleteSharedItemsByUser { user } => {
            Some((WriteResult::Wrote, db.st_shared_items(user)))
        }
        SqlStmt::DeleteSendsByOwner { owner } => Some((WriteResult::Wrote, db.st_sends(owner))),
        SqlStmt::DeleteVaultChunksByUser { user } => {
            Some((WriteResult::Wrote, db.st_vault_chunks(user)))
        }
        SqlStmt::DeleteOramBucketsByUser { user } => {
            Some((WriteResult::Wrote, db.st_oram_buckets(user)))
        }
        SqlStmt::DeleteDevicesByUser { user } => {
            Some((WriteResult::Wrote, db.st_devices_of_user(user)))
        }
        SqlStmt::DeleteUserById { user } => match db.users.get(user) {
            Some(_) => Some((WriteResult::WroteOne, db.st_delete_user(user))),
            None => Some((WriteResult::WroteAbsent, db.clone())),
        },
        SqlStmt::RevokeDeviceRecord { now, revoked_by, device_id } => Some((
            WriteResult::Wrote,
            db.st_revoke_device(device_id, now, revoked_by),
        )),
        SqlStmt::RevokeWebSessionsApprovedBy { device_id, user } => {
            Some((WriteResult::Wrote, db.st_revoke_approved(device_id, user)))
        }
        SqlStmt::UpdateDeviceLastActive { now, device_id } => Some((
            WriteResult::Wrote,
            db.st_login_last_active(device_id, now, None, None),
        )),
        SqlStmt::UpdateDeviceLastActiveNamed {
            now,
            name,
            kind,
            device_id,
        } => Some((
            WriteResult::Wrote,
            db.st_login_last_active(device_id, now, Some(name), Some(kind)),
        )),
    }
}

fn faulted(fault: Option<usize>, k: usize) -> bool {
    fault == Some(k)
}

/// F*: `run_tx`.
pub fn run_tx(pre: &Db, plan: &[SqlStmt], fault: Option<usize>) -> (Vec<WriteOutcome>, Db) {
    let mut work = pre.clone();
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, pre.clone());
        }
        if let SqlStmt::Commit = stmt {
            outcomes.push(WriteOutcome::Applied(0));
            continue;
        }
        match exec_stmt(&work, stmt) {
            Some((rows, next)) => {
                outcomes.push(rows.outcome());
                work = next;
            }
            None => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, pre.clone());
            }
        }
    }
    (outcomes, work)
}

// ── Store ──────────────────────────────────────────────────────────────────

/// F*: `exec_store_out`. Applies one store statement and reports whether the
/// handler saw it succeed. An over-limit counter still grew before refusing.
pub fn exec_store(store: &Store, stmt: &StoreStmt) -> (StoreOutcome, Store) {
    let mut next = store.clone();
    match stmt {
        StoreStmt::SetEx { key, value, .. } => {
            next.kv.insert(key.clone(), (*value).to_string());
            (StoreOutcome::Applied, next)
        }
        StoreStmt::RevokeJtis { device } => {
            let members = next.sets.remove(device).unwrap_or_default();
            next.revoked.extend(members);
            (StoreOutcome::Applied, next)
        }
        StoreStmt::Take { key } => {
            next.kv.remove(key);
            (StoreOutcome::Applied, next)
        }
        StoreStmt::Incr { key, limit, .. } => {
            let count = next.counters.get(key).copied().unwrap_or(0) + 1;
            next.counters.insert(key.clone(), count);
            let outcome = if count <= *limit {
                StoreOutcome::Applied
            } else {
                StoreOutcome::Failed
            };
            (outcome, next)
        }
        StoreStmt::BackoffFailure { streak, backoff } => {
            let count = next.streaks.get(streak).copied().unwrap_or(0) + 1;
            next.streaks.insert(streak.clone(), count);
            if count >= 3 {
                next.kv.insert(backoff.clone(), s("1"));
            }
            (StoreOutcome::Applied, next)
        }
        StoreStmt::ResetBackoff { streak, backoff } => {
            next.streaks.remove(streak);
            next.kv.remove(backoff);
            (StoreOutcome::Applied, next)
        }
        StoreStmt::AddMember { key, member, .. } => {
            next.sets.entry(key.clone()).or_default().insert(member.clone());
            (StoreOutcome::Applied, next)
        }
    }
}

/// F*: `run_store`.
pub fn run_store(store: &Store, plan: &[StoreStmt], fault: Option<usize>) -> (Vec<StoreOutcome>, Store) {
    let mut state = store.clone();
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(StoreOutcome::Failed);
            return (outcomes, state);
        }
        let (outcome, next) = exec_store(&state, stmt);
        state = next;
        outcomes.push(outcome);
        if outcome == StoreOutcome::Failed {
            return (outcomes, state);
        }
    }
    (outcomes, state)
}

/// F*: `lockout_each` — per-id lockouts, continuing past a failure.
pub fn lockout_each(
    store: &Store,
    ids: &[String],
    plan_of: impl Fn(&str) -> Vec<StoreStmt>,
    fault: Option<usize>,
) -> (Store, usize) {
    let mut state = store.clone();
    let mut calls = 0;
    for id in ids {
        let plan = plan_of(id);
        let relative = match fault {
            Some(j) if j >= calls => Some(j - calls),
            _ => None,
        };
        let (outcomes, next) = run_store(&state, &plan, relative);
        calls += outcomes.len();
        state = next;
    }
    (state, calls)
}

// ── Reads ──────────────────────────────────────────────────────────────────

/// F*: `target_truth`.
pub fn target_truth(db: &Db, caller: &str, dev: &str) -> DeviceLookupObservation {
    match db.devices.get(dev) {
        Some(row) => DeviceLookupObservation::Present(TargetObservation {
            same_account: row.user_id == caller,
            already_revoked: row.revoked != 0,
        }),
        None => DeviceLookupObservation::Absent,
    }
}

/// F*: `read_target`.
pub fn read_target(db: &Db, dev: &str, failed: bool) -> ReadOutcome<TargetRowView> {
    if failed {
        ReadOutcome::Failed
    } else {
        ReadOutcome::Row(db.devices.get(dev).map(|row| TargetRowView {
            user_id: Some(row.user_id.clone()),
            revoked: Some(row.revoked),
        }))
    }
}

// ── Login: VerifyIo ────────────────────────────────────────────────────────

/// F*: `login_challenge`. The atomic take of the one challenge key.
pub fn login_challenge(
    store: &Store,
    challenge: &str,
    expected_tag: &str,
    fault: Option<usize>,
) -> (ChallengeObservation, Store) {
    let plan = crate::store::plan_take_challenge(s(challenge));
    let key = match plan.first() {
        Some(StoreStmt::Take { key }) => key.clone(),
        _ => String::new(),
    };
    if faulted(fault, 0) {
        (
            classify_login_challenge(&TakeOutcome::Failed, &s(expected_tag)),
            store.clone(),
        )
    } else {
        let taken = store.kv.get(&key).cloned();
        let mut post = store.clone();
        post.kv.remove(&key);
        (
            classify_login_challenge(&TakeOutcome::Taken(taken), &s(expected_tag)),
            post,
        )
    }
}

/// F*: `login_device`. What the unrevoked-device query and decoder returned.
pub fn login_device(
    db: &Db,
    dev: &str,
    failed: bool,
    undecodable: bool,
) -> DeviceReadOutcome {
    if failed {
        DeviceReadOutcome::Failed
    } else {
        match db.devices.get(dev) {
            None => DeviceReadOutcome::Missing,
            Some(row) if row.revoked != 0 => DeviceReadOutcome::Missing,
            Some(_) => {
                if undecodable {
                    DeviceReadOutcome::Undecodable
                } else {
                    DeviceReadOutcome::Row
                }
            }
        }
    }
}

/// F*: `observe_device`.
pub fn observe_device(
    db: &Db,
    dev: &str,
    failed: bool,
    undecodable: bool,
) -> DeviceObservation {
    classify_login_device(&login_device(db, dev, failed, undecodable))
}

/// F*: `login_failure_record`. Two independent store calls: the log-only
/// backoff record at fault 0, the request-level counter at fault 1.
pub fn login_failure_record(
    store: &Store,
    ip: &str,
    dev: &str,
    fault: Option<usize>,
) -> (FailureRecordObservation, Store) {
    let plan = crate::store::plan_backoff_record(s(ip), s(dev));
    let (_, after_record) = run_store(store, &plan, if fault == Some(0) { Some(0) } else { None });
    let plan = crate::store::plan_failure_counter(s(ip), s(dev));
    let (outcomes, after_counter) =
        run_store(&after_record, &plan, if fault == Some(1) { Some(0) } else { None });
    (classify_failure_counter(&outcomes), after_counter)
}

/// F*: `login_reset`. The streak reset at fault 0, then the best-effort stamp
/// at fault 1 (whose failure the observation ignores).
pub fn login_reset(
    store: &Store,
    db: &Db,
    ip: &str,
    dev: &str,
    now: &str,
    name: Option<&str>,
    kind: Option<&str>,
    fault: Option<usize>,
) -> (BackoffResetObservation, Store, Db) {
    let plan = crate::store::plan_reset_login_streak(s(ip), s(dev));
    let (outcomes, after_reset) = run_store(store, &plan, if fault == Some(0) { Some(0) } else { None });
    let outcome = outcomes.first().copied().unwrap_or(StoreOutcome::Failed);
    if outcome == StoreOutcome::Failed {
        return (classify_backoff_reset(&outcome), after_reset, db.clone());
    }
    let stamp = crate::store::plan_login_last_active(
        s(dev),
        s(now),
        name.map(s),
        kind.map(s),
    );
    let updated = if fault == Some(1) {
        db.clone()
    } else {
        match exec_stmt(db, &stamp) {
            Some((_, next)) => next,
            None => db.clone(),
        }
    };
    (classify_backoff_reset(&outcome), after_reset, updated)
}

/// F*: `login_track`.
pub fn login_track(
    store: &Store,
    dev: &str,
    jti: &str,
    fault: Option<usize>,
) -> (TokenTrackObservation, Store) {
    let plan = crate::store::plan_track_jti(s(dev), s(jti));
    let (outcomes, post) = run_store(store, &plan, fault);
    let outcome = outcomes.first().copied().unwrap_or(StoreOutcome::Failed);
    (classify_track_jti(&outcome), post)
}


/// F*: `logout_jti`.
pub fn logout(store: &Store, jti: &str, fault: Option<usize>)
    -> (crate::revocation_driver::LogoutObservation, Store)
{
    let plan = crate::store::plan_logout(jti.to_string());
    let (outcomes, post) = run_store(store, &plan, fault);
    (classify_logout(&outcomes), post)
}

/// F*: `lockout_device`.
pub fn lockout_device(store: &Store, dev: &str, fault: Option<usize>)
    -> (LockoutObservation, Store)
{
    let plan = crate::store::plan_lockout_device(dev.to_string());
    let (outcomes, post) = run_store(store, &plan, fault);
    (classify_lockout_device(&outcomes), post)
}

/// F*: `revoke_observe`.
pub fn revoke_observe(db: &Db, caller: &str, dev: &str, fault: Option<usize>)
    -> DeviceLookupObservation
{
    crate::store::classify_target(&caller.to_string(), &read_target(db, dev, faulted(fault, 0)))
}

/// F*: `revoke_record`.
pub fn revoke_record(db: &Db, dev: &str, now: &str, revoker: &str, fault: Option<usize>)
    -> (RecordObservation, Db)
{
    if faulted(fault, 0) {
        (classify_record(&WriteOutcome::Failed), db.clone())
    } else {
        (
            classify_record(&WriteOutcome::Applied(1)),
            db.st_revoke_device(dev, now, revoker),
        )
    }
}

/// F*: `scan_devices`.
pub fn scan_devices(db: &Db, acct: &str, failed: bool)
    -> (ScanObservation, Vec<String>)
{
    let ids = if failed {
        Vec::new()
    } else {
        ids_where(&db.devices, |r| r.user_id == acct)
    };
    let outcome = if failed {
        IdsOutcome::Failed
    } else {
        IdsOutcome::Ids(ids.clone())
    };
    (classify_scan(&outcome), ids)
}

/// F*: `scan_web_sessions`.
pub fn scan_web_sessions(db: &Db, acct: &str, failed: bool)
    -> (ScanObservation, Vec<String>)
{
    let ids = if failed {
        Vec::new()
    } else {
        ids_where(&db.sessions, |r| {
            r.user_id.as_deref() == Some(acct) || r.approver_user_id.as_deref() == Some(acct)
        })
    };
    let outcome = if failed {
        IdsOutcome::Failed
    } else {
        IdsOutcome::Ids(ids.clone())
    };
    (classify_scan(&outcome), ids)
}

/// F*: `lockout_scanned`.
pub fn lockout_scanned(
    store: &Store,
    ids: &[String],
    plan_of: impl Fn(&str) -> Vec<StoreStmt>,
    fault: Option<usize>,
) -> (DeletionLockoutObservation, Store) {
    let (post, _) = lockout_each(store, ids, plan_of, fault);
    (classify_lockout_ignored(&[]), post)
}

/// F*: `begin_tx`.
pub fn begin_tx(db: &Db, fault: Option<usize>) -> (TransactionObservation, Db) {
    if faulted(fault, 0) {
        (classify_transaction(&WriteOutcome::Failed), db.clone())
    } else {
        (classify_transaction(&WriteOutcome::Applied(0)), db.clone())
    }
}

/// F*: `delete_table`.
pub fn delete_table(db: &Db, acct: &str, table: DeletionTable, fault: Option<usize>)
    -> (TableDeleteObservation, Db)
{
    if faulted(fault, 0) {
        (classify_table_delete(&WriteOutcome::Failed), db.clone())
    } else {
        (
            classify_table_delete(&WriteOutcome::Applied(1)),
            db.delete_table_state(acct, table),
        )
    }
}

/// F*: `delete_users`.
pub fn delete_users(db: &Db, acct: &str, fault: Option<usize>)
    -> (UsersDeleteObservation, Db)
{
    if faulted(fault, 0) {
        (classify_users_delete(&WriteOutcome::Failed), db.clone())
    } else if db.users.contains_key(acct) {
        (
            classify_users_delete(&WriteOutcome::Applied(1)),
            db.st_delete_user(acct),
        )
    } else {
        (
            classify_users_delete(&WriteOutcome::Applied(0)),
            db.clone(),
        )
    }
}

/// F*: `commit_tx`.
pub fn commit_tx(db: &Db, fault: Option<usize>) -> (CommitObservation, Db) {
    if faulted(fault, 0) {
        (classify_commit(&WriteOutcome::Failed), db.clone())
    } else {
        (classify_commit(&WriteOutcome::Applied(0)), db.clone())
    }
}

/// F*: `deletion_plan` — the seven table deletes, the `users` delete, then the
/// commit (the statements the handler runs in one transaction).
pub fn deletion_plan(acct: &str) -> Vec<SqlStmt> {
    let mut plan: Vec<SqlStmt> = [
        DeletionTable::WebSessions,
        DeletionTable::ShareInbox,
        DeletionTable::SharedItems,
        DeletionTable::Sends,
        DeletionTable::VaultChunks,
        DeletionTable::OramBuckets,
        DeletionTable::Devices,
    ]
    .into_iter()
    .map(|table| crate::store::plan_delete_table(acct.to_string(), table))
    .collect();
    plan.push(crate::store::plan_delete_users(acct.to_string()));
    plan.push(crate::store::plan_commit());
    plan
}

/// F*: `deleted_account` — the whole account's rows gone.
pub fn deleted_account(db: &Db, acct: &str) -> Db {
    db.st_delete_user(acct)
        .st_devices_of_user(acct)
        .st_oram_buckets(acct)
        .st_vault_chunks(acct)
        .st_sends(acct)
        .st_shared_items(acct)
        .st_share_inbox(acct)
        .st_web_sessions(acct)
}

/// F*: `deletion_transaction`.
pub fn deletion_transaction(db: &Db, acct: &str, fault: Option<usize>) -> (Vec<WriteOutcome>, Db) {
    run_tx(db, &deletion_plan(acct), fault)
}

/// F*: `draft_cascade_observation` helper: the observable cascade outcome.
pub fn cascade(ok: bool) -> CascadeObservation {
    classify_cascade(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    /// The F* lemmas `vector_logout`, `vector_logout_fault`,
    /// `vector_lockout` and `vector_lockout_fault` prove the same runs.
    #[test]
    fn shared_vectors() {
        let store = Store::default();
        let (obs, post) = logout(&store, "j", None);
        assert_eq!(obs, crate::revocation_driver::LogoutObservation::Applied);
        assert_eq!(post.kv.get("jti:revoked:j").map(String::as_str), Some("1"));
        let (obs, post) = logout(&store, "j", Some(0));
        assert_eq!(obs, crate::revocation_driver::LogoutObservation::StorageFailed);
        assert_eq!(post, store);

        let locked = Store {
            kv: BTreeMap::new(),
            sets: BTreeMap::from([(s("dev"), BTreeSet::from([s("j1"), s("j2")]))]),
            revoked: BTreeSet::new(),
            counters: BTreeMap::new(),
            streaks: BTreeMap::new(),
        };
        let (obs, post) = lockout_device(&locked, "dev", None);
        assert_eq!(obs, crate::revocation_driver::LockoutObservation::Applied);
        assert_eq!(post.kv.get("device:revoked:dev").map(String::as_str), Some("1"));
        assert!(post.sets.get("dev").map(|set| set.is_empty()).unwrap_or(true));
        assert_eq!(
            post.revoked,
            BTreeSet::from([s("j1"), s("j2")])
        );
        let (obs, post) = lockout_device(&locked, "dev", Some(0));
        assert_eq!(obs, crate::revocation_driver::LockoutObservation::StorageFailed);
        assert_eq!(post, locked);
    }

    #[test]
    fn login_shared_vectors() {
        let mut store = Store::default();
        store.kv.insert(s("challenge:c"), s("login"));
        let (obs, post) = login_challenge(&store, "c", "login", None);
        assert_eq!(
            obs,
            ChallengeObservation::Observed(crate::challenge::ChallengeConsumption::Accepted)
        );
        assert!(!post.kv.contains_key("challenge:c"));
        let (obs, _) = login_challenge(&Store::default(), "c", "login", None);
        assert_eq!(
            obs,
            ChallengeObservation::Observed(crate::challenge::ChallengeConsumption::Missing)
        );
        let (obs, post) = login_track(&Store::default(), "dev", "jti", None);
        assert_eq!(obs, TokenTrackObservation::Tracked);
        assert!(post
            .sets
            .get("device:jtis:dev")
            .map(|set| set.contains("jti"))
            .unwrap_or(false));
    }

    #[test]
    fn login_failure_counter_refuses_after_its_window_quota() {
        let mut store = Store::default();
        let key = crate::store::plan_failure_counter(s("ip"), s("dev"));
        let crate::store::StoreStmt::Incr { key: counter, limit, .. } = &key[0] else {
            panic!("the counter plan is not an incr");
        };
        for n in 0..*limit {
            store.counters.insert(counter.clone(), n);
            let (obs, _) = login_failure_record(&store, "ip", "dev", None);
            assert!(obs.fallback_counter_ok, "counter at {n}");
        }
        store.counters.insert(counter.clone(), *limit);
        let (obs, post) = login_failure_record(&store, "ip", "dev", None);
        assert!(!obs.fallback_counter_ok);
        assert_eq!(post.counters.get(counter).copied(), Some(*limit + 1));
    }

    #[test]
    fn login_device_sees_only_unrevoked_rows() {
        let mut db = Db::default();
        db.devices.insert(
            s("dev"),
            DeviceRow {
                user_id: s("me"),
                revoked: 0,
                hybrid_vk: s("vk"),
                last_active: None,
                name: s("n"),
                kind: s("k"),
                revoked_at: None,
                revoked_by: None,
            },
        );
        assert_eq!(observe_device(&db, "dev", false, false), DeviceObservation::Present);
        assert_eq!(
            observe_device(&db, "dev", false, true),
            DeviceObservation::ParseFailed
        );
        assert_eq!(observe_device(&db, "dev", true, false), DeviceObservation::QueryFailed);
        let mut revoked = db.clone();
        revoked.devices.get_mut("dev").unwrap().revoked = 1;
        assert_eq!(
            observe_device(&revoked, "dev", false, false),
            DeviceObservation::Absent
        );
        assert_eq!(observe_device(&db, "other", false, false), DeviceObservation::Absent);
    }

    #[test]
    fn deletion_transaction_removes_the_whole_account() {
        let mut db = Db::default();
        db.users.insert(s("me"), UserRow { share_ek: s("ek"), share_ek_since: s("t") });
        db.devices.insert(
            s("d1"),
            DeviceRow {
                user_id: s("me"),
                revoked: 0,
                hybrid_vk: s("vk"),
                last_active: None,
                name: s("n"),
                kind: s("k"),
                revoked_at: None,
                revoked_by: None,
            },
        );
        db.sessions.insert(
            s("s1"),
            SessionRow {
                user_id: None,
                approver_user_id: Some(s("me")),
                status: s("pending"),
                capsule: None,
                approved_by: None,
            },
        );
        db.inbox.insert(s("i1"), MailRow { sender: s("me"), recipient: s("you") });
        let (outcomes, post) = deletion_transaction(&db, "me", None);
        assert!(outcomes.iter().all(|o| matches!(o, WriteOutcome::Applied(_))));
        assert_eq!(post, deleted_account(&db, "me"));
        assert!(post.users.is_empty() && post.devices.is_empty());
        assert!(post.sessions.is_empty() && post.inbox.is_empty());
        // A fault anywhere leaves the starting state.
        for k in 0..outcomes.len() {
            let (_, post) = deletion_transaction(&db, "me", Some(k));
            assert_eq!(post, db, "fault at {k}");
        }
    }
}
