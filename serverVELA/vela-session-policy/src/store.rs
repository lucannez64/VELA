//! The SQL and store operations behind the session executors, split so the
//! observation each executor returns can be proved against a store model
//! (F-1).
//!
//! Every executor method in scope is
//!
//! 1. a pure `plan_*` function from the method's inputs to typed statements
//!    ([`SqlStmt`] or [`StoreStmt`]);
//! 2. [`render_sql`] / [`render_store`], from each statement to the exact SQL
//!    text and parameters, or the exact store key, value and TTL the handler
//!    has always used (pinned by the unit tests below);
//! 3. a pure `classify_*` function from the per-statement outcomes to the
//!    observation the driver receives.
//!
//! The server runs a thin loop: plan, render and run each statement in order,
//! stop at the first failure, classify. hax extracts the plans and
//! classifiers; `proofs/fstar/store-lemmas` proves them against a model of the
//! tables and store keys these statements touch, for every starting database
//! and every failing statement.
//!
//! Every SQL value is text: ids, timestamps and names are all bound as text
//! parameters. Store values are the single byte the handlers wrote.
//!
//! The lockout helpers `rate_limit::revoke_all_device_jtis` and
//! `rate_limit::track_device_jti` are modelled as one logical statement each
//! ([`StoreStmt::RevokeJtis`], [`StoreStmt::AddMember`]): the executor only
//! ever learns whether the helper returned an error, and the helper's own keys
//! are tested directly in `vela-server/src/auth/session_store.rs`.

use crate::challenge::ChallengeConsumption;
use crate::challenge_issue_driver::{RateLimitObservation, StoreObservation};
use crate::deletion_driver::{
    CommitObservation, DeletionTable, LockoutObservation, ScanObservation, TableDeleteObservation,
    TransactionObservation, UsersDeleteObservation,
};
use crate::login_driver::{
    BackoffResetObservation, ChallengeObservation, DeviceObservation, FailureRecordObservation,
    TokenTrackObservation,
};
use crate::registration_driver::{BudgetObservation, InsertObservation, TrackObservation};
use crate::revocation_driver::{
    CascadeObservation, DeviceLookupObservation, LogoutObservation, RecordObservation,
    TargetObservation,
};
use crate::websession_driver::{
    DeleteRecordObservation, DeleteSentinelObservation, GrantUpdateObservation,
    StartInsertObservation, TokenClaimObservation, TokenIssueObservation,
};

/// The remaining-lifetime TTL of a revoked JTI, in seconds
/// (`rate_limit::TOKEN_MAX_LIFETIME_SECS`).
pub const TOKEN_MAX_LIFETIME_SECS: u64 = 15 * 60;
/// The ceiling of a granted web session, in seconds
/// (`web_session::MAX_TTL_SECS`); a revoked session is locked out for it.
pub const WEB_SESSION_MAX_TTL_SECS: u64 = 24 * 60 * 60;
/// The window of the per-(ip, device) failed-proof counter
/// (`rate_limit::verify_fail_by_device`).
pub const VERIFY_FAIL_WINDOW_SECS: u64 = 60;
/// How many failed proofs that window allows.
pub const VERIFY_FAIL_LIMIT: u64 = 5;
/// The TTL of a device's tracked-JTI set (`rate_limit::SESSION_HARD_CAP_SECS`).
pub const JTI_SET_TTL_SECS: u64 = 8 * 60 * 60;
/// 20 challenge issues per minute per IP (`rate_limit::challenge_by_ip`).
pub const CHALLENGE_RATE_LIMIT: u64 = 20;
/// The challenge limiter's fixed window (`rate_limit::WINDOW_SECS`).
pub const CHALLENGE_RATE_WINDOW_SECS: u64 = 60;
/// The lifetime of one issued challenge (`challenge::CHALLENGE_TTL_SECS`).
pub const CHALLENGE_TTL_SECS: u64 = 60;
/// 5 registrations per hour per IP (`account::RegisterIo`).
pub const REGISTER_RATE_LIMIT: u64 = 5;
/// The registration limiter's fixed window.
pub const REGISTER_RATE_WINDOW_SECS: u64 = 60 * 60;

/// One SQL statement an executor may run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlStmt {
    /// `SELECT id FROM devices WHERE user_id = ?`
    SelectDeviceIdsByUser { user: String },
    /// `SELECT id FROM web_sessions WHERE user_id = ? OR approver_user_id = ?`
    SelectWebSessionIdsByUser { user: String },
    /// The target `devices` row, by id.
    SelectDeviceById { device_id: String },
    /// `SELECT id FROM web_sessions WHERE approved_by = ? AND user_id = ? AND status != 'revoked'`
    SelectWebSessionIdsApprovedBy { device_id: String, user: String },
    /// `DELETE FROM web_sessions WHERE user_id = ? OR approver_user_id = ?`
    DeleteWebSessionsByUser { user: String },
    /// `DELETE FROM share_inbox WHERE recipient_user_id = ? OR sender_user_id = ?`
    DeleteShareInboxByUser { user: String },
    /// `DELETE FROM shared_items WHERE recipient_user_id = ? OR sender_user_id = ?`
    DeleteSharedItemsByUser { user: String },
    /// `DELETE FROM sends WHERE owner_user_id = ?`
    DeleteSendsByOwner { owner: String },
    /// `DELETE FROM vault_chunks WHERE user_id = ?`
    DeleteVaultChunksByUser { user: String },
    /// `DELETE FROM oram_buckets WHERE user_id = ?`
    DeleteOramBucketsByUser { user: String },
    /// `DELETE FROM devices WHERE user_id = ?`
    DeleteDevicesByUser { user: String },
    /// `DELETE FROM users WHERE id = ?`
    DeleteUserById { user: String },
    /// `UPDATE devices SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE id = ?`
    RevokeDeviceRecord {
        now: String,
        revoked_by: String,
        device_id: String,
    },
    /// `UPDATE web_sessions SET status = 'revoked', capsule = NULL ...`
    RevokeWebSessionsApprovedBy { device_id: String, user: String },
    /// The unrevoked target device row, by id:
    /// `SELECT ... FROM devices WHERE id = ? AND revoked = 0`.
    SelectUnrevokedDeviceById { device_id: String },
    /// `UPDATE devices SET last_active = ? WHERE id = ?` (best effort).
    UpdateDeviceLastActive { now: String, device_id: String },
    /// `UPDATE devices SET last_active = ?, device_name = ?, device_type = ? WHERE id = ?`
    /// (best effort).
    UpdateDeviceLastActiveNamed {
        now: String,
        name: String,
        kind: String,
        device_id: String,
    },
    /// `INSERT INTO users (id, created_at, share_ek, share_ek_since) VALUES (?, ?, ?, ?)`.
    /// The id is `UNIQUE`: an existing row makes the statement fail.
    InsertUser {
        user: String,
        now: String,
        share_ek: String,
        share_ek_since: String,
    },
    /// `INSERT INTO devices (id, user_id, device_name, device_type, last_active,
    /// hybrid_ek, hybrid_vk, enrolled_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`.
    /// The id is `UNIQUE`: an existing row makes the statement fail. `ek` and
    /// `vk` are already base64, exactly as the handler encoded them.
    InsertDevice {
        device: String,
        user: String,
        name: String,
        kind: String,
        now: String,
        ek: String,
        vk: String,
    },
    /// `SELECT COUNT(*) FROM users`: the registration account budget.
    CountUsers,
    /// `INSERT INTO web_sessions (id, user_id, approver_user_id,
    /// poll_secret_hash, ephemeral_pk, web_vk, link_nonce, mode, status,
    /// capsule, approved_by, created_at, expires_at) VALUES (?, NULL, ?, ?, ?,
    /// ?, ?, NULL, 'pending', NULL, NULL, ?, NULL)`. The id is `UNIQUE`: an
    /// existing row makes the statement fail.
    InsertPendingSession {
        session: String,
        approver: String,
        poll_secret_hash: String,
        ephemeral_pk: String,
        web_vk: String,
        link_nonce: String,
        now: String,
    },
    /// The grant compare-and-swap:
    /// `UPDATE web_sessions SET user_id = ?, mode = ?, status = 'granted',
    /// capsule = ?, approved_by = ?, expires_at = ?, key_epoch = ? WHERE id = ?
    /// AND status = 'pending' AND approver_user_id = ? AND EXISTS (SELECT 1
    /// FROM users WHERE id = ? AND rekey_state IS NULL AND key_epoch = ?) AND
    /// EXISTS (SELECT 1 FROM devices WHERE id = ? AND user_id = ? AND
    /// revoked = 0)`.
    ///
    /// `approved_by` is the approving device; it is also the device the second
    /// `EXISTS` names, and `user` is the granting account, the session's
    /// `approver_user_id` guard and the `users`/`devices` owner. Zero rows is
    /// the handler's `Conflict`.
    GrantWebSession {
        session: String,
        user: String,
        device: String,
        mode: String,
        capsule: String,
        expires_at: String,
        epoch: i64,
    },
    /// `UPDATE web_sessions SET status = 'revoked', capsule = NULL WHERE id = ?`
    /// (the delete handler's audit record; its row count is not observed).
    RevokeSessionById { session: String },
    /// Commit the open transaction.
    Commit,
}

/// One store statement an executor may run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreStmt {
    /// `set_ex(key, [value], ttl)`.
    SetEx { key: String, value: u8, ttl: u64 },
    /// `rate_limit::revoke_all_device_jtis(device)`: write a
    /// `jti:revoked:` marker for every tracked JTI and drop the tracking set.
    RevokeJtis { device: String },
    /// `Store::get_del(key)`: read the key's value and remove it.
    Take { key: String },
    /// One fixed-window counter increment (`rate_limit::check`): the count
    /// grows by one and the request is refused once it exceeds `limit`.
    Incr { key: String, limit: u64, ttl: u64 },
    /// `rate_limit::record_verify_failure` / `record_backoff_failure`: one
    /// logical statement that grows the `streak` counter and, from the third
    /// consecutive failure on, writes the `backoff` marker.
    BackoffFailure { streak: String, backoff: String },
    /// `rate_limit::reset_verify_streak` / `reset_backoff`: drop the `streak`
    /// counter and the `backoff` marker.
    ResetBackoff { streak: String, backoff: String },
    /// `rate_limit::track_device_jti`: add `member` to the `key` set.
    AddMember {
        key: String,
        member: String,
        ttl: u64,
    },
    /// `Store::set_ex_nx(key, value, ttl)`: insert only when the key is absent
    /// (first writer wins). The value is the exact bytes the handler stores,
    /// carried as text because every challenge tag is ASCII.
    SetExNx {
        key: String,
        value: String,
        ttl: u64,
    },
    /// `Store::set_ex_nx(key, [value], ttl)` with a one-byte value (the web
    /// token claim's marker).
    SetExNxByte {
        key: String,
        value: u8,
        ttl: u64,
    },
    /// `Store::exists(key)`: a read, so it never changes the store.
    Exists { key: String },
}

/// What one SQL statement returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// It ran; the number of rows it changed (0 for the commit).
    Applied(u64),
    /// It returned an error.
    Failed,
}

/// What one store statement returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOutcome {
    Applied,
    Failed,
}

/// What one read statement returned: its first row, or an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadOutcome<R> {
    Row(Option<R>),
    Failed,
}

/// What an id scan returned: the ids of the matching rows, or an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdsOutcome {
    Ids(Vec<String>),
    Failed,
}

/// The cells of a `SelectDeviceById` row that the classifier reads:
/// `user_id` and `revoked`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetRowView {
    pub user_id: Option<String>,
    pub revoked: Option<i64>,
}

/// What the atomic challenge take returned: the stored value it removed, or
/// the `get_del` error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TakeOutcome {
    Taken(Option<String>),
    Failed,
}

/// What a first-writer-wins insert (`set_ex_nx`) returned: it inserted, the
/// key was already there, or the store failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NxOutcome {
    Inserted,
    KeyExists,
    Failed,
}

/// What `Store::exists` returned: the key is present, absent, or the call
/// failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExistsOutcome {
    Present,
    Absent,
    Failed,
}

/// What `SELECT COUNT(*) FROM users` returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountOutcome {
    Count(i64),
    Failed,
}

/// What the unrevoked-device lookup returned, after decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceReadOutcome {
    /// One row with `revoked = 0`, decoded into a device.
    Row,
    /// One row, but its cells could not be decoded (the handler's internal
    /// error, which must not spend the challenge).
    Undecodable,
    /// No row: absent or already revoked.
    Missing,
    /// The query returned an error.
    Failed,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// `LogoutJtiIo::revoke_jti`: the caller's JTI marker, with the token
/// lifetime's TTL.
pub fn plan_logout(jti: String) -> Vec<StoreStmt> {
    vec![StoreStmt::SetEx {
        key: format!("jti:revoked:{}", jti),
        value: 1,
        ttl: TOKEN_MAX_LIFETIME_SECS,
    }]
}

/// One `device:revoked:` sentinel: a revoked device (or web session) is
/// rejected by the middleware for the whole token lifetime.
pub fn plan_sentinel(device: String, ttl: u64) -> Vec<StoreStmt> {
    vec![StoreStmt::SetEx {
        key: format!("device:revoked:{}", device),
        value: 1,
        ttl,
    }]
}

/// `RevokeDeviceIo::lockout_device`: revoke every tracked JTI, then — only if
/// that succeeded — write the sentinel.
pub fn plan_lockout_device(device: String) -> Vec<StoreStmt> {
    vec![
        StoreStmt::RevokeJtis {
            device: device.clone(),
        },
        StoreStmt::SetEx {
            key: format!("device:revoked:{}", device),
            value: 1,
            ttl: TOKEN_MAX_LIFETIME_SECS,
        },
    ]
}

/// `DeleteAccountIo::lockout_web_sessions`, per session: the sentinel first,
/// then every tracked JTI (the historical order).
pub fn plan_lockout_web_session(session: String) -> Vec<StoreStmt> {
    vec![
        StoreStmt::SetEx {
            key: format!("device:revoked:{}", session),
            value: 1,
            ttl: WEB_SESSION_MAX_TTL_SECS,
        },
        StoreStmt::RevokeJtis {
            device: session,
        },
    ]
}

/// `DeleteAccountIo::scan_devices`.
pub fn plan_scan_devices(user: String) -> SqlStmt {
    SqlStmt::SelectDeviceIdsByUser { user }
}

/// `DeleteAccountIo::scan_web_sessions`.
pub fn plan_scan_web_sessions(user: String) -> SqlStmt {
    SqlStmt::SelectWebSessionIdsByUser { user }
}

/// `DeleteAccountIo::delete_table`, in the driver's historical order.
pub fn plan_delete_table(user: String, table: DeletionTable) -> SqlStmt {
    match table {
        DeletionTable::WebSessions => SqlStmt::DeleteWebSessionsByUser { user },
        DeletionTable::ShareInbox => SqlStmt::DeleteShareInboxByUser { user },
        DeletionTable::SharedItems => SqlStmt::DeleteSharedItemsByUser { user },
        DeletionTable::Sends => SqlStmt::DeleteSendsByOwner { owner: user },
        DeletionTable::VaultChunks => SqlStmt::DeleteVaultChunksByUser { user },
        DeletionTable::OramBuckets => SqlStmt::DeleteOramBucketsByUser { user },
        DeletionTable::Devices => SqlStmt::DeleteDevicesByUser { user },
    }
}

/// `DeleteAccountIo::delete_users`: the account-existence signal.
pub fn plan_delete_users(user: String) -> SqlStmt {
    SqlStmt::DeleteUserById { user }
}

/// `DeleteAccountIo::commit`.
pub fn plan_commit() -> SqlStmt {
    SqlStmt::Commit
}

/// `RevokeDeviceIo::lookup_target`.
pub fn plan_target_lookup(device_id: String) -> SqlStmt {
    SqlStmt::SelectDeviceById { device_id }
}

/// `RevokeDeviceIo::record_revocation`.
pub fn plan_revoke_record(device_id: String, now: String, revoked_by: String) -> SqlStmt {
    SqlStmt::RevokeDeviceRecord {
        now,
        revoked_by,
        device_id,
    }
}

/// `revoke_web_sessions_approved_by`: read the sessions the device approved.
pub fn plan_cascade_read(device_id: String, user: String) -> SqlStmt {
    SqlStmt::SelectWebSessionIdsApprovedBy { device_id, user }
}

/// `revoke_web_sessions_approved_by`: mark the approved sessions revoked and
/// drop their capsules.
pub fn plan_cascade_update(device_id: String, user: String) -> SqlStmt {
    SqlStmt::RevokeWebSessionsApprovedBy { device_id, user }
}

/// The text `GET /auth/challenge` stores for `purpose`, as the atomic take
/// reads it back. The unit tests below pin the bytes to
/// `challenge::purpose_tag_bytes`, so this text form never drifts from the
/// value the issuer actually wrote.
#[cfg(not(hax))]
pub fn challenge_tag_text(purpose: crate::challenge::ChallengePurpose) -> String {
    String::from_utf8_lossy(crate::challenge::purpose_tag_bytes(purpose)).into_owned()
}

/// `VerifyIo::consume_challenge`: remove the one challenge key.
pub fn plan_take_challenge(challenge: String) -> Vec<StoreStmt> {
    vec![StoreStmt::Take {
        key: format!("challenge:{}", challenge),
    }]
}

/// `VerifyIo::observe_device`.
pub fn plan_login_device(device_id: String) -> SqlStmt {
    SqlStmt::SelectUnrevokedDeviceById { device_id }
}

/// `VerifyIo::record_verification_failure`: the log-only exponential-backoff
/// record for the request's `(ip, device)` scope.
pub fn plan_backoff_record(ip: String, device: String) -> Vec<StoreStmt> {
    vec![StoreStmt::BackoffFailure {
        streak: format!("rl:streak:verify:{}:{}", ip, device),
        backoff: format!("rl:backoff:verify:{}:{}", ip, device),
    }]
}

/// `VerifyIo::record_verification_failure`: the request-level failed-proof
/// counter, whose refusal is the only failure the driver propagates.
pub fn plan_failure_counter(ip: String, device: String) -> Vec<StoreStmt> {
    vec![StoreStmt::Incr {
        key: format!("rl:verify:fail:dev:{}:{}", ip, device),
        limit: VERIFY_FAIL_LIMIT,
        ttl: VERIFY_FAIL_WINDOW_SECS,
    }]
}

/// `VerifyIo::reset_backoff`: drop the success streak and backoff marker.
pub fn plan_reset_login_streak(ip: String, device: String) -> Vec<StoreStmt> {
    vec![StoreStmt::ResetBackoff {
        streak: format!("rl:streak:verify:{}:{}", ip, device),
        backoff: format!("rl:backoff:verify:{}:{}", ip, device),
    }]
}

/// `VerifyIo::reset_backoff`: the historical best-effort `last_active` stamp,
/// with the device's own name and type when the request did not rename it.
pub fn plan_login_last_active(
    device_id: String,
    now: String,
    name: Option<String>,
    kind: Option<String>,
) -> SqlStmt {
    match (name, kind) {
        (Some(name), Some(kind)) => SqlStmt::UpdateDeviceLastActiveNamed {
            now,
            name,
            kind,
            device_id,
        },
        _ => SqlStmt::UpdateDeviceLastActive { now, device_id },
    }
}

/// `VerifyIo::track_token`: register the issued JTI against the device.
pub fn plan_track_jti(device: String, jti: String) -> Vec<StoreStmt> {
    vec![StoreStmt::AddMember {
        key: format!("device:jtis:{}", device),
        member: jti,
        ttl: JTI_SET_TTL_SECS,
    }]
}

// ── Registration and challenge ─────────────────────────────────────────────

/// `ChallengeIssueIo::check_rate_limit`: the per-IP fixed window.
pub fn plan_challenge_rate_limit(ip: String) -> Vec<StoreStmt> {
    vec![StoreStmt::Incr {
        key: format!("rl:challenge:ip:{}", ip),
        limit: CHALLENGE_RATE_LIMIT,
        ttl: CHALLENGE_RATE_WINDOW_SECS,
    }]
}

/// `ChallengeIssueIo::store_nonce`: one purpose tag under the fresh nonce's
/// key, first writer wins.
pub fn plan_store_nonce(challenge: String, tag: String) -> Vec<StoreStmt> {
    vec![StoreStmt::SetExNx {
        key: format!("challenge:{}", challenge),
        value: tag,
        ttl: CHALLENGE_TTL_SECS,
    }]
}

/// `RegisterIo::check_rate_limit`: the per-IP fixed window.
pub fn plan_registration_rate_limit(ip: String) -> Vec<StoreStmt> {
    vec![StoreStmt::Incr {
        key: format!("rl:register:ip:{}", ip),
        limit: REGISTER_RATE_LIMIT,
        ttl: REGISTER_RATE_WINDOW_SECS,
    }]
}

/// `RegisterIo::check_account_budget`: the account-count query.
pub fn plan_account_count() -> SqlStmt {
    SqlStmt::CountUsers
}

/// `RegisterIo::insert_account`.
pub fn plan_insert_account(
    user: String,
    now: String,
    share_ek: String,
    share_ek_since: String,
) -> SqlStmt {
    SqlStmt::InsertUser {
        user,
        now,
        share_ek,
        share_ek_since,
    }
}

/// `RegisterIo::insert_device`.
pub fn plan_insert_device(
    device: String,
    user: String,
    name: String,
    kind: String,
    now: String,
    ek: String,
    vk: String,
) -> SqlStmt {
    SqlStmt::InsertDevice {
        device,
        user,
        name,
        kind,
        now,
        ek,
        vk,
    }
}

// ── Web sessions ───────────────────────────────────────────────────────────

/// `StartIo::insert_pending`: the one pending `web_sessions` row, with the
/// account the browser committed to and `user_id`/grant fields still NULL.
pub fn plan_insert_pending(
    session: String,
    approver: String,
    poll_secret_hash: String,
    ephemeral_pk: String,
    web_vk: String,
    link_nonce: String,
    now: String,
) -> SqlStmt {
    SqlStmt::InsertPendingSession {
        session,
        approver,
        poll_secret_hash,
        ephemeral_pk,
        web_vk,
        link_nonce,
        now,
    }
}

/// `GrantIo::update_grant`: the guarded compare-and-swap that publishes the
/// grant only while the session is still pending for this approver, the
/// account is not mid-rekey at the declared epoch, and the approving device is
/// stored, owned by the account and unrevoked.
pub fn plan_grant_update(
    session: String,
    user: String,
    device: String,
    mode: String,
    capsule: String,
    expires_at: String,
    epoch: i64,
) -> SqlStmt {
    SqlStmt::GrantWebSession {
        session,
        user,
        device,
        mode,
        capsule,
        expires_at,
        epoch,
    }
}

/// `DeleteSessionIo::record_revocation`: the audit row.
pub fn plan_revoke_session(session: String) -> SqlStmt {
    SqlStmt::RevokeSessionById { session }
}

/// `TokenIo::claim_token`: the one `web_session:token_issued:` marker, first
/// writer wins for the session's whole token ceiling.
pub fn plan_token_claim(session: String) -> Vec<StoreStmt> {
    vec![StoreStmt::SetExNxByte {
        key: format!("web_session:token_issued:{}", session),
        value: 1,
        ttl: WEB_SESSION_MAX_TTL_SECS,
    }]
}

/// `TokenIo::issue_token`: the issue-time lockout re-check. It reads the
/// sentinel the delete handler and the revocation cascade write.
pub fn plan_token_sentinel(session: String) -> Vec<StoreStmt> {
    vec![StoreStmt::Exists {
        key: format!("device:revoked:{}", session),
    }]
}

// ── Classification ─────────────────────────────────────────────────────────

/// The logout marker: it was written exactly when its one statement ran.
pub fn classify_logout(outcomes: &[StoreOutcome]) -> LogoutObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            StoreOutcome::Applied => LogoutObservation::Applied,
            StoreOutcome::Failed => LogoutObservation::StorageFailed,
        }
    } else {
        LogoutObservation::StorageFailed
    }
}

/// The device lockout: both statements ran. A `Failed` outcome means the
/// sentinel was not written (the JTI enumeration failed first).
pub fn classify_lockout_device(
    outcomes: &[StoreOutcome],
) -> crate::revocation_driver::LockoutObservation {
    if outcomes.len() == 2 {
        match (outcomes[0], outcomes[1]) {
            (StoreOutcome::Applied, StoreOutcome::Applied) => {
                crate::revocation_driver::LockoutObservation::Applied
            }
            _ => crate::revocation_driver::LockoutObservation::StorageFailed,
        }
    } else {
        crate::revocation_driver::LockoutObservation::StorageFailed
    }
}

/// A row scan: it returned rows exactly when its one query ran.
pub fn classify_scan(outcome: &IdsOutcome) -> ScanObservation {
    match outcome {
        IdsOutcome::Ids(_) => ScanObservation::Rows,
        IdsOutcome::Failed => ScanObservation::QueryFailed,
    }
}

/// A batch lockout whose failures the deletion handler ignores: it always
/// reports `Applied`, exactly as before (the observation carries no claim
/// about the store).
pub fn classify_lockout_ignored(_outcomes: &[StoreOutcome]) -> LockoutObservation {
    LockoutObservation::Applied
}

/// Opening the transaction.
pub fn classify_transaction(outcome: &WriteOutcome) -> TransactionObservation {
    match outcome {
        WriteOutcome::Applied(_) => TransactionObservation::Begun,
        WriteOutcome::Failed => TransactionObservation::Failed,
    }
}

/// One table delete.
pub fn classify_table_delete(outcome: &WriteOutcome) -> TableDeleteObservation {
    match outcome {
        WriteOutcome::Applied(_) => TableDeleteObservation::Deleted,
        WriteOutcome::Failed => TableDeleteObservation::Failed,
    }
}

/// The `users` delete: zero rows is the account-absence signal.
pub fn classify_users_delete(outcome: &WriteOutcome) -> UsersDeleteObservation {
    match outcome {
        WriteOutcome::Applied(0) => UsersDeleteObservation::Absent,
        WriteOutcome::Applied(_) => UsersDeleteObservation::Deleted,
        WriteOutcome::Failed => UsersDeleteObservation::Failed,
    }
}

/// The commit.
pub fn classify_commit(outcome: &WriteOutcome) -> CommitObservation {
    match outcome {
        WriteOutcome::Applied(_) => CommitObservation::Committed,
        WriteOutcome::Failed => CommitObservation::Failed,
    }
}

/// The target device row as the revocation policy sees it. A failed read is a
/// storage failure; a missing row is `Absent`. A row the handler cannot decode
/// is reported as `Malformed` before this classifier runs.
#[allow(clippy::ptr_arg)]
pub fn classify_target(
    caller: &String,
    outcome: &ReadOutcome<TargetRowView>,
) -> DeviceLookupObservation {
    match outcome {
        ReadOutcome::Row(Some(row)) => DeviceLookupObservation::Present(TargetObservation {
            same_account: match &row.user_id {
                Some(owner) => owner == caller,
                None => false,
            },
            // Mirror the handler's `revoked != 0` cell rule.
            already_revoked: match row.revoked {
                Some(revoked) => revoked != 0,
                None => false,
            },
        }),
        ReadOutcome::Row(None) => DeviceLookupObservation::Absent,
        ReadOutcome::Failed => DeviceLookupObservation::QueryFailed,
    }
}

/// The durable revocation record: it was written exactly when its one
/// statement ran.
pub fn classify_record(outcome: &WriteOutcome) -> RecordObservation {
    match outcome {
        WriteOutcome::Applied(_) => RecordObservation::Updated,
        WriteOutcome::Failed => RecordObservation::Failed,
    }
}

/// The approved-web-session cascade: `ok` is the read, every per-session
/// lockout and the SQL update all having succeeded.
pub fn classify_cascade(ok: bool) -> CascadeObservation {
    if ok {
        CascadeObservation::Completed
    } else {
        CascadeObservation::StorageFailed
    }
}

// ── Login: VerifyIo ────────────────────────────────────────────────────────

/// The atomic challenge take: `StorageFailed` exactly when the take failed;
/// otherwise the observation is the exact match of the value it removed
/// against the tag this consumer expected. A present but different value (or
/// an unrecognized one) is spent and reported as the wrong purpose.
pub fn classify_login_challenge(
    outcome: &TakeOutcome,
    expected_tag: &String,
) -> ChallengeObservation {
    match outcome {
        TakeOutcome::Taken(Some(value)) => {
            if value == expected_tag {
                ChallengeObservation::Observed(ChallengeConsumption::Accepted)
            } else {
                ChallengeObservation::Observed(ChallengeConsumption::WrongPurpose)
            }
        }
        TakeOutcome::Taken(None) => ChallengeObservation::Observed(ChallengeConsumption::Missing),
        TakeOutcome::Failed => ChallengeObservation::StorageFailed,
    }
}

/// The unrevoked-device lookup: the observation names exactly what the query
/// and decoder produced.
pub fn classify_login_device(outcome: &DeviceReadOutcome) -> DeviceObservation {
    match outcome {
        DeviceReadOutcome::Row => DeviceObservation::Present,
        DeviceReadOutcome::Undecodable => DeviceObservation::ParseFailed,
        DeviceReadOutcome::Missing => DeviceObservation::Absent,
        DeviceReadOutcome::Failed => DeviceObservation::QueryFailed,
    }
}

/// The failed-proof side effects: only the request-level counter's refusal is
/// reported; the log-only backoff record cannot change the observation.
pub fn classify_failure_counter(outcomes: &[StoreOutcome]) -> FailureRecordObservation {
    let fallback_counter_ok = outcomes.len() == 1
        && match outcomes[0] {
            StoreOutcome::Applied => true,
            StoreOutcome::Failed => false,
        };
    FailureRecordObservation { fallback_counter_ok }
}

/// The success-streak reset: `Reset` exactly when its one statement ran.
pub fn classify_backoff_reset(outcome: &StoreOutcome) -> BackoffResetObservation {
    match outcome {
        StoreOutcome::Applied => BackoffResetObservation::Reset,
        StoreOutcome::Failed => BackoffResetObservation::StorageFailed,
    }
}

/// JTI tracking: `Tracked` exactly when the set add ran.
pub fn classify_track_jti(outcome: &StoreOutcome) -> TokenTrackObservation {
    match outcome {
        StoreOutcome::Applied => TokenTrackObservation::Tracked,
        StoreOutcome::Failed => TokenTrackObservation::Failed,
    }
}

// ── Registration and challenge ─────────────────────────────────────────────

/// A rate limiter: `Allowed` exactly when its one counter statement ran.
pub fn classify_challenge_rate_limit(outcome: &StoreOutcome) -> RateLimitObservation {
    match outcome {
        StoreOutcome::Applied => RateLimitObservation::Allowed,
        StoreOutcome::Failed => RateLimitObservation::Denied,
    }
}

/// The first-writer-wins challenge write: `Inserted` exactly when the key was
/// absent and the write ran.
pub fn classify_store_nonce(outcome: &NxOutcome) -> StoreObservation {
    match outcome {
        NxOutcome::Inserted => StoreObservation::Inserted,
        NxOutcome::KeyExists => StoreObservation::KeyExists,
        NxOutcome::Failed => StoreObservation::Failed,
    }
}

/// The registration limiter.
pub fn classify_registration_rate_limit(
    outcome: &StoreOutcome,
) -> crate::registration_driver::RateLimitObservation {
    match outcome {
        StoreOutcome::Applied => crate::registration_driver::RateLimitObservation::Allowed,
        StoreOutcome::Failed => crate::registration_driver::RateLimitObservation::Denied,
    }
}

/// The registration transaction begin.
pub fn classify_registration_transaction(
    outcome: &WriteOutcome,
) -> crate::registration_driver::TransactionObservation {
    match outcome {
        WriteOutcome::Applied(_) => crate::registration_driver::TransactionObservation::Begun,
        WriteOutcome::Failed => crate::registration_driver::TransactionObservation::Failed,
    }
}

/// The registration commit.
pub fn classify_registration_commit(
    outcome: &WriteOutcome,
) -> crate::registration_driver::CommitObservation {
    match outcome {
        WriteOutcome::Applied(_) => crate::registration_driver::CommitObservation::Committed,
        WriteOutcome::Failed => crate::registration_driver::CommitObservation::Failed,
    }
}

/// The account budget: `Counted` exactly when the query ran, carrying the
/// exact number of `users` rows.
pub fn classify_account_count(outcome: &CountOutcome) -> BudgetObservation {
    match outcome {
        CountOutcome::Count(count) => BudgetObservation::Counted { count: *count },
        CountOutcome::Failed => BudgetObservation::QueryFailed,
    }
}

/// One `INSERT`: `Inserted` exactly when it ran (its id was fresh).
pub fn classify_insert(outcome: &WriteOutcome) -> InsertObservation {
    match outcome {
        WriteOutcome::Applied(_) => InsertObservation::Inserted,
        WriteOutcome::Failed => InsertObservation::Failed,
    }
}

/// `RegisterIo::track_token`: `Tracked` exactly when the set add ran.
pub fn classify_registration_track(outcome: &StoreOutcome) -> TrackObservation {
    match outcome {
        StoreOutcome::Applied => TrackObservation::Tracked,
        StoreOutcome::Failed => TrackObservation::Failed,
    }
}

// ── Web sessions ───────────────────────────────────────────────────────────

/// `StartIo::insert_pending`: `Inserted` exactly when the one statement ran
/// (its id was fresh).
pub fn classify_start_insert(outcome: &WriteOutcome) -> StartInsertObservation {
    match outcome {
        WriteOutcome::Applied(_) => StartInsertObservation::Inserted,
        WriteOutcome::Failed => StartInsertObservation::Failed,
    }
}

/// `GrantIo::update_grant`: zero rows is the CAS conflict; a failure is the
/// storage error; one row is the grant.
pub fn classify_grant_update(outcome: &WriteOutcome) -> GrantUpdateObservation {
    match outcome {
        WriteOutcome::Applied(0) => GrantUpdateObservation::Conflict,
        WriteOutcome::Applied(_) => GrantUpdateObservation::Updated,
        WriteOutcome::Failed => GrantUpdateObservation::Failed,
    }
}

/// `TokenIo::claim_token`: `Claimed` exactly when this call inserted the
/// marker, `AlreadyClaimed` when it was already there.
pub fn classify_token_claim(outcome: &NxOutcome) -> TokenClaimObservation {
    match outcome {
        NxOutcome::Inserted => TokenClaimObservation::Claimed,
        NxOutcome::KeyExists => TokenClaimObservation::AlreadyClaimed,
        NxOutcome::Failed => TokenClaimObservation::StorageFailed,
    }
}

/// `TokenIo::issue_token`: `Issued` exactly when the issuer produced a token,
/// the issue-time sentinel was absent and the JTI was tracked.
pub fn classify_token_issue(
    issued: bool,
    sentinel: &ExistsOutcome,
    tracked: &StoreOutcome,
) -> TokenIssueObservation {
    if issued
        && matches!(sentinel, ExistsOutcome::Absent)
        && matches!(tracked, StoreOutcome::Applied)
    {
        TokenIssueObservation::Issued
    } else {
        TokenIssueObservation::Failed
    }
}

/// `DeleteSessionIo::lockout_session`: `Applied` exactly when the sentinel
/// write ran.
pub fn classify_lockout_session(outcome: &StoreOutcome) -> DeleteSentinelObservation {
    match outcome {
        StoreOutcome::Applied => DeleteSentinelObservation::Applied,
        StoreOutcome::Failed => DeleteSentinelObservation::StorageFailed,
    }
}

/// `DeleteSessionIo::record_revocation`: `Updated` exactly when the audit
/// statement ran (its row count is not observed).
pub fn classify_revoke_session(outcome: &WriteOutcome) -> DeleteRecordObservation {
    match outcome {
        WriteOutcome::Applied(_) => DeleteRecordObservation::Updated,
        WriteOutcome::Failed => DeleteRecordObservation::Failed,
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

/// One SQL statement as the database receives it.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rendered {
    Query { sql: &'static str, params: Vec<String> },
    Execute { sql: &'static str, params: Vec<String> },
    /// An `execute` whose parameters mix text and integer cells, exactly as
    /// the handler bound them.
    ExecuteMixed {
        sql: &'static str,
        params: Vec<Param>,
    },
    Commit,
}

/// One bound parameter.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Param {
    Text(String),
    Int(i64),
}

/// The store operation a [`StoreStmt`] performs.
#[cfg(not(hax))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOp {
    SetEx,
    RevokeJtis,
    Take,
    Incr,
    BackoffFailure,
    ResetBackoff,
    AddMember,
    SetExNx,
    SetExNxByte,
    Exists,
}

/// One store statement as the handler sends it.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedStore {
    pub op: StoreOp,
    /// The key (`SetEx`, `Take`, `Incr`, `AddMember`) or the device/scope
    /// whose JTIs are revoked / whose streak is touched.
    pub key: String,
    pub value: u8,
    pub ttl: u64,
    /// The counter ceiling (`Incr`), or the tracked member (`AddMember`), or
    /// the scope's backoff key (`BackoffFailure`, `ResetBackoff`).
    pub limit: u64,
    pub member: String,
}

/// The exact SQL text and text parameters each statement has always used.
#[cfg(not(hax))]
pub fn render_sql(stmt: &SqlStmt) -> Rendered {
    match stmt {
        SqlStmt::SelectDeviceIdsByUser { user } => Rendered::Query {
            sql: "SELECT id FROM devices WHERE user_id = ?",
            params: vec![user.clone()],
        },
        SqlStmt::SelectWebSessionIdsByUser { user } => Rendered::Query {
            sql: "SELECT id FROM web_sessions WHERE user_id = ? OR approver_user_id = ?",
            params: vec![user.clone(), user.clone()],
        },
        SqlStmt::SelectDeviceById { device_id } => Rendered::Query {
            sql: "SELECT id, user_id, device_name, device_type, last_active,
                    hybrid_ek, hybrid_vk,
                    enrolled_by, rms_capsule, revoked,
                    revoked_at, revoked_by, created_at
             FROM devices
             WHERE id = ?",
            params: vec![device_id.clone()],
        },
        SqlStmt::SelectWebSessionIdsApprovedBy { device_id, user } => Rendered::Query {
            sql: "SELECT id FROM web_sessions
             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'",
            params: vec![device_id.clone(), user.clone()],
        },
        SqlStmt::DeleteWebSessionsByUser { user } => Rendered::Execute {
            sql: "DELETE FROM web_sessions WHERE user_id = ? OR approver_user_id = ?",
            params: vec![user.clone(), user.clone()],
        },
        SqlStmt::DeleteShareInboxByUser { user } => Rendered::Execute {
            sql: "DELETE FROM share_inbox WHERE recipient_user_id = ? OR sender_user_id = ?",
            params: vec![user.clone(), user.clone()],
        },
        SqlStmt::DeleteSharedItemsByUser { user } => Rendered::Execute {
            sql: "DELETE FROM shared_items WHERE recipient_user_id = ? OR sender_user_id = ?",
            params: vec![user.clone(), user.clone()],
        },
        SqlStmt::DeleteSendsByOwner { owner } => Rendered::Execute {
            sql: "DELETE FROM sends WHERE owner_user_id = ?",
            params: vec![owner.clone()],
        },
        SqlStmt::DeleteVaultChunksByUser { user } => Rendered::Execute {
            sql: "DELETE FROM vault_chunks WHERE user_id = ?",
            params: vec![user.clone()],
        },
        SqlStmt::DeleteOramBucketsByUser { user } => Rendered::Execute {
            sql: "DELETE FROM oram_buckets WHERE user_id = ?",
            params: vec![user.clone()],
        },
        SqlStmt::DeleteDevicesByUser { user } => Rendered::Execute {
            sql: "DELETE FROM devices WHERE user_id = ?",
            params: vec![user.clone()],
        },
        SqlStmt::DeleteUserById { user } => Rendered::Execute {
            sql: "DELETE FROM users WHERE id = ?",
            params: vec![user.clone()],
        },
        SqlStmt::RevokeDeviceRecord {
            now,
            revoked_by,
            device_id,
        } => Rendered::Execute {
            sql: "UPDATE devices SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE id = ?",
            params: vec![now.clone(), revoked_by.clone(), device_id.clone()],
        },
        SqlStmt::RevokeWebSessionsApprovedBy { device_id, user } => Rendered::Execute {
            sql: "UPDATE web_sessions SET status = 'revoked', capsule = NULL
             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'",
            params: vec![device_id.clone(), user.clone()],
        },
        SqlStmt::SelectUnrevokedDeviceById { device_id } => Rendered::Query {
            sql: "SELECT id, user_id, device_name, device_type, last_active,
                    hybrid_ek, hybrid_vk,
                    enrolled_by, rms_capsule, revoked,
                    revoked_at, revoked_by, created_at
                 FROM devices
                 WHERE id = ? AND revoked = 0",
            params: vec![device_id.clone()],
        },
        SqlStmt::UpdateDeviceLastActive { now, device_id } => Rendered::Execute {
            sql: "UPDATE devices SET last_active = ? WHERE id = ?",
            params: vec![now.clone(), device_id.clone()],
        },
        SqlStmt::UpdateDeviceLastActiveNamed {
            now,
            name,
            kind,
            device_id,
        } => Rendered::Execute {
            sql: "UPDATE devices SET last_active = ?, device_name = ?, device_type = ? WHERE id = ?",
            params: vec![now.clone(), name.clone(), kind.clone(), device_id.clone()],
        },
        SqlStmt::InsertUser {
            user,
            now,
            share_ek,
            share_ek_since,
        } => Rendered::Execute {
            sql: "INSERT INTO users (id, created_at, share_ek, share_ek_since)
             VALUES (?, ?, ?, ?)",
            params: vec![
                user.clone(),
                now.clone(),
                share_ek.clone(),
                share_ek_since.clone(),
            ],
        },
        SqlStmt::InsertDevice {
            device,
            user,
            name,
            kind,
            now,
            ek,
            vk,
        } => Rendered::Execute {
            sql: "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            params: vec![
                device.clone(),
                user.clone(),
                name.clone(),
                kind.clone(),
                now.clone(),
                ek.clone(),
                vk.clone(),
                now.clone(),
            ],
        },
        SqlStmt::CountUsers => Rendered::Query {
            sql: "SELECT COUNT(*) FROM users",
            params: vec![],
        },
        SqlStmt::InsertPendingSession {
            session,
            approver,
            poll_secret_hash,
            ephemeral_pk,
            web_vk,
            link_nonce,
            now,
        } => Rendered::Execute {
            sql: "INSERT INTO web_sessions
                    (id, user_id, approver_user_id, poll_secret_hash, ephemeral_pk, web_vk, link_nonce, mode, status, capsule, approved_by, created_at, expires_at)
                 VALUES (?, NULL, ?, ?, ?, ?, ?, NULL, 'pending', NULL, NULL, ?, NULL)",
            params: vec![
                session.clone(),
                approver.clone(),
                poll_secret_hash.clone(),
                ephemeral_pk.clone(),
                web_vk.clone(),
                link_nonce.clone(),
                now.clone(),
            ],
        },
        SqlStmt::GrantWebSession {
            session,
            user,
            device,
            mode,
            capsule,
            expires_at,
            epoch,
        } => Rendered::ExecuteMixed {
            sql: "UPDATE web_sessions
                 SET user_id = ?, mode = ?, status = 'granted', capsule = ?,
                     approved_by = ?, expires_at = ?,
                     key_epoch = ?
                 WHERE id = ? AND status = 'pending' AND approver_user_id = ?
                   AND EXISTS (
                       SELECT 1 FROM users
                       WHERE id = ? AND rekey_state IS NULL AND key_epoch = ?
                   )
                   -- A device being revoked cannot slip a grant past the
                   -- revocation cascade (see device::revoke).
                   AND EXISTS (
                       SELECT 1 FROM devices
                       WHERE id = ? AND user_id = ? AND revoked = 0
                   )",
            params: vec![
                Param::Text(user.clone()),
                Param::Text(mode.clone()),
                Param::Text(capsule.clone()),
                Param::Text(device.clone()),
                Param::Text(expires_at.clone()),
                Param::Int(*epoch),
                Param::Text(session.clone()),
                Param::Text(user.clone()),
                Param::Text(user.clone()),
                Param::Int(*epoch),
                Param::Text(device.clone()),
                Param::Text(user.clone()),
            ],
        },
        SqlStmt::RevokeSessionById { session } => Rendered::Execute {
            sql: "UPDATE web_sessions SET status = 'revoked', capsule = NULL WHERE id = ?",
            params: vec![session.clone()],
        },
        SqlStmt::Commit => Rendered::Commit,
    }
}

/// The exact key, value and TTL each store statement has always used.
#[cfg(not(hax))]
pub fn render_store(stmt: &StoreStmt) -> RenderedStore {
    match stmt {
        StoreStmt::SetEx { key, value, ttl } => RenderedStore {
            op: StoreOp::SetEx,
            key: key.clone(),
            value: *value,
            ttl: *ttl,
            limit: 0,
            member: String::new(),
        },
        StoreStmt::RevokeJtis { device } => RenderedStore {
            op: StoreOp::RevokeJtis,
            key: device.clone(),
            value: 0,
            ttl: 0,
            limit: 0,
            member: String::new(),
        },
        StoreStmt::Take { key } => RenderedStore {
            op: StoreOp::Take,
            key: key.clone(),
            value: 0,
            ttl: 0,
            limit: 0,
            member: String::new(),
        },
        StoreStmt::Incr { key, limit, ttl } => RenderedStore {
            op: StoreOp::Incr,
            key: key.clone(),
            value: 1,
            ttl: *ttl,
            limit: *limit,
            member: String::new(),
        },
        StoreStmt::BackoffFailure { streak, backoff } => RenderedStore {
            op: StoreOp::BackoffFailure,
            key: streak.clone(),
            value: 0,
            ttl: 0,
            limit: 0,
            member: backoff.clone(),
        },
        StoreStmt::ResetBackoff { streak, backoff } => RenderedStore {
            op: StoreOp::ResetBackoff,
            key: streak.clone(),
            value: 0,
            ttl: 0,
            limit: 0,
            member: backoff.clone(),
        },
        StoreStmt::AddMember { key, member, ttl } => RenderedStore {
            op: StoreOp::AddMember,
            key: key.clone(),
            value: 0,
            ttl: *ttl,
            limit: 0,
            member: member.clone(),
        },
        StoreStmt::SetExNx { key, value, ttl } => RenderedStore {
            op: StoreOp::SetExNx,
            key: key.clone(),
            value: 0,
            ttl: *ttl,
            limit: 0,
            member: value.clone(),
        },
        StoreStmt::SetExNxByte { key, value, ttl } => RenderedStore {
            op: StoreOp::SetExNxByte,
            key: key.clone(),
            value: *value,
            ttl: *ttl,
            limit: 0,
            member: String::new(),
        },
        StoreStmt::Exists { key } => RenderedStore {
            op: StoreOp::Exists,
            key: key.clone(),
            value: 0,
            ttl: 0,
            limit: 0,
            member: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn exec(stmt: &SqlStmt) -> (&'static str, Vec<String>) {
        match render_sql(stmt) {
            Rendered::Execute { sql, params } => (sql, params),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    fn query(stmt: &SqlStmt) -> (&'static str, Vec<String>) {
        match render_sql(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    fn mixed(stmt: &SqlStmt) -> (&'static str, Vec<Param>) {
        match render_sql(stmt) {
            Rendered::ExecuteMixed { sql, params } => (sql, params),
            other => panic!("expected a mixed write, got {other:?}"),
        }
    }

    // The expected strings are byte-for-byte copies of the literals the
    // handlers used before the split (vela-server at b9e3d67), including their
    // line breaks and indentation.

    #[test]
    fn logout_writes_the_historical_jti_marker() {
        let plan = plan_logout(s("j"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::SetEx,
                key: s("jti:revoked:j"),
                value: 1,
                ttl: 900,
                limit: 0,
                member: String::new()
            }
        );
        assert_eq!(classify_logout(&[StoreOutcome::Applied]), LogoutObservation::Applied);
        assert_eq!(
            classify_logout(&[StoreOutcome::Failed]),
            LogoutObservation::StorageFailed
        );
        assert_eq!(classify_logout(&[]), LogoutObservation::StorageFailed);
    }

    #[test]
    fn revocation_plans_render_the_historical_statements() {
        let (sql, params) = query(&plan_target_lookup(s("dev")));
        assert_eq!(
            sql,
            "SELECT id, user_id, device_name, device_type, last_active,\n                    hybrid_ek, hybrid_vk,\n                    enrolled_by, rms_capsule, revoked,\n                    revoked_at, revoked_by, created_at\n             FROM devices\n             WHERE id = ?"
        );
        assert_eq!(params, vec![s("dev")]);

        let (sql, params) = exec(&plan_revoke_record(s("dev"), s("now"), s("by")));
        assert_eq!(
            sql,
            "UPDATE devices SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE id = ?"
        );
        assert_eq!(params, vec![s("now"), s("by"), s("dev")]);

        let (sql, params) = query(&plan_cascade_read(s("dev"), s("me")));
        assert_eq!(
            sql,
            "SELECT id FROM web_sessions\n             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'"
        );
        assert_eq!(params, vec![s("dev"), s("me")]);

        let (sql, params) = exec(&plan_cascade_update(s("dev"), s("me")));
        assert_eq!(
            sql,
            "UPDATE web_sessions SET status = 'revoked', capsule = NULL\n             WHERE approved_by = ? AND user_id = ? AND status != 'revoked'"
        );
        assert_eq!(params, vec![s("dev"), s("me")]);
    }

    #[test]
    fn lockout_plans_render_the_historical_store_keys() {
        let plan = plan_lockout_device(s("dev"));
        assert_eq!(plan.len(), 2);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::RevokeJtis,
                key: s("dev"),
                value: 0,
                ttl: 0,
                limit: 0,
                member: String::new()
            }
        );
        assert_eq!(
            render_store(&plan[1]),
            RenderedStore {
                op: StoreOp::SetEx,
                key: s("device:revoked:dev"),
                value: 1,
                ttl: 900,
                limit: 0,
                member: String::new()
            }
        );

        let plan = plan_lockout_web_session(s("sess"));
        assert_eq!(plan.len(), 2);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::SetEx,
                key: s("device:revoked:sess"),
                value: 1,
                ttl: 86_400,
                limit: 0,
                member: String::new()
            }
        );
        assert_eq!(
            render_store(&plan[1]),
            RenderedStore {
                op: StoreOp::RevokeJtis,
                key: s("sess"),
                value: 0,
                ttl: 0,
                limit: 0,
                member: String::new()
            }
        );

        assert_eq!(
            render_store(&plan_sentinel(s("dev"), 86_400)[0]),
            RenderedStore {
                op: StoreOp::SetEx,
                key: s("device:revoked:dev"),
                value: 1,
                ttl: 86_400,
                limit: 0,
                member: String::new()
            }
        );
    }

    #[test]
    fn deletion_plans_render_the_historical_statements() {
        let (sql, params) = query(&plan_scan_devices(s("me")));
        assert_eq!(sql, "SELECT id FROM devices WHERE user_id = ?");
        assert_eq!(params, vec![s("me")]);

        let (sql, params) = query(&plan_scan_web_sessions(s("me")));
        assert_eq!(
            sql,
            "SELECT id FROM web_sessions WHERE user_id = ? OR approver_user_id = ?"
        );
        assert_eq!(params, vec![s("me"), s("me")]);

        let expected = [
            (
                DeletionTable::WebSessions,
                "DELETE FROM web_sessions WHERE user_id = ? OR approver_user_id = ?",
                vec![s("me"), s("me")],
            ),
            (
                DeletionTable::ShareInbox,
                "DELETE FROM share_inbox WHERE recipient_user_id = ? OR sender_user_id = ?",
                vec![s("me"), s("me")],
            ),
            (
                DeletionTable::SharedItems,
                "DELETE FROM shared_items WHERE recipient_user_id = ? OR sender_user_id = ?",
                vec![s("me"), s("me")],
            ),
            (
                DeletionTable::Sends,
                "DELETE FROM sends WHERE owner_user_id = ?",
                vec![s("me")],
            ),
            (
                DeletionTable::VaultChunks,
                "DELETE FROM vault_chunks WHERE user_id = ?",
                vec![s("me")],
            ),
            (
                DeletionTable::OramBuckets,
                "DELETE FROM oram_buckets WHERE user_id = ?",
                vec![s("me")],
            ),
            (
                DeletionTable::Devices,
                "DELETE FROM devices WHERE user_id = ?",
                vec![s("me")],
            ),
        ];
        for (table, sql, params) in expected {
            let (got_sql, got_params) = exec(&plan_delete_table(s("me"), table));
            assert_eq!(got_sql, sql, "table {table:?}");
            assert_eq!(got_params, params, "table {table:?}");
        }

        let (sql, params) = exec(&plan_delete_users(s("me")));
        assert_eq!(sql, "DELETE FROM users WHERE id = ?");
        assert_eq!(params, vec![s("me")]);
        assert_eq!(render_sql(&plan_commit()), Rendered::Commit);
    }

    #[test]
    fn classifiers_keep_the_historical_observations() {
        assert_eq!(classify_scan(&IdsOutcome::Ids(vec![])), ScanObservation::Rows);
        assert_eq!(classify_scan(&IdsOutcome::Failed), ScanObservation::QueryFailed);
        assert_eq!(
            classify_transaction(&WriteOutcome::Applied(0)),
            TransactionObservation::Begun
        );
        assert_eq!(
            classify_transaction(&WriteOutcome::Failed),
            TransactionObservation::Failed
        );
        assert_eq!(
            classify_table_delete(&WriteOutcome::Applied(0)),
            TableDeleteObservation::Deleted
        );
        assert_eq!(
            classify_users_delete(&WriteOutcome::Applied(0)),
            UsersDeleteObservation::Absent
        );
        assert_eq!(
            classify_users_delete(&WriteOutcome::Applied(1)),
            UsersDeleteObservation::Deleted
        );
        assert_eq!(
            classify_users_delete(&WriteOutcome::Failed),
            UsersDeleteObservation::Failed
        );
        assert_eq!(
            classify_commit(&WriteOutcome::Applied(0)),
            CommitObservation::Committed
        );
        assert_eq!(
            classify_commit(&WriteOutcome::Failed),
            CommitObservation::Failed
        );
        assert_eq!(
            classify_record(&WriteOutcome::Applied(0)),
            RecordObservation::Updated
        );
        assert_eq!(classify_record(&WriteOutcome::Failed), RecordObservation::Failed);
        assert_eq!(classify_cascade(true), CascadeObservation::Completed);
        assert_eq!(
            classify_cascade(false),
            CascadeObservation::StorageFailed
        );
        assert_eq!(
            classify_lockout_device(&[StoreOutcome::Applied, StoreOutcome::Applied]),
            crate::revocation_driver::LockoutObservation::Applied
        );
        assert_eq!(
            classify_lockout_device(&[StoreOutcome::Failed]),
            crate::revocation_driver::LockoutObservation::StorageFailed
        );
        assert_eq!(
            classify_lockout_ignored(&[StoreOutcome::Failed]),
            LockoutObservation::Applied
        );
    }

    #[test]
    fn login_plans_render_the_historical_statements() {
        let plan = plan_take_challenge(s("abc"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::Take,
                key: s("challenge:abc"),
                value: 0,
                ttl: 0,
                limit: 0,
                member: String::new()
            }
        );

        let (sql, params) = query(&plan_login_device(s("dev")));
        assert_eq!(
            sql,
            "SELECT id, user_id, device_name, device_type, last_active,\n                    hybrid_ek, hybrid_vk,\n                    enrolled_by, rms_capsule, revoked,\n                    revoked_at, revoked_by, created_at\n                 FROM devices\n                 WHERE id = ? AND revoked = 0"
        );
        assert_eq!(params, vec![s("dev")]);

        let plan = plan_backoff_record(s("1.2.3.4"), s("dev"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::BackoffFailure,
                key: s("rl:streak:verify:1.2.3.4:dev"),
                value: 0,
                ttl: 0,
                limit: 0,
                member: s("rl:backoff:verify:1.2.3.4:dev")
            }
        );

        let plan = plan_failure_counter(s("1.2.3.4"), s("dev"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::Incr,
                key: s("rl:verify:fail:dev:1.2.3.4:dev"),
                value: 1,
                ttl: 60,
                limit: 5,
                member: String::new()
            }
        );

        let plan = plan_reset_login_streak(s("1.2.3.4"), s("dev"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::ResetBackoff,
                key: s("rl:streak:verify:1.2.3.4:dev"),
                value: 0,
                ttl: 0,
                limit: 0,
                member: s("rl:backoff:verify:1.2.3.4:dev")
            }
        );

        let plan = plan_track_jti(s("dev"), s("jti"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::AddMember,
                key: s("device:jtis:dev"),
                value: 0,
                ttl: 28_800,
                limit: 0,
                member: s("jti")
            }
        );

        let (sql, params) = exec(&plan_login_last_active(s("dev"), s("now"), None, None));
        assert_eq!(sql, "UPDATE devices SET last_active = ? WHERE id = ?");
        assert_eq!(params, vec![s("now"), s("dev")]);

        let (sql, params) = exec(&plan_login_last_active(
            s("dev"),
            s("now"),
            Some(s("name")),
            Some(s("kind")),
        ));
        assert_eq!(
            sql,
            "UPDATE devices SET last_active = ?, device_name = ?, device_type = ? WHERE id = ?"
        );
        assert_eq!(params, vec![s("now"), s("name"), s("kind"), s("dev")]);

        // One of the two missing falls back to the plain stamp, as before.
        let (sql, params) =
            exec(&plan_login_last_active(s("dev"), s("now"), Some(s("name")), None));
        assert_eq!(sql, "UPDATE devices SET last_active = ? WHERE id = ?");
        assert_eq!(params, vec![s("now"), s("dev")]);
    }

    #[test]
    fn login_classifiers_keep_the_historical_observations() {
        let login = s("login");
        assert_eq!(
            classify_login_challenge(&TakeOutcome::Taken(Some(s("login"))), &login),
            ChallengeObservation::Observed(ChallengeConsumption::Accepted)
        );
        assert_eq!(
            classify_login_challenge(&TakeOutcome::Taken(Some(s("enroll"))), &login),
            ChallengeObservation::Observed(ChallengeConsumption::WrongPurpose)
        );
        assert_eq!(
            classify_login_challenge(&TakeOutcome::Taken(None), &login),
            ChallengeObservation::Observed(ChallengeConsumption::Missing)
        );
        assert_eq!(
            classify_login_challenge(&TakeOutcome::Failed, &login),
            ChallengeObservation::StorageFailed
        );

        assert_eq!(
            classify_login_device(&DeviceReadOutcome::Row),
            DeviceObservation::Present
        );
        assert_eq!(
            classify_login_device(&DeviceReadOutcome::Undecodable),
            DeviceObservation::ParseFailed
        );
        assert_eq!(
            classify_login_device(&DeviceReadOutcome::Missing),
            DeviceObservation::Absent
        );
        assert_eq!(
            classify_login_device(&DeviceReadOutcome::Failed),
            DeviceObservation::QueryFailed
        );

        assert_eq!(
            classify_failure_counter(&[StoreOutcome::Applied]),
            FailureRecordObservation {
                fallback_counter_ok: true
            }
        );
        assert_eq!(
            classify_failure_counter(&[StoreOutcome::Failed]),
            FailureRecordObservation {
                fallback_counter_ok: false
            }
        );
        assert_eq!(
            classify_failure_counter(&[]),
            FailureRecordObservation {
                fallback_counter_ok: false
            }
        );

        assert_eq!(
            classify_backoff_reset(&StoreOutcome::Applied),
            BackoffResetObservation::Reset
        );
        assert_eq!(
            classify_backoff_reset(&StoreOutcome::Failed),
            BackoffResetObservation::StorageFailed
        );
        assert_eq!(
            classify_track_jti(&StoreOutcome::Applied),
            TokenTrackObservation::Tracked
        );
        assert_eq!(
            classify_track_jti(&StoreOutcome::Failed),
            TokenTrackObservation::Failed
        );
    }

    #[test]
    fn challenge_tags_are_the_issuer_s_exact_bytes() {        for purpose in [
            crate::challenge::ChallengePurpose::Login,
            crate::challenge::ChallengePurpose::Enroll,
            crate::challenge::ChallengePurpose::WebToken,
        ] {
            assert_eq!(
                challenge_tag_text(purpose).as_bytes(),
                crate::challenge::purpose_tag_bytes(purpose)
            );
        }
        assert_eq!(challenge_tag_text(crate::challenge::ChallengePurpose::Login), "login");
    }

    #[test]
    fn target_classifier_matches_the_historical_cell_rules() {
        let me = s("me");
        let present = |owner: Option<&str>, revoked: Option<i64>| {
            ReadOutcome::Row(Some(TargetRowView {
                user_id: owner.map(s),
                revoked,
            }))
        };
        assert_eq!(
            classify_target(&me, &present(Some("me"), Some(0))),
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: false
            })
        );
        assert_eq!(
            classify_target(&me, &present(Some("you"), Some(1))),
            DeviceLookupObservation::Present(TargetObservation {
                same_account: false,
                already_revoked: true
            })
        );
        // A cell the handler cannot read as a number never counts as revoked.
        assert_eq!(
            classify_target(&me, &present(Some("me"), None)),
            DeviceLookupObservation::Present(TargetObservation {
                same_account: true,
                already_revoked: false
            })
        );
        assert_eq!(
            classify_target(&me, &ReadOutcome::Row(None)),
            DeviceLookupObservation::Absent
        );
        assert_eq!(
            classify_target(&me, &ReadOutcome::Failed),
            DeviceLookupObservation::QueryFailed
        );
    }

    // ── Registration and challenge ─────────────────────────────────────────

    #[test]
    fn challenge_plans_render_the_historical_statements() {
        let plan = plan_challenge_rate_limit(s("1.2.3.4"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::Incr,
                key: s("rl:challenge:ip:1.2.3.4"),
                value: 1,
                ttl: 60,
                limit: 20,
                member: String::new()
            }
        );

        let tag = challenge_tag_text(crate::challenge::ChallengePurpose::Login);
        let plan = plan_store_nonce(s("abc"), tag.clone());
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::SetExNx,
                key: s("challenge:abc"),
                value: 0,
                ttl: 60,
                limit: 0,
                // The exact bytes the issuer wrote: the purpose tag.
                member: tag
            }
        );
    }

    #[test]
    fn registration_plans_render_the_historical_statements() {
        let plan = plan_registration_rate_limit(s("1.2.3.4"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::Incr,
                key: s("rl:register:ip:1.2.3.4"),
                value: 1,
                ttl: 3600,
                limit: 5,
                member: String::new()
            }
        );

        let (sql, params) = query(&plan_account_count());
        assert_eq!(sql, "SELECT COUNT(*) FROM users");
        assert!(params.is_empty());

        let (sql, params) =
            exec(&plan_insert_account(s("u"), s("now"), s("ek"), s("since")));
        assert_eq!(
            sql,
            "INSERT INTO users (id, created_at, share_ek, share_ek_since)\n             VALUES (?, ?, ?, ?)"
        );
        assert_eq!(params, vec![s("u"), s("now"), s("ek"), s("since")]);

        let (sql, params) = exec(&plan_insert_device(
            s("d"),
            s("u"),
            s("name"),
            s("desktop"),
            s("now"),
            s("ekb64"),
            s("vkb64"),
        ));
        assert_eq!(
            sql,
            "INSERT INTO devices\n         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)\n         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)"
        );
        assert_eq!(
            params,
            vec![s("d"), s("u"), s("name"), s("desktop"), s("now"), s("ekb64"), s("vkb64"), s("now")]
        );

        // The registration's tracked-JTI plan is the login one, byte for byte.
        assert_eq!(
            render_store(&plan_track_jti(s("d"), s("j"))[0]),
            RenderedStore {
                op: StoreOp::AddMember,
                key: s("device:jtis:d"),
                value: 0,
                ttl: 28_800,
                limit: 0,
                member: s("j")
            }
        );
    }

    #[test]
    fn registration_classifiers_keep_the_historical_observations() {
        let allowed = vec![StoreOutcome::Applied];
        let denied = vec![StoreOutcome::Failed];
        assert_eq!(
            classify_challenge_rate_limit(&allowed[0]),
            crate::challenge_issue_driver::RateLimitObservation::Allowed
        );
        assert_eq!(
            classify_challenge_rate_limit(&denied[0]),
            crate::challenge_issue_driver::RateLimitObservation::Denied
        );
        assert_eq!(
            classify_registration_rate_limit(&allowed[0]),
            crate::registration_driver::RateLimitObservation::Allowed
        );
        assert_eq!(
            classify_registration_rate_limit(&denied[0]),
            crate::registration_driver::RateLimitObservation::Denied
        );
        assert_eq!(
            classify_store_nonce(&NxOutcome::Inserted),
            crate::challenge_issue_driver::StoreObservation::Inserted
        );
        assert_eq!(
            classify_store_nonce(&NxOutcome::KeyExists),
            crate::challenge_issue_driver::StoreObservation::KeyExists
        );
        assert_eq!(
            classify_store_nonce(&NxOutcome::Failed),
            crate::challenge_issue_driver::StoreObservation::Failed
        );
        assert_eq!(
            classify_account_count(&CountOutcome::Count(7)),
            crate::registration_driver::BudgetObservation::Counted { count: 7 }
        );
        assert_eq!(
            classify_account_count(&CountOutcome::Failed),
            crate::registration_driver::BudgetObservation::QueryFailed
        );
        assert_eq!(
            classify_insert(&WriteOutcome::Applied(1)),
            crate::registration_driver::InsertObservation::Inserted
        );
        assert_eq!(
            classify_insert(&WriteOutcome::Failed),
            crate::registration_driver::InsertObservation::Failed
        );
        assert_eq!(
            classify_registration_track(&StoreOutcome::Applied),
            crate::registration_driver::TrackObservation::Tracked
        );
        assert_eq!(
            classify_registration_track(&StoreOutcome::Failed),
            crate::registration_driver::TrackObservation::Failed
        );
    }

    // ── Web sessions ───────────────────────────────────────────────────────

    #[test]
    fn web_session_plans_render_the_historical_statements() {
        let (sql, params) = exec(&plan_insert_pending(
            s("sess"),
            s("acct"),
            s("hash"),
            s("epk"),
            s("vk"),
            s("nonce"),
            s("now"),
        ));
        assert_eq!(
            sql,
            "INSERT INTO web_sessions
                    (id, user_id, approver_user_id, poll_secret_hash, ephemeral_pk, web_vk, link_nonce, mode, status, capsule, approved_by, created_at, expires_at)
                 VALUES (?, NULL, ?, ?, ?, ?, ?, NULL, 'pending', NULL, NULL, ?, NULL)"
        );
        assert_eq!(
            params,
            vec![s("sess"), s("acct"), s("hash"), s("epk"), s("vk"), s("nonce"), s("now")]
        );

        let (sql, params) = mixed(&plan_grant_update(
            s("sess"),
            s("acct"),
            s("dev"),
            s("rw"),
            s("cap"),
            s("exp"),
            7,
        ));
        assert_eq!(
            sql,
            "UPDATE web_sessions
                 SET user_id = ?, mode = ?, status = 'granted', capsule = ?,
                     approved_by = ?, expires_at = ?,
                     key_epoch = ?
                 WHERE id = ? AND status = 'pending' AND approver_user_id = ?
                   AND EXISTS (
                       SELECT 1 FROM users
                       WHERE id = ? AND rekey_state IS NULL AND key_epoch = ?
                   )
                   -- A device being revoked cannot slip a grant past the
                   -- revocation cascade (see device::revoke).
                   AND EXISTS (
                       SELECT 1 FROM devices
                       WHERE id = ? AND user_id = ? AND revoked = 0
                   )"
        );
        assert_eq!(
            params,
            vec![
                Param::Text(s("acct")),
                Param::Text(s("rw")),
                Param::Text(s("cap")),
                Param::Text(s("dev")),
                Param::Text(s("exp")),
                Param::Int(7),
                Param::Text(s("sess")),
                Param::Text(s("acct")),
                Param::Text(s("acct")),
                Param::Int(7),
                Param::Text(s("dev")),
                Param::Text(s("acct")),
            ]
        );

        let (sql, params) = exec(&plan_revoke_session(s("sess")));
        assert_eq!(
            sql,
            "UPDATE web_sessions SET status = 'revoked', capsule = NULL WHERE id = ?"
        );
        assert_eq!(params, vec![s("sess")]);

        let plan = plan_token_claim(s("sess"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::SetExNxByte,
                key: s("web_session:token_issued:sess"),
                value: 1,
                ttl: 86_400,
                limit: 0,
                member: String::new()
            }
        );

        let plan = plan_token_sentinel(s("sess"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            render_store(&plan[0]),
            RenderedStore {
                op: StoreOp::Exists,
                key: s("device:revoked:sess"),
                value: 0,
                ttl: 0,
                limit: 0,
                member: String::new()
            }
        );

        // The delete handler's sentinel is the shared plan, with the web
        // session ceiling.
        assert_eq!(
            render_store(&plan_sentinel(s("sess"), WEB_SESSION_MAX_TTL_SECS)[0]),
            RenderedStore {
                op: StoreOp::SetEx,
                key: s("device:revoked:sess"),
                value: 1,
                ttl: 86_400,
                limit: 0,
                member: String::new()
            }
        );
    }

    #[test]
    fn web_session_classifiers_keep_the_historical_observations() {
        assert_eq!(
            classify_start_insert(&WriteOutcome::Applied(1)),
            StartInsertObservation::Inserted
        );
        assert_eq!(
            classify_start_insert(&WriteOutcome::Failed),
            StartInsertObservation::Failed
        );
        assert_eq!(
            classify_grant_update(&WriteOutcome::Applied(1)),
            GrantUpdateObservation::Updated
        );
        assert_eq!(
            classify_grant_update(&WriteOutcome::Applied(0)),
            GrantUpdateObservation::Conflict
        );
        assert_eq!(
            classify_grant_update(&WriteOutcome::Failed),
            GrantUpdateObservation::Failed
        );
        assert_eq!(
            classify_token_claim(&NxOutcome::Inserted),
            TokenClaimObservation::Claimed
        );
        assert_eq!(
            classify_token_claim(&NxOutcome::KeyExists),
            TokenClaimObservation::AlreadyClaimed
        );
        assert_eq!(
            classify_token_claim(&NxOutcome::Failed),
            TokenClaimObservation::StorageFailed
        );
        assert_eq!(
            classify_token_issue(true, &ExistsOutcome::Absent, &StoreOutcome::Applied),
            TokenIssueObservation::Issued
        );
        for (issued, sentinel, tracked) in [
            (false, ExistsOutcome::Absent, StoreOutcome::Applied),
            (true, ExistsOutcome::Present, StoreOutcome::Applied),
            (true, ExistsOutcome::Failed, StoreOutcome::Applied),
            (true, ExistsOutcome::Absent, StoreOutcome::Failed),
        ] {
            assert_eq!(
                classify_token_issue(issued, &sentinel, &tracked),
                TokenIssueObservation::Failed,
                "issued {issued}, sentinel {sentinel:?}, tracked {tracked:?}"
            );
        }
        assert_eq!(
            classify_lockout_session(&StoreOutcome::Applied),
            DeleteSentinelObservation::Applied
        );
        assert_eq!(
            classify_lockout_session(&StoreOutcome::Failed),
            DeleteSentinelObservation::StorageFailed
        );
        assert_eq!(
            classify_revoke_session(&WriteOutcome::Applied(0)),
            DeleteRecordObservation::Updated
        );
        assert_eq!(
            classify_revoke_session(&WriteOutcome::Applied(1)),
            DeleteRecordObservation::Updated
        );
        assert_eq!(
            classify_revoke_session(&WriteOutcome::Failed),
            DeleteRecordObservation::Failed
        );
    }
}
