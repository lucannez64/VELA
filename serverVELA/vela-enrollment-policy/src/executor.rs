//! The store and SQL behind the device-enrollment executors, split so the
//! observation each executor returns can be proved against a store model (F-1).
//!
//! Every executor method in `vela-server/src/device/{enroll,invitation,rendezvous}.rs`
//! is
//!
//! 1. a pure `plan_*` function from the method's inputs to typed statements
//!    ([`PairingStmt`]);
//! 2. [`render`], from each statement to the exact SQL text, store key, value
//!    and TTL the handler has always used (pinned by the unit tests below);
//! 3. a pure `classify_*` function from the per-statement outcomes to the
//!    observation the driver receives.
//!
//! The server runs a thin loop: plan, render and run each statement in order,
//! stop at the first failure, classify. hax extracts the plans and classifiers;
//! `proofs/fstar/executor-lemmas` proves them against a model of the tables and
//! store keys these statements touch, for every starting state and every
//! failing statement. [`crate::executor_model`] is the Rust mirror of that
//! model, used by the server's conformance test against a real database and a
//! real sled store.
//!
//! Every value is text (`String`): ids, keys, keys and serialized records are
//! all bound as text parameters or stored as bytes. TTLs are part of the
//! rendering, not of the model: the model treats a live key as live for the
//! length of one request (stated as an assumption).

use crate::pairing_driver::{
    ClaimReadObservation, ClaimWriteObservation, CompletionAccountObservation,
    CompletionPreflightObservation, DeviceGrantObservation, DeviceInsertObservation,
    OpenerObservation, RedeemObservation, ResultReadObservation, SignatureObservation,
    StoreObservation, TakeObservation,
};

/// TTL of an invitation package (`ENROLLMENT_PACKAGE_TTL_SECS`).
pub const PACKAGE_TTL_SECS: u64 = 15 * 60;
/// TTL of an enrollment grant, its claim and its result (`GRANT_TTL_SECS`).
pub const GRANT_TTL_SECS: u64 = 5 * 60;

// ── Keys ───────────────────────────────────────────────────────────────────

pub fn package_key(token: &str) -> String {
    format!("enrollment_package:{token}")
}

pub fn grant_key(id: &str) -> String {
    format!("enroll_grant:{id}")
}

pub fn claim_key(id: &str) -> String {
    format!("enroll_claim:{id}")
}

pub fn result_key(id: &str) -> String {
    format!("enroll_result:{id}")
}

pub fn challenge_key(challenge: &str) -> String {
    format!("challenge:{challenge}")
}

// ── Statements ─────────────────────────────────────────────────────────────

/// One statement an executor may run. Field names follow the bound parameters
/// (SQL) or the stored record (store); [`render`] fixes their order and text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingStmt {
    /// `set_ex(enrollment_package:<token>, ciphertext, 900)`
    StorePackage { token: String, ciphertext: String },
    /// `get_del(enrollment_package:<token>)`
    TakePackage { token: String },
    /// `set_ex(enroll_grant:<id>, <grant json>, 300)`
    StoreGrant {
        grant_id: String,
        user_id: String,
        device_id: String,
    },
    /// `exists(enroll_claim:<id>)`
    ClaimExists { grant_id: String },
    /// `set_ex_nx_if_live(enroll_grant:<id>, enroll_claim:<id>, <claim json>, 300)`
    WriteClaim {
        grant_id: String,
        hybrid_ek: String,
        hybrid_vk: String,
        device_name: Option<String>,
        device_type: Option<String>,
    },
    /// `get(enroll_claim:<id>)`
    ReadClaim { grant_id: String },
    /// `SELECT key_epoch, rekey_state FROM users WHERE id = ?`
    SelectAccount { user_id: String },
    /// `SELECT hybrid_vk, revoked FROM devices WHERE id = ? AND user_id = ?`
    SelectOpener { device_id: String, user_id: String },
    /// `take_live_pair(enroll_grant:<id>, enroll_claim:<id>)`
    TakeCeremony { grant_id: String },
    /// The completion path's guarded device insert.
    InsertCompletionDevice {
        new_device_id: String,
        user_id: String,
        device_name: String,
        device_type: String,
        hybrid_ek: String,
        hybrid_vk: String,
        enrolled_by: String,
        grant_id: String,
        rms_capsule: String,
        now: String,
        guard_user: String,
        guard_epoch: i64,
    },
    /// `set_ex(enroll_result:<id>, <result json>, 300)`
    StoreResult {
        grant_id: String,
        device_id: String,
        hybrid_vk: String,
    },
    /// `get(enroll_result:<id>)`
    ReadResult { grant_id: String },
    /// `SELECT id, hybrid_vk FROM devices WHERE enrollment_grant_id = ?`
    SelectDeviceByGrant { grant_id: String },
    /// `SELECT ... FROM devices WHERE id = ? AND revoked = 0`
    SelectActiveDevice { device_id: String },
    /// The enrollment path's guarded device insert.
    InsertEnrollDevice {
        new_device_id: String,
        user_id: String,
        device_name: String,
        device_type: String,
        hybrid_ek: String,
        hybrid_vk: String,
        enrolled_by: String,
        rms_capsule: String,
        now: String,
        guard_user: String,
        guard_epoch: i64,
    },
    /// `get_del(challenge:<challenge>)`
    TakeChallenge { challenge: String },
}

/// What one write statement returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// It ran; the number of rows it changed.
    Applied(u64),
    /// A guarded `set_ex_nx_if_live` inserted the key.
    Inserted,
    /// A guarded `set_ex_nx_if_live` found its guard key gone.
    GuardMissing,
    /// A guarded `set_ex_nx_if_live` found the key already present.
    KeyExists,
    /// It returned an error.
    Failed,
}

/// What one destructive read (`get_del`, `take_live_pair`) returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TakeOutcome {
    /// It returned an error.
    Failed,
    /// Nothing was stored under the key (or one pair member was missing).
    Missing,
    /// The value (or the pair) was removed.
    Present,
}

/// The cells of a `claim` record after JSON decoding. Decoding itself is
/// trusted (serde, checked by the unit tests and the conformance test).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimRowView {
    pub hybrid_ek: Option<String>,
    pub hybrid_vk: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

/// The cells of an `EnrollmentResult` record after JSON decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultRowView {
    pub device_id: Option<String>,
    pub hybrid_vk: Option<String>,
}

/// The cells of a `users` row the completion preflight reads:
/// `key_epoch` and `rekey_state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRowView {
    pub key_epoch: Option<i64>,
    pub rekey_state: Option<String>,
}

/// The cells of a `devices` row the reads and the hinge use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRowView {
    pub device_id: Option<String>,
    pub hybrid_vk: Option<String>,
    pub revoked: Option<i64>,
    pub user_id: Option<String>,
    pub enrollment_grant_id: Option<String>,
}

/// What one read statement returned: its first row (decoded), no row, a row
/// the handler could not decode, or an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    /// The statement returned an error.
    Failed,
    /// The row was returned but a cell the handler needs did not decode.
    Undecodable,
    /// `SELECT key_epoch, rekey_state FROM users`.
    Account(Option<AccountRowView>),
    /// `SELECT ... FROM devices`.
    Device(Option<DeviceRowView>),
    /// `SELECT hybrid_vk, revoked FROM devices WHERE id = ? AND user_id = ?`.
    Opener(Option<DeviceRowView>),
    /// `SELECT id, hybrid_vk FROM devices WHERE enrollment_grant_id = ?`.
    DeviceByGrant(Option<DeviceRowView>),
    /// `SELECT ... FROM devices WHERE id = ? AND revoked = 0`.
    ActiveDevice(Option<DeviceRowView>),
    /// `exists(enroll_claim:<id>)`.
    ClaimExists(bool),
    /// `get(enroll_claim:<id>)`; `None` means the key was absent.
    Claim(Option<ClaimRowView>),
    /// `get(enroll_result:<id>)`; `None` means the key was absent.
    Result(Option<ResultRowView>),
}

/// Verdicts the handler computes from a request and a stored row (base64 and
/// JSON decoding, the hybrid signature checks, the rekey policy). They are
/// inputs here: crypto and request decoding stay outside the store model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionVerdicts {
    /// Both public keys in the stored claim decoded.
    pub claim_keys_usable: bool,
    /// `rms_capsule` decoded and had an accepted length.
    pub capsule_valid: bool,
    /// `signature` decoded and had the exact signature length.
    pub signature_field_valid: bool,
    /// The opener's stored `hybrid_vk` decoded.
    pub opener_key_decodes: bool,
    /// The opener's signature over the stored claim verified.
    pub signature_verified: bool,
    /// `users.key_epoch` as read by the account preflight.
    pub account_epoch: i64,
    /// The request's `key_epoch`.
    pub declared_epoch: i64,
    /// `users.rekey_state` was not null.
    pub rotation_in_progress: bool,
    /// The rekey policy accepted the account epoch.
    pub account_epoch_active: bool,
}

/// The enrollment device read's request verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollAuthVerdict {
    /// The challenge and the authentication signature verified.
    Verified,
    /// The challenge field did not decode or had the wrong length.
    MalformedChallenge,
    /// The authentication signature was rejected.
    Rejected,
}

/// The result collector's key and signature verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorVerdicts {
    /// The stored record's `hybrid_vk` decoded.
    pub key_decodes: bool,
    /// The stored claimed key's decoded length.
    pub key_len: usize,
    /// The collector's signature verified under the stored key.
    pub signature_verified: bool,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// `StorePackageIo::store_package`.
pub fn plan_store_package(token: String, ciphertext: String) -> Vec<PairingStmt> {
    vec![PairingStmt::StorePackage { token, ciphertext }]
}

/// `RedeemPackageIo::redeem_package`.
pub fn plan_redeem_package(token: String) -> Vec<PairingStmt> {
    vec![PairingStmt::TakePackage { token }]
}

/// `OpenGrantIo::store_grant`.
pub fn plan_store_grant(grant_id: String, user_id: String, device_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::StoreGrant {
        grant_id,
        user_id,
        device_id,
    }]
}

/// `ClaimIo::check_claim`: read whether a claim already exists.
pub fn plan_claim_check(grant_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::ClaimExists { grant_id }]
}

/// `ClaimIo::write_claim`: the guarded first-writer-wins write.
pub fn plan_claim_write(
    grant_id: String,
    hybrid_ek: String,
    hybrid_vk: String,
    device_name: Option<String>,
    device_type: Option<String>,
) -> Vec<PairingStmt> {
    vec![PairingStmt::WriteClaim {
        grant_id,
        hybrid_ek,
        hybrid_vk,
        device_name,
        device_type,
    }]
}

/// `CompleteIo::check_account`: the account epoch and rekey state.
pub fn plan_account_read(user_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::SelectAccount { user_id }]
}

/// `CompleteIo::prepare_completion`: the stored claim, then the opener row.
pub fn plan_completion_preflight(
    grant_id: String,
    device_id: String,
    user_id: String,
) -> Vec<PairingStmt> {
    vec![
        PairingStmt::ReadClaim { grant_id },
        PairingStmt::SelectOpener { device_id, user_id },
    ]
}

/// `CompleteIo::take_ceremony`: consume the grant and claim together.
pub fn plan_take_ceremony(grant_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::TakeCeremony { grant_id }]
}

/// `CompleteIo::insert_device`: the guarded insert from the stored claim.
#[allow(clippy::too_many_arguments)]
pub fn plan_completion_insert(
    new_device_id: String,
    user_id: String,
    device_name: String,
    device_type: String,
    hybrid_ek: String,
    hybrid_vk: String,
    enrolled_by: String,
    grant_id: String,
    rms_capsule: String,
    now: String,
    guard_user: String,
    guard_epoch: i64,
) -> Vec<PairingStmt> {
    vec![PairingStmt::InsertCompletionDevice {
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
    }]
}

/// `CompleteIo::write_result`: the result record, after the row exists.
pub fn plan_result_write(
    grant_id: String,
    device_id: String,
    hybrid_vk: String,
) -> Vec<PairingStmt> {
    vec![PairingStmt::StoreResult {
        grant_id,
        device_id,
        hybrid_vk,
    }]
}

/// `ResultIo::read_result`.
pub fn plan_result_read(grant_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::ReadResult { grant_id }]
}

/// `ResultIo::read_claim`.
pub fn plan_claim_read(grant_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::ReadClaim { grant_id }]
}

/// `ResultIo::read_enrolled_device` (U-20 fallback).
pub fn plan_device_by_grant(grant_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::SelectDeviceByGrant { grant_id }]
}

/// `EnrollIo::check_device`.
pub fn plan_active_device_read(device_id: String) -> Vec<PairingStmt> {
    vec![PairingStmt::SelectActiveDevice { device_id }]
}

/// `EnrollIo::insert_device`.
#[allow(clippy::too_many_arguments)]
pub fn plan_enroll_insert(
    new_device_id: String,
    user_id: String,
    device_name: String,
    device_type: String,
    hybrid_ek: String,
    hybrid_vk: String,
    enrolled_by: String,
    rms_capsule: String,
    now: String,
    guard_user: String,
    guard_epoch: i64,
) -> Vec<PairingStmt> {
    vec![PairingStmt::InsertEnrollDevice {
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
    }]
}

/// `EnrollIo::consume_challenge`.
pub fn plan_challenge_take(challenge: String) -> Vec<PairingStmt> {
    vec![PairingStmt::TakeChallenge { challenge }]
}

// ── Classification ─────────────────────────────────────────────────────────

/// A single unconditional store write: stored exactly when it ran.
pub fn classify_store(outcomes: &[WriteOutcome]) -> StoreObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            WriteOutcome::Applied(_) => StoreObservation::Stored,
            _ => StoreObservation::Failed,
        }
    } else {
        StoreObservation::Failed
    }
}

/// The destructive package read. A present value is handed out; a failure and
/// a miss are both the historical "not found" observation.
pub fn classify_redeem(outcome: &TakeOutcome, utf8_valid: bool) -> RedeemObservation {
    match outcome {
        TakeOutcome::Present => RedeemObservation::Present { utf8_valid },
        _ => RedeemObservation::Missing,
    }
}

/// The challenge take: accepted exactly when the key was present, removed,
/// and its stored purpose tag matched the endpoint's purpose.
pub fn classify_challenge_take(outcome: &TakeOutcome, purpose_matches: bool) -> bool {
    match outcome {
        TakeOutcome::Present => purpose_matches,
        _ => false,
    }
}

/// The claim existence read. A failed read (or a plan that ran no read) gives
/// the historical rejecting observation with zero lengths.
pub fn classify_claim_check(
    grant_live: bool,
    ek_len: usize,
    vk_len: usize,
    outcomes: &[ReadOutcome],
) -> crate::ClaimObservation {
    let (claim_exists, ek_len, vk_len) = if outcomes.len() == 1 {
        match &outcomes[0] {
            ReadOutcome::ClaimExists(exists) => (*exists, ek_len, vk_len),
            _ => (false, 0, 0),
        }
    } else {
        (false, 0, 0)
    };
    crate::ClaimObservation {
        grant_live,
        claim_exists,
        hybrid_ek_len: ek_len,
        hybrid_vk_len: vk_len,
    }
}

/// The guarded claim write.
pub fn classify_claim_write(outcomes: &[WriteOutcome]) -> ClaimWriteObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            WriteOutcome::Inserted => ClaimWriteObservation::Inserted,
            WriteOutcome::KeyExists => ClaimWriteObservation::KeyExists,
            _ => ClaimWriteObservation::GuardMissing,
        }
    } else {
        ClaimWriteObservation::GuardMissing
    }
}

/// The account preflight's observation`; its row-derived fields (epoch and
/// rotation) are read separately by [`account_fields`].
pub fn classify_account(
    outcomes: &[ReadOutcome],
    declared_epoch_positive: bool,
    rekey_permitted: bool,
) -> CompletionAccountObservation {
    let ok = outcomes.len() == 1 && matches!(&outcomes[0], ReadOutcome::Account(_));
    CompletionAccountObservation {
        account_query_ok: ok,
        declared_epoch_positive,
        rekey_permitted,
    }
}

/// The account row's truth as the completion driver consumes it: the stored
/// `key_epoch` (0 when absent or unread) and whether a rotation is recorded.
pub fn account_fields(outcomes: &[ReadOutcome]) -> (i64, bool) {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            ReadOutcome::Account(Some(row)) => {
                (row.key_epoch.unwrap_or(0), row.rekey_state.is_some())
            }
            _ => (0, false),
        }
    } else {
        (0, false)
    }
}

/// The completion preflight. The stored claim decides `Usable`/`Missing`/
/// `Error`; the opener row decides `Active`/`Inactive`/`Error`; a failed claim
/// read short-circuits the historical observation (the opener read never ran).
pub fn classify_completion_preflight(
    outcomes: &[ReadOutcome],
    verdicts: CompletionVerdicts,
) -> CompletionPreflightObservation {
    if outcomes.len() > 0 && matches!(&outcomes[0], ReadOutcome::Failed) {
        return CompletionPreflightObservation {
            claim: crate::pairing_driver::ClaimMaterialObservation::Error,
            capsule_valid: false,
            signature_field_valid: false,
            opener: OpenerObservation::Inactive,
            signature: SignatureObservation::Failed,
            account_epoch: verdicts.account_epoch,
            declared_epoch: verdicts.declared_epoch,
            rotation_in_progress: verdicts.rotation_in_progress,
            account_epoch_active: verdicts.account_epoch_active,
        };
    }
    let claim = if outcomes.len() > 0 {
        match &outcomes[0] {
            ReadOutcome::Claim(Some(_)) => {
                if verdicts.claim_keys_usable {
                    crate::pairing_driver::ClaimMaterialObservation::Usable
                } else {
                    crate::pairing_driver::ClaimMaterialObservation::Error
                }
            }
            ReadOutcome::Claim(None) => crate::pairing_driver::ClaimMaterialObservation::Missing,
            _ => crate::pairing_driver::ClaimMaterialObservation::Error,
        }
    } else {
        crate::pairing_driver::ClaimMaterialObservation::Error
    };
    let opener = if outcomes.len() > 1 {
        match &outcomes[1] {
            ReadOutcome::Opener(None) => OpenerObservation::Inactive,
            ReadOutcome::Opener(Some(row)) => match row.revoked {
                Some(0) => {
                    if row.hybrid_vk.is_some() && verdicts.opener_key_decodes {
                        OpenerObservation::Active
                    } else {
                        OpenerObservation::Error
                    }
                }
                _ => OpenerObservation::Inactive,
            },
            _ => OpenerObservation::Error,
        }
    } else {
        OpenerObservation::Error
    };
    let signature = if verdicts.signature_verified {
        SignatureObservation::Verified
    } else {
        SignatureObservation::Failed
    };
    CompletionPreflightObservation {
        claim,
        capsule_valid: verdicts.capsule_valid,
        signature_field_valid: verdicts.signature_field_valid,
        opener,
        signature,
        account_epoch: verdicts.account_epoch,
        declared_epoch: verdicts.declared_epoch,
        rotation_in_progress: verdicts.rotation_in_progress,
        account_epoch_active: verdicts.account_epoch_active,
    }
}

/// The ceremony take. The two match verdicts are the executor's byte
/// comparisons of the taken records with the snapshot it validated.
pub fn classify_take_ceremony(
    outcomes: &[TakeOutcome],
    grant_matches: bool,
    claim_matches: bool,
) -> TakeObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            TakeOutcome::Present => TakeObservation::Taken {
                grant_matches,
                claim_matches,
            },
            _ => TakeObservation::Missing,
        }
    } else {
        TakeObservation::Missing
    }
}

/// The completion insert.
pub fn classify_insert_completion(outcomes: &[WriteOutcome]) -> DeviceInsertObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            WriteOutcome::Applied(rows) if *rows > 0 => DeviceInsertObservation::Inserted,
            WriteOutcome::Applied(_) => DeviceInsertObservation::Skipped,
            _ => DeviceInsertObservation::Failed,
        }
    } else {
        DeviceInsertObservation::Failed
    }
}

/// The enrollment insert. Zero rows is the epoch guard's refusal; an error is
/// a storage failure.
pub fn classify_insert_enroll(
    outcomes: &[WriteOutcome],
) -> crate::enroll_driver::InsertObservation {
    use crate::enroll_driver::InsertObservation;
    if outcomes.len() == 1 {
        match &outcomes[0] {
            WriteOutcome::Applied(rows) if *rows > 0 => InsertObservation::Inserted,
            WriteOutcome::Applied(_) => InsertObservation::EpochMismatch,
            _ => InsertObservation::Failed,
        }
    } else {
        InsertObservation::Failed
    }
}

/// The result record's read.
pub fn classify_result_read(
    outcomes: &[ReadOutcome],
    verdicts: CollectorVerdicts,
) -> ResultReadObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            ReadOutcome::Result(Some(_)) => {
                if verdicts.key_decodes {
                    ResultReadObservation::Completed {
                        claimed_key_len: verdicts.key_len,
                        signature_verified: verdicts.signature_verified,
                    }
                } else {
                    ResultReadObservation::Unreadable
                }
            }
            ReadOutcome::Result(None) => ResultReadObservation::Absent,
            _ => ResultReadObservation::Unreadable,
        }
    } else {
        ResultReadObservation::Unreadable
    }
}

/// The claim record's read by the result collector.
pub fn classify_claim_read(
    outcomes: &[ReadOutcome],
    verdicts: CollectorVerdicts,
) -> ClaimReadObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            ReadOutcome::Claim(Some(_)) => {
                if verdicts.key_decodes {
                    ClaimReadObservation::Claimed {
                        claimed_key_len: verdicts.key_len,
                        signature_verified: verdicts.signature_verified,
                    }
                } else {
                    ClaimReadObservation::Unreadable
                }
            }
            ReadOutcome::Claim(None) => ClaimReadObservation::Absent,
            _ => ClaimReadObservation::Unreadable,
        }
    } else {
        ClaimReadObservation::Unreadable
    }
}

/// The U-20 device-row fallback.
pub fn classify_enrolled_device(
    outcomes: &[ReadOutcome],
    verdicts: CollectorVerdicts,
) -> DeviceGrantObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            ReadOutcome::DeviceByGrant(Some(row)) => {
                if row.device_id.is_some() && row.hybrid_vk.is_some() && verdicts.key_decodes {
                    DeviceGrantObservation::Enrolled {
                        claimed_key_len: verdicts.key_len,
                        signature_verified: verdicts.signature_verified,
                    }
                } else {
                    DeviceGrantObservation::Unreadable
                }
            }
            ReadOutcome::DeviceByGrant(None) => DeviceGrantObservation::Absent,
            _ => DeviceGrantObservation::Unreadable,
        }
    } else {
        DeviceGrantObservation::Unreadable
    }
}

/// The enrollment device read.
pub fn classify_device_check(
    outcomes: &[ReadOutcome],
    verdict: EnrollAuthVerdict,
) -> crate::enroll_driver::DeviceObservation {
    use crate::enroll_driver::DeviceObservation;
    if outcomes.len() == 1 {
        match &outcomes[0] {
            ReadOutcome::ActiveDevice(None) => DeviceObservation::Unavailable,
            ReadOutcome::ActiveDevice(Some(_)) => match verdict {
                EnrollAuthVerdict::Verified => DeviceObservation::Verified,
                EnrollAuthVerdict::MalformedChallenge => DeviceObservation::MalformedChallenge,
                EnrollAuthVerdict::Rejected => DeviceObservation::AuthSignatureRejected,
            },
            _ => DeviceObservation::Error,
        }
    } else {
        DeviceObservation::Error
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

/// One statement as the database or the store receives it.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rendered {
    /// A SQL read (`query`).
    Query { sql: &'static str, params: Vec<String> },
    /// A SQL write (`execute`).
    Execute { sql: &'static str, params: Vec<String> },
    /// A SQL write whose last bound parameter is the integer account epoch
    /// (the guarded device inserts). The epoch is never bound as text.
    ExecuteEpoch {
        sql: &'static str,
        params: Vec<String>,
        epoch: i64,
    },
    /// `set_ex`: an expiring store write.
    StoreSet {
        key: String,
        value: Vec<u8>,
        ttl: u64,
    },
    /// `get`: a store read.
    StoreGet { key: String },
    /// `get_del`: a destructive store read.
    StoreTake { key: String },
    /// `exists`: a store presence read.
    StoreExists { key: String },
    /// `set_ex_nx_if_live`: first-writer-wins while the guard key is live.
    StoreSetIfLive {
        guard: String,
        key: String,
        value: Vec<u8>,
        ttl: u64,
    },
    /// `take_live_pair`: consume two records together.
    StoreTakePair { first: String, second: String },
}

#[cfg(not(hax))]
mod records {
    use serde::{Deserialize, Serialize};

    /// The grant record as `OpenGrantIo` has always serialized it.
    #[derive(Serialize, Deserialize)]
    pub struct Grant {
        pub user_id: String,
        pub device_id: String,
    }

    /// The claim record as `ClaimIo` has always serialized it.
    #[derive(Serialize, Deserialize)]
    pub struct Claim {
        pub hybrid_ek: String,
        pub hybrid_vk: String,
        pub device_name: Option<String>,
        pub device_type: Option<String>,
    }

    /// The result record as `CompleteIo` has always serialized it.
    #[derive(Serialize, Deserialize)]
    pub struct EnrollmentResult {
        pub device_id: String,
        pub hybrid_vk: String,
    }
}

/// The exact SQL text, store key, value, TTL and parameters each statement has
/// always used.
#[cfg(not(hax))]
pub fn render(stmt: &PairingStmt) -> Rendered {
    match stmt {
        PairingStmt::StorePackage { token, ciphertext } => Rendered::StoreSet {
            key: package_key(token),
            value: ciphertext.as_bytes().to_vec(),
            ttl: PACKAGE_TTL_SECS,
        },
        PairingStmt::TakePackage { token } => Rendered::StoreTake {
            key: package_key(token),
        },
        PairingStmt::StoreGrant {
            grant_id,
            user_id,
            device_id,
        } => Rendered::StoreSet {
            key: grant_key(grant_id),
            value: serde_json::to_vec(&records::Grant {
                user_id: user_id.clone(),
                device_id: device_id.clone(),
            })
            .expect("a grant serializes"),
            ttl: GRANT_TTL_SECS,
        },
        PairingStmt::ClaimExists { grant_id } => Rendered::StoreExists {
            key: claim_key(grant_id),
        },
        PairingStmt::WriteClaim {
            grant_id,
            hybrid_ek,
            hybrid_vk,
            device_name,
            device_type,
        } => Rendered::StoreSetIfLive {
            guard: grant_key(grant_id),
            key: claim_key(grant_id),
            value: serde_json::to_vec(&records::Claim {
                hybrid_ek: hybrid_ek.clone(),
                hybrid_vk: hybrid_vk.clone(),
                device_name: device_name.clone(),
                device_type: device_type.clone(),
            })
            .expect("a claim serializes"),
            ttl: GRANT_TTL_SECS,
        },
        PairingStmt::ReadClaim { grant_id } => Rendered::StoreGet {
            key: claim_key(grant_id),
        },
        PairingStmt::SelectAccount { user_id } => Rendered::Query {
            sql: "SELECT key_epoch, rekey_state FROM users WHERE id = ?",
            params: vec![user_id.clone()],
        },
        PairingStmt::SelectOpener { device_id, user_id } => Rendered::Query {
            sql: "SELECT hybrid_vk, revoked FROM devices WHERE id = ? AND user_id = ?",
            params: vec![device_id.clone(), user_id.clone()],
        },
        PairingStmt::TakeCeremony { grant_id } => Rendered::StoreTakePair {
            first: grant_key(grant_id),
            second: claim_key(grant_id),
        },
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
        } => Rendered::ExecuteEpoch {
            sql: "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, enrollment_grant_id, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
         )",
            params: vec![
                new_device_id.clone(),
                user_id.clone(),
                device_name.clone(),
                device_type.clone(),
                hybrid_ek.clone(),
                hybrid_vk.clone(),
                enrolled_by.clone(),
                grant_id.clone(),
                rms_capsule.clone(),
                now.clone(),
                guard_user.clone(),
            ],
            epoch: *guard_epoch,
        },
        PairingStmt::StoreResult {
            grant_id,
            device_id,
            hybrid_vk,
        } => Rendered::StoreSet {
            key: result_key(grant_id),
            value: serde_json::to_vec(&records::EnrollmentResult {
                device_id: device_id.clone(),
                hybrid_vk: hybrid_vk.clone(),
            })
            .expect("a result serializes"),
            ttl: GRANT_TTL_SECS,
        },
        PairingStmt::ReadResult { grant_id } => Rendered::StoreGet {
            key: result_key(grant_id),
        },
        PairingStmt::SelectDeviceByGrant { grant_id } => Rendered::Query {
            sql: "SELECT id, hybrid_vk FROM devices WHERE enrollment_grant_id = ?",
            params: vec![grant_id.clone()],
        },
        PairingStmt::SelectActiveDevice { device_id } => Rendered::Query {
            sql: "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = ? AND revoked = 0",
            params: vec![device_id.clone()],
        },
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
        } => Rendered::ExecuteEpoch {
            sql: "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
         )",
            params: vec![
                new_device_id.clone(),
                user_id.clone(),
                device_name.clone(),
                device_type.clone(),
                hybrid_ek.clone(),
                hybrid_vk.clone(),
                enrolled_by.clone(),
                rms_capsule.clone(),
                now.clone(),
                guard_user.clone(),
            ],
            epoch: *guard_epoch,
        },
        PairingStmt::TakeChallenge { challenge } => Rendered::StoreTake {
            key: challenge_key(challenge),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing_driver::ClaimMaterialObservation;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn one(plan: Vec<PairingStmt>) -> PairingStmt {
        assert_eq!(plan.len(), 1);
        plan[0].clone()
    }

    // The expected text is a byte-for-byte copy of the literals the handlers
    // used before the split, including their line breaks and indentation.

    #[test]
    fn store_plans_render_the_historical_keys_and_records() {
        assert_eq!(
            render(&one(plan_store_package(s("tok"), s("ct")))),
            Rendered::StoreSet {
                key: s("enrollment_package:tok"),
                value: b"ct".to_vec(),
                ttl: 900,
            }
        );
        assert_eq!(
            render(&one(plan_redeem_package(s("tok")))),
            Rendered::StoreTake { key: s("enrollment_package:tok") }
        );
        assert_eq!(
            render(&one(plan_challenge_take(s("nonce")))),
            Rendered::StoreTake { key: s("challenge:nonce") }
        );
        assert_eq!(
            render(&one(plan_store_grant(s("g"), s("u"), s("d")))),
            Rendered::StoreSet {
                key: s("enroll_grant:g"),
                value: br#"{"user_id":"u","device_id":"d"}"#.to_vec(),
                ttl: 300,
            }
        );
        assert_eq!(
            render(&one(plan_claim_write(s("g"), s("ek"), s("vk"), Some(s("Phone")), None))),
            Rendered::StoreSetIfLive {
                guard: s("enroll_grant:g"),
                key: s("enroll_claim:g"),
                value: br#"{"hybrid_ek":"ek","hybrid_vk":"vk","device_name":"Phone","device_type":null}"#.to_vec(),
                ttl: 300,
            }
        );
        assert_eq!(
            render(&one(plan_result_write(s("g"), s("dev"), s("vk")))),
            Rendered::StoreSet {
                key: s("enroll_result:g"),
                value: br#"{"device_id":"dev","hybrid_vk":"vk"}"#.to_vec(),
                ttl: 300,
            }
        );
        assert_eq!(
            render(&one(plan_result_read(s("g")))),
            Rendered::StoreGet { key: s("enroll_result:g") }
        );
        assert_eq!(
            render(&one(plan_claim_read(s("g")))),
            Rendered::StoreGet { key: s("enroll_claim:g") }
        );
        assert_eq!(
            render(&one(plan_claim_check(s("g")))),
            Rendered::StoreExists { key: s("enroll_claim:g") }
        );
        assert_eq!(
            render(&one(plan_take_ceremony(s("g")))),
            Rendered::StoreTakePair {
                first: s("enroll_grant:g"),
                second: s("enroll_claim:g"),
            }
        );
    }

    #[test]
    fn sql_statements_render_the_historical_text() {
        let query = |stmt: &PairingStmt| match render(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        };
        let exec = |stmt: &PairingStmt| match render(stmt) {
            Rendered::Execute { sql, params } => (sql, params, None),
            Rendered::ExecuteEpoch { sql, params, epoch } => (sql, params, Some(epoch)),
            other => panic!("expected a write, got {other:?}"),
        };

        assert_eq!(
            query(&one(plan_account_read(s("u")))),
            ("SELECT key_epoch, rekey_state FROM users WHERE id = ?", vec![s("u")])
        );
        let preflight = plan_completion_preflight(s("g"), s("d"), s("u"));
        assert_eq!(preflight.len(), 2);
        assert_eq!(
            preflight[0],
            PairingStmt::ReadClaim { grant_id: s("g") }
        );
        assert_eq!(
            query(&preflight[1]),
            (
                "SELECT hybrid_vk, revoked FROM devices WHERE id = ? AND user_id = ?",
                vec![s("d"), s("u")]
            )
        );
        assert_eq!(
            query(&one(plan_device_by_grant(s("g")))),
            ("SELECT id, hybrid_vk FROM devices WHERE enrollment_grant_id = ?", vec![s("g")])
        );
        assert_eq!(
            query(&one(plan_active_device_read(s("d")))),
            (
                "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = ? AND revoked = 0",
                vec![s("d")]
            )
        );
        assert_eq!(
            exec(&one(plan_completion_insert(
                s("new"), s("u"), s("Phone"), s("android"), s("ek"), s("vk"), s("by"),
                s("g"), s("cap"), s("now"), s("u"), 7,
            ))),
            (
                "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, enrollment_grant_id, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
         )",
                vec![
                    s("new"), s("u"), s("Phone"), s("android"), s("ek"), s("vk"),
                    s("by"), s("g"), s("cap"), s("now"), s("u"),
                ],
                Some(7)
            )
        );
        assert_eq!(
            exec(&one(plan_enroll_insert(
                s("new"), s("u"), s("Desktop Device"), s("desktop"), s("ek"), s("vk"),
                s("by"), s("cap"), s("now"), s("u"), 3,
            ))),
            (
                "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
         )",
                vec![
                    s("new"), s("u"), s("Desktop Device"), s("desktop"), s("ek"), s("vk"),
                    s("by"), s("cap"), s("now"), s("u"),
                ],
                Some(3)
            )
        );
    }

    #[test]
    fn classifiers_keep_the_historical_observations() {
        use crate::pairing_driver::{ClaimWriteObservation, DeviceInsertObservation};

        assert_eq!(classify_store(&[WriteOutcome::Applied(1)]), StoreObservation::Stored);
        assert_eq!(classify_store(&[WriteOutcome::Failed]), StoreObservation::Failed);
        assert_eq!(classify_store(&[]), StoreObservation::Failed);
        assert_eq!(
            classify_redeem(&TakeOutcome::Present, true),
            RedeemObservation::Present { utf8_valid: true }
        );
        assert_eq!(classify_redeem(&TakeOutcome::Missing, true), RedeemObservation::Missing);
        assert_eq!(classify_redeem(&TakeOutcome::Failed, true), RedeemObservation::Missing);
        assert!(classify_challenge_take(&TakeOutcome::Present, true));
        assert!(!classify_challenge_take(&TakeOutcome::Present, false));
        assert!(!classify_challenge_take(&TakeOutcome::Missing, true));

        assert_eq!(
            classify_claim_write(&[WriteOutcome::Inserted]),
            ClaimWriteObservation::Inserted
        );
        assert_eq!(
            classify_claim_write(&[WriteOutcome::KeyExists]),
            ClaimWriteObservation::KeyExists
        );
        assert_eq!(
            classify_claim_write(&[WriteOutcome::GuardMissing]),
            ClaimWriteObservation::GuardMissing
        );
        assert_eq!(classify_claim_write(&[WriteOutcome::Failed]), ClaimWriteObservation::GuardMissing);
        assert_eq!(classify_claim_write(&[]), ClaimWriteObservation::GuardMissing);

        let claim = classify_claim_check(true, 7, 8, &[ReadOutcome::ClaimExists(true)]);
        assert!(claim.grant_live && claim.claim_exists);
        assert_eq!((claim.hybrid_ek_len, claim.hybrid_vk_len), (7, 8));
        let failed = classify_claim_check(true, 7, 8, &[ReadOutcome::Failed]);
        assert!(!failed.claim_exists);
        assert_eq!((failed.hybrid_ek_len, failed.hybrid_vk_len), (0, 0));

        assert_eq!(
            classify_account(&[ReadOutcome::Account(None)], true, true),
            CompletionAccountObservation {
                account_query_ok: true,
                declared_epoch_positive: true,
                rekey_permitted: true,
            }
        );
        assert_eq!(account_fields(&[ReadOutcome::Failed]), (0, false));
        assert_eq!(
            account_fields(&[ReadOutcome::Account(Some(AccountRowView {
                key_epoch: Some(4),
                rekey_state: Some(s("freezing")),
            }))]),
            (4, true)
        );

        assert_eq!(
            classify_insert_completion(&[WriteOutcome::Applied(1)]),
            DeviceInsertObservation::Inserted
        );
        assert_eq!(
            classify_insert_completion(&[WriteOutcome::Applied(0)]),
            DeviceInsertObservation::Skipped
        );
        assert_eq!(
            classify_insert_completion(&[WriteOutcome::Failed]),
            DeviceInsertObservation::Failed
        );
        use crate::enroll_driver::InsertObservation;
        assert_eq!(
            classify_insert_enroll(&[WriteOutcome::Applied(1)]),
            InsertObservation::Inserted
        );
        assert_eq!(
            classify_insert_enroll(&[WriteOutcome::Applied(0)]),
            InsertObservation::EpochMismatch
        );
        assert_eq!(
            classify_insert_enroll(&[WriteOutcome::Failed]),
            InsertObservation::Failed
        );

        let verdicts = CompletionVerdicts {
            claim_keys_usable: true,
            capsule_valid: true,
            signature_field_valid: true,
            opener_key_decodes: true,
            signature_verified: true,
            account_epoch: 3,
            declared_epoch: 3,
            rotation_in_progress: false,
            account_epoch_active: true,
        };
        let opened = classify_completion_preflight(
            &[
                ReadOutcome::Claim(Some(ClaimRowView {
                    hybrid_ek: Some(s("ek")),
                    hybrid_vk: Some(s("vk")),
                    device_name: None,
                    device_type: None,
                })),
                ReadOutcome::Opener(Some(DeviceRowView {
                    device_id: None,
                    hybrid_vk: Some(s("vk")),
                    revoked: Some(0),
                    user_id: Some(s("u")),
                    enrollment_grant_id: None,
                })),
            ],
            verdicts,
        );
        assert_eq!(opened.claim, ClaimMaterialObservation::Usable);
        assert_eq!(opened.opener, OpenerObservation::Active);
        assert_eq!(opened.signature, SignatureObservation::Verified);

        let short = classify_completion_preflight(&[ReadOutcome::Failed], verdicts);
        assert_eq!(short.claim, ClaimMaterialObservation::Error);
        assert_eq!(short.opener, OpenerObservation::Inactive);
        assert!(!short.capsule_valid);
    }
}
