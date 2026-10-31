//! The thin loop behind the recovered-device enrollment executor (F-1).
//!
//! An executor method builds a typed plan with
//! `vela_recovery_policy::redemption_store`, runs it here (render each
//! statement, run it against turso or the key-value store, stop at the first
//! failure) and hands the per-statement outcomes to the matching `classify_*`.
//! The plans and classifiers are proved in F* against a store model; this
//! module is the part that model trusts, and `conformance.rs` checks it, with
//! injected failures, against a real database and store.

use vela_recovery_policy::possession_driver::CommitmentObservation;
use vela_recovery_policy::possession_store::{
    self, InitiateRowView, PossessionStmt, ProofAccountRowView,
};
use vela_recovery_policy::redemption_store::{
    self, AuthorityRowView, Param, Rendered, RedemptionStmt, WriteOutcome,
};
use vela_recovery_policy::share_store::{
    self, FinalizeAccountRowView, ShareRowView, ShareStmt, StageAccountRowView,
};
use vela_recovery_policy::webauthn_store::{
    self, AuthStateView, CredentialHolderView, CredentialRowView, FinishAccountRowView, SetNxOutcome,
    SetOutcome, ShareRowView as WebAuthnShareRowView, WebAuthnStmt,
};
use webauthn_rs::prelude::Passkey;

use crate::sqldb::{Db as _, TursoDb, TursoValue, VelaRow};
use crate::error::{AppError, Result};

/// Where an executor's SQL statements run. The enrollment path uses the pool:
/// each statement commits on its own.
pub(super) trait RecoverySql {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>>;
    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64>;
}

/// The connection pool: each statement commits on its own.
pub(super) struct PoolSql<'a>(pub &'a TursoDb);

impl RecoverySql for PoolSql<'_> {
    async fn query(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<Vec<VelaRow>> {
        self.0.query(sql, params).await
    }

    async fn execute(&mut self, sql: &str, params: Vec<TursoValue>) -> anyhow::Result<u64> {
        self.0.execute(sql, params).await
    }
}

/// Where an executor's enrollment-grant and challenge operations run.
pub(super) trait RecoveryKv {
    fn take(&mut self, key: &str) -> Result<Option<Vec<u8>>>;
    fn put(&mut self, key: &str, value: &[u8]) -> Result<()>;
    /// Whether the exact key is present.
    fn exists(&mut self, key: &str) -> Result<bool>;
    /// Set the key only while it is absent; `true` when this call wrote it.
    fn set_nx(&mut self, key: &str, value: &[u8], ttl_secs: u64) -> Result<bool>;
    /// Set the key, overwriting any current value.
    fn set_ex(&mut self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()>;
}

/// The sled-backed store the recovery grants live in.
pub(super) struct StoreKv<'a>(pub &'a crate::store::Store);

impl RecoveryKv for StoreKv<'_> {
    fn take(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        self.0.get_del(key)
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.0
            .set_ex(key, value, super::recover::ENROLL_GRANT_TTL_SECS)
    }

    fn exists(&mut self, key: &str) -> Result<bool> {
        self.0.exists(key)
    }

    fn set_nx(&mut self, key: &str, value: &[u8], ttl_secs: u64) -> Result<bool> {
        self.0.set_ex_nx(key, value, ttl_secs)
    }

    fn set_ex(&mut self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        self.0.set_ex(key, value, ttl_secs)
    }
}

fn turso_params(params: Vec<Param>) -> Vec<TursoValue> {
    params
        .into_iter()
        .map(|param| match param {
            Param::Text(text) => TursoValue::Text(text),
            Param::Int(value) => TursoValue::Integer(value),
        })
        .collect()
}

/// Runs a write plan in order, stopping at the first failure. Returns one
/// outcome per statement run and the error that stopped it, if any.
pub(super) async fn run_writes<S: RecoverySql>(
    sql: &mut S,
    plan: &[RedemptionStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match redemption_store::render(stmt) {
            Rendered::Execute { sql: text, params } => sql.execute(text, turso_params(params)).await,
            Rendered::Query { .. } => Err(anyhow::anyhow!("a read statement in a write plan")),
            Rendered::KvTake { .. }
            | Rendered::KvPut { .. }
            | Rendered::KvExists { .. }
            | Rendered::KvSetNx { .. }
            | Rendered::KvSetEx { .. } => {
                Err(anyhow::anyhow!("a store statement in a SQL write plan"))
            }
        };
        match result {
            Ok(rows) => outcomes.push(WriteOutcome::Applied(rows)),
            Err(error) => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, Some(error));
            }
        }
    }
    (outcomes, None)
}

/// Runs one read statement.
pub(super) async fn run_read<S: RecoverySql>(
    sql: &mut S,
    stmt: &RedemptionStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match redemption_store::render(stmt) {
        Rendered::Query { sql: text, params } => sql.query(text, turso_params(params)).await,
        _ => Err(anyhow::anyhow!("a non-read statement in a read plan")),
    }
}

/// Runs a recovery-share write plan in order, stopping at the first failure.
pub(super) async fn run_share_writes<S: RecoverySql>(
    sql: &mut S,
    plan: &[ShareStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        let result = match share_store::render(stmt) {
            Rendered::Execute { sql: text, params } => sql.execute(text, turso_params(params)).await,
            Rendered::Query { .. } => Err(anyhow::anyhow!("a read statement in a write plan")),
            Rendered::KvTake { .. }
            | Rendered::KvPut { .. }
            | Rendered::KvExists { .. }
            | Rendered::KvSetNx { .. }
            | Rendered::KvSetEx { .. } => {
                Err(anyhow::anyhow!("a store statement in a SQL write plan"))
            }
        };
        match result {
            Ok(rows) => outcomes.push(WriteOutcome::Applied(rows)),
            Err(error) => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, Some(error));
            }
        }
    }
    (outcomes, None)
}

/// Runs one recovery-share read statement.
pub(super) async fn run_share_read<S: RecoverySql>(
    sql: &mut S,
    stmt: &ShareStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match share_store::render(stmt) {
        Rendered::Query { sql: text, params } => sql.query(text, turso_params(params)).await,
        _ => Err(anyhow::anyhow!("a non-read statement in a read plan")),
    }
}

/// Runs one atomic grant take.
pub(super) fn take_grant<K: RecoveryKv>(    kv: &mut K,
    stmt: &RedemptionStmt,
) -> Result<Option<Vec<u8>>> {
    match redemption_store::render(stmt) {
        Rendered::KvTake { key } => kv.take(&key),
        _ => Err(crate::error::AppError::Internal(
            "a non-take statement in a take plan".into(),
        )),
    }
}

/// Runs one grant restoration.
pub(super) fn put_grant<K: RecoveryKv>(kv: &mut K, stmt: &RedemptionStmt) -> Result<()> {
    match redemption_store::render(stmt) {
        Rendered::KvPut { key, value } => kv.put(&key, &value),
        _ => Err(crate::error::AppError::Internal(
            "a non-put statement in a put plan".into(),
        )),
    }
}

/// The first `SelectAuthority` row. An empty `recovery_auth_hash` is reported
/// as no commitment, exactly as the insert guard's `<> ''` treats it.
pub(super) fn authority_row_view(rows: &[VelaRow]) -> Option<AuthorityRowView> {
    rows.first().map(|row| AuthorityRowView {
        credential_id: row.text(0).map(String::from),
        auth_hash: row.text(1).filter(|hash| !hash.is_empty()).map(String::from),
    })
}

/// The first `SelectStageAccount` row.
pub(super) fn stage_account_row_view(rows: &[VelaRow]) -> Option<StageAccountRowView> {
    rows.first().map(|row| StageAccountRowView {
        stored_epoch: row.i64(0),
        rotation_active: row.text(1).is_some(),
        active_share: row.text(2).map(String::from),
        active_split: row.text(3).map(String::from),
    })
}

/// The first `SelectFinalizeAccount` row.
pub(super) fn finalize_account_row_view(rows: &[VelaRow]) -> Option<FinalizeAccountRowView> {
    rows.first().map(|row| FinalizeAccountRowView {
        stored_epoch: row.i64(0),
        rotation_active: row.text(1).is_some(),
        active_split: row.text(2).map(String::from),
    })
}

/// The first `SelectShare` row.
pub(super) fn share_row_view(rows: &[VelaRow]) -> Option<ShareRowView> {
    rows.first().map(|row| ShareRowView {
        share: row.text(0).map(String::from),
        split_id: row.text(1).map(String::from),
        epoch: row.i64(2),
    })
}

// ── Possession-proof plans (F-1) ───────────────────────────────────────────

/// Decode one base64 commitment cell into the observation the driver sees.
fn commitment_cell(row: &VelaRow, index: usize) -> CommitmentObservation {
    match row.get(index) {
        Some(TursoValue::Text(text)) => match crate::db::decode_b64(text) {
            Ok(bytes) => CommitmentObservation::Present { len: bytes.len() },
            Err(_) => CommitmentObservation::Corrupt,
        },
        _ => CommitmentObservation::Missing,
    }
}

/// The decode error behind a corrupt cell, exactly the error the handler has
/// always rendered.
fn commitment_error(row: &VelaRow, index: usize) -> Option<AppError> {
    match row.get(index) {
        Some(TursoValue::Text(text)) => crate::db::decode_b64(text).err(),
        _ => None,
    }
}

/// The first initiation row: `recovery_share`, the decoded commitment,
/// `key_epoch` and `rekey_state`, with the decode error if the cell is corrupt.
pub(super) fn initiate_row(rows: &[VelaRow]) -> (Option<InitiateRowView>, Option<AppError>) {
    let Some(row) = rows.first() else {
        return (None, None);
    };
    let commitment = commitment_cell(row, 1);
    let decode_error = if commitment == CommitmentObservation::Corrupt {
        commitment_error(row, 1)
    } else {
        None
    };
    (
        Some(InitiateRowView {
            share_present: !matches!(row.get(0), Some(TursoValue::Null) | None),
            commitment,
            key_epoch: row.i64(2),
            rotation_active: row.text(3).is_some(),
        }),
        decode_error,
    )
}

/// The first proof-recovery row: the decoded commitment, `key_epoch` and
/// `rekey_state`, with the decode error if the cell is corrupt and the decoded
/// commitment bytes for verification.
pub(super) fn proof_account_row(
    rows: &[VelaRow],
) -> (
    Option<ProofAccountRowView>,
    Option<AppError>,
    Option<Vec<u8>>,
) {
    let Some(row) = rows.first() else {
        return (None, None, None);
    };
    let commitment = commitment_cell(row, 0);
    let (decode_error, commitment_bytes) = match row.get(0) {
        Some(TursoValue::Text(text)) => match crate::db::decode_b64(text) {
            Ok(bytes) => (None, Some(bytes)),
            Err(error) => (Some(error), None),
        },
        _ => (None, None),
    };
    (
        Some(ProofAccountRowView {
            commitment,
            stored_epoch: row.i64(1),
            rotation_active: row.text(2).is_some(),
        }),
        decode_error,
        commitment_bytes,
    )
}

/// Runs one possession read statement.
pub(super) async fn run_possession_read<S: RecoverySql>(
    sql: &mut S,
    stmt: &PossessionStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match possession_store::render(stmt) {
        Rendered::Query { sql: text, params } => sql.query(text, turso_params(params)).await,
        _ => Err(anyhow::anyhow!("a non-read statement in a possession read plan")),
    }
}

/// Runs the exact user/attempt proof-slot probe.
pub(super) fn probe_proof_slot<K: RecoveryKv>(kv: &mut K, stmt: &PossessionStmt) -> Result<bool> {
    match possession_store::render(stmt) {
        Rendered::KvExists { key } => kv.exists(&key),
        _ => Err(AppError::Internal(
            "a non-exists statement in a proof-slot plan".into(),
        )),
    }
}

/// Runs the atomic insert-if-absent of the drawn challenge.
pub(super) fn store_proof_challenge<K: RecoveryKv>(
    kv: &mut K,
    stmt: &PossessionStmt,
) -> Result<bool> {
    match possession_store::render(stmt) {
        Rendered::KvSetNx {
            key,
            value,
            ttl_secs,
        } => kv.set_nx(&key, &value, ttl_secs),
        _ => Err(AppError::Internal(
            "a non-set_nx statement in a challenge plan".into(),
        )),
    }
}

/// Runs the atomic read-and-delete of the exact proof attempt.
pub(super) fn take_proof_attempt<K: RecoveryKv>(
    kv: &mut K,
    stmt: &PossessionStmt,
) -> Result<Option<Vec<u8>>> {
    match possession_store::render(stmt) {
        Rendered::KvTake { key } => kv.take(&key),
        _ => Err(AppError::Internal(
            "a non-take statement in a proof-attempt plan".into(),
        )),
    }
}

/// Runs one single-use enrollment-grant store.
pub(super) fn put_enrollment_grant<K: RecoveryKv>(kv: &mut K, stmt: &PossessionStmt) -> Result<()> {
    match possession_store::render(stmt) {
        Rendered::KvSetEx {
            key,
            value,
            ttl_secs,
        } => kv.set_ex(&key, &value, ttl_secs),
        _ => Err(AppError::Internal(
            "a non-set_ex statement in a grant plan".into(),
        )),
    }
}

// ── WebAuthn recovery plans (F-1) ──────────────────────────────────────────

/// Runs one WebAuthn read statement.
pub(super) async fn run_webauthn_read<S: RecoverySql>(
    sql: &mut S,
    stmt: &WebAuthnStmt,
) -> anyhow::Result<Vec<VelaRow>> {
    match webauthn_store::render(stmt) {
        Rendered::Query { sql: text, params } => sql.query(text, turso_params(params)).await,
        _ => Err(anyhow::anyhow!(
            "a non-read statement in a WebAuthn read plan"
        )),
    }
}

/// Runs one WebAuthn write statement, returning the rows it changed.
pub(super) async fn run_webauthn_write<S: RecoverySql>(
    sql: &mut S,
    stmt: &WebAuthnStmt,
) -> anyhow::Result<u64> {
    match webauthn_store::render(stmt) {
        Rendered::Execute { sql: text, params } => sql.execute(text, turso_params(params)).await,
        _ => Err(anyhow::anyhow!(
            "a non-write statement in a WebAuthn write plan"
        )),
    }
}

/// Runs a one-statement WebAuthn write plan: its outcome, or the error that
/// stopped it.
pub(super) async fn run_webauthn_writes<S: RecoverySql>(
    sql: &mut S,
    plan: &[WebAuthnStmt],
) -> (Vec<WriteOutcome>, Option<anyhow::Error>) {
    let mut outcomes = Vec::with_capacity(plan.len());
    for stmt in plan {
        match run_webauthn_write(sql, stmt).await {
            Ok(rows) => outcomes.push(WriteOutcome::Applied(rows)),
            Err(error) => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, Some(error));
            }
        }
    }
    (outcomes, None)
}

/// Whether the exact attempt slot is occupied.
pub(super) fn probe_auth_slot<K: RecoveryKv>(kv: &mut K, stmt: &WebAuthnStmt) -> Result<bool> {
    match webauthn_store::render(stmt) {
        Rendered::KvExists { key } => kv.exists(&key),
        _ => Err(AppError::Internal(
            "a non-exists statement in an attempt-slot plan".into(),
        )),
    }
}

/// The atomic insert-if-absent of one attempt envelope.
pub(super) fn store_auth_state<K: RecoveryKv>(
    kv: &mut K,
    stmt: &WebAuthnStmt,
) -> Result<SetNxOutcome> {
    match webauthn_store::render(stmt) {
        Rendered::KvSetNx {
            key,
            value,
            ttl_secs,
        } => Ok(if kv.set_nx(&key, &value, ttl_secs)? {
            SetNxOutcome::Wrote
        } else {
            SetNxOutcome::Occupied
        }),
        _ => Err(AppError::Internal(
            "a non-set_nx statement in a challenge plan".into(),
        )),
    }
}

/// The atomic read-and-delete of the exact attempt envelope.
pub(super) fn take_auth_state<K: RecoveryKv>(
    kv: &mut K,
    stmt: &WebAuthnStmt,
) -> Result<Option<Vec<u8>>> {
    match webauthn_store::render(stmt) {
        Rendered::KvTake { key } => kv.take(&key),
        _ => Err(AppError::Internal(
            "a non-take statement in an attempt plan".into(),
        )),
    }
}

/// The overwriting write of the registration ceremony state.
pub(super) fn store_registration_state<K: RecoveryKv>(
    kv: &mut K,
    stmt: &WebAuthnStmt,
) -> Result<SetOutcome> {
    match webauthn_store::render(stmt) {
        Rendered::KvSetEx {
            key,
            value,
            ttl_secs,
        } => {
            kv.set_ex(&key, &value, ttl_secs)?;
            Ok(SetOutcome::Wrote)
        }
        _ => Err(AppError::Internal(
            "a non-set_ex statement in a registration-state plan".into(),
        )),
    }
}

/// The atomic read-and-delete of the registration ceremony state.
pub(super) fn take_registration_state<K: RecoveryKv>(
    kv: &mut K,
    stmt: &WebAuthnStmt,
) -> Result<Option<Vec<u8>>> {
    match webauthn_store::render(stmt) {
        Rendered::KvTake { key } => kv.take(&key),
        _ => Err(AppError::Internal(
            "a non-take statement in a registration-state plan".into(),
        )),
    }
}

/// Stores one credential-bound enrollment grant.
pub(super) fn store_credential_grant<K: RecoveryKv>(
    kv: &mut K,
    stmt: &WebAuthnStmt,
) -> Result<()> {
    match webauthn_store::render(stmt) {
        Rendered::KvSetEx {
            key,
            value,
            ttl_secs,
        } => kv.set_ex(&key, &value, ttl_secs),
        _ => Err(AppError::Internal(
            "a non-set_ex statement in a grant plan".into(),
        )),
    }
}

/// The decoded stored-credential recall: the row view the drivers classify,
/// plus the decoded passkey and its decode error when the cell does not parse.
pub(super) struct CredentialObservation {
    pub view: CredentialRowView,
    pub passkey: Option<Passkey>,
    pub decode_error: Option<AppError>,
}

/// The first `SelectCredential` row, decoded exactly as
/// `observe_recovery_credential` decodes it.
pub(super) fn credential_row(rows: &[VelaRow]) -> Result<CredentialObservation> {
    let Some(row) = rows.first() else {
        return Ok(CredentialObservation {
            view: CredentialRowView {
                account_present: false,
                credential: vela_recovery_policy::webauthn_driver::StoredCredentialObservation::Missing,
            },
            passkey: None,
            decode_error: None,
        });
    };
    match row.get(0) {
        Some(TursoValue::Null) | None => Ok(CredentialObservation {
            view: CredentialRowView {
                account_present: true,
                credential: vela_recovery_policy::webauthn_driver::StoredCredentialObservation::Missing,
            },
            passkey: None,
            decode_error: None,
        }),
        Some(TursoValue::Text(passkey_json)) => match serde_json::from_str(passkey_json) {
            Ok(passkey) => Ok(CredentialObservation {
                view: CredentialRowView {
                    account_present: true,
                    credential:
                        vela_recovery_policy::webauthn_driver::StoredCredentialObservation::Present,
                },
                passkey: Some(passkey),
                decode_error: None,
            }),
            Err(e) => Ok(CredentialObservation {
                view: CredentialRowView {
                    account_present: true,
                    credential:
                        vela_recovery_policy::webauthn_driver::StoredCredentialObservation::Corrupt,
                },
                passkey: None,
                decode_error: Some(AppError::Internal(format!(
                    "invalid stored WebAuthn credential: {e}"
                ))),
            }),
        },
        _ => Err(AppError::Internal(
            "expected WebAuthn credential JSON".into(),
        )),
    }
}

/// The first `SelectShare` row.
pub(super) fn webauthn_share_row_view(rows: &[VelaRow]) -> WebAuthnShareRowView {
    match rows.first() {
        Some(row) => WebAuthnShareRowView {
            account_present: true,
            share_present: !matches!(row.get(0), Some(TursoValue::Null) | None),
        },
        None => WebAuthnShareRowView {
            account_present: false,
            share_present: false,
        },
    }
}

/// The first `SelectFinishAccount` row.
pub(super) fn finish_account_row_view(rows: &[VelaRow]) -> Option<FinishAccountRowView> {
    rows.first().map(|row| FinishAccountRowView {
        share: row.text(0).map(String::from),
        stored_epoch: row.i64(1),
        rotation_active: row.text(2).is_some(),
        stored_credential_id: row.text(3).map(String::from),
        split_id: row.text(4).map(String::from),
    })
}

/// The credential-holder lookup: whether a row belongs to another account, and
/// the error a row whose id cell did not read as text has always produced.
pub(super) fn holder_view(
    rows: &[VelaRow],
    user_id: &str,
) -> (CredentialHolderView, Option<AppError>) {
    for row in rows {
        let Some(id) = row.text(0) else {
            return (
                CredentialHolderView::Unreadable,
                Some(AppError::Internal("expected user id".into())),
            );
        };
        if id != user_id {
            return (CredentialHolderView::OtherAccount, None);
        }
    }
    (CredentialHolderView::OnlyCaller, None)
}

/// The view an attempt envelope carries, for the plan.
pub(super) fn auth_state_view(
    user_id: uuid::Uuid,
    attempt: uuid::Uuid,
    credential_id: &str,
) -> AuthStateView {
    AuthStateView {
        user: user_id.to_string(),
        attempt: attempt.to_string(),
        credential_id: credential_id.to_string(),
    }
}
