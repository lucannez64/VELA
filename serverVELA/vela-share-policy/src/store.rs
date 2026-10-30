//! The SQL behind the sharing and one-off send-link executors, split so the
//! observation each executor returns can be proved against a store model
//! (F-1).
//!
//! Every `impl ShareExecutor` method in `vela-server/src/share/mod.rs` is
//!
//! 1. a pure `plan_*` function from the method's inputs to typed statements
//!    ([`ShareStmt`]);
//! 2. [`render`], from each statement to the exact SQL text and parameters
//!    the handler has always sent (pinned byte for byte by the unit tests
//!    below);
//! 3. a pure `classify_*` function from the per-statement outcomes to the
//!    observation the driver receives.
//!
//! The server runs a thin loop: plan, render and run each statement in order,
//! stop at the first failure, classify. hax extracts the plans and classifiers;
//! `proofs/fstar/store-lemmas` proves them against a model of the tables these
//! statements touch, for every starting database and every failing statement.
//! [`crate::store_model`] is the Rust mirror of that model, used by the
//! server's conformance test against a real database.
//!
//! Every value is text (`String`): ids, capsules, timestamps and keys are all
//! bound as SQL text parameters.

use crate::driver::{CleanupObservation, EkDeviceObservation, RowsObservation, SendResultObservation};
use crate::send_driver::{
    ConsumeObservation, ReadObservation, RemoveObservation, RowsObservation as SendRowsObservation,
};
use crate::{EkRegistrationObservation, LinkMutationObservation, SHARE_EK_LEN};

/// One statement an executor may run. Field names follow the bound
/// parameters; [`render`] fixes their order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShareStmt {
    /// `SELECT sender_user_id, revoked FROM shared_items WHERE id = ?`
    SelectLink { id: String },
    /// The signing-device row joined with its user's binding instant.
    SelectDevice { device_id: String, user: String },
    /// The linked copy of a sent capsule (`revoked = 0`).
    InsertSharedItem {
        id: String,
        sender: String,
        recipient: String,
        capsule: String,
        now: String,
    },
    /// The recipient's pending inbox copy, same id as the linked copy.
    InsertInboxItem {
        id: String,
        sender: String,
        recipient: String,
        capsule: String,
        now: String,
    },
    /// Replace a live linked item's capsule; only its sender may.
    UpdateLinkedCapsule { capsule: String, now: String, id: String, sender: String },
    /// Revoke a live linked item; only its sender may.
    RevokeLinkedItem { now: String, id: String, sender: String },
    /// Drop the pending inbox copy of a revoked linked item.
    DeleteLinkedInbox { id: String },
    /// Delete one inbox item, only from its recipient's inbox.
    DeleteInboxItem { id: String, recipient: String },
    /// Store the caller's device-signed share key binding.
    UpdateShareEk {
        share_ek: String,
        since: String,
        device_id: String,
        user: String,
    },
    /// Commit the open transaction.
    Commit,
}

/// What one write statement (or the commit) returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// It ran; the number of rows it changed (0 for the commit).
    Applied(u64),
    /// It returned an error.
    Failed,
}

/// What one read statement returned: its first row, or an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadOutcome<R> {
    Row(Option<R>),
    Failed,
}

/// The cells of a `SelectLink` row, as the handler decodes them: a text
/// `sender_user_id` and an integer `revoked`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkRowView {
    pub sender: Option<String>,
    pub revoked: Option<i64>,
}

/// The cells of a `SelectDevice` row: `d.hybrid_vk`, `d.revoked`,
/// `u.share_ek_since`, `d.user_id`. `revoked` is `Some(i)` for an integer
/// cell, `Some(1)` for the text `"1"`, and `None` otherwise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRowView {
    pub hybrid_vk: Option<String>,
    pub revoked: Option<i64>,
    pub share_ek_since: Option<String>,
    pub user_id: Option<String>,
}

/// Verdicts the handler computes from a device row's key and binding instant
/// (base64 decoding, the hybrid signature check, the freshness comparison).
/// They are inputs here: crypto and decoding stay outside the store model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceVerdicts {
    pub signature_verified: bool,
    pub stored_vk_decode_failed: bool,
    pub signature_decode_failed: bool,
    pub signed_at_is_fresher: bool,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// `insert_capsule`: both copies of the capsule, then the commit, inside the
/// transaction the handler opened for the quota reads.
pub fn plan_send_insert(
    id: String,
    sender: String,
    recipient: String,
    capsule: String,
    now: String,
) -> Vec<ShareStmt> {
    vec![
        ShareStmt::InsertSharedItem {
            id: id.clone(),
            sender: sender.clone(),
            recipient: recipient.clone(),
            capsule: capsule.clone(),
            now: now.clone(),
        },
        ShareStmt::InsertInboxItem {
            id,
            sender,
            recipient,
            capsule,
            now,
        },
        ShareStmt::Commit,
    ]
}

/// `observe_link`: read the linked row.
pub fn plan_link_read(id: String) -> ShareStmt {
    ShareStmt::SelectLink { id }
}

/// `update_linked_item`: one guarded update (autocommit).
pub fn plan_link_update(id: String, sender: String, capsule: String, now: String) -> Vec<ShareStmt> {
    vec![ShareStmt::UpdateLinkedCapsule {
        capsule,
        now,
        id,
        sender,
    }]
}

/// `revoke_linked_item`: one guarded revoke (autocommit).
pub fn plan_link_revoke(id: String, sender: String, now: String) -> Vec<ShareStmt> {
    vec![ShareStmt::RevokeLinkedItem { now, id, sender }]
}

/// `delete_linked_inbox`: drop the revoked item's pending inbox copy.
pub fn plan_linked_inbox_cleanup(id: String) -> Vec<ShareStmt> {
    vec![ShareStmt::DeleteLinkedInbox { id }]
}

/// `delete_inbox_item`: one recipient-scoped delete (autocommit).
pub fn plan_inbox_delete(id: String, recipient: String) -> Vec<ShareStmt> {
    vec![ShareStmt::DeleteInboxItem { id, recipient }]
}

/// `observe_device`: read the caller's signing-device row.
pub fn plan_device_read(device_id: String, user: String) -> ShareStmt {
    ShareStmt::SelectDevice { device_id, user }
}

/// `update_share_ek`: one binding update (autocommit).
pub fn plan_share_ek_update(
    user: String,
    share_ek: String,
    since: String,
    device_id: String,
) -> Vec<ShareStmt> {
    vec![ShareStmt::UpdateShareEk {
        share_ek,
        since,
        device_id,
        user,
    }]
}

// ── Classification ─────────────────────────────────────────────────────────

/// The send transaction: committed only when both inserts and the commit
/// succeeded; a failed commit is a conflict; anything else a storage failure.
pub fn classify_send(outcomes: &[WriteOutcome]) -> SendResultObservation {
    if outcomes.len() == 3 {
        match (outcomes[0], outcomes[1], outcomes[2]) {
            (WriteOutcome::Applied(_), WriteOutcome::Applied(_), WriteOutcome::Applied(_)) => {
                SendResultObservation::Committed
            }
            (WriteOutcome::Applied(_), WriteOutcome::Applied(_), WriteOutcome::Failed) => {
                SendResultObservation::CommitConflict
            }
            _ => SendResultObservation::StorageFailed,
        }
    } else {
        SendResultObservation::StorageFailed
    }
}

/// A single guarded write: the rows it changed, or none if it failed.
pub fn classify_rows(outcomes: &[WriteOutcome]) -> RowsObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => RowsObservation { rows },
            WriteOutcome::Failed => RowsObservation { rows: 0 },
        }
    } else {
        RowsObservation { rows: 0 }
    }
}

/// The revoke's inbox cleanup: it failed unless its one statement ran.
pub fn classify_cleanup(outcomes: &[WriteOutcome]) -> CleanupObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(_) => CleanupObservation {
                storage_failed: false,
            },
            WriteOutcome::Failed => CleanupObservation {
                storage_failed: true,
            },
        }
    } else {
        CleanupObservation {
            storage_failed: true,
        }
    }
}

/// The linked row as the mutation policy sees it. A failed read rejects.
#[allow(clippy::ptr_arg)]
pub fn classify_link(
    caller: &String,
    outcome: &ReadOutcome<LinkRowView>,
) -> LinkMutationObservation {
    match outcome {
        ReadOutcome::Row(Some(row)) => LinkMutationObservation {
            item_present: true,
            caller_matches_sender: match &row.sender {
                Some(sender) => sender == caller,
                None => false,
            },
            // Mirror the SQL `revoked = 0` predicate: only a zero cell is live.
            item_not_revoked: match row.revoked {
                Some(revoked) => revoked == 0,
                None => false,
            },
        },
        _ => LinkMutationObservation {
            item_present: false,
            caller_matches_sender: false,
            item_not_revoked: false,
        },
    }
}

/// The signing-device row as the registration policy sees it. A failed read
/// gives the historical rejecting observation.
#[allow(clippy::ptr_arg)]
pub fn classify_device(
    caller: &String,
    ek_len: usize,
    outcome: &ReadOutcome<DeviceRowView>,
    verdicts: DeviceVerdicts,
) -> EkDeviceObservation {
    match outcome {
        ReadOutcome::Failed => EkDeviceObservation {
            registration: EkRegistrationObservation {
                ek_len: SHARE_EK_LEN,
                signature_verified: false,
                device_row_present: false,
                device_user_matches: false,
                device_active: false,
                signed_at_is_fresher: false,
                binding_exists: false,
            },
            stored_identity_vk_decode_failed: false,
            signature_decode_failed: false,
        },
        ReadOutcome::Row(row) => {
            let (present, user_matches, active, binding_exists) = match row {
                Some(row) => (
                    true,
                    match &row.user_id {
                        Some(owner) => owner == caller,
                        None => false,
                    },
                    match row.revoked {
                        Some(revoked) => revoked != 1,
                        None => true,
                    },
                    match &row.share_ek_since {
                        Some(_) => true,
                        None => false,
                    },
                ),
                None => (false, false, false, false),
            };
            EkDeviceObservation {
                registration: EkRegistrationObservation {
                    ek_len,
                    signature_verified: verdicts.signature_verified,
                    device_row_present: present,
                    device_user_matches: user_matches,
                    device_active: active,
                    signed_at_is_fresher: verdicts.signed_at_is_fresher,
                    binding_exists,
                },
                stored_identity_vk_decode_failed: verdicts.stored_vk_decode_failed,
                signature_decode_failed: verdicts.signature_decode_failed,
            }
        }
    }
}

// ── One-off send links: `sends` ────────────────────────────────────────────

/// One statement an `sends` executor may run (F-1, send-link driver). The
/// `sends` table is keyed by its `UNIQUE` id; every statement here is
/// autocommit, so no transaction or `Commit` statement exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendStmt {
    /// `INSERT INTO sends (...)` with `view_count` and `revoked` pinned to 0.
    InsertSend {
        id: String,
        owner: String,
        ciphertext: String,
        has_passphrase: bool,
        kdf_salt: Option<String>,
        label: Option<String>,
        view_once: bool,
        max_views: Option<i64>,
        created_at: String,
        expires_at: String,
    },
    /// Consume one view of a live, unexpired, unexhausted link.
    ConsumeSendView { id: String, now: String },
    /// The row the fetch handler returns to the anonymous reader.
    SelectSend { id: String },
    /// Drop the delivered view-once row.
    DeleteSend { id: String },
    /// Delete one link, only from its owner's rows.
    DeleteOwnedSend { id: String, owner: String },
}

/// The cells of a `SelectSend` row, as the handler decodes them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendRowView {
    pub ciphertext: Option<String>,
    pub has_passphrase: Option<i64>,
    pub kdf_salt: Option<String>,
    pub view_once: Option<i64>,
    pub max_views: Option<i64>,
    pub view_count: Option<i64>,
    pub expires_at: Option<String>,
}

/// Which required cell of a fetched row was missing, so the handler keeps its
/// historical error message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendCell {
    Ciphertext,
    ExpiresAt,
}

/// The fetch read's whole observation: the driver's verdict, the response
/// cells, and the missing cell that made a row unreadable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendFetchObservation {
    pub read: ReadObservation,
    pub missing_cell: Option<SendCell>,
    pub ciphertext: Option<String>,
    pub has_passphrase: bool,
    pub kdf_salt: Option<String>,
    pub view_once: bool,
    pub max_views: Option<i64>,
    pub view_count: i64,
    pub expires_at: Option<String>,
}

/// The historical default for every cell the handler has not decoded.
fn empty_fetch(read: ReadObservation, missing_cell: Option<SendCell>) -> SendFetchObservation {
    SendFetchObservation {
        read,
        missing_cell,
        ciphertext: None,
        has_passphrase: false,
        kdf_salt: None,
        view_once: false,
        max_views: None,
        view_count: 0,
        expires_at: None,
    }
}

/// `row.bool_int(i).unwrap_or(false)`: a non-zero integer cell is true and an
/// unreadable one is false.
fn bool_cell(cell: Option<i64>) -> bool {
    match cell {
        Some(value) => value != 0,
        None => false,
    }
}

// ── Send plans ─────────────────────────────────────────────────────────────

/// `CreateSendIo::insert_send`: one insert on the pool (autocommit).
#[allow(clippy::too_many_arguments)]
pub fn plan_send_create(
    id: String,
    owner: String,
    ciphertext: String,
    has_passphrase: bool,
    kdf_salt: Option<String>,
    label: Option<String>,
    view_once: bool,
    max_views: Option<i64>,
    created_at: String,
    expires_at: String,
) -> Vec<SendStmt> {
    vec![SendStmt::InsertSend {
        id,
        owner,
        ciphertext,
        has_passphrase,
        kdf_salt,
        label,
        view_once,
        max_views,
        created_at,
        expires_at,
    }]
}

/// `FetchSendIo::consume_view`: the atomic view consume (autocommit).
pub fn plan_send_consume(id: String, now: String) -> Vec<SendStmt> {
    vec![SendStmt::ConsumeSendView { id, now }]
}

/// `FetchSendIo::read_send`: read the delivered row.
pub fn plan_send_read(id: String) -> SendStmt {
    SendStmt::SelectSend { id }
}

/// `FetchSendIo::remove_fetched`: drop the delivered view-once row
/// (autocommit).
pub fn plan_send_remove(id: String) -> Vec<SendStmt> {
    vec![SendStmt::DeleteSend { id }]
}

/// `DeleteSendIo::delete_link`: the owner-scoped delete (autocommit).
pub fn plan_send_delete(id: String, owner: String) -> Vec<SendStmt> {
    vec![SendStmt::DeleteOwnedSend { id, owner }]
}

// ── Send classification ────────────────────────────────────────────────────

/// `CreateSendIo::insert_send`: the rows the insert changed, or a storage
/// failure.
pub fn classify_send_create(outcomes: &[WriteOutcome]) -> SendRowsObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => SendRowsObservation {
                rows,
                failed: false,
            },
            WriteOutcome::Failed => SendRowsObservation {
                rows: 0,
                failed: true,
            },
        }
    } else {
        SendRowsObservation {
            rows: 0,
            failed: true,
        }
    }
}

/// `FetchSendIo::consume_view`: no row matched the SQL guard, one view was
/// consumed, or the statement failed.
pub fn classify_send_consume(outcomes: &[WriteOutcome]) -> ConsumeObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(0) => ConsumeObservation::Unavailable,
            WriteOutcome::Applied(_) => ConsumeObservation::Consumed,
            WriteOutcome::Failed => ConsumeObservation::Error,
        }
    } else {
        ConsumeObservation::Error
    }
}

/// `FetchSendIo::remove_fetched`: the cleanup is reported as performed unless
/// its one statement failed.
pub fn classify_send_remove(outcomes: &[WriteOutcome]) -> RemoveObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(_) => RemoveObservation {
                removed: true,
                failed: false,
            },
            WriteOutcome::Failed => RemoveObservation {
                removed: false,
                failed: true,
            },
        }
    } else {
        RemoveObservation {
            removed: false,
            failed: true,
        }
    }
}

/// `DeleteSendIo::delete_link`: the rows the owner-scoped delete removed, or a
/// storage failure.
pub fn classify_send_delete(outcomes: &[WriteOutcome]) -> SendRowsObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => SendRowsObservation {
                rows,
                failed: false,
            },
            WriteOutcome::Failed => SendRowsObservation {
                rows: 0,
                failed: true,
            },
        }
    } else {
        SendRowsObservation {
            rows: 0,
            failed: true,
        }
    }
}

/// `FetchSendIo::read_send`: the row's cells, the driver's read verdict and
/// (for an unreadable row) which required cell was missing. A failed query is
/// `Unreadable` with no cell to blame; an absent row is `Missing`.
#[allow(clippy::ptr_arg)]
pub fn classify_send_read(outcome: &ReadOutcome<SendRowView>) -> SendFetchObservation {
    match outcome {
        ReadOutcome::Failed => empty_fetch(ReadObservation::Unreadable, None),
        ReadOutcome::Row(None) => empty_fetch(ReadObservation::Missing, None),
        ReadOutcome::Row(Some(row)) => {
            let Some(ciphertext) = row.ciphertext.clone() else {
                return empty_fetch(ReadObservation::Unreadable, Some(SendCell::Ciphertext));
            };
            let has_passphrase = bool_cell(row.has_passphrase);
            let kdf_salt = row.kdf_salt.clone();
            let view_once = bool_cell(row.view_once);
            let max_views = row.max_views;
            let view_count = match row.view_count {
                Some(value) => value,
                None => 0,
            };
            let Some(expires_at) = row.expires_at.clone() else {
                return SendFetchObservation {
                    read: ReadObservation::Unreadable,
                    missing_cell: Some(SendCell::ExpiresAt),
                    ciphertext: Some(ciphertext),
                    has_passphrase,
                    kdf_salt,
                    view_once,
                    max_views,
                    view_count,
                    expires_at: None,
                };
            };
            SendFetchObservation {
                read: ReadObservation::Payload { view_once },
                missing_cell: None,
                ciphertext: Some(ciphertext),
                has_passphrase,
                kdf_salt,
                view_once,
                max_views,
                view_count,
                expires_at: Some(expires_at),
            }
        }
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

/// One statement as the database receives it.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rendered {
    /// A read (`query`).
    Query { sql: &'static str, params: Vec<String> },
    /// A write (`execute`).
    Execute { sql: &'static str, params: Vec<String> },
    /// `COMMIT` on the open transaction.
    Commit,
}

/// The exact SQL text and text parameters each statement has always used.
#[cfg(not(hax))]
pub fn render(stmt: &ShareStmt) -> Rendered {
    match stmt {
        ShareStmt::SelectLink { id } => Rendered::Query {
            sql: "SELECT sender_user_id, revoked FROM shared_items WHERE id = ?",
            params: vec![id.clone()],
        },
        ShareStmt::SelectDevice { device_id, user } => Rendered::Query {
            sql: "SELECT d.hybrid_vk, d.revoked, u.share_ek_since, d.user_id
             FROM devices d JOIN users u ON u.id = d.user_id
             WHERE d.id = ? AND d.user_id = ?",
            params: vec![device_id.clone(), user.clone()],
        },
        ShareStmt::InsertSharedItem {
            id,
            sender,
            recipient,
            capsule,
            now,
        } => Rendered::Execute {
            sql: "INSERT INTO shared_items (id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked)
             VALUES (?, ?, ?, ?, ?, ?, 0)",
            params: vec![
                id.clone(),
                sender.clone(),
                recipient.clone(),
                capsule.clone(),
                now.clone(),
                now.clone(),
            ],
        },
        ShareStmt::InsertInboxItem {
            id,
            sender,
            recipient,
            capsule,
            now,
        } => Rendered::Execute {
            sql: "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at)
                 VALUES (?, ?, ?, ?, ?)",
            params: vec![
                id.clone(),
                sender.clone(),
                recipient.clone(),
                capsule.clone(),
                now.clone(),
            ],
        },
        ShareStmt::UpdateLinkedCapsule {
            capsule,
            now,
            id,
            sender,
        } => Rendered::Execute {
            sql: "UPDATE shared_items
         SET capsule = ?, updated_at = ?
         WHERE id = ? AND sender_user_id = ? AND revoked = 0",
            params: vec![capsule.clone(), now.clone(), id.clone(), sender.clone()],
        },
        ShareStmt::RevokeLinkedItem { now, id, sender } => Rendered::Execute {
            sql: "UPDATE shared_items
         SET revoked = 1, updated_at = ?
         WHERE id = ? AND sender_user_id = ? AND revoked = 0",
            params: vec![now.clone(), id.clone(), sender.clone()],
        },
        ShareStmt::DeleteLinkedInbox { id } => Rendered::Execute {
            sql: "DELETE FROM share_inbox WHERE id = ?",
            params: vec![id.clone()],
        },
        ShareStmt::DeleteInboxItem { id, recipient } => Rendered::Execute {
            sql: "DELETE FROM share_inbox WHERE id = ? AND recipient_user_id = ?",
            params: vec![id.clone(), recipient.clone()],
        },
        ShareStmt::UpdateShareEk {
            share_ek,
            since,
            device_id,
            user,
        } => Rendered::Execute {
            sql: "UPDATE users SET share_ek = ?, share_ek_since = ?, share_ek_device_id = ?
             WHERE id = ?",
            params: vec![share_ek.clone(), since.clone(), device_id.clone(), user.clone()],
        },
        ShareStmt::Commit => Rendered::Commit,
    }
}

/// One bound parameter of a rendered `sends` statement: the handler binds
/// text, integers and NULL (for the nullable columns) exactly as before.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlParam {
    Text(String),
    Int(i64),
    Null,
}

/// One `sends` statement as the database receives it.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendRendered {
    /// A read (`query`).
    Query { sql: &'static str, params: Vec<SqlParam> },
    /// A write (`execute`).
    Execute { sql: &'static str, params: Vec<SqlParam> },
}

/// The exact SQL text and parameters each `sends` statement has always used.
#[cfg(not(hax))]
pub fn render_send(stmt: &SendStmt) -> SendRendered {
    match stmt {
        SendStmt::InsertSend {
            id,
            owner,
            ciphertext,
            has_passphrase,
            kdf_salt,
            label,
            view_once,
            max_views,
            created_at,
            expires_at,
        } => SendRendered::Execute {
            sql: "INSERT INTO sends
                (id, owner_user_id, ciphertext, has_passphrase, kdf_salt, label,
                 view_once, max_views, view_count, created_at, expires_at, revoked)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)",
            params: vec![
                SqlParam::Text(id.clone()),
                SqlParam::Text(owner.clone()),
                SqlParam::Text(ciphertext.clone()),
                SqlParam::Int(if *has_passphrase { 1 } else { 0 }),
                match kdf_salt {
                    Some(value) => SqlParam::Text(value.clone()),
                    None => SqlParam::Null,
                },
                match label {
                    Some(value) => SqlParam::Text(value.clone()),
                    None => SqlParam::Null,
                },
                SqlParam::Int(if *view_once { 1 } else { 0 }),
                match max_views {
                    Some(value) => SqlParam::Int(*value),
                    None => SqlParam::Null,
                },
                SqlParam::Text(created_at.clone()),
                SqlParam::Text(expires_at.clone()),
            ],
        },
        SendStmt::ConsumeSendView { id, now } => SendRendered::Execute {
            sql: "UPDATE sends SET view_count = view_count + 1
             WHERE id = ? AND revoked = 0 AND expires_at > ?
               AND (max_views IS NULL OR view_count < max_views)",
            params: vec![SqlParam::Text(id.clone()), SqlParam::Text(now.clone())],
        },
        SendStmt::SelectSend { id } => SendRendered::Query {
            sql: "SELECT ciphertext, has_passphrase, kdf_salt, view_once, max_views, view_count, expires_at
             FROM sends WHERE id = ?",
            params: vec![SqlParam::Text(id.clone())],
        },
        SendStmt::DeleteSend { id } => SendRendered::Execute {
            sql: "DELETE FROM sends WHERE id = ?",
            params: vec![SqlParam::Text(id.clone())],
        },
        SendStmt::DeleteOwnedSend { id, owner } => SendRendered::Execute {
            sql: "DELETE FROM sends WHERE id = ? AND owner_user_id = ?",
            params: vec![SqlParam::Text(id.clone()), SqlParam::Text(owner.clone())],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn exec(stmt: &ShareStmt) -> (&'static str, Vec<String>) {
        match render(stmt) {
            Rendered::Execute { sql, params } => (sql, params),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    fn query(stmt: &ShareStmt) -> (&'static str, Vec<String>) {
        match render(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    // The expected strings are byte-for-byte copies of the literals the
    // handlers used before the split (vela-server/src/share/mod.rs at 22206b0),
    // including their line breaks and indentation.

    #[test]
    fn send_plan_renders_the_historical_transaction() {
        let plan = plan_send_insert(s("id"), s("snd"), s("rcp"), s("cap"), s("now"));
        assert_eq!(plan.len(), 3);
        assert_eq!(
            exec(&plan[0]),
            (
                "INSERT INTO shared_items (id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked)\n             VALUES (?, ?, ?, ?, ?, ?, 0)",
                vec![s("id"), s("snd"), s("rcp"), s("cap"), s("now"), s("now")]
            )
        );
        assert_eq!(
            exec(&plan[1]),
            (
                "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at)\n                 VALUES (?, ?, ?, ?, ?)",
                vec![s("id"), s("snd"), s("rcp"), s("cap"), s("now")]
            )
        );
        assert_eq!(render(&plan[2]), Rendered::Commit);
    }

    #[test]
    fn link_plans_render_the_historical_statements() {
        assert_eq!(
            query(&plan_link_read(s("id"))),
            (
                "SELECT sender_user_id, revoked FROM shared_items WHERE id = ?",
                vec![s("id")]
            )
        );
        let update = plan_link_update(s("id"), s("snd"), s("cap"), s("now"));
        assert_eq!(update.len(), 1);
        assert_eq!(
            exec(&update[0]),
            (
                "UPDATE shared_items\n         SET capsule = ?, updated_at = ?\n         WHERE id = ? AND sender_user_id = ? AND revoked = 0",
                vec![s("cap"), s("now"), s("id"), s("snd")]
            )
        );
        let revoke = plan_link_revoke(s("id"), s("snd"), s("now"));
        assert_eq!(revoke.len(), 1);
        assert_eq!(
            exec(&revoke[0]),
            (
                "UPDATE shared_items\n         SET revoked = 1, updated_at = ?\n         WHERE id = ? AND sender_user_id = ? AND revoked = 0",
                vec![s("now"), s("id"), s("snd")]
            )
        );
        let cleanup = plan_linked_inbox_cleanup(s("id"));
        assert_eq!(cleanup.len(), 1);
        assert_eq!(
            exec(&cleanup[0]),
            ("DELETE FROM share_inbox WHERE id = ?", vec![s("id")])
        );
    }

    #[test]
    fn inbox_and_ek_plans_render_the_historical_statements() {
        let delete = plan_inbox_delete(s("id"), s("me"));
        assert_eq!(delete.len(), 1);
        assert_eq!(
            exec(&delete[0]),
            (
                "DELETE FROM share_inbox WHERE id = ? AND recipient_user_id = ?",
                vec![s("id"), s("me")]
            )
        );
        assert_eq!(
            query(&plan_device_read(s("dev"), s("me"))),
            (
                "SELECT d.hybrid_vk, d.revoked, u.share_ek_since, d.user_id\n             FROM devices d JOIN users u ON u.id = d.user_id\n             WHERE d.id = ? AND d.user_id = ?",
                vec![s("dev"), s("me")]
            )
        );
        let ek = plan_share_ek_update(s("me"), s("ek"), s("since"), s("dev"));
        assert_eq!(ek.len(), 1);
        assert_eq!(
            exec(&ek[0]),
            (
                "UPDATE users SET share_ek = ?, share_ek_since = ?, share_ek_device_id = ?\n             WHERE id = ?",
                vec![s("ek"), s("since"), s("dev"), s("me")]
            )
        );
    }

    #[test]
    fn classifiers_keep_the_historical_observations() {
        use WriteOutcome::{Applied, Failed};
        assert_eq!(classify_send(&[Failed]), SendResultObservation::StorageFailed);
        assert_eq!(classify_send(&[Applied(1), Failed]), SendResultObservation::StorageFailed);
        assert_eq!(
            classify_send(&[Applied(1), Applied(1), Failed]),
            SendResultObservation::CommitConflict
        );
        assert_eq!(
            classify_send(&[Applied(1), Applied(1), Applied(0)]),
            SendResultObservation::Committed
        );
        assert_eq!(classify_rows(&[Applied(1)]), RowsObservation { rows: 1 });
        assert_eq!(classify_rows(&[Applied(0)]), RowsObservation { rows: 0 });
        assert_eq!(classify_rows(&[Failed]), RowsObservation { rows: 0 });
        assert!(!classify_cleanup(&[Applied(0)]).storage_failed);
        assert!(classify_cleanup(&[Failed]).storage_failed);

        let me = s("me");
        let live = ReadOutcome::Row(Some(LinkRowView { sender: Some(s("me")), revoked: Some(0) }));
        assert_eq!(
            classify_link(&me, &live),
            LinkMutationObservation { item_present: true, caller_matches_sender: true, item_not_revoked: true }
        );
        let foreign = ReadOutcome::Row(Some(LinkRowView { sender: Some(s("you")), revoked: Some(1) }));
        assert_eq!(
            classify_link(&me, &foreign),
            LinkMutationObservation { item_present: true, caller_matches_sender: false, item_not_revoked: false }
        );
        let missing: ReadOutcome<LinkRowView> = ReadOutcome::Row(None);
        assert!(!classify_link(&me, &missing).item_present);
        assert!(!classify_link(&me, &ReadOutcome::Failed).item_present);
    }

    #[test]
    fn device_classifier_matches_the_historical_cell_rules() {
        let me = s("me");
        let verdicts = DeviceVerdicts {
            signature_verified: true,
            stored_vk_decode_failed: false,
            signature_decode_failed: false,
            signed_at_is_fresher: true,
        };
        let row = |revoked: Option<i64>, since: Option<&str>| {
            ReadOutcome::Row(Some(DeviceRowView {
                hybrid_vk: Some(s("vk")),
                revoked,
                share_ek_since: since.map(s),
                user_id: Some(s("me")),
            }))
        };
        let active = classify_device(&me, 7, &row(Some(0), None), verdicts);
        assert!(active.registration.device_row_present);
        assert!(active.registration.device_user_matches);
        assert!(active.registration.device_active);
        assert!(!active.registration.binding_exists);
        assert_eq!(active.registration.ek_len, 7);
        let revoked = classify_device(&me, 7, &row(Some(1), Some("t")), verdicts);
        assert!(!revoked.registration.device_active);
        assert!(revoked.registration.binding_exists);
        // A cell the handler cannot read as 1 never counted as revoked.
        assert!(classify_device(&me, 7, &row(None, None), verdicts).registration.device_active);
        let failed = classify_device(&me, 7, &ReadOutcome::Failed, verdicts);
        assert_eq!(failed.registration.ek_len, SHARE_EK_LEN);
        assert!(!failed.registration.signature_verified);
        assert!(!failed.stored_identity_vk_decode_failed);
        let absent = classify_device(&me, 7, &ReadOutcome::Row(None), verdicts);
        assert!(!absent.registration.device_row_present);
        assert!(!absent.registration.device_active);
    }

    fn send_exec(stmt: &SendStmt) -> (&'static str, Vec<SqlParam>) {
        match render_send(stmt) {
            SendRendered::Execute { sql, params } => (sql, params),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    fn send_query(stmt: &SendStmt) -> (&'static str, Vec<SqlParam>) {
        match render_send(stmt) {
            SendRendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    // Byte-for-byte copies of the literals `vela-server/src/send.rs` used
    // before the split, including their line breaks and indentation.

    #[test]
    fn send_plans_render_the_historical_statements() {
        let create = plan_send_create(
            s("id"),
            s("own"),
            s("ct"),
            true,
            Some(s("salt")),
            Some(s("label")),
            false,
            Some(5),
            s("t0"),
            s("t1"),
        );
        assert_eq!(create.len(), 1);
        assert_eq!(
            send_exec(&create[0]),
            (
                "INSERT INTO sends
                (id, owner_user_id, ciphertext, has_passphrase, kdf_salt, label,
                 view_once, max_views, view_count, created_at, expires_at, revoked)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)",
                vec![
                    SqlParam::Text(s("id")),
                    SqlParam::Text(s("own")),
                    SqlParam::Text(s("ct")),
                    SqlParam::Int(1),
                    SqlParam::Text(s("salt")),
                    SqlParam::Text(s("label")),
                    SqlParam::Int(0),
                    SqlParam::Int(5),
                    SqlParam::Text(s("t0")),
                    SqlParam::Text(s("t1")),
                ]
            )
        );
        // Nullable columns bind NULL, never an empty string.
        let bare = plan_send_create(
            s("id"),
            s("own"),
            s("ct"),
            false,
            None,
            None,
            true,
            None,
            s("t0"),
            s("t1"),
        );
        assert_eq!(
            send_exec(&bare[0]).1,
            vec![
                SqlParam::Text(s("id")),
                SqlParam::Text(s("own")),
                SqlParam::Text(s("ct")),
                SqlParam::Int(0),
                SqlParam::Null,
                SqlParam::Null,
                SqlParam::Int(1),
                SqlParam::Null,
                SqlParam::Text(s("t0")),
                SqlParam::Text(s("t1")),
            ]
        );

        let consume = plan_send_consume(s("id"), s("now"));
        assert_eq!(consume.len(), 1);
        assert_eq!(
            send_exec(&consume[0]),
            (
                "UPDATE sends SET view_count = view_count + 1
             WHERE id = ? AND revoked = 0 AND expires_at > ?
               AND (max_views IS NULL OR view_count < max_views)",
                vec![SqlParam::Text(s("id")), SqlParam::Text(s("now"))]
            )
        );

        assert_eq!(
            send_query(&plan_send_read(s("id"))),
            (
                "SELECT ciphertext, has_passphrase, kdf_salt, view_once, max_views, view_count, expires_at
             FROM sends WHERE id = ?",
                vec![SqlParam::Text(s("id"))]
            )
        );

        let remove = plan_send_remove(s("id"));
        assert_eq!(remove.len(), 1);
        assert_eq!(
            send_exec(&remove[0]),
            ("DELETE FROM sends WHERE id = ?", vec![SqlParam::Text(s("id"))])
        );

        let delete = plan_send_delete(s("id"), s("own"));
        assert_eq!(delete.len(), 1);
        assert_eq!(
            send_exec(&delete[0]),
            (
                "DELETE FROM sends WHERE id = ? AND owner_user_id = ?",
                vec![SqlParam::Text(s("id")), SqlParam::Text(s("own"))]
            )
        );
    }

    #[test]
    fn send_classifiers_keep_the_historical_observations() {
        use WriteOutcome::{Applied, Failed};
        assert_eq!(
            classify_send_create(&[Applied(1)]),
            SendRowsObservation { rows: 1, failed: false }
        );
        assert_eq!(
            classify_send_create(&[Failed]),
            SendRowsObservation { rows: 0, failed: true }
        );
        assert_eq!(classify_send_consume(&[Applied(0)]), ConsumeObservation::Unavailable);
        assert_eq!(classify_send_consume(&[Applied(1)]), ConsumeObservation::Consumed);
        assert_eq!(classify_send_consume(&[Applied(3)]), ConsumeObservation::Consumed);
        assert_eq!(classify_send_consume(&[Failed]), ConsumeObservation::Error);
        assert_eq!(
            classify_send_remove(&[Applied(0)]),
            RemoveObservation { removed: true, failed: false }
        );
        assert_eq!(
            classify_send_remove(&[Failed]),
            RemoveObservation { removed: false, failed: true }
        );
        assert_eq!(
            classify_send_delete(&[Applied(0)]),
            SendRowsObservation { rows: 0, failed: false }
        );
        assert_eq!(
            classify_send_delete(&[Failed]),
            SendRowsObservation { rows: 0, failed: true }
        );

        let failed = classify_send_read(&ReadOutcome::Failed);
        assert_eq!(failed.read, ReadObservation::Unreadable);
        assert_eq!(failed.missing_cell, None);
        assert_eq!(failed.ciphertext, None);

        let missing = classify_send_read(&ReadOutcome::Row(None));
        assert_eq!(missing.read, ReadObservation::Missing);
        assert_eq!(missing.missing_cell, None);

        let row = |ciphertext: Option<&str>, expires_at: Option<&str>| {
            ReadOutcome::Row(Some(SendRowView {
                ciphertext: ciphertext.map(s),
                has_passphrase: Some(1),
                kdf_salt: Some(s("salt")),
                view_once: Some(1),
                max_views: Some(4),
                view_count: Some(2),
                expires_at: expires_at.map(s),
            }))
        };
        let payload = classify_send_read(&row(Some("ct"), Some("exp")));
        assert_eq!(payload.read, ReadObservation::Payload { view_once: true });
        assert_eq!(payload.missing_cell, None);
        assert_eq!(payload.ciphertext, Some(s("ct")));
        assert!(payload.has_passphrase);
        assert_eq!(payload.kdf_salt, Some(s("salt")));
        assert!(payload.view_once);
        assert_eq!(payload.max_views, Some(4));
        assert_eq!(payload.view_count, 2);
        assert_eq!(payload.expires_at, Some(s("exp")));

        let no_ciphertext = classify_send_read(&row(None, Some("exp")));
        assert_eq!(no_ciphertext.read, ReadObservation::Unreadable);
        assert_eq!(no_ciphertext.missing_cell, Some(SendCell::Ciphertext));
        assert_eq!(no_ciphertext.ciphertext, None);

        let no_expiry = classify_send_read(&row(Some("ct"), None));
        assert_eq!(no_expiry.read, ReadObservation::Unreadable);
        assert_eq!(no_expiry.missing_cell, Some(SendCell::ExpiresAt));
        // The handler assigns the earlier cells before it notices the expiry.
        assert_eq!(no_expiry.ciphertext, Some(s("ct")));
        assert!(no_expiry.view_once);
        assert_eq!(no_expiry.expires_at, None);
    }
}
