//! Rust mirror of the F* store model in
//! `proofs/fstar/store-lemmas/Vela_share_policy_store_model.fst`.
//!
//! The server's conformance test runs every sharing executor against a real
//! database and compares the tables and the observation with what this model
//! predicts. The F* module proves the plans and classifiers against the same
//! semantics. Each function here has a namesake there with the same case
//! order; keep them in step. `tests::shared_vectors` checks the concrete
//! runs the F* `vector_*` lemmas prove from the general theorems.
//!
//! Only the columns the sharing statements read or write are modelled. Every
//! table is keyed by its `UNIQUE` id column, so a missing key is a missing
//! row and an `INSERT` of a present key fails.

use std::collections::BTreeMap;

use crate::store::{DeviceRowView, LinkRowView, ReadOutcome, ShareStmt, WriteOutcome};

/// A `shared_items` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemRow {
    pub sender: String,
    pub recipient: String,
    pub capsule: String,
    pub created_at: String,
    pub updated_at: String,
    pub revoked: i64,
}

/// A `share_inbox` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxRow {
    pub sender: String,
    pub recipient: String,
    pub capsule: String,
    pub created_at: String,
}

/// The share-key columns of a `users` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRow {
    pub share_ek: Option<String>,
    pub share_ek_since: Option<String>,
    pub share_ek_device_id: Option<String>,
}

/// The columns of a `devices` row the device read uses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRow {
    pub user_id: String,
    pub hybrid_vk: String,
    pub revoked: i64,
}

/// The four tables, each keyed by its id.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Db {
    pub items: BTreeMap<String, ItemRow>,
    pub inbox: BTreeMap<String, InboxRow>,
    pub users: BTreeMap<String, UserRow>,
    pub devices: BTreeMap<String, DeviceRow>,
}

/// One write statement on a working state: `Some((rows changed, new state))`,
/// or `None` when the statement itself errors (a duplicate id, or a read or
/// commit passed where a write is expected). F*: `exec`.
pub fn exec(db: &Db, stmt: &ShareStmt) -> Option<(u64, Db)> {
    let mut next = db.clone();
    match stmt {
        ShareStmt::InsertSharedItem { id, sender, recipient, capsule, now } => {
            if db.items.contains_key(id) {
                return None;
            }
            next.items.insert(
                id.clone(),
                ItemRow {
                    sender: sender.clone(),
                    recipient: recipient.clone(),
                    capsule: capsule.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                    revoked: 0,
                },
            );
            Some((1, next))
        }
        ShareStmt::InsertInboxItem { id, sender, recipient, capsule, now } => {
            if db.inbox.contains_key(id) {
                return None;
            }
            next.inbox.insert(
                id.clone(),
                InboxRow {
                    sender: sender.clone(),
                    recipient: recipient.clone(),
                    capsule: capsule.clone(),
                    created_at: now.clone(),
                },
            );
            Some((1, next))
        }
        ShareStmt::UpdateLinkedCapsule { capsule, now, id, sender } => match db.items.get(id) {
            Some(row) if &row.sender == sender && row.revoked == 0 => {
                let mut row = row.clone();
                row.capsule = capsule.clone();
                row.updated_at = now.clone();
                next.items.insert(id.clone(), row);
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        ShareStmt::RevokeLinkedItem { now, id, sender } => match db.items.get(id) {
            Some(row) if &row.sender == sender && row.revoked == 0 => {
                let mut row = row.clone();
                row.revoked = 1;
                row.updated_at = now.clone();
                next.items.insert(id.clone(), row);
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        ShareStmt::DeleteLinkedInbox { id } => match db.inbox.get(id) {
            Some(_) => {
                next.inbox.remove(id);
                Some((1, next))
            }
            None => Some((0, next)),
        },
        ShareStmt::DeleteInboxItem { id, recipient } => match db.inbox.get(id) {
            Some(row) if &row.recipient == recipient => {
                next.inbox.remove(id);
                Some((1, next))
            }
            _ => Some((0, next)),
        },
        ShareStmt::UpdateShareEk { share_ek, since, device_id, user } => match db.users.get(user) {
            Some(_) => {
                next.users.insert(
                    user.clone(),
                    UserRow {
                        share_ek: Some(share_ek.clone()),
                        share_ek_since: Some(since.clone()),
                        share_ek_device_id: Some(device_id.clone()),
                    },
                );
                Some((1, next))
            }
            None => Some((0, next)),
        },
        ShareStmt::SelectLink { .. } | ShareStmt::SelectDevice { .. } | ShareStmt::Commit => None,
    }
}

fn faulted(fault: Option<usize>, k: usize) -> bool {
    fault == Some(k)
}

/// A plan run inside an open transaction, stopping at the first failure.
/// Writes go to a working state; `Commit` publishes it. A failure, or a plan
/// that ends without committing, leaves the state the transaction began
/// from (the handler drops the transaction, which rolls it back).
/// `fault = Some(k)` makes the k-th statement (from 0) fail. F*: `run_tx`.
pub fn run_transaction(
    pre: &Db,
    plan: &[ShareStmt],
    fault: Option<usize>,
) -> (Vec<WriteOutcome>, Db) {
    let mut base = pre.clone();
    let mut work = pre.clone();
    let mut outcomes = Vec::new();
    for (k, stmt) in plan.iter().enumerate() {
        if faulted(fault, k) {
            outcomes.push(WriteOutcome::Failed);
            return (outcomes, base);
        }
        if let ShareStmt::Commit = stmt {
            outcomes.push(WriteOutcome::Applied(0));
            base = work.clone();
            continue;
        }
        match exec(&work, stmt) {
            Some((rows, next)) => {
                outcomes.push(WriteOutcome::Applied(rows));
                work = next;
            }
            None => {
                outcomes.push(WriteOutcome::Failed);
                return (outcomes, base);
            }
        }
    }
    (outcomes, base)
}

/// A plan run statement by statement on the pool, each statement its own
/// transaction, stopping at the first failure. A failed statement changes
/// nothing; `Commit` has no transaction to commit and fails. F*: `run_auto`.
pub fn run_autocommit(
    pre: &Db,
    plan: &[ShareStmt],
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

/// `SelectLink` on a state; `failed` injects a read error. F*: `read_link`.
pub fn read_link(db: &Db, stmt: &ShareStmt, failed: bool) -> ReadOutcome<LinkRowView> {
    match stmt {
        ShareStmt::SelectLink { id } if !failed => ReadOutcome::Row(db.items.get(id).map(|row| LinkRowView {
            sender: Some(row.sender.clone()),
            revoked: Some(row.revoked),
        })),
        _ => ReadOutcome::Failed,
    }
}

/// `SelectDevice` on a state: the device with that id and owner, joined with
/// its owner's `users` row. F*: `read_device`.
pub fn read_device(db: &Db, stmt: &ShareStmt, failed: bool) -> ReadOutcome<DeviceRowView> {
    match stmt {
        ShareStmt::SelectDevice { device_id, user } if !failed => {
            let row = match db.devices.get(device_id) {
                Some(device) if &device.user_id == user => db.users.get(&device.user_id).map(|owner| DeviceRowView {
                    hybrid_vk: Some(device.hybrid_vk.clone()),
                    revoked: Some(device.revoked),
                    share_ek_since: owner.share_ek_since.clone(),
                    user_id: Some(device.user_id.clone()),
                }),
                _ => None,
            };
            ReadOutcome::Row(row)
        }
        _ => ReadOutcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::SendResultObservation;
    use crate::store::{classify_rows, classify_send, plan_inbox_delete, plan_link_revoke, plan_send_insert};

    fn s(x: &str) -> String {
        x.to_string()
    }

    /// The F* lemmas `vector_send_*`, `vector_revoke_*` and `vector_inbox_*`
    /// prove the same runs.
    #[test]
    fn shared_vectors() {
        let mut pre = Db::default();
        pre.items.insert(
            s("i"),
            ItemRow {
                sender: s("a"),
                recipient: s("b"),
                capsule: s("c"),
                created_at: s("t0"),
                updated_at: s("t0"),
                revoked: 0,
            },
        );
        pre.inbox.insert(
            s("i"),
            InboxRow { sender: s("a"), recipient: s("b"), capsule: s("c"), created_at: s("t0") },
        );

        // vector_send_fresh: a fresh id commits both rows.
        let send = plan_send_insert(s("j"), s("a"), s("b"), s("d"), s("t1"));
        let (outs, post) = run_transaction(&pre, &send, None);
        assert_eq!(classify_send(&outs), SendResultObservation::Committed);
        assert_eq!(post.items.len(), 2);
        assert_eq!(post.inbox["j"].recipient, "b");
        // vector_send_commit_fault: a failed commit changes nothing.
        let (outs, post) = run_transaction(&pre, &send, Some(2));
        assert_eq!(classify_send(&outs), SendResultObservation::CommitConflict);
        assert_eq!(post, pre);
        // vector_send_duplicate: a present id fails the first insert.
        let dup = plan_send_insert(s("i"), s("a"), s("b"), s("d"), s("t1"));
        let (outs, post) = run_transaction(&pre, &dup, None);
        assert_eq!(classify_send(&outs), SendResultObservation::StorageFailed);
        assert_eq!(outs, vec![WriteOutcome::Failed]);
        assert_eq!(post, pre);

        // vector_revoke_sender / vector_revoke_other.
        let (outs, post) = run_autocommit(&pre, &plan_link_revoke(s("i"), s("a"), s("t1")), None);
        assert_eq!(classify_rows(&outs).rows, 1);
        assert_eq!(post.items["i"].revoked, 1);
        let (outs, post) = run_autocommit(&pre, &plan_link_revoke(s("i"), s("b"), s("t1")), None);
        assert_eq!(classify_rows(&outs).rows, 0);
        assert_eq!(post, pre);

        // vector_inbox_recipient / vector_inbox_sender.
        let (outs, post) = run_autocommit(&pre, &plan_inbox_delete(s("i"), s("b")), None);
        assert_eq!(classify_rows(&outs).rows, 1);
        assert!(post.inbox.is_empty());
        let (outs, post) = run_autocommit(&pre, &plan_inbox_delete(s("i"), s("a")), None);
        assert_eq!(classify_rows(&outs).rows, 0);
        assert_eq!(post, pre);
    }
}
