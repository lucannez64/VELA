//! The guarded `users` statements behind the recovery-share lifecycle, split
//! so the observation each executor returns can be proved against a store
//! model (F-1).
//!
//! The four handlers in `vela-server/src/recovery/mod.rs` are thin loops:
//! plan → render → run → classify, exactly like `EnrollDeviceIo`. This module
//! owns the plans, the exact SQL text and parameters, and the classifiers for
//! `PutShareIo`, `FinalizeShareIo`, `GetShareIo` and `DeleteShareIo`.
//!
//! hax extracts these functions; `proofs/fstar/share-lemmas` proves them
//! against a model of the `users` columns they read and write, for every
//! starting row and every failing statement. The unit tests below pin the
//! rendered SQL byte for byte, so splitting the handler changed no behaviour.

use crate::recovery_share_driver::{
    DeleteUpdateObservation, FinalizeAccountObservation, FinalizeUpdateObservation,
    ReadObservation, StageAccountObservation, StageUpdateObservation,
};
use crate::redemption_store::WriteOutcome;
#[cfg(not(hax))]
use crate::redemption_store::{Param, Rendered};

/// One statement a recovery-share executor method runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShareStmt {
    /// The guarded update that stages one recovery share and the possession
    /// commitment that must be finalized with it.
    StageShare {
        user: String,
        share: String,
        split_id: String,
        epoch: i64,
        auth_hash: String,
    },
    /// The guarded update that promotes the exact staged split.
    PromoteStagedSplit {
        user: String,
        epoch: i64,
        split_id: String,
    },
    /// The guarded update that clears the active share and the staged split
    /// together.
    DeleteShare { user: String, epoch: i64 },
    /// The live-row read after a zero-row stage update.
    SelectStageAccount { user: String },
    /// The live-row read after a zero-row finalize update.
    SelectFinalizeAccount { user: String },
    /// The active-share read behind `GET /recovery/share`.
    SelectShare { user: String },
}

/// The cells of a `SelectStageAccount` row: `key_epoch`, `rekey_state`,
/// `recovery_share` and `recovery_split_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageAccountRowView {
    pub stored_epoch: Option<i64>,
    pub rotation_active: bool,
    pub active_share: Option<String>,
    pub active_split: Option<String>,
}

/// The cells of a `SelectFinalizeAccount` row: `key_epoch`, `rekey_state` and
/// `recovery_split_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeAccountRowView {
    pub stored_epoch: Option<i64>,
    pub rotation_active: bool,
    pub active_split: Option<String>,
}

/// The cells of a `SelectShare` row: `recovery_share`, `recovery_split_id` and
/// `key_epoch`. `share` is the raw stored base64 text; the handler decodes it
/// after classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareRowView {
    pub share: Option<String>,
    pub split_id: Option<String>,
    pub epoch: Option<i64>,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// `PutShareIo::stage_share`: one guarded update of the staged candidate.
pub fn plan_stage_share(
    user: String,
    share: String,
    split_id: String,
    epoch: i64,
    auth_hash: String,
) -> Vec<ShareStmt> {
    vec![ShareStmt::StageShare {
        user,
        share,
        split_id,
        epoch,
        auth_hash,
    }]
}

/// `FinalizeShareIo::promote_staged_split`: one guarded promotion.
pub fn plan_promote_staged_split(user: String, epoch: i64, split_id: String) -> Vec<ShareStmt> {
    vec![ShareStmt::PromoteStagedSplit {
        user,
        epoch,
        split_id,
    }]
}

/// `DeleteShareIo::delete_share`: one guarded clear of share and candidate.
pub fn plan_delete_share(user: String, epoch: i64) -> Vec<ShareStmt> {
    vec![ShareStmt::DeleteShare { user, epoch }]
}

/// `PutShareIo::stage_query_account`: read the live row after a zero-row
/// stage update.
pub fn plan_stage_account(user: String) -> ShareStmt {
    ShareStmt::SelectStageAccount { user }
}

/// `FinalizeShareIo::finalize_query_account`: read the live row after a
/// zero-row finalize update.
pub fn plan_finalize_account(user: String) -> ShareStmt {
    ShareStmt::SelectFinalizeAccount { user }
}

/// `GetShareIo::read_share`: read the active share of the session account.
pub fn plan_read_share(user: String) -> ShareStmt {
    ShareStmt::SelectShare { user }
}

// ── Classification ─────────────────────────────────────────────────────────

/// `stage_share`: exactly one updated row is `Staged`, anything else is
/// `NotStaged`. A statement error aborts before classification.
pub fn classify_stage_update(outcomes: &[WriteOutcome]) -> StageUpdateObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => {
                if rows == 1 {
                    StageUpdateObservation::Staged
                } else {
                    StageUpdateObservation::NotStaged
                }
            }
            WriteOutcome::Failed => StageUpdateObservation::NotStaged,
        }
    } else {
        StageUpdateObservation::NotStaged
    }
}

/// `stage_query_account`: the live row's truth, or the all-absent observation
/// when the account row is gone.
pub fn classify_stage_account(
    row: Option<StageAccountRowView>,
    share: &String,
    split_id: &String,
) -> StageAccountObservation {
    match row {
        None => StageAccountObservation {
            account_present: false,
            stored_epoch: None,
            rotation_active: false,
            active_share_matches: false,
            active_split_matches: false,
        },
        Some(row) => StageAccountObservation {
            account_present: true,
            stored_epoch: row.stored_epoch,
            rotation_active: row.rotation_active,
            active_share_matches: row.active_share.as_ref() == Some(share),
            active_split_matches: row.active_split.as_ref() == Some(split_id),
        },
    }
}

/// `promote_staged_split`: exactly one updated row is `Promoted`, anything else
/// is `NotPromoted`.
pub fn classify_finalize_update(outcomes: &[WriteOutcome]) -> FinalizeUpdateObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => {
                if rows == 1 {
                    FinalizeUpdateObservation::Promoted
                } else {
                    FinalizeUpdateObservation::NotPromoted
                }
            }
            WriteOutcome::Failed => FinalizeUpdateObservation::NotPromoted,
        }
    } else {
        FinalizeUpdateObservation::NotPromoted
    }
}

/// `finalize_query_account`: the live row's truth, or the all-absent
/// observation when the account row is gone.
pub fn classify_finalize_account(
    row: Option<FinalizeAccountRowView>,
    split_id: &String,
) -> FinalizeAccountObservation {
    match row {
        None => FinalizeAccountObservation {
            account_present: false,
            stored_epoch: None,
            rotation_active: false,
            active_split_matches: false,
        },
        Some(row) => FinalizeAccountObservation {
            account_present: true,
            stored_epoch: row.stored_epoch,
            rotation_active: row.rotation_active,
            active_split_matches: row.active_split.as_ref() == Some(split_id),
        },
    }
}

/// `delete_share`: exactly one updated row is `Deleted`, anything else is
/// `NotDeleted`.
pub fn classify_delete_update(outcomes: &[WriteOutcome]) -> DeleteUpdateObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => {
                if rows == 1 {
                    DeleteUpdateObservation::Deleted
                } else {
                    DeleteUpdateObservation::NotDeleted
                }
            }
            WriteOutcome::Failed => DeleteUpdateObservation::NotDeleted,
        }
    } else {
        DeleteUpdateObservation::NotDeleted
    }
}

/// `read_share`: the live row's truth about account and share presence.
pub fn classify_read_share(row: Option<ShareRowView>) -> ReadObservation {
    match row {
        None => ReadObservation {
            account_present: false,
            share_present: false,
        },
        Some(row) => ReadObservation {
            account_present: true,
            share_present: row.share.is_some(),
        },
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

/// The exact SQL text and parameters each statement has always used.
#[cfg(not(hax))]
pub fn render(stmt: &ShareStmt) -> Rendered {
    match stmt {
        ShareStmt::StageShare {
            user,
            share,
            split_id,
            epoch,
            auth_hash,
        } => Rendered::Execute {
            sql: "UPDATE users
             SET recovery_pending_share = ?, recovery_pending_split_id = ?,
                 recovery_pending_epoch = ?, recovery_pending_auth_hash = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_share IS NULL AND recovery_split_id IS NULL",
            params: vec![
                Param::Text(share.clone()),
                Param::Text(split_id.clone()),
                Param::Int(*epoch),
                Param::Text(auth_hash.clone()),
                Param::Text(user.clone()),
                Param::Int(*epoch),
            ],
        },
        ShareStmt::PromoteStagedSplit {
            user,
            epoch,
            split_id,
        } => Rendered::Execute {
            sql: "UPDATE users
             SET recovery_share = recovery_pending_share,
                 recovery_split_id = recovery_pending_split_id,
                 recovery_auth_hash = recovery_pending_auth_hash,
                 recovery_pending_share = NULL,
                 recovery_pending_split_id = NULL,
                 recovery_pending_epoch = NULL,
                 recovery_pending_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_pending_epoch = ?
               AND recovery_pending_split_id = ?
               AND recovery_pending_share IS NOT NULL
               AND recovery_pending_auth_hash IS NOT NULL
               AND recovery_share IS NULL AND recovery_split_id IS NULL",
            params: vec![
                Param::Text(user.clone()),
                Param::Int(*epoch),
                Param::Int(*epoch),
                Param::Text(split_id.clone()),
            ],
        },
        ShareStmt::DeleteShare { user, epoch } => Rendered::Execute {
            sql: "UPDATE users
             SET recovery_share = NULL, recovery_split_id = NULL,
                 recovery_pending_share = NULL,
                 recovery_pending_split_id = NULL,
                 recovery_pending_epoch = NULL,
                 recovery_auth_hash = NULL,
                 recovery_pending_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            params: vec![Param::Text(user.clone()), Param::Int(*epoch)],
        },
        ShareStmt::SelectStageAccount { user } => Rendered::Query {
            sql: "SELECT key_epoch, rekey_state, recovery_share, recovery_split_id
                 FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        ShareStmt::SelectFinalizeAccount { user } => Rendered::Query {
            sql: "SELECT key_epoch, rekey_state, recovery_split_id
                 FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        ShareStmt::SelectShare { user } => Rendered::Query {
            sql: "SELECT recovery_share, recovery_split_id, key_epoch
             FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn exec(stmt: &ShareStmt) -> (&'static str, Vec<Param>) {
        match render(stmt) {
            Rendered::Execute { sql, params } => (sql, params),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    fn query(stmt: &ShareStmt) -> (&'static str, Vec<Param>) {
        match render(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    // The expected strings are byte-for-byte copies of the literals the
    // recovery-share handlers used before the split
    // (vela-server/src/recovery/mod.rs at b9e3d67).

    #[test]
    fn stage_plan_renders_the_historical_statement() {
        let plan = plan_stage_share(s("u"), s("share"), s("split"), 7, s("auth"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            exec(&plan[0]),
            (
                "UPDATE users
             SET recovery_pending_share = ?, recovery_pending_split_id = ?,
                 recovery_pending_epoch = ?, recovery_pending_auth_hash = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_share IS NULL AND recovery_split_id IS NULL",
                vec![
                    Param::Text(s("share")),
                    Param::Text(s("split")),
                    Param::Int(7),
                    Param::Text(s("auth")),
                    Param::Text(s("u")),
                    Param::Int(7),
                ]
            )
        );
    }

    #[test]
    fn finalize_plan_renders_the_historical_statement() {
        let plan = plan_promote_staged_split(s("u"), 7, s("split"));
        assert_eq!(plan.len(), 1);
        assert_eq!(
            exec(&plan[0]),
            (
                "UPDATE users
             SET recovery_share = recovery_pending_share,
                 recovery_split_id = recovery_pending_split_id,
                 recovery_auth_hash = recovery_pending_auth_hash,
                 recovery_pending_share = NULL,
                 recovery_pending_split_id = NULL,
                 recovery_pending_epoch = NULL,
                 recovery_pending_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_pending_epoch = ?
               AND recovery_pending_split_id = ?
               AND recovery_pending_share IS NOT NULL
               AND recovery_pending_auth_hash IS NOT NULL
               AND recovery_share IS NULL AND recovery_split_id IS NULL",
                vec![
                    Param::Text(s("u")),
                    Param::Int(7),
                    Param::Int(7),
                    Param::Text(s("split")),
                ]
            )
        );
    }

    #[test]
    fn delete_plan_renders_the_historical_statement() {
        let plan = plan_delete_share(s("u"), 7);
        assert_eq!(plan.len(), 1);
        assert_eq!(
            exec(&plan[0]),
            (
                "UPDATE users
             SET recovery_share = NULL, recovery_split_id = NULL,
                 recovery_pending_share = NULL,
                 recovery_pending_split_id = NULL,
                 recovery_pending_epoch = NULL,
                 recovery_auth_hash = NULL,
                 recovery_pending_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
                vec![Param::Text(s("u")), Param::Int(7)]
            )
        );
    }

    #[test]
    fn reads_render_the_historical_queries() {
        assert_eq!(
            query(&plan_stage_account(s("u"))),
            (
                "SELECT key_epoch, rekey_state, recovery_share, recovery_split_id
                 FROM users WHERE id = ?",
                vec![Param::Text(s("u"))]
            )
        );
        assert_eq!(
            query(&plan_finalize_account(s("u"))),
            (
                "SELECT key_epoch, rekey_state, recovery_split_id
                 FROM users WHERE id = ?",
                vec![Param::Text(s("u"))]
            )
        );
        assert_eq!(
            query(&plan_read_share(s("u"))),
            (
                "SELECT recovery_share, recovery_split_id, key_epoch
             FROM users WHERE id = ?",
                vec![Param::Text(s("u"))]
            )
        );
    }

    #[test]
    fn classifiers_keep_the_historical_observations() {
        use WriteOutcome::{Applied, Failed};
        assert_eq!(
            classify_stage_update(&[Applied(1)]),
            StageUpdateObservation::Staged
        );
        assert_eq!(
            classify_stage_update(&[Applied(0)]),
            StageUpdateObservation::NotStaged
        );
        assert_eq!(
            classify_stage_update(&[Applied(2)]),
            StageUpdateObservation::NotStaged
        );
        assert_eq!(
            classify_stage_update(&[Failed]),
            StageUpdateObservation::NotStaged
        );
        assert_eq!(
            classify_finalize_update(&[Applied(1)]),
            FinalizeUpdateObservation::Promoted
        );
        assert_eq!(
            classify_finalize_update(&[Applied(0)]),
            FinalizeUpdateObservation::NotPromoted
        );
        assert_eq!(
            classify_delete_update(&[Applied(1)]),
            DeleteUpdateObservation::Deleted
        );
        assert_eq!(
            classify_delete_update(&[Applied(0)]),
            DeleteUpdateObservation::NotDeleted
        );

        assert_eq!(
            classify_stage_account(None, &s("share"), &s("split")),
            StageAccountObservation {
                account_present: false,
                stored_epoch: None,
                rotation_active: false,
                active_share_matches: false,
                active_split_matches: false,
            }
        );
        let row = StageAccountRowView {
            stored_epoch: Some(7),
            rotation_active: false,
            active_share: Some(s("share")),
            active_split: Some(s("split")),
        };
        assert_eq!(
            classify_stage_account(Some(row.clone()), &s("share"), &s("split")),
            StageAccountObservation {
                account_present: true,
                stored_epoch: Some(7),
                rotation_active: false,
                active_share_matches: true,
                active_split_matches: true,
            }
        );
        assert!(!classify_stage_account(Some(row), &s("other"), &s("split")).active_share_matches);

        assert_eq!(
            classify_finalize_account(None, &s("split")),
            FinalizeAccountObservation {
                account_present: false,
                stored_epoch: None,
                rotation_active: false,
                active_split_matches: false,
            }
        );
        let row = FinalizeAccountRowView {
            stored_epoch: Some(7),
            rotation_active: true,
            active_split: Some(s("split")),
        };
        assert_eq!(
            classify_finalize_account(Some(row), &s("split")),
            FinalizeAccountObservation {
                account_present: true,
                stored_epoch: Some(7),
                rotation_active: true,
                active_split_matches: true,
            }
        );

        assert_eq!(
            classify_read_share(None),
            ReadObservation {
                account_present: false,
                share_present: false
            }
        );
        assert_eq!(
            classify_read_share(Some(ShareRowView {
                share: None,
                split_id: None,
                epoch: Some(1),
            })),
            ReadObservation {
                account_present: true,
                share_present: false
            }
        );
        assert_eq!(
            classify_read_share(Some(ShareRowView {
                share: Some(s("share")),
                split_id: Some(s("split")),
                epoch: Some(7),
            })),
            ReadObservation {
                account_present: true,
                share_present: true
            }
        );
    }
}
