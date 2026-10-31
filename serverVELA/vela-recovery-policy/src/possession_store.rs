//! The SQL and key-value operations behind the possession-proof recovery
//! executors, split so the observation each method returns can be proved
//! against a store model (F-1).
//!
//! `InitiateProofIo` and `RecoverProofIo` in
//! `vela-server/src/recovery/possess.rs` are
//!
//! 1. pure `plan_*` functions from the method's inputs to typed statements
//!    ([`PossessionStmt`]);
//! 2. [`render`], from each statement to the exact SQL text, parameters or
//!    store key and value the handler has always used (pinned byte for byte by
//!    the unit tests below);
//! 3. pure `classify_*` functions from the statement outcomes to the
//!    observation the driver receives.
//!
//! The server runs the statement and classifies the outcome. hax extracts the
//! plans and classifiers; `proofs/fstar/possession-lemmas` proves them against
//! a model of the `users` row, the single-use proof-attempt slot and the
//! enrollment-grant store, for every starting state, every fault point and
//! every starting attempt.
//!
//! Every id, key, credential id and envelope value is text (`String`); the only
//! integer statement parameter apart from TTLs is the epoch.

use crate::possession_driver::{
    AttemptConsumptionObservation, ChallengeStoreObservation, CommitmentObservation,
    GrantStoreObservation, InitiateObservation, ProofAccountObservation,
};

/// One statement a possession executor method runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PossessionStmt {
    /// The live account row the initiation observation is built from:
    /// `recovery_share`, `recovery_auth_hash`, `key_epoch`, `rekey_state`.
    SelectInitiateAccount { user: String },
    /// Whether the exact user/attempt proof-state slot is occupied.
    ProofSlotExists { key: String },
    /// Commit the drawn challenge only while the exact slot is free.
    StoreProofChallenge {
        key: String,
        /// The serialized [`ProofAttemptView`]; [`render`] sends these bytes.
        value: String,
        attempt: ProofAttemptView,
        ttl_secs: u64,
    },
    /// The atomic single-use read-and-delete of the exact proof attempt.
    TakeProofAttempt { key: String },
    /// The live account row the proof-recovery observation is built from:
    /// `recovery_auth_hash`, `key_epoch`, `rekey_state`.
    SelectProofAccount { user: String },
    /// Store one single-use enrollment grant at the driver's epoch.
    PutEnrollmentGrant {
        key: String,
        /// The serialized grant; [`render`] sends exactly these bytes.
        value: String,
        grant: EnrollmentGrantView,
        ttl_secs: u64,
    },
}

/// The fields one stored proof attempt carries, as the plan writes them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofAttemptView {
    pub user: String,
    pub attempt: String,
    pub key_epoch: i64,
}

/// The single-use enrollment grant as the store holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentGrantView {
    pub key_epoch: i64,
}

/// The cells of an initiation account row: `recovery_share`,
/// `recovery_auth_hash` (decoded), `key_epoch` and `rekey_state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiateRowView {
    pub share_present: bool,
    /// The decoded base64 commitment column: absent, its byte length, or
    /// present-but-undecodable.
    pub commitment: CommitmentObservation,
    pub key_epoch: Option<i64>,
    pub rotation_active: bool,
}

/// The cells of a proof-recovery account row: `recovery_auth_hash` (decoded),
/// `key_epoch` and `rekey_state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofAccountRowView {
    pub commitment: CommitmentObservation,
    pub stored_epoch: Option<i64>,
    pub rotation_active: bool,
}

/// What the atomic `get_del` of one proof attempt observed. A store error
/// aborts the request before classification, so it is not a variant here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofAttemptTake {
    /// No live proof state matched the exact key.
    Missing,
    /// The state was removed but its envelope did not decode.
    Corrupt,
    /// The state was removed and decoded to these fields.
    Present(ProofAttemptView),
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// `InitiateProofIo::observe`: read the live account row.
pub fn plan_initiate_account(user: String) -> PossessionStmt {
    PossessionStmt::SelectInitiateAccount { user }
}

/// `InitiateProofIo::observe`: probe the generated attempt slot.
pub fn plan_proof_slot(key: String) -> PossessionStmt {
    PossessionStmt::ProofSlotExists { key }
}

/// `InitiateProofIo::store_challenge`: commit the drawn challenge.
pub fn plan_store_challenge(
    key: String,
    value: String,
    attempt: ProofAttemptView,
    ttl_secs: u64,
) -> PossessionStmt {
    PossessionStmt::StoreProofChallenge {
        key,
        value,
        attempt,
        ttl_secs,
    }
}

/// `RecoverProofIo::consume_attempt`: the atomic single-use take.
pub fn plan_take_attempt(key: String) -> PossessionStmt {
    PossessionStmt::TakeProofAttempt { key }
}

/// `RecoverProofIo::query_account`: read the live account row.
pub fn plan_proof_account(user: String) -> PossessionStmt {
    PossessionStmt::SelectProofAccount { user }
}

/// `RecoverProofIo::issue_grant`: store exactly one single-use grant.
pub fn plan_issue_grant(
    key: String,
    value: String,
    grant: EnrollmentGrantView,
    ttl_secs: u64,
) -> PossessionStmt {
    PossessionStmt::PutEnrollmentGrant {
        key,
        value,
        grant,
        ttl_secs,
    }
}

// ── Classification ─────────────────────────────────────────────────────────

/// `InitiateProofIo::observe`: every field is the live row's truth; the
/// attempt slot is reported fresh exactly when the probe found it empty.
pub fn classify_initiate(
    row: Option<InitiateRowView>,
    slot_occupied: bool,
    ttl_secs: u64,
) -> InitiateObservation {
    match row {
        None => InitiateObservation {
            account_present: false,
            share_present: false,
            commitment: CommitmentObservation::Missing,
            rotation_active: false,
            attempt_id_fresh: !slot_occupied,
            ttl_secs,
        },
        Some(row) => InitiateObservation {
            account_present: true,
            share_present: row.share_present,
            commitment: row.commitment,
            rotation_active: row.rotation_active,
            attempt_id_fresh: !slot_occupied,
            ttl_secs,
        },
    }
}

/// `InitiateProofIo::observe`: the epoch the challenge is bound to, normalized
/// exactly as `observed_recovery_epoch` normalizes a missing row or column.
pub fn initiate_epoch(row: &Option<InitiateRowView>) -> i64 {
    let stored = match row {
        Some(row) => row.key_epoch,
        None => None,
    };
    crate::observed_recovery_epoch(stored)
}

/// `InitiateProofIo::store_challenge`: a written slot is `Stored`, a lost race
/// is `Lost`.
pub fn classify_store_challenge(written: bool) -> ChallengeStoreObservation {
    if written {
        ChallengeStoreObservation::Stored
    } else {
        ChallengeStoreObservation::Lost
    }
}

/// `RecoverProofIo::consume_attempt`: the removed state's own fields and the
/// binding comparison with the request.
pub fn classify_attempt(
    taken: &ProofAttemptTake,
    user: &String,
    attempt: &String,
) -> AttemptConsumptionObservation {
    match taken {
        ProofAttemptTake::Missing => AttemptConsumptionObservation::Missing,
        ProofAttemptTake::Corrupt => AttemptConsumptionObservation::Corrupt,
        ProofAttemptTake::Present(state) => AttemptConsumptionObservation::Present {
            user_matches: &state.user == user,
            attempt_matches: &state.attempt == attempt,
            key_epoch: state.key_epoch,
        },
    }
}

/// `RecoverProofIo::query_account`: every field is the live row's truth.
pub fn classify_proof_account(row: Option<ProofAccountRowView>) -> ProofAccountObservation {
    match row {
        None => ProofAccountObservation {
            account_present: false,
            account_epoch_active: false,
            commitment: CommitmentObservation::Missing,
            stored_epoch: None,
        },
        Some(row) => ProofAccountObservation {
            account_present: true,
            account_epoch_active: !row.rotation_active,
            commitment: row.commitment,
            stored_epoch: row.stored_epoch,
        },
    }
}

/// `RecoverProofIo::issue_grant`: a successful `set_ex` is `Stored`, any store
/// error is the `Failed` observation.
pub fn classify_grant_store(stored: bool) -> GrantStoreObservation {
    if stored {
        GrantStoreObservation::Stored
    } else {
        GrantStoreObservation::Failed
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

#[cfg(not(hax))]
use crate::redemption_store::{Param, Rendered};

/// The exact SQL text and store operation each statement has always used.
#[cfg(not(hax))]
pub fn render(stmt: &PossessionStmt) -> Rendered {
    match stmt {
        PossessionStmt::SelectInitiateAccount { user } => Rendered::Query {
            sql: "SELECT recovery_share, recovery_auth_hash, key_epoch, rekey_state
                 FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        PossessionStmt::ProofSlotExists { key } => Rendered::KvExists { key: key.clone() },
        PossessionStmt::StoreProofChallenge {
            key,
            value,
            ttl_secs,
            ..
        } => Rendered::KvSetNx {
            key: key.clone(),
            value: value.as_bytes().to_vec(),
            ttl_secs: *ttl_secs,
        },
        PossessionStmt::TakeProofAttempt { key } => Rendered::KvTake { key: key.clone() },
        PossessionStmt::SelectProofAccount { user } => Rendered::Query {
            sql: "SELECT recovery_auth_hash, key_epoch, rekey_state
                 FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        PossessionStmt::PutEnrollmentGrant {
            key,
            value,
            ttl_secs,
            ..
        } => Rendered::KvSetEx {
            key: key.clone(),
            value: value.as_bytes().to_vec(),
            ttl_secs: *ttl_secs,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn query(stmt: &PossessionStmt) -> (&'static str, Vec<Param>) {
        match render(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    // The expected strings are byte-for-byte copies of the literals the
    // handler used before the split (vela-server/src/recovery/possess.rs at
    // b9e3d67), including their line breaks and indentation.

    #[test]
    fn account_plans_render_the_historical_queries() {
        assert_eq!(
            query(&plan_initiate_account(s("me"))),
            (
                "SELECT recovery_share, recovery_auth_hash, key_epoch, rekey_state
                 FROM users WHERE id = ?",
                vec![Param::Text(s("me"))]
            )
        );
        assert_eq!(
            query(&plan_proof_account(s("me"))),
            (
                "SELECT recovery_auth_hash, key_epoch, rekey_state
                 FROM users WHERE id = ?",
                vec![Param::Text(s("me"))]
            )
        );
    }

    #[test]
    fn store_plans_render_the_historical_keys_and_values() {
        let attempt = ProofAttemptView {
            user: s("u"),
            attempt: s("a"),
            key_epoch: 7,
        };
        assert_eq!(
            render(&plan_proof_slot(s("k"))),
            Rendered::KvExists { key: s("k") }
        );
        assert_eq!(
            render(&plan_store_challenge(s("k"), s("{\"k\":7}"), attempt.clone(), 300)),
            Rendered::KvSetNx {
                key: s("k"),
                value: b"{\"k\":7}".to_vec(),
                ttl_secs: 300,
            }
        );
        assert_eq!(
            render(&plan_take_attempt(s("k"))),
            Rendered::KvTake { key: s("k") }
        );
        assert_eq!(
            render(&plan_issue_grant(
                s("g"),
                s("{\"key_epoch\":7}"),
                EnrollmentGrantView { key_epoch: 7 },
                600
            )),
            Rendered::KvSetEx {
                key: s("g"),
                value: b"{\"key_epoch\":7}".to_vec(),
                ttl_secs: 600,
            }
        );
    }

    #[test]
    fn classifiers_keep_the_historical_observations() {
        let row = InitiateRowView {
            share_present: true,
            commitment: CommitmentObservation::Present { len: 32 },
            key_epoch: Some(7),
            rotation_active: false,
        };
        let closed = classify_initiate(Some(row.clone()), false, 300);
        assert!(closed.account_present && closed.share_present && closed.attempt_id_fresh);
        assert_eq!(closed.commitment, CommitmentObservation::Present { len: 32 });
        assert_eq!(closed.ttl_secs, 300);
        let occupied = classify_initiate(Some(row.clone()), true, 300);
        assert!(!occupied.attempt_id_fresh);
        let absent = classify_initiate(None, false, 300);
        assert!(!absent.account_present && absent.attempt_id_fresh);
        assert_eq!(initiate_epoch(&Some(row.clone())), 7);
        assert_eq!(initiate_epoch(&Some(InitiateRowView { key_epoch: Some(0), ..row })), 1);
        assert_eq!(initiate_epoch(&None), 1);

        assert_eq!(
            classify_store_challenge(true),
            ChallengeStoreObservation::Stored
        );
        assert_eq!(classify_store_challenge(false), ChallengeStoreObservation::Lost);

        let state = ProofAttemptView {
            user: s("u"),
            attempt: s("a"),
            key_epoch: 7,
        };
        assert_eq!(
            classify_attempt(&ProofAttemptTake::Missing, &s("u"), &s("a")),
            AttemptConsumptionObservation::Missing
        );
        assert_eq!(
            classify_attempt(&ProofAttemptTake::Corrupt, &s("u"), &s("a")),
            AttemptConsumptionObservation::Corrupt
        );
        assert_eq!(
            classify_attempt(&ProofAttemptTake::Present(state.clone()), &s("u"), &s("a")),
            AttemptConsumptionObservation::Present {
                user_matches: true,
                attempt_matches: true,
                key_epoch: 7,
            }
        );
        assert_eq!(
            classify_attempt(&ProofAttemptTake::Present(state.clone()), &s("x"), &s("a")),
            AttemptConsumptionObservation::Present {
                user_matches: false,
                attempt_matches: true,
                key_epoch: 7,
            }
        );

        let account = ProofAccountRowView {
            commitment: CommitmentObservation::Present { len: 32 },
            stored_epoch: Some(7),
            rotation_active: false,
        };
        assert_eq!(
            classify_proof_account(Some(account)),
            ProofAccountObservation {
                account_present: true,
                account_epoch_active: true,
                commitment: CommitmentObservation::Present { len: 32 },
                stored_epoch: Some(7),
            }
        );
        let absent = classify_proof_account(None);
        assert!(!absent.account_present && !absent.account_epoch_active);

        assert_eq!(
            classify_grant_store(true),
            GrantStoreObservation::Stored
        );
        assert_eq!(
            classify_grant_store(false),
            GrantStoreObservation::Failed
        );
    }
}
