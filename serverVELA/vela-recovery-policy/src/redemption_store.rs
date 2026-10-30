//! The SQL and key-value operations behind the recovered-device enrollment
//! executor, split so the observation each method returns can be proved
//! against a store model (F-1).
//!
//! `EnrollDeviceIo` in `vela-server/src/recovery/enroll_device.rs` is
//!
//! 1. a pure `plan_*` function from the method's inputs to typed statements
//!    ([`RedemptionStmt`]);
//! 2. [`render`], from each statement to the exact SQL text, parameters or
//!    store key and value the handler has always used (pinned byte for byte by
//!    the unit tests below);
//! 3. a pure `classify_*` function from the statement outcomes to the
//!    observation the driver receives.
//!
//! The server runs the statement and classifies the outcome. hax extracts the
//! plans and classifiers; `proofs/fstar/redemption-lemmas` proves them against
//! a model of the `users`, `devices` and enrollment-grant store, for every
//! starting state, every fault point and every starting grant.
//!
//! Every value is text (`String`): ids, keys, credential ids, hybrid keys and
//! timestamps are all bound as SQL text parameters. The only integer statement
//! parameter is the epoch.

use crate::driver::{
    AuthorityRecheckObservation, ConsumedGrantObservation, ConsumptionObservation, InsertObservation,
};

/// Which live authority the guarded insert requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantGuard {
    /// A credential-bound grant: the exact stored WebAuthn credential must
    /// still be current.
    Credential { credential_id: String },
    /// A possession grant: the staged RMS commitment must still be present
    /// and non-empty.
    Commitment,
}

/// One enrollment grant as the key-value store holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantView {
    pub key_epoch: i64,
    pub credential_id: String,
    pub possession: bool,
}

/// What the atomic `get_del` of one grant observed. A store error aborts the
/// request before classification, so it is not a variant here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantTake {
    /// No live grant matched the exact key.
    Missing,
    /// The live grant was removed and decoded.
    Taken(GrantView),
}

/// One statement an executor method runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedemptionStmt {
    /// Atomic read-and-delete of the exact enrollment-grant key.
    TakeGrant { key: String },
    /// The guarded recovered-device insert:
    /// `INSERT ... SELECT ... WHERE EXISTS (SELECT 1 FROM users ...)`.
    InsertDevice {
        device_id: String,
        user: String,
        device_name: String,
        device_type: String,
        hybrid_ek: String,
        hybrid_vk: String,
        created_at: String,
        epoch: i64,
        guard: GrantGuard,
    },
    /// The live authority recheck.
    SelectAuthority { user: String },
    /// Restore the exact consumed grant, overwriting any current value.
    PutGrant {
        key: String,
        /// The serialized grant value; [`render`] sends exactly these bytes.
        value: String,
        grant: GrantView,
    },
}

/// What one write statement returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// It ran; the number of rows it changed.
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

/// The cells of a `SelectAuthority` row: `recovery_webauthn_cred_id` and
/// `recovery_auth_hash`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRowView {
    pub credential_id: Option<String>,
    pub auth_hash: Option<String>,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// The exact enrollment-grant key the store has always used.
#[cfg(not(hax))]
pub fn grant_key(user: &str, grant: &str) -> String {
    format!("recovery:enroll_grant:{user}:{grant}")
}

/// `consume_grant`: the single-use `get_del` of the exact grant key.
pub fn plan_take_grant(key: String) -> RedemptionStmt {
    RedemptionStmt::TakeGrant { key }
}

/// `insert_device`: exactly one guarded device insert with the driver's
/// permit and the grant's guard.
pub fn plan_insert_device(
    device_id: String,
    user: String,
    device_name: String,
    device_type: String,
    hybrid_ek: String,
    hybrid_vk: String,
    created_at: String,
    epoch: i64,
    guard: GrantGuard,
) -> Vec<RedemptionStmt> {
    vec![RedemptionStmt::InsertDevice {
        device_id,
        user,
        device_name,
        device_type,
        hybrid_ek,
        hybrid_vk,
        created_at,
        epoch,
        guard,
    }]
}

/// `recheck_authority`: read the live credential and commitment columns.
pub fn plan_authority_read(user: String) -> RedemptionStmt {
    RedemptionStmt::SelectAuthority { user }
}

/// `restore_grant`: overwrite the exact grant key with the consumed grant.
pub fn plan_restore_grant(key: String, value: String, grant: GrantView) -> Vec<RedemptionStmt> {
    vec![RedemptionStmt::PutGrant { key, value, grant }]
}

// ── Classification ─────────────────────────────────────────────────────────

/// The single-use consumption: a missing grant is `Missing`; a removed grant
/// is `Present` with the value's own fields and the full-value equality with
/// the preflight permit.
pub fn classify_take(taken: &GrantTake, preflight: &GrantView) -> ConsumptionObservation {
    match taken {
        GrantTake::Missing => ConsumptionObservation::Missing,
        GrantTake::Taken(grant) => ConsumptionObservation::Present(ConsumedGrantObservation {
            key_epoch: grant.key_epoch,
            possession: grant.possession,
            matches_observed_grant: grant.key_epoch == preflight.key_epoch
                && grant.possession == preflight.possession
                && grant.credential_id == preflight.credential_id,
        }),
    }
}

/// The guarded insert: a positive row count is `Inserted`, zero is `Skipped`,
/// an error is `Failed`.
pub fn classify_insert(outcomes: &[WriteOutcome]) -> InsertObservation {
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => {
                if rows > 0 {
                    InsertObservation::Inserted
                } else {
                    InsertObservation::Skipped
                }
            }
            WriteOutcome::Failed => InsertObservation::Failed,
        }
    } else {
        InsertObservation::Failed
    }
}

/// The live authority recheck, in the handler's historical precedence.
pub fn classify_authority(
    outcome: &ReadOutcome<AuthorityRowView>,
    possession: bool,
    credential_id: &String,
) -> AuthorityRecheckObservation {
    match outcome {
        ReadOutcome::Failed => AuthorityRecheckObservation::QueryFailed,
        ReadOutcome::Row(None) => AuthorityRecheckObservation::AccountAbsent,
        ReadOutcome::Row(Some(row)) => {
            if possession {
                // `SelectAuthority`'s view already normalizes an empty
                // `recovery_auth_hash` to `None`, exactly as the insert guard
                // treats `''` as absent.
                match &row.auth_hash {
                    Some(_) => AuthorityRecheckObservation::StillRotating,
                    None => AuthorityRecheckObservation::CommitmentRevoked,
                }
            } else {
                match &row.credential_id {
                    Some(current) => {
                        if current == credential_id {
                            AuthorityRecheckObservation::StillRotating
                        } else {
                            AuthorityRecheckObservation::CredentialReplaced
                        }
                    }
                    None => AuthorityRecheckObservation::CredentialReplaced,
                }
            }
        }
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

/// One SQL parameter, in the wire type the handler binds.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Param {
    Text(String),
    Int(i64),
}

/// One statement as the database or the key-value store receives it.
#[cfg(not(hax))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rendered {
    /// A read (`query`).
    Query { sql: &'static str, params: Vec<Param> },
    /// A write (`execute`).
    Execute { sql: &'static str, params: Vec<Param> },
    /// The atomic read-and-delete of a key.
    KvTake { key: String },
    /// Set a key with its serialized value.
    KvPut { key: String, value: Vec<u8> },
}

/// The exact SQL text and parameters each statement has always used.
#[cfg(not(hax))]
pub fn render(stmt: &RedemptionStmt) -> Rendered {
    match stmt {
        RedemptionStmt::TakeGrant { key } => Rendered::KvTake { key: key.clone() },
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
            let (sql, guard_params) = match guard {
                GrantGuard::Credential { credential_id } => (
                    "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, NULL, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_webauthn_cred_id = ?
         )",
                    vec![Param::Text(credential_id.clone())],
                ),
                GrantGuard::Commitment => (
                    "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, NULL, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_auth_hash IS NOT NULL AND recovery_auth_hash <> ''
         )",
                    vec![],
                ),
            };
            Rendered::Execute {
                sql,
                params: vec![
                    Param::Text(device_id.clone()),
                    Param::Text(user.clone()),
                    Param::Text(device_name.clone()),
                    Param::Text(device_type.clone()),
                    Param::Text(hybrid_ek.clone()),
                    Param::Text(hybrid_vk.clone()),
                    Param::Text(created_at.clone()),
                    Param::Text(user.clone()),
                    Param::Int(*epoch),
                ]
                .into_iter()
                .chain(guard_params)
                .collect(),
            }
        }
        RedemptionStmt::SelectAuthority { user } => Rendered::Query {
            sql: "SELECT recovery_webauthn_cred_id, recovery_auth_hash FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        RedemptionStmt::PutGrant { key, value, .. } => Rendered::KvPut {
            key: key.clone(),
            value: value.as_bytes().to_vec(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn exec(stmt: &RedemptionStmt) -> (&'static str, Vec<Param>) {
        match render(stmt) {
            Rendered::Execute { sql, params } => (sql, params),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    fn query(stmt: &RedemptionStmt) -> (&'static str, Vec<Param>) {
        match render(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    // The expected strings are byte-for-byte copies of the literals the
    // handler used before the split (vela-server/src/recovery/enroll_device.rs
    // at b9e3d67), including their line breaks and indentation.

    #[test]
    fn grant_plan_renders_the_historical_key() {
        assert_eq!(grant_key("u", "g"), "recovery:enroll_grant:u:g");
        let plan = plan_take_grant(grant_key("u", "g"));
        assert_eq!(
            render(&plan),
            Rendered::KvTake { key: s("recovery:enroll_grant:u:g") }
        );
    }

    #[test]
    fn insert_plan_renders_the_historical_statement() {
        let credential = plan_insert_device(
            s("dev"),
            s("me"),
            s("name"),
            s("kind"),
            s("ek"),
            s("vk"),
            s("t"),
            7,
            GrantGuard::Credential { credential_id: s("cred") },
        );
        assert_eq!(credential.len(), 1);
        assert_eq!(
            exec(&credential[0]),
            (
                "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, NULL, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_webauthn_cred_id = ?
         )",
                vec![
                    Param::Text(s("dev")),
                    Param::Text(s("me")),
                    Param::Text(s("name")),
                    Param::Text(s("kind")),
                    Param::Text(s("ek")),
                    Param::Text(s("vk")),
                    Param::Text(s("t")),
                    Param::Text(s("me")),
                    Param::Int(7),
                    Param::Text(s("cred")),
                ]
            )
        );
        let commitment = plan_insert_device(
            s("dev"),
            s("me"),
            s("name"),
            s("kind"),
            s("ek"),
            s("vk"),
            s("t"),
            7,
            GrantGuard::Commitment,
        );
        assert_eq!(
            exec(&commitment[0]),
            (
                "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, NULL, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_auth_hash IS NOT NULL AND recovery_auth_hash <> ''
         )",
                vec![
                    Param::Text(s("dev")),
                    Param::Text(s("me")),
                    Param::Text(s("name")),
                    Param::Text(s("kind")),
                    Param::Text(s("ek")),
                    Param::Text(s("vk")),
                    Param::Text(s("t")),
                    Param::Text(s("me")),
                    Param::Int(7),
                ]
            )
        );
    }

    #[test]
    fn authority_and_restore_plans_render_the_historical_io() {
        assert_eq!(
            query(&plan_authority_read(s("me"))),
            (
                "SELECT recovery_webauthn_cred_id, recovery_auth_hash FROM users WHERE id = ?",
                vec![Param::Text(s("me"))]
            )
        );
        let grant = GrantView { key_epoch: 7, credential_id: s("c"), possession: false };
        let restore = plan_restore_grant(s("k"), s("{\"key_epoch\":7}"), grant);
        assert_eq!(restore.len(), 1);
        assert_eq!(
            render(&restore[0]),
            Rendered::KvPut { key: s("k"), value: b"{\"key_epoch\":7}".to_vec() }
        );
    }

    #[test]
    fn classifiers_keep_the_historical_observations() {
        use WriteOutcome::{Applied, Failed};
        let me = GrantView { key_epoch: 7, credential_id: s("cred"), possession: false };
        let other = GrantView { key_epoch: 7, credential_id: s("other"), possession: false };
        assert_eq!(classify_take(&GrantTake::Missing, &me), ConsumptionObservation::Missing);
        assert_eq!(
            classify_take(&GrantTake::Taken(me.clone()), &me),
            ConsumptionObservation::Present(ConsumedGrantObservation {
                key_epoch: 7,
                possession: false,
                matches_observed_grant: true,
            })
        );
        assert_eq!(
            classify_take(&GrantTake::Taken(other), &me),
            ConsumptionObservation::Present(ConsumedGrantObservation {
                key_epoch: 7,
                possession: false,
                matches_observed_grant: false,
            })
        );
        assert_eq!(
            classify_insert(&[Applied(1)]),
            InsertObservation::Inserted
        );
        assert_eq!(classify_insert(&[Applied(0)]), InsertObservation::Skipped);
        assert_eq!(classify_insert(&[Failed]), InsertObservation::Failed);

        let live = ReadOutcome::Row(Some(AuthorityRowView {
            credential_id: Some(s("cred")),
            auth_hash: Some(s("h")),
        }));
        assert_eq!(
            classify_authority(&live, false, &s("cred")),
            AuthorityRecheckObservation::StillRotating
        );
        assert_eq!(
            classify_authority(&live, false, &s("other")),
            AuthorityRecheckObservation::CredentialReplaced
        );
        assert_eq!(
            classify_authority(&live, true, &s("other")),
            AuthorityRecheckObservation::StillRotating
        );
        let rotating = ReadOutcome::Row(Some(AuthorityRowView {
            credential_id: Some(s("cred")),
            auth_hash: None,
        }));
        assert_eq!(
            classify_authority(&rotating, true, &s("cred")),
            AuthorityRecheckObservation::CommitmentRevoked
        );
        assert_eq!(
            classify_authority(&ReadOutcome::Row(None), true, &s("cred")),
            AuthorityRecheckObservation::AccountAbsent
        );
        assert_eq!(
            classify_authority(&ReadOutcome::Failed, true, &s("cred")),
            AuthorityRecheckObservation::QueryFailed
        );
    }
}
