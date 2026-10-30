//! The SQL and key-value operations behind the four WebAuthn recovery
//! executors, split so the observation each method returns can be proved
//! against a store model (F-1).
//!
//! `InitiateIo` (`vela-server/src/recovery/initiate.rs`), `RecoverIo`
//! (`recovery/recover.rs`), `RegisterStartIo` and `RegisterFinishIo`
//! (`recovery/webauthn.rs`) are
//!
//! 1. pure `plan_*` functions from the method's inputs to typed statements
//!    ([`WebAuthnStmt`]);
//! 2. [`render`], from each statement to the exact SQL text, parameters or
//!    store key and value the handlers have always used (pinned byte for byte
//!    by the unit tests below);
//! 3. pure `classify_*` functions from the statement outcomes and row views to
//!    the observation the driver receives.
//!
//! The server runs the statement and classifies the outcome. hax extracts the
//! plans and classifiers; `proofs/fstar/webauthn-lemmas` proves them against a
//! model of the `users` row, the single-use WebAuthn attempt and registration
//! slots, the credential-id index and the enrollment-grant store, for every
//! starting state, every fault point and every ceremony result.
//!
//! Everything a WebAuthn ceremony produces (a challenge, a registration state,
//! an assertion result, an updated credential) stays an input: only the rows
//! and store keys the handlers touch are modelled here.

use crate::redemption_store::WriteOutcome;
use crate::webauthn_driver::{
    AuthAccountObservation, AuthAttemptConsumptionObservation, AuthFinishContextObservation,
    AuthStartObservation, ChallengeStoreObservation, CredentialPersistObservation,
    CredentialUniquenessObservation, CredentialUpdateStoreObservation, GrantStoreObservation,
    RegistrationStartObservation, RegistrationStateObservation, ShareDecodeObservation,
    StoredCredentialObservation,
};

/// One statement a WebAuthn executor method runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebAuthnStmt {
    /// The account row's `recovery_share` cell.
    SelectShare { user: String },
    /// The account row's stored recovery credential JSON.
    SelectCredential { user: String },
    /// Whether the exact user/attempt challenge slot is occupied.
    AuthSlotExists { key: String },
    /// Commit the drawn challenge envelope only while the exact slot is free.
    StoreAuthState {
        key: String,
        /// The serialized [`AuthStateView`]; [`render`] sends these bytes.
        value: String,
        state: AuthStateView,
        ttl_secs: u64,
    },
    /// The atomic single-use read-and-delete of the exact attempt envelope.
    TakeAuthState { key: String },
    /// The live account row the release decision is built from:
    /// `recovery_share`, `key_epoch`, `rekey_state`,
    /// `recovery_webauthn_cred_id` and `recovery_split_id`.
    SelectFinishAccount { user: String },
    /// Replace the stored credential only while the exact stored credential id
    /// is still current.
    UpdateCredentialIfCurrent {
        user: String,
        expected_credential_id: String,
        /// The serialized [`Passkey`](webauthn_rs) JSON.
        credential: String,
        credential_id: String,
    },
    /// The cross-account duplicate-credential lookup.
    SelectCredentialHolders { credential_id: String },
    /// Write a freshly registered credential onto the caller's row.
    PersistCredential {
        user: String,
        /// The serialized [`Passkey`](webauthn_rs) JSON.
        credential: String,
        credential_id: String,
    },
    /// Write the registration ceremony state, overwriting any current value.
    StoreRegistrationState {
        key: String,
        /// The serialized registration state; [`render`] sends these bytes.
        value: String,
        ttl_secs: u64,
    },
    /// The atomic single-use read-and-delete of the registration state.
    TakeRegistrationState { key: String },
    /// Store one single-use credential-bound enrollment grant.
    StoreCredentialGrant {
        key: String,
        /// The serialized grant; [`render`] sends exactly these bytes.
        value: String,
        grant: CredentialGrantView,
        ttl_secs: u64,
    },
}

/// What one attempt slot holds, as the plan writes it: the bindings the
/// redemption side later compares with the request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthStateView {
    pub user: String,
    pub attempt: String,
    pub credential_id: String,
}

/// One credential-bound enrollment grant as the store holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialGrantView {
    pub key_epoch: i64,
    pub credential_id: String,
    pub possession: bool,
}

/// The `recovery_share` read: whether the account exists and whether the
/// column is non-null.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareRowView {
    pub account_present: bool,
    pub share_present: bool,
}

/// The stored-credential read: whether the account exists and what the
/// credential cell decodes to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialRowView {
    pub account_present: bool,
    pub credential: StoredCredentialObservation,
}

/// The five cells of a live account row at release time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishAccountRowView {
    /// The stored share text; `None` is a NULL cell.
    pub share: Option<String>,
    pub stored_epoch: Option<i64>,
    pub rotation_active: bool,
    pub stored_credential_id: Option<String>,
    pub split_id: Option<String>,
}

/// What the atomic `get_del` of one attempt envelope observed. A store error
/// aborts the request before classification, so it is not a variant here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthStateTake {
    /// No live attempt matched the exact key.
    Missing,
    /// The envelope was removed but its JSON did not decode.
    Corrupt,
    /// The envelope was removed and decoded to these bindings.
    Present(AuthStateView),
}

/// What the atomic `get_del` of the registration state observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStateTake {
    /// No live state matched the exact key.
    Missing,
    /// The state was removed but its JSON did not decode.
    Corrupt,
    /// The state was removed and decoded.
    Present,
}

/// What one atomic `set_ex_nx` reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetNxOutcome {
    /// This call wrote the slot.
    Wrote,
    /// Another writer already occupied the slot; nothing was written.
    Occupied,
    /// The store call itself failed; nothing was written.
    Failed,
}

/// What one atomic `set_ex` reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetOutcome {
    /// This call wrote the key.
    Wrote,
    /// The store call itself failed; nothing was written.
    Failed,
}

/// Whether another account holds the credential id. `Unreadable` covers a
/// failed lookup and a holder row whose id cell does not read as text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialHolderView {
    /// A different account already holds this credential id.
    OtherAccount,
    /// Every holder row (possibly none) belongs to the caller.
    OnlyCaller,
    /// The lookup could not be read.
    Unreadable,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// The exact attempt-state key the store has always used.
#[cfg(not(hax))]
pub fn auth_state_key(user: &str, attempt: &str) -> String {
    format!("recovery:webauthn:auth:{user}:{attempt}")
}

/// The exact registration-state key the store has always used.
#[cfg(not(hax))]
pub fn registration_state_key(user: &str) -> String {
    format!("recovery:webauthn:register:{user}")
}

/// `InitiateIo::auth_start_observe` / `RecoverIo::auth_finish_context`: read
/// the account's `recovery_share` cell.
pub fn plan_select_share(user: String) -> WebAuthnStmt {
    WebAuthnStmt::SelectShare { user }
}

/// `InitiateIo::auth_start_observe` / `RecoverIo::auth_finish_context` /
/// `RegisterStartIo::registration_start_observe`: read the stored recovery
/// credential.
pub fn plan_select_credential(user: String) -> WebAuthnStmt {
    WebAuthnStmt::SelectCredential { user }
}

/// `InitiateIo::auth_start_observe`: probe the generated attempt slot.
pub fn plan_auth_slot(key: String) -> WebAuthnStmt {
    WebAuthnStmt::AuthSlotExists { key }
}

/// `InitiateIo::auth_start_store`: commit the drawn attempt envelope.
pub fn plan_store_auth_state(
    key: String,
    value: String,
    state: AuthStateView,
    ttl_secs: u64,
) -> WebAuthnStmt {
    WebAuthnStmt::StoreAuthState {
        key,
        value,
        state,
        ttl_secs,
    }
}

/// `RecoverIo::auth_finish_consume`: the atomic single-use take.
pub fn plan_take_auth_state(key: String) -> WebAuthnStmt {
    WebAuthnStmt::TakeAuthState { key }
}

/// `RecoverIo::auth_finish_account`: read the live row.
pub fn plan_finish_account(user: String) -> WebAuthnStmt {
    WebAuthnStmt::SelectFinishAccount { user }
}

/// `RecoverIo::auth_finish_update`: replace the stored credential only while
/// the exact stored id is still current.
pub fn plan_update_credential_if_current(
    user: String,
    expected_credential_id: String,
    credential: String,
    credential_id: String,
) -> WebAuthnStmt {
    WebAuthnStmt::UpdateCredentialIfCurrent {
        user,
        expected_credential_id,
        credential,
        credential_id,
    }
}

/// `RegisterFinishIo::registration_check_uniqueness`: the duplicate lookup.
pub fn plan_credential_holders(credential_id: String) -> WebAuthnStmt {
    WebAuthnStmt::SelectCredentialHolders { credential_id }
}

/// `RegisterFinishIo::registration_persist`: write the credential onto the
/// caller's row.
pub fn plan_persist_credential(
    user: String,
    credential: String,
    credential_id: String,
) -> WebAuthnStmt {
    WebAuthnStmt::PersistCredential {
        user,
        credential,
        credential_id,
    }
}

/// `RegisterStartIo::registration_start_store`: write the ceremony state.
pub fn plan_store_registration_state(key: String, value: String, ttl_secs: u64) -> WebAuthnStmt {
    WebAuthnStmt::StoreRegistrationState {
        key,
        value,
        ttl_secs,
    }
}

/// `RegisterFinishIo::registration_consume_state`: the atomic single-use take.
pub fn plan_take_registration_state(key: String) -> WebAuthnStmt {
    WebAuthnStmt::TakeRegistrationState { key }
}

/// `RecoverIo::auth_finish_store_grant`: store exactly one grant.
pub fn plan_store_credential_grant(
    key: String,
    value: String,
    grant: CredentialGrantView,
    ttl_secs: u64,
) -> WebAuthnStmt {
    WebAuthnStmt::StoreCredentialGrant {
        key,
        value,
        grant,
        ttl_secs,
    }
}

// ── Classification ─────────────────────────────────────────────────────────

/// `InitiateIo::auth_start_observe`: every field is the truth about the live
/// row, and the attempt slot is reported fresh exactly when it was empty.
pub fn classify_auth_start(
    share: &ShareRowView,
    credential: &CredentialRowView,
    slot_occupied: bool,
    ttl_secs: u64,
) -> AuthStartObservation {
    AuthStartObservation {
        account_present: share.account_present,
        share_present: share.share_present,
        credential: credential.credential,
        attempt_id_fresh: !slot_occupied,
        ttl_secs,
    }
}

/// `RecoverIo::auth_finish_context`: the same row facts plus whether the
/// request carried an attempt id.
pub fn classify_finish_context(
    share: &ShareRowView,
    credential: &CredentialRowView,
    attempt_id_present: bool,
) -> AuthFinishContextObservation {
    AuthFinishContextObservation {
        account_present: share.account_present,
        share_present: share.share_present,
        credential: credential.credential,
        attempt_id_present,
    }
}

/// `InitiateIo::auth_start_store`: this call wrote the slot, another writer
/// already held it, or the store failed.
pub fn classify_store_auth_state(outcome: &SetNxOutcome) -> ChallengeStoreObservation {
    match outcome {
        SetNxOutcome::Wrote => ChallengeStoreObservation::Stored,
        SetNxOutcome::Occupied => ChallengeStoreObservation::Lost,
        SetNxOutcome::Failed => ChallengeStoreObservation::StorageFailed,
    }
}

/// `RegisterStartIo::registration_start_store`: the overwriting write either
/// landed or failed.
pub fn classify_store_registration_state(outcome: &SetOutcome) -> ChallengeStoreObservation {
    match outcome {
        SetOutcome::Wrote => ChallengeStoreObservation::Stored,
        SetOutcome::Failed => ChallengeStoreObservation::StorageFailed,
    }
}

/// `RecoverIo::auth_finish_consume`: the removed envelope's own bindings and
/// the comparisons with the request and the live credential.
pub fn classify_take_auth_state(
    taken: &AuthStateTake,
    user: &String,
    attempt: &String,
    observed_credential_id: &String,
) -> AuthAttemptConsumptionObservation {
    match taken {
        AuthStateTake::Missing => AuthAttemptConsumptionObservation::Missing,
        AuthStateTake::Corrupt => AuthAttemptConsumptionObservation::Corrupt,
        AuthStateTake::Present(state) => AuthAttemptConsumptionObservation::Present {
            user_matches: &state.user == user,
            attempt_matches: &state.attempt == attempt,
            credential_matches: &state.credential_id == observed_credential_id,
        },
    }
}

/// `RecoverIo::auth_finish_update`: a `UPDATE` that changed a row is `Updated`;
/// a zero-row update is `Changed`.
pub fn classify_credential_update(rows: u64) -> CredentialUpdateStoreObservation {
    if rows > 0 {
        CredentialUpdateStoreObservation::Updated
    } else {
        CredentialUpdateStoreObservation::Changed
    }
}

/// `RecoverIo::auth_finish_account`: every field is the live row's truth,
/// compared with the challenge-bound credential id.
pub fn classify_finish_account(
    row: Option<FinishAccountRowView>,
    credential_id: &String,
) -> AuthAccountObservation {
    match row {
        None => AuthAccountObservation {
            account_present: false,
            account_epoch_active: false,
            share_present: false,
            stored_credential_matches: false,
            stored_epoch: None,
        },
        Some(row) => AuthAccountObservation {
            account_present: true,
            account_epoch_active: !row.rotation_active,
            share_present: row.share.is_some(),
            stored_credential_matches: row.stored_credential_id.as_ref() == Some(credential_id),
            stored_epoch: row.stored_epoch,
        },
    }
}

/// `RecoverIo::auth_finish_account`'s split-id side channel: the live row's
/// `recovery_split_id`, exactly as read.
pub fn finish_account_split(row: &Option<FinishAccountRowView>) -> Option<String> {
    match row {
        None => None,
        Some(row) => row.split_id.clone(),
    }
}

/// `RecoverIo::auth_finish_release`: the observed share text decoded, did not
/// decode, or the row carried no share (the handler aborts).
pub fn classify_share_release(share_present: bool, decoded: bool) -> Option<ShareDecodeObservation> {
    if !share_present {
        None
    } else if decoded {
        Some(ShareDecodeObservation::Decoded)
    } else {
        Some(ShareDecodeObservation::Corrupt)
    }
}

/// `RecoverIo::auth_finish_store_grant`: `Stored` exactly when the store wrote.
pub fn classify_grant_store(stored: bool) -> GrantStoreObservation {
    if stored {
        GrantStoreObservation::Stored
    } else {
        GrantStoreObservation::Failed
    }
}

/// `RegisterStartIo::registration_start_observe`: the row's own facts.
pub fn classify_registration_start(row: &CredentialRowView) -> RegistrationStartObservation {
    RegistrationStartObservation {
        account_present: row.account_present,
        credential: row.credential,
    }
}

/// `RegisterFinishIo::registration_consume_state`: the removed state decoded,
/// did not decode, or nothing matched.
pub fn classify_registration_state(taken: &RegistrationStateTake) -> RegistrationStateObservation {
    match taken {
        RegistrationStateTake::Missing => RegistrationStateObservation::Missing,
        RegistrationStateTake::Corrupt => RegistrationStateObservation::Corrupt,
        RegistrationStateTake::Present => RegistrationStateObservation::Present,
    }
}

/// `RegisterFinishIo::registration_check_uniqueness`: the lookup's own facts.
pub fn classify_uniqueness(view: &CredentialHolderView) -> CredentialUniquenessObservation {
    match view {
        CredentialHolderView::OtherAccount => CredentialUniquenessObservation::RegisteredElsewhere,
        CredentialHolderView::OnlyCaller => CredentialUniquenessObservation::Unique,
        CredentialHolderView::Unreadable => CredentialUniquenessObservation::LookupFailed,
    }
}

/// `RegisterFinishIo::registration_persist`: the serialized credential either
/// updated the caller's row, found no row, failed to serialize, or the write
/// itself failed.
pub fn classify_persist_credential(
    encoded: bool,
    outcomes: &[WriteOutcome],
) -> CredentialPersistObservation {
    if !encoded {
        return CredentialPersistObservation::EncodingFailed;
    }
    if outcomes.len() == 1 {
        match outcomes[0] {
            WriteOutcome::Applied(rows) => {
                if rows > 0 {
                    CredentialPersistObservation::Persisted
                } else {
                    CredentialPersistObservation::AccountGone
                }
            }
            WriteOutcome::Failed => CredentialPersistObservation::StorageFailed,
        }
    } else {
        CredentialPersistObservation::StorageFailed
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

#[cfg(not(hax))]
use crate::redemption_store::{Param, Rendered};

/// The exact SQL text and store operation each statement has always used.
#[cfg(not(hax))]
pub fn render(stmt: &WebAuthnStmt) -> Rendered {
    match stmt {
        WebAuthnStmt::SelectShare { user } => Rendered::Query {
            sql: "SELECT recovery_share FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        WebAuthnStmt::SelectCredential { user } => Rendered::Query {
            sql: "SELECT recovery_webauthn_credential FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        WebAuthnStmt::AuthSlotExists { key } => Rendered::KvExists { key: key.clone() },
        WebAuthnStmt::StoreAuthState {
            key,
            value,
            ttl_secs,
            ..
        } => Rendered::KvSetNx {
            key: key.clone(),
            value: value.as_bytes().to_vec(),
            ttl_secs: *ttl_secs,
        },
        WebAuthnStmt::TakeAuthState { key } => Rendered::KvTake { key: key.clone() },
        WebAuthnStmt::SelectFinishAccount { user } => Rendered::Query {
            sql: "SELECT recovery_share, key_epoch, rekey_state,
                        recovery_webauthn_cred_id, recovery_split_id
                 FROM users WHERE id = ?",
            params: vec![Param::Text(user.clone())],
        },
        WebAuthnStmt::UpdateCredentialIfCurrent {
            user,
            expected_credential_id,
            credential,
            credential_id,
        } => Rendered::Execute {
            sql: "UPDATE users SET recovery_webauthn_credential = ?, recovery_webauthn_cred_id = ?
             WHERE id = ? AND recovery_webauthn_cred_id = ?",
            params: vec![
                Param::Text(credential.clone()),
                Param::Text(credential_id.clone()),
                Param::Text(user.clone()),
                Param::Text(expected_credential_id.clone()),
            ],
        },
        WebAuthnStmt::SelectCredentialHolders { credential_id } => Rendered::Query {
            sql: "SELECT id FROM users WHERE recovery_webauthn_cred_id = ?",
            params: vec![Param::Text(credential_id.clone())],
        },
        WebAuthnStmt::PersistCredential {
            user,
            credential,
            credential_id,
        } => Rendered::Execute {
            sql: "UPDATE users SET recovery_webauthn_credential = ?, recovery_webauthn_cred_id = ? WHERE id = ?",
            params: vec![
                Param::Text(credential.clone()),
                Param::Text(credential_id.clone()),
                Param::Text(user.clone()),
            ],
        },
        WebAuthnStmt::StoreRegistrationState {
            key,
            value,
            ttl_secs,
        } => Rendered::KvSetEx {
            key: key.clone(),
            value: value.as_bytes().to_vec(),
            ttl_secs: *ttl_secs,
        },
        WebAuthnStmt::TakeRegistrationState { key } => Rendered::KvTake { key: key.clone() },
        WebAuthnStmt::StoreCredentialGrant {
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

    fn query(stmt: &WebAuthnStmt) -> (&'static str, Vec<Param>) {
        match render(stmt) {
            Rendered::Query { sql, params } => (sql, params),
            other => panic!("expected a read, got {other:?}"),
        }
    }

    fn exec(stmt: &WebAuthnStmt) -> (&'static str, Vec<Param>) {
        match render(stmt) {
            Rendered::Execute { sql, params } => (sql, params),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    // The expected strings are byte-for-byte copies of the literals the
    // handlers used before the split (vela-server/src/recovery/{initiate,
    // recover,webauthn}.rs at b9e3d67), including their line breaks and
    // indentation.

    #[test]
    fn account_reads_render_the_historical_queries() {
        assert_eq!(
            query(&plan_select_share(s("me"))),
            (
                "SELECT recovery_share FROM users WHERE id = ?",
                vec![Param::Text(s("me"))]
            )
        );
        assert_eq!(
            query(&plan_select_credential(s("me"))),
            (
                "SELECT recovery_webauthn_credential FROM users WHERE id = ?",
                vec![Param::Text(s("me"))]
            )
        );
        assert_eq!(
            query(&plan_finish_account(s("me"))),
            (
                "SELECT recovery_share, key_epoch, rekey_state,
                        recovery_webauthn_cred_id, recovery_split_id
                 FROM users WHERE id = ?",
                vec![Param::Text(s("me"))]
            )
        );
        assert_eq!(
            query(&plan_credential_holders(s("cred"))),
            (
                "SELECT id FROM users WHERE recovery_webauthn_cred_id = ?",
                vec![Param::Text(s("cred"))]
            )
        );
    }

    #[test]
    fn guarded_credential_writes_render_the_historical_statements() {
        assert_eq!(
            exec(&plan_update_credential_if_current(
                s("me"),
                s("cred"),
                s("{\"cred\":1}"),
                s("cred2")
            )),
            (
                "UPDATE users SET recovery_webauthn_credential = ?, recovery_webauthn_cred_id = ?
             WHERE id = ? AND recovery_webauthn_cred_id = ?",
                vec![
                    Param::Text(s("{\"cred\":1}")),
                    Param::Text(s("cred2")),
                    Param::Text(s("me")),
                    Param::Text(s("cred")),
                ]
            )
        );
        assert_eq!(
            exec(&plan_persist_credential(s("me"), s("{\"cred\":1}"), s("cred"))),
            (
                "UPDATE users SET recovery_webauthn_credential = ?, recovery_webauthn_cred_id = ? WHERE id = ?",
                vec![
                    Param::Text(s("{\"cred\":1}")),
                    Param::Text(s("cred")),
                    Param::Text(s("me")),
                ]
            )
        );
    }

    #[test]
    fn store_plans_render_the_historical_keys_and_values() {
        assert_eq!(
            auth_state_key("u", "a"),
            "recovery:webauthn:auth:u:a"
        );
        assert_eq!(
            registration_state_key("u"),
            "recovery:webauthn:register:u"
        );
        let state = AuthStateView {
            user: s("u"),
            attempt: s("a"),
            credential_id: s("c"),
        };
        assert_eq!(
            render(&plan_auth_slot(s("k"))),
            Rendered::KvExists { key: s("k") }
        );
        assert_eq!(
            render(&plan_store_auth_state(s("k"), s("{\"u\":1}"), state.clone(), 300)),
            Rendered::KvSetNx {
                key: s("k"),
                value: b"{\"u\":1}".to_vec(),
                ttl_secs: 300,
            }
        );
        assert_eq!(
            render(&plan_take_auth_state(s("k"))),
            Rendered::KvTake { key: s("k") }
        );
        assert_eq!(
            render(&plan_store_registration_state(s("r"), s("{}"), 300)),
            Rendered::KvSetEx {
                key: s("r"),
                value: b"{}".to_vec(),
                ttl_secs: 300,
            }
        );
        assert_eq!(
            render(&plan_take_registration_state(s("r"))),
            Rendered::KvTake { key: s("r") }
        );
        let grant = CredentialGrantView {
            key_epoch: 7,
            credential_id: s("c"),
            possession: false,
        };
        assert_eq!(
            render(&plan_store_credential_grant(
                s("g"),
                s("{\"key_epoch\":7}"),
                grant,
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
        let share = ShareRowView {
            account_present: true,
            share_present: true,
        };
        let credential = CredentialRowView {
            account_present: true,
            credential: StoredCredentialObservation::Present,
        };
        let start = classify_auth_start(&share, &credential, false, 300);
        assert!(start.account_present && start.share_present && start.attempt_id_fresh);
        assert_eq!(start.credential, StoredCredentialObservation::Present);
        assert_eq!(start.ttl_secs, 300);
        assert!(!classify_auth_start(&share, &credential, true, 300).attempt_id_fresh);
        let context = classify_finish_context(&share, &credential, true);
        assert!(context.attempt_id_present);

        assert_eq!(
            classify_store_auth_state(&SetNxOutcome::Wrote),
            ChallengeStoreObservation::Stored
        );
        assert_eq!(
            classify_store_auth_state(&SetNxOutcome::Occupied),
            ChallengeStoreObservation::Lost
        );
        assert_eq!(
            classify_store_auth_state(&SetNxOutcome::Failed),
            ChallengeStoreObservation::StorageFailed
        );
        assert_eq!(
            classify_store_registration_state(&SetOutcome::Wrote),
            ChallengeStoreObservation::Stored
        );
        assert_eq!(
            classify_store_registration_state(&SetOutcome::Failed),
            ChallengeStoreObservation::StorageFailed
        );

        let state = AuthStateView {
            user: s("u"),
            attempt: s("a"),
            credential_id: s("c"),
        };
        assert_eq!(
            classify_take_auth_state(&AuthStateTake::Missing, &s("u"), &s("a"), &s("c")),
            AuthAttemptConsumptionObservation::Missing
        );
        assert_eq!(
            classify_take_auth_state(&AuthStateTake::Corrupt, &s("u"), &s("a"), &s("c")),
            AuthAttemptConsumptionObservation::Corrupt
        );
        assert_eq!(
            classify_take_auth_state(&AuthStateTake::Present(state.clone()), &s("u"), &s("a"), &s("c")),
            AuthAttemptConsumptionObservation::Present {
                user_matches: true,
                attempt_matches: true,
                credential_matches: true,
            }
        );
        assert_eq!(
            classify_take_auth_state(&AuthStateTake::Present(state), &s("x"), &s("y"), &s("z")),
            AuthAttemptConsumptionObservation::Present {
                user_matches: false,
                attempt_matches: false,
                credential_matches: false,
            }
        );

        assert_eq!(
            classify_credential_update(1),
            CredentialUpdateStoreObservation::Updated
        );
        assert_eq!(
            classify_credential_update(0),
            CredentialUpdateStoreObservation::Changed
        );

        let row = FinishAccountRowView {
            share: Some(s("c2hhcmU=")),
            stored_epoch: Some(7),
            rotation_active: false,
            stored_credential_id: Some(s("c")),
            split_id: Some(s("sp")),
        };
        assert_eq!(
            classify_finish_account(Some(row.clone()), &s("c")),
            AuthAccountObservation {
                account_present: true,
                account_epoch_active: true,
                share_present: true,
                stored_credential_matches: true,
                stored_epoch: Some(7),
            }
        );
        assert!(!classify_finish_account(Some(row.clone()), &s("x")).stored_credential_matches);
        assert_eq!(finish_account_split(&Some(row)), Some(s("sp")));
        assert_eq!(finish_account_split(&None), None);
        let absent = classify_finish_account(None, &s("c"));
        assert!(!absent.account_present && !absent.account_epoch_active);

        assert_eq!(
            classify_share_release(true, true),
            Some(ShareDecodeObservation::Decoded)
        );
        assert_eq!(
            classify_share_release(true, false),
            Some(ShareDecodeObservation::Corrupt)
        );
        assert_eq!(classify_share_release(false, true), None);
        assert_eq!(
            classify_grant_store(true),
            GrantStoreObservation::Stored
        );
        assert_eq!(
            classify_grant_store(false),
            GrantStoreObservation::Failed
        );

        let registration = classify_registration_start(&credential);
        assert!(registration.account_present);
        assert_eq!(
            registration.credential,
            StoredCredentialObservation::Present
        );
        assert_eq!(
            classify_registration_state(&RegistrationStateTake::Missing),
            RegistrationStateObservation::Missing
        );
        assert_eq!(
            classify_registration_state(&RegistrationStateTake::Corrupt),
            RegistrationStateObservation::Corrupt
        );
        assert_eq!(
            classify_registration_state(&RegistrationStateTake::Present),
            RegistrationStateObservation::Present
        );

        assert_eq!(
            classify_uniqueness(&CredentialHolderView::OtherAccount),
            CredentialUniquenessObservation::RegisteredElsewhere
        );
        assert_eq!(
            classify_uniqueness(&CredentialHolderView::OnlyCaller),
            CredentialUniquenessObservation::Unique
        );
        assert_eq!(
            classify_uniqueness(&CredentialHolderView::Unreadable),
            CredentialUniquenessObservation::LookupFailed
        );

        use WriteOutcome::{Applied, Failed};
        assert_eq!(
            classify_persist_credential(true, &[Applied(1)]),
            CredentialPersistObservation::Persisted
        );
        assert_eq!(
            classify_persist_credential(true, &[Applied(0)]),
            CredentialPersistObservation::AccountGone
        );
        assert_eq!(
            classify_persist_credential(true, &[Failed]),
            CredentialPersistObservation::StorageFailed
        );
        assert_eq!(
            classify_persist_credential(false, &[Applied(1)]),
            CredentialPersistObservation::EncodingFailed
        );
    }
}
