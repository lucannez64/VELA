//! Bounded conformance of the real `DELETE /account` handler and database
//! against an independent account-deletion state machine.
//!
//! Every command sequence up to `VELA_DELETION_MODEL_DEPTH` (default 3) over a
//! fixed alphabet runs against the reference model and against the real Axum
//! router backed by the real Turso schema and sled store. After every step the
//! test compares the HTTP status and every observable view a client has:
//!
//! - `GET /vault/sync` (token liveness + chunk ids),
//! - `GET /devices` (enrolled devices),
//! - `GET /share/inbox` and `GET /share/linked` (cross-account shares),
//! - `GET /sends` (one-off share links),
//! - `GET /recovery/share` (recovery publication).
//!
//! The reference model is the account lifecycle the server documents:
//!
//! - an account owns its user row, its devices, its vault chunks and ORAM
//!   buckets, its recovery record, the send links it created, the web sessions
//!   it approved, and both ends of every share it sent or received;
//! - deleting it removes all of that atomically from the client's point of
//!   view: the deleted token, and any correctly signed token minted for the
//!   same user id afterwards, is refused everywhere; the device cannot log in;
//!   deleting twice is refused (the second request fails at authentication
//!   because the user row is already gone);
//! - the other account keeps its own rows and its own send links, but loses
//!   shares in which the deleted account was either sender or recipient.
//!
//! ## Residue scan (the point of this test)
//!
//! Immediately after every successful delete, the test queries the database
//! directly and asserts that **no row in any user-scoped table** still
//! references the deleted user id or any of its device ids. The tables and the
//! columns that can hold an account/device reference are enumerated explicitly
//! in `USER_SCOPED`; the set of tables is also compared against
//! `sqlite_master`, so a new user-scoped table that this test does not know
//! about makes it fail rather than silently going unchecked.
//!
//! The sled store is checked the same way, with two documented exceptions:
//! `device:revoked:{device_id}` (and `jti:revoked:*`) are *revocation
//! tombstones* deliberately retained so a stolen token stays dead for its
//! lifetime, and `rl:*` keys are rate-limit counters keyed by user/device id
//! that hold no account data and expire. Any other key or sled tree that still
//! names the deleted account or device fails the test.
//!
//! ## Not covered
//!
//! Backups, replicas and point-in-time recovery; a crash or error between the
//! individual SQL statements of the delete (the handler is a sequence of
//! statements, not one transaction — this test observes only the completed
//! operation); concurrency with in-flight requests from another device; clock
//! and TTL expiry; and WebAuthn recovery credentials (no command drives them
//! here — the users row that stores them is covered by the residue scan).
//! This is bounded executable evidence, not a proof.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use vela_crypto::signing::{
    auth_message, generate_keypair, share_ek_binding_message, sign, HybridSigningKey,
};
use vela_server::sqldb::{Db as _, TursoValue};

mod helpers;

const DEFAULT_DEPTH: usize = 3;

fn depth() -> usize {
    std::env::var("VELA_DELETION_MODEL_DEPTH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_DEPTH)
}

/// Every table in the schema that can hold an account or device reference.
///
/// `users.id` is the account itself; `devices.id` is the device itself. The
/// remaining columns are the only places another row can name a user or device
/// (`last_writer`, `enrolled_by`, `revoked_by` are device ids; `approved_by` is
/// a user id). A new table that holds account data must be added here, and the
/// `sqlite_master` check below fails until it is.
const USER_SCOPED: &[(&str, &[&str])] = &[
    ("users", &["id"]),
    ("devices", &["id", "user_id", "enrolled_by", "revoked_by"]),
    ("vault_chunks", &["user_id", "last_writer"]),
    ("oram_buckets", &["user_id", "last_writer"]),
    ("share_inbox", &["sender_user_id", "recipient_user_id"]),
    ("shared_items", &["sender_user_id", "recipient_user_id"]),
    (
        "web_sessions",
        &["user_id", "approver_user_id", "approved_by"],
    ),
    ("sends", &["owner_user_id"]),
];

const KNOWN_TABLES: [&str; 8] = [
    "devices",
    "oram_buckets",
    "sends",
    "share_inbox",
    "shared_items",
    "users",
    "vault_chunks",
    "web_sessions",
];

/// `vela_share_policy` / `vela_enrollment_policy` hybrid key sizes.
const SHARE_EK_LEN: usize = 1568 + 32;
const DEVICE_EK_LEN: usize = 1568 + 32;
const EPHEMERAL_PK_LEN: usize = 1568 + 32;

// ── Command alphabet ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum User {
    Alice,
    Bob,
}

const USERS: [User; 2] = [User::Alice, User::Bob];

impl User {
    fn name(self) -> &'static str {
        match self {
            User::Alice => "Alice",
            User::Bob => "Bob",
        }
    }

    fn index(self) -> u8 {
        match self {
            User::Alice => 0,
            User::Bob => 1,
        }
    }

    fn other(self) -> User {
        match self {
            User::Alice => User::Bob,
            User::Bob => User::Alice,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Command {
    /// Create one vault chunk with `If-Match: 0` (a fresh client-chosen id).
    WriteVault(User),
    /// Register (or refresh) the user's share key with a device-signed binding.
    RegisterEk(User),
    /// Send a share; it lands in the recipient's inbox and in both linked views.
    Share { from: User, to: User },
    /// Create a one-off send link owned by the user.
    SendLink(User),
    /// Stage and finalize a recovery share.
    SetupRecovery(User),
    /// `DELETE /account` with the user's device token.
    Delete(User),
    /// Use the user's original token on `GET /vault/sync`.
    UseToken(User),
    /// Obtain a fresh challenge and log the device in again.
    Relogin(User),
}

impl Command {
    fn kind(self) -> &'static str {
        match self {
            Command::WriteVault(_) => "WriteVault",
            Command::RegisterEk(_) => "RegisterEk",
            Command::Share { .. } => "Share",
            Command::SendLink(_) => "SendLink",
            Command::SetupRecovery(_) => "SetupRecovery",
            Command::Delete(_) => "Delete",
            Command::UseToken(_) => "UseToken",
            Command::Relogin(_) => "Relogin",
        }
    }
}

fn alphabet() -> Vec<Command> {
    use Command::*;
    use User::*;
    vec![
        WriteVault(Alice),
        WriteVault(Bob),
        RegisterEk(Alice),
        RegisterEk(Bob),
        Share {
            from: Alice,
            to: Bob,
        },
        Share {
            from: Bob,
            to: Alice,
        },
        SendLink(Alice),
        SendLink(Bob),
        SetupRecovery(Alice),
        Delete(Alice),
        Delete(Bob),
        UseToken(Alice),
        Relogin(Alice),
    ]
}

/// Every sequence of length `0..=depth` over the alphabet.
fn sequences(depth: usize) -> Vec<Vec<Command>> {
    let alphabet = alphabet();
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for prefix in &frontier {
            for command in &alphabet {
                let mut sequence = prefix.clone();
                sequence.push(*command);
                next.push(sequence);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

// ── Reference model ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Share {
    /// Creation order; stable for the lifetime of the trace.
    slot: usize,
    sender: User,
    recipient: User,
    /// Bytes of the capsule this trace sent (kept as a printable label).
    capsule: String,
}

#[derive(Clone, Debug)]
struct UserModel {
    alive: bool,
    share_ek: bool,
    vault: BTreeSet<String>,
    sends: BTreeSet<usize>,
    recovery: Option<String>,
}

impl UserModel {
    fn new() -> Self {
        Self {
            alive: true,
            share_ek: false,
            vault: BTreeSet::new(),
            sends: BTreeSet::new(),
            recovery: None,
        }
    }
}

#[derive(Clone, Debug)]
struct Model {
    users: BTreeMap<User, UserModel>,
    shares: Vec<Share>,
    /// Monotonic share slot counter. Slots are never reused after a delete, so
    /// the model and the real id map cannot drift if the alphabet grows.
    next_share_slot: usize,
}

impl Model {
    fn new() -> Self {
        Self {
            users: USERS.iter().map(|u| (*u, UserModel::new())).collect(),
            shares: Vec::new(),
            next_share_slot: 0,
        }
    }

    fn apply(&mut self, command: Command, step: usize) -> StatusCode {
        match command {
            Command::WriteVault(user) => {
                if !self.users[&user].alive {
                    return StatusCode::UNAUTHORIZED;
                }
                self.users
                    .get_mut(&user)
                    .unwrap()
                    .vault
                    .insert(format!("chunk-s{step}-{}", user.name()));
                StatusCode::OK
            }
            Command::RegisterEk(user) => {
                if !self.users[&user].alive {
                    return StatusCode::UNAUTHORIZED;
                }
                self.users.get_mut(&user).unwrap().share_ek = true;
                StatusCode::OK
            }
            Command::Share { from, to } => {
                // Authentication of the sender happens before the recipient is
                // looked up, so a dead sender is 401 and a dead/unregistered
                // recipient is the indistinguishable 404.
                if !self.users[&from].alive {
                    return StatusCode::UNAUTHORIZED;
                }
                if !self.users[&to].alive || !self.users[&to].share_ek {
                    return StatusCode::NOT_FOUND;
                }
                let slot = self.next_share_slot;
                self.next_share_slot += 1;
                self.shares.push(Share {
                    slot,
                    sender: from,
                    recipient: to,
                    capsule: format!("capsule-s{step}"),
                });
                StatusCode::OK
            }
            Command::SendLink(user) => {
                if !self.users[&user].alive {
                    return StatusCode::UNAUTHORIZED;
                }
                self.users.get_mut(&user).unwrap().sends.insert(step);
                StatusCode::OK
            }
            Command::SetupRecovery(user) => {
                if !self.users[&user].alive {
                    return StatusCode::UNAUTHORIZED;
                }
                let state = self.users.get_mut(&user).unwrap();
                if state.recovery.is_some() {
                    // The handler refuses to stage a second split for the same
                    // epoch once one is finalized.
                    return StatusCode::CONFLICT;
                }
                state.recovery = Some(format!("recovery-share-s{step}"));
                StatusCode::OK
            }
            Command::Delete(user) => {
                if !self.users[&user].alive {
                    // The middleware rejects the token before the handler's
                    // own "account not found" branch can run.
                    return StatusCode::UNAUTHORIZED;
                }
                let state = self.users.get_mut(&user).unwrap();
                state.alive = false;
                state.share_ek = false;
                state.vault.clear();
                state.sends.clear();
                state.recovery = None;
                // Both directions of a share are removed: the deleted account
                // is a party to the capsule in either role.
                self.shares
                    .retain(|share| share.sender != user && share.recipient != user);
                StatusCode::OK
            }
            Command::UseToken(user) => {
                if self.users[&user].alive {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
            Command::Relogin(user) => {
                if self.users[&user].alive {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
        }
    }

    fn inbox(&self, user: User) -> BTreeSet<(usize, User, String)> {
        self.shares
            .iter()
            .filter(|share| share.recipient == user)
            .map(|share| (share.slot, share.sender, share.capsule.clone()))
            .collect()
    }

    fn linked(&self, user: User) -> BTreeSet<(usize, User, User, String)> {
        self.shares
            .iter()
            .filter(|share| share.sender == user || share.recipient == user)
            .map(|share| {
                (
                    share.slot,
                    share.sender,
                    share.recipient,
                    share.capsule.clone(),
                )
            })
            .collect()
    }
}

// ── Real system ─────────────────────────────────────────────────────────────

struct Party {
    user_id: Uuid,
    device_id: Uuid,
    signing_key: HybridSigningKey,
    token: String,
    ek_registrations: u32,
}

struct Real {
    app: Router,
    state: vela_server::state::AppState,
    parties: BTreeMap<User, Party>,
    /// Server-issued share id -> model slot.
    share_slots: BTreeMap<Uuid, usize>,
    /// Server-issued send id -> model slot.
    send_slots: BTreeMap<Uuid, usize>,
    next_share_slot: usize,
    /// Accounts this trace has successfully deleted, so the "survivor is
    /// unaffected" probe does not demand that an already-deleted account work.
    deleted: BTreeSet<User>,
    /// Tables that held a row for a deleted account immediately before a
    /// successful delete. Merged by the trace runner to prove the residue scan
    /// was not vacuous.
    coverage: BTreeSet<&'static str>,
}

static NEXT_IP: AtomicU32 = AtomicU32::new(1);

/// A distinct source address per request keeps per-IP limits out of the way.
fn fresh_ip() -> ConnectInfo<SocketAddr> {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed);
    let [_, b, c, d] = n.to_be_bytes();
    ConnectInfo(SocketAddr::from(([10, b, c, d.max(1)], 40000)))
}

fn token_for(state: &vela_server::state::AppState, user_id: Uuid, device_id: Uuid) -> String {
    let ts = vela_server::auth::token::TokenService::new(
        state.paseto_sk.clone(),
        state.paseto_pk.clone(),
    );
    let plan = match vela_session_policy::plan_device_token(chrono::Utc::now().timestamp(), None) {
        vela_session_policy::TokenDecision::Issue(plan) => plan,
        vela_session_policy::TokenDecision::Reject => unreachable!(),
    };
    ts.issue_from_plan(user_id, device_id, plan).unwrap().0
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(fresh_ip());
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

impl Real {
    async fn new(state: &vela_server::state::AppState, app: Router) -> Self {
        let mut parties = BTreeMap::new();
        for user in USERS {
            parties.insert(user, new_party(state, user).await);
        }

        let real = Self {
            app,
            state: state.clone(),
            parties,
            share_slots: BTreeMap::new(),
            send_slots: BTreeMap::new(),
            next_share_slot: 0,
            deleted: BTreeSet::new(),
            coverage: BTreeSet::new(),
        };

        // ORAM rows have no cheap public write command in this alphabet; seed
        // one per account so the residue scan really checks the table.
        for user in USERS {
            let party = &real.parties[&user];
            let now = chrono::Utc::now().to_rfc3339();
            state
                .sqldb
                .execute(
                    "INSERT INTO oram_buckets
                        (user_id, tree_id, bucket_index, version, lamport_clock,
                         last_writer, ciphertext, epoch, created_at, updated_at)
                     VALUES (?, 'seeded-tree', 0, 1, 1, ?, ?, 1, ?, ?)",
                    vec![
                        TursoValue::Text(party.user_id.to_string()),
                        TursoValue::Text(party.device_id.to_string()),
                        TursoValue::Text(B64.encode(b"seeded-oram-bucket")),
                        TursoValue::Text(now.clone()),
                        TursoValue::Text(now),
                    ],
                )
                .await
                .unwrap();
        }

        // A browser login in flight against each account. It is unauthenticated
        // to start, so it is exactly the kind of row that can outlive the
        // account if the delete does not consider `approver_user_id`.
        for user in USERS {
            let party = &real.parties[&user];
            let (status, _) = call(
                &real.app,
                "POST",
                "/web-session/start",
                None,
                Some(json!({
                    "ephemeral_pk": B64.encode([7u8; EPHEMERAL_PK_LEN]),
                    "link_nonce": B64.encode([8u8; 32]),
                    "poll_secret_hash": B64.encode([9u8; 32]),
                    "approver_user_id": party.user_id,
                })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "seeding a pending web session failed"
            );
        }

        real
    }

    fn token(&self, user: User) -> &str {
        &self.parties[&user].token
    }

    fn user_of(&self, id: Uuid) -> User {
        *self
            .parties
            .iter()
            .find(|(_, party)| party.user_id == id)
            .unwrap_or_else(|| panic!("the server named a user outside this trace: {id}"))
            .0
    }

    fn share_slot(&self, id: Uuid) -> usize {
        *self
            .share_slots
            .get(&id)
            .unwrap_or_else(|| panic!("the server listed a share id the test never created: {id}"))
    }

    fn send_slot(&self, id: Uuid) -> usize {
        *self
            .send_slots
            .get(&id)
            .unwrap_or_else(|| panic!("the server listed a send id the test never created: {id}"))
    }

    async fn apply(&mut self, command: Command, step: usize) -> StatusCode {
        match command {
            Command::WriteVault(user) => {
                // `PUT /vault/chunk/:id` takes raw bytes, not JSON.
                let id = format!("chunk-s{step}-{}", user.name());
                let request = Request::builder()
                    .method("PUT")
                    .uri(format!("/vault/chunk/{id}"))
                    .extension(fresh_ip())
                    .header("Authorization", format!("Bearer {}", self.token(user)))
                    .header("if-match", "0")
                    .header("x-lamport-clock", "1")
                    .body(Body::from(format!("chunk-body-s{step}").into_bytes()))
                    .unwrap();
                let response = self.app.clone().oneshot(request).await.unwrap();
                response.status()
            }
            Command::RegisterEk(user) => {
                let party = self.parties.get_mut(&user).unwrap();
                party.ek_registrations += 1;
                let n = party.ek_registrations;
                // Canonical, strictly increasing, in the past.
                let signed_at = format!("2026-01-01T00:{:02}:{:02}Z", (n / 60) % 60, n % 60);
                let share_ek = [user.index() + 7; SHARE_EK_LEN];
                let message = share_ek_binding_message(&share_ek, &signed_at);
                let signature = sign(&party.signing_key, &message).unwrap();
                let body = json!({
                    "share_ek": B64.encode(share_ek),
                    "device_id": party.device_id,
                    "signed_at": signed_at,
                    "signature": B64.encode(signature.to_bytes()),
                });
                call(
                    &self.app,
                    "PUT",
                    "/share/my-ek",
                    Some(&party.token),
                    Some(body),
                )
                .await
                .0
            }
            Command::Share { from, to } => {
                let capsule = format!("capsule-s{step}");
                let body = json!({
                    "recipient_user_id": self.parties[&to].user_id,
                    "capsule": B64.encode(capsule.as_bytes()),
                });
                let (status, value) = call(
                    &self.app,
                    "POST",
                    "/share/send",
                    Some(self.token(from)),
                    Some(body),
                )
                .await;
                if status == StatusCode::OK {
                    let id: Uuid = serde_json::from_value(value["share_id"].clone()).unwrap();
                    self.share_slots.insert(id, self.next_share_slot);
                    self.next_share_slot += 1;
                }
                status
            }
            Command::SendLink(user) => {
                let body = json!({
                    "ciphertext": B64.encode(format!("send-body-s{step}").as_bytes()),
                    "ttl_secs": 3600,
                    "label": format!("send-s{step}"),
                });
                let (status, value) = call(
                    &self.app,
                    "POST",
                    "/send",
                    Some(self.token(user)),
                    Some(body),
                )
                .await;
                if status == StatusCode::OK {
                    let id: Uuid = serde_json::from_value(value["id"].clone()).unwrap();
                    self.send_slots.insert(id, step);
                }
                status
            }
            Command::SetupRecovery(user) => {
                let split_id = Uuid::new_v4();
                let body = json!({
                    "share": B64.encode(format!("recovery-share-s{step}").as_bytes()),
                    "key_epoch": 1,
                    "split_id": split_id,
                    "possession_hash": B64.encode([3u8; 32]),
                });
                let (status, _) = call(
                    &self.app,
                    "PUT",
                    "/recovery/share",
                    Some(self.token(user)),
                    Some(body),
                )
                .await;
                if status != StatusCode::OK {
                    return status;
                }
                call(
                    &self.app,
                    "POST",
                    "/recovery/share/finalize",
                    Some(self.token(user)),
                    Some(json!({ "key_epoch": 1, "split_id": split_id })),
                )
                .await
                .0
            }
            Command::Delete(user) => self.delete(user, step).await,
            Command::UseToken(user) => {
                call(
                    &self.app,
                    "GET",
                    "/vault/sync",
                    Some(self.token(user)),
                    None,
                )
                .await
                .0
            }
            Command::Relogin(user) => self.relogin(user).await,
        }
    }

    async fn relogin(&self, user: User) -> StatusCode {
        let party = &self.parties[&user];
        let (status, value) = call(&self.app, "GET", "/auth/challenge", None, None).await;
        assert_eq!(status, StatusCode::OK, "GET /auth/challenge failed");
        let challenge = value["challenge"].as_str().unwrap();
        let challenge_bytes = B64.decode(challenge).unwrap();
        let message = auth_message(&party.device_id.to_string(), &challenge_bytes);
        let signature = sign(&party.signing_key, &message).unwrap();
        let body = json!({
            "device_id": party.device_id,
            "challenge": challenge,
            "signature": B64.encode(signature.to_bytes()),
        });
        call(&self.app, "POST", "/auth/verify", None, Some(body))
            .await
            .0
    }

    /// `DELETE /account` plus the properties that must hold immediately after
    /// a completed delete.
    async fn delete(&mut self, user: User, step: usize) -> StatusCode {
        let (token, user_id, device_id) = {
            let party = &self.parties[&user];
            (party.token.clone(), party.user_id, party.device_id)
        };
        let ids = [user_id.to_string(), device_id.to_string()];

        let before = self.counts(&ids).await;
        let (status, body) = call(&self.app, "DELETE", "/account", Some(&token), None).await;
        if status != StatusCode::OK {
            return status;
        }
        assert_eq!(body["deleted"], Value::Bool(true));
        assert_eq!(body["user_id"], Value::String(user_id.to_string()));

        for (table, _) in USER_SCOPED {
            let had_row = before.iter().any(|((t, _), n)| t == table && *n > 0);
            if had_row {
                self.coverage.insert(table);
            }
        }

        // 1. No residual row anywhere, and no unknown table that could hide one.
        self.assert_no_unknown_tables().await;
        let after = self.counts(&ids).await;
        for ((table, column), n) in &after {
            assert_eq!(
                *n,
                0,
                "account {} was deleted but {table}.{column} still has {n} row(s) referencing it \
                 after step {step} of the trace (user {user_id}, device {device_id})",
                user.name()
            );
        }

        // 2. No token of the account works anywhere: the original token, a
        // freshly minted token for the same device, and one for a device id
        // that never existed but belongs to the same user id.
        for (method, uri, body) in [
            ("GET", "/vault/sync", None),
            ("GET", "/devices", None),
            ("GET", "/share/inbox", None),
            ("GET", "/share/linked", None),
            ("GET", "/sends", None),
            ("GET", "/recovery/share", None),
            (
                "POST",
                "/send",
                Some(json!({ "ciphertext": B64.encode(b"probe") })),
            ),
            ("DELETE", "/account", None),
        ] {
            let (status, value) = call(&self.app, method, uri, Some(&token), body).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {uri} accepted a deleted account's token"
            );
            assert_eq!(value["error"], "unauthorized", "{method} {uri} error body");
        }
        for (label, candidate_device) in [
            ("same device", device_id),
            ("unseen device", Uuid::new_v4()),
        ] {
            let fresh = token_for(&self.state, user_id, candidate_device);
            let (status, _) = call(&self.app, "GET", "/vault/sync", Some(&fresh), None).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "a correctly signed token for the deleted account ({label}) was accepted"
            );
        }

        // 3. The device cannot log in again.
        assert_eq!(
            self.relogin(user).await,
            StatusCode::UNAUTHORIZED,
            "a deleted account's device completed a challenge/verify login"
        );

        // 4. Deleting twice is refused consistently.
        let (again, value) = call(&self.app, "DELETE", "/account", Some(&token), None).await;
        assert_eq!(
            again,
            StatusCode::UNAUTHORIZED,
            "second delete was not refused"
        );
        assert_eq!(value["error"], "unauthorized", "second delete error body");

        // 5. The sled store keeps only revocation tombstones and rate-limit
        // counters for this account/device.
        self.assert_sled_clean(&ids);

        self.deleted.insert(user);

        // 6. The other account still works, unless the trace already deleted
        // it too.
        let survivor = user.other();
        if !self.deleted.contains(&survivor) {
            let (survivor_status, _) = call(
                &self.app,
                "GET",
                "/vault/sync",
                Some(self.token(survivor)),
                None,
            )
            .await;
            assert_eq!(
                survivor_status,
                StatusCode::OK,
                "deleting {} broke {}",
                user.name(),
                survivor.name()
            );
        }

        status
    }

    /// Every user/device reference count in every user-scoped column.
    async fn counts(&self, ids: &[String; 2]) -> BTreeMap<(&'static str, &'static str), i64> {
        let mut out = BTreeMap::new();
        for (table, columns) in USER_SCOPED {
            for column in *columns {
                let sql = format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?");
                for id in ids {
                    let rows = self
                        .state
                        .sqldb
                        .query(&sql, vec![TursoValue::Text(id.clone())])
                        .await
                        .unwrap();
                    let n = rows.first().and_then(|row| row.i64(0)).unwrap_or(0);
                    *out.entry((*table, *column)).or_insert(0) += n;
                }
            }
        }
        out
    }

    async fn table_set(&self) -> BTreeSet<String> {
        let rows = self
            .state
            .sqldb
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'table'",
                vec![],
            )
            .await
            .unwrap();
        rows.iter()
            .filter_map(|row| row.text(0))
            .filter(|name| !name.starts_with("sqlite_"))
            .map(str::to_string)
            .collect()
    }

    async fn assert_no_unknown_tables(&self) {
        let actual = self.table_set().await;
        let known: BTreeSet<&str> = KNOWN_TABLES.iter().copied().collect();
        let unknown: Vec<&String> = actual
            .iter()
            .filter(|name| !known.contains(name.as_str()))
            .collect();
        assert!(
            unknown.is_empty(),
            "the schema has table(s) this residue check does not know about: {unknown:?}. \
             Add them to USER_SCOPED (or prove they hold no account data) before trusting \
             account deletion."
        );
        let missing: Vec<&str> = known
            .iter()
            .copied()
            .filter(|name| !actual.contains(*name))
            .collect();
        assert!(
            missing.is_empty(),
            "expected tables missing from sqlite_master: {missing:?}"
        );
    }

    /// Sled keys are raw strings. Only two kinds may still name the deleted
    /// account or device: revocation tombstones (which are what keep the stolen
    /// tokens dead) and `rl:*` rate-limit counters (no account data, TTL'd).
    fn assert_sled_clean(&self, ids: &[String; 2]) {
        let user_id = &ids[0];
        let device_id = &ids[1];
        let db = self.state.store.inner();

        for name in db.tree_names() {
            let name = String::from_utf8_lossy(&name).to_string();
            assert!(
                !name.contains(user_id) && !name.contains(device_id),
                "a sled tree still names the deleted account/device: {name}"
            );
        }

        let check_key = |key: &str| {
            if key.contains(user_id) {
                assert!(
                    key.starts_with("rl:"),
                    "sled key still names the deleted account: {key}"
                );
            }
            if key.contains(device_id) {
                assert!(
                    key.starts_with("rl:") || key == format!("device:revoked:{device_id}"),
                    "sled key still names the deleted device: {key}"
                );
            }
        };

        for tree_name in ["ttl", "persist"] {
            let tree = db.open_tree(tree_name).unwrap();
            for item in tree.iter() {
                let (key, _) = item.unwrap();
                check_key(&String::from_utf8_lossy(&key));
            }
        }
        // Set metadata lives in the default tree.
        for item in db.iter() {
            let (key, _) = item.unwrap();
            check_key(&String::from_utf8_lossy(&key));
        }
    }

    /// Compare every client-visible view of every account with the model.
    async fn assert_matches(&self, model: &Model, step: usize, trace: &[Command]) {
        for user in USERS {
            let expected = &model.users[&user];
            let token = self.token(user);

            // The sync manifest is both the token-liveness probe and the vault
            // chunk view.
            let (status, value) = call(&self.app, "GET", "/vault/sync", Some(token), None).await;
            let expected_status = if expected.alive {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(
                status,
                expected_status,
                "GET /vault/sync for {} after step {step} of {trace:?}",
                user.name()
            );
            if !expected.alive {
                continue;
            }

            let chunks: BTreeSet<String> = value["chunks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|chunk| chunk["chunk_id"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                chunks,
                expected.vault,
                "vault of {} after step {step} of {trace:?}",
                user.name()
            );

            let (status, value) = call(&self.app, "GET", "/devices", Some(token), None).await;
            assert_eq!(status, StatusCode::OK);
            let devices: BTreeSet<Uuid> = value["devices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|device| serde_json::from_value(device["id"].clone()).unwrap())
                .collect();
            assert_eq!(
                devices,
                BTreeSet::from([self.parties[&user].device_id]),
                "devices of {} after step {step} of {trace:?}",
                user.name()
            );

            let (status, value) = call(&self.app, "GET", "/share/inbox", Some(token), None).await;
            assert_eq!(status, StatusCode::OK);
            let inbox: BTreeSet<(usize, User, String)> = value["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    let id: Uuid = serde_json::from_value(item["id"].clone()).unwrap();
                    let sender = self
                        .user_of(serde_json::from_value(item["sender_user_id"].clone()).unwrap());
                    (
                        self.share_slot(id),
                        sender,
                        item["capsule"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            let expected_inbox: BTreeSet<(usize, User, String)> = model
                .inbox(user)
                .into_iter()
                .map(|(slot, sender, capsule)| (slot, sender, B64.encode(capsule.as_bytes())))
                .collect();
            assert_eq!(
                inbox,
                expected_inbox,
                "inbox of {} after step {step} of {trace:?}",
                user.name()
            );

            let (status, value) = call(&self.app, "GET", "/share/linked", Some(token), None).await;
            assert_eq!(status, StatusCode::OK);
            let linked: BTreeSet<(usize, User, User, String)> = value["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    let id: Uuid = serde_json::from_value(item["id"].clone()).unwrap();
                    let sender = self
                        .user_of(serde_json::from_value(item["sender_user_id"].clone()).unwrap());
                    let recipient = self.user_of(
                        serde_json::from_value(item["recipient_user_id"].clone()).unwrap(),
                    );
                    assert_eq!(item["revoked"], Value::Bool(false));
                    (
                        self.share_slot(id),
                        sender,
                        recipient,
                        item["capsule"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            let expected_linked: BTreeSet<(usize, User, User, String)> = model
                .linked(user)
                .into_iter()
                .map(|(slot, sender, recipient, capsule)| {
                    (slot, sender, recipient, B64.encode(capsule.as_bytes()))
                })
                .collect();
            assert_eq!(
                linked,
                expected_linked,
                "linked shares of {} after step {step} of {trace:?}",
                user.name()
            );

            let (status, value) = call(&self.app, "GET", "/sends", Some(token), None).await;
            assert_eq!(status, StatusCode::OK);
            let sends: BTreeSet<usize> = value["sends"]
                .as_array()
                .unwrap()
                .iter()
                .map(|send| {
                    let id: Uuid = serde_json::from_value(send["id"].clone()).unwrap();
                    self.send_slot(id)
                })
                .collect();
            assert_eq!(
                sends,
                expected.sends,
                "send links of {} after step {step} of {trace:?}",
                user.name()
            );

            let (status, value) =
                call(&self.app, "GET", "/recovery/share", Some(token), None).await;
            match &expected.recovery {
                Some(share) => {
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(
                        value["share"],
                        Value::String(B64.encode(share.as_bytes())),
                        "recovery share of {} after step {step} of {trace:?}",
                        user.name()
                    );
                }
                None => assert_eq!(
                    status,
                    StatusCode::NOT_FOUND,
                    "recovery of {} after step {step} of {trace:?}",
                    user.name()
                ),
            }
        }
    }
}

async fn new_party(state: &vela_server::state::AppState, user: User) -> Party {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(now.clone()),
            ],
        )
        .await
        .unwrap();

    let (vk, signing_key) = generate_keypair().unwrap();
    state
        .sqldb
        .execute(
            "INSERT INTO devices (id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk, enrolled_by, created_at)
             VALUES (?, ?, ?, 'desktop', NULL, ?, ?, NULL, ?)",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(format!("device-{}", user.name())),
                TursoValue::Text(B64.encode([1u8; DEVICE_EK_LEN])),
                TursoValue::Text(B64.encode(vk.to_bytes())),
                TursoValue::Text(now),
            ],
        )
        .await
        .unwrap();

    Party {
        user_id,
        device_id,
        signing_key,
        token: token_for(state, user_id, device_id),
        ek_registrations: 0,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn every_bounded_account_deletion_trace_matches_the_model() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    // Fail loudly at the start if the schema grew a table this check does not
    // enumerate.
    let probe = Real::new(&state, app.clone()).await;
    probe.assert_no_unknown_tables().await;
    drop(probe);

    let depth = depth();
    let traces = sequences(depth);
    let mut steps = 0usize;
    let mut status_seen: BTreeSet<(&'static str, u16)> = BTreeSet::new();
    let mut covered: BTreeSet<&'static str> = BTreeSet::new();

    for trace in &traces {
        let mut model = Model::new();
        let mut real = Real::new(&state, app.clone()).await;

        for (step, command) in trace.iter().enumerate() {
            let expected = model.apply(*command, step);
            let actual = real.apply(*command, step).await;
            assert_eq!(
                actual, expected,
                "status mismatch for {command:?} at step {step} of {trace:?}"
            );
            status_seen.insert((command.kind(), actual.as_u16()));
            covered.extend(real.coverage.iter().copied());
            real.assert_matches(&model, step, trace).await;
            steps += 1;
        }
    }

    // Guard against a vacuous run: every command kind must have succeeded and
    // been refused somewhere in the exploration. Share and SetupRecovery have
    // two distinct refusal reasons, and both must appear.
    for (kind, success, refusals) in [
        ("WriteVault", 200u16, vec![401u16]),
        ("RegisterEk", 200, vec![401]),
        ("Share", 200, vec![401, 404]),
        ("SendLink", 200, vec![401]),
        ("SetupRecovery", 200, vec![401, 409]),
        ("Delete", 200, vec![401]),
        ("UseToken", 200, vec![401]),
        ("Relogin", 200, vec![401]),
    ] {
        assert!(
            status_seen.contains(&(kind, success)),
            "{kind} never succeeded: {status_seen:?}"
        );
        for refusal in refusals {
            assert!(
                status_seen.contains(&(kind, refusal)),
                "{kind} was never refused with {refusal}: {status_seen:?}"
            );
        }
    }

    // Guard against a vacuous residue scan: every table must have held at
    // least one row for an account at the moment it was deleted.
    for table in KNOWN_TABLES {
        assert!(
            covered.contains(table),
            "no trace ever had a {table} row for the account being deleted; \
             the residue check for that table was vacuous (covered: {covered:?})"
        );
    }

    eprintln!(
        "account deletion model: {} traces, {} steps, depth {}, tables covered: {:?}",
        traces.len(),
        steps,
        depth,
        covered
    );
}
