//! Bounded conformance of the real sharing handlers and database against the
//! M19b/M21 share-channel state machine.
//!
//! Every command sequence up to `DEPTH` over a fixed alphabet is executed both
//! against a small reference model and against the real Axum router backed by
//! the real Turso schema. After every step the test compares, for every user,
//! the HTTP status of the command, the user's inbox (ids and senders) and the
//! user's linked shares (ids, roles and current capsule) with the model.
//!
//! The reference model is the protocol relation the symbolic models prove
//! properties of:
//! - a share is delivered only to a recipient with a registered share key
//!   (M19b `sends_use_registered_bindings`);
//! - the inbox is visible to and deletable by its recipient only;
//! - only the original sender can update or revoke a linked share
//!   (M21 `only_sender_can_revoke_link`);
//! - a revoked share is never listed or updated again
//!   (M21 `revoked_links_can_never_be_read_again`), and revocation removes the
//!   pending inbox item.
//!
//! This is executable evidence for bounded traces, not a proof: it covers
//! every sequence up to the depth below with three users and two share slots,
//! and it trusts the database's single-statement atomicity. Concurrency is not
//! explored here.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use vela_server::sqldb::{Db as _, TursoValue};

mod helpers;

/// Command sequences are explored exhaustively up to this length. CI uses the
/// default; `VELA_SHARE_MODEL_DEPTH=4` runs the deeper exploration locally.
const DEFAULT_DEPTH: usize = 3;

fn depth() -> usize {
    std::env::var("VELA_SHARE_MODEL_DEPTH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_DEPTH)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum User {
    Alice,
    Bob,
    Carol,
}

const USERS: [User; 3] = [User::Alice, User::Bob, User::Carol];

#[derive(Clone, Copy, Debug)]
enum Command {
    /// Register (or refresh) the user's share key with a valid device-signed binding.
    RegisterEk(User),
    /// Send a new share; it occupies the next free share slot.
    Send { from: User, to: User },
    /// Delete (accept or decline) the inbox item in a slot.
    DeleteInbox { by: User, slot: usize },
    /// Re-seal the linked share in a slot with a new capsule.
    Update { by: User, slot: usize },
    /// Revoke the linked share in a slot.
    Revoke { by: User, slot: usize },
}

impl Command {
    fn kind(self) -> &'static str {
        match self {
            Command::RegisterEk(_) => "RegisterEk",
            Command::Send { .. } => "Send",
            Command::DeleteInbox { .. } => "DeleteInbox",
            Command::Update { .. } => "Update",
            Command::Revoke { .. } => "Revoke",
        }
    }
}

fn alphabet() -> Vec<Command> {
    use Command::*;
    use User::*;
    vec![
        RegisterEk(Bob),
        Send { from: Alice, to: Bob },
        Send { from: Alice, to: Carol },
        DeleteInbox { by: Bob, slot: 0 },
        DeleteInbox { by: Carol, slot: 0 },
        Update { by: Alice, slot: 0 },
        Update { by: Bob, slot: 0 },
        Revoke { by: Alice, slot: 0 },
        Revoke { by: Bob, slot: 0 },
        Update { by: Alice, slot: 1 },
        Revoke { by: Alice, slot: 1 },
    ]
}

// ── Reference model ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Share {
    sender: User,
    recipient: User,
    in_inbox: bool,
    revoked: bool,
    /// Version of the capsule currently stored (bumped by each update).
    version: u32,
}

#[derive(Clone, Debug, Default)]
struct Model {
    registered: BTreeSet<User>,
    shares: Vec<Share>,
}

impl Model {
    fn apply(&mut self, command: Command) -> StatusCode {
        match command {
            Command::RegisterEk(user) => {
                self.registered.insert(user);
                StatusCode::OK
            }
            Command::Send { from, to } => {
                if !self.registered.contains(&to) {
                    return StatusCode::NOT_FOUND;
                }
                self.shares.push(Share {
                    sender: from,
                    recipient: to,
                    in_inbox: true,
                    revoked: false,
                    version: 0,
                });
                StatusCode::OK
            }
            Command::DeleteInbox { by, slot } => match self.shares.get_mut(slot) {
                Some(share) if share.in_inbox && share.recipient == by => {
                    share.in_inbox = false;
                    StatusCode::NO_CONTENT
                }
                _ => StatusCode::NOT_FOUND,
            },
            Command::Update { by, slot } => match self.shares.get_mut(slot) {
                Some(share) if share.sender == by && !share.revoked => {
                    share.version += 1;
                    StatusCode::OK
                }
                _ => StatusCode::NOT_FOUND,
            },
            Command::Revoke { by, slot } => match self.shares.get_mut(slot) {
                Some(share) if share.sender == by && !share.revoked => {
                    share.revoked = true;
                    share.in_inbox = false;
                    StatusCode::OK
                }
                _ => StatusCode::NOT_FOUND,
            },
        }
    }

    /// What `GET /share/inbox` should list for `user`: slot -> sender.
    fn inbox(&self, user: User) -> BTreeMap<usize, User> {
        self.shares
            .iter()
            .enumerate()
            .filter(|(_, s)| s.in_inbox && s.recipient == user)
            .map(|(slot, s)| (slot, s.sender))
            .collect()
    }

    /// What `GET /share/linked` should list for `user`: slot -> (sender, recipient, version).
    fn linked(&self, user: User) -> BTreeMap<usize, (User, User, u32)> {
        self.shares
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.revoked && (s.sender == user || s.recipient == user))
            .map(|(slot, s)| (slot, (s.sender, s.recipient, s.version)))
            .collect()
    }
}

// ── Real system ─────────────────────────────────────────────────────────────

struct Party {
    user_id: Uuid,
    device_id: Uuid,
    signing_key: vela_crypto::signing::HybridSigningKey,
    token: String,
    ek_registrations: u32,
}

struct Real {
    app: Router,
    parties: BTreeMap<User, Party>,
    /// Real share ids, by slot.
    slots: Vec<Uuid>,
    /// Capsule bytes the real system should currently hold, by slot.
    capsules: Vec<Vec<u8>>,
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

async fn new_party(state: &vela_server::state::AppState) -> Party {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![TursoValue::Text(user_id.to_string()), TursoValue::Text(now.clone())],
        )
        .await
        .unwrap();
    let (vk, signing_key) = vela_crypto::signing::generate_keypair().unwrap();
    state
        .sqldb
        .execute(
            "INSERT INTO devices (id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk, enrolled_by, created_at)
             VALUES (?, ?, 'model', 'desktop', NULL, ?, ?, NULL, ?)",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(B64.encode([1u8; 16])),
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

async fn call(app: &Router, method: &str, uri: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"));
    let body = match body {
        Some(json) => {
            builder = builder.header("content-type", "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    let response = app.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

impl Real {
    async fn new(state: &vela_server::state::AppState, app: Router) -> Self {
        let mut parties = BTreeMap::new();
        for user in USERS {
            parties.insert(user, new_party(state).await);
        }
        // Alice and Carol start with registered share keys; Bob does not, so
        // sends to Bob exercise the "recipient cannot receive" path until he
        // registers. The model starts the same way.
        let mut real = Self { app, parties, slots: Vec::new(), capsules: Vec::new() };
        for user in [User::Alice, User::Carol] {
            assert_eq!(real.register_ek(user).await, StatusCode::OK);
        }
        real
    }

    async fn register_ek(&mut self, user: User) -> StatusCode {
        let party = self.parties.get_mut(&user).unwrap();
        party.ek_registrations += 1;
        // Canonical UTC seconds, strictly increasing per registration.
        let signed_at = format!("2026-01-01T00:00:{:02}Z", party.ek_registrations);
        let share_ek = [user as u8 + 7; 1568 + 32];
        let message = vela_crypto::signing::share_ek_binding_message(&share_ek, &signed_at);
        let signature = vela_crypto::signing::sign(&party.signing_key, &message).unwrap();
        let body = json!({
            "share_ek": B64.encode(share_ek),
            "device_id": party.device_id,
            "signed_at": signed_at,
            "signature": B64.encode(signature.to_bytes()),
        });
        let token = party.token.clone();
        call(&self.app, "PUT", "/share/my-ek", &token, Some(body)).await.0
    }

    async fn apply(&mut self, command: Command) -> StatusCode {
        match command {
            Command::RegisterEk(user) => self.register_ek(user).await,
            Command::Send { from, to } => {
                let capsule = format!("capsule slot {} v0", self.slots.len()).into_bytes();
                let body = json!({
                    "recipient_user_id": self.parties[&to].user_id,
                    "capsule": B64.encode(&capsule),
                });
                let (status, value) =
                    call(&self.app, "POST", "/share/send", &self.parties[&from].token, Some(body)).await;
                if status == StatusCode::OK {
                    let id: Uuid = serde_json::from_value(value["share_id"].clone()).unwrap();
                    self.slots.push(id);
                    self.capsules.push(capsule);
                }
                status
            }
            Command::DeleteInbox { by, slot } => {
                let id = self.slot_id(slot);
                call(&self.app, "DELETE", &format!("/share/inbox/{id}"), &self.parties[&by].token, None).await.0
            }
            Command::Update { by, slot } => {
                let id = self.slot_id(slot);
                let capsule = format!("capsule slot {slot} by {by:?} {}", Uuid::new_v4()).into_bytes();
                let (status, _) = call(
                    &self.app,
                    "PUT",
                    &format!("/share/linked/{id}"),
                    &self.parties[&by].token,
                    Some(json!({ "capsule": B64.encode(&capsule) })),
                )
                .await;
                if status == StatusCode::OK {
                    self.capsules[slot] = capsule;
                }
                status
            }
            Command::Revoke { by, slot } => {
                let id = self.slot_id(slot);
                call(&self.app, "DELETE", &format!("/share/linked/{id}"), &self.parties[&by].token, None).await.0
            }
        }
    }

    /// A share slot that was never created maps to a fresh, unknown id, so the
    /// command is still sent and must be refused like the model refuses it.
    fn slot_id(&self, slot: usize) -> Uuid {
        self.slots.get(slot).copied().unwrap_or_else(Uuid::new_v4)
    }

    fn slot_of(&self, id: Uuid) -> usize {
        self.slots
            .iter()
            .position(|known| *known == id)
            .unwrap_or_else(|| panic!("the server listed an id the test never created: {id}"))
    }

    fn user_of(&self, id: Uuid) -> User {
        *self
            .parties
            .iter()
            .find(|(_, party)| party.user_id == id)
            .unwrap_or_else(|| panic!("the server named a user outside this trace: {id}"))
            .0
    }

    async fn inbox(&self, user: User) -> BTreeMap<usize, User> {
        let (status, value) = call(&self.app, "GET", "/share/inbox", &self.parties[&user].token, None).await;
        assert_eq!(status, StatusCode::OK);
        let mut out = BTreeMap::new();
        for item in value["items"].as_array().unwrap() {
            let id: Uuid = serde_json::from_value(item["id"].clone()).unwrap();
            let sender: Uuid = serde_json::from_value(item["sender_user_id"].clone()).unwrap();
            assert!(out.insert(self.slot_of(id), self.user_of(sender)).is_none(), "duplicate inbox id");
        }
        out
    }

    async fn linked(&self, user: User, model: &Model) -> BTreeMap<usize, (User, User, u32)> {
        let (status, value) = call(&self.app, "GET", "/share/linked", &self.parties[&user].token, None).await;
        assert_eq!(status, StatusCode::OK);
        let mut out = BTreeMap::new();
        for item in value["items"].as_array().unwrap() {
            let id: Uuid = serde_json::from_value(item["id"].clone()).unwrap();
            let slot = self.slot_of(id);
            let sender = self.user_of(serde_json::from_value(item["sender_user_id"].clone()).unwrap());
            let recipient = self.user_of(serde_json::from_value(item["recipient_user_id"].clone()).unwrap());
            assert_eq!(item["revoked"], Value::Bool(false), "a revoked share was listed");
            let capsule = B64.decode(item["capsule"].as_str().unwrap()).unwrap();
            assert_eq!(capsule, self.capsules[slot], "slot {slot} does not hold its latest capsule");
            // The capsule check above pins the content; report the model's
            // version so the maps compare equal when the content matches.
            let version = model.shares.get(slot).map_or(u32::MAX, |s| s.version);
            assert!(out.insert(slot, (sender, recipient, version)).is_none(), "duplicate linked id");
        }
        out
    }
}

fn sequences(depth: usize) -> Vec<Vec<Command>> {
    let alphabet = alphabet();
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for prefix in &frontier {
            for command in &alphabet {
                let mut sequence: Vec<Command> = prefix.clone();
                sequence.push(*command);
                next.push(sequence);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

#[tokio::test(flavor = "current_thread")]
async fn every_bounded_share_trace_matches_the_m19_m21_state_machine() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let depth = depth();
    let traces = sequences(depth);
    let mut steps = 0usize;
    let mut status_seen: BTreeSet<(&'static str, u16)> = BTreeSet::new();

    for trace in &traces {
        let mut model = Model::default();
        model.registered.insert(User::Alice);
        model.registered.insert(User::Carol);
        let mut real = Real::new(&state, app.clone()).await;

        for (step, command) in trace.iter().enumerate() {
            let expected = model.apply(*command);
            let actual = real.apply(*command).await;
            assert_eq!(actual, expected, "status mismatch at step {step} of {trace:?}");
            status_seen.insert((command.kind(), actual.as_u16()));

            for user in USERS {
                assert_eq!(real.inbox(user).await, model.inbox(user), "inbox of {user:?} after step {step} of {trace:?}");
                assert_eq!(real.linked(user, &model).await, model.linked(user), "linked of {user:?} after step {step} of {trace:?}");
            }
            steps += 1;
        }
    }

    // Guard against a vacuous run: every command kind must have been seen both
    // succeeding and being refused somewhere in the exploration.
    for (kind, ok, refused) in [
        ("Send", 200u16, 404u16),
        ("DeleteInbox", 204, 404),
        ("Update", 200, 404),
        ("Revoke", 200, 404),
    ] {
        let seen = |code: u16| status_seen.contains(&(kind, code));
        assert!(seen(ok) && seen(refused), "{kind} was not exercised both ways: {status_seen:?}");
    }
    eprintln!("share channel model: {} traces, {} steps, depth {}", traces.len(), steps, depth);
}

/// Revocation marks the linked share revoked, then deletes the recipient's
/// inbox copy in a separate cleanup step. If that cleanup fails or the request
/// is dropped in between, the inbox must still stop serving the capsule.
#[tokio::test(flavor = "current_thread")]
async fn a_revoked_share_leaves_the_inbox_even_if_cleanup_never_ran() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let mut real = Real::new(&state, app.clone()).await;

    let send = Command::Send { from: User::Alice, to: User::Carol };
    assert_eq!(real.apply(send).await, StatusCode::OK);
    assert_eq!(real.apply(send).await, StatusCode::OK);
    let (revoked, kept) = (real.slot_id(0), real.slot_id(1));
    assert_eq!(real.inbox(User::Carol).await.len(), 2);

    // The state an interrupted revocation leaves: revoked, inbox row present.
    state
        .sqldb
        .execute(
            "UPDATE shared_items SET revoked = 1 WHERE id = ?",
            vec![TursoValue::Text(revoked.to_string())],
        )
        .await
        .unwrap();
    let rows = state
        .sqldb
        .query(
            "SELECT COUNT(*) FROM share_inbox WHERE id = ?",
            vec![TursoValue::Text(revoked.to_string())],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].i64(0), Some(1), "the inbox row must still exist for this test");

    let inbox = real.inbox(User::Carol).await;
    assert_eq!(inbox.len(), 1, "a revoked share must not be listed: {inbox:?}");
    assert!(inbox.contains_key(&real.slot_of(kept)));
}
