//! Bounded conformance of device revocation and logout against an independent
//! reference state machine.
//!
//! Two handlers own the "stop this authority now" transitions:
//!
//! - `POST /device/revoke` (`src/device/revoke.rs`) writes, for the target
//!   device, every tracked JTI into `jti:revoked:{jti}` (via
//!   `rate_limit::revoke_all_device_jtis`) and then the sled sentinel
//!   `device:revoked:{device_id}` with a 15-minute TTL, and only afterwards
//!   flips the SQL `devices.revoked` column.
//! - `POST /auth/logout` (`src/auth/logout.rs`) writes
//!   `jti:revoked:{jti}` for the caller's own token with a 15-minute TTL.
//!
//! `AuthSession::from_request_parts` (`src/middleware.rs`) is the single place
//! that turns either record into a refusal, in this order: PASETO signature →
//! hard cap → `jti:revoked` → `device:revoked` → per-JTI rate limit → account
//! existence. Every authenticated route extracts `AuthSession` or the stricter
//! `DeviceSession`, so the two checks gate all of them.
//!
//! ## Reference model
//!
//! One account with devices `A` (primary), `B`, `C`, plus one device `E` of a
//! second account. Each device owns up to two token slots, but the alphabet
//! only exposes both slots for `A` (`A0`, `A1`); `B0`, `C0` and `E0` are the
//! other devices' single slot. Slots are token identities, not server state: a
//! login into an occupied slot replaces the client's handle, and the model
//! deliberately forgets the replaced token kept alive on the server (nothing in
//! the alphabet can reach it again). `None` means no login was ever performed
//! into that slot, so requests from it carry a bearer the server never issued.
//!
//! The transition relation:
//!
//! - `Login(t)` succeeds iff `t`'s device is not revoked, and makes `t`'s slot
//!   live.
//! - `Use(t, endpoint)` succeeds iff `t` is live (`200`; the vault write also
//!   returns `200`).
//! - `Logout(t)` succeeds iff `t` is live and kills exactly `t`.
//! - `Revoke(actor, target)` refuses a dead actor (`401`), then refuses a target
//!   of the other account (`403`), then refuses an already-revoked target
//!   (`400`), and otherwise revokes `target` permanently — killing every token
//!   of the target device, including the actor's own when it self-revokes.
//!
//! Revocation is monotone: nothing in the alphabet un-revokes. The server
//! permits revoking the **last** non-revoked device of an account (no
//! "you would lock yourself out" check in `post_revoke`); the model records
//! that and the focused test drives it, leaving the account with no usable
//! device. A self-revoke is also accepted while the actor's own token is being
//! killed mid-handler, because the authorization check happened before the
//! revocation writes; the model asserts the successful `200` and the following
//! `401`s.
//!
//! States follow the symbolic vocabulary: M27 `Revoked(dev)` / no fresh
//! `ActiveDeviceLookup`, and M21's revocation finality. The SQL `revoked` flag
//! is the durable record; the sled sentinel and JTI markers are what the
//! request path actually consults.
//!
//! ## Exploration
//!
//! Every command sequence up to `VELA_REVOCATION_MODEL_DEPTH` (default 3) over a
//! 22-command alphabet is executed against the model and against the real Axum
//! router with the real Turso schema and sled store.
//!
//! After **every** step the test compares:
//!
//! - the HTTP status of the command (and the `revoked` echo of a successful
//!   revoke);
//! - the SQL `devices` rows of both accounts: `revoked`, `revoked_by`,
//!   `revoked_at` presence and the exact device set per account;
//! - the sled `device:revoked:{id}` sentinel for every device;
//! - which of the five token handles the server still accepts, by replaying
//!   each one against `GET /devices` (a handle the model calls dead must be
//!   `401`, a live one `200`, and a live owner token must list exactly its
//!   account's devices with the model's `revoked` flags);
//! - explicitly after a successful revoke, that **every** token handle of the
//!   target is refused at every endpoint in the alphabet, not just `/devices`.
//!
//! Fresh accounts and devices are created for each trace, so revocation state
//! never leaks between traces. The four login challenges are obtained from the
//! real `GET /auth/challenge` once and re-armed under the same store key before
//! every `Login`, which makes the hybrid signatures precomputable without
//! weakening the store semantics under test (the challenge namespace is not
//! what this test models; `challenge_single_use_model.rs` owns that).
//!
//! ## Not covered
//!
//! Token cryptography (PASETO verification and hybrid signatures are assumed
//! sound), real concurrency between a revoke and an in-flight request, TTL
//! expiry of the 15-minute markers (counted as "present" for the whole run),
//! multi-node stores where the sled sentinel and Turso row could be written on
//! different nodes, and the unauthenticated endpoints listed in the README.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use vela_crypto::signing::{auth_message, generate_keypair, sign, HybridSigningKey};
use vela_server::sqldb::{Db as _, TursoValue};

mod helpers;

/// CI uses the default; `VELA_REVOCATION_MODEL_DEPTH=4` is a local exploration.
const DEFAULT_DEPTH: usize = 3;

fn depth() -> usize {
    std::env::var("VELA_REVOCATION_MODEL_DEPTH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_DEPTH)
}

/// A bearer string the server never issued. Used when a token slot is empty so
/// the request is still well-formed HTTP but cannot authenticate.
const NO_TOKEN: &str = "device-revocation-model-no-such-token";

// ── Universe ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Owner {
    Alice,
    Eve,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Dev {
    /// Primary device of the first account.
    A,
    /// Second device of the first account.
    B,
    /// Third device of the first account.
    C,
    /// The only device of the second account.
    E,
}

impl Dev {
    const ALL: [Dev; 4] = [Dev::A, Dev::B, Dev::C, Dev::E];

    fn index(self) -> usize {
        match self {
            Dev::A => 0,
            Dev::B => 1,
            Dev::C => 2,
            Dev::E => 3,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Dev::A => "a",
            Dev::B => "b",
            Dev::C => "c",
            Dev::E => "eve",
        }
    }

    fn owner(self) -> Owner {
        match self {
            Dev::A | Dev::B | Dev::C => Owner::Alice,
            Dev::E => Owner::Eve,
        }
    }
}

/// A token handle. `A` has two slots so a logout or a revoke can be checked to
/// kill exactly the addressed token and not its sibling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TokenRef {
    A0,
    A1,
    B0,
    C0,
    E0,
}

impl TokenRef {
    const ALL: [TokenRef; 5] = [
        TokenRef::A0,
        TokenRef::A1,
        TokenRef::B0,
        TokenRef::C0,
        TokenRef::E0,
    ];

    fn index(self) -> usize {
        match self {
            TokenRef::A0 => 0,
            TokenRef::A1 => 1,
            TokenRef::B0 => 2,
            TokenRef::C0 => 3,
            TokenRef::E0 => 4,
        }
    }

    fn device(self) -> Dev {
        match self {
            TokenRef::A0 | TokenRef::A1 => Dev::A,
            TokenRef::B0 => Dev::B,
            TokenRef::C0 => Dev::C,
            TokenRef::E0 => Dev::E,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Endpoint {
    /// `GET /devices` — device-only read of the account's device rows.
    Devices,
    /// `GET /vault/epoch` — vault read.
    VaultEpoch,
    /// `GET /share/inbox` — share read (`AuthSession`, not `DeviceSession`).
    Inbox,
    /// `PUT /vault/chunk/:id` — a real vault write (`200`). Each invocation
    /// uses a fresh chunk id with `If-Match: 0`, so the model's "success" is
    /// history-independent.
    VaultChunkWrite,
}

impl Endpoint {
    const ALL: [Endpoint; 4] = [
        Endpoint::Devices,
        Endpoint::VaultEpoch,
        Endpoint::Inbox,
        Endpoint::VaultChunkWrite,
    ];

    fn name(self) -> &'static str {
        match self {
            Endpoint::Devices => "UseDevices",
            Endpoint::VaultEpoch => "UseVaultEpoch",
            Endpoint::Inbox => "UseInbox",
            Endpoint::VaultChunkWrite => "UseVaultChunkWrite",
        }
    }

    fn success(self) -> StatusCode {
        StatusCode::OK
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Login(TokenRef),
    Use { token: TokenRef, endpoint: Endpoint },
    Logout(TokenRef),
    Revoke { actor: TokenRef, target: Dev },
}

impl Command {
    fn kind(self) -> &'static str {
        match self {
            Command::Login(_) => "Login",
            Command::Use { endpoint, .. } => endpoint.name(),
            Command::Logout(_) => "Logout",
            Command::Revoke { .. } => "Revoke",
        }
    }
}

fn alphabet() -> Vec<Command> {
    use Command::*;
    let mut out = vec![
        // One login per exposed slot/device.
        Login(TokenRef::A0),
        Login(TokenRef::A1),
        Login(TokenRef::B0),
        Login(TokenRef::C0),
        Login(TokenRef::E0),
    ];
    // Every endpoint kind, on more than one device and both of A's tokens.
    out.extend([
        Use {
            token: TokenRef::A0,
            endpoint: Endpoint::Devices,
        },
        Use {
            token: TokenRef::A0,
            endpoint: Endpoint::VaultChunkWrite,
        },
        Use {
            token: TokenRef::A1,
            endpoint: Endpoint::Inbox,
        },
        Use {
            token: TokenRef::A1,
            endpoint: Endpoint::VaultEpoch,
        },
        Use {
            token: TokenRef::B0,
            endpoint: Endpoint::Devices,
        },
        Use {
            token: TokenRef::C0,
            endpoint: Endpoint::Inbox,
        },
        Use {
            token: TokenRef::E0,
            endpoint: Endpoint::VaultEpoch,
        },
    ]);
    out.extend([
        Logout(TokenRef::A0),
        Logout(TokenRef::A1),
        Logout(TokenRef::B0),
    ]);
    // Normal, self-, second-token-actor, already-revoked and cross-account
    // revocation shapes. Repetition in a trace produces the "already revoked"
    // and "revoked actor" refusals without dedicated commands.
    out.extend([
        Revoke {
            actor: TokenRef::A0,
            target: Dev::B,
        },
        Revoke {
            actor: TokenRef::A0,
            target: Dev::A,
        },
        Revoke {
            actor: TokenRef::A1,
            target: Dev::C,
        },
        Revoke {
            actor: TokenRef::B0,
            target: Dev::B,
        },
        Revoke {
            actor: TokenRef::C0,
            target: Dev::E,
        },
        Revoke {
            actor: TokenRef::E0,
            target: Dev::E,
        },
        Revoke {
            actor: TokenRef::E0,
            target: Dev::A,
        },
    ]);
    out
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Live,
    Dead,
}

#[derive(Clone, Debug, Default)]
struct Model {
    /// `None` = no login ever reached this slot; `Dead` tokens stay recorded so
    /// every later request through that handle is asserted to be refused.
    slots: [Option<SlotState>; 5],
    revoked: [bool; 4],
    revoked_by: [Option<Dev>; 4],
}

impl Model {
    fn is_live(&self, token: TokenRef) -> bool {
        self.slots[token.index()] == Some(SlotState::Live)
    }

    fn apply(&mut self, command: Command) -> StatusCode {
        match command {
            Command::Login(token) => {
                if self.revoked[token.device().index()] {
                    // M27: a revoked device gets no fresh lookup, so no token.
                    StatusCode::UNAUTHORIZED
                } else {
                    self.slots[token.index()] = Some(SlotState::Live);
                    StatusCode::OK
                }
            }
            Command::Use { token, endpoint } => {
                if self.is_live(token) {
                    endpoint.success()
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
            Command::Logout(token) => {
                if self.is_live(token) {
                    self.slots[token.index()] = Some(SlotState::Dead);
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
            Command::Revoke { actor, target } => {
                if !self.is_live(actor) {
                    // Middleware rejects the caller before the handler runs.
                    StatusCode::UNAUTHORIZED
                } else if actor.device().owner() != target.owner() {
                    // Cross-account targets are refused before the revoked flag
                    // is inspected, so this stays 403 even if target is revoked.
                    StatusCode::FORBIDDEN
                } else if self.revoked[target.index()] {
                    StatusCode::BAD_REQUEST
                } else {
                    self.revoked[target.index()] = true;
                    self.revoked_by[target.index()] = Some(actor.device());
                    for token in TokenRef::ALL {
                        if token.device() == target {
                            if self.slots[token.index()] == Some(SlotState::Live) {
                                self.slots[token.index()] = Some(SlotState::Dead);
                            }
                        }
                    }
                    StatusCode::OK
                }
            }
        }
    }

    /// Invariants that must hold after every command, independent of the
    /// status comparison.
    fn assert_invariants(&self, context: &str) {
        for dev in Dev::ALL {
            if self.revoked[dev.index()] {
                assert!(
                    self.revoked_by[dev.index()].is_some(),
                    "revoked device {} has no revoker {context}",
                    dev.name()
                );
                for token in TokenRef::ALL {
                    if token.device() == dev {
                        assert_ne!(
                            self.slots[token.index()],
                            Some(SlotState::Live),
                            "revoked device {} still holds a live token {:?} {context}",
                            dev.name(),
                            token
                        );
                    }
                }
            } else {
                assert!(
                    self.revoked_by[dev.index()].is_none(),
                    "unrevoked device {} carries a revoker {context}",
                    dev.name()
                );
            }
        }
    }
}

// ── Real system ─────────────────────────────────────────────────────────────

static NEXT_IP: AtomicU32 = AtomicU32::new(1);

/// A distinct source address per request keeps the per-IP limits (20
/// challenges/min, 20 verifies/min) out of the way. Three varying octets cover
/// the ~300k requests a depth-3 run sends.
fn fresh_ip() -> ConnectInfo<SocketAddr> {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed) + 1;
    let [_, b, c, d] = n.to_be_bytes();
    ConnectInfo(SocketAddr::from(([10, b, c, d], 40000)))
}

/// ML-DSA signing is stack hungry; the same 8 MiB workaround as
/// `tests/integration.rs` and the other model tests.
fn with_big_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn_scoped(scope, f)
            .expect("spawn 8 MiB stack thread")
            .join()
            .expect("big-stack thread panicked")
    })
}

struct DeviceKeys {
    signing: HybridSigningKey,
    vk: Vec<u8>,
}

struct Keys {
    devices: [DeviceKeys; 4],
}

impl Keys {
    fn new() -> Self {
        let devices = with_big_stack(|| {
            std::array::from_fn(|_| {
                let (vk, signing) = generate_keypair().expect("device keygen");
                DeviceKeys {
                    signing,
                    vk: vk.to_bytes().to_vec(),
                }
            })
        });
        Self { devices }
    }

    fn device(&self, dev: Dev) -> &DeviceKeys {
        &self.devices[dev.index()]
    }
}

async fn get_challenge(app: &Router) -> (String, Vec<u8>) {
    let request = Request::builder()
        .method("GET")
        .uri("/auth/challenge")
        .extension(fresh_ip())
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /auth/challenge failed"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let b64 = value["challenge"]
        .as_str()
        .expect("challenge response has no string `challenge`")
        .to_string();
    let decoded = B64.decode(&b64).expect("challenge is not base64");
    (b64, decoded)
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
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
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A real vault write: create a fresh chunk with `If-Match: 0`. Successful
/// calls return `200` with the new version; a refused token never reaches the
/// handler, so the id is irrelevant on the probe path.
async fn put_chunk(app: &Router, token: &str, id: &str) -> (StatusCode, HeaderMap, Value) {
    let request = Request::builder()
        .method("PUT")
        .uri(format!("/vault/chunk/{id}"))
        .extension(fresh_ip())
        .header("Authorization", format!("Bearer {token}"))
        .header("if-match", "0")
        .header("x-lamport-clock", "1")
        .body(Body::from(vec![0xA5u8; 64]))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

struct Party {
    user_id: Uuid,
    device_id: Uuid,
}

struct Fixture {
    app: Router,
    state: vela_server::state::AppState,
    /// Owner account then the other account.
    users: [Uuid; 2],
    /// Indexed by `Dev::index`.
    parties: [Party; 4],
    /// Challenges obtained from the real endpoint, one per device (indexed by
    /// `Dev::index`), re-armed by every login.
    challenges: [(String, Vec<u8>); 4],
    /// Current bearer string per token handle. Dead handles keep their string so
    /// the server is asked to refuse the real token, not just garbage.
    tokens: [Option<String>; 5],
    /// Every successful vault write uses a fresh chunk id.
    chunk_counter: u64,
}

async fn insert_user(state: &vela_server::state::AppState, user_id: Uuid) {
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(chrono::Utc::now().to_rfc3339()),
            ],
        )
        .await
        .expect("insert user");
}

async fn insert_device(
    state: &vela_server::state::AppState,
    user_id: Uuid,
    device_id: Uuid,
    name: &str,
    vk: &[u8],
) {
    state
        .sqldb
        .execute(
            "INSERT INTO devices (id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk, enrolled_by, created_at)
             VALUES (?, ?, ?, 'desktop', NULL, ?, ?, NULL, ?)",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(name.to_string()),
                // Public KEM material is opaque to this test; only its length
                // class matters to the handlers touched here.
                TursoValue::Text(B64.encode([7u8; 1568 + 32])),
                TursoValue::Text(B64.encode(vk)),
                TursoValue::Text(chrono::Utc::now().to_rfc3339()),
            ],
        )
        .await
        .expect("insert device");
}

impl Fixture {
    async fn new(
        state: vela_server::state::AppState,
        app: Router,
        keys: &Keys,
        challenges: &[(String, Vec<u8>)],
    ) -> Self {
        // Each trace gets fresh accounts and devices, so revocation state never
        // leaks between traces. The previous trace's rows are deleted rather
        // than left behind: a depth-3 run creates ~11k traces, and keeping
        // 4 device rows (with ~5 KiB of public key material each) per trace
        // would grow the temporary database past a gigabyte. Deleting them
        // lets the database reuse its pages and keeps the file bounded.
        for table in ["vault_chunks", "devices", "users"] {
            state
                .sqldb
                .execute(&format!("DELETE FROM {table}"), vec![])
                .await
                .unwrap_or_else(|e| panic!("clear {table}: {e}"));
        }

        let alice = Uuid::new_v4();
        let eve = Uuid::new_v4();
        insert_user(&state, alice).await;
        insert_user(&state, eve).await;

        let parties = std::array::from_fn(|index| {
            let dev = Dev::ALL[index];
            Party {
                user_id: match dev.owner() {
                    Owner::Alice => alice,
                    Owner::Eve => eve,
                },
                device_id: Uuid::new_v4(),
            }
        });
        for dev in Dev::ALL {
            let party = &parties[dev.index()];
            insert_device(
                &state,
                party.user_id,
                party.device_id,
                dev.name(),
                &keys.device(dev).vk,
            )
            .await;
        }

        Self {
            app,
            state,
            users: [alice, eve],
            parties,
            challenges: std::array::from_fn(|index| challenges[index].clone()),
            tokens: std::array::from_fn(|_| None),
            chunk_counter: 0,
        }
    }

    fn bearer(&self, token: TokenRef) -> String {
        self.tokens[token.index()]
            .clone()
            .unwrap_or_else(|| NO_TOKEN.to_string())
    }

    fn device_id(&self, dev: Dev) -> Uuid {
        self.parties[dev.index()].device_id
    }

    fn user_id(&self, owner: Owner) -> Uuid {
        self.users[match owner {
            Owner::Alice => 0,
            Owner::Eve => 1,
        }]
    }

    async fn apply(&mut self, command: Command, keys: &Keys) -> (StatusCode, Value) {
        match command {
            Command::Login(token) => {
                let dev = token.device();
                let device_id = self.device_id(dev).to_string();
                let (challenge_b64, challenge_bytes) = &self.challenges[dev.index()];
                // Re-arm the real nonce under the key `/auth/verify` consumes.
                // Every trace is independent; the nonce namespace is covered by
                // `challenge_single_use_model.rs`, not by this model.
                self.state
                    .store
                    .set_ex(&format!("challenge:{challenge_b64}"), b"login", 60)
                    .expect("re-arm pre-issued challenge");
                let signature = with_big_stack(|| {
                    B64.encode(
                        sign(
                            &keys.device(dev).signing,
                            &auth_message(&device_id, challenge_bytes),
                        )
                        .expect("login sign")
                        .to_bytes(),
                    )
                });
                let (status, _headers, body) = call(
                    &self.app,
                    "POST",
                    "/auth/verify",
                    None,
                    Some(json!({
                        "device_id": self.device_id(dev),
                        "challenge": challenge_b64,
                        "signature": signature,
                    })),
                )
                .await;
                if status == StatusCode::OK {
                    let issued = body["token"]
                        .as_str()
                        .unwrap_or_else(|| panic!("login returned no token: {body}"))
                        .to_string();
                    self.tokens[token.index()] = Some(issued);
                }
                (status, body)
            }
            Command::Use { token, endpoint } => {
                let bearer = self.bearer(token);
                if endpoint == Endpoint::VaultChunkWrite {
                    self.chunk_counter += 1;
                    let id = format!("revocation-chunk-{}", self.chunk_counter);
                    let (status, _headers, body) = put_chunk(&self.app, &bearer, &id).await;
                    return (status, body);
                }
                let (method, uri) = match endpoint {
                    Endpoint::Devices => ("GET", "/devices".to_string()),
                    Endpoint::VaultEpoch => ("GET", "/vault/epoch".to_string()),
                    Endpoint::Inbox => ("GET", "/share/inbox".to_string()),
                    Endpoint::VaultChunkWrite => unreachable!("handled above"),
                };
                let (status, _headers, body) =
                    call(&self.app, method, &uri, Some(&bearer), None).await;
                (status, body)
            }
            Command::Logout(token) => {
                let bearer = self.bearer(token);
                let (status, _headers, body) =
                    call(&self.app, "POST", "/auth/logout", Some(&bearer), None).await;
                (status, body)
            }
            Command::Revoke { actor, target } => {
                let bearer = self.bearer(actor);
                let target_id = self.device_id(target);
                let (status, _headers, body) = call(
                    &self.app,
                    "POST",
                    "/device/revoke",
                    Some(&bearer),
                    Some(json!({ "target_device_id": target_id })),
                )
                .await;
                if status == StatusCode::OK {
                    assert_eq!(
                        body["revoked"].as_str(),
                        Some(target_id.to_string().as_str()),
                        "a successful revoke must echo the target device id"
                    );
                }
                (status, body)
            }
        }
    }

    async fn probe(&self, token: TokenRef, endpoint: Endpoint) -> (StatusCode, HeaderMap, Value) {
        let bearer = self.bearer(token);
        if endpoint == Endpoint::VaultChunkWrite {
            // A dead token must be refused by the extractor, before any write.
            return put_chunk(&self.app, &bearer, "revocation-probe").await;
        }
        let (method, uri) = match endpoint {
            Endpoint::Devices => ("GET", "/devices".to_string()),
            Endpoint::VaultEpoch => ("GET", "/vault/epoch".to_string()),
            Endpoint::Inbox => ("GET", "/share/inbox".to_string()),
            Endpoint::VaultChunkWrite => unreachable!("handled above"),
        };
        call(&self.app, method, &uri, Some(&bearer), None).await
    }

    /// Which devices of `owner` the model expects to see, with their flags.
    fn expected_listing(&self, model: &Model, owner: Owner) -> Vec<(Uuid, bool)> {
        Dev::ALL
            .iter()
            .filter(|dev| dev.owner() == owner)
            .map(|dev| (self.device_id(*dev), model.revoked[dev.index()]))
            .collect()
    }

    async fn assert_listing(&self, model: &Model, owner: Owner, body: &Value, context: &str) {
        let expected = self.expected_listing(model, owner);
        let items = body["devices"]
            .as_array()
            .unwrap_or_else(|| panic!("GET /devices returned no devices array: {body}"));
        assert_eq!(
            items.len(),
            expected.len(),
            "device listing length for {owner:?} {context}"
        );
        let mut actual: Vec<(Uuid, bool)> = items
            .iter()
            .map(|item| {
                (
                    serde_json::from_value(item["id"].clone()).expect("device id"),
                    item["revoked"].as_bool().expect("revoked flag"),
                )
            })
            .collect();
        actual.sort();
        let mut expected = expected;
        expected.sort();
        assert_eq!(actual, expected, "device listing for {owner:?} {context}");
    }

    async fn stored_devices(&self) -> Vec<(Uuid, Uuid, bool, Option<String>, bool)> {
        let rows = self
            .state
            .sqldb
            .query(
                "SELECT id, user_id, revoked, revoked_by, revoked_at FROM devices
                 WHERE user_id = ? OR user_id = ?",
                vec![
                    TursoValue::Text(self.users[0].to_string()),
                    TursoValue::Text(self.users[1].to_string()),
                ],
            )
            .await
            .expect("read device rows");
        rows.iter()
            .map(|row| {
                (
                    row.text(0).expect("device id").parse().expect("uuid"),
                    row.text(1).expect("user id").parse().expect("uuid"),
                    row.i64(2).unwrap_or(0) != 0,
                    row.text(3).map(str::to_string),
                    row.text(4).is_some(),
                )
            })
            .collect()
    }

    /// Compare every observable piece of state with the model.
    async fn assert_observables(&self, model: &Model, context: &str) {
        // 1. SQL rows: exactly the four devices, with matching revocation
        //    flags, revoker and timestamp presence.
        let rows = self.stored_devices().await;
        assert_eq!(rows.len(), 4, "device row count {context}");
        let mut seen = BTreeSet::new();
        for dev in Dev::ALL {
            let id = self.device_id(dev);
            let row = rows
                .iter()
                .find(|row| row.0 == id)
                .unwrap_or_else(|| panic!("device {} is missing from SQL {context}", dev.name()));
            assert_eq!(
                row.2,
                model.revoked[dev.index()],
                "SQL revoked flag for {} {context}",
                dev.name()
            );
            assert_eq!(
                row.4,
                model.revoked[dev.index()],
                "SQL revoked_at presence for {} {context}",
                dev.name()
            );
            let expected_revoker =
                model.revoked_by[dev.index()].map(|actor| self.device_id(actor).to_string());
            assert_eq!(
                row.3,
                expected_revoker,
                "SQL revoked_by for {} {context}",
                dev.name()
            );
            assert_eq!(
                row.1,
                self.parties[dev.index()].user_id,
                "device {} changed owner {context}",
                dev.name()
            );
            assert!(seen.insert(id), "duplicate device row {context}");
        }

        // 2. The sled sentinel the request path actually consults.
        for dev in Dev::ALL {
            let present = self
                .state
                .store
                .exists(&format!("device:revoked:{}", self.device_id(dev)))
                .expect("read device sentinel");
            assert_eq!(
                present,
                model.revoked[dev.index()],
                "device:revoked sentinel for {} {context}",
                dev.name()
            );
        }

        // 3. Which token handles the server still accepts, at /devices. A live
        //    owner token also shows the listing, which is compared field by
        //    field against the model's revocation flags.
        for token in TokenRef::ALL {
            let live = model.is_live(token);
            let (status, _headers, body) = self.probe(token, Endpoint::Devices).await;
            assert_eq!(
                status == StatusCode::OK,
                live,
                "token {token:?} acceptance was {status:?}, model says live={live} {context}"
            );
            if live {
                self.assert_listing(model, token.device().owner(), &body, context)
                    .await;
            }
        }
    }

    /// After a successful revoke, every token of the target must be refused at
    /// **every** endpoint, not only the one this test happens to probe. Dead
    /// tokens of devices revoked earlier are covered at every step by the
    /// `/devices` probe above and by the alphabet's own commands.
    async fn assert_revoked_everywhere(&self, target: Dev, context: &str) {
        let refs: Vec<TokenRef> = TokenRef::ALL
            .into_iter()
            .filter(|token| token.device() == target)
            .collect();
        assert!(
            !refs.is_empty(),
            "every device has at least one token handle {context}"
        );
        for token in refs {
            for endpoint in Endpoint::ALL {
                let (status, _headers, _body) = self.probe(token, endpoint).await;
                assert_eq!(
                    status,
                    StatusCode::UNAUTHORIZED,
                    "revoked device {} still accepted token {token:?} at {endpoint:?} {context}",
                    target.name()
                );
            }
        }
    }
}

// ── Driver ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Coverage {
    statuses: BTreeSet<(&'static str, u16)>,
    /// Successful revokes that also revoked the actor's own device.
    self_revokes: usize,
    /// Successful revokes that left an account with no non-revoked device.
    account_left_deviceless: usize,
    /// Revokes refused because the target belonged to the other account.
    cross_account_rejections: usize,
    /// Revokes refused because the target was already revoked.
    already_revoked_rejections: usize,
    /// Logouts that killed exactly one token.
    logouts: usize,
}

async fn step(
    model: &mut Model,
    real: &mut Fixture,
    command: Command,
    keys: &Keys,
    coverage: &mut Coverage,
    context: &str,
) {
    let before_revoked: [bool; 4] = std::array::from_fn(|i| model.revoked[i]);
    let expected = model.apply(command);
    let (status, _body) = real.apply(command, keys).await;
    assert_eq!(
        status, expected,
        "status mismatch for {command:?} ({context})"
    );
    coverage.statuses.insert((command.kind(), status.as_u16()));

    match command {
        Command::Logout(token) if status == StatusCode::OK => {
            coverage.logouts += 1;
            // The model killed exactly this handle; the per-step probe already
            // checks that its sibling, if any, is still accepted.
            assert_eq!(
                model.slots[token.index()],
                Some(SlotState::Dead),
                "a successful logout must kill its own handle {context}"
            );
        }
        Command::Revoke { actor, target } if status == StatusCode::OK => {
            if actor.device() == target {
                coverage.self_revokes += 1;
            }
            if Dev::ALL
                .iter()
                .filter(|dev| dev.owner() == target.owner())
                .all(|dev| model.revoked[dev.index()])
            {
                coverage.account_left_deviceless += 1;
            }
            real.assert_revoked_everywhere(target, context).await;
        }
        Command::Revoke { actor: _, target } if status == StatusCode::FORBIDDEN => {
            coverage.cross_account_rejections += 1;
            assert_eq!(
                model.revoked[target.index()],
                before_revoked[target.index()],
                "a 403 must not change the target's revocation state {context}"
            );
        }
        Command::Revoke { actor: _, target } if status == StatusCode::BAD_REQUEST => {
            coverage.already_revoked_rejections += 1;
            assert!(
                before_revoked[target.index()],
                "a 400 implies an already-revoked target {context}"
            );
        }
        _ => {}
    }

    model.assert_invariants(context);
    real.assert_observables(model, context).await;
}

// ── Exhaustive bounded traces ───────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn every_bounded_revocation_trace_matches_the_model() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let keys = Keys::new();

    // Obtain one genuine nonce per device from the real endpoint. Every trace
    // re-arms its device's nonce under the same store key before logging in.
    let mut challenges = Vec::new();
    for _ in Dev::ALL {
        challenges.push(get_challenge(&app).await);
    }

    let depth = depth();
    let traces = sequences(depth);
    let mut steps = 0usize;
    let mut coverage = Coverage::default();

    for trace in &traces {
        let mut model = Model::default();
        let mut real = Fixture::new(state.clone(), app.clone(), &keys, &challenges).await;

        for (step_index, command) in trace.iter().enumerate() {
            let context = format!("at step {step_index} of {trace:?}");
            step(
                &mut model,
                &mut real,
                *command,
                &keys,
                &mut coverage,
                &context,
            )
            .await;
            steps += 1;
        }
    }

    // Non-vacuity: every command kind must have produced both an acceptance and
    // a refusal somewhere in the exploration. `Revoke 400/403` need three steps
    // (login, first revoke, second revoke) and every `Use*` success needs a
    // login first, so these claims are stated for the default depth and above.
    if depth >= 3 {
        for endpoint in Endpoint::ALL {
            let kind = endpoint.name();
            assert!(
                coverage
                    .statuses
                    .contains(&(kind, endpoint.success().as_u16())),
                "{kind} never succeeded: {:?}",
                coverage.statuses
            );
            assert!(
                coverage.statuses.contains(&(kind, 401u16)),
                "{kind} never refused a revoked or absent token: {:?}",
                coverage.statuses
            );
        }
        for (kind, code) in [
            ("Login", 200u16),
            ("Login", 401),
            ("Logout", 200),
            ("Logout", 401),
            ("Revoke", 200),
            ("Revoke", 400),
            ("Revoke", 401),
            ("Revoke", 403),
        ] {
            assert!(
                coverage.statuses.contains(&(kind, code)),
                "{kind} {code} was never exercised: {:?}",
                coverage.statuses
            );
        }
        assert!(coverage.logouts > 0, "no logout succeeded");
        assert!(coverage.self_revokes > 0, "no self-revoke was exercised");
        assert!(
            coverage.account_left_deviceless > 0,
            "no trace revoked an account's last non-revoked device"
        );
        assert!(
            coverage.cross_account_rejections > 0,
            "no cross-account revoke was attempted"
        );
        assert!(
            coverage.already_revoked_rejections > 0,
            "no already-revoked target was revoked twice"
        );
    } else {
        eprintln!(
            "non-vacuity coverage claims require depth >= 3; \
             this run only asserts trace/model agreement"
        );
    }

    eprintln!(
        "device revocation model: {} traces, {} steps, depth {} \
         ({} logouts, {} self-revokes, {} revokes that left an account deviceless, \
         {} cross-account rejections, {} already-revoked rejections)",
        traces.len(),
        steps,
        depth,
        coverage.logouts,
        coverage.self_revokes,
        coverage.account_left_deviceless,
        coverage.cross_account_rejections,
        coverage.already_revoked_rejections
    );
}

/// One readable end-to-end sequence, run at any depth. It drives the cases the
/// exhaustive search only reaches as fragments, and is the regression story for
/// the properties in the README.
#[tokio::test(flavor = "current_thread")]
async fn revoke_and_logout_invalidate_exactly_the_expected_authority() {
    use Command::*;
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let keys = Keys::new();
    let mut challenges = Vec::new();
    for _ in Dev::ALL {
        challenges.push(get_challenge(&app).await);
    }
    let mut model = Model::default();
    let mut real = Fixture::new(state.clone(), app.clone(), &keys, &challenges).await;
    let mut coverage = Coverage::default();

    let sequence = [
        // Two live tokens for A, one for each other device.
        Login(TokenRef::A0),
        Login(TokenRef::A1),
        Login(TokenRef::B0),
        Login(TokenRef::C0),
        Login(TokenRef::E0),
        Use {
            token: TokenRef::A0,
            endpoint: Endpoint::Devices,
        },
        Use {
            token: TokenRef::A1,
            endpoint: Endpoint::VaultEpoch,
        },
        Use {
            token: TokenRef::B0,
            endpoint: Endpoint::VaultChunkWrite,
        },
        // The other account's token authenticates normally on its own account.
        Use {
            token: TokenRef::E0,
            endpoint: Endpoint::Inbox,
        },
        // Logout kills exactly the addressed token; A0 dies, A1 keeps working.
        Logout(TokenRef::A0),
        Logout(TokenRef::A0),
        Use {
            token: TokenRef::A1,
            endpoint: Endpoint::Devices,
        },
        // Revoking B kills B's token everywhere and blocks B's next login.
        Revoke {
            actor: TokenRef::A1,
            target: Dev::B,
        },
        Use {
            token: TokenRef::B0,
            endpoint: Endpoint::Devices,
        },
        Login(TokenRef::B0),
        Revoke {
            actor: TokenRef::A1,
            target: Dev::B,
        },
        // Cross-account targets are refused, even for a revoked target.
        Revoke {
            actor: TokenRef::A1,
            target: Dev::E,
        },
        // Self-revoke succeeds and kills both of A's tokens.
        Revoke {
            actor: TokenRef::A1,
            target: Dev::A,
        },
        Use {
            token: TokenRef::A1,
            endpoint: Endpoint::Devices,
        },
        Use {
            token: TokenRef::A0,
            endpoint: Endpoint::Devices,
        },
        Login(TokenRef::A0),
        // A dead actor is refused by the middleware, not by the handler.
        Revoke {
            actor: TokenRef::A1,
            target: Dev::C,
        },
        Revoke {
            actor: TokenRef::B0,
            target: Dev::C,
        },
        // Cross-account precedence: A is revoked but E still may not touch it.
        Revoke {
            actor: TokenRef::E0,
            target: Dev::A,
        },
        // E self-revokes as the last device of its account.
        Revoke {
            actor: TokenRef::E0,
            target: Dev::E,
        },
        Revoke {
            actor: TokenRef::E0,
            target: Dev::E,
        },
        // C self-revokes as the last non-revoked device of the first account:
        // the server permits it, and the account is left with no usable device.
        Revoke {
            actor: TokenRef::C0,
            target: Dev::C,
        },
        Use {
            token: TokenRef::C0,
            endpoint: Endpoint::Devices,
        },
        Login(TokenRef::C0),
        Revoke {
            actor: TokenRef::C0,
            target: Dev::B,
        },
    ];

    for (step_index, command) in sequence.iter().enumerate() {
        let context = format!("at step {step_index} of the revocation regression sequence");
        step(
            &mut model,
            &mut real,
            *command,
            &keys,
            &mut coverage,
            &context,
        )
        .await;
    }

    assert_eq!(coverage.logouts, 1, "exactly one logout succeeded");
    assert!(
        coverage.statuses.contains(&("Logout", 401u16)),
        "the repeated logout was not refused: {:?}",
        coverage.statuses
    );
    assert!(coverage.self_revokes >= 2, "A and E self-revoked");
    assert_eq!(coverage.cross_account_rejections, 2);
    assert_eq!(coverage.already_revoked_rejections, 1);
    assert_eq!(
        coverage.account_left_deviceless, 2,
        "both accounts were left with no non-revoked device"
    );
    // Every device of both accounts is revoked and none can authenticate.
    for dev in Dev::ALL {
        assert!(
            model.revoked[dev.index()],
            "{} should be revoked",
            dev.name()
        );
    }
    for token in TokenRef::ALL {
        assert!(!model.is_live(token), "{token:?} should be dead");
    }
}

// ── Automatic renewal (no explicit refresh endpoint) ─────────────────────────

/// The server has no `refresh` route: `AuthSession` renews a device token when
/// less than five minutes remain and returns the replacement in `X-New-Token`,
/// revoking the old JTI. This test pins that a renewal neither escapes a later
/// device revocation nor revives a revoked device.
#[tokio::test(flavor = "current_thread")]
async fn automatic_renewal_stays_bound_to_the_device() {
    use vela_session_policy::{plan_device_token, TokenDecision};

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let keys = Keys::new();
    let mut challenges = Vec::new();
    for _ in Dev::ALL {
        challenges.push(get_challenge(&app).await);
    }
    let mut real = Fixture::new(state.clone(), app.clone(), &keys, &challenges).await;

    // Log in A and B for real.
    for token in [TokenRef::A0, TokenRef::B0] {
        assert_eq!(
            real.apply(Command::Login(token), &keys).await.0,
            StatusCode::OK,
            "login for {token:?}"
        );
    }
    let b_token = real.bearer(TokenRef::B0);

    // A token with 120 seconds left: inside the five-minute renewal window.
    let now = chrono::Utc::now().timestamp();
    let plan = match plan_device_token(now - (15 * 60) + 120, None) {
        TokenDecision::Issue(plan) => plan,
        TokenDecision::Reject => panic!("a near-expiry device plan must be issued"),
    };
    let ts = vela_server::auth::token::TokenService::new(
        state.paseto_sk.clone(),
        state.paseto_pk.clone(),
    );
    let a_device = real.device_id(Dev::A);
    let a_user = real.user_id(Owner::Alice);
    let (near_expiry, near_jti) = ts
        .issue_from_plan(a_user, a_device, plan)
        .expect("issue near-expiry token");
    vela_server::rate_limit::track_device_jti(&state.store, &a_device.to_string(), &near_jti)
        .expect("track near-expiry jti");

    let (status, headers, _body) = call(&app, "GET", "/devices", Some(&near_expiry), None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the near-expiry token must authenticate"
    );
    let refreshed = headers
        .get("X-New-Token")
        .expect("a token inside the renewal window must be renewed")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(refreshed, near_expiry, "renewal must issue a new token");

    // The old JTI is retired; the replacement works.
    assert_eq!(
        call(&app, "GET", "/devices", Some(&near_expiry), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "the renewed-away token must be refused"
    );
    assert_eq!(
        call(&app, "GET", "/vault/epoch", Some(&refreshed), None)
            .await
            .0,
        StatusCode::OK,
        "the replacement must carry the same device authority"
    );

    // Revoking A kills the replacement too: middleware registered its JTI with
    // the device before handing it back.
    assert_eq!(
        call(
            &app,
            "POST",
            "/device/revoke",
            Some(&b_token),
            Some(json!({ "target_device_id": a_device })),
        )
        .await
        .0,
        StatusCode::OK
    );
    for endpoint in Endpoint::ALL {
        let (method, uri) = match endpoint {
            Endpoint::Devices => ("GET", "/devices".to_string()),
            Endpoint::VaultEpoch => ("GET", "/vault/epoch".to_string()),
            Endpoint::Inbox => ("GET", "/share/inbox".to_string()),
            Endpoint::VaultChunkWrite => ("PUT", "/vault/chunk/revocation-probe".to_string()),
        };
        assert_eq!(
            call(&app, method, &uri, Some(&refreshed), None).await.0,
            StatusCode::UNAUTHORIZED,
            "a renewed token must die with its device at {endpoint:?}"
        );
        assert_eq!(
            call(&app, method, &uri, Some(&near_expiry), None).await.0,
            StatusCode::UNAUTHORIZED,
            "the renewed-away token must stay dead at {endpoint:?}"
        );
    }
    // And A cannot mint another one.
    assert_eq!(
        real.apply(Command::Login(TokenRef::A0), &keys).await.0,
        StatusCode::UNAUTHORIZED
    );
}

// ── The sentinel covers a token that escaped JTI enumeration ────────────────

/// `post_revoke` deliberately writes the device sentinel **after** enumerating
/// `device:jtis:{id}` and **before** flipping the SQL flag, because the
/// middleware consults both records. A token issued in the window between the
/// enumeration and the sentinel write would not be in the JTI set; the sentinel
/// is what stops it. Concurrency cannot be interleaved deterministically here,
/// so this test projects the race sequentially: issue a valid device token and
/// deliberately do not register its JTI, then revoke the device. The sentinel
/// must be the only thing standing between that token and the vault.
#[tokio::test(flavor = "current_thread")]
async fn the_device_sentinel_stops_a_token_that_escaped_jti_enumeration() {
    use vela_session_policy::{plan_device_token, TokenDecision};

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let keys = Keys::new();
    let mut challenges = Vec::new();
    for _ in Dev::ALL {
        challenges.push(get_challenge(&app).await);
    }
    let mut real = Fixture::new(state.clone(), app.clone(), &keys, &challenges).await;

    // B is the live actor that performs the revocation.
    assert_eq!(
        real.apply(Command::Login(TokenRef::B0), &keys).await.0,
        StatusCode::OK
    );
    let b_token = real.bearer(TokenRef::B0);

    // A valid A token that is deliberately *not* in `device:jtis:{A}`.
    let now = chrono::Utc::now().timestamp();
    let plan = match plan_device_token(now, None) {
        TokenDecision::Issue(plan) => plan,
        TokenDecision::Reject => panic!("a device plan must be issued"),
    };
    let ts = vela_server::auth::token::TokenService::new(
        state.paseto_sk.clone(),
        state.paseto_pk.clone(),
    );
    let a_device = real.device_id(Dev::A);
    let a_user = real.user_id(Owner::Alice);
    let (untracked, _jti) = ts
        .issue_from_plan(a_user, a_device, plan)
        .expect("issue untracked token");
    assert!(
        state
            .store
            .smembers(&format!("device:jtis:{a_device}"))
            .expect("read jti set")
            .is_empty(),
        "the fixture must not have registered A's JTI for this test"
    );
    assert_eq!(
        call(&app, "GET", "/devices", Some(&untracked), None)
            .await
            .0,
        StatusCode::OK,
        "the untracked token must work before revocation"
    );

    assert_eq!(
        call(
            &app,
            "POST",
            "/device/revoke",
            Some(&b_token),
            Some(json!({ "target_device_id": a_device })),
        )
        .await
        .0,
        StatusCode::OK
    );

    // No JTI marker exists for it: only `device:revoked:{A}` can refuse it.
    assert!(
        state
            .store
            .smembers(&format!("device:jtis:{a_device}"))
            .expect("read jti set")
            .is_empty(),
        "revocation enumerates and then deletes the tracked set"
    );
    for endpoint in Endpoint::ALL {
        let (method, uri) = match endpoint {
            Endpoint::Devices => ("GET", "/devices".to_string()),
            Endpoint::VaultEpoch => ("GET", "/vault/epoch".to_string()),
            Endpoint::Inbox => ("GET", "/share/inbox".to_string()),
            Endpoint::VaultChunkWrite => ("PUT", "/vault/chunk/revocation-probe".to_string()),
        };
        assert_eq!(
            call(&app, method, &uri, Some(&untracked), None).await.0,
            StatusCode::UNAUTHORIZED,
            "a token outside the JTI set survived revocation at {endpoint:?}"
        );
    }
}
