//! Bounded conformance of every consumer of a `/auth/challenge` nonce against
//! a single-use reference model, plus a real-concurrency redemption test.
//!
//! The nonce is issued by `GET /auth/challenge` as `challenge:<b64>` in sled
//! (`src/auth/challenge.rs`), tagged with its purpose (`?purpose=`), and
//! consumed with `Store::get_del`. Three handlers read that namespace, each
//! accepting only its own purpose:
//!
//! - `POST /auth/verify`                    (`src/auth/verify.rs`)
//! - `POST /device/enroll`                  (`src/device/enroll.rs`)
//! - `POST /web-session/:id/token`          (`src/web_session/mod.rs`)
//!
//! The recovery handlers (`src/recovery/initiate.rs`, `src/recovery/possess.rs`,
//! `src/recovery/enroll-device` in `recover.rs`) also call `get_del`, but over
//! their own attempt-bound keys (`recovery:webauthn:auth:{user}:{id}`,
//! `recovery:possess:proof:{user}:{id}`, `recovery:enroll_grant:{user}:{grant}`)
//! and never a `challenge:` key. `challenge_single_use_model` therefore models
//! the three handlers above; the recovery keys are covered by
//! `recovery_possession_model.rs` and the recovery integration tests.
//!
//! ## Reference model
//!
//! A challenge is a linear token: issuing one makes a *fresh* token, presenting
//! it at any endpoint consumes it **before** the proof is checked (the handlers
//! call `get_del` before device lookup / signature verification), and every
//! later presentation of that token — at any endpoint, with any proof — is
//! refused. Each nonce is issued for one endpoint: presenting it elsewhere is
//! refused even with a valid proof, and that refusal spends it (U-16).
//!
//! The model keeps every issued token, not just the latest per slot: issuing a
//! second nonce into a slot does not revoke the first one, so the first remains
//! live and present in the store until it is consumed or expires. That is the
//! server's actual behaviour and the model asserts it after every step.
//!
//! ## Exploration
//!
//! Every command sequence up to `VELA_CHALLENGE_MODEL_DEPTH` (default 3) over a
//! 23-command alphabet runs against the model and against the real Axum router
//! with the real Turso schema and sled store. After every step the test compares
//! the HTTP status and the presence of every issued challenge key.
//!
//! The alphabet issues real nonces obtained from `GET /auth/challenge` before
//! the exploration. Re-issuing a *pre-issued* nonce for an independent trace is
//! what makes the valid signatures precomputable; every nonce in the pool was
//! produced by the real endpoint and every trace is independent.
//!
//! ## Not covered
//!
//! Signature-scheme security, TTL races beyond "key absent", multi-node or
//! distributed stores, crash/restart between `get_del` and the response, and
//! proof/authorization checks inside each endpoint. This is bounded executable
//! evidence, not a proof.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

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
    auth_message, enrollment_message, generate_keypair, sign, HybridSigningKey,
};
use vela_server::sqldb::{Db as _, TursoDb, TursoValue};
use vela_server::{config, state::AppStateInner, store::Store};

mod helpers;

const DEFAULT_DEPTH: usize = 3;

fn depth() -> usize {
    std::env::var("VELA_CHALLENGE_MODEL_DEPTH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_DEPTH)
}

const SLOTS: usize = 2;
/// Concurrent presentations per round.
const CONCURRENCY: usize = 16;
/// Rounds in which every request targets the same endpoint.
const SAME_ENDPOINT_ROUNDS: usize = 6;
/// Rounds mixing all three endpoints.
const MIXED_ROUNDS: usize = 24;

// ── Command alphabet ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Endpoint {
    Verify,
    Enroll,
    WebToken,
}

const ENDPOINTS: [Endpoint; 3] = [Endpoint::Verify, Endpoint::Enroll, Endpoint::WebToken];

impl Endpoint {
    /// The `/auth/challenge?purpose=` value and stored tag for this endpoint.
    fn purpose(self) -> &'static str {
        match self {
            Endpoint::Verify => "login",
            Endpoint::Enroll => "enroll",
            Endpoint::WebToken => "web_token",
        }
    }

    fn tag(self) -> &'static [u8] {
        self.purpose().as_bytes()
    }

    fn name(self) -> &'static str {
        match self {
            Endpoint::Verify => "PresentVerify",
            Endpoint::Enroll => "PresentEnroll",
            Endpoint::WebToken => "PresentWebToken",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    /// Issue a fresh nonce for one endpoint's purpose into a slot (real
    /// `GET /auth/challenge` output, re-armed under the same store key with
    /// that purpose's tag).
    Issue(usize, Endpoint),
    /// Present the slot's latest nonce at an endpoint, with a valid proof for
    /// that endpoint or a well-formed invalid one.
    Present {
        slot: usize,
        endpoint: Endpoint,
        honest: bool,
    },
    /// Present a nonce that was never issued.
    PresentUnknown { endpoint: Endpoint },
    /// Simulate the 60-second TTL elapsing: remove the key without consuming it.
    Expire(usize),
}

impl Command {
    fn kind(self) -> &'static str {
        match self {
            Command::Issue(..) => "Issue",
            Command::Expire(_) => "Expire",
            Command::PresentUnknown { endpoint } => match endpoint {
                Endpoint::Verify => "PresentUnknownVerify",
                Endpoint::Enroll => "PresentUnknownEnroll",
                Endpoint::WebToken => "PresentUnknownWebToken",
            },
            Command::Present { endpoint, .. } => endpoint.name(),
        }
    }
}

fn alphabet() -> Vec<Command> {
    use Command::*;
    let mut out = Vec::new();
    for slot in 0..SLOTS {
        for endpoint in ENDPOINTS {
            out.push(Issue(slot, endpoint));
        }
        out.push(Expire(slot));
    }
    for slot in 0..SLOTS {
        for endpoint in ENDPOINTS {
            out.push(Present {
                slot,
                endpoint,
                honest: true,
            });
            out.push(Present {
                slot,
                endpoint,
                honest: false,
            });
        }
    }
    for endpoint in ENDPOINTS {
        out.push(PresentUnknown { endpoint });
    }
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
enum ChallengeState {
    Live,
    Consumed,
    Expired,
}

#[derive(Clone, Debug, Default)]
struct Model {
    /// Next fresh nonce index for each slot.
    next_index: [usize; SLOTS],
    /// Latest nonce index issued into each slot.
    current: [Option<usize>; SLOTS],
    /// Every nonce ever issued in this trace: `(slot, index) -> state`.
    issued: BTreeMap<(usize, usize), ChallengeState>,
    /// The endpoint each nonce was issued for.
    purpose: BTreeMap<(usize, usize), Endpoint>,
    /// Successful presentations per nonce. Must never exceed 1.
    successes: BTreeMap<(usize, usize), u32>,
}

impl Model {
    fn apply(&mut self, command: Command) -> Option<StatusCode> {
        match command {
            Command::Issue(slot, purpose) => {
                let index = self.next_index[slot];
                self.next_index[slot] += 1;
                self.current[slot] = Some(index);
                self.issued.insert((slot, index), ChallengeState::Live);
                self.purpose.insert((slot, index), purpose);
                // Issuing is not an HTTP command.
                None
            }
            Command::Expire(slot) => {
                if let Some(index) = self.current[slot] {
                    if let Some(state) = self.issued.get_mut(&(slot, index)) {
                        if *state == ChallengeState::Live {
                            *state = ChallengeState::Expired;
                        }
                    }
                }
                None
            }
            Command::PresentUnknown { .. } => Some(StatusCode::UNAUTHORIZED),
            Command::Present {
                slot,
                endpoint,
                honest,
            } => {
                let Some(index) = self.current[slot] else {
                    return Some(StatusCode::UNAUTHORIZED);
                };
                match self.issued.get(&(slot, index)).copied() {
                    Some(ChallengeState::Live) => {
                        // Consumed on presentation, whatever the proof or the
                        // endpoint; accepted only at the endpoint it was
                        // issued for.
                        self.issued.insert((slot, index), ChallengeState::Consumed);
                        if honest && self.purpose.get(&(slot, index)) == Some(&endpoint) {
                            *self.successes.entry((slot, index)).or_insert(0) += 1;
                            Some(StatusCode::OK)
                        } else {
                            Some(StatusCode::UNAUTHORIZED)
                        }
                    }
                    _ => Some(StatusCode::UNAUTHORIZED),
                }
            }
        }
    }

    fn current_state(&self, slot: usize) -> Option<ChallengeState> {
        let index = self.current[slot]?;
        self.issued.get(&(slot, index)).copied()
    }

    fn current_purpose(&self, slot: usize) -> Option<Endpoint> {
        let index = self.current[slot]?;
        self.purpose.get(&(slot, index)).copied()
    }

    fn assert_state(&self, fixture: &Fixture, trace: &[Command], step: usize) {
        for (&(slot, index), &expected) in &self.issued {
            let key = fixture.challenge_key(slot, index);
            let present = fixture
                .state
                .store
                .get(&key)
                .unwrap_or_else(|e| panic!("store read for {key} failed: {e}"))
                .is_some();
            assert_eq!(
                present,
                expected == ChallengeState::Live,
                "challenge ({slot},{index}) store presence should be {} but was {present} \
                 (state {expected:?}) at step {step} of {trace:?}",
                expected == ChallengeState::Live
            );
        }
        for (&(slot, index), &successes) in &self.successes {
            assert!(
                successes <= 1,
                "challenge ({slot},{index}) was accepted {successes} times at step {step} of {trace:?}"
            );
        }
    }
}

// ── Real system ─────────────────────────────────────────────────────────────

static NEXT_IP: AtomicU32 = AtomicU32::new(1);

/// A distinct source address per request keeps the per-IP limits out of the
/// way; the per-session web-token budget is reset per trace/round below.
/// The counter is offset by one so the first address is not `10.0.0.0`, and
/// three varying octets make collisions impossible for the ~350k requests a
/// depth-4 run sends.
fn fresh_ip() -> ConnectInfo<SocketAddr> {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed) + 1;
    let [_, b, c, d] = n.to_be_bytes();
    ConnectInfo(SocketAddr::from(([10, b, c, d], 40000)))
}

/// Run `f` on an 8 MiB stack. ML-DSA keygen/signing in `vela-crypto` is stack
/// hungry; the same workaround is used by `tests/integration.rs`.
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

#[derive(Clone, Debug)]
struct PooledChallenge {
    b64: String,
    bytes: Vec<u8>,
    /// Signature under the enrolled device key over `auth_message(device_id, nonce)`.
    /// (`/auth/verify` and `/device/enroll` use the same transcript.)
    device_sig: String,
    /// Signature under the web session's ephemeral key over
    /// `auth_message(session_id, nonce)`.
    web_sig: String,
}

#[derive(Clone, Debug)]
struct EnrollPayload {
    ek: Vec<u8>,
    vk: Vec<u8>,
    capsule: Vec<u8>,
    signature: String,
}

struct Fixture {
    app: Router,
    state: vela_server::state::AppState,
    device_id: Uuid,
    device_id_str: String,
    web_session_id: Uuid,
    web_session_id_str: String,
    device_sk: HybridSigningKey,
    web_sk: HybridSigningKey,
    /// `[slot][issue-index]`; every nonce was returned by `GET /auth/challenge`.
    pool: Vec<Vec<PooledChallenge>>,
    unknown_b64: String,
    wrong_device_sig: String,
    wrong_web_sig: String,
    enroll: EnrollPayload,
}

impl Fixture {
    async fn new(state: vela_server::state::AppState, app: Router, depth: usize) -> Self {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let device_id_str = device_id.to_string();
        let web_session_id = Uuid::new_v4();
        let web_session_id_str = web_session_id.to_string();
        let now = chrono::Utc::now();

        let (device_vk, device_sk, web_vk, web_sk) = with_big_stack(|| {
            let (device_vk, device_sk) = generate_keypair().expect("device keygen");
            let (web_vk, web_sk) = generate_keypair().expect("web keygen");
            (device_vk, device_sk, web_vk, web_sk)
        });

        state
            .sqldb
            .execute(
                "INSERT INTO users (id, created_at, key_epoch) VALUES (?, ?, 1)",
                vec![
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Text(now.to_rfc3339()),
                ],
            )
            .await
            .expect("insert user");

        state
            .sqldb
            .execute(
                "INSERT INTO devices
                 (id, user_id, device_name, device_type, last_active, hybrid_ek,
                  hybrid_vk, enrolled_by, created_at)
                 VALUES (?, ?, 'challenge-model', 'desktop', NULL, ?, ?, NULL, ?)",
                vec![
                    TursoValue::Text(device_id_str.clone()),
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Text(B64.encode([1u8; 1568 + 32])),
                    TursoValue::Text(B64.encode(device_vk.to_bytes())),
                    TursoValue::Text(now.to_rfc3339()),
                ],
            )
            .await
            .expect("insert device");

        // A granted RW web session. Driving `/web-session/start` + `/grant`
        // would only re-test the grant path; the token handler is what consumes
        // the challenge, so the row is inserted in exactly the state a grant
        // leaves behind (M12 `RWGranted`).
        state
            .sqldb
            .execute(
                "INSERT INTO web_sessions
                 (id, user_id, approver_user_id, poll_secret_hash, ephemeral_pk,
                  web_vk, link_nonce, mode, status, capsule, approved_by,
                  key_epoch, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'rw', 'granted', NULL, ?, 1, ?, ?)",
                vec![
                    TursoValue::Text(web_session_id_str.clone()),
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Text(B64.encode([2u8; 32])),
                    TursoValue::Text(B64.encode([3u8; 1568 + 32])),
                    TursoValue::Text(B64.encode(web_vk.to_bytes())),
                    TursoValue::Text(B64.encode([4u8; 32])),
                    TursoValue::Text(device_id_str.clone()),
                    TursoValue::Text(now.to_rfc3339()),
                    TursoValue::Text((now + chrono::Duration::hours(1)).to_rfc3339()),
                ],
            )
            .await
            .expect("insert granted web session");

        // Obtain `SLOTS * depth` genuine nonces from the real endpoint before the
        // exploration. Each call uses a fresh source address, so the 20/min
        // per-IP issuance limit never binds.
        let mut raw_pool: Vec<Vec<(String, Vec<u8>)>> = vec![Vec::new(); SLOTS];
        for slot in 0..SLOTS {
            for _ in 0..depth.max(1) {
                let (b64, bytes) = get_challenge(&app, Endpoint::Verify).await;
                raw_pool[slot].push((b64, bytes));
            }
        }

        // Start each trace from an empty challenge namespace.
        for slot in &raw_pool {
            for (b64, _) in slot {
                state
                    .store
                    .del(&format!("challenge:{b64}"))
                    .expect("clear setup nonce");
            }
        }

        let enroll_ek = vec![5u8; 1568 + 32];
        let enroll_vk = vec![6u8; 2592 + 32];
        let enroll_capsule = b"challenge-single-use-model-capsule".to_vec();

        let (pool, wrong_device_sig, wrong_web_sig, enroll_signature) = with_big_stack(|| {
            let device_sig = |challenge: &[u8]| {
                B64.encode(
                    sign(&device_sk, &auth_message(&device_id_str, challenge))
                        .expect("device sign")
                        .to_bytes(),
                )
            };
            let web_sig = |challenge: &[u8]| {
                B64.encode(
                    sign(&web_sk, &auth_message(&web_session_id_str, challenge))
                        .expect("web sign")
                        .to_bytes(),
                )
            };

            let pool: Vec<Vec<PooledChallenge>> = raw_pool
                .into_iter()
                .map(|slot| {
                    slot.into_iter()
                        .map(|(b64, bytes)| PooledChallenge {
                            device_sig: device_sig(&bytes),
                            web_sig: web_sig(&bytes),
                            b64,
                            bytes,
                        })
                        .collect()
                })
                .collect();

            let enroll_signature = B64.encode(
                sign(
                    &device_sk,
                    &enrollment_message(&enroll_ek, &enroll_vk, &enroll_capsule),
                )
                .expect("enrollment sign")
                .to_bytes(),
            );
            let wrong_device_sig = device_sig(&[0u8; 32]);
            let wrong_web_sig = web_sig(&[0u8; 32]);
            (pool, wrong_device_sig, wrong_web_sig, enroll_signature)
        });

        let mut seen = BTreeSet::new();
        for slot in &pool {
            for challenge in slot {
                assert_eq!(challenge.bytes.len(), 32, "a challenge must be 32 bytes");
                assert!(
                    seen.insert(challenge.b64.clone()),
                    "the endpoint returned a duplicate nonce"
                );
            }
        }
        let unknown_b64 = B64.encode([0u8; 32]);
        assert!(
            !seen.contains(&unknown_b64),
            "the never-issued nonce collided with a pooled one"
        );

        Self {
            app,
            state,
            device_id,
            device_id_str,
            web_session_id,
            web_session_id_str,
            device_sk,
            web_sk,
            pool,
            unknown_b64,
            wrong_device_sig,
            wrong_web_sig,
            enroll: EnrollPayload {
                ek: enroll_ek,
                vk: enroll_vk,
                capsule: enroll_capsule,
                signature: enroll_signature,
            },
        }
    }

    fn challenge_key(&self, slot: usize, index: usize) -> String {
        format!("challenge:{}", self.pool[slot][index].b64)
    }

    fn device_signature(&self, challenge: &[u8]) -> String {
        with_big_stack(|| {
            B64.encode(
                sign(
                    &self.device_sk,
                    &auth_message(&self.device_id_str, challenge),
                )
                .expect("device sign")
                .to_bytes(),
            )
        })
    }

    fn web_signature(&self, challenge: &[u8]) -> String {
        with_big_stack(|| {
            B64.encode(
                sign(
                    &self.web_sk,
                    &auth_message(&self.web_session_id_str, challenge),
                )
                .expect("web sign")
                .to_bytes(),
            )
        })
    }

    async fn issue_challenge(&self, endpoint: Endpoint) -> (String, Vec<u8>) {
        get_challenge(&self.app, endpoint).await
    }

    /// Clear the challenge namespace and the web-token per-session budget so a
    /// trace/round starts from the same state as the model.
    fn reset(&self) {
        for slot in &self.pool {
            for challenge in slot {
                self.state
                    .store
                    .del(&format!("challenge:{}", challenge.b64))
                    .expect("clear challenge key");
            }
        }
        self.state
            .store
            .del(&format!("rl:websession:token:{}", self.web_session_id))
            .expect("clear web-token budget");
    }

    fn present_request(
        &self,
        endpoint: Endpoint,
        challenge_b64: &str,
        signature: &str,
    ) -> Request<Body> {
        let (uri, body) = match endpoint {
            Endpoint::Verify => (
                "/auth/verify".to_string(),
                json!({
                    "device_id": self.device_id,
                    "challenge": challenge_b64,
                    "signature": signature,
                }),
            ),
            Endpoint::Enroll => (
                "/device/enroll".to_string(),
                json!({
                    "enrolling_device_id": self.device_id,
                    "challenge": challenge_b64,
                    "auth_signature": signature,
                    "new_device": {
                        "hybrid_ek": B64.encode(&self.enroll.ek),
                        "hybrid_vk": B64.encode(&self.enroll.vk),
                        "rms_capsule": B64.encode(&self.enroll.capsule),
                        "key_epoch": 1,
                        "signature": self.enroll.signature,
                        "device_name": "challenge-model",
                        "device_type": "desktop",
                    },
                }),
            ),
            Endpoint::WebToken => (
                format!("/web-session/{}/token", self.web_session_id),
                json!({
                    "challenge": challenge_b64,
                    "signature": signature,
                }),
            ),
        };
        Request::builder()
            .method("POST")
            .uri(uri)
            .extension(fresh_ip())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build request")
    }
}

async fn get_challenge(app: &Router, endpoint: Endpoint) -> (String, Vec<u8>) {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/auth/challenge?purpose={}", endpoint.purpose()))
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

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

struct TraceReal<'a> {
    fixture: &'a Fixture,
    next_index: [usize; SLOTS],
    current: [Option<usize>; SLOTS],
}

impl<'a> TraceReal<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        fixture.reset();
        Self {
            fixture,
            next_index: [0; SLOTS],
            current: [None; SLOTS],
        }
    }

    async fn apply(&mut self, command: Command) -> Option<StatusCode> {
        match command {
            Command::Issue(slot, purpose) => {
                let index = self.next_index[slot];
                assert!(
                    index < self.fixture.pool[slot].len(),
                    "trace issues more nonces than the pool holds"
                );
                self.next_index[slot] += 1;
                self.current[slot] = Some(index);
                self.fixture
                    .state
                    .store
                    .set_ex(
                        &self.fixture.challenge_key(slot, index),
                        purpose.tag(),
                        60,
                    )
                    .expect("re-arm pre-issued challenge");
                None
            }
            Command::Expire(slot) => {
                if let Some(index) = self.current[slot] {
                    self.fixture
                        .state
                        .store
                        .del(&self.fixture.challenge_key(slot, index))
                        .expect("expire challenge");
                }
                None
            }
            Command::PresentUnknown { endpoint } => {
                let signature = match endpoint {
                    Endpoint::WebToken => &self.fixture.wrong_web_sig,
                    _ => &self.fixture.wrong_device_sig,
                };
                let request =
                    self.fixture
                        .present_request(endpoint, &self.fixture.unknown_b64, signature);
                Some(send(&self.fixture.app, request).await.0)
            }
            Command::Present {
                slot,
                endpoint,
                honest,
            } => {
                let (challenge_b64, signature) = match self.current[slot] {
                    Some(index) => {
                        let challenge = &self.fixture.pool[slot][index];
                        let signature = if honest {
                            match endpoint {
                                Endpoint::WebToken => challenge.web_sig.clone(),
                                _ => challenge.device_sig.clone(),
                            }
                        } else {
                            match endpoint {
                                Endpoint::WebToken => self.fixture.wrong_web_sig.clone(),
                                _ => self.fixture.wrong_device_sig.clone(),
                            }
                        };
                        (challenge.b64.clone(), signature)
                    }
                    // The model refuses a presentation with no current nonce;
                    // send a never-issued one so the real system refuses it too.
                    None => (
                        self.fixture.unknown_b64.clone(),
                        match endpoint {
                            Endpoint::WebToken => self.fixture.wrong_web_sig.clone(),
                            _ => self.fixture.wrong_device_sig.clone(),
                        },
                    ),
                };
                let request = self
                    .fixture
                    .present_request(endpoint, &challenge_b64, &signature);
                Some(send(&self.fixture.app, request).await.0)
            }
        }
    }
}

// ── Exhaustive bounded traces ───────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn every_bounded_challenge_trace_matches_the_single_use_model() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let depth = depth();
    let fixture = Fixture::new(state.clone(), app, depth).await;
    let traces = sequences(depth);
    let mut steps = 0usize;
    let mut seen: BTreeSet<(&'static str, u16)> = BTreeSet::new();
    let mut no_status: BTreeSet<&'static str> = BTreeSet::new();
    let mut dead_presentations = 0usize;
    let mut cross_purpose_refusals = 0usize;

    for trace in &traces {
        let mut model = Model::default();
        let mut real = TraceReal::new(&fixture);
        for (step, command) in trace.iter().enumerate() {
            // Was this presentation aimed at a challenge that was already
            // consumed or expired? Count it to prove replay is exercised.
            if let Command::Present {
                slot,
                endpoint,
                honest,
            } = command
            {
                if matches!(
                    model.current_state(*slot),
                    Some(ChallengeState::Consumed) | Some(ChallengeState::Expired)
                ) {
                    dead_presentations += 1;
                }
                if *honest
                    && model.current_state(*slot) == Some(ChallengeState::Live)
                    && model.current_purpose(*slot) != Some(*endpoint)
                {
                    cross_purpose_refusals += 1;
                }
            }

            let expected = model.apply(*command);
            let actual = real.apply(*command).await;
            assert_eq!(
                actual, expected,
                "status mismatch at step {step} of trace {trace:?} (command {command:?})"
            );
            if let Some(status) = actual {
                seen.insert((command.kind(), status.as_u16()));
            } else {
                no_status.insert(command.kind());
            }
            model.assert_state(&fixture, trace, step);
            steps += 1;
        }
    }

    // Non-vacuity: every command kind reaches both acceptance and refusal.
    for endpoint in ENDPOINTS {
        let kind = endpoint.name();
        for code in [200u16, 401] {
            assert!(
                seen.contains(&(kind, code)),
                "{kind} never produced {code}: {seen:?}"
            );
        }
        assert!(
            seen.contains(&(
                match endpoint {
                    Endpoint::Verify => "PresentUnknownVerify",
                    Endpoint::Enroll => "PresentUnknownEnroll",
                    Endpoint::WebToken => "PresentUnknownWebToken",
                },
                401u16,
            )),
            "an unknown nonce was never presented at {endpoint:?}: {seen:?}"
        );
    }
    assert!(
        cross_purpose_refusals > 0,
        "no live nonce was ever presented at the wrong endpoint with a valid proof"
    );
    assert!(
        no_status.contains("Issue"),
        "no challenge was ever issued: {no_status:?}"
    );
    assert!(
        no_status.contains("Expire"),
        "no challenge was ever expired: {no_status:?}"
    );
    assert!(
        dead_presentations > 0,
        "replay of a dead challenge was never exercised"
    );

    eprintln!(
        "challenge single-use model: {} traces, {} steps, depth {}, {} dead-challenge presentations",
        traces.len(),
        steps,
        depth,
        dead_presentations
    );
}

// ── Focused semantics ───────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn failed_or_unknown_or_expired_or_replayed_challenges_never_succeed() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let fixture = Fixture::new(state.clone(), app.clone(), 2).await;

    // (1) Every consumer burns the nonce before checking the proof: an invalid
    //     proof returns 401 and leaves no challenge behind, and a subsequent
    //     valid proof of the same nonce is also refused.
    for endpoint in ENDPOINTS {
        let (challenge_b64, challenge_bytes) = fixture.issue_challenge(endpoint).await;
        assert!(
            state
                .store
                .get(&format!("challenge:{challenge_b64}"))
                .unwrap()
                .is_some(),
            "GET /auth/challenge did not store challenge:{challenge_b64}"
        );
        let (valid, invalid) = match endpoint {
            Endpoint::Verify | Endpoint::Enroll => (
                fixture.device_signature(&challenge_bytes),
                fixture.wrong_device_sig.clone(),
            ),
            Endpoint::WebToken => (
                fixture.web_signature(&challenge_bytes),
                fixture.wrong_web_sig.clone(),
            ),
        };
        assert_eq!(
            send(
                &app,
                fixture.present_request(endpoint, &challenge_b64, &invalid)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED,
            "{endpoint:?} accepted an invalid proof"
        );
        assert!(
            state
                .store
                .get(&format!("challenge:{challenge_b64}"))
                .unwrap()
                .is_none(),
            "{endpoint:?} did not consume the challenge on an invalid proof"
        );
        assert_eq!(
            send(
                &app,
                fixture.present_request(endpoint, &challenge_b64, &valid)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED,
            "{endpoint:?} accepted a replay after a failed proof"
        );
    }

    // (2) A successful login burns the nonce for every other endpoint too.
    let (challenge_b64, challenge_bytes) = fixture.issue_challenge(Endpoint::Verify).await;
    let valid = fixture.device_signature(&challenge_bytes);
    assert_eq!(
        send(
            &app,
            fixture.present_request(Endpoint::Verify, &challenge_b64, &valid)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            fixture.present_request(Endpoint::Enroll, &challenge_b64, &valid)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "a login challenge was accepted for device enrollment"
    );
    assert_eq!(
        send(
            &app,
            fixture.present_request(Endpoint::Verify, &challenge_b64, &valid)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "a login challenge was accepted twice"
    );

    // (2b) U-16: a nonce issued for one endpoint is refused at every other
    //      endpoint even with a valid proof, and that refusal spends it.
    for issued in ENDPOINTS {
        for presented in ENDPOINTS {
            if issued == presented {
                continue;
            }
            let (b64, bytes) = fixture.issue_challenge(issued).await;
            let valid = match presented {
                Endpoint::WebToken => fixture.web_signature(&bytes),
                _ => fixture.device_signature(&bytes),
            };
            assert_eq!(
                send(&app, fixture.present_request(presented, &b64, &valid))
                    .await
                    .0,
                StatusCode::UNAUTHORIZED,
                "a {issued:?} nonce was accepted at {presented:?}"
            );
            assert!(
                state.store.get(&format!("challenge:{b64}")).unwrap().is_none(),
                "a cross-purpose presentation at {presented:?} did not spend the nonce"
            );
            let own = match issued {
                Endpoint::WebToken => fixture.web_signature(&bytes),
                _ => fixture.device_signature(&bytes),
            };
            assert_eq!(
                send(&app, fixture.present_request(issued, &b64, &own))
                    .await
                    .0,
                StatusCode::UNAUTHORIZED,
                "a spent {issued:?} nonce was accepted at its own endpoint"
            );
        }
    }

    // (3) An expired (removed) challenge never succeeds.
    let (expired_b64, expired_bytes) = fixture.issue_challenge(Endpoint::Verify).await;
    let expired_valid = fixture.device_signature(&expired_bytes);
    state
        .store
        .del(&format!("challenge:{expired_b64}"))
        .expect("simulate expiry");
    assert_eq!(
        send(
            &app,
            fixture.present_request(Endpoint::Verify, &expired_b64, &expired_valid)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );

    // (4) A nonce that was never issued never succeeds at any endpoint.
    for endpoint in ENDPOINTS {
        let signature = match endpoint {
            Endpoint::WebToken => fixture.wrong_web_sig.clone(),
            _ => fixture.wrong_device_sig.clone(),
        };
        assert_eq!(
            send(
                &app,
                fixture.present_request(endpoint, &fixture.unknown_b64, &signature)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED,
            "{endpoint:?} accepted a nonce it never issued"
        );
    }

    // (5) A web-token request refused *before* the challenge lookup must not
    //     burn the nonce: `post_token` checks session status/mode/expiry first
    //     and only then calls get_del. The model's web-token command always
    //     presents against a valid session, so pin the ordering explicitly.
    let (precheck_b64, precheck_bytes) = fixture.issue_challenge(Endpoint::WebToken).await;
    let precheck_valid = fixture.web_signature(&precheck_bytes);
    state
        .sqldb
        .execute(
            "UPDATE web_sessions SET status = 'pending' WHERE id = ?",
            vec![TursoValue::Text(fixture.web_session_id.to_string())],
        )
        .await
        .expect("park web session");
    assert_eq!(
        send(
            &app,
            fixture.present_request(Endpoint::WebToken, &precheck_b64, &precheck_valid)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "a pending web session accepted a token exchange"
    );
    assert!(
        state
            .store
            .get(&format!("challenge:{precheck_b64}"))
            .unwrap()
            .is_some(),
        "a session-status rejection before get_del must not consume the challenge"
    );
    state
        .sqldb
        .execute(
            "UPDATE web_sessions SET status = 'granted' WHERE id = ?",
            vec![TursoValue::Text(fixture.web_session_id.to_string())],
        )
        .await
        .expect("restore web session");
    assert_eq!(
        send(
            &app,
            fixture.present_request(Endpoint::WebToken, &precheck_b64, &precheck_valid)
        )
        .await
        .0,
        StatusCode::OK,
        "the restored session could not exchange its still-live challenge"
    );
}

// ── Real concurrency ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_challenge_yields_exactly_one_success_under_concurrency() {
    // `helpers::test_state` opens Turso with a one-connection pool, which is
    // right for the sequential traces but makes genuinely concurrent session
    // lookups fail on a shared connection. Give this test one connection per
    // racing request so a 500 cannot masquerade as a refusal.
    let turso_path = format!(
        "{}/vela-challenge-concurrency-{}.db",
        std::env::temp_dir().display(),
        Uuid::new_v4()
    );
    let state: vela_server::state::AppState = Arc::new(
        AppStateInner::new(
            Arc::new(
                TursoDb::open(&turso_path, CONCURRENCY)
                    .await
                    .expect("open concurrent turso"),
            ),
            Store::open_temp().expect("open temp sled store"),
            config::Config::from_env().expect("load config"),
        )
        .await
        .expect("create concurrent state"),
    );
    let app = vela_server::routes::build(state.clone());
    let fixture = Fixture::new(state.clone(), app.clone(), 1).await;
    let mut wins: BTreeMap<&'static str, usize> = BTreeMap::new();

    // First `SAME_ENDPOINT_ROUNDS` per endpoint (so every consumer is
    // guaranteed to win at least one race), then mixed-endpoint rounds.
    let mut rounds: Vec<Option<Endpoint>> = Vec::new();
    for endpoint in ENDPOINTS {
        for _ in 0..SAME_ENDPOINT_ROUNDS {
            rounds.push(Some(endpoint));
        }
    }
    for round in 0..MIXED_ROUNDS {
        let _ = round;
        rounds.push(None);
    }

    let mut mixed_zero = 0usize;
    for (round, fixed) in rounds.into_iter().enumerate() {
        // Fixed rounds race requests at the nonce's own endpoint; mixed rounds
        // also race wrong-endpoint requests, which may spend it first.
        let purpose = fixed.unwrap_or(ENDPOINTS[round % ENDPOINTS.len()]);
        let (challenge_b64, challenge_bytes) = fixture.issue_challenge(purpose).await;
        // One budget per round: the per-session web-token limit is 30/min and
        // an all-web round sends 16 requests.
        fixture.reset();

        let (device_sig, web_sig) = with_big_stack(|| {
            (
                B64.encode(
                    sign(
                        &fixture.device_sk,
                        &auth_message(&fixture.device_id_str, &challenge_bytes),
                    )
                    .expect("device sign")
                    .to_bytes(),
                ),
                B64.encode(
                    sign(
                        &fixture.web_sk,
                        &auth_message(&fixture.web_session_id_str, &challenge_bytes),
                    )
                    .expect("web sign")
                    .to_bytes(),
                ),
            )
        });

        let mut tasks = Vec::with_capacity(CONCURRENCY);
        for i in 0..CONCURRENCY {
            let endpoint = fixed.unwrap_or(ENDPOINTS[i % ENDPOINTS.len()]);
            let signature = match endpoint {
                Endpoint::WebToken => web_sig.clone(),
                _ => device_sig.clone(),
            };
            let request = fixture.present_request(endpoint, &challenge_b64, &signature);
            let app = app.clone();
            tasks.push(tokio::spawn(async move {
                let response = app.oneshot(request).await.unwrap();
                response.status()
            }));
        }

        let mut statuses = Vec::with_capacity(CONCURRENCY);
        for task in tasks {
            statuses.push(task.await.expect("concurrent request panicked"));
        }

        let successes = statuses.iter().filter(|&&s| s == StatusCode::OK).count();
        if fixed.is_some() {
            assert_eq!(
                successes, 1,
                "round {round} (fixed {fixed:?}) produced {successes} successes: {statuses:?}"
            );
        } else {
            assert!(
                successes <= 1,
                "mixed round {round} produced {successes} successes: {statuses:?}"
            );
            mixed_zero += usize::from(successes == 0);
        }
        for (i, status) in statuses.iter().enumerate() {
            if *status != StatusCode::OK {
                assert_eq!(
                    *status,
                    StatusCode::UNAUTHORIZED,
                    "round {round} request {i} (endpoint {:?}) failed unexpectedly: {statuses:?}",
                    fixed.unwrap_or(ENDPOINTS[i % ENDPOINTS.len()])
                );
            } else {
                let winner = fixed.unwrap_or(ENDPOINTS[i % ENDPOINTS.len()]);
                assert_eq!(
                    winner, purpose,
                    "round {round}: a {purpose:?} nonce won at {winner:?}"
                );
                *wins.entry(winner.name()).or_insert(0) += 1;
            }
        }
    }

    // Non-vacuity: each consumer won at least one real race.
    for endpoint in ENDPOINTS {
        assert!(
            wins.get(endpoint.name()).copied().unwrap_or(0) > 0,
            "{endpoint:?} never won a concurrent round: {wins:?}"
        );
    }

    eprintln!(
        "challenge concurrency: {} rounds x {} requests, wins {:?}, mixed rounds with no winner {}",
        SAME_ENDPOINT_ROUNDS * ENDPOINTS.len() + MIXED_ROUNDS,
        CONCURRENCY,
        wins,
        mixed_zero
    );
}
