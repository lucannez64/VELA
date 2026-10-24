//! Bounded conformance of the real device-pairing handlers and store against
//! an independent invitation/rendezvous state machine.
//!
//! Every command sequence up to `DEPTH` over a fixed alphabet is executed both
//! against a small reference model and against the real Axum router backed by
//! the real Turso schema and sled store:
//!
//! - invitation: `POST /device/enrollment-package`,
//!   `GET /device/enrollment-package/:token`;
//! - rendezvous: `POST /device/enrollment-grant`,
//!   `POST /device/enrollment-grant/:id/claim`,
//!   `GET /device/enrollment-grant/:id`,
//!   `POST /device/enrollment-grant/:id/complete`,
//!   `POST /device/enrollment-grant/:id/result`.
//!
//! The reference model is the ceremony relation `m13_device_enrollment_ceremony`
//! proves ordering properties of, projected onto what the server stores:
//! a grant is opened, the first claim fixes the joining keys, the opener
//! inspects the stored claim, completion consumes grant **and** claim together
//! and enrolls exactly the stored keys, and the joining device collects the
//! result with a signature under the key it claimed with.
//!
//! States are named after the Tamarin theory, with the collapses the server
//! makes recorded explicitly:
//!
//! | Tamarin | here |
//! |---|---|
//! | `Open` | `Phase::Open` |
//! | `Claimed` | `Phase::Claimed` |
//! | `Inspected` | not stored: `/result` reads the claim, so inspection is a read |
//! | `Confirmed` + `ResultReady` | `Phase::Completed` (one sled transaction + one row) |
//! | `ResultCollected` | client-side; modelled only as `/result`'s answer |
//!
//! Safety properties asserted at every step, not just the status codes:
//!
//! 1. an invitation package is redeemed **at most once** per store (one
//!    successful fetch per `StorePackage`);
//! 2. a grant is claimed at most once, and completion enrolls at most one
//!    device, so a replayed or stale grant/claim never enrolls anything;
//! 3. the enrolled row carries the *stored claim's* keys and the opener's id,
//!    and it belongs to the opening account — a second account's device list
//!    never grows and no completion driven by it can succeed;
//! 4. the per-step observable state matches: package liveness/content, the
//!    grant/claim/result records, the account's device list over HTTP and the
//!    stored key material over SQL.
//!
//! Executable evidence for bounded sequential traces, not a proof. Not covered:
//! cryptographic validity beyond "the primary's signature verifies" (the test
//! holds real hybrid keys, so it also exercises rejection of a valid signature
//! over the wrong message), clock/TTL expiry (no `/cancel` or `/expire`
//! endpoint exists, and the grant TTL is 5 minutes while a trace lasts
//! milliseconds), account key rotation, and real concurrency. The single
//! redemption races are asserted at the store level in `store.rs` and by
//! `enrollment_ceremony_model.rs` over the verified policy.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use vela_crypto::signing::{self, HybridSigningKey};
use vela_server::sqldb::{Db as _, TursoValue};

mod helpers;

/// Command sequences are explored exhaustively up to this length. CI uses the
/// default; `VELA_PAIRING_MODEL_DEPTH=4` runs the deeper exploration locally.
const DEFAULT_DEPTH: usize = 3;

fn depth() -> usize {
    std::env::var("VELA_PAIRING_MODEL_DEPTH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_DEPTH)
}

/// `vela_enrollment_policy::HYBRID_EK_LEN` / `HYBRID_VK_LEN`.
const EK_LEN: usize = 1568 + 32;
const VK_LEN: usize = 2592 + 32;

// ── Commands ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Joiner {
    J1,
    J2,
}
impl Joiner {
    fn index(self) -> usize {
        match self {
            Joiner::J1 => 0,
            Joiner::J2 => 1,
        }
    }

    fn device_name(self) -> &'static str {
        match self {
            Joiner::J1 => "phone-j1",
            Joiner::J2 => "phone-j2",
        }
    }
}

/// Who drives a handler that needs a device session: the opener itself, a
/// second device of the same account, or a device of another account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Actor {
    Primary,
    Secondary,
    Eve,
}

#[derive(Clone, Copy, Debug)]
enum Command {
    /// Store the invitation capsule under the one invitation token.
    StorePackage,
    /// Same endpoint with a token that fails validation.
    StorePackageBadToken,
    /// Redeem the invitation token (destructive).
    FetchPackage,
    /// Fetch with a token that fails validation.
    FetchPackageBadToken,
    /// The opener opens a grant.
    OpenGrant,
    /// Same endpoint without a session.
    OpenGrantUnauthenticated,
    /// A joining device claims the addressed grant with its own keys.
    Claim(Joiner),
    /// A claim whose key lengths are wrong; it must not fix the ceremony.
    ClaimBadKeys,
    /// The opener (or a non-opener) reads the claimed keys.
    GetClaim(Actor),
    /// The opener completes with a real signature over the stored claim.
    Complete,
    /// The opener signs a different message: well-formed, wrong signature.
    CompleteWrongSignature,
    /// A non-opener tries to complete.
    CompleteAs(Actor),
    /// A joining device polls for the outcome, signing with its own key.
    Result(Joiner),
}

impl Command {
    fn kind(self) -> &'static str {
        match self {
            Command::StorePackage | Command::StorePackageBadToken => "StorePackage",
            Command::FetchPackage | Command::FetchPackageBadToken => "FetchPackage",
            Command::OpenGrant | Command::OpenGrantUnauthenticated => "OpenGrant",
            Command::Claim(_) | Command::ClaimBadKeys => "Claim",
            Command::GetClaim(_) => "GetClaim",
            Command::Complete | Command::CompleteWrongSignature | Command::CompleteAs(_) => {
                "Complete"
            }
            Command::Result(_) => "Result",
        }
    }
}

fn alphabet() -> Vec<Command> {
    use Command::*;
    vec![
        StorePackage,
        StorePackageBadToken,
        FetchPackage,
        FetchPackageBadToken,
        OpenGrant,
        OpenGrantUnauthenticated,
        Claim(Joiner::J1),
        Claim(Joiner::J2),
        ClaimBadKeys,
        GetClaim(Actor::Primary),
        GetClaim(Actor::Secondary),
        Complete,
        CompleteWrongSignature,
        CompleteAs(Actor::Secondary),
        CompleteAs(Actor::Eve),
        Result(Joiner::J1),
        Result(Joiner::J2),
    ]
}

// ── Reference model ─────────────────────────────────────────────────────────

/// The ritual M13 calls Open -> Claimed -> (Inspected) -> Confirmed. The
/// server keeps no inspection record and writes the result in the same step
/// that consumes the ceremony, so one `Completed` state covers the last three
/// protocol states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Open,
    Claimed,
    Completed,
}

#[derive(Clone, Copy, Debug)]
struct GrantState {
    phase: Phase,
    /// Set by the single winning claim and never replaced.
    claimant: Option<Joiner>,
    /// Set by the single winning completion.
    result: Option<Joiner>,
}

impl GrantState {
    fn open() -> Self {
        Self { phase: Phase::Open, claimant: None, result: None }
    }

    /// The grant record still exists in the store.
    fn record_live(self) -> bool {
        self.phase != Phase::Completed
    }

    fn claimed(self) -> bool {
        self.phase == Phase::Claimed
    }

    fn completed(self) -> bool {
        self.phase == Phase::Completed
    }
}

#[derive(Clone, Debug, Default)]
struct Model {
    /// Ciphertext currently held under the invitation token, if any.
    package: Option<String>,
    /// Successful `StorePackage` calls, which names the next ciphertext.
    package_stores: usize,
    /// Grants in the order the opener created them. Only slot 0 is addressed
    /// by the alphabet; later grants exist but nothing enumerates or reaches
    /// them, exactly as on the server.
    grants: Vec<GrantState>,
}

/// What one command must produce, beyond the status code.
#[derive(Debug)]
struct Expect {
    status: StatusCode,
    /// Ciphertext a successful package fetch must return.
    package_payload: Option<String>,
    /// `status` field a successful result poll must report.
    result_view: Option<&'static str>,
}

impl Expect {
    fn of(status: StatusCode) -> Self {
        Self { status, package_payload: None, result_view: None }
    }
}

impl Model {
    fn grant(&self) -> Option<GrantState> {
        self.grants.first().copied()
    }

    fn enrolled(&self) -> Vec<Joiner> {
        self.grants.iter().filter_map(|grant| grant.result).collect()
    }

    fn apply(&mut self, command: Command) -> Expect {
        match command {
            Command::StorePackage => {
                self.package_stores += 1;
                self.package = Some(format!("pairing-capsule-{}", self.package_stores));
                Expect::of(StatusCode::OK)
            }
            // `validate_token` runs before the ciphertext length check.
            Command::StorePackageBadToken => Expect::of(StatusCode::BAD_REQUEST),
            Command::FetchPackage => match self.package.take() {
                Some(payload) => Expect {
                    status: StatusCode::OK,
                    package_payload: Some(payload),
                    result_view: None,
                },
                None => Expect::of(StatusCode::NOT_FOUND),
            },
            Command::FetchPackageBadToken => Expect::of(StatusCode::BAD_REQUEST),
            Command::OpenGrant => {
                self.grants.push(GrantState::open());
                Expect::of(StatusCode::OK)
            }
            // The grant route is device-only; a missing session is refused
            // before anything is stored.
            Command::OpenGrantUnauthenticated => Expect::of(StatusCode::UNAUTHORIZED),
            Command::Claim(joiner) => match self.grant() {
                None => Expect::of(StatusCode::NOT_FOUND),
                // Completion consumed the grant; a later claim is a miss, not
                // a "already claimed" conflict.
                Some(grant) if grant.completed() => Expect::of(StatusCode::NOT_FOUND),
                Some(grant) if grant.claimed() => Expect::of(StatusCode::CONFLICT),
                Some(_) => {
                    let grant = self.grants.first_mut().expect("slot 0 exists");
                    grant.phase = Phase::Claimed;
                    grant.claimant = Some(joiner);
                    Expect::of(StatusCode::OK)
                }
            },
            // The policy checks the public-key lengths before "a claim already
            // exists", so bad keys are a 400 even after a winning claim — and
            // they never replace the stored claim.
            Command::ClaimBadKeys => match self.grant() {
                None => Expect::of(StatusCode::NOT_FOUND),
                Some(grant) if grant.completed() => Expect::of(StatusCode::NOT_FOUND),
                Some(_) => Expect::of(StatusCode::BAD_REQUEST),
            },
            Command::GetClaim(actor) => match (actor, self.grant()) {
                (Actor::Primary, Some(grant)) if grant.claimed() => Expect::of(StatusCode::OK),
                _ => Expect::of(StatusCode::NOT_FOUND),
            },
            Command::Complete | Command::CompleteWrongSignature => match self.grant() {
                Some(grant) if grant.claimed() => {
                    if matches!(command, Command::Complete) {
                        let grant = self.grants.first_mut().expect("slot 0 exists");
                        grant.phase = Phase::Completed;
                        grant.result = grant.claimant;
                        Expect::of(StatusCode::OK)
                    } else {
                        // A refusal never spends the ceremony.
                        Expect::of(StatusCode::UNAUTHORIZED)
                    }
                }
                // Missing grant, or live grant with no claim yet.
                _ => Expect::of(StatusCode::NOT_FOUND),
            },
            Command::CompleteAs(_) => Expect::of(StatusCode::NOT_FOUND),
            Command::Result(joiner) => match self.grant() {
                Some(grant) if grant.completed() => {
                    if grant.claimant == Some(joiner) {
                        Expect {
                            status: StatusCode::OK,
                            package_payload: None,
                            result_view: Some("enrolled"),
                        }
                    } else {
                        // The stored result is checked against the key it was
                        // claimed with, so another device learns nothing.
                        Expect::of(StatusCode::UNAUTHORIZED)
                    }
                }
                Some(grant) if grant.claimed() => {
                    if grant.claimant == Some(joiner) {
                        Expect {
                            status: StatusCode::OK,
                            package_payload: None,
                            result_view: Some("pending"),
                        }
                    } else {
                        Expect::of(StatusCode::UNAUTHORIZED)
                    }
                }
                _ => Expect::of(StatusCode::NOT_FOUND),
            },
        }
    }
}

// ── Real system ─────────────────────────────────────────────────────────────

struct JoinerKeys {
    signing: HybridSigningKey,
    ek: Vec<u8>,
    ek_b64: String,
    vk: Vec<u8>,
    vk_b64: String,
}

/// Keys are generated once per test run. The completion signature covers only
/// (ek, vk, capsule) — no user, device or grant id — so the same keys and
/// signature are valid in every trace, which keeps thousands of traces cheap.
struct Keys {
    joiners: [JoinerKeys; 2],
    primary_vk: Vec<u8>,
    capsule: Vec<u8>,
    /// The opener's signature over the keys a joiner claimed plus `capsule`.
    complete_signature: [String; 2],
    /// Same keys, different capsule: well-formed but must be refused.
    wrong_completion_signature: [String; 2],
}

impl Keys {
    fn new() -> Self {
        fn joiner_keys(index: usize) -> JoinerKeys {
            let (vk, signing) = signing::generate_keypair().unwrap();
            let ek = vec![0x11 + index as u8; EK_LEN];
            let vk = vk.to_bytes().to_vec();
            JoinerKeys {
                signing,
                ek_b64: B64.encode(&ek),
                vk_b64: B64.encode(&vk),
                ek,
                vk,
            }
        }

        let (primary_vk, primary_signing) = signing::generate_keypair().unwrap();
        let capsule = vec![0xC5u8; 96];
        let other_capsule = vec![0xC6u8; 96];
        let joiners = [joiner_keys(0), joiner_keys(1)];

        let signature_over = |joiner: &JoinerKeys, capsule: &[u8]| -> String {
            let message = signing::enrollment_message(&joiner.ek, &joiner.vk, capsule);
            B64.encode(signing::sign(&primary_signing, &message).unwrap().to_bytes())
        };
        let complete_signature = [
            signature_over(&joiners[0], &capsule),
            signature_over(&joiners[1], &capsule),
        ];
        let wrong_completion_signature = [
            signature_over(&joiners[0], &other_capsule),
            signature_over(&joiners[1], &other_capsule),
        ];

        Self {
            joiners,
            primary_vk: primary_vk.to_bytes().to_vec(),
            capsule,
            complete_signature,
            wrong_completion_signature,
        }
    }

    fn joiner(&self, joiner: Joiner) -> &JoinerKeys {
        &self.joiners[joiner.index()]
    }
}

struct Party {
    user_id: Uuid,
    device_id: Uuid,
    token: String,
}

struct Real<'a> {
    app: Router,
    state: vela_server::state::AppState,
    keys: &'a Keys,
    primary: Party,
    secondary: Party,
    eve: Party,
    package_token: String,
    /// Successful `StorePackage` calls; names the next ciphertext, exactly as
    /// the model's counter does.
    package_stores: usize,
    /// Real grant ids in the order the opener created them.
    grants: Vec<Uuid>,
    /// Which joining device won the (single) claim on slot 0.
    claim: Option<Joiner>,
    /// Devices completion actually enrolled: (claimant, device id).
    enrolled: Vec<(Joiner, Uuid)>,
    result_signatures: HashMap<(Uuid, Joiner), String>,
}

static NEXT_IP: AtomicU32 = AtomicU32::new(1);

/// A distinct source address per request keeps the per-IP limits (20 claims,
/// 60 package fetches per hour) out of the way; each trace uses a fresh
/// account, so the per-user grant limit never binds either.
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

async fn new_account(state: &vela_server::state::AppState) -> Uuid {
    let user_id = Uuid::new_v4();
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
        .unwrap();
    user_id
}

async fn new_device(
    state: &vela_server::state::AppState,
    user_id: Uuid,
    name: &str,
    vk: &[u8],
) -> Party {
    let device_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
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
                TursoValue::Text(B64.encode([1u8; EK_LEN])),
                TursoValue::Text(B64.encode(vk)),
                TursoValue::Text(now),
            ],
        )
        .await
        .unwrap();
    Party { user_id, device_id, token: token_for(state, user_id, device_id) }
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
    let response = app.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A device as `GET /devices` shows it.
struct Listed {
    name: String,
    enrolled_by: Option<Uuid>,
    ek_b64: String,
}

/// A device row as SQL stores it (values the HTTP listing does not expose).
#[derive(Debug)]
struct StoredDevice {
    id: Uuid,
    user_id: Uuid,
    name: String,
    enrolled_by: Option<String>,
    ek_b64: String,
    vk_b64: String,
}

impl<'a> Real<'a> {
    async fn new(state: &vela_server::state::AppState, app: Router, keys: &'a Keys) -> Self {
        // One account with two devices: the opener and a sibling that must not
        // be able to drive the ceremony.
        let user_id = new_account(state).await;
        let primary = new_device(state, user_id, "primary", &keys.primary_vk).await;
        let secondary =
            new_device(state, user_id, "secondary", &vec![0x22u8; VK_LEN]).await;
        // A different account, whose device must never become an enrollee.
        let eve_user = new_account(state).await;
        let eve = new_device(state, eve_user, "eve", &vec![0x33u8; VK_LEN]).await;
        Self {
            app,
            state: state.clone(),
            keys,
            primary,
            secondary,
            eve,
            package_token: format!("pairing-invitation-{}", Uuid::new_v4().simple()),
            package_stores: 0,
            grants: Vec::new(),
            claim: None,
            enrolled: Vec::new(),
            result_signatures: HashMap::new(),
        }
    }

    fn token(&self, actor: Actor) -> Option<&str> {
        match actor {
            Actor::Primary => Some(&self.primary.token),
            Actor::Secondary => Some(&self.secondary.token),
            Actor::Eve => Some(&self.eve.token),
        }
    }

    fn grant_id(&self, slot: usize) -> Uuid {
        self.grants.get(slot).copied().unwrap_or_else(Uuid::new_v4)
    }

    fn result_signature(&mut self, grant_id: Uuid, joiner: Joiner) -> String {
        if let Some(signature) = self.result_signatures.get(&(grant_id, joiner)) {
            return signature.clone();
        }
        let message = signing::enrollment_result_message(&grant_id.to_string());
        let signature = B64.encode(
            signing::sign(&self.keys.joiner(joiner).signing, &message)
                .unwrap()
                .to_bytes(),
        );
        self.result_signatures.insert((grant_id, joiner), signature.clone());
        signature
    }

    async fn apply(&mut self, command: Command) -> (StatusCode, Value) {
        match command {
            Command::StorePackage | Command::StorePackageBadToken => {
                let token = if matches!(command, Command::StorePackage) {
                    self.package_token.clone()
                } else {
                    // Shorter than the 32-byte minimum.
                    "too-short".to_string()
                };
                let payload = format!("pairing-capsule-{}", self.package_stores + 1);
                let (status, body) = call(
                    &self.app,
                    "POST",
                    "/device/enrollment-package",
                    None,
                    Some(json!({ "token": token, "ciphertext": payload })),
                )
                .await;
                if status == StatusCode::OK {
                    self.package_stores += 1;
                }
                (status, body)
            }
            Command::FetchPackage | Command::FetchPackageBadToken => {
                let token = if matches!(command, Command::FetchPackage) {
                    self.package_token.clone()
                } else {
                    "too-short".to_string()
                };
                call(
                    &self.app,
                    "GET",
                    &format!("/device/enrollment-package/{token}"),
                    None,
                    None,
                )
                .await
            }
            Command::OpenGrant | Command::OpenGrantUnauthenticated => {
                let token = matches!(command, Command::OpenGrant).then_some(self.primary.token.as_str());
                let (status, body) =
                    call(&self.app, "POST", "/device/enrollment-grant", token, None).await;
                if status == StatusCode::OK {
                    let grant_id: Uuid =
                        serde_json::from_value(body["grant_id"].clone()).unwrap();
                    self.grants.push(grant_id);
                    assert_eq!(
                        body["expires_in"].as_u64(),
                        Some(300),
                        "unexpected grant TTL in {body}"
                    );
                }
                (status, body)
            }
            Command::Claim(_) | Command::ClaimBadKeys => {
                let grant_id = self.grant_id(0);
                let (ek, vk) = match command {
                    Command::Claim(joiner) => {
                        let keys = self.keys.joiner(joiner);
                        (keys.ek_b64.clone(), keys.vk_b64.clone())
                    }
                    // Decodable base64 of the wrong length: a 400, never a claim.
                    _ => (B64.encode([9u8; 16]), B64.encode([8u8; 16])),
                };
                let name = match command {
                    Command::Claim(joiner) => joiner.device_name(),
                    _ => "bad-keys",
                };
                let (status, body) = call(
                    &self.app,
                    "POST",
                    &format!("/device/enrollment-grant/{grant_id}/claim"),
                    None,
                    Some(json!({
                        "hybrid_ek": ek,
                        "hybrid_vk": vk,
                        "device_name": name,
                        "device_type": "phone",
                    })),
                )
                .await;
                if status == StatusCode::OK {
                    match command {
                        Command::Claim(joiner) => self.claim = Some(joiner),
                        _ => panic!("a claim with invalid key lengths was accepted"),
                    }
                }
                (status, body)
            }
            Command::GetClaim(actor) => {
                let grant_id = self.grant_id(0);
                call(
                    &self.app,
                    "GET",
                    &format!("/device/enrollment-grant/{grant_id}"),
                    self.token(actor),
                    None,
                )
                .await
            }
            Command::Complete | Command::CompleteWrongSignature | Command::CompleteAs(_) => {
                let grant_id = self.grant_id(0);
                let claimant = self.claim.unwrap_or(Joiner::J1);
                let signature = match command {
                    Command::Complete => self.keys.complete_signature[claimant.index()].clone(),
                    Command::CompleteWrongSignature => {
                        self.keys.wrong_completion_signature[claimant.index()].clone()
                    }
                    // A non-opener never gets as far as the signature; send a
                    // genuine one so only the binding can refuse it.
                    Command::CompleteAs(_) => self.keys.complete_signature[claimant.index()].clone(),
                    _ => unreachable!("the outer match admits only completion commands"),
                };
                let token = match command {
                    Command::Complete | Command::CompleteWrongSignature => {
                        Some(self.primary.token.as_str())
                    }
                    Command::CompleteAs(actor) => self.token(actor),
                    _ => unreachable!(),
                };
                let (status, body) = call(
                    &self.app,
                    "POST",
                    &format!("/device/enrollment-grant/{grant_id}/complete"),
                    token,
                    Some(json!({
                        "rms_capsule": B64.encode(&self.keys.capsule),
                        "signature": signature,
                        "key_epoch": 1,
                    })),
                )
                .await;
                if status == StatusCode::OK {
                    let device_id: Uuid =
                        serde_json::from_value(body["device_id"].clone()).unwrap();
                    self.enrolled.push((claimant, device_id));
                }
                (status, body)
            }
            Command::Result(joiner) => {
                let grant_id = self.grant_id(0);
                let signature = self.result_signature(grant_id, joiner);
                call(
                    &self.app,
                    "POST",
                    &format!("/device/enrollment-grant/{grant_id}/result"),
                    None,
                    Some(json!({ "signature": signature })),
                )
                .await
            }
        }
    }

    async fn list_devices(&self, actor: Actor) -> BTreeMap<Uuid, Listed> {
        let token = self.token(actor).expect("actor has a session");
        let (status, value) = call(&self.app, "GET", "/devices", Some(token), None).await;
        assert_eq!(status, StatusCode::OK, "GET /devices failed: {value}");
        let mut out = BTreeMap::new();
        for item in value["devices"].as_array().unwrap() {
            let id: Uuid = serde_json::from_value(item["id"].clone()).unwrap();
            let enrolled_by = item["enrolled_by"].as_str().map(|s| s.parse().unwrap());
            let listed = Listed {
                name: item["name"].as_str().unwrap().to_string(),
                enrolled_by,
                ek_b64: item["hybrid_ek"].as_str().unwrap().to_string(),
            };
            assert!(out.insert(id, listed).is_none(), "duplicate device id in listing");
        }
        out
    }

    async fn stored_devices(&self) -> Vec<StoredDevice> {
        let rows = self
            .state
            .sqldb
            .query(
                "SELECT id, user_id, device_name, enrolled_by, hybrid_ek, hybrid_vk
                 FROM devices WHERE user_id = ? OR user_id = ?",
                vec![
                    TursoValue::Text(self.primary.user_id.to_string()),
                    TursoValue::Text(self.eve.user_id.to_string()),
                ],
            )
            .await
            .unwrap();
        rows.iter()
            .map(|row| StoredDevice {
                id: row.text(0).unwrap().parse().unwrap(),
                user_id: row.text(1).unwrap().parse().unwrap(),
                name: row.text(2).unwrap().to_string(),
                enrolled_by: row.text(3).map(str::to_string),
                ek_b64: row.text(4).unwrap().to_string(),
                vk_b64: row.text(5).unwrap().to_string(),
            })
            .collect()
    }

    /// Compare every observable piece of state to the model.
    async fn assert_matches(&self, model: &Model, context: &str) {
        // 1. The invitation record is present exactly when the model holds a
        //    payload, and holds exactly that payload.
        let package_key = format!("enrollment_package:{}", self.package_token);
        let stored_package = self
            .state
            .store
            .get(&package_key)
            .unwrap()
            .map(|bytes| String::from_utf8(bytes).unwrap());
        assert_eq!(stored_package, model.package, "invitation package {context}");

        // 2. Grant / claim / result records for the addressed ceremony.
        assert_eq!(self.grants.len(), model.grants.len(), "grant count {context}");
        if let (Some(grant_id), Some(expected)) = (self.grants.first(), model.grant()) {
            let grant_bytes = self
                .state
                .store
                .get(&format!("enroll_grant:{grant_id}"))
                .unwrap();
            assert_eq!(
                grant_bytes.is_some(),
                expected.record_live(),
                "grant record {context}"
            );
            let claim_bytes = self
                .state
                .store
                .get(&format!("enroll_claim:{grant_id}"))
                .unwrap();
            assert_eq!(
                claim_bytes.is_some(),
                expected.claimed(),
                "claim record {context}"
            );
            if expected.claimed() {
                let claimant = expected.claimant.expect("a claimed grant has a claimant");
                let claim: Value = serde_json::from_slice(&claim_bytes.unwrap()).unwrap();
                let keys = self.keys.joiner(claimant);
                assert_eq!(claim["hybrid_ek"], keys.ek_b64, "stored claim ek {context}");
                assert_eq!(claim["hybrid_vk"], keys.vk_b64, "stored claim vk {context}");
                assert_eq!(
                    claim["device_name"],
                    claimant.device_name(),
                    "stored claim name {context}"
                );
            }
            let result_bytes = self
                .state
                .store
                .get(&format!("enroll_result:{grant_id}"))
                .unwrap();
            assert_eq!(
                result_bytes.is_some(),
                expected.result.is_some(),
                "result record {context}"
            );
            if let Some(result_owner) = expected.result {
                let result: Value = serde_json::from_slice(&result_bytes.unwrap()).unwrap();
                assert_eq!(
                    result["hybrid_vk"],
                    self.keys.joiner(result_owner).vk_b64,
                    "result key {context}"
                );
                let enrolled_id = self
                    .enrolled
                    .iter()
                    .find(|(joiner, _)| *joiner == result_owner)
                    .map(|(_, id)| id.to_string())
                    .expect("the model and driver agree on who was enrolled");
                assert_eq!(result["device_id"], enrolled_id, "result device id {context}");
            }
        }

        // 3. Device lists, over the API and over SQL. The opening account holds
        //    exactly its two starting devices plus the one completion's device;
        //    the other account never gains a row.
        let listed = self.list_devices(Actor::Primary).await;
        let rows = self.stored_devices().await;
        let ours: Vec<&StoredDevice> = rows
            .iter()
            .filter(|row| row.user_id == self.primary.user_id)
            .collect();
        let theirs: Vec<&StoredDevice> = rows
            .iter()
            .filter(|row| row.user_id == self.eve.user_id)
            .collect();

        assert_eq!(theirs.len(), 1, "another account gained a device {context}");
        assert_eq!(theirs[0].id, self.eve.device_id, "other account's device id {context}");
        assert_eq!(theirs[0].name, "eve", "other account's device name {context}");

        let enrolled = model.enrolled();
        assert_eq!(
            ours.len(),
            2 + enrolled.len(),
            "device count for the opening account {context}: {:?}",
            ours.iter().map(|row| row.name.as_str()).collect::<Vec<_>>()
        );
        assert_eq!(listed.len(), ours.len(), "listing and rows disagree {context}");

        let mut expected_names: BTreeSet<String> =
            ["primary".to_string(), "secondary".to_string()].into_iter().collect();
        expected_names.extend(enrolled.iter().map(|joiner| joiner.device_name().to_string()));
        let actual_names: BTreeSet<String> =
            ours.iter().map(|row| row.name.clone()).collect();
        assert_eq!(actual_names, expected_names, "device names {context}");

        for (joiner, device_id) in &self.enrolled {
            let keys = self.keys.joiner(*joiner);
            let row = ours
                .iter()
                .find(|row| row.id == *device_id)
                .unwrap_or_else(|| panic!("the enrolled device {device_id} is not listed {context}"));
            assert_eq!(row.name, joiner.device_name(), "enrolled name {context}");
            assert_eq!(
                row.enrolled_by,
                Some(self.primary.device_id.to_string()),
                "enrolled_by {context}"
            );
            assert_eq!(row.ek_b64, keys.ek_b64, "the enrolled ek is not the claimed ek {context}");
            assert_eq!(row.vk_b64, keys.vk_b64, "the enrolled vk is not the claimed vk {context}");

            let from_api = listed
                .get(device_id)
                .unwrap_or_else(|| panic!("the enrolled device is missing from /devices {context}"));
            assert_eq!(from_api.name, row.name, "listing name {context}");
            assert_eq!(
                from_api.enrolled_by,
                Some(self.primary.device_id),
                "listing enrolled_by {context}"
            );
            assert_eq!(from_api.ek_b64, keys.ek_b64, "listing ek {context}");
        }

        // The opener's own row is untouched by any of this.
        let primary_row = ours
            .iter()
            .find(|row| row.id == self.primary.device_id)
            .expect("the opener is still listed");
        assert_eq!(primary_row.vk_b64, B64.encode(&self.keys.primary_vk));
    }
}

// ── Driver ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Coverage {
    statuses: BTreeSet<(&'static str, u16)>,
    result_views: BTreeSet<&'static str>,
}

#[derive(Default)]
struct Counts {
    stores: usize,
    fetches: usize,
    claims: usize,
    completes: usize,
}

/// Apply one command to both sides, compare the status, the response shape and
/// the whole observable state, and enforce the at-most-once properties.
async fn step(
    model: &mut Model,
    real: &mut Real<'_>,
    command: Command,
    coverage: &mut Coverage,
    counts: &mut Counts,
    context: &str,
) {
    let expect = model.apply(command);
    let (status, body) = real.apply(command).await;
    assert_eq!(
        status, expect.status,
        "status mismatch for {command:?} ({context}); body: {body}"
    );
    coverage.statuses.insert((command.kind(), status.as_u16()));

    match command {
        Command::StorePackage if status == StatusCode::OK => {
            assert_eq!(body["stored"], Value::Bool(true), "store body {context}");
            assert_eq!(body["expires_in"].as_u64(), Some(900), "store TTL {context}");
            counts.stores += 1;
        }
        Command::FetchPackage if status == StatusCode::OK => {
            assert_eq!(
                body["ciphertext"].as_str(),
                expect.package_payload.as_deref(),
                "a fetch returned a different capsule than was stored {context}"
            );
            counts.fetches += 1;
        }
        Command::Claim(_) if status == StatusCode::OK => {
            assert_eq!(body["claimed"], Value::Bool(true), "claim body {context}");
            counts.claims += 1;
        }
        Command::GetClaim(actor) if status == StatusCode::OK => {
            assert_eq!(actor, Actor::Primary, "only the opener may read the claim");
            let claimant = model.grant().and_then(|grant| grant.claimant).unwrap();
            let keys = real.keys.joiner(claimant);
            assert_eq!(body["hybrid_ek"], keys.ek_b64, "claim view ek {context}");
            assert_eq!(body["hybrid_vk"], keys.vk_b64, "claim view vk {context}");
            assert_eq!(
                body["device_name"],
                claimant.device_name(),
                "claim view name {context}"
            );
        }
        Command::Complete if status == StatusCode::OK => {
            let device_id: Uuid = serde_json::from_value(body["device_id"].clone()).unwrap();
            assert_ne!(device_id, real.primary.device_id);
            assert_ne!(device_id, real.secondary.device_id);
            assert_ne!(device_id, real.eve.device_id);
            let (claimant, recorded) = real.enrolled.last().expect("driver recorded the device");
            assert_eq!(*recorded, device_id, "complete body and driver disagree");
            assert_eq!(
                model.grant().and_then(|grant| grant.result),
                Some(*claimant),
                "the model did not expect this enrollment {context}"
            );
            counts.completes += 1;
        }
        Command::Result(_) if status == StatusCode::OK => {
            let view = expect.result_view.expect("a successful poll has a view");
            coverage.result_views.insert(view);
            assert_eq!(body["status"].as_str(), Some(view), "result view {context}");
            if view == "enrolled" {
                let (_, device_id) = real.enrolled.last().expect("an enrolled device");
                assert_eq!(
                    body["device_id"].as_str(),
                    Some(device_id.to_string().as_str()),
                    "the joining device learned the wrong id {context}"
                );
            }
        }
        _ => {}
    }

    // Property 1: redemption is at most once per stored capsule.
    assert!(
        counts.fetches <= counts.stores,
        "the invitation token was redeemed more often than it was stored {context}"
    );
    // Property 2: one claim and one enrollment per trace, and they agree.
    assert!(counts.claims <= 1, "a grant was claimed twice {context}");
    assert_eq!(
        counts.completes,
        model.enrolled().len(),
        "completion count and enrolled-device count disagree {context}"
    );
    assert!(counts.completes <= 1, "a grant completed twice {context}");

    real.assert_matches(model, context).await;
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
async fn every_bounded_pairing_trace_matches_the_m13_ceremony() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let keys = Keys::new();

    let depth = depth();
    let traces = sequences(depth);
    let mut steps = 0usize;
    let mut coverage = Coverage::default();

    for trace in &traces {
        let mut model = Model::default();
        let mut real = Real::new(&state, app.clone(), &keys).await;
        let mut counts = Counts::default();

        for (step_index, command) in trace.iter().enumerate() {
            let context = format!("at step {step_index} of {trace:?}");
            step(&mut model, &mut real, *command, &mut coverage, &mut counts, &context).await;
            steps += 1;
        }
    }

    // Non-vacuity: every command kind must have been seen both succeeding and
    // being refused somewhere in the exploration.
    for (kind, code) in [
        ("StorePackage", 200u16),
        ("StorePackage", 400),
        ("FetchPackage", 200),
        ("FetchPackage", 404),
        ("FetchPackage", 400),
        ("OpenGrant", 200),
        ("OpenGrant", 401),
        ("Claim", 200),
        ("Claim", 404),
        ("Claim", 409),
        ("Claim", 400),
        ("GetClaim", 200),
        ("GetClaim", 404),
        ("Complete", 200),
        ("Complete", 401),
        ("Complete", 404),
        ("Result", 200),
        ("Result", 401),
        ("Result", 404),
    ] {
        assert!(
            coverage.statuses.contains(&(kind, code)),
            "{kind} {code} was never exercised: {:?}",
            coverage.statuses
        );
    }
    assert!(coverage.result_views.contains("pending"), "no pending poll was exercised");
    // The enrolled view needs open, claim, complete and poll: depth 4.
    if depth >= 4 {
        assert!(
            coverage.result_views.contains("enrolled"),
            "no enrolled poll was exercised: {:?}",
            coverage.result_views
        );
    }

    eprintln!(
        "pairing model: {} traces, {} steps, depth {}",
        traces.len(),
        steps,
        depth
    );
}

/// A single deterministic ceremony, asserted end to end. This runs at any
/// depth and covers the `enrolled` result view (which needs four steps), the
/// idempotent poll, and every replay/stale-token refusal as a readable
/// regression sequence.
#[tokio::test(flavor = "current_thread")]
async fn a_pairing_ceremony_completes_once_and_replays_are_refused() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let keys = Keys::new();
    let mut model = Model::default();
    let mut real = Real::new(&state, app.clone(), &keys).await;
    let mut coverage = Coverage::default();
    let mut counts = Counts::default();

    let sequence = [
        Command::FetchPackage,             // nothing stored yet
        Command::StorePackage,             // 200
        Command::FetchPackage,             // 200, the capsule is released
        Command::FetchPackage,             // 404: replayed invitation token
        Command::OpenGrant,                // 200
        Command::Claim(Joiner::J2),        // 200: the second candidate wins
        Command::Claim(Joiner::J1),        // 409: first claim wins
        Command::GetClaim(Actor::Secondary), // 404: not the opener
        Command::CompleteWrongSignature,   // 401: bad signature does not spend it
        Command::Complete,                 // 200
        Command::Complete,                 // 404: replayed completion
        Command::Claim(Joiner::J1),        // 404: the grant is gone
        Command::Result(Joiner::J1),       // 401: wrong joining key
        Command::Result(Joiner::J2),       // 200 enrolled
        Command::Result(Joiner::J2),       // 200 enrolled, polled again
        Command::GetClaim(Actor::Primary), // 404: the claim is consumed
        Command::CompleteAs(Actor::Eve),   // 404: another account cannot drive it
    ];

    for (step_index, command) in sequence.iter().enumerate() {
        let context = format!("at step {step_index} of the regression sequence");
        step(&mut model, &mut real, *command, &mut coverage, &mut counts, &context).await;
    }

    assert_eq!(counts.claims, 1);
    assert_eq!(counts.completes, 1);
    assert_eq!(counts.fetches, 1);
    assert_eq!(model.enrolled(), vec![Joiner::J2]);
    assert!(coverage.result_views.contains("enrolled"));
}
