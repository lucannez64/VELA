//! Bounded conformance of the real possession-proof recovery handlers and
//! database against the M18/M26a recovery chain.
//!
//! Every command sequence up to the depth below runs against a reference state
//! machine and against the real Axum router with the real Turso schema and
//! sled store: `/recovery/initiate-proof`, `/recovery/recover/proof`,
//! `/recovery/enroll-device`, plus account events (key rotation, freezing,
//! deleting and re-staging the possession commitment) applied to the row the
//! handlers read. After every step the HTTP status and the number of enrolled
//! devices must match the model.
//!
//! The reference model is the relation M18/M26a prove properties of:
//! - an attempt is issued only for an account with a staged commitment and no
//!   rotation in progress, and is bound to the current epoch;
//! - an attempt is consumed by its first proof, valid or not (single use);
//! - a grant is issued only for a valid proof under the staged commitment, for
//!   an attempt from the current epoch, and never releases the server share;
//! - a grant enrolls at most one device; rotation (epoch change) and commitment
//!   deletion strand outstanding grants; a paused rotation refuses without
//!   spending the grant.
//!
//! Executable evidence for bounded sequential traces, not a proof. The WebAuthn
//! path (`/recovery/initiate`, `/recovery/recover`) is not driven: it needs
//! genuine authenticator assertions. Rotation is applied as the epoch/state
//! change a committed rotation leaves in the row; the rotation protocol itself
//! is covered by M11 and `rekey_state_model.rs`. Concurrency is not explored.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt;
use uuid::Uuid;
use vela_server::sqldb::{Db as _, TursoValue};

mod helpers;

const DEFAULT_DEPTH: usize = 4;

fn depth() -> usize {
    std::env::var("VELA_RECOVERY_MODEL_DEPTH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_DEPTH)
}

const RMS: [u8; 32] = [42u8; 32];
const WRONG_RMS: [u8; 32] = [7u8; 32];

#[derive(Clone, Copy, Debug)]
enum Command {
    Initiate,
    Prove { slot: usize, honest: bool },
    Enroll { slot: usize },
    Rotate,
    Freeze,
    Unfreeze,
    Unstage,
    Restage,
}

impl Command {
    fn kind(self) -> &'static str {
        match self {
            Command::Initiate => "Initiate",
            Command::Prove { .. } => "Prove",
            Command::Enroll { .. } => "Enroll",
            Command::Rotate => "Rotate",
            Command::Freeze => "Freeze",
            Command::Unfreeze => "Unfreeze",
            Command::Unstage => "Unstage",
            Command::Restage => "Restage",
        }
    }
}

fn alphabet() -> Vec<Command> {
    use Command::*;
    vec![
        Initiate,
        Prove { slot: 0, honest: true },
        Prove { slot: 0, honest: false },
        Prove { slot: 1, honest: true },
        Enroll { slot: 0 },
        Enroll { slot: 1 },
        Rotate,
        Freeze,
        Unfreeze,
        Unstage,
        Restage,
    ]
}

// ── Reference model ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct Attempt {
    epoch: i64,
    alive: bool,
}

#[derive(Clone, Copy, Debug)]
struct Grant {
    epoch: i64,
    alive: bool,
}

#[derive(Clone, Debug)]
struct Model {
    epoch: i64,
    freezing: bool,
    committed: bool,
    attempts: Vec<Attempt>,
    grants: Vec<Grant>,
    devices: i64,
}

impl Model {
    fn new() -> Self {
        Self { epoch: 1, freezing: false, committed: true, attempts: Vec::new(), grants: Vec::new(), devices: 0 }
    }

    fn apply(&mut self, command: Command) -> Option<StatusCode> {
        Some(match command {
            Command::Initiate => {
                if self.freezing {
                    StatusCode::CONFLICT
                } else if !self.committed {
                    StatusCode::NOT_FOUND
                } else {
                    self.attempts.push(Attempt { epoch: self.epoch, alive: true });
                    StatusCode::OK
                }
            }
            Command::Prove { slot, honest } => {
                let Some(attempt) = self.attempts.get_mut(slot).filter(|a| a.alive) else {
                    return Some(StatusCode::BAD_REQUEST);
                };
                // Consumed by the first proof, whatever happens next.
                attempt.alive = false;
                let attempt = *attempt;
                if self.freezing {
                    StatusCode::CONFLICT
                } else if !self.committed || !honest || attempt.epoch != self.epoch {
                    StatusCode::UNAUTHORIZED
                } else {
                    self.grants.push(Grant { epoch: self.epoch, alive: true });
                    StatusCode::OK
                }
            }
            Command::Enroll { slot } => {
                let Some(grant) = self.grants.get_mut(slot).filter(|g| g.alive) else {
                    return Some(StatusCode::UNAUTHORIZED);
                };
                // Preflight order: epoch mismatch, rotation paused, commitment
                // missing. None of them spends the grant.
                if grant.epoch != self.epoch {
                    StatusCode::UNAUTHORIZED
                } else if self.freezing {
                    StatusCode::CONFLICT
                } else if !self.committed {
                    StatusCode::UNAUTHORIZED
                } else {
                    grant.alive = false;
                    self.devices += 1;
                    StatusCode::OK
                }
            }
            // Account events are applied directly to the row; they have no
            // HTTP status.
            Command::Rotate => {
                self.epoch += 1;
                return None;
            }
            Command::Freeze => {
                self.freezing = true;
                return None;
            }
            Command::Unfreeze => {
                self.freezing = false;
                return None;
            }
            Command::Unstage => {
                self.committed = false;
                return None;
            }
            Command::Restage => {
                self.committed = true;
                return None;
            }
        })
    }
}

// ── Real system ─────────────────────────────────────────────────────────────

struct Attempted {
    recovery_id: Uuid,
    challenge: Vec<u8>,
    epoch: i64,
}

struct Real {
    app: Router,
    state: vela_server::state::AppState,
    user_id: Uuid,
    attempts: Vec<Attempted>,
    grants: Vec<Uuid>,
}

static NEXT_IP: AtomicU32 = AtomicU32::new(1);

/// A distinct source address per request keeps the per-IP limits out of the
/// way: each trace uses a fresh account, so per-user limits never bind.
fn fresh_ip() -> ConnectInfo<SocketAddr> {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed);
    let [_, b, c, d] = n.to_be_bytes();
    ConnectInfo(SocketAddr::from(([10, b, c, d.max(1)], 40000)))
}

async fn post(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .extension(fresh_ip())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

impl Real {
    async fn new(state: &vela_server::state::AppState, app: Router) -> Self {
        let user_id = Uuid::new_v4();
        let commitment = vela_crypto::recovery::rms_possession_commitment(&RMS);
        state
            .sqldb
            .execute(
                "INSERT INTO users (id, created_at, key_epoch, recovery_share, recovery_split_id, recovery_auth_hash)
                 VALUES (?, ?, 1, ?, ?, ?)",
                vec![
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Text(chrono::Utc::now().to_rfc3339()),
                    TursoValue::Text(B64.encode([1u8; 8])),
                    TursoValue::Text(Uuid::new_v4().to_string()),
                    TursoValue::Text(B64.encode(commitment)),
                ],
            )
            .await
            .unwrap();
        Self { app, state: state.clone(), user_id, attempts: Vec::new(), grants: Vec::new() }
    }

    async fn sql(&self, statement: &str) {
        self.state
            .sqldb
            .execute(statement, vec![TursoValue::Text(self.user_id.to_string())])
            .await
            .unwrap();
    }

    async fn apply(&mut self, command: Command) -> Option<StatusCode> {
        Some(match command {
            Command::Initiate => {
                let (status, body) = post(&self.app, "/recovery/initiate-proof", json!({ "user_id": self.user_id })).await;
                if status == StatusCode::OK {
                    self.attempts.push(Attempted {
                        recovery_id: body["recovery_id"].as_str().unwrap().parse().unwrap(),
                        challenge: B64.decode(body["challenge_b64"].as_str().unwrap()).unwrap(),
                        epoch: body["key_epoch"].as_i64().unwrap(),
                    });
                }
                status
            }
            Command::Prove { slot, honest } => {
                // An attempt that was never issued maps to a fresh unknown id.
                let (recovery_id, challenge, epoch) = match self.attempts.get(slot) {
                    Some(a) => (a.recovery_id, a.challenge.clone(), a.epoch),
                    None => (Uuid::new_v4(), vec![0u8; 32], 1),
                };
                let rms = if honest { RMS } else { WRONG_RMS };
                let proof = vela_crypto::recovery::rms_possession_sign(
                    &rms,
                    &self.user_id.to_string(),
                    &recovery_id.to_string(),
                    &challenge,
                    epoch,
                );
                let (status, body) = post(
                    &self.app,
                    "/recovery/recover/proof",
                    json!({ "user_id": self.user_id, "recovery_id": recovery_id, "proof_b64": B64.encode(proof) }),
                )
                .await;
                if status == StatusCode::OK {
                    assert!(body.get("share").is_none(), "the possession path released the server share");
                    self.grants.push(body["recovery_grant"].as_str().unwrap().parse().unwrap());
                }
                status
            }
            Command::Enroll { slot } => {
                let grant = self.grants.get(slot).copied().unwrap_or_else(Uuid::new_v4);
                post(
                    &self.app,
                    "/recovery/enroll-device",
                    json!({
                        "user_id": self.user_id,
                        "recovery_grant": grant,
                        "hybrid_ek": B64.encode(vec![1u8; 1600]),
                        "hybrid_vk": B64.encode(vec![1u8; 2624]),
                        "device_name": "Recovered",
                    }),
                )
                .await
                .0
            }
            Command::Rotate => {
                self.sql("UPDATE users SET key_epoch = key_epoch + 1 WHERE id = ?").await;
                return None;
            }
            Command::Freeze => {
                self.sql("UPDATE users SET rekey_state = 'freezing' WHERE id = ?").await;
                return None;
            }
            Command::Unfreeze => {
                self.sql("UPDATE users SET rekey_state = NULL WHERE id = ?").await;
                return None;
            }
            Command::Unstage => {
                self.sql("UPDATE users SET recovery_auth_hash = NULL WHERE id = ?").await;
                return None;
            }
            Command::Restage => {
                let commitment = vela_crypto::recovery::rms_possession_commitment(&RMS);
                self.state
                    .sqldb
                    .execute(
                        "UPDATE users SET recovery_auth_hash = ? WHERE id = ?",
                        vec![
                            TursoValue::Text(B64.encode(commitment)),
                            TursoValue::Text(self.user_id.to_string()),
                        ],
                    )
                    .await
                    .unwrap();
                return None;
            }
        })
    }

    async fn devices(&self) -> i64 {
        let rows = self
            .state
            .sqldb
            .query(
                "SELECT COUNT(*) FROM devices WHERE user_id = ?",
                vec![TursoValue::Text(self.user_id.to_string())],
            )
            .await
            .unwrap();
        rows.first().and_then(|row| row.i64(0)).unwrap()
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
async fn every_bounded_possession_recovery_trace_matches_the_m18_chain() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let depth = depth();
    let traces = sequences(depth);
    let mut steps = 0usize;
    let mut seen = std::collections::BTreeSet::new();

    for trace in &traces {
        let mut model = Model::new();
        let mut real = Real::new(&state, app.clone()).await;
        for (step, command) in trace.iter().enumerate() {
            let expected = model.apply(*command);
            let actual = real.apply(*command).await;
            assert_eq!(actual, expected, "status mismatch at step {step} of {trace:?}");
            if let Some(status) = actual {
                seen.insert((command.kind(), status.as_u16()));
            }
            assert_eq!(real.devices().await, model.devices, "device count after step {step} of {trace:?}");
            steps += 1;
        }
    }

    // Non-vacuity: every handler path the model distinguishes was exercised.
    for expected in [
        ("Initiate", 200u16),
        ("Initiate", 404),
        ("Initiate", 409),
        ("Prove", 200),
        ("Prove", 400),
        ("Prove", 401),
        ("Prove", 409),
        ("Enroll", 200),
        ("Enroll", 401),
    ] {
        assert!(seen.contains(&expected), "{expected:?} never exercised: {seen:?}");
    }
    // A paused enrollment needs four steps (initiate, prove, freeze, enroll).
    if depth >= 4 {
        assert!(seen.contains(&("Enroll", 409)), "paused enrollment never exercised: {seen:?}");
    }
    eprintln!("possession recovery model: {} traces, {} steps, depth {}", traces.len(), steps, depth);
}
