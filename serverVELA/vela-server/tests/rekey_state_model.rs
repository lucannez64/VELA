//! Executable reference model for the epoch/rekey state machine.
//!
//! Unlike example-based endpoint tests, this test explores the complete finite
//! state graph through three epochs. Every accepted command is followed to a
//! fixed point; every rejected stale/future/replayed variant is evaluated too.
//! The model is deliberately independent of handler code so it can serve as an
//! oracle for the real-database conformance test below.

use std::collections::{HashSet, VecDeque};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;
use vela_rekey_policy::{
    MutationAuthority, MutationDecision, MutationKind, MutationRequest, Phase as PolicyPhase,
    RekeyState as PolicyState, ShadowDecision,
};

mod helpers;

const DEVICES: u8 = 0b11;
const CHUNKS: u8 = 0b11;
const MAX_EPOCH: u8 = 3;
// Fresh UUIDs make attempts unbounded in production. Four symbolic identities
// cover current, immediately stale, repeated-abort and second-rotation replay
// classes while keeping exhaustive exploration finite.
const MAX_ATTEMPTS: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Phase {
    Active,
    Freezing {
        target: u8,
        rid: u8,
        starter: u8,
        shadows: u8,
        capsules: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct State {
    epoch: u8,
    phase: Phase,
    device_epochs: [u8; 2],
    pending: [Option<(u8, u8)>; 2],
    recovery_epoch: Option<u8>,
    /// Epochs for which an operation was prepared before a possible commit.
    /// Web, recovery and enrollment share the same authority predicate, so one
    /// bitset is sufficient to explore their temporal state without multiplying
    /// equivalent states by 8^3.
    staged_epochs: u8,
    next_rid: u8,
    commits: u8,
}

impl Default for State {
    fn default() -> Self {
        Self {
            epoch: 1,
            phase: Phase::Active,
            device_epochs: [1, 1],
            pending: [None, None],
            recovery_epoch: Some(1),
            staged_epochs: 0,
            next_rid: 1,
            commits: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Command {
    Start {
        actor: u8,
    },
    Shadow {
        actor: u8,
        epoch: u8,
        rid: u8,
        chunk: u8,
    },
    Capsules {
        actor: u8,
        epoch: u8,
        rid: u8,
        device: u8,
    },
    Commit {
        actor: u8,
        epoch: u8,
        rid: u8,
    },
    Abort {
        actor: u8,
        rid: u8,
    },
    Timeout,
    Adopt {
        device: u8,
        outer_epoch: u8,
        inner_epoch: u8,
        rid: u8,
    },
    Ack {
        device: u8,
        epoch: u8,
    },
    StageWeb {
        epoch: u8,
    },
    ExecuteWeb {
        claim_epoch: u8,
        declared_epoch: u8,
    },
    StageRecovery {
        epoch: u8,
    },
    ExecuteRecovery {
        local_epoch: u8,
    },
    StageEnrollment {
        epoch: u8,
    },
    ExecuteEnrollment {
        local_epoch: u8,
    },
    DeviceWrite {
        declared_epoch: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Accepted,
    Rejected,
}

#[derive(Default)]
struct Coverage {
    commit: bool,
    repeated_commit: bool,
    abort: bool,
    timeout: bool,
    pending_blocks_next_rotation: bool,
    acknowledged_devices_enable_next_rotation: bool,
    stale_web_rejected: bool,
    stale_recovery_rejected: bool,
    stale_enrollment_rejected: bool,
    stale_capsule_replay_rejected: bool,
    wrong_starter_rejected: bool,
    incomplete_commit_rejected: bool,
    current_authority_reachable: bool,
}

const fn bit(epoch: u8) -> u8 {
    1u8 << epoch
}

fn execute(mut state: State, command: Command) -> (Outcome, State) {
    let accepted = match command {
        Command::Start { actor } => {
            if state.epoch >= MAX_EPOCH
                || state.next_rid > MAX_ATTEMPTS
                || state.phase != Phase::Active
                || state.pending != [None, None]
                || state.device_epochs != [state.epoch, state.epoch]
            {
                false
            } else {
                let rid = state.next_rid;
                state.next_rid += 1;
                state.phase = Phase::Freezing {
                    target: state.epoch + 1,
                    rid,
                    starter: actor,
                    shadows: 0,
                    capsules: 0,
                };
                true
            }
        }
        Command::Shadow {
            actor,
            epoch,
            rid,
            chunk,
        } => match state.phase {
            Phase::Freezing {
                target,
                rid: current,
                starter,
                ref mut shadows,
                ..
            } if actor == starter && epoch == target && rid == current && chunk < 2 => {
                *shadows |= 1 << chunk;
                true
            }
            _ => false,
        },
        Command::Capsules {
            actor,
            epoch,
            rid,
            device,
        } => match state.phase {
            Phase::Freezing {
                target,
                rid: current,
                starter,
                ref mut capsules,
                ..
            } if actor == starter && epoch == target && rid == current && device < 2 => {
                *capsules |= 1 << device;
                true
            }
            _ => false,
        },
        Command::Commit { actor, epoch, rid } => match state.phase {
            Phase::Freezing {
                target,
                rid: current,
                starter,
                shadows,
                capsules,
            } if actor == starter
                && epoch == target
                && rid == current
                && shadows == CHUNKS
                && capsules == DEVICES =>
            {
                state.epoch = target;
                state.phase = Phase::Active;
                state.pending = [Some((target, rid)), Some((target, rid))];
                state.recovery_epoch = None;
                state.commits += 1;
                true
            }
            _ => false,
        },
        Command::Abort { actor, rid } => match state.phase {
            Phase::Freezing {
                rid: current,
                starter,
                ..
            } if actor == starter && rid == current => {
                state.phase = Phase::Active;
                true
            }
            _ => false,
        },
        Command::Timeout => match state.phase {
            Phase::Freezing { .. } => {
                state.phase = Phase::Active;
                true
            }
            Phase::Active => false,
        },
        Command::Adopt {
            device,
            outer_epoch,
            inner_epoch,
            rid,
        } => {
            let Some(slot) = state.pending.get_mut(device as usize) else {
                return (Outcome::Rejected, state);
            };
            match *slot {
                Some((target, current_rid))
                    if outer_epoch == target
                        && inner_epoch == target
                        && rid == current_rid
                        && target == state.epoch
                        && state.device_epochs[device as usize] + 1 == target =>
                {
                    state.device_epochs[device as usize] = target;
                    true
                }
                _ => false,
            }
        }
        Command::Ack { device, epoch } => {
            let Some(slot) = state.pending.get_mut(device as usize) else {
                return (Outcome::Rejected, state);
            };
            match *slot {
                Some((target, _))
                    if epoch == target && state.device_epochs[device as usize] == target =>
                {
                    *slot = None;
                    true
                }
                None if epoch == state.device_epochs[device as usize] => true,
                _ => false,
            }
        }
        Command::StageWeb { epoch } => {
            if epoch == state.epoch {
                state.staged_epochs |= bit(epoch);
                true
            } else {
                false
            }
        }
        Command::ExecuteWeb {
            claim_epoch,
            declared_epoch,
        } => {
            state.phase == Phase::Active
                && claim_epoch == declared_epoch
                && declared_epoch == state.epoch
                && state.staged_epochs & bit(claim_epoch) != 0
        }
        Command::StageRecovery { epoch } => {
            if state.device_epochs.contains(&epoch) {
                state.staged_epochs |= bit(epoch);
                true
            } else {
                false
            }
        }
        Command::ExecuteRecovery { local_epoch } => {
            if state.phase == Phase::Active
                && local_epoch == state.epoch
                && state.staged_epochs & bit(local_epoch) != 0
            {
                state.recovery_epoch = Some(local_epoch);
                true
            } else {
                false
            }
        }
        Command::StageEnrollment { epoch } => {
            if state.device_epochs.contains(&epoch) {
                state.staged_epochs |= bit(epoch);
                true
            } else {
                false
            }
        }
        Command::ExecuteEnrollment { local_epoch } => {
            state.phase == Phase::Active
                && local_epoch == state.epoch
                && state.staged_epochs & bit(local_epoch) != 0
        }
        Command::DeviceWrite { declared_epoch } => {
            state.phase == Phase::Active && declared_epoch == state.epoch
        }
    };
    (
        if accepted {
            Outcome::Accepted
        } else {
            Outcome::Rejected
        },
        state,
    )
}

fn commands(state: State) -> Vec<Command> {
    let stale = state.epoch.saturating_sub(1);
    let future = (state.epoch + 1).min(MAX_EPOCH + 1);
    let mut out = vec![
        Command::Start { actor: 0 },
        Command::Start { actor: 1 },
        Command::StageWeb { epoch: state.epoch },
        Command::StageWeb { epoch: stale },
        Command::ExecuteWeb {
            claim_epoch: state.epoch,
            declared_epoch: state.epoch,
        },
        Command::ExecuteWeb {
            claim_epoch: stale,
            declared_epoch: state.epoch,
        },
        Command::ExecuteWeb {
            claim_epoch: state.epoch,
            declared_epoch: future,
        },
        Command::StageRecovery { epoch: state.epoch },
        Command::StageRecovery { epoch: stale },
        Command::ExecuteRecovery {
            local_epoch: state.epoch,
        },
        Command::ExecuteRecovery { local_epoch: stale },
        Command::StageEnrollment { epoch: state.epoch },
        Command::StageEnrollment { epoch: stale },
        Command::ExecuteEnrollment {
            local_epoch: state.epoch,
        },
        Command::ExecuteEnrollment { local_epoch: stale },
        Command::DeviceWrite {
            declared_epoch: state.epoch,
        },
        Command::DeviceWrite {
            declared_epoch: stale,
        },
        Command::DeviceWrite {
            declared_epoch: future,
        },
        Command::Timeout,
    ];

    let (target, rid, starter) = match state.phase {
        Phase::Active => (future, state.next_rid, 0),
        Phase::Freezing {
            target,
            rid,
            starter,
            ..
        } => (target, rid, starter),
    };
    let wrong_rid = rid.saturating_add(7);
    for actor in 0..2 {
        for chunk in 0..2 {
            out.push(Command::Shadow {
                actor,
                epoch: target,
                rid,
                chunk,
            });
        }
        for device in 0..2 {
            out.push(Command::Capsules {
                actor,
                epoch: target,
                rid,
                device,
            });
        }
        out.push(Command::Commit {
            actor,
            epoch: target,
            rid,
        });
        out.push(Command::Abort { actor, rid });
    }
    out.extend([
        Command::Shadow {
            actor: starter,
            epoch: state.epoch,
            rid,
            chunk: 0,
        },
        Command::Shadow {
            actor: starter,
            epoch: target,
            rid: wrong_rid,
            chunk: 0,
        },
        Command::Capsules {
            actor: starter,
            epoch: state.epoch,
            rid,
            device: 0,
        },
        Command::Capsules {
            actor: starter,
            epoch: target,
            rid: wrong_rid,
            device: 0,
        },
        Command::Commit {
            actor: starter,
            epoch: target,
            rid: wrong_rid,
        },
        Command::Abort {
            actor: starter,
            rid: wrong_rid,
        },
    ]);
    for device in 0..2 {
        let pending = state.pending[device as usize].unwrap_or((state.epoch, rid));
        out.extend([
            Command::Adopt {
                device,
                outer_epoch: pending.0,
                inner_epoch: pending.0,
                rid: pending.1,
            },
            Command::Adopt {
                device,
                outer_epoch: state.epoch,
                inner_epoch: stale,
                rid: pending.1,
            },
            Command::Adopt {
                device,
                outer_epoch: state.epoch,
                inner_epoch: state.epoch,
                rid: wrong_rid,
            },
            Command::Ack {
                device,
                epoch: state.epoch,
            },
            Command::Ack {
                device,
                epoch: stale,
            },
        ]);
    }
    out
}

fn assert_invariants(state: State) {
    assert!((1..=MAX_EPOCH).contains(&state.epoch));
    assert!(state
        .device_epochs
        .iter()
        .all(|e| *e >= 1 && *e <= state.epoch));
    assert!(state.recovery_epoch.is_none_or(|e| e == state.epoch));
    for (index, pending) in state.pending.iter().enumerate() {
        if let Some((target, _)) = pending {
            assert_eq!(*target, state.epoch);
            assert!(
                state.device_epochs[index] == state.epoch
                    || state.device_epochs[index] + 1 == state.epoch
            );
        }
    }
    if let Phase::Freezing {
        target,
        shadows,
        capsules,
        ..
    } = state.phase
    {
        assert_eq!(target, state.epoch + 1);
        assert_eq!(shadows & !CHUNKS, 0);
        assert_eq!(capsules & !DEVICES, 0);
        assert_eq!(state.pending, [None, None]);
    }
}

#[test]
fn verified_mutation_permit_matches_the_m11c_authority_relation() {
    let kinds = [
        MutationKind::Vault,
        MutationKind::Recovery,
        MutationKind::Enrollment,
    ];
    let authorities = [
        MutationAuthority::Device,
        MutationAuthority::WebSession,
        MutationAuthority::RecoveryGrant,
    ];
    for state_epoch in 1..=3i64 {
        for phase in [PolicyPhase::Active, PolicyPhase::Freezing] {
            let state = PolicyState {
                epoch: state_epoch,
                phase,
            };
            for declared_epoch in 0..=4i64 {
                for authority_epoch in 0..=4i64 {
                    for kind in kinds {
                        for authority in authorities {
                            let request = MutationRequest {
                                declared_epoch,
                                authority_epoch,
                                kind,
                                authority,
                            };
                            let scope_allowed = match kind {
                                MutationKind::Vault => {
                                    authority == MutationAuthority::Device
                                        || authority == MutationAuthority::WebSession
                                }
                                MutationKind::Recovery => authority == MutationAuthority::Device,
                                MutationKind::Enrollment => {
                                    authority == MutationAuthority::Device
                                        || authority == MutationAuthority::RecoveryGrant
                                }
                            };
                            let request_expected = declared_epoch >= 1
                                && authority_epoch >= 1
                                && declared_epoch == authority_epoch
                                && scope_allowed;
                            let decision = vela_rekey_policy::plan_active_mutation(request);
                            assert_eq!(
                                matches!(decision, MutationDecision::Permit(_)),
                                request_expected,
                                "request mismatch: {request:?}"
                            );
                            if let MutationDecision::Permit(permit) = decision {
                                let state_expected =
                                    phase == PolicyPhase::Active && state_epoch == declared_epoch;
                                assert_eq!(
                                    vela_rekey_policy::authorize_active_mutation(state, permit)
                                        == ShadowDecision::Allow,
                                    state_expected,
                                    "state mismatch: {state:?} {request:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
        let permit = match vela_rekey_policy::plan_active_mutation(MutationRequest {
            declared_epoch: state_epoch,
            authority_epoch: state_epoch,
            kind: MutationKind::Vault,
            authority: MutationAuthority::Device,
        }) {
            MutationDecision::Permit(permit) => permit,
            MutationDecision::Reject => unreachable!(),
        };
        assert!(!vela_rekey_policy::stale_permit_authorizes_successor(
            PolicyState {
                epoch: state_epoch,
                phase: PolicyPhase::Active,
            },
            permit,
        ));
    }
}

#[test]
fn every_bounded_reachable_state_preserves_epoch_invariants() {
    let initial = State::default();
    let mut seen = HashSet::from([initial]);
    let mut queue = VecDeque::from([initial]);
    let mut coverage = Coverage::default();

    while let Some(state) = queue.pop_front() {
        assert_invariants(state);
        for command in commands(state) {
            let (outcome, next) = execute(state, command);
            assert_invariants(next);

            match (command, outcome) {
                (Command::Commit { .. }, Outcome::Accepted) => {
                    coverage.commit = true;
                    coverage.repeated_commit |= next.commits >= 2;
                }
                (Command::Commit { .. }, Outcome::Rejected) => {
                    if let Phase::Freezing {
                        shadows, capsules, ..
                    } = state.phase
                    {
                        coverage.incomplete_commit_rejected |=
                            shadows != CHUNKS || capsules != DEVICES;
                    }
                }
                (Command::Abort { .. }, Outcome::Accepted) => coverage.abort = true,
                (Command::Timeout, Outcome::Accepted) => coverage.timeout = true,
                (Command::Start { .. }, Outcome::Rejected) if state.pending != [None, None] => {
                    coverage.pending_blocks_next_rotation = true;
                }
                (Command::Start { .. }, Outcome::Accepted) if state.commits > 0 => {
                    coverage.acknowledged_devices_enable_next_rotation = true;
                }
                (Command::ExecuteWeb { claim_epoch, .. }, Outcome::Rejected)
                    if claim_epoch < state.epoch =>
                {
                    coverage.stale_web_rejected = true
                }
                (Command::ExecuteRecovery { local_epoch }, Outcome::Rejected)
                    if local_epoch < state.epoch =>
                {
                    coverage.stale_recovery_rejected = true
                }
                (Command::ExecuteEnrollment { local_epoch }, Outcome::Rejected)
                    if local_epoch < state.epoch =>
                {
                    coverage.stale_enrollment_rejected = true
                }
                (Command::Adopt { inner_epoch, .. }, Outcome::Rejected)
                    if inner_epoch < state.epoch =>
                {
                    coverage.stale_capsule_replay_rejected = true
                }
                (Command::Shadow { actor, .. }, Outcome::Rejected)
                | (Command::Capsules { actor, .. }, Outcome::Rejected)
                    if matches!(state.phase, Phase::Freezing { starter, .. } if actor != starter) =>
                {
                    coverage.wrong_starter_rejected = true;
                }
                (Command::DeviceWrite { declared_epoch }, Outcome::Accepted)
                    if declared_epoch == state.epoch =>
                {
                    coverage.current_authority_reachable = true
                }
                _ => {}
            }

            if outcome == Outcome::Accepted && seen.insert(next) {
                queue.push_back(next);
            }
        }
    }

    assert!(
        seen.len() >= 100,
        "state exploration was unexpectedly shallow: {}",
        seen.len()
    );
    assert!(coverage.commit);
    assert!(coverage.repeated_commit);
    assert!(coverage.abort);
    assert!(coverage.timeout);
    assert!(coverage.pending_blocks_next_rotation);
    assert!(coverage.acknowledged_devices_enable_next_rotation);
    assert!(coverage.stale_web_rejected);
    assert!(coverage.stale_recovery_rejected);
    assert!(coverage.stale_enrollment_rejected);
    assert!(coverage.stale_capsule_replay_rejected);
    assert!(coverage.wrong_starter_rejected);
    assert!(coverage.incomplete_commit_rejected);
    assert!(coverage.current_authority_reachable);
}

fn permutations() -> Vec<[u8; 4]> {
    fn visit(values: &mut [u8; 4], at: usize, out: &mut Vec<[u8; 4]>) {
        if at == values.len() {
            out.push(*values);
            return;
        }
        for index in at..values.len() {
            values.swap(at, index);
            visit(values, at + 1, out);
            values.swap(at, index);
        }
    }
    let mut values = [0, 1, 2, 3];
    let mut out = Vec::new();
    visit(&mut values, 0, &mut out);
    out
}

fn issue_token(state: &vela_server::state::AppState, user_id: Uuid, device_id: Uuid) -> String {
    let service = vela_server::auth::token::TokenService::new(
        state.paseto_sk.clone(),
        state.paseto_pk.clone(),
    );
    let (token, jti) = service.issue(user_id, device_id, None).unwrap();
    vela_server::rate_limit::track_device_jti(&state.store, &device_id.to_string(), &jti).unwrap();
    token
}

/// Replay all 4! orderings of the two chunk-shadow and two device-capsule
/// obligations through the real Axum handlers and Turso transactions. After
/// every strict prefix the model says commit is incomplete and the SQL must
/// reject it; after the final obligation both must accept exactly once.
#[tokio::test]
async fn every_completeness_order_matches_the_real_atomic_commit_guard() {
    use vela_server::sqldb::{Db as _, TursoValue};

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let orders = permutations();
    assert_eq!(orders.len(), 24);

    for order in orders {
        let user = Uuid::new_v4();
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        let now = chrono::Utc::now().to_rfc3339();
        state
            .sqldb
            .execute(
                "INSERT INTO users (id, recovery_share, created_at)
                 VALUES (?, 'epoch-one-share', ?)",
                vec![
                    TursoValue::Text(user.to_string()),
                    TursoValue::Text(now.clone()),
                ],
            )
            .await
            .unwrap();
        for device in devices {
            state
                .sqldb
                .execute(
                    "INSERT INTO devices
                     (id, user_id, hybrid_ek, hybrid_vk, revoked, rekey_capable, created_at)
                     VALUES (?, ?, ?, ?, 0, 1, ?)",
                    vec![
                        TursoValue::Text(device.to_string()),
                        TursoValue::Text(user.to_string()),
                        TursoValue::Text(B64.encode(vec![0u8; 1600])),
                        TursoValue::Text(B64.encode(vec![0u8; 2624])),
                        TursoValue::Text(now.clone()),
                    ],
                )
                .await
                .unwrap();
        }
        for chunk in ["model-a", "model-b"] {
            state
                .sqldb
                .execute(
                    "INSERT INTO vault_chunks
                     (chunk_id, user_id, version, lamport_clock, last_writer,
                      ciphertext, epoch, created_at, updated_at)
                     VALUES (?, ?, 1, 1, ?, 'b2xk', 1, ?, ?)",
                    vec![
                        TursoValue::Text(chunk.into()),
                        TursoValue::Text(user.to_string()),
                        TursoValue::Text(devices[0].to_string()),
                        TursoValue::Text(now.clone()),
                        TursoValue::Text(now.clone()),
                    ],
                )
                .await
                .unwrap();
        }
        let token = issue_token(&state, user, devices[0]);
        let start = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vault/rekey/start")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::OK, "order {order:?}");
        let start_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(start.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let rid = start_body["rotation_id"].as_str().unwrap().to_string();
        assert_eq!(start_body["epoch"], 2);
        assert_eq!(start_body["chunks"].as_array().unwrap().len(), 2);

        for (position, artifact) in order.into_iter().enumerate() {
            let response = match artifact {
                chunk @ 0..=1 => {
                    let chunk_id = ["model-a", "model-b"][chunk as usize];
                    app.clone()
                        .oneshot(
                            Request::builder()
                                .method("PUT")
                                .uri(format!("/vault/chunk/{chunk_id}"))
                                .header("authorization", format!("Bearer {token}"))
                                .header("if-match", "0")
                                .header("x-lamport-clock", "2")
                                .header("x-vela-epoch", "2")
                                .header("x-vela-rekey-id", &rid)
                                .body(Body::from(vec![2u8, chunk]))
                                .unwrap(),
                        )
                        .await
                        .unwrap()
                }
                capsule @ 2..=3 => {
                    let device = devices[(capsule - 2) as usize];
                    app.clone()
                        .oneshot(
                            Request::builder()
                                .method("POST")
                                .uri("/vault/rekey/capsules")
                                .header("authorization", format!("Bearer {token}"))
                                .header("x-vela-rekey-id", &rid)
                                .header("content-type", "application/json")
                                .body(Body::from(
                                    json!({ "capsules": {
                                        device.to_string(): B64.encode([capsule; 32])
                                    } })
                                    .to_string(),
                                ))
                                .unwrap(),
                        )
                        .await
                        .unwrap()
                }
                _ => unreachable!(),
            };
            assert!(
                response.status().is_success(),
                "artifact {artifact} failed in order {order:?}: {}",
                response.status()
            );

            let commit = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/vault/rekey/commit")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-vela-rekey-id", &rid)
                        .header("x-vela-epoch", "2")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let expected = if position == 3 {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CONFLICT
            };
            assert_eq!(commit.status(), expected, "prefix {position} of {order:?}");
        }

        let user_row = state
            .sqldb
            .query(
                "SELECT key_epoch, rekey_state, recovery_share FROM users WHERE id = ?",
                vec![TursoValue::Text(user.to_string())],
            )
            .await
            .unwrap();
        assert_eq!(user_row[0].i64(0), Some(2));
        assert!(user_row[0].text(1).is_none());
        assert!(user_row[0].text(2).is_none());
        let chunks = state
            .sqldb
            .query(
                "SELECT chunk_id, epoch FROM vault_chunks
                 WHERE user_id = ? ORDER BY chunk_id, epoch",
                vec![TursoValue::Text(user.to_string())],
            )
            .await
            .unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|row| row.i64(1) == Some(2)));
        let capsules = state
            .sqldb
            .query(
                "SELECT rms_capsule_epoch FROM devices WHERE user_id = ?",
                vec![TursoValue::Text(user.to_string())],
            )
            .await
            .unwrap();
        assert_eq!(capsules.len(), 2);
        assert!(capsules.iter().all(|row| row.i64(0) == Some(2)));
    }
}

#[tokio::test]
async fn concurrent_start_and_active_write_have_a_lossless_linearization() {
    use vela_server::sqldb::{Db as _, TursoValue};

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    for attempt in 0..24 {
        let user = Uuid::new_v4();
        let device = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();
        state
            .sqldb
            .execute(
                "INSERT INTO users (id, created_at) VALUES (?, ?)",
                vec![
                    TursoValue::Text(user.to_string()),
                    TursoValue::Text(now.clone()),
                ],
            )
            .await
            .unwrap();
        state
            .sqldb
            .execute(
                "INSERT INTO devices
                 (id, user_id, hybrid_ek, hybrid_vk, revoked, rekey_capable, created_at)
                 VALUES (?, ?, ?, ?, 0, 1, ?)",
                vec![
                    TursoValue::Text(device.to_string()),
                    TursoValue::Text(user.to_string()),
                    TursoValue::Text(B64.encode(vec![0u8; 1600])),
                    TursoValue::Text(B64.encode(vec![0u8; 2624])),
                    TursoValue::Text(now.clone()),
                ],
            )
            .await
            .unwrap();
        state
            .sqldb
            .execute(
                "INSERT INTO vault_chunks
                 (chunk_id, user_id, version, lamport_clock, last_writer,
                  ciphertext, epoch, created_at, updated_at)
                 VALUES ('race', ?, 1, 1, ?, 'b2xk', 1, ?, ?)",
                vec![
                    TursoValue::Text(user.to_string()),
                    TursoValue::Text(device.to_string()),
                    TursoValue::Text(now.clone()),
                    TursoValue::Text(now),
                ],
            )
            .await
            .unwrap();
        let token = issue_token(&state, user, device);
        let start = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/start")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        );
        let write = app.clone().oneshot(
            Request::builder()
                .method("PUT")
                .uri("/vault/chunk/race")
                .header("authorization", format!("Bearer {token}"))
                .header("if-match", "1")
                .header("x-lamport-clock", "2")
                .header("x-vela-epoch", "1")
                .body(Body::from(vec![9u8, attempt]))
                .unwrap(),
        );
        let (start, write) = tokio::join!(start, write);
        let start = start.unwrap();
        let write = write.unwrap();
        assert_eq!(start.status(), StatusCode::OK, "attempt {attempt}");
        assert!(
            matches!(write.status(), StatusCode::OK | StatusCode::CONFLICT),
            "unexpected write result on attempt {attempt}: {}",
            write.status()
        );
        let start_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(start.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let inventory_version = start_body["chunks"][0]["version"].as_i64().unwrap();
        let expected = if write.status() == StatusCode::OK {
            2
        } else {
            1
        };
        assert_eq!(inventory_version, expected, "attempt {attempt}");
        let row = state
            .sqldb
            .query(
                "SELECT version, epoch FROM vault_chunks
                 WHERE user_id = ? AND chunk_id = 'race'",
                vec![TursoValue::Text(user.to_string())],
            )
            .await
            .unwrap();
        assert_eq!(row.len(), 1);
        assert_eq!(row[0].i64(0), Some(expected));
        assert_eq!(row[0].i64(1), Some(1));
    }
}

#[tokio::test]
async fn expired_rotation_beats_commit_and_cleans_every_attempt_artifact() {
    use vela_server::sqldb::{Db as _, TursoValue};

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let expired = (chrono::Utc::now() - chrono::Duration::minutes(16)).to_rfc3339();
    let rid = Uuid::new_v4().to_string();
    state
        .sqldb
        .execute(
            "INSERT INTO users
             (id, key_epoch, rekey_state, rekey_started_at, rekey_starter,
              rekey_id, recovery_share, created_at)
             VALUES (?, 1, 'freezing', ?, ?, ?, 'old-share', ?)",
            vec![
                TursoValue::Text(user.to_string()),
                TursoValue::Text(expired),
                TursoValue::Text(device.to_string()),
                TursoValue::Text(rid.clone()),
                TursoValue::Text(now.clone()),
            ],
        )
        .await
        .unwrap();
    state
        .sqldb
        .execute(
            "INSERT INTO devices
             (id, user_id, hybrid_ek, hybrid_vk, rms_capsule,
              rms_capsule_epoch, revoked, rekey_capable, created_at)
             VALUES (?, ?, ?, ?, 'Y2Fw', 2, 0, 1, ?)",
            vec![
                TursoValue::Text(device.to_string()),
                TursoValue::Text(user.to_string()),
                TursoValue::Text(B64.encode(vec![0u8; 1600])),
                TursoValue::Text(B64.encode(vec![0u8; 2624])),
                TursoValue::Text(now.clone()),
            ],
        )
        .await
        .unwrap();
    for epoch in [1, 2] {
        state
            .sqldb
            .execute(
                "INSERT INTO vault_chunks
                 (chunk_id, user_id, version, lamport_clock, last_writer,
                  ciphertext, epoch, created_at, updated_at)
                 VALUES ('timeout', ?, 1, 1, ?, 'Y3Q=', ?, ?, ?)",
                vec![
                    TursoValue::Text(user.to_string()),
                    TursoValue::Text(device.to_string()),
                    TursoValue::Integer(epoch),
                    TursoValue::Text(now.clone()),
                    TursoValue::Text(now.clone()),
                ],
            )
            .await
            .unwrap();
    }
    let token = issue_token(&state, user, device);
    let observe = app.clone().oneshot(
        Request::builder()
            .uri("/vault/epoch")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    );
    let commit = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/vault/rekey/commit")
            .header("authorization", format!("Bearer {token}"))
            .header("x-vela-rekey-id", &rid)
            .header("x-vela-epoch", "2")
            .body(Body::empty())
            .unwrap(),
    );
    let (observe, commit) = tokio::join!(observe, commit);
    let observe = observe.unwrap();
    let commit = commit.unwrap();
    assert_eq!(observe.status(), StatusCode::OK);
    assert_eq!(commit.status(), StatusCode::CONFLICT);
    let epoch: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(observe.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(epoch["epoch"], 1);
    assert_eq!(epoch["state"], "active");

    let user_row = state
        .sqldb
        .query(
            "SELECT key_epoch, rekey_state, recovery_share FROM users WHERE id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    assert_eq!(user_row[0].i64(0), Some(1));
    assert!(user_row[0].text(1).is_none());
    assert_eq!(user_row[0].text(2), Some("old-share"));
    let chunks = state
        .sqldb
        .query(
            "SELECT epoch FROM vault_chunks WHERE user_id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].i64(0), Some(1));
    let device_row = state
        .sqldb
        .query(
            "SELECT rms_capsule, rms_capsule_epoch FROM devices WHERE id = ?",
            vec![TursoValue::Text(device.to_string())],
        )
        .await
        .unwrap();
    assert!(device_row[0].text(0).is_none());
    assert!(device_row[0].i64(1).is_none());

    // A delayed shadow from the expired attempt can no longer recreate output.
    let delayed = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/vault/chunk/timeout")
                .header("authorization", format!("Bearer {token}"))
                .header("if-match", "0")
                .header("x-lamport-clock", "2")
                .header("x-vela-epoch", "2")
                .header("x-vela-rekey-id", &rid)
                .body(Body::from(vec![2u8]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delayed.status(), StatusCode::CONFLICT);
}
