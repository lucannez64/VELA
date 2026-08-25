//! Pure authorization policy for vault epoch rotation.
//!
//! This crate intentionally contains no HTTP, database, clock, UUID, or async
//! code. Production handlers turn authenticated/database facts into these
//! small value types and must use the returned decision. Keeping that boundary
//! functional lets hax extract the actual Rust policy into F* and prove that
//! every write and lifecycle decision has the epoch, readiness, completeness,
//! and authority shape claimed by the Tamarin M11/M11c models.

/// Epoch zero is reserved; every persisted account begins at epoch one.
pub const INITIAL_EPOCH: i64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Active,
    Freezing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyState {
    pub epoch: i64,
    pub phase: Phase,
}

impl RekeyState {
    pub const fn is_valid(self) -> bool {
        self.epoch >= INITIAL_EPOCH
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochRoute {
    pub write_epoch: i64,
    pub read_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteDecision {
    Accept(EpochRoute),
    Reject,
}

/// Return the exact successor without ever overflowing at the integer bound.
#[cfg_attr(hax, hax_lib::ensures(|result| match result {
    Some(next) => epoch < i64::MAX && next == epoch + 1,
    None => epoch == i64::MAX,
}))]
pub fn next_epoch(epoch: i64) -> Option<i64> {
    if epoch == i64::MAX {
        None
    } else {
        Some(epoch + 1)
    }
}

/// The complete acceptance predicate for an ordinary or shadow write.
pub fn write_is_accepted(state: RekeyState, declared: Option<i64>) -> bool {
    if !state.is_valid() {
        return false;
    }
    match state.phase {
        Phase::Active => {
            declared == Some(state.epoch) || (state.epoch == INITIAL_EPOCH && declared.is_none())
        }
        Phase::Freezing => match next_epoch(state.epoch) {
            Some(next) => declared == Some(next),
            None => false,
        },
    }
}

/// State the full functional specification of [`resolve_write_epoch`].
pub fn write_decision_matches_spec(
    state: RekeyState,
    declared: Option<i64>,
    decision: WriteDecision,
) -> bool {
    match decision {
        WriteDecision::Accept(route) => {
            write_is_accepted(state, declared)
                && route.read_epoch == state.epoch
                && match state.phase {
                    Phase::Active => route.write_epoch == state.epoch,
                    Phase::Freezing => next_epoch(state.epoch) == Some(route.write_epoch),
                }
        }
        WriteDecision::Reject => !write_is_accepted(state, declared),
    }
}

/// Decide which epoch a ciphertext may be written to and which epoch remains
/// readable. This is the pure implementation used by the server write paths.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    write_decision_matches_spec(state, declared, decision)
}))]
pub fn resolve_write_epoch(state: RekeyState, declared: Option<i64>) -> WriteDecision {
    if !state.is_valid() {
        return WriteDecision::Reject;
    }
    match state.phase {
        Phase::Active => {
            if declared == Some(state.epoch) || (state.epoch == INITIAL_EPOCH && declared.is_none())
            {
                WriteDecision::Accept(EpochRoute {
                    write_epoch: state.epoch,
                    read_epoch: state.epoch,
                })
            } else {
                WriteDecision::Reject
            }
        }
        Phase::Freezing => match next_epoch(state.epoch) {
            Some(next) if declared == Some(next) => WriteDecision::Accept(EpochRoute {
                write_epoch: next,
                read_epoch: state.epoch,
            }),
            _ => WriteDecision::Reject,
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartFacts {
    pub no_oram: bool,
    pub all_devices_rekey_capable: bool,
    pub all_devices_acknowledged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionPlan {
    pub from_epoch: i64,
    pub to_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartDecision {
    Start(TransitionPlan),
    Reject,
}

/// Whether an ACTIVE account is ready to begin exactly one rotation.
pub fn start_is_authorized(state: RekeyState, facts: StartFacts) -> bool {
    state.is_valid()
        && state.phase == Phase::Active
        && next_epoch(state.epoch).is_some()
        && facts.no_oram
        && facts.all_devices_rekey_capable
        && facts.all_devices_acknowledged
}

pub fn start_decision_matches_spec(
    state: RekeyState,
    facts: StartFacts,
    decision: StartDecision,
) -> bool {
    match decision {
        StartDecision::Start(plan) => {
            start_is_authorized(state, facts)
                && plan.from_epoch == state.epoch
                && next_epoch(state.epoch) == Some(plan.to_epoch)
        }
        StartDecision::Reject => !start_is_authorized(state, facts),
    }
}

/// Produce the only legal transition plan for a new rotation.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    start_decision_matches_spec(state, facts, decision)
}))]
pub fn plan_start(state: RekeyState, facts: StartFacts) -> StartDecision {
    if !start_is_authorized(state, facts) {
        return StartDecision::Reject;
    }
    match next_epoch(state.epoch) {
        Some(to_epoch) => StartDecision::Start(TransitionPlan {
            from_epoch: state.epoch,
            to_epoch,
        }),
        None => StartDecision::Reject,
    }
}

/// Authenticated facts tying an operation to the current rotation attempt.
/// These are computed by comparing the authenticated session and request with
/// the current database row; no identity strings enter the proof core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptAuthority {
    pub device_scope: bool,
    pub starter_matches: bool,
    pub rotation_id_present: bool,
    pub rotation_id_matches: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowDecision {
    Allow,
    Reject,
}

pub fn attempt_is_authorized(state: RekeyState, authority: AttemptAuthority) -> bool {
    state.is_valid()
        && state.phase == Phase::Freezing
        && authority.device_scope
        && authority.starter_matches
        && authority.rotation_id_present
        && authority.rotation_id_matches
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    (decision == ShadowDecision::Allow) == attempt_is_authorized(state, authority)
}))]
pub fn authorize_attempt(state: RekeyState, authority: AttemptAuthority) -> ShadowDecision {
    if attempt_is_authorized(state, authority) {
        ShadowDecision::Allow
    } else {
        ShadowDecision::Reject
    }
}

/// Exact authorization predicate for target-epoch shadow ciphertext.
pub fn shadow_is_authorized(
    state: RekeyState,
    route: EpochRoute,
    authority: AttemptAuthority,
) -> bool {
    attempt_is_authorized(state, authority)
        && next_epoch(state.epoch) == Some(route.write_epoch)
        && route.read_epoch == state.epoch
}

/// Authorize a shadow write using only already-authenticated facts.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    (decision == ShadowDecision::Allow) == shadow_is_authorized(state, route, authority)
}))]
pub fn authorize_shadow(
    state: RekeyState,
    route: EpochRoute,
    authority: AttemptAuthority,
) -> ShadowDecision {
    if shadow_is_authorized(state, route, authority) {
        ShadowDecision::Allow
    } else {
        ShadowDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitFacts {
    pub authority: AttemptAuthority,
    pub chunk_shadows_complete: bool,
    pub device_capsules_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDecision {
    Commit(TransitionPlan),
    Reject,
}

pub fn commit_is_authorized(state: RekeyState, facts: CommitFacts) -> bool {
    attempt_is_authorized(state, facts.authority)
        && next_epoch(state.epoch).is_some()
        && facts.chunk_shadows_complete
        && facts.device_capsules_complete
}

pub fn commit_decision_matches_spec(
    state: RekeyState,
    facts: CommitFacts,
    decision: CommitDecision,
) -> bool {
    match decision {
        CommitDecision::Commit(plan) => {
            commit_is_authorized(state, facts)
                && plan.from_epoch == state.epoch
                && next_epoch(state.epoch) == Some(plan.to_epoch)
        }
        CommitDecision::Reject => !commit_is_authorized(state, facts),
    }
}

/// Commit only an authorized, structurally complete rotation and advance by
/// exactly one representable epoch.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    commit_decision_matches_spec(state, facts, decision)
}))]
pub fn plan_commit(state: RekeyState, facts: CommitFacts) -> CommitDecision {
    if !commit_is_authorized(state, facts) {
        return CommitDecision::Reject;
    }
    match next_epoch(state.epoch) {
        Some(to_epoch) => CommitDecision::Commit(TransitionPlan {
            from_epoch: state.epoch,
            to_epoch,
        }),
        None => CommitDecision::Reject,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortDecision {
    Abort(RekeyState),
    Reject,
}

pub fn abort_decision_matches_spec(
    state: RekeyState,
    authority: AttemptAuthority,
    decision: AbortDecision,
) -> bool {
    match decision {
        AbortDecision::Abort(after) => {
            attempt_is_authorized(state, authority)
                && after.epoch == state.epoch
                && after.phase == Phase::Active
        }
        AbortDecision::Reject => !attempt_is_authorized(state, authority),
    }
}

/// Abort an authorized attempt without changing its authoritative epoch.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    abort_decision_matches_spec(state, authority, decision)
}))]
pub fn plan_abort(state: RekeyState, authority: AttemptAuthority) -> AbortDecision {
    if attempt_is_authorized(state, authority) {
        AbortDecision::Abort(RekeyState {
            epoch: state.epoch,
            phase: Phase::Active,
        })
    } else {
        AbortDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutFacts {
    pub expired: bool,
    pub rotation_id_present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutDecision {
    Rollback(RekeyState),
    Keep,
}

pub fn timeout_is_required(state: RekeyState, facts: TimeoutFacts) -> bool {
    state.is_valid() && state.phase == Phase::Freezing && facts.expired && facts.rotation_id_present
}

pub fn timeout_decision_matches_spec(
    state: RekeyState,
    facts: TimeoutFacts,
    decision: TimeoutDecision,
) -> bool {
    match decision {
        TimeoutDecision::Rollback(after) => {
            timeout_is_required(state, facts)
                && after.epoch == state.epoch
                && after.phase == Phase::Active
        }
        TimeoutDecision::Keep => !timeout_is_required(state, facts),
    }
}

/// Roll back an expired attempt without advancing its authoritative epoch.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    timeout_decision_matches_spec(state, facts, decision)
}))]
pub fn plan_timeout(state: RekeyState, facts: TimeoutFacts) -> TimeoutDecision {
    if timeout_is_required(state, facts) {
        TimeoutDecision::Rollback(RekeyState {
            epoch: state.epoch,
            phase: Phase::Active,
        })
    } else {
        TimeoutDecision::Keep
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReplayFacts {
    pub target_epoch: Option<i64>,
    pub recorded_epoch: Option<i64>,
    pub rotation_id_present: bool,
    pub rotation_id_matches: bool,
}

pub fn commit_replay_is_authorized(state: RekeyState, facts: CommitReplayFacts) -> bool {
    state.is_valid()
        && state.phase == Phase::Active
        && facts.target_epoch == Some(state.epoch)
        && facts.recorded_epoch == Some(state.epoch)
        && facts.rotation_id_present
        && facts.rotation_id_matches
}

/// Accept a lost-response replay exactly when it names the recorded commit.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    (decision == ShadowDecision::Allow) == commit_replay_is_authorized(state, facts)
}))]
pub fn authorize_commit_replay(state: RekeyState, facts: CommitReplayFacts) -> ShadowDecision {
    if commit_replay_is_authorized(state, facts) {
        ShadowDecision::Allow
    } else {
        ShadowDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    Vault,
    Recovery,
    Enrollment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationAuthority {
    Device,
    WebSession,
    RecoveryGrant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationRequest {
    pub declared_epoch: i64,
    pub authority_epoch: i64,
    pub kind: MutationKind,
    pub authority: MutationAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationPermit {
    epoch: i64,
}

impl MutationPermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationDecision {
    Permit(MutationPermit),
    Reject,
}

pub fn mutation_request_is_authorized(request: MutationRequest) -> bool {
    request.declared_epoch >= INITIAL_EPOCH
        && request.authority_epoch >= INITIAL_EPOCH
        && request.declared_epoch == request.authority_epoch
        && match request.kind {
            MutationKind::Vault => {
                request.authority == MutationAuthority::Device
                    || request.authority == MutationAuthority::WebSession
            }
            MutationKind::Recovery => request.authority == MutationAuthority::Device,
            MutationKind::Enrollment => {
                request.authority == MutationAuthority::Device
                    || request.authority == MutationAuthority::RecoveryGrant
            }
        }
}

pub fn mutation_decision_matches_spec(
    request: MutationRequest,
    decision: MutationDecision,
) -> bool {
    match decision {
        MutationDecision::Permit(permit) => {
            mutation_request_is_authorized(request)
                && permit.epoch == request.declared_epoch
                && permit.epoch == request.authority_epoch
        }
        MutationDecision::Reject => !mutation_request_is_authorized(request),
    }
}

/// Produce the epoch permit consumed by an atomic ACTIVE-state SQL guard.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    mutation_decision_matches_spec(request, decision)
}))]
pub fn plan_active_mutation(request: MutationRequest) -> MutationDecision {
    if mutation_request_is_authorized(request) {
        MutationDecision::Permit(MutationPermit {
            epoch: request.declared_epoch,
        })
    } else {
        MutationDecision::Reject
    }
}

/// The database-side condition represented by a mutation permit.
pub fn active_mutation_is_authorized(state: RekeyState, permit: MutationPermit) -> bool {
    state.is_valid() && state.phase == Phase::Active && state.epoch == permit.epoch
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    (decision == ShadowDecision::Allow) == active_mutation_is_authorized(state, permit)
}))]
pub fn authorize_active_mutation(state: RekeyState, permit: MutationPermit) -> ShadowDecision {
    if active_mutation_is_authorized(state, permit) {
        ShadowDecision::Allow
    } else {
        ShadowDecision::Reject
    }
}

/// A permit for ACTIVE(N) cannot authorize a mutation after a successful
/// transition to ACTIVE(N+1).
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn stale_permit_authorizes_successor(before: RekeyState, permit: MutationPermit) -> bool {
    if !before.is_valid() || before.phase != Phase::Active || permit.epoch != before.epoch {
        return false;
    }
    match next_epoch(before.epoch) {
        Some(after_epoch) => active_mutation_is_authorized(
            RekeyState {
                epoch: after_epoch,
                phase: Phase::Active,
            },
            permit,
        ),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(epoch: i64, phase: Phase) -> RekeyState {
        RekeyState { epoch, phase }
    }

    #[test]
    fn active_accepts_only_current_epoch_with_epoch_one_legacy_exception() {
        assert_eq!(
            resolve_write_epoch(state(1, Phase::Active), None),
            WriteDecision::Accept(EpochRoute {
                write_epoch: 1,
                read_epoch: 1,
            })
        );
        assert!(matches!(
            resolve_write_epoch(state(2, Phase::Active), None),
            WriteDecision::Reject
        ));
        assert!(matches!(
            resolve_write_epoch(state(2, Phase::Active), Some(1)),
            WriteDecision::Reject
        ));
        assert!(matches!(
            resolve_write_epoch(state(2, Phase::Active), Some(3)),
            WriteDecision::Reject
        ));
    }

    #[test]
    fn freezing_routes_only_next_epoch_writes_while_reading_current() {
        assert_eq!(
            resolve_write_epoch(state(4, Phase::Freezing), Some(5)),
            WriteDecision::Accept(EpochRoute {
                write_epoch: 5,
                read_epoch: 4,
            })
        );
        for declared in [None, Some(4), Some(6)] {
            assert_eq!(
                resolve_write_epoch(state(4, Phase::Freezing), declared),
                WriteDecision::Reject
            );
        }
    }

    #[test]
    fn integer_boundary_and_invalid_epochs_fail_closed() {
        assert_eq!(next_epoch(i64::MAX), None);
        assert_eq!(
            resolve_write_epoch(state(i64::MAX, Phase::Freezing), None),
            WriteDecision::Reject
        );
        assert_eq!(
            resolve_write_epoch(state(0, Phase::Active), Some(0)),
            WriteDecision::Reject
        );
    }

    #[test]
    fn every_shadow_authority_fact_is_required() {
        let current = state(7, Phase::Freezing);
        let route = EpochRoute {
            write_epoch: 8,
            read_epoch: 7,
        };
        let all = AttemptAuthority {
            device_scope: true,
            starter_matches: true,
            rotation_id_present: true,
            rotation_id_matches: true,
        };
        assert_eq!(authorize_shadow(current, route, all), ShadowDecision::Allow);

        for facts in [
            AttemptAuthority {
                device_scope: false,
                ..all
            },
            AttemptAuthority {
                starter_matches: false,
                ..all
            },
            AttemptAuthority {
                rotation_id_present: false,
                ..all
            },
            AttemptAuthority {
                rotation_id_matches: false,
                ..all
            },
        ] {
            assert_eq!(
                authorize_shadow(current, route, facts),
                ShadowDecision::Reject
            );
        }
        assert_eq!(
            authorize_shadow(state(7, Phase::Active), route, all),
            ShadowDecision::Reject
        );
    }

    #[test]
    fn start_requires_every_readiness_gate_and_exact_successor() {
        let ready = StartFacts {
            no_oram: true,
            all_devices_rekey_capable: true,
            all_devices_acknowledged: true,
        };
        assert_eq!(
            plan_start(state(9, Phase::Active), ready),
            StartDecision::Start(TransitionPlan {
                from_epoch: 9,
                to_epoch: 10,
            })
        );
        for facts in [
            StartFacts {
                no_oram: false,
                ..ready
            },
            StartFacts {
                all_devices_rekey_capable: false,
                ..ready
            },
            StartFacts {
                all_devices_acknowledged: false,
                ..ready
            },
        ] {
            assert_eq!(
                plan_start(state(9, Phase::Active), facts),
                StartDecision::Reject
            );
        }
        assert_eq!(
            plan_start(state(9, Phase::Freezing), ready),
            StartDecision::Reject
        );
        assert_eq!(
            plan_start(state(i64::MAX, Phase::Active), ready),
            StartDecision::Reject
        );
    }

    #[test]
    fn commit_requires_attempt_authority_and_both_completeness_witnesses() {
        let authority = AttemptAuthority {
            device_scope: true,
            starter_matches: true,
            rotation_id_present: true,
            rotation_id_matches: true,
        };
        let complete = CommitFacts {
            authority,
            chunk_shadows_complete: true,
            device_capsules_complete: true,
        };
        assert_eq!(
            plan_commit(state(9, Phase::Freezing), complete),
            CommitDecision::Commit(TransitionPlan {
                from_epoch: 9,
                to_epoch: 10,
            })
        );
        assert_eq!(
            plan_commit(
                state(9, Phase::Freezing),
                CommitFacts {
                    chunk_shadows_complete: false,
                    ..complete
                }
            ),
            CommitDecision::Reject
        );
        assert_eq!(
            plan_commit(
                state(9, Phase::Freezing),
                CommitFacts {
                    device_capsules_complete: false,
                    ..complete
                }
            ),
            CommitDecision::Reject
        );
        assert_eq!(
            plan_commit(
                state(9, Phase::Freezing),
                CommitFacts {
                    authority: AttemptAuthority {
                        rotation_id_matches: false,
                        ..authority
                    },
                    ..complete
                }
            ),
            CommitDecision::Reject
        );
    }

    #[test]
    fn abort_preserves_epoch_and_requires_attempt_authority() {
        let authority = AttemptAuthority {
            device_scope: true,
            starter_matches: true,
            rotation_id_present: true,
            rotation_id_matches: true,
        };
        assert_eq!(
            plan_abort(state(12, Phase::Freezing), authority),
            AbortDecision::Abort(state(12, Phase::Active))
        );
        assert_eq!(
            plan_abort(
                state(12, Phase::Freezing),
                AttemptAuthority {
                    starter_matches: false,
                    ..authority
                }
            ),
            AbortDecision::Reject
        );
    }

    #[test]
    fn timeout_rolls_back_only_expired_well_formed_attempts() {
        let expired = TimeoutFacts {
            expired: true,
            rotation_id_present: true,
        };
        assert_eq!(
            plan_timeout(state(12, Phase::Freezing), expired),
            TimeoutDecision::Rollback(state(12, Phase::Active))
        );
        assert_eq!(
            plan_timeout(
                state(12, Phase::Freezing),
                TimeoutFacts {
                    expired: false,
                    ..expired
                }
            ),
            TimeoutDecision::Keep
        );
        assert_eq!(
            plan_timeout(
                state(12, Phase::Freezing),
                TimeoutFacts {
                    rotation_id_present: false,
                    ..expired
                }
            ),
            TimeoutDecision::Keep
        );
        assert_eq!(
            plan_timeout(state(12, Phase::Active), expired),
            TimeoutDecision::Keep
        );
    }

    #[test]
    fn commit_replay_must_name_the_exact_recorded_attempt() {
        let replay = CommitReplayFacts {
            target_epoch: Some(5),
            recorded_epoch: Some(5),
            rotation_id_present: true,
            rotation_id_matches: true,
        };
        assert_eq!(
            authorize_commit_replay(state(5, Phase::Active), replay),
            ShadowDecision::Allow
        );
        assert_eq!(
            authorize_commit_replay(state(5, Phase::Freezing), replay),
            ShadowDecision::Reject
        );
        assert_eq!(
            authorize_commit_replay(
                state(5, Phase::Active),
                CommitReplayFacts {
                    target_epoch: Some(4),
                    ..replay
                }
            ),
            ShadowDecision::Reject
        );
        assert_eq!(
            authorize_commit_replay(
                state(5, Phase::Active),
                CommitReplayFacts {
                    rotation_id_matches: false,
                    ..replay
                }
            ),
            ShadowDecision::Reject
        );
    }

    #[test]
    fn mutation_permits_bind_epoch_and_authority_class() {
        let vault_web = MutationRequest {
            declared_epoch: 4,
            authority_epoch: 4,
            kind: MutationKind::Vault,
            authority: MutationAuthority::WebSession,
        };
        assert_eq!(
            plan_active_mutation(vault_web),
            MutationDecision::Permit(MutationPermit { epoch: 4 })
        );
        for rejected in [
            MutationRequest {
                authority_epoch: 3,
                ..vault_web
            },
            MutationRequest {
                declared_epoch: 0,
                authority_epoch: 0,
                ..vault_web
            },
            MutationRequest {
                kind: MutationKind::Recovery,
                ..vault_web
            },
            MutationRequest {
                kind: MutationKind::Enrollment,
                ..vault_web
            },
        ] {
            assert_eq!(plan_active_mutation(rejected), MutationDecision::Reject);
        }

        let recovery = MutationRequest {
            declared_epoch: 4,
            authority_epoch: 4,
            kind: MutationKind::Recovery,
            authority: MutationAuthority::Device,
        };
        let enrollment = MutationRequest {
            kind: MutationKind::Enrollment,
            authority: MutationAuthority::RecoveryGrant,
            ..recovery
        };
        assert!(matches!(
            plan_active_mutation(recovery),
            MutationDecision::Permit(_)
        ));
        assert!(matches!(
            plan_active_mutation(enrollment),
            MutationDecision::Permit(_)
        ));
    }

    #[test]
    fn active_guard_rejects_freezing_and_stale_permits() {
        let permit = MutationPermit { epoch: 6 };
        assert_eq!(
            authorize_active_mutation(state(6, Phase::Active), permit),
            ShadowDecision::Allow
        );
        assert_eq!(
            authorize_active_mutation(state(6, Phase::Freezing), permit),
            ShadowDecision::Reject
        );
        assert_eq!(
            authorize_active_mutation(state(7, Phase::Active), permit),
            ShadowDecision::Reject
        );
        assert!(!stale_permit_authorizes_successor(
            state(6, Phase::Active),
            permit
        ));
    }
}
