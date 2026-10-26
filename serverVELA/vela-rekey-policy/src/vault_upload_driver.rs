//! Pure post-validation decision drivers for vault chunk uploads and reads.
//!
//! The HTTP handlers in `vela-server` perform the effectful steps: loading the
//! post-rollback key state, the shadow-attempt lookup, the quota query, the
//! guarded `INSERT`/`UPDATE` against `vault_chunks`, the version read-back, the
//! shadow-activity refresh, the change publication and response rendering.
//! This module owns every *decision* between those effects:
//!
//! 1. which epoch a declared ciphertext may write and which epoch readers keep
//!    serving (`vela_rekey_policy::resolve_write_epoch`);
//! 2. whether a shadow write belongs to the device that started the live
//!    rotation (`authorize_shadow`);
//! 3. whether the authenticated writer's authority epoch is the write epoch
//!    (`plan_active_mutation`);
//! 4. which quota is enforced;
//! 5. how a guarded insert/update outcome is classified, including the
//!    already-exists pre-check, the shadow-replay upsert, the unique-key race
//!    and the stale-version recheck;
//! 6. how the version read-back, shadow-activity refresh and publication are
//!    classified;
//! 7. for `GET /vault/chunk/:id`, whether the resolved read epoch is valid and
//!    whether a returned row is same-account and current-epoch.
//!
//! The drivers are per-request values. They do not observe the SQL database,
//! the clock, or other requests. Every input except the request facts is an
//! observation produced by the handler, and the handler performs exactly the
//! effect the driver returns, in order.
//!
//! The server does **not** enforce Lamport-clock monotonicity on uploads. The
//! write paths store the client-supplied `x-lamport-clock` and guard only the
//! row version, the account epoch and the rotation state. Lamport rollback is
//! rejected by the *client* download policy (`vela-sync-policy`), not here; the
//! drivers below therefore make no clock-decrease claim.

use crate::{
    authorize_shadow, next_epoch, plan_active_mutation, resolve_write_epoch, AttemptAuthority,
    EpochRoute, MutationAuthority, MutationDecision, MutationKind, MutationRequest, Phase,
    RekeyState, ShadowDecision, WriteDecision, INITIAL_EPOCH,
};

// ── Upload driver ───────────────────────────────────────────────────────────

/// Whether the request creates a row or replaces the row at an exact version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteIntent {
    /// `If-Match: 0`: create-or-conflict (or a shadow upsert during rotation).
    Create,
    /// `If-Match: n`: compare-and-swap on `version = n`.
    Replace { version: i64 },
}

/// Authenticated writer facts captured before the first effect.
///
/// `web` distinguishes the two authority classes the middleware issues. A web
/// token is only minted for a read-write grant
/// (`vela_session_policy::plan_web_session_token` requires
/// `SessionMode::ReadWrite`), so a `WebSession` reaching this driver already
/// carries RW authority; `web_epoch` is the token's pinned `key_epoch`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadWriter {
    /// The `AuthSession` extractor verified a live PASETO identity.
    pub authenticated: bool,
    /// True for a temporary web-session token, false for a device token.
    pub web: bool,
    /// Web tokens pin the epoch at issue time; device tokens follow the write
    /// epoch and carry `None`.
    pub web_epoch: Option<i64>,
}

/// The request facts the handler parses before any effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadRequest {
    pub writer: UploadWriter,
    pub intent: WriteIntent,
    /// `X-Vela-Epoch`; `None` is the epoch-one legacy tolerance.
    pub declared_epoch: Option<i64>,
}

/// Post-rollback key-state observation. The handler obtains it from the same
/// load that `resolve_write_epoch` used; the driver re-applies the extracted
/// policy to this value. `Rejected` is the handler's observation that the
/// extracted resolver refused the declared epoch; the handler keeps the
/// original error for rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyObservation {
    State { epoch: i64, phase: Phase },
    Rejected,
}

/// Quota outcome. `Exceeded` and `StorageFailed` are terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaObservation {
    Allowed,
    Exceeded,
    StorageFailed,
}

/// Outcome of the guarded `INSERT`/`UPDATE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteObservation {
    /// A fresh insert wrote one row.
    Inserted,
    /// The `version = ?` update wrote one row.
    Updated,
    /// The `If-Match: 0` pre-check found a row.
    Existing,
    /// The statement matched no row (stale version, stale epoch, rotation
    /// guard, or an insert `SELECT` that produced no row).
    Skipped,
    /// The insert failed with a unique/constraint error from a concurrent
    /// create.
    Duplicate,
    /// The statement returned an error.
    Failed,
}

/// Re-resolution performed only after an update matched zero rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecheckObservation {
    /// The request would still resolve to the same write route.
    Unchanged,
    /// The account epoch or rotation state moved before the write completed.
    Changed,
    /// The re-resolution query failed.
    Failed,
}

/// Version read-back after a successful write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RereadObservation {
    Read { version: i64 },
    Missing,
    Failed,
}

/// Shadow-activity refresh outcome. `Ended` means the guarded refresh matched
/// zero rows because the rotation ended; the handler treats it as non-fatal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityObservation {
    Refreshed,
    Ended,
    Failed,
}

/// One upload driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadEvent {
    Rekey(RekeyObservation),
    Attempt(AttemptAuthority),
    Quota(QuotaObservation),
    Write(WriteObservation),
    Recheck(RecheckObservation),
    Reread(RereadObservation),
    Activity(ActivityObservation),
    Published,
}

/// Failure categories, preserving the handler's status/message precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadFailure {
    /// No authenticated session. The extractor rejects this before the driver.
    Unauthenticated,
    /// The declared epoch is neither current nor the rotation target.
    EpochMismatch,
    /// A web session tried to write shadow ciphertext.
    ShadowWebSessionForbidden,
    /// A shadow write omitted `X-Vela-Rekey-Id`.
    ShadowRotationIdRequired,
    /// The shadow writer is not the device that started the rotation.
    ShadowStarterForbidden,
    /// The writer's authority epoch is not the resolved write epoch.
    AuthorityEpochMismatch,
    /// The storage quota would be exceeded.
    QuotaExceeded,
    /// The quota query failed.
    QuotaStorage,
    /// `If-Match: 0` found an existing row (or lost a unique-index race).
    AlreadyExists,
    /// A shadow replay arrived after the rotation ended.
    RekeyEnded,
    /// The update matched zero rows and the state did not move.
    VersionMismatch,
    /// The update matched zero rows because the epoch/rotation moved.
    Rekeyed,
    /// The guarded statement returned a storage error.
    WriteStorage,
    /// The zero-row re-resolution query failed.
    RecheckStorage,
    /// The version read-back failed.
    RereadStorage,
    /// The shadow-activity refresh failed.
    ActivityStorage,
}

/// The write permit the handler must use for the guarded statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadWritePermit {
    pub write_epoch: i64,
    pub read_epoch: i64,
    pub shadow: bool,
    pub permit_epoch: i64,
    pub web: bool,
    /// The phase the driver observed when it resolved the route. The modelled
    /// SQL guard is `authorize_active_mutation`/`authorize_shadow` against the
    /// live account row, not against this captured value.
    pub state_epoch: i64,
    pub state_phase: Phase,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadEffect {
    /// Load the post-rollback key state and resolve the write route.
    ResolveEpoch,
    /// Load the live rotation attempt and check that this device started it.
    AuthorizeShadow,
    /// Enforce the ordinary or shadow storage quota.
    EnforceQuota,
    /// Perform exactly one guarded insert/update with this permit.
    Write(UploadWritePermit),
    /// Re-resolve the write route after a zero-row update.
    RecheckState,
    /// Read back the committed version.
    RereadVersion,
    /// Refresh the rotation inactivity deadline.
    RecordShadowActivity,
    /// Publish the chunk change to the account's other devices.
    Publish,
    /// Terminal success.
    Complete,
    /// Terminal failure without further effects.
    Fail(UploadFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Where the upload is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadStage {
    Resolve,
    Shadow,
    Quota,
    Write,
    Recheck,
    Reread,
    Activity,
    Publish,
    Done,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadDriver {
    pub stage: UploadStage,
    pub authenticated: bool,
    pub web: bool,
    pub web_epoch: Option<i64>,
    pub intent: WriteIntent,
    pub declared_epoch: Option<i64>,
    /// The authority epoch the writer's token binds: the resolved write epoch
    /// for a device token, the pinned `key_epoch` for a web token.
    pub authority_epoch: i64,
    pub state_epoch: i64,
    pub state_phase: Phase,
    pub write_epoch: i64,
    pub read_epoch: i64,
    pub shadow: bool,
    pub permit_epoch: i64,
    pub write_matched: bool,
    pub version: i64,
    pub activity_done: bool,
    pub published: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadTransition {
    pub driver: UploadDriver,
    pub effect: UploadEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn upload_state_is_sound(d: UploadDriver) -> bool {
    let untouched = d.state_epoch == 0
        && d.write_epoch == 0
        && d.read_epoch == 0
        && d.permit_epoch == 0
        && !d.write_matched
        && !d.activity_done
        && !d.published
        && !d.responded
        && !d.failed;
    let resolved = d.state_epoch >= INITIAL_EPOCH
        && d.read_epoch == d.state_epoch
        && match d.state_phase {
            Phase::Active => !d.shadow && d.write_epoch == d.state_epoch,
            Phase::Freezing => {
                d.shadow && !d.web && next_epoch(d.state_epoch) == Some(d.write_epoch)
            }
        };
    let permitted = resolved && d.permit_epoch == d.write_epoch;
    let resolve_clean = d.authenticated && untouched;
    let shadow_clean = d.authenticated
        && resolved
        && d.shadow
        && d.permit_epoch == 0
        && !d.write_matched
        && !d.activity_done
        && !d.published
        && !d.responded
        && !d.failed;
    let quota_clean = d.authenticated
        && permitted
        && !d.write_matched
        && !d.activity_done
        && !d.published
        && !d.responded
        && !d.failed;
    let write_clean = quota_clean;
    let recheck_clean = quota_clean
        && !d.shadow
        && matches!(d.intent, WriteIntent::Replace { .. });
    let reread_clean = d.authenticated
        && permitted
        && d.write_matched
        && !d.activity_done
        && !d.published
        && !d.responded
        && !d.failed;
    let activity_clean = reread_clean && d.shadow;
    let publish_clean = d.authenticated
        && permitted
        && d.write_matched
        && !d.published
        && !d.responded
        && !d.failed
        && (!d.shadow || d.activity_done);
    let done_clean = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded
            || (d.authenticated
                && permitted
                && d.write_matched
                && ((!d.shadow && d.published) || (d.shadow && d.activity_done))));
    (!matches!(d.stage, UploadStage::Resolve) || resolve_clean)
        && (!matches!(d.stage, UploadStage::Shadow) || shadow_clean)
        && (!matches!(d.stage, UploadStage::Quota) || quota_clean)
        && (!matches!(d.stage, UploadStage::Write) || write_clean)
        && (!matches!(d.stage, UploadStage::Recheck) || recheck_clean)
        && (!matches!(d.stage, UploadStage::Reread) || reread_clean)
        && (!matches!(d.stage, UploadStage::Activity) || activity_clean)
        && (!matches!(d.stage, UploadStage::Publish) || publish_clean)
        && (!matches!(d.stage, UploadStage::Done) || done_clean)
        && (!d.shadow || !d.web)
        && (!d.write_matched || d.write_epoch >= INITIAL_EPOCH)
        && (!d.activity_done || d.shadow)
        && (!d.published || (!d.shadow && d.write_matched))
        && (!d.responded
            || (d.write_matched
                && ((!d.shadow && d.published) || (d.shadow && d.activity_done))))
        && (!d.failed || !d.responded)
}

/// Every effect the driver emits agrees with the state it produces.
pub fn upload_effect_is_sound(d: UploadDriver, effect: UploadEffect) -> bool {
    match effect {
        UploadEffect::ResolveEpoch => {
            matches!(d.stage, UploadStage::Resolve) && d.authenticated
        }
        UploadEffect::AuthorizeShadow => matches!(d.stage, UploadStage::Shadow) && d.shadow,
        UploadEffect::EnforceQuota => {
            matches!(d.stage, UploadStage::Quota) && d.permit_epoch == d.write_epoch
        }
        UploadEffect::Write(permit) => {
            matches!(d.stage, UploadStage::Write)
                && permit.write_epoch == d.write_epoch
                && permit.read_epoch == d.read_epoch
                && permit.permit_epoch == d.permit_epoch
                && permit.shadow == d.shadow
                && permit.web == d.web
                && permit.state_epoch == d.state_epoch
                && permit.state_phase == d.state_phase
        }
        UploadEffect::RecheckState => matches!(d.stage, UploadStage::Recheck),
        UploadEffect::RereadVersion => {
            matches!(d.stage, UploadStage::Reread) && d.write_matched
        }
        UploadEffect::RecordShadowActivity => {
            matches!(d.stage, UploadStage::Activity) && d.shadow
        }
        UploadEffect::Publish => matches!(d.stage, UploadStage::Publish),
        UploadEffect::Complete => {
            matches!(d.stage, UploadStage::Done) && d.responded && !d.failed
        }
        UploadEffect::Fail(_) => matches!(d.stage, UploadStage::Done) && d.failed && !d.responded,
        UploadEffect::Idle => true,
    }
}

fn transition(driver: UploadDriver, effect: UploadEffect) -> UploadTransition {
    UploadTransition { driver, effect }
}

fn idle(driver: UploadDriver) -> UploadTransition {
    transition(driver, UploadEffect::Idle)
}

fn terminal(driver: UploadDriver, failure: UploadFailure) -> UploadTransition {
    transition(
        UploadDriver {
            stage: UploadStage::Done,
            failed: true,
            ..driver
        },
        UploadEffect::Fail(failure),
    )
}

fn write_permit(d: UploadDriver) -> UploadWritePermit {
    UploadWritePermit {
        write_epoch: d.write_epoch,
        read_epoch: d.read_epoch,
        shadow: d.shadow,
        permit_epoch: d.permit_epoch,
        web: d.web,
        state_epoch: d.state_epoch,
        state_phase: d.state_phase,
    }
}

/// Decide the mutation permit and move to quota enforcement.
fn enter_quota(d: UploadDriver) -> UploadTransition {
    let authority = if d.web {
        MutationAuthority::WebSession
    } else {
        MutationAuthority::Device
    };
    let authority_epoch = if d.web { d.authority_epoch } else { d.write_epoch };
    let request = MutationRequest {
        declared_epoch: d.write_epoch,
        authority_epoch,
        kind: MutationKind::Vault,
        authority,
    };
    match plan_active_mutation(request) {
        MutationDecision::Permit(permit) => transition(
            UploadDriver {
                stage: UploadStage::Quota,
                permit_epoch: permit.epoch(),
                ..d
            },
            UploadEffect::EnforceQuota,
        ),
        MutationDecision::Reject => terminal(d, UploadFailure::AuthorityEpochMismatch),
    }
}

/// Start a per-request upload. The extractor already refused an
/// unauthenticated caller; the driver still fails closed on that observation.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    upload_state_is_sound(result.driver)
        && upload_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_upload(request: UploadRequest) -> UploadTransition {
    let driver = UploadDriver {
        stage: UploadStage::Resolve,
        authenticated: request.writer.authenticated,
        web: request.writer.web,
        web_epoch: request.writer.web_epoch,
        intent: request.intent,
        declared_epoch: request.declared_epoch,
        authority_epoch: if request.writer.web {
            match request.writer.web_epoch {
                Some(epoch) => epoch,
                None => INITIAL_EPOCH,
            }
        } else {
            0
        },
        state_epoch: 0,
        state_phase: Phase::Active,
        write_epoch: 0,
        read_epoch: 0,
        shadow: false,
        permit_epoch: 0,
        write_matched: false,
        version: 0,
        activity_done: false,
        published: false,
        responded: false,
        failed: false,
    };
    if request.writer.authenticated {
        transition(driver, UploadEffect::ResolveEpoch)
    } else {
        terminal(driver, UploadFailure::Unauthenticated)
    }
}

fn on_rekey(driver: UploadDriver, observation: RekeyObservation) -> UploadTransition {
    match observation {
        RekeyObservation::Rejected => terminal(driver, UploadFailure::EpochMismatch),
        RekeyObservation::State { epoch, phase } => {
            let state = RekeyState { epoch, phase };
            match resolve_write_epoch(state, driver.declared_epoch) {
                WriteDecision::Accept(route) => {
                    let shadow = route.write_epoch != route.read_epoch;
                    let resolved = UploadDriver {
                        state_epoch: epoch,
                        state_phase: phase,
                        write_epoch: route.write_epoch,
                        read_epoch: route.read_epoch,
                        authority_epoch: if driver.web {
                            driver.authority_epoch
                        } else {
                            route.write_epoch
                        },
                        shadow,
                        ..driver
                    };
                    if shadow {
                        transition(
                            UploadDriver {
                                stage: UploadStage::Shadow,
                                ..resolved
                            },
                            UploadEffect::AuthorizeShadow,
                        )
                    } else {
                        enter_quota(resolved)
                    }
                }
                WriteDecision::Reject => terminal(driver, UploadFailure::EpochMismatch),
            }
        }
    }
}

fn on_attempt(driver: UploadDriver, authority: AttemptAuthority) -> UploadTransition {
    // Defense in depth: a web session can never write shadow ciphertext even
    // if an observation incorrectly claimed device scope. The handler derives
    // `device_scope` from the authenticated token, so this branch is
    // unreachable in production but keeps the policy independent of how the
    // observation was built.
    if driver.web {
        return terminal(driver, UploadFailure::ShadowWebSessionForbidden);
    }
    let state = RekeyState {
        epoch: driver.state_epoch,
        phase: driver.state_phase,
    };
    let route = EpochRoute {
        write_epoch: driver.write_epoch,
        read_epoch: driver.read_epoch,
    };
    match authorize_shadow(state, route, authority) {
        ShadowDecision::Allow => enter_quota(driver),
        ShadowDecision::Reject => {
            if !authority.device_scope {
                terminal(driver, UploadFailure::ShadowWebSessionForbidden)
            } else if !authority.rotation_id_present {
                terminal(driver, UploadFailure::ShadowRotationIdRequired)
            } else {
                terminal(driver, UploadFailure::ShadowStarterForbidden)
            }
        }
    }
}

fn on_quota(driver: UploadDriver, observation: QuotaObservation) -> UploadTransition {
    match observation {
        QuotaObservation::Allowed => transition(
            UploadDriver {
                stage: UploadStage::Write,
                ..driver
            },
            UploadEffect::Write(write_permit(driver)),
        ),
        QuotaObservation::Exceeded => terminal(driver, UploadFailure::QuotaExceeded),
        QuotaObservation::StorageFailed => terminal(driver, UploadFailure::QuotaStorage),
    }
}

fn on_write(driver: UploadDriver, observation: WriteObservation) -> UploadTransition {
    match observation {
        WriteObservation::Inserted | WriteObservation::Updated => transition(
            UploadDriver {
                stage: UploadStage::Reread,
                write_matched: true,
                ..driver
            },
            UploadEffect::RereadVersion,
        ),
        WriteObservation::Existing | WriteObservation::Duplicate => {
            terminal(driver, UploadFailure::AlreadyExists)
        }
        WriteObservation::Skipped => {
            if driver.shadow {
                terminal(driver, UploadFailure::RekeyEnded)
            } else if matches!(driver.intent, WriteIntent::Create) {
                terminal(driver, UploadFailure::Rekeyed)
            } else {
                transition(
                    UploadDriver {
                        stage: UploadStage::Recheck,
                        ..driver
                    },
                    UploadEffect::RecheckState,
                )
            }
        }
        WriteObservation::Failed => terminal(driver, UploadFailure::WriteStorage),
    }
}

fn on_recheck(driver: UploadDriver, observation: RecheckObservation) -> UploadTransition {
    match observation {
        RecheckObservation::Unchanged => terminal(driver, UploadFailure::VersionMismatch),
        RecheckObservation::Changed => terminal(driver, UploadFailure::Rekeyed),
        RecheckObservation::Failed => terminal(driver, UploadFailure::RecheckStorage),
    }
}

fn on_reread(driver: UploadDriver, observation: RereadObservation) -> UploadTransition {
    match observation {
        RereadObservation::Read { version } => {
            if driver.shadow {
                transition(
                    UploadDriver {
                        stage: UploadStage::Activity,
                        version,
                        ..driver
                    },
                    UploadEffect::RecordShadowActivity,
                )
            } else {
                transition(
                    UploadDriver {
                        stage: UploadStage::Publish,
                        version,
                        ..driver
                    },
                    UploadEffect::Publish,
                )
            }
        }
        RereadObservation::Missing | RereadObservation::Failed => {
            terminal(driver, UploadFailure::RereadStorage)
        }
    }
}

fn on_activity(driver: UploadDriver, observation: ActivityObservation) -> UploadTransition {
    match observation {
        ActivityObservation::Refreshed | ActivityObservation::Ended => transition(
            UploadDriver {
                stage: UploadStage::Publish,
                activity_done: true,
                ..driver
            },
            UploadEffect::Publish,
        ),
        ActivityObservation::Failed => terminal(driver, UploadFailure::ActivityStorage),
    }
}

fn on_publish(driver: UploadDriver) -> UploadTransition {
    transition(
        UploadDriver {
            stage: UploadStage::Done,
            published: !driver.shadow,
            responded: true,
            ..driver
        },
        UploadEffect::Complete,
    )
}

/// The complete, total upload transition relation. Events that do not match
/// the current stage (and every event after `Done`) are ignored.
pub fn upload_step(driver: UploadDriver, event: UploadEvent) -> UploadTransition {
    match event {
        UploadEvent::Rekey(observation) => {
            if matches!(driver.stage, UploadStage::Resolve) {
                on_rekey(driver, observation)
            } else {
                idle(driver)
            }
        }
        UploadEvent::Attempt(authority) => {
            if matches!(driver.stage, UploadStage::Shadow) {
                on_attempt(driver, authority)
            } else {
                idle(driver)
            }
        }
        UploadEvent::Quota(observation) => {
            if matches!(driver.stage, UploadStage::Quota) {
                on_quota(driver, observation)
            } else {
                idle(driver)
            }
        }
        UploadEvent::Write(observation) => {
            if matches!(driver.stage, UploadStage::Write) {
                on_write(driver, observation)
            } else {
                idle(driver)
            }
        }
        UploadEvent::Recheck(observation) => {
            if matches!(driver.stage, UploadStage::Recheck) {
                on_recheck(driver, observation)
            } else {
                idle(driver)
            }
        }
        UploadEvent::Reread(observation) => {
            if matches!(driver.stage, UploadStage::Reread) {
                on_reread(driver, observation)
            } else {
                idle(driver)
            }
        }
        UploadEvent::Activity(observation) => {
            if matches!(driver.stage, UploadStage::Activity) {
                on_activity(driver, observation)
            } else {
                idle(driver)
            }
        }
        UploadEvent::Published => {
            if matches!(driver.stage, UploadStage::Publish) {
                on_publish(driver)
            } else {
                idle(driver)
            }
        }
    }
}

pub fn on_rekey_observed(
    driver: UploadDriver,
    observation: RekeyObservation,
) -> UploadTransition {
    upload_step(driver, UploadEvent::Rekey(observation))
}

pub fn on_attempt_observed(
    driver: UploadDriver,
    authority: AttemptAuthority,
) -> UploadTransition {
    upload_step(driver, UploadEvent::Attempt(authority))
}

pub fn on_quota_observed(
    driver: UploadDriver,
    observation: QuotaObservation,
) -> UploadTransition {
    upload_step(driver, UploadEvent::Quota(observation))
}

pub fn on_write_observed(
    driver: UploadDriver,
    observation: WriteObservation,
) -> UploadTransition {
    upload_step(driver, UploadEvent::Write(observation))
}

pub fn on_recheck_observed(
    driver: UploadDriver,
    observation: RecheckObservation,
) -> UploadTransition {
    upload_step(driver, UploadEvent::Recheck(observation))
}

pub fn on_reread_observed(
    driver: UploadDriver,
    observation: RereadObservation,
) -> UploadTransition {
    upload_step(driver, UploadEvent::Reread(observation))
}

pub fn on_activity_observed(
    driver: UploadDriver,
    observation: ActivityObservation,
) -> UploadTransition {
    upload_step(driver, UploadEvent::Activity(observation))
}

pub fn on_published_observed(driver: UploadDriver) -> UploadTransition {
    upload_step(driver, UploadEvent::Published)
}

// ── Read driver ─────────────────────────────────────────────────────────────

/// Authenticated reader facts captured before the read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    pub authenticated: bool,
}

/// The post-rollback epoch served to readers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadEpochObservation {
    pub epoch: i64,
}

/// A decoded `vault_chunks` row, or a lookup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadLookupObservation {
    Found {
        account_matches: bool,
        epoch_matches: bool,
        version: i64,
        lamport_clock: i64,
    },
    Missing,
    QueryFailed,
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadEvent {
    Epoch(ReadEpochObservation),
    Lookup(ReadLookupObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFailure {
    Unauthenticated,
    InvalidEpoch,
    NotFound,
    QueryStorage,
    ParseStorage,
    /// The store returned a row outside the request's account/epoch scope.
    ScopeViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadEffect {
    ReadEpoch,
    LookupChunk,
    Serve { version: i64, lamport_clock: i64 },
    Fail(ReadFailure),
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStage {
    Epoch,
    Lookup,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadDriver {
    pub stage: ReadStage,
    pub authenticated: bool,
    pub epoch: i64,
    pub version: i64,
    pub lamport_clock: i64,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadTransition {
    pub driver: ReadDriver,
    pub effect: ReadEffect,
}

pub fn read_state_is_sound(r: ReadDriver) -> bool {
    let fresh = r.epoch == 0
        && r.version == 0
        && r.lamport_clock == 0
        && !r.responded
        && !r.failed;
    let lookup_clean = r.authenticated
        && r.epoch >= INITIAL_EPOCH
        && r.version == 0
        && r.lamport_clock == 0
        && !r.responded
        && !r.failed;
    let served = r.authenticated
        && r.epoch >= INITIAL_EPOCH
        && r.responded
        && !r.failed
        && r.version >= 0;
    (!matches!(r.stage, ReadStage::Epoch) || (r.authenticated && fresh))
        && (!matches!(r.stage, ReadStage::Lookup) || lookup_clean)
        && (!matches!(r.stage, ReadStage::Done)
            || ((r.responded || r.failed)
                && !(r.responded && r.failed)
                && (!r.responded || served)))
}

pub fn read_effect_is_sound(r: ReadDriver, effect: ReadEffect) -> bool {
    match effect {
        ReadEffect::ReadEpoch => matches!(r.stage, ReadStage::Epoch) && r.authenticated,
        ReadEffect::LookupChunk => matches!(r.stage, ReadStage::Lookup),
        ReadEffect::Serve { .. } => {
            matches!(r.stage, ReadStage::Done) && r.responded && !r.failed
        }
        ReadEffect::Fail(_) => matches!(r.stage, ReadStage::Done) && r.failed && !r.responded,
        ReadEffect::Idle => true,
    }
}

fn read_transition(driver: ReadDriver, effect: ReadEffect) -> ReadTransition {
    ReadTransition { driver, effect }
}

fn read_terminal(driver: ReadDriver, failure: ReadFailure) -> ReadTransition {
    read_transition(
        ReadDriver {
            stage: ReadStage::Done,
            failed: true,
            ..driver
        },
        ReadEffect::Fail(failure),
    )
}

/// Start a per-request read.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    read_state_is_sound(result.driver)
        && read_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_read(request: ReadRequest) -> ReadTransition {
    let driver = ReadDriver {
        stage: ReadStage::Epoch,
        authenticated: request.authenticated,
        epoch: 0,
        version: 0,
        lamport_clock: 0,
        responded: false,
        failed: false,
    };
    if request.authenticated {
        read_transition(driver, ReadEffect::ReadEpoch)
    } else {
        read_terminal(driver, ReadFailure::Unauthenticated)
    }
}

pub fn read_step(driver: ReadDriver, event: ReadEvent) -> ReadTransition {
    match event {
        ReadEvent::Epoch(observation) => {
            if !matches!(driver.stage, ReadStage::Epoch) {
                return read_transition(driver, ReadEffect::Idle);
            }
            if observation.epoch < INITIAL_EPOCH {
                read_terminal(driver, ReadFailure::InvalidEpoch)
            } else {
                read_transition(
                    ReadDriver {
                        stage: ReadStage::Lookup,
                        epoch: observation.epoch,
                        ..driver
                    },
                    ReadEffect::LookupChunk,
                )
            }
        }
        ReadEvent::Lookup(observation) => {
            if !matches!(driver.stage, ReadStage::Lookup) {
                return read_transition(driver, ReadEffect::Idle);
            }
            match observation {
                ReadLookupObservation::Found {
                    account_matches,
                    epoch_matches,
                    version,
                    lamport_clock,
                } => {
                    if account_matches && epoch_matches {
                        read_transition(
                            ReadDriver {
                                stage: ReadStage::Done,
                                version,
                                lamport_clock,
                                responded: true,
                                ..driver
                            },
                            ReadEffect::Serve {
                                version,
                                lamport_clock,
                            },
                        )
                    } else {
                        read_terminal(driver, ReadFailure::ScopeViolation)
                    }
                }
                ReadLookupObservation::Missing => read_terminal(driver, ReadFailure::NotFound),
                ReadLookupObservation::QueryFailed => {
                    read_terminal(driver, ReadFailure::QueryStorage)
                }
                ReadLookupObservation::Malformed => {
                    read_terminal(driver, ReadFailure::ParseStorage)
                }
            }
        }
    }
}

pub fn on_read_epoch(
    driver: ReadDriver,
    observation: ReadEpochObservation,
) -> ReadTransition {
    read_step(driver, ReadEvent::Epoch(observation))
}

pub fn on_read_lookup(
    driver: ReadDriver,
    observation: ReadLookupObservation,
) -> ReadTransition {
    read_step(driver, ReadEvent::Lookup(observation))
}

// ── Rust conformance tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const UPLOAD_STAGES: [UploadStage; 9] = [
        UploadStage::Resolve,
        UploadStage::Shadow,
        UploadStage::Quota,
        UploadStage::Write,
        UploadStage::Recheck,
        UploadStage::Reread,
        UploadStage::Activity,
        UploadStage::Publish,
        UploadStage::Done,
    ];

    fn device() -> UploadWriter {
        UploadWriter {
            authenticated: true,
            web: false,
            web_epoch: None,
        }
    }

    fn web(epoch: i64) -> UploadWriter {
        UploadWriter {
            authenticated: true,
            web: true,
            web_epoch: Some(epoch),
        }
    }

    fn request(intent: WriteIntent, declared: Option<i64>) -> UploadRequest {
        UploadRequest {
            writer: device(),
            intent,
            declared_epoch: declared,
        }
    }

    fn upload_events() -> Vec<UploadEvent> {
        let mut out = Vec::new();
        for (epoch, phase) in [
            (1, Phase::Active),
            (2, Phase::Active),
            (2, Phase::Freezing),
            (0, Phase::Active),
        ] {
            out.push(UploadEvent::Rekey(RekeyObservation::State { epoch, phase }));
        }
        out.push(UploadEvent::Rekey(RekeyObservation::Rejected));
        let all = AttemptAuthority {
            device_scope: true,
            starter_matches: true,
            rotation_id_present: true,
            rotation_id_matches: true,
        };
        for authority in [
            all,
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
            out.push(UploadEvent::Attempt(authority));
        }
        for observation in [
            QuotaObservation::Allowed,
            QuotaObservation::Exceeded,
            QuotaObservation::StorageFailed,
        ] {
            out.push(UploadEvent::Quota(observation));
        }
        for observation in [
            WriteObservation::Inserted,
            WriteObservation::Updated,
            WriteObservation::Existing,
            WriteObservation::Skipped,
            WriteObservation::Duplicate,
            WriteObservation::Failed,
        ] {
            out.push(UploadEvent::Write(observation));
        }
        for observation in [
            RecheckObservation::Unchanged,
            RecheckObservation::Changed,
            RecheckObservation::Failed,
        ] {
            out.push(UploadEvent::Recheck(observation));
        }
        for observation in [
            RereadObservation::Read { version: 3 },
            RereadObservation::Missing,
            RereadObservation::Failed,
        ] {
            out.push(UploadEvent::Reread(observation));
        }
        for observation in [
            ActivityObservation::Refreshed,
            ActivityObservation::Ended,
            ActivityObservation::Failed,
        ] {
            out.push(UploadEvent::Activity(observation));
        }
        out.push(UploadEvent::Published);
        out
    }

    fn sample_driver(stage: UploadStage) -> UploadDriver {
        let base = UploadDriver {
            stage,
            authenticated: true,
            web: false,
            web_epoch: None,
            intent: WriteIntent::Replace { version: 1 },
            declared_epoch: Some(1),
            authority_epoch: 1,
            state_epoch: 1,
            state_phase: Phase::Active,
            write_epoch: 1,
            read_epoch: 1,
            shadow: false,
            permit_epoch: 1,
            write_matched: false,
            version: 0,
            activity_done: false,
            published: false,
            responded: false,
            failed: false,
        };
        match stage {
            UploadStage::Resolve => UploadDriver {
                state_epoch: 0,
                state_phase: Phase::Active,
                write_epoch: 0,
                read_epoch: 0,
                permit_epoch: 0,
                authority_epoch: 0,
                ..base
            },
            UploadStage::Shadow => UploadDriver {
                web: false,
                web_epoch: None,
                state_epoch: 1,
                state_phase: Phase::Freezing,
                write_epoch: 2,
                read_epoch: 1,
                shadow: true,
                permit_epoch: 0,
                ..base
            },
            UploadStage::Quota | UploadStage::Write => base,
            UploadStage::Recheck => UploadDriver {
                state_epoch: 1,
                state_phase: Phase::Active,
                write_epoch: 1,
                read_epoch: 1,
                permit_epoch: 1,
                ..base
            },
            UploadStage::Reread => UploadDriver {
                write_matched: true,
                ..base
            },
            UploadStage::Activity => UploadDriver {
                state_epoch: 1,
                state_phase: Phase::Freezing,
                write_epoch: 2,
                read_epoch: 1,
                shadow: true,
                permit_epoch: 2,
                write_matched: true,
                ..base
            },
            UploadStage::Publish => UploadDriver {
                write_matched: true,
                ..base
            },
            UploadStage::Done => UploadDriver {
                write_matched: true,
                published: true,
                responded: true,
                ..base
            },
        }
    }

    #[test]
    fn exhaustive_stage_times_event_is_total_and_sound() {
        for stage in UPLOAD_STAGES {
            let driver = sample_driver(stage);
            assert!(
                upload_state_is_sound(driver),
                "sample driver for {stage:?} is unsound"
            );
            for event in upload_events() {
                let t = upload_step(driver, event);
                assert!(
                    upload_state_is_sound(t.driver),
                    "soundness lost from {stage:?} on {event:?}"
                );
                assert!(
                    upload_effect_is_sound(t.driver, t.effect),
                    "effect soundness lost from {stage:?} on {event:?}"
                );
            }
        }
    }

    #[test]
    fn out_of_order_events_are_inert() {
        for stage in UPLOAD_STAGES {
            let driver = sample_driver(stage);
            for event in upload_events() {
                let matching = match (stage, &event) {
                    (UploadStage::Resolve, UploadEvent::Rekey(_)) => true,
                    (UploadStage::Shadow, UploadEvent::Attempt(_)) => true,
                    (UploadStage::Quota, UploadEvent::Quota(_)) => true,
                    (UploadStage::Write, UploadEvent::Write(_)) => true,
                    (UploadStage::Recheck, UploadEvent::Recheck(_)) => true,
                    (UploadStage::Reread, UploadEvent::Reread(_)) => true,
                    (UploadStage::Activity, UploadEvent::Activity(_)) => true,
                    (UploadStage::Publish, UploadEvent::Published) => true,
                    _ => false,
                };
                let t = upload_step(driver, event);
                if !matching {
                    assert_eq!(t.driver, driver, "non-matching event changed state");
                    assert_eq!(t.effect, UploadEffect::Idle);
                }
                assert!(upload_state_is_sound(t.driver));
                assert!(upload_effect_is_sound(t.driver, t.effect));
            }
        }
    }

    #[test]
    fn active_create_walks_resolve_quota_write_reread_publish_complete() {
        let start = begin_upload(request(WriteIntent::Create, Some(1)));
        assert_eq!(start.effect, UploadEffect::ResolveEpoch);

        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 1, phase: Phase::Active },
        );
        assert_eq!(t.effect, UploadEffect::EnforceQuota);
        assert!(!t.driver.shadow);
        assert_eq!(t.driver.permit_epoch, 1);

        let t = on_quota_observed(t.driver, QuotaObservation::Allowed);
        assert!(matches!(t.effect, UploadEffect::Write(_)));

        let t = on_write_observed(t.driver, WriteObservation::Inserted);
        assert_eq!(t.effect, UploadEffect::RereadVersion);
        assert!(t.driver.write_matched);

        let t = on_reread_observed(t.driver, RereadObservation::Read { version: 1 });
        assert_eq!(t.effect, UploadEffect::Publish);

        let t = on_published_observed(t.driver);
        assert_eq!(t.effect, UploadEffect::Complete);
        assert!(t.driver.responded && t.driver.published && !t.driver.failed);
    }

    #[test]
    fn shadow_write_requires_the_starting_device_and_a_rotation_id() {
        let start = begin_upload(request(WriteIntent::Create, Some(2)));
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 1, phase: Phase::Freezing },
        );
        assert_eq!(t.effect, UploadEffect::AuthorizeShadow);
        assert!(t.driver.shadow);
        assert_eq!(t.driver.write_epoch, 2);
        assert_eq!(t.driver.read_epoch, 1);

        let all = AttemptAuthority {
            device_scope: true,
            starter_matches: true,
            rotation_id_present: true,
            rotation_id_matches: true,
        };
        let ok = on_attempt_observed(t.driver, all);
        assert_eq!(ok.effect, UploadEffect::EnforceQuota);
        assert_eq!(ok.driver.permit_epoch, 2);

        for (authority, failure) in [
            (
                AttemptAuthority {
                    device_scope: false,
                    ..all
                },
                UploadFailure::ShadowWebSessionForbidden,
            ),
            (
                AttemptAuthority {
                    rotation_id_present: false,
                    ..all
                },
                UploadFailure::ShadowRotationIdRequired,
            ),
            (
                AttemptAuthority {
                    starter_matches: false,
                    ..all
                },
                UploadFailure::ShadowStarterForbidden,
            ),
            (
                AttemptAuthority {
                    rotation_id_matches: false,
                    ..all
                },
                UploadFailure::ShadowStarterForbidden,
            ),
        ] {
            let rejected = on_attempt_observed(t.driver, authority);
            assert_eq!(
                rejected.effect,
                UploadEffect::Fail(failure),
                "{authority:?}"
            );
        }
    }

    #[test]
    fn web_writer_must_be_pinned_to_the_resolved_epoch() {
        let stale = UploadRequest {
            writer: web(1),
            intent: WriteIntent::Create,
            declared_epoch: Some(2),
        };
        let start = begin_upload(stale);
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 2, phase: Phase::Active },
        );
        assert_eq!(
            t.effect,
            UploadEffect::Fail(UploadFailure::AuthorityEpochMismatch)
        );

        let current = UploadRequest {
            writer: web(2),
            intent: WriteIntent::Create,
            declared_epoch: Some(2),
        };
        let start = begin_upload(current);
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 2, phase: Phase::Active },
        );
        assert_eq!(t.effect, UploadEffect::EnforceQuota);
    }

    #[test]
    fn web_session_never_authorizes_a_shadow_write() {
        let request = UploadRequest {
            writer: web(1),
            intent: WriteIntent::Create,
            declared_epoch: Some(2),
        };
        let start = begin_upload(request);
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 1, phase: Phase::Freezing },
        );
        assert_eq!(t.effect, UploadEffect::AuthorizeShadow);
        let t = on_attempt_observed(
            t.driver,
            AttemptAuthority {
                device_scope: false,
                starter_matches: false,
                rotation_id_present: true,
                rotation_id_matches: false,
            },
        );
        assert_eq!(
            t.effect,
            UploadEffect::Fail(UploadFailure::ShadowWebSessionForbidden)
        );
    }

    #[test]
    fn skipped_update_rechecks_and_classifies_version_vs_epoch() {
        let start = begin_upload(request(WriteIntent::Replace { version: 7 }, Some(1)));
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 1, phase: Phase::Active },
        );
        let t = on_quota_observed(t.driver, QuotaObservation::Allowed);
        let t = on_write_observed(t.driver, WriteObservation::Skipped);
        assert_eq!(t.effect, UploadEffect::RecheckState);

        assert_eq!(
            on_recheck_observed(t.driver, RecheckObservation::Unchanged).effect,
            UploadEffect::Fail(UploadFailure::VersionMismatch)
        );
        assert_eq!(
            on_recheck_observed(t.driver, RecheckObservation::Changed).effect,
            UploadEffect::Fail(UploadFailure::Rekeyed)
        );
        assert_eq!(
            on_recheck_observed(t.driver, RecheckObservation::Failed).effect,
            UploadEffect::Fail(UploadFailure::RecheckStorage)
        );
    }

    #[test]
    fn shadow_skipped_never_rechecks_and_reports_rotation_end() {
        let start = begin_upload(request(WriteIntent::Create, Some(2)));
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 1, phase: Phase::Freezing },
        );
        let t = on_attempt_observed(
            t.driver,
            AttemptAuthority {
                device_scope: true,
                starter_matches: true,
                rotation_id_present: true,
                rotation_id_matches: true,
            },
        );
        let t = on_quota_observed(t.driver, QuotaObservation::Allowed);
        let t = on_write_observed(t.driver, WriteObservation::Skipped);
        assert_eq!(t.effect, UploadEffect::Fail(UploadFailure::RekeyEnded));
    }

    #[test]
    fn create_conflicts_are_terminal_and_never_read_back() {
        let start = begin_upload(request(WriteIntent::Create, Some(1)));
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 1, phase: Phase::Active },
        );
        let t = on_quota_observed(t.driver, QuotaObservation::Allowed);
        for observation in [WriteObservation::Existing, WriteObservation::Duplicate] {
            let t = on_write_observed(t.driver, observation);
            assert_eq!(t.effect, UploadEffect::Fail(UploadFailure::AlreadyExists));
            assert!(!t.driver.write_matched);
        }
        let t = on_write_observed(t.driver, WriteObservation::Failed);
        assert_eq!(t.effect, UploadEffect::Fail(UploadFailure::WriteStorage));
    }

    #[test]
    fn shadow_success_records_activity_and_publishes_nothing() {
        let start = begin_upload(request(WriteIntent::Create, Some(2)));
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 1, phase: Phase::Freezing },
        );
        let t = on_attempt_observed(
            t.driver,
            AttemptAuthority {
                device_scope: true,
                starter_matches: true,
                rotation_id_present: true,
                rotation_id_matches: true,
            },
        );
        let t = on_quota_observed(t.driver, QuotaObservation::Allowed);
        let t = on_write_observed(t.driver, WriteObservation::Inserted);
        let t = on_reread_observed(t.driver, RereadObservation::Read { version: 2 });
        assert_eq!(t.effect, UploadEffect::RecordShadowActivity);
        for observation in [ActivityObservation::Refreshed, ActivityObservation::Ended] {
            let t = on_activity_observed(t.driver, observation);
            assert_eq!(t.effect, UploadEffect::Publish);
            let t = on_published_observed(t.driver);
            assert_eq!(t.effect, UploadEffect::Complete);
            assert!(t.driver.responded && !t.driver.published);
        }
        let t = on_activity_observed(t.driver, ActivityObservation::Failed);
        assert_eq!(t.effect, UploadEffect::Fail(UploadFailure::ActivityStorage));
    }

    #[test]
    fn unauthenticated_and_invalid_epochs_fail_closed() {
        let start = begin_upload(UploadRequest {
            writer: UploadWriter {
                authenticated: false,
                web: false,
                web_epoch: None,
            },
            intent: WriteIntent::Create,
            declared_epoch: Some(1),
        });
        assert_eq!(start.effect, UploadEffect::Fail(UploadFailure::Unauthenticated));
        for event in upload_events() {
            assert_eq!(upload_step(start.driver, event).effect, UploadEffect::Idle);
        }

        let start = begin_upload(request(WriteIntent::Create, Some(0)));
        let t = on_rekey_observed(
            start.driver,
            RekeyObservation::State { epoch: 0, phase: Phase::Active },
        );
        assert_eq!(t.effect, UploadEffect::Fail(UploadFailure::EpochMismatch));
    }

    /// Breadth-first exploration of every reachable upload state up to a
    /// bounded depth; every reachable state and emitted effect is sound.
    #[test]
    fn bfs_reachable_states_preserve_the_invariant() {
        let start = begin_upload(request(WriteIntent::Create, Some(1)));
        assert!(upload_state_is_sound(start.driver));
        let mut frontier = vec![start.driver];
        let mut seen = BTreeSet::new();
        seen.insert(format!("{:?}", start.driver));
        for _ in 0..8 {
            let mut next = Vec::new();
            for driver in frontier {
                for event in upload_events() {
                    let t = upload_step(driver, event);
                    assert!(upload_state_is_sound(t.driver));
                    assert!(upload_effect_is_sound(t.driver, t.effect));
                    let key = format!("{:?}", t.driver);
                    if seen.insert(key) {
                        next.push(t.driver);
                    }
                }
            }
            frontier = next;
        }
        assert!(!seen.is_empty());
    }

    #[test]
    fn read_serves_only_the_current_account_and_epoch() {
        let start = begin_read(ReadRequest { authenticated: true });
        assert_eq!(start.effect, ReadEffect::ReadEpoch);
        let t = on_read_epoch(start.driver, ReadEpochObservation { epoch: 4 });
        assert_eq!(t.effect, ReadEffect::LookupChunk);

        let found = on_read_lookup(
            t.driver,
            ReadLookupObservation::Found {
                account_matches: true,
                epoch_matches: true,
                version: 3,
                lamport_clock: 9,
            },
        );
        assert_eq!(
            found.effect,
            ReadEffect::Serve {
                version: 3,
                lamport_clock: 9
            }
        );
        assert!(found.driver.responded);

        for observation in [
            ReadLookupObservation::Found {
                account_matches: false,
                epoch_matches: true,
                version: 3,
                lamport_clock: 9,
            },
            ReadLookupObservation::Found {
                account_matches: true,
                epoch_matches: false,
                version: 3,
                lamport_clock: 9,
            },
        ] {
            assert_eq!(
                on_read_lookup(t.driver, observation).effect,
                ReadEffect::Fail(ReadFailure::ScopeViolation)
            );
        }
        assert_eq!(
            on_read_lookup(t.driver, ReadLookupObservation::Missing).effect,
            ReadEffect::Fail(ReadFailure::NotFound)
        );
        assert_eq!(
            on_read_lookup(t.driver, ReadLookupObservation::QueryFailed).effect,
            ReadEffect::Fail(ReadFailure::QueryStorage)
        );
        assert_eq!(
            on_read_lookup(t.driver, ReadLookupObservation::Malformed).effect,
            ReadEffect::Fail(ReadFailure::ParseStorage)
        );
    }

    #[test]
    fn read_rejects_invalid_epochs_and_unauthenticated_callers() {
        let start = begin_read(ReadRequest { authenticated: true });
        let t = on_read_epoch(start.driver, ReadEpochObservation { epoch: 0 });
        assert_eq!(t.effect, ReadEffect::Fail(ReadFailure::InvalidEpoch));

        let start = begin_read(ReadRequest {
            authenticated: false,
        });
        assert_eq!(
            start.effect,
            ReadEffect::Fail(ReadFailure::Unauthenticated)
        );
        for event in [
            ReadEvent::Epoch(ReadEpochObservation { epoch: 1 }),
            ReadEvent::Lookup(ReadLookupObservation::Missing),
        ] {
            assert_eq!(read_step(start.driver, event).effect, ReadEffect::Idle);
        }
    }
}
