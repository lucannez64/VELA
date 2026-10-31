//! Pure decision drivers for the web-session handlers.
//!
//! The HTTP handlers in `vela-server/src/web_session/` perform the effectful
//! steps: the per-IP/per-session limiters, the pending-session insert, the
//! session lookup, the atomic waterfall challenge take, the hybrid signature
//! verification, the single-use token claim, PASETO issuance/JTI tracking, the
//! `device:revoked:` sentinel and the `web_sessions` updates. This module owns
//! every *decision* between those effects.
//!
//! There is one driver per state transition, because each request has its own
//! authority and its own observations:
//!
//! - [`StartDriver`] (`POST /web-session/start`): the unauthenticated browser
//!   may only create one `pending` row. The driver has no effect that could
//!   grant, issue or revoke, and `InsertPending` is emitted only after the
//!   request validated.
//! - [`GrantDriver`] (`POST /web-session/:id/grant`): an authenticated, active
//!   device may grant exactly one pending session bound to its own account,
//!   with the registered link nonce, and only through the checked
//!   [`crate::plan_observed_grant`]. The driver also calls
//!   [`crate::clamp_web_ttl`], so the stored expiry is bounded by policy.
//! - [`TokenDriver`] (`POST /web-session/:id/token`): an RW granted session may
//!   redeem one purpose-bound `web_token` challenge for at most one token. The
//!   driver calls [`crate::plan_observed_web_token`]; the token plan is the
//!   private value the signer accepts.
//! - [`DeleteDriver`] (`DELETE /web-session/:id`): only the owning account (the
//!   granted user, or the committed approver while pending) may lock out and
//!   revoke the session.
//!
//! Every driver is total: an out-of-order event, or any event after `Done`, is
//! ignored (`*Effect::Idle`). F* proves the resulting trace properties over
//! every event list in `proofs/fstar/websession-driver-lemmas` and the
//! handler-to-driver link in `proofs/fstar/websession-interpreter-lemmas`.
//!
//! The drivers do not observe the store or SQL database themselves and do not
//! coordinate concurrent requests. Store/SQL linearizability, the challenge
//! store's `get_del` atomicity, the single-use claim's first-writer-wins
//! semantics, signature verification, PASETO signing and the clock remain
//! trusted observations/effects. Concurrent composition over the shared
//! session/challenge store is `proofs/fstar/websession-driver-composition`.

use crate::{
    plan_observed_grant, plan_observed_web_token, GrantDecision, GrantObservation, SessionMode,
    SessionPhase, TokenDecision, TokenPlan, WebTokenObservation,
};

// ════════════════════════════════════════════════════════════════════════════
// POST /web-session/start
// ════════════════════════════════════════════════════════════════════════════

/// Observation from the per-IP start limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartLimitObservation {
    Allowed,
    Limited,
}

/// Observation from the (pure, but message-preserving) request validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartValidationObservation {
    Valid,
    Invalid,
}

/// Observation from the one `INSERT ... status = 'pending'`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartInsertObservation {
    Inserted,
    Failed,
}

/// Where a browser start is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartStage {
    /// Apply the per-IP limiter.
    Limit,
    /// Validate the registered keys and the poll-secret hash.
    Validate,
    /// Insert the one pending row.
    Insert,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// One driver event for `POST /web-session/start`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartEvent {
    LimitObserved(StartLimitObservation),
    Validated(StartValidationObservation),
    Inserted(StartInsertObservation),
}

/// Failure categories for a browser start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartFailure {
    /// The per-IP limiter refused the request.
    RateLimited,
    /// A key, nonce or poll-secret hash was not the exact expected length.
    Validation,
    /// The insert itself failed.
    InsertStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartEffect {
    /// `web_session_start_by_ip`.
    CheckRateLimit,
    /// Decode and length-check the request fields.
    ValidateStart,
    /// `INSERT INTO web_sessions (...) VALUES (..., 'pending', ...)` with
    /// `user_id = NULL` and no grant/token fields set.
    InsertPending,
    /// Terminal success.
    Complete,
    /// Terminal failure; nothing else is performed.
    Fail(StartFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request start state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartDriver {
    pub stage: StartStage,
    /// The limiter allowed this request.
    pub limited_ok: bool,
    /// The request fields passed validation.
    pub validated: bool,
    /// The pending row was inserted.
    pub inserted: bool,
    /// A success response was authorized.
    pub responded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartTransition {
    pub driver: StartDriver,
    pub effect: StartEffect,
}

/// State invariant: the pending insert happens only after the limiter and
/// validation, and a response only after that insert. There is no state in
/// which a start has granted, issued or revoked anything.
pub fn start_state_is_sound(d: StartDriver) -> bool {
    let limit = !d.limited_ok && !d.validated && !d.inserted && !d.responded && !d.failed;
    let validate = d.limited_ok && !d.validated && !d.inserted && !d.responded && !d.failed;
    let insert = d.limited_ok && d.validated && !d.inserted && !d.responded && !d.failed;
    let done = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded || d.inserted);
    (!matches!(d.stage, StartStage::Limit) || limit)
        && (!matches!(d.stage, StartStage::Validate) || validate)
        && (!matches!(d.stage, StartStage::Insert) || insert)
        && (!matches!(d.stage, StartStage::Done) || done)
        && (!d.validated || d.limited_ok)
        && (!d.inserted || d.validated)
        && (!d.responded || d.inserted)
        && (!d.failed || !d.responded)
}

/// Every emitted effect agrees with the state that produced it.
pub fn start_effect_is_sound(d: StartDriver, effect: StartEffect) -> bool {
    match effect {
        StartEffect::CheckRateLimit => {
            matches!(d.stage, StartStage::Limit)
                && !d.limited_ok
                && !d.validated
                && !d.inserted
                && !d.responded
                && !d.failed
        }
        StartEffect::ValidateStart => {
            matches!(d.stage, StartStage::Validate)
                && d.limited_ok
                && !d.validated
                && !d.inserted
                && !d.responded
                && !d.failed
        }
        StartEffect::InsertPending => {
            matches!(d.stage, StartStage::Insert)
                && d.limited_ok
                && d.validated
                && !d.inserted
                && !d.responded
                && !d.failed
        }
        StartEffect::Complete => {
            matches!(d.stage, StartStage::Done)
                && d.inserted
                && d.responded
                && !d.failed
        }
        StartEffect::Fail(_) => matches!(d.stage, StartStage::Done) && d.failed && !d.responded,
        StartEffect::Idle => true,
    }
}

fn start_transition(driver: StartDriver, effect: StartEffect) -> StartTransition {
    StartTransition { driver, effect }
}

fn start_idle(driver: StartDriver) -> StartTransition {
    start_transition(driver, StartEffect::Idle)
}

fn start_terminal(driver: StartDriver, failure: StartFailure) -> StartTransition {
    start_transition(
        StartDriver {
            stage: StartStage::Done,
            failed: true,
            ..driver
        },
        StartEffect::Fail(failure),
    )
}

fn start_blank() -> StartDriver {
    StartDriver {
        stage: StartStage::Limit,
        limited_ok: false,
        validated: false,
        inserted: false,
        responded: false,
        failed: false,
    }
}

/// Start the unauthenticated browser flow. The only effect that mutates state
/// after this point is the pending insert; the driver cannot grant or issue.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    start_state_is_sound(result.driver)
        && start_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_start() -> StartTransition {
    start_transition(start_blank(), StartEffect::CheckRateLimit)
}

fn on_start_limit(driver: StartDriver, observation: StartLimitObservation) -> StartTransition {
    match observation {
        StartLimitObservation::Allowed => start_transition(
            StartDriver {
                stage: StartStage::Validate,
                limited_ok: true,
                ..driver
            },
            StartEffect::ValidateStart,
        ),
        StartLimitObservation::Limited => start_terminal(driver, StartFailure::RateLimited),
    }
}

fn on_start_validated(
    driver: StartDriver,
    observation: StartValidationObservation,
) -> StartTransition {
    match observation {
        StartValidationObservation::Valid => start_transition(
            StartDriver {
                stage: StartStage::Insert,
                validated: true,
                ..driver
            },
            StartEffect::InsertPending,
        ),
        StartValidationObservation::Invalid => start_terminal(driver, StartFailure::Validation),
    }
}

fn on_start_inserted(
    driver: StartDriver,
    observation: StartInsertObservation,
) -> StartTransition {
    match observation {
        StartInsertObservation::Inserted => start_transition(
            StartDriver {
                stage: StartStage::Done,
                inserted: true,
                responded: true,
                ..driver
            },
            StartEffect::Complete,
        ),
        StartInsertObservation::Failed => start_terminal(driver, StartFailure::InsertStorage),
    }
}

/// The total start transition relation.
#[cfg_attr(hax, hax_lib::requires(start_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    start_effect_is_sound(result.driver, result.effect)
        && (!start_state_is_sound(driver) || start_state_is_sound(result.driver))
}))]
pub fn start_step(driver: StartDriver, event: StartEvent) -> StartTransition {
    match event {
        StartEvent::LimitObserved(observation) => {
            if matches!(driver.stage, StartStage::Limit) {
                on_start_limit(driver, observation)
            } else {
                start_idle(driver)
            }
        }
        StartEvent::Validated(observation) => {
            if matches!(driver.stage, StartStage::Validate) {
                on_start_validated(driver, observation)
            } else {
                start_idle(driver)
            }
        }
        StartEvent::Inserted(observation) => {
            if matches!(driver.stage, StartStage::Insert) {
                on_start_inserted(driver, observation)
            } else {
                start_idle(driver)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// POST /web-session/:id/grant
// ════════════════════════════════════════════════════════════════════════════

/// Actor facts established by the authenticated `DeviceSession` extractor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantActorObservation {
    pub authenticated: bool,
    /// The middleware's durable `devices.revoked = 0` check.
    pub device_active: bool,
}

/// Observation from mode/epoch/capsule validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantValidationObservation {
    Valid,
    Invalid,
}

/// Outcome of the session row lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantLookupObservation {
    Absent,
    QueryFailed,
    Present(GrantObservation),
}

/// Outcome of the atomic grant `UPDATE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantUpdateObservation {
    Updated,
    /// Zero rows: the session was no longer pending, the epoch moved, or the
    /// approving device was revoked before the CAS.
    Conflict,
    Failed,
}

/// The values the verified grant permit authorizes the handler to write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantUpdate {
    pub mode: SessionMode,
    pub epoch: i64,
    pub ttl_secs: i64,
}

/// Where a grant is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantStage {
    Validate,
    ObserveSession,
    Update,
    Done,
}

/// One grant driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantEvent {
    Validated(GrantValidationObservation),
    SessionObserved(GrantLookupObservation),
    UpdateObserved(GrantUpdateObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantFailure {
    Unauthenticated,
    Validation,
    NotFound,
    LookupStorage,
    /// The session was not pending (already granted or revoked).
    NotPending,
    /// The browser committed to a different account than the approver.
    CrossAccount,
    /// The scanned link nonce does not match the registered one.
    NonceMismatch,
    /// An RW grant needs the browser's registered signing key.
    MissingWebVk,
    /// The checked policy refused the remaining facts (e.g. a non-positive
    /// epoch that slipped past validation).
    InconsistentFacts,
    /// The CAS found no pending row, a moved epoch, or a revoked device.
    Conflict,
    UpdateStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantEffect {
    ValidateGrant,
    LoadSession,
    /// The checked policy authorized the grant; the argument carries only the
    /// permit values.
    UpdateGrant(GrantUpdate),
    Complete,
    Fail(GrantFailure),
    Idle,
}

/// Per-request grant state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantDriver {
    pub stage: GrantStage,
    pub actor_active: bool,
    pub request_valid: bool,
    pub session_loaded: bool,
    /// The extracted policy returned a permit.
    pub plan_authorized: bool,
    /// The permit's mode, retained for the effect and the theorem.
    pub permit_mode: SessionMode,
    /// The permit's epoch.
    pub permit_epoch: i64,
    /// The browser-requested TTL, retained so the checked clamp is applied
    /// when the session observation is classified.
    pub requested_ttl: Option<i64>,
    /// The policy-clamped TTL.
    pub ttl_secs: i64,
    pub updated: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantTransition {
    pub driver: GrantDriver,
    pub effect: GrantEffect,
}

fn grant_blank(actor_active: bool, requested_ttl: Option<i64>) -> GrantDriver {
    GrantDriver {
        stage: GrantStage::Validate,
        actor_active,
        request_valid: false,
        session_loaded: false,
        plan_authorized: false,
        permit_mode: SessionMode::ReadOnly,
        permit_epoch: 0,
        requested_ttl,
        ttl_secs: 0,
        updated: false,
        responded: false,
        failed: false,
    }
}

pub fn grant_state_is_sound(d: GrantDriver) -> bool {
    let validate = d.actor_active
        && !d.request_valid
        && !d.session_loaded
        && !d.plan_authorized
        && !d.updated
        && !d.responded
        && !d.failed;
    let observe = d.actor_active
        && d.request_valid
        && !d.session_loaded
        && !d.plan_authorized
        && !d.updated
        && !d.responded
        && !d.failed;
    let update = d.actor_active
        && d.request_valid
        && d.session_loaded
        && d.plan_authorized
        && !d.updated
        && !d.responded
        && !d.failed;
    let done = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded
            || (d.actor_active && d.request_valid && d.session_loaded && d.plan_authorized && d.updated));
    (!matches!(d.stage, GrantStage::Validate) || validate)
        && (!matches!(d.stage, GrantStage::ObserveSession) || observe)
        && (!matches!(d.stage, GrantStage::Update) || update)
        && (!matches!(d.stage, GrantStage::Done) || done)
        && (!d.request_valid || d.actor_active)
        && (!d.session_loaded || d.request_valid)
        && (!d.plan_authorized || d.session_loaded)
        && (!d.updated || d.plan_authorized)
        && (!d.responded || d.updated)
        && (!d.failed || !d.responded)
        // A grant permit always carries a policy-legal epoch. The TTL is the
        // checked `clamp_web_ttl` value the effect carries.
        && (!d.plan_authorized || d.permit_epoch >= crate::INITIAL_EPOCH)
}

pub fn grant_effect_is_sound(d: GrantDriver, effect: GrantEffect) -> bool {
    match effect {
        GrantEffect::ValidateGrant => {
            matches!(d.stage, GrantStage::Validate)
                && d.actor_active
                && !d.request_valid
                && !d.session_loaded
                && !d.plan_authorized
                && !d.updated
                && !d.responded
                && !d.failed
        }
        GrantEffect::LoadSession => {
            matches!(d.stage, GrantStage::ObserveSession)
                && d.actor_active
                && d.request_valid
                && !d.session_loaded
                && !d.plan_authorized
                && !d.updated
                && !d.responded
                && !d.failed
        }
        GrantEffect::UpdateGrant(update) => {
            matches!(d.stage, GrantStage::Update)
                && d.actor_active
                && d.request_valid
                && d.session_loaded
                && d.plan_authorized
                && !d.updated
                && !d.responded
                && !d.failed
                && update.epoch == d.permit_epoch
                && update.ttl_secs == d.ttl_secs
                && same_grant_mode(update.mode, d.permit_mode)
        }
        GrantEffect::Complete => {
            matches!(d.stage, GrantStage::Done)
                && d.actor_active
                && d.request_valid
                && d.session_loaded
                && d.plan_authorized
                && d.updated
                && d.responded
                && !d.failed
        }
        GrantEffect::Fail(_) => matches!(d.stage, GrantStage::Done) && d.failed && !d.responded,
        GrantEffect::Idle => true,
    }
}

fn same_grant_mode(a: SessionMode, b: SessionMode) -> bool {
    matches!(
        (a, b),
        (SessionMode::ReadOnly, SessionMode::ReadOnly)
            | (SessionMode::ReadWrite, SessionMode::ReadWrite)
    )
}

fn grant_transition(driver: GrantDriver, effect: GrantEffect) -> GrantTransition {
    GrantTransition { driver, effect }
}

fn grant_idle(driver: GrantDriver) -> GrantTransition {
    grant_transition(driver, GrantEffect::Idle)
}

fn grant_terminal(driver: GrantDriver, failure: GrantFailure) -> GrantTransition {
    grant_transition(
        GrantDriver {
            stage: GrantStage::Done,
            failed: true,
            ..driver
        },
        GrantEffect::Fail(failure),
    )
}

/// Start a grant. An actor the middleware did not verify as an authenticated,
/// active device gets a terminal refusal and performs no effect at all.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    grant_state_is_sound(result.driver)
        && grant_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_grant(actor: GrantActorObservation, requested_ttl: Option<i64>) -> GrantTransition {
    let actor_active = actor.authenticated && actor.device_active;
    if actor_active {
        grant_transition(grant_blank(true, requested_ttl), GrantEffect::ValidateGrant)
    } else {
        let driver = grant_blank(false, requested_ttl);
        grant_transition(
            GrantDriver {
                stage: GrantStage::Done,
                failed: true,
                ..driver
            },
            GrantEffect::Fail(GrantFailure::Unauthenticated),
        )
    }
}

fn on_grant_validated(
    driver: GrantDriver,
    observation: GrantValidationObservation,
) -> GrantTransition {
    match observation {
        GrantValidationObservation::Valid => grant_transition(
            GrantDriver {
                stage: GrantStage::ObserveSession,
                request_valid: true,
                ..driver
            },
            GrantEffect::LoadSession,
        ),
        GrantValidationObservation::Invalid => grant_terminal(driver, GrantFailure::Validation),
    }
}

/// Classify a refused plan while preserving the original handler's precedence.
/// The *decision* is the checked policy's; this only chooses the historical
/// status/message for the refusal.
fn grant_refusal(observation: GrantObservation) -> GrantFailure {
    if !matches!(observation.phase, SessionPhase::Pending) {
        return GrantFailure::NotPending;
    }
    if observation.approver_user != Some(observation.authenticated_user) {
        return GrantFailure::CrossAccount;
    }
    if observation.nonce_length != 32 || !observation.nonce_equal {
        return GrantFailure::NonceMismatch;
    }
    if matches!(observation.mode, SessionMode::ReadWrite) && !observation.has_web_vk {
        return GrantFailure::MissingWebVk;
    }
    GrantFailure::InconsistentFacts
}

fn on_grant_session(
    driver: GrantDriver,
    observation: GrantLookupObservation,
) -> GrantTransition {
    match observation {
        GrantLookupObservation::Absent => grant_terminal(driver, GrantFailure::NotFound),
        GrantLookupObservation::QueryFailed => {
            grant_terminal(driver, GrantFailure::LookupStorage)
        }
        GrantLookupObservation::Present(observed) => match plan_observed_grant(observed) {
            GrantDecision::Grant(permit) => grant_transition(
                GrantDriver {
                    stage: GrantStage::Update,
                    session_loaded: true,
                    plan_authorized: true,
                    permit_mode: permit.mode(),
                    permit_epoch: permit.epoch(),
                    ttl_secs: crate::clamp_web_ttl(driver.requested_ttl),
                    ..driver
                },
                GrantEffect::UpdateGrant(GrantUpdate {
                    mode: permit.mode(),
                    epoch: permit.epoch(),
                    ttl_secs: crate::clamp_web_ttl(driver.requested_ttl),
                }),
            ),
            GrantDecision::Reject => grant_terminal(driver, grant_refusal(observed)),
        },
    }
}

fn on_grant_updated(
    driver: GrantDriver,
    observation: GrantUpdateObservation,
) -> GrantTransition {
    match observation {
        GrantUpdateObservation::Updated => grant_transition(
            GrantDriver {
                stage: GrantStage::Done,
                updated: true,
                responded: true,
                ..driver
            },
            GrantEffect::Complete,
        ),
        GrantUpdateObservation::Conflict => grant_terminal(driver, GrantFailure::Conflict),
        GrantUpdateObservation::Failed => grant_terminal(driver, GrantFailure::UpdateStorage),
    }
}

/// The total grant transition relation.
#[cfg_attr(hax, hax_lib::requires(grant_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    grant_effect_is_sound(result.driver, result.effect)
        && (!grant_state_is_sound(driver) || grant_state_is_sound(result.driver))
}))]
pub fn grant_step(driver: GrantDriver, event: GrantEvent) -> GrantTransition {
    match event {
        GrantEvent::Validated(observation) => {
            if matches!(driver.stage, GrantStage::Validate) {
                on_grant_validated(driver, observation)
            } else {
                grant_idle(driver)
            }
        }
        GrantEvent::SessionObserved(observation) => {
            if matches!(driver.stage, GrantStage::ObserveSession) {
                on_grant_session(driver, observation)
            } else {
                grant_idle(driver)
            }
        }
        GrantEvent::UpdateObserved(observation) => {
            if matches!(driver.stage, GrantStage::Update) {
                on_grant_updated(driver, observation)
            } else {
                grant_idle(driver)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// POST /web-session/:id/token
// ════════════════════════════════════════════════════════════════════════════

/// Observation from the two limiters and the exponential backoff precheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenLimitObservation {
    Allowed,
    Limited,
}

/// The session facts needed to decide an exchange. `now` is the clock reading
/// taken after the success-side backoff reset, exactly where the handler used
/// to read it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenSessionObservation {
    pub phase: SessionPhase,
    pub mode: SessionMode,
    pub granted_user: Option<u128>,
    pub approver_user: Option<u128>,
    pub nonce_present: bool,
    pub web_vk_present: bool,
    pub key_epoch: i64,
    /// The clock reading taken with the row load, and the stored expiry.
    pub now: i64,
    pub expires_at: Option<i64>,
}

/// Outcome of the session lookup. `Malformed` is a decodable row whose
/// `web_vk` field is not valid base64 (an internal error in the original).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenLookupObservation {
    Absent,
    QueryFailed,
    /// The session was granted but lacks the fields a token needs.
    MissingGrant,
    Malformed,
    Present(TokenSessionObservation),
}

/// Outcome of the atomic purpose-bound challenge take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenChallengeObservation {
    Observed(crate::challenge::ChallengeConsumption),
    StorageFailed,
}

/// Outcome of decoding the challenge and running the verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenSignatureObservation {
    Valid,
    /// The challenge was not valid base64. The original returns `BadRequest`
    /// before the verifier and does not touch the failure backoff.
    InvalidChallengeEncoding,
    /// The actual verifier rejected the proof.
    Rejected,
}

/// Outcome of recording a failed proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenFailureRecordObservation {
    Recorded,
    StorageFailed,
}

/// Outcome of the success-side backoff reset, carrying the clock reading the
/// issuance decision uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenResetObservation {
    Reset { now: i64 },
    StorageFailed,
}

/// Outcome of the first-writer-wins token claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenClaimObservation {
    Claimed,
    AlreadyClaimed,
    StorageFailed,
}

/// Outcome of PASETO issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenIssueObservation {
    Issued,
    Failed,
}

/// Where an exchange is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenStage {
    /// Per-IP, per-session and backoff prechecks.
    Precheck,
    /// Load the session row and classify it.
    ObserveSession,
    /// Take the `web_token` challenge once.
    Challenge,
    /// Decode the challenge and run the verifier.
    Verify,
    /// Record a failed proof before returning.
    RecordFailure,
    /// Reset the success-side backoff.
    Reset,
    /// Claim the one token this grant may issue.
    Claim,
    /// Issue (and track) the PASETO from the checked plan.
    Issue,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// One token driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEvent {
    LimitsObserved(TokenLimitObservation),
    SessionObserved(TokenLookupObservation),
    ChallengeObserved(TokenChallengeObservation),
    SignatureObserved(TokenSignatureObservation),
    FailureRecorded(TokenFailureRecordObservation),
    ResetObserved(TokenResetObservation),
    ClaimObserved(TokenClaimObservation),
    Issued(TokenIssueObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenFailure {
    RateLimited,
    NotFound,
    LookupStorage,
    NotGranted,
    ReadOnly,
    Expired,
    MissingGrantFields,
    MissingExpiry,
    MissingUser,
    MissingSigningKey,
    MalformedSession,
    ChallengeMissing,
    ChallengeWrongPurpose,
    ChallengeStorage,
    InvalidChallengeEncoding,
    SignatureRejected,
    FailureRecordStorage,
    BackoffResetStorage,
    AlreadyIssued,
    ClaimStorage,
    IssueFailed,
    /// The checked policy refused facts that passed the handler prechecks.
    InconsistentFacts,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEffect {
    CheckTokenLimits,
    LoadSession,
    /// Take the waterfall challenge key with the `web_token` purpose.
    ConsumeWebTokenChallenge,
    /// Decode the challenge and run the hybrid verifier.
    VerifyWebSignature,
    /// Record the failed proof (exponential backoff) before returning it.
    RecordTokenFailure,
    /// Reset the success-side backoff and read the clock.
    ResetTokenBackoff,
    /// First-writer-wins claim of the one token this grant may issue.
    ClaimToken,
    /// Sign the checked plan and track its JTI.
    IssueToken(TokenPlan),
    Complete,
    Fail(TokenFailure),
    Idle,
}

/// Per-request token-exchange state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenDriver {
    pub stage: TokenStage,
    pub limits_allowed: bool,
    pub session_loaded: bool,
    /// The row was a live, granted, RW session with an account and key.
    pub session_eligible: bool,
    pub granted_by_same_account: bool,
    pub granted_user: Option<u128>,
    pub approver_user: Option<u128>,
    pub nonce_present: bool,
    pub hard_cap: i64,
    pub key_epoch: i64,
    pub challenge_consumed: bool,
    pub signature_valid: bool,
    pub backoff_reset: bool,
    pub token_claimed: bool,
    /// The extracted policy returned a plan.
    pub plan_authorized: bool,
    /// The clock reading taken by the success-side reset; the claim re-runs
    /// the checked plan with it.
    pub now: i64,
    pub token_issued: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenTransition {
    pub driver: TokenDriver,
    pub effect: TokenEffect,
}

fn token_blank() -> TokenDriver {
    TokenDriver {
        stage: TokenStage::Precheck,
        limits_allowed: false,
        session_loaded: false,
        session_eligible: false,
        granted_by_same_account: false,
        granted_user: None,
        approver_user: None,
        nonce_present: false,
        hard_cap: 0,
        key_epoch: 0,
        challenge_consumed: false,
        signature_valid: false,
        backoff_reset: false,
        token_claimed: false,
        plan_authorized: false,
        now: 0,
        token_issued: false,
        responded: false,
        failed: false,
    }
}

/// The clean prefix through each stage: every later fact is still false.
fn token_clean(d: TokenDriver) -> bool {
    !d.challenge_consumed
        && !d.signature_valid
        && !d.backoff_reset
        && !d.token_claimed
        && !d.plan_authorized
        && !d.token_issued
        && !d.responded
        && !d.failed
}

pub fn token_state_is_sound(d: TokenDriver) -> bool {
    let precheck = !d.limits_allowed
        && !d.session_loaded
        && !d.session_eligible
        && token_clean(d);
    let observe = d.limits_allowed
        && !d.session_loaded
        && !d.session_eligible
        && token_clean(d);
    let challenge = d.limits_allowed
        && d.session_loaded
        && d.session_eligible
        && token_clean(d);
    let verify = d.limits_allowed
        && d.session_loaded
        && d.session_eligible
        && d.challenge_consumed
        && !d.signature_valid
        && !d.backoff_reset
        && !d.token_claimed
        && !d.plan_authorized
        && !d.token_issued
        && !d.responded
        && !d.failed;
    let record_failure = d.limits_allowed
        && d.session_loaded
        && d.session_eligible
        && d.challenge_consumed
        && !d.signature_valid
        && !d.backoff_reset
        && !d.token_claimed
        && !d.plan_authorized
        && !d.token_issued
        && !d.responded
        && !d.failed;
    let reset = d.limits_allowed
        && d.session_loaded
        && d.session_eligible
        && d.challenge_consumed
        && d.signature_valid
        && !d.token_claimed
        && !d.plan_authorized
        && !d.token_issued
        && !d.responded
        && !d.failed;
    let claim = d.limits_allowed
        && d.session_loaded
        && d.session_eligible
        && d.challenge_consumed
        && d.signature_valid
        && d.backoff_reset
        && !d.token_claimed
        && !d.token_issued
        && !d.responded
        && !d.failed;
    let issue = d.limits_allowed
        && d.session_loaded
        && d.session_eligible
        && d.challenge_consumed
        && d.signature_valid
        && d.backoff_reset
        && d.token_claimed
        && d.plan_authorized
        && !d.token_issued
        && !d.responded
        && !d.failed;
    let done = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded
            || (d.limits_allowed
                && d.session_loaded
                && d.session_eligible
                && d.challenge_consumed
                && d.signature_valid
                && d.backoff_reset
                && d.token_claimed
                && d.plan_authorized
                && d.token_issued));
    (!matches!(d.stage, TokenStage::Precheck) || precheck)
        && (!matches!(d.stage, TokenStage::ObserveSession) || observe)
        && (!matches!(d.stage, TokenStage::Challenge) || challenge)
        && (!matches!(d.stage, TokenStage::Verify) || verify)
        && (!matches!(d.stage, TokenStage::RecordFailure) || record_failure)
        && (!matches!(d.stage, TokenStage::Reset) || reset)
        && (!matches!(d.stage, TokenStage::Claim) || claim)
        && (!matches!(d.stage, TokenStage::Issue) || issue)
        && (!matches!(d.stage, TokenStage::Done) || done)
        && (!d.session_loaded || d.limits_allowed)
        && (!d.session_eligible || d.session_loaded)
        && (!d.challenge_consumed || d.session_eligible)
        && (!d.signature_valid || d.challenge_consumed)
        && (!d.backoff_reset || d.signature_valid)
        && (!d.token_claimed || d.backoff_reset)
        && (!d.token_issued || d.plan_authorized)
        && (!d.responded || d.token_issued)
        && (!d.failed || !d.responded)
        // A plan only exists with the eligibility facts it was built from, and
        // its scope/epoch/hard-cap are the verified policy's values.
        && (!d.plan_authorized
            || (d.session_eligible
                && d.granted_by_same_account
                && d.nonce_present
                && d.challenge_consumed
                && d.signature_valid
                && d.key_epoch >= crate::INITIAL_EPOCH
                && d.hard_cap > 0))



}

pub fn token_effect_is_sound(d: TokenDriver, effect: TokenEffect) -> bool {
    match effect {
        TokenEffect::CheckTokenLimits => {
            matches!(d.stage, TokenStage::Precheck)
                && !d.limits_allowed
                && !d.session_loaded
                && !d.session_eligible
                && token_clean(d)
        }
        TokenEffect::LoadSession => {
            matches!(d.stage, TokenStage::ObserveSession)
                && d.limits_allowed
                && !d.session_loaded
                && !d.session_eligible
                && token_clean(d)
        }
        TokenEffect::ConsumeWebTokenChallenge => {
            matches!(d.stage, TokenStage::Challenge)
                && d.limits_allowed
                && d.session_loaded
                && d.session_eligible
                && !d.challenge_consumed
                && !d.signature_valid
                && !d.backoff_reset
                && !d.token_claimed
                && !d.plan_authorized
                && !d.token_issued
                && !d.responded
                && !d.failed
        }
        TokenEffect::VerifyWebSignature => {
            matches!(d.stage, TokenStage::Verify)
                && d.challenge_consumed
                && !d.signature_valid
                && !d.backoff_reset
                && !d.token_claimed
                && !d.plan_authorized
                && !d.token_issued
                && !d.responded
                && !d.failed
        }
        TokenEffect::RecordTokenFailure => {
            matches!(d.stage, TokenStage::RecordFailure)
                && d.challenge_consumed
                && !d.signature_valid
                && !d.backoff_reset
                && !d.plan_authorized
                && !d.token_issued
                && !d.responded
                && !d.failed
        }
        TokenEffect::ResetTokenBackoff => {
            matches!(d.stage, TokenStage::Reset)
                && d.challenge_consumed
                && d.signature_valid
                && !d.backoff_reset
                && !d.token_claimed
                && !d.plan_authorized
                && !d.token_issued
                && !d.responded
                && !d.failed
        }
        TokenEffect::ClaimToken => {
            matches!(d.stage, TokenStage::Claim)
                && d.challenge_consumed
                && d.signature_valid
                && d.backoff_reset
                && !d.token_claimed
                && !d.token_issued
                && !d.responded
                && !d.failed
        }
        TokenEffect::IssueToken(_plan) => {
            matches!(d.stage, TokenStage::Issue)
                && d.session_eligible
                && d.granted_by_same_account
                && d.nonce_present
                && d.challenge_consumed
                && d.signature_valid
                && d.backoff_reset
                && d.token_claimed
                && d.plan_authorized
                && !d.token_issued
                && !d.responded
                && !d.failed
        }
        TokenEffect::Complete => {
            matches!(d.stage, TokenStage::Done)
                && d.session_eligible
                && d.challenge_consumed
                && d.signature_valid
                && d.backoff_reset
                && d.token_claimed
                && d.plan_authorized
                && d.token_issued
                && d.responded
                && !d.failed
        }
        TokenEffect::Fail(_) => matches!(d.stage, TokenStage::Done) && d.failed && !d.responded,
        TokenEffect::Idle => true,
    }
}

fn token_transition(driver: TokenDriver, effect: TokenEffect) -> TokenTransition {
    TokenTransition { driver, effect }
}

fn token_idle(driver: TokenDriver) -> TokenTransition {
    token_transition(driver, TokenEffect::Idle)
}

fn token_terminal(driver: TokenDriver, failure: TokenFailure) -> TokenTransition {
    token_transition(
        TokenDriver {
            stage: TokenStage::Done,
            failed: true,
            ..driver
        },
        TokenEffect::Fail(failure),
    )
}

/// Start an exchange. Every request begins at the limit/backoff prechecks.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    token_state_is_sound(result.driver)
        && token_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_token() -> TokenTransition {
    token_transition(token_blank(), TokenEffect::CheckTokenLimits)
}

fn on_token_limits(
    driver: TokenDriver,
    observation: TokenLimitObservation,
) -> TokenTransition {
    match observation {
        TokenLimitObservation::Allowed => token_transition(
            TokenDriver {
                stage: TokenStage::ObserveSession,
                limits_allowed: true,
                ..driver
            },
            TokenEffect::LoadSession,
        ),
        TokenLimitObservation::Limited => token_terminal(driver, TokenFailure::RateLimited),
    }
}

fn on_token_session(
    driver: TokenDriver,
    observation: TokenLookupObservation,
) -> TokenTransition {
    match observation {
        TokenLookupObservation::Absent => token_terminal(driver, TokenFailure::NotFound),
        TokenLookupObservation::QueryFailed => token_terminal(driver, TokenFailure::LookupStorage),
        TokenLookupObservation::Malformed => {
            token_terminal(driver, TokenFailure::MalformedSession)
        }
        TokenLookupObservation::MissingGrant => {
            token_terminal(driver, TokenFailure::MissingGrantFields)
        }
        TokenLookupObservation::Present(session) => {
            // Preserve the handler's exact precheck order.
            let failure = if !matches!(session.phase, SessionPhase::Granted) {
                Some(TokenFailure::NotGranted)
            } else if !matches!(session.mode, SessionMode::ReadWrite) {
                Some(TokenFailure::ReadOnly)
            } else {
                match session.expires_at {
                    None => Some(TokenFailure::MissingExpiry),
                    Some(expires_at) if session.now >= expires_at => {
                        Some(TokenFailure::Expired)
                    }
                    Some(_) if session.granted_user.is_none() => {
                        Some(TokenFailure::MissingUser)
                    }
                    Some(_) if !session.web_vk_present => {
                        Some(TokenFailure::MissingSigningKey)
                    }
                    Some(_) if session.approver_user.is_none() => {
                        Some(TokenFailure::MissingGrantFields)
                    }
                    Some(_) => None,
                }
            };
            match failure {
                Some(failure) => token_terminal(driver, failure),
                None => token_transition(
                    TokenDriver {
                        stage: TokenStage::Challenge,
                        session_loaded: true,
                        session_eligible: true,
                        granted_by_same_account: match (
                            session.granted_user,
                            session.approver_user,
                        ) {
                            (Some(granted), Some(approver)) => granted == approver,
                            _ => false,
                        },
                        granted_user: session.granted_user,
                        approver_user: session.approver_user,
                        nonce_present: session.nonce_present,
                        key_epoch: session.key_epoch,
                        hard_cap: session.expires_at.unwrap_or(0),
                        ..driver
                    },
                    TokenEffect::ConsumeWebTokenChallenge,
                ),
            }
        }
    }
}

fn on_token_challenge(
    driver: TokenDriver,
    observation: TokenChallengeObservation,
) -> TokenTransition {
    use crate::challenge::ChallengeConsumption;
    match observation {
        TokenChallengeObservation::Observed(ChallengeConsumption::Accepted) => token_transition(
            TokenDriver {
                stage: TokenStage::Verify,
                challenge_consumed: true,
                ..driver
            },
            TokenEffect::VerifyWebSignature,
        ),
        TokenChallengeObservation::Observed(ChallengeConsumption::Missing) => {
            token_terminal(driver, TokenFailure::ChallengeMissing)
        }
        TokenChallengeObservation::Observed(ChallengeConsumption::WrongPurpose) => {
            token_terminal(driver, TokenFailure::ChallengeWrongPurpose)
        }
        TokenChallengeObservation::StorageFailed => {
            token_terminal(driver, TokenFailure::ChallengeStorage)
        }
    }
}

fn on_token_signature(
    driver: TokenDriver,
    observation: TokenSignatureObservation,
) -> TokenTransition {
    match observation {
        TokenSignatureObservation::Valid => token_transition(
            TokenDriver {
                stage: TokenStage::Reset,
                signature_valid: true,
                ..driver
            },
            TokenEffect::ResetTokenBackoff,
        ),
        TokenSignatureObservation::InvalidChallengeEncoding => {
            token_terminal(driver, TokenFailure::InvalidChallengeEncoding)
        }
        TokenSignatureObservation::Rejected => token_transition(
            TokenDriver {
                stage: TokenStage::RecordFailure,
                ..driver
            },
            TokenEffect::RecordTokenFailure,
        ),
    }
}

fn on_token_failure_recorded(
    driver: TokenDriver,
    observation: TokenFailureRecordObservation,
) -> TokenTransition {
    match observation {
        TokenFailureRecordObservation::Recorded => {
            token_terminal(driver, TokenFailure::SignatureRejected)
        }
        TokenFailureRecordObservation::StorageFailed => {
            token_terminal(driver, TokenFailure::FailureRecordStorage)
        }
    }
}

fn on_token_reset(driver: TokenDriver, observation: TokenResetObservation) -> TokenTransition {
    match observation {
        TokenResetObservation::Reset { now } => token_transition(
            TokenDriver {
                stage: TokenStage::Claim,
                backoff_reset: true,
                now,
                ..driver
            },
            TokenEffect::ClaimToken,
        ),
        TokenResetObservation::StorageFailed => {
            token_terminal(driver, TokenFailure::BackoffResetStorage)
        }
    }
}

fn on_token_claim(driver: TokenDriver, observation: TokenClaimObservation) -> TokenTransition {
    match observation {
        TokenClaimObservation::Claimed => {
            // Facts the checked plan needs. They are established by the
            // session observation and the challenge/verifier stages; checking
            // them here keeps the state invariant independent of the plan
            // call's postcondition (the plan still decides).
            if !(driver.nonce_present
                && driver.granted_by_same_account
                && driver.key_epoch >= crate::INITIAL_EPOCH
                && driver.hard_cap > 0)
            {
                return token_terminal(driver, TokenFailure::InconsistentFacts);
            }
            // Re-run the checked plan with the clock reading the reset
            // observed. The decision is the policy's; the driver only supplies
            // the grant, nonce, challenge and verifier facts.
            let decision = plan_observed_web_token(
                WebTokenObservation {
                    phase: SessionPhase::Granted,
                    mode: SessionMode::ReadWrite,
                    granted_user: driver.granted_user,
                    approver_user: driver.approver_user,
                    nonce_present: driver.nonce_present,
                    challenge_consumed: driver.challenge_consumed,
                    signature_valid: driver.signature_valid,
                },
                driver.now,
                driver.hard_cap,
                driver.key_epoch,
            );
            match decision {
                TokenDecision::Issue(plan) => token_transition(
                    TokenDriver {
                        stage: TokenStage::Issue,
                        token_claimed: true,
                        plan_authorized: true,
                        ..driver
                    },
                    TokenEffect::IssueToken(plan),
                ),
                TokenDecision::Reject => {
                    token_terminal(driver, TokenFailure::InconsistentFacts)
                }
            }
        }
        TokenClaimObservation::AlreadyClaimed => token_terminal(driver, TokenFailure::AlreadyIssued),
        TokenClaimObservation::StorageFailed => token_terminal(driver, TokenFailure::ClaimStorage),
    }
}

fn on_token_issued(driver: TokenDriver, observation: TokenIssueObservation) -> TokenTransition {
    match observation {
        TokenIssueObservation::Issued => token_transition(
            TokenDriver {
                stage: TokenStage::Done,
                token_issued: true,
                responded: true,
                ..driver
            },
            TokenEffect::Complete,
        ),
        TokenIssueObservation::Failed => token_terminal(driver, TokenFailure::IssueFailed),
    }
}


/// The total token-exchange transition relation. The checked plan is built by
/// [`crate::plan_observed_web_token`] from an observation where every grant,
/// nonce, challenge and signature fact must hold.
#[cfg_attr(hax, hax_lib::requires(token_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    token_effect_is_sound(result.driver, result.effect)
        && (!token_state_is_sound(driver) || token_state_is_sound(result.driver))
}))]
pub fn token_step(driver: TokenDriver, event: TokenEvent) -> TokenTransition {
    match event {
        TokenEvent::LimitsObserved(observation) => {
            if matches!(driver.stage, TokenStage::Precheck) {
                on_token_limits(driver, observation)
            } else {
                token_idle(driver)
            }
        }
        TokenEvent::SessionObserved(observation) => {
            if matches!(driver.stage, TokenStage::ObserveSession) {
                on_token_session(driver, observation)
            } else {
                token_idle(driver)
            }
        }
        TokenEvent::ChallengeObserved(observation) => {
            if matches!(driver.stage, TokenStage::Challenge) {
                on_token_challenge(driver, observation)
            } else {
                token_idle(driver)
            }
        }
        TokenEvent::SignatureObserved(observation) => {
            if matches!(driver.stage, TokenStage::Verify) {
                on_token_signature(driver, observation)
            } else {
                token_idle(driver)
            }
        }
        TokenEvent::FailureRecorded(observation) => {
            if matches!(driver.stage, TokenStage::RecordFailure) {
                on_token_failure_recorded(driver, observation)
            } else {
                token_idle(driver)
            }
        }
        TokenEvent::ResetObserved(observation) => {
            if matches!(driver.stage, TokenStage::Reset) {
                on_token_reset(driver, observation)
            } else {
                token_idle(driver)
            }
        }
        TokenEvent::ClaimObserved(observation) => {
            if matches!(driver.stage, TokenStage::Claim) {
                on_token_claim(driver, observation)
            } else {
                token_idle(driver)
            }
        }
        TokenEvent::Issued(observation) => {
            if matches!(driver.stage, TokenStage::Issue) {
                on_token_issued(driver, observation)
            } else {
                token_idle(driver)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DELETE /web-session/:id
// ════════════════════════════════════════════════════════════════════════════

/// Actor facts established by the authenticated `DeviceSession` extractor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteActorObservation {
    pub authenticated: bool,
    /// The authenticated account the request is scoped to.
    pub user: u128,
}

/// The ownership fields of a session row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteSessionFacts {
    pub session_user: Option<u128>,
    pub approver_user: Option<u128>,
}

/// Outcome of the session lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteLookupObservation {
    Absent,
    QueryFailed,
    Present(DeleteSessionFacts),
}

/// Outcome of the `device:revoked:` sentinel write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteSentinelObservation {
    Applied,
    StorageFailed,
}

/// Outcome of the `web_sessions` revocation `UPDATE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteRecordObservation {
    Updated,
    Failed,
}

/// Where a session delete is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteStage {
    Observe,
    Lockout,
    Record,
    Done,
}

/// One delete driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteEvent {
    SessionObserved(DeleteLookupObservation),
    SentinelWritten(DeleteSentinelObservation),
    RecordObserved(DeleteRecordObservation),
}

/// Failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteFailure {
    Unauthenticated,
    /// Missing session or a different account — deliberately the same
    /// `NotFound` response, so a stray id reveals nothing.
    NotFound,
    LookupStorage,
    LockoutStorage,
    RecordStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteEffect {
    LoadSession,
    /// Write `device:revoked:<session_id>` before the SQL row says revoked.
    LockoutSession,
    /// `UPDATE web_sessions SET status = 'revoked', capsule = NULL`.
    RecordRevocation,
    Complete,
    Fail(DeleteFailure),
    Idle,
}

/// Per-request delete state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteDriver {
    pub stage: DeleteStage,
    pub actor_active: bool,
    /// The authenticated account the request is scoped to.
    pub actor_user: u128,
    pub owner_matches: bool,
    pub locked: bool,
    pub recorded: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteTransition {
    pub driver: DeleteDriver,
    pub effect: DeleteEffect,
}

fn delete_blank(actor_active: bool) -> DeleteDriver {
    DeleteDriver {
        stage: DeleteStage::Observe,
        actor_active,
        actor_user: 0,
        owner_matches: false,
        locked: false,
        recorded: false,
        responded: false,
        failed: false,
    }
}

pub fn delete_state_is_sound(d: DeleteDriver) -> bool {
    let observe = d.actor_active
        && !d.owner_matches
        && !d.locked
        && !d.recorded
        && !d.responded
        && !d.failed;
    let lockout = d.actor_active
        && d.owner_matches
        && !d.locked
        && !d.recorded
        && !d.responded
        && !d.failed;
    let record = d.actor_active
        && d.owner_matches
        && d.locked
        && !d.recorded
        && !d.responded
        && !d.failed;
    let done = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded || (d.actor_active && d.owner_matches && d.locked && d.recorded));
    (!matches!(d.stage, DeleteStage::Observe) || observe)
        && (!matches!(d.stage, DeleteStage::Lockout) || lockout)
        && (!matches!(d.stage, DeleteStage::Record) || record)
        && (!matches!(d.stage, DeleteStage::Done) || done)
        && (!d.owner_matches || d.actor_active)
        && (!d.locked || d.owner_matches)
        && (!d.recorded || d.locked)
        && (!d.responded || d.recorded)
        && (!d.failed || !d.responded)
}

pub fn delete_effect_is_sound(d: DeleteDriver, effect: DeleteEffect) -> bool {
    match effect {
        DeleteEffect::LoadSession => {
            matches!(d.stage, DeleteStage::Observe)
                && d.actor_active
                && !d.owner_matches
                && !d.locked
                && !d.recorded
                && !d.responded
                && !d.failed
        }
        DeleteEffect::LockoutSession => {
            matches!(d.stage, DeleteStage::Lockout)
                && d.actor_active
                && d.owner_matches
                && !d.locked
                && !d.recorded
                && !d.responded
                && !d.failed
        }
        DeleteEffect::RecordRevocation => {
            matches!(d.stage, DeleteStage::Record)
                && d.actor_active
                && d.owner_matches
                && d.locked
                && !d.recorded
                && !d.responded
                && !d.failed
        }
        DeleteEffect::Complete => {
            matches!(d.stage, DeleteStage::Done)
                && d.actor_active
                && d.owner_matches
                && d.locked
                && d.recorded
                && d.responded
                && !d.failed
        }
        DeleteEffect::Fail(_) => matches!(d.stage, DeleteStage::Done) && d.failed && !d.responded,
        DeleteEffect::Idle => true,
    }
}

fn delete_transition(driver: DeleteDriver, effect: DeleteEffect) -> DeleteTransition {
    DeleteTransition { driver, effect }
}

fn delete_idle(driver: DeleteDriver) -> DeleteTransition {
    delete_transition(driver, DeleteEffect::Idle)
}

fn delete_terminal(driver: DeleteDriver, failure: DeleteFailure) -> DeleteTransition {
    delete_transition(
        DeleteDriver {
            stage: DeleteStage::Done,
            failed: true,
            ..driver
        },
        DeleteEffect::Fail(failure),
    )
}

/// Start a delete. An unauthenticated actor gets a terminal refusal with no
/// effect; only the account that owns (or is committed to) the session may
/// lock it out or record its revocation.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    delete_state_is_sound(result.driver)
        && delete_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_delete(actor: DeleteActorObservation) -> DeleteTransition {
    if actor.authenticated {
        delete_transition(
            DeleteDriver {
                actor_user: actor.user,
                ..delete_blank(true)
            },
            DeleteEffect::LoadSession,
        )
    } else {
        delete_transition(
            DeleteDriver {
                stage: DeleteStage::Done,
                failed: true,
                ..delete_blank(false)
            },
            DeleteEffect::Fail(DeleteFailure::Unauthenticated),
        )
    }
}

fn delete_owner(facts: DeleteSessionFacts) -> Option<u128> {
    match facts.session_user {
        Some(user) => Some(user),
        None => facts.approver_user,
    }
}

fn on_delete_session(
    driver: DeleteDriver,
    actor_user: u128,
    observation: DeleteLookupObservation,
) -> DeleteTransition {
    match observation {
        DeleteLookupObservation::Absent => delete_terminal(driver, DeleteFailure::NotFound),
        DeleteLookupObservation::QueryFailed => {
            delete_terminal(driver, DeleteFailure::LookupStorage)
        }
        DeleteLookupObservation::Present(facts) => {
            if delete_owner(facts) == Some(actor_user) {
                delete_transition(
                    DeleteDriver {
                        stage: DeleteStage::Lockout,
                        owner_matches: true,
                        ..driver
                    },
                    DeleteEffect::LockoutSession,
                )
            } else {
                delete_terminal(driver, DeleteFailure::NotFound)
            }
        }
    }
}

fn on_delete_sentinel(
    driver: DeleteDriver,
    observation: DeleteSentinelObservation,
) -> DeleteTransition {
    match observation {
        DeleteSentinelObservation::Applied => delete_transition(
            DeleteDriver {
                stage: DeleteStage::Record,
                locked: true,
                ..driver
            },
            DeleteEffect::RecordRevocation,
        ),
        DeleteSentinelObservation::StorageFailed => {
            delete_terminal(driver, DeleteFailure::LockoutStorage)
        }
    }
}

fn on_delete_record(
    driver: DeleteDriver,
    observation: DeleteRecordObservation,
) -> DeleteTransition {
    match observation {
        DeleteRecordObservation::Updated => delete_transition(
            DeleteDriver {
                stage: DeleteStage::Done,
                recorded: true,
                responded: true,
                ..driver
            },
            DeleteEffect::Complete,
        ),
        DeleteRecordObservation::Failed => delete_terminal(driver, DeleteFailure::RecordStorage),
    }
}

/// The total delete transition relation.
#[cfg_attr(hax, hax_lib::requires(delete_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    delete_effect_is_sound(result.driver, result.effect)
        && (!delete_state_is_sound(driver) || delete_state_is_sound(result.driver))
}))]
pub fn delete_step(driver: DeleteDriver, event: DeleteEvent) -> DeleteTransition {
    match event {
        DeleteEvent::SessionObserved(observation) => {
            if matches!(driver.stage, DeleteStage::Observe) {
                on_delete_session(driver, driver.actor_user, observation)
            } else {
                delete_idle(driver)
            }
        }
        DeleteEvent::SentinelWritten(observation) => {
            if matches!(driver.stage, DeleteStage::Lockout) {
                on_delete_sentinel(driver, observation)
            } else {
                delete_idle(driver)
            }
        }
        DeleteEvent::RecordObserved(observation) => {
            if matches!(driver.stage, DeleteStage::Record) {
                on_delete_record(driver, observation)
            } else {
                delete_idle(driver)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Rust conformance tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::ChallengeConsumption;

    fn valid_grant_observation() -> GrantObservation {
        GrantObservation {
            phase: SessionPhase::Pending,
            mode: SessionMode::ReadWrite,
            approver_user: Some(7),
            authenticated_user: 7,
            nonce_length: 32,
            nonce_equal: true,
            has_web_vk: true,
            declared_epoch: 3,
        }
    }

    #[test]
    fn start_only_ever_reaches_the_pending_insert() {
        let mut t = begin_start();
        assert_eq!(t.effect, StartEffect::CheckRateLimit);
        t = start_step(t.driver, StartEvent::LimitObserved(StartLimitObservation::Allowed));
        assert_eq!(t.effect, StartEffect::ValidateStart);
        t = start_step(t.driver, StartEvent::Validated(StartValidationObservation::Valid));
        assert_eq!(t.effect, StartEffect::InsertPending);
        t = start_step(t.driver, StartEvent::Inserted(StartInsertObservation::Inserted));
        assert_eq!(t.effect, StartEffect::Complete);
        assert!(t.driver.inserted && t.driver.responded);
        for event in [
            StartEvent::LimitObserved(StartLimitObservation::Allowed),
            StartEvent::Validated(StartValidationObservation::Valid),
            StartEvent::Inserted(StartInsertObservation::Inserted),
        ] {
            let after = start_step(t.driver, event);
            assert_eq!(after.effect, StartEffect::Idle);
        }
    }

    #[test]
    fn start_refuses_every_failure_before_an_insert() {
        for (event, failure) in [
            (
                StartEvent::LimitObserved(StartLimitObservation::Limited),
                StartFailure::RateLimited,
            ),
            (
                StartEvent::Validated(StartValidationObservation::Invalid),
                StartFailure::Validation,
            ),
            (
                StartEvent::Inserted(StartInsertObservation::Failed),
                StartFailure::InsertStorage,
            ),
        ] {
            let mut driver = begin_start().driver;
            if !matches!(event, StartEvent::LimitObserved(_)) {
                driver = start_step(driver, StartEvent::LimitObserved(StartLimitObservation::Allowed)).driver;
            }
            if matches!(event, StartEvent::Inserted(_)) {
                driver = start_step(driver, StartEvent::Validated(StartValidationObservation::Valid)).driver;
            }
            let t = start_step(driver, event);
            assert_eq!(t.effect, StartEffect::Fail(failure));
            assert!(t.driver.failed && !t.driver.inserted && !t.driver.responded);
        }
    }

    #[test]
    fn inactive_grant_actor_performs_nothing() {
        for actor in [
            GrantActorObservation { authenticated: false, device_active: true },
            GrantActorObservation { authenticated: true, device_active: false },
        ] {
            let t = begin_grant(actor, None);
            assert_eq!(t.effect, GrantEffect::Fail(GrantFailure::Unauthenticated));
            let after = grant_step(t.driver, GrantEvent::Validated(GrantValidationObservation::Valid));
            assert_eq!(after.effect, GrantEffect::Idle);
        }
    }

    #[test]
    fn grant_requires_the_checked_plan_and_a_pending_row() {
        let actor = GrantActorObservation { authenticated: true, device_active: true };
        let mut t = begin_grant(actor, Some(60));
        t = grant_step(t.driver, GrantEvent::Validated(GrantValidationObservation::Valid));
        assert_eq!(t.effect, GrantEffect::LoadSession);
        t = grant_step(
            t.driver,
            GrantEvent::SessionObserved(GrantLookupObservation::Present(valid_grant_observation())),
        );
        assert!(t.driver.plan_authorized);
        assert_eq!(t.driver.ttl_secs, crate::MIN_WEB_TTL_SECS);
        assert!(matches!(t.effect, GrantEffect::UpdateGrant(_)));
        t = grant_step(t.driver, GrantEvent::UpdateObserved(GrantUpdateObservation::Updated));
        assert_eq!(t.effect, GrantEffect::Complete);

        for observation in [
            GrantObservation { phase: SessionPhase::Granted, ..valid_grant_observation() },
            GrantObservation { approver_user: Some(8), ..valid_grant_observation() },
            GrantObservation { nonce_equal: false, ..valid_grant_observation() },
            GrantObservation { mode: SessionMode::ReadWrite, has_web_vk: false, ..valid_grant_observation() },
        ] {
            let mut t = begin_grant(actor, None);
            t = grant_step(t.driver, GrantEvent::Validated(GrantValidationObservation::Valid));
            t = grant_step(
                t.driver,
                GrantEvent::SessionObserved(GrantLookupObservation::Present(observation)),
            );
            assert!(matches!(t.effect, GrantEffect::Fail(_)), "{observation:?}");
        }
    }

    fn valid_token_session() -> TokenSessionObservation {
        TokenSessionObservation {
            phase: SessionPhase::Granted,
            mode: SessionMode::ReadWrite,
            granted_user: Some(7),
            approver_user: Some(7),
            nonce_present: true,
            web_vk_present: true,
            key_epoch: 1,
            now: 100,
            expires_at: Some(1_000),
        }
    }

    fn drive_token_to_reset(now: i64) -> TokenTransition {
        let mut t = begin_token();
        t = token_step(t.driver, TokenEvent::LimitsObserved(TokenLimitObservation::Allowed));
        t = token_step(
            t.driver,
            TokenEvent::SessionObserved(TokenLookupObservation::Present(valid_token_session())),
        );
        t = token_step(
            t.driver,
            TokenEvent::ChallengeObserved(TokenChallengeObservation::Observed(
                ChallengeConsumption::Accepted,
            )),
        );
        t = token_step(
            t.driver,
            TokenEvent::SignatureObserved(TokenSignatureObservation::Valid),
        );
        assert_eq!(t.effect, TokenEffect::ResetTokenBackoff);
        token_step(t.driver, TokenEvent::ResetObserved(TokenResetObservation::Reset { now }))
    }

    #[test]
    fn token_requires_every_fact_and_claims_once() {
        let mut t = drive_token_to_reset(100);
        assert_eq!(t.effect, TokenEffect::ClaimToken);
        assert!(!t.driver.plan_authorized);
        t = token_step(t.driver, TokenEvent::ClaimObserved(TokenClaimObservation::Claimed));
        assert!(t.driver.plan_authorized);
        assert!(matches!(t.effect, TokenEffect::IssueToken(_)));
        t = token_step(t.driver, TokenEvent::Issued(TokenIssueObservation::Issued));
        assert_eq!(t.effect, TokenEffect::Complete);
        assert!(t.driver.token_issued && t.driver.responded);

        let t = token_step(
            drive_token_to_reset(100).driver,
            TokenEvent::ClaimObserved(TokenClaimObservation::AlreadyClaimed),
        );
        assert_eq!(t.effect, TokenEffect::Fail(TokenFailure::AlreadyIssued));
    }

    #[test]
    fn token_rejects_terminal_sessions_and_wrong_challenges() {
        for session in [
            TokenSessionObservation { phase: SessionPhase::Pending, ..valid_token_session() },
            TokenSessionObservation { phase: SessionPhase::Revoked, ..valid_token_session() },
            TokenSessionObservation { mode: SessionMode::ReadOnly, ..valid_token_session() },
        ] {
            let mut t = begin_token();
            t = token_step(t.driver, TokenEvent::LimitsObserved(TokenLimitObservation::Allowed));
            t = token_step(
                t.driver,
                TokenEvent::SessionObserved(TokenLookupObservation::Present(session)),
            );
            assert!(matches!(t.effect, TokenEffect::Fail(_)), "{session:?}");
        }
        for challenge in [
            TokenChallengeObservation::Observed(ChallengeConsumption::Missing),
            TokenChallengeObservation::Observed(ChallengeConsumption::WrongPurpose),
            TokenChallengeObservation::StorageFailed,
        ] {
            let mut t = begin_token();
            t = token_step(t.driver, TokenEvent::LimitsObserved(TokenLimitObservation::Allowed));
            t = token_step(
                t.driver,
                TokenEvent::SessionObserved(TokenLookupObservation::Present(valid_token_session())),
            );
            t = token_step(t.driver, TokenEvent::ChallengeObserved(challenge));
            assert!(matches!(t.effect, TokenEffect::Fail(_)), "{challenge:?}");
        }
    }

    #[test]
    fn delete_requires_the_owning_account() {
        let actor = DeleteActorObservation { authenticated: true, user: 7 };
        let mut t = begin_delete(actor);
        t = delete_step(
            t.driver,
            DeleteEvent::SessionObserved(DeleteLookupObservation::Present(DeleteSessionFacts {
                session_user: Some(7),
                approver_user: None,
            })),
        );
        assert_eq!(t.effect, DeleteEffect::LockoutSession);
        t = delete_step(
            t.driver,
            DeleteEvent::SentinelWritten(DeleteSentinelObservation::Applied),
        );
        assert_eq!(t.effect, DeleteEffect::RecordRevocation);
        t = delete_step(
            t.driver,
            DeleteEvent::RecordObserved(DeleteRecordObservation::Updated),
        );
        assert_eq!(t.effect, DeleteEffect::Complete);

        for facts in [
            DeleteSessionFacts { session_user: Some(8), approver_user: None },
            DeleteSessionFacts { session_user: None, approver_user: Some(8) },
            DeleteSessionFacts { session_user: None, approver_user: None },
        ] {
            let mut t = begin_delete(actor);
            t = delete_step(
                t.driver,
                DeleteEvent::SessionObserved(DeleteLookupObservation::Present(facts)),
            );
            assert_eq!(t.effect, DeleteEffect::Fail(DeleteFailure::NotFound), "{facts:?}");
        }
        let pending = DeleteSessionFacts { session_user: None, approver_user: Some(7) };
        let t = delete_step(
            begin_delete(actor).driver,
            DeleteEvent::SessionObserved(DeleteLookupObservation::Present(pending)),
        );
        assert_eq!(t.effect, DeleteEffect::LockoutSession);
    }

    /// Every out-of-order event leaves the state unchanged and emits `Idle`.
    #[test]
    fn out_of_order_events_are_inert() {
        let start = begin_start();
        for event in [
            StartEvent::Validated(StartValidationObservation::Valid),
            StartEvent::Inserted(StartInsertObservation::Inserted),
        ] {
            let t = start_step(start.driver, event);
            assert_eq!(t.driver, start.driver);
            assert_eq!(t.effect, StartEffect::Idle);
        }

        let grant = begin_grant(GrantActorObservation { authenticated: true, device_active: true }, None);
        for event in [
            GrantEvent::SessionObserved(GrantLookupObservation::Absent),
            GrantEvent::UpdateObserved(GrantUpdateObservation::Updated),
        ] {
            let t = grant_step(grant.driver, event);
            assert_eq!(t.driver, grant.driver);
            assert_eq!(t.effect, GrantEffect::Idle);
        }

        let token = begin_token();
        for event in [
            TokenEvent::SessionObserved(TokenLookupObservation::Absent),
            TokenEvent::ChallengeObserved(TokenChallengeObservation::StorageFailed),
            TokenEvent::SignatureObserved(TokenSignatureObservation::Valid),
            TokenEvent::Issued(TokenIssueObservation::Issued),
        ] {
            let t = token_step(token.driver, event);
            assert_eq!(t.driver, token.driver);
            assert_eq!(t.effect, TokenEffect::Idle);
        }

        let delete = begin_delete(DeleteActorObservation { authenticated: true, user: 7 });
        for event in [
            DeleteEvent::SentinelWritten(DeleteSentinelObservation::Applied),
            DeleteEvent::RecordObserved(DeleteRecordObservation::Updated),
        ] {
            let t = delete_step(delete.driver, event);
            assert_eq!(t.driver, delete.driver);
            assert_eq!(t.effect, DeleteEffect::Idle);
        }
    }
}
