//! Pure post-validation decision drivers for the device-pairing ceremonies.
//!
//! The HTTP handlers in `vela-server` perform the effectful steps: the sled
//! invitation-package writes and destructive reads, the enrollment-grant
//! write, the unauthenticated claim write, the grant/claim snapshot read, the
//! single-use `take_live_pair` that linearizes completion, the guarded device
//! `INSERT` and the result record. This module owns every *decision* between
//! those effects:
//!
//! * invitation: whether a store request may write at all, and how a
//!   destructive package read (missing, non-UTF-8, present) is classified;
//! * grant opening: whether the verified open policy permits the write, and how
//!   the write outcome is classified;
//! * claim: whether a live grant may take a claim, the historical rejection
//!   precedence, and how a guarded write outcome is classified;
//! * completion: the opener binding, the epoch/rekey preflight, the verified
//!   completion policy (stored claim, active opener, signature, active epoch),
//!   the single-use take outcome, the guarded insert outcome and the result
//!   record write;
//! * result collection: whether a completed result or a live claim may be
//!   answered, and under which verified signature.
//!
//! The driver is a per-request value: it does not observe the store or the SQL
//! database and does not coordinate concurrent requests. Every input is an
//! observation produced by the handler. The transition relation is total:
//! events that do not match the current ceremony/stage (and every event after
//! `Done`) are ignored, so the unbounded trace induction in
//! `proofs/fstar/pairing-driver-lemmas` is a statement about every event list,
//! not only the handler's intended order.
//!
//! The state records only *decision facts* established by a prior transition.
//! In particular `inserted` means the handler reported at least one inserted
//! row, not that an ambiguous error could not have committed one;
//! `signature_verified` means the hybrid verifier returned `Ok`, not that the
//! cryptography is unforgeable.

use crate::{
    authorize_result, claim_facts, completion_facts, open_facts, plan_claim, plan_completion,
    plan_open, result_facts, ClaimDecision, ClaimKeySource, ClaimObservation,
    CompletionDecision, CompletionObservation, OpenDecision, OpenObservation, ResultDecision,
    ResultKind, ResultObservation, ResultSource, HYBRID_EK_LEN, HYBRID_VK_LEN,
};

// ── Invitation package observations ─────────────────────────────────────────

/// Request-level validation of a package-store request. The handler already
/// parsed the token and the ciphertext; the driver decides whether they permit
/// the write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageStoreObservation {
    pub token_valid: bool,
    /// The ciphertext is between 1 byte and 64 KiB.
    pub ciphertext_len_valid: bool,
}

/// Request-level validation of a package-fetch request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTokenObservation {
    pub token_valid: bool,
}

/// Outcome of a non-destructive store write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreObservation {
    Stored,
    Failed,
}

/// Outcome of the destructive `get_del` package read. `Present` carries only
/// whether the removed bytes were valid UTF-8; the bytes themselves stay in
/// the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedeemObservation {
    /// `get_del` returned nothing: the package is missing, expired or already
    /// redeemed.
    Missing,
    Present { utf8_valid: bool },
}

// ── Grant opening and claim observations ────────────────────────────────────

/// The grant record as read by the completion handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantObservation {
    Absent,
    /// The record decoded; both bindings are observations of the session.
    Present {
        user_matches: bool,
        opener_matches: bool,
    },
    /// The read or decode failed; the handler retains the original error.
    Error,
}

/// Outcome of the unauthenticated guarded claim write
/// (`set_ex_nx_if_live`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimWriteObservation {
    Inserted,
    /// The guard key (the grant) was gone.
    GuardMissing,
    /// A claim record already existed for this grant.
    KeyExists,
}

// ── Completion observations ─────────────────────────────────────────────────

/// What the handler found under the claim key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimMaterialObservation {
    Missing,
    /// The record decoded and both stored public keys decoded.
    Usable,
    /// The record or one of its keys did not decode; the handler retains the
    /// original error.
    Error,
}

/// The opener device row, as seen by `load_primary_key`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenerObservation {
    /// A row exists, is not revoked and its verification key decoded.
    Active,
    /// No row, or a revoked row. Both render the same refusal.
    Inactive,
    /// The query or key decode failed; the handler retains the original error.
    Error,
}

/// The opener's hybrid signature check over the stored claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureObservation {
    Verified,
    /// The verifier rejected the signature; the handler retains the original
    /// (unauthorized/bad-request/internal) error for rendering.
    Failed,
}

/// The handler observations that feed the verified completion policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionPreflightObservation {
    pub claim: ClaimMaterialObservation,
    pub capsule_valid: bool,
    pub signature_field_valid: bool,
    pub opener: OpenerObservation,
    pub signature: SignatureObservation,
    pub account_epoch: i64,
    pub declared_epoch: i64,
    pub rotation_in_progress: bool,
    /// `vela_rekey_policy::authorize_active_mutation` allowed the account.
    pub account_epoch_active: bool,
}

/// The destructive `take_live_pair` outcome. The handler compares the returned
/// bytes with the snapshot it validated; the driver sees only the equality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TakeObservation {
    Missing,
    Taken {
        grant_matches: bool,
        claim_matches: bool,
    },
}

/// Outcome of the guarded device insert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceInsertObservation {
    Inserted,
    /// Zero rows: the `users.key_epoch` / `rekey_state` guard refused it.
    Skipped,
    /// The insert errored. This does not prove nothing committed.
    Failed,
}

// ── Result-collection observations ──────────────────────────────────────────

/// The first read of the result collector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultReadObservation {
    /// A completed result record exists and its stored verification key
    /// decoded.
    Completed {
        claimed_key_len: usize,
        signature_verified: bool,
    },
    Absent,
    /// The record or its key did not decode; the handler retains the error.
    Unreadable,
}

/// The fallback read of the result collector, when no result record exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimReadObservation {
    Claimed {
        claimed_key_len: usize,
        signature_verified: bool,
    },
    Absent,
    Unreadable,
}

// ── The decision state machine ──────────────────────────────────────────────

/// Which ceremony this per-request driver belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingCeremony {
    StorePackage,
    RedeemPackage,
    OpenGrant,
    ClaimGrant,
    CompleteGrant,
    CollectResult,
}

/// Where the ceremony is in its decision sequence. A stage names the effect
/// that has been emitted and whose observation is awaited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingStage {
    /// The begin decision ran and its first effect was emitted. For the
    /// committing ceremonies that effect is the commit (`wrote` is set); for
    /// claim/completion/result it is the check or prepare step.
    Start,
    /// Claim: the verified claim policy authorized the write and `WriteClaim`
    /// was emitted. Completion: the verified completion policy authorized the
    /// take and `TakeCeremony` was emitted.
    Applied,
    /// Completion: the take matched and `InsertDevice` was emitted.
    InFlight,
    /// Completion: the insert reported rows and `WriteResult` was emitted.
    WroteResult,
    /// Result: no result record exists and `ReadClaim` was emitted.
    ResultClaim,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders them; this module never formats a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingFailure {
    // Invitation
    InvalidToken,
    InvalidCiphertext,
    PackageStorage,
    /// The destructive read found nothing: replayed or refused token.
    PackageUnavailable,
    PackageNotUtf8,
    // Grant opening
    OpenPolicy,
    GrantStorage,
    // Claim
    /// No live grant, or the guarded write found the guard gone.
    GrantUnavailable,
    InvalidEkLength,
    InvalidVkLength,
    AlreadyClaimed,
    ClaimNotAuthorized,
    // Completion begin
    /// The stored grant did not decode; the handler retains the error.
    GrantError,
    AccountStorage,
    KeyEpochInvalid,
    RekeyPolicy,
    // Completion preflight
    EpochChanged,
    NoClaim,
    ClaimUnreadable,
    CapsuleInvalid,
    SignatureFieldInvalid,
    OpenerStorage,
    OpenerRevoked,
    SignatureRejected,
    CompletionNotAuthorized,
    // Completion effects
    CeremonyConsumed,
    CeremonyChanged,
    Rotation,
    InsertStorage,
    ResultStorage,
    // Result collection
    ResultUnreadable,
    ClaimRecordUnreadable,
    ResultSignatureRejected,
    ResultNotAuthorized,
}

/// The effect the handler must perform next (`Idle` means "do nothing").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingEffect {
    /// Write the package under its token.
    StorePackage,
    /// Destructively read the package under its token.
    RedeemPackage,
    /// Write the freshly generated enrollment grant.
    StoreGrant,
    /// Read whether a claim record exists (the driver then plans the write).
    CheckClaim,
    /// Perform the guarded single-claim write.
    WriteClaim,
    /// Read the grant, the account row, the claim, the capsule, the opener key
    /// and verify the signature.
    CheckAccount,
    PrepareCompletion,
    /// Perform the single-use `take_live_pair`.
    TakeCeremony,
    /// Perform the guarded device insert.
    InsertDevice,
    /// Write the enrollment result record.
    WriteResult,
    /// Read the result record.
    ReadResult,
    /// Read the claim record after the result was absent.
    ReadClaim,
    /// Terminal success (a stored/redeemed package, an opened grant, a claimed
    /// grant, a completed enrollment).
    Complete,
    /// The collector may answer with this kind.
    ReturnResult(ResultKind),
    /// Terminal failure without restoration.
    Fail(PairingFailure),
    /// Restore the consumed grant+claim, then return the failure.
    RestoreAndFail(PairingFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingDriver {
    pub ceremony: PairingCeremony,
    pub stage: PairingStage,
    /// The begin decision ran and emitted the ceremony's first effect.
    pub authorized: bool,
    /// The ceremony's committing effect was emitted at most once.
    pub wrote: bool,
    /// Completion: the destructive take observed the exact validated pair.
    pub consumed: bool,
    /// Completion: the guarded insert reported at least one row.
    pub inserted: bool,
    /// Completion: the result record write was observed as stored.
    pub recorded: bool,
    /// Completion: the driver instructed a grant+claim restoration.
    pub restored: bool,
    /// A terminal success was authorized.
    pub succeeded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
    /// The grant record existed (completion preflight fact).
    pub grant_present: bool,
    /// The session user id equalled the grant's user id.
    pub user_matches: bool,
    /// The session device id equalled the grant's opener id.
    pub opener_matches: bool,
    /// Completion: a stored claim record was present.
    pub claim_present: bool,
    /// Completion: the opener device row was active.
    pub opener_active: bool,
    /// Completion: the opener's signature verified over the stored claim.
    pub signature_verified: bool,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingEvent {
    PackageWritten(StoreObservation),
    PackageRedeemed(RedeemObservation),
    GrantWritten(StoreObservation),
    ClaimChecked(ClaimObservation),
    ClaimWritten(ClaimWriteObservation),
    /// The account-epoch and rekey preflight for a completion. It is its own
    /// event so the total `step` relation covers every effect the handler
    /// performs, including the one that directly calls
    /// `on_completion_account`.
    AccountChecked(CompletionAccountObservation),
    CompletionReady(CompletionPreflightObservation),
    CeremonyTaken(TakeObservation),
    DeviceInserted(DeviceInsertObservation),
    ResultWritten(StoreObservation),
    ResultRead(ResultReadObservation),
    ClaimRead(ClaimReadObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingTransition {
    pub driver: PairingDriver,
    pub effect: PairingEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn pairing_state_is_sound(d: PairingDriver) -> bool {
    let start_clean =
        !d.consumed && !d.inserted && !d.recorded && !d.restored && !d.succeeded && !d.failed;
    let applied_clean = d.authorized
        && d.wrote
        && !d.consumed
        && !d.inserted
        && !d.recorded
        && !d.restored
        && !d.succeeded
        && !d.failed;
    let inflight_clean = d.authorized
        && d.wrote
        && d.consumed
        && !d.inserted
        && !d.recorded
        && !d.restored
        && !d.succeeded
        && !d.failed;
    let wrote_result_clean = d.authorized
        && d.wrote
        && d.consumed
        && d.inserted
        && !d.recorded
        && !d.restored
        && !d.succeeded
        && !d.failed;
    let result_claim_clean = d.authorized
        && !d.wrote
        && !d.consumed
        && !d.inserted
        && !d.recorded
        && !d.restored
        && !d.succeeded
        && !d.failed;
    let done_clean = (d.succeeded || d.failed)
        && !(d.succeeded && d.failed)
        && (!d.succeeded || (d.authorized && !d.restored))
        && (!d.succeeded || !matches!(d.ceremony, PairingCeremony::CompleteGrant)
            || (d.consumed && d.inserted && d.recorded))
        && (!d.succeeded
            || matches!(d.ceremony, PairingCeremony::CompleteGrant)
            || matches!(d.ceremony, PairingCeremony::CollectResult)
            || d.wrote)
        && (!d.restored
            || (d.failed && matches!(d.ceremony, PairingCeremony::CompleteGrant) && !d.inserted));
    (!matches!(d.stage, PairingStage::Start) || start_clean)
        && (!matches!(d.stage, PairingStage::Applied) || applied_clean)
        && (!matches!(d.stage, PairingStage::InFlight) || inflight_clean)
        && (!matches!(d.stage, PairingStage::WroteResult) || wrote_result_clean)
        && (!matches!(d.stage, PairingStage::ResultClaim) || result_claim_clean)
        && (!matches!(d.stage, PairingStage::Done) || done_clean)
        // Stage/ceremony discipline: only the ceremonies that have those
        // milestones may reach those stages.
        && (!matches!(d.stage, PairingStage::InFlight | PairingStage::WroteResult)
            || matches!(d.ceremony, PairingCeremony::CompleteGrant))
        && (!matches!(d.stage, PairingStage::ResultClaim)
            || matches!(d.ceremony, PairingCeremony::CollectResult))
        && (!matches!(d.stage, PairingStage::Applied)
            || matches!(d.ceremony, PairingCeremony::ClaimGrant)
            || matches!(d.ceremony, PairingCeremony::CompleteGrant))
        // Flags are established in one direction only.
        && (!d.consumed || (d.wrote && matches!(d.ceremony, PairingCeremony::CompleteGrant)))
        && (!d.inserted || d.consumed)
        && (!d.recorded || d.inserted)
        && (!d.recorded || matches!(d.stage, PairingStage::Done))
        && (!d.wrote || !matches!(d.ceremony, PairingCeremony::CollectResult))
        && (!d.grant_present || matches!(d.ceremony, PairingCeremony::CompleteGrant))
        && (!d.user_matches || d.grant_present)
        && (!d.opener_matches || d.grant_present)
        && (!d.claim_present || matches!(d.ceremony, PairingCeremony::CompleteGrant))
        && (!d.opener_active || matches!(d.ceremony, PairingCeremony::CompleteGrant))
        && (!d.signature_verified || matches!(d.ceremony, PairingCeremony::CompleteGrant))
        // An enrolled device was behind a present claim, a live opener and a
        // signature the verified policy accepted.
        && (!d.inserted
            || (d.grant_present
                && d.claim_present
                && d.opener_active
                && d.signature_verified
                && d.user_matches
                && d.opener_matches))
        // A completion that has authorized the take already holds every fact
        // the verified policy was asked about.
        && (!matches!(d.stage, PairingStage::Applied)
            || !matches!(d.ceremony, PairingCeremony::CompleteGrant)
            || (d.grant_present
                && d.claim_present
                && d.opener_active
                && d.signature_verified
                && d.user_matches
                && d.opener_matches))
        // Reaching the destructive take means every completion fact is
        // established; no later transition clears them.
        && (!matches!(
            d.stage,
            PairingStage::InFlight | PairingStage::WroteResult
        ) || (d.grant_present
            && d.claim_present
            && d.opener_active
            && d.signature_verified
            && d.user_matches
            && d.opener_matches))
        // A driver that is still waiting for its first observation has run its
        // begin decision (only a terminal failure can leave `Start` unauthorised).
        && (!matches!(d.stage, PairingStage::Start) || d.authorized)
}

/// Every effect the driver emits agrees with the state it produces.
pub fn pairing_effect_is_sound(d: PairingDriver, effect: PairingEffect) -> bool {
    match effect {
        PairingEffect::StorePackage => {
            matches!(d.ceremony, PairingCeremony::StorePackage)
                && matches!(d.stage, PairingStage::Start)
                && d.authorized
                && d.wrote
        }
        PairingEffect::RedeemPackage => {
            matches!(d.ceremony, PairingCeremony::RedeemPackage)
                && matches!(d.stage, PairingStage::Start)
                && d.authorized
                && d.wrote
        }
        PairingEffect::StoreGrant => {
            matches!(d.ceremony, PairingCeremony::OpenGrant)
                && matches!(d.stage, PairingStage::Start)
                && d.authorized
                && d.wrote
        }
        PairingEffect::CheckClaim => {
            matches!(d.ceremony, PairingCeremony::ClaimGrant)
                && matches!(d.stage, PairingStage::Start)
                && d.authorized
                && !d.wrote
        }
        PairingEffect::WriteClaim => {
            matches!(d.ceremony, PairingCeremony::ClaimGrant)
                && matches!(d.stage, PairingStage::Applied)
                && d.authorized
                && d.wrote
        }
        PairingEffect::CheckAccount => {
            matches!(d.ceremony, PairingCeremony::CompleteGrant)
                && matches!(d.stage, PairingStage::Start)
                && d.authorized
                && !d.wrote
        }
        PairingEffect::PrepareCompletion => {
            matches!(d.ceremony, PairingCeremony::CompleteGrant)
                && matches!(d.stage, PairingStage::Start)
                && d.authorized
                && !d.wrote
        }
        PairingEffect::TakeCeremony => {
            matches!(d.ceremony, PairingCeremony::CompleteGrant)
                && matches!(d.stage, PairingStage::Applied)
                && d.authorized
                && d.wrote
                && !d.consumed
        }
        PairingEffect::InsertDevice => {
            matches!(d.ceremony, PairingCeremony::CompleteGrant)
                && matches!(d.stage, PairingStage::InFlight)
                && d.authorized
                && d.wrote
                && d.consumed
                && !d.inserted
                && !d.recorded
                && !d.restored
        }
        PairingEffect::WriteResult => {
            matches!(d.ceremony, PairingCeremony::CompleteGrant)
                && matches!(d.stage, PairingStage::WroteResult)
                && d.consumed
                && d.inserted
                && !d.recorded
                && !d.restored
        }
        PairingEffect::ReadResult => {
            matches!(d.ceremony, PairingCeremony::CollectResult)
                && matches!(d.stage, PairingStage::Start)
                && d.authorized
                && !d.wrote
        }
        PairingEffect::ReadClaim => {
            matches!(d.ceremony, PairingCeremony::CollectResult)
                && matches!(d.stage, PairingStage::ResultClaim)
                && d.authorized
                && !d.wrote
        }
        PairingEffect::Complete => {
            matches!(d.stage, PairingStage::Done)
                && d.succeeded
                && !d.failed
                && !matches!(d.ceremony, PairingCeremony::CollectResult)
        }
        PairingEffect::ReturnResult(_) => {
            matches!(d.stage, PairingStage::Done)
                && d.succeeded
                && !d.failed
                && matches!(d.ceremony, PairingCeremony::CollectResult)
        }
        PairingEffect::Fail(_) => {
            matches!(d.stage, PairingStage::Done) && d.failed && !d.succeeded && !d.restored
        }
        PairingEffect::RestoreAndFail(_) => {
            matches!(d.stage, PairingStage::Done) && d.failed && d.restored && !d.succeeded
        }
        PairingEffect::Idle => true,
    }
}

fn fresh_driver(ceremony: PairingCeremony) -> PairingDriver {
    PairingDriver {
        ceremony,
        stage: PairingStage::Start,
        authorized: false,
        wrote: false,
        consumed: false,
        inserted: false,
        recorded: false,
        restored: false,
        succeeded: false,
        failed: false,
        grant_present: false,
        user_matches: false,
        opener_matches: false,
        claim_present: false,
        opener_active: false,
        signature_verified: false,
    }
}

fn transition(d: PairingDriver, effect: PairingEffect) -> PairingTransition {
    PairingTransition {
        driver: d,
        effect,
    }
}

fn idle(d: PairingDriver) -> PairingTransition {
    transition(d, PairingEffect::Idle)
}

fn terminal(d: PairingDriver, failure: PairingFailure) -> PairingTransition {
    transition(
        PairingDriver {
            stage: PairingStage::Done,
            failed: true,
            ..d
        },
        PairingEffect::Fail(failure),
    )
}

fn restore_then_fail(d: PairingDriver, failure: PairingFailure) -> PairingTransition {
    transition(
        PairingDriver {
            stage: PairingStage::Done,
            failed: true,
            restored: true,
            ..d
        },
        PairingEffect::RestoreAndFail(failure),
    )
}

fn complete(d: PairingDriver) -> PairingTransition {
    transition(
        PairingDriver {
            stage: PairingStage::Done,
            succeeded: true,
            recorded: matches!(d.ceremony, PairingCeremony::CompleteGrant),
            ..d
        },
        PairingEffect::Complete,
    )
}

fn complete_result(d: PairingDriver, kind: ResultKind) -> PairingTransition {
    transition(
        PairingDriver {
            stage: PairingStage::Done,
            succeeded: true,
            ..d
        },
        PairingEffect::ReturnResult(kind),
    )
}

// ── Invitation package ──────────────────────────────────────────────────────

/// Start a package-store request. An invalid token or ciphertext length is
/// terminal and performs no store effect.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_state_is_sound(result.driver)
        && pairing_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_store_package(observation: PackageStoreObservation) -> PairingTransition {
    if !observation.token_valid {
        terminal(fresh_driver(PairingCeremony::StorePackage), PairingFailure::InvalidToken)
    } else if !observation.ciphertext_len_valid {
        terminal(
            fresh_driver(PairingCeremony::StorePackage),
            PairingFailure::InvalidCiphertext,
        )
    } else {
        transition(
            PairingDriver {
                authorized: true,
                wrote: true,
                ..fresh_driver(PairingCeremony::StorePackage)
            },
            PairingEffect::StorePackage,
        )
    }
}

/// Start a package-fetch request. An invalid token is terminal and performs no
/// destructive read.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_state_is_sound(result.driver)
        && pairing_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_redeem_package(observation: PackageTokenObservation) -> PairingTransition {
    if !observation.token_valid {
        terminal(
            fresh_driver(PairingCeremony::RedeemPackage),
            PairingFailure::InvalidToken,
        )
    } else {
        transition(
            PairingDriver {
                authorized: true,
                wrote: true,
                ..fresh_driver(PairingCeremony::RedeemPackage)
            },
            PairingEffect::RedeemPackage,
        )
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Start) && d.wrote && matches!(d.ceremony, PairingCeremony::StorePackage)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_package_written(d: PairingDriver, observation: StoreObservation) -> PairingTransition {
    match observation {
        StoreObservation::Stored => complete(d),
        StoreObservation::Failed => terminal(d, PairingFailure::PackageStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Start) && d.wrote && matches!(d.ceremony, PairingCeremony::RedeemPackage)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_package_redeemed(d: PairingDriver, observation: RedeemObservation) -> PairingTransition {
    match observation {
        // A replayed or refused token observes nothing. It is terminal and
        // must never hand the caller a package.
        RedeemObservation::Missing => terminal(d, PairingFailure::PackageUnavailable),
        RedeemObservation::Present { utf8_valid } => {
            if utf8_valid {
                complete(d)
            } else {
                terminal(d, PairingFailure::PackageNotUtf8)
            }
        }
    }
}

// ── Grant opening ───────────────────────────────────────────────────────────

/// Start a grant-open request after the verified open policy was asked. The
/// handler passes the real session observations.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_state_is_sound(result.driver)
        && pairing_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_open_grant(observation: OpenObservation) -> PairingTransition {
    match plan_open(open_facts(observation)) {
        OpenDecision::Open(_permit) => transition(
            PairingDriver {
                authorized: true,
                wrote: true,
                ..fresh_driver(PairingCeremony::OpenGrant)
            },
            PairingEffect::StoreGrant,
        ),
        OpenDecision::Reject => terminal(fresh_driver(PairingCeremony::OpenGrant), PairingFailure::OpenPolicy),
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Start) && d.wrote && matches!(d.ceremony, PairingCeremony::OpenGrant)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_grant_written(d: PairingDriver, observation: StoreObservation) -> PairingTransition {
    match observation {
        StoreObservation::Stored => complete(d),
        StoreObservation::Failed => terminal(d, PairingFailure::GrantStorage),
    }
}

// ── Claim ───────────────────────────────────────────────────────────────────

/// Begin the claim request with the only observation the handler reads before
/// decoding the body: whether the grant key is live.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_state_is_sound(result.driver)
        && pairing_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_claim(grant_live: bool) -> PairingTransition {
    if !grant_live {
        terminal(
            fresh_driver(PairingCeremony::ClaimGrant),
            PairingFailure::GrantUnavailable,
        )
    } else {
        transition(
            PairingDriver {
                authorized: true,
                ..fresh_driver(PairingCeremony::ClaimGrant)
            },
            PairingEffect::CheckClaim,
        )
    }
}

/// The handler's historical rejection precedence, kept in one place. It is
/// only consulted when the verified `plan_claim` refused, so at least one
/// guard is false.
fn claim_rejection(observation: ClaimObservation) -> PairingFailure {
    if observation.hybrid_ek_len != HYBRID_EK_LEN {
        PairingFailure::InvalidEkLength
    } else if observation.hybrid_vk_len != HYBRID_VK_LEN {
        PairingFailure::InvalidVkLength
    } else if observation.claim_exists {
        PairingFailure::AlreadyClaimed
    } else if !observation.grant_live {
        PairingFailure::GrantUnavailable
    } else {
        PairingFailure::ClaimNotAuthorized
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Start) && !d.wrote && matches!(d.ceremony, PairingCeremony::ClaimGrant)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_claim_checked(d: PairingDriver, observation: ClaimObservation) -> PairingTransition {
    match plan_claim(claim_facts(observation)) {
        ClaimDecision::Claim(_permit) => transition(
            PairingDriver {
                stage: PairingStage::Applied,
                wrote: true,
                ..d
            },
            PairingEffect::WriteClaim,
        ),
        ClaimDecision::Reject => terminal(d, claim_rejection(observation)),
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Applied) && matches!(d.ceremony, PairingCeremony::ClaimGrant)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_claim_written(d: PairingDriver, observation: ClaimWriteObservation) -> PairingTransition {
    match observation {
        ClaimWriteObservation::Inserted => complete(d),
        ClaimWriteObservation::GuardMissing => terminal(d, PairingFailure::GrantUnavailable),
        ClaimWriteObservation::KeyExists => terminal(d, PairingFailure::AlreadyClaimed),
    }
}

// ── Completion ──────────────────────────────────────────────────────────────

/// The account observations the completion handler makes after the grant
/// binding passed: the `users` row query, the declared epoch and the rekey
/// permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionAccountObservation {
    pub account_query_ok: bool,
    pub declared_epoch_positive: bool,
    pub rekey_permitted: bool,
}

/// Start a completion request. Only a grant bound to this user *and* this
/// device may continue; the handler then reads the account row.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_state_is_sound(result.driver)
        && pairing_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_completion(grant: GrantObservation) -> PairingTransition {
    let base = fresh_driver(PairingCeremony::CompleteGrant);
    match grant {
        GrantObservation::Absent => terminal(base, PairingFailure::GrantUnavailable),
        GrantObservation::Error => terminal(base, PairingFailure::GrantError),
        GrantObservation::Present {
            user_matches,
            opener_matches,
        } => {
            if !user_matches || !opener_matches {
                terminal(base, PairingFailure::GrantUnavailable)
            } else {
                transition(
                    PairingDriver {
                        authorized: true,
                        grant_present: true,
                        user_matches,
                        opener_matches,
                        ..base
                    },
                    PairingEffect::CheckAccount,
                )
            }
        }
    }
}

/// Apply the account-epoch and rekey preflight. The order is the handler's
/// historical status order: query failure, then a non-positive declared
/// epoch, then the rekey permit.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_completion_account(
    driver: PairingDriver,
    observation: CompletionAccountObservation,
) -> PairingTransition {
    if !matches!(driver.ceremony, PairingCeremony::CompleteGrant)
        || !stage_start(driver)
        || driver.wrote
    {
        return idle(driver);
    }
    if !observation.account_query_ok {
        terminal(driver, PairingFailure::AccountStorage)
    } else if !observation.declared_epoch_positive {
        terminal(driver, PairingFailure::KeyEpochInvalid)
    } else if !observation.rekey_permitted {
        terminal(driver, PairingFailure::RekeyPolicy)
    } else {
        transition(driver, PairingEffect::PrepareCompletion)
    }
}

/// Apply the verified completion policy to the real preflight observations.
/// A permit is the only way to reach the destructive take, and the historical
/// failure precedence is applied only after the policy refused.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Start) && !d.wrote && matches!(d.ceremony, PairingCeremony::CompleteGrant)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_completion_ready(
    d: PairingDriver,
    observation: CompletionPreflightObservation,
) -> PairingTransition {
    let claim_present = !matches!(observation.claim, ClaimMaterialObservation::Missing);
    let opener_active = matches!(observation.opener, OpenerObservation::Active);
    let signature_verified = matches!(observation.signature, SignatureObservation::Verified);
    let facts = completion_facts(CompletionObservation {
        claim_present,
        user_matches: d.user_matches,
        opener_matches: d.opener_matches,
        opener_active,
        signature_verified,
        // The handler verifies and enrolls only the immutable stored claim.
        claim_key_source: ClaimKeySource::StoredClaim,
        account_epoch: observation.account_epoch,
        declared_epoch: observation.declared_epoch,
        rotation_in_progress: observation.rotation_in_progress,
    });
    match plan_completion(facts) {
        CompletionDecision::Complete(_permit) => transition(
            PairingDriver {
                stage: PairingStage::Applied,
                wrote: true,
                claim_present,
                opener_active,
                signature_verified,
                ..d
            },
            PairingEffect::TakeCeremony,
        ),
        CompletionDecision::Reject => {
            let failure = if !observation.account_epoch_active {
                PairingFailure::EpochChanged
            } else if !claim_present {
                PairingFailure::NoClaim
            } else if matches!(observation.claim, ClaimMaterialObservation::Error) {
                PairingFailure::ClaimUnreadable
            } else if !observation.capsule_valid {
                PairingFailure::CapsuleInvalid
            } else if !observation.signature_field_valid {
                PairingFailure::SignatureFieldInvalid
            } else if matches!(observation.opener, OpenerObservation::Error) {
                PairingFailure::OpenerStorage
            } else if !opener_active {
                PairingFailure::OpenerRevoked
            } else if !signature_verified {
                PairingFailure::SignatureRejected
            } else {
                PairingFailure::CompletionNotAuthorized
            };
            terminal(d, failure)
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Applied) && matches!(d.ceremony, PairingCeremony::CompleteGrant)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_ceremony_taken(d: PairingDriver, observation: TakeObservation) -> PairingTransition {
    match observation {
        TakeObservation::Missing => terminal(d, PairingFailure::CeremonyConsumed),
        TakeObservation::Taken {
            grant_matches,
            claim_matches,
        } => {
            if grant_matches && claim_matches {
                transition(
                    PairingDriver {
                        stage: PairingStage::InFlight,
                        consumed: true,
                        ..d
                    },
                    PairingEffect::InsertDevice,
                )
            } else {
                // The pair changed between validation and consumption. Put it
                // back so the ceremony can be retried, exactly as the handler
                // does.
                restore_then_fail(d, PairingFailure::CeremonyChanged)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::InFlight)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_device_inserted(d: PairingDriver, observation: DeviceInsertObservation) -> PairingTransition {
    match observation {
        DeviceInsertObservation::Inserted => transition(
            PairingDriver {
                stage: PairingStage::WroteResult,
                inserted: true,
                ..d
            },
            PairingEffect::WriteResult,
        ),
        // A rotation may have started after the fast check. Restore the exact
        // consumed pair so the confirmed pairing can be retried.
        DeviceInsertObservation::Skipped => restore_then_fail(d, PairingFailure::Rotation),
        // An INSERT error is ambiguous: the row may have committed before the
        // error surfaced. Restoring the grant and claim would let a second
        // request enroll another device with them, so the failure is terminal.
        DeviceInsertObservation::Failed => terminal(d, PairingFailure::InsertStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::WroteResult)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_result_written(d: PairingDriver, observation: StoreObservation) -> PairingTransition {
    match observation {
        StoreObservation::Stored => complete(d),
        // The row is already enrolled; only the collector's answer is lost.
        // No restoration: the grant and claim are legitimately consumed.
        StoreObservation::Failed => terminal(d, PairingFailure::ResultStorage),
    }
}

// ── Result collection ───────────────────────────────────────────────────────

/// Start a result-collection request. The first effect is the result read.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_state_is_sound(result.driver)
        && pairing_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_result() -> PairingTransition {
    transition(
        PairingDriver {
            authorized: true,
            ..fresh_driver(PairingCeremony::CollectResult)
        },
        PairingEffect::ReadResult,
    )
}

fn result_failure(signature_verified: bool) -> PairingFailure {
    if !signature_verified {
        PairingFailure::ResultSignatureRejected
    } else {
        PairingFailure::ResultNotAuthorized
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::Start) && !d.wrote && matches!(d.ceremony, PairingCeremony::CollectResult)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_result_read(d: PairingDriver, observation: ResultReadObservation) -> PairingTransition {
    match observation {
        ResultReadObservation::Completed {
            claimed_key_len,
            signature_verified,
        } => match authorize_result(result_facts(ResultObservation {
            source: ResultSource::CompletedResult,
            claimed_key_len,
            signature_verified,
        })) {
            ResultDecision::Return(permit) => complete_result(d, permit.kind()),
            ResultDecision::Reject => terminal(d, result_failure(signature_verified)),
        },
        ResultReadObservation::Absent => transition(
            PairingDriver {
                stage: PairingStage::ResultClaim,
                ..d
            },
            PairingEffect::ReadClaim,
        ),
        ResultReadObservation::Unreadable => terminal(d, PairingFailure::ResultUnreadable),
    }
}

#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(d) && matches!(d.stage, PairingStage::ResultClaim) && matches!(d.ceremony, PairingCeremony::CollectResult)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(d) || pairing_state_is_sound(result.driver))
}))]
fn on_claim_read(d: PairingDriver, observation: ClaimReadObservation) -> PairingTransition {
    match observation {
        ClaimReadObservation::Claimed {
            claimed_key_len,
            signature_verified,
        } => match authorize_result(result_facts(ResultObservation {
            source: ResultSource::ClaimedClaim,
            claimed_key_len,
            signature_verified,
        })) {
            ResultDecision::Return(permit) => complete_result(d, permit.kind()),
            ResultDecision::Reject => terminal(d, result_failure(signature_verified)),
        },
        ClaimReadObservation::Absent => terminal(d, PairingFailure::GrantUnavailable),
        ClaimReadObservation::Unreadable => terminal(d, PairingFailure::ClaimRecordUnreadable),
    }
}

// ── The total transition relation ───────────────────────────────────────────

fn stage_start(d: PairingDriver) -> bool {
    matches!(d.stage, PairingStage::Start)
}

/// The complete, total transition relation. Events that do not match the
/// current ceremony and stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn step(driver: PairingDriver, event: PairingEvent) -> PairingTransition {
    match event {
        PairingEvent::PackageWritten(observation) => {
            if stage_start(driver) && driver.wrote && matches!(
                driver.ceremony,
                PairingCeremony::StorePackage
            ) {
                on_package_written(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::PackageRedeemed(observation) => {
            if stage_start(driver) && driver.wrote && matches!(
                driver.ceremony,
                PairingCeremony::RedeemPackage
            ) {
                on_package_redeemed(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::GrantWritten(observation) => {
            if stage_start(driver)
                && driver.wrote
                && matches!(driver.ceremony, PairingCeremony::OpenGrant)
            {
                on_grant_written(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::ClaimChecked(observation) => {
            if stage_start(driver)
                && !driver.wrote
                && matches!(driver.ceremony, PairingCeremony::ClaimGrant)
            {
                on_claim_checked(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::ClaimWritten(observation) => {
            if matches!(driver.stage, PairingStage::Applied)
                && matches!(driver.ceremony, PairingCeremony::ClaimGrant)
            {
                on_claim_written(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::AccountChecked(observation) => {
            on_completion_account(driver, observation)
        }
        PairingEvent::CompletionReady(observation) => {
            if stage_start(driver)
                && !driver.wrote
                && matches!(driver.ceremony, PairingCeremony::CompleteGrant)
            {
                on_completion_ready(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::CeremonyTaken(observation) => {
            if matches!(driver.stage, PairingStage::Applied)
                && matches!(driver.ceremony, PairingCeremony::CompleteGrant)
            {
                on_ceremony_taken(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::DeviceInserted(observation) => {
            if matches!(driver.stage, PairingStage::InFlight) {
                on_device_inserted(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::ResultWritten(observation) => {
            if matches!(driver.stage, PairingStage::WroteResult) {
                on_result_written(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::ResultRead(observation) => {
            if stage_start(driver)
                && !driver.wrote
                && matches!(driver.ceremony, PairingCeremony::CollectResult)
            {
                on_result_read(driver, observation)
            } else {
                idle(driver)
            }
        }
        PairingEvent::ClaimRead(observation) => {
            if matches!(driver.stage, PairingStage::ResultClaim)
                && matches!(driver.ceremony, PairingCeremony::CollectResult)
            {
                on_claim_read(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

// ── Per-effect wrappers for the evidence log and the proofs ─────────────────

/// Total wrapper: the handler feeds the store/redeem outcome.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_package_written_event(
    driver: PairingDriver,
    observation: StoreObservation,
) -> PairingTransition {
    step(driver, PairingEvent::PackageWritten(observation))
}

/// Total wrapper: the handler feeds the destructive package read.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_package_redeemed_event(
    driver: PairingDriver,
    observation: RedeemObservation,
) -> PairingTransition {
    step(driver, PairingEvent::PackageRedeemed(observation))
}

/// Total wrapper: the handler feeds the grant write outcome.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_grant_written_event(
    driver: PairingDriver,
    observation: StoreObservation,
) -> PairingTransition {
    step(driver, PairingEvent::GrantWritten(observation))
}

/// Total wrapper: the handler feeds the claim plan.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_claim_checked_event(
    driver: PairingDriver,
    observation: ClaimObservation,
) -> PairingTransition {
    step(driver, PairingEvent::ClaimChecked(observation))
}

/// Total wrapper: the handler feeds the guarded claim write outcome.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_claim_written_event(
    driver: PairingDriver,
    observation: ClaimWriteObservation,
) -> PairingTransition {
    step(driver, PairingEvent::ClaimWritten(observation))
}

/// Total wrapper: the handler feeds the verified completion preflight.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_completion_ready_event(
    driver: PairingDriver,
    observation: CompletionPreflightObservation,
) -> PairingTransition {
    step(driver, PairingEvent::CompletionReady(observation))
}

/// Total wrapper: the handler feeds the single-use take outcome.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_ceremony_taken_event(
    driver: PairingDriver,
    observation: TakeObservation,
) -> PairingTransition {
    step(driver, PairingEvent::CeremonyTaken(observation))
}

/// Total wrapper: the handler feeds the guarded insert outcome.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_device_inserted_event(
    driver: PairingDriver,
    observation: DeviceInsertObservation,
) -> PairingTransition {
    step(driver, PairingEvent::DeviceInserted(observation))
}

/// Total wrapper: the handler feeds the result-record write outcome.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_result_written_event(
    driver: PairingDriver,
    observation: StoreObservation,
) -> PairingTransition {
    step(driver, PairingEvent::ResultWritten(observation))
}

/// Total wrapper: the handler feeds the result read.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_result_read_event(
    driver: PairingDriver,
    observation: ResultReadObservation,
) -> PairingTransition {
    step(driver, PairingEvent::ResultRead(observation))
}

/// Total wrapper: the handler feeds the claim read that follows an absent
/// result record.
#[cfg_attr(hax, hax_lib::requires(pairing_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    pairing_effect_is_sound(result.driver, result.effect)
        && (!pairing_state_is_sound(driver) || pairing_state_is_sound(result.driver))
}))]
pub fn on_claim_read_event(
    driver: PairingDriver,
    observation: ClaimReadObservation,
) -> PairingTransition {
    step(driver, PairingEvent::ClaimRead(observation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events() -> Vec<PairingEvent> {
        let mut out = Vec::new();
        for observation in [StoreObservation::Stored, StoreObservation::Failed] {
            out.push(PairingEvent::PackageWritten(observation));
            out.push(PairingEvent::GrantWritten(observation));
            out.push(PairingEvent::ResultWritten(observation));
        }
        for observation in [
            RedeemObservation::Missing,
            RedeemObservation::Present { utf8_valid: true },
            RedeemObservation::Present { utf8_valid: false },
        ] {
            out.push(PairingEvent::PackageRedeemed(observation));
        }
        for claim_exists in [false, true] {
            for ek_len in [HYBRID_EK_LEN, 0] {
                for vk_len in [HYBRID_VK_LEN, 0] {
                    out.push(PairingEvent::ClaimChecked(ClaimObservation {
                        grant_live: true,
                        claim_exists,
                        hybrid_ek_len: ek_len,
                        hybrid_vk_len: vk_len,
                    }));
                }
            }
        }
        for observation in [
            ClaimWriteObservation::Inserted,
            ClaimWriteObservation::GuardMissing,
            ClaimWriteObservation::KeyExists,
        ] {
            out.push(PairingEvent::ClaimWritten(observation));
        }
        for observation in [
            CompletionAccountObservation {
                account_query_ok: true,
                declared_epoch_positive: true,
                rekey_permitted: true,
            },
            CompletionAccountObservation {
                account_query_ok: false,
                declared_epoch_positive: true,
                rekey_permitted: true,
            },
            CompletionAccountObservation {
                account_query_ok: true,
                declared_epoch_positive: false,
                rekey_permitted: true,
            },
            CompletionAccountObservation {
                account_query_ok: true,
                declared_epoch_positive: true,
                rekey_permitted: false,
            },
        ] {
            out.push(PairingEvent::AccountChecked(observation));
        }
        for observation in [TakeObservation::Missing, TakeObservation::Taken {
            grant_matches: true,
            claim_matches: true,
        }, TakeObservation::Taken {
            grant_matches: true,
            claim_matches: false,
        }] {
            out.push(PairingEvent::CeremonyTaken(observation));
        }
        for observation in [
            DeviceInsertObservation::Inserted,
            DeviceInsertObservation::Skipped,
            DeviceInsertObservation::Failed,
        ] {
            out.push(PairingEvent::DeviceInserted(observation));
        }
        for observation in [
            ResultReadObservation::Completed {
                claimed_key_len: HYBRID_VK_LEN,
                signature_verified: true,
            },
            ResultReadObservation::Completed {
                claimed_key_len: HYBRID_VK_LEN,
                signature_verified: false,
            },
            ResultReadObservation::Absent,
            ResultReadObservation::Unreadable,
        ] {
            out.push(PairingEvent::ResultRead(observation));
        }
        for observation in [
            ClaimReadObservation::Claimed {
                claimed_key_len: HYBRID_VK_LEN,
                signature_verified: true,
            },
            ClaimReadObservation::Claimed {
                claimed_key_len: HYBRID_VK_LEN,
                signature_verified: false,
            },
            ClaimReadObservation::Absent,
            ClaimReadObservation::Unreadable,
        ] {
            out.push(PairingEvent::ClaimRead(observation));
        }
        out
    }

    fn preflight() -> CompletionPreflightObservation {
        CompletionPreflightObservation {
            claim: ClaimMaterialObservation::Usable,
            capsule_valid: true,
            signature_field_valid: true,
            opener: OpenerObservation::Active,
            signature: SignatureObservation::Verified,
            account_epoch: 3,
            declared_epoch: 3,
            rotation_in_progress: false,
            account_epoch_active: true,
        }
    }

    fn sound_states() -> Vec<PairingDriver> {
        let mut states = Vec::new();
        states.push(begin_store_package(PackageStoreObservation {
            token_valid: true,
            ciphertext_len_valid: true,
        })
        .driver);
        states.push(begin_redeem_package(PackageTokenObservation { token_valid: true }).driver);
        states.push(
            begin_open_grant(OpenObservation {
                scope_is_device: true,
                user_id_present: true,
                device_id_present: true,
                ttl_secs: 300,
            })
            .driver,
        );
        states.push(begin_claim(true).driver);
        let claim_written = on_claim_checked(
            begin_claim(true).driver,
            ClaimObservation {
                grant_live: true,
                claim_exists: false,
                hybrid_ek_len: HYBRID_EK_LEN,
                hybrid_vk_len: HYBRID_VK_LEN,
            },
        );
        assert!(matches!(claim_written.effect, PairingEffect::WriteClaim));
        states.push(claim_written.driver);
        let begin = completion_start();
        assert!(matches!(begin.effect, PairingEffect::PrepareCompletion));
        states.push(begin.driver);
        let take = on_completion_ready(begin.driver, preflight());
        assert!(matches!(take.effect, PairingEffect::TakeCeremony));
        states.push(take.driver);
        let insert = on_ceremony_taken(
            take.driver,
            TakeObservation::Taken {
                grant_matches: true,
                claim_matches: true,
            },
        );
        assert!(matches!(insert.effect, PairingEffect::InsertDevice));
        states.push(insert.driver);
        let record = on_device_inserted(insert.driver, DeviceInsertObservation::Inserted);
        assert!(matches!(record.effect, PairingEffect::WriteResult));
        states.push(record.driver);
        states.push(begin_result().driver);
        let result_claim = on_result_read(begin_result().driver, ResultReadObservation::Absent);
        assert!(matches!(result_claim.effect, PairingEffect::ReadClaim));
        states.push(result_claim.driver);
        states
    }

    #[test]
    fn every_sound_state_times_event_is_total_and_sound() {
        for state in sound_states() {
            assert!(pairing_state_is_sound(state), "unsound sample: {state:?}");
            for event in events() {
                let t = step(state, event);
                assert!(
                    pairing_state_is_sound(t.driver),
                    "soundness lost from {state:?} on {event:?}"
                );
                assert!(
                    pairing_effect_is_sound(t.driver, t.effect),
                    "effect soundness lost from {state:?} on {event:?}: {t:?}"
                );
            }
        }
    }

    #[test]
    fn bfs_reachable_states_preserve_the_invariant() {
        use std::collections::BTreeSet;
        let mut frontier = sound_states();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for state in &frontier {
            seen.insert(format!("{state:?}"));
        }
        for _ in 0..8 {
            let mut next = Vec::new();
            for state in frontier {
                for event in events() {
                    let t = step(state, event);
                    assert!(pairing_state_is_sound(t.driver));
                    assert!(pairing_effect_is_sound(t.driver, t.effect));
                    if seen.insert(format!("{:?}", t.driver)) {
                        next.push(t.driver);
                    }
                }
            }
            frontier = next;
        }
    }

    fn completion_start() -> PairingTransition {
        let begin = begin_completion(GrantObservation::Present {
            user_matches: true,
            opener_matches: true,
        });
        assert!(matches!(begin.effect, PairingEffect::CheckAccount));
        let account = on_completion_account(
            begin.driver,
            CompletionAccountObservation {
                account_query_ok: true,
                declared_epoch_positive: true,
                rekey_permitted: true,
            },
        );
        assert!(matches!(account.effect, PairingEffect::PrepareCompletion));
        account
    }

    fn completion_begin() -> PairingTransition {
        completion_start()
    }

    fn drive_completion(observations: &[PairingEvent]) -> PairingTransition {
        let mut transition = completion_begin();
        for event in observations {
            transition = step(transition.driver, *event);
        }
        transition
    }

    #[test]
    fn a_completion_is_signed_bound_and_taken_once() {
        let t = drive_completion(&[
            PairingEvent::CompletionReady(preflight()),
            PairingEvent::CeremonyTaken(TakeObservation::Taken {
                grant_matches: true,
                claim_matches: true,
            }),
            PairingEvent::DeviceInserted(DeviceInsertObservation::Inserted),
            PairingEvent::ResultWritten(StoreObservation::Stored),
        ]);
        assert!(matches!(t.effect, PairingEffect::Complete));
        assert!(t.driver.succeeded && t.driver.inserted && t.driver.recorded);
        assert!(t.driver.signature_verified && t.driver.claim_present);

        // Replay: the same event list has no further effect.
        let t2 = step(t.driver, PairingEvent::CeremonyTaken(TakeObservation::Missing));
        assert!(matches!(t2.effect, PairingEffect::Idle));
        assert_eq!(t2.driver, t.driver);
    }

    #[test]
    fn a_completion_needs_the_stored_claim_and_the_opener_signature() {
        for mutation in [
            CompletionPreflightObservation {
                claim: ClaimMaterialObservation::Missing,
                ..preflight()
            },
            CompletionPreflightObservation {
                signature: SignatureObservation::Failed,
                ..preflight()
            },
            CompletionPreflightObservation {
                opener: OpenerObservation::Inactive,
                ..preflight()
            },
            CompletionPreflightObservation {
                declared_epoch: 2,
                ..preflight()
            },
            CompletionPreflightObservation {
                rotation_in_progress: true,
                ..preflight()
            },
        ] {
            let t = on_completion_ready(completion_begin().driver, mutation);
            assert!(!matches!(t.effect, PairingEffect::TakeCeremony));
            assert!(t.driver.failed && !t.driver.wrote);
        }
    }

    #[test]
    fn a_take_mismatch_restores_and_never_inserts() {
        let take = on_completion_ready(completion_begin().driver, preflight());
        let t = on_ceremony_taken(
            take.driver,
            TakeObservation::Taken {
                grant_matches: true,
                claim_matches: false,
            },
        );
        assert!(matches!(
            t.effect,
            PairingEffect::RestoreAndFail(PairingFailure::CeremonyChanged)
        ));
        assert!(t.driver.restored && !t.driver.inserted);
    }

    #[test]
    fn an_insert_failure_never_claims_a_recorded_result() {
        let take = on_completion_ready(completion_begin().driver, preflight());
        let insert = on_ceremony_taken(
            take.driver,
            TakeObservation::Taken {
                grant_matches: true,
                claim_matches: true,
            },
        );
        // A definite zero-row insert did not commit: restore so the confirmed
        // pairing can be retried after rotation.
        let skipped = on_device_inserted(insert.driver, DeviceInsertObservation::Skipped);
        assert!(skipped.driver.restored && skipped.driver.failed);
        assert!(!skipped.driver.inserted && !skipped.driver.recorded);

        // An insert error is ambiguous: the row may have committed. The
        // grant+claim therefore stay consumed and no second device can be
        // enrolled from them.
        let failed = on_device_inserted(insert.driver, DeviceInsertObservation::Failed);
        assert!(matches!(
            failed.effect,
            PairingEffect::Fail(PairingFailure::InsertStorage)
        ));
        assert!(failed.driver.failed && !failed.driver.restored);
        assert!(!failed.driver.inserted && !failed.driver.recorded);
    }

    /// Regression: an ambiguous SQL insert error must not restore the consumed
    /// grant+claim, or a retry could enroll a second device from one ceremony.
    #[test]
    fn an_ambiguous_insert_error_consumes_the_ceremony() {
        let take = on_completion_ready(completion_begin().driver, preflight());
        let insert = on_ceremony_taken(
            take.driver,
            TakeObservation::Taken {
                grant_matches: true,
                claim_matches: true,
            },
        );
        let failed = on_device_inserted(insert.driver, DeviceInsertObservation::Failed);
        assert!(matches!(
            failed.effect,
            PairingEffect::Fail(PairingFailure::InsertStorage)
        ));
        assert!(failed.driver.failed);
        assert!(!failed.driver.restored);
        assert!(!failed.driver.inserted);
    }

    #[test]
    fn a_replayed_package_fetch_returns_nothing() {
        let start = begin_redeem_package(PackageTokenObservation { token_valid: true });
        let t = on_package_redeemed(start.driver, RedeemObservation::Missing);
        assert!(matches!(
            t.effect,
            PairingEffect::Fail(PairingFailure::PackageUnavailable)
        ));
        assert!(!matches!(t.effect, PairingEffect::Complete));
    }

    #[test]
    fn claim_rejection_precedence_is_historical() {
        let base = ClaimObservation {
            grant_live: true,
            claim_exists: true,
            hybrid_ek_len: 0,
            hybrid_vk_len: 0,
        };
        assert_eq!(claim_rejection(base), PairingFailure::InvalidEkLength);
        assert_eq!(
            claim_rejection(ClaimObservation {
                hybrid_ek_len: HYBRID_EK_LEN,
                ..base
            }),
            PairingFailure::InvalidVkLength
        );
        assert_eq!(
            claim_rejection(ClaimObservation {
                hybrid_ek_len: HYBRID_EK_LEN,
                hybrid_vk_len: HYBRID_VK_LEN,
                ..base
            }),
            PairingFailure::AlreadyClaimed
        );
    }

    /// The driver's historical rejection precedence is exactly the verified
    /// claim policy's refusal, with the per-field guards the old handler used.
    #[test]
    fn claim_rejection_is_exactly_the_policy_refusal() {
        for grant_live in [false, true] {
            for claim_exists in [false, true] {
                for ek in [0usize, HYBRID_EK_LEN] {
                    for vk in [0usize, HYBRID_VK_LEN] {
                        let observation = ClaimObservation {
                            grant_live,
                            claim_exists,
                            hybrid_ek_len: ek,
                            hybrid_vk_len: vk,
                        };
                        let rejected =
                            matches!(plan_claim(claim_facts(observation)), ClaimDecision::Reject);
                        if !rejected {
                            continue;
                        }
                        let failure = claim_rejection(observation);
                        let guard = match failure {
                            PairingFailure::InvalidEkLength => ek != HYBRID_EK_LEN,
                            PairingFailure::InvalidVkLength => {
                                ek == HYBRID_EK_LEN && vk != HYBRID_VK_LEN
                            }
                            PairingFailure::AlreadyClaimed => {
                                ek == HYBRID_EK_LEN
                                    && vk == HYBRID_VK_LEN
                                    && claim_exists
                            }
                            PairingFailure::GrantUnavailable => {
                                ek == HYBRID_EK_LEN
                                    && vk == HYBRID_VK_LEN
                                    && !claim_exists
                                    && !grant_live
                            }
                            PairingFailure::ClaimNotAuthorized => {
                                ek == HYBRID_EK_LEN
                                    && vk == HYBRID_VK_LEN
                                    && !claim_exists
                                    && grant_live
                            }
                            other => panic!("unexpected rejection reason {other:?}"),
                        };
                        assert!(guard, "guard mismatch for {observation:?} -> {failure:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn out_of_order_events_are_inert() {
        for state in sound_states() {
            for event in events() {
                let t = step(state, event);
                if matches!(t.effect, PairingEffect::Idle) {
                    assert_eq!(t.driver, state, "idle event changed {state:?}");
                }
            }
        }
    }
}
