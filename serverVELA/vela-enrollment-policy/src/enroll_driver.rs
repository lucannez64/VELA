//! Pure post-validation decision driver for `POST /device/enroll`.
//!
//! The HTTP handler performs the effectful steps: the single-use `enroll`
//! challenge consumption, the enrolling-device row query, the two hybrid
//! signature checks, the `users.key_epoch`/`rekey_state`-guarded device insert.
//! This module owns every *decision* between those effects: whether the
//! consumed challenge permits the ceremony to continue, how the device and
//! signature observations are classified, whether the rekey policy permits a
//! device-authority mutation, and how the guarded insert outcome is classified.
//!
//! The driver is a per-request value: it does not observe SQL and does not
//! coordinate concurrent requests. Every input is an observation produced by
//! the handler. The transition relation is total: events that do not match the
//! current stage (and every event after `Done`) are ignored, so the unbounded
//! trace induction in `proofs/fstar/enroll-driver-lemmas` is a statement about
//! every event list, not only the handler's intended order.
//!
//! The state records only *decision facts* established by a prior transition.
//! In particular `inserted` means the guarded `INSERT` reported one inserted
//! row, and `account_epoch_active` is that report's consequence (the SQL guard
//! matched the account epoch and found no rotation in progress). An ambiguous
//! insert error is terminal and restores nothing (cf. U-19): the row may have
//! committed before the error surfaced, so a retry must not reuse the challenge.

/// Decoded length of a hybrid signature (`ML-DSA` + `Ed25519`).
pub const HYBRID_SIG_LEN: usize = 4627 + 64;

// ── Observations ────────────────────────────────────────────────────────────

/// Outcome of the single-use `enroll`-purpose challenge consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeObservation {
    /// The exact challenge was consumed for the enroll purpose exactly once.
    Consumed,
    /// The challenge was missing, expired, already used, or bound to another
    /// purpose. The handler retains the original error for rendering.
    Rejected,
}

/// The enrolling device row, the challenge decoding and the authentication
/// signature over the challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceObservation {
    /// An unrevoked row exists and its signature over
    /// `auth_message(device_id, challenge)` verified.
    Verified,
    /// No row, a revoked row, or a row that no longer decodes as this device.
    Unavailable,
    /// The challenge was not valid base64, or did not decode to 32 bytes.
    MalformedChallenge,
    /// The authentication signature did not verify under the row's key.
    AuthSignatureRejected,
    /// The row query or decode failed; the handler retains the original error.
    Error,
}

/// The new device's key material and its enrollment signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentObservation {
    /// All four fields decoded and every decoded length is exact; the enrolling
    /// device signed the new keys and the RMS capsule.
    Verified,
    /// One of the four base64 fields did not decode; the handler retains the
    /// original error (including which field failed).
    DecodeFailed,
    /// `hybrid_ek` had the wrong decoded length.
    EkLengthInvalid,
    /// `hybrid_vk` had the wrong decoded length.
    VkLengthInvalid,
    /// `signature` had the wrong decoded length.
    SignatureLengthInvalid,
    /// The enrollment signature did not verify under the enrolling device's key.
    SignatureRejected,
    /// The verifier itself failed; the handler retains the original error.
    Error,
}

/// The declared epoch and the rekey policy's device-authority permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountObservation {
    /// The declared epoch is positive and `plan_active_mutation` permitted a
    /// device-authority enrollment mutation at that epoch.
    Permitted,
    /// The declared epoch was not positive.
    EpochInvalid,
    /// The rekey policy refused a device-authority enrollment mutation.
    RekeyRejected,
}

/// Outcome of the guarded device `INSERT ... SELECT ... WHERE EXISTS (...)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertObservation {
    /// One row was inserted: the account epoch matched and no rotation was in
    /// progress at the moment the statement ran.
    Inserted,
    /// Zero rows: `users.key_epoch` changed or `rekey_state` was set.
    EpochMismatch,
    /// The insert errored. This does not prove nothing committed.
    Failed,
}

// ── The decision state machine ──────────────────────────────────────────────

/// Where the ceremony is in its decision sequence. A stage names the effect
/// that has been emitted and whose observation is awaited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollStage {
    /// The begin decision ran and `ConsumeChallenge` was emitted.
    Start,
    /// The challenge was consumed and `CheckDevice` was emitted.
    Device,
    /// The enrolling device authenticated and `PrepareEnrollment` was emitted.
    Prepared,
    /// The new key material and its signature verified and `CheckAccount` was
    /// emitted.
    Account,
    /// The rekey policy permitted the mutation and `InsertDevice` was emitted.
    Insert,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders them; this module never formats a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollFailure {
    /// The enroll-purpose challenge was missing, expired or already consumed.
    ChallengeRejected,
    /// No unrevoked device row for the enrolling id.
    DeviceUnavailable,
    /// The challenge was not 32 base64-decoded bytes.
    MalformedChallenge,
    /// The authentication signature over the challenge did not verify.
    AuthSignatureRejected,
    /// The device row query or decode failed.
    DeviceStorage,
    /// One of the four new-device base64 fields did not decode.
    KeyDecode,
    /// `hybrid_ek` had the wrong decoded length.
    EkLength,
    /// `hybrid_vk` had the wrong decoded length.
    VkLength,
    /// `signature` had the wrong decoded length.
    SignatureLength,
    /// The enrollment signature over the new payload did not verify.
    EnrollmentSignatureRejected,
    /// The signature verifier itself failed.
    SignatureStorage,
    /// The declared epoch was not positive.
    KeyEpochInvalid,
    /// The rekey policy refused the device-authority mutation.
    RekeyPolicy,
    /// The guarded insert matched zero rows: the epoch changed or a rotation
    /// started.
    EpochConflict,
    /// The guarded insert errored; possibly after committing.
    InsertStorage,
}

/// The effect the handler must perform next (`Idle` means "do nothing").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollEffect {
    /// Consume the presented challenge for the enroll purpose, exactly once.
    ConsumeChallenge,
    /// Read the enrolling device row and verify its authentication signature.
    CheckDevice,
    /// Decode the new key material, check its lengths and verify the enrolling
    /// device's signature over it.
    PrepareEnrollment,
    /// Check the declared epoch and ask `vela_rekey_policy` for the
    /// device-authority permit.
    CheckAccount,
    /// Perform the guarded device insert, exactly once.
    InsertDevice,
    /// Terminal success (the device row was inserted).
    Complete,
    /// Terminal failure without restoration.
    Fail(EnrollFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about SQL beyond the effect's observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollDriver {
    pub stage: EnrollStage,
    /// The begin decision ran and emitted `ConsumeChallenge`.
    pub authorized: bool,
    /// The enroll-purpose challenge was consumed once by this request.
    pub challenge_consumed: bool,
    /// That consumption was scoped to the enroll purpose.
    pub challenge_purpose_enroll: bool,
    /// The enrolling device row was present, unrevoked and decoded.
    pub device_active: bool,
    /// The enrolling device proved possession of its key over the challenge.
    pub auth_signature_verified: bool,
    /// All new key-material lengths were exact.
    pub keys_valid: bool,
    /// The enrolling device signed the new keys and RMS capsule.
    pub enrollment_signature_verified: bool,
    /// The declared epoch was positive.
    pub epoch_positive: bool,
    /// The rekey policy permitted the device-authority mutation.
    pub rekey_permitted: bool,
    /// The guarded insert reported one row.
    pub inserted: bool,
    /// The guarded insert's account-epoch/rekey guard matched.
    pub account_epoch_active: bool,
    /// A terminal success was authorized.
    pub succeeded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollEvent {
    ChallengeConsumed(ChallengeObservation),
    DeviceChecked(DeviceObservation),
    EnrollmentPrepared(EnrollmentObservation),
    AccountChecked(AccountObservation),
    DeviceInserted(InsertObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollTransition {
    pub driver: EnrollDriver,
    pub effect: EnrollEffect,
}

// ── The state invariant ─────────────────────────────────────────────────────

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn enroll_state_is_sound(d: EnrollDriver) -> bool {
    let start_clean = !d.challenge_consumed
        && !d.challenge_purpose_enroll
        && !d.device_active
        && !d.auth_signature_verified
        && !d.keys_valid
        && !d.enrollment_signature_verified
        && !d.epoch_positive
        && !d.rekey_permitted
        && !d.inserted
        && !d.account_epoch_active
        && !d.succeeded
        && !d.failed;
    let device_clean = d.challenge_consumed
        && d.challenge_purpose_enroll
        && !d.device_active
        && !d.auth_signature_verified
        && !d.keys_valid
        && !d.enrollment_signature_verified
        && !d.epoch_positive
        && !d.rekey_permitted
        && !d.inserted
        && !d.account_epoch_active
        && !d.succeeded
        && !d.failed;
    let prepared_clean = d.challenge_consumed
        && d.challenge_purpose_enroll
        && d.device_active
        && d.auth_signature_verified
        && !d.keys_valid
        && !d.enrollment_signature_verified
        && !d.epoch_positive
        && !d.rekey_permitted
        && !d.inserted
        && !d.account_epoch_active
        && !d.succeeded
        && !d.failed;
    let account_clean = d.challenge_consumed
        && d.challenge_purpose_enroll
        && d.device_active
        && d.auth_signature_verified
        && d.keys_valid
        && d.enrollment_signature_verified
        && !d.epoch_positive
        && !d.rekey_permitted
        && !d.inserted
        && !d.account_epoch_active
        && !d.succeeded
        && !d.failed;
    let insert_clean = d.challenge_consumed
        && d.challenge_purpose_enroll
        && d.device_active
        && d.auth_signature_verified
        && d.keys_valid
        && d.enrollment_signature_verified
        && d.epoch_positive
        && d.rekey_permitted
        && !d.inserted
        && !d.account_epoch_active
        && !d.succeeded
        && !d.failed;
    let done_clean = (d.succeeded || d.failed)
        && !(d.succeeded && d.failed)
        && (!d.succeeded || (d.inserted && d.account_epoch_active))
        && (!d.failed || !d.inserted);
    d.authorized
        && (!matches!(d.stage, EnrollStage::Start) || start_clean)
        && (!matches!(d.stage, EnrollStage::Device) || device_clean)
        && (!matches!(d.stage, EnrollStage::Prepared) || prepared_clean)
        && (!matches!(d.stage, EnrollStage::Account) || account_clean)
        && (!matches!(d.stage, EnrollStage::Insert) || insert_clean)
        && (!matches!(d.stage, EnrollStage::Done) || done_clean)
        // Flags are established in one direction only.
        && (!d.challenge_purpose_enroll || d.challenge_consumed)
        && (!d.device_active || d.challenge_consumed)
        && (!d.auth_signature_verified || d.device_active)
        && (!d.keys_valid || (d.device_active && d.auth_signature_verified))
        && (!d.enrollment_signature_verified || d.keys_valid)
        && (!d.epoch_positive || d.enrollment_signature_verified)
        && (!d.rekey_permitted || d.epoch_positive)
        && (!d.inserted || d.rekey_permitted)
        && (!d.account_epoch_active || d.inserted)
        // An inserted device row is only ever behind the enroll-purpose
        // challenge, the approving device checks and the active account epoch.
        && (!d.inserted
            || (d.challenge_consumed
                && d.challenge_purpose_enroll
                && d.device_active
                && d.auth_signature_verified
                && d.keys_valid
                && d.enrollment_signature_verified
                && d.epoch_positive
                && d.rekey_permitted
                && d.account_epoch_active))
        // A driver that is still waiting for its first observation has run its
        // begin decision (only a terminal failure can leave a non-Start stage
        // without the corresponding facts).
        && (!matches!(d.stage, EnrollStage::Start) || d.authorized)
}

/// Every effect the driver emits agrees with the state it produces.
pub fn enroll_effect_is_sound(d: EnrollDriver, effect: EnrollEffect) -> bool {
    match effect {
        EnrollEffect::ConsumeChallenge => {
            matches!(d.stage, EnrollStage::Start)
                && d.authorized
                && !d.challenge_consumed
                && !d.inserted
                && !d.succeeded
                && !d.failed
        }
        EnrollEffect::CheckDevice => {
            matches!(d.stage, EnrollStage::Device)
                && d.authorized
                && d.challenge_consumed
                && d.challenge_purpose_enroll
                && !d.inserted
                && !d.succeeded
                && !d.failed
        }
        EnrollEffect::PrepareEnrollment => {
            matches!(d.stage, EnrollStage::Prepared)
                && d.authorized
                && d.challenge_consumed
                && d.device_active
                && d.auth_signature_verified
                && !d.inserted
                && !d.succeeded
                && !d.failed
        }
        EnrollEffect::CheckAccount => {
            matches!(d.stage, EnrollStage::Account)
                && d.authorized
                && d.keys_valid
                && d.enrollment_signature_verified
                && !d.inserted
                && !d.succeeded
                && !d.failed
        }
        EnrollEffect::InsertDevice => {
            matches!(d.stage, EnrollStage::Insert)
                && d.authorized
                && d.epoch_positive
                && d.rekey_permitted
                && !d.inserted
                && !d.succeeded
                && !d.failed
        }
        EnrollEffect::Complete => {
            matches!(d.stage, EnrollStage::Done)
                && d.succeeded
                && !d.failed
                && d.inserted
                && d.account_epoch_active
        }
        EnrollEffect::Fail(_) => {
            matches!(d.stage, EnrollStage::Done) && d.failed && !d.succeeded && !d.inserted
        }
        EnrollEffect::Idle => true,
    }
}

fn fresh_driver() -> EnrollDriver {
    EnrollDriver {
        stage: EnrollStage::Start,
        authorized: false,
        challenge_consumed: false,
        challenge_purpose_enroll: false,
        device_active: false,
        auth_signature_verified: false,
        keys_valid: false,
        enrollment_signature_verified: false,
        epoch_positive: false,
        rekey_permitted: false,
        inserted: false,
        account_epoch_active: false,
        succeeded: false,
        failed: false,
    }
}

fn transition(d: EnrollDriver, effect: EnrollEffect) -> EnrollTransition {
    EnrollTransition {
        driver: d,
        effect,
    }
}

fn idle(d: EnrollDriver) -> EnrollTransition {
    transition(d, EnrollEffect::Idle)
}

fn terminal(d: EnrollDriver, failure: EnrollFailure) -> EnrollTransition {
    transition(
        EnrollDriver {
            stage: EnrollStage::Done,
            failed: true,
            ..d
        },
        EnrollEffect::Fail(failure),
    )
}

fn complete(d: EnrollDriver) -> EnrollTransition {
    transition(
        EnrollDriver {
            stage: EnrollStage::Done,
            succeeded: true,
            ..d
        },
        EnrollEffect::Complete,
    )
}

// ── Begin ───────────────────────────────────────────────────────────────────

/// Start an enrollment request. The only effect before any observation is the
/// challenge consumption; a rejected challenge ends the ceremony with no
/// device row written.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_state_is_sound(result.driver)
        && enroll_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_enroll() -> EnrollTransition {
    transition(
        EnrollDriver {
            authorized: true,
            ..fresh_driver()
        },
        EnrollEffect::ConsumeChallenge,
    )
}

// ── Per-stage handlers ──────────────────────────────────────────────────────

#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(d) && matches!(d.stage, EnrollStage::Start) && d.authorized))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(d) || enroll_state_is_sound(result.driver))
}))]
fn on_challenge_consumed(d: EnrollDriver, observation: ChallengeObservation) -> EnrollTransition {
    match observation {
        ChallengeObservation::Consumed => transition(
            EnrollDriver {
                stage: EnrollStage::Device,
                challenge_consumed: true,
                challenge_purpose_enroll: true,
                ..d
            },
            EnrollEffect::CheckDevice,
        ),
        ChallengeObservation::Rejected => terminal(d, EnrollFailure::ChallengeRejected),
    }
}

#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(d) && matches!(d.stage, EnrollStage::Device) && d.challenge_consumed))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(d) || enroll_state_is_sound(result.driver))
}))]
fn on_device_checked(d: EnrollDriver, observation: DeviceObservation) -> EnrollTransition {
    match observation {
        DeviceObservation::Verified => transition(
            EnrollDriver {
                stage: EnrollStage::Prepared,
                device_active: true,
                auth_signature_verified: true,
                ..d
            },
            EnrollEffect::PrepareEnrollment,
        ),
        DeviceObservation::Unavailable => terminal(d, EnrollFailure::DeviceUnavailable),
        DeviceObservation::MalformedChallenge => terminal(d, EnrollFailure::MalformedChallenge),
        DeviceObservation::AuthSignatureRejected => {
            terminal(d, EnrollFailure::AuthSignatureRejected)
        }
        DeviceObservation::Error => terminal(d, EnrollFailure::DeviceStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(d) && matches!(d.stage, EnrollStage::Prepared) && d.device_active && d.auth_signature_verified))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(d) || enroll_state_is_sound(result.driver))
}))]
fn on_enrollment_prepared(
    d: EnrollDriver,
    observation: EnrollmentObservation,
) -> EnrollTransition {
    match observation {
        EnrollmentObservation::Verified => transition(
            EnrollDriver {
                stage: EnrollStage::Account,
                keys_valid: true,
                enrollment_signature_verified: true,
                ..d
            },
            EnrollEffect::CheckAccount,
        ),
        EnrollmentObservation::DecodeFailed => terminal(d, EnrollFailure::KeyDecode),
        EnrollmentObservation::EkLengthInvalid => terminal(d, EnrollFailure::EkLength),
        EnrollmentObservation::VkLengthInvalid => terminal(d, EnrollFailure::VkLength),
        EnrollmentObservation::SignatureLengthInvalid => {
            terminal(d, EnrollFailure::SignatureLength)
        }
        EnrollmentObservation::SignatureRejected => {
            terminal(d, EnrollFailure::EnrollmentSignatureRejected)
        }
        EnrollmentObservation::Error => terminal(d, EnrollFailure::SignatureStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(d) && matches!(d.stage, EnrollStage::Account) && d.keys_valid && d.enrollment_signature_verified))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(d) || enroll_state_is_sound(result.driver))
}))]
fn on_account_checked(d: EnrollDriver, observation: AccountObservation) -> EnrollTransition {
    match observation {
        AccountObservation::Permitted => transition(
            EnrollDriver {
                stage: EnrollStage::Insert,
                epoch_positive: true,
                rekey_permitted: true,
                ..d
            },
            EnrollEffect::InsertDevice,
        ),
        AccountObservation::EpochInvalid => terminal(d, EnrollFailure::KeyEpochInvalid),
        AccountObservation::RekeyRejected => terminal(d, EnrollFailure::RekeyPolicy),
    }
}

#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(d) && matches!(d.stage, EnrollStage::Insert) && d.epoch_positive && d.rekey_permitted))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(d) || enroll_state_is_sound(result.driver))
}))]
fn on_device_inserted(d: EnrollDriver, observation: InsertObservation) -> EnrollTransition {
    match observation {
        InsertObservation::Inserted => complete(EnrollDriver {
            inserted: true,
            account_epoch_active: true,
            ..d
        }),
        // The guard matched zero rows: the epoch changed or a rotation started
        // after the preflight. No device row exists, but the challenge is spent.
        InsertObservation::EpochMismatch => terminal(d, EnrollFailure::EpochConflict),
        // An INSERT error is ambiguous: the row may have committed before the
        // error surfaced. Restoring the challenge would let a second request
        // enroll another device with it, so the failure is terminal (U-19).
        InsertObservation::Failed => terminal(d, EnrollFailure::InsertStorage),
    }
}

// ── The total transition relation ───────────────────────────────────────────

fn stage_start(d: EnrollDriver) -> bool {
    matches!(d.stage, EnrollStage::Start)
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(driver) || enroll_state_is_sound(result.driver))
}))]
pub fn step(driver: EnrollDriver, event: EnrollEvent) -> EnrollTransition {
    match event {
        EnrollEvent::ChallengeConsumed(observation) => {
            if stage_start(driver) && driver.authorized {
                on_challenge_consumed(driver, observation)
            } else {
                idle(driver)
            }
        }
        EnrollEvent::DeviceChecked(observation) => {
            if matches!(driver.stage, EnrollStage::Device) && driver.challenge_consumed {
                on_device_checked(driver, observation)
            } else {
                idle(driver)
            }
        }
        EnrollEvent::EnrollmentPrepared(observation) => {
            if matches!(driver.stage, EnrollStage::Prepared)
                && driver.device_active
                && driver.auth_signature_verified
            {
                on_enrollment_prepared(driver, observation)
            } else {
                idle(driver)
            }
        }
        EnrollEvent::AccountChecked(observation) => {
            if matches!(driver.stage, EnrollStage::Account)
                && driver.keys_valid
                && driver.enrollment_signature_verified
            {
                on_account_checked(driver, observation)
            } else {
                idle(driver)
            }
        }
        EnrollEvent::DeviceInserted(observation) => {
            if matches!(driver.stage, EnrollStage::Insert)
                && driver.epoch_positive
                && driver.rekey_permitted
            {
                on_device_inserted(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

// ── Per-effect wrappers for the evidence log and the proofs ─────────────────

/// Total wrapper: the handler feeds the challenge consumption outcome.
#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(driver) || enroll_state_is_sound(result.driver))
}))]
pub fn on_challenge_consumed_event(
    driver: EnrollDriver,
    observation: ChallengeObservation,
) -> EnrollTransition {
    step(driver, EnrollEvent::ChallengeConsumed(observation))
}

/// Total wrapper: the handler feeds the device/signature check.
#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(driver) || enroll_state_is_sound(result.driver))
}))]
pub fn on_device_checked_event(
    driver: EnrollDriver,
    observation: DeviceObservation,
) -> EnrollTransition {
    step(driver, EnrollEvent::DeviceChecked(observation))
}

/// Total wrapper: the handler feeds the new-key/signature check.
#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(driver) || enroll_state_is_sound(result.driver))
}))]
pub fn on_enrollment_prepared_event(
    driver: EnrollDriver,
    observation: EnrollmentObservation,
) -> EnrollTransition {
    step(driver, EnrollEvent::EnrollmentPrepared(observation))
}

/// Total wrapper: the handler feeds the epoch/rekey decision.
#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(driver) || enroll_state_is_sound(result.driver))
}))]
pub fn on_account_checked_event(
    driver: EnrollDriver,
    observation: AccountObservation,
) -> EnrollTransition {
    step(driver, EnrollEvent::AccountChecked(observation))
}

/// Total wrapper: the handler feeds the guarded insert outcome.
#[cfg_attr(hax, hax_lib::requires(enroll_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    enroll_effect_is_sound(result.driver, result.effect)
        && (!enroll_state_is_sound(driver) || enroll_state_is_sound(result.driver))
}))]
pub fn on_device_inserted_event(
    driver: EnrollDriver,
    observation: InsertObservation,
) -> EnrollTransition {
    step(driver, EnrollEvent::DeviceInserted(observation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(events: &[EnrollEvent]) -> EnrollTransition {
        let mut t = begin_enroll();
        for event in events {
            t = step(t.driver, *event);
            assert!(enroll_state_is_sound(t.driver), "{t:?}");
            assert!(enroll_effect_is_sound(t.driver, t.effect), "{t:?}");
        }
        t
    }

    fn happy() -> Vec<EnrollEvent> {
        vec![
            EnrollEvent::ChallengeConsumed(ChallengeObservation::Consumed),
            EnrollEvent::DeviceChecked(DeviceObservation::Verified),
            EnrollEvent::EnrollmentPrepared(EnrollmentObservation::Verified),
            EnrollEvent::AccountChecked(AccountObservation::Permitted),
            EnrollEvent::DeviceInserted(InsertObservation::Inserted),
        ]
    }

    #[test]
    fn happy_path_inserts_after_every_approval() {
        let t = run(&happy());
        assert_eq!(t.effect, EnrollEffect::Complete);
        assert!(t.driver.inserted && t.driver.succeeded && !t.driver.failed);
    }

    #[test]
    fn a_rejected_challenge_never_reaches_the_insert() {
        let t = run(&[EnrollEvent::ChallengeConsumed(
            ChallengeObservation::Rejected,
        )]);
        assert_eq!(t.effect, EnrollEffect::Fail(EnrollFailure::ChallengeRejected));
        let after = step(t.driver, EnrollEvent::DeviceInserted(InsertObservation::Inserted));
        assert_eq!(after.effect, EnrollEffect::Idle);
        assert!(!after.driver.inserted);
    }

    #[test]
    fn every_pre_insert_failure_spends_the_challenge_and_stops() {
        let consumed = EnrollEvent::ChallengeConsumed(ChallengeObservation::Consumed);
        let device_ok = EnrollEvent::DeviceChecked(DeviceObservation::Verified);
        let prepared_ok = EnrollEvent::EnrollmentPrepared(EnrollmentObservation::Verified);
        let account_ok = EnrollEvent::AccountChecked(AccountObservation::Permitted);
        let cases: Vec<(Vec<EnrollEvent>, EnrollEvent)> = vec![
            (vec![], EnrollEvent::DeviceChecked(DeviceObservation::Unavailable)),
            (vec![], EnrollEvent::DeviceChecked(DeviceObservation::MalformedChallenge)),
            (
                vec![],
                EnrollEvent::DeviceChecked(DeviceObservation::AuthSignatureRejected),
            ),
            (
                vec![device_ok],
                EnrollEvent::EnrollmentPrepared(EnrollmentObservation::DecodeFailed),
            ),
            (
                vec![device_ok],
                EnrollEvent::EnrollmentPrepared(EnrollmentObservation::EkLengthInvalid),
            ),
            (
                vec![device_ok],
                EnrollEvent::EnrollmentPrepared(EnrollmentObservation::VkLengthInvalid),
            ),
            (
                vec![device_ok],
                EnrollEvent::EnrollmentPrepared(EnrollmentObservation::SignatureLengthInvalid),
            ),
            (
                vec![device_ok],
                EnrollEvent::EnrollmentPrepared(EnrollmentObservation::SignatureRejected),
            ),
            (
                vec![device_ok, prepared_ok],
                EnrollEvent::AccountChecked(AccountObservation::EpochInvalid),
            ),
            (
                vec![device_ok, prepared_ok],
                EnrollEvent::AccountChecked(AccountObservation::RekeyRejected),
            ),
            (
                vec![device_ok, prepared_ok, account_ok],
                EnrollEvent::DeviceInserted(InsertObservation::EpochMismatch),
            ),
            (
                vec![device_ok, prepared_ok, account_ok],
                EnrollEvent::DeviceInserted(InsertObservation::Failed),
            ),
        ];
        for (prefix, failure) in cases {
            let mut events = vec![consumed];
            events.extend(prefix);
            events.push(failure);
            let t = run(&events);
            assert!(matches!(t.effect, EnrollEffect::Fail(_)), "{t:?}");
            assert!(t.driver.failed && !t.driver.succeeded);
            assert!(t.driver.challenge_consumed);
            assert!(!t.driver.inserted);
        }
    }

    #[test]
    fn an_ambiguous_insert_error_is_terminal_and_restores_nothing() {
        let mut events = happy();
        events[4] = EnrollEvent::DeviceInserted(InsertObservation::Failed);
        let t = run(&events);
        assert_eq!(t.effect, EnrollEffect::Fail(EnrollFailure::InsertStorage));
        assert!(t.driver.failed && !t.driver.inserted);
        let after = step(t.driver, EnrollEvent::DeviceInserted(InsertObservation::Inserted));
        assert_eq!(after.effect, EnrollEffect::Idle);
        assert!(!after.driver.inserted);
    }

    #[test]
    fn every_sound_device_stage_observation_is_sound() {
        // Exhaust the three relevant stage/flag combinations and every
        // observation; a postcondition failure shows up as a panic here.
        let mut base = begin_enroll();
        base = step(base.driver, EnrollEvent::ChallengeConsumed(ChallengeObservation::Consumed));
        assert!(enroll_state_is_sound(base.driver));
        for observation in [
            DeviceObservation::Verified,
            DeviceObservation::Unavailable,
            DeviceObservation::MalformedChallenge,
            DeviceObservation::AuthSignatureRejected,
            DeviceObservation::Error,
        ] {
            let t = step(base.driver, EnrollEvent::DeviceChecked(observation));
            assert!(enroll_state_is_sound(t.driver), "{observation:?}: {t:?}");
            assert!(enroll_effect_is_sound(t.driver, t.effect), "{observation:?}: {t:?}");
        }
    }

    #[test]
    fn out_of_order_events_are_ignored() {
        let mut t = begin_enroll();
        t = step(t.driver, EnrollEvent::DeviceInserted(InsertObservation::Inserted));
        assert_eq!(t.effect, EnrollEffect::Idle);
        assert!(!t.driver.inserted);
        t = step(t.driver, EnrollEvent::DeviceChecked(DeviceObservation::Verified));
        assert_eq!(t.effect, EnrollEffect::Idle);
        assert!(!t.driver.device_active);
    }
}
