module Vela_enrollment_policy.Enroll_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Outcome of the single-use `enroll`-purpose challenge consumption.
type t_ChallengeObservation =
  | ChallengeObservation_Consumed : t_ChallengeObservation
  | ChallengeObservation_Rejected : t_ChallengeObservation

/// The enrolling device row, the challenge decoding and the authentication
/// signature over the challenge.
type t_DeviceObservation =
  | DeviceObservation_Verified : t_DeviceObservation
  | DeviceObservation_Unavailable : t_DeviceObservation
  | DeviceObservation_MalformedChallenge : t_DeviceObservation
  | DeviceObservation_AuthSignatureRejected : t_DeviceObservation
  | DeviceObservation_Error : t_DeviceObservation

/// The new device's key material and its enrollment signature.
type t_EnrollmentObservation =
  | EnrollmentObservation_Verified : t_EnrollmentObservation
  | EnrollmentObservation_DecodeFailed : t_EnrollmentObservation
  | EnrollmentObservation_EkLengthInvalid : t_EnrollmentObservation
  | EnrollmentObservation_VkLengthInvalid : t_EnrollmentObservation
  | EnrollmentObservation_SignatureLengthInvalid : t_EnrollmentObservation
  | EnrollmentObservation_SignatureRejected : t_EnrollmentObservation
  | EnrollmentObservation_Error : t_EnrollmentObservation

/// The declared epoch and the rekey policy's device-authority permit.
type t_AccountObservation =
  | AccountObservation_Permitted : t_AccountObservation
  | AccountObservation_EpochInvalid : t_AccountObservation
  | AccountObservation_RekeyRejected : t_AccountObservation

/// Outcome of the guarded device `INSERT ... SELECT ... WHERE EXISTS (...)`.
type t_InsertObservation =
  | InsertObservation_Inserted : t_InsertObservation
  | InsertObservation_EpochMismatch : t_InsertObservation
  | InsertObservation_Failed : t_InsertObservation

/// Where the ceremony is in its decision sequence. A stage names the effect
/// that has been emitted and whose observation is awaited.
type t_EnrollStage =
  | EnrollStage_Start : t_EnrollStage
  | EnrollStage_Device : t_EnrollStage
  | EnrollStage_Prepared : t_EnrollStage
  | EnrollStage_Account : t_EnrollStage
  | EnrollStage_Insert : t_EnrollStage
  | EnrollStage_Done : t_EnrollStage

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders them; this module never formats a message.
type t_EnrollFailure =
  | EnrollFailure_ChallengeRejected : t_EnrollFailure
  | EnrollFailure_DeviceUnavailable : t_EnrollFailure
  | EnrollFailure_MalformedChallenge : t_EnrollFailure
  | EnrollFailure_AuthSignatureRejected : t_EnrollFailure
  | EnrollFailure_DeviceStorage : t_EnrollFailure
  | EnrollFailure_KeyDecode : t_EnrollFailure
  | EnrollFailure_EkLength : t_EnrollFailure
  | EnrollFailure_VkLength : t_EnrollFailure
  | EnrollFailure_SignatureLength : t_EnrollFailure
  | EnrollFailure_EnrollmentSignatureRejected : t_EnrollFailure
  | EnrollFailure_SignatureStorage : t_EnrollFailure
  | EnrollFailure_KeyEpochInvalid : t_EnrollFailure
  | EnrollFailure_RekeyPolicy : t_EnrollFailure
  | EnrollFailure_EpochConflict : t_EnrollFailure
  | EnrollFailure_InsertStorage : t_EnrollFailure

/// The effect the handler must perform next (`Idle` means "do nothing").
type t_EnrollEffect =
  | EnrollEffect_ConsumeChallenge : t_EnrollEffect
  | EnrollEffect_CheckDevice : t_EnrollEffect
  | EnrollEffect_PrepareEnrollment : t_EnrollEffect
  | EnrollEffect_CheckAccount : t_EnrollEffect
  | EnrollEffect_InsertDevice : t_EnrollEffect
  | EnrollEffect_Complete : t_EnrollEffect
  | EnrollEffect_Fail : t_EnrollFailure -> t_EnrollEffect
  | EnrollEffect_Idle : t_EnrollEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about SQL beyond the effect's observation.
type t_EnrollDriver = {
  f_stage:t_EnrollStage;
  f_authorized:bool;
  f_challenge_consumed:bool;
  f_challenge_purpose_enroll:bool;
  f_device_active:bool;
  f_auth_signature_verified:bool;
  f_keys_valid:bool;
  f_enrollment_signature_verified:bool;
  f_epoch_positive:bool;
  f_rekey_permitted:bool;
  f_inserted:bool;
  f_account_epoch_active:bool;
  f_succeeded:bool;
  f_failed:bool
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_EnrollEvent =
  | EnrollEvent_ChallengeConsumed : t_ChallengeObservation -> t_EnrollEvent
  | EnrollEvent_DeviceChecked : t_DeviceObservation -> t_EnrollEvent
  | EnrollEvent_EnrollmentPrepared : t_EnrollmentObservation -> t_EnrollEvent
  | EnrollEvent_AccountChecked : t_AccountObservation -> t_EnrollEvent
  | EnrollEvent_DeviceInserted : t_InsertObservation -> t_EnrollEvent

type t_EnrollTransition = {
  f_driver:t_EnrollDriver;
  f_effect:t_EnrollEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let enroll_state_is_sound (d: t_EnrollDriver) : bool =
  let start_clean:bool =
    ~.d.f_challenge_consumed && ~.d.f_challenge_purpose_enroll && ~.d.f_device_active &&
    ~.d.f_auth_signature_verified &&
    ~.d.f_keys_valid &&
    ~.d.f_enrollment_signature_verified &&
    ~.d.f_epoch_positive &&
    ~.d.f_rekey_permitted &&
    ~.d.f_inserted &&
    ~.d.f_account_epoch_active &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let device_clean:bool =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll && ~.d.f_device_active &&
    ~.d.f_auth_signature_verified &&
    ~.d.f_keys_valid &&
    ~.d.f_enrollment_signature_verified &&
    ~.d.f_epoch_positive &&
    ~.d.f_rekey_permitted &&
    ~.d.f_inserted &&
    ~.d.f_account_epoch_active &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let prepared_clean:bool =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll && d.f_device_active &&
    d.f_auth_signature_verified &&
    ~.d.f_keys_valid &&
    ~.d.f_enrollment_signature_verified &&
    ~.d.f_epoch_positive &&
    ~.d.f_rekey_permitted &&
    ~.d.f_inserted &&
    ~.d.f_account_epoch_active &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let account_clean:bool =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll && d.f_device_active &&
    d.f_auth_signature_verified &&
    d.f_keys_valid &&
    d.f_enrollment_signature_verified &&
    ~.d.f_epoch_positive &&
    ~.d.f_rekey_permitted &&
    ~.d.f_inserted &&
    ~.d.f_account_epoch_active &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let insert_clean:bool =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll && d.f_device_active &&
    d.f_auth_signature_verified &&
    d.f_keys_valid &&
    d.f_enrollment_signature_verified &&
    d.f_epoch_positive &&
    d.f_rekey_permitted &&
    ~.d.f_inserted &&
    ~.d.f_account_epoch_active &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let done_clean:bool =
    (d.f_succeeded || d.f_failed) && ~.(d.f_succeeded && d.f_failed) &&
    (~.d.f_succeeded || d.f_inserted && d.f_account_epoch_active) &&
    (~.d.f_failed || ~.d.f_inserted)
  in
  d.f_authorized &&
  (~.(match d.f_stage <: t_EnrollStage with
    | EnrollStage_Start  -> true
    | _ -> false) ||
  start_clean) &&
  (~.(match d.f_stage <: t_EnrollStage with
    | EnrollStage_Device  -> true
    | _ -> false) ||
  device_clean) &&
  (~.(match d.f_stage <: t_EnrollStage with
    | EnrollStage_Prepared  -> true
    | _ -> false) ||
  prepared_clean) &&
  (~.(match d.f_stage <: t_EnrollStage with
    | EnrollStage_Account  -> true
    | _ -> false) ||
  account_clean) &&
  (~.(match d.f_stage <: t_EnrollStage with
    | EnrollStage_Insert  -> true
    | _ -> false) ||
  insert_clean) &&
  (~.(match d.f_stage <: t_EnrollStage with
    | EnrollStage_Done  -> true
    | _ -> false) ||
  done_clean) &&
  (~.d.f_challenge_purpose_enroll || d.f_challenge_consumed) &&
  (~.d.f_device_active || d.f_challenge_consumed) &&
  (~.d.f_auth_signature_verified || d.f_device_active) &&
  (~.d.f_keys_valid || d.f_device_active && d.f_auth_signature_verified) &&
  (~.d.f_enrollment_signature_verified || d.f_keys_valid) &&
  (~.d.f_epoch_positive || d.f_enrollment_signature_verified) &&
  (~.d.f_rekey_permitted || d.f_epoch_positive) &&
  (~.d.f_inserted || d.f_rekey_permitted) &&
  (~.d.f_account_epoch_active || d.f_inserted) &&
  (~.d.f_inserted ||
  d.f_challenge_consumed && d.f_challenge_purpose_enroll && d.f_device_active &&
  d.f_auth_signature_verified &&
  d.f_keys_valid &&
  d.f_enrollment_signature_verified &&
  d.f_epoch_positive &&
  d.f_rekey_permitted &&
  d.f_account_epoch_active) &&
  (~.(match d.f_stage <: t_EnrollStage with
    | EnrollStage_Start  -> true
    | _ -> false) ||
  d.f_authorized)

/// Every effect the driver emits agrees with the state it produces.
let enroll_effect_is_sound (d: t_EnrollDriver) (v_effect: t_EnrollEffect) : bool =
  match v_effect <: t_EnrollEffect with
  | EnrollEffect_ConsumeChallenge  ->
    (match d.f_stage <: t_EnrollStage with
      | EnrollStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_challenge_consumed &&
    ~.d.f_inserted &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | EnrollEffect_CheckDevice  ->
    (match d.f_stage <: t_EnrollStage with
      | EnrollStage_Device  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_challenge_consumed &&
    d.f_challenge_purpose_enroll &&
    ~.d.f_inserted &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | EnrollEffect_PrepareEnrollment  ->
    (match d.f_stage <: t_EnrollStage with
      | EnrollStage_Prepared  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_challenge_consumed &&
    d.f_device_active &&
    d.f_auth_signature_verified &&
    ~.d.f_inserted &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | EnrollEffect_CheckAccount  ->
    (match d.f_stage <: t_EnrollStage with
      | EnrollStage_Account  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_keys_valid &&
    d.f_enrollment_signature_verified &&
    ~.d.f_inserted &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | EnrollEffect_InsertDevice  ->
    (match d.f_stage <: t_EnrollStage with
      | EnrollStage_Insert  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_epoch_positive &&
    d.f_rekey_permitted &&
    ~.d.f_inserted &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | EnrollEffect_Complete  ->
    (match d.f_stage <: t_EnrollStage with
      | EnrollStage_Done  -> true
      | _ -> false) &&
    d.f_succeeded &&
    ~.d.f_failed &&
    d.f_inserted &&
    d.f_account_epoch_active
  | EnrollEffect_Fail _ ->
    (match d.f_stage <: t_EnrollStage with
      | EnrollStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_succeeded &&
    ~.d.f_inserted
  | EnrollEffect_Idle  -> true

let fresh_driver (_: Prims.unit) : t_EnrollDriver =
  {
    f_stage = EnrollStage_Start <: t_EnrollStage;
    f_authorized = false;
    f_challenge_consumed = false;
    f_challenge_purpose_enroll = false;
    f_device_active = false;
    f_auth_signature_verified = false;
    f_keys_valid = false;
    f_enrollment_signature_verified = false;
    f_epoch_positive = false;
    f_rekey_permitted = false;
    f_inserted = false;
    f_account_epoch_active = false;
    f_succeeded = false;
    f_failed = false
  }
  <:
  t_EnrollDriver

let transition (d: t_EnrollDriver) (v_effect: t_EnrollEffect) : t_EnrollTransition =
  { f_driver = d; f_effect = v_effect } <: t_EnrollTransition

let idle (d: t_EnrollDriver) : t_EnrollTransition =
  transition d (EnrollEffect_Idle <: t_EnrollEffect)

let terminal (d: t_EnrollDriver) (failure: t_EnrollFailure) : t_EnrollTransition =
  transition ({ d with f_stage = EnrollStage_Done <: t_EnrollStage; f_failed = true }
      <:
      t_EnrollDriver)
    (EnrollEffect_Fail failure <: t_EnrollEffect)

let complete (d: t_EnrollDriver) : t_EnrollTransition =
  transition ({ d with f_stage = EnrollStage_Done <: t_EnrollStage; f_succeeded = true }
      <:
      t_EnrollDriver)
    (EnrollEffect_Complete <: t_EnrollEffect)

/// Start an enrollment request. The only effect before any observation is the
/// challenge consumption; a rejected challenge ends the ceremony with no
/// device row written.
let begin_enroll (_: Prims.unit)
    : Prims.Pure t_EnrollTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_state_is_sound result.f_driver &&
          enroll_effect_is_sound result.f_driver result.f_effect) =
  transition ({ (fresh_driver () <: t_EnrollDriver) with f_authorized = true } <: t_EnrollDriver)
    (EnrollEffect_ConsumeChallenge <: t_EnrollEffect)

let on_challenge_consumed (d: t_EnrollDriver) (observation: t_ChallengeObservation)
    : Prims.Pure t_EnrollTransition
      (requires
        enroll_state_is_sound d &&
        (match d.f_stage <: t_EnrollStage with
          | EnrollStage_Start  -> true
          | _ -> false) &&
        d.f_authorized)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound d <: bool) || enroll_state_is_sound result.f_driver)) =
  match observation <: t_ChallengeObservation with
  | ChallengeObservation_Consumed  ->
    transition ({
          d with
          f_stage = EnrollStage_Device <: t_EnrollStage;
          f_challenge_consumed = true;
          f_challenge_purpose_enroll = true
        }
        <:
        t_EnrollDriver)
      (EnrollEffect_CheckDevice <: t_EnrollEffect)
  | ChallengeObservation_Rejected  ->
    terminal d (EnrollFailure_ChallengeRejected <: t_EnrollFailure)

let on_device_checked (d: t_EnrollDriver) (observation: t_DeviceObservation)
    : Prims.Pure t_EnrollTransition
      (requires
        enroll_state_is_sound d &&
        (match d.f_stage <: t_EnrollStage with
          | EnrollStage_Device  -> true
          | _ -> false) &&
        d.f_challenge_consumed)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound d <: bool) || enroll_state_is_sound result.f_driver)) =
  match observation <: t_DeviceObservation with
  | DeviceObservation_Verified  ->
    transition ({
          d with
          f_stage = EnrollStage_Prepared <: t_EnrollStage;
          f_device_active = true;
          f_auth_signature_verified = true
        }
        <:
        t_EnrollDriver)
      (EnrollEffect_PrepareEnrollment <: t_EnrollEffect)
  | DeviceObservation_Unavailable  ->
    terminal d (EnrollFailure_DeviceUnavailable <: t_EnrollFailure)
  | DeviceObservation_MalformedChallenge  ->
    terminal d (EnrollFailure_MalformedChallenge <: t_EnrollFailure)
  | DeviceObservation_AuthSignatureRejected  ->
    terminal d (EnrollFailure_AuthSignatureRejected <: t_EnrollFailure)
  | DeviceObservation_Error  -> terminal d (EnrollFailure_DeviceStorage <: t_EnrollFailure)

let on_enrollment_prepared (d: t_EnrollDriver) (observation: t_EnrollmentObservation)
    : Prims.Pure t_EnrollTransition
      (requires
        enroll_state_is_sound d &&
        (match d.f_stage <: t_EnrollStage with
          | EnrollStage_Prepared  -> true
          | _ -> false) &&
        d.f_device_active &&
        d.f_auth_signature_verified)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound d <: bool) || enroll_state_is_sound result.f_driver)) =
  match observation <: t_EnrollmentObservation with
  | EnrollmentObservation_Verified  ->
    transition ({
          d with
          f_stage = EnrollStage_Account <: t_EnrollStage;
          f_keys_valid = true;
          f_enrollment_signature_verified = true
        }
        <:
        t_EnrollDriver)
      (EnrollEffect_CheckAccount <: t_EnrollEffect)
  | EnrollmentObservation_DecodeFailed  -> terminal d (EnrollFailure_KeyDecode <: t_EnrollFailure)
  | EnrollmentObservation_EkLengthInvalid  -> terminal d (EnrollFailure_EkLength <: t_EnrollFailure)
  | EnrollmentObservation_VkLengthInvalid  -> terminal d (EnrollFailure_VkLength <: t_EnrollFailure)
  | EnrollmentObservation_SignatureLengthInvalid  ->
    terminal d (EnrollFailure_SignatureLength <: t_EnrollFailure)
  | EnrollmentObservation_SignatureRejected  ->
    terminal d (EnrollFailure_EnrollmentSignatureRejected <: t_EnrollFailure)
  | EnrollmentObservation_Error  -> terminal d (EnrollFailure_SignatureStorage <: t_EnrollFailure)

let on_account_checked (d: t_EnrollDriver) (observation: t_AccountObservation)
    : Prims.Pure t_EnrollTransition
      (requires
        enroll_state_is_sound d &&
        (match d.f_stage <: t_EnrollStage with
          | EnrollStage_Account  -> true
          | _ -> false) &&
        d.f_keys_valid &&
        d.f_enrollment_signature_verified)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound d <: bool) || enroll_state_is_sound result.f_driver)) =
  match observation <: t_AccountObservation with
  | AccountObservation_Permitted  ->
    transition ({
          d with
          f_stage = EnrollStage_Insert <: t_EnrollStage;
          f_epoch_positive = true;
          f_rekey_permitted = true
        }
        <:
        t_EnrollDriver)
      (EnrollEffect_InsertDevice <: t_EnrollEffect)
  | AccountObservation_EpochInvalid  ->
    terminal d (EnrollFailure_KeyEpochInvalid <: t_EnrollFailure)
  | AccountObservation_RekeyRejected  -> terminal d (EnrollFailure_RekeyPolicy <: t_EnrollFailure)

let on_device_inserted (d: t_EnrollDriver) (observation: t_InsertObservation)
    : Prims.Pure t_EnrollTransition
      (requires
        enroll_state_is_sound d &&
        (match d.f_stage <: t_EnrollStage with
          | EnrollStage_Insert  -> true
          | _ -> false) &&
        d.f_epoch_positive &&
        d.f_rekey_permitted)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound d <: bool) || enroll_state_is_sound result.f_driver)) =
  match observation <: t_InsertObservation with
  | InsertObservation_Inserted  ->
    complete ({ d with f_inserted = true; f_account_epoch_active = true } <: t_EnrollDriver)
  | InsertObservation_EpochMismatch  -> terminal d (EnrollFailure_EpochConflict <: t_EnrollFailure)
  | InsertObservation_Failed  -> terminal d (EnrollFailure_InsertStorage <: t_EnrollFailure)

let stage_start (d: t_EnrollDriver) : bool =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Start  -> true
  | _ -> false

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
let step (driver: t_EnrollDriver) (event: t_EnrollEvent)
    : Prims.Pure t_EnrollTransition
      (requires enroll_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound driver <: bool) || enroll_state_is_sound result.f_driver)) =
  match event <: t_EnrollEvent with
  | EnrollEvent_ChallengeConsumed observation ->
    if stage_start driver && driver.f_authorized
    then on_challenge_consumed driver observation
    else idle driver
  | EnrollEvent_DeviceChecked observation ->
    if
      (match driver.f_stage <: t_EnrollStage with
        | EnrollStage_Device  -> true
        | _ -> false) &&
      driver.f_challenge_consumed
    then on_device_checked driver observation
    else idle driver
  | EnrollEvent_EnrollmentPrepared observation ->
    if
      (match driver.f_stage <: t_EnrollStage with
        | EnrollStage_Prepared  -> true
        | _ -> false) &&
      driver.f_device_active &&
      driver.f_auth_signature_verified
    then on_enrollment_prepared driver observation
    else idle driver
  | EnrollEvent_AccountChecked observation ->
    if
      (match driver.f_stage <: t_EnrollStage with
        | EnrollStage_Account  -> true
        | _ -> false) &&
      driver.f_keys_valid &&
      driver.f_enrollment_signature_verified
    then on_account_checked driver observation
    else idle driver
  | EnrollEvent_DeviceInserted observation ->
    if
      (match driver.f_stage <: t_EnrollStage with
        | EnrollStage_Insert  -> true
        | _ -> false) &&
      driver.f_epoch_positive &&
      driver.f_rekey_permitted
    then on_device_inserted driver observation
    else idle driver

/// Total wrapper: the handler feeds the challenge consumption outcome.
let on_challenge_consumed_event (driver: t_EnrollDriver) (observation: t_ChallengeObservation)
    : Prims.Pure t_EnrollTransition
      (requires enroll_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound driver <: bool) || enroll_state_is_sound result.f_driver)) =
  step driver (EnrollEvent_ChallengeConsumed observation <: t_EnrollEvent)

/// Total wrapper: the handler feeds the device/signature check.
let on_device_checked_event (driver: t_EnrollDriver) (observation: t_DeviceObservation)
    : Prims.Pure t_EnrollTransition
      (requires enroll_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound driver <: bool) || enroll_state_is_sound result.f_driver)) =
  step driver (EnrollEvent_DeviceChecked observation <: t_EnrollEvent)

/// Total wrapper: the handler feeds the new-key/signature check.
let on_enrollment_prepared_event (driver: t_EnrollDriver) (observation: t_EnrollmentObservation)
    : Prims.Pure t_EnrollTransition
      (requires enroll_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound driver <: bool) || enroll_state_is_sound result.f_driver)) =
  step driver (EnrollEvent_EnrollmentPrepared observation <: t_EnrollEvent)

/// Total wrapper: the handler feeds the epoch/rekey decision.
let on_account_checked_event (driver: t_EnrollDriver) (observation: t_AccountObservation)
    : Prims.Pure t_EnrollTransition
      (requires enroll_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound driver <: bool) || enroll_state_is_sound result.f_driver)) =
  step driver (EnrollEvent_AccountChecked observation <: t_EnrollEvent)

/// Total wrapper: the handler feeds the guarded insert outcome.
let on_device_inserted_event (driver: t_EnrollDriver) (observation: t_InsertObservation)
    : Prims.Pure t_EnrollTransition
      (requires enroll_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_EnrollTransition = result in
          enroll_effect_is_sound result.f_driver result.f_effect &&
          (~.(enroll_state_is_sound driver <: bool) || enroll_state_is_sound result.f_driver)) =
  step driver (EnrollEvent_DeviceInserted observation <: t_EnrollEvent)
