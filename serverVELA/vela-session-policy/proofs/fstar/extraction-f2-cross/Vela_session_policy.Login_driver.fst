module Vela_session_policy.Login_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Where the login is in its decision sequence. Each stage names the effect
/// the handler may perform next.
type t_LoginStage =
  | LoginStage_Challenge : t_LoginStage
  | LoginStage_Device : t_LoginStage
  | LoginStage_Verify : t_LoginStage
  | LoginStage_RecordFailure : t_LoginStage
  | LoginStage_Reset : t_LoginStage
  | LoginStage_Issue : t_LoginStage
  | LoginStage_Track : t_LoginStage
  | LoginStage_Done : t_LoginStage

/// Observation from the atomic challenge take. `StorageFailed` is the
/// `get_del` error; the handler still holds the original error for rendering.
type t_ChallengeObservation =
  | ChallengeObservation_Observed : Vela_session_policy.Challenge.t_ChallengeConsumption
    -> t_ChallengeObservation
  | ChallengeObservation_StorageFailed : t_ChallengeObservation

/// Observation from the device lookup. `Present` means the query returned a
/// row with `revoked = 0` and it decoded into a device. `Absent` is the
/// historical uniform authentication failure; the other two preserve the
/// handler's internal-error precedence.
type t_DeviceObservation =
  | DeviceObservation_Present : t_DeviceObservation
  | DeviceObservation_Absent : t_DeviceObservation
  | DeviceObservation_QueryFailed : t_DeviceObservation
  | DeviceObservation_ParseFailed : t_DeviceObservation

/// The verifier failure class, retained until the failure side effects have
/// been observed. `None` means no verifier rejection is pending.
type t_VerifierFailure =
  | VerifierFailure_None : t_VerifierFailure
  | VerifierFailure_Unauthorized : t_VerifierFailure
  | VerifierFailure_BadRequest : t_VerifierFailure
  | VerifierFailure_Internal : t_VerifierFailure

/// Observation from the actual verifier. `Valid` is the only successful
/// result. `ChallengeDecodeFailed` is the handler's base64 decode failure,
/// which occurs before the verifier and does not touch the failure counter
/// (matching the historical order). The three rejection classes preserve the
/// handler's status/message precedence.
type t_VerifierObservation =
  | VerifierObservation_Valid : t_VerifierObservation
  | VerifierObservation_RejectedUnauthorized : t_VerifierObservation
  | VerifierObservation_RejectedBadRequest : t_VerifierObservation
  | VerifierObservation_RejectedInternal : t_VerifierObservation
  | VerifierObservation_ChallengeDecodeFailed : t_VerifierObservation

/// Observation after the handler performed the rejection side effects.
/// `record_verify_failure` is attempted and its error is only logged, so it
/// cannot change the decision; `fallback_counter_ok` is the result of the
/// request-level `verify_fail_by_device` limiter, which the handler still
/// propagates.
type t_FailureRecordObservation = { f_fallback_counter_ok:bool }

/// Observation from the success-streak/backoff reset.
type t_BackoffResetObservation =
  | BackoffResetObservation_Reset : t_BackoffResetObservation
  | BackoffResetObservation_StorageFailed : t_BackoffResetObservation

/// Observation from PASETO issuance. Issuance itself is the existing
/// `TokenService::issue`, which uses the verified `plan_device_token` policy;
/// the driver treats the result as a trusted observation.
type t_TokenIssueObservation =
  | TokenIssueObservation_Issued : t_TokenIssueObservation
  | TokenIssueObservation_Failed : t_TokenIssueObservation

/// Observation from JTI tracking. A failed track must not produce a response.
type t_TokenTrackObservation =
  | TokenTrackObservation_Tracked : t_TokenTrackObservation
  | TokenTrackObservation_Failed : t_TokenTrackObservation

/// One driver event. The handler feeds exactly the observation it obtained from
/// the corresponding effect.
type t_LoginEvent =
  | LoginEvent_ChallengeObserved : t_ChallengeObservation -> t_LoginEvent
  | LoginEvent_DeviceObserved : t_DeviceObservation -> t_LoginEvent
  | LoginEvent_VerifierObserved : t_VerifierObservation -> t_LoginEvent
  | LoginEvent_FailureRecorded : t_FailureRecordObservation -> t_LoginEvent
  | LoginEvent_BackoffResetObserved : t_BackoffResetObservation -> t_LoginEvent
  | LoginEvent_TokenIssued : t_TokenIssueObservation -> t_LoginEvent
  | LoginEvent_TokenTracked : t_TokenTrackObservation -> t_LoginEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders each category with the original error where
/// the error text is not a fixed authentication message.
type t_LoginFailure =
  | LoginFailure_ChallengeMissing : t_LoginFailure
  | LoginFailure_ChallengeWrongPurpose : t_LoginFailure
  | LoginFailure_ChallengeStorage : t_LoginFailure
  | LoginFailure_DeviceUnavailable : t_LoginFailure
  | LoginFailure_DeviceQueryStorage : t_LoginFailure
  | LoginFailure_DeviceParseStorage : t_LoginFailure
  | LoginFailure_ChallengeDecode : t_LoginFailure
  | LoginFailure_VerifierUnauthorized : t_LoginFailure
  | LoginFailure_VerifierBadRequest : t_LoginFailure
  | LoginFailure_VerifierInternal : t_LoginFailure
  | LoginFailure_FailureCounterStorage : t_LoginFailure
  | LoginFailure_BackoffResetStorage : t_LoginFailure
  | LoginFailure_TokenIssueFailed : t_LoginFailure
  | LoginFailure_TrackingFailed : t_LoginFailure

/// The effect the handler must perform next.
type t_LoginEffect =
  | LoginEffect_ConsumeChallenge : t_LoginEffect
  | LoginEffect_ObserveDevice : t_LoginEffect
  | LoginEffect_VerifySignature : t_LoginEffect
  | LoginEffect_RecordVerificationFailure : t_LoginEffect
  | LoginEffect_ResetBackoff : t_LoginEffect
  | LoginEffect_IssueToken : t_LoginEffect
  | LoginEffect_TrackToken : t_LoginEffect
  | LoginEffect_Respond : t_LoginEffect
  | LoginEffect_Fail : t_LoginFailure -> t_LoginEffect
  | LoginEffect_Idle : t_LoginEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store, SQL row or verifier.
type t_LoginDriver = {
  f_stage:t_LoginStage;
  f_challenge_accepted:bool;
  f_device_present:bool;
  f_verifier_valid:bool;
  f_verifier_failure:t_VerifierFailure;
  f_backoff_reset:bool;
  f_token_issued:bool;
  f_token_tracked:bool;
  f_responded:bool;
  f_failed:bool
}

type t_LoginTransition = {
  f_driver:t_LoginDriver;
  f_effect:t_LoginEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let login_state_is_sound (d: t_LoginDriver) : bool =
  let no_pending_verifier_failure:bool =
    match d.f_verifier_failure <: t_VerifierFailure with
    | VerifierFailure_None  -> true
    | _ -> false
  in
  let challenge_clean:bool =
    ~.d.f_challenge_accepted && ~.d.f_device_present && ~.d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let device_clean:bool =
    d.f_challenge_accepted && ~.d.f_device_present && ~.d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let verify_clean:bool =
    d.f_challenge_accepted && d.f_device_present && ~.d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let record_clean:bool =
    d.f_challenge_accepted && d.f_device_present && ~.d.f_verifier_valid &&
    ~.no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let reset_clean:bool =
    d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let issue_clean:bool =
    d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
    no_pending_verifier_failure &&
    d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let track_clean:bool =
    d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
    no_pending_verifier_failure &&
    d.f_backoff_reset &&
    d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done_clean:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
    no_pending_verifier_failure &&
    d.f_backoff_reset &&
    d.f_token_issued &&
    d.f_token_tracked)
  in
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_Challenge  -> true
    | _ -> false) ||
  challenge_clean) &&
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_Device  -> true
    | _ -> false) ||
  device_clean) &&
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_Verify  -> true
    | _ -> false) ||
  verify_clean) &&
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_RecordFailure  -> true
    | _ -> false) ||
  record_clean) &&
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_Reset  -> true
    | _ -> false) ||
  reset_clean) &&
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_Issue  -> true
    | _ -> false) ||
  issue_clean) &&
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_Track  -> true
    | _ -> false) ||
  track_clean) &&
  (~.(match d.f_stage <: t_LoginStage with
    | LoginStage_Done  -> true
    | _ -> false) ||
  done_clean) &&
  (~.d.f_device_present || d.f_challenge_accepted) &&
  (~.d.f_verifier_valid || d.f_device_present) &&
  (~.d.f_backoff_reset || d.f_verifier_valid) &&
  (~.d.f_token_issued || d.f_backoff_reset) &&
  (~.d.f_token_tracked || d.f_token_issued) &&
  (~.d.f_responded || d.f_token_tracked) &&
  (~.d.f_failed || ~.d.f_responded) &&
  (no_pending_verifier_failure || ~.d.f_verifier_valid)

/// Every effect agrees with the state it produces. In particular `Respond`
/// requires a tracked token, an accepted matching-purpose challenge, a present
/// device, a valid verifier result and a successful backoff reset.
let login_effect_is_sound (d: t_LoginDriver) (v_effect: t_LoginEffect) : bool =
  let no_pending_verifier_failure:bool =
    match d.f_verifier_failure <: t_VerifierFailure with
    | VerifierFailure_None  -> true
    | _ -> false
  in
  match v_effect <: t_LoginEffect with
  | LoginEffect_ConsumeChallenge  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Challenge  -> true
      | _ -> false) &&
    ~.d.f_challenge_accepted &&
    ~.d.f_device_present &&
    ~.d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LoginEffect_ObserveDevice  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Device  -> true
      | _ -> false) &&
    d.f_challenge_accepted &&
    ~.d.f_device_present &&
    ~.d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LoginEffect_VerifySignature  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Verify  -> true
      | _ -> false) &&
    d.f_challenge_accepted &&
    d.f_device_present &&
    ~.d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LoginEffect_RecordVerificationFailure  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_RecordFailure  -> true
      | _ -> false) &&
    d.f_challenge_accepted &&
    d.f_device_present &&
    ~.d.f_verifier_valid &&
    ~.no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LoginEffect_ResetBackoff  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Reset  -> true
      | _ -> false) &&
    d.f_challenge_accepted &&
    d.f_device_present &&
    d.f_verifier_valid &&
    no_pending_verifier_failure &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LoginEffect_IssueToken  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Issue  -> true
      | _ -> false) &&
    d.f_challenge_accepted &&
    d.f_device_present &&
    d.f_verifier_valid &&
    no_pending_verifier_failure &&
    d.f_backoff_reset &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LoginEffect_TrackToken  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Track  -> true
      | _ -> false) &&
    d.f_challenge_accepted &&
    d.f_device_present &&
    d.f_verifier_valid &&
    no_pending_verifier_failure &&
    d.f_backoff_reset &&
    d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LoginEffect_Respond  ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Done  -> true
      | _ -> false) &&
    d.f_challenge_accepted &&
    d.f_device_present &&
    d.f_verifier_valid &&
    no_pending_verifier_failure &&
    d.f_backoff_reset &&
    d.f_token_issued &&
    d.f_token_tracked &&
    d.f_responded &&
    ~.d.f_failed
  | LoginEffect_Fail _ ->
    (match d.f_stage <: t_LoginStage with
      | LoginStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | LoginEffect_Idle  -> true

let transition (driver: t_LoginDriver) (v_effect: t_LoginEffect) : t_LoginTransition =
  { f_driver = driver; f_effect = v_effect } <: t_LoginTransition

let idle (driver: t_LoginDriver) : t_LoginTransition =
  transition driver (LoginEffect_Idle <: t_LoginEffect)

let terminal (driver: t_LoginDriver) (failure: t_LoginFailure) : t_LoginTransition =
  transition ({ driver with f_stage = LoginStage_Done <: t_LoginStage; f_failed = true }
      <:
      t_LoginDriver)
    (LoginEffect_Fail failure <: t_LoginEffect)

/// The pending verifier class. `None` is unreachable from `RecordFailure`
/// (the state invariant excludes it); mapping it to `VerifierInternal` keeps
/// the total transition relation total without weakening the checked path.
let pending_verifier_failure (value: t_VerifierFailure) : t_LoginFailure =
  match value <: t_VerifierFailure with
  | VerifierFailure_Unauthorized  -> LoginFailure_VerifierUnauthorized <: t_LoginFailure
  | VerifierFailure_BadRequest  -> LoginFailure_VerifierBadRequest <: t_LoginFailure
  | VerifierFailure_Internal
  | VerifierFailure_None  -> LoginFailure_VerifierInternal <: t_LoginFailure

/// Start a per-request login. Only the challenge take may be attempted.
let begin_login (_: Prims.unit)
    : Prims.Pure t_LoginTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_state_is_sound result.f_driver &&
          login_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_LoginStage with
            | LoginStage_Challenge  -> true
            | _ -> false) &&
          ~.result.f_driver.f_challenge_accepted &&
          ~.result.f_driver.f_device_present &&
          ~.result.f_driver.f_verifier_valid &&
          ~.result.f_driver.f_backoff_reset &&
          ~.result.f_driver.f_token_issued &&
          ~.result.f_driver.f_token_tracked &&
          ~.result.f_driver.f_responded &&
          ~.result.f_driver.f_failed) =
  transition ({
        f_stage = LoginStage_Challenge <: t_LoginStage;
        f_challenge_accepted = false;
        f_device_present = false;
        f_verifier_valid = false;
        f_verifier_failure = VerifierFailure_None <: t_VerifierFailure;
        f_backoff_reset = false;
        f_token_issued = false;
        f_token_tracked = false;
        f_responded = false;
        f_failed = false
      }
      <:
      t_LoginDriver)
    (LoginEffect_ConsumeChallenge <: t_LoginEffect)

let on_challenge_observed (driver: t_LoginDriver) (observation: t_ChallengeObservation)
    : t_LoginTransition =
  match observation <: t_ChallengeObservation with
  | ChallengeObservation_Observed (Vela_session_policy.Challenge.ChallengeConsumption_Accepted ) ->
    transition ({
          driver with
          f_stage = LoginStage_Device <: t_LoginStage;
          f_challenge_accepted = true
        }
        <:
        t_LoginDriver)
      (LoginEffect_ObserveDevice <: t_LoginEffect)
  | ChallengeObservation_Observed (Vela_session_policy.Challenge.ChallengeConsumption_Missing ) ->
    terminal driver (LoginFailure_ChallengeMissing <: t_LoginFailure)
  | ChallengeObservation_Observed (Vela_session_policy.Challenge.ChallengeConsumption_WrongPurpose ) ->
    terminal driver (LoginFailure_ChallengeWrongPurpose <: t_LoginFailure)
  | ChallengeObservation_StorageFailed  ->
    terminal driver (LoginFailure_ChallengeStorage <: t_LoginFailure)

let on_device_observed (driver: t_LoginDriver) (observation: t_DeviceObservation)
    : t_LoginTransition =
  match observation <: t_DeviceObservation with
  | DeviceObservation_Present  ->
    transition ({ driver with f_stage = LoginStage_Verify <: t_LoginStage; f_device_present = true }
        <:
        t_LoginDriver)
      (LoginEffect_VerifySignature <: t_LoginEffect)
  | DeviceObservation_Absent  -> terminal driver (LoginFailure_DeviceUnavailable <: t_LoginFailure)
  | DeviceObservation_QueryFailed  ->
    terminal driver (LoginFailure_DeviceQueryStorage <: t_LoginFailure)
  | DeviceObservation_ParseFailed  ->
    terminal driver (LoginFailure_DeviceParseStorage <: t_LoginFailure)

let on_verifier_observed (driver: t_LoginDriver) (observation: t_VerifierObservation)
    : t_LoginTransition =
  match observation <: t_VerifierObservation with
  | VerifierObservation_Valid  ->
    transition ({
          driver with
          f_stage = LoginStage_Reset <: t_LoginStage;
          f_verifier_valid = true;
          f_verifier_failure = VerifierFailure_None <: t_VerifierFailure
        }
        <:
        t_LoginDriver)
      (LoginEffect_ResetBackoff <: t_LoginEffect)
  | VerifierObservation_RejectedUnauthorized  ->
    transition ({
          driver with
          f_stage = LoginStage_RecordFailure <: t_LoginStage;
          f_verifier_valid = false;
          f_verifier_failure = VerifierFailure_Unauthorized <: t_VerifierFailure
        }
        <:
        t_LoginDriver)
      (LoginEffect_RecordVerificationFailure <: t_LoginEffect)
  | VerifierObservation_RejectedBadRequest  ->
    transition ({
          driver with
          f_stage = LoginStage_RecordFailure <: t_LoginStage;
          f_verifier_valid = false;
          f_verifier_failure = VerifierFailure_BadRequest <: t_VerifierFailure
        }
        <:
        t_LoginDriver)
      (LoginEffect_RecordVerificationFailure <: t_LoginEffect)
  | VerifierObservation_RejectedInternal  ->
    transition ({
          driver with
          f_stage = LoginStage_RecordFailure <: t_LoginStage;
          f_verifier_valid = false;
          f_verifier_failure = VerifierFailure_Internal <: t_VerifierFailure
        }
        <:
        t_LoginDriver)
      (LoginEffect_RecordVerificationFailure <: t_LoginEffect)
  | VerifierObservation_ChallengeDecodeFailed  ->
    terminal driver (LoginFailure_ChallengeDecode <: t_LoginFailure)

let on_failure_recorded (driver: t_LoginDriver) (observation: t_FailureRecordObservation)
    : t_LoginTransition =
  if observation.f_fallback_counter_ok
  then terminal driver (pending_verifier_failure driver.f_verifier_failure <: t_LoginFailure)
  else terminal driver (LoginFailure_FailureCounterStorage <: t_LoginFailure)

let on_backoff_reset_observed (driver: t_LoginDriver) (observation: t_BackoffResetObservation)
    : t_LoginTransition =
  match observation <: t_BackoffResetObservation with
  | BackoffResetObservation_Reset  ->
    transition ({ driver with f_stage = LoginStage_Issue <: t_LoginStage; f_backoff_reset = true }
        <:
        t_LoginDriver)
      (LoginEffect_IssueToken <: t_LoginEffect)
  | BackoffResetObservation_StorageFailed  ->
    terminal driver (LoginFailure_BackoffResetStorage <: t_LoginFailure)

let on_token_issued (driver: t_LoginDriver) (observation: t_TokenIssueObservation)
    : t_LoginTransition =
  match observation <: t_TokenIssueObservation with
  | TokenIssueObservation_Issued  ->
    transition ({ driver with f_stage = LoginStage_Track <: t_LoginStage; f_token_issued = true }
        <:
        t_LoginDriver)
      (LoginEffect_TrackToken <: t_LoginEffect)
  | TokenIssueObservation_Failed  ->
    terminal driver (LoginFailure_TokenIssueFailed <: t_LoginFailure)

let on_token_tracked (driver: t_LoginDriver) (observation: t_TokenTrackObservation)
    : t_LoginTransition =
  match observation <: t_TokenTrackObservation with
  | TokenTrackObservation_Tracked  ->
    transition ({
          driver with
          f_stage = LoginStage_Done <: t_LoginStage;
          f_token_tracked = true;
          f_responded = true
        }
        <:
        t_LoginDriver)
      (LoginEffect_Respond <: t_LoginEffect)
  | TokenTrackObservation_Failed  -> terminal driver (LoginFailure_TrackingFailed <: t_LoginFailure)

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
let step (driver: t_LoginDriver) (event: t_LoginEvent)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  match event <: t_LoginEvent with
  | LoginEvent_ChallengeObserved observation ->
    if
      match driver.f_stage <: t_LoginStage with
      | LoginStage_Challenge  -> true
      | _ -> false
    then on_challenge_observed driver observation
    else idle driver
  | LoginEvent_DeviceObserved observation ->
    if
      match driver.f_stage <: t_LoginStage with
      | LoginStage_Device  -> true
      | _ -> false
    then on_device_observed driver observation
    else idle driver
  | LoginEvent_VerifierObserved observation ->
    if
      match driver.f_stage <: t_LoginStage with
      | LoginStage_Verify  -> true
      | _ -> false
    then on_verifier_observed driver observation
    else idle driver
  | LoginEvent_FailureRecorded observation ->
    if
      match driver.f_stage <: t_LoginStage with
      | LoginStage_RecordFailure  -> true
      | _ -> false
    then on_failure_recorded driver observation
    else idle driver
  | LoginEvent_BackoffResetObserved observation ->
    if
      match driver.f_stage <: t_LoginStage with
      | LoginStage_Reset  -> true
      | _ -> false
    then on_backoff_reset_observed driver observation
    else idle driver
  | LoginEvent_TokenIssued observation ->
    if
      match driver.f_stage <: t_LoginStage with
      | LoginStage_Issue  -> true
      | _ -> false
    then on_token_issued driver observation
    else idle driver
  | LoginEvent_TokenTracked observation ->
    if
      match driver.f_stage <: t_LoginStage with
      | LoginStage_Track  -> true
      | _ -> false
    then on_token_tracked driver observation
    else idle driver

let on_challenge_taken (driver: t_LoginDriver) (observation: t_ChallengeObservation)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  step driver (LoginEvent_ChallengeObserved observation <: t_LoginEvent)

let on_device_looked_up (driver: t_LoginDriver) (observation: t_DeviceObservation)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  step driver (LoginEvent_DeviceObserved observation <: t_LoginEvent)

let on_verifier_finished (driver: t_LoginDriver) (observation: t_VerifierObservation)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  step driver (LoginEvent_VerifierObserved observation <: t_LoginEvent)

let on_failure_record_observed (driver: t_LoginDriver) (observation: t_FailureRecordObservation)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  step driver (LoginEvent_FailureRecorded observation <: t_LoginEvent)

let on_backoff_reset_observed_event (driver: t_LoginDriver) (observation: t_BackoffResetObservation)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  step driver (LoginEvent_BackoffResetObserved observation <: t_LoginEvent)

let on_token_issue_observed (driver: t_LoginDriver) (observation: t_TokenIssueObservation)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  step driver (LoginEvent_TokenIssued observation <: t_LoginEvent)

let on_token_track_observed (driver: t_LoginDriver) (observation: t_TokenTrackObservation)
    : Prims.Pure t_LoginTransition
      (requires login_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LoginTransition = result in
          login_effect_is_sound result.f_driver result.f_effect &&
          (~.(login_state_is_sound driver <: bool) || login_state_is_sound result.f_driver)) =
  step driver (LoginEvent_TokenTracked observation <: t_LoginEvent)
