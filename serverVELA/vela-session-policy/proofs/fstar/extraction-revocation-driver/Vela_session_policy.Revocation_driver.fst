module Vela_session_policy.Revocation_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Actor facts established by the authenticated `DeviceSession` extractor.
/// `authenticated` is the verified PASETO identity; `device_active` is the
/// middleware's durable `devices.revoked = 0` check for device-scoped tokens.
type t_ActorObservation = {
  f_authenticated:bool;
  f_device_active:bool
}

/// The target device row as observed by the lookup query.
type t_TargetObservation = {
  f_same_account:bool;
  f_already_revoked:bool
}

/// Outcome of the target lookup. `Malformed` is a row that the handler could
/// not decode; the handler still holds the original error for rendering.
type t_DeviceLookupObservation =
  | DeviceLookupObservation_Absent : t_DeviceLookupObservation
  | DeviceLookupObservation_QueryFailed : t_DeviceLookupObservation
  | DeviceLookupObservation_Malformed : t_DeviceLookupObservation
  | DeviceLookupObservation_Present : t_TargetObservation -> t_DeviceLookupObservation

/// Outcome of the device lockout effect (`revoke_all_device_jtis` plus the
/// `device:revoked:` sentinel).
type t_LockoutObservation =
  | LockoutObservation_Applied : t_LockoutObservation
  | LockoutObservation_StorageFailed : t_LockoutObservation

/// Outcome of the durable `UPDATE devices SET revoked = 1` effect. `Failed` is
/// an observation, not proof that no row was committed.
type t_RecordObservation =
  | RecordObservation_Updated : t_RecordObservation
  | RecordObservation_Failed : t_RecordObservation

/// Outcome of the approved-web-session cascade.
type t_CascadeObservation =
  | CascadeObservation_Completed : t_CascadeObservation
  | CascadeObservation_StorageFailed : t_CascadeObservation

/// Where the revocation is in its decision sequence.
type t_RevocationStage =
  | RevocationStage_Observe : t_RevocationStage
  | RevocationStage_Lockout : t_RevocationStage
  | RevocationStage_Record : t_RevocationStage
  | RevocationStage_Cascade : t_RevocationStage
  | RevocationStage_RepeatLockout : t_RevocationStage
  | RevocationStage_RepeatCascade : t_RevocationStage
  | RevocationStage_Done : t_RevocationStage

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_RevocationEvent =
  | RevocationEvent_TargetObserved : t_DeviceLookupObservation -> t_RevocationEvent
  | RevocationEvent_LockoutObserved : t_LockoutObservation -> t_RevocationEvent
  | RevocationEvent_RecordObserved : t_RecordObservation -> t_RevocationEvent
  | RevocationEvent_CascadeObserved : t_CascadeObservation -> t_RevocationEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_RevocationFailure =
  | RevocationFailure_Unauthenticated : t_RevocationFailure
  | RevocationFailure_TargetNotFound : t_RevocationFailure
  | RevocationFailure_CrossAccount : t_RevocationFailure
  | RevocationFailure_AlreadyRevoked : t_RevocationFailure
  | RevocationFailure_TargetQueryStorage : t_RevocationFailure
  | RevocationFailure_TargetParseStorage : t_RevocationFailure
  | RevocationFailure_LockoutStorage : t_RevocationFailure
  | RevocationFailure_RecordStorage : t_RevocationFailure
  | RevocationFailure_CascadeStorage : t_RevocationFailure

/// The effect the handler must perform next.
type t_RevocationEffect =
  | RevocationEffect_LookupTarget : t_RevocationEffect
  | RevocationEffect_LockoutDevice : t_RevocationEffect
  | RevocationEffect_RecordRevocation : t_RevocationEffect
  | RevocationEffect_CascadeWebSessions : t_RevocationEffect
  | RevocationEffect_Complete : t_RevocationEffect
  | RevocationEffect_Fail : t_RevocationFailure -> t_RevocationEffect
  | RevocationEffect_Idle : t_RevocationEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
type t_RevocationDriver = {
  f_stage:t_RevocationStage;
  f_actor_active:bool;
  f_same_account:bool;
  f_already_revoked:bool;
  f_locked_out:bool;
  f_lockout_done:bool;
  f_recorded:bool;
  f_cascade_done:bool;
  f_responded:bool;
  f_failed:bool
}

type t_RevocationTransition = {
  f_driver:t_RevocationDriver;
  f_effect:t_RevocationEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let revocation_state_is_sound (d: t_RevocationDriver) : bool =
  let untouched:bool =
    ~.d.f_same_account && ~.d.f_already_revoked && ~.d.f_locked_out && ~.d.f_lockout_done &&
    ~.d.f_recorded &&
    ~.d.f_cascade_done &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let observe_clean:bool = d.f_actor_active && untouched in
  let lockout_clean:bool =
    d.f_actor_active && d.f_same_account && ~.d.f_already_revoked && d.f_locked_out &&
    ~.d.f_lockout_done &&
    ~.d.f_recorded &&
    ~.d.f_cascade_done &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let record_clean:bool =
    d.f_actor_active && d.f_same_account && ~.d.f_already_revoked && d.f_locked_out &&
    d.f_lockout_done &&
    ~.d.f_recorded &&
    ~.d.f_cascade_done &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let cascade_clean:bool =
    d.f_actor_active && d.f_same_account && ~.d.f_already_revoked && d.f_locked_out &&
    d.f_lockout_done &&
    d.f_recorded &&
    ~.d.f_cascade_done &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let repeat_lockout_clean:bool =
    d.f_actor_active && d.f_same_account && d.f_already_revoked && d.f_locked_out &&
    ~.d.f_lockout_done &&
    ~.d.f_recorded &&
    ~.d.f_cascade_done &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let repeat_cascade_clean:bool =
    d.f_actor_active && d.f_same_account && d.f_already_revoked && d.f_locked_out &&
    d.f_lockout_done &&
    ~.d.f_recorded &&
    ~.d.f_cascade_done &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done_clean:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    d.f_actor_active && d.f_same_account && ~.d.f_already_revoked && d.f_locked_out &&
    d.f_lockout_done &&
    d.f_recorded &&
    d.f_cascade_done)
  in
  (~.(match d.f_stage <: t_RevocationStage with
    | RevocationStage_Observe  -> true
    | _ -> false) ||
  observe_clean) &&
  (~.(match d.f_stage <: t_RevocationStage with
    | RevocationStage_Lockout  -> true
    | _ -> false) ||
  lockout_clean) &&
  (~.(match d.f_stage <: t_RevocationStage with
    | RevocationStage_Record  -> true
    | _ -> false) ||
  record_clean) &&
  (~.(match d.f_stage <: t_RevocationStage with
    | RevocationStage_Cascade  -> true
    | _ -> false) ||
  cascade_clean) &&
  (~.(match d.f_stage <: t_RevocationStage with
    | RevocationStage_RepeatLockout  -> true
    | _ -> false) ||
  repeat_lockout_clean) &&
  (~.(match d.f_stage <: t_RevocationStage with
    | RevocationStage_RepeatCascade  -> true
    | _ -> false) ||
  repeat_cascade_clean) &&
  (~.(match d.f_stage <: t_RevocationStage with
    | RevocationStage_Done  -> true
    | _ -> false) ||
  done_clean) &&
  (~.d.f_same_account || d.f_actor_active) &&
  (~.d.f_locked_out || d.f_actor_active) &&
  (~.d.f_already_revoked || d.f_same_account) &&
  (~.d.f_recorded || d.f_locked_out && d.f_lockout_done) &&
  (~.d.f_cascade_done || d.f_locked_out && d.f_lockout_done) &&
  (~.d.f_cascade_done || d.f_recorded || d.f_already_revoked) &&
  (~.d.f_recorded || d.f_same_account && ~.d.f_already_revoked) &&
  (~.d.f_responded || d.f_recorded && d.f_cascade_done) &&
  (~.d.f_lockout_done || d.f_locked_out)

/// Every effect the driver emits agrees with the state it produces.
let revocation_effect_is_sound (d: t_RevocationDriver) (v_effect: t_RevocationEffect) : bool =
  let common:bool =
    d.f_actor_active && d.f_same_account && d.f_locked_out && ~.d.f_responded && ~.d.f_failed
  in
  match v_effect <: t_RevocationEffect with
  | RevocationEffect_LookupTarget  ->
    (match d.f_stage <: t_RevocationStage with
      | RevocationStage_Observe  -> true
      | _ -> false) &&
    d.f_actor_active &&
    ~.d.f_same_account &&
    ~.d.f_already_revoked &&
    ~.d.f_locked_out &&
    ~.d.f_lockout_done &&
    ~.d.f_recorded &&
    ~.d.f_cascade_done &&
    ~.d.f_responded &&
    ~.d.f_failed
  | RevocationEffect_LockoutDevice  ->
    common && ~.d.f_lockout_done && ~.d.f_recorded && ~.d.f_cascade_done &&
    ((match d.f_stage <: t_RevocationStage with
      | RevocationStage_Lockout  -> true
      | _ -> false) &&
    ~.d.f_already_revoked ||
    (match d.f_stage <: t_RevocationStage with
      | RevocationStage_RepeatLockout  -> true
      | _ -> false) &&
    d.f_already_revoked)
  | RevocationEffect_RecordRevocation  ->
    common && d.f_lockout_done && ~.d.f_recorded && ~.d.f_cascade_done && ~.d.f_already_revoked &&
    (match d.f_stage <: t_RevocationStage with
      | RevocationStage_Record  -> true
      | _ -> false)
  | RevocationEffect_CascadeWebSessions  ->
    common && d.f_lockout_done && ~.d.f_cascade_done &&
    ((match d.f_stage <: t_RevocationStage with
      | RevocationStage_Cascade  -> true
      | _ -> false) &&
    d.f_recorded ||
    (match d.f_stage <: t_RevocationStage with
      | RevocationStage_RepeatCascade  -> true
      | _ -> false) &&
    d.f_already_revoked &&
    ~.d.f_recorded)
  | RevocationEffect_Complete  ->
    (match d.f_stage <: t_RevocationStage with
      | RevocationStage_Done  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_same_account &&
    ~.d.f_already_revoked &&
    d.f_locked_out &&
    d.f_lockout_done &&
    d.f_recorded &&
    d.f_cascade_done &&
    d.f_responded &&
    ~.d.f_failed
  | RevocationEffect_Fail _ ->
    (match d.f_stage <: t_RevocationStage with
      | RevocationStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | RevocationEffect_Idle  -> true

let transition (driver: t_RevocationDriver) (v_effect: t_RevocationEffect) : t_RevocationTransition =
  { f_driver = driver; f_effect = v_effect } <: t_RevocationTransition

let idle (driver: t_RevocationDriver) : t_RevocationTransition =
  transition driver (RevocationEffect_Idle <: t_RevocationEffect)

let terminal (driver: t_RevocationDriver) (failure: t_RevocationFailure) : t_RevocationTransition =
  transition ({ driver with f_stage = RevocationStage_Done <: t_RevocationStage; f_failed = true }
      <:
      t_RevocationDriver)
    (RevocationEffect_Fail failure <: t_RevocationEffect)

/// Start a per-request revocation. An actor the middleware did not verify as an
/// authenticated, active device produces a terminal failure without any
/// effect, so a revoked actor can never reach the lockout or SQL record.
let begin_revocation (actor: t_ActorObservation)
    : Prims.Pure t_RevocationTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RevocationTransition = result in
          revocation_state_is_sound result.f_driver &&
          revocation_effect_is_sound result.f_driver result.f_effect) =
  if actor.f_authenticated && actor.f_device_active
  then
    transition ({
          f_stage = RevocationStage_Observe <: t_RevocationStage;
          f_actor_active = true;
          f_same_account = false;
          f_already_revoked = false;
          f_locked_out = false;
          f_lockout_done = false;
          f_recorded = false;
          f_cascade_done = false;
          f_responded = false;
          f_failed = false
        }
        <:
        t_RevocationDriver)
      (RevocationEffect_LookupTarget <: t_RevocationEffect)
  else
    transition ({
          f_stage = RevocationStage_Done <: t_RevocationStage;
          f_actor_active = false;
          f_same_account = false;
          f_already_revoked = false;
          f_locked_out = false;
          f_lockout_done = false;
          f_recorded = false;
          f_cascade_done = false;
          f_responded = false;
          f_failed = true
        }
        <:
        t_RevocationDriver)
      (RevocationEffect_Fail (RevocationFailure_Unauthenticated <: t_RevocationFailure)
        <:
        t_RevocationEffect)

let on_target_observed (driver: t_RevocationDriver) (observation: t_DeviceLookupObservation)
    : t_RevocationTransition =
  match observation <: t_DeviceLookupObservation with
  | DeviceLookupObservation_Absent  ->
    terminal driver (RevocationFailure_TargetNotFound <: t_RevocationFailure)
  | DeviceLookupObservation_QueryFailed  ->
    terminal driver (RevocationFailure_TargetQueryStorage <: t_RevocationFailure)
  | DeviceLookupObservation_Malformed  ->
    terminal driver (RevocationFailure_TargetParseStorage <: t_RevocationFailure)
  | DeviceLookupObservation_Present target ->
    if ~.target.f_same_account
    then terminal driver (RevocationFailure_CrossAccount <: t_RevocationFailure)
    else
      if target.f_already_revoked
      then
        transition ({
              driver with
              f_stage = RevocationStage_RepeatLockout <: t_RevocationStage;
              f_same_account = true;
              f_already_revoked = true;
              f_locked_out = true
            }
            <:
            t_RevocationDriver)
          (RevocationEffect_LockoutDevice <: t_RevocationEffect)
      else
        transition ({
              driver with
              f_stage = RevocationStage_Lockout <: t_RevocationStage;
              f_same_account = true;
              f_locked_out = true
            }
            <:
            t_RevocationDriver)
          (RevocationEffect_LockoutDevice <: t_RevocationEffect)

let on_lockout_observed (driver: t_RevocationDriver) (observation: t_LockoutObservation)
    : t_RevocationTransition =
  match observation <: t_LockoutObservation with
  | LockoutObservation_Applied  ->
    if driver.f_already_revoked
    then
      transition ({
            driver with
            f_stage = RevocationStage_RepeatCascade <: t_RevocationStage;
            f_lockout_done = true
          }
          <:
          t_RevocationDriver)
        (RevocationEffect_CascadeWebSessions <: t_RevocationEffect)
    else
      transition ({
            driver with
            f_stage = RevocationStage_Record <: t_RevocationStage;
            f_lockout_done = true
          }
          <:
          t_RevocationDriver)
        (RevocationEffect_RecordRevocation <: t_RevocationEffect)
  | LockoutObservation_StorageFailed  ->
    terminal driver (RevocationFailure_LockoutStorage <: t_RevocationFailure)

let on_record_observed (driver: t_RevocationDriver) (observation: t_RecordObservation)
    : t_RevocationTransition =
  match observation <: t_RecordObservation with
  | RecordObservation_Updated  ->
    transition ({
          driver with
          f_stage = RevocationStage_Cascade <: t_RevocationStage;
          f_recorded = true
        }
        <:
        t_RevocationDriver)
      (RevocationEffect_CascadeWebSessions <: t_RevocationEffect)
  | RecordObservation_Failed  ->
    terminal driver (RevocationFailure_RecordStorage <: t_RevocationFailure)

let on_cascade_observed (driver: t_RevocationDriver) (observation: t_CascadeObservation)
    : t_RevocationTransition =
  match observation <: t_CascadeObservation with
  | CascadeObservation_Completed  ->
    if driver.f_already_revoked
    then
      transition ({
            driver with
            f_stage = RevocationStage_Done <: t_RevocationStage;
            f_cascade_done = true;
            f_failed = true
          }
          <:
          t_RevocationDriver)
        (RevocationEffect_Fail (RevocationFailure_AlreadyRevoked <: t_RevocationFailure)
          <:
          t_RevocationEffect)
    else
      transition ({
            driver with
            f_stage = RevocationStage_Done <: t_RevocationStage;
            f_cascade_done = true;
            f_responded = true
          }
          <:
          t_RevocationDriver)
        (RevocationEffect_Complete <: t_RevocationEffect)
  | CascadeObservation_StorageFailed  ->
    terminal driver (RevocationFailure_CascadeStorage <: t_RevocationFailure)

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
let step (driver: t_RevocationDriver) (event: t_RevocationEvent)
    : Prims.Pure t_RevocationTransition
      (requires revocation_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RevocationTransition = result in
          revocation_effect_is_sound result.f_driver result.f_effect &&
          (~.(revocation_state_is_sound driver <: bool) || revocation_state_is_sound result.f_driver)
      ) =
  match event <: t_RevocationEvent with
  | RevocationEvent_TargetObserved observation ->
    if
      match driver.f_stage <: t_RevocationStage with
      | RevocationStage_Observe  -> true
      | _ -> false
    then on_target_observed driver observation
    else idle driver
  | RevocationEvent_LockoutObserved observation ->
    if
      match driver.f_stage <: t_RevocationStage with
      | RevocationStage_Lockout  | RevocationStage_RepeatLockout  -> true
      | _ -> false
    then on_lockout_observed driver observation
    else idle driver
  | RevocationEvent_RecordObserved observation ->
    if
      match driver.f_stage <: t_RevocationStage with
      | RevocationStage_Record  -> true
      | _ -> false
    then on_record_observed driver observation
    else idle driver
  | RevocationEvent_CascadeObserved observation ->
    if
      match driver.f_stage <: t_RevocationStage with
      | RevocationStage_Cascade  | RevocationStage_RepeatCascade  -> true
      | _ -> false
    then on_cascade_observed driver observation
    else idle driver

let on_target_looked_up (driver: t_RevocationDriver) (observation: t_DeviceLookupObservation)
    : Prims.Pure t_RevocationTransition
      (requires revocation_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RevocationTransition = result in
          revocation_effect_is_sound result.f_driver result.f_effect &&
          (~.(revocation_state_is_sound driver <: bool) || revocation_state_is_sound result.f_driver)
      ) = step driver (RevocationEvent_TargetObserved observation <: t_RevocationEvent)

let on_lockout_completed (driver: t_RevocationDriver) (observation: t_LockoutObservation)
    : Prims.Pure t_RevocationTransition
      (requires revocation_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RevocationTransition = result in
          revocation_effect_is_sound result.f_driver result.f_effect &&
          (~.(revocation_state_is_sound driver <: bool) || revocation_state_is_sound result.f_driver)
      ) = step driver (RevocationEvent_LockoutObserved observation <: t_RevocationEvent)

let on_record_completed (driver: t_RevocationDriver) (observation: t_RecordObservation)
    : Prims.Pure t_RevocationTransition
      (requires revocation_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RevocationTransition = result in
          revocation_effect_is_sound result.f_driver result.f_effect &&
          (~.(revocation_state_is_sound driver <: bool) || revocation_state_is_sound result.f_driver)
      ) = step driver (RevocationEvent_RecordObserved observation <: t_RevocationEvent)

let on_cascade_completed (driver: t_RevocationDriver) (observation: t_CascadeObservation)
    : Prims.Pure t_RevocationTransition
      (requires revocation_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RevocationTransition = result in
          revocation_effect_is_sound result.f_driver result.f_effect &&
          (~.(revocation_state_is_sound driver <: bool) || revocation_state_is_sound result.f_driver)
      ) = step driver (RevocationEvent_CascadeObserved observation <: t_RevocationEvent)

/// Where the logout is in its decision sequence.
type t_LogoutStage =
  | LogoutStage_Apply : t_LogoutStage
  | LogoutStage_Done : t_LogoutStage

/// Outcome of the JTI revocation write.
type t_LogoutObservation =
  | LogoutObservation_Applied : t_LogoutObservation
  | LogoutObservation_StorageFailed : t_LogoutObservation

type t_LogoutFailure = | LogoutFailure_Storage : t_LogoutFailure

/// The effect the handler must perform next.
type t_LogoutEffect =
  | LogoutEffect_RevokeJti : t_LogoutEffect
  | LogoutEffect_Complete : t_LogoutEffect
  | LogoutEffect_Fail : t_LogoutFailure -> t_LogoutEffect
  | LogoutEffect_Idle : t_LogoutEffect

type t_LogoutDriver = {
  f_stage:t_LogoutStage;
  f_jti_revoked:bool;
  f_responded:bool;
  f_failed:bool
}

type t_LogoutTransition = {
  f_driver:t_LogoutDriver;
  f_effect:t_LogoutEffect
}

let logout_state_is_sound (d: t_LogoutDriver) : bool =
  let apply_clean:bool = ~.d.f_jti_revoked && ~.d.f_responded && ~.d.f_failed in
  let done_clean:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded || d.f_jti_revoked)
  in
  (~.(match d.f_stage <: t_LogoutStage with
    | LogoutStage_Apply  -> true
    | _ -> false) ||
  apply_clean) &&
  (~.(match d.f_stage <: t_LogoutStage with
    | LogoutStage_Done  -> true
    | _ -> false) ||
  done_clean) &&
  (~.d.f_responded || d.f_jti_revoked) &&
  (~.d.f_failed || ~.d.f_responded)

let logout_effect_is_sound (d: t_LogoutDriver) (v_effect: t_LogoutEffect) : bool =
  match v_effect <: t_LogoutEffect with
  | LogoutEffect_RevokeJti  ->
    (match d.f_stage <: t_LogoutStage with
      | LogoutStage_Apply  -> true
      | _ -> false) &&
    ~.d.f_jti_revoked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | LogoutEffect_Complete  ->
    (match d.f_stage <: t_LogoutStage with
      | LogoutStage_Done  -> true
      | _ -> false) &&
    d.f_jti_revoked &&
    d.f_responded &&
    ~.d.f_failed
  | LogoutEffect_Fail _ ->
    (match d.f_stage <: t_LogoutStage with
      | LogoutStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | LogoutEffect_Idle  -> true

/// Start a per-request logout. Only the JTI marker may be attempted.
let begin_logout (_: Prims.unit)
    : Prims.Pure t_LogoutTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_LogoutTransition = result in
          logout_state_is_sound result.f_driver &&
          logout_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_LogoutStage with
            | LogoutStage_Apply  -> true
            | _ -> false) &&
          (match result.f_effect <: t_LogoutEffect with
            | LogoutEffect_RevokeJti  -> true
            | _ -> false)) =
  {
    f_driver
    =
    {
      f_stage = LogoutStage_Apply <: t_LogoutStage;
      f_jti_revoked = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_LogoutDriver;
    f_effect = LogoutEffect_RevokeJti <: t_LogoutEffect
  }
  <:
  t_LogoutTransition

let on_logout_observed (driver: t_LogoutDriver) (observation: t_LogoutObservation)
    : t_LogoutTransition =
  match observation <: t_LogoutObservation with
  | LogoutObservation_Applied  ->
    {
      f_driver
      =
      {
        f_stage = LogoutStage_Done <: t_LogoutStage;
        f_jti_revoked = true;
        f_responded = true;
        f_failed = false
      }
      <:
      t_LogoutDriver;
      f_effect = LogoutEffect_Complete <: t_LogoutEffect
    }
    <:
    t_LogoutTransition
  | LogoutObservation_StorageFailed  ->
    {
      f_driver
      =
      { driver with f_stage = LogoutStage_Done <: t_LogoutStage; f_failed = true } <: t_LogoutDriver;
      f_effect = LogoutEffect_Fail (LogoutFailure_Storage <: t_LogoutFailure) <: t_LogoutEffect
    }
    <:
    t_LogoutTransition

/// The complete, total logout transition relation.
let logout_step (driver: t_LogoutDriver) (observation: t_LogoutObservation)
    : Prims.Pure t_LogoutTransition
      (requires logout_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LogoutTransition = result in
          logout_effect_is_sound result.f_driver result.f_effect &&
          (~.(logout_state_is_sound driver <: bool) || logout_state_is_sound result.f_driver)) =
  if
    match driver.f_stage <: t_LogoutStage with
    | LogoutStage_Apply  -> true
    | _ -> false
  then on_logout_observed driver observation
  else { f_driver = driver; f_effect = LogoutEffect_Idle <: t_LogoutEffect } <: t_LogoutTransition

let on_logout_completed (driver: t_LogoutDriver) (observation: t_LogoutObservation)
    : Prims.Pure t_LogoutTransition
      (requires logout_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_LogoutTransition = result in
          logout_effect_is_sound result.f_driver result.f_effect &&
          (~.(logout_state_is_sound driver <: bool) || logout_state_is_sound result.f_driver)) =
  logout_step driver observation

/// The observations that decide whether an authenticated request proceeds.
/// The middleware reads them in the same order it historically did.
type t_AdmissionObservation = {
  f_jti_revoked:bool;
  f_device_revoked:bool;
  f_account_present:bool;
  f_device_row_active:bool;
  f_device_scoped:bool
}

/// Why an authenticated request was refused.
type t_AdmissionRefusal =
  | AdmissionRefusal_JtiRevoked : t_AdmissionRefusal
  | AdmissionRefusal_DeviceRevoked : t_AdmissionRefusal
  | AdmissionRefusal_AccountAbsent : t_AdmissionRefusal
  | AdmissionRefusal_DeviceRowRevoked : t_AdmissionRefusal

type t_AdmissionDecision =
  | AdmissionDecision_Admit : t_AdmissionDecision
  | AdmissionDecision_Reject : t_AdmissionRefusal -> t_AdmissionDecision

let admission_is_authorized (o: t_AdmissionObservation) : bool =
  ~.o.f_jti_revoked && ~.o.f_device_revoked && o.f_account_present &&
  (~.o.f_device_scoped || o.f_device_row_active)

/// The independent, historical-precedence specification of the admission
/// decision: a JTI marker wins over a device sentinel, which wins over account
/// absence, which wins over the durable device-row guard.
let admission_decision_matches_spec (o: t_AdmissionObservation) (decision: t_AdmissionDecision)
    : bool =
  match decision <: t_AdmissionDecision with
  | AdmissionDecision_Admit  -> admission_is_authorized o
  | AdmissionDecision_Reject refusal ->
    match refusal <: t_AdmissionRefusal with
    | AdmissionRefusal_JtiRevoked  -> o.f_jti_revoked
    | AdmissionRefusal_DeviceRevoked  -> ~.o.f_jti_revoked && o.f_device_revoked
    | AdmissionRefusal_AccountAbsent  ->
      ~.o.f_jti_revoked && ~.o.f_device_revoked && ~.o.f_account_present
    | AdmissionRefusal_DeviceRowRevoked  ->
      ~.o.f_jti_revoked && ~.o.f_device_revoked && o.f_account_present && o.f_device_scoped &&
      ~.o.f_device_row_active

let plan_admission (observation: t_AdmissionObservation)
    : Prims.Pure t_AdmissionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_AdmissionDecision = decision in
          admission_decision_matches_spec observation decision) =
  if observation.f_jti_revoked
  then
    AdmissionDecision_Reject (AdmissionRefusal_JtiRevoked <: t_AdmissionRefusal)
    <:
    t_AdmissionDecision
  else
    if observation.f_device_revoked
    then
      AdmissionDecision_Reject (AdmissionRefusal_DeviceRevoked <: t_AdmissionRefusal)
      <:
      t_AdmissionDecision
    else
      if ~.observation.f_account_present
      then
        AdmissionDecision_Reject (AdmissionRefusal_AccountAbsent <: t_AdmissionRefusal)
        <:
        t_AdmissionDecision
      else
        if observation.f_device_scoped && ~.observation.f_device_row_active
        then
          AdmissionDecision_Reject (AdmissionRefusal_DeviceRowRevoked <: t_AdmissionRefusal)
          <:
          t_AdmissionDecision
        else AdmissionDecision_Admit <: t_AdmissionDecision

/// Direct theorem used by the F* gate: a revoked JTI is never admitted,
/// regardless of the other observations.
let revoked_jti_can_be_admitted (observation: t_AdmissionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let observation:t_AdmissionObservation =
    { observation with f_jti_revoked = true } <: t_AdmissionObservation
  in
  match plan_admission observation <: t_AdmissionDecision with
  | AdmissionDecision_Admit  -> true
  | _ -> false

/// Direct theorem used by the F* gate: a device sentinel refuses admission,
/// regardless of the other observations.
let revoked_device_can_be_admitted (observation: t_AdmissionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let observation:t_AdmissionObservation =
    { observation with f_jti_revoked = false } <: t_AdmissionObservation
  in
  let observation:t_AdmissionObservation =
    { observation with f_device_revoked = true } <: t_AdmissionObservation
  in
  match plan_admission observation <: t_AdmissionDecision with
  | AdmissionDecision_Admit  -> true
  | _ -> false

/// Direct theorem used by the F* gate: the durable device-row guard refuses a
/// device-scoped token even when both revocation markers are clear.
let revoked_device_row_can_be_admitted (observation: t_AdmissionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let observation:t_AdmissionObservation =
    { observation with f_jti_revoked = false } <: t_AdmissionObservation
  in
  let observation:t_AdmissionObservation =
    { observation with f_device_revoked = false } <: t_AdmissionObservation
  in
  let observation:t_AdmissionObservation =
    { observation with f_account_present = true } <: t_AdmissionObservation
  in
  let observation:t_AdmissionObservation =
    { observation with f_device_scoped = true } <: t_AdmissionObservation
  in
  let observation:t_AdmissionObservation =
    { observation with f_device_row_active = false } <: t_AdmissionObservation
  in
  match plan_admission observation <: t_AdmissionDecision with
  | AdmissionDecision_Admit  -> true
  | _ -> false
