module Vela_session_policy.Websession_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Observation from the per-IP start limiter.
type t_StartLimitObservation =
  | StartLimitObservation_Allowed : t_StartLimitObservation
  | StartLimitObservation_Limited : t_StartLimitObservation

/// Observation from the (pure, but message-preserving) request validation.
type t_StartValidationObservation =
  | StartValidationObservation_Valid : t_StartValidationObservation
  | StartValidationObservation_Invalid : t_StartValidationObservation

/// Observation from the one `INSERT ... status = 'pending'`.
type t_StartInsertObservation =
  | StartInsertObservation_Inserted : t_StartInsertObservation
  | StartInsertObservation_Failed : t_StartInsertObservation

/// Where a browser start is in its decision sequence.
type t_StartStage =
  | StartStage_Limit : t_StartStage
  | StartStage_Validate : t_StartStage
  | StartStage_Insert : t_StartStage
  | StartStage_Done : t_StartStage

/// One driver event for `POST /web-session/start`.
type t_StartEvent =
  | StartEvent_LimitObserved : t_StartLimitObservation -> t_StartEvent
  | StartEvent_Validated : t_StartValidationObservation -> t_StartEvent
  | StartEvent_Inserted : t_StartInsertObservation -> t_StartEvent

/// Failure categories for a browser start.
type t_StartFailure =
  | StartFailure_RateLimited : t_StartFailure
  | StartFailure_Validation : t_StartFailure
  | StartFailure_InsertStorage : t_StartFailure

/// The effect the handler must perform next.
type t_StartEffect =
  | StartEffect_CheckRateLimit : t_StartEffect
  | StartEffect_ValidateStart : t_StartEffect
  | StartEffect_InsertPending : t_StartEffect
  | StartEffect_Complete : t_StartEffect
  | StartEffect_Fail : t_StartFailure -> t_StartEffect
  | StartEffect_Idle : t_StartEffect

/// Per-request start state.
type t_StartDriver = {
  f_stage:t_StartStage;
  f_limited_ok:bool;
  f_validated:bool;
  f_inserted:bool;
  f_responded:bool;
  f_failed:bool
}

type t_StartTransition = {
  f_driver:t_StartDriver;
  f_effect:t_StartEffect
}

/// State invariant: the pending insert happens only after the limiter and
/// validation, and a response only after that insert. There is no state in
/// which a start has granted, issued or revoked anything.
let start_state_is_sound (d: t_StartDriver) : bool =
  let limit:bool =
    ~.d.f_limited_ok && ~.d.f_validated && ~.d.f_inserted && ~.d.f_responded && ~.d.f_failed
  in
  let validate:bool =
    d.f_limited_ok && ~.d.f_validated && ~.d.f_inserted && ~.d.f_responded && ~.d.f_failed
  in
  let insert:bool =
    d.f_limited_ok && d.f_validated && ~.d.f_inserted && ~.d.f_responded && ~.d.f_failed
  in
  let done:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded || d.f_inserted)
  in
  (~.(match d.f_stage <: t_StartStage with
    | StartStage_Limit  -> true
    | _ -> false) ||
  limit) &&
  (~.(match d.f_stage <: t_StartStage with
    | StartStage_Validate  -> true
    | _ -> false) ||
  validate) &&
  (~.(match d.f_stage <: t_StartStage with
    | StartStage_Insert  -> true
    | _ -> false) ||
  insert) &&
  (~.(match d.f_stage <: t_StartStage with
    | StartStage_Done  -> true
    | _ -> false) ||
  done) &&
  (~.d.f_validated || d.f_limited_ok) &&
  (~.d.f_inserted || d.f_validated) &&
  (~.d.f_responded || d.f_inserted) &&
  (~.d.f_failed || ~.d.f_responded)

/// Every emitted effect agrees with the state that produced it.
let start_effect_is_sound (d: t_StartDriver) (v_effect: t_StartEffect) : bool =
  match v_effect <: t_StartEffect with
  | StartEffect_CheckRateLimit  ->
    (match d.f_stage <: t_StartStage with
      | StartStage_Limit  -> true
      | _ -> false) &&
    ~.d.f_limited_ok &&
    ~.d.f_validated &&
    ~.d.f_inserted &&
    ~.d.f_responded &&
    ~.d.f_failed
  | StartEffect_ValidateStart  ->
    (match d.f_stage <: t_StartStage with
      | StartStage_Validate  -> true
      | _ -> false) &&
    d.f_limited_ok &&
    ~.d.f_validated &&
    ~.d.f_inserted &&
    ~.d.f_responded &&
    ~.d.f_failed
  | StartEffect_InsertPending  ->
    (match d.f_stage <: t_StartStage with
      | StartStage_Insert  -> true
      | _ -> false) &&
    d.f_limited_ok &&
    d.f_validated &&
    ~.d.f_inserted &&
    ~.d.f_responded &&
    ~.d.f_failed
  | StartEffect_Complete  ->
    (match d.f_stage <: t_StartStage with
      | StartStage_Done  -> true
      | _ -> false) &&
    d.f_inserted &&
    d.f_responded &&
    ~.d.f_failed
  | StartEffect_Fail _ ->
    (match d.f_stage <: t_StartStage with
      | StartStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | StartEffect_Idle  -> true

let start_transition (driver: t_StartDriver) (v_effect: t_StartEffect) : t_StartTransition =
  { f_driver = driver; f_effect = v_effect } <: t_StartTransition

let start_idle (driver: t_StartDriver) : t_StartTransition =
  start_transition driver (StartEffect_Idle <: t_StartEffect)

let start_terminal (driver: t_StartDriver) (failure: t_StartFailure) : t_StartTransition =
  start_transition ({ driver with f_stage = StartStage_Done <: t_StartStage; f_failed = true }
      <:
      t_StartDriver)
    (StartEffect_Fail failure <: t_StartEffect)

let start_blank (_: Prims.unit) : t_StartDriver =
  {
    f_stage = StartStage_Limit <: t_StartStage;
    f_limited_ok = false;
    f_validated = false;
    f_inserted = false;
    f_responded = false;
    f_failed = false
  }
  <:
  t_StartDriver

/// Start the unauthenticated browser flow. The only effect that mutates state
/// after this point is the pending insert; the driver cannot grant or issue.
let begin_start (_: Prims.unit)
    : Prims.Pure t_StartTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_StartTransition = result in
          start_state_is_sound result.f_driver &&
          start_effect_is_sound result.f_driver result.f_effect) =
  start_transition (start_blank () <: t_StartDriver) (StartEffect_CheckRateLimit <: t_StartEffect)

let on_start_limit (driver: t_StartDriver) (observation: t_StartLimitObservation)
    : t_StartTransition =
  match observation <: t_StartLimitObservation with
  | StartLimitObservation_Allowed  ->
    start_transition ({
          driver with
          f_stage = StartStage_Validate <: t_StartStage;
          f_limited_ok = true
        }
        <:
        t_StartDriver)
      (StartEffect_ValidateStart <: t_StartEffect)
  | StartLimitObservation_Limited  ->
    start_terminal driver (StartFailure_RateLimited <: t_StartFailure)

let on_start_validated (driver: t_StartDriver) (observation: t_StartValidationObservation)
    : t_StartTransition =
  match observation <: t_StartValidationObservation with
  | StartValidationObservation_Valid  ->
    start_transition ({
          driver with
          f_stage = StartStage_Insert <: t_StartStage;
          f_validated = true
        }
        <:
        t_StartDriver)
      (StartEffect_InsertPending <: t_StartEffect)
  | StartValidationObservation_Invalid  ->
    start_terminal driver (StartFailure_Validation <: t_StartFailure)

let on_start_inserted (driver: t_StartDriver) (observation: t_StartInsertObservation)
    : t_StartTransition =
  match observation <: t_StartInsertObservation with
  | StartInsertObservation_Inserted  ->
    start_transition ({
          driver with
          f_stage = StartStage_Done <: t_StartStage;
          f_inserted = true;
          f_responded = true
        }
        <:
        t_StartDriver)
      (StartEffect_Complete <: t_StartEffect)
  | StartInsertObservation_Failed  ->
    start_terminal driver (StartFailure_InsertStorage <: t_StartFailure)

/// The total start transition relation.
let start_step (driver: t_StartDriver) (event: t_StartEvent)
    : Prims.Pure t_StartTransition
      (requires start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_StartTransition = result in
          start_effect_is_sound result.f_driver result.f_effect &&
          (~.(start_state_is_sound driver <: bool) || start_state_is_sound result.f_driver)) =
  match event <: t_StartEvent with
  | StartEvent_LimitObserved observation ->
    if
      match driver.f_stage <: t_StartStage with
      | StartStage_Limit  -> true
      | _ -> false
    then on_start_limit driver observation
    else start_idle driver
  | StartEvent_Validated observation ->
    if
      match driver.f_stage <: t_StartStage with
      | StartStage_Validate  -> true
      | _ -> false
    then on_start_validated driver observation
    else start_idle driver
  | StartEvent_Inserted observation ->
    if
      match driver.f_stage <: t_StartStage with
      | StartStage_Insert  -> true
      | _ -> false
    then on_start_inserted driver observation
    else start_idle driver

/// Actor facts established by the authenticated `DeviceSession` extractor.
type t_GrantActorObservation = {
  f_authenticated:bool;
  f_device_active:bool
}

/// Observation from mode/epoch/capsule validation.
type t_GrantValidationObservation =
  | GrantValidationObservation_Valid : t_GrantValidationObservation
  | GrantValidationObservation_Invalid : t_GrantValidationObservation

/// Outcome of the session row lookup.
type t_GrantLookupObservation =
  | GrantLookupObservation_Absent : t_GrantLookupObservation
  | GrantLookupObservation_QueryFailed : t_GrantLookupObservation
  | GrantLookupObservation_Present : Vela_session_policy.t_GrantObservation
    -> t_GrantLookupObservation

/// Outcome of the atomic grant `UPDATE`.
type t_GrantUpdateObservation =
  | GrantUpdateObservation_Updated : t_GrantUpdateObservation
  | GrantUpdateObservation_Conflict : t_GrantUpdateObservation
  | GrantUpdateObservation_Failed : t_GrantUpdateObservation

/// The values the verified grant permit authorizes the handler to write.
type t_GrantUpdate = {
  f_mode:Vela_session_policy.t_SessionMode;
  f_epoch:i64;
  f_ttl_secs:i64
}

/// Where a grant is in its decision sequence.
type t_GrantStage =
  | GrantStage_Validate : t_GrantStage
  | GrantStage_ObserveSession : t_GrantStage
  | GrantStage_Update : t_GrantStage
  | GrantStage_Done : t_GrantStage

/// One grant driver event.
type t_GrantEvent =
  | GrantEvent_Validated : t_GrantValidationObservation -> t_GrantEvent
  | GrantEvent_SessionObserved : t_GrantLookupObservation -> t_GrantEvent
  | GrantEvent_UpdateObserved : t_GrantUpdateObservation -> t_GrantEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_GrantFailure =
  | GrantFailure_Unauthenticated : t_GrantFailure
  | GrantFailure_Validation : t_GrantFailure
  | GrantFailure_NotFound : t_GrantFailure
  | GrantFailure_LookupStorage : t_GrantFailure
  | GrantFailure_NotPending : t_GrantFailure
  | GrantFailure_CrossAccount : t_GrantFailure
  | GrantFailure_NonceMismatch : t_GrantFailure
  | GrantFailure_MissingWebVk : t_GrantFailure
  | GrantFailure_InconsistentFacts : t_GrantFailure
  | GrantFailure_Conflict : t_GrantFailure
  | GrantFailure_UpdateStorage : t_GrantFailure

/// The effect the handler must perform next.
type t_GrantEffect =
  | GrantEffect_ValidateGrant : t_GrantEffect
  | GrantEffect_LoadSession : t_GrantEffect
  | GrantEffect_UpdateGrant : t_GrantUpdate -> t_GrantEffect
  | GrantEffect_Complete : t_GrantEffect
  | GrantEffect_Fail : t_GrantFailure -> t_GrantEffect
  | GrantEffect_Idle : t_GrantEffect

/// Per-request grant state.
type t_GrantDriver = {
  f_stage:t_GrantStage;
  f_actor_active:bool;
  f_request_valid:bool;
  f_session_loaded:bool;
  f_plan_authorized:bool;
  f_permit_mode:Vela_session_policy.t_SessionMode;
  f_permit_epoch:i64;
  f_requested_ttl:Core_models.Option.t_Option i64;
  f_ttl_secs:i64;
  f_updated:bool;
  f_responded:bool;
  f_failed:bool
}

type t_GrantTransition = {
  f_driver:t_GrantDriver;
  f_effect:t_GrantEffect
}

let grant_blank (actor_active: bool) (requested_ttl: Core_models.Option.t_Option i64)
    : t_GrantDriver =
  {
    f_stage = GrantStage_Validate <: t_GrantStage;
    f_actor_active = actor_active;
    f_request_valid = false;
    f_session_loaded = false;
    f_plan_authorized = false;
    f_permit_mode = Vela_session_policy.SessionMode_ReadOnly <: Vela_session_policy.t_SessionMode;
    f_permit_epoch = mk_i64 0;
    f_requested_ttl = requested_ttl;
    f_ttl_secs = mk_i64 0;
    f_updated = false;
    f_responded = false;
    f_failed = false
  }
  <:
  t_GrantDriver

let grant_state_is_sound (d: t_GrantDriver) : bool =
  let validate:bool =
    d.f_actor_active && ~.d.f_request_valid && ~.d.f_session_loaded && ~.d.f_plan_authorized &&
    ~.d.f_updated &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let observe:bool =
    d.f_actor_active && d.f_request_valid && ~.d.f_session_loaded && ~.d.f_plan_authorized &&
    ~.d.f_updated &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let update:bool =
    d.f_actor_active && d.f_request_valid && d.f_session_loaded && d.f_plan_authorized &&
    ~.d.f_updated &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    d.f_actor_active && d.f_request_valid && d.f_session_loaded && d.f_plan_authorized &&
    d.f_updated)
  in
  (~.(match d.f_stage <: t_GrantStage with
    | GrantStage_Validate  -> true
    | _ -> false) ||
  validate) &&
  (~.(match d.f_stage <: t_GrantStage with
    | GrantStage_ObserveSession  -> true
    | _ -> false) ||
  observe) &&
  (~.(match d.f_stage <: t_GrantStage with
    | GrantStage_Update  -> true
    | _ -> false) ||
  update) &&
  (~.(match d.f_stage <: t_GrantStage with
    | GrantStage_Done  -> true
    | _ -> false) ||
  done) &&
  (~.d.f_request_valid || d.f_actor_active) &&
  (~.d.f_session_loaded || d.f_request_valid) &&
  (~.d.f_plan_authorized || d.f_session_loaded) &&
  (~.d.f_updated || d.f_plan_authorized) &&
  (~.d.f_responded || d.f_updated) &&
  (~.d.f_failed || ~.d.f_responded) &&
  (~.d.f_plan_authorized || d.f_permit_epoch >=. Vela_session_policy.v_INITIAL_EPOCH)

let same_grant_mode (a b: Vela_session_policy.t_SessionMode) : bool =
  match a, b <: (Vela_session_policy.t_SessionMode & Vela_session_policy.t_SessionMode) with
  | Vela_session_policy.SessionMode_ReadOnly , Vela_session_policy.SessionMode_ReadOnly
  | Vela_session_policy.SessionMode_ReadWrite , Vela_session_policy.SessionMode_ReadWrite  -> true
  | _ -> false

let grant_effect_is_sound (d: t_GrantDriver) (v_effect: t_GrantEffect) : bool =
  match v_effect <: t_GrantEffect with
  | GrantEffect_ValidateGrant  ->
    (match d.f_stage <: t_GrantStage with
      | GrantStage_Validate  -> true
      | _ -> false) &&
    d.f_actor_active &&
    ~.d.f_request_valid &&
    ~.d.f_session_loaded &&
    ~.d.f_plan_authorized &&
    ~.d.f_updated &&
    ~.d.f_responded &&
    ~.d.f_failed
  | GrantEffect_LoadSession  ->
    (match d.f_stage <: t_GrantStage with
      | GrantStage_ObserveSession  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_request_valid &&
    ~.d.f_session_loaded &&
    ~.d.f_plan_authorized &&
    ~.d.f_updated &&
    ~.d.f_responded &&
    ~.d.f_failed
  | GrantEffect_UpdateGrant update ->
    (match d.f_stage <: t_GrantStage with
      | GrantStage_Update  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_request_valid &&
    d.f_session_loaded &&
    d.f_plan_authorized &&
    ~.d.f_updated &&
    ~.d.f_responded &&
    ~.d.f_failed &&
    update.f_epoch =. d.f_permit_epoch &&
    update.f_ttl_secs =. d.f_ttl_secs &&
    same_grant_mode update.f_mode d.f_permit_mode
  | GrantEffect_Complete  ->
    (match d.f_stage <: t_GrantStage with
      | GrantStage_Done  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_request_valid &&
    d.f_session_loaded &&
    d.f_plan_authorized &&
    d.f_updated &&
    d.f_responded &&
    ~.d.f_failed
  | GrantEffect_Fail _ ->
    (match d.f_stage <: t_GrantStage with
      | GrantStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | GrantEffect_Idle  -> true

let grant_transition (driver: t_GrantDriver) (v_effect: t_GrantEffect) : t_GrantTransition =
  { f_driver = driver; f_effect = v_effect } <: t_GrantTransition

let grant_idle (driver: t_GrantDriver) : t_GrantTransition =
  grant_transition driver (GrantEffect_Idle <: t_GrantEffect)

let grant_terminal (driver: t_GrantDriver) (failure: t_GrantFailure) : t_GrantTransition =
  grant_transition ({ driver with f_stage = GrantStage_Done <: t_GrantStage; f_failed = true }
      <:
      t_GrantDriver)
    (GrantEffect_Fail failure <: t_GrantEffect)

/// Start a grant. An actor the middleware did not verify as an authenticated,
/// active device gets a terminal refusal and performs no effect at all.
let begin_grant (actor: t_GrantActorObservation) (requested_ttl: Core_models.Option.t_Option i64)
    : Prims.Pure t_GrantTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_GrantTransition = result in
          grant_state_is_sound result.f_driver &&
          grant_effect_is_sound result.f_driver result.f_effect) =
  let actor_active:bool = actor.f_authenticated && actor.f_device_active in
  if actor_active
  then
    grant_transition (grant_blank true requested_ttl <: t_GrantDriver)
      (GrantEffect_ValidateGrant <: t_GrantEffect)
  else
    let driver:t_GrantDriver = grant_blank false requested_ttl in
    grant_transition ({ driver with f_stage = GrantStage_Done <: t_GrantStage; f_failed = true }
        <:
        t_GrantDriver)
      (GrantEffect_Fail (GrantFailure_Unauthenticated <: t_GrantFailure) <: t_GrantEffect)

let on_grant_validated (driver: t_GrantDriver) (observation: t_GrantValidationObservation)
    : t_GrantTransition =
  match observation <: t_GrantValidationObservation with
  | GrantValidationObservation_Valid  ->
    grant_transition ({
          driver with
          f_stage = GrantStage_ObserveSession <: t_GrantStage;
          f_request_valid = true
        }
        <:
        t_GrantDriver)
      (GrantEffect_LoadSession <: t_GrantEffect)
  | GrantValidationObservation_Invalid  ->
    grant_terminal driver (GrantFailure_Validation <: t_GrantFailure)

/// Classify a refused plan while preserving the original handler's precedence.
/// The *decision* is the checked policy's; this only chooses the historical
/// status/message for the refusal.
let grant_refusal (observation: Vela_session_policy.t_GrantObservation) : t_GrantFailure =
  if
    ~.(match observation.Vela_session_policy.f_phase <: Vela_session_policy.t_SessionPhase with
      | Vela_session_policy.SessionPhase_Pending  -> true
      | _ -> false)
  then GrantFailure_NotPending <: t_GrantFailure
  else
    if
      observation.Vela_session_policy.f_approver_user <>.
      (Core_models.Option.Option_Some observation.Vela_session_policy.f_authenticated_user
        <:
        Core_models.Option.t_Option u128)
    then GrantFailure_CrossAccount <: t_GrantFailure
    else
      if
        observation.Vela_session_policy.f_nonce_length <>. mk_usize 32 ||
        ~.observation.Vela_session_policy.f_nonce_equal
      then GrantFailure_NonceMismatch <: t_GrantFailure
      else
        if
          (match observation.Vela_session_policy.f_mode <: Vela_session_policy.t_SessionMode with
            | Vela_session_policy.SessionMode_ReadWrite  -> true
            | _ -> false) &&
          ~.observation.Vela_session_policy.f_has_web_vk
        then GrantFailure_MissingWebVk <: t_GrantFailure
        else GrantFailure_InconsistentFacts <: t_GrantFailure

let on_grant_session (driver: t_GrantDriver) (observation: t_GrantLookupObservation)
    : t_GrantTransition =
  match observation <: t_GrantLookupObservation with
  | GrantLookupObservation_Absent  ->
    grant_terminal driver (GrantFailure_NotFound <: t_GrantFailure)
  | GrantLookupObservation_QueryFailed  ->
    grant_terminal driver (GrantFailure_LookupStorage <: t_GrantFailure)
  | GrantLookupObservation_Present observed ->
    match
      Vela_session_policy.plan_observed_grant observed <: Vela_session_policy.t_GrantDecision
    with
    | Vela_session_policy.GrantDecision_Grant permit ->
      grant_transition ({
            driver with
            f_stage = GrantStage_Update <: t_GrantStage;
            f_session_loaded = true;
            f_plan_authorized = true;
            f_permit_mode
            =
            Vela_session_policy.impl_GrantPermit__mode permit <: Vela_session_policy.t_SessionMode;
            f_permit_epoch = Vela_session_policy.impl_GrantPermit__epoch permit <: i64;
            f_ttl_secs = Vela_session_policy.clamp_web_ttl driver.f_requested_ttl <: i64
          }
          <:
          t_GrantDriver)
        (GrantEffect_UpdateGrant
          ({
              f_mode
              =
              Vela_session_policy.impl_GrantPermit__mode permit <: Vela_session_policy.t_SessionMode;
              f_epoch = Vela_session_policy.impl_GrantPermit__epoch permit <: i64;
              f_ttl_secs = Vela_session_policy.clamp_web_ttl driver.f_requested_ttl <: i64
            }
            <:
            t_GrantUpdate)
          <:
          t_GrantEffect)
    | Vela_session_policy.GrantDecision_Reject  ->
      grant_terminal driver (grant_refusal observed <: t_GrantFailure)

let on_grant_updated (driver: t_GrantDriver) (observation: t_GrantUpdateObservation)
    : t_GrantTransition =
  match observation <: t_GrantUpdateObservation with
  | GrantUpdateObservation_Updated  ->
    grant_transition ({
          driver with
          f_stage = GrantStage_Done <: t_GrantStage;
          f_updated = true;
          f_responded = true
        }
        <:
        t_GrantDriver)
      (GrantEffect_Complete <: t_GrantEffect)
  | GrantUpdateObservation_Conflict  ->
    grant_terminal driver (GrantFailure_Conflict <: t_GrantFailure)
  | GrantUpdateObservation_Failed  ->
    grant_terminal driver (GrantFailure_UpdateStorage <: t_GrantFailure)

/// The total grant transition relation.
let grant_step (driver: t_GrantDriver) (event: t_GrantEvent)
    : Prims.Pure t_GrantTransition
      (requires grant_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_GrantTransition = result in
          grant_effect_is_sound result.f_driver result.f_effect &&
          (~.(grant_state_is_sound driver <: bool) || grant_state_is_sound result.f_driver)) =
  match event <: t_GrantEvent with
  | GrantEvent_Validated observation ->
    if
      match driver.f_stage <: t_GrantStage with
      | GrantStage_Validate  -> true
      | _ -> false
    then on_grant_validated driver observation
    else grant_idle driver
  | GrantEvent_SessionObserved observation ->
    if
      match driver.f_stage <: t_GrantStage with
      | GrantStage_ObserveSession  -> true
      | _ -> false
    then on_grant_session driver observation
    else grant_idle driver
  | GrantEvent_UpdateObserved observation ->
    if
      match driver.f_stage <: t_GrantStage with
      | GrantStage_Update  -> true
      | _ -> false
    then on_grant_updated driver observation
    else grant_idle driver

/// Observation from the two limiters and the exponential backoff precheck.
type t_TokenLimitObservation =
  | TokenLimitObservation_Allowed : t_TokenLimitObservation
  | TokenLimitObservation_Limited : t_TokenLimitObservation

/// The session facts needed to decide an exchange. `now` is the clock reading
/// taken after the success-side backoff reset, exactly where the handler used
/// to read it.
type t_TokenSessionObservation = {
  f_phase:Vela_session_policy.t_SessionPhase;
  f_mode:Vela_session_policy.t_SessionMode;
  f_granted_user:Core_models.Option.t_Option u128;
  f_approver_user:Core_models.Option.t_Option u128;
  f_nonce_present:bool;
  f_web_vk_present:bool;
  f_key_epoch:i64;
  f_now:i64;
  f_expires_at:Core_models.Option.t_Option i64
}

/// Outcome of the session lookup. `Malformed` is a decodable row whose
/// `web_vk` field is not valid base64 (an internal error in the original).
type t_TokenLookupObservation =
  | TokenLookupObservation_Absent : t_TokenLookupObservation
  | TokenLookupObservation_QueryFailed : t_TokenLookupObservation
  | TokenLookupObservation_MissingGrant : t_TokenLookupObservation
  | TokenLookupObservation_Malformed : t_TokenLookupObservation
  | TokenLookupObservation_Present : t_TokenSessionObservation -> t_TokenLookupObservation

/// Outcome of the atomic purpose-bound challenge take.
type t_TokenChallengeObservation =
  | TokenChallengeObservation_Observed : Vela_session_policy.Challenge.t_ChallengeConsumption
    -> t_TokenChallengeObservation
  | TokenChallengeObservation_StorageFailed : t_TokenChallengeObservation

/// Outcome of decoding the challenge and running the verifier.
type t_TokenSignatureObservation =
  | TokenSignatureObservation_Valid : t_TokenSignatureObservation
  | TokenSignatureObservation_InvalidChallengeEncoding : t_TokenSignatureObservation
  | TokenSignatureObservation_Rejected : t_TokenSignatureObservation

/// Outcome of recording a failed proof.
type t_TokenFailureRecordObservation =
  | TokenFailureRecordObservation_Recorded : t_TokenFailureRecordObservation
  | TokenFailureRecordObservation_StorageFailed : t_TokenFailureRecordObservation

/// Outcome of the success-side backoff reset, carrying the clock reading the
/// issuance decision uses.
type t_TokenResetObservation =
  | TokenResetObservation_Reset { f_now:i64 }: t_TokenResetObservation
  | TokenResetObservation_StorageFailed : t_TokenResetObservation

/// Outcome of the first-writer-wins token claim.
type t_TokenClaimObservation =
  | TokenClaimObservation_Claimed : t_TokenClaimObservation
  | TokenClaimObservation_AlreadyClaimed : t_TokenClaimObservation
  | TokenClaimObservation_StorageFailed : t_TokenClaimObservation

/// Outcome of PASETO issuance.
type t_TokenIssueObservation =
  | TokenIssueObservation_Issued : t_TokenIssueObservation
  | TokenIssueObservation_Failed : t_TokenIssueObservation

/// Where an exchange is in its decision sequence.
type t_TokenStage =
  | TokenStage_Precheck : t_TokenStage
  | TokenStage_ObserveSession : t_TokenStage
  | TokenStage_Challenge : t_TokenStage
  | TokenStage_Verify : t_TokenStage
  | TokenStage_RecordFailure : t_TokenStage
  | TokenStage_Reset : t_TokenStage
  | TokenStage_Claim : t_TokenStage
  | TokenStage_Issue : t_TokenStage
  | TokenStage_Done : t_TokenStage

/// One token driver event.
type t_TokenEvent =
  | TokenEvent_LimitsObserved : t_TokenLimitObservation -> t_TokenEvent
  | TokenEvent_SessionObserved : t_TokenLookupObservation -> t_TokenEvent
  | TokenEvent_ChallengeObserved : t_TokenChallengeObservation -> t_TokenEvent
  | TokenEvent_SignatureObserved : t_TokenSignatureObservation -> t_TokenEvent
  | TokenEvent_FailureRecorded : t_TokenFailureRecordObservation -> t_TokenEvent
  | TokenEvent_ResetObserved : t_TokenResetObservation -> t_TokenEvent
  | TokenEvent_ClaimObserved : t_TokenClaimObservation -> t_TokenEvent
  | TokenEvent_Issued : t_TokenIssueObservation -> t_TokenEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_TokenFailure =
  | TokenFailure_RateLimited : t_TokenFailure
  | TokenFailure_NotFound : t_TokenFailure
  | TokenFailure_LookupStorage : t_TokenFailure
  | TokenFailure_NotGranted : t_TokenFailure
  | TokenFailure_ReadOnly : t_TokenFailure
  | TokenFailure_Expired : t_TokenFailure
  | TokenFailure_MissingGrantFields : t_TokenFailure
  | TokenFailure_MissingExpiry : t_TokenFailure
  | TokenFailure_MissingUser : t_TokenFailure
  | TokenFailure_MissingSigningKey : t_TokenFailure
  | TokenFailure_MalformedSession : t_TokenFailure
  | TokenFailure_ChallengeMissing : t_TokenFailure
  | TokenFailure_ChallengeWrongPurpose : t_TokenFailure
  | TokenFailure_ChallengeStorage : t_TokenFailure
  | TokenFailure_InvalidChallengeEncoding : t_TokenFailure
  | TokenFailure_SignatureRejected : t_TokenFailure
  | TokenFailure_FailureRecordStorage : t_TokenFailure
  | TokenFailure_BackoffResetStorage : t_TokenFailure
  | TokenFailure_AlreadyIssued : t_TokenFailure
  | TokenFailure_ClaimStorage : t_TokenFailure
  | TokenFailure_IssueFailed : t_TokenFailure
  | TokenFailure_InconsistentFacts : t_TokenFailure

/// The effect the handler must perform next.
type t_TokenEffect =
  | TokenEffect_CheckTokenLimits : t_TokenEffect
  | TokenEffect_LoadSession : t_TokenEffect
  | TokenEffect_ConsumeWebTokenChallenge : t_TokenEffect
  | TokenEffect_VerifyWebSignature : t_TokenEffect
  | TokenEffect_RecordTokenFailure : t_TokenEffect
  | TokenEffect_ResetTokenBackoff : t_TokenEffect
  | TokenEffect_ClaimToken : t_TokenEffect
  | TokenEffect_IssueToken : Vela_session_policy.t_TokenPlan -> t_TokenEffect
  | TokenEffect_Complete : t_TokenEffect
  | TokenEffect_Fail : t_TokenFailure -> t_TokenEffect
  | TokenEffect_Idle : t_TokenEffect

/// Per-request token-exchange state.
type t_TokenDriver = {
  f_stage:t_TokenStage;
  f_limits_allowed:bool;
  f_session_loaded:bool;
  f_session_eligible:bool;
  f_granted_by_same_account:bool;
  f_granted_user:Core_models.Option.t_Option u128;
  f_approver_user:Core_models.Option.t_Option u128;
  f_nonce_present:bool;
  f_hard_cap:i64;
  f_key_epoch:i64;
  f_challenge_consumed:bool;
  f_signature_valid:bool;
  f_backoff_reset:bool;
  f_token_claimed:bool;
  f_plan_authorized:bool;
  f_now:i64;
  f_token_issued:bool;
  f_responded:bool;
  f_failed:bool
}

type t_TokenTransition = {
  f_driver:t_TokenDriver;
  f_effect:t_TokenEffect
}

let token_blank (_: Prims.unit) : t_TokenDriver =
  {
    f_stage = TokenStage_Precheck <: t_TokenStage;
    f_limits_allowed = false;
    f_session_loaded = false;
    f_session_eligible = false;
    f_granted_by_same_account = false;
    f_granted_user = Core_models.Option.Option_None <: Core_models.Option.t_Option u128;
    f_approver_user = Core_models.Option.Option_None <: Core_models.Option.t_Option u128;
    f_nonce_present = false;
    f_hard_cap = mk_i64 0;
    f_key_epoch = mk_i64 0;
    f_challenge_consumed = false;
    f_signature_valid = false;
    f_backoff_reset = false;
    f_token_claimed = false;
    f_plan_authorized = false;
    f_now = mk_i64 0;
    f_token_issued = false;
    f_responded = false;
    f_failed = false
  }
  <:
  t_TokenDriver

/// The clean prefix through each stage: every later fact is still false.
let token_clean (d: t_TokenDriver) : bool =
  ~.d.f_challenge_consumed && ~.d.f_signature_valid && ~.d.f_backoff_reset && ~.d.f_token_claimed &&
  ~.d.f_plan_authorized &&
  ~.d.f_token_issued &&
  ~.d.f_responded &&
  ~.d.f_failed

let token_state_is_sound (d: t_TokenDriver) : bool =
  let precheck:bool =
    ~.d.f_limits_allowed && ~.d.f_session_loaded && ~.d.f_session_eligible && token_clean d
  in
  let observe:bool =
    d.f_limits_allowed && ~.d.f_session_loaded && ~.d.f_session_eligible && token_clean d
  in
  let challenge:bool =
    d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && token_clean d
  in
  let verify:bool =
    d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && d.f_challenge_consumed &&
    ~.d.f_signature_valid &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_claimed &&
    ~.d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let record_failure:bool =
    d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && d.f_challenge_consumed &&
    ~.d.f_signature_valid &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_claimed &&
    ~.d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let reset:bool =
    d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && d.f_challenge_consumed &&
    d.f_signature_valid &&
    ~.d.f_token_claimed &&
    ~.d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let claim:bool =
    d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && d.f_challenge_consumed &&
    d.f_signature_valid &&
    d.f_backoff_reset &&
    ~.d.f_token_claimed &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let issue:bool =
    d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && d.f_challenge_consumed &&
    d.f_signature_valid &&
    d.f_backoff_reset &&
    d.f_token_claimed &&
    d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && d.f_challenge_consumed &&
    d.f_signature_valid &&
    d.f_backoff_reset &&
    d.f_token_claimed &&
    d.f_plan_authorized &&
    d.f_token_issued)
  in
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_Precheck  -> true
    | _ -> false) ||
  precheck) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_ObserveSession  -> true
    | _ -> false) ||
  observe) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_Challenge  -> true
    | _ -> false) ||
  challenge) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_Verify  -> true
    | _ -> false) ||
  verify) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_RecordFailure  -> true
    | _ -> false) ||
  record_failure) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_Reset  -> true
    | _ -> false) ||
  reset) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_Claim  -> true
    | _ -> false) ||
  claim) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_Issue  -> true
    | _ -> false) ||
  issue) &&
  (~.(match d.f_stage <: t_TokenStage with
    | TokenStage_Done  -> true
    | _ -> false) ||
  done) &&
  (~.d.f_session_loaded || d.f_limits_allowed) &&
  (~.d.f_session_eligible || d.f_session_loaded) &&
  (~.d.f_challenge_consumed || d.f_session_eligible) &&
  (~.d.f_signature_valid || d.f_challenge_consumed) &&
  (~.d.f_backoff_reset || d.f_signature_valid) &&
  (~.d.f_token_claimed || d.f_backoff_reset) &&
  (~.d.f_token_issued || d.f_plan_authorized) &&
  (~.d.f_responded || d.f_token_issued) &&
  (~.d.f_failed || ~.d.f_responded) &&
  (~.d.f_plan_authorized ||
  d.f_session_eligible && d.f_granted_by_same_account && d.f_nonce_present && d.f_challenge_consumed &&
  d.f_signature_valid &&
  d.f_key_epoch >=. Vela_session_policy.v_INITIAL_EPOCH &&
  d.f_hard_cap >. mk_i64 0)

let token_effect_is_sound (d: t_TokenDriver) (v_effect: t_TokenEffect) : bool =
  match v_effect <: t_TokenEffect with
  | TokenEffect_CheckTokenLimits  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Precheck  -> true
      | _ -> false) &&
    ~.d.f_limits_allowed &&
    ~.d.f_session_loaded &&
    ~.d.f_session_eligible &&
    token_clean d
  | TokenEffect_LoadSession  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_ObserveSession  -> true
      | _ -> false) &&
    d.f_limits_allowed &&
    ~.d.f_session_loaded &&
    ~.d.f_session_eligible &&
    token_clean d
  | TokenEffect_ConsumeWebTokenChallenge  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Challenge  -> true
      | _ -> false) &&
    d.f_limits_allowed &&
    d.f_session_loaded &&
    d.f_session_eligible &&
    ~.d.f_challenge_consumed &&
    ~.d.f_signature_valid &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_claimed &&
    ~.d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  | TokenEffect_VerifyWebSignature  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Verify  -> true
      | _ -> false) &&
    d.f_challenge_consumed &&
    ~.d.f_signature_valid &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_claimed &&
    ~.d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  | TokenEffect_RecordTokenFailure  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_RecordFailure  -> true
      | _ -> false) &&
    d.f_challenge_consumed &&
    ~.d.f_signature_valid &&
    ~.d.f_backoff_reset &&
    ~.d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  | TokenEffect_ResetTokenBackoff  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Reset  -> true
      | _ -> false) &&
    d.f_challenge_consumed &&
    d.f_signature_valid &&
    ~.d.f_backoff_reset &&
    ~.d.f_token_claimed &&
    ~.d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  | TokenEffect_ClaimToken  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Claim  -> true
      | _ -> false) &&
    d.f_challenge_consumed &&
    d.f_signature_valid &&
    d.f_backoff_reset &&
    ~.d.f_token_claimed &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  | TokenEffect_IssueToken e_plan ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Issue  -> true
      | _ -> false) &&
    d.f_session_eligible &&
    d.f_granted_by_same_account &&
    d.f_nonce_present &&
    d.f_challenge_consumed &&
    d.f_signature_valid &&
    d.f_backoff_reset &&
    d.f_token_claimed &&
    d.f_plan_authorized &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  | TokenEffect_Complete  ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Done  -> true
      | _ -> false) &&
    d.f_session_eligible &&
    d.f_challenge_consumed &&
    d.f_signature_valid &&
    d.f_backoff_reset &&
    d.f_token_claimed &&
    d.f_plan_authorized &&
    d.f_token_issued &&
    d.f_responded &&
    ~.d.f_failed
  | TokenEffect_Fail _ ->
    (match d.f_stage <: t_TokenStage with
      | TokenStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | TokenEffect_Idle  -> true

let token_transition (driver: t_TokenDriver) (v_effect: t_TokenEffect) : t_TokenTransition =
  { f_driver = driver; f_effect = v_effect } <: t_TokenTransition

let token_idle (driver: t_TokenDriver) : t_TokenTransition =
  token_transition driver (TokenEffect_Idle <: t_TokenEffect)

let token_terminal (driver: t_TokenDriver) (failure: t_TokenFailure) : t_TokenTransition =
  token_transition ({ driver with f_stage = TokenStage_Done <: t_TokenStage; f_failed = true }
      <:
      t_TokenDriver)
    (TokenEffect_Fail failure <: t_TokenEffect)

/// Start an exchange. Every request begins at the limit/backoff prechecks.
let begin_token (_: Prims.unit)
    : Prims.Pure t_TokenTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_TokenTransition = result in
          token_state_is_sound result.f_driver &&
          token_effect_is_sound result.f_driver result.f_effect) =
  token_transition (token_blank () <: t_TokenDriver) (TokenEffect_CheckTokenLimits <: t_TokenEffect)

let on_token_limits (driver: t_TokenDriver) (observation: t_TokenLimitObservation)
    : t_TokenTransition =
  match observation <: t_TokenLimitObservation with
  | TokenLimitObservation_Allowed  ->
    token_transition ({
          driver with
          f_stage = TokenStage_ObserveSession <: t_TokenStage;
          f_limits_allowed = true
        }
        <:
        t_TokenDriver)
      (TokenEffect_LoadSession <: t_TokenEffect)
  | TokenLimitObservation_Limited  ->
    token_terminal driver (TokenFailure_RateLimited <: t_TokenFailure)

let on_token_session (driver: t_TokenDriver) (observation: t_TokenLookupObservation)
    : t_TokenTransition =
  match observation <: t_TokenLookupObservation with
  | TokenLookupObservation_Absent  ->
    token_terminal driver (TokenFailure_NotFound <: t_TokenFailure)
  | TokenLookupObservation_QueryFailed  ->
    token_terminal driver (TokenFailure_LookupStorage <: t_TokenFailure)
  | TokenLookupObservation_Malformed  ->
    token_terminal driver (TokenFailure_MalformedSession <: t_TokenFailure)
  | TokenLookupObservation_MissingGrant  ->
    token_terminal driver (TokenFailure_MissingGrantFields <: t_TokenFailure)
  | TokenLookupObservation_Present session ->
    let failure:Core_models.Option.t_Option t_TokenFailure =
      if
        ~.(match session.f_phase <: Vela_session_policy.t_SessionPhase with
          | Vela_session_policy.SessionPhase_Granted  -> true
          | _ -> false)
      then
        Core_models.Option.Option_Some (TokenFailure_NotGranted <: t_TokenFailure)
        <:
        Core_models.Option.t_Option t_TokenFailure
      else
        if
          ~.(match session.f_mode <: Vela_session_policy.t_SessionMode with
            | Vela_session_policy.SessionMode_ReadWrite  -> true
            | _ -> false)
        then
          Core_models.Option.Option_Some (TokenFailure_ReadOnly <: t_TokenFailure)
          <:
          Core_models.Option.t_Option t_TokenFailure
        else
          match session.f_expires_at <: Core_models.Option.t_Option i64 with
          | Core_models.Option.Option_None  ->
            Core_models.Option.Option_Some (TokenFailure_MissingExpiry <: t_TokenFailure)
            <:
            Core_models.Option.t_Option t_TokenFailure
          | _ ->
            match
              (match session.f_expires_at <: Core_models.Option.t_Option i64 with
                | Core_models.Option.Option_Some expires_at ->
                  (match session.f_now >=. expires_at <: bool with
                    | true ->
                      Core_models.Option.Option_Some
                      (Core_models.Option.Option_Some (TokenFailure_Expired <: t_TokenFailure)
                        <:
                        Core_models.Option.t_Option t_TokenFailure)
                      <:
                      Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
                    | _ ->
                      Core_models.Option.Option_None
                      <:
                      Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure))
                | _ ->
                  Core_models.Option.Option_None
                  <:
                  Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure))
              <:
              Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
            with
            | Core_models.Option.Option_Some x -> x
            | Core_models.Option.Option_None  ->
              match
                (match session.f_expires_at <: Core_models.Option.t_Option i64 with
                  | Core_models.Option.Option_Some _ ->
                    (match
                        Core_models.Option.impl__is_none #u128 session.f_granted_user <: bool
                      with
                      | true ->
                        Core_models.Option.Option_Some
                        (Core_models.Option.Option_Some (TokenFailure_MissingUser <: t_TokenFailure)
                          <:
                          Core_models.Option.t_Option t_TokenFailure)
                        <:
                        Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
                      | _ ->
                        Core_models.Option.Option_None
                        <:
                        Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure))
                  | _ ->
                    Core_models.Option.Option_None
                    <:
                    Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure))
                <:
                Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
              with
              | Core_models.Option.Option_Some x -> x
              | Core_models.Option.Option_None  ->
                match
                  (match session.f_expires_at <: Core_models.Option.t_Option i64 with
                    | Core_models.Option.Option_Some _ ->
                      (match ~.session.f_web_vk_present <: bool with
                        | true ->
                          Core_models.Option.Option_Some
                          (Core_models.Option.Option_Some
                            (TokenFailure_MissingSigningKey <: t_TokenFailure)
                            <:
                            Core_models.Option.t_Option t_TokenFailure)
                          <:
                          Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
                        | _ ->
                          Core_models.Option.Option_None
                          <:
                          Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure))
                    | _ ->
                      Core_models.Option.Option_None
                      <:
                      Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure))
                  <:
                  Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
                with
                | Core_models.Option.Option_Some x -> x
                | Core_models.Option.Option_None  ->
                  match
                    (match session.f_expires_at <: Core_models.Option.t_Option i64 with
                      | Core_models.Option.Option_Some _ ->
                        (match
                            Core_models.Option.impl__is_none #u128 session.f_approver_user <: bool
                          with
                          | true ->
                            Core_models.Option.Option_Some
                            (Core_models.Option.Option_Some
                              (TokenFailure_MissingGrantFields <: t_TokenFailure)
                              <:
                              Core_models.Option.t_Option t_TokenFailure)
                            <:
                            Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
                          | _ ->
                            Core_models.Option.Option_None
                            <:
                            Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
                        )
                      | _ ->
                        Core_models.Option.Option_None
                        <:
                        Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure))
                    <:
                    Core_models.Option.t_Option (Core_models.Option.t_Option t_TokenFailure)
                  with
                  | Core_models.Option.Option_Some x -> x
                  | Core_models.Option.Option_None  ->
                    match session.f_expires_at <: Core_models.Option.t_Option i64 with
                    | Core_models.Option.Option_Some _ ->
                      Core_models.Option.Option_None <: Core_models.Option.t_Option t_TokenFailure
    in
    match failure <: Core_models.Option.t_Option t_TokenFailure with
    | Core_models.Option.Option_Some failure -> token_terminal driver failure
    | Core_models.Option.Option_None  ->
      token_transition ({
            driver with
            f_stage = TokenStage_Challenge <: t_TokenStage;
            f_session_loaded = true;
            f_session_eligible = true;
            f_granted_by_same_account
            =
            (match
                session.f_granted_user, session.f_approver_user
                <:
                (Core_models.Option.t_Option u128 & Core_models.Option.t_Option u128)
              with
              | Core_models.Option.Option_Some granted, Core_models.Option.Option_Some approver ->
                granted =. approver <: bool
              | _ -> false);
            f_granted_user = session.f_granted_user;
            f_approver_user = session.f_approver_user;
            f_nonce_present = session.f_nonce_present;
            f_key_epoch = session.f_key_epoch;
            f_hard_cap
            =
            Core_models.Option.impl__unwrap_or #i64 session.f_expires_at (mk_i64 0) <: i64
          }
          <:
          t_TokenDriver)
        (TokenEffect_ConsumeWebTokenChallenge <: t_TokenEffect)

let on_token_challenge (driver: t_TokenDriver) (observation: t_TokenChallengeObservation)
    : t_TokenTransition =
  match observation <: t_TokenChallengeObservation with
  | TokenChallengeObservation_Observed
    (Vela_session_policy.Challenge.ChallengeConsumption_Accepted ) ->
    token_transition ({
          driver with
          f_stage = TokenStage_Verify <: t_TokenStage;
          f_challenge_consumed = true
        }
        <:
        t_TokenDriver)
      (TokenEffect_VerifyWebSignature <: t_TokenEffect)
  | TokenChallengeObservation_Observed (Vela_session_policy.Challenge.ChallengeConsumption_Missing ) ->
    token_terminal driver (TokenFailure_ChallengeMissing <: t_TokenFailure)
  | TokenChallengeObservation_Observed
    (Vela_session_policy.Challenge.ChallengeConsumption_WrongPurpose ) ->
    token_terminal driver (TokenFailure_ChallengeWrongPurpose <: t_TokenFailure)
  | TokenChallengeObservation_StorageFailed  ->
    token_terminal driver (TokenFailure_ChallengeStorage <: t_TokenFailure)

let on_token_signature (driver: t_TokenDriver) (observation: t_TokenSignatureObservation)
    : t_TokenTransition =
  match observation <: t_TokenSignatureObservation with
  | TokenSignatureObservation_Valid  ->
    token_transition ({
          driver with
          f_stage = TokenStage_Reset <: t_TokenStage;
          f_signature_valid = true
        }
        <:
        t_TokenDriver)
      (TokenEffect_ResetTokenBackoff <: t_TokenEffect)
  | TokenSignatureObservation_InvalidChallengeEncoding  ->
    token_terminal driver (TokenFailure_InvalidChallengeEncoding <: t_TokenFailure)
  | TokenSignatureObservation_Rejected  ->
    token_transition ({ driver with f_stage = TokenStage_RecordFailure <: t_TokenStage }
        <:
        t_TokenDriver)
      (TokenEffect_RecordTokenFailure <: t_TokenEffect)

let on_token_failure_recorded (driver: t_TokenDriver) (observation: t_TokenFailureRecordObservation)
    : t_TokenTransition =
  match observation <: t_TokenFailureRecordObservation with
  | TokenFailureRecordObservation_Recorded  ->
    token_terminal driver (TokenFailure_SignatureRejected <: t_TokenFailure)
  | TokenFailureRecordObservation_StorageFailed  ->
    token_terminal driver (TokenFailure_FailureRecordStorage <: t_TokenFailure)

let on_token_reset (driver: t_TokenDriver) (observation: t_TokenResetObservation)
    : t_TokenTransition =
  match observation <: t_TokenResetObservation with
  | TokenResetObservation_Reset { f_now = now } ->
    token_transition ({
          driver with
          f_stage = TokenStage_Claim <: t_TokenStage;
          f_backoff_reset = true;
          f_now = now
        }
        <:
        t_TokenDriver)
      (TokenEffect_ClaimToken <: t_TokenEffect)
  | TokenResetObservation_StorageFailed  ->
    token_terminal driver (TokenFailure_BackoffResetStorage <: t_TokenFailure)

let on_token_claim (driver: t_TokenDriver) (observation: t_TokenClaimObservation)
    : t_TokenTransition =
  match observation <: t_TokenClaimObservation with
  | TokenClaimObservation_Claimed  ->
    if
      ~.(driver.f_nonce_present && driver.f_granted_by_same_account &&
        (driver.f_key_epoch >=. Vela_session_policy.v_INITIAL_EPOCH <: bool) &&
        (driver.f_hard_cap >. mk_i64 0 <: bool))
    then token_terminal driver (TokenFailure_InconsistentFacts <: t_TokenFailure)
    else
      let decision:Vela_session_policy.t_TokenDecision =
        Vela_session_policy.plan_observed_web_token ({
              Vela_session_policy.f_phase
              =
              Vela_session_policy.SessionPhase_Granted <: Vela_session_policy.t_SessionPhase;
              Vela_session_policy.f_mode
              =
              Vela_session_policy.SessionMode_ReadWrite <: Vela_session_policy.t_SessionMode;
              Vela_session_policy.f_granted_user = driver.f_granted_user;
              Vela_session_policy.f_approver_user = driver.f_approver_user;
              Vela_session_policy.f_nonce_present = driver.f_nonce_present;
              Vela_session_policy.f_challenge_consumed = driver.f_challenge_consumed;
              Vela_session_policy.f_signature_valid = driver.f_signature_valid
            }
            <:
            Vela_session_policy.t_WebTokenObservation)
          driver.f_now
          driver.f_hard_cap
          driver.f_key_epoch
      in
      (match decision <: Vela_session_policy.t_TokenDecision with
        | Vela_session_policy.TokenDecision_Issue plan ->
          token_transition ({
                driver with
                f_stage = TokenStage_Issue <: t_TokenStage;
                f_token_claimed = true;
                f_plan_authorized = true
              }
              <:
              t_TokenDriver)
            (TokenEffect_IssueToken plan <: t_TokenEffect)
        | Vela_session_policy.TokenDecision_Reject  ->
          token_terminal driver (TokenFailure_InconsistentFacts <: t_TokenFailure))
  | TokenClaimObservation_AlreadyClaimed  ->
    token_terminal driver (TokenFailure_AlreadyIssued <: t_TokenFailure)
  | TokenClaimObservation_StorageFailed  ->
    token_terminal driver (TokenFailure_ClaimStorage <: t_TokenFailure)

let on_token_issued (driver: t_TokenDriver) (observation: t_TokenIssueObservation)
    : t_TokenTransition =
  match observation <: t_TokenIssueObservation with
  | TokenIssueObservation_Issued  ->
    token_transition ({
          driver with
          f_stage = TokenStage_Done <: t_TokenStage;
          f_token_issued = true;
          f_responded = true
        }
        <:
        t_TokenDriver)
      (TokenEffect_Complete <: t_TokenEffect)
  | TokenIssueObservation_Failed  ->
    token_terminal driver (TokenFailure_IssueFailed <: t_TokenFailure)

/// The total token-exchange transition relation. The checked plan is built by
/// [`crate::plan_observed_web_token`] from an observation where every grant,
/// nonce, challenge and signature fact must hold.
let token_step (driver: t_TokenDriver) (event: t_TokenEvent)
    : Prims.Pure t_TokenTransition
      (requires token_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_TokenTransition = result in
          token_effect_is_sound result.f_driver result.f_effect &&
          (~.(token_state_is_sound driver <: bool) || token_state_is_sound result.f_driver)) =
  match event <: t_TokenEvent with
  | TokenEvent_LimitsObserved observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_Precheck  -> true
      | _ -> false
    then on_token_limits driver observation
    else token_idle driver
  | TokenEvent_SessionObserved observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_ObserveSession  -> true
      | _ -> false
    then on_token_session driver observation
    else token_idle driver
  | TokenEvent_ChallengeObserved observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_Challenge  -> true
      | _ -> false
    then on_token_challenge driver observation
    else token_idle driver
  | TokenEvent_SignatureObserved observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_Verify  -> true
      | _ -> false
    then on_token_signature driver observation
    else token_idle driver
  | TokenEvent_FailureRecorded observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_RecordFailure  -> true
      | _ -> false
    then on_token_failure_recorded driver observation
    else token_idle driver
  | TokenEvent_ResetObserved observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_Reset  -> true
      | _ -> false
    then on_token_reset driver observation
    else token_idle driver
  | TokenEvent_ClaimObserved observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_Claim  -> true
      | _ -> false
    then on_token_claim driver observation
    else token_idle driver
  | TokenEvent_Issued observation ->
    if
      match driver.f_stage <: t_TokenStage with
      | TokenStage_Issue  -> true
      | _ -> false
    then on_token_issued driver observation
    else token_idle driver

/// Actor facts established by the authenticated `DeviceSession` extractor.
type t_DeleteActorObservation = {
  f_authenticated:bool;
  f_user:u128
}

/// The ownership fields of a session row.
type t_DeleteSessionFacts = {
  f_session_user:Core_models.Option.t_Option u128;
  f_approver_user:Core_models.Option.t_Option u128
}

/// Outcome of the session lookup.
type t_DeleteLookupObservation =
  | DeleteLookupObservation_Absent : t_DeleteLookupObservation
  | DeleteLookupObservation_QueryFailed : t_DeleteLookupObservation
  | DeleteLookupObservation_Present : t_DeleteSessionFacts -> t_DeleteLookupObservation

/// Outcome of the `device:revoked:` sentinel write.
type t_DeleteSentinelObservation =
  | DeleteSentinelObservation_Applied : t_DeleteSentinelObservation
  | DeleteSentinelObservation_StorageFailed : t_DeleteSentinelObservation

/// Outcome of the `web_sessions` revocation `UPDATE`.
type t_DeleteRecordObservation =
  | DeleteRecordObservation_Updated : t_DeleteRecordObservation
  | DeleteRecordObservation_Failed : t_DeleteRecordObservation

/// Where a session delete is in its decision sequence.
type t_DeleteStage =
  | DeleteStage_Observe : t_DeleteStage
  | DeleteStage_Lockout : t_DeleteStage
  | DeleteStage_Record : t_DeleteStage
  | DeleteStage_Done : t_DeleteStage

/// One delete driver event.
type t_DeleteEvent =
  | DeleteEvent_SessionObserved : t_DeleteLookupObservation -> t_DeleteEvent
  | DeleteEvent_SentinelWritten : t_DeleteSentinelObservation -> t_DeleteEvent
  | DeleteEvent_RecordObserved : t_DeleteRecordObservation -> t_DeleteEvent

/// Failure categories.
type t_DeleteFailure =
  | DeleteFailure_Unauthenticated : t_DeleteFailure
  | DeleteFailure_NotFound : t_DeleteFailure
  | DeleteFailure_LookupStorage : t_DeleteFailure
  | DeleteFailure_LockoutStorage : t_DeleteFailure
  | DeleteFailure_RecordStorage : t_DeleteFailure

/// The effect the handler must perform next.
type t_DeleteEffect =
  | DeleteEffect_LoadSession : t_DeleteEffect
  | DeleteEffect_LockoutSession : t_DeleteEffect
  | DeleteEffect_RecordRevocation : t_DeleteEffect
  | DeleteEffect_Complete : t_DeleteEffect
  | DeleteEffect_Fail : t_DeleteFailure -> t_DeleteEffect
  | DeleteEffect_Idle : t_DeleteEffect

/// Per-request delete state.
type t_DeleteDriver = {
  f_stage:t_DeleteStage;
  f_actor_active:bool;
  f_actor_user:u128;
  f_owner_matches:bool;
  f_locked:bool;
  f_recorded:bool;
  f_responded:bool;
  f_failed:bool
}

type t_DeleteTransition = {
  f_driver:t_DeleteDriver;
  f_effect:t_DeleteEffect
}

let delete_blank (actor_active: bool) : t_DeleteDriver =
  {
    f_stage = DeleteStage_Observe <: t_DeleteStage;
    f_actor_active = actor_active;
    f_actor_user = mk_u128 0;
    f_owner_matches = false;
    f_locked = false;
    f_recorded = false;
    f_responded = false;
    f_failed = false
  }
  <:
  t_DeleteDriver

let delete_state_is_sound (d: t_DeleteDriver) : bool =
  let observe:bool =
    d.f_actor_active && ~.d.f_owner_matches && ~.d.f_locked && ~.d.f_recorded && ~.d.f_responded &&
    ~.d.f_failed
  in
  let lockout:bool =
    d.f_actor_active && d.f_owner_matches && ~.d.f_locked && ~.d.f_recorded && ~.d.f_responded &&
    ~.d.f_failed
  in
  let record:bool =
    d.f_actor_active && d.f_owner_matches && d.f_locked && ~.d.f_recorded && ~.d.f_responded &&
    ~.d.f_failed
  in
  let done:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded || d.f_actor_active && d.f_owner_matches && d.f_locked && d.f_recorded)
  in
  (~.(match d.f_stage <: t_DeleteStage with
    | DeleteStage_Observe  -> true
    | _ -> false) ||
  observe) &&
  (~.(match d.f_stage <: t_DeleteStage with
    | DeleteStage_Lockout  -> true
    | _ -> false) ||
  lockout) &&
  (~.(match d.f_stage <: t_DeleteStage with
    | DeleteStage_Record  -> true
    | _ -> false) ||
  record) &&
  (~.(match d.f_stage <: t_DeleteStage with
    | DeleteStage_Done  -> true
    | _ -> false) ||
  done) &&
  (~.d.f_owner_matches || d.f_actor_active) &&
  (~.d.f_locked || d.f_owner_matches) &&
  (~.d.f_recorded || d.f_locked) &&
  (~.d.f_responded || d.f_recorded) &&
  (~.d.f_failed || ~.d.f_responded)

let delete_effect_is_sound (d: t_DeleteDriver) (v_effect: t_DeleteEffect) : bool =
  match v_effect <: t_DeleteEffect with
  | DeleteEffect_LoadSession  ->
    (match d.f_stage <: t_DeleteStage with
      | DeleteStage_Observe  -> true
      | _ -> false) &&
    d.f_actor_active &&
    ~.d.f_owner_matches &&
    ~.d.f_locked &&
    ~.d.f_recorded &&
    ~.d.f_responded &&
    ~.d.f_failed
  | DeleteEffect_LockoutSession  ->
    (match d.f_stage <: t_DeleteStage with
      | DeleteStage_Lockout  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_owner_matches &&
    ~.d.f_locked &&
    ~.d.f_recorded &&
    ~.d.f_responded &&
    ~.d.f_failed
  | DeleteEffect_RecordRevocation  ->
    (match d.f_stage <: t_DeleteStage with
      | DeleteStage_Record  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_owner_matches &&
    d.f_locked &&
    ~.d.f_recorded &&
    ~.d.f_responded &&
    ~.d.f_failed
  | DeleteEffect_Complete  ->
    (match d.f_stage <: t_DeleteStage with
      | DeleteStage_Done  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_owner_matches &&
    d.f_locked &&
    d.f_recorded &&
    d.f_responded &&
    ~.d.f_failed
  | DeleteEffect_Fail _ ->
    (match d.f_stage <: t_DeleteStage with
      | DeleteStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | DeleteEffect_Idle  -> true

let delete_transition (driver: t_DeleteDriver) (v_effect: t_DeleteEffect) : t_DeleteTransition =
  { f_driver = driver; f_effect = v_effect } <: t_DeleteTransition

let delete_idle (driver: t_DeleteDriver) : t_DeleteTransition =
  delete_transition driver (DeleteEffect_Idle <: t_DeleteEffect)

let delete_terminal (driver: t_DeleteDriver) (failure: t_DeleteFailure) : t_DeleteTransition =
  delete_transition ({ driver with f_stage = DeleteStage_Done <: t_DeleteStage; f_failed = true }
      <:
      t_DeleteDriver)
    (DeleteEffect_Fail failure <: t_DeleteEffect)

/// Start a delete. An unauthenticated actor gets a terminal refusal with no
/// effect; only the account that owns (or is committed to) the session may
/// lock it out or record its revocation.
let begin_delete (actor: t_DeleteActorObservation)
    : Prims.Pure t_DeleteTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_DeleteTransition = result in
          delete_state_is_sound result.f_driver &&
          delete_effect_is_sound result.f_driver result.f_effect) =
  if actor.f_authenticated
  then
    delete_transition ({ (delete_blank true <: t_DeleteDriver) with f_actor_user = actor.f_user }
        <:
        t_DeleteDriver)
      (DeleteEffect_LoadSession <: t_DeleteEffect)
  else
    delete_transition ({
          (delete_blank false <: t_DeleteDriver) with
          f_stage = DeleteStage_Done <: t_DeleteStage;
          f_failed = true
        }
        <:
        t_DeleteDriver)
      (DeleteEffect_Fail (DeleteFailure_Unauthenticated <: t_DeleteFailure) <: t_DeleteEffect)

let delete_owner (facts: t_DeleteSessionFacts) : Core_models.Option.t_Option u128 =
  match facts.f_session_user <: Core_models.Option.t_Option u128 with
  | Core_models.Option.Option_Some user ->
    Core_models.Option.Option_Some user <: Core_models.Option.t_Option u128
  | Core_models.Option.Option_None  -> facts.f_approver_user

let on_delete_session
      (driver: t_DeleteDriver)
      (actor_user: u128)
      (observation: t_DeleteLookupObservation)
    : t_DeleteTransition =
  match observation <: t_DeleteLookupObservation with
  | DeleteLookupObservation_Absent  ->
    delete_terminal driver (DeleteFailure_NotFound <: t_DeleteFailure)
  | DeleteLookupObservation_QueryFailed  ->
    delete_terminal driver (DeleteFailure_LookupStorage <: t_DeleteFailure)
  | DeleteLookupObservation_Present facts ->
    if
      (delete_owner facts <: Core_models.Option.t_Option u128) =.
      (Core_models.Option.Option_Some actor_user <: Core_models.Option.t_Option u128)
    then
      delete_transition ({
            driver with
            f_stage = DeleteStage_Lockout <: t_DeleteStage;
            f_owner_matches = true
          }
          <:
          t_DeleteDriver)
        (DeleteEffect_LockoutSession <: t_DeleteEffect)
    else delete_terminal driver (DeleteFailure_NotFound <: t_DeleteFailure)

let on_delete_sentinel (driver: t_DeleteDriver) (observation: t_DeleteSentinelObservation)
    : t_DeleteTransition =
  match observation <: t_DeleteSentinelObservation with
  | DeleteSentinelObservation_Applied  ->
    delete_transition ({
          driver with
          f_stage = DeleteStage_Record <: t_DeleteStage;
          f_locked = true
        }
        <:
        t_DeleteDriver)
      (DeleteEffect_RecordRevocation <: t_DeleteEffect)
  | DeleteSentinelObservation_StorageFailed  ->
    delete_terminal driver (DeleteFailure_LockoutStorage <: t_DeleteFailure)

let on_delete_record (driver: t_DeleteDriver) (observation: t_DeleteRecordObservation)
    : t_DeleteTransition =
  match observation <: t_DeleteRecordObservation with
  | DeleteRecordObservation_Updated  ->
    delete_transition ({
          driver with
          f_stage = DeleteStage_Done <: t_DeleteStage;
          f_recorded = true;
          f_responded = true
        }
        <:
        t_DeleteDriver)
      (DeleteEffect_Complete <: t_DeleteEffect)
  | DeleteRecordObservation_Failed  ->
    delete_terminal driver (DeleteFailure_RecordStorage <: t_DeleteFailure)

/// The total delete transition relation.
let delete_step (driver: t_DeleteDriver) (event: t_DeleteEvent)
    : Prims.Pure t_DeleteTransition
      (requires delete_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeleteTransition = result in
          delete_effect_is_sound result.f_driver result.f_effect &&
          (~.(delete_state_is_sound driver <: bool) || delete_state_is_sound result.f_driver)) =
  match event <: t_DeleteEvent with
  | DeleteEvent_SessionObserved observation ->
    if
      match driver.f_stage <: t_DeleteStage with
      | DeleteStage_Observe  -> true
      | _ -> false
    then on_delete_session driver driver.f_actor_user observation
    else delete_idle driver
  | DeleteEvent_SentinelWritten observation ->
    if
      match driver.f_stage <: t_DeleteStage with
      | DeleteStage_Lockout  -> true
      | _ -> false
    then on_delete_sentinel driver observation
    else delete_idle driver
  | DeleteEvent_RecordObserved observation ->
    if
      match driver.f_stage <: t_DeleteStage with
      | DeleteStage_Record  -> true
      | _ -> false
    then on_delete_record driver observation
    else delete_idle driver
