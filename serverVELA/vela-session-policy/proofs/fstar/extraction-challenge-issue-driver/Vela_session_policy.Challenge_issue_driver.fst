module Vela_session_policy.Challenge_issue_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Byte length of an issued nonce.
let v_NONCE_LEN: usize = mk_usize 32

/// The parsed purpose query. `Invalid` is the handler's `400`.
type t_PurposeObservation =
  | PurposeObservation_Requested : Vela_session_policy.Challenge.t_ChallengePurpose
    -> t_PurposeObservation
  | PurposeObservation_Invalid : t_PurposeObservation

/// Outcome of the per-IP challenge limiter.
type t_RateLimitObservation =
  | RateLimitObservation_Allowed : t_RateLimitObservation
  | RateLimitObservation_Denied : t_RateLimitObservation

/// Outcome of the OS random call.
type t_NonceObservation =
  | NonceObservation_Generated { f_len:usize }: t_NonceObservation
  | NonceObservation_Unavailable : t_NonceObservation

/// Outcome of the first-writer-wins store write (`set_ex_nx`). `Inserted` is
/// the only observation that proves the key was absent and is now ours.
type t_StoreObservation =
  | StoreObservation_Inserted : t_StoreObservation
  | StoreObservation_KeyExists : t_StoreObservation
  | StoreObservation_Failed : t_StoreObservation

/// Where the issue is in its decision sequence.
type t_IssueStage =
  | IssueStage_RateLimit : t_IssueStage
  | IssueStage_GenerateNonce : t_IssueStage
  | IssueStage_StoreNonce : t_IssueStage
  | IssueStage_Done : t_IssueStage

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_IssueEvent =
  | IssueEvent_RateLimitObserved : t_RateLimitObservation -> t_IssueEvent
  | IssueEvent_NonceObserved : t_NonceObservation -> t_IssueEvent
  | IssueEvent_StoreObserved : t_StoreObservation -> t_IssueEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence where the driver fixes the class. `InvalidPurpose` and
/// `RandomUnavailable` keep the handler's original error text in its `error`
/// slot.
type t_IssueFailure =
  | IssueFailure_InvalidPurpose : t_IssueFailure
  | IssueFailure_RateLimited : t_IssueFailure
  | IssueFailure_RandomUnavailable : t_IssueFailure
  | IssueFailure_NonceLength : t_IssueFailure
  | IssueFailure_Collision : t_IssueFailure
  | IssueFailure_Storage : t_IssueFailure

/// The effect the handler must perform next.
type t_IssueEffect =
  | IssueEffect_CheckRateLimit : t_IssueEffect
  | IssueEffect_GenerateNonce : t_IssueEffect
  | IssueEffect_StoreNonce : t_IssueEffect
  | IssueEffect_Issue : t_IssueEffect
  | IssueEffect_Fail : t_IssueFailure -> t_IssueEffect
  | IssueEffect_Idle : t_IssueEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about sled or the OS.
type t_IssueDriver = {
  f_stage:t_IssueStage;
  f_purpose:Vela_session_policy.Challenge.t_ChallengePurpose;
  f_purpose_valid:bool;
  f_rate_allowed:bool;
  f_nonce_valid:bool;
  f_stored_fresh:bool;
  f_issued:bool;
  f_failed:bool
}

type t_IssueTransition = {
  f_driver:t_IssueDriver;
  f_effect:t_IssueEffect
}

/// Structural purpose equality, independent of derived `PartialEq` for hax.
let same_issue_purpose (a b: Vela_session_policy.Challenge.t_ChallengePurpose) : bool =
  match
    a, b
    <:
    (Vela_session_policy.Challenge.t_ChallengePurpose &
      Vela_session_policy.Challenge.t_ChallengePurpose)
  with
  | Vela_session_policy.Challenge.ChallengePurpose_Login ,
  Vela_session_policy.Challenge.ChallengePurpose_Login
  | Vela_session_policy.Challenge.ChallengePurpose_Enroll ,
  Vela_session_policy.Challenge.ChallengePurpose_Enroll
  | Vela_session_policy.Challenge.ChallengePurpose_WebToken ,
  Vela_session_policy.Challenge.ChallengePurpose_WebToken  ->
    true
  | _ -> false

/// Position of the stage in the fixed issue order. A step never moves it
/// backwards; a terminal verdict moves it to `Done`.
let issue_stage_index (d: t_IssueDriver) : usize =
  match d.f_stage <: t_IssueStage with
  | IssueStage_RateLimit  -> mk_usize 0
  | IssueStage_GenerateNonce  -> mk_usize 1
  | IssueStage_StoreNonce  -> mk_usize 2
  | IssueStage_Done  -> mk_usize 3

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let issue_state_is_sound (d: t_IssueDriver) : bool =
  let rate:bool =
    match d.f_stage <: t_IssueStage with
    | IssueStage_RateLimit  -> true
    | _ -> false
  in
  let generate:bool =
    match d.f_stage <: t_IssueStage with
    | IssueStage_GenerateNonce  -> true
    | _ -> false
  in
  let store:bool =
    match d.f_stage <: t_IssueStage with
    | IssueStage_StoreNonce  -> true
    | _ -> false
  in
  let done:bool =
    match d.f_stage <: t_IssueStage with
    | IssueStage_Done  -> true
    | _ -> false
  in
  let purpose_bound:bool = d.f_purpose_valid in
  (~.rate ||
  d.f_purpose_valid && ~.d.f_rate_allowed && ~.d.f_nonce_valid && ~.d.f_stored_fresh && ~.d.f_issued &&
  ~.d.f_failed) &&
  (~.generate ||
  d.f_purpose_valid && d.f_rate_allowed && ~.d.f_nonce_valid && ~.d.f_stored_fresh && ~.d.f_issued &&
  ~.d.f_failed) &&
  (~.store ||
  d.f_purpose_valid && d.f_rate_allowed && d.f_nonce_valid && ~.d.f_stored_fresh && ~.d.f_issued &&
  ~.d.f_failed) &&
  (~.done ||
  (d.f_issued || d.f_failed) && ~.(d.f_issued && d.f_failed) &&
  (~.d.f_issued || purpose_bound && d.f_rate_allowed && d.f_nonce_valid && d.f_stored_fresh)) &&
  (~.d.f_nonce_valid || d.f_rate_allowed) &&
  (~.d.f_stored_fresh || d.f_rate_allowed && d.f_nonce_valid) &&
  (~.d.f_issued || d.f_stored_fresh && purpose_bound) &&
  (~.d.f_stored_fresh || purpose_bound) &&
  (~.d.f_failed || ~.d.f_issued)

/// Every effect the driver emits agrees with the state it produces. In
/// particular `StoreNonce` names the parsed purpose, is emitted only after the
/// limiter, a 32-byte nonce and the absence check, and is emitted at most once
/// because the next state is terminal.
let issue_effect_is_sound (d: t_IssueDriver) (v_effect: t_IssueEffect) : bool =
  match v_effect <: t_IssueEffect with
  | IssueEffect_CheckRateLimit  ->
    (match d.f_stage <: t_IssueStage with
      | IssueStage_RateLimit  -> true
      | _ -> false) &&
    ~.d.f_rate_allowed &&
    ~.d.f_nonce_valid &&
    ~.d.f_stored_fresh &&
    ~.d.f_issued &&
    ~.d.f_failed
  | IssueEffect_GenerateNonce  ->
    (match d.f_stage <: t_IssueStage with
      | IssueStage_GenerateNonce  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    ~.d.f_nonce_valid &&
    ~.d.f_stored_fresh &&
    ~.d.f_issued &&
    ~.d.f_failed
  | IssueEffect_StoreNonce  ->
    (match d.f_stage <: t_IssueStage with
      | IssueStage_StoreNonce  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_nonce_valid &&
    ~.d.f_stored_fresh &&
    ~.d.f_issued &&
    ~.d.f_failed &&
    d.f_purpose_valid
  | IssueEffect_Issue  ->
    (match d.f_stage <: t_IssueStage with
      | IssueStage_Done  -> true
      | _ -> false) &&
    d.f_issued &&
    d.f_rate_allowed &&
    d.f_nonce_valid &&
    d.f_stored_fresh &&
    ~.d.f_failed &&
    d.f_purpose_valid
  | IssueEffect_Fail _ ->
    (match d.f_stage <: t_IssueStage with
      | IssueStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_issued &&
    ~.d.f_stored_fresh
  | IssueEffect_Idle  -> true

let transition (driver: t_IssueDriver) (v_effect: t_IssueEffect) : t_IssueTransition =
  { f_driver = driver; f_effect = v_effect } <: t_IssueTransition

let idle (driver: t_IssueDriver) : t_IssueTransition =
  transition driver (IssueEffect_Idle <: t_IssueEffect)

let terminal (driver: t_IssueDriver) (failure: t_IssueFailure) : t_IssueTransition =
  transition ({ driver with f_stage = IssueStage_Done <: t_IssueStage; f_failed = true }
      <:
      t_IssueDriver)
    (IssueEffect_Fail failure <: t_IssueEffect)

/// The empty request state before the first effect.
let request_state (purpose: Vela_session_policy.Challenge.t_ChallengePurpose) (purpose_valid: bool)
    : t_IssueDriver =
  {
    f_stage = IssueStage_RateLimit <: t_IssueStage;
    f_purpose = purpose;
    f_purpose_valid = purpose_valid;
    f_rate_allowed = false;
    f_nonce_valid = false;
    f_stored_fresh = false;
    f_issued = false;
    f_failed = false
  }
  <:
  t_IssueDriver

/// Start a per-request challenge issue. An unparseable purpose is a terminal
/// `400` with no limiter, random or store effect.
let begin_issue (purpose: t_PurposeObservation)
    : Prims.Pure t_IssueTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_state_is_sound result.f_driver &&
          issue_effect_is_sound result.f_driver result.f_effect) =
  match purpose <: t_PurposeObservation with
  | PurposeObservation_Invalid  ->
    terminal (request_state (Vela_session_policy.Challenge.ChallengePurpose_Login
            <:
            Vela_session_policy.Challenge.t_ChallengePurpose)
          false
        <:
        t_IssueDriver)
      (IssueFailure_InvalidPurpose <: t_IssueFailure)
  | PurposeObservation_Requested purpose ->
    transition (request_state purpose true <: t_IssueDriver)
      (IssueEffect_CheckRateLimit <: t_IssueEffect)

let on_rate_limit (driver: t_IssueDriver) (observation: t_RateLimitObservation)
    : Prims.Pure t_IssueTransition
      (requires
        issue_state_is_sound driver &&
        (match driver.f_stage <: t_IssueStage with
          | IssueStage_RateLimit  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_effect_is_sound result.f_driver result.f_effect &&
          (~.(issue_state_is_sound driver <: bool) || issue_state_is_sound result.f_driver)) =
  match observation <: t_RateLimitObservation with
  | RateLimitObservation_Allowed  ->
    transition ({
          driver with
          f_stage = IssueStage_GenerateNonce <: t_IssueStage;
          f_rate_allowed = true
        }
        <:
        t_IssueDriver)
      (IssueEffect_GenerateNonce <: t_IssueEffect)
  | RateLimitObservation_Denied  -> terminal driver (IssueFailure_RateLimited <: t_IssueFailure)

let on_nonce (driver: t_IssueDriver) (observation: t_NonceObservation)
    : Prims.Pure t_IssueTransition
      (requires
        issue_state_is_sound driver &&
        (match driver.f_stage <: t_IssueStage with
          | IssueStage_GenerateNonce  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_effect_is_sound result.f_driver result.f_effect &&
          (~.(issue_state_is_sound driver <: bool) || issue_state_is_sound result.f_driver)) =
  match
    (match observation <: t_NonceObservation with
      | NonceObservation_Generated { f_len = len } ->
        (match len =. v_NONCE_LEN <: bool with
          | true ->
            Core_models.Option.Option_Some
            (transition ({
                    driver with
                    f_stage = IssueStage_StoreNonce <: t_IssueStage;
                    f_nonce_valid = true
                  }
                  <:
                  t_IssueDriver)
                (IssueEffect_StoreNonce <: t_IssueEffect))
            <:
            Core_models.Option.t_Option t_IssueTransition
          | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option t_IssueTransition)
      | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option t_IssueTransition)
    <:
    Core_models.Option.t_Option t_IssueTransition
  with
  | Core_models.Option.Option_Some x -> x
  | Core_models.Option.Option_None  ->
    match observation <: t_NonceObservation with
    | NonceObservation_Generated { f_len = _ } ->
      terminal driver (IssueFailure_NonceLength <: t_IssueFailure)
    | NonceObservation_Unavailable  ->
      terminal driver (IssueFailure_RandomUnavailable <: t_IssueFailure)

let on_store (driver: t_IssueDriver) (observation: t_StoreObservation)
    : Prims.Pure t_IssueTransition
      (requires
        issue_state_is_sound driver &&
        (match driver.f_stage <: t_IssueStage with
          | IssueStage_StoreNonce  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_effect_is_sound result.f_driver result.f_effect &&
          (~.(issue_state_is_sound driver <: bool) || issue_state_is_sound result.f_driver)) =
  match observation <: t_StoreObservation with
  | StoreObservation_Inserted  ->
    transition ({
          driver with
          f_stage = IssueStage_Done <: t_IssueStage;
          f_stored_fresh = true;
          f_issued = true
        }
        <:
        t_IssueDriver)
      (IssueEffect_Issue <: t_IssueEffect)
  | StoreObservation_KeyExists  -> terminal driver (IssueFailure_Collision <: t_IssueFailure)
  | StoreObservation_Failed  -> terminal driver (IssueFailure_Storage <: t_IssueFailure)

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
let step (driver: t_IssueDriver) (event: t_IssueEvent)
    : Prims.Pure t_IssueTransition
      (requires issue_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_effect_is_sound result.f_driver result.f_effect &&
          (~.(issue_state_is_sound driver <: bool) || issue_state_is_sound result.f_driver) &&
          (issue_stage_index result.f_driver <: usize) >=. (issue_stage_index driver <: usize) &&
          same_issue_purpose result.f_driver.f_purpose driver.f_purpose &&
          (~.(match result.f_effect <: t_IssueEffect with
            | IssueEffect_GenerateNonce  -> true
            | _ -> false) ||
          (match driver.f_stage <: t_IssueStage with
            | IssueStage_RateLimit  -> true
            | _ -> false)) &&
          (~.(match result.f_effect <: t_IssueEffect with
            | IssueEffect_StoreNonce  -> true
            | _ -> false) ||
          (match driver.f_stage <: t_IssueStage with
            | IssueStage_GenerateNonce  -> true
            | _ -> false)) &&
          (~.(match result.f_effect <: t_IssueEffect with
            | IssueEffect_Issue  -> true
            | _ -> false) ||
          (match driver.f_stage <: t_IssueStage with
            | IssueStage_StoreNonce  -> true
            | _ -> false))) =
  match event <: t_IssueEvent with
  | IssueEvent_RateLimitObserved observation ->
    if
      match driver.f_stage <: t_IssueStage with
      | IssueStage_RateLimit  -> true
      | _ -> false
    then on_rate_limit driver observation
    else idle driver
  | IssueEvent_NonceObserved observation ->
    if
      match driver.f_stage <: t_IssueStage with
      | IssueStage_GenerateNonce  -> true
      | _ -> false
    then on_nonce driver observation
    else idle driver
  | IssueEvent_StoreObserved observation ->
    if
      match driver.f_stage <: t_IssueStage with
      | IssueStage_StoreNonce  -> true
      | _ -> false
    then on_store driver observation
    else idle driver

let on_rate_limit_event (driver: t_IssueDriver) (observation: t_RateLimitObservation)
    : Prims.Pure t_IssueTransition
      (requires issue_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_effect_is_sound result.f_driver result.f_effect &&
          (~.(issue_state_is_sound driver <: bool) || issue_state_is_sound result.f_driver)) =
  step driver (IssueEvent_RateLimitObserved observation <: t_IssueEvent)

let on_nonce_event (driver: t_IssueDriver) (observation: t_NonceObservation)
    : Prims.Pure t_IssueTransition
      (requires issue_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_effect_is_sound result.f_driver result.f_effect &&
          (~.(issue_state_is_sound driver <: bool) || issue_state_is_sound result.f_driver)) =
  step driver (IssueEvent_NonceObserved observation <: t_IssueEvent)

let on_store_event (driver: t_IssueDriver) (observation: t_StoreObservation)
    : Prims.Pure t_IssueTransition
      (requires issue_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_IssueTransition = result in
          issue_effect_is_sound result.f_driver result.f_effect &&
          (~.(issue_state_is_sound driver <: bool) || issue_state_is_sound result.f_driver)) =
  step driver (IssueEvent_StoreObserved observation <: t_IssueEvent)
