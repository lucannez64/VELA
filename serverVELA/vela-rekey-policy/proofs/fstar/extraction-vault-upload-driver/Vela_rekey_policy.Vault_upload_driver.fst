module Vela_rekey_policy.Vault_upload_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Vela_rekey_policy in
  ()

/// Whether the request creates a row or replaces the row at an exact version.
type t_WriteIntent =
  | WriteIntent_Create : t_WriteIntent
  | WriteIntent_Replace { f_version:i64 }: t_WriteIntent

/// Authenticated writer facts captured before the first effect.
/// `web` distinguishes the two authority classes the middleware issues. A web
/// token is only minted for a read-write grant
/// (`vela_session_policy::plan_web_session_token` requires
/// `SessionMode::ReadWrite`), so a `WebSession` reaching this driver already
/// carries RW authority; `web_epoch` is the token's pinned `key_epoch`.
type t_UploadWriter = {
  f_authenticated:bool;
  f_web:bool;
  f_web_epoch:Core_models.Option.t_Option i64
}

/// The request facts the handler parses before any effect.
type t_UploadRequest = {
  f_writer:t_UploadWriter;
  f_intent:t_WriteIntent;
  f_declared_epoch:Core_models.Option.t_Option i64
}

/// Post-rollback key-state observation. The handler obtains it from the same
/// load that `resolve_write_epoch` used; the driver re-applies the extracted
/// policy to this value. `Rejected` is the handler's observation that the
/// extracted resolver refused the declared epoch; the handler keeps the
/// original error for rendering.
type t_RekeyObservation =
  | RekeyObservation_State {
    f_epoch:i64;
    f_phase:Vela_rekey_policy.t_Phase
  }: t_RekeyObservation
  | RekeyObservation_Rejected : t_RekeyObservation

/// Quota outcome. `Exceeded` and `StorageFailed` are terminal.
type t_QuotaObservation =
  | QuotaObservation_Allowed : t_QuotaObservation
  | QuotaObservation_Exceeded : t_QuotaObservation
  | QuotaObservation_StorageFailed : t_QuotaObservation

/// Outcome of the guarded `INSERT`/`UPDATE`.
type t_WriteObservation =
  | WriteObservation_Inserted : t_WriteObservation
  | WriteObservation_Updated : t_WriteObservation
  | WriteObservation_Existing : t_WriteObservation
  | WriteObservation_Skipped : t_WriteObservation
  | WriteObservation_Duplicate : t_WriteObservation
  | WriteObservation_Failed : t_WriteObservation

/// Re-resolution performed only after an update matched zero rows.
type t_RecheckObservation =
  | RecheckObservation_Unchanged : t_RecheckObservation
  | RecheckObservation_Changed : t_RecheckObservation
  | RecheckObservation_Failed : t_RecheckObservation

/// Version read-back after a successful write.
type t_RereadObservation =
  | RereadObservation_Read { f_version:i64 }: t_RereadObservation
  | RereadObservation_Missing : t_RereadObservation
  | RereadObservation_Failed : t_RereadObservation

/// Shadow-activity refresh outcome. `Ended` means the guarded refresh matched
/// zero rows because the rotation ended; the handler treats it as non-fatal.
type t_ActivityObservation =
  | ActivityObservation_Refreshed : t_ActivityObservation
  | ActivityObservation_Ended : t_ActivityObservation
  | ActivityObservation_Failed : t_ActivityObservation

/// One upload driver event.
type t_UploadEvent =
  | UploadEvent_Rekey : t_RekeyObservation -> t_UploadEvent
  | UploadEvent_Attempt : Vela_rekey_policy.t_AttemptAuthority -> t_UploadEvent
  | UploadEvent_Quota : t_QuotaObservation -> t_UploadEvent
  | UploadEvent_Write : t_WriteObservation -> t_UploadEvent
  | UploadEvent_Recheck : t_RecheckObservation -> t_UploadEvent
  | UploadEvent_Reread : t_RereadObservation -> t_UploadEvent
  | UploadEvent_Activity : t_ActivityObservation -> t_UploadEvent
  | UploadEvent_Published : t_UploadEvent

/// Failure categories, preserving the handler's status/message precedence.
type t_UploadFailure =
  | UploadFailure_Unauthenticated : t_UploadFailure
  | UploadFailure_EpochMismatch : t_UploadFailure
  | UploadFailure_ShadowWebSessionForbidden : t_UploadFailure
  | UploadFailure_ShadowRotationIdRequired : t_UploadFailure
  | UploadFailure_ShadowStarterForbidden : t_UploadFailure
  | UploadFailure_AuthorityEpochMismatch : t_UploadFailure
  | UploadFailure_QuotaExceeded : t_UploadFailure
  | UploadFailure_QuotaStorage : t_UploadFailure
  | UploadFailure_AlreadyExists : t_UploadFailure
  | UploadFailure_RekeyEnded : t_UploadFailure
  | UploadFailure_VersionMismatch : t_UploadFailure
  | UploadFailure_Rekeyed : t_UploadFailure
  | UploadFailure_WriteStorage : t_UploadFailure
  | UploadFailure_RecheckStorage : t_UploadFailure
  | UploadFailure_RereadStorage : t_UploadFailure
  | UploadFailure_ActivityStorage : t_UploadFailure

/// The write permit the handler must use for the guarded statement.
type t_UploadWritePermit = {
  f_write_epoch:i64;
  f_read_epoch:i64;
  f_shadow:bool;
  f_permit_epoch:i64;
  f_web:bool;
  f_state_epoch:i64;
  f_state_phase:Vela_rekey_policy.t_Phase
}

/// The effect the handler must perform next.
type t_UploadEffect =
  | UploadEffect_ResolveEpoch : t_UploadEffect
  | UploadEffect_AuthorizeShadow : t_UploadEffect
  | UploadEffect_EnforceQuota : t_UploadEffect
  | UploadEffect_Write : t_UploadWritePermit -> t_UploadEffect
  | UploadEffect_RecheckState : t_UploadEffect
  | UploadEffect_RereadVersion : t_UploadEffect
  | UploadEffect_RecordShadowActivity : t_UploadEffect
  | UploadEffect_Publish : t_UploadEffect
  | UploadEffect_Complete : t_UploadEffect
  | UploadEffect_Fail : t_UploadFailure -> t_UploadEffect
  | UploadEffect_Idle : t_UploadEffect

/// Where the upload is in its decision sequence.
type t_UploadStage =
  | UploadStage_Resolve : t_UploadStage
  | UploadStage_Shadow : t_UploadStage
  | UploadStage_Quota : t_UploadStage
  | UploadStage_Write : t_UploadStage
  | UploadStage_Recheck : t_UploadStage
  | UploadStage_Reread : t_UploadStage
  | UploadStage_Activity : t_UploadStage
  | UploadStage_Publish : t_UploadStage
  | UploadStage_Done : t_UploadStage

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
type t_UploadDriver = {
  f_stage:t_UploadStage;
  f_authenticated:bool;
  f_web:bool;
  f_web_epoch:Core_models.Option.t_Option i64;
  f_intent:t_WriteIntent;
  f_declared_epoch:Core_models.Option.t_Option i64;
  f_authority_epoch:i64;
  f_state_epoch:i64;
  f_state_phase:Vela_rekey_policy.t_Phase;
  f_write_epoch:i64;
  f_read_epoch:i64;
  f_shadow:bool;
  f_permit_epoch:i64;
  f_write_matched:bool;
  f_version:i64;
  f_activity_done:bool;
  f_published:bool;
  f_responded:bool;
  f_failed:bool
}

type t_UploadTransition = {
  f_driver:t_UploadDriver;
  f_effect:t_UploadEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let upload_state_is_sound (d: t_UploadDriver) : bool =
  let untouched:bool =
    d.f_state_epoch =. mk_i64 0 && d.f_write_epoch =. mk_i64 0 && d.f_read_epoch =. mk_i64 0 &&
    d.f_permit_epoch =. mk_i64 0 &&
    ~.d.f_write_matched &&
    ~.d.f_activity_done &&
    ~.d.f_published &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let resolved:bool =
    d.f_state_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH && d.f_read_epoch =. d.f_state_epoch &&
    (match d.f_state_phase <: Vela_rekey_policy.t_Phase with
      | Vela_rekey_policy.Phase_Active  -> ~.d.f_shadow && d.f_write_epoch =. d.f_state_epoch
      | Vela_rekey_policy.Phase_Freezing  ->
        d.f_shadow && ~.d.f_web &&
        (Vela_rekey_policy.next_epoch d.f_state_epoch <: Core_models.Option.t_Option i64) =.
        (Core_models.Option.Option_Some d.f_write_epoch <: Core_models.Option.t_Option i64))
  in
  let permitted:bool = resolved && d.f_permit_epoch =. d.f_write_epoch in
  let resolve_clean:bool = d.f_authenticated && untouched in
  let shadow_clean:bool =
    d.f_authenticated && resolved && d.f_shadow && d.f_permit_epoch =. mk_i64 0 &&
    ~.d.f_write_matched &&
    ~.d.f_activity_done &&
    ~.d.f_published &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let quota_clean:bool =
    d.f_authenticated && permitted && ~.d.f_write_matched && ~.d.f_activity_done && ~.d.f_published &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let write_clean:bool = quota_clean in
  let recheck_clean:bool =
    quota_clean && ~.d.f_shadow &&
    (match d.f_intent <: t_WriteIntent with
      | WriteIntent_Replace { f_version = _ } -> true
      | _ -> false)
  in
  let reread_clean:bool =
    d.f_authenticated && permitted && d.f_write_matched && ~.d.f_activity_done && ~.d.f_published &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let activity_clean:bool = reread_clean && d.f_shadow in
  let publish_clean:bool =
    d.f_authenticated && permitted && d.f_write_matched && ~.d.f_published && ~.d.f_responded &&
    ~.d.f_failed &&
    (~.d.f_shadow || d.f_activity_done)
  in
  let done_clean:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    d.f_authenticated && permitted && d.f_write_matched &&
    (~.d.f_shadow && d.f_published || d.f_shadow && d.f_activity_done))
  in
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Resolve  -> true
    | _ -> false) ||
  resolve_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Shadow  -> true
    | _ -> false) ||
  shadow_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Quota  -> true
    | _ -> false) ||
  quota_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Write  -> true
    | _ -> false) ||
  write_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Recheck  -> true
    | _ -> false) ||
  recheck_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Reread  -> true
    | _ -> false) ||
  reread_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Activity  -> true
    | _ -> false) ||
  activity_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Publish  -> true
    | _ -> false) ||
  publish_clean) &&
  (~.(match d.f_stage <: t_UploadStage with
    | UploadStage_Done  -> true
    | _ -> false) ||
  done_clean) &&
  (~.d.f_shadow || ~.d.f_web) &&
  (~.d.f_write_matched || d.f_write_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH) &&
  (~.d.f_activity_done || d.f_shadow) &&
  (~.d.f_published || ~.d.f_shadow && d.f_write_matched) &&
  (~.d.f_responded ||
  d.f_write_matched && (~.d.f_shadow && d.f_published || d.f_shadow && d.f_activity_done)) &&
  (~.d.f_failed || ~.d.f_responded)

/// Every effect the driver emits agrees with the state it produces.
let upload_effect_is_sound (d: t_UploadDriver) (v_effect: t_UploadEffect) : bool =
  match v_effect <: t_UploadEffect with
  | UploadEffect_ResolveEpoch  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Resolve  -> true
      | _ -> false) &&
    d.f_authenticated
  | UploadEffect_AuthorizeShadow  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Shadow  -> true
      | _ -> false) &&
    d.f_shadow
  | UploadEffect_EnforceQuota  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Quota  -> true
      | _ -> false) &&
    d.f_permit_epoch =. d.f_write_epoch
  | UploadEffect_Write permit ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Write  -> true
      | _ -> false) &&
    permit.f_write_epoch =. d.f_write_epoch &&
    permit.f_read_epoch =. d.f_read_epoch &&
    permit.f_permit_epoch =. d.f_permit_epoch &&
    permit.f_shadow =. d.f_shadow &&
    permit.f_web =. d.f_web &&
    permit.f_state_epoch =. d.f_state_epoch &&
    permit.f_state_phase =. d.f_state_phase
  | UploadEffect_RecheckState  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Recheck  -> true
      | _ -> false)
  | UploadEffect_RereadVersion  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Reread  -> true
      | _ -> false) &&
    d.f_write_matched
  | UploadEffect_RecordShadowActivity  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Activity  -> true
      | _ -> false) &&
    d.f_shadow
  | UploadEffect_Publish  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Publish  -> true
      | _ -> false)
  | UploadEffect_Complete  ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed
  | UploadEffect_Fail _ ->
    (match d.f_stage <: t_UploadStage with
      | UploadStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | UploadEffect_Idle  -> true

let transition (driver: t_UploadDriver) (v_effect: t_UploadEffect) : t_UploadTransition =
  { f_driver = driver; f_effect = v_effect } <: t_UploadTransition

let idle (driver: t_UploadDriver) : t_UploadTransition =
  transition driver (UploadEffect_Idle <: t_UploadEffect)

let terminal (driver: t_UploadDriver) (failure: t_UploadFailure) : t_UploadTransition =
  transition ({ driver with f_stage = UploadStage_Done <: t_UploadStage; f_failed = true }
      <:
      t_UploadDriver)
    (UploadEffect_Fail failure <: t_UploadEffect)

let write_permit (d: t_UploadDriver) : t_UploadWritePermit =
  {
    f_write_epoch = d.f_write_epoch;
    f_read_epoch = d.f_read_epoch;
    f_shadow = d.f_shadow;
    f_permit_epoch = d.f_permit_epoch;
    f_web = d.f_web;
    f_state_epoch = d.f_state_epoch;
    f_state_phase = d.f_state_phase
  }
  <:
  t_UploadWritePermit

/// Decide the mutation permit and move to quota enforcement.
let enter_quota (d: t_UploadDriver) : t_UploadTransition =
  let authority:Vela_rekey_policy.t_MutationAuthority =
    if d.f_web
    then Vela_rekey_policy.MutationAuthority_WebSession <: Vela_rekey_policy.t_MutationAuthority
    else Vela_rekey_policy.MutationAuthority_Device <: Vela_rekey_policy.t_MutationAuthority
  in
  let authority_epoch:i64 = if d.f_web then d.f_authority_epoch else d.f_write_epoch in
  let request:Vela_rekey_policy.t_MutationRequest =
    {
      Vela_rekey_policy.f_declared_epoch = d.f_write_epoch;
      Vela_rekey_policy.f_authority_epoch = authority_epoch;
      Vela_rekey_policy.f_kind
      =
      Vela_rekey_policy.MutationKind_Vault <: Vela_rekey_policy.t_MutationKind;
      Vela_rekey_policy.f_authority = authority
    }
    <:
    Vela_rekey_policy.t_MutationRequest
  in
  match Vela_rekey_policy.plan_active_mutation request <: Vela_rekey_policy.t_MutationDecision with
  | Vela_rekey_policy.MutationDecision_Permit permit ->
    transition ({
          d with
          f_stage = UploadStage_Quota <: t_UploadStage;
          f_permit_epoch = Vela_rekey_policy.impl_MutationPermit__epoch permit <: i64
        }
        <:
        t_UploadDriver)
      (UploadEffect_EnforceQuota <: t_UploadEffect)
  | Vela_rekey_policy.MutationDecision_Reject  ->
    terminal d (UploadFailure_AuthorityEpochMismatch <: t_UploadFailure)

/// Start a per-request upload. The extractor already refused an
/// unauthenticated caller; the driver still fails closed on that observation.
let begin_upload (request: t_UploadRequest)
    : Prims.Pure t_UploadTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_UploadTransition = result in
          upload_state_is_sound result.f_driver &&
          upload_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_UploadDriver =
    {
      f_stage = UploadStage_Resolve <: t_UploadStage;
      f_authenticated = request.f_writer.f_authenticated;
      f_web = request.f_writer.f_web;
      f_web_epoch = request.f_writer.f_web_epoch;
      f_intent = request.f_intent;
      f_declared_epoch = request.f_declared_epoch;
      f_authority_epoch
      =
      if request.f_writer.f_web
      then
        match request.f_writer.f_web_epoch <: Core_models.Option.t_Option i64 with
        | Core_models.Option.Option_Some epoch -> epoch
        | Core_models.Option.Option_None  -> Vela_rekey_policy.v_INITIAL_EPOCH
      else mk_i64 0;
      f_state_epoch = mk_i64 0;
      f_state_phase = Vela_rekey_policy.Phase_Active <: Vela_rekey_policy.t_Phase;
      f_write_epoch = mk_i64 0;
      f_read_epoch = mk_i64 0;
      f_shadow = false;
      f_permit_epoch = mk_i64 0;
      f_write_matched = false;
      f_version = mk_i64 0;
      f_activity_done = false;
      f_published = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_UploadDriver
  in
  if request.f_writer.f_authenticated
  then transition driver (UploadEffect_ResolveEpoch <: t_UploadEffect)
  else terminal driver (UploadFailure_Unauthenticated <: t_UploadFailure)

let on_rekey (driver: t_UploadDriver) (observation: t_RekeyObservation) : t_UploadTransition =
  match observation <: t_RekeyObservation with
  | RekeyObservation_Rejected  -> terminal driver (UploadFailure_EpochMismatch <: t_UploadFailure)
  | RekeyObservation_State { f_epoch = epoch ; f_phase = phase } ->
    let state:Vela_rekey_policy.t_RekeyState =
      { Vela_rekey_policy.f_epoch = epoch; Vela_rekey_policy.f_phase = phase }
      <:
      Vela_rekey_policy.t_RekeyState
    in
    match
      Vela_rekey_policy.resolve_write_epoch state driver.f_declared_epoch
      <:
      Vela_rekey_policy.t_WriteDecision
    with
    | Vela_rekey_policy.WriteDecision_Accept route ->
      let shadow:bool =
        route.Vela_rekey_policy.f_write_epoch <>. route.Vela_rekey_policy.f_read_epoch
      in
      let resolved:t_UploadDriver =
        {
          driver with
          f_state_epoch = epoch;
          f_state_phase = phase;
          f_write_epoch = route.Vela_rekey_policy.f_write_epoch;
          f_read_epoch = route.Vela_rekey_policy.f_read_epoch;
          f_authority_epoch
          =
          if driver.f_web then driver.f_authority_epoch else route.Vela_rekey_policy.f_write_epoch;
          f_shadow = shadow
        }
        <:
        t_UploadDriver
      in
      if shadow
      then
        transition ({ resolved with f_stage = UploadStage_Shadow <: t_UploadStage }
            <:
            t_UploadDriver)
          (UploadEffect_AuthorizeShadow <: t_UploadEffect)
      else enter_quota resolved
    | Vela_rekey_policy.WriteDecision_Reject  ->
      terminal driver (UploadFailure_EpochMismatch <: t_UploadFailure)

let on_attempt (driver: t_UploadDriver) (authority: Vela_rekey_policy.t_AttemptAuthority)
    : t_UploadTransition =
  if driver.f_web
  then terminal driver (UploadFailure_ShadowWebSessionForbidden <: t_UploadFailure)
  else
    let state:Vela_rekey_policy.t_RekeyState =
      {
        Vela_rekey_policy.f_epoch = driver.f_state_epoch;
        Vela_rekey_policy.f_phase = driver.f_state_phase
      }
      <:
      Vela_rekey_policy.t_RekeyState
    in
    let route:Vela_rekey_policy.t_EpochRoute =
      {
        Vela_rekey_policy.f_write_epoch = driver.f_write_epoch;
        Vela_rekey_policy.f_read_epoch = driver.f_read_epoch
      }
      <:
      Vela_rekey_policy.t_EpochRoute
    in
    match
      Vela_rekey_policy.authorize_shadow state route authority <: Vela_rekey_policy.t_ShadowDecision
    with
    | Vela_rekey_policy.ShadowDecision_Allow  -> enter_quota driver
    | Vela_rekey_policy.ShadowDecision_Reject  ->
      if ~.authority.Vela_rekey_policy.f_device_scope
      then terminal driver (UploadFailure_ShadowWebSessionForbidden <: t_UploadFailure)
      else
        if ~.authority.Vela_rekey_policy.f_rotation_id_present
        then terminal driver (UploadFailure_ShadowRotationIdRequired <: t_UploadFailure)
        else terminal driver (UploadFailure_ShadowStarterForbidden <: t_UploadFailure)

let on_quota (driver: t_UploadDriver) (observation: t_QuotaObservation) : t_UploadTransition =
  match observation <: t_QuotaObservation with
  | QuotaObservation_Allowed  ->
    transition ({ driver with f_stage = UploadStage_Write <: t_UploadStage } <: t_UploadDriver)
      (UploadEffect_Write (write_permit driver <: t_UploadWritePermit) <: t_UploadEffect)
  | QuotaObservation_Exceeded  -> terminal driver (UploadFailure_QuotaExceeded <: t_UploadFailure)
  | QuotaObservation_StorageFailed  ->
    terminal driver (UploadFailure_QuotaStorage <: t_UploadFailure)

let on_write (driver: t_UploadDriver) (observation: t_WriteObservation) : t_UploadTransition =
  match observation <: t_WriteObservation with
  | WriteObservation_Inserted
  | WriteObservation_Updated  ->
    transition ({
          driver with
          f_stage = UploadStage_Reread <: t_UploadStage;
          f_write_matched = true
        }
        <:
        t_UploadDriver)
      (UploadEffect_RereadVersion <: t_UploadEffect)
  | WriteObservation_Existing
  | WriteObservation_Duplicate  -> terminal driver (UploadFailure_AlreadyExists <: t_UploadFailure)
  | WriteObservation_Skipped  ->
    if driver.f_shadow
    then terminal driver (UploadFailure_RekeyEnded <: t_UploadFailure)
    else
      if
        match driver.f_intent <: t_WriteIntent with
        | WriteIntent_Create  -> true
        | _ -> false
      then terminal driver (UploadFailure_Rekeyed <: t_UploadFailure)
      else
        transition ({ driver with f_stage = UploadStage_Recheck <: t_UploadStage } <: t_UploadDriver
          )
          (UploadEffect_RecheckState <: t_UploadEffect)
  | WriteObservation_Failed  -> terminal driver (UploadFailure_WriteStorage <: t_UploadFailure)

let on_recheck (driver: t_UploadDriver) (observation: t_RecheckObservation) : t_UploadTransition =
  match observation <: t_RecheckObservation with
  | RecheckObservation_Unchanged  ->
    terminal driver (UploadFailure_VersionMismatch <: t_UploadFailure)
  | RecheckObservation_Changed  -> terminal driver (UploadFailure_Rekeyed <: t_UploadFailure)
  | RecheckObservation_Failed  -> terminal driver (UploadFailure_RecheckStorage <: t_UploadFailure)

let on_reread (driver: t_UploadDriver) (observation: t_RereadObservation) : t_UploadTransition =
  match observation <: t_RereadObservation with
  | RereadObservation_Read { f_version = version } ->
    if driver.f_shadow
    then
      transition ({
            driver with
            f_stage = UploadStage_Activity <: t_UploadStage;
            f_version = version
          }
          <:
          t_UploadDriver)
        (UploadEffect_RecordShadowActivity <: t_UploadEffect)
    else
      transition ({
            driver with
            f_stage = UploadStage_Publish <: t_UploadStage;
            f_version = version
          }
          <:
          t_UploadDriver)
        (UploadEffect_Publish <: t_UploadEffect)
  | RereadObservation_Missing
  | RereadObservation_Failed  -> terminal driver (UploadFailure_RereadStorage <: t_UploadFailure)

let on_activity (driver: t_UploadDriver) (observation: t_ActivityObservation) : t_UploadTransition =
  match observation <: t_ActivityObservation with
  | ActivityObservation_Refreshed
  | ActivityObservation_Ended  ->
    transition ({
          driver with
          f_stage = UploadStage_Publish <: t_UploadStage;
          f_activity_done = true
        }
        <:
        t_UploadDriver)
      (UploadEffect_Publish <: t_UploadEffect)
  | ActivityObservation_Failed  ->
    terminal driver (UploadFailure_ActivityStorage <: t_UploadFailure)

let on_publish (driver: t_UploadDriver) : t_UploadTransition =
  transition ({
        driver with
        f_stage = UploadStage_Done <: t_UploadStage;
        f_published = ~.driver.f_shadow <: bool;
        f_responded = true
      }
      <:
      t_UploadDriver)
    (UploadEffect_Complete <: t_UploadEffect)

/// The complete, total upload transition relation. Events that do not match
/// the current stage (and every event after `Done`) are ignored.
let upload_step (driver: t_UploadDriver) (event: t_UploadEvent) : t_UploadTransition =
  match event <: t_UploadEvent with
  | UploadEvent_Rekey observation ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Resolve  -> true
      | _ -> false
    then on_rekey driver observation
    else idle driver
  | UploadEvent_Attempt authority ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Shadow  -> true
      | _ -> false
    then on_attempt driver authority
    else idle driver
  | UploadEvent_Quota observation ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Quota  -> true
      | _ -> false
    then on_quota driver observation
    else idle driver
  | UploadEvent_Write observation ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Write  -> true
      | _ -> false
    then on_write driver observation
    else idle driver
  | UploadEvent_Recheck observation ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Recheck  -> true
      | _ -> false
    then on_recheck driver observation
    else idle driver
  | UploadEvent_Reread observation ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Reread  -> true
      | _ -> false
    then on_reread driver observation
    else idle driver
  | UploadEvent_Activity observation ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Activity  -> true
      | _ -> false
    then on_activity driver observation
    else idle driver
  | UploadEvent_Published  ->
    if
      match driver.f_stage <: t_UploadStage with
      | UploadStage_Publish  -> true
      | _ -> false
    then on_publish driver
    else idle driver

let on_rekey_observed (driver: t_UploadDriver) (observation: t_RekeyObservation)
    : t_UploadTransition = upload_step driver (UploadEvent_Rekey observation <: t_UploadEvent)

let on_attempt_observed (driver: t_UploadDriver) (authority: Vela_rekey_policy.t_AttemptAuthority)
    : t_UploadTransition = upload_step driver (UploadEvent_Attempt authority <: t_UploadEvent)

let on_quota_observed (driver: t_UploadDriver) (observation: t_QuotaObservation)
    : t_UploadTransition = upload_step driver (UploadEvent_Quota observation <: t_UploadEvent)

let on_write_observed (driver: t_UploadDriver) (observation: t_WriteObservation)
    : t_UploadTransition = upload_step driver (UploadEvent_Write observation <: t_UploadEvent)

let on_recheck_observed (driver: t_UploadDriver) (observation: t_RecheckObservation)
    : t_UploadTransition = upload_step driver (UploadEvent_Recheck observation <: t_UploadEvent)

let on_reread_observed (driver: t_UploadDriver) (observation: t_RereadObservation)
    : t_UploadTransition = upload_step driver (UploadEvent_Reread observation <: t_UploadEvent)

let on_activity_observed (driver: t_UploadDriver) (observation: t_ActivityObservation)
    : t_UploadTransition = upload_step driver (UploadEvent_Activity observation <: t_UploadEvent)

let on_published_observed (driver: t_UploadDriver) : t_UploadTransition =
  upload_step driver (UploadEvent_Published <: t_UploadEvent)

/// Authenticated reader facts captured before the read.
type t_ReadRequest = { f_authenticated:bool }

/// The post-rollback epoch served to readers.
type t_ReadEpochObservation = { f_epoch:i64 }

/// A decoded `vault_chunks` row, or a lookup failure.
type t_ReadLookupObservation =
  | ReadLookupObservation_Found {
    f_account_matches:bool;
    f_epoch_matches:bool;
    f_version:i64;
    f_lamport_clock:i64
  }: t_ReadLookupObservation
  | ReadLookupObservation_Missing : t_ReadLookupObservation
  | ReadLookupObservation_QueryFailed : t_ReadLookupObservation
  | ReadLookupObservation_Malformed : t_ReadLookupObservation

type t_ReadEvent =
  | ReadEvent_Epoch : t_ReadEpochObservation -> t_ReadEvent
  | ReadEvent_Lookup : t_ReadLookupObservation -> t_ReadEvent

type t_ReadFailure =
  | ReadFailure_Unauthenticated : t_ReadFailure
  | ReadFailure_InvalidEpoch : t_ReadFailure
  | ReadFailure_NotFound : t_ReadFailure
  | ReadFailure_QueryStorage : t_ReadFailure
  | ReadFailure_ParseStorage : t_ReadFailure
  | ReadFailure_ScopeViolation : t_ReadFailure

type t_ReadEffect =
  | ReadEffect_ReadEpoch : t_ReadEffect
  | ReadEffect_LookupChunk : t_ReadEffect
  | ReadEffect_Serve {
    f_version:i64;
    f_lamport_clock:i64
  }: t_ReadEffect
  | ReadEffect_Fail : t_ReadFailure -> t_ReadEffect
  | ReadEffect_Idle : t_ReadEffect

type t_ReadStage =
  | ReadStage_Epoch : t_ReadStage
  | ReadStage_Lookup : t_ReadStage
  | ReadStage_Done : t_ReadStage

type t_ReadDriver = {
  f_stage:t_ReadStage;
  f_authenticated:bool;
  f_epoch:i64;
  f_version:i64;
  f_lamport_clock:i64;
  f_responded:bool;
  f_failed:bool
}

type t_ReadTransition = {
  f_driver:t_ReadDriver;
  f_effect:t_ReadEffect
}

let read_state_is_sound (r: t_ReadDriver) : bool =
  let fresh:bool =
    r.f_epoch =. mk_i64 0 && r.f_version =. mk_i64 0 && r.f_lamport_clock =. mk_i64 0 &&
    ~.r.f_responded &&
    ~.r.f_failed
  in
  let lookup_clean:bool =
    r.f_authenticated && r.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH && r.f_version =. mk_i64 0 &&
    r.f_lamport_clock =. mk_i64 0 &&
    ~.r.f_responded &&
    ~.r.f_failed
  in
  let served:bool =
    r.f_authenticated && r.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH && r.f_responded &&
    ~.r.f_failed &&
    r.f_version >=. mk_i64 0
  in
  (~.(match r.f_stage <: t_ReadStage with
    | ReadStage_Epoch  -> true
    | _ -> false) ||
  r.f_authenticated && fresh) &&
  (~.(match r.f_stage <: t_ReadStage with
    | ReadStage_Lookup  -> true
    | _ -> false) ||
  lookup_clean) &&
  (~.(match r.f_stage <: t_ReadStage with
    | ReadStage_Done  -> true
    | _ -> false) ||
  (r.f_responded || r.f_failed) && ~.(r.f_responded && r.f_failed) && (~.r.f_responded || served))

let read_effect_is_sound (r: t_ReadDriver) (v_effect: t_ReadEffect) : bool =
  match v_effect <: t_ReadEffect with
  | ReadEffect_ReadEpoch  ->
    (match r.f_stage <: t_ReadStage with
      | ReadStage_Epoch  -> true
      | _ -> false) &&
    r.f_authenticated
  | ReadEffect_LookupChunk  ->
    (match r.f_stage <: t_ReadStage with
      | ReadStage_Lookup  -> true
      | _ -> false)
  | ReadEffect_Serve { f_version = _ ; f_lamport_clock = _ } ->
    (match r.f_stage <: t_ReadStage with
      | ReadStage_Done  -> true
      | _ -> false) &&
    r.f_responded &&
    ~.r.f_failed
  | ReadEffect_Fail _ ->
    (match r.f_stage <: t_ReadStage with
      | ReadStage_Done  -> true
      | _ -> false) &&
    r.f_failed &&
    ~.r.f_responded
  | ReadEffect_Idle  -> true

let read_transition (driver: t_ReadDriver) (v_effect: t_ReadEffect) : t_ReadTransition =
  { f_driver = driver; f_effect = v_effect } <: t_ReadTransition

let read_terminal (driver: t_ReadDriver) (failure: t_ReadFailure) : t_ReadTransition =
  read_transition ({ driver with f_stage = ReadStage_Done <: t_ReadStage; f_failed = true }
      <:
      t_ReadDriver)
    (ReadEffect_Fail failure <: t_ReadEffect)

/// Start a per-request read.
let begin_read (request: t_ReadRequest)
    : Prims.Pure t_ReadTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ReadTransition = result in
          read_state_is_sound result.f_driver &&
          read_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_ReadDriver =
    {
      f_stage = ReadStage_Epoch <: t_ReadStage;
      f_authenticated = request.f_authenticated;
      f_epoch = mk_i64 0;
      f_version = mk_i64 0;
      f_lamport_clock = mk_i64 0;
      f_responded = false;
      f_failed = false
    }
    <:
    t_ReadDriver
  in
  if request.f_authenticated
  then read_transition driver (ReadEffect_ReadEpoch <: t_ReadEffect)
  else read_terminal driver (ReadFailure_Unauthenticated <: t_ReadFailure)

let read_step (driver: t_ReadDriver) (event: t_ReadEvent) : t_ReadTransition =
  match event <: t_ReadEvent with
  | ReadEvent_Epoch observation ->
    if
      ~.(match driver.f_stage <: t_ReadStage with
        | ReadStage_Epoch  -> true
        | _ -> false)
    then read_transition driver (ReadEffect_Idle <: t_ReadEffect)
    else
      if observation.f_epoch <. Vela_rekey_policy.v_INITIAL_EPOCH
      then read_terminal driver (ReadFailure_InvalidEpoch <: t_ReadFailure)
      else
        read_transition ({
              driver with
              f_stage = ReadStage_Lookup <: t_ReadStage;
              f_epoch = observation.f_epoch
            }
            <:
            t_ReadDriver)
          (ReadEffect_LookupChunk <: t_ReadEffect)
  | ReadEvent_Lookup observation ->
    if
      ~.(match driver.f_stage <: t_ReadStage with
        | ReadStage_Lookup  -> true
        | _ -> false)
    then read_transition driver (ReadEffect_Idle <: t_ReadEffect)
    else
      match observation <: t_ReadLookupObservation with
      | ReadLookupObservation_Found
        { f_account_matches = account_matches ;
          f_epoch_matches = epoch_matches ;
          f_version = version ;
          f_lamport_clock = lamport_clock } ->
        if account_matches && epoch_matches
        then
          read_transition ({
                driver with
                f_stage = ReadStage_Done <: t_ReadStage;
                f_version = version;
                f_lamport_clock = lamport_clock;
                f_responded = true
              }
              <:
              t_ReadDriver)
            (ReadEffect_Serve ({ f_version = version; f_lamport_clock = lamport_clock })
              <:
              t_ReadEffect)
        else read_terminal driver (ReadFailure_ScopeViolation <: t_ReadFailure)
      | ReadLookupObservation_Missing  ->
        read_terminal driver (ReadFailure_NotFound <: t_ReadFailure)
      | ReadLookupObservation_QueryFailed  ->
        read_terminal driver (ReadFailure_QueryStorage <: t_ReadFailure)
      | ReadLookupObservation_Malformed  ->
        read_terminal driver (ReadFailure_ParseStorage <: t_ReadFailure)

let on_read_epoch (driver: t_ReadDriver) (observation: t_ReadEpochObservation) : t_ReadTransition =
  read_step driver (ReadEvent_Epoch observation <: t_ReadEvent)

let on_read_lookup (driver: t_ReadDriver) (observation: t_ReadLookupObservation) : t_ReadTransition =
  read_step driver (ReadEvent_Lookup observation <: t_ReadEvent)
