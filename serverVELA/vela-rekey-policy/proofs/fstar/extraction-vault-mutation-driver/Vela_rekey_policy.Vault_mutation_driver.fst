module Vela_rekey_policy.Vault_mutation_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Outcome of the vault write-schema floor check.
type t_SchemaObservation =
  | SchemaObservation_Allowed : t_SchemaObservation
  | SchemaObservation_Refused : t_SchemaObservation
  | SchemaObservation_Storage : t_SchemaObservation

/// Outcome of resolving the write route (including the lazy timeout rollback).
type t_RouteObservation =
  | RouteObservation_Active { f_epoch:i64 }: t_RouteObservation
  | RouteObservation_Freezing : t_RouteObservation
  | RouteObservation_Rejected : t_RouteObservation
  | RouteObservation_Storage : t_RouteObservation

/// Outcome of the ordinary storage quota.
type t_QuotaObservation =
  | QuotaObservation_Allowed : t_QuotaObservation
  | QuotaObservation_Exceeded : t_QuotaObservation
  | QuotaObservation_Storage : t_QuotaObservation

type t_ChunkDeleteRequest = {
  f_authenticated:bool;
  f_web:bool;
  f_web_epoch:Core_models.Option.t_Option i64;
  f_if_match:i64
}

type t_VersionObservation =
  | VersionObservation_Found { f_version:i64 }: t_VersionObservation
  | VersionObservation_Missing : t_VersionObservation
  | VersionObservation_Storage : t_VersionObservation

type t_DeleteObservation =
  | DeleteObservation_Deleted : t_DeleteObservation
  | DeleteObservation_Skipped : t_DeleteObservation
  | DeleteObservation_Storage : t_DeleteObservation

type t_ChunkDeleteEvent =
  | ChunkDeleteEvent_Schema : t_SchemaObservation -> t_ChunkDeleteEvent
  | ChunkDeleteEvent_Route : t_RouteObservation -> t_ChunkDeleteEvent
  | ChunkDeleteEvent_Version : t_VersionObservation -> t_ChunkDeleteEvent
  | ChunkDeleteEvent_Delete : t_DeleteObservation -> t_ChunkDeleteEvent
  | ChunkDeleteEvent_Published : t_ChunkDeleteEvent

type t_ChunkDeleteFailure =
  | ChunkDeleteFailure_SchemaRefused : t_ChunkDeleteFailure
  | ChunkDeleteFailure_SchemaStorage : t_ChunkDeleteFailure
  | ChunkDeleteFailure_Unauthenticated : t_ChunkDeleteFailure
  | ChunkDeleteFailure_EpochMismatch : t_ChunkDeleteFailure
  | ChunkDeleteFailure_RekeyInProgress : t_ChunkDeleteFailure
  | ChunkDeleteFailure_EpochStorage : t_ChunkDeleteFailure
  | ChunkDeleteFailure_AuthorityEpochMismatch : t_ChunkDeleteFailure
  | ChunkDeleteFailure_NotFound : t_ChunkDeleteFailure
  | ChunkDeleteFailure_VersionMismatch : t_ChunkDeleteFailure
  | ChunkDeleteFailure_Rekeyed : t_ChunkDeleteFailure
  | ChunkDeleteFailure_DeleteStorage : t_ChunkDeleteFailure

type t_ChunkDeleteEffect =
  | ChunkDeleteEffect_CheckSchema : t_ChunkDeleteEffect
  | ChunkDeleteEffect_ResolveEpoch : t_ChunkDeleteEffect
  | ChunkDeleteEffect_ReadVersion : t_ChunkDeleteEffect
  | ChunkDeleteEffect_DeleteRow : t_ChunkDeleteEffect
  | ChunkDeleteEffect_Publish : t_ChunkDeleteEffect
  | ChunkDeleteEffect_Complete : t_ChunkDeleteEffect
  | ChunkDeleteEffect_Fail : t_ChunkDeleteFailure -> t_ChunkDeleteEffect
  | ChunkDeleteEffect_Idle : t_ChunkDeleteEffect

type t_ChunkDeleteStage =
  | ChunkDeleteStage_Schema : t_ChunkDeleteStage
  | ChunkDeleteStage_Epoch : t_ChunkDeleteStage
  | ChunkDeleteStage_Version : t_ChunkDeleteStage
  | ChunkDeleteStage_Delete : t_ChunkDeleteStage
  | ChunkDeleteStage_Publish : t_ChunkDeleteStage
  | ChunkDeleteStage_Done : t_ChunkDeleteStage

type t_ChunkDeleteDriver = {
  f_stage:t_ChunkDeleteStage;
  f_authenticated:bool;
  f_web:bool;
  f_web_epoch:Core_models.Option.t_Option i64;
  f_if_match:i64;
  f_epoch:i64;
  f_permit_epoch:i64;
  f_current_version:i64;
  f_deleted:bool;
  f_published:bool;
  f_responded:bool;
  f_failed:bool
}

type t_ChunkDeleteTransition = {
  f_driver:t_ChunkDeleteDriver;
  f_effect:t_ChunkDeleteEffect
}

let impl_ChunkDeleteDriver__permitted (self: t_ChunkDeleteDriver) : bool =
  self.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH && self.f_permit_epoch =. self.f_epoch

let chunk_delete_state_is_sound (d: t_ChunkDeleteDriver) : bool =
  let fresh:bool =
    d.f_epoch =. mk_i64 0 && d.f_permit_epoch =. mk_i64 0 && d.f_current_version =. mk_i64 0 &&
    ~.d.f_deleted &&
    ~.d.f_published &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let permitted:bool =
    d.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH && d.f_permit_epoch =. d.f_epoch
  in
  let done:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded || impl_ChunkDeleteDriver__permitted d && d.f_deleted && d.f_published) &&
    (~.d.f_failed || ~.d.f_deleted)
  in
  (~.(match d.f_stage <: t_ChunkDeleteStage with
    | ChunkDeleteStage_Schema  -> true
    | _ -> false) ||
  d.f_authenticated && fresh) &&
  (~.(match d.f_stage <: t_ChunkDeleteStage with
    | ChunkDeleteStage_Epoch  -> true
    | _ -> false) ||
  d.f_authenticated && fresh) &&
  (~.(match d.f_stage <: t_ChunkDeleteStage with
    | ChunkDeleteStage_Version  -> true
    | _ -> false) ||
  permitted) &&
  (~.(match d.f_stage <: t_ChunkDeleteStage with
    | ChunkDeleteStage_Delete  -> true
    | _ -> false) ||
  permitted && d.f_current_version >=. mk_i64 0) &&
  (~.(match d.f_stage <: t_ChunkDeleteStage with
    | ChunkDeleteStage_Publish  -> true
    | _ -> false) ||
  permitted && d.f_deleted) &&
  (~.(match d.f_stage <: t_ChunkDeleteStage with
    | ChunkDeleteStage_Done  -> true
    | _ -> false) ||
  done) &&
  (~.d.f_deleted || permitted) &&
  (~.d.f_published || d.f_deleted)

let chunk_delete_effect_is_sound (d: t_ChunkDeleteDriver) (v_effect: t_ChunkDeleteEffect) : bool =
  match v_effect <: t_ChunkDeleteEffect with
  | ChunkDeleteEffect_CheckSchema  ->
    (match d.f_stage <: t_ChunkDeleteStage with
      | ChunkDeleteStage_Schema  -> true
      | _ -> false) &&
    d.f_authenticated
  | ChunkDeleteEffect_ResolveEpoch  ->
    (match d.f_stage <: t_ChunkDeleteStage with
      | ChunkDeleteStage_Epoch  -> true
      | _ -> false)
  | ChunkDeleteEffect_ReadVersion  ->
    (match d.f_stage <: t_ChunkDeleteStage with
      | ChunkDeleteStage_Version  -> true
      | _ -> false) &&
    impl_ChunkDeleteDriver__permitted d
  | ChunkDeleteEffect_DeleteRow  ->
    (match d.f_stage <: t_ChunkDeleteStage with
      | ChunkDeleteStage_Delete  -> true
      | _ -> false) &&
    impl_ChunkDeleteDriver__permitted d
  | ChunkDeleteEffect_Publish  ->
    (match d.f_stage <: t_ChunkDeleteStage with
      | ChunkDeleteStage_Publish  -> true
      | _ -> false) &&
    d.f_deleted
  | ChunkDeleteEffect_Complete  ->
    (match d.f_stage <: t_ChunkDeleteStage with
      | ChunkDeleteStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed
  | ChunkDeleteEffect_Fail _ ->
    (match d.f_stage <: t_ChunkDeleteStage with
      | ChunkDeleteStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | ChunkDeleteEffect_Idle  -> true

let chunk_transition (driver: t_ChunkDeleteDriver) (v_effect: t_ChunkDeleteEffect)
    : t_ChunkDeleteTransition =
  { f_driver = driver; f_effect = v_effect } <: t_ChunkDeleteTransition

let chunk_terminal (driver: t_ChunkDeleteDriver) (failure: t_ChunkDeleteFailure)
    : t_ChunkDeleteTransition =
  chunk_transition ({
        driver with
        f_stage = ChunkDeleteStage_Done <: t_ChunkDeleteStage;
        f_failed = true
      }
      <:
      t_ChunkDeleteDriver)
    (ChunkDeleteEffect_Fail failure <: t_ChunkDeleteEffect)

let begin_chunk_delete (request: t_ChunkDeleteRequest)
    : Prims.Pure t_ChunkDeleteTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ChunkDeleteTransition = result in
          chunk_delete_state_is_sound result.f_driver &&
          chunk_delete_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_ChunkDeleteDriver =
    {
      f_stage = ChunkDeleteStage_Schema <: t_ChunkDeleteStage;
      f_authenticated = request.f_authenticated;
      f_web = request.f_web;
      f_web_epoch = request.f_web_epoch;
      f_if_match = request.f_if_match;
      f_epoch = mk_i64 0;
      f_permit_epoch = mk_i64 0;
      f_current_version = mk_i64 0;
      f_deleted = false;
      f_published = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_ChunkDeleteDriver
  in
  if request.f_authenticated
  then chunk_transition driver (ChunkDeleteEffect_CheckSchema <: t_ChunkDeleteEffect)
  else chunk_terminal driver (ChunkDeleteFailure_SchemaRefused <: t_ChunkDeleteFailure)

let chunk_permit (driver: t_ChunkDeleteDriver)
    : Core_models.Result.t_Result i64 t_ChunkDeleteFailure =
  let authority:Vela_rekey_policy.t_MutationAuthority =
    if driver.f_web
    then Vela_rekey_policy.MutationAuthority_WebSession <: Vela_rekey_policy.t_MutationAuthority
    else Vela_rekey_policy.MutationAuthority_Device <: Vela_rekey_policy.t_MutationAuthority
  in
  let authority_epoch:i64 =
    if driver.f_web
    then
      Core_models.Option.impl__unwrap_or #i64 driver.f_web_epoch Vela_rekey_policy.v_INITIAL_EPOCH
    else driver.f_epoch
  in
  let request:Vela_rekey_policy.t_MutationRequest =
    {
      Vela_rekey_policy.f_declared_epoch = driver.f_epoch;
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
    Core_models.Result.Result_Ok (Vela_rekey_policy.impl_MutationPermit__epoch permit)
    <:
    Core_models.Result.t_Result i64 t_ChunkDeleteFailure
  | Vela_rekey_policy.MutationDecision_Reject  ->
    Core_models.Result.Result_Err
    (ChunkDeleteFailure_AuthorityEpochMismatch <: t_ChunkDeleteFailure)
    <:
    Core_models.Result.t_Result i64 t_ChunkDeleteFailure

let chunk_delete_step (driver: t_ChunkDeleteDriver) (event: t_ChunkDeleteEvent)
    : Prims.Pure t_ChunkDeleteTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ChunkDeleteTransition = result in
          ~.(chunk_delete_state_is_sound driver <: bool) ||
          chunk_delete_state_is_sound result.f_driver &&
          chunk_delete_effect_is_sound result.f_driver result.f_effect) =
  match event <: t_ChunkDeleteEvent with
  | ChunkDeleteEvent_Schema observation ->
    if
      ~.(match driver.f_stage <: t_ChunkDeleteStage with
        | ChunkDeleteStage_Schema  -> true
        | _ -> false)
    then chunk_transition driver (ChunkDeleteEffect_Idle <: t_ChunkDeleteEffect)
    else
      (match observation <: t_SchemaObservation with
        | SchemaObservation_Allowed  ->
          chunk_transition ({ driver with f_stage = ChunkDeleteStage_Epoch <: t_ChunkDeleteStage }
              <:
              t_ChunkDeleteDriver)
            (ChunkDeleteEffect_ResolveEpoch <: t_ChunkDeleteEffect)
        | SchemaObservation_Refused  ->
          chunk_terminal driver (ChunkDeleteFailure_SchemaRefused <: t_ChunkDeleteFailure)
        | SchemaObservation_Storage  ->
          chunk_terminal driver (ChunkDeleteFailure_SchemaStorage <: t_ChunkDeleteFailure))
  | ChunkDeleteEvent_Route observation ->
    if
      ~.(match driver.f_stage <: t_ChunkDeleteStage with
        | ChunkDeleteStage_Epoch  -> true
        | _ -> false)
    then chunk_transition driver (ChunkDeleteEffect_Idle <: t_ChunkDeleteEffect)
    else
      (match observation <: t_RouteObservation with
        | RouteObservation_Active { f_epoch = epoch } ->
          let routed:t_ChunkDeleteDriver = { driver with f_epoch = epoch } <: t_ChunkDeleteDriver in
          (match chunk_permit routed <: Core_models.Result.t_Result i64 t_ChunkDeleteFailure with
            | Core_models.Result.Result_Ok permit_epoch ->
              chunk_transition ({
                    routed with
                    f_stage = ChunkDeleteStage_Version <: t_ChunkDeleteStage;
                    f_permit_epoch = permit_epoch
                  }
                  <:
                  t_ChunkDeleteDriver)
                (ChunkDeleteEffect_ReadVersion <: t_ChunkDeleteEffect)
            | Core_models.Result.Result_Err failure -> chunk_terminal routed failure)
        | RouteObservation_Freezing  ->
          chunk_terminal driver (ChunkDeleteFailure_RekeyInProgress <: t_ChunkDeleteFailure)
        | RouteObservation_Rejected  ->
          chunk_terminal driver (ChunkDeleteFailure_EpochMismatch <: t_ChunkDeleteFailure)
        | RouteObservation_Storage  ->
          chunk_terminal driver (ChunkDeleteFailure_EpochStorage <: t_ChunkDeleteFailure))
  | ChunkDeleteEvent_Version observation ->
    if
      ~.(match driver.f_stage <: t_ChunkDeleteStage with
        | ChunkDeleteStage_Version  -> true
        | _ -> false)
    then chunk_transition driver (ChunkDeleteEffect_Idle <: t_ChunkDeleteEffect)
    else
      (match observation <: t_VersionObservation with
        | VersionObservation_Found { f_version = version } ->
          if version <>. driver.f_if_match
          then chunk_terminal driver (ChunkDeleteFailure_VersionMismatch <: t_ChunkDeleteFailure)
          else
            chunk_transition ({
                  driver with
                  f_stage = ChunkDeleteStage_Delete <: t_ChunkDeleteStage;
                  f_current_version = version
                }
                <:
                t_ChunkDeleteDriver)
              (ChunkDeleteEffect_DeleteRow <: t_ChunkDeleteEffect)
        | VersionObservation_Missing  ->
          chunk_terminal driver (ChunkDeleteFailure_NotFound <: t_ChunkDeleteFailure)
        | VersionObservation_Storage  ->
          chunk_terminal driver (ChunkDeleteFailure_DeleteStorage <: t_ChunkDeleteFailure))
  | ChunkDeleteEvent_Delete observation ->
    if
      ~.(match driver.f_stage <: t_ChunkDeleteStage with
        | ChunkDeleteStage_Delete  -> true
        | _ -> false)
    then chunk_transition driver (ChunkDeleteEffect_Idle <: t_ChunkDeleteEffect)
    else
      (match observation <: t_DeleteObservation with
        | DeleteObservation_Deleted  ->
          chunk_transition ({
                driver with
                f_stage = ChunkDeleteStage_Publish <: t_ChunkDeleteStage;
                f_deleted = true
              }
              <:
              t_ChunkDeleteDriver)
            (ChunkDeleteEffect_Publish <: t_ChunkDeleteEffect)
        | DeleteObservation_Skipped  ->
          chunk_terminal driver (ChunkDeleteFailure_Rekeyed <: t_ChunkDeleteFailure)
        | DeleteObservation_Storage  ->
          chunk_terminal driver (ChunkDeleteFailure_DeleteStorage <: t_ChunkDeleteFailure))
  | ChunkDeleteEvent_Published  ->
    if
      ~.(match driver.f_stage <: t_ChunkDeleteStage with
        | ChunkDeleteStage_Publish  -> true
        | _ -> false)
    then chunk_transition driver (ChunkDeleteEffect_Idle <: t_ChunkDeleteEffect)
    else
      chunk_transition ({
            driver with
            f_stage = ChunkDeleteStage_Done <: t_ChunkDeleteStage;
            f_published = true;
            f_responded = true
          }
          <:
          t_ChunkDeleteDriver)
        (ChunkDeleteEffect_Complete <: t_ChunkDeleteEffect)

type t_OramRequest = {
  f_authenticated:bool;
  f_web:bool;
  f_web_epoch:Core_models.Option.t_Option i64;
  f_bucket_count:i64;
  f_create_mask:u64
}

type t_BucketObservation =
  | BucketObservation_Written : t_BucketObservation
  | BucketObservation_Invalid : t_BucketObservation
  | BucketObservation_Existing : t_BucketObservation
  | BucketObservation_Skipped : t_BucketObservation
  | BucketObservation_Storage : t_BucketObservation

type t_BucketRecheckObservation =
  | BucketRecheckObservation_Unchanged : t_BucketRecheckObservation
  | BucketRecheckObservation_Changed : t_BucketRecheckObservation
  | BucketRecheckObservation_Failed : t_BucketRecheckObservation

type t_OramEvent =
  | OramEvent_Route : t_RouteObservation -> t_OramEvent
  | OramEvent_Quota : t_QuotaObservation -> t_OramEvent
  | OramEvent_Bucket : t_BucketObservation -> t_OramEvent
  | OramEvent_Recheck : t_BucketRecheckObservation -> t_OramEvent
  | OramEvent_Published : t_OramEvent

type t_OramFailure =
  | OramFailure_Unauthenticated : t_OramFailure
  | OramFailure_EpochMismatch : t_OramFailure
  | OramFailure_RekeyInProgress : t_OramFailure
  | OramFailure_EpochStorage : t_OramFailure
  | OramFailure_AuthorityEpochMismatch : t_OramFailure
  | OramFailure_QuotaExceeded : t_OramFailure
  | OramFailure_QuotaStorage : t_OramFailure
  | OramFailure_BucketInvalid : t_OramFailure
  | OramFailure_BucketExists : t_OramFailure
  | OramFailure_Rekeyed : t_OramFailure
  | OramFailure_BucketStorage : t_OramFailure
  | OramFailure_VersionMismatch : t_OramFailure
  | OramFailure_RecheckStorage : t_OramFailure

type t_OramEffect =
  | OramEffect_ResolveEpoch : t_OramEffect
  | OramEffect_EnforceQuota : t_OramEffect
  | OramEffect_WriteBucket { f_index:i64 }: t_OramEffect
  | OramEffect_RecheckBucket { f_index:i64 }: t_OramEffect
  | OramEffect_Publish : t_OramEffect
  | OramEffect_Complete : t_OramEffect
  | OramEffect_Fail : t_OramFailure -> t_OramEffect
  | OramEffect_Idle : t_OramEffect

type t_OramStage =
  | OramStage_Epoch : t_OramStage
  | OramStage_Quota : t_OramStage
  | OramStage_Bucket : t_OramStage
  | OramStage_Recheck : t_OramStage
  | OramStage_Publish : t_OramStage
  | OramStage_Done : t_OramStage

type t_OramDriver = {
  f_stage:t_OramStage;
  f_authenticated:bool;
  f_web:bool;
  f_web_epoch:Core_models.Option.t_Option i64;
  f_bucket_count:i64;
  f_create_mask:u64;
  f_written:i64;
  f_recheck_index:i64;
  f_epoch:i64;
  f_permit_epoch:i64;
  f_quota_allowed:bool;
  f_published:bool;
  f_responded:bool;
  f_failed:bool
}

type t_OramTransition = {
  f_driver:t_OramDriver;
  f_effect:t_OramEffect
}

let oram_state_is_sound (d: t_OramDriver) : bool =
  let fresh:bool =
    d.f_epoch =. mk_i64 0 && d.f_permit_epoch =. mk_i64 0 && d.f_written =. mk_i64 0 &&
    ~.d.f_quota_allowed &&
    ~.d.f_published &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let permitted:bool =
    d.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH && d.f_permit_epoch =. d.f_epoch
  in
  let done:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded || permitted && d.f_written =. d.f_bucket_count && d.f_published) &&
    (~.d.f_failed || ~.d.f_published)
  in
  (~.(match d.f_stage <: t_OramStage with
    | OramStage_Epoch  -> true
    | _ -> false) ||
  d.f_authenticated && fresh) &&
  (~.(match d.f_stage <: t_OramStage with
    | OramStage_Quota  -> true
    | _ -> false) ||
  permitted) &&
  (~.(match d.f_stage <: t_OramStage with
    | OramStage_Bucket  -> true
    | _ -> false) ||
  permitted && d.f_quota_allowed && d.f_written <. d.f_bucket_count) &&
  (~.(match d.f_stage <: t_OramStage with
    | OramStage_Recheck  -> true
    | _ -> false) ||
  permitted && d.f_quota_allowed && d.f_recheck_index <. d.f_bucket_count) &&
  (~.(match d.f_stage <: t_OramStage with
    | OramStage_Publish  -> true
    | _ -> false) ||
  permitted && d.f_written =. d.f_bucket_count && d.f_quota_allowed) &&
  (~.(match d.f_stage <: t_OramStage with
    | OramStage_Done  -> true
    | _ -> false) ||
  done) &&
  d.f_written <=. d.f_bucket_count &&
  (~.d.f_published || d.f_written =. d.f_bucket_count)

let oram_effect_is_sound (d: t_OramDriver) (v_effect: t_OramEffect) : bool =
  match v_effect <: t_OramEffect with
  | OramEffect_ResolveEpoch  ->
    (match d.f_stage <: t_OramStage with
      | OramStage_Epoch  -> true
      | _ -> false) &&
    d.f_authenticated
  | OramEffect_EnforceQuota  ->
    (match d.f_stage <: t_OramStage with
      | OramStage_Quota  -> true
      | _ -> false)
  | OramEffect_WriteBucket { f_index = index } ->
    (match d.f_stage <: t_OramStage with
      | OramStage_Bucket  -> true
      | _ -> false) &&
    index =. d.f_written &&
    index <. d.f_bucket_count
  | OramEffect_RecheckBucket { f_index = index } ->
    (match d.f_stage <: t_OramStage with
      | OramStage_Recheck  -> true
      | _ -> false) &&
    index =. d.f_recheck_index
  | OramEffect_Publish  ->
    (match d.f_stage <: t_OramStage with
      | OramStage_Publish  -> true
      | _ -> false) &&
    d.f_written =. d.f_bucket_count
  | OramEffect_Complete  ->
    (match d.f_stage <: t_OramStage with
      | OramStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed
  | OramEffect_Fail _ ->
    (match d.f_stage <: t_OramStage with
      | OramStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | OramEffect_Idle  -> true

let oram_transition (driver: t_OramDriver) (v_effect: t_OramEffect) : t_OramTransition =
  { f_driver = driver; f_effect = v_effect } <: t_OramTransition

let oram_terminal (driver: t_OramDriver) (failure: t_OramFailure) : t_OramTransition =
  oram_transition ({ driver with f_stage = OramStage_Done <: t_OramStage; f_failed = true }
      <:
      t_OramDriver)
    (OramEffect_Fail failure <: t_OramEffect)

let begin_oram (request: t_OramRequest)
    : Prims.Pure t_OramTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_OramTransition = result in
          oram_state_is_sound result.f_driver &&
          oram_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_OramDriver =
    {
      f_stage = OramStage_Epoch <: t_OramStage;
      f_authenticated = request.f_authenticated;
      f_web = request.f_web;
      f_web_epoch = request.f_web_epoch;
      f_bucket_count = request.f_bucket_count;
      f_create_mask = request.f_create_mask;
      f_written = mk_i64 0;
      f_recheck_index = mk_i64 0;
      f_epoch = mk_i64 0;
      f_permit_epoch = mk_i64 0;
      f_quota_allowed = false;
      f_published = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_OramDriver
  in
  if ~.request.f_authenticated
  then oram_terminal driver (OramFailure_Unauthenticated <: t_OramFailure)
  else
    if request.f_bucket_count =. mk_i64 0 || request.f_bucket_count >. mk_i64 33
    then oram_terminal driver (OramFailure_BucketInvalid <: t_OramFailure)
    else oram_transition driver (OramEffect_ResolveEpoch <: t_OramEffect)

let oram_permit (driver: t_OramDriver) : Core_models.Result.t_Result i64 t_OramFailure =
  let authority:Vela_rekey_policy.t_MutationAuthority =
    if driver.f_web
    then Vela_rekey_policy.MutationAuthority_WebSession <: Vela_rekey_policy.t_MutationAuthority
    else Vela_rekey_policy.MutationAuthority_Device <: Vela_rekey_policy.t_MutationAuthority
  in
  let authority_epoch:i64 =
    if driver.f_web
    then
      Core_models.Option.impl__unwrap_or #i64 driver.f_web_epoch Vela_rekey_policy.v_INITIAL_EPOCH
    else driver.f_epoch
  in
  let request:Vela_rekey_policy.t_MutationRequest =
    {
      Vela_rekey_policy.f_declared_epoch = driver.f_epoch;
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
    Core_models.Result.Result_Ok (Vela_rekey_policy.impl_MutationPermit__epoch permit)
    <:
    Core_models.Result.t_Result i64 t_OramFailure
  | Vela_rekey_policy.MutationDecision_Reject  ->
    Core_models.Result.Result_Err (OramFailure_AuthorityEpochMismatch <: t_OramFailure)
    <:
    Core_models.Result.t_Result i64 t_OramFailure

let oram_bucket_is_create (driver: t_OramDriver) (index: i64) : bool =
  index >=. mk_i64 0 && index <. mk_i64 64 &&
  (driver.f_create_mask &. (mk_u64 1 <<! index <: u64) <: u64) <>. mk_u64 0

let oram_step (driver: t_OramDriver) (event: t_OramEvent)
    : Prims.Pure t_OramTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_OramTransition = result in
          ~.(oram_state_is_sound driver <: bool) ||
          oram_state_is_sound result.f_driver &&
          oram_effect_is_sound result.f_driver result.f_effect) =
  match event <: t_OramEvent with
  | OramEvent_Route observation ->
    if
      ~.(match driver.f_stage <: t_OramStage with
        | OramStage_Epoch  -> true
        | _ -> false)
    then oram_transition driver (OramEffect_Idle <: t_OramEffect)
    else
      (match observation <: t_RouteObservation with
        | RouteObservation_Active { f_epoch = epoch } ->
          if epoch <. Vela_rekey_policy.v_INITIAL_EPOCH
          then oram_terminal driver (OramFailure_EpochMismatch <: t_OramFailure)
          else
            let routed:t_OramDriver = { driver with f_epoch = epoch } <: t_OramDriver in
            (match oram_permit routed <: Core_models.Result.t_Result i64 t_OramFailure with
              | Core_models.Result.Result_Ok permit_epoch ->
                oram_transition ({
                      routed with
                      f_stage = OramStage_Quota <: t_OramStage;
                      f_permit_epoch = permit_epoch
                    }
                    <:
                    t_OramDriver)
                  (OramEffect_EnforceQuota <: t_OramEffect)
              | Core_models.Result.Result_Err failure -> oram_terminal routed failure)
        | RouteObservation_Freezing  ->
          oram_terminal driver (OramFailure_RekeyInProgress <: t_OramFailure)
        | RouteObservation_Rejected  ->
          oram_terminal driver (OramFailure_EpochMismatch <: t_OramFailure)
        | RouteObservation_Storage  ->
          oram_terminal driver (OramFailure_EpochStorage <: t_OramFailure))
  | OramEvent_Quota observation ->
    if
      ~.(match driver.f_stage <: t_OramStage with
        | OramStage_Quota  -> true
        | _ -> false)
    then oram_transition driver (OramEffect_Idle <: t_OramEffect)
    else
      (match observation <: t_QuotaObservation with
        | QuotaObservation_Allowed  ->
          oram_transition ({
                driver with
                f_stage = OramStage_Bucket <: t_OramStage;
                f_quota_allowed = true
              }
              <:
              t_OramDriver)
            (OramEffect_WriteBucket ({ f_index = mk_i64 0 }) <: t_OramEffect)
        | QuotaObservation_Exceeded  ->
          oram_terminal driver (OramFailure_QuotaExceeded <: t_OramFailure)
        | QuotaObservation_Storage  ->
          oram_terminal driver (OramFailure_QuotaStorage <: t_OramFailure))
  | OramEvent_Bucket observation ->
    if
      ~.(match driver.f_stage <: t_OramStage with
        | OramStage_Bucket  -> true
        | _ -> false)
    then oram_transition driver (OramEffect_Idle <: t_OramEffect)
    else
      let index:i64 = driver.f_written in
      (match observation <: t_BucketObservation with
        | BucketObservation_Written  ->
          let next:i64 = if index <. driver.f_bucket_count then index +! mk_i64 1 else index in
          if next =. driver.f_bucket_count
          then
            oram_transition ({
                  driver with
                  f_stage = OramStage_Publish <: t_OramStage;
                  f_written = next
                }
                <:
                t_OramDriver)
              (OramEffect_Publish <: t_OramEffect)
          else
            oram_transition ({ driver with f_written = next } <: t_OramDriver)
              (OramEffect_WriteBucket ({ f_index = next }) <: t_OramEffect)
        | BucketObservation_Skipped  ->
          if oram_bucket_is_create driver index
          then oram_terminal driver (OramFailure_Rekeyed <: t_OramFailure)
          else
            oram_transition ({
                  driver with
                  f_stage = OramStage_Recheck <: t_OramStage;
                  f_recheck_index = index
                }
                <:
                t_OramDriver)
              (OramEffect_RecheckBucket ({ f_index = index }) <: t_OramEffect)
        | BucketObservation_Existing  ->
          oram_terminal driver (OramFailure_BucketExists <: t_OramFailure)
        | BucketObservation_Invalid  ->
          oram_terminal driver (OramFailure_BucketInvalid <: t_OramFailure)
        | BucketObservation_Storage  ->
          oram_terminal driver (OramFailure_BucketStorage <: t_OramFailure))
  | OramEvent_Recheck observation ->
    if
      ~.(match driver.f_stage <: t_OramStage with
        | OramStage_Recheck  -> true
        | _ -> false)
    then oram_transition driver (OramEffect_Idle <: t_OramEffect)
    else
      (match observation <: t_BucketRecheckObservation with
        | BucketRecheckObservation_Unchanged  ->
          oram_terminal driver (OramFailure_VersionMismatch <: t_OramFailure)
        | BucketRecheckObservation_Changed  ->
          oram_terminal driver (OramFailure_Rekeyed <: t_OramFailure)
        | BucketRecheckObservation_Failed  ->
          oram_terminal driver (OramFailure_RecheckStorage <: t_OramFailure))
  | OramEvent_Published  ->
    if
      ~.(match driver.f_stage <: t_OramStage with
        | OramStage_Publish  -> true
        | _ -> false)
    then oram_transition driver (OramEffect_Idle <: t_OramEffect)
    else
      oram_transition ({
            driver with
            f_stage = OramStage_Done <: t_OramStage;
            f_published = true;
            f_responded = true
          }
          <:
          t_OramDriver)
        (OramEffect_Complete <: t_OramEffect)

type t_SchemaRequest = {
  f_authenticated:bool;
  f_device_scope:bool
}

type t_SchemaWriteObservation =
  | SchemaWriteObservation_Written : t_SchemaWriteObservation
  | SchemaWriteObservation_Storage : t_SchemaWriteObservation

type t_SchemaEvent = | SchemaEvent_Write : t_SchemaWriteObservation -> t_SchemaEvent

type t_SchemaFailure =
  | SchemaFailure_Unauthenticated : t_SchemaFailure
  | SchemaFailure_WebSessionForbidden : t_SchemaFailure
  | SchemaFailure_WriteStorage : t_SchemaFailure

type t_SchemaEffect =
  | SchemaEffect_WriteFloor : t_SchemaEffect
  | SchemaEffect_Complete : t_SchemaEffect
  | SchemaEffect_Fail : t_SchemaFailure -> t_SchemaEffect
  | SchemaEffect_Idle : t_SchemaEffect

type t_SchemaStage =
  | SchemaStage_Write : t_SchemaStage
  | SchemaStage_Done : t_SchemaStage

type t_SchemaDriver = {
  f_stage:t_SchemaStage;
  f_authenticated:bool;
  f_device_scope:bool;
  f_written:bool;
  f_responded:bool;
  f_failed:bool
}

type t_SchemaTransition = {
  f_driver:t_SchemaDriver;
  f_effect:t_SchemaEffect
}

let schema_state_is_sound (d: t_SchemaDriver) : bool =
  (~.(match d.f_stage <: t_SchemaStage with
    | SchemaStage_Write  -> true
    | _ -> false) ||
  d.f_authenticated && d.f_device_scope && ~.d.f_written) &&
  (~.(match d.f_stage <: t_SchemaStage with
    | SchemaStage_Done  -> true
    | _ -> false) ||
  (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
  (~.d.f_responded || d.f_written)) &&
  (~.d.f_written || d.f_authenticated && d.f_device_scope)

let schema_effect_is_sound (d: t_SchemaDriver) (v_effect: t_SchemaEffect) : bool =
  match v_effect <: t_SchemaEffect with
  | SchemaEffect_WriteFloor  ->
    (match d.f_stage <: t_SchemaStage with
      | SchemaStage_Write  -> true
      | _ -> false) &&
    d.f_authenticated &&
    d.f_device_scope
  | SchemaEffect_Complete  ->
    (match d.f_stage <: t_SchemaStage with
      | SchemaStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed
  | SchemaEffect_Fail _ ->
    (match d.f_stage <: t_SchemaStage with
      | SchemaStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | SchemaEffect_Idle  -> true

let schema_transition (driver: t_SchemaDriver) (v_effect: t_SchemaEffect) : t_SchemaTransition =
  { f_driver = driver; f_effect = v_effect } <: t_SchemaTransition

let schema_terminal (driver: t_SchemaDriver) (failure: t_SchemaFailure) : t_SchemaTransition =
  schema_transition ({ driver with f_stage = SchemaStage_Done <: t_SchemaStage; f_failed = true }
      <:
      t_SchemaDriver)
    (SchemaEffect_Fail failure <: t_SchemaEffect)

let begin_schema (request: t_SchemaRequest)
    : Prims.Pure t_SchemaTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_SchemaTransition = result in
          schema_state_is_sound result.f_driver &&
          schema_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_SchemaDriver =
    {
      f_stage = SchemaStage_Write <: t_SchemaStage;
      f_authenticated = request.f_authenticated;
      f_device_scope = request.f_device_scope;
      f_written = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_SchemaDriver
  in
  if ~.request.f_authenticated
  then schema_terminal driver (SchemaFailure_Unauthenticated <: t_SchemaFailure)
  else
    if ~.request.f_device_scope
    then schema_terminal driver (SchemaFailure_WebSessionForbidden <: t_SchemaFailure)
    else schema_transition driver (SchemaEffect_WriteFloor <: t_SchemaEffect)

let schema_step (driver: t_SchemaDriver) (event: t_SchemaEvent)
    : Prims.Pure t_SchemaTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_SchemaTransition = result in
          ~.(schema_state_is_sound driver <: bool) ||
          schema_state_is_sound result.f_driver &&
          schema_effect_is_sound result.f_driver result.f_effect) =
  match event <: t_SchemaEvent with
  | SchemaEvent_Write observation ->
    if
      ~.(match driver.f_stage <: t_SchemaStage with
        | SchemaStage_Write  -> true
        | _ -> false)
    then schema_transition driver (SchemaEffect_Idle <: t_SchemaEffect)
    else
      match observation <: t_SchemaWriteObservation with
      | SchemaWriteObservation_Written  ->
        schema_transition ({
              driver with
              f_stage = SchemaStage_Done <: t_SchemaStage;
              f_written = true;
              f_responded = true
            }
            <:
            t_SchemaDriver)
          (SchemaEffect_Complete <: t_SchemaEffect)
      | SchemaWriteObservation_Storage  ->
        schema_terminal driver (SchemaFailure_WriteStorage <: t_SchemaFailure)

type t_CapsuleAckRequest = {
  f_authenticated:bool;
  f_device_scope:bool
}

type t_AckObservation =
  | AckObservation_Cleared : t_AckObservation
  | AckObservation_Missed : t_AckObservation
  | AckObservation_Storage : t_AckObservation

type t_PendingObservation =
  | PendingObservation_Replay : t_PendingObservation
  | PendingObservation_Pending : t_PendingObservation
  | PendingObservation_Missing : t_PendingObservation
  | PendingObservation_Storage : t_PendingObservation

type t_CapsuleAckEvent =
  | CapsuleAckEvent_Ack : t_AckObservation -> t_CapsuleAckEvent
  | CapsuleAckEvent_Pending : t_PendingObservation -> t_CapsuleAckEvent

type t_CapsuleAckFailure =
  | CapsuleAckFailure_Unauthenticated : t_CapsuleAckFailure
  | CapsuleAckFailure_WebSessionForbidden : t_CapsuleAckFailure
  | CapsuleAckFailure_AckStorage : t_CapsuleAckFailure
  | CapsuleAckFailure_NoLongerEligible : t_CapsuleAckFailure
  | CapsuleAckFailure_DifferentPending : t_CapsuleAckFailure
  | CapsuleAckFailure_PendingStorage : t_CapsuleAckFailure

type t_CapsuleAckEffect =
  | CapsuleAckEffect_Acknowledge : t_CapsuleAckEffect
  | CapsuleAckEffect_InspectPending : t_CapsuleAckEffect
  | CapsuleAckEffect_Complete : t_CapsuleAckEffect
  | CapsuleAckEffect_Fail : t_CapsuleAckFailure -> t_CapsuleAckEffect
  | CapsuleAckEffect_Idle : t_CapsuleAckEffect

type t_CapsuleAckStage =
  | CapsuleAckStage_Ack : t_CapsuleAckStage
  | CapsuleAckStage_Pending : t_CapsuleAckStage
  | CapsuleAckStage_Done : t_CapsuleAckStage

type t_CapsuleAckDriver = {
  f_stage:t_CapsuleAckStage;
  f_authenticated:bool;
  f_device_scope:bool;
  f_cleared:bool;
  f_responded:bool;
  f_failed:bool
}

type t_CapsuleAckTransition = {
  f_driver:t_CapsuleAckDriver;
  f_effect:t_CapsuleAckEffect
}

let capsule_ack_state_is_sound (d: t_CapsuleAckDriver) : bool =
  (~.(match d.f_stage <: t_CapsuleAckStage with
    | CapsuleAckStage_Ack  -> true
    | _ -> false) ||
  d.f_authenticated && d.f_device_scope && ~.d.f_cleared) &&
  (~.(match d.f_stage <: t_CapsuleAckStage with
    | CapsuleAckStage_Pending  -> true
    | _ -> false) ||
  d.f_authenticated && d.f_device_scope) &&
  (~.(match d.f_stage <: t_CapsuleAckStage with
    | CapsuleAckStage_Done  -> true
    | _ -> false) ||
  (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
  (~.d.f_responded || d.f_cleared)) &&
  (~.d.f_cleared || d.f_authenticated && d.f_device_scope)

let capsule_ack_effect_is_sound (d: t_CapsuleAckDriver) (v_effect: t_CapsuleAckEffect) : bool =
  match v_effect <: t_CapsuleAckEffect with
  | CapsuleAckEffect_Acknowledge  ->
    (match d.f_stage <: t_CapsuleAckStage with
      | CapsuleAckStage_Ack  -> true
      | _ -> false) &&
    d.f_authenticated &&
    d.f_device_scope
  | CapsuleAckEffect_InspectPending  ->
    (match d.f_stage <: t_CapsuleAckStage with
      | CapsuleAckStage_Pending  -> true
      | _ -> false)
  | CapsuleAckEffect_Complete  ->
    (match d.f_stage <: t_CapsuleAckStage with
      | CapsuleAckStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed
  | CapsuleAckEffect_Fail _ ->
    (match d.f_stage <: t_CapsuleAckStage with
      | CapsuleAckStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | CapsuleAckEffect_Idle  -> true

let ack_transition (driver: t_CapsuleAckDriver) (v_effect: t_CapsuleAckEffect)
    : t_CapsuleAckTransition = { f_driver = driver; f_effect = v_effect } <: t_CapsuleAckTransition

let ack_terminal (driver: t_CapsuleAckDriver) (failure: t_CapsuleAckFailure)
    : t_CapsuleAckTransition =
  ack_transition ({
        driver with
        f_stage = CapsuleAckStage_Done <: t_CapsuleAckStage;
        f_failed = true
      }
      <:
      t_CapsuleAckDriver)
    (CapsuleAckEffect_Fail failure <: t_CapsuleAckEffect)

let begin_capsule_ack (request: t_CapsuleAckRequest)
    : Prims.Pure t_CapsuleAckTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_CapsuleAckTransition = result in
          capsule_ack_state_is_sound result.f_driver &&
          capsule_ack_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_CapsuleAckDriver =
    {
      f_stage = CapsuleAckStage_Ack <: t_CapsuleAckStage;
      f_authenticated = request.f_authenticated;
      f_device_scope = request.f_device_scope;
      f_cleared = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_CapsuleAckDriver
  in
  if ~.request.f_authenticated
  then ack_terminal driver (CapsuleAckFailure_Unauthenticated <: t_CapsuleAckFailure)
  else
    if ~.request.f_device_scope
    then ack_terminal driver (CapsuleAckFailure_WebSessionForbidden <: t_CapsuleAckFailure)
    else ack_transition driver (CapsuleAckEffect_Acknowledge <: t_CapsuleAckEffect)

let capsule_ack_step (driver: t_CapsuleAckDriver) (event: t_CapsuleAckEvent)
    : Prims.Pure t_CapsuleAckTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_CapsuleAckTransition = result in
          ~.(capsule_ack_state_is_sound driver <: bool) ||
          capsule_ack_state_is_sound result.f_driver &&
          capsule_ack_effect_is_sound result.f_driver result.f_effect) =
  match event <: t_CapsuleAckEvent with
  | CapsuleAckEvent_Ack observation ->
    if
      ~.(match driver.f_stage <: t_CapsuleAckStage with
        | CapsuleAckStage_Ack  -> true
        | _ -> false)
    then ack_transition driver (CapsuleAckEffect_Idle <: t_CapsuleAckEffect)
    else
      (match observation <: t_AckObservation with
        | AckObservation_Cleared  ->
          ack_transition ({
                driver with
                f_stage = CapsuleAckStage_Done <: t_CapsuleAckStage;
                f_cleared = true;
                f_responded = true
              }
              <:
              t_CapsuleAckDriver)
            (CapsuleAckEffect_Complete <: t_CapsuleAckEffect)
        | AckObservation_Missed  ->
          ack_transition ({ driver with f_stage = CapsuleAckStage_Pending <: t_CapsuleAckStage }
              <:
              t_CapsuleAckDriver)
            (CapsuleAckEffect_InspectPending <: t_CapsuleAckEffect)
        | AckObservation_Storage  ->
          ack_terminal driver (CapsuleAckFailure_AckStorage <: t_CapsuleAckFailure))
  | CapsuleAckEvent_Pending observation ->
    if
      ~.(match driver.f_stage <: t_CapsuleAckStage with
        | CapsuleAckStage_Pending  -> true
        | _ -> false)
    then ack_transition driver (CapsuleAckEffect_Idle <: t_CapsuleAckEffect)
    else
      match observation <: t_PendingObservation with
      | PendingObservation_Replay  ->
        ack_transition ({
              driver with
              f_stage = CapsuleAckStage_Done <: t_CapsuleAckStage;
              f_cleared = true;
              f_responded = true
            }
            <:
            t_CapsuleAckDriver)
          (CapsuleAckEffect_Complete <: t_CapsuleAckEffect)
      | PendingObservation_Pending  ->
        ack_terminal driver (CapsuleAckFailure_DifferentPending <: t_CapsuleAckFailure)
      | PendingObservation_Missing  ->
        ack_terminal driver (CapsuleAckFailure_NoLongerEligible <: t_CapsuleAckFailure)
      | PendingObservation_Storage  ->
        ack_terminal driver (CapsuleAckFailure_PendingStorage <: t_CapsuleAckFailure)

type t_RekeyCapableRequest = {
  f_authenticated:bool;
  f_device_scope:bool
}

type t_AttestObservation =
  | AttestObservation_Attested : t_AttestObservation
  | AttestObservation_Missing : t_AttestObservation
  | AttestObservation_Storage : t_AttestObservation

type t_RekeyCapableEvent = | RekeyCapableEvent_Attest : t_AttestObservation -> t_RekeyCapableEvent

type t_RekeyCapableFailure =
  | RekeyCapableFailure_Unauthenticated : t_RekeyCapableFailure
  | RekeyCapableFailure_WebSessionForbidden : t_RekeyCapableFailure
  | RekeyCapableFailure_NotFound : t_RekeyCapableFailure
  | RekeyCapableFailure_Storage : t_RekeyCapableFailure

type t_RekeyCapableEffect =
  | RekeyCapableEffect_Attest : t_RekeyCapableEffect
  | RekeyCapableEffect_Complete : t_RekeyCapableEffect
  | RekeyCapableEffect_Fail : t_RekeyCapableFailure -> t_RekeyCapableEffect
  | RekeyCapableEffect_Idle : t_RekeyCapableEffect

type t_RekeyCapableStage =
  | RekeyCapableStage_Attest : t_RekeyCapableStage
  | RekeyCapableStage_Done : t_RekeyCapableStage

type t_RekeyCapableDriver = {
  f_stage:t_RekeyCapableStage;
  f_authenticated:bool;
  f_device_scope:bool;
  f_attested:bool;
  f_responded:bool;
  f_failed:bool
}

type t_RekeyCapableTransition = {
  f_driver:t_RekeyCapableDriver;
  f_effect:t_RekeyCapableEffect
}

let rekey_capable_state_is_sound (d: t_RekeyCapableDriver) : bool =
  (~.(match d.f_stage <: t_RekeyCapableStage with
    | RekeyCapableStage_Attest  -> true
    | _ -> false) ||
  d.f_authenticated && d.f_device_scope && ~.d.f_attested) &&
  (~.(match d.f_stage <: t_RekeyCapableStage with
    | RekeyCapableStage_Done  -> true
    | _ -> false) ||
  (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
  (~.d.f_responded || d.f_attested)) &&
  (~.d.f_attested || d.f_authenticated && d.f_device_scope)

let rekey_capable_effect_is_sound (d: t_RekeyCapableDriver) (v_effect: t_RekeyCapableEffect) : bool =
  match v_effect <: t_RekeyCapableEffect with
  | RekeyCapableEffect_Attest  ->
    (match d.f_stage <: t_RekeyCapableStage with
      | RekeyCapableStage_Attest  -> true
      | _ -> false) &&
    d.f_authenticated &&
    d.f_device_scope
  | RekeyCapableEffect_Complete  ->
    (match d.f_stage <: t_RekeyCapableStage with
      | RekeyCapableStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed
  | RekeyCapableEffect_Fail _ ->
    (match d.f_stage <: t_RekeyCapableStage with
      | RekeyCapableStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | RekeyCapableEffect_Idle  -> true

let capable_transition (driver: t_RekeyCapableDriver) (v_effect: t_RekeyCapableEffect)
    : t_RekeyCapableTransition =
  { f_driver = driver; f_effect = v_effect } <: t_RekeyCapableTransition

let capable_terminal (driver: t_RekeyCapableDriver) (failure: t_RekeyCapableFailure)
    : t_RekeyCapableTransition =
  capable_transition ({
        driver with
        f_stage = RekeyCapableStage_Done <: t_RekeyCapableStage;
        f_failed = true
      }
      <:
      t_RekeyCapableDriver)
    (RekeyCapableEffect_Fail failure <: t_RekeyCapableEffect)

let begin_rekey_capable (request: t_RekeyCapableRequest)
    : Prims.Pure t_RekeyCapableTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RekeyCapableTransition = result in
          rekey_capable_state_is_sound result.f_driver &&
          rekey_capable_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_RekeyCapableDriver =
    {
      f_stage = RekeyCapableStage_Attest <: t_RekeyCapableStage;
      f_authenticated = request.f_authenticated;
      f_device_scope = request.f_device_scope;
      f_attested = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_RekeyCapableDriver
  in
  if ~.request.f_authenticated
  then capable_terminal driver (RekeyCapableFailure_Unauthenticated <: t_RekeyCapableFailure)
  else
    if ~.request.f_device_scope
    then capable_terminal driver (RekeyCapableFailure_WebSessionForbidden <: t_RekeyCapableFailure)
    else capable_transition driver (RekeyCapableEffect_Attest <: t_RekeyCapableEffect)

let rekey_capable_step (driver: t_RekeyCapableDriver) (event: t_RekeyCapableEvent)
    : Prims.Pure t_RekeyCapableTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RekeyCapableTransition = result in
          ~.(rekey_capable_state_is_sound driver <: bool) ||
          rekey_capable_state_is_sound result.f_driver &&
          rekey_capable_effect_is_sound result.f_driver result.f_effect) =
  match event <: t_RekeyCapableEvent with
  | RekeyCapableEvent_Attest observation ->
    if
      ~.(match driver.f_stage <: t_RekeyCapableStage with
        | RekeyCapableStage_Attest  -> true
        | _ -> false)
    then capable_transition driver (RekeyCapableEffect_Idle <: t_RekeyCapableEffect)
    else
      match observation <: t_AttestObservation with
      | AttestObservation_Attested  ->
        capable_transition ({
              driver with
              f_stage = RekeyCapableStage_Done <: t_RekeyCapableStage;
              f_attested = true;
              f_responded = true
            }
            <:
            t_RekeyCapableDriver)
          (RekeyCapableEffect_Complete <: t_RekeyCapableEffect)
      | AttestObservation_Missing  ->
        capable_terminal driver (RekeyCapableFailure_NotFound <: t_RekeyCapableFailure)
      | AttestObservation_Storage  ->
        capable_terminal driver (RekeyCapableFailure_Storage <: t_RekeyCapableFailure)
