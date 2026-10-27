module Vela_recovery_policy.Recovery_share_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Which recovery-share handler this request is running.
type t_ShareOperation =
  | ShareOperation_Stage : t_ShareOperation
  | ShareOperation_Finalize : t_ShareOperation
  | ShareOperation_Delete : t_ShareOperation
  | ShareOperation_Read : t_ShareOperation

/// Actor facts established by the authenticated `DeviceSession` extractor.
type t_ShareActorObservation = {
  f_authenticated:bool;
  f_device_active:bool;
  f_scoped_to_session_account:bool
}

/// The request facts the driver needs. `split` is a deterministic token derived
/// from the request's split id; it is used only to keep the driver's own
/// publication identity coherent and never changes the SQL text.
type t_ShareRequestObservation = {
  f_operation:t_ShareOperation;
  f_actor:t_ShareActorObservation;
  f_declared_epoch:i64;
  f_split_id_present:bool;
  f_share_present:bool;
  f_device_authority:bool;
  f_split:i64
}

/// Outcome of the guarded update that stages a candidate.
type t_StageUpdateObservation =
  | StageUpdateObservation_Staged : t_StageUpdateObservation
  | StageUpdateObservation_NotStaged : t_StageUpdateObservation

/// Live-row observation after a zero-row stage update.
type t_StageAccountObservation = {
  f_account_present:bool;
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_rotation_active:bool;
  f_active_share_matches:bool;
  f_active_split_matches:bool
}

/// Outcome of the guarded update that promotes the exact staged split.
type t_FinalizeUpdateObservation =
  | FinalizeUpdateObservation_Promoted : t_FinalizeUpdateObservation
  | FinalizeUpdateObservation_NotPromoted : t_FinalizeUpdateObservation

/// Live-row observation after a zero-row finalize update.
type t_FinalizeAccountObservation = {
  f_account_present:bool;
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_rotation_active:bool;
  f_active_split_matches:bool
}

/// Outcome of the guarded delete.
type t_DeleteUpdateObservation =
  | DeleteUpdateObservation_Deleted : t_DeleteUpdateObservation
  | DeleteUpdateObservation_NotDeleted : t_DeleteUpdateObservation

/// Outcome of the read query and the share-text decode.
type t_ReadObservation = {
  f_account_present:bool;
  f_share_present:bool
}

/// Where the lifecycle request is in its decision sequence.
type t_ShareStage =
  | ShareStage_Stage : t_ShareStage
  | ShareStage_StageAccount : t_ShareStage
  | ShareStage_Finalize : t_ShareStage
  | ShareStage_FinalizeAccount : t_ShareStage
  | ShareStage_Delete : t_ShareStage
  | ShareStage_Read : t_ShareStage
  | ShareStage_Done : t_ShareStage

/// One driver event. The handler feeds exactly the observation it obtained from
/// the corresponding effect.
type t_ShareEvent =
  | ShareEvent_StageUpdate : t_StageUpdateObservation -> t_ShareEvent
  | ShareEvent_StageAccount : t_StageAccountObservation -> t_ShareEvent
  | ShareEvent_FinalizeUpdate : t_FinalizeUpdateObservation -> t_ShareEvent
  | ShareEvent_FinalizeAccount : t_FinalizeAccountObservation -> t_ShareEvent
  | ShareEvent_DeleteUpdate : t_DeleteUpdateObservation -> t_ShareEvent
  | ShareEvent_ReadObserved : t_ReadObservation -> t_ShareEvent

/// Failure categories, preserving the handlers' historical statuses/messages.
type t_ShareFailure =
  | ShareFailure_Unauthenticated : t_ShareFailure
  | ShareFailure_CrossAccount : t_ShareFailure
  | ShareFailure_PolicyRejected : t_ShareFailure
  | ShareFailure_AccountMissing : t_ShareFailure
  | ShareFailure_Rekeyed : t_ShareFailure
  | ShareFailure_Conflict : t_ShareFailure
  | ShareFailure_ShareMissing : t_ShareFailure

/// Authority to stage one split at one epoch.
type t_ShareStagePermit = {
  f_epoch:i64;
  f_split:i64;
  f_binds_split_and_share:bool
}

/// Authority to promote exactly one staged split at one epoch.
type t_ShareFinalizePermit = {
  f_epoch:i64;
  f_split:i64;
  f_exact_pending_required:bool;
  f_empty_active_required:bool
}

/// Authority to clear both the active share and the staged split.
type t_ShareDeletePermit = {
  f_epoch:i64;
  f_clears_share_and_pending:bool
}

/// The effect the handler must perform next.
type t_ShareEffect =
  | ShareEffect_StageShare : t_ShareStagePermit -> t_ShareEffect
  | ShareEffect_StageQueryAccount : t_ShareEffect
  | ShareEffect_PromoteStagedSplit : t_ShareFinalizePermit -> t_ShareEffect
  | ShareEffect_FinalizeQueryAccount : t_ShareEffect
  | ShareEffect_DeleteShare : t_ShareDeletePermit -> t_ShareEffect
  | ShareEffect_ReadShare : t_ShareEffect
  | ShareEffect_Complete : t_ShareEffect
  | ShareEffect_Fail : t_ShareFailure -> t_ShareEffect
  | ShareEffect_Idle : t_ShareEffect

/// Per-request lifecycle state. Every field is a decision fact established by a
/// prior transition, never a claim about the database.
type t_ShareLifecycleDriver = {
  f_stage:t_ShareStage;
  f_operation:t_ShareOperation;
  f_actor_active:bool;
  f_same_account:bool;
  f_epoch:i64;
  f_split:i64;
  f_split_id_present:bool;
  f_update_attempted:bool;
  f_update_applied:bool;
  f_account_checked:bool;
  f_active_confirmed:bool;
  f_read_confirmed:bool;
  f_deletes_share:bool;
  f_deletes_pending:bool;
  f_responded:bool;
  f_failed:bool
}

type t_ShareTransition = {
  f_driver:t_ShareLifecycleDriver;
  f_effect:t_ShareEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let share_lifecycle_state_is_sound (d: t_ShareLifecycleDriver) : bool =
  let initial:bool =
    ~.d.f_update_attempted && ~.d.f_update_applied && ~.d.f_account_checked &&
    ~.d.f_active_confirmed &&
    ~.d.f_read_confirmed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let awaiting_account:bool =
    d.f_update_attempted && ~.d.f_update_applied && ~.d.f_account_checked && ~.d.f_active_confirmed &&
    ~.d.f_read_confirmed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done_ok:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Stage
      | ShareOperation_Finalize  -> d.f_update_applied || d.f_active_confirmed
      | ShareOperation_Delete  -> d.f_update_applied && d.f_deletes_share && d.f_deletes_pending
      | ShareOperation_Read  -> d.f_read_confirmed)) &&
    (~.d.f_failed || ~.d.f_update_applied && ~.d.f_read_confirmed)
  in
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Stage  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Stage  -> true
    | _ -> false) &&
  initial) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_StageAccount  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Stage  -> true
    | _ -> false) &&
  awaiting_account) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Finalize  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Finalize  -> true
    | _ -> false) &&
  initial) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_FinalizeAccount  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Finalize  -> true
    | _ -> false) &&
  awaiting_account) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Delete  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Delete  -> true
    | _ -> false) &&
  initial &&
  d.f_deletes_share &&
  d.f_deletes_pending) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Read  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Read  -> true
    | _ -> false) &&
  ~.d.f_update_attempted &&
  ~.d.f_update_applied &&
  ~.d.f_account_checked &&
  ~.d.f_active_confirmed &&
  ~.d.f_read_confirmed &&
  ~.d.f_responded &&
  ~.d.f_failed) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false) ||
  done_ok) &&
  (~.d.f_same_account || d.f_actor_active) &&
  ((match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false) ||
  d.f_actor_active && d.f_same_account) &&
  (~.d.f_update_attempted ||
  d.f_actor_active && d.f_same_account &&
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Stage  | ShareOperation_Finalize  | ShareOperation_Delete  -> true
    | _ -> false)) &&
  (~.d.f_update_applied || d.f_update_attempted && d.f_responded) &&
  (~.d.f_account_checked ||
  d.f_update_attempted &&
  ~.(match d.f_operation <: t_ShareOperation with
    | ShareOperation_Read  -> true
    | _ -> false)) &&
  (~.d.f_active_confirmed || d.f_account_checked && d.f_responded) &&
  (~.d.f_read_confirmed ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Read  -> true
    | _ -> false) &&
  d.f_responded) &&
  (~.d.f_deletes_share ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Delete  -> true
    | _ -> false)) &&
  (~.d.f_deletes_pending ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Delete  -> true
    | _ -> false)) &&
  (~.(d.f_deletes_share || d.f_deletes_pending) || d.f_deletes_share && d.f_deletes_pending) &&
  (~.d.f_responded ||
  (match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false)) &&
  (~.d.f_failed ||
  (match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false))

/// Every effect the driver emits agrees with the state it produces.
let share_lifecycle_effect_is_sound (d: t_ShareLifecycleDriver) (v_effect: t_ShareEffect) : bool =
  let active:bool = d.f_actor_active && d.f_same_account && ~.d.f_failed in
  match v_effect <: t_ShareEffect with
  | ShareEffect_StageShare permit ->
    active &&
    (match d.f_stage <: t_ShareStage with
      | ShareStage_Stage  -> true
      | _ -> false) &&
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Stage  -> true
      | _ -> false) &&
    ~.d.f_update_attempted &&
    d.f_split_id_present &&
    permit.f_epoch =. d.f_epoch &&
    permit.f_split =. d.f_split &&
    permit.f_binds_split_and_share
  | ShareEffect_StageQueryAccount  ->
    active &&
    (match d.f_stage <: t_ShareStage with
      | ShareStage_StageAccount  -> true
      | _ -> false) &&
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Stage  -> true
      | _ -> false) &&
    d.f_update_attempted &&
    ~.d.f_update_applied &&
    ~.d.f_account_checked
  | ShareEffect_PromoteStagedSplit permit ->
    active &&
    (match d.f_stage <: t_ShareStage with
      | ShareStage_Finalize  -> true
      | _ -> false) &&
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Finalize  -> true
      | _ -> false) &&
    ~.d.f_update_attempted &&
    d.f_split_id_present &&
    permit.f_epoch =. d.f_epoch &&
    permit.f_split =. d.f_split &&
    permit.f_exact_pending_required &&
    permit.f_empty_active_required
  | ShareEffect_FinalizeQueryAccount  ->
    active &&
    (match d.f_stage <: t_ShareStage with
      | ShareStage_FinalizeAccount  -> true
      | _ -> false) &&
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Finalize  -> true
      | _ -> false) &&
    d.f_update_attempted &&
    ~.d.f_update_applied &&
    ~.d.f_account_checked
  | ShareEffect_DeleteShare permit ->
    active &&
    (match d.f_stage <: t_ShareStage with
      | ShareStage_Delete  -> true
      | _ -> false) &&
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Delete  -> true
      | _ -> false) &&
    ~.d.f_update_attempted &&
    permit.f_epoch =. d.f_epoch &&
    permit.f_epoch >=. Vela_recovery_policy.v_INITIAL_EPOCH &&
    permit.f_clears_share_and_pending &&
    d.f_deletes_share &&
    d.f_deletes_pending
  | ShareEffect_ReadShare  ->
    active &&
    (match d.f_stage <: t_ShareStage with
      | ShareStage_Read  -> true
      | _ -> false) &&
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Read  -> true
      | _ -> false) &&
    ~.d.f_read_confirmed &&
    ~.d.f_responded
  | ShareEffect_Complete  ->
    (match d.f_stage <: t_ShareStage with
      | ShareStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed &&
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Stage
      | ShareOperation_Finalize  -> d.f_update_applied || d.f_active_confirmed
      | ShareOperation_Delete  -> d.f_update_applied && d.f_deletes_share && d.f_deletes_pending
      | ShareOperation_Read  -> d.f_read_confirmed)
  | ShareEffect_Fail _ ->
    (match d.f_stage <: t_ShareStage with
      | ShareStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded &&
    ~.d.f_update_applied &&
    ~.d.f_read_confirmed
  | ShareEffect_Idle  -> true

let transition (driver: t_ShareLifecycleDriver) (v_effect: t_ShareEffect) : t_ShareTransition =
  { f_driver = driver; f_effect = v_effect } <: t_ShareTransition

let idle (driver: t_ShareLifecycleDriver) : t_ShareTransition =
  transition driver (ShareEffect_Idle <: t_ShareEffect)

let terminal (driver: t_ShareLifecycleDriver) (failure: t_ShareFailure) : t_ShareTransition =
  transition ({ driver with f_stage = ShareStage_Done <: t_ShareStage; f_failed = true }
      <:
      t_ShareLifecycleDriver)
    (ShareEffect_Fail failure <: t_ShareEffect)

let base_driver (observation: t_ShareRequestObservation) (stage: t_ShareStage) (epoch: i64)
    : t_ShareLifecycleDriver =
  {
    f_stage = stage;
    f_operation = observation.f_operation;
    f_actor_active = true;
    f_same_account = true;
    f_epoch = epoch;
    f_split = observation.f_split;
    f_split_id_present = observation.f_split_id_present;
    f_update_attempted = false;
    f_update_applied = false;
    f_account_checked = false;
    f_active_confirmed = false;
    f_read_confirmed = false;
    f_deletes_share = false;
    f_deletes_pending = false;
    f_responded = false;
    f_failed = false
  }
  <:
  t_ShareLifecycleDriver

let begin_stage (observation: t_ShareRequestObservation)
    : Prims.Pure t_ShareTransition
      (requires
        (match observation.f_operation <: t_ShareOperation with
          | ShareOperation_Stage  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_state_is_sound result.f_driver &&
          share_lifecycle_effect_is_sound result.f_driver result.f_effect) =
  let request:Vela_recovery_policy.t_PublicationStageRequest =
    {
      Vela_recovery_policy.f_declared_epoch = observation.f_declared_epoch;
      Vela_recovery_policy.f_split_id_present = observation.f_split_id_present;
      Vela_recovery_policy.f_server_share_present = observation.f_share_present;
      Vela_recovery_policy.f_device_authority = observation.f_device_authority
    }
    <:
    Vela_recovery_policy.t_PublicationStageRequest
  in
  match
    Vela_recovery_policy.plan_publication_stage request
    <:
    Vela_recovery_policy.t_PublicationStageDecision
  with
  | Vela_recovery_policy.PublicationStageDecision_Stage permit ->
    let d:t_ShareLifecycleDriver =
      base_driver observation
        (ShareStage_Stage <: t_ShareStage)
        (Vela_recovery_policy.impl_PublicationStagePermit__epoch permit <: i64)
    in
    transition d
      (ShareEffect_StageShare
        ({
            f_epoch = Vela_recovery_policy.impl_PublicationStagePermit__epoch permit <: i64;
            f_split = observation.f_split;
            f_binds_split_and_share
            =
            Vela_recovery_policy.impl_PublicationStagePermit__binds_split_and_share permit <: bool
          }
          <:
          t_ShareStagePermit)
        <:
        t_ShareEffect)
  | Vela_recovery_policy.PublicationStageDecision_Reject  ->
    let d:t_ShareLifecycleDriver =
      base_driver observation (ShareStage_Done <: t_ShareStage) observation.f_declared_epoch
    in
    terminal d (ShareFailure_PolicyRejected <: t_ShareFailure)

let begin_finalize (observation: t_ShareRequestObservation)
    : Prims.Pure t_ShareTransition
      (requires
        (match observation.f_operation <: t_ShareOperation with
          | ShareOperation_Finalize  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_state_is_sound result.f_driver &&
          share_lifecycle_effect_is_sound result.f_driver result.f_effect) =
  let request:Vela_recovery_policy.t_PublicationFinalizeRequest =
    {
      Vela_recovery_policy.f_declared_epoch = observation.f_declared_epoch;
      Vela_recovery_policy.f_split_id_present = observation.f_split_id_present;
      Vela_recovery_policy.f_device_authority = observation.f_device_authority
    }
    <:
    Vela_recovery_policy.t_PublicationFinalizeRequest
  in
  match
    Vela_recovery_policy.plan_publication_finalize request
    <:
    Vela_recovery_policy.t_PublicationFinalizeDecision
  with
  | Vela_recovery_policy.PublicationFinalizeDecision_Finalize permit ->
    let d:t_ShareLifecycleDriver =
      base_driver observation
        (ShareStage_Finalize <: t_ShareStage)
        (Vela_recovery_policy.impl_PublicationFinalizePermit__epoch permit <: i64)
    in
    transition d
      (ShareEffect_PromoteStagedSplit
        ({
            f_epoch = Vela_recovery_policy.impl_PublicationFinalizePermit__epoch permit <: i64;
            f_split = observation.f_split;
            f_exact_pending_required
            =
            Vela_recovery_policy.impl_PublicationFinalizePermit__requires_exact_pending permit
            <:
            bool;
            f_empty_active_required
            =
            Vela_recovery_policy.impl_PublicationFinalizePermit__requires_empty_active permit
            <:
            bool
          }
          <:
          t_ShareFinalizePermit)
        <:
        t_ShareEffect)
  | Vela_recovery_policy.PublicationFinalizeDecision_Reject  ->
    let d:t_ShareLifecycleDriver =
      base_driver observation (ShareStage_Done <: t_ShareStage) observation.f_declared_epoch
    in
    terminal d (ShareFailure_PolicyRejected <: t_ShareFailure)

let begin_delete (observation: t_ShareRequestObservation)
    : Prims.Pure t_ShareTransition
      (requires
        (match observation.f_operation <: t_ShareOperation with
          | ShareOperation_Delete  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_state_is_sound result.f_driver &&
          share_lifecycle_effect_is_sound result.f_driver result.f_effect) =
  let request:Vela_recovery_policy.t_ShareDeletionRequest =
    {
      Vela_recovery_policy.f_declared_epoch = observation.f_declared_epoch;
      Vela_recovery_policy.f_device_authority = observation.f_device_authority
    }
    <:
    Vela_recovery_policy.t_ShareDeletionRequest
  in
  match
    Vela_recovery_policy.plan_share_deletion request <: Vela_recovery_policy.t_ShareDeletionDecision
  with
  | Vela_recovery_policy.ShareDeletionDecision_Delete permit ->
    let d:t_ShareLifecycleDriver =
      base_driver observation
        (ShareStage_Delete <: t_ShareStage)
        (Vela_recovery_policy.impl_ShareDeletionPermit__epoch permit <: i64)
    in
    let d:t_ShareLifecycleDriver = { d with f_deletes_share = true } <: t_ShareLifecycleDriver in
    let d:t_ShareLifecycleDriver = { d with f_deletes_pending = true } <: t_ShareLifecycleDriver in
    transition d
      (ShareEffect_DeleteShare
        ({
            f_epoch = Vela_recovery_policy.impl_ShareDeletionPermit__epoch permit <: i64;
            f_clears_share_and_pending
            =
            Vela_recovery_policy.impl_ShareDeletionPermit__clears_share_and_pending permit <: bool
          }
          <:
          t_ShareDeletePermit)
        <:
        t_ShareEffect)
  | Vela_recovery_policy.ShareDeletionDecision_Reject  ->
    let d:t_ShareLifecycleDriver =
      base_driver observation (ShareStage_Done <: t_ShareStage) observation.f_declared_epoch
    in
    terminal d (ShareFailure_PolicyRejected <: t_ShareFailure)

let begin_read (observation: t_ShareRequestObservation)
    : Prims.Pure t_ShareTransition
      (requires
        (match observation.f_operation <: t_ShareOperation with
          | ShareOperation_Read  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_state_is_sound result.f_driver &&
          share_lifecycle_effect_is_sound result.f_driver result.f_effect) =
  let d:t_ShareLifecycleDriver =
    base_driver observation (ShareStage_Read <: t_ShareStage) observation.f_declared_epoch
  in
  transition d (ShareEffect_ReadShare <: t_ShareEffect)

/// Start a per-request recovery-share lifecycle operation. An actor the
/// middleware did not verify as an authenticated, active device — or a request
/// whose effects are not scoped to the session\'s own account — produces a
/// terminal failure without any effect.
let begin_share_lifecycle (observation: t_ShareRequestObservation)
    : Prims.Pure t_ShareTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_state_is_sound result.f_driver &&
          share_lifecycle_effect_is_sound result.f_driver result.f_effect) =
  let actor_active:bool =
    observation.f_actor.f_authenticated && observation.f_actor.f_device_active
  in
  if ~.actor_active
  then
    let d:t_ShareLifecycleDriver =
      base_driver observation (ShareStage_Done <: t_ShareStage) observation.f_declared_epoch
    in
    let d:t_ShareLifecycleDriver = { d with f_actor_active = false } <: t_ShareLifecycleDriver in
    let d:t_ShareLifecycleDriver = { d with f_same_account = false } <: t_ShareLifecycleDriver in
    terminal d (ShareFailure_Unauthenticated <: t_ShareFailure)
  else
    if ~.observation.f_actor.f_scoped_to_session_account
    then
      let d:t_ShareLifecycleDriver =
        base_driver observation (ShareStage_Done <: t_ShareStage) observation.f_declared_epoch
      in
      let d:t_ShareLifecycleDriver = { d with f_same_account = false } <: t_ShareLifecycleDriver in
      terminal d (ShareFailure_CrossAccount <: t_ShareFailure)
    else
      match observation.f_operation <: t_ShareOperation with
      | ShareOperation_Stage  -> begin_stage observation
      | ShareOperation_Finalize  -> begin_finalize observation
      | ShareOperation_Delete  -> begin_delete observation
      | ShareOperation_Read  -> begin_read observation

let apply_on_stage_update (driver: t_ShareLifecycleDriver) (observation: t_StageUpdateObservation)
    : Prims.Pure t_ShareTransition
      (requires
        share_lifecycle_state_is_sound driver &&
        (match driver.f_stage <: t_ShareStage with
          | ShareStage_Stage  -> true
          | _ -> false) &&
        (match driver.f_operation <: t_ShareOperation with
          | ShareOperation_Stage  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_lifecycle_state_is_sound driver <: bool) ||
          share_lifecycle_state_is_sound result.f_driver)) =
  match observation <: t_StageUpdateObservation with
  | StageUpdateObservation_Staged  ->
    transition ({
          driver with
          f_stage = ShareStage_Done <: t_ShareStage;
          f_update_attempted = true;
          f_update_applied = true;
          f_responded = true
        }
        <:
        t_ShareLifecycleDriver)
      (ShareEffect_Complete <: t_ShareEffect)
  | StageUpdateObservation_NotStaged  ->
    transition ({
          driver with
          f_stage = ShareStage_StageAccount <: t_ShareStage;
          f_update_attempted = true
        }
        <:
        t_ShareLifecycleDriver)
      (ShareEffect_StageQueryAccount <: t_ShareEffect)

let apply_on_stage_account (driver: t_ShareLifecycleDriver) (observation: t_StageAccountObservation)
    : Prims.Pure t_ShareTransition
      (requires
        share_lifecycle_state_is_sound driver &&
        (match driver.f_stage <: t_ShareStage with
          | ShareStage_StageAccount  -> true
          | _ -> false) &&
        (match driver.f_operation <: t_ShareOperation with
          | ShareOperation_Stage  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_lifecycle_state_is_sound driver <: bool) ||
          share_lifecycle_state_is_sound result.f_driver)) =
  if ~.observation.f_account_present
  then
    terminal ({ driver with f_account_checked = true } <: t_ShareLifecycleDriver)
      (ShareFailure_AccountMissing <: t_ShareFailure)
  else
    if
      observation.f_stored_epoch <>.
      (Core_models.Option.Option_Some driver.f_epoch <: Core_models.Option.t_Option i64) ||
      observation.f_rotation_active
    then
      terminal ({ driver with f_account_checked = true } <: t_ShareLifecycleDriver)
        (ShareFailure_Rekeyed <: t_ShareFailure)
    else
      if observation.f_active_share_matches && observation.f_active_split_matches
      then
        transition ({
              driver with
              f_stage = ShareStage_Done <: t_ShareStage;
              f_account_checked = true;
              f_active_confirmed = true;
              f_responded = true
            }
            <:
            t_ShareLifecycleDriver)
          (ShareEffect_Complete <: t_ShareEffect)
      else
        terminal ({ driver with f_account_checked = true } <: t_ShareLifecycleDriver)
          (ShareFailure_Conflict <: t_ShareFailure)

let apply_on_finalize_update
      (driver: t_ShareLifecycleDriver)
      (observation: t_FinalizeUpdateObservation)
    : Prims.Pure t_ShareTransition
      (requires
        share_lifecycle_state_is_sound driver &&
        (match driver.f_stage <: t_ShareStage with
          | ShareStage_Finalize  -> true
          | _ -> false) &&
        (match driver.f_operation <: t_ShareOperation with
          | ShareOperation_Finalize  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_lifecycle_state_is_sound driver <: bool) ||
          share_lifecycle_state_is_sound result.f_driver)) =
  match observation <: t_FinalizeUpdateObservation with
  | FinalizeUpdateObservation_Promoted  ->
    transition ({
          driver with
          f_stage = ShareStage_Done <: t_ShareStage;
          f_update_attempted = true;
          f_update_applied = true;
          f_responded = true
        }
        <:
        t_ShareLifecycleDriver)
      (ShareEffect_Complete <: t_ShareEffect)
  | FinalizeUpdateObservation_NotPromoted  ->
    transition ({
          driver with
          f_stage = ShareStage_FinalizeAccount <: t_ShareStage;
          f_update_attempted = true
        }
        <:
        t_ShareLifecycleDriver)
      (ShareEffect_FinalizeQueryAccount <: t_ShareEffect)

let apply_on_finalize_account
      (driver: t_ShareLifecycleDriver)
      (observation: t_FinalizeAccountObservation)
    : Prims.Pure t_ShareTransition
      (requires
        share_lifecycle_state_is_sound driver &&
        (match driver.f_stage <: t_ShareStage with
          | ShareStage_FinalizeAccount  -> true
          | _ -> false) &&
        (match driver.f_operation <: t_ShareOperation with
          | ShareOperation_Finalize  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_lifecycle_state_is_sound driver <: bool) ||
          share_lifecycle_state_is_sound result.f_driver)) =
  if ~.observation.f_account_present
  then
    terminal ({ driver with f_account_checked = true } <: t_ShareLifecycleDriver)
      (ShareFailure_AccountMissing <: t_ShareFailure)
  else
    if
      observation.f_stored_epoch <>.
      (Core_models.Option.Option_Some driver.f_epoch <: Core_models.Option.t_Option i64) ||
      observation.f_rotation_active
    then
      terminal ({ driver with f_account_checked = true } <: t_ShareLifecycleDriver)
        (ShareFailure_Rekeyed <: t_ShareFailure)
    else
      if observation.f_active_split_matches
      then
        transition ({
              driver with
              f_stage = ShareStage_Done <: t_ShareStage;
              f_account_checked = true;
              f_active_confirmed = true;
              f_responded = true
            }
            <:
            t_ShareLifecycleDriver)
          (ShareEffect_Complete <: t_ShareEffect)
      else
        terminal ({ driver with f_account_checked = true } <: t_ShareLifecycleDriver)
          (ShareFailure_Conflict <: t_ShareFailure)

let apply_on_delete_update (driver: t_ShareLifecycleDriver) (observation: t_DeleteUpdateObservation)
    : Prims.Pure t_ShareTransition
      (requires
        share_lifecycle_state_is_sound driver &&
        (match driver.f_stage <: t_ShareStage with
          | ShareStage_Delete  -> true
          | _ -> false) &&
        (match driver.f_operation <: t_ShareOperation with
          | ShareOperation_Delete  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_lifecycle_state_is_sound driver <: bool) ||
          share_lifecycle_state_is_sound result.f_driver)) =
  match observation <: t_DeleteUpdateObservation with
  | DeleteUpdateObservation_Deleted  ->
    transition ({
          driver with
          f_stage = ShareStage_Done <: t_ShareStage;
          f_update_attempted = true;
          f_update_applied = true;
          f_responded = true
        }
        <:
        t_ShareLifecycleDriver)
      (ShareEffect_Complete <: t_ShareEffect)
  | DeleteUpdateObservation_NotDeleted  ->
    terminal ({ driver with f_update_attempted = true } <: t_ShareLifecycleDriver)
      (ShareFailure_Rekeyed <: t_ShareFailure)

let apply_on_read (driver: t_ShareLifecycleDriver) (observation: t_ReadObservation)
    : Prims.Pure t_ShareTransition
      (requires
        share_lifecycle_state_is_sound driver &&
        (match driver.f_stage <: t_ShareStage with
          | ShareStage_Read  -> true
          | _ -> false) &&
        (match driver.f_operation <: t_ShareOperation with
          | ShareOperation_Read  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_lifecycle_state_is_sound driver <: bool) ||
          share_lifecycle_state_is_sound result.f_driver)) =
  if ~.observation.f_account_present || ~.observation.f_share_present
  then terminal driver (ShareFailure_ShareMissing <: t_ShareFailure)
  else
    transition ({
          driver with
          f_stage = ShareStage_Done <: t_ShareStage;
          f_read_confirmed = true;
          f_responded = true
        }
        <:
        t_ShareLifecycleDriver)
      (ShareEffect_Complete <: t_ShareEffect)

/// The complete, total transition relation. Events that do not answer the
/// current stage (and every event after `Done`) are ignored.
let step_share_lifecycle (driver: t_ShareLifecycleDriver) (event: t_ShareEvent)
    : Prims.Pure t_ShareTransition
      (requires share_lifecycle_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_lifecycle_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_lifecycle_state_is_sound driver <: bool) ||
          share_lifecycle_state_is_sound result.f_driver)) =
  match event <: t_ShareEvent with
  | ShareEvent_StageUpdate observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_Stage  -> true
      | _ -> false
    then apply_on_stage_update driver observation
    else idle driver
  | ShareEvent_StageAccount observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_StageAccount  -> true
      | _ -> false
    then apply_on_stage_account driver observation
    else idle driver
  | ShareEvent_FinalizeUpdate observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_Finalize  -> true
      | _ -> false
    then apply_on_finalize_update driver observation
    else idle driver
  | ShareEvent_FinalizeAccount observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_FinalizeAccount  -> true
      | _ -> false
    then apply_on_finalize_account driver observation
    else idle driver
  | ShareEvent_DeleteUpdate observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_Delete  -> true
      | _ -> false
    then apply_on_delete_update driver observation
    else idle driver
  | ShareEvent_ReadObserved observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_Read  -> true
      | _ -> false
    then apply_on_read driver observation
    else idle driver
