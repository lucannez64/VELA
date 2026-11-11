module Vela_rekey_policy.Rekey_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Which rotation entry point this request is.
type t_RekeyOp =
  | RekeyOp_Start : t_RekeyOp
  | RekeyOp_Capsules : t_RekeyOp
  | RekeyOp_Commit : t_RekeyOp
  | RekeyOp_Abort : t_RekeyOp

/// Authenticated facts captured by the `DeviceSession` extractor before the
/// first effect.
type t_RekeyRequest = {
  f_authenticated:bool;
  f_device_scope:bool;
  f_capsule_count:i64
}

/// Outcome of the per-account rotation pacing check.
type t_RateLimitObservation =
  | RateLimitObservation_Allowed : t_RateLimitObservation
  | RateLimitObservation_Limited : t_RateLimitObservation

/// The post-load key state plus the authenticated request facts the driver
/// compares against it. The handler derives these booleans by comparing the
/// loaded row with the request; the driver never sees identity strings.
type t_KeyStateObs = {
  f_epoch:i64;
  f_freezing:bool;
  f_starter_matches:bool;
  f_rotation_id_present:bool;
  f_header_present:bool;
  f_header_matches:bool;
  f_replay_target:Core_models.Option.t_Option i64;
  f_replay_recorded:Core_models.Option.t_Option i64;
  f_replay_id_matches:bool;
  f_expired:bool
}

type t_StateObservation =
  | StateObservation_Loaded : t_KeyStateObs -> t_StateObservation
  | StateObservation_Storage : t_StateObservation
  | StateObservation_NotFound : t_StateObservation

/// Outcome of the lazy timeout rollback. `Raced` carries the state the
/// winning transition left behind, which the handler reloads and continues
/// with.
type t_TimeoutObservation =
  | TimeoutObservation_RolledBack : t_TimeoutObservation
  | TimeoutObservation_Raced : t_KeyStateObs -> t_TimeoutObservation
  | TimeoutObservation_Storage : t_TimeoutObservation

/// Outcome of one readiness/completeness `SELECT 1 ... LIMIT 1` probe.
type t_ProbeObservation =
  | ProbeObservation_Empty : t_ProbeObservation
  | ProbeObservation_Found : t_ProbeObservation
  | ProbeObservation_Storage : t_ProbeObservation

/// Outcome of opening or committing the freeze transaction.
type t_TransactionObservation =
  | TransactionObservation_Committed : t_TransactionObservation
  | TransactionObservation_Failed : t_TransactionObservation

/// Outcome of the inventory read inside the freeze transaction.
type t_InventoryObservation =
  | InventoryObservation_Read : t_InventoryObservation
  | InventoryObservation_Failed : t_InventoryObservation

/// Outcome of a compare-and-swap `UPDATE`.
type t_CasObservation =
  | CasObservation_Updated : t_CasObservation
  | CasObservation_Skipped : t_CasObservation
  | CasObservation_Storage : t_CasObservation

/// Outcome of the post-freeze cleanup delete.
type t_CleanupObservation =
  | CleanupObservation_Done : t_CleanupObservation
  | CleanupObservation_Storage : t_CleanupObservation

/// Outcome of one capsule target update.
type t_CapsuleObservation =
  | CapsuleObservation_Stored : t_CapsuleObservation
  | CapsuleObservation_Invalid : t_CapsuleObservation
  | CapsuleObservation_NotTarget : t_CapsuleObservation
  | CapsuleObservation_Storage : t_CapsuleObservation

/// Outcome of the abort / timeout rollback CAS and its cleanup.
type t_RollbackObservation =
  | RollbackObservation_RolledBack : t_RollbackObservation
  | RollbackObservation_Raced : t_RollbackObservation
  | RollbackObservation_Storage : t_RollbackObservation

/// The superseded-row sweep is best effort: the handler only logs a failure.
type t_SweepObservation =
  | SweepObservation_Done : t_SweepObservation
  | SweepObservation_Failed : t_SweepObservation

/// One driver event.
type t_RekeyEvent =
  | RekeyEvent_RateLimit : t_RateLimitObservation -> t_RekeyEvent
  | RekeyEvent_State : t_StateObservation -> t_RekeyEvent
  | RekeyEvent_Timeout : t_TimeoutObservation -> t_RekeyEvent
  | RekeyEvent_Oram : t_ProbeObservation -> t_RekeyEvent
  | RekeyEvent_Capable : t_ProbeObservation -> t_RekeyEvent
  | RekeyEvent_Acknowledged : t_ProbeObservation -> t_RekeyEvent
  | RekeyEvent_Transaction : t_TransactionObservation -> t_RekeyEvent
  | RekeyEvent_Inventory : t_InventoryObservation -> t_RekeyEvent
  | RekeyEvent_FreezeCas : t_CasObservation -> t_RekeyEvent
  | RekeyEvent_Cleanup : t_CleanupObservation -> t_RekeyEvent
  | RekeyEvent_TxCommit : t_TransactionObservation -> t_RekeyEvent
  | RekeyEvent_Capsule : t_CapsuleObservation -> t_RekeyEvent
  | RekeyEvent_Chunks : t_ProbeObservation -> t_RekeyEvent
  | RekeyEvent_Devices : t_ProbeObservation -> t_RekeyEvent
  | RekeyEvent_CommitCas : t_CasObservation -> t_RekeyEvent
  | RekeyEvent_Sweep : t_SweepObservation -> t_RekeyEvent
  | RekeyEvent_Published : t_RekeyEvent
  | RekeyEvent_Rollback : t_RollbackObservation -> t_RekeyEvent

/// Failure categories preserving every handler's status/message precedence.
type t_RekeyFailure =
  | RekeyFailure_Unauthenticated : t_RekeyFailure
  | RekeyFailure_WebSessionForbidden : t_RekeyFailure
  | RekeyFailure_RateLimited : t_RekeyFailure
  | RekeyFailure_StateStorage : t_RekeyFailure
  | RekeyFailure_AccountNotFound : t_RekeyFailure
  | RekeyFailure_InvalidEpoch : t_RekeyFailure
  | RekeyFailure_AlreadyInProgress : t_RekeyFailure
  | RekeyFailure_NoRekeyInProgress : t_RekeyFailure
  | RekeyFailure_OramPresent : t_RekeyFailure
  | RekeyFailure_CapabilityRequired : t_RekeyFailure
  | RekeyFailure_AdoptionRequired : t_RekeyFailure
  | RekeyFailure_TransactionStorage : t_RekeyFailure
  | RekeyFailure_InventoryStorage : t_RekeyFailure
  | RekeyFailure_ConcurrentStart : t_RekeyFailure
  | RekeyFailure_CleanupStorage : t_RekeyFailure
  | RekeyFailure_TxCommitStorage : t_RekeyFailure
  | RekeyFailure_StarterRequired : t_RekeyFailure
  | RekeyFailure_RotationIdRequired : t_RekeyFailure
  | RekeyFailure_RotationIdMismatch : t_RekeyFailure
  | RekeyFailure_NotAuthorized : t_RekeyFailure
  | RekeyFailure_NoSuccessor : t_RekeyFailure
  | RekeyFailure_TooManyCapsules : t_RekeyFailure
  | RekeyFailure_CapsuleTargetInvalid : t_RekeyFailure
  | RekeyFailure_ChunkShadowsIncomplete : t_RekeyFailure
  | RekeyFailure_DeviceCapsulesIncomplete : t_RekeyFailure
  | RekeyFailure_CommitNotAuthorized : t_RekeyFailure
  | RekeyFailure_ConcurrentCommit : t_RekeyFailure
  | RekeyFailure_ConcurrentRollback : t_RekeyFailure
  | RekeyFailure_ChunkProbeStorage : t_RekeyFailure
  | RekeyFailure_CapsuleProbeStorage : t_RekeyFailure
  | RekeyFailure_RollbackStorage : t_RekeyFailure

/// The effect the handler must perform next.
type t_RekeyEffect =
  | RekeyEffect_RateLimit : t_RekeyEffect
  | RekeyEffect_LoadState : t_RekeyEffect
  | RekeyEffect_TimeoutRollback : t_RekeyEffect
  | RekeyEffect_CheckOram : t_RekeyEffect
  | RekeyEffect_CheckCapable : t_RekeyEffect
  | RekeyEffect_CheckAcknowledged : t_RekeyEffect
  | RekeyEffect_BeginFreezeTransaction : t_RekeyEffect
  | RekeyEffect_ReadInventory : t_RekeyEffect
  | RekeyEffect_FreezeCas : t_RekeyEffect
  | RekeyEffect_CleanupChunks : t_RekeyEffect
  | RekeyEffect_CommitFreezeTransaction : t_RekeyEffect
  | RekeyEffect_WriteCapsule { f_index:i64 }: t_RekeyEffect
  | RekeyEffect_CheckChunkShadows : t_RekeyEffect
  | RekeyEffect_CheckDeviceCapsules : t_RekeyEffect
  | RekeyEffect_CommitCas : t_RekeyEffect
  | RekeyEffect_SweepOldChunks : t_RekeyEffect
  | RekeyEffect_PublishEpoch : t_RekeyEffect
  | RekeyEffect_RollbackAttempt : t_RekeyEffect
  | RekeyEffect_Complete : t_RekeyEffect
  | RekeyEffect_CompleteReplay : t_RekeyEffect
  | RekeyEffect_Fail : t_RekeyFailure -> t_RekeyEffect
  | RekeyEffect_Idle : t_RekeyEffect

type t_RekeyStage =
  | RekeyStage_RateLimit : t_RekeyStage
  | RekeyStage_Load : t_RekeyStage
  | RekeyStage_Timeout : t_RekeyStage
  | RekeyStage_Oram : t_RekeyStage
  | RekeyStage_Capable : t_RekeyStage
  | RekeyStage_Acknowledged : t_RekeyStage
  | RekeyStage_BeginTx : t_RekeyStage
  | RekeyStage_Inventory : t_RekeyStage
  | RekeyStage_FreezeCas : t_RekeyStage
  | RekeyStage_Cleanup : t_RekeyStage
  | RekeyStage_TxCommit : t_RekeyStage
  | RekeyStage_Capsule : t_RekeyStage
  | RekeyStage_Chunks : t_RekeyStage
  | RekeyStage_Devices : t_RekeyStage
  | RekeyStage_CommitCas : t_RekeyStage
  | RekeyStage_Sweep : t_RekeyStage
  | RekeyStage_Publish : t_RekeyStage
  | RekeyStage_Rollback : t_RekeyStage
  | RekeyStage_Done : t_RekeyStage

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the SQL database.
type t_RekeyDriver = {
  f_op:t_RekeyOp;
  f_stage:t_RekeyStage;
  f_authenticated:bool;
  f_device_scope:bool;
  f_epoch:i64;
  f_active:bool;
  f_timeout_done:bool;
  f_starter_matches:bool;
  f_rotation_present:bool;
  f_header_present:bool;
  f_rotation_matches:bool;
  f_replay_target:Core_models.Option.t_Option i64;
  f_replay_recorded:Core_models.Option.t_Option i64;
  f_replay_id_matches:bool;
  f_capsule_count:i64;
  f_capsules_written:i64;
  f_no_oram:bool;
  f_capable:bool;
  f_acknowledged:bool;
  f_from_epoch:i64;
  f_to_epoch:i64;
  f_chunks_complete:bool;
  f_capsules_complete:bool;
  f_committed:bool;
  f_rolled_back:bool;
  f_timeout_rollback:bool;
  f_published:bool;
  f_responded:bool;
  f_failed:bool
}

type t_RekeyTransition = {
  f_driver:t_RekeyDriver;
  f_effect:t_RekeyEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let rekey_state_is_sound (d: t_RekeyDriver) : bool =
  let commit_authority:bool =
    d.f_device_scope && d.f_starter_matches && d.f_rotation_present && d.f_rotation_matches
  in
  let commit_stage:bool =
    match d.f_stage <: t_RekeyStage with
    | RekeyStage_Sweep  | RekeyStage_Publish  -> true
    | _ -> false
  in
  let commit_cas_stage:bool =
    match d.f_stage <: t_RekeyStage with
    | RekeyStage_CommitCas  -> true
    | _ -> false
  in
  let committed_stage:bool =
    match d.f_stage <: t_RekeyStage with
    | RekeyStage_Sweep  | RekeyStage_Publish  | RekeyStage_Done  -> true
    | _ -> false
  in
  (~.d.f_failed || ~.d.f_committed) && (~.d.f_committed || committed_stage) &&
  (~.d.f_responded || ~.d.f_failed) &&
  (~.d.f_responded ||
  (match d.f_stage <: t_RekeyStage with
    | RekeyStage_Done  -> true
    | _ -> false)) &&
  (~.d.f_responded ||
  ~.(match d.f_op <: t_RekeyOp with
    | RekeyOp_Capsules  -> true
    | _ -> false) ||
  d.f_capsules_complete) &&
  (~.d.f_failed ||
  (match d.f_stage <: t_RekeyStage with
    | RekeyStage_Done  -> true
    | _ -> false)) &&
  (~.d.f_committed ||
  (match d.f_op <: t_RekeyOp with
    | RekeyOp_Commit  -> true
    | _ -> false) &&
  d.f_active &&
  commit_authority &&
  d.f_chunks_complete &&
  d.f_capsules_complete &&
  d.f_epoch =. d.f_to_epoch &&
  (Vela_rekey_policy.next_epoch d.f_from_epoch <: Core_models.Option.t_Option i64) =.
  (Core_models.Option.Option_Some d.f_to_epoch <: Core_models.Option.t_Option i64) &&
  d.f_to_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH) &&
  (~.commit_cas_stage ||
  d.f_from_epoch =. d.f_epoch &&
  (Vela_rekey_policy.next_epoch d.f_from_epoch <: Core_models.Option.t_Option i64) =.
  (Core_models.Option.Option_Some d.f_to_epoch <: Core_models.Option.t_Option i64) &&
  commit_authority &&
  d.f_chunks_complete &&
  d.f_capsules_complete &&
  d.f_to_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH &&
  ~.d.f_committed) &&
  (~.commit_stage || d.f_committed) &&
  (~.d.f_rolled_back ||
  d.f_active && d.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH && ~.d.f_committed) &&
  (~.d.f_rolled_back ||
  ~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Chunks
    | RekeyStage_Devices
    | RekeyStage_CommitCas
    | RekeyStage_Sweep
    | RekeyStage_Publish  -> true
    | _ -> false)) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Rollback  -> true
    | _ -> false) ||
  d.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH) &&
  (~.d.f_timeout_rollback || d.f_rolled_back) &&
  (~.d.f_rolled_back ||
  (match d.f_op <: t_RekeyOp with
    | RekeyOp_Abort  -> true
    | _ -> false) ||
  d.f_timeout_rollback) &&
  d.f_capsules_written <=. d.f_capsule_count &&
  d.f_capsules_written <=. mk_i64 64 &&
  (~.(match d.f_op <: t_RekeyOp with
    | RekeyOp_Start  | RekeyOp_Commit  | RekeyOp_Abort  -> true
    | _ -> false) ||
  d.f_capsule_count =. mk_i64 0) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Chunks
    | RekeyStage_Devices
    | RekeyStage_CommitCas
    | RekeyStage_Sweep
    | RekeyStage_Publish  -> true
    | _ -> false) ||
  d.f_capsules_written =. d.f_capsule_count) &&
  (~.d.f_capsules_complete || d.f_capsules_written =. d.f_capsule_count) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_RateLimit  | RekeyStage_Load  | RekeyStage_Timeout  -> true
    | _ -> false) ||
  d.f_capsules_written =. mk_i64 0) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Capsule  -> true
    | _ -> false) ||
  (match d.f_op <: t_RekeyOp with
    | RekeyOp_Capsules  -> true
    | _ -> false) &&
  d.f_capsules_written <. d.f_capsule_count) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Oram
    | RekeyStage_Capable
    | RekeyStage_Acknowledged
    | RekeyStage_BeginTx
    | RekeyStage_Inventory
    | RekeyStage_FreezeCas
    | RekeyStage_Cleanup
    | RekeyStage_TxCommit  -> true
    | _ -> false) ||
  (match d.f_op <: t_RekeyOp with
    | RekeyOp_Start  -> true
    | _ -> false)) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Chunks
    | RekeyStage_Devices
    | RekeyStage_CommitCas
    | RekeyStage_Sweep
    | RekeyStage_Publish  -> true
    | _ -> false) ||
  (match d.f_op <: t_RekeyOp with
    | RekeyOp_Commit  -> true
    | _ -> false)) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Rollback  -> true
    | _ -> false) ||
  (match d.f_op <: t_RekeyOp with
    | RekeyOp_Abort  -> true
    | _ -> false)) &&
  (~.(match d.f_stage <: t_RekeyStage with
    | RekeyStage_Timeout  -> true
    | _ -> false) ||
  d.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH) &&
  (~.d.f_published || d.f_committed)

/// Every effect the driver emits agrees with the state it produces.
let rekey_effect_is_sound (d: t_RekeyDriver) (v_effect: t_RekeyEffect) : bool =
  match v_effect <: t_RekeyEffect with
  | RekeyEffect_RateLimit  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_RateLimit  -> true
      | _ -> false) &&
    d.f_authenticated &&
    d.f_device_scope
  | RekeyEffect_LoadState  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Load  -> true
      | _ -> false)
  | RekeyEffect_TimeoutRollback  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Timeout  -> true
      | _ -> false)
  | RekeyEffect_CheckOram  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Oram  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_CheckCapable  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Capable  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_CheckAcknowledged  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Acknowledged  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_BeginFreezeTransaction  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_BeginTx  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_ReadInventory  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Inventory  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_FreezeCas  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_FreezeCas  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_CleanupChunks  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Cleanup  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_CommitFreezeTransaction  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_TxCommit  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Start  -> true
      | _ -> false)
  | RekeyEffect_WriteCapsule { f_index = index } ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Capsule  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Capsules  -> true
      | _ -> false) &&
    index =. d.f_capsules_written &&
    index <. d.f_capsule_count
  | RekeyEffect_CheckChunkShadows  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Chunks  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Commit  -> true
      | _ -> false)
  | RekeyEffect_CheckDeviceCapsules  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Devices  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Commit  -> true
      | _ -> false)
  | RekeyEffect_CommitCas  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_CommitCas  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Commit  -> true
      | _ -> false) &&
    d.f_chunks_complete &&
    d.f_capsules_complete &&
    d.f_device_scope &&
    d.f_starter_matches &&
    d.f_rotation_present &&
    d.f_rotation_matches &&
    ~.d.f_committed
  | RekeyEffect_SweepOldChunks  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Sweep  -> true
      | _ -> false) &&
    d.f_committed
  | RekeyEffect_PublishEpoch  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Publish  -> true
      | _ -> false) &&
    d.f_committed
  | RekeyEffect_RollbackAttempt  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Rollback  -> true
      | _ -> false) &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Abort  -> true
      | _ -> false)
  | RekeyEffect_Complete  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed &&
    (~.(match d.f_op <: t_RekeyOp with
      | RekeyOp_Commit  -> true
      | _ -> false) ||
    d.f_committed) &&
    (~.(match d.f_op <: t_RekeyOp with
      | RekeyOp_Abort  -> true
      | _ -> false) ||
    d.f_rolled_back) &&
    (~.(match d.f_op <: t_RekeyOp with
      | RekeyOp_Capsules  -> true
      | _ -> false) ||
    d.f_capsules_complete)
  | RekeyEffect_CompleteReplay  ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    ~.d.f_failed &&
    (match d.f_op <: t_RekeyOp with
      | RekeyOp_Commit  -> true
      | _ -> false) &&
    d.f_replay_target =.
    (Core_models.Option.Option_Some d.f_epoch <: Core_models.Option.t_Option i64) &&
    d.f_replay_recorded =.
    (Core_models.Option.Option_Some d.f_epoch <: Core_models.Option.t_Option i64) &&
    d.f_header_present &&
    d.f_replay_id_matches
  | RekeyEffect_Fail _ ->
    (match d.f_stage <: t_RekeyStage with
      | RekeyStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | RekeyEffect_Idle  -> true

let transition (driver: t_RekeyDriver) (v_effect: t_RekeyEffect) : t_RekeyTransition =
  { f_driver = driver; f_effect = v_effect } <: t_RekeyTransition

let idle (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  transition driver (RekeyEffect_Idle <: t_RekeyEffect)

let terminal (driver: t_RekeyDriver) (failure: t_RekeyFailure)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver && ~.driver.f_committed && ~.driver.f_responded)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  transition ({ driver with f_stage = RekeyStage_Done <: t_RekeyStage; f_failed = true }
      <:
      t_RekeyDriver)
    (RekeyEffect_Fail failure <: t_RekeyEffect)

let complete (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver && ~.driver.f_failed && ~.driver.f_responded &&
        (~.(match driver.f_op <: t_RekeyOp with
          | RekeyOp_Capsules  -> true
          | _ -> false) ||
        driver.f_capsules_complete) &&
        (~.(match driver.f_op <: t_RekeyOp with
          | RekeyOp_Commit  -> true
          | _ -> false) ||
        driver.f_committed) &&
        (~.(match driver.f_op <: t_RekeyOp with
          | RekeyOp_Abort  -> true
          | _ -> false) ||
        driver.f_rolled_back))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  transition ({ driver with f_stage = RekeyStage_Done <: t_RekeyStage; f_responded = true }
      <:
      t_RekeyDriver)
    (RekeyEffect_Complete <: t_RekeyEffect)

let complete_replay (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_op <: t_RekeyOp with
          | RekeyOp_Commit  -> true
          | _ -> false) &&
        ~.driver.f_failed &&
        driver.f_replay_target =.
        (Core_models.Option.Option_Some driver.f_epoch <: Core_models.Option.t_Option i64) &&
        driver.f_replay_recorded =.
        (Core_models.Option.Option_Some driver.f_epoch <: Core_models.Option.t_Option i64) &&
        driver.f_header_present &&
        driver.f_replay_id_matches)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  transition ({ driver with f_stage = RekeyStage_Done <: t_RekeyStage; f_responded = true }
      <:
      t_RekeyDriver)
    (RekeyEffect_CompleteReplay <: t_RekeyEffect)

let fresh (op: t_RekeyOp) (request: t_RekeyRequest) : t_RekeyDriver =
  {
    f_op = op;
    f_stage = RekeyStage_RateLimit <: t_RekeyStage;
    f_authenticated = request.f_authenticated;
    f_device_scope = request.f_device_scope;
    f_epoch = mk_i64 0;
    f_active = false;
    f_timeout_done = false;
    f_starter_matches = false;
    f_rotation_present = false;
    f_header_present = false;
    f_rotation_matches = false;
    f_replay_target = Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
    f_replay_recorded = Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
    f_replay_id_matches = false;
    f_capsule_count
    =
    (match op <: t_RekeyOp with
      | RekeyOp_Capsules  ->
        if request.f_capsule_count <. mk_i64 0 then mk_i64 0 else request.f_capsule_count
      | _ -> mk_i64 0);
    f_capsules_written = mk_i64 0;
    f_no_oram = false;
    f_capable = false;
    f_acknowledged = false;
    f_from_epoch = mk_i64 0;
    f_to_epoch = mk_i64 0;
    f_chunks_complete = false;
    f_capsules_complete = false;
    f_committed = false;
    f_rolled_back = false;
    f_timeout_rollback = false;
    f_published = false;
    f_responded = false;
    f_failed = false
  }
  <:
  t_RekeyDriver

let v_begin (op: t_RekeyOp) (request: t_RekeyRequest)
    : Prims.Pure t_RekeyTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect) =
  let driver:t_RekeyDriver = fresh op request in
  if ~.request.f_authenticated
  then terminal driver (RekeyFailure_Unauthenticated <: t_RekeyFailure)
  else
    if ~.request.f_device_scope
    then terminal driver (RekeyFailure_WebSessionForbidden <: t_RekeyFailure)
    else transition driver (RekeyEffect_RateLimit <: t_RekeyEffect)

let begin_start (request: t_RekeyRequest)
    : Prims.Pure t_RekeyTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect) =
  v_begin (RekeyOp_Start <: t_RekeyOp) request

let begin_capsules (request: t_RekeyRequest)
    : Prims.Pure t_RekeyTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect) =
  v_begin (RekeyOp_Capsules <: t_RekeyOp) request

let begin_commit (request: t_RekeyRequest)
    : Prims.Pure t_RekeyTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect) =
  v_begin (RekeyOp_Commit <: t_RekeyOp) request

let begin_abort (request: t_RekeyRequest)
    : Prims.Pure t_RekeyTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect) =
  v_begin (RekeyOp_Abort <: t_RekeyOp) request

let on_rate_limit (driver: t_RekeyDriver) (observation: t_RateLimitObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_RateLimit  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect) =
  match observation <: t_RateLimitObservation with
  | RateLimitObservation_Allowed  ->
    transition ({ driver with f_stage = RekeyStage_Load <: t_RekeyStage } <: t_RekeyDriver)
      (RekeyEffect_LoadState <: t_RekeyEffect)
  | RateLimitObservation_Limited  -> terminal driver (RekeyFailure_RateLimited <: t_RekeyFailure)

let finish_capsules (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false) &&
        (match driver.f_op <: t_RekeyOp with
          | RekeyOp_Capsules  -> true
          | _ -> false) &&
        ~.driver.f_active &&
        driver.f_starter_matches &&
        driver.f_header_present &&
        driver.f_rotation_matches &&
        driver.f_device_scope &&
        driver.f_capsules_written =. mk_i64 0 &&
        driver.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    Core_models.Option.impl__is_none #i64
      (Vela_rekey_policy.next_epoch driver.f_epoch <: Core_models.Option.t_Option i64)
  then terminal driver (RekeyFailure_NoSuccessor <: t_RekeyFailure)
  else
    if driver.f_capsule_count >. mk_i64 64
    then terminal driver (RekeyFailure_TooManyCapsules <: t_RekeyFailure)
    else
      if driver.f_capsule_count =. mk_i64 0
      then complete ({ driver with f_capsules_complete = true } <: t_RekeyDriver)
      else
        transition ({ driver with f_stage = RekeyStage_Capsule <: t_RekeyStage } <: t_RekeyDriver)
          (RekeyEffect_WriteCapsule ({ f_index = mk_i64 0 }) <: t_RekeyEffect)

let finish_commit (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false) &&
        (match driver.f_op <: t_RekeyOp with
          | RekeyOp_Commit  -> true
          | _ -> false) &&
        ~.driver.f_active &&
        driver.f_starter_matches &&
        driver.f_header_present &&
        driver.f_rotation_matches &&
        driver.f_device_scope &&
        driver.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    Core_models.Option.impl__is_none #i64
      (Vela_rekey_policy.next_epoch driver.f_epoch <: Core_models.Option.t_Option i64)
  then terminal driver (RekeyFailure_NoSuccessor <: t_RekeyFailure)
  else
    transition ({ driver with f_stage = RekeyStage_Chunks <: t_RekeyStage } <: t_RekeyDriver)
      (RekeyEffect_CheckChunkShadows <: t_RekeyEffect)

let finish_abort (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false) &&
        (match driver.f_op <: t_RekeyOp with
          | RekeyOp_Abort  -> true
          | _ -> false) &&
        ~.driver.f_active &&
        driver.f_starter_matches &&
        driver.f_header_present &&
        driver.f_rotation_matches &&
        driver.f_device_scope &&
        driver.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  let authority:Vela_rekey_policy.t_AttemptAuthority =
    {
      Vela_rekey_policy.f_device_scope = driver.f_device_scope;
      Vela_rekey_policy.f_starter_matches = driver.f_starter_matches;
      Vela_rekey_policy.f_rotation_id_present = driver.f_rotation_present;
      Vela_rekey_policy.f_rotation_id_matches = driver.f_rotation_matches
    }
    <:
    Vela_rekey_policy.t_AttemptAuthority
  in
  match
    Vela_rekey_policy.plan_abort ({
          Vela_rekey_policy.f_epoch = driver.f_epoch;
          Vela_rekey_policy.f_phase = Vela_rekey_policy.Phase_Freezing <: Vela_rekey_policy.t_Phase
        }
        <:
        Vela_rekey_policy.t_RekeyState)
      authority
    <:
    Vela_rekey_policy.t_AbortDecision
  with
  | Vela_rekey_policy.AbortDecision_Abort after ->
    transition ({
          driver with
          f_stage = RekeyStage_Rollback <: t_RekeyStage;
          f_epoch = after.Vela_rekey_policy.f_epoch
        }
        <:
        t_RekeyDriver)
      (RekeyEffect_RollbackAttempt <: t_RekeyEffect)
  | Vela_rekey_policy.AbortDecision_Reject  ->
    terminal driver (RekeyFailure_NotAuthorized <: t_RekeyFailure)

/// `ensure_starter`, `require_rotation_id` and `authorize_attempt`, in the
/// handler\'s historical precedence.
let after_freeze_checks (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false) &&
        (match driver.f_op <: t_RekeyOp with
          | RekeyOp_Capsules  | RekeyOp_Commit  | RekeyOp_Abort  -> true
          | _ -> false) &&
        driver.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if driver.f_active
  then terminal driver (RekeyFailure_NoRekeyInProgress <: t_RekeyFailure)
  else
    if ~.driver.f_starter_matches
    then terminal driver (RekeyFailure_StarterRequired <: t_RekeyFailure)
    else
      if ~.driver.f_header_present
      then terminal driver (RekeyFailure_RotationIdRequired <: t_RekeyFailure)
      else
        if ~.driver.f_rotation_matches
        then terminal driver (RekeyFailure_RotationIdMismatch <: t_RekeyFailure)
        else
          let authority:Vela_rekey_policy.t_AttemptAuthority =
            {
              Vela_rekey_policy.f_device_scope = driver.f_device_scope;
              Vela_rekey_policy.f_starter_matches = driver.f_starter_matches;
              Vela_rekey_policy.f_rotation_id_present = driver.f_rotation_present;
              Vela_rekey_policy.f_rotation_id_matches = driver.f_rotation_matches
            }
            <:
            Vela_rekey_policy.t_AttemptAuthority
          in
          match
            Vela_rekey_policy.authorize_attempt ({
                  Vela_rekey_policy.f_epoch = driver.f_epoch;
                  Vela_rekey_policy.f_phase
                  =
                  Vela_rekey_policy.Phase_Freezing <: Vela_rekey_policy.t_Phase
                }
                <:
                Vela_rekey_policy.t_RekeyState)
              authority
            <:
            Vela_rekey_policy.t_ShadowDecision
          with
          | Vela_rekey_policy.ShadowDecision_Allow  ->
            (match driver.f_op <: t_RekeyOp with
              | RekeyOp_Capsules  -> finish_capsules driver
              | RekeyOp_Commit  -> finish_commit driver
              | RekeyOp_Abort  -> finish_abort driver
              | RekeyOp_Start  -> transition driver (RekeyEffect_Idle <: t_RekeyEffect))
          | Vela_rekey_policy.ShadowDecision_Reject  ->
            terminal driver (RekeyFailure_NotAuthorized <: t_RekeyFailure)

let on_oram (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Oram  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_ProbeObservation with
  | ProbeObservation_Empty  ->
    transition ({ driver with f_stage = RekeyStage_Capable <: t_RekeyStage; f_no_oram = true }
        <:
        t_RekeyDriver)
      (RekeyEffect_CheckCapable <: t_RekeyEffect)
  | ProbeObservation_Found  ->
    let decided:t_RekeyDriver = { driver with f_no_oram = false } <: t_RekeyDriver in
    terminal decided (RekeyFailure_OramPresent <: t_RekeyFailure)
  | ProbeObservation_Storage  -> terminal driver (RekeyFailure_StateStorage <: t_RekeyFailure)

let on_capable (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Capable  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_ProbeObservation with
  | ProbeObservation_Empty  ->
    transition ({ driver with f_stage = RekeyStage_Acknowledged <: t_RekeyStage; f_capable = true }
        <:
        t_RekeyDriver)
      (RekeyEffect_CheckAcknowledged <: t_RekeyEffect)
  | ProbeObservation_Found  ->
    let decided:t_RekeyDriver = { driver with f_capable = false } <: t_RekeyDriver in
    terminal decided (RekeyFailure_CapabilityRequired <: t_RekeyFailure)
  | ProbeObservation_Storage  -> terminal driver (RekeyFailure_StateStorage <: t_RekeyFailure)

let start_plan (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Acknowledged  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  let facts:Vela_rekey_policy.t_StartFacts =
    {
      Vela_rekey_policy.f_no_oram = driver.f_no_oram;
      Vela_rekey_policy.f_all_devices_rekey_capable = driver.f_capable;
      Vela_rekey_policy.f_all_devices_acknowledged = driver.f_acknowledged
    }
    <:
    Vela_rekey_policy.t_StartFacts
  in
  match
    Vela_rekey_policy.plan_start ({
          Vela_rekey_policy.f_epoch = driver.f_epoch;
          Vela_rekey_policy.f_phase = Vela_rekey_policy.Phase_Active <: Vela_rekey_policy.t_Phase
        }
        <:
        Vela_rekey_policy.t_RekeyState)
      facts
    <:
    Vela_rekey_policy.t_StartDecision
  with
  | Vela_rekey_policy.StartDecision_Start plan ->
    transition ({
          driver with
          f_stage = RekeyStage_BeginTx <: t_RekeyStage;
          f_from_epoch = plan.Vela_rekey_policy.f_from_epoch;
          f_to_epoch = plan.Vela_rekey_policy.f_to_epoch
        }
        <:
        t_RekeyDriver)
      (RekeyEffect_BeginFreezeTransaction <: t_RekeyEffect)
  | Vela_rekey_policy.StartDecision_Reject  ->
    terminal driver (RekeyFailure_NoSuccessor <: t_RekeyFailure)

let on_acknowledged (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Acknowledged  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_ProbeObservation with
  | ProbeObservation_Empty  -> start_plan ({ driver with f_acknowledged = true } <: t_RekeyDriver)
  | ProbeObservation_Found  ->
    let decided:t_RekeyDriver = { driver with f_acknowledged = false } <: t_RekeyDriver in
    terminal decided (RekeyFailure_AdoptionRequired <: t_RekeyFailure)
  | ProbeObservation_Storage  -> terminal driver (RekeyFailure_StateStorage <: t_RekeyFailure)

let on_transaction (driver: t_RekeyDriver) (observation: t_TransactionObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_BeginTx  | RekeyStage_TxCommit  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match observation <: t_TransactionObservation with
    | TransactionObservation_Failed  -> true
    | _ -> false
  then
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_BeginTx  -> terminal driver (RekeyFailure_TransactionStorage <: t_RekeyFailure)
    | RekeyStage_TxCommit  -> terminal driver (RekeyFailure_TxCommitStorage <: t_RekeyFailure)
    | _ -> idle driver
  else
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_BeginTx  ->
      transition ({ driver with f_stage = RekeyStage_Inventory <: t_RekeyStage } <: t_RekeyDriver)
        (RekeyEffect_ReadInventory <: t_RekeyEffect)
    | RekeyStage_TxCommit  -> complete driver
    | _ -> idle driver

let on_inventory (driver: t_RekeyDriver) (observation: t_InventoryObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Inventory  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_InventoryObservation with
  | InventoryObservation_Read  ->
    transition ({ driver with f_stage = RekeyStage_FreezeCas <: t_RekeyStage } <: t_RekeyDriver)
      (RekeyEffect_FreezeCas <: t_RekeyEffect)
  | InventoryObservation_Failed  ->
    terminal driver (RekeyFailure_InventoryStorage <: t_RekeyFailure)

let on_freeze_cas (driver: t_RekeyDriver) (observation: t_CasObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_FreezeCas  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_CasObservation with
  | CasObservation_Updated  ->
    transition ({ driver with f_stage = RekeyStage_Cleanup <: t_RekeyStage } <: t_RekeyDriver)
      (RekeyEffect_CleanupChunks <: t_RekeyEffect)
  | CasObservation_Skipped  -> terminal driver (RekeyFailure_ConcurrentStart <: t_RekeyFailure)
  | CasObservation_Storage  -> terminal driver (RekeyFailure_TransactionStorage <: t_RekeyFailure)

let on_cleanup (driver: t_RekeyDriver) (observation: t_CleanupObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Cleanup  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_CleanupObservation with
  | CleanupObservation_Done  ->
    transition ({ driver with f_stage = RekeyStage_TxCommit <: t_RekeyStage } <: t_RekeyDriver)
      (RekeyEffect_CommitFreezeTransaction <: t_RekeyEffect)
  | CleanupObservation_Storage  -> terminal driver (RekeyFailure_CleanupStorage <: t_RekeyFailure)

let on_capsule (driver: t_RekeyDriver) (observation: t_CapsuleObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Capsule  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_CapsuleObservation with
  | CapsuleObservation_Stored  ->
    let next:i64 =
      if driver.f_capsules_written <. driver.f_capsule_count
      then driver.f_capsules_written +! mk_i64 1
      else driver.f_capsules_written
    in
    if next >. mk_i64 64
    then terminal driver (RekeyFailure_TooManyCapsules <: t_RekeyFailure)
    else
      if next =. driver.f_capsule_count
      then
        transition ({
              driver with
              f_stage = RekeyStage_Done <: t_RekeyStage;
              f_capsules_written = next;
              f_capsules_complete = true;
              f_responded = true
            }
            <:
            t_RekeyDriver)
          (RekeyEffect_Complete <: t_RekeyEffect)
      else
        transition ({
              driver with
              f_capsules_written = next;
              f_stage = RekeyStage_Capsule <: t_RekeyStage
            }
            <:
            t_RekeyDriver)
          (RekeyEffect_WriteCapsule ({ f_index = next }) <: t_RekeyEffect)
  | CapsuleObservation_Invalid
  | CapsuleObservation_NotTarget  ->
    terminal driver (RekeyFailure_CapsuleTargetInvalid <: t_RekeyFailure)
  | CapsuleObservation_Storage  -> terminal driver (RekeyFailure_StateStorage <: t_RekeyFailure)

let on_chunks (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Chunks  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_ProbeObservation with
  | ProbeObservation_Empty  ->
    transition ({
          driver with
          f_stage = RekeyStage_Devices <: t_RekeyStage;
          f_chunks_complete = true
        }
        <:
        t_RekeyDriver)
      (RekeyEffect_CheckDeviceCapsules <: t_RekeyEffect)
  | ProbeObservation_Found  ->
    let decided:t_RekeyDriver = { driver with f_chunks_complete = false } <: t_RekeyDriver in
    terminal decided (RekeyFailure_ChunkShadowsIncomplete <: t_RekeyFailure)
  | ProbeObservation_Storage  -> terminal driver (RekeyFailure_ChunkProbeStorage <: t_RekeyFailure)

let commit_plan (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Devices  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  let authority:Vela_rekey_policy.t_AttemptAuthority =
    {
      Vela_rekey_policy.f_device_scope = driver.f_device_scope;
      Vela_rekey_policy.f_starter_matches = driver.f_starter_matches;
      Vela_rekey_policy.f_rotation_id_present = driver.f_rotation_present;
      Vela_rekey_policy.f_rotation_id_matches = driver.f_rotation_matches
    }
    <:
    Vela_rekey_policy.t_AttemptAuthority
  in
  let facts:Vela_rekey_policy.t_CommitFacts =
    {
      Vela_rekey_policy.f_authority = authority;
      Vela_rekey_policy.f_chunk_shadows_complete = driver.f_chunks_complete;
      Vela_rekey_policy.f_device_capsules_complete = driver.f_capsules_complete
    }
    <:
    Vela_rekey_policy.t_CommitFacts
  in
  match
    Vela_rekey_policy.plan_commit ({
          Vela_rekey_policy.f_epoch = driver.f_epoch;
          Vela_rekey_policy.f_phase = Vela_rekey_policy.Phase_Freezing <: Vela_rekey_policy.t_Phase
        }
        <:
        Vela_rekey_policy.t_RekeyState)
      facts
    <:
    Vela_rekey_policy.t_CommitDecision
  with
  | Vela_rekey_policy.CommitDecision_Commit plan ->
    transition ({
          driver with
          f_stage = RekeyStage_CommitCas <: t_RekeyStage;
          f_from_epoch = plan.Vela_rekey_policy.f_from_epoch;
          f_to_epoch = plan.Vela_rekey_policy.f_to_epoch
        }
        <:
        t_RekeyDriver)
      (RekeyEffect_CommitCas <: t_RekeyEffect)
  | Vela_rekey_policy.CommitDecision_Reject  ->
    terminal driver (RekeyFailure_CommitNotAuthorized <: t_RekeyFailure)

let on_devices (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Devices  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_ProbeObservation with
  | ProbeObservation_Empty  ->
    commit_plan ({ driver with f_capsules_complete = true } <: t_RekeyDriver)
  | ProbeObservation_Found  ->
    let decided:t_RekeyDriver = { driver with f_capsules_complete = false } <: t_RekeyDriver in
    terminal decided (RekeyFailure_DeviceCapsulesIncomplete <: t_RekeyFailure)
  | ProbeObservation_Storage  ->
    terminal driver (RekeyFailure_CapsuleProbeStorage <: t_RekeyFailure)

let on_commit_cas (driver: t_RekeyDriver) (observation: t_CasObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_CommitCas  -> true
          | _ -> false) &&
        ~.driver.f_committed &&
        ~.driver.f_rolled_back &&
        ~.driver.f_responded &&
        ~.driver.f_failed &&
        driver.f_from_epoch =. driver.f_epoch &&
        (Vela_rekey_policy.next_epoch driver.f_from_epoch <: Core_models.Option.t_Option i64) =.
        (Core_models.Option.Option_Some driver.f_to_epoch <: Core_models.Option.t_Option i64) &&
        driver.f_to_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH &&
        driver.f_device_scope &&
        driver.f_starter_matches &&
        driver.f_rotation_present &&
        driver.f_rotation_matches &&
        driver.f_chunks_complete &&
        driver.f_capsules_complete &&
        driver.f_capsules_written =. driver.f_capsule_count)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_CasObservation with
  | CasObservation_Updated  ->
    transition ({
          driver with
          f_stage = RekeyStage_Sweep <: t_RekeyStage;
          f_committed = true;
          f_epoch = driver.f_to_epoch;
          f_active = true
        }
        <:
        t_RekeyDriver)
      (RekeyEffect_SweepOldChunks <: t_RekeyEffect)
  | CasObservation_Skipped  -> terminal driver (RekeyFailure_ConcurrentCommit <: t_RekeyFailure)
  | CasObservation_Storage  -> terminal driver (RekeyFailure_TransactionStorage <: t_RekeyFailure)

let on_sweep (driver: t_RekeyDriver) (e_observation: t_SweepObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Sweep  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  transition ({ driver with f_stage = RekeyStage_Publish <: t_RekeyStage } <: t_RekeyDriver)
    (RekeyEffect_PublishEpoch <: t_RekeyEffect)

let on_published (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Publish  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  transition ({
        driver with
        f_stage = RekeyStage_Done <: t_RekeyStage;
        f_published = true;
        f_responded = true
      }
      <:
      t_RekeyDriver)
    (RekeyEffect_Complete <: t_RekeyEffect)

let on_rollback (driver: t_RekeyDriver) (observation: t_RollbackObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Rollback  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_RollbackObservation with
  | RollbackObservation_RolledBack  ->
    complete ({ driver with f_active = true; f_rolled_back = true } <: t_RekeyDriver)
  | RollbackObservation_Raced  ->
    terminal driver (RekeyFailure_ConcurrentRollback <: t_RekeyFailure)
  | RollbackObservation_Storage  -> terminal driver (RekeyFailure_RollbackStorage <: t_RekeyFailure)

/// The commit replay decision for a non-freezing account.
let on_replay_state (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false) &&
        driver.f_active &&
        (match driver.f_op <: t_RekeyOp with
          | RekeyOp_Commit  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  let facts:Vela_rekey_policy.t_CommitReplayFacts =
    {
      Vela_rekey_policy.f_target_epoch = driver.f_replay_target;
      Vela_rekey_policy.f_recorded_epoch = driver.f_replay_recorded;
      Vela_rekey_policy.f_rotation_id_present = driver.f_header_present;
      Vela_rekey_policy.f_rotation_id_matches = driver.f_replay_id_matches
    }
    <:
    Vela_rekey_policy.t_CommitReplayFacts
  in
  match
    Vela_rekey_policy.authorize_commit_replay ({
          Vela_rekey_policy.f_epoch = driver.f_epoch;
          Vela_rekey_policy.f_phase = Vela_rekey_policy.Phase_Active <: Vela_rekey_policy.t_Phase
        }
        <:
        Vela_rekey_policy.t_RekeyState)
      facts
    <:
    Vela_rekey_policy.t_ShadowDecision
  with
  | Vela_rekey_policy.ShadowDecision_Allow  ->
    if
      driver.f_replay_target =.
      (Core_models.Option.Option_Some driver.f_epoch <: Core_models.Option.t_Option i64) &&
      driver.f_replay_recorded =.
      (Core_models.Option.Option_Some driver.f_epoch <: Core_models.Option.t_Option i64) &&
      driver.f_header_present &&
      driver.f_replay_id_matches
    then complete_replay driver
    else terminal driver (RekeyFailure_NoRekeyInProgress <: t_RekeyFailure)
  | Vela_rekey_policy.ShadowDecision_Reject  ->
    terminal driver (RekeyFailure_NoRekeyInProgress <: t_RekeyFailure)

/// The entry-point-specific decision after the state (and any timeout
/// rollback) is settled.
let dispatch_after_timeout (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false) &&
        driver.f_epoch >=. Vela_rekey_policy.v_INITIAL_EPOCH)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match driver.f_op <: t_RekeyOp with
  | RekeyOp_Start  ->
    if ~.driver.f_active
    then terminal driver (RekeyFailure_AlreadyInProgress <: t_RekeyFailure)
    else
      transition ({ driver with f_stage = RekeyStage_Oram <: t_RekeyStage } <: t_RekeyDriver)
        (RekeyEffect_CheckOram <: t_RekeyEffect)
  | RekeyOp_Capsules  -> after_freeze_checks driver
  | RekeyOp_Commit  ->
    if driver.f_active then on_replay_state driver else after_freeze_checks driver
  | RekeyOp_Abort  -> after_freeze_checks driver

/// Apply the post-load timeout decision and continue with `state`.
/// `maybe_rollback` is the only place the lazy timeout exists; the driver owns
/// the decision, the executor only performs the rollback. A rollback that
/// loses the race returns the winning state, exactly like the handler\'s
/// re-load.
let after_state (driver: t_RekeyDriver) (state: t_KeyStateObs)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  let observed:t_RekeyDriver =
    {
      f_op = driver.f_op;
      f_stage = RekeyStage_Load <: t_RekeyStage;
      f_authenticated = driver.f_authenticated;
      f_device_scope = driver.f_device_scope;
      f_epoch = state.f_epoch;
      f_active = ~.state.f_freezing;
      f_timeout_done = driver.f_timeout_done;
      f_starter_matches = state.f_starter_matches;
      f_rotation_present = state.f_rotation_id_present;
      f_header_present = state.f_header_present;
      f_rotation_matches = state.f_header_matches;
      f_replay_target = state.f_replay_target;
      f_replay_recorded = state.f_replay_recorded;
      f_replay_id_matches = state.f_replay_id_matches;
      f_capsule_count = driver.f_capsule_count;
      f_capsules_written = mk_i64 0;
      f_no_oram = false;
      f_capable = false;
      f_acknowledged = false;
      f_from_epoch = mk_i64 0;
      f_to_epoch = mk_i64 0;
      f_chunks_complete = false;
      f_capsules_complete = false;
      f_committed = false;
      f_rolled_back = false;
      f_timeout_rollback = false;
      f_published = false;
      f_responded = false;
      f_failed = false
    }
    <:
    t_RekeyDriver
  in
  if observed.f_epoch <. Vela_rekey_policy.v_INITIAL_EPOCH
  then terminal observed (RekeyFailure_InvalidEpoch <: t_RekeyFailure)
  else
    if state.f_freezing && ~.driver.f_timeout_done
    then
      let timeout:Vela_rekey_policy.t_TimeoutFacts =
        {
          Vela_rekey_policy.f_expired = state.f_expired;
          Vela_rekey_policy.f_rotation_id_present = state.f_rotation_id_present
        }
        <:
        Vela_rekey_policy.t_TimeoutFacts
      in
      match
        Vela_rekey_policy.plan_timeout ({
              Vela_rekey_policy.f_epoch = state.f_epoch;
              Vela_rekey_policy.f_phase
              =
              Vela_rekey_policy.Phase_Freezing <: Vela_rekey_policy.t_Phase
            }
            <:
            Vela_rekey_policy.t_RekeyState)
          timeout
        <:
        Vela_rekey_policy.t_TimeoutDecision
      with
      | Vela_rekey_policy.TimeoutDecision_Rollback _ ->
        transition ({ observed with f_stage = RekeyStage_Timeout <: t_RekeyStage } <: t_RekeyDriver)
          (RekeyEffect_TimeoutRollback <: t_RekeyEffect)
      | Vela_rekey_policy.TimeoutDecision_Keep  -> dispatch_after_timeout observed
    else dispatch_after_timeout observed

let on_state (driver: t_RekeyDriver) (observation: t_StateObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Load  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_StateObservation with
  | StateObservation_Loaded state -> after_state driver state
  | StateObservation_Storage  -> terminal driver (RekeyFailure_StateStorage <: t_RekeyFailure)
  | StateObservation_NotFound  -> terminal driver (RekeyFailure_AccountNotFound <: t_RekeyFailure)

let on_timeout (driver: t_RekeyDriver) (observation: t_TimeoutObservation)
    : Prims.Pure t_RekeyTransition
      (requires
        rekey_state_is_sound driver &&
        (match driver.f_stage <: t_RekeyStage with
          | RekeyStage_Timeout  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match observation <: t_TimeoutObservation with
  | TimeoutObservation_RolledBack  ->
    let restored:t_RekeyDriver =
      {
        driver with
        f_active = true;
        f_timeout_done = true;
        f_rolled_back = true;
        f_timeout_rollback = true;
        f_stage = RekeyStage_Load <: t_RekeyStage
      }
      <:
      t_RekeyDriver
    in
    dispatch_after_timeout restored
  | TimeoutObservation_Raced state ->
    let raced:t_RekeyDriver =
      { driver with f_timeout_done = true; f_stage = RekeyStage_Load <: t_RekeyStage }
      <:
      t_RekeyDriver
    in
    after_state raced state
  | TimeoutObservation_Storage  -> terminal driver (RekeyFailure_RollbackStorage <: t_RekeyFailure)

let step_rate_limit (driver: t_RekeyDriver) (observation: t_RateLimitObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_RateLimit  -> true
    | _ -> false
  then on_rate_limit driver observation
  else idle driver

let step_state (driver: t_RekeyDriver) (observation: t_StateObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Load  -> true
    | _ -> false
  then on_state driver observation
  else idle driver

let step_timeout (driver: t_RekeyDriver) (observation: t_TimeoutObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Timeout  -> true
    | _ -> false
  then on_timeout driver observation
  else idle driver

let step_oram (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Oram  -> true
    | _ -> false
  then on_oram driver observation
  else idle driver

let step_capable (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Capable  -> true
    | _ -> false
  then on_capable driver observation
  else idle driver

let step_acknowledged (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Acknowledged  -> true
    | _ -> false
  then on_acknowledged driver observation
  else idle driver

let step_transaction (driver: t_RekeyDriver) (observation: t_TransactionObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_BeginTx  | RekeyStage_TxCommit  -> true
    | _ -> false
  then on_transaction driver observation
  else idle driver

let step_tx_commit (driver: t_RekeyDriver) (observation: t_TransactionObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_TxCommit  -> true
    | _ -> false
  then on_transaction driver observation
  else idle driver

let step_inventory (driver: t_RekeyDriver) (observation: t_InventoryObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Inventory  -> true
    | _ -> false
  then on_inventory driver observation
  else idle driver

let step_freeze_cas (driver: t_RekeyDriver) (observation: t_CasObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_FreezeCas  -> true
    | _ -> false
  then on_freeze_cas driver observation
  else idle driver

let step_cleanup (driver: t_RekeyDriver) (observation: t_CleanupObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Cleanup  -> true
    | _ -> false
  then on_cleanup driver observation
  else idle driver

let step_capsule (driver: t_RekeyDriver) (observation: t_CapsuleObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Capsule  -> true
    | _ -> false
  then on_capsule driver observation
  else idle driver

let step_chunks (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Chunks  -> true
    | _ -> false
  then on_chunks driver observation
  else idle driver

let step_devices (driver: t_RekeyDriver) (observation: t_ProbeObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Devices  -> true
    | _ -> false
  then on_devices driver observation
  else idle driver

let step_commit_cas (driver: t_RekeyDriver) (observation: t_CasObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_CommitCas  -> true
    | _ -> false
  then on_commit_cas driver observation
  else idle driver

let step_sweep (driver: t_RekeyDriver) (observation: t_SweepObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Sweep  -> true
    | _ -> false
  then on_sweep driver observation
  else idle driver

let step_rollback (driver: t_RekeyDriver) (observation: t_RollbackObservation)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Rollback  -> true
    | _ -> false
  then on_rollback driver observation
  else idle driver

let step_published (driver: t_RekeyDriver)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  if
    match driver.f_stage <: t_RekeyStage with
    | RekeyStage_Publish  -> true
    | _ -> false
  then on_published driver
  else idle driver

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored. Each event is
/// dispatched to one contracted helper, so this function has no decision of
/// its own.
let rekey_step (driver: t_RekeyDriver) (event: t_RekeyEvent)
    : Prims.Pure t_RekeyTransition
      (requires rekey_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RekeyTransition = result in
          rekey_state_is_sound result.f_driver &&
          rekey_effect_is_sound result.f_driver result.f_effect &&
          (~.driver.f_committed || result.f_driver.f_committed) &&
          result.f_driver.f_op =. driver.f_op) =
  match event <: t_RekeyEvent with
  | RekeyEvent_RateLimit observation -> step_rate_limit driver observation
  | RekeyEvent_State observation -> step_state driver observation
  | RekeyEvent_Timeout observation -> step_timeout driver observation
  | RekeyEvent_Oram observation -> step_oram driver observation
  | RekeyEvent_Capable observation -> step_capable driver observation
  | RekeyEvent_Acknowledged observation -> step_acknowledged driver observation
  | RekeyEvent_Transaction observation -> step_transaction driver observation
  | RekeyEvent_Inventory observation -> step_inventory driver observation
  | RekeyEvent_FreezeCas observation -> step_freeze_cas driver observation
  | RekeyEvent_Cleanup observation -> step_cleanup driver observation
  | RekeyEvent_TxCommit observation -> step_tx_commit driver observation
  | RekeyEvent_Capsule observation -> step_capsule driver observation
  | RekeyEvent_Chunks observation -> step_chunks driver observation
  | RekeyEvent_Devices observation -> step_devices driver observation
  | RekeyEvent_CommitCas observation -> step_commit_cas driver observation
  | RekeyEvent_Sweep observation -> step_sweep driver observation
  | RekeyEvent_Published  -> step_published driver
  | RekeyEvent_Rollback observation -> step_rollback driver observation
