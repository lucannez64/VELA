module Vela_rekey_policy.Rekey_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects any rotation request performs: pacing, state load, a timeout
/// rollback, the readiness probes, the freeze transaction, the inventory, the
/// freeze CAS, the cleanup, the transaction commit — or 64 capsule writes, or
/// the two completeness probes, the commit CAS, the sweep and the publication.
let v_REKEY_MAX_EFFECTS: usize = mk_usize 67

/// The state invariant every loop keeps.
let rekey_loop_is_sound (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) : bool =
  Vela_rekey_policy.Rekey_driver.rekey_state_is_sound transition
      .Vela_rekey_policy.Rekey_driver.f_driver &&
  Vela_rekey_policy.Rekey_driver.rekey_effect_is_sound transition
      .Vela_rekey_policy.Rekey_driver.f_driver
    transition.Vela_rekey_policy.Rekey_driver.f_effect

/// The driver has decided: nothing more may be performed.
let rekey_effect_is_terminal (v_effect: Vela_rekey_policy.Rekey_driver.t_RekeyEffect) : bool =
  match v_effect <: Vela_rekey_policy.Rekey_driver.t_RekeyEffect with
  | Vela_rekey_policy.Rekey_driver.RekeyEffect_Complete
  | Vela_rekey_policy.Rekey_driver.RekeyEffect_CompleteReplay
  | Vela_rekey_policy.Rekey_driver.RekeyEffect_Fail _
  | Vela_rekey_policy.Rekey_driver.RekeyEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal rotation effect. Each method returns
/// only the observation its effect expects.
class t_RekeyIo (v_Self: Type0) = {
  f_rate_limit_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_rate_limit_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_RateLimitObservation)
    -> Type0;
  f_rate_limit:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_RateLimitObservation)
        (f_rate_limit_pre x0)
        (fun result -> f_rate_limit_post x0 result);
  f_load_state_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_load_state_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_StateObservation) -> Type0;
  f_load_state:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_StateObservation)
        (f_load_state_pre x0)
        (fun result -> f_load_state_post x0 result);
  f_timeout_rollback_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_timeout_rollback_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_TimeoutObservation)
    -> Type0;
  f_timeout_rollback:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_TimeoutObservation)
        (f_timeout_rollback_pre x0)
        (fun result -> f_timeout_rollback_post x0 result);
  f_check_oram_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_oram_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation) -> Type0;
  f_check_oram:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
        (f_check_oram_pre x0)
        (fun result -> f_check_oram_post x0 result);
  f_check_capable_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_capable_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
    -> Type0;
  f_check_capable:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
        (f_check_capable_pre x0)
        (fun result -> f_check_capable_post x0 result);
  f_check_acknowledged_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_acknowledged_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
    -> Type0;
  f_check_acknowledged:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
        (f_check_acknowledged_pre x0)
        (fun result -> f_check_acknowledged_post x0 result);
  f_begin_freeze_transaction_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_begin_freeze_transaction_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_TransactionObservation)
    -> Type0;
  f_begin_freeze_transaction:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_TransactionObservation)
        (f_begin_freeze_transaction_pre x0)
        (fun result -> f_begin_freeze_transaction_post x0 result);
  f_read_inventory_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_read_inventory_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_InventoryObservation)
    -> Type0;
  f_read_inventory:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_InventoryObservation)
        (f_read_inventory_pre x0)
        (fun result -> f_read_inventory_post x0 result);
  f_freeze_cas_pre:self_: v_Self -> from_epoch: i64 -> to_epoch: i64 -> pred: Type0{true ==> pred};
  f_freeze_cas_post:
      v_Self ->
      i64 ->
      i64 ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_CasObservation)
    -> Type0;
  f_freeze_cas:x0: v_Self -> x1: i64 -> x2: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_CasObservation)
        (f_freeze_cas_pre x0 x1 x2)
        (fun result -> f_freeze_cas_post x0 x1 x2 result);
  f_cleanup_chunks_pre:self_: v_Self -> from_epoch: i64 -> pred: Type0{true ==> pred};
  f_cleanup_chunks_post:
      v_Self ->
      i64 ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_CleanupObservation)
    -> Type0;
  f_cleanup_chunks:x0: v_Self -> x1: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_CleanupObservation)
        (f_cleanup_chunks_pre x0 x1)
        (fun result -> f_cleanup_chunks_post x0 x1 result);
  f_commit_freeze_transaction_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_commit_freeze_transaction_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_TransactionObservation)
    -> Type0;
  f_commit_freeze_transaction:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_TransactionObservation)
        (f_commit_freeze_transaction_pre x0)
        (fun result -> f_commit_freeze_transaction_post x0 result);
  f_write_capsule_pre:self_: v_Self -> index: i64 -> pred: Type0{true ==> pred};
  f_write_capsule_post:
      v_Self ->
      i64 ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_CapsuleObservation)
    -> Type0;
  f_write_capsule:x0: v_Self -> x1: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_CapsuleObservation)
        (f_write_capsule_pre x0 x1)
        (fun result -> f_write_capsule_post x0 x1 result);
  f_check_chunk_shadows_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_chunk_shadows_post:v_Self -> (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
    -> Type0;
  f_check_chunk_shadows:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
        (f_check_chunk_shadows_pre x0)
        (fun result -> f_check_chunk_shadows_post x0 result);
  f_check_device_capsules_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_device_capsules_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
    -> Type0;
  f_check_device_capsules:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_ProbeObservation)
        (f_check_device_capsules_pre x0)
        (fun result -> f_check_device_capsules_post x0 result);
  f_commit_cas_pre:self_: v_Self -> from_epoch: i64 -> to_epoch: i64 -> pred: Type0{true ==> pred};
  f_commit_cas_post:
      v_Self ->
      i64 ->
      i64 ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_CasObservation)
    -> Type0;
  f_commit_cas:x0: v_Self -> x1: i64 -> x2: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_CasObservation)
        (f_commit_cas_pre x0 x1 x2)
        (fun result -> f_commit_cas_post x0 x1 x2 result);
  f_sweep_old_chunks_pre:self_: v_Self -> new_epoch: i64 -> pred: Type0{true ==> pred};
  f_sweep_old_chunks_post:
      v_Self ->
      i64 ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_SweepObservation)
    -> Type0;
  f_sweep_old_chunks:x0: v_Self -> x1: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_SweepObservation)
        (f_sweep_old_chunks_pre x0 x1)
        (fun result -> f_sweep_old_chunks_post x0 x1 result);
  f_publish_epoch_pre:self_: v_Self -> epoch: i64 -> pred: Type0{true ==> pred};
  f_publish_epoch_post:v_Self -> i64 -> v_Self -> Type0;
  f_publish_epoch:x0: v_Self -> x1: i64
    -> Prims.Pure v_Self
        (f_publish_epoch_pre x0 x1)
        (fun result -> f_publish_epoch_post x0 x1 result);
  f_rollback_attempt_pre:self_: v_Self -> epoch: i64 -> pred: Type0{true ==> pred};
  f_rollback_attempt_post:
      v_Self ->
      i64 ->
      (v_Self & Vela_rekey_policy.Rekey_driver.t_RollbackObservation)
    -> Type0;
  f_rollback_attempt:x0: v_Self -> x1: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Rekey_driver.t_RollbackObservation)
        (f_rollback_attempt_pre x0 x1)
        (fun result -> f_rollback_attempt_post x0 x1 result)
}

/// The synchronous expansion of [`rekey_start_interpreter!`].
let run_start
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RekeyIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Rekey_driver.t_RekeyRequest)
    : (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
  let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition =
    Vela_rekey_policy.Rekey_driver.begin_start request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REKEY_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          rekey_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist44: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            match
              transition.Vela_rekey_policy.Rekey_driver.f_effect
              <:
              Vela_rekey_policy.Rekey_driver.t_RekeyEffect
            with
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RateLimit  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RateLimitObservation) =
                f_rate_limit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_RateLimit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_LoadState  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_StateObservation) =
                f_load_state #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_State out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_TimeoutRollback  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TimeoutObservation) =
                f_timeout_rollback #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Timeout out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckOram  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_oram #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Oram out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckCapable  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_capable #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capable out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckAcknowledged  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_acknowledged #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Acknowledged out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_BeginFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_begin_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Transaction out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_ReadInventory  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_InventoryObservation) =
                f_read_inventory #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Inventory out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_FreezeCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_freeze_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_FreezeCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CleanupChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CleanupObservation) =
                f_cleanup_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Cleanup out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_commit_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_TxCommit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_WriteCapsule
              { Vela_rekey_policy.Rekey_driver.f_index = index } ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CapsuleObservation) =
                f_write_capsule #v_Io #FStar.Tactics.Typeclasses.solve io index
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capsule out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckChunkShadows  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_chunk_shadows #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Chunks out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckDeviceCapsules  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_device_capsules #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Devices out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_commit_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_CommitCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_SweepOldChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_SweepObservation) =
                f_sweep_old_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Sweep out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_PublishEpoch  ->
              let io:v_Io =
                f_publish_epoch #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Published
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RollbackAttempt  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RollbackObservation) =
                f_rollback_attempt #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Rollback out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Complete
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CompleteReplay
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Fail _
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
          in
          let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = hoist44 in
          io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)

/// The synchronous expansion of [`rekey_capsules_interpreter!`].
let run_capsules
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RekeyIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Rekey_driver.t_RekeyRequest)
    : (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
  let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition =
    Vela_rekey_policy.Rekey_driver.begin_capsules request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REKEY_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          rekey_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist79: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            match
              transition.Vela_rekey_policy.Rekey_driver.f_effect
              <:
              Vela_rekey_policy.Rekey_driver.t_RekeyEffect
            with
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RateLimit  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RateLimitObservation) =
                f_rate_limit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_RateLimit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_LoadState  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_StateObservation) =
                f_load_state #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_State out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_TimeoutRollback  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TimeoutObservation) =
                f_timeout_rollback #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Timeout out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckOram  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_oram #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Oram out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckCapable  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_capable #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capable out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckAcknowledged  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_acknowledged #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Acknowledged out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_BeginFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_begin_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Transaction out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_ReadInventory  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_InventoryObservation) =
                f_read_inventory #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Inventory out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_FreezeCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_freeze_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_FreezeCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CleanupChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CleanupObservation) =
                f_cleanup_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Cleanup out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_commit_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_TxCommit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_WriteCapsule
              { Vela_rekey_policy.Rekey_driver.f_index = index } ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CapsuleObservation) =
                f_write_capsule #v_Io #FStar.Tactics.Typeclasses.solve io index
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capsule out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckChunkShadows  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_chunk_shadows #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Chunks out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckDeviceCapsules  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_device_capsules #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Devices out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_commit_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_CommitCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_SweepOldChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_SweepObservation) =
                f_sweep_old_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Sweep out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_PublishEpoch  ->
              let io:v_Io =
                f_publish_epoch #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Published
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RollbackAttempt  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RollbackObservation) =
                f_rollback_attempt #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Rollback out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Complete
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CompleteReplay
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Fail _
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
          in
          let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = hoist79 in
          io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)

/// The synchronous expansion of [`rekey_commit_interpreter!`].
let run_commit
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RekeyIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Rekey_driver.t_RekeyRequest)
    : (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
  let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition =
    Vela_rekey_policy.Rekey_driver.begin_commit request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REKEY_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          rekey_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist114: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            match
              transition.Vela_rekey_policy.Rekey_driver.f_effect
              <:
              Vela_rekey_policy.Rekey_driver.t_RekeyEffect
            with
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RateLimit  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RateLimitObservation) =
                f_rate_limit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_RateLimit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_LoadState  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_StateObservation) =
                f_load_state #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_State out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_TimeoutRollback  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TimeoutObservation) =
                f_timeout_rollback #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Timeout out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckOram  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_oram #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Oram out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckCapable  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_capable #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capable out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckAcknowledged  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_acknowledged #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Acknowledged out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_BeginFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_begin_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Transaction out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_ReadInventory  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_InventoryObservation) =
                f_read_inventory #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Inventory out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_FreezeCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_freeze_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_FreezeCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CleanupChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CleanupObservation) =
                f_cleanup_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Cleanup out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_commit_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_TxCommit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_WriteCapsule
              { Vela_rekey_policy.Rekey_driver.f_index = index } ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CapsuleObservation) =
                f_write_capsule #v_Io #FStar.Tactics.Typeclasses.solve io index
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capsule out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckChunkShadows  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_chunk_shadows #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Chunks out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckDeviceCapsules  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_device_capsules #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Devices out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_commit_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_CommitCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_SweepOldChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_SweepObservation) =
                f_sweep_old_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Sweep out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_PublishEpoch  ->
              let io:v_Io =
                f_publish_epoch #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Published
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RollbackAttempt  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RollbackObservation) =
                f_rollback_attempt #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Rollback out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Complete
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CompleteReplay
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Fail _
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
          in
          let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = hoist114 in
          io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)

/// The synchronous expansion of [`rekey_abort_interpreter!`].
let run_abort
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RekeyIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Rekey_driver.t_RekeyRequest)
    : (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
  let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition =
    Vela_rekey_policy.Rekey_driver.begin_abort request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REKEY_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          rekey_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist149: Vela_rekey_policy.Rekey_driver.t_RekeyTransition) =
            match
              transition.Vela_rekey_policy.Rekey_driver.f_effect
              <:
              Vela_rekey_policy.Rekey_driver.t_RekeyEffect
            with
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RateLimit  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RateLimitObservation) =
                f_rate_limit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_RateLimit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_LoadState  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_StateObservation) =
                f_load_state #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_State out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_TimeoutRollback  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TimeoutObservation) =
                f_timeout_rollback #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Timeout out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckOram  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_oram #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Oram out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckCapable  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_capable #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capable out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckAcknowledged  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_acknowledged #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Acknowledged out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_BeginFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_begin_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Transaction out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_ReadInventory  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_InventoryObservation) =
                f_read_inventory #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Inventory out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_FreezeCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_freeze_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_FreezeCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CleanupChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CleanupObservation) =
                f_cleanup_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Cleanup out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitFreezeTransaction  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_TransactionObservation) =
                f_commit_freeze_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_TxCommit out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_WriteCapsule
              { Vela_rekey_policy.Rekey_driver.f_index = index } ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CapsuleObservation) =
                f_write_capsule #v_Io #FStar.Tactics.Typeclasses.solve io index
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Capsule out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckChunkShadows  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_chunk_shadows #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Chunks out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CheckDeviceCapsules  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_ProbeObservation) =
                f_check_device_capsules #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Devices out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CommitCas  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_CasObservation) =
                f_commit_cas #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_from_epoch
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_CommitCas out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_SweepOldChunks  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_SweepObservation) =
                f_sweep_old_chunks #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Sweep out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_PublishEpoch  ->
              let io:v_Io =
                f_publish_epoch #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_to_epoch
              in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Published
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_RollbackAttempt  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Rekey_driver.t_RollbackObservation) =
                f_rollback_attempt #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_rekey_policy.Rekey_driver.f_driver
                    .Vela_rekey_policy.Rekey_driver.f_epoch
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Rekey_driver.rekey_step transition
                  .Vela_rekey_policy.Rekey_driver.f_driver
                (Vela_rekey_policy.Rekey_driver.RekeyEvent_Rollback out
                  <:
                  Vela_rekey_policy.Rekey_driver.t_RekeyEvent)
              <:
              (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Complete
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_CompleteReplay
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Fail _
            | Vela_rekey_policy.Rekey_driver.RekeyEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
          in
          let transition:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = hoist149 in
          io, transition <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Rekey_driver.t_RekeyTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Rekey_driver.t_RekeyTransition)
