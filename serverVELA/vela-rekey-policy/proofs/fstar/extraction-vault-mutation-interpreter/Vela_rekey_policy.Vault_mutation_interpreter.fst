module Vela_rekey_policy.Vault_mutation_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects a chunk delete performs: schema, route, version, delete and
/// publication.
let v_CHUNK_DELETE_MAX_EFFECTS: usize = mk_usize 5

/// Most effects an ORAM path write performs: route, quota, one write and at
/// most one recheck per bucket (33 buckets), and the publication.
let v_ORAM_MAX_EFFECTS: usize = mk_usize 69

/// Most effects the schema activation performs.
let v_SCHEMA_MAX_EFFECTS: usize = mk_usize 1

/// Most effects a capsule acknowledgement performs: the clear and the pending
/// inspection.
let v_CAPSULE_ACK_MAX_EFFECTS: usize = mk_usize 2

/// Most effects a capability attestation performs.
let v_REKEY_CAPABLE_MAX_EFFECTS: usize = mk_usize 1

let chunk_delete_loop_is_sound
      (transition: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
    : bool =
  Vela_rekey_policy.Vault_mutation_driver.chunk_delete_state_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver &&
  Vela_rekey_policy.Vault_mutation_driver.chunk_delete_effect_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver
    transition.Vela_rekey_policy.Vault_mutation_driver.f_effect

let oram_loop_is_sound (transition: Vela_rekey_policy.Vault_mutation_driver.t_OramTransition) : bool =
  Vela_rekey_policy.Vault_mutation_driver.oram_state_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver &&
  Vela_rekey_policy.Vault_mutation_driver.oram_effect_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver
    transition.Vela_rekey_policy.Vault_mutation_driver.f_effect

let schema_loop_is_sound (transition: Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition)
    : bool =
  Vela_rekey_policy.Vault_mutation_driver.schema_state_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver &&
  Vela_rekey_policy.Vault_mutation_driver.schema_effect_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver
    transition.Vela_rekey_policy.Vault_mutation_driver.f_effect

let capsule_ack_loop_is_sound
      (transition: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition)
    : bool =
  Vela_rekey_policy.Vault_mutation_driver.capsule_ack_state_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver &&
  Vela_rekey_policy.Vault_mutation_driver.capsule_ack_effect_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver
    transition.Vela_rekey_policy.Vault_mutation_driver.f_effect

let rekey_capable_loop_is_sound
      (transition: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition)
    : bool =
  Vela_rekey_policy.Vault_mutation_driver.rekey_capable_state_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver &&
  Vela_rekey_policy.Vault_mutation_driver.rekey_capable_effect_is_sound transition
      .Vela_rekey_policy.Vault_mutation_driver.f_driver
    transition.Vela_rekey_policy.Vault_mutation_driver.f_effect

let chunk_delete_effect_is_terminal
      (v_effect: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEffect)
    : bool =
  match v_effect <: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEffect with
  | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_Complete
  | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_Fail _
  | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_Idle  -> true
  | _ -> false

let oram_effect_is_terminal (v_effect: Vela_rekey_policy.Vault_mutation_driver.t_OramEffect) : bool =
  match v_effect <: Vela_rekey_policy.Vault_mutation_driver.t_OramEffect with
  | Vela_rekey_policy.Vault_mutation_driver.OramEffect_Complete
  | Vela_rekey_policy.Vault_mutation_driver.OramEffect_Fail _
  | Vela_rekey_policy.Vault_mutation_driver.OramEffect_Idle  -> true
  | _ -> false

let schema_effect_is_terminal (v_effect: Vela_rekey_policy.Vault_mutation_driver.t_SchemaEffect)
    : bool =
  match v_effect <: Vela_rekey_policy.Vault_mutation_driver.t_SchemaEffect with
  | Vela_rekey_policy.Vault_mutation_driver.SchemaEffect_Complete
  | Vela_rekey_policy.Vault_mutation_driver.SchemaEffect_Fail _
  | Vela_rekey_policy.Vault_mutation_driver.SchemaEffect_Idle  -> true
  | _ -> false

let capsule_ack_effect_is_terminal
      (v_effect: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckEffect)
    : bool =
  match v_effect <: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckEffect with
  | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_Complete
  | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_Fail _
  | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_Idle  -> true
  | _ -> false

let rekey_capable_effect_is_terminal
      (v_effect: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableEffect)
    : bool =
  match v_effect <: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableEffect with
  | Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEffect_Complete
  | Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEffect_Fail _
  | Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEffect_Idle  -> true
  | _ -> false

class t_ChunkDeleteIo (v_Self: Type0) = {
  f_check_schema_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_schema_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_SchemaObservation)
    -> Type0;
  f_check_schema:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_SchemaObservation)
        (f_check_schema_pre x0)
        (fun result -> f_check_schema_post x0 result);
  f_resolve_epoch_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_resolve_epoch_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_RouteObservation)
    -> Type0;
  f_resolve_epoch:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_RouteObservation)
        (f_resolve_epoch_pre x0)
        (fun result -> f_resolve_epoch_post x0 result);
  f_read_version_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_read_version_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_VersionObservation)
    -> Type0;
  f_read_version:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_VersionObservation)
        (f_read_version_pre x0)
        (fun result -> f_read_version_post x0 result);
  f_delete_row_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_delete_row_post:v_Self -> (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation)
    -> Type0;
  f_delete_row:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation)
        (f_delete_row_pre x0)
        (fun result -> f_delete_row_post x0 result);
  f_publish_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_publish_post:v_Self -> v_Self -> Type0;
  f_publish:x0: v_Self
    -> Prims.Pure v_Self (f_publish_pre x0) (fun result -> f_publish_post x0 result)
}

class t_OramIo (v_Self: Type0) = {
  f_resolve_path_epoch_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_resolve_path_epoch_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_RouteObservation)
    -> Type0;
  f_resolve_path_epoch:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_RouteObservation)
        (f_resolve_path_epoch_pre x0)
        (fun result -> f_resolve_path_epoch_post x0 result);
  f_enforce_quota_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_enforce_quota_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_QuotaObservation)
    -> Type0;
  f_enforce_quota:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_QuotaObservation)
        (f_enforce_quota_pre x0)
        (fun result -> f_enforce_quota_post x0 result);
  f_write_bucket_pre:self_: v_Self -> index: i64 -> pred: Type0{true ==> pred};
  f_write_bucket_post:
      v_Self ->
      i64 ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation)
    -> Type0;
  f_write_bucket:x0: v_Self -> x1: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation)
        (f_write_bucket_pre x0 x1)
        (fun result -> f_write_bucket_post x0 x1 result);
  f_recheck_bucket_pre:self_: v_Self -> index: i64 -> pred: Type0{true ==> pred};
  f_recheck_bucket_post:
      v_Self ->
      i64 ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_BucketRecheckObservation)
    -> Type0;
  f_recheck_bucket:x0: v_Self -> x1: i64
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_BucketRecheckObservation)
        (f_recheck_bucket_pre x0 x1)
        (fun result -> f_recheck_bucket_post x0 x1 result);
  f_publish_path_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_publish_path_post:v_Self -> v_Self -> Type0;
  f_publish_path:x0: v_Self
    -> Prims.Pure v_Self (f_publish_path_pre x0) (fun result -> f_publish_path_post x0 result)
}

class t_SchemaIo (v_Self: Type0) = {
  f_write_floor_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_write_floor_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_SchemaWriteObservation)
    -> Type0;
  f_write_floor:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_SchemaWriteObservation)
        (f_write_floor_pre x0)
        (fun result -> f_write_floor_post x0 result)
}

class t_CapsuleAckIo (v_Self: Type0) = {
  f_acknowledge_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_acknowledge_post:v_Self -> (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_AckObservation)
    -> Type0;
  f_acknowledge:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_AckObservation)
        (f_acknowledge_pre x0)
        (fun result -> f_acknowledge_post x0 result);
  f_inspect_pending_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_inspect_pending_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation)
    -> Type0;
  f_inspect_pending:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation)
        (f_inspect_pending_pre x0)
        (fun result -> f_inspect_pending_post x0 result)
}

class t_RekeyCapableIo (v_Self: Type0) = {
  f_attest_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_attest_post:v_Self -> (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation)
    -> Type0;
  f_attest:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation)
        (f_attest_pre x0)
        (fun result -> f_attest_post x0 result)
}

let run_chunk_delete
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_ChunkDeleteIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteRequest)
    : (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition) =
  let transition:Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition =
    Vela_rekey_policy.Vault_mutation_driver.begin_chunk_delete request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_CHUNK_DELETE_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          chunk_delete_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition))
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist16: Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
          =
            match
              transition.Vela_rekey_policy.Vault_mutation_driver.f_effect
              <:
              Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEffect
            with
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_CheckSchema  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_SchemaObservation) =
                f_check_schema #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.chunk_delete_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEvent_Schema out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_ResolveEpoch  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_RouteObservation) =
                f_resolve_epoch #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.chunk_delete_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEvent_Route out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_ReadVersion  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_VersionObservation)
              =
                f_read_version #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.chunk_delete_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEvent_Version out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_DeleteRow  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation) =
                f_delete_row #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.chunk_delete_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEvent_Delete out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_Publish  ->
              let io:v_Io = f_publish #v_Io #FStar.Tactics.Typeclasses.solve io in
              io,
              Vela_rekey_policy.Vault_mutation_driver.chunk_delete_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEvent_Published
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_Complete
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_Fail _
            | Vela_rekey_policy.Vault_mutation_driver.ChunkDeleteEffect_Idle  ->
              io, transition
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
          in
          let transition:Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition =
            hoist16
          in
          io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)
      )
  in
  let hax_temp_output:Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition =
    transition
  in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_ChunkDeleteTransition)

let run_oram
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_OramIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Vault_mutation_driver.t_OramRequest)
    : (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition) =
  let transition:Vela_rekey_policy.Vault_mutation_driver.t_OramTransition =
    Vela_rekey_policy.Vault_mutation_driver.begin_oram request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_OramTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_ORAM_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_OramTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          oram_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_OramTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist25: Vela_rekey_policy.Vault_mutation_driver.t_OramTransition) =
            match
              transition.Vela_rekey_policy.Vault_mutation_driver.f_effect
              <:
              Vela_rekey_policy.Vault_mutation_driver.t_OramEffect
            with
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_ResolveEpoch  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_RouteObservation) =
                f_resolve_path_epoch #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.oram_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.OramEvent_Route out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_OramEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition)
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_EnforceQuota  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_QuotaObservation) =
                f_enforce_quota #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.oram_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.OramEvent_Quota out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_OramEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition)
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_WriteBucket
              { Vela_rekey_policy.Vault_mutation_driver.f_index = index } ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation) =
                f_write_bucket #v_Io #FStar.Tactics.Typeclasses.solve io index
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.oram_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.OramEvent_Bucket out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_OramEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition)
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_RecheckBucket
              { Vela_rekey_policy.Vault_mutation_driver.f_index = index } ->
              let
              (tmp0: v_Io),
              (out: Vela_rekey_policy.Vault_mutation_driver.t_BucketRecheckObservation) =
                f_recheck_bucket #v_Io #FStar.Tactics.Typeclasses.solve io index
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.oram_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.OramEvent_Recheck out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_OramEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition)
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_Publish  ->
              let io:v_Io = f_publish_path #v_Io #FStar.Tactics.Typeclasses.solve io in
              io,
              Vela_rekey_policy.Vault_mutation_driver.oram_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.OramEvent_Published
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_OramEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition)
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_Complete
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_Fail _
            | Vela_rekey_policy.Vault_mutation_driver.OramEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition)
          in
          let transition:Vela_rekey_policy.Vault_mutation_driver.t_OramTransition = hoist25 in
          io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Vault_mutation_driver.t_OramTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_OramTransition)

let run_schema
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_SchemaIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Vault_mutation_driver.t_SchemaRequest)
    : (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition) =
  let transition:Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition =
    Vela_rekey_policy.Vault_mutation_driver.begin_schema request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_SCHEMA_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          schema_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist28: Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition) =
            match
              transition.Vela_rekey_policy.Vault_mutation_driver.f_effect
              <:
              Vela_rekey_policy.Vault_mutation_driver.t_SchemaEffect
            with
            | Vela_rekey_policy.Vault_mutation_driver.SchemaEffect_WriteFloor  ->
              let
              (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_SchemaWriteObservation)
              =
                f_write_floor #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.schema_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.SchemaEvent_Write out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_SchemaEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition)
            | Vela_rekey_policy.Vault_mutation_driver.SchemaEffect_Complete
            | Vela_rekey_policy.Vault_mutation_driver.SchemaEffect_Fail _
            | Vela_rekey_policy.Vault_mutation_driver.SchemaEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition)
          in
          let transition:Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition = hoist28 in
          io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_SchemaTransition)

let run_capsule_ack
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_CapsuleAckIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckRequest)
    : (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition) =
  let transition:Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition =
    Vela_rekey_policy.Vault_mutation_driver.begin_capsule_ack request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_CAPSULE_ACK_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          capsule_ack_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition))
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist33: Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition)
          =
            match
              transition.Vela_rekey_policy.Vault_mutation_driver.f_effect
              <:
              Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckEffect
            with
            | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_Acknowledge  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_AckObservation) =
                f_acknowledge #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.capsule_ack_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEvent_Ack out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition)
            | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_InspectPending  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation)
              =
                f_inspect_pending #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.capsule_ack_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEvent_Pending out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition)
            | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_Complete
            | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_Fail _
            | Vela_rekey_policy.Vault_mutation_driver.CapsuleAckEffect_Idle  ->
              io, transition
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition)
          in
          let transition:Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition = hoist33 in
          io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_CapsuleAckTransition)

let run_rekey_capable
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RekeyCapableIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableRequest)
    : (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition) =
  let transition:Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition =
    Vela_rekey_policy.Vault_mutation_driver.begin_rekey_capable request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REKEY_CAPABLE_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          rekey_capable_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition))
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          let
          (io: v_Io), (hoist36: Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition) =
            match
              transition.Vela_rekey_policy.Vault_mutation_driver.f_effect
              <:
              Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableEffect
            with
            | Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEffect_Attest  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation) =
                f_attest #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_mutation_driver.rekey_capable_step transition
                  .Vela_rekey_policy.Vault_mutation_driver.f_driver
                (Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEvent_Attest out
                  <:
                  Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition)
            | Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEffect_Complete
            | Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEffect_Fail _
            | Vela_rekey_policy.Vault_mutation_driver.RekeyCapableEffect_Idle  ->
              io, transition
              <:
              (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition)
          in
          let transition:Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition =
            hoist36
          in
          io, transition
          <:
          (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition =
    transition
  in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Vault_mutation_driver.t_RekeyCapableTransition)
