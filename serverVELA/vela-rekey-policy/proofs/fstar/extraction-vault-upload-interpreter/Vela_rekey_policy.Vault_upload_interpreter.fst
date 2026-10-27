module Vela_rekey_policy.Vault_upload_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one upload performs: resolve, shadow authority, quota, the
/// guarded write, the version read-back, the shadow-activity refresh and the
/// publication.
let v_UPLOAD_MAX_EFFECTS: usize = mk_usize 7

/// Most effects one read performs: the served epoch and the row lookup.
let v_READ_MAX_EFFECTS: usize = mk_usize 2

/// The state invariant the upload loop keeps: the driver's own soundness
/// predicate on the transition's driver. It is a named helper so the extracted
/// loop invariant need not project a record field from a tuple whose type is
/// still being inferred.
let upload_loop_is_sound (transition: Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
    : bool =
  Vela_rekey_policy.Vault_upload_driver.upload_state_is_sound transition
      .Vela_rekey_policy.Vault_upload_driver.f_driver &&
  Vela_rekey_policy.Vault_upload_driver.upload_effect_is_sound transition
      .Vela_rekey_policy.Vault_upload_driver.f_driver
    transition.Vela_rekey_policy.Vault_upload_driver.f_effect

/// The state invariant the read loop keeps.
let read_loop_is_sound (transition: Vela_rekey_policy.Vault_upload_driver.t_ReadTransition) : bool =
  Vela_rekey_policy.Vault_upload_driver.read_state_is_sound transition
      .Vela_rekey_policy.Vault_upload_driver.f_driver &&
  Vela_rekey_policy.Vault_upload_driver.read_effect_is_sound transition
      .Vela_rekey_policy.Vault_upload_driver.f_driver
    transition.Vela_rekey_policy.Vault_upload_driver.f_effect

/// The driver has decided: nothing more may be performed.
let upload_effect_is_terminal (v_effect: Vela_rekey_policy.Vault_upload_driver.t_UploadEffect)
    : bool =
  match v_effect <: Vela_rekey_policy.Vault_upload_driver.t_UploadEffect with
  | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Complete
  | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Fail _
  | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Idle  -> true
  | _ -> false

/// The driver has decided: nothing more may be performed.
let read_effect_is_terminal (v_effect: Vela_rekey_policy.Vault_upload_driver.t_ReadEffect) : bool =
  match v_effect <: Vela_rekey_policy.Vault_upload_driver.t_ReadEffect with
  | Vela_rekey_policy.Vault_upload_driver.ReadEffect_Serve
    { Vela_rekey_policy.Vault_upload_driver.f_version = _ ;
      Vela_rekey_policy.Vault_upload_driver.f_lamport_clock = _ }
  | Vela_rekey_policy.Vault_upload_driver.ReadEffect_Fail _
  | Vela_rekey_policy.Vault_upload_driver.ReadEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal upload effect. Each method returns only
/// the observation its effect expects; `None` from a lookup method means
/// that lookup failed and the handler kept its error.
class t_UploadIo (v_Self: Type0) = {
  f_resolve_epoch_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_resolve_epoch_post:v_Self -> (v_Self & Vela_rekey_policy.Vault_upload_driver.t_RekeyObservation)
    -> Type0;
  f_resolve_epoch:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_upload_driver.t_RekeyObservation)
        (f_resolve_epoch_pre x0)
        (fun result -> f_resolve_epoch_post x0 result);
  f_authorize_shadow_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_authorize_shadow_post:
      v_Self ->
      (v_Self & Core_models.Option.t_Option Vela_rekey_policy.t_AttemptAuthority)
    -> Type0;
  f_authorize_shadow:x0: v_Self
    -> Prims.Pure (v_Self & Core_models.Option.t_Option Vela_rekey_policy.t_AttemptAuthority)
        (f_authorize_shadow_pre x0)
        (fun result -> f_authorize_shadow_post x0 result);
  f_enforce_quota_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_enforce_quota_post:v_Self -> (v_Self & Vela_rekey_policy.Vault_upload_driver.t_QuotaObservation)
    -> Type0;
  f_enforce_quota:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_upload_driver.t_QuotaObservation)
        (f_enforce_quota_pre x0)
        (fun result -> f_enforce_quota_post x0 result);
  f_guarded_write_pre:
      self_: v_Self ->
      permit: Vela_rekey_policy.Vault_upload_driver.t_UploadWritePermit
    -> pred: Type0{true ==> pred};
  f_guarded_write_post:
      v_Self ->
      Vela_rekey_policy.Vault_upload_driver.t_UploadWritePermit ->
      (v_Self & Vela_rekey_policy.Vault_upload_driver.t_WriteObservation)
    -> Type0;
  f_guarded_write:x0: v_Self -> x1: Vela_rekey_policy.Vault_upload_driver.t_UploadWritePermit
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_upload_driver.t_WriteObservation)
        (f_guarded_write_pre x0 x1)
        (fun result -> f_guarded_write_post x0 x1 result);
  f_recheck_state_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_recheck_state_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_upload_driver.t_RecheckObservation)
    -> Type0;
  f_recheck_state:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_upload_driver.t_RecheckObservation)
        (f_recheck_state_pre x0)
        (fun result -> f_recheck_state_post x0 result);
  f_reread_version_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_reread_version_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_upload_driver.t_RereadObservation)
    -> Type0;
  f_reread_version:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_upload_driver.t_RereadObservation)
        (f_reread_version_pre x0)
        (fun result -> f_reread_version_post x0 result);
  f_record_shadow_activity_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_record_shadow_activity_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation)
    -> Type0;
  f_record_shadow_activity:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation)
        (f_record_shadow_activity_pre x0)
        (fun result -> f_record_shadow_activity_post x0 result);
  f_publish_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_publish_post:v_Self -> v_Self -> Type0;
  f_publish:x0: v_Self
    -> Prims.Pure v_Self (f_publish_pre x0) (fun result -> f_publish_post x0 result)
}

/// The I/O behind each non-terminal read effect.
class t_ReadIo (v_Self: Type0) = {
  f_read_epoch_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_read_epoch_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_rekey_policy.Vault_upload_driver.t_ReadEpochObservation)
    -> Type0;
  f_read_epoch:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_rekey_policy.Vault_upload_driver.t_ReadEpochObservation)
        (f_read_epoch_pre x0)
        (fun result -> f_read_epoch_post x0 result);
  f_lookup_chunk_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_lookup_chunk_post:
      v_Self ->
      (v_Self & Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation)
    -> Type0;
  f_lookup_chunk:x0: v_Self
    -> Prims.Pure (v_Self & Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation)
        (f_lookup_chunk_pre x0)
        (fun result -> f_lookup_chunk_post x0 result)
}

/// The synchronous expansion of [`upload_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_upload
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_UploadIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Vault_upload_driver.t_UploadRequest)
    : (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition) =
  let transition:Vela_rekey_policy.Vault_upload_driver.t_UploadTransition =
    Vela_rekey_policy.Vault_upload_driver.begin_upload request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Vault_upload_driver.t_UploadTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_UPLOAD_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_upload_driver.t_UploadTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          upload_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_upload_driver.t_UploadTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist18: Vela_rekey_policy.Vault_upload_driver.t_UploadTransition) =
            match
              transition.Vela_rekey_policy.Vault_upload_driver.f_effect
              <:
              Vela_rekey_policy.Vault_upload_driver.t_UploadEffect
            with
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_ResolveEpoch  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_upload_driver.t_RekeyObservation) =
                f_resolve_epoch #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_upload_driver.upload_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Rekey out
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_AuthorizeShadow  ->
              let
              (tmp0: v_Io), (out: Core_models.Option.t_Option Vela_rekey_policy.t_AttemptAuthority)
              =
                f_authorize_shadow #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              (match out <: Core_models.Option.t_Option Vela_rekey_policy.t_AttemptAuthority with
                | Core_models.Option.Option_Some authority ->
                  io,
                  Vela_rekey_policy.Vault_upload_driver.upload_step transition
                      .Vela_rekey_policy.Vault_upload_driver.f_driver
                    (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Attempt authority
                      <:
                      Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
                  <:
                  (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
                | Core_models.Option.Option_None  ->
                  io,
                  Vela_rekey_policy.Vault_upload_driver.upload_step transition
                      .Vela_rekey_policy.Vault_upload_driver.f_driver
                    (Vela_rekey_policy.Vault_upload_driver.UploadEvent_AttemptStorage
                      <:
                      Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
                  <:
                  (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition))
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_EnforceQuota  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_upload_driver.t_QuotaObservation) =
                f_enforce_quota #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_upload_driver.upload_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Quota out
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Write permit ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_upload_driver.t_WriteObservation) =
                f_guarded_write #v_Io #FStar.Tactics.Typeclasses.solve io permit
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_upload_driver.upload_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Write out
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_RecheckState  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_upload_driver.t_RecheckObservation) =
                f_recheck_state #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_upload_driver.upload_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Recheck out
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_RereadVersion  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_upload_driver.t_RereadObservation) =
                f_reread_version #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_upload_driver.upload_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Reread out
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_RecordShadowActivity  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation) =
                f_record_shadow_activity #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_upload_driver.upload_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Activity out
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Publish  ->
              let io:v_Io = f_publish #v_Io #FStar.Tactics.Typeclasses.solve io in
              io,
              Vela_rekey_policy.Vault_upload_driver.upload_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.UploadEvent_Published
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_UploadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Complete
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Fail _
            | Vela_rekey_policy.Vault_upload_driver.UploadEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)
          in
          let transition:Vela_rekey_policy.Vault_upload_driver.t_UploadTransition = hoist18 in
          io, transition <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Vault_upload_driver.t_UploadTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_UploadTransition)

/// The synchronous expansion of [`read_interpreter!`].
let run_read
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_ReadIo v_Io)
      (io: v_Io)
      (request: Vela_rekey_policy.Vault_upload_driver.t_ReadRequest)
    : (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition) =
  let transition:Vela_rekey_policy.Vault_upload_driver.t_ReadTransition =
    Vela_rekey_policy.Vault_upload_driver.begin_read request
  in
  let (io: v_Io), (transition: Vela_rekey_policy.Vault_upload_driver.t_ReadTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_READ_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_upload_driver.t_ReadTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          read_loop_is_sound transition <: bool)
      (io, transition <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_rekey_policy.Vault_upload_driver.t_ReadTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist22: Vela_rekey_policy.Vault_upload_driver.t_ReadTransition) =
            match
              transition.Vela_rekey_policy.Vault_upload_driver.f_effect
              <:
              Vela_rekey_policy.Vault_upload_driver.t_ReadEffect
            with
            | Vela_rekey_policy.Vault_upload_driver.ReadEffect_ReadEpoch  ->
              let
              (tmp0: v_Io),
              (out:
                Core_models.Option.t_Option
                Vela_rekey_policy.Vault_upload_driver.t_ReadEpochObservation) =
                f_read_epoch #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              (match
                  out
                  <:
                  Core_models.Option.t_Option
                  Vela_rekey_policy.Vault_upload_driver.t_ReadEpochObservation
                with
                | Core_models.Option.Option_Some observation ->
                  io,
                  Vela_rekey_policy.Vault_upload_driver.read_step transition
                      .Vela_rekey_policy.Vault_upload_driver.f_driver
                    (Vela_rekey_policy.Vault_upload_driver.ReadEvent_Epoch observation
                      <:
                      Vela_rekey_policy.Vault_upload_driver.t_ReadEvent)
                  <:
                  (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition)
                | Core_models.Option.Option_None  ->
                  io,
                  Vela_rekey_policy.Vault_upload_driver.read_step transition
                      .Vela_rekey_policy.Vault_upload_driver.f_driver
                    (Vela_rekey_policy.Vault_upload_driver.ReadEvent_EpochStorage
                      <:
                      Vela_rekey_policy.Vault_upload_driver.t_ReadEvent)
                  <:
                  (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition))
            | Vela_rekey_policy.Vault_upload_driver.ReadEffect_LookupChunk  ->
              let (tmp0: v_Io), (out: Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation)
              =
                f_lookup_chunk #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_rekey_policy.Vault_upload_driver.read_step transition
                  .Vela_rekey_policy.Vault_upload_driver.f_driver
                (Vela_rekey_policy.Vault_upload_driver.ReadEvent_Lookup out
                  <:
                  Vela_rekey_policy.Vault_upload_driver.t_ReadEvent)
              <:
              (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition)
            | Vela_rekey_policy.Vault_upload_driver.ReadEffect_Serve
              { Vela_rekey_policy.Vault_upload_driver.f_version = _ ;
                Vela_rekey_policy.Vault_upload_driver.f_lamport_clock = _ }
            | Vela_rekey_policy.Vault_upload_driver.ReadEffect_Fail _
            | Vela_rekey_policy.Vault_upload_driver.ReadEffect_Idle  ->
              io, transition <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition)
          in
          let transition:Vela_rekey_policy.Vault_upload_driver.t_ReadTransition = hoist22 in
          io, transition <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition))
  in
  let hax_temp_output:Vela_rekey_policy.Vault_upload_driver.t_ReadTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_rekey_policy.Vault_upload_driver.t_ReadTransition)
