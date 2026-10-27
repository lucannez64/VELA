module Vela_recovery_policy.Recovery_share_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one lifecycle request performs: the update/read, an account
/// inspection after a zero-row update, and the verdict turn.
let v_RECOVERY_SHARE_MAX_EFFECTS: usize = mk_usize 3

/// The driver has decided: nothing more may be performed.
let share_lifecycle_effect_is_terminal
      (v_effect: Vela_recovery_policy.Recovery_share_driver.t_ShareEffect)
    : bool =
  match v_effect <: Vela_recovery_policy.Recovery_share_driver.t_ShareEffect with
  | Vela_recovery_policy.Recovery_share_driver.ShareEffect_Complete
  | Vela_recovery_policy.Recovery_share_driver.ShareEffect_Fail _
  | Vela_recovery_policy.Recovery_share_driver.ShareEffect_Idle  -> true
  | _ -> false

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
let share_lifecycle_transition_is_sound
      (transition: Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
    : bool =
  Vela_recovery_policy.Recovery_share_driver.share_lifecycle_state_is_sound transition
      .Vela_recovery_policy.Recovery_share_driver.f_driver &&
  Vela_recovery_policy.Recovery_share_driver.share_lifecycle_effect_is_sound transition
      .Vela_recovery_policy.Recovery_share_driver.f_driver
    transition.Vela_recovery_policy.Recovery_share_driver.f_effect

/// The I/O behind every non-terminal lifecycle effect. Each handler
/// implements the method for its own operation; the others refuse with
/// `None` (the driver never emits them, but the trait stays total and
/// panic-free). `None` aborts the request with the error the executor
/// recorded.
class t_RecoveryShareIo (v_Self: Type0) = {
  f_stage_share_pre:
      self_: v_Self ->
      permit: Vela_recovery_policy.Recovery_share_driver.t_ShareStagePermit
    -> pred: Type0{true ==> pred};
  f_stage_share_post:
      v_Self ->
      Vela_recovery_policy.Recovery_share_driver.t_ShareStagePermit ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation)
    -> Type0;
  f_stage_share:x0: v_Self -> x1: Vela_recovery_policy.Recovery_share_driver.t_ShareStagePermit
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation)
        (f_stage_share_pre x0 x1)
        (fun result -> f_stage_share_post x0 x1 result);
  f_stage_query_account_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_stage_query_account_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation)
    -> Type0;
  f_stage_query_account:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation)
        (f_stage_query_account_pre x0)
        (fun result -> f_stage_query_account_post x0 result);
  f_promote_staged_split_pre:
      self_: v_Self ->
      permit: Vela_recovery_policy.Recovery_share_driver.t_ShareFinalizePermit
    -> pred: Type0{true ==> pred};
  f_promote_staged_split_post:
      v_Self ->
      Vela_recovery_policy.Recovery_share_driver.t_ShareFinalizePermit ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation)
    -> Type0;
  f_promote_staged_split:
      x0: v_Self ->
      x1: Vela_recovery_policy.Recovery_share_driver.t_ShareFinalizePermit
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation)
        (f_promote_staged_split_pre x0 x1)
        (fun result -> f_promote_staged_split_post x0 x1 result);
  f_finalize_query_account_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_finalize_query_account_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation)
    -> Type0;
  f_finalize_query_account:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation)
        (f_finalize_query_account_pre x0)
        (fun result -> f_finalize_query_account_post x0 result);
  f_delete_share_pre:
      self_: v_Self ->
      permit: Vela_recovery_policy.Recovery_share_driver.t_ShareDeletePermit
    -> pred: Type0{true ==> pred};
  f_delete_share_post:
      v_Self ->
      Vela_recovery_policy.Recovery_share_driver.t_ShareDeletePermit ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation)
    -> Type0;
  f_delete_share:x0: v_Self -> x1: Vela_recovery_policy.Recovery_share_driver.t_ShareDeletePermit
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation)
        (f_delete_share_pre x0 x1)
        (fun result -> f_delete_share_post x0 x1 result);
  f_read_share_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_read_share_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Recovery_share_driver.t_ReadObservation)
    -> Type0;
  f_read_share:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Recovery_share_driver.t_ReadObservation)
        (f_read_share_pre x0)
        (fun result -> f_read_share_post x0 result)
}

/// The synchronous expansion of [`recovery_share_interpreter!`]: the artifact
/// hax extracts and F* checks.
let run_share_lifecycle
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RecoveryShareIo v_Io)
      (io: v_Io)
      (request: Vela_recovery_policy.Recovery_share_driver.t_ShareRequestObservation)
    : (v_Io &
      Core_models.Option.t_Option Vela_recovery_policy.Recovery_share_driver.t_ShareTransition) =
  let transition:Vela_recovery_policy.Recovery_share_driver.t_ShareTransition =
    Vela_recovery_policy.Recovery_share_driver.begin_share_lifecycle request
  in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (transition: Vela_recovery_policy.Recovery_share_driver.t_ShareTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_RECOVERY_SHARE_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Recovery_share_driver.t_ShareTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          share_lifecycle_transition_is_sound transition <: bool)
      (aborted, io, transition
        <:
        (bool & v_Io & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Recovery_share_driver.t_ShareTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if ~.aborted <: bool
          then
            let
            ((aborted: bool), (io: v_Io)),
            (hoist16: Vela_recovery_policy.Recovery_share_driver.t_ShareTransition) =
              match
                transition.Vela_recovery_policy.Recovery_share_driver.f_effect
                <:
                Vela_recovery_policy.Recovery_share_driver.t_ShareEffect
              with
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_StageShare permit ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation) =
                  f_stage_share #v_Io #FStar.Tactics.Typeclasses.solve io permit
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Recovery_share_driver.step_share_lifecycle transition
                        .Vela_recovery_policy.Recovery_share_driver.f_driver
                      (Vela_recovery_policy.Recovery_share_driver.ShareEvent_StageUpdate observation
                        <:
                        Vela_recovery_policy.Recovery_share_driver.t_ShareEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_StageQueryAccount  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation) =
                  f_stage_query_account #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Recovery_share_driver.step_share_lifecycle transition
                        .Vela_recovery_policy.Recovery_share_driver.f_driver
                      (Vela_recovery_policy.Recovery_share_driver.ShareEvent_StageAccount
                        observation
                        <:
                        Vela_recovery_policy.Recovery_share_driver.t_ShareEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_PromoteStagedSplit permit ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation) =
                  f_promote_staged_split #v_Io #FStar.Tactics.Typeclasses.solve io permit
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Recovery_share_driver.step_share_lifecycle transition
                        .Vela_recovery_policy.Recovery_share_driver.f_driver
                      (Vela_recovery_policy.Recovery_share_driver.ShareEvent_FinalizeUpdate
                        observation
                        <:
                        Vela_recovery_policy.Recovery_share_driver.t_ShareEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_FinalizeQueryAccount  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation) =
                  f_finalize_query_account #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Recovery_share_driver.step_share_lifecycle transition
                        .Vela_recovery_policy.Recovery_share_driver.f_driver
                      (Vela_recovery_policy.Recovery_share_driver.ShareEvent_FinalizeAccount
                        observation
                        <:
                        Vela_recovery_policy.Recovery_share_driver.t_ShareEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_DeleteShare permit ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation) =
                  f_delete_share #v_Io #FStar.Tactics.Typeclasses.solve io permit
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Recovery_share_driver.step_share_lifecycle transition
                        .Vela_recovery_policy.Recovery_share_driver.f_driver
                      (Vela_recovery_policy.Recovery_share_driver.ShareEvent_DeleteUpdate
                        observation
                        <:
                        Vela_recovery_policy.Recovery_share_driver.t_ShareEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_ReadShare  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Recovery_share_driver.t_ReadObservation) =
                  f_read_share #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Recovery_share_driver.t_ReadObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Recovery_share_driver.step_share_lifecycle transition
                        .Vela_recovery_policy.Recovery_share_driver.f_driver
                      (Vela_recovery_policy.Recovery_share_driver.ShareEvent_ReadObserved
                        observation
                        <:
                        Vela_recovery_policy.Recovery_share_driver.t_ShareEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_Complete
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_Fail _
              | Vela_recovery_policy.Recovery_share_driver.ShareEffect_Idle  ->
                (aborted, io <: (bool & v_Io)), transition
                <:
                ((bool & v_Io) & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
            in
            let transition:Vela_recovery_policy.Recovery_share_driver.t_ShareTransition = hoist16 in
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
          else
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Recovery_share_driver.t_ShareTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option
  Vela_recovery_policy.Recovery_share_driver.t_ShareTransition =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Recovery_share_driver.t_ShareTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Recovery_share_driver.t_ShareTransition
  in
  io, hax_temp_output
  <:
  (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Recovery_share_driver.t_ShareTransition)
