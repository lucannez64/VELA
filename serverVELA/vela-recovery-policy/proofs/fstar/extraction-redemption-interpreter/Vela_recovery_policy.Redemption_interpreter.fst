module Vela_recovery_policy.Redemption_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most turns one request takes: consume, final policy, insert, optional
/// authority recheck, and the optional grant restoration.
let v_REDEMPTION_MAX_EFFECTS: usize = mk_usize 5

/// The driver has decided: nothing more may be performed (a `RestoreAndFail`
/// still performs its one recorded restoration first).
let redemption_effect_is_terminal (v_effect: Vela_recovery_policy.Driver.t_RedemptionEffect) : bool =
  match v_effect <: Vela_recovery_policy.Driver.t_RedemptionEffect with
  | Vela_recovery_policy.Driver.RedemptionEffect_Complete
  | Vela_recovery_policy.Driver.RedemptionEffect_Fail _
  | Vela_recovery_policy.Driver.RedemptionEffect_RestoreAndFail _
  | Vela_recovery_policy.Driver.RedemptionEffect_Idle  -> true
  | _ -> false

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
let redemption_transition_is_sound (transition: Vela_recovery_policy.Driver.t_RedemptionTransition)
    : bool =
  Vela_recovery_policy.Driver.redemption_state_is_sound transition
      .Vela_recovery_policy.Driver.f_driver &&
  Vela_recovery_policy.Driver.redemption_effect_is_sound transition
      .Vela_recovery_policy.Driver.f_driver
    transition.Vela_recovery_policy.Driver.f_effect

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects; `None` aborts the request with the
/// error the executor recorded.
class t_RedemptionIo (v_Self: Type0) = {
  f_consume_grant_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_consume_grant_post:
      v_Self ->
      (v_Self & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_ConsumptionObservation)
    -> Type0;
  f_consume_grant:x0: v_Self
    -> Prims.Pure
        (v_Self & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_ConsumptionObservation)
        (f_consume_grant_pre x0)
        (fun result -> f_consume_grant_post x0 result);
  f_final_policy_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_final_policy_post:
      v_Self ->
      (v_Self & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_FinalPolicyObservation)
    -> Type0;
  f_final_policy:x0: v_Self
    -> Prims.Pure
        (v_Self & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_FinalPolicyObservation)
        (f_final_policy_pre x0)
        (fun result -> f_final_policy_post x0 result);
  f_insert_device_pre:self_: v_Self -> permit: Vela_recovery_policy.Driver.t_RedemptionInsertPermit
    -> pred: Type0{true ==> pred};
  f_insert_device_post:
      v_Self ->
      Vela_recovery_policy.Driver.t_RedemptionInsertPermit ->
      (v_Self & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_InsertObservation)
    -> Type0;
  f_insert_device:x0: v_Self -> x1: Vela_recovery_policy.Driver.t_RedemptionInsertPermit
    -> Prims.Pure
        (v_Self & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_InsertObservation)
        (f_insert_device_pre x0 x1)
        (fun result -> f_insert_device_post x0 x1 result);
  f_recheck_authority_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_recheck_authority_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Driver.t_AuthorityRecheckObservation)
    -> Type0;
  f_recheck_authority:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Driver.t_AuthorityRecheckObservation)
        (f_recheck_authority_pre x0)
        (fun result -> f_recheck_authority_post x0 result);
  f_restore_grant_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_restore_grant_post:v_Self -> (v_Self & Core_models.Option.t_Option Prims.unit) -> Type0;
  f_restore_grant:x0: v_Self
    -> Prims.Pure (v_Self & Core_models.Option.t_Option Prims.unit)
        (f_restore_grant_pre x0)
        (fun result -> f_restore_grant_post x0 result)
}

/// The synchronous expansion of [`redemption_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_redemption
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RedemptionIo v_Io)
      (io: v_Io)
      (ready: Vela_recovery_policy.t_ReadyToConsume)
    : (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_RedemptionTransition) =
  let transition:Vela_recovery_policy.Driver.t_RedemptionTransition =
    Vela_recovery_policy.Driver.begin_redemption ready
  in
  let restore_done:bool = false in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (restore_done: bool),
  (transition: Vela_recovery_policy.Driver.t_RedemptionTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REDEMPTION_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (restore_done: bool),
          (transition: Vela_recovery_policy.Driver.t_RedemptionTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          redemption_transition_is_sound transition <: bool)
      (aborted, io, restore_done, transition
        <:
        (bool & v_Io & bool & Vela_recovery_policy.Driver.t_RedemptionTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (restore_done: bool),
          (transition: Vela_recovery_policy.Driver.t_RedemptionTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if (~.aborted <: bool) && (~.restore_done <: bool)
          then
            let
            ((aborted: bool), (io: v_Io), (restore_done: bool)),
            (hoist6: Vela_recovery_policy.Driver.t_RedemptionTransition) =
              match
                transition.Vela_recovery_policy.Driver.f_effect
                <:
                Vela_recovery_policy.Driver.t_RedemptionEffect
              with
              | Vela_recovery_policy.Driver.RedemptionEffect_Consume  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option Vela_recovery_policy.Driver.t_ConsumptionObservation)
                =
                  f_consume_grant #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option Vela_recovery_policy.Driver.t_ConsumptionObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io, restore_done <: (bool & v_Io & bool)),
                    Vela_recovery_policy.Driver.step transition.Vela_recovery_policy.Driver.f_driver
                      (Vela_recovery_policy.Driver.RedemptionEvent_Consumed observation
                        <:
                        Vela_recovery_policy.Driver.t_RedemptionEvent)
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io, restore_done <: (bool & v_Io & bool)), transition
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition))
              | Vela_recovery_policy.Driver.RedemptionEffect_FinalPolicy  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option Vela_recovery_policy.Driver.t_FinalPolicyObservation)
                =
                  f_final_policy #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option Vela_recovery_policy.Driver.t_FinalPolicyObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io, restore_done <: (bool & v_Io & bool)),
                    Vela_recovery_policy.Driver.step transition.Vela_recovery_policy.Driver.f_driver
                      (Vela_recovery_policy.Driver.RedemptionEvent_FinalPolicy observation
                        <:
                        Vela_recovery_policy.Driver.t_RedemptionEvent)
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io, restore_done <: (bool & v_Io & bool)), transition
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition))
              | Vela_recovery_policy.Driver.RedemptionEffect_Insert permit ->
                let
                (tmp0: v_Io),
                (out: Core_models.Option.t_Option Vela_recovery_policy.Driver.t_InsertObservation) =
                  f_insert_device #v_Io #FStar.Tactics.Typeclasses.solve io permit
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option Vela_recovery_policy.Driver.t_InsertObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io, restore_done <: (bool & v_Io & bool)),
                    Vela_recovery_policy.Driver.step transition.Vela_recovery_policy.Driver.f_driver
                      (Vela_recovery_policy.Driver.RedemptionEvent_Insert observation
                        <:
                        Vela_recovery_policy.Driver.t_RedemptionEvent)
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io, restore_done <: (bool & v_Io & bool)), transition
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition))
              | Vela_recovery_policy.Driver.RedemptionEffect_Recheck  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Driver.t_AuthorityRecheckObservation) =
                  f_recheck_authority #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io, restore_done <: (bool & v_Io & bool)),
                    Vela_recovery_policy.Driver.step transition.Vela_recovery_policy.Driver.f_driver
                      (Vela_recovery_policy.Driver.RedemptionEvent_Recheck observation
                        <:
                        Vela_recovery_policy.Driver.t_RedemptionEvent)
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io, restore_done <: (bool & v_Io & bool)), transition
                    <:
                    ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition))
              | Vela_recovery_policy.Driver.RedemptionEffect_RestoreAndFail _ ->
                let (tmp0: v_Io), (out: Core_models.Option.t_Option Prims.unit) =
                  f_restore_grant #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                let (aborted: bool), (restore_done: bool) =
                  match out <: Core_models.Option.t_Option Prims.unit with
                  | Core_models.Option.Option_Some _ -> aborted, true <: (bool & bool)
                  | Core_models.Option.Option_None  -> true, restore_done <: (bool & bool)
                in
                (aborted, io, restore_done <: (bool & v_Io & bool)), transition
                <:
                ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition)
              | Vela_recovery_policy.Driver.RedemptionEffect_Complete
              | Vela_recovery_policy.Driver.RedemptionEffect_Fail _
              | Vela_recovery_policy.Driver.RedemptionEffect_Idle  ->
                (aborted, io, restore_done <: (bool & v_Io & bool)), transition
                <:
                ((bool & v_Io & bool) & Vela_recovery_policy.Driver.t_RedemptionTransition)
            in
            let transition:Vela_recovery_policy.Driver.t_RedemptionTransition = hoist6 in
            aborted, io, restore_done, transition
            <:
            (bool & v_Io & bool & Vela_recovery_policy.Driver.t_RedemptionTransition)
          else
            aborted, io, restore_done, transition
            <:
            (bool & v_Io & bool & Vela_recovery_policy.Driver.t_RedemptionTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option Vela_recovery_policy.Driver.t_RedemptionTransition
  =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Driver.t_RedemptionTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Driver.t_RedemptionTransition
  in
  io, hax_temp_output
  <:
  (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Driver.t_RedemptionTransition)
