module Vela_share_policy.Send_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one fetch performs: consume, read, cleanup. Create and delete
/// perform one effect each.
let v_SEND_MAX_EFFECTS: usize = mk_usize 3

/// The driver has decided: nothing more may be performed.
let send_effect_is_terminal (v_effect: Vela_share_policy.Send_driver.t_SendEffect) : bool =
  match v_effect <: Vela_share_policy.Send_driver.t_SendEffect with
  | Vela_share_policy.Send_driver.SendEffect_CompleteCreate
  | Vela_share_policy.Send_driver.SendEffect_CompleteFetch
  | Vela_share_policy.Send_driver.SendEffect_CompleteDelete
    { Vela_share_policy.Send_driver.f_deleted = _ }
  | Vela_share_policy.Send_driver.SendEffect_Fail _
  | Vela_share_policy.Send_driver.SendEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects; the handler keeps the original error in
/// its own slot.
class t_SendIo (v_Self: Type0) = {
  f_insert_send_pre:self_: v_Self -> permit: Vela_share_policy.Send_driver.t_CreatePermit
    -> pred: Type0{true ==> pred};
  f_insert_send_post:
      v_Self ->
      Vela_share_policy.Send_driver.t_CreatePermit ->
      (v_Self & Vela_share_policy.Send_driver.t_RowsObservation)
    -> Type0;
  f_insert_send:x0: v_Self -> x1: Vela_share_policy.Send_driver.t_CreatePermit
    -> Prims.Pure (v_Self & Vela_share_policy.Send_driver.t_RowsObservation)
        (f_insert_send_pre x0 x1)
        (fun result -> f_insert_send_post x0 x1 result);
  f_consume_view_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_consume_view_post:v_Self -> (v_Self & Vela_share_policy.Send_driver.t_ConsumeObservation)
    -> Type0;
  f_consume_view:x0: v_Self
    -> Prims.Pure (v_Self & Vela_share_policy.Send_driver.t_ConsumeObservation)
        (f_consume_view_pre x0)
        (fun result -> f_consume_view_post x0 result);
  f_read_send_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_read_send_post:v_Self -> (v_Self & Vela_share_policy.Send_driver.t_ReadObservation) -> Type0;
  f_read_send:x0: v_Self
    -> Prims.Pure (v_Self & Vela_share_policy.Send_driver.t_ReadObservation)
        (f_read_send_pre x0)
        (fun result -> f_read_send_post x0 result);
  f_remove_fetched_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_remove_fetched_post:v_Self -> (v_Self & Vela_share_policy.Send_driver.t_RemoveObservation)
    -> Type0;
  f_remove_fetched:x0: v_Self
    -> Prims.Pure (v_Self & Vela_share_policy.Send_driver.t_RemoveObservation)
        (f_remove_fetched_pre x0)
        (fun result -> f_remove_fetched_post x0 result);
  f_delete_link_pre:self_: v_Self -> permit: Vela_share_policy.Send_driver.t_DeletePermit
    -> pred: Type0{true ==> pred};
  f_delete_link_post:
      v_Self ->
      Vela_share_policy.Send_driver.t_DeletePermit ->
      (v_Self & Vela_share_policy.Send_driver.t_RowsObservation)
    -> Type0;
  f_delete_link:x0: v_Self -> x1: Vela_share_policy.Send_driver.t_DeletePermit
    -> Prims.Pure (v_Self & Vela_share_policy.Send_driver.t_RowsObservation)
        (f_delete_link_pre x0 x1)
        (fun result -> f_delete_link_post x0 x1 result)
}

/// The synchronous expansion of [`send_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_send
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_SendIo v_Io)
      (io: v_Io)
      (start: Vela_share_policy.Send_driver.t_SendTransition)
    : Prims.Pure (v_Io & Vela_share_policy.Send_driver.t_SendTransition)
      (requires
        Vela_share_policy.Send_driver.send_state_is_sound start
            .Vela_share_policy.Send_driver.f_driver)
      (fun _ -> Prims.l_True) =
  let transition:Vela_share_policy.Send_driver.t_SendTransition = start in
  let (io: v_Io), (transition: Vela_share_policy.Send_driver.t_SendTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_SEND_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_share_policy.Send_driver.t_SendTransition) = temp_0_ in
          let _:usize = temp_1_ in
          Vela_share_policy.Send_driver.send_state_is_sound transition
              .Vela_share_policy.Send_driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_share_policy.Send_driver.t_SendTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_share_policy.Send_driver.t_SendTransition) = temp_0_ in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist19: Vela_share_policy.Send_driver.t_SendTransition) =
            match
              transition.Vela_share_policy.Send_driver.f_effect
              <:
              Vela_share_policy.Send_driver.t_SendEffect
            with
            | Vela_share_policy.Send_driver.SendEffect_InsertSend permit ->
              let (tmp0: v_Io), (out: Vela_share_policy.Send_driver.t_RowsObservation) =
                f_insert_send #v_Io #FStar.Tactics.Typeclasses.solve io permit
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Send_driver.step transition.Vela_share_policy.Send_driver.f_driver
                (Vela_share_policy.Send_driver.SendEvent_SendInserted out
                  <:
                  Vela_share_policy.Send_driver.t_SendEvent)
              <:
              (v_Io & Vela_share_policy.Send_driver.t_SendTransition)
            | Vela_share_policy.Send_driver.SendEffect_ConsumeView  ->
              let (tmp0: v_Io), (out: Vela_share_policy.Send_driver.t_ConsumeObservation) =
                f_consume_view #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Send_driver.step transition.Vela_share_policy.Send_driver.f_driver
                (Vela_share_policy.Send_driver.SendEvent_ViewConsumed out
                  <:
                  Vela_share_policy.Send_driver.t_SendEvent)
              <:
              (v_Io & Vela_share_policy.Send_driver.t_SendTransition)
            | Vela_share_policy.Send_driver.SendEffect_ReadSend  ->
              let (tmp0: v_Io), (out: Vela_share_policy.Send_driver.t_ReadObservation) =
                f_read_send #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Send_driver.step transition.Vela_share_policy.Send_driver.f_driver
                (Vela_share_policy.Send_driver.SendEvent_SendRead out
                  <:
                  Vela_share_policy.Send_driver.t_SendEvent)
              <:
              (v_Io & Vela_share_policy.Send_driver.t_SendTransition)
            | Vela_share_policy.Send_driver.SendEffect_RemoveFetched  ->
              let (tmp0: v_Io), (out: Vela_share_policy.Send_driver.t_RemoveObservation) =
                f_remove_fetched #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Send_driver.step transition.Vela_share_policy.Send_driver.f_driver
                (Vela_share_policy.Send_driver.SendEvent_SendRemoved out
                  <:
                  Vela_share_policy.Send_driver.t_SendEvent)
              <:
              (v_Io & Vela_share_policy.Send_driver.t_SendTransition)
            | Vela_share_policy.Send_driver.SendEffect_DeleteLink permit ->
              let (tmp0: v_Io), (out: Vela_share_policy.Send_driver.t_RowsObservation) =
                f_delete_link #v_Io #FStar.Tactics.Typeclasses.solve io permit
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Send_driver.step transition.Vela_share_policy.Send_driver.f_driver
                (Vela_share_policy.Send_driver.SendEvent_SendDeleted out
                  <:
                  Vela_share_policy.Send_driver.t_SendEvent)
              <:
              (v_Io & Vela_share_policy.Send_driver.t_SendTransition)
            | Vela_share_policy.Send_driver.SendEffect_CompleteCreate
            | Vela_share_policy.Send_driver.SendEffect_CompleteFetch
            | Vela_share_policy.Send_driver.SendEffect_CompleteDelete
              { Vela_share_policy.Send_driver.f_deleted = _ }
            | Vela_share_policy.Send_driver.SendEffect_Fail _
            | Vela_share_policy.Send_driver.SendEffect_Idle  ->
              io, transition <: (v_Io & Vela_share_policy.Send_driver.t_SendTransition)
          in
          let transition:Vela_share_policy.Send_driver.t_SendTransition = hoist19 in
          io, transition <: (v_Io & Vela_share_policy.Send_driver.t_SendTransition))
  in
  let hax_temp_output:Vela_share_policy.Send_driver.t_SendTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_share_policy.Send_driver.t_SendTransition)

let start_create (observation: Vela_share_policy.Send_driver.t_CreateObservation)
    : Vela_share_policy.Send_driver.t_SendTransition =
  Vela_share_policy.Send_driver.begin_create observation

let start_fetch (_: Prims.unit) : Vela_share_policy.Send_driver.t_SendTransition =
  Vela_share_policy.Send_driver.begin_fetch ()

let start_delete (owner_present: bool) : Vela_share_policy.Send_driver.t_SendTransition =
  Vela_share_policy.Send_driver.begin_delete owner_present
