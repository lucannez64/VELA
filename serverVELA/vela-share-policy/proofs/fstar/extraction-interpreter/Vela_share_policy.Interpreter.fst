module Vela_share_policy.Interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one request performs: observe the linked row, revoke it and
/// clean up its pending inbox row.
let v_SHARE_MAX_EFFECTS: usize = mk_usize 3

/// The driver has decided: nothing more may be performed.
let share_effect_is_terminal (v_effect: Vela_share_policy.Driver.t_ShareEffect) : bool =
  match v_effect <: Vela_share_policy.Driver.t_ShareEffect with
  | Vela_share_policy.Driver.ShareEffect_Complete
  | Vela_share_policy.Driver.ShareEffect_Fail _
  | Vela_share_policy.Driver.ShareEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects.
class t_ShareIo (v_Self: Type0) = {
  f_observe_link_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_observe_link_post:v_Self -> (v_Self & Vela_share_policy.t_LinkMutationObservation) -> Type0;
  f_observe_link:x0: v_Self
    -> Prims.Pure (v_Self & Vela_share_policy.t_LinkMutationObservation)
        (f_observe_link_pre x0)
        (fun result -> f_observe_link_post x0 result);
  f_observe_device_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_observe_device_post:v_Self -> (v_Self & Vela_share_policy.Driver.t_EkDeviceObservation) -> Type0;
  f_observe_device:x0: v_Self
    -> Prims.Pure (v_Self & Vela_share_policy.Driver.t_EkDeviceObservation)
        (f_observe_device_pre x0)
        (fun result -> f_observe_device_post x0 result);
  f_insert_capsule_pre:self_: v_Self -> permit: Vela_share_policy.Driver.t_SendInsertPermit
    -> pred: Type0{true ==> pred};
  f_insert_capsule_post:
      v_Self ->
      Vela_share_policy.Driver.t_SendInsertPermit ->
      (v_Self & Vela_share_policy.Driver.t_SendResultObservation)
    -> Type0;
  f_insert_capsule:x0: v_Self -> x1: Vela_share_policy.Driver.t_SendInsertPermit
    -> Prims.Pure (v_Self & Vela_share_policy.Driver.t_SendResultObservation)
        (f_insert_capsule_pre x0 x1)
        (fun result -> f_insert_capsule_post x0 x1 result);
  f_update_linked_item_pre:self_: v_Self -> permit: Vela_share_policy.Driver.t_LinkUpdatePermit
    -> pred: Type0{true ==> pred};
  f_update_linked_item_post:
      v_Self ->
      Vela_share_policy.Driver.t_LinkUpdatePermit ->
      (v_Self & Vela_share_policy.Driver.t_RowsObservation)
    -> Type0;
  f_update_linked_item:x0: v_Self -> x1: Vela_share_policy.Driver.t_LinkUpdatePermit
    -> Prims.Pure (v_Self & Vela_share_policy.Driver.t_RowsObservation)
        (f_update_linked_item_pre x0 x1)
        (fun result -> f_update_linked_item_post x0 x1 result);
  f_revoke_linked_item_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_revoke_linked_item_post:v_Self -> (v_Self & Vela_share_policy.Driver.t_RowsObservation) -> Type0;
  f_revoke_linked_item:x0: v_Self
    -> Prims.Pure (v_Self & Vela_share_policy.Driver.t_RowsObservation)
        (f_revoke_linked_item_pre x0)
        (fun result -> f_revoke_linked_item_post x0 result);
  f_delete_linked_inbox_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_delete_linked_inbox_post:v_Self -> (v_Self & Vela_share_policy.Driver.t_CleanupObservation)
    -> Type0;
  f_delete_linked_inbox:x0: v_Self
    -> Prims.Pure (v_Self & Vela_share_policy.Driver.t_CleanupObservation)
        (f_delete_linked_inbox_pre x0)
        (fun result -> f_delete_linked_inbox_post x0 result);
  f_delete_inbox_item_pre:self_: v_Self -> permit: Vela_share_policy.Driver.t_InboxDeletePermit
    -> pred: Type0{true ==> pred};
  f_delete_inbox_item_post:
      v_Self ->
      Vela_share_policy.Driver.t_InboxDeletePermit ->
      (v_Self & Vela_share_policy.Driver.t_RowsObservation)
    -> Type0;
  f_delete_inbox_item:x0: v_Self -> x1: Vela_share_policy.Driver.t_InboxDeletePermit
    -> Prims.Pure (v_Self & Vela_share_policy.Driver.t_RowsObservation)
        (f_delete_inbox_item_pre x0 x1)
        (fun result -> f_delete_inbox_item_post x0 x1 result);
  f_update_share_ek_pre:self_: v_Self -> permit: Vela_share_policy.t_EkRegistrationPermit
    -> pred: Type0{true ==> pred};
  f_update_share_ek_post:
      v_Self ->
      Vela_share_policy.t_EkRegistrationPermit ->
      (v_Self & Vela_share_policy.Driver.t_RowsObservation)
    -> Type0;
  f_update_share_ek:x0: v_Self -> x1: Vela_share_policy.t_EkRegistrationPermit
    -> Prims.Pure (v_Self & Vela_share_policy.Driver.t_RowsObservation)
        (f_update_share_ek_pre x0 x1)
        (fun result -> f_update_share_ek_post x0 x1 result)
}

/// The synchronous expansion of [`share_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_share
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_ShareIo v_Io)
      (io: v_Io)
      (start: Vela_share_policy.Driver.t_ShareTransition)
    : Prims.Pure (v_Io & Vela_share_policy.Driver.t_ShareTransition)
      (requires
        Vela_share_policy.Driver.share_state_is_sound start.Vela_share_policy.Driver.f_driver)
      (fun _ -> Prims.l_True) =
  let transition:Vela_share_policy.Driver.t_ShareTransition = start in
  let (io: v_Io), (transition: Vela_share_policy.Driver.t_ShareTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_SHARE_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_share_policy.Driver.t_ShareTransition) = temp_0_ in
          let _:usize = temp_1_ in
          Vela_share_policy.Driver.share_state_is_sound transition.Vela_share_policy.Driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_share_policy.Driver.t_ShareTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_share_policy.Driver.t_ShareTransition) = temp_0_ in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist30: Vela_share_policy.Driver.t_ShareTransition) =
            match
              transition.Vela_share_policy.Driver.f_effect <: Vela_share_policy.Driver.t_ShareEffect
            with
            | Vela_share_policy.Driver.ShareEffect_ObserveLink  ->
              let (tmp0: v_Io), (out: Vela_share_policy.t_LinkMutationObservation) =
                f_observe_link #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_LinkObserved out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_ObserveDevice  ->
              let (tmp0: v_Io), (out: Vela_share_policy.Driver.t_EkDeviceObservation) =
                f_observe_device #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_EkObserved out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_InsertCapsule permit ->
              let (tmp0: v_Io), (out: Vela_share_policy.Driver.t_SendResultObservation) =
                f_insert_capsule #v_Io #FStar.Tactics.Typeclasses.solve io permit
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_SendResult out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_UpdateLinkedItem permit ->
              let (tmp0: v_Io), (out: Vela_share_policy.Driver.t_RowsObservation) =
                f_update_linked_item #v_Io #FStar.Tactics.Typeclasses.solve io permit
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_Mutated out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_RevokeLinkedItem  ->
              let (tmp0: v_Io), (out: Vela_share_policy.Driver.t_RowsObservation) =
                f_revoke_linked_item #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_Mutated out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_DeleteLinkedInbox  ->
              let (tmp0: v_Io), (out: Vela_share_policy.Driver.t_CleanupObservation) =
                f_delete_linked_inbox #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_Cleaned out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_DeleteInboxItem permit ->
              let (tmp0: v_Io), (out: Vela_share_policy.Driver.t_RowsObservation) =
                f_delete_inbox_item #v_Io #FStar.Tactics.Typeclasses.solve io permit
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_Mutated out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_UpdateShareEk permit ->
              let (tmp0: v_Io), (out: Vela_share_policy.Driver.t_RowsObservation) =
                f_update_share_ek #v_Io #FStar.Tactics.Typeclasses.solve io permit
              in
              let io:v_Io = tmp0 in
              io,
              Vela_share_policy.Driver.step transition.Vela_share_policy.Driver.f_driver
                (Vela_share_policy.Driver.ShareEvent_Mutated out
                  <:
                  Vela_share_policy.Driver.t_ShareEvent)
              <:
              (v_Io & Vela_share_policy.Driver.t_ShareTransition)
            | Vela_share_policy.Driver.ShareEffect_Complete
            | Vela_share_policy.Driver.ShareEffect_Fail _
            | Vela_share_policy.Driver.ShareEffect_Idle  ->
              io, transition <: (v_Io & Vela_share_policy.Driver.t_ShareTransition)
          in
          let transition:Vela_share_policy.Driver.t_ShareTransition = hoist30 in
          io, transition <: (v_Io & Vela_share_policy.Driver.t_ShareTransition))
  in
  let hax_temp_output:Vela_share_policy.Driver.t_ShareTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_share_policy.Driver.t_ShareTransition)

let start_send (observation: Vela_share_policy.Driver.t_SendRequestObservation)
    : Vela_share_policy.Driver.t_ShareTransition = Vela_share_policy.Driver.begin_send observation

let start_link_update (observation: Vela_share_policy.Driver.t_LinkUpdateStartObservation)
    : Vela_share_policy.Driver.t_ShareTransition =
  Vela_share_policy.Driver.begin_link_update observation

let start_link_revoke (_: Prims.unit) : Vela_share_policy.Driver.t_ShareTransition =
  Vela_share_policy.Driver.begin_link_revoke ()

let start_inbox_delete (_: Prims.unit) : Vela_share_policy.Driver.t_ShareTransition =
  Vela_share_policy.Driver.begin_inbox_delete ()

let start_ek_registration (observation: Vela_share_policy.Driver.t_EkRegistrationStartObservation)
    : Vela_share_policy.Driver.t_ShareTransition =
  Vela_share_policy.Driver.begin_ek_registration observation
