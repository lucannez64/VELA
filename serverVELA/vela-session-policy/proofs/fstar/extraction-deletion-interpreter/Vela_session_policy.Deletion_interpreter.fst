module Vela_session_policy.Deletion_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one request performs: two scans, two lockouts, the transaction
/// begin, seven table deletes, the `users` delete and the commit.
let v_DELETION_MAX_EFFECTS: usize = mk_usize 14

/// The driver has decided: nothing more may be performed.
let deletion_effect_is_terminal (v_effect: Vela_session_policy.Deletion_driver.t_DeletionEffect)
    : bool =
  match v_effect <: Vela_session_policy.Deletion_driver.t_DeletionEffect with
  | Vela_session_policy.Deletion_driver.DeletionEffect_Complete
  | Vela_session_policy.Deletion_driver.DeletionEffect_Fail _
  | Vela_session_policy.Deletion_driver.DeletionEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects.
class t_DeletionIo (v_Self: Type0) = {
  f_scan_devices_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_scan_devices_post:v_Self -> (v_Self & Vela_session_policy.Deletion_driver.t_ScanObservation)
    -> Type0;
  f_scan_devices:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_ScanObservation)
        (f_scan_devices_pre x0)
        (fun result -> f_scan_devices_post x0 result);
  f_lockout_devices_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_lockout_devices_post:
      v_Self ->
      (v_Self & Vela_session_policy.Deletion_driver.t_LockoutObservation)
    -> Type0;
  f_lockout_devices:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_LockoutObservation)
        (f_lockout_devices_pre x0)
        (fun result -> f_lockout_devices_post x0 result);
  f_scan_web_sessions_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_scan_web_sessions_post:
      v_Self ->
      (v_Self & Vela_session_policy.Deletion_driver.t_ScanObservation)
    -> Type0;
  f_scan_web_sessions:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_ScanObservation)
        (f_scan_web_sessions_pre x0)
        (fun result -> f_scan_web_sessions_post x0 result);
  f_lockout_web_sessions_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_lockout_web_sessions_post:
      v_Self ->
      (v_Self & Vela_session_policy.Deletion_driver.t_LockoutObservation)
    -> Type0;
  f_lockout_web_sessions:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_LockoutObservation)
        (f_lockout_web_sessions_pre x0)
        (fun result -> f_lockout_web_sessions_post x0 result);
  f_begin_transaction_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_begin_transaction_post:
      v_Self ->
      (v_Self & Vela_session_policy.Deletion_driver.t_TransactionObservation)
    -> Type0;
  f_begin_transaction:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_TransactionObservation)
        (f_begin_transaction_pre x0)
        (fun result -> f_begin_transaction_post x0 result);
  f_delete_table_pre:self_: v_Self -> table: Vela_session_policy.Deletion_driver.t_DeletionTable
    -> pred: Type0{true ==> pred};
  f_delete_table_post:
      v_Self ->
      Vela_session_policy.Deletion_driver.t_DeletionTable ->
      (v_Self & Vela_session_policy.Deletion_driver.t_TableDeleteObservation)
    -> Type0;
  f_delete_table:x0: v_Self -> x1: Vela_session_policy.Deletion_driver.t_DeletionTable
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_TableDeleteObservation)
        (f_delete_table_pre x0 x1)
        (fun result -> f_delete_table_post x0 x1 result);
  f_delete_users_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_delete_users_post:
      v_Self ->
      (v_Self & Vela_session_policy.Deletion_driver.t_UsersDeleteObservation)
    -> Type0;
  f_delete_users:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_UsersDeleteObservation)
        (f_delete_users_pre x0)
        (fun result -> f_delete_users_post x0 result);
  f_commit_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_commit_post:v_Self -> (v_Self & Vela_session_policy.Deletion_driver.t_CommitObservation)
    -> Type0;
  f_commit:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Deletion_driver.t_CommitObservation)
        (f_commit_pre x0)
        (fun result -> f_commit_post x0 result)
}

/// The synchronous expansion of [`deletion_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_deletion
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DeletionIo v_Io)
      (io: v_Io)
      (actor: Vela_session_policy.Deletion_driver.t_DeletionActorObservation)
    : (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition) =
  let transition:Vela_session_policy.Deletion_driver.t_DeletionTransition =
    Vela_session_policy.Deletion_driver.begin_deletion actor
  in
  let (io: v_Io), (transition: Vela_session_policy.Deletion_driver.t_DeletionTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_DELETION_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Deletion_driver.t_DeletionTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Deletion_driver.deletion_state_is_sound transition
              .Vela_session_policy.Deletion_driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Deletion_driver.t_DeletionTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist17: Vela_session_policy.Deletion_driver.t_DeletionTransition) =
            match
              transition.Vela_session_policy.Deletion_driver.f_effect
              <:
              Vela_session_policy.Deletion_driver.t_DeletionEffect
            with
            | Vela_session_policy.Deletion_driver.DeletionEffect_ScanDevices  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_ScanObservation) =
                f_scan_devices #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_DevicesScanned out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_LockoutDevices  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_LockoutObservation) =
                f_lockout_devices #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_DeviceLockout out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_ScanWebSessions  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_ScanObservation) =
                f_scan_web_sessions #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_WebSessionsScanned out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_LockoutWebSessions  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_LockoutObservation) =
                f_lockout_web_sessions #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_WebSessionLockout out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_BeginTransaction  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_TransactionObservation)
              =
                f_begin_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_Transaction out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_DeleteTable table ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_TableDeleteObservation)
              =
                f_delete_table #v_Io #FStar.Tactics.Typeclasses.solve io table
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_TableDeleted out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_DeleteUsers  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_UsersDeleteObservation)
              =
                f_delete_users #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_UsersDeleted out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_CommitTransaction  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Deletion_driver.t_CommitObservation) =
                f_commit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Deletion_driver.step transition
                  .Vela_session_policy.Deletion_driver.f_driver
                (Vela_session_policy.Deletion_driver.DeletionEvent_Commit out
                  <:
                  Vela_session_policy.Deletion_driver.t_DeletionEvent)
              <:
              (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
            | Vela_session_policy.Deletion_driver.DeletionEffect_Complete
            | Vela_session_policy.Deletion_driver.DeletionEffect_Fail _
            | Vela_session_policy.Deletion_driver.DeletionEffect_Idle  ->
              io, transition <: (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
          in
          let transition:Vela_session_policy.Deletion_driver.t_DeletionTransition = hoist17 in
          io, transition <: (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition))
  in
  let hax_temp_output:Vela_session_policy.Deletion_driver.t_DeletionTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Deletion_driver.t_DeletionTransition)
