module Vela_session_policy_deletion_interpreter_lemmas

/// The extracted `run_deletion` is the loop `DELETE /account` runs: the server
/// expands the same `deletion_interpreter!` macro text, adding only `.await`
/// after each executor call. This module proves, for every executor
/// implementation (any `t_DeletionIo` instance, any behaviour):
///
/// 1. `run_deletion` calls the executor exactly as `run_ev` below does: one
///    method per turn, chosen by the effect the driver has just emitted, with
///    that effect's arguments, and nothing once the driver reached a verdict
///    (`run_deletion_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_actor actor evs` (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of 14 turns
///    (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request deletion theorem holds for the state the real
///    handler ends in (`run_deletion_theorem`).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_session_policy.Deletion_driver
open Vela_session_policy.Deletion_interpreter
open Vela_session_policy_deletion_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_DeletionEffect) : bool =
  match e with
  | DeletionEffect_Complete | DeletionEffect_Fail _ | DeletionEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_DeletionEffect) (ev: t_DeletionEvent) : bool =
  match e, ev with
  | DeletionEffect_ScanDevices, DeletionEvent_DevicesScanned _
  | DeletionEffect_LockoutDevices, DeletionEvent_DeviceLockout _
  | DeletionEffect_ScanWebSessions, DeletionEvent_WebSessionsScanned _
  | DeletionEffect_LockoutWebSessions, DeletionEvent_WebSessionLockout _
  | DeletionEffect_BeginTransaction, DeletionEvent_Transaction _
  | DeletionEffect_DeleteTable _, DeletionEvent_TableDeleted _
  | DeletionEffect_DeleteUsers, DeletionEvent_UsersDeleted _
  | DeletionEffect_CommitTransaction, DeletionEvent_Commit _ -> true
  | _ -> false

let sound_transition (t: t_DeletionTransition) : bool =
  deletion_state_is_sound t.f_driver && deletion_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_DeletionIo io_t |} (s: io_t) (t: t_DeletionTransition)
  : Pure (io_t & t_DeletionTransition & option t_DeletionEvent)
    (requires deletion_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | DeletionEffect_ScanDevices ->
      let (s', o) = f_scan_devices #io_t #i s in
      let ev = DeletionEvent_DevicesScanned o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_LockoutDevices ->
      let (s', o) = f_lockout_devices #io_t #i s in
      let ev = DeletionEvent_DeviceLockout o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_ScanWebSessions ->
      let (s', o) = f_scan_web_sessions #io_t #i s in
      let ev = DeletionEvent_WebSessionsScanned o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_LockoutWebSessions ->
      let (s', o) = f_lockout_web_sessions #io_t #i s in
      let ev = DeletionEvent_WebSessionLockout o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_BeginTransaction ->
      let (s', o) = f_begin_transaction #io_t #i s in
      let ev = DeletionEvent_Transaction o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_DeleteTable table ->
      let (s', o) = f_delete_table #io_t #i s table in
      let ev = DeletionEvent_TableDeleted o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_DeleteUsers ->
      let (s', o) = f_delete_users #io_t #i s in
      let ev = DeletionEvent_UsersDeleted o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_CommitTransaction ->
      let (s', o) = f_commit #io_t #i s in
      let ev = DeletionEvent_Commit o in
      (s', step t.f_driver ev, Some ev)
  | DeletionEffect_Complete | DeletionEffect_Fail _ | DeletionEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the
/// extracted loop body.
let turn (#io_t: Type0) {| i: t_DeletionIo io_t |} (acc: io_t & t_DeletionTransition)
  : (io_t & t_DeletionTransition) =
  let (s, t) = acc in
  if deletion_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_DeletionIo io_t |} (n: nat)
  (acc: io_t & t_DeletionTransition)
  : Tot (io_t & t_DeletionTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_DeletionEvent) (evs: list t_DeletionEvent) : list t_DeletionEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_DeletionIo io_t |} (n: nat) (s: io_t)
  (t: t_DeletionTransition)
  : Pure (io_t & t_DeletionTransition & list t_DeletionEvent)
    (requires sound_transition t)
    (ensures fun (_, t', _) -> sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = turn_ev #io_t #i s t in
    let (s2, t2, evs) = run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

// ── 1. The extracted loop is `run_ev` ─────────────────────────────────────

/// `fold_range` over a body that is one `turn` per index is `iter_turn`. The
/// two patterns fire together when a goal mentions both the extracted loop and
/// the specification, which binds every variable including the instance.
let rec fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_DeletionIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_DeletionTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_DeletionTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_DeletionTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_DeletionTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_DeletionTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (iter_turn #io_t #i n init)] =
  if v start < v end_
  then fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_DeletionIo io_t |} (n: nat) (s: io_t)
  (t: t_DeletionTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (s2, t2, _) = run_ev #io_t #i n s t in
                    iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = turn_ev #io_t #i s t in
    iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

/// The extracted loop calls the executor exactly as `run_ev` does.
let run_deletion_is_run_ev (#io_t: Type0) {| i: t_DeletionIo io_t |} (s: io_t)
  (actor: t_DeletionActorObservation)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 14 s (begin_deletion actor) in
           run_deletion #io_t #i s actor == (s2, t2)) =
  let t0 = begin_deletion actor in
  iter_turn_is_run_ev #io_t #i 14 s t0;
  assert (v v_DELETION_MAX_EFFECTS = 14);
  assert (run_deletion #io_t #i s actor == iter_turn #io_t #i 14 (s, t0))

// ── 1b. Cancellation: every prefix is a sound driver state ────────────────

/// The handler is async: if the client disconnects, the handler future is
/// dropped after any executor call and the loop stops after an arbitrary
/// prefix of turns. For every executor, every budget `k` and every sound start
/// transition, the state after `k` turns is still sound. `sound_transition`
/// conjoins `deletion_state_is_sound` (which carries the per-request state
/// invariants: a committed delete implies the `users` delete and a started
/// transaction, a response implies a commit, and a failure never claims a
/// commit) and `deletion_effect_is_sound` (the next effect agrees with the
/// state that produced it).
let cancellation (#io_t: Type0) {| i: t_DeletionIo io_t |} (k: nat) (s: io_t)
  (t: t_DeletionTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in sound_transition t2)) =
  let (_, t2, _) = run_ev #io_t #i k s t in
  iter_turn_is_run_ev #io_t #i k s t

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_DeletionTransition) (evs: list t_DeletionEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_DeletionIo io_t |} (n: nat) (s: io_t)
  (t: t_DeletionTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2, evs) = run_ev #io_t #i n s t in
                    trace_sound t.f_driver /\
                    responds t evs /\
                    t2.f_driver == run t.f_driver evs))
          (decreases n) =
  trace_sound_matches_rust t.f_driver;
  if n = 0 then ()
  else begin
    let (s1, t1, o) = turn_ev #io_t #i s t in
    run_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> step_sound t.f_driver ev
  end

// ── 3. A verdict within the budget ────────────────────────────────────────

/// Position of a table in the fixed deletion order.
let table_position (table: t_DeletionTable) : nat =
  match table with
  | DeletionTable_WebSessions -> 0
  | DeletionTable_ShareInbox -> 1
  | DeletionTable_SharedItems -> 2
  | DeletionTable_Sends -> 3
  | DeletionTable_VaultChunks -> 4
  | DeletionTable_OramBuckets -> 5
  | DeletionTable_Devices -> 6

/// Effects still to perform before a verdict, at most.
let remaining (e: t_DeletionEffect) : nat =
  match e with
  | DeletionEffect_ScanDevices -> 14
  | DeletionEffect_LockoutDevices -> 13
  | DeletionEffect_ScanWebSessions -> 12
  | DeletionEffect_LockoutWebSessions -> 11
  | DeletionEffect_BeginTransaction -> 10
  | DeletionEffect_DeleteTable table -> 9 - table_position table
  | DeletionEffect_DeleteUsers -> 2
  | DeletionEffect_CommitTransaction -> 1
  | DeletionEffect_Complete | DeletionEffect_Fail _ | DeletionEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_DeletionTransition) (ev: t_DeletionEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect with
  | DeletionEffect_DeleteTable _ -> ()
  | _ -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_DeletionIo io_t |} (n: nat) (s: io_t)
  (t: t_DeletionTransition)
  : Lemma (requires sound_transition t /\ remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = run_ev #io_t #i n s t in terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> step_decreases t ev);
    run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

// ── 4. The handler's final state satisfies the per-request theorems ───────

let run_deletion_theorem (#io_t: Type0) {| i: t_DeletionIo io_t |} (s: io_t)
  (actor: t_DeletionActorObservation)
  : Lemma (
      let (_, t) = run_deletion #io_t #i s actor in
      exists (evs: list t_DeletionEvent).
        responds (begin_deletion actor) evs /\
        t.f_driver == run_from_actor actor evs /\
        terminal t.f_effect /\
        deletion_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         (d.f_responded ==> (d.f_committed && d.f_users_deleted && d.f_transaction_started)) /\
         (d.f_committed ==> (d.f_users_deleted && d.f_transaction_started)) /\
         not (d.f_responded && d.f_failed) /\
         (not d.f_failed || not d.f_committed))) =
  let t0 = begin_deletion actor in
  run_deletion_is_run_ev #io_t #i s actor;
  run_ev_follows_the_driver #io_t #i 14 s t0;
  run_ev_reaches_a_verdict #io_t #i 14 s t0;
  let (_, t2, evs) = run_ev #io_t #i 14 s t0 in
  deletion_trace_theorem actor evs
