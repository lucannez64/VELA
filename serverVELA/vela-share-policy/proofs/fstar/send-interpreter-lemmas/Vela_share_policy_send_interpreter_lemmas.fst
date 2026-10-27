module Vela_share_policy_send_interpreter_lemmas

/// The extracted `run_send` is the loop the one-off share-link handlers run:
/// each server handler expands the same `send_interpreter!` macro text, adding
/// only `.await` after each executor call. This module proves, for every
/// executor implementation (any `t_SendIo` instance, any behaviour):
///
/// 1. `run_send` calls the executor exactly as `run_ev` below does: one method
///    per turn, chosen by the effect the driver has just emitted, with that
///    effect's argument, and nothing once the driver reached a verdict
///    (`run_send_is_run_ev`);
/// 2. the observations the executor returned form a list in which each
///    observation answers the effect it was returned for, and the final driver
///    is the extracted driver's `run_from_*` over that list
///    (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of 3 turns
///    (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request send theorem holds for the state the real
///    handler ends in (the corollaries at the end), and the extracted
///    composition module covers concurrent create/fetch/delete interleavings.
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copies differ only by `.await`).

open FStar.Mul
open Core_models
open Vela_share_policy
open Vela_share_policy.Send_driver
open Vela_share_policy.Send_interpreter
open Vela_share_policy_send_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_SendEffect) : bool =
  match e <: t_SendEffect with
  | SendEffect_CompleteCreate | SendEffect_CompleteFetch
  | SendEffect_CompleteDelete _ | SendEffect_Fail _ | SendEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_SendEffect) (ev: t_SendEvent) : bool =
  match e, ev with
  | SendEffect_InsertSend _, SendEvent_SendInserted _
  | SendEffect_ConsumeView, SendEvent_ViewConsumed _
  | SendEffect_ReadSend, SendEvent_SendRead _
  | SendEffect_RemoveFetched, SendEvent_SendRemoved _
  | SendEffect_DeleteLink _, SendEvent_SendDeleted _ -> true
  | _ -> false

let sound_transition (t: t_SendTransition) : bool =
  send_state_is_sound t.f_driver && send_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_SendIo io_t |} (s: io_t) (t: t_SendTransition)
  : Pure (io_t & t_SendTransition & option t_SendEvent)
    (requires send_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect <: t_SendEffect with
  | SendEffect_InsertSend permit ->
      let (s', o) = f_insert_send #io_t #i s permit in
      let ev = SendEvent_SendInserted o in
      (s', step t.f_driver ev, Some ev)
  | SendEffect_ConsumeView ->
      let (s', o) = f_consume_view #io_t #i s in
      let ev = SendEvent_ViewConsumed o in
      (s', step t.f_driver ev, Some ev)
  | SendEffect_ReadSend ->
      let (s', o) = f_read_send #io_t #i s in
      let ev = SendEvent_SendRead o in
      (s', step t.f_driver ev, Some ev)
  | SendEffect_RemoveFetched ->
      let (s', o) = f_remove_fetched #io_t #i s in
      let ev = SendEvent_SendRemoved o in
      (s', step t.f_driver ev, Some ev)
  | SendEffect_DeleteLink permit ->
      let (s', o) = f_delete_link #io_t #i s permit in
      let ev = SendEvent_SendDeleted o in
      (s', step t.f_driver ev, Some ev)
  | SendEffect_CompleteCreate | SendEffect_CompleteFetch
  | SendEffect_CompleteDelete _ | SendEffect_Fail _ | SendEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the
/// extracted loop body.
let turn (#io_t: Type0) {| i: t_SendIo io_t |} (acc: io_t & t_SendTransition)
  : (io_t & t_SendTransition) =
  let (s, t) = acc in
  if send_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_SendIo io_t |} (n: nat)
  (acc: io_t & t_SendTransition)
  : Tot (io_t & t_SendTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_SendEvent) (evs: list t_SendEvent) : list t_SendEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_SendIo io_t |} (n: nat) (s: io_t)
  (t: t_SendTransition)
  : Pure (io_t & t_SendTransition & list t_SendEvent)
    (requires sound_transition t)
    (ensures fun (_, t', _) -> sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = turn_ev #io_t #i s t in
    let (s2, t2, evs) = run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

// ── 1. The extracted loop is `run_ev` ─────────────────────────────────────

let rec fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_SendIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_SendTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_SendTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_SendTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_SendTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_SendTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_SendIo io_t |} (n: nat) (s: io_t)
  (t: t_SendTransition)
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
let run_send_is_run_ev (#io_t: Type0) {| i: t_SendIo io_t |} (s: io_t)
  (start: t_SendTransition)
  : Lemma (requires sound_transition start)
          (ensures (let (s2, t2, _) = run_ev #io_t #i 3 s start in
                    run_send #io_t #i s start == (s2, t2))) =
  iter_turn_is_run_ev #io_t #i 3 s start;
  assert (v v_SEND_MAX_EFFECTS = 3);
  assert (run_send #io_t #i s start == iter_turn #io_t #i 3 (s, start))

// ── 2. The observations drive the extracted driver ────────────────────────

let rec responds (t: t_SendTransition) (evs: list t_SendEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_SendIo io_t |} (n: nat) (s: io_t)
  (t: t_SendTransition)
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

let remaining (e: t_SendEffect) : nat =
  match e <: t_SendEffect with
  | SendEffect_InsertSend _ -> 1
  | SendEffect_ConsumeView -> 3
  | SendEffect_ReadSend -> 2
  | SendEffect_RemoveFetched -> 1
  | SendEffect_DeleteLink _ -> 1
  | SendEffect_CompleteCreate | SendEffect_CompleteFetch
  | SendEffect_CompleteDelete _ | SendEffect_Fail _ | SendEffect_Idle -> 0

let step_decreases (t: t_SendTransition) (ev: t_SendEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match (t.f_effect <: t_SendEffect), (ev <: t_SendEvent) with
  | SendEffect_InsertSend _, SendEvent_SendInserted _ -> ()
  | SendEffect_ConsumeView, SendEvent_ViewConsumed _ -> ()
  | SendEffect_ReadSend, SendEvent_SendRead _ -> ()
  | SendEffect_RemoveFetched, SendEvent_SendRemoved _ -> ()
  | SendEffect_DeleteLink _, SendEvent_SendDeleted _ -> ()
  | _ -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_SendIo io_t |} (n: nat) (s: io_t)
  (t: t_SendTransition)
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

let run_send_theorem (#io_t: Type0) {| i: t_SendIo io_t |} (s: io_t)
  (start: t_SendTransition)
  : Lemma (requires sound_transition start)
          (ensures (
            let (_, t) = run_send #io_t #i s start in
            exists (evs: list t_SendEvent).
              responds start evs /\
              t.f_driver == run start.f_driver evs /\
              terminal t.f_effect /\
              trace_sound t.f_driver /\
              send_effect_is_sound t.f_driver t.f_effect)) =
  run_send_is_run_ev #io_t #i s start;
  run_ev_follows_the_driver #io_t #i 3 s start;
  run_ev_reaches_a_verdict #io_t #i 3 s start;
  let (_, t, evs) = run_ev #io_t #i 3 s start in
  ()

/// `POST /send`: the loop stops and ends in `run_from_create` over the
/// observations. A create insert carries the driver's clamped TTL/view bounds,
/// and no insert effect exists without an authenticated owner.
let create_interpreter_theorem (#io_t: Type0) {| i: t_SendIo io_t |} (s: io_t)
  (observation: t_CreateObservation)
  : Lemma (
      let t0 = begin_create observation in
      let (_, t) = run_send #io_t #i s t0 in
      exists (evs: list t_SendEvent).
        responds t0 evs /\
        t.f_driver == run_from_create observation evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        send_effect_is_sound t0.f_driver t0.f_effect /\
        not (t.f_driver.f_succeeded && t.f_driver.f_failed)) =
  let t0 = begin_create observation in
  run_send_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  success_excludes_failure t.f_driver;
  assert (run_from_create observation evs == run t0.f_driver evs)

/// `GET /send/:id`: at most one delivery per request, and a delivery is only
/// behind a successful consume. A failed consume can never deliver.
let fetch_interpreter_theorem (#io_t: Type0) {| i: t_SendIo io_t |} (s: io_t)
  : Lemma (
      let t0 = begin_fetch () in
      let (_, t) = run_send #io_t #i s t0 in
      exists (evs: list t_SendEvent).
        responds t0 evs /\
        t.f_driver == run_from_fetch evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        delivery_count t0.f_driver evs <= 1 /\
        (t.f_driver.f_delivered ==> t.f_driver.f_consumed) /\
        (t.f_driver.f_failed ==> not t.f_driver.f_delivered) /\
        not (t.f_driver.f_succeeded && t.f_driver.f_failed)) =
  let t0 = begin_fetch () in
  run_send_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  fetch_delivers_at_most_once evs;
  delivered_implies_consumed t.f_driver;
  success_excludes_failure t.f_driver;
  assert (run_from_fetch evs == run t0.f_driver evs)

/// `DELETE /send/:id`: the driver reaches the delete only through an
/// owner-bound permit; without an owner the request stops as a failure and
/// never deletes.
let delete_interpreter_theorem (#io_t: Type0) {| i: t_SendIo io_t |} (s: io_t)
  (owner_present: bool)
  : Lemma (
      let t0 = begin_delete owner_present in
      let (_, t) = run_send #io_t #i s t0 in
      exists (evs: list t_SendEvent).
        responds t0 evs /\
        t.f_driver == run_from_delete owner_present evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        (not owner_present ==> (t.f_driver.f_failed /\ not t.f_driver.f_deleted)) /\
        (t.f_driver.f_deleted ==> t.f_driver.f_succeeded) /\
        not (t.f_driver.f_succeeded && t.f_driver.f_failed)) =
  let t0 = begin_delete owner_present in
  run_send_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  deleted_implies_succeeded t.f_driver;
  success_excludes_failure t.f_driver;
  assert (run_from_delete owner_present evs == run t0.f_driver evs)
