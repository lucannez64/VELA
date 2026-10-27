module Vela_share_policy_interpreter_lemmas

/// The extracted `run_share` is the loop every sharing handler runs: the
/// server expands the same `share_interpreter!` macro text, adding only
/// `.await` after each executor call. This module proves, for every executor
/// implementation (any `t_ShareIo` instance, any behaviour):
///
/// 1. `run_share` calls the executor exactly as `run_ev` below does: one
///    method per turn, chosen by the effect the driver has just emitted, with
///    that effect's permit argument, and nothing once the driver reached a
///    verdict (`run_share_is_run_ev`);
/// 2. the observations the executor returned form a list in which each
///    observation answers the effect it was returned for, and the final driver
///    is the extracted driver's `run_from_*` over that list
///    (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of 3 turns
///    (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request sharing theorem holds for the state the real
///    handler ends in (the corollaries at the end).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copies differ only by `.await`).

open FStar.Mul
open Core_models
open Vela_share_policy.Driver
open Vela_share_policy.Interpreter
open Vela_share_policy_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_ShareEffect) : bool =
  match e with
  | ShareEffect_Complete | ShareEffect_Fail _ | ShareEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_ShareEffect) (ev: t_ShareEvent) : bool =
  match e, ev with
  | ShareEffect_ObserveLink, ShareEvent_LinkObserved _
  | ShareEffect_ObserveDevice, ShareEvent_EkObserved _
  | ShareEffect_InsertCapsule _, ShareEvent_SendResult _
  | ShareEffect_UpdateLinkedItem _, ShareEvent_Mutated _
  | ShareEffect_RevokeLinkedItem, ShareEvent_Mutated _
  | ShareEffect_DeleteLinkedInbox, ShareEvent_Cleaned _
  | ShareEffect_DeleteInboxItem _, ShareEvent_Mutated _
  | ShareEffect_UpdateShareEk _, ShareEvent_Mutated _ -> true
  | _ -> false

let sound_transition (t: t_ShareTransition) : bool =
  share_state_is_sound t.f_driver && share_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t) (t: t_ShareTransition)
  : Pure (io_t & t_ShareTransition & option t_ShareEvent)
    (requires share_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | ShareEffect_ObserveLink ->
      let (s', o) = f_observe_link #io_t #i s in
      let ev = ShareEvent_LinkObserved o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_ObserveDevice ->
      let (s', o) = f_observe_device #io_t #i s in
      let ev = ShareEvent_EkObserved o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_InsertCapsule permit ->
      let (s', o) = f_insert_capsule #io_t #i s permit in
      let ev = ShareEvent_SendResult o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_UpdateLinkedItem permit ->
      let (s', o) = f_update_linked_item #io_t #i s permit in
      let ev = ShareEvent_Mutated o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_RevokeLinkedItem ->
      let (s', o) = f_revoke_linked_item #io_t #i s in
      let ev = ShareEvent_Mutated o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_DeleteLinkedInbox ->
      let (s', o) = f_delete_linked_inbox #io_t #i s in
      let ev = ShareEvent_Cleaned o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_DeleteInboxItem permit ->
      let (s', o) = f_delete_inbox_item #io_t #i s permit in
      let ev = ShareEvent_Mutated o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_UpdateShareEk permit ->
      let (s', o) = f_update_share_ek #io_t #i s permit in
      let ev = ShareEvent_Mutated o in
      (s', step t.f_driver ev, Some ev)
  | ShareEffect_Complete | ShareEffect_Fail _ | ShareEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the
/// extracted loop body.
let turn (#io_t: Type0) {| i: t_ShareIo io_t |} (acc: io_t & t_ShareTransition)
  : (io_t & t_ShareTransition) =
  let (s, t) = acc in
  if share_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_ShareIo io_t |} (n: nat)
  (acc: io_t & t_ShareTransition)
  : Tot (io_t & t_ShareTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_ShareEvent) (evs: list t_ShareEvent) : list t_ShareEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_ShareIo io_t |} (n: nat) (s: io_t)
  (t: t_ShareTransition)
  : Pure (io_t & t_ShareTransition & list t_ShareEvent)
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
  (#io_t: Type0) {| i: t_ShareIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_ShareTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_ShareTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_ShareTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_ShareTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_ShareTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_ShareIo io_t |} (n: nat) (s: io_t)
  (t: t_ShareTransition)
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
let run_share_is_run_ev (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t)
  (start: t_ShareTransition)
  : Lemma (requires sound_transition start)
          (ensures (let (s2, t2, _) = run_ev #io_t #i 3 s start in
                    run_share #io_t #i s start == (s2, t2))) =
  iter_turn_is_run_ev #io_t #i 3 s start;
  assert (v v_SHARE_MAX_EFFECTS = 3);
  assert (run_share #io_t #i s start == iter_turn #io_t #i 3 (s, start))

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_ShareTransition) (evs: list t_ShareEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_ShareIo io_t |} (n: nat) (s: io_t)
  (t: t_ShareTransition)
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

/// Effects still to perform before a verdict, at most.
let remaining (e: t_ShareEffect) : nat =
  match e with
  | ShareEffect_ObserveLink -> 3
  | ShareEffect_ObserveDevice -> 2
  | ShareEffect_InsertCapsule _ -> 1
  | ShareEffect_UpdateLinkedItem _ -> 1
  | ShareEffect_RevokeLinkedItem -> 2
  | ShareEffect_DeleteLinkedInbox -> 1
  | ShareEffect_DeleteInboxItem _ -> 1
  | ShareEffect_UpdateShareEk _ -> 1
  | ShareEffect_Complete | ShareEffect_Fail _ | ShareEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_ShareTransition) (ev: t_ShareEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect, ev with
  | ShareEffect_ObserveLink, ShareEvent_LinkObserved _ -> ()
  | ShareEffect_ObserveDevice, ShareEvent_EkObserved _ -> ()
  | ShareEffect_InsertCapsule _, ShareEvent_SendResult _ -> ()
  | ShareEffect_UpdateLinkedItem _, ShareEvent_Mutated _ -> ()
  | ShareEffect_RevokeLinkedItem, ShareEvent_Mutated _ -> ()
  | ShareEffect_DeleteLinkedInbox, ShareEvent_Cleaned _ -> ()
  | ShareEffect_DeleteInboxItem _, ShareEvent_Mutated _ -> ()
  | ShareEffect_UpdateShareEk _, ShareEvent_Mutated _ -> ()
  | _ -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_ShareIo io_t |} (n: nat) (s: io_t)
  (t: t_ShareTransition)
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

/// The generic result: for every sound start transition, the loop performs
/// exactly the driver's effects, stops at a verdict, and ends in the state the
/// extracted driver reaches by replaying the observations.
let run_share_theorem (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t)
  (start: t_ShareTransition)
  : Lemma (requires sound_transition start)
          (ensures (
            let (_, t) = run_share #io_t #i s start in
            exists (evs: list t_ShareEvent).
              responds start evs /\
              t.f_driver == run start.f_driver evs /\
              terminal t.f_effect /\
              trace_sound t.f_driver /\
              share_effect_is_sound t.f_driver t.f_effect)) =
  run_share_is_run_ev #io_t #i s start;
  run_ev_follows_the_driver #io_t #i 3 s start;
  run_ev_reaches_a_verdict #io_t #i 3 s start;
  let (_, t, evs) = run_ev #io_t #i 3 s start in
  ()

/// Send: the final state is the driver's `run_from_send` over the
/// observations, and the send headline theorem holds.
let send_interpreter_theorem (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t)
  (observation: t_SendRequestObservation)
  : Lemma (
      let t0 = begin_send observation in
      let (_, t) = run_share #io_t #i s t0 in
      exists (evs: list t_ShareEvent).
        responds t0 evs /\
        t.f_driver == run_from_send observation evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        (t.f_driver.f_revoked ==> False) /\
        count_completes_from_send observation evs <= 1) =
  let t0 = begin_send observation in
  run_share_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  share_trace_send_theorem observation evs;
  assert (run_from_send observation evs == run t0.f_driver evs)

/// Update: at most one success, and the final state is the driver's
/// `run_from_update` over the observations.
let update_interpreter_theorem (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t)
  (observation: t_LinkUpdateStartObservation)
  : Lemma (
      let t0 = begin_link_update observation in
      let (_, t) = run_share #io_t #i s t0 in
      exists (evs: list t_ShareEvent).
        responds t0 evs /\
        t.f_driver == run_from_update observation evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_completes_from_update observation evs <= 1) =
  let t0 = begin_link_update observation in
  run_share_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  begin_link_update_sound observation;
  trace_sound_matches_rust t0.f_driver;
  complete_count_le_one t0.f_driver evs;
  assert (run_from_update observation evs == run t0.f_driver evs)

/// Revoke: the revoke headline theorem holds for the final state, including
/// the committed-revoke cleanup.
let revoke_interpreter_theorem (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t)
  : Lemma (
      let t0 = begin_link_revoke () in
      let (_, t) = run_share #io_t #i s t0 in
      exists (evs: list t_ShareEvent).
        responds t0 evs /\
        t.f_driver == run_from_revoke () evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        (t.f_driver.f_committed ==> t.f_driver.f_revoked) /\
        (t.f_driver.f_revoked ==> t.f_driver.f_cleanup_issued) /\
        count_completes_from_revoke () evs <= 1) =
  let t0 = begin_link_revoke () in
  run_share_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  share_trace_revoke_theorem () evs;
  assert (run_from_revoke () evs == run t0.f_driver evs)

/// Inbox delete: at most one success and the final state is the driver's
/// `run_from_inbox` over the observations.
let inbox_interpreter_theorem (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t)
  : Lemma (
      let t0 = begin_inbox_delete () in
      let (_, t) = run_share #io_t #i s t0 in
      exists (evs: list t_ShareEvent).
        responds t0 evs /\
        t.f_driver == run_from_inbox () evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_completes_from_inbox () evs <= 1) =
  let t0 = begin_inbox_delete () in
  run_share_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  begin_inbox_delete_sound ();
  trace_sound_matches_rust t0.f_driver;
  complete_count_le_one t0.f_driver evs;
  assert (run_from_inbox () evs == run t0.f_driver evs)

/// Share-EK registration: at most one success and the final state is the
/// driver's `run_from_ek` over the observations.
let ek_interpreter_theorem (#io_t: Type0) {| i: t_ShareIo io_t |} (s: io_t)
  (observation: t_EkRegistrationStartObservation)
  : Lemma (
      let t0 = begin_ek_registration observation in
      let (_, t) = run_share #io_t #i s t0 in
      exists (evs: list t_ShareEvent).
        responds t0 evs /\
        t.f_driver == run_from_ek observation evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_completes_from_ek observation evs <= 1) =
  let t0 = begin_ek_registration observation in
  run_share_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 3 s t0 in
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  begin_ek_registration_sound observation;
  trace_sound_matches_rust t0.f_driver;
  complete_count_le_one t0.f_driver evs;
  assert (run_from_ek observation evs == run t0.f_driver evs)
