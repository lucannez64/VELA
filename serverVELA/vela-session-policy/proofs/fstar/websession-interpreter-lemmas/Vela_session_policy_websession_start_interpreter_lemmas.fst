module Vela_session_policy_websession_start_interpreter_lemmas



/// This module is the start handler loop of the four web-session handlers.
/// It is checked in its own fstar.exe invocation so the SMT patterns of the
/// fold/iteration lemmas cannot interact across drivers.

open FStar.Mul
open Core_models
open Vela_session_policy.Websession_driver
open Vela_session_policy.Websession_interpreter
open Vela_session_policy_websession_driver_lemmas

let cons_opt (#a: Type) (o: option a) (evs: list a) : list a =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

// ── POST /web-session/start ──────────────────────────────────────────────────────────

let start_terminal (e: t_StartEffect) : bool =
  match e with
  | StartEffect_Complete | StartEffect_Fail _ | StartEffect_Idle -> true
  | _ -> false

let start_responds_to (e: t_StartEffect) (ev: t_StartEvent) : bool =
  match e, ev with
  | StartEffect_CheckRateLimit, StartEvent_LimitObserved _ -> true
  | StartEffect_ValidateStart, StartEvent_Validated _ -> true
  | StartEffect_InsertPending, StartEvent_Inserted _ -> true
  | _ -> false

let start_sound_transition (t: t_StartTransition) : bool =
  start_state_is_sound t.f_driver && start_effect_is_sound t.f_driver t.f_effect

let start_turn_ev (#io_t: Type0) {| i: t_StartIo io_t |} (s: io_t) (t: t_StartTransition)
  : Pure (io_t & t_StartTransition & option t_StartEvent)
    (requires start_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | StartEffect_CheckRateLimit ->
      let (s', o) = f_check_rate_limit #io_t #i s in
      let ev = StartEvent_LimitObserved o in
      (s', start_step t.f_driver ev, Some ev)
  | StartEffect_ValidateStart ->
      let (s', o) = f_validate_start #io_t #i s in
      let ev = StartEvent_Validated o in
      (s', start_step t.f_driver ev, Some ev)
  | StartEffect_InsertPending ->
      let (s', o) = f_insert_pending #io_t #i s in
      let ev = StartEvent_Inserted o in
      (s', start_step t.f_driver ev, Some ev)
  | StartEffect_Complete | StartEffect_Fail _ | StartEffect_Idle -> (s, t, None)

let start_turn (#io_t: Type0) {| i: t_StartIo io_t |} (acc: io_t & t_StartTransition)
  : (io_t & t_StartTransition) =
  let (s, t) = acc in
  if start_state_is_sound t.f_driver
  then let (s', t', _) = start_turn_ev #io_t #i s t in (s', t')
  else acc

let rec start_iter_turn (#io_t: Type0) {| i: t_StartIo io_t |} (n: nat)
  (acc: io_t & t_StartTransition)
  : Tot (io_t & t_StartTransition) (decreases n) =
  if n = 0 then acc else start_iter_turn #io_t #i (n - 1) (start_turn #io_t #i acc)

let rec start_run_ev (#io_t: Type0) {| i: t_StartIo io_t |} (n: nat) (s: io_t)
  (t: t_StartTransition)
  : Pure (io_t & t_StartTransition & list t_StartEvent)
    (requires start_sound_transition t)
    (ensures fun (_, t', _) -> start_sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = start_turn_ev #io_t #i s t in
    let (s2, t2, evs) = start_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

let rec start_fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_StartIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_StartTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_StartTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_StartTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_StartTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_StartTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == start_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              start_iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (start_iter_turn #io_t #i n init)] =
  if v start < v end_
  then start_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec start_iter_turn_is_run_ev (#io_t: Type0) {| i: t_StartIo io_t |} (n: nat) (s: io_t)
  (t: t_StartTransition)
  : Lemma (requires start_sound_transition t)
          (ensures (let (s2, t2, _) = start_run_ev #io_t #i n s t in
                    start_iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = start_turn_ev #io_t #i s t in
    start_iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

let start_run_is_run_ev (#io_t: Type0) {| i: t_StartIo io_t |} (s: io_t)
  : Lemma (let (s2, t2, _) = start_run_ev #io_t #i 3 s (begin_start ()) in
           run_start #io_t #i s == (s2, t2)) =
  let t0 = begin_start () in
  start_iter_turn_is_run_ev #io_t #i 3 s t0;
  assert (v v_START_MAX_EFFECTS = 3);
  assert (run_start #io_t #i s == start_iter_turn #io_t #i 3 (s, t0))

let rec start_responds (t: t_StartTransition) (evs: list t_StartEvent)
  : Pure bool (requires start_sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (start_terminal t.f_effect) && start_responds_to t.f_effect ev &&
      start_responds (start_step t.f_driver ev) rest

let rec start_run_ev_follows_the_driver (#io_t: Type0) {| i: t_StartIo io_t |}  (n: nat) (s: io_t)
  (t: t_StartTransition)
  : Lemma (requires start_sound_transition t)
          (ensures (let (_, t2, evs) = start_run_ev #io_t #i n s t in
                    start_trace_sound t.f_driver /\
                    start_responds t evs /\
                    t2.f_driver == start_run t.f_driver evs))
          (decreases n) =
  start_trace_sound_matches_rust t.f_driver;
  if n = 0 then ()
  else begin
    let (s1, t1, o) = start_turn_ev #io_t #i s t in
    start_run_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> start_step_sound t.f_driver ev
  end

let start_remaining (e: t_StartEffect) : nat =
  match e with
  | StartEffect_CheckRateLimit -> 3
  | StartEffect_ValidateStart -> 2
  | StartEffect_InsertPending -> 1
  | _ -> 0

let start_step_decreases (t: t_StartTransition) (ev: t_StartEvent)
  : Lemma (requires start_sound_transition t /\ not (start_terminal t.f_effect) /\ start_responds_to t.f_effect ev)
          (ensures start_remaining (start_step t.f_driver ev).f_effect < start_remaining t.f_effect) =
  match t.f_effect with
  | StartEffect_CheckRateLimit -> ()
  | StartEffect_ValidateStart -> ()
  | StartEffect_InsertPending -> ()
  | _ -> ()

let rec start_run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_StartIo io_t |} (n: nat) (s: io_t)
  (t: t_StartTransition)
  : Lemma (requires start_sound_transition t /\ start_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = start_run_ev #io_t #i n s t in start_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = start_turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> start_step_decreases t ev);
    start_run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

let start_run_theorem (#io_t: Type0) {| i: t_StartIo io_t |} (s: io_t)
  : Lemma (
      let (_, t) = run_start #io_t #i s in
      exists (evs: list t_StartEvent).
        start_responds (begin_start ()) evs /\
        t.f_driver == start_run_from_begin evs /\
        start_terminal t.f_effect /\
        start_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         (d.f_inserted ==> (d.f_limited_ok && d.f_validated)) /\
         (d.f_responded ==> (d.f_inserted && d.f_limited_ok && d.f_validated)) /\
         not (d.f_responded && d.f_failed))) =
  let t0 = begin_start () in
  start_run_is_run_ev #io_t #i s;
  start_run_ev_follows_the_driver #io_t #i 3 s t0;
  start_run_ev_reaches_a_verdict #io_t #i 3 s t0;
  let (_, t2, evs) = start_run_ev #io_t #i 3 s t0 in
  start_trace_theorem evs

/// Cancellation (web session start): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver state
/// whose next effect agrees with it.
let websession_start_cancellation (#io_t: Type0) {| i: t_StartIo io_t |} (k: nat) (s: io_t)
  (t: t_StartTransition)
  : Lemma (requires start_sound_transition t)
          (ensures (let (_, t2) = start_iter_turn #io_t #i k (s, t) in start_sound_transition t2)) =
  start_iter_turn_is_run_ev #io_t #i k s t
