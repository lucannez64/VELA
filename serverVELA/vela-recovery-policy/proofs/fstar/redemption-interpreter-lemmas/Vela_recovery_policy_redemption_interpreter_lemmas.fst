module Vela_recovery_policy_redemption_interpreter_lemmas

/// The extracted `run_redemption` is the loop `POST /recovery/enroll-device`
/// runs: the server expands the same `redemption_interpreter!` macro text,
/// adding only `.await` after each executor call. This module proves, for every
/// executor implementation (any `t_RedemptionIo` instance, any behaviour):
///
/// 1. `run_redemption` calls the executor exactly as `run_ev` below does: one
///    method per turn, chosen by the effect the driver has just emitted, with
///    that effect's argument (the insert permit), nothing once the driver
///    reached a verdict, and exactly one restoration for `RestoreAndFail`
///    (`run_redemption_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_ready ready evs` (`run_ev_follows_the_driver`);
/// 3. the loop reaches a verdict within its five-turn budget, or stops early
///    because an effect aborted (the handler then renders the recorded error)
///    (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request redemption theorem holds for the state the real
///    handler ends in (`run_redemption_theorem`).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_recovery_policy.Driver
open Vela_recovery_policy.Redemption_interpreter
open Vela_recovery_policy_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_RedemptionEffect) : bool =
  match e with
  | RedemptionEffect_Complete | RedemptionEffect_Fail _ | RedemptionEffect_RestoreAndFail _
  | RedemptionEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_RedemptionEffect) (ev: t_RedemptionEvent) : bool =
  match e, ev with
  | RedemptionEffect_Consume, RedemptionEvent_Consumed _
  | RedemptionEffect_FinalPolicy, RedemptionEvent_FinalPolicy _
  | RedemptionEffect_Insert _, RedemptionEvent_Insert _
  | RedemptionEffect_Recheck, RedemptionEvent_Recheck _ -> true
  | _ -> false

let sound_transition (t: t_RedemptionTransition) : bool =
  redemption_transition_is_sound t

/// The loop's accumulator is exactly the extracted one: abort flag, executor,
/// restoration flag, driver transition.
let acc_transition (#io_t: Type0) (acc: bool & io_t & bool & t_RedemptionTransition)
  : t_RedemptionTransition =
  let (_, _, _, t) = acc in t

let acc_aborted (#io_t: Type0) (acc: bool & io_t & bool & t_RedemptionTransition) : bool =
  let (aborted, _, _, _) = acc in aborted

/// A restoration flag is only ever set while the driver's verdict is
/// `RestoreAndFail`, which is terminal.
let flag_sound (#io_t: Type0) (acc: bool & io_t & bool & t_RedemptionTransition) : bool =
  let (_, _, restore_done, t) = acc in not restore_done || terminal t.f_effect

/// Drop the collected event from a turn result, so the flag/state predicates
/// can be applied to it.
let result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & bool & t_RedemptionTransition & ev)
  : (bool & io_t & bool & t_RedemptionTransition) =
  let (a, s, r, t, _) = result in (a, s, r, t)

/// One turn: call the executor method for the current effect, feed its
/// observation (when the effect returned one) to the extracted `step`, and
/// report the event. A verdict performs nothing; a restoration performs its
/// one call without stepping; a failed effect aborts.
let turn_ev (#io_t: Type0) {| i: t_RedemptionIo io_t |}
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : Pure (bool & io_t & bool & t_RedemptionTransition & option t_RedemptionEvent)
    (requires sound_transition (acc_transition acc))
    (ensures fun result ->
      sound_transition (acc_transition (result_acc result)) /\
      (flag_sound acc ==> flag_sound (result_acc result))) =
  let (aborted, s, restore_done, t) = acc in
  if aborted || restore_done then (aborted, s, restore_done, t, None)
  else
    match t.f_effect with
    | RedemptionEffect_Consume ->
        let (s', o) = f_consume_grant #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RedemptionEvent_Consumed observation in
             (aborted, s', restore_done, step t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', restore_done, t, None))
    | RedemptionEffect_FinalPolicy ->
        let (s', o) = f_final_policy #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RedemptionEvent_FinalPolicy observation in
             (aborted, s', restore_done, step t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', restore_done, t, None))
    | RedemptionEffect_Insert permit ->
        let (s', o) = f_insert_device #io_t #i s permit in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RedemptionEvent_Insert observation in
             (aborted, s', restore_done, step t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', restore_done, t, None))
    | RedemptionEffect_Recheck ->
        let (s', o) = f_recheck_authority #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RedemptionEvent_Recheck observation in
             (aborted, s', restore_done, step t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', restore_done, t, None))
    | RedemptionEffect_RestoreAndFail _ ->
        let (s', o) = f_restore_grant #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some _ -> (aborted, s', true, t, None)
         | Core_models.Option.Option_None -> (true, s', restore_done, t, None))
    | RedemptionEffect_Complete | RedemptionEffect_Fail _ | RedemptionEffect_Idle ->
        (aborted, s, restore_done, t, None)

/// `turn_ev` without the event, total so it can be compared with the extracted
/// loop body.
let turn (#io_t: Type0) {| i: t_RedemptionIo io_t |}
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : (bool & io_t & bool & t_RedemptionTransition) =
  if sound_transition (acc_transition acc)
  then let (a', s', r', t', _) = turn_ev #io_t #i acc in (a', s', r', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_RedemptionIo io_t |} (n: nat)
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : Tot (bool & io_t & bool & t_RedemptionTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_RedemptionEvent) (evs: list t_RedemptionEvent)
  : list t_RedemptionEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_RedemptionIo io_t |} (n: nat)
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : Pure (bool & io_t & bool & t_RedemptionTransition & list t_RedemptionEvent)
    (requires sound_transition (acc_transition acc) /\ flag_sound acc)
    (ensures fun result ->
      sound_transition (acc_transition (result_acc result)) /\ flag_sound (result_acc result))
    (decreases n) =
  if n = 0 then (let (a, s, r, t) = acc in (a, s, r, t, []))
  else
    let (a1, s1, r1, t1, o) = turn_ev #io_t #i acc in
    let (a2, s2, r2, t2, evs) = run_ev #io_t #i (n - 1) (a1, s1, r1, t1) in
    (a2, s2, r2, t2, cons_opt o evs)

// ── 1. The extracted loop is `run_ev` ─────────────────────────────────────

/// `fold_range` over a body that is one `turn` per index is `iter_turn`. The
/// two patterns fire together when a goal mentions both the extracted loop and
/// the specification, which binds every variable including the instance.
let rec fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_RedemptionIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (bool & io_t & bool & t_RedemptionTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & bool & t_RedemptionTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & bool & t_RedemptionTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & bool & t_RedemptionTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & bool & t_RedemptionTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_RedemptionIo io_t |} (n: nat)
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : Lemma (requires sound_transition (acc_transition acc) /\ flag_sound acc)
          (ensures (let (a2, s2, r2, t2, _) = run_ev #io_t #i n acc in
                    iter_turn #io_t #i n acc == (a2, s2, r2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, r1, t1, _) = turn_ev #io_t #i acc in
    iter_turn_is_run_ev #io_t #i (n - 1) (a1, s1, r1, t1)
  end

/// The extracted loop calls the executor exactly as `run_ev` does.
let run_redemption_is_run_ev (#io_t: Type0) {| i: t_RedemptionIo io_t |} (s: io_t)
      (ready: Vela_recovery_policy.t_ReadyToConsume)
  : Lemma
    (let t0 = begin_redemption ready in
     let (a2, s2, r2, t2, _) = run_ev #io_t #i 5 (false, s, false, t0) in
     run_redemption #io_t #i s ready ==
       (s2, (if a2 then Core_models.Option.Option_None else Core_models.Option.Option_Some t2))) =
  let t0 = begin_redemption ready in
  assert (v v_REDEMPTION_MAX_EFFECTS = 5);
  assert (run_redemption #io_t #i s ready ==
          (let (a2, s2, r2, t2, _) = run_ev #io_t #i 5 (false, s, false, t0) in
           (s2, (if a2 then Core_models.Option.Option_None else Core_models.Option.Option_Some t2))))

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_RedemptionTransition) (evs: list t_RedemptionEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_RedemptionIo io_t |} (n: nat)
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : Lemma (requires sound_transition (acc_transition acc) /\ flag_sound acc)
          (ensures (let (_, _, _, t2, evs) = run_ev #io_t #i n acc in
                    trace_sound t2.f_driver /\
                    responds (acc_transition acc) evs /\
                    t2.f_driver == run (acc_transition acc).f_driver evs))
          (decreases n) =
  trace_sound_matches_rust (acc_transition acc).f_driver;
  let (aborted, _, restore_done, t) = acc in
  if n = 0 then ()
  else if aborted || restore_done then begin
    let (a1, s1, r1, t1, _) = turn_ev #io_t #i acc in
    assert (t1 == t);
    run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, r1, t1)
  end else begin
    let (a1, s1, r1, t1, o) = turn_ev #io_t #i acc in
    run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, r1, t1);
    match o with
    | None -> ()
    | Some ev ->
        step_sound t.f_driver ev;
        assert (responds t (ev :: (let (_, _, _, _, evs) = run_ev #io_t #i (n - 1) (a1, s1, r1, t1) in evs)))
  end

// ── 3. A verdict within the budget ────────────────────────────────────────

/// Effects still to perform before a verdict, at most. `RestoreAndFail` is
/// already the verdict; its one restoration happens inside the budget.
let remaining (e: t_RedemptionEffect) : nat =
  match e with
  | RedemptionEffect_Consume -> 4
  | RedemptionEffect_FinalPolicy -> 3
  | RedemptionEffect_Insert _ -> 2
  | RedemptionEffect_Recheck -> 1
  | RedemptionEffect_Complete | RedemptionEffect_Fail _ | RedemptionEffect_RestoreAndFail _
  | RedemptionEffect_Idle -> 0

let remaining_zero_is_terminal (e: t_RedemptionEffect)
  : Lemma (requires remaining e = 0) (ensures terminal e) =
  match e with
  | RedemptionEffect_Consume -> ()
  | RedemptionEffect_FinalPolicy -> ()
  | RedemptionEffect_Insert _ -> ()
  | RedemptionEffect_Recheck -> ()
  | RedemptionEffect_Complete -> ()
  | RedemptionEffect_Fail _ -> ()
  | RedemptionEffect_RestoreAndFail _ -> ()
  | RedemptionEffect_Idle -> ()

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_RedemptionTransition) (ev: t_RedemptionEvent)
  : Lemma
    (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
    (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect with
  | RedemptionEffect_Consume -> ()
  | RedemptionEffect_FinalPolicy -> ()
  | RedemptionEffect_Insert _ -> ()
  | RedemptionEffect_Recheck -> ()

/// Once a turn aborted, every later turn is inert and the abort flag stays set.
let rec run_ev_aborted (#io_t: Type0) {| i: t_RedemptionIo io_t |} (n: nat)
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : Lemma
    (requires acc_aborted acc /\ sound_transition (acc_transition acc) /\ flag_sound acc)
    (ensures (let (a2, _, _, _, _) = run_ev #io_t #i n acc in a2))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, r1, t1, o) = turn_ev #io_t #i acc in
    assert (a1);
    let rest = run_ev #io_t #i (n - 1) (a1, s1, r1, t1) in
    assert (run_ev #io_t #i n acc ==
            (let (a2, s2, r2, t2, evs) = rest in
             (a2, s2, r2, t2, cons_opt o evs)));
    run_ev_aborted #io_t #i (n - 1) (a1, s1, r1, t1)
  end

#push-options "--fuel 4 --ifuel 2"
let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_RedemptionIo io_t |} (n: nat)
      (acc: bool & io_t & bool & t_RedemptionTransition)
  : Lemma
    (requires sound_transition (acc_transition acc) /\ flag_sound acc /\
              remaining (acc_transition acc).f_effect <= n)
    (ensures (let (a2, _, _, t2, _) = run_ev #io_t #i n acc in
              terminal t2.f_effect \/ a2))
    (decreases n) =
  let (aborted, _, restore_done, t) = acc in
  if n = 0 then remaining_zero_is_terminal t.f_effect
  else begin
    let (a1, s1, r1, t1, o) = turn_ev #io_t #i acc in
    let rest = run_ev #io_t #i (n - 1) (a1, s1, r1, t1) in
    assert (run_ev #io_t #i n acc ==
            (let (a2, s2, r2, t2, evs) = rest in
             (a2, s2, r2, t2, cons_opt o evs)));
    if a1 then run_ev_aborted #io_t #i (n - 1) (a1, s1, r1, t1)
    else begin
      (match o with
       | None ->
           assert (t1 == t);
           assert (terminal t.f_effect);
           assert (remaining t.f_effect = 0)
       | Some ev ->
           assert (t1 == step t.f_driver ev);
           step_decreases t ev;
           assert (remaining t1.f_effect <= n - 1));
      assert (flag_sound (a1, s1, r1, t1));
      run_ev_reaches_a_verdict #io_t #i (n - 1) (a1, s1, r1, t1)
    end
  end
#pop-options

// ── 4. The handler's final state satisfies the per-request theorems ───────

let run_redemption_theorem (#io_t: Type0) {| i: t_RedemptionIo io_t |} (s: io_t)
      (ready: Vela_recovery_policy.t_ReadyToConsume)
  : Lemma (
      let (_, outcome) = run_redemption #io_t #i s ready in
      match outcome with
      | Core_models.Option.Option_None -> True
      | Core_models.Option.Option_Some t ->
          terminal t.f_effect /\
          sound_transition t /\
          (exists (evs: list t_RedemptionEvent).
            responds (begin_redemption ready) evs /\
            t.f_driver == run_from_ready ready evs /\
            trace_sound t.f_driver /\
            (let d = t.f_driver in
             (d.f_insert_succeeded ==> not d.f_restored) /\
             (d.f_restored ==> not d.f_insert_succeeded) /\
             count_complete_from_ready ready evs <= 1))) =
  let t0 = begin_redemption ready in
  run_redemption_is_run_ev #io_t #i s ready;
  let (a2, s2, r2, t2, evs) = run_ev #io_t #i 5 (false, s, false, t0) in
  begin_sound ready;
  trace_sound_matches_rust t0.f_driver;
  run_ev_follows_the_driver #io_t #i 5 (false, s, false, t0);
  run_ev_reaches_a_verdict #io_t #i 5 (false, s, false, t0);
  if a2 then ()
  else begin
    assert ((let (_, outcome) = run_redemption #io_t #i s ready in outcome) ==
            Core_models.Option.Option_Some t2);
    assert (responds t0 evs);
    assert (t2.f_driver == run t0.f_driver evs);
    redemption_trace_theorem ready evs;
    assert (t2.f_driver == run_from_ready ready evs)
  end
