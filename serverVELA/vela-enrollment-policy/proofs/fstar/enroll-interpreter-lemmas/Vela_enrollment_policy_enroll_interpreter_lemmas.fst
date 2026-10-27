module Vela_enrollment_policy_enroll_interpreter_lemmas

/// The extracted `run_enroll` is the loop `POST /device/enroll` runs: the
/// server expands the same `enroll_interpreter!` macro text, adding only
/// `.await` after each executor call. This module proves, for every executor
/// implementation (any `t_EnrollIo` instance, any behaviour):
///
/// 1. `run_enroll` calls the executor exactly as `run_ev` below does: one
///    method per turn, chosen by the effect the driver has just emitted, with
///    that effect's argument, and nothing once the driver reached a verdict
///    (`run_enroll_is_run_ev`);
/// 2. the observations the executor returned form a list in which each
///    observation answers the effect it was returned for, and the final driver
///    is the extracted driver's `run_from_enroll` over that list
///    (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of 5 turns
///    (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request enrollment theorem holds for the state the real
///    handler ends in (the corollaries at the end).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_enrollment_policy
open Vela_enrollment_policy.Enroll_driver
open Vela_enrollment_policy.Enroll_interpreter
open Vela_enrollment_policy_enroll_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_EnrollEffect) : bool =
  match e <: t_EnrollEffect with
  | EnrollEffect_Complete | EnrollEffect_Fail _ | EnrollEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_EnrollEffect) (ev: t_EnrollEvent) : bool =
  match e, ev with
  | EnrollEffect_ConsumeChallenge, EnrollEvent_ChallengeConsumed _
  | EnrollEffect_CheckDevice, EnrollEvent_DeviceChecked _
  | EnrollEffect_PrepareEnrollment, EnrollEvent_EnrollmentPrepared _
  | EnrollEffect_CheckAccount, EnrollEvent_AccountChecked _
  | EnrollEffect_InsertDevice, EnrollEvent_DeviceInserted _ -> true
  | _ -> false

let sound_transition (t: t_EnrollTransition) : bool =
  enroll_state_is_sound t.f_driver && enroll_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_EnrollIo io_t |} (s: io_t) (t: t_EnrollTransition)
  : Pure (io_t & t_EnrollTransition & option t_EnrollEvent)
    (requires enroll_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect <: t_EnrollEffect with
  | EnrollEffect_ConsumeChallenge ->
      let (s', o) = f_consume_challenge #io_t #i s in
      let ev = EnrollEvent_ChallengeConsumed o in
      (s', step t.f_driver ev, Some ev)
  | EnrollEffect_CheckDevice ->
      let (s', o) = f_check_device #io_t #i s in
      let ev = EnrollEvent_DeviceChecked o in
      (s', step t.f_driver ev, Some ev)
  | EnrollEffect_PrepareEnrollment ->
      let (s', o) = f_prepare_enrollment #io_t #i s in
      let ev = EnrollEvent_EnrollmentPrepared o in
      (s', step t.f_driver ev, Some ev)
  | EnrollEffect_CheckAccount ->
      let (s', o) = f_check_account #io_t #i s in
      let ev = EnrollEvent_AccountChecked o in
      (s', step t.f_driver ev, Some ev)
  | EnrollEffect_InsertDevice ->
      let (s', o) = f_insert_device #io_t #i s in
      let ev = EnrollEvent_DeviceInserted o in
      (s', step t.f_driver ev, Some ev)
  | EnrollEffect_Complete | EnrollEffect_Fail _ | EnrollEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the
/// extracted loop body.
let turn (#io_t: Type0) {| i: t_EnrollIo io_t |} (acc: io_t & t_EnrollTransition)
  : (io_t & t_EnrollTransition) =
  let (s, t) = acc in
  if enroll_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_EnrollIo io_t |} (n: nat)
  (acc: io_t & t_EnrollTransition)
  : Tot (io_t & t_EnrollTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_EnrollEvent) (evs: list t_EnrollEvent) : list t_EnrollEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_EnrollIo io_t |} (n: nat) (s: io_t)
  (t: t_EnrollTransition)
  : Pure (io_t & t_EnrollTransition & list t_EnrollEvent)
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
  (#io_t: Type0) {| i: t_EnrollIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_EnrollTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_EnrollTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_EnrollTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_EnrollTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_EnrollTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_EnrollIo io_t |} (n: nat) (s: io_t)
  (t: t_EnrollTransition)
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
let run_enroll_is_run_ev (#io_t: Type0) {| i: t_EnrollIo io_t |} (s: io_t)
  (start: t_EnrollTransition)
  : Lemma (requires sound_transition start)
          (ensures (let (s2, t2, _) = run_ev #io_t #i 5 s start in
                    run_enroll #io_t #i s start == (s2, t2))) =
  iter_turn_is_run_ev #io_t #i 5 s start;
  assert (v v_ENROLL_MAX_EFFECTS = 5);
  assert (run_enroll #io_t #i s start == iter_turn #io_t #i 5 (s, start))

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_EnrollTransition) (evs: list t_EnrollEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_EnrollIo io_t |} (n: nat) (s: io_t)
  (t: t_EnrollTransition)
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
let remaining (e: t_EnrollEffect) : nat =
  match e <: t_EnrollEffect with
  | EnrollEffect_ConsumeChallenge -> 5
  | EnrollEffect_CheckDevice -> 4
  | EnrollEffect_PrepareEnrollment -> 3
  | EnrollEffect_CheckAccount -> 2
  | EnrollEffect_InsertDevice -> 1
  | EnrollEffect_Complete | EnrollEffect_Fail _ | EnrollEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_EnrollTransition) (ev: t_EnrollEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match (t.f_effect <: t_EnrollEffect), (ev <: t_EnrollEvent) with
  | EnrollEffect_ConsumeChallenge, EnrollEvent_ChallengeConsumed _ -> ()
  | EnrollEffect_CheckDevice, EnrollEvent_DeviceChecked _ -> ()
  | EnrollEffect_PrepareEnrollment, EnrollEvent_EnrollmentPrepared _ -> ()
  | EnrollEffect_CheckAccount, EnrollEvent_AccountChecked _ -> ()
  | EnrollEffect_InsertDevice, EnrollEvent_DeviceInserted _ -> ()
  | _ -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_EnrollIo io_t |} (n: nat) (s: io_t)
  (t: t_EnrollTransition)
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
let run_enroll_theorem (#io_t: Type0) {| i: t_EnrollIo io_t |} (s: io_t)
  (start: t_EnrollTransition)
  : Lemma (requires sound_transition start)
          (ensures (
            let (_, t) = run_enroll #io_t #i s start in
            exists (evs: list t_EnrollEvent).
              responds start evs /\
              t.f_driver == run start.f_driver evs /\
              terminal t.f_effect /\
              trace_sound t.f_driver /\
              enroll_effect_is_sound t.f_driver t.f_effect)) =
  run_enroll_is_run_ev #io_t #i s start;
  run_ev_follows_the_driver #io_t #i 5 s start;
  run_ev_reaches_a_verdict #io_t #i 5 s start;
  let (_, t, evs) = run_ev #io_t #i 5 s start in
  ()

/// `POST /device/enroll`: whatever the executor returns, the loop stops and
/// the final state is the driver's `run_from_enroll` over the observations.
/// At most one insert decision is taken per request; a final inserted state is
/// behind the consumed enroll-purpose challenge, the approving device checks,
/// the verified new-key signature, the active rekey permit and the matching
/// account epoch; success and failure exclude each other and failure never
/// inserted.
let enroll_interpreter_theorem (#io_t: Type0) {| i: t_EnrollIo io_t |} (s: io_t)
  : Lemma (
      let t0 = begin_enroll () in
      let (_, t) = run_enroll #io_t #i s t0 in
      exists (evs: list t_EnrollEvent).
        responds t0 evs /\
        t.f_driver == run_from_enroll evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        insert_decisions t0.f_driver evs <= 1 /\
        (t.f_driver.f_inserted ==>
          (t.f_driver.f_challenge_consumed &&
           t.f_driver.f_challenge_purpose_enroll &&
           t.f_driver.f_device_active &&
           t.f_driver.f_auth_signature_verified &&
           t.f_driver.f_keys_valid &&
           t.f_driver.f_enrollment_signature_verified &&
           t.f_driver.f_epoch_positive &&
           t.f_driver.f_rekey_permitted &&
           t.f_driver.f_account_epoch_active)) /\
        (t.f_driver.f_succeeded ==> t.f_driver.f_inserted) /\
        (t.f_driver.f_failed ==> not t.f_driver.f_inserted) /\
        not (t.f_driver.f_succeeded && t.f_driver.f_failed)) =
  let t0 = begin_enroll () in
  run_enroll_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 5 s t0 in
  run_ev_follows_the_driver #io_t #i 5 s t0;
  run_ev_reaches_a_verdict #io_t #i 5 s t0;
  insert_decisions_from_begin_le_one evs;
  inserted_implies_approvals t.f_driver;
  succeeded_implies_inserted t.f_driver;
  failed_implies_not_inserted t.f_driver;
  success_excludes_failure t.f_driver;
  assert (run_from_enroll evs == run t0.f_driver evs)
