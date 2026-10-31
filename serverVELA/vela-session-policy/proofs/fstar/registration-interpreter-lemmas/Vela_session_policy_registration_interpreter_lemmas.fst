module Vela_session_policy_registration_interpreter_lemmas

/// The extracted `run_registration` is the loop `POST /account/register` runs:
/// the server expands the same `registration_interpreter!` macro text, adding
/// only `.await` after each executor call. This module proves, for every
/// executor implementation (any `t_RegistrationIo` instance, any behaviour):
///
/// 1. `run_registration` calls the executor exactly as `run_ev` below does:
///    one method per turn, chosen by the effect the driver just emitted, and
///    nothing once the driver reached a verdict
///    (`run_registration_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_observation observation evs`
///    (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of eight
///    turns (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request registration theorem holds for the state the
///    real handler ends in (`run_registration_theorem`).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), the transaction's rollback on
/// drop, and the macro expansion (the server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_session_policy.Registration_driver
open Vela_session_policy.Registration_interpreter
open Vela_session_policy_registration_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_RegistrationEffect) : bool =
  match e <: t_RegistrationEffect with
  | RegistrationEffect_Complete | RegistrationEffect_Fail _ | RegistrationEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_RegistrationEffect) (ev: t_RegistrationEvent) : bool =
  match e, ev with
  | RegistrationEffect_CheckRateLimit, RegistrationEvent_RateLimitObserved _
  | RegistrationEffect_CheckAccountBudget, RegistrationEvent_BudgetObserved _
  | RegistrationEffect_BeginTransaction, RegistrationEvent_TransactionObserved _
  | RegistrationEffect_InsertAccount, RegistrationEvent_AccountInserted _
  | RegistrationEffect_InsertDevice, RegistrationEvent_DeviceInserted _
  | RegistrationEffect_CommitTransaction, RegistrationEvent_CommitObserved _
  | RegistrationEffect_IssueToken, RegistrationEvent_TokenObserved _
  | RegistrationEffect_TrackToken, RegistrationEvent_TrackObserved _ -> true
  | _ -> false

let sound_transition (t: t_RegistrationTransition) : bool =
  registration_state_is_sound t.f_driver &&
  registration_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_RegistrationIo io_t |} (s: io_t)
    (t: t_RegistrationTransition)
  : Pure (io_t & t_RegistrationTransition & option t_RegistrationEvent)
    (requires registration_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect <: t_RegistrationEffect with
  | RegistrationEffect_CheckRateLimit ->
      let (s', o) = f_check_rate_limit #io_t #i s in
      let ev = RegistrationEvent_RateLimitObserved o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_CheckAccountBudget ->
      let (s', o) = f_check_account_budget #io_t #i s in
      let ev = RegistrationEvent_BudgetObserved o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_BeginTransaction ->
      let (s', o) = f_begin_transaction #io_t #i s in
      let ev = RegistrationEvent_TransactionObserved o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_InsertAccount ->
      let (s', o) = f_insert_account #io_t #i s in
      let ev = RegistrationEvent_AccountInserted o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_InsertDevice ->
      let (s', o) = f_insert_device #io_t #i s in
      let ev = RegistrationEvent_DeviceInserted o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_CommitTransaction ->
      let (s', o) = f_commit #io_t #i s in
      let ev = RegistrationEvent_CommitObserved o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_IssueToken ->
      let (s', o) = f_issue_token #io_t #i s in
      let ev = RegistrationEvent_TokenObserved o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_TrackToken ->
      let (s', o) = f_track_token #io_t #i s in
      let ev = RegistrationEvent_TrackObserved o in
      (s', step t.f_driver ev, Some ev)
  | RegistrationEffect_Complete | RegistrationEffect_Fail _ | RegistrationEffect_Idle ->
      (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the
/// extracted loop body.
let turn (#io_t: Type0) {| i: t_RegistrationIo io_t |}
    (acc: io_t & t_RegistrationTransition)
  : (io_t & t_RegistrationTransition) =
  let (s, t) = acc in
  if registration_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_RegistrationIo io_t |} (n: nat)
    (acc: io_t & t_RegistrationTransition)
  : Tot (io_t & t_RegistrationTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_RegistrationEvent)
    (evs: list t_RegistrationEvent) : list t_RegistrationEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_RegistrationIo io_t |} (n: nat) (s: io_t)
    (t: t_RegistrationTransition)
  : Pure (io_t & t_RegistrationTransition & list t_RegistrationEvent)
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
  (#io_t: Type0) {| i: t_RegistrationIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_RegistrationTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_RegistrationTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_RegistrationTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_RegistrationTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_RegistrationTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_RegistrationIo io_t |} (n: nat) (s: io_t)
    (t: t_RegistrationTransition)
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
let run_registration_is_run_ev (#io_t: Type0) {| i: t_RegistrationIo io_t |} (s: io_t)
    (observation: t_RegistrationRequestObservation)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 8 s (begin_registration observation) in
           run_registration #io_t #i s observation == (s2, t2)) =
  let t0 = begin_registration observation in
  iter_turn_is_run_ev #io_t #i 8 s t0;
  assert (v v_REGISTRATION_MAX_EFFECTS = 8);
  assert (run_registration #io_t #i s observation == iter_turn #io_t #i 8 (s, t0))

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_RegistrationTransition) (evs: list t_RegistrationEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_RegistrationIo io_t |}
    (n: nat) (s: io_t) (t: t_RegistrationTransition)
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
let remaining (e: t_RegistrationEffect) : nat =
  match e <: t_RegistrationEffect with
  | RegistrationEffect_CheckRateLimit -> 8
  | RegistrationEffect_CheckAccountBudget -> 7
  | RegistrationEffect_BeginTransaction -> 6
  | RegistrationEffect_InsertAccount -> 5
  | RegistrationEffect_InsertDevice -> 4
  | RegistrationEffect_CommitTransaction -> 3
  | RegistrationEffect_IssueToken -> 2
  | RegistrationEffect_TrackToken -> 1
  | RegistrationEffect_Complete | RegistrationEffect_Fail _ | RegistrationEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_RegistrationTransition) (ev: t_RegistrationEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect <: t_RegistrationEffect with
  | RegistrationEffect_CheckRateLimit -> ()
  | RegistrationEffect_CheckAccountBudget -> ()
  | RegistrationEffect_BeginTransaction -> ()
  | RegistrationEffect_InsertAccount -> ()
  | RegistrationEffect_InsertDevice -> ()
  | RegistrationEffect_CommitTransaction -> ()
  | RegistrationEffect_IssueToken -> ()
  | RegistrationEffect_TrackToken -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_RegistrationIo io_t |}
    (n: nat) (s: io_t) (t: t_RegistrationTransition)
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

let run_registration_theorem (#io_t: Type0) {| i: t_RegistrationIo io_t |} (s: io_t)
    (observation: t_RegistrationRequestObservation)
  : Lemma (
      let (_, t) = run_registration #io_t #i s observation in
      exists (evs: list t_RegistrationEvent).
        responds (begin_registration observation) evs /\
        t.f_driver == run_from_observation observation evs /\
        terminal t.f_effect /\
        registration_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         trace_sound d /\
         (d.f_responded ==>
           (d.f_account_inserted && d.f_device_inserted && d.f_committed &&
            d.f_token_issued && d.f_token_tracked)) /\
         (d.f_committed ==> (d.f_device_inserted && d.f_account_inserted)) /\
         (d.f_device_inserted ==> d.f_account_inserted) /\
         not (d.f_responded && d.f_failed) /\
         count_complete (begin_registration observation).f_driver evs <= 1 /\
         count_fail (begin_registration observation).f_driver evs <= 1)) =
  let t0 = begin_registration observation in
  run_registration_is_run_ev #io_t #i s observation;
  run_ev_follows_the_driver #io_t #i 8 s t0;
  run_ev_reaches_a_verdict #io_t #i 8 s t0;
  let (_, t2, evs) = run_ev #io_t #i 8 s t0 in
  registration_trace_theorem observation evs

/// Cancellation (POST /account/register): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver state
/// whose next effect agrees with it.
let registration_cancellation (#io_t: Type0) {| i: t_RegistrationIo io_t |} (k: nat) (s: io_t)
  (t: t_RegistrationTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in sound_transition t2)) =
  iter_turn_is_run_ev #io_t #i k s t
