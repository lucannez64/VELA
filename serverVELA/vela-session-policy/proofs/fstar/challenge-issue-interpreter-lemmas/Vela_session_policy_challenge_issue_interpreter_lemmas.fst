module Vela_session_policy_challenge_issue_interpreter_lemmas

/// The extracted `run_issue` is the loop `GET /auth/challenge` runs: the server
/// expands the same `challenge_issue_interpreter!` macro text, adding only
/// `.await` after each executor call. This module proves, for every executor
/// implementation (any `t_ChallengeIssueIo` instance, any behaviour):
///
/// 1. `run_issue` calls the executor exactly as `run_ev` below does: one
///    method per turn, chosen by the effect the driver just emitted, with the
///    parsed purpose for the store, and nothing once the driver reached a
///    verdict (`run_issue_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_purpose purpose evs` (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of three
///    turns (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request issue theorem holds for the state the real
///    handler ends in (`run_issue_theorem`).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge_issue_driver
open Vela_session_policy.Challenge_issue_interpreter
open Vela_session_policy_challenge_issue_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_IssueEffect) : bool =
  match e <: t_IssueEffect with
  | IssueEffect_Issue | IssueEffect_Fail _ | IssueEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_IssueEffect) (ev: t_IssueEvent) : bool =
  match e, ev with
  | IssueEffect_CheckRateLimit, IssueEvent_RateLimitObserved _
  | IssueEffect_GenerateNonce, IssueEvent_NonceObserved _
  | IssueEffect_StoreNonce, IssueEvent_StoreObserved _ -> true
  | _ -> false

let sound_transition (t: t_IssueTransition) : bool =
  issue_state_is_sound t.f_driver && issue_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |} (s: io_t) (t: t_IssueTransition)
  : Pure (io_t & t_IssueTransition & option t_IssueEvent)
    (requires issue_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect <: t_IssueEffect with
  | IssueEffect_CheckRateLimit ->
      let (s', o) = f_check_rate_limit #io_t #i s in
      let ev = IssueEvent_RateLimitObserved o in
      (s', step t.f_driver ev, Some ev)
  | IssueEffect_GenerateNonce ->
      let (s', o) = f_generate_nonce #io_t #i s in
      let ev = IssueEvent_NonceObserved o in
      (s', step t.f_driver ev, Some ev)
  | IssueEffect_StoreNonce ->
      let (s', o) = f_store_nonce #io_t #i s t.f_driver.f_purpose in
      let ev = IssueEvent_StoreObserved o in
      (s', step t.f_driver ev, Some ev)
  | IssueEffect_Issue | IssueEffect_Fail _ | IssueEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the
/// extracted loop body.
let turn (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |}
    (acc: io_t & t_IssueTransition)
  : (io_t & t_IssueTransition) =
  let (s, t) = acc in
  if issue_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |} (n: nat)
    (acc: io_t & t_IssueTransition)
  : Tot (io_t & t_IssueTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_IssueEvent) (evs: list t_IssueEvent) : list t_IssueEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |} (n: nat) (s: io_t)
    (t: t_IssueTransition)
  : Pure (io_t & t_IssueTransition & list t_IssueEvent)
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
  (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_IssueTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_IssueTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_IssueTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_IssueTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_IssueTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |} (n: nat) (s: io_t)
    (t: t_IssueTransition)
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
let run_issue_is_run_ev (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |} (s: io_t)
    (purpose: t_PurposeObservation)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 3 s (begin_issue purpose) in
           run_issue #io_t #i s purpose == (s2, t2)) =
  let t0 = begin_issue purpose in
  iter_turn_is_run_ev #io_t #i 3 s t0;
  assert (v v_ISSUE_MAX_EFFECTS = 3);
  assert (run_issue #io_t #i s purpose == iter_turn #io_t #i 3 (s, t0))

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_IssueTransition) (evs: list t_IssueEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |}
    (n: nat) (s: io_t) (t: t_IssueTransition)
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
let remaining (e: t_IssueEffect) : nat =
  match e <: t_IssueEffect with
  | IssueEffect_CheckRateLimit -> 3
  | IssueEffect_GenerateNonce -> 2
  | IssueEffect_StoreNonce -> 1
  | IssueEffect_Issue | IssueEffect_Fail _ | IssueEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_IssueTransition) (ev: t_IssueEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect <: t_IssueEffect with
  | IssueEffect_CheckRateLimit -> ()
  | IssueEffect_GenerateNonce -> ()
  | IssueEffect_StoreNonce -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |}
    (n: nat) (s: io_t) (t: t_IssueTransition)
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

// ── 4. The handler's final state satisfies the per-request theorem ────────

let run_issue_theorem (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |} (s: io_t)
    (purpose: t_PurposeObservation)
  : Lemma (
      let (_, t) = run_issue #io_t #i s purpose in
      exists (evs: list t_IssueEvent).
        responds (begin_issue purpose) evs /\
        t.f_driver == run_from_purpose purpose evs /\
        terminal t.f_effect /\
        issue_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         trace_sound d /\
         (d.f_issued ==> (d.f_purpose_valid && d.f_rate_allowed && d.f_nonce_valid && d.f_stored_fresh)) /\
         (d.f_stored_fresh ==> d.f_purpose_valid) /\
         not (d.f_issued && d.f_failed) /\
         count_issue (begin_issue purpose).f_driver evs <= 1 /\
         count_fail (begin_issue purpose).f_driver evs <= 1 /\
         count_store (begin_issue purpose).f_driver evs <= 1 /\
         count_nonce (begin_issue purpose).f_driver evs <= 1)) =
  let t0 = begin_issue purpose in
  run_issue_is_run_ev #io_t #i s purpose;
  run_ev_follows_the_driver #io_t #i 3 s t0;
  run_ev_reaches_a_verdict #io_t #i 3 s t0;
  let (_, t2, evs) = run_ev #io_t #i 3 s t0 in
  issue_trace_theorem purpose evs

/// Cancellation (POST /auth/challenge): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver state
/// whose next effect agrees with it.
let challenge_issue_cancellation (#io_t: Type0) {| i: t_ChallengeIssueIo io_t |} (k: nat) (s: io_t)
  (t: t_IssueTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in sound_transition t2)) =
  iter_turn_is_run_ev #io_t #i k s t
