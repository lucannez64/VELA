module Vela_session_policy_login_interpreter_lemmas

/// The extracted `run_login` is the loop `/auth/verify` runs: the server
/// expands the same `login_interpreter!` macro text, adding only `.await` after
/// each executor call. This module proves, for every executor implementation
/// (any `t_LoginIo` instance, any behaviour):
///
/// 1. `run_login` calls the executor exactly as `run_ev` below does: one method
///    per turn, chosen by the effect the driver has just emitted, and nothing
///    once the driver reached a verdict (`run_login_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_begin evs` (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of six turns
///    (`run_ev_reaches_a_verdict`);
/// 4. hence the per-request login theorem holds for the state the real handler
///    ends in (`run_login_theorem`).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_session_policy.Login_driver
open Vela_session_policy.Login_interpreter
open Vela_session_policy_login_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_LoginEffect) : bool =
  match e with
  | LoginEffect_Respond | LoginEffect_Fail _ | LoginEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_LoginEffect) (ev: t_LoginEvent) : bool =
  match e, ev with
  | LoginEffect_ConsumeChallenge, LoginEvent_ChallengeObserved _
  | LoginEffect_ObserveDevice, LoginEvent_DeviceObserved _
  | LoginEffect_VerifySignature, LoginEvent_VerifierObserved _
  | LoginEffect_RecordVerificationFailure, LoginEvent_FailureRecorded _
  | LoginEffect_ResetBackoff, LoginEvent_BackoffResetObserved _
  | LoginEffect_IssueToken, LoginEvent_TokenIssued _
  | LoginEffect_TrackToken, LoginEvent_TokenTracked _ -> true
  | _ -> false

let sound_transition (t: t_LoginTransition) : bool =
  login_state_is_sound t.f_driver && login_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_LoginIo io_t |} (s: io_t) (t: t_LoginTransition)
  : Pure (io_t & t_LoginTransition & option t_LoginEvent)
    (requires login_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | LoginEffect_ConsumeChallenge ->
      let (s', o) = f_consume_challenge #io_t #i s in
      let ev = LoginEvent_ChallengeObserved o in
      (s', step t.f_driver ev, Some ev)
  | LoginEffect_ObserveDevice ->
      let (s', o) = f_observe_device #io_t #i s in
      let ev = LoginEvent_DeviceObserved o in
      (s', step t.f_driver ev, Some ev)
  | LoginEffect_VerifySignature ->
      let (s', o) = f_verify_signature #io_t #i s in
      let ev = LoginEvent_VerifierObserved o in
      (s', step t.f_driver ev, Some ev)
  | LoginEffect_RecordVerificationFailure ->
      let (s', o) = f_record_verification_failure #io_t #i s in
      let ev = LoginEvent_FailureRecorded o in
      (s', step t.f_driver ev, Some ev)
  | LoginEffect_ResetBackoff ->
      let (s', o) = f_reset_backoff #io_t #i s in
      let ev = LoginEvent_BackoffResetObserved o in
      (s', step t.f_driver ev, Some ev)
  | LoginEffect_IssueToken ->
      let (s', o) = f_issue_token #io_t #i s in
      let ev = LoginEvent_TokenIssued o in
      (s', step t.f_driver ev, Some ev)
  | LoginEffect_TrackToken ->
      let (s', o) = f_track_token #io_t #i s in
      let ev = LoginEvent_TokenTracked o in
      (s', step t.f_driver ev, Some ev)
  | LoginEffect_Respond | LoginEffect_Fail _ | LoginEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the extracted
/// loop body.
let turn (#io_t: Type0) {| i: t_LoginIo io_t |} (acc: io_t & t_LoginTransition)
  : (io_t & t_LoginTransition) =
  let (s, t) = acc in
  if login_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_LoginIo io_t |} (n: nat)
  (acc: io_t & t_LoginTransition)
  : Tot (io_t & t_LoginTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_LoginEvent) (evs: list t_LoginEvent) : list t_LoginEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_LoginIo io_t |} (n: nat) (s: io_t)
  (t: t_LoginTransition)
  : Pure (io_t & t_LoginTransition & list t_LoginEvent)
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
  (#io_t: Type0) {| i: t_LoginIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_LoginTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_LoginTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_LoginTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_LoginTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_LoginTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_LoginIo io_t |} (n: nat) (s: io_t)
  (t: t_LoginTransition)
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
let run_login_is_run_ev (#io_t: Type0) {| i: t_LoginIo io_t |} (s: io_t)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 6 s (begin_login ()) in
           run_login #io_t #i s == (s2, t2)) =
  let t0 = begin_login () in
  iter_turn_is_run_ev #io_t #i 6 s t0;
  assert (v v_LOGIN_MAX_EFFECTS = 6);
  assert (run_login #io_t #i s == iter_turn #io_t #i 6 (s, t0))

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_LoginTransition) (evs: list t_LoginEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_LoginIo io_t |} (n: nat) (s: io_t)
  (t: t_LoginTransition)
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
let remaining (e: t_LoginEffect) : nat =
  match e with
  | LoginEffect_ConsumeChallenge -> 6
  | LoginEffect_ObserveDevice -> 5
  | LoginEffect_VerifySignature -> 4
  | LoginEffect_RecordVerificationFailure -> 1
  | LoginEffect_ResetBackoff -> 3
  | LoginEffect_IssueToken -> 2
  | LoginEffect_TrackToken -> 1
  | LoginEffect_Respond | LoginEffect_Fail _ | LoginEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_LoginTransition) (ev: t_LoginEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\
                     responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect <: t_LoginEffect with
  | LoginEffect_ConsumeChallenge -> ()
  | LoginEffect_ObserveDevice -> ()
  | LoginEffect_VerifySignature -> ()
  | LoginEffect_RecordVerificationFailure -> ()
  | LoginEffect_ResetBackoff -> ()
  | LoginEffect_IssueToken -> ()
  | LoginEffect_TrackToken -> ()
  | LoginEffect_Respond | LoginEffect_Fail _ | LoginEffect_Idle -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_LoginIo io_t |} (n: nat) (s: io_t)
  (t: t_LoginTransition)
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

let run_login_theorem (#io_t: Type0) {| i: t_LoginIo io_t |} (s: io_t)
  : Lemma (
      let (_, t) = run_login #io_t #i s in
      exists (evs: list t_LoginEvent).
        responds (begin_login ()) evs /\
        t.f_driver == run_from_begin evs /\
        terminal t.f_effect /\
        login_effect_is_sound t.f_driver t.f_effect /\
        (let d = run_from_begin evs in
         trace_sound d /\
         (d.f_responded ==> not d.f_failed) /\
         (d.f_failed ==> not d.f_responded) /\
         count_respond_from_begin evs <= 1 /\
         (d.f_responded ==> has_accepted_event evs) /\
         (d.f_responded ==> has_valid_verifier_event evs) /\
         (d.f_responded ==> has_tracked_event evs))) =
  let t0 = begin_login () in
  run_login_is_run_ev #io_t #i s;
  run_ev_follows_the_driver #io_t #i 6 s t0;
  run_ev_reaches_a_verdict #io_t #i 6 s t0;
  let (_, t2, evs) = run_ev #io_t #i 6 s t0 in
  login_trace_theorem evs
