module Vela_session_policy_revocation_interpreter_lemmas

/// The extracted `run_revocation` and `run_logout` are the loops
/// `/device/revoke` and `/auth/logout` run: the server expands the same
/// `revocation_interpreter!` and `logout_interpreter!` macro text, adding only
/// `.await` after each executor call. This module proves, for every executor
/// implementation (any `t_RevocationIo` or `t_LogoutIo` instance, any
/// behaviour):
///
/// 1. each loop calls the executor exactly as `run_ev` below does: one method
///    per turn, chosen by the effect the driver has just emitted, and nothing
///    once the driver reached a verdict (`run_revocation_is_run_ev`,
///    `run_logout_is_run_ev`);
/// 2. the observations the executor returned form a list in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_actor actor evs` / `logout_run_from_begin observations`
///    (`run_ev_follows_the_driver`, `logout_run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of four
///    revocation turns and one logout turn (`run_ev_reaches_a_verdict`,
///    `logout_run_ev_reaches_a_verdict`);
/// 4. hence the per-request revocation and logout theorems hold for the state
///    the real handlers end in (`run_revocation_theorem`,
///    `run_logout_theorem`).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), the macro expansion (the
/// server's copies differ only by `.await`), and `plan_admission`, which is a
/// single pure decision with no effect loop to interpret.

open FStar.Mul
open Core_models
open Vela_session_policy.Revocation_driver
open Vela_session_policy.Revocation_interpreter
open Vela_session_policy_revocation_driver_lemmas

// ══ Revocation ════════════════════════════════════════════════════════════

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_RevocationEffect) : bool =
  match e with
  | RevocationEffect_Complete | RevocationEffect_Fail _ | RevocationEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_RevocationEffect) (ev: t_RevocationEvent) : bool =
  match e, ev with
  | RevocationEffect_LookupTarget, RevocationEvent_TargetObserved _
  | RevocationEffect_LockoutDevice, RevocationEvent_LockoutObserved _
  | RevocationEffect_RecordRevocation, RevocationEvent_RecordObserved _
  | RevocationEffect_CascadeWebSessions, RevocationEvent_CascadeObserved _ -> true
  | _ -> false

let sound_transition (t: t_RevocationTransition) : bool =
  revocation_state_is_sound t.f_driver &&
  revocation_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_RevocationIo io_t |} (s: io_t)
  (t: t_RevocationTransition)
  : Pure (io_t & t_RevocationTransition & option t_RevocationEvent)
    (requires revocation_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | RevocationEffect_LookupTarget ->
      let (s', o) = f_lookup_target #io_t #i s in
      let ev = RevocationEvent_TargetObserved o in
      (s', step t.f_driver ev, Some ev)
  | RevocationEffect_LockoutDevice ->
      let (s', o) = f_lockout_device #io_t #i s in
      let ev = RevocationEvent_LockoutObserved o in
      (s', step t.f_driver ev, Some ev)
  | RevocationEffect_RecordRevocation ->
      let (s', o) = f_record_revocation #io_t #i s in
      let ev = RevocationEvent_RecordObserved o in
      (s', step t.f_driver ev, Some ev)
  | RevocationEffect_CascadeWebSessions ->
      let (s', o) = f_cascade_web_sessions #io_t #i s in
      let ev = RevocationEvent_CascadeObserved o in
      (s', step t.f_driver ev, Some ev)
  | RevocationEffect_Complete | RevocationEffect_Fail _ | RevocationEffect_Idle ->
      (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the extracted
/// loop body.
let turn (#io_t: Type0) {| i: t_RevocationIo io_t |} (acc: io_t & t_RevocationTransition)
  : (io_t & t_RevocationTransition) =
  let (s, t) = acc in
  if revocation_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_RevocationIo io_t |} (n: nat)
  (acc: io_t & t_RevocationTransition)
  : Tot (io_t & t_RevocationTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_RevocationEvent) (evs: list t_RevocationEvent)
  : list t_RevocationEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_RevocationIo io_t |} (n: nat) (s: io_t)
  (t: t_RevocationTransition)
  : Pure (io_t & t_RevocationTransition & list t_RevocationEvent)
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
  (#io_t: Type0) {| i: t_RevocationIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_RevocationTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_RevocationTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_RevocationTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_RevocationTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_RevocationTransition))
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

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_RevocationIo io_t |} (n: nat) (s: io_t)
  (t: t_RevocationTransition)
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
let run_revocation_is_run_ev (#io_t: Type0) {| i: t_RevocationIo io_t |} (s: io_t)
  (actor: t_ActorObservation)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 4 s (begin_revocation actor) in
           run_revocation #io_t #i s actor == (s2, t2)) =
  let t0 = begin_revocation actor in
  iter_turn_is_run_ev #io_t #i 4 s t0;
  assert (v v_REVOCATION_MAX_EFFECTS = 4);
  assert (run_revocation #io_t #i s actor == iter_turn #io_t #i 4 (s, t0))

// ── 1b. Cancellation: every prefix is a sound driver state ────────────────

/// A dropped handler future stops the revocation loop after an arbitrary
/// prefix of turns. For every executor, every `k` and every sound start, the
/// state after `k` turns is sound: `revocation_state_is_sound` carries the
/// per-request state invariants (a recorded revocation implies the lockout and
/// the target were observed, a cascade implies the lockout, and a terminal
/// verdict never claims both success and failure), and the next effect agrees
/// with the state that produced it.
let revocation_cancellation (#io_t: Type0) {| i: t_RevocationIo io_t |} (k: nat)
  (s: io_t) (t: t_RevocationTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in sound_transition t2)) =
  let (_, t2, _) = run_ev #io_t #i k s t in
  iter_turn_is_run_ev #io_t #i k s t

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_RevocationTransition) (evs: list t_RevocationEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_RevocationIo io_t |} (n: nat)
  (s: io_t) (t: t_RevocationTransition)
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
let remaining (e: t_RevocationEffect) : nat =
  match e with
  | RevocationEffect_LookupTarget -> 4
  | RevocationEffect_LockoutDevice -> 3
  | RevocationEffect_RecordRevocation -> 2
  | RevocationEffect_CascadeWebSessions -> 1
  | RevocationEffect_Complete | RevocationEffect_Fail _ | RevocationEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_RevocationTransition) (ev: t_RevocationEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\
                     responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect <: t_RevocationEffect with
  | RevocationEffect_LookupTarget -> ()
  | RevocationEffect_LockoutDevice -> ()
  | RevocationEffect_RecordRevocation -> ()
  | RevocationEffect_CascadeWebSessions -> ()
  | RevocationEffect_Complete | RevocationEffect_Fail _ | RevocationEffect_Idle -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_RevocationIo io_t |} (n: nat)
  (s: io_t) (t: t_RevocationTransition)
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

let run_revocation_theorem (#io_t: Type0) {| i: t_RevocationIo io_t |} (s: io_t)
  (actor: t_ActorObservation)
  : Lemma (
      let (_, t) = run_revocation #io_t #i s actor in
      exists (evs: list t_RevocationEvent).
        responds (begin_revocation actor) evs /\
        t.f_driver == run_from_actor actor evs /\
        terminal t.f_effect /\
        revocation_effect_is_sound t.f_driver t.f_effect /\
        (let d = run_from_actor actor evs in
         trace_sound d /\
         (d.f_responded ==> (d.f_recorded && d.f_cascade_done && not d.f_already_revoked)) /\
         (d.f_recorded ==> (d.f_locked_out && d.f_lockout_done)) /\
         (d.f_cascade_done ==>
            (d.f_locked_out && d.f_lockout_done && (d.f_recorded || d.f_already_revoked))) /\
         not (d.f_responded && d.f_failed) /\
         count_complete (begin_revocation actor).f_driver evs <= 1 /\
         count_fail (begin_revocation actor).f_driver evs <= 1 /\
         trace_order (begin_revocation actor).f_driver evs 0)) =
  let t0 = begin_revocation actor in
  run_revocation_is_run_ev #io_t #i s actor;
  run_ev_follows_the_driver #io_t #i 4 s t0;
  run_ev_reaches_a_verdict #io_t #i 4 s t0;
  let (_, t2, evs) = run_ev #io_t #i 4 s t0 in
  revocation_trace_theorem actor evs

// ══ Logout ════════════════════════════════════════════════════════════════

// ── The specification of one interpreter turn ─────────────────────────────

let logout_terminal (e: t_LogoutEffect) : bool =
  match e with
  | LogoutEffect_Complete | LogoutEffect_Fail _ | LogoutEffect_Idle -> true
  | _ -> false

/// The single JTI write is the only effect that expects an observation.
let logout_responds_to (e: t_LogoutEffect) (_: t_LogoutObservation) : bool =
  match e with
  | LogoutEffect_RevokeJti -> true
  | _ -> false

let logout_sound_transition (t: t_LogoutTransition) : bool =
  logout_state_is_sound t.f_driver && logout_effect_is_sound t.f_driver t.f_effect

/// One turn: write the JTI marker for the current effect, feed the observation
/// to the extracted `logout_step`, and report it. A verdict performs nothing.
let logout_turn_ev (#io_t: Type0) {| i: t_LogoutIo io_t |} (s: io_t)
  (t: t_LogoutTransition)
  : Pure (io_t & t_LogoutTransition & option t_LogoutObservation)
    (requires logout_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | LogoutEffect_RevokeJti ->
      let (s', o) = f_revoke_jti #io_t #i s in
      (s', logout_step t.f_driver o, Some o)
  | LogoutEffect_Complete | LogoutEffect_Fail _ | LogoutEffect_Idle -> (s, t, None)

/// `logout_turn_ev` without the observation.
let logout_turn (#io_t: Type0) {| i: t_LogoutIo io_t |}
  (acc: io_t & t_LogoutTransition)
  : (io_t & t_LogoutTransition) =
  let (s, t) = acc in
  if logout_state_is_sound t.f_driver
  then let (s', t', _) = logout_turn_ev #io_t #i s t in (s', t')
  else acc

let rec logout_iter_turn (#io_t: Type0) {| i: t_LogoutIo io_t |} (n: nat)
  (acc: io_t & t_LogoutTransition)
  : Tot (io_t & t_LogoutTransition) (decreases n) =
  if n = 0 then acc else logout_iter_turn #io_t #i (n - 1) (logout_turn #io_t #i acc)

let logout_cons_opt (o: option t_LogoutObservation) (observations: list t_LogoutObservation)
  : list t_LogoutObservation =
  match o with
  | None -> observations
  | Some observation -> observation :: observations

/// `n` turns, collecting the observations in order.
let rec logout_run_ev (#io_t: Type0) {| i: t_LogoutIo io_t |} (n: nat) (s: io_t)
  (t: t_LogoutTransition)
  : Pure (io_t & t_LogoutTransition & list t_LogoutObservation)
    (requires logout_sound_transition t)
    (ensures fun (_, t', _) -> logout_sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = logout_turn_ev #io_t #i s t in
    let (s2, t2, observations) = logout_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, logout_cons_opt o observations)

// ── 1. The extracted loop is `logout_run_ev` ─────────────────────────────

let rec fold_range_is_logout_iter_turn
  (#io_t: Type0) {| i: t_LogoutIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_LogoutTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_LogoutTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_LogoutTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_LogoutTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_LogoutTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == logout_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              logout_iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (logout_iter_turn #io_t #i n init)] =
  if v start < v end_
  then fold_range_is_logout_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec logout_iter_turn_is_run_ev (#io_t: Type0) {| i: t_LogoutIo io_t |} (n: nat) (s: io_t)
  (t: t_LogoutTransition)
  : Lemma (requires logout_sound_transition t)
          (ensures (let (s2, t2, _) = logout_run_ev #io_t #i n s t in
                    logout_iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = logout_turn_ev #io_t #i s t in
    logout_iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

/// The extracted loop calls the executor exactly as `logout_run_ev` does.
let run_logout_is_run_ev (#io_t: Type0) {| i: t_LogoutIo io_t |} (s: io_t)
  : Lemma (let (s2, t2, _) = logout_run_ev #io_t #i 1 s (begin_logout ()) in
           run_logout #io_t #i s == (s2, t2)) =
  let t0 = begin_logout () in
  logout_iter_turn_is_run_ev #io_t #i 1 s t0;
  assert (v v_LOGOUT_MAX_EFFECTS = 1);
  assert (run_logout #io_t #i s == logout_iter_turn #io_t #i 1 (s, t0))

/// A dropped logout future stops the loop after the single marker write, or
/// before it. For every executor and every `k`, the state after `k` turns is
/// sound; `logout_state_is_sound` carries the per-request invariant that a
/// completed logout wrote the JTI marker and a failure wrote nothing.
let logout_cancellation (#io_t: Type0) {| i: t_LogoutIo io_t |} (k: nat) (s: io_t)
  (t: t_LogoutTransition)
  : Lemma (requires logout_sound_transition t)
          (ensures (let (_, t2) = logout_iter_turn #io_t #i k (s, t) in
                    logout_sound_transition t2)) =
  let (_, t2, _) = logout_run_ev #io_t #i k s t in
  logout_iter_turn_is_run_ev #io_t #i k s t

// ── 2. The observations drive the extracted driver ────────────────────────

let rec logout_responds (t: t_LogoutTransition) (observations: list t_LogoutObservation)
  : Pure bool (requires logout_sound_transition t) (ensures fun _ -> True)
    (decreases observations) =
  match observations with
  | [] -> true
  | observation :: rest ->
      not (logout_terminal t.f_effect) && logout_responds_to t.f_effect observation &&
      logout_responds (logout_step t.f_driver observation) rest

let rec logout_run_ev_follows_the_driver (#io_t: Type0) {| i: t_LogoutIo io_t |}
  (n: nat) (s: io_t) (t: t_LogoutTransition)
  : Lemma (requires logout_sound_transition t)
          (ensures (let (_, t2, observations) = logout_run_ev #io_t #i n s t in
                    logout_trace_sound t.f_driver /\
                    logout_responds t observations /\
                    t2.f_driver == logout_run t.f_driver observations))
          (decreases n) =
  logout_trace_sound_matches_rust t.f_driver;
  if n = 0 then ()
  else begin
    let (s1, t1, o) = logout_turn_ev #io_t #i s t in
    logout_run_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some observation -> logout_step_sound t.f_driver observation
  end

// ── 3. A verdict within the budget ────────────────────────────────────────

/// Effects still to perform before a verdict, at most.
let logout_remaining (e: t_LogoutEffect) : nat =
  match e with
  | LogoutEffect_RevokeJti -> 1
  | LogoutEffect_Complete | LogoutEffect_Fail _ | LogoutEffect_Idle -> 0

let logout_step_decreases (t: t_LogoutTransition) (observation: t_LogoutObservation)
  : Lemma (requires logout_sound_transition t /\ not (logout_terminal t.f_effect) /\
                     logout_responds_to t.f_effect observation)
          (ensures logout_remaining (logout_step t.f_driver observation).f_effect <
                   logout_remaining t.f_effect) =
  match t.f_effect <: t_LogoutEffect with
  | LogoutEffect_RevokeJti -> ()
  | LogoutEffect_Complete | LogoutEffect_Fail _ | LogoutEffect_Idle -> ()

let rec logout_run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_LogoutIo io_t |}
  (n: nat) (s: io_t) (t: t_LogoutTransition)
  : Lemma (requires logout_sound_transition t /\ logout_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = logout_run_ev #io_t #i n s t in
                    logout_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = logout_turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some observation -> logout_step_decreases t observation);
    logout_run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

// ── 4. The handler's final state satisfies the per-request theorem ────────

let run_logout_theorem (#io_t: Type0) {| i: t_LogoutIo io_t |} (s: io_t)
  : Lemma (
      let (_, t) = run_logout #io_t #i s in
      exists (observations: list t_LogoutObservation).
        logout_responds (begin_logout ()) observations /\
        t.f_driver == logout_run_from_begin observations /\
        logout_terminal t.f_effect /\
        logout_effect_is_sound t.f_driver t.f_effect /\
        (let d = logout_run_from_begin observations in
         logout_trace_sound d /\
         (d.f_responded ==> d.f_jti_revoked) /\
         not (d.f_responded && d.f_failed))) =
  let t0 = begin_logout () in
  run_logout_is_run_ev #io_t #i s;
  logout_run_ev_follows_the_driver #io_t #i 1 s t0;
  logout_run_ev_reaches_a_verdict #io_t #i 1 s t0;
  let (_, t2, observations) = logout_run_ev #io_t #i 1 s t0 in
  logout_success_implies_marker observations
