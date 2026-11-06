module Vela_recovery_policy_webauthn_interpreter_lemmas

/// The extracted `run_registration_start`, `run_registration`,
/// `run_auth_start` and `run_auth_finish` are the four loops the WebAuthn
/// recovery handlers run: the server expands the same macro text, adding only
/// `.await` after each executor call. This module proves, for every executor
/// implementation, that
///
/// 1. each loop calls the executor exactly as its `*_run_ev` below does: one
///    method per turn, chosen by the effect the driver has just emitted, with
///    that effect's argument (the release permit), and nothing once the driver
///    reached a verdict (`run_*_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is the driver's `run_*` over `evs` (`*_run_ev_follows_the_driver`);
/// 3. the loop reaches a verdict within its budget, or stops early because an
///    effect aborted (the handler then renders the recorded error)
///    (`*_run_ev_reaches_a_verdict`);
/// 4. hence every per-request WebAuthn theorem holds for the state the real
///    handler ends in (`run_*_theorem`).
///
/// `*_turn` is a total mirror of the body hax extracted from the macro. The
/// extracted `fold_range` body is a lambda that destructures the accumulator,
/// tests the abort flag, matches on the driver effect and returns the same
/// tuple; `*_turn` is written in exactly that shape, so the pointwise equality
/// the `fold_range`/<name>_iter_turn pattern needs is a definitional equality
/// and does not require the solver to reason through the soundness predicate
/// and the whole effect match at once. `*_turn_ev` adds the collected
/// observation to the same body for `*_run_ev`.
///
/// What remains outside: each executor method's I/O, and the macro expansion
/// (the server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Webauthn_driver
open Vela_recovery_policy.Webauthn_interpreter
open Vela_recovery_policy_webauthn_driver_lemmas

// ══════════════════════════════════════════════════════════════════════════
// Registration start
// ══════════════════════════════════════════════════════════════════════════

let rs_terminal (e: t_RegistrationStartEffect) : bool =
  match e with
  | RegistrationStartEffect_Complete | RegistrationStartEffect_Fail _
  | RegistrationStartEffect_Idle -> true
  | _ -> false

let rs_responds_to (e: t_RegistrationStartEffect) (ev: t_RegistrationStartEvent)
  : bool =
  match e, ev with
  | RegistrationStartEffect_Observe, RegistrationStartEvent_Observed _
  | RegistrationStartEffect_StartCeremony, RegistrationStartEvent_CeremonyStarted _
  | RegistrationStartEffect_StoreState, RegistrationStartEvent_Stored _ -> true
  | _ -> false

let rs_sound (t: t_RegistrationStartTransition) : bool =
  registration_start_transition_is_sound t

let rs_acc_transition (#io_t: Type0) (acc: bool & io_t & t_RegistrationStartTransition)
  : t_RegistrationStartTransition =
  let (_, _, t) = acc in t

let rs_acc_aborted (#io_t: Type0) (acc: bool & io_t & t_RegistrationStartTransition) : bool =
  let (a, _, _) = acc in a

let rs_result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & t_RegistrationStartTransition & ev)
  : (bool & io_t & t_RegistrationStartTransition) =
  let (a, s, t, _) = result in (a, s, t)

/// One turn, collecting the observation. This is the body hax extracts with
/// the additional `option` of what the executor returned.
let rs_turn_ev (#io_t: Type0) {| i: t_RegistrationStartIo io_t |}
      (acc: bool & io_t & t_RegistrationStartTransition)
  : Pure (bool & io_t & t_RegistrationStartTransition & option t_RegistrationStartEvent)
    (requires rs_sound (rs_acc_transition acc))
    (ensures fun result ->
      rs_sound (rs_acc_transition (rs_result_acc result))) =
  let (aborted, s, t) = acc in
  if aborted then (aborted, s, t, None)
  else
    match t.f_effect with
    | RegistrationStartEffect_Observe ->
        let (s', o) = f_registration_start_observe #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationStartEvent_Observed observation in
             (aborted, s', step_registration_start t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationStartEffect_StartCeremony ->
        let (s', o) = f_registration_start_ceremony #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationStartEvent_CeremonyStarted observation in
             (aborted, s', step_registration_start t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationStartEffect_StoreState ->
        let (s', o) = f_registration_start_store #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationStartEvent_Stored observation in
             (aborted, s', step_registration_start t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationStartEffect_Complete | RegistrationStartEffect_Fail _
    | RegistrationStartEffect_Idle ->
        (aborted, s, t, None)

/// `rs_turn_ev` without the observation, total so it can be compared
/// with the extracted loop body.
let rs_turn (#io_t: Type0) {| i: t_RegistrationStartIo io_t |}
      (acc: bool & io_t & t_RegistrationStartTransition)
  : (bool & io_t & t_RegistrationStartTransition) =
  if rs_sound (rs_acc_transition acc)
  then let (a', s', t', _) = rs_turn_ev #io_t #i acc in (a', s', t')
  else acc

let rec rs_iter_turn (#io_t: Type0) {| i: t_RegistrationStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationStartTransition)
  : Tot (bool & io_t & t_RegistrationStartTransition) (decreases n) =
  if n = 0 then acc else rs_iter_turn #io_t #i (n - 1) (rs_turn #io_t #i acc)

let rs_cons_opt (o: option t_RegistrationStartEvent) (evs: list t_RegistrationStartEvent)
  : list t_RegistrationStartEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec rs_run_ev (#io_t: Type0) {| i: t_RegistrationStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationStartTransition)
  : Pure (bool & io_t & t_RegistrationStartTransition & list t_RegistrationStartEvent)
    (requires rs_sound (rs_acc_transition acc))
    (ensures fun result ->
      rs_sound (rs_acc_transition (rs_result_acc result)))
    (decreases n) =
  if n = 0 then (let (a, s, t) = acc in (a, s, t, []))
  else
    let (a1, s1, t1, o) = rs_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = rs_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    (a2, s2, t2, rs_cons_opt o evs)

let rec rs_fold_is_iter_turn
  (#io_t: Type0) {| i: t_RegistrationStartIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (bool & io_t & t_RegistrationStartTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & t_RegistrationStartTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & t_RegistrationStartTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & t_RegistrationStartTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & t_RegistrationStartTransition))
                   (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                   f acc k == rs_turn #io_t #i acc)))
     (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
               rs_iter_turn #io_t #i n init))
     (decreases n)
     [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
      SMTPat (rs_iter_turn #io_t #i n init)] =
  if v start < v end_
  then rs_fold_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec rs_iter_turn_is_run_ev (#io_t: Type0) {| i: t_RegistrationStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationStartTransition)
  : Lemma
    (requires rs_sound (rs_acc_transition acc))
    (ensures (let (a2, s2, t2, _) = rs_run_ev #io_t #i n acc in
              rs_iter_turn #io_t #i n acc == (a2, s2, t2)))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, _) = rs_turn_ev #io_t #i acc in
    rs_iter_turn_is_run_ev #io_t #i (n - 1) (a1, s1, t1)
  end

/// The extracted loop calls the executor exactly as `rs_run_ev` does.
let run_registration_start_is_run_ev (#io_t: Type0)
      {| i: t_RegistrationStartIo io_t |} (s: io_t)
  : Lemma
    (let t0 = begin_registration_start () in
     let (a2, s2, t2, _) = rs_run_ev #io_t #i 3 (false, s, t0) in
     Vela_recovery_policy.Webauthn_interpreter.run_registration_start #io_t #i s ==
       (s2, (if a2 then Core_models.Option.Option_None
             else Core_models.Option.Option_Some t2))) =
  let t0 = begin_registration_start () in
  rs_iter_turn_is_run_ev #io_t #i 3 (false, s, t0);
  assert (rs_iter_turn #io_t #i 3 (false, s, t0) ==
          (let (a2, s2, t2, _) = rs_run_ev #io_t #i 3 (false, s, t0) in
           (a2, s2, t2)));
  assert (v v_REGISTRATION_START_MAX_EFFECTS = 3);
  assert (Vela_recovery_policy.Webauthn_interpreter.run_registration_start #io_t #i s ==
          (let (a2, s2, t2, _) = rs_run_ev #io_t #i 3 (false, s, t0) in
           (s2, (if a2 then Core_models.Option.Option_None
                 else Core_models.Option.Option_Some t2))))

/// A dropped handler future stops this loop after an arbitrary prefix of
/// turns. For every executor, every `k` and every sound start, the transition
/// after `k` turns is sound: `registration_start_state_is_sound` carries the
/// per-request state invariants (a stored ceremony state implies an authorized
/// observation and nothing stored before the store effect; a completed start
/// stores exactly once), and the next effect agrees with the state that
/// produced it.
let rs_cancellation (#io_t: Type0) {| i: t_RegistrationStartIo io_t |}
      (k: nat) (acc: bool & io_t & t_RegistrationStartTransition)
  : Lemma (requires rs_sound (rs_acc_transition acc))
          (ensures (let (_, _, t2) = rs_iter_turn #io_t #i k acc in rs_sound t2)) =
  let (_, _, _, _) = rs_run_ev #io_t #i k acc in
  rs_iter_turn_is_run_ev #io_t #i k acc

let rec rs_responds (t: t_RegistrationStartTransition)
                    (evs: list t_RegistrationStartEvent)
  : Pure bool (requires rs_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (rs_terminal t.f_effect) && rs_responds_to t.f_effect ev &&
      rs_responds (step_registration_start t.f_driver ev) rest

let rec rs_run_ev_follows_the_driver (#io_t: Type0)
      {| i: t_RegistrationStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationStartTransition)
  : Lemma
    (requires rs_sound (rs_acc_transition acc))
    (ensures (let (_, _, t2, evs) = rs_run_ev #io_t #i n acc in
              rs_trace_sound t2.f_driver /\
              rs_responds (rs_acc_transition acc) evs /\
              t2.f_driver ==
                Vela_recovery_policy_webauthn_driver_lemmas.run_registration_start
                  (rs_acc_transition acc).f_driver evs))
    (decreases n) =
  rs_trace_sound_matches_rust (rs_acc_transition acc).f_driver;
  let (aborted, _, t) = acc in
  if n = 0 then ()
  else if aborted then begin
    let (a1, s1, t1, _) = rs_turn_ev #io_t #i acc in
    assert (t1 == t);
    rs_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1)
  end else begin
    let (a1, s1, t1, o) = rs_turn_ev #io_t #i acc in
    rs_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1);
    match o with
    | None -> ()
    | Some ev ->
        rs_step_sound t.f_driver ev;
        assert (rs_responds t
          (ev :: (let (_, _, _, evs) = rs_run_ev #io_t #i (n - 1) (a1, s1, t1) in evs)))
  end

let rs_remaining (e: t_RegistrationStartEffect) : nat =
  match e with
  | RegistrationStartEffect_Observe -> 3
  | RegistrationStartEffect_StartCeremony -> 2
  | RegistrationStartEffect_StoreState -> 1
  | RegistrationStartEffect_Complete | RegistrationStartEffect_Fail _
  | RegistrationStartEffect_Idle -> 0

let rs_remaining_zero_is_terminal (e: t_RegistrationStartEffect)
  : Lemma (requires rs_remaining e = 0) (ensures rs_terminal e) =
  match e with
  | RegistrationStartEffect_Observe -> ()
  | RegistrationStartEffect_StartCeremony -> ()
  | RegistrationStartEffect_StoreState -> ()
  | RegistrationStartEffect_Complete -> ()
  | RegistrationStartEffect_Fail _ -> ()
  | RegistrationStartEffect_Idle -> ()

let rs_step_decreases (t: t_RegistrationStartTransition)
                      (ev: t_RegistrationStartEvent)
  : Lemma
    (requires rs_sound t /\ not (rs_terminal t.f_effect) /\
              rs_responds_to t.f_effect ev)
    (ensures rs_remaining (step_registration_start t.f_driver ev).f_effect <
             rs_remaining t.f_effect) =
  match t.f_effect with
  | RegistrationStartEffect_Observe -> ()
  | RegistrationStartEffect_StartCeremony -> ()
  | RegistrationStartEffect_StoreState -> ()

let rec rs_run_ev_aborted (#io_t: Type0)
      {| i: t_RegistrationStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationStartTransition)
  : Lemma
    (requires rs_acc_aborted acc /\ rs_sound (rs_acc_transition acc))
    (ensures (let (a2, _, _, _) = rs_run_ev #io_t #i n acc in a2))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, o) = rs_turn_ev #io_t #i acc in
    assert (a1);
    let (a2, s2, t2, evs) = rs_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (rs_run_ev #io_t #i n acc == (a2, s2, t2, rs_cons_opt o evs));
    rs_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
  end

#push-options "--fuel 4 --ifuel 2"
let rec rs_run_ev_reaches_a_verdict (#io_t: Type0)
      {| i: t_RegistrationStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationStartTransition)
  : Lemma
    (requires rs_sound (rs_acc_transition acc) /\
              rs_remaining (rs_acc_transition acc).f_effect <= n)
    (ensures (let (a2, _, t2, _) = rs_run_ev #io_t #i n acc in
              rs_terminal t2.f_effect \/ a2))
    (decreases n) =
  let (aborted, _, t) = acc in
  if n = 0 then rs_remaining_zero_is_terminal t.f_effect
  else begin
    let (a1, s1, t1, o) = rs_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = rs_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (rs_run_ev #io_t #i n acc == (a2, s2, t2, rs_cons_opt o evs));
    if a1 then rs_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
    else begin
      (match o with
       | None ->
           assert (t1 == t);
           assert (rs_terminal t.f_effect);
           assert (rs_remaining t.f_effect = 0)
       | Some ev ->
           assert (t1 == step_registration_start t.f_driver ev);
           rs_step_decreases t ev;
           assert (rs_remaining t1.f_effect <= n - 1));
      rs_run_ev_reaches_a_verdict #io_t #i (n - 1) (a1, s1, t1)
    end
  end
#pop-options

/// Every per-request registration-start theorem holds for the state the real
/// handler ends in.
let run_registration_start_theorem (#io_t: Type0)
      {| i: t_RegistrationStartIo io_t |} (s: io_t)
  : Lemma (
      let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_registration_start #io_t #i s in
      match outcome with
      | Core_models.Option.Option_None -> True
      | Core_models.Option.Option_Some t ->
          rs_terminal t.f_effect /\
          rs_sound t /\
          (exists (evs: list t_RegistrationStartEvent).
            rs_responds (begin_registration_start ()) evs /\
            t.f_driver == run_registration_start_from_begin evs /\
            rs_trace_sound t.f_driver /\
            count_registration_ceremonies_from_begin evs <= 1 /\
            count_registration_start_stores_from_begin evs <= 1 /\
            (t.f_driver.f_stored ==> (is_rs_done t.f_driver /\ t.f_driver.f_authorized)))) =
  let t0 = begin_registration_start () in
  run_registration_start_is_run_ev #io_t #i s;
  let (a2, s2, t2, evs) = rs_run_ev #io_t #i 3 (false, s, t0) in
  rs_begin_sound ();
  rs_trace_sound_matches_rust t0.f_driver;
  rs_run_ev_follows_the_driver #io_t #i 3 (false, s, t0);
  rs_run_ev_reaches_a_verdict #io_t #i 3 (false, s, t0);
  if a2 then ()
  else begin
    assert ((let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_registration_start #io_t #i s in outcome) ==
            Core_models.Option.Option_Some t2);
    assert (rs_responds t0 evs);
    assert (t2.f_driver ==
            Vela_recovery_policy_webauthn_driver_lemmas.run_registration_start
              t0.f_driver evs);
    registration_start_trace_theorem evs;
    assert (t2.f_driver == run_registration_start_from_begin evs)
  end

// ══════════════════════════════════════════════════════════════════════════
// Registration finish
// ══════════════════════════════════════════════════════════════════════════

let reg_terminal (e: t_RegistrationEffect) : bool =
  match e with
  | RegistrationEffect_Complete | RegistrationEffect_Fail _
  | RegistrationEffect_Idle -> true
  | _ -> false

let reg_responds_to (e: t_RegistrationEffect) (ev: t_RegistrationEvent) : bool =
  match e, ev with
  | RegistrationEffect_CountAttempt, RegistrationEvent_AttemptCounted _
  | RegistrationEffect_ConsumeState, RegistrationEvent_StateConsumed _
  | RegistrationEffect_VerifyRegistration, RegistrationEvent_RegistrationVerified _
  | RegistrationEffect_CheckCredentialUniqueness, RegistrationEvent_CredentialLookedUp _
  | RegistrationEffect_PersistCredential, RegistrationEvent_CredentialPersisted _ -> true
  | _ -> false

let reg_sound (t: t_RegistrationTransition) : bool =
  registration_transition_is_sound t

let reg_acc_transition (#io_t: Type0) (acc: bool & io_t & t_RegistrationTransition)
  : t_RegistrationTransition =
  let (_, _, t) = acc in t

let reg_acc_aborted (#io_t: Type0) (acc: bool & io_t & t_RegistrationTransition) : bool =
  let (a, _, _) = acc in a

let reg_result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & t_RegistrationTransition & ev)
  : (bool & io_t & t_RegistrationTransition) =
  let (a, s, t, _) = result in (a, s, t)

let reg_turn_ev (#io_t: Type0) {| i: t_RegistrationIo io_t |}
      (acc: bool & io_t & t_RegistrationTransition)
  : Pure (bool & io_t & t_RegistrationTransition & option t_RegistrationEvent)
    (requires reg_sound (reg_acc_transition acc))
    (ensures fun result ->
      reg_sound (reg_acc_transition (reg_result_acc result))) =
  let (aborted, s, t) = acc in
  if aborted then (aborted, s, t, None)
  else
    match t.f_effect with
    | RegistrationEffect_CountAttempt ->
        let (s', o) = f_registration_count_attempt #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationEvent_AttemptCounted observation in
             (aborted, s', step_registration t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationEffect_ConsumeState ->
        let (s', o) = f_registration_consume_state #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationEvent_StateConsumed observation in
             (aborted, s', step_registration t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationEffect_VerifyRegistration ->
        let (s', o) = f_registration_verify #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationEvent_RegistrationVerified observation in
             (aborted, s', step_registration t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationEffect_CheckCredentialUniqueness ->
        let (s', o) = f_registration_check_uniqueness #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationEvent_CredentialLookedUp observation in
             (aborted, s', step_registration t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationEffect_PersistCredential ->
        let (s', o) = f_registration_persist #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = RegistrationEvent_CredentialPersisted observation in
             (aborted, s', step_registration t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | RegistrationEffect_Complete | RegistrationEffect_Fail _
    | RegistrationEffect_Idle ->
        (aborted, s, t, None)

/// `reg_turn_ev` without the observation, total so it can be compared
/// with the extracted loop body.
let reg_turn (#io_t: Type0) {| i: t_RegistrationIo io_t |}
      (acc: bool & io_t & t_RegistrationTransition)
  : (bool & io_t & t_RegistrationTransition) =
  if reg_sound (reg_acc_transition acc)
  then let (a', s', t', _) = reg_turn_ev #io_t #i acc in (a', s', t')
  else acc

let rec reg_iter_turn (#io_t: Type0) {| i: t_RegistrationIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationTransition)
  : Tot (bool & io_t & t_RegistrationTransition) (decreases n) =
  if n = 0 then acc else reg_iter_turn #io_t #i (n - 1) (reg_turn #io_t #i acc)

let reg_cons_opt (o: option t_RegistrationEvent) (evs: list t_RegistrationEvent)
  : list t_RegistrationEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec reg_run_ev (#io_t: Type0) {| i: t_RegistrationIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationTransition)
  : Pure (bool & io_t & t_RegistrationTransition & list t_RegistrationEvent)
    (requires reg_sound (reg_acc_transition acc))
    (ensures fun result ->
      reg_sound (reg_acc_transition (reg_result_acc result)))
    (decreases n) =
  if n = 0 then (let (a, s, t) = acc in (a, s, t, []))
  else
    let (a1, s1, t1, o) = reg_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = reg_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    (a2, s2, t2, reg_cons_opt o evs)

let rec reg_fold_is_iter_turn
  (#io_t: Type0) {| i: t_RegistrationIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (bool & io_t & t_RegistrationTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & t_RegistrationTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & t_RegistrationTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & t_RegistrationTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & t_RegistrationTransition))
                   (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                   f acc k == reg_turn #io_t #i acc)))
     (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
               reg_iter_turn #io_t #i n init))
     (decreases n)
     [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
      SMTPat (reg_iter_turn #io_t #i n init)] =
  if v start < v end_
  then reg_fold_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec reg_iter_turn_is_run_ev (#io_t: Type0) {| i: t_RegistrationIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationTransition)
  : Lemma
    (requires reg_sound (reg_acc_transition acc))
    (ensures (let (a2, s2, t2, _) = reg_run_ev #io_t #i n acc in
              reg_iter_turn #io_t #i n acc == (a2, s2, t2)))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, _) = reg_turn_ev #io_t #i acc in
    reg_iter_turn_is_run_ev #io_t #i (n - 1) (a1, s1, t1)
  end

let run_registration_is_run_ev (#io_t: Type0)
      {| i: t_RegistrationIo io_t |} (s: io_t)
  : Lemma
    (let t0 = begin_registration () in
     let (a2, s2, t2, _) = reg_run_ev #io_t #i 5 (false, s, t0) in
     Vela_recovery_policy.Webauthn_interpreter.run_registration #io_t #i s ==
       (s2, (if a2 then Core_models.Option.Option_None
             else Core_models.Option.Option_Some t2))) =
  let t0 = begin_registration () in
  reg_iter_turn_is_run_ev #io_t #i 5 (false, s, t0);
  assert (reg_iter_turn #io_t #i 5 (false, s, t0) ==
          (let (a2, s2, t2, _) = reg_run_ev #io_t #i 5 (false, s, t0) in
           (a2, s2, t2)));
  assert (v v_REGISTRATION_MAX_EFFECTS = 5);
  assert (Vela_recovery_policy.Webauthn_interpreter.run_registration #io_t #i s ==
          (let (a2, s2, t2, _) = reg_run_ev #io_t #i 5 (false, s, t0) in
           (s2, (if a2 then Core_models.Option.Option_None
                 else Core_models.Option.Option_Some t2))))

/// A dropped handler future stops this loop after an arbitrary prefix of
/// turns. For every executor, every `k` and every sound start, the transition
/// after `k` turns is sound: `registration_state_is_sound` carries the
/// per-request state invariants (a stored credential implies a consumed
/// ceremony state, a valid and unique credential and the policy's persist
/// permit; nothing is stored before the persist effect), and the next effect
/// agrees with the state that produced it.
let reg_cancellation (#io_t: Type0) {| i: t_RegistrationIo io_t |}
      (k: nat) (acc: bool & io_t & t_RegistrationTransition)
  : Lemma (requires reg_sound (reg_acc_transition acc))
          (ensures (let (_, _, t2) = reg_iter_turn #io_t #i k acc in reg_sound t2)) =
  let (_, _, _, _) = reg_run_ev #io_t #i k acc in
  reg_iter_turn_is_run_ev #io_t #i k acc

let rec reg_responds (t: t_RegistrationTransition)
                     (evs: list t_RegistrationEvent)
  : Pure bool (requires reg_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (reg_terminal t.f_effect) && reg_responds_to t.f_effect ev &&
      reg_responds (step_registration t.f_driver ev) rest

let rec reg_run_ev_follows_the_driver (#io_t: Type0)
      {| i: t_RegistrationIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationTransition)
  : Lemma
    (requires reg_sound (reg_acc_transition acc))
    (ensures (let (_, _, t2, evs) = reg_run_ev #io_t #i n acc in
              reg_trace_sound t2.f_driver /\
              reg_responds (reg_acc_transition acc) evs /\
              t2.f_driver ==
                Vela_recovery_policy_webauthn_driver_lemmas.run_registration
                  (reg_acc_transition acc).f_driver evs))
    (decreases n) =
  reg_trace_sound_matches_rust (reg_acc_transition acc).f_driver;
  let (aborted, _, t) = acc in
  if n = 0 then ()
  else if aborted then begin
    let (a1, s1, t1, _) = reg_turn_ev #io_t #i acc in
    assert (t1 == t);
    reg_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1)
  end else begin
    let (a1, s1, t1, o) = reg_turn_ev #io_t #i acc in
    reg_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1);
    match o with
    | None -> ()
    | Some ev ->
        reg_step_sound t.f_driver ev;
        assert (reg_responds t
          (ev :: (let (_, _, _, evs) = reg_run_ev #io_t #i (n - 1) (a1, s1, t1) in evs)))
  end

let reg_remaining (e: t_RegistrationEffect) : nat =
  match e with
  | RegistrationEffect_CountAttempt -> 5
  | RegistrationEffect_ConsumeState -> 4
  | RegistrationEffect_VerifyRegistration -> 3
  | RegistrationEffect_CheckCredentialUniqueness -> 2
  | RegistrationEffect_PersistCredential -> 1
  | RegistrationEffect_Complete | RegistrationEffect_Fail _
  | RegistrationEffect_Idle -> 0

let reg_remaining_zero_is_terminal (e: t_RegistrationEffect)
  : Lemma (requires reg_remaining e = 0) (ensures reg_terminal e) =
  match e with
  | RegistrationEffect_CountAttempt -> ()
  | RegistrationEffect_ConsumeState -> ()
  | RegistrationEffect_VerifyRegistration -> ()
  | RegistrationEffect_CheckCredentialUniqueness -> ()
  | RegistrationEffect_PersistCredential -> ()
  | RegistrationEffect_Complete -> ()
  | RegistrationEffect_Fail _ -> ()
  | RegistrationEffect_Idle -> ()

let reg_step_decreases (t: t_RegistrationTransition) (ev: t_RegistrationEvent)
  : Lemma
    (requires reg_sound t /\ not (reg_terminal t.f_effect) /\
              reg_responds_to t.f_effect ev)
    (ensures reg_remaining (step_registration t.f_driver ev).f_effect <
             reg_remaining t.f_effect) =
  match t.f_effect with
  | RegistrationEffect_CountAttempt -> ()
  | RegistrationEffect_ConsumeState -> ()
  | RegistrationEffect_VerifyRegistration -> ()
  | RegistrationEffect_CheckCredentialUniqueness -> ()
  | RegistrationEffect_PersistCredential -> ()

let rec reg_run_ev_aborted (#io_t: Type0)
      {| i: t_RegistrationIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationTransition)
  : Lemma
    (requires reg_acc_aborted acc /\ reg_sound (reg_acc_transition acc))
    (ensures (let (a2, _, _, _) = reg_run_ev #io_t #i n acc in a2))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, o) = reg_turn_ev #io_t #i acc in
    assert (a1);
    let (a2, s2, t2, evs) = reg_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (reg_run_ev #io_t #i n acc == (a2, s2, t2, reg_cons_opt o evs));
    reg_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
  end

#push-options "--fuel 4 --ifuel 2"
let rec reg_run_ev_reaches_a_verdict (#io_t: Type0)
      {| i: t_RegistrationIo io_t |} (n: nat)
      (acc: bool & io_t & t_RegistrationTransition)
  : Lemma
    (requires reg_sound (reg_acc_transition acc) /\
              reg_remaining (reg_acc_transition acc).f_effect <= n)
    (ensures (let (a2, _, t2, _) = reg_run_ev #io_t #i n acc in
              reg_terminal t2.f_effect \/ a2))
    (decreases n) =
  let (aborted, _, t) = acc in
  if n = 0 then reg_remaining_zero_is_terminal t.f_effect
  else begin
    let (a1, s1, t1, o) = reg_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = reg_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (reg_run_ev #io_t #i n acc == (a2, s2, t2, reg_cons_opt o evs));
    if a1 then reg_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
    else begin
      (match o with
       | None ->
           assert (t1 == t);
           assert (reg_terminal t.f_effect);
           assert (reg_remaining t.f_effect = 0)
       | Some ev ->
           assert (t1 == step_registration t.f_driver ev);
           reg_step_decreases t ev;
           assert (reg_remaining t1.f_effect <= n - 1));
      reg_run_ev_reaches_a_verdict #io_t #i (n - 1) (a1, s1, t1)
    end
  end
#pop-options

let run_registration_theorem (#io_t: Type0)
      {| i: t_RegistrationIo io_t |} (s: io_t)
  : Lemma (
      let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_registration #io_t #i s in
      match outcome with
      | Core_models.Option.Option_None -> True
      | Core_models.Option.Option_Some t ->
          reg_terminal t.f_effect /\
          reg_sound t /\
          (exists (evs: list t_RegistrationEvent).
            reg_responds (begin_registration ()) evs /\
            t.f_driver == run_registration_from_begin evs /\
            reg_trace_sound t.f_driver /\
            count_registration_persists_from_begin evs <= 1 /\
            (t.f_driver.f_credential_stored ==>
              (t.f_driver.f_permit_issued /\
               t.f_driver.f_state_consumed /\
               t.f_driver.f_credential_valid /\
               t.f_driver.f_credential_unique /\
               is_reg_done t.f_driver)))) =
  let t0 = begin_registration () in
  run_registration_is_run_ev #io_t #i s;
  let (a2, s2, t2, evs) = reg_run_ev #io_t #i 5 (false, s, t0) in
  reg_begin_sound ();
  reg_trace_sound_matches_rust t0.f_driver;
  reg_run_ev_follows_the_driver #io_t #i 5 (false, s, t0);
  reg_run_ev_reaches_a_verdict #io_t #i 5 (false, s, t0);
  if a2 then ()
  else begin
    assert ((let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_registration #io_t #i s in outcome) ==
            Core_models.Option.Option_Some t2);
    assert (reg_responds t0 evs);
    assert (t2.f_driver ==
            Vela_recovery_policy_webauthn_driver_lemmas.run_registration
              t0.f_driver evs);
    registration_trace_theorem evs;
    assert (t2.f_driver == run_registration_from_begin evs)
  end

// ══════════════════════════════════════════════════════════════════════════
// Authentication start
// ══════════════════════════════════════════════════════════════════════════

let as_terminal (e: t_AuthStartEffect) : bool =
  match e with
  | AuthStartEffect_Complete | AuthStartEffect_Fail _
  | AuthStartEffect_Idle -> true
  | _ -> false

let as_responds_to (e: t_AuthStartEffect) (ev: t_AuthStartEvent) : bool =
  match e, ev with
  | AuthStartEffect_Observe, AuthStartEvent_Observed _
  | AuthStartEffect_StartCeremony, AuthStartEvent_CeremonyStarted _
  | AuthStartEffect_StoreChallenge, AuthStartEvent_Stored _ -> true
  | _ -> false

let as_sound (t: t_AuthStartTransition) : bool =
  auth_start_transition_is_sound t

let as_acc_transition (#io_t: Type0) (acc: bool & io_t & t_AuthStartTransition)
  : t_AuthStartTransition =
  let (_, _, t) = acc in t

let as_acc_aborted (#io_t: Type0) (acc: bool & io_t & t_AuthStartTransition) : bool =
  let (a, _, _) = acc in a

let as_result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & t_AuthStartTransition & ev)
  : (bool & io_t & t_AuthStartTransition) =
  let (a, s, t, _) = result in (a, s, t)

let as_turn_ev (#io_t: Type0) {| i: t_AuthStartIo io_t |}
      (acc: bool & io_t & t_AuthStartTransition)
  : Pure (bool & io_t & t_AuthStartTransition & option t_AuthStartEvent)
    (requires as_sound (as_acc_transition acc))
    (ensures fun result ->
      as_sound (as_acc_transition (as_result_acc result))) =
  let (aborted, s, t) = acc in
  if aborted then (aborted, s, t, None)
  else
    match t.f_effect with
    | AuthStartEffect_Observe ->
        let (s', o) = f_auth_start_observe #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthStartEvent_Observed observation in
             (aborted, s', step_auth_start t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthStartEffect_StartCeremony ->
        let (s', o) = f_auth_start_ceremony #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthStartEvent_CeremonyStarted observation in
             (aborted, s', step_auth_start t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthStartEffect_StoreChallenge ->
        let (s', o) = f_auth_start_store #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthStartEvent_Stored observation in
             (aborted, s', step_auth_start t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthStartEffect_Complete | AuthStartEffect_Fail _ | AuthStartEffect_Idle ->
        (aborted, s, t, None)

/// `as_turn_ev` without the observation, total so it can be compared
/// with the extracted loop body.
let as_turn (#io_t: Type0) {| i: t_AuthStartIo io_t |}
      (acc: bool & io_t & t_AuthStartTransition)
  : (bool & io_t & t_AuthStartTransition) =
  if as_sound (as_acc_transition acc)
  then let (a', s', t', _) = as_turn_ev #io_t #i acc in (a', s', t')
  else acc

let rec as_iter_turn (#io_t: Type0) {| i: t_AuthStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthStartTransition)
  : Tot (bool & io_t & t_AuthStartTransition) (decreases n) =
  if n = 0 then acc else as_iter_turn #io_t #i (n - 1) (as_turn #io_t #i acc)

let as_cons_opt (o: option t_AuthStartEvent) (evs: list t_AuthStartEvent)
  : list t_AuthStartEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec as_run_ev (#io_t: Type0) {| i: t_AuthStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthStartTransition)
  : Pure (bool & io_t & t_AuthStartTransition & list t_AuthStartEvent)
    (requires as_sound (as_acc_transition acc))
    (ensures fun result ->
      as_sound (as_acc_transition (as_result_acc result)))
    (decreases n) =
  if n = 0 then (let (a, s, t) = acc in (a, s, t, []))
  else
    let (a1, s1, t1, o) = as_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = as_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    (a2, s2, t2, as_cons_opt o evs)

let rec as_fold_is_iter_turn
  (#io_t: Type0) {| i: t_AuthStartIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (bool & io_t & t_AuthStartTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & t_AuthStartTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & t_AuthStartTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & t_AuthStartTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & t_AuthStartTransition))
                   (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                   f acc k == as_turn #io_t #i acc)))
     (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
               as_iter_turn #io_t #i n init))
     (decreases n)
     [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
      SMTPat (as_iter_turn #io_t #i n init)] =
  if v start < v end_
  then as_fold_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec as_iter_turn_is_run_ev (#io_t: Type0) {| i: t_AuthStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthStartTransition)
  : Lemma
    (requires as_sound (as_acc_transition acc))
    (ensures (let (a2, s2, t2, _) = as_run_ev #io_t #i n acc in
              as_iter_turn #io_t #i n acc == (a2, s2, t2)))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, _) = as_turn_ev #io_t #i acc in
    as_iter_turn_is_run_ev #io_t #i (n - 1) (a1, s1, t1)
  end

let run_auth_start_is_run_ev (#io_t: Type0)
      {| i: t_AuthStartIo io_t |} (s: io_t)
  : Lemma
    (let t0 = begin_auth_start () in
     let (a2, s2, t2, _) = as_run_ev #io_t #i 3 (false, s, t0) in
     Vela_recovery_policy.Webauthn_interpreter.run_auth_start #io_t #i s ==
       (s2, (if a2 then Core_models.Option.Option_None
             else Core_models.Option.Option_Some t2))) =
  let t0 = begin_auth_start () in
  as_iter_turn_is_run_ev #io_t #i 3 (false, s, t0);
  assert (as_iter_turn #io_t #i 3 (false, s, t0) ==
          (let (a2, s2, t2, _) = as_run_ev #io_t #i 3 (false, s, t0) in
           (a2, s2, t2)));
  assert (v v_AUTH_START_MAX_EFFECTS = 3);
  assert (Vela_recovery_policy.Webauthn_interpreter.run_auth_start #io_t #i s ==
          (let (a2, s2, t2, _) = as_run_ev #io_t #i 3 (false, s, t0) in
           (s2, (if a2 then Core_models.Option.Option_None
                 else Core_models.Option.Option_Some t2))))

/// A dropped handler future stops this loop after an arbitrary prefix of
/// turns. For every executor, every `k` and every sound start, the transition
/// after `k` turns is sound: `auth_start_state_is_sound` carries the
/// per-request state invariants (a stored challenge implies an authorized
/// observation and nothing stored before the store effect; a completed start
/// stores exactly once), and the next effect agrees with the state that
/// produced it.
let as_cancellation (#io_t: Type0) {| i: t_AuthStartIo io_t |}
      (k: nat) (acc: bool & io_t & t_AuthStartTransition)
  : Lemma (requires as_sound (as_acc_transition acc))
          (ensures (let (_, _, t2) = as_iter_turn #io_t #i k acc in as_sound t2)) =
  let (_, _, _, _) = as_run_ev #io_t #i k acc in
  as_iter_turn_is_run_ev #io_t #i k acc

let rec as_responds (t: t_AuthStartTransition) (evs: list t_AuthStartEvent)
  : Pure bool (requires as_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (as_terminal t.f_effect) && as_responds_to t.f_effect ev &&
      as_responds (step_auth_start t.f_driver ev) rest

let rec as_run_ev_follows_the_driver (#io_t: Type0)
      {| i: t_AuthStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthStartTransition)
  : Lemma
    (requires as_sound (as_acc_transition acc))
    (ensures (let (_, _, t2, evs) = as_run_ev #io_t #i n acc in
              as_trace_sound t2.f_driver /\
              as_responds (as_acc_transition acc) evs /\
              t2.f_driver ==
                Vela_recovery_policy_webauthn_driver_lemmas.run_auth_start
                  (as_acc_transition acc).f_driver evs))
    (decreases n) =
  as_trace_sound_matches_rust (as_acc_transition acc).f_driver;
  let (aborted, _, t) = acc in
  if n = 0 then ()
  else if aborted then begin
    let (a1, s1, t1, _) = as_turn_ev #io_t #i acc in
    assert (t1 == t);
    as_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1)
  end else begin
    let (a1, s1, t1, o) = as_turn_ev #io_t #i acc in
    as_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1);
    match o with
    | None -> ()
    | Some ev ->
        as_step_sound t.f_driver ev;
        assert (as_responds t
          (ev :: (let (_, _, _, evs) = as_run_ev #io_t #i (n - 1) (a1, s1, t1) in evs)))
  end

let as_remaining (e: t_AuthStartEffect) : nat =
  match e with
  | AuthStartEffect_Observe -> 3
  | AuthStartEffect_StartCeremony -> 2
  | AuthStartEffect_StoreChallenge -> 1
  | AuthStartEffect_Complete | AuthStartEffect_Fail _
  | AuthStartEffect_Idle -> 0

let as_remaining_zero_is_terminal (e: t_AuthStartEffect)
  : Lemma (requires as_remaining e = 0) (ensures as_terminal e) =
  match e with
  | AuthStartEffect_Observe -> ()
  | AuthStartEffect_StartCeremony -> ()
  | AuthStartEffect_StoreChallenge -> ()
  | AuthStartEffect_Complete -> ()
  | AuthStartEffect_Fail _ -> ()
  | AuthStartEffect_Idle -> ()

let as_step_decreases (t: t_AuthStartTransition) (ev: t_AuthStartEvent)
  : Lemma
    (requires as_sound t /\ not (as_terminal t.f_effect) /\
              as_responds_to t.f_effect ev)
    (ensures as_remaining (step_auth_start t.f_driver ev).f_effect <
             as_remaining t.f_effect) =
  match t.f_effect with
  | AuthStartEffect_Observe -> ()
  | AuthStartEffect_StartCeremony -> ()
  | AuthStartEffect_StoreChallenge -> ()

let rec as_run_ev_aborted (#io_t: Type0)
      {| i: t_AuthStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthStartTransition)
  : Lemma
    (requires as_acc_aborted acc /\ as_sound (as_acc_transition acc))
    (ensures (let (a2, _, _, _) = as_run_ev #io_t #i n acc in a2))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, o) = as_turn_ev #io_t #i acc in
    assert (a1);
    let (a2, s2, t2, evs) = as_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (as_run_ev #io_t #i n acc == (a2, s2, t2, as_cons_opt o evs));
    as_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
  end

#push-options "--fuel 4 --ifuel 2"
let rec as_run_ev_reaches_a_verdict (#io_t: Type0)
      {| i: t_AuthStartIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthStartTransition)
  : Lemma
    (requires as_sound (as_acc_transition acc) /\
              as_remaining (as_acc_transition acc).f_effect <= n)
    (ensures (let (a2, _, t2, _) = as_run_ev #io_t #i n acc in
              as_terminal t2.f_effect \/ a2))
    (decreases n) =
  let (aborted, _, t) = acc in
  if n = 0 then as_remaining_zero_is_terminal t.f_effect
  else begin
    let (a1, s1, t1, o) = as_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = as_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (as_run_ev #io_t #i n acc == (a2, s2, t2, as_cons_opt o evs));
    if a1 then as_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
    else begin
      (match o with
       | None ->
           assert (t1 == t);
           assert (as_terminal t.f_effect);
           assert (as_remaining t.f_effect = 0)
       | Some ev ->
           assert (t1 == step_auth_start t.f_driver ev);
           as_step_decreases t ev;
           assert (as_remaining t1.f_effect <= n - 1));
      as_run_ev_reaches_a_verdict #io_t #i (n - 1) (a1, s1, t1)
    end
  end
#pop-options

let run_auth_start_theorem (#io_t: Type0)
      {| i: t_AuthStartIo io_t |} (s: io_t)
  : Lemma (
      let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_auth_start #io_t #i s in
      match outcome with
      | Core_models.Option.Option_None -> True
      | Core_models.Option.Option_Some t ->
          as_terminal t.f_effect /\
          as_sound t /\
          (exists (evs: list t_AuthStartEvent).
            as_responds (begin_auth_start ()) evs /\
            t.f_driver == run_auth_start_from_begin evs /\
            as_trace_sound t.f_driver /\
            count_auth_start_stores_from_begin evs <= 1 /\
            (t.f_driver.f_stored ==> (is_as_done t.f_driver /\ t.f_driver.f_authorized)))) =
  let t0 = begin_auth_start () in
  run_auth_start_is_run_ev #io_t #i s;
  let (a2, s2, t2, evs) = as_run_ev #io_t #i 3 (false, s, t0) in
  as_begin_sound ();
  as_trace_sound_matches_rust t0.f_driver;
  as_run_ev_follows_the_driver #io_t #i 3 (false, s, t0);
  as_run_ev_reaches_a_verdict #io_t #i 3 (false, s, t0);
  if a2 then ()
  else begin
    assert ((let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_auth_start #io_t #i s in outcome) ==
            Core_models.Option.Option_Some t2);
    assert (as_responds t0 evs);
    assert (t2.f_driver ==
            Vela_recovery_policy_webauthn_driver_lemmas.run_auth_start
              t0.f_driver evs);
    auth_start_trace_theorem evs;
    assert (t2.f_driver == run_auth_start_from_begin evs)
  end

// ══════════════════════════════════════════════════════════════════════════
// Authentication finish
// ══════════════════════════════════════════════════════════════════════════

let af_terminal (e: t_AuthFinishEffect) : bool =
  match e with
  | AuthFinishEffect_Complete | AuthFinishEffect_Fail _
  | AuthFinishEffect_Idle -> true
  | _ -> false

let af_responds_to (e: t_AuthFinishEffect) (ev: t_AuthFinishEvent) : bool =
  match e, ev with
  | AuthFinishEffect_CountAttempt, AuthFinishEvent_AttemptCounted _
  | AuthFinishEffect_ObserveContext, AuthFinishEvent_ContextObserved _
  | AuthFinishEffect_ConsumeAttempt, AuthFinishEvent_AttemptConsumed _
  | AuthFinishEffect_VerifyAssertion, AuthFinishEvent_AssertionObserved _
  | AuthFinishEffect_UpdateCredential, AuthFinishEvent_CredentialUpdated _
  | AuthFinishEffect_QueryAccount, AuthFinishEvent_AccountObserved _
  | AuthFinishEffect_ReleaseGrant _, AuthFinishEvent_ShareObserved _
  | AuthFinishEffect_StoreGrant, AuthFinishEvent_GrantStored _ -> true
  | _ -> false

let af_sound (t: t_AuthFinishTransition) : bool =
  auth_finish_transition_is_sound t

let af_acc_transition (#io_t: Type0) (acc: bool & io_t & t_AuthFinishTransition)
  : t_AuthFinishTransition =
  let (_, _, t) = acc in t

let af_acc_aborted (#io_t: Type0) (acc: bool & io_t & t_AuthFinishTransition) : bool =
  let (a, _, _) = acc in a

let af_result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & t_AuthFinishTransition & ev)
  : (bool & io_t & t_AuthFinishTransition) =
  let (a, s, t, _) = result in (a, s, t)

let af_turn_ev (#io_t: Type0) {| i: t_AuthFinishIo io_t |}
      (acc: bool & io_t & t_AuthFinishTransition)
  : Pure (bool & io_t & t_AuthFinishTransition & option t_AuthFinishEvent)
    (requires af_sound (af_acc_transition acc))
    (ensures fun result ->
      af_sound (af_acc_transition (af_result_acc result))) =
  let (aborted, s, t) = acc in
  if aborted then (aborted, s, t, None)
  else
    match t.f_effect with
    | AuthFinishEffect_CountAttempt ->
        let (s', o) = f_auth_finish_count #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_AttemptCounted observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_ObserveContext ->
        let (s', o) = f_auth_finish_context #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_ContextObserved observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_ConsumeAttempt ->
        let (s', o) = f_auth_finish_consume #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_AttemptConsumed observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_VerifyAssertion ->
        let (s', o) = f_auth_finish_verify #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_AssertionObserved observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_UpdateCredential ->
        let (s', o) = f_auth_finish_update #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_CredentialUpdated observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_QueryAccount ->
        let (s', o) = f_auth_finish_account #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_AccountObserved observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_ReleaseGrant permit ->
        let (s', o) = f_auth_finish_release #io_t #i s permit in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_ShareObserved observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_StoreGrant ->
        let (s', o) = f_auth_finish_store_grant #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = AuthFinishEvent_GrantStored observation in
             (aborted, s', step_auth_finish t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | AuthFinishEffect_Complete | AuthFinishEffect_Fail _
    | AuthFinishEffect_Idle ->
        (aborted, s, t, None)

/// `af_turn_ev` without the observation, total so it can be compared
/// with the extracted loop body.
let af_turn (#io_t: Type0) {| i: t_AuthFinishIo io_t |}
      (acc: bool & io_t & t_AuthFinishTransition)
  : (bool & io_t & t_AuthFinishTransition) =
  if af_sound (af_acc_transition acc)
  then let (a', s', t', _) = af_turn_ev #io_t #i acc in (a', s', t')
  else acc

let rec af_iter_turn (#io_t: Type0) {| i: t_AuthFinishIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthFinishTransition)
  : Tot (bool & io_t & t_AuthFinishTransition) (decreases n) =
  if n = 0 then acc else af_iter_turn #io_t #i (n - 1) (af_turn #io_t #i acc)

let af_cons_opt (o: option t_AuthFinishEvent) (evs: list t_AuthFinishEvent)
  : list t_AuthFinishEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec af_run_ev (#io_t: Type0) {| i: t_AuthFinishIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthFinishTransition)
  : Pure (bool & io_t & t_AuthFinishTransition & list t_AuthFinishEvent)
    (requires af_sound (af_acc_transition acc))
    (ensures fun result ->
      af_sound (af_acc_transition (af_result_acc result)))
    (decreases n) =
  if n = 0 then (let (a, s, t) = acc in (a, s, t, []))
  else
    let (a1, s1, t1, o) = af_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = af_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    (a2, s2, t2, af_cons_opt o evs)

let rec af_fold_is_iter_turn
  (#io_t: Type0) {| i: t_AuthFinishIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (bool & io_t & t_AuthFinishTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & t_AuthFinishTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & t_AuthFinishTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & t_AuthFinishTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & t_AuthFinishTransition))
                   (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                   f acc k == af_turn #io_t #i acc)))
     (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
               af_iter_turn #io_t #i n init))
     (decreases n)
     [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
      SMTPat (af_iter_turn #io_t #i n init)] =
  if v start < v end_
  then af_fold_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec af_iter_turn_is_run_ev (#io_t: Type0) {| i: t_AuthFinishIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthFinishTransition)
  : Lemma
    (requires af_sound (af_acc_transition acc))
    (ensures (let (a2, s2, t2, _) = af_run_ev #io_t #i n acc in
              af_iter_turn #io_t #i n acc == (a2, s2, t2)))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, _) = af_turn_ev #io_t #i acc in
    af_iter_turn_is_run_ev #io_t #i (n - 1) (a1, s1, t1)
  end

let run_auth_finish_is_run_ev (#io_t: Type0)
      {| i: t_AuthFinishIo io_t |} (s: io_t)
  : Lemma
    (let t0 = begin_auth_finish () in
     let (a2, s2, t2, _) = af_run_ev #io_t #i 8 (false, s, t0) in
     Vela_recovery_policy.Webauthn_interpreter.run_auth_finish #io_t #i s ==
       (s2, (if a2 then Core_models.Option.Option_None
             else Core_models.Option.Option_Some t2))) =
  let t0 = begin_auth_finish () in
  af_iter_turn_is_run_ev #io_t #i 8 (false, s, t0);
  assert (af_iter_turn #io_t #i 8 (false, s, t0) ==
          (let (a2, s2, t2, _) = af_run_ev #io_t #i 8 (false, s, t0) in
           (a2, s2, t2)));
  assert (v v_AUTH_FINISH_MAX_EFFECTS = 8);
  assert (Vela_recovery_policy.Webauthn_interpreter.run_auth_finish #io_t #i s ==
          (let (a2, s2, t2, _) = af_run_ev #io_t #i 8 (false, s, t0) in
           (s2, (if a2 then Core_models.Option.Option_None
                 else Core_models.Option.Option_Some t2))))

/// A dropped handler future stops this loop after an arbitrary prefix of
/// turns. For every executor, every `k` and every sound start, the transition
/// after `k` turns is sound: `auth_finish_state_is_sound` carries the
/// per-request state invariants (an issued grant implies the consumed,
/// verified attempt and every live account/share release fact; a stored grant
/// implies a decoded share; a credential update implies a needed update), and
/// the next effect agrees with the state that produced it.
let af_cancellation (#io_t: Type0) {| i: t_AuthFinishIo io_t |}
      (k: nat) (acc: bool & io_t & t_AuthFinishTransition)
  : Lemma (requires af_sound (af_acc_transition acc))
          (ensures (let (_, _, t2) = af_iter_turn #io_t #i k acc in af_sound t2)) =
  let (_, _, _, _) = af_run_ev #io_t #i k acc in
  af_iter_turn_is_run_ev #io_t #i k acc

let rec af_responds (t: t_AuthFinishTransition) (evs: list t_AuthFinishEvent)
  : Pure bool (requires af_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (af_terminal t.f_effect) && af_responds_to t.f_effect ev &&
      af_responds (step_auth_finish t.f_driver ev) rest

let rec af_run_ev_follows_the_driver (#io_t: Type0)
      {| i: t_AuthFinishIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthFinishTransition)
  : Lemma
    (requires af_sound (af_acc_transition acc))
    (ensures (let (_, _, t2, evs) = af_run_ev #io_t #i n acc in
              af_trace_sound t2.f_driver /\
              af_responds (af_acc_transition acc) evs /\
              t2.f_driver ==
                Vela_recovery_policy_webauthn_driver_lemmas.run_auth_finish
                  (af_acc_transition acc).f_driver evs))
    (decreases n) =
  af_trace_sound_matches_rust (af_acc_transition acc).f_driver;
  let (aborted, _, t) = acc in
  if n = 0 then ()
  else if aborted then begin
    let (a1, s1, t1, _) = af_turn_ev #io_t #i acc in
    assert (t1 == t);
    af_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1)
  end else begin
    let (a1, s1, t1, o) = af_turn_ev #io_t #i acc in
    af_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1);
    match o with
    | None -> ()
    | Some ev ->
        af_step_sound t.f_driver ev;
        assert (af_responds t
          (ev :: (let (_, _, _, evs) = af_run_ev #io_t #i (n - 1) (a1, s1, t1) in evs)))
  end

let af_remaining (e: t_AuthFinishEffect) : nat =
  match e with
  | AuthFinishEffect_CountAttempt -> 8
  | AuthFinishEffect_ObserveContext -> 7
  | AuthFinishEffect_ConsumeAttempt -> 6
  | AuthFinishEffect_VerifyAssertion -> 5
  | AuthFinishEffect_UpdateCredential -> 4
  | AuthFinishEffect_QueryAccount -> 3
  | AuthFinishEffect_ReleaseGrant _ -> 2
  | AuthFinishEffect_StoreGrant -> 1
  | AuthFinishEffect_Complete | AuthFinishEffect_Fail _
  | AuthFinishEffect_Idle -> 0

let af_remaining_zero_is_terminal (e: t_AuthFinishEffect)
  : Lemma (requires af_remaining e = 0) (ensures af_terminal e) =
  match e with
  | AuthFinishEffect_CountAttempt -> ()
  | AuthFinishEffect_ObserveContext -> ()
  | AuthFinishEffect_ConsumeAttempt -> ()
  | AuthFinishEffect_VerifyAssertion -> ()
  | AuthFinishEffect_UpdateCredential -> ()
  | AuthFinishEffect_QueryAccount -> ()
  | AuthFinishEffect_ReleaseGrant _ -> ()
  | AuthFinishEffect_StoreGrant -> ()
  | AuthFinishEffect_Complete -> ()
  | AuthFinishEffect_Fail _ -> ()
  | AuthFinishEffect_Idle -> ()

let af_step_decreases (t: t_AuthFinishTransition) (ev: t_AuthFinishEvent)
  : Lemma
    (requires af_sound t /\ not (af_terminal t.f_effect) /\
              af_responds_to t.f_effect ev)
    (ensures af_remaining (step_auth_finish t.f_driver ev).f_effect <
             af_remaining t.f_effect) =
  match t.f_effect with
  | AuthFinishEffect_CountAttempt -> ()
  | AuthFinishEffect_ObserveContext -> ()
  | AuthFinishEffect_ConsumeAttempt -> ()
  | AuthFinishEffect_VerifyAssertion -> ()
  | AuthFinishEffect_UpdateCredential -> ()
  | AuthFinishEffect_QueryAccount -> ()
  | AuthFinishEffect_ReleaseGrant _ -> ()
  | AuthFinishEffect_StoreGrant -> ()

let rec af_run_ev_aborted (#io_t: Type0)
      {| i: t_AuthFinishIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthFinishTransition)
  : Lemma
    (requires af_acc_aborted acc /\ af_sound (af_acc_transition acc))
    (ensures (let (a2, _, _, _) = af_run_ev #io_t #i n acc in a2))
    (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, o) = af_turn_ev #io_t #i acc in
    assert (a1);
    let (a2, s2, t2, evs) = af_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (af_run_ev #io_t #i n acc == (a2, s2, t2, af_cons_opt o evs));
    af_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
  end

#push-options "--fuel 4 --ifuel 2"
let rec af_run_ev_reaches_a_verdict (#io_t: Type0)
      {| i: t_AuthFinishIo io_t |} (n: nat)
      (acc: bool & io_t & t_AuthFinishTransition)
  : Lemma
    (requires af_sound (af_acc_transition acc) /\
              af_remaining (af_acc_transition acc).f_effect <= n)
    (ensures (let (a2, _, t2, _) = af_run_ev #io_t #i n acc in
              af_terminal t2.f_effect \/ a2))
    (decreases n) =
  let (aborted, _, t) = acc in
  if n = 0 then af_remaining_zero_is_terminal t.f_effect
  else begin
    let (a1, s1, t1, o) = af_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = af_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (af_run_ev #io_t #i n acc == (a2, s2, t2, af_cons_opt o evs));
    if a1 then af_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
    else begin
      (match o with
       | None ->
           assert (t1 == t);
           assert (af_terminal t.f_effect);
           assert (af_remaining t.f_effect = 0)
       | Some ev ->
           assert (t1 == step_auth_finish t.f_driver ev);
           af_step_decreases t ev;
           assert (af_remaining t1.f_effect <= n - 1));
      af_run_ev_reaches_a_verdict #io_t #i (n - 1) (a1, s1, t1)
    end
  end
#pop-options

let run_auth_finish_theorem (#io_t: Type0)
      {| i: t_AuthFinishIo io_t |} (s: io_t)
  : Lemma (
      let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_auth_finish #io_t #i s in
      match outcome with
      | Core_models.Option.Option_None -> True
      | Core_models.Option.Option_Some t ->
          af_terminal t.f_effect /\
          af_sound t /\
          (exists (evs: list t_AuthFinishEvent).
            af_responds (begin_auth_finish ()) evs /\
            t.f_driver == run_auth_finish_from_begin evs /\
            af_trace_sound t.f_driver /\
            count_auth_finish_releases_from_begin evs <= 1 /\
            (t.f_driver.f_grant_issued ==>
              (t.f_driver.f_attempt_consumed /\
               t.f_driver.f_user_matches /\
               t.f_driver.f_attempt_matches /\
               t.f_driver.f_challenge_credential_matches /\
               t.f_driver.f_assertion_valid /\
               t.f_driver.f_user_verified /\
               t.f_driver.f_assertion_credential_matches /\
               (not t.f_driver.f_credential_update_needed \/
                t.f_driver.f_credential_updated) /\
               t.f_driver.f_account_present /\
               t.f_driver.f_account_epoch_active /\
               t.f_driver.f_share_present /\
               t.f_driver.f_stored_credential_matches /\
               observed_recovery_epoch t.f_driver.f_stored_epoch >=. v_INITIAL_EPOCH)) /\
            (t.f_driver.f_grant_stored ==>
              (t.f_driver.f_grant_issued /\
               t.f_driver.f_share_decoded /\
               is_af_done t.f_driver)))) =
  let t0 = begin_auth_finish () in
  run_auth_finish_is_run_ev #io_t #i s;
  let (a2, s2, t2, evs) = af_run_ev #io_t #i 8 (false, s, t0) in
  af_begin_sound ();
  af_trace_sound_matches_rust t0.f_driver;
  af_run_ev_follows_the_driver #io_t #i 8 (false, s, t0);
  af_run_ev_reaches_a_verdict #io_t #i 8 (false, s, t0);
  if a2 then ()
  else begin
    assert ((let (_, outcome) = Vela_recovery_policy.Webauthn_interpreter.run_auth_finish #io_t #i s in outcome) ==
            Core_models.Option.Option_Some t2);
    assert (af_responds t0 evs);
    assert (t2.f_driver ==
            Vela_recovery_policy_webauthn_driver_lemmas.run_auth_finish
              t0.f_driver evs);
    auth_finish_trace_theorem evs;
    assert (t2.f_driver == run_auth_finish_from_begin evs)
  end
