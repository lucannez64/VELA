module Vela_session_policy_websession_delete_interpreter_lemmas



/// This module is the delete handler loop of the four web-session handlers.
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

// ── DELETE /web-session/:id ──────────────────────────────────────────────────────────

let delete_terminal (e: t_DeleteEffect) : bool =
  match e with
  | DeleteEffect_Complete | DeleteEffect_Fail _ | DeleteEffect_Idle -> true
  | _ -> false

let delete_responds_to (e: t_DeleteEffect) (ev: t_DeleteEvent) : bool =
  match e, ev with
  | DeleteEffect_LoadSession, DeleteEvent_SessionObserved _ -> true
  | DeleteEffect_LockoutSession, DeleteEvent_SentinelWritten _ -> true
  | DeleteEffect_RecordRevocation, DeleteEvent_RecordObserved _ -> true
  | _ -> false

let delete_sound_transition (t: t_DeleteTransition) : bool =
  delete_state_is_sound t.f_driver && delete_effect_is_sound t.f_driver t.f_effect

let delete_turn_ev (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (s: io_t) (t: t_DeleteTransition)
  : Pure (io_t & t_DeleteTransition & option t_DeleteEvent)
    (requires delete_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | DeleteEffect_LoadSession ->
      let (s', o) = f_delete_load_session #io_t #i s in
      let ev = DeleteEvent_SessionObserved o in
      (s', delete_step t.f_driver ev, Some ev)
  | DeleteEffect_LockoutSession ->
      let (s', o) = f_lockout_session #io_t #i s in
      let ev = DeleteEvent_SentinelWritten o in
      (s', delete_step t.f_driver ev, Some ev)
  | DeleteEffect_RecordRevocation ->
      let (s', o) = f_record_revocation #io_t #i s in
      let ev = DeleteEvent_RecordObserved o in
      (s', delete_step t.f_driver ev, Some ev)
  | DeleteEffect_Complete | DeleteEffect_Fail _ | DeleteEffect_Idle -> (s, t, None)

let delete_turn (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (acc: io_t & t_DeleteTransition)
  : (io_t & t_DeleteTransition) =
  let (s, t) = acc in
  if delete_state_is_sound t.f_driver
  then let (s', t', _) = delete_turn_ev #io_t #i s t in (s', t')
  else acc

let rec delete_iter_turn (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (n: nat)
  (acc: io_t & t_DeleteTransition)
  : Tot (io_t & t_DeleteTransition) (decreases n) =
  if n = 0 then acc else delete_iter_turn #io_t #i (n - 1) (delete_turn #io_t #i acc)

let rec delete_run_ev (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (n: nat) (s: io_t)
  (t: t_DeleteTransition)
  : Pure (io_t & t_DeleteTransition & list t_DeleteEvent)
    (requires delete_sound_transition t)
    (ensures fun (_, t', _) -> delete_sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = delete_turn_ev #io_t #i s t in
    let (s2, t2, evs) = delete_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

let rec delete_fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_DeleteSessionIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_DeleteTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_DeleteTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_DeleteTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_DeleteTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_DeleteTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == delete_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              delete_iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (delete_iter_turn #io_t #i n init)] =
  if v start < v end_
  then delete_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec delete_iter_turn_is_run_ev (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (n: nat) (s: io_t)
  (t: t_DeleteTransition)
  : Lemma (requires delete_sound_transition t)
          (ensures (let (s2, t2, _) = delete_run_ev #io_t #i n s t in
                    delete_iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = delete_turn_ev #io_t #i s t in
    delete_iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

let delete_run_is_run_ev (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (s: io_t) (actor: t_DeleteActorObservation)
  : Lemma (let (s2, t2, _) = delete_run_ev #io_t #i 3 s (begin_delete actor) in
           run_delete #io_t #i s actor == (s2, t2)) =
  let t0 = begin_delete actor in
  delete_iter_turn_is_run_ev #io_t #i 3 s t0;
  assert (v v_DELETE_SESSION_MAX_EFFECTS = 3);
  assert (run_delete #io_t #i s actor == delete_iter_turn #io_t #i 3 (s, t0))

let rec delete_responds (t: t_DeleteTransition) (evs: list t_DeleteEvent)
  : Pure bool (requires delete_sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (delete_terminal t.f_effect) && delete_responds_to t.f_effect ev &&
      delete_responds (delete_step t.f_driver ev) rest

let rec delete_run_ev_follows_the_driver (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (actor: t_DeleteActorObservation) (n: nat) (s: io_t)
  (t: t_DeleteTransition)
  : Lemma (requires delete_sound_transition t)
          (ensures (let (_, t2, evs) = delete_run_ev #io_t #i n s t in
                    delete_trace_sound t.f_driver /\
                    delete_responds t evs /\
                    t2.f_driver == delete_run t.f_driver evs))
          (decreases n) =
  delete_trace_sound_matches_rust t.f_driver;
  if n = 0 then ()
  else begin
    let (s1, t1, o) = delete_turn_ev #io_t #i s t in
    delete_run_ev_follows_the_driver #io_t #i actor (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> delete_step_sound t.f_driver ev
  end

let delete_remaining (e: t_DeleteEffect) : nat =
  match e with
  | DeleteEffect_LoadSession -> 3
  | DeleteEffect_LockoutSession -> 2
  | DeleteEffect_RecordRevocation -> 1
  | _ -> 0

let delete_step_decreases (t: t_DeleteTransition) (ev: t_DeleteEvent)
  : Lemma (requires delete_sound_transition t /\ not (delete_terminal t.f_effect) /\ delete_responds_to t.f_effect ev)
          (ensures delete_remaining (delete_step t.f_driver ev).f_effect < delete_remaining t.f_effect) =
  match t.f_effect with
  | DeleteEffect_LoadSession -> ()
  | DeleteEffect_LockoutSession -> ()
  | DeleteEffect_RecordRevocation -> ()
  | _ -> ()

let rec delete_run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (n: nat) (s: io_t)
  (t: t_DeleteTransition)
  : Lemma (requires delete_sound_transition t /\ delete_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = delete_run_ev #io_t #i n s t in delete_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = delete_turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> delete_step_decreases t ev);
    delete_run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

let delete_run_theorem (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (s: io_t)
  (actor: t_DeleteActorObservation)
  : Lemma (
      let (_, t) = run_delete #io_t #i s actor in
      exists (evs: list t_DeleteEvent).
        delete_responds (begin_delete actor) evs /\
        t.f_driver == delete_run_from_actor actor evs /\
        delete_terminal t.f_effect /\
        delete_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         (d.f_locked ==> (d.f_actor_active && d.f_owner_matches)) /\
         (d.f_recorded ==> (d.f_actor_active && d.f_owner_matches && d.f_locked)) /\
         (d.f_responded ==> d.f_recorded))) =
  let t0 = begin_delete actor in
  delete_run_is_run_ev #io_t #i s actor;
  delete_run_ev_follows_the_driver #io_t #i actor 3 s t0;
  delete_run_ev_reaches_a_verdict #io_t #i 3 s t0;
  let (_, t2, evs) = delete_run_ev #io_t #i 3 s t0 in
  delete_trace_theorem actor evs

/// Cancellation (web session delete): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver state
/// whose next effect agrees with it.
let websession_delete_cancellation (#io_t: Type0) {| i: t_DeleteSessionIo io_t |} (k: nat) (s: io_t)
  (t: t_DeleteTransition)
  : Lemma (requires delete_sound_transition t)
          (ensures (let (_, t2) = delete_iter_turn #io_t #i k (s, t) in delete_sound_transition t2)) =
  delete_iter_turn_is_run_ev #io_t #i k s t
