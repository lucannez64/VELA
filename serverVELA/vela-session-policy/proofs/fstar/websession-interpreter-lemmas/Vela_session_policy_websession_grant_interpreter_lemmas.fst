module Vela_session_policy_websession_grant_interpreter_lemmas



/// This module is the grant handler loop of the four web-session handlers.
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

// ── POST /web-session/:id/grant ──────────────────────────────────────────────────────────

let grant_terminal (e: t_GrantEffect) : bool =
  match e with
  | GrantEffect_Complete | GrantEffect_Fail _ | GrantEffect_Idle -> true
  | _ -> false

let grant_responds_to (e: t_GrantEffect) (ev: t_GrantEvent) : bool =
  match e, ev with
  | GrantEffect_ValidateGrant, GrantEvent_Validated _ -> true
  | GrantEffect_LoadSession, GrantEvent_SessionObserved _ -> true
  | GrantEffect_UpdateGrant _, GrantEvent_UpdateObserved _ -> true
  | _ -> false

let grant_sound_transition (t: t_GrantTransition) : bool =
  grant_state_is_sound t.f_driver && grant_effect_is_sound t.f_driver t.f_effect

let grant_turn_ev (#io_t: Type0) {| i: t_GrantIo io_t |} (s: io_t) (t: t_GrantTransition)
  : Pure (io_t & t_GrantTransition & option t_GrantEvent)
    (requires grant_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | GrantEffect_ValidateGrant ->
      let (s', o) = f_validate_grant #io_t #i s in
      let ev = GrantEvent_Validated o in
      (s', grant_step t.f_driver ev, Some ev)
  | GrantEffect_LoadSession ->
      let (s', o) = f_grant_load_session #io_t #i s in
      let ev = GrantEvent_SessionObserved o in
      (s', grant_step t.f_driver ev, Some ev)
  | GrantEffect_UpdateGrant update ->
      let (s', o) = f_update_grant #io_t #i s update in
      let ev = GrantEvent_UpdateObserved o in
      (s', grant_step t.f_driver ev, Some ev)
  | GrantEffect_Complete | GrantEffect_Fail _ | GrantEffect_Idle -> (s, t, None)

let grant_turn (#io_t: Type0) {| i: t_GrantIo io_t |} (acc: io_t & t_GrantTransition)
  : (io_t & t_GrantTransition) =
  let (s, t) = acc in
  if grant_state_is_sound t.f_driver
  then let (s', t', _) = grant_turn_ev #io_t #i s t in (s', t')
  else acc

let rec grant_iter_turn (#io_t: Type0) {| i: t_GrantIo io_t |} (n: nat)
  (acc: io_t & t_GrantTransition)
  : Tot (io_t & t_GrantTransition) (decreases n) =
  if n = 0 then acc else grant_iter_turn #io_t #i (n - 1) (grant_turn #io_t #i acc)

let rec grant_run_ev (#io_t: Type0) {| i: t_GrantIo io_t |} (n: nat) (s: io_t)
  (t: t_GrantTransition)
  : Pure (io_t & t_GrantTransition & list t_GrantEvent)
    (requires grant_sound_transition t)
    (ensures fun (_, t', _) -> grant_sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = grant_turn_ev #io_t #i s t in
    let (s2, t2, evs) = grant_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

let rec grant_fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_GrantIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_GrantTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_GrantTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_GrantTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_GrantTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_GrantTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == grant_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              grant_iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (grant_iter_turn #io_t #i n init)] =
  if v start < v end_
  then grant_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec grant_iter_turn_is_run_ev (#io_t: Type0) {| i: t_GrantIo io_t |} (n: nat) (s: io_t)
  (t: t_GrantTransition)
  : Lemma (requires grant_sound_transition t)
          (ensures (let (s2, t2, _) = grant_run_ev #io_t #i n s t in
                    grant_iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = grant_turn_ev #io_t #i s t in
    grant_iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

let grant_run_is_run_ev (#io_t: Type0) {| i: t_GrantIo io_t |} (s: io_t) (actor: t_GrantActorObservation) (ttl: Core_models.Option.t_Option i64)
  : Lemma (let (s2, t2, _) = grant_run_ev #io_t #i 3 s (begin_grant actor ttl) in
           run_grant #io_t #i s actor ttl == (s2, t2)) =
  let t0 = begin_grant actor ttl in
  grant_iter_turn_is_run_ev #io_t #i 3 s t0;
  assert (v v_GRANT_MAX_EFFECTS = 3);
  assert (run_grant #io_t #i s actor ttl == grant_iter_turn #io_t #i 3 (s, t0))

let rec grant_responds (t: t_GrantTransition) (evs: list t_GrantEvent)
  : Pure bool (requires grant_sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (grant_terminal t.f_effect) && grant_responds_to t.f_effect ev &&
      grant_responds (grant_step t.f_driver ev) rest

let rec grant_run_ev_follows_the_driver (#io_t: Type0) {| i: t_GrantIo io_t |} (actor: t_GrantActorObservation) (ttl: Core_models.Option.t_Option i64) (n: nat) (s: io_t)
  (t: t_GrantTransition)
  : Lemma (requires grant_sound_transition t)
          (ensures (let (_, t2, evs) = grant_run_ev #io_t #i n s t in
                    grant_trace_sound t.f_driver /\
                    grant_responds t evs /\
                    t2.f_driver == grant_run t.f_driver evs))
          (decreases n) =
  grant_trace_sound_matches_rust t.f_driver;
  if n = 0 then ()
  else begin
    let (s1, t1, o) = grant_turn_ev #io_t #i s t in
    grant_run_ev_follows_the_driver #io_t #i actor ttl (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> grant_step_sound t.f_driver ev
  end

let grant_remaining (e: t_GrantEffect) : nat =
  match e with
  | GrantEffect_ValidateGrant -> 3
  | GrantEffect_LoadSession -> 2
  | GrantEffect_UpdateGrant _ -> 1
  | _ -> 0

let grant_step_decreases (t: t_GrantTransition) (ev: t_GrantEvent)
  : Lemma (requires grant_sound_transition t /\ not (grant_terminal t.f_effect) /\ grant_responds_to t.f_effect ev)
          (ensures grant_remaining (grant_step t.f_driver ev).f_effect < grant_remaining t.f_effect) =
  match t.f_effect with
  | GrantEffect_ValidateGrant -> ()
  | GrantEffect_LoadSession -> ()
  | GrantEffect_UpdateGrant _ -> ()
  | _ -> ()

let rec grant_run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_GrantIo io_t |} (n: nat) (s: io_t)
  (t: t_GrantTransition)
  : Lemma (requires grant_sound_transition t /\ grant_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = grant_run_ev #io_t #i n s t in grant_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = grant_turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> grant_step_decreases t ev);
    grant_run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

let grant_run_theorem (#io_t: Type0) {| i: t_GrantIo io_t |} (s: io_t)
  (actor: t_GrantActorObservation) (ttl: Core_models.Option.t_Option i64)
  : Lemma (
      let (_, t) = run_grant #io_t #i s actor ttl in
      exists (evs: list t_GrantEvent).
        grant_responds (begin_grant actor ttl) evs /\
        t.f_driver == grant_run_from_actor actor evs ttl /\
        grant_terminal t.f_effect /\
        grant_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         (d.f_updated ==> (d.f_actor_active && d.f_request_valid && d.f_session_loaded && d.f_plan_authorized)) /\
         (d.f_responded ==> (d.f_updated && d.f_actor_active && d.f_plan_authorized)) /\
         not (d.f_responded && d.f_failed))) =
  let t0 = begin_grant actor ttl in
  grant_run_is_run_ev #io_t #i s actor ttl;
  grant_run_ev_follows_the_driver #io_t #i actor ttl 3 s t0;
  grant_run_ev_reaches_a_verdict #io_t #i 3 s t0;
  let (_, t2, evs) = grant_run_ev #io_t #i 3 s t0 in
  grant_trace_theorem actor evs ttl

