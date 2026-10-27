module Vela_recovery_policy_recovery_share_interpreter_lemmas

/// The extracted `run_share_lifecycle` is the loop all four recovery-share
/// handlers run: the server expands the same macro text, adding only `.await`
/// after each executor call. This module proves, for every executor
/// implementation, that
///
/// 1. the loop calls the executor exactly as `rs_run_ev` below does: one method
///    per turn, chosen by the effect the driver has just emitted, with that
///    effect's permit, and nothing once the driver reached a verdict
///    (`run_share_lifecycle_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is the driver's `run` over `evs` (`rs_run_ev_follows_the_driver`);
/// 3. a terminal effect performs no executor call, and an abort stops every
///    later turn (the handler then renders the recorded error);
/// 4. hence every per-request lifecycle theorem holds for the state the real
///    handler ends in (`run_share_lifecycle_theorem`).
///
/// `rs_turn` is a total mirror of the body hax extracted from the macro, in the
/// same tuple shape, so the pointwise equality the `fold_range`/`rs_iter_turn`
/// pattern needs is definitional. `rs_turn_ev` adds the collected observation.
///
/// What remains outside: each executor method's I/O, and the macro expansion
/// (the server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Recovery_share_driver
open Vela_recovery_policy.Recovery_share_interpreter
open Vela_recovery_policy_recovery_share_driver_lemmas

let rs_terminal (e: t_ShareEffect) : bool =
  share_lifecycle_effect_is_terminal e

let rs_responds_to (e: t_ShareEffect) (ev: t_ShareEvent) : bool =
  match e, ev with
  | ShareEffect_StageShare _, ShareEvent_StageUpdate _
  | ShareEffect_StageQueryAccount, ShareEvent_StageAccount _
  | ShareEffect_PromoteStagedSplit _, ShareEvent_FinalizeUpdate _
  | ShareEffect_FinalizeQueryAccount, ShareEvent_FinalizeAccount _
  | ShareEffect_DeleteShare _, ShareEvent_DeleteUpdate _
  | ShareEffect_ReadShare, ShareEvent_ReadObserved _ -> true
  | _ -> false

let rs_sound (t: t_ShareTransition) : bool =
  share_lifecycle_transition_is_sound t

let rs_acc_transition (#io_t: Type0) (acc: bool & io_t & t_ShareTransition)
  : t_ShareTransition =
  let (_, _, t) = acc in t

let rs_acc_aborted (#io_t: Type0) (acc: bool & io_t & t_ShareTransition) : bool =
  let (a, _, _) = acc in a

let rs_result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & t_ShareTransition & ev)
  : (bool & io_t & t_ShareTransition) =
  let (a, s, t, _) = result in (a, s, t)

/// One turn, collecting the observation.
let rs_turn_ev (#io_t: Type0) {| i: t_RecoveryShareIo io_t |}
      (acc: bool & io_t & t_ShareTransition)
  : Pure (bool & io_t & t_ShareTransition & option t_ShareEvent)
    (requires rs_sound (rs_acc_transition acc))
    (ensures fun result ->
      rs_sound (rs_acc_transition (rs_result_acc result))) =
  let (aborted, s, t) = acc in
  if aborted then (aborted, s, t, None)
  else
    match t.f_effect <: t_ShareEffect with
    | ShareEffect_StageShare permit ->
        let (s', o) = f_stage_share #io_t #i s permit in
        (match o <: Core_models.Option.t_Option t_StageUpdateObservation with
         | Core_models.Option.Option_Some observation ->
             let ev = ShareEvent_StageUpdate observation in
             (aborted, s', step_share_lifecycle t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ShareEffect_StageQueryAccount ->
        let (s', o) = f_stage_query_account #io_t #i s in
        (match o <: Core_models.Option.t_Option t_StageAccountObservation with
         | Core_models.Option.Option_Some observation ->
             let ev = ShareEvent_StageAccount observation in
             (aborted, s', step_share_lifecycle t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ShareEffect_PromoteStagedSplit permit ->
        let (s', o) = f_promote_staged_split #io_t #i s permit in
        (match o <: Core_models.Option.t_Option t_FinalizeUpdateObservation with
         | Core_models.Option.Option_Some observation ->
             let ev = ShareEvent_FinalizeUpdate observation in
             (aborted, s', step_share_lifecycle t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ShareEffect_FinalizeQueryAccount ->
        let (s', o) = f_finalize_query_account #io_t #i s in
        (match o <: Core_models.Option.t_Option t_FinalizeAccountObservation with
         | Core_models.Option.Option_Some observation ->
             let ev = ShareEvent_FinalizeAccount observation in
             (aborted, s', step_share_lifecycle t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ShareEffect_DeleteShare permit ->
        let (s', o) = f_delete_share #io_t #i s permit in
        (match o <: Core_models.Option.t_Option t_DeleteUpdateObservation with
         | Core_models.Option.Option_Some observation ->
             let ev = ShareEvent_DeleteUpdate observation in
             (aborted, s', step_share_lifecycle t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ShareEffect_ReadShare ->
        let (s', o) = f_read_share #io_t #i s in
        (match o <: Core_models.Option.t_Option t_ReadObservation with
         | Core_models.Option.Option_Some observation ->
             let ev = ShareEvent_ReadObserved observation in
             (aborted, s', step_share_lifecycle t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ShareEffect_Complete | ShareEffect_Fail _ | ShareEffect_Idle ->
        (aborted, s, t, None)

/// `rs_turn_ev` without the observation, total so it can be compared with the
/// extracted loop body.
let rs_turn (#io_t: Type0) {| i: t_RecoveryShareIo io_t |}
      (acc: bool & io_t & t_ShareTransition)
  : (bool & io_t & t_ShareTransition) =
  if rs_sound (rs_acc_transition acc)
  then let (a', s', t', _) = rs_turn_ev #io_t #i acc in (a', s', t')
  else acc

let rec rs_iter_turn (#io_t: Type0) {| i: t_RecoveryShareIo io_t |} (n: nat)
      (acc: bool & io_t & t_ShareTransition)
  : Tot (bool & io_t & t_ShareTransition) (decreases n) =
  if n = 0 then acc else rs_iter_turn #io_t #i (n - 1) (rs_turn #io_t #i acc)

let rs_cons_opt (o: option t_ShareEvent) (evs: list t_ShareEvent) : list t_ShareEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec rs_run_ev (#io_t: Type0) {| i: t_RecoveryShareIo io_t |} (n: nat)
      (acc: bool & io_t & t_ShareTransition)
  : Pure (bool & io_t & t_ShareTransition & list t_ShareEvent)
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
  (#io_t: Type0) {| i: t_RecoveryShareIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (bool & io_t & t_ShareTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & t_ShareTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & t_ShareTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & t_ShareTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & t_ShareTransition))
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

let rec rs_iter_turn_is_run_ev (#io_t: Type0) {| i: t_RecoveryShareIo io_t |} (n: nat)
      (acc: bool & io_t & t_ShareTransition)
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
let run_share_lifecycle_is_run_ev (#io_t: Type0)
      {| i: t_RecoveryShareIo io_t |} (s: io_t) (request: t_ShareRequestObservation)
  : Lemma
    (let t0 = begin_share_lifecycle request in
     let (a2, s2, t2, _) = rs_run_ev #io_t #i 3 (false, s, t0) in
     Vela_recovery_policy.Recovery_share_interpreter.run_share_lifecycle #io_t #i s request ==
       (s2, (if a2 then Core_models.Option.Option_None
             else Core_models.Option.Option_Some t2))) =
  let t0 = begin_share_lifecycle request in
  rs_iter_turn_is_run_ev #io_t #i 3 (false, s, t0);
  assert (rs_iter_turn #io_t #i 3 (false, s, t0) ==
          (let (a2, s2, t2, _) = rs_run_ev #io_t #i 3 (false, s, t0) in
           (a2, s2, t2)));
  assert (v v_RECOVERY_SHARE_MAX_EFFECTS = 3);
  assert (Vela_recovery_policy.Recovery_share_interpreter.run_share_lifecycle #io_t #i s request ==
          (let (a2, s2, t2, _) = rs_run_ev #io_t #i 3 (false, s, t0) in
           (s2, (if a2 then Core_models.Option.Option_None
                 else Core_models.Option.Option_Some t2))))

let rec rs_responds (t: t_ShareTransition) (evs: list t_ShareEvent)
  : Pure bool (requires rs_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (rs_terminal t.f_effect) && rs_responds_to t.f_effect ev &&
      rs_responds (step_share_lifecycle t.f_driver ev) rest

let rec rs_run_ev_follows_the_driver (#io_t: Type0)
      {| i: t_RecoveryShareIo io_t |} (n: nat)
      (acc: bool & io_t & t_ShareTransition)
  : Lemma
    (requires rs_sound (rs_acc_transition acc))
    (ensures (let (_, _, t2, evs) = rs_run_ev #io_t #i n acc in
              trace_sound t2.f_driver /\
              rs_responds (rs_acc_transition acc) evs /\
              t2.f_driver ==
                Vela_recovery_policy_recovery_share_driver_lemmas.run
                  (rs_acc_transition acc).f_driver evs))
    (decreases n) =
  trace_sound_matches_rust (rs_acc_transition acc).f_driver;
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
        step_sound t.f_driver ev;
        assert (rs_responds t
          (ev :: (let (_, _, _, evs) = rs_run_ev #io_t #i (n - 1) (a1, s1, t1) in evs)))
  end

/// Headline interpreter theorem: for every executor and every request, the
/// loop performs exactly the driver's effects, stops at a verdict (or at the
/// aborting effect) within three turns, and ends in `run begin evs`.
let run_share_lifecycle_theorem (#io_t: Type0)
      {| i: t_RecoveryShareIo io_t |} (s: io_t) (request: t_ShareRequestObservation)
  : Lemma (
      let t0 = begin_share_lifecycle request in
      let (a2, s2, t2, evs) = rs_run_ev #io_t #i 3 (false, s, t0) in
      Vela_recovery_policy.Recovery_share_interpreter.run_share_lifecycle #io_t #i s request ==
        (s2, (if a2 then Core_models.Option.Option_None
              else Core_models.Option.Option_Some t2)) /\
      (a2 \/ (trace_sound t2.f_driver /\
              t2.f_driver ==
                Vela_recovery_policy_recovery_share_driver_lemmas.run
                  t0.f_driver evs))) =
  let t0 = begin_share_lifecycle request in
  run_share_lifecycle_is_run_ev #io_t #i s request;
  rs_run_ev_follows_the_driver #io_t #i 3 (false, s, t0)
