module Vela_rekey_policy_rekey_capsules_interpreter_lemmas

/// The `POST /vault/rekey/capsules` handler loop (`run_capsules`, budget 68).
///
/// It is checked in its own fstar.exe invocation so the SMT pattern of its
/// fold lemma cannot interact with the other three rotation loops. The shared
/// turn specification and the inductive loop lemmas are in
/// `Vela_rekey_policy_rekey_interpreter_lemmas`.
///
/// For every executor (any `t_RekeyIo` instance, any behaviour):
///
/// - `run_capsules_is_run_ev`: the extracted loop is `run_ev 68`, i.e. one executor
///   call per turn, for the effect the driver has just emitted and with that
///   effect's argument, and nothing once the driver reached a verdict;
/// - `run_capsules_theorem`: the observations the executor returned answer the
///   effects they were returned for, the final driver is
///   `run_from_capsules request evs`, the driver reached a verdict within 68 turns,
///   and the per-request rotation theorem holds for that final state.

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Rekey_driver
open Vela_rekey_policy.Rekey_interpreter
open Vela_rekey_policy_rekey_driver_lemmas
open Vela_rekey_policy_rekey_interpreter_lemmas


/// The extracted `fold_range` is `iter_turn`, by induction on the range
/// length: one `turn` per index.
let rec capsules_fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_RekeyIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_RekeyTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_RekeyTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_RekeyTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_RekeyTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_RekeyTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (iter_turn #io_t #i n init)] =
  if v start < v end_
  then capsules_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let run_capsules_is_iter_turn (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (run_capsules #io_t #i s request == iter_turn #io_t #i 68 (s, begin_capsules request)) =
  assert (v v_CAPSULES_MAX_EFFECTS = 68)

let run_capsules_is_run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 68 s (begin_capsules request) in
           run_capsules #io_t #i s request == (s2, t2)) =
  run_capsules_is_iter_turn #io_t #i s request;
  iter_turn_is_run_ev #io_t #i 68 s (begin_capsules request)

/// The final driver of the real handler loop.
let capsules_final (request: t_RekeyRequest) (evs: list t_RekeyEvent) (t: t_RekeyTransition) : prop =
  responds (begin_capsules request) evs /\
  t.f_driver == run_from_capsules request evs /\
  terminal t.f_effect /\
  rekey_effect_is_sound t.f_driver t.f_effect /\
  (let d = t.f_driver in
         rekey_state_is_sound d /\ not d.f_committed /\
         (d.f_responded ==> d.f_capsules_complete) /\
         not (d.f_responded && d.f_failed))

let run_capsules_theorem (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (let (_, t) = run_capsules #io_t #i s request in
           exists (evs: list t_RekeyEvent). capsules_final request evs t) =
  let t0 = begin_capsules request in
  begin_progress_ok request;
  run_capsules_is_run_ev #io_t #i s request;
  run_ev_follows_the_driver #io_t #i 68 s t0;
  run_ev_reaches_a_verdict #io_t #i 68 s t0;
  let (_, t2, evs) = run_ev #io_t #i 68 s t0 in
  rekey_capsules_trace_theorem request evs;
  assert (capsules_final request evs t2)

/// Cancellation (`POST /vault/rekey/capsules`): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver state
/// (`rekey_state_is_sound`) whose next effect agrees with it.
let rekey_capsules_cancellation (#io_t: Type0) {| i: t_RekeyIo io_t |} (k: nat) (s: io_t)
  (t: t_RekeyTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in sound_transition t2)) =
  iter_turn_is_run_ev #io_t #i k s t
