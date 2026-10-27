module Vela_rekey_policy_rekey_interpreter_lemmas

/// The extracted `run_start`, `run_capsules`, `run_commit` and `run_abort` are
/// the loops the four rotation handlers run: the server expands the same
/// `rekey_*_interpreter!` macro text, adding only `.await` after each executor
/// call. This module proves, for every executor implementation (any
/// `t_RekeyIo` instance, any behaviour):
///
/// 1. each loop calls the executor exactly as `run_ev` does: one method per
///    turn, chosen by the effect the driver has just emitted, with that
///    effect's argument (the capsule index), and nothing once the driver
///    reached a verdict;
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_* request evs`;
/// 3. the driver always reaches a verdict within the loop budget of 67 turns;
/// 4. hence every per-request rotation theorem holds for the state the real
///    handler ends in.
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_rekey_policy.Rekey_driver
open Vela_rekey_policy.Rekey_interpreter
open Vela_rekey_policy_rekey_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_RekeyEffect) : bool =
  match e with
  | RekeyEffect_Complete | RekeyEffect_CompleteReplay | RekeyEffect_Fail _ | RekeyEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_RekeyEffect) (ev: t_RekeyEvent) : bool =
  match e, ev with
  | RekeyEffect_RateLimit, RekeyEvent_RateLimit _
  | RekeyEffect_LoadState, RekeyEvent_State _
  | RekeyEffect_TimeoutRollback, RekeyEvent_Timeout _
  | RekeyEffect_CheckOram, RekeyEvent_Oram _
  | RekeyEffect_CheckCapable, RekeyEvent_Capable _
  | RekeyEffect_CheckAcknowledged, RekeyEvent_Acknowledged _
  | RekeyEffect_BeginFreezeTransaction, RekeyEvent_Transaction _
  | RekeyEffect_ReadInventory, RekeyEvent_Inventory _
  | RekeyEffect_FreezeCas, RekeyEvent_FreezeCas _
  | RekeyEffect_CleanupChunks, RekeyEvent_Cleanup _
  | RekeyEffect_CommitFreezeTransaction, RekeyEvent_TxCommit _
  | RekeyEffect_WriteCapsule _, RekeyEvent_Capsule _
  | RekeyEffect_CheckChunkShadows, RekeyEvent_Chunks _
  | RekeyEffect_CheckDeviceCapsules, RekeyEvent_Devices _
  | RekeyEffect_CommitCas, RekeyEvent_CommitCas _
  | RekeyEffect_SweepOldChunks, RekeyEvent_Sweep _
  | RekeyEffect_PublishEpoch, RekeyEvent_Published
  | RekeyEffect_RollbackAttempt, RekeyEvent_Rollback _ -> true
  | _ -> false

let sound_transition (t: t_RekeyTransition) : bool =
  rekey_state_is_sound t.f_driver && rekey_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `rekey_step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t) (t: t_RekeyTransition)
  : Pure (io_t & t_RekeyTransition & option t_RekeyEvent)
    (requires (rekey_state_is_sound t.f_driver))
    (ensures fun _ -> True) =
  match t.f_effect with
  | RekeyEffect_RateLimit ->
      let (s', o) = f_rate_limit #io_t #i s in
      let ev = RekeyEvent_RateLimit o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_LoadState ->
      let (s', o) = f_load_state #io_t #i s in
      let ev = RekeyEvent_State o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_TimeoutRollback ->
      let (s', o) = f_timeout_rollback #io_t #i s in
      let ev = RekeyEvent_Timeout o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CheckOram ->
      let (s', o) = f_check_oram #io_t #i s in
      let ev = RekeyEvent_Oram o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CheckCapable ->
      let (s', o) = f_check_capable #io_t #i s in
      let ev = RekeyEvent_Capable o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CheckAcknowledged ->
      let (s', o) = f_check_acknowledged #io_t #i s in
      let ev = RekeyEvent_Acknowledged o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_BeginFreezeTransaction ->
      let (s', o) = f_begin_freeze_transaction #io_t #i s in
      let ev = RekeyEvent_Transaction o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_ReadInventory ->
      let (s', o) = f_read_inventory #io_t #i s in
      let ev = RekeyEvent_Inventory o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_FreezeCas ->
      let (s', o) = f_freeze_cas #io_t #i s t.f_driver.f_from_epoch t.f_driver.f_to_epoch in
      let ev = RekeyEvent_FreezeCas o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CleanupChunks ->
      let (s', o) = f_cleanup_chunks #io_t #i s t.f_driver.f_from_epoch in
      let ev = RekeyEvent_Cleanup o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CommitFreezeTransaction ->
      let (s', o) = f_commit_freeze_transaction #io_t #i s in
      let ev = RekeyEvent_TxCommit o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_WriteCapsule { f_index = index } ->
      let (s', o) = f_write_capsule #io_t #i s index in
      let ev = RekeyEvent_Capsule o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CheckChunkShadows ->
      let (s', o) = f_check_chunk_shadows #io_t #i s in
      let ev = RekeyEvent_Chunks o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CheckDeviceCapsules ->
      let (s', o) = f_check_device_capsules #io_t #i s in
      let ev = RekeyEvent_Devices o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_CommitCas ->
      let (s', o) = f_commit_cas #io_t #i s t.f_driver.f_from_epoch t.f_driver.f_to_epoch in
      let ev = RekeyEvent_CommitCas o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_SweepOldChunks ->
      let (s', o) = f_sweep_old_chunks #io_t #i s t.f_driver.f_to_epoch in
      let ev = RekeyEvent_Sweep o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_PublishEpoch ->
      let (s', ()) = f_publish_epoch #io_t #i s t.f_driver.f_to_epoch in
      let ev = RekeyEvent_Published in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_RollbackAttempt ->
      let (s', o) = f_rollback_attempt #io_t #i s t.f_driver.f_epoch in
      let ev = RekeyEvent_Rollback o in
      (s', rekey_step t.f_driver ev, Some ev)
  | RekeyEffect_Complete | RekeyEffect_CompleteReplay | RekeyEffect_Fail _ | RekeyEffect_Idle ->
      (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the extracted
/// loop body.
let turn (#io_t: Type0) {| i: t_RekeyIo io_t |} (acc: io_t & t_RekeyTransition)
  : (io_t & t_RekeyTransition) =
  let (s, t) = acc in
  if rekey_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat)
  (acc: io_t & t_RekeyTransition)
  : Tot (io_t & t_RekeyTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_RekeyEvent) (evs: list t_RekeyEvent) : list t_RekeyEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyTransition)
  : Pure (io_t & t_RekeyTransition & list t_RekeyEvent)
    (requires sound_transition t)
    (ensures fun (_, t', _) -> sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = turn_ev #io_t #i s t in
    let (s2, t2, evs) = run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

// ── 1. The extracted loops are `run_ev` ───────────────────────────────────

let rec fold_range_is_iter_turn
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
  then fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (s2, t2, _) = run_ev #io_t #i n s t in
                    iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = turn_ev #io_t #i s t in
    iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

let run_start_is_run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 67 s (begin_start request) in
           run_start #io_t #i s request == (s2, t2)) =
  let t0 = begin_start request in
  iter_turn_is_run_ev #io_t #i 67 s t0;
  assert (v v_REKEY_MAX_EFFECTS = 67);
  assert (run_start #io_t #i s request == iter_turn #io_t #i 67 (s, t0))

let run_capsules_is_run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 67 s (begin_capsules request) in
           run_capsules #io_t #i s request == (s2, t2)) =
  let t0 = begin_capsules request in
  iter_turn_is_run_ev #io_t #i 67 s t0;
  assert (v v_REKEY_MAX_EFFECTS = 67);
  assert (run_capsules #io_t #i s request == iter_turn #io_t #i 67 (s, t0))

let run_commit_is_run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 67 s (begin_commit request) in
           run_commit #io_t #i s request == (s2, t2)) =
  let t0 = begin_commit request in
  iter_turn_is_run_ev #io_t #i 67 s t0;
  assert (v v_REKEY_MAX_EFFECTS = 67);
  assert (run_commit #io_t #i s request == iter_turn #io_t #i 67 (s, t0))

let run_abort_is_run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (let (s2, t2, _) = run_ev #io_t #i 67 s (begin_abort request) in
           run_abort #io_t #i s request == (s2, t2)) =
  let t0 = begin_abort request in
  iter_turn_is_run_ev #io_t #i 67 s t0;
  assert (v v_REKEY_MAX_EFFECTS = 67);
  assert (run_abort #io_t #i s request == iter_turn #io_t #i 67 (s, t0))

// ── 2. The observations drive the extracted driver ────────────────────────

let rec responds (t: t_RekeyTransition) (evs: list t_RekeyEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (rekey_step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2, evs) = run_ev #io_t #i n s t in
                    rekey_state_is_sound t.f_driver /\
                    responds t evs /\
                    t2.f_driver == run t.f_driver evs))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = turn_ev #io_t #i s t in
    run_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> step_sound t.f_driver ev
  end

// ── 3. A verdict within the budget ────────────────────────────────────────

/// Effects still to perform before a verdict. The capsule index strictly
/// decreases the bound on every write.
let remaining (e: t_RekeyEffect) : nat =
  match e with
  | RekeyEffect_RateLimit -> 700
  | RekeyEffect_LoadState -> 699
  | RekeyEffect_TimeoutRollback -> 698
  | RekeyEffect_CheckOram -> 697
  | RekeyEffect_CheckCapable -> 696
  | RekeyEffect_CheckAcknowledged -> 695
  | RekeyEffect_BeginFreezeTransaction -> 694
  | RekeyEffect_ReadInventory -> 693
  | RekeyEffect_FreezeCas -> 692
  | RekeyEffect_CleanupChunks -> 691
  | RekeyEffect_CommitFreezeTransaction -> 690
  | RekeyEffect_WriteCapsule { f_index = index } -> 500 - index
  | RekeyEffect_CheckChunkShadows -> 680
  | RekeyEffect_CheckDeviceCapsules -> 679
  | RekeyEffect_CommitCas -> 678
  | RekeyEffect_SweepOldChunks -> 677
  | RekeyEffect_PublishEpoch -> 676
  | RekeyEffect_RollbackAttempt -> 675
  | RekeyEffect_Complete | RekeyEffect_CompleteReplay | RekeyEffect_Fail _ | RekeyEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_RekeyTransition) (ev: t_RekeyEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (rekey_step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect <: t_RekeyEffect with
  | RekeyEffect_WriteCapsule { f_index = index } -> ()
  | _ -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyTransition)
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

let run_start_theorem (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (
      let (_, t) = run_start #io_t #i s request in
      exists (evs: list t_RekeyEvent).
        responds (begin_start request) evs /\
        t.f_driver == run_from_start request evs /\
        terminal t.f_effect /\
        rekey_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         rekey_state_is_sound d /\ not d.f_committed /\
         not (d.f_responded && d.f_failed))) =
  let t0 = begin_start request in
  run_start_is_run_ev #io_t #i s request;
  run_ev_follows_the_driver #io_t #i 67 s t0;
  run_ev_reaches_a_verdict #io_t #i 67 s t0;
  let (_, t2, evs) = run_ev #io_t #i 67 s t0 in
  rekey_start_trace_theorem request evs

let run_capsules_theorem (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (
      let (_, t) = run_capsules #io_t #i s request in
      exists (evs: list t_RekeyEvent).
        responds (begin_capsules request) evs /\
        t.f_driver == run_from_capsules request evs /\
        terminal t.f_effect /\
        rekey_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         rekey_state_is_sound d /\ not d.f_committed /\
         (d.f_responded ==> d.f_capsules_complete) /\
         not (d.f_responded && d.f_failed))) =
  let t0 = begin_capsules request in
  run_capsules_is_run_ev #io_t #i s request;
  run_ev_follows_the_driver #io_t #i 67 s t0;
  run_ev_reaches_a_verdict #io_t #i 67 s t0;
  let (_, t2, evs) = run_ev #io_t #i 67 s t0 in
  rekey_capsules_trace_theorem request evs

let run_commit_theorem (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (
      let (_, t) = run_commit #io_t #i s request in
      exists (evs: list t_RekeyEvent).
        responds (begin_commit request) evs /\
        t.f_driver == run_from_commit request evs /\
        terminal t.f_effect /\
        rekey_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         rekey_state_is_sound d /\
         (d.f_committed ==>
           (d.f_active /\ d.f_starter_matches /\ d.f_rotation_matches /\
            d.f_chunks_complete /\ d.f_capsules_complete)) /\
         (d.f_responded ==> d.f_committed) /\
         not (d.f_responded && d.f_failed) /\
         (not d.f_failed || not d.f_committed))) =
  let t0 = begin_commit request in
  run_commit_is_run_ev #io_t #i s request;
  run_ev_follows_the_driver #io_t #i 67 s t0;
  run_ev_reaches_a_verdict #io_t #i 67 s t0;
  let (_, t2, evs) = run_ev #io_t #i 67 s t0 in
  rekey_commit_trace_theorem request evs

let run_abort_theorem (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t)
  (request: t_RekeyRequest)
  : Lemma (
      let (_, t) = run_abort #io_t #i s request in
      exists (evs: list t_RekeyEvent).
        responds (begin_abort request) evs /\
        t.f_driver == run_from_abort request evs /\
        terminal t.f_effect /\
        rekey_effect_is_sound t.f_driver t.f_effect /\
        (let d = t.f_driver in
         rekey_state_is_sound d /\ not d.f_committed /\
         (d.f_rolled_back ==> (d.f_active /\ d.f_epoch >=. v_INITIAL_EPOCH)) /\
         not (d.f_responded && d.f_failed))) =
  let t0 = begin_abort request in
  run_abort_is_run_ev #io_t #i s request;
  run_ev_follows_the_driver #io_t #i 67 s t0;
  run_ev_reaches_a_verdict #io_t #i 67 s t0;
  let (_, t2, evs) = run_ev #io_t #i 67 s t0 in
  rekey_abort_trace_theorem request evs
