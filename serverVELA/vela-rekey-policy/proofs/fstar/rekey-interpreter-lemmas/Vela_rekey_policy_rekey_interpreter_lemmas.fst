module Vela_rekey_policy_rekey_interpreter_lemmas

/// Shared specification of the four rotation handler loops.
///
/// The extracted `run_start`, `run_capsules`, `run_commit` and `run_abort` are
/// the loops the four rotation handlers run: the server expands the same
/// `rekey_*_interpreter!` macro text, adding only `.await` after each executor
/// call. This module defines one interpreter turn (`turn_ev`), its iteration
/// (`iter_turn`, `run_ev`) and proves, by induction on the number of turns and
/// for every executor implementation (any `t_RekeyIo` instance, any
/// behaviour):
///
/// 1. `iter_turn n` and `run_ev n` agree (`iter_turn_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run d evs` (`run_ev_follows_the_driver`);
/// 3. answering the current effect strictly decreases a per-entry-point
///    measure bounded by the loop budget (`step_progress`), so the driver
///    reaches a verdict within the budget (`run_ev_reaches_a_verdict`).
///
/// The per-loop modules (`Vela_rekey_policy_rekey_{start,capsules,commit,
/// abort}_interpreter_lemmas`) each connect one extracted loop to `iter_turn`
/// and conclude the per-request theorems. They are checked in separate
/// fstar.exe invocations so the SMT pattern of each fold lemma cannot interact
/// with the other loops.
///
/// No lemma unrolls a loop: every statement about `n` turns is proved by
/// induction on `n` from a one-turn lemma.
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_rekey_policy
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

/// The extracted loop invariant (`rekey_loop_is_sound`).
let sound_transition (t: t_RekeyTransition) : bool =
  rekey_state_is_sound t.f_driver && rekey_effect_is_sound t.f_driver t.f_effect

/// What one turn did: nothing at a verdict, otherwise one observation that
/// answers the current effect, fed to the extracted `rekey_step`.
let turn_post (#io_t: Type0) (s: io_t) (t: t_RekeyTransition{rekey_state_is_sound t.f_driver})
  (r: io_t & t_RekeyTransition & option t_RekeyEvent) : prop =
  let (s1, t1, o) = r in
  match o with
  | None -> terminal t.f_effect /\ s1 == s /\ t1 == t
  | Some ev ->
      not (terminal t.f_effect) /\ responds_to t.f_effect ev /\
      t1 == rekey_step t.f_driver ev

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `rekey_step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t) (t: t_RekeyTransition)
  : Pure (io_t & t_RekeyTransition & option t_RekeyEvent)
    (requires (rekey_state_is_sound t.f_driver))
    (ensures fun r -> turn_post s t r) =
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
      let s' = f_publish_epoch #io_t #i s t.f_driver.f_to_epoch in
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

// ── 1. `iter_turn` is `run_ev` ─────────────────────────────────────────────

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (s2, t2, _) = run_ev #io_t #i n s t in
                    iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = turn_ev #io_t #i s t in
    assert (turn #io_t #i (s, t) == (s1, t1));
    iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

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

/// A capsule write at index `k` has at most `65 - k` effects left: the writes
/// `k..64`. The driver refuses the 65th write.
let capsule_remaining (index: i64) : nat =
  if 0 <= v index && v index <= 64 then 65 - v index else 0

/// Effects still to perform before a verdict, per entry point. The extracted
/// loops have separate budgets, so the measure is selected by the driver's
/// operation. Each entry point's first effect is exactly its budget.
let start_remaining (e: t_RekeyEffect) : nat =
  match e with
  | RekeyEffect_RateLimit -> 12
  | RekeyEffect_LoadState -> 11
  | RekeyEffect_TimeoutRollback -> 10
  | RekeyEffect_CheckOram -> 9
  | RekeyEffect_CheckCapable -> 8
  | RekeyEffect_CheckAcknowledged -> 7
  | RekeyEffect_BeginFreezeTransaction -> 6
  | RekeyEffect_ReadInventory -> 5
  | RekeyEffect_FreezeCas -> 4
  | RekeyEffect_CleanupChunks -> 3
  | RekeyEffect_CommitFreezeTransaction -> 2
  | _ -> 0

let capsules_remaining (e: t_RekeyEffect) : nat =
  match e with
  | RekeyEffect_RateLimit -> 68
  | RekeyEffect_LoadState -> 67
  | RekeyEffect_TimeoutRollback -> 66
  | RekeyEffect_WriteCapsule { f_index = index } -> capsule_remaining index
  | _ -> 0

let commit_remaining (e: t_RekeyEffect) : nat =
  match e with
  | RekeyEffect_RateLimit -> 10
  | RekeyEffect_LoadState -> 9
  | RekeyEffect_TimeoutRollback -> 8
  | RekeyEffect_CheckChunkShadows -> 7
  | RekeyEffect_CheckDeviceCapsules -> 6
  | RekeyEffect_CommitCas -> 5
  | RekeyEffect_SweepOldChunks -> 4
  | RekeyEffect_PublishEpoch -> 3
  | _ -> 0

let abort_remaining (e: t_RekeyEffect) : nat =
  match e with
  | RekeyEffect_RateLimit -> 4
  | RekeyEffect_LoadState -> 3
  | RekeyEffect_TimeoutRollback -> 2
  | RekeyEffect_RollbackAttempt -> 1
  | _ -> 0

let remaining_at (op: t_RekeyOp) (e: t_RekeyEffect) : nat =
  match op with
  | RekeyOp_Start -> start_remaining e
  | RekeyOp_Capsules -> capsules_remaining e
  | RekeyOp_Commit -> commit_remaining e
  | RekeyOp_Abort -> abort_remaining e

let remaining (t: t_RekeyTransition) : nat = remaining_at t.f_driver.f_op t.f_effect

/// The capsule counter never goes negative. The driver's own invariant bounds
/// it from above only; this lemma module carries the lower bound so the
/// capsule measure is positive at every write.
let counter_ok (d: t_RekeyDriver) : bool = v d.f_capsules_written >= 0

let progress_ok (t: t_RekeyTransition) : bool =
  sound_transition t && counter_ok t.f_driver

/// The one-step obligation: answering the current effect keeps the counter
/// bound and strictly decreases the measure.
let progresses (t: t_RekeyTransition) (t': t_RekeyTransition) : prop =
  counter_ok t'.f_driver /\ remaining t' < remaining t

/// Every non-terminal effect a sound driver emits has a positive measure.
let positive_remaining (t: t_RekeyTransition)
  : Lemma (requires progress_ok t /\ not (terminal t.f_effect))
          (ensures remaining t > 0) =
  match t.f_effect with
  | RekeyEffect_WriteCapsule { f_index = index } -> ()
  | RekeyEffect_SweepOldChunks -> ()
  | RekeyEffect_PublishEpoch -> ()
  | _ -> ()

// One lemma per effect: the driver's answer to that effect's observation.

let progress_rate_limit (t: t_RekeyTransition) (o: t_RateLimitObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_RateLimit)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_RateLimit o))) =
  match o with
  | RateLimitObservation_Allowed -> ()
  | RateLimitObservation_Limited -> ()

#push-options "--fuel 4 --ifuel 2"
let progress_state_start (t: t_RekeyTransition) (o: t_StateObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_LoadState /\
                    t.f_driver.f_op == RekeyOp_Start)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let progress_state_capsules (t: t_RekeyTransition) (o: t_StateObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_LoadState /\
                    t.f_driver.f_op == RekeyOp_Capsules)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let progress_state_commit (t: t_RekeyTransition) (o: t_StateObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_LoadState /\
                    t.f_driver.f_op == RekeyOp_Commit)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let progress_state_abort (t: t_RekeyTransition) (o: t_StateObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_LoadState /\
                    t.f_driver.f_op == RekeyOp_Abort)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let progress_timeout_start (t: t_RekeyTransition) (o: t_TimeoutObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_TimeoutRollback /\
                    t.f_driver.f_op == RekeyOp_Start)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let progress_timeout_capsules (t: t_RekeyTransition) (o: t_TimeoutObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_TimeoutRollback /\
                    t.f_driver.f_op == RekeyOp_Capsules)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let progress_timeout_commit (t: t_RekeyTransition) (o: t_TimeoutObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_TimeoutRollback /\
                    t.f_driver.f_op == RekeyOp_Commit)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let progress_timeout_abort (t: t_RekeyTransition) (o: t_TimeoutObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_TimeoutRollback /\
                    t.f_driver.f_op == RekeyOp_Abort)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()
#pop-options

let progress_state (t: t_RekeyTransition) (o: t_StateObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_LoadState)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_State o))) =
  match t.f_driver.f_op with
  | RekeyOp_Start -> progress_state_start t o
  | RekeyOp_Capsules -> progress_state_capsules t o
  | RekeyOp_Commit -> progress_state_commit t o
  | RekeyOp_Abort -> progress_state_abort t o

let progress_timeout (t: t_RekeyTransition) (o: t_TimeoutObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_TimeoutRollback)
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_Timeout o))) =
  match t.f_driver.f_op with
  | RekeyOp_Start -> progress_timeout_start t o
  | RekeyOp_Capsules -> progress_timeout_capsules t o
  | RekeyOp_Commit -> progress_timeout_commit t o
  | RekeyOp_Abort -> progress_timeout_abort t o

let progress_probe (t: t_RekeyTransition) (ev: t_RekeyEvent)
  : Lemma (requires progress_ok t /\
                    (match t.f_effect, ev with
                     | RekeyEffect_CheckOram, RekeyEvent_Oram _
                     | RekeyEffect_CheckCapable, RekeyEvent_Capable _
                     | RekeyEffect_CheckAcknowledged, RekeyEvent_Acknowledged _
                     | RekeyEffect_CheckChunkShadows, RekeyEvent_Chunks _
                     | RekeyEffect_CheckDeviceCapsules, RekeyEvent_Devices _ -> True
                     | _ -> False))
          (ensures progresses t (rekey_step t.f_driver ev)) =
  match ev with
  | RekeyEvent_Oram ProbeObservation_Empty -> ()
  | RekeyEvent_Oram ProbeObservation_Found -> ()
  | RekeyEvent_Oram ProbeObservation_Storage -> ()
  | RekeyEvent_Capable ProbeObservation_Empty -> ()
  | RekeyEvent_Capable ProbeObservation_Found -> ()
  | RekeyEvent_Capable ProbeObservation_Storage -> ()
  | RekeyEvent_Acknowledged ProbeObservation_Empty -> ()
  | RekeyEvent_Acknowledged ProbeObservation_Found -> ()
  | RekeyEvent_Acknowledged ProbeObservation_Storage -> ()
  | RekeyEvent_Chunks ProbeObservation_Empty -> ()
  | RekeyEvent_Chunks ProbeObservation_Found -> ()
  | RekeyEvent_Chunks ProbeObservation_Storage -> ()
  | RekeyEvent_Devices ProbeObservation_Empty -> ()
  | RekeyEvent_Devices ProbeObservation_Found -> ()
  | RekeyEvent_Devices ProbeObservation_Storage -> ()
  | _ -> ()

let progress_freeze (t: t_RekeyTransition) (ev: t_RekeyEvent)
  : Lemma (requires progress_ok t /\
                    (match t.f_effect, ev with
                     | RekeyEffect_BeginFreezeTransaction, RekeyEvent_Transaction _
                     | RekeyEffect_ReadInventory, RekeyEvent_Inventory _
                     | RekeyEffect_FreezeCas, RekeyEvent_FreezeCas _
                     | RekeyEffect_CleanupChunks, RekeyEvent_Cleanup _
                     | RekeyEffect_CommitFreezeTransaction, RekeyEvent_TxCommit _ -> True
                     | _ -> False))
          (ensures progresses t (rekey_step t.f_driver ev)) =
  match ev with
  | RekeyEvent_Transaction TransactionObservation_Committed -> ()
  | RekeyEvent_Transaction TransactionObservation_Failed -> ()
  | RekeyEvent_Inventory InventoryObservation_Read -> ()
  | RekeyEvent_Inventory InventoryObservation_Failed -> ()
  | RekeyEvent_FreezeCas CasObservation_Updated -> ()
  | RekeyEvent_FreezeCas CasObservation_Skipped -> ()
  | RekeyEvent_FreezeCas CasObservation_Storage -> ()
  | RekeyEvent_Cleanup CleanupObservation_Done -> ()
  | RekeyEvent_Cleanup CleanupObservation_Storage -> ()
  | RekeyEvent_TxCommit TransactionObservation_Committed -> ()
  | RekeyEvent_TxCommit TransactionObservation_Failed -> ()
  | _ -> ()

let progress_capsule (t: t_RekeyTransition) (index: i64) (o: t_CapsuleObservation)
  : Lemma (requires progress_ok t /\ t.f_effect == RekeyEffect_WriteCapsule ({ f_index = index }))
          (ensures progresses t (rekey_step t.f_driver (RekeyEvent_Capsule o))) =
  match o with
  | CapsuleObservation_Stored -> ()
  | CapsuleObservation_Invalid -> ()
  | CapsuleObservation_NotTarget -> ()
  | CapsuleObservation_Storage -> ()

let progress_commit (t: t_RekeyTransition) (ev: t_RekeyEvent)
  : Lemma (requires progress_ok t /\
                    (match t.f_effect, ev with
                     | RekeyEffect_CommitCas, RekeyEvent_CommitCas _
                     | RekeyEffect_SweepOldChunks, RekeyEvent_Sweep _
                     | RekeyEffect_PublishEpoch, RekeyEvent_Published
                     | RekeyEffect_RollbackAttempt, RekeyEvent_Rollback _ -> True
                     | _ -> False))
          (ensures progresses t (rekey_step t.f_driver ev)) =
  match ev with
  | RekeyEvent_CommitCas CasObservation_Updated -> ()
  | RekeyEvent_CommitCas CasObservation_Skipped -> ()
  | RekeyEvent_CommitCas CasObservation_Storage -> ()
  | RekeyEvent_Sweep SweepObservation_Done -> ()
  | RekeyEvent_Sweep SweepObservation_Failed -> ()
  | RekeyEvent_Published -> ()
  | RekeyEvent_Rollback RollbackObservation_RolledBack -> ()
  | RekeyEvent_Rollback RollbackObservation_Raced -> ()
  | RekeyEvent_Rollback RollbackObservation_Storage -> ()
  | _ -> ()

/// Answering the current effect moves strictly closer to a verdict.
let step_progress (t: t_RekeyTransition) (ev: t_RekeyEvent)
  : Lemma (requires progress_ok t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures progresses t (rekey_step t.f_driver ev)) =
  match t.f_effect, ev with
  | RekeyEffect_RateLimit, RekeyEvent_RateLimit o -> progress_rate_limit t o
  | RekeyEffect_LoadState, RekeyEvent_State o -> progress_state t o
  | RekeyEffect_TimeoutRollback, RekeyEvent_Timeout o -> progress_timeout t o
  | RekeyEffect_WriteCapsule { f_index = index }, RekeyEvent_Capsule o ->
      progress_capsule t index o
  | RekeyEffect_CheckOram, _
  | RekeyEffect_CheckCapable, _
  | RekeyEffect_CheckAcknowledged, _
  | RekeyEffect_CheckChunkShadows, _
  | RekeyEffect_CheckDeviceCapsules, _ -> progress_probe t ev
  | RekeyEffect_BeginFreezeTransaction, _
  | RekeyEffect_ReadInventory, _
  | RekeyEffect_FreezeCas, _
  | RekeyEffect_CleanupChunks, _
  | RekeyEffect_CommitFreezeTransaction, _ -> progress_freeze t ev
  | RekeyEffect_CommitCas, _
  | RekeyEffect_SweepOldChunks, _
  | RekeyEffect_PublishEpoch, _
  | RekeyEffect_RollbackAttempt, _ -> progress_commit t ev
  | _ -> ()

/// One turn keeps `progress_ok`; it stays put at a verdict and otherwise
/// strictly decreases the measure.
let turn_progress (#io_t: Type0) {| i: t_RekeyIo io_t |} (s: io_t) (t: t_RekeyTransition)
  : Lemma (requires progress_ok t)
          (ensures (let (_, t1, _) = turn_ev #io_t #i s t in
                    progress_ok t1 /\
                    (terminal t.f_effect ==> t1 == t) /\
                    (not (terminal t.f_effect) ==> remaining t1 < remaining t))) =
  let (_, t1, o) = turn_ev #io_t #i s t in
  match o with
  | None -> ()
  | Some ev -> step_progress t ev

/// `n + 1` turns are one turn followed by `n` turns.
let run_ev_unfold (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyTransition)
  : Lemma (requires sound_transition t /\ n > 0)
          (ensures (let (s1, t1, _) = turn_ev #io_t #i s t in
                    let (_, t2, _) = run_ev #io_t #i n s t in
                    let (_, t2', _) = run_ev #io_t #i (n - 1) s1 t1 in
                    t2 == t2')) = ()

/// The induction over the loop: no unrolling, one `turn_progress` per turn.
let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_RekeyIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyTransition)
  : Lemma (requires progress_ok t /\ remaining t <= n)
          (ensures (let (_, t2, _) = run_ev #io_t #i n s t in terminal t2.f_effect))
          (decreases n) =
  if n = 0 then begin
    if not (terminal t.f_effect) then positive_remaining t
  end else begin
    let (s1, t1, _) = turn_ev #io_t #i s t in
    turn_progress #io_t #i s t;
    run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1;
    run_ev_unfold #io_t #i n s t
  end

/// Every entry point starts within its budget.
let begin_progress_ok (r: t_RekeyRequest)
  : Lemma (progress_ok (begin_start r) /\ remaining (begin_start r) <= 12 /\
           progress_ok (begin_capsules r) /\ remaining (begin_capsules r) <= 68 /\
           progress_ok (begin_commit r) /\ remaining (begin_commit r) <= 10 /\
           progress_ok (begin_abort r) /\ remaining (begin_abort r) <= 4) = ()
