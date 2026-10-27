module Vela_rekey_policy_rekey_driver_composition

/// Concurrent composition over one shared account rotation state.
///
/// Each action runs the *extracted* driver for one request (`begin_start`,
/// `begin_capsules`, `begin_commit`, `begin_abort` followed by `run` over an
/// arbitrary event list). The world only records the account's shared
/// rotation fact — the current epoch, whether a rotation is freezing, and the
/// live rotation id — plus the rotation ids that started, committed and
/// aborted. The counters are incremented from the driver's own verdicts, never
/// from a modelled SQL guard:
///
/// - `w_two_rotations` counts a successful `start` while the account is
///   already freezing;
/// - `w_second_commit` counts a successful commit whose rotation id already
///   committed (or was not the live rotation);
/// - `w_commit_after_abort` counts a successful commit of an aborted id.
///
/// The theorem below proves all three counters stay zero for every schedule,
/// that a committed id is never committed twice, and that a committed id is
/// never also recorded as aborted. The world observation supplied to the
/// driver is the shared account state; the driver's own policy functions then
/// refuse a start while freezing, a commit without the live rotation id, and
/// an abort without it.

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Rekey_driver
open Vela_rekey_policy_rekey_driver_lemmas

// ── Small list vocabulary ──────────────────────────────────────────────────

let rec contains (x: nat) (xs: list nat) : bool =
  match xs with
  | [] -> false
  | y :: ys -> if x = y then true else contains x ys

let rec nodup (xs: list nat) : bool =
  match xs with
  | [] -> true
  | y :: ys -> not (contains y ys) && nodup ys

let rec disjoint (a b: list nat) : bool =
  match a with
  | [] -> true
  | x :: xs -> not (contains x b) && disjoint xs b

/// Every element of `a` occurs in `b`.
let rec all_in (a b: list nat) : bool =
  match a with
  | [] -> true
  | x :: xs -> contains x b && all_in xs b

/// Insert once; ids start once (the server mints a fresh UUID per rotation).
let add_id (x: nat) (xs: list nat) : list nat =
  if contains x xs then xs else x :: xs

// ── World state ────────────────────────────────────────────────────────────

type t_World = {
  w_epoch: i64;
  w_freezing: bool;
  w_rid: nat;
  w_started: list nat;
  w_committed: list nat;
  w_aborted: list nat;
  w_two_rotations: nat;
  w_second_commit: nat;
  w_commit_after_abort: nat;
}

let initial_world : t_World = {
  w_epoch = mk_i64 1;
  w_freezing = false;
  w_rid = 0;
  w_started = [];
  w_committed = [];
  w_aborted = [];
  w_two_rotations = 0;
  w_second_commit = 0;
  w_commit_after_abort = 0;
}

let inv (w: t_World) : bool =
  w.w_epoch >=. v_INITIAL_EPOCH /\
  (w.w_freezing ==> contains w.w_rid w.w_started) /\
  (w.w_freezing ==> not (contains w.w_rid w.w_committed)) /\
  (w.w_freezing ==> not (contains w.w_rid w.w_aborted)) /\
  nodup w.w_committed /\
  nodup w.w_aborted /\
  disjoint w.w_committed w.w_aborted /\
  all_in w.w_committed w.w_started /\
  all_in w.w_aborted w.w_started /\
  w.w_two_rotations = 0 /\
  w.w_second_commit = 0 /\
  w.w_commit_after_abort = 0

// ── The shared observation handed to each driver ───────────────────────────

let world_obs (w: t_World) (rid: nat) : t_KeyStateObs =
  { f_epoch = w.w_epoch;
    f_freezing = w.w_freezing;
    f_starter_matches = (w.w_rid = rid);
    f_rotation_id_present = w.w_freezing;
    f_header_present = true;
    f_header_matches = (w.w_freezing && w.w_rid = rid);
    f_replay_target = Core_models.Option.Option_None;
    f_replay_recorded = Core_models.Option.Option_None;
    f_replay_id_matches = false;
    f_expired = false }

let device_request (capsules: i64) : t_RekeyRequest =
  { f_authenticated = true; f_device_scope = true; f_capsule_count = capsules }

/// The first two events every request observes: pacing and the shared state.
let preface (w: t_World) (rid: nat) : list t_RekeyEvent =
  [ RekeyEvent_RateLimit RateLimitObservation_Allowed;
    RekeyEvent_State (StateObservation_Loaded (world_obs w rid)) ]

let start_run (w: t_World) (rid: nat) (events: list t_RekeyEvent) : t_RekeyDriver =
  run (begin_start (device_request (mk_i64 0))).f_driver (preface w rid @ events)

let capsules_run (w: t_World) (rid: nat) (events: list t_RekeyEvent) : t_RekeyDriver =
  run (begin_capsules (device_request (mk_i64 0))).f_driver (preface w rid @ events)

let commit_run (w: t_World) (rid: nat) (events: list t_RekeyEvent) : t_RekeyDriver =
  run (begin_commit (device_request (mk_i64 0))).f_driver (preface w rid @ events)

let abort_run (w: t_World) (rid: nat) (events: list t_RekeyEvent) : t_RekeyDriver =
  run (begin_abort (device_request (mk_i64 0))).f_driver (preface w rid @ events)

// ── Driver verdicts determine the shared update ────────────────────────────

/// A second start while freezing is refused by the driver before any freeze
/// decision, so it can never respond.
let start_while_freezing_is_refused
      (w: t_World)
      (rid: nat)
      (events: list t_RekeyEvent)
  : Lemma
    (requires (w.w_freezing = true))
    (ensures (not (start_run w rid events).f_responded)) =
  let t0 = begin_start (device_request (mk_i64 0)) in
  let t1 = rekey_step t0.f_driver (RekeyEvent_RateLimit RateLimitObservation_Allowed) in
  let t2 = rekey_step t1.f_driver
    (RekeyEvent_State (StateObservation_Loaded (world_obs w rid))) in
  assert (t2.f_effect = RekeyEffect_Fail RekeyFailure_AlreadyInProgress);
  assert (is_done t2.f_driver);
  done_suffix_inert t2.f_driver events

/// A commit only succeeds for the live rotation id while the account is
/// freezing. An active account takes the replay path, which cannot authorize a
/// commit because no recorded replay epoch is supplied; a different id loses
/// the starter/rotation checks.
let commit_requires_live
      (w: t_World)
      (rid: nat)
      (events: list t_RekeyEvent)
  : Lemma
    (ensures (
      (commit_run w rid events).f_committed ==>
      (w.w_freezing = true /\ w.w_rid = rid))) =
  let t0 = begin_commit (device_request (mk_i64 0)) in
  let t1 = rekey_step t0.f_driver (RekeyEvent_RateLimit RateLimitObservation_Allowed) in
  let t2 = rekey_step t1.f_driver
    (RekeyEvent_State (StateObservation_Loaded (world_obs w rid))) in
  if w.w_freezing then begin
    if w.w_rid = rid then begin
      // Only this branch may reach the completeness probes and the commit CAS.
      assert (not (t2.f_effect = RekeyEffect_Fail RekeyFailure_NoRekeyInProgress));
      assert (not (t2.f_effect = RekeyEffect_Fail RekeyFailure_StarterRequired));
      assert (not (t2.f_effect = RekeyEffect_Fail RekeyFailure_RotationIdMismatch));
      ()
    end else begin
      assert (t2.f_effect = RekeyEffect_Fail RekeyFailure_StarterRequired \/
              t2.f_effect = RekeyEffect_Fail RekeyFailure_RotationIdMismatch);
      assert (is_done t2.f_driver);
      done_suffix_inert t2.f_driver events;
      assert (not (commit_run w rid events).f_committed)
    end
  end else begin
    assert (t2.f_effect = RekeyEffect_Fail RekeyFailure_NoRekeyInProgress);
    assert (is_done t2.f_driver);
    done_suffix_inert t2.f_driver events;
    assert (not (commit_run w rid events).f_committed)
  end

/// An abort only rolls back the live rotation id.
let abort_requires_live
      (w: t_World)
      (rid: nat)
      (events: list t_RekeyEvent)
  : Lemma
    (ensures (
      (abort_run w rid events).f_rolled_back ==>
      (w.w_freezing = true /\ w.w_rid = rid))) =
  let t0 = begin_abort (device_request (mk_i64 0)) in
  let t1 = rekey_step t0.f_driver (RekeyEvent_RateLimit RateLimitObservation_Allowed) in
  let t2 = rekey_step t1.f_driver
    (RekeyEvent_State (StateObservation_Loaded (world_obs w rid))) in
  if w.w_freezing then begin
    if w.w_rid = rid then ()
    else begin
      assert (t2.f_effect = RekeyEffect_Fail RekeyFailure_StarterRequired \/
              t2.f_effect = RekeyEffect_Fail RekeyFailure_RotationIdMismatch);
      assert (is_done t2.f_driver);
      done_suffix_inert t2.f_driver events;
      assert (not (abort_run w rid events).f_rolled_back)
    end
  end else begin
    assert (t2.f_effect = RekeyEffect_Fail RekeyFailure_NoRekeyInProgress);
    assert (is_done t2.f_driver);
    done_suffix_inert t2.f_driver events;
    assert (not (abort_run w rid events).f_rolled_back)
  end

// ── The schedule ───────────────────────────────────────────────────────────

type t_Action =
  | ActStart : rid: nat -> events: list t_RekeyEvent -> t_Action
  | ActCapsules : rid: nat -> events: list t_RekeyEvent -> t_Action
  | ActCommit : rid: nat -> events: list t_RekeyEvent -> t_Action
  | ActAbort : rid: nat -> events: list t_RekeyEvent -> t_Action

let step_world (w: t_World) (action: t_Action) : t_World =
  match action with
  | ActStart rid events ->
      let d = start_run w rid events in
      if contains rid w.w_started then
        // Ids are minted once; a reused id is not a new rotation.
        w
      else if d.f_responded && not d.f_failed then
        if w.w_freezing then
          { w with w_two_rotations = w.w_two_rotations + 1 }
        else
          { w with w_freezing = true;
                   w_rid = rid;
                   w_started = rid :: w.w_started }
      else w
  | ActCapsules _ _ -> w
  | ActCommit rid events ->
      let d = commit_run w rid events in
      if d.f_committed then
        if contains rid w.w_committed then
          { w with w_second_commit = w.w_second_commit + 1 }
        else if contains rid w.w_aborted then
          { w with w_commit_after_abort = w.w_commit_after_abort + 1 }
        else if w.w_freezing && w.w_rid = rid then
          { w with w_epoch = w.w_epoch +. mk_i64 1;
                   w_freezing = false;
                   w_committed = rid :: w.w_committed }
        else
          { w with w_second_commit = w.w_second_commit + 1 }
      else w
  | ActAbort rid events ->
      let d = abort_run w rid events in
      if d.f_rolled_back && w.w_freezing && w.w_rid = rid then
        { w with w_freezing = false;
                 w_aborted = rid :: w.w_aborted }
      else w

let rec run_world (w: t_World) (schedule: list t_Action) : t_World =
  match schedule with
  | [] -> w
  | action :: rest -> run_world (step_world w action) rest

// ── Preservation ───────────────────────────────────────────────────────────

let step_world_preserves_inv (w: t_World) (action: t_Action)
  : Lemma
    (requires (inv w))
    (ensures (inv (step_world w action))) =
  match action with
  | ActStart rid events ->
      if contains rid w.w_started then ()
      else begin
        let d = start_run w rid events in
        if d.f_responded && not d.f_failed then begin
          // `start_while_freezing_is_refused` makes the counter branch
          // unreachable.
          if w.w_freezing then begin
            start_while_freezing_is_refused w rid events;
            assert false
          end else begin
            assert (not (contains rid w.w_committed));
            assert (not (contains rid w.w_aborted));
            ()
          end
        end
      end
  | ActCapsules _ _ -> ()
  | ActCommit rid events ->
      let d = commit_run w rid events in
      if d.f_committed then begin
        commit_requires_live w rid events;
        if contains rid w.w_committed then begin
          // The live id cannot already be committed (invariant).
          assert false
        end else if contains rid w.w_aborted then begin
          assert false
        end else if w.w_freezing && w.w_rid = rid then begin
          assert (not (contains rid w.w_committed));
          assert (not (contains rid w.w_aborted));
          ()
        end else begin
          assert false
        end
      end
  | ActAbort rid events ->
      let d = abort_run w rid events in
      if d.f_rolled_back && w.w_freezing && w.w_rid = rid then begin
        abort_requires_live w rid events;
        ()
      end

let rec run_world_preserves_inv (w: t_World) (schedule: list t_Action)
  : Lemma
    (requires (inv w))
    (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | action :: rest ->
      step_world_preserves_inv w action;
      run_world_preserves_inv (step_world w action) rest

// ── Headline composition theorem ───────────────────────────────────────────

let rekey_composition_theorem (schedule: list t_Action)
  : Lemma (
      let w = run_world initial_world schedule in
      inv w /\
      w.w_two_rotations = 0 /\
      w.w_second_commit = 0 /\
      w.w_commit_after_abort = 0 /\
      nodup w.w_committed /\
      disjoint w.w_committed w.w_aborted) =
  run_world_preserves_inv initial_world schedule

let no_second_commit (schedule: list t_Action)
  : Lemma ((run_world initial_world schedule).w_second_commit = 0) =
  rekey_composition_theorem schedule

let no_commit_after_abort (schedule: list t_Action)
  : Lemma ((run_world initial_world schedule).w_commit_after_abort = 0) =
  rekey_composition_theorem schedule

let no_two_concurrent_rotations (schedule: list t_Action)
  : Lemma ((run_world initial_world schedule).w_two_rotations = 0) =
  rekey_composition_theorem schedule

let committed_ids_are_unique (schedule: list t_Action)
  : Lemma (nodup (run_world initial_world schedule).w_committed /\
           disjoint (run_world initial_world schedule).w_committed
                    (run_world initial_world schedule).w_aborted) =
  rekey_composition_theorem schedule

// ── Witness schedules ──────────────────────────────────────────────────────

let successful_start_events : list t_RekeyEvent =
  [ RekeyEvent_Oram ProbeObservation_Empty;
    RekeyEvent_Capable ProbeObservation_Empty;
    RekeyEvent_Acknowledged ProbeObservation_Empty;
    RekeyEvent_Transaction TransactionObservation_Committed;
    RekeyEvent_Inventory InventoryObservation_Read;
    RekeyEvent_FreezeCas CasObservation_Updated;
    RekeyEvent_Cleanup CleanupObservation_Done;
    RekeyEvent_TxCommit TransactionObservation_Committed ]

let successful_commit_events : list t_RekeyEvent =
  [ RekeyEvent_Chunks ProbeObservation_Empty;
    RekeyEvent_Devices ProbeObservation_Empty;
    RekeyEvent_CommitCas CasObservation_Updated;
    RekeyEvent_Sweep SweepObservation_Done;
    RekeyEvent_Published ]

let successful_abort_events : list t_RekeyEvent =
  [ RekeyEvent_Rollback RollbackObservation_RolledBack ]

let witness_complete : list t_Action =
  [ ActStart 1 successful_start_events;
    ActCapsules 1 [];
    ActCommit 1 successful_commit_events ]

let witness_abort : list t_Action =
  [ ActStart 1 successful_start_events;
    ActAbort 1 successful_abort_events ]

let witness_start_records_one_rotation ()
  : Lemma (
      let w = run_world initial_world [ActStart 1 successful_start_events] in
      w.w_freezing = true /\ w.w_rid = 1 /\ contains 1 w.w_started /\
      w.w_two_rotations = 0) =
  ()

let witness_complete_commits_once ()
  : Lemma (
      let w = run_world initial_world witness_complete in
      contains 1 w.w_committed /\ nodup w.w_committed /\
      w.w_second_commit = 0 /\ w.w_epoch = mk_i64 2 /\
      not w.w_freezing) =
  ()

let witness_abort_clears_the_rotation ()
  : Lemma (
      let w = run_world initial_world witness_abort in
      contains 1 w.w_aborted /\ not w.w_freezing /\
      not (contains 1 w.w_committed) /\
      w.w_commit_after_abort = 0) =
  ()

let witness_second_start_does_not_run ()
  : Lemma (
      let w = run_world initial_world
        [ ActStart 1 successful_start_events;
          ActStart 2 successful_start_events ] in
      w.w_freezing = true /\ w.w_rid = 1 /\
      w.w_two_rotations = 0) =
  ()
