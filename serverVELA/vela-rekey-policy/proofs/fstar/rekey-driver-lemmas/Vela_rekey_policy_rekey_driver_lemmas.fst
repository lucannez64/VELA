module Vela_rekey_policy_rekey_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* vault
/// key-rotation driver (`Vela_rekey_policy.Rekey_driver`).
///
/// Scope: one `RekeyDriver` value, i.e. one HTTP request to
/// `POST /vault/rekey/{start,capsules,commit,abort}`. The theorem does not
/// claim anything about two concurrent requests; that is
/// `Vela_rekey_policy_rekey_driver_composition`. The SQL statements, the
/// transaction, the store publication and the order in which the handler
/// performs them remain effectful glue outside this module. The driver's
/// observations are never verified origins.
///
/// The security-relevant invariant is the extracted `rekey_state_is_sound`
/// predicate, which every `begin_*` and `rekey_step` postcondition already
/// carries. The lemmas below therefore use the driver's own contract instead
/// of restating the transition relation. All trace lemmas quantify over every
/// event list.

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Rekey_driver

let is_done (d: t_RekeyDriver) : bool =
  match d.f_stage <: t_RekeyStage with
  | RekeyStage_Done -> true
  | _ -> false

let is_timeout (d: t_RekeyDriver) : bool =
  match d.f_stage <: t_RekeyStage with
  | RekeyStage_Timeout -> true
  | _ -> false

let is_rollback (d: t_RekeyDriver) : bool =
  match d.f_stage <: t_RekeyStage with
  | RekeyStage_Rollback -> true
  | _ -> false

let is_start_op (d: t_RekeyDriver) : bool =
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Start -> true
  | _ -> false

let is_commit_op (d: t_RekeyDriver) : bool =
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Commit -> true
  | _ -> false

let is_abort_op (d: t_RekeyDriver) : bool =
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Abort -> true
  | _ -> false

let is_capsules_op (d: t_RekeyDriver) : bool =
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Capsules -> true
  | _ -> false

let begin_sound_start (r: t_RekeyRequest)
  : Lemma (rekey_state_is_sound (begin_start r).f_driver) = ()

let begin_sound_capsules (r: t_RekeyRequest)
  : Lemma (rekey_state_is_sound (begin_capsules r).f_driver) = ()

let begin_sound_commit (r: t_RekeyRequest)
  : Lemma (rekey_state_is_sound (begin_commit r).f_driver) = ()

let begin_sound_abort (r: t_RekeyRequest)
  : Lemma (rekey_state_is_sound (begin_abort r).f_driver) = ()

let step_sound (d: t_RekeyDriver) (e: t_RekeyEvent)
  : Lemma
    (requires (rekey_state_is_sound d))
    (ensures (rekey_state_is_sound (rekey_step d e).f_driver)) = ()

let step_effect_sound (d: t_RekeyDriver) (e: t_RekeyEvent)
  : Lemma
    (requires (rekey_state_is_sound d))
    (ensures (
      rekey_effect_is_sound (rekey_step d e).f_driver (rekey_step d e).f_effect)) = ()

let rec run (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Pure t_RekeyDriver
    (requires (rekey_state_is_sound d))
    (ensures (fun result -> rekey_state_is_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      step_sound d e;
      run (rekey_step d e).f_driver rest

let rec last_effect (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Pure t_RekeyEffect
    (requires (rekey_state_is_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> RekeyEffect_Idle
  | e :: [] -> (rekey_step d e).f_effect
  | e :: rest ->
      step_sound d e;
      last_effect (rekey_step d e).f_driver rest

let run_from_start (r: t_RekeyRequest) (events: list t_RekeyEvent)
  : Pure t_RekeyDriver (requires True)
    (ensures (fun result -> rekey_state_is_sound result)) (decreases events) =
  begin_sound_start r;
  run (begin_start r).f_driver events

let run_from_capsules (r: t_RekeyRequest) (events: list t_RekeyEvent)
  : Pure t_RekeyDriver (requires True)
    (ensures (fun result -> rekey_state_is_sound result)) (decreases events) =
  begin_sound_capsules r;
  run (begin_capsules r).f_driver events

let run_from_commit (r: t_RekeyRequest) (events: list t_RekeyEvent)
  : Pure t_RekeyDriver (requires True)
    (ensures (fun result -> rekey_state_is_sound result)) (decreases events) =
  begin_sound_commit r;
  run (begin_commit r).f_driver events

let run_from_abort (r: t_RekeyRequest) (events: list t_RekeyEvent)
  : Pure t_RekeyDriver (requires True)
    (ensures (fun result -> rekey_state_is_sound result)) (decreases events) =
  begin_sound_abort r;
  run (begin_abort r).f_driver events

let rec op_sticky (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Lemma
    (requires (rekey_state_is_sound d))
    (ensures ((run d events).f_op = d.f_op))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_sound d e;
      op_sticky (rekey_step d e).f_driver rest

let step_after_done (d: t_RekeyDriver) (e: t_RekeyEvent)
  : Lemma
    (requires (rekey_state_is_sound d /\ is_done d))
    (ensures ((rekey_step d e).f_driver = d /\
              (rekey_step d e).f_effect = RekeyEffect_Idle)) =
  match e <: t_RekeyEvent with
  | RekeyEvent_RateLimit _ -> ()
  | RekeyEvent_State _ -> ()
  | RekeyEvent_Timeout _ -> ()
  | RekeyEvent_Oram _ -> ()
  | RekeyEvent_Capable _ -> ()
  | RekeyEvent_Acknowledged _ -> ()
  | RekeyEvent_Transaction _ -> ()
  | RekeyEvent_Inventory _ -> ()
  | RekeyEvent_FreezeCas _ -> ()
  | RekeyEvent_Cleanup _ -> ()
  | RekeyEvent_TxCommit _ -> ()
  | RekeyEvent_Capsule _ -> ()
  | RekeyEvent_Chunks _ -> ()
  | RekeyEvent_Devices _ -> ()
  | RekeyEvent_CommitCas _ -> ()
  | RekeyEvent_Sweep _ -> ()
  | RekeyEvent_Published -> ()
  | RekeyEvent_Rollback _ -> ()

let rec count_complete (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Pure nat (requires (rekey_state_is_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      step_sound d e;
      (match (rekey_step d e).f_effect <: t_RekeyEffect with
       | RekeyEffect_Complete -> 1
       | _ -> 0) + count_complete (rekey_step d e).f_driver rest

let rec count_fail (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Pure nat (requires (rekey_state_is_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      step_sound d e;
      (match (rekey_step d e).f_effect <: t_RekeyEffect with
       | RekeyEffect_Fail _ -> 1
       | _ -> 0) + count_fail (rekey_step d e).f_driver rest

let rec count_commit_cas (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Pure nat (requires (rekey_state_is_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      step_sound d e;
      (match (rekey_step d e).f_effect <: t_RekeyEffect with
       | RekeyEffect_CommitCas -> 1
       | _ -> 0) + count_commit_cas (rekey_step d e).f_driver rest

let rec done_suffix_inert (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Lemma
    (requires (rekey_state_is_sound d /\ is_done d))
    (ensures (run d events = d /\ last_effect d events = RekeyEffect_Idle /\
              count_complete d events = 0 /\
              count_fail d events = 0 /\
              count_commit_cas d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

let rec complete_count_le_one (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Lemma (requires (rekey_state_is_sound d))
          (ensures (count_complete d events <= 1))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_sound d e;
      step_effect_sound d e;
      let t = rekey_step d e in
      if (match t.f_effect <: t_RekeyEffect with
          | RekeyEffect_Complete -> true
          | _ -> false)
      then begin
        assert (is_done t.f_driver);
        done_suffix_inert t.f_driver rest
      end else complete_count_le_one t.f_driver rest

let rec fail_count_le_one (d: t_RekeyDriver) (events: list t_RekeyEvent)
  : Lemma (requires (rekey_state_is_sound d))
          (ensures (count_fail d events <= 1))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_sound d e;
      step_effect_sound d e;
      let t = rekey_step d e in
      if (match t.f_effect <: t_RekeyEffect with
          | RekeyEffect_Fail _ -> true
          | _ -> false)
      then begin
        assert (is_done t.f_driver);
        done_suffix_inert t.f_driver rest
      end else fail_count_le_one t.f_driver rest

/// `committed` is monotone: no transition ever clears it.
let commit_effect_requires_completeness (d: t_RekeyDriver) (e: t_RekeyEvent)
  : Lemma
    (requires (rekey_state_is_sound d))
    (ensures (
      (rekey_step d e).f_effect = RekeyEffect_CommitCas ==>
      ((rekey_step d e).f_driver.f_chunks_complete /\
       (rekey_step d e).f_driver.f_capsules_complete /\
       (rekey_step d e).f_driver.f_device_scope /\
       (rekey_step d e).f_driver.f_starter_matches /\
       (rekey_step d e).f_driver.f_rotation_present /\
       (rekey_step d e).f_driver.f_rotation_matches))) =
  step_effect_sound d e

let abort_rollback_restores_active
      (d: t_RekeyDriver)
      (observation: t_RollbackObservation)
  : Lemma
    (requires (rekey_state_is_sound d /\ is_rollback d))
    (ensures (
      observation = RollbackObservation_RolledBack ==>
      (let t = rekey_step d (RekeyEvent_Rollback observation) in
       t.f_effect = RekeyEffect_Complete /\
       t.f_driver.f_rolled_back /\
       t.f_driver.f_active /\
       t.f_driver.f_epoch = d.f_epoch /\
       not t.f_driver.f_committed))) =
  match observation <: t_RollbackObservation with
  | RollbackObservation_RolledBack -> ()
  | RollbackObservation_Raced -> ()
  | RollbackObservation_Storage -> ()

let timeout_rollback_restores_active
      (d: t_RekeyDriver)
      (observation: t_TimeoutObservation)
  : Lemma
    (requires (rekey_state_is_sound d /\ is_timeout d))
    (ensures (
      observation = TimeoutObservation_RolledBack ==>
      (let t = rekey_step d (RekeyEvent_Timeout observation) in
       t.f_driver.f_rolled_back /\
       t.f_driver.f_timeout_rollback /\
       t.f_driver.f_active /\
       t.f_driver.f_epoch = d.f_epoch /\
       not t.f_driver.f_committed))) =
  match observation <: t_TimeoutObservation with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let inactive_request (capsules: i64) : t_RekeyRequest =
  { f_authenticated = true; f_device_scope = false; f_capsule_count = capsules }

let web_start_is_refused (events: list t_RekeyEvent)
  : Lemma (
      let t = begin_start (inactive_request (mk_i64 0)) in
      t.f_effect = RekeyEffect_Fail RekeyFailure_WebSessionForbidden /\
      is_done t.f_driver /\
      run_from_start (inactive_request (mk_i64 0)) events = t.f_driver /\
      not (run_from_start (inactive_request (mk_i64 0)) events).f_responded) =
  done_suffix_inert (begin_start (inactive_request (mk_i64 0))).f_driver events

let web_commit_is_refused (events: list t_RekeyEvent)
  : Lemma (
      let t = begin_commit (inactive_request (mk_i64 0)) in
      t.f_effect = RekeyEffect_Fail RekeyFailure_WebSessionForbidden /\
      is_done t.f_driver /\
      run_from_commit (inactive_request (mk_i64 0)) events = t.f_driver /\
      not (run_from_commit (inactive_request (mk_i64 0)) events).f_committed) =
  done_suffix_inert (begin_commit (inactive_request (mk_i64 0))).f_driver events

let web_abort_is_refused (events: list t_RekeyEvent)
  : Lemma (
      let t = begin_abort (inactive_request (mk_i64 0)) in
      t.f_effect = RekeyEffect_Fail RekeyFailure_WebSessionForbidden /\
      is_done t.f_driver /\
      run_from_abort (inactive_request (mk_i64 0)) events = t.f_driver /\
      not (run_from_abort (inactive_request (mk_i64 0)) events).f_rolled_back) =
  done_suffix_inert (begin_abort (inactive_request (mk_i64 0))).f_driver events

#push-options "--fuel 4 --ifuel 2"

let rekey_start_trace_theorem
      (request: t_RekeyRequest)
      (events: list t_RekeyEvent)
  : Lemma (
      let d = run_from_start request events in
      rekey_state_is_sound d /\
      not d.f_committed /\
      not (d.f_responded && d.f_failed) /\
      count_complete (begin_start request).f_driver events <= 1 /\
      count_fail (begin_start request).f_driver events <= 1) =
  begin_sound_start request;
  op_sticky (begin_start request).f_driver events;
  complete_count_le_one (begin_start request).f_driver events;
  fail_count_le_one (begin_start request).f_driver events;
  let d = run_from_start request events in
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Start -> ()
  | _ -> ()

let rekey_capsules_trace_theorem
      (request: t_RekeyRequest)
      (events: list t_RekeyEvent)
  : Lemma (
      let d = run_from_capsules request events in
      rekey_state_is_sound d /\
      not d.f_committed /\
      not (d.f_responded && d.f_failed) /\
      (d.f_responded ==> d.f_capsules_complete) /\
      count_complete (begin_capsules request).f_driver events <= 1 /\
      count_fail (begin_capsules request).f_driver events <= 1) =
  begin_sound_capsules request;
  op_sticky (begin_capsules request).f_driver events;
  complete_count_le_one (begin_capsules request).f_driver events;
  fail_count_le_one (begin_capsules request).f_driver events;
  let d = run_from_capsules request events in
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Capsules -> ()
  | _ -> ()

let rekey_commit_trace_theorem
      (request: t_RekeyRequest)
      (events: list t_RekeyEvent)
  : Lemma (
      let d = run_from_commit request events in
      rekey_state_is_sound d /\
      (d.f_committed ==>
        (d.f_active /\
         d.f_device_scope /\
         d.f_starter_matches /\
         d.f_rotation_present /\
         d.f_rotation_matches /\
         d.f_chunks_complete /\
         d.f_capsules_complete /\
         next_epoch d.f_from_epoch = Core_models.Option.Option_Some d.f_to_epoch /\
         d.f_epoch = d.f_to_epoch)) /\
      not (d.f_responded && d.f_failed) /\
      (not d.f_failed || not d.f_committed) /\
      count_complete (begin_commit request).f_driver events <= 1 /\
      count_fail (begin_commit request).f_driver events <= 1) =
  begin_sound_commit request;
  complete_count_le_one (begin_commit request).f_driver events;
  fail_count_le_one (begin_commit request).f_driver events;
  let d = run_from_commit request events in
  assert (rekey_state_is_sound d);
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Commit -> ()
  | _ -> ()

let rekey_abort_trace_theorem
      (request: t_RekeyRequest)
      (events: list t_RekeyEvent)
  : Lemma (
      let d = run_from_abort request events in
      rekey_state_is_sound d /\
      not d.f_committed /\
      (d.f_rolled_back ==> (d.f_active /\ d.f_epoch >=. v_INITIAL_EPOCH)) /\
      not (d.f_responded && d.f_failed) /\
      count_complete (begin_abort request).f_driver events <= 1 /\
      count_fail (begin_abort request).f_driver events <= 1) =
  begin_sound_abort request;
  op_sticky (begin_abort request).f_driver events;
  complete_count_le_one (begin_abort request).f_driver events;
  fail_count_le_one (begin_abort request).f_driver events;
  let d = run_from_abort request events in
  match d.f_op <: t_RekeyOp with
  | RekeyOp_Abort -> ()
  | _ -> ()

#pop-options

// ── Reachability witnesses ─────────────────────────────────────────────────

let active_state (epoch: i64) : t_KeyStateObs =
  { f_epoch = epoch; f_freezing = false; f_starter_matches = false;
    f_rotation_id_present = false; f_header_present = false;
    f_header_matches = false; f_replay_target = Core_models.Option.Option_None;
    f_replay_recorded = Core_models.Option.Option_None;
    f_replay_id_matches = false; f_expired = false }

let freezing_state (epoch: i64) : t_KeyStateObs =
  { f_epoch = epoch; f_freezing = true; f_starter_matches = true;
    f_rotation_id_present = true; f_header_present = true;
    f_header_matches = true; f_replay_target = Core_models.Option.Option_None;
    f_replay_recorded = Core_models.Option.Option_None;
    f_replay_id_matches = false; f_expired = false }

let expired_state (epoch: i64) : t_KeyStateObs =
  { f_epoch = epoch; f_freezing = true; f_starter_matches = true;
    f_rotation_id_present = true; f_header_present = true;
    f_header_matches = true; f_replay_target = Core_models.Option.Option_None;
    f_replay_recorded = Core_models.Option.Option_None;
    f_replay_id_matches = false; f_expired = true }

let device_request (capsules: i64) : t_RekeyRequest =
  { f_authenticated = true; f_device_scope = true; f_capsule_count = capsules }

let start_prefix : list t_RekeyEvent =
  [ RekeyEvent_RateLimit RateLimitObservation_Allowed;
    RekeyEvent_State (StateObservation_Loaded (active_state (mk_i64 2)));
    RekeyEvent_Oram ProbeObservation_Empty;
    RekeyEvent_Capable ProbeObservation_Empty;
    RekeyEvent_Acknowledged ProbeObservation_Empty ]

let start_run () : t_RekeyDriver =
  run (begin_start (device_request (mk_i64 0))).f_driver start_prefix

let start_reaches_freeze ()
  : Lemma (
      (start_run ()).f_stage = RekeyStage_BeginTx /\
      (start_run ()).f_from_epoch = mk_i64 2 /\
      (start_run ()).f_to_epoch = mk_i64 3) =
  ()

let start_tail : list t_RekeyEvent =
  [ RekeyEvent_Transaction TransactionObservation_Committed;
    RekeyEvent_Inventory InventoryObservation_Read;
    RekeyEvent_FreezeCas CasObservation_Updated;
    RekeyEvent_Cleanup CleanupObservation_Done;
    RekeyEvent_TxCommit TransactionObservation_Committed ]

let start_witness : t_RekeyDriver =
  run (start_run ()) start_tail

let start_witness_completes ()
  : Lemma (
      start_witness.f_responded = true /\
      not start_witness.f_failed /\
      not start_witness.f_committed /\
      start_witness.f_from_epoch = mk_i64 2 /\
      start_witness.f_to_epoch = mk_i64 3) =
  ()

let commit_prefix : list t_RekeyEvent =
  [ RekeyEvent_RateLimit RateLimitObservation_Allowed;
    RekeyEvent_State (StateObservation_Loaded (freezing_state (mk_i64 2)));
    RekeyEvent_Chunks ProbeObservation_Empty;
    RekeyEvent_Devices ProbeObservation_Empty ]

let commit_witness : t_RekeyDriver =
  run (begin_commit (device_request (mk_i64 0))).f_driver
    (commit_prefix @
     [ RekeyEvent_CommitCas CasObservation_Updated;
       RekeyEvent_Sweep SweepObservation_Done;
       RekeyEvent_Published ])

let commit_witness_completes ()
  : Lemma (
      commit_witness.f_committed = true /\
      commit_witness.f_responded = true /\
      commit_witness.f_active = true /\
      commit_witness.f_chunks_complete = true /\
      commit_witness.f_capsules_complete = true /\
      commit_witness.f_epoch = mk_i64 3) =
  ()

let abort_witness : t_RekeyDriver =
  run (begin_abort (device_request (mk_i64 0))).f_driver
    [ RekeyEvent_RateLimit RateLimitObservation_Allowed;
      RekeyEvent_State (StateObservation_Loaded (freezing_state (mk_i64 4)));
      RekeyEvent_Rollback RollbackObservation_RolledBack ]

let abort_witness_restores ()
  : Lemma (
      abort_witness.f_rolled_back = true /\
      abort_witness.f_active = true /\
      abort_witness.f_epoch = mk_i64 4 /\
      not abort_witness.f_committed /\
      abort_witness.f_responded = true) =
  ()

let timeout_witness : t_RekeyTransition =
  let t0 = begin_start (device_request (mk_i64 0)) in
  let t1 = rekey_step t0.f_driver (RekeyEvent_RateLimit RateLimitObservation_Allowed) in
  rekey_step t1.f_driver
    (RekeyEvent_State (StateObservation_Loaded (expired_state (mk_i64 5))))

let timeout_witness_restores ()
  : Lemma (
      (timeout_witness).f_effect = RekeyEffect_TimeoutRollback /\
      (timeout_witness).f_driver.f_active = false /\
      (timeout_witness).f_driver.f_epoch = mk_i64 5 /\
      not (timeout_witness).f_driver.f_committed) =
  ()
