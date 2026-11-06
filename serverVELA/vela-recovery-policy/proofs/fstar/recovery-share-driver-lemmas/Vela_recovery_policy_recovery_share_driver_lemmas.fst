module Vela_recovery_policy_recovery_share_driver_lemmas

/// Unbounded per-request trace induction over the extracted recovery-share
/// lifecycle driver (`Vela_recovery_policy.Recovery_share_driver`).
///
/// Scope: one `ShareLifecycleDriver`, i.e. one `PUT`, `POST .../finalize`,
/// `DELETE` or `GET /recovery/share` request. The guarded SQL updates, the
/// live-row queries and the share decode remain effectful glue outside this
/// module; their inputs are observations, never verified origins.
///
/// The theorems below talk about every event list, not only the handler's
/// intended order. They establish:
///
/// - the state invariant is preserved by every step and every suffix;
/// - a stage update is instructed at most once, only from the stage stage,
///   with a permit whose epoch and split are exactly the request's;
/// - a promotion is instructed at most once and completes only after either
///   the exact pending row was promoted, or the live row confirmed the exact
///   already-finalized split at the same epoch;
/// - a delete completes only after its single instruction, which clears the
///   active share and the staged split together;
/// - a read completes only after the row observation reported a present share;
/// - at most one success and at most one failure are ever produced, never both;
/// - each outcome (success, rekeyed, conflict, policy rejection, missing share)
///   is reachable.

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Recovery_share_driver

// ── Stage helpers ──────────────────────────────────────────────────────────

let is_stage (d: t_ShareLifecycleDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_Stage -> true
  | _ -> false

let is_stage_account (d: t_ShareLifecycleDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_StageAccount -> true
  | _ -> false

let is_finalize (d: t_ShareLifecycleDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_Finalize -> true
  | _ -> false

let is_finalize_account (d: t_ShareLifecycleDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_FinalizeAccount -> true
  | _ -> false

let is_delete (d: t_ShareLifecycleDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_Delete -> true
  | _ -> false

let is_read (d: t_ShareLifecycleDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_Read -> true
  | _ -> false

let is_done (d: t_ShareLifecycleDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_Done -> true
  | _ -> false

// ── Independently restated state invariant ─────────────────────────────────

let trace_sound (d: t_ShareLifecycleDriver) : bool =
  let initial:bool =
    ~.d.f_update_attempted && ~.d.f_update_applied && ~.d.f_account_checked &&
    ~.d.f_active_confirmed &&
    ~.d.f_read_confirmed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let awaiting_account:bool =
    d.f_update_attempted && ~.d.f_update_applied && ~.d.f_account_checked && ~.d.f_active_confirmed &&
    ~.d.f_read_confirmed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done_ok:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    (match d.f_operation <: t_ShareOperation with
      | ShareOperation_Stage
      | ShareOperation_Finalize  -> d.f_update_applied || d.f_active_confirmed
      | ShareOperation_Delete  -> d.f_update_applied && d.f_deletes_share && d.f_deletes_pending
      | ShareOperation_Read  -> d.f_read_confirmed)) &&
    (~.d.f_failed || ~.d.f_update_applied && ~.d.f_read_confirmed)
  in
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Stage  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Stage  -> true
    | _ -> false) &&
  initial) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_StageAccount  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Stage  -> true
    | _ -> false) &&
  awaiting_account) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Finalize  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Finalize  -> true
    | _ -> false) &&
  initial) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_FinalizeAccount  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Finalize  -> true
    | _ -> false) &&
  awaiting_account) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Delete  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Delete  -> true
    | _ -> false) &&
  initial &&
  d.f_deletes_share &&
  d.f_deletes_pending) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Read  -> true
    | _ -> false) ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Read  -> true
    | _ -> false) &&
  ~.d.f_update_attempted &&
  ~.d.f_update_applied &&
  ~.d.f_account_checked &&
  ~.d.f_active_confirmed &&
  ~.d.f_read_confirmed &&
  ~.d.f_responded &&
  ~.d.f_failed) &&
  (~.(match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false) ||
  done_ok) &&
  (~.d.f_same_account || d.f_actor_active) &&
  ((match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false) ||
   d.f_actor_active && d.f_same_account) &&
  (~.d.f_update_attempted ||
  d.f_actor_active && d.f_same_account &&
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Stage  | ShareOperation_Finalize  | ShareOperation_Delete  -> true
    | _ -> false)) &&
  (~.d.f_update_applied || d.f_update_attempted && d.f_responded) &&
  (~.d.f_account_checked ||
  d.f_update_attempted &&
  ~.(match d.f_operation <: t_ShareOperation with
    | ShareOperation_Read  -> true
    | _ -> false)) &&
  (~.d.f_active_confirmed || d.f_account_checked && d.f_responded) &&
  (~.d.f_read_confirmed ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Read  -> true
    | _ -> false) &&
  d.f_responded) &&
  (~.d.f_deletes_share ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Delete  -> true
    | _ -> false)) &&
  (~.d.f_deletes_pending ||
  (match d.f_operation <: t_ShareOperation with
    | ShareOperation_Delete  -> true
    | _ -> false)) &&
  (~.(d.f_deletes_share || d.f_deletes_pending) || d.f_deletes_share && d.f_deletes_pending) &&
  (~.d.f_responded ||
  (match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false)) &&
  (~.d.f_failed ||
  (match d.f_stage <: t_ShareStage with
    | ShareStage_Done  -> true
    | _ -> false))

/// The independently written invariant is exactly the Rust postcondition.
let trace_sound_matches_rust (d: t_ShareLifecycleDriver)
  : Lemma (trace_sound d = share_lifecycle_state_is_sound d) =
  match d.f_stage <: t_ShareStage with
  | ShareStage_Stage -> ()
  | ShareStage_StageAccount -> ()
  | ShareStage_Finalize -> ()
  | ShareStage_FinalizeAccount -> ()
  | ShareStage_Delete -> ()
  | ShareStage_Read -> ()
  | ShareStage_Done -> ()

let begin_sound (request: t_ShareRequestObservation)
  : Lemma (trace_sound (begin_share_lifecycle request).f_driver) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver

let step_sound (d: t_ShareLifecycleDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step_share_lifecycle d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (share_lifecycle_state_is_sound d = true);
  trace_sound_matches_rust (step_share_lifecycle d e).f_driver

// ── Unbounded trace execution ──────────────────────────────────────────────

let rec run (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure t_ShareLifecycleDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step_share_lifecycle d e).f_driver rest

let rec last_effect (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure t_ShareEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> ShareEffect_Idle
  | e :: [] -> (step_share_lifecycle d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step_share_lifecycle d e).f_driver rest

let run_from_begin (request: t_ShareRequestObservation)
                   (events: list t_ShareEvent)
  : Pure t_ShareLifecycleDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  run (begin_share_lifecycle request).f_driver events

let last_effect_from_begin (request: t_ShareRequestObservation)
                           (events: list t_ShareEvent)
  : Pure t_ShareEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  last_effect (begin_share_lifecycle request).f_driver events

/// A success effect is produced at most once, and only from `Done` with the
/// operation's publication evidence.
let succeeded (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_Complete -> 1
  | _ -> 0

let failed (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_Fail _ -> 1
  | _ -> 0

let staged (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_StageShare _ -> 1
  | _ -> 0

let promoted (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_PromoteStagedSplit _ -> 1
  | _ -> 0

let deleted (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_DeleteShare _ -> 1
  | _ -> 0

let read (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_ReadShare -> 1
  | _ -> 0

let rec count_success (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      succeeded (step_share_lifecycle d e).f_effect +
      count_success (step_share_lifecycle d e).f_driver rest

let rec count_failure (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      failed (step_share_lifecycle d e).f_effect +
      count_failure (step_share_lifecycle d e).f_driver rest

let rec count_stages (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      staged (step_share_lifecycle d e).f_effect +
      count_stages (step_share_lifecycle d e).f_driver rest

let rec count_promotions (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      promoted (step_share_lifecycle d e).f_effect +
      count_promotions (step_share_lifecycle d e).f_driver rest

let rec count_deletes (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      deleted (step_share_lifecycle d e).f_effect +
      count_deletes (step_share_lifecycle d e).f_driver rest

let rec count_reads (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      read (step_share_lifecycle d e).f_effect +
      count_reads (step_share_lifecycle d e).f_driver rest

let count_success_from_begin (request: t_ShareRequestObservation)
                              (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  count_success (begin_share_lifecycle request).f_driver events

let count_failure_from_begin (request: t_ShareRequestObservation)
                              (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  count_failure (begin_share_lifecycle request).f_driver events

let count_stages_from_begin (request: t_ShareRequestObservation)
                             (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  count_stages (begin_share_lifecycle request).f_driver events

let count_promotions_from_begin (request: t_ShareRequestObservation)
                                 (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  count_promotions (begin_share_lifecycle request).f_driver events

let count_deletes_from_begin (request: t_ShareRequestObservation)
                              (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  count_deletes (begin_share_lifecycle request).f_driver events

let count_reads_from_begin (request: t_ShareRequestObservation)
                            (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  trace_sound_matches_rust (begin_share_lifecycle request).f_driver;
  count_reads (begin_share_lifecycle request).f_driver events

/// Once the driver has responded or failed, every later event is inert.
let step_after_terminal (d: t_ShareLifecycleDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d /\ (d.f_responded || d.f_failed)))
    (ensures (
      (step_share_lifecycle d e).f_driver = d /\
      (step_share_lifecycle d e).f_effect = ShareEffect_Idle)) =
  trace_sound_matches_rust d;
  assert (is_done d = true)

let rec terminal_suffix_inert (d: t_ShareLifecycleDriver)
                              (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d /\ (d.f_responded || d.f_failed)))
    (ensures (run d events = d /\
              count_success d events = 0 /\
              count_failure d events = 0 /\
              count_stages d events = 0 /\
              count_promotions d events = 0 /\
              count_deletes d events = 0 /\
              count_reads d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_terminal d e;
      terminal_suffix_inert d rest

let rec at_most_one_success (d: t_ShareLifecycleDriver)
                            (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_success d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_share_lifecycle d e in
      if succeeded t.f_effect = 1
      then begin
        assert (t.f_driver.f_responded = true);
        terminal_suffix_inert t.f_driver rest
      end else at_most_one_success t.f_driver rest

let rec at_most_one_failure (d: t_ShareLifecycleDriver)
                            (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_failure d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_share_lifecycle d e in
      if failed t.f_effect = 1
      then begin
        assert (t.f_driver.f_failed = true);
        terminal_suffix_inert t.f_driver rest
      end else at_most_one_failure t.f_driver rest

let rec never_both (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_success d events + count_failure d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_share_lifecycle d e in
      if succeeded t.f_effect + failed t.f_effect = 1
      then terminal_suffix_inert t.f_driver rest
      else never_both t.f_driver rest

/// A stage instruction is emitted only at the beginning of a Stage request,
/// and a later event can never emit a second one.
let stage_effect_origin (d: t_ShareLifecycleDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step_share_lifecycle d e).f_effect <: t_ShareEffect with
      | ShareEffect_StageShare permit ->
          is_stage d /\
          d.f_operation = ShareOperation_Stage /\
          not d.f_update_attempted /\
          permit.f_epoch = d.f_epoch /\
          permit.f_split = d.f_split
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (share_lifecycle_state_is_sound d = true);
  let t = step_share_lifecycle d e in
  assert (share_lifecycle_effect_is_sound t.f_driver t.f_effect)

let rec stage_count_le_one (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_stages d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_share_lifecycle d e in
      if staged t.f_effect = 1
      then begin
        assert (t.f_driver.f_update_attempted = true);
        assert (not (is_stage t.f_driver));
        stage_count_le_one t.f_driver rest
      end else stage_count_le_one t.f_driver rest

let promotion_effect_origin (d: t_ShareLifecycleDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step_share_lifecycle d e).f_effect <: t_ShareEffect with
      | ShareEffect_PromoteStagedSplit permit ->
          is_finalize d /\
          d.f_operation = ShareOperation_Finalize /\
          not d.f_update_attempted /\
          permit.f_epoch = d.f_epoch /\
          permit.f_split = d.f_split /\
          permit.f_exact_pending_required /\
          permit.f_empty_active_required
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (share_lifecycle_state_is_sound d = true);
  let t = step_share_lifecycle d e in
  assert (share_lifecycle_effect_is_sound t.f_driver t.f_effect)

let rec promotion_count_le_one (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_promotions d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_share_lifecycle d e in
      if promoted t.f_effect = 1
      then begin
        assert (t.f_driver.f_update_attempted = true);
        assert (not (is_finalize t.f_driver));
        promotion_count_le_one t.f_driver rest
      end else promotion_count_le_one t.f_driver rest

let delete_effect_origin (d: t_ShareLifecycleDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step_share_lifecycle d e).f_effect <: t_ShareEffect with
      | ShareEffect_DeleteShare permit ->
          is_delete d /\
          d.f_operation = ShareOperation_Delete /\
          not d.f_update_attempted /\
          permit.f_epoch = d.f_epoch /\
          permit.f_clears_share_and_pending /\
          d.f_deletes_share /\
          d.f_deletes_pending
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (share_lifecycle_state_is_sound d = true);
  let t = step_share_lifecycle d e in
  assert (share_lifecycle_effect_is_sound t.f_driver t.f_effect)

let rec delete_count_le_one (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_deletes d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_share_lifecycle d e in
      if deleted t.f_effect = 1
      then begin
        assert (t.f_driver.f_update_attempted = true);
        assert (not (is_delete t.f_driver));
        delete_count_le_one t.f_driver rest
      end else delete_count_le_one t.f_driver rest

let read_effect_origin (d: t_ShareLifecycleDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step_share_lifecycle d e).f_effect <: t_ShareEffect with
      | ShareEffect_ReadShare ->
          is_read d /\ d.f_operation = ShareOperation_Read /\
          not d.f_read_confirmed
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (share_lifecycle_state_is_sound d = true);
  let t = step_share_lifecycle d e in
  assert (share_lifecycle_effect_is_sound t.f_driver t.f_effect)

let rec read_count_le_one (d: t_ShareLifecycleDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_reads d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_share_lifecycle d e in
      if read t.f_effect = 1
      then begin
        assert (t.f_driver.f_read_confirmed = true);
        assert (not (is_read t.f_driver));
        read_count_le_one t.f_driver rest
      end else read_count_le_one t.f_driver rest

/// A successful delete has cleared both the active share and the staged split.
let delete_complete_clears_both (d: t_ShareLifecycleDriver)
  : Lemma
    (requires (
      trace_sound d /\ d.f_operation = ShareOperation_Delete /\
      d.f_responded))
    (ensures (d.f_update_applied /\ d.f_deletes_share /\ d.f_deletes_pending)) =
  trace_sound_matches_rust d

/// A successful stage/finalize has either applied its own guarded update or
/// confirmed the exact already-current split on the live row.
let publication_complete_has_evidence (d: t_ShareLifecycleDriver)
  : Lemma
    (requires (
      trace_sound d /\
      (d.f_operation = ShareOperation_Stage || d.f_operation = ShareOperation_Finalize) /\
      d.f_responded))
    (ensures (d.f_update_applied || d.f_active_confirmed)) =
  trace_sound_matches_rust d

// ── Headline per-request theorem ───────────────────────────────────────────

/// For every event list: the final state is sound, at most one success and at
/// most one failure were produced (never both), each operation's instruction
/// was at most one, a successful delete cleared both fields, and a successful
/// publication has publication evidence. A response is never a failure.
let share_lifecycle_trace_theorem
      (request: t_ShareRequestObservation)
      (events: list t_ShareEvent)
  : Lemma (
      let d = run_from_begin request events in
      trace_sound d /\
      count_success_from_begin request events <= 1 /\
      count_failure_from_begin request events <= 1 /\
      count_success_from_begin request events + count_failure_from_begin request events <= 1 /\
      count_stages_from_begin request events <= 1 /\
      count_promotions_from_begin request events <= 1 /\
      count_deletes_from_begin request events <= 1 /\
      count_reads_from_begin request events <= 1 /\
      (d.f_responded ==> not d.f_failed) /\
      (d.f_responded && d.f_operation = ShareOperation_Delete ==>
        d.f_update_applied && d.f_deletes_share && d.f_deletes_pending) /\
      (d.f_responded &&
        (d.f_operation = ShareOperation_Stage || d.f_operation = ShareOperation_Finalize) ==>
        d.f_update_applied || d.f_active_confirmed)) =
  let b = begin_share_lifecycle request in
  trace_sound_matches_rust b.f_driver;
  assert (trace_sound b.f_driver);
  at_most_one_success b.f_driver events;
  at_most_one_failure b.f_driver events;
  never_both b.f_driver events;
  stage_count_le_one b.f_driver events;
  promotion_count_le_one b.f_driver events;
  delete_count_le_one b.f_driver events;
  read_count_le_one b.f_driver events;
  ()

#push-options "--fuel 4 --ifuel 2"

// ── Reachability witnesses ─────────────────────────────────────────────────

let active_actor : t_ShareActorObservation =
  { f_authenticated = true; f_device_active = true; f_scoped_to_session_account = true }

let stage_request : t_ShareRequestObservation =
  { f_operation = ShareOperation_Stage; f_actor = active_actor;
    f_declared_epoch = mk_i64 1; f_split_id_present = true; f_share_present = true;
    f_device_authority = true; f_split = mk_i64 7 }

let finalize_request : t_ShareRequestObservation =
  { stage_request with f_operation = ShareOperation_Finalize }

let delete_request : t_ShareRequestObservation =
  { stage_request with f_operation = ShareOperation_Delete; f_split = mk_i64 0 }

let read_request : t_ShareRequestObservation =
  { stage_request with f_operation = ShareOperation_Read; f_split = mk_i64 0 }

let staged_row : t_StageUpdateObservation = StageUpdateObservation_Staged
let not_staged_row : t_StageUpdateObservation = StageUpdateObservation_NotStaged
let promoted_row : t_FinalizeUpdateObservation = FinalizeUpdateObservation_Promoted
let not_promoted_row : t_FinalizeUpdateObservation = FinalizeUpdateObservation_NotPromoted
let deleted_row : t_DeleteUpdateObservation = DeleteUpdateObservation_Deleted
let not_deleted_row : t_DeleteUpdateObservation = DeleteUpdateObservation_NotDeleted

let current_stage_account : t_StageAccountObservation =
  { f_account_present = true; f_stored_epoch = Core_models.Option.Option_Some (mk_i64 1);
    f_rotation_active = false; f_active_share_matches = true; f_active_split_matches = true }

let current_finalize_account : t_FinalizeAccountObservation =
  { f_account_present = true; f_stored_epoch = Core_models.Option.Option_Some (mk_i64 1);
    f_rotation_active = false; f_active_split_matches = true }

let present_share : t_ReadObservation =
  { f_account_present = true; f_share_present = true }

let stage_success_events : list t_ShareEvent =
  [ ShareEvent_StageUpdate staged_row ]

let stage_idempotent_events : list t_ShareEvent =
  [ ShareEvent_StageUpdate not_staged_row;
    ShareEvent_StageAccount current_stage_account ]

let stage_rekeyed_events : list t_ShareEvent =
  [ ShareEvent_StageUpdate not_staged_row;
    ShareEvent_StageAccount { current_stage_account with f_rotation_active = true } ]

let stage_conflict_events : list t_ShareEvent =
  [ ShareEvent_StageUpdate not_staged_row;
    ShareEvent_StageAccount { current_stage_account with f_active_share_matches = false } ]

let finalize_success_events : list t_ShareEvent =
  [ ShareEvent_FinalizeUpdate promoted_row ]

let finalize_idempotent_events : list t_ShareEvent =
  [ ShareEvent_FinalizeUpdate not_promoted_row;
    ShareEvent_FinalizeAccount current_finalize_account ]

let finalize_conflict_events : list t_ShareEvent =
  [ ShareEvent_FinalizeUpdate not_promoted_row;
    ShareEvent_FinalizeAccount { current_finalize_account with f_active_split_matches = false } ]

let delete_success_events : list t_ShareEvent =
  [ ShareEvent_DeleteUpdate deleted_row ]

let delete_rekeyed_events : list t_ShareEvent =
  [ ShareEvent_DeleteUpdate not_deleted_row ]

let read_success_events : list t_ShareEvent =
  [ ShareEvent_ReadObserved present_share ]

let read_missing_events : list t_ShareEvent =
  [ ShareEvent_ReadObserved { present_share with f_share_present = false } ]

let stage_success_is_reachable ()
  : Lemma (
      let d = run_from_begin stage_request stage_success_events in
      d.f_responded = true /\ d.f_update_applied = true) =
  ()

let stage_idempotent_is_reachable ()
  : Lemma (
      let d = run_from_begin stage_request stage_idempotent_events in
      d.f_responded = true /\ d.f_active_confirmed = true /\
      d.f_update_applied = false) =
  ()

let stage_rekeyed_is_reachable ()
  : Lemma (
      let d = run_from_begin stage_request stage_rekeyed_events in
      d.f_failed = true /\
      last_effect_from_begin stage_request stage_rekeyed_events =
        ShareEffect_Fail ShareFailure_Rekeyed) =
  ()

let stage_conflict_is_reachable ()
  : Lemma (
      let d = run_from_begin stage_request stage_conflict_events in
      d.f_failed = true /\
      last_effect_from_begin stage_request stage_conflict_events =
        ShareEffect_Fail ShareFailure_Conflict) =
  ()

let finalize_success_is_reachable ()
  : Lemma (
      let d = run_from_begin finalize_request finalize_success_events in
      d.f_responded = true /\ d.f_update_applied = true) =
  ()

let finalize_idempotent_is_reachable ()
  : Lemma (
      let d = run_from_begin finalize_request finalize_idempotent_events in
      d.f_responded = true /\ d.f_active_confirmed = true) =
  ()

let finalize_conflict_is_reachable ()
  : Lemma (
      let d = run_from_begin finalize_request finalize_conflict_events in
      d.f_failed = true /\
      last_effect_from_begin finalize_request finalize_conflict_events =
        ShareEffect_Fail ShareFailure_Conflict) =
  ()

let delete_success_is_reachable ()
  : Lemma (
      let d = run_from_begin delete_request delete_success_events in
      d.f_responded = true /\ d.f_update_applied = true /\
      d.f_deletes_share = true /\ d.f_deletes_pending = true) =
  ()

let delete_rekeyed_is_reachable ()
  : Lemma (
      let d = run_from_begin delete_request delete_rekeyed_events in
      d.f_failed = true /\
      last_effect_from_begin delete_request delete_rekeyed_events =
        ShareEffect_Fail ShareFailure_Rekeyed) =
  ()

let read_success_is_reachable ()
  : Lemma (
      let d = run_from_begin read_request read_success_events in
      d.f_responded = true /\ d.f_read_confirmed = true) =
  ()

let read_missing_is_reachable ()
  : Lemma (
      let d = run_from_begin read_request read_missing_events in
      d.f_failed = true /\
      last_effect_from_begin read_request read_missing_events =
        ShareEffect_Fail ShareFailure_ShareMissing) =
  ()

let policy_rejection_is_reachable ()
  : Lemma (
      let request = { stage_request with f_device_authority = false } in
      let d = run_from_begin request [] in
      d.f_failed = true /\
      (begin_share_lifecycle request).f_effect =
        ShareEffect_Fail ShareFailure_PolicyRejected) =
  ()

let unauthenticated_is_reachable ()
  : Lemma (
      let request =
        { stage_request with
          f_actor = { active_actor with f_authenticated = false } } in
      let d = run_from_begin request [] in
      d.f_failed = true /\
      (begin_share_lifecycle request).f_effect =
        ShareEffect_Fail ShareFailure_Unauthenticated) =
  ()

#pop-options
