module Vela_recovery_policy_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* enrollment
/// redemption driver (`Vela_recovery_policy.Driver.step`).
///
/// Scope: one `RedemptionDriver` value, i.e. one HTTP request. The theorem
/// does not claim anything about two concurrent requests redeeming the same
/// grant; the single-use store `get_del`, the guarded SQL insert and the
/// restoration effect remain effectful glue
/// outside this module. The driver's SQL/store inputs are observations, never
/// verified origins.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `redemption_state_is_sound` and proved equivalent to it;
/// all trace lemmas then quantify over every event list.

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Driver

// ── Independent state invariant ─────────────────────────────────────────────

let is_consume (d: t_RedemptionDriver) : bool =
  match d.f_stage <: t_RedemptionStage with
  | RedemptionStage_Consume -> true
  | _ -> false

let is_policy (d: t_RedemptionDriver) : bool =
  match d.f_stage <: t_RedemptionStage with
  | RedemptionStage_FinalPolicy -> true
  | _ -> false

let is_insert (d: t_RedemptionDriver) : bool =
  match d.f_stage <: t_RedemptionStage with
  | RedemptionStage_Insert -> true
  | _ -> false

let is_recheck (d: t_RedemptionDriver) : bool =
  match d.f_stage <: t_RedemptionStage with
  | RedemptionStage_Recheck -> true
  | _ -> false

let is_replay (d: t_RedemptionDriver) : bool =
  match d.f_stage <: t_RedemptionStage with
  | RedemptionStage_Replay -> true
  | _ -> false

let is_done (d: t_RedemptionDriver) : bool =
  match d.f_stage <: t_RedemptionStage with
  | RedemptionStage_Done -> true
  | _ -> false

/// Strengthened trace invariant. It encodes the stage/flag discipline of the
/// driver: an insert attempt has a matched consumption and both permits, a
/// success is terminal and never restored, a restoration never follows a
/// success, and a replay never consumes, inserts or restores anything.
let trace_sound (d: t_RedemptionDriver) : bool =
  (not (is_consume d) ||
    (not d.f_consumed_matched && not d.f_permit_issued &&
     not d.f_insert_attempted && not d.f_insert_succeeded && not d.f_restored &&
     not d.f_replay)) &&
  (not (is_policy d) ||
    (d.f_consumed_matched && not d.f_permit_issued &&
     not d.f_insert_attempted && not d.f_insert_succeeded && not d.f_restored &&
     not d.f_replay)) &&
  (not (is_insert d) ||
    (d.f_consumed_matched && d.f_permit_issued &&
     d.f_insert_attempted && not d.f_insert_succeeded && not d.f_restored &&
     not d.f_replay)) &&
  (not (is_recheck d) ||
    (d.f_consumed_matched && d.f_permit_issued &&
     d.f_insert_attempted && not d.f_insert_succeeded && not d.f_restored &&
     not d.f_replay)) &&
  (not (is_replay d) ||
    (d.f_replay && d.f_replay_attempted && not d.f_replay_succeeded &&
     not d.f_consumed_matched && not d.f_permit_issued &&
     not d.f_insert_attempted && not d.f_insert_succeeded && not d.f_restored)) &&
  (not d.f_insert_attempted || (d.f_consumed_matched && d.f_permit_issued)) &&
  (not d.f_insert_succeeded ||
    (d.f_insert_attempted && d.f_consumed_matched && d.f_permit_issued &&
     is_done d && not d.f_restored && not d.f_replay)) &&
  (not d.f_restored || (is_done d && not d.f_insert_succeeded && not d.f_replay)) &&
  (not d.f_replay ||
    (not d.f_consumed_matched && not d.f_permit_issued &&
     not d.f_insert_attempted && not d.f_insert_succeeded && not d.f_restored)) &&
  (not d.f_replay_attempted || d.f_replay) &&
  (not d.f_replay_succeeded ||
    (d.f_replay && d.f_replay_attempted && is_done d &&
     not d.f_insert_succeeded && not d.f_restored))

/// The independently written invariant is exactly the Rust postcondition's
/// predicate. Proved by exhaustive stage case analysis, not by aliasing the
/// implementation definition in the statements below.
let trace_sound_matches_rust (d: t_RedemptionDriver)
  : Lemma (trace_sound d = redemption_state_is_sound d) =
  match d.f_stage <: t_RedemptionStage with
  | RedemptionStage_Consume -> ()
  | RedemptionStage_FinalPolicy -> ()
  | RedemptionStage_Insert -> ()
  | RedemptionStage_Recheck -> ()
  | RedemptionStage_Replay -> ()
  | RedemptionStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_sound (ready: t_ReadyToConsume)
  : Lemma (trace_sound (begin_redemption ready).f_driver) =
  trace_sound_matches_rust (begin_redemption ready).f_driver

/// The U-24 replay start is sound: no consumption, insert or restoration fact
/// can be set, and the only legal effect is the device-row lookup.
let begin_replay_sound ()
  : Lemma (trace_sound (begin_redemption_replay ()).f_driver) =
  trace_sound_matches_rust (begin_redemption_replay ()).f_driver

let begin_from_sound (start: t_RedemptionStart)
  : Lemma (trace_sound (begin_redemption_from start).f_driver) =
  match start <: t_RedemptionStart with
  | RedemptionStart_Redeem ready -> begin_sound ready
  | RedemptionStart_Replay -> begin_replay_sound ()

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (redemption_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

/// After a success the driver is terminal: every event is inert.
let step_after_success (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_insert_succeeded))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = RedemptionEffect_Idle)) =
  trace_sound_matches_rust d;
  assert (is_done d = true);
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed _ -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert _ -> ()
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed _ -> ()

/// A finished driver is inert for every event.
let step_after_done (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = RedemptionEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed _ -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert _ -> ()
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed _ -> ()

/// After the replay verdict the driver is terminal: every event is inert.
/// This is the replay analogue of `step_after_success` (a replay never
/// inserts, so `f_insert_succeeded` stays false and cannot be used).
let step_after_replay_verdict (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_replay /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = RedemptionEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed _ -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert _ -> ()
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed _ -> ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_RedemptionDriver) (events: list t_RedemptionEvent)
  : Pure t_RedemptionDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let rec count_complete (d: t_RedemptionDriver) (events: list t_RedemptionEvent)
  : Pure nat
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_RedemptionEffect with
       | RedemptionEffect_Complete -> 1
       | _ -> 0) +
      count_complete (step d e).f_driver rest

let rec count_insert (d: t_RedemptionDriver) (events: list t_RedemptionEvent)
  : Pure nat
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_RedemptionEffect with
       | RedemptionEffect_Insert _ -> 1
       | _ -> 0) +
      count_insert (step d e).f_driver rest

let rec done_suffix_inert (d: t_RedemptionDriver) (events: list t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (run d events = d /\ count_complete d events = 0 /\
              count_insert d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

let rec last_effect (d: t_RedemptionDriver) (events: list t_RedemptionEvent)
  : Pure t_RedemptionEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> RedemptionEffect_Idle
  | e :: [] -> (step d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step d e).f_driver rest

/// Total wrappers starting from the actual extracted `begin_redemption`.
let run_from_ready (ready: t_ReadyToConsume) (events: list t_RedemptionEvent)
  : Pure t_RedemptionDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_sound ready;
  trace_sound_matches_rust (begin_redemption ready).f_driver;
  run (begin_redemption ready).f_driver events

let count_complete_from_ready (ready: t_ReadyToConsume) (events: list t_RedemptionEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound ready;
  trace_sound_matches_rust (begin_redemption ready).f_driver;
  count_complete (begin_redemption ready).f_driver events

let last_effect_from_ready (ready: t_ReadyToConsume) (events: list t_RedemptionEvent)
  : Pure t_RedemptionEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound ready;
  trace_sound_matches_rust (begin_redemption ready).f_driver;
  last_effect (begin_redemption ready).f_driver events

/// The U-24 replay start, as a total wrapper over the extracted
/// `begin_redemption_replay`.
let run_from_replay (events: list t_RedemptionEvent)
  : Pure t_RedemptionDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_replay_sound ();
  trace_sound_matches_rust (begin_redemption_replay ()).f_driver;
  run (begin_redemption_replay ()).f_driver events

/// Both starts in one wrapper, so the interpreter lemma can state its result
/// for the request shape the handler actually runs.
let run_from_start (start: t_RedemptionStart) (events: list t_RedemptionEvent)
  : Pure t_RedemptionDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match start <: t_RedemptionStart with
  | RedemptionStart_Redeem ready -> run_from_ready ready events
  | RedemptionStart_Replay -> run_from_replay events

/// The wrapper is the extracted begin composed with `run`.
let run_from_start_is_begin (start: t_RedemptionStart) (events: list t_RedemptionEvent)
  : Lemma (run_from_start start events == run (begin_redemption_from start).f_driver events) =
  match start <: t_RedemptionStart with
  | RedemptionStart_Redeem ready -> ()
  | RedemptionStart_Replay -> ()

let count_complete_from_start (start: t_RedemptionStart) (events: list t_RedemptionEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  match start <: t_RedemptionStart with
  | RedemptionStart_Redeem ready -> count_complete_from_ready ready events
  | RedemptionStart_Replay ->
      begin_replay_sound ();
      trace_sound_matches_rust (begin_redemption_replay ()).f_driver;
      count_complete (begin_redemption_replay ()).f_driver events

// ── Trace properties ────────────────────────────────────────────────────────

/// (1) An `Insert` effect can only be produced by a state that has already
/// processed a matched consumption (`consumed_matched`) and a matching actual
/// `plan_enrollment` + rekey permit (`permit_issued`), and its permit fields
/// are exactly the driver's preflight epoch/type.
let insert_effect_requires_authority (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step d e).f_effect <: t_RedemptionEffect with
      | RedemptionEffect_Insert permit ->
          (step d e).f_driver.f_consumed_matched /\
          (step d e).f_driver.f_permit_issued /\
          (step d e).f_driver.f_insert_attempted /\
          is_insert (step d e).f_driver /\
          permit.f_epoch = (step d e).f_driver.f_epoch /\
          permit.f_possession = (step d e).f_driver.f_possession
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (redemption_state_is_sound d = true);
  ()

/// The matched-consumption provenance: `consumed_matched` is only ever set by
/// a `Present` observation whose decoded value matched the preflight grant and
/// whose epoch/type matched the preflight permit.
let consumed_flag_origin (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ not d.f_consumed_matched))
    (ensures (
      (step d e).f_driver.f_consumed_matched ==>
      (match e <: t_RedemptionEvent with
       | RedemptionEvent_Consumed (ConsumptionObservation_Present consumed) ->
           consumed.f_matches_observed_grant /\
           consumed.f_key_epoch = d.f_epoch /\
           consumed.f_possession = d.f_possession
       | _ -> False))) =
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed (ConsumptionObservation_Missing) -> ()
  | RedemptionEvent_Consumed (ConsumptionObservation_Present _) -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert _ -> ()
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed _ -> ()

/// The final-policy provenance: `permit_issued` is only ever set by a
/// `FinalPolicy` event whose actual `plan_enrollment` returned an enrollment
/// permit at the driver epoch and whose actual rekey observation permitted the
/// same epoch.
let permit_flag_origin (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ not d.f_permit_issued))
    (ensures (
      (step d e).f_driver.f_permit_issued ==>
      (match e <: t_RedemptionEvent with
       | RedemptionEvent_FinalPolicy obs ->
           (match plan_enrollment (enrollment_facts obs.f_enrollment)
                  <: t_EnrollmentDecision with
            | EnrollmentDecision_Enroll permit ->
                impl_EnrollmentPermit__epoch permit = d.f_epoch /\
                (match obs.f_rekey <: t_RekeyObservation with
                 | RekeyObservation_Permit rekey ->
                     rekey.f_epoch = impl_EnrollmentPermit__epoch permit
                 | RekeyObservation_Reject -> False)
            | EnrollmentDecision_Reject -> False)
       | _ -> False))) =
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed _ -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert _ -> ()
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed _ -> ()

/// (2) Every `Complete` effect answers exactly one of two observations: an
/// `InsertObservation_Inserted` from the `Insert` stage, or a replay row whose
/// stored keys equal the request's from the `Replay` stage. A
/// `Skipped`/`Failed` insert and an absent or different-key replay row cannot
/// produce success.
let complete_only_after_inserted_or_replay (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      ((step d e).f_effect = RedemptionEffect_Complete) ==>
      (match e <: t_RedemptionEvent with
       | RedemptionEvent_Insert InsertObservation_Inserted -> is_insert d
       | RedemptionEvent_Replayed (ReplayObservation_Enrolled c) ->
           is_replay d /\ c.f_key_matches = true
       | _ -> False))) =
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed _ -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert obs ->
      (match obs <: t_InsertObservation with
       | InsertObservation_Inserted -> ()
       | InsertObservation_Skipped -> ()
       | InsertObservation_Failed -> ())
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed obs ->
      (match obs <: t_ReplayObservation with
       | ReplayObservation_Enrolled _ -> ()
       | ReplayObservation_Absent -> ())

/// (3) No restoration effect is ever emitted after an insert success.
let no_restore_after_success (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_insert_succeeded))
    (ensures (
      (match (step d e).f_effect <: t_RedemptionEffect with
       | RedemptionEffect_RestoreAndFail _ -> False
       | _ -> True) /\
      (step d e).f_driver.f_restored = d.f_restored)) =
  step_after_success d e

let rec no_restore_after_success_suffix
      (d: t_RedemptionDriver)
      (events: list t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_insert_succeeded))
    (ensures (
      run d events = d /\
      count_complete d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_success d e;
      no_restore_after_success_suffix d rest

/// (4) At most one `Complete` (insert success) per driver instance, for an
/// arbitrary-length event list. Any two Complete effects in the same trace
/// must be the same step; in particular there is no second success after a
/// successful prefix.
let rec complete_count_le_one (d: t_RedemptionDriver) (events: list t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_complete d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if (match t.f_effect <: t_RedemptionEffect with
          | RedemptionEffect_Complete -> true
          | _ -> false)
      then begin
        // Effect soundness makes the post-state a success, so the tail is
        // inert: an insert success for a redemption, a replay verdict for the
        // U-24 lookup.
        if t.f_driver.f_replay
        then done_suffix_inert t.f_driver rest
        else begin
          assert (t.f_driver.f_insert_succeeded = true);
          no_restore_after_success_suffix t.f_driver rest
        end
      end else begin
        complete_count_le_one t.f_driver rest
      end

/// All-pairs corollary: after any successful prefix, every possibly-unbounded
/// suffix contains no further success and no restoration.
let no_second_success_after_prefix
      (ready: t_ReadyToConsume)
      (pre: list t_RedemptionEvent)
      (suffix: list t_RedemptionEvent)
  : Lemma
    (requires (let d = run_from_ready ready pre in d.f_insert_succeeded))
    (ensures (
      let d = run_from_ready ready pre in
      run d suffix = d /\ count_complete d suffix = 0)) =
  let d = run_from_ready ready pre in
  begin_sound ready;
  trace_sound_matches_rust (begin_redemption ready).f_driver;
  no_restore_after_success_suffix d suffix

/// Headline unbounded theorem over the actual extracted driver, for either
/// start. For every request and every event list, the final state is sound, a
/// success is never paired with a restoration, and the trace contains at most
/// one `Complete` effect.
let redemption_trace_theorem
      (start: t_RedemptionStart)
      (events: list t_RedemptionEvent)
  : Lemma (
      let d = run_from_start start events in
      trace_sound d /\
      (d.f_insert_succeeded ==> not d.f_restored) /\
      (d.f_restored ==> not d.f_insert_succeeded) /\
      count_complete_from_start start events <= 1) =
  begin_from_sound start;
  trace_sound_matches_rust (begin_redemption_from start).f_driver;
  run_from_start_is_begin start events;
  complete_count_le_one (begin_redemption_from start).f_driver events;
  ()

/// (5) No insert outcome restores the grant. Restoration after an insert
/// attempt is only possible from the recheck stage, which is reached only by
/// a definite zero-row (`Skipped`) observation.
let insert_stage_never_restores (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ is_insert d))
    (ensures (
      (match (step d e).f_effect <: t_RedemptionEffect with
       | RedemptionEffect_RestoreAndFail _ -> False
       | _ -> True) /\
      not (step d e).f_driver.f_restored /\
      (is_recheck (step d e).f_driver ==>
        (match e <: t_RedemptionEvent with
         | RedemptionEvent_Insert InsertObservation_Skipped -> True
         | _ -> False)))) =
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed _ -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert obs ->
      (match obs <: t_InsertObservation with
       | InsertObservation_Inserted -> ()
       | InsertObservation_Skipped -> ()
       | InsertObservation_Failed -> ())
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed _ -> ()

/// (6) An ambiguous insert error is final for the whole trace: it fails
/// without restoration and every later event, of any number, is inert, so the
/// grant consumed by this request is never re-armed and no success follows.
let failed_insert_is_final
      (d: t_RedemptionDriver)
      (suffix: list t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ is_insert d))
    (ensures (
      let t = step d (RedemptionEvent_Insert InsertObservation_Failed) in
      t.f_effect = RedemptionEffect_Fail RedemptionFailure_InsertStorage /\
      is_done t.f_driver /\
      not t.f_driver.f_restored /\
      not t.f_driver.f_insert_succeeded /\
      run t.f_driver suffix = t.f_driver /\
      count_complete t.f_driver suffix = 0)) =
  let t = step d (RedemptionEvent_Insert InsertObservation_Failed) in
  step_sound d (RedemptionEvent_Insert InsertObservation_Failed);
  done_suffix_inert t.f_driver suffix

// ── The U-24 replay: no insertion, one matching row ────────────────────────

/// A replay request emits no `Insert` effect, whatever observations it is fed.
/// The driver starts in the `Replay` stage, every event but `Replayed` is idle
/// there, and the replay verdict is terminal; so no later step can reach the
/// insert stage. This is the "a replay never enrolls a second device" half of
/// the U-24 theorem, for an arbitrary-length event list.
let rec replay_never_inserts (events: list t_RedemptionEvent)
  : Lemma
    (requires True)
    (ensures (count_insert (begin_redemption_replay ()).f_driver events = 0))
    (decreases events) =
  begin_replay_sound ();
  let d = (begin_redemption_replay ()).f_driver in
  trace_sound_matches_rust d;
  match events with
  | [] -> ()
  | e :: rest ->
      let t = step d e in
      step_sound d e;
      (match e <: t_RedemptionEvent with
       | RedemptionEvent_Replayed _ ->
           done_suffix_inert t.f_driver rest
       | _ ->
           assert (t.f_driver = d);
           replay_never_inserts rest)

/// A replay only ever answers `Complete` from a `Replayed` observation that
/// carries the matching-key row. Together with the store-model lemma
/// `replay_finds_the_inserted_device` (the row the first request inserted is
/// exactly the row this lookup returns), a replay returns the device the first
/// request created.
let replay_complete_only_from_a_matching_row
      (d: t_RedemptionDriver)
      (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d /\ is_replay d))
    (ensures (
      (step d e).f_effect = RedemptionEffect_Complete ==>
      (match e <: t_RedemptionEvent with
       | RedemptionEvent_Replayed (ReplayObservation_Enrolled c) ->
           c.f_key_matches = true
       | _ -> False))) =
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed _ -> ()
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert _ -> ()
  | RedemptionEvent_Recheck _ -> ()
  | RedemptionEvent_Replayed obs ->
      (match obs <: t_ReplayObservation with
       | ReplayObservation_Enrolled _ -> ()
       | ReplayObservation_Absent -> ())

/// An absent row and a row whose keys differ from the request's are the same
/// uniform `GrantUnavailable` refusal the missing-grant path always returned.
let replay_refusal_is_grant_unavailable
      (d: t_RedemptionDriver)
      (observation: t_ReplayObservation)
  : Lemma
    (requires (trace_sound d /\ is_replay d))
    (ensures (
      (match observation <: t_ReplayObservation with
       | ReplayObservation_Enrolled c -> c.f_key_matches = false
       | ReplayObservation_Absent -> true) ==>
      (step d (RedemptionEvent_Replayed observation)).f_effect =
        RedemptionEffect_Fail RedemptionFailure_GrantUnavailable)) =
  match observation <: t_ReplayObservation with
  | ReplayObservation_Enrolled _ -> ()
  | ReplayObservation_Absent -> ()

/// A replay success is reachable from the extracted begin, and it neither
/// inserts nor restores anything: one lookup answers `Complete`.
let replay_success_is_reachable ()
  : Lemma (
      let d = run_from_replay
        [ RedemptionEvent_Replayed
            (ReplayObservation_Enrolled { f_key_matches = true }) ] in
      d.f_replay_succeeded = true /\
      not d.f_insert_succeeded /\
      not d.f_insert_attempted /\
      not d.f_restored /\
      is_done d /\
      count_insert (begin_redemption_replay ()).f_driver
        [ RedemptionEvent_Replayed
            (ReplayObservation_Enrolled { f_key_matches = true }) ] = 0) =
  replay_never_inserts
    [ RedemptionEvent_Replayed (ReplayObservation_Enrolled { f_key_matches = true }) ]

/// A different-key replay is the historical refusal, reachable in one step.
let replay_mismatch_is_reachable ()
  : Lemma (
      last_effect (begin_redemption_replay ()).f_driver
        [ RedemptionEvent_Replayed
            (ReplayObservation_Enrolled { f_key_matches = false }) ]
      = RedemptionEffect_Fail RedemptionFailure_GrantUnavailable) =
  ()

/// A replay request whose lookup finds no row is the same refusal.
let replay_absent_is_reachable ()
  : Lemma (
      last_effect (begin_redemption_replay ()).f_driver
        [ RedemptionEvent_Replayed ReplayObservation_Absent ]
      = RedemptionEffect_Fail RedemptionFailure_GrantUnavailable) =
  ()

// ── Reachability witnesses ──────────────────────────────────────────────────

let ready_credential : t_ReadyToConsume =
  { f_epoch = mk_i64 3; f_possession = false }

let ready_possession : t_ReadyToConsume =
  { f_epoch = mk_i64 3; f_possession = true }

let enrollment_observation_credential : t_EnrollmentObservation =
  {
    f_grant_present = true;
    f_grant_consumed = true;
    f_consumed_matches_observed = true;
    f_account_present = true;
    f_grant_possession = false;
    f_grant_epoch = mk_i64 3;
    f_stored_epoch = Core_models.Option.Option_Some (mk_i64 3);
    f_account_epoch_active = true;
    f_credential_id_matches = true;
    f_commitment_len = mk_usize 0;
    f_hybrid_ek_len = v_HYBRID_EK_LEN;
    f_hybrid_vk_len = v_HYBRID_VK_LEN;
  }

let enrollment_observation_revoked : t_EnrollmentObservation =
  {
    enrollment_observation_credential with
    f_credential_id_matches = false;
  }

let matched_consumption : t_ConsumptionObservation =
  ConsumptionObservation_Present
    ({ f_key_epoch = mk_i64 3;
       f_possession = false;
       f_matches_observed_grant = true })

let permitted_policy (obs: t_EnrollmentObservation) : t_FinalPolicyObservation =
  { f_enrollment = obs;
    f_rekey = RekeyObservation_Permit { f_epoch = mk_i64 3 } }

let success_events : list t_RedemptionEvent =
  [ RedemptionEvent_Consumed matched_consumption;
    RedemptionEvent_FinalPolicy (permitted_policy enrollment_observation_credential);
    RedemptionEvent_Insert InsertObservation_Inserted ]

let insert_failed_events : list t_RedemptionEvent =
  [ RedemptionEvent_Consumed matched_consumption;
    RedemptionEvent_FinalPolicy (permitted_policy enrollment_observation_credential);
    RedemptionEvent_Insert InsertObservation_Failed ]

let revocation_events : list t_RedemptionEvent =
  [ RedemptionEvent_Consumed matched_consumption;
    RedemptionEvent_FinalPolicy (permitted_policy enrollment_observation_credential);
    RedemptionEvent_Insert InsertObservation_Skipped;
    RedemptionEvent_Recheck AuthorityRecheckObservation_CredentialReplaced ]

let rotation_events : list t_RedemptionEvent =
  [ RedemptionEvent_Consumed matched_consumption;
    RedemptionEvent_FinalPolicy (permitted_policy enrollment_observation_credential);
    RedemptionEvent_Insert InsertObservation_Skipped;
    RedemptionEvent_Recheck AuthorityRecheckObservation_StillRotating ]

/// A complete success is reachable from the real `begin_redemption`: matched
/// consumption, a real `Enroll` permit, and an `Inserted` observation. The
/// count is exactly one.
let success_is_reachable ()
  : Lemma (
      let d = run_from_ready ready_credential success_events in
      d.f_insert_succeeded = true /\ d.f_restored = false /\ is_done d /\
      count_complete_from_ready ready_credential success_events = 1) =
  ()

/// A failed insert observation is reachable and is terminal: the grant is
/// not restored, because the INSERT may have committed before the error.
let insert_failure_is_reachable ()
  : Lemma (
      let d = run_from_ready ready_credential insert_failed_events in
      d.f_insert_succeeded = false /\ d.f_restored = false /\ is_done d /\
      last_effect_from_ready ready_credential insert_failed_events =
        RedemptionEffect_Fail RedemptionFailure_InsertStorage) =
  ()

/// A zero-row insert followed by credential replacement is terminal without
/// restoration (revocation, not a retryable rotation).
let revocation_is_reachable ()
  : Lemma (
      let d = run_from_ready ready_credential revocation_events in
      d.f_insert_succeeded = false /\ d.f_restored = false /\
      last_effect_from_ready ready_credential revocation_events =
        RedemptionEffect_Fail RedemptionFailure_CredentialReplaced) =
  ()

/// The final enrollment policy can also deny after a matched consumption; that
/// denial is terminal and does not restore the consumed grant.
let policy_denial_is_reachable ()
  : Lemma (
      let events =
        [ RedemptionEvent_Consumed matched_consumption;
          RedemptionEvent_FinalPolicy (permitted_policy enrollment_observation_revoked) ] in
      let d = run_from_ready ready_credential events in
      d.f_insert_succeeded = false /\ d.f_restored = false /\
      last_effect_from_ready ready_credential events =
        RedemptionEffect_Fail RedemptionFailure_PolicyRejected) =
  ()

/// A zero-row insert followed by unchanged authority is the retryable rotation
/// conflict and restores the grant.
let rotation_is_reachable ()
  : Lemma (
      let d = run_from_ready ready_credential rotation_events in
      d.f_insert_succeeded = false /\ d.f_restored = true /\
      last_effect_from_ready ready_credential rotation_events =
        RedemptionEffect_RestoreAndFail RedemptionFailure_Rotating) =
  ()

/// The possession-ready permit is a different driver instance: its matched
/// consumption and permission reach an insert authority, not a success.
let possession_insert_is_reachable ()
  : Lemma (
      let events =
        [ RedemptionEvent_Consumed
            (ConsumptionObservation_Present
              ({ f_key_epoch = mk_i64 3;
                 f_possession = true;
                 f_matches_observed_grant = true }));
          RedemptionEvent_FinalPolicy
            (permitted_policy
              ({ enrollment_observation_credential with
                 f_grant_possession = true;
                 f_credential_id_matches = false;
                 f_commitment_len = mk_usize 32 })) ]
      in
      let d = run_from_ready ready_possession events in
      d.f_insert_succeeded = false /\ d.f_restored = false /\
      is_insert d /\
      last_effect_from_ready ready_possession events =
        RedemptionEffect_Insert ({ f_epoch = mk_i64 3; f_possession = true })) =
  ()
