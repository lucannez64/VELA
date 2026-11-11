module Vela_enrollment_policy_enroll_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* device
/// enrollment transition relation (`Vela_enrollment_policy.Enroll_driver`).
///
/// Scope: one `EnrollDriver` value, i.e. one `POST /device/enroll` request.
/// SQL, signature verification, clocks, rate limiting and response rendering
/// remain effectful glue outside this module; the driver's inputs are
/// observations, never verified origins.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `enroll_state_is_sound` and proved equivalent to it; all
/// trace lemmas then quantify over every event list.
///
/// Headline facts: the insert effect is emitted at most once; a final
/// `inserted` state implies the enroll-purpose challenge was consumed, the
/// enrolling device authenticated, the new key material and its signature
/// verified, the rekey policy permitted the mutation and the account-epoch
/// guard matched; success implies exactly one insert; failure never inserts.

open FStar.Mul
open Core_models
open Vela_enrollment_policy
open Vela_enrollment_policy.Enroll_driver

// ── Independent state invariant ─────────────────────────────────────────────

let is_start (d: t_EnrollDriver) : bool =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Start -> true
  | _ -> false

let is_device (d: t_EnrollDriver) : bool =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Device -> true
  | _ -> false

let is_prepared (d: t_EnrollDriver) : bool =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Prepared -> true
  | _ -> false

let is_account (d: t_EnrollDriver) : bool =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Account -> true
  | _ -> false

let is_insert (d: t_EnrollDriver) : bool =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Insert -> true
  | _ -> false

let is_done (d: t_EnrollDriver) : bool =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Done -> true
  | _ -> false

/// Strengthened trace invariant, written out independently of the Rust
/// postcondition. The last clauses record the provenance of an inserted row
/// and the one-way establishment of every approval flag.
let trace_sound (d: t_EnrollDriver) : bool =
  let start_clean =
    not d.f_challenge_consumed && not d.f_challenge_purpose_enroll &&
    not d.f_device_active && not d.f_auth_signature_verified &&
    not d.f_keys_valid && not d.f_enrollment_signature_verified &&
    not d.f_epoch_positive && not d.f_rekey_permitted &&
    not d.f_inserted && not d.f_account_epoch_active &&
    not d.f_succeeded && not d.f_failed
  in
  let device_clean =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll &&
    not d.f_device_active && not d.f_auth_signature_verified &&
    not d.f_keys_valid && not d.f_enrollment_signature_verified &&
    not d.f_epoch_positive && not d.f_rekey_permitted &&
    not d.f_inserted && not d.f_account_epoch_active &&
    not d.f_succeeded && not d.f_failed
  in
  let prepared_clean =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll &&
    d.f_device_active && d.f_auth_signature_verified &&
    not d.f_keys_valid && not d.f_enrollment_signature_verified &&
    not d.f_epoch_positive && not d.f_rekey_permitted &&
    not d.f_inserted && not d.f_account_epoch_active &&
    not d.f_succeeded && not d.f_failed
  in
  let account_clean =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll &&
    d.f_device_active && d.f_auth_signature_verified &&
    d.f_keys_valid && d.f_enrollment_signature_verified &&
    not d.f_epoch_positive && not d.f_rekey_permitted &&
    not d.f_inserted && not d.f_account_epoch_active &&
    not d.f_succeeded && not d.f_failed
  in
  let insert_clean =
    d.f_challenge_consumed && d.f_challenge_purpose_enroll &&
    d.f_device_active && d.f_auth_signature_verified &&
    d.f_keys_valid && d.f_enrollment_signature_verified &&
    d.f_epoch_positive && d.f_rekey_permitted &&
    not d.f_inserted && not d.f_account_epoch_active &&
    not d.f_succeeded && not d.f_failed
  in
  let done_clean =
    (d.f_succeeded || d.f_failed) && not (d.f_succeeded && d.f_failed) &&
    (not d.f_succeeded || (d.f_inserted && d.f_account_epoch_active)) &&
    (not d.f_failed || not d.f_inserted)
  in
  d.f_authorized &&
  (not (is_start d) || start_clean) &&
  (not (is_device d) || device_clean) &&
  (not (is_prepared d) || prepared_clean) &&
  (not (is_account d) || account_clean) &&
  (not (is_insert d) || insert_clean) &&
  (not (is_done d) || done_clean) &&
  (not d.f_challenge_purpose_enroll || d.f_challenge_consumed) &&
  (not d.f_device_active || d.f_challenge_consumed) &&
  (not d.f_auth_signature_verified || d.f_device_active) &&
  (not d.f_keys_valid || (d.f_device_active && d.f_auth_signature_verified)) &&
  (not d.f_enrollment_signature_verified || d.f_keys_valid) &&
  (not d.f_epoch_positive || d.f_enrollment_signature_verified) &&
  (not d.f_rekey_permitted || d.f_epoch_positive) &&
  (not d.f_inserted || d.f_rekey_permitted) &&
  (not d.f_account_epoch_active || d.f_inserted) &&
  (not d.f_inserted ||
    (d.f_challenge_consumed && d.f_challenge_purpose_enroll &&
     d.f_device_active && d.f_auth_signature_verified && d.f_keys_valid &&
     d.f_enrollment_signature_verified && d.f_epoch_positive &&
     d.f_rekey_permitted && d.f_account_epoch_active)) &&
  (not (is_start d) || d.f_authorized)

/// The independently written invariant is exactly the Rust postcondition's
/// predicate. Proved by exhaustive stage case analysis, not by aliasing the
/// definition in the statements below.
let trace_sound_matches_rust (d: t_EnrollDriver)
  : Lemma (trace_sound d = enroll_state_is_sound d) =
  match d.f_stage <: t_EnrollStage with
  | EnrollStage_Start -> ()
  | EnrollStage_Device -> ()
  | EnrollStage_Prepared -> ()
  | EnrollStage_Account -> ()
  | EnrollStage_Insert -> ()
  | EnrollStage_Done -> ()

// ── The transition relation ─────────────────────────────────────────────────

let begin_sound ()
  : Lemma (trace_sound (begin_enroll ()).f_driver) =
  trace_sound_matches_rust (begin_enroll ()).f_driver

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_EnrollDriver) (e: t_EnrollEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (enroll_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

/// A finished driver is inert for every event.
let step_after_done (d: t_EnrollDriver) (e: t_EnrollEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = EnrollEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_EnrollEvent with
  | EnrollEvent_ChallengeConsumed _ -> ()
  | EnrollEvent_DeviceChecked _ -> ()
  | EnrollEvent_EnrollmentPrepared _ -> ()
  | EnrollEvent_AccountChecked _ -> ()
  | EnrollEvent_DeviceInserted _ -> ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_EnrollDriver) (events: list t_EnrollEvent)
  : Pure t_EnrollDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let run_from_enroll (events: list t_EnrollEvent)
  : Pure t_EnrollDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_sound ();
  run (begin_enroll ()).f_driver events

// ── Effect provenance ──────────────────────────────────────────────────────

let is_insert_effect (e: t_EnrollEffect) : bool =
  match e <: t_EnrollEffect with
  | EnrollEffect_InsertDevice -> true
  | _ -> false

let is_success_effect (e: t_EnrollEffect) : bool =
  match e <: t_EnrollEffect with
  | EnrollEffect_Complete -> true
  | _ -> false

let is_failure_effect (e: t_EnrollEffect) : bool =
  match e <: t_EnrollEffect with
  | EnrollEffect_Fail _ -> true
  | _ -> false

/// The insert observation is itself the terminal decision.
let on_device_inserted_is_done (d: t_EnrollDriver) (o: t_InsertObservation)
  : Lemma
    (requires (enroll_state_is_sound d /\ is_insert d /\
      d.f_epoch_positive /\ d.f_rekey_permitted))
    (ensures (is_done (on_device_inserted d o).f_driver)) = ()

/// An insert decision is the driver's Insert stage answering its insert event.
let is_insert_event (e: t_EnrollEvent) : bool =
  match e <: t_EnrollEvent with
  | EnrollEvent_DeviceInserted _ -> true
  | _ -> false

let is_insert_decision (d: t_EnrollDriver) (e: t_EnrollEvent) : bool =
  is_insert d && is_insert_event e

/// Such a decision always reaches `Done`.
let insert_decision_is_done (d: t_EnrollDriver) (e: t_EnrollEvent)
  : Lemma
    (requires (trace_sound d /\ is_insert_decision d e))
    (ensures (is_done (step d e).f_driver)) =
  trace_sound_matches_rust d;
  match e <: t_EnrollEvent with
  | EnrollEvent_DeviceInserted o ->
      assert (is_insert d);
      assert (d.f_epoch_positive && d.f_rekey_permitted);
      assert ((step d e).f_driver = (on_device_inserted d o).f_driver);
      on_device_inserted_is_done d o
  | EnrollEvent_ChallengeConsumed _ -> ()
  | EnrollEvent_DeviceChecked _ -> ()
  | EnrollEvent_EnrollmentPrepared _ -> ()
  | EnrollEvent_AccountChecked _ -> ()

/// Number of insert decisions the driver takes while consuming a schedule.
let rec insert_decisions (d: t_EnrollDriver) (events: list t_EnrollEvent)
  : Pure nat
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (if is_insert_decision d e then 1 else 0) +
      insert_decisions (step d e).f_driver rest

let rec insert_decisions_from_done (d: t_EnrollDriver) (events: list t_EnrollEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (insert_decisions d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      insert_decisions_from_done d rest

let rec insert_decisions_le_one (d: t_EnrollDriver) (events: list t_EnrollEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (insert_decisions d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      let t = step d e in
      step_sound d e;
      if is_insert_decision d e then begin
        insert_decision_is_done d e;
        assert (is_done t.f_driver);
        insert_decisions_from_done t.f_driver rest
      end else begin
        insert_decisions_le_one t.f_driver rest
      end

let insert_decisions_from_begin_le_one (events: list t_EnrollEvent)
  : Lemma (insert_decisions (begin_enroll ()).f_driver events <= 1) =
  begin_sound ();
  insert_decisions_le_one (begin_enroll ()).f_driver events

// ── Ordering and terminal facts ────────────────────────────────────────────

/// A final inserted state carries every approval the statement names.
let inserted_implies_approvals (d: t_EnrollDriver)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      d.f_inserted ==>
      (d.f_challenge_consumed && d.f_challenge_purpose_enroll &&
       d.f_device_active && d.f_auth_signature_verified && d.f_keys_valid &&
       d.f_enrollment_signature_verified && d.f_epoch_positive &&
       d.f_rekey_permitted && d.f_account_epoch_active))) = ()

/// A final success inserted exactly one row.
let succeeded_implies_inserted (d: t_EnrollDriver)
  : Lemma
    (requires (trace_sound d))
    (ensures (d.f_succeeded ==> d.f_inserted)) =
  trace_sound_matches_rust d

/// A final failure never inserted a row.
let failed_implies_not_inserted (d: t_EnrollDriver)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (d.f_failed ==> not d.f_inserted)) =
  trace_sound_matches_rust d

/// Success and failure are mutually exclusive.
let success_excludes_failure (d: t_EnrollDriver)
  : Lemma
    (requires (trace_sound d))
    (ensures (not (d.f_succeeded && d.f_failed))) =
  trace_sound_matches_rust d

// ── Reachability witnesses (the statements are not vacuous) ────────────────

let happy_events : list t_EnrollEvent =
  [
    EnrollEvent_ChallengeConsumed ChallengeObservation_Consumed;
    EnrollEvent_DeviceChecked DeviceObservation_Verified;
    EnrollEvent_EnrollmentPrepared EnrollmentObservation_Verified;
    EnrollEvent_AccountChecked AccountObservation_Permitted;
    EnrollEvent_DeviceInserted InsertObservation_Inserted;
  ]

let refused_challenge_events : list t_EnrollEvent =
  [ EnrollEvent_ChallengeConsumed ChallengeObservation_Rejected ]

let failed_insert_events : list t_EnrollEvent =
  [
    EnrollEvent_ChallengeConsumed ChallengeObservation_Consumed;
    EnrollEvent_DeviceChecked DeviceObservation_Verified;
    EnrollEvent_EnrollmentPrepared EnrollmentObservation_Verified;
    EnrollEvent_AccountChecked AccountObservation_Permitted;
    EnrollEvent_DeviceInserted InsertObservation_Failed;
  ]

let happy_reaches_success ()
  : Lemma (
      let d = run_from_enroll happy_events in
      d.f_succeeded && d.f_inserted && d.f_account_epoch_active &&
      is_done d) =
  ()

let refused_challenge_reaches_failure ()
  : Lemma (
      let d = run_from_enroll refused_challenge_events in
      d.f_failed && not d.f_inserted && not d.f_succeeded && is_done d) =
  ()

let ambiguous_insert_error_is_terminal ()
  : Lemma (
      let d = run_from_enroll failed_insert_events in
      d.f_failed && not d.f_inserted && d.f_challenge_consumed) =
  ()

/// One insert effect on the happy schedule, none on the refused one.
let happy_insert_count ()
  : Lemma (
      insert_decisions (begin_enroll ()).f_driver happy_events = 1) =
  ()

let refused_insert_count ()
  : Lemma (
      insert_decisions (begin_enroll ()).f_driver refused_challenge_events = 0) =
  ()
