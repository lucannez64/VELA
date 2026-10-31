module Vela_session_policy_login_driver_lemmas

/// Hand-written, unbounded per-request trace induction over the *extracted*
/// `/auth/verify` decision driver (`Vela_session_policy.Login_driver.step`).
///
/// Scope: one `LoginDriver` value, i.e. one HTTP request. The theorem does not
/// claim anything about two concurrent requests; the single-use store
/// `get_del`, the SQL device query, the hybrid verifier, PASETO issuance, the
/// JTI store and the failure-counter effects are effectful glue outside this
/// module. Their results reach the driver only as explicit observations.
///
/// The invariant below is restated independently of `login_state_is_sound` and
/// proved equivalent to it; all trace lemmas then quantify over every event
/// list. No proof escape or solver laxity is used.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Login_driver

// ── Independent state invariant ─────────────────────────────────────────────

let is_challenge (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Challenge -> true
  | _ -> false

let is_device (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Device -> true
  | _ -> false

let is_verify (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Verify -> true
  | _ -> false

let is_record_failure (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_RecordFailure -> true
  | _ -> false

let is_reset (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Reset -> true
  | _ -> false

let is_issue (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Issue -> true
  | _ -> false

let is_track (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Track -> true
  | _ -> false

let is_done (d: t_LoginDriver) : bool =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Done -> true
  | _ -> false

let no_pending (d: t_LoginDriver) : bool =
  match d.f_verifier_failure <: t_VerifierFailure with
  | VerifierFailure_None -> true
  | _ -> false

/// Strengthened trace invariant: every stage carries exactly the facts its
/// position implies, a response requires the full successful chain, and a
/// failure can never coexist with a response.
let trace_sound (d: t_LoginDriver) : bool =
  let challenge_clean =
    not d.f_challenge_accepted && not d.f_device_present && not d.f_verifier_valid &&
    no_pending d && not d.f_backoff_reset && not d.f_token_issued &&
    not d.f_token_tracked && not d.f_responded && not d.f_failed
  in
  let device_clean =
    d.f_challenge_accepted && not d.f_device_present && not d.f_verifier_valid &&
    no_pending d && not d.f_backoff_reset && not d.f_token_issued &&
    not d.f_token_tracked && not d.f_responded && not d.f_failed
  in
  let verify_clean =
    d.f_challenge_accepted && d.f_device_present && not d.f_verifier_valid &&
    no_pending d && not d.f_backoff_reset && not d.f_token_issued &&
    not d.f_token_tracked && not d.f_responded && not d.f_failed
  in
  let record_clean =
    d.f_challenge_accepted && d.f_device_present && not d.f_verifier_valid &&
    not (no_pending d) && not d.f_backoff_reset && not d.f_token_issued &&
    not d.f_token_tracked && not d.f_responded && not d.f_failed
  in
  let reset_clean =
    d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
    no_pending d && not d.f_backoff_reset && not d.f_token_issued &&
    not d.f_token_tracked && not d.f_responded && not d.f_failed
  in
  let issue_clean =
    d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
    no_pending d && d.f_backoff_reset && not d.f_token_issued &&
    not d.f_token_tracked && not d.f_responded && not d.f_failed
  in
  let track_clean =
    d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
    no_pending d && d.f_backoff_reset && d.f_token_issued &&
    not d.f_token_tracked && not d.f_responded && not d.f_failed
  in
  let done_clean =
    (d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
    (not d.f_responded ||
      (d.f_challenge_accepted && d.f_device_present && d.f_verifier_valid &&
       no_pending d && d.f_backoff_reset && d.f_token_issued && d.f_token_tracked))
  in
  (match d.f_stage <: t_LoginStage with
   | LoginStage_Challenge -> challenge_clean
   | LoginStage_Device -> device_clean
   | LoginStage_Verify -> verify_clean
   | LoginStage_RecordFailure -> record_clean
   | LoginStage_Reset -> reset_clean
   | LoginStage_Issue -> issue_clean
   | LoginStage_Track -> track_clean
   | LoginStage_Done -> done_clean) &&
  (not d.f_device_present || d.f_challenge_accepted) &&
  (not d.f_verifier_valid || d.f_device_present) &&
  (not d.f_backoff_reset || d.f_verifier_valid) &&
  (not d.f_token_issued || d.f_backoff_reset) &&
  (not d.f_token_tracked || d.f_token_issued) &&
  (not d.f_responded || d.f_token_tracked) &&
  (not d.f_failed || not d.f_responded) &&
  (no_pending d || not d.f_verifier_valid)

/// The independently written invariant is exactly the Rust postcondition's
/// predicate, by exhaustive stage case analysis.
let trace_sound_matches_rust (d: t_LoginDriver)
  : Lemma (trace_sound d = login_state_is_sound d) =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Challenge -> ()
  | LoginStage_Device -> ()
  | LoginStage_Verify -> ()
  | LoginStage_RecordFailure -> ()
  | LoginStage_Reset -> ()
  | LoginStage_Issue -> ()
  | LoginStage_Track -> ()
  | LoginStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_sound ()
  : Lemma (trace_sound (begin_login ()).f_driver) =
  trace_sound_matches_rust (begin_login ()).f_driver

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (login_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

/// After a response the driver is terminal: every event is inert.
let step_after_response (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_responded))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = LoginEffect_Idle)) =
  trace_sound_matches_rust d;
  assert (is_done d = true);
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved _ -> ()
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked _ -> ()

/// A finished driver is inert for every event.
let step_after_done (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = LoginEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved _ -> ()
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked _ -> ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_LoginDriver) (events: list t_LoginEvent)
  : Pure t_LoginDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let rec count_respond (d: t_LoginDriver) (events: list t_LoginEvent)
  : Pure nat
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_LoginEffect with
       | LoginEffect_Respond -> 1
       | _ -> 0) +
      count_respond (step d e).f_driver rest

let rec last_effect (d: t_LoginDriver) (events: list t_LoginEvent)
  : Pure t_LoginEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> LoginEffect_Idle
  | e :: [] -> (step d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step d e).f_driver rest

/// Total wrappers starting from the actual extracted `begin_login`.
let run_from_begin (events: list t_LoginEvent)
  : Pure t_LoginDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  run (begin_login ()).f_driver events

let count_respond_from_begin (events: list t_LoginEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  count_respond (begin_login ()).f_driver events

let last_effect_from_begin (events: list t_LoginEvent)
  : Pure t_LoginEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  last_effect (begin_login ()).f_driver events

// ── Event provenance helpers ────────────────────────────────────────────────

let is_accepted_event (e: t_LoginEvent) : bool =
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved (ChallengeObservation_Observed (ChallengeConsumption_Accepted )) -> true
  | _ -> false

let is_valid_verifier_event (e: t_LoginEvent) : bool =
  match e <: t_LoginEvent with
  | LoginEvent_VerifierObserved VerifierObservation_Valid -> true
  | _ -> false

let is_tracked_event (e: t_LoginEvent) : bool =
  match e <: t_LoginEvent with
  | LoginEvent_TokenTracked TokenTrackObservation_Tracked -> true
  | _ -> false

let rec has_accepted_event (events: list t_LoginEvent) : bool =
  match events with
  | [] -> false
  | e :: rest -> is_accepted_event e || has_accepted_event rest

let rec has_valid_verifier_event (events: list t_LoginEvent) : bool =
  match events with
  | [] -> false
  | e :: rest -> is_valid_verifier_event e || has_valid_verifier_event rest

let rec has_tracked_event (events: list t_LoginEvent) : bool =
  match events with
  | [] -> false
  | e :: rest -> is_tracked_event e || has_tracked_event rest

// ── Effect provenance ──────────────────────────────────────────────────────

/// A `Respond` effect carries the complete successful chain.
let respond_effect_requires_all (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step d e).f_effect <: t_LoginEffect with
      | LoginEffect_Respond ->
          (step d e).f_driver.f_challenge_accepted /\
          (step d e).f_driver.f_device_present /\
          (step d e).f_driver.f_verifier_valid /\
          (step d e).f_driver.f_backoff_reset /\
          (step d e).f_driver.f_token_issued /\
          (step d e).f_driver.f_token_tracked /\
          (step d e).f_driver.f_responded /\
          not (step d e).f_driver.f_failed /\
          is_done (step d e).f_driver
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (login_state_is_sound d = true);
  ()

/// A `Respond` effect can only be produced by the tracked-token event from the
/// `Track` stage.
let respond_only_from_tracked (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      ((step d e).f_effect = LoginEffect_Respond) ==>
      (match e <: t_LoginEvent with
       | LoginEvent_TokenTracked TokenTrackObservation_Tracked -> is_track d
       | _ -> False))) =
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved _ -> ()
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked obs ->
      (match obs <: t_TokenTrackObservation with
       | TokenTrackObservation_Tracked -> ()
       | TokenTrackObservation_Failed -> ())

/// Every `Fail` effect is terminal and cannot be followed by a response.
let rec done_suffix_inert (d: t_LoginDriver) (events: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (run d events = d /\ count_respond d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

let fail_effect_is_terminal
      (d: t_LoginDriver)
      (e: t_LoginEvent)
      (suffix: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step d e).f_effect <: t_LoginEffect with
      | LoginEffect_Fail _ ->
          is_done (step d e).f_driver /\
          (step d e).f_driver.f_failed /\
          not (step d e).f_driver.f_responded /\
          run (step d e).f_driver suffix = (step d e).f_driver /\
          count_respond (step d e).f_driver suffix = 0
      | _ -> True)) =
  trace_sound_matches_rust d;
  step_sound d e;
  match (step d e).f_effect <: t_LoginEffect with
  | LoginEffect_Fail _ ->
      done_suffix_inert (step d e).f_driver suffix
  | _ -> ()

// ── Flag provenance ────────────────────────────────────────────────────────

let step_challenge_flag_origin (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d e).f_driver.f_challenge_accepted ==>
      (d.f_challenge_accepted \/ is_accepted_event e))) =
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved obs ->
      (match obs <: t_ChallengeObservation with
       | ChallengeObservation_Observed consumption ->
           (match consumption <: t_ChallengeConsumption with
            | ChallengeConsumption_Accepted -> ()
            | ChallengeConsumption_Missing -> ()
            | ChallengeConsumption_WrongPurpose -> ())
       | ChallengeObservation_StorageFailed -> ())
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked _ -> ()

let step_verifier_flag_origin (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d e).f_driver.f_verifier_valid ==>
      (d.f_verifier_valid \/ is_valid_verifier_event e))) =
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved _ -> ()
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved obs ->
      (match obs <: t_VerifierObservation with
       | VerifierObservation_Valid -> ()
       | VerifierObservation_RejectedUnauthorized -> ()
       | VerifierObservation_RejectedBadRequest -> ()
       | VerifierObservation_RejectedInternal -> ()
       | VerifierObservation_ChallengeDecodeFailed -> ())
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked _ -> ()

let step_tracked_flag_origin (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d e).f_driver.f_token_tracked ==>
      (d.f_token_tracked \/ is_tracked_event e))) =
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved _ -> ()
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked obs ->
      (match obs <: t_TokenTrackObservation with
       | TokenTrackObservation_Tracked -> ()
       | TokenTrackObservation_Failed -> ())

let rec challenge_flag_origin (d: t_LoginDriver) (events: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (run d events).f_challenge_accepted ==>
      (d.f_challenge_accepted \/ has_accepted_event events)))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      step_challenge_flag_origin d e;
      challenge_flag_origin (step d e).f_driver rest

let rec verifier_flag_origin (d: t_LoginDriver) (events: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (run d events).f_verifier_valid ==>
      (d.f_verifier_valid \/ has_valid_verifier_event events)))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      step_verifier_flag_origin d e;
      verifier_flag_origin (step d e).f_driver rest

let rec tracked_flag_origin (d: t_LoginDriver) (events: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (run d events).f_token_tracked ==>
      (d.f_token_tracked \/ has_tracked_event events)))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      step_tracked_flag_origin d e;
      tracked_flag_origin (step d e).f_driver rest

// ── Response trace properties ──────────────────────────────────────────────

/// At most one response per driver instance, for an arbitrary-length event
/// list.
let rec respond_count_le_one (d: t_LoginDriver) (events: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_respond d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if (match t.f_effect <: t_LoginEffect with
          | LoginEffect_Respond -> true
          | _ -> false)
      then begin
        assert (t.f_driver.f_responded = true);
        done_suffix_inert t.f_driver rest
      end else begin
        respond_count_le_one t.f_driver rest
      end

/// A response requires a consumed matching-purpose challenge.
let response_implies_accepted_event
      (events: list t_LoginEvent)
  : Lemma
    (requires ((run_from_begin events).f_responded))
    (ensures (has_accepted_event events)) =
  let d = run_from_begin events in
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  trace_sound_matches_rust d;
  assert (d.f_challenge_accepted);
  challenge_flag_origin (begin_login ()).f_driver events;
  assert (not (begin_login ()).f_driver.f_challenge_accepted);
  ()

/// A response requires an actual successful verifier result.
let response_implies_valid_verifier_event
      (events: list t_LoginEvent)
  : Lemma
    (requires ((run_from_begin events).f_responded))
    (ensures (has_valid_verifier_event events)) =
  let d = run_from_begin events in
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  trace_sound_matches_rust d;
  assert (d.f_verifier_valid);
  verifier_flag_origin (begin_login ()).f_driver events;
  assert (not (begin_login ()).f_driver.f_verifier_valid);
  ()

/// A response requires a successful tracking observation.
let response_implies_tracked_event
      (events: list t_LoginEvent)
  : Lemma
    (requires ((run_from_begin events).f_responded))
    (ensures (has_tracked_event events)) =
  let d = run_from_begin events in
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  trace_sound_matches_rust d;
  assert (d.f_token_tracked);
  tracked_flag_origin (begin_login ()).f_driver events;
  assert (not (begin_login ()).f_driver.f_token_tracked);
  ()

/// Headline unbounded per-request theorem over the actual extracted driver.
let login_trace_theorem (events: list t_LoginEvent)
  : Lemma (
      let d = run_from_begin events in
      trace_sound d /\
      (d.f_responded ==> not d.f_failed) /\
      (d.f_failed ==> not d.f_responded) /\
      count_respond_from_begin events <= 1 /\
      (d.f_responded ==> has_accepted_event events) /\
      (d.f_responded ==> has_valid_verifier_event events) /\
      (d.f_responded ==> has_tracked_event events)) =
  let d = run_from_begin events in
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  respond_count_le_one (begin_login ()).f_driver events;
  if d.f_responded then begin
    response_implies_accepted_event events;
    response_implies_valid_verifier_event events;
    response_implies_tracked_event events
  end else ()

// ── Terminal refusal lemmas ────────────────────────────────────────────────

/// A wrong-purpose observation at the challenge stage is terminal, spends the
/// nonce (the handler's `get_del` already removed it) and cannot respond.
let wrong_purpose_is_terminal
      (d: t_LoginDriver)
      (suffix: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d /\ is_challenge d))
    (ensures (
      let t = step d (LoginEvent_ChallengeObserved
        (ChallengeObservation_Observed ChallengeConsumption_WrongPurpose)) in
      t.f_effect = LoginEffect_Fail LoginFailure_ChallengeWrongPurpose /\
      is_done t.f_driver /\
      t.f_driver.f_failed /\
      not t.f_driver.f_responded /\
      run t.f_driver suffix = t.f_driver /\
      count_respond t.f_driver suffix = 0)) =
  let t = step d (LoginEvent_ChallengeObserved
    (ChallengeObservation_Observed ChallengeConsumption_WrongPurpose)) in
  step_sound d (LoginEvent_ChallengeObserved
    (ChallengeObservation_Observed ChallengeConsumption_WrongPurpose));
  done_suffix_inert t.f_driver suffix

/// A missing challenge is terminal and cannot respond.
let missing_challenge_is_terminal
      (d: t_LoginDriver)
      (suffix: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d /\ is_challenge d))
    (ensures (
      let t = step d (LoginEvent_ChallengeObserved
        (ChallengeObservation_Observed ChallengeConsumption_Missing)) in
      t.f_effect = LoginEffect_Fail LoginFailure_ChallengeMissing /\
      is_done t.f_driver /\
      not t.f_driver.f_responded /\
      run t.f_driver suffix = t.f_driver /\
      count_respond t.f_driver suffix = 0)) =
  let t = step d (LoginEvent_ChallengeObserved
    (ChallengeObservation_Observed ChallengeConsumption_Missing)) in
  step_sound d (LoginEvent_ChallengeObserved
    (ChallengeObservation_Observed ChallengeConsumption_Missing));
  done_suffix_inert t.f_driver suffix

/// An actual verifier rejection is terminal after the failure side effects and
/// cannot respond, regardless of the fallback counter result.
let verifier_rejection_is_terminal
      (d: t_LoginDriver)
      (observation: t_VerifierObservation)
      (record: t_FailureRecordObservation)
      (suffix: list t_LoginEvent)
  : Lemma
    (requires (
      trace_sound d /\ is_verify d /\
      (match observation <: t_VerifierObservation with
       | VerifierObservation_RejectedUnauthorized -> True
       | VerifierObservation_RejectedBadRequest -> True
       | VerifierObservation_RejectedInternal -> True
       | _ -> False)))
    (ensures (
      let t = step d (LoginEvent_VerifierObserved observation) in
      t.f_effect = LoginEffect_RecordVerificationFailure /\
      is_record_failure t.f_driver /\
      (let u = step t.f_driver (LoginEvent_FailureRecorded record) in
       (match u.f_effect <: t_LoginEffect with
        | LoginEffect_Fail _ -> True
        | _ -> False) /\
       is_done u.f_driver /\
       not u.f_driver.f_responded /\
       run u.f_driver suffix = u.f_driver /\
       count_respond u.f_driver suffix = 0))) =
  let t = step d (LoginEvent_VerifierObserved observation) in
  step_sound d (LoginEvent_VerifierObserved observation);
  let u = step t.f_driver (LoginEvent_FailureRecorded record) in
  step_sound t.f_driver (LoginEvent_FailureRecorded record);
  done_suffix_inert u.f_driver suffix

/// A tracking failure is terminal even though the token was issued; no token
/// response may follow.
let tracking_failure_is_terminal
      (d: t_LoginDriver)
      (suffix: list t_LoginEvent)
  : Lemma
    (requires (trace_sound d /\ is_track d))
    (ensures (
      let t = step d (LoginEvent_TokenTracked TokenTrackObservation_Failed) in
      t.f_effect = LoginEffect_Fail LoginFailure_TrackingFailed /\
      is_done t.f_driver /\
      t.f_driver.f_token_issued /\
      not t.f_driver.f_token_tracked /\
      t.f_driver.f_failed /\
      not t.f_driver.f_responded /\
      run t.f_driver suffix = t.f_driver /\
      count_respond t.f_driver suffix = 0)) =
  let t = step d (LoginEvent_TokenTracked TokenTrackObservation_Failed) in
  step_sound d (LoginEvent_TokenTracked TokenTrackObservation_Failed);
  done_suffix_inert t.f_driver suffix

// ── Reachability witnesses ─────────────────────────────────────────────────

let success_events : list t_LoginEvent =
  [ LoginEvent_ChallengeObserved
      (ChallengeObservation_Observed ChallengeConsumption_Accepted);
    LoginEvent_DeviceObserved DeviceObservation_Present;
    LoginEvent_VerifierObserved VerifierObservation_Valid;
    LoginEvent_BackoffResetObserved BackoffResetObservation_Reset;
    LoginEvent_TokenIssued TokenIssueObservation_Issued;
    LoginEvent_TokenTracked TokenTrackObservation_Tracked ]

let wrong_purpose_events : list t_LoginEvent =
  [ LoginEvent_ChallengeObserved
      (ChallengeObservation_Observed ChallengeConsumption_WrongPurpose) ]

let verifier_rejection_events : list t_LoginEvent =
  [ LoginEvent_ChallengeObserved
      (ChallengeObservation_Observed ChallengeConsumption_Accepted);
    LoginEvent_DeviceObserved DeviceObservation_Present;
    LoginEvent_VerifierObserved VerifierObservation_RejectedUnauthorized;
    LoginEvent_FailureRecorded ({ f_fallback_counter_ok = true }) ]

let tracking_failure_events : list t_LoginEvent =
  [ LoginEvent_ChallengeObserved
      (ChallengeObservation_Observed ChallengeConsumption_Accepted);
    LoginEvent_DeviceObserved DeviceObservation_Present;
    LoginEvent_VerifierObserved VerifierObservation_Valid;
    LoginEvent_BackoffResetObserved BackoffResetObservation_Reset;
    LoginEvent_TokenIssued TokenIssueObservation_Issued;
    LoginEvent_TokenTracked TokenTrackObservation_Failed ]

/// A complete successful login is reachable from the real `begin_login`.
let success_is_reachable ()
  : Lemma (
      let d = run_from_begin success_events in
      d.f_responded = true /\ d.f_failed = false /\ is_done d /\
      count_respond_from_begin success_events = 1 /\
      has_accepted_event success_events /\
      has_valid_verifier_event success_events /\
      has_tracked_event success_events) =
  ()

/// A wrong-purpose challenge is reachable and terminal.
let wrong_purpose_is_reachable ()
  : Lemma (
      let d = run_from_begin wrong_purpose_events in
      d.f_failed = true /\ d.f_responded = false /\
      last_effect_from_begin wrong_purpose_events =
        LoginEffect_Fail LoginFailure_ChallengeWrongPurpose) =
  ()

/// An actual verifier rejection is reachable and terminal.
let verifier_rejection_is_reachable ()
  : Lemma (
      let d = run_from_begin verifier_rejection_events in
      d.f_failed = true /\ d.f_responded = false /\
      d.f_verifier_valid = false /\
      last_effect_from_begin verifier_rejection_events =
        LoginEffect_Fail LoginFailure_VerifierUnauthorized) =
  ()

/// A tracking failure is reachable, terminal, and issues no response even
/// though the token was issued.
let tracking_failure_is_reachable ()
  : Lemma (
      let d = run_from_begin tracking_failure_events in
      d.f_failed = true /\ d.f_responded = false /\
      d.f_token_issued = true /\ d.f_token_tracked = false /\
      last_effect_from_begin tracking_failure_events =
        LoginEffect_Fail LoginFailure_TrackingFailed) =
  ()
