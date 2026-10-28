module Vela_session_policy_registration_driver_lemmas

/// Hand-written, unbounded per-request trace induction over the *extracted*
/// `POST /account/register` decision driver
/// (`Vela_session_policy.Registration_driver`).
///
/// Scope: one `RegistrationDriver` value, i.e. one HTTP request. The SQL
/// transaction, the account/device inserts, PASETO issuance and JTI tracking
/// are effectful glue outside this module; their outcomes reach the driver only
/// as explicit observations. The transaction is the handler's unit of
/// atomicity: a failure after the account insert makes the handler drop the
/// guard, which rolls the account row back.
///
/// Headline facts, for every request observation and every event list:
///
/// - a `Complete` effect requires a started transaction, one account insert and
///   one first-device insert observed inserted, a commit, an issued token and a
///   tracked JTI, so it never authorizes a response for a partial account;
/// - `Complete` and `Fail` occur at most once each and never both;
/// - a `Fail` effect is terminal, failed and does not respond, so an untracked
///   or uncommitted registration cannot return a token;
/// - `InsertDevice` names an account already observed inserted, the commit
///   requires both inserts, and issuance/tracking follow the commit in order.
///
/// No proof escape or solver laxity is used. `trace_sound` is restated
/// independently and proved equal to `registration_state_is_sound`; all trace
/// lemmas then quantify over every event list.

open FStar.Mul
open Core_models
open Vela_session_policy.Registration_driver

// ── Stage predicates ────────────────────────────────────────────────────────

let is_rate_limit (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_RateLimit -> true
  | _ -> false

let is_budget (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_AccountBudget -> true
  | _ -> false

let is_begin_transaction (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_BeginTransaction -> true
  | _ -> false

let is_insert_account (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_InsertAccount -> true
  | _ -> false

let is_insert_device (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_InsertDevice -> true
  | _ -> false

let is_commit (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Commit -> true
  | _ -> false

let is_issue_token (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_IssueToken -> true
  | _ -> false

let is_track_token (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_TrackToken -> true
  | _ -> false

let is_done (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Done -> true
  | _ -> false

/// Strengthened trace invariant: the same predicate as the Rust postcondition,
/// with every stage fact spelled out.
let trace_sound (d: t_RegistrationDriver) : bool =
  let pre:bool =
    not d.f_transaction_open && not d.f_transaction_started &&
    not d.f_account_inserted &&
    not d.f_device_inserted &&
    not d.f_committed &&
    not d.f_token_issued &&
    not d.f_token_tracked &&
    not d.f_responded &&
    not d.f_failed
  in
  let rate_limit:bool =
    is_rate_limit d && not d.f_budget_checked && pre
  in
  let account_budget:bool =
    is_budget d &&
    d.f_rate_allowed &&
    d.f_has_account_limit &&
    not d.f_budget_checked &&
    pre
  in
  let begin_transaction:bool =
    is_begin_transaction d &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    not d.f_transaction_open &&
    not d.f_transaction_started &&
    not d.f_account_inserted &&
    not d.f_device_inserted &&
    not d.f_committed &&
    not d.f_token_issued &&
    not d.f_token_tracked &&
    not d.f_responded &&
    not d.f_failed
  in
  let inserting:bool =
    d.f_rate_allowed && d.f_budget_checked && d.f_transaction_open && d.f_transaction_started &&
    not d.f_committed &&
    not d.f_token_issued &&
    not d.f_token_tracked &&
    not d.f_responded &&
    not d.f_failed
  in
  let insert_account:bool =
    is_insert_account d &&
    inserting &&
    not d.f_account_inserted &&
    not d.f_device_inserted
  in
  let insert_device:bool =
    is_insert_device d &&
    inserting &&
    d.f_account_inserted &&
    not d.f_device_inserted
  in
  let commit:bool =
    is_commit d &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    not d.f_committed &&
    not d.f_token_issued &&
    not d.f_token_tracked &&
    not d.f_responded &&
    not d.f_failed
  in
  let issue_token:bool =
    is_issue_token d &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    d.f_committed &&
    not d.f_token_issued &&
    not d.f_token_tracked &&
    not d.f_responded &&
    not d.f_failed
  in
  let track_token:bool =
    is_track_token d &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    d.f_committed &&
    d.f_token_issued &&
    not d.f_token_tracked &&
    not d.f_responded &&
    not d.f_failed
  in
  let done:bool =
    is_done d &&
    (d.f_responded || d.f_failed) &&
    not (d.f_responded && d.f_failed) &&
    (not d.f_responded ||
      (d.f_rate_allowed && d.f_budget_checked && d.f_transaction_started &&
       d.f_account_inserted && d.f_device_inserted && d.f_committed &&
       d.f_token_issued && d.f_token_tracked))
  in
  (match d.f_stage <: t_RegistrationStage with
   | RegistrationStage_RateLimit -> rate_limit
   | RegistrationStage_AccountBudget -> account_budget
   | RegistrationStage_BeginTransaction -> begin_transaction
   | RegistrationStage_InsertAccount -> insert_account
   | RegistrationStage_InsertDevice -> insert_device
   | RegistrationStage_Commit -> commit
   | RegistrationStage_IssueToken -> issue_token
   | RegistrationStage_TrackToken -> track_token
   | RegistrationStage_Done -> done) &&
  (not d.f_budget_checked || d.f_rate_allowed) &&
  (not d.f_transaction_open || d.f_budget_checked) &&
  (not d.f_transaction_started || d.f_transaction_open) &&
  (not d.f_account_inserted || d.f_transaction_started) &&
  (not d.f_device_inserted || d.f_account_inserted) &&
  (not d.f_committed || d.f_device_inserted) &&
  (not d.f_token_issued || d.f_committed) &&
  (not d.f_token_tracked || d.f_token_issued) &&
  (not d.f_responded || d.f_token_tracked)

let trace_sound_matches_rust (d: t_RegistrationDriver)
  : Lemma (trace_sound d = registration_state_is_sound d) =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_RateLimit -> ()
  | RegistrationStage_AccountBudget -> ()
  | RegistrationStage_BeginTransaction -> ()
  | RegistrationStage_InsertAccount -> ()
  | RegistrationStage_InsertDevice -> ()
  | RegistrationStage_Commit -> ()
  | RegistrationStage_IssueToken -> ()
  | RegistrationStage_TrackToken -> ()
  | RegistrationStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_sound (observation: t_RegistrationRequestObservation)
  : Lemma (trace_sound (begin_registration observation).f_driver) =
  trace_sound_matches_rust (begin_registration observation).f_driver

let step_sound (d: t_RegistrationDriver) (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (registration_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

let step_effect_sound (d: t_RegistrationDriver) (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures (registration_effect_is_sound (step d e).f_driver (step d e).f_effect)) =
  trace_sound_matches_rust d;
  assert (registration_state_is_sound d = true)

/// A finished driver is inert for every event.
let step_after_done (d: t_RegistrationDriver) (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d /\ is_done d))
          (ensures ((step d e).f_driver = d /\
                    (step d e).f_effect = RegistrationEffect_Idle)) =
  trace_sound_matches_rust d;
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Done ->
      (match e <: t_RegistrationEvent with
       | RegistrationEvent_RateLimitObserved _ -> ()
       | RegistrationEvent_BudgetObserved _ -> ()
       | RegistrationEvent_TransactionObserved _ -> ()
       | RegistrationEvent_AccountInserted _ -> ()
       | RegistrationEvent_DeviceInserted _ -> ()
       | RegistrationEvent_CommitObserved _ -> ()
       | RegistrationEvent_TokenObserved _ -> ()
       | RegistrationEvent_TrackObserved _ -> ())
  | _ -> ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_RegistrationDriver) (events: list t_RegistrationEvent)
  : Pure t_RegistrationDriver (requires (trace_sound d))
    (ensures (fun r -> trace_sound r)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let run_from_observation
      (observation: t_RegistrationRequestObservation)
      (events: list t_RegistrationEvent)
  : Pure t_RegistrationDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_sound observation;
  run (begin_registration observation).f_driver events

// ── Success and failure counts ──────────────────────────────────────────────

let b2n (b: bool) : nat = if b then 1 else 0

let is_complete_effect (e: t_RegistrationEffect) : bool =
  match e <: t_RegistrationEffect with
  | RegistrationEffect_Complete -> true
  | _ -> false

let is_fail_effect (e: t_RegistrationEffect) : bool =
  match e <: t_RegistrationEffect with
  | RegistrationEffect_Fail _ -> true
  | _ -> false

let rec count_complete (d: t_RegistrationDriver) (events: list t_RegistrationEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n (is_complete_effect (step d e).f_effect) +
      count_complete (step d e).f_driver rest

let rec count_fail (d: t_RegistrationDriver) (events: list t_RegistrationEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n (is_fail_effect (step d e).f_effect) +
      count_fail (step d e).f_driver rest

let rec done_suffix_inert (d: t_RegistrationDriver) (events: list t_RegistrationEvent)
  : Lemma (requires (trace_sound d /\ is_done d))
          (ensures (run d events = d /\
                    count_complete d events = 0 /\
                    count_fail d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

let rec complete_count_le_one (d: t_RegistrationDriver) (events: list t_RegistrationEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_complete d events <= 1))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_complete_effect t.f_effect
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (is_done t.f_driver = true);
        done_suffix_inert t.f_driver rest
      end else complete_count_le_one t.f_driver rest

let rec fail_count_le_one (d: t_RegistrationDriver) (events: list t_RegistrationEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_fail d events <= 1))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_fail_effect t.f_effect
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (is_done t.f_driver = true);
        done_suffix_inert t.f_driver rest
      end else fail_count_le_one t.f_driver rest

/// Success and failure never both occur.
let rec success_and_failure_exclusive (d: t_RegistrationDriver)
    (events: list t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures (count_complete d events = 0 \/ count_fail d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_complete_effect t.f_effect || is_fail_effect t.f_effect
      then begin
        trace_sound_matches_rust t.f_driver;
        done_suffix_inert t.f_driver rest
      end else success_and_failure_exclusive t.f_driver rest

// ── Ordering facts from the extracted effect contract ───────────────────────

let insert_device_effect_requires_account (d: t_RegistrationDriver)
    (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_effect = RegistrationEffect_InsertDevice ==>
                    (let t = (step d e).f_driver in
                     t.f_transaction_open && t.f_transaction_started &&
                     t.f_account_inserted && not t.f_device_inserted))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

let commit_effect_requires_both_inserts (d: t_RegistrationDriver)
    (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_effect = RegistrationEffect_CommitTransaction ==>
                    (let t = (step d e).f_driver in
                     t.f_account_inserted && t.f_device_inserted &&
                     t.f_transaction_open && t.f_transaction_started &&
                     not t.f_committed))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

let issue_effect_requires_commit (d: t_RegistrationDriver)
    (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_effect = RegistrationEffect_IssueToken ==>
                    (let t = (step d e).f_driver in
                     t.f_committed && not t.f_token_issued))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

let track_effect_requires_issued (d: t_RegistrationDriver)
    (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_effect = RegistrationEffect_TrackToken ==>
                    (let t = (step d e).f_driver in
                     t.f_token_issued && not t.f_token_tracked))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

/// A `Complete` effect is the only response authorization, and it requires the
/// full one-account/one-device/committed/tracked chain.
let complete_effect_requires_everything (d: t_RegistrationDriver)
    (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_effect = RegistrationEffect_Complete ==>
                    (let t = (step d e).f_driver in
                     is_done t /\
                     t.f_account_inserted && t.f_device_inserted &&
                     t.f_committed && t.f_token_issued && t.f_token_tracked))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

/// A `Fail` effect is terminal: the state is `Done`, failed, not responded,
/// and it never claims a commit it did not observe.
let fail_effect_is_terminal (d: t_RegistrationDriver) (e: t_RegistrationEvent)
  : Lemma (requires (trace_sound d))
          (ensures (match (step d e).f_effect <: t_RegistrationEffect with
                    | RegistrationEffect_Fail _ ->
                        is_done (step d e).f_driver /\
                        (step d e).f_driver.f_failed = true /\
                        not (step d e).f_driver.f_responded
                    | _ -> True)) =
  trace_sound_matches_rust d;
  step_effect_sound d e

// ── Headline per-request theorem ────────────────────────────────────────────

let registration_trace_theorem
      (observation: t_RegistrationRequestObservation)
      (events: list t_RegistrationEvent)
  : Lemma (
      let d = run_from_observation observation events in
      trace_sound d /\
      (d.f_responded ==>
        (d.f_account_inserted && d.f_device_inserted && d.f_committed &&
         d.f_token_issued && d.f_token_tracked)) /\
      (d.f_committed ==> (d.f_device_inserted && d.f_account_inserted)) /\
      (d.f_device_inserted ==> d.f_account_inserted) /\
      not (d.f_responded && d.f_failed) /\
      count_complete (begin_registration observation).f_driver events <= 1 /\
      count_fail (begin_registration observation).f_driver events <= 1) =
  begin_sound observation;
  trace_sound_matches_rust (begin_registration observation).f_driver;
  complete_count_le_one (begin_registration observation).f_driver events;
  fail_count_le_one (begin_registration observation).f_driver events;
  success_and_failure_exclusive (begin_registration observation).f_driver events;
  let d = run_from_observation observation events in
  assert (trace_sound d)

// ── Reachability witnesses ─────────────────────────────────────────────────

let valid_request : t_RegistrationRequestObservation =
  { f_has_account_limit = false;
    f_account_limit = mk_i64 0;
    f_identity_ek_valid = true;
    f_identity_vk_valid = true;
    f_share_ek_valid = true }

let limited_request : t_RegistrationRequestObservation =
  { f_has_account_limit = true;
    f_account_limit = mk_i64 3;
    f_identity_ek_valid = true;
    f_identity_vk_valid = true;
    f_share_ek_valid = true }

let invalid_key_request : t_RegistrationRequestObservation =
  { f_has_account_limit = false;
    f_account_limit = mk_i64 0;
    f_identity_ek_valid = false;
    f_identity_vk_valid = true;
    f_share_ek_valid = true }

let rate_allowed : t_RegistrationEvent =
  RegistrationEvent_RateLimitObserved RateLimitObservation_Allowed

let rate_denied : t_RegistrationEvent =
  RegistrationEvent_RateLimitObserved RateLimitObservation_Denied

let budget_counted (count: i64) : t_RegistrationEvent =
  RegistrationEvent_BudgetObserved (BudgetObservation_Counted { f_count = count })

let transaction_begun : t_RegistrationEvent =
  RegistrationEvent_TransactionObserved TransactionObservation_Begun

let account_inserted : t_RegistrationEvent =
  RegistrationEvent_AccountInserted InsertObservation_Inserted

let device_inserted : t_RegistrationEvent =
  RegistrationEvent_DeviceInserted InsertObservation_Inserted

let commit_ok : t_RegistrationEvent =
  RegistrationEvent_CommitObserved CommitObservation_Committed

let token_issued : t_RegistrationEvent =
  RegistrationEvent_TokenObserved TokenObservation_Issued

let track_ok : t_RegistrationEvent =
  RegistrationEvent_TrackObserved TrackObservation_Tracked

let success_events : list t_RegistrationEvent =
  [rate_allowed; transaction_begun; account_inserted; device_inserted;
   commit_ok; token_issued; track_ok]

/// The complete success path is reachable, emits exactly one `Complete`, and
/// ends with the account and first device inserted plus a tracked token.
let success_path_is_reachable ()
  : Lemma (
      let d = run_from_observation valid_request success_events in
      d.f_responded = true /\
      d.f_failed = false /\
      d.f_account_inserted = true /\
      d.f_device_inserted = true /\
      d.f_committed = true /\
      d.f_token_issued = true /\
      d.f_token_tracked = true /\
      count_complete (begin_registration valid_request).f_driver success_events = 1 /\
      count_fail (begin_registration valid_request).f_driver success_events = 0) =
  ()

/// The account ceiling is enforced: a counted budget at the configured limit
/// fails before any transaction, and a failed count fails closed.
let account_limit_is_reachable ()
  : Lemma (
      let d1 = run_from_observation limited_request [rate_allowed; budget_counted (mk_i64 3)] in
      let d2 = run_from_observation limited_request
        [rate_allowed; RegistrationEvent_BudgetObserved BudgetObservation_QueryFailed] in
      d1.f_failed = true /\ not d1.f_transaction_open /\
      d2.f_failed = true /\ not d2.f_transaction_open) =
  ()

/// A denied limiter performs no SQL and no device insert.
let rate_limit_is_reachable ()
  : Lemma (
      let d = run_from_observation valid_request [rate_denied] in
      d.f_failed = true /\ not d.f_transaction_open /\
      not d.f_account_inserted /\ not d.f_device_inserted) =
  ()

/// Invalid key lengths are refused after the limiter/budget and before any
/// transaction.
let invalid_keys_are_refused ()
  : Lemma (
      let d = run_from_observation invalid_key_request [rate_allowed] in
      d.f_failed = true /\ not d.f_transaction_open /\
      count_complete (begin_registration invalid_key_request).f_driver
        [rate_allowed] = 0) =
  ()

/// A device insert failure is terminal, never commits and never responds, so
/// the handler's dropped transaction rolls the account row back.
let device_insert_failure_rolls_back ()
  : Lemma (
      let events =
        [rate_allowed; transaction_begun; account_inserted;
         RegistrationEvent_DeviceInserted InsertObservation_Failed] in
      let d = run_from_observation valid_request events in
      d.f_failed = true /\ not d.f_committed /\ not d.f_responded /\
      count_complete (begin_registration valid_request).f_driver events = 0) =
  ()

/// A commit failure is not reported as success.
let commit_failure_is_reachable ()
  : Lemma (
      let events =
        [rate_allowed; transaction_begun; account_inserted; device_inserted;
         RegistrationEvent_CommitObserved CommitObservation_Failed] in
      let d = run_from_observation valid_request events in
      d.f_failed = true /\ not d.f_committed /\ not d.f_responded) =
  ()

/// An untracked token is never returned.
let tracking_failure_never_responds ()
  : Lemma (
      let events =
        [rate_allowed; transaction_begun; account_inserted; device_inserted;
         commit_ok; token_issued;
         RegistrationEvent_TrackObserved TrackObservation_Failed] in
      let d = run_from_observation valid_request events in
      d.f_token_issued = true /\ d.f_failed = true /\ not d.f_responded) =
  ()
