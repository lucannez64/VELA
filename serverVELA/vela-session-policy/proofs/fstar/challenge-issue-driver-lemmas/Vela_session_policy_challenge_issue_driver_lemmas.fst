module Vela_session_policy_challenge_issue_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted*
/// `GET /auth/challenge` issue driver
/// (`Vela_session_policy.Challenge_issue_driver`).
///
/// Scope: one `IssueDriver` value, i.e. one HTTP request. The theorem does not
/// claim anything about concurrent issues; the shared-key consequences are in
/// `Vela_session_policy_challenge_issue_composition`. The sled write, the OS
/// random call, the limiter and the TTL remain effectful glue outside this
/// module. The driver's observations are never verified origins: `Inserted`
/// means `Store::set_ex_nx` reported that the key was absent, not that sled is
/// linearizable.
///
/// Headline facts, for every purpose observation and every event list:
///
/// - at most one `Issue`, at most one `Fail`, at most one `StoreNonce` and at
///   most one `GenerateNonce` effect;
/// - a `StoreNonce` effect only names a parsed purpose, only follows an
///   allowed limiter and a 32-byte random read, and is never emitted after a
///   failure;
/// - `Issue` implies `stored_fresh`, so the issued key was absent when this
///   request wrote it, and no effect follows `Issue` or `Fail`.
///
/// No proof escape or solver laxity is used. `trace_sound` is restated
/// independently and proved equal to `issue_state_is_sound`; all trace lemmas
/// then quantify over every event list.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Challenge_issue_driver

// ── Stage predicates ────────────────────────────────────────────────────────

let is_rate_limit (d: t_IssueDriver) : bool =
  match d.f_stage <: t_IssueStage with
  | IssueStage_RateLimit -> true
  | _ -> false

let is_generate_nonce (d: t_IssueDriver) : bool =
  match d.f_stage <: t_IssueStage with
  | IssueStage_GenerateNonce -> true
  | _ -> false

let is_store_nonce (d: t_IssueDriver) : bool =
  match d.f_stage <: t_IssueStage with
  | IssueStage_StoreNonce -> true
  | _ -> false

let is_done (d: t_IssueDriver) : bool =
  match d.f_stage <: t_IssueStage with
  | IssueStage_Done -> true
  | _ -> false

/// Strengthened trace invariant: the same predicate as the Rust postcondition,
/// with the stage/flag discipline spelled out.
let trace_sound (d: t_IssueDriver) : bool =
  let rate = is_rate_limit d && d.f_purpose_valid && not d.f_rate_allowed &&
             not d.f_nonce_valid &&
             not d.f_stored_fresh && not d.f_issued && not d.f_failed in
  let generate = is_generate_nonce d && d.f_purpose_valid && d.f_rate_allowed &&
                 not d.f_nonce_valid &&
                 not d.f_stored_fresh && not d.f_issued && not d.f_failed in
  let store = is_store_nonce d && d.f_purpose_valid && d.f_rate_allowed &&
              d.f_nonce_valid && not d.f_stored_fresh && not d.f_issued &&
              not d.f_failed in
  let done = is_done d && (d.f_issued || d.f_failed) &&
             not (d.f_issued && d.f_failed) &&
             (not d.f_issued ||
                (d.f_purpose_valid && d.f_rate_allowed && d.f_nonce_valid &&
                 d.f_stored_fresh)) in
  (match d.f_stage <: t_IssueStage with
   | IssueStage_RateLimit -> rate
   | IssueStage_GenerateNonce -> generate
   | IssueStage_StoreNonce -> store
   | IssueStage_Done -> done) &&
  (not d.f_nonce_valid || d.f_rate_allowed) &&
  (not d.f_stored_fresh || (d.f_rate_allowed && d.f_nonce_valid)) &&
  (not d.f_issued || (d.f_stored_fresh && d.f_purpose_valid)) &&
  (not d.f_stored_fresh || d.f_purpose_valid)

let trace_sound_matches_rust (d: t_IssueDriver)
  : Lemma (trace_sound d = issue_state_is_sound d) =
  match d.f_stage <: t_IssueStage with
  | IssueStage_RateLimit -> ()
  | IssueStage_GenerateNonce -> ()
  | IssueStage_StoreNonce -> ()
  | IssueStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_sound (purpose: t_PurposeObservation)
  : Lemma (trace_sound (begin_issue purpose).f_driver) =
  trace_sound_matches_rust (begin_issue purpose).f_driver

let step_sound (d: t_IssueDriver) (e: t_IssueEvent)
  : Lemma (requires (trace_sound d))
          (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (issue_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

let step_effect_sound (d: t_IssueDriver) (e: t_IssueEvent)
  : Lemma (requires (trace_sound d))
          (ensures (issue_effect_is_sound (step d e).f_driver (step d e).f_effect)) =
  trace_sound_matches_rust d;
  assert (issue_state_is_sound d = true)

/// The driver never changes the purpose parsed at the start of the request.
let step_keeps_purpose (d: t_IssueDriver) (e: t_IssueEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_driver.f_purpose = d.f_purpose)) =
  trace_sound_matches_rust d;
  assert (issue_state_is_sound d = true)

/// A finished driver is inert for every event.
let step_after_done (d: t_IssueDriver) (e: t_IssueEvent)
  : Lemma (requires (trace_sound d /\ is_done d))
          (ensures ((step d e).f_driver = d /\
                    (step d e).f_effect = IssueEffect_Idle)) =
  trace_sound_matches_rust d;
  match d.f_stage <: t_IssueStage with
  | IssueStage_Done ->
      (match e <: t_IssueEvent with
       | IssueEvent_RateLimitObserved _ -> ()
       | IssueEvent_NonceObserved _ -> ()
       | IssueEvent_StoreObserved _ -> ())
  | _ -> ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_IssueDriver) (events: list t_IssueEvent)
  : Pure t_IssueDriver (requires (trace_sound d)) (ensures (fun r -> trace_sound r))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let rec last_effect (d: t_IssueDriver) (events: list t_IssueEvent)
  : Pure t_IssueEffect (requires (trace_sound d)) (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> IssueEffect_Idle
  | e :: [] -> (step d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step d e).f_driver rest

let run_from_purpose (purpose: t_PurposeObservation) (events: list t_IssueEvent)
  : Pure t_IssueDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_sound purpose;
  trace_sound_matches_rust (begin_issue purpose).f_driver;
  run (begin_issue purpose).f_driver events

let last_effect_from_purpose (purpose: t_PurposeObservation) (events: list t_IssueEvent)
  : Pure t_IssueEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound purpose;
  trace_sound_matches_rust (begin_issue purpose).f_driver;
  last_effect (begin_issue purpose).f_driver events

// ── Effect counts ───────────────────────────────────────────────────────────

let b2n (b: bool) : nat = if b then 1 else 0

let is_issue_effect (e: t_IssueEffect) : bool =
  match e <: t_IssueEffect with
  | IssueEffect_Issue -> true
  | _ -> false

let is_fail_effect (e: t_IssueEffect) : bool =
  match e <: t_IssueEffect with
  | IssueEffect_Fail _ -> true
  | _ -> false

let is_store_effect (e: t_IssueEffect) : bool =
  match e <: t_IssueEffect with
  | IssueEffect_StoreNonce -> true
  | _ -> false

let is_nonce_effect (e: t_IssueEffect) : bool =
  match e <: t_IssueEffect with
  | IssueEffect_GenerateNonce -> true
  | _ -> false

/// A store effect only follows an allowed limiter, a valid nonce and a parsed
/// purpose: this is the per-step ordering fact the composition relies on.
let store_effect_requires_nonce (d: t_IssueDriver) (e: t_IssueEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_effect = IssueEffect_StoreNonce ==>
                    (let t = (step d e).f_driver in
                     t.f_rate_allowed && t.f_nonce_valid && t.f_purpose_valid))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

/// `Issue` is the response authorization, so the driver that emits it has a
/// fresh stored key and a parsed purpose.
let issue_effect_requires_fresh_store (d: t_IssueDriver) (e: t_IssueEvent)
  : Lemma (requires (trace_sound d))
          (ensures ((step d e).f_effect = IssueEffect_Issue ==>
                    (let t = (step d e).f_driver in
                     t.f_stored_fresh && t.f_purpose_valid && t.f_issued))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

let rec count_issue (d: t_IssueDriver) (events: list t_IssueEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n (is_issue_effect (step d e).f_effect) + count_issue (step d e).f_driver rest

let rec count_fail (d: t_IssueDriver) (events: list t_IssueEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n (is_fail_effect (step d e).f_effect) + count_fail (step d e).f_driver rest

let rec count_store (d: t_IssueDriver) (events: list t_IssueEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n (is_store_effect (step d e).f_effect) + count_store (step d e).f_driver rest

let rec count_nonce (d: t_IssueDriver) (events: list t_IssueEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n (is_nonce_effect (step d e).f_effect) + count_nonce (step d e).f_driver rest

let rec done_suffix_inert (d: t_IssueDriver) (events: list t_IssueEvent)
  : Lemma (requires (trace_sound d /\ is_done d))
          (ensures (run d events = d /\
                    last_effect d events = IssueEffect_Idle /\
                    count_issue d events = 0 /\
                    count_fail d events = 0 /\
                    count_store d events = 0 /\
                    count_nonce d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

let rec issue_count_le_one (d: t_IssueDriver) (events: list t_IssueEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_issue d events <= 1))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_issue_effect t.f_effect
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (is_done t.f_driver = true);
        done_suffix_inert t.f_driver rest
      end else issue_count_le_one t.f_driver rest

let rec fail_count_le_one (d: t_IssueDriver) (events: list t_IssueEvent)
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

/// The extracted stage index, as a natural number.
let drv_rank (d: t_IssueDriver) : nat = v (issue_stage_index d)

/// No store effect can be emitted once the driver has reached the store stage
/// (or later): a store effect names the *previous* stage, which is the nonce
/// stage, and a step never moves the stage backwards.
let rec no_store_from_store_stage (d: t_IssueDriver) (events: list t_IssueEvent)
  : Lemma (requires (trace_sound d /\ drv_rank d >= 2))
          (ensures (count_store d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_store_effect t.f_effect
      then begin
        trace_sound_matches_rust d;
        assert (is_generate_nonce d = true);
        assert false
      end else begin
        assert (drv_rank t.f_driver >= drv_rank d);
        no_store_from_store_stage t.f_driver rest
      end

/// No nonce effect can be emitted once the driver has reached the nonce stage
/// (or later): a nonce effect names the rate-limit stage.
let rec no_nonce_from_nonce_stage (d: t_IssueDriver) (events: list t_IssueEvent)
  : Lemma (requires (trace_sound d /\ drv_rank d >= 1))
          (ensures (count_nonce d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_nonce_effect t.f_effect
      then begin
        trace_sound_matches_rust d;
        assert (is_rate_limit d = true);
        assert false
      end else begin
        assert (drv_rank t.f_driver >= drv_rank d);
        no_nonce_from_nonce_stage t.f_driver rest
      end

let rec store_count_le_one (d: t_IssueDriver) (events: list t_IssueEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_store d events <= 1))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_store_effect t.f_effect
      then begin
        trace_sound_matches_rust t.f_driver;
        step_effect_sound d e;
        assert (is_store_nonce t.f_driver = true);
        assert (drv_rank t.f_driver >= 2);
        no_store_from_store_stage t.f_driver rest
      end else store_count_le_one t.f_driver rest

let rec nonce_count_le_one (d: t_IssueDriver) (events: list t_IssueEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_nonce d events <= 1))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_nonce_effect t.f_effect
      then begin
        trace_sound_matches_rust t.f_driver;
        step_effect_sound d e;
        assert (is_generate_nonce t.f_driver = true);
        assert (drv_rank t.f_driver >= 1);
        no_nonce_from_nonce_stage t.f_driver rest
      end else nonce_count_le_one t.f_driver rest

/// Success and failure never both occur.
let rec success_and_failure_exclusive (d: t_IssueDriver) (events: list t_IssueEvent)
  : Lemma (requires (trace_sound d))
          (ensures (count_issue d events = 0 \/ count_fail d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if is_issue_effect t.f_effect || is_fail_effect t.f_effect
      then begin
        trace_sound_matches_rust t.f_driver;
        done_suffix_inert t.f_driver rest
      end else success_and_failure_exclusive t.f_driver rest

// ── Headline per-request theorem ────────────────────────────────────────────

let issue_trace_theorem (purpose: t_PurposeObservation) (events: list t_IssueEvent)
  : Lemma (
      let d = run_from_purpose purpose events in
      trace_sound d /\
      (d.f_issued ==> (d.f_purpose_valid && d.f_rate_allowed && d.f_nonce_valid && d.f_stored_fresh)) /\
      (d.f_stored_fresh ==> d.f_purpose_valid) /\
      not (d.f_issued && d.f_failed) /\
      count_issue (begin_issue purpose).f_driver events <= 1 /\
      count_fail (begin_issue purpose).f_driver events <= 1 /\
      count_store (begin_issue purpose).f_driver events <= 1 /\
      count_nonce (begin_issue purpose).f_driver events <= 1 /\
      (count_store (begin_issue purpose).f_driver events = 1 ==>
        (begin_issue purpose).f_driver.f_purpose_valid)) =
  begin_sound purpose;
  trace_sound_matches_rust (begin_issue purpose).f_driver;
  issue_count_le_one (begin_issue purpose).f_driver events;
  fail_count_le_one (begin_issue purpose).f_driver events;
  store_count_le_one (begin_issue purpose).f_driver events;
  nonce_count_le_one (begin_issue purpose).f_driver events;
  (match purpose <: t_PurposeObservation with
   | PurposeObservation_Invalid ->
       let b = begin_issue purpose in
       trace_sound_matches_rust b.f_driver;
       assert (is_done b.f_driver = true);
       done_suffix_inert b.f_driver events;
       assert (count_store b.f_driver events = 0)
   | PurposeObservation_Requested p ->
       assert ((begin_issue purpose).f_driver.f_purpose_valid = true));
  let d = run_from_purpose purpose events in
  assert (trace_sound d);
  assert (d.f_issued ==> (d.f_purpose_valid && d.f_rate_allowed && d.f_nonce_valid && d.f_stored_fresh));
  assert (d.f_stored_fresh ==> d.f_purpose_valid);
  assert (not (d.f_issued && d.f_failed));
  assert (count_issue (begin_issue purpose).f_driver events <= 1);
  assert (count_fail (begin_issue purpose).f_driver events <= 1);
  assert (count_store (begin_issue purpose).f_driver events <= 1);
  assert (count_nonce (begin_issue purpose).f_driver events <= 1);
  assert (count_store (begin_issue purpose).f_driver events = 1 ==>
          (begin_issue purpose).f_driver.f_purpose_valid)

// ── Reachability witnesses ─────────────────────────────────────────────────

let login_request : t_PurposeObservation =
  PurposeObservation_Requested ChallengePurpose_Login

let enroll_request : t_PurposeObservation =
  PurposeObservation_Requested ChallengePurpose_Enroll

let thirty_two : usize = mk_usize 32

let nonce_ok : t_IssueEvent =
  IssueEvent_NonceObserved (NonceObservation_Generated { f_len = thirty_two })

let store_ok : t_IssueEvent = IssueEvent_StoreObserved StoreObservation_Inserted

let witness_1 = begin_issue enroll_request

let witness_2 = step witness_1.f_driver
  (IssueEvent_RateLimitObserved RateLimitObservation_Allowed)

let witness_3 = step witness_2.f_driver nonce_ok

let witness_4 = step witness_3.f_driver store_ok

/// The success path stores exactly once, for the requested purpose, and then
/// issues a response.
let success_path_is_reachable ()
  : Lemma (witness_2.f_effect = IssueEffect_GenerateNonce /\
           witness_3.f_effect = IssueEffect_StoreNonce /\
           witness_3.f_driver.f_purpose = ChallengePurpose_Enroll /\
           witness_4.f_effect = IssueEffect_Issue /\
           witness_4.f_driver.f_issued = true /\
           witness_4.f_driver.f_stored_fresh = true /\
           witness_4.f_driver.f_purpose = ChallengePurpose_Enroll /\
           witness_4.f_driver.f_purpose_valid = true) =
  ()

/// An unparseable purpose fails before the limiter.
let invalid_purpose_is_reachable ()
  : Lemma (
      let t = begin_issue PurposeObservation_Invalid in
      t.f_effect = IssueEffect_Fail IssueFailure_InvalidPurpose /\
      t.f_driver.f_failed = true /\ t.f_driver.f_stage = IssueStage_Done) =
  ()

/// A denied limiter fails with no random or store effect.
let denied_is_reachable ()
  : Lemma (
      let t = step witness_1.f_driver
        (IssueEvent_RateLimitObserved RateLimitObservation_Denied) in
      t.f_effect = IssueEffect_Fail IssueFailure_RateLimited /\
      not t.f_driver.f_nonce_valid /\ not t.f_driver.f_stored_fresh) =
  ()

/// A short random read fails before the store.
let short_nonce_is_reachable ()
  : Lemma (
      let t = step witness_2.f_driver
        (IssueEvent_NonceObserved (NonceObservation_Generated { f_len = mk_usize 31 })) in
      t.f_effect = IssueEffect_Fail IssueFailure_NonceLength /\
      not t.f_driver.f_stored_fresh) =
  ()

/// A collision fails and never claims freshness or an issue: the existing
/// challenge was not overwritten.
let collision_is_reachable ()
  : Lemma (
      let t = step witness_3.f_driver
        (IssueEvent_StoreObserved StoreObservation_KeyExists) in
      t.f_effect = IssueEffect_Fail IssueFailure_Collision /\
      not t.f_driver.f_stored_fresh /\ not t.f_driver.f_issued) =
  ()

/// A storage failure is terminal and issues nothing.
let storage_failure_is_reachable ()
  : Lemma (
      let t = step witness_3.f_driver
        (IssueEvent_StoreObserved StoreObservation_Failed) in
      t.f_effect = IssueEffect_Fail IssueFailure_Storage /\
      not t.f_driver.f_issued) =
  ()

/// Once issued, every later event is idle, so one request cannot store twice.
let issued_is_terminal ()
  : Lemma (
      let w = run_from_purpose enroll_request [IssueEvent_RateLimitObserved
        RateLimitObservation_Allowed; nonce_ok; store_ok] in
      w.f_issued = true /\
      count_store (begin_issue enroll_request).f_driver
        [IssueEvent_RateLimitObserved RateLimitObservation_Allowed; nonce_ok; store_ok] = 1 /\
      count_issue (begin_issue enroll_request).f_driver
        [IssueEvent_RateLimitObserved RateLimitObservation_Allowed; nonce_ok; store_ok] = 1) =
  ()
