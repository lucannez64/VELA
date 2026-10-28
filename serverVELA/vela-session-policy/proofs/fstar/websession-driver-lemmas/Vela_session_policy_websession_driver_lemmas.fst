module Vela_session_policy_websession_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* web-session
/// drivers (`Vela_session_policy.Websession_driver`): browser start, device
/// grant, browser token exchange and session delete.
///
/// Scope: one request of one kind at a time. The four drivers are separate
/// values, exactly as the handlers are separate requests. Concurrent
/// composition over the shared session/challenge store is
/// `Vela_session_policy_websession_driver_composition`.
///
/// The module states, for every event list (not only the handler's intended
/// order):
///
/// - the final state is sound and the last effect agrees with it;
/// - success and failure are each emitted at most once and never together;
/// - start inserts only after validation and never has any other mutating
///   effect;
/// - a grant update is emitted only from a state where the extracted
///   `plan_observed_grant` returned a permit for an authenticated, active
///   device, and carries that permit's mode and epoch plus the checked
///   `Vela_session_policy.clamp_web_ttl` value;
/// - a token issue is emitted only after a consumed `web_token` challenge, a
///   valid signature, a first-writer-wins claim, and from the checks the
///   extracted `plan_observed_web_token` returned a plan for; at most one
///   issue effect per request, carrying exactly that plan;
/// - a delete lockout or revocation record is emitted only for the owning
///   account.
///
/// The drivers' inputs are observations, never verified origins; store/SQL
/// linearizability, the challenge `get_del`, the claim's first-writer-wins
/// semantics, the clock, verification and signing remain outside.

open FStar.Mul
open Core_models
open Vela_session_policy.Websession_driver


// ════════════════════════════════════════════════════════════════════════════
// POST /web-session/start
// ════════════════════════════════════════════════════════════════════════════

let start_is_limit (d: t_StartDriver) : bool =
  match d.f_stage <: t_StartStage with
  | StartStage_Limit -> true
  | _ -> false

let start_is_validate (d: t_StartDriver) : bool =
  match d.f_stage <: t_StartStage with
  | StartStage_Validate -> true
  | _ -> false

let start_is_insert (d: t_StartDriver) : bool =
  match d.f_stage <: t_StartStage with
  | StartStage_Insert -> true
  | _ -> false

let start_is_done (d: t_StartDriver) : bool =
  match d.f_stage <: t_StartStage with
  | StartStage_Done -> true
  | _ -> false

let start_trace_sound (d: t_StartDriver) : bool =
  let limit = not d.f_limited_ok && not d.f_validated && not d.f_inserted &&
              not d.f_responded && not d.f_failed in
  let validate = d.f_limited_ok && not d.f_validated && not d.f_inserted &&
                 not d.f_responded && not d.f_failed in
  let insert = d.f_limited_ok && d.f_validated && not d.f_inserted &&
               not d.f_responded && not d.f_failed in
  let done = (d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
             (not d.f_responded || d.f_inserted) in
  (not (start_is_limit d) || limit) &&
  (not (start_is_validate d) || validate) &&
  (not (start_is_insert d) || insert) &&
  (not (start_is_done d) || done) &&
  (not d.f_validated || d.f_limited_ok) &&
  (not d.f_inserted || d.f_validated) &&
  (not d.f_responded || d.f_inserted) &&
  (not d.f_failed || not d.f_responded)

let start_trace_sound_matches_rust (d: t_StartDriver)
  : Lemma (start_trace_sound d = start_state_is_sound d) =
  match d.f_stage <: t_StartStage with
  | StartStage_Limit -> ()
  | StartStage_Validate -> ()
  | StartStage_Insert -> ()
  | StartStage_Done -> ()

let start_step_sound (d: t_StartDriver) (e: t_StartEvent)
  : Lemma (requires (start_trace_sound d))
          (ensures (start_trace_sound (start_step d e).f_driver)) =
  start_trace_sound_matches_rust d;
  assert (start_state_is_sound d = true);
  start_trace_sound_matches_rust (start_step d e).f_driver

let start_step_effect_sound (d: t_StartDriver) (e: t_StartEvent)
  : Lemma (requires (start_trace_sound d))
          (ensures (start_effect_is_sound (start_step d e).f_driver (start_step d e).f_effect)) =
  start_trace_sound_matches_rust d;
  assert (start_state_is_sound d = true)

let start_step_after_done (d: t_StartDriver) (e: t_StartEvent)
  : Lemma (requires (start_trace_sound d /\ start_is_done d))
          (ensures ((start_step d e).f_driver = d /\
                    (start_step d e).f_effect = StartEffect_Idle)) =
  start_trace_sound_matches_rust d;
  match d.f_stage <: t_StartStage with
  | StartStage_Done -> ()

let rec start_run (d: t_StartDriver) (events: list t_StartEvent)
  : Pure (t_StartDriver) (requires (start_trace_sound d))
    (ensures (fun r -> start_trace_sound r)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      start_step_sound d e;
      start_run (start_step d e).f_driver rest

let start_run_from_begin (events: list t_StartEvent) : t_StartDriver =
  start_run (begin_start ()).f_driver events

let rec start_count_complete (d: t_StartDriver) (events: list t_StartEvent)
  : Pure nat (requires (start_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      start_step_sound d e;
      (match (start_step d e).f_effect <: t_StartEffect with
       | StartEffect_Complete -> 1
       | _ -> 0) + start_count_complete (start_step d e).f_driver rest

let rec start_count_fail (d: t_StartDriver) (events: list t_StartEvent)
  : Pure nat (requires (start_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      start_step_sound d e;
      (match (start_step d e).f_effect <: t_StartEffect with
       | StartEffect_Fail _ -> 1
       | _ -> 0) + start_count_fail (start_step d e).f_driver rest

let rec start_done_suffix_inert (d: t_StartDriver) (events: list t_StartEvent)
  : Lemma (requires (start_trace_sound d /\ start_is_done d))
          (ensures (start_run d events = d /\
                    start_count_complete d events = 0 /\
                    start_count_fail d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      start_step_after_done d e;
      start_done_suffix_inert d rest

let rec start_complete_count_le_one (d: t_StartDriver) (events: list t_StartEvent)
  : Lemma (requires (start_trace_sound d))
          (ensures (start_count_complete d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      start_step_sound d e;
      start_step_effect_sound d e;
      let t = start_step d e in
      if (match t.f_effect <: t_StartEffect with
          | StartEffect_Complete -> true
          | _ -> false)
      then begin
        start_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_responded = true);
        assert (start_is_done t.f_driver = true);
        start_done_suffix_inert t.f_driver rest
      end else start_complete_count_le_one t.f_driver rest

let rec start_fail_count_le_one (d: t_StartDriver) (events: list t_StartEvent)
  : Lemma (requires (start_trace_sound d))
          (ensures (start_count_fail d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      start_step_sound d e;
      start_step_effect_sound d e;
      let t = start_step d e in
      if (match t.f_effect <: t_StartEffect with
          | StartEffect_Fail _ -> true
          | _ -> false)
      then begin
        start_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_failed = true);
        assert (start_is_done t.f_driver = true);
        start_done_suffix_inert t.f_driver rest
      end else start_fail_count_le_one t.f_driver rest

/// Only the pending insert is ever emitted by a start, and only after the
/// limiter and validation succeeded.
let start_trace_theorem (events: list t_StartEvent)
  : Lemma (
      let d = start_run_from_begin events in
      start_trace_sound d /\
      (d.f_inserted ==> (d.f_limited_ok && d.f_validated)) /\
      (d.f_responded ==> (d.f_inserted && d.f_limited_ok && d.f_validated)) /\
      (not (d.f_responded && d.f_failed)) /\
      start_count_complete (begin_start ()).f_driver events <= 1 /\
      start_count_fail (begin_start ()).f_driver events <= 1) =
  start_trace_sound_matches_rust (begin_start ()).f_driver;
  assert (start_trace_sound (begin_start ()).f_driver);
  start_complete_count_le_one (begin_start ()).f_driver events;
  start_fail_count_le_one (begin_start ()).f_driver events

// ════════════════════════════════════════════════════════════════════════════
// POST /web-session/:id/grant
// ════════════════════════════════════════════════════════════════════════════

let grant_is_validate (d: t_GrantDriver) : bool =
  match d.f_stage <: t_GrantStage with
  | GrantStage_Validate -> true
  | _ -> false

let grant_is_observe (d: t_GrantDriver) : bool =
  match d.f_stage <: t_GrantStage with
  | GrantStage_ObserveSession -> true
  | _ -> false

let grant_is_update (d: t_GrantDriver) : bool =
  match d.f_stage <: t_GrantStage with
  | GrantStage_Update -> true
  | _ -> false

let grant_is_done (d: t_GrantDriver) : bool =
  match d.f_stage <: t_GrantStage with
  | GrantStage_Done -> true
  | _ -> false

let grant_trace_sound (d: t_GrantDriver) : bool =
  let validate = d.f_actor_active && not d.f_request_valid && not d.f_session_loaded &&
                 not d.f_plan_authorized && not d.f_updated && not d.f_responded &&
                 not d.f_failed in
  let observe = d.f_actor_active && d.f_request_valid && not d.f_session_loaded &&
                not d.f_plan_authorized && not d.f_updated && not d.f_responded &&
                not d.f_failed in
  let update = d.f_actor_active && d.f_request_valid && d.f_session_loaded &&
               d.f_plan_authorized && not d.f_updated && not d.f_responded &&
               not d.f_failed in
  let done = (d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
             (not d.f_responded ||
              (d.f_actor_active && d.f_request_valid && d.f_session_loaded &&
               d.f_plan_authorized && d.f_updated)) in
  (not (grant_is_validate d) || validate) &&
  (not (grant_is_observe d) || observe) &&
  (not (grant_is_update d) || update) &&
  (not (grant_is_done d) || done) &&
  (not d.f_request_valid || d.f_actor_active) &&
  (not d.f_session_loaded || d.f_request_valid) &&
  (not d.f_plan_authorized || d.f_session_loaded) &&
  (not d.f_updated || d.f_plan_authorized) &&
  (not d.f_responded || d.f_updated) &&
  (not d.f_failed || not d.f_responded) &&
  (not d.f_plan_authorized || d.f_permit_epoch >=. Vela_session_policy.v_INITIAL_EPOCH)

let grant_trace_sound_matches_rust (d: t_GrantDriver)
  : Lemma (grant_trace_sound d = grant_state_is_sound d) =
  match d.f_stage <: t_GrantStage with
  | GrantStage_Validate -> ()
  | GrantStage_ObserveSession -> ()
  | GrantStage_Update -> ()
  | GrantStage_Done -> ()

let grant_step_sound (d: t_GrantDriver) (e: t_GrantEvent)
  : Lemma (requires (grant_trace_sound d))
          (ensures (grant_trace_sound (grant_step d e).f_driver)) =
  grant_trace_sound_matches_rust d;
  assert (grant_state_is_sound d = true);
  grant_trace_sound_matches_rust (grant_step d e).f_driver

let grant_step_effect_sound (d: t_GrantDriver) (e: t_GrantEvent)
  : Lemma (requires (grant_trace_sound d))
          (ensures (grant_effect_is_sound (grant_step d e).f_driver
                                           (grant_step d e).f_effect)) =
  grant_trace_sound_matches_rust d;
  assert (grant_state_is_sound d = true)

let grant_step_after_done (d: t_GrantDriver) (e: t_GrantEvent)
  : Lemma (requires (grant_trace_sound d /\ grant_is_done d))
          (ensures ((grant_step d e).f_driver = d /\
                    (grant_step d e).f_effect = GrantEffect_Idle)) =
  grant_trace_sound_matches_rust d;
  match d.f_stage <: t_GrantStage with
  | GrantStage_Done -> ()

let rec grant_run (d: t_GrantDriver) (events: list t_GrantEvent)
  : Pure t_GrantDriver (requires (grant_trace_sound d))
    (ensures (fun r -> grant_trace_sound r)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      grant_step_sound d e;
      grant_run (grant_step d e).f_driver rest

let grant_run_from_actor (actor: t_GrantActorObservation)
                         (events: list t_GrantEvent) (ttl: Core_models.Option.t_Option i64) : t_GrantDriver =
  grant_run (begin_grant actor ttl).f_driver events

let rec grant_count_complete (d: t_GrantDriver) (events: list t_GrantEvent)
  : Pure nat (requires (grant_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      grant_step_sound d e;
      (match (grant_step d e).f_effect <: t_GrantEffect with
       | GrantEffect_Complete -> 1
       | _ -> 0) + grant_count_complete (grant_step d e).f_driver rest

let rec grant_count_fail (d: t_GrantDriver) (events: list t_GrantEvent)
  : Pure nat (requires (grant_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      grant_step_sound d e;
      (match (grant_step d e).f_effect <: t_GrantEffect with
       | GrantEffect_Fail _ -> 1
       | _ -> 0) + grant_count_fail (grant_step d e).f_driver rest

let rec grant_done_suffix_inert (d: t_GrantDriver) (events: list t_GrantEvent)
  : Lemma (requires (grant_trace_sound d /\ grant_is_done d))
          (ensures (grant_run d events = d /\
                    grant_count_complete d events = 0 /\
                    grant_count_fail d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      grant_step_after_done d e;
      grant_done_suffix_inert d rest

let rec grant_complete_count_le_one (d: t_GrantDriver) (events: list t_GrantEvent)
  : Lemma (requires (grant_trace_sound d))
          (ensures (grant_count_complete d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      grant_step_sound d e;
      grant_step_effect_sound d e;
      let t = grant_step d e in
      if (match t.f_effect <: t_GrantEffect with
          | GrantEffect_Complete -> true
          | _ -> false)
      then begin
        grant_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_responded = true);
        assert (grant_is_done t.f_driver = true);
        grant_done_suffix_inert t.f_driver rest
      end else grant_complete_count_le_one t.f_driver rest

let rec grant_fail_count_le_one (d: t_GrantDriver) (events: list t_GrantEvent)
  : Lemma (requires (grant_trace_sound d))
          (ensures (grant_count_fail d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      grant_step_sound d e;
      grant_step_effect_sound d e;
      let t = grant_step d e in
      if (match t.f_effect <: t_GrantEffect with
          | GrantEffect_Fail _ -> true
          | _ -> false)
      then begin
        grant_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_failed = true);
        assert (grant_is_done t.f_driver = true);
        grant_done_suffix_inert t.f_driver rest
      end else grant_fail_count_le_one t.f_driver rest

/// Every update effect comes from the checked plan, and its mode, epoch and
/// TTL are the permit's and the checked clamp's values.
let grant_trace_theorem (actor: t_GrantActorObservation)
                        (events: list t_GrantEvent) (ttl: Core_models.Option.t_Option i64)
  : Lemma (
      let d = grant_run_from_actor actor events ttl in
      grant_trace_sound d /\
      (d.f_updated ==> (d.f_actor_active && d.f_request_valid && d.f_session_loaded &&
                        d.f_plan_authorized)) /\
      (d.f_responded ==> (d.f_updated && d.f_actor_active && d.f_plan_authorized)) /\
      (not (d.f_responded && d.f_failed)) /\
      grant_count_complete (begin_grant actor ttl).f_driver events <= 1 /\
      grant_count_fail (begin_grant actor ttl).f_driver events <= 1) =
  grant_trace_sound_matches_rust (begin_grant actor ttl).f_driver;
  assert (grant_trace_sound (begin_grant actor ttl).f_driver);
  grant_complete_count_le_one (begin_grant actor ttl).f_driver events;
  grant_fail_count_le_one (begin_grant actor ttl).f_driver events

// ════════════════════════════════════════════════════════════════════════════
// POST /web-session/:id/token
// ════════════════════════════════════════════════════════════════════════════

let token_is_precheck (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Precheck -> true
  | _ -> false

let token_is_observe (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_ObserveSession -> true
  | _ -> false

let token_is_challenge (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Challenge -> true
  | _ -> false

let token_is_verify (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Verify -> true
  | _ -> false

let token_is_record_failure (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_RecordFailure -> true
  | _ -> false

let token_is_reset (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Reset -> true
  | _ -> false

let token_is_claim (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Claim -> true
  | _ -> false

let token_is_issue (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Issue -> true
  | _ -> false

let token_is_done (d: t_TokenDriver) : bool =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Done -> true
  | _ -> false

let token_trace_sound (d: t_TokenDriver) : bool =
  let clean = not d.f_challenge_consumed && not d.f_signature_valid &&
              not d.f_backoff_reset && not d.f_token_claimed &&
              not d.f_plan_authorized &&
              not d.f_token_issued &&
              not d.f_responded && not d.f_failed in
  let precheck = not d.f_limits_allowed && not d.f_session_loaded &&
                 not d.f_session_eligible && clean in
  let observe = d.f_limits_allowed && not d.f_session_loaded &&
                not d.f_session_eligible && clean in
  let challenge = d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible && clean in
  let verify = d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible &&
               d.f_challenge_consumed && not d.f_signature_valid &&
               not d.f_backoff_reset && not d.f_token_claimed &&
               not d.f_plan_authorized &&
                not d.f_token_issued &&
               not d.f_responded && not d.f_failed in
  let record_failure = d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible &&
               d.f_challenge_consumed && not d.f_signature_valid &&
               not d.f_backoff_reset && not d.f_token_claimed &&
               not d.f_plan_authorized &&
                not d.f_token_issued &&
               not d.f_responded && not d.f_failed in
  let reset = d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible &&
              d.f_challenge_consumed && d.f_signature_valid &&
              not d.f_token_claimed && not d.f_plan_authorized &&
              not d.f_token_issued &&
              not d.f_responded && not d.f_failed in
  let claim = d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible &&
              d.f_challenge_consumed && d.f_signature_valid && d.f_backoff_reset &&
              not d.f_token_claimed &&
              not d.f_token_issued &&
              not d.f_responded && not d.f_failed in
  let issue = d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible &&
              d.f_challenge_consumed && d.f_signature_valid && d.f_backoff_reset &&
              d.f_token_claimed && d.f_plan_authorized &&
              not d.f_token_issued &&
              not d.f_responded && not d.f_failed in
  let done = (d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
             (not d.f_responded ||
              (d.f_limits_allowed && d.f_session_loaded && d.f_session_eligible &&
               d.f_challenge_consumed && d.f_signature_valid && d.f_backoff_reset &&
               d.f_token_claimed && d.f_plan_authorized &&
               d.f_token_issued)) in
  (not (token_is_precheck d) || precheck) &&
  (not (token_is_observe d) || observe) &&
  (not (token_is_challenge d) || challenge) &&
  (not (token_is_verify d) || verify) &&
  (not (token_is_record_failure d) || record_failure) &&
  (not (token_is_reset d) || reset) &&
  (not (token_is_claim d) || claim) &&
  (not (token_is_issue d) || issue) &&
  (not (token_is_done d) || done) &&
  (not d.f_session_loaded || d.f_limits_allowed) &&
  (not d.f_session_eligible || d.f_session_loaded) &&
  (not d.f_challenge_consumed || d.f_session_eligible) &&
  (not d.f_signature_valid || d.f_challenge_consumed) &&
  (not d.f_backoff_reset || d.f_signature_valid) &&
  (not d.f_token_claimed || d.f_backoff_reset) &&
  (not d.f_token_issued || d.f_plan_authorized) &&
  (not d.f_responded || d.f_token_issued) &&
  (not d.f_failed || not d.f_responded) &&
  (not d.f_plan_authorized ||
    (d.f_session_eligible && d.f_granted_by_same_account && d.f_nonce_present &&
     d.f_challenge_consumed && d.f_signature_valid &&
     d.f_key_epoch >=. Vela_session_policy.v_INITIAL_EPOCH && d.f_hard_cap >. mk_i64 0))

let token_trace_sound_matches_rust (d: t_TokenDriver)
  : Lemma (token_trace_sound d = token_state_is_sound d) =
  match d.f_stage <: t_TokenStage with
  | TokenStage_Precheck -> ()
  | TokenStage_ObserveSession -> ()
  | TokenStage_Challenge -> ()
  | TokenStage_Verify -> ()
  | TokenStage_RecordFailure -> ()
  | TokenStage_Reset -> ()
  | TokenStage_Claim -> ()
  | TokenStage_Issue -> ()
  | TokenStage_Done -> ()

let token_step_sound (d: t_TokenDriver) (e: t_TokenEvent)
  : Lemma (requires (token_trace_sound d))
          (ensures (token_trace_sound (token_step d e).f_driver)) =
  token_trace_sound_matches_rust d;
  assert (token_state_is_sound d = true);
  token_trace_sound_matches_rust (token_step d e).f_driver

let token_step_effect_sound (d: t_TokenDriver) (e: t_TokenEvent)
  : Lemma (requires (token_trace_sound d))
          (ensures (token_effect_is_sound (token_step d e).f_driver
                                           (token_step d e).f_effect)) =
  token_trace_sound_matches_rust d;
  assert (token_state_is_sound d = true)

let token_step_after_done (d: t_TokenDriver) (e: t_TokenEvent)
  : Lemma (requires (token_trace_sound d /\ token_is_done d))
          (ensures ((token_step d e).f_driver = d /\
                    (token_step d e).f_effect = TokenEffect_Idle)) =
  token_trace_sound_matches_rust d;
  match d.f_stage <: t_TokenStage with
  | TokenStage_Done -> ()

let rec token_run (d: t_TokenDriver) (events: list t_TokenEvent)
  : Pure t_TokenDriver (requires (token_trace_sound d))
    (ensures (fun r -> token_trace_sound r)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      token_step_sound d e;
      token_run (token_step d e).f_driver rest

let token_run_from_begin (events: list t_TokenEvent) : t_TokenDriver =
  token_run (begin_token ()).f_driver events

let rec token_count_complete (d: t_TokenDriver) (events: list t_TokenEvent)
  : Pure nat (requires (token_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      token_step_sound d e;
      (match (token_step d e).f_effect <: t_TokenEffect with
       | TokenEffect_Complete -> 1
       | _ -> 0) + token_count_complete (token_step d e).f_driver rest

let rec token_count_fail (d: t_TokenDriver) (events: list t_TokenEvent)
  : Pure nat (requires (token_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      token_step_sound d e;
      (match (token_step d e).f_effect <: t_TokenEffect with
       | TokenEffect_Fail _ -> 1
       | _ -> 0) + token_count_fail (token_step d e).f_driver rest

/// How many times the driver authorized signing a token. This is the counter
/// the at-most-one-token-per-grant theorem uses; it is driven solely by the
/// extracted driver's effect.
let rec token_count_issue (d: t_TokenDriver) (events: list t_TokenEvent)
  : Pure nat (requires (token_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      token_step_sound d e;
      (match (token_step d e).f_effect <: t_TokenEffect with
       | TokenEffect_IssueToken _ -> 1
       | _ -> 0) + token_count_issue (token_step d e).f_driver rest

let rec token_done_suffix_inert (d: t_TokenDriver) (events: list t_TokenEvent)
  : Lemma (requires (token_trace_sound d /\ token_is_done d))
          (ensures (token_run d events = d /\
                    token_count_complete d events = 0 /\
                    token_count_fail d events = 0 /\
                    token_count_issue d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      token_step_after_done d e;
      token_done_suffix_inert d rest

let rec token_complete_count_le_one (d: t_TokenDriver) (events: list t_TokenEvent)
  : Lemma (requires (token_trace_sound d))
          (ensures (token_count_complete d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      token_step_sound d e;
      token_step_effect_sound d e;
      let t = token_step d e in
      if (match t.f_effect <: t_TokenEffect with
          | TokenEffect_Complete -> true
          | _ -> false)
      then begin
        token_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_responded = true);
        assert (token_is_done t.f_driver = true);
        token_done_suffix_inert t.f_driver rest
      end else token_complete_count_le_one t.f_driver rest

let rec token_fail_count_le_one (d: t_TokenDriver) (events: list t_TokenEvent)
  : Lemma (requires (token_trace_sound d))
          (ensures (token_count_fail d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      token_step_sound d e;
      token_step_effect_sound d e;
      let t = token_step d e in
      if (match t.f_effect <: t_TokenEffect with
          | TokenEffect_Fail _ -> true
          | _ -> false)
      then begin
        token_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_failed = true);
        assert (token_is_done t.f_driver = true);
        token_done_suffix_inert t.f_driver rest
      end else token_fail_count_le_one t.f_driver rest

let issue_step_no_issue (d: t_TokenDriver) (e: t_TokenEvent)
  : Lemma (requires (token_trace_sound d /\ token_is_issue d))
          (ensures (
            (match (token_step d e).f_effect <: t_TokenEffect with
             | TokenEffect_IssueToken _ -> false
             | _ -> true))) =
  token_trace_sound_matches_rust d;
  match d.f_stage <: t_TokenStage with
  | TokenStage_Issue -> ()

let issue_step_is_issue_or_done (d: t_TokenDriver) (e: t_TokenEvent)
  : Lemma (requires (token_trace_sound d /\ token_is_issue d))
          (ensures (token_is_issue (token_step d e).f_driver \/
                    token_is_done (token_step d e).f_driver)) =
  token_trace_sound_matches_rust d;
  match d.f_stage <: t_TokenStage with
  | TokenStage_Issue -> ()

let rec no_issue_from_issue (d: t_TokenDriver) (events: list t_TokenEvent)
  : Lemma (requires (token_trace_sound d /\ token_is_issue d))
          (ensures (token_count_issue d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      token_step_sound d e;
      issue_step_no_issue d e;
      issue_step_is_issue_or_done d e;
      let t = token_step d e in
      if token_is_done t.f_driver
      then token_done_suffix_inert t.f_driver rest
      else no_issue_from_issue t.f_driver rest

let rec token_issue_count_le_one (d: t_TokenDriver) (events: list t_TokenEvent)
  : Lemma (requires (token_trace_sound d))
          (ensures (token_count_issue d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      token_step_sound d e;
      token_step_effect_sound d e;
      let t = token_step d e in
      if (match t.f_effect <: t_TokenEffect with
          | TokenEffect_IssueToken _ -> true
          | _ -> false)
      then begin
        token_trace_sound_matches_rust t.f_driver;
        assert (token_is_issue t.f_driver);
        no_issue_from_issue t.f_driver rest
      end else token_issue_count_le_one t.f_driver rest

/// Every issue carries the exact checked plan and all the facts the exchange
/// policy requires.
let token_trace_theorem (events: list t_TokenEvent)
  : Lemma (
      let d = token_run_from_begin events in
      token_trace_sound d /\
      token_count_complete (begin_token ()).f_driver events <= 1 /\
      token_count_fail (begin_token ()).f_driver events <= 1 /\
      token_count_issue (begin_token ()).f_driver events <= 1) =
  token_trace_sound_matches_rust (begin_token ()).f_driver;
  assert (token_trace_sound (begin_token ()).f_driver);
  token_complete_count_le_one (begin_token ()).f_driver events;
  token_fail_count_le_one (begin_token ()).f_driver events;
  token_issue_count_le_one (begin_token ()).f_driver events

// ════════════════════════════════════════════════════════════════════════════
// DELETE /web-session/:id
// ════════════════════════════════════════════════════════════════════════════

let delete_is_observe (d: t_DeleteDriver) : bool =
  match d.f_stage <: t_DeleteStage with
  | DeleteStage_Observe -> true
  | _ -> false

let delete_is_lockout (d: t_DeleteDriver) : bool =
  match d.f_stage <: t_DeleteStage with
  | DeleteStage_Lockout -> true
  | _ -> false

let delete_is_record (d: t_DeleteDriver) : bool =
  match d.f_stage <: t_DeleteStage with
  | DeleteStage_Record -> true
  | _ -> false

let delete_is_done (d: t_DeleteDriver) : bool =
  match d.f_stage <: t_DeleteStage with
  | DeleteStage_Done -> true
  | _ -> false

let delete_trace_sound (d: t_DeleteDriver) : bool =
  let observe = d.f_actor_active && not d.f_owner_matches && not d.f_locked &&
                not d.f_recorded && not d.f_responded && not d.f_failed in
  let lockout = d.f_actor_active && d.f_owner_matches && not d.f_locked &&
                not d.f_recorded && not d.f_responded && not d.f_failed in
  let record = d.f_actor_active && d.f_owner_matches && d.f_locked &&
               not d.f_recorded && not d.f_responded && not d.f_failed in
  let done = (d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
             (not d.f_responded ||
              (d.f_actor_active && d.f_owner_matches && d.f_locked && d.f_recorded)) in
  (not (delete_is_observe d) || observe) &&
  (not (delete_is_lockout d) || lockout) &&
  (not (delete_is_record d) || record) &&
  (not (delete_is_done d) || done) &&
  (not d.f_owner_matches || d.f_actor_active) &&
  (not d.f_locked || d.f_owner_matches) &&
  (not d.f_recorded || d.f_locked) &&
  (not d.f_responded || d.f_recorded) &&
  (not d.f_failed || not d.f_responded)

let delete_trace_sound_matches_rust (d: t_DeleteDriver)
  : Lemma (delete_trace_sound d = delete_state_is_sound d) =
  match d.f_stage <: t_DeleteStage with
  | DeleteStage_Observe -> ()
  | DeleteStage_Lockout -> ()
  | DeleteStage_Record -> ()
  | DeleteStage_Done -> ()

let delete_step_sound (d: t_DeleteDriver) (e: t_DeleteEvent)
  : Lemma (requires (delete_trace_sound d))
          (ensures (delete_trace_sound (delete_step d e).f_driver)) =
  delete_trace_sound_matches_rust d;
  assert (delete_state_is_sound d = true);
  delete_trace_sound_matches_rust (delete_step d e).f_driver

let delete_step_effect_sound (d: t_DeleteDriver) (e: t_DeleteEvent)
  : Lemma (requires (delete_trace_sound d))
          (ensures (delete_effect_is_sound (delete_step d e).f_driver
                                             (delete_step d e).f_effect)) =
  delete_trace_sound_matches_rust d;
  assert (delete_state_is_sound d = true)

let delete_step_after_done (d: t_DeleteDriver) (e: t_DeleteEvent)
  : Lemma (requires (delete_trace_sound d /\ delete_is_done d))
          (ensures ((delete_step d e).f_driver = d /\
                    (delete_step d e).f_effect = DeleteEffect_Idle)) =
  delete_trace_sound_matches_rust d;
  match d.f_stage <: t_DeleteStage with
  | DeleteStage_Done -> ()

let rec delete_run (d: t_DeleteDriver) (events: list t_DeleteEvent)
  : Pure t_DeleteDriver (requires (delete_trace_sound d))
    (ensures (fun r -> delete_trace_sound r)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      delete_step_sound d e;
      delete_run (delete_step d e).f_driver rest

let delete_run_from_actor (actor: t_DeleteActorObservation)
                          (events: list t_DeleteEvent) : t_DeleteDriver =
  delete_run (begin_delete actor).f_driver events

let rec delete_count_complete (d: t_DeleteDriver) (events: list t_DeleteEvent)
  : Pure nat (requires (delete_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      delete_step_sound d e;
      (match (delete_step d e).f_effect <: t_DeleteEffect with
       | DeleteEffect_Complete -> 1
       | _ -> 0) + delete_count_complete (delete_step d e).f_driver rest

let rec delete_count_fail (d: t_DeleteDriver) (events: list t_DeleteEvent)
  : Pure nat (requires (delete_trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      delete_step_sound d e;
      (match (delete_step d e).f_effect <: t_DeleteEffect with
       | DeleteEffect_Fail _ -> 1
       | _ -> 0) + delete_count_fail (delete_step d e).f_driver rest

let rec delete_done_suffix_inert (d: t_DeleteDriver) (events: list t_DeleteEvent)
  : Lemma (requires (delete_trace_sound d /\ delete_is_done d))
          (ensures (delete_run d events = d /\
                    delete_count_complete d events = 0 /\
                    delete_count_fail d events = 0))
          (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      delete_step_after_done d e;
      delete_done_suffix_inert d rest

let rec delete_complete_count_le_one (d: t_DeleteDriver) (events: list t_DeleteEvent)
  : Lemma (requires (delete_trace_sound d))
          (ensures (delete_count_complete d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      delete_step_sound d e;
      delete_step_effect_sound d e;
      let t = delete_step d e in
      if (match t.f_effect <: t_DeleteEffect with
          | DeleteEffect_Complete -> true
          | _ -> false)
      then begin
        delete_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_responded = true);
        assert (delete_is_done t.f_driver = true);
        delete_done_suffix_inert t.f_driver rest
      end else delete_complete_count_le_one t.f_driver rest

let rec delete_fail_count_le_one (d: t_DeleteDriver) (events: list t_DeleteEvent)
  : Lemma (requires (delete_trace_sound d))
          (ensures (delete_count_fail d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      delete_step_sound d e;
      delete_step_effect_sound d e;
      let t = delete_step d e in
      if (match t.f_effect <: t_DeleteEffect with
          | DeleteEffect_Fail _ -> true
          | _ -> false)
      then begin
        delete_trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_failed = true);
        assert (delete_is_done t.f_driver = true);
        delete_done_suffix_inert t.f_driver rest
      end else delete_fail_count_le_one t.f_driver rest

/// Lockout and revocation-record effects are emitted only for the owning
/// account (and only after the driver observed it).
let delete_trace_theorem (actor: t_DeleteActorObservation) (events: list t_DeleteEvent)
  : Lemma (
      let d = delete_run_from_actor actor events in
      delete_trace_sound d /\
      (d.f_locked ==> (d.f_actor_active && d.f_owner_matches)) /\
      (d.f_recorded ==> (d.f_actor_active && d.f_owner_matches && d.f_locked)) /\
      (d.f_responded ==> (d.f_recorded && d.f_owner_matches)) /\
      (not (d.f_responded && d.f_failed)) /\
      delete_count_complete (begin_delete actor).f_driver events <= 1 /\
      delete_count_fail (begin_delete actor).f_driver events <= 1) =
  delete_trace_sound_matches_rust (begin_delete actor).f_driver;
  assert (delete_trace_sound (begin_delete actor).f_driver);
  delete_complete_count_le_one (begin_delete actor).f_driver events;
  delete_fail_count_le_one (begin_delete actor).f_driver events

// ════════════════════════════════════════════════════════════════════════════
// Reachability witnesses (non-vacuity)
// ════════════════════════════════════════════════════════════════════════════

let start_success_events : list t_StartEvent =
  [ StartEvent_LimitObserved StartLimitObservation_Allowed;
    StartEvent_Validated StartValidationObservation_Valid;
    StartEvent_Inserted StartInsertObservation_Inserted ]

let start_failure_events : list t_StartEvent =
  [ StartEvent_LimitObserved StartLimitObservation_Allowed;
    StartEvent_Validated StartValidationObservation_Invalid ]

let start_success_is_reachable ()
  : Lemma (
      let d = start_run_from_begin start_success_events in
      d.f_inserted && d.f_responded && not d.f_failed /\
      start_count_complete (begin_start ()).f_driver start_success_events = 1) =
  start_trace_theorem start_success_events

let start_failure_is_reachable ()
  : Lemma (
      let d = start_run_from_begin start_failure_events in
      d.f_failed && not d.f_inserted && not d.f_responded /\
      start_count_fail (begin_start ()).f_driver start_failure_events = 1) =
  start_trace_theorem start_failure_events

let active_grant_actor : t_GrantActorObservation =
  { f_authenticated = true; f_device_active = true }

let inactive_grant_actor : t_GrantActorObservation =
  { f_authenticated = true; f_device_active = false }

let pending_grant_observation : Vela_session_policy.t_GrantObservation =
  { f_phase = Vela_session_policy.SessionPhase_Pending;
    f_mode = Vela_session_policy.SessionMode_ReadWrite;
    f_approver_user = Core_models.Option.Option_Some (mk_u128 7);
    f_authenticated_user = mk_u128 7;
    f_nonce_length = mk_usize 32;
    f_nonce_equal = true;
    f_has_web_vk = true;
    f_declared_epoch = mk_i64 2 }

let grant_success_events : list t_GrantEvent =
  [ GrantEvent_Validated GrantValidationObservation_Valid;
    GrantEvent_SessionObserved
      (GrantLookupObservation_Present pending_grant_observation);
    GrantEvent_UpdateObserved GrantUpdateObservation_Updated ]

let grant_refusal_events : list t_GrantEvent =
  [ GrantEvent_Validated GrantValidationObservation_Valid;
    GrantEvent_SessionObserved
      (GrantLookupObservation_Present
        ({ pending_grant_observation with
           f_approver_user = Core_models.Option.Option_Some (mk_u128 8) })) ]

let grant_success_is_reachable ()
  : Lemma (
      let d = grant_run_from_actor active_grant_actor grant_success_events
                (Core_models.Option.Option_Some (mk_i64 60)) in
      d.f_plan_authorized && d.f_updated && d.f_responded && not d.f_failed /\
      grant_count_complete (begin_grant active_grant_actor
        (Core_models.Option.Option_Some (mk_i64 60))).f_driver grant_success_events = 1) =
  grant_trace_theorem active_grant_actor grant_success_events
    (Core_models.Option.Option_Some (mk_i64 60))

let inactive_grant_is_refused (events: list t_GrantEvent) (ttl: Core_models.Option.t_Option i64)
  : Lemma (
      let d = grant_run_from_actor inactive_grant_actor events ttl in
      d.f_failed && not d.f_updated && not d.f_responded /\
      grant_count_complete (begin_grant inactive_grant_actor ttl).f_driver events = 0) =
  grant_trace_sound_matches_rust (begin_grant inactive_grant_actor ttl).f_driver;
  assert (grant_trace_sound (begin_grant inactive_grant_actor ttl).f_driver);
  assert (grant_is_done (begin_grant inactive_grant_actor ttl).f_driver);
  grant_done_suffix_inert (begin_grant inactive_grant_actor ttl).f_driver events;
  grant_trace_theorem inactive_grant_actor events ttl

let token_success_events : list t_TokenEvent =
  [ TokenEvent_LimitsObserved TokenLimitObservation_Allowed;
    TokenEvent_SessionObserved
      (TokenLookupObservation_Present
        ({ f_phase = Vela_session_policy.SessionPhase_Granted;
           f_mode = Vela_session_policy.SessionMode_ReadWrite;
           f_granted_user = Core_models.Option.Option_Some (mk_u128 7);
           f_approver_user = Core_models.Option.Option_Some (mk_u128 7);
           f_nonce_present = true;
           f_web_vk_present = true;
           f_key_epoch = mk_i64 1;
           f_now = mk_i64 100;
           f_expires_at = Core_models.Option.Option_Some (mk_i64 1000) }));
    TokenEvent_ChallengeObserved
      (TokenChallengeObservation_Observed
        Vela_session_policy.Challenge.ChallengeConsumption_Accepted);
    TokenEvent_SignatureObserved TokenSignatureObservation_Valid;
    TokenEvent_ResetObserved
      (TokenResetObservation_Reset { f_now = mk_i64 100 });
    TokenEvent_ClaimObserved TokenClaimObservation_Claimed;
    TokenEvent_Issued TokenIssueObservation_Issued ]

let token_replay_events : list t_TokenEvent =
  [ TokenEvent_LimitsObserved TokenLimitObservation_Allowed;
    TokenEvent_SessionObserved
      (TokenLookupObservation_Present
        ({ f_phase = Vela_session_policy.SessionPhase_Granted;
           f_mode = Vela_session_policy.SessionMode_ReadWrite;
           f_granted_user = Core_models.Option.Option_Some (mk_u128 7);
           f_approver_user = Core_models.Option.Option_Some (mk_u128 7);
           f_nonce_present = true;
           f_web_vk_present = true;
           f_key_epoch = mk_i64 1;
           f_now = mk_i64 100;
           f_expires_at = Core_models.Option.Option_Some (mk_i64 1000) }));
    TokenEvent_ChallengeObserved
      (TokenChallengeObservation_Observed
        Vela_session_policy.Challenge.ChallengeConsumption_Accepted);
    TokenEvent_SignatureObserved TokenSignatureObservation_Valid;
    TokenEvent_ResetObserved
      (TokenResetObservation_Reset { f_now = mk_i64 100 });
    TokenEvent_ClaimObserved TokenClaimObservation_AlreadyClaimed ]

let token_success_trace_is_checked ()
  : Lemma (
      let d = token_run_from_begin token_success_events in
      token_trace_sound d /\
      token_count_issue (begin_token ()).f_driver token_success_events <= 1) =
  token_trace_theorem token_success_events

let token_replay_trace_is_checked ()
  : Lemma (
      let d = token_run_from_begin token_replay_events in
      token_trace_sound d /\
      token_count_issue (begin_token ()).f_driver token_replay_events <= 1) =
  token_trace_theorem token_replay_events

let owner_delete_actor : t_DeleteActorObservation =
  { f_authenticated = true; f_user = mk_u128 7 }

let foreign_delete_actor : t_DeleteActorObservation =
  { f_authenticated = true; f_user = mk_u128 8 }

let owner_session_facts : t_DeleteSessionFacts =
  { f_session_user = Core_models.Option.Option_Some (mk_u128 7);
    f_approver_user = Core_models.Option.Option_None }

let delete_success_events : list t_DeleteEvent =
  [ DeleteEvent_SessionObserved (DeleteLookupObservation_Present owner_session_facts);
    DeleteEvent_SentinelWritten DeleteSentinelObservation_Applied;
    DeleteEvent_RecordObserved DeleteRecordObservation_Updated ]

let delete_refusal_events : list t_DeleteEvent =
  [ DeleteEvent_SessionObserved (DeleteLookupObservation_Present owner_session_facts) ]

let delete_success_is_reachable ()
  : Lemma (
      let d = delete_run_from_actor owner_delete_actor delete_success_events in
      d.f_locked && d.f_recorded && d.f_responded && not d.f_failed /\
      delete_count_complete (begin_delete owner_delete_actor).f_driver delete_success_events = 1) =
  delete_trace_theorem owner_delete_actor delete_success_events

let foreign_delete_refusal_events : list t_DeleteEvent =
  [ DeleteEvent_SessionObserved (DeleteLookupObservation_Present owner_session_facts) ]

let foreign_delete_is_refused ()
  : Lemma (
      let d = delete_run_from_actor foreign_delete_actor foreign_delete_refusal_events in
      d.f_failed && not d.f_locked && not d.f_recorded) =
  delete_trace_theorem foreign_delete_actor foreign_delete_refusal_events

