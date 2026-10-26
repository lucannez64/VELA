module Vela_recovery_policy_webauthn_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* WebAuthn
/// recovery drivers (`Vela_recovery_policy.Webauthn_driver`).
///
/// Scope: one `RegistrationStartDriver`, `RegistrationDriver`,
/// `AuthStartDriver` or `AuthFinishDriver` value, i.e. one HTTP request. The
/// theorem does not compose concurrent requests sharing one attempt state; that
/// is `webauthn-driver-composition`. The SQL row queries, the credential/JSON
/// decodes, the WebAuthn ceremony verification, the atomic `get_del`/`set_ex*`
/// calls, the conditional credential update, the single-use grant store and the
/// rate-limit counters remain effectful glue outside this module. Their inputs
/// are observations, never verified origins.
///
/// No proof escape or solver laxity is used. Every invariant below is restated
/// independently of its Rust predicate and proved equal to it; all trace
/// lemmas then quantify over every event list.
///
/// The WebAuthn path genuinely releases Share 2, so — unlike the possession
/// path — the effect language has exactly one share-releasing effect,
/// `ReleaseGrant`. The lemmas prove that only the checked `plan_recovery`
/// decision can produce it and that every other effect is share-free.

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Webauthn_driver

// ══════════════════════════════════════════════════════════════════════════
// Registration start
// ══════════════════════════════════════════════════════════════════════════

let is_rs_observe (d: t_RegistrationStartDriver) : bool =
  match d.f_stage <: t_RegistrationStartStage with
  | RegistrationStartStage_Observe -> true
  | _ -> false

let is_rs_ceremony (d: t_RegistrationStartDriver) : bool =
  match d.f_stage <: t_RegistrationStartStage with
  | RegistrationStartStage_Ceremony -> true
  | _ -> false

let is_rs_store (d: t_RegistrationStartDriver) : bool =
  match d.f_stage <: t_RegistrationStartStage with
  | RegistrationStartStage_Store -> true
  | _ -> false

let is_rs_done (d: t_RegistrationStartDriver) : bool =
  match d.f_stage <: t_RegistrationStartStage with
  | RegistrationStartStage_Done -> true
  | _ -> false

let rs_trace_sound (d: t_RegistrationStartDriver) : bool =
  (not (is_rs_observe d) || (not d.f_authorized && not d.f_stored)) &&
  (not (is_rs_ceremony d) || (d.f_authorized && not d.f_stored)) &&
  (not (is_rs_store d) || (d.f_authorized && not d.f_stored)) &&
  (not d.f_stored || d.f_authorized) &&
  (not d.f_stored || is_rs_done d)

let rs_trace_sound_matches_rust (d: t_RegistrationStartDriver)
  : Lemma (rs_trace_sound d = registration_start_state_is_sound d) =
  match d.f_stage <: t_RegistrationStartStage with
  | RegistrationStartStage_Observe -> ()
  | RegistrationStartStage_Ceremony -> ()
  | RegistrationStartStage_Store -> ()
  | RegistrationStartStage_Done -> ()

let rs_begin_sound ()
  : Lemma (rs_trace_sound (begin_registration_start ()).f_driver) =
  rs_trace_sound_matches_rust (begin_registration_start ()).f_driver

let rs_step_sound (d: t_RegistrationStartDriver) (e: t_RegistrationStartEvent)
  : Lemma
    (requires (rs_trace_sound d))
    (ensures (rs_trace_sound (step_registration_start d e).f_driver)) =
  rs_trace_sound_matches_rust d;
  assert (registration_start_state_is_sound d = true);
  rs_trace_sound_matches_rust (step_registration_start d e).f_driver

let rec run_registration_start (d: t_RegistrationStartDriver)
                               (events: list t_RegistrationStartEvent)
  : Pure t_RegistrationStartDriver
    (requires (rs_trace_sound d))
    (ensures (fun result -> rs_trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      rs_step_sound d e;
      run_registration_start (step_registration_start d e).f_driver rest

let rec count_registration_ceremonies (d: t_RegistrationStartDriver)
                                      (events: list t_RegistrationStartEvent)
  : Pure nat
    (requires (rs_trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      rs_step_sound d e;
      (match (step_registration_start d e).f_effect <: t_RegistrationStartEffect with
       | RegistrationStartEffect_StartCeremony -> 1
       | _ -> 0) +
      count_registration_ceremonies (step_registration_start d e).f_driver rest

let rec count_registration_start_stores (d: t_RegistrationStartDriver)
                                        (events: list t_RegistrationStartEvent)
  : Pure nat
    (requires (rs_trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      rs_step_sound d e;
      (match (step_registration_start d e).f_effect <: t_RegistrationStartEffect with
       | RegistrationStartEffect_StoreState -> 1
       | _ -> 0) +
      count_registration_start_stores (step_registration_start d e).f_driver rest

let run_registration_start_from_begin (events: list t_RegistrationStartEvent)
  : Pure t_RegistrationStartDriver
    (requires True)
    (ensures (fun result -> rs_trace_sound result))
    (decreases events) =
  rs_begin_sound ();
  run_registration_start (begin_registration_start ()).f_driver events

let count_registration_ceremonies_from_begin (events: list t_RegistrationStartEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  rs_begin_sound ();
  count_registration_ceremonies (begin_registration_start ()).f_driver events

let count_registration_start_stores_from_begin (events: list t_RegistrationStartEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  rs_begin_sound ();
  count_registration_start_stores (begin_registration_start ()).f_driver events

/// A ceremony is only requested after the credential observation authorized it.
let registration_start_ceremony_requires_authority
      (d: t_RegistrationStartDriver) (e: t_RegistrationStartEvent)
  : Lemma
    (requires (rs_trace_sound d))
    (ensures (
      match (step_registration_start d e).f_effect <: t_RegistrationStartEffect with
      | RegistrationStartEffect_StartCeremony ->
          (step_registration_start d e).f_driver.f_authorized /\
          not (step_registration_start d e).f_driver.f_stored
      | _ -> True)) =
  rs_trace_sound_matches_rust d;
  assert (registration_start_state_is_sound d = true);
  ()

/// Once the driver has left `Observe`, no later event can start another
/// ceremony; once it has left `Store`, no later event can write another state.
let rec no_ceremony_from_ceremony (d: t_RegistrationStartDriver)
                                  (events: list t_RegistrationStartEvent)
  : Lemma
    (requires (rs_trace_sound d /\ (is_rs_ceremony d || is_rs_store d || is_rs_done d)))
    (ensures (count_registration_ceremonies d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      rs_step_sound d e;
      no_ceremony_from_ceremony (step_registration_start d e).f_driver rest

let rec no_store_from_store (d: t_RegistrationStartDriver)
                            (events: list t_RegistrationStartEvent)
  : Lemma
    (requires (rs_trace_sound d /\ (is_rs_store d || is_rs_done d)))
    (ensures (count_registration_start_stores d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      rs_step_sound d e;
      no_store_from_store (step_registration_start d e).f_driver rest

let rec registration_start_ceremony_count_le_one
      (d: t_RegistrationStartDriver) (events: list t_RegistrationStartEvent)
  : Lemma
    (requires (rs_trace_sound d))
    (ensures (count_registration_ceremonies d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      rs_trace_sound_matches_rust d;
      rs_step_sound d e;
      let t = step_registration_start d e in
      if (match t.f_effect <: t_RegistrationStartEffect with
          | RegistrationStartEffect_StartCeremony -> true
          | _ -> false)
      then begin
        assert (is_rs_ceremony t.f_driver = true);
        no_ceremony_from_ceremony t.f_driver rest
      end else begin
        registration_start_ceremony_count_le_one t.f_driver rest
      end

let rec registration_start_store_count_le_one
      (d: t_RegistrationStartDriver) (events: list t_RegistrationStartEvent)
  : Lemma
    (requires (rs_trace_sound d))
    (ensures (count_registration_start_stores d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      rs_trace_sound_matches_rust d;
      rs_step_sound d e;
      let t = step_registration_start d e in
      if (match t.f_effect <: t_RegistrationStartEffect with
          | RegistrationStartEffect_StoreState -> true
          | _ -> false)
      then begin
        assert (is_rs_store t.f_driver = true);
        no_store_from_store t.f_driver rest
      end else begin
        registration_start_store_count_le_one t.f_driver rest
      end

let registration_start_trace_theorem (events: list t_RegistrationStartEvent)
  : Lemma (
      let d = run_registration_start_from_begin events in
      rs_trace_sound d /\
      count_registration_ceremonies_from_begin events <= 1 /\
      count_registration_start_stores_from_begin events <= 1 /\
      (d.f_stored ==> (is_rs_done d /\ d.f_authorized))) =
  rs_begin_sound ();
  registration_start_ceremony_count_le_one (begin_registration_start ()).f_driver events;
  registration_start_store_count_le_one (begin_registration_start ()).f_driver events;
  ()

// ══════════════════════════════════════════════════════════════════════════
// Registration finish
// ══════════════════════════════════════════════════════════════════════════

let is_reg_attempt (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Attempt -> true
  | _ -> false

let is_reg_consume (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Consume -> true
  | _ -> false

let is_reg_verify (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Verify -> true
  | _ -> false

let is_reg_uniqueness (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Uniqueness -> true
  | _ -> false

let is_reg_persist (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Persist -> true
  | _ -> false

let is_reg_done (d: t_RegistrationDriver) : bool =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Done -> true
  | _ -> false

let reg_trace_sound (d: t_RegistrationDriver) : bool =
  let attempt_clean =
    not d.f_budget_counted && not d.f_state_consumed &&
    not d.f_credential_valid && not d.f_credential_unique &&
    not d.f_permit_issued && not d.f_credential_stored in
  let consume_clean =
    d.f_budget_counted && not d.f_state_consumed &&
    not d.f_credential_valid && not d.f_credential_unique &&
    not d.f_permit_issued && not d.f_credential_stored in
  let verify_clean =
    d.f_budget_counted && d.f_state_consumed &&
    not d.f_credential_valid && not d.f_credential_unique &&
    not d.f_permit_issued && not d.f_credential_stored in
  let uniqueness_clean =
    d.f_budget_counted && d.f_state_consumed &&
    d.f_credential_valid && not d.f_credential_unique &&
    not d.f_permit_issued && not d.f_credential_stored in
  let persist_clean =
    d.f_budget_counted && d.f_state_consumed &&
    d.f_credential_valid && d.f_credential_unique &&
    d.f_permit_issued && not d.f_credential_stored in
  (not (is_reg_attempt d) || attempt_clean) &&
  (not (is_reg_consume d) || consume_clean) &&
  (not (is_reg_verify d) || verify_clean) &&
  (not (is_reg_uniqueness d) || uniqueness_clean) &&
  (not (is_reg_persist d) || persist_clean) &&
  (not d.f_state_consumed || d.f_budget_counted) &&
  (not d.f_credential_valid || d.f_state_consumed) &&
  (not d.f_credential_unique || d.f_credential_valid) &&
  (not d.f_permit_issued || (d.f_credential_valid && d.f_credential_unique)) &&
  (not d.f_credential_stored || (d.f_permit_issued && is_reg_done d))

let reg_trace_sound_matches_rust (d: t_RegistrationDriver)
  : Lemma (reg_trace_sound d = registration_state_is_sound d) =
  match d.f_stage <: t_RegistrationStage with
  | RegistrationStage_Attempt -> ()
  | RegistrationStage_Consume -> ()
  | RegistrationStage_Verify -> ()
  | RegistrationStage_Uniqueness -> ()
  | RegistrationStage_Persist -> ()
  | RegistrationStage_Done -> ()

let reg_begin_sound ()
  : Lemma (reg_trace_sound (begin_registration ()).f_driver) =
  reg_trace_sound_matches_rust (begin_registration ()).f_driver

let reg_step_sound (d: t_RegistrationDriver) (e: t_RegistrationEvent)
  : Lemma
    (requires (reg_trace_sound d))
    (ensures (reg_trace_sound (step_registration d e).f_driver)) =
  reg_trace_sound_matches_rust d;
  assert (registration_state_is_sound d = true);
  reg_trace_sound_matches_rust (step_registration d e).f_driver

let rec run_registration (d: t_RegistrationDriver) (events: list t_RegistrationEvent)
  : Pure t_RegistrationDriver
    (requires (reg_trace_sound d))
    (ensures (fun result -> reg_trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      reg_step_sound d e;
      run_registration (step_registration d e).f_driver rest

let rec count_registration_persists (d: t_RegistrationDriver)
                                    (events: list t_RegistrationEvent)
  : Pure nat
    (requires (reg_trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      reg_step_sound d e;
      (match (step_registration d e).f_effect <: t_RegistrationEffect with
       | RegistrationEffect_PersistCredential -> 1
       | _ -> 0) +
      count_registration_persists (step_registration d e).f_driver rest

let run_registration_from_begin (events: list t_RegistrationEvent)
  : Pure t_RegistrationDriver
    (requires True)
    (ensures (fun result -> reg_trace_sound result))
    (decreases events) =
  reg_begin_sound ();
  run_registration (begin_registration ()).f_driver events

let count_registration_persists_from_begin (events: list t_RegistrationEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  reg_begin_sound ();
  count_registration_persists (begin_registration ()).f_driver events

/// The checked registration policy is the authority: a `PersistCredential`
/// effect is only emitted after `plan_registration` returned `Register`.
let registration_persist_requires_policy (d: t_RegistrationDriver) (e: t_RegistrationEvent)
  : Lemma
    (requires (reg_trace_sound d))
    (ensures (
      match (step_registration d e).f_effect <: t_RegistrationEffect with
      | RegistrationEffect_PersistCredential ->
          (match e <: t_RegistrationEvent with
           | RegistrationEvent_CredentialLookedUp CredentialUniquenessObservation_Unique ->
               registration_is_authorized
                 ({ f_device_scope = true;
                    f_account_matches = true;
                    f_challenge_pending = d.f_state_consumed;
                    f_challenge_consumed = d.f_state_consumed;
                    f_credential_valid = d.f_credential_valid;
                    f_credential_unique = true } <: t_RegistrationFacts) /\
               (step_registration d e).f_driver.f_permit_issued /\
               (step_registration d e).f_driver.f_state_consumed /\
               (step_registration d e).f_driver.f_credential_valid
           | _ -> False)
      | _ -> True)) =
  reg_trace_sound_matches_rust d;
  assert (registration_state_is_sound d = true);
  match e <: t_RegistrationEvent with
  | RegistrationEvent_AttemptCounted _ -> ()
  | RegistrationEvent_StateConsumed _ -> ()
  | RegistrationEvent_RegistrationVerified _ -> ()
  | RegistrationEvent_CredentialLookedUp obs ->
      if is_reg_uniqueness d then begin
        match obs <: t_CredentialUniquenessObservation with
        | CredentialUniquenessObservation_LookupFailed -> ()
        | CredentialUniquenessObservation_RegisteredElsewhere -> ()
        | CredentialUniquenessObservation_Unique ->
            let facts =
              ({ f_device_scope = true;
                 f_account_matches = true;
                 f_challenge_pending = d.f_state_consumed;
                 f_challenge_consumed = d.f_state_consumed;
                 f_credential_valid = d.f_credential_valid;
                 f_credential_unique = true } <: t_RegistrationFacts) in
            let decision = plan_registration facts in
            assert (registration_decision_matches_spec facts decision);
            (match decision <: t_RegistrationDecision with
             | RegistrationDecision_Register _ ->
                 assert (registration_is_authorized facts)
             | RegistrationDecision_Reject -> ())
      end
  | RegistrationEvent_CredentialPersisted _ -> ()

/// Once a credential is persisted, no later event can persist another one.
let rec no_persist_from_persist (d: t_RegistrationDriver)
                                (events: list t_RegistrationEvent)
  : Lemma
    (requires (reg_trace_sound d /\ (is_reg_persist d || is_reg_done d)))
    (ensures (count_registration_persists d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      reg_step_sound d e;
      no_persist_from_persist (step_registration d e).f_driver rest

let rec registration_persist_count_le_one (d: t_RegistrationDriver)
                                          (events: list t_RegistrationEvent)
  : Lemma
    (requires (reg_trace_sound d))
    (ensures (count_registration_persists d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      reg_trace_sound_matches_rust d;
      reg_step_sound d e;
      let t = step_registration d e in
      if (match t.f_effect <: t_RegistrationEffect with
          | RegistrationEffect_PersistCredential -> true
          | _ -> false)
      then begin
        assert (is_reg_persist t.f_driver = true);
        no_persist_from_persist t.f_driver rest
      end else begin
        registration_persist_count_le_one t.f_driver rest
      end

let registration_trace_theorem (events: list t_RegistrationEvent)
  : Lemma (
      let d = run_registration_from_begin events in
      reg_trace_sound d /\
      count_registration_persists_from_begin events <= 1 /\
      (d.f_credential_stored ==>
        (d.f_permit_issued /\
         d.f_state_consumed /\
         d.f_credential_valid /\
         d.f_credential_unique /\
         is_reg_done d))) =
  reg_begin_sound ();
  registration_persist_count_le_one (begin_registration ()).f_driver events;
  ()

// ══════════════════════════════════════════════════════════════════════════
// Authentication start
// ══════════════════════════════════════════════════════════════════════════

let is_as_observe (d: t_AuthStartDriver) : bool =
  match d.f_stage <: t_AuthStartStage with
  | AuthStartStage_Observe -> true
  | _ -> false

let is_as_ceremony (d: t_AuthStartDriver) : bool =
  match d.f_stage <: t_AuthStartStage with
  | AuthStartStage_Ceremony -> true
  | _ -> false

let is_as_store (d: t_AuthStartDriver) : bool =
  match d.f_stage <: t_AuthStartStage with
  | AuthStartStage_Store -> true
  | _ -> false

let is_as_done (d: t_AuthStartDriver) : bool =
  match d.f_stage <: t_AuthStartStage with
  | AuthStartStage_Done -> true
  | _ -> false

let as_trace_sound (d: t_AuthStartDriver) : bool =
  (not (is_as_observe d) || (not d.f_authorized && not d.f_stored)) &&
  (not (is_as_ceremony d) || (d.f_authorized && not d.f_stored)) &&
  (not (is_as_store d) || (d.f_authorized && not d.f_stored)) &&
  (not d.f_stored || d.f_authorized) &&
  (not d.f_stored || is_as_done d)

let as_trace_sound_matches_rust (d: t_AuthStartDriver)
  : Lemma (as_trace_sound d = auth_start_state_is_sound d) =
  match d.f_stage <: t_AuthStartStage with
  | AuthStartStage_Observe -> ()
  | AuthStartStage_Ceremony -> ()
  | AuthStartStage_Store -> ()
  | AuthStartStage_Done -> ()

let as_begin_sound ()
  : Lemma (as_trace_sound (begin_auth_start ()).f_driver) =
  as_trace_sound_matches_rust (begin_auth_start ()).f_driver

let as_step_sound (d: t_AuthStartDriver) (e: t_AuthStartEvent)
  : Lemma
    (requires (as_trace_sound d))
    (ensures (as_trace_sound (step_auth_start d e).f_driver)) =
  as_trace_sound_matches_rust d;
  assert (auth_start_state_is_sound d = true);
  as_trace_sound_matches_rust (step_auth_start d e).f_driver

let rec run_auth_start (d: t_AuthStartDriver) (events: list t_AuthStartEvent)
  : Pure t_AuthStartDriver
    (requires (as_trace_sound d))
    (ensures (fun result -> as_trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      as_step_sound d e;
      run_auth_start (step_auth_start d e).f_driver rest

let rec count_auth_start_stores (d: t_AuthStartDriver) (events: list t_AuthStartEvent)
  : Pure nat
    (requires (as_trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      as_step_sound d e;
      (match (step_auth_start d e).f_effect <: t_AuthStartEffect with
       | AuthStartEffect_StoreChallenge -> 1
       | _ -> 0) +
      count_auth_start_stores (step_auth_start d e).f_driver rest

let run_auth_start_from_begin (events: list t_AuthStartEvent)
  : Pure t_AuthStartDriver
    (requires True)
    (ensures (fun result -> as_trace_sound result))
    (decreases events) =
  as_begin_sound ();
  run_auth_start (begin_auth_start ()).f_driver events

let count_auth_start_stores_from_begin (events: list t_AuthStartEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  as_begin_sound ();
  count_auth_start_stores (begin_auth_start ()).f_driver events

/// The checked initiation policy is the authority: a `StoreChallenge` effect
/// is only a response to an observation the policy admitted.
let auth_start_store_requires_policy (d: t_AuthStartDriver) (e: t_AuthStartEvent)
  : Lemma
    (requires (as_trace_sound d))
    (ensures (
      match (step_auth_start d e).f_effect <: t_AuthStartEffect with
      | AuthStartEffect_StoreChallenge ->
          (step_auth_start d e).f_driver.f_authorized /\
          not (step_auth_start d e).f_driver.f_stored
      | _ -> True)) =
  as_trace_sound_matches_rust d;
  assert (auth_start_state_is_sound d = true);
  ()

let rec no_auth_store_from_store (d: t_AuthStartDriver) (events: list t_AuthStartEvent)
  : Lemma
    (requires (as_trace_sound d /\ (is_as_store d || is_as_done d)))
    (ensures (count_auth_start_stores d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      as_step_sound d e;
      no_auth_store_from_store (step_auth_start d e).f_driver rest

let rec auth_start_store_count_le_one (d: t_AuthStartDriver)
                                      (events: list t_AuthStartEvent)
  : Lemma
    (requires (as_trace_sound d))
    (ensures (count_auth_start_stores d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      as_trace_sound_matches_rust d;
      as_step_sound d e;
      let t = step_auth_start d e in
      if (match t.f_effect <: t_AuthStartEffect with
          | AuthStartEffect_StoreChallenge -> true
          | _ -> false)
      then begin
        assert (is_as_store t.f_driver = true);
        no_auth_store_from_store t.f_driver rest
      end else begin
        auth_start_store_count_le_one t.f_driver rest
      end

let auth_start_trace_theorem (events: list t_AuthStartEvent)
  : Lemma (
      let d = run_auth_start_from_begin events in
      as_trace_sound d /\
      count_auth_start_stores_from_begin events <= 1 /\
      (d.f_stored ==> (is_as_done d /\ d.f_authorized))) =
  as_begin_sound ();
  auth_start_store_count_le_one (begin_auth_start ()).f_driver events;
  ()

// ══════════════════════════════════════════════════════════════════════════
// Authentication finish (share release + enrollment grant)
// ══════════════════════════════════════════════════════════════════════════

let is_af_attempt (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Attempt -> true
  | _ -> false

let is_af_context (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Context -> true
  | _ -> false

let is_af_consume (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Consume -> true
  | _ -> false

let is_af_verify (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Verify -> true
  | _ -> false

let is_af_update (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Update -> true
  | _ -> false

let is_af_account (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Account -> true
  | _ -> false

let is_af_release (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Release -> true
  | _ -> false

let is_af_store (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Store -> true
  | _ -> false

let is_af_done (d: t_AuthFinishDriver) : bool =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Done -> true
  | _ -> false

/// Independently written trace invariant. It encodes the stage discipline: an
/// attempt is counted before the challenge is spent, the challenge is spent
/// before any assertion fact is recorded, the metadata update completes before
/// the live row is trusted, and a release needs a consumed, matching,
/// attempt-bound challenge, a verified user-verified assertion under the
/// challenge-bound credential, an active current-epoch account, a present
/// share and the exact stored credential.
let af_trace_sound (d: t_AuthFinishDriver) : bool =
  let attempt_clean =
    not d.f_budget_counted && not d.f_context_observed &&
    not d.f_attempt_consumed && not d.f_user_matches &&
    not d.f_attempt_matches && not d.f_challenge_credential_matches &&
    not d.f_assertion_valid && not d.f_user_verified &&
    not d.f_assertion_credential_matches && not d.f_credential_update_needed &&
    not d.f_credential_updated && not d.f_account_present &&
    not d.f_account_epoch_active && not d.f_share_present &&
    not d.f_stored_credential_matches && not d.f_grant_issued &&
    not d.f_share_decoded && not d.f_grant_stored in
  let context_clean =
    d.f_budget_counted && not d.f_context_observed &&
    not d.f_attempt_consumed && not d.f_user_matches &&
    not d.f_attempt_matches && not d.f_challenge_credential_matches &&
    not d.f_assertion_valid && not d.f_user_verified &&
    not d.f_assertion_credential_matches && not d.f_credential_update_needed &&
    not d.f_credential_updated && not d.f_account_present &&
    not d.f_account_epoch_active && not d.f_share_present &&
    not d.f_stored_credential_matches && not d.f_grant_issued &&
    not d.f_share_decoded && not d.f_grant_stored in
  let consume_clean =
    d.f_budget_counted && d.f_context_observed &&
    not d.f_attempt_consumed && not d.f_user_matches &&
    not d.f_attempt_matches && not d.f_challenge_credential_matches &&
    not d.f_assertion_valid && not d.f_user_verified &&
    not d.f_assertion_credential_matches && not d.f_credential_update_needed &&
    not d.f_credential_updated && not d.f_account_present &&
    not d.f_account_epoch_active && not d.f_share_present &&
    not d.f_stored_credential_matches && not d.f_grant_issued &&
    not d.f_share_decoded && not d.f_grant_stored in
  let verify_clean =
    d.f_budget_counted && d.f_context_observed &&
    d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
    d.f_challenge_credential_matches && not d.f_assertion_valid &&
    not d.f_user_verified && not d.f_assertion_credential_matches &&
    not d.f_credential_update_needed && not d.f_credential_updated &&
    not d.f_account_present && not d.f_account_epoch_active &&
    not d.f_share_present && not d.f_stored_credential_matches &&
    not d.f_grant_issued && not d.f_share_decoded && not d.f_grant_stored in
  let update_clean =
    d.f_budget_counted && d.f_context_observed &&
    d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
    d.f_challenge_credential_matches && d.f_assertion_valid &&
    d.f_user_verified && d.f_assertion_credential_matches &&
    d.f_credential_update_needed && not d.f_credential_updated &&
    not d.f_account_present && not d.f_account_epoch_active &&
    not d.f_share_present && not d.f_stored_credential_matches &&
    not d.f_grant_issued && not d.f_share_decoded && not d.f_grant_stored in
  let account_clean =
    d.f_budget_counted && d.f_context_observed &&
    d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
    d.f_challenge_credential_matches && d.f_assertion_valid &&
    d.f_user_verified && d.f_assertion_credential_matches &&
    (not d.f_credential_update_needed || d.f_credential_updated) &&
    not d.f_grant_issued && not d.f_share_decoded && not d.f_grant_stored in
  let release_clean =
    d.f_budget_counted && d.f_context_observed &&
    d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
    d.f_challenge_credential_matches && d.f_assertion_valid &&
    d.f_user_verified && d.f_assertion_credential_matches &&
    (not d.f_credential_update_needed || d.f_credential_updated) &&
    d.f_account_present && d.f_account_epoch_active &&
    d.f_share_present && d.f_stored_credential_matches &&
    d.f_grant_issued && not d.f_share_decoded && not d.f_grant_stored in
  let store_clean =
    d.f_budget_counted && d.f_context_observed &&
    d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
    d.f_challenge_credential_matches && d.f_assertion_valid &&
    d.f_user_verified && d.f_assertion_credential_matches &&
    (not d.f_credential_update_needed || d.f_credential_updated) &&
    d.f_account_present && d.f_account_epoch_active && d.f_share_present &&
    d.f_stored_credential_matches && d.f_grant_issued &&
    d.f_share_decoded && not d.f_grant_stored in
  (not (is_af_attempt d) || attempt_clean) &&
  (not (is_af_context d) || context_clean) &&
  (not (is_af_consume d) || consume_clean) &&
  (not (is_af_verify d) || verify_clean) &&
  (not (is_af_update d) || update_clean) &&
  (not (is_af_account d) || account_clean) &&
  (not (is_af_release d) || release_clean) &&
  (not (is_af_store d) || store_clean) &&
  (not d.f_context_observed || d.f_budget_counted) &&
  (not d.f_attempt_consumed || d.f_context_observed) &&
  (not (d.f_user_matches || d.f_attempt_matches || d.f_challenge_credential_matches)
    || d.f_attempt_consumed) &&
  (not d.f_assertion_valid ||
    (d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches)) &&
  (not d.f_user_verified || d.f_assertion_valid) &&
  (not d.f_assertion_credential_matches || d.f_assertion_valid) &&
  (not d.f_credential_updated || d.f_credential_update_needed) &&
  (not (d.f_account_present || d.f_account_epoch_active ||
        d.f_share_present || d.f_stored_credential_matches)
    || d.f_attempt_consumed) &&
  (not d.f_grant_issued ||
    (d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
     d.f_challenge_credential_matches && d.f_assertion_valid &&
     d.f_user_verified && d.f_assertion_credential_matches &&
     (not d.f_credential_update_needed || d.f_credential_updated) &&
     d.f_account_present && d.f_account_epoch_active && d.f_share_present &&
     d.f_stored_credential_matches &&
     observed_recovery_epoch d.f_stored_epoch >=. v_INITIAL_EPOCH &&
     (is_af_release d || is_af_store d || is_af_done d))) &&
  (not d.f_share_decoded || d.f_grant_issued) &&
  (not d.f_grant_stored || (d.f_share_decoded && is_af_done d))

let af_trace_sound_matches_rust (d: t_AuthFinishDriver)
  : Lemma (af_trace_sound d = auth_finish_state_is_sound d) =
  match d.f_stage <: t_AuthFinishStage with
  | AuthFinishStage_Attempt -> ()
  | AuthFinishStage_Context -> ()
  | AuthFinishStage_Consume -> ()
  | AuthFinishStage_Verify -> ()
  | AuthFinishStage_Update -> ()
  | AuthFinishStage_Account -> ()
  | AuthFinishStage_Release -> ()
  | AuthFinishStage_Store -> ()
  | AuthFinishStage_Done -> ()

let af_begin_sound ()
  : Lemma (af_trace_sound (begin_auth_finish ()).f_driver) =
  af_trace_sound_matches_rust (begin_auth_finish ()).f_driver

let af_step_sound (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d))
    (ensures (af_trace_sound (step_auth_finish d e).f_driver)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  af_trace_sound_matches_rust (step_auth_finish d e).f_driver

let rec run_auth_finish (d: t_AuthFinishDriver) (events: list t_AuthFinishEvent)
  : Pure t_AuthFinishDriver
    (requires (af_trace_sound d))
    (ensures (fun result -> af_trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      af_trace_sound_matches_rust d;
      af_step_sound d e;
      run_auth_finish (step_auth_finish d e).f_driver rest

let released (e: t_AuthFinishEffect) : nat =
  match e <: t_AuthFinishEffect with
  | AuthFinishEffect_ReleaseGrant _ -> 1
  | _ -> 0

let rec count_auth_finish_releases (d: t_AuthFinishDriver)
                                   (events: list t_AuthFinishEvent)
  : Pure nat
    (requires (af_trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      af_trace_sound_matches_rust d;
      af_step_sound d e;
      released (step_auth_finish d e).f_effect +
      count_auth_finish_releases (step_auth_finish d e).f_driver rest

let rec last_auth_finish_effect (d: t_AuthFinishDriver)
                                (events: list t_AuthFinishEvent)
  : Pure t_AuthFinishEffect
    (requires (af_trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> AuthFinishEffect_Idle
  | e :: [] -> (step_auth_finish d e).f_effect
  | e :: rest ->
      af_trace_sound_matches_rust d;
      af_step_sound d e;
      last_auth_finish_effect (step_auth_finish d e).f_driver rest

let run_auth_finish_from_begin (events: list t_AuthFinishEvent)
  : Pure t_AuthFinishDriver
    (requires True)
    (ensures (fun result -> af_trace_sound result))
    (decreases events) =
  af_begin_sound ();
  run_auth_finish (begin_auth_finish ()).f_driver events

let count_auth_finish_releases_from_begin (events: list t_AuthFinishEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  af_begin_sound ();
  count_auth_finish_releases (begin_auth_finish ()).f_driver events

let last_auth_finish_effect_from_begin (events: list t_AuthFinishEvent)
  : Pure t_AuthFinishEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  af_begin_sound ();
  last_auth_finish_effect (begin_auth_finish ()).f_driver events

// ── Policy provenance ───────────────────────────────────────────────────────

/// The checked recovery policy is the authority: if it releases, every fact it
/// was built from held, including a verified user-verified assertion, the
/// challenge/assertion/stored credential chain, a present share and an active
/// account at a positive epoch.
let plan_release_requires_authorization (obs: t_RecoverObservation)
  : Lemma
    (requires (
      match plan_recovery (recover_facts obs) <: t_RecoverDecision with
      | RecoverDecision_Release _ -> True
      | RecoverDecision_Reject -> False))
    (ensures (
      let facts = recover_facts obs in
      recovery_is_authorized facts)) =
  let facts = recover_facts obs in
  let decision = plan_recovery facts in
  assert (recovery_decision_matches_spec facts decision);
  match decision <: t_RecoverDecision with
  | RecoverDecision_Release _ -> assert (recovery_is_authorized facts)
  | RecoverDecision_Reject -> ()

/// A `ReleaseGrant` effect is only a response to a live-account observation from
/// stage `Account`, for a policy that released, and the permit epoch is the
/// normalized live epoch.
let release_effect_origin (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d))
    (ensures (
      match (step_auth_finish d e).f_effect <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant permit ->
          (match e <: t_AuthFinishEvent with
           | AuthFinishEvent_AccountObserved obs ->
               is_af_account d /\
               obs.f_account_present /\
               obs.f_account_epoch_active /\
               obs.f_share_present /\
               obs.f_stored_credential_matches /\
               d.f_attempt_consumed /\
               d.f_user_matches /\
               d.f_attempt_matches /\
               d.f_challenge_credential_matches /\
               d.f_assertion_valid /\
               d.f_user_verified /\
               d.f_assertion_credential_matches /\
               (not d.f_credential_update_needed || d.f_credential_updated) /\
               (step_auth_finish d e).f_driver.f_grant_issued /\
               permit.f_epoch = observed_recovery_epoch obs.f_stored_epoch /\
               permit.f_epoch = observed_recovery_epoch (step_auth_finish d e).f_driver.f_stored_epoch /\
               permit.f_epoch >=. v_INITIAL_EPOCH
           | _ -> False)
      | _ -> True)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted _ -> ()
  | AuthFinishEvent_ContextObserved _ -> ()
  | AuthFinishEvent_AttemptConsumed _ -> ()
  | AuthFinishEvent_AssertionObserved _ -> ()
  | AuthFinishEvent_CredentialUpdated _ -> ()
  | AuthFinishEvent_AccountObserved obs ->
      if is_af_account d then begin
        if obs.f_account_present then begin
          let facts = recover_facts
            ({ f_attempt_source = RecoveryAttemptSource_Consumed <: t_RecoveryAttemptSource;
               f_user_matches = d.f_user_matches;
               f_attempt_matches = d.f_attempt_matches;
               f_credential_matches_current =
                 (d.f_challenge_credential_matches &&
                  d.f_assertion_credential_matches &&
                  obs.f_stored_credential_matches);
               f_assertion_valid = d.f_assertion_valid;
               f_user_verified = d.f_user_verified;
               f_share_present = obs.f_share_present;
               f_account_epoch_active = obs.f_account_epoch_active;
               f_stored_epoch = obs.f_stored_epoch } <: t_RecoverObservation) in
          let decision = plan_recovery facts in
          assert (recovery_decision_matches_spec facts decision);
          match decision <: t_RecoverDecision with
          | RecoverDecision_Release permit ->
              assert (recovery_is_authorized facts);
              assert (permit.f_epoch = facts.f_epoch);
              assert (facts.f_epoch = observed_recovery_epoch obs.f_stored_epoch);
              assert (permit.f_epoch >=. v_INITIAL_EPOCH)
          | RecoverDecision_Reject -> ()
        end
      end
  | AuthFinishEvent_ShareObserved _ -> ()
  | AuthFinishEvent_GrantStored _ -> ()

/// No release while freezing/rotation is active.
let no_release_while_freezing (d: t_AuthFinishDriver) (obs: t_AuthAccountObservation)
  : Lemma
    (requires (af_trace_sound d /\ not obs.f_account_epoch_active))
    (ensures (
      match (step_auth_finish d (AuthFinishEvent_AccountObserved obs)).f_effect
            <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant _ -> False
      | _ -> True)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  ()

/// No release after the stored recovery credential was replaced: the live row
/// must still hold the challenge-bound credential.
let no_release_after_credential_replacement
      (d: t_AuthFinishDriver) (obs: t_AuthAccountObservation)
  : Lemma
    (requires (af_trace_sound d /\ not obs.f_stored_credential_matches))
    (ensures (
      match (step_auth_finish d (AuthFinishEvent_AccountObserved obs)).f_effect
            <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant _ -> False
      | _ -> True)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  ()

/// No release after the challenge was issued for a different credential.
let no_release_on_replaced_challenge (d: t_AuthFinishDriver)
      (obs: t_AuthAttemptConsumptionObservation)
  : Lemma
    (requires (
      af_trace_sound d /\
      (match obs <: t_AuthAttemptConsumptionObservation with
       | AuthAttemptConsumptionObservation_Present p -> not p.f_credential_matches
       | _ -> False)))
    (ensures (
      match (step_auth_finish d (AuthFinishEvent_AttemptConsumed obs)).f_effect
            <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant _ -> False
      | _ -> True)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  ()

/// No release without a present share.
let no_release_without_share (d: t_AuthFinishDriver) (obs: t_AuthAccountObservation)
  : Lemma
    (requires (af_trace_sound d /\ not obs.f_share_present))
    (ensures (
      match (step_auth_finish d (AuthFinishEvent_AccountObserved obs)).f_effect
            <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant _ -> False
      | _ -> True)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  ()

/// No release unless the assertion verified with user verification.
let release_requires_verified_assertion (d: t_AuthFinishDriver)
      (obs: t_AssertionObservation)
  : Lemma
    (requires (
      af_trace_sound d /\
      (not obs.f_assertion_valid \/ not obs.f_user_verified \/
       not obs.f_credential_matches)))
    (ensures (
      match (step_auth_finish d (AuthFinishEvent_AssertionObserved obs)).f_effect
            <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant _ -> False
      | _ -> True)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  ()

/// `ReleaseGrant` is the only share-releasing effect, and no other effect can
/// release the share at any stage.
let only_release_effect_releases_share (e: t_AuthFinishEffect)
  : Lemma (auth_finish_effect_releases_share e = (released e = 1)) =
  match e <: t_AuthFinishEffect with
  | AuthFinishEffect_CountAttempt -> ()
  | AuthFinishEffect_ObserveContext -> ()
  | AuthFinishEffect_ConsumeAttempt -> ()
  | AuthFinishEffect_VerifyAssertion -> ()
  | AuthFinishEffect_UpdateCredential -> ()
  | AuthFinishEffect_QueryAccount -> ()
  | AuthFinishEffect_ReleaseGrant _ -> ()
  | AuthFinishEffect_StoreGrant -> ()
  | AuthFinishEffect_Complete -> ()
  | AuthFinishEffect_Fail _ -> ()
  | AuthFinishEffect_Idle -> ()

/// After a release, no later event can release again.
let no_release_after_issue (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d /\ d.f_grant_issued))
    (ensures (released (step_auth_finish d e).f_effect = 0)) =
  af_trace_sound_matches_rust d;
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted _ -> ()
  | AuthFinishEvent_ContextObserved _ -> ()
  | AuthFinishEvent_AttemptConsumed _ -> ()
  | AuthFinishEvent_AssertionObserved _ -> ()
  | AuthFinishEvent_CredentialUpdated _ -> ()
  | AuthFinishEvent_AccountObserved _ -> ()
  | AuthFinishEvent_ShareObserved _ -> ()
  | AuthFinishEvent_GrantStored _ -> ()

let rec release_suffix_no_releases (d: t_AuthFinishDriver)
                                   (events: list t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d /\ d.f_grant_issued))
    (ensures (count_auth_finish_releases d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      no_release_after_issue d e;
      release_suffix_no_releases (step_auth_finish d e).f_driver rest

/// After a stored grant the driver is terminal: every event is inert.
let step_after_complete (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d /\ d.f_grant_stored))
    (ensures (
      (step_auth_finish d e).f_driver = d /\
      (step_auth_finish d e).f_effect = AuthFinishEffect_Idle)) =
  af_trace_sound_matches_rust d;
  assert (is_af_done d = true);
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted _ -> ()
  | AuthFinishEvent_ContextObserved _ -> ()
  | AuthFinishEvent_AttemptConsumed _ -> ()
  | AuthFinishEvent_AssertionObserved _ -> ()
  | AuthFinishEvent_CredentialUpdated _ -> ()
  | AuthFinishEvent_AccountObserved _ -> ()
  | AuthFinishEvent_ShareObserved _ -> ()
  | AuthFinishEvent_GrantStored _ -> ()

let rec complete_suffix_inert (d: t_AuthFinishDriver) (events: list t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d /\ d.f_grant_stored))
    (ensures (run_auth_finish d events = d /\ count_auth_finish_releases d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_complete d e;
      complete_suffix_inert d rest

/// At most one release per driver instance, for an arbitrary event list.
let rec auth_finish_release_count_le_one (d: t_AuthFinishDriver)
                                         (events: list t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d))
    (ensures (count_auth_finish_releases d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      af_trace_sound_matches_rust d;
      af_step_sound d e;
      let t = step_auth_finish d e in
      if (match t.f_effect <: t_AuthFinishEffect with
          | AuthFinishEffect_ReleaseGrant _ -> true
          | _ -> false)
      then begin
        assert (t.f_driver.f_grant_issued = true);
        release_suffix_no_releases t.f_driver rest
      end else begin
        auth_finish_release_count_le_one t.f_driver rest
      end

/// All-pairs corollary: after any prefix that released, every unbounded suffix
/// releases nothing.
let no_second_release_after_prefix
      (pre: list t_AuthFinishEvent) (suffix: list t_AuthFinishEvent)
  : Lemma
    (requires (let d = run_auth_finish_from_begin pre in d.f_grant_issued))
    (ensures (
      let d = run_auth_finish_from_begin pre in
      count_auth_finish_releases d suffix = 0)) =
  let d = run_auth_finish_from_begin pre in
  af_begin_sound ();
  release_suffix_no_releases d suffix

/// Headline per-request theorem over the actual extracted driver. For every
/// event list the final state is sound, at most one release was authorized, and
/// a released grant carries a consumed, bound challenge, a verified
/// user-verified assertion under the still-current credential, an active
/// non-rotating current-epoch account, a present share and (when the
/// authenticator asked for it) a completed metadata update.
let auth_finish_trace_theorem (events: list t_AuthFinishEvent)
  : Lemma (
      let d = run_auth_finish_from_begin events in
      af_trace_sound d /\
      count_auth_finish_releases_from_begin events <= 1 /\
      (d.f_grant_issued ==>
        (d.f_attempt_consumed /\
         d.f_user_matches /\
         d.f_attempt_matches /\
         d.f_challenge_credential_matches /\
         d.f_assertion_valid /\
         d.f_user_verified /\
         d.f_assertion_credential_matches /\
         (not d.f_credential_update_needed || d.f_credential_updated) /\
         d.f_account_present /\
         d.f_account_epoch_active /\
         d.f_share_present /\
         d.f_stored_credential_matches /\
         observed_recovery_epoch d.f_stored_epoch >=. v_INITIAL_EPOCH)) /\
      (d.f_grant_stored ==>
        (d.f_grant_issued /\ d.f_share_decoded /\ is_af_done d))) =
  af_begin_sound ();
  af_trace_sound_matches_rust (begin_auth_finish ()).f_driver;
  auth_finish_release_count_le_one (begin_auth_finish ()).f_driver events;
  ()

// ══════════════════════════════════════════════════════════════════════════
// Reachability witnesses
// ══════════════════════════════════════════════════════════════════════════

let ready_credential : t_StoredCredentialObservation =
  StoredCredentialObservation_Present

let registration_start_observation : t_RegistrationStartObservation =
  { f_account_present = true; f_credential = ready_credential }

let registration_start_events : list t_RegistrationStartEvent =
  [ RegistrationStartEvent_Observed registration_start_observation;
    RegistrationStartEvent_CeremonyStarted CeremonyStartObservation_Started;
    RegistrationStartEvent_Stored ChallengeStoreObservation_Stored ]

let registration_start_success_is_reachable ()
  : Lemma (
      let d = run_registration_start_from_begin registration_start_events in
      d.f_stored = true /\ is_rs_done d /\
      count_registration_ceremonies_from_begin registration_start_events = 1 /\
      count_registration_start_stores_from_begin registration_start_events = 1) =
  ()

let registration_start_corrupt_is_reachable ()
  : Lemma (
      let events =
        [ RegistrationStartEvent_Observed
            ({ registration_start_observation with
               f_credential = StoredCredentialObservation_Corrupt }) ] in
      let d = run_registration_start_from_begin events in
      d.f_stored = false /\ not d.f_authorized /\ is_rs_done d /\
      count_registration_ceremonies_from_begin events = 0) =
  ()

let admitted_registration : t_RegistrationEvent =
  RegistrationEvent_AttemptCounted AttemptBudgetObservation_Admitted
let verified_registration : t_RegistrationEvent =
  RegistrationEvent_RegistrationVerified { f_credential_valid = true }
let unique_credential : t_RegistrationEvent =
  RegistrationEvent_CredentialLookedUp CredentialUniquenessObservation_Unique
let persisted_credential : t_RegistrationEvent =
  RegistrationEvent_CredentialPersisted CredentialPersistObservation_Persisted

let registration_success_events : list t_RegistrationEvent =
  [ admitted_registration;
    RegistrationEvent_StateConsumed RegistrationStateObservation_Present;
    verified_registration;
    unique_credential;
    persisted_credential ]

let registration_success_is_reachable ()
  : Lemma (
      let d = run_registration_from_begin registration_success_events in
      d.f_credential_stored = true /\ d.f_permit_issued = true /\ is_reg_done d /\
      count_registration_persists_from_begin registration_success_events = 1) =
  ()

let registration_limited_is_reachable ()
  : Lemma (
      let events =
        [ RegistrationEvent_AttemptCounted AttemptBudgetObservation_Limited ] in
      let d = run_registration_from_begin events in
      d.f_state_consumed = false /\ d.f_credential_stored = false /\
      is_reg_done d) =
  ()

let registration_duplicate_is_reachable ()
  : Lemma (
      let events =
        [ admitted_registration;
          RegistrationEvent_StateConsumed RegistrationStateObservation_Present;
          verified_registration;
          RegistrationEvent_CredentialLookedUp
            CredentialUniquenessObservation_RegisteredElsewhere ] in
      let d = run_registration_from_begin events in
      d.f_permit_issued = false /\ d.f_credential_stored = false /\ is_reg_done d) =
  ()

let available_auth_start : t_AuthStartObservation =
  { f_account_present = true;
    f_share_present = true;
    f_credential = ready_credential;
    f_attempt_id_fresh = true;
    f_ttl_secs = mk_u64 300 }

let auth_start_events : list t_AuthStartEvent =
  [ AuthStartEvent_Observed available_auth_start;
    AuthStartEvent_CeremonyStarted CeremonyStartObservation_Started;
    AuthStartEvent_Stored ChallengeStoreObservation_Stored ]

let auth_start_success_is_reachable ()
  : Lemma (
      let d = run_auth_start_from_begin auth_start_events in
      d.f_stored = true /\ is_as_done d /\
      count_auth_start_stores_from_begin auth_start_events = 1) =
  ()

let auth_start_collision_is_reachable ()
  : Lemma (
      let events =
        [ AuthStartEvent_Observed
            ({ available_auth_start with f_attempt_id_fresh = false }) ] in
      let d = run_auth_start_from_begin events in
      d.f_stored = false /\ is_as_done d /\
      count_auth_start_stores_from_begin events = 0) =
  ()

let auth_start_lost_race_is_reachable ()
  : Lemma (
      let d =
        run_auth_start_from_begin
          [ AuthStartEvent_Observed available_auth_start;
            AuthStartEvent_CeremonyStarted CeremonyStartObservation_Started;
            AuthStartEvent_Stored ChallengeStoreObservation_Lost ] in
      d.f_stored = false /\ is_as_done d) =
  ()

// ── Authentication-finish witnesses ────────────────────────────────────────

let available_context : t_AuthFinishContextObservation =
  { f_account_present = true;
    f_share_present = true;
    f_credential = ready_credential;
    f_attempt_id_present = true }

let matched_attempt : t_AuthAttemptConsumptionObservation =
  AuthAttemptConsumptionObservation_Present
    ({ f_user_matches = true; f_attempt_matches = true; f_credential_matches = true })

let replaced_challenge_attempt : t_AuthAttemptConsumptionObservation =
  AuthAttemptConsumptionObservation_Present
    ({ f_user_matches = true; f_attempt_matches = true; f_credential_matches = false })

let verified_assertion : t_AssertionObservation =
  { f_assertion_valid = true;
    f_user_verified = true;
    f_credential_matches = true;
    f_needs_update = false }

let verified_assertion_with_update : t_AssertionObservation =
  { verified_assertion with f_needs_update = true }

let active_account : t_AuthAccountObservation =
  { f_account_present = true;
    f_account_epoch_active = true;
    f_share_present = true;
    f_stored_credential_matches = true;
    f_stored_epoch = Core_models.Option.Option_Some (mk_i64 3) }

let auth_finish_success_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion;
    AuthFinishEvent_AccountObserved active_account;
    AuthFinishEvent_ShareObserved ShareDecodeObservation_Decoded;
    AuthFinishEvent_GrantStored GrantStoreObservation_Stored ]

let auth_finish_update_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion_with_update;
    AuthFinishEvent_CredentialUpdated CredentialUpdateStoreObservation_Updated;
    AuthFinishEvent_AccountObserved active_account;
    AuthFinishEvent_ShareObserved ShareDecodeObservation_Decoded;
    AuthFinishEvent_GrantStored GrantStoreObservation_Stored ]

let auth_finish_limited_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Limited ]

let auth_finish_missing_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed AuthAttemptConsumptionObservation_Missing ]

let auth_finish_corrupt_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed AuthAttemptConsumptionObservation_Corrupt ]

let auth_finish_binding_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed
      (AuthAttemptConsumptionObservation_Present
        ({ f_user_matches = false; f_attempt_matches = true; f_credential_matches = true })) ]

let auth_finish_replaced_challenge_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed replaced_challenge_attempt ]

let auth_finish_bad_assertion_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved
      ({ verified_assertion with f_assertion_valid = false }) ]

let auth_finish_no_uv_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved
      ({ verified_assertion with f_user_verified = false }) ]

let auth_finish_assertion_credential_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved
      ({ verified_assertion with f_credential_matches = false }) ]

let auth_finish_update_changed_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion_with_update;
    AuthFinishEvent_CredentialUpdated CredentialUpdateStoreObservation_Changed ]

let auth_finish_frozen_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion;
    AuthFinishEvent_AccountObserved
      ({ active_account with f_account_epoch_active = false }) ]

let auth_finish_replacement_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion;
    AuthFinishEvent_AccountObserved
      ({ active_account with f_stored_credential_matches = false }) ]

let auth_finish_no_share_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion;
    AuthFinishEvent_AccountObserved
      ({ active_account with f_share_present = false }) ]

let auth_finish_share_corrupt_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion;
    AuthFinishEvent_AccountObserved active_account;
    AuthFinishEvent_ShareObserved ShareDecodeObservation_Corrupt ]

let auth_finish_grant_storage_events : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion;
    AuthFinishEvent_AccountObserved active_account;
    AuthFinishEvent_ShareObserved ShareDecodeObservation_Decoded;
    AuthFinishEvent_GrantStored GrantStoreObservation_Failed ]

let auth_finish_success_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_success_events in
      d.f_grant_issued = true /\ d.f_grant_stored = true /\
      d.f_share_decoded = true /\ is_af_done d /\
      count_auth_finish_releases_from_begin auth_finish_success_events = 1) =
  ()

/// The update path is witnessed in two bounded prefixes: the 5-event prefix
/// reaches the completed metadata update, and the 6-event prefix (the same
/// trace plus the live-account observation) reaches the policy release. The
/// final grant-store step is transition-identical to the success witness above,
/// so it is not re-normalized here.
let auth_finish_update_prefix : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion_with_update;
    AuthFinishEvent_CredentialUpdated CredentialUpdateStoreObservation_Updated ]

let auth_finish_update_release_prefix : list t_AuthFinishEvent =
  [ AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    AuthFinishEvent_ContextObserved available_context;
    AuthFinishEvent_AttemptConsumed matched_attempt;
    AuthFinishEvent_AssertionObserved verified_assertion_with_update;
    AuthFinishEvent_CredentialUpdated CredentialUpdateStoreObservation_Updated;
    AuthFinishEvent_AccountObserved active_account ]

let auth_finish_update_completed ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_update_prefix in
      d.f_credential_updated = true /\ d.f_credential_update_needed = true) =
  ()

let auth_finish_update_success_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_update_release_prefix in
      d.f_credential_updated = true /\ d.f_grant_issued = true /\
      is_af_release d) =
  ()

let auth_finish_limited_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_limited_events in
      d.f_budget_counted = false /\ d.f_attempt_consumed = false /\
      d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_limited_events =
        AuthFinishEffect_Fail AuthFinishFailure_AttemptLimited) =
  ()

let auth_finish_missing_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_missing_events in
      d.f_attempt_consumed = false /\ d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_missing_events =
        AuthFinishEffect_Fail AuthFinishFailure_AttemptMissing) =
  ()

let auth_finish_corrupt_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_corrupt_events in
      d.f_attempt_consumed = true /\ d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_corrupt_events =
        AuthFinishEffect_Fail AuthFinishFailure_AttemptCorrupt) =
  ()

let auth_finish_binding_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_binding_events in
      d.f_attempt_consumed = true /\ d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_binding_events =
        AuthFinishEffect_Fail AuthFinishFailure_BindingMismatch) =
  ()

let auth_finish_replaced_challenge_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_replaced_challenge_events in
      d.f_attempt_consumed = true /\ d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_replaced_challenge_events =
        AuthFinishEffect_Fail AuthFinishFailure_ChallengeCredentialReplaced) =
  ()

let auth_finish_bad_assertion_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_bad_assertion_events in
      d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_bad_assertion_events =
        AuthFinishEffect_Fail AuthFinishFailure_AssertionInvalid) =
  ()

let auth_finish_no_uv_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_no_uv_events in
      d.f_grant_issued = false /\ d.f_user_verified = false /\
      last_auth_finish_effect_from_begin auth_finish_no_uv_events =
        AuthFinishEffect_Fail AuthFinishFailure_UserVerificationRequired) =
  ()

let auth_finish_assertion_credential_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_assertion_credential_events in
      d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_assertion_credential_events =
        AuthFinishEffect_Fail AuthFinishFailure_AssertionCredentialMismatch) =
  ()

let auth_finish_update_changed_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_update_changed_events in
      d.f_grant_issued = false /\ d.f_credential_updated = false /\
      last_auth_finish_effect_from_begin auth_finish_update_changed_events =
        AuthFinishEffect_Fail AuthFinishFailure_CredentialUpdateMismatch) =
  ()

/// Freezing pauses recovery after the challenge was consumed, without a grant.
let auth_finish_frozen_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_frozen_events in
      d.f_grant_issued = false /\ d.f_attempt_consumed = true /\
      last_auth_finish_effect_from_begin auth_finish_frozen_events =
        AuthFinishEffect_Fail AuthFinishFailure_RotationPaused) =
  ()

/// Credential replacement in the live row is terminal without a grant.
let auth_finish_replacement_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_replacement_events in
      d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_replacement_events =
        AuthFinishEffect_Fail AuthFinishFailure_StoredCredentialMismatch) =
  ()

let auth_finish_no_share_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_no_share_events in
      d.f_grant_issued = false /\
      last_auth_finish_effect_from_begin auth_finish_no_share_events =
        AuthFinishEffect_Fail AuthFinishFailure_ShareMissing) =
  ()

let auth_finish_share_corrupt_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_share_corrupt_events in
      d.f_grant_issued = true /\ d.f_grant_stored = false /\
      last_auth_finish_effect_from_begin auth_finish_share_corrupt_events =
        AuthFinishEffect_Fail AuthFinishFailure_ShareCorrupt) =
  ()

let auth_finish_grant_storage_is_reachable ()
  : Lemma (
      let d = run_auth_finish_from_begin auth_finish_grant_storage_events in
      d.f_grant_issued = true /\ d.f_grant_stored = false /\
      last_auth_finish_effect_from_begin auth_finish_grant_storage_events =
        AuthFinishEffect_Fail AuthFinishFailure_GrantStorage) =
  ()
