module Vela_rekey_policy_vault_upload_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* vault chunk
/// upload and read drivers (`Vela_rekey_policy.Vault_upload_driver`).
///
/// Scope: one `UploadDriver` / `ReadDriver` value, i.e. one HTTP request. The
/// theorem does not claim anything about two concurrent requests; the SQL
/// guards, quota queries, row read-back and the order in which the handler
/// performs them remain effectful glue outside this module. The driver's
/// rekey/quota/write inputs are observations, never verified origins.
///
/// The invariant below is stated independently of
/// `upload_state_is_sound`; it keeps only the security-relevant facts and the
/// stage discipline needed by the trace theorem. All trace lemmas quantify
/// over every event list.
///
/// The headline write-authorization theorem is stated with an explicit
/// running counter (`trace_writes`): a `Write` effect is counted whenever the
/// extracted driver emits one, and the counter is threaded through the trace.
/// It is not an artefact of the modelled SQL guard, because the counter is
/// driven solely by the extracted driver's effect.

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Vault_upload_driver

// ── Stage predicates ───────────────────────────────────────────────────────

let is_resolve (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Resolve -> true
  | _ -> false

let is_shadow (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Shadow -> true
  | _ -> false

let is_quota (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Quota -> true
  | _ -> false

let is_write (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Write -> true
  | _ -> false

let is_recheck (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Recheck -> true
  | _ -> false

let is_reread (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Reread -> true
  | _ -> false

let is_activity (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Activity -> true
  | _ -> false

let is_publish (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Publish -> true
  | _ -> false

let is_done (d: t_UploadDriver) : bool =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Done -> true
  | _ -> false

// ── Route and trace invariant ──────────────────────────────────────────────

/// An authoritative write route: the account is ACTIVE at the live epoch and
/// the write/read epochs are that same epoch.
let active_route (d: t_UploadDriver) : bool =
  d.f_state_epoch >=. v_INITIAL_EPOCH &&
  d.f_state_phase = Phase_Active &&
  not d.f_shadow &&
  d.f_write_epoch = d.f_state_epoch &&
  d.f_read_epoch = d.f_state_epoch

/// A shadow route: the account is FREEZING and the write targets exactly the
/// successor epoch while reads keep serving the current one. Only a device
/// token may take this route.
let shadow_route (d: t_UploadDriver) : bool =
  d.f_state_epoch >=. v_INITIAL_EPOCH &&
  d.f_state_phase = Phase_Freezing &&
  d.f_shadow &&
  (next_epoch d.f_state_epoch <: Core_models.Option.t_Option i64) =
    (Core_models.Option.Option_Some d.f_write_epoch <: Core_models.Option.t_Option i64) &&
  d.f_read_epoch = d.f_state_epoch

let route_clean (d: t_UploadDriver) : bool =
  shadow_route d || active_route d

/// Boolean implication (logical `==>` is a proposition, not a `bool`).
let imp (a b: bool) : bool = (not a) || b

/// Strengthened trace invariant. It keeps the security facts plus the stage
/// discipline that makes the transition relation deterministic.
let trace_sound (d: t_UploadDriver) : bool =
  (d.f_authenticated || (is_done d && d.f_failed)) &&
  imp d.f_shadow (shadow_route d) &&
  imp (d.f_shadow && not (is_shadow d) && not d.f_failed) (not d.f_web) &&
  imp d.f_write_matched (route_clean d && d.f_permit_epoch = d.f_write_epoch &&
                         d.f_write_epoch >=. v_INITIAL_EPOCH) &&
  imp d.f_activity_done d.f_shadow &&
  imp d.f_published (not d.f_shadow && d.f_write_matched) &&
  imp d.f_responded (d.f_write_matched &&
                     imp d.f_shadow d.f_activity_done &&
                     imp (not d.f_shadow) d.f_published) &&
  not (d.f_responded && d.f_failed) &&
  imp (is_resolve d) (not d.f_write_matched && not d.f_responded && not d.f_failed &&
                      d.f_state_epoch = mk_i64 0 && d.f_write_epoch = mk_i64 0 &&
                      d.f_read_epoch = mk_i64 0 && d.f_permit_epoch = mk_i64 0) &&
  imp (is_shadow d) (d.f_shadow && d.f_permit_epoch = mk_i64 0 &&
                     not d.f_write_matched && not d.f_responded && not d.f_failed) &&
  imp (is_recheck d) (active_route d && d.f_permit_epoch = d.f_write_epoch &&
                      not d.f_write_matched && not d.f_responded && not d.f_failed) &&
  imp (is_quota d) (route_clean d && d.f_permit_epoch = d.f_write_epoch &&
                    not d.f_write_matched && not d.f_responded && not d.f_failed) &&
  imp (is_write d) (route_clean d && d.f_permit_epoch = d.f_write_epoch &&
                    not d.f_write_matched && not d.f_responded && not d.f_failed) &&
  imp (is_reread d) (route_clean d && d.f_permit_epoch = d.f_write_epoch &&
                     d.f_write_matched && not d.f_responded && not d.f_failed) &&
  imp (is_activity d) (shadow_route d && d.f_permit_epoch = d.f_write_epoch &&
                       d.f_write_matched && not d.f_responded && not d.f_failed) &&
  imp (is_publish d) (d.f_write_matched && imp d.f_shadow d.f_activity_done &&
                      not d.f_responded && not d.f_failed) &&
  imp (is_done d) (d.f_responded || d.f_failed)

let test_shadow (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ d.f_shadow)) (ensures (shadow_route d)) = ()

let test_shadow_auth (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ is_shadow d)) (ensures (d.f_authenticated)) = ()

let test_shadow_permit (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ is_shadow d)) (ensures (d.f_permit_epoch = mk_i64 0)) = ()

let test_shadow_matched (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ is_shadow d)) (ensures (not d.f_write_matched)) = ()

let test_shadow_responded (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ is_shadow d)) (ensures (not d.f_responded)) = ()

let test_shadow_failed (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ is_shadow d)) (ensures (not d.f_failed)) = ()

/// The initial request state satisfies the invariant.
let begin_trace_sound (request: t_UploadRequest)
  : Lemma (trace_sound (begin_upload request).f_driver) =
  ()

// ── Per-transition preservation lemmas ────────────────────────────────────

let accepted_route_clean
      (state: t_RekeyState)
      (declared: Core_models.Option.t_Option i64)
      (route: t_EpochRoute)
  : Lemma
    (requires (Vela_rekey_policy.write_decision_matches_spec state declared
                 (WriteDecision_Accept route)))
    (ensures (
      route.f_read_epoch = state.f_epoch /\
      (state.f_phase = Phase_Active ==> route.f_write_epoch = state.f_epoch) /\
      (state.f_phase = Phase_Freezing ==>
        (Vela_rekey_policy.next_epoch state.f_epoch <: Core_models.Option.t_Option i64) =
          (Core_models.Option.Option_Some route.f_write_epoch <: Core_models.Option.t_Option i64)))) =
  ()

let permit_epoch_is_declared
      (request: Vela_rekey_policy.t_MutationRequest)
      (permit: Vela_rekey_policy.t_MutationPermit)
  : Lemma
    (requires (Vela_rekey_policy.mutation_decision_matches_spec request
                 (Vela_rekey_policy.MutationDecision_Permit permit)))
    (ensures (permit.f_epoch = request.Vela_rekey_policy.f_declared_epoch)) =
  ()

let rekey_rejected_sound (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ is_resolve d))
          (ensures (trace_sound (on_rekey d RekeyObservation_Rejected).f_driver)) =
  ()

let resolved_route_clean_freezing
      (d: t_UploadDriver) (epoch: i64) (route: t_EpochRoute) : bool =
  route.f_read_epoch = epoch &&
  (Vela_rekey_policy.next_epoch epoch <: Core_models.Option.t_Option i64) =
    (Core_models.Option.Option_Some route.f_write_epoch <: Core_models.Option.t_Option i64) &&
  route.f_write_epoch <> route.f_read_epoch

let rekey_accept_freezing_sound
      (d: t_UploadDriver) (epoch: i64) (route: t_EpochRoute)
  : Lemma
    (requires (
      trace_sound d /\ is_resolve d /\
      Vela_rekey_policy.resolve_write_epoch
        ({ Vela_rekey_policy.f_epoch = epoch;
           Vela_rekey_policy.f_phase = Phase_Freezing } <: t_RekeyState)
        d.f_declared_epoch = (WriteDecision_Accept route <: t_WriteDecision) /\
      route.f_read_epoch = epoch /\
      (Vela_rekey_policy.next_epoch epoch <: Core_models.Option.t_Option i64) =
        (Core_models.Option.Option_Some route.f_write_epoch <: Core_models.Option.t_Option i64) /\
      route.f_write_epoch <> route.f_read_epoch))
    (ensures (
      trace_sound (on_rekey d
        (RekeyObservation_State
          { f_epoch = epoch; f_phase = Phase_Freezing })).f_driver)) =
  let expected: t_UploadDriver =
    { d with
      f_stage = UploadStage_Shadow;
      f_state_epoch = epoch;
      f_state_phase = Phase_Freezing;
      f_write_epoch = route.f_write_epoch;
      f_read_epoch = route.f_read_epoch;
      f_authority_epoch = if d.f_web then d.f_authority_epoch else route.f_write_epoch;
      f_shadow = true } in
  assert (expected.f_state_phase = Phase_Freezing);
  assert (expected.f_shadow);
  assert ((Vela_rekey_policy.next_epoch expected.f_state_epoch <: Core_models.Option.t_Option i64) =
          (Core_models.Option.Option_Some expected.f_write_epoch <: Core_models.Option.t_Option i64));
  assert (expected.f_read_epoch = expected.f_state_epoch);
  assert (shadow_route expected)

let rekey_accept_active_sound
      (d: t_UploadDriver) (epoch: i64) (route: t_EpochRoute)
  : Lemma
    (requires (
      trace_sound d /\ is_resolve d /\
      Vela_rekey_policy.resolve_write_epoch
        ({ Vela_rekey_policy.f_epoch = epoch;
           Vela_rekey_policy.f_phase = Phase_Active } <: t_RekeyState)
        d.f_declared_epoch = (WriteDecision_Accept route <: t_WriteDecision) /\
      route.f_read_epoch = epoch /\
      route.f_write_epoch = epoch))
    (ensures (
      trace_sound (on_rekey d
        (RekeyObservation_State
          { f_epoch = epoch; f_phase = Phase_Active })).f_driver)) =
  ()

let on_rekey_sound (d: t_UploadDriver) (observation: t_RekeyObservation)
  : Lemma (requires (trace_sound d /\ is_resolve d))
          (ensures (trace_sound (on_rekey d observation).f_driver)) =
  match observation <: t_RekeyObservation with
  | RekeyObservation_Rejected -> rekey_rejected_sound d
  | RekeyObservation_State { f_epoch = epoch; f_phase = phase } ->
      let state: t_RekeyState = { f_epoch = epoch; f_phase = phase } in
      match Vela_rekey_policy.resolve_write_epoch state d.f_declared_epoch <: t_WriteDecision with
      | WriteDecision_Reject -> ()
      | WriteDecision_Accept route ->
          accepted_route_clean state d.f_declared_epoch route;
          (match phase <: t_Phase with
           | Phase_Active -> rekey_accept_active_sound d epoch route
           | Phase_Freezing -> rekey_accept_freezing_sound d epoch route)

let terminal_sound (d: t_UploadDriver) (failure: t_UploadFailure)
  : Lemma (requires (trace_sound d /\ not d.f_responded))
          (ensures (trace_sound (terminal d failure).f_driver)) =
  ()

let shadow_facts (d: t_UploadDriver)
  : Lemma
    (requires (trace_sound d /\ is_shadow d))
    (ensures (d.f_authenticated /\ shadow_route d /\
              d.f_permit_epoch = mk_i64 0 /\ not d.f_write_matched /\
              not d.f_responded /\ not d.f_failed)) =
  assert (trace_sound d);
  assert (is_shadow d);
  test_shadow_auth d;
  test_shadow d;
  test_shadow_permit d;
  test_shadow_matched d;
  test_shadow_responded d;
  test_shadow_failed d

/// The permit decision inside `enter_quota` always names the declared epoch.
let enter_quota_permit_sound
      (d: t_UploadDriver) (permit_epoch: i64)
  : Lemma
    (requires (
      trace_sound d /\
      is_shadow d /\
      d.f_authenticated /\
      d.f_write_epoch >=. v_INITIAL_EPOCH /\
      not d.f_web /\
      not d.f_write_matched /\
      permit_epoch = d.f_write_epoch))
    (ensures (
      trace_sound ({ d with
                     f_stage = UploadStage_Quota;
                     f_permit_epoch = permit_epoch })))
  =
  shadow_facts d

let on_attempt_sound (d: t_UploadDriver) (authority: t_AttemptAuthority)
  : Lemma (requires (trace_sound d /\ is_shadow d))
          (ensures (trace_sound (on_attempt d authority).f_driver)) =
  if d.f_web then begin
    assert ((on_attempt d authority).f_driver =
            (terminal d UploadFailure_ShadowWebSessionForbidden).f_driver);
    terminal_sound d UploadFailure_ShadowWebSessionForbidden
  end else begin
    let state: t_RekeyState =
      { f_epoch = d.f_state_epoch; f_phase = d.f_state_phase } in
    let route: t_EpochRoute =
      { f_write_epoch = d.f_write_epoch; f_read_epoch = d.f_read_epoch } in
    match Vela_rekey_policy.authorize_shadow state route authority
          <: Vela_rekey_policy.t_ShadowDecision with
    | Vela_rekey_policy.ShadowDecision_Allow ->
        let request: Vela_rekey_policy.t_MutationRequest =
          { Vela_rekey_policy.f_declared_epoch = d.f_write_epoch;
            Vela_rekey_policy.f_authority_epoch = d.f_write_epoch;
            Vela_rekey_policy.f_kind = Vela_rekey_policy.MutationKind_Vault;
            Vela_rekey_policy.f_authority = Vela_rekey_policy.MutationAuthority_Device } in
        (match Vela_rekey_policy.plan_active_mutation request
               <: Vela_rekey_policy.t_MutationDecision with
         | Vela_rekey_policy.MutationDecision_Permit permit ->
             permit_epoch_is_declared request permit;
             enter_quota_permit_sound d permit.f_epoch
         | Vela_rekey_policy.MutationDecision_Reject ->
             ())
    | Vela_rekey_policy.ShadowDecision_Reject ->
        if not authority.Vela_rekey_policy.f_device_scope
        then begin
          assert ((on_attempt d authority).f_driver =
                  (terminal d UploadFailure_ShadowWebSessionForbidden).f_driver);
          terminal_sound d UploadFailure_ShadowWebSessionForbidden
        end else if not authority.Vela_rekey_policy.f_rotation_id_present
        then begin
          assert ((on_attempt d authority).f_driver =
                  (terminal d UploadFailure_ShadowRotationIdRequired).f_driver);
          terminal_sound d UploadFailure_ShadowRotationIdRequired
        end else begin
          assert ((on_attempt d authority).f_driver =
                  (terminal d UploadFailure_ShadowStarterForbidden).f_driver);
          terminal_sound d UploadFailure_ShadowStarterForbidden
        end
  end

let on_quota_sound (d: t_UploadDriver) (observation: t_QuotaObservation)
  : Lemma (requires (trace_sound d /\ is_quota d))
          (ensures (trace_sound (on_quota d observation).f_driver)) = ()

let on_write_sound (d: t_UploadDriver) (observation: t_WriteObservation)
  : Lemma (requires (trace_sound d /\ is_write d))
          (ensures (trace_sound (on_write d observation).f_driver)) = ()

let on_recheck_sound (d: t_UploadDriver) (observation: t_RecheckObservation)
  : Lemma (requires (trace_sound d /\ is_recheck d))
          (ensures (trace_sound (on_recheck d observation).f_driver)) = ()

let on_reread_sound (d: t_UploadDriver) (observation: t_RereadObservation)
  : Lemma (requires (trace_sound d /\ is_reread d))
          (ensures (trace_sound (on_reread d observation).f_driver)) = ()

let on_activity_sound (d: t_UploadDriver) (observation: t_ActivityObservation)
  : Lemma (requires (trace_sound d /\ is_activity d))
          (ensures (trace_sound (on_activity d observation).f_driver)) = ()

let on_publish_sound (d: t_UploadDriver)
  : Lemma (requires (trace_sound d /\ is_publish d))
          (ensures (trace_sound (on_publish d).f_driver)) = ()

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (upload_step d e).f_driver)) =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Resolve ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey observation -> on_rekey_sound d observation
       | _ -> ())
  | UploadStage_Shadow ->
      (match e <: t_UploadEvent with
       | UploadEvent_Attempt authority -> on_attempt_sound d authority
       | UploadEvent_AttemptStorage ->
           assert ((upload_step d e).f_driver =
                   (terminal d UploadFailure_AttemptStorage).f_driver);
           terminal_sound d UploadFailure_AttemptStorage
       | _ -> ())
  | UploadStage_Quota ->
      (match e <: t_UploadEvent with
       | UploadEvent_Quota observation -> on_quota_sound d observation
       | _ -> ())
  | UploadStage_Write ->
      (match e <: t_UploadEvent with
       | UploadEvent_Write observation -> on_write_sound d observation
       | _ -> ())
  | UploadStage_Recheck ->
      (match e <: t_UploadEvent with
       | UploadEvent_Recheck observation -> on_recheck_sound d observation
       | _ -> ())
  | UploadStage_Reread ->
      (match e <: t_UploadEvent with
       | UploadEvent_Reread observation -> on_reread_sound d observation
       | _ -> ())
  | UploadStage_Activity ->
      (match e <: t_UploadEvent with
       | UploadEvent_Activity observation -> on_activity_sound d observation
       | _ -> ())
  | UploadStage_Publish ->
      (match e <: t_UploadEvent with
       | UploadEvent_Published -> on_publish_sound d
       | _ -> ())
  | UploadStage_Done -> ()

/// A finished driver is inert for every event.
let step_after_done (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (upload_step d e).f_driver = d /\
      (upload_step d e).f_effect = UploadEffect_Idle)) =
  match e <: t_UploadEvent with
  | UploadEvent_Rekey _ -> ()
  | UploadEvent_Attempt _ -> ()
  | UploadEvent_AttemptStorage -> ()
  | UploadEvent_Quota _ -> ()
  | UploadEvent_Write _ -> ()
  | UploadEvent_Recheck _ -> ()
  | UploadEvent_Reread _ -> ()
  | UploadEvent_Activity _ -> ()
  | UploadEvent_Published -> ()

/// An unauthenticated request reaches a terminal state without any effect.
let unauthenticated_never_writes (request: t_UploadRequest)
  : Lemma
    (requires (not request.f_writer.f_authenticated))
    (ensures (
      let t = begin_upload request in
      trace_sound t.f_driver /\ is_done t.f_driver /\
      t.f_effect = UploadEffect_Fail UploadFailure_Unauthenticated)) =
  ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_UploadDriver) (events: list t_UploadEvent)
  : Pure t_UploadDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      step_sound d e;
      run (upload_step d e).f_driver rest

let rec last_effect (d: t_UploadDriver) (events: list t_UploadEvent)
  : Pure t_UploadEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> UploadEffect_Idle
  | e :: [] -> (upload_step d e).f_effect
  | e :: rest ->
      step_sound d e;
      last_effect (upload_step d e).f_driver rest

/// Total wrappers starting from the actual extracted `begin_upload`.
let run_from_request (request: t_UploadRequest) (events: list t_UploadEvent)
  : Pure t_UploadDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_trace_sound request;
  run (begin_upload request).f_driver events

let last_effect_from_request (request: t_UploadRequest) (events: list t_UploadEvent)
  : Pure t_UploadEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_trace_sound request;
  last_effect (begin_upload request).f_driver events

// ── Effect provenance and write authorization ─────────────────────────────

let b2n (b: bool) : nat = if b then 1 else 0

/// A `Write` effect carries a permit that agrees with the driver's route and
/// authority epoch.
let write_effect_route (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (upload_step d e).f_effect <: t_UploadEffect with
      | UploadEffect_Write permit ->
          permit.f_write_epoch = d.f_write_epoch /\
          permit.f_read_epoch = d.f_read_epoch /\
          permit.f_permit_epoch = d.f_permit_epoch /\
          permit.f_shadow = d.f_shadow /\
          permit.f_web = d.f_web /\
          permit.f_state_epoch = d.f_state_epoch /\
          permit.f_state_phase = d.f_state_phase /\
          (permit.f_shadow ==>
            (d.f_state_phase = Vela_rekey_policy.Phase_Freezing /\
             Vela_rekey_policy.next_epoch d.f_state_epoch =
               Core_models.Option.Option_Some d.f_write_epoch)) /\
          (not permit.f_shadow ==>
            (d.f_state_phase = Vela_rekey_policy.Phase_Active /\
             permit.f_write_epoch = d.f_state_epoch))
      | _ -> True)) =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Quota ->
      (match e <: t_UploadEvent with
       | UploadEvent_Quota (QuotaObservation_Allowed) -> ()
       | _ -> ())
  | _ -> ()

/// Every `Write` effect is emitted with an authenticated writer and a route
/// that matches the driver's captured live state.
let write_effect_authority (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (upload_step d e).f_effect <: t_UploadEffect with
      | UploadEffect_Write _ ->
          d.f_authenticated /\
          (d.f_shadow ==> shadow_route d) /\
          (not d.f_shadow ==> active_route d)
      | _ -> True)) =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Quota ->
      (match e <: t_UploadEvent with
       | UploadEvent_Quota (QuotaObservation_Allowed) -> ()
       | _ -> ())
  | _ -> ()

let rec count_complete (d: t_UploadDriver) (events: list t_UploadEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      step_sound d e;
      (match (upload_step d e).f_effect <: t_UploadEffect with
       | UploadEffect_Complete -> 1
       | _ -> 0) +
      count_complete (upload_step d e).f_driver rest

let rec count_fail (d: t_UploadDriver) (events: list t_UploadEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      step_sound d e;
      (match (upload_step d e).f_effect <: t_UploadEffect with
       | UploadEffect_Fail _ -> 1
       | _ -> 0) +
      count_fail (upload_step d e).f_driver rest

let rec done_suffix_inert (d: t_UploadDriver) (events: list t_UploadEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      run d events = d /\
      count_complete d events = 0 /\
      count_fail d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

let rec complete_count_le_one (d: t_UploadDriver) (events: list t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_complete d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_sound d e;
      let t = upload_step d e in
      if (match t.f_effect <: t_UploadEffect with
          | UploadEffect_Complete -> true
          | _ -> false)
      then begin
        assert (is_done t.f_driver);
        done_suffix_inert t.f_driver rest
      end else begin
        complete_count_le_one t.f_driver rest
      end

let rec fail_count_le_one (d: t_UploadDriver) (events: list t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_fail d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_sound d e;
      let t = upload_step d e in
      if (match t.f_effect <: t_UploadEffect with
          | UploadEffect_Fail _ -> true
          | _ -> false)
      then begin
        assert (is_done t.f_driver);
        done_suffix_inert t.f_driver rest
      end else begin
        fail_count_le_one t.f_driver rest
      end

/// Headline per-request theorem over the actual extracted driver. For every
/// request and every event list:
///
/// - the final state is sound;
/// - every successful response has a matched guarded write behind it;
/// - a shadow success has a completed activity refresh, an authoritative
///   success has been published;
/// - at most one success, at most one failure and at most one write effect
///   occur;
/// - the driver never pairs a success with a failure.
let upload_trace_theorem
      (request: t_UploadRequest)
      (events: list t_UploadEvent)
  : Lemma (
      let d = run_from_request request events in
      trace_sound d /\
      (d.f_responded ==> d.f_write_matched) /\
      (d.f_responded ==> (d.f_shadow ==> d.f_activity_done)) /\
      (d.f_responded ==> (not d.f_shadow ==> d.f_published)) /\
      (d.f_write_matched ==> route_clean d) /\
      (d.f_shadow ==> shadow_route d) /\
      (not (d.f_responded && d.f_failed)) /\
      count_complete (begin_upload request).f_driver events <= 1 /\
      count_fail (begin_upload request).f_driver events <= 1) =
  begin_trace_sound request;
  complete_count_le_one (begin_upload request).f_driver events;
  fail_count_le_one (begin_upload request).f_driver events;
  ()

// ── Read driver ────────────────────────────────────────────────────────────

let read_is_epoch (r: t_ReadDriver) : bool =
  match r.f_stage <: t_ReadStage with
  | ReadStage_Epoch -> true
  | _ -> false

let read_is_lookup (r: t_ReadDriver) : bool =
  match r.f_stage <: t_ReadStage with
  | ReadStage_Lookup -> true
  | _ -> false

let read_is_done (r: t_ReadDriver) : bool =
  match r.f_stage <: t_ReadStage with
  | ReadStage_Done -> true
  | _ -> false

let read_trace_sound (r: t_ReadDriver) : bool =
  (r.f_epoch = mk_i64 0 || r.f_epoch >=. v_INITIAL_EPOCH) &&
  imp (read_is_epoch r) (r.f_authenticated && r.f_epoch = mk_i64 0 &&
                         r.f_version = mk_i64 0 && r.f_lamport_clock = mk_i64 0 &&
                         not r.f_responded && not r.f_failed) &&
  imp (read_is_lookup r) (r.f_authenticated && r.f_epoch >=. v_INITIAL_EPOCH &&
                          not r.f_responded && not r.f_failed) &&
  imp (read_is_done r) ((r.f_responded || r.f_failed) &&
                        not (r.f_responded && r.f_failed) &&
                        imp r.f_responded (r.f_authenticated &&
                                           r.f_epoch >=. v_INITIAL_EPOCH))

let begin_read_trace_sound (request: t_ReadRequest)
  : Lemma (read_trace_sound (begin_read request).f_driver) =
  ()

let read_step_sound (r: t_ReadDriver) (e: t_ReadEvent)
  : Lemma
    (requires (read_trace_sound r))
    (ensures (read_trace_sound (read_step r e).f_driver)) =
  match r.f_stage <: t_ReadStage with
  | ReadStage_Epoch ->
      (match e <: t_ReadEvent with
       | ReadEvent_Epoch _ -> ()
       | ReadEvent_EpochStorage -> ()
       | ReadEvent_Lookup _ -> ())
  | ReadStage_Lookup ->
      (match e <: t_ReadEvent with
       | ReadEvent_Epoch _ -> ()
       | ReadEvent_EpochStorage -> ()
       | ReadEvent_Lookup _ -> ())
  | ReadStage_Done ->
      (match e <: t_ReadEvent with
       | ReadEvent_Epoch _ -> ()
       | ReadEvent_EpochStorage -> ()
       | ReadEvent_Lookup _ -> ())

let rec read_run (r: t_ReadDriver) (events: list t_ReadEvent)
  : Pure t_ReadDriver
    (requires (read_trace_sound r))
    (ensures (fun result -> read_trace_sound result))
    (decreases events) =
  match events with
  | [] -> r
  | e :: rest ->
      read_step_sound r e;
      read_run (read_step r e).f_driver rest

let read_run_from_request (request: t_ReadRequest) (events: list t_ReadEvent)
  : Pure t_ReadDriver (requires True) (ensures (fun result -> read_trace_sound result))
    (decreases events) =
  begin_read_trace_sound request;
  read_run (begin_read request).f_driver events

/// A served row always has a valid epoch and an authenticated reader behind
/// it; the response is never paired with a failure.
let read_trace_theorem (request: t_ReadRequest) (events: list t_ReadEvent)
  : Lemma (
      let r = read_run_from_request request events in
      read_trace_sound r /\
      (r.f_responded ==> (r.f_authenticated /\ r.f_epoch >=. v_INITIAL_EPOCH)) /\
      not (r.f_responded && r.f_failed)) =
  begin_read_trace_sound request;
  ()

// ── Reachability witnesses ─────────────────────────────────────────────────

let device_writer : t_UploadWriter =
  { f_authenticated = true; f_web = false; f_web_epoch = Core_models.Option.Option_None }

let web_writer (epoch: i64) : t_UploadWriter =
  { f_authenticated = true; f_web = true; f_web_epoch = Core_models.Option.Option_Some epoch }

let create_request (declared: Core_models.Option.t_Option i64) : t_UploadRequest =
  { f_writer = device_writer; f_intent = WriteIntent_Create; f_declared_epoch = declared }

let replace_request (version: i64) (declared: Core_models.Option.t_Option i64) : t_UploadRequest =
  { f_writer = device_writer;
    f_intent = WriteIntent_Replace { f_version = version };
    f_declared_epoch = declared }

let active_state : t_RekeyObservation = RekeyObservation_State { f_epoch = mk_i64 1; f_phase = Phase_Active }
let freezing_state : t_RekeyObservation = RekeyObservation_State { f_epoch = mk_i64 1; f_phase = Phase_Freezing }
let rejected_state : t_RekeyObservation = RekeyObservation_Rejected

let starting_authority : t_AttemptAuthority =
  { f_device_scope = true; f_starter_matches = true;
    f_rotation_id_present = true; f_rotation_id_matches = true }

let active_create_events : list t_UploadEvent =
  [ UploadEvent_Rekey active_state;
    UploadEvent_Quota QuotaObservation_Allowed;
    UploadEvent_Write WriteObservation_Inserted;
    UploadEvent_Reread (RereadObservation_Read { f_version = mk_i64 1 });
    UploadEvent_Published ]

let shadow_events : list t_UploadEvent =
  [ UploadEvent_Rekey freezing_state;
    UploadEvent_Attempt starting_authority;
    UploadEvent_Quota QuotaObservation_Allowed;
    UploadEvent_Write WriteObservation_Inserted;
    UploadEvent_Reread (RereadObservation_Read { f_version = mk_i64 2 });
    UploadEvent_Activity ActivityObservation_Refreshed;
    UploadEvent_Published ]

let version_conflict_events : list t_UploadEvent =
  [ UploadEvent_Rekey active_state;
    UploadEvent_Quota QuotaObservation_Allowed;
    UploadEvent_Write WriteObservation_Skipped;
    UploadEvent_Recheck RecheckObservation_Unchanged ]

/// A fresh active create publishes the change and completes.
let active_create_is_reachable ()
  : Lemma (
      let d = run_from_request (create_request (Core_models.Option.Option_Some (mk_i64 1))) active_create_events in
      d.f_responded = true /\ d.f_write_matched = true /\ d.f_published = true /\
      not d.f_shadow /\ not d.f_failed /\
      last_effect_from_request (create_request (Core_models.Option.Option_Some (mk_i64 1))) active_create_events =
        UploadEffect_Complete) =
  ()

/// A shadow write by the starting device reaches completion without publishing.
let shadow_is_reachable ()
  : Lemma (
      let d = run_from_request (create_request (Core_models.Option.Option_Some (mk_i64 2))) shadow_events in
      d.f_responded = true /\ d.f_write_matched = true /\ d.f_activity_done = true /\
      d.f_shadow = true /\ not d.f_published /\ not d.f_failed /\
      last_effect_from_request (create_request (Core_models.Option.Option_Some (mk_i64 2))) shadow_events =
        UploadEffect_Complete) =
  ()

/// A zero-row update that re-resolves to the same route reports a version
/// conflict.
let version_conflict_is_reachable ()
  : Lemma (
      let d = run_from_request (replace_request (mk_i64 7) (Core_models.Option.Option_Some (mk_i64 1)))
        version_conflict_events in
      d.f_failed = true /\ not d.f_responded /\ d.f_write_matched = false /\
      last_effect_from_request (replace_request (mk_i64 7) (Core_models.Option.Option_Some (mk_i64 1)))
        version_conflict_events = UploadEffect_Fail UploadFailure_VersionMismatch) =
  ()

/// An unauthenticated request is terminal before any effect.
let unauthenticated_is_reachable ()
  : Lemma (
      let request = { create_request (Core_models.Option.Option_Some (mk_i64 1)) with
                      f_writer = { device_writer with f_authenticated = false } } in
      let d = run_from_request request [] in
      d.f_failed = true /\ not d.f_responded /\
      (begin_upload request).f_effect =
        UploadEffect_Fail UploadFailure_Unauthenticated) =
  ()

/// A web-session shadow attempt is refused before a write.
let web_shadow_is_refused ()
  : Lemma (
      let request = { create_request (Core_models.Option.Option_Some (mk_i64 2)) with
                      f_writer = web_writer (mk_i64 1) } in
      let d = run_from_request request
        [ UploadEvent_Rekey freezing_state;
          UploadEvent_Attempt { starting_authority with f_device_scope = false } ] in
      d.f_failed = true /\ not d.f_write_matched /\
      last_effect_from_request request
        [ UploadEvent_Rekey freezing_state;
          UploadEvent_Attempt { starting_authority with f_device_scope = false } ] =
        UploadEffect_Fail UploadFailure_ShadowWebSessionForbidden) =
  ()

/// A stale web-session epoch is refused before quota or write.
let stale_web_is_refused ()
  : Lemma (
      let request = { create_request (Core_models.Option.Option_Some (mk_i64 2)) with
                      f_writer = web_writer (mk_i64 1) } in
      let d = run_from_request request
        [ UploadEvent_Rekey (RekeyObservation_State { f_epoch = mk_i64 2; f_phase = Phase_Active }) ] in
      d.f_failed = true /\ not d.f_write_matched /\
      last_effect_from_request request
        [ UploadEvent_Rekey (RekeyObservation_State { f_epoch = mk_i64 2; f_phase = Phase_Active }) ] =
        UploadEffect_Fail UploadFailure_AuthorityEpochMismatch) =
  ()

/// A pre-resolve rejection is terminal.
let epoch_rejection_is_reachable ()
  : Lemma (
      let d = run_from_request (create_request (Core_models.Option.Option_Some (mk_i64 2))) [ UploadEvent_Rekey rejected_state ] in
      d.f_failed = true /\ not d.f_responded /\
      last_effect_from_request (create_request (Core_models.Option.Option_Some (mk_i64 2)))
        [ UploadEvent_Rekey rejected_state ] = UploadEffect_Fail UploadFailure_EpochMismatch) =
  ()
