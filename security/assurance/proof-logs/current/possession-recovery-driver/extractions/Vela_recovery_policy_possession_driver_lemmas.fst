module Vela_recovery_policy_possession_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* possession-proof
/// recovery drivers (`Vela_recovery_policy.Possession_driver.step_initiation`
/// and `.step_proof_recover`).
///
/// Scope: one `InitiationDriver` / `ProofRecoverDriver` value, i.e. one HTTP
/// request. The theorem does not compose concurrent requests sharing a proof
/// state; that is `possession-driver-composition`. The atomic store `get_del`,
/// the `set_ex_nx` challenge store, the `users` row query, the cryptographic
/// verification, the grant store and the rate-limit counters remain effectful
/// glue outside this module. Their inputs are observations, never verified
/// origins.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `proof_recover_state_is_sound` and proved equivalent to it;
/// all trace lemmas then quantify over every event list.

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Possession_driver

// ── Initiation: independent state invariant ────────────────────────────────

let is_observe (d: t_InitiationDriver) : bool =
  match d.f_stage <: t_InitiateStage with
  | InitiateStage_Observe -> true
  | _ -> false

let is_store (d: t_InitiationDriver) : bool =
  match d.f_stage <: t_InitiateStage with
  | InitiateStage_Store -> true
  | _ -> false

let is_initiation_done (d: t_InitiationDriver) : bool =
  match d.f_stage <: t_InitiateStage with
  | InitiateStage_Done -> true
  | _ -> false

let initiation_trace_sound (d: t_InitiationDriver) : bool =
  (not (is_observe d) || (not d.f_authorized && not d.f_stored)) &&
  (not (is_store d) || (d.f_authorized && not d.f_stored)) &&
  (not d.f_stored || is_initiation_done d)

let initiation_trace_sound_matches_rust (d: t_InitiationDriver)
  : Lemma (initiation_trace_sound d = initiation_state_is_sound d) =
  match d.f_stage <: t_InitiateStage with
  | InitiateStage_Observe -> ()
  | InitiateStage_Store -> ()
  | InitiateStage_Done -> ()

let initiation_begin_sound ()
  : Lemma (initiation_trace_sound (begin_initiation ()).f_driver) =
  initiation_trace_sound_matches_rust (begin_initiation ()).f_driver

let initiation_step_sound (d: t_InitiationDriver) (e: t_InitiateEvent)
  : Lemma
    (requires (initiation_trace_sound d))
    (ensures (initiation_trace_sound (step_initiation d e).f_driver)) =
  initiation_trace_sound_matches_rust d;
  assert (initiation_state_is_sound d = true);
  initiation_trace_sound_matches_rust (step_initiation d e).f_driver

let rec run_initiation (d: t_InitiationDriver) (events: list t_InitiateEvent)
  : Pure t_InitiationDriver
    (requires (initiation_trace_sound d))
    (ensures (fun result -> initiation_trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      initiation_step_sound d e;
      run_initiation (step_initiation d e).f_driver rest

let rec count_challenge_stores (d: t_InitiationDriver) (events: list t_InitiateEvent)
  : Pure nat
    (requires (initiation_trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      initiation_step_sound d e;
      (match (step_initiation d e).f_effect <: t_InitiateEffect with
       | InitiateEffect_StoreChallenge -> 1
       | _ -> 0) +
      count_challenge_stores (step_initiation d e).f_driver rest

let run_initiation_from_begin (events: list t_InitiateEvent)
  : Pure t_InitiationDriver
    (requires True)
    (ensures (fun result -> initiation_trace_sound result))
    (decreases events) =
  initiation_begin_sound ();
  run_initiation (begin_initiation ()).f_driver events

let count_challenge_stores_from_begin (events: list t_InitiateEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  initiation_begin_sound ();
  count_challenge_stores (begin_initiation ()).f_driver events

/// A `StoreChallenge` effect is only produced by an observation the checked
/// policy admitted, and leaves the driver authorized at `Store`.
let initiation_store_requires_authority (d: t_InitiationDriver) (e: t_InitiateEvent)
  : Lemma
    (requires (initiation_trace_sound d))
    (ensures (
      match (step_initiation d e).f_effect <: t_InitiateEffect with
      | InitiateEffect_StoreChallenge ->
          (step_initiation d e).f_driver.f_authorized /\
          is_store (step_initiation d e).f_driver /\
          not (step_initiation d e).f_driver.f_stored
      | _ -> True)) =
  initiation_trace_sound_matches_rust d;
  assert (initiation_state_is_sound d = true);
  ()

/// Once the driver is at `Store` or `Done`, no later event can emit another
/// `StoreChallenge`.
let rec no_store_from_store (d: t_InitiationDriver) (events: list t_InitiateEvent)
  : Lemma
    (requires (initiation_trace_sound d /\ (is_store d || is_initiation_done d)))
    (ensures (count_challenge_stores d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      initiation_step_sound d e;
      no_store_from_store (step_initiation d e).f_driver rest

/// At most one challenge is ever stored by one initiation driver, for every
/// event list.
let rec initiation_store_count_le_one (d: t_InitiationDriver) (events: list t_InitiateEvent)
  : Lemma
    (requires (initiation_trace_sound d))
    (ensures (count_challenge_stores d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      initiation_trace_sound_matches_rust d;
      initiation_step_sound d e;
      let t = step_initiation d e in
      if (match t.f_effect <: t_InitiateEffect with
          | InitiateEffect_StoreChallenge -> true
          | _ -> false)
      then begin
        assert (t.f_driver.f_stored = false);
        assert (is_store t.f_driver = true);
        no_store_from_store t.f_driver rest
      end else begin
        initiation_store_count_le_one t.f_driver rest
      end

let initiation_trace_theorem (events: list t_InitiateEvent)
  : Lemma (
      let d = run_initiation_from_begin events in
      initiation_trace_sound d /\
      count_challenge_stores_from_begin events <= 1 /\
      (d.f_stored ==> is_initiation_done d)) =
  initiation_begin_sound ();
  initiation_store_count_le_one (begin_initiation ()).f_driver events;
  ()

// ── Proof recovery: independent state invariant ─────────────────────────────

let is_attempt (d: t_ProofRecoverDriver) : bool =
  match d.f_stage <: t_ProofRecoverStage with
  | ProofRecoverStage_Attempt -> true
  | _ -> false

let is_consume (d: t_ProofRecoverDriver) : bool =
  match d.f_stage <: t_ProofRecoverStage with
  | ProofRecoverStage_Consume -> true
  | _ -> false

let is_live (d: t_ProofRecoverDriver) : bool =
  match d.f_stage <: t_ProofRecoverStage with
  | ProofRecoverStage_Live -> true
  | _ -> false

let is_verify (d: t_ProofRecoverDriver) : bool =
  match d.f_stage <: t_ProofRecoverStage with
  | ProofRecoverStage_Verify -> true
  | _ -> false

let is_issue (d: t_ProofRecoverDriver) : bool =
  match d.f_stage <: t_ProofRecoverStage with
  | ProofRecoverStage_Issue -> true
  | _ -> false

let is_done (d: t_ProofRecoverDriver) : bool =
  match d.f_stage <: t_ProofRecoverStage with
  | ProofRecoverStage_Done -> true
  | _ -> false

/// Strengthened trace invariant, independently written. It encodes the
/// stage/flag discipline: an attempt is counted before the proof state is
/// consumed, a binding mismatch is terminal, verification needs a live current
/// account, and a grant needs a matched, consumed, verified proof at the live
/// epoch with a non-empty commitment.
let trace_sound (d: t_ProofRecoverDriver) : bool =
  let attempt_clean =
    not d.f_budget_counted && not d.f_attempt_consumed &&
    not d.f_proof_verified && not d.f_grant_issued && not d.f_grant_stored in
  let consume_clean =
    d.f_budget_counted && not d.f_attempt_consumed &&
    not d.f_proof_verified && not d.f_grant_issued && not d.f_grant_stored in
  let live_clean =
    d.f_budget_counted && d.f_attempt_consumed &&
    d.f_user_matches && d.f_attempt_matches &&
    not d.f_proof_verified && not d.f_grant_issued && not d.f_grant_stored in
  let verify_clean =
    live_clean && d.f_account_present && d.f_account_epoch_active &&
    d.f_commitment_present in
  let issue_clean =
    d.f_budget_counted && d.f_attempt_consumed &&
    d.f_user_matches && d.f_attempt_matches &&
    d.f_account_present && d.f_account_epoch_active &&
    d.f_commitment_present && d.f_proof_verified &&
    d.f_grant_issued && not d.f_grant_stored in
  (not (is_attempt d) || attempt_clean) &&
  (not (is_consume d) || consume_clean) &&
  (not (is_live d) || live_clean) &&
  (not (is_verify d) || verify_clean) &&
  (not (is_issue d) || issue_clean) &&
  (not d.f_attempt_consumed || d.f_budget_counted) &&
  (not (d.f_user_matches || d.f_attempt_matches) || d.f_attempt_consumed) &&
  (not d.f_proof_verified ||
    (d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches)) &&
  (not d.f_grant_issued ||
    (d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
     d.f_proof_verified && d.f_account_present && d.f_account_epoch_active &&
     d.f_commitment_present && d.f_commitment_len >. mk_usize 0 &&
     d.f_attempt_epoch = observed_recovery_epoch d.f_stored_epoch &&
     (is_issue d || is_done d))) &&
  (not d.f_grant_stored || (d.f_grant_issued && is_done d))

/// The independently written invariant is exactly the Rust postcondition's
/// predicate. Proved by exhaustive stage case analysis.
let trace_sound_matches_rust (d: t_ProofRecoverDriver)
  : Lemma (trace_sound d = proof_recover_state_is_sound d) =
  match d.f_stage <: t_ProofRecoverStage with
  | ProofRecoverStage_Attempt -> ()
  | ProofRecoverStage_Consume -> ()
  | ProofRecoverStage_Live -> ()
  | ProofRecoverStage_Verify -> ()
  | ProofRecoverStage_Issue -> ()
  | ProofRecoverStage_Done -> ()

let begin_sound ()
  : Lemma (trace_sound (begin_proof_recover ()).f_driver) =
  trace_sound_matches_rust (begin_proof_recover ()).f_driver

let step_sound (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step_proof_recover d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (proof_recover_state_is_sound d = true);
  trace_sound_matches_rust (step_proof_recover d e).f_driver

// ── Unbounded trace execution ───────────────────────────────────────────────

let issued (e: t_ProofRecoverEffect) : nat =
  match e <: t_ProofRecoverEffect with
  | ProofRecoverEffect_IssueGrant _ -> 1
  | _ -> 0

let rec run (d: t_ProofRecoverDriver) (events: list t_ProofRecoverEvent)
  : Pure t_ProofRecoverDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step_proof_recover d e).f_driver rest

let rec count_grants (d: t_ProofRecoverDriver) (events: list t_ProofRecoverEvent)
  : Pure nat
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      issued (step_proof_recover d e).f_effect +
      count_grants (step_proof_recover d e).f_driver rest

let rec last_effect (d: t_ProofRecoverDriver) (events: list t_ProofRecoverEvent)
  : Pure t_ProofRecoverEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> ProofRecoverEffect_Idle
  | e :: [] -> (step_proof_recover d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step_proof_recover d e).f_driver rest

let run_from_begin (events: list t_ProofRecoverEvent)
  : Pure t_ProofRecoverDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_sound ();
  run (begin_proof_recover ()).f_driver events

let count_grants_from_begin (events: list t_ProofRecoverEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound ();
  count_grants (begin_proof_recover ()).f_driver events

let last_effect_from_begin (events: list t_ProofRecoverEvent)
  : Pure t_ProofRecoverEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound ();
  last_effect (begin_proof_recover ()).f_driver events

// ── Decision provenance and trace properties ────────────────────────────────

/// The checked possession policy is the authority: if it grants, the proof
/// observation it was built from was verified.
let plan_grant_requires_verified (obs: t_PossessionRecoverObservation)
  : Lemma
    (requires (
      match plan_possession_recovery (possession_recover_facts obs)
            <: t_PossessionRecoverDecision with
      | PossessionRecoverDecision_Grant _ -> True
      | PossessionRecoverDecision_Reject -> False))
    (ensures obs.f_proof_verified) =
  let facts = possession_recover_facts obs in
  let decision = plan_possession_recovery facts in
  assert (possession_recovery_decision_matches_spec facts decision);
  match decision <: t_PossessionRecoverDecision with
  | PossessionRecoverDecision_Grant _ ->
      assert (possession_recovery_is_authorized facts);
      assert (facts.f_proof_verified)
  | PossessionRecoverDecision_Reject -> ()

/// A grant is issued only in response to a verified `ProofObserved` event, and
/// the resulting driver carries a matched, single-use, current-epoch proof.
let grant_effect_origin (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step_proof_recover d e).f_effect <: t_ProofRecoverEffect with
      | ProofRecoverEffect_IssueGrant _ ->
          (match e <: t_ProofRecoverEvent with
           | ProofRecoverEvent_ProofObserved obs ->
               obs.f_verified /\
               is_verify d /\
               d.f_attempt_consumed /\
               d.f_user_matches /\
               d.f_attempt_matches /\
               (step_proof_recover d e).f_driver.f_grant_issued /\
               (step_proof_recover d e).f_driver.f_proof_verified /\
               (step_proof_recover d e).f_driver.f_account_present /\
               (step_proof_recover d e).f_driver.f_account_epoch_active /\
               (step_proof_recover d e).f_driver.f_commitment_present /\
               (step_proof_recover d e).f_driver.f_commitment_len >. mk_usize 0
           | _ -> False)
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (proof_recover_state_is_sound d = true);
  match e <: t_ProofRecoverEvent with
  | ProofRecoverEvent_AttemptCounted _ -> ()
  | ProofRecoverEvent_AttemptConsumed _ -> ()
  | ProofRecoverEvent_AccountObserved _ -> ()
  | ProofRecoverEvent_ProofObserved obs ->
      if is_verify d then begin
        let facts = possession_recover_facts
          ({
             f_attempt_source = RecoveryAttemptSource_Consumed <: t_RecoveryAttemptSource;
             f_account_present = true;
             f_user_matches = d.f_user_matches;
             f_attempt_matches = d.f_attempt_matches;
             f_proof_verified = obs.f_verified;
             f_account_epoch_active = true;
             f_commitment_len = d.f_commitment_len;
             f_commitment_epoch = d.f_attempt_epoch;
             f_stored_epoch = d.f_stored_epoch
           } <: t_PossessionRecoverObservation) in
        match plan_possession_recovery facts <: t_PossessionRecoverDecision with
        | PossessionRecoverDecision_Grant _ ->
            plan_grant_requires_verified
              ({
                 f_attempt_source = RecoveryAttemptSource_Consumed <: t_RecoveryAttemptSource;
                 f_account_present = true;
                 f_user_matches = d.f_user_matches;
                 f_attempt_matches = d.f_attempt_matches;
                 f_proof_verified = obs.f_verified;
                 f_account_epoch_active = true;
                 f_commitment_len = d.f_commitment_len;
                 f_commitment_epoch = d.f_attempt_epoch;
                 f_stored_epoch = d.f_stored_epoch
               } <: t_PossessionRecoverObservation)
        | PossessionRecoverDecision_Reject -> ()
      end
  | ProofRecoverEvent_GrantStored _ -> ()

/// The grant permit's epoch is exactly the live observed epoch, and the policy
/// authorization implies that epoch is at least `INITIAL_EPOCH`.
let grant_effect_epoch (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
    (permit: t_ProofGrantPermit)
  : Lemma
    (requires (
      trace_sound d /\
      (step_proof_recover d e).f_effect = ProofRecoverEffect_IssueGrant permit))
    (ensures (
      permit.f_epoch = observed_recovery_epoch d.f_stored_epoch /\
      permit.f_epoch = d.f_attempt_epoch /\
      permit.f_epoch >=. v_INITIAL_EPOCH)) =
  trace_sound_matches_rust d;
  assert (proof_recover_state_is_sound d = true);
  match e <: t_ProofRecoverEvent with
  | ProofRecoverEvent_ProofObserved obs ->
      let facts = possession_recover_facts
        ({
           f_attempt_source = RecoveryAttemptSource_Consumed <: t_RecoveryAttemptSource;
           f_account_present = true;
           f_user_matches = d.f_user_matches;
           f_attempt_matches = d.f_attempt_matches;
           f_proof_verified = obs.f_verified;
           f_account_epoch_active = true;
           f_commitment_len = d.f_commitment_len;
           f_commitment_epoch = d.f_attempt_epoch;
           f_stored_epoch = d.f_stored_epoch
         } <: t_PossessionRecoverObservation) in
      assert (possession_recovery_is_authorized facts)
  | _ -> ()

/// No grant while freezing/rotation is active: the live account observation is
/// terminal before verification.
let no_grant_while_freezing (d: t_ProofRecoverDriver)
    (obs: t_ProofAccountObservation)
  : Lemma
    (requires (trace_sound d /\ not obs.f_account_epoch_active))
    (ensures (
      match (step_proof_recover d (ProofRecoverEvent_AccountObserved obs)).f_effect
            <: t_ProofRecoverEffect with
      | ProofRecoverEffect_IssueGrant _ -> False
      | _ -> True)) =
  ()

/// No grant after commitment revocation: a missing or corrupt staged commitment
/// never reaches verification.
let no_grant_after_revocation (d: t_ProofRecoverDriver)
    (obs: t_ProofAccountObservation)
  : Lemma
    (requires (
      trace_sound d /\
      (match obs.f_commitment <: t_CommitmentObservation with
       | CommitmentObservation_Missing -> True
       | CommitmentObservation_Corrupt -> True
       | _ -> False)))
    (ensures (
      match (step_proof_recover d (ProofRecoverEvent_AccountObserved obs)).f_effect
            <: t_ProofRecoverEffect with
      | ProofRecoverEffect_IssueGrant _ -> False
      | _ -> True)) =
  ()

/// The share is never an effect: the effect language has no release variant,
/// and the only grant-carrying effect cannot release it either.
let no_effect_releases_share (e: t_ProofRecoverEffect)
  : Lemma (not (proof_recover_effect_releases_share e)) =
  match e <: t_ProofRecoverEffect with
  | ProofRecoverEffect_CountAttempt -> ()
  | ProofRecoverEffect_ConsumeAttempt -> ()
  | ProofRecoverEffect_QueryAccount -> ()
  | ProofRecoverEffect_VerifyProof -> ()
  | ProofRecoverEffect_IssueGrant _ -> ()
  | ProofRecoverEffect_Complete -> ()
  | ProofRecoverEffect_Fail _ -> ()
  | ProofRecoverEffect_Idle -> ()

let step_never_releases_share (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (not (proof_recover_effect_releases_share (step_proof_recover d e).f_effect))) =
  trace_sound_matches_rust d;
  assert (proof_recover_state_is_sound d = true);
  no_effect_releases_share (step_proof_recover d e).f_effect

/// After a grant is issued, no later event can issue another one.
let no_grant_after_issue (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_grant_issued))
    (ensures (issued (step_proof_recover d e).f_effect = 0)) =
  trace_sound_matches_rust d;
  match e <: t_ProofRecoverEvent with
  | ProofRecoverEvent_AttemptCounted _ -> ()
  | ProofRecoverEvent_AttemptConsumed _ -> ()
  | ProofRecoverEvent_AccountObserved _ -> ()
  | ProofRecoverEvent_ProofObserved _ -> ()
  | ProofRecoverEvent_GrantStored _ -> ()

let rec issue_suffix_no_grants (d: t_ProofRecoverDriver)
                               (events: list t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_grant_issued))
    (ensures (count_grants d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      no_grant_after_issue d e;
      issue_suffix_no_grants (step_proof_recover d e).f_driver rest

/// After a stored grant the driver is terminal: every event is inert.
let step_after_complete (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_grant_stored))
    (ensures (
      (step_proof_recover d e).f_driver = d /\
      (step_proof_recover d e).f_effect = ProofRecoverEffect_Idle)) =
  trace_sound_matches_rust d;
  assert (is_done d = true);
  match e <: t_ProofRecoverEvent with
  | ProofRecoverEvent_AttemptCounted _ -> ()
  | ProofRecoverEvent_AttemptConsumed _ -> ()
  | ProofRecoverEvent_AccountObserved _ -> ()
  | ProofRecoverEvent_ProofObserved _ -> ()
  | ProofRecoverEvent_GrantStored _ -> ()

let rec complete_suffix_inert (d: t_ProofRecoverDriver)
                              (events: list t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d /\ d.f_grant_stored))
    (ensures (run d events = d /\ count_grants d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_complete d e;
      complete_suffix_inert d rest

/// At most one grant per driver instance, for an arbitrary event list.
let rec grant_count_le_one (d: t_ProofRecoverDriver)
                           (events: list t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_grants d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step_proof_recover d e in
      if (match t.f_effect <: t_ProofRecoverEffect with
          | ProofRecoverEffect_IssueGrant _ -> true
          | _ -> false)
      then begin
        assert (t.f_driver.f_grant_issued = true);
        issue_suffix_no_grants t.f_driver rest
      end else begin
        grant_count_le_one t.f_driver rest
      end

/// All-pairs corollary: after any prefix that issued a grant, every unbounded
/// suffix issues no further grant.
let no_second_grant_after_prefix
      (pre: list t_ProofRecoverEvent)
      (suffix: list t_ProofRecoverEvent)
  : Lemma
    (requires (let d = run_from_begin pre in d.f_grant_issued))
    (ensures (
      let d = run_from_begin pre in
      count_grants d suffix = 0)) =
  let d = run_from_begin pre in
  begin_sound ();
  issue_suffix_no_grants d suffix

/// Headline per-request theorem over the actual extracted driver. For every
/// event list the final state is sound, at most one grant was issued, and a
/// grant state carries a consumed, matched, verified, non-empty current-epoch
/// proof. The server share is never an effect.
let proof_recover_trace_theorem (events: list t_ProofRecoverEvent)
  : Lemma (
      let d = run_from_begin events in
      trace_sound d /\
      count_grants_from_begin events <= 1 /\
      (d.f_grant_issued ==>
        (d.f_attempt_consumed /\
         d.f_user_matches /\
         d.f_attempt_matches /\
         d.f_proof_verified /\
         d.f_account_present /\
         d.f_account_epoch_active /\
         d.f_commitment_present /\
         d.f_commitment_len >. mk_usize 0 /\
         d.f_attempt_epoch = observed_recovery_epoch d.f_stored_epoch)) /\
      (d.f_grant_stored ==> d.f_grant_issued)) =
  begin_sound ();
  trace_sound_matches_rust (begin_proof_recover ()).f_driver;
  grant_count_le_one (begin_proof_recover ()).f_driver events;
  ()

// ── Reachability witnesses ──────────────────────────────────────────────────

let ready_commitment (len: usize) : t_CommitmentObservation =
  CommitmentObservation_Present { f_len = len }

let available_initiation : t_InitiateObservation =
  {
    f_account_present = true;
    f_share_present = true;
    f_commitment = ready_commitment (mk_usize 2624);
    f_rotation_active = false;
    f_attempt_id_fresh = true;
    f_ttl_secs = mk_u64 300;
  }

let initiation_start_events : list t_InitiateEvent =
  [ InitiateEvent_Observed available_initiation;
    InitiateEvent_Stored ChallengeStoreObservation_Stored ]

/// A real initiation is reachable and stores exactly one challenge.
let initiation_success_is_reachable ()
  : Lemma (
      let d = run_initiation_from_begin initiation_start_events in
      d.f_stored = true /\ is_initiation_done d /\
      count_challenge_stores_from_begin initiation_start_events = 1) =
  ()

/// A collision is reachable and terminal without a store.
let initiation_collision_is_reachable ()
  : Lemma (
      let events =
        [ InitiateEvent_Observed
            ({ available_initiation with f_attempt_id_fresh = false }) ] in
      let d = run_initiation_from_begin events in
      d.f_stored = false /\ is_initiation_done d /\
      count_challenge_stores_from_begin events = 0) =
  ()

/// An unavailable account is reachable and stores nothing.
let initiation_unavailable_is_reachable ()
  : Lemma (
      let events =
        [ InitiateEvent_Observed
            ({ available_initiation with f_account_present = false }) ] in
      let d = run_initiation_from_begin events in
      d.f_stored = false /\ is_initiation_done d) =
  ()

let matched_attempt : t_AttemptConsumptionObservation =
  AttemptConsumptionObservation_Present
    ({ f_user_matches = true; f_attempt_matches = true; f_key_epoch = mk_i64 3 })

let stale_attempt : t_AttemptConsumptionObservation =
  AttemptConsumptionObservation_Present
    ({ f_user_matches = true; f_attempt_matches = true; f_key_epoch = mk_i64 2 })

let active_account : t_ProofAccountObservation =
  {
    f_account_present = true;
    f_account_epoch_active = true;
    f_commitment = ready_commitment (mk_usize 2624);
    f_stored_epoch = Core_models.Option.Option_Some (mk_i64 3);
  }

let verified_proof : t_ProofObservation = { f_verified = true }
let rejected_proof : t_ProofObservation = { f_verified = false }

let success_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    ProofRecoverEvent_AttemptConsumed matched_attempt;
    ProofRecoverEvent_AccountObserved active_account;
    ProofRecoverEvent_ProofObserved verified_proof;
    ProofRecoverEvent_GrantStored GrantStoreObservation_Stored ]

let grant_failed_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    ProofRecoverEvent_AttemptConsumed matched_attempt;
    ProofRecoverEvent_AccountObserved active_account;
    ProofRecoverEvent_ProofObserved verified_proof;
    ProofRecoverEvent_GrantStored GrantStoreObservation_Failed ]

let limited_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Limited ]

let missing_attempt_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    ProofRecoverEvent_AttemptConsumed AttemptConsumptionObservation_Missing ]

let stale_attempt_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    ProofRecoverEvent_AttemptConsumed stale_attempt;
    ProofRecoverEvent_AccountObserved active_account;
    ProofRecoverEvent_ProofObserved verified_proof ]

let rotation_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    ProofRecoverEvent_AttemptConsumed matched_attempt;
    ProofRecoverEvent_AccountObserved
      ({ active_account with f_account_epoch_active = false }) ]

let revocation_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    ProofRecoverEvent_AttemptConsumed matched_attempt;
    ProofRecoverEvent_AccountObserved
      ({ active_account with
         f_commitment = CommitmentObservation_Missing }) ]

let bad_proof_events : list t_ProofRecoverEvent =
  [ ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted;
    ProofRecoverEvent_AttemptConsumed matched_attempt;
    ProofRecoverEvent_AccountObserved active_account;
    ProofRecoverEvent_ProofObserved rejected_proof ]

let success_is_reachable ()
  : Lemma (
      let d = run_from_begin success_events in
      d.f_grant_issued = true /\ d.f_grant_stored = true /\ is_done d /\
      count_grants_from_begin success_events = 1 /\
      d.f_proof_verified = true /\
      d.f_attempt_epoch = observed_recovery_epoch d.f_stored_epoch) =
  ()

let grant_storage_failure_is_reachable ()
  : Lemma (
      let d = run_from_begin grant_failed_events in
      d.f_grant_issued = true /\ d.f_grant_stored = false /\
      last_effect_from_begin grant_failed_events =
        ProofRecoverEffect_Fail ProofRecoverFailure_GrantStorage) =
  ()

let limited_attempt_is_reachable ()
  : Lemma (
      let d = run_from_begin limited_events in
      d.f_budget_counted = false /\ d.f_attempt_consumed = false /\
      d.f_grant_issued = false /\
      last_effect_from_begin limited_events =
        ProofRecoverEffect_Fail ProofRecoverFailure_AttemptLimited) =
  ()

let missing_attempt_is_reachable ()
  : Lemma (
      let d = run_from_begin missing_attempt_events in
      d.f_attempt_consumed = false /\ d.f_grant_issued = false /\
      last_effect_from_begin missing_attempt_events =
        ProofRecoverEffect_Fail ProofRecoverFailure_AttemptMissing) =
  ()

/// A verified proof at a stale envelope epoch is rejected: the grant epoch is
/// the live epoch, not the attempt's.
let stale_epoch_is_rejected ()
  : Lemma (
      let d = run_from_begin stale_attempt_events in
      d.f_proof_verified = true /\ d.f_grant_issued = false /\
      last_effect_from_begin stale_attempt_events =
        ProofRecoverEffect_Fail ProofRecoverFailure_ProofRejected) =
  ()

/// Freezing pauses recovery without a grant.
let freezing_is_reachable ()
  : Lemma (
      let d = run_from_begin rotation_events in
      d.f_grant_issued = false /\ d.f_attempt_consumed = true /\
      last_effect_from_begin rotation_events =
        ProofRecoverEffect_Fail ProofRecoverFailure_RotationPaused) =
  ()

/// Commitment revocation is terminal without a grant.
let revocation_is_reachable ()
  : Lemma (
      let d = run_from_begin revocation_events in
      d.f_grant_issued = false /\
      last_effect_from_begin revocation_events =
        ProofRecoverEffect_Fail ProofRecoverFailure_CommitmentMissing) =
  ()

/// An unverified proof is rejected without a grant.
let bad_proof_is_rejected ()
  : Lemma (
      let d = run_from_begin bad_proof_events in
      d.f_grant_issued = false /\
      last_effect_from_begin bad_proof_events =
        ProofRecoverEffect_Fail ProofRecoverFailure_ProofRejected) =
  ()
