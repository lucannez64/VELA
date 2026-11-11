module Vela_recovery_policy_webauthn_driver_composition

/// Concurrent composition of the *extracted* WebAuthn authentication-finish
/// driver (`Vela_recovery_policy.Webauthn_driver.step_auth_finish`).
///
/// One attempt-bound challenge and one rate-limit budget are shared by any
/// number of requests, each running its own driver. A schedule is an arbitrary
/// list of actions: spawn a request, count an attempt, observe the
/// pre-consumption context, consume the challenge, deliver the assertion /
/// credential-update / live-account / share-decode / grant-store observation to
/// any request.
///
/// The world abstracts the handler's effects:
///
/// - the rate limiter: `Count` spends one unit of the shared budget and is the
///   only way a request may reach the single-use consume; a refused request is
///   delivered `Limited` and must not mark its attempt counted;
/// - the store's atomic `get_del` (a `Consume` sees the challenge iff
///   `attempt_state` is still set, and clears it in the same step);
/// - the `users` row, the credential comparison, the WebAuthn verification and
///   the share decode, whose observations the schedule chooses;
/// - the single-use enrollment grant and the Share 2 release: one
///   `ReleaseGrant` driver effect converts the held challenge token into one
///   grant, and `Store` records the grant-store success.
///
/// Theorem: for every schedule and every initial budget `k`,
///
/// - at most one grant is authorized for the one challenge (`w.grants <= 1`);
/// - at most `k` attempts are counted (`counted w.w_reqs <= k`);
/// - the driver never authorizes a release from a live-account observation
///   that forbids it (`w.w_forbidden_release = 0`): no release while
///   freezing/rotating, after the stored credential was replaced, without a
///   present share, or without the challenge/assertion credential chain.
///
/// Every counter is incremented at the point the *driver* authorizes the
/// forbidden thing, never by a modelled store guard refusing a write:
/// `w.grants` and `w.w_forbidden_release` are keyed on the `ReleaseGrant`
/// effect, and `counted` is the sum of the drivers' own `budget_counted`
/// flags. The mutation notes in the evidence directory show each counter is
/// load-bearing.
///
/// Assumptions (not proved here): `get_del` is linearizable, the handler
/// performs exactly the effect the driver returns in the same step as its
/// observation, the challenge was created once by an admitted initiation, the
/// WebAuthn verification and JSON decodes produce the observations they claim,
/// and the account row's stable credential binding is not transferred between
/// accounts. SQL/row semantics, cryptography, TTL expiry and multi-node
/// replication remain outside this module.
///
/// This module deliberately does not import the per-request lemma module: the
/// composition is a statement about the extracted driver alone. That also makes
/// the mutation checks fail here, not in an unrelated lemma.

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Webauthn_driver

let b2n (b: bool) : nat = if b then 1 else 0

// ── Independent per-request invariant (restated, not imported) ──────────────

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

// ── Per-request token and counter accounting over the extracted step ───────

/// A request holds the consumed-challenge token between a fully matched
/// consumption and the grant decision.
let holds (d: t_AuthFinishDriver) : nat =
  if is_af_verify d || is_af_update d || is_af_account d then 1 else 0

/// The token released by a fully matched `Present` consumption observation.
let consume_release (e: t_AuthFinishEvent) : nat =
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptConsumed
      (AuthAttemptConsumptionObservation_Present
        { f_user_matches = user_matches; f_attempt_matches = attempt_matches;
          f_credential_matches = credential_matches }) ->
      b2n (user_matches && attempt_matches && credential_matches)
  | _ -> 0

let released (e: t_AuthFinishEffect) : nat =
  match e <: t_AuthFinishEffect with
  | AuthFinishEffect_ReleaseGrant _ -> 1
  | _ -> 0

let step_tokens (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d))
    (ensures (
      let t = step_auth_finish d e in
      holds t.f_driver + released t.f_effect <= holds d + consume_release e)) =
  af_trace_sound_matches_rust d;
  af_step_sound d e;
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted _ -> ()
  | AuthFinishEvent_ContextObserved _ -> ()
  | AuthFinishEvent_AttemptConsumed obs ->
      (match obs <: t_AuthAttemptConsumptionObservation with
       | AuthAttemptConsumptionObservation_Missing -> ()
       | AuthAttemptConsumptionObservation_Corrupt -> ()
       | AuthAttemptConsumptionObservation_Present _ -> ())
  | AuthFinishEvent_AssertionObserved _ -> ()
  | AuthFinishEvent_CredentialUpdated _ -> ()
  | AuthFinishEvent_AccountObserved _ -> ()
  | AuthFinishEvent_ShareObserved _ -> ()
  | AuthFinishEvent_GrantStored _ -> ()

/// For every non-consumption event the step creates no token from the store.
let step_tokens_other (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (
      af_trace_sound d = true /\
      (match e <: t_AuthFinishEvent with
       | AuthFinishEvent_AttemptConsumed _ -> False
       | _ -> True)))
    (ensures (
      let t = step_auth_finish d e in
      holds t.f_driver + released t.f_effect <= holds d)) =
  step_tokens d e;
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted _ -> ()
  | AuthFinishEvent_ContextObserved _ -> ()
  | AuthFinishEvent_AttemptConsumed _ -> ()
  | AuthFinishEvent_AssertionObserved _ -> ()
  | AuthFinishEvent_CredentialUpdated _ -> ()
  | AuthFinishEvent_AccountObserved _ -> ()
  | AuthFinishEvent_ShareObserved _ -> ()
  | AuthFinishEvent_GrantStored _ -> ()

// ── The forbidden-release counter ──────────────────────────────────────────

/// Every fact a live-account observation must carry for a release. The
/// credential chain is the conjunction of the two earlier comparisons plus the
/// live row comparison; the update condition says an authenticator that asked
/// for a metadata update must have got one.
let release_facts (d: t_AuthFinishDriver) (obs: t_AuthAccountObservation) : bool =
  d.f_attempt_consumed && d.f_user_matches && d.f_attempt_matches &&
  d.f_challenge_credential_matches && d.f_assertion_valid &&
  d.f_user_verified && d.f_assertion_credential_matches &&
  (not d.f_credential_update_needed || d.f_credential_updated) &&
  obs.f_account_present && obs.f_account_epoch_active &&
  obs.f_share_present && obs.f_stored_credential_matches

/// The forbidden-release increment produced by one driver step. It is keyed on
/// the *observation* and the pre-state, not on the driver's own recording, so a
/// driver mutation that trusts a bad observation still increments it.
let forbidden_add (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
                  (eff: t_AuthFinishEffect) : nat =
  match eff <: t_AuthFinishEffect with
  | AuthFinishEffect_ReleaseGrant _ ->
      (match e <: t_AuthFinishEvent with
       | AuthFinishEvent_AccountObserved obs ->
           if release_facts d obs then 0 else 1
       | _ -> 1)
  | _ -> 0

/// The checked policy's release decision implies every observation fact.
let release_requires_observation_facts (d: t_AuthFinishDriver)
      (obs: t_AuthAccountObservation)
  : Lemma
    (requires (af_trace_sound d /\ is_af_account d))
    (ensures (
      match (step_auth_finish d (AuthFinishEvent_AccountObserved obs)).f_effect
            <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant _ -> release_facts d obs
      | _ -> True)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
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
    | RecoverDecision_Release _ ->
        assert (recovery_is_authorized facts)
    | RecoverDecision_Reject -> ()
  end

/// The extracted driver never authorizes a forbidden release.
let step_never_forbidden (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (af_trace_sound d))
    (ensures (forbidden_add d e (step_auth_finish d e).f_effect = 0)) =
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  af_step_sound d e;
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted _ -> ()
  | AuthFinishEvent_ContextObserved _ -> ()
  | AuthFinishEvent_AttemptConsumed _ -> ()
  | AuthFinishEvent_AssertionObserved _ -> ()
  | AuthFinishEvent_CredentialUpdated _ -> ()
  | AuthFinishEvent_AccountObserved obs ->
      if is_af_account d then release_requires_observation_facts d obs
  | AuthFinishEvent_ShareObserved _ -> ()
  | AuthFinishEvent_GrantStored _ -> ()

// ── Request lists ──────────────────────────────────────────────────────────

let rec update (l: list t_AuthFinishDriver) (i: nat) (x: t_AuthFinishDriver)
  : Tot (list t_AuthFinishDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec all_sound (l: list t_AuthFinishDriver) : bool =
  match l with
  | [] -> true
  | d :: r -> af_trace_sound d && all_sound r

let rec held (l: list t_AuthFinishDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> holds d + held r

let rec counted (l: list t_AuthFinishDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> b2n d.f_budget_counted + counted r

let rec index_sound (l: list t_AuthFinishDriver) (i: nat)
  : Lemma
    (requires (all_sound l /\ i < FStar.List.Tot.length l))
    (ensures (af_trace_sound (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else index_sound t (i - 1)

let rec update_sound (l: list t_AuthFinishDriver) (i: nat) (x: t_AuthFinishDriver)
  : Lemma
    (requires (all_sound l /\ af_trace_sound x))
    (ensures (all_sound (update l i x)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_sound t (i - 1) x

let rec update_held (l: list t_AuthFinishDriver) (i: nat) (x: t_AuthFinishDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (held (update l i x) + holds (FStar.List.Tot.index l i) = held l + holds x))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_held t (i - 1) x

let rec update_counted (l: list t_AuthFinishDriver) (i: nat) (x: t_AuthFinishDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (
      counted (update l i x) + b2n (FStar.List.Tot.index l i).f_budget_counted =
      counted l + b2n x.f_budget_counted))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_counted t (i - 1) x

let counted_unchanged (l: list t_AuthFinishDriver) (i: nat) (x: t_AuthFinishDriver)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      (FStar.List.Tot.index l i).f_budget_counted = x.f_budget_counted))
    (ensures (counted (update l i x) = counted l)) =
  update_counted l i x

let counted_admitted (l: list t_AuthFinishDriver) (i: nat) (x: t_AuthFinishDriver)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      not (FStar.List.Tot.index l i).f_budget_counted /\
      x.f_budget_counted))
    (ensures (counted (update l i x) = counted l + 1)) =
  update_counted l i x

// ── The shared world and arbitrary schedules ───────────────────────────────

noeq type world = {
  attempt_state: bool;
  budget: nat;
  /// Driver-authorised releases (`ReleaseGrant` effects).
  grants: nat;
  /// Releases authorised for a live-account observation that forbids them.
  w_forbidden_release: nat;
  reqs: list t_AuthFinishDriver;
}

type action =
  | Spawn : action
  | Count : nat -> action
  | ContextStep : nat -> t_AuthFinishContextObservation -> action
  | Consume : nat -> t_AuthAttemptConsumptionObservation -> action
  | Verify : nat -> t_AssertionObservation -> action
  | Update : nat -> t_CredentialUpdateStoreObservation -> action
  | AccountStep : nat -> t_AuthAccountObservation -> action
  | Share : nat -> t_ShareDecodeObservation -> action
  | Store : nat -> t_GrantStoreObservation -> action

/// Deliver an event to request `i` and perform the effect the driver returns.
/// `attempt_state_mid` is the store's challenge bit after the atomic effect.
let deliver (w: world) (i: nat{i < FStar.List.Tot.length w.reqs})
    (e: t_AuthFinishEvent) (attempt_state_mid: bool) : world =
  let d = FStar.List.Tot.index w.reqs i in
  if auth_finish_state_is_sound d then
    let t = step_auth_finish d e in
    { attempt_state = attempt_state_mid;
      budget = w.budget;
      grants = w.grants + released t.f_effect;
      w_forbidden_release = w.w_forbidden_release + forbidden_add d e t.f_effect;
      reqs = update w.reqs i t.f_driver }
  else { w with attempt_state = attempt_state_mid }

let world_step (w: world) (a: action) : world =
  match a with
  | Spawn -> { w with reqs = (begin_auth_finish ()).f_driver :: w.reqs }
  | Count i ->
      if i < FStar.List.Tot.length w.reqs && is_af_attempt (FStar.List.Tot.index w.reqs i)
      then
        if w.budget > 0
        then
          deliver { w with budget = w.budget - 1 } i
            (AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted)
            w.attempt_state
        else
          deliver w i
            (AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Limited)
            w.attempt_state
      else w
  | ContextStep i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_context (FStar.List.Tot.index w.reqs i)
      then deliver w i (AuthFinishEvent_ContextObserved obs) w.attempt_state
      else w
  | Consume i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_consume (FStar.List.Tot.index w.reqs i)
      then
        if w.attempt_state
        then
          (match obs <: t_AuthAttemptConsumptionObservation with
           | AuthAttemptConsumptionObservation_Missing ->
               // A present challenge cannot be observed missing.
               w
           | _ ->
               deliver { w with attempt_state = false } i
                 (AuthFinishEvent_AttemptConsumed obs) false)
        else
          deliver w i
            (AuthFinishEvent_AttemptConsumed AuthAttemptConsumptionObservation_Missing)
            false
      else w
  | Verify i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_verify (FStar.List.Tot.index w.reqs i)
      then deliver w i (AuthFinishEvent_AssertionObserved obs) w.attempt_state
      else w
  | Update i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_update (FStar.List.Tot.index w.reqs i)
      then deliver w i (AuthFinishEvent_CredentialUpdated obs) w.attempt_state
      else w
  | AccountStep i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_account (FStar.List.Tot.index w.reqs i)
      then deliver w i (AuthFinishEvent_AccountObserved obs) w.attempt_state
      else w
  | Share i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_release (FStar.List.Tot.index w.reqs i)
      then deliver w i (AuthFinishEvent_ShareObserved obs) w.attempt_state
      else w
  | Store i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_store (FStar.List.Tot.index w.reqs i)
      then deliver w i (AuthFinishEvent_GrantStored obs) w.attempt_state
      else w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

/// Token conservation: the challenge in the store, grants authorised and
/// tokens held by in-flight requests never exceed one. The attempt budget is
/// consumed only by counted requests, and no driver ever authorises a
/// forbidden release.
let inv (w: world) (k: nat) : prop =
  all_sound w.reqs /\
  w.w_forbidden_release = 0 /\
  b2n w.attempt_state + w.grants + held w.reqs <= 1 /\
  w.budget + counted w.reqs <= k

let deliver_inv (w: world) (i: nat{i < FStar.List.Tot.length w.reqs})
    (e: t_AuthFinishEvent) (attempt_state_mid: bool) (k: nat)
  : Lemma
    (requires (
      inv w k /\
      (let d = FStar.List.Tot.index w.reqs i in
       auth_finish_state_is_sound d ==>
       (let t = step_auth_finish d e in
        counted (update w.reqs i t.f_driver) = counted w.reqs /\
        b2n attempt_state_mid + released t.f_effect + holds t.f_driver
          <= b2n w.attempt_state + holds d /\
        forbidden_add d e t.f_effect = 0))))
    (ensures (inv (deliver w i e attempt_state_mid) k)) =
  let d = FStar.List.Tot.index w.reqs i in
  index_sound w.reqs i;
  af_trace_sound_matches_rust d;
  assert (auth_finish_state_is_sound d = true);
  af_step_sound d e;
  let t = step_auth_finish d e in
  update_sound w.reqs i t.f_driver;
  update_held w.reqs i t.f_driver

/// Admitting an attempt preserves the invariant: one budget unit is spent and
/// the request's counted flag flips on.
let deliver_admit_inv (w: world) (i: nat{i < FStar.List.Tot.length w.reqs}) (k: nat)
  : Lemma
    (requires (
      inv w k /\ w.budget > 0 /\
      is_af_attempt (FStar.List.Tot.index w.reqs i)))
    (ensures (
      inv (deliver { w with budget = w.budget - 1 } i
             (AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted)
             w.attempt_state) k)) =
  let d = FStar.List.Tot.index w.reqs i in
  index_sound w.reqs i;
  af_trace_sound_matches_rust d;
  let e = AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Admitted in
  step_tokens_other d e;
  step_never_forbidden d e;
  af_step_sound d e;
  let t = step_auth_finish d e in
  assert (not d.f_budget_counted);
  assert (t.f_driver.f_budget_counted);
  counted_admitted w.reqs i t.f_driver;
  update_sound w.reqs i t.f_driver;
  update_held w.reqs i t.f_driver

/// Every action preserves the invariant.
let world_step_inv (w: world) (a: action) (k: nat)
  : Lemma (requires (inv w k)) (ensures (inv (world_step w a) k)) =
  match a with
  | Spawn ->
      af_begin_sound ();
      af_trace_sound_matches_rust (begin_auth_finish ()).f_driver
  | Count i ->
      if i < FStar.List.Tot.length w.reqs && is_af_attempt (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d0 = FStar.List.Tot.index w.reqs i in
        af_trace_sound_matches_rust d0;
        if w.budget > 0 then begin
          assert (w.budget > 0);
          deliver_admit_inv w i k
        end else begin
          let e = AuthFinishEvent_AttemptCounted AttemptBudgetObservation_Limited in
          let t = step_auth_finish d0 e in
          step_tokens_other d0 e;
          step_never_forbidden d0 e;
          assert (not d0.f_budget_counted);
          assert (not t.f_driver.f_budget_counted);
          counted_unchanged w.reqs i t.f_driver;
          deliver_inv w i e w.attempt_state k
        end
      end
  | ContextStep i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_context (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d = FStar.List.Tot.index w.reqs i in
        let e = AuthFinishEvent_ContextObserved obs in
        let t = step_auth_finish d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        step_never_forbidden d e;
        deliver_inv w i e w.attempt_state k
      end
  | Consume i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_consume (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        af_trace_sound_matches_rust (FStar.List.Tot.index w.reqs i);
        if w.attempt_state then begin
          match obs <: t_AuthAttemptConsumptionObservation with
          | AuthAttemptConsumptionObservation_Missing -> ()
          | _ ->
              let e = AuthFinishEvent_AttemptConsumed obs in
              let d = FStar.List.Tot.index w.reqs i in
              let t = step_auth_finish d e in
              counted_unchanged w.reqs i t.f_driver;
              step_never_forbidden d e;
              step_tokens d e;
              assert (released t.f_effect = 0);
              assert (b2n false + released t.f_effect + holds t.f_driver
                      <= b2n w.attempt_state + holds d);
              deliver_inv w i e false k
        end else begin
          let e = AuthFinishEvent_AttemptConsumed AuthAttemptConsumptionObservation_Missing in
          let d = FStar.List.Tot.index w.reqs i in
          let t = step_auth_finish d e in
          counted_unchanged w.reqs i t.f_driver;
          step_tokens d e;
          step_never_forbidden d e;
          deliver_inv w i e false k
        end
      end
  | Verify i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_verify (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d = FStar.List.Tot.index w.reqs i in
        let e = AuthFinishEvent_AssertionObserved obs in
        let t = step_auth_finish d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        step_never_forbidden d e;
        deliver_inv w i e w.attempt_state k
      end
  | Update i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_update (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d = FStar.List.Tot.index w.reqs i in
        let e = AuthFinishEvent_CredentialUpdated obs in
        let t = step_auth_finish d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        step_never_forbidden d e;
        deliver_inv w i e w.attempt_state k
      end
  | AccountStep i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_account (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d = FStar.List.Tot.index w.reqs i in
        let e = AuthFinishEvent_AccountObserved obs in
        let t = step_auth_finish d e in
        counted_unchanged w.reqs i t.f_driver;
        step_never_forbidden d e;
        step_tokens_other d e;
        deliver_inv w i e w.attempt_state k
      end
  | Share i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_release (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d = FStar.List.Tot.index w.reqs i in
        let e = AuthFinishEvent_ShareObserved obs in
        let t = step_auth_finish d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        step_never_forbidden d e;
        deliver_inv w i e w.attempt_state k
      end
  | Store i obs ->
      if i < FStar.List.Tot.length w.reqs && is_af_store (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d = FStar.List.Tot.index w.reqs i in
        let e = AuthFinishEvent_GrantStored obs in
        let t = step_auth_finish d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        step_never_forbidden d e;
        deliver_inv w i e w.attempt_state k
      end

let rec run_world_inv (w: world) (schedule: list action) (k: nat)
  : Lemma (requires (inv w k)) (ensures (inv (run_world w schedule) k))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      world_step_inv w a k;
      run_world_inv (world_step w a) rest k

let initial (k: nat) : world =
  { attempt_state = true; budget = k; grants = 0; w_forbidden_release = 0; reqs = [] }

let initial_inv (k: nat) : Lemma (inv (initial k) k) = ()

/// Headline theorem: whatever the number of concurrent requests, their
/// interleaving and the observations they receive, one attempt-bound challenge
/// yields at most one grant, at most `k` attempts are counted against an
/// initial budget of `k`, and no release is authorised from a live-account
/// observation that forbids it.
let one_challenge_at_most_one_grant (k: nat) (schedule: list action)
  : Lemma (
      let w = run_world (initial k) schedule in
      w.grants <= 1 /\ counted w.reqs <= k /\ w.budget <= k /\
      w.w_forbidden_release = 0) =
  initial_inv k;
  run_world_inv (initial k) schedule k

// ── Non-vacuity: one grant is reachable, races, refusals and bad live guards ─

#push-options "--fuel 4 --ifuel 2"

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

let available_context : t_AuthFinishContextObservation =
  { f_account_present = true;
    f_share_present = true;
    f_credential = StoredCredentialObservation_Present;
    f_attempt_id_present = true }

let matched_attempt : t_AuthAttemptConsumptionObservation =
  AuthAttemptConsumptionObservation_Present
    ({ f_user_matches = true; f_attempt_matches = true; f_credential_matches = true })

let verified_assertion : t_AssertionObservation =
  { f_assertion_valid = true;
    f_user_verified = true;
    f_credential_matches = true;
    f_needs_update = false }

let active_account : t_AuthAccountObservation =
  { f_account_present = true;
    f_account_epoch_active = true;
    f_share_present = true;
    f_stored_credential_matches = true;
    f_stored_epoch = Core_models.Option.Option_Some (mk_i64 3) }

let s1 = world_step (initial 1) Spawn
let s2 = world_step s1 (Count 0)
let s3 = world_step s2 (ContextStep 0 available_context)
let s4 = world_step s3 (Consume 0 matched_attempt)
let s5 = world_step s4 (Verify 0 verified_assertion)
let s6 = world_step s5 (AccountStep 0 active_account)
let s7 = world_step s6 (Share 0 ShareDecodeObservation_Decoded)
let s8 = world_step s7 (Store 0 GrantStoreObservation_Stored)

let s1_ok () : Lemma (s1.attempt_state = true /\ s1.budget = 1 /\ s1.grants = 0 /\
                      FStar.List.Tot.length s1.reqs = 1) = ()
let s2_ok () : Lemma (s2.attempt_state = true /\ s2.budget = 0 /\
                      FStar.List.Tot.length s2.reqs = 1 /\
                      is_af_context (FStar.List.Tot.index s2.reqs 0)) = s1_ok ()
let s3_ok () : Lemma (s3.attempt_state = true /\ s3.grants = 0 /\
                      is_af_consume (FStar.List.Tot.index s3.reqs 0)) = s2_ok ()
let s4_ok () : Lemma (s4.attempt_state = false /\ s4.grants = 0 /\
                      is_af_verify (FStar.List.Tot.index s4.reqs 0)) = s3_ok ()
let s5_ok () : Lemma (s5.grants = 0 /\
                      is_af_account (FStar.List.Tot.index s5.reqs 0)) = s4_ok ()
let s6_ok () : Lemma (s6.grants = 1 /\ s6.w_forbidden_release = 0 /\
                      is_af_release (FStar.List.Tot.index s6.reqs 0)) = s5_ok ()
let s7_ok () : Lemma (s7.grants = 1 /\
                      is_af_store (FStar.List.Tot.index s7.reqs 0)) = s6_ok ()
let s8_ok () : Lemma (s8.grants = 1 /\ s8.w_forbidden_release = 0 /\
                      is_af_done (FStar.List.Tot.index s8.reqs 0)) = s7_ok ()

let success_schedule : list action =
  [ Spawn; Count 0; ContextStep 0 available_context; Consume 0 matched_attempt;
    Verify 0 verified_assertion; AccountStep 0 active_account;
    Share 0 ShareDecodeObservation_Decoded; Store 0 GrantStoreObservation_Stored ]

let one_grant_is_reachable ()
  : Lemma ((run_world (initial 1) success_schedule).grants = 1) =
  run_cons (initial 1) Spawn [Count 0; ContextStep 0 available_context;
                              Consume 0 matched_attempt; Verify 0 verified_assertion;
                              AccountStep 0 active_account;
                              Share 0 ShareDecodeObservation_Decoded;
                              Store 0 GrantStoreObservation_Stored];
  run_cons s1 (Count 0) [ContextStep 0 available_context;
                         Consume 0 matched_attempt; Verify 0 verified_assertion;
                         AccountStep 0 active_account;
                         Share 0 ShareDecodeObservation_Decoded;
                         Store 0 GrantStoreObservation_Stored];
  run_cons s2 (ContextStep 0 available_context) [Consume 0 matched_attempt;
                                                 Verify 0 verified_assertion;
                                                 AccountStep 0 active_account;
                                                 Share 0 ShareDecodeObservation_Decoded;
                                                 Store 0 GrantStoreObservation_Stored];
  run_cons s3 (Consume 0 matched_attempt) [Verify 0 verified_assertion;
                                           AccountStep 0 active_account;
                                           Share 0 ShareDecodeObservation_Decoded;
                                           Store 0 GrantStoreObservation_Stored];
  run_cons s4 (Verify 0 verified_assertion) [AccountStep 0 active_account;
                                             Share 0 ShareDecodeObservation_Decoded;
                                             Store 0 GrantStoreObservation_Stored];
  run_cons s5 (AccountStep 0 active_account) [Share 0 ShareDecodeObservation_Decoded;
                                              Store 0 GrantStoreObservation_Stored];
  run_cons s6 (Share 0 ShareDecodeObservation_Decoded) [Store 0 GrantStoreObservation_Stored];
  run_cons s7 (Store 0 GrantStoreObservation_Stored) [];
  run_nil s8;
  s8_ok ()

/// Two racing requests share one challenge: the second consumption sees it
/// missing and fails; exactly one grant is issued.
let r1 = world_step (initial 2) Spawn
let r2 = world_step r1 Spawn
let r3 = world_step r2 (Count 0)
let r4 = world_step r3 (Count 1)
let r5 = world_step r4 (ContextStep 0 available_context)
let r6 = world_step r5 (ContextStep 1 available_context)
let r7 = world_step r6 (Consume 0 matched_attempt)
let r8 = world_step r7 (Consume 1 matched_attempt)
let r9 = world_step r8 (Verify 0 verified_assertion)
let r10 = world_step r9 (AccountStep 0 active_account)
let r11 = world_step r10 (Share 0 ShareDecodeObservation_Decoded)
let r12 = world_step r11 (Store 0 GrantStoreObservation_Stored)

let r2_ok () : Lemma (r2.attempt_state = true /\ r2.budget = 2 /\
                      FStar.List.Tot.length r2.reqs = 2 /\
                      is_af_attempt (FStar.List.Tot.index r2.reqs 0) /\
                      is_af_attempt (FStar.List.Tot.index r2.reqs 1)) = ()
let r4_ok () : Lemma (r4.budget = 0 /\ FStar.List.Tot.length r4.reqs = 2 /\
                      is_af_context (FStar.List.Tot.index r4.reqs 0) /\
                      is_af_context (FStar.List.Tot.index r4.reqs 1)) = r2_ok ()
let r6_ok () : Lemma (r6.attempt_state = true /\
                      is_af_consume (FStar.List.Tot.index r6.reqs 0) /\
                      is_af_consume (FStar.List.Tot.index r6.reqs 1)) = r4_ok ()
let r7_ok () : Lemma (r7.attempt_state = false /\ r7.grants = 0 /\
                      is_af_verify (FStar.List.Tot.index r7.reqs 0) /\
                      is_af_consume (FStar.List.Tot.index r7.reqs 1)) = r6_ok ()
let r8_ok () : Lemma (r8.attempt_state = false /\ r8.grants = 0 /\
                      is_af_verify (FStar.List.Tot.index r8.reqs 0) /\
                      is_af_done (FStar.List.Tot.index r8.reqs 1)) = r7_ok ()
let r10_ok () : Lemma (r10.grants = 1 /\
                       is_af_release (FStar.List.Tot.index r10.reqs 0)) = r8_ok ()
let r12_ok () : Lemma (r12.grants = 1 /\ r12.w_forbidden_release = 0 /\
                       is_af_done (FStar.List.Tot.index r12.reqs 0) /\
                       is_af_done (FStar.List.Tot.index r12.reqs 1)) = r10_ok ()

let race_schedule : list action =
  [ Spawn; Spawn; Count 0; Count 1;
    ContextStep 0 available_context; ContextStep 1 available_context;
    Consume 0 matched_attempt; Consume 1 matched_attempt;
    Verify 0 verified_assertion; AccountStep 0 active_account;
    Share 0 ShareDecodeObservation_Decoded; Store 0 GrantStoreObservation_Stored ]

let race_issues_one_grant ()
  : Lemma (
      let w = run_world (initial 2) race_schedule in
      w.grants = 1 /\ w.attempt_state = false /\ w.w_forbidden_release = 0) =
  run_cons (initial 2) Spawn [Spawn; Count 0; Count 1;
                              ContextStep 0 available_context;
                              ContextStep 1 available_context;
                              Consume 0 matched_attempt; Consume 1 matched_attempt;
                              Verify 0 verified_assertion;
                              AccountStep 0 active_account;
                              Share 0 ShareDecodeObservation_Decoded;
                              Store 0 GrantStoreObservation_Stored];
  run_cons r1 Spawn [Count 0; Count 1; ContextStep 0 available_context;
                     ContextStep 1 available_context;
                     Consume 0 matched_attempt; Consume 1 matched_attempt;
                     Verify 0 verified_assertion; AccountStep 0 active_account;
                     Share 0 ShareDecodeObservation_Decoded;
                     Store 0 GrantStoreObservation_Stored];
  run_cons r2 (Count 0) [Count 1; ContextStep 0 available_context;
                         ContextStep 1 available_context;
                         Consume 0 matched_attempt; Consume 1 matched_attempt;
                         Verify 0 verified_assertion; AccountStep 0 active_account;
                         Share 0 ShareDecodeObservation_Decoded;
                         Store 0 GrantStoreObservation_Stored];
  run_cons r3 (Count 1) [ContextStep 0 available_context;
                         ContextStep 1 available_context;
                         Consume 0 matched_attempt; Consume 1 matched_attempt;
                         Verify 0 verified_assertion; AccountStep 0 active_account;
                         Share 0 ShareDecodeObservation_Decoded;
                         Store 0 GrantStoreObservation_Stored];
  run_cons r4 (ContextStep 0 available_context) [ContextStep 1 available_context;
                                                 Consume 0 matched_attempt;
                                                 Consume 1 matched_attempt;
                                                 Verify 0 verified_assertion;
                                                 AccountStep 0 active_account;
                                                 Share 0 ShareDecodeObservation_Decoded;
                                                 Store 0 GrantStoreObservation_Stored];
  run_cons r5 (ContextStep 1 available_context) [Consume 0 matched_attempt;
                                                 Consume 1 matched_attempt;
                                                 Verify 0 verified_assertion;
                                                 AccountStep 0 active_account;
                                                 Share 0 ShareDecodeObservation_Decoded;
                                                 Store 0 GrantStoreObservation_Stored];
  run_cons r6 (Consume 0 matched_attempt) [Consume 1 matched_attempt;
                                           Verify 0 verified_assertion;
                                           AccountStep 0 active_account;
                                           Share 0 ShareDecodeObservation_Decoded;
                                           Store 0 GrantStoreObservation_Stored];
  run_cons r7 (Consume 1 matched_attempt) [Verify 0 verified_assertion;
                                           AccountStep 0 active_account;
                                           Share 0 ShareDecodeObservation_Decoded;
                                           Store 0 GrantStoreObservation_Stored];
  run_cons r8 (Verify 0 verified_assertion) [AccountStep 0 active_account;
                                             Share 0 ShareDecodeObservation_Decoded;
                                             Store 0 GrantStoreObservation_Stored];
  run_cons r9 (AccountStep 0 active_account)
    [Share 0 ShareDecodeObservation_Decoded; Store 0 GrantStoreObservation_Stored];
  run_cons r10 (Share 0 ShareDecodeObservation_Decoded)
    [Store 0 GrantStoreObservation_Stored];
  run_cons r11 (Store 0 GrantStoreObservation_Stored) [];
  run_nil r12;
  r12_ok ()

/// The attempt budget is enforced: with one unit, the second request is
/// refused before it can reach the challenge.
let b1 = world_step (initial 1) Spawn
let b2 = world_step b1 Spawn
let b3 = world_step b2 (Count 0)
let b4 = world_step b3 (Count 1)
let b3_ok () : Lemma (b3.budget = 0 /\ b3.attempt_state = true /\
                      is_af_context (FStar.List.Tot.index b3.reqs 0)) = ()
let b4_ok () : Lemma (b4.budget = 0 /\ b4.grants = 0 /\ b4.attempt_state = true /\
                      is_af_done (FStar.List.Tot.index b4.reqs 1)) =
  b3_ok ()

let budget_schedule : list action =
  [ Spawn; Spawn; Count 0; Count 1 ]

let budget_is_enforced ()
  : Lemma (
      let w = run_world (initial 1) budget_schedule in
      w.budget = 0 /\ w.grants = 0 /\ w.attempt_state = true /\
      counted w.reqs = 1) =
  run_cons (initial 1) Spawn [Spawn; Count 0; Count 1];
  run_cons b1 Spawn [Count 0; Count 1];
  run_cons b2 (Count 0) [Count 1];
  run_cons b3 (Count 1) [];
  run_nil b4;
  b4_ok ()

/// Freezing after the challenge was consumed issues no grant.
let f1 = world_step (initial 1) Spawn
let f2 = world_step f1 (Count 0)
let f3 = world_step f2 (ContextStep 0 available_context)
let f4 = world_step f3 (Consume 0 matched_attempt)
let f5 = world_step f4 (Verify 0 verified_assertion)
let f6 = world_step f5 (AccountStep 0 ({ active_account with f_account_epoch_active = false }))
let f6_ok () : Lemma (f6.grants = 0 /\ f6.w_forbidden_release = 0 /\
                      is_af_done (FStar.List.Tot.index f6.reqs 0)) = ()

let freezing_schedule : list action =
  [ Spawn; Count 0; ContextStep 0 available_context; Consume 0 matched_attempt;
    Verify 0 verified_assertion;
    AccountStep 0 ({ active_account with f_account_epoch_active = false }) ]

let freezing_issues_no_grant ()
  : Lemma ((run_world (initial 1) freezing_schedule).grants = 0) =
  run_cons (initial 1) Spawn [Count 0; ContextStep 0 available_context;
                              Consume 0 matched_attempt; Verify 0 verified_assertion;
                              AccountStep 0
                                ({ active_account with f_account_epoch_active = false })];
  run_cons f1 (Count 0) [ContextStep 0 available_context; Consume 0 matched_attempt;
                         Verify 0 verified_assertion;
                         AccountStep 0
                           ({ active_account with f_account_epoch_active = false })];
  run_cons f2 (ContextStep 0 available_context) [Consume 0 matched_attempt;
                                                 Verify 0 verified_assertion;
                                                 AccountStep 0
                                                   ({ active_account with
                                                      f_account_epoch_active = false })];
  run_cons f3 (Consume 0 matched_attempt) [Verify 0 verified_assertion;
                                           AccountStep 0
                                             ({ active_account with
                                                f_account_epoch_active = false })];
  run_cons f4 (Verify 0 verified_assertion)
    [AccountStep 0 ({ active_account with f_account_epoch_active = false })];
  run_cons f5 (AccountStep 0 ({ active_account with f_account_epoch_active = false })) [];
  run_nil f6;
  f6_ok ()

/// A live row whose credential no longer matches the challenge issues no grant.
let g1 = world_step (initial 1) Spawn
let g2 = world_step g1 (Count 0)
let g3 = world_step g2 (ContextStep 0 available_context)
let g4 = world_step g3 (Consume 0 matched_attempt)
let g5 = world_step g4 (Verify 0 verified_assertion)
let g6 = world_step g5 (AccountStep 0 ({ active_account with f_stored_credential_matches = false }))
let g6_ok () : Lemma (g6.grants = 0 /\ g6.w_forbidden_release = 0 /\
                      is_af_done (FStar.List.Tot.index g6.reqs 0)) = ()

let replacement_schedule : list action =
  [ Spawn; Count 0; ContextStep 0 available_context; Consume 0 matched_attempt;
    Verify 0 verified_assertion;
    AccountStep 0 ({ active_account with f_stored_credential_matches = false }) ]

let replacement_issues_no_grant ()
  : Lemma ((run_world (initial 1) replacement_schedule).grants = 0) =
  run_cons (initial 1) Spawn [Count 0; ContextStep 0 available_context;
                              Consume 0 matched_attempt; Verify 0 verified_assertion;
                              AccountStep 0
                                ({ active_account with f_stored_credential_matches = false })];
  run_cons g1 (Count 0) [ContextStep 0 available_context; Consume 0 matched_attempt;
                         Verify 0 verified_assertion;
                         AccountStep 0
                           ({ active_account with f_stored_credential_matches = false })];
  run_cons g2 (ContextStep 0 available_context) [Consume 0 matched_attempt;
                                                 Verify 0 verified_assertion;
                                                 AccountStep 0
                                                   ({ active_account with
                                                      f_stored_credential_matches = false })];
  run_cons g3 (Consume 0 matched_attempt) [Verify 0 verified_assertion;
                                           AccountStep 0
                                             ({ active_account with
                                                f_stored_credential_matches = false })];
  run_cons g4 (Verify 0 verified_assertion)
    [AccountStep 0 ({ active_account with f_stored_credential_matches = false })];
  run_cons g5 (AccountStep 0 ({ active_account with f_stored_credential_matches = false })) [];
  run_nil g6;
  g6_ok ()

/// An unverified assertion issues no grant.
let p1 = world_step (initial 1) Spawn
let p2 = world_step p1 (Count 0)
let p3 = world_step p2 (ContextStep 0 available_context)
let p4 = world_step p3 (Consume 0 matched_attempt)
let p5 = world_step p4 (Verify 0 ({ verified_assertion with f_user_verified = false }))
let p5_ok () : Lemma (p5.grants = 0 /\ p5.w_forbidden_release = 0 /\
                      is_af_done (FStar.List.Tot.index p5.reqs 0)) = ()

let no_uv_schedule : list action =
  [ Spawn; Count 0; ContextStep 0 available_context; Consume 0 matched_attempt;
    Verify 0 ({ verified_assertion with f_user_verified = false }) ]

let no_uv_issues_no_grant ()
  : Lemma ((run_world (initial 1) no_uv_schedule).grants = 0) =
  run_cons (initial 1) Spawn [Count 0; ContextStep 0 available_context;
                              Consume 0 matched_attempt;
                              Verify 0 ({ verified_assertion with f_user_verified = false })];
  run_cons p1 (Count 0) [ContextStep 0 available_context; Consume 0 matched_attempt;
                         Verify 0 ({ verified_assertion with f_user_verified = false })];
  run_cons p2 (ContextStep 0 available_context) [Consume 0 matched_attempt;
                                                 Verify 0
                                                   ({ verified_assertion with
                                                      f_user_verified = false })];
  run_cons p3 (Consume 0 matched_attempt)
    [Verify 0 ({ verified_assertion with f_user_verified = false })];
  run_cons p4 (Verify 0 ({ verified_assertion with f_user_verified = false })) [];
  run_nil p5;
  p5_ok ()

#pop-options
