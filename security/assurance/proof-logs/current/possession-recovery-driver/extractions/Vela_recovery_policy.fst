module Vela_recovery_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

let v_INITIAL_EPOCH: i64 = mk_i64 1

type t_RecoveryPhase =
  | RecoveryPhase_Unavailable : t_RecoveryPhase
  | RecoveryPhase_Ready : t_RecoveryPhase
  | RecoveryPhase_ChallengePending : t_RecoveryPhase
  | RecoveryPhase_GrantIssued : t_RecoveryPhase
  | RecoveryPhase_Completed : t_RecoveryPhase
  | RecoveryPhase_Revoked : t_RecoveryPhase
  | RecoveryPhase_Expired : t_RecoveryPhase

/// Where a `/recovery/recover` request found the stored challenge state.
type t_RecoveryAttemptSource =
  | RecoveryAttemptSource_Missing : t_RecoveryAttemptSource
  | RecoveryAttemptSource_Consumed : t_RecoveryAttemptSource

/// Normalize a stored recovery epoch the same way the handler does: a missing
/// or non-positive column falls back to the initial epoch.
let observed_recovery_epoch (stored_epoch: Core_models.Option.t_Option i64)
    : Prims.Pure i64
      Prims.l_True
      (ensures
        fun epoch ->
          let epoch:i64 = epoch in
          epoch =.
          (match stored_epoch <: Core_models.Option.t_Option i64 with
            | Core_models.Option.Option_None  -> v_INITIAL_EPOCH
            | Core_models.Option.Option_Some value ->
              if value <. v_INITIAL_EPOCH <: bool then v_INITIAL_EPOCH else value)) =
  match stored_epoch <: Core_models.Option.t_Option i64 with
  | Core_models.Option.Option_None  -> v_INITIAL_EPOCH
  | Core_models.Option.Option_Some value ->
    if value <. v_INITIAL_EPOCH then v_INITIAL_EPOCH else value

/// Raw observations from the possession-proof initiation request, the `users`
/// row and the store slot for the new attempt.
type t_ProofInitiateObservation = {
  f_account_present:bool;
  f_share_present:bool;
  f_commitment_len:usize;
  f_rotation_active:bool;
  f_attempt_id_fresh:bool;
  f_ttl_secs:u64
}

/// Facts for starting a possession-proof recovery attempt.
type t_ProofInitiateFacts = {
  f_phase:t_RecoveryPhase;
  f_account_exists:bool;
  f_share_present:bool;
  f_possession_hash_present:bool;
  f_attempt_id_fresh:bool;
  f_ttl_positive:bool
}

let proof_initiation_is_authorized (facts: t_ProofInitiateFacts) : bool =
  (match facts.f_phase <: t_RecoveryPhase with
    | RecoveryPhase_Ready  -> true
    | _ -> false) &&
  facts.f_account_exists &&
  facts.f_share_present &&
  facts.f_possession_hash_present &&
  facts.f_attempt_id_fresh &&
  facts.f_ttl_positive

type t_ProofInitiateDecision =
  | ProofInitiateDecision_Start : t_ProofInitiateDecision
  | ProofInitiateDecision_Reject : t_ProofInitiateDecision

let plan_proof_initiation (facts: t_ProofInitiateFacts)
    : Prims.Pure t_ProofInitiateDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ProofInitiateDecision = decision in
          (match decision <: t_ProofInitiateDecision with
            | ProofInitiateDecision_Start  -> true
            | _ -> false) =.
          (proof_initiation_is_authorized facts <: bool)) =
  if proof_initiation_is_authorized facts
  then ProofInitiateDecision_Start <: t_ProofInitiateDecision
  else ProofInitiateDecision_Reject <: t_ProofInitiateDecision

/// Turn the account, share, decoded-commitment, rotation, store-slot and TTL
/// observations into the possession-initiation facts. `Ready` names exactly
/// the observed availability of an account, its recovery share and a non-empty
/// staged commitment on an account that is not rotating.
let proof_initiate_facts (obs: t_ProofInitiateObservation)
    : Prims.Pure t_ProofInitiateFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_ProofInitiateFacts = facts in
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_Ready  -> true
            | _ -> false) =.
          (obs.f_account_present && obs.f_share_present &&
          (obs.f_commitment_len >. mk_usize 0 <: bool) &&
          (~.obs.f_rotation_active <: bool)) &&
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_Unavailable  -> true
            | _ -> false) =.
          (~.(obs.f_account_present && obs.f_share_present &&
              (obs.f_commitment_len >. mk_usize 0 <: bool) &&
              (~.obs.f_rotation_active <: bool))
            <:
            bool) &&
          facts.f_account_exists =. obs.f_account_present &&
          facts.f_share_present =. obs.f_share_present &&
          facts.f_possession_hash_present =. (obs.f_commitment_len >. mk_usize 0 <: bool) &&
          facts.f_attempt_id_fresh =. obs.f_attempt_id_fresh &&
          facts.f_ttl_positive =. (obs.f_ttl_secs >. mk_u64 0 <: bool)) =
  let available:bool =
    obs.f_account_present && obs.f_share_present && obs.f_commitment_len >. mk_usize 0 &&
    ~.obs.f_rotation_active
  in
  {
    f_phase
    =
    if available
    then RecoveryPhase_Ready <: t_RecoveryPhase
    else RecoveryPhase_Unavailable <: t_RecoveryPhase;
    f_account_exists = obs.f_account_present;
    f_share_present = obs.f_share_present;
    f_possession_hash_present = obs.f_commitment_len >. mk_usize 0;
    f_attempt_id_fresh = obs.f_attempt_id_fresh;
    f_ttl_positive = obs.f_ttl_secs >. mk_u64 0
  }
  <:
  t_ProofInitiateFacts

/// Facts for redeeming one possession-proof attempt. The cryptographic
/// comparison itself stays outside this crate; `proof_verified` carries only
/// its authenticated outcome.
type t_PossessionRecoverFacts = {
  f_phase:t_RecoveryPhase;
  f_account_present:bool;
  f_user_matches:bool;
  f_attempt_matches:bool;
  f_challenge_consumed:bool;
  f_proof_verified:bool;
  f_account_epoch_active:bool;
  f_commitment_present:bool;
  f_commitment_epoch_matches:bool;
  f_epoch:i64
}

/// Raw observations from the consumed possession attempt, the decoded proof
/// state, the verification result and the live `users` row.
type t_PossessionRecoverObservation = {
  f_attempt_source:t_RecoveryAttemptSource;
  f_account_present:bool;
  f_user_matches:bool;
  f_attempt_matches:bool;
  f_proof_verified:bool;
  f_account_epoch_active:bool;
  f_commitment_len:usize;
  f_commitment_epoch:i64;
  f_stored_epoch:Core_models.Option.t_Option i64
}

type t_PossessionGrantPermit = {
  f_epoch:i64;
  f_issues_single_use_grant:bool
}

type t_PossessionRecoverDecision =
  | PossessionRecoverDecision_Grant : t_PossessionGrantPermit -> t_PossessionRecoverDecision
  | PossessionRecoverDecision_Reject : t_PossessionRecoverDecision

let impl_PossessionGrantPermit__epoch (self: t_PossessionGrantPermit) : i64 = self.f_epoch

/// A possession grant never releases Share 2 — the caller already proved
/// they can reconstruct without it.
let impl_PossessionGrantPermit__releases_server_share (self: t_PossessionGrantPermit) : bool = false

let possession_recovery_is_authorized (facts: t_PossessionRecoverFacts) : bool =
  (match facts.f_phase <: t_RecoveryPhase with
    | RecoveryPhase_ChallengePending  -> true
    | _ -> false) &&
  facts.f_account_present &&
  facts.f_user_matches &&
  facts.f_attempt_matches &&
  facts.f_challenge_consumed &&
  facts.f_proof_verified &&
  facts.f_account_epoch_active &&
  facts.f_commitment_present &&
  facts.f_commitment_epoch_matches &&
  facts.f_epoch >=. v_INITIAL_EPOCH

let possession_recovery_decision_matches_spec
      (facts: t_PossessionRecoverFacts)
      (decision: t_PossessionRecoverDecision)
    : bool =
  match decision <: t_PossessionRecoverDecision with
  | PossessionRecoverDecision_Grant permit ->
    possession_recovery_is_authorized facts && permit.f_epoch =. facts.f_epoch &&
    permit.f_issues_single_use_grant &&
    ~.(impl_PossessionGrantPermit__releases_server_share permit <: bool)
  | PossessionRecoverDecision_Reject  -> ~.(possession_recovery_is_authorized facts <: bool)

let plan_possession_recovery (facts: t_PossessionRecoverFacts)
    : Prims.Pure t_PossessionRecoverDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_PossessionRecoverDecision = decision in
          possession_recovery_decision_matches_spec facts decision) =
  if possession_recovery_is_authorized facts
  then
    PossessionRecoverDecision_Grant
    ({ f_epoch = facts.f_epoch; f_issues_single_use_grant = true } <: t_PossessionGrantPermit)
    <:
    t_PossessionRecoverDecision
  else PossessionRecoverDecision_Reject <: t_PossessionRecoverDecision

/// Turn the consumed-attempt, decoded-envelope, verification and row
/// observations into the possession-recovery facts. The phase and one-shot
/// flag come from whether the store actually returned (and removed) the exact
/// attempt; commitment presence and epoch equality come from the decoded
/// commitment length and the decoded envelope epoch.
let possession_recover_facts (obs: t_PossessionRecoverObservation)
    : Prims.Pure t_PossessionRecoverFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_PossessionRecoverFacts = facts in
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_ChallengePending  -> true
            | _ -> false) =.
          (match obs.f_attempt_source <: t_RecoveryAttemptSource with
            | RecoveryAttemptSource_Consumed  -> true
            | _ -> false) &&
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_Expired  -> true
            | _ -> false) =.
          (match obs.f_attempt_source <: t_RecoveryAttemptSource with
            | RecoveryAttemptSource_Missing  -> true
            | _ -> false) &&
          facts.f_account_present =. obs.f_account_present &&
          facts.f_user_matches =. obs.f_user_matches &&
          facts.f_attempt_matches =. obs.f_attempt_matches &&
          facts.f_challenge_consumed =.
          (match obs.f_attempt_source <: t_RecoveryAttemptSource with
            | RecoveryAttemptSource_Consumed  -> true
            | _ -> false) &&
          facts.f_proof_verified =. obs.f_proof_verified &&
          facts.f_account_epoch_active =. obs.f_account_epoch_active &&
          facts.f_commitment_present =. (obs.f_commitment_len >. mk_usize 0 <: bool) &&
          facts.f_commitment_epoch_matches =.
          (obs.f_commitment_epoch =. (observed_recovery_epoch obs.f_stored_epoch <: i64) <: bool) &&
          facts.f_epoch =. (observed_recovery_epoch obs.f_stored_epoch <: i64)) =
  let challenge_consumed:bool =
    match obs.f_attempt_source <: t_RecoveryAttemptSource with
    | RecoveryAttemptSource_Consumed  -> true
    | _ -> false
  in
  let epoch:i64 = observed_recovery_epoch obs.f_stored_epoch in
  {
    f_phase
    =
    if challenge_consumed
    then RecoveryPhase_ChallengePending <: t_RecoveryPhase
    else RecoveryPhase_Expired <: t_RecoveryPhase;
    f_account_present = obs.f_account_present;
    f_user_matches = obs.f_user_matches;
    f_attempt_matches = obs.f_attempt_matches;
    f_challenge_consumed = challenge_consumed;
    f_proof_verified = obs.f_proof_verified;
    f_account_epoch_active = obs.f_account_epoch_active;
    f_commitment_present = obs.f_commitment_len >. mk_usize 0;
    f_commitment_epoch_matches = obs.f_commitment_epoch =. epoch;
    f_epoch = epoch
  }
  <:
  t_PossessionRecoverFacts
