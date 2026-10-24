module Vela_recovery_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

let v_INITIAL_EPOCH: i64 = mk_i64 1

type t_PublicationStageRequest = {
  f_declared_epoch:i64;
  f_split_id_present:bool;
  f_server_share_present:bool;
  f_device_authority:bool
}

type t_PublicationStagePermit = {
  f_epoch:i64;
  f_binds_split_and_share:bool
}

type t_PublicationStageDecision =
  | PublicationStageDecision_Stage : t_PublicationStagePermit -> t_PublicationStageDecision
  | PublicationStageDecision_Reject : t_PublicationStageDecision

let publication_stage_is_authorized (request: t_PublicationStageRequest) : bool =
  request.f_declared_epoch >=. v_INITIAL_EPOCH && request.f_split_id_present &&
  request.f_server_share_present &&
  request.f_device_authority

let publication_stage_decision_matches_spec
      (request: t_PublicationStageRequest)
      (decision: t_PublicationStageDecision)
    : bool =
  match decision <: t_PublicationStageDecision with
  | PublicationStageDecision_Stage permit ->
    publication_stage_is_authorized request && permit.f_epoch =. request.f_declared_epoch &&
    permit.f_binds_split_and_share
  | PublicationStageDecision_Reject  -> ~.(publication_stage_is_authorized request <: bool)

let plan_publication_stage (request: t_PublicationStageRequest)
    : Prims.Pure t_PublicationStageDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_PublicationStageDecision = decision in
          publication_stage_decision_matches_spec request decision) =
  if publication_stage_is_authorized request
  then
    PublicationStageDecision_Stage
    ({ f_epoch = request.f_declared_epoch; f_binds_split_and_share = true }
      <:
      t_PublicationStagePermit)
    <:
    t_PublicationStageDecision
  else PublicationStageDecision_Reject <: t_PublicationStageDecision

type t_PublicationFinalizeRequest = {
  f_declared_epoch:i64;
  f_split_id_present:bool;
  f_device_authority:bool
}

type t_PublicationFinalizePermit = {
  f_epoch:i64;
  f_exact_pending_required:bool;
  f_empty_active_required:bool
}

type t_PublicationFinalizeDecision =
  | PublicationFinalizeDecision_Finalize : t_PublicationFinalizePermit
    -> t_PublicationFinalizeDecision
  | PublicationFinalizeDecision_Reject : t_PublicationFinalizeDecision

let publication_finalize_is_authorized (request: t_PublicationFinalizeRequest) : bool =
  request.f_declared_epoch >=. v_INITIAL_EPOCH && request.f_split_id_present &&
  request.f_device_authority

let publication_finalize_decision_matches_spec
      (request: t_PublicationFinalizeRequest)
      (decision: t_PublicationFinalizeDecision)
    : bool =
  match decision <: t_PublicationFinalizeDecision with
  | PublicationFinalizeDecision_Finalize permit ->
    publication_finalize_is_authorized request && permit.f_epoch =. request.f_declared_epoch &&
    permit.f_exact_pending_required &&
    permit.f_empty_active_required
  | PublicationFinalizeDecision_Reject  -> ~.(publication_finalize_is_authorized request <: bool)

let plan_publication_finalize (request: t_PublicationFinalizeRequest)
    : Prims.Pure t_PublicationFinalizeDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_PublicationFinalizeDecision = decision in
          publication_finalize_decision_matches_spec request decision) =
  if publication_finalize_is_authorized request
  then
    PublicationFinalizeDecision_Finalize
    ({
        f_epoch = request.f_declared_epoch;
        f_exact_pending_required = true;
        f_empty_active_required = true
      }
      <:
      t_PublicationFinalizePermit)
    <:
    t_PublicationFinalizeDecision
  else PublicationFinalizeDecision_Reject <: t_PublicationFinalizeDecision

type t_PublicationStateFacts = {
  f_account_epoch_active:bool;
  f_active_share_absent:bool;
  f_account_epoch:i64;
  f_pending_epoch:i64;
  f_pending_split_matches:bool;
  f_pending_share_present:bool
}

let pending_publication_can_commit
      (permit: t_PublicationFinalizePermit)
      (state: t_PublicationStateFacts)
    : bool =
  permit.f_exact_pending_required && permit.f_empty_active_required && state.f_account_epoch_active &&
  state.f_active_share_absent &&
  permit.f_epoch >=. v_INITIAL_EPOCH &&
  state.f_account_epoch =. permit.f_epoch &&
  state.f_pending_epoch =. permit.f_epoch &&
  state.f_pending_split_matches &&
  state.f_pending_share_present

let competing_split_can_finalize
      (permit: t_PublicationFinalizePermit)
      (state: t_PublicationStateFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let state:t_PublicationStateFacts =
    { state with f_pending_split_matches = false } <: t_PublicationStateFacts
  in
  pending_publication_can_commit permit state

let retired_epoch_publication_can_finalize
      (permit: t_PublicationFinalizePermit)
      (state: t_PublicationStateFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let state:t_PublicationStateFacts =
    {
      state with
      f_account_epoch
      =
      if permit.f_epoch =. Core_models.Num.impl_i64__MAX
      then permit.f_epoch -! mk_i64 1
      else permit.f_epoch +! mk_i64 1
    }
    <:
    t_PublicationStateFacts
  in
  pending_publication_can_commit permit state

let already_finalized_epoch_can_finalize
      (permit: t_PublicationFinalizePermit)
      (state: t_PublicationStateFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let state:t_PublicationStateFacts =
    { state with f_active_share_absent = false } <: t_PublicationStateFacts
  in
  pending_publication_can_commit permit state

type t_RecoveryPhase =
  | RecoveryPhase_Unavailable : t_RecoveryPhase
  | RecoveryPhase_Ready : t_RecoveryPhase
  | RecoveryPhase_ChallengePending : t_RecoveryPhase
  | RecoveryPhase_GrantIssued : t_RecoveryPhase
  | RecoveryPhase_Completed : t_RecoveryPhase
  | RecoveryPhase_Revoked : t_RecoveryPhase
  | RecoveryPhase_Expired : t_RecoveryPhase

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_53': Core_models.Cmp.t_PartialEq t_RecoveryPhase t_RecoveryPhase

unfold
let impl_53 = impl_53'

type t_InitiateFacts = {
  f_phase:t_RecoveryPhase;
  f_account_exists:bool;
  f_share_present:bool;
  f_credential_present:bool;
  f_attempt_id_fresh:bool;
  f_ttl_positive:bool
}

type t_ChallengePermit = { f_bind_user_attempt_and_credential:bool }

type t_InitiateDecision =
  | InitiateDecision_Start : t_ChallengePermit -> t_InitiateDecision
  | InitiateDecision_Reject : t_InitiateDecision

let initiation_is_authorized (facts: t_InitiateFacts) : bool =
  facts.f_phase =. (RecoveryPhase_Ready <: t_RecoveryPhase) && facts.f_account_exists &&
  facts.f_share_present &&
  facts.f_credential_present &&
  facts.f_attempt_id_fresh &&
  facts.f_ttl_positive

let initiation_decision_matches_spec (facts: t_InitiateFacts) (decision: t_InitiateDecision) : bool =
  match decision <: t_InitiateDecision with
  | InitiateDecision_Start permit ->
    initiation_is_authorized facts && permit.f_bind_user_attempt_and_credential
  | InitiateDecision_Reject  -> ~.(initiation_is_authorized facts <: bool)

let plan_initiation (facts: t_InitiateFacts)
    : Prims.Pure t_InitiateDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_InitiateDecision = decision in
          initiation_decision_matches_spec facts decision) =
  if initiation_is_authorized facts
  then
    InitiateDecision_Start ({ f_bind_user_attempt_and_credential = true } <: t_ChallengePermit)
    <:
    t_InitiateDecision
  else InitiateDecision_Reject <: t_InitiateDecision

type t_RegistrationFacts = {
  f_device_scope:bool;
  f_account_matches:bool;
  f_challenge_pending:bool;
  f_challenge_consumed:bool;
  f_credential_valid:bool;
  f_credential_unique:bool
}

type t_RegistrationPermit = { f_authorized:bool }

type t_RegistrationDecision =
  | RegistrationDecision_Register : t_RegistrationPermit -> t_RegistrationDecision
  | RegistrationDecision_Reject : t_RegistrationDecision

let registration_is_authorized (facts: t_RegistrationFacts) : bool =
  facts.f_device_scope && facts.f_account_matches && facts.f_challenge_pending &&
  facts.f_challenge_consumed &&
  facts.f_credential_valid &&
  facts.f_credential_unique

let registration_decision_matches_spec
      (facts: t_RegistrationFacts)
      (decision: t_RegistrationDecision)
    : bool =
  match decision <: t_RegistrationDecision with
  | RegistrationDecision_Register permit -> registration_is_authorized facts && permit.f_authorized
  | RegistrationDecision_Reject  -> ~.(registration_is_authorized facts <: bool)

let plan_registration (facts: t_RegistrationFacts)
    : Prims.Pure t_RegistrationDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_RegistrationDecision = decision in
          registration_decision_matches_spec facts decision) =
  if registration_is_authorized facts
  then
    RegistrationDecision_Register ({ f_authorized = true } <: t_RegistrationPermit)
    <:
    t_RegistrationDecision
  else RegistrationDecision_Reject <: t_RegistrationDecision

type t_RecoverFacts = {
  f_phase:t_RecoveryPhase;
  f_user_matches:bool;
  f_attempt_matches:bool;
  f_challenge_consumed:bool;
  f_credential_matches_current:bool;
  f_assertion_valid:bool;
  f_user_verified:bool;
  f_share_present:bool;
  f_account_epoch_active:bool;
  f_epoch:i64
}

type t_ReleasePermit = {
  f_epoch:i64;
  f_issue_single_use_grant:bool
}

type t_RecoverDecision =
  | RecoverDecision_Release : t_ReleasePermit -> t_RecoverDecision
  | RecoverDecision_Reject : t_RecoverDecision

let recovery_is_authorized (facts: t_RecoverFacts) : bool =
  facts.f_phase =. (RecoveryPhase_ChallengePending <: t_RecoveryPhase) && facts.f_user_matches &&
  facts.f_attempt_matches &&
  facts.f_challenge_consumed &&
  facts.f_credential_matches_current &&
  facts.f_assertion_valid &&
  facts.f_user_verified &&
  facts.f_share_present &&
  facts.f_account_epoch_active &&
  facts.f_epoch >=. v_INITIAL_EPOCH

let recovery_decision_matches_spec (facts: t_RecoverFacts) (decision: t_RecoverDecision) : bool =
  match decision <: t_RecoverDecision with
  | RecoverDecision_Release permit ->
    recovery_is_authorized facts && permit.f_epoch =. facts.f_epoch &&
    permit.f_issue_single_use_grant
  | RecoverDecision_Reject  -> ~.(recovery_is_authorized facts <: bool)

let plan_recovery (facts: t_RecoverFacts)
    : Prims.Pure t_RecoverDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_RecoverDecision = decision in
          recovery_decision_matches_spec facts decision) =
  if recovery_is_authorized facts
  then
    RecoverDecision_Release
    ({ f_epoch = facts.f_epoch; f_issue_single_use_grant = true } <: t_ReleasePermit)
    <:
    t_RecoverDecision
  else RecoverDecision_Reject <: t_RecoverDecision

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
  facts.f_phase =. (RecoveryPhase_Ready <: t_RecoveryPhase) && facts.f_account_exists &&
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

/// Facts for redeeming one possession-proof attempt. The cryptographic
/// comparison itself stays outside this crate; `proof_verified` carries only
/// its authenticated outcome.
type t_PossessionRecoverFacts = {
  f_phase:t_RecoveryPhase;
  f_user_matches:bool;
  f_attempt_matches:bool;
  f_challenge_consumed:bool;
  f_proof_verified:bool;
  f_account_epoch_active:bool;
  f_commitment_epoch_matches:bool;
  f_epoch:i64
}

type t_PossessionGrantPermit = {
  f_epoch:i64;
  f_issues_single_use_grant:bool
}

type t_PossessionRecoverDecision =
  | PossessionRecoverDecision_Grant : t_PossessionGrantPermit -> t_PossessionRecoverDecision
  | PossessionRecoverDecision_Reject : t_PossessionRecoverDecision

/// A possession grant never releases Share 2 — the caller already proved
/// they can reconstruct without it.
let impl_PossessionGrantPermit__releases_server_share (self: t_PossessionGrantPermit) : bool = false

let possession_recovery_is_authorized (facts: t_PossessionRecoverFacts) : bool =
  facts.f_phase =. (RecoveryPhase_ChallengePending <: t_RecoveryPhase) && facts.f_user_matches &&
  facts.f_attempt_matches &&
  facts.f_challenge_consumed &&
  facts.f_proof_verified &&
  facts.f_account_epoch_active &&
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

let unproven_possession_claim_can_recover (facts: t_PossessionRecoverFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PossessionRecoverFacts =
    { facts with f_proof_verified = false } <: t_PossessionRecoverFacts
  in
  possession_recovery_is_authorized facts

let stale_commitment_can_recover (facts: t_PossessionRecoverFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PossessionRecoverFacts =
    { facts with f_commitment_epoch_matches = false } <: t_PossessionRecoverFacts
  in
  possession_recovery_is_authorized facts

type t_CredentialUpdateFacts = {
  f_assertion_valid:bool;
  f_credential_matches_current:bool;
  f_needs_update:bool
}

type t_CredentialUpdateDecision =
  | CredentialUpdateDecision_Update : t_CredentialUpdateDecision
  | CredentialUpdateDecision_Keep : t_CredentialUpdateDecision
  | CredentialUpdateDecision_Reject : t_CredentialUpdateDecision

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_149': Core_models.Cmp.t_PartialEq t_CredentialUpdateDecision t_CredentialUpdateDecision

unfold
let impl_149 = impl_149'

let credential_update_decision_matches_spec
      (facts: t_CredentialUpdateFacts)
      (decision: t_CredentialUpdateDecision)
    : bool =
  decision =.
  (if (~.facts.f_assertion_valid <: bool) || (~.facts.f_credential_matches_current <: bool)
    then CredentialUpdateDecision_Reject <: t_CredentialUpdateDecision
    else
      if facts.f_needs_update
      then CredentialUpdateDecision_Update <: t_CredentialUpdateDecision
      else CredentialUpdateDecision_Keep <: t_CredentialUpdateDecision)

let plan_credential_update (facts: t_CredentialUpdateFacts)
    : Prims.Pure t_CredentialUpdateDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_CredentialUpdateDecision = decision in
          credential_update_decision_matches_spec facts decision) =
  if ~.facts.f_assertion_valid || ~.facts.f_credential_matches_current
  then CredentialUpdateDecision_Reject <: t_CredentialUpdateDecision
  else
    if facts.f_needs_update
    then CredentialUpdateDecision_Update <: t_CredentialUpdateDecision
    else CredentialUpdateDecision_Keep <: t_CredentialUpdateDecision

type t_EnrollmentFacts = {
  f_phase:t_RecoveryPhase;
  f_user_matches:bool;
  f_grant_live:bool;
  f_grant_consumed:bool;
  f_credential_matches_current:bool;
  f_possession_grant:bool;
  f_possession_hash_present:bool;
  f_public_keys_valid:bool;
  f_account_epoch_active:bool;
  f_grant_epoch:i64;
  f_account_epoch:i64
}

type t_EnrollmentPermit = { f_epoch:i64 }

type t_EnrollmentDecision =
  | EnrollmentDecision_Enroll : t_EnrollmentPermit -> t_EnrollmentDecision
  | EnrollmentDecision_Reject : t_EnrollmentDecision

let enrollment_is_authorized (facts: t_EnrollmentFacts) : bool =
  let grant_authority_ok:bool =
    if facts.f_possession_grant
    then facts.f_possession_hash_present
    else facts.f_credential_matches_current
  in
  grant_authority_ok && facts.f_phase =. (RecoveryPhase_GrantIssued <: t_RecoveryPhase) &&
  facts.f_user_matches &&
  facts.f_grant_live &&
  facts.f_grant_consumed &&
  facts.f_public_keys_valid &&
  facts.f_account_epoch_active &&
  facts.f_grant_epoch >=. v_INITIAL_EPOCH &&
  facts.f_grant_epoch =. facts.f_account_epoch

let enrollment_decision_matches_spec (facts: t_EnrollmentFacts) (decision: t_EnrollmentDecision)
    : bool =
  match decision <: t_EnrollmentDecision with
  | EnrollmentDecision_Enroll permit ->
    enrollment_is_authorized facts && permit.f_epoch =. facts.f_grant_epoch
  | EnrollmentDecision_Reject  -> ~.(enrollment_is_authorized facts <: bool)

let plan_enrollment (facts: t_EnrollmentFacts)
    : Prims.Pure t_EnrollmentDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_EnrollmentDecision = decision in
          enrollment_decision_matches_spec facts decision) =
  if enrollment_is_authorized facts
  then
    EnrollmentDecision_Enroll ({ f_epoch = facts.f_grant_epoch } <: t_EnrollmentPermit)
    <:
    t_EnrollmentDecision
  else EnrollmentDecision_Reject <: t_EnrollmentDecision

let replaced_credential_can_recover (facts: t_RecoverFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_RecoverFacts =
    { facts with f_credential_matches_current = false } <: t_RecoverFacts
  in
  recovery_is_authorized facts

let consumed_challenge_can_recover_again (facts: t_RecoverFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_RecoverFacts =
    { facts with f_phase = RecoveryPhase_Completed <: t_RecoveryPhase } <: t_RecoverFacts
  in
  recovery_is_authorized facts

let cross_user_grant_can_enroll (facts: t_EnrollmentFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EnrollmentFacts = { facts with f_user_matches = false } <: t_EnrollmentFacts in
  enrollment_is_authorized facts

let revoked_credential_grant_can_enroll (facts: t_EnrollmentFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EnrollmentFacts =
    { facts with f_credential_matches_current = false } <: t_EnrollmentFacts
  in
  let facts:t_EnrollmentFacts = { facts with f_possession_grant = false } <: t_EnrollmentFacts in
  enrollment_is_authorized facts

/// A possession grant whose verifying commitment was deleted (setup removal,
/// RMS rotation) can no longer enroll.
let commitmentless_possession_grant_can_enroll (facts: t_EnrollmentFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EnrollmentFacts = { facts with f_possession_grant = true } <: t_EnrollmentFacts in
  let facts:t_EnrollmentFacts =
    { facts with f_credential_matches_current = false } <: t_EnrollmentFacts
  in
  let facts:t_EnrollmentFacts =
    { facts with f_possession_hash_present = false } <: t_EnrollmentFacts
  in
  enrollment_is_authorized facts

let rotated_grant_can_enroll (facts: t_EnrollmentFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EnrollmentFacts =
    {
      facts with
      f_account_epoch
      =
      if facts.f_grant_epoch =. Core_models.Num.impl_i64__MAX
      then facts.f_grant_epoch -! mk_i64 1
      else facts.f_grant_epoch +! mk_i64 1
    }
    <:
    t_EnrollmentFacts
  in
  enrollment_is_authorized facts

let consumed_grant_can_enroll_again (facts: t_EnrollmentFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EnrollmentFacts =
    { facts with f_phase = RecoveryPhase_Completed <: t_RecoveryPhase } <: t_EnrollmentFacts
  in
  enrollment_is_authorized facts
