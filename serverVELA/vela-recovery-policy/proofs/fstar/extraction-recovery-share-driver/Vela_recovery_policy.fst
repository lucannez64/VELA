module Vela_recovery_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
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

let impl_PublicationStagePermit__epoch (self: t_PublicationStagePermit) : i64 = self.f_epoch

let impl_PublicationStagePermit__binds_split_and_share (self: t_PublicationStagePermit) : bool =
  self.f_binds_split_and_share

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

let impl_PublicationFinalizePermit__epoch (self: t_PublicationFinalizePermit) : i64 = self.f_epoch

let impl_PublicationFinalizePermit__requires_exact_pending (self: t_PublicationFinalizePermit)
    : bool = self.f_exact_pending_required

let impl_PublicationFinalizePermit__requires_empty_active (self: t_PublicationFinalizePermit) : bool =
  self.f_empty_active_required

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

/// `DELETE /recovery/share`: the request names the epoch it believes is
/// current and the rekey policy issued a device-authority permit for it.
type t_ShareDeletionRequest = {
  f_declared_epoch:i64;
  f_device_authority:bool
}

type t_ShareDeletionPermit = {
  f_epoch:i64;
  f_clears_share_and_pending:bool
}

let impl_ShareDeletionPermit__epoch (self: t_ShareDeletionPermit) : i64 = self.f_epoch

let impl_ShareDeletionPermit__clears_share_and_pending (self: t_ShareDeletionPermit) : bool =
  self.f_clears_share_and_pending

type t_ShareDeletionDecision =
  | ShareDeletionDecision_Delete : t_ShareDeletionPermit -> t_ShareDeletionDecision
  | ShareDeletionDecision_Reject : t_ShareDeletionDecision

let share_deletion_is_authorized (request: t_ShareDeletionRequest) : bool =
  request.f_declared_epoch >=. v_INITIAL_EPOCH && request.f_device_authority

let share_deletion_decision_matches_spec
      (request: t_ShareDeletionRequest)
      (decision: t_ShareDeletionDecision)
    : bool =
  match decision <: t_ShareDeletionDecision with
  | ShareDeletionDecision_Delete permit ->
    share_deletion_is_authorized request && permit.f_epoch =. request.f_declared_epoch &&
    permit.f_clears_share_and_pending
  | ShareDeletionDecision_Reject  -> ~.(share_deletion_is_authorized request <: bool)

/// The single guarded statement clears the active share and the staged split
/// together; the permit records that indivisibility.
let plan_share_deletion (request: t_ShareDeletionRequest)
    : Prims.Pure t_ShareDeletionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ShareDeletionDecision = decision in
          share_deletion_decision_matches_spec request decision) =
  if share_deletion_is_authorized request
  then
    ShareDeletionDecision_Delete
    ({ f_epoch = request.f_declared_epoch; f_clears_share_and_pending = true }
      <:
      t_ShareDeletionPermit)
    <:
    t_ShareDeletionDecision
  else ShareDeletionDecision_Reject <: t_ShareDeletionDecision

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

/// Raw observations from `/recovery/recover`, the consumed challenge state,
/// the WebAuthn assertion and the `users` row.
type t_RecoverObservation = {
  f_attempt_source:t_RecoveryAttemptSource;
  f_user_matches:bool;
  f_attempt_matches:bool;
  f_credential_matches_current:bool;
  f_assertion_valid:bool;
  f_user_verified:bool;
  f_share_present:bool;
  f_account_epoch_active:bool;
  f_stored_epoch:Core_models.Option.t_Option i64
}

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

let impl_ReleasePermit__epoch (self: t_ReleasePermit) : i64 = self.f_epoch

let impl_ReleasePermit__issues_single_use_grant (self: t_ReleasePermit) : bool =
  self.f_issue_single_use_grant

type t_RecoverDecision =
  | RecoverDecision_Release : t_ReleasePermit -> t_RecoverDecision
  | RecoverDecision_Reject : t_RecoverDecision

let recovery_is_authorized (facts: t_RecoverFacts) : bool =
  (match facts.f_phase <: t_RecoveryPhase with
    | RecoveryPhase_ChallengePending  -> true
    | _ -> false) &&
  facts.f_user_matches &&
  facts.f_attempt_matches &&
  facts.f_challenge_consumed &&
  facts.f_credential_matches_current &&
  facts.f_assertion_valid &&
  facts.f_user_verified &&
  facts.f_share_present &&
  facts.f_account_epoch_active &&
  facts.f_epoch >=. v_INITIAL_EPOCH

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

/// Turn the consumed-attempt, assertion, credential and row observations into
/// the share-release facts. The phase and one-shot flag come from whether the
/// store actually returned (and removed) the exact challenge.
let recover_facts (obs: t_RecoverObservation)
    : Prims.Pure t_RecoverFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_RecoverFacts = facts in
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
          facts.f_user_matches =. obs.f_user_matches &&
          facts.f_attempt_matches =. obs.f_attempt_matches &&
          facts.f_challenge_consumed =.
          (match obs.f_attempt_source <: t_RecoveryAttemptSource with
            | RecoveryAttemptSource_Consumed  -> true
            | _ -> false) &&
          facts.f_credential_matches_current =. obs.f_credential_matches_current &&
          facts.f_assertion_valid =. obs.f_assertion_valid &&
          facts.f_user_verified =. obs.f_user_verified &&
          facts.f_share_present =. obs.f_share_present &&
          facts.f_account_epoch_active =. obs.f_account_epoch_active &&
          facts.f_epoch =. (observed_recovery_epoch obs.f_stored_epoch <: i64)) =
  let challenge_consumed:bool =
    match obs.f_attempt_source <: t_RecoveryAttemptSource with
    | RecoveryAttemptSource_Consumed  -> true
    | _ -> false
  in
  {
    f_phase
    =
    if challenge_consumed
    then RecoveryPhase_ChallengePending <: t_RecoveryPhase
    else RecoveryPhase_Expired <: t_RecoveryPhase;
    f_user_matches = obs.f_user_matches;
    f_attempt_matches = obs.f_attempt_matches;
    f_challenge_consumed = challenge_consumed;
    f_credential_matches_current = obs.f_credential_matches_current;
    f_assertion_valid = obs.f_assertion_valid;
    f_user_verified = obs.f_user_verified;
    f_share_present = obs.f_share_present;
    f_account_epoch_active = obs.f_account_epoch_active;
    f_epoch = observed_recovery_epoch obs.f_stored_epoch
  }
  <:
  t_RecoverFacts

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

/// Raw observations from the WebAuthn assertion and the live credential.
type t_CredentialUpdateObservation = {
  f_assertion_valid:bool;
  f_credential_matches_current:bool;
  f_needs_update:bool
}

type t_CredentialUpdateFacts = {
  f_assertion_valid:bool;
  f_credential_matches_current:bool;
  f_needs_update:bool
}

type t_CredentialUpdateDecision =
  | CredentialUpdateDecision_Update : t_CredentialUpdateDecision
  | CredentialUpdateDecision_Keep : t_CredentialUpdateDecision
  | CredentialUpdateDecision_Reject : t_CredentialUpdateDecision

/// Turn the assertion result and stored-credential comparison into the
/// metadata-update facts.
let credential_update_facts (obs: t_CredentialUpdateObservation)
    : Prims.Pure t_CredentialUpdateFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_CredentialUpdateFacts = facts in
          facts.f_assertion_valid =. obs.f_assertion_valid &&
          facts.f_credential_matches_current =. obs.f_credential_matches_current &&
          facts.f_needs_update =. obs.f_needs_update) =
  {
    f_assertion_valid = obs.f_assertion_valid;
    f_credential_matches_current = obs.f_credential_matches_current;
    f_needs_update = obs.f_needs_update
  }
  <:
  t_CredentialUpdateFacts

let credential_update_decision_matches_spec
      (facts: t_CredentialUpdateFacts)
      (decision: t_CredentialUpdateDecision)
    : bool =
  if ~.facts.f_assertion_valid || ~.facts.f_credential_matches_current
  then
    match decision <: t_CredentialUpdateDecision with
    | CredentialUpdateDecision_Reject  -> true
    | _ -> false
  else
    if facts.f_needs_update
    then
      match decision <: t_CredentialUpdateDecision with
      | CredentialUpdateDecision_Update  -> true
      | _ -> false
    else
      match decision <: t_CredentialUpdateDecision with
      | CredentialUpdateDecision_Keep  -> true
      | _ -> false

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
