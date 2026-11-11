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

/// Raw observations from the recovery-initiation request, the `users` row and
/// the store slot that will hold the new attempt.
type t_InitiateObservation = {
  f_account_present:bool;
  f_share_present:bool;
  f_credential_present:bool;
  f_attempt_id_fresh:bool;
  f_ttl_secs:u64
}

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
  (match facts.f_phase <: t_RecoveryPhase with
    | RecoveryPhase_Ready  -> true
    | _ -> false) &&
  facts.f_account_exists &&
  facts.f_share_present &&
  facts.f_credential_present &&
  facts.f_attempt_id_fresh &&
  facts.f_ttl_positive

/// Turn raw account/share/credential/store observations into the initiation
/// facts. The phase names exactly the observed availability of an account,
/// its recovery share and its recovery credential; it is not supplied by the
/// caller.
let initiate_facts (obs: t_InitiateObservation)
    : Prims.Pure t_InitiateFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_InitiateFacts = facts in
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_Ready  -> true
            | _ -> false) =.
          (obs.f_account_present && obs.f_share_present && obs.f_credential_present) &&
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_Unavailable  -> true
            | _ -> false) =.
          (~.(obs.f_account_present && obs.f_share_present && obs.f_credential_present) <: bool) &&
          facts.f_account_exists =. obs.f_account_present &&
          facts.f_share_present =. obs.f_share_present &&
          facts.f_credential_present =. obs.f_credential_present &&
          facts.f_attempt_id_fresh =. obs.f_attempt_id_fresh &&
          facts.f_ttl_positive =. (obs.f_ttl_secs >. mk_u64 0 <: bool)) =
  let available:bool = obs.f_account_present && obs.f_share_present && obs.f_credential_present in
  {
    f_phase
    =
    if available
    then RecoveryPhase_Ready <: t_RecoveryPhase
    else RecoveryPhase_Unavailable <: t_RecoveryPhase;
    f_account_exists = obs.f_account_present;
    f_share_present = obs.f_share_present;
    f_credential_present = obs.f_credential_present;
    f_attempt_id_fresh = obs.f_attempt_id_fresh;
    f_ttl_positive = obs.f_ttl_secs >. mk_u64 0
  }
  <:
  t_InitiateFacts

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
