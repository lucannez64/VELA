module Vela_recovery_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

let v_INITIAL_EPOCH: i64 = mk_i64 1

let v_HYBRID_EK_LEN: usize = mk_usize 1568 +! mk_usize 32

let v_HYBRID_VK_LEN: usize = mk_usize 2592 +! mk_usize 32

type t_RecoveryPhase =
  | RecoveryPhase_Unavailable : t_RecoveryPhase
  | RecoveryPhase_Ready : t_RecoveryPhase
  | RecoveryPhase_ChallengePending : t_RecoveryPhase
  | RecoveryPhase_GrantIssued : t_RecoveryPhase
  | RecoveryPhase_Completed : t_RecoveryPhase
  | RecoveryPhase_Revoked : t_RecoveryPhase
  | RecoveryPhase_Expired : t_RecoveryPhase

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

/// Permission to attempt the atomic single-use redemption. It says nothing
/// about whether the grant was actually consumed or whether a device may be
/// inserted; `plan_enrollment` decides the latter from the actual consumed
/// grant and the final observations.
type t_ReadyToConsume = {
  f_epoch:i64;
  f_possession:bool
}

let impl_ReadyToConsume__epoch (self: t_ReadyToConsume) : i64 = self.f_epoch

let impl_ReadyToConsume__possession (self: t_ReadyToConsume) : bool = self.f_possession

type t_EnrollmentFacts = {
  f_phase:t_RecoveryPhase;
  f_account_present:bool;
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

/// Raw observations from the enrollment grant store, the decoded grant and
/// the live `users` row.
type t_EnrollmentObservation = {
  f_grant_present:bool;
  f_grant_consumed:bool;
  f_consumed_matches_observed:bool;
  f_account_present:bool;
  f_grant_possession:bool;
  f_grant_epoch:i64;
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_account_epoch_active:bool;
  f_credential_id_matches:bool;
  f_commitment_len:usize;
  f_hybrid_ek_len:usize;
  f_hybrid_vk_len:usize
}

type t_EnrollmentPermit = { f_epoch:i64 }

let impl_EnrollmentPermit__epoch (self: t_EnrollmentPermit) : i64 = self.f_epoch

type t_EnrollmentDecision =
  | EnrollmentDecision_Enroll : t_EnrollmentPermit -> t_EnrollmentDecision
  | EnrollmentDecision_Reject : t_EnrollmentDecision

let enrollment_is_authorized (facts: t_EnrollmentFacts) : bool =
  let grant_authority_ok:bool =
    if facts.f_possession_grant
    then facts.f_possession_hash_present
    else facts.f_credential_matches_current
  in
  grant_authority_ok &&
  (match facts.f_phase <: t_RecoveryPhase with
    | RecoveryPhase_GrantIssued  -> true
    | _ -> false) &&
  facts.f_account_present &&
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

/// Turn the grant-store, decoded-grant and `users`-row observations into the
/// enrollment facts. The phase distinguishes a consumed grant from a missing
/// or race-replaced one; user binding, consumption, credential/commitment
/// authority and the normalized grant/account epoch equality are exactly the
/// observed values.
let enrollment_facts (obs: t_EnrollmentObservation)
    : Prims.Pure t_EnrollmentFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_EnrollmentFacts = facts in
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_GrantIssued  -> true
            | _ -> false) =.
          (obs.f_grant_present && obs.f_grant_consumed && obs.f_consumed_matches_observed) &&
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_Expired  -> true
            | _ -> false) =.
          (~.obs.f_grant_present <: bool) &&
          (match facts.f_phase <: t_RecoveryPhase with
            | RecoveryPhase_Revoked  -> true
            | _ -> false) =.
          (obs.f_grant_present &&
          (~.(obs.f_grant_consumed && obs.f_consumed_matches_observed) <: bool)) &&
          facts.f_account_present =. obs.f_account_present &&
          facts.f_user_matches =. obs.f_grant_present &&
          facts.f_grant_live =. obs.f_grant_present &&
          facts.f_grant_consumed =. (obs.f_grant_consumed && obs.f_consumed_matches_observed) &&
          facts.f_credential_matches_current =. obs.f_credential_id_matches &&
          facts.f_possession_grant =. obs.f_grant_possession &&
          facts.f_possession_hash_present =. (obs.f_commitment_len >. mk_usize 0 <: bool) &&
          facts.f_public_keys_valid =.
          ((obs.f_hybrid_ek_len =. v_HYBRID_EK_LEN <: bool) &&
          (obs.f_hybrid_vk_len =. v_HYBRID_VK_LEN <: bool)) &&
          facts.f_account_epoch_active =. obs.f_account_epoch_active &&
          facts.f_grant_epoch =. obs.f_grant_epoch &&
          facts.f_account_epoch =. (observed_recovery_epoch obs.f_stored_epoch <: i64)) =
  let consumed:bool = obs.f_grant_consumed && obs.f_consumed_matches_observed in
  {
    f_phase
    =
    if obs.f_grant_present && consumed
    then RecoveryPhase_GrantIssued <: t_RecoveryPhase
    else
      if ~.obs.f_grant_present
      then RecoveryPhase_Expired <: t_RecoveryPhase
      else RecoveryPhase_Revoked <: t_RecoveryPhase;
    f_account_present = obs.f_account_present;
    f_user_matches = obs.f_grant_present;
    f_grant_live = obs.f_grant_present;
    f_grant_consumed = consumed;
    f_credential_matches_current = obs.f_credential_id_matches;
    f_possession_grant = obs.f_grant_possession;
    f_possession_hash_present = obs.f_commitment_len >. mk_usize 0;
    f_public_keys_valid
    =
    obs.f_hybrid_ek_len =. v_HYBRID_EK_LEN && obs.f_hybrid_vk_len =. v_HYBRID_VK_LEN;
    f_account_epoch_active = obs.f_account_epoch_active;
    f_grant_epoch = obs.f_grant_epoch;
    f_account_epoch = observed_recovery_epoch obs.f_stored_epoch
  }
  <:
  t_EnrollmentFacts
