module Vela_enrollment_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

/// Decoded length of a hybrid encapsulation key (`X25519` + `ML-KEM`).
let v_HYBRID_EK_LEN: usize = mk_usize 1568 +! mk_usize 32

/// Decoded length of a hybrid verification key (`Ed25519` + `ML-DSA`).
let v_HYBRID_VK_LEN: usize = mk_usize 2592 +! mk_usize 32

type t_CeremonyPhase =
  | CeremonyPhase_Open : t_CeremonyPhase
  | CeremonyPhase_Claimed : t_CeremonyPhase
  | CeremonyPhase_Completed : t_CeremonyPhase
  | CeremonyPhase_Revoked : t_CeremonyPhase
  | CeremonyPhase_Expired : t_CeremonyPhase

/// Raw observations from the authenticated grant-opening request.
type t_OpenObservation = {
  f_scope_is_device:bool;
  f_user_id_present:bool;
  f_device_id_present:bool;
  f_ttl_secs:u64
}

type t_OpenFacts = {
  f_device_scope:bool;
  f_user_bound:bool;
  f_opener_bound:bool;
  f_ttl_positive:bool
}

type t_OpenPermit = { f_authorized:bool }

type t_OpenDecision =
  | OpenDecision_Open : t_OpenPermit -> t_OpenDecision
  | OpenDecision_Reject : t_OpenDecision

let open_is_authorized (facts: t_OpenFacts) : bool =
  facts.f_device_scope && facts.f_user_bound && facts.f_opener_bound && facts.f_ttl_positive

/// Turn raw session observations into the grant-opening facts.
let open_facts (obs: t_OpenObservation)
    : Prims.Pure t_OpenFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_OpenFacts = facts in
          facts.f_device_scope =. obs.f_scope_is_device &&
          facts.f_user_bound =. obs.f_user_id_present &&
          facts.f_opener_bound =. obs.f_device_id_present &&
          facts.f_ttl_positive =. (obs.f_ttl_secs >. mk_u64 0 <: bool)) =
  {
    f_device_scope = obs.f_scope_is_device;
    f_user_bound = obs.f_user_id_present;
    f_opener_bound = obs.f_device_id_present;
    f_ttl_positive = obs.f_ttl_secs >. mk_u64 0
  }
  <:
  t_OpenFacts

let open_decision_matches_spec (facts: t_OpenFacts) (decision: t_OpenDecision) : bool =
  match decision <: t_OpenDecision with
  | OpenDecision_Open permit -> open_is_authorized facts && permit.f_authorized
  | OpenDecision_Reject  -> ~.(open_is_authorized facts <: bool)

let plan_open (facts: t_OpenFacts)
    : Prims.Pure t_OpenDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_OpenDecision = decision in
          open_decision_matches_spec facts decision) =
  if open_is_authorized facts
  then OpenDecision_Open ({ f_authorized = true } <: t_OpenPermit) <: t_OpenDecision
  else OpenDecision_Reject <: t_OpenDecision

/// Raw observations from the unauthenticated claim request and the store.
type t_ClaimObservation = {
  f_grant_live:bool;
  f_claim_exists:bool;
  f_hybrid_ek_len:usize;
  f_hybrid_vk_len:usize
}

type t_ClaimFacts = {
  f_phase:t_CeremonyPhase;
  f_grant_live:bool;
  f_no_existing_claim:bool;
  f_public_keys_valid:bool
}

type t_ClaimPermit = { f_authorized:bool }

type t_ClaimDecision =
  | ClaimDecision_Claim : t_ClaimPermit -> t_ClaimDecision
  | ClaimDecision_Reject : t_ClaimDecision

let claim_is_authorized (facts: t_ClaimFacts) : bool =
  (match facts.f_phase <: t_CeremonyPhase with
    | CeremonyPhase_Open  -> true
    | _ -> false) &&
  facts.f_grant_live &&
  facts.f_no_existing_claim &&
  facts.f_public_keys_valid

/// Turn raw grant/claim/store observations into the claim facts.
let claim_facts (obs: t_ClaimObservation)
    : Prims.Pure t_ClaimFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_ClaimFacts = facts in
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Claimed  -> true
            | _ -> false) =.
          obs.f_claim_exists &&
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Open  -> true
            | _ -> false) =.
          (~.obs.f_claim_exists <: bool) &&
          facts.f_grant_live =. obs.f_grant_live &&
          facts.f_no_existing_claim =. (~.obs.f_claim_exists <: bool) &&
          facts.f_public_keys_valid =.
          ((obs.f_hybrid_ek_len =. v_HYBRID_EK_LEN <: bool) &&
          (obs.f_hybrid_vk_len =. v_HYBRID_VK_LEN <: bool))) =
  {
    f_phase
    =
    if obs.f_claim_exists
    then CeremonyPhase_Claimed <: t_CeremonyPhase
    else CeremonyPhase_Open <: t_CeremonyPhase;
    f_grant_live = obs.f_grant_live;
    f_no_existing_claim = ~.obs.f_claim_exists;
    f_public_keys_valid
    =
    obs.f_hybrid_ek_len =. v_HYBRID_EK_LEN && obs.f_hybrid_vk_len =. v_HYBRID_VK_LEN
  }
  <:
  t_ClaimFacts

let claim_decision_matches_spec (facts: t_ClaimFacts) (decision: t_ClaimDecision) : bool =
  match decision <: t_ClaimDecision with
  | ClaimDecision_Claim permit -> claim_is_authorized facts && permit.f_authorized
  | ClaimDecision_Reject  -> ~.(claim_is_authorized facts <: bool)

let plan_claim (facts: t_ClaimFacts)
    : Prims.Pure t_ClaimDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ClaimDecision = decision in
          claim_decision_matches_spec facts decision) =
  if claim_is_authorized facts
  then ClaimDecision_Claim ({ f_authorized = true } <: t_ClaimPermit) <: t_ClaimDecision
  else ClaimDecision_Reject <: t_ClaimDecision

/// Raw observations from the claim-inspection request.
type t_InspectObservation = {
  f_claim_present:bool;
  f_user_matches:bool;
  f_opener_matches:bool
}

type t_InspectFacts = {
  f_phase:t_CeremonyPhase;
  f_user_matches:bool;
  f_opener_matches:bool;
  f_claim_present:bool
}

type t_InspectPermit = { f_authorized:bool }

type t_InspectDecision =
  | InspectDecision_Inspect : t_InspectPermit -> t_InspectDecision
  | InspectDecision_Reject : t_InspectDecision

let inspection_is_authorized (facts: t_InspectFacts) : bool =
  (match facts.f_phase <: t_CeremonyPhase with
    | CeremonyPhase_Claimed  -> true
    | _ -> false) &&
  facts.f_user_matches &&
  facts.f_opener_matches &&
  facts.f_claim_present

/// Turn raw claim/store/session observations into the inspection facts.
let inspect_facts (obs: t_InspectObservation)
    : Prims.Pure t_InspectFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_InspectFacts = facts in
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Claimed  -> true
            | _ -> false) =.
          obs.f_claim_present &&
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Open  -> true
            | _ -> false) =.
          (~.obs.f_claim_present <: bool) &&
          facts.f_user_matches =. obs.f_user_matches &&
          facts.f_opener_matches =. obs.f_opener_matches &&
          facts.f_claim_present =. obs.f_claim_present) =
  {
    f_phase
    =
    if obs.f_claim_present
    then CeremonyPhase_Claimed <: t_CeremonyPhase
    else CeremonyPhase_Open <: t_CeremonyPhase;
    f_user_matches = obs.f_user_matches;
    f_opener_matches = obs.f_opener_matches;
    f_claim_present = obs.f_claim_present
  }
  <:
  t_InspectFacts

let inspection_decision_matches_spec (facts: t_InspectFacts) (decision: t_InspectDecision) : bool =
  match decision <: t_InspectDecision with
  | InspectDecision_Inspect permit -> inspection_is_authorized facts && permit.f_authorized
  | InspectDecision_Reject  -> ~.(inspection_is_authorized facts <: bool)

let authorize_inspection (facts: t_InspectFacts)
    : Prims.Pure t_InspectDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_InspectDecision = decision in
          inspection_decision_matches_spec facts decision) =
  if inspection_is_authorized facts
  then InspectDecision_Inspect ({ f_authorized = true } <: t_InspectPermit) <: t_InspectDecision
  else InspectDecision_Reject <: t_InspectDecision

/// Where the completion path obtained the key material it verified and enrolled.
type t_ClaimKeySource =
  | ClaimKeySource_StoredClaim : t_ClaimKeySource
  | ClaimKeySource_RequestSupplied : t_ClaimKeySource

/// Raw observations from the completion request, the store, SQL and the
/// primary's hybrid signature check.
type t_CompletionObservation = {
  f_claim_present:bool;
  f_user_matches:bool;
  f_opener_matches:bool;
  f_opener_active:bool;
  f_signature_verified:bool;
  f_claim_key_source:t_ClaimKeySource;
  f_account_epoch:i64;
  f_declared_epoch:i64;
  f_rotation_in_progress:bool
}

type t_CompletionFacts = {
  f_phase:t_CeremonyPhase;
  f_user_matches:bool;
  f_opener_matches:bool;
  f_opener_active:bool;
  f_claim_present:bool;
  f_displayed_claim_is_stored_claim:bool;
  f_signature_covers_stored_claim:bool;
  f_account_epoch_active:bool
}

type t_CompletionPermit = { f_consume_grant_and_claim:bool }

type t_CompletionDecision =
  | CompletionDecision_Complete : t_CompletionPermit -> t_CompletionDecision
  | CompletionDecision_Reject : t_CompletionDecision

let completion_is_authorized (facts: t_CompletionFacts) : bool =
  (match facts.f_phase <: t_CeremonyPhase with
    | CeremonyPhase_Claimed  -> true
    | _ -> false) &&
  facts.f_user_matches &&
  facts.f_opener_matches &&
  facts.f_opener_active &&
  facts.f_claim_present &&
  facts.f_displayed_claim_is_stored_claim &&
  facts.f_signature_covers_stored_claim &&
  facts.f_account_epoch_active

/// Turn raw completion observations into the completion facts.
let completion_facts (obs: t_CompletionObservation)
    : Prims.Pure t_CompletionFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_CompletionFacts = facts in
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Claimed  -> true
            | _ -> false) =.
          obs.f_claim_present &&
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Open  -> true
            | _ -> false) =.
          (~.obs.f_claim_present <: bool) &&
          facts.f_user_matches =. obs.f_user_matches &&
          facts.f_opener_matches =. obs.f_opener_matches &&
          facts.f_opener_active =. obs.f_opener_active &&
          facts.f_claim_present =. obs.f_claim_present &&
          facts.f_displayed_claim_is_stored_claim =.
          (obs.f_claim_present &&
          (match obs.f_claim_key_source <: t_ClaimKeySource with
            | ClaimKeySource_StoredClaim  -> true
            | _ -> false)) &&
          facts.f_signature_covers_stored_claim =.
          (obs.f_signature_verified && obs.f_claim_present &&
          (match obs.f_claim_key_source <: t_ClaimKeySource with
            | ClaimKeySource_StoredClaim  -> true
            | _ -> false)) &&
          facts.f_account_epoch_active =.
          ((obs.f_declared_epoch >=. mk_i64 1 <: bool) &&
          (obs.f_account_epoch =. obs.f_declared_epoch <: bool) &&
          (~.obs.f_rotation_in_progress <: bool))) =
  {
    f_phase
    =
    if obs.f_claim_present
    then CeremonyPhase_Claimed <: t_CeremonyPhase
    else CeremonyPhase_Open <: t_CeremonyPhase;
    f_user_matches = obs.f_user_matches;
    f_opener_matches = obs.f_opener_matches;
    f_opener_active = obs.f_opener_active;
    f_claim_present = obs.f_claim_present;
    f_displayed_claim_is_stored_claim
    =
    obs.f_claim_present &&
    (match obs.f_claim_key_source <: t_ClaimKeySource with
      | ClaimKeySource_StoredClaim  -> true
      | _ -> false);
    f_signature_covers_stored_claim
    =
    obs.f_signature_verified && obs.f_claim_present &&
    (match obs.f_claim_key_source <: t_ClaimKeySource with
      | ClaimKeySource_StoredClaim  -> true
      | _ -> false);
    f_account_epoch_active
    =
    obs.f_declared_epoch >=. mk_i64 1 && obs.f_account_epoch =. obs.f_declared_epoch &&
    ~.obs.f_rotation_in_progress
  }
  <:
  t_CompletionFacts

let completion_decision_matches_spec (facts: t_CompletionFacts) (decision: t_CompletionDecision)
    : bool =
  match decision <: t_CompletionDecision with
  | CompletionDecision_Complete permit ->
    completion_is_authorized facts && permit.f_consume_grant_and_claim
  | CompletionDecision_Reject  -> ~.(completion_is_authorized facts <: bool)

let plan_completion (facts: t_CompletionFacts)
    : Prims.Pure t_CompletionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_CompletionDecision = decision in
          completion_decision_matches_spec facts decision) =
  if completion_is_authorized facts
  then
    CompletionDecision_Complete ({ f_consume_grant_and_claim = true } <: t_CompletionPermit)
    <:
    t_CompletionDecision
  else CompletionDecision_Reject <: t_CompletionDecision

/// Where the result request found the ceremony.
type t_ResultSource =
  | ResultSource_CompletedResult : t_ResultSource
  | ResultSource_ClaimedClaim : t_ResultSource
  | ResultSource_NoRecord : t_ResultSource

/// Raw observations from the result request and the store.
type t_ResultObservation = {
  f_source:t_ResultSource;
  f_claimed_key_len:usize;
  f_signature_verified:bool
}

type t_ResultFacts = {
  f_phase:t_CeremonyPhase;
  f_claimed_key_present:bool;
  f_claimed_key_proof_valid:bool
}

type t_ResultKind =
  | ResultKind_Pending : t_ResultKind
  | ResultKind_Enrolled : t_ResultKind

type t_ResultPermit = { f_kind:t_ResultKind }

type t_ResultDecision =
  | ResultDecision_Return : t_ResultPermit -> t_ResultDecision
  | ResultDecision_Reject : t_ResultDecision

let result_is_authorized (facts: t_ResultFacts) : bool =
  ((match facts.f_phase <: t_CeremonyPhase with
    | CeremonyPhase_Claimed  -> true
    | _ -> false) ||
  (match facts.f_phase <: t_CeremonyPhase with
    | CeremonyPhase_Completed  -> true
    | _ -> false)) &&
  facts.f_claimed_key_present &&
  facts.f_claimed_key_proof_valid

/// Turn raw result/store/signature observations into the result facts.
let result_facts (obs: t_ResultObservation)
    : Prims.Pure t_ResultFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_ResultFacts = facts in
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Completed  -> true
            | _ -> false) =.
          (match obs.f_source <: t_ResultSource with
            | ResultSource_CompletedResult  -> true
            | _ -> false) &&
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Claimed  -> true
            | _ -> false) =.
          (match obs.f_source <: t_ResultSource with
            | ResultSource_ClaimedClaim  -> true
            | _ -> false) &&
          (match facts.f_phase <: t_CeremonyPhase with
            | CeremonyPhase_Expired  -> true
            | _ -> false) =.
          (match obs.f_source <: t_ResultSource with
            | ResultSource_NoRecord  -> true
            | _ -> false) &&
          facts.f_claimed_key_present =. (obs.f_claimed_key_len >. mk_usize 0 <: bool) &&
          facts.f_claimed_key_proof_valid =.
          ((obs.f_claimed_key_len >. mk_usize 0 <: bool) && obs.f_signature_verified)) =
  {
    f_phase
    =
    (match obs.f_source <: t_ResultSource with
      | ResultSource_CompletedResult  -> CeremonyPhase_Completed <: t_CeremonyPhase
      | ResultSource_ClaimedClaim  -> CeremonyPhase_Claimed <: t_CeremonyPhase
      | ResultSource_NoRecord  -> CeremonyPhase_Expired <: t_CeremonyPhase);
    f_claimed_key_present = obs.f_claimed_key_len >. mk_usize 0;
    f_claimed_key_proof_valid = obs.f_claimed_key_len >. mk_usize 0 && obs.f_signature_verified
  }
  <:
  t_ResultFacts

let result_decision_matches_spec (facts: t_ResultFacts) (decision: t_ResultDecision) : bool =
  match decision <: t_ResultDecision with
  | ResultDecision_Return permit ->
    result_is_authorized facts &&
    (if
        match facts.f_phase <: t_CeremonyPhase with
        | CeremonyPhase_Claimed  -> true
        | _ -> false
      then
        match permit.f_kind <: t_ResultKind with
        | ResultKind_Pending  -> true
        | _ -> false
      else
        match permit.f_kind <: t_ResultKind with
        | ResultKind_Enrolled  -> true
        | _ -> false)
  | ResultDecision_Reject  -> ~.(result_is_authorized facts <: bool)

let authorize_result (facts: t_ResultFacts)
    : Prims.Pure t_ResultDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ResultDecision = decision in
          result_decision_matches_spec facts decision) =
  if ~.(result_is_authorized facts <: bool)
  then ResultDecision_Reject <: t_ResultDecision
  else
    let kind:t_ResultKind =
      if
        match facts.f_phase <: t_CeremonyPhase with
        | CeremonyPhase_Claimed  -> true
        | _ -> false
      then ResultKind_Pending <: t_ResultKind
      else ResultKind_Enrolled <: t_ResultKind
    in
    ResultDecision_Return ({ f_kind = kind } <: t_ResultPermit) <: t_ResultDecision

let completed_ceremony_can_complete_again (facts: t_CompletionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_CompletionFacts =
    { facts with f_phase = CeremonyPhase_Completed <: t_CeremonyPhase } <: t_CompletionFacts
  in
  completion_is_authorized facts

let other_device_can_inspect (facts: t_InspectFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_InspectFacts = { facts with f_opener_matches = false } <: t_InspectFacts in
  inspection_is_authorized facts

let substituted_claim_can_complete (facts: t_CompletionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_CompletionFacts =
    { facts with f_displayed_claim_is_stored_claim = false } <: t_CompletionFacts
  in
  completion_is_authorized facts

let result_without_claimed_key_proof (facts: t_ResultFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ResultFacts = { facts with f_claimed_key_proof_valid = false } <: t_ResultFacts in
  result_is_authorized facts

let web_session_can_open_enrollment_grant (obs: t_OpenObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_OpenObservation = { obs with f_scope_is_device = false } <: t_OpenObservation in
  open_is_authorized (open_facts obs <: t_OpenFacts)

let expired_grant_can_open (obs: t_OpenObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_OpenObservation = { obs with f_ttl_secs = mk_u64 0 } <: t_OpenObservation in
  open_is_authorized (open_facts obs <: t_OpenFacts)

let missing_grant_can_be_claimed (obs: t_ClaimObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_ClaimObservation = { obs with f_grant_live = false } <: t_ClaimObservation in
  claim_is_authorized (claim_facts obs <: t_ClaimFacts)

let invalid_public_key_length_can_be_claimed (obs: t_ClaimObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_ClaimObservation = { obs with f_hybrid_ek_len = mk_usize 0 } <: t_ClaimObservation in
  claim_is_authorized (claim_facts obs <: t_ClaimFacts)

let missing_claim_can_be_inspected (obs: t_InspectObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_InspectObservation = { obs with f_claim_present = false } <: t_InspectObservation in
  inspection_is_authorized (inspect_facts obs <: t_InspectFacts)

let other_device_can_inspect_observed_claim (obs: t_InspectObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_InspectObservation = { obs with f_opener_matches = false } <: t_InspectObservation in
  inspection_is_authorized (inspect_facts obs <: t_InspectFacts)

let revoked_opener_can_complete (obs: t_CompletionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_CompletionObservation =
    { obs with f_opener_active = false } <: t_CompletionObservation
  in
  completion_is_authorized (completion_facts obs <: t_CompletionFacts)

let fforeign_device_can_complete_observed_ceremony (obs: t_CompletionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_CompletionObservation =
    { obs with f_opener_matches = false } <: t_CompletionObservation
  in
  completion_is_authorized (completion_facts obs <: t_CompletionFacts)

let unverified_signature_can_complete (obs: t_CompletionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_CompletionObservation =
    { obs with f_signature_verified = false } <: t_CompletionObservation
  in
  completion_is_authorized (completion_facts obs <: t_CompletionFacts)

let missing_claim_can_complete_observed_ceremony (obs: t_CompletionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_CompletionObservation =
    { obs with f_claim_present = false } <: t_CompletionObservation
  in
  completion_is_authorized (completion_facts obs <: t_CompletionFacts)

let request_supplied_claim_can_complete (obs: t_CompletionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_CompletionObservation =
    { obs with f_claim_key_source = ClaimKeySource_RequestSupplied <: t_ClaimKeySource }
    <:
    t_CompletionObservation
  in
  completion_is_authorized (completion_facts obs <: t_CompletionFacts)

let stale_epoch_can_complete (obs: t_CompletionObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_CompletionObservation =
    { obs with f_declared_epoch = mk_i64 1 } <: t_CompletionObservation
  in
  let obs:t_CompletionObservation =
    { obs with f_account_epoch = mk_i64 0 } <: t_CompletionObservation
  in
  completion_is_authorized (completion_facts obs <: t_CompletionFacts)

let invalid_result_signature_can_return_result (obs: t_ResultObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_ResultObservation = { obs with f_signature_verified = false } <: t_ResultObservation in
  result_is_authorized (result_facts obs <: t_ResultFacts)

let missing_claimed_key_can_return_result (obs: t_ResultObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_ResultObservation =
    { obs with f_claimed_key_len = mk_usize 0 } <: t_ResultObservation
  in
  result_is_authorized (result_facts obs <: t_ResultFacts)

let unclaimed_ceremony_can_return_result (obs: t_ResultObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let obs:t_ResultObservation =
    { obs with f_source = ResultSource_NoRecord <: t_ResultSource } <: t_ResultObservation
  in
  result_is_authorized (result_facts obs <: t_ResultFacts)
