module Vela_enrollment_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

type t_CeremonyPhase =
  | CeremonyPhase_Open : t_CeremonyPhase
  | CeremonyPhase_Claimed : t_CeremonyPhase
  | CeremonyPhase_Completed : t_CeremonyPhase
  | CeremonyPhase_Revoked : t_CeremonyPhase
  | CeremonyPhase_Expired : t_CeremonyPhase

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core_models.Cmp.t_PartialEq t_CeremonyPhase t_CeremonyPhase

unfold
let impl_7 = impl_7'

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
  facts.f_phase =. (CeremonyPhase_Open <: t_CeremonyPhase) && facts.f_grant_live &&
  facts.f_no_existing_claim &&
  facts.f_public_keys_valid

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
  facts.f_phase =. (CeremonyPhase_Claimed <: t_CeremonyPhase) && facts.f_user_matches &&
  facts.f_opener_matches &&
  facts.f_claim_present

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
  facts.f_phase =. (CeremonyPhase_Claimed <: t_CeremonyPhase) && facts.f_user_matches &&
  facts.f_opener_matches &&
  facts.f_opener_active &&
  facts.f_claim_present &&
  facts.f_displayed_claim_is_stored_claim &&
  facts.f_signature_covers_stored_claim &&
  facts.f_account_epoch_active

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

type t_ResultFacts = {
  f_phase:t_CeremonyPhase;
  f_claimed_key_present:bool;
  f_claimed_key_proof_valid:bool
}

type t_ResultKind =
  | ResultKind_Pending : t_ResultKind
  | ResultKind_Enrolled : t_ResultKind

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_91': Core_models.Cmp.t_PartialEq t_ResultKind t_ResultKind

unfold
let impl_91 = impl_91'

type t_ResultPermit = { f_kind:t_ResultKind }

type t_ResultDecision =
  | ResultDecision_Return : t_ResultPermit -> t_ResultDecision
  | ResultDecision_Reject : t_ResultDecision

let result_is_authorized (facts: t_ResultFacts) : bool =
  (facts.f_phase =. (CeremonyPhase_Claimed <: t_CeremonyPhase) ||
  facts.f_phase =. (CeremonyPhase_Completed <: t_CeremonyPhase)) &&
  facts.f_claimed_key_present &&
  facts.f_claimed_key_proof_valid

let result_decision_matches_spec (facts: t_ResultFacts) (decision: t_ResultDecision) : bool =
  match decision <: t_ResultDecision with
  | ResultDecision_Return permit ->
    result_is_authorized facts &&
    permit.f_kind =.
    (if facts.f_phase =. (CeremonyPhase_Claimed <: t_CeremonyPhase) <: bool
      then ResultKind_Pending <: t_ResultKind
      else ResultKind_Enrolled <: t_ResultKind)
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
      if facts.f_phase =. (CeremonyPhase_Claimed <: t_CeremonyPhase)
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
