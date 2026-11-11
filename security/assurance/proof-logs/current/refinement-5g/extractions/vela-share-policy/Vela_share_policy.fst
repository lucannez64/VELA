module Vela_share_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

let v_INITIAL_SEQ: i64 = mk_i64 1

/// Facts observed when a device registers or updates its share encapsulation
/// key. The cryptographic signature check itself stays outside this crate;
/// `signature_verified` carries its authenticated outcome.
type t_EkRegistrationFacts = {
  f_ek_size_valid:bool;
  f_signature_verified:bool;
  f_device_owned_by_caller:bool;
  f_device_active:bool;
  f_signed_at_is_fresher:bool;
  f_seq:i64
}

type t_EkRegistrationPermit = {
  f_seq:i64;
  f_binds_device_signature:bool
}

type t_EkRegistrationDecision =
  | EkRegistrationDecision_Register : t_EkRegistrationPermit -> t_EkRegistrationDecision
  | EkRegistrationDecision_Reject : t_EkRegistrationDecision

let ek_registration_is_authorized (facts: t_EkRegistrationFacts) : bool =
  facts.f_ek_size_valid && facts.f_signature_verified && facts.f_device_owned_by_caller &&
  facts.f_device_active &&
  facts.f_signed_at_is_fresher &&
  facts.f_seq >=. v_INITIAL_SEQ

let ek_registration_decision_matches_spec
      (facts: t_EkRegistrationFacts)
      (decision: t_EkRegistrationDecision)
    : bool =
  match decision <: t_EkRegistrationDecision with
  | EkRegistrationDecision_Register permit ->
    ek_registration_is_authorized facts && permit.f_seq =. facts.f_seq &&
    permit.f_binds_device_signature
  | EkRegistrationDecision_Reject  -> ~.(ek_registration_is_authorized facts <: bool)

let plan_ek_registration (facts: t_EkRegistrationFacts)
    : Prims.Pure t_EkRegistrationDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_EkRegistrationDecision = decision in
          ek_registration_decision_matches_spec facts decision) =
  if ek_registration_is_authorized facts
  then
    EkRegistrationDecision_Register
    ({ f_seq = facts.f_seq; f_binds_device_signature = true } <: t_EkRegistrationPermit)
    <:
    t_EkRegistrationDecision
  else EkRegistrationDecision_Reject <: t_EkRegistrationDecision

let forged_ek_binding_can_register (facts: t_EkRegistrationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EkRegistrationFacts =
    { facts with f_signature_verified = false } <: t_EkRegistrationFacts
  in
  ek_registration_is_authorized facts

let replayed_ek_binding_can_register (facts: t_EkRegistrationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EkRegistrationFacts =
    { facts with f_signed_at_is_fresher = false } <: t_EkRegistrationFacts
  in
  ek_registration_is_authorized facts

let fforeign_device_ek_can_register (facts: t_EkRegistrationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EkRegistrationFacts =
    { facts with f_device_owned_by_caller = false } <: t_EkRegistrationFacts
  in
  ek_registration_is_authorized facts

let revoked_device_ek_can_register (facts: t_EkRegistrationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EkRegistrationFacts =
    { facts with f_device_active = false } <: t_EkRegistrationFacts
  in
  ek_registration_is_authorized facts

/// Minimum plausible length for a canonical RFC 3339 UTC rendering
/// (`YYYY-MM-DDTHH:MM:SSZ` = 20 chars); the handler caps at 64.
let timestamp_format_plausible (len: usize) : bool = len >=. mk_usize 20 && len <=. mk_usize 64

type t_SendCapsuleFacts = {
  f_sender_authenticated:bool;
  f_recipient_registered:bool;
  f_capsule_size_valid:bool;
  f_inbox_has_capacity:bool
}

type t_SendDecision =
  | SendDecision_Deliver : t_SendDecision
  | SendDecision_Reject : t_SendDecision

let send_is_authorized (facts: t_SendCapsuleFacts) : bool =
  facts.f_sender_authenticated && facts.f_recipient_registered && facts.f_capsule_size_valid &&
  facts.f_inbox_has_capacity

let plan_send (facts: t_SendCapsuleFacts)
    : Prims.Pure t_SendDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_SendDecision = decision in
          (match decision <: t_SendDecision with
            | SendDecision_Deliver  -> true
            | _ -> false) =.
          (send_is_authorized facts <: bool)) =
  if send_is_authorized facts
  then SendDecision_Deliver <: t_SendDecision
  else SendDecision_Reject <: t_SendDecision

type t_LinkMutationFacts = {
  f_caller_is_sender:bool;
  f_item_exists:bool;
  f_not_already_revoked:bool
}

type t_LinkMutationDecision =
  | LinkMutationDecision_Apply : t_LinkMutationDecision
  | LinkMutationDecision_Reject : t_LinkMutationDecision

let link_mutation_is_authorized (facts: t_LinkMutationFacts) : bool =
  facts.f_caller_is_sender && facts.f_item_exists && facts.f_not_already_revoked

let plan_link_mutation (facts: t_LinkMutationFacts)
    : Prims.Pure t_LinkMutationDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_LinkMutationDecision = decision in
          (match decision <: t_LinkMutationDecision with
            | LinkMutationDecision_Apply  -> true
            | _ -> false) =.
          (link_mutation_is_authorized facts <: bool)) =
  if link_mutation_is_authorized facts
  then LinkMutationDecision_Apply <: t_LinkMutationDecision
  else LinkMutationDecision_Reject <: t_LinkMutationDecision

let non_sender_can_mutate_link (facts: t_LinkMutationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_LinkMutationFacts =
    { facts with f_caller_is_sender = false } <: t_LinkMutationFacts
  in
  link_mutation_is_authorized facts

let revoked_link_can_mutate (facts: t_LinkMutationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_LinkMutationFacts =
    { facts with f_not_already_revoked = false } <: t_LinkMutationFacts
  in
  link_mutation_is_authorized facts
