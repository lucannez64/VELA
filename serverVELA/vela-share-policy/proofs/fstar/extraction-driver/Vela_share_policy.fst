module Vela_share_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

let v_INITIAL_SEQ: i64 = mk_i64 1

/// Decoded length of a hybrid share encapsulation key (`ML-KEM` + `X25519`).
let v_SHARE_EK_LEN: usize = mk_usize 1568 +! mk_usize 32

/// Largest capsule the send handler accepts, in decoded bytes.
let v_MAX_CAPSULE_BYTES: i64 = mk_i64 1024 *! mk_i64 1024

/// Largest total pending capsule payload a recipient inbox may hold.
let v_MAX_RECIPIENT_INBOX_BYTES: i64 = (mk_i64 32 *! mk_i64 1024 <: i64) *! mk_i64 1024

/// Raw observations from the share-EK registration request, the device row
/// and the store.
type t_EkRegistrationObservation = {
  f_ek_len:usize;
  f_signature_verified:bool;
  f_device_row_present:bool;
  f_device_user_matches:bool;
  f_device_active:bool;
  f_signed_at_is_fresher:bool;
  f_binding_exists:bool
}

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

let impl_EkRegistrationPermit__binds_device_signature (self: t_EkRegistrationPermit) : bool =
  self.f_binds_device_signature

type t_EkRegistrationDecision =
  | EkRegistrationDecision_Register : t_EkRegistrationPermit -> t_EkRegistrationDecision
  | EkRegistrationDecision_Reject : t_EkRegistrationDecision

let ek_registration_is_authorized (facts: t_EkRegistrationFacts) : bool =
  facts.f_ek_size_valid && facts.f_signature_verified && facts.f_device_owned_by_caller &&
  facts.f_device_active &&
  facts.f_signed_at_is_fresher &&
  facts.f_seq >=. v_INITIAL_SEQ

/// Turn raw request/device-row/store observations into the registration facts.
let ek_registration_facts (obs: t_EkRegistrationObservation)
    : Prims.Pure t_EkRegistrationFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_EkRegistrationFacts = facts in
          facts.f_ek_size_valid =. (obs.f_ek_len =. v_SHARE_EK_LEN <: bool) &&
          facts.f_signature_verified =. obs.f_signature_verified &&
          facts.f_device_owned_by_caller =. (obs.f_device_row_present && obs.f_device_user_matches) &&
          facts.f_device_active =. obs.f_device_active &&
          facts.f_signed_at_is_fresher =. obs.f_signed_at_is_fresher &&
          facts.f_seq =. (if obs.f_binding_exists then mk_i64 2 else mk_i64 1)) =
  {
    f_ek_size_valid = obs.f_ek_len =. v_SHARE_EK_LEN;
    f_signature_verified = obs.f_signature_verified;
    f_device_owned_by_caller = obs.f_device_row_present && obs.f_device_user_matches;
    f_device_active = obs.f_device_active;
    f_signed_at_is_fresher = obs.f_signed_at_is_fresher;
    f_seq = if obs.f_binding_exists then mk_i64 2 else mk_i64 1
  }
  <:
  t_EkRegistrationFacts

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

/// Raw observations from the send request, the recipient row and the inbox
/// quota queries.
type t_SendObservation = {
  f_session_user_id_present:bool;
  f_recipient_has_share_ek:bool;
  f_capsule_len:i64;
  f_existing_inbox_bytes:i64
}

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

/// Turn raw session/recipient/capsule/inbox observations into the send facts.
let send_facts (obs: t_SendObservation)
    : Prims.Pure t_SendCapsuleFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_SendCapsuleFacts = facts in
          facts.f_sender_authenticated =. obs.f_session_user_id_present &&
          facts.f_recipient_registered =. obs.f_recipient_has_share_ek &&
          facts.f_capsule_size_valid =.
          ((obs.f_capsule_len >. mk_i64 0 <: bool) &&
          (obs.f_capsule_len <=. v_MAX_CAPSULE_BYTES <: bool)) &&
          facts.f_inbox_has_capacity =.
          ((obs.f_existing_inbox_bytes >=. mk_i64 0 <: bool) &&
          (obs.f_capsule_len >=. mk_i64 0 <: bool) &&
          (((cast (obs.f_existing_inbox_bytes <: i64) <: i128) +!
              (cast (obs.f_capsule_len <: i64) <: i128)
              <:
              i128) <=.
            (cast (v_MAX_RECIPIENT_INBOX_BYTES <: i64) <: i128)
            <:
            bool))) =
  {
    f_sender_authenticated = obs.f_session_user_id_present;
    f_recipient_registered = obs.f_recipient_has_share_ek;
    f_capsule_size_valid
    =
    obs.f_capsule_len >. mk_i64 0 && obs.f_capsule_len <=. v_MAX_CAPSULE_BYTES;
    f_inbox_has_capacity
    =
    obs.f_existing_inbox_bytes >=. mk_i64 0 && obs.f_capsule_len >=. mk_i64 0 &&
    obs.f_capsule_len <=. v_MAX_RECIPIENT_INBOX_BYTES &&
    obs.f_existing_inbox_bytes <=. (v_MAX_RECIPIENT_INBOX_BYTES -! obs.f_capsule_len <: i64)
  }
  <:
  t_SendCapsuleFacts

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

/// Raw observations from the linked-share row.
type t_LinkMutationObservation = {
  f_item_present:bool;
  f_caller_matches_sender:bool;
  f_item_not_revoked:bool
}

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

/// Turn raw linked-row observations into the mutation facts.
let link_mutation_facts (obs: t_LinkMutationObservation)
    : Prims.Pure t_LinkMutationFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_LinkMutationFacts = facts in
          facts.f_caller_is_sender =. (obs.f_item_present && obs.f_caller_matches_sender) &&
          facts.f_item_exists =. obs.f_item_present &&
          facts.f_not_already_revoked =. (obs.f_item_present && obs.f_item_not_revoked)) =
  {
    f_caller_is_sender = obs.f_item_present && obs.f_caller_matches_sender;
    f_item_exists = obs.f_item_present;
    f_not_already_revoked = obs.f_item_present && obs.f_item_not_revoked
  }
  <:
  t_LinkMutationFacts

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
