module Vela_crypto.Share_envelope
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

/// Everything the sender signs besides the item itself.
type t_ShareHeader = {
  f_sender_user_id:Alloc.String.t_String;
  f_sender_device_id:Alloc.String.t_String;
  f_sender_vk:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_recipient_user_id:Alloc.String.t_String;
  f_recipient_ek_digest:t_Array u8 (mk_usize 32);
  f_lineage_id:Alloc.String.t_String;
  f_revision:u64
}

/// A verified envelope: the signature checked out under `header.sender_vk`
/// and the recipient key digest matches the key that opened it.
type t_OpenedShare = {
  f_header:t_ShareHeader;
  f_item:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

/// What a recipient remembers about a share it accepted.
type t_SharePin = {
  f_sender_user_id:Alloc.String.t_String;
  f_sender_vk:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_lineage_id:Alloc.String.t_String;
  f_revision:u64
}

/// What the recipient knows independently of the envelope.
type t_AdmissionContext = {
  f_recipient_user_id:string;
  f_attributed_sender_user_id:string;
  f_pin:Core_models.Option.t_Option t_SharePin
}

/// Turn observations into policy facts. Public so tests and bridges can
/// check the mapping itself.
let admission_facts
      (opened: Core_models.Option.t_Option t_OpenedShare)
      (context: t_AdmissionContext)
    : Prims.Pure Vela_client_share_policy.t_ShareAdmissionFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:Vela_client_share_policy.t_ShareAdmissionFacts = facts in
          facts.Vela_client_share_policy.f_envelope_authenticated =.
          (Core_models.Option.impl__is_some #t_OpenedShare opened <: bool) &&
          facts.Vela_client_share_policy.f_has_pin =.
          (Core_models.Option.impl__is_some #t_SharePin context.f_pin <: bool) &&
          facts.Vela_client_share_policy.f_pinned_revision =.
          (Core_models.Option.impl__map_or #t_SharePin
              #u64
              #(t_SharePin -> u64)
              context.f_pin
              (mk_u64 0)
              (fun pin ->
                  let pin:t_SharePin = pin in
                  pin.f_revision)
            <:
            u64) &&
          facts.Vela_client_share_policy.f_candidate_revision =.
          (Core_models.Option.impl__map_or #t_OpenedShare
              #u64
              #(t_OpenedShare -> u64)
              opened
              (mk_u64 0)
              (fun value ->
                  let value:t_OpenedShare = value in
                  value.f_header.f_revision)
            <:
            u64) &&
          (match opened <: Core_models.Option.t_Option t_OpenedShare with
            | Core_models.Option.Option_Some value ->
              facts.Vela_client_share_policy.f_addressed_to_recipient =.
              ((Alloc.String.impl_String__as_str value.f_header.f_recipient_user_id <: string) =.
                context.f_recipient_user_id
                <:
                bool) &&
              facts.Vela_client_share_policy.f_sender_matches_attribution =.
              ((Alloc.String.impl_String__as_str value.f_header.f_sender_user_id <: string) =.
                context.f_attributed_sender_user_id
                <:
                bool) &&
              facts.Vela_client_share_policy.f_signer_matches_pin =.
              (Core_models.Option.impl__is_some_and #t_SharePin
                  #(t_SharePin -> bool)
                  context.f_pin
                  (fun pin ->
                      let pin:t_SharePin = pin in
                      (pin.f_sender_vk =. value.f_header.f_sender_vk <: bool) &&
                      (pin.f_sender_user_id =. value.f_header.f_sender_user_id <: bool))
                <:
                bool) &&
              facts.Vela_client_share_policy.f_lineage_matches_pin =.
              (Core_models.Option.impl__is_some_and #t_SharePin
                  #(t_SharePin -> bool)
                  context.f_pin
                  (fun pin ->
                      let pin:t_SharePin = pin in
                      pin.f_lineage_id =. value.f_header.f_lineage_id <: bool)
                <:
                bool)
            | Core_models.Option.Option_None  ->
              ~.facts.Vela_client_share_policy.f_addressed_to_recipient &&
              ~.facts.Vela_client_share_policy.f_sender_matches_attribution &&
              ~.facts.Vela_client_share_policy.f_signer_matches_pin &&
              ~.facts.Vela_client_share_policy.f_lineage_matches_pin)) =
  match opened <: Core_models.Option.t_Option t_OpenedShare with
  | Core_models.Option.Option_Some opened ->
    let h:t_ShareHeader = opened.f_header in
    {
      Vela_client_share_policy.f_envelope_authenticated = true;
      Vela_client_share_policy.f_addressed_to_recipient
      =
      (Alloc.String.impl_String__as_str h.f_recipient_user_id <: string) =.
      context.f_recipient_user_id;
      Vela_client_share_policy.f_sender_matches_attribution
      =
      (Alloc.String.impl_String__as_str h.f_sender_user_id <: string) =.
      context.f_attributed_sender_user_id;
      Vela_client_share_policy.f_has_pin
      =
      Core_models.Option.impl__is_some #t_SharePin context.f_pin;
      Vela_client_share_policy.f_signer_matches_pin
      =
      Core_models.Option.impl__is_some_and #t_SharePin
        #(t_SharePin -> bool)
        context.f_pin
        (fun p ->
            let p:t_SharePin = p in
            (p.f_sender_vk =. h.f_sender_vk <: bool) &&
            (p.f_sender_user_id =. h.f_sender_user_id <: bool));
      Vela_client_share_policy.f_lineage_matches_pin
      =
      Core_models.Option.impl__is_some_and #t_SharePin
        #(t_SharePin -> bool)
        context.f_pin
        (fun p ->
            let p:t_SharePin = p in
            p.f_lineage_id =. h.f_lineage_id <: bool);
      Vela_client_share_policy.f_pinned_revision
      =
      Core_models.Option.impl__map_or #t_SharePin
        #u64
        #(t_SharePin -> u64)
        context.f_pin
        (mk_u64 0)
        (fun p ->
            let p:t_SharePin = p in
            p.f_revision);
      Vela_client_share_policy.f_candidate_revision = h.f_revision
    }
    <:
    Vela_client_share_policy.t_ShareAdmissionFacts
  | _ ->
    {
      Vela_client_share_policy.f_envelope_authenticated = false;
      Vela_client_share_policy.f_addressed_to_recipient = false;
      Vela_client_share_policy.f_sender_matches_attribution = false;
      Vela_client_share_policy.f_has_pin
      =
      Core_models.Option.impl__is_some #t_SharePin context.f_pin;
      Vela_client_share_policy.f_signer_matches_pin = false;
      Vela_client_share_policy.f_lineage_matches_pin = false;
      Vela_client_share_policy.f_pinned_revision
      =
      Core_models.Option.impl__map_or #t_SharePin
        #u64
        #(t_SharePin -> u64)
        context.f_pin
        (mk_u64 0)
        (fun p ->
            let p:t_SharePin = p in
            p.f_revision);
      Vela_client_share_policy.f_candidate_revision = mk_u64 0
    }
    <:
    Vela_client_share_policy.t_ShareAdmissionFacts
