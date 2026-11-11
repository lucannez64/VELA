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

/// Pure prefix parser used by the real signed-envelope reader. Under the
/// trusted slice semantics, success returns exactly the requested prefix and
/// suffix; failure consumes nothing and never indexes outside the input.
let split_envelope_prefix (input: t_Slice u8) (n: usize)
    : Prims.Pure (Core_models.Option.t_Option (t_Slice u8 & t_Slice u8))
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) = result in
          match result <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
          | Core_models.Option.Option_Some (prefix, suffix) ->
            n <=. (Core_models.Slice.impl__len #u8 input <: usize) &&
            prefix =.
            (input.[ { Core_models.Ops.Range.f_end = n } <: Core_models.Ops.Range.t_RangeTo usize ]
              <:
              t_Slice u8) &&
            suffix =.
            (input.[ { Core_models.Ops.Range.f_start = n }
                <:
                Core_models.Ops.Range.t_RangeFrom usize ]
              <:
              t_Slice u8)
          | Core_models.Option.Option_None  -> (Core_models.Slice.impl__len #u8 input <: usize) <. n
      ) =
  if (Core_models.Slice.impl__len #u8 input <: usize) <. n
  then Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
  else
    Core_models.Option.Option_Some
    (input.[ { Core_models.Ops.Range.f_end = n } <: Core_models.Ops.Range.t_RangeTo usize ],
      input.[ { Core_models.Ops.Range.f_start = n } <: Core_models.Ops.Range.t_RangeFrom usize ]
      <:
      (t_Slice u8 & t_Slice u8))
    <:
    Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)

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

/// Exact authorization contract over decoded observations, rather than a facts
/// struct supplied by the caller. Cryptographic opening is a separate boundary.
let observed_admission_matches_spec
      (opened: Core_models.Option.t_Option t_OpenedShare)
      (context: t_AdmissionContext)
      (decision: Vela_client_share_policy.t_ShareAdmissionDecision)
    : bool =
  match opened <: Core_models.Option.t_Option t_OpenedShare with
  | Core_models.Option.Option_Some opened ->
    let h:t_ShareHeader = opened.f_header in
    let bound:bool =
      (Alloc.String.impl_String__as_str h.f_recipient_user_id <: string) =.
      context.f_recipient_user_id &&
      (Alloc.String.impl_String__as_str h.f_sender_user_id <: string) =.
      context.f_attributed_sender_user_id &&
      h.f_revision >=. mk_u64 1
    in
    (match decision <: Vela_client_share_policy.t_ShareAdmissionDecision with
      | Vela_client_share_policy.ShareAdmissionDecision_AcceptFirstContact permit ->
        Core_models.Option.impl__is_none #t_SharePin context.f_pin && bound &&
        (Vela_client_share_policy.share_permit_revision permit <: u64) =. h.f_revision
      | Vela_client_share_policy.ShareAdmissionDecision_ApplyUpdate permit ->
        (match context.f_pin <: Core_models.Option.t_Option t_SharePin with
          | Core_models.Option.Option_Some pin ->
            bound && pin.f_sender_user_id =. h.f_sender_user_id && pin.f_sender_vk =. h.f_sender_vk &&
            pin.f_lineage_id =. h.f_lineage_id &&
            h.f_revision >. pin.f_revision &&
            (Vela_client_share_policy.share_permit_revision permit <: u64) =. h.f_revision
          | Core_models.Option.Option_None  -> false)
      | Vela_client_share_policy.ShareAdmissionDecision_Reject  ->
        ~.bound ||
        (match context.f_pin <: Core_models.Option.t_Option t_SharePin with
          | Core_models.Option.Option_None  -> false
          | Core_models.Option.Option_Some pin ->
            pin.f_sender_user_id <>. h.f_sender_user_id || pin.f_sender_vk <>. h.f_sender_vk ||
            pin.f_lineage_id <>. h.f_lineage_id ||
            h.f_revision <=. pin.f_revision))
  | _ ->
    match decision <: Vela_client_share_policy.t_ShareAdmissionDecision with
    | Vela_client_share_policy.ShareAdmissionDecision_Reject  -> true
    | _ -> false

/// Production composition: decoded fields -> facts -> verified policy.
let plan_observed_share
      (opened: Core_models.Option.t_Option t_OpenedShare)
      (context: t_AdmissionContext)
    : Prims.Pure Vela_client_share_policy.t_ShareAdmissionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:Vela_client_share_policy.t_ShareAdmissionDecision = decision in
          observed_admission_matches_spec opened context decision) =
  Vela_client_share_policy.plan_share_admission (admission_facts opened context
      <:
      Vela_client_share_policy.t_ShareAdmissionFacts)
