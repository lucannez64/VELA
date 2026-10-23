module Vela_crypto.Share_envelope
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

/// Prefix of the sealed plaintext.
let v_SHARE_ENVELOPE_MAGIC: t_Array u8 (mk_usize 4) =
  let list = [mk_u8 86; mk_u8 83; mk_u8 69; mk_u8 50] in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 4);
  Rust_primitives.Hax.array_of_list 4 list

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
/// Safe callers cannot construct a witness from unchecked fields:
/// ```compile_fail
/// use vela_crypto::share_envelope::{OpenedShare, ShareHeader};
/// fn forge(header: ShareHeader, item: Vec<u8>) -> OpenedShare {
///     OpenedShare { header, item }
/// }
/// ```
/// Nor can they mutate its authenticated plaintext:
/// ```compile_fail
/// use vela_crypto::share_envelope::OpenedShare;
/// fn change(share: &mut OpenedShare) { share.item.clear(); }
/// ```
type t_OpenedShare = {
  f_header:t_ShareHeader;
  f_item:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

let opened_share_header (share: t_OpenedShare)
    : Prims.Pure t_ShareHeader
      Prims.l_True
      (ensures
        fun header ->
          let header:t_ShareHeader = header in
          (Alloc.String.impl_String__as_str header.f_sender_user_id <: string) =.
          (Alloc.String.impl_String__as_str share.f_header.f_sender_user_id <: string) &&
          (Alloc.String.impl_String__as_str header.f_sender_device_id <: string) =.
          (Alloc.String.impl_String__as_str share.f_header.f_sender_device_id <: string) &&
          header.f_sender_vk =. share.f_header.f_sender_vk &&
          (Alloc.String.impl_String__as_str header.f_recipient_user_id <: string) =.
          (Alloc.String.impl_String__as_str share.f_header.f_recipient_user_id <: string) &&
          header.f_recipient_ek_digest =. share.f_header.f_recipient_ek_digest &&
          (Alloc.String.impl_String__as_str header.f_lineage_id <: string) =.
          (Alloc.String.impl_String__as_str share.f_header.f_lineage_id <: string) &&
          header.f_revision =. share.f_header.f_revision) = share.f_header

let opened_share_item (share: t_OpenedShare)
    : Prims.Pure (t_Slice u8)
      Prims.l_True
      (ensures
        fun bytes ->
          let bytes:t_Slice u8 = bytes in
          bytes =. (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global share.f_item <: t_Slice u8)
      ) = Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global share.f_item

let into_opened_share_item (share: t_OpenedShare)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Prims.l_True
      (ensures
        fun bytes ->
          let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = bytes in
          (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global bytes <: t_Slice u8) =.
          (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global share.f_item <: t_Slice u8)) =
  share.f_item

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

/// Borrowed syntactic fields. Authentication and UTF-8 validation occur after
/// this framing step; no field is trusted merely because parsing succeeded.
type t_ShareFrame = {
  f_signed_body:t_Slice u8;
  f_sender_user_id:t_Slice u8;
  f_sender_device_id:t_Slice u8;
  f_sender_vk:t_Slice u8;
  f_recipient_user_id:t_Slice u8;
  f_recipient_ek_digest:t_Slice u8;
  f_lineage_id:t_Slice u8;
  f_revision:u64;
  f_item:t_Slice u8;
  f_signature:t_Slice u8
}

/// Cursor operation used by the concrete frame parser.
let take_frame_prefix (input: t_Slice u8) (n: usize)
    : Prims.Pure (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8))
      Prims.l_True
      (ensures
        fun temp_0_ ->
          let (input_future: t_Slice u8), (result: Core_models.Option.t_Option (t_Slice u8)) =
            temp_0_
          in
          match
            split_envelope_prefix input n <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
          with
          | Core_models.Option.Option_Some (head, tail) ->
            result =.
            (Core_models.Option.Option_Some head <: Core_models.Option.t_Option (t_Slice u8)) &&
            input_future =. tail
          | Core_models.Option.Option_None  ->
            (match result <: Core_models.Option.t_Option (t_Slice u8) with
              | Core_models.Option.Option_None  -> true
              | _ -> false) &&
            input_future =. input) =
  match split_envelope_prefix input n <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
  | Core_models.Option.Option_Some (head, tail) ->
    let input:t_Slice u8 = tail in
    let hax_temp_output:Core_models.Option.t_Option (t_Slice u8) =
      Core_models.Option.Option_Some head <: Core_models.Option.t_Option (t_Slice u8)
    in
    input, hax_temp_output <: (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8))
  | Core_models.Option.Option_None  ->
    input, (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
    <:
    (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8))

/// Functional byte grammar used as the specification of the stateful parser.
/// Each LP production expands to the separately checked exact slice contract.
let share_frame_spec (input: t_Slice u8) : Core_models.Option.t_Option t_ShareFrame =
  let (digest_len: usize):usize = mk_usize 32 in
  let (marker_len: usize):usize = mk_usize 4 in
  let (signature_trailer: usize):usize = mk_usize 8 +! Vela_crypto.Signing.v_HYBRID_SIG_LEN in
  match
    split_envelope_prefix input (mk_usize 4)
    <:
    Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
  with
  | Core_models.Option.Option_Some (prefix, rest) ->
    if prefix <>. v_SHARE_ENVELOPE_MAGIC
    then Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame
    else
      (match
          Vela_crypto.Wire.split_lp_four rest
          <:
          Core_models.Option.t_Option
          (((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) & t_Slice u8)
        with
        | Core_models.Option.Option_Some
          (((sender_user_id, sender_device_id), (sender_vk, recipient_user_id)), rest) ->
          (match
              split_envelope_prefix rest digest_len
              <:
              Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
            with
            | Core_models.Option.Option_Some (recipient_ek_digest, rest) ->
              (match
                  Vela_crypto.Wire.split_length_prefixed rest
                  <:
                  Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
                with
                | Core_models.Option.Option_Some (lineage_id, rest) ->
                  (match
                      Vela_crypto.Wire.split_u64_prefix rest
                      <:
                      Core_models.Option.t_Option (u64 & t_Slice u8)
                    with
                    | Core_models.Option.Option_Some (revision, rest) ->
                      (match
                          Vela_crypto.Wire.split_lp_pair rest
                          <:
                          Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8)
                        with
                        | Core_models.Option.Option_Some ((item, signature), rest) ->
                          if
                            ~.(Core_models.Slice.impl__is_empty #u8 rest <: bool) ||
                            (Core_models.Slice.impl__len #u8 sender_vk <: usize) <>.
                            Vela_crypto.Signing.v_HYBRID_VK_LEN ||
                            (Core_models.Slice.impl__len #u8 signature <: usize) <>.
                            Vela_crypto.Signing.v_HYBRID_SIG_LEN
                          then
                            Core_models.Option.Option_None
                            <:
                            Core_models.Option.t_Option t_ShareFrame
                          else
                            (match
                                Vela_crypto.Wire.frame_body input marker_len signature_trailer
                                <:
                                Core_models.Option.t_Option (t_Slice u8)
                              with
                              | Core_models.Option.Option_Some signed_body ->
                                Core_models.Option.Option_Some
                                ({
                                    f_signed_body = signed_body;
                                    f_sender_user_id = sender_user_id;
                                    f_sender_device_id = sender_device_id;
                                    f_sender_vk = sender_vk;
                                    f_recipient_user_id = recipient_user_id;
                                    f_recipient_ek_digest = recipient_ek_digest;
                                    f_lineage_id = lineage_id;
                                    f_revision = revision;
                                    f_item = item;
                                    f_signature = signature
                                  }
                                  <:
                                  t_ShareFrame)
                                <:
                                Core_models.Option.t_Option t_ShareFrame
                              | Core_models.Option.Option_None  ->
                                Core_models.Option.Option_None
                                <:
                                Core_models.Option.t_Option t_ShareFrame)
                        | Core_models.Option.Option_None  ->
                          Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame
                      )
                    | Core_models.Option.Option_None  ->
                      Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
                | Core_models.Option.Option_None  ->
                  Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
            | Core_models.Option.Option_None  ->
              Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
        | Core_models.Option.Option_None  ->
          Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
  | Core_models.Option.Option_None  ->
    Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame

/// Explicit structural comparison avoids an opaque derived-equality assumption.
let frame_results_equal (left right: Core_models.Option.t_Option t_ShareFrame) : bool =
  match
    left, right
    <:
    (Core_models.Option.t_Option t_ShareFrame & Core_models.Option.t_Option t_ShareFrame)
  with
  | Core_models.Option.Option_None , Core_models.Option.Option_None  -> true
  | Core_models.Option.Option_Some left, Core_models.Option.Option_Some right ->
    left.f_signed_body =. right.f_signed_body && left.f_sender_user_id =. right.f_sender_user_id &&
    left.f_sender_device_id =. right.f_sender_device_id &&
    left.f_sender_vk =. right.f_sender_vk &&
    left.f_recipient_user_id =. right.f_recipient_user_id &&
    left.f_recipient_ek_digest =. right.f_recipient_ek_digest &&
    left.f_lineage_id =. right.f_lineage_id &&
    left.f_revision =. right.f_revision &&
    left.f_item =. right.f_item &&
    left.f_signature =. right.f_signature
  | _ -> false

#push-options "--fuel 2 --ifuel 2"

/// Concrete stateful parser refines the complete byte grammar, including all
/// rejection cases and exact field values. This does not prove authentication.
let parse_share_frame (input: t_Slice u8)
    : Prims.Pure (Core_models.Option.t_Option t_ShareFrame)
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option t_ShareFrame = result in
          frame_results_equal result
            (share_frame_spec input <: Core_models.Option.t_Option t_ShareFrame)) =
  let (digest_len: usize):usize = mk_usize 32 in
  let (marker_len: usize):usize = mk_usize 4 in
  let (signature_trailer: usize):usize = mk_usize 8 +! Vela_crypto.Signing.v_HYBRID_SIG_LEN in
  let rest:t_Slice u8 = input in
  let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option (t_Slice u8)) =
    take_frame_prefix rest (mk_usize 4)
  in
  let rest:t_Slice u8 = tmp0 in
  match out <: Core_models.Option.t_Option (t_Slice u8) with
  | Core_models.Option.Option_Some hoist4 ->
    if hoist4 <>. v_SHARE_ENVELOPE_MAGIC
    then Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame
    else
      let
      (tmp0: t_Slice u8),
      (out: Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))) =
        Vela_crypto.Wire.take_lp_four rest
      in
      let rest:t_Slice u8 = tmp0 in
      (match
          out <: Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))
        with
        | Core_models.Option.Option_Some
          ((sender_user_id, sender_device_id), (sender_vk, recipient_user_id)) ->
          let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option (t_Slice u8)) =
            take_frame_prefix rest digest_len
          in
          let rest:t_Slice u8 = tmp0 in
          (match out <: Core_models.Option.t_Option (t_Slice u8) with
            | Core_models.Option.Option_Some recipient_ek_digest ->
              let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option (t_Slice u8)) =
                Vela_crypto.Wire.take_length_prefixed rest
              in
              let rest:t_Slice u8 = tmp0 in
              (match out <: Core_models.Option.t_Option (t_Slice u8) with
                | Core_models.Option.Option_Some lineage_id ->
                  let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option u64) =
                    Vela_crypto.Wire.take_u64 rest
                  in
                  let rest:t_Slice u8 = tmp0 in
                  (match out <: Core_models.Option.t_Option u64 with
                    | Core_models.Option.Option_Some revision ->
                      let
                      (tmp0: t_Slice u8),
                      (out: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)) =
                        Vela_crypto.Wire.take_lp_pair rest
                      in
                      let rest:t_Slice u8 = tmp0 in
                      (match out <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
                        | Core_models.Option.Option_Some (item, signature) ->
                          if
                            ~.(Core_models.Slice.impl__is_empty #u8 rest <: bool) ||
                            (Core_models.Slice.impl__len #u8 sender_vk <: usize) <>.
                            Vela_crypto.Signing.v_HYBRID_VK_LEN ||
                            (Core_models.Slice.impl__len #u8 signature <: usize) <>.
                            Vela_crypto.Signing.v_HYBRID_SIG_LEN
                          then
                            Core_models.Option.Option_None
                            <:
                            Core_models.Option.t_Option t_ShareFrame
                          else
                            (match
                                Vela_crypto.Wire.frame_body input marker_len signature_trailer
                                <:
                                Core_models.Option.t_Option (t_Slice u8)
                              with
                              | Core_models.Option.Option_Some signed_body ->
                                Core_models.Option.Option_Some
                                ({
                                    f_signed_body = signed_body;
                                    f_sender_user_id = sender_user_id;
                                    f_sender_device_id = sender_device_id;
                                    f_sender_vk = sender_vk;
                                    f_recipient_user_id = recipient_user_id;
                                    f_recipient_ek_digest = recipient_ek_digest;
                                    f_lineage_id = lineage_id;
                                    f_revision = revision;
                                    f_item = item;
                                    f_signature = signature
                                  }
                                  <:
                                  t_ShareFrame)
                                <:
                                Core_models.Option.t_Option t_ShareFrame
                              | Core_models.Option.Option_None  ->
                                Core_models.Option.Option_None
                                <:
                                Core_models.Option.t_Option t_ShareFrame)
                        | Core_models.Option.Option_None  ->
                          Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame
                      )
                    | Core_models.Option.Option_None  ->
                      Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
                | Core_models.Option.Option_None  ->
                  Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
            | Core_models.Option.Option_None  ->
              Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
        | Core_models.Option.Option_None  ->
          Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame)
  | Core_models.Option.Option_None  ->
    Core_models.Option.Option_None <: Core_models.Option.t_Option t_ShareFrame

#pop-options

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
