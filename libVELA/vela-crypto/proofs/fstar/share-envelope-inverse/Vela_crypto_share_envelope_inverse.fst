module Vela_crypto_share_envelope_inverse

/// Encoder inverse for the VSE2 share-envelope frame.
///
/// The production encoder (`Vela_crypto.Share_envelope.encode_share_frame`)
/// builds `VSE2 || header || lp(item) || lp(signature)` through checked
/// appends.  This module proves, for every well-formed byte envelope value,
/// that the production parser accepts those bytes and returns exactly the
/// encoded fields (including the exact signed body), and that the encoder is
/// injective on such values.
///
/// The well-formedness precondition (`well_formed`) is explicit:
///
///  * the verifying key is 2624 bytes and the signature is 4691 bytes, because
///    `share_frame_spec`/`parse_share_frame` reject other widths;
///  * the complete frame length fits `usize` (the `Alloc.Vec` model's exact
///    concatenation bound, and the only reason a production append can fail).
///
/// Text fields are already bytes here.  Connecting `ShareHeader`'s `String`
/// fields to these bytes (UTF-8 conversion) is step O14b, not this module.

open FStar.Mul
open Rust_primitives
open Rust_primitives.Sequence
open Core_models
open Vela_crypto.Share_envelope
open Vela_crypto.Wire

module Seq = FStar.Seq
module L = FStar.List.Tot

// ── Notational helpers ──────────────────────────────────────────────────────

let len (s: t_Slice u8) : nat = Seq.length s

let vlen (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : nat = Seq.length v._0

let marker_bytes : Seq.seq u8 = v_SHARE_ENVELOPE_MAGIC

/// Big-endian bytes of a `u64` (the production `wire::encode_u64_be`).
let u8s (n: u64) : Seq.seq u8 = encode_u64_be n

/// The production cast of a slice length to the LP length field.
let u64_len (s: t_Slice u8) : u64 =
  cast (Core_models.Slice.impl__len #u8 s) <: u64

/// One length-prefixed production: `u64_be(len b) || b`.
let lp (b: t_Slice u8) : Seq.seq u8 =
  Seq.append (u8s (u64_len b)) b

/// The signed body: every header field in wire order, then `lp(item)`.
let body_spec (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : Seq.seq u8 =
  Seq.append (lp f.f_sender_user_id)
    (Seq.append (lp f.f_sender_device_id)
      (Seq.append (lp f.f_sender_vk)
        (Seq.append (lp f.f_recipient_user_id)
          (Seq.append f.f_recipient_ek_digest
            (Seq.append (lp f.f_lineage_id)
              (Seq.append (u8s f.f_revision) (lp item)))))))

/// Marker followed by the signed body: the bytes the encoder builds before
/// appending the signature trailer.
let prefix_spec (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : Seq.seq u8 =
  Seq.append marker_bytes (body_spec f item)

/// Complete frame, in parser order.
let frame_spec
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  Seq.seq u8 =
  Seq.append marker_bytes (Seq.append (body_spec f item) (lp sig))

let body_len (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : nat =
  Seq.length (body_spec f item)

let frame_len
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  nat =
  Seq.length (frame_spec f item sig)

/// The explicit precondition of the inverse theorem.
let well_formed
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  prop =
  Seq.length f.f_sender_vk = v Vela_crypto.Signing.v_HYBRID_VK_LEN /\
  Seq.length sig = v Vela_crypto.Signing.v_HYBRID_SIG_LEN /\
  frame_len f item sig <= max_usize

// ── Length facts ────────────────────────────────────────────────────────────

let u8s_len (n: u64) : Lemma (Seq.length (u8s n) = 8) = ()

let u64_len_value (s: t_Slice u8) :
  Lemma (v (u64_len s) = Seq.length s) =
  ()

let impl_len_nat (s: t_Slice u8) :
  Lemma (v (Core_models.Slice.impl__len #u8 s) = Seq.length s) =
  ()

let lp_len (b: t_Slice u8) :
  Lemma (Seq.length (lp b) = 8 + Seq.length b) =
  Seq.lemma_len_append (u8s (u64_len b)) b;
  u8s_len (u64_len b)

let body_len_unfold (f: t_ShareEnvelopeBytes) (item: t_Slice u8) :
  Lemma
    (body_len f item =
      8 + Seq.length f.f_sender_user_id +
      (8 + Seq.length f.f_sender_device_id +
       (8 + Seq.length f.f_sender_vk +
        (8 + Seq.length f.f_recipient_user_id +
         (32 + (8 + Seq.length f.f_lineage_id + (8 + (8 + Seq.length item)))))))) =
  ()

let frame_len_unfold
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  Lemma (frame_len f item sig = 4 + (body_len f item + (8 + Seq.length sig))) =
  lp_len sig

/// `split_envelope_prefix`'s `usize` used for the marker.
let marker_len : usize = mk_usize 4

/// `split_envelope_prefix`'s `usize` used for the recipient-key digest.
let digest_len : usize = mk_usize 32

/// Trailer length `8 + 4691` used by `share_frame_spec`.
let signature_trailer : usize =
  mk_usize 8 +! Vela_crypto.Signing.v_HYBRID_SIG_LEN

/// The expected parsed frame.  `signed_body` is the exact signed plaintext
/// without marker and signature trailer.  The unit proof argument records the
/// frame bound needed to make that body a Rust byte slice.
let frame_of
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8)
      (_: unit{frame_len f item sig <= max_usize}) :
  t_ShareFrame =
  assert (Seq.length (body_spec f item) <= max_usize);
  {
    f_signed_body = body_spec f item;
    f_sender_user_id = f.f_sender_user_id;
    f_sender_device_id = f.f_sender_device_id;
    f_sender_vk = f.f_sender_vk;
    f_recipient_user_id = f.f_recipient_user_id;
    f_recipient_ek_digest =
      Rust_primitives.Slice.array_as_slice (mk_usize 32) f.f_recipient_ek_digest;
    f_lineage_id = f.f_lineage_id;
    f_revision = f.f_revision;
    f_item = item;
    f_signature = sig;
  }

// ── Generic sequence lemmas ─────────────────────────────────────────────────

/// The prefix of `a || b` is exactly `a`.
let slice_append_prefix (a b: Seq.seq u8) :
  Lemma (Seq.slice (Seq.append a b) 0 (Seq.length a) == a) =
  Seq.lemma_eq_intro (Seq.slice (Seq.append a b) 0 (Seq.length a)) a;
  Seq.lemma_eq_elim (Seq.slice (Seq.append a b) 0 (Seq.length a)) a

/// The suffix of `a || b` after `a` is exactly `b`.
let slice_append_suffix (a b: Seq.seq u8) :
  Lemma
    (Seq.slice (Seq.append a b) (Seq.length a) (Seq.length a + Seq.length b) == b) =
  Seq.lemma_eq_intro
    (Seq.slice (Seq.append a b) (Seq.length a) (Seq.length a + Seq.length b)) b;
  Seq.lemma_eq_elim
    (Seq.slice (Seq.append a b) (Seq.length a) (Seq.length a + Seq.length b)) b

/// `((a || b) || c)[|a| .. |a|+|b|+|c|] = b || c`.
let slice_append_left3_full (a b c: Seq.seq u8) :
  Lemma
    (Seq.slice
        (Seq.append (Seq.append a b) c)
        (Seq.length a)
        (Seq.length a + Seq.length b + Seq.length c) ==
      Seq.append b c) =
  let s = Seq.append (Seq.append a b) c in
  let t = Seq.append b c in
  let x =
    Seq.slice s (Seq.length a) (Seq.length a + Seq.length b + Seq.length c)
  in
  Seq.lemma_eq_intro x t;
  Seq.lemma_eq_elim x t

/// `(a || (b || c))[|a| .. |a|+|b|] = b`.
let slice_append_right3_mid (a b c: Seq.seq u8) :
  Lemma
    (Seq.slice
        (Seq.append a (Seq.append b c))
        (Seq.length a)
        (Seq.length a + Seq.length b) ==
      b) =
  let s = Seq.append a (Seq.append b c) in
  let x = Seq.slice s (Seq.length a) (Seq.length a + Seq.length b) in
  Seq.lemma_eq_intro x b;
  Seq.lemma_eq_elim x b

// ── `head8`: the byte array the production `split_length_prefixed` decodes ──

/// The eight leading bytes, in the exact shape produced by the extracted
/// `split_length_prefixed`/`split_u64_prefix` (`array_of_list 8 [...]`).
let first8_list (s: Seq.seq u8{Seq.length s >= 8}) : list u8 =
  [
    Seq.index s 0;
    Seq.index s 1;
    Seq.index s 2;
    Seq.index s 3;
    Seq.index s 4;
    Seq.index s 5;
    Seq.index s 6;
    Seq.index s 7;
  ]

let head8 (s: Seq.seq u8{Seq.length s >= 8}) : t_Array u8 (mk_usize 8) =
  let list = first8_list s in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 8);
  Rust_primitives.Hax.array_of_list 8 list

/// Projection out of the eight-element list.
let rec first8_list_index (s: Seq.seq u8{Seq.length s >= 8}) (i: nat{i < 8}) :
  Lemma (L.index (first8_list s) i == Seq.index s i) =
  if i = 0 then ()
  else if i = 1 then ()
  else if i = 2 then ()
  else if i = 3 then ()
  else if i = 4 then ()
  else if i = 5 then ()
  else if i = 6 then ()
  else if i = 7 then ()

let head8_index (s: Seq.seq u8{Seq.length s >= 8}) (i: nat{i < 8}) :
  Lemma (Seq.index (head8 s) i == Seq.index s i) =
  first8_list_index s i

/// `decode(head8 p)` when `p` is eight bytes long.
let decode_head8 (p: Seq.seq u8) :
  Lemma (requires Seq.length p = 8)
        (ensures decode_u64_be (head8 p) == decode_u64_be p) =
  head8_index p 0;
  head8_index p 1;
  head8_index p 2;
  head8_index p 3;
  head8_index p 4;
  head8_index p 5;
  head8_index p 6;
  head8_index p 7

/// `decode` sees only the first eight bytes of `((p || b) || c)`.
let decode_head8_prefixed (p b c: Seq.seq u8) :
  Lemma (requires Seq.length p = 8)
        (ensures
          decode_u64_be (head8 (Seq.append (Seq.append p b) c)) ==
          decode_u64_be p) =
  let s = Seq.append (Seq.append p b) c in
  head8_index s 0;
  head8_index s 1;
  head8_index s 2;
  head8_index s 3;
  head8_index s 4;
  head8_index s 5;
  head8_index s 6;
  head8_index s 7;
  decode_head8 p

/// `decode` of `head8 (u8s n || rest)` is `n`.
let decode_head8_append (n: u64) (rest: Seq.seq u8) :
  Lemma (decode_u64_be (head8 (Seq.append (u8s n) rest)) == n) =
  decode_head8_prefixed (u8s n) rest Seq.empty;
  u8s_len n;
  Seq.append_empty_r rest;
  let _ = u64_wire_round_trip n in
  ()

// ── Splitting appended productions ──────────────────────────────────────────

/// `split_envelope_prefix (prefix || rest) n` when `prefix` has length `n`.
let split_prefix_append
      (prefix rest: Seq.seq u8)
      (n: usize) :
  Lemma
    (requires
      Seq.length prefix = v n /\
      Seq.length prefix + Seq.length rest <= max_usize)
    (ensures
      split_envelope_prefix (Seq.append prefix rest) n ==
      Core_models.Option.Option_Some (prefix, rest)) =
  let input = Seq.append prefix rest in
  Seq.lemma_len_append prefix rest;
  slice_append_prefix prefix rest;
  slice_append_suffix prefix rest

/// `split_length_prefixed` on one LP production followed by `rest`.
let split_lp_append (b: t_Slice u8) (rest: Seq.seq u8) :
  Lemma
    (requires Seq.length (lp b) + Seq.length rest <= max_usize)
    (ensures
      split_length_prefixed (Seq.append (lp b) rest) == Core_models.Option.Option_Some (b, rest)) =
  let n = u64_len b in
  let s = Seq.append (lp b) rest in
  lp_len b;
  u8s_len n;
  Seq.lemma_len_append (u8s n) b;
  Seq.lemma_len_append (Seq.append (u8s n) b) rest;
  slice_append_left3_full (u8s n) b rest;
  slice_append_prefix b rest;
  slice_append_suffix b rest;
  decode_head8_prefixed (u8s n) b rest;
  u64_len_value b;
  let _ = u64_wire_round_trip n in
  ()

/// `split_u64_prefix` on the eight-byte revision followed by `rest`.
let split_u64_append (value: u64) (rest: Seq.seq u8) :
  Lemma
    (requires 8 + Seq.length rest <= max_usize)
    (ensures
      split_u64_prefix (Seq.append (u8s value) rest) ==
      Core_models.Option.Option_Some (value, rest)) =
  let s = Seq.append (u8s value) rest in
  u8s_len value;
  Seq.lemma_len_append (u8s value) rest;
  slice_append_suffix (u8s value) rest;
  decode_head8_append value rest;
  let _ = u64_wire_round_trip value in
  ()

/// `split_lp_pair` on two LP productions followed by `rest`.
let split_lp_pair_append
      (a b: t_Slice u8)
      (rest: Seq.seq u8) :
  Lemma
    (requires
      Seq.length (lp a) + (Seq.length (lp b) + Seq.length rest) <=
      max_usize)
    (ensures
      split_lp_pair (Seq.append (lp a) (Seq.append (lp b) rest)) ==
      Core_models.Option.Option_Some ((a, b), rest)) =
  let tail = Seq.append (lp b) rest in
  lp_len a;
  lp_len b;
  Seq.lemma_len_append (lp b) rest;
  split_lp_append a tail;
  split_lp_append b rest

/// `split_lp_pair` on the final item/signature pair.
let split_lp_pair_last (a b: t_Slice u8) :
  Lemma
    (requires Seq.length (lp a) + Seq.length (lp b) <= max_usize)
    (ensures
      split_lp_pair (Seq.append (lp a) (lp b)) ==
      Core_models.Option.Option_Some ((a, b), Seq.empty)) =
  Seq.append_empty_r (lp b);
  split_lp_pair_append a b Seq.empty

/// `split_lp_four` on four LP productions followed by `rest`.
let split_lp_four_append
      (a b c d: t_Slice u8)
      (rest: Seq.seq u8) :
  Lemma
    (requires
      Seq.length (lp a) +
      (Seq.length (lp b) +
       (Seq.length (lp c) + (Seq.length (lp d) + Seq.length rest))) <=
      max_usize)
    (ensures
      split_lp_four
          (Seq.append (lp a)
            (Seq.append (lp b)
              (Seq.append (lp c) (Seq.append (lp d) rest)))) ==
      Core_models.Option.Option_Some (((a, b), (c, d)), rest)) =
  let tail = Seq.append (lp c) (Seq.append (lp d) rest) in
  lp_len a;
  lp_len b;
  lp_len c;
  lp_len d;
  Seq.lemma_len_append (lp c) (Seq.append (lp d) rest);
  Seq.lemma_len_append (lp d) rest;
  split_lp_pair_append a b tail;
  split_lp_pair_append c d rest

// ── Encoder equals the concatenation spec ───────────────────────────────────

/// Associativity as an SMT rewrite, so the encoder's left-nested appends are
/// compared with the parser's right-nested specification without repeating the
/// lemma at every step.  The pattern only fires on left-nested appends.
let append_assoc_smt (a b c: Seq.seq u8) :
  Lemma
    (ensures Seq.append (Seq.append a b) c == Seq.append a (Seq.append b c))
    [SMTPat (Seq.append (Seq.append a b) c)] =
  Seq.append_assoc a b c

#push-options "--fuel 2 --ifuel 2"

/// One checked append under its exact bound.
let push_bytes_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (value: t_Slice u8) :
  Lemma
    (requires vlen input + len value <= max_usize)
    (ensures
      push_bytes input value ==
      Core_models.Option.Option_Some (Alloc.Vec.Vec (Seq.append input._0 value) input._1)) =
  ()

/// One checked `u64` append under its exact bound.
let push_u64_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (value: u64) :
  Lemma
    (requires vlen input + 8 <= max_usize)
    (ensures
      push_u64 input value ==
      Core_models.Option.Option_Some (Alloc.Vec.Vec (Seq.append input._0 (u8s value)) input._1)) =
  push_bytes_spec input (u8s value)

/// One checked LP append under its exact bound.
let push_lp_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (value: t_Slice u8) :
  Lemma
    (requires vlen input + 8 + len value <= max_usize)
    (ensures
      push_lp_checked input value ==
      Core_models.Option.Option_Some
        (Alloc.Vec.Vec
          (Seq.append (Seq.append input._0 (u8s (u64_len value))) value)
          input._1)) =
  push_u64_spec input (u64_len value);
  push_bytes_spec
    (Alloc.Vec.Vec (Seq.append input._0 (u8s (u64_len value))) input._1)
    value

/// `push_share_body` builds the signed body.
let push_share_body_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (f: t_ShareEnvelopeBytes)
      (item: t_Slice u8) :
  Lemma
    (requires vlen input + body_len f item <= max_usize)
    (ensures
      push_share_body input f item ==
      Core_models.Option.Option_Some (Alloc.Vec.Vec (Seq.append input._0 (body_spec f item)) input._1)) =
  let a = f.f_sender_user_id in
  let b = f.f_sender_device_id in
  let c = f.f_sender_vk in
  let d = f.f_recipient_user_id in
  let e: t_Slice u8 = f.f_recipient_ek_digest in
  let g = f.f_lineage_id in
  let h = f.f_revision in
  let v0 = input in
  body_len_unfold f item;
  lp_len a;
  lp_len b;
  lp_len c;
  lp_len d;
  lp_len g;
  lp_len item;
  Seq.lemma_len_append (u8s h) (lp item);
  u8s_len h;
  Seq.slice_length e;
  // Each step is the actual `push_*` result, so no intermediate `Vec` is
  // reconstructed and no extra concatenation-bound obligation is generated.
  push_lp_spec v0 a;
  let v1 = Core_models.Option.impl__unwrap (push_lp_checked v0 a) in
  push_lp_spec v1 b;
  let v2 = Core_models.Option.impl__unwrap (push_lp_checked v1 b) in
  push_lp_spec v2 c;
  let v3 = Core_models.Option.impl__unwrap (push_lp_checked v2 c) in
  push_lp_spec v3 d;
  let v4 = Core_models.Option.impl__unwrap (push_lp_checked v3 d) in
  push_bytes_spec v4 e;
  let v5 = Core_models.Option.impl__unwrap (push_bytes v4 e) in
  push_lp_spec v5 g;
  let v6 = Core_models.Option.impl__unwrap (push_lp_checked v5 g) in
  push_u64_spec v6 h;
  let v7 = Core_models.Option.impl__unwrap (push_u64 v6 h) in
  push_lp_spec v7 item;
  let v8 = Core_models.Option.impl__unwrap (push_lp_checked v7 item) in
  // The body is the left fold of the same appends; associativity is supplied
  // by `append_assoc_smt`, and `body_spec`/`lp` unfold definitionally.
  ()

/// `push_share_prefix` builds `VSE2 || body`.
let push_share_prefix_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (f: t_ShareEnvelopeBytes)
      (item: t_Slice u8) :
  Lemma
    (requires vlen input + 4 + body_len f item <= max_usize)
    (ensures
      push_share_prefix input f item ==
      Core_models.Option.Option_Some
        (Alloc.Vec.Vec
          (Seq.append input._0 (prefix_spec f item))
          input._1)) =
  body_len_unfold f item;
  Seq.slice_length v_SHARE_ENVELOPE_MAGIC;
  push_bytes_spec input marker_bytes;
  push_share_body_spec
    (Alloc.Vec.Vec (Seq.append input._0 marker_bytes) input._1)
    f
    item

/// The full prefix from the empty vector is exactly `prefix_spec`.
let encode_share_prefix_spec
      (f: t_ShareEnvelopeBytes)
      (item: t_Slice u8) :
  Lemma
    (requires 4 + body_len f item <= max_usize)
    (ensures
      encode_share_prefix f item ==
      Core_models.Option.Option_Some
        (Alloc.Vec.Vec
          (prefix_spec f item)
          (Alloc.Vec.impl__new #u8 ())._1)) =
  let empty = Alloc.Vec.impl__new #u8 () in
  push_share_prefix_spec empty f item;
  Seq.append_empty_l (prefix_spec f item)

/// Appending the signature trailer.
let append_share_signature_spec
      (prefix: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (signature: t_Slice u8) :
  Lemma
    (requires vlen prefix + 8 + len signature <= max_usize)
    (ensures
      append_share_signature prefix signature ==
      Core_models.Option.Option_Some
        (Alloc.Vec.Vec
          (Seq.append prefix._0 (lp signature))
          prefix._1)) =
  push_lp_spec prefix signature

/// The production encoder returns exactly `frame_spec`.
let encode_share_frame_spec
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  Lemma
    (requires frame_len f item sig <= max_usize)
    (ensures
      encode_share_frame f item sig ==
      Core_models.Option.Option_Some
        (Alloc.Vec.Vec
          (frame_spec f item sig)
          (Alloc.Vec.impl__new #u8 ())._1)) =
  frame_len_unfold f item sig;
  body_len_unfold f item;
  lp_len sig;
  encode_share_prefix_spec f item;
  append_share_signature_spec
    (Alloc.Vec.Vec
      (prefix_spec f item)
      (Alloc.Vec.impl__new #u8 ())._1)
    sig;
  ()

#pop-options

// ── The functional parser on an encoded frame ───────────────────────────────

#push-options "--fuel 2 --ifuel 2"

/// `v` of a `usize` subtraction that does not underflow.
let usize_sub_value (x y: usize) :
  Lemma (requires v x >= v y) (ensures v (x -! y) = v x - v y) =
  ()

/// The marker is four bytes, matching `marker_len`.
let marker_len_value () :
  Lemma (v marker_len = 4 /\ Seq.length marker_bytes = 4) =
  Seq.slice_length v_SHARE_ENVELOPE_MAGIC

/// The signature trailer is exactly `lp sig` long.
let signature_trailer_value (sig: t_Slice u8) :
  Lemma
    (requires Seq.length sig = v Vela_crypto.Signing.v_HYBRID_SIG_LEN)
    (ensures v signature_trailer = Seq.length (lp sig)) =
  lp_len sig;
  assert_norm (v signature_trailer = 8 + v Vela_crypto.Signing.v_HYBRID_SIG_LEN)

/// `frame_body (a || (b || c)) |a| |c|` is `b`.  Generic in the three parts,
/// so the solver never sees the concrete header and body terms.
let frame_body_append3
      (a b c: Seq.seq u8)
      (prefix_len trailer_len: usize) :
  Lemma
    (requires
      v prefix_len = Seq.length a /\
      v trailer_len = Seq.length c /\
      Seq.length a + (Seq.length b + Seq.length c) <= max_usize)
    (ensures
      frame_body (Seq.append a (Seq.append b c)) prefix_len trailer_len ==
      Core_models.Option.Option_Some b) =
  let input = Seq.append a (Seq.append b c) in
  Seq.lemma_len_append b c;
  Seq.lemma_len_append a (Seq.append b c);
  impl_len_nat input;
  let n = Core_models.Slice.impl__len #u8 input in
  usize_sub_value n prefix_len;
  usize_sub_value n trailer_len;
  slice_append_right3_mid a b c

/// `frame_body` on a complete frame is exactly the signed body.
let frame_body_frame
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  Lemma
    (requires well_formed f item sig)
    (ensures
      frame_body (frame_spec f item sig) marker_len signature_trailer ==
      Core_models.Option.Option_Some (body_spec f item)) =
  let body = body_spec f item in
  let trailer = lp sig in
  marker_len_value ();
  signature_trailer_value sig;
  Seq.lemma_len_append body trailer;
  Seq.lemma_len_append marker_bytes (Seq.append body trailer);
  frame_body_append3 marker_bytes body trailer marker_len signature_trailer

/// The full `share_frame_spec` on `frame_spec f item sig` returns exactly the
/// encoded fields.
let share_frame_spec_frame
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  Lemma
    (requires well_formed f item sig)
    (ensures
      share_frame_spec (frame_spec f item sig) ==
      Core_models.Option.Option_Some (frame_of f item sig ())) =
  let a = f.f_sender_user_id in
  let b = f.f_sender_device_id in
  let c = f.f_sender_vk in
  let d = f.f_recipient_user_id in
  let e = f.f_recipient_ek_digest in
  let g = f.f_lineage_id in
  let h = f.f_revision in
  let input = frame_spec f item sig in
  let rest0 = Seq.append (body_spec f item) (lp sig) in
  let rest1 =
    Seq.append e
      (Seq.append (lp g) (Seq.append (u8s h) (Seq.append (lp item) (lp sig))))
  in
  let rest2 = Seq.append (lp g) (Seq.append (u8s h) (Seq.append (lp item) (lp sig))) in
  let rest3 = Seq.append (u8s h) (Seq.append (lp item) (lp sig)) in
  let rest4 = Seq.append (lp item) (lp sig) in
  frame_len_unfold f item sig;
  body_len_unfold f item;
  u8s_len h;
  lp_len g;
  lp_len item;
  lp_len sig;
  Seq.lemma_len_append (u8s h) (lp item);
  Seq.lemma_len_append (lp item) (lp sig);
  Seq.lemma_len_append (lp g) (Seq.append (u8s h) rest4);
  Seq.lemma_len_append e rest2;
  Seq.lemma_len_append marker_bytes rest0;
  // The body followed by the signature is the right-nested frame shape.
  Seq.append_assoc (u8s h) (lp item) (lp sig);
  // Marker.
  split_prefix_append marker_bytes rest0 marker_len;
  // Four LP header fields.
  split_lp_four_append a b c d rest1;
  // Recipient-key digest.
  split_prefix_append e rest2 digest_len;
  // Lineage.
  split_lp_append g rest3;
  // Revision.
  split_u64_append h rest4;
  // Item and signature.
  split_lp_pair_last item sig;
  // Length admission checks.
  impl_len_nat c;
  impl_len_nat sig;
  frame_body_frame f item sig;
  ()

#pop-options

// ── Parser composition and injectivity ──────────────────────────────────────

/// Eliminate the explicit structural comparator.
let frame_results_equal_elim
      (left right: Core_models.Option.t_Option t_ShareFrame) :
  Lemma
    (requires frame_results_equal left right)
    (ensures left == right) =
  match left, right with
  | Core_models.Option.Option_None, Core_models.Option.Option_None -> ()
  | Core_models.Option.Option_Some l, Core_models.Option.Option_Some r ->
      assert (l.f_signed_body == r.f_signed_body);
      assert (l.f_sender_user_id == r.f_sender_user_id);
      assert (l.f_sender_device_id == r.f_sender_device_id);
      assert (l.f_sender_vk == r.f_sender_vk);
      assert (l.f_recipient_user_id == r.f_recipient_user_id);
      assert (l.f_recipient_ek_digest == r.f_recipient_ek_digest);
      assert (l.f_lineage_id == r.f_lineage_id);
      assert (l.f_revision == r.f_revision);
      assert (l.f_item == r.f_item);
      assert (l.f_signature == r.f_signature);
      assert (l == r)
  | _ -> ()

/// The production parser refines the functional grammar.
let parse_refines_spec (input: t_Slice u8) :
  Lemma (parse_share_frame input == share_frame_spec input) =
  let result = parse_share_frame input in
  frame_results_equal_elim result (share_frame_spec input)

/// `parse (encode x) = x` for every well-formed `x`.
let parse_encode_share_frame
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  Lemma
    (requires well_formed f item sig)
    (ensures
      (match encode_share_frame f item sig with
       | Core_models.Option.Option_Some out ->
         parse_share_frame out._0 == Core_models.Option.Option_Some (frame_of f item sig ())
       | Core_models.Option.Option_None -> False)) =
  encode_share_frame_spec f item sig;
  share_frame_spec_frame f item sig;
  parse_refines_spec (frame_spec f item sig)

/// The encoder is injective on well-formed values.
let encode_share_frame_injective
      (f1 f2: t_ShareEnvelopeBytes)
      (item1 item2 sig1 sig2: t_Slice u8) :
  Lemma
    (requires
      well_formed f1 item1 sig1 /\
      well_formed f2 item2 sig2 /\
      encode_share_frame f1 item1 sig1 == encode_share_frame f2 item2 sig2)
    (ensures
      f1.f_sender_user_id == f2.f_sender_user_id /\
      f1.f_sender_device_id == f2.f_sender_device_id /\
      f1.f_sender_vk == f2.f_sender_vk /\
      f1.f_recipient_user_id == f2.f_recipient_user_id /\
      f1.f_recipient_ek_digest == f2.f_recipient_ek_digest /\
      f1.f_lineage_id == f2.f_lineage_id /\
      f1.f_revision = f2.f_revision /\
      item1 == item2 /\
      sig1 == sig2) =
  encode_share_frame_spec f1 item1 sig1;
  encode_share_frame_spec f2 item2 sig2;
  parse_encode_share_frame f1 item1 sig1;
  parse_encode_share_frame f2 item2 sig2;
  ()
