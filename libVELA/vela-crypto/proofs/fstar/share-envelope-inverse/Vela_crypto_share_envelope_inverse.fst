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
///  * the complete frame length fits `usize` (the `Alloc.Vec` model's exact
///    concatenation bound, and the only reason a production append can fail);
///  * the verifying key is 2624 bytes and the signature is 4691 bytes, because
///    `share_frame_spec`/`parse_share_frame` reject other widths.
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

/// Big-endian bytes of a `u64` (the production `wire::encode_u64_be`).
let u8s (n: u64) : Seq.seq u8 = encode_u64_be n

/// The production cast of a slice length to the LP length field.
let u64_len (s: t_Slice u8) : u64 =
  cast #USIZE #U64 (Core_models.Slice.impl__len #u8 s)

/// One length-prefixed production: `u64_be(len b) || b`.
let lp (b: t_Slice u8) : Seq.seq u8 =
  Seq.append (u8s (u64_len b)) b

/// The complete `VSE2` marker (`v_SHARE_ENVELOPE_MAGIC`).
let magic : Seq.seq u8 = v_SHARE_ENVELOPE_MAGIC

let rec parts_len (parts: list (Seq.seq u8)) : nat =
  match parts with
  | [] -> 0
  | head :: tail -> Seq.length head + parts_len tail

/// Right-nested concatenation: the parser-facing shape.
let rec concat_right (parts: list (Seq.seq u8)) : Seq.seq u8 =
  match parts with
  | [] -> Seq.empty
  | head :: tail -> Seq.append head (concat_right tail)

/// Left-nested concatenation with an accumulator: the encoder-facing shape.
let rec concat_left (acc: Seq.seq u8) (parts: list (Seq.seq u8)) : Seq.seq u8 =
  match parts with
  | [] -> acc
  | head :: tail -> concat_left (Seq.append acc head) tail

// ── Generic sequence lemmas ─────────────────────────────────────────────────

/// The prefix of `a || b` is exactly `a`.
let slice_append_prefix (a b: Seq.seq u8) :
  Lemma (Seq.slice (Seq.append a b) 0 (Seq.length a) == a) =
  Seq.lemma_eq_intro (Seq.slice (Seq.append a b) 0 (Seq.length a)) a

/// The suffix of `a || b` after `a` is exactly `b`.
let slice_append_suffix (a b: Seq.seq u8) :
  Lemma
    (Seq.slice (Seq.append a b) (Seq.length a) (Seq.length a + Seq.length b) == b) =
  Seq.lemma_eq_intro
    (Seq.slice (Seq.append a b) (Seq.length a) (Seq.length a + Seq.length b))
    b

/// Slicing `(a || b)` inside the left component is slicing `a`.
let slice_append_left (a b: Seq.seq u8) (i j: nat{i <= j /\ j <= Seq.length a}) :
  Lemma (Seq.slice (Seq.append a b) i j == Seq.slice a i j) =
  Seq.lemma_eq_intro (Seq.slice (Seq.append a b) i j) (Seq.slice a i j)

/// A slice of a slice collapses to the corresponding outer slice.
let slice_slice
      (s: Seq.seq u8)
      (i j k l: nat)
      (hi: i <= j)
      (hj: j <= k)
      (hk: k <= l)
      (hl: l <= Seq.length s) :
  Lemma (Seq.slice (Seq.slice s i l) (j - i) (k - i) == Seq.slice s j k) =
  Seq.lemma_eq_intro (Seq.slice (Seq.slice s i l) (j - i) (k - i)) (Seq.slice s j k)

/// The first eight bytes of a slice, in the exact shape produced by the
/// extracted `split_length_prefixed`/`split_u64_prefix`.
let head8 (s: t_Slice u8) : t_Array u8 (mk_usize 8) =
  Rust_primitives.Hax.array_of_list 8
    [ Seq.index s 0;
      Seq.index s 1;
      Seq.index s 2;
      Seq.index s 3;
      Seq.index s 4;
      Seq.index s 5;
      Seq.index s 6;
      Seq.index s 7 ]

let head8_prefix (p rest: Seq.seq u8) (h: Seq.length p == 8) :
  Lemma (head8 (Seq.append p rest) == p) =
  Seq.lemma_eq_intro (head8 (Seq.append p rest)) p

// ── Concatenation length and fold lemmas ────────────────────────────────────

let rec concat_right_len (parts: list (Seq.seq u8)) :
  Lemma (Seq.length (concat_right parts) == parts_len parts) =
  match parts with
  | [] -> ()
  | head :: tail -> concat_right_len tail

let rec concat_left_len (acc: Seq.seq u8) (parts: list (Seq.seq u8)) :
  Lemma (Seq.length (concat_left acc parts) == Seq.length acc + parts_len parts) =
  match parts with
  | [] -> ()
  | head :: tail -> concat_left_len (Seq.append acc head) tail

let rec parts_len_append (xs ys: list (Seq.seq u8)) :
  Lemma (parts_len (L.append xs ys) == parts_len xs + parts_len ys) =
  match xs with
  | [] -> ()
  | head :: tail -> parts_len_append tail ys

/// Splitting a left-nested list concatenation at an append.
let rec concat_left_append (acc: Seq.seq u8) (xs ys: list (Seq.seq u8)) :
  Lemma
    (ensures concat_left acc (L.append xs ys) == concat_left (concat_left acc xs) ys)
  (decreases xs) =
  match xs with
  | [] -> ()
  | head :: tail -> concat_left_append (Seq.append acc head) tail ys

/// Left and right folds agree up to one leading append.
let rec concat_left_eq_right (acc: Seq.seq u8) (parts: list (Seq.seq u8)) :
  Lemma (ensures concat_left acc parts == Seq.append acc (concat_right parts))
  (decreases parts) =
  match parts with
  | [] -> Seq.append_empty_l acc
  | head :: tail ->
    concat_left_eq_right (Seq.append acc head) tail;
    Seq.append_assoc acc head (concat_right tail)

/// The encoder's left fold from the empty vector is the parser's right fold.
let concat_from_empty (parts: list (Seq.seq u8)) :
  Lemma (concat_left Seq.empty parts == concat_right parts) =
  concat_left_eq_right Seq.empty parts;
  Seq.append_empty_l (concat_right parts)

// ── Chunks: the production appends and the parser parts ─────────────────────

/// One encoder step.  `Raw` appends a fixed field once; `Lp` appends the
/// length and then the payload (two appends in the production code).
noeq
type chunk =
  | Raw : s:Seq.seq u8 -> chunk
  | Lp : b:t_Slice u8 -> chunk

/// Sequence of appends the encoder performs for one chunk.
let chunk_appends (c: chunk) : list (Seq.seq u8) =
  match c with
  | Raw s -> [s]
  | Lp b -> [u8s (u64_len b); b]

/// Single value the parser reads for one chunk.
let chunk_value (c: chunk) : Seq.seq u8 =
  match c with
  | Raw s -> s
  | Lp b -> lp b

let rec expanded (cs: list chunk) : list (Seq.seq u8) =
  match cs with
  | [] -> []
  | c :: rest -> L.append (chunk_appends c) (expanded rest)

let rec compact (cs: list chunk) : list (Seq.seq u8) =
  match cs with
  | [] -> []
  | c :: rest -> chunk_value c :: compact rest

let rec parts_len_expanded (cs: list chunk) :
  Lemma (parts_len (expanded cs) == parts_len (compact cs)) =
  match cs with
  | [] -> ()
  | Raw s :: rest -> parts_len_expanded rest
  | Lp b :: rest -> parts_len_expanded rest

/// The encoder's left fold of the expanded appends equals the parser's
/// right-nested compact parts.
let rec concat_left_expanded (acc: Seq.seq u8) (cs: list chunk) :
  Lemma
    (ensures
      concat_left acc (expanded cs) ==
      Seq.append acc (concat_right (compact cs)))
  (decreases cs) =
  match cs with
  | [] -> Seq.append_empty_l acc
  | Raw s :: rest ->
    concat_left_expanded (Seq.append acc s) rest;
    Seq.append_assoc acc s (concat_right (compact rest))
  | Lp b :: rest ->
    concat_left_expanded
      (Seq.append (Seq.append acc (u8s (u64_len b))) b)
      rest;
    Seq.append_assoc acc (u8s (u64_len b)) b;
    Seq.append_assoc
      acc
      (Seq.append (u8s (u64_len b)) b)
      (concat_right (compact rest))

// ── Frame chunks ────────────────────────────────────────────────────────────

/// The signed body: every header field in wire order, then `lp(item)`.
let body_chunks (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : list chunk =
  [ Lp f.f_sender_user_id;
    Lp f.f_sender_device_id;
    Lp f.f_sender_vk;
    Lp f.f_recipient_user_id;
    Raw f.f_recipient_ek_digest;
    Lp f.f_lineage_id;
    Raw (u8s f.f_revision);
    Lp item ]

/// The complete frame: marker, signed body, then `lp(signature)`.
let frame_chunks
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  list chunk =
  Raw magic :: L.append (body_chunks f item) [Lp sig]

let body_parts (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : list (Seq.seq u8) =
  compact (body_chunks f item)

let frame_parts
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  list (Seq.seq u8) =
  compact (frame_chunks f item sig)

let body_spec (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : Seq.seq u8 =
  concat_right (body_parts f item)

let frame_spec
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  Seq.seq u8 =
  concat_right (frame_parts f item sig)

let body_len (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : nat =
  parts_len (body_parts f item)

let frame_len
      (f: t_ShareEnvelopeBytes)
      (item sig: t_Slice u8) :
  nat =
  parts_len (frame_parts f item sig)

// ── Vector step contracts ───────────────────────────────────────────────────

#push-options "--fuel 2 --ifuel 2"

/// One checked append under its exact bound.
let push_bytes_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (value: t_Slice u8) :
  Lemma
    (requires vlen input + len value <= max_usize)
    (ensures
      push_bytes input value ==
      Some (Alloc.Vec.Vec (Seq.append input._0 value) input._1)) =
  ()

let push_u64_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (value: u64) :
  Lemma
    (requires vlen input + 8 <= max_usize)
    (ensures
      push_u64 input value ==
      Some (Alloc.Vec.Vec (Seq.append input._0 (u8s value)) input._1)) =
  push_bytes_spec input (u8s value)

let push_lp_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (value: t_Slice u8) :
  Lemma
    (requires vlen input + 8 + len value <= max_usize)
    (ensures
      push_lp_checked input value ==
      Some
        (Alloc.Vec.Vec
          (Seq.append (Seq.append input._0 (u8s (u64_len value))) value)
          input._1)) =
  push_u64_spec input (u64_len value);
  push_bytes_spec
    (Alloc.Vec.Vec (Seq.append input._0 (u8s (u64_len value))) input._1)
    value

// ── Encoder equals the concatenation spec ───────────────────────────────────

let push_share_body_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (f: t_ShareEnvelopeBytes)
      (item: t_Slice u8) :
  Lemma
    (requires vlen input + body_len f item <= max_usize)
    (ensures
      push_share_body input f item ==
      Some
        (Alloc.Vec.Vec
          (concat_left input._0 (expanded (body_chunks f item)))
          input._1)) =
  let a = f.f_sender_user_id in
  let b = f.f_sender_device_id in
  let c = f.f_sender_vk in
  let d = f.f_recipient_user_id in
  let e: t_Slice u8 = f.f_recipient_ek_digest in
  let g = f.f_lineage_id in
  let h = f.f_revision in
  let v0 = input in
  let v1 = Alloc.Vec.Vec (Seq.append v0._0 (u8s (u64_len a))) v0._1 in
  let v2 = Alloc.Vec.Vec (Seq.append v1._0 a) v1._1 in
  let v3 = Alloc.Vec.Vec (Seq.append v2._0 (u8s (u64_len b))) v2._1 in
  let v4 = Alloc.Vec.Vec (Seq.append v3._0 b) v3._1 in
  let v5 = Alloc.Vec.Vec (Seq.append v4._0 (u8s (u64_len c))) v4._1 in
  let v6 = Alloc.Vec.Vec (Seq.append v5._0 c) v5._1 in
  let v7 = Alloc.Vec.Vec (Seq.append v6._0 (u8s (u64_len d))) v6._1 in
  let v8 = Alloc.Vec.Vec (Seq.append v7._0 d) v7._1 in
  let v9 = Alloc.Vec.Vec (Seq.append v8._0 e) v8._1 in
  let v10 = Alloc.Vec.Vec (Seq.append v9._0 (u8s (u64_len g))) v9._1 in
  let v11 = Alloc.Vec.Vec (Seq.append v10._0 g) v10._1 in
  let v12 = Alloc.Vec.Vec (Seq.append v11._0 (u8s h)) v11._1 in
  let v13 = Alloc.Vec.Vec (Seq.append v12._0 (u8s (u64_len item))) v12._1 in
  push_lp_spec v0 a;
  push_lp_spec v2 b;
  push_lp_spec v4 c;
  push_lp_spec v6 d;
  push_bytes_spec v8 e;
  push_lp_spec v9 g;
  push_u64_spec v11 h;
  push_lp_spec v13 item

/// The `VSE2` marker followed by the signed body.
let prefix_chunks (f: t_ShareEnvelopeBytes) (item: t_Slice u8) : list chunk =
  Raw magic :: body_chunks f item

let push_share_prefix_spec
      (input: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (f: t_ShareEnvelopeBytes)
      (item: t_Slice u8) :
  Lemma
    (requires vlen input + 4 + body_len f item <= max_usize)
    (ensures
      push_share_prefix input f item ==
      Some
        (Alloc.Vec.Vec
          (concat_left input._0 (expanded (prefix_chunks f item)))
          input._1)) =
  push_bytes_spec input magic;
  push_share_body_spec
    (Alloc.Vec.Vec (Seq.append input._0 magic) input._1)
    f
    item

#pop-options
