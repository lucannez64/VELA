module Vela_session_policy_tag_producer_lemmas

/// Hand-written refinement of the extracted raw-slice challenge-tag producer.
///
/// The production constructor is `Vela_session_policy.Challenge.stored_tag_from_bytes`.
/// hax extracts its real body: the raw `usize` length plus nine unrolled,
/// bounds-checked `byte_or_zero` reads. This module states and proves, for an
/// *arbitrary* `t_Slice u8` (an unbounded stored value):
///
///   * the real length is preserved, so a long value cannot alias a short tag;
///   * the first `min (Seq.length bytes) 9` buffer positions are exactly the raw
///     bytes and every later position is zero padding;
///   * the composed classifier accepts exactly the literal `login`, `enroll`
///     and `web_token` byte strings;
///   * the composed consumption decision accepts for `expected` exactly when
///     the raw slice is `expected`'s literal tag;
///   * the issued path `purpose_tag_bytes` is a literal tag for every purpose.
///
/// The literal predicates below are written over the raw slice independently of
/// the Rust contract helper `stored_tag_copies_prefix` and of the bounded
/// predicates in `Vela_session_policy_challenge_lemmas`; the glue between them
/// is proved from the extracted producer body. No proof escape is used.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy_challenge_lemmas

// ── Independent raw-slice byte specification ───────────────────────────────

/// Total byte reader for the independent specification: positions past the raw
/// length read as zero padding. This mirrors the required copy semantics
/// without calling the implementation's `byte_or_zero`.
let slice_byte (b: t_Slice u8) (k: nat) : u8 =
  if k < Seq.length b then Seq.index b k else mk_u8 0

/// `login` = 108,111,103,105,110.
let slice_is_login (b: t_Slice u8) : bool =
  Seq.length b = 5 &&
  slice_byte b 0 =. mk_u8 108 &&
  slice_byte b 1 =. mk_u8 111 &&
  slice_byte b 2 =. mk_u8 103 &&
  slice_byte b 3 =. mk_u8 105 &&
  slice_byte b 4 =. mk_u8 110

/// `enroll` = 101,110,114,111,108,108.
let slice_is_enroll (b: t_Slice u8) : bool =
  Seq.length b = 6 &&
  slice_byte b 0 =. mk_u8 101 &&
  slice_byte b 1 =. mk_u8 110 &&
  slice_byte b 2 =. mk_u8 114 &&
  slice_byte b 3 =. mk_u8 111 &&
  slice_byte b 4 =. mk_u8 108 &&
  slice_byte b 5 =. mk_u8 108

/// `web_token` = 119,101,98,95,116,111,107,101,110.
let slice_is_web_token (b: t_Slice u8) : bool =
  Seq.length b = 9 &&
  slice_byte b 0 =. mk_u8 119 &&
  slice_byte b 1 =. mk_u8 101 &&
  slice_byte b 2 =. mk_u8 98 &&
  slice_byte b 3 =. mk_u8 95 &&
  slice_byte b 4 =. mk_u8 116 &&
  slice_byte b 5 =. mk_u8 111 &&
  slice_byte b 6 =. mk_u8 107 &&
  slice_byte b 7 =. mk_u8 101 &&
  slice_byte b 8 =. mk_u8 110

/// The raw specification's recognition result for an arbitrary slice.
let classify_slice (b: t_Slice u8) : t_TagClass =
  if slice_is_login b then TagClass_Recognized ChallengePurpose_Login
  else if slice_is_enroll b then TagClass_Recognized ChallengePurpose_Enroll
  else if slice_is_web_token b then TagClass_Recognized ChallengePurpose_WebToken
  else TagClass_Unknown

// ── Producer facts from the extracted body ─────────────────────────────────

/// `Slice::len` is the sequence length: the producer stores the raw `usize`,
/// and this is the only place that equation is introduced.
let slice_len_v (b: t_Slice u8)
  : Lemma (v (Core_models.Slice.impl__len b) = Seq.length b) =
  ()

/// The producer's stored length is the raw slice length, unchanged.
let producer_len_usize (b: t_Slice u8)
  : Lemma ((stored_tag_from_bytes b).f_len = Core_models.Slice.impl__len b) =
  ()

/// Headline length-preservation fact: no truncation happens. In particular a
/// long input keeps a long length and therefore cannot alias a short tag.
let producer_len (b: t_Slice u8)
  : Lemma (v ((stored_tag_from_bytes b).f_len) = Seq.length b) =
  slice_len_v b

/// Total copied-buffer reader: the first nine produced positions, zero beyond.
let tag_byte (tag: t_StoredTag) (k: nat) : u8 =
  if k < 9 then Seq.index tag.f_bytes k else mk_u8 0

/// The `k`-th produced buffer position.
let producer_byte (b: t_Slice u8) (k: nat) : u8 =
  tag_byte (stored_tag_from_bytes b) k

/// Each of the nine positions is the implementation's checked byte read.
let producer_byte_is_byte_or_zero (b: t_Slice u8) (k: nat)
  : Lemma
    (requires (k < 9))
    (ensures (producer_byte b k = byte_or_zero b (mk_usize k))) =
  if k = 0 then ()
  else if k = 1 then ()
  else if k = 2 then ()
  else if k = 3 then ()
  else if k = 4 then ()
  else if k = 5 then ()
  else if k = 6 then ()
  else if k = 7 then ()
  else ()

/// The copied position equals the independent raw-slice byte reader: the raw
/// byte when it exists, zero padding otherwise.
let producer_position_matches_slice_byte (b: t_Slice u8) (k: nat)
  : Lemma
    (requires (k < 9))
    (ensures (producer_byte b k = slice_byte b k)) =
  producer_byte_is_byte_or_zero b k;
  slice_len_v b

/// Headline prefix-exactness fact: every in-range copied position is exactly
/// the raw byte, for an arbitrary slice and position.
let copied_prefix_is_exact (b: t_Slice u8) (k: nat)
  : Lemma
    (requires (k < 9 /\ k < Seq.length b))
    (ensures (Seq.index (stored_tag_from_bytes b).f_bytes k = Seq.index b k)) =
  producer_position_matches_slice_byte b k

/// The same statement in range-wide form: for every position below nine, the
/// copied position equals the independent raw-slice reader.
let copied_prefix_is_exact_forall (b: t_Slice u8)
  : Lemma (
      forall (k: nat).
        k < 9 ==> producer_byte b k = slice_byte b k) =
  FStar.Classical.forall_intro
    (FStar.Classical.move_requires (producer_position_matches_slice_byte b))

/// Positions past the raw length are zero padding, not stale bytes.
let copied_padding_is_zero (b: t_Slice u8) (k: nat)
  : Lemma
    (requires (k < 9 /\ Seq.length b <= k))
    (ensures (producer_byte b k = mk_u8 0)) =
  producer_position_matches_slice_byte b k

// ── The bounded raw predicates agree with the slice literals ───────────────

let bounded_login_iff_slice (b: t_Slice u8)
  : Lemma (raw_login (stored_tag_from_bytes b) = slice_is_login b) =
  producer_len b;
  producer_position_matches_slice_byte b 0;
  producer_position_matches_slice_byte b 1;
  producer_position_matches_slice_byte b 2;
  producer_position_matches_slice_byte b 3;
  producer_position_matches_slice_byte b 4

let bounded_enroll_iff_slice (b: t_Slice u8)
  : Lemma (raw_enroll (stored_tag_from_bytes b) = slice_is_enroll b) =
  producer_len b;
  producer_position_matches_slice_byte b 0;
  producer_position_matches_slice_byte b 1;
  producer_position_matches_slice_byte b 2;
  producer_position_matches_slice_byte b 3;
  producer_position_matches_slice_byte b 4;
  producer_position_matches_slice_byte b 5

let bounded_web_token_iff_slice (b: t_Slice u8)
  : Lemma (raw_web_token (stored_tag_from_bytes b) = slice_is_web_token b) =
  producer_len b;
  producer_position_matches_slice_byte b 0;
  producer_position_matches_slice_byte b 1;
  producer_position_matches_slice_byte b 2;
  producer_position_matches_slice_byte b 3;
  producer_position_matches_slice_byte b 4;
  producer_position_matches_slice_byte b 5;
  producer_position_matches_slice_byte b 6;
  producer_position_matches_slice_byte b 7;
  producer_position_matches_slice_byte b 8

// ── Composed classifier and consumption decision ───────────────────────────

/// Headline composed-classifier theorem: for every slice, the actual
/// production conversion followed by the actual classifier recognizes exactly
/// the literal issued byte strings.
let classify_producer_matches_slice (b: t_Slice u8)
  : Lemma (classify_stored_tag (stored_tag_from_bytes b) = classify_slice b) =
  classify_matches_raw (stored_tag_from_bytes b);
  bounded_login_iff_slice b;
  bounded_enroll_iff_slice b;
  bounded_web_token_iff_slice b

/// The composed consumption decision accepts `expected` exactly when the raw
/// slice is `expected`'s literal tag. A wrong or unknown raw value is spent and
/// reported as `WrongPurpose`.
let consumption_accepts_iff_slice
      (b: t_Slice u8)
      (expected: t_ChallengePurpose)
  : Lemma
    (classify_consumption (Core_models.Option.Option_Some (stored_tag_from_bytes b)) expected =
     ChallengeConsumption_Accepted
     <==>
     ((expected = ChallengePurpose_Login /\ slice_is_login b) \/
      (expected = ChallengePurpose_Enroll /\ slice_is_enroll b) \/
      (expected = ChallengePurpose_WebToken /\ slice_is_web_token b))) =
  classify_producer_matches_slice b;
  classify_consumption_matches_raw
    (Core_models.Option.Option_Some (stored_tag_from_bytes b)) expected

/// A long value keeps a long length and is never recognized. This is the
/// truncation/aliasing exclusion stated on its own.
let long_input_cannot_alias_short (b: t_Slice u8)
  : Lemma
    (requires (Seq.length b > 9))
    (ensures (
      v ((stored_tag_from_bytes b).f_len) > 9 /\
      classify_stored_tag (stored_tag_from_bytes b) = TagClass_Unknown)) =
  producer_len b;
  classify_producer_matches_slice b

// ── The issued path: `purpose_tag_bytes` is a literal tag ──────────────────

let issued_login_is_literal ()
  : Lemma (slice_is_login (purpose_tag_bytes ChallengePurpose_Login)) =
  ()

let issued_enroll_is_literal ()
  : Lemma (slice_is_enroll (purpose_tag_bytes ChallengePurpose_Enroll)) =
  ()

let issued_web_token_is_literal ()
  : Lemma (slice_is_web_token (purpose_tag_bytes ChallengePurpose_WebToken)) =
  ()

/// The producer converts each issued literal into the bounded representation
/// the classifier recognizes for that purpose.
let issued_classified (purpose: t_ChallengePurpose)
  : Lemma
    (classify_stored_tag (stored_tag_from_bytes (purpose_tag_bytes purpose)) =
     TagClass_Recognized purpose) =
  classify_producer_matches_slice (purpose_tag_bytes purpose);
  match purpose <: t_ChallengePurpose with
  | ChallengePurpose_Login -> issued_login_is_literal ()
  | ChallengePurpose_Enroll -> issued_enroll_is_literal ()
  | ChallengePurpose_WebToken -> issued_web_token_is_literal ()

/// The full issued path used by `/auth/verify`, `/device/enroll` and
/// `/web-session/:id/token`: issue the purpose literal, store it, take it back
/// as raw bytes, convert with the production constructor, and classify. The
/// consumer's own purpose is accepted, and no other purpose is.
let issued_path_accepts_only_its_purpose (stored expected: t_ChallengePurpose)
  : Lemma
    (classify_consumption
       (Core_models.Option.Option_Some
          (stored_tag_from_bytes (purpose_tag_bytes stored)))
       expected =
     (if stored = expected then ChallengeConsumption_Accepted
      else ChallengeConsumption_WrongPurpose)) =
  issued_classified stored;
  match stored <: t_ChallengePurpose with
  | ChallengePurpose_Login ->
    (match expected <: t_ChallengePurpose with
     | ChallengePurpose_Login -> ()
     | ChallengePurpose_Enroll -> ()
     | ChallengePurpose_WebToken -> ())
  | ChallengePurpose_Enroll ->
    (match expected <: t_ChallengePurpose with
     | ChallengePurpose_Login -> ()
     | ChallengePurpose_Enroll -> ()
     | ChallengePurpose_WebToken -> ())
  | ChallengePurpose_WebToken ->
    (match expected <: t_ChallengePurpose with
     | ChallengePurpose_Login -> ()
     | ChallengePurpose_Enroll -> ()
     | ChallengePurpose_WebToken -> ())

// ── Non-vacuity witnesses ─────────────────────────────────────────────────

let concrete_login : t_Slice u8 =
  let list = [mk_u8 108; mk_u8 111; mk_u8 103; mk_u8 105; mk_u8 110] in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 5);
  Rust_primitives.Hax.array_of_list 5 list

let concrete_long : t_Slice u8 =
  let list =
    [
      mk_u8 108; mk_u8 111; mk_u8 103; mk_u8 105; mk_u8 110;
      mk_u8 33; mk_u8 33; mk_u8 33; mk_u8 33; mk_u8 33
    ]
  in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 10);
  Rust_primitives.Hax.array_of_list 10 list

let concrete_login_is_literal ()
  : Lemma (slice_is_login concrete_login) =
  ()

/// The composed classifier really does recognize a concrete raw `login` slice,
/// so the equivalence above is not vacuous.
let concrete_login_classified ()
  : Lemma
    (classify_stored_tag (stored_tag_from_bytes concrete_login) =
     TagClass_Recognized ChallengePurpose_Login) =
  classify_producer_matches_slice concrete_login;
  concrete_login_is_literal ()

/// That same raw slice is refused for every other purpose.
let concrete_login_refused_for_other_purposes ()
  : Lemma (
      classify_consumption (Core_models.Option.Option_Some (stored_tag_from_bytes concrete_login))
        ChallengePurpose_Enroll = ChallengeConsumption_WrongPurpose /\
      classify_consumption (Core_models.Option.Option_Some (stored_tag_from_bytes concrete_login))
        ChallengePurpose_WebToken = ChallengeConsumption_WrongPurpose) =
  consumption_accepts_iff_slice concrete_login ChallengePurpose_Enroll;
  consumption_accepts_iff_slice concrete_login ChallengePurpose_WebToken

/// A ten-byte raw value keeps its length and is unknown: truncation to the
/// nine-byte buffer cannot make it a five-byte tag.
let concrete_long_is_unknown ()
  : Lemma ((stored_tag_from_bytes concrete_long).f_len = mk_usize 10 /\
           classify_stored_tag (stored_tag_from_bytes concrete_long) = TagClass_Unknown) =
  producer_len concrete_long;
  long_input_cannot_alias_short concrete_long
