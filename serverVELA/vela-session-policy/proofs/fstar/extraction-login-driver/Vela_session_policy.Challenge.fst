module Vela_session_policy.Challenge
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// What a challenge may be redeemed for.
type t_ChallengePurpose =
  | ChallengePurpose_Login : t_ChallengePurpose
  | ChallengePurpose_Enroll : t_ChallengePurpose
  | ChallengePurpose_WebToken : t_ChallengePurpose

/// The bounded raw bytes stored under a challenge key.
type t_StoredTag = {
  f_len:usize;
  f_bytes:t_Array u8 (mk_usize 9)
}

/// Exact recognition of a stored tag.
type t_TagClass =
  | TagClass_Recognized : t_ChallengePurpose -> t_TagClass
  | TagClass_Unknown : t_TagClass

/// The decision after the atomic challenge take.
type t_ChallengeConsumption =
  | ChallengeConsumption_Accepted : t_ChallengeConsumption
  | ChallengeConsumption_Missing : t_ChallengeConsumption
  | ChallengeConsumption_WrongPurpose : t_ChallengeConsumption

/// The exact bytes `GET /auth/challenge` stores for `purpose`.
let purpose_tag_bytes (purpose: t_ChallengePurpose) : t_Slice u8 =
  match purpose <: t_ChallengePurpose with
  | ChallengePurpose_Login  ->
    (let list = [mk_u8 108; mk_u8 111; mk_u8 103; mk_u8 105; mk_u8 110] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 5);
      Rust_primitives.Hax.array_of_list 5 list)
    <:
    t_Slice u8
  | ChallengePurpose_Enroll  ->
    (let list = [mk_u8 101; mk_u8 110; mk_u8 114; mk_u8 111; mk_u8 108; mk_u8 108] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 6);
      Rust_primitives.Hax.array_of_list 6 list)
    <:
    t_Slice u8
  | ChallengePurpose_WebToken  ->
    (let list =
        [
          mk_u8 119;
          mk_u8 101;
          mk_u8 98;
          mk_u8 95;
          mk_u8 116;
          mk_u8 111;
          mk_u8 107;
          mk_u8 101;
          mk_u8 110
        ]
      in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
      Rust_primitives.Hax.array_of_list 9 list)
    <:
    t_Slice u8

/// The bounded representation of `purpose_tag_bytes(purpose)`.
let purpose_stored_tag (purpose: t_ChallengePurpose) : t_StoredTag =
  match purpose <: t_ChallengePurpose with
  | ChallengePurpose_Login  ->
    {
      f_len = mk_usize 5;
      f_bytes
      =
      let list =
        [mk_u8 108; mk_u8 111; mk_u8 103; mk_u8 105; mk_u8 110; mk_u8 0; mk_u8 0; mk_u8 0; mk_u8 0]
      in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
      Rust_primitives.Hax.array_of_list 9 list
    }
    <:
    t_StoredTag
  | ChallengePurpose_Enroll  ->
    {
      f_len = mk_usize 6;
      f_bytes
      =
      let list =
        [
          mk_u8 101;
          mk_u8 110;
          mk_u8 114;
          mk_u8 111;
          mk_u8 108;
          mk_u8 108;
          mk_u8 0;
          mk_u8 0;
          mk_u8 0
        ]
      in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
      Rust_primitives.Hax.array_of_list 9 list
    }
    <:
    t_StoredTag
  | ChallengePurpose_WebToken  ->
    {
      f_len = mk_usize 9;
      f_bytes
      =
      let list =
        [
          mk_u8 119;
          mk_u8 101;
          mk_u8 98;
          mk_u8 95;
          mk_u8 116;
          mk_u8 111;
          mk_u8 107;
          mk_u8 101;
          mk_u8 110
        ]
      in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
      Rust_primitives.Hax.array_of_list 9 list
    }
    <:
    t_StoredTag

/// The byte at `index` when the raw value is long enough, zero otherwise.
/// Each call is an explicit bounds test plus a checked slice read, so the
/// unrolled copy below never indexes out of bounds and the extracted body is a
/// pure conditional rather than a loop.
let byte_or_zero (bytes: t_Slice u8) (index: usize) : u8 =
  if index <. (Core_models.Slice.impl__len #u8 bytes <: usize) then bytes.[ index ] else mk_u8 0

/// Structural contract of the bounded copy, stated over the raw slice: the
/// real length is preserved and each of the nine buffer positions holds the raw
/// byte at that position when the raw value reaches it, and zero otherwise.
/// The comparisons and index reads are written out explicitly rather than by
/// calling [`byte_or_zero`], so the contract does not restate the helper used
/// by the implementation.
let stored_tag_copies_prefix (tag: t_StoredTag) (bytes: t_Slice u8) : bool =
  tag.f_len =. (Core_models.Slice.impl__len #u8 bytes <: usize) &&
  (tag.f_bytes.[ mk_usize 0 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 0 <: bool
    then bytes.[ mk_usize 0 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 1 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 1 <: bool
    then bytes.[ mk_usize 1 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 2 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 2 <: bool
    then bytes.[ mk_usize 2 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 3 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 3 <: bool
    then bytes.[ mk_usize 3 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 4 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 4 <: bool
    then bytes.[ mk_usize 4 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 5 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 5 <: bool
    then bytes.[ mk_usize 5 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 6 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 6 <: bool
    then bytes.[ mk_usize 6 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 7 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 7 <: bool
    then bytes.[ mk_usize 7 ] <: u8
    else mk_u8 0) &&
  (tag.f_bytes.[ mk_usize 8 ] <: u8) =.
  (if (Core_models.Slice.impl__len #u8 bytes <: usize) >. mk_usize 8 <: bool
    then bytes.[ mk_usize 8 ] <: u8
    else mk_u8 0)

/// Copy the stored bytes into the bounded representation. Bytes past
/// `MAX_CHALLENGE_TAG_LEN` are not copied but the real length is retained, so
/// the classifier cannot mistake a truncated long value for a short tag. The
/// nine reads are unrolled so the extracted body is a single record literal;
/// the checked `ensures` states the exact prefix and length relation hax then
/// proves against that body.
let stored_tag_from_bytes (bytes: t_Slice u8)
    : Prims.Pure t_StoredTag
      Prims.l_True
      (ensures
        fun tag ->
          let tag:t_StoredTag = tag in
          stored_tag_copies_prefix tag bytes) =
  {
    f_len = Core_models.Slice.impl__len #u8 bytes;
    f_bytes
    =
    let list =
      [
        byte_or_zero bytes (mk_usize 0);
        byte_or_zero bytes (mk_usize 1);
        byte_or_zero bytes (mk_usize 2);
        byte_or_zero bytes (mk_usize 3);
        byte_or_zero bytes (mk_usize 4);
        byte_or_zero bytes (mk_usize 5);
        byte_or_zero bytes (mk_usize 6);
        byte_or_zero bytes (mk_usize 7);
        byte_or_zero bytes (mk_usize 8)
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
    Rust_primitives.Hax.array_of_list 9 list
  }
  <:
  t_StoredTag

/// Structural recognition equality over the *significant* stored bytes.
/// Padding past `len` is not part of the stored value and is ignored; the
/// three recognized lengths are 5, 6 and 9. Written without derived
/// `PartialEq` so the hax translation is an explicit conjunction.
let same_stored_tag (a b: t_StoredTag) : bool =
  a.f_len =. b.f_len &&
  (a.f_len <>. mk_usize 5 ||
  (a.f_bytes.[ mk_usize 0 ] <: u8) =. (b.f_bytes.[ mk_usize 0 ] <: u8) &&
  (a.f_bytes.[ mk_usize 1 ] <: u8) =. (b.f_bytes.[ mk_usize 1 ] <: u8) &&
  (a.f_bytes.[ mk_usize 2 ] <: u8) =. (b.f_bytes.[ mk_usize 2 ] <: u8) &&
  (a.f_bytes.[ mk_usize 3 ] <: u8) =. (b.f_bytes.[ mk_usize 3 ] <: u8) &&
  (a.f_bytes.[ mk_usize 4 ] <: u8) =. (b.f_bytes.[ mk_usize 4 ] <: u8)) &&
  (a.f_len <>. mk_usize 6 ||
  (a.f_bytes.[ mk_usize 0 ] <: u8) =. (b.f_bytes.[ mk_usize 0 ] <: u8) &&
  (a.f_bytes.[ mk_usize 1 ] <: u8) =. (b.f_bytes.[ mk_usize 1 ] <: u8) &&
  (a.f_bytes.[ mk_usize 2 ] <: u8) =. (b.f_bytes.[ mk_usize 2 ] <: u8) &&
  (a.f_bytes.[ mk_usize 3 ] <: u8) =. (b.f_bytes.[ mk_usize 3 ] <: u8) &&
  (a.f_bytes.[ mk_usize 4 ] <: u8) =. (b.f_bytes.[ mk_usize 4 ] <: u8) &&
  (a.f_bytes.[ mk_usize 5 ] <: u8) =. (b.f_bytes.[ mk_usize 5 ] <: u8)) &&
  (a.f_len <>. mk_usize 9 ||
  (a.f_bytes.[ mk_usize 0 ] <: u8) =. (b.f_bytes.[ mk_usize 0 ] <: u8) &&
  (a.f_bytes.[ mk_usize 1 ] <: u8) =. (b.f_bytes.[ mk_usize 1 ] <: u8) &&
  (a.f_bytes.[ mk_usize 2 ] <: u8) =. (b.f_bytes.[ mk_usize 2 ] <: u8) &&
  (a.f_bytes.[ mk_usize 3 ] <: u8) =. (b.f_bytes.[ mk_usize 3 ] <: u8) &&
  (a.f_bytes.[ mk_usize 4 ] <: u8) =. (b.f_bytes.[ mk_usize 4 ] <: u8) &&
  (a.f_bytes.[ mk_usize 5 ] <: u8) =. (b.f_bytes.[ mk_usize 5 ] <: u8) &&
  (a.f_bytes.[ mk_usize 6 ] <: u8) =. (b.f_bytes.[ mk_usize 6 ] <: u8) &&
  (a.f_bytes.[ mk_usize 7 ] <: u8) =. (b.f_bytes.[ mk_usize 7 ] <: u8) &&
  (a.f_bytes.[ mk_usize 8 ] <: u8) =. (b.f_bytes.[ mk_usize 8 ] <: u8))

let stored_tag_matches_purpose (tag: t_StoredTag) (purpose: t_ChallengePurpose) : bool =
  same_stored_tag tag (purpose_stored_tag purpose <: t_StoredTag)

let same_purpose (a b: t_ChallengePurpose) : bool =
  match a, b <: (t_ChallengePurpose & t_ChallengePurpose) with
  | ChallengePurpose_Login , ChallengePurpose_Login
  | ChallengePurpose_Enroll , ChallengePurpose_Enroll
  | ChallengePurpose_WebToken , ChallengePurpose_WebToken  -> true
  | _ -> false

/// Independent Rust restatement of exact recognition. The hand-written F*
/// module additionally proves this against literal byte values, not against
/// this predicate.
let classification_matches_spec (tag: t_StoredTag) (v_class: t_TagClass) : bool =
  match v_class <: t_TagClass with
  | TagClass_Recognized purpose -> stored_tag_matches_purpose tag purpose
  | TagClass_Unknown  ->
    ~.(stored_tag_matches_purpose tag (ChallengePurpose_Login <: t_ChallengePurpose) <: bool) &&
    ~.(stored_tag_matches_purpose tag (ChallengePurpose_Enroll <: t_ChallengePurpose) <: bool) &&
    ~.(stored_tag_matches_purpose tag (ChallengePurpose_WebToken <: t_ChallengePurpose) <: bool)

/// Recognize the exact stored bytes. A tag is accepted only if its length and
/// all significant bytes equal one of the three issued tags.
let classify_stored_tag (tag: t_StoredTag)
    : Prims.Pure t_TagClass
      Prims.l_True
      (ensures
        fun v_class ->
          let v_class:t_TagClass = v_class in
          classification_matches_spec tag v_class) =
  if
    same_stored_tag tag
      (purpose_stored_tag (ChallengePurpose_Login <: t_ChallengePurpose) <: t_StoredTag)
  then TagClass_Recognized (ChallengePurpose_Login <: t_ChallengePurpose) <: t_TagClass
  else
    if
      same_stored_tag tag
        (purpose_stored_tag (ChallengePurpose_Enroll <: t_ChallengePurpose) <: t_StoredTag)
    then TagClass_Recognized (ChallengePurpose_Enroll <: t_ChallengePurpose) <: t_TagClass
    else
      if
        same_stored_tag tag
          (purpose_stored_tag (ChallengePurpose_WebToken <: t_ChallengePurpose) <: t_StoredTag)
      then TagClass_Recognized (ChallengePurpose_WebToken <: t_ChallengePurpose) <: t_TagClass
      else TagClass_Unknown <: t_TagClass

/// Independent Rust restatement of the consumption decision.
let consumption_matches_spec
      (stored: Core_models.Option.t_Option t_StoredTag)
      (expected: t_ChallengePurpose)
      (decision: t_ChallengeConsumption)
    : bool =
  match decision <: t_ChallengeConsumption with
  | ChallengeConsumption_Accepted  ->
    (match stored <: Core_models.Option.t_Option t_StoredTag with
      | Core_models.Option.Option_Some tag ->
        (match classify_stored_tag tag <: t_TagClass with
          | TagClass_Recognized actual -> same_purpose actual expected
          | TagClass_Unknown  -> false)
      | Core_models.Option.Option_None  -> false)
  | ChallengeConsumption_Missing  ->
    (match stored <: Core_models.Option.t_Option t_StoredTag with
      | Core_models.Option.Option_None  -> true
      | _ -> false)
  | ChallengeConsumption_WrongPurpose  ->
    match stored <: Core_models.Option.t_Option t_StoredTag with
    | Core_models.Option.Option_None  -> false
    | Core_models.Option.Option_Some tag ->
      match classify_stored_tag tag <: t_TagClass with
      | TagClass_Recognized actual -> ~.(same_purpose actual expected <: bool)
      | TagClass_Unknown  -> true

/// Classify the value returned by the atomic take. The take has already
/// removed the key, so every `Some` outcome (accepted or wrong purpose) spends
/// the nonce.
let classify_consumption
      (stored: Core_models.Option.t_Option t_StoredTag)
      (expected: t_ChallengePurpose)
    : Prims.Pure t_ChallengeConsumption
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ChallengeConsumption = decision in
          consumption_matches_spec stored expected decision) =
  match stored <: Core_models.Option.t_Option t_StoredTag with
  | Core_models.Option.Option_None  -> ChallengeConsumption_Missing <: t_ChallengeConsumption
  | Core_models.Option.Option_Some tag ->
    match classify_stored_tag tag <: t_TagClass with
    | TagClass_Recognized actual ->
      if same_purpose actual expected
      then ChallengeConsumption_Accepted <: t_ChallengeConsumption
      else ChallengeConsumption_WrongPurpose <: t_ChallengeConsumption
    | TagClass_Unknown  -> ChallengeConsumption_WrongPurpose <: t_ChallengeConsumption

/// Classify the exact value the atomic take returned.
/// This is the complete pure adapter from the store result to the decision:
/// `None` means the nonce was absent, expired or already spent and yields
/// [`ChallengeConsumption::Missing`]. `Some(bytes)` is converted with the
/// production [`stored_tag_from_bytes`] and classified with the production
/// [`classify_consumption`]; it is accepted only when the stored bytes are
/// exactly `expected`'s issued tag, and every other present value is
/// [`ChallengeConsumption::WrongPurpose`]. The take already removed a present
/// value, so both `Some` outcomes spend the nonce.
/// The parameter is a borrow so the caller keeps ownership of the value
/// returned by `get_del`; nothing is truncated or copied beyond the bounded
/// conversion.
let classify_taken_challenge
      (consumed: Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      (expected: t_ChallengePurpose)
    : t_ChallengeConsumption =
  match consumed <: Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) with
  | Core_models.Option.Option_None  -> ChallengeConsumption_Missing <: t_ChallengeConsumption
  | Core_models.Option.Option_Some bytes ->
    classify_consumption (Core_models.Option.Option_Some
        (stored_tag_from_bytes (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global bytes
              <:
              t_Slice u8)
          <:
          t_StoredTag)
        <:
        Core_models.Option.t_Option t_StoredTag)
      expected
