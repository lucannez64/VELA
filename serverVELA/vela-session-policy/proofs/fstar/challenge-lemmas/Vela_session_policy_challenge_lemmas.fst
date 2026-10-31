module Vela_session_policy_challenge_lemmas

/// Hand-written exact-byte refinement of the extracted challenge classifier.
///
/// The Rust production decision is `Vela_session_policy.Challenge.classify_stored_tag`
/// (and `classify_consumption`). This module restates the intended recognition
/// as literal byte values and lengths, independent of the Rust helper
/// `purpose_stored_tag` / `same_stored_tag`, and proves the extracted functions
/// equal that raw-byte specification for *every* bounded tag.
///
/// The stored-tag conversion from an unbounded `Vec<u8>` is Rust glue
/// (`stored_tag_from_bytes`) and is covered by Rust tests; this module speaks
/// about the bounded value it produces. No proof escape is used.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge

// ── Independent raw-byte specification ─────────────────────────────────────

let b0 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 0 ]
let b1 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 1 ]
let b2 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 2 ]
let b3 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 3 ]
let b4 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 4 ]
let b5 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 5 ]
let b6 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 6 ]
let b7 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 7 ]
let b8 (t: t_StoredTag) : u8 = t.f_bytes.[ mk_usize 8 ]

/// `login` = 108,111,103,105,110.
let raw_login (t: t_StoredTag) : bool =
  t.f_len =. mk_usize 5 &&
  b0 t =. mk_u8 108 &&
  b1 t =. mk_u8 111 &&
  b2 t =. mk_u8 103 &&
  b3 t =. mk_u8 105 &&
  b4 t =. mk_u8 110

/// `enroll` = 101,110,114,111,108,108.
let raw_enroll (t: t_StoredTag) : bool =
  t.f_len =. mk_usize 6 &&
  b0 t =. mk_u8 101 &&
  b1 t =. mk_u8 110 &&
  b2 t =. mk_u8 114 &&
  b3 t =. mk_u8 111 &&
  b4 t =. mk_u8 108 &&
  b5 t =. mk_u8 108

/// `web_token` = 119,101,98,95,116,111,107,101,110.
let raw_web_token (t: t_StoredTag) : bool =
  t.f_len =. mk_usize 9 &&
  b0 t =. mk_u8 119 &&
  b1 t =. mk_u8 101 &&
  b2 t =. mk_u8 98 &&
  b3 t =. mk_u8 95 &&
  b4 t =. mk_u8 116 &&
  b5 t =. mk_u8 111 &&
  b6 t =. mk_u8 107 &&
  b7 t =. mk_u8 101 &&
  b8 t =. mk_u8 110

/// The raw specification's recognition result.
let raw_classify (t: t_StoredTag) : t_TagClass =
  if raw_login t then TagClass_Recognized ChallengePurpose_Login
  else if raw_enroll t then TagClass_Recognized ChallengePurpose_Enroll
  else if raw_web_token t then TagClass_Recognized ChallengePurpose_WebToken
  else TagClass_Unknown

// ── The extracted classifier equals the raw-byte specification ─────────────

/// Each issued tag has exactly the literal bytes in the raw specification.
let issued_tags_are_raw ()
  : Lemma (
      raw_login (purpose_stored_tag ChallengePurpose_Login) /\
      raw_enroll (purpose_stored_tag ChallengePurpose_Enroll) /\
      raw_web_token (purpose_stored_tag ChallengePurpose_WebToken)) =
  ()

/// The exact recognition result for every bounded tag.
let classify_matches_raw (t: t_StoredTag)
  : Lemma (classify_stored_tag t = raw_classify t) =
  ()

/// The raw classifier is a function of the exact bytes: two tags with the same
/// recognition result agree on which raw predicate fired.
let raw_recognized_purpose (t: t_StoredTag)
  : Lemma (
      (match raw_classify t with
       | TagClass_Recognized p -> p = ChallengePurpose_Login \/ p = ChallengePurpose_Enroll \/ p = ChallengePurpose_WebToken
       | TagClass_Unknown -> True)) =
  ()

// ── Consumption decision ───────────────────────────────────────────────────

/// The raw consumption specification, independent of `classify_consumption`.
let raw_consumption
      (stored: Core_models.Option.t_Option t_StoredTag)
      (expected: t_ChallengePurpose)
  : t_ChallengeConsumption =
  match stored <: Core_models.Option.t_Option t_StoredTag with
  | Core_models.Option.Option_None -> ChallengeConsumption_Missing
  | Core_models.Option.Option_Some tag ->
    (match raw_classify tag <: t_TagClass with
     | TagClass_Recognized actual ->
       if same_purpose actual expected
       then ChallengeConsumption_Accepted
       else ChallengeConsumption_WrongPurpose
     | TagClass_Unknown -> ChallengeConsumption_WrongPurpose)

let classify_consumption_matches_raw
      (stored: Core_models.Option.t_Option t_StoredTag)
      (expected: t_ChallengePurpose)
  : Lemma (classify_consumption stored expected = raw_consumption stored expected) =
  match stored <: Core_models.Option.t_Option t_StoredTag with
  | Core_models.Option.Option_None -> ()
  | Core_models.Option.Option_Some tag ->
    classify_matches_raw tag

/// An accepted consumption carries exactly the expected purpose's raw bytes.
let accepted_implies_raw_expected
      (tag: t_StoredTag)
      (expected: t_ChallengePurpose)
  : Lemma
    (requires (classify_consumption (Core_models.Option.Option_Some tag) expected = ChallengeConsumption_Accepted))
    (ensures (
      (expected = ChallengePurpose_Login ==> raw_login tag) /\
      (expected = ChallengePurpose_Enroll ==> raw_enroll tag) /\
      (expected = ChallengePurpose_WebToken ==> raw_web_token tag))) =
  classify_matches_raw tag

/// A present but non-matching tag is always the wrong-purpose decision (and
/// therefore the caller's `get_del` has already spent it).
let present_non_matching_is_wrong_purpose
      (tag: t_StoredTag)
      (expected: t_ChallengePurpose)
  : Lemma
    (requires (classify_consumption (Core_models.Option.Option_Some tag) expected <> ChallengeConsumption_Accepted))
    (ensures (classify_consumption (Core_models.Option.Option_Some tag) expected = ChallengeConsumption_WrongPurpose)) =
  classify_matches_raw tag

/// An absent tag is the missing decision, never accepted.
let absent_is_missing (expected: t_ChallengePurpose)
  : Lemma (classify_consumption Core_models.Option.Option_None expected = ChallengeConsumption_Missing) =
  ()

// ── Non-vacuity witnesses ──────────────────────────────────────────────────

let login_tag : t_StoredTag = purpose_stored_tag ChallengePurpose_Login
let enroll_tag : t_StoredTag = purpose_stored_tag ChallengePurpose_Enroll
let web_token_tag : t_StoredTag = purpose_stored_tag ChallengePurpose_WebToken

let login_is_recognized ()
  : Lemma (classify_stored_tag login_tag = TagClass_Recognized ChallengePurpose_Login) =
  ()

let enroll_is_recognized ()
  : Lemma (classify_stored_tag enroll_tag = TagClass_Recognized ChallengePurpose_Enroll) =
  ()

let web_token_is_recognized ()
  : Lemma (classify_stored_tag web_token_tag = TagClass_Recognized ChallengePurpose_WebToken) =
  ()

let login_accepted_for_login ()
  : Lemma (classify_consumption (Core_models.Option.Option_Some login_tag) ChallengePurpose_Login = ChallengeConsumption_Accepted) =
  ()

let login_refused_for_enroll ()
  : Lemma (classify_consumption (Core_models.Option.Option_Some login_tag) ChallengePurpose_Enroll = ChallengeConsumption_WrongPurpose) =
  ()

let unknown_is_wrong_purpose ()
  : Lemma (
      let tag : t_StoredTag =
        { f_len = mk_usize 4;
          f_bytes = login_tag.f_bytes } in
      classify_consumption (Core_models.Option.Option_Some tag) ChallengePurpose_Login = ChallengeConsumption_WrongPurpose) =
  ()
