module Vela_session_policy_challenge_take_adapter

/// Hand-written refinement of the extracted `Option<Vec<u8>>` take adapter.
///
/// The production adapter is
/// `Vela_session_policy.Challenge.classify_taken_challenge`. hax extracts its
/// real body: match on the value the atomic take returned, `Missing` for
/// `None`, and otherwise the production `stored_tag_from_bytes` conversion
/// followed by the production `classify_consumption` decision, applied to the
/// actual `Vec` slice. Every handler now routes its post-`get_del` decision
/// through this extracted function.
///
/// This module states an *independent literal-byte specification* over the
/// actual `Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global` and proves the extracted
/// adapter equals it for every store result and every expected purpose:
///
///   * `None` is `Missing` (absent, expired or already spent);
///   * `Some v` is `Accepted` exactly when the underlying bytes of `v` are
///     `expected`'s issued literal tag (`login`, `enroll` or `web_token`);
///   * every other present value (empty, truncated, corrupted, longer than the
///     literal, or issued for another purpose) is `WrongPurpose` and is
///     therefore already spent by the take;
///   * the real length is retained by the bounded conversion, so a long value
///     cannot alias a short literal.
///
/// The adapter on a present actual `Vec` is also proved equal to the earlier
/// checked `raw_login_decision` on the same slice, and the issued path is
/// checked for all three purposes through the adapter. The literal predicates
/// below are written directly over the actual store value and its byte
/// positions; they do not call the implementation's conversion, classifier or
/// contract helpers. No proof goal is used as a hypothesis.
///
/// This is a pure adapter refinement. It does not claim `get_del`
/// atomicity/durability, sled or handler execution, `Vec` allocation/aliasing
/// semantics, the trusted imported hax models, TTL/expiry, crash/retry
/// behaviour, or any effect/refinement theorem. The raw slice returned by the
/// real store is still modelled by this `Vec` value.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy_tag_producer_lemmas
open Vela_session_policy_challenge_lemmas

// ── Independent literal-byte specification over the actual store value ─────

/// The bytes actually carried by the store value the take returned.
let vec_bytes (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : t_Slice u8 = v._0

/// Total byte reader for the independent specification: positions past the
/// value's real length read as zero padding. This does not call the
/// implementation's `byte_or_zero`.
let vec_byte (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (k: nat) : u8 =
  if k < Seq.length (vec_bytes v) then Seq.index (vec_bytes v) k else mk_u8 0

/// `login` = 108,111,103,105,110.
let vec_is_login (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : bool =
  Seq.length (vec_bytes v) = 5 &&
  vec_byte v 0 =. mk_u8 108 &&
  vec_byte v 1 =. mk_u8 111 &&
  vec_byte v 2 =. mk_u8 103 &&
  vec_byte v 3 =. mk_u8 105 &&
  vec_byte v 4 =. mk_u8 110

/// `enroll` = 101,110,114,111,108,108.
let vec_is_enroll (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : bool =
  Seq.length (vec_bytes v) = 6 &&
  vec_byte v 0 =. mk_u8 101 &&
  vec_byte v 1 =. mk_u8 110 &&
  vec_byte v 2 =. mk_u8 114 &&
  vec_byte v 3 =. mk_u8 111 &&
  vec_byte v 4 =. mk_u8 108 &&
  vec_byte v 5 =. mk_u8 108

/// `web_token` = 119,101,98,95,116,111,107,101,110.
let vec_is_web_token (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : bool =
  Seq.length (vec_bytes v) = 9 &&
  vec_byte v 0 =. mk_u8 119 &&
  vec_byte v 1 =. mk_u8 101 &&
  vec_byte v 2 =. mk_u8 98 &&
  vec_byte v 3 =. mk_u8 95 &&
  vec_byte v 4 =. mk_u8 116 &&
  vec_byte v 5 =. mk_u8 111 &&
  vec_byte v 6 =. mk_u8 107 &&
  vec_byte v 7 =. mk_u8 101 &&
  vec_byte v 8 =. mk_u8 110

/// The complete independent decision for the actual store result. It says:
/// absent is `Missing`; a present value is accepted exactly when its bytes are
/// `expected`'s literal tag; every other present value is `WrongPurpose`.
let taken_literal_spec
      (consumed: Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      (expected: t_ChallengePurpose)
  : t_ChallengeConsumption =
  match consumed <: Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) with
  | Core_models.Option.Option_None -> ChallengeConsumption_Missing
  | Core_models.Option.Option_Some v ->
    if expected = ChallengePurpose_Login then
      (if vec_is_login v
       then ChallengeConsumption_Accepted
       else ChallengeConsumption_WrongPurpose)
    else if expected = ChallengePurpose_Enroll then
      (if vec_is_enroll v
       then ChallengeConsumption_Accepted
       else ChallengeConsumption_WrongPurpose)
    else
      (if vec_is_web_token v
       then ChallengeConsumption_Accepted
       else ChallengeConsumption_WrongPurpose)

// ── The adapter reads the actual Vec slice ─────────────────────────────────

let vec_slice_is_vec_bytes (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  : Lemma (Alloc.Vec.impl_1__as_slice v = vec_bytes v) =
  ()

/// The independent literal predicates over the store value agree with the
/// checked literal predicates over the slice the adapter passes on.
let vec_login_iff_slice (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  : Lemma (vec_is_login v = slice_is_login (Alloc.Vec.impl_1__as_slice v)) =
  ()

let vec_enroll_iff_slice (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  : Lemma (vec_is_enroll v = slice_is_enroll (Alloc.Vec.impl_1__as_slice v)) =
  ()

let vec_web_token_iff_slice (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  : Lemma (vec_is_web_token v =
           slice_is_web_token (Alloc.Vec.impl_1__as_slice v)) =
  ()

// ── Present values are never `Missing` ─────────────────────────────────────

/// A present tag is either accepted or the wrong purpose; the extracted
/// decision has no other present outcome.
let consumption_some_is_accepted_or_wrong
      (tag: t_StoredTag)
      (expected: t_ChallengePurpose)
  : Lemma
    (classify_consumption (Core_models.Option.Option_Some tag) expected =
       ChallengeConsumption_Accepted \/
     classify_consumption (Core_models.Option.Option_Some tag) expected =
       ChallengeConsumption_WrongPurpose) =
  ()

/// A present value is never `Missing`.
let taken_some_never_missing
      (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (expected: t_ChallengePurpose)
  : Lemma
    (classify_taken_challenge (Core_models.Option.Option_Some v) expected <>
     ChallengeConsumption_Missing) =
  consumption_some_is_accepted_or_wrong
    (stored_tag_from_bytes (Alloc.Vec.impl_1__as_slice v))
    expected

// ── Headline: the extracted adapter equals the literal specification ───────

let classify_taken_challenge_matches_literal
      (consumed: Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      (expected: t_ChallengePurpose)
  : Lemma (classify_taken_challenge consumed expected =
           taken_literal_spec consumed expected) =
  match consumed <: Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) with
  | Core_models.Option.Option_None -> ()
  | Core_models.Option.Option_Some v ->
    let b = Alloc.Vec.impl_1__as_slice v in
    vec_login_iff_slice v;
    vec_enroll_iff_slice v;
    vec_web_token_iff_slice v;
    consumption_accepts_iff_slice b expected;
    taken_some_never_missing v expected;
    match expected <: t_ChallengePurpose with
    | ChallengePurpose_Login ->
      if vec_is_login v then () else ()
    | ChallengePurpose_Enroll ->
      if vec_is_enroll v then () else ()
    | ChallengePurpose_WebToken ->
      if vec_is_web_token v then () else ()

/// Absent store result: `Missing`, never accepted.
let classify_taken_challenge_none (expected: t_ChallengePurpose)
  : Lemma (classify_taken_challenge Core_models.Option.Option_None expected =
           ChallengeConsumption_Missing) =
  ()

/// The acceptance form of the headline theorem: for any present actual store
/// value, the extracted adapter accepts `expected` exactly when that value's
/// bytes are the expected literal tag. This is stated over the literal
/// predicates, not over the classifier.
let taken_accepts_iff_literal
      (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (expected: t_ChallengePurpose)
  : Lemma
    (classify_taken_challenge (Core_models.Option.Option_Some v) expected =
       ChallengeConsumption_Accepted
     <==>
     ((expected = ChallengePurpose_Login /\ vec_is_login v) \/
      (expected = ChallengePurpose_Enroll /\ vec_is_enroll v) \/
      (expected = ChallengePurpose_WebToken /\ vec_is_web_token v))) =
  vec_login_iff_slice v;
  vec_enroll_iff_slice v;
  vec_web_token_iff_slice v;
  consumption_accepts_iff_slice (Alloc.Vec.impl_1__as_slice v) expected

/// A present value that is not accepted is the wrong-purpose outcome (and the
/// atomic take already removed it).
let taken_present_nonmatching_is_wrong_purpose
      (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (expected: t_ChallengePurpose)
  : Lemma
    (requires
      (classify_taken_challenge (Core_models.Option.Option_Some v) expected <>
       ChallengeConsumption_Accepted))
    (ensures
      (classify_taken_challenge (Core_models.Option.Option_Some v) expected =
       ChallengeConsumption_WrongPurpose)) =
  taken_some_never_missing v expected

// ── Retained length / no truncation ────────────────────────────────────────

/// The bounded conversion keeps the actual store length; nothing is truncated.
let taken_some_retains_actual_length (value: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  : Lemma
    (v ((stored_tag_from_bytes (Alloc.Vec.impl_1__as_slice value)).f_len) =
     Seq.length (vec_bytes value)) =
  producer_len (Alloc.Vec.impl_1__as_slice value)

/// A value longer than the bounded buffer reaches none of the literals.
let vec_long_is_no_literal (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  : Lemma
    (requires (Seq.length (vec_bytes v) > 9))
    (ensures
      (vec_is_login v = false /\
       vec_is_enroll v = false /\
       vec_is_web_token v = false)) =
  ()

/// A long store value keeps its length and is refused for every purpose: the
/// retained prefix cannot alias a shorter literal.
let taken_long_value_is_wrong_purpose
      (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (expected: t_ChallengePurpose)
  : Lemma
    (requires (Seq.length (vec_bytes v) > 9))
    (ensures
      (classify_taken_challenge (Core_models.Option.Option_Some v) expected =
       ChallengeConsumption_WrongPurpose)) =
  vec_long_is_no_literal v;
  classify_taken_challenge_matches_literal
    (Core_models.Option.Option_Some v) expected

// ── Relation to the earlier checked raw login decision ─────────────────────

/// On a present actual store value, the take adapter is exactly the earlier
/// checked `raw_login_decision` applied to the same actual slice. No decision
/// rule is restated: both sides expose the same extracted conversion and
/// classifier call.
let taken_some_login_equals_raw_login_decision
      (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  : Lemma
    (classify_taken_challenge (Core_models.Option.Option_Some v)
       ChallengePurpose_Login =
     Vela_session_policy_login_raw_nonce.raw_login_decision
       (Alloc.Vec.impl_1__as_slice v)) =
  ()

// ── The issued path through the adapter ────────────────────────────────────

/// The actual store value carrying `purpose`'s issued bytes.
let issued_vec (purpose: t_ChallengePurpose)
  : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Alloc.Vec.Vec (purpose_tag_bytes purpose)
    (Core_models.Marker.PhantomData <:
      Core_models.Marker.t_PhantomData Alloc.Alloc.t_Global)

let issued_vec_slice (purpose: t_ChallengePurpose)
  : Lemma (Alloc.Vec.impl_1__as_slice (issued_vec purpose) =
           purpose_tag_bytes purpose) =
  ()

/// The adapter accepts the exact issued value for its own purpose.
let taken_issued_accepts_its_purpose (purpose: t_ChallengePurpose)
  : Lemma
    (classify_taken_challenge
       (Core_models.Option.Option_Some (issued_vec purpose)) purpose =
     ChallengeConsumption_Accepted) =
  issued_vec_slice purpose;
  issued_path_accepts_only_its_purpose purpose purpose

/// The adapter refuses an issued value presented as another purpose; the take
/// has already spent it.
let taken_issued_refuses_other
      (stored: t_ChallengePurpose)
      (expected: t_ChallengePurpose)
  : Lemma
    (requires (stored <> expected))
    (ensures
      (classify_taken_challenge
         (Core_models.Option.Option_Some (issued_vec stored)) expected =
       ChallengeConsumption_WrongPurpose)) =
  issued_vec_slice stored;
  issued_path_accepts_only_its_purpose stored expected

// ── Concrete non-vacuity witnesses over the actual store value ─────────────

/// The checked producer's ten-byte long raw value, carried by the actual store
/// value type.
let long_vec : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Alloc.Vec.Vec concrete_long
    (Core_models.Marker.PhantomData <:
      Core_models.Marker.t_PhantomData Alloc.Alloc.t_Global)

/// An empty stored value.
let empty_vec : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Alloc.Vec.Vec (FStar.Seq.empty #u8)
    (Core_models.Marker.PhantomData <:
      Core_models.Marker.t_PhantomData Alloc.Alloc.t_Global)

let long_vec_is_long ()
  : Lemma (Seq.length (vec_bytes long_vec) > 9) =
  concrete_long_is_unknown ()

let empty_vec_is_empty ()
  : Lemma (vec_is_login empty_vec = false /\
           vec_is_enroll empty_vec = false /\
           vec_is_web_token empty_vec = false) =
  ()

/// Login issuer: the actual adapter accepts the issued `login` value, and its
/// decision is the earlier checked raw login decision on the same slice.
let taken_login_issuer_accepted ()
  : Lemma (classify_taken_challenge
             (Core_models.Option.Option_Some (issued_vec ChallengePurpose_Login))
             ChallengePurpose_Login = ChallengeConsumption_Accepted) =
  taken_issued_accepts_its_purpose ChallengePurpose_Login

let taken_login_issuer_equals_raw_login ()
  : Lemma
    (classify_taken_challenge
       (Core_models.Option.Option_Some (issued_vec ChallengePurpose_Login))
       ChallengePurpose_Login =
     Vela_session_policy_login_raw_nonce.raw_login_decision
       (Alloc.Vec.impl_1__as_slice (issued_vec ChallengePurpose_Login))) =
  taken_some_login_equals_raw_login_decision
    (issued_vec ChallengePurpose_Login)

/// Enroll issuer presented to the login consumer: refused as wrong purpose.
let taken_enroll_issuer_refused_for_login ()
  : Lemma
    (classify_taken_challenge
       (Core_models.Option.Option_Some (issued_vec ChallengePurpose_Enroll))
       ChallengePurpose_Login = ChallengeConsumption_WrongPurpose) =
  taken_issued_refuses_other ChallengePurpose_Enroll ChallengePurpose_Login

/// Web-token issuer presented to the login consumer: refused as wrong purpose.
let taken_web_token_issuer_refused_for_login ()
  : Lemma
    (classify_taken_challenge
       (Core_models.Option.Option_Some (issued_vec ChallengePurpose_WebToken))
       ChallengePurpose_Login = ChallengeConsumption_WrongPurpose) =
  taken_issued_refuses_other ChallengePurpose_WebToken ChallengePurpose_Login

/// The long value keeps its actual length and is refused for login.
let taken_long_issuer_refused_for_login ()
  : Lemma
    (v ((stored_tag_from_bytes (Alloc.Vec.impl_1__as_slice long_vec)).f_len) > 9 /\
     classify_taken_challenge
       (Core_models.Option.Option_Some long_vec) ChallengePurpose_Login =
       ChallengeConsumption_WrongPurpose) =
  taken_some_retains_actual_length long_vec;
  long_vec_is_long ();
  taken_long_value_is_wrong_purpose long_vec ChallengePurpose_Login

/// The same long value agrees with the earlier checked raw long decision.
let taken_long_issuer_equals_raw_long ()
  : Lemma
    (classify_taken_challenge
       (Core_models.Option.Option_Some long_vec) ChallengePurpose_Login =
     Vela_session_policy_login_raw_nonce.raw_login_decision
       (Vela_session_policy_login_raw_nonce.raw_long_slice)) =
  taken_some_login_equals_raw_login_decision long_vec

/// An empty present value is refused for every purpose.
let taken_empty_is_wrong_purpose (expected: t_ChallengePurpose)
  : Lemma
    (classify_taken_challenge
       (Core_models.Option.Option_Some empty_vec) expected =
     ChallengeConsumption_WrongPurpose) =
  empty_vec_is_empty ();
  classify_taken_challenge_matches_literal
    (Core_models.Option.Option_Some empty_vec) expected
