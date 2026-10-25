module Vela_session_policy_login_raw_nonce

/// Raw-byte nonce bridge for the extracted `/auth/verify` login driver.
///
/// The existing composition module
/// (`Vela_session_policy_login_driver_composition`) proves the concurrent
/// at-most-one-admission theorem over an abstract stored purpose
/// (`StoredPurpose_Login` / `StoredPurpose_Other`).  This module removes that
/// abstraction at the nonce boundary: the stored nonce is the *actual* value
/// returned by the atomic take, modelled as `option (t_Slice u8)`, and every
/// take decision is computed by the *actual extracted* functions
///
///   stored_tag_from_bytes  (the production byte-to-tag conversion)
///   classify_consumption   (the production expected-purpose decision)
///
/// applied to `ChallengePurpose_Login`.  The raw world is projected to the
/// existing abstract world by deriving the abstract purpose from the same
/// actual decision.  The projection is proved to commute with every action and
/// with arbitrary action schedules; the headline bounds and the non-login
/// refusal theorem are then transported across the projection.
///
/// This is a pure model bridge.  It does **not** claim sled/store
/// refinement, handler execution, SQL/row semantics, verifier soundness,
/// PASETO/JTI security, TTL/crash behaviour, or that the real handler passes
/// exactly these bytes to these functions.  Those remain explicit interface
/// assumptions (see the evidence README).

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Login_driver
open Vela_session_policy_login_driver_lemmas
open Vela_session_policy_login_driver_composition
open Vela_session_policy_challenge_lemmas
open Vela_session_policy_tag_producer_lemmas

// ── The actual extracted take decision ─────────────────────────────────────
//
// These are the only two places where the raw bytes become a decision.  No
// transition rule is restated here: the driver transition is always the
// extracted `step` (through `raw_deliver`).

/// The actual production decision for a present raw value, for the login
/// consumer: convert the raw slice with `stored_tag_from_bytes`, then classify
/// it with `classify_consumption` for `ChallengePurpose_Login`.
let raw_login_decision (b: t_Slice u8) : t_ChallengeConsumption =
  classify_consumption
    (Core_models.Option.Option_Some (stored_tag_from_bytes b))
    ChallengePurpose_Login

/// `Missing` is impossible for a present raw value.  This is the only coercion
/// used on the take path; it is proved unreachable below.
let present_consumption (c: t_ChallengeConsumption) : t_ChallengeConsumption =
  match c <: t_ChallengeConsumption with
  | ChallengeConsumption_Missing -> ChallengeConsumption_WrongPurpose
  | _ -> c

/// Definitional unfolding of the extracted consumption decision for a present
/// tag.  This exposes the actual classifier result; it adds no decision rule.
let classify_consumption_some (tag: t_StoredTag) (expected: t_ChallengePurpose)
  : Lemma
    (classify_consumption (Core_models.Option.Option_Some tag) expected =
     (match classify_stored_tag tag <: t_TagClass with
      | TagClass_Recognized actual ->
          if same_purpose actual expected
          then ChallengeConsumption_Accepted
          else ChallengeConsumption_WrongPurpose
      | TagClass_Unknown -> ChallengeConsumption_WrongPurpose)) =
  ()

/// A present raw value never classifies as `Missing`.
let raw_decision_not_missing (b: t_Slice u8)
  : Lemma (raw_login_decision b <> ChallengeConsumption_Missing) =
  classify_consumption_some (stored_tag_from_bytes b) ChallengePurpose_Login

/// The coercion is the identity on every reachable present decision.
let present_consumption_eq (b: t_Slice u8)
  : Lemma (present_consumption (raw_login_decision b) = raw_login_decision b) =
  raw_decision_not_missing b;
  match raw_login_decision b <: t_ChallengeConsumption with
  | ChallengeConsumption_Accepted -> ()
  | ChallengeConsumption_WrongPurpose -> ()
  | ChallengeConsumption_Missing -> ()

let present_consumption_accepted (c: t_ChallengeConsumption)
  : Lemma
    (requires (c = ChallengeConsumption_Accepted))
    (ensures (present_consumption c = ChallengeConsumption_Accepted)) =
  ()

let present_consumption_not_accepted (c: t_ChallengeConsumption)
  : Lemma
    (requires (c <> ChallengeConsumption_Accepted))
    (ensures (present_consumption c = ChallengeConsumption_WrongPurpose)) =
  match c <: t_ChallengeConsumption with
  | ChallengeConsumption_Accepted -> ()
  | ChallengeConsumption_WrongPurpose -> ()
  | ChallengeConsumption_Missing -> ()

// ── Raw purpose, derived from the actual decision ─────────────────────────

/// The abstract purpose used by the existing composition, but derived here
/// from the actual raw bytes: `Some bytes` is a login purpose exactly when the
/// actual extracted classifier accepts it for `ChallengePurpose_Login`.
let raw_purpose (o: option (t_Slice u8)) : option t_StoredPurpose =
  match o with
  | None -> None
  | Some b ->
      Some (if raw_login_decision b = ChallengeConsumption_Accepted
            then StoredPurpose_Login
            else StoredPurpose_Other)

let raw_purpose_some_login (b: t_Slice u8)
  : Lemma
    (requires (raw_login_decision b = ChallengeConsumption_Accepted))
    (ensures (raw_purpose (Some b) = Some StoredPurpose_Login)) =
  ()

let raw_purpose_some_other (b: t_Slice u8)
  : Lemma
    (requires (raw_login_decision b <> ChallengeConsumption_Accepted))
    (ensures (raw_purpose (Some b) = Some StoredPurpose_Other)) =
  ()

let raw_purpose_eq_none (o: option (t_Slice u8))
  : Lemma (raw_purpose o = None <==> o = None) =
  match o with
  | None -> ()
  | Some b -> ()

/// Raw presence, the counterpart of `challenge_present` in the abstract world.
let raw_present (o: option (t_Slice u8)) : nat =
  match o with
  | None -> 0
  | Some _ -> 1

let raw_purpose_present (o: option (t_Slice u8))
  : Lemma (challenge_present_opt (raw_purpose o) = raw_present o) =
  match o with
  | None -> ()
  | Some b -> ()

/// The raw login predicate is exactly acceptance by the actual classifier.
let raw_is_login (o: option (t_Slice u8)) : bool =
  match o with
  | None -> false
  | Some b -> raw_login_decision b = ChallengeConsumption_Accepted

let raw_purpose_login_iff (o: option (t_Slice u8))
  : Lemma (raw_purpose o = Some StoredPurpose_Login <==> raw_is_login o) =
  match o with
  | None -> ()
  | Some b -> ()

/// The actual decision, connected to the checked producer's literal-byte
/// predicate.  This is the raw purpose connection used by every witness below.
let raw_login_decision_iff_slice (b: t_Slice u8)
  : Lemma
    (raw_login_decision b = ChallengeConsumption_Accepted <==>
     slice_is_login b) =
  consumption_accepts_iff_slice b ChallengePurpose_Login

/// The whole raw purpose is decided by the actual literal-byte predicate.
let raw_purpose_iff_slice (o: option (t_Slice u8))
  : Lemma
    (raw_purpose o = Some StoredPurpose_Login <==>
     (match o with
      | Some b -> slice_is_login b
      | None -> False)) =
  raw_purpose_login_iff o;
  match o with
  | None -> ()
  | Some b ->
      raw_login_decision_iff_slice b

// ── Raw world and the actual extracted driver ─────────────────────────────

/// The raw nonce is the value the atomic take returns: absent, or the exact
/// stored bytes.  The remaining fields mirror the abstract composition.
noeq type raw_world = {
  raw_nonce: option (t_Slice u8);
  raw_admitted: bool;
  raw_responses: nat;
  raw_tokens: nat;
  raw_reqs: list t_LoginDriver;
}

/// Projection to the existing abstract composition world.  The abstract
/// purpose is not supplied by the caller: it is computed from the actual
/// classifier applied to the raw bytes.
let project (w: raw_world) : world =
  { challenge = raw_purpose w.raw_nonce;
    nonce_admitted = w.raw_admitted;
    responses = w.raw_responses;
    tokens = w.raw_tokens;
    reqs = w.raw_reqs }

let challenge_present_project (w: raw_world)
  : Lemma (challenge_present (project w) = raw_present w.raw_nonce) =
  raw_purpose_present w.raw_nonce

/// Presence zero means the abstract nonce is absent.  This is the inverse of
/// `challenge_present_opt` used to recover the raw `None` from the projected
/// invariant.
let challenge_present_none (aw: world)
  : Lemma (challenge_present aw = 0 <==> aw.challenge = None) =
  match aw.challenge with
  | None -> ()
  | Some _ -> ()

/// Deliver one event to request `i`, perform the effect the actual extracted
/// driver returns, and record the post-effect raw nonce state.  This mirrors
/// the abstract composition's `deliver` but keeps the raw stored value; it
/// calls the extracted `step`, not a restated transition relation.
let raw_deliver (w: raw_world) (i: nat{i < FStar.List.Tot.length w.raw_reqs})
    (e: t_LoginEvent) (nonce_mid: option (t_Slice u8))
    (admitted_mid: bool)
  : raw_world =
  let d = FStar.List.Tot.index w.raw_reqs i in
  if login_state_is_sound d then
    let t = step d e in
    { raw_nonce = nonce_mid;
      raw_admitted = admitted_mid;
      raw_responses = w.raw_responses + respond_delta t.f_effect;
      raw_tokens = w.raw_tokens + issued_delta d e;
      raw_reqs = update w.raw_reqs i t.f_driver }
  else w

/// Projection commutes with delivery: the abstract `deliver` uses the same
/// extracted `step` and the projected raw nonce.
let project_raw_deliver (w: raw_world)
    (i: nat{i < FStar.List.Tot.length w.raw_reqs})
    (e: t_LoginEvent) (nonce_mid: option (t_Slice u8))
    (admitted_mid: bool)
  : Lemma
    (project (raw_deliver w i e nonce_mid admitted_mid) ==
     deliver (project w) i e (raw_purpose nonce_mid) admitted_mid) =
  ()

/// The raw world step.  The only action that inspects the nonce is `Take`,
/// and it uses the actual extracted conversion/classification.  Every request
/// transition still goes through `raw_deliver` / the extracted `step`.
let raw_step (w: raw_world) (a: action) : raw_world =
  match a with
  | Spawn -> { w with raw_reqs = (begin_login ()).f_driver :: w.raw_reqs }
  | Take i ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_challenge (FStar.List.Tot.index w.raw_reqs i)
      then begin
        match w.raw_nonce with
        | None ->
            raw_deliver w i
              (LoginEvent_ChallengeObserved
                (ChallengeObservation_Observed ChallengeConsumption_Missing))
              w.raw_nonce w.raw_admitted
        | Some b ->
            let c = raw_login_decision b in
            let ev =
              LoginEvent_ChallengeObserved
                (ChallengeObservation_Observed (present_consumption c))
            in
            if c = ChallengeConsumption_Accepted
            then raw_deliver w i ev None true
            else raw_deliver w i ev None w.raw_admitted
      end
      else w
  | TakeFailed i ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_challenge (FStar.List.Tot.index w.raw_reqs i)
      then
        raw_deliver w i
          (LoginEvent_ChallengeObserved ChallengeObservation_StorageFailed)
          w.raw_nonce w.raw_admitted
      else w
  | Device i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_device (FStar.List.Tot.index w.raw_reqs i)
      then raw_deliver w i (LoginEvent_DeviceObserved obs)
             w.raw_nonce w.raw_admitted
      else w
  | Verify i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_verify (FStar.List.Tot.index w.raw_reqs i)
      then raw_deliver w i (LoginEvent_VerifierObserved obs)
             w.raw_nonce w.raw_admitted
      else w
  | Record i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_record_failure (FStar.List.Tot.index w.raw_reqs i)
      then raw_deliver w i (LoginEvent_FailureRecorded obs)
             w.raw_nonce w.raw_admitted
      else w
  | Reset i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_reset (FStar.List.Tot.index w.raw_reqs i)
      then raw_deliver w i (LoginEvent_BackoffResetObserved obs)
             w.raw_nonce w.raw_admitted
      else w
  | Issue i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_issue (FStar.List.Tot.index w.raw_reqs i)
      then raw_deliver w i (LoginEvent_TokenIssued obs)
             w.raw_nonce w.raw_admitted
      else w
  | Track i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_track (FStar.List.Tot.index w.raw_reqs i)
      then raw_deliver w i (LoginEvent_TokenTracked obs)
             w.raw_nonce w.raw_admitted
      else w

let rec raw_run (w: raw_world) (schedule: list action)
  : Tot raw_world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> raw_run (raw_step w a) rest

// ── Projection commutes with every action and every schedule ───────────────

/// Per-action commutation.  The `Take` case is the bridge between the actual
/// raw classification and the abstract stored purpose.
let project_raw_step (w: raw_world) (a: action)
  : Lemma (project (raw_step w a) == world_step (project w) a) =
  match a with
  | Spawn -> ()
  | Take i ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_challenge (FStar.List.Tot.index w.raw_reqs i)
      then begin
        match w.raw_nonce with
        | None ->
            project_raw_deliver w i
              (LoginEvent_ChallengeObserved
                (ChallengeObservation_Observed ChallengeConsumption_Missing))
              w.raw_nonce w.raw_admitted
        | Some b ->
            let c = raw_login_decision b in
            let ev =
              LoginEvent_ChallengeObserved
                (ChallengeObservation_Observed (present_consumption c))
            in
            if c = ChallengeConsumption_Accepted
            then begin
              raw_purpose_some_login b;
              present_consumption_accepted c;
              project_raw_deliver w i ev None true
            end
            else begin
              raw_purpose_some_other b;
              present_consumption_not_accepted c;
              project_raw_deliver w i ev None w.raw_admitted
            end
      end
      else ()
  | TakeFailed i ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_challenge (FStar.List.Tot.index w.raw_reqs i)
      then
        project_raw_deliver w i
          (LoginEvent_ChallengeObserved ChallengeObservation_StorageFailed)
          w.raw_nonce w.raw_admitted
      else ()
  | Device i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_device (FStar.List.Tot.index w.raw_reqs i)
      then project_raw_deliver w i (LoginEvent_DeviceObserved obs)
             w.raw_nonce w.raw_admitted
      else ()
  | Verify i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_verify (FStar.List.Tot.index w.raw_reqs i)
      then project_raw_deliver w i (LoginEvent_VerifierObserved obs)
             w.raw_nonce w.raw_admitted
      else ()
  | Record i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_record_failure (FStar.List.Tot.index w.raw_reqs i)
      then project_raw_deliver w i (LoginEvent_FailureRecorded obs)
             w.raw_nonce w.raw_admitted
      else ()
  | Reset i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_reset (FStar.List.Tot.index w.raw_reqs i)
      then project_raw_deliver w i (LoginEvent_BackoffResetObserved obs)
             w.raw_nonce w.raw_admitted
      else ()
  | Issue i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_issue (FStar.List.Tot.index w.raw_reqs i)
      then project_raw_deliver w i (LoginEvent_TokenIssued obs)
             w.raw_nonce w.raw_admitted
      else ()
  | Track i obs ->
      if i < FStar.List.Tot.length w.raw_reqs &&
         is_track (FStar.List.Tot.index w.raw_reqs i)
      then project_raw_deliver w i (LoginEvent_TokenTracked obs)
             w.raw_nonce w.raw_admitted
      else ()

/// Arbitrary schedules: projection commutes with the whole run.
let rec project_raw_run (w: raw_world) (schedule: list action)
  : Lemma (ensures (project (raw_run w schedule) ==
                    run_world (project w) schedule))
          (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      project_raw_step w a;
      project_raw_run (raw_step w a) rest

let raw_initial (nonce0: option (t_Slice u8)) : raw_world =
  { raw_nonce = nonce0;
    raw_admitted = false;
    raw_responses = 0;
    raw_tokens = 0;
    raw_reqs = [] }

let project_raw_initial (nonce0: option (t_Slice u8))
  : Lemma
    (project (raw_initial nonce0) ==
     initial (raw_purpose nonce0)) =
  ()

// ── Headline raw bounds ────────────────────────────────────────────────────

/// Whatever the initial raw nonce and whatever the schedule, one nonce admits
/// at most one request, produces at most one `Respond` effect, and performs at
/// most one successful token-issue observation.  All counts are raw-world
/// counts transported from the existing composition through the projection.
let raw_one_nonce_at_most_one_admission
      (nonce0: option (t_Slice u8))
      (schedule: list action)
  : Lemma (
      let w = raw_run (raw_initial nonce0) schedule in
      w.raw_responses <= 1 /\
      w.raw_tokens <= 1 /\
      accepted_count w.raw_reqs <= 1 /\
      responded_count w.raw_reqs <= 1 /\
      issued_count w.raw_reqs <= 1 /\
      b2n w.raw_admitted + raw_present w.raw_nonce <= 1) =
  project_raw_initial nonce0;
  project_raw_run (raw_initial nonce0) schedule;
  let w = raw_run (raw_initial nonce0) schedule in
  let pw = project w in
  assert (pw == run_world (initial (raw_purpose nonce0)) schedule);
  one_nonce_at_most_one_admission (raw_purpose nonce0) schedule;
  challenge_present_project w

/// The three observations named separately, for readers that want one claim
/// at a time.  Each is a direct corollary of the combined raw bound.
let raw_at_most_one_accepted
      (nonce0: option (t_Slice u8))
      (schedule: list action)
  : Lemma (
      let w = raw_run (raw_initial nonce0) schedule in
      accepted_count w.raw_reqs <= 1) =
  raw_one_nonce_at_most_one_admission nonce0 schedule

let raw_at_most_one_respond
      (nonce0: option (t_Slice u8))
      (schedule: list action)
  : Lemma (
      let w = raw_run (raw_initial nonce0) schedule in
      w.raw_responses <= 1) =
  raw_one_nonce_at_most_one_admission nonce0 schedule

let raw_at_most_one_successful_issue
      (nonce0: option (t_Slice u8))
      (schedule: list action)
  : Lemma (
      let w = raw_run (raw_initial nonce0) schedule in
      w.raw_tokens <= 1) =
  raw_one_nonce_at_most_one_admission nonce0 schedule

/// If the raw value is not accepted as a login value, no schedule can admit a
/// request, respond, or issue a token.  The premise is stated directly over
/// the actual raw decision, not over the abstract purpose.
let raw_purpose_not_login_of_raw_is_login_false
      (o: option (t_Slice u8))
  : Lemma
    (requires (raw_is_login o = false))
    (ensures (
      match raw_purpose o with
      | Some StoredPurpose_Login -> False
      | _ -> True)) =
  match o with
  | None -> ()
  | Some b -> ()

let raw_non_login_never_admits
      (nonce0: option (t_Slice u8))
      (schedule: list action)
  : Lemma
    (requires (raw_is_login nonce0 = false))
    (ensures (
      let w = raw_run (raw_initial nonce0) schedule in
      not w.raw_admitted /\
      accepted_count w.raw_reqs = 0 /\
      w.raw_responses = 0 /\
      w.raw_tokens = 0)) =
  raw_purpose_not_login_of_raw_is_login_false nonce0;
  project_raw_initial nonce0;
  project_raw_run (raw_initial nonce0) schedule;
  non_login_nonce_never_admits (raw_purpose nonce0) schedule;
  let w = raw_run (raw_initial nonce0) schedule in
  assert (project w == run_world (initial (raw_purpose nonce0)) schedule)

/// Same refusal with the abstract-purpose premise, for callers that already
/// reason at the projected level.
let raw_non_login_purpose_never_admits
      (nonce0: option (t_Slice u8))
      (schedule: list action)
  : Lemma
    (requires (
      match raw_purpose nonce0 with
      | Some StoredPurpose_Login -> False
      | _ -> True))
    (ensures (
      let w = raw_run (raw_initial nonce0) schedule in
      not w.raw_admitted /\
      accepted_count w.raw_reqs = 0 /\
      w.raw_responses = 0 /\
      w.raw_tokens = 0)) =
  project_raw_initial nonce0;
  project_raw_run (raw_initial nonce0) schedule;
  non_login_nonce_never_admits (raw_purpose nonce0) schedule;
  let w = raw_run (raw_initial nonce0) schedule in
  assert (project w == run_world (initial (raw_purpose nonce0)) schedule)

// ── Concrete raw values and classification witnesses ──────────────────────

/// The checked producer's concrete raw `login` slice.
let raw_login_slice : t_Slice u8 = concrete_login
/// The actual issued raw `enroll` slice (wrong purpose for a login take).
let raw_enroll_slice : t_Slice u8 = purpose_tag_bytes ChallengePurpose_Enroll
/// The checked producer's ten-byte long value (`login!!!!!`).
let raw_long_slice : t_Slice u8 = concrete_long

let accepted_of_recognized_login (tag: t_StoredTag)
  : Lemma
    (requires (classify_stored_tag tag =
               TagClass_Recognized ChallengePurpose_Login))
    (ensures (classify_consumption
                (Core_models.Option.Option_Some tag)
                ChallengePurpose_Login =
              ChallengeConsumption_Accepted)) =
  ()

let wrong_of_unknown (tag: t_StoredTag)
  : Lemma
    (requires (classify_stored_tag tag = TagClass_Unknown))
    (ensures (classify_consumption
                (Core_models.Option.Option_Some tag)
                ChallengePurpose_Login =
              ChallengeConsumption_WrongPurpose)) =
  ()

let wrong_of_recognized_other (tag: t_StoredTag) (p: t_ChallengePurpose)
  : Lemma
    (requires (classify_stored_tag tag = TagClass_Recognized p /\
               p <> ChallengePurpose_Login))
    (ensures (classify_consumption
                (Core_models.Option.Option_Some tag)
                ChallengePurpose_Login =
              ChallengeConsumption_WrongPurpose)) =
  ()

let raw_login_slice_is_literal ()
  : Lemma (slice_is_login raw_login_slice) =
  concrete_login_is_literal ()

/// The actual extracted classifier accepts the concrete raw `login` bytes.
let raw_login_slice_decision ()
  : Lemma (raw_login_decision raw_login_slice =
           ChallengeConsumption_Accepted) =
  concrete_login_classified ();
  accepted_of_recognized_login (stored_tag_from_bytes raw_login_slice)

/// The actual extracted classifier refuses the issued raw `enroll` bytes for
/// a login take.
let raw_enroll_slice_decision ()
  : Lemma (raw_login_decision raw_enroll_slice =
           ChallengeConsumption_WrongPurpose) =
  issued_classified ChallengePurpose_Enroll;
  wrong_of_recognized_other
    (stored_tag_from_bytes raw_enroll_slice)
    ChallengePurpose_Enroll

/// The actual extracted classifier refuses the long raw value: the retained
/// length prevents truncation/aliasing.
let raw_long_slice_decision ()
  : Lemma (raw_login_decision raw_long_slice =
           ChallengeConsumption_WrongPurpose) =
  concrete_long_is_unknown ();
  wrong_of_unknown (stored_tag_from_bytes raw_long_slice)

// ── Reachability witnesses over the raw world ─────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let raw_run_cons (w: raw_world) (a: action) (rest: list action)
  : Lemma (raw_run w (a :: rest) == raw_run (raw_step w a) rest) = ()

let raw_run_nil (w: raw_world) : Lemma (raw_run w [] == w) = ()

/// Complete successful login from the concrete raw `login` bytes.  The take
/// decision is the actual extracted classification; the effect/flag counts are
/// transported through the projection from the abstract composition witness.
let raw_success_is_reachable ()
  : Lemma (
      let w = raw_run (raw_initial (Some raw_login_slice)) success_schedule in
      w.raw_nonce = None /\ w.raw_admitted /\
      w.raw_responses = 1 /\ w.raw_tokens = 1 /\
      accepted_count w.raw_reqs = 1 /\
      responded_count w.raw_reqs = 1 /\
      issued_count w.raw_reqs = 1) =
  raw_login_slice_decision ();
  raw_purpose_some_login raw_login_slice;
  project_raw_initial (Some raw_login_slice);
  project_raw_run (raw_initial (Some raw_login_slice)) success_schedule;
  let w = raw_run (raw_initial (Some raw_login_slice)) success_schedule in
  let pw = project w in
  assert (pw == run_world (initial login_nonce) success_schedule);
  success_is_reachable ();
  raw_purpose_eq_none w.raw_nonce

/// Wrong purpose: the concrete raw `enroll` bytes are spent by the take and
/// the login request is refused; no response or token follows.
let raw_wrong_purpose_spends_nonce ()
  : Lemma (
      let w = raw_run (raw_initial (Some raw_enroll_slice))
                      wrong_purpose_schedule in
      w.raw_nonce = None /\ not w.raw_admitted /\
      w.raw_responses = 0 /\ w.raw_tokens = 0 /\
      accepted_count w.raw_reqs = 0) =
  raw_enroll_slice_decision ();
  raw_purpose_some_other raw_enroll_slice;
  project_raw_initial (Some raw_enroll_slice);
  project_raw_run (raw_initial (Some raw_enroll_slice))
    wrong_purpose_schedule;
  let w = raw_run (raw_initial (Some raw_enroll_slice))
                  wrong_purpose_schedule in
  let pw = project w in
  assert (pw == run_world (initial other_nonce) wrong_purpose_schedule);
  wrong_purpose_spends_nonce ();
  raw_purpose_eq_none w.raw_nonce

/// Unknown/long raw bytes are refused and spent, and cannot alias the short
/// `login` literal because the producer retained the real length.
let raw_long_unknown_is_refused ()
  : Lemma (
      let w = raw_run (raw_initial (Some raw_long_slice))
                      wrong_purpose_schedule in
      w.raw_nonce = None /\ not w.raw_admitted /\
      w.raw_responses = 0 /\ w.raw_tokens = 0 /\
      accepted_count w.raw_reqs = 0 /\
      v ((stored_tag_from_bytes raw_long_slice).f_len) = 10 /\
      classify_stored_tag (stored_tag_from_bytes raw_long_slice) =
        TagClass_Unknown) =
  raw_long_slice_decision ();
  raw_purpose_some_other raw_long_slice;
  project_raw_initial (Some raw_long_slice);
  project_raw_run (raw_initial (Some raw_long_slice))
    wrong_purpose_schedule;
  let w = raw_run (raw_initial (Some raw_long_slice))
                  wrong_purpose_schedule in
  let pw = project w in
  assert (pw == run_world (initial other_nonce) wrong_purpose_schedule);
  wrong_purpose_spends_nonce ();
  concrete_long_is_unknown ();
  raw_purpose_eq_none w.raw_nonce

/// Absent raw nonce: the take reports `Missing`; no admission or effect.
let raw_missing_nonce_is_terminal ()
  : Lemma (
      let w = raw_run (raw_initial None) missing_schedule in
      w.raw_nonce = None /\ not w.raw_admitted /\
      w.raw_responses = 0 /\ w.raw_tokens = 0 /\
      accepted_count w.raw_reqs = 0) =
  raw_non_login_never_admits None missing_schedule

/// Two requests contend for one concrete raw `login` nonce: the first take
/// admits and removes it; the second sees `Missing` and fails.  Only one
/// request is accepted, one response occurs and one token is issued.
let raw_two_request_contention ()
  : Lemma (
      let w = raw_run (raw_initial (Some raw_login_slice)) race_schedule in
      w.raw_nonce = None /\ w.raw_admitted /\
      w.raw_responses = 1 /\ w.raw_tokens = 1 /\
      accepted_count w.raw_reqs = 1 /\
      responded_count w.raw_reqs = 1 /\
      issued_count w.raw_reqs = 1) =
  raw_login_slice_decision ();
  raw_purpose_some_login raw_login_slice;
  project_raw_initial (Some raw_login_slice);
  project_raw_run (raw_initial (Some raw_login_slice)) race_schedule;
  let w = raw_run (raw_initial (Some raw_login_slice)) race_schedule in
  let pw = project w in
  assert (pw == run_world (initial login_nonce) race_schedule);
  two_request_contention ();
  initial_inv login_nonce;
  run_world_inv (initial login_nonce) race_schedule;
  assert (inv pw);
  assert (accepted_count pw.reqs <= b2n pw.nonce_admitted);
  assert (b2n pw.nonce_admitted + challenge_present pw <= 1);
  assert (pw.tokens = issued_count pw.reqs);
  challenge_present_none pw;
  raw_purpose_eq_none w.raw_nonce

/// A failed take does not spend the raw nonce: a later request can still take
/// the same concrete raw `login` value.
let raw_take_failure_preserves_nonce ()
  : Lemma (
      let w = raw_run (raw_initial (Some raw_login_slice))
                      take_failure_schedule in
      w.raw_nonce = None /\ w.raw_admitted /\
      w.raw_responses = 0 /\ w.raw_tokens = 0 /\
      accepted_count w.raw_reqs = 1) =
  raw_login_slice_decision ();
  raw_purpose_some_login raw_login_slice;
  project_raw_initial (Some raw_login_slice);
  project_raw_run (raw_initial (Some raw_login_slice))
    take_failure_schedule;
  let w = raw_run (raw_initial (Some raw_login_slice))
                  take_failure_schedule in
  let pw = project w in
  assert (pw == run_world (initial login_nonce) take_failure_schedule);
  take_failure_preserves_nonce ();
  raw_purpose_eq_none w.raw_nonce

#pop-options
