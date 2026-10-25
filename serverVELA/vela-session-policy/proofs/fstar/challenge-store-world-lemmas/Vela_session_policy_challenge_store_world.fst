module Vela_session_policy_challenge_store_world

/// Joins the login nonce theorems to the value the real store returns.
///
/// `Vela_session_policy_login_raw_nonce` proves the concurrent login bounds
/// over a raw world whose nonce is an F* `option (t_Slice u8)`.
/// `Vela_session_policy_challenge_take_adapter` proves the extracted
/// `classify_taken_challenge` over the store's actual result type,
/// `Option<Vec<u8>>`. This module puts the two together: a store world keeps
/// the nonce as that actual result type, its `Take` step calls the extracted
/// adapter exactly as `take_challenge` does after `get_del`, and the value is
/// removed whatever the decision. The conversion to the raw world commutes
/// with every action and every schedule, so the raw bounds hold for the store
/// world directly.
///
/// Still assumed: `get_del` is linearizable and returns the stored value, the
/// handler delivers that value to this decision and performs the driver's
/// effects, and the imported hax `Option`/`Vec` models. No store, SQL or
/// handler refinement is claimed.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Login_driver
open Vela_session_policy_login_driver_lemmas
open Vela_session_policy_login_driver_composition
open Vela_session_policy_login_raw_nonce
open Vela_session_policy_challenge_take_adapter

/// What `Store::get_del` returns, in the extracted types.
type store_value = Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)

/// The raw world's view of a store value: the same bytes, as a slice.
let to_raw_value (v: store_value) : option (t_Slice u8) =
  match v with
  | Core_models.Option.Option_None -> None
  | Core_models.Option.Option_Some x -> Some (Alloc.Vec.impl_1__as_slice x)

// ── One take: the real adapter and the raw model see the same event ────────

/// The event the handler delivers after a take, from the real adapter.
let adapter_event (v: store_value) : t_LoginEvent =
  LoginEvent_ChallengeObserved
    (ChallengeObservation_Observed (classify_taken_challenge v ChallengePurpose_Login))

/// The event the raw world delivers for the same bytes.
let raw_take_event (o: option (t_Slice u8)) : t_LoginEvent =
  match o with
  | None ->
      LoginEvent_ChallengeObserved
        (ChallengeObservation_Observed ChallengeConsumption_Missing)
  | Some b ->
      LoginEvent_ChallengeObserved
        (ChallengeObservation_Observed (present_consumption (raw_login_decision b)))

let take_event_agrees (v: store_value)
  : Lemma (adapter_event v == raw_take_event (to_raw_value v)) =
  match v with
  | Core_models.Option.Option_None -> classify_taken_challenge_none ChallengePurpose_Login
  | Core_models.Option.Option_Some x ->
      taken_some_login_equals_raw_login_decision x;
      present_consumption_eq (Alloc.Vec.impl_1__as_slice x)

/// The real adapter accepts exactly when the raw world admits.
let take_accepts_agree (v: store_value)
  : Lemma
    ((classify_taken_challenge v ChallengePurpose_Login = ChallengeConsumption_Accepted) =
     (match to_raw_value v with
      | None -> false
      | Some b -> raw_login_decision b = ChallengeConsumption_Accepted)) =
  match v with
  | Core_models.Option.Option_None -> classify_taken_challenge_none ChallengePurpose_Login
  | Core_models.Option.Option_Some x -> taken_some_login_equals_raw_login_decision x

// ── The store world ────────────────────────────────────────────────────────

noeq type store_world = {
  st_nonce: store_value;
  st_admitted: bool;
  st_responses: nat;
  st_tokens: nat;
  st_reqs: list t_LoginDriver;
}

let to_raw (w: store_world) : raw_world =
  { raw_nonce = to_raw_value w.st_nonce;
    raw_admitted = w.st_admitted;
    raw_responses = w.st_responses;
    raw_tokens = w.st_tokens;
    raw_reqs = w.st_reqs }

/// Rebuild a store world from a raw world, keeping the given store value.
let with_store_value (r: raw_world) (v: store_value) : store_world =
  { st_nonce = v;
    st_admitted = r.raw_admitted;
    st_responses = r.raw_responses;
    st_tokens = r.raw_tokens;
    st_reqs = r.raw_reqs }

let is_take (a: action) : bool =
  match a with
  | Take _ -> true
  | _ -> false

/// The store step. `Take` calls the real adapter on the real result type and
/// empties the slot whatever the decision (`get_del`); the request then moves
/// through the extracted driver via `raw_deliver`. Every other action never
/// reads the nonce, so it is the raw model's step with the store value kept.
let store_step (w: store_world) (a: action) : store_world =
  match a with
  | Take i ->
      if i < FStar.List.Tot.length w.st_reqs &&
         is_challenge (FStar.List.Tot.index w.st_reqs i)
      then
        let c = classify_taken_challenge w.st_nonce ChallengePurpose_Login in
        let admitted' =
          if c = ChallengeConsumption_Accepted then true else w.st_admitted in
        // `raw_deliver` leaves the world untouched for an unsound request
        // (never reachable from the initial world); keep the value then too.
        let left =
          if login_state_is_sound (FStar.List.Tot.index w.st_reqs i)
          then Core_models.Option.Option_None
          else w.st_nonce in
        with_store_value
          (raw_deliver (to_raw w) i (adapter_event w.st_nonce) None admitted')
          left
      else w
  | _ -> with_store_value (raw_step (to_raw w) a) w.st_nonce

let rec store_run (w: store_world) (schedule: list action)
  : Tot store_world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> store_run (store_step w a) rest

// ── Commutation ────────────────────────────────────────────────────────────

/// Actions other than `Take` leave the raw nonce where it was.
let raw_step_keeps_nonce (w: raw_world) (a: action)
  : Lemma (requires (not (is_take a)))
          (ensures ((raw_step w a).raw_nonce == w.raw_nonce)) =
  match a with
  | Spawn -> ()
  | Take _ -> ()
  | TakeFailed _ -> ()
  | Device _ _ -> ()
  | Verify _ _ -> ()
  | Record _ _ -> ()
  | Reset _ _ -> ()
  | Issue _ _ -> ()
  | Track _ _ -> ()

let to_raw_with_store_value (r: raw_world) (v: store_value)
  : Lemma (requires (r.raw_nonce == to_raw_value v))
          (ensures (to_raw (with_store_value r v) == r)) =
  ()

/// One step: converting then stepping equals stepping then converting.
let to_raw_store_step (w: store_world) (a: action)
  : Lemma (to_raw (store_step w a) == raw_step (to_raw w) a) =
  match a with
  | Take i ->
      if i < FStar.List.Tot.length w.st_reqs &&
         is_challenge (FStar.List.Tot.index w.st_reqs i)
      then begin
        take_event_agrees w.st_nonce;
        take_accepts_agree w.st_nonce;
        let c = classify_taken_challenge w.st_nonce ChallengePurpose_Login in
        let admitted' =
          if c = ChallengeConsumption_Accepted then true else w.st_admitted in
        let left =
          if login_state_is_sound (FStar.List.Tot.index w.st_reqs i)
          then Core_models.Option.Option_None
          else w.st_nonce in
        let r = raw_deliver (to_raw w) i (adapter_event w.st_nonce) None admitted' in
        assert (r.raw_nonce == to_raw_value left);
        to_raw_with_store_value r left;
        match w.st_nonce with
        | Core_models.Option.Option_None -> ()
        | Core_models.Option.Option_Some x ->
            present_consumption_eq (Alloc.Vec.impl_1__as_slice x)
      end
  | _ ->
      raw_step_keeps_nonce (to_raw w) a;
      to_raw_with_store_value (raw_step (to_raw w) a) w.st_nonce

/// Every schedule: the store world runs exactly as the raw world.
let rec to_raw_store_run (w: store_world) (schedule: list action)
  : Lemma (ensures (to_raw (store_run w schedule) == raw_run (to_raw w) schedule))
          (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      to_raw_store_step w a;
      to_raw_store_run (store_step w a) rest

let store_initial (v: store_value) : store_world =
  { st_nonce = v;
    st_admitted = false;
    st_responses = 0;
    st_tokens = 0;
    st_reqs = [] }

let store_present (v: store_value) : nat =
  match v with
  | Core_models.Option.Option_None -> 0
  | Core_models.Option.Option_Some _ -> 1

let raw_present_to_raw (v: store_value)
  : Lemma (raw_present (to_raw_value v) = store_present v) =
  match v with
  | Core_models.Option.Option_None -> ()
  | Core_models.Option.Option_Some _ -> ()

// ── Headline: the login bounds over the store's actual result type ─────────

/// For any value the store holds for one challenge key and any interleaving
/// of any number of login requests: at most one request is admitted, at most
/// one response is produced and at most one token issuance succeeds, with
/// every take decided by the extracted adapter on the real result type.
let store_one_nonce_at_most_one_admission (v: store_value) (schedule: list action)
  : Lemma (
      let w = store_run (store_initial v) schedule in
      w.st_responses <= 1 /\
      w.st_tokens <= 1 /\
      accepted_count w.st_reqs <= 1 /\
      responded_count w.st_reqs <= 1 /\
      issued_count w.st_reqs <= 1 /\
      b2n w.st_admitted + store_present w.st_nonce <= 1) =
  let w0 = store_initial v in
  assert (to_raw w0 == raw_initial (to_raw_value v));
  to_raw_store_run w0 schedule;
  raw_one_nonce_at_most_one_admission (to_raw_value v) schedule;
  raw_present_to_raw (store_run w0 schedule).st_nonce

// ── Non-vacuity ────────────────────────────────────────────────────────────

let login_store_value : store_value =
  Core_models.Option.Option_Some (issued_vec ChallengePurpose_Login)

/// The issued login value is accepted by the take step and moves the request
/// past the challenge stage.
let login_value_is_admitted ()
  : Lemma (
      let w = store_run (store_initial login_store_value) [Spawn; Take 0] in
      w.st_admitted = true /\
      store_present w.st_nonce = 0) =
  taken_issued_accepts_its_purpose ChallengePurpose_Login;
  let w0 = store_initial login_store_value in
  let w1 = store_step w0 Spawn in
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  assert (is_challenge (begin_login ()).f_driver);
  assert (store_run w0 [Spawn; Take 0] == store_step (store_step w0 Spawn) (Take 0))

/// An enrollment value is spent by the take and admits nothing.
let enroll_value_is_spent_not_admitted ()
  : Lemma (
      let w = store_run
        (store_initial (Core_models.Option.Option_Some (issued_vec ChallengePurpose_Enroll)))
        [Spawn; Take 0] in
      w.st_admitted = false /\
      store_present w.st_nonce = 0) =
  taken_issued_refuses_other ChallengePurpose_Enroll ChallengePurpose_Login;
  let w0 = store_initial (Core_models.Option.Option_Some (issued_vec ChallengePurpose_Enroll)) in
  let w1 = store_step w0 Spawn in
  begin_sound ();
  trace_sound_matches_rust (begin_login ()).f_driver;
  assert (is_challenge (begin_login ()).f_driver);
  assert (store_run w0 [Spawn; Take 0] == store_step (store_step w0 Spawn) (Take 0))
