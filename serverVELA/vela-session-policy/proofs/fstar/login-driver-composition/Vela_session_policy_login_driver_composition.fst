module Vela_session_policy_login_driver_composition

/// Concurrent composition of the *extracted* `/auth/verify` login driver.
///
/// One single-use challenge (one nonce key) is shared by any number of
/// requests, each running its own `Vela_session_policy.Login_driver.step`. A
/// schedule is an arbitrary list of actions: start a request, perform the
/// atomic challenge take, or deliver the next effect observation to any
/// request. The world abstracts the handler's effects:
///
/// - the atomic challenge `get_del`: a take sees the nonce iff it is still
///   present, removes it in the same step, and reports the classification of
///   the stored purpose tag (`Accepted` only for a stored login tag,
///   `WrongPurpose` for any other stored tag, `Missing` when absent);
/// - a failed `get_del` (`TakeFailed`) leaves the nonce in place;
/// - the device query, the hybrid verifier, the failure side effects, the
///   backoff reset, PASETO issuance and JTI tracking, whose observations the
///   schedule chooses subject to the extracted driver's stage guards.
///
/// Theorem: for every schedule, at most one request is admitted by the nonce,
/// at most one `Respond` effect occurs, and at most one token is issued. When
/// the stored challenge is not a login challenge, no request is admitted and
/// no response/token is produced.
///
/// The composition calls the actual extracted `step`; it does not restate the
/// transition relation. Assumptions (not proved here): `get_del` is
/// linearizable, the stored tag classifier is the actual `challenge` module's
/// decision, the nonce key identifies one challenge, the handler performs
/// exactly the effect the driver returns, and an observation reaches the
/// driver in the same step as its effect. Sled atomicity, SQL/row semantics,
/// verifier soundness, PASETO security, JTI/crash behavior and revocation
/// linearization remain outside this module. In particular the purpose bit is
/// an interface parameter of the take, not a proved property of sled bytes.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Login_driver
open Vela_session_policy_login_driver_lemmas

let b2n (b: bool) : nat = if b then 1 else 0

/// The only purpose information the take interface exposes: the exact stored
/// tag is a login tag, or it is not. The composition does not decode bytes;
/// that refinement is the challenge lemma module's job.
type t_StoredPurpose =
  | StoredPurpose_Login : t_StoredPurpose
  | StoredPurpose_Other : t_StoredPurpose

let challenge_present_opt (c: option t_StoredPurpose) : nat =
  match c with
  | None -> 0
  | Some _ -> 1

let respond_delta (e: t_LoginEffect) : nat =
  match e <: t_LoginEffect with
  | LoginEffect_Respond -> 1
  | _ -> 0

/// A successful issuance observation is the step that actually flips the
/// token-issued flag; the `IssueToken` effect is only the request to issue.
let issued_delta (d: t_LoginDriver) (e: t_LoginEvent) : nat =
  if (match e <: t_LoginEvent with
      | LoginEvent_TokenIssued TokenIssueObservation_Issued -> true
      | _ -> false) &&
     is_issue d
  then 1
  else 0

// ── Request lists ──────────────────────────────────────────────────────────

let rec update (l: list t_LoginDriver) (i: nat) (x: t_LoginDriver)
  : Tot (list t_LoginDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec all_sound (l: list t_LoginDriver) : bool =
  match l with
  | [] -> true
  | d :: r -> trace_sound d && all_sound r

let all_sound_cons (d: t_LoginDriver) (l: list t_LoginDriver)
  : Lemma (all_sound (d :: l) = (trace_sound d && all_sound l)) = ()

let rec accepted_count (l: list t_LoginDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> b2n d.f_challenge_accepted + accepted_count r

let accepted_count_cons (d: t_LoginDriver) (l: list t_LoginDriver)
  : Lemma (accepted_count (d :: l) =
           b2n d.f_challenge_accepted + accepted_count l) = ()

let rec responded_count (l: list t_LoginDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> b2n d.f_responded + responded_count r

let responded_count_cons (d: t_LoginDriver) (l: list t_LoginDriver)
  : Lemma (responded_count (d :: l) =
           b2n d.f_responded + responded_count l) = ()

let rec issued_count (l: list t_LoginDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> b2n d.f_token_issued + issued_count r

let issued_count_cons (d: t_LoginDriver) (l: list t_LoginDriver)
  : Lemma (issued_count (d :: l) =
           b2n d.f_token_issued + issued_count l) = ()

let rec index_sound (l: list t_LoginDriver) (i: nat)
  : Lemma
    (requires (all_sound l /\ i < FStar.List.Tot.length l))
    (ensures (trace_sound (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else index_sound t (i - 1)

let rec update_sound (l: list t_LoginDriver) (i: nat) (x: t_LoginDriver)
  : Lemma
    (requires (all_sound l /\ trace_sound x))
    (ensures (all_sound (update l i x)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_sound t (i - 1) x

let rec update_accepted (l: list t_LoginDriver) (i: nat) (x: t_LoginDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (
      accepted_count (update l i x) +
        b2n (FStar.List.Tot.index l i).f_challenge_accepted =
      accepted_count l + b2n x.f_challenge_accepted))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_accepted t (i - 1) x

let rec update_responded (l: list t_LoginDriver) (i: nat) (x: t_LoginDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (
      responded_count (update l i x) +
        b2n (FStar.List.Tot.index l i).f_responded =
      responded_count l + b2n x.f_responded))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_responded t (i - 1) x

let rec update_issued (l: list t_LoginDriver) (i: nat) (x: t_LoginDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (
      issued_count (update l i x) +
        b2n (FStar.List.Tot.index l i).f_token_issued =
      issued_count l + b2n x.f_token_issued))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_issued t (i - 1) x

// ── Per-request flag/delta accounting over the extracted step ──────────────

/// A step changes the accepted flag only on an `Accepted` challenge event at
/// the challenge stage, and then it flips it from false to true.
let step_accepted_delta (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      b2n t.f_driver.f_challenge_accepted =
        b2n d.f_challenge_accepted +
        (if is_accepted_event e && is_challenge d then 1 else 0))) =
  trace_sound_matches_rust d;
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved obs ->
      (match obs <: t_ChallengeObservation with
       | ChallengeObservation_Observed consumption ->
           (match consumption <: t_ChallengeConsumption with
            | ChallengeConsumption_Accepted ->
                (match d.f_stage <: t_LoginStage with
                 | LoginStage_Challenge -> ()
                 | _ -> ())
            | ChallengeConsumption_Missing -> ()
            | ChallengeConsumption_WrongPurpose -> ())
       | ChallengeObservation_StorageFailed -> ())
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked _ -> ()

/// Only a successful `Tracked` observation from the track stage flips the
/// responded flag, and that step emits exactly one `Respond` effect.
let step_responded_delta (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      b2n t.f_driver.f_responded =
        b2n d.f_responded + respond_delta t.f_effect)) =
  trace_sound_matches_rust d;
  match e <: t_LoginEvent with
  | LoginEvent_TokenTracked obs ->
      (match obs <: t_TokenTrackObservation with
       | TokenTrackObservation_Tracked ->
           (match d.f_stage <: t_LoginStage with
            | LoginStage_Track -> ()
            | _ -> ())
       | TokenTrackObservation_Failed ->
           (match d.f_stage <: t_LoginStage with
            | LoginStage_Track -> ()
            | _ -> ()))
  | LoginEvent_ChallengeObserved _ -> ()
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()

/// Only a successful issuance observation from the issue stage flips the
/// token-issued flag. It is counted by `issued_delta`; `IssueToken` is the
/// preceding request to perform issuance, not the effect emitted here.
let step_issued_delta (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      b2n t.f_driver.f_token_issued =
        b2n d.f_token_issued + issued_delta d e)) =
  trace_sound_matches_rust d;
  match e <: t_LoginEvent with
  | LoginEvent_TokenIssued obs ->
      (match obs <: t_TokenIssueObservation with
       | TokenIssueObservation_Issued ->
           (match d.f_stage <: t_LoginStage with
            | LoginStage_Issue -> ()
            | _ -> ())
       | TokenIssueObservation_Failed ->
           (match d.f_stage <: t_LoginStage with
            | LoginStage_Issue -> ()
            | _ -> ()))
  | LoginEvent_ChallengeObserved _ -> ()
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenTracked _ -> ()

let rec responded_count_le_accepted (l: list t_LoginDriver)
  : Lemma
    (requires (all_sound l))
    (ensures (responded_count l <= accepted_count l))
    (decreases l) =
  match l with
  | [] -> ()
  | d :: r ->
      trace_sound_matches_rust d;
      assert (d.f_responded ==> d.f_challenge_accepted);
      responded_count_le_accepted r

let rec issued_count_le_accepted (l: list t_LoginDriver)
  : Lemma
    (requires (all_sound l))
    (ensures (issued_count l <= accepted_count l))
    (decreases l) =
  match l with
  | [] -> ()
  | d :: r ->
      trace_sound_matches_rust d;
      assert (d.f_token_issued ==> d.f_challenge_accepted);
      issued_count_le_accepted r

// ── The shared world and arbitrary schedules ───────────────────────────────

noeq type world = {
  challenge: option t_StoredPurpose;
  nonce_admitted: bool;
  responses: nat;
  tokens: nat;
  reqs: list t_LoginDriver;
}

/// The purpose actually stored under the one nonce key. There is no action
/// that inserts a new challenge: this composition is one nonce.
type action =
  | Spawn : action
  | Take : nat -> action
  | TakeFailed : nat -> action
  | Device : nat -> t_DeviceObservation -> action
  | Verify : nat -> t_VerifierObservation -> action
  | Record : nat -> t_FailureRecordObservation -> action
  | Reset : nat -> t_BackoffResetObservation -> action
  | Issue : nat -> t_TokenIssueObservation -> action
  | Track : nat -> t_TokenTrackObservation -> action

let challenge_present (w: world) : nat =
  challenge_present_opt w.challenge

/// Deliver one event to request `i`, perform the effect the driver returns,
/// and record the post-effect nonce state chosen by the caller.
let deliver (w: world) (i: nat{i < FStar.List.Tot.length w.reqs})
    (e: t_LoginEvent) (challenge_mid: option t_StoredPurpose)
    (admitted_mid: bool)
  : world =
  let d = FStar.List.Tot.index w.reqs i in
  if login_state_is_sound d then
    let t = step d e in
    { challenge = challenge_mid;
      nonce_admitted = admitted_mid;
      responses = w.responses + respond_delta t.f_effect;
      tokens = w.tokens + issued_delta d e;
      reqs = update w.reqs i t.f_driver }
  else w

/// Atomic take: the observation is a function of the stored purpose, and any
/// present nonce is removed in the same step. This is the modelled `get_del`
/// interface, not a proof about sled.
let world_step (w: world) (a: action) : world =
  match a with
  | Spawn -> { w with reqs = (begin_login ()).f_driver :: w.reqs }
  | Take i ->
      if i < FStar.List.Tot.length w.reqs && is_challenge (FStar.List.Tot.index w.reqs i)
      then begin
        match w.challenge with
        | None ->
            deliver w i
              (LoginEvent_ChallengeObserved
                (ChallengeObservation_Observed ChallengeConsumption_Missing))
              w.challenge w.nonce_admitted
        | Some StoredPurpose_Login ->
            deliver w i
              (LoginEvent_ChallengeObserved
                (ChallengeObservation_Observed ChallengeConsumption_Accepted))
              None true
        | Some StoredPurpose_Other ->
            deliver w i
              (LoginEvent_ChallengeObserved
                (ChallengeObservation_Observed ChallengeConsumption_WrongPurpose))
              None w.nonce_admitted
      end
      else w
  | TakeFailed i ->
      if i < FStar.List.Tot.length w.reqs && is_challenge (FStar.List.Tot.index w.reqs i)
      then
        deliver w i
          (LoginEvent_ChallengeObserved ChallengeObservation_StorageFailed)
          w.challenge w.nonce_admitted
      else w
  | Device i obs ->
      if i < FStar.List.Tot.length w.reqs && is_device (FStar.List.Tot.index w.reqs i)
      then deliver w i (LoginEvent_DeviceObserved obs) w.challenge w.nonce_admitted
      else w
  | Verify i obs ->
      if i < FStar.List.Tot.length w.reqs && is_verify (FStar.List.Tot.index w.reqs i)
      then deliver w i (LoginEvent_VerifierObserved obs) w.challenge w.nonce_admitted
      else w
  | Record i obs ->
      if i < FStar.List.Tot.length w.reqs && is_record_failure (FStar.List.Tot.index w.reqs i)
      then deliver w i (LoginEvent_FailureRecorded obs) w.challenge w.nonce_admitted
      else w
  | Reset i obs ->
      if i < FStar.List.Tot.length w.reqs && is_reset (FStar.List.Tot.index w.reqs i)
      then deliver w i (LoginEvent_BackoffResetObserved obs) w.challenge w.nonce_admitted
      else w
  | Issue i obs ->
      if i < FStar.List.Tot.length w.reqs && is_issue (FStar.List.Tot.index w.reqs i)
      then deliver w i (LoginEvent_TokenIssued obs) w.challenge w.nonce_admitted
      else w
  | Track i obs ->
      if i < FStar.List.Tot.length w.reqs && is_track (FStar.List.Tot.index w.reqs i)
      then deliver w i (LoginEvent_TokenTracked obs) w.challenge w.nonce_admitted
      else w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

/// Nonce conservation: the nonce is either still stored or has admitted one
/// request (and then it is gone), at most one request is admitted, responses
/// and token-issuance effects are exactly the corresponding driver flags.
let inv (w: world) : prop =
  all_sound w.reqs /\
  b2n w.nonce_admitted + challenge_present w <= 1 /\
  accepted_count w.reqs <= b2n w.nonce_admitted /\
  w.responses = responded_count w.reqs /\
  w.tokens = issued_count w.reqs

/// Deliver while preserving nonce conservation. The caller supplies the
/// arithmetic facts for the chosen post-effect nonce state; no transition
/// logic is restated: the flag deltas come from the extracted `step`.
let deliver_inv (w: world) (i: nat{i < FStar.List.Tot.length w.reqs})
    (e: t_LoginEvent) (challenge_mid: option t_StoredPurpose)
    (admitted_mid: bool)
  : Lemma
    (requires (
      inv w /\
      (let d = FStar.List.Tot.index w.reqs i in
       trace_sound d /\
       (let t = step d e in
        b2n admitted_mid + challenge_present_opt challenge_mid <= 1 /\
        accepted_count (update w.reqs i t.f_driver) <= b2n admitted_mid /\
        responded_count (update w.reqs i t.f_driver) =
          w.responses + respond_delta t.f_effect /\
        issued_count (update w.reqs i t.f_driver) =
          w.tokens + issued_delta d e))))
    (ensures (inv (deliver w i e challenge_mid admitted_mid))) =
  let d = FStar.List.Tot.index w.reqs i in
  index_sound w.reqs i;
  trace_sound_matches_rust d;
  assert (login_state_is_sound d = true);
  let t = step d e in
  update_sound w.reqs i t.f_driver

/// Every action preserves the invariant.
let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | Spawn ->
      begin_sound ();
      let b = (begin_login ()).f_driver in
      trace_sound_matches_rust b;
      all_sound_cons b w.reqs;
      accepted_count_cons b w.reqs;
      responded_count_cons b w.reqs;
      issued_count_cons b w.reqs
  | Take i ->
      if i < FStar.List.Tot.length w.reqs && is_challenge (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        (match w.challenge with
         | None ->
             let e = LoginEvent_ChallengeObserved
               (ChallengeObservation_Observed ChallengeConsumption_Missing) in
             step_accepted_delta d e;
             step_responded_delta d e;
             step_issued_delta d e;
             update_accepted w.reqs i (step d e).f_driver;
             update_responded w.reqs i (step d e).f_driver;
             update_issued w.reqs i (step d e).f_driver;
             deliver_inv w i e w.challenge w.nonce_admitted
         | Some StoredPurpose_Login ->
             let e = LoginEvent_ChallengeObserved
               (ChallengeObservation_Observed ChallengeConsumption_Accepted) in
             step_accepted_delta d e;
             step_responded_delta d e;
             step_issued_delta d e;
             update_accepted w.reqs i (step d e).f_driver;
             update_responded w.reqs i (step d e).f_driver;
             update_issued w.reqs i (step d e).f_driver;
             deliver_inv w i e None true
         | Some StoredPurpose_Other ->
             let e = LoginEvent_ChallengeObserved
               (ChallengeObservation_Observed ChallengeConsumption_WrongPurpose) in
             step_accepted_delta d e;
             step_responded_delta d e;
             step_issued_delta d e;
             update_accepted w.reqs i (step d e).f_driver;
             update_responded w.reqs i (step d e).f_driver;
             update_issued w.reqs i (step d e).f_driver;
             deliver_inv w i e None w.nonce_admitted)
      end
      else ()
  | TakeFailed i ->
      if i < FStar.List.Tot.length w.reqs && is_challenge (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        let e = LoginEvent_ChallengeObserved ChallengeObservation_StorageFailed in
        step_accepted_delta d e;
        step_responded_delta d e;
        step_issued_delta d e;
        update_accepted w.reqs i (step d e).f_driver;
        update_responded w.reqs i (step d e).f_driver;
        update_issued w.reqs i (step d e).f_driver;
        deliver_inv w i e w.challenge w.nonce_admitted
      end
      else ()
  | Device i obs ->
      if i < FStar.List.Tot.length w.reqs && is_device (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        let e = LoginEvent_DeviceObserved obs in
        step_accepted_delta d e;
        step_responded_delta d e;
        step_issued_delta d e;
        update_accepted w.reqs i (step d e).f_driver;
        update_responded w.reqs i (step d e).f_driver;
        update_issued w.reqs i (step d e).f_driver;
        deliver_inv w i e w.challenge w.nonce_admitted
      end
      else ()
  | Verify i obs ->
      if i < FStar.List.Tot.length w.reqs && is_verify (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        let e = LoginEvent_VerifierObserved obs in
        step_accepted_delta d e;
        step_responded_delta d e;
        step_issued_delta d e;
        update_accepted w.reqs i (step d e).f_driver;
        update_responded w.reqs i (step d e).f_driver;
        update_issued w.reqs i (step d e).f_driver;
        deliver_inv w i e w.challenge w.nonce_admitted
      end
      else ()
  | Record i obs ->
      if i < FStar.List.Tot.length w.reqs && is_record_failure (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        let e = LoginEvent_FailureRecorded obs in
        step_accepted_delta d e;
        step_responded_delta d e;
        step_issued_delta d e;
        update_accepted w.reqs i (step d e).f_driver;
        update_responded w.reqs i (step d e).f_driver;
        update_issued w.reqs i (step d e).f_driver;
        deliver_inv w i e w.challenge w.nonce_admitted
      end
      else ()
  | Reset i obs ->
      if i < FStar.List.Tot.length w.reqs && is_reset (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        let e = LoginEvent_BackoffResetObserved obs in
        step_accepted_delta d e;
        step_responded_delta d e;
        step_issued_delta d e;
        update_accepted w.reqs i (step d e).f_driver;
        update_responded w.reqs i (step d e).f_driver;
        update_issued w.reqs i (step d e).f_driver;
        deliver_inv w i e w.challenge w.nonce_admitted
      end
      else ()
  | Issue i obs ->
      if i < FStar.List.Tot.length w.reqs && is_issue (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        let e = LoginEvent_TokenIssued obs in
        step_accepted_delta d e;
        step_responded_delta d e;
        step_issued_delta d e;
        update_accepted w.reqs i (step d e).f_driver;
        update_responded w.reqs i (step d e).f_driver;
        update_issued w.reqs i (step d e).f_driver;
        deliver_inv w i e w.challenge w.nonce_admitted
      end
      else ()
  | Track i obs ->
      if i < FStar.List.Tot.length w.reqs && is_track (FStar.List.Tot.index w.reqs i)
      then begin
        let d = FStar.List.Tot.index w.reqs i in
        index_sound w.reqs i;
        trace_sound_matches_rust d;
        let e = LoginEvent_TokenTracked obs in
        step_accepted_delta d e;
        step_responded_delta d e;
        step_issued_delta d e;
        update_accepted w.reqs i (step d e).f_driver;
        update_responded w.reqs i (step d e).f_driver;
        update_issued w.reqs i (step d e).f_driver;
        deliver_inv w i e w.challenge w.nonce_admitted
      end
      else ()

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      world_step_inv w a;
      run_world_inv (world_step w a) rest

let initial (p: option t_StoredPurpose) : world =
  { challenge = p; nonce_admitted = false; responses = 0; tokens = 0; reqs = [] }

let initial_inv (p: option t_StoredPurpose) : Lemma (inv (initial p)) = ()

/// Headline theorem: whatever the number of requests, their interleaving, the
/// observations they receive, take failures and verification/tracking
/// failures, one nonce admits at most one request, one response and one token
/// issuance.
let one_nonce_at_most_one_admission (p: option t_StoredPurpose)
    (schedule: list action)
  : Lemma (
      let w = run_world (initial p) schedule in
      w.responses <= 1 /\
      w.tokens <= 1 /\
      accepted_count w.reqs <= 1 /\
      responded_count w.reqs <= 1 /\
      issued_count w.reqs <= 1 /\
      b2n w.nonce_admitted + challenge_present w <= 1) =
  initial_inv p;
  run_world_inv (initial p) schedule;
  let w = run_world (initial p) schedule in
  assert (all_sound w.reqs);
  responded_count_le_accepted w.reqs;
  issued_count_le_accepted w.reqs;
  assert (accepted_count w.reqs <= b2n w.nonce_admitted);
  assert (b2n w.nonce_admitted <= 1);
  assert (w.responses = responded_count w.reqs);
  assert (w.tokens = issued_count w.reqs)

// ── Purpose isolation ──────────────────────────────────────────────────────

/// The nonce state is never a login challenge.
let no_login_challenge (w: world) : bool =
  match w.challenge with
  | Some StoredPurpose_Login -> false
  | _ -> true

let no_login_core (w: world) : prop =
  inv w /\ no_login_challenge w = true /\ not w.nonce_admitted

/// If the stored challenge is not a login challenge, no action can flip the
/// admission bit or turn the stored purpose into a login purpose. The main
/// invariant then forces the accepted count to zero.
let world_step_no_login (w: world) (a: action)
  : Lemma (requires (no_login_core w)) (ensures (no_login_core (world_step w a))) =
  world_step_inv w a;
  match a with
  | Spawn -> ()
  | Take i ->
      if i < FStar.List.Tot.length w.reqs && is_challenge (FStar.List.Tot.index w.reqs i)
      then begin
        match w.challenge with
        | None -> ()
        | Some StoredPurpose_Other -> ()
        | Some StoredPurpose_Login -> ()
      end
      else ()
  | TakeFailed i -> ()
  | Device i obs -> ()
  | Verify i obs -> ()
  | Record i obs -> ()
  | Reset i obs -> ()
  | Issue i obs -> ()
  | Track i obs -> ()

let rec run_world_no_login (w: world) (schedule: list action)
  : Lemma (requires (no_login_core w)) (ensures (no_login_core (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      world_step_no_login w a;
      run_world_no_login (world_step w a) rest

/// If the one nonce is absent or carries another purpose, no schedule can
/// accept a login request, respond, or issue a token.
let non_login_nonce_never_admits (p: option t_StoredPurpose)
    (schedule: list action)
  : Lemma
    (requires (
      match p with
      | Some StoredPurpose_Login -> False
      | _ -> True))
    (ensures (
      let w = run_world (initial p) schedule in
      not w.nonce_admitted /\
      accepted_count w.reqs = 0 /\
      w.responses = 0 /\
      w.tokens = 0)) =
  initial_inv p;
  let w0 = initial p in
  assert (no_login_challenge w0 = true);
  assert (not w0.nonce_admitted);
  run_world_no_login w0 schedule;
  let w = run_world w0 schedule in
  assert (inv w);
  assert (not w.nonce_admitted);
  assert (accepted_count w.reqs <= b2n w.nonce_admitted);
  assert (accepted_count w.reqs = 0);
  assert (all_sound w.reqs);
  responded_count_le_accepted w.reqs;
  issued_count_le_accepted w.reqs;
  assert (w.responses = responded_count w.reqs);
  assert (w.tokens = issued_count w.reqs)

// ── Reachability witnesses ─────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

let login_nonce : option t_StoredPurpose = Some StoredPurpose_Login
let other_nonce : option t_StoredPurpose = Some StoredPurpose_Other
let absent_nonce : option t_StoredPurpose = None

/// One request performs the complete successful login: accepted login
/// challenge, present device, valid verifier, reset backoff, issue, track.
let s1 = world_step (initial login_nonce) Spawn
let s2 = world_step s1 (Take 0)
let s3 = world_step s2 (Device 0 DeviceObservation_Present)
let s4 = world_step s3 (Verify 0 VerifierObservation_Valid)
let s5 = world_step s4 (Reset 0 BackoffResetObservation_Reset)
let s6 = world_step s5 (Issue 0 TokenIssueObservation_Issued)
let s7 = world_step s6 (Track 0 TokenTrackObservation_Tracked)

let s1_ok ()
  : Lemma (s1.challenge = login_nonce /\ not s1.nonce_admitted /\
           s1.responses = 0 /\ s1.tokens = 0 /\
           FStar.List.Tot.length s1.reqs = 1) = ()

let s2_ok ()
  : Lemma (s2.challenge = None /\ s2.nonce_admitted /\
           s2.responses = 0 /\ s2.tokens = 0 /\
           FStar.List.Tot.length s2.reqs = 1 /\
           is_device (FStar.List.Tot.index s2.reqs 0)) = s1_ok ()

let s3_ok ()
  : Lemma (s3.challenge = None /\ s3.nonce_admitted /\
           s3.responses = 0 /\ s3.tokens = 0 /\
           is_verify (FStar.List.Tot.index s3.reqs 0)) = s2_ok ()

let s4_ok ()
  : Lemma (s4.responses = 0 /\ s4.tokens = 0 /\
           is_reset (FStar.List.Tot.index s4.reqs 0)) = s3_ok ()

let s5_ok ()
  : Lemma (s5.responses = 0 /\ s5.tokens = 0 /\
           is_issue (FStar.List.Tot.index s5.reqs 0)) = s4_ok ()

let s6_ok ()
  : Lemma (s6.responses = 0 /\ s6.tokens = 1 /\
           is_track (FStar.List.Tot.index s6.reqs 0)) = s5_ok ()

let s7_ok ()
  : Lemma (s7.responses = 1 /\ s7.tokens = 1 /\
           is_done (FStar.List.Tot.index s7.reqs 0) /\
           (FStar.List.Tot.index s7.reqs 0).f_responded /\
           not (FStar.List.Tot.index s7.reqs 0).f_failed) = s6_ok ()

let success_schedule : list action =
  [ Spawn; Take 0; Device 0 DeviceObservation_Present;
    Verify 0 VerifierObservation_Valid;
    Reset 0 BackoffResetObservation_Reset;
    Issue 0 TokenIssueObservation_Issued;
    Track 0 TokenTrackObservation_Tracked ]

/// A complete successful login is reachable from the real `begin_login`.
let success_is_reachable ()
  : Lemma (
      let w = run_world (initial login_nonce) success_schedule in
      w.challenge = None /\ w.nonce_admitted /\
      w.responses = 1 /\ w.tokens = 1 /\
      accepted_count w.reqs = 1 /\
      responded_count w.reqs = 1 /\
      issued_count w.reqs = 1) =
  run_cons (initial login_nonce) Spawn
    [Take 0; Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons s1 (Take 0)
    [Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons s2 (Device 0 DeviceObservation_Present)
    [Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons s3 (Verify 0 VerifierObservation_Valid)
    [Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons s4 (Reset 0 BackoffResetObservation_Reset)
    [Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons s5 (Issue 0 TokenIssueObservation_Issued)
    [Track 0 TokenTrackObservation_Tracked];
  run_cons s6 (Track 0 TokenTrackObservation_Tracked) [];
  run_nil s7;
  s7_ok ()

/// Two requests race for the same nonce: the first take admits request 0 and
/// removes the nonce; request 1 then observes it missing and fails. Only one
/// response and one token issuance occur.
let r1 = world_step (initial login_nonce) Spawn
let r2 = world_step r1 Spawn
let r3 = world_step r2 (Take 0)
let r4 = world_step r3 (Take 1)
let r5 = world_step r4 (Device 0 DeviceObservation_Present)
let r6 = world_step r5 (Verify 0 VerifierObservation_Valid)
let r7 = world_step r6 (Reset 0 BackoffResetObservation_Reset)
let r8 = world_step r7 (Issue 0 TokenIssueObservation_Issued)
let r9 = world_step r8 (Track 0 TokenTrackObservation_Tracked)

let r2_ok ()
  : Lemma (r2.challenge = login_nonce /\ not r2.nonce_admitted /\
           r2.responses = 0 /\ r2.tokens = 0 /\
           FStar.List.Tot.length r2.reqs = 2 /\
           is_challenge (FStar.List.Tot.index r2.reqs 0) /\
           is_challenge (FStar.List.Tot.index r2.reqs 1)) = ()

let r3_ok ()
  : Lemma (r3.challenge = None /\ r3.nonce_admitted /\
           r3.responses = 0 /\ r3.tokens = 0 /\
           FStar.List.Tot.length r3.reqs = 2 /\
           is_device (FStar.List.Tot.index r3.reqs 0) /\
           is_challenge (FStar.List.Tot.index r3.reqs 1)) = r2_ok ()

let r4_ok ()
  : Lemma (r4.challenge = None /\ r4.nonce_admitted /\
           r4.responses = 0 /\ r4.tokens = 0 /\
           FStar.List.Tot.length r4.reqs = 2 /\
           is_device (FStar.List.Tot.index r4.reqs 0) /\
           is_done (FStar.List.Tot.index r4.reqs 1) /\
           (FStar.List.Tot.index r4.reqs 1).f_failed /\
           not (FStar.List.Tot.index r4.reqs 1).f_challenge_accepted) = r3_ok ()

let r5_ok ()
  : Lemma (is_verify (FStar.List.Tot.index r5.reqs 0) /\
           is_done (FStar.List.Tot.index r5.reqs 1)) = r4_ok ()

let r6_ok ()
  : Lemma (is_reset (FStar.List.Tot.index r6.reqs 0) /\
           is_done (FStar.List.Tot.index r6.reqs 1)) = r5_ok ()

let r7_ok ()
  : Lemma (is_issue (FStar.List.Tot.index r7.reqs 0) /\
           is_done (FStar.List.Tot.index r7.reqs 1) /\
           r7.tokens = 0 /\ r7.responses = 0) = r6_ok ()

let r8_ok ()
  : Lemma (is_track (FStar.List.Tot.index r8.reqs 0) /\
           is_done (FStar.List.Tot.index r8.reqs 1) /\
           r8.tokens = 1 /\ r8.responses = 0) = r7_ok ()

let r9_ok ()
  : Lemma (r9.responses = 1 /\ r9.tokens = 1 /\
           (FStar.List.Tot.index r9.reqs 0).f_responded /\
           (FStar.List.Tot.index r9.reqs 1).f_failed /\
           FStar.List.Tot.length r9.reqs = 2) = r8_ok ()

let race_schedule : list action =
  [ Spawn; Spawn; Take 0; Take 1; Device 0 DeviceObservation_Present;
    Verify 0 VerifierObservation_Valid;
    Reset 0 BackoffResetObservation_Reset;
    Issue 0 TokenIssueObservation_Issued;
    Track 0 TokenTrackObservation_Tracked ]

let two_request_contention ()
  : Lemma (
      let w = run_world (initial login_nonce) race_schedule in
      w.responses = 1 /\ w.tokens = 1 /\
      accepted_count w.reqs = 1 /\ responded_count w.reqs = 1) =
  run_cons (initial login_nonce) Spawn
    [Spawn; Take 0; Take 1; Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons r1 Spawn
    [Take 0; Take 1; Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons r2 (Take 0)
    [Take 1; Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons r3 (Take 1)
    [Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons r4 (Device 0 DeviceObservation_Present)
    [Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons r5 (Verify 0 VerifierObservation_Valid)
    [Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons r6 (Reset 0 BackoffResetObservation_Reset)
    [Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Tracked];
  run_cons r7 (Issue 0 TokenIssueObservation_Issued)
    [Track 0 TokenTrackObservation_Tracked];
  run_cons r8 (Track 0 TokenTrackObservation_Tracked) [];
  run_nil r9;
  r9_ok ()

/// A non-login (wrong-purpose) challenge is spent by the take and the next
/// request sees it missing; neither is admitted.
let p1 = world_step (initial other_nonce) Spawn
let p2 = world_step p1 (Take 0)
let p3 = world_step p2 Spawn
let p4 = world_step p3 (Take 0)

let p1_ok ()
  : Lemma (p1.challenge = other_nonce /\ not p1.nonce_admitted) = ()

let p2_ok ()
  : Lemma (p2.challenge = None /\ not p2.nonce_admitted /\
           p2.responses = 0 /\ p2.tokens = 0 /\
           is_done (FStar.List.Tot.index p2.reqs 0) /\
           (FStar.List.Tot.index p2.reqs 0).f_failed /\
           not (FStar.List.Tot.index p2.reqs 0).f_challenge_accepted) = p1_ok ()

let p3_ok ()
  : Lemma (p3.challenge = None /\ not p3.nonce_admitted /\
           FStar.List.Tot.length p3.reqs = 2 /\
           is_challenge (FStar.List.Tot.index p3.reqs 0) /\
           is_done (FStar.List.Tot.index p3.reqs 1)) = p2_ok ()

let p4_ok ()
  : Lemma (p4.challenge = None /\ not p4.nonce_admitted /\
           p4.responses = 0 /\ p4.tokens = 0 /\
           is_done (FStar.List.Tot.index p4.reqs 0) /\
           is_done (FStar.List.Tot.index p4.reqs 1) /\
           (FStar.List.Tot.index p4.reqs 0).f_failed /\
           (FStar.List.Tot.index p4.reqs 1).f_failed /\
           not (FStar.List.Tot.index p4.reqs 0).f_challenge_accepted /\
           not (FStar.List.Tot.index p4.reqs 1).f_challenge_accepted) = p3_ok ()

let wrong_purpose_schedule : list action =
  [ Spawn; Take 0; Spawn; Take 0 ]

let wrong_purpose_spends_nonce ()
  : Lemma (
      let w = run_world (initial other_nonce) wrong_purpose_schedule in
      w.challenge = None /\ not w.nonce_admitted /\
      w.responses = 0 /\ w.tokens = 0 /\
      accepted_count w.reqs = 0) =
  run_cons (initial other_nonce) Spawn [Take 0; Spawn; Take 0];
  run_cons p1 (Take 0) [Spawn; Take 0];
  run_cons p2 Spawn [Take 0];
  run_cons p3 (Take 0) [];
  run_nil p4;
  p4_ok ()

/// A missing nonce is terminal and cannot accept.
let m1 = world_step (initial absent_nonce) Spawn
let m2 = world_step m1 (Take 0)

let m1_ok ()
  : Lemma (m1.challenge = None /\ not m1.nonce_admitted) = ()

let m2_ok ()
  : Lemma (m2.challenge = None /\ not m2.nonce_admitted /\
           m2.responses = 0 /\ m2.tokens = 0 /\
           is_done (FStar.List.Tot.index m2.reqs 0) /\
           (FStar.List.Tot.index m2.reqs 0).f_failed /\
           not (FStar.List.Tot.index m2.reqs 0).f_challenge_accepted) = m1_ok ()

let missing_schedule : list action = [ Spawn; Take 0 ]

let missing_nonce_is_terminal ()
  : Lemma (
      let w = run_world (initial absent_nonce) missing_schedule in
      w.challenge = None /\ not w.nonce_admitted /\
      w.responses = 0 /\ w.tokens = 0 /\
      accepted_count w.reqs = 0) =
  run_cons (initial absent_nonce) Spawn [Take 0];
  run_cons m1 (Take 0) [];
  run_nil m2;
  m2_ok ()

/// A get_del failure does not spend the nonce: a later request can still take
/// the same login challenge, while the failed request is terminal.
let f1 = world_step (initial login_nonce) Spawn
let f2 = world_step f1 (TakeFailed 0)
let f3 = world_step f2 Spawn
let f4 = world_step f3 (Take 0)

let f1_ok ()
  : Lemma (f1.challenge = login_nonce /\ not f1.nonce_admitted) = ()

let f2_ok ()
  : Lemma (f2.challenge = login_nonce /\ not f2.nonce_admitted /\
           f2.responses = 0 /\ f2.tokens = 0 /\
           is_done (FStar.List.Tot.index f2.reqs 0) /\
           (FStar.List.Tot.index f2.reqs 0).f_failed) = f1_ok ()

let f3_ok ()
  : Lemma (f3.challenge = login_nonce /\ not f3.nonce_admitted /\
           FStar.List.Tot.length f3.reqs = 2 /\
           is_challenge (FStar.List.Tot.index f3.reqs 0) /\
           is_done (FStar.List.Tot.index f3.reqs 1)) = f2_ok ()

let f4_ok ()
  : Lemma (f4.challenge = None /\ f4.nonce_admitted /\
           f4.responses = 0 /\ f4.tokens = 0 /\
           is_device (FStar.List.Tot.index f4.reqs 0) /\
           is_done (FStar.List.Tot.index f4.reqs 1)) = f3_ok ()

let take_failure_schedule : list action =
  [ Spawn; TakeFailed 0; Spawn; Take 0 ]

let take_failure_preserves_nonce ()
  : Lemma (
      let w = run_world (initial login_nonce) take_failure_schedule in
      w.challenge = None /\ w.nonce_admitted /\
      w.responses = 0 /\ w.tokens = 0 /\
      accepted_count w.reqs = 1) =
  run_cons (initial login_nonce) Spawn [TakeFailed 0; Spawn; Take 0];
  run_cons f1 (TakeFailed 0) [Spawn; Take 0];
  run_cons f2 Spawn [Take 0];
  run_cons f3 (Take 0) [];
  run_nil f4;
  f4_ok ()

/// An actual verifier rejection is terminal after the failure side effects;
/// no token or response follows.
let v1 = world_step (initial login_nonce) Spawn
let v2 = world_step v1 (Take 0)
let v3 = world_step v2 (Device 0 DeviceObservation_Present)
let v4 = world_step v3 (Verify 0 VerifierObservation_RejectedUnauthorized)
let v5 = world_step v4 (Record 0 ({ f_fallback_counter_ok = true }))

let v4_ok ()
  : Lemma (is_record_failure (FStar.List.Tot.index v4.reqs 0) /\
           v4.tokens = 0 /\ v4.responses = 0) = ()

let v5_ok ()
  : Lemma (v5.responses = 0 /\ v5.tokens = 0 /\
           is_done (FStar.List.Tot.index v5.reqs 0) /\
           (FStar.List.Tot.index v5.reqs 0).f_failed /\
           not (FStar.List.Tot.index v5.reqs 0).f_responded) = v4_ok ()

let verifier_failure_schedule : list action =
  [ Spawn; Take 0; Device 0 DeviceObservation_Present;
    Verify 0 VerifierObservation_RejectedUnauthorized;
    Record 0 ({ f_fallback_counter_ok = true }) ]

let verifier_failure_is_terminal ()
  : Lemma (
      let w = run_world (initial login_nonce) verifier_failure_schedule in
      w.responses = 0 /\ w.tokens = 0 /\
      accepted_count w.reqs = 1 /\
      not (FStar.List.Tot.index w.reqs 0).f_responded) =
  run_cons (initial login_nonce) Spawn
    [Take 0; Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_RejectedUnauthorized;
     Record 0 ({ f_fallback_counter_ok = true })];
  run_cons v1 (Take 0)
    [Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_RejectedUnauthorized;
     Record 0 ({ f_fallback_counter_ok = true })];
  run_cons v2 (Device 0 DeviceObservation_Present)
    [Verify 0 VerifierObservation_RejectedUnauthorized;
     Record 0 ({ f_fallback_counter_ok = true })];
  run_cons v3 (Verify 0 VerifierObservation_RejectedUnauthorized)
    [Record 0 ({ f_fallback_counter_ok = true })];
  run_cons v4 (Record 0 ({ f_fallback_counter_ok = true })) [];
  run_nil v5;
  v5_ok ()

/// A JTI tracking failure is terminal even though a token was issued: no
/// response is delivered.
let k1 = world_step (initial login_nonce) Spawn
let k2 = world_step k1 (Take 0)
let k3 = world_step k2 (Device 0 DeviceObservation_Present)
let k4 = world_step k3 (Verify 0 VerifierObservation_Valid)
let k5 = world_step k4 (Reset 0 BackoffResetObservation_Reset)
let k6 = world_step k5 (Issue 0 TokenIssueObservation_Issued)
let k7 = world_step k6 (Track 0 TokenTrackObservation_Failed)

let k6_ok ()
  : Lemma (is_track (FStar.List.Tot.index k6.reqs 0) /\
           k6.tokens = 1 /\ k6.responses = 0) = ()

let k7_ok ()
  : Lemma (k7.responses = 0 /\ k7.tokens = 1 /\
           FStar.List.Tot.length k7.reqs = 1 /\
           is_done (FStar.List.Tot.index k7.reqs 0) /\
           (FStar.List.Tot.index k7.reqs 0).f_failed /\
           (FStar.List.Tot.index k7.reqs 0).f_token_issued /\
           not (FStar.List.Tot.index k7.reqs 0).f_token_tracked /\
           not (FStar.List.Tot.index k7.reqs 0).f_responded) = k6_ok ()

let tracking_failure_schedule : list action =
  [ Spawn; Take 0; Device 0 DeviceObservation_Present;
    Verify 0 VerifierObservation_Valid;
    Reset 0 BackoffResetObservation_Reset;
    Issue 0 TokenIssueObservation_Issued;
    Track 0 TokenTrackObservation_Failed ]

let tracking_failure_is_terminal ()
  : Lemma (
      let w = run_world (initial login_nonce) tracking_failure_schedule in
      w.responses = 0 /\ w.tokens = 1 /\
      FStar.List.Tot.length w.reqs = 1 /\
      (FStar.List.Tot.index w.reqs 0).f_token_issued /\
      not (FStar.List.Tot.index w.reqs 0).f_token_tracked /\
      not (FStar.List.Tot.index w.reqs 0).f_responded) =
  run_cons (initial login_nonce) Spawn
    [Take 0; Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Failed];
  run_cons k1 (Take 0)
    [Device 0 DeviceObservation_Present;
     Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Failed];
  run_cons k2 (Device 0 DeviceObservation_Present)
    [Verify 0 VerifierObservation_Valid;
     Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Failed];
  run_cons k3 (Verify 0 VerifierObservation_Valid)
    [Reset 0 BackoffResetObservation_Reset;
     Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Failed];
  run_cons k4 (Reset 0 BackoffResetObservation_Reset)
    [Issue 0 TokenIssueObservation_Issued;
     Track 0 TokenTrackObservation_Failed];
  run_cons k5 (Issue 0 TokenIssueObservation_Issued)
    [Track 0 TokenTrackObservation_Failed];
  run_cons k6 (Track 0 TokenTrackObservation_Failed) [];
  run_nil k7;
  k7_ok ()

#pop-options
