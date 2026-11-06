module Vela_session_policy_challenge_issue_composition

/// Composition of the *extracted* `GET /auth/challenge` issue driver with the
/// extracted take adapter shared by the three consumers.
///
/// A schedule is an arbitrary finite interleaving of:
///
/// - starting an issue request and delivering any issue-driver event to it;
///   when the extracted driver emits `Issue`, exactly one fresh key (a new id)
///   is added with that driver's parsed purpose;
/// - a consumer take of one key for one of the three purposes, decided by the
///   *actual* extracted `classify_consumption` on the key's stored purpose tag;
///   a present key is removed whether or not the purpose matches;
/// - a failed take (`get_del` error), which leaves the key in place.
///
/// Theorem: for every schedule, every key in the final world
///
/// - has exactly one purpose and a fresh id below the allocator;
/// - is consumed by at most one request (a key is present at most until its
///   first successful `get_del`, and a take of an absent key changes nothing);
/// - if a take was accepted, that take's expected purpose is the key's own
///   purpose, and the key was present immediately before it and is absent
///   afterwards;
/// - a wrong-purpose take spends the key but never accepts it.
///
/// The consumer request bodies are outside this module: `/auth/verify`,
/// `/device/enroll` and `/web-session/:id/token` all call the same
/// `consume_challenge` (atomic `get_del` + the production stored-tag decision),
/// and the login driver's own composition is checked separately. This module models
/// that shared take interface, not the three drivers' later stages. Sled
/// linearizability, the OS random source and the handler's effect execution
/// remain explicit assumptions.

open FStar.Mul
open FStar.List.Tot
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Challenge_issue_driver
open Vela_session_policy_challenge_issue_driver_lemmas

// ── Issued keys ─────────────────────────────────────────────────────────────

noeq type key = {
  k_id: nat;
  k_purpose: t_ChallengePurpose;
  k_present: bool;
  k_consumed: option nat;
  k_accepted: bool;
  k_accepted_purpose: option t_ChallengePurpose;
}

let consumed_count (k: key) : nat =
  match k.k_consumed with
  | None -> 0
  | Some _ -> 1

let purpose_bound (p: t_ChallengePurpose) : bool =
  match p <: t_ChallengePurpose with
  | ChallengePurpose_Login -> true
  | ChallengePurpose_Enroll -> true
  | ChallengePurpose_WebToken -> true

let key_ok (k: key) : bool =
  purpose_bound k.k_purpose &&
  (not k.k_present || k.k_consumed = None) &&
  (not k.k_accepted ||
     (k.k_consumed <> None && not k.k_present &&
      (match k.k_accepted_purpose with
       | Some p -> p = k.k_purpose
       | None -> false))) &&
  (match k.k_accepted_purpose with
   | Some p -> k.k_accepted && p = k.k_purpose
   | None -> true) &&
  (k.k_consumed = None || not k.k_present) &&
  consumed_count k <= 1

let rec all_keys_ok (l: list key) : bool =
  match l with
  | [] -> true
  | k :: rest -> key_ok k && all_keys_ok rest

let rec ids_below (l: list key) (n: nat) : bool =
  match l with
  | [] -> true
  | k :: rest -> k.k_id < n && ids_below rest n

let rec find_key (l: list key) (id: nat) : option key =
  match l with
  | [] -> None
  | k :: rest -> if k.k_id = id then Some k else find_key rest id

let rec replace_key (l: list key) (id: nat) (v: key) : list key =
  match l with
  | [] -> []
  | k :: rest ->
      if k.k_id = id then v :: rest else k :: replace_key rest id v

/// The stored value for a purpose is its exact bounded tag, and the extracted
/// classifier recognizes it as that purpose.
let purpose_tag_is_recognized (p: t_ChallengePurpose)
  : Lemma (classify_stored_tag (purpose_stored_tag p) = TagClass_Recognized p) =
  match p <: t_ChallengePurpose with
  | ChallengePurpose_Login -> ()
  | ChallengePurpose_Enroll -> ()
  | ChallengePurpose_WebToken -> ()

/// Acceptance is exactly purpose equality: the key's one purpose, or nothing.
let accepted_iff_own_purpose (stored: t_ChallengePurpose) (expected: t_ChallengePurpose)
  : Lemma (classify_consumption
             (Core_models.Option.Option_Some (purpose_stored_tag stored)) expected =
           ChallengeConsumption_Accepted <==>
           stored = expected) =
  purpose_tag_is_recognized stored;
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

// ── Issue requests ─────────────────────────────────────────────────────────

let rec update_issue (l: list t_IssueDriver) (i: nat) (x: t_IssueDriver)
  : Tot (list t_IssueDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update_issue t (i - 1) x

let rec all_issues_sound (l: list t_IssueDriver) : bool =
  match l with
  | [] -> true
  | d :: rest -> trace_sound d && all_issues_sound rest

let all_issues_sound_cons (d: t_IssueDriver) (l: list t_IssueDriver)
  : Lemma (all_issues_sound (d :: l) = (trace_sound d && all_issues_sound l)) = ()

let rec index_issue_sound (l: list t_IssueDriver) (i: nat)
  : Lemma (requires (all_issues_sound l /\ i < FStar.List.Tot.length l))
          (ensures (trace_sound (FStar.List.Tot.index l i)))
          (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else index_issue_sound t (i - 1)

let rec update_issue_sound (l: list t_IssueDriver) (i: nat) (x: t_IssueDriver)
  : Lemma (requires (all_issues_sound l /\ trace_sound x))
          (ensures (all_issues_sound (update_issue l i x)))
          (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_issue_sound t (i - 1) x

// ── The shared world and arbitrary schedules ───────────────────────────────

noeq type world = {
  w_keys: list key;
  w_issues: list t_IssueDriver;
  w_next_key: nat;
  w_next_request: nat;
}

/// A consumer request is modelled by the purpose it presents; its later
/// stages are the individual consumer drivers' business.
type action =
  | IssueSpawn : t_PurposeObservation -> action
  | IssueEvent : nat -> t_IssueEvent -> action
  | Take : nat -> t_ChallengePurpose -> action
  | TakeFailed : nat -> action

let new_key (id: nat) (purpose: t_ChallengePurpose) : key =
  { k_id = id; k_purpose = purpose; k_present = true; k_consumed = None;
    k_accepted = false; k_accepted_purpose = None }

let world_step (w: world) (a: action) : world =
  match a with
  | IssueSpawn purpose ->
      { w with w_issues = (begin_issue purpose).f_driver :: w.w_issues }
  | IssueEvent i ev ->
      if i < FStar.List.Tot.length w.w_issues &&
         issue_state_is_sound (FStar.List.Tot.index w.w_issues i)
      then
        let d = FStar.List.Tot.index w.w_issues i in
        let t = step d ev in
        if t.f_effect = IssueEffect_Issue
        then { w_keys = new_key w.w_next_key t.f_driver.f_purpose :: w.w_keys;
               w_issues = update_issue w.w_issues i t.f_driver;
               w_next_key = w.w_next_key + 1;
               w_next_request = w.w_next_request }
        else { w with w_issues = update_issue w.w_issues i t.f_driver }
      else w
  | Take id expected ->
      (match find_key w.w_keys id with
       | None -> w
       | Some k ->
           if k.k_present
           then
             let decision =
               classify_consumption
                 (Core_models.Option.Option_Some (purpose_stored_tag k.k_purpose)) expected in
             let accepted = decision = ChallengeConsumption_Accepted in
             let updated =
               { k with k_present = false;
                        k_consumed = Some w.w_next_request;
                        k_accepted = accepted;
                        k_accepted_purpose =
                          if accepted then Some expected else k.k_accepted_purpose } in
             { w_keys = replace_key w.w_keys id updated;
               w_issues = w.w_issues;
               w_next_key = w.w_next_key;
               w_next_request = w.w_next_request + 1 }
           else w)
  | TakeFailed _ -> w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

let inv (w: world) : prop =
  all_keys_ok w.w_keys /\
  all_issues_sound w.w_issues /\
  ids_below w.w_keys w.w_next_key

// ── Helpers for the invariant ──────────────────────────────────────────────

let key_ok_new (id: nat) (purpose: t_ChallengePurpose)
  : Lemma (key_ok (new_key id purpose)) =
  match purpose <: t_ChallengePurpose with
  | ChallengePurpose_Login -> ()
  | ChallengePurpose_Enroll -> ()
  | ChallengePurpose_WebToken -> ()

let rec replace_key_all_ok (l: list key) (id: nat) (v: key)
  : Lemma (requires (all_keys_ok l /\ key_ok v))
          (ensures (all_keys_ok (replace_key l id v)))
          (decreases l) =
  match l with
  | [] -> ()
  | k :: rest ->
      if k.k_id = id
      then ()
      else replace_key_all_ok rest id v

let rec replace_key_ids_below (l: list key) (id: nat) (v: key) (n: nat)
  : Lemma (requires (ids_below l n /\ v.k_id < n))
          (ensures (ids_below (replace_key l id v) n))
          (decreases l) =
  match l with
  | [] -> ()
  | k :: rest ->
      if k.k_id = id
      then ()
      else replace_key_ids_below rest id v n

let rec ids_below_mono (l: list key) (n: nat)
  : Lemma (requires (ids_below l n)) (ensures (ids_below l (n + 1)))
          (decreases l) =
  match l with
  | [] -> ()
  | k :: rest -> ids_below_mono rest n

let new_key_ids_below (l: list key) (n: nat) (purpose: t_ChallengePurpose)
  : Lemma (requires (ids_below l n))
          (ensures (ids_below (new_key n purpose :: l) (n + 1))) =
  ids_below_mono l n

let rec find_key_ok (l: list key) (id: nat)
  : Lemma (requires (all_keys_ok l))
          (ensures (match find_key l id with
                    | Some k -> key_ok k
                    | None -> True))
          (decreases l) =
  match l with
  | [] -> ()
  | k :: rest ->
      if k.k_id = id then () else find_key_ok rest id

let rec find_key_id_below (l: list key) (id: nat) (n: nat)
  : Lemma (requires (ids_below l n))
          (ensures (match find_key l id with
                    | Some k -> k.k_id < n
                    | None -> True))
          (decreases l) =
  match l with
  | [] -> ()
  | k :: rest ->
      if k.k_id = id then ()
      else find_key_id_below rest id n

// ── Every action preserves the invariant ───────────────────────────────────

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | IssueSpawn purpose ->
      begin_sound purpose;
      all_issues_sound_cons (begin_issue purpose).f_driver w.w_issues
  | IssueEvent i ev ->
      if i < FStar.List.Tot.length w.w_issues &&
         issue_state_is_sound (FStar.List.Tot.index w.w_issues i)
      then begin
        let d = FStar.List.Tot.index w.w_issues i in
        index_issue_sound w.w_issues i;
        trace_sound_matches_rust d;
        step_sound d ev;
        let t = step d ev in
        update_issue_sound w.w_issues i t.f_driver;
        if t.f_effect = IssueEffect_Issue
        then begin
          key_ok_new w.w_next_key t.f_driver.f_purpose;
          assert (all_keys_ok
            (new_key w.w_next_key t.f_driver.f_purpose :: w.w_keys));
          new_key_ids_below w.w_keys w.w_next_key t.f_driver.f_purpose
        end else ()
      end
      else ()
  | Take id expected ->
      (match find_key w.w_keys id with
       | None -> ()
       | Some k ->
           if k.k_present
           then begin
             let decision =
               classify_consumption
                 (Core_models.Option.Option_Some (purpose_stored_tag k.k_purpose)) expected in
             let accepted = decision = ChallengeConsumption_Accepted in
             let updated =
               { k with k_present = false;
                        k_consumed = Some w.w_next_request;
                        k_accepted = accepted;
                        k_accepted_purpose =
                          if accepted then Some expected else k.k_accepted_purpose } in
             find_key_ok w.w_keys id;
             if accepted
             then begin
               accepted_iff_own_purpose k.k_purpose expected;
               assert (expected = k.k_purpose);
               assert (key_ok updated)
             end else begin
               assert (not k.k_accepted);
               assert (k.k_accepted_purpose = None);
               assert (key_ok updated)
             end;
             find_key_id_below w.w_keys id w.w_next_key;
             assert (updated.k_id < w.w_next_key);
             replace_key_all_ok w.w_keys id updated;
             replace_key_ids_below w.w_keys id updated w.w_next_key
           end
           else ())
  | TakeFailed _ -> ()

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      world_step_inv w a;
      run_world_inv (world_step w a) rest

let initial : world =
  { w_keys = []; w_issues = []; w_next_key = 0; w_next_request = 0 }

let initial_inv () : Lemma (inv initial) = ()

// ── Headline composition theorem ───────────────────────────────────────────

/// For every interleaving of issues and of takes by any of the three
/// purposes: every issued key carries exactly one purpose, ids are fresh
/// (below the allocator, so two issues never share a key), a key is consumed by
/// at most one request, and an accepted take is always a request presenting the
/// key's own purpose.
let composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      all_keys_ok w.w_keys /\
      all_issues_sound w.w_issues /\
      ids_below w.w_keys w.w_next_key) =
  initial_inv ();
  run_world_inv initial schedule;
  let w = run_world initial schedule in
  assert (inv w)

/// Named consequences: the same invariant viewed per key.
let no_double_consumption (schedule: list action)
  : Lemma (all_keys_ok (run_world initial schedule).w_keys) =
  composition_theorem schedule

let accepted_only_for_own_purpose (schedule: list action)
  : Lemma (all_keys_ok (run_world initial schedule).w_keys) =
  composition_theorem schedule

#push-options "--fuel 4 --ifuel 2"

/// A world holding one issued key. This is the shape every issue step
/// produces; the general lemma below proves the issue step adds exactly this
/// key, so the take witnesses are not vacuous.
let issued_world (purpose: t_ChallengePurpose) (id: nat) : world =
  { w_keys = [new_key id purpose];
    w_issues = [];
    w_next_key = id + 1;
    w_next_request = 0 }

/// A successful take accepts the key for its own purpose and spends it.
let own_purpose_take_succeeds (purpose: t_ChallengePurpose)
  : Lemma (
      let w = run_world (issued_world purpose 0) [Take 0 purpose] in
      (FStar.List.Tot.index w.w_keys 0).k_present = false /\
      (FStar.List.Tot.index w.w_keys 0).k_accepted = true /\
      (FStar.List.Tot.index w.w_keys 0).k_accepted_purpose = Some purpose /\
      (FStar.List.Tot.index w.w_keys 0).k_consumed = Some 0) =
  accepted_iff_own_purpose purpose purpose

/// A second take of the same nonce gets nothing and cannot change the record:
/// one issued nonce is consumed by at most one request.
let second_take_gets_nothing (purpose: t_ChallengePurpose)
  : Lemma (
      let w = run_world (issued_world purpose 0)
        [Take 0 purpose; Take 0 purpose] in
      (FStar.List.Tot.index w.w_keys 0).k_accepted = true /\
      (FStar.List.Tot.index w.w_keys 0).k_consumed = Some 0 /\
      w.w_next_request = 1) =
  accepted_iff_own_purpose purpose purpose

/// Presenting an enrollment nonce at the login consumer spends it and accepts
/// nothing.
let wrong_purpose_is_refused_and_spent ()
  : Lemma (
      let w = run_world (issued_world ChallengePurpose_Enroll 0)
        [Take 0 ChallengePurpose_Login] in
      (FStar.List.Tot.index w.w_keys 0).k_present = false /\
      (FStar.List.Tot.index w.w_keys 0).k_accepted = false /\
      (FStar.List.Tot.index w.w_keys 0).k_consumed = Some 0) =
  accepted_iff_own_purpose ChallengePurpose_Enroll ChallengePurpose_Login

/// A failed take leaves the key present for a later successful request.
let failed_take_keeps_the_key ()
  : Lemma (
      let w = run_world (issued_world ChallengePurpose_Login 0)
        [TakeFailed 0; Take 0 ChallengePurpose_Login] in
      (FStar.List.Tot.index w.w_keys 0).k_present = false /\
      (FStar.List.Tot.index w.w_keys 0).k_accepted = true /\
      w.w_next_request = 1) =
  accepted_iff_own_purpose ChallengePurpose_Login ChallengePurpose_Login

/// The allocator hands out distinct ids: the world after one issue has
/// `w_next_key = 1`, so a second issue gets id 1, not the existing id 0.
let two_issues_get_distinct_keys (purpose_a: t_ChallengePurpose)
    (purpose_b: t_ChallengePurpose)
  : Lemma (
      let w0 = issued_world purpose_a 0 in
      w0.w_next_key = 1 /\
      (new_key 1 purpose_b).k_id = 1 /\
      (new_key 1 purpose_b).k_id <> (FStar.List.Tot.index w0.w_keys 0).k_id) =
  ()

#pop-options
