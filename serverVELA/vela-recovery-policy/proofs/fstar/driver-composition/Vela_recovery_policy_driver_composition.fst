module Vela_recovery_policy_driver_composition

/// Concurrent composition of the *extracted* enrollment-redemption driver.
///
/// One enrollment grant is shared by any number of requests, each running its
/// own `Vela_recovery_policy.Driver.step`. A schedule is an arbitrary list of
/// actions: start a request, expire the grant, or deliver the next observation
/// to any request. The world abstracts the effects the handler performs:
///
/// - the store's atomic `get_del` (a consumption sees the grant iff it is still
///   present, and removes it in the same step);
/// - the guarded device INSERT (`Inserted` wrote a row, `Skipped` wrote none,
///   `Failed` may or may not have written one: the schedule chooses);
/// - `restore_enroll_grant`, performed exactly when the driver returns
///   `RestoreAndFail`, which re-arms the grant;
/// - TTL expiry, which may remove the grant at any time.
///
/// Theorem: for every schedule, at most one device row is ever written for the
/// grant. Assumptions (not proved here): `get_del` is linearizable, the
/// handler performs exactly the effect the driver returns, the grant key is
/// issued once (random id), and an observation reaches the driver in the same
/// step as its effect. SQL guard semantics and the observation origins remain
/// outside this module.

open FStar.Mul

open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Driver
open Vela_recovery_policy_driver_lemmas

let b2n (b: bool) : nat = if b then 1 else 0

/// A request holds the consumed grant between a matched consumption and its
/// final outcome.
let holds (d: t_RedemptionDriver) : nat =
  if is_policy d || is_insert d || is_recheck d then 1 else 0

let is_restore (e: t_RedemptionEffect) : bool =
  match e with
  | RedemptionEffect_RestoreAndFail _ -> true
  | _ -> false

let present_event (e: t_RedemptionEvent) : nat =
  match e with
  | RedemptionEvent_Consumed (ConsumptionObservation_Present _) -> 1
  | _ -> 0

// ── Per-request token accounting over the extracted step ───────────────────

/// A step never creates a held grant or a restoration out of nothing: the only
/// source is a consumption that actually observed the grant.
let step_tokens (d: t_RedemptionDriver) (e: t_RedemptionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      trace_sound t.f_driver /\
      holds t.f_driver + b2n (is_restore t.f_effect) <=
        holds d + (if is_consume d then present_event e else 0))) =
  trace_sound_matches_rust d;
  step_sound d e;
  match e <: t_RedemptionEvent with
  | RedemptionEvent_Consumed obs ->
      (match obs <: t_ConsumptionObservation with
       | ConsumptionObservation_Missing -> ()
       | ConsumptionObservation_Present _ -> ())
  | RedemptionEvent_FinalPolicy _ -> ()
  | RedemptionEvent_Insert obs ->
      (match obs <: t_InsertObservation with
       | InsertObservation_Inserted -> ()
       | InsertObservation_Skipped -> ()
       | InsertObservation_Failed -> ())
  | RedemptionEvent_Recheck obs ->
      (match obs <: t_AuthorityRecheckObservation with
       | AuthorityRecheckObservation_QueryFailed -> ()
       | AuthorityRecheckObservation_AccountAbsent -> ()
       | AuthorityRecheckObservation_CommitmentRevoked -> ()
       | AuthorityRecheckObservation_CredentialReplaced -> ()
       | AuthorityRecheckObservation_StillRotating -> ())

/// An insert outcome that may have written a row (`Inserted`, or `Failed`
/// with an unknown commit) releases the held grant and never restores it.
let insert_tokens (d: t_RedemptionDriver) (obs: t_InsertObservation)
  : Lemma
    (requires (trace_sound d /\ is_insert d))
    (ensures (
      let t = step d (RedemptionEvent_Insert obs) in
      not (is_restore t.f_effect) /\
      holds t.f_driver +
        (match obs with InsertObservation_Skipped -> 0 | _ -> 1) <= 1)) =
  trace_sound_matches_rust d;
  match obs <: t_InsertObservation with
  | InsertObservation_Inserted -> ()
  | InsertObservation_Skipped -> ()
  | InsertObservation_Failed -> ()

// ── Request lists ──────────────────────────────────────────────────────────

let rec update (l: list t_RedemptionDriver) (i: nat) (x: t_RedemptionDriver)
  : Tot (list t_RedemptionDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec all_sound (l: list t_RedemptionDriver) : bool =
  match l with
  | [] -> true
  | d :: r -> trace_sound d && all_sound r

let rec held (l: list t_RedemptionDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> holds d + held r

let rec index_sound (l: list t_RedemptionDriver) (i: nat)
  : Lemma
    (requires (all_sound l /\ i < FStar.List.Tot.length l))
    (ensures (trace_sound (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else index_sound t (i - 1)

let rec update_sound (l: list t_RedemptionDriver) (i: nat) (x: t_RedemptionDriver)
  : Lemma
    (requires (all_sound l /\ trace_sound x))
    (ensures (all_sound (update l i x)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_sound t (i - 1) x

let rec update_held (l: list t_RedemptionDriver) (i: nat) (x: t_RedemptionDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (held (update l i x) + holds (FStar.List.Tot.index l i) = held l + holds x))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_held t (i - 1) x

// ── The shared world and arbitrary schedules ───────────────────────────────

noeq type world = {
  grant: bool;
  rows: nat;
  reqs: list t_RedemptionDriver;
}

type action =
  | Spawn : t_ReadyToConsume -> action
  | Expire : action
  | Consume : nat -> t_ConsumedGrantObservation -> action
  | Policy : nat -> t_FinalPolicyObservation -> action
  | InsertDone : nat -> t_InsertObservation -> committed_if_failed: bool -> action
  | Recheck : nat -> t_AuthorityRecheckObservation -> action

/// Rows written by an insert attempt: `Inserted` wrote one, `Skipped` none,
/// and an errored attempt may have committed (chosen by the schedule).
let written (obs: t_InsertObservation) (committed_if_failed: bool) : nat =
  match obs with
  | InsertObservation_Inserted -> 1
  | InsertObservation_Skipped -> 0
  | InsertObservation_Failed -> b2n committed_if_failed

/// Deliver an event to request `i` and perform the effect the driver returns.
let deliver (w: world) (i: nat{i < FStar.List.Tot.length w.reqs}) (e: t_RedemptionEvent)
    (grant_mid: bool) (new_rows: nat)
  : world =
  let d = FStar.List.Tot.index w.reqs i in
  // Every reachable request is sound (see `inv`), so the guard never fails;
  // it only discharges `step`'s precondition.
  if redemption_state_is_sound d then
    let t = step d e in
    { grant = (if is_restore t.f_effect then true else grant_mid);
      rows = w.rows + new_rows;
      reqs = update w.reqs i t.f_driver }
  else w

let world_step (w: world) (a: action) : world =
  match a with
  | Spawn ready -> { w with reqs = (begin_redemption ready).f_driver :: w.reqs }
  | Expire -> { w with grant = false }
  | Consume i obs ->
      if i < FStar.List.Tot.length w.reqs && is_consume (FStar.List.Tot.index w.reqs i) then
        if w.grant then
          deliver w i (RedemptionEvent_Consumed (ConsumptionObservation_Present obs)) false 0
        else
          deliver w i (RedemptionEvent_Consumed ConsumptionObservation_Missing) false 0
      else w
  | Policy i obs ->
      if i < FStar.List.Tot.length w.reqs && is_policy (FStar.List.Tot.index w.reqs i)
      then deliver w i (RedemptionEvent_FinalPolicy obs) w.grant 0
      else w
  | InsertDone i obs c ->
      if i < FStar.List.Tot.length w.reqs && is_insert (FStar.List.Tot.index w.reqs i)
      then deliver w i (RedemptionEvent_Insert obs) w.grant (written obs c)
      else w
  | Recheck i obs ->
      if i < FStar.List.Tot.length w.reqs && is_recheck (FStar.List.Tot.index w.reqs i)
      then deliver w i (RedemptionEvent_Recheck obs) w.grant 0
      else w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

/// Token conservation: the grant in the store, rows written and grants held
/// by in-flight requests never exceed one.
let inv (w: world) : prop =
  all_sound w.reqs /\ b2n w.grant + w.rows + held w.reqs <= 1

let deliver_inv (w: world) (i: nat{i < FStar.List.Tot.length w.reqs}) (e: t_RedemptionEvent)
    (grant_mid: bool) (new_rows: nat)
  : Lemma
    (requires (
      inv w /\
      (let d = FStar.List.Tot.index w.reqs i in
       redemption_state_is_sound d ==>
       (let t = step d e in
       b2n grant_mid + new_rows + holds t.f_driver + b2n (is_restore t.f_effect)
         <= b2n w.grant + holds d))))
    (ensures (inv (deliver w i e grant_mid new_rows))) =
  let d = FStar.List.Tot.index w.reqs i in
  index_sound w.reqs i;
  trace_sound_matches_rust d;
  step_tokens d e;
  let t = step d e in
  update_sound w.reqs i t.f_driver;
  update_held w.reqs i t.f_driver

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | Spawn ready ->
      begin_sound ready;
      trace_sound_matches_rust (begin_redemption ready).f_driver
  | Expire -> ()
  | Consume i obs ->
      if i < FStar.List.Tot.length w.reqs && is_consume (FStar.List.Tot.index w.reqs i) then begin
        index_sound w.reqs i;
        let d = FStar.List.Tot.index w.reqs i in
        if w.grant then begin
          let e = RedemptionEvent_Consumed (ConsumptionObservation_Present obs) in
          step_tokens d e;
          deliver_inv w i e false 0
        end else begin
          let e = RedemptionEvent_Consumed ConsumptionObservation_Missing in
          step_tokens d e;
          deliver_inv w i e false 0
        end
      end
  | Policy i obs ->
      if i < FStar.List.Tot.length w.reqs && is_policy (FStar.List.Tot.index w.reqs i) then begin
        index_sound w.reqs i;
        let e = RedemptionEvent_FinalPolicy obs in
        step_tokens (FStar.List.Tot.index w.reqs i) e;
        // A held grant means the store copy is gone.
        update_held w.reqs i (FStar.List.Tot.index w.reqs i);
        deliver_inv w i e w.grant 0
      end
  | InsertDone i obs c ->
      if i < FStar.List.Tot.length w.reqs && is_insert (FStar.List.Tot.index w.reqs i) then begin
        index_sound w.reqs i;
        let e = RedemptionEvent_Insert obs in
        insert_tokens (FStar.List.Tot.index w.reqs i) obs;
        step_tokens (FStar.List.Tot.index w.reqs i) e;
        update_held w.reqs i (FStar.List.Tot.index w.reqs i);
        deliver_inv w i e w.grant (written obs c)
      end
  | Recheck i obs ->
      if i < FStar.List.Tot.length w.reqs && is_recheck (FStar.List.Tot.index w.reqs i) then begin
        index_sound w.reqs i;
        let e = RedemptionEvent_Recheck obs in
        step_tokens (FStar.List.Tot.index w.reqs i) e;
        update_held w.reqs i (FStar.List.Tot.index w.reqs i);
        deliver_inv w i e w.grant 0
      end

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

let initial : world = { grant = true; rows = 0; reqs = [] }

/// Headline theorem: whatever the number of concurrent requests, their
/// interleaving, the observations they receive, grant expiry, and whether
/// errored inserts committed, one grant writes at most one device row.
let one_grant_at_most_one_device (schedule: list action)
  : Lemma ((run_world initial schedule).rows <= 1) =
  run_world_inv initial schedule

// ── Non-vacuity: one device is reachable, and a restore re-arms the grant ──

#push-options "--fuel 4 --ifuel 2"

let consumed_ok : t_ConsumedGrantObservation =
  { f_key_epoch = mk_i64 3; f_possession = false; f_matches_observed_grant = true }

let policy_ok : t_FinalPolicyObservation =
  permitted_policy enrollment_observation_credential

// Each witness is checked one world step at a time; `run_world` over the
// listed schedule is then the composition of those steps.

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

/// One request redeems the grant and writes exactly one device row.
let s1 = world_step initial (Spawn ready_credential)
let s2 = world_step s1 (Consume 0 consumed_ok)
let s3 = world_step s2 (Policy 0 policy_ok)
let s4 = world_step s3 (InsertDone 0 InsertObservation_Inserted false)
let s1_ok () : Lemma (s1.grant = true /\ s1.rows = 0 /\ s1.reqs == [(begin_redemption ready_credential).f_driver]) = ()
let s2_ok () : Lemma (s2.grant = false /\ s2.rows = 0 /\ FStar.List.Tot.length s2.reqs = 1 /\ is_policy (FStar.List.Tot.index s2.reqs 0)) = s1_ok ()
let s3_ok () : Lemma (s3.grant = false /\ s3.rows = 0 /\ FStar.List.Tot.length s3.reqs = 1 /\ is_insert (FStar.List.Tot.index s3.reqs 0)) = s2_ok ()
let s4_ok () : Lemma (s4.grant = false /\ s4.rows = 1) = s3_ok ()

let success_schedule : list action =
  [ Spawn ready_credential;
    Consume 0 consumed_ok;
    Policy 0 policy_ok;
    InsertDone 0 InsertObservation_Inserted false ]

let one_device_is_reachable ()
  : Lemma ((run_world initial success_schedule).rows = 1) =
  run_cons initial (Spawn ready_credential) (FStar.List.Tot.tl success_schedule);
  run_cons s1 (Consume 0 consumed_ok) [Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons s2 (Policy 0 policy_ok) [InsertDone 0 InsertObservation_Inserted false];
  run_cons s3 (InsertDone 0 InsertObservation_Inserted false) [];
  run_nil s4;
  s4_ok ()

/// Two racing requests: while the first holds the grant, the second sees it
/// missing; only one row is written.
let r1 = world_step initial (Spawn ready_credential)
let r2 = world_step r1 (Spawn ready_credential)
let r3 = world_step r2 (Consume 0 consumed_ok)
let r4 = world_step r3 (Consume 1 consumed_ok)
let r5 = world_step r4 (Policy 0 policy_ok)
let r6 = world_step r5 (InsertDone 0 InsertObservation_Inserted false)
let r2_ok () : Lemma (r2.grant = true /\ FStar.List.Tot.length r2.reqs = 2 /\ is_consume (FStar.List.Tot.index r2.reqs 0) /\ is_consume (FStar.List.Tot.index r2.reqs 1)) = ()
let r3_ok () : Lemma (r3.grant = false /\ r3.rows = 0 /\ FStar.List.Tot.length r3.reqs = 2 /\ is_policy (FStar.List.Tot.index r3.reqs 0) /\ is_consume (FStar.List.Tot.index r3.reqs 1)) = r2_ok ()
let r4_ok () : Lemma (r4.grant = false /\ r4.rows = 0 /\ FStar.List.Tot.length r4.reqs = 2 /\ is_policy (FStar.List.Tot.index r4.reqs 0) /\ is_done (FStar.List.Tot.index r4.reqs 1)) = r3_ok ()
let r5_ok () : Lemma (r5.grant = false /\ r5.rows = 0 /\ FStar.List.Tot.length r5.reqs = 2 /\ is_insert (FStar.List.Tot.index r5.reqs 0)) = r4_ok ()
let r6_ok () : Lemma (r6.grant = false /\ r6.rows = 1) = r5_ok ()

let race_schedule : list action =
  [ Spawn ready_credential;
    Spawn ready_credential;
    Consume 0 consumed_ok;
    Consume 1 consumed_ok;
    Policy 0 policy_ok;
    InsertDone 0 InsertObservation_Inserted false ]

let race_writes_one_device ()
  : Lemma (
      let w = run_world initial race_schedule in
      w.rows = 1 /\ w.grant = false) =
  run_cons initial (Spawn ready_credential) (FStar.List.Tot.tl race_schedule);
  run_cons r1 (Spawn ready_credential) [Consume 0 consumed_ok; Consume 1 consumed_ok; Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons r2 (Consume 0 consumed_ok) [Consume 1 consumed_ok; Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons r3 (Consume 1 consumed_ok) [Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons r4 (Policy 0 policy_ok) [InsertDone 0 InsertObservation_Inserted false];
  run_cons r5 (InsertDone 0 InsertObservation_Inserted false) [];
  run_nil r6;
  r6_ok ()

/// A definite zero-row insert during rotation restores the grant, and a later
/// request can then use it: restoration is live, not just safe.
let q1 = s3
let q2 = world_step q1 (InsertDone 0 InsertObservation_Skipped false)
let q3 = world_step q2 (Recheck 0 AuthorityRecheckObservation_StillRotating)
let q4 = world_step q3 (Spawn ready_credential)
let q5 = world_step q4 (Consume 0 consumed_ok)
let q6 = world_step q5 (Policy 0 policy_ok)
let q7 = world_step q6 (InsertDone 0 InsertObservation_Inserted false)
let q2_ok () : Lemma (q2.grant = false /\ q2.rows = 0 /\ FStar.List.Tot.length q2.reqs = 1 /\ is_recheck (FStar.List.Tot.index q2.reqs 0)) = s3_ok ()
let q3_ok () : Lemma (q3.grant = true /\ q3.rows = 0 /\ FStar.List.Tot.length q3.reqs = 1) = q2_ok ()
let q4_ok () : Lemma (q4.grant = true /\ q4.rows = 0 /\ FStar.List.Tot.length q4.reqs = 2 /\ is_consume (FStar.List.Tot.index q4.reqs 0)) = q3_ok ()
let q5_ok () : Lemma (q5.grant = false /\ q5.rows = 0 /\ FStar.List.Tot.length q5.reqs = 2 /\ is_policy (FStar.List.Tot.index q5.reqs 0)) = q4_ok ()
let q6_ok () : Lemma (q6.grant = false /\ q6.rows = 0 /\ FStar.List.Tot.length q6.reqs = 2 /\ is_insert (FStar.List.Tot.index q6.reqs 0)) = q5_ok ()
let q7_ok () : Lemma (q7.rows = 1) = q6_ok ()

let retry_schedule : list action =
  [ Spawn ready_credential;
    Consume 0 consumed_ok;
    Policy 0 policy_ok;
    InsertDone 0 InsertObservation_Skipped false;
    Recheck 0 AuthorityRecheckObservation_StillRotating;
    Spawn ready_credential;
    Consume 0 consumed_ok;
    Policy 0 policy_ok;
    InsertDone 0 InsertObservation_Inserted false ]

let retry_after_rotation_is_reachable ()
  : Lemma ((run_world initial retry_schedule).rows = 1) =
  run_cons initial (Spawn ready_credential) (FStar.List.Tot.tl retry_schedule);
  run_cons s1 (Consume 0 consumed_ok) [Policy 0 policy_ok; InsertDone 0 InsertObservation_Skipped false; Recheck 0 AuthorityRecheckObservation_StillRotating; Spawn ready_credential; Consume 0 consumed_ok; Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons s2 (Policy 0 policy_ok) [InsertDone 0 InsertObservation_Skipped false; Recheck 0 AuthorityRecheckObservation_StillRotating; Spawn ready_credential; Consume 0 consumed_ok; Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons q1 (InsertDone 0 InsertObservation_Skipped false) [Recheck 0 AuthorityRecheckObservation_StillRotating; Spawn ready_credential; Consume 0 consumed_ok; Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons q2 (Recheck 0 AuthorityRecheckObservation_StillRotating) [Spawn ready_credential; Consume 0 consumed_ok; Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons q3 (Spawn ready_credential) [Consume 0 consumed_ok; Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons q4 (Consume 0 consumed_ok) [Policy 0 policy_ok; InsertDone 0 InsertObservation_Inserted false];
  run_cons q5 (Policy 0 policy_ok) [InsertDone 0 InsertObservation_Inserted false];
  run_cons q6 (InsertDone 0 InsertObservation_Inserted false) [];
  run_nil q7;
  q7_ok ()

/// An errored insert that committed leaves the grant consumed: a later
/// request finds no grant (the bug fixed in aaf708f).
let a1 = world_step s3 (InsertDone 0 InsertObservation_Failed true)
let a2 = world_step a1 (Spawn ready_credential)
let a3 = world_step a2 (Consume 0 consumed_ok)
let a1_ok () : Lemma (a1.grant = false /\ a1.rows = 1 /\ FStar.List.Tot.length a1.reqs = 1) = s3_ok ()
let a2_ok () : Lemma (a2.grant = false /\ a2.rows = 1 /\ FStar.List.Tot.length a2.reqs = 2 /\ is_consume (FStar.List.Tot.index a2.reqs 0)) = a1_ok ()
let a3_ok () : Lemma (a3.grant = false /\ a3.rows = 1 /\ FStar.List.Tot.length a3.reqs = 2 /\ is_done (FStar.List.Tot.index a3.reqs 0)) = a2_ok ()

let ambiguous_failure_schedule : list action =
  [ Spawn ready_credential;
    Consume 0 consumed_ok;
    Policy 0 policy_ok;
    InsertDone 0 InsertObservation_Failed true;
    Spawn ready_credential;
    Consume 0 consumed_ok ]

let ambiguous_failure_keeps_grant_consumed ()
  : Lemma (
      let w = run_world initial ambiguous_failure_schedule in
      w.rows = 1 /\ w.grant = false /\
      FStar.List.Tot.length w.reqs = 2 /\ is_done (FStar.List.Tot.index w.reqs 0)) =
  run_cons initial (Spawn ready_credential) (FStar.List.Tot.tl ambiguous_failure_schedule);
  run_cons s1 (Consume 0 consumed_ok) [Policy 0 policy_ok; InsertDone 0 InsertObservation_Failed true; Spawn ready_credential; Consume 0 consumed_ok];
  run_cons s2 (Policy 0 policy_ok) [InsertDone 0 InsertObservation_Failed true; Spawn ready_credential; Consume 0 consumed_ok];
  run_cons s3 (InsertDone 0 InsertObservation_Failed true) [Spawn ready_credential; Consume 0 consumed_ok];
  run_cons a1 (Spawn ready_credential) [Consume 0 consumed_ok];
  run_cons a2 (Consume 0 consumed_ok) [];
  run_nil a3;
  a3_ok ()

#pop-options
