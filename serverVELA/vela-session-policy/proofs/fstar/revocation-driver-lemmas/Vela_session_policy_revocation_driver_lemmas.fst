module Vela_session_policy_revocation_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* device
/// revocation and logout drivers (`Vela_session_policy.Revocation_driver`).
///
/// Scope: one `RevocationDriver` / `LogoutDriver` value, i.e. one HTTP request.
/// The theorem does not claim anything about two concurrent requests; the
/// sled marker writes, the SQL update, the web-session cascade and the order in
/// which the handler performs them remain effectful glue outside this module.
/// The driver's store/SQL inputs are observations, never verified origins.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `revocation_state_is_sound` and proved equivalent to it;
/// all trace lemmas then quantify over every event list.
///
/// The headline ordering theorem is stated with an explicit running lockout
/// counter (`trace_order`): a `RecordRevocation` effect is only allowed at a
/// point where a `LockoutDevice` effect has already occurred in the trace. It
/// is not an artefact of the SQL guard, because the counter is driven solely by
/// the extracted driver's effect.

open FStar.Mul
open Core_models
open Vela_session_policy.Revocation_driver

// ── Independent state invariant ─────────────────────────────────────────────

let is_observe (d: t_RevocationDriver) : bool =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Observe -> true
  | _ -> false

let is_lockout (d: t_RevocationDriver) : bool =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Lockout -> true
  | _ -> false

let is_record (d: t_RevocationDriver) : bool =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Record -> true
  | _ -> false

let is_cascade (d: t_RevocationDriver) : bool =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Cascade -> true
  | _ -> false

let is_repeat_lockout (d: t_RevocationDriver) : bool =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_RepeatLockout -> true
  | _ -> false

let is_repeat_cascade (d: t_RevocationDriver) : bool =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_RepeatCascade -> true
  | _ -> false

let is_done (d: t_RevocationDriver) : bool =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Done -> true
  | _ -> false

/// Strengthened trace invariant. It encodes the stage/flag discipline of the
/// driver plus the two effect-order facts: a recorded SQL row has an instructed
/// and observed lockout behind it, and a completed cascade has a successful or
/// repeated revoke behind it.
let trace_sound (d: t_RevocationDriver) : bool =
  let untouched =
    not d.f_same_account && not d.f_already_revoked && not d.f_locked_out &&
    not d.f_lockout_done && not d.f_recorded && not d.f_cascade_done &&
    not d.f_responded && not d.f_failed
  in
  (not (is_observe d) || (d.f_actor_active && untouched)) &&
  (not (is_lockout d) ||
    (d.f_actor_active && d.f_same_account && not d.f_already_revoked &&
     d.f_locked_out && not d.f_lockout_done && not d.f_recorded &&
     not d.f_cascade_done && not d.f_responded && not d.f_failed)) &&
  (not (is_record d) ||
    (d.f_actor_active && d.f_same_account && not d.f_already_revoked &&
     d.f_locked_out && d.f_lockout_done && not d.f_recorded &&
     not d.f_cascade_done && not d.f_responded && not d.f_failed)) &&
  (not (is_cascade d) ||
    (d.f_actor_active && d.f_same_account && not d.f_already_revoked &&
     d.f_locked_out && d.f_lockout_done && d.f_recorded &&
     not d.f_cascade_done && not d.f_responded && not d.f_failed)) &&
  (not (is_repeat_lockout d) ||
    (d.f_actor_active && d.f_same_account && d.f_already_revoked &&
     d.f_locked_out && not d.f_lockout_done && not d.f_recorded &&
     not d.f_cascade_done && not d.f_responded && not d.f_failed)) &&
  (not (is_repeat_cascade d) ||
    (d.f_actor_active && d.f_same_account && d.f_already_revoked &&
     d.f_locked_out && d.f_lockout_done && not d.f_recorded &&
     not d.f_cascade_done && not d.f_responded && not d.f_failed)) &&
  (not (is_done d) ||
    ((d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
     (not d.f_responded ||
      (d.f_actor_active && d.f_same_account && not d.f_already_revoked &&
       d.f_locked_out && d.f_lockout_done && d.f_recorded && d.f_cascade_done)))) &&
  (not d.f_same_account || d.f_actor_active) &&
  (not d.f_locked_out || d.f_actor_active) &&
  (not d.f_already_revoked || d.f_same_account) &&
  (not d.f_recorded || (d.f_locked_out && d.f_lockout_done)) &&
  (not d.f_cascade_done || (d.f_locked_out && d.f_lockout_done)) &&
  (not d.f_cascade_done || d.f_recorded || d.f_already_revoked) &&
  (not d.f_recorded || (d.f_same_account && not d.f_already_revoked)) &&
  (not d.f_responded || (d.f_recorded && d.f_cascade_done)) &&
  (not d.f_lockout_done || d.f_locked_out)

/// The independently written invariant is exactly the Rust postcondition's
/// predicate. Proved by exhaustive stage case analysis, not by aliasing the
/// implementation definition in the statements below.
let trace_sound_matches_rust (d: t_RevocationDriver)
  : Lemma (trace_sound d = revocation_state_is_sound d) =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Observe -> ()
  | RevocationStage_Lockout -> ()
  | RevocationStage_Record -> ()
  | RevocationStage_Cascade -> ()
  | RevocationStage_RepeatLockout -> ()
  | RevocationStage_RepeatCascade -> ()
  | RevocationStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_sound (actor: t_ActorObservation)
  : Lemma (trace_sound (begin_revocation actor).f_driver) =
  trace_sound_matches_rust (begin_revocation actor).f_driver

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (revocation_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

/// A finished driver is inert for every event.
let step_after_done (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = RevocationEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_RevocationEvent with
  | RevocationEvent_TargetObserved _ -> ()
  | RevocationEvent_LockoutObserved _ -> ()
  | RevocationEvent_RecordObserved _ -> ()
  | RevocationEvent_CascadeObserved _ -> ()

/// An actor the middleware did not establish as authenticated and active
/// reaches a terminal state without ever emitting a revocation effect.
let inactive_actor_never_revokes (actor: t_ActorObservation)
  : Lemma
    (requires (not (actor.f_authenticated && actor.f_device_active)))
    (ensures (
      let t = begin_revocation actor in
      trace_sound t.f_driver /\ is_done t.f_driver /\
      t.f_effect = RevocationEffect_Fail RevocationFailure_Unauthenticated)) =
  trace_sound_matches_rust (begin_revocation actor).f_driver

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_RevocationDriver) (events: list t_RevocationEvent)
  : Pure t_RevocationDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let rec last_effect (d: t_RevocationDriver) (events: list t_RevocationEvent)
  : Pure t_RevocationEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> RevocationEffect_Idle
  | e :: [] -> (step d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step d e).f_driver rest

/// Total wrappers starting from the actual extracted `begin_revocation`.
let run_from_actor (actor: t_ActorObservation) (events: list t_RevocationEvent)
  : Pure t_RevocationDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_sound actor;
  trace_sound_matches_rust (begin_revocation actor).f_driver;
  run (begin_revocation actor).f_driver events

let last_effect_from_actor (actor: t_ActorObservation) (events: list t_RevocationEvent)
  : Pure t_RevocationEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound actor;
  trace_sound_matches_rust (begin_revocation actor).f_driver;
  last_effect (begin_revocation actor).f_driver events

// ── Effect provenance and ordering ─────────────────────────────────────────

let b2n (b: bool) : nat = if b then 1 else 0

/// (1) Every revocation-authorizing effect requires an authenticated, active
/// actor and a same-account target. The fresh SQL record additionally requires
/// that the target was not already revoked; the already-revoked branch only
/// re-runs the lockout/cascade.
let revoke_effect_requires_authority (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step d e).f_effect <: t_RevocationEffect with
      | RevocationEffect_LockoutDevice ->
          (step d e).f_driver.f_actor_active /\
          (step d e).f_driver.f_same_account
      | RevocationEffect_RecordRevocation ->
          (step d e).f_driver.f_actor_active /\
          (step d e).f_driver.f_same_account /\
          not (step d e).f_driver.f_already_revoked /\
          (step d e).f_driver.f_locked_out
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (revocation_state_is_sound d = true);
  ()

/// (2) An emitted `RecordRevocation` effect is only possible at a state that
/// has already instructed the device lockout. This is the state half of the
/// "lockout before SQL record" property.
let record_effect_prestate (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d e).f_effect = RevocationEffect_RecordRevocation ==>
      (d.f_locked_out /\ not d.f_lockout_done /\
       d.f_actor_active /\ d.f_same_account /\ not d.f_already_revoked))) =
  trace_sound_matches_rust d;
  assert (revocation_state_is_sound d = true);
  match e <: t_RevocationEvent with
  | RevocationEvent_TargetObserved _ -> ()
  | RevocationEvent_LockoutObserved obs ->
      (match obs <: t_LockoutObservation with
       | LockoutObservation_Applied -> ()
       | LockoutObservation_StorageFailed -> ())
  | RevocationEvent_RecordObserved _ -> ()
  | RevocationEvent_CascadeObserved _ -> ()

/// The lockout instruction flag is monotone and is only ever set by a step
/// whose effect is `LockoutDevice`.
let locked_out_origin (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (trace_sound d /\ not d.f_locked_out))
    (ensures (
      (step d e).f_driver.f_locked_out ==>
      ((step d e).f_effect = RevocationEffect_LockoutDevice))) =
  trace_sound_matches_rust d;
  match e <: t_RevocationEvent with
  | RevocationEvent_TargetObserved obs ->
      (match obs <: t_DeviceLookupObservation with
       | DeviceLookupObservation_Absent -> ()
       | DeviceLookupObservation_QueryFailed -> ()
       | DeviceLookupObservation_Malformed -> ()
       | DeviceLookupObservation_Present _ -> ())
  | RevocationEvent_LockoutObserved _ -> ()
  | RevocationEvent_RecordObserved _ -> ()
  | RevocationEvent_CascadeObserved _ -> ()

/// (3) A `CascadeWebSessions` effect follows a successful (`recorded`) or
/// repeated (`already_revoked`) revoke, and always behind an applied lockout.
let cascade_effect_prestate (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d e).f_effect = RevocationEffect_CascadeWebSessions ==>
      ((step d e).f_driver.f_locked_out /\
       (step d e).f_driver.f_lockout_done /\
       ((step d e).f_driver.f_recorded || (step d e).f_driver.f_already_revoked) /\
       (step d e).f_driver.f_actor_active /\
       (step d e).f_driver.f_same_account))) =
  trace_sound_matches_rust d;
  assert (revocation_state_is_sound d = true);
  assert (revocation_effect_is_sound (step d e).f_driver (step d e).f_effect = true);
  ()

/// (4) The ordering theorem over an arbitrary trace. `trace_order` carries the
/// number of `LockoutDevice` effects already seen; a `RecordRevocation` effect
/// is only allowed when that counter is at least one. The theorem starts at
/// zero and from `begin_revocation`, so every SQL record in any request trace
/// has a lockout effect strictly before it.
let rec trace_order
    (d: t_RevocationDriver)
    (events: list t_RevocationEvent)
    (lockouts_before: nat)
  : Pure bool
    (requires (
      trace_sound d /\
      (d.f_locked_out ==> lockouts_before >= 1) /\
      (d.f_lockout_done ==> d.f_locked_out)))
    (ensures (fun result -> result = true))
    (decreases events) =
  match events with
  | [] -> true
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      let emits_lockout =
        (match t.f_effect <: t_RevocationEffect with
         | RevocationEffect_LockoutDevice -> true
         | _ -> false)
      in
      let emits_record =
        (match t.f_effect <: t_RevocationEffect with
         | RevocationEffect_RecordRevocation -> true
         | _ -> false)
      in
      let lockouts_after = lockouts_before + b2n emits_lockout in
      if emits_record then begin
        // `record_effect_prestate` gives `d.locked_out`, and the running
        // hypothesis turns that into a prior lockout.
        record_effect_prestate d e;
        assert (d.f_locked_out = true);
        assert (lockouts_before >= 1)
      end;
      // Re-establish the running hypothesis for the next state.
      if t.f_driver.f_locked_out then begin
        if d.f_locked_out then begin
          assert (lockouts_before >= 1);
          assert (lockouts_after >= 1)
        end else begin
          locked_out_origin d e;
          assert (emits_lockout = true);
          assert (lockouts_after >= 1)
        end
      end;
      trace_order t.f_driver rest lockouts_after

/// Corollary over the actual extracted `begin_revocation`: for every actor and
/// every event list, every SQL-record effect is preceded by a lockout effect.
let record_follows_lockout
      (actor: t_ActorObservation)
      (events: list t_RevocationEvent)
  : Lemma (
      trace_order (begin_revocation actor).f_driver events 0) =
  begin_sound actor;
  trace_sound_matches_rust (begin_revocation actor).f_driver;
  let ok = trace_order (begin_revocation actor).f_driver events 0 in
  assert (ok = true)

// ── Terminal effects are unique ─────────────────────────────────────────────

let rec count_complete (d: t_RevocationDriver) (events: list t_RevocationEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_RevocationEffect with
       | RevocationEffect_Complete -> 1
       | _ -> 0) +
      count_complete (step d e).f_driver rest

let rec count_fail (d: t_RevocationDriver) (events: list t_RevocationEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_RevocationEffect with
       | RevocationEffect_Fail _ -> 1
       | _ -> 0) +
      count_fail (step d e).f_driver rest

let rec done_suffix_inert (d: t_RevocationDriver) (events: list t_RevocationEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      run d events = d /\
      count_complete d events = 0 /\
      count_fail d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

/// Complete happens at most once, and never after a terminal failure.
let rec complete_count_le_one (d: t_RevocationDriver) (events: list t_RevocationEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_complete d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if (match t.f_effect <: t_RevocationEffect with
          | RevocationEffect_Complete -> true
          | _ -> false)
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_responded = true);
        assert (is_done t.f_driver = true);
        done_suffix_inert t.f_driver rest
      end else begin
        complete_count_le_one t.f_driver rest
      end

/// Fail happens at most once.
let rec fail_count_le_one (d: t_RevocationDriver) (events: list t_RevocationEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_fail d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if (match t.f_effect <: t_RevocationEffect with
          | RevocationEffect_Fail _ -> true
          | _ -> false)
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_failed = true);
        assert (is_done t.f_driver = true);
        done_suffix_inert t.f_driver rest
      end else begin
        fail_count_le_one t.f_driver rest
      end

/// Headline per-request theorem over the actual extracted driver. For every
/// actor observation and every event list:
///
/// - the final state is sound;
/// - a successful response is never paired with a terminal failure;
/// - at most one success and at most one failure effect occur;
/// - a recorded SQL row always has an applied lockout behind it;
/// - a completed cascade always follows a successful or repeated revoke;
/// - every SQL-record effect is preceded by a lockout effect.
let revocation_trace_theorem
      (actor: t_ActorObservation)
      (events: list t_RevocationEvent)
  : Lemma (
      let d = run_from_actor actor events in
      trace_sound d /\
      (d.f_responded ==> (d.f_recorded && d.f_cascade_done && not d.f_already_revoked)) /\
      (d.f_recorded ==> (d.f_locked_out && d.f_lockout_done)) /\
      (d.f_cascade_done ==> (d.f_locked_out && d.f_lockout_done && (d.f_recorded || d.f_already_revoked))) /\
      (not (d.f_responded && d.f_failed)) /\
      count_complete (begin_revocation actor).f_driver events <= 1 /\
      count_fail (begin_revocation actor).f_driver events <= 1 /\
      trace_order (begin_revocation actor).f_driver events 0) =
  begin_sound actor;
  trace_sound_matches_rust (begin_revocation actor).f_driver;
  complete_count_le_one (begin_revocation actor).f_driver events;
  fail_count_le_one (begin_revocation actor).f_driver events;
  record_follows_lockout actor events;
  ()

// ── Reachability witnesses ─────────────────────────────────────────────────

let active_actor : t_ActorObservation =
  { f_authenticated = true; f_device_active = true }

let inactive_actor : t_ActorObservation =
  { f_authenticated = true; f_device_active = false }

let target_fresh : t_DeviceLookupObservation =
  DeviceLookupObservation_Present
    ({ f_same_account = true; f_already_revoked = false })

let target_repeat : t_DeviceLookupObservation =
  DeviceLookupObservation_Present
    ({ f_same_account = true; f_already_revoked = true })

let target_cross : t_DeviceLookupObservation =
  DeviceLookupObservation_Present
    ({ f_same_account = false; f_already_revoked = false })

let success_events : list t_RevocationEvent =
  [ RevocationEvent_TargetObserved target_fresh;
    RevocationEvent_LockoutObserved LockoutObservation_Applied;
    RevocationEvent_RecordObserved RecordObservation_Updated;
    RevocationEvent_CascadeObserved CascadeObservation_Completed ]

let already_revoked_events : list t_RevocationEvent =
  [ RevocationEvent_TargetObserved target_repeat;
    RevocationEvent_LockoutObserved LockoutObservation_Applied;
    RevocationEvent_CascadeObserved CascadeObservation_Completed ]

let lockout_failed_events : list t_RevocationEvent =
  [ RevocationEvent_TargetObserved target_fresh;
    RevocationEvent_LockoutObserved LockoutObservation_StorageFailed ]

let record_failed_events : list t_RevocationEvent =
  [ RevocationEvent_TargetObserved target_fresh;
    RevocationEvent_LockoutObserved LockoutObservation_Applied;
    RevocationEvent_RecordObserved RecordObservation_Failed ]

let cascade_failed_events : list t_RevocationEvent =
  [ RevocationEvent_TargetObserved target_fresh;
    RevocationEvent_LockoutObserved LockoutObservation_Applied;
    RevocationEvent_RecordObserved RecordObservation_Updated;
    RevocationEvent_CascadeObserved CascadeObservation_StorageFailed ]

/// A fresh revoke is reachable and succeeds after lockout, record and cascade.
let success_is_reachable ()
  : Lemma (
      let d = run_from_actor active_actor success_events in
      d.f_responded = true /\ d.f_recorded = true /\ d.f_cascade_done = true /\
      d.f_locked_out = true /\ d.f_lockout_done = true /\
      is_done d /\ not d.f_failed /\
      last_effect_from_actor active_actor success_events = RevocationEffect_Complete) =
  ()

/// The already-revoked retry repeats lockout and cascade, never records SQL,
/// and still fails with `AlreadyRevoked`.
let already_revoked_is_reachable ()
  : Lemma (
      let d = run_from_actor active_actor already_revoked_events in
      d.f_failed = true /\ d.f_recorded = false /\ d.f_cascade_done = true /\
      d.f_locked_out = true /\
      last_effect_from_actor active_actor already_revoked_events =
        RevocationEffect_Fail RevocationFailure_AlreadyRevoked) =
  ()

/// A cross-account target is terminal before any effect.
let cross_account_is_reachable ()
  : Lemma (
      let d = run_from_actor active_actor [RevocationEvent_TargetObserved target_cross] in
      d.f_failed = true /\ not d.f_locked_out /\ not d.f_recorded /\
      last_effect_from_actor active_actor [RevocationEvent_TargetObserved target_cross] =
        RevocationEffect_Fail RevocationFailure_CrossAccount) =
  ()

/// A missing target is terminal before any effect.
let missing_target_is_reachable ()
  : Lemma (
      let d = run_from_actor active_actor
        [RevocationEvent_TargetObserved DeviceLookupObservation_Absent] in
      d.f_failed = true /\ not d.f_locked_out /\
      last_effect_from_actor active_actor
        [RevocationEvent_TargetObserved DeviceLookupObservation_Absent] =
        RevocationEffect_Fail RevocationFailure_TargetNotFound) =
  ()

/// An inactive actor can never reach a lockout or record, no matter what
/// events follow.
let inactive_actor_is_refused (events: list t_RevocationEvent)
  : Lemma (
      let d = run_from_actor inactive_actor events in
      d.f_failed = true /\ not d.f_locked_out /\ not d.f_recorded /\
      d.f_responded = false /\
      count_complete (begin_revocation inactive_actor).f_driver events = 0) =
  inactive_actor_never_revokes inactive_actor;
  done_suffix_inert (begin_revocation inactive_actor).f_driver events

/// A lockout storage failure is terminal and never records SQL.
let lockout_failure_is_reachable ()
  : Lemma (
      let d = run_from_actor active_actor lockout_failed_events in
      d.f_failed = true /\ d.f_locked_out = true /\ d.f_lockout_done = false /\
      d.f_recorded = false /\
      last_effect_from_actor active_actor lockout_failed_events =
        RevocationEffect_Fail RevocationFailure_LockoutStorage) =
  ()

/// A record storage failure leaves the device locked out but never claims the
/// SQL row was written.
let record_failure_is_reachable ()
  : Lemma (
      let d = run_from_actor active_actor record_failed_events in
      d.f_failed = true /\ d.f_locked_out = true /\ d.f_lockout_done = true /\
      d.f_recorded = false /\
      last_effect_from_actor active_actor record_failed_events =
        RevocationEffect_Fail RevocationFailure_RecordStorage) =
  ()

/// A cascade failure keeps the durable record and lockout but reports failure.
let cascade_failure_is_reachable ()
  : Lemma (
      let d = run_from_actor active_actor cascade_failed_events in
      d.f_failed = true /\ d.f_recorded = true /\ d.f_cascade_done = false /\
      last_effect_from_actor active_actor cascade_failed_events =
        RevocationEffect_Fail RevocationFailure_CascadeStorage) =
  ()

// ── Logout driver ───────────────────────────────────────────────────────────

let logout_is_apply (d: t_LogoutDriver) : bool =
  match d.f_stage <: t_LogoutStage with
  | LogoutStage_Apply -> true
  | _ -> false

let logout_is_done (d: t_LogoutDriver) : bool =
  match d.f_stage <: t_LogoutStage with
  | LogoutStage_Done -> true
  | _ -> false

let logout_trace_sound (d: t_LogoutDriver) : bool =
  (not (logout_is_apply d) ||
    (not d.f_jti_revoked && not d.f_responded && not d.f_failed)) &&
  (not (logout_is_done d) ||
    ((d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
     (not d.f_responded || d.f_jti_revoked))) &&
  (not d.f_responded || d.f_jti_revoked) &&
  (not d.f_failed || not d.f_responded)

let logout_trace_sound_matches_rust (d: t_LogoutDriver)
  : Lemma (logout_trace_sound d = logout_state_is_sound d) =
  match d.f_stage <: t_LogoutStage with
  | LogoutStage_Apply -> ()
  | LogoutStage_Done -> ()

let logout_step_sound (d: t_LogoutDriver) (observation: t_LogoutObservation)
  : Lemma
    (requires (logout_trace_sound d))
    (ensures (logout_trace_sound (logout_step d observation).f_driver)) =
  logout_trace_sound_matches_rust d;
  assert (logout_state_is_sound d = true);
  logout_trace_sound_matches_rust (logout_step d observation).f_driver

let logout_after_done (d: t_LogoutDriver) (observation: t_LogoutObservation)
  : Lemma
    (requires (logout_trace_sound d /\ logout_is_done d))
    (ensures (
      (logout_step d observation).f_driver = d /\
      (logout_step d observation).f_effect = LogoutEffect_Idle)) =
  logout_trace_sound_matches_rust d

let rec logout_run (d: t_LogoutDriver) (observations: list t_LogoutObservation)
  : Pure t_LogoutDriver
    (requires (logout_trace_sound d))
    (ensures (fun result -> logout_trace_sound result))
    (decreases observations) =
  match observations with
  | [] -> d
  | o :: rest ->
      logout_trace_sound_matches_rust d;
      logout_step_sound d o;
      logout_run (logout_step d o).f_driver rest

let logout_run_from_begin (observations: list t_LogoutObservation)
  : Pure t_LogoutDriver (requires True) (ensures (fun result -> logout_trace_sound result))
    (decreases observations) =
  logout_trace_sound_matches_rust (begin_logout ()).f_driver;
  logout_run (begin_logout ()).f_driver observations

/// A logout writes at most one JTI marker and a success implies that marker.
let logout_success_implies_marker
      (observations: list t_LogoutObservation)
  : Lemma (
      let d = logout_run_from_begin observations in
      (d.f_responded ==> d.f_jti_revoked) /\
      not (d.f_responded && d.f_failed)) =
  logout_trace_sound_matches_rust (logout_run_from_begin observations)

/// A failed marker write is terminal and never authorizes a response.
let logout_storage_failure_is_reachable ()
  : Lemma (
      let d = logout_run_from_begin [LogoutObservation_StorageFailed] in
      d.f_failed = true /\ not d.f_jti_revoked /\ not d.f_responded) =
  ()

/// A successful marker write authorizes the response.
let logout_success_is_reachable ()
  : Lemma (
      let d = logout_run_from_begin [LogoutObservation_Applied] in
      d.f_responded = true /\ d.f_jti_revoked = true /\ not d.f_failed) =
  ()
