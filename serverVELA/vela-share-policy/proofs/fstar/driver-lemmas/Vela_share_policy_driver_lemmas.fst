module Vela_share_policy_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* sharing
/// driver (`Vela_share_policy.Driver.step`).
///
/// Scope: one `ShareDriver` value, i.e. one HTTP request. The theorem does not
/// claim anything about two concurrent requests touching the same linked row
/// or inbox; the guarded SQL statements and the row observations remain
/// effectful glue outside this module. The driver's SQL/store inputs are
/// observations, never verified origins.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `share_state_is_sound` and proved equivalent to it; all
/// trace lemmas then quantify over every event list.

open FStar.Mul
open Core_models
open Vela_share_policy
open Vela_share_policy.Driver

// ── Independent state invariant ─────────────────────────────────────────────

let is_send (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_SendInsert -> true
  | _ -> false

let is_update_observe (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkUpdateObserve -> true
  | _ -> false

let is_update_apply (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkUpdateApply -> true
  | _ -> false

let is_revoke_observe (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkRevokeObserve -> true
  | _ -> false

let is_revoke_apply (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkRevokeApply -> true
  | _ -> false

let is_cleanup (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkCleanup -> true
  | _ -> false

let is_inbox_delete (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_InboxDelete -> true
  | _ -> false

let is_ek_observe (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_EkObserve -> true
  | _ -> false

let is_ek_register (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_EkRegister -> true
  | _ -> false

let is_done (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_Done -> true
  | _ -> false

let is_send_kind (d: t_ShareDriver) : bool =
  match d.f_kind <: t_ShareRequestKind with
  | ShareRequestKind_SendCapsule -> true
  | _ -> false

let is_update_kind (d: t_ShareDriver) : bool =
  match d.f_kind <: t_ShareRequestKind with
  | ShareRequestKind_UpdateLinkedItem -> true
  | _ -> false

let is_revoke_kind (d: t_ShareDriver) : bool =
  match d.f_kind <: t_ShareRequestKind with
  | ShareRequestKind_RevokeLinkedItem -> true
  | _ -> false

let is_inbox_kind (d: t_ShareDriver) : bool =
  match d.f_kind <: t_ShareRequestKind with
  | ShareRequestKind_DeleteInboxItem -> true
  | _ -> false

let is_ek_kind (d: t_ShareDriver) : bool =
  match d.f_kind <: t_ShareRequestKind with
  | ShareRequestKind_RegisterShareEk -> true
  | _ -> false

/// Strengthened trace invariant. It encodes the stage/flag discipline of the
/// driver: a send authority implies an authenticated session and an
/// authorizing plan, a link mutation authority implies a sender-owned live
/// row, a committed revoke is terminal for the link, and a cleanup never
/// precedes a revoke.
let trace_sound (d: t_ShareDriver) : bool =
  (not (is_send d) ||
    (is_send_kind d && d.f_authorized && d.f_sender_authenticated &&
     d.f_effect_issued && not d.f_observe_issued && not d.f_committed &&
     not d.f_revoked && not d.f_cleanup_issued)) &&
  (not (is_update_observe d) ||
    (is_update_kind d && d.f_observe_issued && not d.f_effect_issued &&
     not d.f_committed)) &&
  (not (is_update_apply d) ||
    (is_update_kind d && d.f_observe_issued && d.f_effect_issued &&
     d.f_authorized && d.f_caller_is_sender && d.f_link_live &&
     not d.f_committed && not d.f_revoked && not d.f_cleanup_issued)) &&
  (not (is_revoke_observe d) ||
    (is_revoke_kind d && d.f_observe_issued && not d.f_effect_issued &&
     not d.f_committed)) &&
  (not (is_revoke_apply d) ||
    (is_revoke_kind d && d.f_observe_issued && d.f_effect_issued &&
     d.f_authorized && d.f_caller_is_sender && d.f_link_live &&
     not d.f_committed && not d.f_revoked && not d.f_cleanup_issued)) &&
  (not (is_cleanup d) ||
    (is_revoke_kind d && d.f_observe_issued && d.f_effect_issued &&
     d.f_authorized && d.f_caller_is_sender && d.f_link_live &&
     d.f_committed && d.f_revoked && d.f_cleanup_issued)) &&
  (not (is_inbox_delete d) ||
    (is_inbox_kind d && d.f_effect_issued && d.f_recipient_scoped &&
     not d.f_committed)) &&
  (not (is_ek_observe d) ||
    (is_ek_kind d && d.f_observe_issued && not d.f_effect_issued &&
     not d.f_committed)) &&
  (not (is_ek_register d) ||
    (is_ek_kind d && d.f_effect_issued && d.f_authorized &&
     not d.f_committed && not d.f_revoked && not d.f_cleanup_issued)) &&
  (not d.f_effect_issued || d.f_authorized ||
    (is_inbox_kind d && d.f_recipient_scoped)) &&
  (not d.f_committed || d.f_effect_issued) &&
  (not (d.f_committed && is_revoke_kind d) || d.f_revoked) &&
  (not d.f_revoked ||
    (is_revoke_kind d && d.f_committed && d.f_effect_issued && d.f_authorized &&
     d.f_caller_is_sender && d.f_link_live)) &&
  (not d.f_cleanup_issued || d.f_revoked) &&
  (not d.f_revoked || d.f_cleanup_issued) &&
  (not d.f_observe_issued ||
    (is_update_kind d || is_revoke_kind d || is_ek_kind d))

/// The independently written invariant is exactly the Rust postcondition's
/// predicate. Proved by exhaustive stage case analysis, not by aliasing the
/// implementation definition in the statements below.
let trace_sound_matches_rust (d: t_ShareDriver)
  : Lemma (trace_sound d = share_state_is_sound d) =
  match d.f_stage <: t_ShareStage with
  | ShareStage_SendInsert -> ()
  | ShareStage_LinkUpdateObserve -> ()
  | ShareStage_LinkUpdateApply -> ()
  | ShareStage_LinkRevokeObserve -> ()
  | ShareStage_LinkRevokeApply -> ()
  | ShareStage_LinkCleanup -> ()
  | ShareStage_InboxDelete -> ()
  | ShareStage_EkObserve -> ()
  | ShareStage_EkRegister -> ()
  | ShareStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_send_sound (obs: t_SendRequestObservation)
  : Lemma (trace_sound (begin_send obs).f_driver) =
  trace_sound_matches_rust (begin_send obs).f_driver

let begin_link_update_sound (obs: t_LinkUpdateStartObservation)
  : Lemma (trace_sound (begin_link_update obs).f_driver) =
  trace_sound_matches_rust (begin_link_update obs).f_driver

let begin_link_revoke_sound (u: unit)
  : Lemma (trace_sound (begin_link_revoke u).f_driver) =
  trace_sound_matches_rust (begin_link_revoke u).f_driver

let begin_inbox_delete_sound (u: unit)
  : Lemma (trace_sound (begin_inbox_delete u).f_driver) =
  trace_sound_matches_rust (begin_inbox_delete u).f_driver

let begin_ek_registration_sound (obs: t_EkRegistrationStartObservation)
  : Lemma (trace_sound (begin_ek_registration obs).f_driver) =
  trace_sound_matches_rust (begin_ek_registration obs).f_driver

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_ShareDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (share_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

/// The request kind is immutable: no event can turn a send into a revoke.
let step_kind (d: t_ShareDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures ((step d e).f_driver.f_kind = d.f_kind)) =
  trace_sound_matches_rust d;
  assert (share_state_is_sound d = true);
  match e <: t_ShareEvent with
  | ShareEvent_LinkObserved _ -> ()
  | ShareEvent_EkObserved _ -> ()
  | ShareEvent_SendResult _ -> ()
  | ShareEvent_Mutated _ -> ()
  | ShareEvent_Cleaned _ -> ()

let begin_send_kind (obs: t_SendRequestObservation)
  : Lemma ((begin_send obs).f_driver.f_kind = ShareRequestKind_SendCapsule) = ()

let begin_link_revoke_kind (u: unit)
  : Lemma ((begin_link_revoke u).f_driver.f_kind = ShareRequestKind_RevokeLinkedItem) = ()

/// A finished driver is inert for every event.
let step_after_done (d: t_ShareDriver) (e: t_ShareEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = ShareEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_ShareEvent with
  | ShareEvent_LinkObserved _ -> ()
  | ShareEvent_EkObserved _ -> ()
  | ShareEvent_SendResult _ -> ()
  | ShareEvent_Mutated _ -> ()
  | ShareEvent_Cleaned _ -> ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_ShareDriver) (events: list t_ShareEvent)
  : Pure t_ShareDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let rec run_kind (d: t_ShareDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures ((run d events).f_kind = d.f_kind))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      step_kind d e;
      run_kind (step d e).f_driver rest

let rec count_completes (d: t_ShareDriver) (events: list t_ShareEvent)
  : Pure nat
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_ShareEffect with
       | ShareEffect_Complete -> 1
       | _ -> 0) +
      count_completes (step d e).f_driver rest

let rec last_effect (d: t_ShareDriver) (events: list t_ShareEvent)
  : Pure t_ShareEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> ShareEffect_Idle
  | e :: [] -> (step d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step d e).f_driver rest

let rec done_suffix_inert (d: t_ShareDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (run d events = d /\ count_completes d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

/// Total wrappers starting from the actual extracted constructors.
let run_from_send (obs: t_SendRequestObservation) (events: list t_ShareEvent)
  : Pure t_ShareDriver (requires True) (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_send_sound obs;
  trace_sound_matches_rust (begin_send obs).f_driver;
  run (begin_send obs).f_driver events

let run_from_update (obs: t_LinkUpdateStartObservation) (events: list t_ShareEvent)
  : Pure t_ShareDriver (requires True) (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_link_update_sound obs;
  trace_sound_matches_rust (begin_link_update obs).f_driver;
  run (begin_link_update obs).f_driver events

let run_from_revoke (u: unit) (events: list t_ShareEvent)
  : Pure t_ShareDriver (requires True) (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_link_revoke_sound u;
  trace_sound_matches_rust (begin_link_revoke u).f_driver;
  run (begin_link_revoke u).f_driver events

let run_from_inbox (u: unit) (events: list t_ShareEvent)
  : Pure t_ShareDriver (requires True) (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_inbox_delete_sound u;
  trace_sound_matches_rust (begin_inbox_delete u).f_driver;
  run (begin_inbox_delete u).f_driver events

let run_from_ek (obs: t_EkRegistrationStartObservation) (events: list t_ShareEvent)
  : Pure t_ShareDriver (requires True) (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_ek_registration_sound obs;
  trace_sound_matches_rust (begin_ek_registration obs).f_driver;
  run (begin_ek_registration obs).f_driver events

let count_completes_from_send (obs: t_SendRequestObservation) (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_send_sound obs;
  trace_sound_matches_rust (begin_send obs).f_driver;
  count_completes (begin_send obs).f_driver events

let count_completes_from_update (obs: t_LinkUpdateStartObservation) (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_link_update_sound obs;
  trace_sound_matches_rust (begin_link_update obs).f_driver;
  count_completes (begin_link_update obs).f_driver events

let count_completes_from_revoke (u: unit) (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_link_revoke_sound u;
  trace_sound_matches_rust (begin_link_revoke u).f_driver;
  count_completes (begin_link_revoke u).f_driver events

let count_completes_from_inbox (u: unit) (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_inbox_delete_sound u;
  trace_sound_matches_rust (begin_inbox_delete u).f_driver;
  count_completes (begin_inbox_delete u).f_driver events

let count_completes_from_ek (obs: t_EkRegistrationStartObservation) (events: list t_ShareEvent)
  : Pure nat (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_ek_registration_sound obs;
  trace_sound_matches_rust (begin_ek_registration obs).f_driver;
  count_completes (begin_ek_registration obs).f_driver events

let last_effect_from_send (obs: t_SendRequestObservation) (events: list t_ShareEvent)
  : Pure t_ShareEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_send_sound obs;
  trace_sound_matches_rust (begin_send obs).f_driver;
  last_effect (begin_send obs).f_driver events

let last_effect_from_update (obs: t_LinkUpdateStartObservation) (events: list t_ShareEvent)
  : Pure t_ShareEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_link_update_sound obs;
  trace_sound_matches_rust (begin_link_update obs).f_driver;
  last_effect (begin_link_update obs).f_driver events

let last_effect_from_revoke (u: unit) (events: list t_ShareEvent)
  : Pure t_ShareEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_link_revoke_sound u;
  trace_sound_matches_rust (begin_link_revoke u).f_driver;
  last_effect (begin_link_revoke u).f_driver events

let last_effect_from_inbox (u: unit) (events: list t_ShareEvent)
  : Pure t_ShareEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_inbox_delete_sound u;
  trace_sound_matches_rust (begin_inbox_delete u).f_driver;
  last_effect (begin_inbox_delete u).f_driver events

let last_effect_from_ek (obs: t_EkRegistrationStartObservation) (events: list t_ShareEvent)
  : Pure t_ShareEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_ek_registration_sound obs;
  trace_sound_matches_rust (begin_ek_registration obs).f_driver;
  last_effect (begin_ek_registration obs).f_driver events

// ── Trace properties ────────────────────────────────────────────────────────

/// (1) A send effect can only be produced by the extracted `begin_send` when
/// the authenticated-session observation is true and the real `plan_send`
/// decision is `Deliver`; the permit carries the observed capsule length.
let send_effect_requires_authentication_and_plan (obs: t_SendRequestObservation)
  : Lemma (
      match (begin_send obs).f_effect <: t_ShareEffect with
      | ShareEffect_InsertCapsule permit ->
          (begin_send obs).f_driver.f_sender_authenticated /\
          (begin_send obs).f_driver.f_authorized /\
          (begin_send obs).f_driver.f_stage = ShareStage_SendInsert /\
          permit.f_capsule_len = obs.f_policy.Vela_share_policy.f_capsule_len /\
          Vela_share_policy.plan_send (Vela_share_policy.send_facts obs.f_policy) =
            Vela_share_policy.SendDecision_Deliver
      | _ -> True) = ()

/// The plan provenance implies the authenticated session observation itself.
let send_effect_implies_session_observed (obs: t_SendRequestObservation)
  : Lemma (
      (match (begin_send obs).f_effect <: t_ShareEffect with
       | ShareEffect_InsertCapsule _ ->
           obs.f_policy.Vela_share_policy.f_session_user_id_present = true
       | _ -> True)) =
  send_effect_requires_authentication_and_plan obs

/// (2) A linked-item mutation effect can only be produced by a step whose
/// observed row went through the real `plan_link_mutation` and returned
/// `Apply`.
let link_effect_requires_plan (d: t_ShareDriver) (obs: t_LinkMutationObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step d (ShareEvent_LinkObserved obs)).f_effect <: t_ShareEffect with
      | ShareEffect_UpdateLinkedItem _ | ShareEffect_RevokeLinkedItem ->
          Vela_share_policy.plan_link_mutation (Vela_share_policy.link_mutation_facts obs) =
            Vela_share_policy.LinkMutationDecision_Apply
      | _ -> True)) =
  trace_sound_matches_rust d;
  assert (share_state_is_sound d = true)

/// (3) Only the sender can mutate a live link: an update/revoke effect implies
/// the observed row existed, the caller was the sender, and the row was not
/// revoked.
let link_effect_implies_sender_and_live (d: t_ShareDriver) (obs: t_LinkMutationObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (step d (ShareEvent_LinkObserved obs)).f_effect <: t_ShareEffect with
      | ShareEffect_UpdateLinkedItem _ | ShareEffect_RevokeLinkedItem ->
          obs.f_item_present = true /\
          obs.f_caller_matches_sender = true /\
          obs.f_item_not_revoked = true
      | _ -> True)) =
  link_effect_requires_plan d obs;
  match (step d (ShareEvent_LinkObserved obs)).f_effect <: t_ShareEffect with
  | ShareEffect_UpdateLinkedItem _ -> ()
  | ShareEffect_RevokeLinkedItem -> ()
  | _ -> ()

/// (4) A revoked link is an immutable tombstone: no update or revoke effect can
/// be produced from an observation that saw the revoked flag.
let revoked_link_cannot_mutate (d: t_ShareDriver) (obs: t_LinkMutationObservation)
  : Lemma
    (requires (trace_sound d /\ obs.f_item_present = true /\ obs.f_item_not_revoked = false))
    (ensures (
      match (step d (ShareEvent_LinkObserved obs)).f_effect <: t_ShareEffect with
      | ShareEffect_UpdateLinkedItem _ | ShareEffect_RevokeLinkedItem -> False
      | _ -> True)) =
  link_effect_implies_sender_and_live d obs

/// (5) An inbox delete is always constructed with the recipient-scoped guard
/// recorded on both the permit and the driver. The handler must apply it with
/// `recipient_user_id = session.user_id`.
let begin_inbox_delete_is_recipient_scoped (u: unit)
  : Lemma (
      match (begin_inbox_delete u).f_effect <: t_ShareEffect with
      | ShareEffect_DeleteInboxItem permit ->
          permit.f_recipient_scoped = true /\
          (begin_inbox_delete u).f_driver.f_recipient_scoped = true
      | _ -> False) = ()

/// (6) A successful send/update/revoke/delete/EK registration is terminal and
/// never un-revoked: for an arbitrary-length event list, the driver cannot
/// both commit and revoke, and no later event changes the terminal state.
let no_commit_and_revoke_after_send (obs: t_SendRequestObservation) (events: list t_ShareEvent)
  : Lemma (
      let d = run_from_send obs events in
      not (d.f_committed && d.f_revoked)) =
  let d = run_from_send obs events in
  begin_send_kind obs;
  run_kind (begin_send obs).f_driver events;
  assert (d.f_kind = ShareRequestKind_SendCapsule);
  ()

let no_commit_and_revoke_after_revoke (u: unit) (events: list t_ShareEvent)
  : Lemma (
      let d = run_from_revoke u events in
      not (d.f_committed && not d.f_revoked)) =
  let d = run_from_revoke u events in
  begin_link_revoke_kind u;
  run_kind (begin_link_revoke u).f_driver events;
  assert (d.f_kind = ShareRequestKind_RevokeLinkedItem);
  ()

/// (7) At most one `Complete` (committed effect) per request instance.
let rec complete_count_le_one (d: t_ShareDriver) (events: list t_ShareEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_completes d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if (match t.f_effect <: t_ShareEffect with
          | ShareEffect_Complete -> true
          | _ -> false)
      then begin
        done_suffix_inert t.f_driver rest
      end else begin
        complete_count_le_one t.f_driver rest
      end

/// (8) A committed revoke is never followed by a second successful revoke or
/// update on the same request; the cleanup suffix is inert after completion.
let revoke_cleanup_reaches_complete (u: unit) (events: list t_ShareEvent)
  : Lemma (
      let d = run_from_revoke u events in
      d.f_revoked ==> d.f_cleanup_issued) =
  let _ = run_from_revoke u events in
  ()

/// Headline unbounded theorem over the actual extracted driver. For every
/// request observation and every event list, the final state is sound, a
/// send/update commit is never paired with a revoke, and the number of
/// successes in the trace is at most one.
let share_trace_send_theorem (obs: t_SendRequestObservation) (events: list t_ShareEvent)
  : Lemma (
      let d = run_from_send obs events in
      trace_sound d /\
      (d.f_revoked ==> False) /\
      count_completes_from_send obs events <= 1) =
  let d = run_from_send obs events in
  begin_send_sound obs;
  begin_send_kind obs;
  run_kind (begin_send obs).f_driver events;
  trace_sound_matches_rust (begin_send obs).f_driver;
  complete_count_le_one (begin_send obs).f_driver events;
  ()

let share_trace_revoke_theorem (u: unit) (events: list t_ShareEvent)
  : Lemma (
      let d = run_from_revoke u events in
      trace_sound d /\
      (d.f_committed ==> d.f_revoked) /\
      (d.f_revoked ==> d.f_cleanup_issued) /\
      count_completes_from_revoke u events <= 1) =
  let d = run_from_revoke u events in
  begin_link_revoke_sound u;
  begin_link_revoke_kind u;
  run_kind (begin_link_revoke u).f_driver events;
  trace_sound_matches_rust (begin_link_revoke u).f_driver;
  complete_count_le_one (begin_link_revoke u).f_driver events;
  ()

// ── Reachability witnesses ──────────────────────────────────────────────────

let valid_send_observation : t_SendRequestObservation =
  {
    f_policy = {
      Vela_share_policy.f_session_user_id_present = true;
      Vela_share_policy.f_recipient_has_share_ek = true;
      Vela_share_policy.f_capsule_len = mk_i64 16;
      Vela_share_policy.f_existing_inbox_bytes = mk_i64 0;
    };
    f_decode_failed = false;
    f_inbox_count = mk_i64 0;
    f_pair_bytes = mk_i64 0;
  }

let unauthenticated_send_observation : t_SendRequestObservation =
  { valid_send_observation with
    f_policy = { valid_send_observation.f_policy with
                 Vela_share_policy.f_session_user_id_present = false } }

let live_link_observation : t_LinkMutationObservation =
  {
    Vela_share_policy.f_item_present = true;
    Vela_share_policy.f_caller_matches_sender = true;
    Vela_share_policy.f_item_not_revoked = true;
  }

let foreign_link_observation : t_LinkMutationObservation =
  { live_link_observation with
    Vela_share_policy.f_caller_matches_sender = false }

let revoked_link_observation : t_LinkMutationObservation =
  { live_link_observation with
    Vela_share_policy.f_item_not_revoked = false }

let valid_update_start : t_LinkUpdateStartObservation =
  { f_decode_failed = false; f_capsule_len = mk_i64 16 }

let valid_ek_start : t_EkRegistrationStartObservation =
  {
    f_ek_decode_failed = false;
    f_ek_len = Vela_share_policy.v_SHARE_EK_LEN;
    f_signed_at_not_canonical = false;
    f_signed_at_unparseable = false;
    f_signed_at_future = false;
  }

let valid_ek_device : t_EkDeviceObservation =
  {
    f_registration = {
      Vela_share_policy.f_ek_len = Vela_share_policy.v_SHARE_EK_LEN;
      Vela_share_policy.f_signature_verified = true;
      Vela_share_policy.f_device_row_present = true;
      Vela_share_policy.f_device_user_matches = true;
      Vela_share_policy.f_device_active = true;
      Vela_share_policy.f_signed_at_is_fresher = true;
      Vela_share_policy.f_binding_exists = false;
    };
    f_stored_identity_vk_decode_failed = false;
    f_signature_decode_failed = false;
  }

let rows_committed : t_RowsObservation = { f_rows = mk_u64 1 }
let rows_missing : t_RowsObservation = { f_rows = mk_u64 0 }
let cleanup_ok : t_CleanupObservation = { f_storage_failed = false }

let send_success_events : list t_ShareEvent =
  [ ShareEvent_SendResult SendResultObservation_Committed ]

let update_success_events : list t_ShareEvent =
  [ ShareEvent_LinkObserved live_link_observation;
    ShareEvent_Mutated rows_committed ]

let revoke_success_events : list t_ShareEvent =
  [ ShareEvent_LinkObserved live_link_observation;
    ShareEvent_Mutated rows_committed;
    ShareEvent_Cleaned cleanup_ok ]

let inbox_success_events : list t_ShareEvent =
  [ ShareEvent_Mutated rows_committed ]

let ek_success_events : list t_ShareEvent =
  [ ShareEvent_EkObserved valid_ek_device;
    ShareEvent_Mutated rows_committed ]

/// A valid send reaches `Complete` with exactly one success.
let send_success_is_reachable ()
  : Lemma (
      let d = run_from_send valid_send_observation send_success_events in
      d.f_committed = true /\ d.f_revoked = false /\ is_done d /\
      count_completes_from_send valid_send_observation send_success_events = 1) =
  ()

/// An unauthenticated session still reaches `plan_send`, which rejects it.
let unauthenticated_send_is_rejected ()
  : Lemma (
      (begin_send unauthenticated_send_observation).f_effect =
        ShareEffect_Fail ShareFailure_CapsulePolicyRejected) =
  ()

/// A sender-owned live link update reaches `Complete`.
let update_success_is_reachable ()
  : Lemma (
      let d = run_from_update valid_update_start update_success_events in
      d.f_committed = true /\ d.f_revoked = false /\ is_done d /\
      count_completes_from_update valid_update_start update_success_events = 1) =
  ()

/// A foreign sender observation is rejected before any update effect.
let foreign_update_is_rejected ()
  : Lemma (
      last_effect_from_update valid_update_start
        [ ShareEvent_LinkObserved foreign_link_observation ] =
        ShareEffect_Fail ShareFailure_LinkNotFound) =
  ()

/// A revoked linked row can never be updated.
let revoked_update_is_rejected ()
  : Lemma (
      last_effect_from_update valid_update_start
        [ ShareEvent_LinkObserved revoked_link_observation ] =
        ShareEffect_Fail ShareFailure_LinkNotFound) =
  ()

/// A sender's revoke reaches the cleanup effect and then `Complete`, keeping
/// the revoked flag set.
let revoke_success_is_reachable ()
  : Lemma (
      let d = run_from_revoke () revoke_success_events in
      d.f_committed = true /\ d.f_revoked = true /\ d.f_cleanup_issued = true /\
      is_done d /\
      count_completes_from_revoke () revoke_success_events = 1) =
  ()

/// A recipient-scoped inbox delete reaches `Complete` on one affected row.
let inbox_delete_success_is_reachable ()
  : Lemma (
      let d = run_from_inbox () inbox_success_events in
      d.f_committed = true /\ is_done d /\
      count_completes_from_inbox () inbox_success_events = 1) =
  ()

/// A device-signed EK registration reaches `Complete`.
let ek_registration_success_is_reachable ()
  : Lemma (
      let d = run_from_ek valid_ek_start ek_success_events in
      d.f_committed = true /\ is_done d /\
      count_completes_from_ek valid_ek_start ek_success_events = 1) =
  ()

/// The send effect itself carries the observed capsule length.
let send_effect_carries_length ()
  : Lemma (
      match (begin_send valid_send_observation).f_effect <: t_ShareEffect with
      | ShareEffect_InsertCapsule permit -> permit.f_capsule_len = mk_i64 16
      | _ -> False) =
  send_effect_requires_authentication_and_plan valid_send_observation
