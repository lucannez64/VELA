module Vela_share_policy_send_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* one-off
/// share-link transition relation (`Vela_share_policy.Send_driver`).
///
/// Scope: one `SendDriver` value, i.e. one `POST /send`, `GET /send/:id` or
/// `DELETE /send/:id` request. SQL, clocks, rate limiting and response
/// rendering remain effectful glue outside this module; the driver's inputs
/// are observations, never verified origins. The concurrent composition over
/// a shared link store lives in `send-driver-composition`.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `send_state_is_sound` and proved equivalent to it; all
/// trace lemmas then quantify over every event list.
///
/// Headline facts: a create insert carries exactly the clamped TTL/view bounds;
/// no create or owner delete effect is emitted without an authenticated owner;
/// a delete permit is owner-bound; a fetch delivers at most once per request
/// and only after a successful consume.

open FStar.Mul
open Core_models
open Vela_share_policy
open Vela_share_policy.Send_driver

// ── Independent state invariant ─────────────────────────────────────────────

let is_start (d: t_SendDriver) : bool =
  match d.f_stage <: t_SendStage with
  | SendStage_Start -> true
  | _ -> false

let is_read (d: t_SendDriver) : bool =
  match d.f_stage <: t_SendStage with
  | SendStage_Read -> true
  | _ -> false

let is_remove (d: t_SendDriver) : bool =
  match d.f_stage <: t_SendStage with
  | SendStage_Remove -> true
  | _ -> false

let is_done (d: t_SendDriver) : bool =
  match d.f_stage <: t_SendStage with
  | SendStage_Done -> true
  | _ -> false

let trace_sound (d: t_SendDriver) : bool =
  let start_clean =
    d.f_authorized && not d.f_consumed && not d.f_delivered &&
    not d.f_removed && not d.f_deleted && not d.f_succeeded &&
    not d.f_failed &&
    (if is_create d || is_delete d then d.f_wrote else not d.f_wrote)
  in
  let read_clean =
    d.f_authorized && d.f_consumed && not d.f_wrote && not d.f_delivered &&
    not d.f_removed && not d.f_deleted && not d.f_succeeded && not d.f_failed
  in
  let remove_clean =
    d.f_authorized && d.f_consumed && d.f_delivered && not d.f_removed &&
    not d.f_wrote && not d.f_deleted && not d.f_succeeded && not d.f_failed
  in
  let done_clean =
    (d.f_succeeded || d.f_failed) && not (d.f_succeeded && d.f_failed) &&
    (not d.f_succeeded ||
      (is_create d && d.f_wrote) || (is_fetch d && d.f_consumed && d.f_delivered) ||
      (is_delete d && d.f_wrote)) &&
    (not d.f_failed ||
      (not d.f_deleted && not d.f_delivered && (not (is_fetch d) || not d.f_removed)))
  in
  (match d.f_stage <: t_SendStage with
   | SendStage_Start -> start_clean
   | SendStage_Read -> read_clean
   | SendStage_Remove -> remove_clean
   | SendStage_Done -> done_clean) &&
  (not d.f_consumed || is_fetch d) &&
  (not d.f_delivered || d.f_consumed) &&
  (not d.f_removed || d.f_delivered) &&
  (not d.f_removed || is_fetch d) &&
  (not d.f_wrote || is_create d || is_delete d) &&
  (not d.f_deleted || (is_delete d && d.f_wrote)) &&
  (not (is_read d) || (is_fetch d && d.f_consumed)) &&
  (not (is_remove d) || (is_fetch d && d.f_consumed && d.f_delivered))

let trace_sound_matches_rust (d: t_SendDriver)
  : Lemma (trace_sound d = send_state_is_sound d) =
  match d.f_stage <: t_SendStage with
  | SendStage_Start -> ()
  | SendStage_Read -> ()
  | SendStage_Remove -> ()
  | SendStage_Done -> ()

// ── The transition relation ─────────────────────────────────────────────────

let begin_create_sound (o: t_CreateObservation)
  : Lemma (trace_sound (begin_create o).f_driver) =
  trace_sound_matches_rust (begin_create o).f_driver

let begin_fetch_sound ()
  : Lemma (trace_sound (begin_fetch ()).f_driver) =
  trace_sound_matches_rust (begin_fetch ()).f_driver

let begin_delete_sound (owner_present: bool)
  : Lemma (trace_sound (begin_delete owner_present).f_driver) =
  trace_sound_matches_rust (begin_delete owner_present).f_driver

let step_sound (d: t_SendDriver) (e: t_SendEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (send_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

let step_after_done (d: t_SendDriver) (e: t_SendEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures ((step d e).f_driver = d /\ (step d e).f_effect = SendEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_SendEvent with
  | SendEvent_SendInserted _ -> ()
  | SendEvent_ViewConsumed _ -> ()
  | SendEvent_SendRead _ -> ()
  | SendEvent_SendRemoved _ -> ()
  | SendEvent_SendDeleted _ -> ()

let rec run (d: t_SendDriver) (events: list t_SendEvent)
  : Pure t_SendDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let run_from_create (o: t_CreateObservation) (events: list t_SendEvent)
  : Pure t_SendDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_create_sound o;
  run (begin_create o).f_driver events

let run_from_fetch (events: list t_SendEvent)
  : Pure t_SendDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_fetch_sound ();
  run (begin_fetch ()).f_driver events

let run_from_delete (owner_present: bool) (events: list t_SendEvent)
  : Pure t_SendDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_delete_sound owner_present;
  run (begin_delete owner_present).f_driver events

/// A finished driver consumes any remaining schedule without changing.
let rec run_from_done (d: t_SendDriver) (events: list t_SendEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (run d events = d))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      run_from_done d rest

/// A request whose begin decision already failed performs no further effect.
let run_from_failed_begin (d: t_SendDriver) (events: list t_SendEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d /\ d.f_failed /\ not d.f_succeeded /\
      not d.f_deleted /\ not d.f_delivered))
    (ensures (
      let r = run d events in
      r.f_failed /\ not r.f_succeeded /\ not r.f_deleted /\ not r.f_delivered)) =
  run_from_done d events

// ── Per-request authority and bounds ───────────────────────────────────────

/// A create effect is either the bounded insert permit or a terminal failure.
/// The bounds are those `send_effect_is_sound` states, not a restatement.
let create_effect_is_bounded (o: t_CreateObservation)
  : Lemma
    (ensures (
      match (begin_create o).f_effect <: t_SendEffect with
      | SendEffect_InsertSend p ->
          p.f_ttl_secs >=. v_MIN_TTL_SECS /\ p.f_ttl_secs <=. v_MAX_TTL_SECS /\
          (p.f_max_views_present ==>
            (p.f_max_views >=. mk_i64 1 /\ p.f_max_views <=. v_MAX_VIEWS_CEILING)) /\
          (p.f_view_once ==> (p.f_max_views_present && p.f_max_views = mk_i64 1))
      | _ -> True)) =
  let t = begin_create o in
  assert (send_effect_is_sound t.f_driver t.f_effect)

/// No insert effect reaches the handler without an authenticated owner.
let create_requires_owner (o: t_CreateObservation)
  : Lemma
    (requires (not o.f_owner_present))
    (ensures (
      match (begin_create o).f_effect <: t_SendEffect with
      | SendEffect_InsertSend _ -> False
      | _ -> True)) = ()

/// A delete effect is either owner-bound or a terminal failure.
let delete_effect_is_owner_bound (owner_present: bool)
  : Lemma
    (ensures (
      match (begin_delete owner_present).f_effect <: t_SendEffect with
      | SendEffect_DeleteLink p -> p.f_owner_bound
      | _ -> True)) =
  let t = begin_delete owner_present in
  assert (send_effect_is_sound t.f_driver t.f_effect)

/// No delete effect reaches the handler without an authenticated owner.
let delete_requires_owner (owner_present: bool)
  : Lemma
    (requires (not owner_present))
    (ensures (
      match (begin_delete owner_present).f_effect <: t_SendEffect with
      | SendEffect_DeleteLink _ -> False
      | _ -> True)) = ()

/// A rejected delete request performs no effect and stays failed.
let delete_without_owner_fails (events: list t_SendEvent)
  : Lemma (
      let d = run_from_delete false events in
      d.f_failed && not d.f_succeeded && not d.f_deleted) =
  let b = begin_delete false in
  begin_delete_sound false;
  run_from_failed_begin b.f_driver events

/// A fetch that never observes a successful consume never delivers.
let unavailable_fetch_never_delivers (events: list t_SendEvent)
  : Lemma (
      let d = run_from_fetch
        (SendEvent_ViewConsumed ConsumeObservation_Unavailable :: events) in
      d.f_failed && not d.f_delivered && not d.f_succeeded) =
  let b = begin_fetch () in
  let t = step b.f_driver (SendEvent_ViewConsumed ConsumeObservation_Unavailable) in
  begin_fetch_sound ();
  step_sound b.f_driver (SendEvent_ViewConsumed ConsumeObservation_Unavailable);
  assert (is_done t.f_driver);
  assert (t.f_driver.f_failed);
  run_from_failed_begin t.f_driver events

// ── At most one delivery per request ───────────────────────────────────────

let is_delivery_effect (e: t_SendEffect) : bool =
  match e <: t_SendEffect with
  | SendEffect_CompleteFetch -> true
  | _ -> false

/// A delivery effect is only emitted by the read (non-view-once) or cleanup
/// (view-once) step, and both mark the driver `Done`.
let delivery_effect_is_done (d: t_SendDriver) (e: t_SendEvent)
  : Lemma
    (requires (trace_sound d /\
      (step d e).f_effect = SendEffect_CompleteFetch))
    (ensures (is_done (step d e).f_driver /\
      trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  step_sound d e;
  match d.f_stage <: t_SendStage with
  | SendStage_Read ->
      begin match e <: t_SendEvent with
      | SendEvent_SendRead (ReadObservation_Payload payload) ->
          assert (not payload.f_view_once)
      | _ -> ()
      end
  | SendStage_Remove ->
      begin match e <: t_SendEvent with
      | SendEvent_SendRemoved _ -> ()
      | _ -> ()
      end
  | _ -> ()

let rec delivery_count (d: t_SendDriver) (events: list t_SendEvent)
  : Pure nat
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (if is_delivery_effect (step d e).f_effect then 1 else 0) +
      delivery_count (step d e).f_driver rest

let rec delivery_count_from_done (d: t_SendDriver) (events: list t_SendEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (delivery_count d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      delivery_count_from_done d rest

let rec delivery_count_le_one (d: t_SendDriver) (events: list t_SendEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (delivery_count d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      let t = step d e in
      trace_sound_matches_rust d;
      step_sound d e;
      if is_delivery_effect t.f_effect then begin
        delivery_effect_is_done d e;
        delivery_count_from_done t.f_driver rest
      end else begin
        delivery_count_le_one t.f_driver rest
      end

let fetch_delivers_at_most_once (events: list t_SendEvent)
  : Lemma (delivery_count (begin_fetch ()).f_driver events <= 1) =
  begin_fetch_sound ();
  delivery_count_le_one (begin_fetch ()).f_driver events

// ── Ordering facts ─────────────────────────────────────────────────────────

let delivered_implies_consumed (d: t_SendDriver)
  : Lemma
    (requires (trace_sound d))
    (ensures (d.f_delivered ==> d.f_consumed)) = ()

let success_excludes_failure (d: t_SendDriver)
  : Lemma
    (requires (trace_sound d))
    (ensures (not (d.f_succeeded && d.f_failed))) =
  trace_sound_matches_rust d

let deleted_implies_succeeded (d: t_SendDriver)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (d.f_deleted ==> d.f_succeeded)) =
  trace_sound_matches_rust d

// ── Reachability witnesses (the statements are not vacuous) ────────────────

let ok_create : t_CreateObservation =
  {
    f_owner_present = true;
    f_ciphertext_decode_failed = false;
    f_ciphertext_len = mk_i64 10;
    f_has_passphrase = false;
    f_kdf_salt_present = false;
    f_kdf_salt_decode_failed = false;
    f_kdf_salt_len = mk_i64 0;
    f_has_ttl = false;
    f_ttl_secs = mk_i64 0;
    f_has_max_views = false;
    f_max_views = mk_i64 0;
    f_view_once = false;
  }

let rows_ok : t_RowsObservation = { f_rows = mk_u64 1; f_failed = false }
let rows_missing : t_RowsObservation = { f_rows = mk_u64 0; f_failed = false }
let removed_ok : t_RemoveObservation = { f_removed = true; f_failed = false }

let create_events : list t_SendEvent = [ SendEvent_SendInserted rows_ok ]

let fetch_view_once_events : list t_SendEvent =
  [
    SendEvent_ViewConsumed ConsumeObservation_Consumed;
    SendEvent_SendRead (ReadObservation_Payload { f_view_once = true });
    SendEvent_SendRemoved removed_ok;
  ]

let fetch_unavailable_events : list t_SendEvent =
  [ SendEvent_ViewConsumed ConsumeObservation_Unavailable ]

let delete_events (rows: t_RowsObservation) : list t_SendEvent =
  [ SendEvent_SendDeleted rows ]

let create_reaches_success ()
  : Lemma (
      let d = run_from_create ok_create create_events in
      d.f_succeeded && d.f_wrote && not d.f_failed && is_done d) =
  ()

let view_once_fetch_reaches_success ()
  : Lemma (
      let d = run_from_fetch fetch_view_once_events in
      d.f_succeeded && d.f_consumed && d.f_delivered && d.f_removed &&
      not d.f_failed && is_done d) =
  ()

let unavailable_fetch_reaches_failure ()
  : Lemma (
      let d = run_from_fetch fetch_unavailable_events in
      d.f_failed && not d.f_delivered && not d.f_succeeded && is_done d) =
  ()

let owner_delete_reaches_success ()
  : Lemma (
      let d = run_from_delete true (delete_events rows_ok) in
      d.f_succeeded && d.f_deleted && is_done d) =
  ()

let non_owner_delete_reaches_failure ()
  : Lemma (
      let d = run_from_delete false (delete_events rows_ok) in
      d.f_failed && not d.f_deleted && is_done d) =
  ()

let create_without_owner_reaches_failure ()
  : Lemma (
      let d = run_from_create ({ ok_create with f_owner_present = false }) create_events in
      d.f_failed && not d.f_wrote && is_done d) =
  ()

let create_insert_count ()
  : Lemma (delivery_count (begin_create ok_create).f_driver create_events = 0) =
  ()

let view_once_fetch_delivery_count ()
  : Lemma (delivery_count (begin_fetch ()).f_driver fetch_view_once_events = 1) =
  ()

let unavailable_fetch_delivery_count ()
  : Lemma (delivery_count (begin_fetch ()).f_driver fetch_unavailable_events = 0) =
  ()
