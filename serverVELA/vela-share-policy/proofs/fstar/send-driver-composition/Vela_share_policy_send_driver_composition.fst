module Vela_share_policy_send_driver_composition

/// Concurrent composition of the *extracted* one-off share-link driver.
///
/// One link is shared by any number of requests, each running its own
/// `Vela_share_policy.Send_driver` value. A schedule is an arbitrary list of
/// actions: create a link (single-use with one view, or reusable with `n`
/// views), fetch it once, or delete it as the owner or as a non-owner.
///
/// The world abstracts the effects the handler performs:
///
/// - the guarded `INSERT INTO sends ...` is one action: the create driver's
///   insert observation is `Inserted`, and the link becomes live;
/// - the atomic `UPDATE sends SET view_count = view_count + 1 WHERE ...` plus
///   the following `SELECT` and the view-once `DELETE` are one fetch action:
///   the driver sees `Consumed` only while the link is live with views left,
///   and `Unavailable` for missing, deleted or exhausted links;
/// - the owner-scoped `DELETE FROM sends WHERE id = ? AND owner_user_id = ?` is
///   one action: only an owner-bound permit reaches it.
///
/// Theorem: for every schedule, a single-use link yields at most one
/// successful fetch, a fetch after deletion never succeeds, and no non-owner
/// delete ever removes a link. Counters count *driver decisions*
/// (`f_succeeded`, `f_delivered`, `f_deleted`), not SQL statements.
///
/// Assumptions (not proved here): SQL statements are linearizable, the
/// handler performs exactly the effect the driver returns, and the driver's
/// observations are supplied by those statements. This module deliberately
/// does not import the per-request lemma module: the composition is a
/// statement about the extracted driver alone, which also makes the mutation
/// checks fail here rather than in an unrelated lemma.

open FStar.Mul
open Core_models
open Vela_share_policy
open Vela_share_policy.Send_driver

// ── Driving one request over its observation list ──────────────────────────

let rec drive (d: t_SendDriver) (events: list t_SendEvent)
  : Pure t_SendDriver
    (requires (send_state_is_sound d))
    (ensures (fun r -> send_state_is_sound r))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      let t = step d e in
      drive t.f_driver rest

let drive_cons (d: t_SendDriver) (e: t_SendEvent) (rest: list t_SendEvent)
  : Lemma
    (requires (send_state_is_sound d))
    (ensures (drive d (e :: rest) == drive (step d e).f_driver rest)) = ()

/// The concrete observations one create request feeds.
let create_ok : t_RowsObservation = { f_rows = mk_u64 1; f_failed = false }
let remove_ok : t_RemoveObservation = { f_removed = true; f_failed = false }

let create_events : list t_SendEvent = [ SendEvent_SendInserted create_ok ]

let fetch_events (view_once: bool) : list t_SendEvent =
  [
    SendEvent_ViewConsumed ConsumeObservation_Consumed;
    SendEvent_SendRead (ReadObservation_Payload { f_view_once = view_once });
    SendEvent_SendRemoved remove_ok;
  ]

let fetch_unavailable : list t_SendEvent =
  [ SendEvent_ViewConsumed ConsumeObservation_Unavailable ]

let delete_events (rows: t_RowsObservation) : list t_SendEvent =
  [ SendEvent_SendDeleted rows ]

let rows_present : t_RowsObservation = { f_rows = mk_u64 1; f_failed = false }
let rows_absent : t_RowsObservation = { f_rows = mk_u64 0; f_failed = false }

/// A create request with the bounds the driver clamps.
let create_observation (single_use: bool) (views: nat{views < 1000}) : t_CreateObservation =
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
    f_has_max_views = true;
    f_max_views = mk_i64 (if single_use then 1 else (views + 1 <: int));
    f_view_once = single_use;
  }

// ── The shared link world ──────────────────────────────────────────────────

type link_state =
  | Link_None
  | Link_Live : bool -> nat -> link_state
  | Link_Deleted : bool -> link_state

let link_is_deleted (l: link_state) : bool =
  match l with
  | Link_Deleted _ -> true
  | _ -> false

let link_single (l: link_state) : bool =
  match l with
  | Link_Live s _ -> s
  | Link_Deleted s -> s
  | Link_None -> false

let link_has_views (l: link_state) : bool =
  match l with
  | Link_Live _ n -> n > 0
  | _ -> false

noeq type world = {
  w_link: link_state;
  /// Driver decisions that delivered a payload.
  w_fetch_successes: nat;
  /// Driver decisions that delivered after the link was deleted (must be 0).
  w_fetch_after_delete: nat;
  /// Driver decisions that committed an owner delete.
  w_deletes: nat;
  /// Driver decisions that committed a delete for a non-owner (must be 0).
  w_non_owner_deletes: nat;
  /// Driver decisions that committed a create.
  w_creates: nat;
}

let initial_world (l: link_state) : world =
  {
    w_link = l;
    w_fetch_successes = 0;
    w_fetch_after_delete = 0;
    w_deletes = 0;
    w_non_owner_deletes = 0;
    w_creates = 0;
  }

/// The invariant: a single-use link has at most one successful fetch, a
/// deleted single-use link keeps that bound, no delivery is ever counted after
/// deletion, and no non-owner has ever deleted a link.
let inv (w: world) : prop =
  (match w.w_link with
   | Link_None -> w.w_fetch_successes = 0
   | Link_Live single _ -> not single \/ w.w_fetch_successes = 0
   | Link_Deleted single -> not single \/ w.w_fetch_successes <= 1) /\
  w.w_fetch_after_delete = 0 /\
  w.w_non_owner_deletes = 0

// ── One action ─────────────────────────────────────────────────────────────

type action =
  | Create : single_use:bool -> views:nat{views < 1000} -> action
  | Fetch
  | Delete : owner:bool -> action

/// The live link's remaining views, defaulting to 0.
let live_views (l: link_state) : nat =
  match l with
  | Link_Live _ n -> n
  | _ -> 0

let step_world (w: world) (a: action) : world =
  match a with
  | Create single views ->
      let d = drive (begin_create (create_observation single views)).f_driver create_events in
      if d.f_succeeded then
        {
          w with
          w_link = Link_Live single (if single then 1 else views + 1);
          w_fetch_successes = 0;
          w_fetch_after_delete = 0;
          w_creates = w.w_creates + 1;
        }
      else w
  | Fetch ->
      let live = link_has_views w.w_link in
      let single = link_single w.w_link in
      let events =
        if live then fetch_events single else fetch_unavailable
      in
      let d = drive (begin_fetch ()).f_driver events in
      if live && d.f_succeeded then
        {
          w with
          w_link =
            (if single then Link_Deleted true
             else Link_Live false (live_views w.w_link - 1));
          w_fetch_successes = w.w_fetch_successes + 1;
          w_fetch_after_delete =
            w.w_fetch_after_delete +
            (if link_is_deleted w.w_link then 1 else 0);
        }
      else if d.f_succeeded && link_is_deleted w.w_link then
        { w with w_fetch_after_delete = w.w_fetch_after_delete + 1 }
      else w
  | Delete owner ->
      let rows =
        match w.w_link with
        | Link_Live _ _ -> rows_present
        | _ -> rows_absent
      in
      let d = drive (begin_delete owner).f_driver (delete_events rows) in
      if d.f_deleted && owner then
        {
          w with
          w_link = Link_Deleted (link_single w.w_link);
          w_deletes = w.w_deletes + 1;
        }
      else if d.f_deleted && not owner then
        { w with w_non_owner_deletes = w.w_non_owner_deletes + 1 }
      else w

// ── Driver facts the world proof uses (from the extracted step relation) ───

let create_succeeds (single: bool) (views: nat{views < 1000})
  : Lemma (
      let d = drive (begin_create (create_observation single views)).f_driver create_events in
      d.f_succeeded && d.f_wrote) =
  ()

let fetch_live_succeeds (single: bool)
  : Lemma (
      let d = drive (begin_fetch ()).f_driver (fetch_events single) in
      d.f_succeeded && d.f_consumed && d.f_delivered &&
      (not single || d.f_removed)) =
  ()

let fetch_unavailable_fails ()
  : Lemma (
      let d = drive (begin_fetch ()).f_driver fetch_unavailable in
      not d.f_succeeded && d.f_failed && not d.f_delivered) =
  ()

let delete_present_owner_deletes ()
  : Lemma (
      let d = drive (begin_delete true).f_driver (delete_events rows_present) in
      d.f_succeeded && d.f_deleted) =
  ()

let delete_absent_owner_does_not_delete ()
  : Lemma (
      let d = drive (begin_delete true).f_driver (delete_events rows_absent) in
      d.f_succeeded && not d.f_deleted) =
  ()

let delete_non_owner_never_deletes ()
  : Lemma (
      let d = drive (begin_delete false).f_driver (delete_events rows_present) in
      d.f_failed && not d.f_deleted) =
  ()

// ── The invariant is preserved by every action ────────────────────────────

let step_world_preserves (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (step_world w a))) =
  match a with
  | Create single views ->
      create_succeeds single views
  | Fetch ->
      let live = link_has_views w.w_link in
      let single = link_single w.w_link in
      if live then begin
        fetch_live_succeeds single
      end else begin
        fetch_unavailable_fails ()
      end
  | Delete owner ->
      if owner then begin
        match w.w_link with
        | Link_Live _ _ -> delete_present_owner_deletes ()
        | _ -> delete_absent_owner_does_not_delete ()
      end else begin
        delete_non_owner_never_deletes ()
      end

let rec run_world (w: world) (schedule: list action)
  : Pure world (requires (inv w)) (ensures (fun r -> inv r)) (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest ->
      step_world_preserves w a;
      run_world (step_world w a) rest

// ── The composition theorems ──────────────────────────────────────────────

let composition_theorem (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule))) =
  ()

/// A schedule that never creates a new link.
let rec no_create (schedule: list action) : bool =
  match schedule with
  | [] -> true
  | a :: rest ->
      (match a with
       | Create _ _ -> false
       | _ -> true) &&
      no_create rest

/// Over such a schedule a single-use link yields at most one successful fetch:
/// the first one deletes it, and a deleted link cannot be consumed again.
let rec single_use_at_most_one_fetch_aux (w: world) (schedule: list action)
  : Lemma
    (requires (inv w /\ link_single w.w_link /\ no_create schedule))
    (ensures ((run_world w schedule).w_fetch_successes <= 1))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      step_world_preserves w a;
      (match a with
       | Create _ _ -> ()
       | Fetch ->
           let live = link_has_views w.w_link in
           let single = link_single w.w_link in
           if live then begin
             fetch_live_succeeds single
           end else begin
             fetch_unavailable_fails ()
           end
       | Delete owner ->
           if owner then begin
             match w.w_link with
             | Link_Live _ _ -> delete_present_owner_deletes ()
             | _ -> delete_absent_owner_does_not_delete ()
           end else begin
             delete_non_owner_never_deletes ()
           end);
      single_use_at_most_one_fetch_aux (step_world w a) rest

let single_use_at_most_one_fetch (w: world) (schedule: list action)
  : Lemma
    (requires (inv w /\ link_single w.w_link /\ no_create schedule))
    (ensures ((run_world w schedule).w_fetch_successes <= 1)) =
  single_use_at_most_one_fetch_aux w schedule

/// No successful fetch is ever counted after the link was deleted.
let no_fetch_after_delete (w: world) (schedule: list action)
  : Lemma
    (requires (inv w))
    (ensures ((run_world w schedule).w_fetch_after_delete = 0)) =
  composition_theorem w schedule

/// Only an owner delete ever removes a link.
let only_owner_deletes (w: world) (schedule: list action)
  : Lemma
    (requires (inv w))
    (ensures ((run_world w schedule).w_non_owner_deletes = 0)) =
  composition_theorem w schedule

// ── Witnesses (the statements are not vacuous) ────────────────────────────

let single_use_created : world = initial_world (Link_Live true 1)

let single_use_schedule : list action = [ Fetch; Fetch; Delete false ]

let single_use_fetch_witness ()
  : Lemma (
      let r = run_world single_use_created single_use_schedule in
      r.w_fetch_successes = 1 /\ r.w_link = Link_Deleted true) =
  ()

let multi_view_schedule : list action =
  [ Create false 1; Fetch; Fetch; Fetch ]

let multi_view_witness ()
  : Lemma (
      let r = run_world (initial_world Link_None) multi_view_schedule in
      r.w_fetch_successes = 2 /\ r.w_creates = 1) =
  ()

let owner_delete_then_fetch : list action = [ Delete true; Fetch ]

let delete_then_fetch_witness ()
  : Lemma (
      let r = run_world (initial_world (Link_Live false 3)) owner_delete_then_fetch in
      r.w_deletes = 1 /\ r.w_fetch_successes = 0 /\
      r.w_fetch_after_delete = 0 /\ r.w_link = Link_Deleted false) =
  ()
