module Vela_session_policy_deletion_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* account
/// deletion driver (`Vela_session_policy.Deletion_driver`).
///
/// Scope: one `DeletionDriver` value, i.e. one HTTP `DELETE /account` request.
/// The theorem does not claim anything about two concurrent requests; that is
/// `Vela_session_policy_deletion_driver_composition`. The sled marker writes,
/// the single SQL transaction, the eight statements and the order in which the
/// handler performs them remain effectful glue outside this module. The
/// driver's scan/delete/commit inputs are observations, never verified
/// origins.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `deletion_state_is_sound` and proved equivalent to it; all
/// trace lemmas then quantify over every event list.
///
/// The headline ordering theorem (`trace_order`) threads four running
/// counters through the whole trace — device lockouts, web-session lockouts,
/// confirmed table deletes and confirmed `users` deletes — and requires, at the
/// point the extracted driver emits each effect:
///
/// - both store-side lockouts already happened before the transaction is
///   opened and before *any* SQL delete;
/// - the confirmed table deletes are exactly `WebSessions`, `ShareInbox`,
///   `SharedItems`, `Sends`, `VaultChunks`, `OramBuckets`, `Devices`, in that
///   order, each once; and
/// - a commit is only allowed with all seven tables and the `users` row
///   already confirmed deleted.
///
/// The counters are driven solely by the extracted driver's effect and stage,
/// never by a modelled SQL guard.

open FStar.Mul
open Core_models
open FStar.List.Tot
open Vela_session_policy.Deletion_driver

// ── Stage predicates ────────────────────────────────────────────────────────

let is_observe_devices (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_ObserveDevices -> true
  | _ -> false

let is_lockout_devices (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_LockoutDevices -> true
  | _ -> false

let is_observe_web_sessions (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_ObserveWebSessions -> true
  | _ -> false

let is_lockout_web_sessions (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_LockoutWebSessions -> true
  | _ -> false

let is_begin_transaction (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_BeginTransaction -> true
  | _ -> false

let is_delete_table (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_DeleteTable _ -> true
  | _ -> false

let is_delete_users (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_DeleteUsers -> true
  | _ -> false

let is_commit (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_Commit -> true
  | _ -> false

let is_done (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_Done -> true
  | _ -> false

/// Strengthened trace invariant. It encodes the stage/flag discipline of the
/// driver plus the effect-order facts: a web-session lockout only after the
/// device lockout, the SQL transaction only after both lockouts and before any
/// delete, the `users` delete only inside a started transaction, a commit only
/// after the `users` row was deleted, and no commit after a failure.
let trace_sound (d: t_DeletionDriver) : bool =
  let lockouts_clear =
    not d.f_devices_locked && not d.f_devices_lockout_done &&
    not d.f_web_sessions_locked && not d.f_web_sessions_lockout_done
  in
  let transaction_clear =
    not d.f_transaction_open && not d.f_transaction_started &&
    not d.f_users_deleted && not d.f_committed &&
    not d.f_responded && not d.f_failed
  in
  let observe_devices =
    d.f_actor_active && d.f_same_account && lockouts_clear && transaction_clear
  in
  let lockout_devices =
    d.f_actor_active && d.f_same_account && d.f_devices_locked &&
    not d.f_devices_lockout_done && not d.f_web_sessions_locked &&
    not d.f_web_sessions_lockout_done && transaction_clear
  in
  let observe_web_sessions =
    d.f_actor_active && d.f_same_account && d.f_devices_locked &&
    d.f_devices_lockout_done && not d.f_web_sessions_locked &&
    not d.f_web_sessions_lockout_done && transaction_clear
  in
  let lockout_web_sessions =
    d.f_actor_active && d.f_same_account && d.f_devices_locked &&
    d.f_devices_lockout_done && d.f_web_sessions_locked &&
    not d.f_web_sessions_lockout_done && transaction_clear
  in
  let begin_transaction =
    d.f_actor_active && d.f_same_account && d.f_devices_locked &&
    d.f_devices_lockout_done && d.f_web_sessions_locked &&
    d.f_web_sessions_lockout_done && d.f_transaction_open &&
    not d.f_transaction_started && not d.f_users_deleted &&
    not d.f_committed && not d.f_responded && not d.f_failed
  in
  let deleting =
    d.f_actor_active && d.f_same_account && d.f_devices_locked &&
    d.f_devices_lockout_done && d.f_web_sessions_locked &&
    d.f_web_sessions_lockout_done && d.f_transaction_open &&
    d.f_transaction_started && not d.f_users_deleted &&
    not d.f_committed && not d.f_responded && not d.f_failed
  in
  let commit =
    d.f_actor_active && d.f_same_account && d.f_devices_locked &&
    d.f_devices_lockout_done && d.f_web_sessions_locked &&
    d.f_web_sessions_lockout_done && d.f_transaction_open &&
    d.f_transaction_started && d.f_users_deleted &&
    not d.f_committed && not d.f_responded && not d.f_failed
  in
  let done =
    (d.f_responded || d.f_failed) && not (d.f_responded && d.f_failed) &&
    (not d.f_responded ||
      (d.f_committed && d.f_users_deleted && d.f_transaction_started))
  in
  (not (is_observe_devices d) || observe_devices) &&
  (not (is_lockout_devices d) || lockout_devices) &&
  (not (is_observe_web_sessions d) || observe_web_sessions) &&
  (not (is_lockout_web_sessions d) || lockout_web_sessions) &&
  (not (is_begin_transaction d) || begin_transaction) &&
  (not (is_delete_table d) || deleting) &&
  (not (is_delete_users d) || deleting) &&
  (not (is_commit d) || commit) &&
  (not (is_done d) || done) &&
  (not d.f_same_account || d.f_actor_active) &&
  (not d.f_devices_locked || (d.f_actor_active && d.f_same_account)) &&
  (not d.f_devices_lockout_done || d.f_devices_locked) &&
  (not d.f_web_sessions_locked ||
    (d.f_devices_lockout_done && d.f_same_account)) &&
  (not d.f_web_sessions_lockout_done || d.f_web_sessions_locked) &&
  (not d.f_transaction_open ||
    (d.f_devices_lockout_done && d.f_web_sessions_lockout_done)) &&
  (not d.f_transaction_started || d.f_transaction_open) &&
  (not d.f_users_deleted || d.f_transaction_started) &&
  (not d.f_committed || (d.f_users_deleted && d.f_transaction_started)) &&
  (not d.f_responded || d.f_committed) &&
  (not d.f_failed || not d.f_committed)

/// The independently written invariant is exactly the Rust postcondition's
/// predicate. Proved by exhaustive stage case analysis, not by aliasing the
/// implementation definition in the statements below.
let trace_sound_matches_rust (d: t_DeletionDriver)
  : Lemma (trace_sound d = deletion_state_is_sound d) =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_ObserveDevices -> ()
  | DeletionStage_LockoutDevices -> ()
  | DeletionStage_ObserveWebSessions -> ()
  | DeletionStage_LockoutWebSessions -> ()
  | DeletionStage_BeginTransaction -> ()
  | DeletionStage_DeleteTable _ -> ()
  | DeletionStage_DeleteUsers -> ()
  | DeletionStage_Commit -> ()
  | DeletionStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_sound (actor: t_DeletionActorObservation)
  : Lemma (trace_sound (begin_deletion actor).f_driver) =
  trace_sound_matches_rust (begin_deletion actor).f_driver

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (deletion_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

/// Every extracted step's effect agrees with the state it produced.
let step_effect_sound (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (deletion_effect_is_sound (step d e).f_driver (step d e).f_effect)) =
  trace_sound_matches_rust d;
  assert (deletion_state_is_sound d = true)

/// A finished driver is inert for every event.
let step_after_done (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = DeletionEffect_Idle)) =
  trace_sound_matches_rust d;
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_Done ->
      (match e <: t_DeletionEvent with
       | DeletionEvent_DevicesScanned _ -> ()
       | DeletionEvent_DeviceLockout _ -> ()
       | DeletionEvent_WebSessionsScanned _ -> ()
       | DeletionEvent_WebSessionLockout _ -> ()
       | DeletionEvent_Transaction _ -> ()
       | DeletionEvent_TableDeleted _ -> ()
       | DeletionEvent_UsersDeleted _ -> ()
       | DeletionEvent_Commit _ -> ())
  | _ -> ()

/// An actor the middleware did not establish as authenticated, active and
/// scoped to its own account reaches a terminal state without ever emitting a
/// scan, lockout or SQL effect.
let inactive_actor_never_deletes (actor: t_DeletionActorObservation)
  : Lemma
    (requires (
      not (actor.f_authenticated && actor.f_device_active &&
           actor.f_scoped_to_session_account)))
    (ensures (
      let t = begin_deletion actor in
      trace_sound t.f_driver /\ is_done t.f_driver /\
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_Fail _ -> true
       | _ -> false))) =
  trace_sound_matches_rust (begin_deletion actor).f_driver

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Pure t_DeletionDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let rec last_effect (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Pure t_DeletionEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> DeletionEffect_Idle
  | e :: [] -> (step d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step d e).f_driver rest

/// Total wrappers starting from the actual extracted `begin_deletion`.
let run_from_actor (actor: t_DeletionActorObservation) (events: list t_DeletionEvent)
  : Pure t_DeletionDriver
    (requires True)
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  begin_sound actor;
  trace_sound_matches_rust (begin_deletion actor).f_driver;
  run (begin_deletion actor).f_driver events

let last_effect_from_actor
      (actor: t_DeletionActorObservation)
      (events: list t_DeletionEvent)
  : Pure t_DeletionEffect (requires True) (ensures (fun _ -> True)) (decreases events) =
  begin_sound actor;
  trace_sound_matches_rust (begin_deletion actor).f_driver;
  last_effect (begin_deletion actor).f_driver events

// ── Counter vocabulary ──────────────────────────────────────────────────────

let b2n (b: bool) : nat = if b then 1 else 0

let table_index (t: t_DeletionTable) : nat =
  match t <: t_DeletionTable with
  | DeletionTable_WebSessions -> 0
  | DeletionTable_ShareInbox -> 1
  | DeletionTable_SharedItems -> 2
  | DeletionTable_Sends -> 3
  | DeletionTable_VaultChunks -> 4
  | DeletionTable_OramBuckets -> 5
  | DeletionTable_Devices -> 6

/// The next table the driver expects to confirm, 7 once every table is
/// confirmed, and 7 for the terminal/finished states (those are excluded from
/// the trace-link hypothesis).
let stage_table_index (d: t_DeletionDriver) : nat =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_DeleteTable t -> table_index t
  | DeletionStage_DeleteUsers -> 7
  | DeletionStage_Commit -> 7
  | DeletionStage_Done -> 7
  | _ -> 0

let is_table_effect (e: t_DeletionEffect) : bool =
  match e <: t_DeletionEffect with
  | DeletionEffect_DeleteTable _ -> true
  | _ -> false

let is_lockout_devices_effect (e: t_DeletionEffect) : bool =
  match e <: t_DeletionEffect with
  | DeletionEffect_LockoutDevices -> true
  | _ -> false

let is_lockout_web_sessions_effect (e: t_DeletionEffect) : bool =
  match e <: t_DeletionEffect with
  | DeletionEffect_LockoutWebSessions -> true
  | _ -> false

/// A confirmed table delete: the handler reported the delete of the table the
/// driver was waiting for.
let confirmed_table_step (d: t_DeletionDriver) (e: t_DeletionEvent) : bool =
  match e <: t_DeletionEvent with
  | DeletionEvent_TableDeleted TableDeleteObservation_Deleted ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteTable _ -> true
       | _ -> false)
  | _ -> false

/// A confirmed `users` delete: the handler reported that the account row was
/// deleted.
let confirmed_users_step (d: t_DeletionDriver) (e: t_DeletionEvent) : bool =
  match e <: t_DeletionEvent with
  | DeletionEvent_UsersDeleted UsersDeleteObservation_Deleted ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteUsers -> true
       | _ -> false)
  | _ -> false

// ── Step-local facts used by the trace induction ────────────────────────────

/// The lockout, `users` and stage-order links are sticky across one step.
let step_links (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      (d.f_devices_locked ==> t.f_driver.f_devices_locked) /\
      (d.f_web_sessions_locked ==> t.f_driver.f_web_sessions_locked) /\
      (d.f_users_deleted ==> t.f_driver.f_users_deleted) /\
      (not (is_done t.f_driver) ==>
        stage_table_index t.f_driver =
          stage_table_index d + b2n (confirmed_table_step d e)))) =
  trace_sound_matches_rust d;
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveDevices ->
           (match obs <: t_ScanObservation with
            | ScanObservation_Rows -> ()
            | ScanObservation_QueryFailed -> ())
       | _ -> ())
  | DeletionEvent_DeviceLockout _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_LockoutDevices -> ()
       | _ -> ())
  | DeletionEvent_WebSessionsScanned obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveWebSessions ->
           (match obs <: t_ScanObservation with
            | ScanObservation_Rows -> ()
            | ScanObservation_QueryFailed -> ())
       | _ -> ())
  | DeletionEvent_WebSessionLockout _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_LockoutWebSessions -> ()
       | _ -> ())
  | DeletionEvent_Transaction obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_BeginTransaction ->
           (match obs <: t_TransactionObservation with
            | TransactionObservation_Begun -> ()
            | TransactionObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_TableDeleted obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteTable table ->
           (match obs <: t_TableDeleteObservation with
            | TableDeleteObservation_Deleted ->
                (match table <: t_DeletionTable with
                 | DeletionTable_WebSessions -> ()
                 | DeletionTable_ShareInbox -> ()
                 | DeletionTable_SharedItems -> ()
                 | DeletionTable_Sends -> ()
                 | DeletionTable_VaultChunks -> ()
                 | DeletionTable_OramBuckets -> ()
                 | DeletionTable_Devices -> ())
            | TableDeleteObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_UsersDeleted obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteUsers ->
           (match obs <: t_UsersDeleteObservation with
            | UsersDeleteObservation_Deleted -> ()
            | UsersDeleteObservation_Absent -> ()
            | UsersDeleteObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_Commit obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_Commit ->
           (match obs <: t_CommitObservation with
            | CommitObservation_Committed -> ()
            | CommitObservation_Failed -> ())
       | _ -> ())

/// `devices_locked` is only ever set by a step whose effect is the device
/// lockout.
let devices_locked_origin (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d /\ not d.f_devices_locked))
    (ensures (
      (step d e).f_driver.f_devices_locked ==>
      ((step d e).f_effect = DeletionEffect_LockoutDevices))) =
  trace_sound_matches_rust d;
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveDevices ->
           (match obs <: t_ScanObservation with
            | ScanObservation_Rows -> ()
            | ScanObservation_QueryFailed -> ())
       | _ -> ())
  | DeletionEvent_DeviceLockout _ -> ()
  | DeletionEvent_WebSessionsScanned _ -> ()
  | DeletionEvent_WebSessionLockout _ -> ()
  | DeletionEvent_Transaction _ -> ()
  | DeletionEvent_TableDeleted _ -> ()
  | DeletionEvent_UsersDeleted _ -> ()
  | DeletionEvent_Commit _ -> ()

/// `web_sessions_locked` is only ever set by a step whose effect is the
/// web-session lockout.
let web_sessions_locked_origin (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d /\ not d.f_web_sessions_locked))
    (ensures (
      (step d e).f_driver.f_web_sessions_locked ==>
      ((step d e).f_effect = DeletionEffect_LockoutWebSessions))) =
  trace_sound_matches_rust d;
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned _ -> ()
  | DeletionEvent_DeviceLockout _ -> ()
  | DeletionEvent_WebSessionsScanned obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveWebSessions ->
           (match obs <: t_ScanObservation with
            | ScanObservation_Rows -> ()
            | ScanObservation_QueryFailed -> ())
       | _ -> ())
  | DeletionEvent_WebSessionLockout _ -> ()
  | DeletionEvent_Transaction _ -> ()
  | DeletionEvent_TableDeleted _ -> ()
  | DeletionEvent_UsersDeleted _ -> ()
  | DeletionEvent_Commit _ -> ()

/// `users_deleted` is only ever set by a confirmed `users` delete.
let users_deleted_origin (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d /\ not d.f_users_deleted))
    (ensures (
      (step d e).f_driver.f_users_deleted ==>
      (confirmed_users_step d e = true))) =
  trace_sound_matches_rust d;
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned _ -> ()
  | DeletionEvent_DeviceLockout _ -> ()
  | DeletionEvent_WebSessionsScanned _ -> ()
  | DeletionEvent_WebSessionLockout _ -> ()
  | DeletionEvent_Transaction _ -> ()
  | DeletionEvent_TableDeleted _ -> ()
  | DeletionEvent_UsersDeleted obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteUsers ->
           (match obs <: t_UsersDeleteObservation with
            | UsersDeleteObservation_Deleted -> ()
            | UsersDeleteObservation_Absent -> ()
            | UsersDeleteObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_Commit _ -> ()

/// `same_deletion_table` agrees with the table index.
let same_deletion_table_index (a b: t_DeletionTable)
  : Lemma
    (requires (same_deletion_table a b))
    (ensures (table_index a = table_index b)) =
  match a <: t_DeletionTable with
  | DeletionTable_WebSessions -> ()
  | DeletionTable_ShareInbox -> ()
  | DeletionTable_SharedItems -> ()
  | DeletionTable_Sends -> ()
  | DeletionTable_VaultChunks -> ()
  | DeletionTable_OramBuckets -> ()
  | DeletionTable_Devices -> ()

/// A `DeleteTable` effect names the table the driver is waiting for, i.e. the
/// next table in the fixed order.
let table_effect_post_index (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_DeleteTable table ->
           table_index table = stage_table_index t.f_driver
       | _ -> True))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

/// The device and web-session lockouts already happened before the driver
/// authorizes anything inside the SQL transaction.
let sql_effect_requires_lockouts (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_BeginTransaction ->
           d.f_devices_locked /\ d.f_web_sessions_locked
       | DeletionEffect_DeleteTable _ ->
           d.f_devices_locked /\ d.f_web_sessions_locked
       | DeletionEffect_DeleteUsers ->
           d.f_devices_locked /\ d.f_web_sessions_locked
       | DeletionEffect_CommitTransaction ->
           d.f_devices_locked /\ d.f_web_sessions_locked
       | _ -> True))) =
  trace_sound_matches_rust d;
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned _ -> ()
  | DeletionEvent_DeviceLockout _ -> ()
  | DeletionEvent_WebSessionsScanned _ -> ()
  | DeletionEvent_WebSessionLockout obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_LockoutWebSessions ->
           (match obs <: t_LockoutObservation with
            | LockoutObservation_Applied -> ()
            | LockoutObservation_StorageFailed -> ())
       | _ -> ())
  | DeletionEvent_Transaction obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_BeginTransaction ->
           (match obs <: t_TransactionObservation with
            | TransactionObservation_Begun -> ()
            | TransactionObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_TableDeleted obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteTable table ->
           (match obs <: t_TableDeleteObservation with
            | TableDeleteObservation_Deleted -> ()
            | TableDeleteObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_UsersDeleted obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteUsers ->
           (match obs <: t_UsersDeleteObservation with
            | UsersDeleteObservation_Deleted -> ()
            | UsersDeleteObservation_Absent -> ()
            | UsersDeleteObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_Commit obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_Commit ->
           (match obs <: t_CommitObservation with
            | CommitObservation_Committed -> ()
            | CommitObservation_Failed -> ())
       | _ -> ())

/// The commit effect is only emitted in the step that observed the `users` row
/// deleted (the zero-row result is the account-existence signal).
let commit_effect_requires_users_delete (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d e).f_effect = DeletionEffect_CommitTransaction ==>
      confirmed_users_step d e = true)) =
  trace_sound_matches_rust d;
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned _ -> ()
  | DeletionEvent_DeviceLockout _ -> ()
  | DeletionEvent_WebSessionsScanned _ -> ()
  | DeletionEvent_WebSessionLockout _ -> ()
  | DeletionEvent_Transaction _ -> ()
  | DeletionEvent_TableDeleted _ -> ()
  | DeletionEvent_UsersDeleted obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteUsers ->
           (match obs <: t_UsersDeleteObservation with
            | UsersDeleteObservation_Deleted -> ()
            | UsersDeleteObservation_Absent -> ()
            | UsersDeleteObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_Commit _ -> ()

/// A mutating effect only exists for an active actor and a request scoped to
/// its own account.
let scoped_effect_requires_authority (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step d e in
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_LockoutDevices ->
           t.f_driver.f_actor_active /\ t.f_driver.f_same_account
       | DeletionEffect_LockoutWebSessions ->
           t.f_driver.f_actor_active /\ t.f_driver.f_same_account
       | DeletionEffect_DeleteTable _ ->
           t.f_driver.f_actor_active /\ t.f_driver.f_same_account
       | DeletionEffect_DeleteUsers ->
           t.f_driver.f_actor_active /\ t.f_driver.f_same_account
       | DeletionEffect_CommitTransaction ->
           t.f_driver.f_actor_active /\ t.f_driver.f_same_account
       | _ -> True))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

// ── Effect ordering over an arbitrary trace ─────────────────────────────────

/// (1) The running discipline. `dev_locks` / `ws_locks` count the two lockout
/// effects, `tables` counts confirmed table deletes and `users` confirmed
/// `users` deletes. Every effect the driver emits is checked against them:
///
/// - `BeginTransaction`, every table delete, the `users` delete and the commit
///   require both lockouts to have happened;
/// - a `DeleteTable` effect must name the table that comes right after the
///   confirmed ones (`table_index table = tables + 1` when the step confirmed a
///   table, and `= tables` for the first table, which the transaction begin
///   authorizes);
/// - the `users` delete requires all seven tables;
/// - the commit requires all seven tables and the confirmed `users` delete.
let rec trace_order
    (d: t_DeletionDriver)
    (events: list t_DeletionEvent)
    (dev_locks: nat)
    (ws_locks: nat)
    (tables: nat)
    (users: nat)
  : Pure bool
    (requires (
      trace_sound d /\
      (d.f_devices_locked ==> dev_locks >= 1) /\
      (d.f_web_sessions_locked ==> ws_locks >= 1) /\
      (d.f_users_deleted ==> users >= 1) /\
      (not (is_done d) ==> tables = stage_table_index d)))
    (ensures (fun result -> result = true))
    (decreases events) =
  match events with
  | [] -> true
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      step_effect_sound d e;
      let t = step d e in
      let dev_after = dev_locks + b2n (is_lockout_devices_effect t.f_effect) in
      let ws_after = ws_locks + b2n (is_lockout_web_sessions_effect t.f_effect) in
      let tables_after = tables + b2n (confirmed_table_step d e) in
      let users_after = users + b2n (confirmed_users_step d e) in
      // The lockouts strictly precede every SQL effect, the tables are
      // confirmed in the fixed order, the `users` row is confirmed before the
      // driver authorizes the commit, and a success response only exists after
      // that confirmation.
      sql_effect_requires_lockouts d e;
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_BeginTransaction ->
           assert (dev_locks >= 1);
           assert (ws_locks >= 1)
       | DeletionEffect_DeleteTable table ->
           assert (dev_locks >= 1);
           assert (ws_locks >= 1);
           // The emitted delete is the next table in the fixed order.
           table_effect_post_index d e;
           step_links d e;
           assert (not (is_done t.f_driver));
           assert (tables_after = stage_table_index t.f_driver);
           assert (table_index table = tables_after)
       | DeletionEffect_DeleteUsers ->
           assert (dev_locks >= 1);
           assert (ws_locks >= 1);
           // Every one of the seven tables was confirmed deleted.
           step_links d e;
           assert (not (is_done t.f_driver));
           assert (tables_after = 7)
       | DeletionEffect_CommitTransaction ->
           assert (dev_locks >= 1);
           assert (ws_locks >= 1);
           assert (tables = 7);
           // The commit is only authorized in the step that observed the
           // `users` row deleted.
           commit_effect_requires_users_delete d e;
           assert (confirmed_users_step d e = true)
       | DeletionEffect_Complete ->
           assert (dev_locks >= 1);
           assert (ws_locks >= 1);
           assert (tables = 7);
           assert (d.f_users_deleted)
       | _ -> ());
      // Re-establish the running hypotheses for the next state.
      step_links d e;
      if t.f_driver.f_devices_locked then begin
        if d.f_devices_locked then begin
          assert (dev_locks >= 1);
          assert (dev_after >= 1)
        end else begin
          devices_locked_origin d e;
          assert (dev_after = dev_locks + 1)
        end
      end;
      if t.f_driver.f_web_sessions_locked then begin
        if d.f_web_sessions_locked then begin
          assert (ws_locks >= 1);
          assert (ws_after >= 1)
        end else begin
          web_sessions_locked_origin d e;
          assert (ws_after = ws_locks + 1)
        end
      end;
      if t.f_driver.f_users_deleted then begin
        if d.f_users_deleted then begin
          assert (users >= 1);
          assert (users_after >= 1)
        end else begin
          users_deleted_origin d e;
          assert (users_after = users + 1)
        end
      end;
      if not (is_done t.f_driver) then begin
        assert (tables_after = stage_table_index t.f_driver)
      end;
      trace_order t.f_driver rest dev_after ws_after tables_after users_after

/// Corollary over the actual extracted `begin_deletion`: for every actor and
/// every event list, the whole trace obeys the discipline above.
let deletion_trace_order
      (actor: t_DeletionActorObservation)
      (events: list t_DeletionEvent)
  : Lemma (
      trace_order (begin_deletion actor).f_driver events 0 0 0 0) =
  begin_sound actor;
  trace_sound_matches_rust (begin_deletion actor).f_driver;
  let ok = trace_order (begin_deletion actor).f_driver events 0 0 0 0 in
  assert (ok = true)

// ── Terminal effects are unique, and failures never commit ─────────────────

let rec count_complete (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_DeletionEffect with
       | DeletionEffect_Complete -> 1
       | _ -> 0) +
      count_complete (step d e).f_driver rest

let rec count_fail (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_DeletionEffect with
       | DeletionEffect_Fail _ -> 1
       | _ -> 0) +
      count_fail (step d e).f_driver rest

let rec count_commit (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      (match (step d e).f_effect <: t_DeletionEffect with
       | DeletionEffect_CommitTransaction -> 1
       | _ -> 0) +
      count_commit (step d e).f_driver rest

let rec done_suffix_inert (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      run d events = d /\
      last_effect d events = DeletionEffect_Idle /\
      count_complete d events = 0 /\
      count_fail d events = 0 /\
      count_commit d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

/// Complete happens at most once, and never after a terminal failure.
let rec complete_count_le_one (d: t_DeletionDriver) (events: list t_DeletionEvent)
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
      if (match t.f_effect <: t_DeletionEffect with
          | DeletionEffect_Complete -> true
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
let rec fail_count_le_one (d: t_DeletionDriver) (events: list t_DeletionEvent)
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
      if (match t.f_effect <: t_DeletionEffect with
          | DeletionEffect_Fail _ -> true
          | _ -> false)
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_failed = true);
        assert (is_done t.f_driver = true);
        done_suffix_inert t.f_driver rest
      end else begin
        fail_count_le_one t.f_driver rest
      end

/// A `Fail` effect is terminal: the state is `Done`, it is marked failed and
/// it does not claim a commit. The handler drops the transaction, which rolls
/// it back.
let fail_effect_is_terminal (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (match (step d e).f_effect <: t_DeletionEffect with
       | DeletionEffect_Fail _ ->
           is_done (step d e).f_driver /\
           (step d e).f_driver.f_failed = true /\
           (step d e).f_driver.f_committed = false
       | _ -> True))) =
  trace_sound_matches_rust d;
  step_effect_sound d e

/// From the commit stage the driver only emits the commit observation's
/// success/failure (or `Idle`), never a second `CommitTransaction`.
let rec commit_stage_no_commit (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Lemma
    (requires (trace_sound d /\ is_commit d))
    (ensures (count_commit d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_Idle -> commit_stage_no_commit t.f_driver rest
       | DeletionEffect_Complete -> done_suffix_inert t.f_driver rest
       | DeletionEffect_Fail _ -> done_suffix_inert t.f_driver rest
       | _ -> ())

/// `CommitTransaction` happens at most once.
let rec commit_count_le_one (d: t_DeletionDriver) (events: list t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_commit d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_CommitTransaction ->
           commit_stage_no_commit t.f_driver rest
       | _ -> commit_count_le_one t.f_driver rest)

#push-options "--fuel 4 --ifuel 2"

/// A trace never contains both a `Complete` and a `Fail` effect: `Complete`
/// sets the success response and `Fail` sets the terminal failure, and each is
/// terminal for the rest of the trace. So a failed deletion never reports a
/// successful commit.
let rec success_and_failure_are_exclusive
      (d: t_DeletionDriver)
      (events: list t_DeletionEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (count_complete d events = 0 \/ count_fail d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_Complete ->
           trace_sound_matches_rust t.f_driver;
           assert (is_done t.f_driver = true);
           done_suffix_inert t.f_driver rest
       | DeletionEffect_Fail _ ->
           trace_sound_matches_rust t.f_driver;
           assert (is_done t.f_driver = true);
           done_suffix_inert t.f_driver rest
       | _ ->
           success_and_failure_are_exclusive t.f_driver rest)

#pop-options

/// Headline per-request theorem over the actual extracted driver. For every
/// actor observation and every event list:
///
/// - the final state is sound;
/// - a success response implies a committed, started transaction whose `users`
///   row was deleted;
/// - a success and a failure are never both claimed;
/// - at most one `Complete`, at most one `Fail` and at most one commit effect
///   occur;
/// - the whole trace obeys the split-lockout / table-order / commit discipline.
let deletion_trace_theorem
      (actor: t_DeletionActorObservation)
      (events: list t_DeletionEvent)
  : Lemma (
      let d = run_from_actor actor events in
      trace_sound d /\
      (d.f_responded ==> (d.f_committed && d.f_users_deleted && d.f_transaction_started)) /\
      (d.f_committed ==> (d.f_users_deleted && d.f_transaction_started)) /\
      (not (d.f_responded && d.f_failed)) /\
      (not d.f_failed || not d.f_committed) /\
      count_complete (begin_deletion actor).f_driver events <= 1 /\
      count_fail (begin_deletion actor).f_driver events <= 1 /\
      count_commit (begin_deletion actor).f_driver events <= 1 /\
      trace_order (begin_deletion actor).f_driver events 0 0 0 0) =
  begin_sound actor;
  trace_sound_matches_rust (begin_deletion actor).f_driver;
  complete_count_le_one (begin_deletion actor).f_driver events;
  fail_count_le_one (begin_deletion actor).f_driver events;
  commit_count_le_one (begin_deletion actor).f_driver events;
  deletion_trace_order actor events;
  let d = run_from_actor actor events in
  assert (trace_sound d);
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_Done -> ()
  | _ -> ()

// ── Reachability witnesses ─────────────────────────────────────────────────

let active_actor : t_DeletionActorObservation =
  { f_authenticated = true; f_device_active = true; f_scoped_to_session_account = true }

let cross_account_actor : t_DeletionActorObservation =
  { f_authenticated = true; f_device_active = true; f_scoped_to_session_account = false }

let inactive_actor : t_DeletionActorObservation =
  { f_authenticated = true; f_device_active = false; f_scoped_to_session_account = true }

/// The four lockout events, then the transaction begin: the lockouts precede
/// the transaction and both are observed before it opens.
let witness_1 =
  begin_deletion active_actor

let witness_2 =
  step witness_1.f_driver (DeletionEvent_DevicesScanned ScanObservation_Rows)

let witness_3 =
  step witness_2.f_driver (DeletionEvent_DeviceLockout LockoutObservation_Applied)

let witness_4 =
  step witness_3.f_driver (DeletionEvent_WebSessionsScanned ScanObservation_Rows)

let witness_5 =
  step witness_4.f_driver (DeletionEvent_WebSessionLockout LockoutObservation_Applied)

/// A store-side lockout failure does not abort the deletion.
let lockout_failure_still_reaches_the_transaction ()
  : Lemma (
      witness_2.f_effect = DeletionEffect_LockoutDevices /\
      witness_3.f_effect = DeletionEffect_ScanWebSessions /\
      witness_4.f_effect = DeletionEffect_LockoutWebSessions /\
      witness_5.f_effect = DeletionEffect_BeginTransaction /\
      witness_5.f_driver.f_devices_lockout_done = true /\
      witness_5.f_driver.f_web_sessions_lockout_done = true /\
      witness_5.f_driver.f_transaction_open = true /\
      witness_5.f_driver.f_transaction_started = false /\
      not witness_5.f_driver.f_committed /\
      not witness_5.f_driver.f_failed) =
  ()

/// The failed device lockout observation takes the same branch: the deletion
/// proceeds to the web-session lockout.
let lockout_storage_failure_continues ()
  : Lemma (
      (step witness_2.f_driver
        (DeletionEvent_DeviceLockout LockoutObservation_StorageFailed)).f_effect
        = DeletionEffect_ScanWebSessions) =
  ()

/// A scan failure before the transaction is terminal and opens nothing.
let device_scan_failure_is_reachable ()
  : Lemma (
      let t = step witness_1.f_driver
        (DeletionEvent_DevicesScanned ScanObservation_QueryFailed) in
      t.f_effect = DeletionEffect_Fail DeletionFailure_DeviceScanStorage /\
      t.f_driver.f_failed = true /\ not t.f_driver.f_devices_locked /\
      not t.f_driver.f_transaction_open) =
  ()

/// A web-session scan failure happens after the device lockout but before the
/// transaction.
let web_session_scan_failure_is_reachable ()
  : Lemma (
      let t = step witness_3.f_driver
        (DeletionEvent_WebSessionsScanned ScanObservation_QueryFailed) in
      t.f_effect = DeletionEffect_Fail DeletionFailure_WebSessionScanStorage /\
      t.f_driver.f_failed = true /\ t.f_driver.f_devices_locked = true /\
      not t.f_driver.f_transaction_open) =
  ()

/// A transaction begin failure is terminal with nothing deleted.
let transaction_failure_is_reachable ()
  : Lemma (
      let t = step witness_5.f_driver
        (DeletionEvent_Transaction TransactionObservation_Failed) in
      t.f_effect = DeletionEffect_Fail DeletionFailure_TransactionStorage /\
      t.f_driver.f_failed = true /\ not t.f_driver.f_transaction_started /\
      not t.f_driver.f_committed) =
  ()

/// The transaction begin emits the first table delete.
let transaction_begins_with_the_first_table ()
  : Lemma (
      (step witness_5.f_driver
        (DeletionEvent_Transaction TransactionObservation_Begun)).f_effect
        = DeletionEffect_DeleteTable DeletionTable_WebSessions) =
  ()

/// A table failure after the transaction started is terminal, rolled back and
/// never commits.
let table_failure_is_reachable ()
  : Lemma (
      let begun = step witness_5.f_driver
        (DeletionEvent_Transaction TransactionObservation_Begun) in
      let t = step begun.f_driver
        (DeletionEvent_TableDeleted TableDeleteObservation_Failed) in
      t.f_effect = DeletionEffect_Fail DeletionFailure_TableStorage /\
      t.f_driver.f_failed = true /\ t.f_driver.f_transaction_started = true /\
      not t.f_driver.f_committed /\ is_done t.f_driver) =
  ()

/// The eight SQL deletes are reached in the fixed order, and the `users` delete
/// emits the commit authorization; the commit observation then produces the
/// success response.
let commit_path_is_reachable ()
  : Lemma (
      let begun = step witness_5.f_driver
        (DeletionEvent_Transaction TransactionObservation_Begun) in
      let d1 = step begun.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d2 = step d1.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d3 = step d2.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d4 = step d3.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d5 = step d4.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d6 = step d5.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d7 = step d6.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d8 = step d7.f_driver (DeletionEvent_UsersDeleted UsersDeleteObservation_Deleted) in
      let d9 = step d8.f_driver (DeletionEvent_Commit CommitObservation_Committed) in
      d1.f_effect = DeletionEffect_DeleteTable DeletionTable_ShareInbox /\
      d2.f_effect = DeletionEffect_DeleteTable DeletionTable_SharedItems /\
      d3.f_effect = DeletionEffect_DeleteTable DeletionTable_Sends /\
      d4.f_effect = DeletionEffect_DeleteTable DeletionTable_VaultChunks /\
      d5.f_effect = DeletionEffect_DeleteTable DeletionTable_OramBuckets /\
      d6.f_effect = DeletionEffect_DeleteTable DeletionTable_Devices /\
      d7.f_effect = DeletionEffect_DeleteUsers /\
      d8.f_effect = DeletionEffect_CommitTransaction /\
      d9.f_effect = DeletionEffect_Complete /\
      d9.f_driver.f_committed = true /\
      d9.f_driver.f_responded = true /\
      not d9.f_driver.f_failed) =
  ()

/// An absent account — the zero-row `users` delete — is terminal before any
/// commit effect: the handler drops the transaction and reports not found.
let absent_account_is_reachable ()
  : Lemma (
      let begun = step witness_5.f_driver
        (DeletionEvent_Transaction TransactionObservation_Begun) in
      let d1 = step begun.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d2 = step d1.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d3 = step d2.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d4 = step d3.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d5 = step d4.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d6 = step d5.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d7 = step d6.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d8 = step d7.f_driver (DeletionEvent_UsersDeleted UsersDeleteObservation_Absent) in
      d8.f_effect = DeletionEffect_Fail DeletionFailure_AccountNotFound /\
      d8.f_driver.f_failed = true /\ not d8.f_driver.f_committed /\
      not d8.f_driver.f_responded) =
  ()

/// A commit failure is reported as a failure, never as a success.
let commit_failure_is_reachable ()
  : Lemma (
      let begun = step witness_5.f_driver
        (DeletionEvent_Transaction TransactionObservation_Begun) in
      let d1 = step begun.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d2 = step d1.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d3 = step d2.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d4 = step d3.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d5 = step d4.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d6 = step d5.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d7 = step d6.f_driver (DeletionEvent_TableDeleted TableDeleteObservation_Deleted) in
      let d8 = step d7.f_driver (DeletionEvent_UsersDeleted UsersDeleteObservation_Deleted) in
      let d9 = step d8.f_driver (DeletionEvent_Commit CommitObservation_Failed) in
      d9.f_effect = DeletionEffect_Fail DeletionFailure_CommitStorage /\
      d9.f_driver.f_failed = true /\ not d9.f_driver.f_committed /\
      not d9.f_driver.f_responded) =
  ()

/// A cross-account request is refused before any effect, whatever follows.
let cross_account_is_refused (events: list t_DeletionEvent)
  : Lemma (
      let d = run_from_actor cross_account_actor events in
      d.f_failed = true /\ not d.f_devices_locked /\ not d.f_transaction_open /\
      not d.f_committed /\
      count_complete (begin_deletion cross_account_actor).f_driver events = 0 /\
      count_commit (begin_deletion cross_account_actor).f_driver events = 0) =
  inactive_actor_never_deletes cross_account_actor;
  done_suffix_inert (begin_deletion cross_account_actor).f_driver events

/// An inactive actor is refused before any effect, whatever follows.
let inactive_actor_is_refused (events: list t_DeletionEvent)
  : Lemma (
      let d = run_from_actor inactive_actor events in
      d.f_failed = true /\ not d.f_devices_locked /\ not d.f_transaction_open /\
      count_complete (begin_deletion inactive_actor).f_driver events = 0) =
  inactive_actor_never_deletes inactive_actor;
  done_suffix_inert (begin_deletion inactive_actor).f_driver events

/// The success path is also reachable from the race-free full sequence: the
/// composition module proves it over the shared world with `run_world`.
let split_lockout_order ()
  : Lemma (
      witness_5.f_driver.f_devices_lockout_done = true /\
      witness_5.f_driver.f_web_sessions_lockout_done = true /\
      witness_5.f_driver.f_transaction_open = true) =
  ()
