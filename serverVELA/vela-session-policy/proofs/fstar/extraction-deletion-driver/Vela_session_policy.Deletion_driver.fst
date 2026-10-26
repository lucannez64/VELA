module Vela_session_policy.Deletion_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Actor and scope facts established by the authenticated `DeviceSession`
/// extractor.
type t_DeletionActorObservation = {
  f_authenticated:bool;
  f_device_active:bool;
  f_scoped_to_session_account:bool
}

/// Outcome of one row scan (devices, or web sessions).
type t_ScanObservation =
  | ScanObservation_Rows : t_ScanObservation
  | ScanObservation_QueryFailed : t_ScanObservation

/// Outcome of a store-side lockout batch. `StorageFailed` is an observation,
/// not proof that nothing was written.
type t_LockoutObservation =
  | LockoutObservation_Applied : t_LockoutObservation
  | LockoutObservation_StorageFailed : t_LockoutObservation

/// Outcome of opening the one SQL transaction.
type t_TransactionObservation =
  | TransactionObservation_Begun : t_TransactionObservation
  | TransactionObservation_Failed : t_TransactionObservation

/// Outcome of one `DELETE` inside the transaction.
type t_TableDeleteObservation =
  | TableDeleteObservation_Deleted : t_TableDeleteObservation
  | TableDeleteObservation_Failed : t_TableDeleteObservation

/// Outcome of `DELETE FROM users WHERE id = ?`. `Absent` is the zero-row
/// result and is the account-existence signal.
type t_UsersDeleteObservation =
  | UsersDeleteObservation_Deleted : t_UsersDeleteObservation
  | UsersDeleteObservation_Absent : t_UsersDeleteObservation
  | UsersDeleteObservation_Failed : t_UsersDeleteObservation

/// Outcome of the transaction commit. `Failed` is an observation, not proof
/// that nothing was committed.
type t_CommitObservation =
  | CommitObservation_Committed : t_CommitObservation
  | CommitObservation_Failed : t_CommitObservation

/// The account-scoped tables the handler deletes, in the historical order.
type t_DeletionTable =
  | DeletionTable_WebSessions : t_DeletionTable
  | DeletionTable_ShareInbox : t_DeletionTable
  | DeletionTable_SharedItems : t_DeletionTable
  | DeletionTable_Sends : t_DeletionTable
  | DeletionTable_VaultChunks : t_DeletionTable
  | DeletionTable_OramBuckets : t_DeletionTable
  | DeletionTable_Devices : t_DeletionTable

/// Where the deletion is in its decision sequence.
type t_DeletionStage =
  | DeletionStage_ObserveDevices : t_DeletionStage
  | DeletionStage_LockoutDevices : t_DeletionStage
  | DeletionStage_ObserveWebSessions : t_DeletionStage
  | DeletionStage_LockoutWebSessions : t_DeletionStage
  | DeletionStage_BeginTransaction : t_DeletionStage
  | DeletionStage_DeleteTable : t_DeletionTable -> t_DeletionStage
  | DeletionStage_DeleteUsers : t_DeletionStage
  | DeletionStage_Commit : t_DeletionStage
  | DeletionStage_Done : t_DeletionStage

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_DeletionEvent =
  | DeletionEvent_DevicesScanned : t_ScanObservation -> t_DeletionEvent
  | DeletionEvent_DeviceLockout : t_LockoutObservation -> t_DeletionEvent
  | DeletionEvent_WebSessionsScanned : t_ScanObservation -> t_DeletionEvent
  | DeletionEvent_WebSessionLockout : t_LockoutObservation -> t_DeletionEvent
  | DeletionEvent_Transaction : t_TransactionObservation -> t_DeletionEvent
  | DeletionEvent_TableDeleted : t_TableDeleteObservation -> t_DeletionEvent
  | DeletionEvent_UsersDeleted : t_UsersDeleteObservation -> t_DeletionEvent
  | DeletionEvent_Commit : t_CommitObservation -> t_DeletionEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_DeletionFailure =
  | DeletionFailure_Unauthenticated : t_DeletionFailure
  | DeletionFailure_CrossAccount : t_DeletionFailure
  | DeletionFailure_DeviceScanStorage : t_DeletionFailure
  | DeletionFailure_WebSessionScanStorage : t_DeletionFailure
  | DeletionFailure_TransactionStorage : t_DeletionFailure
  | DeletionFailure_TableStorage : t_DeletionFailure
  | DeletionFailure_UsersStorage : t_DeletionFailure
  | DeletionFailure_AccountNotFound : t_DeletionFailure
  | DeletionFailure_CommitStorage : t_DeletionFailure

/// The effect the handler must perform next.
type t_DeletionEffect =
  | DeletionEffect_ScanDevices : t_DeletionEffect
  | DeletionEffect_LockoutDevices : t_DeletionEffect
  | DeletionEffect_ScanWebSessions : t_DeletionEffect
  | DeletionEffect_LockoutWebSessions : t_DeletionEffect
  | DeletionEffect_BeginTransaction : t_DeletionEffect
  | DeletionEffect_DeleteTable : t_DeletionTable -> t_DeletionEffect
  | DeletionEffect_DeleteUsers : t_DeletionEffect
  | DeletionEffect_CommitTransaction : t_DeletionEffect
  | DeletionEffect_Complete : t_DeletionEffect
  | DeletionEffect_Fail : t_DeletionFailure -> t_DeletionEffect
  | DeletionEffect_Idle : t_DeletionEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
type t_DeletionDriver = {
  f_stage:t_DeletionStage;
  f_actor_active:bool;
  f_same_account:bool;
  f_devices_locked:bool;
  f_devices_lockout_done:bool;
  f_web_sessions_locked:bool;
  f_web_sessions_lockout_done:bool;
  f_transaction_open:bool;
  f_transaction_started:bool;
  f_users_deleted:bool;
  f_committed:bool;
  f_responded:bool;
  f_failed:bool
}

type t_DeletionTransition = {
  f_driver:t_DeletionDriver;
  f_effect:t_DeletionEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let deletion_state_is_sound (d: t_DeletionDriver) : bool =
  let lockouts_clear:bool =
    ~.d.f_devices_locked && ~.d.f_devices_lockout_done && ~.d.f_web_sessions_locked &&
    ~.d.f_web_sessions_lockout_done
  in
  let transaction_clear:bool =
    ~.d.f_transaction_open && ~.d.f_transaction_started && ~.d.f_users_deleted && ~.d.f_committed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let observe_devices:bool =
    d.f_actor_active && d.f_same_account && lockouts_clear && transaction_clear
  in
  let lockout_devices:bool =
    d.f_actor_active && d.f_same_account && d.f_devices_locked && ~.d.f_devices_lockout_done &&
    ~.d.f_web_sessions_locked &&
    ~.d.f_web_sessions_lockout_done &&
    transaction_clear
  in
  let observe_web_sessions:bool =
    d.f_actor_active && d.f_same_account && d.f_devices_locked && d.f_devices_lockout_done &&
    ~.d.f_web_sessions_locked &&
    ~.d.f_web_sessions_lockout_done &&
    transaction_clear
  in
  let lockout_web_sessions:bool =
    d.f_actor_active && d.f_same_account && d.f_devices_locked && d.f_devices_lockout_done &&
    d.f_web_sessions_locked &&
    ~.d.f_web_sessions_lockout_done &&
    transaction_clear
  in
  let begin_transaction:bool =
    d.f_actor_active && d.f_same_account && d.f_devices_locked && d.f_devices_lockout_done &&
    d.f_web_sessions_locked &&
    d.f_web_sessions_lockout_done &&
    d.f_transaction_open &&
    ~.d.f_transaction_started &&
    ~.d.f_users_deleted &&
    ~.d.f_committed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let deleting:bool =
    d.f_actor_active && d.f_same_account && d.f_devices_locked && d.f_devices_lockout_done &&
    d.f_web_sessions_locked &&
    d.f_web_sessions_lockout_done &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    ~.d.f_users_deleted &&
    ~.d.f_committed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let commit:bool =
    d.f_actor_active && d.f_same_account && d.f_devices_locked && d.f_devices_lockout_done &&
    d.f_web_sessions_locked &&
    d.f_web_sessions_lockout_done &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_users_deleted &&
    ~.d.f_committed &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done:bool =
    (d.f_responded || d.f_failed) && ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded || d.f_committed && d.f_users_deleted && d.f_transaction_started)
  in
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_ObserveDevices  -> true
    | _ -> false) ||
  observe_devices) &&
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_LockoutDevices  -> true
    | _ -> false) ||
  lockout_devices) &&
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_ObserveWebSessions  -> true
    | _ -> false) ||
  observe_web_sessions) &&
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_LockoutWebSessions  -> true
    | _ -> false) ||
  lockout_web_sessions) &&
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_BeginTransaction  -> true
    | _ -> false) ||
  begin_transaction) &&
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_DeleteTable _ | DeletionStage_DeleteUsers  -> true
    | _ -> false) ||
  deleting) &&
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_Commit  -> true
    | _ -> false) ||
  commit) &&
  (~.(match d.f_stage <: t_DeletionStage with
    | DeletionStage_Done  -> true
    | _ -> false) ||
  done) &&
  (~.d.f_same_account || d.f_actor_active) &&
  (~.d.f_devices_locked || d.f_actor_active && d.f_same_account) &&
  (~.d.f_devices_lockout_done || d.f_devices_locked) &&
  (~.d.f_web_sessions_locked || d.f_devices_lockout_done && d.f_same_account) &&
  (~.d.f_web_sessions_lockout_done || d.f_web_sessions_locked) &&
  (~.d.f_transaction_open || d.f_devices_lockout_done && d.f_web_sessions_lockout_done) &&
  (~.d.f_transaction_started || d.f_transaction_open) &&
  (~.d.f_users_deleted || d.f_transaction_started) &&
  (~.d.f_committed || d.f_users_deleted && d.f_transaction_started) &&
  (~.d.f_responded || d.f_committed) &&
  (~.d.f_failed || ~.d.f_committed)

/// Structural table comparison, kept independent of the derived `PartialEq`
/// implementation for hax extraction.
let same_deletion_table (a b: t_DeletionTable) : bool =
  match a, b <: (t_DeletionTable & t_DeletionTable) with
  | DeletionTable_WebSessions , DeletionTable_WebSessions
  | DeletionTable_ShareInbox , DeletionTable_ShareInbox
  | DeletionTable_SharedItems , DeletionTable_SharedItems
  | DeletionTable_Sends , DeletionTable_Sends
  | DeletionTable_VaultChunks , DeletionTable_VaultChunks
  | DeletionTable_OramBuckets , DeletionTable_OramBuckets
  | DeletionTable_Devices , DeletionTable_Devices  -> true
  | _ -> false

/// Every effect the driver emits agrees with the state it produces. In
/// particular no table or `users` delete and no commit is emitted before the
/// transaction started, and no commit is emitted before the `users` delete
/// succeeded.
let deletion_effect_is_sound (d: t_DeletionDriver) (v_effect: t_DeletionEffect) : bool =
  let common:bool = d.f_actor_active && d.f_same_account && ~.d.f_failed in
  match v_effect <: t_DeletionEffect with
  | DeletionEffect_ScanDevices  ->
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_ObserveDevices  -> true
      | _ -> false) &&
    common &&
    ~.d.f_devices_locked &&
    ~.d.f_devices_lockout_done &&
    ~.d.f_web_sessions_locked &&
    ~.d.f_web_sessions_lockout_done &&
    ~.d.f_transaction_open &&
    ~.d.f_transaction_started &&
    ~.d.f_users_deleted &&
    ~.d.f_committed &&
    ~.d.f_responded
  | DeletionEffect_LockoutDevices  ->
    common &&
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_LockoutDevices  -> true
      | _ -> false) &&
    d.f_devices_locked &&
    ~.d.f_devices_lockout_done &&
    ~.d.f_web_sessions_locked &&
    ~.d.f_transaction_open &&
    ~.d.f_committed &&
    ~.d.f_responded
  | DeletionEffect_ScanWebSessions  ->
    common &&
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_ObserveWebSessions  -> true
      | _ -> false) &&
    d.f_devices_locked &&
    d.f_devices_lockout_done &&
    ~.d.f_web_sessions_locked &&
    ~.d.f_web_sessions_lockout_done &&
    ~.d.f_transaction_open &&
    ~.d.f_committed &&
    ~.d.f_responded
  | DeletionEffect_LockoutWebSessions  ->
    common &&
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_LockoutWebSessions  -> true
      | _ -> false) &&
    d.f_devices_lockout_done &&
    d.f_web_sessions_locked &&
    ~.d.f_web_sessions_lockout_done &&
    ~.d.f_transaction_open &&
    ~.d.f_committed &&
    ~.d.f_responded
  | DeletionEffect_BeginTransaction  ->
    common &&
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_BeginTransaction  -> true
      | _ -> false) &&
    d.f_devices_lockout_done &&
    d.f_web_sessions_lockout_done &&
    d.f_transaction_open &&
    ~.d.f_transaction_started &&
    ~.d.f_users_deleted &&
    ~.d.f_committed &&
    ~.d.f_responded
  | DeletionEffect_DeleteTable table ->
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_DeleteTable current ->
        same_deletion_table current table && common && d.f_devices_lockout_done &&
        d.f_web_sessions_lockout_done &&
        d.f_transaction_started &&
        ~.d.f_users_deleted &&
        ~.d.f_committed &&
        ~.d.f_responded
      | _ -> false)
  | DeletionEffect_DeleteUsers  ->
    common &&
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_DeleteUsers  -> true
      | _ -> false) &&
    d.f_devices_lockout_done &&
    d.f_web_sessions_lockout_done &&
    d.f_transaction_started &&
    ~.d.f_users_deleted &&
    ~.d.f_committed &&
    ~.d.f_responded
  | DeletionEffect_CommitTransaction  ->
    common &&
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_Commit  -> true
      | _ -> false) &&
    d.f_transaction_started &&
    d.f_users_deleted &&
    ~.d.f_committed &&
    ~.d.f_responded
  | DeletionEffect_Complete  ->
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_Done  -> true
      | _ -> false) &&
    d.f_actor_active &&
    d.f_same_account &&
    d.f_transaction_started &&
    d.f_users_deleted &&
    d.f_committed &&
    d.f_responded &&
    ~.d.f_failed
  | DeletionEffect_Fail _ ->
    (match d.f_stage <: t_DeletionStage with
      | DeletionStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded &&
    ~.d.f_committed
  | DeletionEffect_Idle  -> true

let transition (driver: t_DeletionDriver) (v_effect: t_DeletionEffect) : t_DeletionTransition =
  { f_driver = driver; f_effect = v_effect } <: t_DeletionTransition

let idle (driver: t_DeletionDriver) : t_DeletionTransition =
  transition driver (DeletionEffect_Idle <: t_DeletionEffect)

let terminal (driver: t_DeletionDriver) (failure: t_DeletionFailure) : t_DeletionTransition =
  transition ({ driver with f_stage = DeletionStage_Done <: t_DeletionStage; f_failed = true }
      <:
      t_DeletionDriver)
    (DeletionEffect_Fail failure <: t_DeletionEffect)

/// Start a per-request account deletion. An actor the middleware did not
/// verify as an authenticated, active device — or a request whose effects are
/// not scoped to the session\'s own account — produces a terminal failure
/// without any effect, so no scan, lockout or SQL statement is authorized.
let begin_deletion (actor: t_DeletionActorObservation)
    : Prims.Pure t_DeletionTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_state_is_sound result.f_driver &&
          deletion_effect_is_sound result.f_driver result.f_effect) =
  let actor_active:bool = actor.f_authenticated && actor.f_device_active in
  if actor_active && actor.f_scoped_to_session_account
  then
    transition ({
          f_stage = DeletionStage_ObserveDevices <: t_DeletionStage;
          f_actor_active = true;
          f_same_account = true;
          f_devices_locked = false;
          f_devices_lockout_done = false;
          f_web_sessions_locked = false;
          f_web_sessions_lockout_done = false;
          f_transaction_open = false;
          f_transaction_started = false;
          f_users_deleted = false;
          f_committed = false;
          f_responded = false;
          f_failed = false
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_ScanDevices <: t_DeletionEffect)
  else
    let failure:t_DeletionFailure =
      if actor_active
      then DeletionFailure_CrossAccount <: t_DeletionFailure
      else DeletionFailure_Unauthenticated <: t_DeletionFailure
    in
    transition ({
          f_stage = DeletionStage_Done <: t_DeletionStage;
          f_actor_active = actor_active;
          f_same_account = false;
          f_devices_locked = false;
          f_devices_lockout_done = false;
          f_web_sessions_locked = false;
          f_web_sessions_lockout_done = false;
          f_transaction_open = false;
          f_transaction_started = false;
          f_users_deleted = false;
          f_committed = false;
          f_responded = false;
          f_failed = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_Fail failure <: t_DeletionEffect)

let on_devices_scanned (driver: t_DeletionDriver) (observation: t_ScanObservation)
    : t_DeletionTransition =
  match observation <: t_ScanObservation with
  | ScanObservation_Rows  ->
    transition ({
          driver with
          f_stage = DeletionStage_LockoutDevices <: t_DeletionStage;
          f_devices_locked = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_LockoutDevices <: t_DeletionEffect)
  | ScanObservation_QueryFailed  ->
    terminal driver (DeletionFailure_DeviceScanStorage <: t_DeletionFailure)

let on_device_lockout_completed (driver: t_DeletionDriver) (observation: t_LockoutObservation)
    : t_DeletionTransition =
  match observation <: t_LockoutObservation with
  | LockoutObservation_Applied
  | LockoutObservation_StorageFailed  ->
    transition ({
          driver with
          f_stage = DeletionStage_ObserveWebSessions <: t_DeletionStage;
          f_devices_lockout_done = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_ScanWebSessions <: t_DeletionEffect)

let on_web_sessions_scanned (driver: t_DeletionDriver) (observation: t_ScanObservation)
    : t_DeletionTransition =
  match observation <: t_ScanObservation with
  | ScanObservation_Rows  ->
    transition ({
          driver with
          f_stage = DeletionStage_LockoutWebSessions <: t_DeletionStage;
          f_web_sessions_locked = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_LockoutWebSessions <: t_DeletionEffect)
  | ScanObservation_QueryFailed  ->
    terminal driver (DeletionFailure_WebSessionScanStorage <: t_DeletionFailure)

let on_web_session_lockout_completed (driver: t_DeletionDriver) (observation: t_LockoutObservation)
    : t_DeletionTransition =
  match observation <: t_LockoutObservation with
  | LockoutObservation_Applied
  | LockoutObservation_StorageFailed  ->
    transition ({
          driver with
          f_stage = DeletionStage_BeginTransaction <: t_DeletionStage;
          f_web_sessions_lockout_done = true;
          f_transaction_open = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_BeginTransaction <: t_DeletionEffect)

let on_transaction_observed (driver: t_DeletionDriver) (observation: t_TransactionObservation)
    : t_DeletionTransition =
  match observation <: t_TransactionObservation with
  | TransactionObservation_Begun  ->
    transition ({
          driver with
          f_stage
          =
          DeletionStage_DeleteTable (DeletionTable_WebSessions <: t_DeletionTable)
          <:
          t_DeletionStage;
          f_transaction_started = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_DeleteTable (DeletionTable_WebSessions <: t_DeletionTable) <: t_DeletionEffect
      )
  | TransactionObservation_Failed  ->
    terminal driver (DeletionFailure_TransactionStorage <: t_DeletionFailure)

let on_table_deleted
      (driver: t_DeletionDriver)
      (table: t_DeletionTable)
      (observation: t_TableDeleteObservation)
    : t_DeletionTransition =
  match observation <: t_TableDeleteObservation with
  | TableDeleteObservation_Deleted  ->
    (match table <: t_DeletionTable with
      | DeletionTable_WebSessions  ->
        transition ({
              driver with
              f_stage
              =
              DeletionStage_DeleteTable (DeletionTable_ShareInbox <: t_DeletionTable)
              <:
              t_DeletionStage
            }
            <:
            t_DeletionDriver)
          (DeletionEffect_DeleteTable (DeletionTable_ShareInbox <: t_DeletionTable)
            <:
            t_DeletionEffect)
      | DeletionTable_ShareInbox  ->
        transition ({
              driver with
              f_stage
              =
              DeletionStage_DeleteTable (DeletionTable_SharedItems <: t_DeletionTable)
              <:
              t_DeletionStage
            }
            <:
            t_DeletionDriver)
          (DeletionEffect_DeleteTable (DeletionTable_SharedItems <: t_DeletionTable)
            <:
            t_DeletionEffect)
      | DeletionTable_SharedItems  ->
        transition ({
              driver with
              f_stage
              =
              DeletionStage_DeleteTable (DeletionTable_Sends <: t_DeletionTable) <: t_DeletionStage
            }
            <:
            t_DeletionDriver)
          (DeletionEffect_DeleteTable (DeletionTable_Sends <: t_DeletionTable) <: t_DeletionEffect)
      | DeletionTable_Sends  ->
        transition ({
              driver with
              f_stage
              =
              DeletionStage_DeleteTable (DeletionTable_VaultChunks <: t_DeletionTable)
              <:
              t_DeletionStage
            }
            <:
            t_DeletionDriver)
          (DeletionEffect_DeleteTable (DeletionTable_VaultChunks <: t_DeletionTable)
            <:
            t_DeletionEffect)
      | DeletionTable_VaultChunks  ->
        transition ({
              driver with
              f_stage
              =
              DeletionStage_DeleteTable (DeletionTable_OramBuckets <: t_DeletionTable)
              <:
              t_DeletionStage
            }
            <:
            t_DeletionDriver)
          (DeletionEffect_DeleteTable (DeletionTable_OramBuckets <: t_DeletionTable)
            <:
            t_DeletionEffect)
      | DeletionTable_OramBuckets  ->
        transition ({
              driver with
              f_stage
              =
              DeletionStage_DeleteTable (DeletionTable_Devices <: t_DeletionTable)
              <:
              t_DeletionStage
            }
            <:
            t_DeletionDriver)
          (DeletionEffect_DeleteTable (DeletionTable_Devices <: t_DeletionTable) <: t_DeletionEffect
          )
      | DeletionTable_Devices  ->
        transition ({ driver with f_stage = DeletionStage_DeleteUsers <: t_DeletionStage }
            <:
            t_DeletionDriver)
          (DeletionEffect_DeleteUsers <: t_DeletionEffect))
  | TableDeleteObservation_Failed  ->
    terminal driver (DeletionFailure_TableStorage <: t_DeletionFailure)

let on_users_deleted (driver: t_DeletionDriver) (observation: t_UsersDeleteObservation)
    : t_DeletionTransition =
  match observation <: t_UsersDeleteObservation with
  | UsersDeleteObservation_Deleted  ->
    transition ({
          driver with
          f_stage = DeletionStage_Commit <: t_DeletionStage;
          f_users_deleted = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_CommitTransaction <: t_DeletionEffect)
  | UsersDeleteObservation_Absent  ->
    terminal driver (DeletionFailure_AccountNotFound <: t_DeletionFailure)
  | UsersDeleteObservation_Failed  ->
    terminal driver (DeletionFailure_UsersStorage <: t_DeletionFailure)

let on_commit_observed (driver: t_DeletionDriver) (observation: t_CommitObservation)
    : t_DeletionTransition =
  match observation <: t_CommitObservation with
  | CommitObservation_Committed  ->
    transition ({
          driver with
          f_stage = DeletionStage_Done <: t_DeletionStage;
          f_committed = true;
          f_responded = true
        }
        <:
        t_DeletionDriver)
      (DeletionEffect_Complete <: t_DeletionEffect)
  | CommitObservation_Failed  ->
    terminal driver (DeletionFailure_CommitStorage <: t_DeletionFailure)

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
/// The third conjunct is the account-existence decision the transaction relies
/// on: a `CommitTransaction` effect exists exactly when the `users` delete was
/// observed from the `DeleteUsers` stage and reported the row deleted. A
/// zero-row (`Absent`) or failed `users` delete can therefore never authorize a
/// commit, which is what makes a second deletion of the same account unable to
/// commit.
let step (driver: t_DeletionDriver) (event: t_DeletionEvent)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver) &&
          (~.(match result.f_effect <: t_DeletionEffect with
            | DeletionEffect_CommitTransaction  -> true
            | _ -> false) ||
          (match event <: t_DeletionEvent with
            | DeletionEvent_UsersDeleted (UsersDeleteObservation_Deleted ) -> true
            | _ -> false) &&
          (match driver.f_stage <: t_DeletionStage with
            | DeletionStage_DeleteUsers  -> true
            | _ -> false)) &&
          (~.((match event <: t_DeletionEvent with
              | DeletionEvent_UsersDeleted (UsersDeleteObservation_Deleted ) -> true
              | _ -> false) &&
            (match driver.f_stage <: t_DeletionStage with
              | DeletionStage_DeleteUsers  -> true
              | _ -> false)) ||
          (match result.f_effect <: t_DeletionEffect with
            | DeletionEffect_CommitTransaction  -> true
            | _ -> false))) =
  match event <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned observation ->
    if
      match driver.f_stage <: t_DeletionStage with
      | DeletionStage_ObserveDevices  -> true
      | _ -> false
    then on_devices_scanned driver observation
    else idle driver
  | DeletionEvent_DeviceLockout observation ->
    if
      match driver.f_stage <: t_DeletionStage with
      | DeletionStage_LockoutDevices  -> true
      | _ -> false
    then on_device_lockout_completed driver observation
    else idle driver
  | DeletionEvent_WebSessionsScanned observation ->
    if
      match driver.f_stage <: t_DeletionStage with
      | DeletionStage_ObserveWebSessions  -> true
      | _ -> false
    then on_web_sessions_scanned driver observation
    else idle driver
  | DeletionEvent_WebSessionLockout observation ->
    if
      match driver.f_stage <: t_DeletionStage with
      | DeletionStage_LockoutWebSessions  -> true
      | _ -> false
    then on_web_session_lockout_completed driver observation
    else idle driver
  | DeletionEvent_Transaction observation ->
    if
      match driver.f_stage <: t_DeletionStage with
      | DeletionStage_BeginTransaction  -> true
      | _ -> false
    then on_transaction_observed driver observation
    else idle driver
  | DeletionEvent_TableDeleted observation ->
    (match driver.f_stage <: t_DeletionStage with
      | DeletionStage_DeleteTable table -> on_table_deleted driver table observation
      | _ -> idle driver)
  | DeletionEvent_UsersDeleted observation ->
    if
      match driver.f_stage <: t_DeletionStage with
      | DeletionStage_DeleteUsers  -> true
      | _ -> false
    then on_users_deleted driver observation
    else idle driver
  | DeletionEvent_Commit observation ->
    if
      match driver.f_stage <: t_DeletionStage with
      | DeletionStage_Commit  -> true
      | _ -> false
    then on_commit_observed driver observation
    else idle driver

let on_devices_scanned_event (driver: t_DeletionDriver) (observation: t_ScanObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_DevicesScanned observation <: t_DeletionEvent)

let on_device_lockout_event (driver: t_DeletionDriver) (observation: t_LockoutObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_DeviceLockout observation <: t_DeletionEvent)

let on_web_sessions_scanned_event (driver: t_DeletionDriver) (observation: t_ScanObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_WebSessionsScanned observation <: t_DeletionEvent)

let on_web_session_lockout_event (driver: t_DeletionDriver) (observation: t_LockoutObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_WebSessionLockout observation <: t_DeletionEvent)

let on_transaction_observed_event (driver: t_DeletionDriver) (observation: t_TransactionObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_Transaction observation <: t_DeletionEvent)

let on_table_deleted_event (driver: t_DeletionDriver) (observation: t_TableDeleteObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_TableDeleted observation <: t_DeletionEvent)

let on_users_deleted_event (driver: t_DeletionDriver) (observation: t_UsersDeleteObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_UsersDeleted observation <: t_DeletionEvent)

let on_commit_event (driver: t_DeletionDriver) (observation: t_CommitObservation)
    : Prims.Pure t_DeletionTransition
      (requires deletion_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_DeletionTransition = result in
          deletion_effect_is_sound result.f_driver result.f_effect &&
          (~.(deletion_state_is_sound driver <: bool) || deletion_state_is_sound result.f_driver)) =
  step driver (DeletionEvent_Commit observation <: t_DeletionEvent)
