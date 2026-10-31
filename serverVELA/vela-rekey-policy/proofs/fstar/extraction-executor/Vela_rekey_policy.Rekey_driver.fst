module Vela_rekey_policy.Rekey_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Outcome of one readiness/completeness `SELECT 1 ... LIMIT 1` probe.
type t_ProbeObservation =
  | ProbeObservation_Empty : t_ProbeObservation
  | ProbeObservation_Found : t_ProbeObservation
  | ProbeObservation_Storage : t_ProbeObservation

/// Outcome of opening or committing the freeze transaction.
type t_TransactionObservation =
  | TransactionObservation_Committed : t_TransactionObservation
  | TransactionObservation_Failed : t_TransactionObservation

/// Outcome of the inventory read inside the freeze transaction.
type t_InventoryObservation =
  | InventoryObservation_Read : t_InventoryObservation
  | InventoryObservation_Failed : t_InventoryObservation

/// Outcome of a compare-and-swap `UPDATE`.
type t_CasObservation =
  | CasObservation_Updated : t_CasObservation
  | CasObservation_Skipped : t_CasObservation
  | CasObservation_Storage : t_CasObservation

/// Outcome of the post-freeze cleanup delete.
type t_CleanupObservation =
  | CleanupObservation_Done : t_CleanupObservation
  | CleanupObservation_Storage : t_CleanupObservation

/// Outcome of one capsule target update.
type t_CapsuleObservation =
  | CapsuleObservation_Stored : t_CapsuleObservation
  | CapsuleObservation_Invalid : t_CapsuleObservation
  | CapsuleObservation_NotTarget : t_CapsuleObservation
  | CapsuleObservation_Storage : t_CapsuleObservation

/// Outcome of the abort / timeout rollback CAS and its cleanup.
type t_RollbackObservation =
  | RollbackObservation_RolledBack : t_RollbackObservation
  | RollbackObservation_Raced : t_RollbackObservation
  | RollbackObservation_Storage : t_RollbackObservation

/// The superseded-row sweep is best effort: the handler only logs a failure.
type t_SweepObservation =
  | SweepObservation_Done : t_SweepObservation
  | SweepObservation_Failed : t_SweepObservation
