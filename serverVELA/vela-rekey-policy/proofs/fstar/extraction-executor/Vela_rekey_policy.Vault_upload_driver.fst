module Vela_rekey_policy.Vault_upload_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Outcome of the guarded `INSERT`/`UPDATE`.
type t_WriteObservation =
  | WriteObservation_Inserted : t_WriteObservation
  | WriteObservation_Updated : t_WriteObservation
  | WriteObservation_Existing : t_WriteObservation
  | WriteObservation_Skipped : t_WriteObservation
  | WriteObservation_Duplicate : t_WriteObservation
  | WriteObservation_Failed : t_WriteObservation

/// Version read-back after a successful write.
type t_RereadObservation =
  | RereadObservation_Read { f_version:i64 }: t_RereadObservation
  | RereadObservation_Missing : t_RereadObservation
  | RereadObservation_Failed : t_RereadObservation

/// Shadow-activity refresh outcome. `Ended` means the guarded refresh matched
/// zero rows because the rotation ended; the handler treats it as non-fatal.
type t_ActivityObservation =
  | ActivityObservation_Refreshed : t_ActivityObservation
  | ActivityObservation_Ended : t_ActivityObservation
  | ActivityObservation_Failed : t_ActivityObservation

/// A decoded `vault_chunks` row, or a lookup failure.
type t_ReadLookupObservation =
  | ReadLookupObservation_Found {
    f_account_matches:bool;
    f_epoch_matches:bool;
    f_version:i64;
    f_lamport_clock:i64
  }: t_ReadLookupObservation
  | ReadLookupObservation_Missing : t_ReadLookupObservation
  | ReadLookupObservation_QueryFailed : t_ReadLookupObservation
  | ReadLookupObservation_Malformed : t_ReadLookupObservation
