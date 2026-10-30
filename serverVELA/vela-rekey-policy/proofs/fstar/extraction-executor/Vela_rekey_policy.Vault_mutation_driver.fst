module Vela_rekey_policy.Vault_mutation_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

type t_VersionObservation =
  | VersionObservation_Found { f_version:i64 }: t_VersionObservation
  | VersionObservation_Missing : t_VersionObservation
  | VersionObservation_Storage : t_VersionObservation

type t_DeleteObservation =
  | DeleteObservation_Deleted : t_DeleteObservation
  | DeleteObservation_Skipped : t_DeleteObservation
  | DeleteObservation_Storage : t_DeleteObservation

type t_BucketObservation =
  | BucketObservation_Written : t_BucketObservation
  | BucketObservation_Invalid : t_BucketObservation
  | BucketObservation_Existing : t_BucketObservation
  | BucketObservation_Skipped : t_BucketObservation
  | BucketObservation_Storage : t_BucketObservation

type t_SchemaWriteObservation =
  | SchemaWriteObservation_Written : t_SchemaWriteObservation
  | SchemaWriteObservation_Storage : t_SchemaWriteObservation

type t_AckObservation =
  | AckObservation_Cleared : t_AckObservation
  | AckObservation_Missed : t_AckObservation
  | AckObservation_Storage : t_AckObservation

type t_PendingObservation =
  | PendingObservation_Replay : t_PendingObservation
  | PendingObservation_Pending : t_PendingObservation
  | PendingObservation_Missing : t_PendingObservation
  | PendingObservation_Storage : t_PendingObservation

type t_AttestObservation =
  | AttestObservation_Attested : t_AttestObservation
  | AttestObservation_Missing : t_AttestObservation
  | AttestObservation_Storage : t_AttestObservation
