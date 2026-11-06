module Vela_recovery_policy.Redemption_store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// What one write statement returned.
type t_WriteOutcome =
  | WriteOutcome_Applied : u64 -> t_WriteOutcome
  | WriteOutcome_Failed : t_WriteOutcome
