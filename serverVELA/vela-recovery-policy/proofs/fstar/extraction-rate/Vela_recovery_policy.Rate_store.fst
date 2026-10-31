module Vela_recovery_policy.Rate_store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// One statement a rate limiter runs.
type t_RateStmt =
  | RateStmt_Incr {
    f_key:Alloc.String.t_String;
    f_window_secs:u64
  }: t_RateStmt

/// What one counter increment returned.
type t_RateOutcome =
  | RateOutcome_Failed : t_RateOutcome
  | RateOutcome_Count : u64 -> t_RateOutcome

/// The limiter's verdict.
type t_RateObservation =
  | RateObservation_Admitted : t_RateObservation
  | RateObservation_Limited : t_RateObservation
  | RateObservation_StorageFailed : t_RateObservation

/// One fixed-window counter increment at the exact key and window.
let plan_rate_limit (key: Alloc.String.t_String) (window_secs: u64)
    : Alloc.Vec.t_Vec t_RateStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_RateStmt
    #Alloc.Alloc.t_Global
    ((let list = [RateStmt_Incr ({ f_key = key; f_window_secs = window_secs }) <: t_RateStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_RateStmt)

/// Whether a counter value is within an endpoint's limit.
let under_limit (count limit: u64) : bool = count <=. limit

/// `Admitted` exactly while the counter's new value is within the limit.
let classify_rate_limit (outcomes: t_Slice t_RateOutcome) (limit: u64) : t_RateObservation =
  if (Core_models.Slice.impl__len #t_RateOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_RateOutcome with
    | RateOutcome_Count count ->
      if under_limit count limit
      then RateObservation_Admitted <: t_RateObservation
      else RateObservation_Limited <: t_RateObservation
    | RateOutcome_Failed  -> RateObservation_StorageFailed <: t_RateObservation
  else RateObservation_StorageFailed <: t_RateObservation
