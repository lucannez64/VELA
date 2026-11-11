module Vela_recovery_policy_rate_model

/// A model of the fixed-window rate-limit counters the recovery handlers use,
/// and of how one plan's counter increment runs on them (F-1).
///
/// A store is one map from a counter key to its count. `rate_limit` runs the
/// extracted plan: the counter at the plan's key grows by one (saturating, as
/// `Store::incr_fixed_window` does), and `classify_rate_limit` decides
/// admission from the new value and the endpoint's documented limit. `f =
/// Some k` makes the k-th statement fail; a failed statement leaves the
/// counters unchanged.
///
/// What this module trusts, and `vela-server/src/recovery/conformance.rs`
/// checks against a real sled store: the rendering of the statement to its key
/// and window, the store's increment, and TTL expiry (a scheduler choice, not
/// modelled).
///
/// `vela-recovery-policy/src/redemption_model.rs::rate_limit` mirrors this
/// module; its `pre_driver_rate_and_backfill_vectors` test and the
/// `vector_rate_*` lemmas below check the same concrete runs.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Rate_store

module L = FStar.List.Tot

type text = Alloc.String.t_String

/// The counters: key -> count.
type counters = text -> option u64

/// The live count under a key (a missing counter is zero).
let counter (c: counters) (key: text) : u64 =
  match c key with
  | Some n -> n
  | None -> mk_u64 0

/// The saturating increment the store performs.
let bump (n: u64) : u64 = Rust_primitives.Integers.add_sat #U64 n (mk_u64 1)

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// A plan: one counter increment, stopping at the injected failure.
let rec run
      (c: counters) (stmts: list t_RateStmt) (k: nat) (f: option nat)
  : Tot (t_RateOutcome & counters) (decreases stmts) =
  match stmts with
  | [] -> (RateOutcome_Failed, c)
  | s :: rest ->
    if faulted f k
    then (RateOutcome_Failed, c)
    else
      match s with
      | RateStmt_Incr { f_key = key } ->
        let n = bump (counter c key) in
        (RateOutcome_Count n,
         (fun k' -> if k' = key then Some n else c k'))
      | _ -> (RateOutcome_Failed, c)

let stmts_of (p: Alloc.Vec.t_Vec t_RateStmt Alloc.Alloc.t_Global) : list t_RateStmt =
  Seq.seq_to_list p._0

let slice_of (#a: Type) (l: list a{L.length l <= Rust_primitives.Integers.max_usize})
  : t_Slice a =
  Seq.seq_of_list l

/// One limiter check: plan (extracted), run, classify (extracted).
let rate_limit
      (c: counters) (key: text) (window_secs limit: u64) (f: option nat)
  : (t_RateObservation & counters) =
  let r = run c (stmts_of (plan_rate_limit key window_secs)) 0 f in
  (classify_rate_limit (slice_of [fst r]) limit, snd r)
