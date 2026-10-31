module Vela_recovery_policy_rate_lemmas

/// F-1 for the recovery rate limiters: for every starting counter table and
/// every fault point, the extracted plan's increment and the extracted
/// classifier report exactly what happened.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Rate_store
open Vela_recovery_policy_rate_model

module L = FStar.List.Tot
module SP = FStar.Seq.Properties

/// The slice a classifier reads is the outcome list, element by element.
let seq_of_list_facts (#a: Type) (l: list a)
  : Lemma (forall (i: nat). i < L.length l ==>
             Seq.index (Seq.seq_of_list l) i == L.index l i) =
  let aux (i: nat) : Lemma (i < L.length l ==>
                             Seq.index (Seq.seq_of_list l) i == L.index l i) =
    if i < L.length l then SP.lemma_seq_of_list_index l i
  in
  FStar.Classical.forall_intro aux

#push-options "--fuel 4 --ifuel 2"

/// The limiter: the counter grows by exactly one at the plan's key
/// (saturating), a failure leaves every counter unchanged, and the verdict is
/// exactly the new count against the endpoint's limit.
let rate_limit_is_honest
      (c: counters) (key: text) (window_secs limit: u64) (f: option nat)
  : Lemma
    (let (obs, post) = rate_limit c key window_secs limit f in
     (obs == RateObservation_StorageFailed <==> faulted f 0) /\
     (obs == RateObservation_Admitted <==>
        (not (faulted f 0) /\ under_limit (bump (counter c key)) limit)) /\
     (obs == RateObservation_Limited <==>
        (not (faulted f 0) /\
         not (under_limit (bump (counter c key)) limit))) /\
     (not (faulted f 0) ==>
        (post key == Some (bump (counter c key)) /\
         (forall (other: text). other <> key ==> post other == c other))) /\
     (faulted f 0 ==> post == c)) =
  let r = run c (stmts_of (plan_rate_limit key window_secs)) 0 f in
  seq_of_list_facts [fst r]

/// An admitted request grew exactly the plan's counter by one and changed no
/// other counter.
let rate_limit_only_counts_one
      (c: counters) (key: text) (window_secs limit: u64) (f: option nat)
  : Lemma
    (fst (rate_limit c key window_secs limit f) == RateObservation_Admitted ==>
       (not (faulted f 0) /\
        snd (rate_limit c key window_secs limit f) key
        == Some (bump (counter c key)) /\
        (forall (other: text). other <> key ==>
           snd (rate_limit c key window_secs limit f) other == c other))) =
  rate_limit_is_honest c key window_secs limit f

/// A refusal is a request that pushed its counter past the limit, or a store
/// failure; the counter's new value is never hidden.
let limited_only_past_the_limit
      (c: counters) (key: text) (window_secs limit: u64) (f: option nat)
  : Lemma
    (fst (rate_limit c key window_secs limit f) == RateObservation_Limited ==>
       (not (faulted f 0) /\
        not (under_limit (bump (counter c key)) limit))) =
  rate_limit_is_honest c key window_secs limit f

// ── Vectors shared with `redemption_model.rs` ──────────────────────────────

let s (x: string) : text = Alloc.String.String x

let vector_counters : counters =
  (fun k -> if k = s "rl" then Some (mk_u64 2) else None)

let vector_rate ()
  : Lemma
    (let (obs, post) = rate_limit vector_counters (s "rl") (mk_u64 60) (mk_u64 3) None in
     obs == RateObservation_Admitted /\
     post (s "rl") == Some (mk_u64 3) /\
     (fst (rate_limit post (s "rl") (mk_u64 60) (mk_u64 3) None)
      == RateObservation_Limited)) =
  rate_limit_is_honest vector_counters (s "rl") (mk_u64 60) (mk_u64 3) None;
  rate_limit_is_honest
    (snd (rate_limit vector_counters (s "rl") (mk_u64 60) (mk_u64 3) None))
    (s "rl") (mk_u64 60) (mk_u64 3) None

let vector_rate_failure ()
  : Lemma
    (let (obs, post) = rate_limit vector_counters (s "rl") (mk_u64 60) (mk_u64 3) (Some 0) in
     obs == RateObservation_StorageFailed /\ post == vector_counters) =
  rate_limit_is_honest vector_counters (s "rl") (mk_u64 60) (mk_u64 3) (Some 0)

#pop-options
