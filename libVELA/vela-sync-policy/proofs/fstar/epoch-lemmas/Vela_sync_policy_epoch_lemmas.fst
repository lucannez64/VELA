module Vela_sync_policy_epoch_lemmas

/// Parametric properties of the F-5 mobile epoch-agreement kernel.
///
/// `Vela_sync_policy.plan_sync_epoch_match` only carries a postcondition that
/// its result *equals* `sync_epochs_agree_for_download`, which is a definitional
/// wrapper around the same expression. That is enough to show the extracted code
/// matches itself, but it does not state the property an integrator relies on:
/// *every* accepted observation is exactly a positive, equal pair, and *every*
/// positive/equal pair is accepted.
///
/// The predicate below is therefore written out independently of the
/// implementation, and the lemmas quantify over all `i64` inputs instead of
/// replaying a handful of concrete witnesses.

open FStar.Mul
open Core_models
open Vela_sync_policy

/// Independent statement of the admission property. Deliberately not defined by
/// calling the extracted decision function.
let download_epoch_admissible (server local: i64) : bool =
  v server > 0 && v local > 0 && v server = v local

/// Accepted => both epochs positive and equal.
let accepted_implies_positive_and_equal (facts: t_SyncEpochFacts)
  : Lemma
    (requires (plan_sync_epoch_match facts = true))
    (ensures (
      v facts.f_server_epoch > 0 /\
      v facts.f_local_epoch > 0 /\
      v facts.f_server_epoch = v facts.f_local_epoch))
  = ()

/// Converse: a positive, equal pair is always accepted.
let positive_and_equal_admits (facts: t_SyncEpochFacts)
  : Lemma
    (requires (
      v facts.f_server_epoch > 0 /\
      v facts.f_local_epoch > 0 /\
      v facts.f_server_epoch = v facts.f_local_epoch))
    (ensures (plan_sync_epoch_match facts = true))
  = ()

/// The decision is exactly the independently stated predicate for every
/// observation (both directions at once).
let plan_matches_independent_predicate (facts: t_SyncEpochFacts)
  : Lemma
    (plan_sync_epoch_match facts =
     download_epoch_admissible facts.f_server_epoch facts.f_local_epoch)
  = ()

/// Refusal direction stated on its own: a rejected observation is never a
/// positive, equal pair. (Could be derived from the equality above, but the
/// refusal claim is what a reviewer checks.)
let rejected_implies_not_admissible (facts: t_SyncEpochFacts)
  : Lemma
    (requires (plan_sync_epoch_match facts = false))
    (ensures (~(
      v facts.f_server_epoch > 0 /\
      v facts.f_local_epoch > 0 /\
      v facts.f_server_epoch = v facts.f_local_epoch)))
  = ()

/// Parametric form over bare epochs, independent of the facts record: any equal
/// positive pair is admitted.
let equal_positive_pair_admits (server local: i64)
  : Lemma
    (requires (v server > 0 /\ v local > 0 /\ v server = v local))
    (ensures (
      sync_epochs_agree_for_download
        ({ f_server_epoch = server; f_local_epoch = local }) = true))
  = ()

/// Parametric refusal: a disagreement in either direction, or a nonpositive
/// epoch, is never admitted.
let mismatched_or_nonpositive_pair_refuses (server local: i64)
  : Lemma
    (requires (~(v server > 0 /\ v local > 0 /\ v server = v local)))
    (ensures (
      sync_epochs_agree_for_download
        ({ f_server_epoch = server; f_local_epoch = local }) = false))
  = ()
