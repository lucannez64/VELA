module Vela_sync_policy_chunk_lemmas

/// Universal, independent statement of the chunk-download admission kernel.
///
/// `Vela_sync_policy.plan_chunk_download` carries an `ensures` clause that
/// compares its result with `chunk_download_decision_matches_spec`. That spec
/// function is a wrapper around `chunk_download_is_authorized`, so by itself it
/// only shows the planner agrees with its own definition: the concrete
/// `rolled_back_chunk_can_be_accepted` witness is a single sample, not a
/// universal rollback claim.
///
/// This module writes the admission property out independently — over the raw
/// `i64` clock, the optional baseline, and the two caller-supplied flags — and
/// then proves, for *all* observations, that the actual extracted planner
/// returns `Accept` exactly when that independent predicate holds, with a
/// permit whose clock is exactly the admitted server clock. It also pins the
/// `None` (first contact) versus `Some 0` boundary, signed-clock extremes and a false epoch flag, and an arbitrary (parameterised) old baseline.
///
/// Nothing here defines the predicate by calling the extracted decision
/// function, and no proof uses `assume`, `admit`, `--lax` or a weakened guard.

open FStar.Mul
open Core_models
open Vela_sync_policy

// ── An independently stated admission predicate ─────────────────────────────

/// `last_seen_lamport = None` means "no baseline recorded yet": there is no
/// floor to compare against. A recorded baseline only admits a clock at or
/// above it (equal clocks are re-deliveries, not rollbacks). Written with the
/// comparison reversed relative to the implementation to keep the statement
/// independent of its surface syntax.
let last_seen_floor_holds
      (clock: i64)
      (last_seen: Core_models.Option.t_Option i64)
    : bool =
  match last_seen with
  | Core_models.Option.Option_None -> true
  | Core_models.Option.Option_Some seen -> v seen <= v clock

/// The admission property an integrator relies on, stated over raw values:
/// the caller-supplied AAD and epoch-positivity flags must hold,
/// the server clock must name a real Lamport revision (>= 1), and a recorded
/// baseline must not be rolled past.
let chunk_admissible
      (clock: i64)
      (last_seen: Core_models.Option.t_Option i64)
      (aad_binding_verified key_epoch_positive: bool)
    : bool =
  aad_binding_verified && key_epoch_positive && 1 <= v clock &&
  last_seen_floor_holds clock last_seen

let facts_admissible (facts: t_ChunkDownloadFacts) : bool =
  chunk_admissible
    facts.f_server_lamport
    facts.f_last_seen_lamport
    facts.f_aad_binding_verified
    facts.f_key_epoch_positive

/// The only permit the planner may issue for these facts.
let permit_of (clock: i64) : t_ChunkDownloadPermit =
  { f_lamport = clock }

let facts_of
      (clock: i64)
      (last_seen: Core_models.Option.t_Option i64)
      (aad_binding_verified key_epoch_positive: bool)
    : t_ChunkDownloadFacts =
  {
    f_server_lamport = clock;
    f_last_seen_lamport = last_seen;
    f_aad_binding_verified = aad_binding_verified;
    f_key_epoch_positive = key_epoch_positive;
  }

// ── The implementation guard equals the independent predicate ──────────────

/// The extracted guard — including its nested option matching — decides
/// exactly the independently stated predicate. This is proved by exhaustive
/// case analysis on the baseline option, not by definitional aliasing.
let authorized_iff_independent_predicate (facts: t_ChunkDownloadFacts)
  : Lemma
    (chunk_download_is_authorized facts = facts_admissible facts)
  = match facts.f_last_seen_lamport with
    | Core_models.Option.Option_None -> ()
    | Core_models.Option.Option_Some _ -> ()

// ── The actual planner: universal equivalence and exact permit ─────────────

/// Headline theorem. For every observation and every candidate permit, the
/// *actual* extracted planner returns `Accept permit` if and only if the
/// independent predicate holds and the permit is exactly the server clock.
let accept_iff_admissible
      (facts: t_ChunkDownloadFacts)
      (permit: t_ChunkDownloadPermit)
    : Lemma
    ((plan_chunk_download facts = ChunkDownloadDecision_Accept permit) <==>
     (facts_admissible facts = true /\ permit = permit_of facts.f_server_lamport))
  = ()

/// Refusal direction, stated on its own: `Reject` is returned exactly when the
/// independent predicate is false.
let reject_iff_not_admissible (facts: t_ChunkDownloadFacts)
  : Lemma
    ((plan_chunk_download facts = ChunkDownloadDecision_Reject) <==>
     (facts_admissible facts = false))
  = ()

/// Every admission fixes all four facts and the exact permit clock/epoch
/// inputs the caller may rely on: the permit clock is the server clock, the AAD
/// flag is true, the key-epoch-positive flag is true, the clock is at least 1,
/// and any recorded baseline was not rolled back.
let accepted_permit_is_exact
      (facts: t_ChunkDownloadFacts)
      (permit: t_ChunkDownloadPermit)
    : Lemma
    (requires (plan_chunk_download facts = ChunkDownloadDecision_Accept permit))
    (ensures (
      permit.f_lamport = facts.f_server_lamport /\
      facts.f_aad_binding_verified = true /\
      facts.f_key_epoch_positive = true /\
      1 <= v facts.f_server_lamport /\
      last_seen_floor_holds facts.f_server_lamport facts.f_last_seen_lamport = true))
  = ()

/// A permit is unique: two acceptances of the same observations cannot carry
/// different clocks (and the record has no other field that could differ).
let accept_permit_is_unique
      (facts: t_ChunkDownloadFacts)
      (p q: t_ChunkDownloadPermit)
    : Lemma
    (requires (
      plan_chunk_download facts = ChunkDownloadDecision_Accept p /\
      plan_chunk_download facts = ChunkDownloadDecision_Accept q))
    (ensures (p = q))
  = ()

/// A first-contact observation (`None`) is accepted exactly when the remaining
/// conjuncts hold, and the accepted permit clock is the server clock.
let none_baseline_accepts_exactly_positive_bound
      (clock: i64)
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    ((plan_chunk_download
        (facts_of clock Core_models.Option.Option_None aad_binding_verified key_epoch_positive)
      = ChunkDownloadDecision_Accept (permit_of clock)) <==>
     (aad_binding_verified && key_epoch_positive && 1 <= v clock))
  = ()

// ── `None` versus `Some 0` ─────────────────────────────────────────────────

/// A missing baseline and a recorded baseline of `0` decide identically for
/// every clock: the `>= 1` conjunct already excludes the only clock (`0`) where
/// a naive "treat None as 0" reading could have differed, and no negative
/// clock can pass either. They remain different *caller state* (first contact
/// versus a recorded zero), which the permit does not record, so the caller
/// must keep the distinction; the admission decision itself cannot.
let none_baseline_matches_zero_baseline
      (clock: i64)
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    (chunk_admissible clock Core_models.Option.Option_None
       aad_binding_verified key_epoch_positive
     =
     chunk_admissible clock (Core_models.Option.Option_Some (mk_i64 0))
       aad_binding_verified key_epoch_positive)
  = ()

/// Clock `0` is rejected with no baseline at all, so first contact is not a
/// licence to admit an unnumbered revision.
let clock_zero_rejected_without_baseline
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 0) Core_models.Option.Option_None
          aad_binding_verified key_epoch_positive)
     = ChunkDownloadDecision_Reject)
  = ()

/// Clock `0` is likewise rejected when a zero baseline was recorded.
let clock_zero_rejected_with_zero_baseline
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 0) (Core_models.Option.Option_Some (mk_i64 0))
          aad_binding_verified key_epoch_positive)
     = ChunkDownloadDecision_Reject)
  = ()

// ── Parameterised old baseline ─────────────────────────────────────────────

/// For an arbitrary recorded baseline `b` (not just 7), with the other facts
/// good, the planner accepts exactly the clock values at or above `b`.
let baseline_floor_is_exact
      (clock baseline: i64)
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    ((plan_chunk_download
        (facts_of clock (Core_models.Option.Option_Some baseline)
           aad_binding_verified key_epoch_positive)
      = ChunkDownloadDecision_Accept (permit_of clock)) <==>
     (aad_binding_verified && key_epoch_positive && 1 <= v clock /\
      v baseline <= v clock))
  = ()

/// For an arbitrary recorded baseline `b`, any clock strictly below it is a
/// rollback and refuses — the universal form of the constant `Some 7` witness.
let stale_clock_rejected_for_any_baseline
      (clock baseline: i64)
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    (requires (v clock < v baseline))
    (ensures (
      plan_chunk_download
        (facts_of clock (Core_models.Option.Option_Some baseline)
           aad_binding_verified key_epoch_positive)
      = ChunkDownloadDecision_Reject))
  = ()

/// Equal-clock re-delivery of the same revision is admitted with that clock.
let equal_clock_redelivery_admitted
      (clock: i64)
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    (requires (1 <= v clock /\ aad_binding_verified /\ key_epoch_positive))
    (ensures (
      plan_chunk_download
        (facts_of clock (Core_models.Option.Option_Some clock)
           aad_binding_verified key_epoch_positive)
      = ChunkDownloadDecision_Accept (permit_of clock)))
  = ()

// ── Signed clock extremes / false epoch flag ─────────────────────────────────

/// The least signed 64-bit clock never names a revision.
let min_i64_clock_rejected
      (last_seen: Core_models.Option.t_Option i64)
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 (minint I64)) last_seen
          aad_binding_verified key_epoch_positive)
     = ChunkDownloadDecision_Reject)
  = ()

/// Clock `-1` never names a revision either, even with a permissive baseline
/// and both flags set.
let minus_one_clock_rejected
      (last_seen: Core_models.Option.t_Option i64)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 (-1)) last_seen true true)
     = ChunkDownloadDecision_Reject)
  = ()

/// A negative baseline cannot launder a nonpositive clock into an admission:
/// the `>= 1` conjunct is independent of the baseline floor.
let negative_baseline_does_not_admit_nonpositive_clock
      (aad_binding_verified key_epoch_positive: bool)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 0) (Core_models.Option.Option_Some (mk_i64 (-7)))
          aad_binding_verified key_epoch_positive)
     = ChunkDownloadDecision_Reject)
  = ()

/// A negative baseline is dominated by the positive-clock floor: the least
/// signed clock is still admitted when the incoming revision is clock 1.
let min_i64_baseline_admits_positive_clock (_: Prims.unit)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 1) (Core_models.Option.Option_Some (mk_i64 (minint I64)))
          true true)
     = ChunkDownloadDecision_Accept (permit_of (mk_i64 1)))
  = ()

/// A false epoch-positivity input refuses even the largest signed clock.
/// The derivation of this Boolean from an integer epoch is outside this module.
let negative_epoch_flag_rejects_largest_clock
      (last_seen: Core_models.Option.t_Option i64)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 (maxint I64)) last_seen true false)
     = ChunkDownloadDecision_Reject)
  = ()

/// Unverified AAD refuses even the largest signed clock.
let unverified_aad_rejects_largest_clock
      (last_seen: Core_models.Option.t_Option i64)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 (maxint I64)) last_seen false true)
     = ChunkDownloadDecision_Reject)
  = ()

// ── Nonvacuity witnesses ───────────────────────────────────────────────────

/// The equivalence has a true instance: first contact at clock 3 is admitted
/// with exactly permit clock 3.
let accept_witness_first_contact (_: Prims.unit)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 3) Core_models.Option.Option_None true true)
     = ChunkDownloadDecision_Accept (permit_of (mk_i64 3)))
  = ()

/// The equivalence has a false instance: a recorded baseline of 7 refuses
/// clock 3 (the concrete rollback the implementation always refused).
let reject_witness_rolled_back (_: Prims.unit)
    : Lemma
    (plan_chunk_download
       (facts_of (mk_i64 3) (Core_models.Option.Option_Some (mk_i64 7)) true true)
     = ChunkDownloadDecision_Reject)
  = ()
