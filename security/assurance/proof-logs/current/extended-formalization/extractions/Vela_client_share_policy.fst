module Vela_client_share_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

/// Revisions start at 1. Zero is never a valid revision.
let v_INITIAL_REVISION: u64 = mk_u64 1

/// What the client observed about one received envelope.
type t_ShareAdmissionFacts = {
  f_envelope_authenticated:bool;
  f_addressed_to_recipient:bool;
  f_sender_matches_attribution:bool;
  f_has_pin:bool;
  f_signer_matches_pin:bool;
  f_lineage_matches_pin:bool;
  f_pinned_revision:u64;
  f_candidate_revision:u64
}

/// Proof that the policy admitted an envelope. Fields are private: only this
/// crate can mint one, so callers cannot skip the decision.
type t_SharePinPermit = { f_revision:u64 }

type t_ShareAdmissionDecision =
  | ShareAdmissionDecision_AcceptFirstContact : t_SharePinPermit -> t_ShareAdmissionDecision
  | ShareAdmissionDecision_ApplyUpdate : t_SharePinPermit -> t_ShareAdmissionDecision
  | ShareAdmissionDecision_Reject : t_ShareAdmissionDecision

/// Conditions shared by both paths.
let envelope_is_bound (facts: t_ShareAdmissionFacts) : bool =
  facts.f_envelope_authenticated && facts.f_addressed_to_recipient &&
  facts.f_sender_matches_attribution &&
  facts.f_candidate_revision >=. v_INITIAL_REVISION

let first_contact_is_admissible (facts: t_ShareAdmissionFacts) : bool =
  ~.facts.f_has_pin && envelope_is_bound facts

let update_is_admissible (facts: t_ShareAdmissionFacts) : bool =
  facts.f_has_pin && envelope_is_bound facts && facts.f_signer_matches_pin &&
  facts.f_lineage_matches_pin &&
  facts.f_candidate_revision >. facts.f_pinned_revision

let admission_matches_spec (facts: t_ShareAdmissionFacts) (decision: t_ShareAdmissionDecision)
    : bool =
  match decision <: t_ShareAdmissionDecision with
  | ShareAdmissionDecision_AcceptFirstContact permit ->
    first_contact_is_admissible facts && permit.f_revision =. facts.f_candidate_revision
  | ShareAdmissionDecision_ApplyUpdate permit ->
    update_is_admissible facts && permit.f_revision =. facts.f_candidate_revision
  | ShareAdmissionDecision_Reject  ->
    ~.(first_contact_is_admissible facts <: bool) && ~.(update_is_admissible facts <: bool)

/// Decide what to do with one received envelope.
let plan_share_admission (facts: t_ShareAdmissionFacts)
    : Prims.Pure t_ShareAdmissionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ShareAdmissionDecision = decision in
          admission_matches_spec facts decision) =
  if first_contact_is_admissible facts
  then
    ShareAdmissionDecision_AcceptFirstContact
    ({ f_revision = facts.f_candidate_revision } <: t_SharePinPermit)
    <:
    t_ShareAdmissionDecision
  else
    if update_is_admissible facts
    then
      ShareAdmissionDecision_ApplyUpdate
      ({ f_revision = facts.f_candidate_revision } <: t_SharePinPermit)
      <:
      t_ShareAdmissionDecision
    else ShareAdmissionDecision_Reject <: t_ShareAdmissionDecision

let is_admitted (decision: t_ShareAdmissionDecision) : bool =
  match decision <: t_ShareAdmissionDecision with
  | ShareAdmissionDecision_Reject  -> false
  | _ -> true

/// An envelope whose signature did not verify (or that did not parse as v2 —
/// a legacy unsigned capsule) is never admitted.
let unauthenticated_share_can_be_admitted (facts: t_ShareAdmissionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ShareAdmissionFacts =
    { facts with f_envelope_authenticated = false } <: t_ShareAdmissionFacts
  in
  is_admitted (plan_share_admission facts <: t_ShareAdmissionDecision)

/// A signed envelope addressed to someone else (forwarded or retargeted) is
/// never admitted.
let misaddressed_share_can_be_admitted (facts: t_ShareAdmissionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ShareAdmissionFacts =
    { facts with f_addressed_to_recipient = false } <: t_ShareAdmissionFacts
  in
  is_admitted (plan_share_admission facts <: t_ShareAdmissionDecision)

/// An envelope whose signed sender differs from the server\'s attribution is
/// never admitted.
let misattributed_share_can_be_admitted (facts: t_ShareAdmissionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ShareAdmissionFacts =
    { facts with f_sender_matches_attribution = false } <: t_ShareAdmissionFacts
  in
  is_admitted (plan_share_admission facts <: t_ShareAdmissionDecision)

/// Once pinned, an update signed by any other key is never applied — even if
/// the server vouches for it.
let fforeign_signer_update_can_be_applied (facts: t_ShareAdmissionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ShareAdmissionFacts = { facts with f_has_pin = true } <: t_ShareAdmissionFacts in
  let facts:t_ShareAdmissionFacts =
    { facts with f_signer_matches_pin = false } <: t_ShareAdmissionFacts
  in
  is_admitted (plan_share_admission facts <: t_ShareAdmissionDecision)

/// Once pinned, an envelope from another lineage (another share by the same
/// sender) never replaces this one.
let cross_lineage_update_can_be_applied (facts: t_ShareAdmissionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ShareAdmissionFacts = { facts with f_has_pin = true } <: t_ShareAdmissionFacts in
  let facts:t_ShareAdmissionFacts =
    { facts with f_lineage_matches_pin = false } <: t_ShareAdmissionFacts
  in
  is_admitted (plan_share_admission facts <: t_ShareAdmissionDecision)

/// Once pinned, a replayed or older revision is never applied.
let stale_revision_update_can_be_applied (facts: t_ShareAdmissionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ShareAdmissionFacts = { facts with f_has_pin = true } <: t_ShareAdmissionFacts in
  let facts:t_ShareAdmissionFacts =
    if facts.f_candidate_revision >. facts.f_pinned_revision
    then
      let facts:t_ShareAdmissionFacts =
        { facts with f_candidate_revision = facts.f_pinned_revision } <: t_ShareAdmissionFacts
      in
      facts
    else facts
  in
  is_admitted (plan_share_admission facts <: t_ShareAdmissionDecision)

/// A pinned share is never re-admitted as a first contact (which would let a
/// server reset the pin to a key of its choosing).
let pinned_share_can_restart_as_first_contact (facts: t_ShareAdmissionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ShareAdmissionFacts = { facts with f_has_pin = true } <: t_ShareAdmissionFacts in
  match plan_share_admission facts <: t_ShareAdmissionDecision with
  | ShareAdmissionDecision_AcceptFirstContact _ -> true
  | _ -> false

let initial_acceptance_is_authorized (accepted has_pin has_payload: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. ((~.accepted <: bool) && (~.has_pin <: bool) && has_payload)) =
  ~.accepted && ~.has_pin && has_payload

let store_generation_matches_spec
      (current snapshot: u64)
      (pending: bool)
      (result: Core_models.Option.t_Option u64)
    : bool =
  match result <: Core_models.Option.t_Option u64 with
  | Core_models.Option.Option_Some next ->
    current =. snapshot && ~.pending && current <. Core_models.Num.impl_u64__MAX &&
    next =. (current +! mk_u64 1 <: u64) &&
    next >. current
  | Core_models.Option.Option_None  ->
    current <>. snapshot || pending || current =. Core_models.Num.impl_u64__MAX

let next_store_generation (current snapshot: u64) (pending: bool)
    : Prims.Pure (Core_models.Option.t_Option u64)
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option u64 = result in
          store_generation_matches_spec current snapshot pending result) =
  if current <>. snapshot || pending || current =. Core_models.Num.impl_u64__MAX
  then Core_models.Option.Option_None <: Core_models.Option.t_Option u64
  else Core_models.Option.Option_Some (current +! mk_u64 1) <: Core_models.Option.t_Option u64

let stale_snapshot_can_commit (current snapshot: u64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  if current =. snapshot
  then false
  else
    match next_store_generation current snapshot false <: Core_models.Option.t_Option u64 with
    | Core_models.Option.Option_Some _ -> true
    | Core_models.Option.Option_None  -> false

let pending_commit_can_be_overwritten (current snapshot: u64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  match next_store_generation current snapshot true <: Core_models.Option.t_Option u64 with
  | Core_models.Option.Option_Some _ -> true
  | Core_models.Option.Option_None  -> false

let exhausted_generation_can_commit (_: Prims.unit)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  match
    next_store_generation Core_models.Num.impl_u64__MAX Core_models.Num.impl_u64__MAX false
    <:
    Core_models.Option.t_Option u64
  with
  | Core_models.Option.Option_Some _ -> true
  | Core_models.Option.Option_None  -> false

let recovery_should_apply (matches_before current_present tombstoned: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. (matches_before && (current_present || (~.tombstoned <: bool)))) =
  matches_before && (current_present || ~.tombstoned)

let local_edit_can_be_overwritten (current_present tombstoned: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) = recovery_should_apply false current_present tombstoned

let deleted_item_can_be_restored (matches_before: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) = recovery_should_apply matches_before false true

let existing_pin_can_restart_acceptance (accepted has_payload: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) = initial_acceptance_is_authorized accepted true has_payload

let missing_payload_can_be_accepted (accepted has_pin: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) = initial_acceptance_is_authorized accepted has_pin false
