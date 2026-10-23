module Vela_client_recovery_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

let v_INITIAL_EPOCH: i64 = mk_i64 1

/// Durable observations for publishing one freshly generated recovery split.
/// The journal containing these facts must be committed before any external
/// write.  The four progress bits are committed only after their corresponding
/// idempotent operation succeeds.  If a process dies between those two events,
/// the planner simply returns the same operation after restart.
type t_PublicationFacts = {
  f_journal_present:bool;
  f_account_matches:bool;
  f_split_id_present:bool;
  f_cloud_share_present:bool;
  f_server_share_present:bool;
  f_journal_epoch:i64;
  f_current_epoch:i64;
  f_account_epoch_active:bool;
  f_server_staged:bool;
  f_cloud_candidate_durable:bool;
  f_server_finalized:bool;
  f_cloud_active:bool
}

type t_PublicationAction =
  | PublicationAction_StageServer : t_PublicationAction
  | PublicationAction_UploadCloudCandidate : t_PublicationAction
  | PublicationAction_FinalizeServer : t_PublicationAction
  | PublicationAction_PromoteCloudActive : t_PublicationAction
  | PublicationAction_Complete : t_PublicationAction
  | PublicationAction_Retire : t_PublicationAction
  | PublicationAction_Reject : t_PublicationAction

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_13': Core_models.Cmp.t_PartialEq t_PublicationAction t_PublicationAction

unfold
let impl_13 = impl_13'

let publication_state_is_well_formed (facts: t_PublicationFacts) : bool =
  (~.facts.f_server_finalized || facts.f_server_staged && facts.f_cloud_candidate_durable) &&
  (~.facts.f_cloud_active || facts.f_server_finalized)

let publication_journal_is_bound (facts: t_PublicationFacts) : bool =
  facts.f_journal_present && facts.f_account_matches && facts.f_split_id_present &&
  facts.f_cloud_share_present &&
  facts.f_server_share_present &&
  facts.f_journal_epoch >=. v_INITIAL_EPOCH &&
  publication_state_is_well_formed facts

let publication_is_current (facts: t_PublicationFacts) : bool =
  publication_journal_is_bound facts && facts.f_current_epoch >=. v_INITIAL_EPOCH &&
  facts.f_journal_epoch =. facts.f_current_epoch &&
  facts.f_account_epoch_active

let publication_plan_matches_spec (facts: t_PublicationFacts) (action: t_PublicationAction) : bool =
  if ~.(publication_journal_is_bound facts <: bool)
  then action =. (PublicationAction_Reject <: t_PublicationAction)
  else
    if
      facts.f_current_epoch <. v_INITIAL_EPOCH || facts.f_journal_epoch <>. facts.f_current_epoch ||
      ~.facts.f_account_epoch_active
    then action =. (PublicationAction_Retire <: t_PublicationAction)
    else
      if facts.f_cloud_active
      then action =. (PublicationAction_Complete <: t_PublicationAction)
      else
        if facts.f_server_finalized
        then action =. (PublicationAction_PromoteCloudActive <: t_PublicationAction)
        else
          if ~.facts.f_server_staged
          then action =. (PublicationAction_StageServer <: t_PublicationAction)
          else
            if ~.facts.f_cloud_candidate_durable
            then action =. (PublicationAction_UploadCloudCandidate <: t_PublicationAction)
            else action =. (PublicationAction_FinalizeServer <: t_PublicationAction)

/// Return the single operation that should be retried for this journal.
let plan_publication_resume (facts: t_PublicationFacts)
    : Prims.Pure t_PublicationAction
      Prims.l_True
      (ensures
        fun action ->
          let action:t_PublicationAction = action in
          publication_plan_matches_spec facts action) =
  if ~.(publication_journal_is_bound facts <: bool)
  then PublicationAction_Reject <: t_PublicationAction
  else
    if
      facts.f_current_epoch <. v_INITIAL_EPOCH || facts.f_journal_epoch <>. facts.f_current_epoch ||
      ~.facts.f_account_epoch_active
    then PublicationAction_Retire <: t_PublicationAction
    else
      if facts.f_cloud_active
      then PublicationAction_Complete <: t_PublicationAction
      else
        if facts.f_server_finalized
        then PublicationAction_PromoteCloudActive <: t_PublicationAction
        else
          if ~.facts.f_server_staged
          then PublicationAction_StageServer <: t_PublicationAction
          else
            if ~.facts.f_cloud_candidate_durable
            then PublicationAction_UploadCloudCandidate <: t_PublicationAction
            else PublicationAction_FinalizeServer <: t_PublicationAction

/// Authorize an operation selected by a UI.  Staging and candidate upload are
/// intentionally independent, so desktop users may complete those ceremonies
/// in either order.  Finalization and promotion remain strictly ordered.
let publication_action_is_authorized (facts: t_PublicationFacts) (action: t_PublicationAction)
    : bool =
  if ~.(publication_is_current facts <: bool)
  then false
  else
    match action <: t_PublicationAction with
    | PublicationAction_StageServer  -> ~.facts.f_server_finalized && ~.facts.f_cloud_active
    | PublicationAction_UploadCloudCandidate  ->
      ~.facts.f_server_finalized && ~.facts.f_cloud_active
    | PublicationAction_FinalizeServer  ->
      facts.f_server_staged && facts.f_cloud_candidate_durable && ~.facts.f_cloud_active
    | PublicationAction_PromoteCloudActive  -> facts.f_server_finalized
    | PublicationAction_Complete  -> facts.f_cloud_active
    | PublicationAction_Retire  | PublicationAction_Reject  -> false

/// A setup may be discarded only while both externally published copies are
/// still candidates.  Once the server winner is final, restart must finish the
/// active cloud pointer instead of abandoning a half-published recovery set.
let publication_abort_is_authorized (facts: t_PublicationFacts) : bool =
  publication_is_current facts && ~.facts.f_server_finalized && ~.facts.f_cloud_active

let rotated_journal_can_write_external (facts: t_PublicationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PublicationFacts =
    {
      facts with
      f_current_epoch
      =
      if facts.f_journal_epoch =. Core_models.Num.impl_i64__MAX
      then facts.f_journal_epoch -! mk_i64 1
      else facts.f_journal_epoch +! mk_i64 1
    }
    <:
    t_PublicationFacts
  in
  publication_action_is_authorized facts (PublicationAction_StageServer <: t_PublicationAction) ||
  publication_action_is_authorized facts
    (PublicationAction_UploadCloudCandidate <: t_PublicationAction) ||
  publication_action_is_authorized facts (PublicationAction_FinalizeServer <: t_PublicationAction) ||
  publication_action_is_authorized facts
    (PublicationAction_PromoteCloudActive <: t_PublicationAction)

let finalized_publication_can_abort (facts: t_PublicationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PublicationFacts = { facts with f_server_staged = true } <: t_PublicationFacts in
  let facts:t_PublicationFacts =
    { facts with f_cloud_candidate_durable = true } <: t_PublicationFacts
  in
  let facts:t_PublicationFacts = { facts with f_server_finalized = true } <: t_PublicationFacts in
  publication_abort_is_authorized facts

let malformed_journal_can_complete (facts: t_PublicationFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PublicationFacts = { facts with f_split_id_present = false } <: t_PublicationFacts in
  publication_action_is_authorized facts (PublicationAction_Complete <: t_PublicationAction)

/// The three custodian channels of the 2-of-3 split (SPEC.md §4.3).
type t_RecoveryChannel =
  | RecoveryChannel_Cloud : t_RecoveryChannel
  | RecoveryChannel_Server : t_RecoveryChannel
  | RecoveryChannel_TrustedContact : t_RecoveryChannel

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_19': Core_models.Cmp.t_PartialEq t_RecoveryChannel t_RecoveryChannel

unfold
let impl_19 = impl_19'

/// Durable observations about one candidate share of a recovery pair.
/// Every share must be bound to the same account, epoch, and Shamir split as
/// its partner. `recipient_bound` may only be claimed for a share that was
/// opened out of an authenticated envelope addressed to this exact recipient —
/// raw key material copied by hand can never carry it.
type t_BoundShareFacts = {
  f_account_matches:bool;
  f_channel:t_RecoveryChannel;
  f_epoch:i64;
  f_split_id_present:bool;
  f_share_authenticated:bool;
  f_recipient_bound:bool;
  f_coordinate:u8
}

type t_PairSelectionFacts = {
  f_requested_account_present:bool;
  f_split_ids_match:bool;
  f_first:t_BoundShareFacts;
  f_second:t_BoundShareFacts
}

type t_ReconstructionPermit = {
  f_epoch:i64;
  f_exact_account_and_epoch:bool
}

type t_ReconstructionDecision =
  | ReconstructionDecision_Reconstruct : t_ReconstructionPermit -> t_ReconstructionDecision
  | ReconstructionDecision_Reject : t_ReconstructionDecision

/// M18 pair-selection policy: any two *distinct* channels of the same exact
/// account/epoch/split context reconstruct, provided both shares are
/// authenticated, address distinct Shamir coordinates, and trusted-contact
/// shares arrived through a recipient-bound authenticated envelope.
let reconstruction_is_authorized (facts: t_PairSelectionFacts) : bool =
  let (first: t_BoundShareFacts), (second: t_BoundShareFacts) =
    facts.f_first, facts.f_second <: (t_BoundShareFacts & t_BoundShareFacts)
  in
  facts.f_requested_account_present && first.f_account_matches && second.f_account_matches &&
  first.f_channel <>. second.f_channel &&
  first.f_epoch >=. v_INITIAL_EPOCH &&
  first.f_epoch =. second.f_epoch &&
  (~.first.f_split_id_present && ~.second.f_split_id_present ||
  first.f_split_id_present && second.f_split_id_present && facts.f_split_ids_match) &&
  first.f_share_authenticated &&
  second.f_share_authenticated &&
  (first.f_channel <>. (RecoveryChannel_TrustedContact <: t_RecoveryChannel) ||
  first.f_recipient_bound) &&
  (second.f_channel <>. (RecoveryChannel_TrustedContact <: t_RecoveryChannel) ||
  second.f_recipient_bound) &&
  first.f_coordinate <>. second.f_coordinate

let reconstruction_decision_matches_spec
      (facts: t_PairSelectionFacts)
      (decision: t_ReconstructionDecision)
    : bool =
  match decision <: t_ReconstructionDecision with
  | ReconstructionDecision_Reconstruct permit ->
    reconstruction_is_authorized facts && permit.f_epoch =. facts.f_first.f_epoch &&
    permit.f_exact_account_and_epoch
  | ReconstructionDecision_Reject  -> ~.(reconstruction_is_authorized facts <: bool)

let plan_reconstruction (facts: t_PairSelectionFacts)
    : Prims.Pure t_ReconstructionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ReconstructionDecision = decision in
          reconstruction_decision_matches_spec facts decision) =
  if reconstruction_is_authorized facts
  then
    ReconstructionDecision_Reconstruct
    ({ f_epoch = facts.f_first.f_epoch; f_exact_account_and_epoch = true } <: t_ReconstructionPermit
    )
    <:
    t_ReconstructionDecision
  else ReconstructionDecision_Reject <: t_ReconstructionDecision

type t_AdoptionFacts = {
  f_shares_authenticated_together:bool;
  f_reconstructed_rms_is_32_bytes:bool;
  f_target_epoch:i64
}

type t_AdoptionPermit = { f_epoch:i64 }

type t_AdoptionDecision =
  | AdoptionDecision_Adopt : t_AdoptionPermit -> t_AdoptionDecision
  | AdoptionDecision_Reject : t_AdoptionDecision

let adoption_is_authorized (reconstruction: t_ReconstructionPermit) (facts: t_AdoptionFacts) : bool =
  reconstruction.f_exact_account_and_epoch && reconstruction.f_epoch >=. v_INITIAL_EPOCH &&
  facts.f_shares_authenticated_together &&
  facts.f_reconstructed_rms_is_32_bytes &&
  facts.f_target_epoch =. reconstruction.f_epoch

let adoption_decision_matches_spec
      (reconstruction: t_ReconstructionPermit)
      (facts: t_AdoptionFacts)
      (decision: t_AdoptionDecision)
    : bool =
  match decision <: t_AdoptionDecision with
  | AdoptionDecision_Adopt permit ->
    adoption_is_authorized reconstruction facts && permit.f_epoch =. reconstruction.f_epoch
  | AdoptionDecision_Reject  -> ~.(adoption_is_authorized reconstruction facts <: bool)

let plan_adoption (reconstruction: t_ReconstructionPermit) (facts: t_AdoptionFacts)
    : Prims.Pure t_AdoptionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_AdoptionDecision = decision in
          adoption_decision_matches_spec reconstruction facts decision) =
  if adoption_is_authorized reconstruction facts
  then
    AdoptionDecision_Adopt ({ f_epoch = reconstruction.f_epoch } <: t_AdoptionPermit)
    <:
    t_AdoptionDecision
  else AdoptionDecision_Reject <: t_AdoptionDecision

let cross_account_shares_can_reconstruct (facts: t_PairSelectionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PairSelectionFacts =
    { facts with f_first = { facts.f_first with f_account_matches = false } <: t_BoundShareFacts }
    <:
    t_PairSelectionFacts
  in
  reconstruction_is_authorized facts

let mixed_epoch_shares_can_reconstruct (facts: t_PairSelectionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PairSelectionFacts =
    {
      facts with
      f_second
      =
      {
        facts.f_second with
        f_epoch
        =
        if facts.f_first.f_epoch =. Core_models.Num.impl_i64__MAX
        then facts.f_first.f_epoch -! mk_i64 1
        else facts.f_first.f_epoch +! mk_i64 1
      }
      <:
      t_BoundShareFacts
    }
    <:
    t_PairSelectionFacts
  in
  reconstruction_is_authorized facts

let untagged_shares_can_reconstruct (facts: t_PairSelectionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PairSelectionFacts =
    {
      facts with
      f_first = { facts.f_first with f_share_authenticated = false } <: t_BoundShareFacts
    }
    <:
    t_PairSelectionFacts
  in
  reconstruction_is_authorized facts

let mismatched_split_ids_can_reconstruct (facts: t_PairSelectionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PairSelectionFacts =
    { facts with f_first = { facts.f_first with f_split_id_present = true } <: t_BoundShareFacts }
    <:
    t_PairSelectionFacts
  in
  let facts:t_PairSelectionFacts =
    { facts with f_second = { facts.f_second with f_split_id_present = true } <: t_BoundShareFacts }
    <:
    t_PairSelectionFacts
  in
  let facts:t_PairSelectionFacts =
    { facts with f_split_ids_match = false } <: t_PairSelectionFacts
  in
  reconstruction_is_authorized facts

/// Two shares from the *same* channel are one custodian speaking twice — even
/// at distinct coordinates they must never count as a 2-of-3 quorum.
let same_channel_shares_can_reconstruct (facts: t_PairSelectionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PairSelectionFacts =
    {
      facts with
      f_second = { facts.f_second with f_channel = facts.f_first.f_channel } <: t_BoundShareFacts
    }
    <:
    t_PairSelectionFacts
  in
  reconstruction_is_authorized facts

let duplicate_coordinates_can_reconstruct (facts: t_PairSelectionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PairSelectionFacts =
    {
      facts with
      f_second
      =
      { facts.f_second with f_coordinate = facts.f_first.f_coordinate } <: t_BoundShareFacts
    }
    <:
    t_PairSelectionFacts
  in
  reconstruction_is_authorized facts

/// A trusted-contact share that did not arrive through an authenticated
/// envelope addressed to this exact recipient is raw copied material and must
/// never reconstruct.
let unbound_contact_share_can_reconstruct (facts: t_PairSelectionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_PairSelectionFacts =
    {
      facts with
      f_second
      =
      { facts.f_second with f_channel = RecoveryChannel_TrustedContact <: t_RecoveryChannel }
      <:
      t_BoundShareFacts
    }
    <:
    t_PairSelectionFacts
  in
  let facts:t_PairSelectionFacts =
    { facts with f_second = { facts.f_second with f_recipient_bound = false } <: t_BoundShareFacts }
    <:
    t_PairSelectionFacts
  in
  reconstruction_is_authorized facts

/// Durable observations for handing Share 3 to its trusted contact.
type t_ContactDeliveryFacts = {
  f_journal_bound:bool;
  f_journal_is_current:bool;
  f_split_id_present:bool;
  f_share_present:bool;
  f_recipient_key_present:bool
}

type t_ContactDeliveryAction =
  | ContactDeliveryAction_Seal : t_ContactDeliveryAction
  | ContactDeliveryAction_Retire : t_ContactDeliveryAction
  | ContactDeliveryAction_Reject : t_ContactDeliveryAction

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_73': Core_models.Cmp.t_PartialEq t_ContactDeliveryAction t_ContactDeliveryAction

unfold
let impl_73 = impl_73'

let contact_delivery_plan_matches_spec
      (facts: t_ContactDeliveryFacts)
      (action: t_ContactDeliveryAction)
    : bool =
  if ~.facts.f_journal_bound
  then action =. (ContactDeliveryAction_Reject <: t_ContactDeliveryAction)
  else
    if ~.facts.f_journal_is_current || ~.facts.f_share_present
    then action =. (ContactDeliveryAction_Retire <: t_ContactDeliveryAction)
    else
      if facts.f_split_id_present && facts.f_recipient_key_present
      then action =. (ContactDeliveryAction_Seal <: t_ContactDeliveryAction)
      else action =. (ContactDeliveryAction_Reject <: t_ContactDeliveryAction)

/// Decide what may happen to the cached trusted-contact share: seal it into
/// an authenticated envelope for the recorded recipient, retire it because
/// its epoch no longer matches (RMS rotation), or reject a malformed journal.
let plan_contact_delivery (facts: t_ContactDeliveryFacts)
    : Prims.Pure t_ContactDeliveryAction
      Prims.l_True
      (ensures
        fun action ->
          let action:t_ContactDeliveryAction = action in
          contact_delivery_plan_matches_spec facts action) =
  if ~.facts.f_journal_bound
  then ContactDeliveryAction_Reject <: t_ContactDeliveryAction
  else
    if ~.facts.f_journal_is_current || ~.facts.f_share_present
    then ContactDeliveryAction_Retire <: t_ContactDeliveryAction
    else
      if facts.f_split_id_present && facts.f_recipient_key_present
      then ContactDeliveryAction_Seal <: t_ContactDeliveryAction
      else ContactDeliveryAction_Reject <: t_ContactDeliveryAction

let rotated_contact_journal_can_seal (facts: t_ContactDeliveryFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ContactDeliveryFacts =
    { facts with f_journal_is_current = false } <: t_ContactDeliveryFacts
  in
  contact_delivery_plan_matches_spec facts (ContactDeliveryAction_Seal <: t_ContactDeliveryAction)

let keyless_contact_delivery_can_seal (facts: t_ContactDeliveryFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ContactDeliveryFacts =
    { facts with f_recipient_key_present = false } <: t_ContactDeliveryFacts
  in
  contact_delivery_plan_matches_spec facts (ContactDeliveryAction_Seal <: t_ContactDeliveryAction)

let unauthenticated_secret_can_be_adopted
      (reconstruction: t_ReconstructionPermit)
      (facts: t_AdoptionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_AdoptionFacts =
    { facts with f_shares_authenticated_together = false } <: t_AdoptionFacts
  in
  adoption_is_authorized reconstruction facts

let wrong_epoch_secret_can_be_adopted
      (reconstruction: t_ReconstructionPermit)
      (facts: t_AdoptionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_AdoptionFacts =
    {
      facts with
      f_target_epoch
      =
      if reconstruction.f_epoch =. Core_models.Num.impl_i64__MAX
      then reconstruction.f_epoch -! mk_i64 1
      else reconstruction.f_epoch +! mk_i64 1
    }
    <:
    t_AdoptionFacts
  in
  adoption_is_authorized reconstruction facts
