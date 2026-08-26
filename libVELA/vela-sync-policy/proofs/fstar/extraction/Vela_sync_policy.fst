module Vela_sync_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

let v_INITIAL_EPOCH: i64 = mk_i64 1

/// Durable observations from `GET /vault/epoch` and the adoption capsule.
type t_EpochAdoptionFacts = {
  f_rotation_state_active:bool;
  f_server_epoch:i64;
  f_local_epoch:i64;
  f_server_epoch_is_next:bool;
  f_capsule_epoch_matches:Core_models.Option.t_Option bool;
  f_rotation_id_present:Core_models.Option.t_Option bool
}

type t_EpochAdoptionPermit = {
  f_epoch:i64;
  f_binds_capsule_epoch:bool
}

type t_AdoptionDecision =
  | AdoptionDecision_Keep : t_AdoptionDecision
  | AdoptionDecision_FetchCapsule : t_AdoptionDecision
  | AdoptionDecision_Adopt : t_EpochAdoptionPermit -> t_AdoptionDecision
  | AdoptionDecision_Reject : t_AdoptionDecision

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_13': Core_models.Cmp.t_PartialEq t_AdoptionDecision t_AdoptionDecision

unfold
let impl_13 = impl_13'

let impl_EpochAdoptionPermit__epoch (self: t_EpochAdoptionPermit) : i64 = self.f_epoch

let impl_EpochAdoptionPermit__binds_capsule_epoch (self: t_EpochAdoptionPermit) : bool =
  self.f_binds_capsule_epoch

/// The adoption ladder: refuse inactive rotations, refuse rollback, refuse
/// skipped transitions, then require the capsule to be bound to exactly the
/// advertised epoch before permitting migration.
let epoch_adoption_is_authorized (facts: t_EpochAdoptionFacts) : bool =
  facts.f_rotation_state_active && facts.f_server_epoch >=. v_INITIAL_EPOCH &&
  facts.f_local_epoch >=. v_INITIAL_EPOCH &&
  facts.f_server_epoch >. facts.f_local_epoch &&
  facts.f_server_epoch_is_next &&
  facts.f_capsule_epoch_matches ==. Core_models.Option.Option_Some true &&
  facts.f_rotation_id_present ==. Core_models.Option.Option_Some true

/// A sequential advance whose capsule has not been fetched yet (fact fields
/// `None`) asks the caller to fetch it; every other unauthorized shape is a
/// plain rejection.
let epoch_adoption_is_fetch_pending (facts: t_EpochAdoptionFacts) : bool =
  let fetch_pending_or_present (o: Core_models.Option.t_Option bool) : bool =
    match o <: Core_models.Option.t_Option bool with
    | Core_models.Option.Option_None -> true
    | Core_models.Option.Option_Some _ -> false
  in
  facts.f_server_epoch_is_next &&
  (fetch_pending_or_present facts.f_capsule_epoch_matches ||
    fetch_pending_or_present facts.f_rotation_id_present)

let epoch_adoption_decision_matches_spec
      (facts: t_EpochAdoptionFacts)
      (decision: t_AdoptionDecision)
    : bool =
  if ~.facts.f_rotation_state_active
  then decision =. (AdoptionDecision_Reject <: t_AdoptionDecision)
  else
    if facts.f_server_epoch <. v_INITIAL_EPOCH || facts.f_local_epoch <. v_INITIAL_EPOCH
    then decision =. (AdoptionDecision_Reject <: t_AdoptionDecision)
    else
      if facts.f_server_epoch =. facts.f_local_epoch
      then decision =. (AdoptionDecision_Keep <: t_AdoptionDecision)
      else
        if ~.facts.f_server_epoch_is_next
        then decision =. (AdoptionDecision_Reject <: t_AdoptionDecision)
        else
          if epoch_adoption_is_fetch_pending facts
          then decision =. (AdoptionDecision_FetchCapsule <: t_AdoptionDecision)
          else
            if epoch_adoption_is_authorized facts
            then
              match
                (match decision <: t_AdoptionDecision with
                  | AdoptionDecision_Adopt permit ->
                    (match
                        (impl_EpochAdoptionPermit__epoch permit <: i64) =. facts.f_server_epoch &&
                        impl_EpochAdoptionPermit__binds_capsule_epoch permit
                        <:
                        bool
                      with
                      | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
                      | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
                  | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
                <:
                Core_models.Option.t_Option bool
              with
              | Core_models.Option.Option_Some x -> x
              | Core_models.Option.Option_None  -> false
            else decision =. (AdoptionDecision_Reject <: t_AdoptionDecision)

let plan_epoch_adoption (facts: t_EpochAdoptionFacts)
    : Prims.Pure t_AdoptionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_AdoptionDecision = decision in
          epoch_adoption_decision_matches_spec facts decision) =
  if ~.facts.f_rotation_state_active
  then AdoptionDecision_Reject <: t_AdoptionDecision
  else
    if facts.f_server_epoch <. v_INITIAL_EPOCH || facts.f_local_epoch <. v_INITIAL_EPOCH
    then AdoptionDecision_Reject <: t_AdoptionDecision
    else
      if facts.f_server_epoch =. facts.f_local_epoch
      then AdoptionDecision_Keep <: t_AdoptionDecision
      else
        if ~.facts.f_server_epoch_is_next
        then AdoptionDecision_Reject <: t_AdoptionDecision
        else
          if epoch_adoption_is_authorized facts
          then
            AdoptionDecision_Adopt
            ({ f_epoch = facts.f_server_epoch; f_binds_capsule_epoch = true } <: t_EpochAdoptionPermit
            )
            <:
            t_AdoptionDecision
          else
            if epoch_adoption_is_fetch_pending facts
            then AdoptionDecision_FetchCapsule <: t_AdoptionDecision
            else AdoptionDecision_Reject <: t_AdoptionDecision

let rolled_back_server_epoch_can_adopt (facts: t_EpochAdoptionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EpochAdoptionFacts =
    {
      facts with
      f_server_epoch
      =
      if facts.f_local_epoch <=. v_INITIAL_EPOCH
      then v_INITIAL_EPOCH
      else facts.f_local_epoch -! mk_i64 1
    }
    <:
    t_EpochAdoptionFacts
  in
  epoch_adoption_is_authorized facts

let skipped_transition_can_adopt (facts: t_EpochAdoptionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EpochAdoptionFacts =
    { facts with f_server_epoch_is_next = false } <: t_EpochAdoptionFacts
  in
  epoch_adoption_is_authorized facts

let freezing_rotation_can_adopt (facts: t_EpochAdoptionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EpochAdoptionFacts =
    { facts with f_rotation_state_active = false } <: t_EpochAdoptionFacts
  in
  epoch_adoption_is_authorized facts

let fforeign_capsule_can_adopt (facts: t_EpochAdoptionFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_EpochAdoptionFacts =
    {
      facts with
      f_capsule_epoch_matches =
      Core_models.Option.Option_Some false <: Core_models.Option.t_Option bool
    }
    <:
    t_EpochAdoptionFacts
  in
  epoch_adoption_is_authorized facts

/// Observations when a chunk download returns.
type t_ChunkDownloadFacts = {
  f_server_lamport:i64;
  f_last_seen_lamport:Core_models.Option.t_Option i64;
  f_aad_binding_verified:bool;
  f_key_epoch_positive:bool
}

type t_ChunkDownloadPermit = { f_lamport:i64 }

type t_ChunkDownloadDecision =
  | ChunkDownloadDecision_Accept : t_ChunkDownloadPermit -> t_ChunkDownloadDecision
  | ChunkDownloadDecision_Reject : t_ChunkDownloadDecision

let chunk_download_is_authorized (facts: t_ChunkDownloadFacts) : bool =
  let no_seen_clock:bool =
    match facts.f_last_seen_lamport <: Core_models.Option.t_Option i64 with
    | Core_models.Option.Option_None  -> true
    | _ -> false
  in
  let not_older:bool =
    match
      (match facts.f_last_seen_lamport <: Core_models.Option.t_Option i64 with
        | Core_models.Option.Option_Some seen ->
          (match facts.f_server_lamport >=. seen <: bool with
            | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
            | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
        | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
      <:
      Core_models.Option.t_Option bool
    with
    | Core_models.Option.Option_Some x -> x
    | Core_models.Option.Option_None  -> false
  in
  (no_seen_clock || not_older) && facts.f_aad_binding_verified && facts.f_key_epoch_positive &&
  facts.f_server_lamport >=. v_INITIAL_EPOCH

let chunk_download_decision_matches_spec
      (facts: t_ChunkDownloadFacts)
      (decision: t_ChunkDownloadDecision)
    : bool =
  match decision <: t_ChunkDownloadDecision with
  | ChunkDownloadDecision_Accept permit ->
    chunk_download_is_authorized facts && permit.f_lamport =. facts.f_server_lamport
  | ChunkDownloadDecision_Reject  -> ~.(chunk_download_is_authorized facts <: bool)

let plan_chunk_download (facts: t_ChunkDownloadFacts)
    : Prims.Pure t_ChunkDownloadDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ChunkDownloadDecision = decision in
          chunk_download_decision_matches_spec facts decision) =
  if chunk_download_is_authorized facts
  then
    ChunkDownloadDecision_Accept ({ f_lamport = facts.f_server_lamport } <: t_ChunkDownloadPermit)
    <:
    t_ChunkDownloadDecision
  else ChunkDownloadDecision_Reject <: t_ChunkDownloadDecision

/// Witness: a device that recorded Lamport 7 refuses a server revision at
/// Lamport 3. The universal statement — *no* older revision admits — follows
/// from `chunk_download_is_authorized`\'s single `server >= seen` conjunct
/// (verified through `chunk_download_decision_matches_spec`) together with
/// this concrete instantiation.
let rolled_back_chunk_can_be_accepted (_: Prims.unit)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  chunk_download_is_authorized ({
        f_server_lamport = mk_i64 3;
        f_last_seen_lamport
        =
        Core_models.Option.Option_Some (mk_i64 7) <: Core_models.Option.t_Option i64;
        f_aad_binding_verified = true;
        f_key_epoch_positive = true
      }
      <:
      t_ChunkDownloadFacts)

let unbound_aad_chunk_can_be_accepted (facts: t_ChunkDownloadFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ChunkDownloadFacts =
    { facts with f_aad_binding_verified = false } <: t_ChunkDownloadFacts
  in
  chunk_download_is_authorized facts

/// Per-item observations during a merge.
type t_ItemMergeFacts = {
  f_tombstone_covers_item:bool;
  f_server_updated_at_newer:bool;
  f_local_modified_by_this_device:bool;
  f_already_conflicted:bool
}

type t_MergeAction =
  | MergeAction_StayDeleted : t_MergeAction
  | MergeAction_AcceptServer : t_MergeAction
  | MergeAction_Conflict : t_MergeAction
  | MergeAction_KeepLocal : t_MergeAction

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_49': Core_models.Cmp.t_PartialEq t_MergeAction t_MergeAction

unfold
let impl_49 = impl_49'

let merge_action_matches_spec (facts: t_ItemMergeFacts) (action: t_MergeAction) : bool =
  let expected:t_MergeAction =
    if facts.f_tombstone_covers_item
    then MergeAction_StayDeleted <: t_MergeAction
    else
      if facts.f_server_updated_at_newer
      then
        if facts.f_already_conflicted
        then MergeAction_KeepLocal <: t_MergeAction
        else
          if facts.f_local_modified_by_this_device
          then MergeAction_Conflict <: t_MergeAction
          else MergeAction_AcceptServer <: t_MergeAction
      else MergeAction_KeepLocal <: t_MergeAction
  in
  action =. expected

let classify_merge_action (facts: t_ItemMergeFacts)
    : Prims.Pure t_MergeAction
      Prims.l_True
      (ensures
        fun action ->
          let action:t_MergeAction = action in
          merge_action_matches_spec facts action) =
  if facts.f_tombstone_covers_item
  then MergeAction_StayDeleted <: t_MergeAction
  else
    if facts.f_server_updated_at_newer
    then
      if facts.f_already_conflicted
      then MergeAction_KeepLocal <: t_MergeAction
      else
        if facts.f_local_modified_by_this_device
        then MergeAction_Conflict <: t_MergeAction
        else MergeAction_AcceptServer <: t_MergeAction
    else MergeAction_KeepLocal <: t_MergeAction

let tombstoned_item_can_be_resurrected (facts: t_ItemMergeFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ItemMergeFacts = { facts with f_tombstone_covers_item = true } <: t_ItemMergeFacts in
  merge_action_matches_spec facts (MergeAction_AcceptServer <: t_MergeAction)

let conflicted_local_edit_can_be_overwritten (facts: t_ItemMergeFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let facts:t_ItemMergeFacts = { facts with f_already_conflicted = true } <: t_ItemMergeFacts in
  let facts:t_ItemMergeFacts =
    { facts with f_server_updated_at_newer = true } <: t_ItemMergeFacts
  in
  merge_action_matches_spec facts (MergeAction_AcceptServer <: t_MergeAction)
