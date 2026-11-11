module Vela_rekey_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

/// Epoch zero is reserved; every persisted account begins at epoch one.
let v_INITIAL_EPOCH: i64 = mk_i64 1

type t_Phase =
  | Phase_Active : t_Phase
  | Phase_Freezing : t_Phase

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core_models.Cmp.t_PartialEq t_Phase t_Phase

unfold
let impl_7 = impl_7'

type t_RekeyState = {
  f_epoch:i64;
  f_phase:t_Phase
}

let impl_RekeyState__is_valid (self: t_RekeyState) : bool = self.f_epoch >=. v_INITIAL_EPOCH

type t_EpochRoute = {
  f_write_epoch:i64;
  f_read_epoch:i64
}

type t_WriteDecision =
  | WriteDecision_Accept : t_EpochRoute -> t_WriteDecision
  | WriteDecision_Reject : t_WriteDecision

/// Return the exact successor without ever overflowing at the integer bound.
let next_epoch (epoch: i64)
    : Prims.Pure (Core_models.Option.t_Option i64)
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option i64 = result in
          match result <: Core_models.Option.t_Option i64 with
          | Core_models.Option.Option_Some next ->
            epoch <. Core_models.Num.impl_i64__MAX && next =. (epoch +! mk_i64 1 <: i64)
          | Core_models.Option.Option_None  -> epoch =. Core_models.Num.impl_i64__MAX) =
  if epoch =. Core_models.Num.impl_i64__MAX
  then Core_models.Option.Option_None <: Core_models.Option.t_Option i64
  else Core_models.Option.Option_Some (epoch +! mk_i64 1) <: Core_models.Option.t_Option i64

/// The complete acceptance predicate for an ordinary or shadow write.
let write_is_accepted (state: t_RekeyState) (declared: Core_models.Option.t_Option i64) : bool =
  if ~.(impl_RekeyState__is_valid state <: bool)
  then false
  else
    match state.f_phase <: t_Phase with
    | Phase_Active  ->
      declared =. (Core_models.Option.Option_Some state.f_epoch <: Core_models.Option.t_Option i64) ||
      state.f_epoch =. v_INITIAL_EPOCH && Core_models.Option.impl__is_none #i64 declared
    | Phase_Freezing  ->
      match next_epoch state.f_epoch <: Core_models.Option.t_Option i64 with
      | Core_models.Option.Option_Some next ->
        declared =. (Core_models.Option.Option_Some next <: Core_models.Option.t_Option i64)
      | Core_models.Option.Option_None  -> false

/// State the full functional specification of [`resolve_write_epoch`].
let write_decision_matches_spec
      (state: t_RekeyState)
      (declared: Core_models.Option.t_Option i64)
      (decision: t_WriteDecision)
    : bool =
  match decision <: t_WriteDecision with
  | WriteDecision_Accept route ->
    write_is_accepted state declared && route.f_read_epoch =. state.f_epoch &&
    (match state.f_phase <: t_Phase with
      | Phase_Active  -> route.f_write_epoch =. state.f_epoch
      | Phase_Freezing  ->
        (next_epoch state.f_epoch <: Core_models.Option.t_Option i64) =.
        (Core_models.Option.Option_Some route.f_write_epoch <: Core_models.Option.t_Option i64))
  | WriteDecision_Reject  -> ~.(write_is_accepted state declared <: bool)

/// Decide which epoch a ciphertext may be written to and which epoch remains
/// readable. This is the pure implementation used by the server write paths.
let resolve_write_epoch (state: t_RekeyState) (declared: Core_models.Option.t_Option i64)
    : Prims.Pure t_WriteDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_WriteDecision = decision in
          write_decision_matches_spec state declared decision) =
  if ~.(impl_RekeyState__is_valid state <: bool)
  then WriteDecision_Reject <: t_WriteDecision
  else
    match state.f_phase <: t_Phase with
    | Phase_Active  ->
      if
        declared =.
        (Core_models.Option.Option_Some state.f_epoch <: Core_models.Option.t_Option i64) ||
        state.f_epoch =. v_INITIAL_EPOCH && Core_models.Option.impl__is_none #i64 declared
      then
        WriteDecision_Accept
        ({ f_write_epoch = state.f_epoch; f_read_epoch = state.f_epoch } <: t_EpochRoute)
        <:
        t_WriteDecision
      else WriteDecision_Reject <: t_WriteDecision
    | Phase_Freezing  ->
      match
        (match next_epoch state.f_epoch <: Core_models.Option.t_Option i64 with
          | Core_models.Option.Option_Some next ->
            (match
                declared =. (Core_models.Option.Option_Some next <: Core_models.Option.t_Option i64)
                <:
                bool
              with
              | true ->
                Core_models.Option.Option_Some
                (WriteDecision_Accept
                  ({ f_write_epoch = next; f_read_epoch = state.f_epoch } <: t_EpochRoute)
                  <:
                  t_WriteDecision)
                <:
                Core_models.Option.t_Option t_WriteDecision
              | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option t_WriteDecision)
          | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option t_WriteDecision)
        <:
        Core_models.Option.t_Option t_WriteDecision
      with
      | Core_models.Option.Option_Some x -> x
      | Core_models.Option.Option_None  -> WriteDecision_Reject <: t_WriteDecision

type t_StartFacts = {
  f_no_oram:bool;
  f_all_devices_rekey_capable:bool;
  f_all_devices_acknowledged:bool
}

type t_TransitionPlan = {
  f_from_epoch:i64;
  f_to_epoch:i64
}

type t_StartDecision =
  | StartDecision_Start : t_TransitionPlan -> t_StartDecision
  | StartDecision_Reject : t_StartDecision

/// Whether an ACTIVE account is ready to begin exactly one rotation.
let start_is_authorized (state: t_RekeyState) (facts: t_StartFacts) : bool =
  impl_RekeyState__is_valid state && state.f_phase =. (Phase_Active <: t_Phase) &&
  Core_models.Option.impl__is_some #i64
    (next_epoch state.f_epoch <: Core_models.Option.t_Option i64) &&
  facts.f_no_oram &&
  facts.f_all_devices_rekey_capable &&
  facts.f_all_devices_acknowledged

let start_decision_matches_spec
      (state: t_RekeyState)
      (facts: t_StartFacts)
      (decision: t_StartDecision)
    : bool =
  match decision <: t_StartDecision with
  | StartDecision_Start plan ->
    start_is_authorized state facts && plan.f_from_epoch =. state.f_epoch &&
    (next_epoch state.f_epoch <: Core_models.Option.t_Option i64) =.
    (Core_models.Option.Option_Some plan.f_to_epoch <: Core_models.Option.t_Option i64)
  | StartDecision_Reject  -> ~.(start_is_authorized state facts <: bool)

/// Produce the only legal transition plan for a new rotation.
let plan_start (state: t_RekeyState) (facts: t_StartFacts)
    : Prims.Pure t_StartDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_StartDecision = decision in
          start_decision_matches_spec state facts decision) =
  if ~.(start_is_authorized state facts <: bool)
  then StartDecision_Reject <: t_StartDecision
  else
    match next_epoch state.f_epoch <: Core_models.Option.t_Option i64 with
    | Core_models.Option.Option_Some to_epoch ->
      StartDecision_Start
      ({ f_from_epoch = state.f_epoch; f_to_epoch = to_epoch } <: t_TransitionPlan)
      <:
      t_StartDecision
    | Core_models.Option.Option_None  -> StartDecision_Reject <: t_StartDecision

/// Authenticated facts tying an operation to the current rotation attempt.
/// These are computed by comparing the authenticated session and request with
/// the current database row; no identity strings enter the proof core.
type t_AttemptAuthority = {
  f_device_scope:bool;
  f_starter_matches:bool;
  f_rotation_id_present:bool;
  f_rotation_id_matches:bool
}

type t_ShadowDecision =
  | ShadowDecision_Allow : t_ShadowDecision
  | ShadowDecision_Reject : t_ShadowDecision

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_55': Core_models.Cmp.t_PartialEq t_ShadowDecision t_ShadowDecision

unfold
let impl_55 = impl_55'

let attempt_is_authorized (state: t_RekeyState) (authority: t_AttemptAuthority) : bool =
  impl_RekeyState__is_valid state && state.f_phase =. (Phase_Freezing <: t_Phase) &&
  authority.f_device_scope &&
  authority.f_starter_matches &&
  authority.f_rotation_id_present &&
  authority.f_rotation_id_matches

let authorize_attempt (state: t_RekeyState) (authority: t_AttemptAuthority)
    : Prims.Pure t_ShadowDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ShadowDecision = decision in
          (decision =. (ShadowDecision_Allow <: t_ShadowDecision) <: bool) =.
          (attempt_is_authorized state authority <: bool)) =
  if attempt_is_authorized state authority
  then ShadowDecision_Allow <: t_ShadowDecision
  else ShadowDecision_Reject <: t_ShadowDecision

/// Exact authorization predicate for target-epoch shadow ciphertext.
let shadow_is_authorized (state: t_RekeyState) (route: t_EpochRoute) (authority: t_AttemptAuthority)
    : bool =
  attempt_is_authorized state authority &&
  (next_epoch state.f_epoch <: Core_models.Option.t_Option i64) =.
  (Core_models.Option.Option_Some route.f_write_epoch <: Core_models.Option.t_Option i64) &&
  route.f_read_epoch =. state.f_epoch

/// Authorize a shadow write using only already-authenticated facts.
let authorize_shadow (state: t_RekeyState) (route: t_EpochRoute) (authority: t_AttemptAuthority)
    : Prims.Pure t_ShadowDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ShadowDecision = decision in
          (decision =. (ShadowDecision_Allow <: t_ShadowDecision) <: bool) =.
          (shadow_is_authorized state route authority <: bool)) =
  if shadow_is_authorized state route authority
  then ShadowDecision_Allow <: t_ShadowDecision
  else ShadowDecision_Reject <: t_ShadowDecision

type t_CommitFacts = {
  f_authority:t_AttemptAuthority;
  f_chunk_shadows_complete:bool;
  f_device_capsules_complete:bool
}

type t_CommitDecision =
  | CommitDecision_Commit : t_TransitionPlan -> t_CommitDecision
  | CommitDecision_Reject : t_CommitDecision

let commit_is_authorized (state: t_RekeyState) (facts: t_CommitFacts) : bool =
  attempt_is_authorized state facts.f_authority &&
  Core_models.Option.impl__is_some #i64
    (next_epoch state.f_epoch <: Core_models.Option.t_Option i64) &&
  facts.f_chunk_shadows_complete &&
  facts.f_device_capsules_complete

let commit_decision_matches_spec
      (state: t_RekeyState)
      (facts: t_CommitFacts)
      (decision: t_CommitDecision)
    : bool =
  match decision <: t_CommitDecision with
  | CommitDecision_Commit plan ->
    commit_is_authorized state facts && plan.f_from_epoch =. state.f_epoch &&
    (next_epoch state.f_epoch <: Core_models.Option.t_Option i64) =.
    (Core_models.Option.Option_Some plan.f_to_epoch <: Core_models.Option.t_Option i64)
  | CommitDecision_Reject  -> ~.(commit_is_authorized state facts <: bool)

/// Commit only an authorized, structurally complete rotation and advance by
/// exactly one representable epoch.
let plan_commit (state: t_RekeyState) (facts: t_CommitFacts)
    : Prims.Pure t_CommitDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_CommitDecision = decision in
          commit_decision_matches_spec state facts decision) =
  if ~.(commit_is_authorized state facts <: bool)
  then CommitDecision_Reject <: t_CommitDecision
  else
    match next_epoch state.f_epoch <: Core_models.Option.t_Option i64 with
    | Core_models.Option.Option_Some to_epoch ->
      CommitDecision_Commit
      ({ f_from_epoch = state.f_epoch; f_to_epoch = to_epoch } <: t_TransitionPlan)
      <:
      t_CommitDecision
    | Core_models.Option.Option_None  -> CommitDecision_Reject <: t_CommitDecision

type t_AbortDecision =
  | AbortDecision_Abort : t_RekeyState -> t_AbortDecision
  | AbortDecision_Reject : t_AbortDecision

let abort_decision_matches_spec
      (state: t_RekeyState)
      (authority: t_AttemptAuthority)
      (decision: t_AbortDecision)
    : bool =
  match decision <: t_AbortDecision with
  | AbortDecision_Abort after ->
    attempt_is_authorized state authority && after.f_epoch =. state.f_epoch &&
    after.f_phase =. (Phase_Active <: t_Phase)
  | AbortDecision_Reject  -> ~.(attempt_is_authorized state authority <: bool)

/// Abort an authorized attempt without changing its authoritative epoch.
let plan_abort (state: t_RekeyState) (authority: t_AttemptAuthority)
    : Prims.Pure t_AbortDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_AbortDecision = decision in
          abort_decision_matches_spec state authority decision) =
  if attempt_is_authorized state authority
  then
    AbortDecision_Abort
    ({ f_epoch = state.f_epoch; f_phase = Phase_Active <: t_Phase } <: t_RekeyState)
    <:
    t_AbortDecision
  else AbortDecision_Reject <: t_AbortDecision

type t_TimeoutFacts = {
  f_expired:bool;
  f_rotation_id_present:bool
}

type t_TimeoutDecision =
  | TimeoutDecision_Rollback : t_RekeyState -> t_TimeoutDecision
  | TimeoutDecision_Keep : t_TimeoutDecision

let timeout_is_required (state: t_RekeyState) (facts: t_TimeoutFacts) : bool =
  impl_RekeyState__is_valid state && state.f_phase =. (Phase_Freezing <: t_Phase) && facts.f_expired &&
  facts.f_rotation_id_present

let timeout_decision_matches_spec
      (state: t_RekeyState)
      (facts: t_TimeoutFacts)
      (decision: t_TimeoutDecision)
    : bool =
  match decision <: t_TimeoutDecision with
  | TimeoutDecision_Rollback after ->
    timeout_is_required state facts && after.f_epoch =. state.f_epoch &&
    after.f_phase =. (Phase_Active <: t_Phase)
  | TimeoutDecision_Keep  -> ~.(timeout_is_required state facts <: bool)

/// Roll back an expired attempt without advancing its authoritative epoch.
let plan_timeout (state: t_RekeyState) (facts: t_TimeoutFacts)
    : Prims.Pure t_TimeoutDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_TimeoutDecision = decision in
          timeout_decision_matches_spec state facts decision) =
  if timeout_is_required state facts
  then
    TimeoutDecision_Rollback
    ({ f_epoch = state.f_epoch; f_phase = Phase_Active <: t_Phase } <: t_RekeyState)
    <:
    t_TimeoutDecision
  else TimeoutDecision_Keep <: t_TimeoutDecision

type t_CommitReplayFacts = {
  f_target_epoch:Core_models.Option.t_Option i64;
  f_recorded_epoch:Core_models.Option.t_Option i64;
  f_rotation_id_present:bool;
  f_rotation_id_matches:bool
}

let commit_replay_is_authorized (state: t_RekeyState) (facts: t_CommitReplayFacts) : bool =
  impl_RekeyState__is_valid state && state.f_phase =. (Phase_Active <: t_Phase) &&
  facts.f_target_epoch =.
  (Core_models.Option.Option_Some state.f_epoch <: Core_models.Option.t_Option i64) &&
  facts.f_recorded_epoch =.
  (Core_models.Option.Option_Some state.f_epoch <: Core_models.Option.t_Option i64) &&
  facts.f_rotation_id_present &&
  facts.f_rotation_id_matches

/// Accept a lost-response replay exactly when it names the recorded commit.
let authorize_commit_replay (state: t_RekeyState) (facts: t_CommitReplayFacts)
    : Prims.Pure t_ShadowDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ShadowDecision = decision in
          (decision =. (ShadowDecision_Allow <: t_ShadowDecision) <: bool) =.
          (commit_replay_is_authorized state facts <: bool)) =
  if commit_replay_is_authorized state facts
  then ShadowDecision_Allow <: t_ShadowDecision
  else ShadowDecision_Reject <: t_ShadowDecision

type t_MutationKind =
  | MutationKind_Vault : t_MutationKind
  | MutationKind_Recovery : t_MutationKind
  | MutationKind_Enrollment : t_MutationKind

type t_MutationAuthority =
  | MutationAuthority_Device : t_MutationAuthority
  | MutationAuthority_WebSession : t_MutationAuthority
  | MutationAuthority_RecoveryGrant : t_MutationAuthority

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_103': Core_models.Cmp.t_PartialEq t_MutationAuthority t_MutationAuthority

unfold
let impl_103 = impl_103'

type t_MutationRequest = {
  f_declared_epoch:i64;
  f_authority_epoch:i64;
  f_kind:t_MutationKind;
  f_authority:t_MutationAuthority
}

type t_MutationPermit = { f_epoch:i64 }

type t_MutationDecision =
  | MutationDecision_Permit : t_MutationPermit -> t_MutationDecision
  | MutationDecision_Reject : t_MutationDecision

let mutation_request_is_authorized (request: t_MutationRequest) : bool =
  request.f_declared_epoch >=. v_INITIAL_EPOCH && request.f_authority_epoch >=. v_INITIAL_EPOCH &&
  request.f_declared_epoch =. request.f_authority_epoch &&
  (match request.f_kind <: t_MutationKind with
    | MutationKind_Vault  ->
      request.f_authority =. (MutationAuthority_Device <: t_MutationAuthority) ||
      request.f_authority =. (MutationAuthority_WebSession <: t_MutationAuthority)
    | MutationKind_Recovery  ->
      request.f_authority =. (MutationAuthority_Device <: t_MutationAuthority)
    | MutationKind_Enrollment  ->
      request.f_authority =. (MutationAuthority_Device <: t_MutationAuthority) ||
      request.f_authority =. (MutationAuthority_RecoveryGrant <: t_MutationAuthority))

let mutation_decision_matches_spec (request: t_MutationRequest) (decision: t_MutationDecision)
    : bool =
  match decision <: t_MutationDecision with
  | MutationDecision_Permit permit ->
    mutation_request_is_authorized request && permit.f_epoch =. request.f_declared_epoch &&
    permit.f_epoch =. request.f_authority_epoch
  | MutationDecision_Reject  -> ~.(mutation_request_is_authorized request <: bool)

/// Produce the epoch permit consumed by an atomic ACTIVE-state SQL guard.
let plan_active_mutation (request: t_MutationRequest)
    : Prims.Pure t_MutationDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_MutationDecision = decision in
          mutation_decision_matches_spec request decision) =
  if mutation_request_is_authorized request
  then
    MutationDecision_Permit ({ f_epoch = request.f_declared_epoch } <: t_MutationPermit)
    <:
    t_MutationDecision
  else MutationDecision_Reject <: t_MutationDecision

/// The database-side condition represented by a mutation permit.
let active_mutation_is_authorized (state: t_RekeyState) (permit: t_MutationPermit) : bool =
  impl_RekeyState__is_valid state && state.f_phase =. (Phase_Active <: t_Phase) &&
  state.f_epoch =. permit.f_epoch

let authorize_active_mutation (state: t_RekeyState) (permit: t_MutationPermit)
    : Prims.Pure t_ShadowDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ShadowDecision = decision in
          (decision =. (ShadowDecision_Allow <: t_ShadowDecision) <: bool) =.
          (active_mutation_is_authorized state permit <: bool)) =
  if active_mutation_is_authorized state permit
  then ShadowDecision_Allow <: t_ShadowDecision
  else ShadowDecision_Reject <: t_ShadowDecision

/// A permit for ACTIVE(N) cannot authorize a mutation after a successful
/// transition to ACTIVE(N+1).
let stale_permit_authorizes_successor (before: t_RekeyState) (permit: t_MutationPermit)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  if
    ~.(impl_RekeyState__is_valid before <: bool) || before.f_phase <>. (Phase_Active <: t_Phase) ||
    permit.f_epoch <>. before.f_epoch
  then false
  else
    match next_epoch before.f_epoch <: Core_models.Option.t_Option i64 with
    | Core_models.Option.Option_Some after_epoch ->
      active_mutation_is_authorized ({ f_epoch = after_epoch; f_phase = Phase_Active <: t_Phase }
          <:
          t_RekeyState)
        permit
    | Core_models.Option.Option_None  -> false
