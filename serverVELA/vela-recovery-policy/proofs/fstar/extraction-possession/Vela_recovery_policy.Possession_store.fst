module Vela_recovery_policy.Possession_store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// The fields one stored proof attempt carries, as the plan writes them.
type t_ProofAttemptView = {
  f_user:Alloc.String.t_String;
  f_attempt:Alloc.String.t_String;
  f_key_epoch:i64
}

/// The single-use enrollment grant as the store holds it.
type t_EnrollmentGrantView = { f_key_epoch:i64 }

/// One statement a possession executor method runs.
type t_PossessionStmt =
  | PossessionStmt_SelectInitiateAccount { f_user:Alloc.String.t_String }: t_PossessionStmt
  | PossessionStmt_ProofSlotExists { f_key:Alloc.String.t_String }: t_PossessionStmt
  | PossessionStmt_StoreProofChallenge {
    f_key:Alloc.String.t_String;
    f_value:Alloc.String.t_String;
    f_attempt:t_ProofAttemptView;
    f_ttl_secs:u64
  }: t_PossessionStmt
  | PossessionStmt_TakeProofAttempt { f_key:Alloc.String.t_String }: t_PossessionStmt
  | PossessionStmt_SelectProofAccount { f_user:Alloc.String.t_String }: t_PossessionStmt
  | PossessionStmt_PutEnrollmentGrant {
    f_key:Alloc.String.t_String;
    f_value:Alloc.String.t_String;
    f_grant:t_EnrollmentGrantView;
    f_ttl_secs:u64
  }: t_PossessionStmt

/// The cells of an initiation account row: `recovery_share`,
/// `recovery_auth_hash` (decoded), `key_epoch` and `rekey_state`.
type t_InitiateRowView = {
  f_share_present:bool;
  f_commitment:Vela_recovery_policy.Possession_driver.t_CommitmentObservation;
  f_key_epoch:Core_models.Option.t_Option i64;
  f_rotation_active:bool
}

/// The cells of a proof-recovery account row: `recovery_auth_hash` (decoded),
/// `key_epoch` and `rekey_state`.
type t_ProofAccountRowView = {
  f_commitment:Vela_recovery_policy.Possession_driver.t_CommitmentObservation;
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_rotation_active:bool
}

/// What the atomic `get_del` of one proof attempt observed. A store error
/// aborts the request before classification, so it is not a variant here.
type t_ProofAttemptTake =
  | ProofAttemptTake_Missing : t_ProofAttemptTake
  | ProofAttemptTake_Corrupt : t_ProofAttemptTake
  | ProofAttemptTake_Present : t_ProofAttemptView -> t_ProofAttemptTake

/// `InitiateProofIo::observe`: read the live account row.
let plan_initiate_account (user: Alloc.String.t_String) : t_PossessionStmt =
  PossessionStmt_SelectInitiateAccount ({ f_user = user }) <: t_PossessionStmt

/// `InitiateProofIo::observe`: probe the generated attempt slot.
let plan_proof_slot (key: Alloc.String.t_String) : t_PossessionStmt =
  PossessionStmt_ProofSlotExists ({ f_key = key }) <: t_PossessionStmt

/// `InitiateProofIo::store_challenge`: commit the drawn challenge.
let plan_store_challenge
      (key value: Alloc.String.t_String)
      (attempt: t_ProofAttemptView)
      (ttl_secs: u64)
    : t_PossessionStmt =
  PossessionStmt_StoreProofChallenge
  ({ f_key = key; f_value = value; f_attempt = attempt; f_ttl_secs = ttl_secs })
  <:
  t_PossessionStmt

/// `RecoverProofIo::consume_attempt`: the atomic single-use take.
let plan_take_attempt (key: Alloc.String.t_String) : t_PossessionStmt =
  PossessionStmt_TakeProofAttempt ({ f_key = key }) <: t_PossessionStmt

/// `RecoverProofIo::query_account`: read the live account row.
let plan_proof_account (user: Alloc.String.t_String) : t_PossessionStmt =
  PossessionStmt_SelectProofAccount ({ f_user = user }) <: t_PossessionStmt

/// `RecoverProofIo::issue_grant`: store exactly one single-use grant.
let plan_issue_grant
      (key value: Alloc.String.t_String)
      (grant: t_EnrollmentGrantView)
      (ttl_secs: u64)
    : t_PossessionStmt =
  PossessionStmt_PutEnrollmentGrant
  ({ f_key = key; f_value = value; f_grant = grant; f_ttl_secs = ttl_secs })
  <:
  t_PossessionStmt

/// `InitiateProofIo::observe`: every field is the live row's truth; the
/// attempt slot is reported fresh exactly when the probe found it empty.
let classify_initiate
      (row: Core_models.Option.t_Option t_InitiateRowView)
      (slot_occupied: bool)
      (ttl_secs: u64)
    : Vela_recovery_policy.Possession_driver.t_InitiateObservation =
  match row <: Core_models.Option.t_Option t_InitiateRowView with
  | Core_models.Option.Option_None  ->
    {
      Vela_recovery_policy.Possession_driver.f_account_present = false;
      Vela_recovery_policy.Possession_driver.f_share_present = false;
      Vela_recovery_policy.Possession_driver.f_commitment
      =
      Vela_recovery_policy.Possession_driver.CommitmentObservation_Missing
      <:
      Vela_recovery_policy.Possession_driver.t_CommitmentObservation;
      Vela_recovery_policy.Possession_driver.f_rotation_active = false;
      Vela_recovery_policy.Possession_driver.f_attempt_id_fresh = ~.slot_occupied;
      Vela_recovery_policy.Possession_driver.f_ttl_secs = ttl_secs
    }
    <:
    Vela_recovery_policy.Possession_driver.t_InitiateObservation
  | Core_models.Option.Option_Some row ->
    {
      Vela_recovery_policy.Possession_driver.f_account_present = true;
      Vela_recovery_policy.Possession_driver.f_share_present = row.f_share_present;
      Vela_recovery_policy.Possession_driver.f_commitment = row.f_commitment;
      Vela_recovery_policy.Possession_driver.f_rotation_active = row.f_rotation_active;
      Vela_recovery_policy.Possession_driver.f_attempt_id_fresh = ~.slot_occupied;
      Vela_recovery_policy.Possession_driver.f_ttl_secs = ttl_secs
    }
    <:
    Vela_recovery_policy.Possession_driver.t_InitiateObservation

/// `InitiateProofIo::observe`: the epoch the challenge is bound to, normalized
/// exactly as `observed_recovery_epoch` normalizes a missing row or column.
let initiate_epoch (row: Core_models.Option.t_Option t_InitiateRowView) : i64 =
  let stored:Core_models.Option.t_Option i64 =
    match row <: Core_models.Option.t_Option t_InitiateRowView with
    | Core_models.Option.Option_Some row -> row.f_key_epoch
    | Core_models.Option.Option_None  ->
      Core_models.Option.Option_None <: Core_models.Option.t_Option i64
  in
  Vela_recovery_policy.observed_recovery_epoch stored

/// `InitiateProofIo::store_challenge`: a written slot is `Stored`, a lost race
/// is `Lost`.
let classify_store_challenge (written: bool)
    : Vela_recovery_policy.Possession_driver.t_ChallengeStoreObservation =
  if written
  then
    Vela_recovery_policy.Possession_driver.ChallengeStoreObservation_Stored
    <:
    Vela_recovery_policy.Possession_driver.t_ChallengeStoreObservation
  else
    Vela_recovery_policy.Possession_driver.ChallengeStoreObservation_Lost
    <:
    Vela_recovery_policy.Possession_driver.t_ChallengeStoreObservation

/// `RecoverProofIo::consume_attempt`: the removed state's own fields and the
/// binding comparison with the request.
let classify_attempt (taken: t_ProofAttemptTake) (user attempt: Alloc.String.t_String)
    : Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation =
  match taken <: t_ProofAttemptTake with
  | ProofAttemptTake_Missing  ->
    Vela_recovery_policy.Possession_driver.AttemptConsumptionObservation_Missing
    <:
    Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation
  | ProofAttemptTake_Corrupt  ->
    Vela_recovery_policy.Possession_driver.AttemptConsumptionObservation_Corrupt
    <:
    Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation
  | ProofAttemptTake_Present state ->
    Vela_recovery_policy.Possession_driver.AttemptConsumptionObservation_Present
    ({
        Vela_recovery_policy.Possession_driver.f_user_matches = state.f_user =. user;
        Vela_recovery_policy.Possession_driver.f_attempt_matches = state.f_attempt =. attempt;
        Vela_recovery_policy.Possession_driver.f_key_epoch = state.f_key_epoch
      })
    <:
    Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation

/// `RecoverProofIo::query_account`: every field is the live row's truth.
let classify_proof_account (row: Core_models.Option.t_Option t_ProofAccountRowView)
    : Vela_recovery_policy.Possession_driver.t_ProofAccountObservation =
  match row <: Core_models.Option.t_Option t_ProofAccountRowView with
  | Core_models.Option.Option_None  ->
    {
      Vela_recovery_policy.Possession_driver.f_account_present = false;
      Vela_recovery_policy.Possession_driver.f_account_epoch_active = false;
      Vela_recovery_policy.Possession_driver.f_commitment
      =
      Vela_recovery_policy.Possession_driver.CommitmentObservation_Missing
      <:
      Vela_recovery_policy.Possession_driver.t_CommitmentObservation;
      Vela_recovery_policy.Possession_driver.f_stored_epoch
      =
      Core_models.Option.Option_None <: Core_models.Option.t_Option i64
    }
    <:
    Vela_recovery_policy.Possession_driver.t_ProofAccountObservation
  | Core_models.Option.Option_Some row ->
    {
      Vela_recovery_policy.Possession_driver.f_account_present = true;
      Vela_recovery_policy.Possession_driver.f_account_epoch_active = ~.row.f_rotation_active;
      Vela_recovery_policy.Possession_driver.f_commitment = row.f_commitment;
      Vela_recovery_policy.Possession_driver.f_stored_epoch = row.f_stored_epoch
    }
    <:
    Vela_recovery_policy.Possession_driver.t_ProofAccountObservation

/// `RecoverProofIo::issue_grant`: a successful `set_ex` is `Stored`, any store
/// error is the `Failed` observation.
let classify_grant_store (stored: bool)
    : Vela_recovery_policy.Possession_driver.t_GrantStoreObservation =
  if stored
  then
    Vela_recovery_policy.Possession_driver.GrantStoreObservation_Stored
    <:
    Vela_recovery_policy.Possession_driver.t_GrantStoreObservation
  else
    Vela_recovery_policy.Possession_driver.GrantStoreObservation_Failed
    <:
    Vela_recovery_policy.Possession_driver.t_GrantStoreObservation
