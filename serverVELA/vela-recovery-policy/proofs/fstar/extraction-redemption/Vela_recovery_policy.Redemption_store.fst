module Vela_recovery_policy.Redemption_store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Which live authority the guarded insert requires.
type t_GrantGuard =
  | GrantGuard_Credential { f_credential_id:Alloc.String.t_String }: t_GrantGuard
  | GrantGuard_Commitment : t_GrantGuard

/// One enrollment grant as the key-value store holds it.
type t_GrantView = {
  f_key_epoch:i64;
  f_credential_id:Alloc.String.t_String;
  f_possession:bool
}

/// What the atomic `get_del` of one grant observed. A store error aborts the
/// request before classification, so it is not a variant here.
type t_GrantTake =
  | GrantTake_Missing : t_GrantTake
  | GrantTake_Taken : t_GrantView -> t_GrantTake

/// One statement an executor method runs.
type t_RedemptionStmt =
  | RedemptionStmt_TakeGrant { f_key:Alloc.String.t_String }: t_RedemptionStmt
  | RedemptionStmt_InsertDevice {
    f_device_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_device_name:Alloc.String.t_String;
    f_device_type:Alloc.String.t_String;
    f_hybrid_ek:Alloc.String.t_String;
    f_hybrid_vk:Alloc.String.t_String;
    f_created_at:Alloc.String.t_String;
    f_epoch:i64;
    f_guard:t_GrantGuard
  }: t_RedemptionStmt
  | RedemptionStmt_SelectAuthority { f_user:Alloc.String.t_String }: t_RedemptionStmt
  | RedemptionStmt_PutGrant {
    f_key:Alloc.String.t_String;
    f_value:Alloc.String.t_String;
    f_grant:t_GrantView
  }: t_RedemptionStmt

/// What one write statement returned.
type t_WriteOutcome =
  | WriteOutcome_Applied : u64 -> t_WriteOutcome
  | WriteOutcome_Failed : t_WriteOutcome

/// What one read statement returned: its first row, or an error.
type t_ReadOutcome (v_R: Type0) =
  | ReadOutcome_Row : Core_models.Option.t_Option v_R -> t_ReadOutcome v_R
  | ReadOutcome_Failed : t_ReadOutcome v_R

/// The cells of a `SelectAuthority` row: `recovery_webauthn_cred_id` and
/// `recovery_auth_hash`.
type t_AuthorityRowView = {
  f_credential_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_auth_hash:Core_models.Option.t_Option Alloc.String.t_String
}

/// `consume_grant`: the single-use `get_del` of the exact grant key.
let plan_take_grant (key: Alloc.String.t_String) : t_RedemptionStmt =
  RedemptionStmt_TakeGrant ({ f_key = key }) <: t_RedemptionStmt

/// `insert_device`: exactly one guarded device insert with the driver's
/// permit and the grant's guard.
let plan_insert_device
      (device_id user device_name device_type hybrid_ek hybrid_vk created_at: Alloc.String.t_String)
      (epoch: i64)
      (guard: t_GrantGuard)
    : Alloc.Vec.t_Vec t_RedemptionStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_RedemptionStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            RedemptionStmt_InsertDevice
            ({
                f_device_id = device_id;
                f_user = user;
                f_device_name = device_name;
                f_device_type = device_type;
                f_hybrid_ek = hybrid_ek;
                f_hybrid_vk = hybrid_vk;
                f_created_at = created_at;
                f_epoch = epoch;
                f_guard = guard
              })
            <:
            t_RedemptionStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_RedemptionStmt)

/// `recheck_authority`: read the live credential and commitment columns.
let plan_authority_read (user: Alloc.String.t_String) : t_RedemptionStmt =
  RedemptionStmt_SelectAuthority ({ f_user = user }) <: t_RedemptionStmt

/// `restore_grant`: overwrite the exact grant key with the consumed grant.
let plan_restore_grant (key value: Alloc.String.t_String) (grant: t_GrantView)
    : Alloc.Vec.t_Vec t_RedemptionStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_RedemptionStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            RedemptionStmt_PutGrant ({ f_key = key; f_value = value; f_grant = grant })
            <:
            t_RedemptionStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_RedemptionStmt)

/// The single-use consumption: a missing grant is `Missing`; a removed grant
/// is `Present` with the value's own fields and the full-value equality with
/// the preflight permit.
let classify_take (taken: t_GrantTake) (preflight: t_GrantView)
    : Vela_recovery_policy.Driver.t_ConsumptionObservation =
  match taken <: t_GrantTake with
  | GrantTake_Missing  ->
    Vela_recovery_policy.Driver.ConsumptionObservation_Missing
    <:
    Vela_recovery_policy.Driver.t_ConsumptionObservation
  | GrantTake_Taken grant ->
    Vela_recovery_policy.Driver.ConsumptionObservation_Present
    ({
        Vela_recovery_policy.Driver.f_key_epoch = grant.f_key_epoch;
        Vela_recovery_policy.Driver.f_possession = grant.f_possession;
        Vela_recovery_policy.Driver.f_matches_observed_grant
        =
        grant.f_key_epoch =. preflight.f_key_epoch && grant.f_possession =. preflight.f_possession &&
        grant.f_credential_id =. preflight.f_credential_id
      }
      <:
      Vela_recovery_policy.Driver.t_ConsumedGrantObservation)
    <:
    Vela_recovery_policy.Driver.t_ConsumptionObservation

/// The guarded insert: a positive row count is `Inserted`, zero is `Skipped`,
/// an error is `Failed`.
let classify_insert (outcomes: t_Slice t_WriteOutcome)
    : Vela_recovery_policy.Driver.t_InsertObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied rows ->
      if rows >. mk_u64 0
      then
        Vela_recovery_policy.Driver.InsertObservation_Inserted
        <:
        Vela_recovery_policy.Driver.t_InsertObservation
      else
        Vela_recovery_policy.Driver.InsertObservation_Skipped
        <:
        Vela_recovery_policy.Driver.t_InsertObservation
    | WriteOutcome_Failed  ->
      Vela_recovery_policy.Driver.InsertObservation_Failed
      <:
      Vela_recovery_policy.Driver.t_InsertObservation
  else
    Vela_recovery_policy.Driver.InsertObservation_Failed
    <:
    Vela_recovery_policy.Driver.t_InsertObservation

/// The live authority recheck, in the handler's historical precedence.
let classify_authority
      (outcome: t_ReadOutcome t_AuthorityRowView)
      (possession: bool)
      (credential_id: Alloc.String.t_String)
    : Vela_recovery_policy.Driver.t_AuthorityRecheckObservation =
  match outcome <: t_ReadOutcome t_AuthorityRowView with
  | ReadOutcome_Failed  ->
    Vela_recovery_policy.Driver.AuthorityRecheckObservation_QueryFailed
    <:
    Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
  | ReadOutcome_Row (Core_models.Option.Option_None ) ->
    Vela_recovery_policy.Driver.AuthorityRecheckObservation_AccountAbsent
    <:
    Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
  | ReadOutcome_Row (Core_models.Option.Option_Some row) ->
    if possession
    then
      match row.f_auth_hash <: Core_models.Option.t_Option Alloc.String.t_String with
      | Core_models.Option.Option_Some _ ->
        Vela_recovery_policy.Driver.AuthorityRecheckObservation_StillRotating
        <:
        Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
      | Core_models.Option.Option_None  ->
        Vela_recovery_policy.Driver.AuthorityRecheckObservation_CommitmentRevoked
        <:
        Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
    else
      match row.f_credential_id <: Core_models.Option.t_Option Alloc.String.t_String with
      | Core_models.Option.Option_Some current ->
        if current =. credential_id
        then
          Vela_recovery_policy.Driver.AuthorityRecheckObservation_StillRotating
          <:
          Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
        else
          Vela_recovery_policy.Driver.AuthorityRecheckObservation_CredentialReplaced
          <:
          Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
      | Core_models.Option.Option_None  ->
        Vela_recovery_policy.Driver.AuthorityRecheckObservation_CredentialReplaced
        <:
        Vela_recovery_policy.Driver.t_AuthorityRecheckObservation
