module Vela_recovery_policy.Share_store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// One statement a recovery-share executor method runs.
type t_ShareStmt =
  | ShareStmt_StageShare {
    f_user:Alloc.String.t_String;
    f_share:Alloc.String.t_String;
    f_split_id:Alloc.String.t_String;
    f_epoch:i64;
    f_auth_hash:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_PromoteStagedSplit {
    f_user:Alloc.String.t_String;
    f_epoch:i64;
    f_split_id:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_DeleteShare {
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_ShareStmt
  | ShareStmt_SelectStageAccount { f_user:Alloc.String.t_String }: t_ShareStmt
  | ShareStmt_SelectFinalizeAccount { f_user:Alloc.String.t_String }: t_ShareStmt
  | ShareStmt_SelectShare { f_user:Alloc.String.t_String }: t_ShareStmt

/// The cells of a `SelectStageAccount` row: `key_epoch`, `rekey_state`,
/// `recovery_share` and `recovery_split_id`.
type t_StageAccountRowView = {
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_rotation_active:bool;
  f_active_share:Core_models.Option.t_Option Alloc.String.t_String;
  f_active_split:Core_models.Option.t_Option Alloc.String.t_String
}

/// The cells of a `SelectFinalizeAccount` row: `key_epoch`, `rekey_state` and
/// `recovery_split_id`.
type t_FinalizeAccountRowView = {
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_rotation_active:bool;
  f_active_split:Core_models.Option.t_Option Alloc.String.t_String
}

/// The cells of a `SelectShare` row: `recovery_share`, `recovery_split_id` and
/// `key_epoch`. `share` is the raw stored base64 text; the handler decodes it
/// after classification.
type t_ShareRowView = {
  f_share:Core_models.Option.t_Option Alloc.String.t_String;
  f_split_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_epoch:Core_models.Option.t_Option i64
}

/// `PutShareIo::stage_share`: one guarded update of the staged candidate.
let plan_stage_share
      (user share split_id: Alloc.String.t_String)
      (epoch: i64)
      (auth_hash: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            ShareStmt_StageShare
            ({
                f_user = user;
                f_share = share;
                f_split_id = split_id;
                f_epoch = epoch;
                f_auth_hash = auth_hash
              })
            <:
            t_ShareStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// `FinalizeShareIo::promote_staged_split`: one guarded promotion.
let plan_promote_staged_split
      (user: Alloc.String.t_String)
      (epoch: i64)
      (split_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            ShareStmt_PromoteStagedSplit ({ f_user = user; f_epoch = epoch; f_split_id = split_id })
            <:
            t_ShareStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// `DeleteShareIo::delete_share`: one guarded clear of share and candidate.
let plan_delete_share (user: Alloc.String.t_String) (epoch: i64)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list = [ShareStmt_DeleteShare ({ f_user = user; f_epoch = epoch }) <: t_ShareStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// `PutShareIo::stage_query_account`: read the live row after a zero-row
/// stage update.
let plan_stage_account (user: Alloc.String.t_String) : t_ShareStmt =
  ShareStmt_SelectStageAccount ({ f_user = user }) <: t_ShareStmt

/// `FinalizeShareIo::finalize_query_account`: read the live row after a
/// zero-row finalize update.
let plan_finalize_account (user: Alloc.String.t_String) : t_ShareStmt =
  ShareStmt_SelectFinalizeAccount ({ f_user = user }) <: t_ShareStmt

/// `GetShareIo::read_share`: read the active share of the session account.
let plan_read_share (user: Alloc.String.t_String) : t_ShareStmt =
  ShareStmt_SelectShare ({ f_user = user }) <: t_ShareStmt

/// `stage_share`: exactly one updated row is `Staged`, anything else is
/// `NotStaged`. A statement error aborts before classification.
let classify_stage_update (outcomes: t_Slice Vela_recovery_policy.Redemption_store.t_WriteOutcome)
    : Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation =
  if
    (Core_models.Slice.impl__len #Vela_recovery_policy.Redemption_store.t_WriteOutcome outcomes
      <:
      usize) =.
    mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: Vela_recovery_policy.Redemption_store.t_WriteOutcome with
    | Vela_recovery_policy.Redemption_store.WriteOutcome_Applied rows ->
      if rows =. mk_u64 1
      then
        Vela_recovery_policy.Recovery_share_driver.StageUpdateObservation_Staged
        <:
        Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation
      else
        Vela_recovery_policy.Recovery_share_driver.StageUpdateObservation_NotStaged
        <:
        Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation
    | Vela_recovery_policy.Redemption_store.WriteOutcome_Failed  ->
      Vela_recovery_policy.Recovery_share_driver.StageUpdateObservation_NotStaged
      <:
      Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation
  else
    Vela_recovery_policy.Recovery_share_driver.StageUpdateObservation_NotStaged
    <:
    Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation

/// `stage_query_account`: the live row's truth, or the all-absent observation
/// when the account row is gone.
let classify_stage_account
      (row: Core_models.Option.t_Option t_StageAccountRowView)
      (share split_id: Alloc.String.t_String)
    : Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation =
  match row <: Core_models.Option.t_Option t_StageAccountRowView with
  | Core_models.Option.Option_None  ->
    {
      Vela_recovery_policy.Recovery_share_driver.f_account_present = false;
      Vela_recovery_policy.Recovery_share_driver.f_stored_epoch
      =
      Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
      Vela_recovery_policy.Recovery_share_driver.f_rotation_active = false;
      Vela_recovery_policy.Recovery_share_driver.f_active_share_matches = false;
      Vela_recovery_policy.Recovery_share_driver.f_active_split_matches = false
    }
    <:
    Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation
  | Core_models.Option.Option_Some row ->
    {
      Vela_recovery_policy.Recovery_share_driver.f_account_present = true;
      Vela_recovery_policy.Recovery_share_driver.f_stored_epoch = row.f_stored_epoch;
      Vela_recovery_policy.Recovery_share_driver.f_rotation_active = row.f_rotation_active;
      Vela_recovery_policy.Recovery_share_driver.f_active_share_matches
      =
      (Core_models.Option.impl__as_ref #Alloc.String.t_String row.f_active_share
        <:
        Core_models.Option.t_Option Alloc.String.t_String) =.
      (Core_models.Option.Option_Some share <: Core_models.Option.t_Option Alloc.String.t_String);
      Vela_recovery_policy.Recovery_share_driver.f_active_split_matches
      =
      (Core_models.Option.impl__as_ref #Alloc.String.t_String row.f_active_split
        <:
        Core_models.Option.t_Option Alloc.String.t_String) =.
      (Core_models.Option.Option_Some split_id <: Core_models.Option.t_Option Alloc.String.t_String)
    }
    <:
    Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation

/// `promote_staged_split`: exactly one updated row is `Promoted`, anything else
/// is `NotPromoted`.
let classify_finalize_update
      (outcomes: t_Slice Vela_recovery_policy.Redemption_store.t_WriteOutcome)
    : Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation =
  if
    (Core_models.Slice.impl__len #Vela_recovery_policy.Redemption_store.t_WriteOutcome outcomes
      <:
      usize) =.
    mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: Vela_recovery_policy.Redemption_store.t_WriteOutcome with
    | Vela_recovery_policy.Redemption_store.WriteOutcome_Applied rows ->
      if rows =. mk_u64 1
      then
        Vela_recovery_policy.Recovery_share_driver.FinalizeUpdateObservation_Promoted
        <:
        Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation
      else
        Vela_recovery_policy.Recovery_share_driver.FinalizeUpdateObservation_NotPromoted
        <:
        Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation
    | Vela_recovery_policy.Redemption_store.WriteOutcome_Failed  ->
      Vela_recovery_policy.Recovery_share_driver.FinalizeUpdateObservation_NotPromoted
      <:
      Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation
  else
    Vela_recovery_policy.Recovery_share_driver.FinalizeUpdateObservation_NotPromoted
    <:
    Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation

/// `finalize_query_account`: the live row's truth, or the all-absent
/// observation when the account row is gone.
let classify_finalize_account
      (row: Core_models.Option.t_Option t_FinalizeAccountRowView)
      (split_id: Alloc.String.t_String)
    : Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation =
  match row <: Core_models.Option.t_Option t_FinalizeAccountRowView with
  | Core_models.Option.Option_None  ->
    {
      Vela_recovery_policy.Recovery_share_driver.f_account_present = false;
      Vela_recovery_policy.Recovery_share_driver.f_stored_epoch
      =
      Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
      Vela_recovery_policy.Recovery_share_driver.f_rotation_active = false;
      Vela_recovery_policy.Recovery_share_driver.f_active_split_matches = false
    }
    <:
    Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation
  | Core_models.Option.Option_Some row ->
    {
      Vela_recovery_policy.Recovery_share_driver.f_account_present = true;
      Vela_recovery_policy.Recovery_share_driver.f_stored_epoch = row.f_stored_epoch;
      Vela_recovery_policy.Recovery_share_driver.f_rotation_active = row.f_rotation_active;
      Vela_recovery_policy.Recovery_share_driver.f_active_split_matches
      =
      (Core_models.Option.impl__as_ref #Alloc.String.t_String row.f_active_split
        <:
        Core_models.Option.t_Option Alloc.String.t_String) =.
      (Core_models.Option.Option_Some split_id <: Core_models.Option.t_Option Alloc.String.t_String)
    }
    <:
    Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation

/// `delete_share`: exactly one updated row is `Deleted`, anything else is
/// `NotDeleted`.
let classify_delete_update (outcomes: t_Slice Vela_recovery_policy.Redemption_store.t_WriteOutcome)
    : Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation =
  if
    (Core_models.Slice.impl__len #Vela_recovery_policy.Redemption_store.t_WriteOutcome outcomes
      <:
      usize) =.
    mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: Vela_recovery_policy.Redemption_store.t_WriteOutcome with
    | Vela_recovery_policy.Redemption_store.WriteOutcome_Applied rows ->
      if rows =. mk_u64 1
      then
        Vela_recovery_policy.Recovery_share_driver.DeleteUpdateObservation_Deleted
        <:
        Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation
      else
        Vela_recovery_policy.Recovery_share_driver.DeleteUpdateObservation_NotDeleted
        <:
        Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation
    | Vela_recovery_policy.Redemption_store.WriteOutcome_Failed  ->
      Vela_recovery_policy.Recovery_share_driver.DeleteUpdateObservation_NotDeleted
      <:
      Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation
  else
    Vela_recovery_policy.Recovery_share_driver.DeleteUpdateObservation_NotDeleted
    <:
    Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation

/// `read_share`: the live row's truth about account and share presence.
let classify_read_share (row: Core_models.Option.t_Option t_ShareRowView)
    : Vela_recovery_policy.Recovery_share_driver.t_ReadObservation =
  match row <: Core_models.Option.t_Option t_ShareRowView with
  | Core_models.Option.Option_None  ->
    {
      Vela_recovery_policy.Recovery_share_driver.f_account_present = false;
      Vela_recovery_policy.Recovery_share_driver.f_share_present = false
    }
    <:
    Vela_recovery_policy.Recovery_share_driver.t_ReadObservation
  | Core_models.Option.Option_Some row ->
    {
      Vela_recovery_policy.Recovery_share_driver.f_account_present = true;
      Vela_recovery_policy.Recovery_share_driver.f_share_present
      =
      Core_models.Option.impl__is_some #Alloc.String.t_String row.f_share
    }
    <:
    Vela_recovery_policy.Recovery_share_driver.t_ReadObservation
