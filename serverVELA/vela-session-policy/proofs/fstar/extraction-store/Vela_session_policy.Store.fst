module Vela_session_policy.Store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// The remaining-lifetime TTL of a revoked JTI, in seconds
/// (`rate_limit::TOKEN_MAX_LIFETIME_SECS`).
let v_TOKEN_MAX_LIFETIME_SECS: u64 = mk_u64 15 *! mk_u64 60

/// The ceiling of a granted web session, in seconds
/// (`web_session::MAX_TTL_SECS`); a revoked session is locked out for it.
let v_WEB_SESSION_MAX_TTL_SECS: u64 = (mk_u64 24 *! mk_u64 60 <: u64) *! mk_u64 60

/// One SQL statement an executor may run.
type t_SqlStmt =
  | SqlStmt_SelectDeviceIdsByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_SelectWebSessionIdsByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_SelectDeviceById { f_device_id:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_SelectWebSessionIdsApprovedBy {
    f_device_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String
  }: t_SqlStmt
  | SqlStmt_DeleteWebSessionsByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_DeleteShareInboxByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_DeleteSharedItemsByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_DeleteSendsByOwner { f_owner:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_DeleteVaultChunksByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_DeleteOramBucketsByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_DeleteDevicesByUser { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_DeleteUserById { f_user:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_RevokeDeviceRecord {
    f_now:Alloc.String.t_String;
    f_revoked_by:Alloc.String.t_String;
    f_device_id:Alloc.String.t_String
  }: t_SqlStmt
  | SqlStmt_RevokeWebSessionsApprovedBy {
    f_device_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String
  }: t_SqlStmt
  | SqlStmt_Commit : t_SqlStmt

/// One store statement an executor may run.
type t_StoreStmt =
  | StoreStmt_SetEx {
    f_key:Alloc.String.t_String;
    f_value:u8;
    f_ttl:u64
  }: t_StoreStmt
  | StoreStmt_RevokeJtis { f_device:Alloc.String.t_String }: t_StoreStmt

/// What one SQL statement returned.
type t_WriteOutcome =
  | WriteOutcome_Applied : u64 -> t_WriteOutcome
  | WriteOutcome_Failed : t_WriteOutcome

/// What one store statement returned.
type t_StoreOutcome =
  | StoreOutcome_Applied : t_StoreOutcome
  | StoreOutcome_Failed : t_StoreOutcome

/// What one read statement returned: its first row, or an error.
type t_ReadOutcome (v_R: Type0) =
  | ReadOutcome_Row : Core_models.Option.t_Option v_R -> t_ReadOutcome v_R
  | ReadOutcome_Failed : t_ReadOutcome v_R

/// What an id scan returned: the ids of the matching rows, or an error.
type t_IdsOutcome =
  | IdsOutcome_Ids : Alloc.Vec.t_Vec Alloc.String.t_String Alloc.Alloc.t_Global -> t_IdsOutcome
  | IdsOutcome_Failed : t_IdsOutcome

/// The cells of a `SelectDeviceById` row that the classifier reads:
/// `user_id` and `revoked`.
type t_TargetRowView = {
  f_user_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_revoked:Core_models.Option.t_Option i64
}

/// `LogoutJtiIo::revoke_jti`: the caller's JTI marker, with the token
/// lifetime's TTL.
let plan_logout (jti: Alloc.String.t_String) : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:Alloc.String.t_String = jti <: Alloc.String.t_String in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_SetEx
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["jti:revoked:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_value = mk_u8 1;
                f_ttl = v_TOKEN_MAX_LIFETIME_SECS
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// One `device:revoked:` sentinel: a revoked device (or web session) is
/// rejected by the middleware for the whole token lifetime.
let plan_sentinel (device: Alloc.String.t_String) (ttl: u64)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:Alloc.String.t_String = device <: Alloc.String.t_String in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_SetEx
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["device:revoked:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_value = mk_u8 1;
                f_ttl = ttl
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `RevokeDeviceIo::lockout_device`: revoke every tracked JTI, then — only if
/// that succeeded — write the sentinel.
let plan_lockout_device (device: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:Alloc.String.t_String = device <: Alloc.String.t_String in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_RevokeJtis
            ({
                f_device
                =
                Core_models.Clone.f_clone #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  device
              })
            <:
            t_StoreStmt;
            StoreStmt_SetEx
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["device:revoked:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_value = mk_u8 1;
                f_ttl = v_TOKEN_MAX_LIFETIME_SECS
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
        Rust_primitives.Hax.array_of_list 2 list)
      <:
      t_Slice t_StoreStmt)

/// `DeleteAccountIo::lockout_web_sessions`, per session: the sentinel first,
/// then every tracked JTI (the historical order).
let plan_lockout_web_session (session: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:Alloc.String.t_String = session <: Alloc.String.t_String in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_SetEx
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["device:revoked:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_value = mk_u8 1;
                f_ttl = v_WEB_SESSION_MAX_TTL_SECS
              })
            <:
            t_StoreStmt;
            StoreStmt_RevokeJtis ({ f_device = session }) <: t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
        Rust_primitives.Hax.array_of_list 2 list)
      <:
      t_Slice t_StoreStmt)

/// `DeleteAccountIo::scan_devices`.
let plan_scan_devices (user: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_SelectDeviceIdsByUser ({ f_user = user }) <: t_SqlStmt

/// `DeleteAccountIo::scan_web_sessions`.
let plan_scan_web_sessions (user: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_SelectWebSessionIdsByUser ({ f_user = user }) <: t_SqlStmt

/// `DeleteAccountIo::delete_table`, in the driver's historical order.
let plan_delete_table
      (user: Alloc.String.t_String)
      (table: Vela_session_policy.Deletion_driver.t_DeletionTable)
    : t_SqlStmt =
  match table <: Vela_session_policy.Deletion_driver.t_DeletionTable with
  | Vela_session_policy.Deletion_driver.DeletionTable_WebSessions  ->
    SqlStmt_DeleteWebSessionsByUser ({ f_user = user }) <: t_SqlStmt
  | Vela_session_policy.Deletion_driver.DeletionTable_ShareInbox  ->
    SqlStmt_DeleteShareInboxByUser ({ f_user = user }) <: t_SqlStmt
  | Vela_session_policy.Deletion_driver.DeletionTable_SharedItems  ->
    SqlStmt_DeleteSharedItemsByUser ({ f_user = user }) <: t_SqlStmt
  | Vela_session_policy.Deletion_driver.DeletionTable_Sends  ->
    SqlStmt_DeleteSendsByOwner ({ f_owner = user }) <: t_SqlStmt
  | Vela_session_policy.Deletion_driver.DeletionTable_VaultChunks  ->
    SqlStmt_DeleteVaultChunksByUser ({ f_user = user }) <: t_SqlStmt
  | Vela_session_policy.Deletion_driver.DeletionTable_OramBuckets  ->
    SqlStmt_DeleteOramBucketsByUser ({ f_user = user }) <: t_SqlStmt
  | Vela_session_policy.Deletion_driver.DeletionTable_Devices  ->
    SqlStmt_DeleteDevicesByUser ({ f_user = user }) <: t_SqlStmt

/// `DeleteAccountIo::delete_users`: the account-existence signal.
let plan_delete_users (user: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_DeleteUserById ({ f_user = user }) <: t_SqlStmt

/// `DeleteAccountIo::commit`.
let plan_commit (_: Prims.unit) : t_SqlStmt = SqlStmt_Commit <: t_SqlStmt

/// `RevokeDeviceIo::lookup_target`.
let plan_target_lookup (device_id: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_SelectDeviceById ({ f_device_id = device_id }) <: t_SqlStmt

/// `RevokeDeviceIo::record_revocation`.
let plan_revoke_record (device_id now revoked_by: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_RevokeDeviceRecord ({ f_now = now; f_revoked_by = revoked_by; f_device_id = device_id })
  <:
  t_SqlStmt

/// `revoke_web_sessions_approved_by`: read the sessions the device approved.
let plan_cascade_read (device_id user: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_SelectWebSessionIdsApprovedBy ({ f_device_id = device_id; f_user = user }) <: t_SqlStmt

/// `revoke_web_sessions_approved_by`: mark the approved sessions revoked and
/// drop their capsules.
let plan_cascade_update (device_id user: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_RevokeWebSessionsApprovedBy ({ f_device_id = device_id; f_user = user }) <: t_SqlStmt

/// The logout marker: it was written exactly when its one statement ran.
let classify_logout (outcomes: t_Slice t_StoreOutcome)
    : Vela_session_policy.Revocation_driver.t_LogoutObservation =
  if (Core_models.Slice.impl__len #t_StoreOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_StoreOutcome with
    | StoreOutcome_Applied  ->
      Vela_session_policy.Revocation_driver.LogoutObservation_Applied
      <:
      Vela_session_policy.Revocation_driver.t_LogoutObservation
    | StoreOutcome_Failed  ->
      Vela_session_policy.Revocation_driver.LogoutObservation_StorageFailed
      <:
      Vela_session_policy.Revocation_driver.t_LogoutObservation
  else
    Vela_session_policy.Revocation_driver.LogoutObservation_StorageFailed
    <:
    Vela_session_policy.Revocation_driver.t_LogoutObservation

/// The device lockout: both statements ran. A `Failed` outcome means the
/// sentinel was not written (the JTI enumeration failed first).
let classify_lockout_device (outcomes: t_Slice t_StoreOutcome)
    : Vela_session_policy.Revocation_driver.t_LockoutObservation =
  if (Core_models.Slice.impl__len #t_StoreOutcome outcomes <: usize) =. mk_usize 2
  then
    match outcomes.[ mk_usize 0 ], outcomes.[ mk_usize 1 ] <: (t_StoreOutcome & t_StoreOutcome) with
    | StoreOutcome_Applied , StoreOutcome_Applied  ->
      Vela_session_policy.Revocation_driver.LockoutObservation_Applied
      <:
      Vela_session_policy.Revocation_driver.t_LockoutObservation
    | _ ->
      Vela_session_policy.Revocation_driver.LockoutObservation_StorageFailed
      <:
      Vela_session_policy.Revocation_driver.t_LockoutObservation
  else
    Vela_session_policy.Revocation_driver.LockoutObservation_StorageFailed
    <:
    Vela_session_policy.Revocation_driver.t_LockoutObservation

/// A row scan: it returned rows exactly when its one query ran.
let classify_scan (outcome: t_IdsOutcome) : Vela_session_policy.Deletion_driver.t_ScanObservation =
  match outcome <: t_IdsOutcome with
  | IdsOutcome_Ids _ ->
    Vela_session_policy.Deletion_driver.ScanObservation_Rows
    <:
    Vela_session_policy.Deletion_driver.t_ScanObservation
  | IdsOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.ScanObservation_QueryFailed
    <:
    Vela_session_policy.Deletion_driver.t_ScanObservation

/// A batch lockout whose failures the deletion handler ignores: it always
/// reports `Applied`, exactly as before (the observation carries no claim
/// about the store).
let classify_lockout_ignored (e_outcomes: t_Slice t_StoreOutcome)
    : Vela_session_policy.Deletion_driver.t_LockoutObservation =
  Vela_session_policy.Deletion_driver.LockoutObservation_Applied
  <:
  Vela_session_policy.Deletion_driver.t_LockoutObservation

/// Opening the transaction.
let classify_transaction (outcome: t_WriteOutcome)
    : Vela_session_policy.Deletion_driver.t_TransactionObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Deletion_driver.TransactionObservation_Begun
    <:
    Vela_session_policy.Deletion_driver.t_TransactionObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.TransactionObservation_Failed
    <:
    Vela_session_policy.Deletion_driver.t_TransactionObservation

/// One table delete.
let classify_table_delete (outcome: t_WriteOutcome)
    : Vela_session_policy.Deletion_driver.t_TableDeleteObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Deletion_driver.TableDeleteObservation_Deleted
    <:
    Vela_session_policy.Deletion_driver.t_TableDeleteObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.TableDeleteObservation_Failed
    <:
    Vela_session_policy.Deletion_driver.t_TableDeleteObservation

/// The `users` delete: zero rows is the account-absence signal.
let classify_users_delete (outcome: t_WriteOutcome)
    : Vela_session_policy.Deletion_driver.t_UsersDeleteObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
    Vela_session_policy.Deletion_driver.UsersDeleteObservation_Absent
    <:
    Vela_session_policy.Deletion_driver.t_UsersDeleteObservation
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Deletion_driver.UsersDeleteObservation_Deleted
    <:
    Vela_session_policy.Deletion_driver.t_UsersDeleteObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.UsersDeleteObservation_Failed
    <:
    Vela_session_policy.Deletion_driver.t_UsersDeleteObservation

/// The commit.
let classify_commit (outcome: t_WriteOutcome)
    : Vela_session_policy.Deletion_driver.t_CommitObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Deletion_driver.CommitObservation_Committed
    <:
    Vela_session_policy.Deletion_driver.t_CommitObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.CommitObservation_Failed
    <:
    Vela_session_policy.Deletion_driver.t_CommitObservation

/// The target device row as the revocation policy sees it. A failed read is a
/// storage failure; a missing row is `Absent`. A row the handler cannot decode
/// is reported as `Malformed` before this classifier runs.
let classify_target (caller: Alloc.String.t_String) (outcome: t_ReadOutcome t_TargetRowView)
    : Vela_session_policy.Revocation_driver.t_DeviceLookupObservation =
  match outcome <: t_ReadOutcome t_TargetRowView with
  | ReadOutcome_Row (Core_models.Option.Option_Some row) ->
    Vela_session_policy.Revocation_driver.DeviceLookupObservation_Present
    ({
        Vela_session_policy.Revocation_driver.f_same_account
        =
        (match row.f_user_id <: Core_models.Option.t_Option Alloc.String.t_String with
          | Core_models.Option.Option_Some owner -> owner =. caller
          | Core_models.Option.Option_None  -> false);
        Vela_session_policy.Revocation_driver.f_already_revoked
        =
        match row.f_revoked <: Core_models.Option.t_Option i64 with
        | Core_models.Option.Option_Some revoked -> revoked <>. mk_i64 0
        | Core_models.Option.Option_None  -> false
      }
      <:
      Vela_session_policy.Revocation_driver.t_TargetObservation)
    <:
    Vela_session_policy.Revocation_driver.t_DeviceLookupObservation
  | ReadOutcome_Row (Core_models.Option.Option_None ) ->
    Vela_session_policy.Revocation_driver.DeviceLookupObservation_Absent
    <:
    Vela_session_policy.Revocation_driver.t_DeviceLookupObservation
  | ReadOutcome_Failed  ->
    Vela_session_policy.Revocation_driver.DeviceLookupObservation_QueryFailed
    <:
    Vela_session_policy.Revocation_driver.t_DeviceLookupObservation

/// The durable revocation record: it was written exactly when its one
/// statement ran.
let classify_record (outcome: t_WriteOutcome)
    : Vela_session_policy.Revocation_driver.t_RecordObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Revocation_driver.RecordObservation_Updated
    <:
    Vela_session_policy.Revocation_driver.t_RecordObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Revocation_driver.RecordObservation_Failed
    <:
    Vela_session_policy.Revocation_driver.t_RecordObservation

/// The approved-web-session cascade: `ok` is the read, every per-session
/// lockout and the SQL update all having succeeded.
let classify_cascade (ok: bool) : Vela_session_policy.Revocation_driver.t_CascadeObservation =
  if ok
  then
    Vela_session_policy.Revocation_driver.CascadeObservation_Completed
    <:
    Vela_session_policy.Revocation_driver.t_CascadeObservation
  else
    Vela_session_policy.Revocation_driver.CascadeObservation_StorageFailed
    <:
    Vela_session_policy.Revocation_driver.t_CascadeObservation
