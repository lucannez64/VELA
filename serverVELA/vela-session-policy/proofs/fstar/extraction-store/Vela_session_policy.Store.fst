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

/// The window of the per-(ip, device) failed-proof counter
/// (`rate_limit::verify_fail_by_device`).
let v_VERIFY_FAIL_WINDOW_SECS: u64 = mk_u64 60

/// How many failed proofs that window allows.
let v_VERIFY_FAIL_LIMIT: u64 = mk_u64 5

/// The TTL of a device's tracked-JTI set (`rate_limit::SESSION_HARD_CAP_SECS`).
let v_JTI_SET_TTL_SECS: u64 = (mk_u64 8 *! mk_u64 60 <: u64) *! mk_u64 60

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
  | SqlStmt_SelectUnrevokedDeviceById { f_device_id:Alloc.String.t_String }: t_SqlStmt
  | SqlStmt_UpdateDeviceLastActive {
    f_now:Alloc.String.t_String;
    f_device_id:Alloc.String.t_String
  }: t_SqlStmt
  | SqlStmt_UpdateDeviceLastActiveNamed {
    f_now:Alloc.String.t_String;
    f_name:Alloc.String.t_String;
    f_kind:Alloc.String.t_String;
    f_device_id:Alloc.String.t_String
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
  | StoreStmt_Take { f_key:Alloc.String.t_String }: t_StoreStmt
  | StoreStmt_Incr {
    f_key:Alloc.String.t_String;
    f_limit:u64;
    f_ttl:u64
  }: t_StoreStmt
  | StoreStmt_BackoffFailure {
    f_streak:Alloc.String.t_String;
    f_backoff:Alloc.String.t_String
  }: t_StoreStmt
  | StoreStmt_ResetBackoff {
    f_streak:Alloc.String.t_String;
    f_backoff:Alloc.String.t_String
  }: t_StoreStmt
  | StoreStmt_AddMember {
    f_key:Alloc.String.t_String;
    f_member:Alloc.String.t_String;
    f_ttl:u64
  }: t_StoreStmt

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

/// What the atomic challenge take returned: the stored value it removed, or
/// the `get_del` error.
type t_TakeOutcome =
  | TakeOutcome_Taken : Core_models.Option.t_Option Alloc.String.t_String -> t_TakeOutcome
  | TakeOutcome_Failed : t_TakeOutcome

/// What the unrevoked-device lookup returned, after decoding.
type t_DeviceReadOutcome =
  | DeviceReadOutcome_Row : t_DeviceReadOutcome
  | DeviceReadOutcome_Undecodable : t_DeviceReadOutcome
  | DeviceReadOutcome_Missing : t_DeviceReadOutcome
  | DeviceReadOutcome_Failed : t_DeviceReadOutcome

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

/// `VerifyIo::consume_challenge`: remove the one challenge key.
let plan_take_challenge (challenge: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:Alloc.String.t_String = challenge <: Alloc.String.t_String in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_Take
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["challenge:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String)
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `VerifyIo::observe_device`.
let plan_login_device (device_id: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_SelectUnrevokedDeviceById ({ f_device_id = device_id }) <: t_SqlStmt

/// `VerifyIo::record_verification_failure`: the log-only exponential-backoff
/// record for the request's `(ip, device)` scope.
let plan_backoff_record (ip device: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:(Alloc.String.t_String & Alloc.String.t_String) =
    ip, device <: (Alloc.String.t_String & Alloc.String.t_String)
  in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
    let list =
      [
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._1;
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._2
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
    Rust_primitives.Hax.array_of_list 2 list
  in
  let args:(Alloc.String.t_String & Alloc.String.t_String) =
    ip, device <: (Alloc.String.t_String & Alloc.String.t_String)
  in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
    let list =
      [
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._1;
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._2
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
    Rust_primitives.Hax.array_of_list 2 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_BackoffFailure
            ({
                f_streak
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                          (mk_usize 2)
                          (let list = ["rl:streak:verify:"; ":"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                            Rust_primitives.Hax.array_of_list 2 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_backoff
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                          (mk_usize 2)
                          (let list = ["rl:backoff:verify:"; ":"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                            Rust_primitives.Hax.array_of_list 2 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String)
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `VerifyIo::record_verification_failure`: the request-level failed-proof
/// counter, whose refusal is the only failure the driver propagates.
let plan_failure_counter (ip device: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:(Alloc.String.t_String & Alloc.String.t_String) =
    ip, device <: (Alloc.String.t_String & Alloc.String.t_String)
  in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
    let list =
      [
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._1;
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._2
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
    Rust_primitives.Hax.array_of_list 2 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_Incr
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                          (mk_usize 2)
                          (let list = ["rl:verify:fail:dev:"; ":"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                            Rust_primitives.Hax.array_of_list 2 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_limit = v_VERIFY_FAIL_LIMIT;
                f_ttl = v_VERIFY_FAIL_WINDOW_SECS
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `VerifyIo::reset_backoff`: drop the success streak and backoff marker.
let plan_reset_login_streak (ip device: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:(Alloc.String.t_String & Alloc.String.t_String) =
    ip, device <: (Alloc.String.t_String & Alloc.String.t_String)
  in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
    let list =
      [
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._1;
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._2
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
    Rust_primitives.Hax.array_of_list 2 list
  in
  let args:(Alloc.String.t_String & Alloc.String.t_String) =
    ip, device <: (Alloc.String.t_String & Alloc.String.t_String)
  in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
    let list =
      [
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._1;
        Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args._2
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
    Rust_primitives.Hax.array_of_list 2 list
  in
  Alloc.Slice.impl__into_vec #t_StoreStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            StoreStmt_ResetBackoff
            ({
                f_streak
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                          (mk_usize 2)
                          (let list = ["rl:streak:verify:"; ":"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                            Rust_primitives.Hax.array_of_list 2 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_backoff
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                          (mk_usize 2)
                          (let list = ["rl:backoff:verify:"; ":"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                            Rust_primitives.Hax.array_of_list 2 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String)
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `VerifyIo::reset_backoff`: the historical best-effort `last_active` stamp,
/// with the device's own name and type when the request did not rename it.
let plan_login_last_active
      (device_id now: Alloc.String.t_String)
      (name kind: Core_models.Option.t_Option Alloc.String.t_String)
    : t_SqlStmt =
  match
    name, kind
    <:
    (Core_models.Option.t_Option Alloc.String.t_String &
      Core_models.Option.t_Option Alloc.String.t_String)
  with
  | Core_models.Option.Option_Some name, Core_models.Option.Option_Some kind ->
    SqlStmt_UpdateDeviceLastActiveNamed
    ({ f_now = now; f_name = name; f_kind = kind; f_device_id = device_id })
    <:
    t_SqlStmt
  | _ -> SqlStmt_UpdateDeviceLastActive ({ f_now = now; f_device_id = device_id }) <: t_SqlStmt

/// `VerifyIo::track_token`: register the issued JTI against the device.
let plan_track_jti (device jti: Alloc.String.t_String)
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
            StoreStmt_AddMember
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["device:jtis:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_member = jti;
                f_ttl = v_JTI_SET_TTL_SECS
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

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

/// The atomic challenge take: `StorageFailed` exactly when the take failed;
/// otherwise the observation is the exact match of the value it removed
/// against the tag this consumer expected. A present but different value (or
/// an unrecognized one) is spent and reported as the wrong purpose.
let classify_login_challenge (outcome: t_TakeOutcome) (expected_tag: Alloc.String.t_String)
    : Vela_session_policy.Login_driver.t_ChallengeObservation =
  match outcome <: t_TakeOutcome with
  | TakeOutcome_Taken (Core_models.Option.Option_Some value) ->
    if value =. expected_tag
    then
      Vela_session_policy.Login_driver.ChallengeObservation_Observed
      (Vela_session_policy.Challenge.ChallengeConsumption_Accepted
        <:
        Vela_session_policy.Challenge.t_ChallengeConsumption)
      <:
      Vela_session_policy.Login_driver.t_ChallengeObservation
    else
      Vela_session_policy.Login_driver.ChallengeObservation_Observed
      (Vela_session_policy.Challenge.ChallengeConsumption_WrongPurpose
        <:
        Vela_session_policy.Challenge.t_ChallengeConsumption)
      <:
      Vela_session_policy.Login_driver.t_ChallengeObservation
  | TakeOutcome_Taken (Core_models.Option.Option_None ) ->
    Vela_session_policy.Login_driver.ChallengeObservation_Observed
    (Vela_session_policy.Challenge.ChallengeConsumption_Missing
      <:
      Vela_session_policy.Challenge.t_ChallengeConsumption)
    <:
    Vela_session_policy.Login_driver.t_ChallengeObservation
  | TakeOutcome_Failed  ->
    Vela_session_policy.Login_driver.ChallengeObservation_StorageFailed
    <:
    Vela_session_policy.Login_driver.t_ChallengeObservation

/// The unrevoked-device lookup: the observation names exactly what the query
/// and decoder produced.
let classify_login_device (outcome: t_DeviceReadOutcome)
    : Vela_session_policy.Login_driver.t_DeviceObservation =
  match outcome <: t_DeviceReadOutcome with
  | DeviceReadOutcome_Row  ->
    Vela_session_policy.Login_driver.DeviceObservation_Present
    <:
    Vela_session_policy.Login_driver.t_DeviceObservation
  | DeviceReadOutcome_Undecodable  ->
    Vela_session_policy.Login_driver.DeviceObservation_ParseFailed
    <:
    Vela_session_policy.Login_driver.t_DeviceObservation
  | DeviceReadOutcome_Missing  ->
    Vela_session_policy.Login_driver.DeviceObservation_Absent
    <:
    Vela_session_policy.Login_driver.t_DeviceObservation
  | DeviceReadOutcome_Failed  ->
    Vela_session_policy.Login_driver.DeviceObservation_QueryFailed
    <:
    Vela_session_policy.Login_driver.t_DeviceObservation

/// The failed-proof side effects: only the request-level counter's refusal is
/// reported; the log-only backoff record cannot change the observation.
let classify_failure_counter (outcomes: t_Slice t_StoreOutcome)
    : Vela_session_policy.Login_driver.t_FailureRecordObservation =
  let fallback_counter_ok:bool =
    (Core_models.Slice.impl__len #t_StoreOutcome outcomes <: usize) =. mk_usize 1 &&
    (match outcomes.[ mk_usize 0 ] <: t_StoreOutcome with
      | StoreOutcome_Applied  -> true
      | StoreOutcome_Failed  -> false)
  in
  { Vela_session_policy.Login_driver.f_fallback_counter_ok = fallback_counter_ok }
  <:
  Vela_session_policy.Login_driver.t_FailureRecordObservation

/// The success-streak reset: `Reset` exactly when its one statement ran.
let classify_backoff_reset (outcome: t_StoreOutcome)
    : Vela_session_policy.Login_driver.t_BackoffResetObservation =
  match outcome <: t_StoreOutcome with
  | StoreOutcome_Applied  ->
    Vela_session_policy.Login_driver.BackoffResetObservation_Reset
    <:
    Vela_session_policy.Login_driver.t_BackoffResetObservation
  | StoreOutcome_Failed  ->
    Vela_session_policy.Login_driver.BackoffResetObservation_StorageFailed
    <:
    Vela_session_policy.Login_driver.t_BackoffResetObservation

/// JTI tracking: `Tracked` exactly when the set add ran.
let classify_track_jti (outcome: t_StoreOutcome)
    : Vela_session_policy.Login_driver.t_TokenTrackObservation =
  match outcome <: t_StoreOutcome with
  | StoreOutcome_Applied  ->
    Vela_session_policy.Login_driver.TokenTrackObservation_Tracked
    <:
    Vela_session_policy.Login_driver.t_TokenTrackObservation
  | StoreOutcome_Failed  ->
    Vela_session_policy.Login_driver.TokenTrackObservation_Failed
    <:
    Vela_session_policy.Login_driver.t_TokenTrackObservation
