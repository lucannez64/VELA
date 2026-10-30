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

/// 20 challenge issues per minute per IP (`rate_limit::challenge_by_ip`).
let v_CHALLENGE_RATE_LIMIT: u64 = mk_u64 20

/// The challenge limiter's fixed window (`rate_limit::WINDOW_SECS`).
let v_CHALLENGE_RATE_WINDOW_SECS: u64 = mk_u64 60

/// The lifetime of one issued challenge (`challenge::CHALLENGE_TTL_SECS`).
let v_CHALLENGE_TTL_SECS: u64 = mk_u64 60

/// 5 registrations per hour per IP (`account::RegisterIo`).
let v_REGISTER_RATE_LIMIT: u64 = mk_u64 5

/// The registration limiter's fixed window.
let v_REGISTER_RATE_WINDOW_SECS: u64 = mk_u64 60 *! mk_u64 60

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
  | SqlStmt_InsertUser {
    f_user:Alloc.String.t_String;
    f_now:Alloc.String.t_String;
    f_share_ek:Alloc.String.t_String;
    f_share_ek_since:Alloc.String.t_String
  }: t_SqlStmt
  | SqlStmt_InsertDevice {
    f_device:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_name:Alloc.String.t_String;
    f_kind:Alloc.String.t_String;
    f_now:Alloc.String.t_String;
    f_ek:Alloc.String.t_String;
    f_vk:Alloc.String.t_String
  }: t_SqlStmt
  | SqlStmt_CountUsers : t_SqlStmt
  | SqlStmt_InsertPendingSession {
    f_session:Alloc.String.t_String;
    f_approver:Alloc.String.t_String;
    f_poll_secret_hash:Alloc.String.t_String;
    f_ephemeral_pk:Alloc.String.t_String;
    f_web_vk:Alloc.String.t_String;
    f_link_nonce:Alloc.String.t_String;
    f_now:Alloc.String.t_String
  }: t_SqlStmt
  | SqlStmt_GrantWebSession {
    f_session:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_device:Alloc.String.t_String;
    f_mode:Alloc.String.t_String;
    f_capsule:Alloc.String.t_String;
    f_expires_at:Alloc.String.t_String;
    f_epoch:i64
  }: t_SqlStmt
  | SqlStmt_RevokeSessionById { f_session:Alloc.String.t_String }: t_SqlStmt
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
  | StoreStmt_SetExNx {
    f_key:Alloc.String.t_String;
    f_value:Alloc.String.t_String;
    f_ttl:u64
  }: t_StoreStmt
  | StoreStmt_SetExNxByte {
    f_key:Alloc.String.t_String;
    f_value:u8;
    f_ttl:u64
  }: t_StoreStmt
  | StoreStmt_Exists { f_key:Alloc.String.t_String }: t_StoreStmt

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

/// What a first-writer-wins insert (`set_ex_nx`) returned: it inserted, the
/// key was already there, or the store failed.
type t_NxOutcome =
  | NxOutcome_Inserted : t_NxOutcome
  | NxOutcome_KeyExists : t_NxOutcome
  | NxOutcome_Failed : t_NxOutcome

/// What `Store::exists` returned: the key is present, absent, or the call
/// failed.
type t_ExistsOutcome =
  | ExistsOutcome_Present : t_ExistsOutcome
  | ExistsOutcome_Absent : t_ExistsOutcome
  | ExistsOutcome_Failed : t_ExistsOutcome

/// What `SELECT COUNT(*) FROM users` returned.
type t_CountOutcome =
  | CountOutcome_Count : i64 -> t_CountOutcome
  | CountOutcome_Failed : t_CountOutcome

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

/// `ChallengeIssueIo::check_rate_limit`: the per-IP fixed window.
let plan_challenge_rate_limit (ip: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:Alloc.String.t_String = ip <: Alloc.String.t_String in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
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
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["rl:challenge:ip:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_limit = v_CHALLENGE_RATE_LIMIT;
                f_ttl = v_CHALLENGE_RATE_WINDOW_SECS
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `ChallengeIssueIo::store_nonce`: one purpose tag under the fresh nonce's
/// key, first writer wins.
let plan_store_nonce (challenge tag: Alloc.String.t_String)
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
            StoreStmt_SetExNx
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
                    Alloc.String.t_String);
                f_value = tag;
                f_ttl = v_CHALLENGE_TTL_SECS
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `RegisterIo::check_rate_limit`: the per-IP fixed window.
let plan_registration_rate_limit (ip: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global =
  let args:Alloc.String.t_String = ip <: Alloc.String.t_String in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #Alloc.String.t_String args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
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
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["rl:register:ip:"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String);
                f_limit = v_REGISTER_RATE_LIMIT;
                f_ttl = v_REGISTER_RATE_WINDOW_SECS
              })
            <:
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `RegisterIo::check_account_budget`: the account-count query.
let plan_account_count (_: Prims.unit) : t_SqlStmt = SqlStmt_CountUsers <: t_SqlStmt

/// `RegisterIo::insert_account`.
let plan_insert_account (user now share_ek share_ek_since: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_InsertUser
  ({ f_user = user; f_now = now; f_share_ek = share_ek; f_share_ek_since = share_ek_since })
  <:
  t_SqlStmt

/// `RegisterIo::insert_device`.
let plan_insert_device (device user name kind now ek vk: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_InsertDevice
  ({
      f_device = device;
      f_user = user;
      f_name = name;
      f_kind = kind;
      f_now = now;
      f_ek = ek;
      f_vk = vk
    })
  <:
  t_SqlStmt

/// `StartIo::insert_pending`: the one pending `web_sessions` row, with the
/// account the browser committed to and `user_id`/grant fields still NULL.
let plan_insert_pending
      (session approver poll_secret_hash ephemeral_pk web_vk link_nonce now: Alloc.String.t_String)
    : t_SqlStmt =
  SqlStmt_InsertPendingSession
  ({
      f_session = session;
      f_approver = approver;
      f_poll_secret_hash = poll_secret_hash;
      f_ephemeral_pk = ephemeral_pk;
      f_web_vk = web_vk;
      f_link_nonce = link_nonce;
      f_now = now
    })
  <:
  t_SqlStmt

/// `GrantIo::update_grant`: the guarded compare-and-swap that publishes the
/// grant only while the session is still pending for this approver, the
/// account is not mid-rekey at the declared epoch, and the approving device is
/// stored, owned by the account and unrevoked.
let plan_grant_update
      (session user device mode capsule expires_at: Alloc.String.t_String)
      (epoch: i64)
    : t_SqlStmt =
  SqlStmt_GrantWebSession
  ({
      f_session = session;
      f_user = user;
      f_device = device;
      f_mode = mode;
      f_capsule = capsule;
      f_expires_at = expires_at;
      f_epoch = epoch
    })
  <:
  t_SqlStmt

/// `DeleteSessionIo::record_revocation`: the audit row.
let plan_revoke_session (session: Alloc.String.t_String) : t_SqlStmt =
  SqlStmt_RevokeSessionById ({ f_session = session }) <: t_SqlStmt

/// `TokenIo::claim_token`: the one `web_session:token_issued:` marker, first
/// writer wins for the session's whole token ceiling.
let plan_token_claim (session: Alloc.String.t_String)
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
            StoreStmt_SetExNxByte
            ({
                f_key
                =
                Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["web_session:token_issued:"] in
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
            t_StoreStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_StoreStmt)

/// `TokenIo::issue_token`: the issue-time lockout re-check. It reads the
/// sentinel the delete handler and the revocation cascade write.
let plan_token_sentinel (session: Alloc.String.t_String)
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
            StoreStmt_Exists
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

/// A rate limiter: `Allowed` exactly when its one counter statement ran.
let classify_challenge_rate_limit (outcome: t_StoreOutcome)
    : Vela_session_policy.Challenge_issue_driver.t_RateLimitObservation =
  match outcome <: t_StoreOutcome with
  | StoreOutcome_Applied  ->
    Vela_session_policy.Challenge_issue_driver.RateLimitObservation_Allowed
    <:
    Vela_session_policy.Challenge_issue_driver.t_RateLimitObservation
  | StoreOutcome_Failed  ->
    Vela_session_policy.Challenge_issue_driver.RateLimitObservation_Denied
    <:
    Vela_session_policy.Challenge_issue_driver.t_RateLimitObservation

/// The first-writer-wins challenge write: `Inserted` exactly when the key was
/// absent and the write ran.
let classify_store_nonce (outcome: t_NxOutcome)
    : Vela_session_policy.Challenge_issue_driver.t_StoreObservation =
  match outcome <: t_NxOutcome with
  | NxOutcome_Inserted  ->
    Vela_session_policy.Challenge_issue_driver.StoreObservation_Inserted
    <:
    Vela_session_policy.Challenge_issue_driver.t_StoreObservation
  | NxOutcome_KeyExists  ->
    Vela_session_policy.Challenge_issue_driver.StoreObservation_KeyExists
    <:
    Vela_session_policy.Challenge_issue_driver.t_StoreObservation
  | NxOutcome_Failed  ->
    Vela_session_policy.Challenge_issue_driver.StoreObservation_Failed
    <:
    Vela_session_policy.Challenge_issue_driver.t_StoreObservation

/// The registration limiter.
let classify_registration_rate_limit (outcome: t_StoreOutcome)
    : Vela_session_policy.Registration_driver.t_RateLimitObservation =
  match outcome <: t_StoreOutcome with
  | StoreOutcome_Applied  ->
    Vela_session_policy.Registration_driver.RateLimitObservation_Allowed
    <:
    Vela_session_policy.Registration_driver.t_RateLimitObservation
  | StoreOutcome_Failed  ->
    Vela_session_policy.Registration_driver.RateLimitObservation_Denied
    <:
    Vela_session_policy.Registration_driver.t_RateLimitObservation

/// The registration transaction begin.
let classify_registration_transaction (outcome: t_WriteOutcome)
    : Vela_session_policy.Registration_driver.t_TransactionObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Registration_driver.TransactionObservation_Begun
    <:
    Vela_session_policy.Registration_driver.t_TransactionObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Registration_driver.TransactionObservation_Failed
    <:
    Vela_session_policy.Registration_driver.t_TransactionObservation

/// The registration commit.
let classify_registration_commit (outcome: t_WriteOutcome)
    : Vela_session_policy.Registration_driver.t_CommitObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Registration_driver.CommitObservation_Committed
    <:
    Vela_session_policy.Registration_driver.t_CommitObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Registration_driver.CommitObservation_Failed
    <:
    Vela_session_policy.Registration_driver.t_CommitObservation

/// The account budget: `Counted` exactly when the query ran, carrying the
/// exact number of `users` rows.
let classify_account_count (outcome: t_CountOutcome)
    : Vela_session_policy.Registration_driver.t_BudgetObservation =
  match outcome <: t_CountOutcome with
  | CountOutcome_Count count ->
    Vela_session_policy.Registration_driver.BudgetObservation_Counted
    ({ Vela_session_policy.Registration_driver.f_count = count })
    <:
    Vela_session_policy.Registration_driver.t_BudgetObservation
  | CountOutcome_Failed  ->
    Vela_session_policy.Registration_driver.BudgetObservation_QueryFailed
    <:
    Vela_session_policy.Registration_driver.t_BudgetObservation

/// One `INSERT`: `Inserted` exactly when it ran (its id was fresh).
let classify_insert (outcome: t_WriteOutcome)
    : Vela_session_policy.Registration_driver.t_InsertObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Registration_driver.InsertObservation_Inserted
    <:
    Vela_session_policy.Registration_driver.t_InsertObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Registration_driver.InsertObservation_Failed
    <:
    Vela_session_policy.Registration_driver.t_InsertObservation

/// `RegisterIo::track_token`: `Tracked` exactly when the set add ran.
let classify_registration_track (outcome: t_StoreOutcome)
    : Vela_session_policy.Registration_driver.t_TrackObservation =
  match outcome <: t_StoreOutcome with
  | StoreOutcome_Applied  ->
    Vela_session_policy.Registration_driver.TrackObservation_Tracked
    <:
    Vela_session_policy.Registration_driver.t_TrackObservation
  | StoreOutcome_Failed  ->
    Vela_session_policy.Registration_driver.TrackObservation_Failed
    <:
    Vela_session_policy.Registration_driver.t_TrackObservation

/// `StartIo::insert_pending`: `Inserted` exactly when the one statement ran
/// (its id was fresh).
let classify_start_insert (outcome: t_WriteOutcome)
    : Vela_session_policy.Websession_driver.t_StartInsertObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Websession_driver.StartInsertObservation_Inserted
    <:
    Vela_session_policy.Websession_driver.t_StartInsertObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.StartInsertObservation_Failed
    <:
    Vela_session_policy.Websession_driver.t_StartInsertObservation

/// `GrantIo::update_grant`: zero rows is the CAS conflict; a failure is the
/// storage error; one row is the grant.
let classify_grant_update (outcome: t_WriteOutcome)
    : Vela_session_policy.Websession_driver.t_GrantUpdateObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
    Vela_session_policy.Websession_driver.GrantUpdateObservation_Conflict
    <:
    Vela_session_policy.Websession_driver.t_GrantUpdateObservation
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated
    <:
    Vela_session_policy.Websession_driver.t_GrantUpdateObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.GrantUpdateObservation_Failed
    <:
    Vela_session_policy.Websession_driver.t_GrantUpdateObservation

/// `TokenIo::claim_token`: `Claimed` exactly when this call inserted the
/// marker, `AlreadyClaimed` when it was already there.
let classify_token_claim (outcome: t_NxOutcome)
    : Vela_session_policy.Websession_driver.t_TokenClaimObservation =
  match outcome <: t_NxOutcome with
  | NxOutcome_Inserted  ->
    Vela_session_policy.Websession_driver.TokenClaimObservation_Claimed
    <:
    Vela_session_policy.Websession_driver.t_TokenClaimObservation
  | NxOutcome_KeyExists  ->
    Vela_session_policy.Websession_driver.TokenClaimObservation_AlreadyClaimed
    <:
    Vela_session_policy.Websession_driver.t_TokenClaimObservation
  | NxOutcome_Failed  ->
    Vela_session_policy.Websession_driver.TokenClaimObservation_StorageFailed
    <:
    Vela_session_policy.Websession_driver.t_TokenClaimObservation

/// `TokenIo::issue_token`: `Issued` exactly when the issuer produced a token,
/// the issue-time sentinel was absent and the JTI was tracked.
let classify_token_issue (issued: bool) (sentinel: t_ExistsOutcome) (tracked: t_StoreOutcome)
    : Vela_session_policy.Websession_driver.t_TokenIssueObservation =
  if
    issued &&
    (match sentinel <: t_ExistsOutcome with
      | ExistsOutcome_Absent  -> true
      | _ -> false) &&
    (match tracked <: t_StoreOutcome with
      | StoreOutcome_Applied  -> true
      | _ -> false)
  then
    Vela_session_policy.Websession_driver.TokenIssueObservation_Issued
    <:
    Vela_session_policy.Websession_driver.t_TokenIssueObservation
  else
    Vela_session_policy.Websession_driver.TokenIssueObservation_Failed
    <:
    Vela_session_policy.Websession_driver.t_TokenIssueObservation

/// `DeleteSessionIo::lockout_session`: `Applied` exactly when the sentinel
/// write ran.
let classify_lockout_session (outcome: t_StoreOutcome)
    : Vela_session_policy.Websession_driver.t_DeleteSentinelObservation =
  match outcome <: t_StoreOutcome with
  | StoreOutcome_Applied  ->
    Vela_session_policy.Websession_driver.DeleteSentinelObservation_Applied
    <:
    Vela_session_policy.Websession_driver.t_DeleteSentinelObservation
  | StoreOutcome_Failed  ->
    Vela_session_policy.Websession_driver.DeleteSentinelObservation_StorageFailed
    <:
    Vela_session_policy.Websession_driver.t_DeleteSentinelObservation

/// `DeleteSessionIo::record_revocation`: `Updated` exactly when the audit
/// statement ran (its row count is not observed).
let classify_revoke_session (outcome: t_WriteOutcome)
    : Vela_session_policy.Websession_driver.t_DeleteRecordObservation =
  match outcome <: t_WriteOutcome with
  | WriteOutcome_Applied _ ->
    Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated
    <:
    Vela_session_policy.Websession_driver.t_DeleteRecordObservation
  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.DeleteRecordObservation_Failed
    <:
    Vela_session_policy.Websession_driver.t_DeleteRecordObservation
