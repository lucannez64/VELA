module Vela_enrollment_policy.Executor
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// One statement an executor may run. Field names follow the bound parameters
/// (SQL) or the stored record (store); [`render`] fixes their order and text.
type t_PairingStmt =
  | PairingStmt_StorePackage {
    f_token:Alloc.String.t_String;
    f_ciphertext:Alloc.String.t_String
  }: t_PairingStmt
  | PairingStmt_TakePackage { f_token:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_StoreGrant {
    f_grant_id:Alloc.String.t_String;
    f_user_id:Alloc.String.t_String;
    f_device_id:Alloc.String.t_String
  }: t_PairingStmt
  | PairingStmt_ClaimExists { f_grant_id:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_WriteClaim {
    f_grant_id:Alloc.String.t_String;
    f_hybrid_ek:Alloc.String.t_String;
    f_hybrid_vk:Alloc.String.t_String;
    f_device_name:Core_models.Option.t_Option Alloc.String.t_String;
    f_device_type:Core_models.Option.t_Option Alloc.String.t_String
  }: t_PairingStmt
  | PairingStmt_ReadClaim { f_grant_id:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_SelectAccount { f_user_id:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_SelectOpener {
    f_device_id:Alloc.String.t_String;
    f_user_id:Alloc.String.t_String
  }: t_PairingStmt
  | PairingStmt_TakeCeremony { f_grant_id:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_InsertCompletionDevice {
    f_new_device_id:Alloc.String.t_String;
    f_user_id:Alloc.String.t_String;
    f_device_name:Alloc.String.t_String;
    f_device_type:Alloc.String.t_String;
    f_hybrid_ek:Alloc.String.t_String;
    f_hybrid_vk:Alloc.String.t_String;
    f_enrolled_by:Alloc.String.t_String;
    f_grant_id:Alloc.String.t_String;
    f_rms_capsule:Alloc.String.t_String;
    f_now:Alloc.String.t_String;
    f_guard_user:Alloc.String.t_String;
    f_guard_epoch:i64
  }: t_PairingStmt
  | PairingStmt_StoreResult {
    f_grant_id:Alloc.String.t_String;
    f_device_id:Alloc.String.t_String;
    f_hybrid_vk:Alloc.String.t_String
  }: t_PairingStmt
  | PairingStmt_ReadResult { f_grant_id:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_SelectDeviceByGrant { f_grant_id:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_SelectActiveDevice { f_device_id:Alloc.String.t_String }: t_PairingStmt
  | PairingStmt_InsertEnrollDevice {
    f_new_device_id:Alloc.String.t_String;
    f_user_id:Alloc.String.t_String;
    f_device_name:Alloc.String.t_String;
    f_device_type:Alloc.String.t_String;
    f_hybrid_ek:Alloc.String.t_String;
    f_hybrid_vk:Alloc.String.t_String;
    f_enrolled_by:Alloc.String.t_String;
    f_rms_capsule:Alloc.String.t_String;
    f_now:Alloc.String.t_String;
    f_guard_user:Alloc.String.t_String;
    f_guard_epoch:i64
  }: t_PairingStmt
  | PairingStmt_TakeChallenge { f_challenge:Alloc.String.t_String }: t_PairingStmt

/// What one write statement returned.
type t_WriteOutcome =
  | WriteOutcome_Applied : u64 -> t_WriteOutcome
  | WriteOutcome_Inserted : t_WriteOutcome
  | WriteOutcome_GuardMissing : t_WriteOutcome
  | WriteOutcome_KeyExists : t_WriteOutcome
  | WriteOutcome_Failed : t_WriteOutcome

/// What one destructive read (`get_del`, `take_live_pair`) returned.
type t_TakeOutcome =
  | TakeOutcome_Failed : t_TakeOutcome
  | TakeOutcome_Missing : t_TakeOutcome
  | TakeOutcome_Present : t_TakeOutcome

/// The cells of a `claim` record after JSON decoding. Decoding itself is
/// trusted (serde, checked by the unit tests and the conformance test).
type t_ClaimRowView = {
  f_hybrid_ek:Core_models.Option.t_Option Alloc.String.t_String;
  f_hybrid_vk:Core_models.Option.t_Option Alloc.String.t_String;
  f_device_name:Core_models.Option.t_Option Alloc.String.t_String;
  f_device_type:Core_models.Option.t_Option Alloc.String.t_String
}

/// The cells of an `EnrollmentResult` record after JSON decoding.
type t_ResultRowView = {
  f_device_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_hybrid_vk:Core_models.Option.t_Option Alloc.String.t_String
}

/// The cells of a `users` row the completion preflight reads:
/// `key_epoch` and `rekey_state`.
type t_AccountRowView = {
  f_key_epoch:Core_models.Option.t_Option i64;
  f_rekey_state:Core_models.Option.t_Option Alloc.String.t_String
}

/// The cells of a `devices` row the reads and the hinge use.
type t_DeviceRowView = {
  f_device_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_hybrid_vk:Core_models.Option.t_Option Alloc.String.t_String;
  f_revoked:Core_models.Option.t_Option i64;
  f_user_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_enrollment_grant_id:Core_models.Option.t_Option Alloc.String.t_String
}

/// What one read statement returned: its first row (decoded), no row, a row
/// the handler could not decode, or an error.
type t_ReadOutcome =
  | ReadOutcome_Failed : t_ReadOutcome
  | ReadOutcome_Undecodable : t_ReadOutcome
  | ReadOutcome_Account : Core_models.Option.t_Option t_AccountRowView -> t_ReadOutcome
  | ReadOutcome_Device : Core_models.Option.t_Option t_DeviceRowView -> t_ReadOutcome
  | ReadOutcome_Opener : Core_models.Option.t_Option t_DeviceRowView -> t_ReadOutcome
  | ReadOutcome_DeviceByGrant : Core_models.Option.t_Option t_DeviceRowView -> t_ReadOutcome
  | ReadOutcome_ActiveDevice : Core_models.Option.t_Option t_DeviceRowView -> t_ReadOutcome
  | ReadOutcome_ClaimExists : bool -> t_ReadOutcome
  | ReadOutcome_Claim : Core_models.Option.t_Option t_ClaimRowView -> t_ReadOutcome
  | ReadOutcome_Result : Core_models.Option.t_Option t_ResultRowView -> t_ReadOutcome

/// Verdicts the handler computes from a request and a stored row (base64 and
/// JSON decoding, the hybrid signature checks, the rekey policy). They are
/// inputs here: crypto and request decoding stay outside the store model.
type t_CompletionVerdicts = {
  f_claim_keys_usable:bool;
  f_capsule_valid:bool;
  f_signature_field_valid:bool;
  f_opener_key_decodes:bool;
  f_signature_verified:bool;
  f_account_epoch:i64;
  f_declared_epoch:i64;
  f_rotation_in_progress:bool;
  f_account_epoch_active:bool
}

/// The enrollment device read's request verdicts.
type t_EnrollAuthVerdict =
  | EnrollAuthVerdict_Verified : t_EnrollAuthVerdict
  | EnrollAuthVerdict_MalformedChallenge : t_EnrollAuthVerdict
  | EnrollAuthVerdict_Rejected : t_EnrollAuthVerdict

/// The result collector's key and signature verdicts.
type t_CollectorVerdicts = {
  f_key_decodes:bool;
  f_key_len:usize;
  f_signature_verified:bool
}

/// `StorePackageIo::store_package`.
let plan_store_package (token ciphertext: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            PairingStmt_StorePackage ({ f_token = token; f_ciphertext = ciphertext })
            <:
            t_PairingStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `RedeemPackageIo::redeem_package`.
let plan_redeem_package (token: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_TakePackage ({ f_token = token }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `OpenGrantIo::store_grant`.
let plan_store_grant (grant_id user_id device_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            PairingStmt_StoreGrant
            ({ f_grant_id = grant_id; f_user_id = user_id; f_device_id = device_id })
            <:
            t_PairingStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `ClaimIo::check_claim`: read whether a claim already exists.
let plan_claim_check (grant_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_ClaimExists ({ f_grant_id = grant_id }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `ClaimIo::write_claim`: the guarded first-writer-wins write.
let plan_claim_write
      (grant_id hybrid_ek hybrid_vk: Alloc.String.t_String)
      (device_name device_type: Core_models.Option.t_Option Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            PairingStmt_WriteClaim
            ({
                f_grant_id = grant_id;
                f_hybrid_ek = hybrid_ek;
                f_hybrid_vk = hybrid_vk;
                f_device_name = device_name;
                f_device_type = device_type
              })
            <:
            t_PairingStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `CompleteIo::check_account`: the account epoch and rekey state.
let plan_account_read (user_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_SelectAccount ({ f_user_id = user_id }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `CompleteIo::prepare_completion`: the stored claim, then the opener row.
let plan_completion_preflight (grant_id device_id user_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            PairingStmt_ReadClaim ({ f_grant_id = grant_id }) <: t_PairingStmt;
            PairingStmt_SelectOpener ({ f_device_id = device_id; f_user_id = user_id })
            <:
            t_PairingStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
        Rust_primitives.Hax.array_of_list 2 list)
      <:
      t_Slice t_PairingStmt)

/// `CompleteIo::take_ceremony`: consume the grant and claim together.
let plan_take_ceremony (grant_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_TakeCeremony ({ f_grant_id = grant_id }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `CompleteIo::insert_device`: the guarded insert from the stored claim.
let plan_completion_insert
      (new_device_id user_id device_name device_type hybrid_ek hybrid_vk enrolled_by grant_id rms_capsule now guard_user:
          Alloc.String.t_String)
      (guard_epoch: i64)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            PairingStmt_InsertCompletionDevice
            ({
                f_new_device_id = new_device_id;
                f_user_id = user_id;
                f_device_name = device_name;
                f_device_type = device_type;
                f_hybrid_ek = hybrid_ek;
                f_hybrid_vk = hybrid_vk;
                f_enrolled_by = enrolled_by;
                f_grant_id = grant_id;
                f_rms_capsule = rms_capsule;
                f_now = now;
                f_guard_user = guard_user;
                f_guard_epoch = guard_epoch
              })
            <:
            t_PairingStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `CompleteIo::write_result`: the result record, after the row exists.
let plan_result_write (grant_id device_id hybrid_vk: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            PairingStmt_StoreResult
            ({ f_grant_id = grant_id; f_device_id = device_id; f_hybrid_vk = hybrid_vk })
            <:
            t_PairingStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `ResultIo::read_result`.
let plan_result_read (grant_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_ReadResult ({ f_grant_id = grant_id }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `ResultIo::read_claim`.
let plan_claim_read (grant_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_ReadClaim ({ f_grant_id = grant_id }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `ResultIo::read_enrolled_device` (U-20 fallback).
let plan_device_by_grant (grant_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_SelectDeviceByGrant ({ f_grant_id = grant_id }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `EnrollIo::check_device`.
let plan_active_device_read (device_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_SelectActiveDevice ({ f_device_id = device_id }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `EnrollIo::insert_device`.
let plan_enroll_insert
      (new_device_id user_id device_name device_type hybrid_ek hybrid_vk enrolled_by rms_capsule now guard_user:
          Alloc.String.t_String)
      (guard_epoch: i64)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            PairingStmt_InsertEnrollDevice
            ({
                f_new_device_id = new_device_id;
                f_user_id = user_id;
                f_device_name = device_name;
                f_device_type = device_type;
                f_hybrid_ek = hybrid_ek;
                f_hybrid_vk = hybrid_vk;
                f_enrolled_by = enrolled_by;
                f_rms_capsule = rms_capsule;
                f_now = now;
                f_guard_user = guard_user;
                f_guard_epoch = guard_epoch
              })
            <:
            t_PairingStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// `EnrollIo::consume_challenge`.
let plan_challenge_take (challenge: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_PairingStmt
    #Alloc.Alloc.t_Global
    ((let list = [PairingStmt_TakeChallenge ({ f_challenge = challenge }) <: t_PairingStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_PairingStmt)

/// A single unconditional store write: stored exactly when it ran.
let classify_store (outcomes: t_Slice t_WriteOutcome)
    : Vela_enrollment_policy.Pairing_driver.t_StoreObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied _ ->
      Vela_enrollment_policy.Pairing_driver.StoreObservation_Stored
      <:
      Vela_enrollment_policy.Pairing_driver.t_StoreObservation
    | _ ->
      Vela_enrollment_policy.Pairing_driver.StoreObservation_Failed
      <:
      Vela_enrollment_policy.Pairing_driver.t_StoreObservation
  else
    Vela_enrollment_policy.Pairing_driver.StoreObservation_Failed
    <:
    Vela_enrollment_policy.Pairing_driver.t_StoreObservation

/// The destructive package read. A present value is handed out; a failure and
/// a miss are both the historical "not found" observation.
let classify_redeem (outcome: t_TakeOutcome) (utf8_valid: bool)
    : Vela_enrollment_policy.Pairing_driver.t_RedeemObservation =
  match outcome <: t_TakeOutcome with
  | TakeOutcome_Present  ->
    Vela_enrollment_policy.Pairing_driver.RedeemObservation_Present
    ({ Vela_enrollment_policy.Pairing_driver.f_utf8_valid = utf8_valid })
    <:
    Vela_enrollment_policy.Pairing_driver.t_RedeemObservation
  | _ ->
    Vela_enrollment_policy.Pairing_driver.RedeemObservation_Missing
    <:
    Vela_enrollment_policy.Pairing_driver.t_RedeemObservation

/// The challenge take: accepted exactly when the key was present, removed,
/// and its stored purpose tag matched the endpoint's purpose.
let classify_challenge_take (outcome: t_TakeOutcome) (purpose_matches: bool) : bool =
  match outcome <: t_TakeOutcome with
  | TakeOutcome_Present  -> purpose_matches
  | _ -> false

/// The claim existence read. A failed read (or a plan that ran no read) gives
/// the historical rejecting observation with zero lengths.
let classify_claim_check (grant_live: bool) (ek_len vk_len: usize) (outcomes: t_Slice t_ReadOutcome)
    : Vela_enrollment_policy.t_ClaimObservation =
  let (claim_exists: bool), (ek_len: usize), (vk_len: usize) =
    if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) =. mk_usize 1
    then
      match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
      | ReadOutcome_ClaimExists v_exists -> v_exists, ek_len, vk_len <: (bool & usize & usize)
      | _ -> false, mk_usize 0, mk_usize 0 <: (bool & usize & usize)
    else false, mk_usize 0, mk_usize 0 <: (bool & usize & usize)
  in
  {
    Vela_enrollment_policy.f_grant_live = grant_live;
    Vela_enrollment_policy.f_claim_exists = claim_exists;
    Vela_enrollment_policy.f_hybrid_ek_len = ek_len;
    Vela_enrollment_policy.f_hybrid_vk_len = vk_len
  }
  <:
  Vela_enrollment_policy.t_ClaimObservation

/// The guarded claim write.
let classify_claim_write (outcomes: t_Slice t_WriteOutcome)
    : Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Inserted  ->
      Vela_enrollment_policy.Pairing_driver.ClaimWriteObservation_Inserted
      <:
      Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation
    | WriteOutcome_KeyExists  ->
      Vela_enrollment_policy.Pairing_driver.ClaimWriteObservation_KeyExists
      <:
      Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation
    | _ ->
      Vela_enrollment_policy.Pairing_driver.ClaimWriteObservation_GuardMissing
      <:
      Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation
  else
    Vela_enrollment_policy.Pairing_driver.ClaimWriteObservation_GuardMissing
    <:
    Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation

/// The account preflight's observation`; its row-derived fields (epoch and
/// rotation) are read separately by [`account_fields`].
let classify_account
      (outcomes: t_Slice t_ReadOutcome)
      (declared_epoch_positive rekey_permitted: bool)
    : Vela_enrollment_policy.Pairing_driver.t_CompletionAccountObservation =
  let ok:bool =
    (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) =. mk_usize 1 &&
    (match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
      | ReadOutcome_Account _ -> true
      | _ -> false)
  in
  {
    Vela_enrollment_policy.Pairing_driver.f_account_query_ok = ok;
    Vela_enrollment_policy.Pairing_driver.f_declared_epoch_positive = declared_epoch_positive;
    Vela_enrollment_policy.Pairing_driver.f_rekey_permitted = rekey_permitted
  }
  <:
  Vela_enrollment_policy.Pairing_driver.t_CompletionAccountObservation

/// The account row's truth as the completion driver consumes it: the stored
/// `key_epoch` (0 when absent or unread) and whether a rotation is recorded.
let account_fields (outcomes: t_Slice t_ReadOutcome) : (i64 & bool) =
  if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
    | ReadOutcome_Account (Core_models.Option.Option_Some row) ->
      Core_models.Option.impl__unwrap_or #i64 row.f_key_epoch (mk_i64 0),
      Core_models.Option.impl__is_some #Alloc.String.t_String row.f_rekey_state
      <:
      (i64 & bool)
    | _ -> mk_i64 0, false <: (i64 & bool)
  else mk_i64 0, false <: (i64 & bool)

/// The completion preflight. The stored claim decides `Usable`/`Missing`/
/// `Error`; the opener row decides `Active`/`Inactive`/`Error`; a failed claim
/// read short-circuits the historical observation (the opener read never ran).
let classify_completion_preflight (outcomes: t_Slice t_ReadOutcome) (verdicts: t_CompletionVerdicts)
    : Vela_enrollment_policy.Pairing_driver.t_CompletionPreflightObservation =
  if
    (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) >. mk_usize 0 &&
    (match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
      | ReadOutcome_Failed  -> true
      | _ -> false)
  then
    {
      Vela_enrollment_policy.Pairing_driver.f_claim
      =
      Vela_enrollment_policy.Pairing_driver.ClaimMaterialObservation_Error
      <:
      Vela_enrollment_policy.Pairing_driver.t_ClaimMaterialObservation;
      Vela_enrollment_policy.Pairing_driver.f_capsule_valid = false;
      Vela_enrollment_policy.Pairing_driver.f_signature_field_valid = false;
      Vela_enrollment_policy.Pairing_driver.f_opener
      =
      Vela_enrollment_policy.Pairing_driver.OpenerObservation_Inactive
      <:
      Vela_enrollment_policy.Pairing_driver.t_OpenerObservation;
      Vela_enrollment_policy.Pairing_driver.f_signature
      =
      Vela_enrollment_policy.Pairing_driver.SignatureObservation_Failed
      <:
      Vela_enrollment_policy.Pairing_driver.t_SignatureObservation;
      Vela_enrollment_policy.Pairing_driver.f_account_epoch = verdicts.f_account_epoch;
      Vela_enrollment_policy.Pairing_driver.f_declared_epoch = verdicts.f_declared_epoch;
      Vela_enrollment_policy.Pairing_driver.f_rotation_in_progress = verdicts.f_rotation_in_progress;
      Vela_enrollment_policy.Pairing_driver.f_account_epoch_active = verdicts.f_account_epoch_active
    }
    <:
    Vela_enrollment_policy.Pairing_driver.t_CompletionPreflightObservation
  else
    let claim:Vela_enrollment_policy.Pairing_driver.t_ClaimMaterialObservation =
      if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) >. mk_usize 0
      then
        match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
        | ReadOutcome_Claim (Core_models.Option.Option_Some _) ->
          if verdicts.f_claim_keys_usable
          then
            Vela_enrollment_policy.Pairing_driver.ClaimMaterialObservation_Usable
            <:
            Vela_enrollment_policy.Pairing_driver.t_ClaimMaterialObservation
          else
            Vela_enrollment_policy.Pairing_driver.ClaimMaterialObservation_Error
            <:
            Vela_enrollment_policy.Pairing_driver.t_ClaimMaterialObservation
        | ReadOutcome_Claim (Core_models.Option.Option_None ) ->
          Vela_enrollment_policy.Pairing_driver.ClaimMaterialObservation_Missing
          <:
          Vela_enrollment_policy.Pairing_driver.t_ClaimMaterialObservation
        | _ ->
          Vela_enrollment_policy.Pairing_driver.ClaimMaterialObservation_Error
          <:
          Vela_enrollment_policy.Pairing_driver.t_ClaimMaterialObservation
      else
        Vela_enrollment_policy.Pairing_driver.ClaimMaterialObservation_Error
        <:
        Vela_enrollment_policy.Pairing_driver.t_ClaimMaterialObservation
    in
    let opener:Vela_enrollment_policy.Pairing_driver.t_OpenerObservation =
      if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) >. mk_usize 1
      then
        match outcomes.[ mk_usize 1 ] <: t_ReadOutcome with
        | ReadOutcome_Opener (Core_models.Option.Option_None ) ->
          Vela_enrollment_policy.Pairing_driver.OpenerObservation_Inactive
          <:
          Vela_enrollment_policy.Pairing_driver.t_OpenerObservation
        | ReadOutcome_Opener (Core_models.Option.Option_Some row) ->
          (match row.f_revoked <: Core_models.Option.t_Option i64 with
            | Core_models.Option.Option_Some (Rust_primitives.Integers.MkInt 0) ->
              if
                Core_models.Option.impl__is_some #Alloc.String.t_String row.f_hybrid_vk &&
                verdicts.f_opener_key_decodes
              then
                Vela_enrollment_policy.Pairing_driver.OpenerObservation_Active
                <:
                Vela_enrollment_policy.Pairing_driver.t_OpenerObservation
              else
                Vela_enrollment_policy.Pairing_driver.OpenerObservation_Error
                <:
                Vela_enrollment_policy.Pairing_driver.t_OpenerObservation
            | _ ->
              Vela_enrollment_policy.Pairing_driver.OpenerObservation_Inactive
              <:
              Vela_enrollment_policy.Pairing_driver.t_OpenerObservation)
        | _ ->
          Vela_enrollment_policy.Pairing_driver.OpenerObservation_Error
          <:
          Vela_enrollment_policy.Pairing_driver.t_OpenerObservation
      else
        Vela_enrollment_policy.Pairing_driver.OpenerObservation_Error
        <:
        Vela_enrollment_policy.Pairing_driver.t_OpenerObservation
    in
    let signature:Vela_enrollment_policy.Pairing_driver.t_SignatureObservation =
      if verdicts.f_signature_verified
      then
        Vela_enrollment_policy.Pairing_driver.SignatureObservation_Verified
        <:
        Vela_enrollment_policy.Pairing_driver.t_SignatureObservation
      else
        Vela_enrollment_policy.Pairing_driver.SignatureObservation_Failed
        <:
        Vela_enrollment_policy.Pairing_driver.t_SignatureObservation
    in
    {
      Vela_enrollment_policy.Pairing_driver.f_claim = claim;
      Vela_enrollment_policy.Pairing_driver.f_capsule_valid = verdicts.f_capsule_valid;
      Vela_enrollment_policy.Pairing_driver.f_signature_field_valid
      =
      verdicts.f_signature_field_valid;
      Vela_enrollment_policy.Pairing_driver.f_opener = opener;
      Vela_enrollment_policy.Pairing_driver.f_signature = signature;
      Vela_enrollment_policy.Pairing_driver.f_account_epoch = verdicts.f_account_epoch;
      Vela_enrollment_policy.Pairing_driver.f_declared_epoch = verdicts.f_declared_epoch;
      Vela_enrollment_policy.Pairing_driver.f_rotation_in_progress = verdicts.f_rotation_in_progress;
      Vela_enrollment_policy.Pairing_driver.f_account_epoch_active = verdicts.f_account_epoch_active
    }
    <:
    Vela_enrollment_policy.Pairing_driver.t_CompletionPreflightObservation

/// The ceremony take. The two match verdicts are the executor's byte
/// comparisons of the taken records with the snapshot it validated.
let classify_take_ceremony (outcomes: t_Slice t_TakeOutcome) (grant_matches claim_matches: bool)
    : Vela_enrollment_policy.Pairing_driver.t_TakeObservation =
  if (Core_models.Slice.impl__len #t_TakeOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_TakeOutcome with
    | TakeOutcome_Present  ->
      Vela_enrollment_policy.Pairing_driver.TakeObservation_Taken
      ({
          Vela_enrollment_policy.Pairing_driver.f_grant_matches = grant_matches;
          Vela_enrollment_policy.Pairing_driver.f_claim_matches = claim_matches
        })
      <:
      Vela_enrollment_policy.Pairing_driver.t_TakeObservation
    | _ ->
      Vela_enrollment_policy.Pairing_driver.TakeObservation_Missing
      <:
      Vela_enrollment_policy.Pairing_driver.t_TakeObservation
  else
    Vela_enrollment_policy.Pairing_driver.TakeObservation_Missing
    <:
    Vela_enrollment_policy.Pairing_driver.t_TakeObservation

/// The completion insert.
let classify_insert_completion (outcomes: t_Slice t_WriteOutcome)
    : Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match
      (match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
        | WriteOutcome_Applied rows ->
          (match rows >. mk_u64 0 <: bool with
            | true ->
              Core_models.Option.Option_Some
              (Vela_enrollment_policy.Pairing_driver.DeviceInsertObservation_Inserted
                <:
                Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation)
              <:
              Core_models.Option.t_Option
              Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation
            | _ ->
              Core_models.Option.Option_None
              <:
              Core_models.Option.t_Option
              Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation)
        | _ ->
          Core_models.Option.Option_None
          <:
          Core_models.Option.t_Option
          Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation)
      <:
      Core_models.Option.t_Option Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation
    with
    | Core_models.Option.Option_Some x -> x
    | Core_models.Option.Option_None  ->
      match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
      | WriteOutcome_Applied _ ->
        Vela_enrollment_policy.Pairing_driver.DeviceInsertObservation_Skipped
        <:
        Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation
      | _ ->
        Vela_enrollment_policy.Pairing_driver.DeviceInsertObservation_Failed
        <:
        Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation
  else
    Vela_enrollment_policy.Pairing_driver.DeviceInsertObservation_Failed
    <:
    Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation

/// The enrollment insert. Zero rows is the epoch guard's refusal; an error is
/// a storage failure.
let classify_insert_enroll (outcomes: t_Slice t_WriteOutcome)
    : Vela_enrollment_policy.Enroll_driver.t_InsertObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match
      (match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
        | WriteOutcome_Applied rows ->
          (match rows >. mk_u64 0 <: bool with
            | true ->
              Core_models.Option.Option_Some
              (Vela_enrollment_policy.Enroll_driver.InsertObservation_Inserted
                <:
                Vela_enrollment_policy.Enroll_driver.t_InsertObservation)
              <:
              Core_models.Option.t_Option Vela_enrollment_policy.Enroll_driver.t_InsertObservation
            | _ ->
              Core_models.Option.Option_None
              <:
              Core_models.Option.t_Option Vela_enrollment_policy.Enroll_driver.t_InsertObservation)
        | _ ->
          Core_models.Option.Option_None
          <:
          Core_models.Option.t_Option Vela_enrollment_policy.Enroll_driver.t_InsertObservation)
      <:
      Core_models.Option.t_Option Vela_enrollment_policy.Enroll_driver.t_InsertObservation
    with
    | Core_models.Option.Option_Some x -> x
    | Core_models.Option.Option_None  ->
      match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
      | WriteOutcome_Applied _ ->
        Vela_enrollment_policy.Enroll_driver.InsertObservation_EpochMismatch
        <:
        Vela_enrollment_policy.Enroll_driver.t_InsertObservation
      | _ ->
        Vela_enrollment_policy.Enroll_driver.InsertObservation_Failed
        <:
        Vela_enrollment_policy.Enroll_driver.t_InsertObservation
  else
    Vela_enrollment_policy.Enroll_driver.InsertObservation_Failed
    <:
    Vela_enrollment_policy.Enroll_driver.t_InsertObservation

/// The result record's read.
let classify_result_read (outcomes: t_Slice t_ReadOutcome) (verdicts: t_CollectorVerdicts)
    : Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation =
  if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
    | ReadOutcome_Result (Core_models.Option.Option_Some _) ->
      if verdicts.f_key_decodes
      then
        Vela_enrollment_policy.Pairing_driver.ResultReadObservation_Completed
        ({
            Vela_enrollment_policy.Pairing_driver.f_claimed_key_len = verdicts.f_key_len;
            Vela_enrollment_policy.Pairing_driver.f_signature_verified
            =
            verdicts.f_signature_verified
          })
        <:
        Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation
      else
        Vela_enrollment_policy.Pairing_driver.ResultReadObservation_Unreadable
        <:
        Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation
    | ReadOutcome_Result (Core_models.Option.Option_None ) ->
      Vela_enrollment_policy.Pairing_driver.ResultReadObservation_Absent
      <:
      Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation
    | _ ->
      Vela_enrollment_policy.Pairing_driver.ResultReadObservation_Unreadable
      <:
      Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation
  else
    Vela_enrollment_policy.Pairing_driver.ResultReadObservation_Unreadable
    <:
    Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation

/// The claim record's read by the result collector.
let classify_claim_read (outcomes: t_Slice t_ReadOutcome) (verdicts: t_CollectorVerdicts)
    : Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation =
  if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
    | ReadOutcome_Claim (Core_models.Option.Option_Some _) ->
      if verdicts.f_key_decodes
      then
        Vela_enrollment_policy.Pairing_driver.ClaimReadObservation_Claimed
        ({
            Vela_enrollment_policy.Pairing_driver.f_claimed_key_len = verdicts.f_key_len;
            Vela_enrollment_policy.Pairing_driver.f_signature_verified
            =
            verdicts.f_signature_verified
          })
        <:
        Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation
      else
        Vela_enrollment_policy.Pairing_driver.ClaimReadObservation_Unreadable
        <:
        Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation
    | ReadOutcome_Claim (Core_models.Option.Option_None ) ->
      Vela_enrollment_policy.Pairing_driver.ClaimReadObservation_Absent
      <:
      Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation
    | _ ->
      Vela_enrollment_policy.Pairing_driver.ClaimReadObservation_Unreadable
      <:
      Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation
  else
    Vela_enrollment_policy.Pairing_driver.ClaimReadObservation_Unreadable
    <:
    Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation

/// The U-20 device-row fallback.
let classify_enrolled_device (outcomes: t_Slice t_ReadOutcome) (verdicts: t_CollectorVerdicts)
    : Vela_enrollment_policy.Pairing_driver.t_DeviceGrantObservation =
  if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
    | ReadOutcome_DeviceByGrant (Core_models.Option.Option_Some row) ->
      if
        Core_models.Option.impl__is_some #Alloc.String.t_String row.f_device_id &&
        Core_models.Option.impl__is_some #Alloc.String.t_String row.f_hybrid_vk &&
        verdicts.f_key_decodes
      then
        Vela_enrollment_policy.Pairing_driver.DeviceGrantObservation_Enrolled
        ({
            Vela_enrollment_policy.Pairing_driver.f_claimed_key_len = verdicts.f_key_len;
            Vela_enrollment_policy.Pairing_driver.f_signature_verified
            =
            verdicts.f_signature_verified
          })
        <:
        Vela_enrollment_policy.Pairing_driver.t_DeviceGrantObservation
      else
        Vela_enrollment_policy.Pairing_driver.DeviceGrantObservation_Unreadable
        <:
        Vela_enrollment_policy.Pairing_driver.t_DeviceGrantObservation
    | ReadOutcome_DeviceByGrant (Core_models.Option.Option_None ) ->
      Vela_enrollment_policy.Pairing_driver.DeviceGrantObservation_Absent
      <:
      Vela_enrollment_policy.Pairing_driver.t_DeviceGrantObservation
    | _ ->
      Vela_enrollment_policy.Pairing_driver.DeviceGrantObservation_Unreadable
      <:
      Vela_enrollment_policy.Pairing_driver.t_DeviceGrantObservation
  else
    Vela_enrollment_policy.Pairing_driver.DeviceGrantObservation_Unreadable
    <:
    Vela_enrollment_policy.Pairing_driver.t_DeviceGrantObservation

/// The enrollment device read.
let classify_device_check (outcomes: t_Slice t_ReadOutcome) (verdict: t_EnrollAuthVerdict)
    : Vela_enrollment_policy.Enroll_driver.t_DeviceObservation =
  if (Core_models.Slice.impl__len #t_ReadOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_ReadOutcome with
    | ReadOutcome_ActiveDevice (Core_models.Option.Option_None ) ->
      Vela_enrollment_policy.Enroll_driver.DeviceObservation_Unavailable
      <:
      Vela_enrollment_policy.Enroll_driver.t_DeviceObservation
    | ReadOutcome_ActiveDevice (Core_models.Option.Option_Some _) ->
      (match verdict <: t_EnrollAuthVerdict with
        | EnrollAuthVerdict_Verified  ->
          Vela_enrollment_policy.Enroll_driver.DeviceObservation_Verified
          <:
          Vela_enrollment_policy.Enroll_driver.t_DeviceObservation
        | EnrollAuthVerdict_MalformedChallenge  ->
          Vela_enrollment_policy.Enroll_driver.DeviceObservation_MalformedChallenge
          <:
          Vela_enrollment_policy.Enroll_driver.t_DeviceObservation
        | EnrollAuthVerdict_Rejected  ->
          Vela_enrollment_policy.Enroll_driver.DeviceObservation_AuthSignatureRejected
          <:
          Vela_enrollment_policy.Enroll_driver.t_DeviceObservation)
    | _ ->
      Vela_enrollment_policy.Enroll_driver.DeviceObservation_Error
      <:
      Vela_enrollment_policy.Enroll_driver.t_DeviceObservation
  else
    Vela_enrollment_policy.Enroll_driver.DeviceObservation_Error
    <:
    Vela_enrollment_policy.Enroll_driver.t_DeviceObservation
