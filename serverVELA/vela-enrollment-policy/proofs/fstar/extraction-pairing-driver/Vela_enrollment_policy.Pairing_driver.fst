module Vela_enrollment_policy.Pairing_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Request-level validation of a package-store request. The handler already
/// parsed the token and the ciphertext; the driver decides whether they permit
/// the write.
type t_PackageStoreObservation = {
  f_token_valid:bool;
  f_ciphertext_len_valid:bool
}

/// Request-level validation of a package-fetch request.
type t_PackageTokenObservation = { f_token_valid:bool }

/// Outcome of a non-destructive store write.
type t_StoreObservation =
  | StoreObservation_Stored : t_StoreObservation
  | StoreObservation_Failed : t_StoreObservation

/// Outcome of the destructive `get_del` package read. `Present` carries only
/// whether the removed bytes were valid UTF-8; the bytes themselves stay in
/// the handler.
type t_RedeemObservation =
  | RedeemObservation_Missing : t_RedeemObservation
  | RedeemObservation_Present { f_utf8_valid:bool }: t_RedeemObservation

/// The grant record as read by the completion handler.
type t_GrantObservation =
  | GrantObservation_Absent : t_GrantObservation
  | GrantObservation_Present {
    f_user_matches:bool;
    f_opener_matches:bool
  }: t_GrantObservation
  | GrantObservation_Error : t_GrantObservation

/// Outcome of the unauthenticated guarded claim write
/// (`set_ex_nx_if_live`).
type t_ClaimWriteObservation =
  | ClaimWriteObservation_Inserted : t_ClaimWriteObservation
  | ClaimWriteObservation_GuardMissing : t_ClaimWriteObservation
  | ClaimWriteObservation_KeyExists : t_ClaimWriteObservation

/// What the handler found under the claim key.
type t_ClaimMaterialObservation =
  | ClaimMaterialObservation_Missing : t_ClaimMaterialObservation
  | ClaimMaterialObservation_Usable : t_ClaimMaterialObservation
  | ClaimMaterialObservation_Error : t_ClaimMaterialObservation

/// The opener device row, as seen by `load_primary_key`.
type t_OpenerObservation =
  | OpenerObservation_Active : t_OpenerObservation
  | OpenerObservation_Inactive : t_OpenerObservation
  | OpenerObservation_Error : t_OpenerObservation

/// The opener's hybrid signature check over the stored claim.
type t_SignatureObservation =
  | SignatureObservation_Verified : t_SignatureObservation
  | SignatureObservation_Failed : t_SignatureObservation

/// The handler observations that feed the verified completion policy.
type t_CompletionPreflightObservation = {
  f_claim:t_ClaimMaterialObservation;
  f_capsule_valid:bool;
  f_signature_field_valid:bool;
  f_opener:t_OpenerObservation;
  f_signature:t_SignatureObservation;
  f_account_epoch:i64;
  f_declared_epoch:i64;
  f_rotation_in_progress:bool;
  f_account_epoch_active:bool
}

/// The destructive `take_live_pair` outcome. The handler compares the returned
/// bytes with the snapshot it validated; the driver sees only the equality.
type t_TakeObservation =
  | TakeObservation_Missing : t_TakeObservation
  | TakeObservation_Taken {
    f_grant_matches:bool;
    f_claim_matches:bool
  }: t_TakeObservation

/// Outcome of the guarded device insert.
type t_DeviceInsertObservation =
  | DeviceInsertObservation_Inserted : t_DeviceInsertObservation
  | DeviceInsertObservation_Skipped : t_DeviceInsertObservation
  | DeviceInsertObservation_Failed : t_DeviceInsertObservation

/// The first read of the result collector.
type t_ResultReadObservation =
  | ResultReadObservation_Completed {
    f_claimed_key_len:usize;
    f_signature_verified:bool
  }: t_ResultReadObservation
  | ResultReadObservation_Absent : t_ResultReadObservation
  | ResultReadObservation_Unreadable : t_ResultReadObservation

/// The fallback read of the result collector, when no result record exists.
type t_ClaimReadObservation =
  | ClaimReadObservation_Claimed {
    f_claimed_key_len:usize;
    f_signature_verified:bool
  }: t_ClaimReadObservation
  | ClaimReadObservation_Absent : t_ClaimReadObservation
  | ClaimReadObservation_Unreadable : t_ClaimReadObservation

/// The fallback read of the result collector, when neither a result record nor
/// a claim exists. U-20: a committed device insert whose result write was lost
/// (storage failure or a cancelled request) leaves the claim consumed and no
/// result record. The inserted row carries the grant id, so the collector can
/// still find it and answer under the same result-signature check.
type t_DeviceGrantObservation =
  | DeviceGrantObservation_Enrolled {
    f_claimed_key_len:usize;
    f_signature_verified:bool
  }: t_DeviceGrantObservation
  | DeviceGrantObservation_Absent : t_DeviceGrantObservation
  | DeviceGrantObservation_Unreadable : t_DeviceGrantObservation

/// Which ceremony this per-request driver belongs to.
type t_PairingCeremony =
  | PairingCeremony_StorePackage : t_PairingCeremony
  | PairingCeremony_RedeemPackage : t_PairingCeremony
  | PairingCeremony_OpenGrant : t_PairingCeremony
  | PairingCeremony_ClaimGrant : t_PairingCeremony
  | PairingCeremony_CompleteGrant : t_PairingCeremony
  | PairingCeremony_CollectResult : t_PairingCeremony

/// Where the ceremony is in its decision sequence. A stage names the effect
/// that has been emitted and whose observation is awaited.
type t_PairingStage =
  | PairingStage_Start : t_PairingStage
  | PairingStage_Applied : t_PairingStage
  | PairingStage_InFlight : t_PairingStage
  | PairingStage_WroteResult : t_PairingStage
  | PairingStage_ResultClaim : t_PairingStage
  | PairingStage_Done : t_PairingStage

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders them; this module never formats a message.
type t_PairingFailure =
  | PairingFailure_InvalidToken : t_PairingFailure
  | PairingFailure_InvalidCiphertext : t_PairingFailure
  | PairingFailure_PackageStorage : t_PairingFailure
  | PairingFailure_PackageUnavailable : t_PairingFailure
  | PairingFailure_PackageNotUtf8 : t_PairingFailure
  | PairingFailure_OpenPolicy : t_PairingFailure
  | PairingFailure_GrantStorage : t_PairingFailure
  | PairingFailure_GrantUnavailable : t_PairingFailure
  | PairingFailure_InvalidEkLength : t_PairingFailure
  | PairingFailure_InvalidVkLength : t_PairingFailure
  | PairingFailure_AlreadyClaimed : t_PairingFailure
  | PairingFailure_ClaimNotAuthorized : t_PairingFailure
  | PairingFailure_GrantError : t_PairingFailure
  | PairingFailure_AccountStorage : t_PairingFailure
  | PairingFailure_KeyEpochInvalid : t_PairingFailure
  | PairingFailure_RekeyPolicy : t_PairingFailure
  | PairingFailure_EpochChanged : t_PairingFailure
  | PairingFailure_NoClaim : t_PairingFailure
  | PairingFailure_ClaimUnreadable : t_PairingFailure
  | PairingFailure_CapsuleInvalid : t_PairingFailure
  | PairingFailure_SignatureFieldInvalid : t_PairingFailure
  | PairingFailure_OpenerStorage : t_PairingFailure
  | PairingFailure_OpenerRevoked : t_PairingFailure
  | PairingFailure_SignatureRejected : t_PairingFailure
  | PairingFailure_CompletionNotAuthorized : t_PairingFailure
  | PairingFailure_CeremonyConsumed : t_PairingFailure
  | PairingFailure_CeremonyChanged : t_PairingFailure
  | PairingFailure_Rotation : t_PairingFailure
  | PairingFailure_InsertStorage : t_PairingFailure
  | PairingFailure_ResultStorage : t_PairingFailure
  | PairingFailure_ResultUnreadable : t_PairingFailure
  | PairingFailure_ClaimRecordUnreadable : t_PairingFailure
  | PairingFailure_ResultSignatureRejected : t_PairingFailure
  | PairingFailure_ResultNotAuthorized : t_PairingFailure
  | PairingFailure_EnrolledDeviceUnreadable : t_PairingFailure

/// The effect the handler must perform next (`Idle` means "do nothing").
type t_PairingEffect =
  | PairingEffect_StorePackage : t_PairingEffect
  | PairingEffect_RedeemPackage : t_PairingEffect
  | PairingEffect_StoreGrant : t_PairingEffect
  | PairingEffect_CheckClaim : t_PairingEffect
  | PairingEffect_WriteClaim : t_PairingEffect
  | PairingEffect_CheckAccount : t_PairingEffect
  | PairingEffect_PrepareCompletion : t_PairingEffect
  | PairingEffect_TakeCeremony : t_PairingEffect
  | PairingEffect_InsertDevice : t_PairingEffect
  | PairingEffect_WriteResult : t_PairingEffect
  | PairingEffect_ReadResult : t_PairingEffect
  | PairingEffect_ReadClaim : t_PairingEffect
  | PairingEffect_ReadEnrolledDevice : t_PairingEffect
  | PairingEffect_Complete : t_PairingEffect
  | PairingEffect_ReturnResult : Vela_enrollment_policy.t_ResultKind -> t_PairingEffect
  | PairingEffect_Fail : t_PairingFailure -> t_PairingEffect
  | PairingEffect_RestoreAndFail : t_PairingFailure -> t_PairingEffect
  | PairingEffect_Idle : t_PairingEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
type t_PairingDriver = {
  f_ceremony:t_PairingCeremony;
  f_stage:t_PairingStage;
  f_authorized:bool;
  f_wrote:bool;
  f_consumed:bool;
  f_inserted:bool;
  f_recorded:bool;
  f_restored:bool;
  f_succeeded:bool;
  f_failed:bool;
  f_grant_present:bool;
  f_user_matches:bool;
  f_opener_matches:bool;
  f_claim_present:bool;
  f_opener_active:bool;
  f_signature_verified:bool
}

type t_PairingTransition = {
  f_driver:t_PairingDriver;
  f_effect:t_PairingEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let pairing_state_is_sound (d: t_PairingDriver) : bool =
  let start_clean:bool =
    ~.d.f_consumed && ~.d.f_inserted && ~.d.f_recorded && ~.d.f_restored && ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let applied_clean:bool =
    d.f_authorized && d.f_wrote && ~.d.f_consumed && ~.d.f_inserted && ~.d.f_recorded &&
    ~.d.f_restored &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let inflight_clean:bool =
    d.f_authorized && d.f_wrote && d.f_consumed && ~.d.f_inserted && ~.d.f_recorded &&
    ~.d.f_restored &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let wrote_result_clean:bool =
    d.f_authorized && d.f_wrote && d.f_consumed && d.f_inserted && ~.d.f_recorded && ~.d.f_restored &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let result_claim_clean:bool =
    d.f_authorized && ~.d.f_wrote && ~.d.f_consumed && ~.d.f_inserted && ~.d.f_recorded &&
    ~.d.f_restored &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let done_clean:bool =
    (d.f_succeeded || d.f_failed) && ~.(d.f_succeeded && d.f_failed) &&
    (~.d.f_succeeded || d.f_authorized && ~.d.f_restored) &&
    (~.d.f_succeeded ||
    ~.(match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) ||
    d.f_consumed && d.f_inserted && d.f_recorded) &&
    (~.d.f_succeeded ||
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) ||
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CollectResult  -> true
      | _ -> false) ||
    d.f_wrote) &&
    (~.d.f_restored ||
    d.f_failed &&
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) &&
    ~.d.f_inserted)
  in
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_Start  -> true
    | _ -> false) ||
  start_clean) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_Applied  -> true
    | _ -> false) ||
  applied_clean) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_InFlight  -> true
    | _ -> false) ||
  inflight_clean) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_WroteResult  -> true
    | _ -> false) ||
  wrote_result_clean) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_ResultClaim  -> true
    | _ -> false) ||
  result_claim_clean) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_Done  -> true
    | _ -> false) ||
  done_clean) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_InFlight  | PairingStage_WroteResult  -> true
    | _ -> false) ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false)) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_ResultClaim  -> true
    | _ -> false) ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CollectResult  -> true
    | _ -> false)) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_Applied  -> true
    | _ -> false) ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_ClaimGrant  -> true
    | _ -> false) ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false)) &&
  (~.d.f_consumed ||
  d.f_wrote &&
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false)) &&
  (~.d.f_inserted || d.f_consumed) &&
  (~.d.f_recorded || d.f_inserted) &&
  (~.d.f_recorded ||
  (match d.f_stage <: t_PairingStage with
    | PairingStage_Done  -> true
    | _ -> false)) &&
  (~.d.f_wrote ||
  ~.(match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CollectResult  -> true
    | _ -> false)) &&
  (~.d.f_grant_present ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false)) &&
  (~.d.f_user_matches || d.f_grant_present) &&
  (~.d.f_opener_matches || d.f_grant_present) &&
  (~.d.f_claim_present ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false)) &&
  (~.d.f_opener_active ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false)) &&
  (~.d.f_signature_verified ||
  (match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false)) &&
  (~.d.f_inserted ||
  d.f_grant_present && d.f_claim_present && d.f_opener_active && d.f_signature_verified &&
  d.f_user_matches &&
  d.f_opener_matches) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_Applied  -> true
    | _ -> false) ||
  ~.(match d.f_ceremony <: t_PairingCeremony with
    | PairingCeremony_CompleteGrant  -> true
    | _ -> false) ||
  d.f_grant_present && d.f_claim_present && d.f_opener_active && d.f_signature_verified &&
  d.f_user_matches &&
  d.f_opener_matches) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_InFlight  | PairingStage_WroteResult  -> true
    | _ -> false) ||
  d.f_grant_present && d.f_claim_present && d.f_opener_active && d.f_signature_verified &&
  d.f_user_matches &&
  d.f_opener_matches) &&
  (~.(match d.f_stage <: t_PairingStage with
    | PairingStage_Start  -> true
    | _ -> false) ||
  d.f_authorized)

/// Every effect the driver emits agrees with the state it produces.
let pairing_effect_is_sound (d: t_PairingDriver) (v_effect: t_PairingEffect) : bool =
  match v_effect <: t_PairingEffect with
  | PairingEffect_StorePackage  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_StorePackage  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote
  | PairingEffect_RedeemPackage  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_RedeemPackage  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote
  | PairingEffect_StoreGrant  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_OpenGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote
  | PairingEffect_CheckClaim  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_ClaimGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_wrote
  | PairingEffect_WriteClaim  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_ClaimGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Applied  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote
  | PairingEffect_CheckAccount  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_wrote
  | PairingEffect_PrepareCompletion  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_wrote
  | PairingEffect_TakeCeremony  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Applied  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote &&
    ~.d.f_consumed
  | PairingEffect_InsertDevice  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_InFlight  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote &&
    d.f_consumed &&
    ~.d.f_inserted &&
    ~.d.f_recorded &&
    ~.d.f_restored
  | PairingEffect_WriteResult  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_WroteResult  -> true
      | _ -> false) &&
    d.f_consumed &&
    d.f_inserted &&
    ~.d.f_recorded &&
    ~.d.f_restored
  | PairingEffect_ReadResult  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CollectResult  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_wrote
  | PairingEffect_ReadClaim  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CollectResult  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_ResultClaim  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_wrote
  | PairingEffect_ReadEnrolledDevice  ->
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CollectResult  -> true
      | _ -> false) &&
    (match d.f_stage <: t_PairingStage with
      | PairingStage_ResultClaim  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_wrote
  | PairingEffect_Complete  ->
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Done  -> true
      | _ -> false) &&
    d.f_succeeded &&
    ~.d.f_failed &&
    ~.(match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CollectResult  -> true
      | _ -> false)
  | PairingEffect_ReturnResult _ ->
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Done  -> true
      | _ -> false) &&
    d.f_succeeded &&
    ~.d.f_failed &&
    (match d.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CollectResult  -> true
      | _ -> false)
  | PairingEffect_Fail _ ->
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_succeeded &&
    ~.d.f_restored
  | PairingEffect_RestoreAndFail _ ->
    (match d.f_stage <: t_PairingStage with
      | PairingStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    d.f_restored &&
    ~.d.f_succeeded
  | PairingEffect_Idle  -> true

let fresh_driver (ceremony: t_PairingCeremony) : t_PairingDriver =
  {
    f_ceremony = ceremony;
    f_stage = PairingStage_Start <: t_PairingStage;
    f_authorized = false;
    f_wrote = false;
    f_consumed = false;
    f_inserted = false;
    f_recorded = false;
    f_restored = false;
    f_succeeded = false;
    f_failed = false;
    f_grant_present = false;
    f_user_matches = false;
    f_opener_matches = false;
    f_claim_present = false;
    f_opener_active = false;
    f_signature_verified = false
  }
  <:
  t_PairingDriver

let transition (d: t_PairingDriver) (v_effect: t_PairingEffect) : t_PairingTransition =
  { f_driver = d; f_effect = v_effect } <: t_PairingTransition

let idle (d: t_PairingDriver) : t_PairingTransition =
  transition d (PairingEffect_Idle <: t_PairingEffect)

let terminal (d: t_PairingDriver) (failure: t_PairingFailure) : t_PairingTransition =
  transition ({ d with f_stage = PairingStage_Done <: t_PairingStage; f_failed = true }
      <:
      t_PairingDriver)
    (PairingEffect_Fail failure <: t_PairingEffect)

let restore_then_fail (d: t_PairingDriver) (failure: t_PairingFailure) : t_PairingTransition =
  transition ({
        d with
        f_stage = PairingStage_Done <: t_PairingStage;
        f_failed = true;
        f_restored = true
      }
      <:
      t_PairingDriver)
    (PairingEffect_RestoreAndFail failure <: t_PairingEffect)

let complete (d: t_PairingDriver) : t_PairingTransition =
  transition ({
        d with
        f_stage = PairingStage_Done <: t_PairingStage;
        f_succeeded = true;
        f_recorded
        =
        match d.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_CompleteGrant  -> true
        | _ -> false
      }
      <:
      t_PairingDriver)
    (PairingEffect_Complete <: t_PairingEffect)

let complete_result (d: t_PairingDriver) (kind: Vela_enrollment_policy.t_ResultKind)
    : t_PairingTransition =
  transition ({ d with f_stage = PairingStage_Done <: t_PairingStage; f_succeeded = true }
      <:
      t_PairingDriver)
    (PairingEffect_ReturnResult kind <: t_PairingEffect)

/// Start a package-store request. An invalid token or ciphertext length is
/// terminal and performs no store effect.
let begin_store_package (observation: t_PackageStoreObservation)
    : Prims.Pure t_PairingTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_state_is_sound result.f_driver &&
          pairing_effect_is_sound result.f_driver result.f_effect) =
  if ~.observation.f_token_valid
  then
    terminal (fresh_driver (PairingCeremony_StorePackage <: t_PairingCeremony) <: t_PairingDriver)
      (PairingFailure_InvalidToken <: t_PairingFailure)
  else
    if ~.observation.f_ciphertext_len_valid
    then
      terminal (fresh_driver (PairingCeremony_StorePackage <: t_PairingCeremony) <: t_PairingDriver)
        (PairingFailure_InvalidCiphertext <: t_PairingFailure)
    else
      transition ({
            (fresh_driver (PairingCeremony_StorePackage <: t_PairingCeremony) <: t_PairingDriver) with
            f_authorized = true;
            f_wrote = true
          }
          <:
          t_PairingDriver)
        (PairingEffect_StorePackage <: t_PairingEffect)

/// Start a package-fetch request. An invalid token is terminal and performs no
/// destructive read.
let begin_redeem_package (observation: t_PackageTokenObservation)
    : Prims.Pure t_PairingTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_state_is_sound result.f_driver &&
          pairing_effect_is_sound result.f_driver result.f_effect) =
  if ~.observation.f_token_valid
  then
    terminal (fresh_driver (PairingCeremony_RedeemPackage <: t_PairingCeremony) <: t_PairingDriver)
      (PairingFailure_InvalidToken <: t_PairingFailure)
  else
    transition ({
          (fresh_driver (PairingCeremony_RedeemPackage <: t_PairingCeremony) <: t_PairingDriver) with
          f_authorized = true;
          f_wrote = true
        }
        <:
        t_PairingDriver)
      (PairingEffect_RedeemPackage <: t_PairingEffect)

let on_package_written (d: t_PairingDriver) (observation: t_StoreObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Start  -> true
          | _ -> false) &&
        d.f_wrote &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_StorePackage  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_StoreObservation with
  | StoreObservation_Stored  -> complete d
  | StoreObservation_Failed  -> terminal d (PairingFailure_PackageStorage <: t_PairingFailure)

let on_package_redeemed (d: t_PairingDriver) (observation: t_RedeemObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Start  -> true
          | _ -> false) &&
        d.f_wrote &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_RedeemPackage  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_RedeemObservation with
  | RedeemObservation_Missing  -> terminal d (PairingFailure_PackageUnavailable <: t_PairingFailure)
  | RedeemObservation_Present { f_utf8_valid = utf8_valid } ->
    if utf8_valid
    then complete d
    else terminal d (PairingFailure_PackageNotUtf8 <: t_PairingFailure)

/// Start a grant-open request after the verified open policy was asked. The
/// handler passes the real session observations.
let begin_open_grant (observation: Vela_enrollment_policy.t_OpenObservation)
    : Prims.Pure t_PairingTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_state_is_sound result.f_driver &&
          pairing_effect_is_sound result.f_driver result.f_effect) =
  match
    Vela_enrollment_policy.plan_open (Vela_enrollment_policy.open_facts observation
        <:
        Vela_enrollment_policy.t_OpenFacts)
    <:
    Vela_enrollment_policy.t_OpenDecision
  with
  | Vela_enrollment_policy.OpenDecision_Open e_permit ->
    transition ({
          (fresh_driver (PairingCeremony_OpenGrant <: t_PairingCeremony) <: t_PairingDriver) with
          f_authorized = true;
          f_wrote = true
        }
        <:
        t_PairingDriver)
      (PairingEffect_StoreGrant <: t_PairingEffect)
  | Vela_enrollment_policy.OpenDecision_Reject  ->
    terminal (fresh_driver (PairingCeremony_OpenGrant <: t_PairingCeremony) <: t_PairingDriver)
      (PairingFailure_OpenPolicy <: t_PairingFailure)

let on_grant_written (d: t_PairingDriver) (observation: t_StoreObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Start  -> true
          | _ -> false) &&
        d.f_wrote &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_OpenGrant  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_StoreObservation with
  | StoreObservation_Stored  -> complete d
  | StoreObservation_Failed  -> terminal d (PairingFailure_GrantStorage <: t_PairingFailure)

/// Begin the claim request with the only observation the handler reads before
/// decoding the body: whether the grant key is live.
let begin_claim (grant_live: bool)
    : Prims.Pure t_PairingTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_state_is_sound result.f_driver &&
          pairing_effect_is_sound result.f_driver result.f_effect) =
  if ~.grant_live
  then
    terminal (fresh_driver (PairingCeremony_ClaimGrant <: t_PairingCeremony) <: t_PairingDriver)
      (PairingFailure_GrantUnavailable <: t_PairingFailure)
  else
    transition ({
          (fresh_driver (PairingCeremony_ClaimGrant <: t_PairingCeremony) <: t_PairingDriver) with
          f_authorized = true
        }
        <:
        t_PairingDriver)
      (PairingEffect_CheckClaim <: t_PairingEffect)

/// The handler's historical rejection precedence, kept in one place. It is
/// only consulted when the verified `plan_claim` refused, so at least one
/// guard is false.
let claim_rejection (observation: Vela_enrollment_policy.t_ClaimObservation) : t_PairingFailure =
  if observation.Vela_enrollment_policy.f_hybrid_ek_len <>. Vela_enrollment_policy.v_HYBRID_EK_LEN
  then PairingFailure_InvalidEkLength <: t_PairingFailure
  else
    if observation.Vela_enrollment_policy.f_hybrid_vk_len <>. Vela_enrollment_policy.v_HYBRID_VK_LEN
    then PairingFailure_InvalidVkLength <: t_PairingFailure
    else
      if observation.Vela_enrollment_policy.f_claim_exists
      then PairingFailure_AlreadyClaimed <: t_PairingFailure
      else
        if ~.observation.Vela_enrollment_policy.f_grant_live
        then PairingFailure_GrantUnavailable <: t_PairingFailure
        else PairingFailure_ClaimNotAuthorized <: t_PairingFailure

let on_claim_checked (d: t_PairingDriver) (observation: Vela_enrollment_policy.t_ClaimObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Start  -> true
          | _ -> false) &&
        ~.d.f_wrote &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_ClaimGrant  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match
    Vela_enrollment_policy.plan_claim (Vela_enrollment_policy.claim_facts observation
        <:
        Vela_enrollment_policy.t_ClaimFacts)
    <:
    Vela_enrollment_policy.t_ClaimDecision
  with
  | Vela_enrollment_policy.ClaimDecision_Claim e_permit ->
    transition ({ d with f_stage = PairingStage_Applied <: t_PairingStage; f_wrote = true }
        <:
        t_PairingDriver)
      (PairingEffect_WriteClaim <: t_PairingEffect)
  | Vela_enrollment_policy.ClaimDecision_Reject  ->
    terminal d (claim_rejection observation <: t_PairingFailure)

let on_claim_written (d: t_PairingDriver) (observation: t_ClaimWriteObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Applied  -> true
          | _ -> false) &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_ClaimGrant  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_ClaimWriteObservation with
  | ClaimWriteObservation_Inserted  -> complete d
  | ClaimWriteObservation_GuardMissing  ->
    terminal d (PairingFailure_GrantUnavailable <: t_PairingFailure)
  | ClaimWriteObservation_KeyExists  ->
    terminal d (PairingFailure_AlreadyClaimed <: t_PairingFailure)

/// The account observations the completion handler makes after the grant
/// binding passed: the `users` row query, the declared epoch and the rekey
/// permit.
type t_CompletionAccountObservation = {
  f_account_query_ok:bool;
  f_declared_epoch_positive:bool;
  f_rekey_permitted:bool
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_PairingEvent =
  | PairingEvent_PackageWritten : t_StoreObservation -> t_PairingEvent
  | PairingEvent_PackageRedeemed : t_RedeemObservation -> t_PairingEvent
  | PairingEvent_GrantWritten : t_StoreObservation -> t_PairingEvent
  | PairingEvent_ClaimChecked : Vela_enrollment_policy.t_ClaimObservation -> t_PairingEvent
  | PairingEvent_ClaimWritten : t_ClaimWriteObservation -> t_PairingEvent
  | PairingEvent_AccountChecked : t_CompletionAccountObservation -> t_PairingEvent
  | PairingEvent_CompletionReady : t_CompletionPreflightObservation -> t_PairingEvent
  | PairingEvent_CeremonyTaken : t_TakeObservation -> t_PairingEvent
  | PairingEvent_DeviceInserted : t_DeviceInsertObservation -> t_PairingEvent
  | PairingEvent_ResultWritten : t_StoreObservation -> t_PairingEvent
  | PairingEvent_ResultRead : t_ResultReadObservation -> t_PairingEvent
  | PairingEvent_ClaimRead : t_ClaimReadObservation -> t_PairingEvent
  | PairingEvent_EnrolledDeviceRead : t_DeviceGrantObservation -> t_PairingEvent

/// Start a completion request. Only a grant bound to this user *and* this
/// device may continue; the handler then reads the account row.
let begin_completion (grant: t_GrantObservation)
    : Prims.Pure t_PairingTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_state_is_sound result.f_driver &&
          pairing_effect_is_sound result.f_driver result.f_effect) =
  let base:t_PairingDriver = fresh_driver (PairingCeremony_CompleteGrant <: t_PairingCeremony) in
  match grant <: t_GrantObservation with
  | GrantObservation_Absent  -> terminal base (PairingFailure_GrantUnavailable <: t_PairingFailure)
  | GrantObservation_Error  -> terminal base (PairingFailure_GrantError <: t_PairingFailure)
  | GrantObservation_Present { f_user_matches = user_matches ; f_opener_matches = opener_matches } ->
    if ~.user_matches || ~.opener_matches
    then terminal base (PairingFailure_GrantUnavailable <: t_PairingFailure)
    else
      transition ({
            base with
            f_authorized = true;
            f_grant_present = true;
            f_user_matches = user_matches;
            f_opener_matches = opener_matches
          }
          <:
          t_PairingDriver)
        (PairingEffect_CheckAccount <: t_PairingEffect)

/// Apply the verified completion policy to the real preflight observations.
/// A permit is the only way to reach the destructive take, and the historical
/// failure precedence is applied only after the policy refused.
let on_completion_ready (d: t_PairingDriver) (observation: t_CompletionPreflightObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Start  -> true
          | _ -> false) &&
        ~.d.f_wrote &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_CompleteGrant  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  let claim_present:bool =
    ~.(match observation.f_claim <: t_ClaimMaterialObservation with
      | ClaimMaterialObservation_Missing  -> true
      | _ -> false)
  in
  let opener_active:bool =
    match observation.f_opener <: t_OpenerObservation with
    | OpenerObservation_Active  -> true
    | _ -> false
  in
  let signature_verified:bool =
    match observation.f_signature <: t_SignatureObservation with
    | SignatureObservation_Verified  -> true
    | _ -> false
  in
  let facts:Vela_enrollment_policy.t_CompletionFacts =
    Vela_enrollment_policy.completion_facts ({
          Vela_enrollment_policy.f_claim_present = claim_present;
          Vela_enrollment_policy.f_user_matches = d.f_user_matches;
          Vela_enrollment_policy.f_opener_matches = d.f_opener_matches;
          Vela_enrollment_policy.f_opener_active = opener_active;
          Vela_enrollment_policy.f_signature_verified = signature_verified;
          Vela_enrollment_policy.f_claim_key_source
          =
          Vela_enrollment_policy.ClaimKeySource_StoredClaim
          <:
          Vela_enrollment_policy.t_ClaimKeySource;
          Vela_enrollment_policy.f_account_epoch = observation.f_account_epoch;
          Vela_enrollment_policy.f_declared_epoch = observation.f_declared_epoch;
          Vela_enrollment_policy.f_rotation_in_progress = observation.f_rotation_in_progress
        }
        <:
        Vela_enrollment_policy.t_CompletionObservation)
  in
  match
    Vela_enrollment_policy.plan_completion facts <: Vela_enrollment_policy.t_CompletionDecision
  with
  | Vela_enrollment_policy.CompletionDecision_Complete e_permit ->
    transition ({
          d with
          f_stage = PairingStage_Applied <: t_PairingStage;
          f_wrote = true;
          f_claim_present = claim_present;
          f_opener_active = opener_active;
          f_signature_verified = signature_verified
        }
        <:
        t_PairingDriver)
      (PairingEffect_TakeCeremony <: t_PairingEffect)
  | Vela_enrollment_policy.CompletionDecision_Reject  ->
    let failure:t_PairingFailure =
      if ~.observation.f_account_epoch_active
      then PairingFailure_EpochChanged <: t_PairingFailure
      else
        if ~.claim_present
        then PairingFailure_NoClaim <: t_PairingFailure
        else
          if
            match observation.f_claim <: t_ClaimMaterialObservation with
            | ClaimMaterialObservation_Error  -> true
            | _ -> false
          then PairingFailure_ClaimUnreadable <: t_PairingFailure
          else
            if ~.observation.f_capsule_valid
            then PairingFailure_CapsuleInvalid <: t_PairingFailure
            else
              if ~.observation.f_signature_field_valid
              then PairingFailure_SignatureFieldInvalid <: t_PairingFailure
              else
                if
                  match observation.f_opener <: t_OpenerObservation with
                  | OpenerObservation_Error  -> true
                  | _ -> false
                then PairingFailure_OpenerStorage <: t_PairingFailure
                else
                  if ~.opener_active
                  then PairingFailure_OpenerRevoked <: t_PairingFailure
                  else
                    if ~.signature_verified
                    then PairingFailure_SignatureRejected <: t_PairingFailure
                    else PairingFailure_CompletionNotAuthorized <: t_PairingFailure
    in
    terminal d failure

let on_ceremony_taken (d: t_PairingDriver) (observation: t_TakeObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Applied  -> true
          | _ -> false) &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_CompleteGrant  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_TakeObservation with
  | TakeObservation_Missing  -> terminal d (PairingFailure_CeremonyConsumed <: t_PairingFailure)
  | TakeObservation_Taken { f_grant_matches = grant_matches ; f_claim_matches = claim_matches } ->
    if grant_matches && claim_matches
    then
      transition ({ d with f_stage = PairingStage_InFlight <: t_PairingStage; f_consumed = true }
          <:
          t_PairingDriver)
        (PairingEffect_InsertDevice <: t_PairingEffect)
    else restore_then_fail d (PairingFailure_CeremonyChanged <: t_PairingFailure)

let on_device_inserted (d: t_PairingDriver) (observation: t_DeviceInsertObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_InFlight  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_DeviceInsertObservation with
  | DeviceInsertObservation_Inserted  ->
    transition ({ d with f_stage = PairingStage_WroteResult <: t_PairingStage; f_inserted = true }
        <:
        t_PairingDriver)
      (PairingEffect_WriteResult <: t_PairingEffect)
  | DeviceInsertObservation_Skipped  ->
    restore_then_fail d (PairingFailure_Rotation <: t_PairingFailure)
  | DeviceInsertObservation_Failed  -> terminal d (PairingFailure_InsertStorage <: t_PairingFailure)

let on_result_written (d: t_PairingDriver) (observation: t_StoreObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_WroteResult  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_StoreObservation with
  | StoreObservation_Stored  -> complete d
  | StoreObservation_Failed  -> terminal d (PairingFailure_ResultStorage <: t_PairingFailure)

/// Start a result-collection request. The first effect is the result read.
let begin_result (_: Prims.unit)
    : Prims.Pure t_PairingTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_state_is_sound result.f_driver &&
          pairing_effect_is_sound result.f_driver result.f_effect) =
  transition ({
        (fresh_driver (PairingCeremony_CollectResult <: t_PairingCeremony) <: t_PairingDriver) with
        f_authorized = true
      }
      <:
      t_PairingDriver)
    (PairingEffect_ReadResult <: t_PairingEffect)

let result_failure (signature_verified: bool) : t_PairingFailure =
  if ~.signature_verified
  then PairingFailure_ResultSignatureRejected <: t_PairingFailure
  else PairingFailure_ResultNotAuthorized <: t_PairingFailure

let on_result_read (d: t_PairingDriver) (observation: t_ResultReadObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_Start  -> true
          | _ -> false) &&
        ~.d.f_wrote &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_CollectResult  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_ResultReadObservation with
  | ResultReadObservation_Completed
    { f_claimed_key_len = claimed_key_len ; f_signature_verified = signature_verified } ->
    (match
        Vela_enrollment_policy.authorize_result (Vela_enrollment_policy.result_facts ({
                  Vela_enrollment_policy.f_source
                  =
                  Vela_enrollment_policy.ResultSource_CompletedResult
                  <:
                  Vela_enrollment_policy.t_ResultSource;
                  Vela_enrollment_policy.f_claimed_key_len = claimed_key_len;
                  Vela_enrollment_policy.f_signature_verified = signature_verified
                }
                <:
                Vela_enrollment_policy.t_ResultObservation)
            <:
            Vela_enrollment_policy.t_ResultFacts)
        <:
        Vela_enrollment_policy.t_ResultDecision
      with
      | Vela_enrollment_policy.ResultDecision_Return permit ->
        complete_result d
          (Vela_enrollment_policy.impl_ResultPermit__kind permit
            <:
            Vela_enrollment_policy.t_ResultKind)
      | Vela_enrollment_policy.ResultDecision_Reject  ->
        terminal d (result_failure signature_verified <: t_PairingFailure))
  | ResultReadObservation_Absent  ->
    transition ({ d with f_stage = PairingStage_ResultClaim <: t_PairingStage } <: t_PairingDriver)
      (PairingEffect_ReadClaim <: t_PairingEffect)
  | ResultReadObservation_Unreadable  ->
    terminal d (PairingFailure_ResultUnreadable <: t_PairingFailure)

let on_claim_read (d: t_PairingDriver) (observation: t_ClaimReadObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_ResultClaim  -> true
          | _ -> false) &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_CollectResult  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_ClaimReadObservation with
  | ClaimReadObservation_Claimed
    { f_claimed_key_len = claimed_key_len ; f_signature_verified = signature_verified } ->
    (match
        Vela_enrollment_policy.authorize_result (Vela_enrollment_policy.result_facts ({
                  Vela_enrollment_policy.f_source
                  =
                  Vela_enrollment_policy.ResultSource_ClaimedClaim
                  <:
                  Vela_enrollment_policy.t_ResultSource;
                  Vela_enrollment_policy.f_claimed_key_len = claimed_key_len;
                  Vela_enrollment_policy.f_signature_verified = signature_verified
                }
                <:
                Vela_enrollment_policy.t_ResultObservation)
            <:
            Vela_enrollment_policy.t_ResultFacts)
        <:
        Vela_enrollment_policy.t_ResultDecision
      with
      | Vela_enrollment_policy.ResultDecision_Return permit ->
        complete_result d
          (Vela_enrollment_policy.impl_ResultPermit__kind permit
            <:
            Vela_enrollment_policy.t_ResultKind)
      | Vela_enrollment_policy.ResultDecision_Reject  ->
        terminal d (result_failure signature_verified <: t_PairingFailure))
  | ClaimReadObservation_Absent  ->
    transition ({ d with f_stage = PairingStage_ResultClaim <: t_PairingStage } <: t_PairingDriver)
      (PairingEffect_ReadEnrolledDevice <: t_PairingEffect)
  | ClaimReadObservation_Unreadable  ->
    terminal d (PairingFailure_ClaimRecordUnreadable <: t_PairingFailure)

/// U-20 fallback: the result record and the claim are both gone, but the
/// committed device row still records the grant it came from. Answer under the
/// same verified result policy and the same result-signature check the stored
/// result uses; only an `Enrolled` observation with a verified proof under the
/// row\'s stored key can produce `ReturnResult Enrolled`.
let on_enrolled_device_read (d: t_PairingDriver) (observation: t_DeviceGrantObservation)
    : Prims.Pure t_PairingTransition
      (requires
        pairing_state_is_sound d &&
        (match d.f_stage <: t_PairingStage with
          | PairingStage_ResultClaim  -> true
          | _ -> false) &&
        (match d.f_ceremony <: t_PairingCeremony with
          | PairingCeremony_CollectResult  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound d <: bool) || pairing_state_is_sound result.f_driver)) =
  match observation <: t_DeviceGrantObservation with
  | DeviceGrantObservation_Enrolled
    { f_claimed_key_len = claimed_key_len ; f_signature_verified = signature_verified } ->
    (match
        Vela_enrollment_policy.authorize_result (Vela_enrollment_policy.result_facts ({
                  Vela_enrollment_policy.f_source
                  =
                  Vela_enrollment_policy.ResultSource_CompletedResult
                  <:
                  Vela_enrollment_policy.t_ResultSource;
                  Vela_enrollment_policy.f_claimed_key_len = claimed_key_len;
                  Vela_enrollment_policy.f_signature_verified = signature_verified
                }
                <:
                Vela_enrollment_policy.t_ResultObservation)
            <:
            Vela_enrollment_policy.t_ResultFacts)
        <:
        Vela_enrollment_policy.t_ResultDecision
      with
      | Vela_enrollment_policy.ResultDecision_Return permit ->
        complete_result d
          (Vela_enrollment_policy.impl_ResultPermit__kind permit
            <:
            Vela_enrollment_policy.t_ResultKind)
      | Vela_enrollment_policy.ResultDecision_Reject  ->
        terminal d (result_failure signature_verified <: t_PairingFailure))
  | DeviceGrantObservation_Absent  ->
    terminal d (PairingFailure_GrantUnavailable <: t_PairingFailure)
  | DeviceGrantObservation_Unreadable  ->
    terminal d (PairingFailure_EnrolledDeviceUnreadable <: t_PairingFailure)

let stage_start (d: t_PairingDriver) : bool =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start  -> true
  | _ -> false

/// Apply the account-epoch and rekey preflight. The order is the handler\'s
/// historical status order: query failure, then a non-positive declared
/// epoch, then the rekey permit.
let on_completion_account (driver: t_PairingDriver) (observation: t_CompletionAccountObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  if
    ~.(match driver.f_ceremony <: t_PairingCeremony with
      | PairingCeremony_CompleteGrant  -> true
      | _ -> false) ||
    ~.(stage_start driver <: bool) ||
    driver.f_wrote
  then idle driver
  else
    if ~.observation.f_account_query_ok
    then terminal driver (PairingFailure_AccountStorage <: t_PairingFailure)
    else
      if ~.observation.f_declared_epoch_positive
      then terminal driver (PairingFailure_KeyEpochInvalid <: t_PairingFailure)
      else
        if ~.observation.f_rekey_permitted
        then terminal driver (PairingFailure_RekeyPolicy <: t_PairingFailure)
        else transition driver (PairingEffect_PrepareCompletion <: t_PairingEffect)

/// The complete, total transition relation. Events that do not match the
/// current ceremony and stage (and every event after `Done`) are ignored.
let step (driver: t_PairingDriver) (event: t_PairingEvent)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  match event <: t_PairingEvent with
  | PairingEvent_PackageWritten observation ->
    if
      stage_start driver && driver.f_wrote &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_StorePackage  -> true
        | _ -> false)
    then on_package_written driver observation
    else idle driver
  | PairingEvent_PackageRedeemed observation ->
    if
      stage_start driver && driver.f_wrote &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_RedeemPackage  -> true
        | _ -> false)
    then on_package_redeemed driver observation
    else idle driver
  | PairingEvent_GrantWritten observation ->
    if
      stage_start driver && driver.f_wrote &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_OpenGrant  -> true
        | _ -> false)
    then on_grant_written driver observation
    else idle driver
  | PairingEvent_ClaimChecked observation ->
    if
      stage_start driver && ~.driver.f_wrote &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_ClaimGrant  -> true
        | _ -> false)
    then on_claim_checked driver observation
    else idle driver
  | PairingEvent_ClaimWritten observation ->
    if
      (match driver.f_stage <: t_PairingStage with
        | PairingStage_Applied  -> true
        | _ -> false) &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_ClaimGrant  -> true
        | _ -> false)
    then on_claim_written driver observation
    else idle driver
  | PairingEvent_AccountChecked observation -> on_completion_account driver observation
  | PairingEvent_CompletionReady observation ->
    if
      stage_start driver && ~.driver.f_wrote &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_CompleteGrant  -> true
        | _ -> false)
    then on_completion_ready driver observation
    else idle driver
  | PairingEvent_CeremonyTaken observation ->
    if
      (match driver.f_stage <: t_PairingStage with
        | PairingStage_Applied  -> true
        | _ -> false) &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_CompleteGrant  -> true
        | _ -> false)
    then on_ceremony_taken driver observation
    else idle driver
  | PairingEvent_DeviceInserted observation ->
    if
      match driver.f_stage <: t_PairingStage with
      | PairingStage_InFlight  -> true
      | _ -> false
    then on_device_inserted driver observation
    else idle driver
  | PairingEvent_ResultWritten observation ->
    if
      match driver.f_stage <: t_PairingStage with
      | PairingStage_WroteResult  -> true
      | _ -> false
    then on_result_written driver observation
    else idle driver
  | PairingEvent_ResultRead observation ->
    if
      stage_start driver && ~.driver.f_wrote &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_CollectResult  -> true
        | _ -> false)
    then on_result_read driver observation
    else idle driver
  | PairingEvent_ClaimRead observation ->
    if
      (match driver.f_stage <: t_PairingStage with
        | PairingStage_ResultClaim  -> true
        | _ -> false) &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_CollectResult  -> true
        | _ -> false)
    then on_claim_read driver observation
    else idle driver
  | PairingEvent_EnrolledDeviceRead observation ->
    if
      (match driver.f_stage <: t_PairingStage with
        | PairingStage_ResultClaim  -> true
        | _ -> false) &&
      (match driver.f_ceremony <: t_PairingCeremony with
        | PairingCeremony_CollectResult  -> true
        | _ -> false)
    then on_enrolled_device_read driver observation
    else idle driver

/// Total wrapper: the handler feeds the store/redeem outcome.
let on_package_written_event (driver: t_PairingDriver) (observation: t_StoreObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_PackageWritten observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the destructive package read.
let on_package_redeemed_event (driver: t_PairingDriver) (observation: t_RedeemObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_PackageRedeemed observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the grant write outcome.
let on_grant_written_event (driver: t_PairingDriver) (observation: t_StoreObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_GrantWritten observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the claim plan.
let on_claim_checked_event
      (driver: t_PairingDriver)
      (observation: Vela_enrollment_policy.t_ClaimObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_ClaimChecked observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the guarded claim write outcome.
let on_claim_written_event (driver: t_PairingDriver) (observation: t_ClaimWriteObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_ClaimWritten observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the verified completion preflight.
let on_completion_ready_event
      (driver: t_PairingDriver)
      (observation: t_CompletionPreflightObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_CompletionReady observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the single-use take outcome.
let on_ceremony_taken_event (driver: t_PairingDriver) (observation: t_TakeObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_CeremonyTaken observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the guarded insert outcome.
let on_device_inserted_event (driver: t_PairingDriver) (observation: t_DeviceInsertObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_DeviceInserted observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the result-record write outcome.
let on_result_written_event (driver: t_PairingDriver) (observation: t_StoreObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_ResultWritten observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the result read.
let on_result_read_event (driver: t_PairingDriver) (observation: t_ResultReadObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_ResultRead observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the claim read that follows an absent
/// result record.
let on_claim_read_event (driver: t_PairingDriver) (observation: t_ClaimReadObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_ClaimRead observation <: t_PairingEvent)

/// Total wrapper: the handler feeds the fallback device-row read after an
/// absent result record and claim.
let on_enrolled_device_read_event (driver: t_PairingDriver) (observation: t_DeviceGrantObservation)
    : Prims.Pure t_PairingTransition
      (requires pairing_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_PairingTransition = result in
          pairing_effect_is_sound result.f_driver result.f_effect &&
          (~.(pairing_state_is_sound driver <: bool) || pairing_state_is_sound result.f_driver)) =
  step driver (PairingEvent_EnrolledDeviceRead observation <: t_PairingEvent)
