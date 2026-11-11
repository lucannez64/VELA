module Vela_recovery_policy.Webauthn_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// The account's currently stored recovery credential, as observed by the
/// handler. `Missing` is a NULL column (no credential registered yet);
/// `Corrupt` is a text cell whose JSON does not decode (the handler's
/// historical internal error).
type t_StoredCredentialObservation =
  | StoredCredentialObservation_Missing : t_StoredCredentialObservation
  | StoredCredentialObservation_Present : t_StoredCredentialObservation
  | StoredCredentialObservation_Corrupt : t_StoredCredentialObservation

/// Outcome of the rate-limit attempt count.
type t_AttemptBudgetObservation =
  | AttemptBudgetObservation_Admitted : t_AttemptBudgetObservation
  | AttemptBudgetObservation_Limited : t_AttemptBudgetObservation

/// Outcome of the single-use grant store.
type t_GrantStoreObservation =
  | GrantStoreObservation_Stored : t_GrantStoreObservation
  | GrantStoreObservation_Failed : t_GrantStoreObservation

/// Where the authentication finish is in its decision sequence.
type t_AuthFinishStage =
  | AuthFinishStage_Attempt : t_AuthFinishStage
  | AuthFinishStage_Context : t_AuthFinishStage
  | AuthFinishStage_Consume : t_AuthFinishStage
  | AuthFinishStage_Verify : t_AuthFinishStage
  | AuthFinishStage_Update : t_AuthFinishStage
  | AuthFinishStage_Account : t_AuthFinishStage
  | AuthFinishStage_Release : t_AuthFinishStage
  | AuthFinishStage_Store : t_AuthFinishStage
  | AuthFinishStage_Done : t_AuthFinishStage

/// Pre-consumption availability observations. The credential is decoded here so
/// the challenge's credential binding can be compared with the live column.
type t_AuthFinishContextObservation = {
  f_account_present:bool;
  f_share_present:bool;
  f_credential:t_StoredCredentialObservation;
  f_attempt_id_present:bool
}

/// Outcome of the atomic single-use attempt consumption. `Present` carries the
/// request/attempt binding comparison and the comparison between the
/// challenge-bound credential id and the live column.
type t_AuthAttemptConsumptionObservation =
  | AuthAttemptConsumptionObservation_Missing : t_AuthAttemptConsumptionObservation
  | AuthAttemptConsumptionObservation_Corrupt : t_AuthAttemptConsumptionObservation
  | AuthAttemptConsumptionObservation_Present {
    f_user_matches:bool;
    f_attempt_matches:bool;
    f_credential_matches:bool
  }: t_AuthAttemptConsumptionObservation

/// Authenticated outcome of `finish_passkey_authentication`.
type t_AssertionObservation = {
  f_assertion_valid:bool;
  f_user_verified:bool;
  f_credential_matches:bool;
  f_needs_update:bool
}

/// Outcome of the conditional credential update. `Changed` covers both a
/// `Passkey::update_credential` that produced no change and a guarded SQL
/// update that matched no row.
type t_CredentialUpdateStoreObservation =
  | CredentialUpdateStoreObservation_Updated : t_CredentialUpdateStoreObservation
  | CredentialUpdateStoreObservation_Changed : t_CredentialUpdateStoreObservation

/// Live `users` row observation after the assertion was accepted.
type t_AuthAccountObservation = {
  f_account_present:bool;
  f_account_epoch_active:bool;
  f_share_present:bool;
  f_stored_credential_matches:bool;
  f_stored_epoch:Core_models.Option.t_Option i64
}

/// Outcome of decoding the staged share text.
type t_ShareDecodeObservation =
  | ShareDecodeObservation_Decoded : t_ShareDecodeObservation
  | ShareDecodeObservation_Corrupt : t_ShareDecodeObservation

/// One authentication-finish driver event.
type t_AuthFinishEvent =
  | AuthFinishEvent_AttemptCounted : t_AttemptBudgetObservation -> t_AuthFinishEvent
  | AuthFinishEvent_ContextObserved : t_AuthFinishContextObservation -> t_AuthFinishEvent
  | AuthFinishEvent_AttemptConsumed : t_AuthAttemptConsumptionObservation -> t_AuthFinishEvent
  | AuthFinishEvent_AssertionObserved : t_AssertionObservation -> t_AuthFinishEvent
  | AuthFinishEvent_CredentialUpdated : t_CredentialUpdateStoreObservation -> t_AuthFinishEvent
  | AuthFinishEvent_AccountObserved : t_AuthAccountObservation -> t_AuthFinishEvent
  | AuthFinishEvent_ShareObserved : t_ShareDecodeObservation -> t_AuthFinishEvent
  | AuthFinishEvent_GrantStored : t_GrantStoreObservation -> t_AuthFinishEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_AuthFinishFailure =
  | AuthFinishFailure_AttemptLimited : t_AuthFinishFailure
  | AuthFinishFailure_AccountUnavailable : t_AuthFinishFailure
  | AuthFinishFailure_ShareMissing : t_AuthFinishFailure
  | AuthFinishFailure_CredentialMissing : t_AuthFinishFailure
  | AuthFinishFailure_CredentialCorrupt : t_AuthFinishFailure
  | AuthFinishFailure_AttemptIdMissing : t_AuthFinishFailure
  | AuthFinishFailure_AttemptMissing : t_AuthFinishFailure
  | AuthFinishFailure_AttemptCorrupt : t_AuthFinishFailure
  | AuthFinishFailure_BindingMismatch : t_AuthFinishFailure
  | AuthFinishFailure_ChallengeCredentialReplaced : t_AuthFinishFailure
  | AuthFinishFailure_AssertionInvalid : t_AuthFinishFailure
  | AuthFinishFailure_UserVerificationRequired : t_AuthFinishFailure
  | AuthFinishFailure_AssertionCredentialMismatch : t_AuthFinishFailure
  | AuthFinishFailure_CredentialUpdateMismatch : t_AuthFinishFailure
  | AuthFinishFailure_AccountAbsent : t_AuthFinishFailure
  | AuthFinishFailure_RotationPaused : t_AuthFinishFailure
  | AuthFinishFailure_StoredCredentialMismatch : t_AuthFinishFailure
  | AuthFinishFailure_PolicyRejected : t_AuthFinishFailure
  | AuthFinishFailure_ShareCorrupt : t_AuthFinishFailure
  | AuthFinishFailure_GrantStorage : t_AuthFinishFailure

/// The grant authority emitted by the driver. It carries only the epoch the
/// released share and the stored grant are bound to; no share bytes.
type t_AuthFinishGrantPermit = { f_epoch:i64 }

/// The effect the handler must perform next. `ReleaseGrant` is the single
/// indivisible authorization to read the observed share and store one
/// single-use enrollment grant.
type t_AuthFinishEffect =
  | AuthFinishEffect_CountAttempt : t_AuthFinishEffect
  | AuthFinishEffect_ObserveContext : t_AuthFinishEffect
  | AuthFinishEffect_ConsumeAttempt : t_AuthFinishEffect
  | AuthFinishEffect_VerifyAssertion : t_AuthFinishEffect
  | AuthFinishEffect_UpdateCredential : t_AuthFinishEffect
  | AuthFinishEffect_QueryAccount : t_AuthFinishEffect
  | AuthFinishEffect_ReleaseGrant : t_AuthFinishGrantPermit -> t_AuthFinishEffect
  | AuthFinishEffect_StoreGrant : t_AuthFinishEffect
  | AuthFinishEffect_Complete : t_AuthFinishEffect
  | AuthFinishEffect_Fail : t_AuthFinishFailure -> t_AuthFinishEffect
  | AuthFinishEffect_Idle : t_AuthFinishEffect

/// Per-request authentication-finish state. Every field is a decision fact
/// established by a prior transition, never a claim about the store.
type t_AuthFinishDriver = {
  f_stage:t_AuthFinishStage;
  f_budget_counted:bool;
  f_context_observed:bool;
  f_attempt_consumed:bool;
  f_user_matches:bool;
  f_attempt_matches:bool;
  f_challenge_credential_matches:bool;
  f_assertion_valid:bool;
  f_user_verified:bool;
  f_assertion_credential_matches:bool;
  f_credential_update_needed:bool;
  f_credential_updated:bool;
  f_account_present:bool;
  f_account_epoch_active:bool;
  f_share_present:bool;
  f_stored_credential_matches:bool;
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_grant_issued:bool;
  f_share_decoded:bool;
  f_grant_stored:bool
}

type t_AuthFinishTransition = {
  f_driver:t_AuthFinishDriver;
  f_effect:t_AuthFinishEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let auth_finish_state_is_sound (driver: t_AuthFinishDriver) : bool =
  let attempt_clean:bool =
    ~.driver.f_budget_counted && ~.driver.f_context_observed && ~.driver.f_attempt_consumed &&
    ~.driver.f_user_matches &&
    ~.driver.f_attempt_matches &&
    ~.driver.f_challenge_credential_matches &&
    ~.driver.f_assertion_valid &&
    ~.driver.f_user_verified &&
    ~.driver.f_assertion_credential_matches &&
    ~.driver.f_credential_update_needed &&
    ~.driver.f_credential_updated &&
    ~.driver.f_account_present &&
    ~.driver.f_account_epoch_active &&
    ~.driver.f_share_present &&
    ~.driver.f_stored_credential_matches &&
    ~.driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  let context_clean:bool =
    driver.f_budget_counted && ~.driver.f_context_observed && ~.driver.f_attempt_consumed &&
    ~.driver.f_user_matches &&
    ~.driver.f_attempt_matches &&
    ~.driver.f_challenge_credential_matches &&
    ~.driver.f_assertion_valid &&
    ~.driver.f_user_verified &&
    ~.driver.f_assertion_credential_matches &&
    ~.driver.f_credential_update_needed &&
    ~.driver.f_credential_updated &&
    ~.driver.f_account_present &&
    ~.driver.f_account_epoch_active &&
    ~.driver.f_share_present &&
    ~.driver.f_stored_credential_matches &&
    ~.driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  let consume_clean:bool =
    driver.f_budget_counted && driver.f_context_observed && ~.driver.f_attempt_consumed &&
    ~.driver.f_user_matches &&
    ~.driver.f_attempt_matches &&
    ~.driver.f_challenge_credential_matches &&
    ~.driver.f_assertion_valid &&
    ~.driver.f_user_verified &&
    ~.driver.f_assertion_credential_matches &&
    ~.driver.f_credential_update_needed &&
    ~.driver.f_credential_updated &&
    ~.driver.f_account_present &&
    ~.driver.f_account_epoch_active &&
    ~.driver.f_share_present &&
    ~.driver.f_stored_credential_matches &&
    ~.driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  let verify_clean:bool =
    driver.f_budget_counted && driver.f_context_observed && driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    ~.driver.f_assertion_valid &&
    ~.driver.f_user_verified &&
    ~.driver.f_assertion_credential_matches &&
    ~.driver.f_credential_update_needed &&
    ~.driver.f_credential_updated &&
    ~.driver.f_account_present &&
    ~.driver.f_account_epoch_active &&
    ~.driver.f_share_present &&
    ~.driver.f_stored_credential_matches &&
    ~.driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  let update_clean:bool =
    driver.f_budget_counted && driver.f_context_observed && driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    driver.f_assertion_valid &&
    driver.f_user_verified &&
    driver.f_assertion_credential_matches &&
    driver.f_credential_update_needed &&
    ~.driver.f_credential_updated &&
    ~.driver.f_account_present &&
    ~.driver.f_account_epoch_active &&
    ~.driver.f_share_present &&
    ~.driver.f_stored_credential_matches &&
    ~.driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  let account_clean:bool =
    driver.f_budget_counted && driver.f_context_observed && driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    driver.f_assertion_valid &&
    driver.f_user_verified &&
    driver.f_assertion_credential_matches &&
    (~.driver.f_credential_update_needed || driver.f_credential_updated) &&
    ~.driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  let release_clean:bool =
    driver.f_budget_counted && driver.f_context_observed && driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    driver.f_assertion_valid &&
    driver.f_user_verified &&
    driver.f_assertion_credential_matches &&
    (~.driver.f_credential_update_needed || driver.f_credential_updated) &&
    driver.f_account_present &&
    driver.f_account_epoch_active &&
    driver.f_share_present &&
    driver.f_stored_credential_matches &&
    driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  let store_clean:bool =
    driver.f_budget_counted && driver.f_context_observed && driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    driver.f_assertion_valid &&
    driver.f_user_verified &&
    driver.f_assertion_credential_matches &&
    (~.driver.f_credential_update_needed || driver.f_credential_updated) &&
    driver.f_account_present &&
    driver.f_account_epoch_active &&
    driver.f_share_present &&
    driver.f_stored_credential_matches &&
    driver.f_grant_issued &&
    driver.f_share_decoded &&
    ~.driver.f_grant_stored
  in
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Attempt  -> true
    | _ -> false) ||
  attempt_clean) &&
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Context  -> true
    | _ -> false) ||
  context_clean) &&
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Consume  -> true
    | _ -> false) ||
  consume_clean) &&
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Verify  -> true
    | _ -> false) ||
  verify_clean) &&
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Update  -> true
    | _ -> false) ||
  update_clean) &&
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Account  -> true
    | _ -> false) ||
  account_clean) &&
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Release  -> true
    | _ -> false) ||
  release_clean) &&
  (~.(match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Store  -> true
    | _ -> false) ||
  store_clean) &&
  (~.driver.f_context_observed || driver.f_budget_counted) &&
  (~.driver.f_attempt_consumed || driver.f_context_observed) &&
  (~.(driver.f_user_matches || driver.f_attempt_matches || driver.f_challenge_credential_matches) ||
  driver.f_attempt_consumed) &&
  (~.driver.f_assertion_valid ||
  driver.f_attempt_consumed && driver.f_user_matches && driver.f_attempt_matches) &&
  (~.driver.f_user_verified || driver.f_assertion_valid) &&
  (~.driver.f_assertion_credential_matches || driver.f_assertion_valid) &&
  (~.driver.f_credential_updated || driver.f_credential_update_needed) &&
  (~.(driver.f_account_present || driver.f_account_epoch_active || driver.f_share_present ||
    driver.f_stored_credential_matches) ||
  driver.f_attempt_consumed) &&
  (~.driver.f_grant_issued ||
  driver.f_attempt_consumed && driver.f_user_matches && driver.f_attempt_matches &&
  driver.f_challenge_credential_matches &&
  driver.f_assertion_valid &&
  driver.f_user_verified &&
  driver.f_assertion_credential_matches &&
  (~.driver.f_credential_update_needed || driver.f_credential_updated) &&
  driver.f_account_present &&
  driver.f_account_epoch_active &&
  driver.f_share_present &&
  driver.f_stored_credential_matches &&
  (Vela_recovery_policy.observed_recovery_epoch driver.f_stored_epoch <: i64) >=.
  Vela_recovery_policy.v_INITIAL_EPOCH &&
  ((match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Release  -> true
    | _ -> false) ||
  (match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Store  -> true
    | _ -> false) ||
  (match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Done  -> true
    | _ -> false))) &&
  (~.driver.f_share_decoded || driver.f_grant_issued) &&
  (~.driver.f_grant_stored ||
  driver.f_share_decoded &&
  (match driver.f_stage <: t_AuthFinishStage with
    | AuthFinishStage_Done  -> true
    | _ -> false))

/// Every effect the driver emits agrees with the state it produces. In
/// particular `ReleaseGrant` leaves the driver authorized at the live epoch
/// with every release fact recorded, and `Complete` is the only success.
let auth_finish_effect_is_sound (driver: t_AuthFinishDriver) (v_effect: t_AuthFinishEffect) : bool =
  match v_effect <: t_AuthFinishEffect with
  | AuthFinishEffect_CountAttempt  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Attempt  -> true
      | _ -> false) &&
    ~.driver.f_budget_counted &&
    ~.driver.f_context_observed &&
    ~.driver.f_attempt_consumed &&
    ~.driver.f_grant_issued
  | AuthFinishEffect_ObserveContext  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Context  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    ~.driver.f_context_observed &&
    ~.driver.f_attempt_consumed
  | AuthFinishEffect_ConsumeAttempt  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Consume  -> true
      | _ -> false) &&
    driver.f_context_observed &&
    ~.driver.f_attempt_consumed
  | AuthFinishEffect_VerifyAssertion  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Verify  -> true
      | _ -> false) &&
    driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    ~.driver.f_assertion_valid &&
    ~.driver.f_grant_issued
  | AuthFinishEffect_UpdateCredential  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Update  -> true
      | _ -> false) &&
    driver.f_assertion_valid &&
    driver.f_user_verified &&
    driver.f_assertion_credential_matches &&
    driver.f_credential_update_needed &&
    ~.driver.f_credential_updated
  | AuthFinishEffect_QueryAccount  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Account  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    driver.f_context_observed &&
    driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    driver.f_assertion_valid &&
    driver.f_user_verified &&
    driver.f_assertion_credential_matches &&
    (~.driver.f_credential_update_needed || driver.f_credential_updated) &&
    ~.driver.f_grant_issued
  | AuthFinishEffect_ReleaseGrant permit ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Release  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    driver.f_context_observed &&
    driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_challenge_credential_matches &&
    driver.f_assertion_valid &&
    driver.f_user_verified &&
    driver.f_assertion_credential_matches &&
    (~.driver.f_credential_update_needed || driver.f_credential_updated) &&
    driver.f_account_present &&
    driver.f_account_epoch_active &&
    driver.f_share_present &&
    driver.f_stored_credential_matches &&
    driver.f_grant_issued &&
    ~.driver.f_share_decoded &&
    permit.f_epoch =. (Vela_recovery_policy.observed_recovery_epoch driver.f_stored_epoch <: i64) &&
    permit.f_epoch >=. Vela_recovery_policy.v_INITIAL_EPOCH
  | AuthFinishEffect_StoreGrant  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Store  -> true
      | _ -> false) &&
    driver.f_grant_issued &&
    driver.f_share_decoded &&
    ~.driver.f_grant_stored
  | AuthFinishEffect_Complete  ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Done  -> true
      | _ -> false) &&
    driver.f_grant_stored
  | AuthFinishEffect_Fail _ ->
    (match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Done  -> true
      | _ -> false) &&
    ~.driver.f_grant_stored
  | AuthFinishEffect_Idle  -> true

/// `ReleaseGrant` is the only effect that releases the recovered server share.
/// The WebAuthn path genuinely releases Share 2 (unlike the possession path);
/// this predicate is what lets the proofs state that no other driver decision
/// can do so, including a registration, initiation or metadata-update effect on
/// the same recovered account.
let auth_finish_effect_releases_share (v_effect: t_AuthFinishEffect) : bool =
  match v_effect <: t_AuthFinishEffect with
  | AuthFinishEffect_ReleaseGrant _ -> true
  | _ -> false

let auth_finish_transition (driver: t_AuthFinishDriver) (v_effect: t_AuthFinishEffect)
    : t_AuthFinishTransition = { f_driver = driver; f_effect = v_effect } <: t_AuthFinishTransition

let auth_finish_idle (driver: t_AuthFinishDriver) : t_AuthFinishTransition =
  auth_finish_transition driver (AuthFinishEffect_Idle <: t_AuthFinishEffect)

let auth_finish_terminal (driver: t_AuthFinishDriver) (failure: t_AuthFinishFailure)
    : t_AuthFinishTransition =
  auth_finish_transition ({ driver with f_stage = AuthFinishStage_Done <: t_AuthFinishStage }
      <:
      t_AuthFinishDriver)
    (AuthFinishEffect_Fail failure <: t_AuthFinishEffect)

/// The first rejection in the handler's historical status/message precedence,
/// or `None` when every preceding guard admitted the observation.
let auth_finish_context_rejection (observation: t_AuthFinishContextObservation)
    : Core_models.Option.t_Option t_AuthFinishFailure =
  if ~.observation.f_account_present
  then
    Core_models.Option.Option_Some (AuthFinishFailure_AccountUnavailable <: t_AuthFinishFailure)
    <:
    Core_models.Option.t_Option t_AuthFinishFailure
  else
    if ~.observation.f_share_present
    then
      Core_models.Option.Option_Some (AuthFinishFailure_ShareMissing <: t_AuthFinishFailure)
      <:
      Core_models.Option.t_Option t_AuthFinishFailure
    else
      match observation.f_credential <: t_StoredCredentialObservation with
      | StoredCredentialObservation_Corrupt  ->
        Core_models.Option.Option_Some (AuthFinishFailure_CredentialCorrupt <: t_AuthFinishFailure)
        <:
        Core_models.Option.t_Option t_AuthFinishFailure
      | StoredCredentialObservation_Missing  ->
        Core_models.Option.Option_Some (AuthFinishFailure_CredentialMissing <: t_AuthFinishFailure)
        <:
        Core_models.Option.t_Option t_AuthFinishFailure
      | StoredCredentialObservation_Present  ->
        if ~.observation.f_attempt_id_present
        then
          Core_models.Option.Option_Some (AuthFinishFailure_AttemptIdMissing <: t_AuthFinishFailure)
          <:
          Core_models.Option.t_Option t_AuthFinishFailure
        else Core_models.Option.Option_None <: Core_models.Option.t_Option t_AuthFinishFailure

/// Start a per-request WebAuthn recovery. The handler must count the attempt
/// before observing the account and before spending the challenge.
let begin_auth_finish (_: Prims.unit)
    : Prims.Pure t_AuthFinishTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_state_is_sound result.f_driver &&
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          ~.(auth_finish_effect_releases_share result.f_effect <: bool) &&
          (match result.f_driver.f_stage <: t_AuthFinishStage with
            | AuthFinishStage_Attempt  -> true
            | _ -> false) &&
          ~.result.f_driver.f_budget_counted &&
          ~.result.f_driver.f_attempt_consumed &&
          ~.result.f_driver.f_grant_issued &&
          ~.result.f_driver.f_grant_stored &&
          (match result.f_effect <: t_AuthFinishEffect with
            | AuthFinishEffect_CountAttempt  -> true
            | _ -> false)) =
  auth_finish_transition ({
        f_stage = AuthFinishStage_Attempt <: t_AuthFinishStage;
        f_budget_counted = false;
        f_context_observed = false;
        f_attempt_consumed = false;
        f_user_matches = false;
        f_attempt_matches = false;
        f_challenge_credential_matches = false;
        f_assertion_valid = false;
        f_user_verified = false;
        f_assertion_credential_matches = false;
        f_credential_update_needed = false;
        f_credential_updated = false;
        f_account_present = false;
        f_account_epoch_active = false;
        f_share_present = false;
        f_stored_credential_matches = false;
        f_stored_epoch = Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
        f_grant_issued = false;
        f_share_decoded = false;
        f_grant_stored = false
      }
      <:
      t_AuthFinishDriver)
    (AuthFinishEffect_CountAttempt <: t_AuthFinishEffect)

let apply_auth_finish_attempt_counted
      (driver: t_AuthFinishDriver)
      (observation: t_AttemptBudgetObservation)
    : t_AuthFinishTransition =
  match observation <: t_AttemptBudgetObservation with
  | AttemptBudgetObservation_Admitted  ->
    auth_finish_transition ({
          driver with
          f_stage = AuthFinishStage_Context <: t_AuthFinishStage;
          f_budget_counted = true
        }
        <:
        t_AuthFinishDriver)
      (AuthFinishEffect_ObserveContext <: t_AuthFinishEffect)
  | AttemptBudgetObservation_Limited  ->
    auth_finish_terminal driver (AuthFinishFailure_AttemptLimited <: t_AuthFinishFailure)

let apply_auth_finish_context_observed
      (driver: t_AuthFinishDriver)
      (observation: t_AuthFinishContextObservation)
    : t_AuthFinishTransition =
  if
    ~.observation.f_account_present || ~.observation.f_share_present ||
    ~.(match observation.f_credential <: t_StoredCredentialObservation with
      | StoredCredentialObservation_Present  -> true
      | _ -> false) ||
    ~.observation.f_attempt_id_present
  then
    let failure:t_AuthFinishFailure =
      Core_models.Option.impl__unwrap_or #t_AuthFinishFailure
        (auth_finish_context_rejection observation
          <:
          Core_models.Option.t_Option t_AuthFinishFailure)
        (AuthFinishFailure_PolicyRejected <: t_AuthFinishFailure)
    in
    auth_finish_terminal driver failure
  else
    auth_finish_transition ({
          driver with
          f_stage = AuthFinishStage_Consume <: t_AuthFinishStage;
          f_context_observed = true
        }
        <:
        t_AuthFinishDriver)
      (AuthFinishEffect_ConsumeAttempt <: t_AuthFinishEffect)

let apply_auth_attempt_consumed
      (driver: t_AuthFinishDriver)
      (observation: t_AuthAttemptConsumptionObservation)
    : t_AuthFinishTransition =
  match observation <: t_AuthAttemptConsumptionObservation with
  | AuthAttemptConsumptionObservation_Missing  ->
    auth_finish_terminal driver (AuthFinishFailure_AttemptMissing <: t_AuthFinishFailure)
  | AuthAttemptConsumptionObservation_Corrupt  ->
    auth_finish_terminal ({ driver with f_attempt_consumed = true } <: t_AuthFinishDriver)
      (AuthFinishFailure_AttemptCorrupt <: t_AuthFinishFailure)
  | AuthAttemptConsumptionObservation_Present
    { f_user_matches = user_matches ;
      f_attempt_matches = attempt_matches ;
      f_credential_matches = credential_matches } ->
    let consumed:t_AuthFinishDriver =
      {
        driver with
        f_attempt_consumed = true;
        f_user_matches = user_matches;
        f_attempt_matches = attempt_matches;
        f_challenge_credential_matches = credential_matches
      }
      <:
      t_AuthFinishDriver
    in
    if user_matches && attempt_matches
    then
      if credential_matches
      then
        auth_finish_transition ({
              consumed with
              f_stage = AuthFinishStage_Verify <: t_AuthFinishStage
            }
            <:
            t_AuthFinishDriver)
          (AuthFinishEffect_VerifyAssertion <: t_AuthFinishEffect)
      else
        auth_finish_terminal consumed
          (AuthFinishFailure_ChallengeCredentialReplaced <: t_AuthFinishFailure)
    else auth_finish_terminal consumed (AuthFinishFailure_BindingMismatch <: t_AuthFinishFailure)

let apply_auth_assertion_observed (driver: t_AuthFinishDriver) (observation: t_AssertionObservation)
    : t_AuthFinishTransition =
  if ~.observation.f_assertion_valid
  then auth_finish_terminal driver (AuthFinishFailure_AssertionInvalid <: t_AuthFinishFailure)
  else
    let verified:t_AuthFinishDriver =
      { driver with f_assertion_valid = true; f_user_verified = observation.f_user_verified }
      <:
      t_AuthFinishDriver
    in
    if ~.observation.f_user_verified
    then
      auth_finish_terminal verified
        (AuthFinishFailure_UserVerificationRequired <: t_AuthFinishFailure)
    else
      let update_facts:Vela_recovery_policy.t_CredentialUpdateFacts =
        Vela_recovery_policy.credential_update_facts ({
              Vela_recovery_policy.f_assertion_valid = true;
              Vela_recovery_policy.f_credential_matches_current = observation.f_credential_matches;
              Vela_recovery_policy.f_needs_update = observation.f_needs_update
            }
            <:
            Vela_recovery_policy.t_CredentialUpdateObservation)
      in
      match
        Vela_recovery_policy.plan_credential_update update_facts
        <:
        Vela_recovery_policy.t_CredentialUpdateDecision
      with
      | Vela_recovery_policy.CredentialUpdateDecision_Reject  ->
        auth_finish_terminal ({
              verified with
              f_assertion_credential_matches = false;
              f_credential_update_needed = observation.f_needs_update
            }
            <:
            t_AuthFinishDriver)
          (AuthFinishFailure_AssertionCredentialMismatch <: t_AuthFinishFailure)
      | Vela_recovery_policy.CredentialUpdateDecision_Update  ->
        auth_finish_transition ({
              verified with
              f_stage = AuthFinishStage_Update <: t_AuthFinishStage;
              f_assertion_credential_matches = true;
              f_credential_update_needed = true
            }
            <:
            t_AuthFinishDriver)
          (AuthFinishEffect_UpdateCredential <: t_AuthFinishEffect)
      | Vela_recovery_policy.CredentialUpdateDecision_Keep  ->
        auth_finish_transition ({
              verified with
              f_stage = AuthFinishStage_Account <: t_AuthFinishStage;
              f_assertion_credential_matches = true;
              f_credential_update_needed = false
            }
            <:
            t_AuthFinishDriver)
          (AuthFinishEffect_QueryAccount <: t_AuthFinishEffect)

let apply_auth_credential_updated
      (driver: t_AuthFinishDriver)
      (observation: t_CredentialUpdateStoreObservation)
    : t_AuthFinishTransition =
  match observation <: t_CredentialUpdateStoreObservation with
  | CredentialUpdateStoreObservation_Updated  ->
    auth_finish_transition ({
          driver with
          f_stage = AuthFinishStage_Account <: t_AuthFinishStage;
          f_credential_updated = true
        }
        <:
        t_AuthFinishDriver)
      (AuthFinishEffect_QueryAccount <: t_AuthFinishEffect)
  | CredentialUpdateStoreObservation_Changed  ->
    auth_finish_terminal driver (AuthFinishFailure_CredentialUpdateMismatch <: t_AuthFinishFailure)

let apply_auth_account_observed (driver: t_AuthFinishDriver) (observation: t_AuthAccountObservation)
    : t_AuthFinishTransition =
  if ~.observation.f_account_present
  then auth_finish_terminal driver (AuthFinishFailure_AccountAbsent <: t_AuthFinishFailure)
  else
    let credential_matches_current:bool =
      driver.f_challenge_credential_matches && driver.f_assertion_credential_matches &&
      observation.f_stored_credential_matches
    in
    let facts:Vela_recovery_policy.t_RecoverFacts =
      Vela_recovery_policy.recover_facts ({
            Vela_recovery_policy.f_attempt_source
            =
            Vela_recovery_policy.RecoveryAttemptSource_Consumed
            <:
            Vela_recovery_policy.t_RecoveryAttemptSource;
            Vela_recovery_policy.f_user_matches = driver.f_user_matches;
            Vela_recovery_policy.f_attempt_matches = driver.f_attempt_matches;
            Vela_recovery_policy.f_credential_matches_current = credential_matches_current;
            Vela_recovery_policy.f_assertion_valid = driver.f_assertion_valid;
            Vela_recovery_policy.f_user_verified = driver.f_user_verified;
            Vela_recovery_policy.f_share_present = observation.f_share_present;
            Vela_recovery_policy.f_account_epoch_active = observation.f_account_epoch_active;
            Vela_recovery_policy.f_stored_epoch = observation.f_stored_epoch
          }
          <:
          Vela_recovery_policy.t_RecoverObservation)
    in
    match Vela_recovery_policy.plan_recovery facts <: Vela_recovery_policy.t_RecoverDecision with
    | Vela_recovery_policy.RecoverDecision_Release permit ->
      let _:Prims.unit =
        if true
        then
          let _:Prims.unit =
            Hax_lib.v_assert (Vela_recovery_policy.impl_ReleasePermit__issues_single_use_grant permit

                <:
                bool)
          in
          ()
      in
      auth_finish_transition ({
            driver with
            f_stage = AuthFinishStage_Release <: t_AuthFinishStage;
            f_account_present = true;
            f_account_epoch_active = true;
            f_share_present = true;
            f_stored_credential_matches = true;
            f_stored_epoch = observation.f_stored_epoch;
            f_grant_issued = true
          }
          <:
          t_AuthFinishDriver)
        (AuthFinishEffect_ReleaseGrant
          ({ f_epoch = Vela_recovery_policy.impl_ReleasePermit__epoch permit <: i64 }
            <:
            t_AuthFinishGrantPermit)
          <:
          t_AuthFinishEffect)
    | Vela_recovery_policy.RecoverDecision_Reject  ->
      if ~.observation.f_account_epoch_active
      then auth_finish_terminal driver (AuthFinishFailure_RotationPaused <: t_AuthFinishFailure)
      else
        if ~.observation.f_stored_credential_matches
        then
          auth_finish_terminal driver
            (AuthFinishFailure_StoredCredentialMismatch <: t_AuthFinishFailure)
        else
          if ~.observation.f_share_present
          then auth_finish_terminal driver (AuthFinishFailure_ShareMissing <: t_AuthFinishFailure)
          else auth_finish_terminal driver (AuthFinishFailure_PolicyRejected <: t_AuthFinishFailure)

let apply_share_observed (driver: t_AuthFinishDriver) (observation: t_ShareDecodeObservation)
    : t_AuthFinishTransition =
  match observation <: t_ShareDecodeObservation with
  | ShareDecodeObservation_Decoded  ->
    auth_finish_transition ({
          driver with
          f_stage = AuthFinishStage_Store <: t_AuthFinishStage;
          f_share_decoded = true
        }
        <:
        t_AuthFinishDriver)
      (AuthFinishEffect_StoreGrant <: t_AuthFinishEffect)
  | ShareDecodeObservation_Corrupt  ->
    auth_finish_terminal driver (AuthFinishFailure_ShareCorrupt <: t_AuthFinishFailure)

let apply_auth_grant_stored (driver: t_AuthFinishDriver) (observation: t_GrantStoreObservation)
    : t_AuthFinishTransition =
  match observation <: t_GrantStoreObservation with
  | GrantStoreObservation_Stored  ->
    auth_finish_transition ({
          driver with
          f_stage = AuthFinishStage_Done <: t_AuthFinishStage;
          f_grant_stored = true
        }
        <:
        t_AuthFinishDriver)
      (AuthFinishEffect_Complete <: t_AuthFinishEffect)
  | GrantStoreObservation_Failed  ->
    auth_finish_terminal driver (AuthFinishFailure_GrantStorage <: t_AuthFinishFailure)

/// The complete, total authentication-finish transition relation. Events that
/// do not match the current stage (and every event after `Done`) are ignored.
let step_auth_finish (driver: t_AuthFinishDriver) (event: t_AuthFinishEvent)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  match event <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Attempt  -> true
      | _ -> false
    then apply_auth_finish_attempt_counted driver observation
    else auth_finish_idle driver
  | AuthFinishEvent_ContextObserved observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Context  -> true
      | _ -> false
    then apply_auth_finish_context_observed driver observation
    else auth_finish_idle driver
  | AuthFinishEvent_AttemptConsumed observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Consume  -> true
      | _ -> false
    then apply_auth_attempt_consumed driver observation
    else auth_finish_idle driver
  | AuthFinishEvent_AssertionObserved observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Verify  -> true
      | _ -> false
    then apply_auth_assertion_observed driver observation
    else auth_finish_idle driver
  | AuthFinishEvent_CredentialUpdated observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Update  -> true
      | _ -> false
    then apply_auth_credential_updated driver observation
    else auth_finish_idle driver
  | AuthFinishEvent_AccountObserved observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Account  -> true
      | _ -> false
    then apply_auth_account_observed driver observation
    else auth_finish_idle driver
  | AuthFinishEvent_ShareObserved observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Release  -> true
      | _ -> false
    then apply_share_observed driver observation
    else auth_finish_idle driver
  | AuthFinishEvent_GrantStored observation ->
    if
      match driver.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Store  -> true
      | _ -> false
    then apply_auth_grant_stored driver observation
    else auth_finish_idle driver
