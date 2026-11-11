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

/// Outcome of the challenge-state write. `Stored` means this request wrote the
/// slot, `Lost` means another writer won an `set_ex_nx` slot first, and
/// `StorageFailed` means the store call itself returned an error.
type t_ChallengeStoreObservation =
  | ChallengeStoreObservation_Stored : t_ChallengeStoreObservation
  | ChallengeStoreObservation_Lost : t_ChallengeStoreObservation
  | ChallengeStoreObservation_StorageFailed : t_ChallengeStoreObservation

/// Outcome of the rate-limit attempt count.
type t_AttemptBudgetObservation =
  | AttemptBudgetObservation_Admitted : t_AttemptBudgetObservation
  | AttemptBudgetObservation_Limited : t_AttemptBudgetObservation

/// Outcome of the single-use grant store.
type t_GrantStoreObservation =
  | GrantStoreObservation_Stored : t_GrantStoreObservation
  | GrantStoreObservation_Failed : t_GrantStoreObservation

/// Where the registration-ceremony start is in its decision sequence.
type t_RegistrationStartStage =
  | RegistrationStartStage_Observe : t_RegistrationStartStage
  | RegistrationStartStage_Ceremony : t_RegistrationStartStage
  | RegistrationStartStage_Store : t_RegistrationStartStage
  | RegistrationStartStage_Done : t_RegistrationStartStage

/// Raw observation from the stored-credential lookup.
type t_RegistrationStartObservation = {
  f_account_present:bool;
  f_credential:t_StoredCredentialObservation
}

/// Outcome of `start_passkey_registration`.
type t_CeremonyStartObservation =
  | CeremonyStartObservation_Started : t_CeremonyStartObservation
  | CeremonyStartObservation_Failed : t_CeremonyStartObservation

/// One registration-start driver event.
type t_RegistrationStartEvent =
  | RegistrationStartEvent_Observed : t_RegistrationStartObservation -> t_RegistrationStartEvent
  | RegistrationStartEvent_CeremonyStarted : t_CeremonyStartObservation -> t_RegistrationStartEvent
  | RegistrationStartEvent_Stored : t_ChallengeStoreObservation -> t_RegistrationStartEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_RegistrationStartFailure =
  | RegistrationStartFailure_AccountUnavailable : t_RegistrationStartFailure
  | RegistrationStartFailure_CredentialCorrupt : t_RegistrationStartFailure
  | RegistrationStartFailure_CeremonyFailed : t_RegistrationStartFailure
  | RegistrationStartFailure_StateStorage : t_RegistrationStartFailure

/// The effect the handler must perform next.
type t_RegistrationStartEffect =
  | RegistrationStartEffect_Observe : t_RegistrationStartEffect
  | RegistrationStartEffect_StartCeremony : t_RegistrationStartEffect
  | RegistrationStartEffect_StoreState : t_RegistrationStartEffect
  | RegistrationStartEffect_Complete : t_RegistrationStartEffect
  | RegistrationStartEffect_Fail : t_RegistrationStartFailure -> t_RegistrationStartEffect
  | RegistrationStartEffect_Idle : t_RegistrationStartEffect

/// Per-request registration-start state.
type t_RegistrationStartDriver = {
  f_stage:t_RegistrationStartStage;
  f_authorized:bool;
  f_stored:bool
}

type t_RegistrationStartTransition = {
  f_driver:t_RegistrationStartDriver;
  f_effect:t_RegistrationStartEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let registration_start_state_is_sound (driver: t_RegistrationStartDriver) : bool =
  let observe_clean:bool = ~.driver.f_authorized && ~.driver.f_stored in
  let ceremony_clean:bool = driver.f_authorized && ~.driver.f_stored in
  (~.(match driver.f_stage <: t_RegistrationStartStage with
    | RegistrationStartStage_Observe  -> true
    | _ -> false) ||
  observe_clean) &&
  (~.(match driver.f_stage <: t_RegistrationStartStage with
    | RegistrationStartStage_Ceremony  -> true
    | _ -> false) ||
  ceremony_clean) &&
  (~.(match driver.f_stage <: t_RegistrationStartStage with
    | RegistrationStartStage_Store  -> true
    | _ -> false) ||
  ceremony_clean) &&
  (~.driver.f_stored || driver.f_authorized) &&
  (~.driver.f_stored ||
  (match driver.f_stage <: t_RegistrationStartStage with
    | RegistrationStartStage_Done  -> true
    | _ -> false))

/// Every registration-start effect agrees with the state it produces.
let registration_start_effect_is_sound
      (driver: t_RegistrationStartDriver)
      (v_effect: t_RegistrationStartEffect)
    : bool =
  match v_effect <: t_RegistrationStartEffect with
  | RegistrationStartEffect_Observe  ->
    (match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Observe  -> true
      | _ -> false) &&
    ~.driver.f_authorized &&
    ~.driver.f_stored
  | RegistrationStartEffect_StartCeremony  ->
    (match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Ceremony  -> true
      | _ -> false) &&
    driver.f_authorized &&
    ~.driver.f_stored
  | RegistrationStartEffect_StoreState  ->
    (match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Store  -> true
      | _ -> false) &&
    driver.f_authorized &&
    ~.driver.f_stored
  | RegistrationStartEffect_Complete  ->
    (match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Done  -> true
      | _ -> false) &&
    driver.f_stored
  | RegistrationStartEffect_Fail _ ->
    (match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Done  -> true
      | _ -> false) &&
    ~.driver.f_stored
  | RegistrationStartEffect_Idle  -> true

let registration_start_transition
      (driver: t_RegistrationStartDriver)
      (v_effect: t_RegistrationStartEffect)
    : t_RegistrationStartTransition =
  { f_driver = driver; f_effect = v_effect } <: t_RegistrationStartTransition

let registration_start_idle (driver: t_RegistrationStartDriver) : t_RegistrationStartTransition =
  registration_start_transition driver (RegistrationStartEffect_Idle <: t_RegistrationStartEffect)

let registration_start_terminal
      (driver: t_RegistrationStartDriver)
      (failure: t_RegistrationStartFailure)
    : t_RegistrationStartTransition =
  registration_start_transition ({
        driver with
        f_stage = RegistrationStartStage_Done <: t_RegistrationStartStage
      }
      <:
      t_RegistrationStartDriver)
    (RegistrationStartEffect_Fail failure <: t_RegistrationStartEffect)

/// Start a per-request recovery-credential registration. The handler may query
/// the currently stored credential next.
let begin_registration_start (_: Prims.unit)
    : Prims.Pure t_RegistrationStartTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RegistrationStartTransition = result in
          registration_start_state_is_sound result.f_driver &&
          registration_start_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_RegistrationStartStage with
            | RegistrationStartStage_Observe  -> true
            | _ -> false) &&
          ~.result.f_driver.f_authorized &&
          ~.result.f_driver.f_stored &&
          (match result.f_effect <: t_RegistrationStartEffect with
            | RegistrationStartEffect_Observe  -> true
            | _ -> false)) =
  registration_start_transition ({
        f_stage = RegistrationStartStage_Observe <: t_RegistrationStartStage;
        f_authorized = false;
        f_stored = false
      }
      <:
      t_RegistrationStartDriver)
    (RegistrationStartEffect_Observe <: t_RegistrationStartEffect)

let apply_registration_start_observed
      (driver: t_RegistrationStartDriver)
      (observation: t_RegistrationStartObservation)
    : t_RegistrationStartTransition =
  if ~.observation.f_account_present
  then
    registration_start_terminal driver
      (RegistrationStartFailure_AccountUnavailable <: t_RegistrationStartFailure)
  else
    match observation.f_credential <: t_StoredCredentialObservation with
    | StoredCredentialObservation_Corrupt  ->
      registration_start_terminal driver
        (RegistrationStartFailure_CredentialCorrupt <: t_RegistrationStartFailure)
    | StoredCredentialObservation_Missing
    | StoredCredentialObservation_Present  ->
      registration_start_transition ({
            driver with
            f_stage = RegistrationStartStage_Ceremony <: t_RegistrationStartStage;
            f_authorized = true
          }
          <:
          t_RegistrationStartDriver)
        (RegistrationStartEffect_StartCeremony <: t_RegistrationStartEffect)

let apply_registration_ceremony_started
      (driver: t_RegistrationStartDriver)
      (observation: t_CeremonyStartObservation)
    : t_RegistrationStartTransition =
  match observation <: t_CeremonyStartObservation with
  | CeremonyStartObservation_Started  ->
    registration_start_transition ({
          driver with
          f_stage = RegistrationStartStage_Store <: t_RegistrationStartStage
        }
        <:
        t_RegistrationStartDriver)
      (RegistrationStartEffect_StoreState <: t_RegistrationStartEffect)
  | CeremonyStartObservation_Failed  ->
    registration_start_terminal driver
      (RegistrationStartFailure_CeremonyFailed <: t_RegistrationStartFailure)

let apply_registration_start_stored
      (driver: t_RegistrationStartDriver)
      (observation: t_ChallengeStoreObservation)
    : t_RegistrationStartTransition =
  match observation <: t_ChallengeStoreObservation with
  | ChallengeStoreObservation_Stored  ->
    registration_start_transition ({
          driver with
          f_stage = RegistrationStartStage_Done <: t_RegistrationStartStage;
          f_stored = true
        }
        <:
        t_RegistrationStartDriver)
      (RegistrationStartEffect_Complete <: t_RegistrationStartEffect)
  | ChallengeStoreObservation_Lost
  | ChallengeStoreObservation_StorageFailed  ->
    registration_start_terminal driver
      (RegistrationStartFailure_StateStorage <: t_RegistrationStartFailure)

/// The complete, total registration-start transition relation. Events that do
/// not match the current stage (and every event after `Done`) are ignored.
let step_registration_start (driver: t_RegistrationStartDriver) (event: t_RegistrationStartEvent)
    : Prims.Pure t_RegistrationStartTransition
      (requires registration_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationStartTransition = result in
          registration_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_start_state_is_sound driver <: bool) ||
          registration_start_state_is_sound result.f_driver)) =
  match event <: t_RegistrationStartEvent with
  | RegistrationStartEvent_Observed observation ->
    if
      match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Observe  -> true
      | _ -> false
    then apply_registration_start_observed driver observation
    else registration_start_idle driver
  | RegistrationStartEvent_CeremonyStarted observation ->
    if
      match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Ceremony  -> true
      | _ -> false
    then apply_registration_ceremony_started driver observation
    else registration_start_idle driver
  | RegistrationStartEvent_Stored observation ->
    if
      match driver.f_stage <: t_RegistrationStartStage with
      | RegistrationStartStage_Store  -> true
      | _ -> false
    then apply_registration_start_stored driver observation
    else registration_start_idle driver

let on_registration_start_observed
      (driver: t_RegistrationStartDriver)
      (observation: t_RegistrationStartObservation)
    : Prims.Pure t_RegistrationStartTransition
      (requires registration_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationStartTransition = result in
          registration_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_start_state_is_sound driver <: bool) ||
          registration_start_state_is_sound result.f_driver)) =
  step_registration_start driver
    (RegistrationStartEvent_Observed observation <: t_RegistrationStartEvent)

let on_registration_ceremony_started
      (driver: t_RegistrationStartDriver)
      (observation: t_CeremonyStartObservation)
    : Prims.Pure t_RegistrationStartTransition
      (requires registration_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationStartTransition = result in
          registration_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_start_state_is_sound driver <: bool) ||
          registration_start_state_is_sound result.f_driver)) =
  step_registration_start driver
    (RegistrationStartEvent_CeremonyStarted observation <: t_RegistrationStartEvent)

let on_registration_start_stored
      (driver: t_RegistrationStartDriver)
      (observation: t_ChallengeStoreObservation)
    : Prims.Pure t_RegistrationStartTransition
      (requires registration_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationStartTransition = result in
          registration_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_start_state_is_sound driver <: bool) ||
          registration_start_state_is_sound result.f_driver)) =
  step_registration_start driver
    (RegistrationStartEvent_Stored observation <: t_RegistrationStartEvent)

/// Where the registration finish is in its decision sequence.
type t_RegistrationStage =
  | RegistrationStage_Attempt : t_RegistrationStage
  | RegistrationStage_Consume : t_RegistrationStage
  | RegistrationStage_Verify : t_RegistrationStage
  | RegistrationStage_Uniqueness : t_RegistrationStage
  | RegistrationStage_Persist : t_RegistrationStage
  | RegistrationStage_Done : t_RegistrationStage

/// Outcome of the atomic single-use registration-state consumption.
type t_RegistrationStateObservation =
  | RegistrationStateObservation_Missing : t_RegistrationStateObservation
  | RegistrationStateObservation_Corrupt : t_RegistrationStateObservation
  | RegistrationStateObservation_Present : t_RegistrationStateObservation

/// Authenticated outcome of `finish_passkey_registration`.
type t_RegistrationVerificationObservation = { f_credential_valid:bool }

/// Outcome of the cross-account duplicate-credential lookup.
type t_CredentialUniquenessObservation =
  | CredentialUniquenessObservation_Unique : t_CredentialUniquenessObservation
  | CredentialUniquenessObservation_RegisteredElsewhere : t_CredentialUniquenessObservation
  | CredentialUniquenessObservation_LookupFailed : t_CredentialUniquenessObservation

/// Outcome of the guarded credential write. `AccountGone` is a zero-row
/// `UPDATE`; `EncodingFailed` is a serialization failure before the write;
/// `StorageFailed` is a database error.
type t_CredentialPersistObservation =
  | CredentialPersistObservation_Persisted : t_CredentialPersistObservation
  | CredentialPersistObservation_AccountGone : t_CredentialPersistObservation
  | CredentialPersistObservation_EncodingFailed : t_CredentialPersistObservation
  | CredentialPersistObservation_StorageFailed : t_CredentialPersistObservation

/// One registration-finish driver event.
type t_RegistrationEvent =
  | RegistrationEvent_AttemptCounted : t_AttemptBudgetObservation -> t_RegistrationEvent
  | RegistrationEvent_StateConsumed : t_RegistrationStateObservation -> t_RegistrationEvent
  | RegistrationEvent_RegistrationVerified : t_RegistrationVerificationObservation
    -> t_RegistrationEvent
  | RegistrationEvent_CredentialLookedUp : t_CredentialUniquenessObservation -> t_RegistrationEvent
  | RegistrationEvent_CredentialPersisted : t_CredentialPersistObservation -> t_RegistrationEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_RegistrationFailure =
  | RegistrationFailure_AttemptLimited : t_RegistrationFailure
  | RegistrationFailure_StateUnavailable : t_RegistrationFailure
  | RegistrationFailure_StateCorrupt : t_RegistrationFailure
  | RegistrationFailure_VerificationFailed : t_RegistrationFailure
  | RegistrationFailure_UniquenessConflict : t_RegistrationFailure
  | RegistrationFailure_UniquenessStorage : t_RegistrationFailure
  | RegistrationFailure_PolicyRejected : t_RegistrationFailure
  | RegistrationFailure_AccountGone : t_RegistrationFailure
  | RegistrationFailure_PersistEncoding : t_RegistrationFailure
  | RegistrationFailure_PersistStorage : t_RegistrationFailure

/// The effect the handler must perform next.
type t_RegistrationEffect =
  | RegistrationEffect_CountAttempt : t_RegistrationEffect
  | RegistrationEffect_ConsumeState : t_RegistrationEffect
  | RegistrationEffect_VerifyRegistration : t_RegistrationEffect
  | RegistrationEffect_CheckCredentialUniqueness : t_RegistrationEffect
  | RegistrationEffect_PersistCredential : t_RegistrationEffect
  | RegistrationEffect_Complete : t_RegistrationEffect
  | RegistrationEffect_Fail : t_RegistrationFailure -> t_RegistrationEffect
  | RegistrationEffect_Idle : t_RegistrationEffect

/// Per-request registration-finish state. Every field is a decision fact
/// established by a prior transition.
type t_RegistrationDriver = {
  f_stage:t_RegistrationStage;
  f_budget_counted:bool;
  f_state_consumed:bool;
  f_credential_valid:bool;
  f_credential_unique:bool;
  f_permit_issued:bool;
  f_credential_stored:bool
}

type t_RegistrationTransition = {
  f_driver:t_RegistrationDriver;
  f_effect:t_RegistrationEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let registration_state_is_sound (driver: t_RegistrationDriver) : bool =
  let attempt_clean:bool =
    ~.driver.f_budget_counted && ~.driver.f_state_consumed && ~.driver.f_credential_valid &&
    ~.driver.f_credential_unique &&
    ~.driver.f_permit_issued &&
    ~.driver.f_credential_stored
  in
  let consume_clean:bool =
    driver.f_budget_counted && ~.driver.f_state_consumed && ~.driver.f_credential_valid &&
    ~.driver.f_credential_unique &&
    ~.driver.f_permit_issued &&
    ~.driver.f_credential_stored
  in
  let verify_clean:bool =
    driver.f_budget_counted && driver.f_state_consumed && ~.driver.f_credential_valid &&
    ~.driver.f_credential_unique &&
    ~.driver.f_permit_issued &&
    ~.driver.f_credential_stored
  in
  let uniqueness_clean:bool =
    driver.f_budget_counted && driver.f_state_consumed && driver.f_credential_valid &&
    ~.driver.f_credential_unique &&
    ~.driver.f_permit_issued &&
    ~.driver.f_credential_stored
  in
  let persist_clean:bool =
    driver.f_budget_counted && driver.f_state_consumed && driver.f_credential_valid &&
    driver.f_credential_unique &&
    driver.f_permit_issued &&
    ~.driver.f_credential_stored
  in
  (~.(match driver.f_stage <: t_RegistrationStage with
    | RegistrationStage_Attempt  -> true
    | _ -> false) ||
  attempt_clean) &&
  (~.(match driver.f_stage <: t_RegistrationStage with
    | RegistrationStage_Consume  -> true
    | _ -> false) ||
  consume_clean) &&
  (~.(match driver.f_stage <: t_RegistrationStage with
    | RegistrationStage_Verify  -> true
    | _ -> false) ||
  verify_clean) &&
  (~.(match driver.f_stage <: t_RegistrationStage with
    | RegistrationStage_Uniqueness  -> true
    | _ -> false) ||
  uniqueness_clean) &&
  (~.(match driver.f_stage <: t_RegistrationStage with
    | RegistrationStage_Persist  -> true
    | _ -> false) ||
  persist_clean) &&
  (~.driver.f_state_consumed || driver.f_budget_counted) &&
  (~.driver.f_credential_valid || driver.f_state_consumed) &&
  (~.driver.f_credential_unique || driver.f_credential_valid) &&
  (~.driver.f_permit_issued || driver.f_credential_valid && driver.f_credential_unique) &&
  (~.driver.f_credential_stored ||
  driver.f_permit_issued &&
  (match driver.f_stage <: t_RegistrationStage with
    | RegistrationStage_Done  -> true
    | _ -> false))

/// Every registration effect agrees with the state it produces. In particular
/// `PersistCredential` is only emitted after the checked policy's permit.
let registration_effect_is_sound (driver: t_RegistrationDriver) (v_effect: t_RegistrationEffect)
    : bool =
  match v_effect <: t_RegistrationEffect with
  | RegistrationEffect_CountAttempt  ->
    (match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Attempt  -> true
      | _ -> false) &&
    ~.driver.f_budget_counted &&
    ~.driver.f_state_consumed &&
    ~.driver.f_permit_issued
  | RegistrationEffect_ConsumeState  ->
    (match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Consume  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    ~.driver.f_state_consumed
  | RegistrationEffect_VerifyRegistration  ->
    (match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Verify  -> true
      | _ -> false) &&
    driver.f_state_consumed &&
    ~.driver.f_credential_valid &&
    ~.driver.f_permit_issued
  | RegistrationEffect_CheckCredentialUniqueness  ->
    (match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Uniqueness  -> true
      | _ -> false) &&
    driver.f_credential_valid &&
    ~.driver.f_credential_unique &&
    ~.driver.f_permit_issued
  | RegistrationEffect_PersistCredential  ->
    (match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Persist  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    driver.f_state_consumed &&
    driver.f_credential_valid &&
    driver.f_credential_unique &&
    driver.f_permit_issued &&
    ~.driver.f_credential_stored
  | RegistrationEffect_Complete  ->
    (match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Done  -> true
      | _ -> false) &&
    driver.f_credential_stored
  | RegistrationEffect_Fail _ ->
    (match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Done  -> true
      | _ -> false) &&
    ~.driver.f_credential_stored
  | RegistrationEffect_Idle  -> true

let registration_transition (driver: t_RegistrationDriver) (v_effect: t_RegistrationEffect)
    : t_RegistrationTransition =
  { f_driver = driver; f_effect = v_effect } <: t_RegistrationTransition

let registration_idle (driver: t_RegistrationDriver) : t_RegistrationTransition =
  registration_transition driver (RegistrationEffect_Idle <: t_RegistrationEffect)

let registration_terminal (driver: t_RegistrationDriver) (failure: t_RegistrationFailure)
    : t_RegistrationTransition =
  registration_transition ({ driver with f_stage = RegistrationStage_Done <: t_RegistrationStage }
      <:
      t_RegistrationDriver)
    (RegistrationEffect_Fail failure <: t_RegistrationEffect)

/// Start a per-request registration finish. The handler must count the attempt
/// before touching the single-use registration state.
let begin_registration (_: Prims.unit)
    : Prims.Pure t_RegistrationTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_state_is_sound result.f_driver &&
          registration_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_RegistrationStage with
            | RegistrationStage_Attempt  -> true
            | _ -> false) &&
          ~.result.f_driver.f_budget_counted &&
          ~.result.f_driver.f_state_consumed &&
          ~.result.f_driver.f_credential_stored &&
          (match result.f_effect <: t_RegistrationEffect with
            | RegistrationEffect_CountAttempt  -> true
            | _ -> false)) =
  registration_transition ({
        f_stage = RegistrationStage_Attempt <: t_RegistrationStage;
        f_budget_counted = false;
        f_state_consumed = false;
        f_credential_valid = false;
        f_credential_unique = false;
        f_permit_issued = false;
        f_credential_stored = false
      }
      <:
      t_RegistrationDriver)
    (RegistrationEffect_CountAttempt <: t_RegistrationEffect)

let apply_registration_attempt_counted
      (driver: t_RegistrationDriver)
      (observation: t_AttemptBudgetObservation)
    : t_RegistrationTransition =
  match observation <: t_AttemptBudgetObservation with
  | AttemptBudgetObservation_Admitted  ->
    registration_transition ({
          driver with
          f_stage = RegistrationStage_Consume <: t_RegistrationStage;
          f_budget_counted = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_ConsumeState <: t_RegistrationEffect)
  | AttemptBudgetObservation_Limited  ->
    registration_terminal driver (RegistrationFailure_AttemptLimited <: t_RegistrationFailure)

let apply_registration_state_consumed
      (driver: t_RegistrationDriver)
      (observation: t_RegistrationStateObservation)
    : t_RegistrationTransition =
  match observation <: t_RegistrationStateObservation with
  | RegistrationStateObservation_Missing  ->
    registration_terminal driver (RegistrationFailure_StateUnavailable <: t_RegistrationFailure)
  | RegistrationStateObservation_Corrupt  ->
    registration_terminal driver (RegistrationFailure_StateCorrupt <: t_RegistrationFailure)
  | RegistrationStateObservation_Present  ->
    registration_transition ({
          driver with
          f_stage = RegistrationStage_Verify <: t_RegistrationStage;
          f_state_consumed = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_VerifyRegistration <: t_RegistrationEffect)

let apply_registration_verified
      (driver: t_RegistrationDriver)
      (observation: t_RegistrationVerificationObservation)
    : t_RegistrationTransition =
  if ~.observation.f_credential_valid
  then
    registration_terminal driver (RegistrationFailure_VerificationFailed <: t_RegistrationFailure)
  else
    registration_transition ({
          driver with
          f_stage = RegistrationStage_Uniqueness <: t_RegistrationStage;
          f_credential_valid = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_CheckCredentialUniqueness <: t_RegistrationEffect)

let apply_credential_looked_up
      (driver: t_RegistrationDriver)
      (observation: t_CredentialUniquenessObservation)
    : t_RegistrationTransition =
  match observation <: t_CredentialUniquenessObservation with
  | CredentialUniquenessObservation_LookupFailed  ->
    registration_terminal driver (RegistrationFailure_UniquenessStorage <: t_RegistrationFailure)
  | CredentialUniquenessObservation_RegisteredElsewhere  ->
    registration_terminal driver (RegistrationFailure_UniquenessConflict <: t_RegistrationFailure)
  | CredentialUniquenessObservation_Unique  ->
    match
      Vela_recovery_policy.plan_registration ({
            Vela_recovery_policy.f_device_scope = true;
            Vela_recovery_policy.f_account_matches = true;
            Vela_recovery_policy.f_challenge_pending = driver.f_state_consumed;
            Vela_recovery_policy.f_challenge_consumed = driver.f_state_consumed;
            Vela_recovery_policy.f_credential_valid = driver.f_credential_valid;
            Vela_recovery_policy.f_credential_unique = true
          }
          <:
          Vela_recovery_policy.t_RegistrationFacts)
      <:
      Vela_recovery_policy.t_RegistrationDecision
    with
    | Vela_recovery_policy.RegistrationDecision_Register e_permit ->
      registration_transition ({
            driver with
            f_stage = RegistrationStage_Persist <: t_RegistrationStage;
            f_credential_unique = true;
            f_permit_issued = true
          }
          <:
          t_RegistrationDriver)
        (RegistrationEffect_PersistCredential <: t_RegistrationEffect)
    | Vela_recovery_policy.RegistrationDecision_Reject  ->
      registration_terminal driver (RegistrationFailure_PolicyRejected <: t_RegistrationFailure)

let apply_credential_persisted
      (driver: t_RegistrationDriver)
      (observation: t_CredentialPersistObservation)
    : t_RegistrationTransition =
  match observation <: t_CredentialPersistObservation with
  | CredentialPersistObservation_Persisted  ->
    registration_transition ({
          driver with
          f_stage = RegistrationStage_Done <: t_RegistrationStage;
          f_credential_stored = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_Complete <: t_RegistrationEffect)
  | CredentialPersistObservation_AccountGone  ->
    registration_terminal driver (RegistrationFailure_AccountGone <: t_RegistrationFailure)
  | CredentialPersistObservation_EncodingFailed  ->
    registration_terminal driver (RegistrationFailure_PersistEncoding <: t_RegistrationFailure)
  | CredentialPersistObservation_StorageFailed  ->
    registration_terminal driver (RegistrationFailure_PersistStorage <: t_RegistrationFailure)

/// The complete, total registration-finish transition relation. Events that do
/// not match the current stage (and every event after `Done`) are ignored.
let step_registration (driver: t_RegistrationDriver) (event: t_RegistrationEvent)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match event <: t_RegistrationEvent with
  | RegistrationEvent_AttemptCounted observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Attempt  -> true
      | _ -> false
    then apply_registration_attempt_counted driver observation
    else registration_idle driver
  | RegistrationEvent_StateConsumed observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Consume  -> true
      | _ -> false
    then apply_registration_state_consumed driver observation
    else registration_idle driver
  | RegistrationEvent_RegistrationVerified observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Verify  -> true
      | _ -> false
    then apply_registration_verified driver observation
    else registration_idle driver
  | RegistrationEvent_CredentialLookedUp observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Uniqueness  -> true
      | _ -> false
    then apply_credential_looked_up driver observation
    else registration_idle driver
  | RegistrationEvent_CredentialPersisted observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Persist  -> true
      | _ -> false
    then apply_credential_persisted driver observation
    else registration_idle driver

let on_registration_attempt_counted
      (driver: t_RegistrationDriver)
      (observation: t_AttemptBudgetObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step_registration driver (RegistrationEvent_AttemptCounted observation <: t_RegistrationEvent)

let on_registration_state_consumed
      (driver: t_RegistrationDriver)
      (observation: t_RegistrationStateObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step_registration driver (RegistrationEvent_StateConsumed observation <: t_RegistrationEvent)

let on_registration_verified
      (driver: t_RegistrationDriver)
      (observation: t_RegistrationVerificationObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step_registration driver
    (RegistrationEvent_RegistrationVerified observation <: t_RegistrationEvent)

let on_credential_looked_up
      (driver: t_RegistrationDriver)
      (observation: t_CredentialUniquenessObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step_registration driver (RegistrationEvent_CredentialLookedUp observation <: t_RegistrationEvent)

let on_credential_persisted
      (driver: t_RegistrationDriver)
      (observation: t_CredentialPersistObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step_registration driver
    (RegistrationEvent_CredentialPersisted observation <: t_RegistrationEvent)

/// Where the authentication-challenge initiation is in its decision sequence.
type t_AuthStartStage =
  | AuthStartStage_Observe : t_AuthStartStage
  | AuthStartStage_Ceremony : t_AuthStartStage
  | AuthStartStage_Store : t_AuthStartStage
  | AuthStartStage_Done : t_AuthStartStage

/// Raw observations from the availability query, the credential decode and the
/// fresh-slot probe.
type t_AuthStartObservation = {
  f_account_present:bool;
  f_share_present:bool;
  f_credential:t_StoredCredentialObservation;
  f_attempt_id_fresh:bool;
  f_ttl_secs:u64
}

/// One authentication-start driver event.
type t_AuthStartEvent =
  | AuthStartEvent_Observed : t_AuthStartObservation -> t_AuthStartEvent
  | AuthStartEvent_CeremonyStarted : t_CeremonyStartObservation -> t_AuthStartEvent
  | AuthStartEvent_Stored : t_ChallengeStoreObservation -> t_AuthStartEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_AuthStartFailure =
  | AuthStartFailure_AccountUnavailable : t_AuthStartFailure
  | AuthStartFailure_ShareMissing : t_AuthStartFailure
  | AuthStartFailure_CredentialMissing : t_AuthStartFailure
  | AuthStartFailure_CredentialCorrupt : t_AuthStartFailure
  | AuthStartFailure_AttemptCollision : t_AuthStartFailure
  | AuthStartFailure_CeremonyFailed : t_AuthStartFailure
  | AuthStartFailure_PolicyRejected : t_AuthStartFailure
  | AuthStartFailure_StateStorage : t_AuthStartFailure

/// The effect the handler must perform next.
type t_AuthStartEffect =
  | AuthStartEffect_Observe : t_AuthStartEffect
  | AuthStartEffect_StartCeremony : t_AuthStartEffect
  | AuthStartEffect_StoreChallenge : t_AuthStartEffect
  | AuthStartEffect_Complete : t_AuthStartEffect
  | AuthStartEffect_Fail : t_AuthStartFailure -> t_AuthStartEffect
  | AuthStartEffect_Idle : t_AuthStartEffect

/// Per-request authentication-start state.
type t_AuthStartDriver = {
  f_stage:t_AuthStartStage;
  f_authorized:bool;
  f_stored:bool
}

type t_AuthStartTransition = {
  f_driver:t_AuthStartDriver;
  f_effect:t_AuthStartEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let auth_start_state_is_sound (driver: t_AuthStartDriver) : bool =
  let observe_clean:bool = ~.driver.f_authorized && ~.driver.f_stored in
  let authorized_clean:bool = driver.f_authorized && ~.driver.f_stored in
  (~.(match driver.f_stage <: t_AuthStartStage with
    | AuthStartStage_Observe  -> true
    | _ -> false) ||
  observe_clean) &&
  (~.(match driver.f_stage <: t_AuthStartStage with
    | AuthStartStage_Ceremony  -> true
    | _ -> false) ||
  authorized_clean) &&
  (~.(match driver.f_stage <: t_AuthStartStage with
    | AuthStartStage_Store  -> true
    | _ -> false) ||
  authorized_clean) &&
  (~.driver.f_stored || driver.f_authorized) &&
  (~.driver.f_stored ||
  (match driver.f_stage <: t_AuthStartStage with
    | AuthStartStage_Done  -> true
    | _ -> false))

/// Every authentication-start effect agrees with the state it produces.
let auth_start_effect_is_sound (driver: t_AuthStartDriver) (v_effect: t_AuthStartEffect) : bool =
  match v_effect <: t_AuthStartEffect with
  | AuthStartEffect_Observe  ->
    (match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Observe  -> true
      | _ -> false) &&
    ~.driver.f_authorized &&
    ~.driver.f_stored
  | AuthStartEffect_StartCeremony  ->
    (match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Ceremony  -> true
      | _ -> false) &&
    driver.f_authorized &&
    ~.driver.f_stored
  | AuthStartEffect_StoreChallenge  ->
    (match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Store  -> true
      | _ -> false) &&
    driver.f_authorized &&
    ~.driver.f_stored
  | AuthStartEffect_Complete  ->
    (match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Done  -> true
      | _ -> false) &&
    driver.f_stored
  | AuthStartEffect_Fail _ ->
    (match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Done  -> true
      | _ -> false) &&
    ~.driver.f_stored
  | AuthStartEffect_Idle  -> true

let auth_start_transition (driver: t_AuthStartDriver) (v_effect: t_AuthStartEffect)
    : t_AuthStartTransition = { f_driver = driver; f_effect = v_effect } <: t_AuthStartTransition

let auth_start_idle (driver: t_AuthStartDriver) : t_AuthStartTransition =
  auth_start_transition driver (AuthStartEffect_Idle <: t_AuthStartEffect)

let auth_start_terminal (driver: t_AuthStartDriver) (failure: t_AuthStartFailure)
    : t_AuthStartTransition =
  auth_start_transition ({ driver with f_stage = AuthStartStage_Done <: t_AuthStartStage }
      <:
      t_AuthStartDriver)
    (AuthStartEffect_Fail failure <: t_AuthStartEffect)

/// The first rejection in the handler's historical status/message precedence,
/// or `None` when every preceding guard admitted the observation. The checked
/// policy is the authority; this helper only names the observed guard that
/// failed so the handler can render the original status and message.
let auth_start_rejection (observation: t_AuthStartObservation)
    : Core_models.Option.t_Option t_AuthStartFailure =
  if ~.observation.f_account_present
  then
    Core_models.Option.Option_Some (AuthStartFailure_AccountUnavailable <: t_AuthStartFailure)
    <:
    Core_models.Option.t_Option t_AuthStartFailure
  else
    if ~.observation.f_share_present
    then
      Core_models.Option.Option_Some (AuthStartFailure_ShareMissing <: t_AuthStartFailure)
      <:
      Core_models.Option.t_Option t_AuthStartFailure
    else
      match observation.f_credential <: t_StoredCredentialObservation with
      | StoredCredentialObservation_Corrupt  ->
        Core_models.Option.Option_Some (AuthStartFailure_CredentialCorrupt <: t_AuthStartFailure)
        <:
        Core_models.Option.t_Option t_AuthStartFailure
      | StoredCredentialObservation_Missing  ->
        Core_models.Option.Option_Some (AuthStartFailure_CredentialMissing <: t_AuthStartFailure)
        <:
        Core_models.Option.t_Option t_AuthStartFailure
      | StoredCredentialObservation_Present  ->
        if ~.observation.f_attempt_id_fresh
        then
          Core_models.Option.Option_Some (AuthStartFailure_AttemptCollision <: t_AuthStartFailure)
          <:
          Core_models.Option.t_Option t_AuthStartFailure
        else Core_models.Option.Option_None <: Core_models.Option.t_Option t_AuthStartFailure

/// Start a per-request authentication challenge. The handler may perform the
/// availability/credential/slot observation next.
let begin_auth_start (_: Prims.unit)
    : Prims.Pure t_AuthStartTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_AuthStartTransition = result in
          auth_start_state_is_sound result.f_driver &&
          auth_start_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_AuthStartStage with
            | AuthStartStage_Observe  -> true
            | _ -> false) &&
          ~.result.f_driver.f_authorized &&
          ~.result.f_driver.f_stored &&
          (match result.f_effect <: t_AuthStartEffect with
            | AuthStartEffect_Observe  -> true
            | _ -> false)) =
  auth_start_transition ({
        f_stage = AuthStartStage_Observe <: t_AuthStartStage;
        f_authorized = false;
        f_stored = false
      }
      <:
      t_AuthStartDriver)
    (AuthStartEffect_Observe <: t_AuthStartEffect)

let apply_auth_start_observed (driver: t_AuthStartDriver) (observation: t_AuthStartObservation)
    : t_AuthStartTransition =
  let credential_present:bool =
    match observation.f_credential <: t_StoredCredentialObservation with
    | StoredCredentialObservation_Present  -> true
    | _ -> false
  in
  let facts:Vela_recovery_policy.t_InitiateFacts =
    Vela_recovery_policy.initiate_facts ({
          Vela_recovery_policy.f_account_present = observation.f_account_present;
          Vela_recovery_policy.f_share_present = observation.f_share_present;
          Vela_recovery_policy.f_credential_present = credential_present;
          Vela_recovery_policy.f_attempt_id_fresh = observation.f_attempt_id_fresh;
          Vela_recovery_policy.f_ttl_secs = observation.f_ttl_secs
        }
        <:
        Vela_recovery_policy.t_InitiateObservation)
  in
  match Vela_recovery_policy.plan_initiation facts <: Vela_recovery_policy.t_InitiateDecision with
  | Vela_recovery_policy.InitiateDecision_Start e_permit ->
    auth_start_transition ({
          driver with
          f_stage = AuthStartStage_Ceremony <: t_AuthStartStage;
          f_authorized = true
        }
        <:
        t_AuthStartDriver)
      (AuthStartEffect_StartCeremony <: t_AuthStartEffect)
  | Vela_recovery_policy.InitiateDecision_Reject  ->
    let failure:t_AuthStartFailure =
      Core_models.Option.impl__unwrap_or #t_AuthStartFailure
        (auth_start_rejection observation <: Core_models.Option.t_Option t_AuthStartFailure)
        (AuthStartFailure_PolicyRejected <: t_AuthStartFailure)
    in
    auth_start_terminal driver failure

let apply_auth_ceremony_started
      (driver: t_AuthStartDriver)
      (observation: t_CeremonyStartObservation)
    : t_AuthStartTransition =
  match observation <: t_CeremonyStartObservation with
  | CeremonyStartObservation_Started  ->
    auth_start_transition ({ driver with f_stage = AuthStartStage_Store <: t_AuthStartStage }
        <:
        t_AuthStartDriver)
      (AuthStartEffect_StoreChallenge <: t_AuthStartEffect)
  | CeremonyStartObservation_Failed  ->
    auth_start_terminal driver (AuthStartFailure_CeremonyFailed <: t_AuthStartFailure)

let apply_auth_start_stored (driver: t_AuthStartDriver) (observation: t_ChallengeStoreObservation)
    : t_AuthStartTransition =
  match observation <: t_ChallengeStoreObservation with
  | ChallengeStoreObservation_Stored  ->
    auth_start_transition ({
          driver with
          f_stage = AuthStartStage_Done <: t_AuthStartStage;
          f_stored = true
        }
        <:
        t_AuthStartDriver)
      (AuthStartEffect_Complete <: t_AuthStartEffect)
  | ChallengeStoreObservation_Lost  ->
    auth_start_terminal driver (AuthStartFailure_AttemptCollision <: t_AuthStartFailure)
  | ChallengeStoreObservation_StorageFailed  ->
    auth_start_terminal driver (AuthStartFailure_StateStorage <: t_AuthStartFailure)

/// The complete, total authentication-start transition relation. Events that
/// do not match the current stage (and every event after `Done`) are ignored.
let step_auth_start (driver: t_AuthStartDriver) (event: t_AuthStartEvent)
    : Prims.Pure t_AuthStartTransition
      (requires auth_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthStartTransition = result in
          auth_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_start_state_is_sound driver <: bool) || auth_start_state_is_sound result.f_driver)
      ) =
  match event <: t_AuthStartEvent with
  | AuthStartEvent_Observed observation ->
    if
      match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Observe  -> true
      | _ -> false
    then apply_auth_start_observed driver observation
    else auth_start_idle driver
  | AuthStartEvent_CeremonyStarted observation ->
    if
      match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Ceremony  -> true
      | _ -> false
    then apply_auth_ceremony_started driver observation
    else auth_start_idle driver
  | AuthStartEvent_Stored observation ->
    if
      match driver.f_stage <: t_AuthStartStage with
      | AuthStartStage_Store  -> true
      | _ -> false
    then apply_auth_start_stored driver observation
    else auth_start_idle driver

let on_auth_start_observed (driver: t_AuthStartDriver) (observation: t_AuthStartObservation)
    : Prims.Pure t_AuthStartTransition
      (requires auth_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthStartTransition = result in
          auth_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_start_state_is_sound driver <: bool) || auth_start_state_is_sound result.f_driver)
      ) = step_auth_start driver (AuthStartEvent_Observed observation <: t_AuthStartEvent)

let on_auth_ceremony_started (driver: t_AuthStartDriver) (observation: t_CeremonyStartObservation)
    : Prims.Pure t_AuthStartTransition
      (requires auth_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthStartTransition = result in
          auth_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_start_state_is_sound driver <: bool) || auth_start_state_is_sound result.f_driver)
      ) = step_auth_start driver (AuthStartEvent_CeremonyStarted observation <: t_AuthStartEvent)

let on_auth_start_stored (driver: t_AuthStartDriver) (observation: t_ChallengeStoreObservation)
    : Prims.Pure t_AuthStartTransition
      (requires auth_start_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthStartTransition = result in
          auth_start_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_start_state_is_sound driver <: bool) || auth_start_state_is_sound result.f_driver)
      ) = step_auth_start driver (AuthStartEvent_Stored observation <: t_AuthStartEvent)

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

let on_auth_finish_attempt_counted
      (driver: t_AuthFinishDriver)
      (observation: t_AttemptBudgetObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_AttemptCounted observation <: t_AuthFinishEvent)

let on_auth_finish_context_observed
      (driver: t_AuthFinishDriver)
      (observation: t_AuthFinishContextObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_ContextObserved observation <: t_AuthFinishEvent)

let on_auth_attempt_consumed
      (driver: t_AuthFinishDriver)
      (observation: t_AuthAttemptConsumptionObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_AttemptConsumed observation <: t_AuthFinishEvent)

let on_auth_assertion_observed (driver: t_AuthFinishDriver) (observation: t_AssertionObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_AssertionObserved observation <: t_AuthFinishEvent)

let on_auth_credential_updated
      (driver: t_AuthFinishDriver)
      (observation: t_CredentialUpdateStoreObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_CredentialUpdated observation <: t_AuthFinishEvent)

let on_auth_account_observed (driver: t_AuthFinishDriver) (observation: t_AuthAccountObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_AccountObserved observation <: t_AuthFinishEvent)

let on_auth_share_observed (driver: t_AuthFinishDriver) (observation: t_ShareDecodeObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_ShareObserved observation <: t_AuthFinishEvent)

let on_auth_grant_stored (driver: t_AuthFinishDriver) (observation: t_GrantStoreObservation)
    : Prims.Pure t_AuthFinishTransition
      (requires auth_finish_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_AuthFinishTransition = result in
          auth_finish_effect_is_sound result.f_driver result.f_effect &&
          (~.(auth_finish_state_is_sound driver <: bool) ||
          auth_finish_state_is_sound result.f_driver)) =
  step_auth_finish driver (AuthFinishEvent_GrantStored observation <: t_AuthFinishEvent)
