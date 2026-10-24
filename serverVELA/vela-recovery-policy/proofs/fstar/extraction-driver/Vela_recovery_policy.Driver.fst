module Vela_recovery_policy.Driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Where the redemption is in its decision sequence.
type t_RedemptionStage =
  | RedemptionStage_Consume : t_RedemptionStage
  | RedemptionStage_FinalPolicy : t_RedemptionStage
  | RedemptionStage_Insert : t_RedemptionStage
  | RedemptionStage_Recheck : t_RedemptionStage
  | RedemptionStage_Done : t_RedemptionStage

/// The grant value removed by the atomic `get_del`, as observed by the
/// handler. `matches_observed_grant` is the decoded-value equality with the
/// non-consuming preflight lookup (including the credential id); the driver
/// checks the epoch and possession fields against its own preflight permit.
type t_ConsumedGrantObservation = {
  f_key_epoch:i64;
  f_possession:bool;
  f_matches_observed_grant:bool
}

/// Outcome of the single-use grant redemption observation.
type t_ConsumptionObservation =
  | ConsumptionObservation_Missing : t_ConsumptionObservation
  | ConsumptionObservation_Present : t_ConsumedGrantObservation -> t_ConsumptionObservation

/// The actual `vela_rekey_policy::plan_active_mutation` decision, passed
/// through the driver so only a permit whose epoch equals the enrollment
/// permit can authorize the insert.
type t_RekeyObservation =
  | RekeyObservation_Permit { f_epoch:i64 }: t_RekeyObservation
  | RekeyObservation_Reject : t_RekeyObservation

/// The final policy observation. The driver calls the real
/// `enrollment_facts`/`plan_enrollment` policy; the handler does not
/// separately fabricate an enrollment permit.
type t_FinalPolicyObservation = {
  f_enrollment:Vela_recovery_policy.t_EnrollmentObservation;
  f_rekey:t_RekeyObservation
}

/// Result of the guarded device insert, as observed by the handler.
type t_InsertObservation =
  | InsertObservation_Inserted : t_InsertObservation
  | InsertObservation_Skipped : t_InsertObservation
  | InsertObservation_Failed : t_InsertObservation

/// Live authority recheck performed only after an insert observed zero rows.
/// The order below is the handler's historical status/message precedence:
/// account absence, then credential/commitment revocation, then the
/// retryable rotation conflict.
type t_AuthorityRecheckObservation =
  | AuthorityRecheckObservation_QueryFailed : t_AuthorityRecheckObservation
  | AuthorityRecheckObservation_AccountAbsent : t_AuthorityRecheckObservation
  | AuthorityRecheckObservation_CommitmentRevoked : t_AuthorityRecheckObservation
  | AuthorityRecheckObservation_CredentialReplaced : t_AuthorityRecheckObservation
  | AuthorityRecheckObservation_StillRotating : t_AuthorityRecheckObservation

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_RedemptionEvent =
  | RedemptionEvent_Consumed : t_ConsumptionObservation -> t_RedemptionEvent
  | RedemptionEvent_FinalPolicy : t_FinalPolicyObservation -> t_RedemptionEvent
  | RedemptionEvent_Insert : t_InsertObservation -> t_RedemptionEvent
  | RedemptionEvent_Recheck : t_AuthorityRecheckObservation -> t_RedemptionEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence. `GrantChanged` is the shared retryable "changed while
/// redeeming" class used by the consumed-value mismatch and rekey rejection.
type t_RedemptionFailure =
  | RedemptionFailure_GrantUnavailable : t_RedemptionFailure
  | RedemptionFailure_GrantChanged : t_RedemptionFailure
  | RedemptionFailure_PolicyRejected : t_RedemptionFailure
  | RedemptionFailure_InsertStorage : t_RedemptionFailure
  | RedemptionFailure_RecheckStorage : t_RedemptionFailure
  | RedemptionFailure_AccountAbsent : t_RedemptionFailure
  | RedemptionFailure_CommitmentRevoked : t_RedemptionFailure
  | RedemptionFailure_CredentialReplaced : t_RedemptionFailure
  | RedemptionFailure_Rotating : t_RedemptionFailure

/// The insert authority emitted by the driver.
type t_RedemptionInsertPermit = {
  f_epoch:i64;
  f_possession:bool
}

/// The effect the handler must perform next. A `RestoreAndFail` requires the
/// handler to restore the consumed grant before returning the failure; a
/// `Fail` requires no restoration.
type t_RedemptionEffect =
  | RedemptionEffect_Consume : t_RedemptionEffect
  | RedemptionEffect_FinalPolicy : t_RedemptionEffect
  | RedemptionEffect_Insert : t_RedemptionInsertPermit -> t_RedemptionEffect
  | RedemptionEffect_Recheck : t_RedemptionEffect
  | RedemptionEffect_Complete : t_RedemptionEffect
  | RedemptionEffect_Fail : t_RedemptionFailure -> t_RedemptionEffect
  | RedemptionEffect_RestoreAndFail : t_RedemptionFailure -> t_RedemptionEffect
  | RedemptionEffect_Idle : t_RedemptionEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
type t_RedemptionDriver = {
  f_stage:t_RedemptionStage;
  f_epoch:i64;
  f_possession:bool;
  f_consumed_matched:bool;
  f_permit_issued:bool;
  f_insert_attempted:bool;
  f_insert_succeeded:bool;
  f_restored:bool
}

type t_RedemptionTransition = {
  f_driver:t_RedemptionDriver;
  f_effect:t_RedemptionEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let redemption_state_is_sound (driver: t_RedemptionDriver) : bool =
  let consume_clean:bool =
    ~.driver.f_consumed_matched && ~.driver.f_permit_issued && ~.driver.f_insert_attempted &&
    ~.driver.f_insert_succeeded &&
    ~.driver.f_restored
  in
  let policy_clean:bool =
    driver.f_consumed_matched && ~.driver.f_permit_issued && ~.driver.f_insert_attempted &&
    ~.driver.f_insert_succeeded &&
    ~.driver.f_restored
  in
  let insert_clean:bool =
    driver.f_consumed_matched && driver.f_permit_issued && driver.f_insert_attempted &&
    ~.driver.f_insert_succeeded &&
    ~.driver.f_restored
  in
  (~.(match driver.f_stage <: t_RedemptionStage with
    | RedemptionStage_Consume  -> true
    | _ -> false) ||
  consume_clean) &&
  (~.(match driver.f_stage <: t_RedemptionStage with
    | RedemptionStage_FinalPolicy  -> true
    | _ -> false) ||
  policy_clean) &&
  (~.(match driver.f_stage <: t_RedemptionStage with
    | RedemptionStage_Insert  -> true
    | _ -> false) ||
  insert_clean) &&
  (~.(match driver.f_stage <: t_RedemptionStage with
    | RedemptionStage_Recheck  -> true
    | _ -> false) ||
  insert_clean) &&
  (~.driver.f_insert_attempted || driver.f_consumed_matched && driver.f_permit_issued) &&
  (~.driver.f_insert_succeeded ||
  driver.f_insert_attempted && driver.f_consumed_matched && driver.f_permit_issued &&
  (match driver.f_stage <: t_RedemptionStage with
    | RedemptionStage_Done  -> true
    | _ -> false) &&
  ~.driver.f_restored) &&
  (~.driver.f_restored ||
  (match driver.f_stage <: t_RedemptionStage with
    | RedemptionStage_Done  -> true
    | _ -> false) &&
  ~.driver.f_insert_succeeded)

/// Every effect the driver emits agrees with the state it produces. In
/// particular an `Insert` effect leaves the driver in `Insert` with a matched
/// consumption and both permits recorded, and no restoration effect can be
/// produced from an insert success.
let redemption_effect_is_sound (driver: t_RedemptionDriver) (v_effect: t_RedemptionEffect) : bool =
  match v_effect <: t_RedemptionEffect with
  | RedemptionEffect_Consume  ->
    (match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Consume  -> true
      | _ -> false) &&
    ~.driver.f_consumed_matched &&
    ~.driver.f_insert_attempted
  | RedemptionEffect_FinalPolicy  ->
    (match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_FinalPolicy  -> true
      | _ -> false) &&
    driver.f_consumed_matched &&
    ~.driver.f_permit_issued &&
    ~.driver.f_insert_attempted
  | RedemptionEffect_Insert permit ->
    (match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Insert  -> true
      | _ -> false) &&
    driver.f_consumed_matched &&
    driver.f_permit_issued &&
    driver.f_insert_attempted &&
    ~.driver.f_insert_succeeded &&
    ~.driver.f_restored &&
    permit.f_epoch =. driver.f_epoch &&
    permit.f_possession =. driver.f_possession
  | RedemptionEffect_Recheck  ->
    (match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Recheck  -> true
      | _ -> false) &&
    driver.f_consumed_matched &&
    driver.f_permit_issued &&
    driver.f_insert_attempted &&
    ~.driver.f_insert_succeeded &&
    ~.driver.f_restored
  | RedemptionEffect_Complete  ->
    (match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Done  -> true
      | _ -> false) &&
    driver.f_insert_succeeded &&
    ~.driver.f_restored
  | RedemptionEffect_Fail _ ->
    (match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Done  -> true
      | _ -> false) &&
    ~.driver.f_insert_succeeded
  | RedemptionEffect_RestoreAndFail _ ->
    (match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Done  -> true
      | _ -> false) &&
    driver.f_restored &&
    ~.driver.f_insert_succeeded
  | RedemptionEffect_Idle  -> true

let transition (driver: t_RedemptionDriver) (v_effect: t_RedemptionEffect) : t_RedemptionTransition =
  { f_driver = driver; f_effect = v_effect } <: t_RedemptionTransition

let idle (driver: t_RedemptionDriver) : t_RedemptionTransition =
  transition driver (RedemptionEffect_Idle <: t_RedemptionEffect)

let terminal (driver: t_RedemptionDriver) (failure: t_RedemptionFailure) : t_RedemptionTransition =
  transition ({ driver with f_stage = RedemptionStage_Done <: t_RedemptionStage }
      <:
      t_RedemptionDriver)
    (RedemptionEffect_Fail failure <: t_RedemptionEffect)

let restore_then_fail (driver: t_RedemptionDriver) (failure: t_RedemptionFailure)
    : t_RedemptionTransition =
  transition ({ driver with f_stage = RedemptionStage_Done <: t_RedemptionStage; f_restored = true }
      <:
      t_RedemptionDriver)
    (RedemptionEffect_RestoreAndFail failure <: t_RedemptionEffect)

/// Start a per-request redemption after the checked preflight produced its
/// `ReadyToConsume` permit. Only the atomic consumption may be attempted.
let begin_redemption (ready: Vela_recovery_policy.t_ReadyToConsume)
    : Prims.Pure t_RedemptionTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RedemptionTransition = result in
          redemption_state_is_sound result.f_driver &&
          redemption_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_RedemptionStage with
            | RedemptionStage_Consume  -> true
            | _ -> false) &&
          ~.result.f_driver.f_consumed_matched &&
          ~.result.f_driver.f_permit_issued &&
          ~.result.f_driver.f_insert_attempted &&
          ~.result.f_driver.f_insert_succeeded &&
          ~.result.f_driver.f_restored) =
  transition ({
        f_stage = RedemptionStage_Consume <: t_RedemptionStage;
        f_epoch = Vela_recovery_policy.impl_ReadyToConsume__epoch ready <: i64;
        f_possession = Vela_recovery_policy.impl_ReadyToConsume__possession ready <: bool;
        f_consumed_matched = false;
        f_permit_issued = false;
        f_insert_attempted = false;
        f_insert_succeeded = false;
        f_restored = false
      }
      <:
      t_RedemptionDriver)
    (RedemptionEffect_Consume <: t_RedemptionEffect)

let on_consumed (driver: t_RedemptionDriver) (observation: t_ConsumptionObservation)
    : t_RedemptionTransition =
  match observation <: t_ConsumptionObservation with
  | ConsumptionObservation_Missing  ->
    terminal driver (RedemptionFailure_GrantUnavailable <: t_RedemptionFailure)
  | ConsumptionObservation_Present consumed ->
    let matched:bool =
      consumed.f_matches_observed_grant && consumed.f_key_epoch =. driver.f_epoch &&
      consumed.f_possession =. driver.f_possession
    in
    if matched
    then
      transition ({
            driver with
            f_stage = RedemptionStage_FinalPolicy <: t_RedemptionStage;
            f_consumed_matched = true
          }
          <:
          t_RedemptionDriver)
        (RedemptionEffect_FinalPolicy <: t_RedemptionEffect)
    else restore_then_fail driver (RedemptionFailure_GrantChanged <: t_RedemptionFailure)

let on_final_policy (driver: t_RedemptionDriver) (observation: t_FinalPolicyObservation)
    : t_RedemptionTransition =
  match
    Vela_recovery_policy.plan_enrollment (Vela_recovery_policy.enrollment_facts observation
            .f_enrollment
        <:
        Vela_recovery_policy.t_EnrollmentFacts)
    <:
    Vela_recovery_policy.t_EnrollmentDecision
  with
  | Vela_recovery_policy.EnrollmentDecision_Enroll permit ->
    let permit_epoch:i64 = Vela_recovery_policy.impl_EnrollmentPermit__epoch permit in
    let rekey_matches:bool =
      match observation.f_rekey <: t_RekeyObservation with
      | RekeyObservation_Permit { f_epoch = epoch } -> epoch =. permit_epoch
      | RekeyObservation_Reject  -> false
    in
    if permit_epoch =. driver.f_epoch && rekey_matches && driver.f_consumed_matched
    then
      transition ({
            driver with
            f_stage = RedemptionStage_Insert <: t_RedemptionStage;
            f_permit_issued = true;
            f_insert_attempted = true
          }
          <:
          t_RedemptionDriver)
        (RedemptionEffect_Insert
          ({ f_epoch = permit_epoch; f_possession = driver.f_possession }
            <:
            t_RedemptionInsertPermit)
          <:
          t_RedemptionEffect)
    else restore_then_fail driver (RedemptionFailure_GrantChanged <: t_RedemptionFailure)
  | Vela_recovery_policy.EnrollmentDecision_Reject  ->
    terminal driver (RedemptionFailure_PolicyRejected <: t_RedemptionFailure)

let on_insert (driver: t_RedemptionDriver) (observation: t_InsertObservation)
    : t_RedemptionTransition =
  match observation <: t_InsertObservation with
  | InsertObservation_Inserted  ->
    transition ({
          driver with
          f_stage = RedemptionStage_Done <: t_RedemptionStage;
          f_insert_succeeded = true
        }
        <:
        t_RedemptionDriver)
      (RedemptionEffect_Complete <: t_RedemptionEffect)
  | InsertObservation_Skipped  ->
    transition ({ driver with f_stage = RedemptionStage_Recheck <: t_RedemptionStage }
        <:
        t_RedemptionDriver)
      (RedemptionEffect_Recheck <: t_RedemptionEffect)
  | InsertObservation_Failed  ->
    restore_then_fail driver (RedemptionFailure_InsertStorage <: t_RedemptionFailure)

let on_recheck (driver: t_RedemptionDriver) (observation: t_AuthorityRecheckObservation)
    : t_RedemptionTransition =
  match observation <: t_AuthorityRecheckObservation with
  | AuthorityRecheckObservation_QueryFailed  ->
    restore_then_fail driver (RedemptionFailure_RecheckStorage <: t_RedemptionFailure)
  | AuthorityRecheckObservation_AccountAbsent  ->
    restore_then_fail driver (RedemptionFailure_AccountAbsent <: t_RedemptionFailure)
  | AuthorityRecheckObservation_CommitmentRevoked  ->
    terminal driver (RedemptionFailure_CommitmentRevoked <: t_RedemptionFailure)
  | AuthorityRecheckObservation_CredentialReplaced  ->
    terminal driver (RedemptionFailure_CredentialReplaced <: t_RedemptionFailure)
  | AuthorityRecheckObservation_StillRotating  ->
    restore_then_fail driver (RedemptionFailure_Rotating <: t_RedemptionFailure)

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
let step (driver: t_RedemptionDriver) (event: t_RedemptionEvent)
    : Prims.Pure t_RedemptionTransition
      (requires redemption_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RedemptionTransition = result in
          redemption_effect_is_sound result.f_driver result.f_effect &&
          (~.(redemption_state_is_sound driver <: bool) || redemption_state_is_sound result.f_driver)
      ) =
  match event <: t_RedemptionEvent with
  | RedemptionEvent_Consumed observation ->
    if
      match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Consume  -> true
      | _ -> false
    then on_consumed driver observation
    else idle driver
  | RedemptionEvent_FinalPolicy observation ->
    if
      match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_FinalPolicy  -> true
      | _ -> false
    then on_final_policy driver observation
    else idle driver
  | RedemptionEvent_Insert observation ->
    if
      match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Insert  -> true
      | _ -> false
    then on_insert driver observation
    else idle driver
  | RedemptionEvent_Recheck observation ->
    if
      match driver.f_stage <: t_RedemptionStage with
      | RedemptionStage_Recheck  -> true
      | _ -> false
    then on_recheck driver observation
    else idle driver

let on_grant_consumed (driver: t_RedemptionDriver) (observation: t_ConsumptionObservation)
    : Prims.Pure t_RedemptionTransition
      (requires redemption_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RedemptionTransition = result in
          redemption_effect_is_sound result.f_driver result.f_effect &&
          (~.(redemption_state_is_sound driver <: bool) || redemption_state_is_sound result.f_driver)
      ) = step driver (RedemptionEvent_Consumed observation <: t_RedemptionEvent)

let on_final_policy_observed (driver: t_RedemptionDriver) (observation: t_FinalPolicyObservation)
    : Prims.Pure t_RedemptionTransition
      (requires redemption_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RedemptionTransition = result in
          redemption_effect_is_sound result.f_driver result.f_effect &&
          (~.(redemption_state_is_sound driver <: bool) || redemption_state_is_sound result.f_driver)
      ) = step driver (RedemptionEvent_FinalPolicy observation <: t_RedemptionEvent)

let on_insert_completed (driver: t_RedemptionDriver) (observation: t_InsertObservation)
    : Prims.Pure t_RedemptionTransition
      (requires redemption_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RedemptionTransition = result in
          redemption_effect_is_sound result.f_driver result.f_effect &&
          (~.(redemption_state_is_sound driver <: bool) || redemption_state_is_sound result.f_driver)
      ) = step driver (RedemptionEvent_Insert observation <: t_RedemptionEvent)

let on_authority_rechecked (driver: t_RedemptionDriver) (observation: t_AuthorityRecheckObservation)
    : Prims.Pure t_RedemptionTransition
      (requires redemption_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RedemptionTransition = result in
          redemption_effect_is_sound result.f_driver result.f_effect &&
          (~.(redemption_state_is_sound driver <: bool) || redemption_state_is_sound result.f_driver)
      ) = step driver (RedemptionEvent_Recheck observation <: t_RedemptionEvent)
