module Vela_recovery_policy.Possession_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// State of the staged commitment column as observed by the handler. `Missing`
/// is a NULL/absent column (the handler's historical unavailable error);
/// `Corrupt` is a text cell that is not valid base64 (the historical internal
/// decode error).
type t_CommitmentObservation =
  | CommitmentObservation_Missing : t_CommitmentObservation
  | CommitmentObservation_Present { f_len:usize }: t_CommitmentObservation
  | CommitmentObservation_Corrupt : t_CommitmentObservation

/// Where the possession-proof redemption is in its decision sequence.
type t_ProofRecoverStage =
  | ProofRecoverStage_Attempt : t_ProofRecoverStage
  | ProofRecoverStage_Consume : t_ProofRecoverStage
  | ProofRecoverStage_Live : t_ProofRecoverStage
  | ProofRecoverStage_Verify : t_ProofRecoverStage
  | ProofRecoverStage_Issue : t_ProofRecoverStage
  | ProofRecoverStage_Done : t_ProofRecoverStage

/// Outcome of the rate-limit attempt count.
type t_AttemptBudgetObservation =
  | AttemptBudgetObservation_Admitted : t_AttemptBudgetObservation
  | AttemptBudgetObservation_Limited : t_AttemptBudgetObservation

/// Outcome of the atomic single-use proof-state consumption.
type t_AttemptConsumptionObservation =
  | AttemptConsumptionObservation_Missing : t_AttemptConsumptionObservation
  | AttemptConsumptionObservation_Corrupt : t_AttemptConsumptionObservation
  | AttemptConsumptionObservation_Present {
    f_user_matches:bool;
    f_attempt_matches:bool;
    f_key_epoch:i64
  }: t_AttemptConsumptionObservation

/// Live `users` row observation after a matched attempt.
type t_ProofAccountObservation = {
  f_account_present:bool;
  f_account_epoch_active:bool;
  f_commitment:t_CommitmentObservation;
  f_stored_epoch:Core_models.Option.t_Option i64
}

/// Authenticated outcome of the hybrid proof verification.
type t_ProofObservation = { f_verified:bool }

/// Outcome of the single-use grant store.
type t_GrantStoreObservation =
  | GrantStoreObservation_Stored : t_GrantStoreObservation
  | GrantStoreObservation_Failed : t_GrantStoreObservation

/// One proof-recovery driver event.
type t_ProofRecoverEvent =
  | ProofRecoverEvent_AttemptCounted : t_AttemptBudgetObservation -> t_ProofRecoverEvent
  | ProofRecoverEvent_AttemptConsumed : t_AttemptConsumptionObservation -> t_ProofRecoverEvent
  | ProofRecoverEvent_AccountObserved : t_ProofAccountObservation -> t_ProofRecoverEvent
  | ProofRecoverEvent_ProofObserved : t_ProofObservation -> t_ProofRecoverEvent
  | ProofRecoverEvent_GrantStored : t_GrantStoreObservation -> t_ProofRecoverEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence.
type t_ProofRecoverFailure =
  | ProofRecoverFailure_AttemptLimited : t_ProofRecoverFailure
  | ProofRecoverFailure_AttemptMissing : t_ProofRecoverFailure
  | ProofRecoverFailure_AttemptCorrupt : t_ProofRecoverFailure
  | ProofRecoverFailure_BindingMismatch : t_ProofRecoverFailure
  | ProofRecoverFailure_AccountAbsent : t_ProofRecoverFailure
  | ProofRecoverFailure_RotationPaused : t_ProofRecoverFailure
  | ProofRecoverFailure_CommitmentMissing : t_ProofRecoverFailure
  | ProofRecoverFailure_CommitmentCorrupt : t_ProofRecoverFailure
  | ProofRecoverFailure_ProofRejected : t_ProofRecoverFailure
  | ProofRecoverFailure_GrantStorage : t_ProofRecoverFailure

/// The grant authority emitted by the driver. It carries only the epoch the
/// stored grant is bound to; the server share is never part of it.
type t_ProofGrantPermit = { f_epoch:i64 }

/// The effect the handler must perform next.
type t_ProofRecoverEffect =
  | ProofRecoverEffect_CountAttempt : t_ProofRecoverEffect
  | ProofRecoverEffect_ConsumeAttempt : t_ProofRecoverEffect
  | ProofRecoverEffect_QueryAccount : t_ProofRecoverEffect
  | ProofRecoverEffect_VerifyProof : t_ProofRecoverEffect
  | ProofRecoverEffect_IssueGrant : t_ProofGrantPermit -> t_ProofRecoverEffect
  | ProofRecoverEffect_Complete : t_ProofRecoverEffect
  | ProofRecoverEffect_Fail : t_ProofRecoverFailure -> t_ProofRecoverEffect
  | ProofRecoverEffect_Idle : t_ProofRecoverEffect

/// Per-request proof-recovery state. Every field is a decision fact established
/// by a prior transition, never a claim about the store.
type t_ProofRecoverDriver = {
  f_stage:t_ProofRecoverStage;
  f_budget_counted:bool;
  f_attempt_consumed:bool;
  f_user_matches:bool;
  f_attempt_matches:bool;
  f_attempt_epoch:i64;
  f_account_present:bool;
  f_account_epoch_active:bool;
  f_commitment_present:bool;
  f_commitment_len:usize;
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_proof_verified:bool;
  f_grant_issued:bool;
  f_grant_stored:bool
}

type t_ProofRecoverTransition = {
  f_driver:t_ProofRecoverDriver;
  f_effect:t_ProofRecoverEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let proof_recover_state_is_sound (driver: t_ProofRecoverDriver) : bool =
  let attempt_clean:bool =
    ~.driver.f_budget_counted && ~.driver.f_attempt_consumed && ~.driver.f_proof_verified &&
    ~.driver.f_grant_issued &&
    ~.driver.f_grant_stored
  in
  let consume_clean:bool =
    driver.f_budget_counted && ~.driver.f_attempt_consumed && ~.driver.f_proof_verified &&
    ~.driver.f_grant_issued &&
    ~.driver.f_grant_stored
  in
  let live_clean:bool =
    driver.f_budget_counted && driver.f_attempt_consumed && driver.f_user_matches &&
    driver.f_attempt_matches &&
    ~.driver.f_proof_verified &&
    ~.driver.f_grant_issued &&
    ~.driver.f_grant_stored
  in
  let verify_clean:bool =
    live_clean && driver.f_account_present && driver.f_account_epoch_active &&
    driver.f_commitment_present
  in
  let issue_clean:bool =
    driver.f_budget_counted && driver.f_attempt_consumed && driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_account_present &&
    driver.f_account_epoch_active &&
    driver.f_commitment_present &&
    driver.f_proof_verified &&
    driver.f_grant_issued &&
    ~.driver.f_grant_stored
  in
  (~.(match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Attempt  -> true
    | _ -> false) ||
  attempt_clean) &&
  (~.(match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Consume  -> true
    | _ -> false) ||
  consume_clean) &&
  (~.(match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Live  -> true
    | _ -> false) ||
  live_clean) &&
  (~.(match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Verify  -> true
    | _ -> false) ||
  verify_clean) &&
  (~.(match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Issue  -> true
    | _ -> false) ||
  issue_clean) &&
  (~.driver.f_attempt_consumed || driver.f_budget_counted) &&
  (~.(driver.f_user_matches || driver.f_attempt_matches) || driver.f_attempt_consumed) &&
  (~.driver.f_proof_verified ||
  driver.f_attempt_consumed && driver.f_user_matches && driver.f_attempt_matches) &&
  (~.driver.f_grant_issued ||
  driver.f_attempt_consumed && driver.f_user_matches && driver.f_attempt_matches &&
  driver.f_proof_verified &&
  driver.f_account_present &&
  driver.f_account_epoch_active &&
  driver.f_commitment_present &&
  driver.f_commitment_len >. mk_usize 0 &&
  driver.f_attempt_epoch =.
  (Vela_recovery_policy.observed_recovery_epoch driver.f_stored_epoch <: i64) &&
  ((match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Issue  -> true
    | _ -> false) ||
  (match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Done  -> true
    | _ -> false))) &&
  (~.driver.f_grant_stored ||
  driver.f_grant_issued &&
  (match driver.f_stage <: t_ProofRecoverStage with
    | ProofRecoverStage_Done  -> true
    | _ -> false))

/// Every effect the driver emits agrees with the state it produces. In
/// particular an `IssueGrant` effect leaves the driver authorized at the
/// attempt's current epoch, and no effect can release the server share.
let proof_recover_effect_is_sound (driver: t_ProofRecoverDriver) (v_effect: t_ProofRecoverEffect)
    : bool =
  match v_effect <: t_ProofRecoverEffect with
  | ProofRecoverEffect_CountAttempt  ->
    (match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Attempt  -> true
      | _ -> false) &&
    ~.driver.f_budget_counted &&
    ~.driver.f_attempt_consumed &&
    ~.driver.f_grant_issued
  | ProofRecoverEffect_ConsumeAttempt  ->
    (match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Consume  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    ~.driver.f_attempt_consumed &&
    ~.driver.f_grant_issued
  | ProofRecoverEffect_QueryAccount  ->
    (match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Live  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    ~.driver.f_proof_verified &&
    ~.driver.f_grant_issued
  | ProofRecoverEffect_VerifyProof  ->
    (match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Verify  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_account_present &&
    driver.f_account_epoch_active &&
    driver.f_commitment_present &&
    ~.driver.f_proof_verified &&
    ~.driver.f_grant_issued
  | ProofRecoverEffect_IssueGrant permit ->
    (match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Issue  -> true
      | _ -> false) &&
    driver.f_budget_counted &&
    driver.f_attempt_consumed &&
    driver.f_user_matches &&
    driver.f_attempt_matches &&
    driver.f_proof_verified &&
    driver.f_account_present &&
    driver.f_account_epoch_active &&
    driver.f_commitment_present &&
    driver.f_commitment_len >. mk_usize 0 &&
    driver.f_grant_issued &&
    ~.driver.f_grant_stored &&
    permit.f_epoch =. (Vela_recovery_policy.observed_recovery_epoch driver.f_stored_epoch <: i64) &&
    permit.f_epoch =. driver.f_attempt_epoch
  | ProofRecoverEffect_Complete  ->
    (match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Done  -> true
      | _ -> false) &&
    driver.f_grant_issued &&
    driver.f_grant_stored
  | ProofRecoverEffect_Fail _ ->
    (match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Done  -> true
      | _ -> false) &&
    ~.driver.f_grant_stored
  | ProofRecoverEffect_Idle  -> true

/// No driver effect can release the server's recovery share. This is the
/// end-to-end statement for the possession path: the share is not merely
/// omitted from the handler response, it has no representation in the effect
/// language at all.
let proof_recover_effect_releases_share (v_effect: t_ProofRecoverEffect) : bool =
  match v_effect <: t_ProofRecoverEffect with
  | ProofRecoverEffect_IssueGrant _ -> false
  | _ -> false

let proof_recover_transition (driver: t_ProofRecoverDriver) (v_effect: t_ProofRecoverEffect)
    : t_ProofRecoverTransition =
  { f_driver = driver; f_effect = v_effect } <: t_ProofRecoverTransition

let proof_recover_idle (driver: t_ProofRecoverDriver) : t_ProofRecoverTransition =
  proof_recover_transition driver (ProofRecoverEffect_Idle <: t_ProofRecoverEffect)

let proof_recover_terminal (driver: t_ProofRecoverDriver) (failure: t_ProofRecoverFailure)
    : t_ProofRecoverTransition =
  proof_recover_transition ({ driver with f_stage = ProofRecoverStage_Done <: t_ProofRecoverStage }
      <:
      t_ProofRecoverDriver)
    (ProofRecoverEffect_Fail failure <: t_ProofRecoverEffect)

/// Start a per-request possession-proof redemption. The handler must count the
/// attempt before touching the single-use proof state.
let begin_proof_recover (_: Prims.unit)
    : Prims.Pure t_ProofRecoverTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ProofRecoverTransition = result in
          proof_recover_state_is_sound result.f_driver &&
          proof_recover_effect_is_sound result.f_driver result.f_effect &&
          ~.(proof_recover_effect_releases_share result.f_effect <: bool) &&
          (match result.f_driver.f_stage <: t_ProofRecoverStage with
            | ProofRecoverStage_Attempt  -> true
            | _ -> false) &&
          ~.result.f_driver.f_budget_counted &&
          ~.result.f_driver.f_attempt_consumed &&
          ~.result.f_driver.f_proof_verified &&
          ~.result.f_driver.f_grant_issued &&
          ~.result.f_driver.f_grant_stored &&
          (match result.f_effect <: t_ProofRecoverEffect with
            | ProofRecoverEffect_CountAttempt  -> true
            | _ -> false)) =
  proof_recover_transition ({
        f_stage = ProofRecoverStage_Attempt <: t_ProofRecoverStage;
        f_budget_counted = false;
        f_attempt_consumed = false;
        f_user_matches = false;
        f_attempt_matches = false;
        f_attempt_epoch = mk_i64 0;
        f_account_present = false;
        f_account_epoch_active = false;
        f_commitment_present = false;
        f_commitment_len = mk_usize 0;
        f_stored_epoch = Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
        f_proof_verified = false;
        f_grant_issued = false;
        f_grant_stored = false
      }
      <:
      t_ProofRecoverDriver)
    (ProofRecoverEffect_CountAttempt <: t_ProofRecoverEffect)

let apply_attempt_counted (driver: t_ProofRecoverDriver) (observation: t_AttemptBudgetObservation)
    : t_ProofRecoverTransition =
  match observation <: t_AttemptBudgetObservation with
  | AttemptBudgetObservation_Admitted  ->
    proof_recover_transition ({
          driver with
          f_stage = ProofRecoverStage_Consume <: t_ProofRecoverStage;
          f_budget_counted = true
        }
        <:
        t_ProofRecoverDriver)
      (ProofRecoverEffect_ConsumeAttempt <: t_ProofRecoverEffect)
  | AttemptBudgetObservation_Limited  ->
    proof_recover_terminal driver (ProofRecoverFailure_AttemptLimited <: t_ProofRecoverFailure)

let apply_attempt_consumed
      (driver: t_ProofRecoverDriver)
      (observation: t_AttemptConsumptionObservation)
    : t_ProofRecoverTransition =
  match observation <: t_AttemptConsumptionObservation with
  | AttemptConsumptionObservation_Missing  ->
    proof_recover_terminal driver (ProofRecoverFailure_AttemptMissing <: t_ProofRecoverFailure)
  | AttemptConsumptionObservation_Corrupt  ->
    proof_recover_terminal driver (ProofRecoverFailure_AttemptCorrupt <: t_ProofRecoverFailure)
  | AttemptConsumptionObservation_Present
    { f_user_matches = user_matches ; f_attempt_matches = attempt_matches ; f_key_epoch = key_epoch
    } ->
    let consumed:t_ProofRecoverDriver =
      {
        driver with
        f_attempt_consumed = true;
        f_user_matches = user_matches;
        f_attempt_matches = attempt_matches;
        f_attempt_epoch = key_epoch
      }
      <:
      t_ProofRecoverDriver
    in
    if user_matches && attempt_matches
    then
      proof_recover_transition ({
            consumed with
            f_stage = ProofRecoverStage_Live <: t_ProofRecoverStage
          }
          <:
          t_ProofRecoverDriver)
        (ProofRecoverEffect_QueryAccount <: t_ProofRecoverEffect)
    else
      proof_recover_terminal consumed (ProofRecoverFailure_BindingMismatch <: t_ProofRecoverFailure)

let apply_account_observed (driver: t_ProofRecoverDriver) (observation: t_ProofAccountObservation)
    : t_ProofRecoverTransition =
  if ~.observation.f_account_present
  then proof_recover_terminal driver (ProofRecoverFailure_AccountAbsent <: t_ProofRecoverFailure)
  else
    if ~.observation.f_account_epoch_active
    then proof_recover_terminal driver (ProofRecoverFailure_RotationPaused <: t_ProofRecoverFailure)
    else
      match observation.f_commitment <: t_CommitmentObservation with
      | CommitmentObservation_Missing  ->
        proof_recover_terminal driver
          (ProofRecoverFailure_CommitmentMissing <: t_ProofRecoverFailure)
      | CommitmentObservation_Corrupt  ->
        proof_recover_terminal driver
          (ProofRecoverFailure_CommitmentCorrupt <: t_ProofRecoverFailure)
      | CommitmentObservation_Present { f_len = len } ->
        proof_recover_transition ({
              driver with
              f_stage = ProofRecoverStage_Verify <: t_ProofRecoverStage;
              f_account_present = true;
              f_account_epoch_active = true;
              f_commitment_present = true;
              f_commitment_len = len;
              f_stored_epoch = observation.f_stored_epoch
            }
            <:
            t_ProofRecoverDriver)
          (ProofRecoverEffect_VerifyProof <: t_ProofRecoverEffect)

let apply_proof_observed (driver: t_ProofRecoverDriver) (observation: t_ProofObservation)
    : t_ProofRecoverTransition =
  let facts:Vela_recovery_policy.t_PossessionRecoverFacts =
    Vela_recovery_policy.possession_recover_facts ({
          Vela_recovery_policy.f_attempt_source
          =
          Vela_recovery_policy.RecoveryAttemptSource_Consumed
          <:
          Vela_recovery_policy.t_RecoveryAttemptSource;
          Vela_recovery_policy.f_account_present = true;
          Vela_recovery_policy.f_user_matches = driver.f_user_matches;
          Vela_recovery_policy.f_attempt_matches = driver.f_attempt_matches;
          Vela_recovery_policy.f_proof_verified = observation.f_verified;
          Vela_recovery_policy.f_account_epoch_active = true;
          Vela_recovery_policy.f_commitment_len = driver.f_commitment_len;
          Vela_recovery_policy.f_commitment_epoch = driver.f_attempt_epoch;
          Vela_recovery_policy.f_stored_epoch = driver.f_stored_epoch
        }
        <:
        Vela_recovery_policy.t_PossessionRecoverObservation)
  in
  match
    Vela_recovery_policy.plan_possession_recovery facts
    <:
    Vela_recovery_policy.t_PossessionRecoverDecision
  with
  | Vela_recovery_policy.PossessionRecoverDecision_Grant permit ->
    let _:Prims.unit =
      if true
      then
        let _:Prims.unit =
          Hax_lib.v_assert (~.(Vela_recovery_policy.impl_PossessionGrantPermit__releases_server_share
                  permit
                <:
                bool)
              <:
              bool)
        in
        ()
    in
    proof_recover_transition ({
          driver with
          f_stage = ProofRecoverStage_Issue <: t_ProofRecoverStage;
          f_proof_verified = true;
          f_grant_issued = true
        }
        <:
        t_ProofRecoverDriver)
      (ProofRecoverEffect_IssueGrant
        ({ f_epoch = Vela_recovery_policy.impl_PossessionGrantPermit__epoch permit <: i64 }
          <:
          t_ProofGrantPermit)
        <:
        t_ProofRecoverEffect)
  | Vela_recovery_policy.PossessionRecoverDecision_Reject  ->
    proof_recover_transition ({
          driver with
          f_stage = ProofRecoverStage_Done <: t_ProofRecoverStage;
          f_proof_verified = observation.f_verified
        }
        <:
        t_ProofRecoverDriver)
      (ProofRecoverEffect_Fail (ProofRecoverFailure_ProofRejected <: t_ProofRecoverFailure)
        <:
        t_ProofRecoverEffect)

let apply_grant_stored (driver: t_ProofRecoverDriver) (observation: t_GrantStoreObservation)
    : t_ProofRecoverTransition =
  match observation <: t_GrantStoreObservation with
  | GrantStoreObservation_Stored  ->
    proof_recover_transition ({
          driver with
          f_stage = ProofRecoverStage_Done <: t_ProofRecoverStage;
          f_grant_stored = true
        }
        <:
        t_ProofRecoverDriver)
      (ProofRecoverEffect_Complete <: t_ProofRecoverEffect)
  | GrantStoreObservation_Failed  ->
    proof_recover_terminal driver (ProofRecoverFailure_GrantStorage <: t_ProofRecoverFailure)

/// The complete, total proof-recovery transition relation. Events that do not
/// match the current stage (and every event after `Done`) are ignored.
let step_proof_recover (driver: t_ProofRecoverDriver) (event: t_ProofRecoverEvent)
    : Prims.Pure t_ProofRecoverTransition
      (requires proof_recover_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ProofRecoverTransition = result in
          proof_recover_effect_is_sound result.f_driver result.f_effect &&
          ~.(proof_recover_effect_releases_share result.f_effect <: bool) &&
          (~.(proof_recover_state_is_sound driver <: bool) ||
          proof_recover_state_is_sound result.f_driver)) =
  match event <: t_ProofRecoverEvent with
  | ProofRecoverEvent_AttemptCounted observation ->
    if
      match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Attempt  -> true
      | _ -> false
    then apply_attempt_counted driver observation
    else proof_recover_idle driver
  | ProofRecoverEvent_AttemptConsumed observation ->
    if
      match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Consume  -> true
      | _ -> false
    then apply_attempt_consumed driver observation
    else proof_recover_idle driver
  | ProofRecoverEvent_AccountObserved observation ->
    if
      match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Live  -> true
      | _ -> false
    then apply_account_observed driver observation
    else proof_recover_idle driver
  | ProofRecoverEvent_ProofObserved observation ->
    if
      match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Verify  -> true
      | _ -> false
    then apply_proof_observed driver observation
    else proof_recover_idle driver
  | ProofRecoverEvent_GrantStored observation ->
    if
      match driver.f_stage <: t_ProofRecoverStage with
      | ProofRecoverStage_Issue  -> true
      | _ -> false
    then apply_grant_stored driver observation
    else proof_recover_idle driver
