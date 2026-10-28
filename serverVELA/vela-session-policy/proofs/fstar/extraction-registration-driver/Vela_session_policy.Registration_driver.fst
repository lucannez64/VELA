module Vela_session_policy.Registration_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Request-side observations established before any effect. Key validity is a
/// pure decode/length/binding-signature fact computed by the handler.
type t_RegistrationRequestObservation = {
  f_has_account_limit:bool;
  f_account_limit:i64;
  f_identity_ek_valid:bool;
  f_identity_vk_valid:bool;
  f_share_ek_valid:bool
}

/// Outcome of the per-IP registration limiter.
type t_RateLimitObservation =
  | RateLimitObservation_Allowed : t_RateLimitObservation
  | RateLimitObservation_Denied : t_RateLimitObservation

/// Outcome of `SELECT COUNT(*) FROM users`.
type t_BudgetObservation =
  | BudgetObservation_Counted { f_count:i64 }: t_BudgetObservation
  | BudgetObservation_QueryFailed : t_BudgetObservation

/// Outcome of opening the one SQL transaction.
type t_TransactionObservation =
  | TransactionObservation_Begun : t_TransactionObservation
  | TransactionObservation_Failed : t_TransactionObservation

/// Outcome of one `INSERT`.
type t_InsertObservation =
  | InsertObservation_Inserted : t_InsertObservation
  | InsertObservation_Failed : t_InsertObservation

/// Outcome of the commit.
type t_CommitObservation =
  | CommitObservation_Committed : t_CommitObservation
  | CommitObservation_Failed : t_CommitObservation

/// Outcome of PASETO issuance.
type t_TokenObservation =
  | TokenObservation_Issued : t_TokenObservation
  | TokenObservation_Failed : t_TokenObservation

/// Outcome of JTI tracking.
type t_TrackObservation =
  | TrackObservation_Tracked : t_TrackObservation
  | TrackObservation_Failed : t_TrackObservation

/// Where the registration is in its decision sequence.
type t_RegistrationStage =
  | RegistrationStage_RateLimit : t_RegistrationStage
  | RegistrationStage_AccountBudget : t_RegistrationStage
  | RegistrationStage_BeginTransaction : t_RegistrationStage
  | RegistrationStage_InsertAccount : t_RegistrationStage
  | RegistrationStage_InsertDevice : t_RegistrationStage
  | RegistrationStage_Commit : t_RegistrationStage
  | RegistrationStage_IssueToken : t_RegistrationStage
  | RegistrationStage_TrackToken : t_RegistrationStage
  | RegistrationStage_Done : t_RegistrationStage

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_RegistrationEvent =
  | RegistrationEvent_RateLimitObserved : t_RateLimitObservation -> t_RegistrationEvent
  | RegistrationEvent_BudgetObserved : t_BudgetObservation -> t_RegistrationEvent
  | RegistrationEvent_TransactionObserved : t_TransactionObservation -> t_RegistrationEvent
  | RegistrationEvent_AccountInserted : t_InsertObservation -> t_RegistrationEvent
  | RegistrationEvent_DeviceInserted : t_InsertObservation -> t_RegistrationEvent
  | RegistrationEvent_CommitObserved : t_CommitObservation -> t_RegistrationEvent
  | RegistrationEvent_TokenObserved : t_TokenObservation -> t_RegistrationEvent
  | RegistrationEvent_TrackObserved : t_TrackObservation -> t_RegistrationEvent

/// Failure categories, preserving the handler's historical status/message
/// precedence. `InvalidRequest` keeps the handler's first decode error text.
type t_RegistrationFailure =
  | RegistrationFailure_RateLimited : t_RegistrationFailure
  | RegistrationFailure_InvalidRequest : t_RegistrationFailure
  | RegistrationFailure_AccountLimit : t_RegistrationFailure
  | RegistrationFailure_AccountCountStorage : t_RegistrationFailure
  | RegistrationFailure_TransactionStorage : t_RegistrationFailure
  | RegistrationFailure_AccountInsertStorage : t_RegistrationFailure
  | RegistrationFailure_DeviceInsertStorage : t_RegistrationFailure
  | RegistrationFailure_CommitStorage : t_RegistrationFailure
  | RegistrationFailure_TokenIssue : t_RegistrationFailure
  | RegistrationFailure_TrackStorage : t_RegistrationFailure

/// The effect the handler must perform next.
type t_RegistrationEffect =
  | RegistrationEffect_CheckRateLimit : t_RegistrationEffect
  | RegistrationEffect_CheckAccountBudget : t_RegistrationEffect
  | RegistrationEffect_BeginTransaction : t_RegistrationEffect
  | RegistrationEffect_InsertAccount : t_RegistrationEffect
  | RegistrationEffect_InsertDevice : t_RegistrationEffect
  | RegistrationEffect_CommitTransaction : t_RegistrationEffect
  | RegistrationEffect_IssueToken : t_RegistrationEffect
  | RegistrationEffect_TrackToken : t_RegistrationEffect
  | RegistrationEffect_Complete : t_RegistrationEffect
  | RegistrationEffect_Fail : t_RegistrationFailure -> t_RegistrationEffect
  | RegistrationEffect_Idle : t_RegistrationEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about SQL, the clock or the token service.
type t_RegistrationDriver = {
  f_stage:t_RegistrationStage;
  f_has_account_limit:bool;
  f_account_limit:i64;
  f_identity_ek_valid:bool;
  f_identity_vk_valid:bool;
  f_share_ek_valid:bool;
  f_rate_allowed:bool;
  f_budget_checked:bool;
  f_transaction_open:bool;
  f_transaction_started:bool;
  f_account_inserted:bool;
  f_device_inserted:bool;
  f_committed:bool;
  f_token_issued:bool;
  f_token_tracked:bool;
  f_responded:bool;
  f_failed:bool
}

type t_RegistrationTransition = {
  f_driver:t_RegistrationDriver;
  f_effect:t_RegistrationEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let registration_state_is_sound (d: t_RegistrationDriver) : bool =
  let pre:bool =
    ~.d.f_transaction_open && ~.d.f_transaction_started && ~.d.f_account_inserted &&
    ~.d.f_device_inserted &&
    ~.d.f_committed &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let rate_limit:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_RateLimit  -> true
      | _ -> false) &&
    ~.d.f_budget_checked &&
    pre
  in
  let account_budget:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_AccountBudget  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_has_account_limit &&
    ~.d.f_budget_checked &&
    pre
  in
  let begin_transaction:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_BeginTransaction  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    ~.d.f_transaction_open &&
    ~.d.f_transaction_started &&
    ~.d.f_account_inserted &&
    ~.d.f_device_inserted &&
    ~.d.f_committed &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let inserting:bool =
    d.f_rate_allowed && d.f_budget_checked && d.f_transaction_open && d.f_transaction_started &&
    ~.d.f_committed &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let insert_account:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_InsertAccount  -> true
      | _ -> false) &&
    inserting &&
    ~.d.f_account_inserted &&
    ~.d.f_device_inserted
  in
  let insert_device:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_InsertDevice  -> true
      | _ -> false) &&
    inserting &&
    d.f_account_inserted &&
    ~.d.f_device_inserted
  in
  let commit:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_Commit  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    ~.d.f_committed &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let issue_token:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_IssueToken  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    d.f_committed &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let track_token:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_TrackToken  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    d.f_committed &&
    d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  let done:bool =
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_Done  -> true
      | _ -> false) &&
    (d.f_responded || d.f_failed) &&
    ~.(d.f_responded && d.f_failed) &&
    (~.d.f_responded ||
    d.f_rate_allowed && d.f_budget_checked && d.f_transaction_started && d.f_account_inserted &&
    d.f_device_inserted &&
    d.f_committed &&
    d.f_token_issued &&
    d.f_token_tracked)
  in
  (match d.f_stage <: t_RegistrationStage with
    | RegistrationStage_RateLimit  -> rate_limit
    | RegistrationStage_AccountBudget  -> account_budget
    | RegistrationStage_BeginTransaction  -> begin_transaction
    | RegistrationStage_InsertAccount  -> insert_account
    | RegistrationStage_InsertDevice  -> insert_device
    | RegistrationStage_Commit  -> commit
    | RegistrationStage_IssueToken  -> issue_token
    | RegistrationStage_TrackToken  -> track_token
    | RegistrationStage_Done  -> done) &&
  (~.d.f_budget_checked || d.f_rate_allowed) &&
  (~.d.f_transaction_open || d.f_budget_checked) &&
  (~.d.f_transaction_started || d.f_transaction_open) &&
  (~.d.f_account_inserted || d.f_transaction_started) &&
  (~.d.f_device_inserted || d.f_account_inserted) &&
  (~.d.f_committed || d.f_device_inserted) &&
  (~.d.f_token_issued || d.f_committed) &&
  (~.d.f_token_tracked || d.f_token_issued) &&
  (~.d.f_responded || d.f_token_tracked)

/// Every effect the driver emits agrees with the state it produces.
let registration_effect_is_sound (d: t_RegistrationDriver) (v_effect: t_RegistrationEffect) : bool =
  let valid_keys:bool = d.f_identity_ek_valid && d.f_identity_vk_valid && d.f_share_ek_valid in
  let pre:bool =
    ~.d.f_transaction_open && ~.d.f_transaction_started && ~.d.f_account_inserted &&
    ~.d.f_device_inserted &&
    ~.d.f_committed &&
    ~.d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  in
  match v_effect <: t_RegistrationEffect with
  | RegistrationEffect_CheckRateLimit  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_RateLimit  -> true
      | _ -> false) &&
    ~.d.f_rate_allowed &&
    pre
  | RegistrationEffect_CheckAccountBudget  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_AccountBudget  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_has_account_limit &&
    ~.d.f_budget_checked &&
    pre
  | RegistrationEffect_BeginTransaction  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_BeginTransaction  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    valid_keys &&
    ~.d.f_transaction_open &&
    pre
  | RegistrationEffect_InsertAccount  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_InsertAccount  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    ~.d.f_account_inserted &&
    ~.d.f_device_inserted &&
    ~.d.f_committed &&
    ~.d.f_responded &&
    ~.d.f_failed
  | RegistrationEffect_InsertDevice  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_InsertDevice  -> true
      | _ -> false) &&
    d.f_rate_allowed &&
    d.f_budget_checked &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    ~.d.f_device_inserted &&
    ~.d.f_committed &&
    ~.d.f_responded &&
    ~.d.f_failed
  | RegistrationEffect_CommitTransaction  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_Commit  -> true
      | _ -> false) &&
    d.f_transaction_open &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    ~.d.f_committed &&
    ~.d.f_responded &&
    ~.d.f_failed
  | RegistrationEffect_IssueToken  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_IssueToken  -> true
      | _ -> false) &&
    d.f_committed &&
    ~.d.f_token_issued &&
    ~.d.f_responded &&
    ~.d.f_failed
  | RegistrationEffect_TrackToken  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_TrackToken  -> true
      | _ -> false) &&
    d.f_committed &&
    d.f_token_issued &&
    ~.d.f_token_tracked &&
    ~.d.f_responded &&
    ~.d.f_failed
  | RegistrationEffect_Complete  ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_Done  -> true
      | _ -> false) &&
    d.f_responded &&
    d.f_transaction_started &&
    d.f_account_inserted &&
    d.f_device_inserted &&
    d.f_committed &&
    d.f_token_issued &&
    d.f_token_tracked &&
    ~.d.f_failed
  | RegistrationEffect_Fail _ ->
    (match d.f_stage <: t_RegistrationStage with
      | RegistrationStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_responded
  | RegistrationEffect_Idle  -> true

let transition (driver: t_RegistrationDriver) (v_effect: t_RegistrationEffect)
    : t_RegistrationTransition =
  { f_driver = driver; f_effect = v_effect } <: t_RegistrationTransition

let idle (driver: t_RegistrationDriver) : t_RegistrationTransition =
  transition driver (RegistrationEffect_Idle <: t_RegistrationEffect)

let terminal (driver: t_RegistrationDriver) (failure: t_RegistrationFailure)
    : t_RegistrationTransition =
  transition ({
        driver with
        f_stage = RegistrationStage_Done <: t_RegistrationStage;
        f_failed = true
      }
      <:
      t_RegistrationDriver)
    (RegistrationEffect_Fail failure <: t_RegistrationEffect)

let request_state (observation: t_RegistrationRequestObservation) : t_RegistrationDriver =
  {
    f_stage = RegistrationStage_RateLimit <: t_RegistrationStage;
    f_has_account_limit = observation.f_has_account_limit;
    f_account_limit = observation.f_account_limit;
    f_identity_ek_valid = observation.f_identity_ek_valid;
    f_identity_vk_valid = observation.f_identity_vk_valid;
    f_share_ek_valid = observation.f_share_ek_valid;
    f_rate_allowed = false;
    f_budget_checked = false;
    f_transaction_open = false;
    f_transaction_started = false;
    f_account_inserted = false;
    f_device_inserted = false;
    f_committed = false;
    f_token_issued = false;
    f_token_tracked = false;
    f_responded = false;
    f_failed = false
  }
  <:
  t_RegistrationDriver

let keys_valid (driver: t_RegistrationDriver) : bool =
  driver.f_identity_ek_valid && driver.f_identity_vk_valid && driver.f_share_ek_valid

/// Start a per-request registration. The request-side key observations are
/// checked only after the limiter and the account budget, preserving the
/// historical error precedence (rate limit, then budget, then key decode).
let begin_registration (observation: t_RegistrationRequestObservation)
    : Prims.Pure t_RegistrationTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_state_is_sound result.f_driver &&
          registration_effect_is_sound result.f_driver result.f_effect) =
  transition (request_state observation <: t_RegistrationDriver)
    (RegistrationEffect_CheckRateLimit <: t_RegistrationEffect)

/// The budget question is resolved (or not configured): decode the keys and
/// either open the transaction or refuse the request with no SQL effect.
let begin_after_budget (driver: t_RegistrationDriver)
    : Prims.Pure t_RegistrationTransition
      (requires
        driver.f_rate_allowed && driver.f_budget_checked && ~.driver.f_transaction_open &&
        ~.driver.f_transaction_started &&
        ~.driver.f_account_inserted &&
        ~.driver.f_device_inserted &&
        ~.driver.f_committed &&
        ~.driver.f_token_issued &&
        ~.driver.f_token_tracked &&
        ~.driver.f_responded &&
        ~.driver.f_failed)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          registration_state_is_sound result.f_driver) =
  if keys_valid driver
  then
    transition ({ driver with f_stage = RegistrationStage_BeginTransaction <: t_RegistrationStage }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_BeginTransaction <: t_RegistrationEffect)
  else terminal driver (RegistrationFailure_InvalidRequest <: t_RegistrationFailure)

let on_rate_limit (driver: t_RegistrationDriver) (observation: t_RateLimitObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_RateLimit  -> true
          | _ -> false) &&
        ~.driver.f_budget_checked &&
        ~.driver.f_transaction_open &&
        ~.driver.f_transaction_started &&
        ~.driver.f_account_inserted &&
        ~.driver.f_device_inserted &&
        ~.driver.f_committed &&
        ~.driver.f_token_issued &&
        ~.driver.f_token_tracked &&
        ~.driver.f_responded &&
        ~.driver.f_failed)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_RateLimitObservation with
  | RateLimitObservation_Denied  ->
    terminal driver (RegistrationFailure_RateLimited <: t_RegistrationFailure)
  | RateLimitObservation_Allowed  ->
    let allowed:t_RegistrationDriver =
      { driver with f_rate_allowed = true } <: t_RegistrationDriver
    in
    if driver.f_has_account_limit
    then
      transition ({ allowed with f_stage = RegistrationStage_AccountBudget <: t_RegistrationStage }
          <:
          t_RegistrationDriver)
        (RegistrationEffect_CheckAccountBudget <: t_RegistrationEffect)
    else begin_after_budget ({ allowed with f_budget_checked = true } <: t_RegistrationDriver)

let on_budget (driver: t_RegistrationDriver) (observation: t_BudgetObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_AccountBudget  -> true
          | _ -> false) &&
        driver.f_rate_allowed &&
        driver.f_has_account_limit &&
        ~.driver.f_budget_checked &&
        ~.driver.f_transaction_open &&
        ~.driver.f_transaction_started &&
        ~.driver.f_account_inserted &&
        ~.driver.f_device_inserted &&
        ~.driver.f_committed &&
        ~.driver.f_token_issued &&
        ~.driver.f_token_tracked &&
        ~.driver.f_responded &&
        ~.driver.f_failed)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_BudgetObservation with
  | BudgetObservation_QueryFailed  ->
    terminal driver (RegistrationFailure_AccountCountStorage <: t_RegistrationFailure)
  | BudgetObservation_Counted { f_count = count } ->
    if count >=. mk_i64 0 && count <. driver.f_account_limit
    then begin_after_budget ({ driver with f_budget_checked = true } <: t_RegistrationDriver)
    else terminal driver (RegistrationFailure_AccountLimit <: t_RegistrationFailure)

let on_transaction (driver: t_RegistrationDriver) (observation: t_TransactionObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_BeginTransaction  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_TransactionObservation with
  | TransactionObservation_Failed  ->
    terminal driver (RegistrationFailure_TransactionStorage <: t_RegistrationFailure)
  | TransactionObservation_Begun  ->
    transition ({
          driver with
          f_stage = RegistrationStage_InsertAccount <: t_RegistrationStage;
          f_transaction_open = true;
          f_transaction_started = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_InsertAccount <: t_RegistrationEffect)

let on_account_insert (driver: t_RegistrationDriver) (observation: t_InsertObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_InsertAccount  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_InsertObservation with
  | InsertObservation_Failed  ->
    terminal driver (RegistrationFailure_AccountInsertStorage <: t_RegistrationFailure)
  | InsertObservation_Inserted  ->
    transition ({
          driver with
          f_stage = RegistrationStage_InsertDevice <: t_RegistrationStage;
          f_account_inserted = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_InsertDevice <: t_RegistrationEffect)

let on_device_insert (driver: t_RegistrationDriver) (observation: t_InsertObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_InsertDevice  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_InsertObservation with
  | InsertObservation_Failed  ->
    terminal driver (RegistrationFailure_DeviceInsertStorage <: t_RegistrationFailure)
  | InsertObservation_Inserted  ->
    transition ({
          driver with
          f_stage = RegistrationStage_Commit <: t_RegistrationStage;
          f_device_inserted = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_CommitTransaction <: t_RegistrationEffect)

let on_commit (driver: t_RegistrationDriver) (observation: t_CommitObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_Commit  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_CommitObservation with
  | CommitObservation_Failed  ->
    terminal driver (RegistrationFailure_CommitStorage <: t_RegistrationFailure)
  | CommitObservation_Committed  ->
    transition ({
          driver with
          f_stage = RegistrationStage_IssueToken <: t_RegistrationStage;
          f_committed = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_IssueToken <: t_RegistrationEffect)

let on_token (driver: t_RegistrationDriver) (observation: t_TokenObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_IssueToken  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_TokenObservation with
  | TokenObservation_Failed  ->
    terminal driver (RegistrationFailure_TokenIssue <: t_RegistrationFailure)
  | TokenObservation_Issued  ->
    transition ({
          driver with
          f_stage = RegistrationStage_TrackToken <: t_RegistrationStage;
          f_token_issued = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_TrackToken <: t_RegistrationEffect)

let on_track (driver: t_RegistrationDriver) (observation: t_TrackObservation)
    : Prims.Pure t_RegistrationTransition
      (requires
        registration_state_is_sound driver &&
        (match driver.f_stage <: t_RegistrationStage with
          | RegistrationStage_TrackToken  -> true
          | _ -> false))
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match observation <: t_TrackObservation with
  | TrackObservation_Failed  ->
    terminal driver (RegistrationFailure_TrackStorage <: t_RegistrationFailure)
  | TrackObservation_Tracked  ->
    transition ({
          driver with
          f_stage = RegistrationStage_Done <: t_RegistrationStage;
          f_token_tracked = true;
          f_responded = true
        }
        <:
        t_RegistrationDriver)
      (RegistrationEffect_Complete <: t_RegistrationEffect)

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
let step (driver: t_RegistrationDriver) (event: t_RegistrationEvent)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  match event <: t_RegistrationEvent with
  | RegistrationEvent_RateLimitObserved observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_RateLimit  -> true
      | _ -> false
    then on_rate_limit driver observation
    else idle driver
  | RegistrationEvent_BudgetObserved observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_AccountBudget  -> true
      | _ -> false
    then on_budget driver observation
    else idle driver
  | RegistrationEvent_TransactionObserved observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_BeginTransaction  -> true
      | _ -> false
    then on_transaction driver observation
    else idle driver
  | RegistrationEvent_AccountInserted observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_InsertAccount  -> true
      | _ -> false
    then on_account_insert driver observation
    else idle driver
  | RegistrationEvent_DeviceInserted observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_InsertDevice  -> true
      | _ -> false
    then on_device_insert driver observation
    else idle driver
  | RegistrationEvent_CommitObserved observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_Commit  -> true
      | _ -> false
    then on_commit driver observation
    else idle driver
  | RegistrationEvent_TokenObserved observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_IssueToken  -> true
      | _ -> false
    then on_token driver observation
    else idle driver
  | RegistrationEvent_TrackObserved observation ->
    if
      match driver.f_stage <: t_RegistrationStage with
      | RegistrationStage_TrackToken  -> true
      | _ -> false
    then on_track driver observation
    else idle driver

let on_rate_limit_event (driver: t_RegistrationDriver) (observation: t_RateLimitObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_RateLimitObserved observation <: t_RegistrationEvent)

let on_budget_event (driver: t_RegistrationDriver) (observation: t_BudgetObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_BudgetObserved observation <: t_RegistrationEvent)

let on_transaction_event (driver: t_RegistrationDriver) (observation: t_TransactionObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_TransactionObserved observation <: t_RegistrationEvent)

let on_account_insert_event (driver: t_RegistrationDriver) (observation: t_InsertObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_AccountInserted observation <: t_RegistrationEvent)

let on_device_insert_event (driver: t_RegistrationDriver) (observation: t_InsertObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_DeviceInserted observation <: t_RegistrationEvent)

let on_commit_event (driver: t_RegistrationDriver) (observation: t_CommitObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_CommitObserved observation <: t_RegistrationEvent)

let on_token_event (driver: t_RegistrationDriver) (observation: t_TokenObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_TokenObserved observation <: t_RegistrationEvent)

let on_track_event (driver: t_RegistrationDriver) (observation: t_TrackObservation)
    : Prims.Pure t_RegistrationTransition
      (requires registration_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_RegistrationTransition = result in
          registration_effect_is_sound result.f_driver result.f_effect &&
          (~.(registration_state_is_sound driver <: bool) ||
          registration_state_is_sound result.f_driver)) =
  step driver (RegistrationEvent_TrackObserved observation <: t_RegistrationEvent)
