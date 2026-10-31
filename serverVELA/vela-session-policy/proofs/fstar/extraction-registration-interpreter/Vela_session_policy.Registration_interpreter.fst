module Vela_session_policy.Registration_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one request performs: limiter, optional budget, transaction
/// begin, two inserts, commit, token issue and JTI tracking.
let v_REGISTRATION_MAX_EFFECTS: usize = mk_usize 8

/// The driver has decided: nothing more may be performed.
let registration_effect_is_terminal
      (v_effect: Vela_session_policy.Registration_driver.t_RegistrationEffect)
    : bool =
  match v_effect <: Vela_session_policy.Registration_driver.t_RegistrationEffect with
  | Vela_session_policy.Registration_driver.RegistrationEffect_Complete
  | Vela_session_policy.Registration_driver.RegistrationEffect_Fail _
  | Vela_session_policy.Registration_driver.RegistrationEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects.
class t_RegistrationIo (v_Self: Type0) = {
  f_check_rate_limit_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_rate_limit_post:
      v_Self ->
      (v_Self & Vela_session_policy.Registration_driver.t_RateLimitObservation)
    -> Type0;
  f_check_rate_limit:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_RateLimitObservation)
        (f_check_rate_limit_pre x0)
        (fun result -> f_check_rate_limit_post x0 result);
  f_check_account_budget_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_account_budget_post:
      v_Self ->
      (v_Self & Vela_session_policy.Registration_driver.t_BudgetObservation)
    -> Type0;
  f_check_account_budget:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_BudgetObservation)
        (f_check_account_budget_pre x0)
        (fun result -> f_check_account_budget_post x0 result);
  f_begin_transaction_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_begin_transaction_post:
      v_Self ->
      (v_Self & Vela_session_policy.Registration_driver.t_TransactionObservation)
    -> Type0;
  f_begin_transaction:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_TransactionObservation)
        (f_begin_transaction_pre x0)
        (fun result -> f_begin_transaction_post x0 result);
  f_insert_account_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_insert_account_post:
      v_Self ->
      (v_Self & Vela_session_policy.Registration_driver.t_InsertObservation)
    -> Type0;
  f_insert_account:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_InsertObservation)
        (f_insert_account_pre x0)
        (fun result -> f_insert_account_post x0 result);
  f_insert_device_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_insert_device_post:
      v_Self ->
      (v_Self & Vela_session_policy.Registration_driver.t_InsertObservation)
    -> Type0;
  f_insert_device:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_InsertObservation)
        (f_insert_device_pre x0)
        (fun result -> f_insert_device_post x0 result);
  f_commit_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_commit_post:v_Self -> (v_Self & Vela_session_policy.Registration_driver.t_CommitObservation)
    -> Type0;
  f_commit:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_CommitObservation)
        (f_commit_pre x0)
        (fun result -> f_commit_post x0 result);
  f_issue_token_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_issue_token_post:v_Self -> (v_Self & Vela_session_policy.Registration_driver.t_TokenObservation)
    -> Type0;
  f_issue_token:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_TokenObservation)
        (f_issue_token_pre x0)
        (fun result -> f_issue_token_post x0 result);
  f_track_token_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_track_token_post:v_Self -> (v_Self & Vela_session_policy.Registration_driver.t_TrackObservation)
    -> Type0;
  f_track_token:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Registration_driver.t_TrackObservation)
        (f_track_token_pre x0)
        (fun result -> f_track_token_post x0 result)
}

/// The synchronous expansion of [`registration_interpreter!`]: the artifact
/// hax extracts and F* checks.
let run_registration
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RegistrationIo v_Io)
      (io: v_Io)
      (observation: Vela_session_policy.Registration_driver.t_RegistrationRequestObservation)
    : (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition) =
  let transition:Vela_session_policy.Registration_driver.t_RegistrationTransition =
    Vela_session_policy.Registration_driver.begin_registration observation
  in
  let (io: v_Io), (transition: Vela_session_policy.Registration_driver.t_RegistrationTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REGISTRATION_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_session_policy.Registration_driver.t_RegistrationTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Registration_driver.registration_state_is_sound transition
              .Vela_session_policy.Registration_driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition))
      (fun temp_0_ temp_1_ ->
          let
          (io: v_Io), (transition: Vela_session_policy.Registration_driver.t_RegistrationTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          let
          (io: v_Io), (hoist17: Vela_session_policy.Registration_driver.t_RegistrationTransition) =
            match
              transition.Vela_session_policy.Registration_driver.f_effect
              <:
              Vela_session_policy.Registration_driver.t_RegistrationEffect
            with
            | Vela_session_policy.Registration_driver.RegistrationEffect_CheckRateLimit  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_RateLimitObservation) =
                f_check_rate_limit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_RateLimitObserved out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_CheckAccountBudget  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_BudgetObservation) =
                f_check_account_budget #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_BudgetObserved out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_BeginTransaction  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_TransactionObservation)
              =
                f_begin_transaction #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_TransactionObserved out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_InsertAccount  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_InsertObservation) =
                f_insert_account #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_AccountInserted out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_InsertDevice  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_InsertObservation) =
                f_insert_device #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_DeviceInserted out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_CommitTransaction  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_CommitObservation) =
                f_commit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_CommitObserved out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_IssueToken  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_TokenObservation) =
                f_issue_token #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_TokenObserved out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_TrackToken  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Registration_driver.t_TrackObservation) =
                f_track_token #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Registration_driver.step transition
                  .Vela_session_policy.Registration_driver.f_driver
                (Vela_session_policy.Registration_driver.RegistrationEvent_TrackObserved out
                  <:
                  Vela_session_policy.Registration_driver.t_RegistrationEvent)
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
            | Vela_session_policy.Registration_driver.RegistrationEffect_Complete
            | Vela_session_policy.Registration_driver.RegistrationEffect_Fail _
            | Vela_session_policy.Registration_driver.RegistrationEffect_Idle  ->
              io, transition
              <:
              (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
          in
          let transition:Vela_session_policy.Registration_driver.t_RegistrationTransition =
            hoist17
          in
          io, transition
          <:
          (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition))
  in
  let hax_temp_output:Vela_session_policy.Registration_driver.t_RegistrationTransition =
    transition
  in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Registration_driver.t_RegistrationTransition)
