module Vela_session_policy.Websession_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

let start_driver_of (transition: Vela_session_policy.Websession_driver.t_StartTransition)
    : Vela_session_policy.Websession_driver.t_StartDriver =
  transition.Vela_session_policy.Websession_driver.f_driver

let start_effect_of (transition: Vela_session_policy.Websession_driver.t_StartTransition)
    : Vela_session_policy.Websession_driver.t_StartEffect =
  transition.Vela_session_policy.Websession_driver.f_effect

let grant_driver_of (transition: Vela_session_policy.Websession_driver.t_GrantTransition)
    : Vela_session_policy.Websession_driver.t_GrantDriver =
  transition.Vela_session_policy.Websession_driver.f_driver

let grant_effect_of (transition: Vela_session_policy.Websession_driver.t_GrantTransition)
    : Vela_session_policy.Websession_driver.t_GrantEffect =
  transition.Vela_session_policy.Websession_driver.f_effect

let token_driver_of (transition: Vela_session_policy.Websession_driver.t_TokenTransition)
    : Vela_session_policy.Websession_driver.t_TokenDriver =
  transition.Vela_session_policy.Websession_driver.f_driver

let token_effect_of (transition: Vela_session_policy.Websession_driver.t_TokenTransition)
    : Vela_session_policy.Websession_driver.t_TokenEffect =
  transition.Vela_session_policy.Websession_driver.f_effect

let delete_driver_of (transition: Vela_session_policy.Websession_driver.t_DeleteTransition)
    : Vela_session_policy.Websession_driver.t_DeleteDriver =
  transition.Vela_session_policy.Websession_driver.f_driver

let delete_effect_of (transition: Vela_session_policy.Websession_driver.t_DeleteTransition)
    : Vela_session_policy.Websession_driver.t_DeleteEffect =
  transition.Vela_session_policy.Websession_driver.f_effect

/// The three effects a start can perform before its verdict.
let v_START_MAX_EFFECTS: usize = mk_usize 3

let start_effect_is_terminal (v_effect: Vela_session_policy.Websession_driver.t_StartEffect) : bool =
  match v_effect <: Vela_session_policy.Websession_driver.t_StartEffect with
  | Vela_session_policy.Websession_driver.StartEffect_Complete
  | Vela_session_policy.Websession_driver.StartEffect_Fail _
  | Vela_session_policy.Websession_driver.StartEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal start effect.
class t_StartIo (v_Self: Type0) = {
  f_check_rate_limit_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_rate_limit_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_StartLimitObservation)
    -> Type0;
  f_check_rate_limit:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_StartLimitObservation)
        (f_check_rate_limit_pre x0)
        (fun result -> f_check_rate_limit_post x0 result);
  f_validate_start_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_validate_start_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_StartValidationObservation)
    -> Type0;
  f_validate_start:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_StartValidationObservation)
        (f_validate_start_pre x0)
        (fun result -> f_validate_start_post x0 result);
  f_insert_pending_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_insert_pending_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_StartInsertObservation)
    -> Type0;
  f_insert_pending:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_StartInsertObservation)
        (f_insert_pending_pre x0)
        (fun result -> f_insert_pending_post x0 result)
}

/// The synchronous expansion of [`websession_start_interpreter!`].
let run_start
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_StartIo v_Io)
      (io: v_Io)
    : (v_Io & Vela_session_policy.Websession_driver.t_StartTransition) =
  let transition:Vela_session_policy.Websession_driver.t_StartTransition =
    Vela_session_policy.Websession_driver.begin_start ()
  in
  let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_StartTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_START_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_StartTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Websession_driver.start_state_is_sound (start_driver_of transition
              <:
              Vela_session_policy.Websession_driver.t_StartDriver)
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_StartTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_StartTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist12: Vela_session_policy.Websession_driver.t_StartTransition) =
            match
              start_effect_of transition <: Vela_session_policy.Websession_driver.t_StartEffect
            with
            | Vela_session_policy.Websession_driver.StartEffect_CheckRateLimit  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_StartLimitObservation)
              =
                f_check_rate_limit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.start_step (start_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_StartDriver)
                (Vela_session_policy.Websession_driver.StartEvent_LimitObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_StartEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_StartTransition)
            | Vela_session_policy.Websession_driver.StartEffect_ValidateStart  ->
              let
              (tmp0: v_Io),
              (out: Vela_session_policy.Websession_driver.t_StartValidationObservation) =
                f_validate_start #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.start_step (start_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_StartDriver)
                (Vela_session_policy.Websession_driver.StartEvent_Validated out
                  <:
                  Vela_session_policy.Websession_driver.t_StartEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_StartTransition)
            | Vela_session_policy.Websession_driver.StartEffect_InsertPending  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_StartInsertObservation) =
                f_insert_pending #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.start_step (start_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_StartDriver)
                (Vela_session_policy.Websession_driver.StartEvent_Inserted out
                  <:
                  Vela_session_policy.Websession_driver.t_StartEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_StartTransition)
            | Vela_session_policy.Websession_driver.StartEffect_Complete
            | Vela_session_policy.Websession_driver.StartEffect_Fail _
            | Vela_session_policy.Websession_driver.StartEffect_Idle  ->
              io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_StartTransition)
          in
          let transition:Vela_session_policy.Websession_driver.t_StartTransition = hoist12 in
          io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_StartTransition))
  in
  let hax_temp_output:Vela_session_policy.Websession_driver.t_StartTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Websession_driver.t_StartTransition)

/// The three effects a grant can perform before its verdict.
let v_GRANT_MAX_EFFECTS: usize = mk_usize 3

let grant_effect_is_terminal (v_effect: Vela_session_policy.Websession_driver.t_GrantEffect) : bool =
  match v_effect <: Vela_session_policy.Websession_driver.t_GrantEffect with
  | Vela_session_policy.Websession_driver.GrantEffect_Complete
  | Vela_session_policy.Websession_driver.GrantEffect_Fail _
  | Vela_session_policy.Websession_driver.GrantEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal grant effect.
class t_GrantIo (v_Self: Type0) = {
  f_validate_grant_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_validate_grant_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_GrantValidationObservation)
    -> Type0;
  f_validate_grant:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_GrantValidationObservation)
        (f_validate_grant_pre x0)
        (fun result -> f_validate_grant_post x0 result);
  f_grant_load_session_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_grant_load_session_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_GrantLookupObservation)
    -> Type0;
  f_grant_load_session:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_GrantLookupObservation)
        (f_grant_load_session_pre x0)
        (fun result -> f_grant_load_session_post x0 result);
  f_update_grant_pre:self_: v_Self -> update: Vela_session_policy.Websession_driver.t_GrantUpdate
    -> pred: Type0{true ==> pred};
  f_update_grant_post:
      v_Self ->
      Vela_session_policy.Websession_driver.t_GrantUpdate ->
      (v_Self & Vela_session_policy.Websession_driver.t_GrantUpdateObservation)
    -> Type0;
  f_update_grant:x0: v_Self -> x1: Vela_session_policy.Websession_driver.t_GrantUpdate
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_GrantUpdateObservation)
        (f_update_grant_pre x0 x1)
        (fun result -> f_update_grant_post x0 x1 result)
}

/// The synchronous expansion of [`websession_grant_interpreter!`].
let run_grant
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_GrantIo v_Io)
      (io: v_Io)
      (actor: Vela_session_policy.Websession_driver.t_GrantActorObservation)
      (requested_ttl: Core_models.Option.t_Option i64)
    : (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition) =
  let transition:Vela_session_policy.Websession_driver.t_GrantTransition =
    Vela_session_policy.Websession_driver.begin_grant actor requested_ttl
  in
  let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_GrantTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_GRANT_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_GrantTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Websession_driver.grant_state_is_sound (grant_driver_of transition
              <:
              Vela_session_policy.Websession_driver.t_GrantDriver)
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_GrantTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist19: Vela_session_policy.Websession_driver.t_GrantTransition) =
            match
              grant_effect_of transition <: Vela_session_policy.Websession_driver.t_GrantEffect
            with
            | Vela_session_policy.Websession_driver.GrantEffect_ValidateGrant  ->
              let
              (tmp0: v_Io),
              (out: Vela_session_policy.Websession_driver.t_GrantValidationObservation) =
                f_validate_grant #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.grant_step (grant_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_GrantDriver)
                (Vela_session_policy.Websession_driver.GrantEvent_Validated out
                  <:
                  Vela_session_policy.Websession_driver.t_GrantEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition)
            | Vela_session_policy.Websession_driver.GrantEffect_LoadSession  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_GrantLookupObservation) =
                f_grant_load_session #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.grant_step (grant_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_GrantDriver)
                (Vela_session_policy.Websession_driver.GrantEvent_SessionObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_GrantEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition)
            | Vela_session_policy.Websession_driver.GrantEffect_UpdateGrant update ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_GrantUpdateObservation) =
                f_update_grant #v_Io #FStar.Tactics.Typeclasses.solve io update
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.grant_step (grant_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_GrantDriver)
                (Vela_session_policy.Websession_driver.GrantEvent_UpdateObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_GrantEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition)
            | Vela_session_policy.Websession_driver.GrantEffect_Complete
            | Vela_session_policy.Websession_driver.GrantEffect_Fail _
            | Vela_session_policy.Websession_driver.GrantEffect_Idle  ->
              io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition)
          in
          let transition:Vela_session_policy.Websession_driver.t_GrantTransition = hoist19 in
          io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition))
  in
  let hax_temp_output:Vela_session_policy.Websession_driver.t_GrantTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Websession_driver.t_GrantTransition)

/// The eight effects an exchange can perform before its verdict.
let v_TOKEN_MAX_EFFECTS: usize = mk_usize 7

let token_effect_is_terminal (v_effect: Vela_session_policy.Websession_driver.t_TokenEffect) : bool =
  match v_effect <: Vela_session_policy.Websession_driver.t_TokenEffect with
  | Vela_session_policy.Websession_driver.TokenEffect_Complete
  | Vela_session_policy.Websession_driver.TokenEffect_Fail _
  | Vela_session_policy.Websession_driver.TokenEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal token effect.
class t_TokenIo (v_Self: Type0) = {
  f_check_token_limits_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_token_limits_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenLimitObservation)
    -> Type0;
  f_check_token_limits:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenLimitObservation)
        (f_check_token_limits_pre x0)
        (fun result -> f_check_token_limits_post x0 result);
  f_token_load_session_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_token_load_session_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenLookupObservation)
    -> Type0;
  f_token_load_session:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenLookupObservation)
        (f_token_load_session_pre x0)
        (fun result -> f_token_load_session_post x0 result);
  f_consume_web_token_challenge_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_consume_web_token_challenge_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenChallengeObservation)
    -> Type0;
  f_consume_web_token_challenge:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenChallengeObservation)
        (f_consume_web_token_challenge_pre x0)
        (fun result -> f_consume_web_token_challenge_post x0 result);
  f_verify_web_signature_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_verify_web_signature_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenSignatureObservation)
    -> Type0;
  f_verify_web_signature:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenSignatureObservation)
        (f_verify_web_signature_pre x0)
        (fun result -> f_verify_web_signature_post x0 result);
  f_record_token_failure_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_record_token_failure_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenFailureRecordObservation)
    -> Type0;
  f_record_token_failure:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenFailureRecordObservation)
        (f_record_token_failure_pre x0)
        (fun result -> f_record_token_failure_post x0 result);
  f_reset_token_backoff_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_reset_token_backoff_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenResetObservation)
    -> Type0;
  f_reset_token_backoff:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenResetObservation)
        (f_reset_token_backoff_pre x0)
        (fun result -> f_reset_token_backoff_post x0 result);
  f_claim_token_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_claim_token_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenClaimObservation)
    -> Type0;
  f_claim_token:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenClaimObservation)
        (f_claim_token_pre x0)
        (fun result -> f_claim_token_post x0 result);
  f_issue_token_pre:self_: v_Self -> plan: Vela_session_policy.t_TokenPlan
    -> pred: Type0{true ==> pred};
  f_issue_token_post:
      v_Self ->
      Vela_session_policy.t_TokenPlan ->
      (v_Self & Vela_session_policy.Websession_driver.t_TokenIssueObservation)
    -> Type0;
  f_issue_token:x0: v_Self -> x1: Vela_session_policy.t_TokenPlan
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_TokenIssueObservation)
        (f_issue_token_pre x0 x1)
        (fun result -> f_issue_token_post x0 x1 result)
}

/// The synchronous expansion of [`websession_token_interpreter!`].
let run_token
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_TokenIo v_Io)
      (io: v_Io)
    : (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition) =
  let transition:Vela_session_policy.Websession_driver.t_TokenTransition =
    Vela_session_policy.Websession_driver.begin_token ()
  in
  let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_TokenTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_TOKEN_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_TokenTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Websession_driver.token_state_is_sound (token_driver_of transition
              <:
              Vela_session_policy.Websession_driver.t_TokenDriver)
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_TokenTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist36: Vela_session_policy.Websession_driver.t_TokenTransition) =
            match
              token_effect_of transition <: Vela_session_policy.Websession_driver.t_TokenEffect
            with
            | Vela_session_policy.Websession_driver.TokenEffect_CheckTokenLimits  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_TokenLimitObservation)
              =
                f_check_token_limits #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_LimitsObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_LoadSession  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_TokenLookupObservation) =
                f_token_load_session #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_SessionObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_ConsumeWebTokenChallenge  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_TokenChallengeObservation)
              =
                f_consume_web_token_challenge #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_ChallengeObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_VerifyWebSignature  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_TokenSignatureObservation)
              =
                f_verify_web_signature #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_SignatureObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_RecordTokenFailure  ->
              let
              (tmp0: v_Io),
              (out: Vela_session_policy.Websession_driver.t_TokenFailureRecordObservation) =
                f_record_token_failure #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_FailureRecorded out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_ResetTokenBackoff  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_TokenResetObservation)
              =
                f_reset_token_backoff #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_ResetObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_ClaimToken  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_TokenClaimObservation)
              =
                f_claim_token #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_ClaimObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_IssueToken plan ->
              let (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_TokenIssueObservation)
              =
                f_issue_token #v_Io #FStar.Tactics.Typeclasses.solve io plan
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.token_step (token_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_TokenDriver)
                (Vela_session_policy.Websession_driver.TokenEvent_Issued out
                  <:
                  Vela_session_policy.Websession_driver.t_TokenEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
            | Vela_session_policy.Websession_driver.TokenEffect_Complete
            | Vela_session_policy.Websession_driver.TokenEffect_Fail _
            | Vela_session_policy.Websession_driver.TokenEffect_Idle  ->
              io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)
          in
          let transition:Vela_session_policy.Websession_driver.t_TokenTransition = hoist36 in
          io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition))
  in
  let hax_temp_output:Vela_session_policy.Websession_driver.t_TokenTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Websession_driver.t_TokenTransition)

/// The three effects a delete can perform before its verdict.
let v_DELETE_SESSION_MAX_EFFECTS: usize = mk_usize 3

let delete_effect_is_terminal (v_effect: Vela_session_policy.Websession_driver.t_DeleteEffect)
    : bool =
  match v_effect <: Vela_session_policy.Websession_driver.t_DeleteEffect with
  | Vela_session_policy.Websession_driver.DeleteEffect_Complete
  | Vela_session_policy.Websession_driver.DeleteEffect_Fail _
  | Vela_session_policy.Websession_driver.DeleteEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal delete effect.
class t_DeleteSessionIo (v_Self: Type0) = {
  f_delete_load_session_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_delete_load_session_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_DeleteLookupObservation)
    -> Type0;
  f_delete_load_session:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_DeleteLookupObservation)
        (f_delete_load_session_pre x0)
        (fun result -> f_delete_load_session_post x0 result);
  f_lockout_session_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_lockout_session_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_DeleteSentinelObservation)
    -> Type0;
  f_lockout_session:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_DeleteSentinelObservation)
        (f_lockout_session_pre x0)
        (fun result -> f_lockout_session_post x0 result);
  f_record_revocation_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_record_revocation_post:
      v_Self ->
      (v_Self & Vela_session_policy.Websession_driver.t_DeleteRecordObservation)
    -> Type0;
  f_record_revocation:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Websession_driver.t_DeleteRecordObservation)
        (f_record_revocation_pre x0)
        (fun result -> f_record_revocation_post x0 result)
}

/// The synchronous expansion of [`websession_delete_interpreter!`].
let run_delete
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DeleteSessionIo v_Io)
      (io: v_Io)
      (actor: Vela_session_policy.Websession_driver.t_DeleteActorObservation)
    : (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition) =
  let transition:Vela_session_policy.Websession_driver.t_DeleteTransition =
    Vela_session_policy.Websession_driver.begin_delete actor
  in
  let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_DeleteTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_DELETE_SESSION_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_DeleteTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Websession_driver.delete_state_is_sound (delete_driver_of transition
              <:
              Vela_session_policy.Websession_driver.t_DeleteDriver)
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Websession_driver.t_DeleteTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist43: Vela_session_policy.Websession_driver.t_DeleteTransition) =
            match
              delete_effect_of transition <: Vela_session_policy.Websession_driver.t_DeleteEffect
            with
            | Vela_session_policy.Websession_driver.DeleteEffect_LoadSession  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_DeleteLookupObservation) =
                f_delete_load_session #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.delete_step (delete_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_DeleteDriver)
                (Vela_session_policy.Websession_driver.DeleteEvent_SessionObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_DeleteEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition)
            | Vela_session_policy.Websession_driver.DeleteEffect_LockoutSession  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_DeleteSentinelObservation)
              =
                f_lockout_session #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.delete_step (delete_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_DeleteDriver)
                (Vela_session_policy.Websession_driver.DeleteEvent_SentinelWritten out
                  <:
                  Vela_session_policy.Websession_driver.t_DeleteEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition)
            | Vela_session_policy.Websession_driver.DeleteEffect_RecordRevocation  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Websession_driver.t_DeleteRecordObservation) =
                f_record_revocation #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Websession_driver.delete_step (delete_driver_of transition
                  <:
                  Vela_session_policy.Websession_driver.t_DeleteDriver)
                (Vela_session_policy.Websession_driver.DeleteEvent_RecordObserved out
                  <:
                  Vela_session_policy.Websession_driver.t_DeleteEvent)
              <:
              (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition)
            | Vela_session_policy.Websession_driver.DeleteEffect_Complete
            | Vela_session_policy.Websession_driver.DeleteEffect_Fail _
            | Vela_session_policy.Websession_driver.DeleteEffect_Idle  ->
              io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition)
          in
          let transition:Vela_session_policy.Websession_driver.t_DeleteTransition = hoist43 in
          io, transition <: (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition))
  in
  let hax_temp_output:Vela_session_policy.Websession_driver.t_DeleteTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Websession_driver.t_DeleteTransition)
