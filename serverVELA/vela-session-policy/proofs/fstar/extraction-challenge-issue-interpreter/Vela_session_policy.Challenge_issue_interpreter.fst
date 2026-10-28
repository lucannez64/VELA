module Vela_session_policy.Challenge_issue_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one request performs: the limiter, the random read and the
/// store write. A terminal effect needs no further turn.
let v_ISSUE_MAX_EFFECTS: usize = mk_usize 3

/// The driver has decided: nothing more may be performed.
let issue_effect_is_terminal (v_effect: Vela_session_policy.Challenge_issue_driver.t_IssueEffect)
    : bool =
  match v_effect <: Vela_session_policy.Challenge_issue_driver.t_IssueEffect with
  | Vela_session_policy.Challenge_issue_driver.IssueEffect_Issue
  | Vela_session_policy.Challenge_issue_driver.IssueEffect_Fail _
  | Vela_session_policy.Challenge_issue_driver.IssueEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects.
class t_ChallengeIssueIo (v_Self: Type0) = {
  f_check_rate_limit_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_rate_limit_post:
      v_Self ->
      (v_Self & Vela_session_policy.Challenge_issue_driver.t_RateLimitObservation)
    -> Type0;
  f_check_rate_limit:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Challenge_issue_driver.t_RateLimitObservation)
        (f_check_rate_limit_pre x0)
        (fun result -> f_check_rate_limit_post x0 result);
  f_generate_nonce_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_generate_nonce_post:
      v_Self ->
      (v_Self & Vela_session_policy.Challenge_issue_driver.t_NonceObservation)
    -> Type0;
  f_generate_nonce:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Challenge_issue_driver.t_NonceObservation)
        (f_generate_nonce_pre x0)
        (fun result -> f_generate_nonce_post x0 result);
  f_store_nonce_pre:self_: v_Self -> purpose: Vela_session_policy.Challenge.t_ChallengePurpose
    -> pred: Type0{true ==> pred};
  f_store_nonce_post:
      v_Self ->
      Vela_session_policy.Challenge.t_ChallengePurpose ->
      (v_Self & Vela_session_policy.Challenge_issue_driver.t_StoreObservation)
    -> Type0;
  f_store_nonce:x0: v_Self -> x1: Vela_session_policy.Challenge.t_ChallengePurpose
    -> Prims.Pure (v_Self & Vela_session_policy.Challenge_issue_driver.t_StoreObservation)
        (f_store_nonce_pre x0 x1)
        (fun result -> f_store_nonce_post x0 x1 result)
}

/// The synchronous expansion of [`challenge_issue_interpreter!`]: the artifact
/// hax extracts and F* checks.
let run_issue
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_ChallengeIssueIo v_Io)
      (io: v_Io)
      (purpose: Vela_session_policy.Challenge_issue_driver.t_PurposeObservation)
    : (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition) =
  let transition:Vela_session_policy.Challenge_issue_driver.t_IssueTransition =
    Vela_session_policy.Challenge_issue_driver.begin_issue purpose
  in
  let (io: v_Io), (transition: Vela_session_policy.Challenge_issue_driver.t_IssueTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_ISSUE_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Challenge_issue_driver.t_IssueTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Challenge_issue_driver.issue_state_is_sound transition
              .Vela_session_policy.Challenge_issue_driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Challenge_issue_driver.t_IssueTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist7: Vela_session_policy.Challenge_issue_driver.t_IssueTransition) =
            match
              transition.Vela_session_policy.Challenge_issue_driver.f_effect
              <:
              Vela_session_policy.Challenge_issue_driver.t_IssueEffect
            with
            | Vela_session_policy.Challenge_issue_driver.IssueEffect_CheckRateLimit  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Challenge_issue_driver.t_RateLimitObservation)
              =
                f_check_rate_limit #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Challenge_issue_driver.step transition
                  .Vela_session_policy.Challenge_issue_driver.f_driver
                (Vela_session_policy.Challenge_issue_driver.IssueEvent_RateLimitObserved out
                  <:
                  Vela_session_policy.Challenge_issue_driver.t_IssueEvent)
              <:
              (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition)
            | Vela_session_policy.Challenge_issue_driver.IssueEffect_GenerateNonce  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Challenge_issue_driver.t_NonceObservation)
              =
                f_generate_nonce #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Challenge_issue_driver.step transition
                  .Vela_session_policy.Challenge_issue_driver.f_driver
                (Vela_session_policy.Challenge_issue_driver.IssueEvent_NonceObserved out
                  <:
                  Vela_session_policy.Challenge_issue_driver.t_IssueEvent)
              <:
              (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition)
            | Vela_session_policy.Challenge_issue_driver.IssueEffect_StoreNonce  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Challenge_issue_driver.t_StoreObservation)
              =
                f_store_nonce #v_Io
                  #FStar.Tactics.Typeclasses.solve
                  io
                  transition.Vela_session_policy.Challenge_issue_driver.f_driver
                    .Vela_session_policy.Challenge_issue_driver.f_purpose
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Challenge_issue_driver.step transition
                  .Vela_session_policy.Challenge_issue_driver.f_driver
                (Vela_session_policy.Challenge_issue_driver.IssueEvent_StoreObserved out
                  <:
                  Vela_session_policy.Challenge_issue_driver.t_IssueEvent)
              <:
              (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition)
            | Vela_session_policy.Challenge_issue_driver.IssueEffect_Issue
            | Vela_session_policy.Challenge_issue_driver.IssueEffect_Fail _
            | Vela_session_policy.Challenge_issue_driver.IssueEffect_Idle  ->
              io, transition
              <:
              (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition)
          in
          let transition:Vela_session_policy.Challenge_issue_driver.t_IssueTransition = hoist7 in
          io, transition <: (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition))
  in
  let hax_temp_output:Vela_session_policy.Challenge_issue_driver.t_IssueTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Challenge_issue_driver.t_IssueTransition)
