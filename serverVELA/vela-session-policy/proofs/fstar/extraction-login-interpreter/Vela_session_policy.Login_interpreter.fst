module Vela_session_policy.Login_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one request performs: the challenge take, the device lookup,
/// the verifier, the success-path reset, issuance and the JTI track. The
/// failure-record path replaces the reset, so six turns is the longest path.
let v_LOGIN_MAX_EFFECTS: usize = mk_usize 6

/// The driver has decided: nothing more may be performed.
let login_effect_is_terminal (v_effect: Vela_session_policy.Login_driver.t_LoginEffect) : bool =
  match v_effect <: Vela_session_policy.Login_driver.t_LoginEffect with
  | Vela_session_policy.Login_driver.LoginEffect_Respond
  | Vela_session_policy.Login_driver.LoginEffect_Fail _
  | Vela_session_policy.Login_driver.LoginEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects.
class t_LoginIo (v_Self: Type0) = {
  f_consume_challenge_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_consume_challenge_post:
      v_Self ->
      (v_Self & Vela_session_policy.Login_driver.t_ChallengeObservation)
    -> Type0;
  f_consume_challenge:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Login_driver.t_ChallengeObservation)
        (f_consume_challenge_pre x0)
        (fun result -> f_consume_challenge_post x0 result);
  f_observe_device_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_observe_device_post:v_Self -> (v_Self & Vela_session_policy.Login_driver.t_DeviceObservation)
    -> Type0;
  f_observe_device:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Login_driver.t_DeviceObservation)
        (f_observe_device_pre x0)
        (fun result -> f_observe_device_post x0 result);
  f_verify_signature_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_verify_signature_post:
      v_Self ->
      (v_Self & Vela_session_policy.Login_driver.t_VerifierObservation)
    -> Type0;
  f_verify_signature:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Login_driver.t_VerifierObservation)
        (f_verify_signature_pre x0)
        (fun result -> f_verify_signature_post x0 result);
  f_record_verification_failure_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_record_verification_failure_post:
      v_Self ->
      (v_Self & Vela_session_policy.Login_driver.t_FailureRecordObservation)
    -> Type0;
  f_record_verification_failure:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Login_driver.t_FailureRecordObservation)
        (f_record_verification_failure_pre x0)
        (fun result -> f_record_verification_failure_post x0 result);
  f_reset_backoff_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_reset_backoff_post:
      v_Self ->
      (v_Self & Vela_session_policy.Login_driver.t_BackoffResetObservation)
    -> Type0;
  f_reset_backoff:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Login_driver.t_BackoffResetObservation)
        (f_reset_backoff_pre x0)
        (fun result -> f_reset_backoff_post x0 result);
  f_issue_token_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_issue_token_post:v_Self -> (v_Self & Vela_session_policy.Login_driver.t_TokenIssueObservation)
    -> Type0;
  f_issue_token:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Login_driver.t_TokenIssueObservation)
        (f_issue_token_pre x0)
        (fun result -> f_issue_token_post x0 result);
  f_track_token_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_track_token_post:v_Self -> (v_Self & Vela_session_policy.Login_driver.t_TokenTrackObservation)
    -> Type0;
  f_track_token:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Login_driver.t_TokenTrackObservation)
        (f_track_token_pre x0)
        (fun result -> f_track_token_post x0 result)
}

/// The synchronous expansion of [`login_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_login
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_LoginIo v_Io)
      (io: v_Io)
    : (v_Io & Vela_session_policy.Login_driver.t_LoginTransition) =
  let transition:Vela_session_policy.Login_driver.t_LoginTransition =
    Vela_session_policy.Login_driver.begin_login ()
  in
  let (io: v_Io), (transition: Vela_session_policy.Login_driver.t_LoginTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_LOGIN_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Login_driver.t_LoginTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Login_driver.login_state_is_sound transition
              .Vela_session_policy.Login_driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Login_driver.t_LoginTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Login_driver.t_LoginTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist15: Vela_session_policy.Login_driver.t_LoginTransition) =
            match
              transition.Vela_session_policy.Login_driver.f_effect
              <:
              Vela_session_policy.Login_driver.t_LoginEffect
            with
            | Vela_session_policy.Login_driver.LoginEffect_ConsumeChallenge  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Login_driver.t_ChallengeObservation) =
                f_consume_challenge #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Login_driver.step transition
                  .Vela_session_policy.Login_driver.f_driver
                (Vela_session_policy.Login_driver.LoginEvent_ChallengeObserved out
                  <:
                  Vela_session_policy.Login_driver.t_LoginEvent)
              <:
              (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
            | Vela_session_policy.Login_driver.LoginEffect_ObserveDevice  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Login_driver.t_DeviceObservation) =
                f_observe_device #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Login_driver.step transition
                  .Vela_session_policy.Login_driver.f_driver
                (Vela_session_policy.Login_driver.LoginEvent_DeviceObserved out
                  <:
                  Vela_session_policy.Login_driver.t_LoginEvent)
              <:
              (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
            | Vela_session_policy.Login_driver.LoginEffect_VerifySignature  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Login_driver.t_VerifierObservation) =
                f_verify_signature #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Login_driver.step transition
                  .Vela_session_policy.Login_driver.f_driver
                (Vela_session_policy.Login_driver.LoginEvent_VerifierObserved out
                  <:
                  Vela_session_policy.Login_driver.t_LoginEvent)
              <:
              (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
            | Vela_session_policy.Login_driver.LoginEffect_RecordVerificationFailure  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Login_driver.t_FailureRecordObservation) =
                f_record_verification_failure #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Login_driver.step transition
                  .Vela_session_policy.Login_driver.f_driver
                (Vela_session_policy.Login_driver.LoginEvent_FailureRecorded out
                  <:
                  Vela_session_policy.Login_driver.t_LoginEvent)
              <:
              (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
            | Vela_session_policy.Login_driver.LoginEffect_ResetBackoff  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Login_driver.t_BackoffResetObservation) =
                f_reset_backoff #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Login_driver.step transition
                  .Vela_session_policy.Login_driver.f_driver
                (Vela_session_policy.Login_driver.LoginEvent_BackoffResetObserved out
                  <:
                  Vela_session_policy.Login_driver.t_LoginEvent)
              <:
              (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
            | Vela_session_policy.Login_driver.LoginEffect_IssueToken  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Login_driver.t_TokenIssueObservation) =
                f_issue_token #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Login_driver.step transition
                  .Vela_session_policy.Login_driver.f_driver
                (Vela_session_policy.Login_driver.LoginEvent_TokenIssued out
                  <:
                  Vela_session_policy.Login_driver.t_LoginEvent)
              <:
              (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
            | Vela_session_policy.Login_driver.LoginEffect_TrackToken  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Login_driver.t_TokenTrackObservation) =
                f_track_token #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Login_driver.step transition
                  .Vela_session_policy.Login_driver.f_driver
                (Vela_session_policy.Login_driver.LoginEvent_TokenTracked out
                  <:
                  Vela_session_policy.Login_driver.t_LoginEvent)
              <:
              (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
            | Vela_session_policy.Login_driver.LoginEffect_Respond
            | Vela_session_policy.Login_driver.LoginEffect_Fail _
            | Vela_session_policy.Login_driver.LoginEffect_Idle  ->
              io, transition <: (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
          in
          let transition:Vela_session_policy.Login_driver.t_LoginTransition = hoist15 in
          io, transition <: (v_Io & Vela_session_policy.Login_driver.t_LoginTransition))
  in
  let hax_temp_output:Vela_session_policy.Login_driver.t_LoginTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Login_driver.t_LoginTransition)
