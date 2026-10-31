module Vela_enrollment_policy.Enroll_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one request performs: consume the challenge, check the device,
/// prepare the key material, check the epoch/rekey permit, insert the row.
let v_ENROLL_MAX_EFFECTS: usize = mk_usize 5

/// The driver has decided: nothing more may be performed.
let enroll_effect_is_terminal (v_effect: Vela_enrollment_policy.Enroll_driver.t_EnrollEffect) : bool =
  match v_effect <: Vela_enrollment_policy.Enroll_driver.t_EnrollEffect with
  | Vela_enrollment_policy.Enroll_driver.EnrollEffect_Complete
  | Vela_enrollment_policy.Enroll_driver.EnrollEffect_Fail _
  | Vela_enrollment_policy.Enroll_driver.EnrollEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects; the handler keeps the original error in
/// its own slot.
class t_EnrollIo (v_Self: Type0) = {
  f_consume_challenge_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_consume_challenge_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Enroll_driver.t_ChallengeObservation)
    -> Type0;
  f_consume_challenge:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Enroll_driver.t_ChallengeObservation)
        (f_consume_challenge_pre x0)
        (fun result -> f_consume_challenge_post x0 result);
  f_check_device_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_device_post:v_Self -> (v_Self & Vela_enrollment_policy.Enroll_driver.t_DeviceObservation)
    -> Type0;
  f_check_device:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Enroll_driver.t_DeviceObservation)
        (f_check_device_pre x0)
        (fun result -> f_check_device_post x0 result);
  f_prepare_enrollment_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_prepare_enrollment_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Enroll_driver.t_EnrollmentObservation)
    -> Type0;
  f_prepare_enrollment:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Enroll_driver.t_EnrollmentObservation)
        (f_prepare_enrollment_pre x0)
        (fun result -> f_prepare_enrollment_post x0 result);
  f_check_account_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_account_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Enroll_driver.t_AccountObservation)
    -> Type0;
  f_check_account:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Enroll_driver.t_AccountObservation)
        (f_check_account_pre x0)
        (fun result -> f_check_account_post x0 result);
  f_insert_device_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_insert_device_post:v_Self -> (v_Self & Vela_enrollment_policy.Enroll_driver.t_InsertObservation)
    -> Type0;
  f_insert_device:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Enroll_driver.t_InsertObservation)
        (f_insert_device_pre x0)
        (fun result -> f_insert_device_post x0 result)
}

/// The synchronous expansion of [`enroll_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_enroll
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_EnrollIo v_Io)
      (io: v_Io)
      (start: Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
    : Prims.Pure (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
      (requires
        Vela_enrollment_policy.Enroll_driver.enroll_state_is_sound start
            .Vela_enrollment_policy.Enroll_driver.f_driver)
      (fun _ -> Prims.l_True) =
  let transition:Vela_enrollment_policy.Enroll_driver.t_EnrollTransition = start in
  let (io: v_Io), (transition: Vela_enrollment_policy.Enroll_driver.t_EnrollTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_ENROLL_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_enrollment_policy.Enroll_driver.t_EnrollTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_enrollment_policy.Enroll_driver.enroll_state_is_sound transition
              .Vela_enrollment_policy.Enroll_driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_enrollment_policy.Enroll_driver.t_EnrollTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist11: Vela_enrollment_policy.Enroll_driver.t_EnrollTransition) =
            match
              transition.Vela_enrollment_policy.Enroll_driver.f_effect
              <:
              Vela_enrollment_policy.Enroll_driver.t_EnrollEffect
            with
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_ConsumeChallenge  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Enroll_driver.t_ChallengeObservation) =
                f_consume_challenge #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Enroll_driver.step transition
                  .Vela_enrollment_policy.Enroll_driver.f_driver
                (Vela_enrollment_policy.Enroll_driver.EnrollEvent_ChallengeConsumed out
                  <:
                  Vela_enrollment_policy.Enroll_driver.t_EnrollEvent)
              <:
              (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_CheckDevice  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Enroll_driver.t_DeviceObservation) =
                f_check_device #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Enroll_driver.step transition
                  .Vela_enrollment_policy.Enroll_driver.f_driver
                (Vela_enrollment_policy.Enroll_driver.EnrollEvent_DeviceChecked out
                  <:
                  Vela_enrollment_policy.Enroll_driver.t_EnrollEvent)
              <:
              (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_PrepareEnrollment  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Enroll_driver.t_EnrollmentObservation)
              =
                f_prepare_enrollment #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Enroll_driver.step transition
                  .Vela_enrollment_policy.Enroll_driver.f_driver
                (Vela_enrollment_policy.Enroll_driver.EnrollEvent_EnrollmentPrepared out
                  <:
                  Vela_enrollment_policy.Enroll_driver.t_EnrollEvent)
              <:
              (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_CheckAccount  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Enroll_driver.t_AccountObservation) =
                f_check_account #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Enroll_driver.step transition
                  .Vela_enrollment_policy.Enroll_driver.f_driver
                (Vela_enrollment_policy.Enroll_driver.EnrollEvent_AccountChecked out
                  <:
                  Vela_enrollment_policy.Enroll_driver.t_EnrollEvent)
              <:
              (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_InsertDevice  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Enroll_driver.t_InsertObservation) =
                f_insert_device #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Enroll_driver.step transition
                  .Vela_enrollment_policy.Enroll_driver.f_driver
                (Vela_enrollment_policy.Enroll_driver.EnrollEvent_DeviceInserted out
                  <:
                  Vela_enrollment_policy.Enroll_driver.t_EnrollEvent)
              <:
              (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_Complete
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_Fail _
            | Vela_enrollment_policy.Enroll_driver.EnrollEffect_Idle  ->
              io, transition <: (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)
          in
          let transition:Vela_enrollment_policy.Enroll_driver.t_EnrollTransition = hoist11 in
          io, transition <: (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition))
  in
  let hax_temp_output:Vela_enrollment_policy.Enroll_driver.t_EnrollTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_enrollment_policy.Enroll_driver.t_EnrollTransition)

/// The handler-facing entry point: the driver's begin decision, unchanged.
/// Handlers may not call the driver's `begin_enroll` directly.
let start_enroll (_: Prims.unit) : Vela_enrollment_policy.Enroll_driver.t_EnrollTransition =
  Vela_enrollment_policy.Enroll_driver.begin_enroll ()
