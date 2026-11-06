module Vela_session_policy.Revocation_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// The two transition records in [`crate::revocation_driver`] share the field
/// names `driver` and `effect`. hax keeps the projections, and F* cannot infer
/// a record type from a bare `transition.effect` when two records declare that
/// field, so the extracted loop reaches both through these typed functions.
/// They are pure accessors; nothing else depends on them.
let revocation_driver_of (transition: Vela_session_policy.Revocation_driver.t_RevocationTransition)
    : Vela_session_policy.Revocation_driver.t_RevocationDriver =
  transition.Vela_session_policy.Revocation_driver.f_driver

let revocation_effect_of (transition: Vela_session_policy.Revocation_driver.t_RevocationTransition)
    : Vela_session_policy.Revocation_driver.t_RevocationEffect =
  transition.Vela_session_policy.Revocation_driver.f_effect

let logout_driver_of (transition: Vela_session_policy.Revocation_driver.t_LogoutTransition)
    : Vela_session_policy.Revocation_driver.t_LogoutDriver =
  transition.Vela_session_policy.Revocation_driver.f_driver

let logout_effect_of (transition: Vela_session_policy.Revocation_driver.t_LogoutTransition)
    : Vela_session_policy.Revocation_driver.t_LogoutEffect =
  transition.Vela_session_policy.Revocation_driver.f_effect

/// Most effects one revocation performs: the target lookup, the device
/// lockout, the SQL record and the approved-web-session cascade. The
/// already-revoked retry repeats the lockout and cascade instead of recording,
/// so four turns is the longest path.
let v_REVOCATION_MAX_EFFECTS: usize = mk_usize 4

/// The revocation driver has decided: nothing more may be performed.
let revocation_effect_is_terminal
      (v_effect: Vela_session_policy.Revocation_driver.t_RevocationEffect)
    : bool =
  match v_effect <: Vela_session_policy.Revocation_driver.t_RevocationEffect with
  | Vela_session_policy.Revocation_driver.RevocationEffect_Complete
  | Vela_session_policy.Revocation_driver.RevocationEffect_Fail _
  | Vela_session_policy.Revocation_driver.RevocationEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal revocation effect. Each method returns
/// only the observation its effect expects.
class t_RevocationIo (v_Self: Type0) = {
  f_lookup_target_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_lookup_target_post:
      v_Self ->
      (v_Self & Vela_session_policy.Revocation_driver.t_DeviceLookupObservation)
    -> Type0;
  f_lookup_target:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Revocation_driver.t_DeviceLookupObservation)
        (f_lookup_target_pre x0)
        (fun result -> f_lookup_target_post x0 result);
  f_lockout_device_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_lockout_device_post:
      v_Self ->
      (v_Self & Vela_session_policy.Revocation_driver.t_LockoutObservation)
    -> Type0;
  f_lockout_device:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Revocation_driver.t_LockoutObservation)
        (f_lockout_device_pre x0)
        (fun result -> f_lockout_device_post x0 result);
  f_record_revocation_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_record_revocation_post:
      v_Self ->
      (v_Self & Vela_session_policy.Revocation_driver.t_RecordObservation)
    -> Type0;
  f_record_revocation:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Revocation_driver.t_RecordObservation)
        (f_record_revocation_pre x0)
        (fun result -> f_record_revocation_post x0 result);
  f_cascade_web_sessions_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_cascade_web_sessions_post:
      v_Self ->
      (v_Self & Vela_session_policy.Revocation_driver.t_CascadeObservation)
    -> Type0;
  f_cascade_web_sessions:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Revocation_driver.t_CascadeObservation)
        (f_cascade_web_sessions_pre x0)
        (fun result -> f_cascade_web_sessions_post x0 result)
}

/// The synchronous expansion of [`revocation_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_revocation
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RevocationIo v_Io)
      (io: v_Io)
      (actor: Vela_session_policy.Revocation_driver.t_ActorObservation)
    : (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition) =
  let transition:Vela_session_policy.Revocation_driver.t_RevocationTransition =
    Vela_session_policy.Revocation_driver.begin_revocation actor
  in
  let (io: v_Io), (transition: Vela_session_policy.Revocation_driver.t_RevocationTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REVOCATION_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Revocation_driver.t_RevocationTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Revocation_driver.revocation_state_is_sound (revocation_driver_of transition

              <:
              Vela_session_policy.Revocation_driver.t_RevocationDriver)
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Revocation_driver.t_RevocationTransition)
          =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist9: Vela_session_policy.Revocation_driver.t_RevocationTransition) =
            match
              revocation_effect_of transition
              <:
              Vela_session_policy.Revocation_driver.t_RevocationEffect
            with
            | Vela_session_policy.Revocation_driver.RevocationEffect_LookupTarget  ->
              let
              (tmp0: v_Io), (out: Vela_session_policy.Revocation_driver.t_DeviceLookupObservation) =
                f_lookup_target #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Revocation_driver.step (revocation_driver_of transition
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationDriver)
                (Vela_session_policy.Revocation_driver.RevocationEvent_TargetObserved out
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationEvent)
              <:
              (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition)
            | Vela_session_policy.Revocation_driver.RevocationEffect_LockoutDevice  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Revocation_driver.t_LockoutObservation) =
                f_lockout_device #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Revocation_driver.step (revocation_driver_of transition
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationDriver)
                (Vela_session_policy.Revocation_driver.RevocationEvent_LockoutObserved out
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationEvent)
              <:
              (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition)
            | Vela_session_policy.Revocation_driver.RevocationEffect_RecordRevocation  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Revocation_driver.t_RecordObservation) =
                f_record_revocation #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Revocation_driver.step (revocation_driver_of transition
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationDriver)
                (Vela_session_policy.Revocation_driver.RevocationEvent_RecordObserved out
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationEvent)
              <:
              (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition)
            | Vela_session_policy.Revocation_driver.RevocationEffect_CascadeWebSessions  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Revocation_driver.t_CascadeObservation) =
                f_cascade_web_sessions #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Revocation_driver.step (revocation_driver_of transition
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationDriver)
                (Vela_session_policy.Revocation_driver.RevocationEvent_CascadeObserved out
                  <:
                  Vela_session_policy.Revocation_driver.t_RevocationEvent)
              <:
              (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition)
            | Vela_session_policy.Revocation_driver.RevocationEffect_Complete
            | Vela_session_policy.Revocation_driver.RevocationEffect_Fail _
            | Vela_session_policy.Revocation_driver.RevocationEffect_Idle  ->
              io, transition
              <:
              (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition)
          in
          let transition:Vela_session_policy.Revocation_driver.t_RevocationTransition = hoist9 in
          io, transition <: (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition))
  in
  let hax_temp_output:Vela_session_policy.Revocation_driver.t_RevocationTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Revocation_driver.t_RevocationTransition)

/// Most effects one logout performs: the single JTI marker write.
let v_LOGOUT_MAX_EFFECTS: usize = mk_usize 1

/// The logout driver has decided: nothing more may be performed.
let logout_effect_is_terminal (v_effect: Vela_session_policy.Revocation_driver.t_LogoutEffect)
    : bool =
  match v_effect <: Vela_session_policy.Revocation_driver.t_LogoutEffect with
  | Vela_session_policy.Revocation_driver.LogoutEffect_Complete
  | Vela_session_policy.Revocation_driver.LogoutEffect_Fail _
  | Vela_session_policy.Revocation_driver.LogoutEffect_Idle  -> true
  | _ -> false

/// The I/O behind the one non-terminal logout effect.
class t_LogoutIo (v_Self: Type0) = {
  f_revoke_jti_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_revoke_jti_post:v_Self -> (v_Self & Vela_session_policy.Revocation_driver.t_LogoutObservation)
    -> Type0;
  f_revoke_jti:x0: v_Self
    -> Prims.Pure (v_Self & Vela_session_policy.Revocation_driver.t_LogoutObservation)
        (f_revoke_jti_pre x0)
        (fun result -> f_revoke_jti_post x0 result)
}

/// The synchronous expansion of [`logout_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_logout
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_LogoutIo v_Io)
      (io: v_Io)
    : (v_Io & Vela_session_policy.Revocation_driver.t_LogoutTransition) =
  let transition:Vela_session_policy.Revocation_driver.t_LogoutTransition =
    Vela_session_policy.Revocation_driver.begin_logout ()
  in
  let (io: v_Io), (transition: Vela_session_policy.Revocation_driver.t_LogoutTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_LOGOUT_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Revocation_driver.t_LogoutTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_session_policy.Revocation_driver.logout_state_is_sound (logout_driver_of transition
              <:
              Vela_session_policy.Revocation_driver.t_LogoutDriver)
          <:
          bool)
      (io, transition <: (v_Io & Vela_session_policy.Revocation_driver.t_LogoutTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_session_policy.Revocation_driver.t_LogoutTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist11: Vela_session_policy.Revocation_driver.t_LogoutTransition) =
            match
              logout_effect_of transition <: Vela_session_policy.Revocation_driver.t_LogoutEffect
            with
            | Vela_session_policy.Revocation_driver.LogoutEffect_RevokeJti  ->
              let (tmp0: v_Io), (out: Vela_session_policy.Revocation_driver.t_LogoutObservation) =
                f_revoke_jti #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_session_policy.Revocation_driver.logout_step (logout_driver_of transition
                  <:
                  Vela_session_policy.Revocation_driver.t_LogoutDriver)
                out
              <:
              (v_Io & Vela_session_policy.Revocation_driver.t_LogoutTransition)
            | Vela_session_policy.Revocation_driver.LogoutEffect_Complete
            | Vela_session_policy.Revocation_driver.LogoutEffect_Fail _
            | Vela_session_policy.Revocation_driver.LogoutEffect_Idle  ->
              io, transition <: (v_Io & Vela_session_policy.Revocation_driver.t_LogoutTransition)
          in
          let transition:Vela_session_policy.Revocation_driver.t_LogoutTransition = hoist11 in
          io, transition <: (v_Io & Vela_session_policy.Revocation_driver.t_LogoutTransition))
  in
  let hax_temp_output:Vela_session_policy.Revocation_driver.t_LogoutTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_session_policy.Revocation_driver.t_LogoutTransition)
