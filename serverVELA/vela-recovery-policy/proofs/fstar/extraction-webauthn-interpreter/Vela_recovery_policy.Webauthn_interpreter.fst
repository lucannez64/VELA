module Vela_recovery_policy.Webauthn_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one registration start performs: registration_start_observe, start the ceremony,
/// store the state, verdict.
let v_REGISTRATION_START_MAX_EFFECTS: usize = mk_usize 3

let registration_start_effect_is_terminal
      (v_effect: Vela_recovery_policy.Webauthn_driver.t_RegistrationStartEffect)
    : bool =
  match v_effect <: Vela_recovery_policy.Webauthn_driver.t_RegistrationStartEffect with
  | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_Complete
  | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_Fail _
  | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_Idle  -> true
  | _ -> false

let registration_start_transition_is_sound
      (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition)
    : bool =
  Vela_recovery_policy.Webauthn_driver.registration_start_state_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver &&
  Vela_recovery_policy.Webauthn_driver.registration_start_effect_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver
    transition.Vela_recovery_policy.Webauthn_driver.f_effect

/// The I/O behind each non-terminal registration-start effect. `None`
/// aborts the request with the error the executor recorded.
class t_RegistrationStartIo (v_Self: Type0) = {
  f_registration_start_observe_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_start_observe_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_RegistrationStartObservation)
    -> Type0;
  f_registration_start_observe:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_RegistrationStartObservation)
        (f_registration_start_observe_pre x0)
        (fun result -> f_registration_start_observe_post x0 result);
  f_registration_start_ceremony_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_start_ceremony_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation)
    -> Type0;
  f_registration_start_ceremony:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation)
        (f_registration_start_ceremony_pre x0)
        (fun result -> f_registration_start_ceremony_post x0 result);
  f_registration_start_store_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_start_store_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation)
    -> Type0;
  f_registration_start_store:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation)
        (f_registration_start_store_pre x0)
        (fun result -> f_registration_start_store_post x0 result)
}

let run_registration_start
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RegistrationStartIo v_Io)
      (io: v_Io)
    : (v_Io &
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition
    ) =
  let transition:Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition =
    Vela_recovery_policy.Webauthn_driver.begin_registration_start ()
  in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REGISTRATION_START_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          registration_start_transition_is_sound transition <: bool)
      (aborted, io, transition
        <:
        (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if ~.aborted <: bool
          then
            let
            ((aborted: bool), (io: v_Io)),
            (hoist10: Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition) =
              match
                transition.Vela_recovery_policy.Webauthn_driver.f_effect
                <:
                Vela_recovery_policy.Webauthn_driver.t_RegistrationStartEffect
              with
              | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_Observe  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_RegistrationStartObservation) =
                  f_registration_start_observe #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_RegistrationStartObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration_start transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationStartEvent_Observed
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationStartEvent)
                    <:
                    ((bool & v_Io) &
                      Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) &
                      Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_StartCeremony  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation) =
                  f_registration_start_ceremony #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration_start transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationStartEvent_CeremonyStarted
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationStartEvent)
                    <:
                    ((bool & v_Io) &
                      Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) &
                      Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_StoreState  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation) =
                  f_registration_start_store #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration_start transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationStartEvent_Stored
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationStartEvent)
                    <:
                    ((bool & v_Io) &
                      Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) &
                      Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_Complete
              | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_Fail _
              | Vela_recovery_policy.Webauthn_driver.RegistrationStartEffect_Idle  ->
                (aborted, io <: (bool & v_Io)), transition
                <:
                ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition)
            in
            let transition:Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition =
              hoist10
            in
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition)
          else
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option
  Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition
  in
  io, hax_temp_output
  <:
  (v_Io &
    Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationStartTransition)

/// Most effects one registration finish performs: count, consume, verify, look
/// up uniqueness, persist, verdict.
let v_REGISTRATION_MAX_EFFECTS: usize = mk_usize 5

let registration_effect_is_terminal
      (v_effect: Vela_recovery_policy.Webauthn_driver.t_RegistrationEffect)
    : bool =
  match v_effect <: Vela_recovery_policy.Webauthn_driver.t_RegistrationEffect with
  | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_Complete
  | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_Fail _
  | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_Idle  -> true
  | _ -> false

let registration_transition_is_sound
      (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
    : bool =
  Vela_recovery_policy.Webauthn_driver.registration_state_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver &&
  Vela_recovery_policy.Webauthn_driver.registration_effect_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver
    transition.Vela_recovery_policy.Webauthn_driver.f_effect

/// The I/O behind each non-terminal registration-finish effect.
class t_RegistrationIo (v_Self: Type0) = {
  f_registration_count_attempt_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_count_attempt_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation)
    -> Type0;
  f_registration_count_attempt:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation)
        (f_registration_count_attempt_pre x0)
        (fun result -> f_registration_count_attempt_post x0 result);
  f_registration_consume_state_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_consume_state_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation)
    -> Type0;
  f_registration_consume_state:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation)
        (f_registration_consume_state_pre x0)
        (fun result -> f_registration_consume_state_post x0 result);
  f_registration_verify_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_verify_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_RegistrationVerificationObservation)
    -> Type0;
  f_registration_verify:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_RegistrationVerificationObservation)
        (f_registration_verify_pre x0)
        (fun result -> f_registration_verify_post x0 result);
  f_registration_check_uniqueness_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_check_uniqueness_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation)
    -> Type0;
  f_registration_check_uniqueness:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation)
        (f_registration_check_uniqueness_pre x0)
        (fun result -> f_registration_check_uniqueness_post x0 result);
  f_registration_persist_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_registration_persist_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation)
    -> Type0;
  f_registration_persist:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation)
        (f_registration_persist_pre x0)
        (fun result -> f_registration_persist_post x0 result)
}

let run_registration
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_RegistrationIo v_Io)
      (io: v_Io)
    : (v_Io &
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition) =
  let transition:Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition =
    Vela_recovery_policy.Webauthn_driver.begin_registration ()
  in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_REGISTRATION_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          registration_transition_is_sound transition <: bool)
      (aborted, io, transition
        <:
        (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if ~.aborted <: bool
          then
            let
            ((aborted: bool), (io: v_Io)),
            (hoist16: Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition) =
              match
                transition.Vela_recovery_policy.Webauthn_driver.f_effect
                <:
                Vela_recovery_policy.Webauthn_driver.t_RegistrationEffect
              with
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_CountAttempt  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation) =
                  f_registration_count_attempt #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationEvent_AttemptCounted
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_ConsumeState  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation) =
                  f_registration_consume_state #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationEvent_StateConsumed
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_VerifyRegistration  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_RegistrationVerificationObservation) =
                  f_registration_verify #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_RegistrationVerificationObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationEvent_RegistrationVerified
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_CheckCredentialUniqueness  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation) =
                  f_registration_check_uniqueness #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationEvent_CredentialLookedUp
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_PersistCredential  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation) =
                  f_registration_persist #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_registration transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.RegistrationEvent_CredentialPersisted
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_RegistrationEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition))
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_Complete
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_Fail _
              | Vela_recovery_policy.Webauthn_driver.RegistrationEffect_Idle  ->
                (aborted, io <: (bool & v_Io)), transition
                <:
                ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
            in
            let transition:Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition =
              hoist16
            in
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)
          else
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option
  Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition
  in
  io, hax_temp_output
  <:
  (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_RegistrationTransition)

/// Most effects one authentication start performs: auth_start_observe, start the
/// ceremony, store the challenge, verdict.
let v_AUTH_START_MAX_EFFECTS: usize = mk_usize 3

let auth_start_effect_is_terminal (v_effect: Vela_recovery_policy.Webauthn_driver.t_AuthStartEffect)
    : bool =
  match v_effect <: Vela_recovery_policy.Webauthn_driver.t_AuthStartEffect with
  | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_Complete
  | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_Fail _
  | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_Idle  -> true
  | _ -> false

let auth_start_transition_is_sound
      (transition: Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition)
    : bool =
  Vela_recovery_policy.Webauthn_driver.auth_start_state_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver &&
  Vela_recovery_policy.Webauthn_driver.auth_start_effect_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver
    transition.Vela_recovery_policy.Webauthn_driver.f_effect

/// The I/O behind each non-terminal authentication-start effect.
class t_AuthStartIo (v_Self: Type0) = {
  f_auth_start_observe_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_start_observe_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthStartObservation)
    -> Type0;
  f_auth_start_observe:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthStartObservation)
        (f_auth_start_observe_pre x0)
        (fun result -> f_auth_start_observe_post x0 result);
  f_auth_start_ceremony_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_start_ceremony_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation)
    -> Type0;
  f_auth_start_ceremony:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation)
        (f_auth_start_ceremony_pre x0)
        (fun result -> f_auth_start_ceremony_post x0 result);
  f_auth_start_store_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_start_store_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation)
    -> Type0;
  f_auth_start_store:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation)
        (f_auth_start_store_pre x0)
        (fun result -> f_auth_start_store_post x0 result)
}

let run_auth_start
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_AuthStartIo v_Io)
      (io: v_Io)
    : (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition
    ) =
  let transition:Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition =
    Vela_recovery_policy.Webauthn_driver.begin_auth_start ()
  in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (transition: Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_AUTH_START_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          auth_start_transition_is_sound transition <: bool)
      (aborted, io, transition
        <:
        (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if ~.aborted <: bool
          then
            let
            ((aborted: bool), (io: v_Io)),
            (hoist20: Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition) =
              match
                transition.Vela_recovery_policy.Webauthn_driver.f_effect
                <:
                Vela_recovery_policy.Webauthn_driver.t_AuthStartEffect
              with
              | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_Observe  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_AuthStartObservation) =
                  f_auth_start_observe #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_AuthStartObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_start transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthStartEvent_Observed observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthStartEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_StartCeremony  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation) =
                  f_auth_start_ceremony #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_CeremonyStartObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_start transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthStartEvent_CeremonyStarted
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthStartEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_StoreChallenge  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation) =
                  f_auth_start_store #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_start transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthStartEvent_Stored observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthStartEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_Complete
              | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_Fail _
              | Vela_recovery_policy.Webauthn_driver.AuthStartEffect_Idle  ->
                (aborted, io <: (bool & v_Io)), transition
                <:
                ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition)
            in
            let transition:Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition = hoist20 in
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition)
          else
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option
  Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition
  in
  io, hax_temp_output
  <:
  (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthStartTransition)

/// Most effects one authentication finish performs: count, observe context,
/// consume, verify, update, query, release, store, verdict.
let v_AUTH_FINISH_MAX_EFFECTS: usize = mk_usize 8

let auth_finish_effect_is_terminal
      (v_effect: Vela_recovery_policy.Webauthn_driver.t_AuthFinishEffect)
    : bool =
  match v_effect <: Vela_recovery_policy.Webauthn_driver.t_AuthFinishEffect with
  | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_Complete
  | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_Fail _
  | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_Idle  -> true
  | _ -> false

let auth_finish_transition_is_sound
      (transition: Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
    : bool =
  Vela_recovery_policy.Webauthn_driver.auth_finish_state_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver &&
  Vela_recovery_policy.Webauthn_driver.auth_finish_effect_is_sound transition
      .Vela_recovery_policy.Webauthn_driver.f_driver
    transition.Vela_recovery_policy.Webauthn_driver.f_effect

/// The I/O behind each non-terminal authentication-finish effect.
class t_AuthFinishIo (v_Self: Type0) = {
  f_auth_finish_count_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_finish_count_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation)
    -> Type0;
  f_auth_finish_count:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation)
        (f_auth_finish_count_pre x0)
        (fun result -> f_auth_finish_count_post x0 result);
  f_auth_finish_context_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_finish_context_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AuthFinishContextObservation)
    -> Type0;
  f_auth_finish_context:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AuthFinishContextObservation)
        (f_auth_finish_context_pre x0)
        (fun result -> f_auth_finish_context_post x0 result);
  f_auth_finish_consume_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_finish_consume_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation)
    -> Type0;
  f_auth_finish_consume:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation)
        (f_auth_finish_consume_pre x0)
        (fun result -> f_auth_finish_consume_post x0 result);
  f_auth_finish_verify_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_finish_verify_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AssertionObservation)
    -> Type0;
  f_auth_finish_verify:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AssertionObservation)
        (f_auth_finish_verify_pre x0)
        (fun result -> f_auth_finish_verify_post x0 result);
  f_auth_finish_update_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_finish_update_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CredentialUpdateStoreObservation)
    -> Type0;
  f_auth_finish_update:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Webauthn_driver.t_CredentialUpdateStoreObservation)
        (f_auth_finish_update_pre x0)
        (fun result -> f_auth_finish_update_post x0 result);
  f_auth_finish_account_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_finish_account_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthAccountObservation)
    -> Type0;
  f_auth_finish_account:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthAccountObservation)
        (f_auth_finish_account_pre x0)
        (fun result -> f_auth_finish_account_post x0 result);
  f_auth_finish_release_pre:
      self_: v_Self ->
      permit: Vela_recovery_policy.Webauthn_driver.t_AuthFinishGrantPermit
    -> pred: Type0{true ==> pred};
  f_auth_finish_release_post:
      v_Self ->
      Vela_recovery_policy.Webauthn_driver.t_AuthFinishGrantPermit ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation)
    -> Type0;
  f_auth_finish_release:
      x0: v_Self ->
      x1: Vela_recovery_policy.Webauthn_driver.t_AuthFinishGrantPermit
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation)
        (f_auth_finish_release_pre x0 x1)
        (fun result -> f_auth_finish_release_post x0 x1 result);
  f_auth_finish_store_grant_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_auth_finish_store_grant_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation)
    -> Type0;
  f_auth_finish_store_grant:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation)
        (f_auth_finish_store_grant_pre x0)
        (fun result -> f_auth_finish_store_grant_post x0 result)
}

let run_auth_finish
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_AuthFinishIo v_Io)
      (io: v_Io)
    : (v_Io &
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition) =
  let transition:Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition =
    Vela_recovery_policy.Webauthn_driver.begin_auth_finish ()
  in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (transition: Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_AUTH_FINISH_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          auth_finish_transition_is_sound transition <: bool)
      (aborted, io, transition
        <:
        (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if ~.aborted <: bool
          then
            let
            ((aborted: bool), (io: v_Io)),
            (hoist29: Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition) =
              match
                transition.Vela_recovery_policy.Webauthn_driver.f_effect
                <:
                Vela_recovery_policy.Webauthn_driver.t_AuthFinishEffect
              with
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_CountAttempt  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation) =
                  f_auth_finish_count #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_AttemptBudgetObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_AttemptCounted
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_ObserveContext  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_AuthFinishContextObservation) =
                  f_auth_finish_context #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_AuthFinishContextObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_ContextObserved
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_ConsumeAttempt  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation) =
                  f_auth_finish_consume #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_AttemptConsumed
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_VerifyAssertion  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_AssertionObservation) =
                  f_auth_finish_verify #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_AssertionObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_AssertionObserved
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_UpdateCredential  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_CredentialUpdateStoreObservation) =
                  f_auth_finish_update #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_CredentialUpdateStoreObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_CredentialUpdated
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_QueryAccount  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_AuthAccountObservation) =
                  f_auth_finish_account #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_AuthAccountObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_AccountObserved
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_ReleaseGrant permit ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation) =
                  f_auth_finish_release #v_Io #FStar.Tactics.Typeclasses.solve io permit
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_ShareObserved
                        observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_StoreGrant  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation) =
                  f_auth_finish_store_grant #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Webauthn_driver.step_auth_finish transition
                        .Vela_recovery_policy.Webauthn_driver.f_driver
                      (Vela_recovery_policy.Webauthn_driver.AuthFinishEvent_GrantStored observation
                        <:
                        Vela_recovery_policy.Webauthn_driver.t_AuthFinishEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_Complete
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_Fail _
              | Vela_recovery_policy.Webauthn_driver.AuthFinishEffect_Idle  ->
                (aborted, io <: (bool & v_Io)), transition
                <:
                ((bool & v_Io) & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
            in
            let transition:Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition = hoist29 in
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
          else
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option
  Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition
  in
  io, hax_temp_output
  <:
  (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_AuthFinishTransition)
