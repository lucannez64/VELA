module Vela_recovery_policy.Possession_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one initiation performs: observe, store the challenge, verdict.
let v_POSSESSION_INITIATION_MAX_EFFECTS: usize = mk_usize 3

/// The driver has decided: nothing more may be performed.
let initiation_effect_is_terminal
      (v_effect: Vela_recovery_policy.Possession_driver.t_InitiateEffect)
    : bool =
  match v_effect <: Vela_recovery_policy.Possession_driver.t_InitiateEffect with
  | Vela_recovery_policy.Possession_driver.InitiateEffect_Complete
  | Vela_recovery_policy.Possession_driver.InitiateEffect_Fail _
  | Vela_recovery_policy.Possession_driver.InitiateEffect_Idle  -> true
  | _ -> false

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
let initiation_transition_is_sound
      (transition: Vela_recovery_policy.Possession_driver.t_InitiateTransition)
    : bool =
  Vela_recovery_policy.Possession_driver.initiation_state_is_sound transition
      .Vela_recovery_policy.Possession_driver.f_driver &&
  Vela_recovery_policy.Possession_driver.initiation_effect_is_sound transition
      .Vela_recovery_policy.Possession_driver.f_driver
    transition.Vela_recovery_policy.Possession_driver.f_effect

/// The I/O behind each non-terminal initiation effect. `None` aborts the
/// request with the error the executor recorded.
class t_PossessionInitiationIo (v_Self: Type0) = {
  f_observe_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_observe_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_InitiateObservation)
    -> Type0;
  f_observe:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_InitiateObservation)
        (f_observe_pre x0)
        (fun result -> f_observe_post x0 result);
  f_store_challenge_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_store_challenge_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_ChallengeStoreObservation)
    -> Type0;
  f_store_challenge:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_ChallengeStoreObservation)
        (f_store_challenge_pre x0)
        (fun result -> f_store_challenge_post x0 result)
}

/// The synchronous expansion of [`possession_initiation_interpreter!`].
let run_possession_initiation
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_PossessionInitiationIo v_Io)
      (io: v_Io)
    : (v_Io &
      Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_InitiateTransition) =
  let transition:Vela_recovery_policy.Possession_driver.t_InitiateTransition =
    Vela_recovery_policy.Possession_driver.begin_initiation ()
  in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (transition: Vela_recovery_policy.Possession_driver.t_InitiateTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_POSSESSION_INITIATION_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Possession_driver.t_InitiateTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          initiation_transition_is_sound transition <: bool)
      (aborted, io, transition
        <:
        (bool & v_Io & Vela_recovery_policy.Possession_driver.t_InitiateTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Possession_driver.t_InitiateTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if ~.aborted <: bool
          then
            let
            ((aborted: bool), (io: v_Io)),
            (hoist5: Vela_recovery_policy.Possession_driver.t_InitiateTransition) =
              match
                transition.Vela_recovery_policy.Possession_driver.f_effect
                <:
                Vela_recovery_policy.Possession_driver.t_InitiateEffect
              with
              | Vela_recovery_policy.Possession_driver.InitiateEffect_Observe  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Possession_driver.t_InitiateObservation) =
                  f_observe #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Possession_driver.t_InitiateObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Possession_driver.step_initiation transition
                        .Vela_recovery_policy.Possession_driver.f_driver
                      (Vela_recovery_policy.Possession_driver.InitiateEvent_Observed observation
                        <:
                        Vela_recovery_policy.Possession_driver.t_InitiateEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_InitiateTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_InitiateTransition))
              | Vela_recovery_policy.Possession_driver.InitiateEffect_StoreChallenge  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Possession_driver.t_ChallengeStoreObservation) =
                  f_store_challenge #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Possession_driver.t_ChallengeStoreObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Possession_driver.step_initiation transition
                        .Vela_recovery_policy.Possession_driver.f_driver
                      (Vela_recovery_policy.Possession_driver.InitiateEvent_Stored observation
                        <:
                        Vela_recovery_policy.Possession_driver.t_InitiateEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_InitiateTransition)
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_InitiateTransition))
              | Vela_recovery_policy.Possession_driver.InitiateEffect_Complete
              | Vela_recovery_policy.Possession_driver.InitiateEffect_Fail _
              | Vela_recovery_policy.Possession_driver.InitiateEffect_Idle  ->
                (aborted, io <: (bool & v_Io)), transition
                <:
                ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_InitiateTransition)
            in
            let transition:Vela_recovery_policy.Possession_driver.t_InitiateTransition = hoist5 in
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Possession_driver.t_InitiateTransition)
          else
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Possession_driver.t_InitiateTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option
  Vela_recovery_policy.Possession_driver.t_InitiateTransition =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_InitiateTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_InitiateTransition
  in
  io, hax_temp_output
  <:
  (v_Io & Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_InitiateTransition)

/// Most effects one proof recovery performs: count, consume, query, verify,
/// issue, verdict.
let v_POSSESSION_RECOVER_MAX_EFFECTS: usize = mk_usize 6

/// The driver has decided: nothing more may be performed.
let proof_recover_effect_is_terminal
      (v_effect: Vela_recovery_policy.Possession_driver.t_ProofRecoverEffect)
    : bool =
  match v_effect <: Vela_recovery_policy.Possession_driver.t_ProofRecoverEffect with
  | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_Complete
  | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_Fail _
  | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_Idle  -> true
  | _ -> false

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
let proof_recover_transition_is_sound
      (transition: Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition)
    : bool =
  Vela_recovery_policy.Possession_driver.proof_recover_state_is_sound transition
      .Vela_recovery_policy.Possession_driver.f_driver &&
  Vela_recovery_policy.Possession_driver.proof_recover_effect_is_sound transition
      .Vela_recovery_policy.Possession_driver.f_driver
    transition.Vela_recovery_policy.Possession_driver.f_effect

/// The I/O behind each non-terminal proof-recovery effect. `None` aborts
/// the request with the error the executor recorded.
class t_PossessionRecoverIo (v_Self: Type0) = {
  f_count_attempt_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_count_attempt_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_AttemptBudgetObservation)
    -> Type0;
  f_count_attempt:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_AttemptBudgetObservation)
        (f_count_attempt_pre x0)
        (fun result -> f_count_attempt_post x0 result);
  f_consume_attempt_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_consume_attempt_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation)
    -> Type0;
  f_consume_attempt:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation)
        (f_consume_attempt_pre x0)
        (fun result -> f_consume_attempt_post x0 result);
  f_query_account_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_query_account_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_ProofAccountObservation)
    -> Type0;
  f_query_account:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option
          Vela_recovery_policy.Possession_driver.t_ProofAccountObservation)
        (f_query_account_pre x0)
        (fun result -> f_query_account_post x0 result);
  f_verify_proof_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_verify_proof_post:
      v_Self ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_ProofObservation)
    -> Type0;
  f_verify_proof:x0: v_Self
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_ProofObservation)
        (f_verify_proof_pre x0)
        (fun result -> f_verify_proof_post x0 result);
  f_issue_grant_pre:
      self_: v_Self ->
      permit: Vela_recovery_policy.Possession_driver.t_ProofGrantPermit
    -> pred: Type0{true ==> pred};
  f_issue_grant_post:
      v_Self ->
      Vela_recovery_policy.Possession_driver.t_ProofGrantPermit ->
      (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_GrantStoreObservation
        )
    -> Type0;
  f_issue_grant:x0: v_Self -> x1: Vela_recovery_policy.Possession_driver.t_ProofGrantPermit
    -> Prims.Pure
        (v_Self &
          Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_GrantStoreObservation
        ) (f_issue_grant_pre x0 x1) (fun result -> f_issue_grant_post x0 x1 result)
}

/// The synchronous expansion of [`possession_recover_interpreter!`].
let run_possession_recover
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_PossessionRecoverIo v_Io)
      (io: v_Io)
    : (v_Io &
      Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition) =
  let transition:Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition =
    Vela_recovery_policy.Possession_driver.begin_proof_recover ()
  in
  let aborted:bool = false in
  let
  (aborted: bool),
  (io: v_Io),
  (transition: Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_POSSESSION_RECOVER_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          proof_recover_transition_is_sound transition <: bool)
      (aborted, io, transition
        <:
        (bool & v_Io & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition))
      (fun temp_0_ temp_1_ ->
          let
          (aborted: bool),
          (io: v_Io),
          (transition: Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          if ~.aborted <: bool
          then
            let
            ((aborted: bool), (io: v_Io)),
            (hoist11: Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition) =
              match
                transition.Vela_recovery_policy.Possession_driver.f_effect
                <:
                Vela_recovery_policy.Possession_driver.t_ProofRecoverEffect
              with
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_CountAttempt  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Possession_driver.t_AttemptBudgetObservation) =
                  f_count_attempt #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Possession_driver.t_AttemptBudgetObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Possession_driver.step_proof_recover transition
                        .Vela_recovery_policy.Possession_driver.f_driver
                      (Vela_recovery_policy.Possession_driver.ProofRecoverEvent_AttemptCounted
                        observation
                        <:
                        Vela_recovery_policy.Possession_driver.t_ProofRecoverEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    )
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    ))
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_ConsumeAttempt  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation) =
                  f_consume_attempt #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Possession_driver.t_AttemptConsumptionObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Possession_driver.step_proof_recover transition
                        .Vela_recovery_policy.Possession_driver.f_driver
                      (Vela_recovery_policy.Possession_driver.ProofRecoverEvent_AttemptConsumed
                        observation
                        <:
                        Vela_recovery_policy.Possession_driver.t_ProofRecoverEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    )
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    ))
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_QueryAccount  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Possession_driver.t_ProofAccountObservation) =
                  f_query_account #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Possession_driver.t_ProofAccountObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Possession_driver.step_proof_recover transition
                        .Vela_recovery_policy.Possession_driver.f_driver
                      (Vela_recovery_policy.Possession_driver.ProofRecoverEvent_AccountObserved
                        observation
                        <:
                        Vela_recovery_policy.Possession_driver.t_ProofRecoverEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    )
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    ))
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_VerifyProof  ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Possession_driver.t_ProofObservation) =
                  f_verify_proof #v_Io #FStar.Tactics.Typeclasses.solve io
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Possession_driver.t_ProofObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Possession_driver.step_proof_recover transition
                        .Vela_recovery_policy.Possession_driver.f_driver
                      (Vela_recovery_policy.Possession_driver.ProofRecoverEvent_ProofObserved
                        observation
                        <:
                        Vela_recovery_policy.Possession_driver.t_ProofRecoverEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    )
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    ))
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_IssueGrant permit ->
                let
                (tmp0: v_Io),
                (out:
                  Core_models.Option.t_Option
                  Vela_recovery_policy.Possession_driver.t_GrantStoreObservation) =
                  f_issue_grant #v_Io #FStar.Tactics.Typeclasses.solve io permit
                in
                let io:v_Io = tmp0 in
                (match
                    out
                    <:
                    Core_models.Option.t_Option
                    Vela_recovery_policy.Possession_driver.t_GrantStoreObservation
                  with
                  | Core_models.Option.Option_Some observation ->
                    (aborted, io <: (bool & v_Io)),
                    Vela_recovery_policy.Possession_driver.step_proof_recover transition
                        .Vela_recovery_policy.Possession_driver.f_driver
                      (Vela_recovery_policy.Possession_driver.ProofRecoverEvent_GrantStored
                        observation
                        <:
                        Vela_recovery_policy.Possession_driver.t_ProofRecoverEvent)
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    )
                  | Core_models.Option.Option_None  ->
                    let aborted:bool = true in
                    (aborted, io <: (bool & v_Io)), transition
                    <:
                    ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
                    ))
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_Complete
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_Fail _
              | Vela_recovery_policy.Possession_driver.ProofRecoverEffect_Idle  ->
                (aborted, io <: (bool & v_Io)), transition
                <:
                ((bool & v_Io) & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition)
            in
            let transition:Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition =
              hoist11
            in
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition)
          else
            aborted, io, transition
            <:
            (bool & v_Io & Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition))
  in
  let hax_temp_output:Core_models.Option.t_Option
  Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition =
    if aborted
    then
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
    else
      Core_models.Option.Option_Some transition
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition
  in
  io, hax_temp_output
  <:
  (v_Io &
    Core_models.Option.t_Option Vela_recovery_policy.Possession_driver.t_ProofRecoverTransition)
