module Vela_enrollment_policy.Pairing_interpreter
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Most effects one request performs: the account preflight, the verified
/// preflight, the destructive take, the guarded insert and the result write.
let v_PAIRING_MAX_EFFECTS: usize = mk_usize 5

/// The driver has decided: nothing more may be performed.
let pairing_effect_is_terminal (v_effect: Vela_enrollment_policy.Pairing_driver.t_PairingEffect)
    : bool =
  match v_effect <: Vela_enrollment_policy.Pairing_driver.t_PairingEffect with
  | Vela_enrollment_policy.Pairing_driver.PairingEffect_Complete
  | Vela_enrollment_policy.Pairing_driver.PairingEffect_ReturnResult _
  | Vela_enrollment_policy.Pairing_driver.PairingEffect_Fail _
  | Vela_enrollment_policy.Pairing_driver.PairingEffect_RestoreAndFail _
  | Vela_enrollment_policy.Pairing_driver.PairingEffect_Idle  -> true
  | _ -> false

/// The I/O behind each non-terminal effect. Each method returns only the
/// observation its effect expects.
class t_PairingIo (v_Self: Type0) = {
  f_store_package_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_store_package_post:v_Self -> (v_Self & Vela_enrollment_policy.Pairing_driver.t_StoreObservation)
    -> Type0;
  f_store_package:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_StoreObservation)
        (f_store_package_pre x0)
        (fun result -> f_store_package_post x0 result);
  f_redeem_package_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_redeem_package_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Pairing_driver.t_RedeemObservation)
    -> Type0;
  f_redeem_package:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_RedeemObservation)
        (f_redeem_package_pre x0)
        (fun result -> f_redeem_package_post x0 result);
  f_store_grant_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_store_grant_post:v_Self -> (v_Self & Vela_enrollment_policy.Pairing_driver.t_StoreObservation)
    -> Type0;
  f_store_grant:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_StoreObservation)
        (f_store_grant_pre x0)
        (fun result -> f_store_grant_post x0 result);
  f_check_claim_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_claim_post:v_Self -> (v_Self & Vela_enrollment_policy.t_ClaimObservation) -> Type0;
  f_check_claim:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.t_ClaimObservation)
        (f_check_claim_pre x0)
        (fun result -> f_check_claim_post x0 result);
  f_write_claim_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_write_claim_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation)
    -> Type0;
  f_write_claim:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation)
        (f_write_claim_pre x0)
        (fun result -> f_write_claim_post x0 result);
  f_check_account_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_check_account_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Pairing_driver.t_CompletionAccountObservation)
    -> Type0;
  f_check_account:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_CompletionAccountObservation)
        (f_check_account_pre x0)
        (fun result -> f_check_account_post x0 result);
  f_prepare_completion_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_prepare_completion_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Pairing_driver.t_CompletionPreflightObservation)
    -> Type0;
  f_prepare_completion:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_CompletionPreflightObservation)
        (f_prepare_completion_pre x0)
        (fun result -> f_prepare_completion_post x0 result);
  f_take_ceremony_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_take_ceremony_post:v_Self -> (v_Self & Vela_enrollment_policy.Pairing_driver.t_TakeObservation)
    -> Type0;
  f_take_ceremony:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_TakeObservation)
        (f_take_ceremony_pre x0)
        (fun result -> f_take_ceremony_post x0 result);
  f_insert_device_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_insert_device_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation)
    -> Type0;
  f_insert_device:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation)
        (f_insert_device_pre x0)
        (fun result -> f_insert_device_post x0 result);
  f_write_result_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_write_result_post:v_Self -> (v_Self & Vela_enrollment_policy.Pairing_driver.t_StoreObservation)
    -> Type0;
  f_write_result:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_StoreObservation)
        (f_write_result_pre x0)
        (fun result -> f_write_result_post x0 result);
  f_read_result_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_read_result_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation)
    -> Type0;
  f_read_result:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation)
        (f_read_result_pre x0)
        (fun result -> f_read_result_post x0 result);
  f_read_claim_pre:self_: v_Self -> pred: Type0{true ==> pred};
  f_read_claim_post:
      v_Self ->
      (v_Self & Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation)
    -> Type0;
  f_read_claim:x0: v_Self
    -> Prims.Pure (v_Self & Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation)
        (f_read_claim_pre x0)
        (fun result -> f_read_claim_post x0 result)
}

/// The synchronous expansion of [`pairing_interpreter!`]: the artifact hax
/// extracts and F* checks.
let run_pairing
      (#v_Io: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_PairingIo v_Io)
      (io: v_Io)
      (start: Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
    : Prims.Pure (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
      (requires
        Vela_enrollment_policy.Pairing_driver.pairing_state_is_sound start
            .Vela_enrollment_policy.Pairing_driver.f_driver)
      (fun _ -> Prims.l_True) =
  let transition:Vela_enrollment_policy.Pairing_driver.t_PairingTransition = start in
  let (io: v_Io), (transition: Vela_enrollment_policy.Pairing_driver.t_PairingTransition) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_PAIRING_MAX_EFFECTS
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_enrollment_policy.Pairing_driver.t_PairingTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          Vela_enrollment_policy.Pairing_driver.pairing_state_is_sound transition
              .Vela_enrollment_policy.Pairing_driver.f_driver
          <:
          bool)
      (io, transition <: (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition))
      (fun temp_0_ temp_1_ ->
          let (io: v_Io), (transition: Vela_enrollment_policy.Pairing_driver.t_PairingTransition) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let (io: v_Io), (hoist26: Vela_enrollment_policy.Pairing_driver.t_PairingTransition) =
            match
              transition.Vela_enrollment_policy.Pairing_driver.f_effect
              <:
              Vela_enrollment_policy.Pairing_driver.t_PairingEffect
            with
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_StorePackage  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_StoreObservation) =
                f_store_package #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_PackageWritten out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_RedeemPackage  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_RedeemObservation) =
                f_redeem_package #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_PackageRedeemed out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_StoreGrant  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_StoreObservation) =
                f_store_grant #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_GrantWritten out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_CheckClaim  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.t_ClaimObservation) =
                f_check_claim #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_ClaimChecked out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_WriteClaim  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation)
              =
                f_write_claim #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_ClaimWritten out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_CheckAccount  ->
              let
              (tmp0: v_Io),
              (out: Vela_enrollment_policy.Pairing_driver.t_CompletionAccountObservation) =
                f_check_account #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_AccountChecked out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_PrepareCompletion  ->
              let
              (tmp0: v_Io),
              (out: Vela_enrollment_policy.Pairing_driver.t_CompletionPreflightObservation) =
                f_prepare_completion #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_CompletionReady out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_TakeCeremony  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_TakeObservation) =
                f_take_ceremony #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_CeremonyTaken out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_InsertDevice  ->
              let
              (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation) =
                f_insert_device #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_DeviceInserted out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_WriteResult  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_StoreObservation) =
                f_write_result #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_ResultWritten out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_ReadResult  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation)
              =
                f_read_result #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_ResultRead out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_ReadClaim  ->
              let (tmp0: v_Io), (out: Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation)
              =
                f_read_claim #v_Io #FStar.Tactics.Typeclasses.solve io
              in
              let io:v_Io = tmp0 in
              io,
              Vela_enrollment_policy.Pairing_driver.step transition
                  .Vela_enrollment_policy.Pairing_driver.f_driver
                (Vela_enrollment_policy.Pairing_driver.PairingEvent_ClaimRead out
                  <:
                  Vela_enrollment_policy.Pairing_driver.t_PairingEvent)
              <:
              (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_Complete
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_ReturnResult _
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_Fail _
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_RestoreAndFail _
            | Vela_enrollment_policy.Pairing_driver.PairingEffect_Idle  ->
              io, transition <: (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)
          in
          let transition:Vela_enrollment_policy.Pairing_driver.t_PairingTransition = hoist26 in
          io, transition <: (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition))
  in
  let hax_temp_output:Vela_enrollment_policy.Pairing_driver.t_PairingTransition = transition in
  io, hax_temp_output <: (v_Io & Vela_enrollment_policy.Pairing_driver.t_PairingTransition)

let start_store_package
      (observation: Vela_enrollment_policy.Pairing_driver.t_PackageStoreObservation)
    : Vela_enrollment_policy.Pairing_driver.t_PairingTransition =
  Vela_enrollment_policy.Pairing_driver.begin_store_package observation

let start_redeem_package
      (observation: Vela_enrollment_policy.Pairing_driver.t_PackageTokenObservation)
    : Vela_enrollment_policy.Pairing_driver.t_PairingTransition =
  Vela_enrollment_policy.Pairing_driver.begin_redeem_package observation

let start_open_grant (observation: Vela_enrollment_policy.t_OpenObservation)
    : Vela_enrollment_policy.Pairing_driver.t_PairingTransition =
  Vela_enrollment_policy.Pairing_driver.begin_open_grant observation

let start_claim (grant_live: bool) : Vela_enrollment_policy.Pairing_driver.t_PairingTransition =
  Vela_enrollment_policy.Pairing_driver.begin_claim grant_live

let start_completion (grant: Vela_enrollment_policy.Pairing_driver.t_GrantObservation)
    : Vela_enrollment_policy.Pairing_driver.t_PairingTransition =
  Vela_enrollment_policy.Pairing_driver.begin_completion grant

let start_result (_: Prims.unit) : Vela_enrollment_policy.Pairing_driver.t_PairingTransition =
  Vela_enrollment_policy.Pairing_driver.begin_result ()
