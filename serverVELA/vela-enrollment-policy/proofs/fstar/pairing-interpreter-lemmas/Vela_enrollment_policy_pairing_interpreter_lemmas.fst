module Vela_enrollment_policy_pairing_interpreter_lemmas

/// The extracted `run_pairing` is the loop every device-pairing handler runs:
/// the server expands the same `pairing_interpreter!` macro text, adding only
/// `.await` after each executor call. This module proves, for every executor
/// implementation (any `t_PairingIo` instance, any behaviour):
///
/// 1. `run_pairing` calls the executor exactly as `run_ev` below does: one
///    method per turn, chosen by the effect the driver has just emitted, with
///    that effect's argument, and nothing once the driver reached a verdict
///    (`run_pairing_is_run_ev`);
/// 2. the observations the executor returned form a list in which each
///    observation answers the effect it was returned for, and the final driver
///    is the extracted driver's `run_from_*` over that list
///    (`run_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of 5 turns
///    (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request pairing theorem holds for the state the real
///    handler ends in (the corollaries at the end).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copies differ only by `.await`).

open FStar.Mul
open Core_models
open Vela_enrollment_policy
open Vela_enrollment_policy.Pairing_driver
open Vela_enrollment_policy.Pairing_interpreter
open Vela_enrollment_policy_pairing_driver_lemmas

// ── The specification of one interpreter turn ─────────────────────────────

let terminal (e: t_PairingEffect) : bool =
  match e with
  | PairingEffect_Complete | PairingEffect_ReturnResult _ | PairingEffect_Fail _
  | PairingEffect_RestoreAndFail _ | PairingEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_PairingEffect) (ev: t_PairingEvent) : bool =
  match e, ev with
  | PairingEffect_StorePackage, PairingEvent_PackageWritten _
  | PairingEffect_RedeemPackage, PairingEvent_PackageRedeemed _
  | PairingEffect_StoreGrant, PairingEvent_GrantWritten _
  | PairingEffect_CheckClaim, PairingEvent_ClaimChecked _
  | PairingEffect_WriteClaim, PairingEvent_ClaimWritten _
  | PairingEffect_CheckAccount, PairingEvent_AccountChecked _
  | PairingEffect_PrepareCompletion, PairingEvent_CompletionReady _
  | PairingEffect_TakeCeremony, PairingEvent_CeremonyTaken _
  | PairingEffect_InsertDevice, PairingEvent_DeviceInserted _
  | PairingEffect_WriteResult, PairingEvent_ResultWritten _
  | PairingEffect_ReadResult, PairingEvent_ResultRead _
  | PairingEffect_ReadClaim, PairingEvent_ClaimRead _
  | PairingEffect_ReadEnrolledDevice, PairingEvent_EnrolledDeviceRead _ -> true
  | _ -> false

let sound_transition (t: t_PairingTransition) : bool =
  pairing_state_is_sound t.f_driver && pairing_effect_is_sound t.f_driver t.f_effect

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t) (t: t_PairingTransition)
  : Pure (io_t & t_PairingTransition & option t_PairingEvent)
    (requires pairing_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | PairingEffect_StorePackage ->
      let (s', o) = f_store_package #io_t #i s in
      let ev = PairingEvent_PackageWritten o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_RedeemPackage ->
      let (s', o) = f_redeem_package #io_t #i s in
      let ev = PairingEvent_PackageRedeemed o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_StoreGrant ->
      let (s', o) = f_store_grant #io_t #i s in
      let ev = PairingEvent_GrantWritten o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_CheckClaim ->
      let (s', o) = f_check_claim #io_t #i s in
      let ev = PairingEvent_ClaimChecked o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_WriteClaim ->
      let (s', o) = f_write_claim #io_t #i s in
      let ev = PairingEvent_ClaimWritten o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_CheckAccount ->
      let (s', o) = f_check_account #io_t #i s in
      let ev = PairingEvent_AccountChecked o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_PrepareCompletion ->
      let (s', o) = f_prepare_completion #io_t #i s in
      let ev = PairingEvent_CompletionReady o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_TakeCeremony ->
      let (s', o) = f_take_ceremony #io_t #i s in
      let ev = PairingEvent_CeremonyTaken o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_InsertDevice ->
      let (s', o) = f_insert_device #io_t #i s in
      let ev = PairingEvent_DeviceInserted o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_WriteResult ->
      let (s', o) = f_write_result #io_t #i s in
      let ev = PairingEvent_ResultWritten o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_ReadResult ->
      let (s', o) = f_read_result #io_t #i s in
      let ev = PairingEvent_ResultRead o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_ReadClaim ->
      let (s', o) = f_read_claim #io_t #i s in
      let ev = PairingEvent_ClaimRead o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_ReadEnrolledDevice ->
      let (s', o) = f_read_enrolled_device #io_t #i s in
      let ev = PairingEvent_EnrolledDeviceRead o in
      (s', step t.f_driver ev, Some ev)
  | PairingEffect_Complete | PairingEffect_ReturnResult _ | PairingEffect_Fail _
  | PairingEffect_RestoreAndFail _ | PairingEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the
/// extracted loop body.
let turn (#io_t: Type0) {| i: t_PairingIo io_t |} (acc: io_t & t_PairingTransition)
  : (io_t & t_PairingTransition) =
  let (s, t) = acc in
  if pairing_state_is_sound t.f_driver
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_PairingIo io_t |} (n: nat)
  (acc: io_t & t_PairingTransition)
  : Tot (io_t & t_PairingTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_PairingEvent) (evs: list t_PairingEvent) : list t_PairingEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_ev (#io_t: Type0) {| i: t_PairingIo io_t |} (n: nat) (s: io_t)
  (t: t_PairingTransition)
  : Pure (io_t & t_PairingTransition & list t_PairingEvent)
    (requires sound_transition t)
    (ensures fun (_, t', _) -> sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = turn_ev #io_t #i s t in
    let (s2, t2, evs) = run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

// ── 1. The extracted loop is `run_ev` ─────────────────────────────────────

/// `fold_range` over a body that is one `turn` per index is `iter_turn`. The
/// two patterns fire together when a goal mentions both the extracted loop and
/// the specification, which binds every variable including the instance.
let rec fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_PairingIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_PairingTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_PairingTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_PairingTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_PairingTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_PairingTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (iter_turn #io_t #i n init)] =
  if v start < v end_
  then fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec iter_turn_is_run_ev (#io_t: Type0) {| i: t_PairingIo io_t |} (n: nat) (s: io_t)
  (t: t_PairingTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (s2, t2, _) = run_ev #io_t #i n s t in
                    iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = turn_ev #io_t #i s t in
    iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

/// The extracted loop calls the executor exactly as `run_ev` does.
let run_pairing_is_run_ev (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  (start: t_PairingTransition)
  : Lemma (requires sound_transition start)
          (ensures (let (s2, t2, _) = run_ev #io_t #i 5 s start in
                    run_pairing #io_t #i s start == (s2, t2))) =
  iter_turn_is_run_ev #io_t #i 5 s start;
  assert (v v_PAIRING_MAX_EFFECTS = 5);
  assert (run_pairing #io_t #i s start == iter_turn #io_t #i 5 (s, start))

// ── 1b. Cancellation: every prefix is a sound driver state ────────────────

/// A dropped handler future stops the pairing loop after an arbitrary prefix
/// of turns. For every executor, every `k` and every sound start, the state
/// after `k` turns is sound: `pairing_state_is_sound` carries the per-request
/// state invariants (an inserted device implies a stored claim, a live opener,
/// a verified signature and matching user/opener bindings; a restored takeover
/// implies a failed, uninserted completion; a record implies an insert), and
/// the next effect agrees with the state that produced it.
let cancellation (#io_t: Type0) {| i: t_PairingIo io_t |} (k: nat) (s: io_t)
  (t: t_PairingTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in sound_transition t2)) =
  let (_, t2, _) = run_ev #io_t #i k s t in
  iter_turn_is_run_ev #io_t #i k s t

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_PairingTransition) (evs: list t_PairingEvent)
  : Pure bool (requires sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (step t.f_driver ev) rest

let rec run_ev_follows_the_driver (#io_t: Type0) {| i: t_PairingIo io_t |} (n: nat) (s: io_t)
  (t: t_PairingTransition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2, evs) = run_ev #io_t #i n s t in
                    trace_sound t.f_driver /\
                    responds t evs /\
                    t2.f_driver == run t.f_driver evs))
          (decreases n) =
  trace_sound_matches_rust t.f_driver;
  if n = 0 then ()
  else begin
    let (s1, t1, o) = turn_ev #io_t #i s t in
    run_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> step_sound t.f_driver ev
  end

// ── 3. A verdict within the budget ────────────────────────────────────────

/// Effects still to perform before a verdict, at most.
let remaining (e: t_PairingEffect) : nat =
  match e with
  | PairingEffect_StorePackage -> 1
  | PairingEffect_RedeemPackage -> 1
  | PairingEffect_StoreGrant -> 1
  | PairingEffect_CheckClaim -> 2
  | PairingEffect_WriteClaim -> 1
  | PairingEffect_CheckAccount -> 5
  | PairingEffect_PrepareCompletion -> 4
  | PairingEffect_TakeCeremony -> 3
  | PairingEffect_InsertDevice -> 2
  | PairingEffect_WriteResult -> 1
  | PairingEffect_ReadResult -> 3
  | PairingEffect_ReadClaim -> 2
  | PairingEffect_ReadEnrolledDevice -> 1
  | PairingEffect_Complete | PairingEffect_ReturnResult _ | PairingEffect_Fail _
  | PairingEffect_RestoreAndFail _ | PairingEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_PairingTransition) (ev: t_PairingEvent)
  : Lemma (requires sound_transition t /\ not (terminal t.f_effect) /\ responds_to t.f_effect ev)
          (ensures remaining (step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect, ev with
  | PairingEffect_StorePackage, PairingEvent_PackageWritten _ -> ()
  | PairingEffect_RedeemPackage, PairingEvent_PackageRedeemed _ -> ()
  | PairingEffect_StoreGrant, PairingEvent_GrantWritten _ -> ()
  | PairingEffect_CheckClaim, PairingEvent_ClaimChecked _ -> ()
  | PairingEffect_WriteClaim, PairingEvent_ClaimWritten _ -> ()
  | PairingEffect_CheckAccount, PairingEvent_AccountChecked _ -> ()
  | PairingEffect_PrepareCompletion, PairingEvent_CompletionReady _ -> ()
  | PairingEffect_TakeCeremony, PairingEvent_CeremonyTaken _ -> ()
  | PairingEffect_InsertDevice, PairingEvent_DeviceInserted _ -> ()
  | PairingEffect_WriteResult, PairingEvent_ResultWritten _ -> ()
  | PairingEffect_ReadResult, PairingEvent_ResultRead _ -> ()
  | PairingEffect_ReadClaim, PairingEvent_ClaimRead _ -> ()
  | PairingEffect_ReadEnrolledDevice, PairingEvent_EnrolledDeviceRead _ -> ()
  | _ -> ()

let rec run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_PairingIo io_t |} (n: nat) (s: io_t)
  (t: t_PairingTransition)
  : Lemma (requires sound_transition t /\ remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = run_ev #io_t #i n s t in terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> step_decreases t ev);
    run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

// ── 4. The handler's final state satisfies the per-request theorems ───────

/// The generic result: for every sound start transition, the loop performs
/// exactly the driver's effects, stops at a verdict, and ends in the state the
/// extracted driver reaches by replaying the observations.
let run_pairing_theorem (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  (start: t_PairingTransition)
  : Lemma (requires sound_transition start)
          (ensures (
            let (_, t) = run_pairing #io_t #i s start in
            exists (evs: list t_PairingEvent).
              responds start evs /\
              t.f_driver == run start.f_driver evs /\
              terminal t.f_effect /\
              trace_sound t.f_driver /\
              pairing_effect_is_sound t.f_driver t.f_effect)) =
  run_pairing_is_run_ev #io_t #i s start;
  run_ev_follows_the_driver #io_t #i 5 s start;
  run_ev_reaches_a_verdict #io_t #i 5 s start;
  let (_, t, evs) = run_ev #io_t #i 5 s start in
  ()

/// Invitation store: whatever the executor returns, the loop stops and the
/// final state is the driver's `run_from_store` over the observations.
let store_interpreter_theorem (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  (observation: t_PackageStoreObservation)
  : Lemma (
      let t0 = begin_store_package observation in
      let (_, t) = run_pairing #io_t #i s t0 in
      exists (evs: list t_PairingEvent).
        responds t0 evs /\
        t.f_driver == run_from_store observation evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_complete t0.f_driver evs <= 1 /\
        count_fail t0.f_driver evs <= 1) =
  let t0 = begin_store_package observation in
  run_pairing_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 5 s t0 in
  run_ev_follows_the_driver #io_t #i 5 s t0;
  run_ev_reaches_a_verdict #io_t #i 5 s t0;
  complete_count_le_one t0.f_driver evs;
  fail_count_le_one t0.f_driver evs;
  assert (run_from_store observation evs == run t0.f_driver evs)

/// Invitation redemption: a missing/replayed token never completes, and at
/// most one destructive read is performed.
let invitation_interpreter_theorem (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  (token: t_PackageTokenObservation)
  : Lemma (
      let t0 = begin_redeem_package token in
      let (_, t) = run_pairing #io_t #i s t0 in
      exists (evs: list t_PairingEvent).
        responds t0 evs /\
        t.f_driver == run_from_redeem token evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_complete t0.f_driver evs <= 1 /\
        count_fail t0.f_driver evs <= 1 /\
        (t.f_driver.f_succeeded ==> not t.f_driver.f_failed)) =
  let t0 = begin_redeem_package token in
  run_pairing_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 5 s t0 in
  run_ev_follows_the_driver #io_t #i 5 s t0;
  run_ev_reaches_a_verdict #io_t #i 5 s t0;
  invitation_trace_theorem token evs

/// Grant opening: the write is authorized at most once and the final state is
/// the driver's `run_from_open` over the observations.
let open_interpreter_theorem (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  (observation: t_OpenObservation)
  : Lemma (
      let t0 = begin_open_grant observation in
      let (_, t) = run_pairing #io_t #i s t0 in
      exists (evs: list t_PairingEvent).
        responds t0 evs /\
        t.f_driver == run_from_open observation evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_complete t0.f_driver evs <= 1 /\
        count_fail t0.f_driver evs <= 1) =
  let t0 = begin_open_grant observation in
  run_pairing_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 5 s t0 in
  run_ev_follows_the_driver #io_t #i 5 s t0;
  run_ev_reaches_a_verdict #io_t #i 5 s t0;
  complete_count_le_one t0.f_driver evs;
  fail_count_le_one t0.f_driver evs;
  assert (run_from_open observation evs == run t0.f_driver evs)

/// Claim: at most one guarded claim write is authorized, and such an
/// authorization implies the verified claim policy accepted a live, unclaimed
/// grant with exact public-key lengths.
let claim_interpreter_theorem (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  (grant_live: bool)
  : Lemma (
      let t0 = begin_claim grant_live in
      let (_, t) = run_pairing #io_t #i s t0 in
      exists (evs: list t_PairingEvent).
        responds t0 evs /\
        t.f_driver == run_from_claim grant_live evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_write_claim t0.f_driver evs <= 1 /\
        count_complete t0.f_driver evs <= 1 /\
        count_fail t0.f_driver evs <= 1 /\
        (t.f_driver.f_succeeded ==> not t.f_driver.f_failed)) =
  let t0 = begin_claim grant_live in
  run_pairing_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 5 s t0 in
  run_ev_follows_the_driver #io_t #i 5 s t0;
  run_ev_reaches_a_verdict #io_t #i 5 s t0;
  claim_trace_theorem grant_live evs

/// Completion: at most one take and one guarded insert are authorized, a
/// finished success implies both the insert and the result record, and an
/// inserted row is behind a stored claim, an active opener, a verified
/// signature and matching user/opener bindings.
let completion_interpreter_theorem (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  (grant: t_GrantObservation)
  : Lemma (
      let t0 = begin_completion grant in
      let (_, t) = run_pairing #io_t #i s t0 in
      exists (evs: list t_PairingEvent).
        responds t0 evs /\
        t.f_driver == run_from_completion grant evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_take t0.f_driver evs <= 1 /\
        count_insert t0.f_driver evs <= 1 /\
        count_complete t0.f_driver evs <= 1 /\
        count_fail t0.f_driver evs <= 1 /\
        (t.f_driver.f_inserted ==>
          (t.f_driver.f_grant_present && t.f_driver.f_claim_present /\
           t.f_driver.f_opener_active && t.f_driver.f_signature_verified /\
           t.f_driver.f_user_matches && t.f_driver.f_opener_matches)) /\
        (t.f_driver.f_restored ==> (t.f_driver.f_failed && not t.f_driver.f_inserted)) /\
        (t.f_driver.f_succeeded ==> not t.f_driver.f_failed)) =
  let t0 = begin_completion grant in
  run_pairing_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 5 s t0 in
  run_ev_follows_the_driver #io_t #i 5 s t0;
  run_ev_reaches_a_verdict #io_t #i 5 s t0;
  completion_trace_theorem grant evs

/// Result collection: an enrolled answer implies the verified result policy
/// accepted a stored claimed key and a proof under it; a refused or absent
/// record never returns an enrolled device.
let result_interpreter_theorem (#io_t: Type0) {| i: t_PairingIo io_t |} (s: io_t)
  : Lemma (
      let t0 = begin_result () in
      let (_, t) = run_pairing #io_t #i s t0 in
      exists (evs: list t_PairingEvent).
        responds t0 evs /\
        t.f_driver == run_from_result evs /\
        terminal t.f_effect /\
        trace_sound t.f_driver /\
        count_complete t0.f_driver evs <= 1 /\
        count_fail t0.f_driver evs <= 1 /\
        (t.f_driver.f_succeeded ==> not t.f_driver.f_failed)) =
  let t0 = begin_result () in
  run_pairing_is_run_ev #io_t #i s t0;
  let (_, t, evs) = run_ev #io_t #i 5 s t0 in
  run_ev_follows_the_driver #io_t #i 5 s t0;
  run_ev_reaches_a_verdict #io_t #i 5 s t0;
  result_trace_theorem evs
