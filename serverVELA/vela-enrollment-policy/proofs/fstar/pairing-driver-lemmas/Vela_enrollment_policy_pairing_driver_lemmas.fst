module Vela_enrollment_policy_pairing_driver_lemmas

/// Hand-written, unbounded trace induction over the *extracted* device-pairing
/// transition relation (`Vela_enrollment_policy.Pairing_driver`).
///
/// Scope: one `PairingDriver` value, i.e. one HTTP request of one ceremony:
/// invitation store, invitation redemption, grant open, claim, completion or
/// result collection. The theorem does not claim anything about two concurrent
/// requests (the companion composition module does, over a modelled store);
/// sled, SQL, signature verification, clocks and response rendering remain
/// effectful glue outside this module. The driver's store/SQL inputs are
/// observations, never verified origins.
///
/// No proof escape or solver laxity is used. The invariant below is restated
/// independently of `pairing_state_is_sound` and proved equivalent to it; all
/// trace lemmas then quantify over every event list.
///
/// The headline facts are stated over counters threaded through the trace, not
/// read off the SQL/store guard: `trace_take_count` counts `TakeCeremony`
/// effects, `trace_insert_count` counts `InsertDevice` effects and
/// `trace_write_claim_count` counts `WriteClaim` effects. Each is driven solely
/// by the extracted driver's emitted effect.

open FStar.Mul
open Core_models
open Vela_enrollment_policy
open Vela_enrollment_policy.Pairing_driver

// ── Independent state invariant ─────────────────────────────────────────────

let is_start (d: t_PairingDriver) : bool =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start -> true
  | _ -> false

let is_applied (d: t_PairingDriver) : bool =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Applied -> true
  | _ -> false

let is_inflight (d: t_PairingDriver) : bool =
  match d.f_stage <: t_PairingStage with
  | PairingStage_InFlight -> true
  | _ -> false

let is_wrote_result (d: t_PairingDriver) : bool =
  match d.f_stage <: t_PairingStage with
  | PairingStage_WroteResult -> true
  | _ -> false

let is_result_claim (d: t_PairingDriver) : bool =
  match d.f_stage <: t_PairingStage with
  | PairingStage_ResultClaim -> true
  | _ -> false

let is_done (d: t_PairingDriver) : bool =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Done -> true
  | _ -> false

let is_claim (d: t_PairingDriver) : bool =
  match d.f_ceremony <: t_PairingCeremony with
  | PairingCeremony_ClaimGrant -> true
  | _ -> false

let is_complete (d: t_PairingDriver) : bool =
  match d.f_ceremony <: t_PairingCeremony with
  | PairingCeremony_CompleteGrant -> true
  | _ -> false

let is_collect (d: t_PairingDriver) : bool =
  match d.f_ceremony <: t_PairingCeremony with
  | PairingCeremony_CollectResult -> true
  | _ -> false

let is_single_shot (d: t_PairingDriver) : bool =
  not (is_complete d) && not (is_collect d)

/// Strengthened trace invariant: the stage/flag discipline of the driver plus
/// the provenance of every completion milestone.
let trace_sound (d: t_PairingDriver) : bool =
  let start_clean =
    not d.f_consumed && not d.f_inserted && not d.f_recorded && not d.f_restored &&
    not d.f_succeeded && not d.f_failed
  in
  let applied_clean =
    d.f_authorized && d.f_wrote && not d.f_consumed && not d.f_inserted &&
    not d.f_recorded && not d.f_restored && not d.f_succeeded && not d.f_failed
  in
  let inflight_clean =
    d.f_authorized && d.f_wrote && d.f_consumed && not d.f_inserted &&
    not d.f_recorded && not d.f_restored && not d.f_succeeded && not d.f_failed
  in
  let wrote_result_clean =
    d.f_authorized && d.f_wrote && d.f_consumed && d.f_inserted &&
    not d.f_recorded && not d.f_restored && not d.f_succeeded && not d.f_failed
  in
  let result_claim_clean =
    d.f_authorized && not d.f_wrote && not d.f_consumed && not d.f_inserted &&
    not d.f_recorded && not d.f_restored && not d.f_succeeded && not d.f_failed
  in
  let done_clean =
    (d.f_succeeded || d.f_failed) && not (d.f_succeeded && d.f_failed) &&
    (not d.f_succeeded || (d.f_authorized && not d.f_restored)) &&
    (not d.f_succeeded || not (is_complete d) ||
      (d.f_consumed && d.f_inserted && d.f_recorded)) &&
    (not d.f_succeeded || is_complete d || is_collect d || d.f_wrote) &&
    (not d.f_restored || (d.f_failed && is_complete d && not d.f_inserted))
  in
  (not (is_start d) || start_clean) &&
  (not (is_applied d) || applied_clean) &&
  (not (is_inflight d) || inflight_clean) &&
  (not (is_wrote_result d) || wrote_result_clean) &&
  (not (is_result_claim d) || result_claim_clean) &&
  (not (is_done d) || done_clean) &&
  (not (is_inflight d || is_wrote_result d) || is_complete d) &&
  (not (is_result_claim d) || is_collect d) &&
  (not (is_applied d) || is_claim d || is_complete d) &&
  (not d.f_consumed || (d.f_wrote && is_complete d)) &&
  (not d.f_inserted || d.f_consumed) &&
  (not d.f_recorded || d.f_inserted) &&
  (not d.f_recorded || is_done d) &&
  (not d.f_wrote || not (is_collect d)) &&
  (not d.f_grant_present || is_complete d) &&
  (not d.f_user_matches || d.f_grant_present) &&
  (not d.f_opener_matches || d.f_grant_present) &&
  (not d.f_claim_present || is_complete d) &&
  (not d.f_opener_active || is_complete d) &&
  (not d.f_signature_verified || is_complete d) &&
  (not d.f_inserted ||
    (d.f_grant_present && d.f_claim_present && d.f_opener_active &&
     d.f_signature_verified && d.f_user_matches && d.f_opener_matches)) &&
  (not (is_applied d) || not (is_complete d) ||
    (d.f_grant_present && d.f_claim_present && d.f_opener_active &&
     d.f_signature_verified && d.f_user_matches && d.f_opener_matches)) &&
  (not (is_inflight d) || (d.f_grant_present && d.f_claim_present && d.f_opener_active &&
                           d.f_signature_verified && d.f_user_matches && d.f_opener_matches)) &&
  (not (is_wrote_result d) || (d.f_grant_present && d.f_claim_present && d.f_opener_active &&
                               d.f_signature_verified && d.f_user_matches && d.f_opener_matches)) &&
  (not (is_start d) || d.f_authorized)

/// The independently written invariant is exactly the Rust postcondition's
/// predicate. Proved by exhaustive stage case analysis, not by aliasing the
/// implementation definition in the statements below.
let trace_sound_matches_rust (d: t_PairingDriver)
  : Lemma (trace_sound d = pairing_state_is_sound d) =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start -> ()
  | PairingStage_Applied -> ()
  | PairingStage_InFlight -> ()
  | PairingStage_WroteResult -> ()
  | PairingStage_ResultClaim -> ()
  | PairingStage_Done -> ()

// ── The driver transition relation ──────────────────────────────────────────

let begin_store_sound (observation: t_PackageStoreObservation)
  : Lemma (trace_sound (begin_store_package observation).f_driver) =
  trace_sound_matches_rust (begin_store_package observation).f_driver

let begin_redeem_sound (observation: t_PackageTokenObservation)
  : Lemma (trace_sound (begin_redeem_package observation).f_driver) =
  trace_sound_matches_rust (begin_redeem_package observation).f_driver

let begin_open_sound (observation: t_OpenObservation)
  : Lemma (trace_sound (begin_open_grant observation).f_driver) =
  trace_sound_matches_rust (begin_open_grant observation).f_driver

let begin_claim_sound (grant_live: bool)
  : Lemma (trace_sound (begin_claim grant_live).f_driver) =
  trace_sound_matches_rust (begin_claim grant_live).f_driver

let begin_completion_sound (grant: t_GrantObservation)
  : Lemma (trace_sound (begin_completion grant).f_driver) =
  trace_sound_matches_rust (begin_completion grant).f_driver

let begin_result_sound ()
  : Lemma (trace_sound (begin_result ()).f_driver) =
  trace_sound_matches_rust (begin_result ()).f_driver

/// Every extracted step preserves the independent invariant.
let step_sound (d: t_PairingDriver) (e: t_PairingEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (trace_sound (step d e).f_driver)) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

/// A finished driver is inert for every event.
let step_after_done (d: t_PairingDriver) (e: t_PairingEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      (step d e).f_driver = d /\
      (step d e).f_effect = PairingEffect_Idle)) =
  trace_sound_matches_rust d;
  match e <: t_PairingEvent with
  | PairingEvent_PackageWritten _ -> ()
  | PairingEvent_PackageRedeemed _ -> ()
  | PairingEvent_GrantWritten _ -> ()
  | PairingEvent_ClaimChecked _ -> ()
  | PairingEvent_ClaimWritten _ -> ()
  | PairingEvent_CompletionReady _ -> ()
  | PairingEvent_CeremonyTaken _ -> ()
  | PairingEvent_DeviceInserted _ -> ()
  | PairingEvent_ResultWritten _ -> ()
  | PairingEvent_ResultRead _ -> ()
  | PairingEvent_ClaimRead _ -> ()

// ── Unbounded trace execution ───────────────────────────────────────────────

let rec run (d: t_PairingDriver) (events: list t_PairingEvent)
  : Pure t_PairingDriver
    (requires (trace_sound d))
    (ensures (fun result -> trace_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      run (step d e).f_driver rest

let rec last_effect (d: t_PairingDriver) (events: list t_PairingEvent)
  : Pure t_PairingEffect
    (requires (trace_sound d))
    (ensures (fun _ -> True))
    (decreases events) =
  match events with
  | [] -> PairingEffect_Idle
  | e :: [] -> (step d e).f_effect
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      last_effect (step d e).f_driver rest

/// Total wrappers starting from the actual extracted begin functions.
let run_from_store (o: t_PackageStoreObservation) (events: list t_PairingEvent)
  : Pure t_PairingDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_store_sound o;
  run (begin_store_package o).f_driver events

let run_from_redeem (o: t_PackageTokenObservation) (events: list t_PairingEvent)
  : Pure t_PairingDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_redeem_sound o;
  run (begin_redeem_package o).f_driver events

let run_from_open (o: t_OpenObservation) (events: list t_PairingEvent)
  : Pure t_PairingDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_open_sound o;
  run (begin_open_grant o).f_driver events

let run_from_claim (grant_live: bool) (events: list t_PairingEvent)
  : Pure t_PairingDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_claim_sound grant_live;
  run (begin_claim grant_live).f_driver events

let run_from_completion (grant: t_GrantObservation) (events: list t_PairingEvent)
  : Pure t_PairingDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_completion_sound grant;
  run (begin_completion grant).f_driver events

let run_from_result (events: list t_PairingEvent)
  : Pure t_PairingDriver (requires True) (ensures (fun r -> trace_sound r))
    (decreases events) =
  begin_result_sound ();
  run (begin_result ()).f_driver events

// ── Effect provenance ──────────────────────────────────────────────────────

/// A `TakeCeremony` effect is only emitted from a state that passed the
/// verified completion policy. The policy object is the same one the handler
/// calls; the driver does not restate it.
let take_requires_completion_policy
      (d: t_PairingDriver)
      (observation: t_CompletionPreflightObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_CompletionReady observation)).f_effect
        = PairingEffect_TakeCeremony ==>
      completion_is_authorized
        (completion_facts
          ({ f_claim_present =
               (match observation.f_claim <: t_ClaimMaterialObservation with
                | ClaimMaterialObservation_Missing -> false
                | _ -> true);
             f_user_matches = d.f_user_matches;
             f_opener_matches = d.f_opener_matches;
             f_opener_active =
               (match observation.f_opener <: t_OpenerObservation with
                | OpenerObservation_Active -> true
                | _ -> false);
             f_signature_verified =
               (match observation.f_signature <: t_SignatureObservation with
                | SignatureObservation_Verified -> true
                | _ -> false);
             f_claim_key_source = ClaimKeySource_StoredClaim;
             f_account_epoch = observation.f_account_epoch;
             f_declared_epoch = observation.f_declared_epoch;
             f_rotation_in_progress = observation.f_rotation_in_progress })))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// Consequently an authorized take implies a stored claim, an active opener,
/// a verified signature and matching account/opener bindings.
let take_implies_completion_facts
      (d: t_PairingDriver)
      (observation: t_CompletionPreflightObservation)
  : Lemma
    (requires (trace_sound d /\
      (step d (PairingEvent_CompletionReady observation)).f_effect
        = PairingEffect_TakeCeremony))
    (ensures (
      (match observation.f_claim <: t_ClaimMaterialObservation with
       | ClaimMaterialObservation_Missing -> False
       | _ -> True) /\
      (match observation.f_opener <: t_OpenerObservation with
       | OpenerObservation_Active -> True
       | _ -> False) /\
      (match observation.f_signature <: t_SignatureObservation with
       | SignatureObservation_Verified -> True
       | _ -> False) /\
      d.f_user_matches /\
      d.f_opener_matches /\
      observation.f_declared_epoch >=. mk_i64 1 /\
      observation.f_account_epoch =. observation.f_declared_epoch /\
      not observation.f_rotation_in_progress)) =
  take_requires_completion_policy d observation

/// A `WriteClaim` effect is only emitted when the verified claim policy
/// authorized the write over the real grant/claim/length observations.
let write_claim_requires_claim_policy
      (d: t_PairingDriver)
      (observation: t_ClaimObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_ClaimChecked observation)).f_effect
        = PairingEffect_WriteClaim ==>
      claim_is_authorized (claim_facts observation))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// An authorized claim write therefore observed a live grant *and* the absence
/// of a previous claim.
let write_claim_implies_live_and_unclaimed
      (d: t_PairingDriver)
      (observation: t_ClaimObservation)
  : Lemma
    (requires (trace_sound d /\
      (step d (PairingEvent_ClaimChecked observation)).f_effect
        = PairingEffect_WriteClaim))
    (ensures (observation.f_grant_live = true /\ observation.f_claim_exists = false)) =
  write_claim_requires_claim_policy d observation

/// An `InsertDevice` effect requires a *taken* ceremony whose two compared
/// byte strings both matched the validated snapshot.
let insert_requires_matched_take
      (d: t_PairingDriver)
      (observation: t_TakeObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_CeremonyTaken observation)).f_effect
        = PairingEffect_InsertDevice ==>
      (match observation <: t_TakeObservation with
       | TakeObservation_Taken t -> t.f_grant_matches && t.f_claim_matches
       | _ -> False))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// A successful redemption only ever follows a present package.
let redeem_complete_requires_present
      (d: t_PairingDriver)
      (observation: t_RedeemObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_PackageRedeemed observation)).f_effect
        = PairingEffect_Complete ==>
      (match observation <: t_RedeemObservation with
       | RedeemObservation_Present t -> t.f_utf8_valid
       | RedeemObservation_Missing -> False))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// A refused or replayed token can never complete a redemption. This is the
/// negative half of the single-use invitation property, over the driver alone.
let missing_redeem_never_completes
      (d: t_PairingDriver)
  : Lemma
    (requires (trace_sound d))
    (ensures ((step d (PairingEvent_PackageRedeemed RedeemObservation_Missing)).f_effect
      <> PairingEffect_Complete)) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// A store completion only ever follows a reported success.
let store_complete_requires_stored
      (d: t_PairingDriver) (observation: t_StoreObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_PackageWritten observation)).f_effect
        = PairingEffect_Complete ==>
      (match observation <: t_StoreObservation with
       | StoreObservation_Stored -> True
       | StoreObservation_Failed -> False))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// A claim completion only ever follows an inserted guarded write.
let claim_complete_requires_inserted
      (d: t_PairingDriver) (observation: t_ClaimWriteObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_ClaimWritten observation)).f_effect
        = PairingEffect_Complete ==>
      (match observation <: t_ClaimWriteObservation with
       | ClaimWriteObservation_Inserted -> True
       | _ -> False))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// A result collector may only answer with an `Enrolled` kind after the
/// verified result policy accepted a claimed key and a proof under it.
let result_return_requires_proof
      (d: t_PairingDriver) (observation: t_ResultReadObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_ResultRead observation)).f_effect
        = PairingEffect_ReturnResult ResultKind_Enrolled ==>
      (match observation <: t_ResultReadObservation with
       | ResultReadObservation_Completed c ->
           c.f_claimed_key_len >. mk_usize 0 /\ c.f_signature_verified
       | _ -> False))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// The same for a `Pending` answer: a live claim record and a proof under its
/// stored key.
let claim_return_requires_proof
      (d: t_PairingDriver) (observation: t_ClaimReadObservation)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d (PairingEvent_ClaimRead observation)).f_effect
        = PairingEffect_ReturnResult ResultKind_Pending ==>
      (match observation <: t_ClaimReadObservation with
       | ClaimReadObservation_Claimed c ->
           c.f_claimed_key_len >. mk_usize 0 /\ c.f_signature_verified
       | _ -> False))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  ()

/// A terminal success of a completion implies the insert *and* the result
/// record, so a client that saw "enrolled" cannot have seen a half ceremony.
let complete_success_implies_insert_and_record
      (d: t_PairingDriver) (e: t_PairingEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      (step d e).f_effect = PairingEffect_Complete ==>
      (is_complete d ==>
       ((step d e).f_driver.f_consumed /\
        (step d e).f_driver.f_inserted /\
        (step d e).f_driver.f_recorded)))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  trace_sound_matches_rust (step d e).f_driver

// ── Counter lemmas: one authorizing effect per request ─────────────────────

let b2n (b: bool) : nat = if b then 1 else 0

let rec count_take (d: t_PairingDriver) (events: list t_PairingEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n ((step d e).f_effect = PairingEffect_TakeCeremony) +
      count_take (step d e).f_driver rest

let rec count_insert (d: t_PairingDriver) (events: list t_PairingEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n ((step d e).f_effect = PairingEffect_InsertDevice) +
      count_insert (step d e).f_driver rest

let rec count_write_claim (d: t_PairingDriver) (events: list t_PairingEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n ((step d e).f_effect = PairingEffect_WriteClaim) +
      count_write_claim (step d e).f_driver rest

let rec count_complete (d: t_PairingDriver) (events: list t_PairingEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n ((step d e).f_effect = PairingEffect_Complete ||
           (match (step d e).f_effect <: t_PairingEffect with
            | PairingEffect_ReturnResult _ -> true
            | _ -> false)) +
      count_complete (step d e).f_driver rest

let rec count_fail (d: t_PairingDriver) (events: list t_PairingEvent)
  : Pure nat (requires (trace_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      b2n ((match (step d e).f_effect <: t_PairingEffect with
            | PairingEffect_Fail _ -> true
            | PairingEffect_RestoreAndFail _ -> true
            | _ -> false)) +
      count_fail (step d e).f_driver rest

let rec done_suffix_inert (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma
    (requires (trace_sound d /\ is_done d))
    (ensures (
      run d events = d /\
      count_take d events = 0 /\
      count_insert d events = 0 /\
      count_write_claim d events = 0 /\
      count_complete d events = 0 /\
      count_fail d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      step_after_done d e;
      done_suffix_inert d rest

/// A driver that has left `Start` never returns to it: no transition assigns
/// `Start`, and every transition either advances or leaves the stage alone.
let step_keeps_not_start (d: t_PairingDriver) (e: t_PairingEvent)
  : Lemma
    (requires (trace_sound d /\ not (is_start d)))
    (ensures (not (is_start (step d e).f_driver))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  match e <: t_PairingEvent with
  | PairingEvent_PackageWritten _ -> ()
  | PairingEvent_PackageRedeemed _ -> ()
  | PairingEvent_GrantWritten _ -> ()
  | PairingEvent_ClaimChecked _ -> ()
  | PairingEvent_ClaimWritten _ -> ()
  | PairingEvent_CompletionReady _ -> ()
  | PairingEvent_CeremonyTaken _ -> ()
  | PairingEvent_DeviceInserted _ -> ()
  | PairingEvent_ResultWritten _ -> ()
  | PairingEvent_ResultRead _ -> ()
  | PairingEvent_ClaimRead _ -> ()

/// After the take, the driver is `Applied`; when it is at least that far along
/// it stays there. This is the structural reason a second destructive effect
/// is impossible.
let step_keeps_not_start_not_applied (d: t_PairingDriver) (e: t_PairingEvent)
  : Lemma
    (requires (trace_sound d /\ not (is_start d) /\ not (is_applied d)))
    (ensures (not (is_start (step d e).f_driver) /\
              not (is_applied (step d e).f_driver))) =
  trace_sound_matches_rust d;
  assert (pairing_state_is_sound d = true);
  match e <: t_PairingEvent with
  | PairingEvent_PackageWritten _ -> ()
  | PairingEvent_PackageRedeemed _ -> ()
  | PairingEvent_GrantWritten _ -> ()
  | PairingEvent_ClaimChecked _ -> ()
  | PairingEvent_ClaimWritten _ -> ()
  | PairingEvent_CompletionReady _ -> ()
  | PairingEvent_CeremonyTaken _ -> ()
  | PairingEvent_DeviceInserted _ -> ()
  | PairingEvent_ResultWritten _ -> ()
  | PairingEvent_ResultRead _ -> ()
  | PairingEvent_ClaimRead _ -> ()

/// `TakeCeremony` and `WriteClaim` are only ever emitted from `Start`, so a
/// trace whose first event already left `Start` contains none.
let rec no_start_no_authorization (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma
    (requires (trace_sound d /\ not (is_start d)))
    (ensures (count_take d events = 0 /\ count_write_claim d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      step_keeps_not_start d e;
      no_start_no_authorization (step d e).f_driver rest

/// `InsertDevice` is only emitted from `Applied`.
let rec no_insert_past_take (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma
    (requires (trace_sound d /\ not (is_start d) /\ not (is_applied d)))
    (ensures (count_insert d events = 0))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      step_keeps_not_start_not_applied d e;
      no_insert_past_take (step d e).f_driver rest

/// `TakeCeremony` is emitted at most once: it moves the driver to `Applied`,
/// and only a fresh `CompletionReady` from `Start` could emit it again.
let rec take_count_le_one (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_take d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if t.f_effect = PairingEffect_TakeCeremony
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_stage = (PairingStage_Applied <: t_PairingStage));
        no_start_no_authorization t.f_driver rest
      end else take_count_le_one t.f_driver rest

/// `InsertDevice` is emitted at most once: it moves the driver to `InFlight`
/// and only a `CeremonyTaken` from `Applied` could emit it again.
let rec insert_count_le_one (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_insert d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if t.f_effect = PairingEffect_InsertDevice
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_stage = (PairingStage_InFlight <: t_PairingStage));
        no_insert_past_take t.f_driver rest
      end else insert_count_le_one t.f_driver rest

/// `WriteClaim` is emitted at most once per claim request.
let rec write_claim_count_le_one (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_write_claim d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if t.f_effect = PairingEffect_WriteClaim
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (t.f_driver.f_stage = (PairingStage_Applied <: t_PairingStage));
        no_start_no_authorization t.f_driver rest
      end else write_claim_count_le_one t.f_driver rest

/// A terminal success happens at most once.
let rec complete_count_le_one (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_complete d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if count_complete d [e] = 1
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (is_done t.f_driver);
        done_suffix_inert t.f_driver rest
      end else complete_count_le_one t.f_driver rest

/// A terminal failure happens at most once.
let rec fail_count_le_one (d: t_PairingDriver) (events: list t_PairingEvent)
  : Lemma (requires (trace_sound d)) (ensures (count_fail d events <= 1))
    (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      trace_sound_matches_rust d;
      step_sound d e;
      let t = step d e in
      if count_fail d [e] = 1
      then begin
        trace_sound_matches_rust t.f_driver;
        assert (is_done t.f_driver);
        done_suffix_inert t.f_driver rest
      end else fail_count_le_one t.f_driver rest

// ── Headline per-request theorems ──────────────────────────────────────────

/// Invitation: whatever the event list, a redemption request performs no
/// destructive effect after the first, and a completion implies the driver saw
/// a present, UTF-8 package. A missing/replayed token never completes.
let invitation_trace_theorem
      (token: t_PackageTokenObservation)
      (events: list t_PairingEvent)
  : Lemma (
      let d = run_from_redeem token events in
      trace_sound d /\
      count_complete (begin_redeem_package token).f_driver events <= 1 /\
      count_fail (begin_redeem_package token).f_driver events <= 1 /\
      (d.f_succeeded ==> not d.f_failed)) =
  begin_redeem_sound token;
  complete_count_le_one (begin_redeem_package token).f_driver events;
  fail_count_le_one (begin_redeem_package token).f_driver events;
  ()

/// Claim: at most one guarded claim write is authorized, and such an
/// authorization implies the verified claim policy accepted a live, unclaimed
/// grant with exact public-key lengths.
let claim_trace_theorem
      (grant_live: bool)
      (events: list t_PairingEvent)
  : Lemma (
      let d = run_from_claim grant_live events in
      trace_sound d /\
      count_write_claim (begin_claim grant_live).f_driver events <= 1 /\
      count_complete (begin_claim grant_live).f_driver events <= 1 /\
      count_fail (begin_claim grant_live).f_driver events <= 1 /\
      (d.f_succeeded ==> not d.f_failed)) =
  begin_claim_sound grant_live;
  write_claim_count_le_one (begin_claim grant_live).f_driver events;
  complete_count_le_one (begin_claim grant_live).f_driver events;
  fail_count_le_one (begin_claim grant_live).f_driver events;
  ()

/// Completion: whatever the event list, at most one take and one guarded insert
/// are authorized, a finished success implies both the insert and the result
/// record, and an inserted row is behind a stored claim, an active opener, a
/// verified signature and matching user/opener bindings.
let completion_trace_theorem
      (grant: t_GrantObservation)
      (events: list t_PairingEvent)
  : Lemma (
      let d = run_from_completion grant events in
      trace_sound d /\
      count_take (begin_completion grant).f_driver events <= 1 /\
      count_insert (begin_completion grant).f_driver events <= 1 /\
      count_complete (begin_completion grant).f_driver events <= 1 /\
      count_fail (begin_completion grant).f_driver events <= 1 /\
      (d.f_inserted ==>
        (d.f_grant_present && d.f_claim_present && d.f_opener_active /\
         d.f_signature_verified && d.f_user_matches && d.f_opener_matches)) /\
      (d.f_restored ==> (d.f_failed && not d.f_inserted)) /\
      (d.f_succeeded ==> not d.f_failed)) =
  begin_completion_sound grant;
  take_count_le_one (begin_completion grant).f_driver events;
  insert_count_le_one (begin_completion grant).f_driver events;
  complete_count_le_one (begin_completion grant).f_driver events;
  fail_count_le_one (begin_completion grant).f_driver events;
  ()

/// Result collection: a successful answer implies the verified result policy
/// accepted a stored claimed key and a proof under it; a refused or absent
/// record never returns an enrolled device.
let result_trace_theorem (events: list t_PairingEvent)
  : Lemma (
      let d = run_from_result events in
      trace_sound d /\
      count_complete (begin_result ()).f_driver events <= 1 /\
      count_fail (begin_result ()).f_driver events <= 1 /\
      (d.f_succeeded ==> not d.f_failed)) =
  begin_result_sound ();
  complete_count_le_one (begin_result ()).f_driver events;
  fail_count_le_one (begin_result ()).f_driver events;
  ()

// ── Reachability witnesses ─────────────────────────────────────────────────

let valid_store : t_PackageStoreObservation =
  { f_token_valid = true; f_ciphertext_len_valid = true }

let valid_token : t_PackageTokenObservation = { f_token_valid = true }

let invalid_token : t_PackageTokenObservation = { f_token_valid = false }

let bound_grant : t_GrantObservation =
  GrantObservation_Present
    ({ f_user_matches = true; f_opener_matches = true })

let foreign_grant : t_GrantObservation =
  GrantObservation_Present
    ({ f_user_matches = false; f_opener_matches = true })

let good_preflight : t_CompletionPreflightObservation =
  { f_claim = ClaimMaterialObservation_Usable;
    f_capsule_valid = true;
    f_signature_field_valid = true;
    f_opener = OpenerObservation_Active;
    f_signature = SignatureObservation_Verified;
    f_account_epoch = mk_i64 3;
    f_declared_epoch = mk_i64 3;
    f_rotation_in_progress = false;
    f_account_epoch_active = true }

let success_events : list t_PairingEvent =
  [ PairingEvent_CompletionReady good_preflight;
    PairingEvent_CeremonyTaken
      (TakeObservation_Taken { f_grant_matches = true; f_claim_matches = true });
    PairingEvent_DeviceInserted DeviceInsertObservation_Inserted;
    PairingEvent_ResultWritten StoreObservation_Stored ]

/// A complete ceremony is reachable and ends enrolled.
let completion_success_is_reachable ()
  : Lemma (
      let d = run_from_completion bound_grant success_events in
      d.f_succeeded = true /\ d.f_inserted = true /\ d.f_recorded = true /\
      d.f_consumed = true /\ d.f_claim_present = true /\
      d.f_signature_verified = true /\
      last_effect (begin_completion bound_grant).f_driver success_events
        = PairingEffect_Complete) =
  ()

/// A foreign account cannot drive a completion at all.
let foreign_account_is_refused ()
  : Lemma (
      let d = run_from_completion foreign_grant success_events in
      d.f_failed = true /\ d.f_inserted = false /\
      (begin_completion foreign_grant).f_effect
        = PairingEffect_Fail PairingFailure_GrantUnavailable) =
  ()

/// A take that did not match restores the pair and never inserts.
let mismatched_take_restores ()
  : Lemma (
      let events =
        [ PairingEvent_CompletionReady good_preflight;
          PairingEvent_CeremonyTaken
            (TakeObservation_Taken
              { f_grant_matches = true; f_claim_matches = false }) ] in
      let d = run_from_completion bound_grant events in
      d.f_failed = true /\ d.f_restored = true /\ d.f_inserted = false) =
  ()

/// A replayed take observes nothing and never inserts.
let replayed_take_is_refused ()
  : Lemma (
      let events =
        [ PairingEvent_CompletionReady good_preflight;
          PairingEvent_CeremonyTaken TakeObservation_Missing ] in
      let d = run_from_completion bound_grant events in
      d.f_failed = true /\ d.f_inserted = false /\
      last_effect (begin_completion bound_grant).f_driver events
        = PairingEffect_Fail PairingFailure_CeremonyConsumed) =
  ()

/// A successful package store is reachable; a failed one is terminal.
let store_success_is_reachable ()
  : Lemma (
      (run_from_store valid_store [PairingEvent_PackageWritten StoreObservation_Stored]).f_succeeded
        = true /\
      (run_from_store valid_store [PairingEvent_PackageWritten StoreObservation_Failed]).f_failed
        = true) =
  ()

/// An invalid token never reaches the store effect.
let invalid_token_is_refused ()
  : Lemma (
      let d = run_from_redeem invalid_token
        [ PairingEvent_PackageRedeemed RedeemObservation_Missing ] in
      d.f_failed = true /\ not d.f_succeeded /\
      (begin_redeem_package invalid_token).f_effect
        = PairingEffect_Fail PairingFailure_InvalidToken) =
  ()

/// A claim write is reachable only on a live, unclaimed grant.
let claim_write_is_reachable ()
  : Lemma (
      let observation: t_ClaimObservation =
        ({ f_grant_live = true; f_claim_exists = false;
           f_hybrid_ek_len = v_HYBRID_EK_LEN;
           f_hybrid_vk_len = v_HYBRID_VK_LEN }) in
      let d = run_from_claim true
        [ PairingEvent_ClaimChecked observation;
          PairingEvent_ClaimWritten ClaimWriteObservation_Inserted ] in
      d.f_succeeded = true /\ d.f_wrote = true) =
  ()

/// An existing claim is refused with the historical conflict, without a write.
let existing_claim_is_refused ()
  : Lemma (
      let observation: t_ClaimObservation =
        ({ f_grant_live = true; f_claim_exists = true;
           f_hybrid_ek_len = v_HYBRID_EK_LEN;
           f_hybrid_vk_len = v_HYBRID_VK_LEN }) in
      let d = run_from_claim true [ PairingEvent_ClaimChecked observation ] in
      d.f_failed = true /\ not d.f_wrote) =
  ()
