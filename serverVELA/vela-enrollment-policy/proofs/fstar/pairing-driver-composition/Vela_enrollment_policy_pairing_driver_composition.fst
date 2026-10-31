module Vela_enrollment_policy_pairing_driver_composition

/// Concurrent composition of the *extracted* device-pairing transition
/// relation (`Vela_enrollment_policy.Pairing_driver`).
///
/// One invitation package and one enrollment grant are shared by any number of
/// requests. A schedule is an arbitrary list of actions: store or redeem the
/// package, spawn a claim or a completion, deliver the account/preflight/take/
/// insert/result observations of a completion, collect a result, and so on.
///
/// The world abstracts the effects the handler performs:
///
/// - the invitation package is one destructive cell; a store creates a new
///   version and resets that version's redemption count, and a redemption
///   consumes the live version and derives its observation from the cell;
/// - the unauthenticated claim is one atomic read-decide-write step, which is
///   what `set_ex_nx_if_live` gives the handler;
/// - the completion's account query, verified preflight, `take_live_pair`,
///   guarded `INSERT` and result write are separate steps; each observation is
///   derived from the world, never chosen by the schedule;
/// - the grant/claim snapshot is consumed exactly when the extracted driver
///   emits `InsertDevice`; the device row is created exactly then.
///
/// Theorem: for every schedule,
///
/// - the driver authorizes at most one claim write (`w_claim_authorizations`,
///   `w_claim_records`);
/// - the driver authorizes at most one destructive take and one insert
///   (`w_take`, `w_enrollments`, `g_enrolled`);
/// - the driver never authorizes an insert on a grant that was already
///   enrolled (`w_enroll_after_enrolled`);
/// - the driver never authorizes an insert for an account other than the
///   grant's owner (`w_enroll_cross_account`);
/// - the driver never authorizes an insert without the opener's verified
///   signature (`w_enroll_without_signature`);
/// - the driver never authorizes a take without a live stored claim
///   (`w_take_without_claim`);
/// - the driver never completes a second redemption of one stored package
///   version (`w_pkg_double_redeem`, `p_version_redemptions`);
/// - every live request remains sound.
///
/// Every counter is incremented at the point the *driver* authorizes the
/// forbidden effect (or, for redemption, returns the package), never because a
/// modelled store guard refused a write. The mutation notes in the evidence
/// directory show each counter becomes non-zero when the corresponding driver
/// decision is removed.
///
/// Assumptions (not proved here): sled and SQL operations are linearizable and
/// the handler performs exactly the effect the driver returns in the same step
/// as its observation; the owner/opener of the single grant never changes; the
/// completion's signature observation is honest (unforgeability is M13/Tamarin,
/// the per-request module proves the driver only authorizes on `Verified`);
/// account epochs and TTL expiry are constants outside the model.
///
/// This module deliberately does not import the per-request lemma module: the
/// composition is a statement about the extracted driver alone. That also makes
/// the mutation checks fail here, not in an unrelated lemma.

open FStar.Mul
open Core_models
open Vela_enrollment_policy
open Vela_enrollment_policy.Pairing_driver

// ── Generic list helpers (Core_models shadows the unqualified names) ────────

let rec update (#a: Type) (l: list a) (i: nat) (x: a)
  : Tot (list a) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec update_length (#a: Type) (l: list a) (i: nat) (x: a)
  : Lemma (ensures (FStar.List.Tot.length (update l i x) = FStar.List.Tot.length l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_length t (i - 1) x

// ── World model ────────────────────────────────────────────────────────────

let i64_one : i64 = mk_i64 1

/// The single enrollment grant. `g_open` is the grant record; `g_claimed` is
/// the claim record; the destructive take clears both. `g_enrolled` counts the
/// device rows the driver authorized, `g_result` the collector's record.
noeq type grant_state = {
  g_open: bool;
  g_owner: nat;
  g_opener: nat;
  g_claimed: bool;
  g_enrolled: nat;
  g_result: bool;
}

/// One stored invitation package version. A store resets the version's
/// redemption count; the destructive read clears `p_live`.
noeq type package_state = {
  p_live: bool;
  p_version_redemptions: nat;
}

/// A request keeps the per-request driver plus the *spawn-time* account facts
/// the handler had when it decided. The facts never change, because a grant is
/// not transferred between accounts or devices.
noeq type request =
  | StoreReq : t_PairingDriver -> request
  | RedeemReq : t_PairingDriver -> request
  | ClaimReq : t_PairingDriver -> request
  | CompleteReq : t_PairingDriver -> bool -> bool -> bool -> request
  /// `account_matches`, `opener_matches`, `signature_ok`.
  | ResultReq : t_PairingDriver -> request

noeq type world = {
  w_package: package_state;
  w_grant: grant_state;
  w_reqs: list request;
  /// Driver authorizations of a claim write.
  w_claim_authorizations: nat;
  /// Claim records the write actually created (the model's CAS applied).
  w_claim_records: nat;
  /// Driver authorizations of a take without a live stored claim.
  w_take_without_claim: nat;
  /// Driver authorizations of `InsertDevice`.
  w_enrollments: nat;
  /// Driver authorizations of an insert after a row was already enrolled.
  w_enroll_after_enrolled: nat;
  /// Driver authorizations of an insert for a different account.
  w_enroll_cross_account: nat;
  /// Driver authorizations of an insert without the opener's signature.
  w_enroll_without_signature: nat;
  /// Completions of a redemption of an already-redeemed stored version.
  w_pkg_double_redeem: nat;
  /// Total successful redemptions (witness aid, not bounded across versions).
  w_pkg_redemptions: nat;
}

// ── Per-request invariant ──────────────────────────────────────────────────

let request_ok (r: request) : prop =
  match r with
  | StoreReq d -> pairing_state_is_sound d
  | RedeemReq d -> pairing_state_is_sound d
  | ClaimReq d -> pairing_state_is_sound d
  | CompleteReq d account_matches opener_matches signature_ok ->
      pairing_state_is_sound d /\
      (d.f_user_matches ==> account_matches) /\
      (d.f_opener_matches ==> opener_matches) /\
      (d.f_signature_verified ==> signature_ok)
  | ResultReq d -> pairing_state_is_sound d

let rec all_requests_ok (l: list request) : prop =
  match l with
  | [] -> true
  | r :: rest -> request_ok r /\ all_requests_ok rest

let rec all_requests_ok_index (l: list request) (i: nat)
  : Lemma
    (requires (all_requests_ok l /\ i < FStar.List.Tot.length l))
    (ensures (request_ok (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else all_requests_ok_index t (i - 1)

let rec all_requests_ok_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (all_requests_ok l /\ request_ok r))
    (ensures (all_requests_ok (update l i r)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_requests_ok_update t (i - 1) r

let all_requests_ok_cons (r: request) (l: list request)
  : Lemma (requires (request_ok r /\ all_requests_ok l))
    (ensures (all_requests_ok (r :: l))) = ()

let request_driver (r: request) : t_PairingDriver =
  match r with
  | StoreReq d -> d
  | RedeemReq d -> d
  | ClaimReq d -> d
  | CompleteReq d _ _ _ -> d
  | ResultReq d -> d

let inflight_of_stage (s: t_PairingStage) : bool =
  match s <: t_PairingStage with
  | PairingStage_InFlight -> true
  | _ -> false

let request_inflight (r: request) : bool =
  inflight_of_stage (request_driver r).f_stage

let rec count_inflight (l: list request) : Tot int (decreases l) =
  match l with
  | [] -> 0
  | r :: rest -> (if request_inflight r then 1 else 0) + count_inflight rest

let count_inflight_cons (r: request) (rest: list request)
  : Lemma (count_inflight (r :: rest) =
           (if request_inflight r then 1 else 0) + count_inflight rest) = ()

let count_inflight_cons_false (r: request) (rest: list request)
  : Lemma (requires (request_inflight r = false))
    (ensures (count_inflight (r :: rest) = count_inflight rest)) = ()

let count_inflight_cons_true (r: request) (rest: list request)
  : Lemma (requires (request_inflight r = true))
    (ensures (count_inflight (r :: rest) = 1 + count_inflight rest)) = ()

let rec count_inflight_nonneg (l: list request)
  : Lemma (ensures (count_inflight l >= 0)) (decreases l) =
  match l with
  | [] -> ()
  | r :: rest -> count_inflight_nonneg rest

let rec count_inflight_positive (l: list request) (i: nat)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      request_inflight (FStar.List.Tot.index l i) = true))
    (ensures (count_inflight l >= 1))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t ->
      if i = 0
      then begin
        assert (request_inflight h = true);
        count_inflight_cons_true h t;
        count_inflight_nonneg t
      end
      else begin
        count_inflight_positive t (i - 1);
        count_inflight_nonneg t;
        if request_inflight h
        then count_inflight_cons_true h t
        else count_inflight_cons_false h t
      end

let rec count_inflight_update_same (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      request_inflight (FStar.List.Tot.index l i) = request_inflight r))
    (ensures (count_inflight (update l i r) = count_inflight l))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t ->
      if i = 0 then ()
      else count_inflight_update_same t (i - 1) r

let rec count_inflight_update_to (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      request_inflight (FStar.List.Tot.index l i) = false /\
      request_inflight r = true))
    (ensures (count_inflight (update l i r) = count_inflight l + 1))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t ->
      if i = 0 then ()
      else count_inflight_update_to t (i - 1) r

let rec count_inflight_update_from (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      request_inflight (FStar.List.Tot.index l i) = true /\
      request_inflight r = false /\
      count_inflight l >= 1))
    (ensures (count_inflight (update l i r) = count_inflight l - 1))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t ->
      if i = 0
      then begin
        assert (request_inflight h = true);
        count_inflight_cons_false r t;
        count_inflight_cons_true h t
      end
      else begin
        assert (FStar.List.Tot.index (h :: t) i ==
                FStar.List.Tot.index t (i - 1));
        assert (request_inflight (FStar.List.Tot.index t (i - 1)) = true);
        count_inflight_positive t (i - 1);
        assert (count_inflight t >= 1);
        count_inflight_update_from t (i - 1) r
      end

/// The stage flags that determine `request_inflight` are preserved (or
/// cleared) by the non-insert transitions, so an update that never turns a
/// request into an `InFlight` one leaves the count alone.
let inflight_account_preserved (d: t_PairingDriver)
                               (o: t_CompletionAccountObservation)
  : Lemma
    (requires (pairing_state_is_sound d))
    (ensures (inflight_of_stage (on_completion_account d o).f_driver.f_stage =
              inflight_of_stage d.f_stage)) =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start -> ()
  | PairingStage_Applied -> ()
  | PairingStage_InFlight -> ()
  | PairingStage_WroteResult -> ()
  | PairingStage_ResultClaim -> ()
  | PairingStage_Done -> ()

let inflight_preflight_preserved (d: t_PairingDriver)
                                  (o: t_CompletionPreflightObservation)
  : Lemma
    (requires (pairing_state_is_sound d))
    (ensures (
      inflight_of_stage
        (on_completion_ready_event d o).f_driver.f_stage =
      inflight_of_stage d.f_stage)) =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start -> ()
  | PairingStage_Applied -> ()
  | PairingStage_InFlight -> ()
  | PairingStage_WroteResult -> ()
  | PairingStage_ResultClaim -> ()
  | PairingStage_Done -> ()

let inflight_result_written_preserved (d: t_PairingDriver) (o: t_StoreObservation)
  : Lemma
    (requires (pairing_state_is_sound d))
    (ensures (
      inflight_of_stage
        (on_result_written_event d o).f_driver.f_stage =
      inflight_of_stage d.f_stage)) =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start -> ()
  | PairingStage_Applied -> ()
  | PairingStage_InFlight -> ()
  | PairingStage_WroteResult -> ()
  | PairingStage_ResultClaim -> ()
  | PairingStage_Done -> ()

let inflight_result_read_preserved (d: t_PairingDriver)
                                    (o: t_ResultReadObservation)
  : Lemma
    (requires (pairing_state_is_sound d))
    (ensures (
      inflight_of_stage (on_result_read_event d o).f_driver.f_stage =
      inflight_of_stage d.f_stage)) =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start -> ()
  | PairingStage_Applied -> ()
  | PairingStage_InFlight -> ()
  | PairingStage_WroteResult -> ()
  | PairingStage_ResultClaim -> ()
  | PairingStage_Done -> ()

let inflight_claim_read_preserved (d: t_PairingDriver)
                                   (o: t_ClaimReadObservation)
  : Lemma
    (requires (pairing_state_is_sound d))
    (ensures (
      inflight_of_stage (on_claim_read_event d o).f_driver.f_stage =
      inflight_of_stage d.f_stage)) =
  match d.f_stage <: t_PairingStage with
  | PairingStage_Start -> ()
  | PairingStage_Applied -> ()
  | PairingStage_InFlight -> ()
  | PairingStage_WroteResult -> ()
  | PairingStage_ResultClaim -> ()
  | PairingStage_Done -> ()

/// The shared invariant. Every counter is a property of the extracted drivers:
/// each is incremented in `world_step` exactly at the driver's authorization.
let inv (w: world) : prop =
  all_requests_ok w.w_reqs /\
  w.w_claim_authorizations <= 1 /\
  w.w_claim_records <= w.w_claim_authorizations /\
  (w.w_claim_authorizations = 1 ==>
    (w.w_grant.g_claimed || not w.w_grant.g_open)) /\
  w.w_take_without_claim = 0 /\
  w.w_enrollments = w.w_grant.g_enrolled /\
  w.w_enrollments <= 1 /\
  w.w_enroll_after_enrolled = 0 /\
  w.w_enroll_cross_account = 0 /\
  w.w_enroll_without_signature = 0 /\
  w.w_pkg_double_redeem = 0 /\
  w.w_package.p_version_redemptions <= 1 /\
  (w.w_package.p_version_redemptions = 1 ==> not w.w_package.p_live) /\
  (w.w_grant.g_claimed ==> w.w_grant.g_open) /\
  w.w_grant.g_enrolled <= 1 /\
  (w.w_grant.g_enrolled > 0 ==> not w.w_grant.g_open) /\
  count_inflight w.w_reqs <= 1 /\
  (count_inflight w.w_reqs > 0 ==> not w.w_grant.g_open) /\
  (w.w_grant.g_enrolled > 0 ==> count_inflight w.w_reqs = 0)

// ── Observations derived from the world ────────────────────────────────────

let grant_observation (w: world) (account: nat) (opener: nat) : t_GrantObservation =
  if w.w_grant.g_open
  then GrantObservation_Present
    ({ f_user_matches = (account = w.w_grant.g_owner);
       f_opener_matches = (opener = w.w_grant.g_opener) })
  else GrantObservation_Absent

let claim_observation (w: world) : t_ClaimObservation =
  ({ f_grant_live = w.w_grant.g_open;
     f_claim_exists = w.w_grant.g_claimed;
     f_hybrid_ek_len = v_HYBRID_EK_LEN;
     f_hybrid_vk_len = v_HYBRID_VK_LEN })

let completion_preflight (w: world) (signature_ok: bool)
  : t_CompletionPreflightObservation =
  ({ f_claim =
       (if w.w_grant.g_claimed
        then ClaimMaterialObservation_Usable
        else ClaimMaterialObservation_Missing);
     f_capsule_valid = true;
     f_signature_field_valid = true;
     f_opener = OpenerObservation_Active;
     f_signature =
       (if signature_ok
        then SignatureObservation_Verified
        else SignatureObservation_Failed);
     f_account_epoch = i64_one;
     f_declared_epoch = i64_one;
     f_rotation_in_progress = false;
     f_account_epoch_active = true })

let take_observation (w: world) : t_TakeObservation =
  if w.w_grant.g_open && w.w_grant.g_claimed
  then TakeObservation_Taken ({ f_grant_matches = true; f_claim_matches = true })
  else TakeObservation_Missing

let result_observation (w: world) : t_ResultReadObservation =
  if w.w_grant.g_result
  then ResultReadObservation_Completed
    ({ f_claimed_key_len = v_HYBRID_VK_LEN; f_signature_verified = true })
  else ResultReadObservation_Absent

let claim_read_observation (w: world) : t_ClaimReadObservation =
  if w.w_grant.g_claimed
  then ClaimReadObservation_Claimed
    ({ f_claimed_key_len = v_HYBRID_VK_LEN; f_signature_verified = true })
  else ClaimReadObservation_Absent

/// U-20 fallback observation: the inserted device row is the only remaining
/// record once the result write is lost. The composition models its key as the
/// same claimed key and a verified signature, so the result policy authorizes
/// the same `Enrolled` answer.
let device_grant_observation (w: world) : t_DeviceGrantObservation =
  if w.w_grant.g_enrolled > 0
  then DeviceGrantObservation_Enrolled
    ({ f_claimed_key_len = v_HYBRID_VK_LEN; f_signature_verified = true })
  else DeviceGrantObservation_Absent

// ── Arbitrary schedules ────────────────────────────────────────────────────

type action =
  | SpawnStore : bool -> action
  | SpawnRedeem : bool -> action
  | SpawnClaim : action
  | SpawnComplete : nat -> nat -> bool -> action
  | CompletionAccount : nat -> action
  | CompletionPreflight : nat -> action
  | CompletionTake : nat -> action
  | CompletionInsert : nat -> action
  | CompletionResult : nat -> action
  | SpawnResult : action
  | ResultRead : nat -> action
  | ResultClaim : nat -> action
  | ResultDevice : nat -> action

let account_observation : t_CompletionAccountObservation =
  ({ f_account_query_ok = true;
     f_declared_epoch_positive = true;
     f_rekey_permitted = true })

let world_step (w: world) (a: action) : Tot world (decreases a) =
  match a with
  | SpawnStore valid ->
      let t0 = begin_store_package
        ({ f_token_valid = valid; f_ciphertext_len_valid = true }) in
      (match t0.f_effect <: t_PairingEffect with
       | PairingEffect_StorePackage ->
           let t = on_package_written_event t0.f_driver StoreObservation_Stored in
           { w with
             w_package = ({ p_live = true; p_version_redemptions = 0 });
             w_reqs = StoreReq t.f_driver :: w.w_reqs }
       | _ ->
           { w with w_reqs = StoreReq t0.f_driver :: w.w_reqs })
  | SpawnRedeem valid ->
      let t0 = begin_redeem_package ({ f_token_valid = valid }) in
      (match t0.f_effect <: t_PairingEffect with
       | PairingEffect_RedeemPackage ->
           let observation =
             if w.w_package.p_live
             then RedeemObservation_Present ({ f_utf8_valid = true })
             else RedeemObservation_Missing in
           let t = on_package_redeemed_event t0.f_driver observation in
           let w1 = { w with w_package = ({ w.w_package with p_live = false }) } in
           let w2 =
             (match t.f_effect <: t_PairingEffect with
              | PairingEffect_Complete ->
                  { w1 with
                    w_package = ({ w1.w_package with
                                   p_version_redemptions =
                                     w1.w_package.p_version_redemptions + 1 });
                    w_pkg_redemptions = w1.w_pkg_redemptions + 1;
                    w_pkg_double_redeem = w1.w_pkg_double_redeem +
                      (if w1.w_package.p_version_redemptions > 0 then 1 else 0) }
              | _ -> w1) in
           { w2 with w_reqs = RedeemReq t.f_driver :: w2.w_reqs }
       | _ ->
           { w with w_reqs = RedeemReq t0.f_driver :: w.w_reqs })
  | SpawnClaim ->
      let t0 = begin_claim w.w_grant.g_open in
      (match t0.f_effect <: t_PairingEffect with
       | PairingEffect_CheckClaim ->
           let t = on_claim_checked_event t0.f_driver (claim_observation w) in
           (match t.f_effect <: t_PairingEffect with
            | PairingEffect_WriteClaim ->
                let already = w.w_grant.g_claimed in
                let w1 =
                  { w with
                    w_claim_authorizations = w.w_claim_authorizations + 1;
                    w_claim_records = w.w_claim_records +
                      (if already then 0 else 1);
                    w_grant = ({ w.w_grant with g_claimed = true }) } in
                let written =
                  if already
                  then ClaimWriteObservation_KeyExists
                  else ClaimWriteObservation_Inserted in
                let t2 = on_claim_written_event t.f_driver written in
                { w1 with w_reqs = ClaimReq t2.f_driver :: w1.w_reqs }
            | _ ->
                { w with w_reqs = ClaimReq t.f_driver :: w.w_reqs })
       | _ ->
           { w with w_reqs = ClaimReq t0.f_driver :: w.w_reqs })
  | SpawnComplete account opener signature_ok ->
      let t0 = begin_completion (grant_observation w account opener) in
      let account_matches = (account = w.w_grant.g_owner) in
      let opener_matches = (opener = w.w_grant.g_opener) in
      { w with
        w_reqs = CompleteReq t0.f_driver account_matches opener_matches
                   signature_ok :: w.w_reqs }
  | CompletionAccount i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | CompleteReq d account_matches opener_matches signature_ok ->
             if pairing_state_is_sound d
             then
               let t = on_completion_account d account_observation in
               { w with
                 w_reqs = update w.w_reqs i
                   (CompleteReq t.f_driver account_matches opener_matches
                      signature_ok) }
             else w
         | _ -> w)
      else w
  | CompletionPreflight i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | CompleteReq d account_matches opener_matches signature_ok ->
             if pairing_state_is_sound d
             then
               let t = on_completion_ready_event d
                 (completion_preflight w signature_ok) in
               let w1 =
                 { w with
                   w_reqs = update w.w_reqs i
                     (CompleteReq t.f_driver account_matches opener_matches
                        signature_ok) } in
               (match t.f_effect <: t_PairingEffect with
                | PairingEffect_TakeCeremony ->
                    { w1 with
                      w_take_without_claim = w1.w_take_without_claim +
                        (if w.w_grant.g_claimed then 0 else 1) }
                | _ -> w1)
             else w
         | _ -> w)
      else w
  | CompletionTake i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | CompleteReq d account_matches opener_matches signature_ok ->
             if pairing_state_is_sound d
             then
               let t = on_ceremony_taken_event d (take_observation w) in
               let w1 =
                 { w with
                   w_reqs = update w.w_reqs i
                     (CompleteReq t.f_driver account_matches opener_matches
                        signature_ok) } in
               (match t.f_effect <: t_PairingEffect with
                | PairingEffect_InsertDevice ->
                    { w1 with
                      w_grant = ({ w1.w_grant with
                                   g_open = false; g_claimed = false }) }
                | _ -> w1)
             else w
         | _ -> w)
      else w
  | CompletionInsert i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | CompleteReq d account_matches opener_matches signature_ok ->
             if pairing_state_is_sound d
             then
               let t = on_device_inserted_event d
                 DeviceInsertObservation_Inserted in
               let w1 =
                 { w with
                   w_reqs = update w.w_reqs i
                     (CompleteReq t.f_driver account_matches opener_matches
                        signature_ok) } in
               (match t.f_effect <: t_PairingEffect with
                | PairingEffect_WriteResult ->
                    { w1 with
                      w_enrollments = w1.w_enrollments + 1;
                      w_enroll_after_enrolled = w1.w_enroll_after_enrolled +
                        (if w1.w_grant.g_enrolled > 0 then 1 else 0);
                      w_enroll_cross_account = w1.w_enroll_cross_account +
                        (if account_matches then 0 else 1);
                      w_enroll_without_signature =
                        w1.w_enroll_without_signature +
                        (if signature_ok then 0 else 1);
                      w_grant = ({ w1.w_grant with
                                   g_enrolled = w1.w_grant.g_enrolled + 1 }) }
                | _ -> w1)
             else w
         | _ -> w)
      else w
  | CompletionResult i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | CompleteReq d account_matches opener_matches signature_ok ->
             if pairing_state_is_sound d
             then
               let t = on_result_written_event d StoreObservation_Stored in
               let w1 =
                 { w with
                   w_reqs = update w.w_reqs i
                     (CompleteReq t.f_driver account_matches opener_matches
                        signature_ok) } in
               (match t.f_effect <: t_PairingEffect with
                | PairingEffect_Complete ->
                    { w1 with w_grant = ({ w1.w_grant with g_result = true }) }
                | _ -> w1)
             else w
         | _ -> w)
      else w
  | SpawnResult ->
      let t0 = begin_result () in
      { w with w_reqs = ResultReq t0.f_driver :: w.w_reqs }
  | ResultRead i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | ResultReq d ->
             if pairing_state_is_sound d
             then
               let t = on_result_read_event d (result_observation w) in
               { w with w_reqs = update w.w_reqs i (ResultReq t.f_driver) }
             else w
         | _ -> w)
      else w
  | ResultClaim i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | ResultReq d ->
             if pairing_state_is_sound d
             then
               let t = on_claim_read_event d (claim_read_observation w) in
               { w with w_reqs = update w.w_reqs i (ResultReq t.f_driver) }
             else w
         | _ -> w)
      else w
  | ResultDevice i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | ResultReq d ->
             if pairing_state_is_sound d
             then
               let t = on_enrolled_device_read_event d (device_grant_observation w) in
               { w with w_reqs = update w.w_reqs i (ResultReq t.f_driver) }
             else w
         | _ -> w)
      else w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Driver-side facts used by the composition ──────────────────────────────

/// A completion request that is about to insert carries the account/opener
/// binding and a verified signature. This is read off the per-request state
/// invariant, not restated here.
let insert_requires_completion_facts (d: t_PairingDriver)
  : Lemma
    (requires (pairing_state_is_sound d /\ d.f_inserted))
    (ensures (d.f_grant_present /\ d.f_claim_present /\ d.f_opener_active /\
              d.f_signature_verified /\ d.f_user_matches /\ d.f_opener_matches)) =
  ()

/// A take authorization follows the verified completion policy, hence a stored
/// claim.
let take_authorization_implies_claim
      (d: t_PairingDriver)
      (observation: t_CompletionPreflightObservation)
  : Lemma
    (requires (
      pairing_state_is_sound d /\
      (match d.f_stage <: t_PairingStage with
       | PairingStage_Start -> true
       | _ -> false) /\
      (match d.f_ceremony <: t_PairingCeremony with
       | PairingCeremony_CompleteGrant -> true
       | _ -> false) /\
      d.f_wrote = false /\
      (on_completion_ready_event d observation).f_effect
        = PairingEffect_TakeCeremony))
    (ensures (
      (match observation.f_claim <: t_ClaimMaterialObservation with
       | ClaimMaterialObservation_Missing -> False
       | _ -> True))) =
  ()

/// The claim policy refuses a request whose observation says the grant is
/// gone or already claimed.
let claim_policy_refuses (observation: t_ClaimObservation)
  : Lemma
    (requires (
      observation.f_grant_live = false \/ observation.f_claim_exists = true))
    (ensures (
      (on_claim_checked_event (begin_claim observation.f_grant_live).f_driver
         observation).f_effect
        <> PairingEffect_WriteClaim)) =
  ()

/// A completed redemption requires a present observation.
let redeem_completion_requires_present (d: t_PairingDriver)
                                        (observation: t_RedeemObservation)
  : Lemma
    (requires (pairing_state_is_sound d))
    (ensures (
      (on_package_redeemed_event d observation).f_effect
        = PairingEffect_Complete ==>
      (match observation <: t_RedeemObservation with
       | RedeemObservation_Present t -> t.f_utf8_valid
       | RedeemObservation_Missing -> False))) =
  ()

// ── Invariant preservation ─────────────────────────────────────────────────

let spawn_store_inv (w: world) (valid: bool)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (SpawnStore valid)))) =
  let t0 = begin_store_package
    ({ f_token_valid = valid; f_ciphertext_len_valid = true }) in
  assert (pairing_state_is_sound t0.f_driver);
  (match t0.f_effect <: t_PairingEffect with
   | PairingEffect_StorePackage ->
       let t = on_package_written_event t0.f_driver StoreObservation_Stored in
       assert (pairing_state_is_sound t.f_driver);
       all_requests_ok_cons (StoreReq t.f_driver) w.w_reqs
   | _ ->
       all_requests_ok_cons (StoreReq t0.f_driver) w.w_reqs)

let spawn_redeem_inv (w: world) (valid: bool)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (SpawnRedeem valid)))) =
  let t0 = begin_redeem_package ({ f_token_valid = valid }) in
  assert (pairing_state_is_sound t0.f_driver);
  (match t0.f_effect <: t_PairingEffect with
   | PairingEffect_RedeemPackage ->
       let observation =
         if w.w_package.p_live
         then RedeemObservation_Present ({ f_utf8_valid = true })
         else RedeemObservation_Missing in
       let t = on_package_redeemed_event t0.f_driver observation in
       assert (pairing_state_is_sound t.f_driver);
       (match t.f_effect <: t_PairingEffect with
        | PairingEffect_Complete ->
            redeem_completion_requires_present t0.f_driver observation;
            assert (w.w_package.p_live = true);
            assert (w.w_package.p_version_redemptions = 1 ==>
                    not w.w_package.p_live);
            assert (w.w_package.p_version_redemptions = 0)
        | _ -> ());
       all_requests_ok_cons (RedeemReq t.f_driver) w.w_reqs
   | _ ->
       all_requests_ok_cons (RedeemReq t0.f_driver) w.w_reqs)

let spawn_claim_inv (w: world)
  : Lemma (requires (inv w)) (ensures (inv (world_step w SpawnClaim))) =
  let t0 = begin_claim w.w_grant.g_open in
  assert (pairing_state_is_sound t0.f_driver);
  (match t0.f_effect <: t_PairingEffect with
   | PairingEffect_CheckClaim ->
       let t = on_claim_checked_event t0.f_driver (claim_observation w) in
       assert (pairing_state_is_sound t.f_driver);
       (match t.f_effect <: t_PairingEffect with
        | PairingEffect_WriteClaim ->
            if w.w_grant.g_open = false
            then begin
              claim_policy_refuses (claim_observation w);
              assert (t.f_effect <> PairingEffect_WriteClaim)
            end;
            if w.w_grant.g_claimed = true
            then begin
              claim_policy_refuses (claim_observation w);
              assert (t.f_effect <> PairingEffect_WriteClaim)
            end;
            assert (w.w_grant.g_open = true);
            assert (w.w_grant.g_claimed = false);
            if w.w_claim_authorizations = 1
            then assert (w.w_grant.g_claimed || not w.w_grant.g_open);
            assert (w.w_claim_authorizations = 0);
            all_requests_ok_cons (ClaimReq t.f_driver) w.w_reqs
        | _ ->
            all_requests_ok_cons (ClaimReq t.f_driver) w.w_reqs)
   | _ ->
       all_requests_ok_cons (ClaimReq t0.f_driver) w.w_reqs)

let spawn_complete_inv (w: world) (account: nat) (opener: nat) (signature_ok: bool)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (SpawnComplete account opener signature_ok)))) =
  let t0 = begin_completion (grant_observation w account opener) in
  assert (pairing_state_is_sound t0.f_driver);
  let account_matches = (account = w.w_grant.g_owner) in
  let opener_matches = (opener = w.w_grant.g_opener) in
  // A failed begin never claims the bindings.
  (match grant_observation w account opener <: t_GrantObservation with
   | GrantObservation_Present g ->
       (match t0.f_effect <: t_PairingEffect with
        | PairingEffect_CheckAccount ->
            assert (t0.f_driver.f_user_matches = g.f_user_matches);
            assert (t0.f_driver.f_opener_matches = g.f_opener_matches)
        | _ -> ())
   | _ -> ());
  all_requests_ok_cons
    (CompleteReq t0.f_driver account_matches opener_matches signature_ok)
    w.w_reqs

let completion_account_inv (w: world) (i: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (CompletionAccount i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | CompleteReq d account_matches opener_matches signature_ok ->
        all_requests_ok_index w.w_reqs i;
        let t = on_completion_account d account_observation in
        assert (pairing_state_is_sound t.f_driver);
        all_requests_ok_update w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok);
        count_inflight_update_same w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok)
    | _ -> ()

let completion_preflight_inv (w: world) (i: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (CompletionPreflight i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | CompleteReq d account_matches opener_matches signature_ok ->
        all_requests_ok_index w.w_reqs i;
        let t = on_completion_ready_event d
          (completion_preflight w signature_ok) in
        assert (pairing_state_is_sound t.f_driver);
        all_requests_ok_update w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok);
        count_inflight_update_same w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok);
        (match t.f_effect <: t_PairingEffect with
         | PairingEffect_TakeCeremony ->
             take_authorization_implies_claim d (completion_preflight w signature_ok);
             assert (w.w_grant.g_claimed = true)
         | _ -> ())
    | _ -> ()

let completion_take_inv (w: world) (i: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (CompletionTake i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | CompleteReq d account_matches opener_matches signature_ok ->
        all_requests_ok_index w.w_reqs i;
        let t = on_ceremony_taken_event d (take_observation w) in
        assert (pairing_state_is_sound t.f_driver);
        all_requests_ok_update w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok);
        (match t.f_effect <: t_PairingEffect with
         | PairingEffect_InsertDevice ->
             assert (request_inflight
               (CompleteReq d account_matches opener_matches signature_ok) = false);
             assert (request_inflight
               (CompleteReq t.f_driver account_matches opener_matches
                  signature_ok) = true);
             count_inflight_update_to w.w_reqs i
               (CompleteReq t.f_driver account_matches opener_matches
                  signature_ok);
             assert (w.w_grant.g_enrolled = 0)
         | _ ->
             count_inflight_update_same w.w_reqs i
               (CompleteReq t.f_driver account_matches opener_matches
                  signature_ok))
    | _ -> ()

let completion_insert_inv (w: world) (i: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (CompletionInsert i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | CompleteReq d account_matches opener_matches signature_ok ->
        all_requests_ok_index w.w_reqs i;
        let t = on_device_inserted_event d DeviceInsertObservation_Inserted in
        assert (pairing_state_is_sound t.f_driver);
        all_requests_ok_update w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok);
        (match t.f_effect <: t_PairingEffect with
         | PairingEffect_WriteResult ->
             assert (FStar.List.Tot.index w.w_reqs i ==
                     CompleteReq d account_matches opener_matches
                       signature_ok);
             assert (request_inflight
               (CompleteReq d account_matches opener_matches signature_ok) = true);
             assert (request_inflight
               (CompleteReq t.f_driver account_matches opener_matches
                  signature_ok) = false);
             count_inflight_positive w.w_reqs i;
             count_inflight_update_from w.w_reqs i
               (CompleteReq t.f_driver account_matches opener_matches
                  signature_ok);
             // The request's driver is sound *after* the insert, so the
             // per-request invariant gives the account, opener and signature
             // facts that make the counters impossible.
             assert (pairing_effect_is_sound t.f_driver t.f_effect);
             assert (t.f_driver.f_inserted = true);
             assert (t.f_driver.f_user_matches = d.f_user_matches);
             assert (t.f_driver.f_signature_verified =
                     d.f_signature_verified);
             insert_requires_completion_facts t.f_driver;
             assert (t.f_driver.f_user_matches = true);
             all_requests_ok_index w.w_reqs i;
             assert (d.f_user_matches = true);
             assert (account_matches = true);
             assert (t.f_driver.f_signature_verified = true);
             assert (signature_ok = true);
             count_inflight_positive w.w_reqs i;
             if w.w_grant.g_enrolled > 0
             then assert (count_inflight w.w_reqs = 0);
             assert (w.w_grant.g_enrolled = 0)
         | _ ->
             count_inflight_update_same w.w_reqs i
               (CompleteReq t.f_driver account_matches opener_matches
                  signature_ok))
    | _ -> ()

let completion_result_inv (w: world) (i: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (CompletionResult i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | CompleteReq d account_matches opener_matches signature_ok ->
        all_requests_ok_index w.w_reqs i;
        let t = on_result_written_event d StoreObservation_Stored in
        assert (pairing_state_is_sound t.f_driver);
        all_requests_ok_update w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok);
        count_inflight_update_same w.w_reqs i
          (CompleteReq t.f_driver account_matches opener_matches signature_ok)
    | _ -> ()

let spawn_result_inv (w: world)
  : Lemma (requires (inv w)) (ensures (inv (world_step w SpawnResult))) =
  let t0 = begin_result () in
  assert (pairing_state_is_sound t0.f_driver);
  all_requests_ok_cons (ResultReq t0.f_driver) w.w_reqs

let result_read_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (ResultRead i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | ResultReq d ->
        all_requests_ok_index w.w_reqs i;
        let t = on_result_read_event d (result_observation w) in
        all_requests_ok_update w.w_reqs i (ResultReq t.f_driver);
        count_inflight_update_same w.w_reqs i (ResultReq t.f_driver)
    | _ -> ()

let result_claim_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (ResultClaim i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | ResultReq d ->
        all_requests_ok_index w.w_reqs i;
        let t = on_claim_read_event d (claim_read_observation w) in
        all_requests_ok_update w.w_reqs i (ResultReq t.f_driver);
        count_inflight_update_same w.w_reqs i (ResultReq t.f_driver)
    | _ -> ()

let result_device_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (ResultDevice i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | ResultReq d ->
        all_requests_ok_index w.w_reqs i;
        let t = on_enrolled_device_read_event d (device_grant_observation w) in
        all_requests_ok_update w.w_reqs i (ResultReq t.f_driver);
        count_inflight_update_same w.w_reqs i (ResultReq t.f_driver)
    | _ -> ()

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | SpawnStore valid -> spawn_store_inv w valid
  | SpawnRedeem valid -> spawn_redeem_inv w valid
  | SpawnClaim -> spawn_claim_inv w
  | SpawnComplete account opener signature_ok ->
      spawn_complete_inv w account opener signature_ok
  | CompletionAccount i -> completion_account_inv w i
  | CompletionPreflight i -> completion_preflight_inv w i
  | CompletionTake i -> completion_take_inv w i
  | CompletionInsert i -> completion_insert_inv w i
  | CompletionResult i -> completion_result_inv w i
  | SpawnResult -> spawn_result_inv w
  | ResultRead i -> result_read_inv w i
  | ResultClaim i -> result_claim_inv w i
  | ResultDevice i -> result_device_inv w i

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── Initial world and headline composition theorem ─────────────────────────

let initial : world =
  {
    w_package = ({ p_live = false; p_version_redemptions = 0 });
    w_grant = ({ g_open = true; g_owner = 0; g_opener = 0; g_claimed = false;
                 g_enrolled = 0; g_result = false });
    w_reqs = [];
    w_claim_authorizations = 0;
    w_claim_records = 0;
    w_take_without_claim = 0;
    w_enrollments = 0;
    w_enroll_after_enrolled = 0;
    w_enroll_cross_account = 0;
    w_enroll_without_signature = 0;
    w_pkg_double_redeem = 0;
    w_pkg_redemptions = 0;
  }

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem: whatever the number of concurrent opener, joiner and
/// other-account requests, their interleaving and their observations, the
/// extracted drivers never authorize a second claim, a second completion, a
/// cross-account enrollment, an unsigned enrollment or a second redemption of
/// one stored package version.
let pairing_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_claim_authorizations <= 1 /\
      w.w_enrollments <= 1 /\
      w.w_enroll_after_enrolled = 0 /\
      w.w_enroll_cross_account = 0 /\
      w.w_enroll_without_signature = 0 /\
      w.w_take_without_claim = 0 /\
      w.w_pkg_double_redeem = 0 /\
      w.w_package.p_version_redemptions <= 1 /\
      w.w_grant.g_enrolled <= 1) =
  initial_inv ();
  run_world_inv initial schedule

let at_most_one_claim (schedule: list action)
  : Lemma ((run_world initial schedule).w_claim_authorizations <= 1) =
  pairing_composition_theorem schedule

let at_most_one_enrollment (schedule: list action)
  : Lemma ((run_world initial schedule).w_enrollments <= 1) =
  pairing_composition_theorem schedule

let no_cross_account_enrollment (schedule: list action)
  : Lemma ((run_world initial schedule).w_enroll_cross_account = 0) =
  pairing_composition_theorem schedule

let no_unsigned_enrollment (schedule: list action)
  : Lemma ((run_world initial schedule).w_enroll_without_signature = 0) =
  pairing_composition_theorem schedule

let no_take_without_claim (schedule: list action)
  : Lemma ((run_world initial schedule).w_take_without_claim = 0) =
  pairing_composition_theorem schedule

let at_most_one_redemption_per_version (schedule: list action)
  : Lemma ((run_world initial schedule).w_pkg_double_redeem = 0 /\
           (run_world initial schedule).w_package.p_version_redemptions <= 1) =
  pairing_composition_theorem schedule

// ── Non-vacuity: reachable ceremonies and refusals ─────────────────────────

#push-options "--fuel 4 --ifuel 2"

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

// A legitimate ceremony: store, redeem, claim, complete, collect.
let legitimate_schedule : list action =
  [ SpawnStore true;
    SpawnRedeem true;
    SpawnClaim;
    SpawnComplete 0 0 true;
    CompletionAccount 0;
    CompletionPreflight 0;
    CompletionTake 0;
    CompletionInsert 0;
    CompletionResult 0;
    SpawnResult;
    ResultRead 0 ]

let v1 = world_step initial (SpawnStore true)
let v2 = world_step v1 (SpawnRedeem true)
let v3 = world_step v2 SpawnClaim
let v4 = world_step v3 (SpawnComplete 0 0 true)
let v5 = world_step v4 (CompletionAccount 0)
let v6 = world_step v5 (CompletionPreflight 0)
let v7 = world_step v6 (CompletionTake 0)
let v8 = world_step v7 (CompletionInsert 0)
let v9 = world_step v8 (CompletionResult 0)
let v10 = world_step v9 SpawnResult
let v11 = world_step v10 (ResultRead 0)

let v1_ok ()
  : Lemma (v1.w_package.p_live = true /\
           v1.w_package.p_version_redemptions = 0 /\
           FStar.List.Tot.length v1.w_reqs = 1) = ()
let v2_ok ()
  : Lemma (v2.w_package.p_live = false /\
           v2.w_package.p_version_redemptions = 1 /\
           v2.w_pkg_double_redeem = 0 /\
           v2.w_claim_authorizations = 0) = v1_ok ()
let v3_ok ()
  : Lemma (v3.w_grant.g_claimed = true /\
           v3.w_claim_authorizations = 1 /\
           v3.w_claim_records = 1 /\
           v3.w_enrollments = 0) = v2_ok ()
let v4_ok ()
  : Lemma (v4.w_claim_authorizations = 1 /\
           v4.w_enrollments = 0) = v3_ok ()
let v5_ok () : Lemma (v5.w_enrollments = 0) = v4_ok ()
let v6_ok ()
  : Lemma (
      let r = FStar.List.Tot.index v6.w_reqs 0 in
      (match r with
       | CompleteReq d _ _ _ ->
           d.f_stage = (PairingStage_Applied <: t_PairingStage)
       | _ -> False) /\
      v6.w_take_without_claim = 0) = v5_ok ()
let v7_ok ()
  : Lemma (v7.w_grant.g_open = false /\
           v7.w_grant.g_claimed = false /\
           v7.w_enrollments = 0) = v6_ok ()
let v8_ok ()
  : Lemma (v8.w_grant.g_enrolled = 1 /\
           v8.w_enrollments = 1 /\
           v8.w_enroll_after_enrolled = 0 /\
           v8.w_enroll_cross_account = 0) = v7_ok ()
let v9_ok () : Lemma (v9.w_grant.g_result = true) = v8_ok ()
let v10_ok ()
  : Lemma (v10.w_enrollments = 1 /\ v10.w_grant.g_result = true) =
  assert_norm (v10.w_enrollments = 1 /\ v10.w_grant.g_result = true)
let v11_ok ()
  : Lemma (
      let r = FStar.List.Tot.index v11.w_reqs 0 in
      (match r with
       | ResultReq d ->
           d.f_succeeded = true /\ d.f_failed = false
       | _ -> False) /\
      v11.w_enrollments = 1) = v10_ok ()

let a_legitimate_ceremony_enrolls_one_device ()
  : Lemma (
      let w = run_world initial legitimate_schedule in
      w.w_grant.g_enrolled = 1 /\
      w.w_grant.g_result = true /\
      w.w_claim_authorizations = 1 /\
      w.w_claim_records = 1 /\
      w.w_enrollments = 1 /\
      w.w_enroll_after_enrolled = 0 /\
      w.w_enroll_cross_account = 0 /\
      w.w_enroll_without_signature = 0 /\
      w.w_take_without_claim = 0 /\
      w.w_pkg_double_redeem = 0 /\
      w.w_package.p_version_redemptions = 1) =
  run_cons initial (SpawnStore true) (FStar.List.Tot.tl legitimate_schedule);
  run_cons v1 (SpawnRedeem true)
    [ SpawnClaim; SpawnComplete 0 0 true; CompletionAccount 0;
      CompletionPreflight 0; CompletionTake 0; CompletionInsert 0;
      CompletionResult 0; SpawnResult; ResultRead 0 ];
  run_cons v2 SpawnClaim
    [ SpawnComplete 0 0 true; CompletionAccount 0; CompletionPreflight 0;
      CompletionTake 0; CompletionInsert 0; CompletionResult 0;
      SpawnResult; ResultRead 0 ];
  run_cons v3 (SpawnComplete 0 0 true)
    [ CompletionAccount 0; CompletionPreflight 0; CompletionTake 0;
      CompletionInsert 0; CompletionResult 0; SpawnResult; ResultRead 0 ];
  run_cons v4 (CompletionAccount 0)
    [ CompletionPreflight 0; CompletionTake 0; CompletionInsert 0;
      CompletionResult 0; SpawnResult; ResultRead 0 ];
  run_cons v5 (CompletionPreflight 0)
    [ CompletionTake 0; CompletionInsert 0; CompletionResult 0;
      SpawnResult; ResultRead 0 ];
  run_cons v6 (CompletionTake 0)
    [ CompletionInsert 0; CompletionResult 0; SpawnResult; ResultRead 0 ];
  run_cons v7 (CompletionInsert 0)
    [ CompletionResult 0; SpawnResult; ResultRead 0 ];
  run_cons v8 (CompletionResult 0) [ SpawnResult; ResultRead 0 ];
  run_cons v9 SpawnResult [ ResultRead 0 ];
  run_cons v10 (ResultRead 0) [];
  run_nil v11;
  v11_ok ()

// A replayed completion finds no grant and enrolls nothing.
let replay_schedule : list action =
  [ SpawnStore true; SpawnRedeem true; SpawnClaim;
    SpawnComplete 0 0 true; CompletionAccount 0; CompletionPreflight 0;
    CompletionTake 0; CompletionInsert 0; CompletionResult 0;
    SpawnComplete 0 0 true; CompletionAccount 0; CompletionPreflight 0;
    CompletionTake 0; CompletionInsert 0 ]

let r1 = world_step v9 (SpawnComplete 0 0 true)
let r2 = world_step r1 (CompletionAccount 0)
let r3 = world_step r2 (CompletionPreflight 0)
let r4 = world_step r3 (CompletionTake 0)
let r5 = world_step r4 (CompletionInsert 0)

let r5_ok ()
  : Lemma (r5.w_grant.g_enrolled = 1 /\
           r5.w_enrollments = 1 /\
           r5.w_enroll_after_enrolled = 0 /\
           r5.w_take_without_claim = 0) =
  assert_norm (r5.w_grant.g_enrolled = 1 /\
               r5.w_enrollments = 1 /\
               r5.w_enroll_after_enrolled = 0 /\
               r5.w_take_without_claim = 0)

/// A replayed completion is refused before the guarded insert.
let replayed_completion_enrolls_nothing ()
  : Lemma (
      let w = run_world initial replay_schedule in
      w.w_grant.g_enrolled = 1 /\
      w.w_enrollments = 1 /\
      w.w_enroll_after_enrolled = 0) =
  run_cons initial (SpawnStore true) (FStar.List.Tot.tl replay_schedule);
  run_cons v1 (SpawnRedeem true)
    (FStar.List.Tot.tl (FStar.List.Tot.tl replay_schedule));
  run_cons v2 SpawnClaim
    (FStar.List.Tot.tl (FStar.List.Tot.tl (FStar.List.Tot.tl replay_schedule)));
  run_cons v3 (SpawnComplete 0 0 true)
    [ CompletionAccount 0; CompletionPreflight 0; CompletionTake 0;
      CompletionInsert 0; CompletionResult 0; SpawnComplete 0 0 true;
      CompletionAccount 0; CompletionPreflight 0; CompletionTake 0;
      CompletionInsert 0 ];
  run_cons v4 (CompletionAccount 0)
    [ CompletionPreflight 0; CompletionTake 0; CompletionInsert 0;
      CompletionResult 0; SpawnComplete 0 0 true; CompletionAccount 0;
      CompletionPreflight 0; CompletionTake 0; CompletionInsert 0 ];
  run_cons v5 (CompletionPreflight 0)
    [ CompletionTake 0; CompletionInsert 0; CompletionResult 0;
      SpawnComplete 0 0 true; CompletionAccount 0; CompletionPreflight 0;
      CompletionTake 0; CompletionInsert 0 ];
  run_cons v6 (CompletionTake 0)
    [ CompletionInsert 0; CompletionResult 0; SpawnComplete 0 0 true;
      CompletionAccount 0; CompletionPreflight 0; CompletionTake 0;
      CompletionInsert 0 ];
  run_cons v7 (CompletionInsert 0)
    [ CompletionResult 0; SpawnComplete 0 0 true; CompletionAccount 0;
      CompletionPreflight 0; CompletionTake 0; CompletionInsert 0 ];
  run_cons v8 (CompletionResult 0)
    [ SpawnComplete 0 0 true; CompletionAccount 0; CompletionPreflight 0;
      CompletionTake 0; CompletionInsert 0 ];
  run_cons v9 (SpawnComplete 0 0 true)
    [ CompletionAccount 0; CompletionPreflight 0; CompletionTake 0;
      CompletionInsert 0 ];
  run_cons r1 (CompletionAccount 0)
    [ CompletionPreflight 0; CompletionTake 0; CompletionInsert 0 ];
  run_cons r2 (CompletionPreflight 0)
    [ CompletionTake 0; CompletionInsert 0 ];
  run_cons r3 (CompletionTake 0) [ CompletionInsert 0 ];
  run_cons r4 (CompletionInsert 0) [];
  run_nil r5;
  r5_ok ()

// A second claim is refused and authorizes no second write.
let claim_replay_schedule : list action =
  [ SpawnClaim; SpawnClaim ]

let c1 = world_step initial SpawnClaim
let c2 = world_step c1 SpawnClaim

let c2_ok ()
  : Lemma (c2.w_grant.g_claimed = true /\
           c2.w_claim_authorizations = 1 /\
           c2.w_claim_records = 1) = ()

let claim_replay_is_not_authorized ()
  : Lemma (
      let w = run_world initial claim_replay_schedule in
      w.w_grant.g_claimed = true /\
      w.w_claim_authorizations = 1 /\
      w.w_claim_records = 1) =
  run_cons initial SpawnClaim [ SpawnClaim ];
  run_cons c1 SpawnClaim [];
  run_nil c2;
  c2_ok ()

// A second redemption of the stored version is refused.
let redeem_replay_schedule : list action =
  [ SpawnStore true; SpawnRedeem true; SpawnRedeem true ]

let p1 = world_step initial (SpawnStore true)
let p2 = world_step p1 (SpawnRedeem true)
let p3 = world_step p2 (SpawnRedeem true)

let p3_ok ()
  : Lemma (p3.w_package.p_version_redemptions = 1 /\
           p3.w_pkg_double_redeem = 0 /\
           p3.w_pkg_redemptions = 1) = ()

let replayed_redemption_returns_nothing ()
  : Lemma (
      let w = run_world initial redeem_replay_schedule in
      w.w_package.p_version_redemptions = 1 /\
      w.w_pkg_double_redeem = 0) =
  run_cons initial (SpawnStore true) [ SpawnRedeem true; SpawnRedeem true ];
  run_cons p1 (SpawnRedeem true) [ SpawnRedeem true ];
  run_cons p2 (SpawnRedeem true) [];
  run_nil p3;
  p3_ok ()

// A cross-account completion is refused at the binding.
let cross_account_schedule : list action =
  [ SpawnClaim; SpawnComplete 1 0 true; CompletionAccount 0;
    CompletionPreflight 0; CompletionTake 0; CompletionInsert 0 ]

let x1 = world_step initial SpawnClaim
let x2 = world_step x1 (SpawnComplete 1 0 true)
let x3 = world_step x2 (CompletionAccount 0)
let x4 = world_step x3 (CompletionPreflight 0)
let x5 = world_step x4 (CompletionTake 0)
let x6 = world_step x5 (CompletionInsert 0)

let x6_ok ()
  : Lemma (x6.w_grant.g_enrolled = 0 /\
           x6.w_enrollments = 0 /\
           x6.w_enroll_cross_account = 0 /\
           x6.w_enroll_without_signature = 0) =
  assert_norm (x6.w_grant.g_enrolled = 0 /\
               x6.w_enrollments = 0 /\
               x6.w_enroll_cross_account = 0 /\
               x6.w_enroll_without_signature = 0)

let cross_account_completion_enrolls_nothing ()
  : Lemma (
      let w = run_world initial cross_account_schedule in
      w.w_grant.g_enrolled = 0 /\
      w.w_enrollments = 0 /\
      w.w_enroll_cross_account = 0) =
  run_cons initial SpawnClaim
    [ SpawnComplete 1 0 true; CompletionAccount 0; CompletionPreflight 0;
      CompletionTake 0; CompletionInsert 0 ];
  run_cons x1 (SpawnComplete 1 0 true)
    [ CompletionAccount 0; CompletionPreflight 0; CompletionTake 0;
      CompletionInsert 0 ];
  run_cons x2 (CompletionAccount 0)
    [ CompletionPreflight 0; CompletionTake 0; CompletionInsert 0 ];
  run_cons x3 (CompletionPreflight 0) [ CompletionTake 0; CompletionInsert 0 ];
  run_cons x4 (CompletionTake 0) [ CompletionInsert 0 ];
  run_cons x5 (CompletionInsert 0) [];
  run_nil x6;
  x6_ok ()

// An unsigned completion is refused by the verified policy.
let unsigned_schedule : list action =
  [ SpawnClaim; SpawnComplete 0 0 false; CompletionAccount 0;
    CompletionPreflight 0; CompletionTake 0; CompletionInsert 0 ]

let u1 = world_step initial SpawnClaim
let u2 = world_step u1 (SpawnComplete 0 0 false)
let u3 = world_step u2 (CompletionAccount 0)
let u4 = world_step u3 (CompletionPreflight 0)
let u5 = world_step u4 (CompletionTake 0)
let u6 = world_step u5 (CompletionInsert 0)

let u6_ok ()
  : Lemma (u6.w_grant.g_enrolled = 0 /\
           u6.w_enrollments = 0 /\
           u6.w_enroll_without_signature = 0) =
  assert_norm (u6.w_grant.g_enrolled = 0 /\
               u6.w_enrollments = 0 /\
               u6.w_enroll_without_signature = 0)

let unsigned_completion_enrolls_nothing ()
  : Lemma (
      let w = run_world initial unsigned_schedule in
      w.w_grant.g_enrolled = 0 /\
      w.w_enroll_without_signature = 0) =
  run_cons initial SpawnClaim
    [ SpawnComplete 0 0 false; CompletionAccount 0; CompletionPreflight 0;
      CompletionTake 0; CompletionInsert 0 ];
  run_cons u1 (SpawnComplete 0 0 false)
    [ CompletionAccount 0; CompletionPreflight 0; CompletionTake 0;
      CompletionInsert 0 ];
  run_cons u2 (CompletionAccount 0)
    [ CompletionPreflight 0; CompletionTake 0; CompletionInsert 0 ];
  run_cons u3 (CompletionPreflight 0) [ CompletionTake 0; CompletionInsert 0 ];
  run_cons u4 (CompletionTake 0) [ CompletionInsert 0 ];
  run_cons u5 (CompletionInsert 0) [];
  run_nil u6;
  u6_ok ()

#pop-options
