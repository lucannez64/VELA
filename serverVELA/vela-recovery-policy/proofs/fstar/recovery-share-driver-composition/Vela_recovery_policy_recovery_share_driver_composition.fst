module Vela_recovery_policy_recovery_share_driver_composition

/// Concurrent composition of the extracted recovery-share lifecycle driver
/// with the extracted WebAuthn release decision and the possession-proof
/// driver.
///
/// One account share state is shared by any number of requests: the stage,
/// finalize and delete drivers write it; the WebAuthn release reads it; the
/// possession driver reads only its staged commitment and never releases the
/// share. A schedule is an arbitrary list of actions: spawn a request, deliver
/// an update/account/read observation, run a WebAuthn attempt/verification/
/// live-account step, run a possession step, rotate, freeze or unfreeze the
/// account.
///
/// The world models the guarded SQL statements:
///
/// - a stage update writes the pending candidate iff no active share exists,
///   the account is not rotating and the permit epoch is the live epoch;
/// - a finalize update promotes the pending candidate iff it is exactly the
///   request's `(epoch, split)`, no active share exists and the account is not
///   rotating;
/// - a delete clears the active share and the staged split in the same step;
/// - a read returns the active share iff one exists.
///
/// Theorem: for every schedule,
///
/// - no WebAuthn release is ever authorized from a share that was deleted or
///   superseded at the time of the release decision
///   (`w.stale_releases = 0` and `w.superseded_releases = 0`);
/// - the account has at most one current split (`active_count w.st <= 1`), the
///   active and pending records are never both present, and each record names
///   the live epoch;
/// - the possession driver never releases the share (`w.proof_releases = 0`).
///
/// Every counter is incremented at the point the *driver* decides:
/// `w.releases`/`w.publications`/`w.deletes`/`w.reads`/`w.proof_grants` count
/// the drivers' own effects, and the stale/superseded counters are keyed on a
/// `ReleaseGrant` effect together with the world state at that decision, not on
/// a modelled guard refusing a write. The mutation notes in the evidence
/// directory show each counter is load-bearing.
///
/// Assumptions (not proved here): the SQL updates are linearizable, the handler
/// performs exactly the effect the driver returns, and the live-row/WebAuthn/
/// possession observations are produced honestly. SQL, cryptography and
/// multi-node replication remain outside this module.

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Recovery_share_driver
open Vela_recovery_policy.Webauthn_driver
open Vela_recovery_policy.Possession_driver

let b2n (b: bool) : nat = if b then 1 else 0

// ── Account share state ────────────────────────────────────────────────────

noeq type split = {
  split_epoch: i64;
  split_id: i64;
}

noeq type state = {
  st_epoch: i64;
  st_rotation: bool;
  st_active: Core_models.Option.t_Option split;
  st_pending: Core_models.Option.t_Option split;
}

let current_share (st: state) : bool =
  match st.st_active <: Core_models.Option.t_Option split with
  | Core_models.Option.Option_Some s -> s.split_epoch = st.st_epoch
  | Core_models.Option.Option_None -> false

let active_count (st: state) : nat =
  match st.st_active <: Core_models.Option.t_Option split with
  | Core_models.Option.Option_Some _ -> 1
  | Core_models.Option.Option_None -> 0

let state_ok (st: state) : prop =
  (match st.st_active <: Core_models.Option.t_Option split with
   | Core_models.Option.Option_Some s -> s.split_epoch = st.st_epoch
   | Core_models.Option.Option_None -> True) /\
  (match st.st_pending <: Core_models.Option.t_Option split with
   | Core_models.Option.Option_Some s -> s.split_epoch = st.st_epoch
   | Core_models.Option.Option_None -> True) /\
  (match (st.st_active <: Core_models.Option.t_Option split),
         (st.st_pending <: Core_models.Option.t_Option split) with
   | Core_models.Option.Option_Some _, Core_models.Option.Option_Some _ -> False
   | _ -> True)

let can_stage (st: state) (d: t_ShareLifecycleDriver) : bool =
  not st.st_rotation && st.st_epoch = d.f_epoch &&
  (match st.st_active <: Core_models.Option.t_Option split with
   | Core_models.Option.Option_None -> true
   | _ -> false)

let stage_into (st: state) (d: t_ShareLifecycleDriver) : state =
  { st with st_pending =
      Core_models.Option.Option_Some
        ({ split_epoch = d.f_epoch; split_id = d.f_split } <: split) }

let can_finalize (st: state) (d: t_ShareLifecycleDriver) : bool =
  not st.st_rotation && st.st_epoch = d.f_epoch &&
  (match st.st_active <: Core_models.Option.t_Option split with
   | Core_models.Option.Option_None -> true
   | _ -> false) &&
  (match st.st_pending <: Core_models.Option.t_Option split with
   | Core_models.Option.Option_Some s ->
       s.split_epoch = d.f_epoch && s.split_id = d.f_split
   | Core_models.Option.Option_None -> false)

let finalize_into (st: state) : state =
  { st with st_active = st.st_pending; st_pending = Core_models.Option.Option_None }

let can_delete (st: state) (d: t_ShareLifecycleDriver) : bool =
  not st.st_rotation && st.st_epoch = d.f_epoch

let delete_into (st: state) : state =
  { st with st_active = Core_models.Option.Option_None;
            st_pending = Core_models.Option.Option_None }

let stage_state_ok (st: state) (d: t_ShareLifecycleDriver)
  : Lemma (requires state_ok st /\ can_stage st d)
          (ensures state_ok (stage_into st d)) = ()

let finalize_state_ok (st: state) (d: t_ShareLifecycleDriver)
  : Lemma (requires state_ok st /\ can_finalize st d)
          (ensures state_ok (finalize_into st)) = ()

let delete_state_ok (st: state) (d: t_ShareLifecycleDriver)
  : Lemma (requires state_ok st /\ can_delete st d)
          (ensures state_ok (delete_into st)) = ()

let freeze_state_ok (st: state) (rotation: bool)
  : Lemma (requires state_ok st)
          (ensures state_ok { st with st_rotation = rotation }) = ()

let rotate_state_ok (st: state)
  : Lemma (requires state_ok st)
          (ensures state_ok
            { st_epoch = st.st_epoch +. mk_i64 1; st_rotation = false;
              st_active = Core_models.Option.Option_None;
              st_pending = Core_models.Option.Option_None }) = ()

// ── Driver effect classifications ──────────────────────────────────────────

let released (e: t_AuthFinishEffect) : nat =
  match e <: t_AuthFinishEffect with
  | AuthFinishEffect_ReleaseGrant _ -> 1
  | _ -> 0

let promoted (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_PromoteStagedSplit _ -> 1
  | _ -> 0

let deleted (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_DeleteShare _ -> 1
  | _ -> 0

let read_count (e: t_ShareEffect) : nat =
  match e <: t_ShareEffect with
  | ShareEffect_ReadShare -> 1
  | _ -> 0

let proof_granted (e: t_ProofRecoverEffect) : nat =
  match e <: t_ProofRecoverEffect with
  | ProofRecoverEffect_IssueGrant _ -> 1
  | _ -> 0

let proof_release (e: t_ProofRecoverEffect) : nat =
  b2n (proof_recover_effect_releases_share e)

let deleted_add (st: state) (e: t_AuthFinishEffect) : nat =
  if released e = 1
  then (match st.st_active <: Core_models.Option.t_Option split with
        | Core_models.Option.Option_None -> 1
        | _ -> 0)
  else 0

let superseded_add (st: state) (e: t_AuthFinishEffect) : nat =
  if released e = 1
  then (match st.st_active <: Core_models.Option.t_Option split with
        | Core_models.Option.Option_Some s ->
            if s.split_epoch = st.st_epoch then 0 else 1
        | Core_models.Option.Option_None -> 0)
  else 0

/// The possession-path effect language cannot release the server share.
let proof_effect_never_releases (e: t_ProofRecoverEffect)
  : Lemma (proof_release e = 0) =
  match e <: t_ProofRecoverEffect with
  | ProofRecoverEffect_CountAttempt -> ()
  | ProofRecoverEffect_ConsumeAttempt -> ()
  | ProofRecoverEffect_QueryAccount -> ()
  | ProofRecoverEffect_VerifyProof -> ()
  | ProofRecoverEffect_IssueGrant _ -> ()
  | ProofRecoverEffect_Complete -> ()
  | ProofRecoverEffect_Fail _ -> ()
  | ProofRecoverEffect_Idle -> ()

/// A WebAuthn release is emitted only by a live-account observation.
let auth_release_only_account (d: t_AuthFinishDriver) (e: t_AuthFinishEvent)
  : Lemma
    (requires (auth_finish_state_is_sound d))
    (ensures (
      match (step_auth_finish d e).f_effect <: t_AuthFinishEffect with
      | AuthFinishEffect_ReleaseGrant _ ->
          (match e <: t_AuthFinishEvent with
           | AuthFinishEvent_AccountObserved _ -> True
           | _ -> False)
      | _ -> True)) =
  match e <: t_AuthFinishEvent with
  | AuthFinishEvent_AttemptCounted _ -> ()
  | AuthFinishEvent_ContextObserved _ -> ()
  | AuthFinishEvent_AttemptConsumed _ -> ()
  | AuthFinishEvent_AssertionObserved _ -> ()
  | AuthFinishEvent_CredentialUpdated _ -> ()
  | AuthFinishEvent_AccountObserved _ -> ()
  | AuthFinishEvent_ShareObserved _ -> ()
  | AuthFinishEvent_GrantStored _ -> ()

/// The live-account observation the composition delivers to the WebAuthn
/// driver is derived from the shared state.
let auth_account_observation (st: state) : t_AuthAccountObservation =
  { f_account_present = true;
    f_account_epoch_active = not st.st_rotation;
    f_share_present = current_share st;
    f_stored_credential_matches = true;
    f_stored_epoch = Core_models.Option.Option_Some st.st_epoch }

/// If the derived live-account observation authorizes a release, the shared
/// state still holds the current share. This is the load-bearing link between
/// the extracted WebAuthn release decision and the lifecycle writers.
let auth_release_implies_current
      (d: t_AuthFinishDriver) (st: state)
  : Lemma
    (requires (
      auth_finish_state_is_sound d /\
      (match (step_auth_finish d
                (AuthFinishEvent_AccountObserved (auth_account_observation st))).f_effect
             <: t_AuthFinishEffect with
       | AuthFinishEffect_ReleaseGrant _ -> True
       | _ -> False)))
    (ensures (current_share st)) =
  let obs = auth_account_observation st in
  let t = step_auth_finish d (AuthFinishEvent_AccountObserved obs) in
  assert (match t.f_effect <: t_AuthFinishEffect with
          | AuthFinishEffect_ReleaseGrant _ -> True
          | _ -> False);
  assert (auth_finish_effect_is_sound t.f_driver t.f_effect);
  assert (t.f_driver.f_share_present)

// ── Request lists ──────────────────────────────────────────────────────────

let rec update_share (l: list t_ShareLifecycleDriver) (i: nat)
                     (x: t_ShareLifecycleDriver)
  : Tot (list t_ShareLifecycleDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update_share t (i - 1) x

let rec update_auth (l: list t_AuthFinishDriver) (i: nat) (x: t_AuthFinishDriver)
  : Tot (list t_AuthFinishDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update_auth t (i - 1) x

let rec update_proof (l: list t_ProofRecoverDriver) (i: nat) (x: t_ProofRecoverDriver)
  : Tot (list t_ProofRecoverDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update_proof t (i - 1) x

// ── The shared world and arbitrary schedules ───────────────────────────────

noeq type world = {
  st: state;
  share_reqs: list t_ShareLifecycleDriver;
  auth_reqs: list t_AuthFinishDriver;
  proof_reqs: list t_ProofRecoverDriver;
  releases: nat;
  stale_releases: nat;
  superseded_releases: nat;
  publications: nat;
  deletes: nat;
  reads: nat;
  proof_grants: nat;
  proof_releases: nat;
}

type action =
  | ShareSpawn : t_ShareRequestObservation -> action
  | Write : nat -> action
  | ShareAccount : nat -> action
  | ReadNow : nat -> action
  | AuthSpawn : action
  | AuthCount : nat -> action
  | AuthContext : nat -> action
  | AuthConsume : nat -> t_AuthAttemptConsumptionObservation -> action
  | AuthVerify : nat -> t_AssertionObservation -> action
  | AuthAccount : nat -> action
  | AuthShare : nat -> t_ShareDecodeObservation -> action
  | AuthStore : nat -> Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation -> action
  | ProofSpawn : action
  | ProofEvent : nat -> t_ProofRecoverEvent -> action
  | Rotate : action
  | Freeze : action
  | Unfreeze : action

let update_share_req (w: world) (i: nat) (d: t_ShareLifecycleDriver) : world =
  { w with share_reqs = update_share w.share_reqs i d }

let deliver_share (w: world) (i: nat{i < FStar.List.Tot.length w.share_reqs})
                  (e: t_ShareEvent) (st: state) : world =
  let d = FStar.List.Tot.index w.share_reqs i in
  if share_lifecycle_state_is_sound d
  then
    let t = step_share_lifecycle d e in
    { w with st = st;
             share_reqs = update_share w.share_reqs i t.f_driver;
             publications = w.publications + promoted t.f_effect;
             deletes = w.deletes + deleted t.f_effect;
             reads = w.reads + read_count t.f_effect }
  else { w with st = st }

let deliver_auth (w: world) (i: nat{i < FStar.List.Tot.length w.auth_reqs})
                 (e: t_AuthFinishEvent) (st: state) : world =
  let d = FStar.List.Tot.index w.auth_reqs i in
  if auth_finish_state_is_sound d
  then
    let t = step_auth_finish d e in
    { w with st = st;
             auth_reqs = update_auth w.auth_reqs i t.f_driver;
             releases = w.releases + released t.f_effect;
             stale_releases = w.stale_releases + deleted_add w.st t.f_effect;
             superseded_releases =
               w.superseded_releases + superseded_add w.st t.f_effect }
  else { w with st = st }

let deliver_proof (w: world) (i: nat{i < FStar.List.Tot.length w.proof_reqs})
                  (e: t_ProofRecoverEvent) (st: state) : world =
  let d = FStar.List.Tot.index w.proof_reqs i in
  if proof_recover_state_is_sound d
  then
    let t = step_proof_recover d e in
    { w with st = st;
             proof_reqs = update_proof w.proof_reqs i t.f_driver;
             proof_grants = w.proof_grants + proof_granted t.f_effect;
             proof_releases = w.proof_releases + proof_release t.f_effect }
  else { w with st = st }

let stage_account_observation (st: state) (d: t_ShareLifecycleDriver)
  : t_StageAccountObservation =
  let matches = (match st.st_active <: Core_models.Option.t_Option split with
                 | Core_models.Option.Option_Some s ->
                     s.split_epoch = d.f_epoch && s.split_id = d.f_split
                 | Core_models.Option.Option_None -> false) in
  { f_account_present = true;
    f_stored_epoch = Core_models.Option.Option_Some st.st_epoch;
    f_rotation_active = st.st_rotation;
    f_active_share_matches = matches;
    f_active_split_matches = matches }

let finalize_account_observation (st: state) (d: t_ShareLifecycleDriver)
  : t_FinalizeAccountObservation =
  { f_account_present = true;
    f_stored_epoch = Core_models.Option.Option_Some st.st_epoch;
    f_rotation_active = st.st_rotation;
    f_active_split_matches =
      (match st.st_active <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_Some s ->
           s.split_epoch = d.f_epoch && s.split_id = d.f_split
       | Core_models.Option.Option_None -> false) }

let read_observation (st: state) : t_ReadObservation =
  { f_account_present = true;
    f_share_present =
      (match st.st_active <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_Some _ -> true
       | Core_models.Option.Option_None -> false) }

let auth_context_observation (st: state) : t_AuthFinishContextObservation =
  { f_account_present = true;
    f_share_present = current_share st;
    f_credential = StoredCredentialObservation_Present;
    f_attempt_id_present = true }

let write_action (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.share_reqs
  then
    let d = FStar.List.Tot.index w.share_reqs i in
    if share_lifecycle_state_is_sound d
    then
      match d.f_stage <: t_ShareStage with
      | ShareStage_Stage ->
          if can_stage w.st d
          then deliver_share w i (ShareEvent_StageUpdate StageUpdateObservation_Staged)
                 (stage_into w.st d)
          else deliver_share w i (ShareEvent_StageUpdate StageUpdateObservation_NotStaged)
                 w.st
      | ShareStage_Finalize ->
          if can_finalize w.st d
          then deliver_share w i
                 (ShareEvent_FinalizeUpdate FinalizeUpdateObservation_Promoted)
                 (finalize_into w.st)
          else deliver_share w i
                 (ShareEvent_FinalizeUpdate FinalizeUpdateObservation_NotPromoted)
                 w.st
      | ShareStage_Delete ->
          if can_delete w.st d
          then deliver_share w i
                 (ShareEvent_DeleteUpdate DeleteUpdateObservation_Deleted)
                 (delete_into w.st)
          else deliver_share w i
                 (ShareEvent_DeleteUpdate DeleteUpdateObservation_NotDeleted)
                 w.st
      | _ -> w
    else w
  else w

let share_account_action (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.share_reqs
  then
    let d = FStar.List.Tot.index w.share_reqs i in
    if share_lifecycle_state_is_sound d
    then
      match d.f_stage <: t_ShareStage with
      | ShareStage_StageAccount ->
          deliver_share w i
            (ShareEvent_StageAccount (stage_account_observation w.st d)) w.st
      | ShareStage_FinalizeAccount ->
          deliver_share w i
            (ShareEvent_FinalizeAccount (finalize_account_observation w.st d)) w.st
      | _ -> w
    else w
  else w

let read_action (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.share_reqs
  then
    let d = FStar.List.Tot.index w.share_reqs i in
    if share_lifecycle_state_is_sound d
    then
      match d.f_stage <: t_ShareStage with
      | ShareStage_Read ->
          deliver_share w i (ShareEvent_ReadObserved (read_observation w.st)) w.st
      | _ -> w
    else w
  else w

let auth_account_action (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.auth_reqs
  then
    let d = FStar.List.Tot.index w.auth_reqs i in
    if auth_finish_state_is_sound d
    then
      match d.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Account ->
          deliver_auth w i
            (AuthFinishEvent_AccountObserved (auth_account_observation w.st)) w.st
      | _ -> w
    else w
  else w

let world_step (w: world) (a: action) : world =
  match a with
  | ShareSpawn obs ->
      let t = begin_share_lifecycle obs in
      { w with share_reqs = t.f_driver :: w.share_reqs;
               publications = w.publications + promoted t.f_effect;
               deletes = w.deletes + deleted t.f_effect;
               reads = w.reads + read_count t.f_effect }
  | Write i -> write_action w i
  | ShareAccount i -> share_account_action w i
  | ReadNow i -> read_action w i
  | AuthSpawn -> { w with auth_reqs = (begin_auth_finish ()).f_driver :: w.auth_reqs }
  | AuthCount i ->
      if i < FStar.List.Tot.length w.auth_reqs
      then deliver_auth w i
             (AuthFinishEvent_AttemptCounted Vela_recovery_policy.Webauthn_driver.AttemptBudgetObservation_Admitted) w.st
      else w
  | AuthContext i ->
      if i < FStar.List.Tot.length w.auth_reqs
      then deliver_auth w i
             (AuthFinishEvent_ContextObserved (auth_context_observation w.st)) w.st
      else w
  | AuthConsume i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then deliver_auth w i (AuthFinishEvent_AttemptConsumed obs) w.st
      else w
  | AuthVerify i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then deliver_auth w i (AuthFinishEvent_AssertionObserved obs) w.st
      else w
  | AuthAccount i -> auth_account_action w i
  | AuthShare i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then deliver_auth w i (AuthFinishEvent_ShareObserved obs) w.st
      else w
  | AuthStore i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then deliver_auth w i (AuthFinishEvent_GrantStored obs) w.st
      else w
  | ProofSpawn -> { w with proof_reqs = (begin_proof_recover ()).f_driver :: w.proof_reqs }
  | ProofEvent i ev ->
      if i < FStar.List.Tot.length w.proof_reqs
      then deliver_proof w i ev w.st
      else w
  | Rotate ->
      { w with st =
          { st_epoch = w.st.st_epoch +. mk_i64 1; st_rotation = false;
            st_active = Core_models.Option.Option_None;
            st_pending = Core_models.Option.Option_None } }
  | Freeze -> { w with st = { w.st with st_rotation = true } }
  | Unfreeze -> { w with st = { w.st with st_rotation = false } }

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Invariant: no stale release and a single coherent current split ────────

let inv (w: world) : prop =
  state_ok w.st /\
  w.stale_releases = 0 /\
  w.superseded_releases = 0 /\
  w.proof_releases = 0

let deliver_share_state (w: world) (i: nat{i < FStar.List.Tot.length w.share_reqs})
                        (e: t_ShareEvent) (st: state) : Lemma
  (requires state_ok st)
  (ensures state_ok (deliver_share w i e st).st) = ()

let deliver_auth_state (w: world) (i: nat{i < FStar.List.Tot.length w.auth_reqs})
                       (e: t_AuthFinishEvent) (st: state) : Lemma
  (requires state_ok st)
  (ensures state_ok (deliver_auth w i e st).st) = ()

let deliver_proof_state (w: world) (i: nat{i < FStar.List.Tot.length w.proof_reqs})
                        (e: t_ProofRecoverEvent) (st: state) : Lemma
  (requires state_ok st)
  (ensures state_ok (deliver_proof w i e st).st) = ()

let state_ok_intro (st: state) : Lemma (requires state_ok st) (ensures state_ok st) = ()

let write_inv (w: world) (i: nat)
  : Lemma (requires inv w) (ensures inv (write_action w i)) =
  state_ok_intro w.st;
  if i < FStar.List.Tot.length w.share_reqs
  then begin
    let d = FStar.List.Tot.index w.share_reqs i in
    if share_lifecycle_state_is_sound d
    then begin
      match d.f_stage <: t_ShareStage with
      | ShareStage_Stage ->
          if can_stage w.st d
          then (stage_state_ok w.st d;
                deliver_share_state w i
                  (ShareEvent_StageUpdate StageUpdateObservation_Staged)
                  (stage_into w.st d))
          else deliver_share_state w i
                 (ShareEvent_StageUpdate StageUpdateObservation_NotStaged) w.st
      | ShareStage_Finalize ->
          if can_finalize w.st d
          then (finalize_state_ok w.st d;
                deliver_share_state w i
                  (ShareEvent_FinalizeUpdate FinalizeUpdateObservation_Promoted)
                  (finalize_into w.st))
          else deliver_share_state w i
                 (ShareEvent_FinalizeUpdate FinalizeUpdateObservation_NotPromoted) w.st
      | ShareStage_Delete ->
          if can_delete w.st d
          then (delete_state_ok w.st d;
                deliver_share_state w i
                  (ShareEvent_DeleteUpdate DeleteUpdateObservation_Deleted)
                  (delete_into w.st))
          else deliver_share_state w i
                 (ShareEvent_DeleteUpdate DeleteUpdateObservation_NotDeleted) w.st
      | _ -> ()
    end
  end

let share_account_inv (w: world) (i: nat)
  : Lemma (requires inv w) (ensures inv (share_account_action w i)) =
  if i < FStar.List.Tot.length w.share_reqs
  then begin
    let d = FStar.List.Tot.index w.share_reqs i in
    if share_lifecycle_state_is_sound d
    then begin
      match d.f_stage <: t_ShareStage with
      | ShareStage_StageAccount ->
          deliver_share_state w i
            (ShareEvent_StageAccount (stage_account_observation w.st d)) w.st
      | ShareStage_FinalizeAccount ->
          deliver_share_state w i
            (ShareEvent_FinalizeAccount (finalize_account_observation w.st d)) w.st
      | _ -> ()
    end
  end

let read_inv (w: world) (i: nat)
  : Lemma (requires inv w) (ensures inv (read_action w i)) =
  if i < FStar.List.Tot.length w.share_reqs
  then begin
    let d = FStar.List.Tot.index w.share_reqs i in
    if share_lifecycle_state_is_sound d
    then begin
      match d.f_stage <: t_ShareStage with
      | ShareStage_Read ->
          deliver_share_state w i
            (ShareEvent_ReadObserved (read_observation w.st)) w.st
      | _ -> ()
    end
  end

let non_account_no_release (w: world) (i: nat) (e: t_AuthFinishEvent)
  : Lemma
    (requires (
      inv w /\ i < FStar.List.Tot.length w.auth_reqs /\
      (match e <: t_AuthFinishEvent with
       | AuthFinishEvent_AccountObserved _ -> False
       | _ -> True)))
    (ensures (
      let delivered = deliver_auth w i e w.st in
      delivered.stale_releases = w.stale_releases /\
      delivered.superseded_releases = w.superseded_releases)) =
  let d = FStar.List.Tot.index w.auth_reqs i in
  if auth_finish_state_is_sound d
  then begin
    auth_release_only_account d e;
    assert (released (step_auth_finish d e).f_effect = 0);
    assert (deleted_add w.st (step_auth_finish d e).f_effect = 0);
    assert (superseded_add w.st (step_auth_finish d e).f_effect = 0)
  end

let auth_account_inv (w: world) (i: nat)
  : Lemma (requires inv w) (ensures inv (auth_account_action w i)) =
  if i < FStar.List.Tot.length w.auth_reqs
  then begin
    let d = FStar.List.Tot.index w.auth_reqs i in
    if auth_finish_state_is_sound d
    then begin
      match d.f_stage <: t_AuthFinishStage with
      | AuthFinishStage_Account ->
          let e = AuthFinishEvent_AccountObserved (auth_account_observation w.st) in
          if released (step_auth_finish d e).f_effect = 1
          then begin
            auth_release_implies_current d w.st;
            assert (current_share w.st);
            assert (deleted_add w.st (step_auth_finish d e).f_effect = 0);
            assert (superseded_add w.st (step_auth_finish d e).f_effect = 0)
          end else begin
            assert (deleted_add w.st (step_auth_finish d e).f_effect = 0);
            assert (superseded_add w.st (step_auth_finish d e).f_effect = 0)
          end
      | _ -> ()
    end
  end

let proof_inv (w: world) (i: nat) (ev: t_ProofRecoverEvent)
  : Lemma
    (requires (inv w /\ i < FStar.List.Tot.length w.proof_reqs))
    (ensures (deliver_proof w i ev w.st).proof_releases = 0) =
  let d = FStar.List.Tot.index w.proof_reqs i in
  if proof_recover_state_is_sound d
  then proof_effect_never_releases (step_proof_recover d ev).f_effect

/// Every action preserves the invariant.
let world_step_inv (w: world) (a: action)
  : Lemma (requires inv w) (ensures inv (world_step w a)) =
  match a with
  | ShareSpawn _ -> ()
  | Write i -> write_inv w i
  | ShareAccount i -> share_account_inv w i
  | ReadNow i -> read_inv w i
  | AuthSpawn -> ()
  | AuthCount i ->
      if i < FStar.List.Tot.length w.auth_reqs
      then non_account_no_release w i
             (AuthFinishEvent_AttemptCounted Vela_recovery_policy.Webauthn_driver.AttemptBudgetObservation_Admitted)
      else ()
  | AuthContext i ->
      if i < FStar.List.Tot.length w.auth_reqs
      then non_account_no_release w i
             (AuthFinishEvent_ContextObserved (auth_context_observation w.st))
      else ()
  | AuthConsume i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then non_account_no_release w i (AuthFinishEvent_AttemptConsumed obs)
      else ()
  | AuthVerify i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then non_account_no_release w i (AuthFinishEvent_AssertionObserved obs)
      else ()
  | AuthAccount i -> auth_account_inv w i
  | AuthShare i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then non_account_no_release w i (AuthFinishEvent_ShareObserved obs)
      else ()
  | AuthStore i obs ->
      if i < FStar.List.Tot.length w.auth_reqs
      then non_account_no_release w i (AuthFinishEvent_GrantStored obs)
      else ()
  | ProofSpawn -> ()
  | ProofEvent i ev ->
      if i < FStar.List.Tot.length w.proof_reqs
      then proof_inv w i ev
      else ()
  | Rotate -> rotate_state_ok w.st
  | Freeze -> freeze_state_ok w.st true
  | Unfreeze -> freeze_state_ok w.st false

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires inv w) (ensures inv (run_world w schedule))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      world_step_inv w a;
      run_world_inv (world_step w a) rest

let initial : world =
  { st = { st_epoch = mk_i64 1; st_rotation = false;
           st_active = Core_models.Option.Option_None;
           st_pending = Core_models.Option.Option_None };
    share_reqs = []; auth_reqs = []; proof_reqs = [];
    releases = 0; stale_releases = 0; superseded_releases = 0;
    publications = 0; deletes = 0; reads = 0; proof_grants = 0;
    proof_releases = 0 }

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem: whatever the interleaving, no WebAuthn release is
/// authorized for a deleted or superseded share, at most one current split
/// exists, and the possession path never releases the share.
let shared_share_lifecycle (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      active_count w.st <= 1 /\
      state_ok w.st /\
      w.stale_releases = 0 /\
      w.superseded_releases = 0 /\
      w.proof_releases = 0) =
  initial_inv ();
  run_world_inv initial schedule

// ── Non-vacuity witnesses ──────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let active_actor : t_ShareActorObservation =
  { f_authenticated = true; f_device_active = true; f_scoped_to_session_account = true }

let stage_request : t_ShareRequestObservation =
  { f_operation = ShareOperation_Stage; f_actor = active_actor;
    f_declared_epoch = mk_i64 1; f_split_id_present = true; f_share_present = true;
    f_device_authority = true; f_split = mk_i64 7 }

let finalize_request : t_ShareRequestObservation =
  { stage_request with f_operation = ShareOperation_Finalize }

let delete_request : t_ShareRequestObservation =
  { stage_request with f_operation = ShareOperation_Delete; f_split = mk_i64 0 }

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

let p0 = initial
let p1 = world_step p0 (ShareSpawn stage_request)
let p2 = world_step p1 (Write 0)
let p3 = world_step p2 (ShareSpawn finalize_request)
let p4 = world_step p3 (Write 0)

let publication_schedule : list action =
  [ ShareSpawn stage_request; Write 0; ShareSpawn finalize_request; Write 0 ]

let p4_ok ()
  : Lemma (
      p4.publications = 1 /\ p4.deletes = 0 /\
      (match p4.st.st_active <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_Some s ->
           s.split_epoch = mk_i64 1 && s.split_id = mk_i64 7
       | Core_models.Option.Option_None -> False)) = ()

/// A staged current split can be promoted into the single active split; the
/// publication counter is the finalize driver's own `PromoteStagedSplit`
/// decision.
let publication_is_reachable ()
  : Lemma (
      let w = run_world initial publication_schedule in
      w.publications = 1 /\ w.deletes = 0 /\
      (match w.st.st_active <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_Some s ->
           s.split_epoch = mk_i64 1 && s.split_id = mk_i64 7
       | Core_models.Option.Option_None -> False)) =
  run_cons p0 (ShareSpawn stage_request) [Write 0; ShareSpawn finalize_request; Write 0];
  run_cons p1 (Write 0) [ShareSpawn finalize_request; Write 0];
  run_cons p2 (ShareSpawn finalize_request) [Write 0];
  run_cons p3 (Write 0) [];
  run_nil p4;
  p4_ok ()

let d0 = initial
let d1 = world_step d0 (ShareSpawn stage_request)
let d2 = world_step d1 (Write 0)
let d3 = world_step d2 (ShareSpawn delete_request)
let d4 = world_step d3 (Write 0)

let delete_schedule : list action =
  [ ShareSpawn stage_request; Write 0; ShareSpawn delete_request; Write 0 ]

let d4_ok ()
  : Lemma (
      d4.deletes = 1 /\
      (match d4.st.st_active <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_None -> True
       | _ -> False) /\
      (match d4.st.st_pending <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_None -> True
       | _ -> False)) = ()

/// Delete removes the active share and the staged split in the same driver
/// decision, and the delete counter records that decision.
let delete_clears_share_and_pending ()
  : Lemma (
      let w = run_world initial delete_schedule in
      w.deletes = 1 /\
      (match w.st.st_active <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_None -> True
       | _ -> False) /\
      (match w.st.st_pending <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_None -> True
       | _ -> False)) =
  run_cons d0 (ShareSpawn stage_request) [Write 0; ShareSpawn delete_request; Write 0];
  run_cons d1 (Write 0) [ShareSpawn delete_request; Write 0];
  run_cons d2 (ShareSpawn delete_request) [Write 0];
  run_cons d3 (Write 0) [];
  run_nil d4;
  d4_ok ()

let f0 = initial
let f1 = world_step f0 (ShareSpawn stage_request)
let f2 = world_step f1 (Write 0)
let f3 = world_step f2 Freeze
let f4 = world_step f3 (ShareSpawn finalize_request)
let f5 = world_step f4 (Write 0)

/// Freezing blocks the finalize update: the shared state keeps the candidate
/// pending and no active share becomes current.
let frozen_finalize_schedule : list action =
  [ ShareSpawn stage_request; Write 0; Freeze;
    ShareSpawn finalize_request; Write 0 ]

let freezing_blocks_finalize ()
  : Lemma (
      let w = run_world initial frozen_finalize_schedule in
      (match w.st.st_active <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_None -> True
       | _ -> False) /\
      (match w.st.st_pending <: Core_models.Option.t_Option split with
       | Core_models.Option.Option_Some s -> s.split_id = mk_i64 7
       | Core_models.Option.Option_None -> False)) =
  run_cons f0 (ShareSpawn stage_request) [Write 0; Freeze;
                                         ShareSpawn finalize_request; Write 0];
  run_cons f1 (Write 0) [Freeze; ShareSpawn finalize_request; Write 0];
  run_cons f2 Freeze [ShareSpawn finalize_request; Write 0];
  run_cons f3 (ShareSpawn finalize_request) [Write 0];
  run_cons f4 (Write 0) [];
  run_nil f5

#pop-options
