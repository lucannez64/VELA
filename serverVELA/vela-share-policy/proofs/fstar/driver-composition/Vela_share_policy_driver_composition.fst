module Vela_share_policy_driver_composition

/// Concurrent composition of the *extracted* sharing driver.
///
/// One linked share and one recipient inbox are shared by any number of
/// requests, each running its own `Vela_share_policy.Driver` value. A schedule
/// is an arbitrary list of actions: spawn a send/update/revoke/inbox-delete/EK
/// request, commit the guarded effect, or deliver the cleanup observation.
///
/// The world abstracts the effects the handler performs:
///
/// - the guarded `UPDATE shared_items ... WHERE sender_user_id = ? AND
///   revoked = 0` is one atomic step: the row is observed and the guarded
///   write is decided in the same action, exactly like the template models
///   `get_del`;
/// - the guarded revoke likewise atomically observes liveness, sets
///   `revoked = 1` and removes the pending inbox row;
/// - the recipient-scoped inbox `DELETE` atomically checks
///   `recipient_user_id = ?`;
/// - the send transaction atomically re-checks the recipient item quota
///   before it counts the new inbox row.
///
/// Theorem: for every schedule, the inbox count never exceeds a configured
/// quota, a non-sender never changes the link, and after a committed revoke no
/// later update commits. Assumptions (not proved here): the SQL statements are
/// linearizable, the handler performs exactly the effect the driver returns,
/// and the driver's row observations are supplied by those SQL statements.
/// SQL guard semantics and observation origins remain outside this module.
///
/// This module deliberately does not import the per-request lemma module: the
/// composition is a statement about the extracted driver alone. That also
/// makes the mutation check fail here, not in an unrelated lemma.

open FStar.Mul

open Core_models
open Vela_share_policy
open Vela_share_policy.Driver

let b2n (b: bool) : nat = if b then 1 else 0

// ── Request lists ──────────────────────────────────────────────────────────

let rec update (l: list t_ShareDriver) (i: nat) (x: t_ShareDriver)
  : Tot (list t_ShareDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec all_sound (l: list t_ShareDriver) : bool =
  match l with
  | [] -> true
  | d :: r -> share_state_is_sound d && all_sound r

let all_sound_cons (d: t_ShareDriver) (l: list t_ShareDriver)
  : Lemma (all_sound (d :: l) = (share_state_is_sound d && all_sound l)) = ()

let rec index_sound (l: list t_ShareDriver) (i: nat)
  : Lemma
    (requires (all_sound l /\ i < FStar.List.Tot.length l))
    (ensures (share_state_is_sound (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else index_sound t (i - 1)

let rec update_sound (l: list t_ShareDriver) (i: nat) (x: t_ShareDriver)
  : Lemma
    (requires (all_sound l /\ share_state_is_sound x))
    (ensures (all_sound (update l i x)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_sound t (i - 1) x

let rec update_length (l: list t_ShareDriver) (i: nat) (x: t_ShareDriver)
  : Lemma (FStar.List.Tot.length (update l i x) = FStar.List.Tot.length l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_length t (i - 1) x

// ── Stage predicates ───────────────────────────────────────────────────────

let is_send (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_SendInsert -> true
  | _ -> false

let is_update_observe (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkUpdateObserve -> true
  | _ -> false

let is_update_apply (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkUpdateApply -> true
  | _ -> false

let is_revoke_observe (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkRevokeObserve -> true
  | _ -> false

let is_revoke_apply (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkRevokeApply -> true
  | _ -> false

let is_cleanup (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_LinkCleanup -> true
  | _ -> false

let is_inbox (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_InboxDelete -> true
  | _ -> false

let is_ek_register (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_EkRegister -> true
  | _ -> false

let is_ek_observe (d: t_ShareDriver) : bool =
  match d.f_stage <: t_ShareStage with
  | ShareStage_EkObserve -> true
  | _ -> false

// ── Actors, link state and the shared world ────────────────────────────────

type actor =
  | Actor_Sender
  | Actor_Recipient
  | Actor_ThirdParty

type link_state =
  | Link_Absent
  | Link_Live
  | Link_Revoked

noeq type world = {
  w_link: link_state;
  w_inbox_item: bool;
  w_inbox_count: nat;
  w_item_quota: option nat;
  w_reqs: list t_ShareDriver;
  /// Successful link changes (update or revoke commits).
  w_link_changes: nat;
  /// Successful update commits, used by the revocation-finality theorem.
  w_update_commits: nat;
  /// Link changes committed by a non-sender. The invariant keeps this at zero.
  w_non_sender_changes: nat;
}

/// The observation a guard-read produces for `actor` at the current world.
let link_obs (w: world) (actor: actor) : t_LinkMutationObservation =
  {
    f_item_present =
      (match w.w_link with
       | Link_Absent -> false
       | _ -> true);
    f_caller_matches_sender =
      (match actor with
       | Actor_Sender -> true
       | _ -> false);
    f_item_not_revoked =
      (match w.w_link with
       | Link_Live -> true
       | _ -> false);
  }

let valid_update_start : t_LinkUpdateStartObservation =
  { f_decode_failed = false; f_capsule_len = mk_i64 1 }

let valid_ek_device : t_EkDeviceObservation =
  {
    f_registration = {
      Vela_share_policy.f_ek_len = Vela_share_policy.v_SHARE_EK_LEN;
      Vela_share_policy.f_signature_verified = true;
      Vela_share_policy.f_device_row_present = true;
      Vela_share_policy.f_device_user_matches = true;
      Vela_share_policy.f_device_active = true;
      Vela_share_policy.f_signed_at_is_fresher = true;
      Vela_share_policy.f_binding_exists = false;
    };
    f_stored_identity_vk_decode_failed = false;
    f_signature_decode_failed = false;
  }

let rows_committed : t_RowsObservation = { f_rows = mk_u64 1 }
let rows_missing : t_RowsObservation = { f_rows = mk_u64 0 }
let cleanup_ok : t_CleanupObservation = { f_storage_failed = false }

/// The shared invariant: every live request is sound, the inbox count fits
/// any configured quota, a present item contributes at least one counted row,
/// and no non-sender has ever changed the link.
let inv (w: world) : prop =
  all_sound w.w_reqs /\
  (match w.w_item_quota with
   | Some quota -> w.w_inbox_count <= quota
   | None -> True) /\
  (w.w_inbox_item = true ==> w.w_inbox_count >= 1) /\
  w.w_non_sender_changes = 0

/// Deliver one event to request `i` and keep every other world component.
let deliver (w: world) (i: nat) (e: t_ShareEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs then
    let d = FStar.List.Tot.index w.w_reqs i in
    // `inv` makes every reachable request sound; the guard only discharges
    // `step`'s precondition.
    if share_state_is_sound d then
      { w with w_reqs = update w.w_reqs i (step d e).f_driver }
    else w
  else w

let deliver_inv (w: world) (i: nat) (e: t_ShareEvent)
  : Lemma
    (requires (inv w /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures (inv (deliver w i e))) =
  let d = FStar.List.Tot.index w.w_reqs i in
  index_sound w.w_reqs i;
  assert (share_state_is_sound d = true);
  update_sound w.w_reqs i (step d e).f_driver

let deliver_length (w: world) (i: nat) (e: t_ShareEvent)
  : Lemma (FStar.List.Tot.length (deliver w i e).w_reqs =
           FStar.List.Tot.length w.w_reqs) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if share_state_is_sound d then
      update_length w.w_reqs i (step d e).f_driver
  end

type action =
  | SpawnSend : t_SendRequestObservation -> action
  | CommitSend : nat -> action
  | SpawnUpdate : action
  | SpawnRevoke : action
  | CommitUpdate : nat -> actor -> action
  | CommitRevoke : nat -> actor -> action
  | CleanupDone : nat -> t_CleanupObservation -> action
  | SpawnInboxDelete : action
  | CommitInboxDelete : nat -> actor -> action
  | SpawnEk : t_EkRegistrationStartObservation -> action
  | CommitEk : nat -> action

let world_step (w: world) (a: action) : world =
  match a with
  | SpawnSend obs ->
      { w with w_reqs = (begin_send obs).f_driver :: w.w_reqs }
  | SpawnUpdate ->
      { w with w_reqs = (begin_link_update valid_update_start).f_driver :: w.w_reqs }
  | SpawnRevoke ->
      { w with w_reqs = (begin_link_revoke ()).f_driver :: w.w_reqs }
  | SpawnInboxDelete ->
      { w with w_reqs = (begin_inbox_delete ()).f_driver :: w.w_reqs }
  | SpawnEk obs ->
      { w with w_reqs = (begin_ek_registration obs).f_driver :: w.w_reqs }
  | CommitSend i ->
      if i < FStar.List.Tot.length w.w_reqs then
        let d = FStar.List.Tot.index w.w_reqs i in
        if is_send d && share_state_is_sound d then
          let fits =
            (match w.w_item_quota with
             | Some quota -> w.w_inbox_count + 1 <= quota
             | None -> true)
          in
          if fits then
            let w1 = { w with w_inbox_count = w.w_inbox_count + 1 } in
            deliver w1 i (ShareEvent_SendResult SendResultObservation_Committed)
          else
            deliver w i (ShareEvent_SendResult SendResultObservation_CommitConflict)
        else w
      else w
  | CommitUpdate i actor ->
      if i < FStar.List.Tot.length w.w_reqs then
        let d = FStar.List.Tot.index w.w_reqs i in
        if is_update_observe d && share_state_is_sound d then
          let t = step d (ShareEvent_LinkObserved (link_obs w actor)) in
          if (match t.f_effect <: t_ShareEffect with
              | ShareEffect_UpdateLinkedItem _ -> true
              | _ -> false)
          then
            if actor = Actor_Sender then
              let t2 = step t.f_driver (ShareEvent_Mutated rows_committed) in
              { w with
                w_reqs = update w.w_reqs i t2.f_driver;
                w_link_changes = w.w_link_changes + 1;
                w_update_commits = w.w_update_commits + 1 }
            else
              let t2 = step t.f_driver (ShareEvent_Mutated rows_missing) in
              { w with w_reqs = update w.w_reqs i t2.f_driver }
          else
            { w with w_reqs = update w.w_reqs i t.f_driver }
        else w
      else w
  | CommitRevoke i actor ->
      if i < FStar.List.Tot.length w.w_reqs then
        let d = FStar.List.Tot.index w.w_reqs i in
        if is_revoke_observe d && share_state_is_sound d then
          let t = step d (ShareEvent_LinkObserved (link_obs w actor)) in
          if (match t.f_effect <: t_ShareEffect with
              | ShareEffect_RevokeLinkedItem -> true
              | _ -> false)
          then
            if actor = Actor_Sender then
              let t2 = step t.f_driver (ShareEvent_Mutated rows_committed) in
              { w with
                w_reqs = update w.w_reqs i t2.f_driver;
                w_link = Link_Revoked;
                w_inbox_item = false;
                w_inbox_count =
                  (if w.w_inbox_item then
                     (if w.w_inbox_count > 0 then w.w_inbox_count - 1 else 0)
                   else w.w_inbox_count);
                w_link_changes = w.w_link_changes + 1 }
            else
              let t2 = step t.f_driver (ShareEvent_Mutated rows_missing) in
              { w with w_reqs = update w.w_reqs i t2.f_driver }
          else
            { w with w_reqs = update w.w_reqs i t.f_driver }
        else w
      else w
  | CleanupDone i obs ->
      if i < FStar.List.Tot.length w.w_reqs then
        let d = FStar.List.Tot.index w.w_reqs i in
        if is_cleanup d && share_state_is_sound d then
          deliver w i (ShareEvent_Cleaned obs)
        else w
      else w
  | CommitInboxDelete i actor ->
      if i < FStar.List.Tot.length w.w_reqs then
        let d = FStar.List.Tot.index w.w_reqs i in
        if is_inbox d && share_state_is_sound d then
          if actor = Actor_Recipient && w.w_inbox_item then
            let w1 =
              { w with
                w_inbox_item = false;
                w_inbox_count =
                  (if w.w_inbox_count > 0 then w.w_inbox_count - 1 else 0) }
            in
            deliver w1 i (ShareEvent_Mutated rows_committed)
          else
            deliver w i (ShareEvent_Mutated rows_missing)
        else w
      else w
  | CommitEk i ->
      if i < FStar.List.Tot.length w.w_reqs then
        let d = FStar.List.Tot.index w.w_reqs i in
        if is_ek_observe d && share_state_is_sound d then
          let t = step d (ShareEvent_EkObserved valid_ek_device) in
          if (match t.f_effect <: t_ShareEffect with
              | ShareEffect_UpdateShareEk _ -> true
              | _ -> false)
          then
            let t2 = step t.f_driver (ShareEvent_Mutated rows_committed) in
            { w with w_reqs = update w.w_reqs i t2.f_driver }
          else
            { w with w_reqs = update w.w_reqs i t.f_driver }
        else w
      else w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

let initial : world =
  {
    w_link = Link_Live;
    w_inbox_item = true;
    w_inbox_count = 1;
    w_item_quota = Some 2;
    w_reqs = [];
    w_link_changes = 0;
    w_update_commits = 0;
    w_non_sender_changes = 0;
  }

// ── Invariant preservation by every extracted step ─────────────────────────

let spawn_send_inv (w: world) (obs: t_SendRequestObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (SpawnSend obs)))) =
  all_sound_cons (begin_send obs).f_driver w.w_reqs

let spawn_update_inv (w: world)
  : Lemma (requires (inv w)) (ensures (inv (world_step w SpawnUpdate))) =
  all_sound_cons (begin_link_update valid_update_start).f_driver w.w_reqs

let spawn_revoke_inv (w: world)
  : Lemma (requires (inv w)) (ensures (inv (world_step w SpawnRevoke))) =
  all_sound_cons (begin_link_revoke ()).f_driver w.w_reqs

let spawn_inbox_inv (w: world)
  : Lemma (requires (inv w)) (ensures (inv (world_step w SpawnInboxDelete))) =
  all_sound_cons (begin_inbox_delete ()).f_driver w.w_reqs

let spawn_ek_inv (w: world) (obs: t_EkRegistrationStartObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (SpawnEk obs)))) =
  all_sound_cons (begin_ek_registration obs).f_driver w.w_reqs

let commit_send_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (CommitSend i)))) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if is_send d && share_state_is_sound d then begin
      let fits =
        (match w.w_item_quota with
         | Some quota -> w.w_inbox_count + 1 <= quota
         | None -> true)
      in
      if fits then begin
        let w1 = { w with w_inbox_count = w.w_inbox_count + 1 } in
        assert (inv w1);
        deliver_inv w1 i (ShareEvent_SendResult SendResultObservation_Committed)
      end else begin
        deliver_inv w i (ShareEvent_SendResult SendResultObservation_CommitConflict)
      end
    end
  end

let commit_update_inv (w: world) (i: nat) (actor: actor)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (CommitUpdate i actor)))) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if is_update_observe d && share_state_is_sound d then begin
      let t = step d (ShareEvent_LinkObserved (link_obs w actor)) in
      if (match t.f_effect <: t_ShareEffect with
          | ShareEffect_UpdateLinkedItem _ -> true
          | _ -> false)
      then begin
        if actor = Actor_Sender then begin
          let t2 = step t.f_driver (ShareEvent_Mutated rows_committed) in
          let w2 =
            { w with
              w_reqs = update w.w_reqs i t2.f_driver;
              w_link_changes = w.w_link_changes + 1;
              w_update_commits = w.w_update_commits + 1 }
          in
          update_sound w.w_reqs i t2.f_driver;
          update_length w.w_reqs i t2.f_driver
        end else begin
          let t2 = step t.f_driver (ShareEvent_Mutated rows_missing) in
          let w2 = { w with w_reqs = update w.w_reqs i t2.f_driver } in
          update_sound w.w_reqs i t2.f_driver;
          update_length w.w_reqs i t2.f_driver
        end
      end else begin
        let w1 = { w with w_reqs = update w.w_reqs i t.f_driver } in
        update_sound w.w_reqs i t.f_driver;
        update_length w.w_reqs i t.f_driver
      end
    end
  end

let commit_revoke_inv (w: world) (i: nat) (actor: actor)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (CommitRevoke i actor)))) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if is_revoke_observe d && share_state_is_sound d then begin
      let t = step d (ShareEvent_LinkObserved (link_obs w actor)) in
      if (match t.f_effect <: t_ShareEffect with
          | ShareEffect_RevokeLinkedItem -> true
          | _ -> false)
      then begin
        if actor = Actor_Sender then begin
          let t2 = step t.f_driver (ShareEvent_Mutated rows_committed) in
          let w2 =
            { w with
              w_reqs = update w.w_reqs i t2.f_driver;
              w_link = Link_Revoked;
              w_inbox_item = false;
              w_inbox_count =
                (if w.w_inbox_item then
                   (if w.w_inbox_count > 0 then w.w_inbox_count - 1 else 0)
                 else w.w_inbox_count);
              w_link_changes = w.w_link_changes + 1 }
          in
          update_sound w.w_reqs i t2.f_driver;
          update_length w.w_reqs i t2.f_driver
        end else begin
          let t2 = step t.f_driver (ShareEvent_Mutated rows_missing) in
          let w2 = { w with w_reqs = update w.w_reqs i t2.f_driver } in
          update_sound w.w_reqs i t2.f_driver;
          update_length w.w_reqs i t2.f_driver
        end
      end else begin
        let w1 = { w with w_reqs = update w.w_reqs i t.f_driver } in
        update_sound w.w_reqs i t.f_driver;
        update_length w.w_reqs i t.f_driver
      end
    end
  end

let cleanup_inv (w: world) (i: nat) (obs: t_CleanupObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (CleanupDone i obs)))) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if is_cleanup d && share_state_is_sound d then
      deliver_inv w i (ShareEvent_Cleaned obs)
  end

let commit_inbox_inv (w: world) (i: nat) (actor: actor)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (CommitInboxDelete i actor)))) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if is_inbox d && share_state_is_sound d then begin
      if actor = Actor_Recipient && w.w_inbox_item then begin
        let w1 =
          { w with
            w_inbox_item = false;
            w_inbox_count =
              (if w.w_inbox_count > 0 then w.w_inbox_count - 1 else 0) }
        in
        assert (inv w1);
        deliver_inv w1 i (ShareEvent_Mutated rows_committed)
      end else begin
        deliver_inv w i (ShareEvent_Mutated rows_missing)
      end
    end
  end

let commit_ek_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (CommitEk i)))) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if is_ek_observe d && share_state_is_sound d then begin
      let t = step d (ShareEvent_EkObserved valid_ek_device) in
      if (match t.f_effect <: t_ShareEffect with
          | ShareEffect_UpdateShareEk _ -> true
          | _ -> false)
      then begin
        let t2 = step t.f_driver (ShareEvent_Mutated rows_committed) in
        let w2 = { w with w_reqs = update w.w_reqs i t2.f_driver } in
        update_sound w.w_reqs i t2.f_driver;
        update_length w.w_reqs i t2.f_driver
      end else begin
        let w1 = { w with w_reqs = update w.w_reqs i t.f_driver } in
        update_sound w.w_reqs i t.f_driver;
        update_length w.w_reqs i t.f_driver
      end
    end
  end

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | SpawnSend obs -> spawn_send_inv w obs
  | SpawnUpdate -> spawn_update_inv w
  | SpawnRevoke -> spawn_revoke_inv w
  | SpawnInboxDelete -> spawn_inbox_inv w
  | SpawnEk obs -> spawn_ek_inv w obs
  | CommitSend i -> commit_send_inv w i
  | CommitUpdate i actor -> commit_update_inv w i actor
  | CommitRevoke i actor -> commit_revoke_inv w i actor
  | CleanupDone i obs -> cleanup_inv w i obs
  | CommitInboxDelete i actor -> commit_inbox_inv w i actor
  | CommitEk i -> commit_ek_inv w i

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

/// Headline composition theorem: whatever the number of concurrent requests,
/// their interleaving and their observations, the inbox count never exceeds a
/// configured quota, a non-sender never changes the link, and every request in
/// the schedule remains sound.
let share_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_non_sender_changes = 0 /\
      (match w.w_item_quota with
       | Some quota -> w.w_inbox_count <= quota
       | None -> True)) =
  run_world_inv initial schedule

// ── Revocation is final ────────────────────────────────────────────────────

/// A revoked observation can never authorize an update: the extracted driver
/// calls the real `plan_link_mutation` on the observed revoked flag. This is
/// the step the mutation check removes.
let revoked_update_observation_rejected
      (d: t_ShareDriver)
      (w: world)
      (actor: actor)
  : Lemma
    (requires (
      share_state_is_sound d /\
      is_update_observe d /\
      w.w_link = Link_Revoked))
    (ensures (
      match (step d (ShareEvent_LinkObserved (link_obs w actor))).f_effect <: t_ShareEffect with
      | ShareEffect_UpdateLinkedItem _ -> False
      | _ -> True)) =
  ()

/// Once the link is revoked it stays revoked, and no later update commits.
let world_step_after_revoke (w: world) (a: action)
  : Lemma
    (requires (inv w /\ w.w_link = Link_Revoked))
    (ensures (
      (world_step w a).w_link = Link_Revoked /\
      (world_step w a).w_update_commits = w.w_update_commits)) =
  match a with
  | CommitUpdate i actor ->
      if i < FStar.List.Tot.length w.w_reqs then begin
        let d = FStar.List.Tot.index w.w_reqs i in
        if is_update_observe d && share_state_is_sound d then begin
          let t = step d (ShareEvent_LinkObserved (link_obs w actor)) in
          revoked_update_observation_rejected d w actor;
          // The rejected observation is not an update effect, so `world_step`
          // takes its no-commit branch and returns the request-list update of
          // the same world: link and commit counter are unchanged.
          assert ((world_step w (CommitUpdate i actor)).w_link = w.w_link);
          assert ((world_step w (CommitUpdate i actor)).w_update_commits =
                  w.w_update_commits)
        end
      end
  | CommitRevoke _ _ -> ()
  | _ -> ()

let rec no_update_after_revoke (w: world) (schedule: list action)
  : Lemma
    (requires (inv w /\ w.w_link = Link_Revoked))
    (ensures (
      (run_world w schedule).w_link = Link_Revoked /\
      (run_world w schedule).w_update_commits = w.w_update_commits))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      world_step_inv w a;
      world_step_after_revoke w a;
      no_update_after_revoke (world_step w a) rest

/// After any prefix that committed a revoke, every unbounded suffix keeps the
/// link revoked and commits no update.
let revocation_is_final (pre: list action) (suffix: list action)
  : Lemma (
      let w = run_world initial pre in
      w.w_link = Link_Revoked ==>
        (let v = run_world w suffix in
         v.w_link = Link_Revoked /\
         v.w_update_commits = w.w_update_commits)) =
  let w = run_world initial pre in
  run_world_inv initial pre;
  if w.w_link = Link_Revoked then
    no_update_after_revoke w suffix

/// An inbox delete only removes a row when the acting request is its
/// recipient. A third party's guarded `DELETE` reports zero affected rows.
let inbox_delete_only_by_recipient (w: world) (i: nat) (actor: actor)
  : Lemma
    (requires (inv w))
    (ensures (
      (world_step w (CommitInboxDelete i actor)).w_inbox_count < w.w_inbox_count ==>
      actor = Actor_Recipient)) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let d = FStar.List.Tot.index w.w_reqs i in
    if is_inbox d && share_state_is_sound d then begin
      if actor = Actor_Recipient && w.w_inbox_item then begin
        // The count only drops in the recipient branch.
        assert (actor = Actor_Recipient)
      end else begin
        assert ((world_step w (CommitInboxDelete i actor)).w_inbox_count = w.w_inbox_count)
      end
    end
  end

/// Only the sender's requests can change the link. The counter is incremented
/// only inside the `actor = Actor_Sender` branch, so it stays zero on every
/// schedule.
let only_sender_changes_link (schedule: list action)
  : Lemma ((run_world initial schedule).w_non_sender_changes = 0) =
  run_world_inv initial schedule

// ── Non-vacuity: reachable successes and refusals ──────────────────────────

#push-options "--fuel 4 --ifuel 2"

let valid_send_observation : t_SendRequestObservation =
  {
    f_policy = {
      Vela_share_policy.f_session_user_id_present = true;
      Vela_share_policy.f_recipient_has_share_ek = true;
      Vela_share_policy.f_capsule_len = mk_i64 16;
      Vela_share_policy.f_existing_inbox_bytes = mk_i64 0;
    };
    f_decode_failed = false;
    f_inbox_count = mk_i64 0;
    f_pair_bytes = mk_i64 0;
  }

let valid_ek_start : t_EkRegistrationStartObservation =
  {
    f_ek_decode_failed = false;
    f_ek_len = Vela_share_policy.v_SHARE_EK_LEN;
    f_signed_at_not_canonical = false;
    f_signed_at_unparseable = false;
    f_signed_at_future = false;
  }

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

/// One sender send commits and fills the configured quota exactly.
let u1 = world_step initial (SpawnSend valid_send_observation)
let u2 = world_step u1 (CommitSend 0)
let u1_ok ()
  : Lemma (
      u1.w_link = Link_Live /\ u1.w_inbox_count = 1 /\
      FStar.List.Tot.length u1.w_reqs = 1 /\
      is_send (FStar.List.Tot.index u1.w_reqs 0)) = ()
let u2_ok () : Lemma (u2.w_inbox_count = 2 /\ u2.w_link_changes = 0) = u1_ok ()

let send_success_schedule : list action =
  [ SpawnSend valid_send_observation; CommitSend 0 ]

let send_success_is_reachable ()
  : Lemma ((run_world initial send_success_schedule).w_inbox_count = 2) =
  run_cons initial (SpawnSend valid_send_observation) [CommitSend 0];
  run_cons u1 (CommitSend 0) [];
  run_nil u2;
  u2_ok ()

/// At the quota, a second send is refused: the count never exceeds two.
let q0 : world = { initial with w_inbox_count = 2; w_inbox_item = true }
let q1 = world_step q0 (SpawnSend valid_send_observation)
let q2 = world_step q1 (CommitSend 0)
let q2_ok () : Lemma (q2.w_inbox_count = 2) = ()
let quota_refuses_send_schedule : list action =
  [ SpawnSend valid_send_observation; CommitSend 0 ]
let quota_never_exceeded ()
  : Lemma (
      let w = run_world q0 quota_refuses_send_schedule in
      w.w_inbox_count = 2 /\ w.w_inbox_count <= 2) =
  run_cons q0 (SpawnSend valid_send_observation) [CommitSend 0];
  run_cons q1 (CommitSend 0) [];
  run_nil q2;
  q2_ok ()

/// A sender's update commits and counts as a link change.
let p1 = world_step initial SpawnUpdate
let p2 = world_step p1 (CommitUpdate 0 Actor_Sender)
let p2_ok ()
  : Lemma (
      p2.w_update_commits = 1 /\ p2.w_link_changes = 1 /\
      p2.w_non_sender_changes = 0 /\ p2.w_link = Link_Live) = ()
let sender_update_schedule : list action =
  [ SpawnUpdate; CommitUpdate 0 Actor_Sender ]
let sender_update_is_reachable ()
  : Lemma ((run_world initial sender_update_schedule).w_update_commits = 1) =
  run_cons initial SpawnUpdate [CommitUpdate 0 Actor_Sender];
  run_cons p1 (CommitUpdate 0 Actor_Sender) [];
  run_nil p2;
  p2_ok ()

/// A third party's update is refused by the extracted driver.
let third_party_schedule : list action =
  [ SpawnUpdate; CommitUpdate 0 Actor_ThirdParty ]
let third_party_update_is_refused ()
  : Lemma (
      let w = run_world initial third_party_schedule in
      w.w_update_commits = 0 /\ w.w_link_changes = 0 /\
      w.w_non_sender_changes = 0) =
  let a1 = world_step initial SpawnUpdate in
  let a2 = world_step a1 (CommitUpdate 0 Actor_ThirdParty) in
  run_cons initial SpawnUpdate [CommitUpdate 0 Actor_ThirdParty];
  run_cons a1 (CommitUpdate 0 Actor_ThirdParty) [];
  run_nil a2

/// A committed revoke is final: a later sender update observes the tombstone,
/// is rejected, and commits nothing.
let v1 = world_step initial SpawnRevoke
let v2 = world_step v1 (CommitRevoke 0 Actor_Sender)
let v3 = world_step v2 SpawnUpdate
let v4 = world_step v3 (CommitUpdate 0 Actor_Sender)
let v2_ok ()
  : Lemma (
      v2.w_link = Link_Revoked /\ v2.w_inbox_item = false /\
      v2.w_inbox_count = 0 /\ v2.w_link_changes = 1 /\
      v2.w_update_commits = 0) = ()
let v3_ok ()
  : Lemma (
      v3.w_link = Link_Revoked /\
      FStar.List.Tot.length v3.w_reqs = 2 /\
      is_update_observe (FStar.List.Tot.index v3.w_reqs 0)) = v2_ok ()
let v4_ok ()
  : Lemma (
      v4.w_link = Link_Revoked /\ v4.w_update_commits = 0 /\
      v4.w_link_changes = 1) = v3_ok ()

let revoke_then_update_schedule : list action =
  [ SpawnRevoke;
    CommitRevoke 0 Actor_Sender;
    SpawnUpdate;
    CommitUpdate 0 Actor_Sender ]

let revoke_then_update_is_refused ()
  : Lemma (
      let w = run_world initial revoke_then_update_schedule in
      w.w_link = Link_Revoked /\ w.w_update_commits = 0 /\
      w.w_link_changes = 1) =
  run_cons initial SpawnRevoke [CommitRevoke 0 Actor_Sender; SpawnUpdate; CommitUpdate 0 Actor_Sender];
  run_cons v1 (CommitRevoke 0 Actor_Sender) [SpawnUpdate; CommitUpdate 0 Actor_Sender];
  run_cons v2 SpawnUpdate [CommitUpdate 0 Actor_Sender];
  run_cons v3 (CommitUpdate 0 Actor_Sender) [];
  run_nil v4;
  v4_ok ()

/// An inbox item can only be removed by its recipient. The third-party attempt
/// leaves the count untouched; a later recipient attempt removes one row.
let r1 = world_step initial SpawnInboxDelete
let r2 = world_step r1 (CommitInboxDelete 0 Actor_ThirdParty)
let r2_ok ()
  : Lemma (r2.w_inbox_count = 1 /\ r2.w_inbox_item = true) = ()
let r3 = world_step r2 SpawnInboxDelete
let r4 = world_step r3 (CommitInboxDelete 0 Actor_Recipient)
let r4_ok ()
  : Lemma (r4.w_inbox_count = 0 /\ r4.w_inbox_item = false) = r2_ok ()

let inbox_delete_schedule : list action =
  [ SpawnInboxDelete;
    CommitInboxDelete 0 Actor_ThirdParty;
    SpawnInboxDelete;
    CommitInboxDelete 0 Actor_Recipient ]

let inbox_delete_only_recipient_is_reachable ()
  : Lemma (
      let w = run_world initial inbox_delete_schedule in
      w.w_inbox_count = 0 /\ w.w_inbox_item = false) =
  run_cons initial SpawnInboxDelete
    [CommitInboxDelete 0 Actor_ThirdParty; SpawnInboxDelete;
     CommitInboxDelete 0 Actor_Recipient];
  run_cons r1 (CommitInboxDelete 0 Actor_ThirdParty)
    [SpawnInboxDelete; CommitInboxDelete 0 Actor_Recipient];
  run_cons r2 SpawnInboxDelete [CommitInboxDelete 0 Actor_Recipient];
  run_cons r3 (CommitInboxDelete 0 Actor_Recipient) [];
  run_nil r4;
  r4_ok ()

/// A device-signed EK registration commits through its own request slot.
let e1 = world_step initial (SpawnEk valid_ek_start)
let e2 = world_step e1 (CommitEk 0)
let e2_ok ()
  : Lemma (
      e2.w_update_commits = 0 /\ e2.w_link = Link_Live /\
      FStar.List.Tot.length e2.w_reqs = 1 /\
      (FStar.List.Tot.index e2.w_reqs 0).f_committed = true) = ()

let ek_registration_schedule : list action =
  [ SpawnEk valid_ek_start; CommitEk 0 ]

let ek_registration_is_reachable ()
  : Lemma (
      (FStar.List.Tot.index
         (run_world initial ek_registration_schedule).w_reqs 0).f_committed = true) =
  run_cons initial (SpawnEk valid_ek_start) [CommitEk 0];
  run_cons e1 (CommitEk 0) [];
  run_nil e2;
  e2_ok ()

#pop-options
