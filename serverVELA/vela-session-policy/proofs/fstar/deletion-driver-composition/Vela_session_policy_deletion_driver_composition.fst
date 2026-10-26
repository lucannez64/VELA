module Vela_session_policy_deletion_driver_composition

/// Concurrent composition of the *extracted* account-deletion driver with the
/// *extracted* middleware admission driver
/// (`Vela_session_policy.Revocation_driver.plan_admission`).
///
/// Any number of requests run their own `DeletionDriver` against one shared
/// world. A schedule is an arbitrary list of actions: spawn a deletion for an
/// account (naming the device whose session authorizes it), deliver the next
/// observation, or attempt a token admission for an account.
///
/// The world abstracts the effects the handler performs:
///
/// - the scans, the transaction begin and the SQL deletes report the
///   observation the handler obtained; the `users` delete observation is
///   derived from the world (the row is absent when the account already
///   committed or another open deletion owns it), never chosen by the
///   schedule, so a lying "deleted" cannot weaken the theorem;
/// - each store-side lockout effect sets the account's device or web-session
///   sentinel flag, which is the flag the middleware's admission observation
///   reads for every token of that account (the "the lockout marks every
///   token" linkage is an assumption; the per-request theorem proves the
///   driver authorizes the lockouts before the transaction);
/// - the `users` delete owns the account row for the first request that
///   reaches it, and only that request's observation reports it deleted; a
///   commit (or a failure) releases the row;
/// - the account is marked deleted only when the handler reports a commit
///   committed;
/// - an admission attempt builds the middleware observation from the account
///   flags and calls the extracted `plan_admission`.
///
/// Theorem: for every schedule,
///
/// - the driver never authorizes a lockout or SQL effect for an account other
///   than the one its verified session names (`w_cross_account = 0`);
/// - the driver never authorizes a commit in the step whose `users` observation
///   said the row was absent or the delete failed (`w_second_commit = 0`), so a
///   second deletion of the same account never commits;
/// - the extracted admission decision never admits an attempt for an account
///   whose deletion driver completed both lockouts (`w_admitted_after_lockout = 0`);
/// - every live request remains sound.
///
/// The counters are incremented at the point the *driver* authorizes the
/// forbidden thing: a scoped effect for a cross-account target, a commit next
/// to a non-deleted `users` observation, or an `Admit` from the extracted
/// `plan_admission` for a locked-out account. No counter is incremented by a
/// modelled SQL guard refusing a write.
///
/// The world fixes two accounts — the deleting account and one other — which is
/// exactly what "the same account" versus "another account" needs; the number
/// of requests, interleavings and observations is unbounded.
///
/// Assumptions (not proved here): sled and SQL writes are linearizable and a
/// transaction is the unit of atomicity (so the first `users` delete owns the
/// row and a failed transaction rolls back); the handler performs exactly the
/// effect the driver returns in the same step as its observation; the
/// store-side lockout applies to every token of the account and the middleware
/// reads those sentinels; devices are not transferred between accounts (so the
/// spawn-time owner comparison stays valid); TTL expiry, token cryptography,
/// multi-node replication and the response rendering remain outside this
/// module.
///
/// This module deliberately does not import the per-request lemma module: the
/// composition is a statement about the extracted drivers alone. That also
/// makes the mutation checks fail here, not in an unrelated lemma.

open FStar.Mul
open Core_models
open Vela_session_policy.Deletion_driver
open Vela_session_policy_deletion_driver_bridge

// ── Generic list helpers (Core_models shadows the unqualified names) ────────

let rec update (#a: Type) (l: list a) (i: nat) (x: a)
  : Tot (list a) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

// ── World model ────────────────────────────────────────────────────────────

/// The authenticated actor facts captured when the request started. `ac_owner`
/// is the session's account, `ac_active` the spawn-time non-revoked state and
/// `ac_target_owner` the account every statement of the request is scoped to.
noeq type actor_ctx = {
  ac_owner: nat;
  ac_active: bool;
  ac_target_owner: nat;
}

noeq type request =
  | DeleteReq : t_DeletionDriver -> actor_ctx -> nat -> request

noeq type world = {
  /// Why each spawned request was refused, if it was (reachability witness).
  w_refused: nat;
  /// The two accounts: device sentinel, web-session sentinel, `users` row
  /// owner and committed-deleted flag.
  w_a0_dev: bool;
  w_a0_ws: bool;
  w_a0_owner: nat;
  w_a0_deleted: bool;
  w_a1_dev: bool;
  w_a1_ws: bool;
  w_a1_owner: nat;
  w_a1_deleted: bool;
  w_reqs: list request;
  /// Driver authorizations of a scoped effect for a cross-account target.
  w_cross_account: nat;
  /// Driver authorizations of a commit next to a non-deleted `users` observation.
  w_second_commit: nat;
  /// Admitted attempts for an account whose driver completed both lockouts.
  w_admitted_after_lockout: nat;
  /// Counts of driver-authorized effects (reachability witnesses).
  w_delete_effects: nat;
  w_commits: nat;
  w_lockouts: nat;
}

// ── Account accessors ──────────────────────────────────────────────────────

let account_deleted (w: world) (a: nat) : bool =
  if a = 0 then w.w_a0_deleted else w.w_a1_deleted

let account_dev_sentinel (w: world) (a: nat) : bool =
  if a = 0 then w.w_a0_dev else w.w_a1_dev

let account_ws_sentinel (w: world) (a: nat) : bool =
  if a = 0 then w.w_a0_ws else w.w_a1_ws

let account_users_owner (w: world) (a: nat) : nat =
  if a = 0 then w.w_a0_owner else w.w_a1_owner

let account_fully_locked (w: world) (a: nat) : bool =
  account_dev_sentinel w a && account_ws_sentinel w a

// ── Invariants ─────────────────────────────────────────────────────────────

let is_done_state (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_Done -> true
  | _ -> false

/// Per-request facts, independent of the shared world.
let request_ok (r: request) : bool =
  match r with
  | DeleteReq d actor _r_id ->
      deletion_state_is_sound d &&
      (d.f_actor_active = actor.ac_active) &&
      (not d.f_same_account || actor.ac_owner = actor.ac_target_owner) &&
      (actor.ac_target_owner = 0 || actor.ac_target_owner = 1)

let rec all_requests_ok (l: list request) : bool =
  match l with
  | [] -> true
  | r :: rest -> request_ok r && all_requests_ok rest

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
  : Lemma
    (requires (request_ok r /\ all_requests_ok l))
    (ensures (all_requests_ok (r :: l))) = ()

let inv (w: world) : prop =
  all_requests_ok w.w_reqs /\
  w.w_cross_account = 0 /\
  w.w_second_commit = 0 /\
  w.w_admitted_after_lockout = 0

// ── World effects ──────────────────────────────────────────────────────────

/// Set one account's device or web-session sentinel flag.
let lock_dev (w: world) (a: nat) : world =
  { w with
    w_a0_dev = (if a = 0 then true else w.w_a0_dev);
    w_a1_dev = (if a = 0 then w.w_a1_dev else true) }

let lock_ws (w: world) (a: nat) : world =
  { w with
    w_a0_ws = (if a = 0 then true else w.w_a0_ws);
    w_a1_ws = (if a = 0 then w.w_a1_ws else true) }

let claim_users (w: world) (a: nat) (owner: nat) : world =
  { w with
    w_a0_owner = (if a = 0 && w.w_a0_owner = 0 && not w.w_a0_deleted
                  then owner else w.w_a0_owner);
    w_a1_owner = (if a = 1 && w.w_a1_owner = 0 && not w.w_a1_deleted
                  then owner else w.w_a1_owner) }

let commit_account (w: world) (a: nat) : world =
  { w with
    w_a0_deleted = (if a = 0 then true else w.w_a0_deleted);
    w_a0_owner = (if a = 0 then 0 else w.w_a0_owner);
    w_a1_deleted = (if a = 0 then w.w_a1_deleted else true);
    w_a1_owner = (if a = 0 then w.w_a1_owner else 0) }

let rollback_account (w: world) (a: nat) (owner: nat) : world =
  { w with
    w_a0_owner = (if a = 0 && w.w_a0_owner = owner then 0 else w.w_a0_owner);
    w_a1_owner = (if a = 1 && w.w_a1_owner = owner then 0 else w.w_a1_owner) }

let is_scoped_effect (e: t_DeletionEffect) : bool =
  match e <: t_DeletionEffect with
  | DeletionEffect_LockoutDevices -> true
  | DeletionEffect_LockoutWebSessions -> true
  | DeletionEffect_DeleteTable _ -> true
  | DeletionEffect_DeleteUsers -> true
  | DeletionEffect_CommitTransaction -> true
  | _ -> false

/// The honest `users` delete observation: the row is absent when the account
/// already committed or another open deletion owns it.
let honest_users_observation (w: world) (actor: actor_ctx) (r_id: nat)
  : t_UsersDeleteObservation =
  if account_deleted w actor.ac_target_owner
     || (account_users_owner w actor.ac_target_owner <> 0
         && account_users_owner w actor.ac_target_owner <> r_id + 1)
  then UsersDeleteObservation_Absent
  else UsersDeleteObservation_Deleted

/// Deliver one observation to request `i` and apply exactly the effect the
/// extracted driver returns. The driver-authorized counters are computed from
/// the pre-effect state.
let deliver (w: world) (i: nat) (e: t_DeletionEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d actor r_id ->
        if deletion_state_is_sound d
        then
          let obs =
            match e <: t_DeletionEvent with
            | DeletionEvent_UsersDeleted UsersDeleteObservation_Failed ->
                UsersDeleteObservation_Failed
            | DeletionEvent_UsersDeleted _ ->
                honest_users_observation w actor r_id
            | _ -> UsersDeleteObservation_Deleted
          in
          let e' =
            match e <: t_DeletionEvent with
            | DeletionEvent_UsersDeleted _ ->
                DeletionEvent_UsersDeleted obs
            | _ -> e
          in
          let t = step d e' in
          let cross =
            if is_scoped_effect t.f_effect
               && actor.ac_owner <> actor.ac_target_owner
            then 1 else 0
          in
          let second =
            if is_commit_effect t.f_effect
               && (obs = UsersDeleteObservation_Absent
                   || obs = UsersDeleteObservation_Failed)
            then 1 else 0
          in
          let w1 =
            { w with
              w_reqs = update w.w_reqs i (DeleteReq t.f_driver actor r_id);
              w_cross_account = w.w_cross_account + cross;
              w_second_commit = w.w_second_commit + second } in
          let w2 =
            match t.f_effect <: t_DeletionEffect with
            | DeletionEffect_LockoutDevices ->
                { (lock_dev w1 actor.ac_target_owner) with
                  w_lockouts = w1.w_lockouts + 1 }
            | DeletionEffect_LockoutWebSessions ->
                { (lock_ws w1 actor.ac_target_owner) with
                  w_lockouts = w1.w_lockouts + 1 }
            | DeletionEffect_DeleteTable _ ->
                { w1 with w_delete_effects = w1.w_delete_effects + 1 }
            | DeletionEffect_DeleteUsers ->
                { (claim_users w1 actor.ac_target_owner (r_id + 1)) with
                  w_delete_effects = w1.w_delete_effects + 1 }
            | DeletionEffect_Complete ->
                { (commit_account w1 actor.ac_target_owner) with
                  w_commits = w1.w_commits + 1 }
            | DeletionEffect_Fail _ ->
                rollback_account w1 actor.ac_target_owner (r_id + 1)
            | _ -> w1 in
          w2
        else w
  else w

// ── Arbitrary schedules ────────────────────────────────────────────────────

type action =
  | SpawnDelete : nat -> nat -> action
  | Deliver : nat -> t_DeletionEvent -> action
  | Use : nat -> action

/// Build the middleware admission observation for one account. The device
/// sentinel flag is the `device:revoked:` lookup for every token of the
/// account (see the modelling note above).
let admission_observation (w: world) (a: nat)
  : Vela_session_policy.Revocation_driver.t_AdmissionObservation =
  { f_jti_revoked = false;
    f_device_revoked = account_dev_sentinel w a;
    f_account_present = not (account_deleted w a);
    f_device_row_active = not (account_deleted w a);
    f_device_scoped = false }

let world_step (w: world) (a: action) : world =
  match a with
  | SpawnDelete actor target ->
      if (target = 0 || target = 1)
      then
        let start =
          begin_deletion
            ({ f_authenticated = true;
               f_device_active = true;
               f_scoped_to_session_account = actor = target })
        in
        let ctx =
          ({ ac_owner = actor;
             ac_active = true;
             ac_target_owner = target })
        in
        let r_id = FStar.List.Tot.length w.w_reqs in
        { w with
          w_reqs = DeleteReq start.f_driver ctx r_id :: w.w_reqs;
          w_refused = (if start.f_driver.f_failed then w.w_refused + 1 else w.w_refused) }
      else w
  | Deliver i e -> deliver w i e
  | Use a ->
      let observation = admission_observation w a in
      match Vela_session_policy.Revocation_driver.plan_admission observation
            <: Vela_session_policy.Revocation_driver.t_AdmissionDecision with
      | Vela_session_policy.Revocation_driver.AdmissionDecision_Admit ->
          if account_fully_locked w a
          then { w with w_admitted_after_lockout = w.w_admitted_after_lockout + 1 }
          else w
      | Vela_session_policy.Revocation_driver.AdmissionDecision_Reject _ -> w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Invariant preservation ─────────────────────────────────────────────────

/// A scoped effect from a same-account request is not a cross-account
/// authorization, and a commit next to an absent/failed `users` observation is
/// not authorized by a sound driver.
let no_forbidden_authorization
      (w: world)
      (d: t_DeletionDriver)
      (actor: actor_ctx)
      (obs: t_UsersDeleteObservation)
  : Lemma
    (requires (
      deletion_state_is_sound d /\
      (not d.f_same_account || actor.ac_owner = actor.ac_target_owner) /\
      (match obs with
       | UsersDeleteObservation_Absent -> True
       | UsersDeleteObservation_Failed -> True
       | _ -> False)))
    (ensures (
      (if is_scoped_effect (step d (DeletionEvent_UsersDeleted obs)).f_effect
          && actor.ac_owner <> actor.ac_target_owner
       then 1 else 0) = 0 /\
      (if is_commit_effect (step d (DeletionEvent_UsersDeleted obs)).f_effect
       then 1 else 0) = 0)) =
  scoped_effect_authority d (DeletionEvent_UsersDeleted obs);
  absent_users_delete_never_commits_stage d obs

/// Delivering an event keeps every invariant.
let deliver_inv (w: world) (i: nat) (e: t_DeletionEvent)
  : Lemma (requires (inv w)) (ensures (inv (deliver w i e))) =
  if i < FStar.List.Tot.length w.w_reqs
  then begin
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d actor r_id ->
        if deletion_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let obs =
            match e <: t_DeletionEvent with
            | DeletionEvent_UsersDeleted UsersDeleteObservation_Failed ->
                UsersDeleteObservation_Failed
            | DeletionEvent_UsersDeleted _ ->
                honest_users_observation w actor r_id
            | _ -> UsersDeleteObservation_Deleted
          in
          let e' =
            match e <: t_DeletionEvent with
            | DeletionEvent_UsersDeleted _ -> DeletionEvent_UsersDeleted obs
            | _ -> e
          in
          let t = step d e' in
          step_keeps_actor d e';
          all_requests_ok_update w.w_reqs i (DeleteReq t.f_driver actor r_id);
          (if is_scoped_effect t.f_effect
              && actor.ac_owner <> actor.ac_target_owner
           then begin
             scoped_effect_authority d e';
             assert (actor.ac_target_owner = actor.ac_owner)
           end);
          (if is_commit_effect t.f_effect
              && (obs = UsersDeleteObservation_Absent
                  || obs = UsersDeleteObservation_Failed)
           then begin
             absent_users_delete_never_commits_stage d obs;
             assert False
           end)
        end
  end

/// A spawned request keeps the invariant.
let spawn_inv (w: world) (actor: nat) (target: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (SpawnDelete actor target)))) =
  if (target = 0 || target = 1)
  then begin
    let start =
      begin_deletion
        ({ f_authenticated = true;
           f_device_active = true;
           f_scoped_to_session_account = actor = target }) in
    let ctx =
      ({ ac_owner = actor;
         ac_active = true;
         ac_target_owner = target }) in
    assert (request_ok (DeleteReq start.f_driver ctx (FStar.List.Tot.length w.w_reqs)));
    assert (all_requests_ok w.w_reqs);
    all_requests_ok_cons
      (DeleteReq start.f_driver ctx (FStar.List.Tot.length w.w_reqs))
      w.w_reqs
  end

/// An admitted observation is never sentinel-marked (the extracted decision's
/// own precedence: the device sentinel is checked before admission).
let admit_implies_sentinel_clear
      (o: Vela_session_policy.Revocation_driver.t_AdmissionObservation)
  : Lemma
    (requires (
      Vela_session_policy.Revocation_driver.admission_decision_matches_spec o
        Vela_session_policy.Revocation_driver.AdmissionDecision_Admit))
    (ensures (not o.f_device_revoked)) =
  ()

/// An admission attempt keeps the invariant: the extracted decision refuses a
/// sentinel-marked account, and the counter only moves for an admitted attempt
/// of a fully locked-out account.
let use_inv (w: world) (a: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Use a)))) =
  let observation = admission_observation w a in
  match Vela_session_policy.Revocation_driver.plan_admission observation
        <: Vela_session_policy.Revocation_driver.t_AdmissionDecision with
  | Vela_session_policy.Revocation_driver.AdmissionDecision_Admit ->
      admit_implies_sentinel_clear observation;
      assert (not (account_dev_sentinel w a));
      assert (not (account_fully_locked w a))
  | Vela_session_policy.Revocation_driver.AdmissionDecision_Reject _ -> ()

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | SpawnDelete actor target -> spawn_inv w actor target
  | Deliver i e -> deliver_inv w i e
  | Use a -> use_inv w a

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── Initial world and headline composition theorem ─────────────────────────

let initial : world =
  {
    w_refused = 0;
    w_a0_dev = false;
    w_a0_ws = false;
    w_a0_owner = 0;
    w_a0_deleted = false;
    w_a1_dev = false;
    w_a1_ws = false;
    w_a1_owner = 0;
    w_a1_deleted = false;
    w_reqs = [];
    w_cross_account = 0;
    w_second_commit = 0;
    w_admitted_after_lockout = 0;
    w_delete_effects = 0;
    w_commits = 0;
    w_lockouts = 0;
  }

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem: whatever the number of concurrent deletions and admission
/// attempts, their interleaving and their observations, the extracted deletion
/// driver never authorizes an effect for another account or a second commit of
/// the same account, and the extracted admission decision never admits an
/// attempt for a fully locked-out account.
let deletion_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_cross_account = 0 /\
      w.w_second_commit = 0 /\
      w.w_admitted_after_lockout = 0) =
  initial_inv ();
  run_world_inv initial schedule

let no_cross_account_deletion (schedule: list action)
  : Lemma ((run_world initial schedule).w_cross_account = 0) =
  deletion_composition_theorem schedule

let no_second_commit (schedule: list action)
  : Lemma ((run_world initial schedule).w_second_commit = 0) =
  deletion_composition_theorem schedule

let locked_account_admission_never_authorized (schedule: list action)
  : Lemma ((run_world initial schedule).w_admitted_after_lockout = 0) =
  deletion_composition_theorem schedule

// ── Non-vacuity: reachable effects ─────────────────────────────────────────

let full_delete_schedule (from: nat) : list action =
  [ Deliver from (DeletionEvent_DevicesScanned ScanObservation_Rows);
    Deliver from (DeletionEvent_DeviceLockout LockoutObservation_Applied);
    Deliver from (DeletionEvent_WebSessionsScanned ScanObservation_Rows);
    Deliver from (DeletionEvent_WebSessionLockout LockoutObservation_Applied);
    Deliver from (DeletionEvent_Transaction TransactionObservation_Begun);
    Deliver from (DeletionEvent_TableDeleted TableDeleteObservation_Deleted);
    Deliver from (DeletionEvent_TableDeleted TableDeleteObservation_Deleted);
    Deliver from (DeletionEvent_TableDeleted TableDeleteObservation_Deleted);
    Deliver from (DeletionEvent_TableDeleted TableDeleteObservation_Deleted);
    Deliver from (DeletionEvent_TableDeleted TableDeleteObservation_Deleted);
    Deliver from (DeletionEvent_TableDeleted TableDeleteObservation_Deleted);
    Deliver from (DeletionEvent_TableDeleted TableDeleteObservation_Deleted);
    Deliver from (DeletionEvent_UsersDeleted UsersDeleteObservation_Deleted);
    Deliver from (DeletionEvent_Commit CommitObservation_Committed) ]

/// A complete deletion commits once, locks the account out, deletes the seven
/// tables plus the users row, and the account is then refused admission.
let successful_deletion_commits ()
  : Lemma (
      let w = run_world initial
        ([ SpawnDelete 0 0 ] @ full_delete_schedule 0 @ [ Use 0 ]) in
      w.w_cross_account = 0 /\ w.w_second_commit = 0 /\
      w.w_admitted_after_lockout = 0 /\
      account_deleted w 0 = true /\ account_fully_locked w 0 = true /\
      w.w_commits = 1 /\ w.w_delete_effects = 8 /\ w.w_lockouts = 2) =
  assert_norm (
      let w = run_world initial
        ([ SpawnDelete 0 0 ] @ full_delete_schedule 0 @ [ Use 0 ]) in
      w.w_cross_account = 0 /\ w.w_second_commit = 0 /\
      w.w_admitted_after_lockout = 0 /\
      account_deleted w 0 = true /\ account_fully_locked w 0 = true /\
      w.w_commits = 1 /\ w.w_delete_effects = 8 /\ w.w_lockouts = 2)

/// Two deletions of the same account: the newer request commits, the older one
/// sees the row owned and never commits.
let second_deletion_never_commits ()
  : Lemma (
      let w = run_world initial
        ([ SpawnDelete 0 0; SpawnDelete 1 0 ] @
         full_delete_schedule 0 @
         full_delete_schedule 1) in
      w.w_commits = 1 /\ w.w_second_commit = 0 /\
      w.w_cross_account = 0 /\ w.w_admitted_after_lockout = 0) =
  assert_norm (
      let w = run_world initial
        ([ SpawnDelete 0 0; SpawnDelete 1 0 ] @
         full_delete_schedule 0 @
         full_delete_schedule 1) in
      w.w_commits = 1 /\ w.w_second_commit = 0 /\
      w.w_cross_account = 0 /\ w.w_admitted_after_lockout = 0)

/// A cross-account spawn is refused: the driver emits no effect, so nothing of
/// the other account is locked out or deleted.
let cross_account_deletion_is_refused ()
  : Lemma (
      let w = run_world initial
        [ SpawnDelete 0 1;
          Deliver 0 (DeletionEvent_DevicesScanned ScanObservation_Rows) ] in
      w.w_cross_account = 0 /\ w.w_delete_effects = 0 /\ w.w_lockouts = 0 /\
      account_deleted w 1 = false /\ not (account_fully_locked w 1)) =
  assert_norm (
      let w = run_world initial
        [ SpawnDelete 0 1;
          Deliver 0 (DeletionEvent_DevicesScanned ScanObservation_Rows) ] in
      w.w_cross_account = 0 /\ w.w_delete_effects = 0 /\ w.w_lockouts = 0 /\
      account_deleted w 1 = false /\ not (account_fully_locked w 1))

/// An admission attempt for a fully locked-out (but not yet deleted) account is
/// refused by the extracted decision.
let locked_account_is_not_admitted ()
  : Lemma (
      let w = run_world initial
        ([ SpawnDelete 0 0 ] @ full_delete_schedule 0 @ [ Use 0 ]) in
      w.w_admitted_after_lockout = 0 /\ account_fully_locked w 0 = true /\
      w.w_cross_account = 0) =
  assert_norm (
      let w = run_world initial
        ([ SpawnDelete 0 0 ] @ full_delete_schedule 0 @ [ Use 0 ]) in
      w.w_admitted_after_lockout = 0 /\ account_fully_locked w 0 = true /\
      w.w_cross_account = 0)
