module Vela_session_policy_deletion_driver_bridge

/// Small corollaries about the *extracted* account-deletion driver's `step`,
/// kept in their own module so the SMT context is just the extraction.
///
/// The composition module imports them instead of re-deriving them among a
/// thousand lines of world model. Every lemma here is a consequence of the
/// extracted `step` contract; none restates the transition logic.

open FStar.Mul
open Core_models
open Vela_session_policy.Deletion_driver

let is_commit_effect (e: t_DeletionEffect) : bool =
  match e <: t_DeletionEffect with
  | DeletionEffect_CommitTransaction -> true
  | _ -> false

let users_observed_deleted (e: t_DeletionEvent) : bool =
  match e <: t_DeletionEvent with
  | DeletionEvent_UsersDeleted UsersDeleteObservation_Deleted -> true
  | _ -> false

let at_delete_users_stage (d: t_DeletionDriver) : bool =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_DeleteUsers -> true
  | _ -> false

/// The extracted step's effect-soundness postcondition.
let step_effect_sound (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (deletion_state_is_sound d))
    (ensures (deletion_effect_is_sound (step d e).f_driver (step d e).f_effect)) =
  ()

/// A step never changes the actor-activity or account-scope facts.
let step_keeps_actor (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (deletion_state_is_sound d))
    (ensures (
      (step d e).f_driver.f_actor_active = d.f_actor_active /\
      (step d e).f_driver.f_same_account = d.f_same_account)) =
  step_effect_sound d e;
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveDevices ->
           (match obs <: t_ScanObservation with
            | ScanObservation_Rows -> ()
            | ScanObservation_QueryFailed -> ())
       | _ -> ())
  | DeletionEvent_DeviceLockout _ -> ()
  | DeletionEvent_WebSessionsScanned obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveWebSessions ->
           (match obs <: t_ScanObservation with
            | ScanObservation_Rows -> ()
            | ScanObservation_QueryFailed -> ())
       | _ -> ())
  | DeletionEvent_WebSessionLockout _ -> ()
  | DeletionEvent_Transaction obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_BeginTransaction ->
           (match obs <: t_TransactionObservation with
            | TransactionObservation_Begun -> ()
            | TransactionObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_TableDeleted _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteTable _ -> ()
       | _ -> ())
  | DeletionEvent_UsersDeleted obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteUsers ->
           (match obs <: t_UsersDeleteObservation with
            | UsersDeleteObservation_Deleted -> ()
            | UsersDeleteObservation_Absent -> ()
            | UsersDeleteObservation_Failed -> ())
       | _ -> ())
  | DeletionEvent_Commit obs ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_Commit ->
           (match obs <: t_CommitObservation with
            | CommitObservation_Committed -> ()
            | CommitObservation_Failed -> ())
       | _ -> ())

/// A scoped effect from a sound driver carries the same-account authority.
let scoped_effect_authority (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (deletion_state_is_sound d))
    (ensures (
      let t = step d e in
      (match t.f_effect <: t_DeletionEffect with
       | DeletionEffect_LockoutDevices -> t.f_driver.f_same_account
       | DeletionEffect_LockoutWebSessions -> t.f_driver.f_same_account
       | DeletionEffect_DeleteTable _ -> t.f_driver.f_same_account
       | DeletionEffect_DeleteUsers -> t.f_driver.f_same_account
       | DeletionEffect_CommitTransaction -> t.f_driver.f_same_account
       | _ -> True))) =
  step_effect_sound d e

/// The account-existence decision: a commit effect only exists when the
/// `users` row was observed deleted from the `DeleteUsers` stage.
let step_commit_implies (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (deletion_state_is_sound d))
    (ensures (
      not (is_commit_effect (step d e).f_effect) ||
      (users_observed_deleted e && at_delete_users_stage d))) =
  ()

/// A `users` delete that reported the row absent (or failed) never produces a
/// commit effect, so a second deletion of the same account cannot commit.
let absent_users_delete_never_commits_stage
      (d: t_DeletionDriver)
      (obs: t_UsersDeleteObservation)
  : Lemma
    (requires (
      deletion_state_is_sound d /\
      (obs = UsersDeleteObservation_Absent || obs = UsersDeleteObservation_Failed)))
    (ensures (
      is_commit_effect (step d (DeletionEvent_UsersDeleted obs)).f_effect = false)) =
  step_commit_implies d (DeletionEvent_UsersDeleted obs)
