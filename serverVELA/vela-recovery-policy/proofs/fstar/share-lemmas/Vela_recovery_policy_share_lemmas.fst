module Vela_recovery_policy_share_lemmas

/// F-1 for the recovery-share executors: for every starting `users` row and
/// every fault point, each `PutShareIo`/`FinalizeShareIo`/`GetShareIo`/
/// `DeleteShareIo` observation (the extracted `classify_*` applied to what the
/// extracted `plan_*` did in `Vela_recovery_policy_share_model`) is the truth
/// about the row.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Share_store
open Vela_recovery_policy_share_model

module L = FStar.List.Tot
module RS = Vela_recovery_policy.Recovery_share_driver

let s (x: string) : text = Alloc.String.String x

// ── Recovery-share executor honesty ────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

/// Only `share_users[user]` may differ.
let share_users_frame (d post: share_db) (user: text) : prop =
  forall (k: text). k <> user ==> post.share_users k == d.share_users k

/// The exact row a successful stage update stores.
let staged_row (u: share_user_row) (share split_id: text) (epoch: i64) (auth: text)
  : share_user_row =
  { u with
    su_pending_share = Some share;
    su_pending_split = Some split_id;
    su_pending_epoch = Some epoch;
    su_pending_auth = Some auth }

/// The exact row a successful promote update stores.
let promoted_row (u: share_user_row) : share_user_row =
  { u with
    su_share = u.su_pending_share;
    su_split = u.su_pending_split;
    su_auth = u.su_pending_auth;
    su_pending_share = None;
    su_pending_split = None;
    su_pending_epoch = None;
    su_pending_auth = None }

/// The exact row a successful delete update stores.
let cleared_row (u: share_user_row) : share_user_row =
  { u with
    su_share = None;
    su_split = None;
    su_pending_share = None;
    su_pending_split = None;
    su_pending_epoch = None;
    su_auth = None;
    su_pending_auth = None }

/// `PutShareIo::stage_share`: `Staged` holds exactly when the SQL guard held
/// and nothing failed; then exactly the candidate columns were staged. A
/// zero-row update is `NotStaged` and changes nothing.
let stage_share_is_honest
      (d: share_db) (user share split_id: text) (epoch: i64) (auth: text) (f: option nat)
  : Lemma
    (match stage_share d user share split_id epoch auth f with
     | None -> faulted f 0
     | Some (obs, post) ->
       not (faulted f 0) /\
       (obs == RS.StageUpdateObservation_Staged <==> stage_guard d user epoch) /\
       (obs == RS.StageUpdateObservation_NotStaged <==> not (stage_guard d user epoch)) /\
       (obs == RS.StageUpdateObservation_Staged ==>
          ((forall (u: share_user_row). d.share_users user == Some u ==>
              post.share_users user == Some (staged_row u share split_id epoch auth)) /\
           share_users_frame d post user)) /\
       (obs == RS.StageUpdateObservation_NotStaged ==> post == d)) =
  ()

/// `FinalizeShareIo::promote_staged_split`: `Promoted` holds exactly when the
/// exact staged split was present, at the current epoch, outside rotation, and
/// nothing failed; then exactly the active columns were published and the
/// candidate cleared.
let promote_staged_split_is_honest
      (d: share_db) (user: text) (epoch: i64) (split_id: text) (f: option nat)
  : Lemma
    (match promote_staged_split d user epoch split_id f with
     | None -> faulted f 0
     | Some (obs, post) ->
       not (faulted f 0) /\
       (obs == RS.FinalizeUpdateObservation_Promoted <==> promote_guard d user epoch split_id) /\
       (obs == RS.FinalizeUpdateObservation_NotPromoted <==>
          not (promote_guard d user epoch split_id)) /\
       (obs == RS.FinalizeUpdateObservation_Promoted ==>
          ((forall (u: share_user_row). d.share_users user == Some u ==>
              post.share_users user == Some (promoted_row u)) /\
           share_users_frame d post user)) /\
       (obs == RS.FinalizeUpdateObservation_NotPromoted ==> post == d)) =
  ()

/// `DeleteShareIo::delete_share`: `Deleted` holds exactly when the row exists
/// at the requested epoch and nothing failed; then the active share, its split
/// and the staged candidate are cleared together. A zero-row update changes
/// nothing.
let delete_share_is_honest
      (d: share_db) (user: text) (epoch: i64) (f: option nat)
  : Lemma
    (match delete_share d user epoch f with
     | None -> faulted f 0
     | Some (obs, post) ->
       not (faulted f 0) /\
       (obs == RS.DeleteUpdateObservation_Deleted <==> delete_guard d user epoch) /\
       (obs == RS.DeleteUpdateObservation_NotDeleted <==> not (delete_guard d user epoch)) /\
       (obs == RS.DeleteUpdateObservation_Deleted ==>
          ((forall (u: share_user_row). d.share_users user == Some u ==>
              post.share_users user == Some (cleared_row u)) /\
           share_users_frame d post user)) /\
       (obs == RS.DeleteUpdateObservation_NotDeleted ==> post == d)) =
  ()

/// `PutShareIo::stage_query_account`: every observation field is the live
/// row's truth.
let stage_account_is_honest
      (d: share_db) (user share split_id: text) (failed: bool)
  : Lemma
    (match stage_account d user share split_id failed with
     | None -> failed
     | Some obs ->
       not failed /\
       obs.RS.f_account_present == Some? (d.share_users user) /\
       obs.RS.f_stored_epoch ==
         (match d.share_users user with
          | Some u -> core_opt (Some u.su_epoch)
          | None -> Core_models.Option.Option_None) /\
       obs.RS.f_rotation_active ==
         (match d.share_users user with
          | Some u -> u.su_rekey
          | None -> false) /\
       obs.RS.f_active_share_matches ==
         (match d.share_users user with
          | Some u -> u.su_share = Some share
          | None -> false) /\
       obs.RS.f_active_split_matches ==
         (match d.share_users user with
          | Some u -> u.su_split = Some split_id
          | None -> false)) =
  ()

/// `FinalizeShareIo::finalize_query_account`: every observation field is the
/// live row's truth.
let finalize_account_is_honest
      (d: share_db) (user split_id: text) (failed: bool)
  : Lemma
    (match finalize_account d user split_id failed with
     | None -> failed
     | Some obs ->
       not failed /\
       obs.RS.f_account_present == Some? (d.share_users user) /\
       obs.RS.f_stored_epoch ==
         (match d.share_users user with
          | Some u -> core_opt (Some u.su_epoch)
          | None -> Core_models.Option.Option_None) /\
       obs.RS.f_rotation_active ==
         (match d.share_users user with
          | Some u -> u.su_rekey
          | None -> false) /\
       obs.RS.f_active_split_matches ==
         (match d.share_users user with
          | Some u -> u.su_split = Some split_id
          | None -> false)) =
  ()

/// `GetShareIo::read_share`: account and share presence are the live row's
/// truth.
let read_share_is_honest (d: share_db) (user: text) (failed: bool)
  : Lemma
    (match read_share d user failed with
     | None -> failed
     | Some obs ->
       not failed /\
       obs.RS.f_account_present == Some? (d.share_users user) /\
       obs.RS.f_share_present ==
         (match d.share_users user with
          | Some u -> Some? u.su_share
          | None -> false)) =
  ()

// ── Facts the recovery-share driver relies on ──────────────────────────────

/// A successful stage update leaves exactly the candidate the request named.
let staged_candidate_is_exact
      (d: share_db) (user share split_id: text) (epoch: i64) (auth: text) (f: option nat)
  : Lemma
    (match stage_share d user share split_id epoch auth f with
     | Some (RS.StageUpdateObservation_Staged, post) ->
       (forall (u: share_user_row). d.share_users user == Some u ==>
          post.share_users user == Some (staged_row u share split_id epoch auth))
     | _ -> True) =
  stage_share_is_honest d user share split_id epoch auth f

/// A successful promotion publishes exactly the staged split.
let promoted_split_is_active
      (d: share_db) (user: text) (epoch: i64) (split_id: text) (f: option nat)
  : Lemma
    (match promote_staged_split d user epoch split_id f with
     | Some (RS.FinalizeUpdateObservation_Promoted, post) ->
       (forall (u: share_user_row). d.share_users user == Some u ==>
          post.share_users user == Some (promoted_row u))
     | _ -> True) =
  promote_staged_split_is_honest d user epoch split_id f

/// A successful delete clears both the active share and the staged candidate.
let deleted_share_is_cleared
      (d: share_db) (user: text) (epoch: i64) (f: option nat)
  : Lemma
    (match delete_share d user epoch f with
     | Some (RS.DeleteUpdateObservation_Deleted, post) ->
       (forall (u: share_user_row). d.share_users user == Some u ==>
          post.share_users user == Some (cleared_row u))
     | _ -> True) =
  delete_share_is_honest d user epoch f

/// A zero-row stage update really did change nothing.
let not_staged_keeps_state
      (d: share_db) (user share split_id auth: text) (epoch: i64) (f: option nat)
  : Lemma
    (match stage_share d user share split_id epoch auth f with
     | Some (RS.StageUpdateObservation_NotStaged, post) -> post == d
     | _ -> True) =
  stage_share_is_honest d user share split_id epoch auth f

// ── Vectors shared with `redemption_model.rs::tests::shared_share_vectors` ─

let share_user (epoch: i64) (rekey: bool) : share_user_row =
  { su_epoch = epoch; su_rekey = rekey;
    su_share = None; su_split = None;
    su_pending_share = None; su_pending_split = None;
    su_pending_epoch = None; su_auth = None; su_pending_auth = None }

let share_db_one (u: share_user_row) : share_db =
  { share_users = (fun k -> if k = s "u" then Some u else None) }

let vector_share_base : share_db = share_db_one (share_user (mk_i64 7) false)

let vector_share_staged : share_db =
  share_db_one (staged_row (share_user (mk_i64 7) false) (s "sh") (s "sp") (mk_i64 7) (s "au"))

let vector_share_promoted : share_db =
  share_db_one (promoted_row (staged_row (share_user (mk_i64 7) false) (s "sh") (s "sp") (mk_i64 7) (s "au")))

let vector_share_stage ()
  : Lemma
    (match stage_share vector_share_base (s "u") (s "sh") (s "sp") (mk_i64 7) (s "au") None with
     | Some (obs, post) ->
       obs == RS.StageUpdateObservation_Staged /\
       post.share_users (s "u") ==
         Some (staged_row (share_user (mk_i64 7) false) (s "sh") (s "sp") (mk_i64 7) (s "au"))
     | None -> False) =
  stage_share_is_honest vector_share_base (s "u") (s "sh") (s "sp") (mk_i64 7) (s "au") None

let vector_share_promote ()
  : Lemma
    (match promote_staged_split vector_share_staged (s "u") (mk_i64 7) (s "sp") None with
     | Some (obs, post) ->
       obs == RS.FinalizeUpdateObservation_Promoted /\
       post.share_users (s "u") ==
         Some (promoted_row (staged_row (share_user (mk_i64 7) false) (s "sh") (s "sp") (mk_i64 7) (s "au")))
     | None -> False) =
  promote_staged_split_is_honest vector_share_staged (s "u") (mk_i64 7) (s "sp") None

let vector_share_delete ()
  : Lemma
    (match delete_share vector_share_promoted (s "u") (mk_i64 7) None with
     | Some (obs, post) ->
       obs == RS.DeleteUpdateObservation_Deleted /\
       post.share_users (s "u") ==
         Some (cleared_row (promoted_row (staged_row (share_user (mk_i64 7) false) (s "sh") (s "sp") (mk_i64 7) (s "au"))))
     | None -> False) =
  delete_share_is_honest vector_share_promoted (s "u") (mk_i64 7) None

let vector_share_stale_epoch ()
  : Lemma
    (match stage_share vector_share_base (s "u") (s "sh") (s "sp") (mk_i64 8) (s "au") None with
     | Some (obs, post) -> obs == RS.StageUpdateObservation_NotStaged /\ post == vector_share_base
     | None -> False) =
  stage_share_is_honest vector_share_base (s "u") (s "sh") (s "sp") (mk_i64 8) (s "au") None

let vector_share_stored : share_db =
  { share_users =
      (fun k ->
        if k = s "u"
        then Some ({ (share_user (mk_i64 7) false) with su_share = Some (s "sh") })
        else None) }

let vector_share_read ()
  : Lemma
    (read_share vector_share_stored (s "u") false ==
       Some ({ RS.f_account_present = true; RS.f_share_present = true }
             <: RS.t_ReadObservation)) =
  read_share_is_honest vector_share_stored (s "u") false

let vector_share_missing ()
  : Lemma
    (read_share vector_share_base (s "missing") false ==
       Some ({ RS.f_account_present = false; RS.f_share_present = false }
             <: RS.t_ReadObservation)) =
  read_share_is_honest vector_share_base (s "missing") false

let vector_share_stage_account ()
  : Lemma
    (match stage_account vector_share_stored (s "u") (s "sh") (s "sp") false with
     | Some obs -> obs.RS.f_account_present = true /\ obs.RS.f_active_share_matches = true
                   /\ obs.RS.f_active_split_matches = false
     | None -> False) =
  stage_account_is_honest vector_share_stored (s "u") (s "sh") (s "sp") false

#pop-options
