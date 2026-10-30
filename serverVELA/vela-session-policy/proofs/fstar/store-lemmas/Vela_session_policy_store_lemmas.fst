module Vela_session_policy_store_lemmas

/// F-1 for the session executors: for every starting database and store and
/// every fault point, each executor's observation (the extracted `classify_*`
/// applied to what the extracted `plan_*` did in `Vela_session_policy_store_model`)
/// is the truth about the tables and keys.
///
/// The lemmas name `fst`/`snd` of each model run instead of destructuring the
/// pair, and depend on the `plan_*_shape` lemmas wherever a plan must reduce,
/// so a changed plan or classifier fails these theorems themselves.

open FStar.Mul
open Core_models
open Vela_session_policy.Store
open Vela_session_policy_store_model

module L = FStar.List.Tot
module D = Vela_session_policy.Deletion_driver
module R = Vela_session_policy.Revocation_driver
module SP = FStar.Seq.Properties
module LG = Vela_session_policy.Login_driver
module LGC = Vela_session_policy.Challenge
module RG = Vela_session_policy.Registration_driver
module CI = Vela_session_policy.Challenge_issue_driver

// ── Outcome slices ─────────────────────────────────────────────────────────

/// The slice a classifier reads is the outcome list, element by element.
/// Nothing about the classifiers is restated here, so a changed classifier
/// fails the honesty theorems themselves.
let seq_of_list_facts (l: list t_StoreOutcome)
  : Lemma (forall (i: nat). i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
  let aux (i: nat) : Lemma (i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
    if i < L.length l then SP.lemma_seq_of_list_index l i
  in
  FStar.Classical.forall_intro aux

/// The first statement of a plan (plans here are never empty).
let first_stmt (l: list t_StoreStmt) : t_StoreStmt =
  match l with
  | st :: _ -> st
  | [] -> StoreStmt_RevokeJtis { f_device = Alloc.String.String "" }

/// The second statement of a plan.
let second_stmt (l: list t_StoreStmt) : t_StoreStmt =
  match l with
  | _ :: st :: _ -> st
  | _ -> first_stmt l

/// The key a `SetEx` writes, or the device a `RevokeJtis` names.
let stmt_key (st: t_StoreStmt) : text =
  match st with
  | StoreStmt_SetEx { f_key = k } -> k
  | StoreStmt_RevokeJtis { f_device = dev } -> dev
  | _ -> Alloc.String.String ""

/// The `jti:revoked:` marker the logout plan writes.
let logout_key (jti: text) : text = stmt_key (first_stmt (stmts_of (plan_logout jti)))

/// The `device:revoked:` sentinel the lockout plan writes.
let sentinel_key (dev: text) : text =
  stmt_key (second_stmt (stmts_of (plan_lockout_device dev)))

// ── Plan shapes ────────────────────────────────────────────────────────────

/// The plans the session executors run are the statements the extractor made;
/// these shape lemmas keep the honesty theorems dependent on the plans, so a
/// swapped or dropped plan statement fails them.

let plan_logout_shape (jti: text)
  : Lemma (L.length (stmts_of (plan_logout jti)) == 1 /\
           stmt_key (first_stmt (stmts_of (plan_logout jti))) == logout_key jti /\
           (match first_stmt (stmts_of (plan_logout jti)) with
            | StoreStmt_SetEx { f_key = _; f_value = value; f_ttl = ttl } ->
              value == mk_u8 1 /\ ttl == v_TOKEN_MAX_LIFETIME_SECS
            | _ -> False)) =
  ()

let plan_lockout_device_shape (dev: text)
  : Lemma (L.length (stmts_of (plan_lockout_device dev)) == 2 /\
           (match first_stmt (stmts_of (plan_lockout_device dev)) with
            | StoreStmt_RevokeJtis { f_device = swept } -> swept == dev
            | _ -> False) /\
           (match second_stmt (stmts_of (plan_lockout_device dev)) with
            | StoreStmt_SetEx { f_key = key; f_value = value; f_ttl = ttl } ->
              key == sentinel_key dev /\ value == mk_u8 1 /\
              ttl == v_TOKEN_MAX_LIFETIME_SECS
            | _ -> False)) =
  ()

let plan_scan_devices_shape (acct: text)
  : Lemma (plan_scan_devices acct == SqlStmt_SelectDeviceIdsByUser { f_user = acct }) =
  ()

let plan_scan_web_sessions_shape (acct: text)
  : Lemma (plan_scan_web_sessions acct == SqlStmt_SelectWebSessionIdsByUser { f_user = acct }) =
  ()

let plan_delete_users_shape (acct: text)
  : Lemma (plan_delete_users acct == SqlStmt_DeleteUserById { f_user = acct }) =
  ()

let plan_commit_shape ()
  : Lemma (plan_commit () == SqlStmt_Commit) =
  ()

let plan_target_lookup_shape (dev: text)
  : Lemma (plan_target_lookup dev == SqlStmt_SelectDeviceById { f_device_id = dev }) =
  ()

let plan_revoke_record_shape (dev now revoker: text)
  : Lemma (plan_revoke_record dev now revoker ==
           SqlStmt_RevokeDeviceRecord { f_now = now; f_revoked_by = revoker; f_device_id = dev }) =
  ()

let plan_cascade_read_shape (dev usr: text)
  : Lemma (plan_cascade_read dev usr ==
           SqlStmt_SelectWebSessionIdsApprovedBy { f_device_id = dev; f_user = usr }) =
  ()

let plan_cascade_update_shape (dev usr: text)
  : Lemma (plan_cascade_update dev usr ==
           SqlStmt_RevokeWebSessionsApprovedBy { f_device_id = dev; f_user = usr }) =
  ()

/// Every table's delete is the account-scoped statement the driver ordered.
let plan_delete_table_shape (acct: text) (table: D.t_DeletionTable)
  : Lemma
    (match table with
     | D.DeletionTable_WebSessions ->
       plan_delete_table acct table == SqlStmt_DeleteWebSessionsByUser { f_user = acct }
     | D.DeletionTable_ShareInbox ->
       plan_delete_table acct table == SqlStmt_DeleteShareInboxByUser { f_user = acct }
     | D.DeletionTable_SharedItems ->
       plan_delete_table acct table == SqlStmt_DeleteSharedItemsByUser { f_user = acct }
     | D.DeletionTable_Sends ->
       plan_delete_table acct table == SqlStmt_DeleteSendsByOwner { f_owner = acct }
     | D.DeletionTable_VaultChunks ->
       plan_delete_table acct table == SqlStmt_DeleteVaultChunksByUser { f_user = acct }
     | D.DeletionTable_OramBuckets ->
       plan_delete_table acct table == SqlStmt_DeleteOramBucketsByUser { f_user = acct }
     | D.DeletionTable_Devices ->
       plan_delete_table acct table == SqlStmt_DeleteDevicesByUser { f_user = acct }) =
  ()

// ── Logout: LogoutJtiIo::revoke_jti ────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"
/// The logout marker: `Applied` exactly when its one statement ran, and then
/// the marker key holds the marker value and nothing else changed; on failure
/// the store is unchanged.
let logout_is_honest (s: store) (jti: text) (f: option nat)
  : Lemma
    ((fst (logout_jti s jti f) == R.LogoutObservation_Applied <==> no_fault_in f 1) /\
     (fst (logout_jti s jti f) == R.LogoutObservation_Applied ==>
        (snd (logout_jti s jti f)).kv (logout_key jti) == Some v_one /\
        (snd (logout_jti s jti f)).sets == s.sets /\
        (snd (logout_jti s jti f)).revoked == s.revoked) /\
     (fst (logout_jti s jti f) == R.LogoutObservation_Applied ==>
        (forall (k: text). k <> logout_key jti ==>
           (snd (logout_jti s jti f)).kv k == s.kv k)) /\
     (fst (logout_jti s jti f) == R.LogoutObservation_Applied <==>
        (no_fault_in f 1 /\ (snd (logout_jti s jti f)).kv (logout_key jti) == Some v_one)) /\
     (fst (logout_jti s jti f) =!= R.LogoutObservation_Applied ==>
        snd (logout_jti s jti f) == s)) =
  plan_logout_shape jti;
  seq_of_list_facts (fst (run_store s (stmts_of (plan_logout jti)) 0 f))
#pop-options

// ── Revocation: RevokeDeviceIo::lockout_device ─────────────────────────────

#push-options "--fuel 4 --ifuel 2"
/// The lockout: `Applied` exactly when both statements ran (the JTI sweep and
/// then the sentinel); on success every tracked JTI is revoked, the tracking
/// set is cleared, the sentinel holds the marker and no other key changed; on
/// failure only the JTI sweep may have run (the sentinel is never written
/// when the sweep failed).
let lockout_device_is_honest (s: store) (dev: text) (f: option nat)
  : Lemma
    (let swept = exec_store s (first_stmt (stmts_of (plan_lockout_device dev))) in
     (fst (lockout_device s dev f) == R.LockoutObservation_Applied <==> no_fault_in f 2) /\
     (fst (lockout_device s dev f) == R.LockoutObservation_Applied ==>
        (snd (lockout_device s dev f)).kv (sentinel_key dev) == Some v_one /\
        (snd (lockout_device s dev f)).sets dev == [] /\
        (snd (lockout_device s dev f)).revoked == s.revoked @ s.sets dev) /\
     (fst (lockout_device s dev f) == R.LockoutObservation_Applied ==>
        (forall (k: text). k <> sentinel_key dev ==>
           (snd (lockout_device s dev f)).kv k == s.kv k)) /\
     (fst (lockout_device s dev f) == R.LockoutObservation_Applied <==>
        (no_fault_in f 2 /\
         (snd (lockout_device s dev f)).kv (sentinel_key dev) == Some v_one)) /\
     (fst (lockout_device s dev f) =!= R.LockoutObservation_Applied ==>
        (snd (lockout_device s dev f) == s \/ snd (lockout_device s dev f) == swept))) =
  plan_lockout_device_shape dev;
  seq_of_list_facts (fst (run_store s (stmts_of (plan_lockout_device dev)) 0 f))
#pop-options

// ── Revocation: RevokeDeviceIo::lookup_target ──────────────────────────────

/// What the stored device row says about the caller.
let target_truth (d: db) (caller dev: text) : R.t_DeviceLookupObservation =
  match lookup d.devices dev with
  | Some r ->
    R.DeviceLookupObservation_Present
      ({
          R.f_same_account = r.dv_user = caller;
          R.f_already_revoked = r.dv_revoked <> mk_i64 0
        } <: R.t_TargetObservation)
  | None -> R.DeviceLookupObservation_Absent

/// `lookup_target`: the observation is the stored row's truth; a failed query
/// is the storage failure.
let revoke_observe_is_honest (d: db) (caller dev: text) (f: option nat)
  : Lemma
    (revoke_observe d caller dev f ==
       (if faulted f 0 then R.DeviceLookupObservation_QueryFailed
        else target_truth d caller dev)) =
  plan_target_lookup_shape dev

// ── Revocation: RevokeDeviceIo::record_revocation ──────────────────────────

#push-options "--fuel 4 --ifuel 2"
/// The durable revocation record: `Updated` exactly when the one statement
/// ran, and then exactly the target row's revocation columns changed; on
/// failure the table is unchanged.
let revoke_record_is_honest (d: db) (dev now revoker: text) (f: option nat)
  : Lemma
    ((fst (revoke_record d dev now revoker f) == R.RecordObservation_Updated
        <==> no_fault_in f 1) /\
     (fst (revoke_record d dev now revoker f) == R.RecordObservation_Updated ==>
        snd (revoke_record d dev now revoker f) == st_revoke_device d dev now revoker) /\
     (fst (revoke_record d dev now revoker f) =!= R.RecordObservation_Updated ==>
        snd (revoke_record d dev now revoker f) == d)) =
  plan_revoke_record_shape dev now revoker
#pop-options

// ── Deletion: the scans and the ignored batch lockout ──────────────────────

#push-options "--fuel 4 --ifuel 2"
/// `scan_devices`: `Rows` exactly when the query ran, and then the ids are
/// exactly the account's device ids.
let scan_devices_is_honest (d: db) (acct: text)
      (v: Alloc.Vec.t_Vec text Alloc.Alloc.t_Global) (failed: bool)
  : Lemma
    ((fst (scan_devices d acct v failed) == D.ScanObservation_Rows <==> not failed) /\
     snd (scan_devices d acct v failed) ==
       (if failed then [] else ids_of (fun r -> r.dv_user = acct) d.devices)) =
  plan_scan_devices_shape acct

/// `scan_web_sessions`: the same for the sessions the account owns or
/// approved.
let scan_web_sessions_is_honest (d: db) (acct: text)
      (v: Alloc.Vec.t_Vec text Alloc.Alloc.t_Global) (failed: bool)
  : Lemma
    ((fst (scan_web_sessions d acct v failed) == D.ScanObservation_Rows <==> not failed) /\
     snd (scan_web_sessions d acct v failed) ==
       (if failed then []
        else ids_of (fun r -> r.ws_user = Some acct || r.ws_approver = Some acct)
               d.sessions)) =
  plan_scan_web_sessions_shape acct

/// A lockout batch whose failures are ignored reports `Applied`, whatever
/// happened (the observation is the historical constant, not a claim). Each
/// id's own effect is `lockout_device_is_honest`.
let ignored_lockout_reports_applied (s: store) (ids: list text)
      (plan_of: text -> list t_StoreStmt) (f: option nat)
  : Lemma (fst (lockout_scanned s ids plan_of f) == D.LockoutObservation_Applied) =
  ()
#pop-options

// ── Deletion: delete_table, delete_users, commit ───────────────────────────

/// The account rows of one table are gone and nothing else changed.
let account_rows_removed (d post: db) (acct: text) (table: D.t_DeletionTable) : prop =
  match table with
  | D.DeletionTable_WebSessions -> post == st_web_sessions d acct
  | D.DeletionTable_ShareInbox -> post == st_share_inbox d acct
  | D.DeletionTable_SharedItems -> post == st_shared_items d acct
  | D.DeletionTable_Sends -> post == st_sends d acct
  | D.DeletionTable_VaultChunks -> post == st_vault_chunks d acct
  | D.DeletionTable_OramBuckets -> post == st_oram_buckets d acct
  | D.DeletionTable_Devices -> post == st_devices_of_user d acct

#push-options "--fuel 4 --ifuel 2"
/// One account-scoped `DELETE`: `Deleted` exactly when its one statement ran,
/// and then exactly that table's account rows are gone; on failure unchanged.
let delete_table_is_honest (d: db) (acct: text) (table: D.t_DeletionTable) (f: option nat)
  : Lemma
    ((fst (delete_table d acct table f) == D.TableDeleteObservation_Deleted
        <==> no_fault_in f 1) /\
     (fst (delete_table d acct table f) == D.TableDeleteObservation_Deleted ==>
        account_rows_removed d (snd (delete_table d acct table f)) acct table) /\
     (fst (delete_table d acct table f) =!= D.TableDeleteObservation_Deleted ==>
        snd (delete_table d acct table f) == d)) =
  plan_delete_table_shape acct table

/// The transaction begin: `Begun` exactly when it ran; it changes no table.
let begin_tx_is_honest (d: db) (f: option nat)
  : Lemma
    ((fst (begin_tx d f) == D.TransactionObservation_Begun <==> no_fault_in f 1) /\
     snd (begin_tx d f) == d) =
  ()

/// The `users` delete's row count is exactly the account's existence.
let delete_users_is_honest (d: db) (acct: text) (f: option nat)
  : Lemma
    ((fst (delete_users d acct f) == D.UsersDeleteObservation_Deleted <==>
        (Some? (lookup d.users acct) /\ no_fault_in f 1)) /\
     (fst (delete_users d acct f) == D.UsersDeleteObservation_Absent <==>
        (None? (lookup d.users acct) /\ no_fault_in f 1)) /\
     (fst (delete_users d acct f) == D.UsersDeleteObservation_Failed <==>
        faulted f 0) /\
     (fst (delete_users d acct f) == D.UsersDeleteObservation_Deleted ==>
        snd (delete_users d acct f) == st_delete_user d acct) /\
     (fst (delete_users d acct f) =!= D.UsersDeleteObservation_Deleted ==>
        snd (delete_users d acct f) == d)) =
  plan_delete_users_shape acct

/// The commit: `Committed` exactly when it ran; it changes no table itself
/// (publishing the transaction is `run_tx`'s job).
let commit_is_honest (d: db) (f: option nat)
  : Lemma
    ((fst (commit_tx d f) == D.CommitObservation_Committed <==> no_fault_in f 1) /\
     snd (commit_tx d f) == d) =
  plan_commit_shape ()
#pop-options

// ── Facts the session drivers rely on ──────────────────────────────────────

/// A logout marker the driver answered `Complete` for is in the store: the
/// JTI is revoked for the marker's lifetime.
let logout_completes_only_with_the_marker (s: store) (jti: text) (f: option nat)
  : Lemma
    (fst (logout_jti s jti f) == R.LogoutObservation_Applied ==>
       (snd (logout_jti s jti f)).kv (logout_key jti) == Some v_one) =
  logout_is_honest s jti f

/// A revocation the driver answered `Complete` for left the target locked
/// out: the sentinel is in the store and every tracked JTI is revoked.
let revocation_completes_only_locked_out (s: store) (dev: text) (f: option nat)
  : Lemma
    (fst (lockout_device s dev f) == R.LockoutObservation_Applied ==>
       (snd (lockout_device s dev f)).kv (sentinel_key dev) == Some v_one /\
       (snd (lockout_device s dev f)).sets dev == [] /\
       (snd (lockout_device s dev f)).revoked == s.revoked @ s.sets dev) =
  lockout_device_is_honest s dev f

/// The revocation lookup authorizes only a stored row: `Present` means the
/// row exists, and its `same_account`/`already_revoked` are the row's truth.
let lookup_observes_only_stored_rows (d: db) (caller dev: text) (f: option nat)
  : Lemma
    (match revoke_observe d caller dev f with
     | R.DeviceLookupObservation_Present facts ->
       (match lookup d.devices dev with
        | Some r -> facts.R.f_same_account == (r.dv_user = caller) /\
                    facts.R.f_already_revoked == (r.dv_revoked <> mk_i64 0)
        | None -> False)
     | _ -> True) =
  revoke_observe_is_honest d caller dev f

/// Deletion's `users` observation is the account-existence signal the driver
/// commits on: `Deleted` exactly when the account row was there.
let account_existed_exactly_when_deleted (d: db) (acct: text) (f: option nat)
  : Lemma
    (fst (delete_users d acct f) == D.UsersDeleteObservation_Deleted ==>
       Some? (lookup d.users acct)) =
  delete_users_is_honest d acct f

/// The revocation record sets exactly the target's `revoked` columns.
let record_revokes_exactly_the_target (d: db) (dev now revoker: text) (f: option nat)
  : Lemma
    (fst (revoke_record d dev now revoker f) == R.RecordObservation_Updated ==>
       snd (revoke_record d dev now revoker f) == st_revoke_device d dev now revoker) =
  revoke_record_is_honest d dev now revoker f

// ── Vectors shared with `store_model.rs::tests::shared_vectors` ────────────

let s (x: string) : text = Alloc.String.String x

let vector_store : store =
  { kv = (fun _ -> None); sets = (fun _ -> []); revoked = []; counters = (fun _ -> 0); streaks = (fun _ -> 0) }

let vector_logout ()
  : Lemma (let (obs, post) = logout_jti vector_store (s "j") None in
           obs == R.LogoutObservation_Applied /\
           post.kv (logout_key (s "j")) == Some v_one) =
  logout_is_honest vector_store (s "j") None

let vector_logout_fault ()
  : Lemma (let (obs, post) = logout_jti vector_store (s "j") (Some 0) in
           obs == R.LogoutObservation_StorageFailed /\ post == vector_store) =
  logout_is_honest vector_store (s "j") (Some 0)

let vector_locked_jtis : store =
  { kv = (fun _ -> None);
    sets = (fun k -> if k = s "dev" then [s "j1"; s "j2"] else []);
    revoked = [];
    counters = (fun _ -> 0);
    streaks = (fun _ -> 0) }

let vector_lockout ()
  : Lemma (let (obs, post) = lockout_device vector_locked_jtis (s "dev") None in
           obs == R.LockoutObservation_Applied /\
           post.kv (sentinel_key (s "dev")) == Some v_one /\
           post.sets (s "dev") == [] /\
           post.revoked == [s "j1"; s "j2"]) =
  lockout_device_is_honest vector_locked_jtis (s "dev") None

let vector_lockout_fault ()
  : Lemma (let (obs, post) = lockout_device vector_locked_jtis (s "dev") (Some 0) in
           obs == R.LockoutObservation_StorageFailed /\ post == vector_locked_jtis) =
  lockout_device_is_honest vector_locked_jtis (s "dev") (Some 0)

// ── Login: VerifyIo ────────────────────────────────────────────────────────

/// The challenge key the take plan removes.
let take_key (challenge: text) : text =
  match first_stmt (stmts_of (plan_take_challenge challenge)) with
  | StoreStmt_Take { f_key = k } -> k
  | _ -> Alloc.String.String ""

/// The failed-proof counter key and its ceiling.
let counter_key (ip dev: text) : text =
  match first_stmt (stmts_of (plan_failure_counter ip dev)) with
  | StoreStmt_Incr { f_key = k } -> k
  | _ -> Alloc.String.String ""

/// The outcome the counter statement itself produced on a store.
let counter_out (s: store) (ip dev: text) : t_StoreOutcome =
  match stmts_of (plan_failure_counter ip dev) with
  | st :: _ -> fst (exec_store_out s st)
  | [] -> StoreOutcome_Failed

/// The backoff record's two keys.
let streak_key (ip dev: text) : text =
  match first_stmt (stmts_of (plan_backoff_record ip dev)) with
  | StoreStmt_BackoffFailure { f_streak = k } -> k
  | _ -> Alloc.String.String ""

let backoff_key (ip dev: text) : text =
  match first_stmt (stmts_of (plan_backoff_record ip dev)) with
  | StoreStmt_BackoffFailure { f_backoff = k } -> k
  | _ -> Alloc.String.String ""

/// The reset's two keys.
let reset_streak_key (ip dev: text) : text =
  match first_stmt (stmts_of (plan_reset_login_streak ip dev)) with
  | StoreStmt_ResetBackoff { f_streak = k } -> k
  | _ -> Alloc.String.String ""

let reset_backoff_key (ip dev: text) : text =
  match first_stmt (stmts_of (plan_reset_login_streak ip dev)) with
  | StoreStmt_ResetBackoff { f_backoff = k } -> k
  | _ -> Alloc.String.String ""

/// The tracked-JTI set the add plan writes.
let track_key (dev: text) : text =
  match first_stmt (stmts_of (plan_track_jti dev (Alloc.String.String ""))) with
  | StoreStmt_AddMember { f_key = k } -> k
  | _ -> Alloc.String.String ""

let plan_take_challenge_shape (challenge: text)
  : Lemma (L.length (stmts_of (plan_take_challenge challenge)) == 1 /\
           (match first_stmt (stmts_of (plan_take_challenge challenge)) with
            | StoreStmt_Take { f_key = k } -> k == take_key challenge
            | _ -> False)) =
  ()

let plan_login_device_shape (dev: text)
  : Lemma (plan_login_device dev ==
           SqlStmt_SelectUnrevokedDeviceById { f_device_id = dev }) =
  ()

let plan_backoff_record_shape (ip dev: text)
  : Lemma (L.length (stmts_of (plan_backoff_record ip dev)) == 1 /\
           (match first_stmt (stmts_of (plan_backoff_record ip dev)) with
            | StoreStmt_BackoffFailure { f_streak = st; f_backoff = bo } ->
              st == streak_key ip dev /\ bo == backoff_key ip dev
            | _ -> False)) =
  ()

let plan_failure_counter_shape (ip dev: text)
  : Lemma (L.length (stmts_of (plan_failure_counter ip dev)) == 1 /\
           (match first_stmt (stmts_of (plan_failure_counter ip dev)) with
            | StoreStmt_Incr { f_key = k; f_limit = lim; f_ttl = ttl } ->
              k == counter_key ip dev /\ lim == v_VERIFY_FAIL_LIMIT /\
              ttl == v_VERIFY_FAIL_WINDOW_SECS
            | _ -> False)) =
  ()

let plan_reset_login_streak_shape (ip dev: text)
  : Lemma (L.length (stmts_of (plan_reset_login_streak ip dev)) == 1 /\
           (match first_stmt (stmts_of (plan_reset_login_streak ip dev)) with
            | StoreStmt_ResetBackoff { f_streak = st; f_backoff = bo } ->
              st == reset_streak_key ip dev /\ bo == reset_backoff_key ip dev
            | _ -> False)) =
  ()

let plan_track_jti_shape (dev jti: text)
  : Lemma (L.length (stmts_of (plan_track_jti dev jti)) == 1 /\
           (match first_stmt (stmts_of (plan_track_jti dev jti)) with
            | StoreStmt_AddMember { f_key = k; f_member = m; f_ttl = ttl } ->
              k == track_key dev /\ m == jti /\ ttl == v_JTI_SET_TTL_SECS
            | _ -> False)) =
  ()

let plan_login_last_active_shape (dev now: text)
      (nm kd: Core_models.Option.t_Option text)
  : Lemma
    (match nm, kd with
     | Core_models.Option.Option_Some n,
       Core_models.Option.Option_Some k ->
       plan_login_last_active dev now nm kd ==
         SqlStmt_UpdateDeviceLastActiveNamed
           { f_now = now; f_name = n; f_kind = k; f_device_id = dev }
     | _ ->
       plan_login_last_active dev now nm kd ==
         SqlStmt_UpdateDeviceLastActive { f_now = now; f_device_id = dev }) =
  ()

#push-options "--fuel 4 --ifuel 2"
/// The challenge take reports storage failure exactly when it failed.
let login_challenge_storage_failed (s: store) (challenge tag: text) (f: option nat)
  : Lemma
    (fst (login_challenge s challenge tag f) ==
       LG.ChallengeObservation_StorageFailed <==> faulted f 0) =
  plan_take_challenge_shape challenge

/// Acceptance is exactly the stored value being this consumer's tag.
let login_challenge_accepts (s: store) (challenge tag: text) (f: option nat)
  : Lemma
    (fst (login_challenge s challenge tag f) ==
        LG.ChallengeObservation_Observed LGC.ChallengeConsumption_Accepted
       <==> (not (faulted f 0) /\
            s.kv (take_key challenge) == Some tag)) =
  plan_take_challenge_shape challenge;
  cm_option_some (s.kv (take_key challenge)) tag

/// An absent value is `Missing`.
let login_challenge_missing (s: store) (challenge tag: text) (f: option nat)
  : Lemma
    (fst (login_challenge s challenge tag f) ==
        LG.ChallengeObservation_Observed LGC.ChallengeConsumption_Missing
       <==> (not (faulted f 0) /\ s.kv (take_key challenge) == None)) =
  plan_take_challenge_shape challenge;
  cm_option_none (s.kv (take_key challenge))

/// A failed take changes nothing; a successful one changes only the key.
let login_challenge_store (s: store) (challenge tag: text) (f: option nat)
  : Lemma
    ((faulted f 0 ==> snd (login_challenge s challenge tag f) == s) /\
     (snd (login_challenge s challenge tag f)).sets == s.sets /\
     (snd (login_challenge s challenge tag f)).revoked == s.revoked /\
     (snd (login_challenge s challenge tag f)).counters == s.counters) =
  plan_take_challenge_shape challenge

/// The take's post state: the one key is gone, every other key is unchanged.
let login_challenge_removes_only_its_key (s: store) (challenge tag: text)
      (f: option nat)
  : Lemma
    (not (faulted f 0) ==>
       (forall (k: text). (snd (login_challenge s challenge tag f)).kv k ==
          (if k = take_key challenge then None else s.kv k))) =
  plan_take_challenge_shape challenge

/// The unrevoked-device lookup is exactly what the query and decoder saw: a
/// failed query, no `revoked = 0` row, a row that did not decode, or one row.
let login_device_is_honest (d: db) (dev: text) (failed undecodable: bool)
  : Lemma
    (observe_device d dev failed undecodable ==
       (if failed then LG.DeviceObservation_QueryFailed
        else match lookup d.devices dev with
             | None -> LG.DeviceObservation_Absent
             | Some r ->
               if r.dv_revoked <> mk_i64 0 then LG.DeviceObservation_Absent
               else if undecodable then LG.DeviceObservation_ParseFailed
               else LG.DeviceObservation_Present)) =
  ()

/// A `Present` observation is only ever a stored, unrevoked, decoded row.
let login_present_observes_the_stored_row (d: db) (dev: text) (r: device_row)
      (failed undecodable: bool)
  : Lemma
    (lookup d.devices dev == Some r ==>
       (observe_device d dev failed undecodable == LG.DeviceObservation_Present
        <==> (not failed /\ not undecodable /\ r.dv_revoked = mk_i64 0))) =
  ()

/// The failed-proof side effects: the counter's own outcome is the only thing
/// the observation reports; the log-only record's failure never changes it.
let login_failure_counter_reports_its_run (s: store) (ip dev: text)
      (f: option nat)
  : Lemma
    (let obs = fst (login_failure_record s ip dev f) in
     obs.LG.f_fallback_counter_ok
       <==> (not (faulted f 1) /\ counter_out s ip dev == StoreOutcome_Applied)) =
  plan_backoff_record_shape ip dev;
  plan_failure_counter_shape ip dev

/// The two side effects' own state changes: the counter grew unless its call
/// failed, and the log-only record grew the streak unless its call failed.
let login_failure_record_state (s: store) (ip dev: text) (f: option nat)
  : Lemma
    (let post = snd (login_failure_record s ip dev f) in
     post.counters (counter_key ip dev) ==
       (if faulted f 1 then s.counters (counter_key ip dev)
        else s.counters (counter_key ip dev) + 1) /\
     (not (faulted f 0) ==>
        post.streaks (streak_key ip dev) == s.streaks (streak_key ip dev) + 1)) =
  plan_backoff_record_shape ip dev;
  plan_failure_counter_shape ip dev

/// The streak reset: `StorageFailed` exactly when its statement failed; on
/// success the streak and backoff marker are gone, and the database is either
/// the best-effort stamp or unchanged when that stamp failed.
let login_reset_is_honest (s: store) (d: db) (ip dev now: text)
      (nm kd: Core_models.Option.t_Option text) (f: option nat)
  : Lemma
    (let (obs, st, d') = login_reset s d ip dev now nm kd f in
     (obs == LG.BackoffResetObservation_Reset <==> not (faulted f 0)) /\
     (faulted f 0 ==> st == s /\ d' == d) /\
     (not (faulted f 0) ==>
        st.streaks (reset_streak_key ip dev) == 0 /\
        st.kv (reset_backoff_key ip dev) == None /\
        st.sets == s.sets /\
        st.revoked == s.revoked) /\
     (not (faulted f 0) ==>
        (if faulted f 1 then d' == d
         else d' == login_stamp d dev now nm kd))) =
  plan_reset_login_streak_shape ip dev;
  plan_login_last_active_shape dev now nm kd

/// JTI tracking: `Tracked` exactly when the add ran, and then the member is in
/// the one set, no other set changed, and no key, JTI revocation or counter
/// changed; on failure the store is unchanged.
let login_track_is_honest (s: store) (dev jti: text) (f: option nat)
  : Lemma
    ((fst (login_track s dev jti f) == LG.TokenTrackObservation_Tracked
       <==> no_fault_in f 1) /\
     (fst (login_track s dev jti f) == LG.TokenTrackObservation_Tracked ==>
        L.mem jti ((snd (login_track s dev jti f)).sets (track_key dev)) /\
        (forall (k: text). k <> track_key dev ==>
           (snd (login_track s dev jti f)).sets k == s.sets k) /\
        (snd (login_track s dev jti f)).kv == s.kv /\
        (snd (login_track s dev jti f)).revoked == s.revoked /\
        (snd (login_track s dev jti f)).counters == s.counters) /\
     (fst (login_track s dev jti f) =!= LG.TokenTrackObservation_Tracked ==>
        snd (login_track s dev jti f) == s)) =
  plan_track_jti_shape dev jti
#pop-options

// ── Login facts the driver relies on ───────────────────────────────────────

/// A login that observed a present device got a stored, unrevoked row.
let login_completes_only_with_the_unrevoked_row (d: db) (dev: text)
      (failed undecodable: bool)
  : Lemma
    (observe_device d dev failed undecodable == LG.DeviceObservation_Present ==>
       (not failed /\ not undecodable /\
        (exists (r: device_row).
           lookup d.devices dev == Some r /\ r.dv_revoked = mk_i64 0))) =
  ()

/// A login whose challenge take was accepted really removed this consumer's
/// tag from the one challenge key.
let login_accepts_only_its_stored_tag (s: store) (challenge tag: text)
      (f: option nat)
  : Lemma
    (fst (login_challenge s challenge tag f) ==
       LG.ChallengeObservation_Observed LGC.ChallengeConsumption_Accepted ==>
       s.kv (take_key challenge) == Some tag /\
       (snd (login_challenge s challenge tag f)).kv (take_key challenge) == None) =
  login_challenge_accepts s challenge tag f;
  login_challenge_store s challenge tag f

/// A tracked login JTI can be revoked by the device-revocation sweep: the add
/// landed in the device's set.
let login_tracks_the_issued_jti (s: store) (dev jti: text) (f: option nat)
  : Lemma
    (fst (login_track s dev jti f) == LG.TokenTrackObservation_Tracked ==>
       L.mem jti ((snd (login_track s dev jti f)).sets (track_key dev))) =
  login_track_is_honest s dev jti f

let vector_challenge_store : store =
  { kv = (fun k -> if k = take_key (s "c") then Some (s "login") else None);
    sets = (fun _ -> []); revoked = []; counters = (fun _ -> 0); streaks = (fun _ -> 0) }

let vector_login_challenge ()
  : Lemma (let (obs, post) =
             login_challenge vector_challenge_store (s "c") (s "login") None in
           obs == LG.ChallengeObservation_Observed LGC.ChallengeConsumption_Accepted /\
           post.kv (take_key (s "c")) == None) =
  login_challenge_accepts vector_challenge_store (s "c") (s "login") None;
  login_challenge_store vector_challenge_store (s "c") (s "login") None

let vector_login_challenge_missing ()
  : Lemma (let (obs, _) = login_challenge vector_store (s "c") (s "login") None in
           obs == LG.ChallengeObservation_Observed LGC.ChallengeConsumption_Missing) =
  login_challenge_missing vector_store (s "c") (s "login") None

let vector_login_track ()
  : Lemma (let (obs, post) = login_track vector_store (s "dev") (s "jti") None in
           obs == LG.TokenTrackObservation_Tracked /\
           L.mem (s "jti") (post.sets (track_key (s "dev")))) =
  login_track_is_honest vector_store (s "dev") (s "jti") None

// ── Registration and challenge ─────────────────────────────────────────────

/// The per-IP challenge limiter's key.
let challenge_rate_key (ip: text) : text =
  match first_stmt (stmts_of (plan_challenge_rate_limit ip)) with
  | StoreStmt_Incr { f_key = k } -> k
  | _ -> Alloc.String.String ""

/// The one counter statement's own outcome on a store.
let challenge_rate_out (s: store) (ip: text) : t_StoreOutcome =
  match stmts_of (plan_challenge_rate_limit ip) with
  | st :: _ -> fst (exec_store_out s st)
  | [] -> StoreOutcome_Failed

/// The per-IP registration limiter's key.
let registration_rate_key (ip: text) : text =
  match first_stmt (stmts_of (plan_registration_rate_limit ip)) with
  | StoreStmt_Incr { f_key = k } -> k
  | _ -> Alloc.String.String ""

let registration_rate_out (s: store) (ip: text) : t_StoreOutcome =
  match stmts_of (plan_registration_rate_limit ip) with
  | st :: _ -> fst (exec_store_out s st)
  | [] -> StoreOutcome_Failed

/// The challenge key and the tag the issue plan writes under it.
let nonce_key (challenge: text) : text =
  match first_stmt (stmts_of (plan_store_nonce challenge (Alloc.String.String ""))) with
  | StoreStmt_SetExNx { f_key = k } -> k
  | _ -> Alloc.String.String ""

let nonce_value (challenge tag: text) : text =
  match first_stmt (stmts_of (plan_store_nonce challenge tag)) with
  | StoreStmt_SetExNx { f_value = v } -> v
  | _ -> Alloc.String.String ""

// ── Plan shapes ────────────────────────────────────────────────────────────

let plan_account_count_shape ()
  : Lemma (plan_account_count () == SqlStmt_CountUsers) =
  ()

let plan_insert_account_shape (usr now ek since: text)
  : Lemma (plan_insert_account usr now ek since ==
           SqlStmt_InsertUser { f_user = usr; f_now = now;
                                f_share_ek = ek; f_share_ek_since = since }) =
  ()

let plan_insert_device_shape (dev usr nm kd now ek vk: text)
  : Lemma (plan_insert_device dev usr nm kd now ek vk ==
           SqlStmt_InsertDevice { f_device = dev; f_user = usr; f_name = nm;
                                  f_kind = kd; f_now = now; f_ek = ek; f_vk = vk }) =
  ()

let plan_challenge_rate_limit_shape (ip: text)
  : Lemma (L.length (stmts_of (plan_challenge_rate_limit ip)) == 1 /\
           (match first_stmt (stmts_of (plan_challenge_rate_limit ip)) with
            | StoreStmt_Incr { f_key = k; f_limit = lim; f_ttl = ttl } ->
              k == challenge_rate_key ip /\ lim == v_CHALLENGE_RATE_LIMIT /\
              ttl == v_CHALLENGE_RATE_WINDOW_SECS
            | _ -> False)) =
  ()

let plan_registration_rate_limit_shape (ip: text)
  : Lemma (L.length (stmts_of (plan_registration_rate_limit ip)) == 1 /\
           (match first_stmt (stmts_of (plan_registration_rate_limit ip)) with
            | StoreStmt_Incr { f_key = k; f_limit = lim; f_ttl = ttl } ->
              k == registration_rate_key ip /\ lim == v_REGISTER_RATE_LIMIT /\
              ttl == v_REGISTER_RATE_WINDOW_SECS
            | _ -> False)) =
  ()

let plan_store_nonce_shape (challenge tag: text)
  : Lemma (L.length (stmts_of (plan_store_nonce challenge tag)) == 1 /\
           (match first_stmt (stmts_of (plan_store_nonce challenge tag)) with
            | StoreStmt_SetExNx { f_key = k; f_value = v; f_ttl = ttl } ->
              k == nonce_key challenge /\ v == tag /\
              ttl == v_CHALLENGE_TTL_SECS
            | _ -> False)) =
  ()

let plan_registration_plan_shape (usr dev now sek since nm kd dek vk: text)
  : Lemma (registration_plan usr dev now sek since nm kd dek vk ==
           [ plan_insert_account usr now sek since;
             plan_insert_device dev usr nm kd now dek vk;
             plan_commit () ]) =
  ()

// ── Account budget and the two limiters ────────────────────────────────────

/// `check_account_budget`: `Counted` exactly when the query ran, carrying the
/// exact number of `users` rows.
let account_count_is_honest (d: db) (failed: bool)
  : Lemma
    (fst (account_count d failed) ==
       (if failed then RG.BudgetObservation_QueryFailed
        else RG.BudgetObservation_Counted { f_count = users_count d }) /\
     snd (account_count d failed) == (if failed then mk_i64 0 else users_count d)) =
  plan_account_count_shape ()

/// The registration limiter allows exactly the calls its counter still has
/// room for, and counts every call it made.
let registration_rate_limit_is_honest (s: store) (ip: text) (f: option nat)
  : Lemma
    ((fst (registration_rate_limit s ip f) == RG.RateLimitObservation_Allowed
        <==> (not (faulted f 0) /\ registration_rate_out s ip == StoreOutcome_Applied)) /\
     (snd (registration_rate_limit s ip f)).counters (registration_rate_key ip) ==
       (if faulted f 0 then s.counters (registration_rate_key ip)
        else s.counters (registration_rate_key ip) + 1) /\
     (snd (registration_rate_limit s ip f)).kv == s.kv /\
     (snd (registration_rate_limit s ip f)).sets == s.sets) =
  plan_registration_rate_limit_shape ip

/// The challenge limiter, the same way.
let challenge_rate_limit_is_honest (s: store) (ip: text) (f: option nat)
  : Lemma
    ((fst (challenge_rate_limit s ip f) == CI.RateLimitObservation_Allowed
        <==> (not (faulted f 0) /\ challenge_rate_out s ip == StoreOutcome_Applied)) /\
     (snd (challenge_rate_limit s ip f)).counters (challenge_rate_key ip) ==
       (if faulted f 0 then s.counters (challenge_rate_key ip)
        else s.counters (challenge_rate_key ip) + 1) /\
     (snd (challenge_rate_limit s ip f)).kv == s.kv /\
     (snd (challenge_rate_limit s ip f)).sets == s.sets) =
  plan_challenge_rate_limit_shape ip

// ── The two registration inserts ───────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"
/// `insert_account`: `Inserted` exactly when the one statement ran on a fresh
/// id, and then exactly that one `users` row is added; a duplicate id or an
/// injected failure changes nothing.
let insert_account_is_honest (d: db) (usr now ek since: text) (f: option nat)
  : Lemma
    ((fst (insert_account d usr now ek since f) == RG.InsertObservation_Inserted
        <==> (no_fault_in f 1 /\ lookup d.users usr == None)) /\
     (fst (insert_account d usr now ek since f) == RG.InsertObservation_Inserted ==>
        snd (insert_account d usr now ek since f) == st_insert_user d usr now ek since) /\
     (fst (insert_account d usr now ek since f) =!= RG.InsertObservation_Inserted ==>
        snd (insert_account d usr now ek since f) == d)) =
  plan_insert_account_shape usr now ek since

/// `insert_device`: the same for the one `devices` row, carrying the exact
/// owner, name, type and keys the plan named.
let insert_device_is_honest (d: db) (dev usr now nm kd ek vk: text) (f: option nat)
  : Lemma
    ((fst (insert_device d dev usr now nm kd ek vk f) == RG.InsertObservation_Inserted
        <==> (no_fault_in f 1 /\ lookup d.devices dev == None)) /\
     (fst (insert_device d dev usr now nm kd ek vk f) == RG.InsertObservation_Inserted ==>
        snd (insert_device d dev usr now nm kd ek vk f) ==
          st_insert_device d dev usr now nm kd ek vk) /\
     (fst (insert_device d dev usr now nm kd ek vk f) =!= RG.InsertObservation_Inserted ==>
        snd (insert_device d dev usr now nm kd ek vk f) == d)) =
  plan_insert_device_shape dev usr nm kd now ek vk
#pop-options

/// `begin_transaction`: `Begun` exactly when it ran; no table changes.
let registration_begin_is_honest (d: db) (f: option nat)
  : Lemma
    ((fst (registration_begin d f) == RG.TransactionObservation_Begun <==>
        no_fault_in f 1) /\
     snd (registration_begin d f) == d) =
  ()

/// `commit`: `Committed` exactly when it ran.
let registration_commit_is_honest (d: db) (f: option nat)
  : Lemma
    ((fst (registration_commit d f) == RG.CommitObservation_Committed <==>
        no_fault_in f 1) /\
     snd (registration_commit d f) == d) =
  plan_commit_shape ()

#push-options "--fuel 4 --ifuel 2"
/// `track_token`: `Tracked` exactly when the one set add ran, and then the JTI
/// is in the device's tracked set and nothing else changed.
let registration_track_is_honest (s: store) (dev jti: text) (f: option nat)
  : Lemma
    ((fst (registration_track s dev jti f) == RG.TrackObservation_Tracked
        <==> no_fault_in f 1) /\
     (fst (registration_track s dev jti f) == RG.TrackObservation_Tracked ==>
        L.mem jti ((snd (registration_track s dev jti f)).sets (track_key dev)) /\
        (forall (k: text). k <> track_key dev ==>
           (snd (registration_track s dev jti f)).sets k == s.sets k) /\
        (snd (registration_track s dev jti f)).kv == s.kv /\
        (snd (registration_track s dev jti f)).revoked == s.revoked) /\
     (fst (registration_track s dev jti f) =!= RG.TrackObservation_Tracked ==>
        snd (registration_track s dev jti f) == s)) =
  plan_track_jti_shape dev jti
#pop-options

// ── The challenge write ────────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"
/// `store_nonce`: `Inserted` exactly when the key was absent and the write
/// ran; a collision is reported without touching the live challenge, and a
/// failed call changes nothing.
let challenge_nonce_is_honest (s: store) (challenge tag: text) (f: option nat)
  : Lemma
    ((fst (challenge_nonce s challenge tag f) == CI.StoreObservation_Inserted
        <==> (no_fault_in f 1 /\ s.kv (nonce_key challenge) == None)) /\
     (fst (challenge_nonce s challenge tag f) == CI.StoreObservation_KeyExists
        <==> (no_fault_in f 1 /\ Some? (s.kv (nonce_key challenge)))) /\
     (fst (challenge_nonce s challenge tag f) == CI.StoreObservation_Failed
        <==> faulted f 0) /\
     (fst (challenge_nonce s challenge tag f) == CI.StoreObservation_Inserted ==>
        (snd (challenge_nonce s challenge tag f)).kv (nonce_key challenge) ==
          Some (tag) /\
        (forall (k: text). k <> nonce_key challenge ==>
           (snd (challenge_nonce s challenge tag f)).kv k == s.kv k)) /\
     (fst (challenge_nonce s challenge tag f) == CI.StoreObservation_KeyExists ==>
        snd (challenge_nonce s challenge tag f) == s) /\
     (fst (challenge_nonce s challenge tag f) == CI.StoreObservation_Failed ==>
        snd (challenge_nonce s challenge tag f) == s)) =
  plan_store_nonce_shape challenge tag
#pop-options

// ── The registration transaction ───────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"
/// The whole registration transaction: when the commit ran and both ids were
/// fresh, exactly the two intended rows are published; otherwise the state is
/// exactly the one the transaction began from (the handler drops it).
let registration_tx_is_honest (d: db) (usr dev now sek since nm kd dek vk: text)
      (f: option nat)
  : Lemma
    (let (outs, post) = registration_transaction d usr dev now sek since nm kd dek vk f in
     ((no_fault_in f 3 /\ lookup d.users usr == None /\ lookup d.devices dev == None) ==>
        (post == registration_published d usr dev now sek since nm kd dek vk /\
         L.length outs == 3)) /\
     (~(no_fault_in f 3 /\ lookup d.users usr == None /\ lookup d.devices dev == None) ==>
        post == d)) =
  plan_registration_plan_shape usr dev now sek since nm kd dek vk
#pop-options

// ── Facts the registration and challenge drivers rely on ───────────────────

/// An `Inserted` observation is only ever a stored row.
let inserted_account_is_stored (d: db) (usr now ek since: text) (f: option nat)
  : Lemma
    (fst (insert_account d usr now ek since f) == RG.InsertObservation_Inserted ==>
       Some? (lookup (snd (insert_account d usr now ek since f)).users usr)) =
  insert_account_is_honest d usr now ek since f

let inserted_device_is_stored (d: db) (dev usr now nm kd ek vk: text) (f: option nat)
  : Lemma
    (fst (insert_device d dev usr now nm kd ek vk f) == RG.InsertObservation_Inserted ==>
       Some? (lookup (snd (insert_device d dev usr now nm kd ek vk f)).devices dev)) =
  insert_device_is_honest d dev usr now nm kd ek vk f

/// A published registration really holds the account row and the device row
/// that names it.
let registration_publishes_both_rows (d: db) (usr dev now sek since nm kd dek vk: text)
      (f: option nat)
  : Lemma
    ((no_fault_in f 3 /\ lookup d.users usr == None /\ lookup d.devices dev == None) ==>
       (Some? (lookup (snd (registration_transaction d usr dev now sek since nm kd dek vk f)).users usr) /\
        Some? (lookup (snd (registration_transaction d usr dev now sek since nm kd dek vk f)).devices dev) /\
        (match lookup (snd (registration_transaction d usr dev now sek since nm kd dek vk f)).devices dev with
         | Some r -> r.dv_user == usr
         | None -> False))) =
  registration_tx_is_honest d usr dev now sek since nm kd dek vk f

/// The account budget counts exactly the stored accounts.
let budget_counts_the_stored_accounts (d: db) (failed: bool)
  : Lemma
    (fst (account_count d failed) == RG.BudgetObservation_QueryFailed \/
     (match fst (account_count d failed) with
      | RG.BudgetObservation_Counted facts -> facts.RG.f_count == users_count d
      | _ -> False)) =
  plan_account_count_shape ()

/// An issued challenge is stored under its nonce key with the purpose tag,
/// and nothing else was touched.
let challenge_issued_nonce_is_stored (s: store) (challenge tag: text) (f: option nat)
  : Lemma
    (fst (challenge_nonce s challenge tag f) == CI.StoreObservation_Inserted ==>
       (snd (challenge_nonce s challenge tag f)).kv (nonce_key challenge) ==
         Some (tag)) =
  challenge_nonce_is_honest s challenge tag f

/// A collision never overwrites the live challenge.
let challenge_collision_keeps_the_live_nonce (s: store) (challenge tag: text)
      (f: option nat)
  : Lemma
    (fst (challenge_nonce s challenge tag f) == CI.StoreObservation_KeyExists ==>
       snd (challenge_nonce s challenge tag f) == s) =
  challenge_nonce_is_honest s challenge tag f

/// A tracked registration JTI can be revoked by the device-revocation sweep.
let registration_tracks_the_issued_jti (s: store) (dev jti: text) (f: option nat)
  : Lemma
    (fst (registration_track s dev jti f) == RG.TrackObservation_Tracked ==>
       L.mem jti ((snd (registration_track s dev jti f)).sets (track_key dev))) =
  registration_track_is_honest s dev jti f

// ── Vectors shared with `store_model.rs::tests` ────────────────────────────

let vector_challenge_nonce ()
  : Lemma (let (obs, post) = challenge_nonce vector_store (s "n") (s "login") None in
           obs == CI.StoreObservation_Inserted /\
           post.kv (nonce_key (s "n")) == Some (s "login")) =
  challenge_nonce_is_honest vector_store (s "n") (s "login") None

let vector_challenge_collision : store =
  { vector_store with kv = (fun k -> if k = nonce_key (s "n") then Some (s "enroll") else None) }

let vector_challenge_nonce_collision ()
  : Lemma (let (obs, post) = challenge_nonce vector_challenge_collision (s "n") (s "login") None in
           obs == CI.StoreObservation_KeyExists /\ post == vector_challenge_collision) =
  challenge_nonce_is_honest vector_challenge_collision (s "n") (s "login") None;
  challenge_collision_keeps_the_live_nonce vector_challenge_collision (s "n") (s "login") None

let vector_empty_db : db =
  { users = []; devices = []; sessions = []; inbox = []; items = [];
    sends = []; chunks = []; buckets = [] }

let vector_insert_account ()
  : Lemma (let (obs, post) =
             insert_account vector_empty_db (s "u") (s "now") (s "ek") (s "now") None in
           obs == RG.InsertObservation_Inserted /\
           Some? (lookup post.users (s "u"))) =
  insert_account_is_honest vector_empty_db (s "u") (s "now") (s "ek") (s "now") None;
  inserted_account_is_stored vector_empty_db (s "u") (s "now") (s "ek") (s "now") None

let vector_registration_tx ()
  : Lemma (let (outs, post) =
             registration_transaction vector_empty_db (s "u") (s "d") (s "now")
               (s "ek") (s "since") (s "name") (s "desktop") (s "ekb64") (s "vkb64") None in
           L.length outs == 3 /\
           Some? (lookup post.users (s "u")) /\
           Some? (lookup post.devices (s "d"))) =
  registration_tx_is_honest vector_empty_db (s "u") (s "d") (s "now")
    (s "ek") (s "since") (s "name") (s "desktop") (s "ekb64") (s "vkb64") None

// ── Web sessions: start, grant, token and delete ───────────────────────────

/// The `web_session:token_issued:` marker key.
let claim_marker_key (sess: text) : text = claim_key sess

/// The sentinel the delete handler writes.
let lockout_key (sess: text) : text =
  stmt_key (first_stmt (stmts_of (plan_sentinel sess v_WEB_SESSION_MAX_TTL_SECS)))

let plan_insert_pending_shape (sess approver hash epk vk nonce now: text)
  : Lemma (plan_insert_pending sess approver hash epk vk nonce now ==
           SqlStmt_InsertPendingSession
             { f_session = sess; f_approver = approver; f_poll_secret_hash = hash;
               f_ephemeral_pk = epk; f_web_vk = vk; f_link_nonce = nonce; f_now = now }) =
  ()

let plan_grant_update_shape (sess usr dev mode capsule expires: text) (epoch: i64)
  : Lemma (plan_grant_update sess usr dev mode capsule expires epoch ==
           SqlStmt_GrantWebSession
             { f_session = sess; f_user = usr; f_device = dev; f_mode = mode;
               f_capsule = capsule; f_expires_at = expires; f_epoch = epoch }) =
  ()

let plan_revoke_session_shape (sess: text)
  : Lemma (plan_revoke_session sess == SqlStmt_RevokeSessionById { f_session = sess }) =
  ()

let plan_lockout_session_shape (sess: text)
  : Lemma (L.length (stmts_of (plan_sentinel sess v_WEB_SESSION_MAX_TTL_SECS)) == 1 /\
           (match first_stmt (stmts_of (plan_sentinel sess v_WEB_SESSION_MAX_TTL_SECS)) with
            | StoreStmt_SetEx { f_key = k; f_value = value; f_ttl = ttl } ->
              k == lockout_key sess /\ value == mk_u8 1 /\
              ttl == v_WEB_SESSION_MAX_TTL_SECS
            | _ -> False)) =
  ()

let plan_token_claim_shape (sess: text)
  : Lemma (L.length (stmts_of (plan_token_claim sess)) == 1 /\
           (match first_stmt (stmts_of (plan_token_claim sess)) with
            | StoreStmt_SetExNxByte { f_key = k; f_value = value; f_ttl = ttl } ->
              k == claim_marker_key sess /\ value == mk_u8 1 /\
              ttl == v_WEB_SESSION_MAX_TTL_SECS
            | _ -> False)) =
  ()

let plan_token_sentinel_shape (sess: text)
  : Lemma (L.length (stmts_of (plan_token_sentinel sess)) == 1 /\
           (match first_stmt (stmts_of (plan_token_sentinel sess)) with
            | StoreStmt_Exists { f_key = k } -> k == sentinel_key sess
            | _ -> False)) =
  ()

#push-options "--fuel 4 --ifuel 2"
/// `StartIo::insert_pending`: `Inserted` exactly when the id was fresh and the
/// one statement ran; then exactly that pending row is added; otherwise the
/// database is unchanged.
let insert_pending_is_honest
      (d: db) (sess approver hash epk vk nonce now: text) (f: option nat)
  : Lemma
    ((fst (insert_pending d sess approver hash epk vk nonce now f) ==
        Vela_session_policy.Websession_driver.StartInsertObservation_Inserted
        <==> (no_fault_in f 1 /\ lookup d.sessions sess == None)) /\
     (fst (insert_pending d sess approver hash epk vk nonce now f) ==
        Vela_session_policy.Websession_driver.StartInsertObservation_Inserted ==>
        snd (insert_pending d sess approver hash epk vk nonce now f) ==
          st_insert_pending d sess approver) /\
     (fst (insert_pending d sess approver hash epk vk nonce now f) =!=
        Vela_session_policy.Websession_driver.StartInsertObservation_Inserted ==>
        snd (insert_pending d sess approver hash epk vk nonce now f) == d)) =
  plan_insert_pending_shape sess approver hash epk vk nonce now

/// `GrantIo::update_grant`: `Updated` exactly when the guard held and the one
/// statement ran; zero rows is the conflict and changes nothing; a failure is
/// the storage error and changes nothing.
let grant_update_is_honest
      (d: db) (sess usr dev mode capsule expires: text) (epoch: i64) (f: option nat)
  : Lemma
    ((fst (grant_update d sess usr dev mode capsule expires epoch f) ==
        Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated
        <==> (no_fault_in f 1 /\ grant_guard d sess usr dev epoch)) /\
     (fst (grant_update d sess usr dev mode capsule expires epoch f) ==
        Vela_session_policy.Websession_driver.GrantUpdateObservation_Conflict
        <==> (no_fault_in f 1 /\ not (grant_guard d sess usr dev epoch))) /\
     (fst (grant_update d sess usr dev mode capsule expires epoch f) ==
        Vela_session_policy.Websession_driver.GrantUpdateObservation_Failed
        <==> faulted f 0) /\
     (fst (grant_update d sess usr dev mode capsule expires epoch f) ==
        Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated ==>
        snd (grant_update d sess usr dev mode capsule expires epoch f) ==
          st_grant_session d sess usr dev mode capsule expires epoch) /\
     (fst (grant_update d sess usr dev mode capsule expires epoch f) ==
        Vela_session_policy.Websession_driver.GrantUpdateObservation_Conflict ==>
        snd (grant_update d sess usr dev mode capsule expires epoch f) == d) /\
     (fst (grant_update d sess usr dev mode capsule expires epoch f) ==
        Vela_session_policy.Websession_driver.GrantUpdateObservation_Failed ==>
        snd (grant_update d sess usr dev mode capsule expires epoch f) == d)) =
  plan_grant_update_shape sess usr dev mode capsule expires epoch

/// The audit statement's observation: `Updated` exactly when the statement
/// ran (zero rows included), `Failed` exactly when it did not.
let revoke_session_observes_its_run (d: db) (sess: text) (f: option nat)
  : Lemma
    ((fst (revoke_session d sess f) ==
        Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated
        <==> not (faulted f 0)) /\
     (fst (revoke_session d sess f) ==
        Vela_session_policy.Websession_driver.DeleteRecordObservation_Failed
        <==> faulted f 0)) =
  ()

/// The audit statement's state change: exactly the revoke rewrite on success,
/// unchanged on failure. An absent target is unchanged (the statement reports
/// zero rows but the handler still classifies it `Updated`).
let revoke_session_state (d: db) (sess: text) (f: option nat)
  : Lemma
    ((fst (revoke_session d sess f) ==
        Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated ==>
        (match lookup d.sessions sess with
         | Some _ -> snd (revoke_session d sess f) == st_revoke_session d sess
         | None -> snd (revoke_session d sess f) == d)) /\
     (fst (revoke_session d sess f) =!=
        Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated ==>
        snd (revoke_session d sess f) == d)) =
  plan_revoke_session_shape sess

/// `no_fault_in f 1` is exactly "statement 0 did not fail".
let one_fault_equivalence (f: option nat)
  : Lemma (no_fault_in f 1 <==> not (faulted f 0)) =
  match f with
  | None -> ()
  | Some _ -> ()

/// `DeleteSessionIo::record_revocation`: `Updated` exactly when the one audit
/// statement ran (its row count is not observed); on failure the table is
/// unchanged.
let revoke_session_is_honest (d: db) (sess: text) (f: option nat)
  : Lemma
    ((fst (revoke_session d sess f) ==
        Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated
        <==> no_fault_in f 1) /\
     (fst (revoke_session d sess f) ==
        Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated ==>
        (match lookup d.sessions sess with
         | Some _ -> snd (revoke_session d sess f) == st_revoke_session d sess
         | None -> snd (revoke_session d sess f) == d)) /\
     (fst (revoke_session d sess f) =!=
        Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated ==>
        snd (revoke_session d sess f) == d)) =
  revoke_session_observes_its_run d sess f;
  revoke_session_state d sess f;
  one_fault_equivalence f

/// `DeleteSessionIo::lockout_session`: `Applied` exactly when the sentinel
/// write ran; then the sentinel holds the marker and nothing else changed; on
/// failure the store is unchanged.
let lockout_session_is_honest (s: store) (sess: text) (f: option nat)
  : Lemma
    ((fst (lockout_session s sess f) ==
        Vela_session_policy.Websession_driver.DeleteSentinelObservation_Applied
        <==> no_fault_in f 1) /\
     (fst (lockout_session s sess f) ==
        Vela_session_policy.Websession_driver.DeleteSentinelObservation_Applied ==>
        (snd (lockout_session s sess f)).kv (lockout_key sess) == Some v_one /\
        (forall (k: text). k <> lockout_key sess ==>
           (snd (lockout_session s sess f)).kv k == s.kv k) /\
        (snd (lockout_session s sess f)).sets == s.sets /\
        (snd (lockout_session s sess f)).revoked == s.revoked /\
        (snd (lockout_session s sess f)).counters == s.counters) /\
     (fst (lockout_session s sess f) =!=
        Vela_session_policy.Websession_driver.DeleteSentinelObservation_Applied ==>
        snd (lockout_session s sess f) == s)) =
  plan_lockout_session_shape sess
#pop-options

#push-options "--fuel 4 --ifuel 2"
/// `TokenIo::claim_token`: `Claimed` exactly when the marker was absent and
/// the write ran; `AlreadyClaimed` exactly when it was present; on success
/// only that one key changed; a collision and a failure change nothing.
let token_claim_is_honest (s: store) (sess: text) (f: option nat)
  : Lemma
    ((fst (token_claim s sess f) ==
        Vela_session_policy.Websession_driver.TokenClaimObservation_Claimed
        <==> (no_fault_in f 1 /\ s.kv (claim_marker_key sess) == None)) /\
     (fst (token_claim s sess f) ==
        Vela_session_policy.Websession_driver.TokenClaimObservation_AlreadyClaimed
        <==> (no_fault_in f 1 /\ Some? (s.kv (claim_marker_key sess)))) /\
     (fst (token_claim s sess f) ==
        Vela_session_policy.Websession_driver.TokenClaimObservation_StorageFailed
        <==> faulted f 0) /\
     (fst (token_claim s sess f) ==
        Vela_session_policy.Websession_driver.TokenClaimObservation_Claimed ==>
        (snd (token_claim s sess f)).kv (claim_marker_key sess) == Some v_one /\
        (forall (k: text). k <> claim_marker_key sess ==>
           (snd (token_claim s sess f)).kv k == s.kv k) /\
        (snd (token_claim s sess f)).sets == s.sets /\
        (snd (token_claim s sess f)).revoked == s.revoked /\
        (snd (token_claim s sess f)).counters == s.counters) /\
     (fst (token_claim s sess f) ==
        Vela_session_policy.Websession_driver.TokenClaimObservation_AlreadyClaimed ==>
        snd (token_claim s sess f) == s) /\
     (fst (token_claim s sess f) ==
        Vela_session_policy.Websession_driver.TokenClaimObservation_StorageFailed ==>
        snd (token_claim s sess f) == s)) =
  plan_token_claim_shape sess

/// `TokenIo::issue_token`'s lockout re-check: a present sentinel, an absent
/// one and a failed read, each the store's truth and changing nothing.
let token_sentinel_is_honest (s: store) (sess: text) (f: option nat)
  : Lemma
    ((fst (token_sentinel s sess f) == ExistsOutcome_Absent
        <==> (no_fault_in f 1 /\ s.kv (sentinel_key sess) == None)) /\
     (fst (token_sentinel s sess f) == ExistsOutcome_Present
        <==> (no_fault_in f 1 /\ Some? (s.kv (sentinel_key sess)))) /\
     (fst (token_sentinel s sess f) == ExistsOutcome_Failed <==> faulted f 0) /\
     snd (token_sentinel s sess f) == s) =
  plan_token_sentinel_shape sess
#pop-options

#push-options "--fuel 4 --ifuel 2"
/// `TokenIo::issue_token`: `Issued` exactly when the issuer produced a token,
/// the issue-time sentinel was absent and the JTI track ran; then the JTI is
/// in the session's set and no key, JTI revocation or counter changed. Any
/// other outcome leaves the store exactly as it was.
let token_issue_is_honest (s: store) (sess jti: text) (paseto_ok: bool) (f: option nat)
  : Lemma
    ((fst (token_issue s sess jti paseto_ok f) ==
        Vela_session_policy.Websession_driver.TokenIssueObservation_Issued
        <==> (paseto_ok /\ no_fault_in f 2 /\
             s.kv (sentinel_key sess) == None)) /\
     (fst (token_issue s sess jti paseto_ok f) ==
        Vela_session_policy.Websession_driver.TokenIssueObservation_Issued ==>
        (L.mem jti ((snd (token_issue s sess jti paseto_ok f)).sets (track_key sess)) /\
         (snd (token_issue s sess jti paseto_ok f)).kv == s.kv /\
         (snd (token_issue s sess jti paseto_ok f)).revoked == s.revoked /\
         (snd (token_issue s sess jti paseto_ok f)).counters == s.counters)) /\
     (fst (token_issue s sess jti paseto_ok f) =!=
        Vela_session_policy.Websession_driver.TokenIssueObservation_Issued ==>
        snd (token_issue s sess jti paseto_ok f) == s)) =
  plan_token_sentinel_shape sess;
  plan_track_jti_shape sess jti
#pop-options

// ── Web-session facts the driver relies on ─────────────────────────────────

/// An `Inserted` pending row is exactly what `start` reports: pending, bound
/// to the committed approver, with no user or grant fields.
let inserted_pending_is_stored
      (d: db) (sess approver hash epk vk nonce now: text) (f: option nat)
  : Lemma
    (fst (insert_pending d sess approver hash epk vk nonce now f) ==
       Vela_session_policy.Websession_driver.StartInsertObservation_Inserted ==>
       (match lookup (snd (insert_pending d sess approver hash epk vk nonce now f)).sessions sess with
        | Some r -> r.ws_status == v_pending /\ r.ws_user == None /\
                    r.ws_approver == Some approver /\ r.ws_capsule == None
        | None -> False)) =
  insert_pending_is_honest d sess approver hash epk vk nonce now f

/// A `Updated` grant held every guard the CAS checks.
let grant_updated_only_pending_guarded
      (d: db) (sess usr dev mode capsule expires: text) (epoch: i64) (f: option nat)
  : Lemma
    (fst (grant_update d sess usr dev mode capsule expires epoch f) ==
       Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated ==>
       grant_guard d sess usr dev epoch) =
  grant_update_is_honest d sess usr dev mode capsule expires epoch f

/// A `Updated` grant changed only the `web_sessions` table (the one intended
/// row is `st_grant_session`; `grant_update_is_honest` names it exactly).
let grant_updated_changes_only_sessions
      (d: db) (sess usr dev mode capsule expires: text) (epoch: i64) (f: option nat)
  : Lemma
    (fst (grant_update d sess usr dev mode capsule expires epoch f) ==
       Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated ==>
       (snd (grant_update d sess usr dev mode capsule expires epoch f)).users == d.users /\
       (snd (grant_update d sess usr dev mode capsule expires epoch f)).devices == d.devices /\
       (snd (grant_update d sess usr dev mode capsule expires epoch f)).inbox == d.inbox /\
       (snd (grant_update d sess usr dev mode capsule expires epoch f)).items == d.items /\
       (snd (grant_update d sess usr dev mode capsule expires epoch f)).sends == d.sends /\
       (snd (grant_update d sess usr dev mode capsule expires epoch f)).chunks == d.chunks /\
       (snd (grant_update d sess usr dev mode capsule expires epoch f)).buckets == d.buckets) =
  grant_update_is_honest d sess usr dev mode capsule expires epoch f

/// A `Claimed` token means the marker was absent before the write and present
/// after it: the one-shot claim.
let token_claim_is_first_writer_wins (s: store) (sess: text) (f: option nat)
  : Lemma
    (fst (token_claim s sess f) ==
       Vela_session_policy.Websession_driver.TokenClaimObservation_Claimed ==>
       (s.kv (claim_marker_key sess) == None /\
        (snd (token_claim s sess f)).kv (claim_marker_key sess) == Some v_one)) =
  token_claim_is_honest s sess f

/// An issued token is only released while no lockout sentinel is stored.
let issued_token_is_not_locked_out (s: store) (sess jti: text) (paseto_ok: bool)
      (f: option nat)
  : Lemma
    (fst (token_issue s sess jti paseto_ok f) ==
       Vela_session_policy.Websession_driver.TokenIssueObservation_Issued ==>
       s.kv (sentinel_key sess) == None) =
  token_issue_is_honest s sess jti paseto_ok f

/// An issued token's JTI is tracked, so the revocation sweep can retire it.
let issued_token_is_tracked (s: store) (sess jti: text) (paseto_ok: bool) (f: option nat)
  : Lemma
    (fst (token_issue s sess jti paseto_ok f) ==
       Vela_session_policy.Websession_driver.TokenIssueObservation_Issued ==>
       L.mem jti ((snd (token_issue s sess jti paseto_ok f)).sets (track_key sess))) =
  token_issue_is_honest s sess jti paseto_ok f

/// A `Applied` delete lockout left the sentinel in the store: the session's
/// tokens are rejected for the whole ceiling.
let lockout_applied_means_sentinel_stored (s: store) (sess: text) (f: option nat)
  : Lemma
    (fst (lockout_session s sess f) ==
       Vela_session_policy.Websession_driver.DeleteSentinelObservation_Applied ==>
       (snd (lockout_session s sess f)).kv (lockout_key sess) == Some v_one) =
  lockout_session_is_honest s sess f

/// An `Updated` audit record left exactly the revoked row (an absent target
/// stays absent).
let revoke_record_marks_the_session (d: db) (sess: text) (f: option nat)
  : Lemma
    (fst (revoke_session d sess f) ==
       Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated ==>
       (match lookup d.sessions sess with
        | Some _ -> snd (revoke_session d sess f) == st_revoke_session d sess
        | None -> snd (revoke_session d sess f) == d)) =
  revoke_session_is_honest d sess f

// ── Vectors shared with `store_model.rs::tests` ────────────────────────────

let vector_web_db : db =
  { users =
      [(s "u",
        ({ us_share_ek = None; us_share_ek_since = None; us_created_at = s "t0";
           us_rekey_state = None; us_key_epoch = mk_i64 3 } <: user_row))];
    devices =
      [(s "d",
        ({ dv_user = s "u"; dv_revoked = mk_i64 0; dv_hybrid_ek = s "";
           dv_hybrid_vk = s ""; dv_last_active = None; dv_name = s "n";
           dv_kind = s "k"; dv_revoked_at = None; dv_revoked_by = None } <: device_row))];
    sessions =
      [(s "s",
        ({ ws_user = None; ws_approver = Some (s "u"); ws_status = v_pending;
           ws_capsule = None; ws_approved_by = None; ws_mode = None;
           ws_key_epoch = None; ws_expires_at = None } <: session_row))];
    inbox = []; items = []; sends = []; chunks = []; buckets = [] }

let vector_insert_pending ()
  : Lemma (let (obs, post) =
             insert_pending vector_empty_db (s "fresh") (s "u") (s "h") (s "e") (s "v")
               (s "n") (s "now") None in
           obs == Vela_session_policy.Websession_driver.StartInsertObservation_Inserted /\
           Some? (lookup post.sessions (s "fresh"))) =
  insert_pending_is_honest vector_empty_db (s "fresh") (s "u") (s "h") (s "e") (s "v")
    (s "n") (s "now") None

let vector_grant_update ()
  : Lemma (let (obs, post) =
             grant_update vector_web_db (s "s") (s "u") (s "d") (s "rw") (s "cap")
               (s "exp") (mk_i64 3) None in
           obs == Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated /\
           post == st_grant_session vector_web_db (s "s") (s "u") (s "d") (s "rw")
                     (s "cap") (s "exp") (mk_i64 3)) =
  grant_update_is_honest vector_web_db (s "s") (s "u") (s "d") (s "rw") (s "cap")
    (s "exp") (mk_i64 3) None

let vector_grant_conflict ()
  : Lemma (let (obs, post) =
             grant_update vector_web_db (s "s") (s "u") (s "d") (s "rw") (s "cap")
               (s "exp") (mk_i64 4) None in
           obs == Vela_session_policy.Websession_driver.GrantUpdateObservation_Conflict /\
           post == vector_web_db) =
  grant_update_is_honest vector_web_db (s "s") (s "u") (s "d") (s "rw") (s "cap")
    (s "exp") (mk_i64 4) None

let vector_revoke_session ()
  : Lemma (let (obs, post) = revoke_session vector_web_db (s "s") None in
           obs == Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated /\
           post == st_revoke_session vector_web_db (s "s")) =
  revoke_session_is_honest vector_web_db (s "s") None

let vector_token_claim ()
  : Lemma (let (obs, post) = token_claim vector_store (s "s") None in
           obs == Vela_session_policy.Websession_driver.TokenClaimObservation_Claimed /\
           post.kv (claim_marker_key (s "s")) == Some v_one) =
  token_claim_is_honest vector_store (s "s") None

let vector_token_claim_exists : store =
  { vector_store with kv = (fun k -> if k = claim_marker_key (s "s") then Some v_one else None) }

let vector_token_claim_collision ()
  : Lemma (let (obs, post) = token_claim vector_token_claim_exists (s "s") None in
           obs == Vela_session_policy.Websession_driver.TokenClaimObservation_AlreadyClaimed /\
           post == vector_token_claim_exists) =
  token_claim_is_honest vector_token_claim_exists (s "s") None

let vector_token_issue ()
  : Lemma (let (obs, post) = token_issue vector_store (s "s") (s "jti") true None in
           obs == Vela_session_policy.Websession_driver.TokenIssueObservation_Issued /\
           L.mem (s "jti") (post.sets (track_key (s "s")))) =
  token_issue_is_honest vector_store (s "s") (s "jti") true None

let vector_token_issue_locked : store =
  { vector_store with kv = (fun k -> if k = sentinel_key (s "s") then Some v_one else None) }

let vector_token_issue_locked_fails ()
  : Lemma (let (obs, post) = token_issue vector_token_issue_locked (s "s") (s "jti") true None in
           obs == Vela_session_policy.Websession_driver.TokenIssueObservation_Failed /\
           post == vector_token_issue_locked) =
  token_issue_is_honest vector_token_issue_locked (s "s") (s "jti") true None
