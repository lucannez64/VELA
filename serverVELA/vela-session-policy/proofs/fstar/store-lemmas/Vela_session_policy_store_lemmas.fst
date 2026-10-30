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
  { kv = (fun _ -> None); sets = (fun _ -> []); revoked = [] }

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
    revoked = [] }

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
