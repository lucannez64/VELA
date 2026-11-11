module Vela_share_policy_store_lemmas

/// F-1 for the sharing executors: for every starting database and every
/// fault point, each executor's observation (the extracted `classify_*`
/// applied to what the extracted `plan_*` did in `Vela_share_policy_store_model`)
/// is the truth about the tables.

open FStar.Mul
open Core_models
open Vela_share_policy.Store
open Vela_share_policy_store_model

module L = FStar.List.Tot
module SP = FStar.Seq.Properties
module D = Vela_share_policy.Driver

// ── Outcome slices ─────────────────────────────────────────────────────────

/// The slice a classifier reads is the outcome list, element by element.
/// Nothing about the classifiers is restated here, so a changed classifier
/// fails the honesty theorems themselves.
let seq_of_list_facts (l: list t_WriteOutcome)
  : Lemma (forall (i: nat). i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
  let aux (i: nat) : Lemma (i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
    if i < L.length l then SP.lemma_seq_of_list_index l i
  in
  FStar.Classical.forall_intro aux

// ── Send: SendIo::insert_capsule ───────────────────────────────────────────

/// No statement among the first `n` is the injected failure.
let no_fault_in (f: option nat) (n: nat) : bool =
  match f with
  | None -> true
  | Some k -> k >= n

let fresh_send (d: db) (id: text) : bool = None? (d.items id) && None? (d.inbox id)

/// Exactly the two intended rows were added and nothing else changed.
let send_delivered (d post: db) (id sender recipient capsule now: text) : prop =
  post.items id == Some ({
      it_sender = sender;
      it_recipient = recipient;
      it_capsule = capsule;
      it_created_at = now;
      it_updated_at = now;
      it_revoked = mk_i64 0
    } <: item) /\
  post.inbox id == Some ({
      ib_sender = sender;
      ib_recipient = recipient;
      ib_capsule = capsule;
      ib_created_at = now
    } <: inbox_row) /\
  (forall (k: text). k <> id ==> post.items k == d.items k /\ post.inbox k == d.inbox k) /\
  post.users == d.users /\
  post.devices == d.devices


#push-options "--fuel 4 --ifuel 2"
/// The send observation is the truth about the transaction: `Committed`
/// exactly when the id was fresh in both tables and no statement failed, and
/// then exactly the two intended rows were added; `CommitConflict` exactly
/// when only the commit failed; on every failure the tables are unchanged.
let send_insert_is_honest (d: db) (id sender recipient capsule now: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_insert d id sender recipient capsule now f in
     (obs == D.SendResultObservation_Committed <==> (fresh_send d id /\ no_fault_in f 3)) /\
     (obs == D.SendResultObservation_CommitConflict <==> (fresh_send d id /\ f == Some 2)) /\
     (obs == D.SendResultObservation_Committed ==>
        send_delivered d post id sender recipient capsule now) /\
     (obs =!= D.SendResultObservation_Committed ==> post == d) /\
     (obs == D.SendResultObservation_Committed <==>
        (fresh_send d id /\ send_delivered d post id sender recipient capsule now))) =
  let r = run_tx d d (stmts_of (plan_send_insert id sender recipient capsule now)) 0 f in
  seq_of_list_facts (fst r)
#pop-options

// ── Guarded single-statement writes ────────────────────────────────────────

let rows_changed (o: D.t_RowsObservation) : bool = o.D.f_rows <> mk_u64 0

/// Only `shared_items[id]` may differ.
let items_frame (d post: db) (id: text) : prop =
  (forall (k: text). k <> id ==> post.items k == d.items k) /\
  post.inbox == d.inbox /\ post.users == d.users /\ post.devices == d.devices

/// Only `share_inbox[id]` may differ.
let inbox_frame (d post: db) (id: text) : prop =
  (forall (k: text). k <> id ==> post.inbox k == d.inbox k) /\
  post.items == d.items /\ post.users == d.users /\ post.devices == d.devices

/// Only `users[user]` may differ.
let users_frame (d post: db) (user: text) : prop =
  (forall (k: text). k <> user ==> post.users k == d.users k) /\
  post.items == d.items /\ post.inbox == d.inbox /\ post.devices == d.devices

/// The SQL guard `id = ? AND sender_user_id = ? AND revoked = 0`.
let live_sender_row (d: db) (id caller: text) : bool =
  match d.items id with
  | Some r -> r.it_sender = caller && r.it_revoked = mk_i64 0
  | None -> false


#push-options "--fuel 4 --ifuel 2"
/// `update_linked_item`: rows are reported exactly when the caller's live row
/// was updated, and then only its capsule and `updated_at` changed; with no
/// rows reported the tables are unchanged.
let link_update_is_honest (d: db) (id caller capsule now: text) (f: option nat)
  : Lemma
    (let (obs, post) = link_update d id caller capsule now f in
     (rows_changed obs <==> (live_sender_row d id caller /\ no_fault_in f 1)) /\
     (rows_changed obs ==>
        obs.D.f_rows == mk_u64 1 /\ items_frame d post id /\
        (match d.items id with
         | Some r -> post.items id == Some ({ r with it_capsule = capsule; it_updated_at = now })
         | None -> False)) /\
     (not (rows_changed obs) ==> post == d)) =
  let r = run_auto d (stmts_of (plan_link_update id caller capsule now)) 0 f in
  seq_of_list_facts (fst r)

/// `revoke_linked_item`: rows are reported exactly when the caller's live row
/// was revoked; then it is revoked and nothing else changed. Equivalently,
/// rows are reported exactly when the post-state holds the intended row.
let link_revoke_is_honest (d: db) (id caller now: text) (f: option nat)
  : Lemma
    (let (obs, post) = link_revoke d id caller now f in
     let revoked_in (post: db) : prop =
       items_frame d post id /\
       (match d.items id with
        | Some r -> post.items id == Some ({ r with it_revoked = mk_i64 1; it_updated_at = now })
        | None -> False)
     in
     (rows_changed obs <==> (live_sender_row d id caller /\ no_fault_in f 1)) /\
     (rows_changed obs ==> obs.D.f_rows == mk_u64 1 /\ revoked_in post) /\
     (not (rows_changed obs) ==> post == d) /\
     (rows_changed obs <==> (live_sender_row d id caller /\ revoked_in post))) =
  let r = run_auto d (stmts_of (plan_link_revoke id caller now)) 0 f in
  seq_of_list_facts (fst r)

/// `delete_linked_inbox`: the cleanup reports success exactly when its
/// delete ran, and then no inbox row with that id is left; a failure leaves
/// the tables unchanged.
let linked_inbox_cleanup_is_honest (d: db) (id: text) (f: option nat)
  : Lemma
    (let (obs, post) = linked_inbox_cleanup d id f in
     (obs.D.f_storage_failed == false <==> no_fault_in f 1) /\
     (obs.D.f_storage_failed == false ==> post.inbox id == None /\ inbox_frame d post id) /\
     (obs.D.f_storage_failed == true ==> post == d)) =
  let r = run_auto d (stmts_of (plan_linked_inbox_cleanup id)) 0 f in
  seq_of_list_facts (fst r)

/// `delete_inbox_item`: rows are reported exactly when the caller's own inbox
/// row was deleted; then only that row is gone. A row addressed to someone
/// else is never deleted.
let inbox_delete_is_honest (d: db) (id caller: text) (f: option nat)
  : Lemma
    (let (obs, post) = inbox_delete d id caller f in
     let owned : bool = (match d.inbox id with Some r -> r.ib_recipient = caller | None -> false) in
     (rows_changed obs <==> (owned /\ no_fault_in f 1)) /\
     (rows_changed obs ==> obs.D.f_rows == mk_u64 1 /\ post.inbox id == None /\ inbox_frame d post id) /\
     (not (rows_changed obs) ==> post == d) /\
     (rows_changed obs <==> (owned /\ post.inbox id == None /\ inbox_frame d post id))) =
  let r = run_auto d (stmts_of (plan_inbox_delete id caller)) 0 f in
  seq_of_list_facts (fst r)

/// `update_share_ek`: rows are reported exactly when the caller's user row
/// exists and was written; then it holds the new key, binding instant and
/// signing device, and nothing else changed.
let share_ek_update_is_honest (d: db) (user ek since device: text) (f: option nat)
  : Lemma
    (let (obs, post) = share_ek_update d user ek since device f in
     (rows_changed obs <==> (Some? (d.users user) /\ no_fault_in f 1)) /\
     (rows_changed obs ==>
        obs.D.f_rows == mk_u64 1 /\ users_frame d post user /\
        post.users user == Some ({
            us_share_ek = Some ek;
            us_share_ek_since = Some since;
            us_share_ek_device_id = Some device
          } <: user_row)) /\
     (not (rows_changed obs) ==> post == d)) =
  let r = run_auto d (stmts_of (plan_share_ek_update user ek since device)) 0 f in
  seq_of_list_facts (fst r)
#pop-options

// ── Reads ──────────────────────────────────────────────────────────────────

let rejecting_link : Vela_share_policy.t_LinkMutationObservation =
  {
    Vela_share_policy.f_item_present = false;
    Vela_share_policy.f_caller_matches_sender = false;
    Vela_share_policy.f_item_not_revoked = false
  }

/// What `shared_items[id]` says about `caller`.
let link_truth (d: db) (caller id: text) : Vela_share_policy.t_LinkMutationObservation =
  match d.items id with
  | Some r ->
    {
      Vela_share_policy.f_item_present = true;
      Vela_share_policy.f_caller_matches_sender = r.it_sender = caller;
      Vela_share_policy.f_item_not_revoked = r.it_revoked = mk_i64 0
    }
  | None -> rejecting_link

/// `observe_link`: the observation is the stored row's truth; a failed read
/// rejects.
let link_observation_is_honest (d: db) (caller id: text) (f: option nat)
  : Lemma (observe_link d caller id f == (if faulted f 0 then rejecting_link else link_truth d caller id)) =
  ()

/// What the joined device read finds for `caller`: present, owned, active,
/// binding exists.
let device_truth (d: db) (caller device_id: text) : (bool & bool & bool & bool) =
  match d.devices device_id with
  | Some dv ->
    if dv.dv_user_id = caller
    then
      (match d.users caller with
       | Some u -> (true, true, dv.dv_revoked <> mk_i64 1, Some? u.us_share_ek_since)
       | None -> (false, false, false, false))
    else (false, false, false, false)
  | None -> (false, false, false, false)

/// `observe_device`: the row-derived fields are the stored rows' truth and
/// the other fields are the caller's inputs; a failed read gives the
/// historical rejecting observation.
let device_observation_is_honest
      (d: db) (caller device_id: text) (ek_len: usize) (verdicts: t_DeviceVerdicts) (f: option nat)
  : Lemma
    (let obs = observe_device d caller device_id ek_len verdicts f in
     let reg = obs.D.f_registration in
     if faulted f 0
     then
       reg.Vela_share_policy.f_ek_len == Vela_share_policy.v_SHARE_EK_LEN /\
       reg.Vela_share_policy.f_signature_verified == false /\
       reg.Vela_share_policy.f_device_row_present == false /\
       reg.Vela_share_policy.f_device_user_matches == false /\
       reg.Vela_share_policy.f_device_active == false /\
       reg.Vela_share_policy.f_signed_at_is_fresher == false /\
       reg.Vela_share_policy.f_binding_exists == false /\
       obs.D.f_stored_identity_vk_decode_failed == false /\
       obs.D.f_signature_decode_failed == false
     else
       (let (present, owned, active, bound) = device_truth d caller device_id in
        reg.Vela_share_policy.f_device_row_present == present /\
        reg.Vela_share_policy.f_device_user_matches == owned /\
        reg.Vela_share_policy.f_device_active == active /\
        reg.Vela_share_policy.f_binding_exists == bound /\
        reg.Vela_share_policy.f_ek_len == ek_len /\
        reg.Vela_share_policy.f_signature_verified == verdicts.f_signature_verified /\
        reg.Vela_share_policy.f_signed_at_is_fresher == verdicts.f_signed_at_is_fresher /\
        obs.D.f_stored_identity_vk_decode_failed == verdicts.f_stored_vk_decode_failed /\
        obs.D.f_signature_decode_failed == verdicts.f_signature_decode_failed)) =
  ()

// ── Facts the sharing driver relies on ─────────────────────────────────────

/// `Committed` (the driver's `Complete` for a send) means the recipient's
/// inbox holds the capsule from the authenticated sender under the new id,
/// and the linked copy is live.
let send_commit_reaches_recipient (d: db) (id sender recipient capsule now: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_insert d id sender recipient capsule now f in
     obs == D.SendResultObservation_Committed ==>
       (match post.inbox id, post.items id with
        | Some m, Some r ->
          m.ib_recipient == recipient /\ m.ib_sender == sender /\ m.ib_capsule == capsule /\
          r.it_sender == sender /\ r.it_recipient == recipient /\ r.it_revoked == mk_i64 0
        | _ -> False)) =
  send_insert_is_honest d id sender recipient capsule now f

/// The linked-row observation lets the verified mutation policy apply only
/// when the stored row is live and the caller is its sender.
let link_observation_authorizes_only_live_sender_rows (d: db) (caller id: text) (f: option nat)
  : Lemma
    (Vela_share_policy.plan_link_mutation
        (Vela_share_policy.link_mutation_facts (observe_link d caller id f)) ==
      Vela_share_policy.LinkMutationDecision_Apply ==>
      live_sender_row d id caller) =
  link_observation_is_honest d caller id f

/// The device observation admits only an existing, unrevoked device of the
/// caller whose user row exists.
let device_observation_admits_only_owned_active_devices
      (d: db) (caller device_id: text) (ek_len: usize) (verdicts: t_DeviceVerdicts) (f: option nat)
  : Lemma
    (let reg = (observe_device d caller device_id ek_len verdicts f).D.f_registration in
     reg.Vela_share_policy.f_device_row_present /\
     reg.Vela_share_policy.f_device_user_matches /\
     reg.Vela_share_policy.f_device_active ==>
       (match d.devices device_id with
        | Some dv -> dv.dv_user_id == caller /\ dv.dv_revoked <> mk_i64 1 /\ Some? (d.users caller)
        | None -> False)) =
  device_observation_is_honest d caller device_id ek_len verdicts f

/// Revocation is final in the store: after a revoke reports a row, no update
/// or revoke of that item reports a row again, for any caller and any fault.
let revocation_is_final_in_store
      (d: db) (id caller now: text) (f: option nat)
      (caller' capsule' now': text) (f': option nat)
  : Lemma
    (let (obs, post) = link_revoke d id caller now f in
     rows_changed obs ==>
       not (rows_changed (fst (link_update post id caller' capsule' now' f'))) /\
       not (rows_changed (fst (link_revoke post id caller' now' f')))) =
  link_revoke_is_honest d id caller now f;
  let (_, post) = link_revoke d id caller now f in
  link_update_is_honest post id caller' capsule' now' f';
  link_revoke_is_honest post id caller' now' f'

/// A non-recipient's inbox delete never removes the row and changes nothing.
let inbox_delete_only_by_recipient (d: db) (id caller: text) (f: option nat)
  : Lemma
    (match d.inbox id with
     | Some r ->
       r.ib_recipient <> caller ==>
         (let (obs, post) = inbox_delete d id caller f in
          not (rows_changed obs) /\ post == d)
     | None -> True) =
  inbox_delete_is_honest d id caller f

/// A linked update reports a row only for the sender of a live item, so the
/// driver's `Complete` for an update is the sender's write to a live item.
let link_update_commits_only_live_sender_rows (d: db) (id caller capsule now: text) (f: option nat)
  : Lemma
    (rows_changed (fst (link_update d id caller capsule now f)) ==> live_sender_row d id caller) =
  link_update_is_honest d id caller capsule now f

// ── Vectors shared with `store_model.rs::tests::shared_vectors` ────────────

let s (x: string) : text = Alloc.String.String x

let vector_item : item =
  { it_sender = s "a"; it_recipient = s "b"; it_capsule = s "c";
    it_created_at = s "t0"; it_updated_at = s "t0"; it_revoked = mk_i64 0 }

let vector_inbox : inbox_row =
  { ib_sender = s "a"; ib_recipient = s "b"; ib_capsule = s "c"; ib_created_at = s "t0" }

let vector_db : db =
  {
    items = (fun k -> if k = s "i" then Some vector_item else None);
    inbox = (fun k -> if k = s "i" then Some vector_inbox else None);
    users = (fun _ -> None);
    devices = (fun _ -> None);
    sends = (fun _ -> None);
    item_ids = [s "i"];
    inbox_ids = [s "i"];
    send_ids = [];
    clock = (fun (a b: text) -> false)
  }

let vector_send_fresh ()
  : Lemma (let (obs, post) = send_insert vector_db (s "j") (s "a") (s "b") (s "d") (s "t1") None in
           obs == D.SendResultObservation_Committed /\ Some? (post.inbox (s "j")) /\
           post.items (s "i") == Some vector_item) =
  send_insert_is_honest vector_db (s "j") (s "a") (s "b") (s "d") (s "t1") None

let vector_send_commit_fault ()
  : Lemma (let (obs, post) = send_insert vector_db (s "j") (s "a") (s "b") (s "d") (s "t1") (Some 2) in
           obs == D.SendResultObservation_CommitConflict /\ post == vector_db) =
  send_insert_is_honest vector_db (s "j") (s "a") (s "b") (s "d") (s "t1") (Some 2)

let vector_send_duplicate ()
  : Lemma (let (obs, post) = send_insert vector_db (s "i") (s "a") (s "b") (s "d") (s "t1") None in
           obs == D.SendResultObservation_StorageFailed /\ post == vector_db) =
  send_insert_is_honest vector_db (s "i") (s "a") (s "b") (s "d") (s "t1") None

let vector_revoke_sender ()
  : Lemma (let (obs, post) = link_revoke vector_db (s "i") (s "a") (s "t1") None in
           obs.D.f_rows == mk_u64 1 /\
           post.items (s "i") == Some ({ vector_item with it_revoked = mk_i64 1; it_updated_at = s "t1" })) =
  link_revoke_is_honest vector_db (s "i") (s "a") (s "t1") None

let vector_revoke_other ()
  : Lemma (let (obs, post) = link_revoke vector_db (s "i") (s "b") (s "t1") None in
           obs.D.f_rows == mk_u64 0 /\ post == vector_db) =
  link_revoke_is_honest vector_db (s "i") (s "b") (s "t1") None

let vector_inbox_recipient ()
  : Lemma (let (obs, post) = inbox_delete vector_db (s "i") (s "b") None in
           obs.D.f_rows == mk_u64 1 /\ post.inbox (s "i") == None) =
  inbox_delete_is_honest vector_db (s "i") (s "b") None

let vector_inbox_sender ()
  : Lemma (let (obs, post) = inbox_delete vector_db (s "i") (s "a") None in
           obs.D.f_rows == mk_u64 0 /\ post == vector_db) =
  inbox_delete_is_honest vector_db (s "i") (s "a") None
