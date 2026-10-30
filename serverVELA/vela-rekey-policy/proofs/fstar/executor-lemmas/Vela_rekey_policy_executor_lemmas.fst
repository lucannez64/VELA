module Vela_rekey_policy_executor_lemmas

/// F-1 for the vault, rekey, capsule, ORAM and schema executors: for every
/// starting database and every fault point, each executor's observation (the
/// extracted `classify_*` applied to what the extracted `plan_*` did in
/// `Vela_rekey_policy_executor_model`) is the truth about the tables and the
/// schema key.
///
/// The two account CAS statements carry the database's answers to their
/// `NOT EXISTS` sub-queries (`answers`); `freeze_guard_is_honest` and
/// `commit_guard_is_honest` state exactly what it means for those answers to
/// be the truth. The conformance test checks the answers, the probe predicates
/// and the inventory rows against a real database.

open FStar.Mul
open Core_models
open Vela_rekey_policy.Executor
open Vela_rekey_policy_executor_model

module L = FStar.List.Tot
module SP = FStar.Seq.Properties
module RD = Vela_rekey_policy.Rekey_driver
module MD = Vela_rekey_policy.Vault_mutation_driver
module UD = Vela_rekey_policy.Vault_upload_driver

// ── Facts about the outcome slice ──────────────────────────────────────────

/// The slice a classifier reads is the outcome list, element by element.
/// Nothing about the classifiers is restated here, so a changed classifier
/// fails the honesty theorems themselves.
let seq_of_list_facts (l: list t_WriteOutcome)
  : Lemma (forall (i: nat). i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
  let aux (i: nat) : Lemma (i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
    if i < L.length l then SP.lemma_seq_of_list_index l i
  in
  FStar.Classical.forall_intro aux

/// No statement among the first `n` is the injected failure.
let no_fault_in (f: option nat) (n: nat) : bool =
  match f with
  | None -> true
  | Some k -> k >= n

let shifted_fault (f: option nat) : option nat =
  match f with
  | None -> None
  | Some k -> Some (if k = 0 then 0 else k - 1)

let empty_outcomes (l: list t_WriteOutcome) : bool = L.length l = 0
let rows_changed (n: u64) : bool = n <> mk_u64 0

// ── Frames ─────────────────────────────────────────────────────────────────

/// Only `vault_chunks[(user, id, epoch)]` may differ.
let chunk_frame (d post: db) (user id: text) (epoch: i64) : prop =
  (forall (k: ckey). k <> mk_ckey user id epoch ==> post.chunks k == d.chunks k) /\
  post.users == d.users /\ post.devices == d.devices /\ post.oram == d.oram /\
  post.kv == d.kv

/// Only `users[user]` may differ.
let users_frame (d post: db) (user: text) : prop =
  (forall (k: text). k <> user ==> post.users k == d.users k) /\
  post.chunks == d.chunks /\ post.devices == d.devices /\ post.oram == d.oram /\
  post.kv == d.kv

/// Only `devices[device]` may differ.
let device_frame (d post: db) (device: text) : prop =
  (forall (k: text). k <> device ==> post.devices k == d.devices k) /\
  post.chunks == d.chunks /\ post.users == d.users /\ post.oram == d.oram /\
  post.kv == d.kv

/// Only `oram_buckets[(user, tree, index, epoch)]` may differ.
let oram_frame (d post: db) (user tree: text) (index epoch: i64) : prop =
  (forall (k: okey). k <> mk_okey user tree index epoch ==> post.oram k == d.oram k) /\
  post.chunks == d.chunks /\ post.users == d.users /\ post.devices == d.devices /\
  post.kv == d.kv

/// Only the schema key may differ.
let kv_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.kv k == d.kv k) /\
  post.chunks == d.chunks /\ post.users == d.users /\ post.devices == d.devices /\
  post.oram == d.oram

// ── Chunk delete ───────────────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"
let chunk_present (d: db) (user id: text) (epoch: i64) : bool =
  Some? (d.chunks (mk_ckey user id epoch))

let delete_chunk (g: answers) (d: db) (id user: text) (epoch: i64) (f: option nat)
  : (MD.t_DeleteObservation & db) =
  let r = run_auto g d (stmts_of (plan_delete_chunk id user epoch)) 0 f in
  (classify_delete (slice_of (fst r)), snd r)

/// The guarded delete is honest: it reports `Deleted` exactly when the row was
/// there and its account was ACTIVE at the row's epoch, and no statement
/// failed; then only that row is gone; otherwise nothing changed. Equivalently,
/// `Deleted` is exactly the post-state without that row.
let delete_chunk_is_honest (g: answers) (d: db) (id user: text) (epoch: i64) (f: option nat)
  : Lemma
    (let (obs, post) = delete_chunk g d id user epoch f in
     (obs == MD.DeleteObservation_Deleted <==>
        (chunk_present d user id epoch && active_at d user epoch && no_fault_in f 1)) /\
     (obs == MD.DeleteObservation_Deleted ==>
        (post.chunks (mk_ckey user id epoch) == None /\ chunk_frame d post user id epoch)) /\
     (obs =!= MD.DeleteObservation_Deleted ==> post == d) /\
     (obs == MD.DeleteObservation_Deleted <==>
        (chunk_present d user id epoch /\ active_at d user epoch /\
         post.chunks (mk_ckey user id epoch) == None /\
         chunk_frame d post user id epoch)) /\
     (obs == MD.DeleteObservation_Storage <==> f = Some 0)) =
  let r = run_auto g d (stmts_of (plan_delete_chunk id user epoch)) 0 f in
  seq_of_list_facts (fst r)

// ── Chunk reads ────────────────────────────────────────────────────────────

let read_version_obs (d: db) (id user: text) (epoch: i64) (f: option nat)
  : MD.t_VersionObservation =
  classify_version (read_chunk_version d (plan_read_version id user epoch) (faulted f 0))

/// The version read reports the stored version; a failed statement is
/// `Storage` and an absent row is `Missing`.
let read_version_is_honest (d: db) (id user: text) (epoch: i64) (f: option nat)
  : Lemma
    (let obs = read_version_obs d id user epoch f in
     (obs == MD.VersionObservation_Missing <==>
        (f <> Some 0 /\ None? (d.chunks (mk_ckey user id epoch)))) /\
     (obs == MD.VersionObservation_Storage <==> f = Some 0) /\
     (forall (v: i64).
       obs == MD.VersionObservation_Found { f_version = v } <==>
       (f <> Some 0 /\ (match d.chunks (mk_ckey user id epoch) with
                        | Some r -> r.ch_version = v
                        | None -> False)))) =
  let obs = read_version_obs d id user epoch f in
  let aux (v: i64)
    : Lemma (obs == MD.VersionObservation_Found { f_version = v } <==>
             (f <> Some 0 /\ (match d.chunks (mk_ckey user id epoch) with
                              | Some r -> r.ch_version = v
                              | None -> False))) =
    ()
  in
  FStar.Classical.forall_intro aux

let reread_obs (d: db) (id user: text) (epoch: i64) (f: option nat)
  : UD.t_RereadObservation =
  classify_reread (read_chunk_version d (plan_reread_version id user epoch) (faulted f 0))

/// The post-write re-read reports the version the guarded write committed.
let reread_is_honest (d: db) (id user: text) (epoch: i64) (f: option nat)
  : Lemma
    (let obs = reread_obs d id user epoch f in
     (obs == UD.RereadObservation_Missing <==>
        (f <> Some 0 /\ None? (d.chunks (mk_ckey user id epoch)))) /\
     (obs == UD.RereadObservation_Failed <==> f = Some 0) /\
     (forall (v: i64).
       obs == UD.RereadObservation_Read { f_version = v } <==>
       (f <> Some 0 /\ (match d.chunks (mk_ckey user id epoch) with
                        | Some r -> r.ch_version = v
                        | None -> False)))) =
  let obs = reread_obs d id user epoch f in
  let aux (v: i64)
    : Lemma (obs == UD.RereadObservation_Read { f_version = v } <==>
             (f <> Some 0 /\ (match d.chunks (mk_ckey user id epoch) with
                              | Some r -> r.ch_version = v
                              | None -> False))) =
    ()
  in
  FStar.Classical.forall_intro aux

let lookup_obs
      (d: db) (caller id: text) (read_epoch: i64) (decode_failed: bool) (f: option nat)
  : UD.t_ReadLookupObservation =
  classify_chunk_read caller read_epoch decode_failed
    (read_chunk_row d (plan_read_chunk id caller read_epoch) (faulted f 0))

/// The served row is the stored row at the caller's account and served epoch:
/// `Found` carries exactly the stored version and clock, and is only possible
/// with both scope checks true; a missing row is `Missing`, a failed statement
/// is `QueryFailed`, an undecodable row is `Malformed`.
let lookup_chunk_is_honest
      (d: db) (caller id: text) (read_epoch: i64) (decode_failed: bool) (f: option nat)
  : Lemma
    (let obs = lookup_obs d caller id read_epoch decode_failed f in
     (obs == UD.ReadLookupObservation_QueryFailed <==> f = Some 0) /\
     (obs == UD.ReadLookupObservation_Missing <==>
        (f <> Some 0 /\ None? (d.chunks (mk_ckey caller id read_epoch)))) /\
     (obs == UD.ReadLookupObservation_Malformed <==>
        (f <> Some 0 /\ decode_failed /\ Some? (d.chunks (mk_ckey caller id read_epoch)))) /\
     (forall (version lamport_clock: i64).
       obs == UD.ReadLookupObservation_Found
                { f_account_matches = true; f_epoch_matches = true; f_version = version;
                  f_lamport_clock = lamport_clock } <==>
       (f <> Some 0 /\ not decode_failed /\
        (match d.chunks (mk_ckey caller id read_epoch) with
         | Some r -> r.ch_version = version /\ r.ch_lamport = lamport_clock
         | None -> False)))) =
  let obs = lookup_obs d caller id read_epoch decode_failed f in
  let aux (version lamport_clock: i64)
    : Lemma
      (obs == UD.ReadLookupObservation_Found
                { f_account_matches = true; f_epoch_matches = true; f_version = version;
                  f_lamport_clock = lamport_clock } <==>
       (f <> Some 0 /\ not decode_failed /\
        (match d.chunks (mk_ckey caller id read_epoch) with
         | Some r -> r.ch_version = version /\ r.ch_lamport = lamport_clock
         | None -> False))) =
    ()
  in
  FStar.Classical.forall_intro_2 aux

#pop-options

// ── Chunk writes ───────────────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let fresh_chunk (user id: text) (epoch lamport: i64) (writer ciphertext now: text) : chunk_row =
  { ch_user = user; ch_id = id; ch_epoch = epoch; ch_version = mk_i64 1;
    ch_lamport = lamport; ch_last_writer = Some writer; ch_ciphertext = ciphertext;
    ch_created_at = now; ch_updated_at = now }

/// `PutChunkIo::guarded_write` for `If-Match: 0` on an ACTIVE account.
let chunk_create
      (g: answers) (d: db) (id user: text) (lamport: i64) (writer ciphertext now: text)
      (epoch permit_epoch: i64) (duplicate: bool) (f: option nat)
  : (UD.t_WriteObservation & db) =
  let probe = read_exists (plan_chunk_exists id user epoch)
      (chunk_present d user id epoch) (faulted f 0) in
  let plan = plan_chunk_create id user lamport writer ciphertext epoch now permit_epoch in
  if chunk_present d user id epoch
  then (classify_chunk_create probe duplicate (Seq.seq_of_list []), d)
  else
    let r = run_auto g d (stmts_of plan) 0 (shifted_fault f) in
    (classify_chunk_create probe duplicate (slice_of (fst r)), snd r)

/// The create path is honest: `Inserted` exactly when the account was ACTIVE
/// at the permit's epoch, the id was fresh and nothing failed; then exactly the
/// intended row is stored; `Existing` exactly when the id was present; a
/// constraint error on a fresh id is `Duplicate`; and nothing changes unless
/// the insert ran.
let chunk_create_is_honest
      (g: answers) (d: db) (id user: text) (lamport: i64) (writer ciphertext now: text)
      (epoch permit_epoch: i64) (duplicate: bool) (f: option nat)
  : Lemma
    (let (obs, post) = chunk_create g d id user lamport writer ciphertext now epoch
                          permit_epoch duplicate f in
     (obs == UD.WriteObservation_Inserted <==>
        (active_at d user permit_epoch && not (chunk_present d user id epoch) &&
         no_fault_in f 2)) /\
     (obs == UD.WriteObservation_Existing <==>
        (chunk_present d user id epoch && f <> Some 0)) /\
     (obs == UD.WriteObservation_Duplicate <==>
        (duplicate && not (chunk_present d user id epoch) && f = Some 1)) /\
     (obs == UD.WriteObservation_Inserted ==>
        (post.chunks (mk_ckey user id epoch) ==
           Some (fresh_chunk user id epoch lamport writer ciphertext now) /\
         chunk_frame d post user id epoch)) /\
     (obs =!= UD.WriteObservation_Inserted ==> post == d)) =
  let probe = read_exists (plan_chunk_exists id user epoch)
      (chunk_present d user id epoch) (faulted f 0) in
  let r = run_auto g d (stmts_of (plan_chunk_create id user lamport writer ciphertext epoch now
                                   permit_epoch)) 0 (shifted_fault f) in
  seq_of_list_facts (fst r)

/// `PutChunkIo::guarded_write` for `If-Match: 0` on a FREEZING account.
let chunk_shadow
      (g: answers) (d: db) (id user: text) (lamport: i64) (writer ciphertext now: text)
      (epoch read_epoch: i64) (starter rotation: text) (f: option nat)
  : (UD.t_WriteObservation & db) =
  let r = run_auto g d
    (stmts_of (plan_chunk_shadow id user lamport writer ciphertext epoch now read_epoch
                 starter rotation)) 0 f in
  (classify_chunk_shadow (slice_of (fst r)), snd r)

/// The shadow upsert is honest: it applies exactly when this account is
/// FREEZING at the served epoch under the same starter and rotation id and
/// nothing failed; then the row is stored with `version` bumped (or as a fresh
/// row) and nothing else changed; otherwise nothing changed. A shadow write can
/// therefore never land outside an attempt the account is actually running.
let chunk_shadow_is_honest
      (g: answers) (d: db) (id user: text) (lamport: i64) (writer ciphertext now: text)
      (epoch read_epoch: i64) (starter rotation: text) (f: option nat)
  : Lemma
    (let (obs, post) = chunk_shadow g d id user lamport writer ciphertext now epoch
                          read_epoch starter rotation f in
     let key = mk_ckey user id epoch in
     (obs == UD.WriteObservation_Inserted <==>
        (freezing_attempt d user read_epoch starter rotation && no_fault_in f 1)) /\
     (obs == UD.WriteObservation_Skipped <==>
        (not (freezing_attempt d user read_epoch starter rotation) && f <> Some 0)) /\
     (obs == UD.WriteObservation_Inserted ==>
        chunk_frame d post user id epoch /\
        (match d.chunks key with
         | Some r ->
           post.chunks key == Some ({ r with ch_version = r.ch_version +. mk_i64 1;
                                            ch_lamport = lamport;
                                            ch_last_writer = Some writer;
                                            ch_ciphertext = ciphertext;
                                            ch_updated_at = now })
         | None ->
           post.chunks key ==
             Some (fresh_chunk user id epoch lamport writer ciphertext now))) /\
     (obs =!= UD.WriteObservation_Inserted ==> post == d)) =
  let r = run_auto g d
    (stmts_of (plan_chunk_shadow id user lamport writer ciphertext epoch now read_epoch
                 starter rotation)) 0 f in
  seq_of_list_facts (fst r)

/// `PutChunkIo::guarded_write` for `If-Match: version`.
let chunk_update
      (g: answers) (d: db) (id user: text) (version lamport: i64) (writer ciphertext now: text)
      (epoch permit_epoch: i64) (f: option nat)
  : (UD.t_WriteObservation & db) =
  let r = run_auto g d
    (stmts_of (plan_chunk_update id user version lamport writer ciphertext epoch now permit_epoch))
    0 f in
  (classify_chunk_update (slice_of (fst r)), snd r)

/// The replace path is honest: `Updated` exactly when the stored row had the
/// `If-Match` version, the account was ACTIVE at the permit's epoch, and
/// nothing failed; then the row is bumped and only that row changed; otherwise
/// nothing changed, so a stale writer cannot overwrite a newer row.
let chunk_update_is_honest
      (g: answers) (d: db) (id user: text) (version lamport: i64) (writer ciphertext now: text)
      (epoch permit_epoch: i64) (f: option nat)
  : Lemma
    (let (obs, post) = chunk_update g d id user version lamport writer ciphertext now
                          epoch permit_epoch f in
     let key = mk_ckey user id epoch in
     (obs == UD.WriteObservation_Updated <==>
        ((match d.chunks key with
          | Some r -> r.ch_version = version
          | None -> false) && active_at d user permit_epoch && no_fault_in f 1)) /\
     (obs == UD.WriteObservation_Updated ==>
        (chunk_frame d post user id epoch /\
         (match d.chunks key with
          | Some r ->
            post.chunks key == Some ({ r with ch_version = r.ch_version +. mk_i64 1;
                                              ch_lamport = lamport;
                                              ch_last_writer = Some writer;
                                              ch_ciphertext = ciphertext;
                                              ch_updated_at = now })
          | None -> False))) /\
     (obs =!= UD.WriteObservation_Updated ==> post == d)) =
  let r = run_auto g d
    (stmts_of (plan_chunk_update id user version lamport writer ciphertext epoch now permit_epoch))
    0 f in
  seq_of_list_facts (fst r)

#pop-options

// ── Multi-row and probe reads ──────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let inventory_obs
      (d: db) (user: text) (epoch: i64)
      (rows: Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global) (f: option nat)
  : RD.t_InventoryObservation =
  classify_inventory (read_inventory (plan_read_inventory user epoch) rows (faulted f 0))

/// The inventory read reports `Read` exactly when its query ran; `rows` are the
/// rows that query returned (a functional table cannot enumerate itself, so the
/// row set is the store's answer, checked against the Rust mirror by the
/// conformance test).
let inventory_is_honest
      (d: db) (user: text) (epoch: i64)
      (rows: Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global) (f: option nat)
  : Lemma
    ((inventory_obs d user epoch rows f == RD.InventoryObservation_Read <==> f <> Some 0) /\
     (inventory_obs d user epoch rows f == RD.InventoryObservation_Failed <==> f = Some 0)) =
  ()

/// A completeness probe: `Found` exactly when its query matched a row and
/// nothing failed, `Empty` exactly when it matched none, `Storage` on failure.
let probe_obs (stmt: t_VaultStmt) (found: bool) (f: option nat) : RD.t_ProbeObservation =
  classify_probe (read_exists stmt found (faulted f 0))

let probe_is_honest (stmt: t_VaultStmt) (found: bool) (f: option nat)
  : Lemma
    ((probe_obs stmt found f == RD.ProbeObservation_Found <==> (f <> Some 0 && found)) /\
     (probe_obs stmt found f == RD.ProbeObservation_Empty <==> (f <> Some 0 && not found)) /\
     (probe_obs stmt found f == RD.ProbeObservation_Storage <==> f = Some 0)) =
  ()

#pop-options

// ── Capsule acknowledgement, capability and the schema key ─────────────────

#push-options "--fuel 4 --ifuel 2"

let ack_capsule (g: answers) (d: db) (device user: text) (epoch: i64) (f: option nat)
  : (MD.t_AckObservation & db) =
  let r = run_auto g d (stmts_of (plan_ack_capsule device user epoch)) 0 f in
  (classify_ack (slice_of (fst r)), snd r)

/// The acknowledgement clears a capsule exactly when the device row was the
/// caller's, unrevoked, and awaiting precisely this epoch; otherwise nothing
/// changes, so a replayed or crossed ACK cannot strand another epoch's capsule.
let ack_capsule_is_honest
      (g: answers) (d: db) (device user: text) (epoch: i64) (f: option nat)
  : Lemma
    (let (obs, post) = ack_capsule g d device user epoch f in
     let matching : bool =
       (match d.devices device with
        | Some r -> r.dv_user = user && r.dv_revoked = mk_i64 0 && r.dv_capsule_epoch = Some epoch
        | None -> false) in
     (obs == MD.AckObservation_Cleared <==> (matching && no_fault_in f 1)) /\
     (obs == MD.AckObservation_Missed <==> (not matching && f <> Some 0)) /\
     (obs == MD.AckObservation_Storage <==> f = Some 0) /\
     (obs == MD.AckObservation_Cleared ==>
        (device_frame d post device /\
         (match d.devices device with
          | Some r ->
            post.devices device == Some ({ r with dv_capsule = None; dv_capsule_epoch = None })
          | None -> False))) /\
     (obs =!= MD.AckObservation_Cleared ==> post == d)) =
  let r = run_auto g d (stmts_of (plan_ack_capsule device user epoch)) 0 f in
  seq_of_list_facts (fst r)

let pending_obs (d: db) (device user: text) (f: option nat) : MD.t_PendingObservation =
  classify_pending (read_pending d (plan_pending_capsule device user) (faulted f 0))

/// The pending-epoch probe reports the stored cell: `Missing` for no eligible
/// row, `Pending` when a capsule epoch is stored, `Replay` when none is.
let pending_is_honest (d: db) (device user: text) (f: option nat)
  : Lemma
    ((pending_obs d device user f == MD.PendingObservation_Storage <==> f = Some 0) /\
     (pending_obs d device user f == MD.PendingObservation_Missing <==>
        (f <> Some 0 /\
         (match d.devices device with
          | Some r -> not (r.dv_user = user && r.dv_revoked = mk_i64 0)
          | None -> True))) /\
     (pending_obs d device user f == MD.PendingObservation_Pending <==>
        (f <> Some 0 /\
         (match d.devices device with
          | Some r ->
            r.dv_user = user && r.dv_revoked = mk_i64 0 && Some? r.dv_capsule_epoch
          | None -> False))) /\
     (pending_obs d device user f == MD.PendingObservation_Replay <==>
        (f <> Some 0 /\
         (match d.devices device with
          | Some r -> r.dv_user = user && r.dv_revoked = mk_i64 0 && None? r.dv_capsule_epoch
          | None -> False)))) =
  ()

let attest_capable (g: answers) (d: db) (device user: text) (f: option nat)
  : (MD.t_AttestObservation & db) =
  let r = run_auto g d (stmts_of (plan_attest_capable device user)) 0 f in
  (classify_attest (slice_of (fst r)), snd r)

/// Capability is attested only for the caller's own unrevoked device, and a
/// revoked or foreign device is reported missing.
let attest_capable_is_honest
      (g: answers) (d: db) (device user: text) (f: option nat)
  : Lemma
    (let (obs, post) = attest_capable g d device user f in
     let matching : bool =
       (match d.devices device with
        | Some r -> r.dv_user = user && r.dv_revoked = mk_i64 0
        | None -> false) in
     (obs == MD.AttestObservation_Attested <==> (matching && no_fault_in f 1)) /\
     (obs == MD.AttestObservation_Missing <==> (not matching && f <> Some 0)) /\
     (obs == MD.AttestObservation_Storage <==> f = Some 0) /\
     (obs == MD.AttestObservation_Attested ==>
        (device_frame d post device /\
         (match d.devices device with
          | Some r -> post.devices device == Some ({ r with dv_capable = mk_i64 1 })
          | None -> False))) /\
     (obs =!= MD.AttestObservation_Attested ==> post == d)) =
  let r = run_auto g d (stmts_of (plan_attest_capable device user)) 0 f in
  seq_of_list_facts (fst r)

let schema_floor (g: answers) (d: db) (key: text) (f: option nat)
  : (MD.t_SchemaWriteObservation & db) =
  let r = run_auto g d (stmts_of (plan_schema_floor key)) 0 f in
  (classify_schema_write (slice_of (fst r)), snd r)

/// The one durable store write: `Written` exactly when it ran, and then the
/// schema key holds "2" and nothing else in the state changed.
let schema_floor_is_honest (g: answers) (d: db) (key: text) (f: option nat)
  : Lemma
    (let (obs, post) = schema_floor g d key f in
     (obs == MD.SchemaWriteObservation_Written <==> f <> Some 0) /\
     (obs == MD.SchemaWriteObservation_Storage <==> f = Some 0) /\
     (obs == MD.SchemaWriteObservation_Written ==>
        (post.kv key == Some (Alloc.String.String "2") /\ kv_frame d post key)) /\
     (obs =!= MD.SchemaWriteObservation_Written ==> post == d)) =
  let r = run_auto g d (stmts_of (plan_schema_floor key)) 0 f in
  seq_of_list_facts (fst r)

#pop-options

// ── ORAM buckets ───────────────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let oram_present (d: db) (user tree: text) (index epoch: i64) : bool =
  Some? (d.oram (mk_okey user tree index epoch))

let fresh_oram (user tree: text) (index epoch lamport: i64) (writer ciphertext now: text)
  : oram_row =
  { or_user = user; or_tree = tree; or_index = index; or_epoch = epoch;
    or_version = mk_i64 1; or_lamport = lamport; or_last_writer = Some writer;
    or_ciphertext = ciphertext; or_created_at = now; or_updated_at = now }

/// `PutOramIo::write_bucket`.
let oram_write
      (g: answers) (d: db) (user tree: text) (index if_match lamport: i64)
      (writer ciphertext now: text) (epoch: i64) (f: option nat)
  : (MD.t_BucketObservation & db) =
  if if_match = mk_i64 0
  then
    let probe = read_exists (plan_oram_exists user tree index epoch)
        (oram_present d user tree index epoch) (faulted f 0) in
    if oram_present d user tree index epoch
    then (classify_oram_create probe (Seq.seq_of_list []), d)
    else
      let r = run_auto g d
        (stmts_of (plan_oram_insert user tree index lamport writer ciphertext epoch now))
        0 (shifted_fault f) in
      (classify_oram_create probe (slice_of (fst r)), snd r)
  else
    let r = run_auto g d
      (stmts_of (plan_oram_update user tree index if_match lamport writer ciphertext epoch now))
      0 f in
    (classify_oram_update (slice_of (fst r)), snd r)

/// The ORAM write is honest: a create inserts exactly when the account was
/// ACTIVE at the bucket's epoch and the bucket was absent (an existing bucket
/// is `Existing`), a replace applies exactly when the stored version matched
/// the `If-Match` version; on success exactly that bucket row is written and
/// nothing else changed, otherwise nothing changed.
let oram_write_is_honest
      (g: answers) (d: db) (user tree: text) (index if_match lamport: i64)
      (writer ciphertext now: text) (epoch: i64) (f: option nat)
  : Lemma
    (let (obs, post) = oram_write g d user tree index if_match lamport writer ciphertext now
                          epoch f in
     let key = mk_okey user tree index epoch in
     (if_match = mk_i64 0 ==>
       ((obs == MD.BucketObservation_Written <==>
           (active_at d user epoch && not (oram_present d user tree index epoch) &&
            no_fault_in f 2)) /\
        (obs == MD.BucketObservation_Existing <==>
           (oram_present d user tree index epoch && f <> Some 0)))) /\
     (if_match <> mk_i64 0 ==>
       (obs == MD.BucketObservation_Written <==>
          (active_at d user epoch &&
           (match d.oram key with
            | Some row -> row.or_version = if_match
            | None -> false) &&
           no_fault_in f 1))) /\
     (obs == MD.BucketObservation_Written ==>
        (oram_frame d post user tree index epoch /\
         (match d.oram key with
          | Some row ->
            post.oram key == Some ({ row with or_version = row.or_version +. mk_i64 1;
                                             or_lamport = lamport;
                                             or_last_writer = Some writer;
                                             or_ciphertext = ciphertext;
                                             or_updated_at = now })
          | None ->
            post.oram key == Some (fresh_oram user tree index epoch lamport writer ciphertext now)))) /\
     (obs =!= MD.BucketObservation_Written ==> post == d)) =
  if if_match = mk_i64 0
  then
    let probe = read_exists (plan_oram_exists user tree index epoch)
        (oram_present d user tree index epoch) (faulted f 0) in
    let r = run_auto g d
      (stmts_of (plan_oram_insert user tree index lamport writer ciphertext epoch now))
      0 (shifted_fault f) in
    seq_of_list_facts (fst r)
  else
    let r = run_auto g d
      (stmts_of (plan_oram_update user tree index if_match lamport writer ciphertext epoch now))
      0 f in
    seq_of_list_facts (fst r)

#pop-options

// ── Capsules written during a rotation, and the deadline refresh ───────────

#push-options "--fuel 4 --ifuel 2"

/// `RekeyIo::write_capsule`.
let write_capsule
      (g: answers) (d: db) (device user capsule: text) (capsule_epoch from_epoch: i64)
      (starter rotation: text) (f: option nat)
  : (RD.t_CapsuleObservation & db) =
  let r = run_auto g d
    (stmts_of (plan_write_capsule device user capsule capsule_epoch from_epoch starter rotation))
    0 f in
  (classify_capsule_write (slice_of (fst r)), snd r)

/// A capsule is stored exactly for the caller's own unrevoked device while the
/// account is FREEZING at the attempt's epoch under the same starter and
/// rotation id; then only that device row gains the capsule. A stale or
/// foreign attempt cannot write one.
let write_capsule_is_honest
      (g: answers) (d: db) (device user capsule: text) (capsule_epoch from_epoch: i64)
      (starter rotation: text) (f: option nat)
  : Lemma
    (let (obs, post) = write_capsule g d device user capsule capsule_epoch from_epoch
                          starter rotation f in
     let eligible : bool =
       (match d.devices device with
        | Some r -> r.dv_user = user && r.dv_revoked = mk_i64 0
        | None -> false) in
     (obs == RD.CapsuleObservation_Stored <==>
        (eligible && freezing_attempt d user from_epoch starter rotation && no_fault_in f 1)) /\
     (obs == RD.CapsuleObservation_NotTarget <==>
        (f <> Some 0 && not (eligible && freezing_attempt d user from_epoch starter rotation))) /\
     (obs == RD.CapsuleObservation_Storage <==> f = Some 0) /\
     (obs == RD.CapsuleObservation_Stored ==>
        (device_frame d post device /\
         (match d.devices device with
          | Some r ->
            post.devices device == Some ({ r with dv_capsule = Some capsule;
                                                  dv_capsule_epoch = Some capsule_epoch })
          | None -> False))) /\
     (obs =!= RD.CapsuleObservation_Stored ==> post == d)) =
  let r = run_auto g d
    (stmts_of (plan_write_capsule device user capsule capsule_epoch from_epoch starter rotation))
    0 f in
  seq_of_list_facts (fst r)

/// `record_shadow_activity`.
let shadow_activity
      (g: answers) (d: db) (user: text) (read_epoch write_epoch: i64)
      (starter rotation now: text) (f: option nat)
  : (UD.t_ActivityObservation & db) =
  if write_epoch = read_epoch
  then (UD.ActivityObservation_Refreshed, d)
  else
    let r = run_auto g d
      (stmts_of (plan_shadow_activity user read_epoch starter rotation now)) 0 f in
    (classify_shadow_activity (slice_of (fst r)), snd r)

/// The deadline refresh reports `Refreshed` exactly when there was nothing to
/// refresh (an ACTIVE write) or the guarded refresh matched the live attempt;
/// `Ended` when the rotation ended first; a failure changes nothing.
let shadow_activity_is_honest
      (g: answers) (d: db) (user: text) (read_epoch write_epoch: i64)
      (starter rotation now: text) (f: option nat)
  : Lemma
    (let (obs, post) = shadow_activity g d user read_epoch write_epoch starter rotation now f in
     let matching : bool =
       (match d.users user with
        | Some r ->
          r.us_key_epoch = read_epoch && freezing (Some r) &&
          r.us_starter = Some starter && r.us_rotation = Some rotation
        | None -> false) in
     (obs == UD.ActivityObservation_Refreshed <==>
        (write_epoch = read_epoch || (matching && no_fault_in f 1))) /\
     (write_epoch = read_epoch ==> post == d) /\
     (write_epoch <> read_epoch /\ obs == UD.ActivityObservation_Refreshed ==>
        (users_frame d post user /\
         (match d.users user with
          | Some r -> post.users user == Some ({ r with us_started = Some now })
          | None -> False))) /\
     (write_epoch <> read_epoch /\ obs =!= UD.ActivityObservation_Refreshed ==> post == d)) =
  if write_epoch = read_epoch
  then ()
  else
    let r = run_auto g d
      (stmts_of (plan_shadow_activity user read_epoch starter rotation now)) 0 f in
    seq_of_list_facts (fst r)

#pop-options

// ── The freeze transaction ─────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let freeze_run
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat)
  : (list t_WriteOutcome & db) =
  cas_tx g d
    (L.append (stmts_of (plan_freeze_cas user from_epoch now starter rotation))
              (L.append (stmts_of (plan_freeze_cleanup user from_epoch))
                        (stmts_of (plan_commit_transaction ()))))
    f

let freeze_cas_obs
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat) : RD.t_CasObservation =
  match fst (freeze_run g d user from_epoch now starter rotation f) with
  | o :: _ -> classify_freeze_cas (Seq.seq_of_list [o])
  | [] -> RD.CasObservation_Storage

let freeze_cleanup_obs
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat) : RD.t_CleanupObservation =
  match fst (freeze_run g d user from_epoch now starter rotation f) with
  | _ :: o :: _ -> classify_cleanup (Seq.seq_of_list [o])
  | _ -> RD.CleanupObservation_Storage

let freeze_tx_obs
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat) : RD.t_TransactionObservation =
  match fst (freeze_run g d user from_epoch now starter rotation f) with
  | _ :: _ :: o :: _ -> classify_transaction (Seq.seq_of_list [o])
  | _ -> RD.TransactionObservation_Failed

let freeze_post
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat) : db =
  snd (freeze_run g d user from_epoch now starter rotation f)

/// The state a committed freeze publishes: the account is FREEZING at the
/// served epoch under this starter and rotation, every other epoch's chunks of
/// the account are gone, and nothing else changed.
let freeze_published
      (d post: db) (user: text) (from_epoch: i64) (now starter rotation: text) : prop =
  (match d.users user with
   | Some r ->
     post.users user ==
       Some ({ r with us_rekey_state = Some (Alloc.String.String "freezing");
                       us_started = Some now; us_starter = Some starter;
                       us_rotation = Some rotation })
   | None -> False) /\
  (forall (k: text). k <> user ==> post.users k == d.users k) /\
  (forall (k: ckey).
     k.ck_user = user && (k.ck_epoch = from_epoch) = false ==> post.chunks k == None) /\
  (forall (k: ckey).
     (k.ck_user = user && (k.ck_epoch = from_epoch) = false) = false ==>
       post.chunks k == d.chunks k) /\
  post.devices == d.devices /\ post.oram == d.oram /\ post.kv == d.kv

/// The freeze CAS is honest: it applies exactly when the account was ACTIVE at
/// that epoch and the three `NOT EXISTS` checks held, and nothing failed; a
/// skipped CAS or a failed statement publishes nothing at all.
let freeze_cas_is_honest
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat)
  : Lemma
    (let cas = freeze_cas_obs g d user from_epoch now starter rotation f in
     let post = freeze_post g d user from_epoch now starter rotation f in
     (cas == RD.CasObservation_Updated <==>
        (freeze_ready g d user from_epoch && f <> Some 0)) /\
     (cas == RD.CasObservation_Skipped <==>
        (not (freeze_ready g d user from_epoch) && f <> Some 0)) /\
     (cas == RD.CasObservation_Storage <==> f = Some 0) /\
     (cas =!= RD.CasObservation_Updated ==> post == d)) =
  let r = cas_tx g d
    (L.append (stmts_of (plan_freeze_cas user from_epoch now starter rotation))
              (L.append (stmts_of (plan_freeze_cleanup user from_epoch))
                        (stmts_of (plan_commit_transaction ()))))
    f in
  seq_of_list_facts (fst r)

/// The freeze transaction publishes both effects at the commit and nothing
/// before it: the cleanup reports `Done` exactly when the CAS won and it ran,
/// the commit reports `Committed` exactly when the CAS won and nothing failed,
/// and only then does the account turn FREEZING with every other epoch's
/// chunks gone. A failed cleanup or commit publishes nothing.
let freeze_transaction_is_honest
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat)
  : Lemma
    (let cleanup = freeze_cleanup_obs g d user from_epoch now starter rotation f in
     let tx = freeze_tx_obs g d user from_epoch now starter rotation f in
     let post = freeze_post g d user from_epoch now starter rotation f in
     (cleanup == RD.CleanupObservation_Done <==>
        (freeze_ready g d user from_epoch && f <> Some 0 && f <> Some 1)) /\
     (tx == RD.TransactionObservation_Committed <==>
        (freeze_ready g d user from_epoch && no_fault_in f 3)) /\
     (tx == RD.TransactionObservation_Committed ==>
        freeze_published d post user from_epoch now starter rotation) /\
     (tx =!= RD.TransactionObservation_Committed ==> post == d)) =
  let r = cas_tx g d
    (L.append (stmts_of (plan_freeze_cas user from_epoch now starter rotation))
              (L.append (stmts_of (plan_freeze_cleanup user from_epoch))
                        (stmts_of (plan_commit_transaction ()))))
    f in
  seq_of_list_facts (fst r)

/// What it means for the freeze CAS's `NOT EXISTS` answers to be the truth.
let freeze_guard_is_honest
      (g: answers) (d: db) (user: text) (from_epoch: i64)
  : Lemma
    ((g.a_oram_empty <==> ~(any_oram d user)) ==>
     (g.a_devices_ready <==> ~(any_incapable d user)) ==>
     (g.a_capsules_free <==> ~(any_pending_capsule d user)) ==>
     (freeze_ready g d user from_epoch <==>
        ((match d.users user with
          | Some r -> r.us_key_epoch = from_epoch && r.us_rekey_state = None
          | None -> False) /\
         ~(any_oram d user) /\ ~(any_incapable d user) /\
         ~(any_pending_capsule d user)))) =
  ()

#pop-options

// ── The commit CAS and its sweep ───────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let commit_cas_obs
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat) : RD.t_CasObservation =
  classify_freeze_cas
    (slice_of (fst (run_auto g d (stmts_of (plan_commit_cas user from_epoch to_epoch
                                              starter rotation)) 0 f)))

let commit_swept
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat) : (list t_WriteOutcome & db) =
  let r0 = run_auto g d (stmts_of (plan_commit_cas user from_epoch to_epoch
                                     starter rotation)) 0 f in
  if commit_cas_obs g d user from_epoch to_epoch starter rotation f =
     RD.CasObservation_Updated
  then run_auto g (snd r0) (stmts_of (plan_sweep_old_chunks user to_epoch)) 0
         (shifted_fault f)
  else ([], snd r0)

let commit_sweep_obs
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat) : RD.t_SweepObservation =
  if commit_cas_obs g d user from_epoch to_epoch starter rotation f =
     RD.CasObservation_Updated
  then classify_sweep (slice_of (fst (commit_swept g d user from_epoch to_epoch
                                         starter rotation f)))
  else RD.SweepObservation_Failed

let commit_post
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat) : db =
  snd (commit_swept g d user from_epoch to_epoch starter rotation f)

/// The account row a committed rotation publishes.
let commit_user (d post: db) (user: text) (to_epoch: i64) (rotation: text) : prop =
  (match d.users user with
   | Some r ->
     post.users user ==
       Some ({ r with us_key_epoch = to_epoch; us_rekey_state = None;
                       us_started = None; us_starter = None; us_rotation = None;
                       us_last_rekey_id = Some rotation;
                       us_last_rekey_epoch = Some to_epoch })
   | None -> False) /\
  (forall (k: text). k <> user ==> post.users k == d.users k) /\
  post.devices == d.devices /\ post.oram == d.oram /\ post.kv == d.kv

/// The commit CAS is honest: it advances the account exactly when it was
/// FREEZING at `from_epoch` under this attempt and both completeness checks
/// held. A skipped or failed commit changes nothing.
let commit_cas_is_honest
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat)
  : Lemma
    (let cas = commit_cas_obs g d user from_epoch to_epoch starter rotation f in
     let post = commit_post g d user from_epoch to_epoch starter rotation f in
     (cas == RD.CasObservation_Updated <==>
        (commit_ready g d user from_epoch to_epoch starter rotation && no_fault_in f 1)) /\
     (cas == RD.CasObservation_Skipped <==>
        (not (commit_ready g d user from_epoch to_epoch starter rotation) &&
         f <> Some 0)) /\
     (cas == RD.CasObservation_Storage <==> f = Some 0) /\
     (cas =!= RD.CasObservation_Updated ==>
        (post == d /\ commit_sweep_obs g d user from_epoch to_epoch starter rotation f ==
                      RD.SweepObservation_Failed))) =
  let r0 = run_auto g d (stmts_of (plan_commit_cas user from_epoch to_epoch
                                     starter rotation)) 0 f in
  seq_of_list_facts (fst r0)

/// The sweep is honest: `Done` exactly when the commit advanced the account and
/// it ran; then the account row is ACTIVE at `to_epoch` with the recorded
/// replay id, every superseded chunk row is gone, and nothing else changed. A
/// failed sweep leaves the committed account with the chunks untouched.
let commit_sweep_is_honest
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat)
  : Lemma
    (let cas = commit_cas_obs g d user from_epoch to_epoch starter rotation f in
     let sweep = commit_sweep_obs g d user from_epoch to_epoch starter rotation f in
     let post = commit_post g d user from_epoch to_epoch starter rotation f in
     (sweep == RD.SweepObservation_Done <==>
        (commit_ready g d user from_epoch to_epoch starter rotation && no_fault_in f 2)) /\
     (cas == RD.CasObservation_Updated ==> commit_user d post user to_epoch rotation) /\
     (sweep == RD.SweepObservation_Done ==>
        (forall (k: ckey).
           k.ck_user = user && k.ck_epoch <. to_epoch ==> post.chunks k == None) /\
        (forall (k: ckey).
           (k.ck_user = user && k.ck_epoch <. to_epoch) = false ==>
             post.chunks k == d.chunks k)) /\
     (cas == RD.CasObservation_Updated /\ sweep =!= RD.SweepObservation_Done ==>
        post.chunks == d.chunks) /\
     (cas =!= RD.CasObservation_Updated ==> post == d)) =
  let r0 = run_auto g d (stmts_of (plan_commit_cas user from_epoch to_epoch
                                     starter rotation)) 0 f in
  seq_of_list_facts (fst r0)

/// What it means for the commit CAS's two `NOT EXISTS` answers to be the truth.
let commit_guard_is_honest
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text)
  : Lemma
    ((g.a_shadows_ready <==> ~(any_missing_shadow d user from_epoch to_epoch)) ==>
     (g.a_capsules_complete <==> ~(any_incomplete_device d user to_epoch)) ==>
     (commit_ready g d user from_epoch to_epoch starter rotation <==>
        ((match d.users user with
          | Some r ->
            r.us_key_epoch = from_epoch && freezing (Some r) &&
            r.us_starter = Some starter && r.us_rotation = Some rotation
          | None -> False) /\
         ~(any_missing_shadow d user from_epoch to_epoch) /\
         ~(any_incomplete_device d user to_epoch)))) =
  ()

#pop-options

// ── The abort / timeout transaction ────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let rollback_run
      (g: answers) (d: db) (user: text) (epoch target_epoch: i64) (rotation: text)
      (f: option nat) : (r: (list t_WriteOutcome & db){L.length (fst r) <= 4}) =
  cas_tx g d
    (L.append (stmts_of (plan_rollback_cas user epoch rotation))
              (L.append (stmts_of (plan_rollback_cleanup user epoch target_epoch))
                        (stmts_of (plan_commit_transaction ()))))
    f

let rollback_obs
      (g: answers) (d: db) (user: text) (epoch target_epoch: i64) (rotation: text)
      (f: option nat) : RD.t_RollbackObservation =
  classify_rollback (slice_of (fst (rollback_run g d user epoch target_epoch rotation f)))

let rollback_post
      (g: answers) (d: db) (user: text) (epoch target_epoch: i64) (rotation: text)
      (f: option nat) : db =
  snd (rollback_run g d user epoch target_epoch rotation f)

/// The guard: the attempt's CAS matches the live row.
let rollback_matches (d: db) (user: text) (epoch: i64) (rotation: text) : bool =
  match d.users user with
  | Some r ->
    r.us_key_epoch = epoch && freezing (Some r) && r.us_rotation = Some rotation
  | None -> false

/// A device row carrying this attempt's capsule.
let capsule_for_attempt (d: db) (id user: text) (target_epoch: i64) : bool =
  match d.devices id with
  | Some r -> r.dv_user = user && r.dv_capsule_epoch = Some target_epoch
  | None -> false

/// The state a rollback publishes: the account is ACTIVE at the same epoch,
/// this attempt's chunks (any epoch above it) are gone, its capsules are
/// cleared, and nothing else changed.
let rollback_published
      (d post: db) (user: text) (epoch target_epoch: i64) : prop =
  (match d.users user with
   | Some r ->
     post.users user ==
       Some ({ r with us_rekey_state = None; us_started = None; us_starter = None;
                       us_rotation = None })
   | None -> False) /\
  (forall (k: text). k <> user ==> post.users k == d.users k) /\
  (forall (k: ckey).
     k.ck_user = user && k.ck_epoch >. epoch ==> post.chunks k == None) /\
  (forall (k: ckey).
     (k.ck_user = user && k.ck_epoch >. epoch) = false ==> post.chunks k == d.chunks k) /\
  (forall (id: text).
     capsule_for_attempt d id user target_epoch ==>
       (match post.devices id with
        | Some r -> r.dv_capsule == None /\ r.dv_capsule_epoch == None
        | None -> False)) /\
  (forall (id: text).
     not (capsule_for_attempt d id user target_epoch) ==>
       post.devices id == d.devices id) /\
  post.oram == d.oram /\ post.kv == d.kv

/// The abort/timeout CAS is honest: `RolledBack` exactly when the CAS matched
/// the live attempt and every statement succeeded, `Raced` exactly when the
/// attempt was already gone, and any failure publishes nothing.
let rollback_cas_is_honest
      (g: answers) (d: db) (user: text) (epoch target_epoch: i64) (rotation: text)
      (f: option nat)
  : Lemma
    (let obs = rollback_obs g d user epoch target_epoch rotation f in
     let post = rollback_post g d user epoch target_epoch rotation f in
     (obs == RD.RollbackObservation_RolledBack <==>
        (rollback_matches d user epoch rotation && no_fault_in f 4)) /\
     (obs == RD.RollbackObservation_Raced <==>
        (not (rollback_matches d user epoch rotation) && f <> Some 0)) /\
     (obs == RD.RollbackObservation_Storage <==>
        (f = Some 0 ||
         (rollback_matches d user epoch rotation &&
          (f = Some 1 || f = Some 2 || f = Some 3)))) /\
     (obs =!= RD.RollbackObservation_RolledBack ==> post == d)) =
  let r = cas_tx g d
    (L.append (stmts_of (plan_rollback_cas user epoch rotation))
              (L.append (stmts_of (plan_rollback_cleanup user epoch target_epoch))
                        (stmts_of (plan_commit_transaction ()))))
    f in
  seq_of_list_facts (fst r)

/// What a won rollback publishes: the account is ACTIVE at the same epoch, this
/// attempt's chunks (every epoch above it) are gone, its capsules are cleared,
/// and nothing else changed.
let rollback_publishes_is_honest
      (g: answers) (d: db) (user: text) (epoch target_epoch: i64) (rotation: text)
      (f: option nat)
  : Lemma
    (rollback_obs g d user epoch target_epoch rotation f ==
       RD.RollbackObservation_RolledBack ==>
     rollback_published d (rollback_post g d user epoch target_epoch rotation f)
       user epoch target_epoch) =
  let r = cas_tx g d
    (L.append (stmts_of (plan_rollback_cas user epoch rotation))
              (L.append (stmts_of (plan_rollback_cleanup user epoch target_epoch))
                        (stmts_of (plan_commit_transaction ()))))
    f in
  seq_of_list_facts (fst r)

#pop-options

// ── Facts the executor users rely on ───────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

/// A committed chunk create ran under an account that was ACTIVE at the
/// permit's epoch, so the epoch guard was evaluated against the live row.
let chunk_create_needs_active_account
      (g: answers) (d: db) (id user: text) (lamport: i64) (writer ciphertext now: text)
      (epoch permit_epoch: i64) (duplicate: bool) (f: option nat)
  : Lemma
    (fst (chunk_create g d id user lamport writer ciphertext now epoch permit_epoch
            duplicate f) == UD.WriteObservation_Inserted ==>
     active_at d user permit_epoch) =
  chunk_create_is_honest g d id user lamport writer ciphertext now epoch permit_epoch
    duplicate f

/// A shadow write ran only inside the attempt the account was actually
/// running: the same served epoch, starter and rotation id.
let shadow_write_runs_only_inside_the_attempt
      (g: answers) (d: db) (id user: text) (lamport: i64) (writer ciphertext now: text)
      (epoch read_epoch: i64) (starter rotation: text) (f: option nat)
  : Lemma
    (fst (chunk_shadow g d id user lamport writer ciphertext now epoch read_epoch
            starter rotation f) == UD.WriteObservation_Inserted ==>
     freezing_attempt d user read_epoch starter rotation) =
  chunk_shadow_is_honest g d id user lamport writer ciphertext now epoch read_epoch
    starter rotation f

/// A chunk delete ran only for an account ACTIVE at the row's epoch, so a
/// frozen account cannot delete its authoritative rows.
let chunk_delete_needs_active_account
      (g: answers) (d: db) (id user: text) (epoch: i64) (f: option nat)
  : Lemma
    (fst (delete_chunk g d id user epoch f) == MD.DeleteObservation_Deleted ==>
     active_at d user epoch) =
  delete_chunk_is_honest g d id user epoch f

/// A cleared acknowledgement means the device row held exactly the epoch the
/// caller sent: a crossed or replayed ACK never clears another epoch.
let ack_clears_only_its_epoch
      (g: answers) (d: db) (device user: text) (epoch: i64) (f: option nat)
  : Lemma
    (fst (ack_capsule g d device user epoch f) == MD.AckObservation_Cleared ==>
     (match d.devices device with
      | Some r -> r.dv_user = user && r.dv_revoked = mk_i64 0 &&
                  r.dv_capsule_epoch = Some epoch
      | None -> False)) =
  ack_capsule_is_honest g d device user epoch f

/// A committed rotation published a shadow for every one of the account's old
/// chunks, so no chunk is lost at the epoch flip.
let commit_publishes_complete_chunks
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat)
  : Lemma
    ((g.a_shadows_ready <==> ~(any_missing_shadow d user from_epoch to_epoch)) ==>
     (commit_cas_obs g d user from_epoch to_epoch starter rotation f ==
        RD.CasObservation_Updated ==>
      (forall (id: text).
         Some? (d.chunks (mk_ckey user id from_epoch)) ==>
         Some? (d.chunks (mk_ckey user id to_epoch))))) =
  commit_cas_is_honest g d user from_epoch to_epoch starter rotation f

/// A committed rotation published a capsule at the new epoch for every active
/// device, and every active device is capable.
let commit_publishes_complete_devices
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64)
      (starter rotation: text) (f: option nat)
  : Lemma
    ((g.a_capsules_complete <==> ~(any_incomplete_device d user to_epoch)) ==>
     (commit_cas_obs g d user from_epoch to_epoch starter rotation f ==
        RD.CasObservation_Updated ==>
      (forall (id: text).
         (match d.devices id with
          | Some r -> r.dv_user = user /\ r.dv_revoked = mk_i64 0
          | None -> False) ==>
         (match d.devices id with
          | Some r -> r.dv_capable <> mk_i64 0 /\ r.dv_capsule_epoch = Some to_epoch
          | None -> False)))) =
  commit_cas_is_honest g d user from_epoch to_epoch starter rotation f

/// A won rollback discarded this attempt's shadow chunks and capsules, so a
/// later attempt cannot inherit them.
let rollback_discards_attempt_output
      (g: answers) (d: db) (user: text) (epoch target_epoch: i64) (rotation: text)
      (f: option nat)
  : Lemma
    (rollback_obs g d user epoch target_epoch rotation f ==
       RD.RollbackObservation_RolledBack ==>
     (forall (k: ckey).
        k.ck_user = user && k.ck_epoch >. epoch ==>
        (rollback_post g d user epoch target_epoch rotation f).chunks k == None) /\
     (forall (id: text).
        capsule_for_attempt d id user target_epoch ==>
        (match (rollback_post g d user epoch target_epoch rotation f).devices id with
         | Some r -> r.dv_capsule == None /\ r.dv_capsule_epoch == None
         | None -> False))) =
  rollback_publishes_is_honest g d user epoch target_epoch rotation f

/// A won freeze froze only a clean account: no ORAM buckets, every active
/// device capable, and no capsule awaiting acknowledgement.
let freeze_requires_a_clean_account
      (g: answers) (d: db) (user: text) (from_epoch: i64)
      (now starter rotation: text) (f: option nat)
  : Lemma
    ((g.a_oram_empty <==> ~(any_oram d user)) ==>
     (g.a_devices_ready <==> ~(any_incapable d user)) ==>
     (g.a_capsules_free <==> ~(any_pending_capsule d user)) ==>
     (freeze_cas_obs g d user from_epoch now starter rotation f ==
        RD.CasObservation_Updated ==>
      (~(any_oram d user) /\ ~(any_incapable d user) /\
       ~(any_pending_capsule d user)))) =
  freeze_guard_is_honest g d user from_epoch;
  freeze_cas_is_honest g d user from_epoch now starter rotation f

#pop-options
