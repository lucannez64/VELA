module Vela_enrollment_policy_executor_lemmas

/// F-1 for the device-enrollment executors: for every starting database and
/// store, and every fault point, each executor's observation (the extracted
/// `classify_*` applied to what the extracted `plan_*` did in
/// `Vela_enrollment_policy_executor_model`) is the truth about the tables and
/// keys.

open FStar.Mul
open Core_models
open Vela_enrollment_policy.Executor
open Vela_enrollment_policy_executor_model

module L = FStar.List.Tot
module SP = FStar.Seq.Properties
module D = Vela_enrollment_policy.Pairing_driver
module ED = Vela_enrollment_policy.Enroll_driver

/// The slice a classifier reads is the outcome list, element by element.
/// Nothing about the classifiers is restated here, so a changed classifier
/// fails the honesty theorems themselves.
let seq_of_list_facts (#a: Type) (l: list a)
  : Lemma (forall (i: nat). i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
  let aux (i: nat) : Lemma (i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
    if i < L.length l then SP.lemma_seq_of_list_index l i
  in
  FStar.Classical.forall_intro aux

#push-options "--fuel 4 --ifuel 2"

// ── Invitation packages and the grant record ───────────────────────────────

/// `StorePackageIo::store_package`: stored exactly when the write ran, and
/// then exactly the package key holds the ciphertext.
let store_package_is_honest (d: db) (token ciphertext: text) (f: option nat)
  : Lemma
    (let (obs, post) = store_package d token ciphertext f in
     (obs == D.StoreObservation_Stored <==> not (faulted f 0)) /\
     (obs == D.StoreObservation_Stored ==>
        post == { d with packages = upd d.packages token (Some ciphertext) }) /\
     (obs =!= D.StoreObservation_Stored ==> post == d)) =
  let r = run_writes d (stmts_of (plan_store_package token ciphertext)) 0 f in
  seq_of_list_facts (fst r)

/// `RedeemPackageIo::redeem_package`: present exactly when the package was
/// stored and no statement failed, and then the key is consumed; a miss or a
/// failure changes nothing.
let redeem_package_is_honest (d: db) (token: text) (utf8_valid: bool) (f: option nat)
  : Lemma
    (let (obs, post) = redeem_package d token utf8_valid f in
     (obs == D.RedeemObservation_Missing <==>
        (faulted f 0 \/ None? (d.packages token))) /\
     (obs =!= D.RedeemObservation_Missing <==>
        (not (faulted f 0) /\ Some? (d.packages token))) /\
     (not (faulted f 0) /\ Some? (d.packages token) ==>
        post == { d with packages = upd d.packages token None }) /\
     (faulted f 0 \/ None? (d.packages token) ==> post == d) /\
     (match obs with
      | D.RedeemObservation_Present r -> r.f_utf8_valid == utf8_valid
      | D.RedeemObservation_Missing -> True)) =
  let r = run_take d (stmts_of (plan_redeem_package token)) 0 f in
  ()

/// `OpenGrantIo::store_grant`: stored exactly when the write ran, and then the
/// grant key holds exactly the user and opener the session named.
let store_grant_is_honest (d: db) (grant_id user_id device_id: text) (f: option nat)
  : Lemma
    (let (obs, post) = store_grant d grant_id user_id device_id f in
     (obs == D.StoreObservation_Stored <==> not (faulted f 0)) /\
     (obs == D.StoreObservation_Stored ==>
        post == { d with grants = upd d.grants grant_id
                            (Some ({ g_user = user_id; g_device = device_id } <: grant_row)) }) /\
     (obs =!= D.StoreObservation_Stored ==> post == d)) =
  let r = run_writes d (stmts_of (plan_store_grant grant_id user_id device_id)) 0 f in
  seq_of_list_facts (fst r)

// ── Claim ──────────────────────────────────────────────────────────────────

/// `ClaimIo::check_claim`: the existence bit is the stored truth (a failed
/// read rejects with zero lengths), and reads change nothing.
let claim_check_is_honest
      (d: db) (grant_id: text) (grant_live: bool) (ek_len vk_len: usize) (f: option nat)
  : Lemma
    (let (obs, post) = claim_check d grant_id grant_live ek_len vk_len f in
     post == d /\
     obs.Vela_enrollment_policy.f_grant_live == grant_live /\
     (not (faulted f 0) ==>
        (obs.Vela_enrollment_policy.f_claim_exists == Some? (d.claims grant_id) /\
         obs.Vela_enrollment_policy.f_hybrid_ek_len == ek_len /\
         obs.Vela_enrollment_policy.f_hybrid_vk_len == vk_len)) /\
     (faulted f 0 ==>
        (obs.Vela_enrollment_policy.f_claim_exists == false /\
         obs.Vela_enrollment_policy.f_hybrid_ek_len == mk_usize 0 /\
         obs.Vela_enrollment_policy.f_hybrid_vk_len == mk_usize 0))) =
  let r = run_reads d (stmts_of (plan_claim_check grant_id)) 0 f in
  seq_of_list_facts r

/// `ClaimIo::write_claim`: first-writer-wins while the grant key is live.
/// `Inserted` is exactly a live grant with no claim yet; `KeyExists` a live
/// grant that already has one; `GuardMissing` a missing grant or a failure.
/// Only `Inserted` changes the store, and it writes exactly the claim.
let claim_write_is_honest
      (d: db) (grant_id ek vk: text)
      (name ty: Core_models.Option.t_Option text) (f: option nat)
  : Lemma
    (let (obs, post) = claim_write d grant_id ek vk name ty f in
     (obs == D.ClaimWriteObservation_Inserted <==>
        (not (faulted f 0) /\ Some? (d.grants grant_id) /\ None? (d.claims grant_id))) /\
     (obs == D.ClaimWriteObservation_KeyExists <==>
        (not (faulted f 0) /\ Some? (d.grants grant_id) /\ Some? (d.claims grant_id))) /\
     (obs == D.ClaimWriteObservation_GuardMissing <==>
        (faulted f 0 \/ None? (d.grants grant_id))) /\
     (obs == D.ClaimWriteObservation_Inserted ==>
        post == { d with claims = upd d.claims grant_id
                            (Some ({ c_ek = ek; c_vk = vk;
                                     c_name = of_core name;
                                     c_type_ = of_core ty } <: claim_row)) }) /\
     (obs =!= D.ClaimWriteObservation_Inserted ==> post == d)) =
  let r = run_writes d (stmts_of (plan_claim_write grant_id ek vk name ty)) 0 f in
  seq_of_list_facts (fst r)

/// A winning claim is never replaced: a second claim write for the same grant
/// can only see the stored key or a missing grant.
let claim_is_first_writer_wins
      (d: db) (grant_id ek vk: text)
      (name ty: Core_models.Option.t_Option text) (f: option nat)
      (ek' vk': text) (name' ty': Core_models.Option.t_Option text) (f': option nat)
  : Lemma
    (let (obs, post) = claim_write d grant_id ek vk name ty f in
     obs == D.ClaimWriteObservation_Inserted ==>
       fst (claim_write post grant_id ek' vk' name' ty' f')
       =!= D.ClaimWriteObservation_Inserted) =
  claim_write_is_honest d grant_id ek vk name ty f;
  let (_, post) = claim_write d grant_id ek vk name ty f in
  claim_write_is_honest post grant_id ek' vk' name' ty' f'

// ── Completion: account, preflight, ceremony ───────────────────────────────

/// `CompleteIo::check_account`: the query outcome and the row-derived epoch
/// and rotation facts are the stored row's truth, and the read changes
/// nothing.
let account_read_is_honest
      (d: db) (user_id: text) (declared_positive rekey_permitted: bool) (f: option nat)
  : Lemma
    (let (obs, fields, post) = account_read d user_id declared_positive rekey_permitted f in
     post == d /\
     (obs.D.f_account_query_ok <==> not (faulted f 0)) /\
     obs.D.f_declared_epoch_positive == declared_positive /\
     obs.D.f_rekey_permitted == rekey_permitted /\
     (not (faulted f 0) ==>
        (fst fields == (match d.users user_id with
                        | Some u -> u.u_epoch
                        | None -> mk_i64 0) /\
         snd fields == (match d.users user_id with
                        | Some u -> Some? u.u_rekey
                        | None -> false)))) =
  let r = run_reads d (stmts_of (plan_account_read user_id)) 0 f in
  seq_of_list_facts r

/// The opener row the completion accepts: owned by the grant's user and not
/// revoked.
let live_opener (d: db) (device_id user_id: text) : bool =
  match opener_row d device_id user_id with
  | Some row -> row.d_revoked = mk_i64 0
  | None -> false

/// `CompleteIo::prepare_completion`: the claim material and the opener row are
/// the stored truth; a failed claim read gives the historical rejecting
/// observation and stops before the opener read; the crypto, capsule and
/// freshness fields are the caller's verdicts.
let completion_preflight_is_honest
      (d: db) (grant_id device_id user_id: text)
      (v: t_CompletionVerdicts) (f: option nat)
  : Lemma
    (let (obs, post) =
       completion_preflight d grant_id device_id user_id v f in
     post == d /\
     (faulted f 0 ==>
        (obs.D.f_claim == D.ClaimMaterialObservation_Error /\
         obs.D.f_opener == D.OpenerObservation_Inactive /\
         obs.D.f_capsule_valid == false /\
         obs.D.f_signature_field_valid == false /\
         obs.D.f_signature == D.SignatureObservation_Failed)) /\
     (not (faulted f 0) ==>
        ((obs.D.f_claim == D.ClaimMaterialObservation_Usable) <==>
           (Some? (d.claims grant_id) && v.f_claim_keys_usable)) /\
        ((obs.D.f_claim == D.ClaimMaterialObservation_Missing) <==>
           None? (d.claims grant_id)) /\
        ((obs.D.f_opener == D.OpenerObservation_Error) <==>
           (faulted f 1 \/
            (live_opener d device_id user_id && not v.f_opener_key_decodes))) /\
        (not (faulted f 1) ==>
           ((obs.D.f_opener == D.OpenerObservation_Active) <==>
              (live_opener d device_id user_id && v.f_opener_key_decodes)) /\
           ((obs.D.f_opener == D.OpenerObservation_Inactive) <==>
              not (live_opener d device_id user_id))) /\
        obs.D.f_capsule_valid == v.f_capsule_valid /\
        obs.D.f_signature_field_valid == v.f_signature_field_valid /\
        ((obs.D.f_signature == D.SignatureObservation_Verified) <==>
           v.f_signature_verified) /\
        obs.D.f_account_epoch == v.f_account_epoch /\
        obs.D.f_declared_epoch == v.f_declared_epoch /\
        obs.D.f_rotation_in_progress == v.f_rotation_in_progress /\
        obs.D.f_account_epoch_active == v.f_account_epoch_active)) =
  let r = run_reads d (stmts_of (plan_completion_preflight grant_id device_id user_id)) 0 f in
  seq_of_list_facts r

/// `CompleteIo::take_ceremony`: the single-use take succeeds exactly when both
/// records were live, and then both are consumed; a miss or a failure changes
/// nothing.
let take_ceremony_is_honest
      (d: db) (grant_id: text) (grant_matches claim_matches: bool) (f: option nat)
  : Lemma
    (let (obs, post) = take_ceremony d grant_id grant_matches claim_matches f in
     (obs == D.TakeObservation_Missing <==>
        (faulted f 0 \/ None? (d.grants grant_id) \/ None? (d.claims grant_id))) /\
     (obs =!= D.TakeObservation_Missing <==>
        (not (faulted f 0) /\ Some? (d.grants grant_id) /\ Some? (d.claims grant_id))) /\
     (post == d \/ post == { d with grants = upd d.grants grant_id None;
                                    claims = upd d.claims grant_id None }) /\
     (not (faulted f 0) /\ Some? (d.grants grant_id) /\ Some? (d.claims grant_id) ==>
        post == { d with grants = upd d.grants grant_id None;
                         claims = upd d.claims grant_id None }) /\
     (faulted f 0 \/ None? (d.grants grant_id) \/ None? (d.claims grant_id) ==>
        post == d) /\
     (match obs with
      | D.TakeObservation_Taken t ->
        t.f_grant_matches == grant_matches /\ t.f_claim_matches == claim_matches
      | D.TakeObservation_Missing -> True)) =
  let r = run_take_pair d (stmts_of (plan_take_ceremony grant_id)) 0 f in
  ()

/// The ceremony take is single-use: after a take that matched both records, a
/// second take (any fault point) finds nothing and changes nothing.
let ceremony_take_is_single_use
      (d: db) (grant_id: text) (f: option nat)
      (grant_matches' claim_matches': bool) (f': option nat)
  : Lemma
    (let (obs, post) = take_ceremony d grant_id true true f in
     obs =!= D.TakeObservation_Missing ==>
       (fst (take_ceremony post grant_id grant_matches' claim_matches' f')
        == D.TakeObservation_Missing)) =
  take_ceremony_is_honest d grant_id true true f;
  let (_, post) = take_ceremony d grant_id true true f in
  take_ceremony_is_honest post grant_id grant_matches' claim_matches' f'

// ── Completion and enrollment inserts ──────────────────────────────────────

/// `CompleteIo::insert_device`: the guarded insert adds exactly the stored
/// claim's device row when the account epoch guard holds; a stale epoch
/// reports `Skipped` and changes nothing; a taken id or a failure reports
/// `Failed`.
let completion_insert_is_honest
      (d: db)
      (new_device_id user_id device_name device_type hybrid_ek hybrid_vk
       enrolled_by grant_id rms_capsule now guard_user: text)
      (guard_epoch: i64) (f: option nat)
  : Lemma
    (let (obs, post) =
       completion_insert d new_device_id user_id device_name device_type hybrid_ek
         hybrid_vk enrolled_by grant_id rms_capsule now guard_user guard_epoch f in
     (obs == D.DeviceInsertObservation_Inserted <==>
        (not (faulted f 0) /\ epoch_guard d guard_user guard_epoch /\
         None? (d.devices new_device_id) /\ None? (d.grant_index grant_id))) /\
     (obs == D.DeviceInsertObservation_Skipped <==>
        (not (faulted f 0) /\ not (epoch_guard d guard_user guard_epoch))) /\
     (obs == D.DeviceInsertObservation_Failed <==>
        (faulted f 0 \/
         (epoch_guard d guard_user guard_epoch /\
          (Some? (d.devices new_device_id) \/ Some? (d.grant_index grant_id))))) /\
     (obs == D.DeviceInsertObservation_Inserted ==>
        post == { d with
                  devices = upd d.devices new_device_id
                    (Some (written_device new_device_id user_id device_name device_type
                             hybrid_ek hybrid_vk enrolled_by rms_capsule now
                             (Some grant_id) (mk_i64 0)));
                  grant_index = upd d.grant_index grant_id (Some new_device_id) }) /\
     (obs =!= D.DeviceInsertObservation_Inserted ==> post == d)) =
  let r =
    run_writes d
      (stmts_of (plan_completion_insert new_device_id user_id device_name device_type
                   hybrid_ek hybrid_vk enrolled_by grant_id rms_capsule now guard_user
                   guard_epoch)) 0 f in
  seq_of_list_facts (fst r)

/// `EnrollIo::insert_device`: the same guarded insert for the enrollment path.
let enroll_insert_is_honest
      (d: db)
      (new_device_id user_id device_name device_type hybrid_ek hybrid_vk
       enrolled_by rms_capsule now guard_user: text)
      (guard_epoch: i64) (f: option nat)
  : Lemma
    (let (obs, post) =
       enroll_insert d new_device_id user_id device_name device_type hybrid_ek
         hybrid_vk enrolled_by rms_capsule now guard_user guard_epoch f in
     (obs == ED.InsertObservation_Inserted <==>
        (not (faulted f 0) /\ epoch_guard d guard_user guard_epoch /\
         None? (d.devices new_device_id))) /\
     (obs == ED.InsertObservation_EpochMismatch <==>
        (not (faulted f 0) /\ not (epoch_guard d guard_user guard_epoch))) /\
     (obs == ED.InsertObservation_Failed <==>
        (faulted f 0 \/
         (epoch_guard d guard_user guard_epoch /\ Some? (d.devices new_device_id)))) /\
     (obs == ED.InsertObservation_Inserted ==>
        post == { d with
                  devices = upd d.devices new_device_id
                    (Some (written_device new_device_id user_id device_name device_type
                             hybrid_ek hybrid_vk enrolled_by rms_capsule now
                             None (mk_i64 0))) }) /\
     (obs =!= ED.InsertObservation_Inserted ==> post == d)) =
  let r =
    run_writes d
      (stmts_of (plan_enroll_insert new_device_id user_id device_name device_type
                   hybrid_ek hybrid_vk enrolled_by rms_capsule now guard_user
                   guard_epoch)) 0 f in
  seq_of_list_facts (fst r)

/// `CompleteIo::write_result`: stored exactly when the result write ran, and
/// then exactly the result key holds the inserted device and its claimed key.
let result_write_is_honest (d: db) (grant_id device_id hybrid_vk: text) (f: option nat)
  : Lemma
    (let (obs, post) = result_write d grant_id device_id hybrid_vk f in
     (obs == D.StoreObservation_Stored <==> not (faulted f 0)) /\
     (obs == D.StoreObservation_Stored ==>
        post == { d with results = upd d.results grant_id
                            (Some ({ r_device = device_id; r_vk = hybrid_vk } <: result_row)) }) /\
     (obs =!= D.StoreObservation_Stored ==> post == d)) =
  let r = run_writes d (stmts_of (plan_result_write grant_id device_id hybrid_vk)) 0 f in
  seq_of_list_facts (fst r)

// ── Result collection ──────────────────────────────────────────────────────

/// `ResultIo::read_result`: a completed answer is a stored result whose key
/// decoded; an absent answer is an absent key; a failure or an undecodable key
/// is the retained error. Reads change nothing.
let result_read_is_honest
      (d: db) (grant_id: text) (v: t_CollectorVerdicts) (f: option nat)
  : Lemma
    (let (obs, post) = result_read d grant_id v f in
     post == d /\
     (obs == D.ResultReadObservation_Absent <==>
        (not (faulted f 0) /\ None? (d.results grant_id))) /\
     ((obs == D.ResultReadObservation_Unreadable) <==>
        (faulted f 0 \/ (Some? (d.results grant_id) && not v.f_key_decodes))) /\
     (match obs with
      | D.ResultReadObservation_Completed r ->
        Some? (d.results grant_id) /\ v.f_key_decodes /\
        r.f_claimed_key_len == v.f_key_len /\
        r.f_signature_verified == v.f_signature_verified
      | _ -> True)) =
  let r = run_reads d (stmts_of (plan_result_read grant_id)) 0 f in
  seq_of_list_facts r

/// `ResultIo::read_claim`: the same honesty for the pending-claim answer.
let claim_read_is_honest
      (d: db) (grant_id: text) (v: t_CollectorVerdicts) (f: option nat)
  : Lemma
    (let (obs, post) = claim_read d grant_id v f in
     post == d /\
     (obs == D.ClaimReadObservation_Absent <==>
        (not (faulted f 0) /\ None? (d.claims grant_id))) /\
     ((obs == D.ClaimReadObservation_Unreadable) <==>
        (faulted f 0 \/ (Some? (d.claims grant_id) && not v.f_key_decodes))) /\
     (match obs with
      | D.ClaimReadObservation_Claimed r ->
        Some? (d.claims grant_id) /\ v.f_key_decodes /\
        r.f_claimed_key_len == v.f_key_len /\
        r.f_signature_verified == v.f_signature_verified
      | _ -> True)) =
  let r = run_reads d (stmts_of (plan_claim_read grant_id)) 0 f in
  seq_of_list_facts r

/// The U-20 fallback lookup: the device row the completion insert recorded for
/// this grant.
let grant_device (d: db) (grant_id: text) : option device_row =
  match d.grant_index grant_id with
  | Some id -> d.devices id
  | None -> None

/// `ResultIo::read_enrolled_device`: an enrolled answer is a device row that
/// carries this grant id and whose key decoded; absent is no such row.
let enrolled_device_is_honest
      (d: db) (grant_id: text) (v: t_CollectorVerdicts) (f: option nat)
  : Lemma
    (let (obs, post) = enrolled_device d grant_id v f in
     post == d /\
     (obs == D.DeviceGrantObservation_Absent <==>
        (not (faulted f 0) /\ None? (grant_device d grant_id))) /\
     ((obs == D.DeviceGrantObservation_Unreadable) <==>
        (faulted f 0 \/ (Some? (grant_device d grant_id) && not v.f_key_decodes))) /\
     (match obs with
      | D.DeviceGrantObservation_Enrolled r ->
        Some? (grant_device d grant_id) /\ v.f_key_decodes /\
        r.f_claimed_key_len == v.f_key_len /\
        r.f_signature_verified == v.f_signature_verified
      | _ -> True)) =
  let r = run_reads d (stmts_of (plan_device_by_grant grant_id)) 0 f in
  seq_of_list_facts r

// ── Enrollment device read and challenge ───────────────────────────────────

/// `EnrollIo::check_device`: an active device row is required for every
/// signature verdict; a miss is `Unavailable`; a failed or undecodable read is
/// `Error`. Reads change nothing.
let active_device_is_honest
      (d: db) (device_id: text) (verdict: t_EnrollAuthVerdict) (f: option nat)
  : Lemma
    (let (obs, post) = active_device d device_id verdict f in
     post == d /\
     (obs == ED.DeviceObservation_Unavailable <==>
        (not (faulted f 0) /\ None? (active_row d device_id))) /\
     (obs == ED.DeviceObservation_Error <==> faulted f 0) /\
     ((obs == ED.DeviceObservation_Verified \/
       obs == ED.DeviceObservation_MalformedChallenge \/
       obs == ED.DeviceObservation_AuthSignatureRejected) ==>
        (not (faulted f 0) /\ Some? (active_row d device_id))) /\
     (obs == ED.DeviceObservation_Verified ==>
        (Some? (active_row d device_id) /\
         (match d.devices device_id with
          | Some row -> row.d_revoked = mk_i64 0
          | None -> False)))) =
  let r = run_reads d (stmts_of (plan_active_device_read device_id)) 0 f in
  seq_of_list_facts r

/// `EnrollIo::consume_challenge`: consumed exactly when the nonce was stored,
/// its purpose matched and no statement failed. The take removes the nonce
/// whatever its purpose, so a wrong-purpose nonce is spent but not accepted.
let challenge_take_is_honest
      (d: db) (challenge: text) (purpose_matches: bool) (f: option nat)
  : Lemma
    (let (consumed, post) = challenge_take d challenge purpose_matches f in
     (consumed <==>
        (not (faulted f 0) /\ Some? (d.challenges challenge) /\ purpose_matches)) /\
     (not (faulted f 0) /\ Some? (d.challenges challenge) ==>
        post == { d with challenges = upd d.challenges challenge None }) /\
     (faulted f 0 \/ None? (d.challenges challenge) ==> post == d)) =
  let r = run_take d (stmts_of (plan_challenge_take challenge)) 0 f in
  ()

// ── Facts the enrollment drivers rely on ───────────────────────────────────

/// A claim is only ever inserted while its grant is live.
let claim_only_while_grant_live
      (d: db) (grant_id ek vk: text)
      (name ty: Core_models.Option.t_Option text) (f: option nat)
  : Lemma
    (fst (claim_write d grant_id ek vk name ty f) == D.ClaimWriteObservation_Inserted ==>
       Some? (d.grants grant_id)) =
  claim_write_is_honest d grant_id ek vk name ty f

/// A completion insert happens only from a live, non-rotating account epoch.
let completion_insert_only_from_live_epoch
      (d: db)
      (new_device_id user_id device_name device_type hybrid_ek hybrid_vk
       enrolled_by grant_id rms_capsule now guard_user: text)
      (guard_epoch: i64) (f: option nat)
  : Lemma
    (fst (completion_insert d new_device_id user_id device_name device_type hybrid_ek
            hybrid_vk enrolled_by grant_id rms_capsule now guard_user guard_epoch f)
       == D.DeviceInsertObservation_Inserted ==>
       (match d.users guard_user with
        | Some u -> u.u_epoch == guard_epoch /\ None? u.u_rekey
        | None -> False)) =
  completion_insert_is_honest d new_device_id user_id device_name device_type hybrid_ek
    hybrid_vk enrolled_by grant_id rms_capsule now guard_user guard_epoch f

/// An enrollment insert happens only from a live, non-rotating account epoch.
let enroll_insert_only_from_live_epoch
      (d: db)
      (new_device_id user_id device_name device_type hybrid_ek hybrid_vk
       enrolled_by rms_capsule now guard_user: text)
      (guard_epoch: i64) (f: option nat)
  : Lemma
    (fst (enroll_insert d new_device_id user_id device_name device_type hybrid_ek
            hybrid_vk enrolled_by rms_capsule now guard_user guard_epoch f)
       == ED.InsertObservation_Inserted ==>
       (match d.users guard_user with
        | Some u -> u.u_epoch == guard_epoch /\ None? u.u_rekey
        | None -> False)) =
  enroll_insert_is_honest d new_device_id user_id device_name device_type hybrid_ek
    hybrid_vk enrolled_by rms_capsule now guard_user guard_epoch f

/// The preflight observation's claim verdict.
let preflight_claim
      (d: db) (grant_id device_id user_id: text)
      (v: t_CompletionVerdicts) (f: option nat)
  : D.t_ClaimMaterialObservation =
  let (obs, _) = completion_preflight d grant_id device_id user_id v f in
  obs.D.f_claim

/// The preflight observation's opener verdict.
let preflight_opener
      (d: db) (grant_id device_id user_id: text)
      (v: t_CompletionVerdicts) (f: option nat)
  : D.t_OpenerObservation =
  let (obs, _) = completion_preflight d grant_id device_id user_id v f in
  obs.D.f_opener

/// `Complete` is authorized only for the claim record the store holds: the
/// keys the completion enrolls are the ones the user compared.
let completion_preflight_admits_only_stored_claim
      (d: db) (grant_id device_id user_id: text)
      (v: t_CompletionVerdicts) (f: option nat)
  : Lemma
    (preflight_claim d grant_id device_id user_id v f
       == D.ClaimMaterialObservation_Usable ==>
       Some? (d.claims grant_id)) =
  completion_preflight_is_honest d grant_id device_id user_id v f

/// `Complete` is authorized only for an unrevoked device of the grant's user.
let completion_preflight_admits_only_active_opener
      (d: db) (grant_id device_id user_id: text)
      (v: t_CompletionVerdicts) (f: option nat)
  : Lemma
    (preflight_opener d grant_id device_id user_id v f == D.OpenerObservation_Active ==>
       (live_opener d device_id user_id /\
        (match d.devices device_id with
         | Some row -> row.d_user == user_id /\ row.d_revoked = mk_i64 0
         | None -> False))) =
  completion_preflight_is_honest d grant_id device_id user_id v f

/// The account fields the completion compares against the request epoch are
/// the stored account row's.
let account_read_reports_the_stored_row
      (d: db) (user_id: text) (declared_positive rekey_permitted: bool) (f: option nat)
  : Lemma
    (not (faulted f 0) ==>
       (let (_, fields, _) =
          account_read d user_id declared_positive rekey_permitted f in
        fst fields == (match d.users user_id with
                       | Some u -> u.u_epoch
                       | None -> mk_i64 0) /\
        snd fields == (match d.users user_id with
                       | Some u -> Some? u.u_rekey
                       | None -> false))) =
  account_read_is_honest d user_id declared_positive rekey_permitted f

/// A completed answer comes only from a stored result record.
let result_read_only_from_stored_record
      (d: db) (grant_id: text) (v: t_CollectorVerdicts) (f: option nat)
  : Lemma
    (match fst (result_read d grant_id v f) with
     | D.ResultReadObservation_Completed _ -> Some? (d.results grant_id)
     | _ -> True) =
  result_read_is_honest d grant_id v f

/// A verified enrollment device read is an unrevoked, stored row.
let device_check_only_from_active_row
      (d: db) (device_id: text) (verdict: t_EnrollAuthVerdict) (f: option nat)
  : Lemma
    (fst (active_device d device_id verdict f) == ED.DeviceObservation_Verified ==>
       (Some? (active_row d device_id) /\
        (match d.devices device_id with
         | Some row -> row.d_revoked = mk_i64 0
         | None -> False))) =
  active_device_is_honest d device_id verdict f

// ── Pre-driver reads, the ceremony restore and the rate limiter ────────────

/// `post_claim`'s pre-driver liveness check: `grant_live` is exactly the grant
/// key's presence, and the read changes nothing.
let grant_exists_is_honest (d: db) (grant_id: text) (f: option nat)
  : Lemma
    (let (live, post) = grant_exists d grant_id f in
     post == d /\
     (faulted f 0 ==> live == false) /\
     (not (faulted f 0) ==> (live <==> Some? (d.grants grant_id)))) =
  let r = run_reads d (stmts_of (plan_grant_exists grant_id)) 0 f in
  seq_of_list_facts r

/// The non-consuming grant read behind `post_complete` and `get_claim`: an
/// absent key is `Absent`, a stored record is `Present` with exactly its two
/// bindings compared with the caller, and a failure or an undecodable record
/// is `Error`. The read changes nothing.
let grant_read_is_honest
      (d: db) (grant_id user device: text) (f: option nat)
  : Lemma
    (let (obs, post) = grant_read d grant_id user device f in
     post == d /\
     (faulted f 0 ==> obs == D.GrantObservation_Error) /\
     (not (faulted f 0) ==>
        ((obs == D.GrantObservation_Absent) <==> None? (d.grants grant_id)) /\
        (match d.grants grant_id with
         | None -> obs == D.GrantObservation_Absent
         | Some row ->
           (match obs with
            | D.GrantObservation_Present p ->
              p.f_user_matches == (row.g_user = user) /\
              p.f_opener_matches == (row.g_device = device)
            | _ -> False)))) =
  let r = run_reads d (stmts_of (plan_grant_read grant_id)) 0 f in
  seq_of_list_facts r

/// `get_claim`'s payload read: the claim is reported present exactly when the
/// key held a decodable record, and then the view is the stored record's own
/// cells. The read changes nothing.
let claim_inspection_is_honest (d: db) (grant_id: text) (f: option nat)
  : Lemma
    (let (obs, post) = claim_inspection d grant_id f in
     post == d /\
     (faulted f 0 ==>
        (obs.f_claim_present == false /\
         (match obs.f_claim with
          | Core_models.Option.Option_None -> True
          | Core_models.Option.Option_Some _ -> False))) /\
     (not (faulted f 0) ==>
        ((obs.f_claim_present <==> Some? (d.claims grant_id)) /\
         (match d.claims grant_id with
          | None -> obs.f_claim_present == false
          | Some row ->
            (match obs.f_claim with
             | Core_models.Option.Option_Some view ->
               view.f_hybrid_ek == Core_models.Option.Option_Some row.c_ek /\
               view.f_hybrid_vk == Core_models.Option.Option_Some row.c_vk /\
               view.f_device_name == to_core row.c_name /\
               view.f_device_type == to_core row.c_type_
             | Core_models.Option.Option_None -> False))))) =
  let r = run_reads d (stmts_of (plan_claim_read grant_id)) 0 f in
  seq_of_list_facts r

/// The completion's ceremony restore: `Stored` exactly when the atomic pair
/// write ran, and then both keys hold exactly the plan's records; a failure
/// changes nothing.
let ceremony_restore_is_honest
      (d: db) (grant_id: text)
      (grant_bytes claim_bytes: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (g: t_GrantRecordView) (c: t_ClaimRecordView) (f: option nat)
  : Lemma
    (let (obs, post) = ceremony_restore d grant_id grant_bytes claim_bytes g c f in
     (obs == D.StoreObservation_Stored <==> not (faulted f 0)) /\
     (obs == D.StoreObservation_Stored ==>
        post == { d with
                  grants = upd d.grants grant_id
                    (Some ({ g_user = g.f_user_id; g_device = g.f_device_id }
                           <: grant_row));
                  claims = upd d.claims grant_id
                    (Some ({ c_ek = c.f_hybrid_ek; c_vk = c.f_hybrid_vk;
                             c_name = of_core c.f_device_name;
                             c_type_ = of_core c.f_device_type } <: claim_row)) }) /\
     (obs =!= D.StoreObservation_Stored ==> post == d)) =
  let r =
    run_writes d
      (stmts_of (plan_ceremony_restore grant_id grant_bytes claim_bytes g c)) 0 f in
  seq_of_list_facts (fst r)

/// The fixed-window limiter: the counter grows by exactly one at the plan's
/// key (saturating), a failure leaves it unchanged, and the verdict is exactly
/// the new count against the endpoint's limit.
let rate_limit_is_honest
      (d: db) (key: text) (window_secs limit: u64) (f: option nat)
  : Lemma
    (let (obs, post) = rate_limit d key window_secs limit f in
     (obs == RateObservation_StorageFailed <==> faulted f 0) /\
     (obs == RateObservation_Admitted <==>
        (not (faulted f 0) /\ under_limit (bump (counter d key)) limit)) /\
     (obs == RateObservation_Limited <==>
        (not (faulted f 0) /\ not (under_limit (bump (counter d key)) limit))) /\
     (not (faulted f 0) ==>
        post == { d with
                  counters = upd d.counters key (Some (bump (counter d key))) }) /\
     (faulted f 0 ==> post == d)) =
  let r = run_rate d (stmts_of (plan_rate_limit key window_secs)) 0 f in
  seq_of_list_facts [fst r]

// ── Facts the pre-driver decisions rely on ─────────────────────────────────

/// The claim driver's liveness bit is the stored grant's presence.
let grant_live_is_the_stored_grant (d: db) (grant_id: text) (f: option nat)
  : Lemma
    (not (faulted f 0) ==>
       (fst (grant_exists d grant_id f) <==> Some? (d.grants grant_id))) =
  grant_exists_is_honest d grant_id f

/// A completion or inspection that saw both bindings match read the stored
/// grant, and it binds exactly that user and opener.
let grant_read_admits_only_the_stored_opener
      (d: db) (grant_id user device: text) (f: option nat)
  : Lemma
    ((match fst (grant_read d grant_id user device f) with
      | D.GrantObservation_Present p ->
        p.f_user_matches = true /\ p.f_opener_matches = true
      | _ -> False) ==>
     (match d.grants grant_id with
      | Some row -> row.g_user = user /\ row.g_device = device
      | None -> False)) =
  grant_read_is_honest d grant_id user device f

/// `get_claim` can only answer with a claim the store holds.
let claim_inspection_admits_only_the_stored_claim
      (d: db) (grant_id: text) (f: option nat)
  : Lemma
    (not (faulted f 0) ==>
       ((fst (claim_inspection d grant_id f)).f_claim_present <==>
        Some? (d.claims grant_id))) =
  claim_inspection_is_honest d grant_id f

/// An admitted request grew the counter by exactly one.
let rate_limit_only_counts_one
      (d: db) (key: text) (window_secs limit: u64) (f: option nat)
  : Lemma
    (fst (rate_limit d key window_secs limit f) == RateObservation_Admitted ==>
       (not (faulted f 0) /\
        (snd (rate_limit d key window_secs limit f)).counters key
        == Some (bump (counter d key)))) =
  rate_limit_is_honest d key window_secs limit f

// ── Vectors shared with `executor_model.rs::tests::shared_vectors` ─────────

let s (x: string) : text = Alloc.String.String x

let vector_db : db =
  {
    grants = (fun k -> if k = s "g"
                       then Some ({ g_user = s "u"; g_device = s "d" } <: grant_row)
                       else None);
    claims = (fun k -> if k = s "g"
                       then Some ({ c_ek = s "ek"; c_vk = s "vk";
                                    c_name = Some (s "Phone");
                                    c_type_ = None } <: claim_row)
                       else None);
    results = (fun k -> if k = s "g"
                        then Some ({ r_device = s "dev"; r_vk = s "vk" } <: result_row)
                        else None);
    packages = (fun _ -> None);
    challenges = (fun _ -> None);
    users = (fun k -> if k = s "u"
                      then Some ({ u_epoch = mk_i64 3; u_rekey = None } <: user_row)
                      else None);
    devices = (fun _ -> None);
    grant_index = (fun _ -> None);
    counters = (fun _ -> None);
  }

/// The same state with no claim yet: a claim lands while the grant is live.
let vector_open_db : db = { vector_db with claims = (fun _ -> None) }

/// The same state with no grant: the guarded claim write refuses.
let vector_empty_db : db =
  { vector_db with grants = (fun _ -> None); claims = (fun _ -> None) }

let vector_claim_insert ()
  : Lemma (let (obs, post) =
             claim_write vector_open_db (s "g") (s "ek2") (s "vk2")
               (Core_models.Option.Option_None) (Core_models.Option.Option_None) None in
           obs == D.ClaimWriteObservation_Inserted /\
           Some? (post.claims (s "g")) /\
           (match post.claims (s "g") with
            | Some row -> row.c_ek == s "ek2"
            | None -> False)) =
  claim_write_is_honest vector_open_db (s "g") (s "ek2") (s "vk2")
    (Core_models.Option.Option_None) (Core_models.Option.Option_None) None

let vector_claim_second ()
  : Lemma (let (obs, post) =
             claim_write vector_db (s "g") (s "ek3") (s "vk3")
               (Core_models.Option.Option_None) (Core_models.Option.Option_None) None in
           obs == D.ClaimWriteObservation_KeyExists /\ post == vector_db) =
  claim_write_is_honest vector_db (s "g") (s "ek3") (s "vk3")
    (Core_models.Option.Option_None) (Core_models.Option.Option_None) None

let vector_claim_no_grant ()
  : Lemma (let (obs, post) =
             claim_write vector_empty_db (s "g") (s "ek") (s "vk")
               (Core_models.Option.Option_None) (Core_models.Option.Option_None) None in
           obs == D.ClaimWriteObservation_GuardMissing /\ post == vector_empty_db) =
  claim_write_is_honest vector_empty_db (s "g") (s "ek") (s "vk")
    (Core_models.Option.Option_None) (Core_models.Option.Option_None) None

let vector_ceremony_take ()
  : Lemma (let (obs, post) = take_ceremony vector_db (s "g") true true None in
           obs == D.TakeObservation_Taken
                    ({ D.f_grant_matches = true; D.f_claim_matches = true }) /\
           None? (post.grants (s "g")) /\ None? (post.claims (s "g"))) =
  take_ceremony_is_honest vector_db (s "g") true true None

let vector_ceremony_replay ()
  : Lemma (let (obs, post) = take_ceremony vector_db (s "g") true true None in
           obs =!= D.TakeObservation_Missing /\
           fst (take_ceremony post (s "g") true true None)
           == D.TakeObservation_Missing) =
  ceremony_take_is_single_use vector_db (s "g") None true true None

/// The pre-driver vectors: the liveness bit, the stored binding and the
/// limiter's counter.
let vector_grant_live ()
  : Lemma (let (present, post) = grant_exists vector_empty_db (s "g") None in
           present == false /\ post == vector_empty_db /\
           fst (grant_exists vector_db (s "g") None) == true) =
  grant_exists_is_honest vector_empty_db (s "g") None;
  grant_exists_is_honest vector_db (s "g") None

let vector_grant_read ()
  : Lemma (let (obs, post) = grant_read vector_db (s "g") (s "u") (s "d") None in
           obs == D.GrantObservation_Present
                    ({ D.f_user_matches = true; D.f_opener_matches = true }) /\
           post == vector_db /\
           (fst (grant_read vector_db (s "g") (s "u") (s "other") None)
            == D.GrantObservation_Present
                 ({ D.f_user_matches = true; D.f_opener_matches = false }))) =
  grant_read_is_honest vector_db (s "g") (s "u") (s "d") None;
  grant_read_is_honest vector_db (s "g") (s "u") (s "other") None

let vector_claim_inspection ()
  : Lemma (let (obs, post) = claim_inspection vector_db (s "g") None in
           obs.f_claim_present == true /\ post == vector_db) =
  claim_inspection_is_honest vector_db (s "g") None

let vector_rate_db : db =
  { vector_db with
    counters = (fun k -> if k = s "rl" then Some (mk_u64 2) else None) }

let vector_rate ()
  : Lemma
    (let (obs, post) = rate_limit vector_rate_db (s "rl") (mk_u64 60) (mk_u64 3) None in
     obs == RateObservation_Admitted /\
     post.counters (s "rl") == Some (mk_u64 3) /\
     (fst (rate_limit post (s "rl") (mk_u64 60) (mk_u64 3) None)
      == RateObservation_Limited) /\
     (fst (rate_limit post (s "rl") (mk_u64 60) (mk_u64 3) None) =!=
      RateObservation_Admitted ==> post.counters (s "rl") == Some (mk_u64 3))) =
  rate_limit_is_honest vector_rate_db (s "rl") (mk_u64 60) (mk_u64 3) None;
  rate_limit_is_honest
    (snd (rate_limit vector_rate_db (s "rl") (mk_u64 60) (mk_u64 3) None))
    (s "rl") (mk_u64 60) (mk_u64 3) None

#pop-options
