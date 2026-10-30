module Vela_recovery_policy_redemption_lemmas

/// F-1 for the recovered-device enrollment executor: for every starting
/// database, every starting enrollment grant and every fault point, each
/// `EnrollDeviceIo` method's observation (the extracted `classify_*` applied
/// to what the extracted `plan_*` did in
/// `Vela_recovery_policy_redemption_model`) is the truth about the tables and
/// the grant store.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Redemption_store
open Vela_recovery_policy_redemption_model

module L = FStar.List.Tot
module SP = FStar.Seq.Properties
module D = Vela_recovery_policy.Driver

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

// ── Frames ─────────────────────────────────────────────────────────────────

/// Only `devices[id]` may differ.
let devices_frame (d post: db) (id: text) : prop =
  (forall (k: text). k <> id ==> post.devices k == d.devices k) /\
  post.users == d.users /\
  post.grants == d.grants

/// Only `grants[key]` may differ.
let grants_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.grants k == d.grants k) /\
  post.users == d.users /\
  post.devices == d.devices

/// The exact device row the insert writes.
let inserted_row (user name kind ek vk created: text) : device_row =
  { dv_user = user; dv_name = name; dv_kind = kind;
    dv_ek = ek; dv_vk = vk; dv_created = created }

#push-options "--fuel 4 --ifuel 2"

// ── Grant consumption ──────────────────────────────────────────────────────

/// `consume_grant`: the observation is the truth about the single-use store.
/// A fault is unobserved (the handler aborts); otherwise `Missing` holds
/// exactly when the key was absent and leaves the state alone, and `Present`
/// carries the removed grant's own fields with `matches_observed_grant`
/// exactly the full-value equality with the preflight permit. Either way the
/// key is gone afterwards and nothing else changed.
let take_grant_is_honest (d: db) (key: text) (preflight: grant) (f: option nat)
  : Lemma
    (match take_grant d key preflight f with
     | None -> faulted f 0
     | Some (obs, post) ->
       not (faulted f 0) /\
       post.grants key == None /\
       grants_frame d post key /\
       (obs == D.ConsumptionObservation_Missing <==> d.grants key == None) /\
       (obs == D.ConsumptionObservation_Missing ==> post == d) /\
       (forall (g: grant). d.grants key == Some g ==>
          obs == D.ConsumptionObservation_Present
            ({ D.f_key_epoch = g.f_key_epoch;
               D.f_possession = g.f_possession;
               D.f_matches_observed_grant =
                 (g.f_key_epoch = preflight.f_key_epoch &&
                  g.f_possession = preflight.f_possession &&
                  g.f_credential_id = preflight.f_credential_id) } <: D.t_ConsumedGrantObservation))) =
  ()

// ── Guarded device insert ──────────────────────────────────────────────────

/// `insert_device`: `Inserted` holds exactly when the SQL guard held, the id
/// was fresh and no statement failed; then exactly the intended device row
/// was added. `Skipped` holds exactly when the guard refused a fresh id; a
/// fault or a duplicate id is `Failed`. Only a successful insert changes the
/// state.
let insert_device_is_honest
      (d: db) (device_id user name kind ek vk created: text) (epoch: i64)
      (guard: t_GrantGuard) (f: option nat)
  : Lemma
    (let (obs, post) =
       insert_device d device_id user name kind ek vk created epoch guard f in
     (obs == D.InsertObservation_Inserted <==>
        (insert_guard d user epoch guard /\ no_fault_in f 1 /\
         None? (d.devices device_id))) /\
     (obs == D.InsertObservation_Skipped <==>
        (not (insert_guard d user epoch guard) /\ no_fault_in f 1 /\
         None? (d.devices device_id))) /\
     (obs == D.InsertObservation_Failed <==>
        (faulted f 0 \/ Some? (d.devices device_id))) /\
     (obs == D.InsertObservation_Inserted ==>
        (post.devices device_id == Some (inserted_row user name kind ek vk created) /\
         devices_frame d post device_id)) /\
     (obs =!= D.InsertObservation_Inserted ==> post == d)) =
  let r =
    run_autocommit d
      (stmts_of (plan_insert_device device_id user name kind ek vk created epoch guard))
      0 f
  in
  seq_of_list_facts (fst r)

// ── Live authority recheck ─────────────────────────────────────────────────

/// `recheck_authority`: the observation is the stored row's truth in the
/// handler's historical precedence; only a failed query is `QueryFailed`.
let authority_observation_is_honest
      (d: db) (user credential_id: text) (possession: bool) (f: option nat)
  : Lemma
    (let obs = recheck_authority d user possession credential_id f in
     if faulted f 0 then obs == D.AuthorityRecheckObservation_QueryFailed
     else
       match d.users user with
       | None -> obs == D.AuthorityRecheckObservation_AccountAbsent
       | Some u ->
         if possession
         then
           (match u.us_auth with
            | Some _ -> obs == D.AuthorityRecheckObservation_StillRotating
            | None -> obs == D.AuthorityRecheckObservation_CommitmentRevoked)
         else
           (match u.us_cred with
            | Some current ->
              if current = credential_id
              then obs == D.AuthorityRecheckObservation_StillRotating
              else obs == D.AuthorityRecheckObservation_CredentialReplaced
            | None -> obs == D.AuthorityRecheckObservation_CredentialReplaced)) =
  ()

// ── Grant restoration ──────────────────────────────────────────────────────

/// `restore_grant`: a store error is unobserved (the handler aborts);
/// success writes exactly the consumed grant at its key and changes nothing
/// else.
let restore_grant_is_honest (d: db) (key value: text) (g: grant) (f: option nat)
  : Lemma
    (match restore_grant d key value g f with
     | None -> faulted f 0
     | Some post ->
       not (faulted f 0) /\
       post.grants key == Some g /\
       grants_frame d post key) =
  ()

// ── Facts the redemption driver relies on ──────────────────────────────────

/// A matching consumption is the preflight grant: `get_del` returned exactly
/// the value the non-consuming preflight observed.
let take_match_is_the_stored_grant
      (d: db) (key: text) (preflight: grant) (f: option nat)
  : Lemma
    (match take_grant d key preflight f with
     | Some (D.ConsumptionObservation_Present c, _) ->
       c.D.f_matches_observed_grant = true ==> d.grants key == Some preflight
     | _ -> True) =
  take_grant_is_honest d key preflight f

/// The single-use take removes the key, so a second redemption of the same
/// grant observes nothing.
let take_is_single_use
      (d: db) (key: text) (preflight: grant) (f: option nat)
      (preflight' : grant) (f' : option nat)
  : Lemma
    (match take_grant d key preflight f with
     | Some (_, post) ->
       (match take_grant post key preflight' f' with
        | Some (obs', _) -> obs' == D.ConsumptionObservation_Missing
        | None -> True)
     | None -> True) =
  take_grant_is_honest d key preflight f;
  match take_grant d key preflight f with
  | Some (_, post) -> take_grant_is_honest post key preflight' f'
  | None -> ()

/// An inserted device belongs to the request's user with exactly the request's
/// identity key, and only lands after every guard held.
let inserted_device_is_owned_and_guarded
      (d: db) (device_id user name kind ek vk created: text) (epoch: i64)
      (guard: t_GrantGuard) (f: option nat)
  : Lemma
    (let (obs, post) =
       insert_device d device_id user name kind ek vk created epoch guard f in
     obs == D.InsertObservation_Inserted ==>
       (insert_guard d user epoch guard /\
        (match post.devices device_id with
         | Some row -> row.dv_user == user /\ row.dv_ek == ek /\ row.dv_vk == vk
         | None -> False))) =
  insert_device_is_honest d device_id user name kind ek vk created epoch guard f

/// A restored grant is live at its key, so the retry path leaves the user
/// with the grant the driver just consumed.
let restored_grant_is_live
      (d: db) (key value: text) (g: grant) (f: option nat)
  : Lemma
    (match restore_grant d key value g f with
     | Some post -> post.grants key == Some g
     | None -> True) =
  restore_grant_is_honest d key value g f

// ── Vectors shared with `redemption_model.rs::tests::shared_vectors` ───────

let s (x: string) : text = Alloc.String.String x

let vector_grant : grant =
  { f_key_epoch = mk_i64 7; f_credential_id = s "c"; f_possession = false }

let vector_user : user_row =
  { us_epoch = mk_i64 7; us_rekey = false;
    us_cred = Some (s "c");
    us_auth = Some (s "h") }

let vector_db : db =
  {
    users = (fun k -> if k = s "u" then Some vector_user else None);
    devices = (fun _ -> None);
    grants = (fun k -> if k = s "k" then Some vector_grant else None)
  }

let vector_take_present ()
  : Lemma
    (match take_grant vector_db (s "k") vector_grant None with
     | Some (obs, post) ->
       obs == D.ConsumptionObservation_Present
         ({ D.f_key_epoch = mk_i64 7; D.f_possession = false;
            D.f_matches_observed_grant = true } <: D.t_ConsumedGrantObservation) /\
       post.grants (s "k") == None
     | None -> False) =
  take_grant_is_honest vector_db (s "k") vector_grant None

let vector_take_missing ()
  : Lemma
    (match take_grant vector_db (s "other") vector_grant None with
     | Some (obs, post) -> obs == D.ConsumptionObservation_Missing /\ post == vector_db
     | None -> False) =
  take_grant_is_honest vector_db (s "other") vector_grant None

let vector_insert_credential ()
  : Lemma
    (let (obs, post) =
       insert_device vector_db (s "d") (s "u") (s "name") (s "kind")
         (s "ek") (s "vk") (s "t") (mk_i64 7)
         (GrantGuard_Credential { f_credential_id = s "c" }) None in
     obs == D.InsertObservation_Inserted /\ Some? (post.devices (s "d"))) =
  insert_device_is_honest vector_db (s "d") (s "u") (s "name") (s "kind")
    (s "ek") (s "vk") (s "t") (mk_i64 7)
    (GrantGuard_Credential { f_credential_id = s "c" }) None

let vector_insert_stale_epoch ()
  : Lemma
    (let (obs, post) =
       insert_device vector_db (s "d") (s "u") (s "name") (s "kind")
         (s "ek") (s "vk") (s "t") (mk_i64 8)
         (GrantGuard_Credential { f_credential_id = s "c" }) None in
     obs == D.InsertObservation_Skipped /\ post == vector_db) =
  insert_device_is_honest vector_db (s "d") (s "u") (s "name") (s "kind")
    (s "ek") (s "vk") (s "t") (mk_i64 8)
    (GrantGuard_Credential { f_credential_id = s "c" }) None

let vector_authority_rotating ()
  : Lemma (recheck_authority vector_db (s "u") false (s "c") None ==
           D.AuthorityRecheckObservation_StillRotating) =
  authority_observation_is_honest vector_db (s "u") (s "c") false None

let vector_authority_absent ()
  : Lemma (recheck_authority vector_db (s "missing") false (s "c") None ==
           D.AuthorityRecheckObservation_AccountAbsent) =
  authority_observation_is_honest vector_db (s "missing") (s "c") false None

let vector_restore_grant ()
  : Lemma
    (match restore_grant
             { users = (fun _ -> None); devices = (fun _ -> None);
               grants = (fun _ -> None) }
             (s "k") (s "v") vector_grant None with
     | Some post -> post.grants (s "k") == Some vector_grant
     | None -> False) =
  restore_grant_is_honest
    { users = (fun _ -> None); devices = (fun _ -> None); grants = (fun _ -> None) }
    (s "k") (s "v") vector_grant None

#pop-options
