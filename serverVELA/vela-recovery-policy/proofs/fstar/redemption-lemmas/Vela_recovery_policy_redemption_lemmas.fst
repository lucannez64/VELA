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

/// Only `devices[id]` and `grant_index[grant]` may differ.
let devices_frame (d post: db) (id grant: text) : prop =
  (forall (k: text). k <> id ==> post.devices k == d.devices k) /\
  (forall (k: text). k <> grant ==> post.grant_index k == d.grant_index k) /\
  post.users == d.users /\
  post.grants == d.grants

/// Only `grants[key]` may differ.
let grants_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.grants k == d.grants k) /\
  post.users == d.users /\
  post.devices == d.devices /\
  post.grant_index == d.grant_index

/// The exact device row the insert writes.
let inserted_row (user name kind ek vk created grant: text) : device_row =
  { dv_user = user; dv_name = name; dv_kind = kind;
    dv_ek = ek; dv_vk = vk; dv_created = created; dv_grant = Some grant }

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
/// was fresh, no other row carried the grant and no statement failed; then
/// exactly the intended device row was added and the grant index names it.
/// `Skipped` holds exactly when the guard refused a fresh id under an unused
/// grant; a fault, a duplicate device id or a used grant is `Failed`. Only a
/// successful insert changes the state, so a grant can never name two rows.
let insert_device_is_honest
      (d: db) (device_id user name kind ek vk created grant: text) (epoch: i64)
      (guard: t_GrantGuard) (f: option nat)
  : Lemma
    (let (obs, post) =
       insert_device d device_id user name kind ek vk created grant epoch guard f in
     (obs == D.InsertObservation_Inserted <==>
        (insert_guard d user epoch guard /\ no_fault_in f 1 /\
         None? (d.devices device_id) /\ None? (d.grant_index grant))) /\
     (obs == D.InsertObservation_Skipped <==>
        (not (insert_guard d user epoch guard) /\ no_fault_in f 1 /\
         None? (d.devices device_id) /\ None? (d.grant_index grant))) /\
     (obs == D.InsertObservation_Failed <==>
        (faulted f 0 \/ Some? (d.devices device_id) \/ Some? (d.grant_index grant))) /\
     (obs == D.InsertObservation_Inserted ==>
        (post.devices device_id == Some (inserted_row user name kind ek vk created grant) /\
         post.grant_index grant == Some device_id /\
         devices_frame d post device_id grant)) /\
     (obs =!= D.InsertObservation_Inserted ==> post == d)) =
  let r =
    run_autocommit d
      (stmts_of (plan_insert_device device_id user name kind ek vk created epoch guard grant))
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
/// identity key and the grant that authorized it, and only lands after every
/// guard held.
let inserted_device_is_owned_and_guarded
      (d: db) (device_id user name kind ek vk created grant: text) (epoch: i64)
      (guard: t_GrantGuard) (f: option nat)
  : Lemma
    (let (obs, post) =
       insert_device d device_id user name kind ek vk created grant epoch guard f in
     obs == D.InsertObservation_Inserted ==>
       (insert_guard d user epoch guard /\
        (match post.devices device_id with
         | Some row -> row.dv_user == user /\ row.dv_ek == ek /\ row.dv_vk == vk /\
                       row.dv_grant == Some grant
         | None -> False) /\
        post.grant_index grant == Some device_id)) =
  insert_device_is_honest d device_id user name kind ek vk created grant epoch guard f

/// U-24: the replay lookup returns exactly the device the first request
/// created. For every starting database, every guard and every fault point: if
/// the insert reported `Inserted`, the row it wrote is the row the lookup
/// names, with the same device id, the same user and the request's own key
/// material. The lookup changes nothing.
let replay_finds_the_inserted_device
      (d: db) (device_id user name kind ek vk created grant: text) (epoch: i64)
      (guard: t_GrantGuard) (f: option nat)
  : Lemma
    (let (obs, post) =
       insert_device d device_id user name kind ek vk created grant epoch guard f in
     obs == D.InsertObservation_Inserted ==>
       (enrolled_device_row post user grant ==
          Some ({ f_device_id = device_id;
                  f_hybrid_ek = ek;
                  f_hybrid_vk = vk } <: t_EnrolledDeviceRowView) /\
        enrolled_device post user grant ek vk ==
          D.ReplayObservation_Enrolled { f_key_matches = true })) =
  insert_device_is_honest d device_id user name kind ek vk created grant epoch guard f

/// U-24: a replay that presents different key material never matches the row
/// this grant created. It is rejected by the same classifier that guards the
/// matching case, so a different key cannot collect another key's device.
let replay_rejects_a_different_key
      (d: db) (device_id user name kind ek vk created grant: text) (epoch: i64)
      (guard: t_GrantGuard) (f: option nat) (ek' vk': text)
  : Lemma
    (let (obs, post) =
       insert_device d device_id user name kind ek vk created grant epoch guard f in
     obs == D.InsertObservation_Inserted ==>
       ((ek' <> ek \/ vk' <> vk) ==>
        enrolled_device post user grant ek' vk' ==
          D.ReplayObservation_Enrolled { f_key_matches = false })) =
  insert_device_is_honest d device_id user name kind ek vk created grant epoch guard f

/// U-24: the grant index is a second wall behind the single-use take. Once a
/// device carries a grant, another insert for that grant is refused, so the
/// grant can name at most one device even if two guarded inserts race.
let insert_with_used_grant_is_refused
      (d: db) (first second: text) (user name kind ek vk created grant: text)
      (epoch: i64) (guard: t_GrantGuard) (f f': option nat)
  : Lemma
    (let (obs, post) =
       insert_device d first user name kind ek vk created grant epoch guard f in
     obs == D.InsertObservation_Inserted ==>
       (let (obs', _) =
          insert_device post second user name kind ek vk created grant epoch guard f' in
        obs' == D.InsertObservation_Failed)) =
  insert_device_is_honest d first user name kind ek vk created grant epoch guard f

/// U-24: with no device row for the grant, the replay lookup is absent and the
/// classifier refuses it.
let replay_without_a_row_is_absent
      (d: db) (user grant ek vk: text)
  : Lemma
    (requires (None? (d.grant_index grant)))
    (ensures (enrolled_device d user grant ek vk == D.ReplayObservation_Absent)) =
  ()

/// A restored grant is live at its key, so the retry path leaves the user
/// with the grant the driver just consumed.
let restored_grant_is_live
      (d: db) (key value: text) (g: grant) (f: option nat)
  : Lemma
    (match restore_grant d key value g f with
     | Some post -> post.grants key == Some g
     | None -> True) =
  restore_grant_is_honest d key value g f

// ── The pre-driver grant read and the enrollment preflight account read ────

/// `observe_enroll_grant`: a present observation is exactly the stored grant,
/// absence is an absent key, the read changes nothing, and a fault is
/// unobserved (the handler aborts with the store's error).
let peek_grant_is_honest (d: db) (key: text) (f: option nat)
  : Lemma
    (match peek_grant d key f with
     | None -> faulted f 0
     | Some (obs, post) ->
       post == d /\
       (match d.grants key with
        | None -> obs == GrantPeekObservation_Absent
        | Some g -> obs == GrantPeekObservation_Present g)) =
  ()

/// `post_enroll_device`'s preflight account read: every field is the live
/// row's truth (the normalized epoch under the grant's epoch and no rotation
/// gate for the commitment length), absence is an absent row, the read changes
/// nothing, and a fault is unobserved.
let enrollment_account_is_honest
      (d: db) (user: text) (epoch: i64) (credential_id: text)
      (commitment_len: usize) (f: option nat)
  : Lemma
    (match enrollment_account d user epoch credential_id commitment_len f with
     | None -> faulted f 0
     | Some (view, post) ->
       post == d /\
       (match d.users user with
        | None -> view == (None <: option t_EnrollmentAccountView)
        | Some row ->
          (match view with
           | Some facts ->
             facts.f_stored_epoch == Core_models.Option.Option_Some row.us_epoch /\
             facts.f_epoch_active == not row.us_rekey /\
             facts.f_credential_id_matches ==
               (match row.us_cred with
                | Some c -> c =. credential_id
                | None -> false) /\
             facts.f_commitment_len ==
               (if (observed_epoch (Core_models.Option.Option_Some row.us_epoch) =. epoch)
                     && not row.us_rekey
                then commitment_len
                else mk_usize 0)
           | _ -> False))) =
  ()

/// The enrollment preflight cannot read account state for a grant it did not
/// observe: the peek is the stored truth, so an absent observation is an
/// absent key.
let absent_peek_means_no_grant (d: db) (key: text) (f: option nat)
  : Lemma
    (match peek_grant d key f with
     | Some (GrantPeekObservation_Absent, _) -> None? (d.grants key)
     | _ -> True) =
  peek_grant_is_honest d key f

/// The preflight's live-row facts are the stored row's: the epoch, the
/// rotation flag and the credential match the `users` row the grant is bound
/// to. The preflight decision therefore compares the stored state, not a
/// caller-supplied one.
let account_facts_are_the_stored_row
      (d: db) (user: text) (epoch: i64) (credential_id: text)
      (commitment_len: usize) (f: option nat)
  : Lemma
    (match enrollment_account d user epoch credential_id commitment_len f with
     | Some (Some facts, _) ->
       (match d.users user with
        | Some row ->
          facts.f_stored_epoch == Core_models.Option.Option_Some row.us_epoch /\
          facts.f_epoch_active == not row.us_rekey /\
          facts.f_credential_id_matches ==
            (match row.us_cred with
             | Some c -> c =. credential_id
             | None -> false)
        | None -> False)
     | _ -> True) =
  enrollment_account_is_honest d user epoch credential_id commitment_len f

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
    grants = (fun k -> if k = s "k" then Some vector_grant else None);
    grant_index = (fun _ -> None)
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
         (s "ek") (s "vk") (s "t") (s "g") (mk_i64 7)
         (GrantGuard_Credential { f_credential_id = s "c" }) None in
     obs == D.InsertObservation_Inserted /\ Some? (post.devices (s "d")) /\
     post.grant_index (s "g") == Some (s "d")) =
  insert_device_is_honest vector_db (s "d") (s "u") (s "name") (s "kind")
    (s "ek") (s "vk") (s "t") (s "g") (mk_i64 7)
    (GrantGuard_Credential { f_credential_id = s "c" }) None

/// The same run as `vector_insert_credential`, then the U-24 replay.
let vector_replay_enrolled ()
  : Lemma
    (let (obs, post) =
       insert_device vector_db (s "d") (s "u") (s "name") (s "kind")
         (s "ek") (s "vk") (s "t") (s "g") (mk_i64 7)
         (GrantGuard_Credential { f_credential_id = s "c" }) None in
     obs == D.InsertObservation_Inserted ==>
       (enrolled_device post (s "u") (s "g") (s "ek") (s "vk") ==
          D.ReplayObservation_Enrolled { f_key_matches = true } /\
        enrolled_device post (s "u") (s "g") (s "ek") (s "other") ==
          D.ReplayObservation_Enrolled { f_key_matches = false } /\
        enrolled_device post (s "other") (s "g") (s "ek") (s "vk") ==
          D.ReplayObservation_Absent /\
        enrolled_device vector_db (s "u") (s "g") (s "ek") (s "vk") ==
          D.ReplayObservation_Absent)) =
  insert_device_is_honest vector_db (s "d") (s "u") (s "name") (s "kind")
    (s "ek") (s "vk") (s "t") (s "g") (mk_i64 7)
    (GrantGuard_Credential { f_credential_id = s "c" }) None

let vector_insert_stale_epoch ()
  : Lemma
    (let (obs, post) =
       insert_device vector_db (s "d") (s "u") (s "name") (s "kind")
         (s "ek") (s "vk") (s "t") (s "g") (mk_i64 8)
         (GrantGuard_Credential { f_credential_id = s "c" }) None in
     obs == D.InsertObservation_Skipped /\ post == vector_db) =
  insert_device_is_honest vector_db (s "d") (s "u") (s "name") (s "kind")
    (s "ek") (s "vk") (s "t") (s "g") (mk_i64 8)
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
               grants = (fun _ -> None); grant_index = (fun _ -> None) }
             (s "k") (s "v") vector_grant None with
     | Some post -> post.grants (s "k") == Some vector_grant
     | None -> False) =
  restore_grant_is_honest
    { users = (fun _ -> None); devices = (fun _ -> None);
      grants = (fun _ -> None); grant_index = (fun _ -> None) }
    (s "k") (s "v") vector_grant None

let vector_peek_grant ()
  : Lemma
    (match peek_grant vector_db (s "k") None with
     | Some (GrantPeekObservation_Present g, post) ->
       g == vector_grant /\ post == vector_db
     | _ -> False) =
  peek_grant_is_honest vector_db (s "k") None

let vector_account ()
  : Lemma
    (match enrollment_account vector_db (s "u") (mk_i64 7) (s "c")
             (mk_usize 1) None with
     | Some (Some facts, post) ->
       facts.f_credential_id_matches == true /\
       facts.f_commitment_len == mk_usize 1 /\
       post == vector_db
     | _ -> False) =
  enrollment_account_is_honest vector_db (s "u") (mk_i64 7) (s "c")
    (mk_usize 1) None

#pop-options
