module Vela_recovery_policy_webauthn_lemmas

/// F-1 for the four WebAuthn recovery executors: for every starting database,
/// every starting attempt and registration slot, every starting credential
/// index and every fault point, each `InitiateIo`/`RecoverIo`/
/// `RegisterStartIo`/`RegisterFinishIo` method's observation (the extracted
/// `classify_*` applied to what the extracted `plan_*` did in
/// `Vela_recovery_policy_webauthn_model`) is the truth about the `users` row,
/// the single-use slots, the credential-id index and the grant store.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Webauthn_store
open Vela_recovery_policy_webauthn_model

module L = FStar.List.Tot
module WD = Vela_recovery_policy.Webauthn_driver

let s (x: string) : text = Alloc.String.String x

// ── Frames ─────────────────────────────────────────────────────────────────

/// Only the attempt slot `key` may differ.
let attempts_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.attempts k == d.attempts k) /\
  post.users == d.users /\
  post.registrations == d.registrations /\
  post.grants == d.grants /\
  post.holders == d.holders

/// Only the registration slot `key` may differ.
let registrations_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.registrations k == d.registrations k) /\
  post.users == d.users /\
  post.attempts == d.attempts /\
  post.grants == d.grants /\
  post.holders == d.holders

/// Only the grant slot `key` may differ.
let grants_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.grants k == d.grants k) /\
  post.users == d.users /\
  post.attempts == d.attempts /\
  post.registrations == d.registrations /\
  post.holders == d.holders

/// Only `users[user]` and the credential-index entries `old` and `new_id` may
/// differ.
let credential_write_frame
      (d post: db) (user: text) (old: Core_models.Option.t_Option text) (new_id: text)
  : prop =
  (forall (k: text). k <> user ==> post.users k == d.users k) /\
  (forall (k: text).
      k <> new_id /\ old <> Core_models.Option.Option_Some k ==>
      post.holders k == d.holders k) /\
  post.attempts == d.attempts /\
  post.registrations == d.registrations /\
  post.grants == d.grants

#push-options "--fuel 4 --ifuel 2"

// ── Authentication start ───────────────────────────────────────────────────

/// `InitiateIo::auth_start_observe`: every observation field is the live
/// row's truth and the slot is reported fresh exactly when the probe found it
/// empty. A failed read or probe is unobserved (the handler aborts); no effect
/// changes the state.
let auth_start_observation_is_honest
      (d: db) (user slot: text) (ttl: u64) (fs fk: option nat)
  : Lemma
    (match auth_start_observe d user slot ttl fs fk with
     | None ->
       faulted fs 0 \/ (not (faulted fs 0) /\ faulted fs 1) \/
       (not (faulted fs 0) /\ not (faulted fs 1) /\ faulted fk 0)
     | Some (obs, post) ->
       not (faulted fs 0) /\ not (faulted fs 1) /\ not (faulted fk 0) /\
       post == d /\
       obs.WD.f_account_present == Some? (d.users user) /\
       obs.WD.f_share_present == row_share_present d user /\
       obs.WD.f_credential ==
         (match d.users user with
          | Some row -> credential_observation row.ws_credential
          | None -> WD.StoredCredentialObservation_Missing) /\
       obs.WD.f_attempt_id_fresh == not (slot_occupied d slot) /\
       obs.WD.f_ttl_secs == ttl) =
  ()

/// `InitiateIo::auth_start_store`: `Stored` holds exactly when nothing failed
/// and the exact slot was free; a lost race wrote nothing, and a store error
/// is the `StorageFailed` observation with no state change.
let auth_start_store_is_honest
      (d: db) (key value: text) (state: stored_attempt) (ttl: u64) (fk: option nat)
  : Lemma
    (let (obs, post) = store_auth_state d key value state ttl fk in
     (obs == WD.ChallengeStoreObservation_Stored <==>
        (not (faulted fk 0) /\ not (slot_occupied d key))) /\
     (obs == WD.ChallengeStoreObservation_Lost <==>
        (not (faulted fk 0) /\ slot_occupied d key)) /\
     (obs == WD.ChallengeStoreObservation_StorageFailed <==> faulted fk 0) /\
     (obs == WD.ChallengeStoreObservation_Stored ==>
        (post.attempts key == Attempt_Valid state /\ attempts_frame d post key)) /\
     ((obs == WD.ChallengeStoreObservation_Lost \/
       obs == WD.ChallengeStoreObservation_StorageFailed) ==> post == d)) =
  ()

// ── Authentication finish ──────────────────────────────────────────────────

/// `RecoverIo::auth_finish_context`: every observation field is the live
/// row's truth. A failed read is unobserved.
let finish_context_is_honest
      (d: db) (user: text) (attempt_id_present: bool) (fs: option nat)
  : Lemma
    (match finish_context d user attempt_id_present fs with
     | None -> faulted fs 0 \/ (not (faulted fs 0) /\ faulted fs 1)
     | Some obs ->
       not (faulted fs 0) /\ not (faulted fs 1) /\
       obs.WD.f_account_present == Some? (d.users user) /\
       obs.WD.f_share_present == row_share_present d user /\
       obs.WD.f_credential ==
         (match d.users user with
          | Some row -> credential_observation row.ws_credential
          | None -> WD.StoredCredentialObservation_Missing) /\
       obs.WD.f_attempt_id_present == attempt_id_present) =
  ()

/// `RecoverIo::auth_finish_consume`: the removed envelope's own bindings, with
/// `Missing` exactly for an absent slot and `Corrupt` exactly for an
/// undecodable one. Either way the exact slot is gone afterwards and nothing
/// else changed.
let attempt_consumption_is_honest
      (d: db) (key user attempt observed_credential_id: text) (fk: option nat)
  : Lemma
    (match take_auth_state d key user attempt observed_credential_id fk,
           d.attempts key with
     | None, _ -> faulted fk 0
     | Some (obs, post), Attempt_Absent ->
       obs == WD.AuthAttemptConsumptionObservation_Missing /\ post == d
     | Some (obs, post), Attempt_Undecodable ->
       obs == WD.AuthAttemptConsumptionObservation_Corrupt /\
       post.attempts key == Attempt_Absent /\
       attempts_frame d post key
     | Some (obs, post), Attempt_Valid state ->
       obs == WD.AuthAttemptConsumptionObservation_Present
         ({ WD.f_user_matches = (state.f_user = user);
            WD.f_attempt_matches = (state.f_attempt = attempt);
            WD.f_credential_matches =
              (state.f_credential_id = observed_credential_id) }) /\
       post.attempts key == Attempt_Absent /\
       attempts_frame d post key) =
  ()

/// `RecoverIo::auth_finish_update`: `Updated` holds exactly when the guard
/// held and nothing failed; `Changed` (a zero-row update) changes nothing.
let credential_update_guard_is_honest
      (d: db) (user expected_credential_id credential credential_id: text)
      (fk: option nat)
  : Lemma
    (match update_credential d user expected_credential_id credential credential_id fk with
     | None -> faulted fk 0
     | Some (obs, _) ->
       not (faulted fk 0) /\
       (obs == WD.CredentialUpdateStoreObservation_Updated <==>
          update_guard d user expected_credential_id) /\
       (obs == WD.CredentialUpdateStoreObservation_Changed <==>
          not (update_guard d user expected_credential_id))) =
  ()

/// `RecoverIo::auth_finish_update`: an `Updated` write stored exactly the new
/// credential and its indexed id under the caller, and moved the index seed;
/// a `Changed` write changed nothing.
let credential_update_is_honest
      (d: db) (user expected_credential_id credential credential_id: text)
      (fk: option nat)
  : Lemma
    (match update_credential d user expected_credential_id credential credential_id fk with
     | None -> faulted fk 0
     | Some (obs, post) ->
       not (faulted fk 0) /\
       (obs == WD.CredentialUpdateStoreObservation_Updated ==>
          ((forall (row: user_row). d.users user == Some row ==>
              post.users user ==
              Some ({ row with
                      ws_credential = Cred_Valid credential_id;
                      ws_cred_id = Some credential_id })) /\
           post.holders credential_id == Some user /\
           credential_write_frame d post user
             (Core_models.Option.Option_Some expected_credential_id) credential_id)) /\
       (obs == WD.CredentialUpdateStoreObservation_Changed ==> post == d)) =
  credential_update_guard_is_honest d user expected_credential_id credential credential_id fk

/// `RecoverIo::auth_finish_account`: every observation field is the live
/// row's truth, compared with the challenge-bound credential id, and the split
/// side channel is the row's own `recovery_split_id`.
let finish_account_is_honest
      (d: db) (user credential_id: text) (fs: option nat)
  : Lemma
    (match finish_account d user credential_id fs with
     | None -> faulted fs 0
     | Some (obs, split) ->
       not (faulted fs 0) /\
       obs.WD.f_account_present == Some? (d.users user) /\
       obs.WD.f_account_epoch_active ==
         (match d.users user with
          | Some row -> not row.ws_rekey
          | None -> false) /\
       obs.WD.f_share_present == row_share_present d user /\
       obs.WD.f_stored_credential_matches ==
         row_credential_matches d user credential_id /\
       obs.WD.f_stored_epoch == row_epoch d user /\
       split == row_split d user) =
  ()

/// `RecoverIo::auth_finish_release`: a released share is exactly the row's own
/// stored share, decoding reports it, and the effect changes nothing; no share
/// means no observation (the handler aborts).
let share_release_is_honest (d: db) (user: text) (decoded: bool)
  : Lemma
    (match release_share d user decoded with
     | None -> not (row_share_present d user)
     | Some (obs, post) ->
       row_share_present d user /\
       post == d /\
       (obs == WD.ShareDecodeObservation_Decoded <==> decoded) /\
       (obs == WD.ShareDecodeObservation_Corrupt <==> not decoded)) =
  ()

/// `RecoverIo::auth_finish_store_grant`: `Stored` holds exactly when the store
/// wrote; then exactly the plan's grant is live at its key, and a failed write
/// changes nothing.
let grant_store_is_honest
      (d: db) (key value: text) (grant: t_CredentialGrantView) (ttl: u64)
      (fk: option nat)
  : Lemma
    (let (obs, post) = store_credential_grant d key value grant ttl fk in
     (obs == WD.GrantStoreObservation_Stored <==> not (faulted fk 0)) /\
     (obs == WD.GrantStoreObservation_Failed <==> faulted fk 0) /\
     (obs == WD.GrantStoreObservation_Stored ==>
        (post.grants key == Some grant /\ grants_frame d post key)) /\
     (obs == WD.GrantStoreObservation_Failed ==> post == d)) =
  ()

// ── Registration ───────────────────────────────────────────────────────────

/// `RegisterStartIo::registration_start_observe`: every observation field is
/// the live row's truth. A failed read is unobserved.
let registration_start_observation_is_honest
      (d: db) (user: text) (fs: option nat)
  : Lemma
    (match registration_start_observe d user fs with
     | None -> faulted fs 0
     | Some obs ->
       not (faulted fs 0) /\
       obs.WD.f_account_present == Some? (d.users user) /\
       obs.WD.f_credential ==
         (match d.users user with
          | Some row -> credential_observation row.ws_credential
          | None -> WD.StoredCredentialObservation_Missing)) =
  ()

/// `RegisterStartIo::registration_start_store`: `Stored` holds exactly when
/// the overwriting write landed; then the slot holds a decodable ceremony
/// state and nothing else changed.
let registration_state_store_is_honest
      (d: db) (key value: text) (ttl: u64) (fk: option nat)
  : Lemma
    (let (obs, post) = store_registration_state d key value ttl fk in
     (obs == WD.ChallengeStoreObservation_Stored <==> not (faulted fk 0)) /\
     (obs == WD.ChallengeStoreObservation_StorageFailed <==> faulted fk 0) /\
     (obs == WD.ChallengeStoreObservation_Stored ==>
        (post.registrations key == Registration_Valid /\
         registrations_frame d post key)) /\
     (obs == WD.ChallengeStoreObservation_StorageFailed ==> post == d)) =
  ()

/// `RegisterFinishIo::registration_consume_state`: the exact state is removed
/// whether or not it decoded, `Missing` is exactly an absent slot and
/// `Corrupt` exactly an undecodable one.
let registration_state_consumption_is_honest
      (d: db) (key: text) (fk: option nat)
  : Lemma
    (match take_registration_state d key fk, d.registrations key with
     | None, _ -> faulted fk 0
     | Some (obs, post), Registration_Absent ->
       obs == WD.RegistrationStateObservation_Missing /\ post == d
     | Some (obs, post), Registration_Undecodable ->
       obs == WD.RegistrationStateObservation_Corrupt /\
       post.registrations key == Registration_Absent /\
       registrations_frame d post key
     | Some (obs, post), Registration_Valid ->
       obs == WD.RegistrationStateObservation_Present /\
       post.registrations key == Registration_Absent /\
       registrations_frame d post key) =
  ()

/// `RegisterFinishIo::registration_check_uniqueness`: `RegisteredElsewhere`
/// holds exactly when the index names another account, `Unique` exactly when
/// it names the caller (or nobody), and a failed lookup is `LookupFailed`.
let uniqueness_is_honest
      (d: db) (credential_id user: text) (fs: option nat)
  : Lemma
    (let obs = check_uniqueness d credential_id user fs in
     (obs == WD.CredentialUniquenessObservation_RegisteredElsewhere <==>
        (not (faulted fs 0) /\ holder_other d credential_id user)) /\
     (obs == WD.CredentialUniquenessObservation_Unique <==>
        (not (faulted fs 0) /\ not (holder_other d credential_id user))) /\
     (obs == WD.CredentialUniquenessObservation_LookupFailed <==> faulted fs 0)) =
  ()

/// `RegisterFinishIo::registration_persist`: `Persisted` holds exactly when
/// the credential serialized, nothing failed and the caller's row exists; then
/// exactly that row and its indexed id were written. `AccountGone` is a
/// zero-row update, `EncodingFailed` a serialization failure, `StorageFailed`
/// a failed statement; each of those changes nothing.
let credential_persist_is_honest
      (d: db) (user credential credential_id: text) (encoded: bool) (fk: option nat)
  : Lemma
    (let (obs, post) = persist_credential d user credential credential_id encoded fk in
     (obs == WD.CredentialPersistObservation_EncodingFailed <==> not encoded) /\
     (obs == WD.CredentialPersistObservation_Persisted <==>
        (encoded /\ not (faulted fk 0) /\ Some? (d.users user))) /\
     (obs == WD.CredentialPersistObservation_AccountGone <==>
        (encoded /\ not (faulted fk 0) /\ not (Some? (d.users user)))) /\
     (obs == WD.CredentialPersistObservation_StorageFailed <==>
        (encoded /\ faulted fk 0)) /\
     (obs == WD.CredentialPersistObservation_Persisted ==>
        ((forall (row: user_row). d.users user == Some row ==>
            post.users user ==
            Some ({ row with
                    ws_credential = Cred_Valid credential_id;
                    ws_cred_id = Some credential_id })) /\
         post.holders credential_id == Some user /\
         credential_write_frame d post user (row_credential_id d user) credential_id)) /\
     (obs <> WD.CredentialPersistObservation_Persisted ==> post == d)) =
  ()

// ── Facts the WebAuthn drivers rely on ─────────────────────────────────────

/// The observed credential is exactly the live row's cell.
let observed_credential_is_the_live_one
      (d: db) (user slot: text) (ttl: u64) (fs fk: option nat)
  : Lemma
    (match auth_start_observe d user slot ttl fs fk with
     | Some (obs, _) ->
       obs.WD.f_credential ==
         (match d.users user with
          | Some row -> credential_observation row.ws_credential
          | None -> WD.StoredCredentialObservation_Missing)
     | None -> True) =
  auth_start_observation_is_honest d user slot ttl fs fk

/// A fresh observation really means the exact slot was empty.
let fresh_attempt_is_an_empty_slot
      (d: db) (user slot: text) (ttl: u64) (fs fk: option nat)
  : Lemma
    (match auth_start_observe d user slot ttl fs fk with
     | Some (obs, _) -> obs.WD.f_attempt_id_fresh ==> not (slot_occupied d slot)
     | None -> True) =
  auth_start_observation_is_honest d user slot ttl fs fk

/// A stored challenge holds exactly the envelope the plan carried, at its key.
let stored_attempt_is_the_drawn_one
      (d: db) (key value: text) (state: stored_attempt) (ttl: u64) (fk: option nat)
  : Lemma
    (match store_auth_state d key value state ttl fk with
     | (WD.ChallengeStoreObservation_Stored, post) ->
       post.attempts key == Attempt_Valid state
     | _ -> True) =
  auth_start_store_is_honest d key value state ttl fk

/// A lost race wrote nothing at all.
let lost_attempt_race_changed_nothing
      (d: db) (key value: text) (state: stored_attempt) (ttl: u64) (fk: option nat)
  : Lemma
    (match store_auth_state d key value state ttl fk with
     | (WD.ChallengeStoreObservation_Lost, post) -> post == d
     | _ -> True) =
  auth_start_store_is_honest d key value state ttl fk

/// The take removed the slot whether or not its bytes decoded, so a corrupt
/// attempt cannot be replayed.
let consumed_attempt_is_single_use
      (d: db) (key user attempt observed_credential_id: text) (fk: option nat)
      (user' attempt' observed': text) (fk': option nat)
  : Lemma
    (match take_auth_state d key user attempt observed_credential_id fk with
     | Some (_, post) ->
       (match take_auth_state post key user' attempt' observed' fk' with
        | Some (obs', _) -> obs' == WD.AuthAttemptConsumptionObservation_Missing
        | None -> True)
     | None -> True) =
  attempt_consumption_is_honest d key user attempt observed_credential_id fk;
  match take_auth_state d key user attempt observed_credential_id fk with
  | Some (_, post) ->
    attempt_consumption_is_honest post key user' attempt' observed' fk'
  | None -> ()

/// The consumed observation's bindings are the removed envelope's own.
let consumed_attempt_bindings_are_the_removed_ones
      (d: db) (key user attempt observed_credential_id: text) (fk: option nat)
      (state: stored_attempt)
  : Lemma
    (d.attempts key == Attempt_Valid state ==>
     (match take_auth_state d key user attempt observed_credential_id fk with
      | Some (obs, _) ->
        obs == WD.AuthAttemptConsumptionObservation_Present
          ({ WD.f_user_matches = (state.f_user = user);
             WD.f_attempt_matches = (state.f_attempt = attempt);
             WD.f_credential_matches =
               (state.f_credential_id = observed_credential_id) })
      | None -> True)) =
  attempt_consumption_is_honest d key user attempt observed_credential_id fk

/// A corrupt attempt is reported as corrupt, never as a missing one, even
/// though it was removed.
let corrupt_attempt_is_not_missing
      (d: db) (key user attempt observed_credential_id: text) (fk: option nat)
  : Lemma
    (match take_auth_state d key user attempt observed_credential_id fk with
     | Some (WD.AuthAttemptConsumptionObservation_Missing, _) ->
       d.attempts key == Attempt_Absent
     | Some (WD.AuthAttemptConsumptionObservation_Corrupt, _) ->
       d.attempts key == Attempt_Undecodable
     | _ -> True) =
  attempt_consumption_is_honest d key user attempt observed_credential_id fk

/// An `Updated` write stored exactly the new credential id under the caller.
let updated_credential_is_the_new_one
      (d: db) (user expected credential credential_id: text) (fk: option nat)
  : Lemma
    (match update_credential d user expected credential credential_id fk with
     | Some (WD.CredentialUpdateStoreObservation_Updated, post) ->
       (forall (row: user_row). d.users user == Some row ==>
          post.users user ==
          Some ({ row with
                  ws_credential = Cred_Valid credential_id;
                  ws_cred_id = Some credential_id })) /\
       post.holders credential_id == Some user
     | _ -> True) =
  credential_update_is_honest d user expected credential credential_id fk

/// The released share is the row's own stored share, and releasing changes
/// nothing.
let released_share_is_the_rows_share (d: db) (user: text) (decoded: bool)
  : Lemma
    (match release_share d user decoded with
     | Some (_, post) -> post == d
     | None -> True) =
  share_release_is_honest d user decoded

/// A stored grant is live at exactly its key with exactly the plan's epoch.
let issued_credential_grant_is_live
      (d: db) (key value: text) (grant: t_CredentialGrantView) (ttl: u64)
      (fk: option nat)
  : Lemma
    (let (obs, post) = store_credential_grant d key value grant ttl fk in
     obs == WD.GrantStoreObservation_Stored ==> post.grants key == Some grant) =
  grant_store_is_honest d key value grant ttl fk

/// A consumed registration state cannot be replayed.
let registration_state_is_single_use
      (d: db) (key: text) (fk fk': option nat)
  : Lemma
    (match take_registration_state d key fk with
     | Some (_, post) ->
       (match take_registration_state post key fk' with
        | Some (obs', _) -> obs' == WD.RegistrationStateObservation_Missing
        | None -> True)
     | None -> True) =
  registration_state_consumption_is_honest d key fk;
  match take_registration_state d key fk with
  | Some (_, post) -> registration_state_consumption_is_honest post key fk'
  | None -> ()

/// A `Unique` credential is held by no other account.
let unique_credential_has_no_other_holder
      (d: db) (credential_id user: text) (fs: option nat)
  : Lemma
    (check_uniqueness d credential_id user fs == WD.CredentialUniquenessObservation_Unique
     ==> not (holder_other d credential_id user)) =
  uniqueness_is_honest d credential_id user fs

/// A persisted credential is live on the caller's row and in the index.
let persisted_credential_is_live
      (d: db) (user credential credential_id: text) (encoded: bool) (fk: option nat)
  : Lemma
    (match persist_credential d user credential credential_id encoded fk with
     | (WD.CredentialPersistObservation_Persisted, post) ->
       post.holders credential_id == Some user
     | _ -> True) =
  credential_persist_is_honest d user credential credential_id encoded fk

// ── Vectors shared with `redemption_model.rs::shared_webauthn_vectors` ─────

let vector_user : user_row =
  { ws_share = Some (s "c2hhcmU=");
    ws_credential = Cred_Valid (s "cred");
    ws_cred_id = Some (s "cred");
    ws_epoch = Some (mk_i64 7);
    ws_rekey = false;
    ws_split = Some (s "split") }

let vector_attempt : stored_attempt =
  { f_user = s "u"; f_attempt = s "a"; f_credential_id = s "cred" }

let vector_db : db =
  { users = (fun k -> if k = s "u" then Some vector_user else None);
    attempts = (fun _ -> Attempt_Absent);
    registrations = (fun _ -> Registration_Absent);
    grants = (fun _ -> None);
    holders = (fun k -> if k = s "cred" then Some (s "u") else None) }

let vector_webauthn_start ()
  : Lemma
    (match auth_start_observe vector_db (s "u") (s "slot") (mk_u64 300) None None with
     | Some (obs, post) ->
       obs.WD.f_account_present = true /\ obs.WD.f_share_present = true /\
       obs.WD.f_attempt_id_fresh = true /\
       obs.WD.f_credential == WD.StoredCredentialObservation_Present /\
       obs.WD.f_ttl_secs == mk_u64 300 /\ post == vector_db
     | None -> False) =
  auth_start_observation_is_honest vector_db (s "u") (s "slot") (mk_u64 300) None None

let vector_webauthn_start_absent ()
  : Lemma
    (match auth_start_observe vector_db (s "missing") (s "slot") (mk_u64 300) None None with
     | Some (obs, post) ->
       obs.WD.f_account_present = false /\ obs.WD.f_share_present = false /\
       obs.WD.f_credential == WD.StoredCredentialObservation_Missing /\
       obs.WD.f_attempt_id_fresh = true /\ post == vector_db
     | None -> False) =
  auth_start_observation_is_honest vector_db (s "missing") (s "slot") (mk_u64 300) None None

let vector_slot_db : db =
  { vector_db with attempts = (fun k -> if k = s "slot" then Attempt_Valid vector_attempt else Attempt_Absent) }

let vector_webauthn_start_occupied ()
  : Lemma
    (match auth_start_observe vector_slot_db (s "u") (s "slot") (mk_u64 300) None None with
     | Some (obs, post) ->
       obs.WD.f_attempt_id_fresh = false /\ post == vector_slot_db
     | None -> False) =
  auth_start_observation_is_honest vector_slot_db (s "u") (s "slot") (mk_u64 300) None None

let vector_webauthn_store ()
  : Lemma
    (let (obs, post) =
       store_auth_state vector_db (s "slot") (s "v") vector_attempt (mk_u64 300) None in
     obs == WD.ChallengeStoreObservation_Stored /\
     post.attempts (s "slot") == Attempt_Valid vector_attempt) =
  auth_start_store_is_honest vector_db (s "slot") (s "v") vector_attempt (mk_u64 300) None

let vector_webauthn_store_lost ()
  : Lemma
    (let (obs, post) =
       store_auth_state vector_slot_db (s "slot") (s "v") vector_attempt (mk_u64 300) None in
     obs == WD.ChallengeStoreObservation_Lost /\ post == vector_slot_db) =
  auth_start_store_is_honest vector_slot_db (s "slot") (s "v") vector_attempt (mk_u64 300) None

let vector_webauthn_store_failed ()
  : Lemma
    (let (obs, post) =
       store_auth_state vector_db (s "slot") (s "v") vector_attempt (mk_u64 300) (Some 0) in
     obs == WD.ChallengeStoreObservation_StorageFailed /\ post == vector_db) =
  auth_start_store_is_honest vector_db (s "slot") (s "v") vector_attempt (mk_u64 300) (Some 0)

let vector_webauthn_context ()
  : Lemma
    (match finish_context vector_db (s "u") true None with
     | Some obs ->
       obs.WD.f_account_present = true /\ obs.WD.f_share_present = true /\
       obs.WD.f_credential == WD.StoredCredentialObservation_Present /\
       obs.WD.f_attempt_id_present = true
     | None -> False) =
  finish_context_is_honest vector_db (s "u") true None

let vector_webauthn_take ()
  : Lemma
    (match take_auth_state vector_slot_db (s "slot") (s "u") (s "a") (s "cred") None with
     | Some (obs, post) ->
       obs == WD.AuthAttemptConsumptionObservation_Present
         ({ WD.f_user_matches = true; WD.f_attempt_matches = true;
            WD.f_credential_matches = true }) /\
       post.attempts (s "slot") == Attempt_Absent
     | None -> False) =
  attempt_consumption_is_honest vector_slot_db (s "slot") (s "u") (s "a") (s "cred") None

let vector_webauthn_take_missing ()
  : Lemma
    (match take_auth_state vector_db (s "slot") (s "u") (s "a") (s "cred") None with
     | Some (obs, post) ->
       obs == WD.AuthAttemptConsumptionObservation_Missing /\ post == vector_db
     | None -> False) =
  attempt_consumption_is_honest vector_db (s "slot") (s "u") (s "a") (s "cred") None

let vector_corrupt_db : db =
  { vector_db with attempts = (fun k -> if k = s "slot" then Attempt_Undecodable else Attempt_Absent) }

let vector_webauthn_take_corrupt ()
  : Lemma
    (match take_auth_state vector_corrupt_db (s "slot") (s "u") (s "a") (s "cred") None with
     | Some (obs, post) ->
       obs == WD.AuthAttemptConsumptionObservation_Corrupt /\
       post.attempts (s "slot") == Attempt_Absent
     | None -> False) =
  attempt_consumption_is_honest vector_corrupt_db (s "slot") (s "u") (s "a") (s "cred") None

let vector_webauthn_update ()
  : Lemma
    (match update_credential vector_db (s "u") (s "cred") (s "{}") (s "cred2") None with
     | Some (obs, post) ->
       obs == WD.CredentialUpdateStoreObservation_Updated /\
       post.holders (s "cred2") == Some (s "u") /\ post.holders (s "cred") == None
     | None -> False) =
  credential_update_is_honest vector_db (s "u") (s "cred") (s "{}") (s "cred2") None

let vector_webauthn_update_stale ()
  : Lemma
    (match update_credential vector_db (s "u") (s "other") (s "{}") (s "cred2") None with
     | Some (obs, post) ->
       obs == WD.CredentialUpdateStoreObservation_Changed /\ post == vector_db
     | None -> False) =
  credential_update_is_honest vector_db (s "u") (s "other") (s "{}") (s "cred2") None

let vector_webauthn_account ()
  : Lemma
    (match finish_account vector_db (s "u") (s "cred") None with
     | Some (obs, split) ->
       obs.WD.f_account_present = true /\ obs.WD.f_account_epoch_active = true /\
       obs.WD.f_share_present = true /\ obs.WD.f_stored_credential_matches = true /\
       obs.WD.f_stored_epoch == Core_models.Option.Option_Some (mk_i64 7) /\
       split == Core_models.Option.Option_Some (s "split")
     | None -> False) =
  finish_account_is_honest vector_db (s "u") (s "cred") None

let vector_webauthn_account_absent ()
  : Lemma
    (match finish_account vector_db (s "missing") (s "cred") None with
     | Some (obs, split) ->
       obs.WD.f_account_present = false /\ obs.WD.f_account_epoch_active = false /\
       obs.WD.f_share_present = false /\ split == Core_models.Option.Option_None
     | None -> False) =
  finish_account_is_honest vector_db (s "missing") (s "cred") None

let vector_webauthn_release ()
  : Lemma
    (match release_share vector_db (s "u") true with
     | Some (obs, post) ->
       obs == WD.ShareDecodeObservation_Decoded /\ post == vector_db
     | None -> False) =
  share_release_is_honest vector_db (s "u") true

let vector_webauthn_release_corrupt ()
  : Lemma
    (match release_share vector_db (s "u") false with
     | Some (obs, post) ->
       obs == WD.ShareDecodeObservation_Corrupt /\ post == vector_db
     | None -> False) =
  share_release_is_honest vector_db (s "u") false

let vector_webauthn_release_missing ()
  : Lemma (release_share vector_db (s "missing") true == None) =
  share_release_is_honest vector_db (s "missing") true

let vector_grant : t_CredentialGrantView =
  { f_key_epoch = mk_i64 7; f_credential_id = s "cred"; f_possession = false }

let vector_webauthn_grant ()
  : Lemma
    (let (obs, post) =
       store_credential_grant vector_db (s "g") (s "v") vector_grant (mk_u64 600) None in
     obs == WD.GrantStoreObservation_Stored /\ post.grants (s "g") == Some vector_grant) =
  grant_store_is_honest vector_db (s "g") (s "v") vector_grant (mk_u64 600) None

let vector_webauthn_grant_failed ()
  : Lemma
    (let (obs, post) =
       store_credential_grant vector_db (s "g") (s "v") vector_grant (mk_u64 600) (Some 0) in
     obs == WD.GrantStoreObservation_Failed /\ post == vector_db) =
  grant_store_is_honest vector_db (s "g") (s "v") vector_grant (mk_u64 600) (Some 0)

let vector_webauthn_registration_start ()
  : Lemma
    (match registration_start_observe vector_db (s "u") None with
     | Some obs ->
       obs.WD.f_account_present = true /\
       obs.WD.f_credential == WD.StoredCredentialObservation_Present
     | None -> False) =
  registration_start_observation_is_honest vector_db (s "u") None

let vector_webauthn_registration_store ()
  : Lemma
    (let (obs, post) =
       store_registration_state vector_db (s "r") (s "{}") (mk_u64 300) None in
     obs == WD.ChallengeStoreObservation_Stored /\
     post.registrations (s "r") == Registration_Valid) =
  registration_state_store_is_honest vector_db (s "r") (s "{}") (mk_u64 300) None

let vector_registration_db : db =
  { vector_db with
    registrations = (fun k -> if k = s "r" then Registration_Valid else Registration_Absent) }

let vector_webauthn_registration_take ()
  : Lemma
    (match take_registration_state vector_registration_db (s "r") None with
     | Some (obs, post) ->
       obs == WD.RegistrationStateObservation_Present /\
       post.registrations (s "r") == Registration_Absent
     | None -> False) =
  registration_state_consumption_is_honest vector_registration_db (s "r") None

let vector_webauthn_registration_take_missing ()
  : Lemma
    (match take_registration_state vector_db (s "r") None with
     | Some (obs, post) ->
       obs == WD.RegistrationStateObservation_Missing /\ post == vector_db
     | None -> False) =
  registration_state_consumption_is_honest vector_db (s "r") None

let vector_webauthn_uniqueness ()
  : Lemma
    (check_uniqueness vector_db (s "cred") (s "u") None ==
       WD.CredentialUniquenessObservation_Unique) =
  uniqueness_is_honest vector_db (s "cred") (s "u") None

let vector_webauthn_uniqueness_elsewhere ()
  : Lemma
    (check_uniqueness vector_db (s "cred") (s "other") None ==
       WD.CredentialUniquenessObservation_RegisteredElsewhere) =
  uniqueness_is_honest vector_db (s "cred") (s "other") None

let vector_webauthn_uniqueness_failed ()
  : Lemma
    (check_uniqueness vector_db (s "cred") (s "u") (Some 0) ==
       WD.CredentialUniquenessObservation_LookupFailed) =
  uniqueness_is_honest vector_db (s "cred") (s "u") (Some 0)

let vector_webauthn_persist ()
  : Lemma
    (let (obs, post) =
       persist_credential vector_db (s "u") (s "{}") (s "cred2") true None in
     obs == WD.CredentialPersistObservation_Persisted /\
     post.holders (s "cred2") == Some (s "u") /\ post.holders (s "cred") == None) =
  credential_persist_is_honest vector_db (s "u") (s "{}") (s "cred2") true None

let vector_webauthn_persist_gone ()
  : Lemma
    (let (obs, post) =
       persist_credential vector_db (s "missing") (s "{}") (s "cred2") true None in
     obs == WD.CredentialPersistObservation_AccountGone /\ post == vector_db) =
  credential_persist_is_honest vector_db (s "missing") (s "{}") (s "cred2") true None

let vector_webauthn_persist_encoding ()
  : Lemma
    (let (obs, post) =
       persist_credential vector_db (s "u") (s "{}") (s "cred2") false None in
     obs == WD.CredentialPersistObservation_EncodingFailed /\ post == vector_db) =
  credential_persist_is_honest vector_db (s "u") (s "{}") (s "cred2") false None

#pop-options
