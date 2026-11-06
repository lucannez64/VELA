module Vela_recovery_policy_possession_lemmas

/// F-1 for the possession-proof recovery executors: for every starting
/// database, every starting attempt slot and every fault point, each
/// `InitiateProofIo`/`RecoverProofIo` method's observation (the extracted
/// `classify_*` applied to what the extracted `plan_*` did in
/// `Vela_recovery_policy_possession_model`) is the truth about the `users`
/// row, the single-use proof slot and the enrollment-grant store.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Possession_store
open Vela_recovery_policy_possession_model

module PD = Vela_recovery_policy.Possession_driver
module V = Vela_recovery_policy

let s (x: string) : text = Alloc.String.String x

// ── Frames ─────────────────────────────────────────────────────────────────

/// Only the challenge slot `key` may differ.
let challenges_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.challenges k == d.challenges k) /\
  post.users == d.users /\
  post.grants == d.grants

/// Only the grant slot `key` may differ.
let grants_frame (d post: db) (key: text) : prop =
  (forall (k: text). k <> key ==> post.grants k == d.grants k) /\
  post.users == d.users /\
  post.challenges == d.challenges

#push-options "--fuel 4 --ifuel 2"

// ── Initiation ─────────────────────────────────────────────────────────────

/// `InitiateProofIo::observe`: every observation field is the live row's truth
/// and the slot is reported fresh exactly when the probe found it empty. A
/// failed read or probe is unobserved (the handler aborts); neither effect
/// changes the state.
let initiate_observation_is_honest
      (d: db) (user key: text) (ttl: u64) (fs fk: option nat)
  : Lemma
    (match initiate_observation d user key ttl fs fk with
     | None -> faulted fs 0 \/ (not (faulted fs 0) /\ faulted fk 0)
     | Some (obs, post) ->
       not (faulted fs 0) /\ not (faulted fk 0) /\
       post == d /\
       obs.PD.f_account_present == Some? (d.users user) /\
       obs.PD.f_share_present ==
         (match d.users user with
          | Some row -> row.us_share
          | None -> false) /\
       obs.PD.f_commitment ==
         (match d.users user with
          | Some row -> row.us_commitment
          | None -> PD.CommitmentObservation_Missing) /\
       obs.PD.f_rotation_active ==
         (match d.users user with
          | Some row -> row.us_rekey
          | None -> false) /\
       obs.PD.f_attempt_id_fresh == not (slot_occupied d key) /\
       obs.PD.f_ttl_secs == ttl) =
  ()

/// `InitiateProofIo::observe`'s epoch side channel: the challenge is bound to
/// the row's stored epoch, normalized exactly as the policy normalizes a
/// missing row or column.
let initiate_epoch_is_honest (d: db) (user: text) (fs: option nat)
  : Lemma
    (match read_initiate_account d user fs with
     | Row row ->
       initiate_epoch row == V.observed_recovery_epoch (row_epoch d user) /\
       initiate_epoch row == initiate_epoch_of d user fs
     | Failed ->
       initiate_epoch_of d user fs == V.v_INITIAL_EPOCH) =
  ()

/// `InitiateProofIo::store_challenge`: a written slot holds exactly the drawn
/// attempt, and a lost race changes nothing.
let store_challenge_is_honest
      (d: db) (key value: text) (attempt: t_ProofAttemptView) (ttl: u64)
      (fk: option nat)
  : Lemma
    (match store_challenge d key value attempt ttl fk with
     | None -> faulted fk 0
     | Some (obs, post) ->
       not (faulted fk 0) /\
       (obs == PD.ChallengeStoreObservation_Stored <==>
          not (slot_occupied d key)) /\
       (obs == PD.ChallengeStoreObservation_Lost <==> slot_occupied d key) /\
       (obs == PD.ChallengeStoreObservation_Stored ==>
          (post.challenges key == Attempt_Valid attempt /\
           challenges_frame d post key)) /\
       (obs == PD.ChallengeStoreObservation_Lost ==> post == d)) =
  ()

// ── Proof consumption ──────────────────────────────────────────────────────

/// `RecoverProofIo::consume_attempt`: the removed state's own bindings, with
/// `Missing` exactly for an absent slot and `Corrupt` exactly for an
/// undecodable one. Either way the slot is gone afterwards and nothing else
/// changed.
let attempt_consumption_is_honest
      (d: db) (key user attempt: text) (fk: option nat)
  : Lemma
    (match take_attempt d key user attempt fk, d.challenges key with
     | None, _ -> faulted fk 0
     | Some (obs, post), Attempt_Absent ->
       not (faulted fk 0) /\
       obs == PD.AttemptConsumptionObservation_Missing /\
       post == d
     | Some (obs, post), Attempt_Undecodable ->
       not (faulted fk 0) /\
       obs == PD.AttemptConsumptionObservation_Corrupt /\
       post.challenges key == Attempt_Absent /\
       challenges_frame d post key
     | Some (obs, post), Attempt_Valid a ->
       not (faulted fk 0) /\
       obs == PD.AttemptConsumptionObservation_Present
         ({ f_user_matches = (a.f_user = user);
            f_attempt_matches = (a.f_attempt = attempt);
            f_key_epoch = a.f_key_epoch }) /\
       post.challenges key == Attempt_Absent /\
       challenges_frame d post key) =
  ()

// ── Live account read ──────────────────────────────────────────────────────

/// `RecoverProofIo::query_account`: every observation field is the live row's
/// truth. A failed query is unobserved.
let proof_account_is_honest (d: db) (user: text) (fs: option nat)
  : Lemma
    (match proof_account d user fs with
     | None -> faulted fs 0
     | Some obs ->
       not (faulted fs 0) /\
       obs.PD.f_account_present == Some? (d.users user) /\
       obs.PD.f_commitment ==
         (match d.users user with
          | Some row -> row.us_commitment
          | None -> PD.CommitmentObservation_Missing) /\
       obs.PD.f_account_epoch_active ==
         (match d.users user with
          | Some row -> not row.us_rekey
          | None -> false) /\
       obs.PD.f_stored_epoch == row_epoch d user) =
  ()

// ── Grant store ────────────────────────────────────────────────────────────

/// `RecoverProofIo::issue_grant`: `Stored` holds exactly when the store wrote;
/// then exactly the plan's grant is live at its key, and a failed write leaves
/// the state unchanged.
let grant_store_is_honest
      (d: db) (key value: text) (grant: t_EnrollmentGrantView) (ttl: u64)
      (fk: option nat)
  : Lemma
    (let (obs, post) = issue_grant d key value grant ttl fk in
     (obs == PD.GrantStoreObservation_Stored <==> not (faulted fk 0)) /\
     (obs == PD.GrantStoreObservation_Failed <==> faulted fk 0) /\
     (obs == PD.GrantStoreObservation_Stored ==>
        (post.grants key == Some grant /\ grants_frame d post key)) /\
     (obs == PD.GrantStoreObservation_Failed ==> post == d)) =
  ()

// ── Facts the possession drivers rely on ───────────────────────────────────

/// A fresh observation really means the exact slot was empty.
let fresh_observation_is_an_empty_slot
      (d: db) (user key: text) (ttl: u64) (fs fk: option nat)
  : Lemma
    (match initiate_observation d user key ttl fs fk with
     | Some (obs, _) -> obs.PD.f_attempt_id_fresh ==> not (slot_occupied d key)
     | None -> True) =
  initiate_observation_is_honest d user key ttl fs fk

/// A stored challenge is exactly the attempt the plan carried, at its key.
let stored_challenge_is_the_drawn_one
      (d: db) (key value: text) (attempt: t_ProofAttemptView) (ttl: u64)
      (fk: option nat)
  : Lemma
    (match store_challenge d key value attempt ttl fk with
     | Some (PD.ChallengeStoreObservation_Stored, post) ->
       post.challenges key == Attempt_Valid attempt
     | _ -> True) =
  store_challenge_is_honest d key value attempt ttl fk

/// A lost race wrote nothing at all.
let lost_challenge_changed_nothing
      (d: db) (key value: text) (attempt: t_ProofAttemptView) (ttl: u64)
      (fk: option nat)
  : Lemma
    (match store_challenge d key value attempt ttl fk with
     | Some (PD.ChallengeStoreObservation_Lost, post) -> post == d
     | _ -> True) =
  store_challenge_is_honest d key value attempt ttl fk

/// The take removed the slot whether or not its bytes decoded, so a corrupt
/// attempt cannot be replayed.
let consumed_attempt_is_single_use
      (d: db) (key user attempt: text) (fk: option nat)
      (user' attempt' : text) (fk' : option nat)
  : Lemma
    (match take_attempt d key user attempt fk with
     | Some (_, post) ->
       (match take_attempt post key user' attempt' fk' with
        | Some (obs', _) -> obs' == PD.AttemptConsumptionObservation_Missing
        | None -> True)
     | None -> True) =
  attempt_consumption_is_honest d key user attempt fk;
  match take_attempt d key user attempt fk with
  | Some (_, post) -> attempt_consumption_is_honest post key user' attempt' fk'
  | None -> ()

/// A corrupt attempt is reported as corrupt, never as a missing one, even
/// though it was removed.
let corrupt_attempt_is_not_missing
      (d: db) (key user attempt: text) (fk: option nat)
  : Lemma
    (match take_attempt d key user attempt fk with
     | Some (PD.AttemptConsumptionObservation_Missing, _) ->
       d.challenges key == Attempt_Absent
     | Some (PD.AttemptConsumptionObservation_Corrupt, _) ->
       d.challenges key == Attempt_Undecodable
     | _ -> True) =
  attempt_consumption_is_honest d key user attempt fk

/// A stored grant is live at exactly its key with exactly the plan's epoch.
let issued_grant_is_live
      (d: db) (key value: text) (grant: t_EnrollmentGrantView) (ttl: u64)
      (fk: option nat)
  : Lemma
    (let (obs, post) = issue_grant d key value grant ttl fk in
     obs == PD.GrantStoreObservation_Stored ==> post.grants key == Some grant) =
  grant_store_is_honest d key value grant ttl fk

// ── Vectors shared with `redemption_model.rs::shared_possession_vectors` ───

let vector_user : user_row =
  { us_share = true;
    us_commitment = PD.CommitmentObservation_Present { f_len = mk_usize 32 };
    us_epoch = Core_models.Option.Option_Some (mk_i64 7);
    us_rekey = false }

let vector_db : db =
  { users = (fun k -> if k = s "u" then Some vector_user else None);
    challenges = (fun _ -> Attempt_Absent);
    grants = (fun _ -> None) }

let vector_attempt : t_ProofAttemptView =
  { f_user = s "u"; f_attempt = s "a"; f_key_epoch = mk_i64 7 }

let vector_possession_initiate ()
  : Lemma
    (match initiate_observation vector_db (s "u") (s "slot") (mk_u64 300) None None with
     | Some (obs, post) ->
       obs.PD.f_account_present = true /\ obs.PD.f_share_present = true /\
       obs.PD.f_attempt_id_fresh = true /\
       obs.PD.f_commitment == PD.CommitmentObservation_Present { f_len = mk_usize 32 } /\
       post == vector_db
     | None -> False) =
  initiate_observation_is_honest vector_db (s "u") (s "slot") (mk_u64 300) None None

let vector_possession_initiate_absent ()
  : Lemma
    (match initiate_observation vector_db (s "missing") (s "slot") (mk_u64 300) None None with
     | Some (obs, post) ->
       obs.PD.f_account_present = false /\ obs.PD.f_share_present = false /\
       obs.PD.f_commitment == PD.CommitmentObservation_Missing /\
       obs.PD.f_attempt_id_fresh = true /\ post == vector_db
     | None -> False) =
  initiate_observation_is_honest vector_db (s "missing") (s "slot") (mk_u64 300) None None

let vector_possession_epoch ()
  : Lemma (initiate_epoch_of vector_db (s "u") None == mk_i64 7 /\
           initiate_epoch_of vector_db (s "missing") None == mk_i64 1) =
  initiate_epoch_is_honest vector_db (s "u") None;
  initiate_epoch_is_honest vector_db (s "missing") None

let vector_slot_db : db =
  { vector_db with challenges = (fun k -> if k = s "slot" then Attempt_Valid vector_attempt else Attempt_Absent) }

let vector_possession_store ()
  : Lemma
    (match store_challenge vector_db (s "slot") (s "v") vector_attempt (mk_u64 300) None with
     | Some (obs, post) ->
       obs == PD.ChallengeStoreObservation_Stored /\
       post.challenges (s "slot") == Attempt_Valid vector_attempt
     | None -> False) =
  store_challenge_is_honest vector_db (s "slot") (s "v") vector_attempt (mk_u64 300) None

let vector_possession_store_lost ()
  : Lemma
    (match store_challenge vector_slot_db (s "slot") (s "v") vector_attempt (mk_u64 300) None with
     | Some (obs, post) ->
       obs == PD.ChallengeStoreObservation_Lost /\ post == vector_slot_db
     | None -> False) =
  store_challenge_is_honest vector_slot_db (s "slot") (s "v") vector_attempt (mk_u64 300) None

let vector_possession_take ()
  : Lemma
    (match take_attempt vector_slot_db (s "slot") (s "u") (s "a") None with
     | Some (obs, post) ->
       obs == PD.AttemptConsumptionObservation_Present
         ({ f_user_matches = true; f_attempt_matches = true; f_key_epoch = mk_i64 7 }) /\
       post.challenges (s "slot") == Attempt_Absent
     | None -> False) =
  attempt_consumption_is_honest vector_slot_db (s "slot") (s "u") (s "a") None

let vector_possession_take_missing ()
  : Lemma
    (match take_attempt vector_db (s "slot") (s "u") (s "a") None with
     | Some (obs, post) ->
       obs == PD.AttemptConsumptionObservation_Missing /\ post == vector_db
     | None -> False) =
  attempt_consumption_is_honest vector_db (s "slot") (s "u") (s "a") None

let vector_corrupt_db : db =
  { vector_db with challenges = (fun k -> if k = s "slot" then Attempt_Undecodable else Attempt_Absent) }

let vector_possession_take_corrupt ()
  : Lemma
    (match take_attempt vector_corrupt_db (s "slot") (s "u") (s "a") None with
     | Some (obs, post) ->
       obs == PD.AttemptConsumptionObservation_Corrupt /\
       post.challenges (s "slot") == Attempt_Absent
     | None -> False) =
  attempt_consumption_is_honest vector_corrupt_db (s "slot") (s "u") (s "a") None

let vector_possession_account ()
  : Lemma
    (match proof_account vector_db (s "u") None with
     | Some obs ->
       obs.PD.f_account_present = true /\ obs.PD.f_account_epoch_active = true /\
       obs.PD.f_commitment == PD.CommitmentObservation_Present { f_len = mk_usize 32 } /\
       obs.PD.f_stored_epoch == Core_models.Option.Option_Some (mk_i64 7)
     | None -> False) =
  proof_account_is_honest vector_db (s "u") None

let vector_possession_account_absent ()
  : Lemma
    (match proof_account vector_db (s "missing") None with
     | Some obs ->
       obs.PD.f_account_present = false /\ obs.PD.f_account_epoch_active = false
     | None -> False) =
  proof_account_is_honest vector_db (s "missing") None

let vector_grant : t_EnrollmentGrantView = { f_key_epoch = mk_i64 7 }

let vector_possession_grant ()
  : Lemma
    (let (obs, post) =
       issue_grant vector_db (s "g") (s "v") vector_grant (mk_u64 600) None in
     obs == PD.GrantStoreObservation_Stored /\ post.grants (s "g") == Some vector_grant) =
  grant_store_is_honest vector_db (s "g") (s "v") vector_grant (mk_u64 600) None

let vector_possession_grant_failed ()
  : Lemma
    (let (obs, post) =
       issue_grant vector_db (s "g") (s "v") vector_grant (mk_u64 600) (Some 0) in
     obs == PD.GrantStoreObservation_Failed /\ post == vector_db) =
  grant_store_is_honest vector_db (s "g") (s "v") vector_grant (mk_u64 600) (Some 0)

#pop-options
