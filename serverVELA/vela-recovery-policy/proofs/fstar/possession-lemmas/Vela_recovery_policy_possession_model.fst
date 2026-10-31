module Vela_recovery_policy_possession_model

/// A model of the `users` row, the single-use proof-attempt slots and the
/// enrollment-grant store the possession-proof executors touch, and of how
/// their statement plans run on them (F-1).
///
/// - `users` is keyed by its `UNIQUE` id; a row stores whether the recovery
///   share is present, the decoded commitment cell, the stored epoch and the
///   rotation flag. A commitment cell is absent, a decoded length, or
///   present-but-undecodable, exactly as the handler's row view reports it.
/// - the challenge store maps the exact user/attempt key to a decoded
///   [`stored_attempt`] or to bytes that do not decode; a missing key is
///   `Attempt_Absent`. `set_ex_nx` is first-writer-wins, and `get_del` is an
///   atomic read-and-delete that removes an undecodable value too.
/// - the grant store maps the exact enrollment-grant key to the typed grant the
///   plan carries. `set_ex` overwrites.
/// - `fs = Some k` makes the k-th SQL statement fail; `fk = Some k` makes the
///   k-th store operation fail.
///
/// What this module trusts, and `vela-server/src/recovery/conformance.rs`
/// checks against a real database and store: these statement meanings,
/// statement atomicity, the rendering of each statement, base64/JSON decoding
/// into views, and the store's first-writer-wins and read-and-delete
/// implementations. Time-to-live expiry is a scheduler choice, not modelled.
///
/// The executor models below are the server's thin method: plan (extracted),
/// run, classify (extracted). `vela-recovery-policy/src/redemption_model.rs`
/// mirrors this module function for function; its `shared_possession_vectors`
/// test and the `vector_possession_*` lemmas check the same concrete runs.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Possession_store

module PD = Vela_recovery_policy.Possession_driver

type text = Alloc.String.t_String

/// One decoded proof-attempt envelope, of the plan's own type, so a change to
/// what the plan stores changes the model with it.
type stored_attempt = t_ProofAttemptView

/// The outcome of one read: its first row, or an error. This is the same
/// shape as `redemption_store::ReadOutcome`, restated here so this module
/// needs no shared read type.
noeq type read_outcome (a: Type) =
  | Row : Core_models.Option.t_Option a -> read_outcome a
  | Failed : read_outcome a

/// A challenge-slot value: absent, decodable, or present-but-undecodable.
noeq type attempt_cell =
  | Attempt_Absent : attempt_cell
  | Attempt_Valid : stored_attempt -> attempt_cell
  | Attempt_Undecodable : attempt_cell

/// The modelled columns of a `users` row for the possession executors.
noeq type user_row = {
  us_share: bool;
  us_commitment: PD.t_CommitmentObservation;
  us_epoch: Core_models.Option.t_Option i64;
  us_rekey: bool;
}

noeq type db = {
  users: text -> option user_row;
  challenges: text -> attempt_cell;
  grants: text -> option t_EnrollmentGrantView;
}

/// Whether the exact proof-slot key is occupied.
let slot_occupied (d: db) (key: text) : bool =
  match d.challenges key with
  | Attempt_Absent -> false
  | _ -> true

/// Replace one challenge slot.
let upd_cell (d: db) (key: text) (cell: attempt_cell) : db =
  { d with challenges = (fun k -> if k = key then cell else d.challenges k) }

/// Replace one grant.
let upd_grant (d: db) (key: text) (grant: t_EnrollmentGrantView) : db =
  { d with grants = (fun k -> if k = key then Some grant else d.grants k) }

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

// ── Reads ──────────────────────────────────────────────────────────────────

/// `InitiateProofIo::observe`'s account read.
let read_initiate_account (d: db) (user: text) (fs: option nat)
  : read_outcome t_InitiateRowView =
  match plan_initiate_account user with
  | PossessionStmt_SelectInitiateAccount { f_user = u } ->
    if faulted fs 0
    then Failed
    else
      (match d.users u with
       | None -> Row Core_models.Option.Option_None
       | Some row ->
         Row
           (Core_models.Option.Option_Some
             ({ f_share_present = row.us_share;
                f_commitment = row.us_commitment;
                f_key_epoch = row.us_epoch;
                f_rotation_active = row.us_rekey } <: t_InitiateRowView)))
  | _ -> Failed

/// `InitiateProofIo::observe`'s exact-slot probe. `true` means occupied.
let probe_slot (d: db) (key: text) (fk: option nat) : read_outcome bool =
  match plan_proof_slot key with
  | PossessionStmt_ProofSlotExists { f_key = k } ->
    if faulted fk 0
    then Failed
    else Row (Core_models.Option.Option_Some (slot_occupied d k))
  | _ -> Failed

/// The row's stored epoch, or `None` when the row or column is absent.
let row_epoch (d: db) (user: text) : Core_models.Option.t_Option i64 =
  match d.users user with
  | Some row -> row.us_epoch
  | None -> Core_models.Option.Option_None

// ── The executors: plan, run, classify ─────────────────────────────────────

/// `InitiateProofIo::observe`.
let initiate_observation (d: db) (user key: text) (ttl: u64) (fs fk: option nat)
  : option (PD.t_InitiateObservation & db) =
  match read_initiate_account d user fs with
  | Failed -> None
  | Row row ->
    (match probe_slot d key fk with
     | Row (Core_models.Option.Option_Some occupied) ->
       Some (classify_initiate row occupied ttl, d)
     | _ -> None)

/// `InitiateProofIo::observe`'s epoch side channel.
let initiate_epoch_of (d: db) (user: text) (fs: option nat) : i64 =
  match read_initiate_account d user fs with
  | Row row -> initiate_epoch row
  | Failed -> initiate_epoch Core_models.Option.Option_None

/// `InitiateProofIo::store_challenge`.
let store_challenge
      (d: db) (key value: text) (attempt: t_ProofAttemptView) (ttl: u64)
      (fk: option nat)
  : option (PD.t_ChallengeStoreObservation & db) =
  match plan_store_challenge key value attempt ttl with
  | PossessionStmt_StoreProofChallenge
      { f_key = k; f_value = _v; f_attempt = a; f_ttl_secs = _t } ->
    if faulted fk 0
    then None
    else if slot_occupied d k
    then Some (classify_store_challenge false, d)
    else Some (classify_store_challenge true, upd_cell d k (Attempt_Valid a))
  | _ -> None

/// `RecoverProofIo::consume_attempt`.
let take_attempt (d: db) (key user attempt: text) (fk: option nat)
  : option (PD.t_AttemptConsumptionObservation & db) =
  match plan_take_attempt key with
  | PossessionStmt_TakeProofAttempt { f_key = k } ->
    if faulted fk 0
    then None
    else
      let cell = d.challenges k in
      let taken =
        match cell with
        | Attempt_Absent -> ProofAttemptTake_Missing
        | Attempt_Undecodable -> ProofAttemptTake_Corrupt
        | Attempt_Valid a -> ProofAttemptTake_Present a
      in
      Some (classify_attempt taken user attempt,
            (match cell with
             | Attempt_Absent -> d
             | _ -> upd_cell d k Attempt_Absent))
  | _ -> None

/// `RecoverProofIo::query_account`.
let proof_account (d: db) (user: text) (fs: option nat)
  : option PD.t_ProofAccountObservation =
  match plan_proof_account user with
  | PossessionStmt_SelectProofAccount { f_user = u } ->
    if faulted fs 0
    then None
    else
      let row =
        match d.users u with
        | None -> Core_models.Option.Option_None
        | Some row ->
          Core_models.Option.Option_Some
            ({ f_commitment = row.us_commitment;
               f_stored_epoch = row.us_epoch;
               f_rotation_active = row.us_rekey } <: t_ProofAccountRowView)
      in
      Some (classify_proof_account row)
  | _ -> None

/// `RecoverProofIo::issue_grant`. A store failure is an observation, not an
/// abort, exactly as the handler reports it.
let issue_grant
      (d: db) (key value: text) (grant: t_EnrollmentGrantView) (ttl: u64)
      (fk: option nat)
  : (PD.t_GrantStoreObservation & db) =
  match plan_issue_grant key value grant ttl with
  | PossessionStmt_PutEnrollmentGrant
      { f_key = k; f_value = _v; f_grant = g; f_ttl_secs = _t } ->
    if faulted fk 0
    then (classify_grant_store false, d)
    else (classify_grant_store true, upd_grant d k g)
  | _ -> (classify_grant_store false, d)
