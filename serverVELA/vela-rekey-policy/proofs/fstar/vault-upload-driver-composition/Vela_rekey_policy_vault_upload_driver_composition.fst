module Vela_rekey_policy_vault_upload_driver_composition

/// Concurrent composition of the *extracted* vault chunk upload driver
/// (`Vela_rekey_policy.Vault_upload_driver`) with a shared account table and a
/// shared chunk store. One account key state is shared by any number of
/// requests, each running its own `UploadDriver`. A schedule is an arbitrary
/// list of actions: spawn a device or web-session request, deliver the next
/// observation, start/commit/abort a rotation, or perform the guarded SQL
/// write for a request that reached the `Write` stage.
///
/// The world abstracts the observations the handler obtains:
///
/// - `Resolve` feeds the current account epoch/phase; the driver re-applies the
///   extracted `resolve_write_epoch`;
/// - `Attempt` derives the shadow authority facts from the request's claimed
///   rotation id, the writer identity and the live account row;
/// - quota, read-back, activity and publication observations are delivered
///   next;
/// - `GuardedWrite` models the guarded `INSERT`/`UPDATE` from
///   `vela-server/src/vault/chunk.rs` as one atomic, linearizable statement. It
///   evaluates the SQL guard against the *live* shared account row (not the
///   permit's captured copy) with the permit the driver emitted and the
///   request's writer, mutates the store, and delivers the resulting
///   `Inserted`/`Updated`/`Existing`/`Skipped` value back to the driver as its
///   `WriteObservation`.
///
/// The guarded statement is modelled exactly as written:
///
/// - active create: `SELECT ... FROM users WHERE id = ? AND key_epoch = ?
///   AND rekey_state IS NULL`, after a `SELECT 1 FROM vault_chunks` pre-check
///   that maps a present row to `Existing`;
/// - active update: `UPDATE ... WHERE chunk_id = ? AND user_id = ? AND
///   epoch = ? AND EXISTS (SELECT 1 FROM users WHERE users.key_epoch = ?
///   AND users.rekey_state IS NULL)`;
/// - shadow upsert: `INSERT ... SELECT ... FROM users WHERE id = ? AND
///   key_epoch = ? AND rekey_state = 'freezing' AND rekey_starter = ?
///   AND rekey_id = ?`, writing the permit's `write_epoch`.
///
/// The row-version conjunct of the update (`version = ?`) is modelled as the
/// presence of the row at the permit's write epoch: ignoring a version check
/// can only make the guard accept more writes, never fewer, so it cannot hide a
/// bad commit.
///
/// Theorem (`upload_store_theorem`): for every schedule,
///
/// - no active (non-shadow) chunk row is committed while the live account row
///   is not ACTIVE or at an epoch other than the row's epoch
///   (`w_stale_commit = 0`, counted at the commit step from the world's real
///   account state);
/// - no shadow row is committed unless the live account is FREEZING, the row
///   epoch is `next(live epoch)`, the writer is the rotation's starting device
///   with the matching rotation id, and the writer is not a web session
///   (`w_bad_shadow_commit = 0`);
/// - a success response is only produced by a request whose own guarded write
///   actually committed (`w_success_without_commit = 0`);
/// - the round-1 driver-level counters stay zero (`w_stale_active = 0`,
///   `w_web_shadow = 0`) and every live request remains sound.
///
/// Assumptions (not proved here): the SQL `vault_chunks` and `users` statements
/// are linearizable, the handler performs exactly the effect the driver returns
/// in the same step as its observation, devices are not transferred between
/// accounts, and the driver's observations originate from the world
/// construction below. Quota accounting, ciphertext storage, durability,
/// clock monotonicity (the server does not enforce it) and multi-node
/// replication remain outside this module. Commit's shadow sweep and abort's
/// cleanup are not modelled: they only remove rows, so they cannot create a
/// commit.

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Vault_upload_driver
open Vela_rekey_policy_vault_upload_driver_lemmas

// ── Generic list helpers ───────────────────────────────────────────────────

let rec update (#a: Type) (l: list a) (i: nat) (x: a) : Tot (list a) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec update_length (#a: Type) (l: list a) (i: nat) (x: a)
  : Lemma (ensures (FStar.List.Tot.length (update l i x) = FStar.List.Tot.length l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_length t (i - 1) x

// ── World model ────────────────────────────────────────────────────────────

/// The shared `users` row of one account. `a_epoch` is `key_epoch`, which does
/// not move during a rotation; `a_phase` is `rekey_state IS NULL` versus
/// `'freezing'`; `a_rid` is the current `rekey_id` (zero when absent);
/// `a_starter` is `rekey_starter`.
noeq type account = {
  a_epoch: i64;
  a_phase: t_Phase;
  a_rid: nat;
  a_starter: nat;
}

/// The authenticated writer and the chunk it targets.
noeq type writer = {
  wr_account: nat;
  wr_device: nat;
  wr_web: bool;
}

noeq type chunk_row = {
  cr_account: nat;
  cr_chunk: nat;
  cr_epoch: i64;
}

noeq type request = {
  rq_writer: writer;
  rq_chunk: nat;
  /// The `X-Vela-Rekey-Id` the client claims (zero when absent).
  rq_rotation_id: nat;
  rq_driver: t_UploadDriver;
  /// The permit emitted by the driver's `Write` effect, consumed by the
  /// guarded statement. `None` before quota admission and after the write.
  rq_permit: Core_models.Option.t_Option t_UploadWritePermit;
  /// Whether this request's own guarded statement committed a row.
  rq_committed: bool;
}

noeq type vworld = {
  w_accounts: list account;
  w_reqs: list request;
  w_store: list chunk_row;
  w_rid: nat;
  /// Driver authorizations of an active write whose captured route was stale.
  w_stale_active: nat;
  /// Driver authorizations of a shadow write by a web session.
  w_web_shadow: nat;
  /// Commits of an active row at an epoch other than the live one, or while
  /// the live account row was not ACTIVE.
  w_stale_commit: nat;
  /// Commits of a shadow row that was not an authorized rotation shadow.
  w_bad_shadow_commit: nat;
  /// Success responses produced by a request whose write did not commit.
  w_success_without_commit: nat;
}

let account_at (w: vworld) (i: nat) : account =
  if i < FStar.List.Tot.length w.w_accounts
  then FStar.List.Tot.index w.w_accounts i
  else { a_epoch = mk_i64 1; a_phase = Phase_Active; a_rid = 0; a_starter = 0 }

let set_account (w: vworld) (i: nat) (a: account) : vworld =
  if i < FStar.List.Tot.length w.w_accounts
  then { w with w_accounts = update w.w_accounts i a }
  else w

let set_account_length (w: vworld) (i: nat) (a: account)
  : Lemma (FStar.List.Tot.length (set_account w i a).w_accounts
           = FStar.List.Tot.length w.w_accounts) =
  if i < FStar.List.Tot.length w.w_accounts then update_length w.w_accounts i a else ()

/// A rotation id is only meaningful when non-zero; a freezing account always
/// carries one, so `rekey_id = ''` (the SQL default for an absent header)
/// never matches.
let account_ok (a: account) : bool =
  imp (a.a_phase = Phase_Freezing) (a.a_rid > 0)

let rec accounts_ok (l: list account) : bool =
  match l with
  | [] -> true
  | h :: t -> account_ok h && accounts_ok t

let rec accounts_ok_index (l: list account) (i: nat)
  : Lemma
    (requires (accounts_ok l /\ i < FStar.List.Tot.length l))
    (ensures (account_ok (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else accounts_ok_index t (i - 1)

let rec accounts_ok_update (l: list account) (i: nat) (a: account)
  : Lemma
    (requires (accounts_ok l /\ account_ok a))
    (ensures (accounts_ok (update l i a)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else accounts_ok_update t (i - 1) a

// ── The shared chunk store ─────────────────────────────────────────────────

let same_slot (h: chunk_row) (acct: nat) (chunk: nat) (epoch: i64) : bool =
  h.cr_account = acct && h.cr_chunk = chunk && h.cr_epoch = epoch

let rec store_has (l: list chunk_row) (acct: nat) (chunk: nat) (epoch: i64) : bool =
  match l with
  | [] -> false
  | h :: t -> if same_slot h acct chunk epoch then true else store_has t acct chunk epoch

/// `INSERT ... ON CONFLICT(user_id, chunk_id, epoch) DO UPDATE`: replace the
/// row in the same slot, or append it.
let rec store_put (l: list chunk_row) (r: chunk_row) : list chunk_row =
  match l with
  | [] -> [r]
  | h :: t ->
      if same_slot h r.cr_account r.cr_chunk r.cr_epoch
      then r :: t
      else h :: store_put t r

let row_ok (r: chunk_row) : bool = r.cr_account < 2

let rec rows_ok (l: list chunk_row) : bool =
  match l with
  | [] -> true
  | h :: t -> row_ok h && rows_ok t

let rec rows_ok_put (l: list chunk_row) (r: chunk_row)
  : Lemma
    (requires (rows_ok l /\ row_ok r))
    (ensures (rows_ok (store_put l r)))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t ->
      if same_slot h r.cr_account r.cr_chunk r.cr_epoch
      then ()
      else rows_ok_put t r

// ── Requests ───────────────────────────────────────────────────────────────

/// The route fields of the stored permit are those of the driver that emitted
/// it. The driver can only change stage between emitting the permit (quota
/// admission) and performing the guarded write, so this survives every step.
let permit_matches_driver (p: t_UploadWritePermit) (d: t_UploadDriver) : bool =
  p.f_write_epoch = d.f_write_epoch &&
  p.f_read_epoch = d.f_read_epoch &&
  p.f_permit_epoch = d.f_permit_epoch &&
  p.f_shadow = d.f_shadow &&
  p.f_web = d.f_web

let permit_agrees (r: request) : bool =
  match r.rq_permit <: Core_models.Option.t_Option t_UploadWritePermit with
  | Core_models.Option.Option_None -> true
  | Core_models.Option.Option_Some p ->
      is_write r.rq_driver && permit_matches_driver p r.rq_driver

/// Per-request invariant: the driver trace is sound, a stored permit belongs to
/// the driver's current write route, and a matched write always has a commit
/// behind it.
let request_ok (r: request) : bool =
  trace_sound r.rq_driver &&
  permit_agrees r &&
  imp r.rq_driver.f_write_matched r.rq_committed

let rec all_requests_ok (l: list request) : bool =
  match l with
  | [] -> true
  | r :: rest -> request_ok r && all_requests_ok rest

let rec all_requests_ok_index (l: list request) (i: nat)
  : Lemma
    (requires (all_requests_ok l /\ i < FStar.List.Tot.length l))
    (ensures (request_ok (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else all_requests_ok_index t (i - 1)

let rec all_requests_ok_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (all_requests_ok l /\ request_ok r))
    (ensures (all_requests_ok (update l i r)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_requests_ok_update t (i - 1) r

let rec all_requests_ok_cons (r: request) (l: list request)
  : Lemma (all_requests_ok (r :: l) = (request_ok r && all_requests_ok l)) = ()

/// Every request was spawned for one of the two modelled accounts.
let rec requests_in_range (l: list request) : bool =
  match l with
  | [] -> true
  | r :: rest -> r.rq_writer.wr_account < 2 && requests_in_range rest

let rec requests_in_range_index (l: list request) (i: nat)
  : Lemma
    (requires (requests_in_range l /\ i < FStar.List.Tot.length l))
    (ensures ((FStar.List.Tot.index l i).rq_writer.wr_account < 2))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else requests_in_range_index t (i - 1)

let rec requests_in_range_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (requests_in_range l /\ r.rq_writer.wr_account < 2))
    (ensures (requests_in_range (update l i r)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else requests_in_range_update t (i - 1) r

let rec requests_in_range_cons (r: request) (l: list request)
  : Lemma (requests_in_range (r :: l) = (r.rq_writer.wr_account < 2 && requests_in_range l)) = ()

/// The shared invariant.
let inv (w: vworld) : prop =
  FStar.List.Tot.length w.w_accounts = 2 /\
  accounts_ok w.w_accounts /\
  all_requests_ok w.w_reqs /\
  requests_in_range w.w_reqs /\
  rows_ok w.w_store /\
  w.w_stale_active = 0 /\
  w.w_web_shadow = 0 /\
  w.w_stale_commit = 0 /\
  w.w_bad_shadow_commit = 0 /\
  w.w_success_without_commit = 0

// ── The guarded SQL statement ─────────────────────────────────────────────

/// `WHERE users.id = ? AND users.key_epoch = permit.permit_epoch AND
/// users.rekey_state IS NULL`.
let sql_active_guard (a: account) (p: t_UploadWritePermit) : bool =
  a.a_epoch = p.f_permit_epoch && a.a_phase = Phase_Active

/// `WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
/// AND rekey_starter = ? AND rekey_id = ?` with the read epoch, the writer's
/// device and the request's rotation id as parameters. A freezing account's
/// `rekey_id` is a fresh non-empty value, so the absent-header default (`''`,
/// modelled as id zero) never matches; hence the explicit `rid > 0`.
let sql_shadow_guard (a: account) (wr: writer) (rid: nat) (p: t_UploadWritePermit) : bool =
  rid > 0 &&
  a.a_epoch = p.f_read_epoch &&
  a.a_phase = Phase_Freezing &&
  a.a_starter = wr.wr_device &&
  a.a_rid = rid

/// A committed active row is acceptable only at the live epoch of an ACTIVE
/// account.
let active_row_ok (a: account) (p: t_UploadWritePermit) : bool =
  a.a_phase = Phase_Active && p.f_write_epoch = a.a_epoch

/// A committed shadow row is acceptable only when it is the next epoch of a
/// FREEZING account, written by the device that started that rotation with the
/// matching (non-empty) rotation id, and the writer is not a web session.
let shadow_row_ok (a: account) (wr: writer) (rid: nat) (p: t_UploadWritePermit) : bool =
  rid > 0 &&
  a.a_phase = Phase_Freezing &&
  (Vela_rekey_policy.next_epoch a.a_epoch <: Core_models.Option.t_Option i64) =
    (Core_models.Option.Option_Some p.f_write_epoch <: Core_models.Option.t_Option i64) &&
  a.a_starter = wr.wr_device &&
  a.a_rid = rid &&
  not p.f_web

noeq type write_outcome = {
  wo_obs: t_WriteObservation;
  wo_store: list chunk_row;
}

let committed_obs (o: t_WriteObservation) : bool =
  match o <: t_WriteObservation with
  | WriteObservation_Inserted -> true
  | WriteObservation_Updated -> true
  | _ -> false

let written_row (wr: writer) (chunk: nat) (p: t_UploadWritePermit) : chunk_row =
  { cr_account = wr.wr_account; cr_chunk = chunk; cr_epoch = p.f_write_epoch }

/// The commit-step counter for a bad active row.
let stale_commit_increment (a: account) (p: t_UploadWritePermit)
                            (obs: t_WriteObservation) : nat =
  if committed_obs obs && not p.f_shadow && not (active_row_ok a p) then 1 else 0

/// The commit-step counter for a bad shadow row.
let bad_shadow_increment (a: account) (wr: writer) (rid: nat)
                         (p: t_UploadWritePermit) (obs: t_WriteObservation) : nat =
  if committed_obs obs && p.f_shadow &&
     not (shadow_row_ok a wr rid p)
  then 1 else 0

let sql_write
      (store: list chunk_row)
      (a: account)
      (wr: writer)
      (chunk: nat)
      (rid: nat)
      (intent: t_WriteIntent)
      (p: t_UploadWritePermit)
  : write_outcome =
  if p.f_shadow
  then
    if sql_shadow_guard a wr rid p
    then { wo_obs = WriteObservation_Inserted;
           wo_store = store_put store (written_row wr chunk p) }
    else { wo_obs = WriteObservation_Skipped; wo_store = store }
  else
    match intent <: t_WriteIntent with
    | WriteIntent_Create ->
        if store_has store wr.wr_account chunk p.f_write_epoch
        then { wo_obs = WriteObservation_Existing; wo_store = store }
        else if sql_active_guard a p
        then { wo_obs = WriteObservation_Inserted;
               wo_store = store_put store (written_row wr chunk p) }
        else { wo_obs = WriteObservation_Skipped; wo_store = store }
    | WriteIntent_Replace _ ->
        if store_has store wr.wr_account chunk p.f_write_epoch && sql_active_guard a p
        then { wo_obs = WriteObservation_Updated;
               wo_store = store_put store (written_row wr chunk p) }
        else { wo_obs = WriteObservation_Skipped; wo_store = store }

/// A committed statement is one whose guard passed.
let sql_write_committed_guard
      (store: list chunk_row) (a: account) (wr: writer) (chunk: nat)
      (rid: nat) (intent: t_WriteIntent) (p: t_UploadWritePermit)
  : Lemma
    (requires (committed_obs (sql_write store a wr chunk rid intent p).wo_obs))
    (ensures (if p.f_shadow then sql_shadow_guard a wr rid p else sql_active_guard a p)) =
  if p.f_shadow
  then ()
  else
    match intent <: t_WriteIntent with
    | WriteIntent_Create -> ()
    | WriteIntent_Replace _ -> ()

let sql_write_rows_ok
      (store: list chunk_row) (a: account) (wr: writer) (chunk: nat)
      (rid: nat) (intent: t_WriteIntent) (p: t_UploadWritePermit)
  : Lemma
    (requires (rows_ok store /\ row_ok (written_row wr chunk p)))
    (ensures (rows_ok (sql_write store a wr chunk rid intent p).wo_store)) =
  if p.f_shadow
  then (if sql_shadow_guard a wr rid p then rows_ok_put store (written_row wr chunk p) else ())
  else
    match intent <: t_WriteIntent with
    | WriteIntent_Create ->
        if store_has store wr.wr_account chunk p.f_write_epoch
        then ()
        else if sql_active_guard a p
        then rows_ok_put store (written_row wr chunk p)
        else ()
    | WriteIntent_Replace _ ->
        if store_has store wr.wr_account chunk p.f_write_epoch && sql_active_guard a p
        then rows_ok_put store (written_row wr chunk p)
        else ()

// ── Commit soundness: the load-bearing guard facts ────────────────────────

let is_write_stage (d: t_UploadDriver)
  : Lemma (requires (is_write d)) (ensures (d.f_stage = UploadStage_Write)) = ()

let route_active_of_not_shadow (d: t_UploadDriver)
  : Lemma
    (requires (route_clean d /\ not d.f_shadow))
    (ensures (active_route d)) =
  assert (not (shadow_route d))

let route_shadow_of_shadow (d: t_UploadDriver)
  : Lemma
    (requires (route_clean d /\ d.f_shadow))
    (ensures (shadow_route d)) =
  assert (not (active_route d))

/// An active guarded statement that commits lands at the live epoch of an
/// ACTIVE account. This is the implication the active-commit counter relies on;
/// dropping the `key_epoch` parameter from the modelled guard breaks it.
let active_guard_commit_ok
      (a: account) (d: t_UploadDriver) (p: t_UploadWritePermit)
  : Lemma
    (requires (
      sql_active_guard a p /\
      trace_sound d /\ is_write d /\
      permit_matches_driver p d /\
      not p.f_shadow))
    (ensures (active_row_ok a p)) =
  assert (not d.f_shadow);
  assert (route_clean d);
  route_active_of_not_shadow d;
  assert (active_route d);
  assert (d.f_state_phase = Phase_Active);
  assert (d.f_write_epoch = d.f_state_epoch);
  assert (p.f_write_epoch = d.f_state_epoch);
  assert (a.a_epoch = p.f_permit_epoch);
  assert (p.f_permit_epoch = d.f_permit_epoch);
  assert (p.f_write_epoch = a.a_epoch);
  assert (a.a_phase = Phase_Active)

/// A shadow guarded statement that commits lands at `next(live epoch)` for the
/// FREEZING rotation the writer started, and never for a web session. Dropping
/// the starter/rotation-id checks from the guard or sending `read_epoch` as the
/// row epoch breaks it.
let shadow_guard_commit_ok
      (a: account) (wr: writer) (rid: nat) (d: t_UploadDriver)
      (p: t_UploadWritePermit)
  : Lemma
    (requires (
      sql_shadow_guard a wr rid p /\
      trace_sound d /\ is_write d /\
      permit_matches_driver p d /\
      p.f_shadow))
    (ensures (shadow_row_ok a wr rid p)) =
  is_write_stage d;
  assert (not d.f_failed);
  assert (route_clean d);
  route_shadow_of_shadow d;
  assert (shadow_route d);
  assert (d.f_state_phase = Phase_Freezing);
  assert (d.f_read_epoch = d.f_state_epoch);
  assert ((Vela_rekey_policy.next_epoch d.f_state_epoch <: Core_models.Option.t_Option i64)
          = (Core_models.Option.Option_Some d.f_write_epoch
             <: Core_models.Option.t_Option i64));
  assert (not d.f_web);
  assert (a.a_epoch = p.f_read_epoch);
  assert (p.f_read_epoch = d.f_read_epoch);
  assert (a.a_epoch = d.f_state_epoch);
  assert ((Vela_rekey_policy.next_epoch a.a_epoch <: Core_models.Option.t_Option i64)
          = (Core_models.Option.Option_Some p.f_write_epoch
             <: Core_models.Option.t_Option i64));
  assert (a.a_phase = Phase_Freezing);
  assert (not p.f_web)

/// A committed active statement satisfies the world-state active-row counter.
let stale_commit_increment_zero
      (a: account) (wr: writer) (chunk: nat) (rid: nat)
      (d: t_UploadDriver) (intent: t_WriteIntent) (p: t_UploadWritePermit)
      (store: list chunk_row)
  : Lemma
    (requires (trace_sound d /\ is_write d /\ permit_matches_driver p d))
    (ensures (
      stale_commit_increment a p
        (sql_write store a wr chunk rid intent p).wo_obs = 0)) =
  if committed_obs (sql_write store a wr chunk rid intent p).wo_obs
  then begin
    sql_write_committed_guard store a wr chunk rid intent p;
    if p.f_shadow then () else active_guard_commit_ok a d p
  end

/// A committed shadow statement satisfies the world-state shadow-row counter.
let bad_shadow_increment_zero
      (a: account) (wr: writer) (chunk: nat) (rid: nat)
      (d: t_UploadDriver) (intent: t_WriteIntent) (p: t_UploadWritePermit)
      (store: list chunk_row)
  : Lemma
    (requires (trace_sound d /\ is_write d /\ permit_matches_driver p d))
    (ensures (
      bad_shadow_increment a wr rid p
        (sql_write store a wr chunk rid intent p).wo_obs = 0)) =
  if committed_obs (sql_write store a wr chunk rid intent p).wo_obs
  then begin
    sql_write_committed_guard store a wr chunk rid intent p;
    if p.f_shadow
    then shadow_guard_commit_ok a wr rid d p
    else ()
  end

// ── Driver observation helpers ────────────────────────────────────────────

let declared_of (a: account) : Core_models.Option.t_Option i64 =
  match a.a_phase <: t_Phase with
  | Phase_Active -> Core_models.Option.Option_Some a.a_epoch
  | Phase_Freezing -> Vela_rekey_policy.next_epoch a.a_epoch

let rekey_observation (w: vworld) (account: nat) : t_RekeyObservation =
  let a = account_at w account in
  RekeyObservation_State { f_epoch = a.a_epoch; f_phase = a.a_phase }

let attempt_observation (w: vworld) (wr: writer) (rid: nat) : t_AttemptAuthority =
  let a = account_at w wr.wr_account in
  { f_device_scope = not wr.wr_web;
    f_starter_matches = wr.wr_device = a.a_starter;
    f_rotation_id_present = rid > 0;
    f_rotation_id_matches = a.a_rid = rid }

let write_permit_of (e: t_UploadEffect) : Core_models.Option.t_Option t_UploadWritePermit =
  match e <: t_UploadEffect with
  | UploadEffect_Write p -> Core_models.Option.Option_Some p
  | _ -> Core_models.Option.Option_None

let is_write_event (e: t_UploadEvent) : bool =
  match e <: t_UploadEvent with
  | UploadEvent_Write _ -> true
  | _ -> false

/// A request that is waiting for its guarded write keeps its permit; any other
/// event delivered to that stage is inert (the handler never invents a
/// `Write` event: it performs the guarded statement with the stored permit).
let write_stage_inert (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (d.f_stage = UploadStage_Write /\ not (is_write_event e)))
    (ensures ((upload_step d e).f_driver = d)) =
  match e <: t_UploadEvent with
  | UploadEvent_Rekey _ -> ()
  | UploadEvent_Attempt _ -> ()
  | UploadEvent_AttemptStorage -> ()
  | UploadEvent_Quota _ -> ()
  | UploadEvent_Write _ -> ()
  | UploadEvent_Recheck _ -> ()
  | UploadEvent_Reread _ -> ()
  | UploadEvent_Activity _ -> ()
  | UploadEvent_Published -> ()

/// A non-write event never changes the writer class or the matched-write bit.
let nonwrite_step_matched (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (not (is_write_event e)))
    (ensures (
      (upload_step d e).f_driver.f_write_matched = d.f_write_matched /\
      (upload_step d e).f_driver.f_web = d.f_web)) =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Resolve ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Shadow ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Quota ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Write ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Recheck ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Reread ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Activity ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Publish ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())
  | UploadStage_Done ->
      (match e <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | UploadEvent_Quota _ -> ()
       | UploadEvent_Write _ -> ()
       | UploadEvent_Recheck _ -> ()
       | UploadEvent_Reread _ -> ()
       | UploadEvent_Activity _ -> ()
       | UploadEvent_Published -> ())

/// A `Write` effect's permit names the post-step driver's route exactly.
let write_effect_permit_matches (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (upload_step d e).f_effect <: t_UploadEffect with
      | UploadEffect_Write p ->
          is_write (upload_step d e).f_driver /\
          permit_matches_driver p (upload_step d e).f_driver
      | _ -> True)) =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Quota ->
      (match e <: t_UploadEvent with
       | UploadEvent_Quota (QuotaObservation_Allowed) -> ()
       | _ -> ())
  | _ -> ()

/// The guarded write is the only event that flips the matched-write bit, and it
/// flips it exactly when the delivered observation was a commit.
let on_write_matched (d: t_UploadDriver) (o: t_WriteObservation)
  : Lemma
    (requires (is_write d /\ not d.f_write_matched))
    (ensures (
      (upload_step d (UploadEvent_Write o)).f_driver.f_write_matched
      = committed_obs o)) =
  match o <: t_WriteObservation with
  | WriteObservation_Inserted -> ()
  | WriteObservation_Updated -> ()
  | WriteObservation_Existing -> ()
  | WriteObservation_Skipped -> ()
  | WriteObservation_Duplicate -> ()
  | WriteObservation_Failed -> ()

/// The round-1 driver-level facts: an active `Write` effect carries an ACTIVE
/// route at the captured epoch, and a shadow `Write` effect is never a web
/// session.
let write_effect_stale_active (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (upload_step d e).f_effect <: t_UploadEffect with
      | UploadEffect_Write p ->
          (not p.f_shadow) ==>
            (p.f_state_phase = Phase_Active /\
             p.f_write_epoch = p.f_state_epoch)
      | _ -> True)) =
  write_effect_route d e

let write_effect_not_web (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (upload_step d e).f_effect <: t_UploadEffect with
      | UploadEffect_Write p -> (p.f_shadow ==> not p.f_web)
      | _ -> True)) =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Quota ->
      (match e <: t_UploadEvent with
       | UploadEvent_Quota QuotaObservation_Allowed -> ()
       | _ -> ())
  | _ -> ()

// ── The world step ────────────────────────────────────────────────────────

type action =
  | Spawn : nat -> bool -> nat -> nat -> nat -> action
  | Resolve : nat -> action
  | Attempt : nat -> action
  | Quota : nat -> t_QuotaObservation -> action
  | GuardedWrite : nat -> action
  | Reread : nat -> t_RereadObservation -> action
  | Activity : nat -> t_ActivityObservation -> action
  | Publish : nat -> action
  | RekeyStart : nat -> nat -> action
  | RekeyCommit : nat -> action
  | RekeyAbort : nat -> action

/// Deliver one driver event and account for the round-1 driver counters and
/// the success-without-commit counter. The guarded write itself is a separate
/// action: it is the only source of `Write` events.
let deliver_upload (w: vworld) (i: nat) (e: t_UploadEvent) : vworld =
  if i < FStar.List.Tot.length w.w_reqs
  then
    let r = FStar.List.Tot.index w.w_reqs i in
    if trace_sound r.rq_driver
    then
      let t = upload_step r.rq_driver e in
      let w1 = { w with
                 w_reqs = update w.w_reqs i
                   { rq_writer = r.rq_writer;
                     rq_chunk = r.rq_chunk;
                     rq_rotation_id = r.rq_rotation_id;
                     rq_driver = t.f_driver;
                     rq_permit = (match write_permit_of t.f_effect
                                        <: Core_models.Option.t_Option t_UploadWritePermit with
                                  | Core_models.Option.Option_Some p ->
                                      Core_models.Option.Option_Some p
                                  | _ -> r.rq_permit);
                     rq_committed = r.rq_committed } } in
      (match write_permit_of t.f_effect <: Core_models.Option.t_Option t_UploadWritePermit with
       | Core_models.Option.Option_Some p ->
           let stale_active =
             if (not p.f_shadow) &&
                (p.f_state_phase <> Phase_Active ||
                 p.f_write_epoch <> p.f_state_epoch)
             then 1 else 0 in
           let web_shadow = if p.f_shadow && p.f_web then 1 else 0 in
           let bad_success =
             if t.f_driver.f_responded && not r.rq_driver.f_responded && not r.rq_committed
             then 1 else 0 in
           { w1 with
             w_stale_active = w1.w_stale_active + stale_active;
             w_web_shadow = w1.w_web_shadow + web_shadow;
             w_success_without_commit = w1.w_success_without_commit + bad_success }
       | _ ->
           let bad_success =
             if t.f_driver.f_responded && not r.rq_driver.f_responded && not r.rq_committed
             then 1 else 0 in
           { w1 with w_success_without_commit = w1.w_success_without_commit + bad_success })
    else w
  else w

let world_step (w: vworld) (a: action) : vworld =
  match a with
  | Spawn account web device chunk rid ->
      if account < FStar.List.Tot.length w.w_accounts
      then
        let a = account_at w account in
        let wr = { wr_account = account; wr_device = device; wr_web = web } in
        let start = begin_upload
          { f_writer = { f_authenticated = true; f_web = web;
                         f_web_epoch = if web
                                       then Core_models.Option.Option_Some a.a_epoch
                                       else Core_models.Option.Option_None };
            f_intent = WriteIntent_Create;
            f_declared_epoch = declared_of a } in
        { w with w_reqs = { rq_writer = wr;
                            rq_chunk = chunk;
                            rq_rotation_id = rid;
                            rq_driver = start.f_driver;
                            rq_permit = Core_models.Option.Option_None;
                            rq_committed = false } :: w.w_reqs }
      else w
  | Resolve i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        let r = FStar.List.Tot.index w.w_reqs i in
        deliver_upload w i (UploadEvent_Rekey (rekey_observation w r.rq_writer.wr_account))
      else w
  | Attempt i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        let r = FStar.List.Tot.index w.w_reqs i in
        deliver_upload w i (UploadEvent_Attempt
          (attempt_observation w r.rq_writer r.rq_rotation_id))
      else w
  | Quota i o -> deliver_upload w i (UploadEvent_Quota o)
  | Reread i o -> deliver_upload w i (UploadEvent_Reread o)
  | Activity i o -> deliver_upload w i (UploadEvent_Activity o)
  | Publish i -> deliver_upload w i UploadEvent_Published
  | GuardedWrite i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        let r = FStar.List.Tot.index w.w_reqs i in
        if trace_sound r.rq_driver && is_write r.rq_driver
        then
          (match r.rq_permit <: Core_models.Option.t_Option t_UploadWritePermit with
           | Core_models.Option.Option_Some p ->
               let a = account_at w r.rq_writer.wr_account in
               let out = sql_write w.w_store a r.rq_writer r.rq_chunk r.rq_rotation_id
                                    r.rq_driver.f_intent p in
               let obs = out.wo_obs in
               let t = upload_step r.rq_driver (UploadEvent_Write obs) in
               let committed = committed_obs obs in
               let w1 = { w with
                          w_store = out.wo_store;
                          w_reqs = update w.w_reqs i
                            { rq_writer = r.rq_writer;
                              rq_chunk = r.rq_chunk;
                              rq_rotation_id = r.rq_rotation_id;
                              rq_driver = t.f_driver;
                              rq_permit = Core_models.Option.Option_None;
                              rq_committed = r.rq_committed || committed } } in
               { w1 with
                 w_stale_commit = w1.w_stale_commit + stale_commit_increment a p obs;
                 w_bad_shadow_commit =
                   w1.w_bad_shadow_commit
                   + bad_shadow_increment a r.rq_writer r.rq_rotation_id p obs }
           | _ -> w)
        else w
      else w
  | RekeyStart account starter ->
      if account < FStar.List.Tot.length w.w_accounts
      then
        let a = account_at w account in
        if a.a_phase = Phase_Active
        then
          (match Vela_rekey_policy.next_epoch a.a_epoch
                 <: Core_models.Option.t_Option i64 with
           | Core_models.Option.Option_Some _ ->
               set_account w account
                 ({ a with a_phase = Phase_Freezing;
                           a_rid = w.w_rid + 1;
                           a_starter = starter })
           | Core_models.Option.Option_None -> w)
        else w
      else w
  | RekeyCommit account ->
      if account < FStar.List.Tot.length w.w_accounts
      then
        let a = account_at w account in
        if a.a_phase = Phase_Freezing
        then
          (match Vela_rekey_policy.next_epoch a.a_epoch
                 <: Core_models.Option.t_Option i64 with
           | Core_models.Option.Option_Some ne ->
               set_account w account
                 ({ a with a_phase = Phase_Active;
                           a_epoch = ne;
                           a_rid = 0;
                           a_starter = 0 })
           | Core_models.Option.Option_None -> w)
        else w
      else w
  | RekeyAbort account ->
      if account < FStar.List.Tot.length w.w_accounts
      then
        let a = account_at w account in
        if a.a_phase = Phase_Freezing
        then set_account w account
               { a with a_phase = Phase_Active; a_rid = 0; a_starter = 0 }
        else w
      else w

let rec run_world (w: vworld) (schedule: list action) : Tot vworld (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Per-request preservation lemmas ───────────────────────────────────────

let delivered_request (r: request) (t: t_UploadTransition) : request =
  { rq_writer = r.rq_writer;
    rq_chunk = r.rq_chunk;
    rq_rotation_id = r.rq_rotation_id;
    rq_driver = t.f_driver;
    rq_permit = (match write_permit_of t.f_effect
                       <: Core_models.Option.t_Option t_UploadWritePermit with
                 | Core_models.Option.Option_Some p -> Core_models.Option.Option_Some p
                 | _ -> r.rq_permit);
    rq_committed = r.rq_committed }

let delivered_request_ok (r: request) (e: t_UploadEvent)
  : Lemma
    (requires (request_ok r /\ not (is_write_event e)))
    (ensures (request_ok (delivered_request r (upload_step r.rq_driver e)))) =
  let t = upload_step r.rq_driver e in
  step_sound r.rq_driver e;
  (match write_permit_of t.f_effect <: Core_models.Option.t_Option t_UploadWritePermit with
   | Core_models.Option.Option_Some p ->
       write_effect_permit_matches r.rq_driver e
   | Core_models.Option.Option_None ->
       (match r.rq_permit <: Core_models.Option.t_Option t_UploadWritePermit with
        | Core_models.Option.Option_None -> ()
        | Core_models.Option.Option_Some p ->
            is_write_stage r.rq_driver;
            write_stage_inert r.rq_driver e));
  nonwrite_step_matched r.rq_driver e

let delivery_preserves_ok (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (all_requests_ok w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs /\
               not (is_write_event e)))
    (ensures (all_requests_ok (deliver_upload w i e).w_reqs)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  all_requests_ok_index w.w_reqs i;
  if trace_sound r.rq_driver
  then begin
    let t = upload_step r.rq_driver e in
    delivered_request_ok r e;
    all_requests_ok_update w.w_reqs i (delivered_request r t)
  end

let delivery_preserves_range (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (requests_in_range w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures (requests_in_range (deliver_upload w i e).w_reqs)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  requests_in_range_index w.w_reqs i;
  if trace_sound r.rq_driver
  then requests_in_range_update w.w_reqs i
    { rq_writer = r.rq_writer; rq_chunk = r.rq_chunk;
      rq_rotation_id = r.rq_rotation_id;
      rq_driver = (upload_step r.rq_driver e).f_driver;
      rq_permit = (delivered_request r (upload_step r.rq_driver e)).rq_permit;
      rq_committed = r.rq_committed }

let delivery_stale_active (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (all_requests_ok w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures ((deliver_upload w i e).w_stale_active = w.w_stale_active)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  all_requests_ok_index w.w_reqs i;
  if trace_sound r.rq_driver
  then begin
    write_effect_stale_active r.rq_driver e;
    let t = upload_step r.rq_driver e in
    match write_permit_of t.f_effect <: Core_models.Option.t_Option t_UploadWritePermit with
    | Core_models.Option.Option_Some p ->
        assert (not (not p.f_shadow &&
                     (p.f_state_phase <> Phase_Active ||
                      p.f_write_epoch <> p.f_state_epoch)))
    | _ -> ()
  end

let delivery_web_shadow (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (all_requests_ok w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures ((deliver_upload w i e).w_web_shadow = w.w_web_shadow)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  all_requests_ok_index w.w_reqs i;
  if trace_sound r.rq_driver
  then begin
    write_effect_not_web r.rq_driver e;
    let t = upload_step r.rq_driver e in
    match write_permit_of t.f_effect <: Core_models.Option.t_Option t_UploadWritePermit with
    | Core_models.Option.Option_Some p -> assert (not (p.f_shadow && p.f_web))
    | _ -> ()
  end

/// A success response can only be produced by a request whose own guarded
/// write committed.
let delivery_success (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (all_requests_ok w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs /\
               not (is_write_event e)))
    (ensures ((deliver_upload w i e).w_success_without_commit
              = w.w_success_without_commit)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  all_requests_ok_index w.w_reqs i;
  if trace_sound r.rq_driver
  then begin
    let t = upload_step r.rq_driver e in
    step_sound r.rq_driver e;
    if t.f_driver.f_responded && not r.rq_driver.f_responded && not r.rq_committed
    then begin
      assert (t.f_driver.f_write_matched);
      nonwrite_step_matched r.rq_driver e;
      assert (r.rq_driver.f_write_matched);
      assert (r.rq_committed)
    end
  end

let delivery_inv (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (inv w /\ i < FStar.List.Tot.length w.w_reqs /\ not (is_write_event e)))
    (ensures (inv (deliver_upload w i e))) =
  delivery_preserves_ok w i e;
  delivery_preserves_range w i e;
  delivery_stale_active w i e;
  delivery_web_shadow w i e;
  delivery_success w i e

// ── Invariant preservation per action ─────────────────────────────────────

let spawn_inv (w: vworld) (account: nat) (web: bool) (device: nat) (chunk: nat)
              (rid: nat)
  : Lemma
    (requires (inv w))
    (ensures (inv (world_step w (Spawn account web device chunk rid)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then begin
    assert (account < 2);
    let a = account_at w account in
    let wr = { wr_account = account; wr_device = device; wr_web = web } in
    let start = begin_upload
      { f_writer = { f_authenticated = true; f_web = web;
                     f_web_epoch = if web
                                   then Core_models.Option.Option_Some a.a_epoch
                                   else Core_models.Option.Option_None };
        f_intent = WriteIntent_Create;
        f_declared_epoch = declared_of a } in
    let r = { rq_writer = wr; rq_chunk = chunk; rq_rotation_id = rid;
              rq_driver = start.f_driver;
              rq_permit = Core_models.Option.Option_None;
              rq_committed = false } in
    begin_trace_sound { f_writer = { f_authenticated = true; f_web = web;
                                     f_web_epoch = if web
                                                   then Core_models.Option.Option_Some a.a_epoch
                                                   else Core_models.Option.Option_None };
                        f_intent = WriteIntent_Create;
                        f_declared_epoch = declared_of a };
    all_requests_ok_cons r w.w_reqs;
    requests_in_range_cons r w.w_reqs
  end

let resolve_inv (w: vworld) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Resolve i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then begin
    let r = FStar.List.Tot.index w.w_reqs i in
    all_requests_ok_index w.w_reqs i;
    delivery_inv w i (UploadEvent_Rekey (rekey_observation w r.rq_writer.wr_account))
  end

let attempt_inv (w: vworld) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Attempt i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then begin
    let r = FStar.List.Tot.index w.w_reqs i in
    all_requests_ok_index w.w_reqs i;
    delivery_inv w i (UploadEvent_Attempt
      (attempt_observation w r.rq_writer r.rq_rotation_id))
  end

let quota_inv (w: vworld) (i: nat) (o: t_QuotaObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Quota i o)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i (UploadEvent_Quota o)

let reread_inv (w: vworld) (i: nat) (o: t_RereadObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Reread i o)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i (UploadEvent_Reread o)

let activity_inv (w: vworld) (i: nat) (o: t_ActivityObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Activity i o)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i (UploadEvent_Activity o)

let publish_inv (w: vworld) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Publish i)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i UploadEvent_Published

let guarded_write_inv (w: vworld) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (GuardedWrite i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then begin
    let r = FStar.List.Tot.index w.w_reqs i in
    all_requests_ok_index w.w_reqs i;
    requests_in_range_index w.w_reqs i;
    if trace_sound r.rq_driver && is_write r.rq_driver
    then begin
      match r.rq_permit <: Core_models.Option.t_Option t_UploadWritePermit with
      | Core_models.Option.Option_Some p ->
          let a = account_at w r.rq_writer.wr_account in
          let out = sql_write w.w_store a r.rq_writer r.rq_chunk r.rq_rotation_id
                               r.rq_driver.f_intent p in
          let obs = out.wo_obs in
          let t = upload_step r.rq_driver (UploadEvent_Write obs) in
          let committed = committed_obs obs in
          // The delivered observation preserves driver soundness.
          step_sound r.rq_driver (UploadEvent_Write obs);
          // The matched-write bit is exactly the commit bit.
          assert (not r.rq_driver.f_write_matched);
          on_write_matched r.rq_driver obs;
          assert (t.f_driver.f_write_matched = committed);
          // A committed statement satisfies the world-state counter predicates.
          if committed
          then begin
            sql_write_committed_guard w.w_store a r.rq_writer r.rq_chunk
              r.rq_rotation_id r.rq_driver.f_intent p;
            if p.f_shadow
            then shadow_guard_commit_ok a r.rq_writer r.rq_rotation_id
                   r.rq_driver p
            else active_guard_commit_ok a r.rq_driver p
          end;
          stale_commit_increment_zero a r.rq_writer r.rq_chunk r.rq_rotation_id
            r.rq_driver r.rq_driver.f_intent p w.w_store;
          bad_shadow_increment_zero a r.rq_writer r.rq_chunk r.rq_rotation_id
            r.rq_driver r.rq_driver.f_intent p w.w_store;
          // The store only gains a row of the request's account.
          assert (row_ok (written_row r.rq_writer r.rq_chunk p));
          sql_write_rows_ok w.w_store a r.rq_writer r.rq_chunk r.rq_rotation_id
            r.rq_driver.f_intent p;
          let r' = { rq_writer = r.rq_writer;
                     rq_chunk = r.rq_chunk;
                     rq_rotation_id = r.rq_rotation_id;
                     rq_driver = t.f_driver;
                     rq_permit = Core_models.Option.Option_None;
                     rq_committed = r.rq_committed || committed } in
          all_requests_ok_update w.w_reqs i r';
          requests_in_range_update w.w_reqs i r'
      | _ -> ()
    end
  end

let rekey_start_inv (w: vworld) (account: nat) (starter: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (RekeyStart account starter)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then begin
    let a = account_at w account in
    if a.a_phase = Phase_Active
    then
      (match Vela_rekey_policy.next_epoch a.a_epoch
             <: Core_models.Option.t_Option i64 with
       | Core_models.Option.Option_Some _ ->
           set_account_length w account
             ({ a with a_phase = Phase_Freezing;
                       a_rid = w.w_rid + 1;
                       a_starter = starter });
           accounts_ok_update w.w_accounts account
             ({ a with a_phase = Phase_Freezing;
                       a_rid = w.w_rid + 1;
                       a_starter = starter })
       | Core_models.Option.Option_None -> ())
    else ()
  end

let rekey_commit_inv (w: vworld) (account: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (RekeyCommit account)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then begin
    let a = account_at w account in
    if a.a_phase = Phase_Freezing
    then
      (match Vela_rekey_policy.next_epoch a.a_epoch
             <: Core_models.Option.t_Option i64 with
       | Core_models.Option.Option_Some ne ->
           set_account_length w account
             ({ a with a_phase = Phase_Active; a_epoch = ne;
                       a_rid = 0; a_starter = 0 });
           accounts_ok_update w.w_accounts account
             ({ a with a_phase = Phase_Active; a_epoch = ne;
                       a_rid = 0; a_starter = 0 })
       | Core_models.Option.Option_None -> ())
    else ()
  end

let rekey_abort_inv (w: vworld) (account: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (RekeyAbort account)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then begin
    let a = account_at w account in
    if a.a_phase = Phase_Freezing
    then begin
      set_account_length w account
        { a with a_phase = Phase_Active; a_rid = 0; a_starter = 0 };
      accounts_ok_update w.w_accounts account
        { a with a_phase = Phase_Active; a_rid = 0; a_starter = 0 }
    end
    else ()
  end

let world_step_inv (w: vworld) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | Spawn account web device chunk rid -> spawn_inv w account web device chunk rid
  | Resolve i -> resolve_inv w i
  | Attempt i -> attempt_inv w i
  | Quota i o -> quota_inv w i o
  | GuardedWrite i -> guarded_write_inv w i
  | Reread i o -> reread_inv w i o
  | Activity i o -> activity_inv w i o
  | Publish i -> publish_inv w i
  | RekeyStart account starter -> rekey_start_inv w account starter
  | RekeyCommit account -> rekey_commit_inv w account
  | RekeyAbort account -> rekey_abort_inv w account

let rec run_world_inv (w: vworld) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── Initial world and headline theorems ───────────────────────────────────

let initial : vworld =
  {
    w_accounts =
      [ { a_epoch = mk_i64 1; a_phase = Phase_Active; a_rid = 0; a_starter = 0 };
        { a_epoch = mk_i64 1; a_phase = Phase_Active; a_rid = 0; a_starter = 0 } ];
    w_reqs = [];
    w_store = [];
    w_rid = 0;
    w_stale_active = 0;
    w_web_shadow = 0;
    w_stale_commit = 0;
    w_bad_shadow_commit = 0;
    w_success_without_commit = 0;
  }

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem: whatever the number of concurrent device/web uploads,
/// rotation starts/commits/aborts and their interleaving, no guarded write ever
/// commits a stale active row, an unauthorized shadow row, or a success
/// response without its own commit.
let upload_store_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_stale_commit = 0 /\
      w.w_bad_shadow_commit = 0 /\
      w.w_success_without_commit = 0) =
  initial_inv ();
  run_world_inv initial schedule

let no_stale_commit (schedule: list action)
  : Lemma ((run_world initial schedule).w_stale_commit = 0) =
  upload_store_theorem schedule

let no_bad_shadow_commit (schedule: list action)
  : Lemma ((run_world initial schedule).w_bad_shadow_commit = 0) =
  upload_store_theorem schedule

let no_success_without_commit (schedule: list action)
  : Lemma ((run_world initial schedule).w_success_without_commit = 0) =
  upload_store_theorem schedule

/// Round-1 theorems, subsumed: the driver-level counters stay zero too.
let upload_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_stale_active = 0 /\
      w.w_web_shadow = 0) =
  upload_store_theorem schedule

let no_stale_active_write (schedule: list action)
  : Lemma ((run_world initial schedule).w_stale_active = 0) =
  upload_store_theorem schedule

let no_web_shadow_write (schedule: list action)
  : Lemma ((run_world initial schedule).w_web_shadow = 0) =
  upload_store_theorem schedule

// ── Non-vacuity: reachable successes, skips and refusals ──────────────────

/// Safe head projections for lemma statements (the concrete schedules below
/// have a non-empty store/request list, so these reduce to the head).
let store_head (l: list chunk_row) : chunk_row =
  match l with
  | [] -> { cr_account = 0; cr_chunk = 0; cr_epoch = mk_i64 0 }
  | h :: _ -> h

let default_request : request =
  { rq_writer = { wr_account = 0; wr_device = 0; wr_web = false };
    rq_chunk = 0;
    rq_rotation_id = 0;
    rq_driver = (begin_upload
      { f_writer = { f_authenticated = true; f_web = false;
                     f_web_epoch = Core_models.Option.Option_None };
        f_intent = WriteIntent_Create;
        f_declared_epoch = Core_models.Option.Option_None }).f_driver;
    rq_permit = Core_models.Option.Option_None;
    rq_committed = false }

let request_head (l: list request) : request =
  match l with
  | [] -> default_request
  | h :: _ -> h

#push-options "--fuel 4 --ifuel 2"

let run_cons (w: vworld) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: vworld) : Lemma (run_world w [] == w) = ()

/// One device upload on an ACTIVE account commits at the live epoch and
/// completes.
let a1 = world_step initial (Spawn 0 false 0 0 0)
let a2 = world_step a1 (Resolve 0)
let a3 = world_step a2 (Quota 0 QuotaObservation_Allowed)
let a4 = world_step a3 (GuardedWrite 0)
let a5 = world_step a4 (Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }))
let a6 = world_step a5 (Publish 0)

let active_commit_schedule : list action =
  [ Spawn 0 false 0 0 0; Resolve 0; Quota 0 QuotaObservation_Allowed;
    GuardedWrite 0;
    Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0 ]

let active_commit_facts ()
  : Lemma (
      FStar.List.Tot.length a6.w_store = 1 /\
      (store_head a6.w_store).cr_epoch = mk_i64 1 /\
      (store_head a6.w_store).cr_account = 0 /\
      (request_head a6.w_reqs).rq_committed = true /\
      (request_head a6.w_reqs).rq_driver.f_responded = true /\
      a4.w_stale_commit = 0 /\ a6.w_stale_commit = 0 /\
      a6.w_bad_shadow_commit = 0 /\ a6.w_success_without_commit = 0) = ()

let active_commit_is_reachable ()
  : Lemma (
      let w = run_world initial active_commit_schedule in
      FStar.List.Tot.length w.w_store = 1 /\
      (store_head w.w_store).cr_epoch = mk_i64 1 /\
      (request_head w.w_reqs).rq_committed = true /\
      w.w_stale_commit = 0 /\ w.w_bad_shadow_commit = 0 /\
      w.w_success_without_commit = 0) =
  run_cons initial (Spawn 0 false 0 0 0)
    [Resolve 0; Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons a1 (Resolve 0)
    [Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons a2 (Quota 0 QuotaObservation_Allowed)
    [GuardedWrite 0;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons a3 (GuardedWrite 0)
    [Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons a4 (Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }))
    [Publish 0];
  run_cons a5 (Publish 0) [];
  run_nil a6;
  active_commit_facts ()

/// A rotation shadow write by the device that started the rotation commits at
/// exactly the successor epoch and completes without publishing.
let b1 = world_step initial (RekeyStart 0 0)
let b2 = world_step b1 (Spawn 0 false 0 0 1)
let b3 = world_step b2 (Resolve 0)
let b4 = world_step b3 (Attempt 0)
let b5 = world_step b4 (Quota 0 QuotaObservation_Allowed)
let b6 = world_step b5 (GuardedWrite 0)
let b7 = world_step b6 (Reread 0 (RereadObservation_Read { f_version = mk_i64 2 }))
let b8 = world_step b7 (Activity 0 ActivityObservation_Refreshed)
let b9 = world_step b8 (Publish 0)

let shadow_commit_schedule : list action =
  [ RekeyStart 0 0; Spawn 0 false 0 0 1; Resolve 0; Attempt 0;
    Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
    Reread 0 (RereadObservation_Read { f_version = mk_i64 2 });
    Activity 0 ActivityObservation_Refreshed; Publish 0 ]

let shadow_commit_facts ()
  : Lemma (
      (account_at b1 0).a_phase = Phase_Freezing /\
      (account_at b1 0).a_rid = 1 /\
      (account_at b1 0).a_epoch = mk_i64 1 /\
      FStar.List.Tot.length b9.w_store = 1 /\
      (store_head b9.w_store).cr_epoch = mk_i64 2 /\
      (store_head b9.w_store).cr_account = 0 /\
      (request_head b9.w_reqs).rq_committed = true /\
      (request_head b9.w_reqs).rq_driver.f_responded = true /\
      (request_head b9.w_reqs).rq_driver.f_shadow = true /\
      b9.w_stale_commit = 0 /\ b9.w_bad_shadow_commit = 0 /\
      b9.w_success_without_commit = 0) = ()

let shadow_commit_is_reachable ()
  : Lemma (
      let w = run_world initial shadow_commit_schedule in
      FStar.List.Tot.length w.w_store = 1 /\
      (store_head w.w_store).cr_epoch = mk_i64 2 /\
      (request_head w.w_reqs).rq_committed = true /\
      w.w_stale_commit = 0 /\ w.w_bad_shadow_commit = 0 /\
      w.w_success_without_commit = 0) =
  run_cons initial (RekeyStart 0 0)
    [Spawn 0 false 0 0 1; Resolve 0; Attempt 0;
     Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 2 });
     Activity 0 ActivityObservation_Refreshed; Publish 0];
  run_cons b1 (Spawn 0 false 0 0 1)
    [Resolve 0; Attempt 0; Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 2 });
     Activity 0 ActivityObservation_Refreshed; Publish 0];
  run_cons b2 (Resolve 0)
    [Attempt 0; Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 2 });
     Activity 0 ActivityObservation_Refreshed; Publish 0];
  run_cons b3 (Attempt 0)
    [Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 2 });
     Activity 0 ActivityObservation_Refreshed; Publish 0];
  run_cons b4 (Quota 0 QuotaObservation_Allowed)
    [GuardedWrite 0; Reread 0 (RereadObservation_Read { f_version = mk_i64 2 });
     Activity 0 ActivityObservation_Refreshed; Publish 0];
  run_cons b5 (GuardedWrite 0)
    [Reread 0 (RereadObservation_Read { f_version = mk_i64 2 });
     Activity 0 ActivityObservation_Refreshed; Publish 0];
  run_cons b6 (Reread 0 (RereadObservation_Read { f_version = mk_i64 2 }))
    [Activity 0 ActivityObservation_Refreshed; Publish 0];
  run_cons b7 (Activity 0 ActivityObservation_Refreshed) [Publish 0];
  run_cons b8 (Publish 0) [];
  run_nil b9;
  shadow_commit_facts ()

/// A rotation committed between resolve and the guarded write makes the guard
/// skip: no stale row lands and the driver reports the rekey.
let c1 = world_step initial (Spawn 0 false 0 0 0)
let c2 = world_step c1 (Resolve 0)
let c3 = world_step c2 (Quota 0 QuotaObservation_Allowed)
let c4 = world_step c3 (RekeyStart 0 0)
let c5 = world_step c4 (RekeyCommit 0)
let c6 = world_step c5 (GuardedWrite 0)

let rotation_skip_schedule : list action =
  [ Spawn 0 false 0 0 0; Resolve 0; Quota 0 QuotaObservation_Allowed;
    RekeyStart 0 0; RekeyCommit 0; GuardedWrite 0 ]

let rotation_skip_facts ()
  : Lemma (
      (account_at c5 0).a_phase = Phase_Active /\
      (account_at c5 0).a_epoch = mk_i64 2 /\
      FStar.List.Tot.length c6.w_store = 0 /\
      (request_head c6.w_reqs).rq_committed = false /\
      (request_head c6.w_reqs).rq_driver.f_failed = true /\
      c6.w_stale_commit = 0 /\ c6.w_bad_shadow_commit = 0 /\
      c6.w_success_without_commit = 0) = ()

let rotation_between_resolve_and_write_skips ()
  : Lemma (
      let w = run_world initial rotation_skip_schedule in
      FStar.List.Tot.length w.w_store = 0 /\
      (request_head w.w_reqs).rq_committed = false /\
      w.w_stale_commit = 0) =
  run_cons initial (Spawn 0 false 0 0 0)
    [Resolve 0; Quota 0 QuotaObservation_Allowed;
     RekeyStart 0 0; RekeyCommit 0; GuardedWrite 0];
  run_cons c1 (Resolve 0)
    [Quota 0 QuotaObservation_Allowed; RekeyStart 0 0; RekeyCommit 0;
     GuardedWrite 0];
  run_cons c2 (Quota 0 QuotaObservation_Allowed)
    [RekeyStart 0 0; RekeyCommit 0; GuardedWrite 0];
  run_cons c3 (RekeyStart 0 0) [RekeyCommit 0; GuardedWrite 0];
  run_cons c4 (RekeyCommit 0) [GuardedWrite 0];
  run_cons c5 (GuardedWrite 0) [];
  run_nil c6;
  rotation_skip_facts ()

/// A web session whose token is pinned at the rotation's base epoch reaches the
/// shadow decision and is refused before any write or commit.
let w1 = world_step initial (RekeyStart 0 0)
let w2 = world_step w1 (Spawn 0 true 0 1 1)
let w3 = world_step w2 (Resolve 0)
let w4 = world_step w3 (Attempt 0)

let web_shadow_schedule : list action =
  [ RekeyStart 0 0; Spawn 0 true 0 1 1; Resolve 0; Attempt 0 ]

let web_shadow_facts ()
  : Lemma (
      (request_head w4.w_reqs).rq_driver.f_failed = true /\
      (request_head w4.w_reqs).rq_driver.f_write_matched = false /\
      (request_head w4.w_reqs).rq_committed = false /\
      FStar.List.Tot.length w4.w_store = 0 /\
      w4.w_web_shadow = 0 /\ w4.w_bad_shadow_commit = 0) = ()

let web_shadow_is_refused ()
  : Lemma (
      let w = run_world initial web_shadow_schedule in
      (request_head w.w_reqs).rq_driver.f_failed = true /\
      FStar.List.Tot.length w.w_store = 0 /\ w.w_web_shadow = 0 /\ w.w_bad_shadow_commit = 0) =
  run_cons initial (RekeyStart 0 0) [Spawn 0 true 0 1 1; Resolve 0; Attempt 0];
  run_cons w1 (Spawn 0 true 0 1 1) [Resolve 0; Attempt 0];
  run_cons w2 (Resolve 0) [Attempt 0];
  run_cons w3 (Attempt 0) [];
  run_nil w4;
  web_shadow_facts ()

/// Two accounts upload concurrently without disturbing one another.
let d1 = world_step initial (Spawn 0 false 0 0 0)
let d2 = world_step d1 (Resolve 0)
let d3 = world_step d2 (Quota 0 QuotaObservation_Allowed)
let d4 = world_step d3 (GuardedWrite 0)
let d5 = world_step d4 (Spawn 1 false 1 1 0)
let d6 = world_step d5 (Resolve 0)
let d7 = world_step d6 (Quota 0 QuotaObservation_Allowed)
let d8 = world_step d7 (GuardedWrite 0)

let two_account_schedule : list action =
  [ Spawn 0 false 0 0 0; Resolve 0; Quota 0 QuotaObservation_Allowed;
    GuardedWrite 0;
    Spawn 1 false 1 1 0; Resolve 0; Quota 0 QuotaObservation_Allowed;
    GuardedWrite 0 ]

let two_account_facts ()
  : Lemma (
      FStar.List.Tot.length d8.w_store = 2 /\
      (store_head d8.w_store).cr_account = 0 /\
      d8.w_stale_commit = 0 /\ d8.w_bad_shadow_commit = 0 /\
      d8.w_success_without_commit = 0) = ()

let two_account_is_reachable ()
  : Lemma (
      let w = run_world initial two_account_schedule in
      FStar.List.Tot.length w.w_store = 2 /\
      w.w_stale_commit = 0 /\ w.w_bad_shadow_commit = 0 /\
      w.w_success_without_commit = 0) =
  run_cons initial (Spawn 0 false 0 0 0)
    [Resolve 0; Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Spawn 1 false 1 1 0; Resolve 0; Quota 0 QuotaObservation_Allowed;
     GuardedWrite 0];
  run_cons d1 (Resolve 0)
    [Quota 0 QuotaObservation_Allowed; GuardedWrite 0;
     Spawn 1 false 1 1 0; Resolve 0; Quota 0 QuotaObservation_Allowed;
     GuardedWrite 0];
  run_cons d2 (Quota 0 QuotaObservation_Allowed)
    [GuardedWrite 0; Spawn 1 false 1 1 0; Resolve 0;
     Quota 0 QuotaObservation_Allowed; GuardedWrite 0];
  run_cons d3 (GuardedWrite 0)
    [Spawn 1 false 1 1 0; Resolve 0; Quota 0 QuotaObservation_Allowed;
     GuardedWrite 0];
  run_cons d4 (Spawn 1 false 1 1 0)
    [Resolve 0; Quota 0 QuotaObservation_Allowed; GuardedWrite 0];
  run_cons d5 (Resolve 0) [Quota 0 QuotaObservation_Allowed; GuardedWrite 0];
  run_cons d6 (Quota 0 QuotaObservation_Allowed) [GuardedWrite 0];
  run_cons d7 (GuardedWrite 0) [];
  run_nil d8;
  two_account_facts ()

/// Every witness schedule keeps the counters zero.
let witnesses_keep_counters_zero ()
  : Lemma (
      (run_world initial web_shadow_schedule).w_web_shadow = 0 /\
      (run_world initial web_shadow_schedule).w_bad_shadow_commit = 0 /\
      (run_world initial shadow_commit_schedule).w_stale_commit = 0 /\
      (run_world initial shadow_commit_schedule).w_bad_shadow_commit = 0 /\
      (run_world initial active_commit_schedule).w_stale_commit = 0 /\
      (run_world initial two_account_schedule).w_stale_commit = 0) =
  upload_store_theorem web_shadow_schedule;
  upload_store_theorem shadow_commit_schedule;
  upload_store_theorem active_commit_schedule;
  upload_store_theorem two_account_schedule

#pop-options
