module Vela_enrollment_policy_executor_model

/// A model of the tables and store keys the device-enrollment executors touch,
/// and of how their statement plans run on them (F-1).
///
/// Every table and every store namespace is keyed by its id, so a table is a
/// partial map from id to row and "every starting database" is every tuple of
/// maps. Only the columns the enrollment statements read or write are
/// modelled.
///
/// - `exec_write` gives each typed write statement its SQL or store meaning:
///   an unconditional expiring write inserts or replaces its key; the guarded
///   claim write is first-writer-wins while the grant key is live; the guarded
///   device inserts add the one intended row exactly when the account guard
///   holds, and error if their fresh id is already taken; a delete removes the
///   one key or reports nothing.
/// - `run_writes` runs a plan in order and stops at the first failure; a
///   failed statement changes nothing. `run_reads` does the same for reads,
///   which never change the state. `run_take` / `run_take_pair` model the
///   destructive reads (`get_del`, `take_live_pair`).
/// - `f = Some k` makes the k-th statement (from 0) fail.
///
/// What this module trusts, and the conformance test in
/// `vela-server/src/device/executor_conformance.rs` checks against a real
/// database and a real sled store: these statement meanings, statement
/// atomicity, the rendering of each typed statement to SQL/key/value, and the
/// decoding of stored records and result rows into views. TTLs are abstracted:
/// a key is live for the length of one request (the conformance store is
/// populated just before each case).
///
/// The executor models below are the server's thin loop: plan (extracted),
/// run, classify (extracted). `vela-enrollment-policy/src/executor_model.rs`
/// mirrors this module function for function; its `shared_vectors` test and
/// the `vector_*` lemmas in
/// `Vela_enrollment_policy_executor_lemmas` check the same concrete runs.

open FStar.Mul
open Core_models
open Vela_enrollment_policy.Executor

module L = FStar.List.Tot
module E = Vela_enrollment_policy.Executor

type text = Alloc.String.t_String

/// A table (or one store namespace): key -> row.
type tbl (a: Type) = text -> option a

let upd (#a: Type) (t: tbl a) (k: text) (x: option a) : tbl a =
  fun k' -> if k' = k then x else t k'

/// The extracted types use hax's `Core_models.Option`; the model uses the
/// native one. The two conversions are definitional.
let of_core (#a: Type) (o: Core_models.Option.t_Option a) : option a =
  match o with
  | Core_models.Option.Option_Some x -> Some x
  | Core_models.Option.Option_None -> None

let to_core (#a: Type) (o: option a) : Core_models.Option.t_Option a =
  match o with
  | Some x -> Core_models.Option.Option_Some x
  | None -> Core_models.Option.Option_None

/// A `devices` row. `d_grant` is the `enrollment_grant_id` column; the model
/// also keeps `grant_index`, the column's unique index, so the U-20 read can
/// look a device up by grant id.
noeq type device_row = {
  d_user: text;
  d_name: text;
  d_type_: text;
  d_ek: text;
  d_vk: text;
  d_enrolled_by: text;
  d_grant: option text;
  d_rms: text;
  d_created: text;
  d_revoked: i64;
}

type grant_row = {
  g_user: text;
  g_device: text;
}

type claim_row = {
  c_ek: text;
  c_vk: text;
  c_name: option text;
  c_type_: option text;
}

type result_row = {
  r_device: text;
  r_vk: text;
}

type user_row = {
  u_epoch: i64;
  u_rekey: option text;
}

noeq type db = {
  grants: tbl grant_row;
  claims: tbl claim_row;
  results: tbl result_row;
  packages: tbl text;
  challenges: tbl text;
  users: tbl user_row;
  devices: tbl device_row;
  /// `devices.enrollment_grant_id`, indexed: grant id -> device id.
  grant_index: tbl text;
}

// ── Statement semantics ────────────────────────────────────────────────────

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// The account guard both device inserts share: the user row exists, is at the
/// statement's epoch and is not rotating.
let epoch_guard (d: db) (user: text) (epoch: i64) : bool =
  match d.users user with
  | Some u -> u.u_epoch = epoch && None? u.u_rekey
  | None -> false

let written_device
      (new_device_id user name ty ek vk enrolled_by rms now: text)
      (grant: option text)
      (revoked: i64)
  : device_row =
  {
    d_user = user;
    d_name = name;
    d_type_ = ty;
    d_ek = ek;
    d_vk = vk;
    d_enrolled_by = enrolled_by;
    d_grant = grant;
    d_rms = rms;
    d_created = now;
    d_revoked = revoked;
  }

/// One write statement on a state: its outcome and the new state, or `None`
/// when the statement errors.
let exec_write (d: db) (s: t_PairingStmt) : option (t_WriteOutcome & db) =
  match s with
  | PairingStmt_StorePackage { f_token = token; f_ciphertext = ciphertext } ->
    Some (WriteOutcome_Applied (mk_u64 1),
          { d with packages = upd d.packages token (Some ciphertext) })
  | PairingStmt_StoreGrant { f_grant_id = id; f_user_id = user; f_device_id = device } ->
    let row : grant_row = { g_user = user; g_device = device } in
    Some (WriteOutcome_Applied (mk_u64 1), { d with grants = upd d.grants id (Some row) })
  | PairingStmt_WriteClaim
    { f_grant_id = id; f_hybrid_ek = ek; f_hybrid_vk = vk;
      f_device_name = name; f_device_type = ty } ->
    if None? (d.grants id)
    then Some (WriteOutcome_GuardMissing, d)
    else if Some? (d.claims id)
    then Some (WriteOutcome_KeyExists, d)
    else
      let row : claim_row =
        { c_ek = ek; c_vk = vk; c_name = of_core name; c_type_ = of_core ty } in
      Some (WriteOutcome_Inserted, { d with claims = upd d.claims id (Some row) })
  | PairingStmt_StoreResult { f_grant_id = id; f_device_id = device; f_hybrid_vk = vk } ->
    let row : result_row = { r_device = device; r_vk = vk } in
    Some (WriteOutcome_Applied (mk_u64 1), { d with results = upd d.results id (Some row) })
  | PairingStmt_InsertCompletionDevice
    { f_new_device_id = new_id; f_user_id = user; f_device_name = name;
      f_device_type = ty; f_hybrid_ek = ek; f_hybrid_vk = vk;
      f_enrolled_by = enrolled_by; f_grant_id = grant; f_rms_capsule = rms;
      f_now = now; f_guard_user = guard_user; f_guard_epoch = guard_epoch } ->
    if not (epoch_guard d guard_user guard_epoch)
    then Some (WriteOutcome_Applied (mk_u64 0), d)
    else if Some? (d.devices new_id)
    then None
    else if Some? (d.grant_index grant)
    then None
    else
      let row = written_device new_id user name ty ek vk enrolled_by rms now (Some grant) (mk_i64 0) in
      Some (WriteOutcome_Applied (mk_u64 1),
            { d with devices = upd d.devices new_id (Some row);
                     grant_index = upd d.grant_index grant (Some new_id) })
  | PairingStmt_InsertEnrollDevice
    { f_new_device_id = new_id; f_user_id = user; f_device_name = name;
      f_device_type = ty; f_hybrid_ek = ek; f_hybrid_vk = vk;
      f_enrolled_by = enrolled_by; f_rms_capsule = rms; f_now = now;
      f_guard_user = guard_user; f_guard_epoch = guard_epoch } ->
    if not (epoch_guard d guard_user guard_epoch)
    then Some (WriteOutcome_Applied (mk_u64 0), d)
    else if Some? (d.devices new_id)
    then None
    else
      let row = written_device new_id user name ty ek vk enrolled_by rms now None (mk_i64 0) in
      Some (WriteOutcome_Applied (mk_u64 1), { d with devices = upd d.devices new_id (Some row) })
  | _ -> None

/// A plan inside a request: writes in order, stopping at the first failure.
let rec run_writes
      (d: db) (stmts: list t_PairingStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts})
        (decreases stmts) =
  match stmts with
  | [] -> ([], d)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], d)
    else
      match exec_write d s with
      | None -> ([WriteOutcome_Failed], d)
      | Some (outcome, d') ->
        let r = run_writes d' rest (k + 1) f in
        (outcome :: fst r, snd r)

let view_claim (row: claim_row) : t_ClaimRowView =
  { f_hybrid_ek = Core_models.Option.Option_Some row.c_ek;
    f_hybrid_vk = Core_models.Option.Option_Some row.c_vk;
    f_device_name = to_core row.c_name;
    f_device_type = to_core row.c_type_ }

let view_result (row: result_row) : t_ResultRowView =
  { f_device_id = Core_models.Option.Option_Some row.r_device;
    f_hybrid_vk = Core_models.Option.Option_Some row.r_vk }

let view_account (row: user_row) : t_AccountRowView =
  { f_key_epoch = Core_models.Option.Option_Some row.u_epoch;
    f_rekey_state = to_core row.u_rekey }

let view_device (id: text) (row: device_row) : t_DeviceRowView =
  { f_device_id = Core_models.Option.Option_Some id;
    f_hybrid_vk = Core_models.Option.Option_Some row.d_vk;
    f_revoked = Core_models.Option.Option_Some row.d_revoked;
    f_user_id = Core_models.Option.Option_Some row.d_user;
    f_enrollment_grant_id = to_core row.d_grant }

/// The opener read's guard: the row must belong to the grant's user.
let opener_row (d: db) (device_id user: text) : option device_row =
  match d.devices device_id with
  | Some row -> if row.d_user = user then Some row else None
  | None -> None

/// The active-device read's guard: the SQL `revoked = 0` predicate.
let active_row (d: db) (device_id: text) : option device_row =
  match d.devices device_id with
  | Some row -> if row.d_revoked = mk_i64 0 then Some row else None
  | None -> None

/// One read statement's meaning; `None` when the statement is not a read.
let read_step (d: db) (s: t_PairingStmt) : option t_ReadOutcome =
  match s with
  | PairingStmt_ClaimExists { f_grant_id = id } ->
    Some (ReadOutcome_ClaimExists (Some? (d.claims id)))
  | PairingStmt_ReadClaim { f_grant_id = id } ->
    Some (ReadOutcome_Claim
            (match d.claims id with
             | Some row -> Core_models.Option.Option_Some (view_claim row)
             | None -> Core_models.Option.Option_None))
  | PairingStmt_SelectAccount { f_user_id = user } ->
    Some (ReadOutcome_Account
            (match d.users user with
             | Some row -> Core_models.Option.Option_Some (view_account row)
             | None -> Core_models.Option.Option_None))
  | PairingStmt_SelectOpener { f_device_id = device_id; f_user_id = user } ->
    Some (ReadOutcome_Opener
            (match opener_row d device_id user with
             | Some row -> Core_models.Option.Option_Some (view_device device_id row)
             | None -> Core_models.Option.Option_None))
  | PairingStmt_SelectActiveDevice { f_device_id = device_id } ->
    Some (ReadOutcome_ActiveDevice
            (match active_row d device_id with
             | Some row -> Core_models.Option.Option_Some (view_device device_id row)
             | None -> Core_models.Option.Option_None))
  | PairingStmt_SelectDeviceByGrant { f_grant_id = grant_id } ->
    Some (ReadOutcome_DeviceByGrant
            (match d.grant_index grant_id with
             | Some id ->
               (match d.devices id with
                | Some row -> Core_models.Option.Option_Some (view_device id row)
                | None -> Core_models.Option.Option_None)
             | None -> Core_models.Option.Option_None))
  | PairingStmt_ReadResult { f_grant_id = id } ->
    Some (ReadOutcome_Result
            (match d.results id with
             | Some row -> Core_models.Option.Option_Some (view_result row)
             | None -> Core_models.Option.Option_None))
  | _ -> None

/// A plan inside a request: reads in order, stopping at the first failure.
/// Reads change nothing.
let rec run_reads
      (d: db) (stmts: list t_PairingStmt) (k: nat) (f: option nat)
  : Tot (r: list t_ReadOutcome{L.length r <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> []
  | s :: rest ->
    if faulted f k
    then [ReadOutcome_Failed]
    else
      match read_step d s with
      | None -> [ReadOutcome_Failed]
      | Some o -> o :: run_reads d rest (k + 1) f

/// A destructive single-key read (`get_del`).
let exec_take (d: db) (s: t_PairingStmt) : option (t_TakeOutcome & db) =
  match s with
  | PairingStmt_TakePackage { f_token = token } ->
    (match d.packages token with
     | Some _ ->
       Some (TakeOutcome_Present,
             { d with packages = upd d.packages token None })
     | None -> Some (TakeOutcome_Missing, d))
  | PairingStmt_TakeChallenge { f_challenge = challenge } ->
    (match d.challenges challenge with
     | Some _ ->
       Some (TakeOutcome_Present,
             { d with challenges = upd d.challenges challenge None })
     | None -> Some (TakeOutcome_Missing, d))
  | _ -> None

/// The last statement of a take plan is the one that runs; enrollment plans
/// have exactly one statement.
let run_take
      (d: db) (stmts: list t_PairingStmt) (k: nat) (f: option nat)
  : Tot (t_TakeOutcome & db) (decreases stmts) =
  match stmts with
  | [] -> (TakeOutcome_Failed, d)
  | s :: rest ->
    if faulted f k
    then (TakeOutcome_Failed, d)
    else
      match exec_take d s with
      | None -> (TakeOutcome_Failed, d)
      | Some r -> r

/// The atomic two-key take (`take_live_pair`).
let exec_take_pair (d: db) (s: t_PairingStmt) : option (t_TakeOutcome & db) =
  match s with
  | PairingStmt_TakeCeremony { f_grant_id = id } ->
    if Some? (d.grants id) && Some? (d.claims id)
    then
      Some (TakeOutcome_Present,
            { d with grants = upd d.grants id None;
                     claims = upd d.claims id None })
    else Some (TakeOutcome_Missing, d)
  | _ -> None

let run_take_pair
      (d: db) (stmts: list t_PairingStmt) (k: nat) (f: option nat)
  : Tot (t_TakeOutcome & db) (decreases stmts) =
  match stmts with
  | [] -> (TakeOutcome_Failed, d)
  | s :: rest ->
    if faulted f k
    then (TakeOutcome_Failed, d)
    else
      match exec_take_pair d s with
      | None -> (TakeOutcome_Failed, d)
      | Some r -> r

// ── The executables: plan, run, classify ───────────────────────────────────

let stmts_of (p: Alloc.Vec.t_Vec t_PairingStmt Alloc.Alloc.t_Global) : list t_PairingStmt =
  Seq.seq_to_list p._0

let slice_of (#a: Type) (l: list a{L.length l <= Rust_primitives.Integers.max_usize}) : t_Slice a =
  Seq.seq_of_list l

/// `StorePackageIo::store_package`.
let store_package d (token ciphertext: text) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_StoreObservation & db) =
  let r = run_writes d (stmts_of (plan_store_package token ciphertext)) 0 f in
  (classify_store (slice_of (fst r)), snd r)

/// `RedeemPackageIo::redeem_package`.
let redeem_package d (token: text) (utf8_valid: bool) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_RedeemObservation & db) =
  let r = run_take d (stmts_of (plan_redeem_package token)) 0 f in
  (classify_redeem (fst r) utf8_valid, snd r)

/// `OpenGrantIo::store_grant`.
let store_grant d (grant_id user_id device_id: text) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_StoreObservation & db) =
  let r = run_writes d (stmts_of (plan_store_grant grant_id user_id device_id)) 0 f in
  (classify_store (slice_of (fst r)), snd r)

/// `ClaimIo::check_claim`.
let claim_check d (grant_id: text) (grant_live: bool) (ek_len vk_len: usize) (f: option nat)
  : (Vela_enrollment_policy.t_ClaimObservation & db) =
  let r = run_reads d (stmts_of (plan_claim_check grant_id)) 0 f in
  (classify_claim_check grant_live ek_len vk_len (slice_of r), d)

/// `ClaimIo::write_claim`.
let claim_write
      d (grant_id ek vk: text)
      (name ty: Core_models.Option.t_Option text) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_ClaimWriteObservation & db) =
  let r = run_writes d (stmts_of (plan_claim_write grant_id ek vk name ty)) 0 f in
  (classify_claim_write (slice_of (fst r)), snd r)

/// `CompleteIo::check_account`.
let account_read
      d (user_id: text) (declared_epoch_positive rekey_permitted: bool) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_CompletionAccountObservation & (i64 & bool) & db) =
  let r = run_reads d (stmts_of (plan_account_read user_id)) 0 f in
  (classify_account (slice_of r) declared_epoch_positive rekey_permitted,
   account_fields (slice_of r),
   d)

/// `CompleteIo::prepare_completion`.
let completion_preflight
      d (grant_id device_id user_id: text) (verdicts: t_CompletionVerdicts) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_CompletionPreflightObservation & db) =
  let r = run_reads d (stmts_of (plan_completion_preflight grant_id device_id user_id)) 0 f in
  (classify_completion_preflight (slice_of r) verdicts, d)

/// `CompleteIo::take_ceremony`.
let take_ceremony d (grant_id: text) (grant_matches claim_matches: bool) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_TakeObservation & db) =
  let r = run_take_pair d (stmts_of (plan_take_ceremony grant_id)) 0 f in
  (classify_take_ceremony (slice_of [fst r]) grant_matches claim_matches, snd r)

/// `CompleteIo::insert_device`.
let completion_insert
      d (new_device_id user_id device_name device_type hybrid_ek hybrid_vk
         enrolled_by grant_id rms_capsule now guard_user: text)
      (guard_epoch: i64) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_DeviceInsertObservation & db) =
  let plan =
    plan_completion_insert new_device_id user_id device_name device_type hybrid_ek
      hybrid_vk enrolled_by grant_id rms_capsule now guard_user guard_epoch in
  let r = run_writes d (stmts_of plan) 0 f in
  (classify_insert_completion (slice_of (fst r)), snd r)

/// `EnrollIo::insert_device`.
let enroll_insert
      d (new_device_id user_id device_name device_type hybrid_ek hybrid_vk
         enrolled_by rms_capsule now guard_user: text)
      (guard_epoch: i64) (f: option nat)
  : (Vela_enrollment_policy.Enroll_driver.t_InsertObservation & db) =
  let plan =
    plan_enroll_insert new_device_id user_id device_name device_type hybrid_ek
      hybrid_vk enrolled_by rms_capsule now guard_user guard_epoch in
  let r = run_writes d (stmts_of plan) 0 f in
  (classify_insert_enroll (slice_of (fst r)), snd r)

/// `CompleteIo::write_result`.
let result_write d (grant_id device_id hybrid_vk: text) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_StoreObservation & db) =
  let r = run_writes d (stmts_of (plan_result_write grant_id device_id hybrid_vk)) 0 f in
  (classify_store (slice_of (fst r)), snd r)

/// `ResultIo::read_result`.
let result_read
      d (grant_id: text) (verdicts: t_CollectorVerdicts) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_ResultReadObservation & db) =
  let r = run_reads d (stmts_of (plan_result_read grant_id)) 0 f in
  (classify_result_read (slice_of r) verdicts, d)

/// `ResultIo::read_claim`.
let claim_read
      d (grant_id: text) (verdicts: t_CollectorVerdicts) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_ClaimReadObservation & db) =
  let r = run_reads d (stmts_of (plan_claim_read grant_id)) 0 f in
  (classify_claim_read (slice_of r) verdicts, d)

/// `ResultIo::read_enrolled_device` (U-20 fallback).
let enrolled_device
      d (grant_id: text) (verdicts: t_CollectorVerdicts) (f: option nat)
  : (Vela_enrollment_policy.Pairing_driver.t_DeviceGrantObservation & db) =
  let r = run_reads d (stmts_of (plan_device_by_grant grant_id)) 0 f in
  (classify_enrolled_device (slice_of r) verdicts, d)

/// `EnrollIo::check_device`.
let active_device d (device_id: text) (verdict: t_EnrollAuthVerdict) (f: option nat)
  : (Vela_enrollment_policy.Enroll_driver.t_DeviceObservation & db) =
  let r = run_reads d (stmts_of (plan_active_device_read device_id)) 0 f in
  (classify_device_check (slice_of r) verdict, d)

/// `EnrollIo::consume_challenge`.
let challenge_take d (challenge: text) (purpose_matches: bool) (f: option nat)
  : (bool & db) =
  let r = run_take d (stmts_of (plan_challenge_take challenge)) 0 f in
  (classify_challenge_take (fst r) purpose_matches, snd r)
