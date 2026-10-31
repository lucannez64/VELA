module Vela_rekey_policy_executor_model

/// A model of the tables and store keys the vault, rekey, capsule, ORAM and
/// schema executors touch, and of how their statement plans run on them (F-1).
///
/// - The chunk, device and ORAM tables are finite associations: a list of rows
///   keyed by the full primary key. `find_*` is the table's lookup and `set_*`
///   replaces a row (or inserts it); a key that is not in the list is a missing
///   row. Because the tables are finite, the `EXISTS`/`NOT EXISTS` predicates
///   of the completeness probes, the account CAS guards and the inventory row
///   set are functions of the state, computed by `probe_of`/`inventory_rows`
///   rather than supplied as inputs.
/// - `exec` gives each typed write statement its SQL (or sled) meaning. A
///   guarded `INSERT` inserts only when its `users` guard holds, and only then
///   can the `UNIQUE` key conflict; a guarded `UPDATE`/`DELETE` changes the one
///   matching row, or none, and reports how many; a version CAS matches only
///   the stored version; the shadow upsert inserts or bumps `version`.
/// - `run_tx` runs a plan inside an open transaction: writes go to a working
///   state, `Commit` publishes it, and a failed statement, a failed commit or
///   a plan that ends without committing leaves the state the transaction
///   began from.
/// - `run_auto` runs a plan on the pool, one statement per implicit
///   transaction: a failed statement changes nothing.
/// - `cas_tx` is the shape of both rotation transactions: the CAS, then (only
///   when it changed the row) the rest of the plan in the same transaction,
///   published by the plan's own `Commit`.
/// - `f = Some k` makes the k-th statement (from 0) fail, including a commit.
///
/// What this module trusts, and the conformance test in
/// `vela-server/src/vault/conformance.rs` checks against a real database:
/// these statement meanings, statement atomicity, the rendering of each typed
/// statement to SQL or store key, and the decoding of result rows into views.
///
/// The executor models below are the server's thin loops: plan (extracted),
/// run, classify (extracted). `vela-rekey-policy/src/executor_model.rs`
/// mirrors this module function for function.

open FStar.Mul
open Core_models
open Vela_rekey_policy.Executor

module L = FStar.List.Tot

type text = Alloc.String.t_String

/// A `vault_chunks` row; keyed by `(user_id, chunk_id, epoch)`.
type ckey = { ck_user: text; ck_id: text; ck_epoch: i64 }

noeq type chunk_row = {
  ch_user: text;
  ch_id: text;
  ch_epoch: i64;
  ch_version: i64;
  ch_lamport: i64;
  ch_last_writer: option text;
  ch_ciphertext: text;
  ch_created_at: text;
  ch_updated_at: text;
}

/// The rotation columns of a `users` row the executors read or write.
noeq type user_row = {
  us_key_epoch: i64;
  /// `None` is ACTIVE, `Some "freezing"` is FREEZING.
  us_rekey_state: option text;
  us_started: option text;
  us_starter: option text;
  us_rotation: option text;
  us_last_rekey_id: option text;
  us_last_rekey_epoch: option i64;
}

/// The device columns the executors read or write, plus the columns
/// `list_devices` serves.
noeq type device_row = {
  dv_user: text;
  dv_revoked: i64;
  dv_capable: i64;
  dv_capsule: option text;
  dv_capsule_epoch: option i64;
  dv_name: text;
  dv_type: text;
  dv_last_active: option text;
  dv_ek: text;
  dv_vk: text;
  dv_enrolled_by: option text;
  dv_revoked_at: option text;
  dv_revoked_by: option text;
  dv_created_at: text;
}

/// An `oram_buckets` row; keyed by `(user_id, tree_id, bucket_index, epoch)`.
type okey = { ok_user: text; ok_tree: text; ok_index: i64; ok_epoch: i64 }

noeq type oram_row = {
  or_user: text;
  or_tree: text;
  or_index: i64;
  or_epoch: i64;
  or_version: i64;
  or_lamport: i64;
  or_last_writer: option text;
  or_ciphertext: text;
  or_created_at: text;
  or_updated_at: text;
}

/// The tables are finite associations keyed by their full primary key.
/// `chunks` and `oram` carry their key columns in the row; a device row is
/// paired with its `id`.
type chunk_tbl = list chunk_row
type device_tbl = list (text & device_row)
type oram_tbl = list oram_row
type user_tbl = text -> option user_row
type kv_tbl = text -> option text

noeq type db = {
  chunks: chunk_tbl;
  users: user_tbl;
  devices: device_tbl;
  oram: oram_tbl;
  kv: kv_tbl;
}

let mk_ckey (user id: text) (epoch: i64) : ckey = { ck_user = user; ck_id = id; ck_epoch = epoch }
let mk_okey (user tree: text) (index epoch: i64) : okey =
  { ok_user = user; ok_tree = tree; ok_index = index; ok_epoch = epoch }

let ckey_of (r: chunk_row) : ckey =
  { ck_user = r.ch_user; ck_id = r.ch_id; ck_epoch = r.ch_epoch }
let okey_of (r: oram_row) : okey =
  { ok_user = r.or_user; ok_tree = r.or_tree; ok_index = r.or_index; ok_epoch = r.or_epoch }

// ── Finite associations ────────────────────────────────────────────────────

let rec find_chunk (l: chunk_tbl) (k: ckey) : option chunk_row =
  match l with
  | [] -> None
  | r :: tl -> if ckey_of r = k then Some r else find_chunk tl k

let rec remove_chunk (l: chunk_tbl) (k: ckey) : chunk_tbl =
  match l with
  | [] -> []
  | r :: tl -> if ckey_of r = k then remove_chunk tl k else r :: remove_chunk tl k

/// Insert `r`, replacing every row with the same key.
let set_chunk (l: chunk_tbl) (k: ckey) (r: chunk_row) : chunk_tbl =
  r :: remove_chunk l k

let rec find_device (l: device_tbl) (id: text) : option device_row =
  match l with
  | [] -> None
  | (id', r) :: tl -> if id' = id then Some r else find_device tl id

let rec remove_device (l: device_tbl) (id: text) : device_tbl =
  match l with
  | [] -> []
  | (id', r) :: tl -> if id' = id then remove_device tl id else (id', r) :: remove_device tl id

let set_device (l: device_tbl) (id: text) (r: device_row) : device_tbl =
  (id, r) :: remove_device l id

let rec find_oram (l: oram_tbl) (k: okey) : option oram_row =
  match l with
  | [] -> None
  | r :: tl -> if okey_of r = k then Some r else find_oram tl k

let rec remove_oram (l: oram_tbl) (k: okey) : oram_tbl =
  match l with
  | [] -> []
  | r :: tl -> if okey_of r = k then remove_oram tl k else r :: remove_oram tl k

let set_oram (l: oram_tbl) (k: okey) (r: oram_row) : oram_tbl =
  r :: remove_oram l k

let upd_users (t: user_tbl) (k: text) (x: option user_row) : user_tbl =
  fun k' -> if k' = k then x else t k'
let upd_kv (t: kv_tbl) (k: text) (x: option text) : kv_tbl =
  fun k' -> if k' = k then x else t k'

// ── Guards ─────────────────────────────────────────────────────────────────

let freezing (u: option user_row) : bool =
  match u with
  | Some r ->
    (match r.us_rekey_state with
     | Some s -> s = Alloc.String.String "freezing"
     | None -> false)
  | None -> false

/// `users[id]` is ACTIVE at `epoch`.
let active_at (d: db) (user: text) (epoch: i64) : bool =
  match d.users user with
  | Some r -> r.us_key_epoch = epoch && r.us_rekey_state = None
  | None -> false

/// `key_epoch = ? AND rekey_state = 'freezing' AND rekey_starter = ? AND
/// rekey_id = ?`.
let freezing_attempt (d: db) (user: text) (epoch: i64) (starter rotation: text) : bool =
  match d.users user with
  | Some r ->
    r.us_key_epoch = epoch && freezing (Some r) && r.us_starter = Some starter &&
    r.us_rotation = Some rotation
  | None -> false

let rec any_oram_in (l: oram_tbl) (user: text) : bool =
  match l with
  | [] -> false
  | r :: tl -> r.or_user = user || any_oram_in tl user

/// The freeze guard's first `NOT EXISTS`: any ORAM bucket of the account.
let any_oram (d: db) (user: text) : bool = any_oram_in d.oram user

let rec any_incapable_in (l: device_tbl) (user: text) : bool =
  match l with
  | [] -> false
  | (_, r) :: tl ->
    (r.dv_user = user && r.dv_revoked = mk_i64 0 && r.dv_capable = mk_i64 0) ||
    any_incapable_in tl user

/// An active device without a `rekey_capable` attestation.
let any_incapable (d: db) (user: text) : bool = any_incapable_in d.devices user

let rec any_pending_capsule_in (l: device_tbl) (user: text) : bool =
  match l with
  | [] -> false
  | (_, r) :: tl ->
    (r.dv_user = user && r.dv_revoked = mk_i64 0 && Some? r.dv_capsule_epoch) ||
    any_pending_capsule_in tl user

/// An active device still holding a pending capsule.
let any_pending_capsule (d: db) (user: text) : bool = any_pending_capsule_in d.devices user

let rec any_missing_shadow_in (l: chunk_tbl) (d: db) (user: text) (from_epoch to_epoch: i64)
  : bool =
  match l with
  | [] -> false
  | r :: tl ->
    (r.ch_user = user && r.ch_epoch = from_epoch &&
     None? (find_chunk d.chunks (mk_ckey user r.ch_id to_epoch))) ||
    any_missing_shadow_in tl d user from_epoch to_epoch

/// The commit's chunk-completeness probe: an old row without its shadow.
let any_missing_shadow (d: db) (user: text) (from_epoch to_epoch: i64) : bool =
  any_missing_shadow_in d.chunks d user from_epoch to_epoch

let rec any_incomplete_device_in (l: device_tbl) (user: text) (to_epoch: i64) : bool =
  match l with
  | [] -> false
  | (_, r) :: tl ->
    (r.dv_user = user && r.dv_revoked = mk_i64 0 &&
     (r.dv_capable = mk_i64 0 || None? r.dv_capsule ||
      r.dv_capsule_epoch <> Some to_epoch)) ||
    any_incomplete_device_in tl user to_epoch

/// The commit's device-completeness probe.
let any_incomplete_device (d: db) (user: text) (to_epoch: i64) : bool =
  any_incomplete_device_in d.devices user to_epoch

/// The freeze guard, computed from the state: the account is ACTIVE at
/// `from_epoch` and the three `NOT EXISTS` clauses hold.
let freeze_ready (d: db) (user: text) (from_epoch: i64) : bool =
  match d.users user with
  | Some r ->
    r.us_key_epoch = from_epoch && r.us_rekey_state = None &&
    not (any_oram d user) && not (any_incapable d user) &&
    not (any_pending_capsule d user)
  | None -> false

/// The commit guard, computed from the state.
let commit_ready (d: db) (user: text) (from_epoch to_epoch: i64) (starter rotation: text)
  : bool =
  match d.users user with
  | Some r ->
    r.us_key_epoch = from_epoch && freezing (Some r) && r.us_starter = Some starter &&
    r.us_rotation = Some rotation && not (any_missing_shadow d user from_epoch to_epoch) &&
    not (any_incomplete_device d user to_epoch)
  | None -> false

// ── Statement helpers ──────────────────────────────────────────────────────

let chunk_not_epoch (user: text) (epoch: i64) (r: chunk_row) : bool =
  r.ch_user = user && (r.ch_epoch = epoch) = false

let chunk_above (user: text) (epoch: i64) (r: chunk_row) : bool =
  r.ch_user = user && r.ch_epoch >. epoch

let chunk_below (user: text) (epoch: i64) (r: chunk_row) : bool =
  r.ch_user = user && r.ch_epoch <. epoch

let device_clears (user: text) (epoch: i64) (r: device_row) : bool =
  r.dv_user = user && r.dv_capsule_epoch = Some epoch

let clear_capsule (r: device_row) : device_row =
  { r with dv_capsule = None; dv_capsule_epoch = None }

/// Clear every capsule the attempt left on a device row.
let map_clear_capsules (user: text) (epoch: i64) (l: device_tbl) : device_tbl =
  L.map (fun (p: text & device_row) ->
           (fst p,
            (if device_clears user epoch (snd p) then clear_capsule (snd p) else snd p)))
    l

/// Keep the chunk rows the statement's predicate does not select.
let keep_chunks (p: chunk_row -> bool) (l: chunk_tbl) : chunk_tbl =
  L.filter (fun (r: chunk_row) -> not (p r)) l

// ── Statement semantics ────────────────────────────────────────────────────

/// One write statement on a state: the rows it changed and the new state, or
/// `None` when the statement errors.
let exec (d: db) (s: t_VaultStmt) : option (u64 & db) =
  match s with
  | VaultStmt_InsertChunkCreate
    { f_chunk_id = id; f_user = user; f_lamport_clock = lamport; f_last_writer = writer;
      f_ciphertext = ciphertext; f_epoch = epoch; f_now = now; f_permit_epoch = permit_epoch } ->
    if not (active_at d user permit_epoch)
    then Some (mk_u64 0, d)
    else
      let key = mk_ckey user id epoch in
      (match find_chunk d.chunks key with
       | Some _ -> None
       | None ->
         let row : chunk_row = {
           ch_user = user; ch_id = id; ch_epoch = epoch; ch_version = mk_i64 1;
           ch_lamport = lamport; ch_last_writer = Some writer; ch_ciphertext = ciphertext;
           ch_created_at = now; ch_updated_at = now
         } in
         Some (mk_u64 1, { d with chunks = set_chunk d.chunks key row }))
  | VaultStmt_InsertChunkShadow
    { f_chunk_id = id; f_user = user; f_lamport_clock = lamport; f_last_writer = writer;
      f_ciphertext = ciphertext; f_epoch = epoch; f_now = now; f_read_epoch = read_epoch;
      f_starter = starter; f_rotation_id = rotation } ->
    if not (freezing_attempt d user read_epoch starter rotation)
    then Some (mk_u64 0, d)
    else
      let key = mk_ckey user id epoch in
      let next =
        match find_chunk d.chunks key with
        | Some row ->
          set_chunk d.chunks key
            ({ row with ch_version = row.ch_version +. mk_i64 1;
                        ch_lamport = lamport; ch_last_writer = Some writer;
                        ch_ciphertext = ciphertext; ch_updated_at = now })
        | None ->
          set_chunk d.chunks key
            ({ ch_user = user; ch_id = id; ch_epoch = epoch; ch_version = mk_i64 1;
               ch_lamport = lamport; ch_last_writer = Some writer;
               ch_ciphertext = ciphertext; ch_created_at = now; ch_updated_at = now })
      in
      Some (mk_u64 1, { d with chunks = next })
  | VaultStmt_UpdateChunkCas
    { f_chunk_id = id; f_user = user; f_version = version; f_lamport_clock = lamport;
      f_last_writer = writer; f_ciphertext = ciphertext; f_epoch = epoch; f_now = now;
      f_permit_epoch = permit_epoch } ->
    let key = mk_ckey user id epoch in
    (match find_chunk d.chunks key with
     | Some row ->
       if row.ch_version = version && active_at d user permit_epoch
       then
         Some (mk_u64 1,
               { d with chunks = set_chunk d.chunks key
                   ({ row with ch_version = row.ch_version +. mk_i64 1;
                               ch_lamport = lamport; ch_last_writer = Some writer;
                               ch_ciphertext = ciphertext; ch_updated_at = now }) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_DeleteChunkCas { f_chunk_id = id; f_user = user; f_epoch = epoch } ->
    let key = mk_ckey user id epoch in
    if Some? (find_chunk d.chunks key) && active_at d user epoch
    then Some (mk_u64 1, { d with chunks = remove_chunk d.chunks key })
    else Some (mk_u64 0, d)
  | VaultStmt_DeleteChunksNotEpoch { f_user = user; f_epoch = epoch } ->
    Some (mk_u64 0, { d with chunks = keep_chunks (chunk_not_epoch user epoch) d.chunks })
  | VaultStmt_DeleteChunksAboveEpoch { f_user = user; f_epoch = epoch } ->
    Some (mk_u64 0, { d with chunks = keep_chunks (chunk_above user epoch) d.chunks })
  | VaultStmt_DeleteChunksBelowEpoch { f_user = user; f_epoch = epoch } ->
    Some (mk_u64 0, { d with chunks = keep_chunks (chunk_below user epoch) d.chunks })
  | VaultStmt_FreezeCas
    { f_user = user; f_from_epoch = from_epoch; f_now = now; f_starter = starter;
      f_rotation_id = rotation } ->
    if freeze_ready d user from_epoch
    then
      (match d.users user with
       | Some row ->
         Some (mk_u64 1,
               { d with users = upd_users d.users user
                   (Some ({ row with us_rekey_state = Some (Alloc.String.String "freezing");
                                     us_started = Some now; us_starter = Some starter;
                                     us_rotation = Some rotation })) })
       | None -> Some (mk_u64 0, d))
    else Some (mk_u64 0, d)
  | VaultStmt_CommitCas
    { f_user = user; f_from_epoch = from_epoch; f_to_epoch = to_epoch; f_starter = starter;
      f_rotation_id = rotation } ->
    if commit_ready d user from_epoch to_epoch starter rotation
    then
      (match d.users user with
       | Some row ->
         Some (mk_u64 1,
               { d with users = upd_users d.users user
                   (Some ({ row with us_key_epoch = to_epoch; us_rekey_state = None;
                                     us_started = None; us_starter = None; us_rotation = None;
                                     us_last_rekey_id = Some rotation;
                                     us_last_rekey_epoch = Some to_epoch })) })
       | None -> Some (mk_u64 0, d))
    else Some (mk_u64 0, d)
  | VaultStmt_RollbackCas { f_user = user; f_epoch = epoch; f_rotation_id = rotation } ->
    (match d.users user with
     | Some row ->
       if row.us_key_epoch = epoch && freezing (Some row) && row.us_rotation = Some rotation
       then
         Some (mk_u64 1,
               { d with users = upd_users d.users user
                   (Some ({ row with us_rekey_state = None; us_started = None;
                                     us_starter = None; us_rotation = None })) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_RefreshShadowActivity
    { f_user = user; f_read_epoch = read_epoch; f_starter = starter;
      f_rotation_id = rotation; f_now = now } ->
    (match d.users user with
     | Some row ->
       if row.us_key_epoch = read_epoch && freezing (Some row) &&
          row.us_starter = Some starter && row.us_rotation = Some rotation
       then
         Some (mk_u64 1,
               { d with users = upd_users d.users user (Some ({ row with us_started = Some now })) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_ClearAttemptCapsules { f_user = user; f_epoch = epoch } ->
    Some (mk_u64 0, { d with devices = map_clear_capsules user epoch d.devices })
  | VaultStmt_WriteDeviceCapsule
    { f_device = device; f_user = user; f_capsule = capsule; f_capsule_epoch = capsule_epoch;
      f_from_epoch = from_epoch; f_starter = starter; f_rotation_id = rotation } ->
    (match find_device d.devices device with
     | Some row ->
       if row.dv_user = user && row.dv_revoked = mk_i64 0 &&
          freezing_attempt d user from_epoch starter rotation
       then
         Some (mk_u64 1,
               { d with devices = set_device d.devices device
                   ({ row with dv_capsule = Some capsule;
                               dv_capsule_epoch = Some capsule_epoch }) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_AckDeviceCapsule { f_device = device; f_user = user; f_epoch = epoch } ->
    (match find_device d.devices device with
     | Some row ->
       if row.dv_user = user && row.dv_revoked = mk_i64 0 && row.dv_capsule_epoch = Some epoch
       then
         Some (mk_u64 1,
               { d with devices = set_device d.devices device
                   ({ row with dv_capsule = None; dv_capsule_epoch = None }) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_AttestCapable { f_device = device; f_user = user } ->
    (match find_device d.devices device with
     | Some row ->
       if row.dv_user = user && row.dv_revoked = mk_i64 0
       then
         Some (mk_u64 1,
               { d with devices = set_device d.devices device
                   ({ row with dv_capable = mk_i64 1 }) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_InsertOramBucket
    { f_user = user; f_tree_id = tree; f_bucket_index = index; f_lamport_clock = lamport;
      f_last_writer = writer; f_ciphertext = ciphertext; f_epoch = epoch; f_now = now } ->
    if not (active_at d user epoch)
    then Some (mk_u64 0, d)
    else
      let key = mk_okey user tree index epoch in
      (match find_oram d.oram key with
       | Some _ -> None
       | None ->
         let row : oram_row = {
           or_user = user; or_tree = tree; or_index = index; or_epoch = epoch;
           or_version = mk_i64 1; or_lamport = lamport; or_last_writer = Some writer;
           or_ciphertext = ciphertext; or_created_at = now; or_updated_at = now
         } in
         Some (mk_u64 1, { d with oram = set_oram d.oram key row }))
  | VaultStmt_UpdateOramBucketCas
    { f_user = user; f_tree_id = tree; f_bucket_index = index; f_version = version;
      f_lamport_clock = lamport; f_last_writer = writer; f_ciphertext = ciphertext;
      f_epoch = epoch; f_now = now } ->
    let key = mk_okey user tree index epoch in
    (match find_oram d.oram key with
     | Some row ->
       if row.or_version = version && active_at d user epoch
       then
         Some (mk_u64 1,
               { d with oram = set_oram d.oram key
                   ({ row with or_version = row.or_version +. mk_i64 1;
                               or_lamport = lamport; or_last_writer = Some writer;
                               or_ciphertext = ciphertext; or_updated_at = now }) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_SchemaFloorSet { f_key = key } ->
    Some (mk_u64 0, { d with kv = upd_kv d.kv key (Some (Alloc.String.String "2")) })
  | VaultStmt_ClearEnrollmentCapsule { f_device = device; f_user = user } ->
    (match find_device d.devices device with
     | Some row ->
       if row.dv_user = user
       then
         Some (mk_u64 1,
               { d with devices = set_device d.devices device
                   ({ row with dv_capsule = None; dv_capsule_epoch = None }) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | _ -> None

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// A plan on the pool: each statement commits on its own.
let rec run_auto (d: db) (stmts: list t_VaultStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], d)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], d)
    else
      match exec d s with
      | None -> ([WriteOutcome_Failed], d)
      | Some (n, d') ->
        let r = run_auto d' rest (k + 1) f in
        (WriteOutcome_Applied n :: fst r, snd r)

/// A plan inside an open transaction that began at `pre`.
let rec run_tx (pre work: db) (stmts: list t_VaultStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], pre)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], pre)
    else
      match s with
      | VaultStmt_Commit ->
        let r = run_tx work work rest (k + 1) f in
        (WriteOutcome_Applied (mk_u64 0) :: fst r, snd r)
      | _ ->
        match exec work s with
        | None -> ([WriteOutcome_Failed], pre)
        | Some (n, w) ->
          let r = run_tx pre w rest (k + 1) f in
          (WriteOutcome_Applied n :: fst r, snd r)

/// The transaction begin: one statement that changes nothing. Only the begin
/// plan is run this way, so any other statement is a failure.
let rec run_begin (d: db) (stmts: list t_VaultStmt) (k: nat) (f: option nat)
  : Tot (r: list t_WriteOutcome{L.length r <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> []
  | s :: rest ->
    match s with
    | VaultStmt_BeginTransaction ->
      if faulted f k
      then [WriteOutcome_Failed]
      else WriteOutcome_Applied (mk_u64 0) :: run_begin d rest (k + 1) f
    | _ -> [WriteOutcome_Failed]

/// A conditional transaction: run the first statement (the CAS) directly, and/// only when it changed a row run the rest of the plan inside the same
/// transaction, publishing at the plan's own `Commit`. A skipped CAS drops the
/// transaction; a failed statement or a plan without a `Commit` publishes
/// nothing. Both rotation transactions have this shape
/// (`[CAS, cleanup..., Commit]`), and the plan supplies every statement.
let cas_tx (pre: db) (stmts: list t_VaultStmt) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) =
  match stmts with
  | [] -> ([], pre)
  | s :: rest ->
    if faulted f 0
    then ([WriteOutcome_Failed], pre)
    else
      match exec pre s with
      | None -> ([WriteOutcome_Failed], pre)
      | Some (n, work) ->
        if n = mk_u64 0
        then ([WriteOutcome_Applied n], pre)
        else
          let r = run_tx pre work rest 1 f in
          (WriteOutcome_Applied n :: fst r, snd r)

// ── Reads ──────────────────────────────────────────────────────────────────

/// `SelectChunkVersion` on a state.
let read_chunk_version (d: db) (s: t_VaultStmt) (failed: bool)
  : t_ReadOutcome (Core_models.Option.t_Option i64) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectChunkVersion { f_chunk_id = id; f_user = user; f_epoch = epoch } ->
      (match find_chunk d.chunks (mk_ckey user id epoch) with
       | Some r -> ReadOutcome_Rows (Core_models.Option.Option_Some r.ch_version)
       | None -> ReadOutcome_Rows Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

/// `SelectChunkRow` on a state.
let read_chunk_row (d: db) (s: t_VaultStmt) (failed: bool)
  : t_ReadOutcome (Core_models.Option.t_Option t_ChunkRowView) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectChunkRow { f_chunk_id = id; f_user = user; f_epoch = epoch } ->
      (match find_chunk d.chunks (mk_ckey user id epoch) with
       | Some r ->
         ReadOutcome_Rows
           (Core_models.Option.Option_Some ({
               f_chunk_id = Core_models.Option.Option_Some id;
               f_user_id = Core_models.Option.Option_Some user;
               f_version = Core_models.Option.Option_Some r.ch_version;
               f_lamport_clock = Core_models.Option.Option_Some r.ch_lamport;
               f_last_writer =
                 (match r.ch_last_writer with
                  | Some w -> Core_models.Option.Option_Some w
                  | None -> Core_models.Option.Option_None);
               f_ciphertext = Core_models.Option.Option_Some r.ch_ciphertext;
               f_epoch = Core_models.Option.Option_Some epoch
             } <: t_ChunkRowView))
       | None -> ReadOutcome_Rows Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

/// `SelectPendingCapsule` on a state.
let read_pending (d: db) (s: t_VaultStmt) (failed: bool)
  : t_ReadOutcome (Core_models.Option.t_Option t_PendingRowView) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectPendingCapsule { f_device = device; f_user = user } ->
      (match find_device d.devices device with
       | Some r ->
         if r.dv_user = user && r.dv_revoked = mk_i64 0
         then ReadOutcome_Rows
                (Core_models.Option.Option_Some ({
                    f_epoch =
                      (match r.dv_capsule_epoch with
                       | Some e -> Core_models.Option.Option_Some e
                       | None -> Core_models.Option.Option_None)
                  } <: t_PendingRowView))
         else ReadOutcome_Rows Core_models.Option.Option_None
       | None -> ReadOutcome_Rows Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

/// The answer a read statement's query gets from the state. `SelectChunkExists`
/// and `SelectOramBucket` are the two uniqueness probes; the other five are the
/// completeness probes, each an `EXISTS` over the finite tables.
let probe_of (d: db) (s: t_VaultStmt) : bool =
  match s with
  | VaultStmt_SelectChunkExists { f_chunk_id = id; f_user = user; f_epoch = epoch } ->
    Some? (find_chunk d.chunks (mk_ckey user id epoch))
  | VaultStmt_SelectOramBucket
    { f_user = user; f_tree_id = tree; f_bucket_index = index; f_epoch = epoch } ->
    Some? (find_oram d.oram (mk_okey user tree index epoch))
  | VaultStmt_ProbeOram { f_user = user } -> any_oram d user
  | VaultStmt_ProbeCapable { f_user = user } -> any_incapable d user
  | VaultStmt_ProbeAcknowledged { f_user = user } -> any_pending_capsule d user
  | VaultStmt_ProbeChunkShadows { f_user = user; f_from_epoch = from_epoch; f_to_epoch = to_epoch } ->
    any_missing_shadow d user from_epoch to_epoch
  | VaultStmt_ProbeDeviceCapsules { f_user = user; f_to_epoch = to_epoch } ->
    any_incomplete_device d user to_epoch
  | _ -> false

/// The existence reads: the probe's computed answer, or an injected failure.
let read_exists (d: db) (s: t_VaultStmt) (failed: bool) : t_ReadOutcome bool =
  if failed then ReadOutcome_Failed else ReadOutcome_Rows (probe_of d s)

/// One `SelectInventory` row.
let inventory_row (r: chunk_row) : t_InventoryRowView = {
  f_chunk_id = Core_models.Option.Option_Some r.ch_id;
  f_version = Core_models.Option.Option_Some r.ch_version;
  f_lamport_clock = Core_models.Option.Option_Some r.ch_lamport;
}

/// The inventory rows of one account at one epoch, as the query returns them.
let rec inventory_rows_in (l: chunk_tbl) (user: text) (epoch: i64)
  : list t_InventoryRowView =
  match l with
  | [] -> []
  | r :: tl ->
    if r.ch_user = user && r.ch_epoch = epoch
    then inventory_row r :: inventory_rows_in tl user epoch
    else inventory_rows_in tl user epoch

let inventory_rows (d: db) (user: text) (epoch: i64) : list t_InventoryRowView =
  inventory_rows_in d.chunks user epoch

/// The inventory read: it accepts the rows the query returned only when they
/// are exactly the account's rows at `epoch` as computed from the state, so the
/// row set is a function of the state and not an input. An injected failure, a
/// different row set, or a non-inventory statement is `Failed`.
let read_inventory (d: db) (s: t_VaultStmt)
      (rows: Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global) (failed: bool)
  : t_ReadOutcome (Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectInventory { f_user = user; f_epoch = epoch } ->
      if Seq.seq_to_list rows._0 = inventory_rows d user epoch
      then ReadOutcome_Rows rows
      else ReadOutcome_Failed
    | _ -> ReadOutcome_Failed

// ── Handler I/O outside executor methods (F-1 wave 2) ─────────────────────
//
// `load_key_state`; the two usage reads and the projected-storage read; the
// ORAM path bucket read; the sync manifest; the schema-floor store read; the
// capsule delivery's read and read-once clear; the device listing; and the
// transaction begin. Each is the extracted plan, its SQL or store meaning
// here, and the extracted classifier.

/// The model's own option, as the extracted row views carry it.
let to_opt (#a: Type) (o: option a) : Core_models.Option.t_Option a =
  match o with
  | Some x -> Core_models.Option.Option_Some x
  | None -> Core_models.Option.Option_None

/// `LENGTH(ciphertext)` over the base64 text the handlers store, which is
/// ASCII, so its byte length is its string length.
let text_len (t: text) : nat = FStar.String.length t._0

/// A `nat` sum as the `i64` the query returns. Saturating under the machine
/// maximum, where every conformance state is.
let nat_i64 (n: nat) : i64 =
  if n <= maxint I64 then mk_i64 n else mk_i64 (maxint I64)

/// The seven rotation cells of a `users` row.
let key_state_view_of (r: user_row) : t_KeyStateView = {
  f_key_epoch = to_opt (Some r.us_key_epoch);
  f_rekey_state = to_opt r.us_rekey_state;
  f_rekey_started_at = to_opt r.us_started;
  f_rekey_starter = to_opt r.us_starter;
  f_rekey_id = to_opt r.us_rotation;
  f_last_rekey_id = to_opt r.us_last_rekey_id;
  f_last_rekey_epoch = to_opt r.us_last_rekey_epoch;
}

/// `SelectKeyState` on a state.
let read_key_state (d: db) (s: t_VaultStmt) (failed: bool)
  : t_ReadOutcome (Core_models.Option.t_Option t_KeyStateView) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectKeyState { f_user = user } ->
      (match d.users user with
       | Some r -> ReadOutcome_Rows (Core_models.Option.Option_Some (key_state_view_of r))
       | None -> ReadOutcome_Rows Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

/// `SUM(LENGTH(ciphertext))` over one account's chunk rows at one epoch.
let rec sum_chunk_len_at (l: chunk_tbl) (user: text) (epoch: i64) : nat =
  match l with
  | [] -> 0
  | r :: tl ->
    (if r.ch_user = user && r.ch_epoch = epoch then text_len r.ch_ciphertext else 0) +
    sum_chunk_len_at tl user epoch

/// `SUM(LENGTH(ciphertext))` over one account's ORAM rows at one epoch.
let rec sum_oram_len_at (l: oram_tbl) (user: text) (epoch: i64) : nat =
  match l with
  | [] -> 0
  | r :: tl ->
    (if r.or_user = user && r.or_epoch = epoch then text_len r.or_ciphertext else 0) +
    sum_oram_len_at tl user epoch

/// `SUM(LENGTH(ciphertext))` over every ORAM row of one account.
let rec sum_oram_len_all (l: oram_tbl) (user: text) : nat =
  match l with
  | [] -> 0
  | r :: tl ->
    (if r.or_user = user then text_len r.or_ciphertext else 0) + sum_oram_len_all tl user

/// `current_usage_bytes`' chunk total: the account's served epoch.
let chunk_usage (d: db) (user: text) : nat =
  match d.users user with
  | Some u -> sum_chunk_len_at d.chunks user u.us_key_epoch
  | None -> 0

/// `current_usage_bytes`' ORAM total: the account's served epoch.
let oram_usage (d: db) (user: text) : nat =
  match d.users user with
  | Some u -> sum_oram_len_at d.oram user u.us_key_epoch
  | None -> 0

/// `enforce_rekey_shadow_quota`'s chunk total: this epoch, minus the replaced
/// chunk.
let rec sum_chunk_len_projected
      (l: chunk_tbl) (user: text) (epoch: i64) (chunk_id: text)
  : nat =
  match l with
  | [] -> 0
  | r :: tl ->
    (if r.ch_user = user && r.ch_epoch = epoch && not (r.ch_id = chunk_id)
     then text_len r.ch_ciphertext else 0) +
    sum_chunk_len_projected tl user epoch chunk_id

/// The projected stored bytes after a rotation replaces `chunk_id`.
let projected_usage (d: db) (user: text) (epoch: i64) (chunk_id: text) : nat =
  sum_chunk_len_projected d.chunks user epoch chunk_id + sum_oram_len_all d.oram user

/// `SelectUsageChunks`: the query's total, accepted only when it is the
/// model's sum over the state.
let read_usage_chunks (d: db) (s: t_VaultStmt) (amount: i64) (failed: bool)
  : t_ReadOutcome i64 =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectUsageChunks { f_user = user } ->
      if amount = nat_i64 (chunk_usage d user)
      then ReadOutcome_Rows amount
      else ReadOutcome_Failed
    | _ -> ReadOutcome_Failed

/// `SelectUsageOram`: the query's total, accepted only when it is the model's
/// sum over the state.
let read_usage_oram (d: db) (s: t_VaultStmt) (amount: i64) (failed: bool)
  : t_ReadOutcome i64 =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectUsageOram { f_user = user } ->
      if amount = nat_i64 (oram_usage d user)
      then ReadOutcome_Rows amount
      else ReadOutcome_Failed
    | _ -> ReadOutcome_Failed

/// `SelectRekeyProjection`: the query's total, accepted only when it is the
/// model's projected usage.
let read_rekey_projection
      (d: db) (s: t_VaultStmt) (amount: i64) (failed: bool)
  : t_ReadOutcome i64 =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectRekeyProjection { f_user = user; f_epoch = epoch;
                                        f_chunk_id = chunk_id } ->
      if amount = nat_i64 (projected_usage d user epoch chunk_id)
      then ReadOutcome_Rows amount
      else ReadOutcome_Failed
    | _ -> ReadOutcome_Failed

/// One `oram_buckets` row as `get_path` decodes it.
let oram_view_of (r: oram_row) : t_OramRowView = {
  f_version = to_opt (Some r.or_version);
  f_lamport_clock = to_opt (Some r.or_lamport);
  f_last_writer = to_opt r.or_last_writer;
  f_ciphertext = to_opt (Some r.or_ciphertext);
}

/// `SelectOramRow` on a state.
let read_oram_row (d: db) (s: t_VaultStmt) (failed: bool)
  : t_ReadOutcome (Core_models.Option.t_Option t_OramRowView) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectOramRow { f_user = user; f_tree_id = tree;
                                f_bucket_index = index; f_epoch = epoch } ->
      (match find_oram d.oram (mk_okey user tree index epoch) with
       | Some r -> ReadOutcome_Rows (Core_models.Option.Option_Some (oram_view_of r))
       | None -> ReadOutcome_Rows Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

/// One `SelectSyncManifest` row.
let sync_view_of (r: chunk_row) : t_SyncRowView = {
  f_chunk_id = Core_models.Option.Option_Some r.ch_id;
  f_version = Core_models.Option.Option_Some r.ch_version;
  f_lamport_clock = Core_models.Option.Option_Some r.ch_lamport;
  f_last_writer = to_opt r.ch_last_writer;
}

/// The manifest rows of one account at one epoch.
let rec sync_rows_in (l: chunk_tbl) (user: text) (epoch: i64)
  : list t_SyncRowView =
  match l with
  | [] -> []
  | r :: tl ->
    if r.ch_user = user && r.ch_epoch = epoch
    then sync_view_of r :: sync_rows_in tl user epoch
    else sync_rows_in tl user epoch

let sync_rows (d: db) (user: text) (epoch: i64) : list t_SyncRowView =
  sync_rows_in d.chunks user epoch

/// The manifest read accepts the rows the query returned only when they are
/// exactly the account's rows at `epoch` computed from the state.
let read_sync
      (d: db) (s: t_VaultStmt)
      (rows: Alloc.Vec.t_Vec t_SyncRowView Alloc.Alloc.t_Global) (failed: bool)
  : t_ReadOutcome (Alloc.Vec.t_Vec t_SyncRowView Alloc.Alloc.t_Global) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectSyncManifest { f_user = user; f_epoch = epoch } ->
      if Seq.seq_to_list rows._0 = sync_rows d user epoch
      then ReadOutcome_Rows rows
      else ReadOutcome_Failed
    | _ -> ReadOutcome_Failed

/// The schema-floor read: the stored value, computed from the model's store.
let read_schema_floor (d: db) (s: t_VaultStmt) (failed: bool)
  : t_ReadOutcome (Core_models.Option.t_Option text) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SchemaFloorGet { f_key = key } ->
      ReadOutcome_Rows (to_opt (d.kv key))
    | _ -> ReadOutcome_Failed

/// The pending capsule a device holds, as `SelectCapsule` returns it.
let capsule_view_of (d: db) (device: text) (user: text) : option t_CapsuleView =
  match find_device d.devices device with
  | Some row ->
    if row.dv_user = user && row.dv_revoked = mk_i64 0
    then
      (match row.dv_capsule, d.users user with
       | Some capsule, Some account ->
         Some {
           f_capsule = to_opt (Some capsule);
           f_capsule_epoch = to_opt row.dv_capsule_epoch;
           f_rotation_id =
             to_opt
               (match row.dv_capsule_epoch, account.us_last_rekey_epoch with
                | Some recorded, Some committed ->
                  if recorded = committed then account.us_last_rekey_id else None
                | _ -> None)
         }
       | _ -> None)
    else None
  | None -> None

/// `SelectCapsule` on a state.
let read_capsule (d: db) (s: t_VaultStmt) (failed: bool)
  : t_ReadOutcome (Core_models.Option.t_Option t_CapsuleView) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectCapsule { f_device = device; f_user = user } ->
      ReadOutcome_Rows (to_opt (capsule_view_of d device user))
    | _ -> ReadOutcome_Failed

/// One `devices` row as `list_devices` serves it.
let device_list_view_of (id: text) (r: device_row) : t_DeviceListRowView = {
  f_id = Core_models.Option.Option_Some id;
  f_user_id = Core_models.Option.Option_Some r.dv_user;
  f_device_name = Core_models.Option.Option_Some r.dv_name;
  f_device_type = Core_models.Option.Option_Some r.dv_type;
  f_last_active = to_opt r.dv_last_active;
  f_hybrid_ek = Core_models.Option.Option_Some r.dv_ek;
  f_hybrid_vk = Core_models.Option.Option_Some r.dv_vk;
  f_enrolled_by = to_opt r.dv_enrolled_by;
  f_rms_capsule = to_opt r.dv_capsule;
  f_revoked = Core_models.Option.Option_Some r.dv_revoked;
  f_revoked_at = to_opt r.dv_revoked_at;
  f_revoked_by = to_opt r.dv_revoked_by;
  f_created_at = Core_models.Option.Option_Some r.dv_created_at;
  f_rekey_capable = Core_models.Option.Option_Some r.dv_capable;
}

/// The account's devices in the listing's order, capped at `room`.
let rec device_list_rows_in (l: device_tbl) (user: text) (room: nat)
  : list t_DeviceListRowView =
  match l with
  | [] -> []
  | (id, r) :: tl ->
    if room = 0
    then []
    else if r.dv_user = user
         then device_list_view_of id r :: device_list_rows_in tl user (room - 1)
         else device_list_rows_in tl user room

/// The rows `SelectDeviceList` selects (`LIMIT 1000`).
let device_list_rows (d: db) (user: text) : list t_DeviceListRowView =
  device_list_rows_in d.devices user 1000

/// The listing read accepts the rows the query returned only when they are
/// exactly the account's devices computed from the state.
let read_device_list
      (d: db) (s: t_VaultStmt)
      (rows: Alloc.Vec.t_Vec t_DeviceListRowView Alloc.Alloc.t_Global) (failed: bool)
  : t_ReadOutcome (Alloc.Vec.t_Vec t_DeviceListRowView Alloc.Alloc.t_Global) =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | VaultStmt_SelectDeviceList { f_user = user } ->
      if Seq.seq_to_list rows._0 = device_list_rows d user
      then ReadOutcome_Rows rows
      else ReadOutcome_Failed
    | _ -> ReadOutcome_Failed

// ── Outcome slices ─────────────────────────────────────────────────────────
let stmts_of (p: Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global) : list t_VaultStmt =
  Seq.seq_to_list p._0

let slice_of (l: list t_WriteOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : t_Slice t_WriteOutcome =
  Seq.seq_of_list l
