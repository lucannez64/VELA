module Vela_rekey_policy_executor_model

/// A model of the tables and store keys the vault, rekey, capsule, ORAM and
/// schema executors touch, and of how their statement plans run on them (F-1).
///
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
/// statement to SQL or store key, the decoding of result rows into views, and
/// the `EXISTS` predicates of the five completeness probes and the inventory
/// row set (a functional table cannot decide or enumerate them; the probe
/// answer and the inventory rows are inputs here, and the conformance test
/// compares them with the Rust mirror on a real database).
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

/// The device columns the executors read or write.
noeq type device_row = {
  dv_user: text;
  dv_revoked: i64;
  dv_capable: i64;
  dv_capsule: option text;
  dv_capsule_epoch: option i64;
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

type chunk_tbl = ckey -> option chunk_row
type user_tbl = text -> option user_row
type device_tbl = text -> option device_row
type oram_tbl = okey -> option oram_row
type kv_tbl = text -> option text

noeq type db = {
  chunks: chunk_tbl;
  users: user_tbl;
  devices: device_tbl;
  oram: oram_tbl;
  kv: kv_tbl;
}

/// The answers the database gives to the `NOT EXISTS` sub-queries of the two
/// account CAS statements. They are inputs, not computed here: a functional
/// table cannot decide an existential over an infinite id type. The
/// `*_guard_is_honest` lemmas in the lemma module state exactly what it means
/// for them to be the truth, and the conformance test checks that the real
/// database gives those answers on small states.
noeq type answers = {
  a_oram_empty: bool;
  a_devices_ready: bool;
  a_capsules_free: bool;
  a_shadows_ready: bool;
  a_capsules_complete: bool;
}

let mk_ckey (user id: text) (epoch: i64) : ckey = { ck_user = user; ck_id = id; ck_epoch = epoch }
let mk_okey (user tree: text) (index epoch: i64) : okey =
  { ok_user = user; ok_tree = tree; ok_index = index; ok_epoch = epoch }

let upd_chunks (t: chunk_tbl) (k: ckey) (x: option chunk_row) : chunk_tbl =
  fun k' -> if k' = k then x else t k'
let upd_users (t: user_tbl) (k: text) (x: option user_row) : user_tbl =
  fun k' -> if k' = k then x else t k'
let upd_devices (t: device_tbl) (k: text) (x: option device_row) : device_tbl =
  fun k' -> if k' = k then x else t k'
let upd_oram (t: oram_tbl) (k: okey) (x: option oram_row) : oram_tbl =
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

/// The freeze guard's first `NOT EXISTS`: any ORAM bucket of the account.
let any_oram (d: db) (user: text) : prop =
  exists (index epoch: i64) (tree: text). Some? (d.oram (mk_okey user tree index epoch))

/// An active device without a `rekey_capable` attestation.
let any_incapable (d: db) (user: text) : prop =
  exists (id: text). (match d.devices id with
                      | Some r -> r.dv_user = user && r.dv_revoked = mk_i64 0 && r.dv_capable = mk_i64 0
                      | None -> False)

/// An active device still holding a pending capsule.
let any_pending_capsule (d: db) (user: text) : prop =
  exists (id: text). (match d.devices id with
                      | Some r -> r.dv_user = user && r.dv_revoked = mk_i64 0 && Some? r.dv_capsule_epoch
                      | None -> False)

/// The commit's chunk-completeness probe: an old row without its shadow.
let any_missing_shadow (d: db) (user: text) (from_epoch to_epoch: i64) : prop =
  exists (id: text).
    Some? (d.chunks (mk_ckey user id from_epoch)) /\ None? (d.chunks (mk_ckey user id to_epoch))

/// The commit's device-completeness probe.
let any_incomplete_device (d: db) (user: text) (to_epoch: i64) : prop =
  exists (id: text). (match d.devices id with
                      | Some r ->
                        r.dv_user = user && r.dv_revoked = mk_i64 0 &&
                        (r.dv_capable = mk_i64 0 || None? r.dv_capsule ||
                         r.dv_capsule_epoch <> Some to_epoch)
                      | None -> False)

/// The freeze guard, as the SQL's three `NOT EXISTS` clauses evaluate it.
let freeze_ready (g: answers) (d: db) (user: text) (from_epoch: i64) : bool =
  match d.users user with
  | Some r ->
    r.us_key_epoch = from_epoch && r.us_rekey_state = None && g.a_oram_empty &&
    g.a_devices_ready && g.a_capsules_free
  | None -> false

/// The commit guard.
let commit_ready
      (g: answers) (d: db) (user: text) (from_epoch to_epoch: i64) (starter rotation: text)
  : bool =
  match d.users user with
  | Some r ->
    r.us_key_epoch = from_epoch && freezing (Some r) && r.us_starter = Some starter &&
    r.us_rotation = Some rotation && g.a_shadows_ready && g.a_capsules_complete
  | None -> false

// ── Statement semantics ────────────────────────────────────────────────────

/// One write statement on a state: the rows it changed and the new state, or
/// `None` when the statement errors.
let exec (g: answers) (d: db) (s: t_VaultStmt) : option (u64 & db) =
  match s with
  | VaultStmt_InsertChunkCreate
    { f_chunk_id = id; f_user = user; f_lamport_clock = lamport; f_last_writer = writer;
      f_ciphertext = ciphertext; f_epoch = epoch; f_now = now; f_permit_epoch = permit_epoch } ->
    if not (active_at d user permit_epoch)
    then Some (mk_u64 0, d)
    else
      let key = mk_ckey user id epoch in
      (match d.chunks key with
       | Some _ -> None
       | None ->
         let row : chunk_row = {
           ch_user = user; ch_id = id; ch_epoch = epoch; ch_version = mk_i64 1;
           ch_lamport = lamport; ch_last_writer = Some writer; ch_ciphertext = ciphertext;
           ch_created_at = now; ch_updated_at = now
         } in
         Some (mk_u64 1, { d with chunks = upd_chunks d.chunks key (Some row) }))
  | VaultStmt_InsertChunkShadow
    { f_chunk_id = id; f_user = user; f_lamport_clock = lamport; f_last_writer = writer;
      f_ciphertext = ciphertext; f_epoch = epoch; f_now = now; f_read_epoch = read_epoch;
      f_starter = starter; f_rotation_id = rotation } ->
    if not (freezing_attempt d user read_epoch starter rotation)
    then Some (mk_u64 0, d)
    else
      let key = mk_ckey user id epoch in
      let next =
        match d.chunks key with
        | Some row ->
          { d with chunks = upd_chunks d.chunks key
              (Some ({ row with ch_version = row.ch_version +. mk_i64 1;
                                ch_lamport = lamport; ch_last_writer = Some writer;
                                ch_ciphertext = ciphertext; ch_updated_at = now })) }
        | None ->
          { d with chunks = upd_chunks d.chunks key
              (Some ({ ch_user = user; ch_id = id; ch_epoch = epoch; ch_version = mk_i64 1;
                       ch_lamport = lamport; ch_last_writer = Some writer;
                       ch_ciphertext = ciphertext; ch_created_at = now; ch_updated_at = now })) }
      in
      Some (mk_u64 1, next)
  | VaultStmt_UpdateChunkCas
    { f_chunk_id = id; f_user = user; f_version = version; f_lamport_clock = lamport;
      f_last_writer = writer; f_ciphertext = ciphertext; f_epoch = epoch; f_now = now;
      f_permit_epoch = permit_epoch } ->
    let key = mk_ckey user id epoch in
    (match d.chunks key with
     | Some row ->
       if row.ch_version = version && active_at d user permit_epoch
       then
         Some (mk_u64 1,
               { d with chunks = upd_chunks d.chunks key
                   (Some ({ row with ch_version = row.ch_version +. mk_i64 1;
                                     ch_lamport = lamport; ch_last_writer = Some writer;
                                     ch_ciphertext = ciphertext; ch_updated_at = now })) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_DeleteChunkCas { f_chunk_id = id; f_user = user; f_epoch = epoch } ->
    let key = mk_ckey user id epoch in
    if Some? (d.chunks key) && active_at d user epoch
    then Some (mk_u64 1, { d with chunks = upd_chunks d.chunks key None })
    else Some (mk_u64 0, d)
  | VaultStmt_DeleteChunksNotEpoch { f_user = user; f_epoch = epoch } ->
    Some (mk_u64 0,
          { d with chunks = (fun k ->
              if k.ck_user = user && (k.ck_epoch = epoch) = false then None else d.chunks k) })
  | VaultStmt_DeleteChunksAboveEpoch { f_user = user; f_epoch = epoch } ->
    Some (mk_u64 0,
          { d with chunks = (fun k ->
              if k.ck_user = user && k.ck_epoch >. epoch then None else d.chunks k) })
  | VaultStmt_DeleteChunksBelowEpoch { f_user = user; f_epoch = epoch } ->
    Some (mk_u64 0,
          { d with chunks = (fun k ->
              if k.ck_user = user && k.ck_epoch <. epoch then None else d.chunks k) })
  | VaultStmt_FreezeCas
    { f_user = user; f_from_epoch = from_epoch; f_now = now; f_starter = starter;
      f_rotation_id = rotation } ->
    if freeze_ready g d user from_epoch
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
    if commit_ready g d user from_epoch to_epoch starter rotation
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
    Some (mk_u64 0,
          { d with devices = (fun id ->
              match d.devices id with
              | Some r ->
                if r.dv_user = user && r.dv_capsule_epoch = Some epoch
                then Some ({ r with dv_capsule = None; dv_capsule_epoch = None })
                else Some r
              | None -> None) })
  | VaultStmt_WriteDeviceCapsule
    { f_device = device; f_user = user; f_capsule = capsule; f_capsule_epoch = capsule_epoch;
      f_from_epoch = from_epoch; f_starter = starter; f_rotation_id = rotation } ->
    (match d.devices device with
     | Some row ->
       if row.dv_user = user && row.dv_revoked = mk_i64 0 &&
          freezing_attempt d user from_epoch starter rotation
       then
         Some (mk_u64 1,
               { d with devices = upd_devices d.devices device
                   (Some ({ row with dv_capsule = Some capsule;
                                     dv_capsule_epoch = Some capsule_epoch })) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_AckDeviceCapsule { f_device = device; f_user = user; f_epoch = epoch } ->
    (match d.devices device with
     | Some row ->
       if row.dv_user = user && row.dv_revoked = mk_i64 0 && row.dv_capsule_epoch = Some epoch
       then
         Some (mk_u64 1,
               { d with devices = upd_devices d.devices device
                   (Some ({ row with dv_capsule = None; dv_capsule_epoch = None })) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_AttestCapable { f_device = device; f_user = user } ->
    (match d.devices device with
     | Some row ->
       if row.dv_user = user && row.dv_revoked = mk_i64 0
       then
         Some (mk_u64 1,
               { d with devices = upd_devices d.devices device
                   (Some ({ row with dv_capable = mk_i64 1 })) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_InsertOramBucket
    { f_user = user; f_tree_id = tree; f_bucket_index = index; f_lamport_clock = lamport;
      f_last_writer = writer; f_ciphertext = ciphertext; f_epoch = epoch; f_now = now } ->
    if not (active_at d user epoch)
    then Some (mk_u64 0, d)
    else
      let key = mk_okey user tree index epoch in
      (match d.oram key with
       | Some _ -> None
       | None ->
         let row : oram_row = {
           or_user = user; or_tree = tree; or_index = index; or_epoch = epoch;
           or_version = mk_i64 1; or_lamport = lamport; or_last_writer = Some writer;
           or_ciphertext = ciphertext; or_created_at = now; or_updated_at = now
         } in
         Some (mk_u64 1, { d with oram = upd_oram d.oram key (Some row) }))
  | VaultStmt_UpdateOramBucketCas
    { f_user = user; f_tree_id = tree; f_bucket_index = index; f_version = version;
      f_lamport_clock = lamport; f_last_writer = writer; f_ciphertext = ciphertext;
      f_epoch = epoch; f_now = now } ->
    let key = mk_okey user tree index epoch in
    (match d.oram key with
     | Some row ->
       if row.or_version = version && active_at d user epoch
       then
         Some (mk_u64 1,
               { d with oram = upd_oram d.oram key
                   (Some ({ row with or_version = row.or_version +. mk_i64 1;
                                     or_lamport = lamport; or_last_writer = Some writer;
                                     or_ciphertext = ciphertext; or_updated_at = now })) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | VaultStmt_SchemaFloorSet { f_key = key } ->
    Some (mk_u64 0, { d with kv = upd_kv d.kv key (Some (Alloc.String.String "2")) })
  | _ -> None

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// A plan on the pool: each statement commits on its own.
let rec run_auto (g: answers) (d: db) (stmts: list t_VaultStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], d)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], d)
    else
      match exec g d s with
      | None -> ([WriteOutcome_Failed], d)
      | Some (n, d') ->
        let r = run_auto g d' rest (k + 1) f in
        (WriteOutcome_Applied n :: fst r, snd r)

/// A plan inside an open transaction that began at `pre`.
let rec run_tx (g: answers) (pre work: db) (stmts: list t_VaultStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], pre)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], pre)
    else
      match s with
      | VaultStmt_Commit ->
        let r = run_tx g work work rest (k + 1) f in
        (WriteOutcome_Applied (mk_u64 0) :: fst r, snd r)
      | _ ->
        match exec g work s with
        | None -> ([WriteOutcome_Failed], pre)
        | Some (n, w) ->
          let r = run_tx g pre w rest (k + 1) f in
          (WriteOutcome_Applied n :: fst r, snd r)

/// A conditional transaction: run the first statement (the CAS) directly, and
/// only when it changed a row run the rest of the plan inside the same
/// transaction, publishing at the plan's own `Commit`. A skipped CAS drops the
/// transaction; a failed statement or a plan without a `Commit` publishes
/// nothing. Both rotation transactions have this shape
/// (`[CAS, cleanup..., Commit]`), and the plan supplies every statement.
let cas_tx (g: answers) (pre: db) (stmts: list t_VaultStmt) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) =
  match stmts with
  | [] -> ([], pre)
  | s :: rest ->
    if faulted f 0
    then ([WriteOutcome_Failed], pre)
    else
      match exec g pre s with
      | None -> ([WriteOutcome_Failed], pre)
      | Some (n, work) ->
        if n = mk_u64 0
        then ([WriteOutcome_Applied n], pre)
        else
          let r = run_tx g pre work rest 1 f in
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
      (match d.chunks (mk_ckey user id epoch) with
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
      (match d.chunks (mk_ckey user id epoch) with
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
      (match d.devices device with
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

/// The existence reads: `SelectChunkExists`, `SelectOramBucket` and the five
/// completeness probes. `found` is the store's answer to the statement's
/// `EXISTS`/`SELECT 1` query; the conformance test checks that answer and the
/// rendered predicate against a real database (see the module header).
let read_exists (s: t_VaultStmt) (found: bool) (failed: bool) : t_ReadOutcome bool =
  if failed then ReadOutcome_Failed else ReadOutcome_Rows found

/// The inventory read. `rows` are the rows the query returned; the conformance
/// test checks them against the Rust mirror (see the module header).
let read_inventory
      (s: t_VaultStmt)
      (rows: Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global)
      (failed: bool)
  : t_ReadOutcome (Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global) =
  if failed then ReadOutcome_Failed else ReadOutcome_Rows rows

// ── Outcome slices ─────────────────────────────────────────────────────────

let stmts_of (p: Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global) : list t_VaultStmt =
  Seq.seq_to_list p._0

let slice_of (l: list t_WriteOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : t_Slice t_WriteOutcome =
  Seq.seq_of_list l

