module Vela_share_policy_store_model

/// A model of the tables the sharing executors touch, and of how the
/// executors' statement plans run on them (F-1).
///
/// Every table is keyed by its `UNIQUE` id column, so a table is a partial
/// map from id to row and "every starting database" is every four maps.
/// Only the columns the sharing statements read or write are modelled.
///
/// - `exec` gives each typed write statement its SQL meaning: an `INSERT`
///   of a present id errors (the `UNIQUE` constraint); a guarded `UPDATE` or
///   `DELETE` changes the one matching row, or none, and reports how many.
/// - `run_tx` runs a plan inside an open transaction: writes go to a working
///   state, `Commit` publishes it, and a failed statement, a failed commit or
///   a plan that ends without committing leaves the state the transaction
///   began from (the handler drops the transaction, which rolls it back).
/// - `run_auto` runs a plan on the pool, one statement per implicit
///   transaction: a failed statement changes nothing.
/// - `f = Some k` makes the k-th statement (from 0) fail: any statement,
///   including the commit, may be the one that fails.
///
/// What this module trusts, and the conformance test in
/// `vela-server/src/share/conformance.rs` checks against a real database:
/// these statement meanings, statement atomicity, the rendering of each
/// typed statement to SQL, and the decoding of result rows into views.
///
/// The executor models below (`send_insert` ... `observe_device`) are the
/// server's thin loop: plan (extracted), run, classify (extracted).
/// `vela-share-policy/src/store_model.rs` mirrors this module function for
/// function; its `shared_vectors` test and the `vector_*` lemmas in
/// `Vela_share_policy_store_lemmas` check the same concrete runs.

open FStar.Mul
open Core_models
open Vela_share_policy.Store

module L = FStar.List.Tot

type text = Alloc.String.t_String

/// A `shared_items` row.
type item = {
  it_sender: text;
  it_recipient: text;
  it_capsule: text;
  it_created_at: text;
  it_updated_at: text;
  it_revoked: i64;
}

/// A `share_inbox` row.
type inbox_row = {
  ib_sender: text;
  ib_recipient: text;
  ib_capsule: text;
  ib_created_at: text;
}

/// The share-key columns of a `users` row.
type user_row = {
  us_share_ek: option text;
  us_share_ek_since: option text;
  us_share_ek_device_id: option text;
}

/// The columns of a `devices` row the device read returns.
type device_row = {
  dv_user_id: text;
  dv_hybrid_vk: text;
  dv_revoked: i64;
}

/// A `sends` row (one-off share links). The handler stores timestamps as
/// text; `db.clock` is the model's order on that text.
type send_row = {
  sd_owner: text;
  sd_ciphertext: text;
  sd_has_passphrase: i64;
  sd_kdf_salt: Core_models.Option.t_Option text;
  sd_label: Core_models.Option.t_Option text;
  sd_view_once: i64;
  sd_max_views: Core_models.Option.t_Option i64;
  sd_view_count: i64;
  sd_created_at: text;
  sd_expires_at: text;
  sd_revoked: i64;
}

type tbl (a: Type) = text -> option a

let upd (#a: Type) (t: tbl a) (k: text) (x: option a) : tbl a =
  fun k' -> if k' = k then x else t k'

noeq type db = {
  items: tbl item;
  inbox: tbl inbox_row;
  users: tbl user_row;
  devices: tbl device_row;
  sends: tbl send_row;
  /// The order the database compares stored timestamps with: SQLite compares
  /// them as text, which for the handler's RFC3339 cells is chronological
  /// order. It is a parameter of the model, not an axiom; the conformance
  /// test supplies the engine's own comparison.
  clock: text -> text -> bool;
}

// ── Statement semantics ────────────────────────────────────────────────────

/// One write statement on a state: the rows it changed and the new state, or
/// `None` when the statement errors. Reads and `Commit` are not writes.
let exec (d: db) (s: t_ShareStmt) : option (u64 & db) =
  match s with
  | ShareStmt_InsertSharedItem
    { f_id = id; f_sender = sender; f_recipient = recipient; f_capsule = capsule; f_now = now } ->
    (match d.items id with
     | Some _ -> None
     | None ->
       let row : item = {
         it_sender = sender;
         it_recipient = recipient;
         it_capsule = capsule;
         it_created_at = now;
         it_updated_at = now;
         it_revoked = mk_i64 0;
       } in
       Some (mk_u64 1, { d with items = upd d.items id (Some row) }))
  | ShareStmt_InsertInboxItem
    { f_id = id; f_sender = sender; f_recipient = recipient; f_capsule = capsule; f_now = now } ->
    (match d.inbox id with
     | Some _ -> None
     | None ->
       let row : inbox_row = {
         ib_sender = sender;
         ib_recipient = recipient;
         ib_capsule = capsule;
         ib_created_at = now;
       } in
       Some (mk_u64 1, { d with inbox = upd d.inbox id (Some row) }))
  | ShareStmt_UpdateLinkedCapsule { f_capsule = capsule; f_now = now; f_id = id; f_sender = sender } ->
    (match d.items id with
     | Some r ->
       if r.it_sender = sender && r.it_revoked = mk_i64 0
       then
         let row : item = { r with it_capsule = capsule; it_updated_at = now } in
         Some (mk_u64 1, { d with items = upd d.items id (Some row) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | ShareStmt_RevokeLinkedItem { f_now = now; f_id = id; f_sender = sender } ->
    (match d.items id with
     | Some r ->
       if r.it_sender = sender && r.it_revoked = mk_i64 0
       then
         let row : item = { r with it_revoked = mk_i64 1; it_updated_at = now } in
         Some (mk_u64 1, { d with items = upd d.items id (Some row) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | ShareStmt_DeleteLinkedInbox { f_id = id } ->
    (match d.inbox id with
     | Some _ -> Some (mk_u64 1, { d with inbox = upd d.inbox id None })
     | None -> Some (mk_u64 0, d))
  | ShareStmt_DeleteInboxItem { f_id = id; f_recipient = recipient } ->
    (match d.inbox id with
     | Some r ->
       if r.ib_recipient = recipient
       then Some (mk_u64 1, { d with inbox = upd d.inbox id None })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | ShareStmt_UpdateShareEk { f_share_ek = ek; f_since = since; f_device_id = device; f_user = user } ->
    (match d.users user with
     | Some _ ->
       let row : user_row = {
         us_share_ek = Some ek;
         us_share_ek_since = Some since;
         us_share_ek_device_id = Some device;
       } in
       Some (mk_u64 1, { d with users = upd d.users user (Some row) })
     | None -> Some (mk_u64 0, d))
  | _ -> None

// ── The one-off share-link statements ─────────────────────────────────────

/// The SQL guard of the view consume: unrevoked, unexpired at `now`, and a
/// view remaining (`max_views IS NULL OR view_count < max_views`).
let send_live (d: db) (r: send_row) (now: text) : bool =
  r.sd_revoked = mk_i64 0 &&
  d.clock r.sd_expires_at now &&
  (match r.sd_max_views with
   | Core_models.Option.Option_Some m -> r.sd_view_count <. m
   | Core_models.Option.Option_None -> true)

/// One `sends` write statement: the rows it changed and the new state, or
/// `None` when it errors. The table is keyed by its `UNIQUE` id, so an
/// `INSERT` of a present id fails; a `DELETE` reports the one matching row or
/// none. `SelectSend` is not a write.
let exec_send (d: db) (s: t_SendStmt) : option (u64 & db) =
  match s with
  | SendStmt_InsertSend
    { f_id = id; f_owner = owner; f_ciphertext = ciphertext;
      f_has_passphrase = has_passphrase; f_kdf_salt = salt; f_label = label;
      f_view_once = view_once; f_max_views = max_views;
      f_created_at = created; f_expires_at = expires } ->
    (match d.sends id with
     | Some _ -> None
     | None ->
       let row : send_row = {
         sd_owner = owner;
         sd_ciphertext = ciphertext;
         sd_has_passphrase = (if has_passphrase then mk_i64 1 else mk_i64 0);
         sd_kdf_salt = salt;
         sd_label = label;
         sd_view_once = (if view_once then mk_i64 1 else mk_i64 0);
         sd_max_views = max_views;
         sd_view_count = mk_i64 0;
         sd_created_at = created;
         sd_expires_at = expires;
         sd_revoked = mk_i64 0;
       } in
       Some (mk_u64 1, { d with sends = upd d.sends id (Some row) }))
  | SendStmt_ConsumeSendView { f_id = id; f_now = now } ->
    (match d.sends id with
     | Some r ->
       if send_live d r now
       then
         let row : send_row = { r with sd_view_count = r.sd_view_count +. mk_i64 1 } in
         Some (mk_u64 1, { d with sends = upd d.sends id (Some row) })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | SendStmt_DeleteSend { f_id = id } ->
    (match d.sends id with
     | Some _ -> Some (mk_u64 1, { d with sends = upd d.sends id None })
     | None -> Some (mk_u64 0, d))
  | SendStmt_DeleteOwnedSend { f_id = id; f_owner = owner } ->
    (match d.sends id with
     | Some r ->
       if r.sd_owner = owner
       then Some (mk_u64 1, { d with sends = upd d.sends id None })
       else Some (mk_u64 0, d)
     | None -> Some (mk_u64 0, d))
  | _ -> None

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// A plan inside an open transaction that began at `pre`.
let rec run_tx (pre work: db) (stmts: list t_ShareStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], pre)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], pre)
    else
      match s with
      | ShareStmt_Commit ->
        let r = run_tx work work rest (k + 1) f in
        (WriteOutcome_Applied (mk_u64 0) :: fst r, snd r)
      | _ ->
        match exec work s with
        | None -> ([WriteOutcome_Failed], pre)
        | Some (n, w) ->
          let r = run_tx pre w rest (k + 1) f in
          (WriteOutcome_Applied n :: fst r, snd r)

/// A plan on the pool: each statement commits on its own.
let rec run_auto (d: db) (stmts: list t_ShareStmt) (k: nat) (f: option nat)
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

/// A `sends` plan on the pool: each statement commits on its own, and a
/// failed statement changes nothing.
let rec run_send_auto (d: db) (stmts: list t_SendStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], d)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], d)
    else
      match exec_send d s with
      | None -> ([WriteOutcome_Failed], d)
      | Some (n, d') ->
        let r = run_send_auto d' rest (k + 1) f in
        (WriteOutcome_Applied n :: fst r, snd r)

/// `SelectLink`: the row with that id, decoded as the handler decodes it.
let read_link (d: db) (s: t_ShareStmt) (failed: bool) : t_ReadOutcome t_LinkRowView =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | ShareStmt_SelectLink { f_id = id } ->
      (match d.items id with
       | Some r ->
         ReadOutcome_Row
           (Core_models.Option.Option_Some
             ({
                 f_sender = Core_models.Option.Option_Some r.it_sender;
                 f_revoked = Core_models.Option.Option_Some r.it_revoked
               } <: t_LinkRowView))
       | None -> ReadOutcome_Row Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

/// `SelectDevice`: the device with that id owned by `user`, joined with the
/// owner's `users` row.
let read_device (d: db) (s: t_ShareStmt) (failed: bool) : t_ReadOutcome t_DeviceRowView =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | ShareStmt_SelectDevice { f_device_id = device_id; f_user = user } ->
      (match d.devices device_id with
       | Some dv ->
         if dv.dv_user_id = user
         then
           (match d.users dv.dv_user_id with
            | Some u ->
              ReadOutcome_Row
                (Core_models.Option.Option_Some
                  ({
                      f_hybrid_vk = Core_models.Option.Option_Some dv.dv_hybrid_vk;
                      f_revoked = Core_models.Option.Option_Some dv.dv_revoked;
                      f_share_ek_since =
                        (match u.us_share_ek_since with
                         | Some since -> Core_models.Option.Option_Some since
                         | None -> Core_models.Option.Option_None);
                      f_user_id = Core_models.Option.Option_Some dv.dv_user_id
                    } <: t_DeviceRowView))
            | None -> ReadOutcome_Row Core_models.Option.Option_None)
         else ReadOutcome_Row Core_models.Option.Option_None
       | None -> ReadOutcome_Row Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

/// `SelectSend`: the row with that id, decoded as the handler decodes it.
/// Schema-conforming rows have every required cell, so a present row decodes
/// in full; the conformance test checks the handler's canonical timestamp
/// against the stored text.
let read_send (d: db) (s: t_SendStmt) (failed: bool) : t_ReadOutcome t_SendRowView =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | SendStmt_SelectSend { f_id = id } ->
      (match d.sends id with
       | Some r ->
         ReadOutcome_Row
           (Core_models.Option.Option_Some
             ({
                 f_ciphertext = Core_models.Option.Option_Some r.sd_ciphertext;
                 f_has_passphrase = Core_models.Option.Option_Some r.sd_has_passphrase;
                 f_kdf_salt = r.sd_kdf_salt;
                 f_view_once = Core_models.Option.Option_Some r.sd_view_once;
                 f_max_views = r.sd_max_views;
                 f_view_count = Core_models.Option.Option_Some r.sd_view_count;
                 f_expires_at = Core_models.Option.Option_Some r.sd_expires_at
               } <: t_SendRowView))
       | None -> ReadOutcome_Row Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

// ── The executors: plan, run, classify ─────────────────────────────────────

let stmts_of (p: Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global) : list t_ShareStmt =
  Seq.seq_to_list p._0

let slice_of (l: list t_WriteOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : t_Slice t_WriteOutcome =
  Seq.seq_of_list l

/// `SendIo::insert_capsule`, inside the transaction the handler opened.
let send_insert (d: db) (id sender recipient capsule now: text) (f: option nat)
  : (Vela_share_policy.Driver.t_SendResultObservation & db) =
  let r = run_tx d d (stmts_of (plan_send_insert id sender recipient capsule now)) 0 f in
  (classify_send (slice_of (fst r)), snd r)

/// `LinkUpdateIo::update_linked_item` for caller `sender`.
let link_update (d: db) (id sender capsule now: text) (f: option nat)
  : (Vela_share_policy.Driver.t_RowsObservation & db) =
  let r = run_auto d (stmts_of (plan_link_update id sender capsule now)) 0 f in
  (classify_rows (slice_of (fst r)), snd r)

/// `LinkRevokeIo::revoke_linked_item` for caller `sender`.
let link_revoke (d: db) (id sender now: text) (f: option nat)
  : (Vela_share_policy.Driver.t_RowsObservation & db) =
  let r = run_auto d (stmts_of (plan_link_revoke id sender now)) 0 f in
  (classify_rows (slice_of (fst r)), snd r)

/// `LinkRevokeIo::delete_linked_inbox`.
let linked_inbox_cleanup (d: db) (id: text) (f: option nat)
  : (Vela_share_policy.Driver.t_CleanupObservation & db) =
  let r = run_auto d (stmts_of (plan_linked_inbox_cleanup id)) 0 f in
  (classify_cleanup (slice_of (fst r)), snd r)

/// `InboxDeleteIo::delete_inbox_item` for caller `recipient`.
let inbox_delete (d: db) (id recipient: text) (f: option nat)
  : (Vela_share_policy.Driver.t_RowsObservation & db) =
  let r = run_auto d (stmts_of (plan_inbox_delete id recipient)) 0 f in
  (classify_rows (slice_of (fst r)), snd r)

/// `ShareEkIo::update_share_ek` for caller `user` (after the permit check).
let share_ek_update (d: db) (user ek since device: text) (f: option nat)
  : (Vela_share_policy.Driver.t_RowsObservation & db) =
  let r = run_auto d (stmts_of (plan_share_ek_update user ek since device)) 0 f in
  (classify_rows (slice_of (fst r)), snd r)

/// `LinkUpdateIo/LinkRevokeIo::observe_link` for `caller`. Reads change
/// nothing, so only the observation is returned.
let observe_link (d: db) (caller id: text) (f: option nat)
  : Vela_share_policy.t_LinkMutationObservation =
  classify_link caller (read_link d (plan_link_read id) (faulted f 0))

/// `ShareEkIo::observe_device` for `caller`; `verdicts` are the crypto and
/// freshness results the handler computes from the returned row.
let observe_device
      (d: db)
      (caller device_id: text)
      (ek_len: usize)
      (verdicts: t_DeviceVerdicts)
      (f: option nat)
  : Vela_share_policy.Driver.t_EkDeviceObservation =
  classify_device caller ek_len (read_device d (plan_device_read device_id caller) (faulted f 0)) verdicts

// ── The one-off share-link executors: plan, run, classify ──────────────────

let stmts_of_send (p: Alloc.Vec.t_Vec t_SendStmt Alloc.Alloc.t_Global) : list t_SendStmt =
  Seq.seq_to_list p._0

/// `CreateSendIo::insert_send`, after the driver's permit.
let send_create
      (d: db) (id owner ciphertext: text)
      (has_passphrase: bool)
      (kdf_salt label: Core_models.Option.t_Option text)
      (view_once: bool)
      (max_views: Core_models.Option.t_Option i64)
      (created_at expires_at: text)
      (f: option nat)
  : (Vela_share_policy.Send_driver.t_RowsObservation & db) =
  let r =
    run_send_auto d
      (stmts_of_send
        (plan_send_create id owner ciphertext has_passphrase kdf_salt label view_once
          max_views created_at expires_at))
      0 f
  in
  (classify_send_create (slice_of (fst r)), snd r)

/// `FetchSendIo::consume_view`.
let send_consume (d: db) (id now: text) (f: option nat)
  : (Vela_share_policy.Send_driver.t_ConsumeObservation & db) =
  let r = run_send_auto d (stmts_of_send (plan_send_consume id now)) 0 f in
  (classify_send_consume (slice_of (fst r)), snd r)

/// `FetchSendIo::remove_fetched`.
let send_remove (d: db) (id: text) (f: option nat)
  : (Vela_share_policy.Send_driver.t_RemoveObservation & db) =
  let r = run_send_auto d (stmts_of_send (plan_send_remove id)) 0 f in
  (classify_send_remove (slice_of (fst r)), snd r)

/// `DeleteSendIo::delete_link` for caller `owner`.
let send_delete (d: db) (id owner: text) (f: option nat)
  : (Vela_share_policy.Send_driver.t_RowsObservation & db) =
  let r = run_send_auto d (stmts_of_send (plan_send_delete id owner)) 0 f in
  (classify_send_delete (slice_of (fst r)), snd r)

/// `FetchSendIo::read_send`. Reads change nothing.
let send_fetch_read (d: db) (id: text) (f: option nat)
  : t_SendFetchObservation =
  classify_send_read (read_send d (plan_send_read id) (faulted f 0))
