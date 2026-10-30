module Vela_recovery_policy_redemption_model

/// A model of the tables and key-value keys the recovered-device enrollment
/// executor touches, and of how its statement plans run on them (F-1).
///
/// - `users` is keyed by its `UNIQUE` id; a row stores the epoch, whether a
///   rotation is active, the current WebAuthn credential id, and the staged
///   possession commitment, normalized so `Some` means "present and
///   non-empty" (both the insert guard and the authority recheck treat `''`
///   as no commitment).
/// - `devices` is keyed by its `UNIQUE` id; the guarded insert adds one row
///   when the user guard holds and errors on a duplicate id.
/// - the enrollment-grant store maps the exact grant key to a typed grant.
///   `get_del` is read-and-delete; `set_ex` overwrites.
/// - `f = Some k` makes the k-th statement (from 0) fail: any statement may
///   be the one that fails.
///
/// What this module trusts, and `vela-server/src/recovery/conformance.rs`
/// checks against a real database and store: these statement meanings,
/// statement atomicity, the rendering of each statement, JSON decoding of a
/// grant and row decoding into views. Time-to-live expiry is a scheduler
/// choice, not modelled.
///
/// The executor models below (`take_grant` ... `restore_grant`) are the
/// server's thin method: plan (extracted), run, classify (extracted).
/// `vela-recovery-policy/src/redemption_model.rs` mirrors this module function
/// for function; its `shared_vectors` test and the `vector_*` lemmas in
/// `Vela_recovery_policy_redemption_lemmas` check the same concrete runs.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Redemption_store

module L = FStar.List.Tot

type text = Alloc.String.t_String

/// An enrollment grant as the store holds it: the plan's own type, so a change
/// to the grant the plan carries changes the model with it.
type grant = t_GrantView

/// The modelled columns of a `users` row.
type user_row = {
  us_epoch: i64;
  us_rekey: bool;
  us_cred: option text;
  us_auth: option text;
}

/// The columns a recovered-device insert writes.
type device_row = {
  dv_user: text;
  dv_name: text;
  dv_kind: text;
  dv_ek: text;
  dv_vk: text;
  dv_created: text;
}

type tbl (a: Type) = text -> option a

let upd (#a: Type) (t: tbl a) (k: text) (x: option a) : tbl a =
  fun k' -> if k' = k then x else t k'

noeq type db = {
  users: tbl user_row;
  devices: tbl device_row;
  grants: tbl grant;
}

/// The SQL guard: the user row exists, its epoch matches, no rotation is
/// active, and the grant's live authority is still present.
let insert_guard (d: db) (user: text) (epoch: i64) (guard: t_GrantGuard) : bool =
  match d.users user with
  | None -> false
  | Some u ->
    u.us_epoch = epoch && not u.us_rekey &&
    (match guard <: t_GrantGuard with
     | GrantGuard_Credential { f_credential_id = cred } ->
       (match u.us_cred with
        | Some current -> current = cred
        | None -> false)
     | GrantGuard_Commitment ->
       (match u.us_auth with
        | Some _ -> true
        | None -> false))

/// One write statement on a state: the rows it changed and the new state, or
/// `None` when the statement errors. Reads and the grant take are not writes.
let exec (d: db) (s: t_RedemptionStmt) : option (u64 & db) =
  match s with
  | RedemptionStmt_PutGrant { f_key = key; f_grant = g } ->
    Some (mk_u64 1, { d with grants = upd d.grants key (Some g) })
  | RedemptionStmt_InsertDevice
    { f_device_id = id; f_user = user; f_device_name = name; f_device_type = kind;
      f_hybrid_ek = ek; f_hybrid_vk = vk; f_created_at = created;
      f_epoch = epoch; f_guard = guard } ->
    (match d.devices id with
     | Some _ -> None
     | None ->
       if insert_guard d user epoch guard
       then
         let row : device_row = {
           dv_user = user;
           dv_name = name;
           dv_kind = kind;
           dv_ek = ek;
           dv_vk = vk;
           dv_created = created;
         } in
         Some (mk_u64 1, { d with devices = upd d.devices id (Some row) })
       else Some (mk_u64 0, d))
  | _ -> None

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// No statement among the first `n` is the injected failure.
let no_fault_in (f: option nat) (n: nat) : bool =
  match f with
  | None -> true
  | Some k -> k >= n

/// The atomic single-use grant take: the taken value and the new state, or
/// `None` when the injected fault fires before the store runs.
let run_take (d: db) (s: t_RedemptionStmt) (f: option nat)
  : option (t_GrantTake & db) =
  if faulted f 0
  then None
  else
    match s with
    | RedemptionStmt_TakeGrant { f_key = key } ->
      (match d.grants key with
       | Some g -> Some (GrantTake_Taken g, { d with grants = upd d.grants key None })
       | None -> Some (GrantTake_Missing, d))
    | _ -> None

/// A plan on the pool: each statement commits on its own.
let rec run_autocommit (d: db) (stmts: list t_RedemptionStmt) (k: nat) (f: option nat)
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
        let r = run_autocommit d' rest (k + 1) f in
        (WriteOutcome_Applied n :: fst r, snd r)

/// `SelectAuthority`: the row with that id, decoded as the handler decodes it
/// (the view normalizes an empty commitment to `None`).
let read_authority
      (d: db) (s: t_RedemptionStmt) (failed: bool)
  : t_ReadOutcome t_AuthorityRowView =
  if failed
  then ReadOutcome_Failed
  else
    match s with
    | RedemptionStmt_SelectAuthority { f_user = user } ->
      (match d.users user with
       | Some u ->
         ReadOutcome_Row
           (Core_models.Option.Option_Some
             ({
                 f_credential_id =
                   (match u.us_cred with
                    | Some c -> Core_models.Option.Option_Some c
                    | None -> Core_models.Option.Option_None);
                 f_auth_hash =
                   (match u.us_auth with
                    | Some h -> Core_models.Option.Option_Some h
                    | None -> Core_models.Option.Option_None);
               } <: t_AuthorityRowView))
       | None -> ReadOutcome_Row Core_models.Option.Option_None)
    | _ -> ReadOutcome_Failed

// ── The executor: plan, run, classify ──────────────────────────────────────

let stmts_of (p: Alloc.Vec.t_Vec t_RedemptionStmt Alloc.Alloc.t_Global)
  : list t_RedemptionStmt =
  Seq.seq_to_list p._0

let slice_of (l: list t_WriteOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : t_Slice t_WriteOutcome =
  Seq.seq_of_list l

/// `EnrollDeviceIo::consume_grant`.
let take_grant (d: db) (key: text) (preflight: grant) (f: option nat)
  : option (Vela_recovery_policy.Driver.t_ConsumptionObservation & db) =
  match run_take d (plan_take_grant key) f with
  | None -> None
  | Some (taken, post) -> Some (classify_take taken preflight, post)

/// `EnrollDeviceIo::insert_device`.
let insert_device
      (d: db)
      (device_id user name kind ek vk created: text)
      (epoch: i64) (guard: t_GrantGuard) (f: option nat)
  : (Vela_recovery_policy.Driver.t_InsertObservation & db) =
  let r = run_autocommit d (stmts_of (plan_insert_device device_id user name kind ek vk created epoch guard)) 0 f in
  (classify_insert (slice_of (fst r)), snd r)

/// `EnrollDeviceIo::recheck_authority`.
let recheck_authority (d: db) (user: text) (possession: bool) (credential_id: text)
      (f: option nat)
  : Vela_recovery_policy.Driver.t_AuthorityRecheckObservation =
  classify_authority
    (read_authority d (plan_authority_read user) (faulted f 0))
    possession
    credential_id

/// `EnrollDeviceIo::restore_grant`.
let restore_grant (d: db) (key value: text) (g: grant) (f: option nat) : option db =
  let r = run_autocommit d (stmts_of (plan_restore_grant key value g)) 0 f in
  match fst r with
  | [WriteOutcome_Applied _] -> Some (snd r)
  | _ -> None
