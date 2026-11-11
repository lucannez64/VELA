module Vela_recovery_policy_share_model

/// A model of the `users` row the four recovery-share executors touch, and of
/// how their statement plans run on it (F-1).
///
/// - the row stores the epoch, whether a rotation is active, the active share
///   and split, the staged candidate with its epoch and commitment, and the
///   active commitment.
/// - `f = Some k` makes the k-th statement (from 0) fail.
/// - every write is a guarded single-row `UPDATE`: a guard that does not hold
///   changes nothing and reports zero rows.
///
/// The executor models below are the server's thin method: plan (extracted),
/// run, classify (extracted). `vela-recovery-policy/src/redemption_model.rs`
/// mirrors this module function for function; its `shared_share_vectors` test
/// and the `vector_share_*` lemmas check the same concrete runs.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Share_store
open Vela_recovery_policy.Redemption_store

module L = FStar.List.Tot

type text = Alloc.String.t_String

/// A `users` row keyed by its `UNIQUE` id.
type tbl (a: Type) = text -> option a

let upd (#a: Type) (t: tbl a) (k: text) (x: option a) : tbl a =
  fun k' -> if k' = k then x else t k'

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

let stmts_of (p: Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global)
  : list t_ShareStmt =
  Seq.seq_to_list p._0

let slice_of (l: list t_WriteOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : t_Slice t_WriteOutcome =
  Seq.seq_of_list l

// ── Recovery-share lifecycle ───────────────────────────────────────────────
//
// The four recovery-share executors (`PutShareIo`, `FinalizeShareIo`,
// `GetShareIo`, `DeleteShareIo` in `vela-server/src/recovery/mod.rs`) touch one
// `users` row: the epoch and rotation state, the active share and split, the
// staged candidate and its commitment. The same fault model (`f = Some k`
// fails the k-th statement) and the same plan/run/classify shape apply.

/// The modelled columns of a `users` row for the share lifecycle.
noeq type share_user_row = {
  su_epoch: i64;
  su_rekey: bool;
  su_share: option text;
  su_split: option text;
  su_pending_share: option text;
  su_pending_split: option text;
  su_pending_epoch: option i64;
  su_auth: option text;
  su_pending_auth: option text;
}

noeq type share_db = {
  share_users: tbl share_user_row;
}

/// The stage update's SQL guard.
let stage_guard (d: share_db) (user: text) (epoch: i64) : bool =
  match d.share_users user with
  | None -> false
  | Some u ->
    u.su_epoch = epoch && not u.su_rekey && u.su_share = None && u.su_split = None

/// The promote update's SQL guard.
let promote_guard (d: share_db) (user: text) (epoch: i64) (split_id: text) : bool =
  match d.share_users user with
  | None -> false
  | Some u ->
    u.su_epoch = epoch && not u.su_rekey &&
    u.su_pending_epoch = Some epoch &&
    u.su_pending_split = Some split_id &&
    Some? u.su_pending_share && Some? u.su_pending_auth &&
    u.su_share = None && u.su_split = None

/// The delete update's SQL guard.
let delete_guard (d: share_db) (user: text) (epoch: i64) : bool =
  match d.share_users user with
  | None -> false
  | Some u -> u.su_epoch = epoch && not u.su_rekey

/// One share write statement on a state. The reads are not writes.
let share_exec (d: share_db) (s: t_ShareStmt) : option (u64 & share_db) =
  match s with
  | ShareStmt_StageShare
    { f_user = user; f_share = share; f_split_id = split_id;
      f_epoch = epoch; f_auth_hash = auth } ->
    (match d.share_users user with
     | None -> Some (mk_u64 0, d)
     | Some u ->
       if stage_guard d user epoch
       then
         Some (mk_u64 1,
               { d with share_users =
                   upd d.share_users user
                     (Some ({ u with
                              su_pending_share = Some share;
                              su_pending_split = Some split_id;
                              su_pending_epoch = Some epoch;
                              su_pending_auth = Some auth })) })
       else Some (mk_u64 0, d))
  | ShareStmt_PromoteStagedSplit
    { f_user = user; f_epoch = epoch; f_split_id = split_id } ->
    (match d.share_users user with
     | None -> Some (mk_u64 0, d)
     | Some u ->
       if promote_guard d user epoch split_id
       then
         Some (mk_u64 1,
               { d with share_users =
                   upd d.share_users user
                     (Some ({ u with
                              su_share = u.su_pending_share;
                              su_split = u.su_pending_split;
                              su_auth = u.su_pending_auth;
                              su_pending_share = None;
                              su_pending_split = None;
                              su_pending_epoch = None;
                              su_pending_auth = None })) })
       else Some (mk_u64 0, d))
  | ShareStmt_DeleteShare { f_user = user; f_epoch = epoch } ->
    (match d.share_users user with
     | None -> Some (mk_u64 0, d)
     | Some u ->
       if delete_guard d user epoch
       then
         Some (mk_u64 1,
               { d with share_users =
                   upd d.share_users user
                     (Some ({ u with
                              su_share = None;
                              su_split = None;
                              su_pending_share = None;
                              su_pending_split = None;
                              su_pending_epoch = None;
                              su_auth = None;
                              su_pending_auth = None })) })
       else Some (mk_u64 0, d))
  | _ -> None

/// A share write plan, each statement committing on its own.
let rec run_share_autocommit (d: share_db) (stmts: list t_ShareStmt) (k: nat)
      (f: option nat)
  : Tot (r: (list t_WriteOutcome & share_db){L.length (fst r) <= L.length stmts})
        (decreases stmts) =
  match stmts with
  | [] -> ([], d)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], d)
    else
      match share_exec d s with
      | None -> ([WriteOutcome_Failed], d)
      | Some (n, d') ->
        let r = run_share_autocommit d' rest (k + 1) f in
        (WriteOutcome_Applied n :: fst r, snd r)

/// `PutShareIo::stage_share`.
let stage_share (d: share_db) (user share split_id: text) (epoch: i64) (auth: text)
      (f: option nat)
  : option (Vela_recovery_policy.Recovery_share_driver.t_StageUpdateObservation & share_db) =
  let r = run_share_autocommit d
            (stmts_of (plan_stage_share user share split_id epoch auth)) 0 f in
  match fst r with
  | [WriteOutcome_Failed] -> None
  | _ -> Some (classify_stage_update (slice_of (fst r)), snd r)

/// `FinalizeShareIo::promote_staged_split`.
let promote_staged_split (d: share_db) (user: text) (epoch: i64) (split_id: text)
      (f: option nat)
  : option (Vela_recovery_policy.Recovery_share_driver.t_FinalizeUpdateObservation & share_db) =
  let r = run_share_autocommit d
            (stmts_of (plan_promote_staged_split user epoch split_id)) 0 f in
  match fst r with
  | [WriteOutcome_Failed] -> None
  | _ -> Some (classify_finalize_update (slice_of (fst r)), snd r)

/// `DeleteShareIo::delete_share`.
let delete_share (d: share_db) (user: text) (epoch: i64) (f: option nat)
  : option (Vela_recovery_policy.Recovery_share_driver.t_DeleteUpdateObservation & share_db) =
  let r = run_share_autocommit d (stmts_of (plan_delete_share user epoch)) 0 f in
  match fst r with
  | [WriteOutcome_Failed] -> None
  | _ -> Some (classify_delete_update (slice_of (fst r)), snd r)


/// Lift a native option into the extracted `Core_models.Option` type.
let core_opt (#a: Type) (x: option a) : Core_models.Option.t_Option a =
  match x with
  | None -> Core_models.Option.Option_None
  | Some v -> Core_models.Option.Option_Some v

/// `PutShareIo::stage_query_account`.
let stage_account (d: share_db) (user share split_id: text) (failed: bool)
  : option (Vela_recovery_policy.Recovery_share_driver.t_StageAccountObservation) =
  if failed
  then None
  else
    match plan_stage_account user with
    | ShareStmt_SelectStageAccount { f_user = u } ->
      let view =
        match d.share_users u with
        | None -> Core_models.Option.Option_None
        | Some row ->
          Core_models.Option.Option_Some
            ({ f_stored_epoch = core_opt (Some row.su_epoch);
               f_rotation_active = row.su_rekey;
               f_active_share = core_opt row.su_share;
               f_active_split = core_opt row.su_split } <: t_StageAccountRowView)
      in
      Some (classify_stage_account view share split_id)
    | _ -> None

/// `FinalizeShareIo::finalize_query_account`.
let finalize_account (d: share_db) (user split_id: text) (failed: bool)
  : option (Vela_recovery_policy.Recovery_share_driver.t_FinalizeAccountObservation) =
  if failed
  then None
  else
    match plan_finalize_account user with
    | ShareStmt_SelectFinalizeAccount { f_user = u } ->
      let view =
        match d.share_users u with
        | None -> Core_models.Option.Option_None
        | Some row ->
          Core_models.Option.Option_Some
            ({ f_stored_epoch = core_opt (Some row.su_epoch);
               f_rotation_active = row.su_rekey;
               f_active_split = core_opt row.su_split } <: t_FinalizeAccountRowView)
      in
      Some (classify_finalize_account view split_id)
    | _ -> None

/// `GetShareIo::read_share`.
let read_share (d: share_db) (user: text) (failed: bool)
  : option (Vela_recovery_policy.Recovery_share_driver.t_ReadObservation) =
  if failed
  then None
  else
    match plan_read_share user with
    | ShareStmt_SelectShare { f_user = u } ->
      let view =
        match d.share_users u with
        | None -> Core_models.Option.Option_None
        | Some row ->
          Core_models.Option.Option_Some
            ({ f_share = core_opt row.su_share;
               f_split_id = core_opt row.su_split;
               f_epoch = core_opt (Some row.su_epoch) } <: t_ShareRowView)
      in
      Some (classify_read_share view)
    | _ -> None
