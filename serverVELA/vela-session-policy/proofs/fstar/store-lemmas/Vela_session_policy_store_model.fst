module Vela_session_policy_store_model

/// A model of the tables and store keys the session executors touch, and of
/// how their statement plans run on them (F-1).
///
/// - Every table is a finite list of `(UNIQUE id, row)` pairs, so "every
///   starting database" is every such list. A delete by column removes
///   exactly the matching rows; an update by id rewrites the one matching row
///   or none; a delete by id reports whether its key was present (the
///   `users` delete's row count is the account-existence signal).
/// - `run_tx` runs a plan inside an open transaction: writes go to a working
///   state, `Commit` publishes it, and a failed statement or failed commit
///   leaves the state the transaction began from (the handler drops the
///   transaction, which rolls it back).
/// - The store is a key-value map plus a set map. `SetEx` overwrites the one
///   key; `RevokeJtis` is the logical `rate_limit::revoke_all_device_jtis`
///   effect: every member of the device's tracked set joins `revoked` and the
///   set is cleared. TTLs are abstracted away (a scheduler choice).
/// - `f = Some k` makes the k-th statement (from 0) fail.
///
/// What this module trusts, and `vela-server/src/auth/session_conformance.rs`
/// checks against a real database and a real sled store: these statement
/// meanings, statement atomicity, the rendering of each typed statement to
/// SQL or a store call, and the decoding of result rows into views. A failed
/// store helper is modelled as atomic: the executor observes only its error,
/// and the conformance harness injects failures at that same logical boundary.
///
/// The executor models below are the server's thin loop: plan (extracted),
/// run, classify (extracted). `vela-session-policy/src/store_model.rs` mirrors
/// this module function for function.

open FStar.Mul
open Core_models
open Vela_session_policy.Store

module L = FStar.List.Tot

type text = Alloc.String.t_String

/// The value every executor writes to a marker key.
let v_one : text = Alloc.String.String "1"

/// The status text a revoked session carries.
let v_revoked : text = Alloc.String.String "revoked"

// ── Finite tables ──────────────────────────────────────────────────────────

/// A table is a list of unique id/row pairs.
type tbl (a: Type0) = list (text & a)

/// The row with key `k`, if any. F*: the SQL `WHERE id = ?` lookup.
let rec lookup (#a: Type0) (t: tbl a) (k: text) : Tot (option a) (decreases t) =
  match t with
  | [] -> None
  | (k', v) :: rest -> if k' = k then Some v else lookup rest k

/// The rows satisfying `p`, in table order. F*: a `WHERE p` scan.
let rec keep (#a: Type0) (p: a -> bool) (l: list a) : Tot (list a) (decreases l) =
  match l with
  | [] -> []
  | x :: xs -> if p x then x :: keep p xs else keep p xs

/// An `INSERT` of a fresh key.
let insert_row (#a: Type0) (t: tbl a) (k: text) (v: a) : tbl a = (k, v) :: t

/// `DELETE FROM t WHERE id = ?`.
let erase_row (#a: Type0) (t: tbl a) (k: text) : tbl a =
  keep (fun (p: text & a) -> not (fst p = k)) t

/// `DELETE FROM t WHERE <row predicate>`.
let delete_rows (#a: Type0) (p: a -> bool) (t: tbl a) : tbl a =
  keep (fun (kv: text & a) -> not (p (snd kv))) t

/// `SELECT id FROM t WHERE <row predicate>`.
let ids_of (#a: Type0) (p: a -> bool) (t: tbl a) : list text =
  L.map fst (keep (fun (kv: text & a) -> p (snd kv)) t)

/// `UPDATE t SET <f> WHERE id = ?`.
let update_rows (#a: Type0) (t: tbl a) (k: text) (f: a -> a) : tbl a =
  L.map (fun (kv: text & a) -> if fst kv = k then (fst kv, f (snd kv)) else kv) t

// ── Rows and the database ──────────────────────────────────────────────────

/// The columns of a `users` row the session statements read or write.
type user_row = {
  us_share_ek: option text;
  us_share_ek_since: option text;
}

/// The `devices` columns the session statements read or write.
type device_row = {
  dv_user: text;
  dv_revoked: i64;
  dv_hybrid_vk: text;
  dv_last_active: option text;
  dv_name: text;
  dv_kind: text;
  dv_revoked_at: option text;
  dv_revoked_by: option text;
}

/// The `web_sessions` columns the session statements read or write.
type session_row = {
  ws_user: option text;
  ws_approver: option text;
  ws_status: text;
  ws_capsule: option text;
  ws_approved_by: option text;
}

/// A `share_inbox` or `shared_items` row.
type mail_row = {
  ml_sender: text;
  ml_recipient: text;
}

/// A `sends`, `vault_chunks` or `oram_buckets` row.
type owned_row = {
  ow_user: text;
}

noeq type db = {
  users: tbl user_row;
  devices: tbl device_row;
  sessions: tbl session_row;
  inbox: tbl mail_row;
  items: tbl mail_row;
  sends: tbl owned_row;
  chunks: tbl owned_row;
  buckets: tbl owned_row;
}

// ── Statement semantics ────────────────────────────────────────────────────

/// What a write statement's row count means to the handler. `WroteOne` and
/// `WroteAbsent` are the `users` delete's one-or-zero rows.
type write_result =
  | Wrote
  | WroteOne
  | WroteAbsent

/// A web session the cascade may end: approved by `dev`, owned by `usr`, and
/// not already revoked (the handler's `status != 'revoked'`).
let live_approved (dev usr: text) (r: session_row) : bool =
  r.ws_approved_by = Some dev && r.ws_user = Some usr && r.ws_status <> v_revoked

/// The state each account-scoped delete leaves behind.
let st_web_sessions (d: db) (acct: text) : db =
  { d with sessions = delete_rows (fun r -> r.ws_user = Some acct || r.ws_approver = Some acct) d.sessions }

let st_share_inbox (d: db) (acct: text) : db =
  { d with inbox = delete_rows (fun r -> r.ml_recipient = acct || r.ml_sender = acct) d.inbox }

let st_shared_items (d: db) (acct: text) : db =
  { d with items = delete_rows (fun r -> r.ml_recipient = acct || r.ml_sender = acct) d.items }

let st_sends (d: db) (acct: text) : db =
  { d with sends = delete_rows (fun r -> r.ow_user = acct) d.sends }

let st_vault_chunks (d: db) (acct: text) : db =
  { d with chunks = delete_rows (fun r -> r.ow_user = acct) d.chunks }

let st_oram_buckets (d: db) (acct: text) : db =
  { d with buckets = delete_rows (fun r -> r.ow_user = acct) d.buckets }

let st_devices_of_user (d: db) (acct: text) : db =
  { d with devices = delete_rows (fun r -> r.dv_user = acct) d.devices }

let st_delete_user (d: db) (acct: text) : db =
  { d with users = erase_row d.users acct }

/// The `devices` row after `UPDATE ... SET revoked = 1 WHERE id = ?`.
let revoked_device_row (now revoker: text) (r: device_row) : device_row =
  { r with dv_revoked = mk_i64 1;
           dv_revoked_at = Some now;
           dv_revoked_by = Some revoker }

let st_revoke_device (d: db) (dev now revoker: text) : db =
  { d with devices = update_rows d.devices dev (revoked_device_row now revoker) }

/// The `devices` row after the login's best-effort last-active stamp. The
/// named form (request renamed or retyped the device) also rewrites the name
/// and type; the plain form only stamps the time.
let login_stamp (d: db) (dev now: text)
      (nm kd: Core_models.Option.t_Option text) : db =
  match nm, kd with
  | Core_models.Option.Option_Some n, Core_models.Option.Option_Some k ->
    { d with devices = update_rows d.devices dev (fun r ->
        { r with dv_last_active = Some now; dv_name = n; dv_kind = k }) }
  | _ ->
    { d with devices = update_rows d.devices dev (fun r ->
        { r with dv_last_active = Some now }) }

/// A web session the cascade ends: revoked with its capsule dropped.
let revoked_session (r: session_row) : session_row =
  { r with ws_status = v_revoked; ws_capsule = None }

/// Every row matching `p` is rewritten by `f`.
let update_where (#a: Type0) (t: tbl a) (p: a -> bool) (f: a -> a) : tbl a =
  L.map (fun (kv: text & a) ->
           if p (snd kv) then (fst kv, f (snd kv)) else kv) t

/// The `web_sessions` table after the approving-device cascade.
let st_revoke_approved (d: db) (dev usr: text) : db =
  { d with sessions = update_where d.sessions (live_approved dev usr) revoked_session }

/// One write statement on a state, or `None` when a read or `Commit` was
/// passed where a write belongs.
let exec_stmt (d: db) (s: t_SqlStmt) : option (write_result & db) =
  match s with
  | SqlStmt_DeleteWebSessionsByUser { f_user = acct } ->
    Some (Wrote, st_web_sessions d acct)
  | SqlStmt_DeleteShareInboxByUser { f_user = acct } ->
    Some (Wrote, st_share_inbox d acct)
  | SqlStmt_DeleteSharedItemsByUser { f_user = acct } ->
    Some (Wrote, st_shared_items d acct)
  | SqlStmt_DeleteSendsByOwner { f_owner = acct } ->
    Some (Wrote, st_sends d acct)
  | SqlStmt_DeleteVaultChunksByUser { f_user = acct } ->
    Some (Wrote, st_vault_chunks d acct)
  | SqlStmt_DeleteOramBucketsByUser { f_user = acct } ->
    Some (Wrote, st_oram_buckets d acct)
  | SqlStmt_DeleteDevicesByUser { f_user = acct } ->
    Some (Wrote, st_devices_of_user d acct)
  | SqlStmt_DeleteUserById { f_user = acct } ->
    (match lookup d.users acct with
     | Some _ -> Some (WroteOne, st_delete_user d acct)
     | None -> Some (WroteAbsent, d))
  | SqlStmt_RevokeDeviceRecord { f_now = now; f_revoked_by = revoker; f_device_id = dev } ->
    Some (Wrote, st_revoke_device d dev now revoker)
  | SqlStmt_RevokeWebSessionsApprovedBy { f_device_id = dev; f_user = usr } ->
    Some (Wrote, st_revoke_approved d dev usr)
  | SqlStmt_UpdateDeviceLastActive { f_now = now; f_device_id = dev } ->
    Some (Wrote, login_stamp d dev now
            Core_models.Option.Option_None Core_models.Option.Option_None)
  | SqlStmt_UpdateDeviceLastActiveNamed
      { f_now = now; f_name = nm; f_kind = kd; f_device_id = dev } ->
    Some (Wrote, login_stamp d dev now
            (Core_models.Option.Option_Some nm) (Core_models.Option.Option_Some kd))
  | SqlStmt_SelectDeviceIdsByUser _
  | SqlStmt_SelectWebSessionIdsByUser _
  | SqlStmt_SelectDeviceById _
  | SqlStmt_SelectWebSessionIdsApprovedBy _
  | SqlStmt_SelectUnrevokedDeviceById _
  | SqlStmt_Commit -> None

/// The state after one write statement (a rejected statement changes nothing).
let exec_write (d: db) (s: t_SqlStmt) : db =
  match exec_stmt d s with
  | Some (_, d') -> d'
  | None -> d

/// The outcome the handler records for a statement it ran.
let outcome_of (w: write_result) : t_WriteOutcome =
  match w with
  | Wrote -> WriteOutcome_Applied (mk_u64 1)
  | WroteOne -> WriteOutcome_Applied (mk_u64 1)
  | WroteAbsent -> WriteOutcome_Applied (mk_u64 0)

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// No statement among the first `n` is the injected failure.
let no_fault_in (f: option nat) (n: nat) : bool =
  match f with
  | Some k -> k >= n
  | None -> true

/// A plan inside an open transaction that began at `pre`.
let rec run_tx (pre work: db) (stmts: list t_SqlStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_WriteOutcome & db){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], pre)
  | s :: rest ->
    if faulted f k
    then ([WriteOutcome_Failed], pre)
    else
      match s with
      | SqlStmt_Commit ->
        let r = run_tx work work rest (k + 1) f in
        (WriteOutcome_Applied (mk_u64 0) :: fst r, snd r)
      | _ ->
        match exec_stmt work s with
        | None -> ([WriteOutcome_Failed], pre)
        | Some (w, w') ->
          let r = run_tx pre w' rest (k + 1) f in
          (outcome_of w :: fst r, snd r)

/// The state after applying every statement of a write-only plan in order.
let rec exec_all (d: db) (plan: list t_SqlStmt) : Tot db (decreases plan) =
  match plan with
  | [] -> d
  | s :: rest -> exec_all (exec_write d s) rest

// ── The store ──────────────────────────────────────────────────────────────

/// A key-value map (`set_ex` targets), a set map (`device:jtis:` targets),
/// the counters behind the login limiters, and every JTI the lockout helper
/// has marked.
noeq type store = {
  kv: text -> option text;
  sets: text -> list text;
  revoked: list text;
  counters: text -> nat;
  streaks: text -> nat;
}

let kv_set (s: text -> option text) (k: text) (v: option text) : (text -> option text) =
  fun k' -> if k' = k then v else s k'

/// A counter map that writes one key.
let cnt_set (c: text -> nat) (k: text) (n: nat) : (text -> nat) =
  fun k' -> if k' = k then n else c k'

/// One store statement.
let exec_store (s: store) (st: t_StoreStmt) : store =
  match st with
  | StoreStmt_SetEx { f_key = k; f_value = _; f_ttl = _ } ->
    { s with kv = kv_set s.kv k (Some v_one) }
  | StoreStmt_RevokeJtis { f_device = dev } ->
    { s with sets = (fun k -> if k = dev then [] else s.sets k);
             revoked = s.revoked @ s.sets dev }
  | StoreStmt_Take { f_key = k } ->
    { s with kv = kv_set s.kv k None }
  | StoreStmt_Incr { f_key = k; f_limit = _; f_ttl = _ } ->
    { s with counters = cnt_set s.counters k (s.counters k + 1) }
  | StoreStmt_BackoffFailure { f_streak = streak; f_backoff = backoff } ->
    { s with streaks = cnt_set s.streaks streak (s.streaks streak + 1);
             kv = (if s.streaks streak + 1 >= 3
                   then kv_set s.kv backoff (Some v_one) else s.kv) }
  | StoreStmt_ResetBackoff { f_streak = streak; f_backoff = backoff } ->
    { s with streaks = cnt_set s.streaks streak 0;
             kv = kv_set s.kv backoff None }
  | StoreStmt_AddMember { f_key = k; f_member = m; f_ttl = _ } ->
    { s with sets = (fun k' -> if k' = k then m :: s.sets k else s.sets k') }

/// One store statement and the outcome the handler observed. Only a fixed
/// window counter can refuse: it grew before it reported the refusal.
let exec_store_out (s: store) (st: t_StoreStmt) : (t_StoreOutcome & store) =
  match st with
  | StoreStmt_Incr { f_key = k; f_limit = lim; f_ttl = _ } ->
    let n = s.counters k + 1 in
    let s' = { s with counters = cnt_set s.counters k n } in
    ((if n <= v lim then StoreOutcome_Applied else StoreOutcome_Failed), s')
  | _ -> (StoreOutcome_Applied, exec_store s st)

/// A plan of store statements: stop at the first failure.
let rec run_store (s: store) (stmts: list t_StoreStmt) (k: nat) (f: option nat)
  : Tot (r: (list t_StoreOutcome & store){L.length (fst r) <= L.length stmts}) (decreases stmts) =
  match stmts with
  | [] -> ([], s)
  | st :: rest ->
    if faulted f k
    then ([StoreOutcome_Failed], s)
    else
      let (o, s') = exec_store_out s st in
      match o with
      | StoreOutcome_Applied ->
        let r = run_store s' rest (k + 1) f in
        (StoreOutcome_Applied :: fst r, snd r)
      | StoreOutcome_Failed -> ([StoreOutcome_Failed], s')

/// The outcome list of a plan that runs to completion.
let rec all_applied (stmts: list t_StoreStmt) : Tot (list t_StoreOutcome) (decreases stmts) =
  match stmts with
  | [] -> []
  | _ :: rest -> StoreOutcome_Applied :: all_applied rest

/// The store after applying every statement of a plan in order.
let rec apply_all (s: store) (stmts: list t_StoreStmt) : Tot store (decreases stmts) =
  match stmts with
  | [] -> s
  | st :: rest -> apply_all (snd (exec_store_out s st)) rest

/// A batch of per-id lockouts, continuing past a failure (the deletion
/// handler ignores a lockout error), with the store call counter carried
/// across the batch so a fault lands at the one global statement it names.
let rec lockout_each
      (s: store)
      (ids: list text)
      (plan_of: text -> list t_StoreStmt)
      (k: nat)
      (f: option nat)
  : Tot (store & nat) (decreases ids) =
  match ids with
  | [] -> (s, k)
  | id :: rest ->
    let r = run_store s (plan_of id) k f in
    lockout_each (snd r) rest plan_of (k + L.length (fst r)) f

// ── Reads ──────────────────────────────────────────────────────────────────

/// A store plan's statements (hax extracts `Vec` as a sequence).
let stmts_of (p: Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global) : list t_StoreStmt =
  Seq.seq_to_list p._0

/// A list as the slice a classifier reads.
let slice_of (l: list t_StoreOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : t_Slice t_StoreOutcome =
  Seq.seq_of_list l


/// `DeleteAccountIo::lockout_devices` / `lockout_web_sessions`: every scanned
/// id is locked out, failures are ignored, and the observation is `Applied`.
let lockout_scanned
      (s: store)
      (ids: list text)
      (plan_of: text -> list t_StoreStmt)
      (f: option nat)
  : (Vela_session_policy.Deletion_driver.t_LockoutObservation & store) =
  let r = lockout_each s ids plan_of 0 f in
  (classify_lockout_ignored (slice_of []), fst r)

/// `DeleteAccountIo::scan_devices`, with the scanned ids. `v` is the id
/// vector the query returned; the classifier ignores it, so its content is the
/// read's truth (proved separately), not the observation's.
let scan_devices
      (d: db)
      (acct: text)
      (v: Alloc.Vec.t_Vec text Alloc.Alloc.t_Global)
      (failed: bool)
  : (Vela_session_policy.Deletion_driver.t_ScanObservation & list text) =
  (classify_scan (if failed then IdsOutcome_Failed else IdsOutcome_Ids v),
   (if failed then [] else ids_of (fun r -> r.dv_user = acct) d.devices))

/// `DeleteAccountIo::scan_web_sessions`.
let scan_web_sessions
      (d: db)
      (acct: text)
      (v: Alloc.Vec.t_Vec text Alloc.Alloc.t_Global)
      (failed: bool)
  : (Vela_session_policy.Deletion_driver.t_ScanObservation & list text) =
  (classify_scan (if failed then IdsOutcome_Failed else IdsOutcome_Ids v),
   (if failed then []
    else ids_of (fun r -> r.ws_user = Some acct || r.ws_approver = Some acct) d.sessions))

/// `SELECT <target columns> FROM devices WHERE id = ?`; `failed` injects a
/// read error.
let read_target (d: db) (dev: text) (failed: bool) : t_ReadOutcome t_TargetRowView =
  if failed
  then ReadOutcome_Failed
  else
    match lookup d.devices dev with
    | Some r ->
      ReadOutcome_Row
        (Core_models.Option.Option_Some
          ({
              f_user_id = Core_models.Option.Option_Some r.dv_user;
              f_revoked = Core_models.Option.Option_Some r.dv_revoked
            } <: t_TargetRowView))
    | None -> ReadOutcome_Row Core_models.Option.Option_None

// ── Login: VerifyIo ────────────────────────────────────────────────────────

/// A native option as the `Core_models` option the extracted views carry.
let cm_option (#a: Type0) (o: option a) : Core_models.Option.t_Option a =
  match o with
  | None -> Core_models.Option.Option_None
  | Some x -> Core_models.Option.Option_Some x

let cm_option_none (#a: Type0) (o: option a)
  : Lemma (cm_option o == Core_models.Option.Option_None <==> o == None) =
  match o with
  | None -> ()
  | Some _ -> ()

let cm_option_some (#a: Type0) (o: option a) (x: a)
  : Lemma (cm_option o == Core_models.Option.Option_Some x <==> o == Some x) =
  match o with
  | None -> ()
  | Some _ -> ()

/// `VerifyIo::consume_challenge`: the atomic take of the one challenge key.
/// The modelled take returns the stored value and removes it; the extracted
/// classifier decides from that value and the tag this consumer expected — on
/// the failure path too.
let login_challenge (s: store) (challenge tag: text) (f: option nat)
  : (Vela_session_policy.Login_driver.t_ChallengeObservation & store) =
  let key = match stmts_of (plan_take_challenge challenge) with
            | StoreStmt_Take { f_key = k } :: _ -> k
            | _ -> Alloc.String.String "" in
  let (outcome, s') =
    if faulted f 0
    then (TakeOutcome_Failed, s)
    else (TakeOutcome_Taken (cm_option (s.kv key)),
          exec_store s (StoreStmt_Take { f_key = key })) in
  (classify_login_challenge outcome tag, s')

/// `VerifyIo::observe_device`: what the `revoked = 0` query and the decoder
/// produced. `undecodable` is the decoder's verdict on a present row.
let login_device (d: db) (dev: text) (failed undecodable: bool)
  : t_DeviceReadOutcome =
  if failed then DeviceReadOutcome_Failed
  else
    match lookup d.devices dev with
    | None -> DeviceReadOutcome_Missing
    | Some r ->
      if r.dv_revoked <> mk_i64 0 then DeviceReadOutcome_Missing
      else if undecodable then DeviceReadOutcome_Undecodable
      else DeviceReadOutcome_Row

/// `VerifyIo::observe_device`.
let observe_device (d: db) (dev: text) (failed undecodable: bool)
  : Vela_session_policy.Login_driver.t_DeviceObservation =
  classify_login_device (login_device d dev failed undecodable)

/// `VerifyIo::record_verification_failure`: the log-only backoff record (fault
/// 0) and then the request-level counter (fault 1), two independent calls.
let login_failure_record (s: store) (ip dev: text) (f: option nat)
  : (Vela_session_policy.Login_driver.t_FailureRecordObservation & store) =
  let a = run_store s (stmts_of (plan_backoff_record ip dev)) 0
            (if faulted f 0 then Some 0 else None) in
  let r = run_store (snd a) (stmts_of (plan_failure_counter ip dev)) 0
                    (if faulted f 1 then Some 0 else None) in
  (classify_failure_counter (slice_of (fst r)), snd r)

/// The first outcome of a run (empty runs never happen; the caller's plan is
/// never empty).
let first_out (l: list t_StoreOutcome) : t_StoreOutcome =
  match l with
  | [] -> StoreOutcome_Failed
  | o :: _ -> o

/// `VerifyIo::reset_backoff`: the streak reset (fault 0), then the historical
/// best-effort stamp (fault 1), whose failure the observation ignores. Both
/// paths classify, so a changed classifier fails the theorem.
let login_reset (s: store) (d: db) (ip dev now: text)
      (nm kd: Core_models.Option.t_Option text) (f: option nat)
  : (Vela_session_policy.Login_driver.t_BackoffResetObservation & store & db) =
  let r = run_store s (stmts_of (plan_reset_login_streak ip dev)) 0 f in
  let outcome = first_out (fst r) in
  let s' = snd r in
  let d' =
    match outcome with
    | StoreOutcome_Applied ->
      (if faulted f 1 then d
       else exec_write d (plan_login_last_active dev now nm kd))
    | StoreOutcome_Failed -> d in
  (classify_backoff_reset outcome, s', d')

/// `VerifyIo::track_token`: one set add.
let login_track (s: store) (dev jti: text) (f: option nat)
  : (Vela_session_policy.Login_driver.t_TokenTrackObservation & store) =
  let r = run_store s (stmts_of (plan_track_jti dev jti)) 0 f in
  (classify_track_jti (first_out (fst r)), snd r)

// ── The executors: plan, run, classify ─────────────────────────────────────

/// `LogoutJtiIo::revoke_jti`.
let logout_jti (s: store) (jti: text) (f: option nat)
  : (Vela_session_policy.Revocation_driver.t_LogoutObservation & store) =
  let r = run_store s (stmts_of (plan_logout jti)) 0 f in
  (classify_logout (slice_of (fst r)), snd r)

/// `RevokeDeviceIo::lockout_device`.
let lockout_device (s: store) (dev: text) (f: option nat)
  : (Vela_session_policy.Revocation_driver.t_LockoutObservation & store) =
  let r = run_store s (stmts_of (plan_lockout_device dev)) 0 f in
  (classify_lockout_device (slice_of (fst r)), snd r)

/// `RevokeDeviceIo::lookup_target`.
let revoke_observe (d: db) (caller dev: text) (f: option nat)
  : Vela_session_policy.Revocation_driver.t_DeviceLookupObservation =
  classify_target caller (read_target d dev (faulted f 0))

/// `RevokeDeviceIo::record_revocation`: one statement on the pool.
let revoke_record (d: db) (dev now revoker: text) (f: option nat)
  : (Vela_session_policy.Revocation_driver.t_RecordObservation & db) =
  if faulted f 0
  then (classify_record WriteOutcome_Failed, d)
  else (classify_record (WriteOutcome_Applied (mk_u64 1)), st_revoke_device d dev now revoker)

/// `DeleteAccountIo::begin_transaction`.
let begin_tx (d: db) (f: option nat)
  : (Vela_session_policy.Deletion_driver.t_TransactionObservation & db) =
  if faulted f 0
  then (classify_transaction WriteOutcome_Failed, d)
  else (classify_transaction (WriteOutcome_Applied (mk_u64 0)), d)

/// `DeleteAccountIo::delete_table`: one statement on the open transaction.
let delete_table (d: db) (acct: text) (table: Vela_session_policy.Deletion_driver.t_DeletionTable)
      (f: option nat)
  : (Vela_session_policy.Deletion_driver.t_TableDeleteObservation & db) =
  if faulted f 0
  then (classify_table_delete WriteOutcome_Failed, d)
  else (classify_table_delete (WriteOutcome_Applied (mk_u64 1)),
        (match table with
         | Vela_session_policy.Deletion_driver.DeletionTable_WebSessions -> st_web_sessions d acct
         | Vela_session_policy.Deletion_driver.DeletionTable_ShareInbox -> st_share_inbox d acct
         | Vela_session_policy.Deletion_driver.DeletionTable_SharedItems -> st_shared_items d acct
         | Vela_session_policy.Deletion_driver.DeletionTable_Sends -> st_sends d acct
         | Vela_session_policy.Deletion_driver.DeletionTable_VaultChunks -> st_vault_chunks d acct
         | Vela_session_policy.Deletion_driver.DeletionTable_OramBuckets -> st_oram_buckets d acct
         | Vela_session_policy.Deletion_driver.DeletionTable_Devices -> st_devices_of_user d acct))

/// `DeleteAccountIo::delete_users`: its row count is the account-existence
/// signal.
let delete_users (d: db) (acct: text) (f: option nat)
  : (Vela_session_policy.Deletion_driver.t_UsersDeleteObservation & db) =
  if faulted f 0
  then (classify_users_delete WriteOutcome_Failed, d)
  else
    match lookup d.users acct with
    | Some _ -> (classify_users_delete (WriteOutcome_Applied (mk_u64 1)), st_delete_user d acct)
    | None -> (classify_users_delete (WriteOutcome_Applied (mk_u64 0)), d)

/// `DeleteAccountIo::commit`.
let commit_tx (d: db) (f: option nat)
  : (Vela_session_policy.Deletion_driver.t_CommitObservation & db) =
  if faulted f 0
  then (classify_commit WriteOutcome_Failed, d)
  else (classify_commit (WriteOutcome_Applied (mk_u64 0)), d)

/// The deletion handler's one transaction: the seven table deletes, the
/// `users` delete, then the commit, in the driver's order.
let deletion_plan (acct: text) : list t_SqlStmt =
  [
    plan_delete_table acct Vela_session_policy.Deletion_driver.DeletionTable_WebSessions;
    plan_delete_table acct Vela_session_policy.Deletion_driver.DeletionTable_ShareInbox;
    plan_delete_table acct Vela_session_policy.Deletion_driver.DeletionTable_SharedItems;
    plan_delete_table acct Vela_session_policy.Deletion_driver.DeletionTable_Sends;
    plan_delete_table acct Vela_session_policy.Deletion_driver.DeletionTable_VaultChunks;
    plan_delete_table acct Vela_session_policy.Deletion_driver.DeletionTable_OramBuckets;
    plan_delete_table acct Vela_session_policy.Deletion_driver.DeletionTable_Devices;
    plan_delete_users acct;
    plan_commit ()
  ]

/// The whole transaction, from the state it began in.
let deletion_transaction (d: db) (acct: text) (f: option nat) : (list t_WriteOutcome & db) =
  run_tx d d (deletion_plan acct) 0 f
