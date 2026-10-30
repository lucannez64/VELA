module Vela_recovery_policy_webauthn_model

/// A model of the `users` row, the single-use WebAuthn attempt and
/// registration slots, the credential-id index and the enrollment-grant store
/// the four WebAuthn recovery executors touch, and of how their statement plans
/// run on them (F-1).
///
/// - `users` is keyed by its `UNIQUE` id; a row stores the staged recovery
///   share text, the decoded recovery credential cell (absent, the credential
///   id its JSON decodes to, or present-but-undecodable), the indexed
///   credential id, the stored epoch, the rotation flag and the split id.
/// - `attempts` maps the exact user/attempt key to a decoded
///   [`stored_attempt`] or to bytes that do not decode; `set_ex_nx` is
///   first-writer-wins and `get_del` is an atomic read-and-delete that removes
///   an undecodable value too.
/// - `registrations` maps the exact user key to a decodable or undecodable
///   ceremony state; `set_ex` overwrites, `get_del` removes.
/// - `grants` maps the exact enrollment-grant key to a typed credential-bound
///   grant; `set_ex` overwrites.
/// - `holders` is the credential-id index the duplicate lookup reads: each
///   credential id is held by at most one account, and the write statements
///   that replace a stored credential id move the index with them.
/// - `fs = Some k` makes the k-th SQL statement fail; `fk = Some k` makes the
///   k-th store operation fail.
///
/// What this module trusts, and `vela-server/src/recovery/conformance.rs`
/// checks against a real database and store: these statement meanings,
/// statement atomicity, the rendering of each statement, JSON decoding into
/// the row views, and the store's first-writer-wins and read-and-delete
/// implementations. Time-to-live expiry is a scheduler choice, not modelled.
/// WebAuthn ceremony results (challenges, registration states, assertions,
/// updated credential metadata) are inputs, not modelled here.
///
/// The executor models below are the server's thin method: plan (extracted),
/// run, classify (extracted). `vela-recovery-policy/src/redemption_model.rs`
/// mirrors this module function for function; its `shared_webauthn_vectors`
/// test and the `vector_webauthn_*` lemmas check the same concrete runs.

open FStar.Mul
open Core_models
open Vela_recovery_policy.Webauthn_store

module L = FStar.List.Tot

module WD = Vela_recovery_policy.Webauthn_driver
module RS = Vela_recovery_policy.Redemption_store

type text = Alloc.String.t_String

/// One decoded attempt envelope, of the plan's own type, so a change to what
/// the plan stores changes the model with it.
type stored_attempt = t_AuthStateView

/// The outcome of one read: its first row, or an error. This is the same shape
/// as `redemption_store::ReadOutcome`, restated here so this module needs no
/// shared read type.
noeq type read_outcome (a: Type) =
  | Row : a -> read_outcome a
  | Failed : read_outcome a

/// A stored credential cell: absent, a decoded credential id, or
/// present-but-undecodable JSON.
noeq type credential_cell =
  | Cred_Absent : credential_cell
  | Cred_Valid : text -> credential_cell
  | Cred_Undecodable : credential_cell

/// An attempt slot: absent, a decoded envelope, or present-but-undecodable.
noeq type attempt_cell =
  | Attempt_Absent : attempt_cell
  | Attempt_Valid : stored_attempt -> attempt_cell
  | Attempt_Undecodable : attempt_cell

/// A registration slot.
noeq type registration_cell =
  | Registration_Absent : registration_cell
  | Registration_Valid : registration_cell
  | Registration_Undecodable : registration_cell

/// The modelled columns of a `users` row for the WebAuthn executors.
noeq type user_row = {
  ws_share: option text;
  ws_credential: credential_cell;
  ws_cred_id: option text;
  ws_epoch: option i64;
  ws_rekey: bool;
  ws_split: option text;
}

type tbl (a: Type) = text -> option a

let upd (#a: Type) (t: tbl a) (k: text) (x: option a) : tbl a =
  fun k' -> if k' = k then x else t k'

noeq type db = {
  users: tbl user_row;
  attempts: text -> attempt_cell;
  registrations: text -> registration_cell;
  grants: tbl t_CredentialGrantView;
  /// The credential-id index: credential id -> the account that holds it.
  holders: tbl text;
}

/// Replace one attempt slot.
let upd_attempt (d: db) (key: text) (cell: attempt_cell) : db =
  { d with attempts = (fun k -> if k = key then cell else d.attempts k) }

/// Replace one registration slot.
let upd_registration (d: db) (key: text) (cell: registration_cell) : db =
  { d with registrations = (fun k -> if k = key then cell else d.registrations k) }

/// Move the credential-id index from one id to another for one account. Kept
/// in step with the `recovery_webauthn_cred_id` column by both writes.
let rebind (h: tbl text) (owner: text) (old: option text) (new_id: text) : tbl text =
  fun k ->
    if k = new_id
    then Some owner
    else if old = Some k
    then None
    else h k

/// The k-th statement is the injected failure.
let faulted (f: option nat) (k: nat) : bool =
  match f with
  | Some j -> j = k
  | None -> false

/// Whether the exact attempt slot is occupied.
let slot_occupied (d: db) (key: text) : bool =
  match d.attempts key with
  | Attempt_Absent -> false
  | _ -> true

/// Whether the exact registration slot holds anything.
let registration_occupied (d: db) (key: text) : bool =
  match d.registrations key with
  | Registration_Absent -> false
  | _ -> true

/// A stored credential cell as the handler's row view reports it.
let credential_observation (cell: credential_cell) : WD.t_StoredCredentialObservation =
  match cell with
  | Cred_Absent -> WD.StoredCredentialObservation_Missing
  | Cred_Valid _ -> WD.StoredCredentialObservation_Present
  | Cred_Undecodable -> WD.StoredCredentialObservation_Corrupt

/// Lift a native option into the extracted `Core_models.Option` type.
let core_opt (#a: Type) (x: option a) : Core_models.Option.t_Option a =
  match x with
  | None -> Core_models.Option.Option_None
  | Some v -> Core_models.Option.Option_Some v

/// Whether the account's stored share cell is non-null.
let row_share_present (d: db) (user: text) : bool =
  match d.users user with
  | Some row -> Some? row.ws_share
  | None -> false

/// Whether the account's stored credential id is the one given, phrased as the
/// row view reports it.
let row_credential_matches (d: db) (user credential_id: text) : bool =
  match d.users user with
  | Some row -> core_opt row.ws_cred_id = Core_models.Option.Option_Some credential_id
  | None -> false

/// The account's stored epoch.
let row_epoch (d: db) (user: text) : Core_models.Option.t_Option i64 =
  match d.users user with
  | Some row -> core_opt row.ws_epoch
  | None -> Core_models.Option.Option_None

/// Whether the account has a rotation in progress.
let row_rekeying (d: db) (user: text) : bool =
  match d.users user with
  | Some row -> row.ws_rekey
  | None -> false

/// The account's indexed credential id.
let row_credential_id (d: db) (user: text) : Core_models.Option.t_Option text =
  match d.users user with
  | Some row -> core_opt row.ws_cred_id
  | None -> Core_models.Option.Option_None

/// The account's stored split id.
let row_split (d: db) (user: text) : Core_models.Option.t_Option text =
  match d.users user with
  | Some row -> core_opt row.ws_split
  | None -> Core_models.Option.Option_None

/// The guarded credential update's SQL guard: the row exists and the exact
/// indexed credential id is still current.
let update_guard (d: db) (user expected_credential_id: text) : bool =
  match d.users user with
  | Some row -> row.ws_cred_id = Some expected_credential_id
  | None -> false

/// Whether another account holds the credential id.
let holder_other (d: db) (credential_id user: text) : bool =
  match d.holders credential_id with
  | Some owner -> owner <> user
  | None -> false

// ── Reads ──────────────────────────────────────────────────────────────────

/// `plan_select_share`'s row view.
let share_view (d: db) (user: text) : t_ShareRowView =
  match d.users user with
  | None -> { f_account_present = false; f_share_present = false }
  | Some row -> { f_account_present = true; f_share_present = Some? row.ws_share }

/// `plan_select_credential`'s row view.
let credential_view (d: db) (user: text) : t_CredentialRowView =
  match d.users user with
  | None ->
    { f_account_present = false;
      f_credential = WD.StoredCredentialObservation_Missing }
  | Some row ->
    { f_account_present = true;
      f_credential = credential_observation row.ws_credential }

/// The `recovery_share` read, as the `k`-th SQL statement of a run.
let read_share (d: db) (user: text) (fs: option nat) (k: nat)
  : read_outcome t_ShareRowView =
  match plan_select_share user with
  | WebAuthnStmt_SelectShare { f_user = u } ->
    if faulted fs k then Failed else Row (share_view d u)
  | _ -> Failed

/// The stored-credential read, as the `k`-th SQL statement of a run.
let read_credential (d: db) (user: text) (fs: option nat) (k: nat)
  : read_outcome t_CredentialRowView =
  match plan_select_credential user with
  | WebAuthnStmt_SelectCredential { f_user = u } ->
    if faulted fs k then Failed else Row (credential_view d u)
  | _ -> Failed

/// The live account row as the release decision's view reports it.
let finish_account_view (row: user_row) : t_FinishAccountRowView =
  { f_share = core_opt row.ws_share;
    f_stored_epoch = core_opt row.ws_epoch;
    f_rotation_active = row.ws_rekey;
    f_stored_credential_id = core_opt row.ws_cred_id;
    f_split_id = core_opt row.ws_split }

/// `InitiateIo::auth_start_observe`'s attempt-slot probe.
let probe_slot (d: db) (key: text) (fk: option nat) : read_outcome bool =
  match plan_auth_slot key with
  | WebAuthnStmt_AuthSlotExists { f_key = k } ->
    if faulted fk 0
    then Failed
    else Row (slot_occupied d k)
  | _ -> Failed

// ── The executors: plan, run, classify ─────────────────────────────────────

/// `InitiateIo::auth_start_observe`.
let auth_start_observe
      (d: db) (user slot: text) (ttl: u64) (fs fk: option nat)
  : option (WD.t_AuthStartObservation & db) =
  match read_share d user fs 0 with
  | Failed -> None
  | Row share ->
    (match read_credential d user fs 1 with
     | Failed -> None
     | Row credential ->
       (match probe_slot d slot fk with
        | Failed -> None
        | Row occupied ->
          Some (classify_auth_start share credential occupied ttl, d)))

/// `InitiateIo::auth_start_store`: the atomic `set_ex_nx` write. A store error
/// is an observation, not an abort, exactly as the handler reports it.
let store_auth_state
      (d: db) (key value: text) (state: stored_attempt) (ttl: u64) (fk: option nat)
  : (WD.t_ChallengeStoreObservation & db) =
  match plan_store_auth_state key value state ttl with
  | WebAuthnStmt_StoreAuthState { f_key = k; f_state = s; f_ttl_secs = _t } ->
    if faulted fk 0
    then (classify_store_auth_state SetNxOutcome_Failed, d)
    else if slot_occupied d k
    then (classify_store_auth_state SetNxOutcome_Occupied, d)
    else (classify_store_auth_state SetNxOutcome_Wrote,
          upd_attempt d k (Attempt_Valid s))
  | _ -> (classify_store_auth_state SetNxOutcome_Failed, d)

/// `RecoverIo::auth_finish_context`.
let finish_context
      (d: db) (user: text) (attempt_id_present: bool) (fs: option nat)
  : option WD.t_AuthFinishContextObservation =
  match read_share d user fs 0 with
  | Failed -> None
  | Row share ->
    (match read_credential d user fs 1 with
     | Failed -> None
     | Row credential ->
       Some (classify_finish_context share credential attempt_id_present))

/// `RecoverIo::auth_finish_consume`.
let take_auth_state
      (d: db) (key user attempt observed_credential_id: text) (fk: option nat)
  : option (WD.t_AuthAttemptConsumptionObservation & db) =
  match plan_take_auth_state key with
  | WebAuthnStmt_TakeAuthState { f_key = k } ->
    if faulted fk 0
    then None
    else
      let cell = d.attempts k in
      let taken =
        match cell with
        | Attempt_Absent -> AuthStateTake_Missing
        | Attempt_Undecodable -> AuthStateTake_Corrupt
        | Attempt_Valid a -> AuthStateTake_Present a
      in
      Some (classify_take_auth_state taken user attempt observed_credential_id,
            (match cell with
             | Attempt_Absent -> d
             | _ -> upd_attempt d k Attempt_Absent))
  | _ -> None

/// `RecoverIo::auth_finish_update`'s guarded write.
let update_credential
      (d: db) (user expected_credential_id credential credential_id: text)
      (fk: option nat)
  : option (WD.t_CredentialUpdateStoreObservation & db) =
  match plan_update_credential_if_current user expected_credential_id credential credential_id with
  | WebAuthnStmt_UpdateCredentialIfCurrent
      { f_user = u; f_expected_credential_id = expected; f_credential_id = new_id } ->
    if faulted fk 0
    then None
    else
      (if update_guard d u expected
       then
         Some (classify_credential_update (mk_u64 1),
               (match d.users u with
                | Some row ->
                  { d with
                    users = upd d.users u
                      (Some ({ row with
                               ws_credential = Cred_Valid new_id;
                               ws_cred_id = Some new_id }));
                    holders = rebind d.holders u (Some expected) new_id }
                | None -> d))
       else Some (classify_credential_update (mk_u64 0), d))
  | _ -> None

/// `RecoverIo::auth_finish_account`, with its split-id side channel.
let finish_account
      (d: db) (user current_credential_id: text) (fs: option nat)
  : option (WD.t_AuthAccountObservation & Core_models.Option.t_Option text) =
  match plan_finish_account user with
  | WebAuthnStmt_SelectFinishAccount { f_user = u } ->
    if faulted fs 0
    then None
    else
      (match d.users u with
       | None ->
         Some (classify_finish_account Core_models.Option.Option_None current_credential_id,
               Core_models.Option.Option_None)
       | Some row ->
         Some (classify_finish_account
                 (Core_models.Option.Option_Some (finish_account_view row))
                 current_credential_id,
               core_opt row.ws_split))
  | _ -> None

/// `RecoverIo::auth_finish_release`: the released share is the row's own, and
/// decoding changes nothing.
let release_share (d: db) (user: text) (decoded: bool)
  : option (WD.t_ShareDecodeObservation & db) =
  match classify_share_release (share_view d user).f_share_present decoded with
  | Core_models.Option.Option_None -> None
  | Core_models.Option.Option_Some observation -> Some (observation, d)

/// `RecoverIo::auth_finish_store_grant`.
let store_credential_grant
      (d: db) (key value: text) (grant: t_CredentialGrantView) (ttl: u64)
      (fk: option nat)
  : (WD.t_GrantStoreObservation & db) =
  match plan_store_credential_grant key value grant ttl with
  | WebAuthnStmt_StoreCredentialGrant { f_key = k; f_grant = g } ->
    if faulted fk 0
    then (classify_grant_store false, d)
    else (classify_grant_store true, { d with grants = upd d.grants k (Some g) })
  | _ -> (classify_grant_store false, d)

/// `RegisterStartIo::registration_start_observe`.
let registration_start_observe (d: db) (user: text) (fs: option nat)
  : option WD.t_RegistrationStartObservation =
  match read_credential d user fs 0 with
  | Failed -> None
  | Row row -> Some (classify_registration_start row)

/// `RegisterStartIo::registration_start_store`.
let store_registration_state
      (d: db) (key value: text) (ttl: u64) (fk: option nat)
  : (WD.t_ChallengeStoreObservation & db) =
  match plan_store_registration_state key value ttl with
  | WebAuthnStmt_StoreRegistrationState { f_key = k; f_ttl_secs = _t } ->
    if faulted fk 0
    then (classify_store_registration_state SetOutcome_Failed, d)
    else (classify_store_registration_state SetOutcome_Wrote,
          upd_registration d k Registration_Valid)
  | _ -> (classify_store_registration_state SetOutcome_Failed, d)

/// `RegisterFinishIo::registration_consume_state`.
let take_registration_state
      (d: db) (key: text) (fk: option nat)
  : option (WD.t_RegistrationStateObservation & db) =
  match plan_take_registration_state key with
  | WebAuthnStmt_TakeRegistrationState { f_key = k } ->
    if faulted fk 0
    then None
    else
      let cell = d.registrations k in
      let taken =
        match cell with
        | Registration_Absent -> RegistrationStateTake_Missing
        | Registration_Undecodable -> RegistrationStateTake_Corrupt
        | Registration_Valid -> RegistrationStateTake_Present
      in
      Some (classify_registration_state taken,
            (match cell with
             | Registration_Absent -> d
             | _ -> upd_registration d k Registration_Absent))
  | _ -> None

/// `RegisterFinishIo::registration_check_uniqueness`. A lookup failure is the
/// `Unreadable` view, exactly as the handler reports it.
let holder_view (d: db) (credential_id user: text) (fs: option nat)
  : t_CredentialHolderView =
  match plan_credential_holders credential_id with
  | WebAuthnStmt_SelectCredentialHolders { f_credential_id = c } ->
    if faulted fs 0
    then CredentialHolderView_Unreadable
    else if holder_other d c user
    then CredentialHolderView_OtherAccount
    else CredentialHolderView_OnlyCaller
  | _ -> CredentialHolderView_Unreadable

/// `RegisterFinishIo::registration_check_uniqueness`.
let check_uniqueness (d: db) (credential_id user: text) (fs: option nat)
  : WD.t_CredentialUniquenessObservation =
  classify_uniqueness (holder_view d credential_id user fs)

/// The outcome slice a one-statement write plan produces.
let one_outcome (o: RS.t_WriteOutcome{L.length [o] <= Rust_primitives.Integers.max_usize})
  : t_Slice RS.t_WriteOutcome =
  Seq.seq_of_list [o]

/// `RegisterFinishIo::registration_persist`: serialization failure, write
/// failure, a zero-row update or the landed write.
let persist_credential
      (d: db) (user credential credential_id: text) (encoded: bool) (fk: option nat)
  : (WD.t_CredentialPersistObservation & db) =
  match plan_persist_credential user credential credential_id with
  | WebAuthnStmt_PersistCredential { f_user = u; f_credential_id = new_id } ->
    if not encoded
    then (classify_persist_credential false (one_outcome RS.WriteOutcome_Failed), d)
    else if faulted fk 0
    then (classify_persist_credential true (one_outcome RS.WriteOutcome_Failed), d)
    else
      (match d.users u with
       | None ->
         (classify_persist_credential true
            (one_outcome (RS.WriteOutcome_Applied (mk_u64 0))), d)
       | Some row ->
         (classify_persist_credential true
            (one_outcome (RS.WriteOutcome_Applied (mk_u64 1))),
          { d with
            users = upd d.users u
              (Some ({ row with
                       ws_credential = Cred_Valid new_id;
                       ws_cred_id = Some new_id }));
            holders = rebind d.holders u row.ws_cred_id new_id }))
  | _ -> (classify_persist_credential true (one_outcome RS.WriteOutcome_Failed), d)
