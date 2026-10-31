module Vela_recovery_policy.Webauthn_store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// What one attempt slot holds, as the plan writes it: the bindings the
/// redemption side later compares with the request.
type t_AuthStateView = {
  f_user:Alloc.String.t_String;
  f_attempt:Alloc.String.t_String;
  f_credential_id:Alloc.String.t_String
}

/// One credential-bound enrollment grant as the store holds it.
type t_CredentialGrantView = {
  f_key_epoch:i64;
  f_credential_id:Alloc.String.t_String;
  f_possession:bool
}

/// One statement a WebAuthn executor method runs.
type t_WebAuthnStmt =
  | WebAuthnStmt_SelectShare { f_user:Alloc.String.t_String }: t_WebAuthnStmt
  | WebAuthnStmt_SelectCredential { f_user:Alloc.String.t_String }: t_WebAuthnStmt
  | WebAuthnStmt_AuthSlotExists { f_key:Alloc.String.t_String }: t_WebAuthnStmt
  | WebAuthnStmt_StoreAuthState {
    f_key:Alloc.String.t_String;
    f_value:Alloc.String.t_String;
    f_state:t_AuthStateView;
    f_ttl_secs:u64
  }: t_WebAuthnStmt
  | WebAuthnStmt_TakeAuthState { f_key:Alloc.String.t_String }: t_WebAuthnStmt
  | WebAuthnStmt_SelectFinishAccount { f_user:Alloc.String.t_String }: t_WebAuthnStmt
  | WebAuthnStmt_UpdateCredentialIfCurrent {
    f_user:Alloc.String.t_String;
    f_expected_credential_id:Alloc.String.t_String;
    f_credential:Alloc.String.t_String;
    f_credential_id:Alloc.String.t_String
  }: t_WebAuthnStmt
  | WebAuthnStmt_SelectCredentialHolders { f_credential_id:Alloc.String.t_String }: t_WebAuthnStmt
  | WebAuthnStmt_PersistCredential {
    f_user:Alloc.String.t_String;
    f_credential:Alloc.String.t_String;
    f_credential_id:Alloc.String.t_String
  }: t_WebAuthnStmt
  | WebAuthnStmt_StoreRegistrationState {
    f_key:Alloc.String.t_String;
    f_value:Alloc.String.t_String;
    f_ttl_secs:u64
  }: t_WebAuthnStmt
  | WebAuthnStmt_TakeRegistrationState { f_key:Alloc.String.t_String }: t_WebAuthnStmt
  | WebAuthnStmt_StoreCredentialGrant {
    f_key:Alloc.String.t_String;
    f_value:Alloc.String.t_String;
    f_grant:t_CredentialGrantView;
    f_ttl_secs:u64
  }: t_WebAuthnStmt

/// The `recovery_share` read: whether the account exists and whether the
/// column is non-null.
type t_ShareRowView = {
  f_account_present:bool;
  f_share_present:bool
}

/// The stored-credential read: whether the account exists and what the
/// credential cell decodes to.
type t_CredentialRowView = {
  f_account_present:bool;
  f_credential:Vela_recovery_policy.Webauthn_driver.t_StoredCredentialObservation
}

/// The five cells of a live account row at release time.
type t_FinishAccountRowView = {
  f_share:Core_models.Option.t_Option Alloc.String.t_String;
  f_stored_epoch:Core_models.Option.t_Option i64;
  f_rotation_active:bool;
  f_stored_credential_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_split_id:Core_models.Option.t_Option Alloc.String.t_String
}

/// What the atomic `get_del` of one attempt envelope observed. A store error
/// aborts the request before classification, so it is not a variant here.
type t_AuthStateTake =
  | AuthStateTake_Missing : t_AuthStateTake
  | AuthStateTake_Corrupt : t_AuthStateTake
  | AuthStateTake_Present : t_AuthStateView -> t_AuthStateTake

/// What the atomic `get_del` of the registration state observed.
type t_RegistrationStateTake =
  | RegistrationStateTake_Missing : t_RegistrationStateTake
  | RegistrationStateTake_Corrupt : t_RegistrationStateTake
  | RegistrationStateTake_Present : t_RegistrationStateTake

/// What one atomic `set_ex_nx` reported.
type t_SetNxOutcome =
  | SetNxOutcome_Wrote : t_SetNxOutcome
  | SetNxOutcome_Occupied : t_SetNxOutcome
  | SetNxOutcome_Failed : t_SetNxOutcome

/// What one atomic `set_ex` reported.
type t_SetOutcome =
  | SetOutcome_Wrote : t_SetOutcome
  | SetOutcome_Failed : t_SetOutcome

/// Whether another account holds the credential id. `Unreadable` covers a
/// failed lookup and a holder row whose id cell does not read as text.
type t_CredentialHolderView =
  | CredentialHolderView_OtherAccount : t_CredentialHolderView
  | CredentialHolderView_OnlyCaller : t_CredentialHolderView
  | CredentialHolderView_Unreadable : t_CredentialHolderView

/// `InitiateIo::auth_start_observe` / `RecoverIo::auth_finish_context`: read
/// the account's `recovery_share` cell.
let plan_select_share (user: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_SelectShare ({ f_user = user }) <: t_WebAuthnStmt

/// `InitiateIo::auth_start_observe` / `RecoverIo::auth_finish_context` /
/// `RegisterStartIo::registration_start_observe`: read the stored recovery
/// credential.
let plan_select_credential (user: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_SelectCredential ({ f_user = user }) <: t_WebAuthnStmt

/// `InitiateIo::auth_start_observe`: probe the generated attempt slot.
let plan_auth_slot (key: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_AuthSlotExists ({ f_key = key }) <: t_WebAuthnStmt

/// `InitiateIo::auth_start_store`: commit the drawn attempt envelope.
let plan_store_auth_state
      (key value: Alloc.String.t_String)
      (state: t_AuthStateView)
      (ttl_secs: u64)
    : t_WebAuthnStmt =
  WebAuthnStmt_StoreAuthState
  ({ f_key = key; f_value = value; f_state = state; f_ttl_secs = ttl_secs })
  <:
  t_WebAuthnStmt

/// `RecoverIo::auth_finish_consume`: the atomic single-use take.
let plan_take_auth_state (key: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_TakeAuthState ({ f_key = key }) <: t_WebAuthnStmt

/// `RecoverIo::auth_finish_account`: read the live row.
let plan_finish_account (user: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_SelectFinishAccount ({ f_user = user }) <: t_WebAuthnStmt

/// `RecoverIo::auth_finish_update`: replace the stored credential only while
/// the exact stored id is still current.
let plan_update_credential_if_current
      (user expected_credential_id credential credential_id: Alloc.String.t_String)
    : t_WebAuthnStmt =
  WebAuthnStmt_UpdateCredentialIfCurrent
  ({
      f_user = user;
      f_expected_credential_id = expected_credential_id;
      f_credential = credential;
      f_credential_id = credential_id
    })
  <:
  t_WebAuthnStmt

/// `RegisterFinishIo::registration_check_uniqueness`: the duplicate lookup.
let plan_credential_holders (credential_id: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_SelectCredentialHolders ({ f_credential_id = credential_id }) <: t_WebAuthnStmt

/// `RegisterFinishIo::registration_persist`: write the credential onto the
/// caller's row.
let plan_persist_credential (user credential credential_id: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_PersistCredential
  ({ f_user = user; f_credential = credential; f_credential_id = credential_id })
  <:
  t_WebAuthnStmt

/// `RegisterStartIo::registration_start_store`: write the ceremony state.
let plan_store_registration_state (key value: Alloc.String.t_String) (ttl_secs: u64)
    : t_WebAuthnStmt =
  WebAuthnStmt_StoreRegistrationState ({ f_key = key; f_value = value; f_ttl_secs = ttl_secs })
  <:
  t_WebAuthnStmt

/// `RegisterFinishIo::registration_consume_state`: the atomic single-use take.
let plan_take_registration_state (key: Alloc.String.t_String) : t_WebAuthnStmt =
  WebAuthnStmt_TakeRegistrationState ({ f_key = key }) <: t_WebAuthnStmt

/// `RecoverIo::auth_finish_store_grant`: store exactly one grant.
let plan_store_credential_grant
      (key value: Alloc.String.t_String)
      (grant: t_CredentialGrantView)
      (ttl_secs: u64)
    : t_WebAuthnStmt =
  WebAuthnStmt_StoreCredentialGrant
  ({ f_key = key; f_value = value; f_grant = grant; f_ttl_secs = ttl_secs })
  <:
  t_WebAuthnStmt

/// `InitiateIo::auth_start_observe`: every field is the truth about the live
/// row, and the attempt slot is reported fresh exactly when it was empty.
let classify_auth_start
      (share: t_ShareRowView)
      (credential: t_CredentialRowView)
      (slot_occupied: bool)
      (ttl_secs: u64)
    : Vela_recovery_policy.Webauthn_driver.t_AuthStartObservation =
  {
    Vela_recovery_policy.Webauthn_driver.f_account_present = share.f_account_present;
    Vela_recovery_policy.Webauthn_driver.f_share_present = share.f_share_present;
    Vela_recovery_policy.Webauthn_driver.f_credential = credential.f_credential;
    Vela_recovery_policy.Webauthn_driver.f_attempt_id_fresh = ~.slot_occupied;
    Vela_recovery_policy.Webauthn_driver.f_ttl_secs = ttl_secs
  }
  <:
  Vela_recovery_policy.Webauthn_driver.t_AuthStartObservation

/// `RecoverIo::auth_finish_context`: the same row facts plus whether the
/// request carried an attempt id.
let classify_finish_context
      (share: t_ShareRowView)
      (credential: t_CredentialRowView)
      (attempt_id_present: bool)
    : Vela_recovery_policy.Webauthn_driver.t_AuthFinishContextObservation =
  {
    Vela_recovery_policy.Webauthn_driver.f_account_present = share.f_account_present;
    Vela_recovery_policy.Webauthn_driver.f_share_present = share.f_share_present;
    Vela_recovery_policy.Webauthn_driver.f_credential = credential.f_credential;
    Vela_recovery_policy.Webauthn_driver.f_attempt_id_present = attempt_id_present
  }
  <:
  Vela_recovery_policy.Webauthn_driver.t_AuthFinishContextObservation

/// `InitiateIo::auth_start_store`: this call wrote the slot, another writer
/// already held it, or the store failed.
let classify_store_auth_state (outcome: t_SetNxOutcome)
    : Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation =
  match outcome <: t_SetNxOutcome with
  | SetNxOutcome_Wrote  ->
    Vela_recovery_policy.Webauthn_driver.ChallengeStoreObservation_Stored
    <:
    Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation
  | SetNxOutcome_Occupied  ->
    Vela_recovery_policy.Webauthn_driver.ChallengeStoreObservation_Lost
    <:
    Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation
  | SetNxOutcome_Failed  ->
    Vela_recovery_policy.Webauthn_driver.ChallengeStoreObservation_StorageFailed
    <:
    Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation

/// `RegisterStartIo::registration_start_store`: the overwriting write either
/// landed or failed.
let classify_store_registration_state (outcome: t_SetOutcome)
    : Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation =
  match outcome <: t_SetOutcome with
  | SetOutcome_Wrote  ->
    Vela_recovery_policy.Webauthn_driver.ChallengeStoreObservation_Stored
    <:
    Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation
  | SetOutcome_Failed  ->
    Vela_recovery_policy.Webauthn_driver.ChallengeStoreObservation_StorageFailed
    <:
    Vela_recovery_policy.Webauthn_driver.t_ChallengeStoreObservation

/// `RecoverIo::auth_finish_consume`: the removed envelope's own bindings and
/// the comparisons with the request and the live credential.
let classify_take_auth_state
      (taken: t_AuthStateTake)
      (user attempt observed_credential_id: Alloc.String.t_String)
    : Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation =
  match taken <: t_AuthStateTake with
  | AuthStateTake_Missing  ->
    Vela_recovery_policy.Webauthn_driver.AuthAttemptConsumptionObservation_Missing
    <:
    Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation
  | AuthStateTake_Corrupt  ->
    Vela_recovery_policy.Webauthn_driver.AuthAttemptConsumptionObservation_Corrupt
    <:
    Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation
  | AuthStateTake_Present state ->
    Vela_recovery_policy.Webauthn_driver.AuthAttemptConsumptionObservation_Present
    ({
        Vela_recovery_policy.Webauthn_driver.f_user_matches = state.f_user =. user;
        Vela_recovery_policy.Webauthn_driver.f_attempt_matches = state.f_attempt =. attempt;
        Vela_recovery_policy.Webauthn_driver.f_credential_matches
        =
        state.f_credential_id =. observed_credential_id
      })
    <:
    Vela_recovery_policy.Webauthn_driver.t_AuthAttemptConsumptionObservation

/// `RecoverIo::auth_finish_update`: a `UPDATE` that changed a row is `Updated`;
/// a zero-row update is `Changed`.
let classify_credential_update (rows: u64)
    : Vela_recovery_policy.Webauthn_driver.t_CredentialUpdateStoreObservation =
  if rows >. mk_u64 0
  then
    Vela_recovery_policy.Webauthn_driver.CredentialUpdateStoreObservation_Updated
    <:
    Vela_recovery_policy.Webauthn_driver.t_CredentialUpdateStoreObservation
  else
    Vela_recovery_policy.Webauthn_driver.CredentialUpdateStoreObservation_Changed
    <:
    Vela_recovery_policy.Webauthn_driver.t_CredentialUpdateStoreObservation

/// `RecoverIo::auth_finish_account`: every field is the live row's truth,
/// compared with the challenge-bound credential id.
let classify_finish_account
      (row: Core_models.Option.t_Option t_FinishAccountRowView)
      (credential_id: Alloc.String.t_String)
    : Vela_recovery_policy.Webauthn_driver.t_AuthAccountObservation =
  match row <: Core_models.Option.t_Option t_FinishAccountRowView with
  | Core_models.Option.Option_None  ->
    {
      Vela_recovery_policy.Webauthn_driver.f_account_present = false;
      Vela_recovery_policy.Webauthn_driver.f_account_epoch_active = false;
      Vela_recovery_policy.Webauthn_driver.f_share_present = false;
      Vela_recovery_policy.Webauthn_driver.f_stored_credential_matches = false;
      Vela_recovery_policy.Webauthn_driver.f_stored_epoch
      =
      Core_models.Option.Option_None <: Core_models.Option.t_Option i64
    }
    <:
    Vela_recovery_policy.Webauthn_driver.t_AuthAccountObservation
  | Core_models.Option.Option_Some row ->
    {
      Vela_recovery_policy.Webauthn_driver.f_account_present = true;
      Vela_recovery_policy.Webauthn_driver.f_account_epoch_active = ~.row.f_rotation_active;
      Vela_recovery_policy.Webauthn_driver.f_share_present
      =
      Core_models.Option.impl__is_some #Alloc.String.t_String row.f_share;
      Vela_recovery_policy.Webauthn_driver.f_stored_credential_matches
      =
      (Core_models.Option.impl__as_ref #Alloc.String.t_String row.f_stored_credential_id
        <:
        Core_models.Option.t_Option Alloc.String.t_String) =.
      (Core_models.Option.Option_Some credential_id
        <:
        Core_models.Option.t_Option Alloc.String.t_String);
      Vela_recovery_policy.Webauthn_driver.f_stored_epoch = row.f_stored_epoch
    }
    <:
    Vela_recovery_policy.Webauthn_driver.t_AuthAccountObservation

/// `RecoverIo::auth_finish_account`'s split-id side channel: the live row's
/// `recovery_split_id`, exactly as read.
let finish_account_split (row: Core_models.Option.t_Option t_FinishAccountRowView)
    : Core_models.Option.t_Option Alloc.String.t_String =
  match row <: Core_models.Option.t_Option t_FinishAccountRowView with
  | Core_models.Option.Option_None  ->
    Core_models.Option.Option_None <: Core_models.Option.t_Option Alloc.String.t_String
  | Core_models.Option.Option_Some row ->
    Core_models.Clone.f_clone #(Core_models.Option.t_Option Alloc.String.t_String)
      #FStar.Tactics.Typeclasses.solve
      row.f_split_id

/// `RecoverIo::auth_finish_release`: the observed share text decoded, did not
/// decode, or the row carried no share (the handler aborts).
let classify_share_release (share_present decoded: bool)
    : Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation =
  if ~.share_present
  then
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation
  else
    if decoded
    then
      Core_models.Option.Option_Some
      (Vela_recovery_policy.Webauthn_driver.ShareDecodeObservation_Decoded
        <:
        Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation)
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation
    else
      Core_models.Option.Option_Some
      (Vela_recovery_policy.Webauthn_driver.ShareDecodeObservation_Corrupt
        <:
        Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation)
      <:
      Core_models.Option.t_Option Vela_recovery_policy.Webauthn_driver.t_ShareDecodeObservation

/// `RecoverIo::auth_finish_store_grant`: `Stored` exactly when the store wrote.
let classify_grant_store (stored: bool)
    : Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation =
  if stored
  then
    Vela_recovery_policy.Webauthn_driver.GrantStoreObservation_Stored
    <:
    Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation
  else
    Vela_recovery_policy.Webauthn_driver.GrantStoreObservation_Failed
    <:
    Vela_recovery_policy.Webauthn_driver.t_GrantStoreObservation

/// `RegisterStartIo::registration_start_observe`: the row's own facts.
let classify_registration_start (row: t_CredentialRowView)
    : Vela_recovery_policy.Webauthn_driver.t_RegistrationStartObservation =
  {
    Vela_recovery_policy.Webauthn_driver.f_account_present = row.f_account_present;
    Vela_recovery_policy.Webauthn_driver.f_credential = row.f_credential
  }
  <:
  Vela_recovery_policy.Webauthn_driver.t_RegistrationStartObservation

/// `RegisterFinishIo::registration_consume_state`: the removed state decoded,
/// did not decode, or nothing matched.
let classify_registration_state (taken: t_RegistrationStateTake)
    : Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation =
  match taken <: t_RegistrationStateTake with
  | RegistrationStateTake_Missing  ->
    Vela_recovery_policy.Webauthn_driver.RegistrationStateObservation_Missing
    <:
    Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation
  | RegistrationStateTake_Corrupt  ->
    Vela_recovery_policy.Webauthn_driver.RegistrationStateObservation_Corrupt
    <:
    Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation
  | RegistrationStateTake_Present  ->
    Vela_recovery_policy.Webauthn_driver.RegistrationStateObservation_Present
    <:
    Vela_recovery_policy.Webauthn_driver.t_RegistrationStateObservation

/// `RegisterFinishIo::registration_check_uniqueness`: the lookup's own facts.
let classify_uniqueness (view: t_CredentialHolderView)
    : Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation =
  match view <: t_CredentialHolderView with
  | CredentialHolderView_OtherAccount  ->
    Vela_recovery_policy.Webauthn_driver.CredentialUniquenessObservation_RegisteredElsewhere
    <:
    Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation
  | CredentialHolderView_OnlyCaller  ->
    Vela_recovery_policy.Webauthn_driver.CredentialUniquenessObservation_Unique
    <:
    Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation
  | CredentialHolderView_Unreadable  ->
    Vela_recovery_policy.Webauthn_driver.CredentialUniquenessObservation_LookupFailed
    <:
    Vela_recovery_policy.Webauthn_driver.t_CredentialUniquenessObservation

/// `RegisterFinishIo::registration_persist`: the serialized credential either
/// updated the caller's row, found no row, failed to serialize, or the write
/// itself failed.
let classify_persist_credential
      (encoded: bool)
      (outcomes: t_Slice Vela_recovery_policy.Redemption_store.t_WriteOutcome)
    : Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation =
  if ~.encoded
  then
    Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_EncodingFailed
    <:
    Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation
  else
    if
      (Core_models.Slice.impl__len #Vela_recovery_policy.Redemption_store.t_WriteOutcome outcomes
        <:
        usize) =.
      mk_usize 1
    then
      match outcomes.[ mk_usize 0 ] <: Vela_recovery_policy.Redemption_store.t_WriteOutcome with
      | Vela_recovery_policy.Redemption_store.WriteOutcome_Applied rows ->
        if rows >. mk_u64 0
        then
          Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_Persisted
          <:
          Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation
        else
          Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_AccountGone
          <:
          Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation
      | Vela_recovery_policy.Redemption_store.WriteOutcome_Failed  ->
        Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_StorageFailed
        <:
        Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation
    else
      Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_StorageFailed
      <:
      Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation
