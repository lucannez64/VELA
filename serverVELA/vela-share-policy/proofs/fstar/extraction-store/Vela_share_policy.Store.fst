module Vela_share_policy.Store
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// One statement an executor may run. Field names follow the bound
/// parameters; [`render`] fixes their order.
type t_ShareStmt =
  | ShareStmt_SelectLink { f_id:Alloc.String.t_String }: t_ShareStmt
  | ShareStmt_SelectDevice {
    f_device_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_InsertSharedItem {
    f_id:Alloc.String.t_String;
    f_sender:Alloc.String.t_String;
    f_recipient:Alloc.String.t_String;
    f_capsule:Alloc.String.t_String;
    f_now:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_InsertInboxItem {
    f_id:Alloc.String.t_String;
    f_sender:Alloc.String.t_String;
    f_recipient:Alloc.String.t_String;
    f_capsule:Alloc.String.t_String;
    f_now:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_UpdateLinkedCapsule {
    f_capsule:Alloc.String.t_String;
    f_now:Alloc.String.t_String;
    f_id:Alloc.String.t_String;
    f_sender:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_RevokeLinkedItem {
    f_now:Alloc.String.t_String;
    f_id:Alloc.String.t_String;
    f_sender:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_DeleteLinkedInbox { f_id:Alloc.String.t_String }: t_ShareStmt
  | ShareStmt_DeleteInboxItem {
    f_id:Alloc.String.t_String;
    f_recipient:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_UpdateShareEk {
    f_share_ek:Alloc.String.t_String;
    f_since:Alloc.String.t_String;
    f_device_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String
  }: t_ShareStmt
  | ShareStmt_Commit : t_ShareStmt

/// What one write statement (or the commit) returned.
type t_WriteOutcome =
  | WriteOutcome_Applied : u64 -> t_WriteOutcome
  | WriteOutcome_Failed : t_WriteOutcome

/// What one read statement returned: its first row, or an error.
type t_ReadOutcome (v_R: Type0) =
  | ReadOutcome_Row : Core_models.Option.t_Option v_R -> t_ReadOutcome v_R
  | ReadOutcome_Failed : t_ReadOutcome v_R

/// The cells of a `SelectLink` row, as the handler decodes them: a text
/// `sender_user_id` and an integer `revoked`.
type t_LinkRowView = {
  f_sender:Core_models.Option.t_Option Alloc.String.t_String;
  f_revoked:Core_models.Option.t_Option i64
}

/// The cells of a `SelectDevice` row: `d.hybrid_vk`, `d.revoked`,
/// `u.share_ek_since`, `d.user_id`. `revoked` is `Some(i)` for an integer
/// cell, `Some(1)` for the text `"1"`, and `None` otherwise.
type t_DeviceRowView = {
  f_hybrid_vk:Core_models.Option.t_Option Alloc.String.t_String;
  f_revoked:Core_models.Option.t_Option i64;
  f_share_ek_since:Core_models.Option.t_Option Alloc.String.t_String;
  f_user_id:Core_models.Option.t_Option Alloc.String.t_String
}

/// Verdicts the handler computes from a device row's key and binding instant
/// (base64 decoding, the hybrid signature check, the freshness comparison).
/// They are inputs here: crypto and decoding stay outside the store model.
type t_DeviceVerdicts = {
  f_signature_verified:bool;
  f_stored_vk_decode_failed:bool;
  f_signature_decode_failed:bool;
  f_signed_at_is_fresher:bool
}

/// `insert_capsule`: both copies of the capsule, then the commit, inside the
/// transaction the handler opened for the quota reads.
let plan_send_insert (id sender recipient capsule now: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            ShareStmt_InsertSharedItem
            ({
                f_id
                =
                Core_models.Clone.f_clone #Alloc.String.t_String #FStar.Tactics.Typeclasses.solve id;
                f_sender
                =
                Core_models.Clone.f_clone #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  sender;
                f_recipient
                =
                Core_models.Clone.f_clone #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  recipient;
                f_capsule
                =
                Core_models.Clone.f_clone #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  capsule;
                f_now
                =
                Core_models.Clone.f_clone #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  now
              })
            <:
            t_ShareStmt;
            ShareStmt_InsertInboxItem
            ({
                f_id = id;
                f_sender = sender;
                f_recipient = recipient;
                f_capsule = capsule;
                f_now = now
              })
            <:
            t_ShareStmt;
            ShareStmt_Commit <: t_ShareStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
        Rust_primitives.Hax.array_of_list 3 list)
      <:
      t_Slice t_ShareStmt)

/// `observe_link`: read the linked row.
let plan_link_read (id: Alloc.String.t_String) : t_ShareStmt =
  ShareStmt_SelectLink ({ f_id = id }) <: t_ShareStmt

/// `update_linked_item`: one guarded update (autocommit).
let plan_link_update (id sender capsule now: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            ShareStmt_UpdateLinkedCapsule
            ({ f_capsule = capsule; f_now = now; f_id = id; f_sender = sender })
            <:
            t_ShareStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// `revoke_linked_item`: one guarded revoke (autocommit).
let plan_link_revoke (id sender now: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            ShareStmt_RevokeLinkedItem ({ f_now = now; f_id = id; f_sender = sender })
            <:
            t_ShareStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// `delete_linked_inbox`: drop the revoked item's pending inbox copy.
let plan_linked_inbox_cleanup (id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list = [ShareStmt_DeleteLinkedInbox ({ f_id = id }) <: t_ShareStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// `delete_inbox_item`: one recipient-scoped delete (autocommit).
let plan_inbox_delete (id recipient: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [ShareStmt_DeleteInboxItem ({ f_id = id; f_recipient = recipient }) <: t_ShareStmt]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// `observe_device`: read the caller's signing-device row.
let plan_device_read (device_id user: Alloc.String.t_String) : t_ShareStmt =
  ShareStmt_SelectDevice ({ f_device_id = device_id; f_user = user }) <: t_ShareStmt

/// `update_share_ek`: one binding update (autocommit).
let plan_share_ek_update (user share_ek since device_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_ShareStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_ShareStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            ShareStmt_UpdateShareEk
            ({ f_share_ek = share_ek; f_since = since; f_device_id = device_id; f_user = user })
            <:
            t_ShareStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_ShareStmt)

/// The send transaction: committed only when both inserts and the commit
/// succeeded; a failed commit is a conflict; anything else a storage failure.
let classify_send (outcomes: t_Slice t_WriteOutcome)
    : Vela_share_policy.Driver.t_SendResultObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 3
  then
    match
      outcomes.[ mk_usize 0 ], outcomes.[ mk_usize 1 ], outcomes.[ mk_usize 2 ]
      <:
      (t_WriteOutcome & t_WriteOutcome & t_WriteOutcome)
    with
    | WriteOutcome_Applied _, WriteOutcome_Applied _, WriteOutcome_Applied _ ->
      Vela_share_policy.Driver.SendResultObservation_Committed
      <:
      Vela_share_policy.Driver.t_SendResultObservation
    | WriteOutcome_Applied _, WriteOutcome_Applied _, WriteOutcome_Failed  ->
      Vela_share_policy.Driver.SendResultObservation_CommitConflict
      <:
      Vela_share_policy.Driver.t_SendResultObservation
    | _ ->
      Vela_share_policy.Driver.SendResultObservation_StorageFailed
      <:
      Vela_share_policy.Driver.t_SendResultObservation
  else
    Vela_share_policy.Driver.SendResultObservation_StorageFailed
    <:
    Vela_share_policy.Driver.t_SendResultObservation

/// A single guarded write: the rows it changed, or none if it failed.
let classify_rows (outcomes: t_Slice t_WriteOutcome) : Vela_share_policy.Driver.t_RowsObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied rows ->
      { Vela_share_policy.Driver.f_rows = rows } <: Vela_share_policy.Driver.t_RowsObservation
    | WriteOutcome_Failed  ->
      { Vela_share_policy.Driver.f_rows = mk_u64 0 } <: Vela_share_policy.Driver.t_RowsObservation
  else { Vela_share_policy.Driver.f_rows = mk_u64 0 } <: Vela_share_policy.Driver.t_RowsObservation

/// The revoke's inbox cleanup: it failed unless its one statement ran.
let classify_cleanup (outcomes: t_Slice t_WriteOutcome)
    : Vela_share_policy.Driver.t_CleanupObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied _ ->
      { Vela_share_policy.Driver.f_storage_failed = false }
      <:
      Vela_share_policy.Driver.t_CleanupObservation
    | WriteOutcome_Failed  ->
      { Vela_share_policy.Driver.f_storage_failed = true }
      <:
      Vela_share_policy.Driver.t_CleanupObservation
  else
    { Vela_share_policy.Driver.f_storage_failed = true }
    <:
    Vela_share_policy.Driver.t_CleanupObservation

/// The linked row as the mutation policy sees it. A failed read rejects.
let classify_link (caller: Alloc.String.t_String) (outcome: t_ReadOutcome t_LinkRowView)
    : Vela_share_policy.t_LinkMutationObservation =
  match outcome <: t_ReadOutcome t_LinkRowView with
  | ReadOutcome_Row (Core_models.Option.Option_Some row) ->
    {
      Vela_share_policy.f_item_present = true;
      Vela_share_policy.f_caller_matches_sender
      =
      (match row.f_sender <: Core_models.Option.t_Option Alloc.String.t_String with
        | Core_models.Option.Option_Some sender -> sender =. caller
        | Core_models.Option.Option_None  -> false);
      Vela_share_policy.f_item_not_revoked
      =
      match row.f_revoked <: Core_models.Option.t_Option i64 with
      | Core_models.Option.Option_Some revoked -> revoked =. mk_i64 0
      | Core_models.Option.Option_None  -> false
    }
    <:
    Vela_share_policy.t_LinkMutationObservation
  | _ ->
    {
      Vela_share_policy.f_item_present = false;
      Vela_share_policy.f_caller_matches_sender = false;
      Vela_share_policy.f_item_not_revoked = false
    }
    <:
    Vela_share_policy.t_LinkMutationObservation

/// The signing-device row as the registration policy sees it. A failed read
/// gives the historical rejecting observation.
let classify_device
      (caller: Alloc.String.t_String)
      (ek_len: usize)
      (outcome: t_ReadOutcome t_DeviceRowView)
      (verdicts: t_DeviceVerdicts)
    : Vela_share_policy.Driver.t_EkDeviceObservation =
  match outcome <: t_ReadOutcome t_DeviceRowView with
  | ReadOutcome_Failed  ->
    {
      Vela_share_policy.Driver.f_registration
      =
      {
        Vela_share_policy.f_ek_len = Vela_share_policy.v_SHARE_EK_LEN;
        Vela_share_policy.f_signature_verified = false;
        Vela_share_policy.f_device_row_present = false;
        Vela_share_policy.f_device_user_matches = false;
        Vela_share_policy.f_device_active = false;
        Vela_share_policy.f_signed_at_is_fresher = false;
        Vela_share_policy.f_binding_exists = false
      }
      <:
      Vela_share_policy.t_EkRegistrationObservation;
      Vela_share_policy.Driver.f_stored_identity_vk_decode_failed = false;
      Vela_share_policy.Driver.f_signature_decode_failed = false
    }
    <:
    Vela_share_policy.Driver.t_EkDeviceObservation
  | ReadOutcome_Row row ->
    let (present: bool), (user_matches: bool), (active: bool), (binding_exists: bool) =
      match row <: Core_models.Option.t_Option t_DeviceRowView with
      | Core_models.Option.Option_Some row ->
        true,
        (match row.f_user_id <: Core_models.Option.t_Option Alloc.String.t_String with
          | Core_models.Option.Option_Some owner -> owner =. caller
          | Core_models.Option.Option_None  -> false),
        (match row.f_revoked <: Core_models.Option.t_Option i64 with
          | Core_models.Option.Option_Some revoked -> revoked <>. mk_i64 1
          | Core_models.Option.Option_None  -> true),
        (match row.f_share_ek_since <: Core_models.Option.t_Option Alloc.String.t_String with
          | Core_models.Option.Option_Some _ -> true
          | Core_models.Option.Option_None  -> false)
        <:
        (bool & bool & bool & bool)
      | Core_models.Option.Option_None  -> false, false, false, false <: (bool & bool & bool & bool)
    in
    {
      Vela_share_policy.Driver.f_registration
      =
      {
        Vela_share_policy.f_ek_len = ek_len;
        Vela_share_policy.f_signature_verified = verdicts.f_signature_verified;
        Vela_share_policy.f_device_row_present = present;
        Vela_share_policy.f_device_user_matches = user_matches;
        Vela_share_policy.f_device_active = active;
        Vela_share_policy.f_signed_at_is_fresher = verdicts.f_signed_at_is_fresher;
        Vela_share_policy.f_binding_exists = binding_exists
      }
      <:
      Vela_share_policy.t_EkRegistrationObservation;
      Vela_share_policy.Driver.f_stored_identity_vk_decode_failed
      =
      verdicts.f_stored_vk_decode_failed;
      Vela_share_policy.Driver.f_signature_decode_failed = verdicts.f_signature_decode_failed
    }
    <:
    Vela_share_policy.Driver.t_EkDeviceObservation

/// One statement an `sends` executor may run (F-1, send-link driver). The
/// `sends` table is keyed by its `UNIQUE` id; every statement here is
/// autocommit, so no transaction or `Commit` statement exists.
type t_SendStmt =
  | SendStmt_InsertSend {
    f_id:Alloc.String.t_String;
    f_owner:Alloc.String.t_String;
    f_ciphertext:Alloc.String.t_String;
    f_has_passphrase:bool;
    f_kdf_salt:Core_models.Option.t_Option Alloc.String.t_String;
    f_label:Core_models.Option.t_Option Alloc.String.t_String;
    f_view_once:bool;
    f_max_views:Core_models.Option.t_Option i64;
    f_created_at:Alloc.String.t_String;
    f_expires_at:Alloc.String.t_String
  }: t_SendStmt
  | SendStmt_ConsumeSendView {
    f_id:Alloc.String.t_String;
    f_now:Alloc.String.t_String
  }: t_SendStmt
  | SendStmt_SelectSend { f_id:Alloc.String.t_String }: t_SendStmt
  | SendStmt_DeleteSend { f_id:Alloc.String.t_String }: t_SendStmt
  | SendStmt_DeleteOwnedSend {
    f_id:Alloc.String.t_String;
    f_owner:Alloc.String.t_String
  }: t_SendStmt

/// The cells of a `SelectSend` row, as the handler decodes them.
type t_SendRowView = {
  f_ciphertext:Core_models.Option.t_Option Alloc.String.t_String;
  f_has_passphrase:Core_models.Option.t_Option i64;
  f_kdf_salt:Core_models.Option.t_Option Alloc.String.t_String;
  f_view_once:Core_models.Option.t_Option i64;
  f_max_views:Core_models.Option.t_Option i64;
  f_view_count:Core_models.Option.t_Option i64;
  f_expires_at:Core_models.Option.t_Option Alloc.String.t_String
}

/// Which required cell of a fetched row was missing, so the handler keeps its
/// historical error message.
type t_SendCell =
  | SendCell_Ciphertext : t_SendCell
  | SendCell_ExpiresAt : t_SendCell

/// The fetch read's whole observation: the driver's verdict, the response
/// cells, and the missing cell that made a row unreadable.
type t_SendFetchObservation = {
  f_read:Vela_share_policy.Send_driver.t_ReadObservation;
  f_missing_cell:Core_models.Option.t_Option t_SendCell;
  f_ciphertext:Core_models.Option.t_Option Alloc.String.t_String;
  f_has_passphrase:bool;
  f_kdf_salt:Core_models.Option.t_Option Alloc.String.t_String;
  f_view_once:bool;
  f_max_views:Core_models.Option.t_Option i64;
  f_view_count:i64;
  f_expires_at:Core_models.Option.t_Option Alloc.String.t_String
}

/// The historical default for every cell the handler has not decoded.
let empty_fetch
      (read: Vela_share_policy.Send_driver.t_ReadObservation)
      (missing_cell: Core_models.Option.t_Option t_SendCell)
    : t_SendFetchObservation =
  {
    f_read = read;
    f_missing_cell = missing_cell;
    f_ciphertext
    =
    Core_models.Option.Option_None <: Core_models.Option.t_Option Alloc.String.t_String;
    f_has_passphrase = false;
    f_kdf_salt = Core_models.Option.Option_None <: Core_models.Option.t_Option Alloc.String.t_String;
    f_view_once = false;
    f_max_views = Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
    f_view_count = mk_i64 0;
    f_expires_at
    =
    Core_models.Option.Option_None <: Core_models.Option.t_Option Alloc.String.t_String
  }
  <:
  t_SendFetchObservation

/// `row.bool_int(i).unwrap_or(false)`: a non-zero integer cell is true and an
/// unreadable one is false.
let bool_cell (cell: Core_models.Option.t_Option i64) : bool =
  match cell <: Core_models.Option.t_Option i64 with
  | Core_models.Option.Option_Some value -> value <>. mk_i64 0
  | Core_models.Option.Option_None  -> false

/// `CreateSendIo::insert_send`: one insert on the pool (autocommit).
let plan_send_create
      (id owner ciphertext: Alloc.String.t_String)
      (has_passphrase: bool)
      (kdf_salt label: Core_models.Option.t_Option Alloc.String.t_String)
      (view_once: bool)
      (max_views: Core_models.Option.t_Option i64)
      (created_at expires_at: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_SendStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_SendStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            SendStmt_InsertSend
            ({
                f_id = id;
                f_owner = owner;
                f_ciphertext = ciphertext;
                f_has_passphrase = has_passphrase;
                f_kdf_salt = kdf_salt;
                f_label = label;
                f_view_once = view_once;
                f_max_views = max_views;
                f_created_at = created_at;
                f_expires_at = expires_at
              })
            <:
            t_SendStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_SendStmt)

/// `FetchSendIo::consume_view`: the atomic view consume (autocommit).
let plan_send_consume (id now: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_SendStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_SendStmt
    #Alloc.Alloc.t_Global
    ((let list = [SendStmt_ConsumeSendView ({ f_id = id; f_now = now }) <: t_SendStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_SendStmt)

/// `FetchSendIo::read_send`: read the delivered row.
let plan_send_read (id: Alloc.String.t_String) : t_SendStmt =
  SendStmt_SelectSend ({ f_id = id }) <: t_SendStmt

/// `FetchSendIo::remove_fetched`: drop the delivered view-once row
/// (autocommit).
let plan_send_remove (id: Alloc.String.t_String) : Alloc.Vec.t_Vec t_SendStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_SendStmt
    #Alloc.Alloc.t_Global
    ((let list = [SendStmt_DeleteSend ({ f_id = id }) <: t_SendStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_SendStmt)

/// `DeleteSendIo::delete_link`: the owner-scoped delete (autocommit).
let plan_send_delete (id owner: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_SendStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_SendStmt
    #Alloc.Alloc.t_Global
    ((let list = [SendStmt_DeleteOwnedSend ({ f_id = id; f_owner = owner }) <: t_SendStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_SendStmt)

/// `CreateSendIo::insert_send`: the rows the insert changed, or a storage
/// failure.
let classify_send_create (outcomes: t_Slice t_WriteOutcome)
    : Vela_share_policy.Send_driver.t_RowsObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied rows ->
      {
        Vela_share_policy.Send_driver.f_rows = rows;
        Vela_share_policy.Send_driver.f_failed = false
      }
      <:
      Vela_share_policy.Send_driver.t_RowsObservation
    | WriteOutcome_Failed  ->
      {
        Vela_share_policy.Send_driver.f_rows = mk_u64 0;
        Vela_share_policy.Send_driver.f_failed = true
      }
      <:
      Vela_share_policy.Send_driver.t_RowsObservation
  else
    {
      Vela_share_policy.Send_driver.f_rows = mk_u64 0;
      Vela_share_policy.Send_driver.f_failed = true
    }
    <:
    Vela_share_policy.Send_driver.t_RowsObservation

/// `FetchSendIo::consume_view`: no row matched the SQL guard, one view was
/// consumed, or the statement failed.
let classify_send_consume (outcomes: t_Slice t_WriteOutcome)
    : Vela_share_policy.Send_driver.t_ConsumeObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
      Vela_share_policy.Send_driver.ConsumeObservation_Unavailable
      <:
      Vela_share_policy.Send_driver.t_ConsumeObservation
    | WriteOutcome_Applied _ ->
      Vela_share_policy.Send_driver.ConsumeObservation_Consumed
      <:
      Vela_share_policy.Send_driver.t_ConsumeObservation
    | WriteOutcome_Failed  ->
      Vela_share_policy.Send_driver.ConsumeObservation_Error
      <:
      Vela_share_policy.Send_driver.t_ConsumeObservation
  else
    Vela_share_policy.Send_driver.ConsumeObservation_Error
    <:
    Vela_share_policy.Send_driver.t_ConsumeObservation

/// `FetchSendIo::remove_fetched`: the cleanup is reported as performed unless
/// its one statement failed.
let classify_send_remove (outcomes: t_Slice t_WriteOutcome)
    : Vela_share_policy.Send_driver.t_RemoveObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied _ ->
      {
        Vela_share_policy.Send_driver.f_removed = true;
        Vela_share_policy.Send_driver.f_failed = false
      }
      <:
      Vela_share_policy.Send_driver.t_RemoveObservation
    | WriteOutcome_Failed  ->
      {
        Vela_share_policy.Send_driver.f_removed = false;
        Vela_share_policy.Send_driver.f_failed = true
      }
      <:
      Vela_share_policy.Send_driver.t_RemoveObservation
  else
    {
      Vela_share_policy.Send_driver.f_removed = false;
      Vela_share_policy.Send_driver.f_failed = true
    }
    <:
    Vela_share_policy.Send_driver.t_RemoveObservation

/// `DeleteSendIo::delete_link`: the rows the owner-scoped delete removed, or a
/// storage failure.
let classify_send_delete (outcomes: t_Slice t_WriteOutcome)
    : Vela_share_policy.Send_driver.t_RowsObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied rows ->
      {
        Vela_share_policy.Send_driver.f_rows = rows;
        Vela_share_policy.Send_driver.f_failed = false
      }
      <:
      Vela_share_policy.Send_driver.t_RowsObservation
    | WriteOutcome_Failed  ->
      {
        Vela_share_policy.Send_driver.f_rows = mk_u64 0;
        Vela_share_policy.Send_driver.f_failed = true
      }
      <:
      Vela_share_policy.Send_driver.t_RowsObservation
  else
    {
      Vela_share_policy.Send_driver.f_rows = mk_u64 0;
      Vela_share_policy.Send_driver.f_failed = true
    }
    <:
    Vela_share_policy.Send_driver.t_RowsObservation

/// `FetchSendIo::read_send`: the row's cells, the driver's read verdict and
/// (for an unreadable row) which required cell was missing. A failed query is
/// `Unreadable` with no cell to blame; an absent row is `Missing`.
let classify_send_read (outcome: t_ReadOutcome t_SendRowView) : t_SendFetchObservation =
  match outcome <: t_ReadOutcome t_SendRowView with
  | ReadOutcome_Failed  ->
    empty_fetch (Vela_share_policy.Send_driver.ReadObservation_Unreadable
        <:
        Vela_share_policy.Send_driver.t_ReadObservation)
      (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SendCell)
  | ReadOutcome_Row (Core_models.Option.Option_None ) ->
    empty_fetch (Vela_share_policy.Send_driver.ReadObservation_Missing
        <:
        Vela_share_policy.Send_driver.t_ReadObservation)
      (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SendCell)
  | ReadOutcome_Row (Core_models.Option.Option_Some row) ->
    match
      Core_models.Clone.f_clone #(Core_models.Option.t_Option Alloc.String.t_String)
        #FStar.Tactics.Typeclasses.solve
        row.f_ciphertext
      <:
      Core_models.Option.t_Option Alloc.String.t_String
    with
    | Core_models.Option.Option_Some ciphertext ->
      let has_passphrase:bool = bool_cell row.f_has_passphrase in
      let kdf_salt:Core_models.Option.t_Option Alloc.String.t_String =
        Core_models.Clone.f_clone #(Core_models.Option.t_Option Alloc.String.t_String)
          #FStar.Tactics.Typeclasses.solve
          row.f_kdf_salt
      in
      let view_once:bool = bool_cell row.f_view_once in
      let max_views:Core_models.Option.t_Option i64 = row.f_max_views in
      let view_count:i64 =
        match row.f_view_count <: Core_models.Option.t_Option i64 with
        | Core_models.Option.Option_Some value -> value
        | Core_models.Option.Option_None  -> mk_i64 0
      in
      (match
          Core_models.Clone.f_clone #(Core_models.Option.t_Option Alloc.String.t_String)
            #FStar.Tactics.Typeclasses.solve
            row.f_expires_at
          <:
          Core_models.Option.t_Option Alloc.String.t_String
        with
        | Core_models.Option.Option_Some expires_at ->
          {
            f_read
            =
            Vela_share_policy.Send_driver.ReadObservation_Payload
            ({ Vela_share_policy.Send_driver.f_view_once = view_once })
            <:
            Vela_share_policy.Send_driver.t_ReadObservation;
            f_missing_cell
            =
            Core_models.Option.Option_None <: Core_models.Option.t_Option t_SendCell;
            f_ciphertext
            =
            Core_models.Option.Option_Some ciphertext
            <:
            Core_models.Option.t_Option Alloc.String.t_String;
            f_has_passphrase = has_passphrase;
            f_kdf_salt = kdf_salt;
            f_view_once = view_once;
            f_max_views = max_views;
            f_view_count = view_count;
            f_expires_at
            =
            Core_models.Option.Option_Some expires_at
            <:
            Core_models.Option.t_Option Alloc.String.t_String
          }
          <:
          t_SendFetchObservation
        | _ ->
          {
            f_read
            =
            Vela_share_policy.Send_driver.ReadObservation_Unreadable
            <:
            Vela_share_policy.Send_driver.t_ReadObservation;
            f_missing_cell
            =
            Core_models.Option.Option_Some (SendCell_ExpiresAt <: t_SendCell)
            <:
            Core_models.Option.t_Option t_SendCell;
            f_ciphertext
            =
            Core_models.Option.Option_Some ciphertext
            <:
            Core_models.Option.t_Option Alloc.String.t_String;
            f_has_passphrase = has_passphrase;
            f_kdf_salt = kdf_salt;
            f_view_once = view_once;
            f_max_views = max_views;
            f_view_count = view_count;
            f_expires_at
            =
            Core_models.Option.Option_None <: Core_models.Option.t_Option Alloc.String.t_String
          }
          <:
          t_SendFetchObservation)
    | _ ->
      empty_fetch (Vela_share_policy.Send_driver.ReadObservation_Unreadable
          <:
          Vela_share_policy.Send_driver.t_ReadObservation)
        (Core_models.Option.Option_Some (SendCell_Ciphertext <: t_SendCell)
          <:
          Core_models.Option.t_Option t_SendCell)
