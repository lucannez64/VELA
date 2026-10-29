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
