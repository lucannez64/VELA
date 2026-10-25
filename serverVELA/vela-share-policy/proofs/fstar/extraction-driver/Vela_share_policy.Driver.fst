module Vela_share_policy.Driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Largest number of pending inbox items one recipient may hold.
let v_MAX_INBOX_ITEMS_PER_USER: i64 = mk_i64 500

/// Largest pending capsule payload one sender may push to one recipient.
let v_MAX_SENDER_TO_RECIPIENT_BYTES: i64 = (mk_i64 8 *! mk_i64 1024 <: i64) *! mk_i64 1024

/// Which sharing request this driver belongs to.
type t_ShareRequestKind =
  | ShareRequestKind_SendCapsule : t_ShareRequestKind
  | ShareRequestKind_UpdateLinkedItem : t_ShareRequestKind
  | ShareRequestKind_RevokeLinkedItem : t_ShareRequestKind
  | ShareRequestKind_DeleteInboxItem : t_ShareRequestKind
  | ShareRequestKind_RegisterShareEk : t_ShareRequestKind

/// Where the request is in its decision sequence.
type t_ShareStage =
  | ShareStage_SendInsert : t_ShareStage
  | ShareStage_LinkUpdateObserve : t_ShareStage
  | ShareStage_LinkUpdateApply : t_ShareStage
  | ShareStage_LinkRevokeObserve : t_ShareStage
  | ShareStage_LinkRevokeApply : t_ShareStage
  | ShareStage_LinkCleanup : t_ShareStage
  | ShareStage_InboxDelete : t_ShareStage
  | ShareStage_EkObserve : t_ShareStage
  | ShareStage_EkRegister : t_ShareStage
  | ShareStage_Done : t_ShareStage

/// Request-side observations for a capsule send. `decode_failed` records a
/// base64 failure; the decoded lengths/quota counters are otherwise the values
/// the handler read before opening the insert transaction.
type t_SendRequestObservation = {
  f_policy:Vela_share_policy.t_SendObservation;
  f_decode_failed:bool;
  f_inbox_count:i64;
  f_pair_bytes:i64
}

/// Request-side observations for a linked-item update.
type t_LinkUpdateStartObservation = {
  f_decode_failed:bool;
  f_capsule_len:i64
}

/// Device-row observations for a share-EK registration, including the two
/// decode outcomes that the historical handler replays after the policy saw
/// the real observations.
type t_EkDeviceObservation = {
  f_registration:Vela_share_policy.t_EkRegistrationObservation;
  f_stored_identity_vk_decode_failed:bool;
  f_signature_decode_failed:bool
}

/// Request-side observations for a share-EK registration, checked before the
/// signing-device row is read. This preserves the handler's historical error
/// precedence: malformed key, wrong key size, malformed timestamp, then the
/// device query.
type t_EkRegistrationStartObservation = {
  f_ek_decode_failed:bool;
  f_ek_len:usize;
  f_signed_at_not_canonical:bool;
  f_signed_at_unparseable:bool;
  f_signed_at_future:bool
}

/// Result-row observation for a guarded UPDATE/DELETE.
type t_RowsObservation = { f_rows:u64 }

/// Outcome of the send transaction, as observed by the handler.
type t_SendResultObservation =
  | SendResultObservation_Committed : t_SendResultObservation
  | SendResultObservation_StorageFailed : t_SendResultObservation
  | SendResultObservation_CommitConflict : t_SendResultObservation

/// Outcome of the revoke's inbox cleanup. The historical handler ignores this
/// result, so both outcomes are terminal and successful.
type t_CleanupObservation = { f_storage_failed:bool }

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
type t_ShareEvent =
  | ShareEvent_LinkObserved : Vela_share_policy.t_LinkMutationObservation -> t_ShareEvent
  | ShareEvent_EkObserved : t_EkDeviceObservation -> t_ShareEvent
  | ShareEvent_SendResult : t_SendResultObservation -> t_ShareEvent
  | ShareEvent_Mutated : t_RowsObservation -> t_ShareEvent
  | ShareEvent_Cleaned : t_CleanupObservation -> t_ShareEvent

/// Failure categories, preserving the handlers' historical status/message
/// precedence. The handler renders each class with the exact existing status
/// and message; link/inbox failures are rendered with the requested id.
type t_ShareFailure =
  | ShareFailure_RecipientUnavailable : t_ShareFailure
  | ShareFailure_MalformedCapsule : t_ShareFailure
  | ShareFailure_CapsuleTooLarge : t_ShareFailure
  | ShareFailure_InboxItemLimit : t_ShareFailure
  | ShareFailure_SenderQuotaExceeded : t_ShareFailure
  | ShareFailure_RecipientQuotaExceeded : t_ShareFailure
  | ShareFailure_CapsulePolicyRejected : t_ShareFailure
  | ShareFailure_LinkNotFound : t_ShareFailure
  | ShareFailure_SendStorage : t_ShareFailure
  | ShareFailure_SendConflict : t_ShareFailure
  | ShareFailure_InboxNotFound : t_ShareFailure
  | ShareFailure_UserNotFound : t_ShareFailure
  | ShareFailure_ShareEkDecode : t_ShareFailure
  | ShareFailure_ShareEkSize : t_ShareFailure
  | ShareFailure_SignedAtNotCanonical : t_ShareFailure
  | ShareFailure_SignedAtUnparseable : t_ShareFailure
  | ShareFailure_SignedAtFuture : t_ShareFailure
  | ShareFailure_DeviceNotEnrolled : t_ShareFailure
  | ShareFailure_StoredIdentityKey : t_ShareFailure
  | ShareFailure_SignatureDecode : t_ShareFailure
  | ShareFailure_EkPolicyRejected : t_ShareFailure

/// The exact send authority emitted by the driver.
type t_SendInsertPermit = { f_capsule_len:i64 }

/// The exact linked-item update authority emitted by the driver.
type t_LinkUpdatePermit = { f_capsule_len:i64 }

/// The inbox-delete authority. It is only constructed by
/// `begin_inbox_delete`, and `recipient_scoped` records that the handler must
/// bind the delete to the authenticated recipient (`recipient_user_id = ?`).
type t_InboxDeletePermit = { f_recipient_scoped:bool }

/// The effect the handler must perform next.
type t_ShareEffect =
  | ShareEffect_ObserveLink : t_ShareEffect
  | ShareEffect_ObserveDevice : t_ShareEffect
  | ShareEffect_InsertCapsule : t_SendInsertPermit -> t_ShareEffect
  | ShareEffect_UpdateLinkedItem : t_LinkUpdatePermit -> t_ShareEffect
  | ShareEffect_RevokeLinkedItem : t_ShareEffect
  | ShareEffect_DeleteLinkedInbox : t_ShareEffect
  | ShareEffect_DeleteInboxItem : t_InboxDeletePermit -> t_ShareEffect
  | ShareEffect_UpdateShareEk : Vela_share_policy.t_EkRegistrationPermit -> t_ShareEffect
  | ShareEffect_Complete : t_ShareEffect
  | ShareEffect_Fail : t_ShareFailure -> t_ShareEffect
  | ShareEffect_Idle : t_ShareEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the database.
type t_ShareDriver = {
  f_kind:t_ShareRequestKind;
  f_stage:t_ShareStage;
  f_capsule_len:i64;
  f_sender_authenticated:bool;
  f_caller_is_sender:bool;
  f_link_live:bool;
  f_observe_issued:bool;
  f_authorized:bool;
  f_effect_issued:bool;
  f_committed:bool;
  f_revoked:bool;
  f_cleanup_issued:bool;
  f_recipient_scoped:bool
}

type t_ShareTransition = {
  f_driver:t_ShareDriver;
  f_effect:t_ShareEffect
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
let share_state_is_sound (driver: t_ShareDriver) : bool =
  let send_clean:bool =
    ~.driver.f_observe_issued && ~.driver.f_committed && ~.driver.f_revoked &&
    ~.driver.f_cleanup_issued
  in
  let observe_clean:bool = ~.driver.f_effect_issued && ~.driver.f_committed in
  let mutate_clean:bool =
    driver.f_authorized && driver.f_caller_is_sender && driver.f_link_live && ~.driver.f_committed &&
    ~.driver.f_revoked &&
    ~.driver.f_cleanup_issued
  in
  let cleanup_clean:bool =
    driver.f_authorized && driver.f_caller_is_sender && driver.f_link_live && driver.f_committed &&
    driver.f_revoked &&
    driver.f_cleanup_issued
  in
  let inbox_clean:bool = driver.f_recipient_scoped && ~.driver.f_committed in
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_SendInsert  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_SendCapsule  -> true
    | _ -> false) &&
  driver.f_authorized &&
  driver.f_sender_authenticated &&
  driver.f_effect_issued &&
  send_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_LinkUpdateObserve  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_UpdateLinkedItem  -> true
    | _ -> false) &&
  driver.f_observe_issued &&
  observe_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_LinkUpdateApply  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_UpdateLinkedItem  -> true
    | _ -> false) &&
  driver.f_observe_issued &&
  driver.f_effect_issued &&
  mutate_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_LinkRevokeObserve  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_RevokeLinkedItem  -> true
    | _ -> false) &&
  driver.f_observe_issued &&
  observe_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_LinkRevokeApply  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_RevokeLinkedItem  -> true
    | _ -> false) &&
  driver.f_observe_issued &&
  driver.f_effect_issued &&
  mutate_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_LinkCleanup  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_RevokeLinkedItem  -> true
    | _ -> false) &&
  driver.f_observe_issued &&
  driver.f_effect_issued &&
  cleanup_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_InboxDelete  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_DeleteInboxItem  -> true
    | _ -> false) &&
  driver.f_effect_issued &&
  inbox_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_EkObserve  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_RegisterShareEk  -> true
    | _ -> false) &&
  driver.f_observe_issued &&
  observe_clean) &&
  (~.(match driver.f_stage <: t_ShareStage with
    | ShareStage_EkRegister  -> true
    | _ -> false) ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_RegisterShareEk  -> true
    | _ -> false) &&
  driver.f_effect_issued &&
  driver.f_authorized &&
  ~.driver.f_committed &&
  ~.driver.f_revoked &&
  ~.driver.f_cleanup_issued) &&
  (~.driver.f_effect_issued || driver.f_authorized ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_DeleteInboxItem  -> true
    | _ -> false) &&
  driver.f_recipient_scoped) &&
  (~.driver.f_committed || driver.f_effect_issued) &&
  (~.(driver.f_committed &&
    (match driver.f_kind <: t_ShareRequestKind with
      | ShareRequestKind_RevokeLinkedItem  -> true
      | _ -> false)) ||
  driver.f_revoked) &&
  (~.driver.f_revoked ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_RevokeLinkedItem  -> true
    | _ -> false) &&
  driver.f_committed &&
  driver.f_effect_issued &&
  driver.f_authorized &&
  driver.f_caller_is_sender &&
  driver.f_link_live) &&
  (~.driver.f_cleanup_issued || driver.f_revoked) &&
  (~.driver.f_revoked || driver.f_cleanup_issued) &&
  (~.driver.f_observe_issued ||
  (match driver.f_kind <: t_ShareRequestKind with
    | ShareRequestKind_UpdateLinkedItem
    | ShareRequestKind_RevokeLinkedItem
    | ShareRequestKind_RegisterShareEk  -> true
    | _ -> false))

/// Every effect the driver emits agrees with the state it produces.
let share_effect_is_sound (driver: t_ShareDriver) (v_effect: t_ShareEffect) : bool =
  match v_effect <: t_ShareEffect with
  | ShareEffect_ObserveLink  ->
    driver.f_observe_issued && ~.driver.f_effect_issued &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_LinkUpdateObserve  | ShareStage_LinkRevokeObserve  -> true
      | _ -> false)
  | ShareEffect_ObserveDevice  ->
    driver.f_observe_issued && ~.driver.f_effect_issued &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_EkObserve  -> true
      | _ -> false)
  | ShareEffect_InsertCapsule permit ->
    (match driver.f_kind <: t_ShareRequestKind with
      | ShareRequestKind_SendCapsule  -> true
      | _ -> false) &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_SendInsert  -> true
      | _ -> false) &&
    driver.f_authorized &&
    driver.f_sender_authenticated &&
    driver.f_effect_issued &&
    ~.driver.f_committed &&
    ~.driver.f_revoked &&
    permit.f_capsule_len =. driver.f_capsule_len
  | ShareEffect_UpdateLinkedItem permit ->
    (match driver.f_kind <: t_ShareRequestKind with
      | ShareRequestKind_UpdateLinkedItem  -> true
      | _ -> false) &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_LinkUpdateApply  -> true
      | _ -> false) &&
    driver.f_observe_issued &&
    driver.f_authorized &&
    driver.f_caller_is_sender &&
    driver.f_link_live &&
    driver.f_effect_issued &&
    ~.driver.f_committed &&
    ~.driver.f_revoked &&
    permit.f_capsule_len =. driver.f_capsule_len
  | ShareEffect_RevokeLinkedItem  ->
    (match driver.f_kind <: t_ShareRequestKind with
      | ShareRequestKind_RevokeLinkedItem  -> true
      | _ -> false) &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_LinkRevokeApply  -> true
      | _ -> false) &&
    driver.f_observe_issued &&
    driver.f_authorized &&
    driver.f_caller_is_sender &&
    driver.f_link_live &&
    driver.f_effect_issued &&
    ~.driver.f_committed &&
    ~.driver.f_revoked
  | ShareEffect_DeleteLinkedInbox  ->
    (match driver.f_kind <: t_ShareRequestKind with
      | ShareRequestKind_RevokeLinkedItem  -> true
      | _ -> false) &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_LinkCleanup  -> true
      | _ -> false) &&
    driver.f_observe_issued &&
    driver.f_revoked &&
    driver.f_committed &&
    driver.f_cleanup_issued
  | ShareEffect_DeleteInboxItem permit ->
    (match driver.f_kind <: t_ShareRequestKind with
      | ShareRequestKind_DeleteInboxItem  -> true
      | _ -> false) &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_InboxDelete  -> true
      | _ -> false) &&
    driver.f_recipient_scoped &&
    permit.f_recipient_scoped &&
    driver.f_effect_issued &&
    ~.driver.f_committed
  | ShareEffect_UpdateShareEk permit ->
    (match driver.f_kind <: t_ShareRequestKind with
      | ShareRequestKind_RegisterShareEk  -> true
      | _ -> false) &&
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_EkRegister  -> true
      | _ -> false) &&
    driver.f_observe_issued &&
    driver.f_authorized &&
    driver.f_effect_issued &&
    ~.driver.f_committed &&
    Vela_share_policy.impl_EkRegistrationPermit__binds_device_signature permit
  | ShareEffect_Complete  ->
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_Done  -> true
      | _ -> false) &&
    driver.f_committed
  | ShareEffect_Fail _ ->
    (match driver.f_stage <: t_ShareStage with
      | ShareStage_Done  -> true
      | _ -> false) &&
    ~.driver.f_committed
  | ShareEffect_Idle  -> true

let transition (driver: t_ShareDriver) (v_effect: t_ShareEffect) : t_ShareTransition =
  { f_driver = driver; f_effect = v_effect } <: t_ShareTransition

let idle (driver: t_ShareDriver) : t_ShareTransition =
  transition driver (ShareEffect_Idle <: t_ShareEffect)

let fail (driver: t_ShareDriver) (failure: t_ShareFailure) : t_ShareTransition =
  transition ({ driver with f_stage = ShareStage_Done <: t_ShareStage } <: t_ShareDriver)
    (ShareEffect_Fail failure <: t_ShareEffect)

let base (kind: t_ShareRequestKind) (capsule_len: i64) (sender_authenticated: bool) : t_ShareDriver =
  {
    f_kind = kind;
    f_stage = ShareStage_Done <: t_ShareStage;
    f_capsule_len = capsule_len;
    f_sender_authenticated = sender_authenticated;
    f_caller_is_sender = false;
    f_link_live = false;
    f_observe_issued = false;
    f_authorized = false;
    f_effect_issued = false;
    f_committed = false;
    f_revoked = false;
    f_cleanup_issued = false;
    f_recipient_scoped = false
  }
  <:
  t_ShareDriver

/// The handler's historical per-(sender, recipient) byte cap, stated without
/// `+` so every `i64` observation is safe. Negative database counters fail
/// closed rather than granting capacity, matching `send_facts`.
let sender_pair_has_capacity (pair_bytes capsule_len: i64) : bool =
  pair_bytes >=. mk_i64 0 && capsule_len >=. mk_i64 0 &&
  capsule_len <=. v_MAX_SENDER_TO_RECIPIENT_BYTES &&
  pair_bytes <=. (v_MAX_SENDER_TO_RECIPIENT_BYTES -! capsule_len <: i64)

/// Start a send. The decision order is the handler\'s historical order:
/// recipient availability, base64 decoding, global capsule cap, inbox item
/// cap, per-pair byte cap, recipient byte cap (`send_facts`), then the real
/// `plan_send` authorization.
let begin_send (obs: t_SendRequestObservation)
    : Prims.Pure t_ShareTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_state_is_sound result.f_driver &&
          share_effect_is_sound result.f_driver result.f_effect &&
          ((match result.f_driver.f_stage <: t_ShareStage with
            | ShareStage_SendInsert  -> true
            | _ -> false) ||
          (match result.f_effect <: t_ShareEffect with
            | ShareEffect_Fail _ -> true
            | _ -> false))) =
  let driver:t_ShareDriver =
    base (ShareRequestKind_SendCapsule <: t_ShareRequestKind)
      obs.f_policy.Vela_share_policy.f_capsule_len
      obs.f_policy.Vela_share_policy.f_session_user_id_present
  in
  if ~.obs.f_policy.Vela_share_policy.f_recipient_has_share_ek
  then fail driver (ShareFailure_RecipientUnavailable <: t_ShareFailure)
  else
    if obs.f_decode_failed
    then fail driver (ShareFailure_MalformedCapsule <: t_ShareFailure)
    else
      if obs.f_policy.Vela_share_policy.f_capsule_len >. Vela_share_policy.v_MAX_CAPSULE_BYTES
      then fail driver (ShareFailure_CapsuleTooLarge <: t_ShareFailure)
      else
        if obs.f_inbox_count >=. v_MAX_INBOX_ITEMS_PER_USER
        then fail driver (ShareFailure_InboxItemLimit <: t_ShareFailure)
        else
          if
            ~.(sender_pair_has_capacity obs.f_pair_bytes
                obs.f_policy.Vela_share_policy.f_capsule_len
              <:
              bool)
          then fail driver (ShareFailure_SenderQuotaExceeded <: t_ShareFailure)
          else
            let facts:Vela_share_policy.t_SendCapsuleFacts =
              Vela_share_policy.send_facts obs.f_policy
            in
            if ~.facts.Vela_share_policy.f_inbox_has_capacity
            then fail driver (ShareFailure_RecipientQuotaExceeded <: t_ShareFailure)
            else
              match Vela_share_policy.plan_send facts <: Vela_share_policy.t_SendDecision with
              | Vela_share_policy.SendDecision_Deliver  ->
                transition ({
                      driver with
                      f_stage = ShareStage_SendInsert <: t_ShareStage;
                      f_authorized = true;
                      f_effect_issued = true
                    }
                    <:
                    t_ShareDriver)
                  (ShareEffect_InsertCapsule
                    ({ f_capsule_len = obs.f_policy.Vela_share_policy.f_capsule_len }
                      <:
                      t_SendInsertPermit)
                    <:
                    t_ShareEffect)
              | Vela_share_policy.SendDecision_Reject  ->
                fail driver (ShareFailure_CapsulePolicyRejected <: t_ShareFailure)

/// Start a linked-item update. Request-side decoding/length failures are
/// decided here; a well-formed request then asks the handler to observe the
/// linked row.
let begin_link_update (obs: t_LinkUpdateStartObservation)
    : Prims.Pure t_ShareTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_state_is_sound result.f_driver &&
          share_effect_is_sound result.f_driver result.f_effect &&
          ((match result.f_driver.f_stage <: t_ShareStage with
            | ShareStage_LinkUpdateObserve  -> true
            | _ -> false) ||
          (match result.f_effect <: t_ShareEffect with
            | ShareEffect_Fail _ -> true
            | _ -> false))) =
  let driver:t_ShareDriver =
    base (ShareRequestKind_UpdateLinkedItem <: t_ShareRequestKind) obs.f_capsule_len false
  in
  if obs.f_decode_failed
  then fail driver (ShareFailure_MalformedCapsule <: t_ShareFailure)
  else
    if obs.f_capsule_len >. Vela_share_policy.v_MAX_CAPSULE_BYTES
    then fail driver (ShareFailure_CapsuleTooLarge <: t_ShareFailure)
    else
      transition ({
            driver with
            f_stage = ShareStage_LinkUpdateObserve <: t_ShareStage;
            f_observe_issued = true
          }
          <:
          t_ShareDriver)
        (ShareEffect_ObserveLink <: t_ShareEffect)

/// Start a linked-item revoke and ask the handler to observe the linked row.
let begin_link_revoke (_: Prims.unit)
    : Prims.Pure t_ShareTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_state_is_sound result.f_driver &&
          share_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_ShareStage with
            | ShareStage_LinkRevokeObserve  -> true
            | _ -> false) &&
          (match result.f_effect <: t_ShareEffect with
            | ShareEffect_ObserveLink  -> true
            | _ -> false)) =
  let driver:t_ShareDriver =
    base (ShareRequestKind_RevokeLinkedItem <: t_ShareRequestKind) (mk_i64 0) false
  in
  transition ({
        driver with
        f_stage = ShareStage_LinkRevokeObserve <: t_ShareStage;
        f_observe_issued = true
      }
      <:
      t_ShareDriver)
    (ShareEffect_ObserveLink <: t_ShareEffect)

/// Start a recipient-scoped inbox delete. The permit records the guard the
/// handler must use; the handler never reads the row first.
let begin_inbox_delete (_: Prims.unit)
    : Prims.Pure t_ShareTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_state_is_sound result.f_driver &&
          share_effect_is_sound result.f_driver result.f_effect &&
          (match result.f_driver.f_stage <: t_ShareStage with
            | ShareStage_InboxDelete  -> true
            | _ -> false) &&
          (match
              (match result.f_effect <: t_ShareEffect with
                | ShareEffect_DeleteInboxItem permit ->
                  (match permit.f_recipient_scoped <: bool with
                    | true ->
                      Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
                    | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
                | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
              <:
              Core_models.Option.t_Option bool
            with
            | Core_models.Option.Option_Some x -> x
            | Core_models.Option.Option_None  -> false)) =
  let driver:t_ShareDriver =
    {
      f_kind = ShareRequestKind_DeleteInboxItem <: t_ShareRequestKind;
      f_stage = ShareStage_InboxDelete <: t_ShareStage;
      f_capsule_len = mk_i64 0;
      f_sender_authenticated = false;
      f_caller_is_sender = false;
      f_link_live = false;
      f_observe_issued = false;
      f_authorized = false;
      f_effect_issued = true;
      f_committed = false;
      f_revoked = false;
      f_cleanup_issued = false;
      f_recipient_scoped = true
    }
    <:
    t_ShareDriver
  in
  transition driver
    (ShareEffect_DeleteInboxItem ({ f_recipient_scoped = true } <: t_InboxDeletePermit)
      <:
      t_ShareEffect)

/// Start a share-EK registration. Request-side decoding, size and timestamp
/// checks are decided here; a well-formed request then asks the handler to
/// read the signing-device row and verify the binding signature.
let begin_ek_registration (obs: t_EkRegistrationStartObservation)
    : Prims.Pure t_ShareTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_state_is_sound result.f_driver &&
          share_effect_is_sound result.f_driver result.f_effect &&
          ((match result.f_driver.f_stage <: t_ShareStage with
            | ShareStage_EkObserve  -> true
            | _ -> false) ||
          (match result.f_effect <: t_ShareEffect with
            | ShareEffect_Fail _ -> true
            | _ -> false))) =
  let driver:t_ShareDriver =
    base (ShareRequestKind_RegisterShareEk <: t_ShareRequestKind) (mk_i64 0) false
  in
  if obs.f_ek_decode_failed
  then fail driver (ShareFailure_ShareEkDecode <: t_ShareFailure)
  else
    if obs.f_ek_len <>. Vela_share_policy.v_SHARE_EK_LEN
    then fail driver (ShareFailure_ShareEkSize <: t_ShareFailure)
    else
      if obs.f_signed_at_not_canonical
      then fail driver (ShareFailure_SignedAtNotCanonical <: t_ShareFailure)
      else
        if obs.f_signed_at_unparseable
        then fail driver (ShareFailure_SignedAtUnparseable <: t_ShareFailure)
        else
          if obs.f_signed_at_future
          then fail driver (ShareFailure_SignedAtFuture <: t_ShareFailure)
          else
            transition ({
                  driver with
                  f_stage = ShareStage_EkObserve <: t_ShareStage;
                  f_observe_issued = true
                }
                <:
                t_ShareDriver)
              (ShareEffect_ObserveDevice <: t_ShareEffect)

let on_link_observed
      (driver: t_ShareDriver)
      (observation: Vela_share_policy.t_LinkMutationObservation)
    : t_ShareTransition =
  let facts:Vela_share_policy.t_LinkMutationFacts =
    Vela_share_policy.link_mutation_facts observation
  in
  let kind:t_ShareRequestKind = driver.f_kind in
  match Vela_share_policy.plan_link_mutation facts <: Vela_share_policy.t_LinkMutationDecision with
  | Vela_share_policy.LinkMutationDecision_Apply  ->
    let authorized:t_ShareDriver =
      {
        driver with
        f_caller_is_sender = facts.Vela_share_policy.f_caller_is_sender;
        f_link_live
        =
        facts.Vela_share_policy.f_item_exists && facts.Vela_share_policy.f_not_already_revoked;
        f_authorized = true;
        f_effect_issued = true
      }
      <:
      t_ShareDriver
    in
    (match kind <: t_ShareRequestKind with
      | ShareRequestKind_UpdateLinkedItem  ->
        transition ({ authorized with f_stage = ShareStage_LinkUpdateApply <: t_ShareStage }
            <:
            t_ShareDriver)
          (ShareEffect_UpdateLinkedItem
            ({ f_capsule_len = driver.f_capsule_len } <: t_LinkUpdatePermit)
            <:
            t_ShareEffect)
      | ShareRequestKind_RevokeLinkedItem  ->
        transition ({ authorized with f_stage = ShareStage_LinkRevokeApply <: t_ShareStage }
            <:
            t_ShareDriver)
          (ShareEffect_RevokeLinkedItem <: t_ShareEffect)
      | _ -> idle driver)
  | Vela_share_policy.LinkMutationDecision_Reject  ->
    fail driver (ShareFailure_LinkNotFound <: t_ShareFailure)

let on_ek_observed (driver: t_ShareDriver) (observation: t_EkDeviceObservation) : t_ShareTransition =
  match
    Vela_share_policy.plan_ek_registration (Vela_share_policy.ek_registration_facts observation
            .f_registration
        <:
        Vela_share_policy.t_EkRegistrationFacts)
    <:
    Vela_share_policy.t_EkRegistrationDecision
  with
  | Vela_share_policy.EkRegistrationDecision_Register permit ->
    transition ({
          driver with
          f_stage = ShareStage_EkRegister <: t_ShareStage;
          f_authorized = true;
          f_effect_issued = true
        }
        <:
        t_ShareDriver)
      (ShareEffect_UpdateShareEk permit <: t_ShareEffect)
  | Vela_share_policy.EkRegistrationDecision_Reject  ->
    if
      ~.observation.f_registration.Vela_share_policy.f_device_row_present ||
      ~.observation.f_registration.Vela_share_policy.f_device_user_matches
    then fail driver (ShareFailure_DeviceNotEnrolled <: t_ShareFailure)
    else
      if observation.f_stored_identity_vk_decode_failed
      then fail driver (ShareFailure_StoredIdentityKey <: t_ShareFailure)
      else
        if observation.f_signature_decode_failed
        then fail driver (ShareFailure_SignatureDecode <: t_ShareFailure)
        else fail driver (ShareFailure_EkPolicyRejected <: t_ShareFailure)

let on_send_result (driver: t_ShareDriver) (observation: t_SendResultObservation)
    : t_ShareTransition =
  match observation <: t_SendResultObservation with
  | SendResultObservation_Committed  ->
    transition ({ driver with f_stage = ShareStage_Done <: t_ShareStage; f_committed = true }
        <:
        t_ShareDriver)
      (ShareEffect_Complete <: t_ShareEffect)
  | SendResultObservation_StorageFailed  -> fail driver (ShareFailure_SendStorage <: t_ShareFailure)
  | SendResultObservation_CommitConflict  ->
    fail driver (ShareFailure_SendConflict <: t_ShareFailure)

let on_rows (driver: t_ShareDriver) (observation: t_RowsObservation) : t_ShareTransition =
  let changed:bool = observation.f_rows >. mk_u64 0 in
  match driver.f_kind <: t_ShareRequestKind with
  | ShareRequestKind_UpdateLinkedItem  ->
    if changed
    then
      transition ({ driver with f_stage = ShareStage_Done <: t_ShareStage; f_committed = true }
          <:
          t_ShareDriver)
        (ShareEffect_Complete <: t_ShareEffect)
    else fail driver (ShareFailure_LinkNotFound <: t_ShareFailure)
  | ShareRequestKind_RevokeLinkedItem  ->
    if changed
    then
      transition ({
            driver with
            f_stage = ShareStage_LinkCleanup <: t_ShareStage;
            f_committed = true;
            f_revoked = true;
            f_cleanup_issued = true
          }
          <:
          t_ShareDriver)
        (ShareEffect_DeleteLinkedInbox <: t_ShareEffect)
    else fail driver (ShareFailure_LinkNotFound <: t_ShareFailure)
  | ShareRequestKind_DeleteInboxItem  ->
    if changed
    then
      transition ({ driver with f_stage = ShareStage_Done <: t_ShareStage; f_committed = true }
          <:
          t_ShareDriver)
        (ShareEffect_Complete <: t_ShareEffect)
    else fail driver (ShareFailure_InboxNotFound <: t_ShareFailure)
  | ShareRequestKind_RegisterShareEk  ->
    if changed
    then
      transition ({ driver with f_stage = ShareStage_Done <: t_ShareStage; f_committed = true }
          <:
          t_ShareDriver)
        (ShareEffect_Complete <: t_ShareEffect)
    else fail driver (ShareFailure_UserNotFound <: t_ShareFailure)
  | ShareRequestKind_SendCapsule  -> idle driver

let on_cleaned (driver: t_ShareDriver) : t_ShareTransition =
  transition ({ driver with f_stage = ShareStage_Done <: t_ShareStage } <: t_ShareDriver)
    (ShareEffect_Complete <: t_ShareEffect)

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
let step (driver: t_ShareDriver) (event: t_ShareEvent)
    : Prims.Pure t_ShareTransition
      (requires share_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_state_is_sound driver <: bool) || share_state_is_sound result.f_driver)) =
  match event <: t_ShareEvent with
  | ShareEvent_LinkObserved observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_LinkUpdateObserve  | ShareStage_LinkRevokeObserve  -> true
      | _ -> false
    then on_link_observed driver observation
    else idle driver
  | ShareEvent_EkObserved observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_EkObserve  -> true
      | _ -> false
    then on_ek_observed driver observation
    else idle driver
  | ShareEvent_SendResult observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_SendInsert  -> true
      | _ -> false
    then on_send_result driver observation
    else idle driver
  | ShareEvent_Mutated observation ->
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_LinkUpdateApply
      | ShareStage_LinkRevokeApply
      | ShareStage_InboxDelete
      | ShareStage_EkRegister  -> true
      | _ -> false
    then on_rows driver observation
    else idle driver
  | ShareEvent_Cleaned observation ->
    let _:t_CleanupObservation = observation in
    if
      match driver.f_stage <: t_ShareStage with
      | ShareStage_LinkCleanup  -> true
      | _ -> false
    then on_cleaned driver
    else idle driver

let on_link_observation
      (driver: t_ShareDriver)
      (observation: Vela_share_policy.t_LinkMutationObservation)
    : Prims.Pure t_ShareTransition
      (requires share_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_state_is_sound driver <: bool) || share_state_is_sound result.f_driver)) =
  step driver (ShareEvent_LinkObserved observation <: t_ShareEvent)

let on_ek_observation (driver: t_ShareDriver) (observation: t_EkDeviceObservation)
    : Prims.Pure t_ShareTransition
      (requires share_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_state_is_sound driver <: bool) || share_state_is_sound result.f_driver)) =
  step driver (ShareEvent_EkObserved observation <: t_ShareEvent)

let on_send_completed (driver: t_ShareDriver) (observation: t_SendResultObservation)
    : Prims.Pure t_ShareTransition
      (requires share_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_state_is_sound driver <: bool) || share_state_is_sound result.f_driver)) =
  step driver (ShareEvent_SendResult observation <: t_ShareEvent)

let on_rows_observed (driver: t_ShareDriver) (observation: t_RowsObservation)
    : Prims.Pure t_ShareTransition
      (requires share_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_state_is_sound driver <: bool) || share_state_is_sound result.f_driver)) =
  step driver (ShareEvent_Mutated observation <: t_ShareEvent)

let on_cleanup_completed (driver: t_ShareDriver) (observation: t_CleanupObservation)
    : Prims.Pure t_ShareTransition
      (requires share_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_ShareTransition = result in
          share_effect_is_sound result.f_driver result.f_effect &&
          (~.(share_state_is_sound driver <: bool) || share_state_is_sound result.f_driver)) =
  step driver (ShareEvent_Cleaned observation <: t_ShareEvent)
