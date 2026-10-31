//! Pure post-validation driver for the M19/M21 cross-user sharing handlers.
//!
//! The HTTP handlers in `vela-server/src/share/mod.rs` perform the effectful
//! steps: the guarded `shared_items` insert, the guarded update/revoke, the
//! recipient-scoped inbox delete, the EK binding update and the read-only row
//! observations those decisions depend on. This module owns every *decision*
//! between those effects: the recipient/capsule/quota admission order, the
//! sender-and-live-item link mutation gate from `vela_share_policy`, the
//! device-signed share-EK registration gate, and how each result-row
//! observation is classified.
//!
//! The driver is a per-request value: it does not coordinate concurrent HTTP
//! requests and it does not observe SQL/store state itself. Every input is an
//! observation produced by the handler. In particular `SendResultObservation`
//! records the transaction outcome the handler saw; it does not prove that SQL
//! committed or rolled back.
//!
//! The transition relation is deliberately total. Invalid or out-of-order
//! events are ignored (`ShareEffect::Idle`), which makes the unbounded trace
//! induction in `proofs/fstar/driver-lemmas` a statement about every event
//! sequence, not only the handler's intended order.
//!
//! The decision functions call the existing policy modules
//! (`send_facts`/`plan_send`, `link_mutation_facts`/`plan_link_mutation`,
//! `ek_registration_facts`/`plan_ek_registration`); they do not restate or
//! weaken those predicates.

use crate::{
    ek_registration_facts, link_mutation_facts, plan_ek_registration, plan_link_mutation,
    plan_send, send_facts, EkRegistrationDecision, EkRegistrationObservation, EkRegistrationPermit,
    LinkMutationDecision, LinkMutationObservation, SendDecision, SendObservation,
    MAX_CAPSULE_BYTES, SHARE_EK_LEN,
};

/// Largest number of pending inbox items one recipient may hold.
pub const MAX_INBOX_ITEMS_PER_USER: i64 = 500;

/// Largest pending capsule payload one sender may push to one recipient.
pub const MAX_SENDER_TO_RECIPIENT_BYTES: i64 = 8 * 1024 * 1024;

/// Which sharing request this driver belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareRequestKind {
    SendCapsule,
    UpdateLinkedItem,
    RevokeLinkedItem,
    DeleteInboxItem,
    RegisterShareEk,
}

/// Where the request is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareStage {
    /// A send is authorized; the guarded `shared_items` + `share_inbox`
    /// transaction may run exactly once.
    SendInsert,
    /// An update passed the request-side checks; the handler must read the
    /// linked row before the policy can authorize the update.
    LinkUpdateObserve,
    /// The linked-row observation authorized the update; the guarded update
    /// may run exactly once.
    LinkUpdateApply,
    /// A revoke must read the linked row first.
    LinkRevokeObserve,
    /// The linked-row observation authorized the revoke; the guarded revoke
    /// may run exactly once.
    LinkRevokeApply,
    /// The revoke committed; the pending inbox row cleanup may run.
    LinkCleanup,
    /// The recipient-scoped inbox delete may run exactly once.
    InboxDelete,
    /// An EK registration must read the signing device row first.
    EkObserve,
    /// The device-signed binding authorized the EK update; the guarded
    /// `users` update may run exactly once.
    EkRegister,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Request-side observations for a capsule send. `decode_failed` records a
/// base64 failure; the decoded lengths/quota counters are otherwise the values
/// the handler read before opening the insert transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendRequestObservation {
    /// The raw policy observation the real `send_facts` consumes.
    pub policy: SendObservation,
    /// The capsule body was not valid base64.
    pub decode_failed: bool,
    /// Pending inbox items for the recipient before this send.
    pub inbox_count: i64,
    /// Pending bytes from this sender to this recipient before this send.
    pub pair_bytes: i64,
}

/// Request-side observations for a linked-item update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkUpdateStartObservation {
    pub decode_failed: bool,
    /// Decoded replacement capsule length.
    pub capsule_len: i64,
}

/// Device-row observations for a share-EK registration, including the two
/// decode outcomes that the historical handler replays after the policy saw
/// the real observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EkDeviceObservation {
    pub registration: EkRegistrationObservation,
    /// The stored `hybrid_vk` cell was absent or not valid base64.
    pub stored_identity_vk_decode_failed: bool,
    /// The request signature was not valid base64.
    pub signature_decode_failed: bool,
}

/// Request-side observations for a share-EK registration, checked before the
/// signing-device row is read. This preserves the handler's historical error
/// precedence: malformed key, wrong key size, malformed timestamp, then the
/// device query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EkRegistrationStartObservation {
    pub ek_decode_failed: bool,
    /// Decoded share-EK length (zero when decoding failed).
    pub ek_len: usize,
    pub signed_at_not_canonical: bool,
    pub signed_at_unparseable: bool,
    pub signed_at_future: bool,
}

/// Result-row observation for a guarded UPDATE/DELETE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RowsObservation {
    pub rows: u64,
}

/// Outcome of the send transaction, as observed by the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendResultObservation {
    /// Both inserts and the commit succeeded.
    Committed,
    /// An INSERT/query inside the transaction failed.
    StorageFailed,
    /// The commit failed (typically a concurrent writer).
    CommitConflict,
}

/// Outcome of the revoke's inbox cleanup. The historical handler ignores this
/// result, so both outcomes are terminal and successful.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupObservation {
    pub storage_failed: bool,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareEvent {
    /// A linked row was read for an update/revoke.
    LinkObserved(LinkMutationObservation),
    /// The signing-device row and signature verdict were read for an EK
    /// registration.
    EkObserved(EkDeviceObservation),
    /// The send transaction finished.
    SendResult(SendResultObservation),
    /// A guarded update/delete returned its affected-row count.
    Mutated(RowsObservation),
    /// The revoke's inbox cleanup finished.
    Cleaned(CleanupObservation),
}

/// Failure categories, preserving the handlers' historical status/message
/// precedence. The handler renders each class with the exact existing status
/// and message; link/inbox failures are rendered with the requested id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareFailure {
    /// No recipient row carries a share EK. 404, indistinguishable from an
    /// unknown user.
    RecipientUnavailable,
    /// 400: capsule is not valid base64.
    MalformedCapsule,
    /// 400: capsule exceeds the global maximum.
    CapsuleTooLarge,
    /// 409: recipient inbox item limit reached.
    InboxItemLimit,
    /// 413: per-(sender, recipient) pending-byte cap reached.
    SenderQuotaExceeded,
    /// 413: recipient total pending-byte cap reached.
    RecipientQuotaExceeded,
    /// 400: the verified send plan rejected the capsule.
    CapsulePolicyRejected,
    /// 404: missing, foreign or revoked linked share.
    LinkNotFound,
    /// 500: an INSERT inside the send transaction failed.
    SendStorage,
    /// 409: the send commit raced with a concurrent request.
    SendConflict,
    /// 404: missing or foreign inbox item.
    InboxNotFound,
    /// 404: the authenticated user row disappeared during EK registration.
    UserNotFound,
    /// 400: share_ek is not valid base64.
    ShareEkDecode,
    /// 400: share_ek has the wrong decoded length.
    ShareEkSize,
    /// 400: signed_at is not canonical RFC 3339 UTC.
    SignedAtNotCanonical,
    /// 400: signed_at does not parse.
    SignedAtUnparseable,
    /// 400: signed_at is too far in the future.
    SignedAtFuture,
    /// 400: signing device is absent or owned by someone else.
    DeviceNotEnrolled,
    /// 400: the stored identity key is absent or malformed.
    StoredIdentityKey,
    /// 400: the binding signature is not valid base64.
    SignatureDecode,
    /// 401: the verified registration plan rejected the binding.
    EkPolicyRejected,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareEffect {
    /// Read the linked row and feed `ShareEvent::LinkObserved`.
    ObserveLink,
    /// Read the signing-device row and feed `ShareEvent::EkObserved`.
    ObserveDevice,
    /// Perform exactly one guarded send transaction.
    InsertCapsule(SendInsertPermit),
    /// Perform exactly one guarded linked-item update.
    UpdateLinkedItem(LinkUpdatePermit),
    /// Perform exactly one guarded linked-item revoke.
    RevokeLinkedItem,
    /// Delete the pending inbox row after a committed revoke.
    DeleteLinkedInbox,
    /// Perform exactly one recipient-scoped inbox delete.
    DeleteInboxItem(InboxDeletePermit),
    /// Perform exactly one guarded `users.share_ek` update.
    UpdateShareEk(EkRegistrationPermit),
    /// Terminal success.
    Complete,
    /// Terminal failure without a mutating effect.
    Fail(ShareFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// The exact send authority emitted by the driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendInsertPermit {
    pub capsule_len: i64,
}

/// The exact linked-item update authority emitted by the driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkUpdatePermit {
    pub capsule_len: i64,
}

/// The inbox-delete authority. It is only constructed by
/// `begin_inbox_delete`, and `recipient_scoped` records that the handler must
/// bind the delete to the authenticated recipient (`recipient_user_id = ?`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxDeletePermit {
    pub recipient_scoped: bool,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareDriver {
    pub kind: ShareRequestKind,
    pub stage: ShareStage,
    /// Decoded capsule length for send/update (zero elsewhere).
    pub capsule_len: i64,
    /// A send observed an authenticated session.
    pub sender_authenticated: bool,
    /// A link observation found the caller equal to the row's sender.
    pub caller_is_sender: bool,
    /// A link observation found the row live (present and not revoked).
    pub link_live: bool,
    /// A read-only observation was requested.
    pub observe_issued: bool,
    /// The verified plan authorized the mutating effect.
    pub authorized: bool,
    /// The request emitted its mutating effect.
    pub effect_issued: bool,
    /// The effect committed at least one row (send: the transaction committed).
    pub committed: bool,
    /// A revoke committed.
    pub revoked: bool,
    /// The inbox cleanup after a committed revoke was requested.
    pub cleanup_issued: bool,
    /// An inbox delete was constructed with the recipient-scoped guard.
    pub recipient_scoped: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareTransition {
    pub driver: ShareDriver,
    pub effect: ShareEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn share_state_is_sound(driver: ShareDriver) -> bool {
    let send_clean =
        !driver.observe_issued && !driver.committed && !driver.revoked && !driver.cleanup_issued;
    let observe_clean = !driver.effect_issued && !driver.committed;
    let mutate_clean = driver.authorized
        && driver.caller_is_sender
        && driver.link_live
        && !driver.committed
        && !driver.revoked
        && !driver.cleanup_issued;
    let cleanup_clean = driver.authorized
        && driver.caller_is_sender
        && driver.link_live
        && driver.committed
        && driver.revoked
        && driver.cleanup_issued;
    let inbox_clean = driver.recipient_scoped && !driver.committed;
    (!matches!(driver.stage, ShareStage::SendInsert)
        || (matches!(driver.kind, ShareRequestKind::SendCapsule)
            && driver.authorized
            && driver.sender_authenticated
            && driver.effect_issued
            && send_clean))
        && (!matches!(driver.stage, ShareStage::LinkUpdateObserve)
            || (matches!(driver.kind, ShareRequestKind::UpdateLinkedItem)
                && driver.observe_issued
                && observe_clean))
        && (!matches!(driver.stage, ShareStage::LinkUpdateApply)
            || (matches!(driver.kind, ShareRequestKind::UpdateLinkedItem)
                && driver.observe_issued
                && driver.effect_issued
                && mutate_clean))
        && (!matches!(driver.stage, ShareStage::LinkRevokeObserve)
            || (matches!(driver.kind, ShareRequestKind::RevokeLinkedItem)
                && driver.observe_issued
                && observe_clean))
        && (!matches!(driver.stage, ShareStage::LinkRevokeApply)
            || (matches!(driver.kind, ShareRequestKind::RevokeLinkedItem)
                && driver.observe_issued
                && driver.effect_issued
                && mutate_clean))
        && (!matches!(driver.stage, ShareStage::LinkCleanup)
            || (matches!(driver.kind, ShareRequestKind::RevokeLinkedItem)
                && driver.observe_issued
                && driver.effect_issued
                && cleanup_clean))
        && (!matches!(driver.stage, ShareStage::InboxDelete)
            || (matches!(driver.kind, ShareRequestKind::DeleteInboxItem)
                && driver.effect_issued
                && inbox_clean))
        && (!matches!(driver.stage, ShareStage::EkObserve)
            || (matches!(driver.kind, ShareRequestKind::RegisterShareEk)
                && driver.observe_issued
                && observe_clean))
        && (!matches!(driver.stage, ShareStage::EkRegister)
            || (matches!(driver.kind, ShareRequestKind::RegisterShareEk)
                && driver.effect_issued
                && driver.authorized
                && !driver.committed
                && !driver.revoked
                && !driver.cleanup_issued))
        && (!driver.effect_issued
            || driver.authorized
            || (matches!(driver.kind, ShareRequestKind::DeleteInboxItem)
                && driver.recipient_scoped))
        && (!driver.committed || driver.effect_issued)
        && (!(driver.committed && matches!(driver.kind, ShareRequestKind::RevokeLinkedItem))
            || driver.revoked)
        && (!driver.revoked
            || (matches!(driver.kind, ShareRequestKind::RevokeLinkedItem)
                && driver.committed
                && driver.effect_issued
                && driver.authorized
                && driver.caller_is_sender
                && driver.link_live))
        && (!driver.cleanup_issued || driver.revoked)
        && (!driver.revoked || driver.cleanup_issued)
        && (!driver.observe_issued
            || matches!(
                driver.kind,
                ShareRequestKind::UpdateLinkedItem
                    | ShareRequestKind::RevokeLinkedItem
                    | ShareRequestKind::RegisterShareEk
            ))
}

/// Every effect the driver emits agrees with the state it produces.
pub fn share_effect_is_sound(driver: ShareDriver, effect: ShareEffect) -> bool {
    match effect {
        ShareEffect::ObserveLink => {
            driver.observe_issued
                && !driver.effect_issued
                && matches!(
                    driver.stage,
                    ShareStage::LinkUpdateObserve | ShareStage::LinkRevokeObserve
                )
        }
        ShareEffect::ObserveDevice => {
            driver.observe_issued
                && !driver.effect_issued
                && matches!(driver.stage, ShareStage::EkObserve)
        }
        ShareEffect::InsertCapsule(permit) => {
            matches!(driver.kind, ShareRequestKind::SendCapsule)
                && matches!(driver.stage, ShareStage::SendInsert)
                && driver.authorized
                && driver.sender_authenticated
                && driver.effect_issued
                && !driver.committed
                && !driver.revoked
                && permit.capsule_len == driver.capsule_len
        }
        ShareEffect::UpdateLinkedItem(permit) => {
            matches!(driver.kind, ShareRequestKind::UpdateLinkedItem)
                && matches!(driver.stage, ShareStage::LinkUpdateApply)
                && driver.observe_issued
                && driver.authorized
                && driver.caller_is_sender
                && driver.link_live
                && driver.effect_issued
                && !driver.committed
                && !driver.revoked
                && permit.capsule_len == driver.capsule_len
        }
        ShareEffect::RevokeLinkedItem => {
            matches!(driver.kind, ShareRequestKind::RevokeLinkedItem)
                && matches!(driver.stage, ShareStage::LinkRevokeApply)
                && driver.observe_issued
                && driver.authorized
                && driver.caller_is_sender
                && driver.link_live
                && driver.effect_issued
                && !driver.committed
                && !driver.revoked
        }
        ShareEffect::DeleteLinkedInbox => {
            matches!(driver.kind, ShareRequestKind::RevokeLinkedItem)
                && matches!(driver.stage, ShareStage::LinkCleanup)
                && driver.observe_issued
                && driver.revoked
                && driver.committed
                && driver.cleanup_issued
        }
        ShareEffect::DeleteInboxItem(permit) => {
            matches!(driver.kind, ShareRequestKind::DeleteInboxItem)
                && matches!(driver.stage, ShareStage::InboxDelete)
                && driver.recipient_scoped
                && permit.recipient_scoped
                && driver.effect_issued
                && !driver.committed
        }
        ShareEffect::UpdateShareEk(permit) => {
            matches!(driver.kind, ShareRequestKind::RegisterShareEk)
                && matches!(driver.stage, ShareStage::EkRegister)
                && driver.observe_issued
                && driver.authorized
                && driver.effect_issued
                && !driver.committed
                && permit.binds_device_signature()
        }
        ShareEffect::Complete => matches!(driver.stage, ShareStage::Done) && driver.committed,
        ShareEffect::Fail(_) => matches!(driver.stage, ShareStage::Done) && !driver.committed,
        ShareEffect::Idle => true,
    }
}

fn transition(driver: ShareDriver, effect: ShareEffect) -> ShareTransition {
    ShareTransition { driver, effect }
}

fn idle(driver: ShareDriver) -> ShareTransition {
    transition(driver, ShareEffect::Idle)
}

fn fail(driver: ShareDriver, failure: ShareFailure) -> ShareTransition {
    transition(
        ShareDriver {
            stage: ShareStage::Done,
            ..driver
        },
        ShareEffect::Fail(failure),
    )
}

fn base(kind: ShareRequestKind, capsule_len: i64, sender_authenticated: bool) -> ShareDriver {
    ShareDriver {
        kind,
        stage: ShareStage::Done,
        capsule_len,
        sender_authenticated,
        caller_is_sender: false,
        link_live: false,
        observe_issued: false,
        authorized: false,
        effect_issued: false,
        committed: false,
        revoked: false,
        cleanup_issued: false,
        recipient_scoped: false,
    }
}

/// The handler's historical per-(sender, recipient) byte cap, stated without
/// `+` so every `i64` observation is safe. Negative database counters fail
/// closed rather than granting capacity, matching `send_facts`.
fn sender_pair_has_capacity(pair_bytes: i64, capsule_len: i64) -> bool {
    pair_bytes >= 0
        && capsule_len >= 0
        && capsule_len <= MAX_SENDER_TO_RECIPIENT_BYTES
        && pair_bytes <= MAX_SENDER_TO_RECIPIENT_BYTES - capsule_len
}

/// Start a send. The decision order is the handler's historical order:
/// recipient availability, base64 decoding, global capsule cap, inbox item
/// cap, per-pair byte cap, recipient byte cap (`send_facts`), then the real
/// `plan_send` authorization.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_state_is_sound(result.driver)
        && share_effect_is_sound(result.driver, result.effect)
        && (matches!(result.driver.stage, ShareStage::SendInsert)
            || matches!(result.effect, ShareEffect::Fail(_)))
}))]
pub fn begin_send(obs: SendRequestObservation) -> ShareTransition {
    let driver = base(
        ShareRequestKind::SendCapsule,
        obs.policy.capsule_len,
        obs.policy.session_user_id_present,
    );
    if !obs.policy.recipient_has_share_ek {
        return fail(driver, ShareFailure::RecipientUnavailable);
    }
    if obs.decode_failed {
        return fail(driver, ShareFailure::MalformedCapsule);
    }
    if obs.policy.capsule_len > MAX_CAPSULE_BYTES {
        return fail(driver, ShareFailure::CapsuleTooLarge);
    }
    if obs.inbox_count >= MAX_INBOX_ITEMS_PER_USER {
        return fail(driver, ShareFailure::InboxItemLimit);
    }
    if !sender_pair_has_capacity(obs.pair_bytes, obs.policy.capsule_len) {
        return fail(driver, ShareFailure::SenderQuotaExceeded);
    }
    let facts = send_facts(obs.policy);
    if !facts.inbox_has_capacity {
        return fail(driver, ShareFailure::RecipientQuotaExceeded);
    }
    match plan_send(facts) {
        SendDecision::Deliver => transition(
            ShareDriver {
                stage: ShareStage::SendInsert,
                authorized: true,
                effect_issued: true,
                ..driver
            },
            ShareEffect::InsertCapsule(SendInsertPermit {
                capsule_len: obs.policy.capsule_len,
            }),
        ),
        SendDecision::Reject => fail(driver, ShareFailure::CapsulePolicyRejected),
    }
}

/// Start a linked-item update. Request-side decoding/length failures are
/// decided here; a well-formed request then asks the handler to observe the
/// linked row.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_state_is_sound(result.driver)
        && share_effect_is_sound(result.driver, result.effect)
        && (matches!(result.driver.stage, ShareStage::LinkUpdateObserve)
            || matches!(result.effect, ShareEffect::Fail(_)))
}))]
pub fn begin_link_update(obs: LinkUpdateStartObservation) -> ShareTransition {
    let driver = base(ShareRequestKind::UpdateLinkedItem, obs.capsule_len, false);
    if obs.decode_failed {
        return fail(driver, ShareFailure::MalformedCapsule);
    }
    if obs.capsule_len > MAX_CAPSULE_BYTES {
        return fail(driver, ShareFailure::CapsuleTooLarge);
    }
    transition(
        ShareDriver {
            stage: ShareStage::LinkUpdateObserve,
            observe_issued: true,
            ..driver
        },
        ShareEffect::ObserveLink,
    )
}

/// Start a linked-item revoke and ask the handler to observe the linked row.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_state_is_sound(result.driver)
        && share_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, ShareStage::LinkRevokeObserve)
        && matches!(result.effect, ShareEffect::ObserveLink)
}))]
pub fn begin_link_revoke() -> ShareTransition {
    let driver = base(ShareRequestKind::RevokeLinkedItem, 0, false);
    transition(
        ShareDriver {
            stage: ShareStage::LinkRevokeObserve,
            observe_issued: true,
            ..driver
        },
        ShareEffect::ObserveLink,
    )
}

/// Start a recipient-scoped inbox delete. The permit records the guard the
/// handler must use; the handler never reads the row first.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_state_is_sound(result.driver)
        && share_effect_is_sound(result.driver, result.effect)
        && matches!(result.driver.stage, ShareStage::InboxDelete)
        && matches!(result.effect, ShareEffect::DeleteInboxItem(permit) if permit.recipient_scoped)
}))]
pub fn begin_inbox_delete() -> ShareTransition {
    let driver = ShareDriver {
        kind: ShareRequestKind::DeleteInboxItem,
        stage: ShareStage::InboxDelete,
        capsule_len: 0,
        sender_authenticated: false,
        caller_is_sender: false,
        link_live: false,
        observe_issued: false,
        authorized: false,
        effect_issued: true,
        committed: false,
        revoked: false,
        cleanup_issued: false,
        recipient_scoped: true,
    };
    transition(
        driver,
        ShareEffect::DeleteInboxItem(InboxDeletePermit {
            recipient_scoped: true,
        }),
    )
}

/// Start a share-EK registration. Request-side decoding, size and timestamp
/// checks are decided here; a well-formed request then asks the handler to
/// read the signing-device row and verify the binding signature.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_state_is_sound(result.driver)
        && share_effect_is_sound(result.driver, result.effect)
        && (matches!(result.driver.stage, ShareStage::EkObserve)
            || matches!(result.effect, ShareEffect::Fail(_)))
}))]
pub fn begin_ek_registration(obs: EkRegistrationStartObservation) -> ShareTransition {
    let driver = base(ShareRequestKind::RegisterShareEk, 0, false);
    if obs.ek_decode_failed {
        return fail(driver, ShareFailure::ShareEkDecode);
    }
    if obs.ek_len != SHARE_EK_LEN {
        return fail(driver, ShareFailure::ShareEkSize);
    }
    if obs.signed_at_not_canonical {
        return fail(driver, ShareFailure::SignedAtNotCanonical);
    }
    if obs.signed_at_unparseable {
        return fail(driver, ShareFailure::SignedAtUnparseable);
    }
    if obs.signed_at_future {
        return fail(driver, ShareFailure::SignedAtFuture);
    }
    transition(
        ShareDriver {
            stage: ShareStage::EkObserve,
            observe_issued: true,
            ..driver
        },
        ShareEffect::ObserveDevice,
    )
}

fn on_link_observed(driver: ShareDriver, observation: LinkMutationObservation) -> ShareTransition {
    let facts = link_mutation_facts(observation);
    let kind = driver.kind;
    match plan_link_mutation(facts) {
        LinkMutationDecision::Apply => {
            let authorized = ShareDriver {
                caller_is_sender: facts.caller_is_sender,
                link_live: facts.item_exists && facts.not_already_revoked,
                authorized: true,
                effect_issued: true,
                ..driver
            };
            match kind {
                ShareRequestKind::UpdateLinkedItem => transition(
                    ShareDriver {
                        stage: ShareStage::LinkUpdateApply,
                        ..authorized
                    },
                    ShareEffect::UpdateLinkedItem(LinkUpdatePermit {
                        capsule_len: driver.capsule_len,
                    }),
                ),
                ShareRequestKind::RevokeLinkedItem => transition(
                    ShareDriver {
                        stage: ShareStage::LinkRevokeApply,
                        ..authorized
                    },
                    ShareEffect::RevokeLinkedItem,
                ),
                _ => idle(driver),
            }
        }
        LinkMutationDecision::Reject => fail(driver, ShareFailure::LinkNotFound),
    }
}

fn on_ek_observed(driver: ShareDriver, observation: EkDeviceObservation) -> ShareTransition {
    match plan_ek_registration(ek_registration_facts(observation.registration)) {
        EkRegistrationDecision::Register(permit) => transition(
            ShareDriver {
                stage: ShareStage::EkRegister,
                authorized: true,
                effect_issued: true,
                ..driver
            },
            ShareEffect::UpdateShareEk(permit),
        ),
        EkRegistrationDecision::Reject => {
            if !observation.registration.device_row_present
                || !observation.registration.device_user_matches
            {
                fail(driver, ShareFailure::DeviceNotEnrolled)
            } else if observation.stored_identity_vk_decode_failed {
                fail(driver, ShareFailure::StoredIdentityKey)
            } else if observation.signature_decode_failed {
                fail(driver, ShareFailure::SignatureDecode)
            } else {
                fail(driver, ShareFailure::EkPolicyRejected)
            }
        }
    }
}

fn on_send_result(driver: ShareDriver, observation: SendResultObservation) -> ShareTransition {
    match observation {
        SendResultObservation::Committed => transition(
            ShareDriver {
                stage: ShareStage::Done,
                committed: true,
                ..driver
            },
            ShareEffect::Complete,
        ),
        SendResultObservation::StorageFailed => fail(driver, ShareFailure::SendStorage),
        SendResultObservation::CommitConflict => fail(driver, ShareFailure::SendConflict),
    }
}

fn on_rows(driver: ShareDriver, observation: RowsObservation) -> ShareTransition {
    let changed = observation.rows > 0;
    match driver.kind {
        ShareRequestKind::UpdateLinkedItem => {
            if changed {
                transition(
                    ShareDriver {
                        stage: ShareStage::Done,
                        committed: true,
                        ..driver
                    },
                    ShareEffect::Complete,
                )
            } else {
                fail(driver, ShareFailure::LinkNotFound)
            }
        }
        ShareRequestKind::RevokeLinkedItem => {
            if changed {
                transition(
                    ShareDriver {
                        stage: ShareStage::LinkCleanup,
                        committed: true,
                        revoked: true,
                        cleanup_issued: true,
                        ..driver
                    },
                    ShareEffect::DeleteLinkedInbox,
                )
            } else {
                fail(driver, ShareFailure::LinkNotFound)
            }
        }
        ShareRequestKind::DeleteInboxItem => {
            if changed {
                transition(
                    ShareDriver {
                        stage: ShareStage::Done,
                        committed: true,
                        ..driver
                    },
                    ShareEffect::Complete,
                )
            } else {
                fail(driver, ShareFailure::InboxNotFound)
            }
        }
        ShareRequestKind::RegisterShareEk => {
            if changed {
                transition(
                    ShareDriver {
                        stage: ShareStage::Done,
                        committed: true,
                        ..driver
                    },
                    ShareEffect::Complete,
                )
            } else {
                fail(driver, ShareFailure::UserNotFound)
            }
        }
        ShareRequestKind::SendCapsule => idle(driver),
    }
}

fn on_cleaned(driver: ShareDriver) -> ShareTransition {
    transition(
        ShareDriver {
            stage: ShareStage::Done,
            ..driver
        },
        ShareEffect::Complete,
    )
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(share_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_effect_is_sound(result.driver, result.effect)
        && (!share_state_is_sound(driver) || share_state_is_sound(result.driver))
}))]
pub fn step(driver: ShareDriver, event: ShareEvent) -> ShareTransition {
    match event {
        ShareEvent::LinkObserved(observation) => {
            if matches!(
                driver.stage,
                ShareStage::LinkUpdateObserve | ShareStage::LinkRevokeObserve
            ) {
                on_link_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::EkObserved(observation) => {
            if matches!(driver.stage, ShareStage::EkObserve) {
                on_ek_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::SendResult(observation) => {
            if matches!(driver.stage, ShareStage::SendInsert) {
                on_send_result(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::Mutated(observation) => {
            if matches!(
                driver.stage,
                ShareStage::LinkUpdateApply
                    | ShareStage::LinkRevokeApply
                    | ShareStage::InboxDelete
                    | ShareStage::EkRegister
            ) {
                on_rows(driver, observation)
            } else {
                idle(driver)
            }
        }
        ShareEvent::Cleaned(observation) => {
            let _ = observation;
            if matches!(driver.stage, ShareStage::LinkCleanup) {
                on_cleaned(driver)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(share_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_effect_is_sound(result.driver, result.effect)
        && (!share_state_is_sound(driver) || share_state_is_sound(result.driver))
}))]
pub fn on_link_observation(
    driver: ShareDriver,
    observation: LinkMutationObservation,
) -> ShareTransition {
    step(driver, ShareEvent::LinkObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_effect_is_sound(result.driver, result.effect)
        && (!share_state_is_sound(driver) || share_state_is_sound(result.driver))
}))]
pub fn on_ek_observation(driver: ShareDriver, observation: EkDeviceObservation) -> ShareTransition {
    step(driver, ShareEvent::EkObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_effect_is_sound(result.driver, result.effect)
        && (!share_state_is_sound(driver) || share_state_is_sound(result.driver))
}))]
pub fn on_send_completed(
    driver: ShareDriver,
    observation: SendResultObservation,
) -> ShareTransition {
    step(driver, ShareEvent::SendResult(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_effect_is_sound(result.driver, result.effect)
        && (!share_state_is_sound(driver) || share_state_is_sound(result.driver))
}))]
pub fn on_rows_observed(driver: ShareDriver, observation: RowsObservation) -> ShareTransition {
    step(driver, ShareEvent::Mutated(observation))
}

#[cfg_attr(hax, hax_lib::requires(share_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    share_effect_is_sound(result.driver, result.effect)
        && (!share_state_is_sound(driver) || share_state_is_sound(result.driver))
}))]
pub fn on_cleanup_completed(
    driver: ShareDriver,
    observation: CleanupObservation,
) -> ShareTransition {
    step(driver, ShareEvent::Cleaned(observation))
}
