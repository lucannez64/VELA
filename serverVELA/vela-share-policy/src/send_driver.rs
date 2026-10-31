//! Pure post-validation decision driver for the anonymous one-off share links
//! (`POST /send`, `GET /send/:id`, `DELETE /send/:id`).
//!
//! The HTTP handler performs the effectful steps: the guarded `sends` insert,
//! the atomic view-consume `UPDATE`, the row `SELECT`, the view-once cleanup
//! `DELETE` and the owner-scoped `DELETE`. This module owns every *decision*
//! between those effects: whether a create request is admissible and with which
//! clamped TTL/view bounds, how the consume/read returns are classified, and
//! whether a link may be deleted at all.
//!
//! The driver is a per-request value: it does not observe SQL and does not
//! coordinate concurrent requests. Every input is an observation produced by
//! the handler. The transition relation is total: events that do not match the
//! current stage (and every event after `Done`) are ignored, so the unbounded
//! trace induction in `proofs/fstar/send-driver-lemmas` is a statement about
//! every event list, not only the handler's intended order. The concurrent
//! at-most-one-fetch/delete composition lives in
//! `proofs/fstar/send-driver-composition`.
//!
//! The link store model keeps only what the statements need: a link is absent,
//! live with a remaining-view counter, or deleted. The handler's SQL guard is
//! the reason `Consumed` is only observable while views remain, and the reason
//! an owner-scoped `DELETE` is the only way the driver reaches `DeleteLink`.

/// A link carries one item; generous for a large secure note.
pub const MAX_SEND_BYTES: i64 = 256 * 1024;
/// Largest accepted link lifetime: 30 days.
pub const MAX_TTL_SECS: i64 = 30 * 24 * 60 * 60;
/// Smallest accepted link lifetime: 5 minutes.
pub const MIN_TTL_SECS: i64 = 5 * 60;
/// Lifetime used when the request names none: 24 hours.
pub const DEFAULT_TTL_SECS: i64 = 24 * 60 * 60;
/// Largest explicit view count.
pub const MAX_VIEWS_CEILING: i64 = 1000;
/// Smallest accepted Argon2id salt.
pub const MIN_KDF_SALT_LEN: i64 = 8;

fn clamp_ttl(has_ttl: bool, ttl_secs: i64) -> i64 {
    if !has_ttl {
        DEFAULT_TTL_SECS
    } else if ttl_secs < MIN_TTL_SECS {
        MIN_TTL_SECS
    } else if ttl_secs > MAX_TTL_SECS {
        MAX_TTL_SECS
    } else {
        ttl_secs
    }
}

/// `view_once` pins the count to exactly one; otherwise clamp to the ceiling.
/// Returns `(present, value)` because an absent cap is not zero.
fn resolve_max_views(view_once: bool, has_max_views: bool, max_views: i64) -> (bool, i64) {
    if view_once {
        (true, 1)
    } else if !has_max_views {
        (false, 0)
    } else if max_views < 1 {
        (true, 1)
    } else if max_views > MAX_VIEWS_CEILING {
        (true, MAX_VIEWS_CEILING)
    } else {
        (true, max_views)
    }
}

// ── Observations ────────────────────────────────────────────────────────────

/// Request-side observations for `POST /send`. Decode failures are recorded
/// separately so the handler's historical error precedence is preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateObservation {
    /// The authenticated session names a user id.
    pub owner_present: bool,
    /// The ciphertext body was not valid base64.
    pub ciphertext_decode_failed: bool,
    /// Decoded ciphertext length (0 when decoding failed).
    pub ciphertext_len: i64,
    pub has_passphrase: bool,
    /// A `kdf_salt` string was present.
    pub kdf_salt_present: bool,
    /// That string was not valid base64.
    pub kdf_salt_decode_failed: bool,
    /// Decoded salt length (0 when decoding failed or absent).
    pub kdf_salt_len: i64,
    /// The request named a TTL.
    pub has_ttl: bool,
    pub ttl_secs: i64,
    /// The request named a view cap.
    pub has_max_views: bool,
    pub max_views: i64,
    pub view_once: bool,
}

/// Outcome of the atomic view-consume `UPDATE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeObservation {
    /// One row matched: the link is live, unexpired, unrevoked and not
    /// exhausted. One view was consumed.
    Consumed,
    /// Zero rows: missing, expired, revoked, exhausted or deleted. All render
    /// the same `404`.
    Unavailable,
    /// The `UPDATE` failed; the handler retains the original error.
    Error,
}

/// Outcome of the row `SELECT` after a successful consume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadObservation {
    Payload { view_once: bool },
    /// The row disappeared between the consume and the read.
    Missing,
    /// A required cell was absent; the handler retains the original error.
    Unreadable,
}

/// Outcome of the view-once cleanup `DELETE`. The handler ignores it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoveObservation {
    pub removed: bool,
    pub failed: bool,
}

/// Outcome of a guarded `DELETE`/`UPDATE`, as observed by the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RowsObservation {
    pub rows: u64,
    /// The statement errored; the handler retains the original error.
    pub failed: bool,
}

// ── The decision state machine ──────────────────────────────────────────────

/// Which request this per-request driver belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendRequestKind {
    Create,
    Fetch,
    Delete,
}

/// Where the request is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendStage {
    /// Create: the insert may run; fetch: the consume may run; delete: the
    /// owner-scoped delete may run.
    Start,
    /// Fetch: a view was consumed and the row may be read.
    Read,
    /// Fetch: the row was delivered and the view-once cleanup may run.
    Remove,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders them; this module never formats a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendFailure {
    /// No authenticated owner on a create/delete request.
    Unauthenticated,
    /// The ciphertext was not valid base64.
    MalformedCiphertext,
    /// The decoded ciphertext was empty.
    EmptyCiphertext,
    /// The decoded ciphertext exceeded [`MAX_SEND_BYTES`].
    CiphertextTooLarge,
    /// `has_passphrase` was set without a `kdf_salt`.
    MissingKdfSalt,
    /// The `kdf_salt` was not valid base64.
    MalformedKdfSalt,
    /// The decoded `kdf_salt` was shorter than [`MIN_KDF_SALT_LEN`].
    KdfSaltTooShort,
    /// The guarded insert failed; the handler retains the original error.
    InsertStorage,
    /// Missing, expired, revoked, exhausted or deleted link.
    NotFound,
    /// The view-consume `UPDATE` failed.
    ConsumeStorage,
    /// A delivered row was missing a required cell.
    RowUnreadable,
    /// The owner-scoped `DELETE` failed.
    DeleteStorage,
}

/// The exact create authority: nothing but this permit may reach the insert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreatePermit {
    ttl_secs: i64,
    max_views_present: bool,
    max_views: i64,
    view_once: bool,
}

impl CreatePermit {
    pub const fn ttl_secs(self) -> i64 {
        self.ttl_secs
    }

    pub const fn max_views_present(self) -> bool {
        self.max_views_present
    }

    pub const fn max_views(self) -> i64 {
        self.max_views
    }

    pub const fn view_once(self) -> bool {
        self.view_once
    }
}

/// The exact delete authority: only an authenticated owner obtains it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletePermit {
    owner_bound: bool,
}

impl DeletePermit {
    pub const fn owner_bound(self) -> bool {
        self.owner_bound
    }
}

/// The effect the handler must perform next (`Idle` means "do nothing").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendEffect {
    /// Insert the link exactly once, scoped to the owner and with these bounds.
    InsertSend(CreatePermit),
    /// Consume one view atomically.
    ConsumeView,
    /// Read the delivered row.
    ReadSend,
    /// Delete the delivered single-use row (the handler ignores the outcome).
    RemoveFetched,
    /// Perform exactly one owner-scoped delete.
    DeleteLink(DeletePermit),
    /// Terminal success for a create.
    CompleteCreate,
    /// Terminal success for a fetch: the payload may be returned.
    CompleteFetch,
    /// Terminal success for a delete, carrying the handler's `deleted` flag.
    CompleteDelete { deleted: bool },
    /// Terminal failure without restoration (a consumed view is not restored).
    Fail(SendFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about SQL beyond the effect's observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendDriver {
    pub request: SendRequestKind,
    pub stage: SendStage,
    /// The begin decision ran and emitted the request's first effect.
    pub authorized: bool,
    /// Create: the insert effect was emitted. Delete: the delete was emitted.
    pub wrote: bool,
    /// Fetch: a view was consumed.
    pub consumed: bool,
    /// Fetch: the payload was authorized for return.
    pub delivered: bool,
    /// Fetch: the view-once cleanup was emitted.
    pub removed: bool,
    /// Delete: the owner-scoped delete matched at least one row.
    pub deleted: bool,
    /// A terminal success was authorized.
    pub succeeded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

/// One driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendEvent {
    SendInserted(RowsObservation),
    ViewConsumed(ConsumeObservation),
    SendRead(ReadObservation),
    SendRemoved(RemoveObservation),
    SendDeleted(RowsObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendTransition {
    pub driver: SendDriver,
    pub effect: SendEffect,
}

// ── The state invariant ─────────────────────────────────────────────────────

fn is_create(d: SendDriver) -> bool {
    matches!(d.request, SendRequestKind::Create)
}

fn is_fetch(d: SendDriver) -> bool {
    matches!(d.request, SendRequestKind::Fetch)
}

fn is_delete(d: SendDriver) -> bool {
    matches!(d.request, SendRequestKind::Delete)
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn send_state_is_sound(d: SendDriver) -> bool {
    let start_clean = d.authorized
        && !d.consumed
        && !d.delivered
        && !d.removed
        && !d.deleted
        && !d.succeeded
        && !d.failed
        && (if is_create(d) || is_delete(d) {
            d.wrote
        } else {
            !d.wrote
        });
    let read_clean = d.authorized
        && d.consumed
        && !d.wrote
        && !d.delivered
        && !d.removed
        && !d.deleted
        && !d.succeeded
        && !d.failed;
    let remove_clean = d.authorized
        && d.consumed
        && d.delivered
        && !d.removed
        && !d.wrote
        && !d.deleted
        && !d.succeeded
        && !d.failed;
    let done_clean = (d.succeeded || d.failed)
        && !(d.succeeded && d.failed)
        && (!d.succeeded
            || (is_create(d) && d.wrote)
            || (is_fetch(d) && d.consumed && d.delivered)
            || (is_delete(d) && d.wrote))
        && (!d.failed
            || (!d.deleted
                && !d.delivered
                && (!is_fetch(d) || !d.removed)));
    (match d.stage {
        SendStage::Start => start_clean,
        SendStage::Read => read_clean,
        SendStage::Remove => remove_clean,
        SendStage::Done => done_clean,
    })
        // A consumed view means a fetch request; delivered means consumed;
        // the cleanup means delivered; `wrote` is only a create or delete.
        && (!d.consumed || is_fetch(d))
        && (!d.delivered || d.consumed)
        && (!d.removed || d.delivered)
        && (!d.removed || is_fetch(d))
        && (!d.wrote || is_create(d) || is_delete(d))
        && (!d.deleted || (is_delete(d) && d.wrote))
        // Only a fetch reaches the Read/Remove stages, and its flags agree.
        && (!matches!(d.stage, SendStage::Read) || (is_fetch(d) && d.consumed))
        && (!matches!(d.stage, SendStage::Remove)
            || (is_fetch(d) && d.consumed && d.delivered))
}

/// Every effect the driver emits agrees with the state it produces.
pub fn send_effect_is_sound(d: SendDriver, effect: SendEffect) -> bool {
    match effect {
        SendEffect::InsertSend(permit) => {
            is_create(d)
                && matches!(d.stage, SendStage::Start)
                && d.authorized
                && d.wrote
                && !d.consumed
                && !d.delivered
                && !d.succeeded
                && !d.failed
                && permit.ttl_secs >= MIN_TTL_SECS
                && permit.ttl_secs <= MAX_TTL_SECS
                && (!permit.max_views_present
                    || (permit.max_views >= 1 && permit.max_views <= MAX_VIEWS_CEILING))
                && (!permit.view_once || (permit.max_views_present && permit.max_views == 1))
        }
        SendEffect::ConsumeView => {
            is_fetch(d)
                && matches!(d.stage, SendStage::Start)
                && d.authorized
                && !d.consumed
                && !d.delivered
                && !d.succeeded
                && !d.failed
        }
        SendEffect::ReadSend => {
            is_fetch(d)
                && matches!(d.stage, SendStage::Read)
                && d.authorized
                && d.consumed
                && !d.delivered
                && !d.succeeded
                && !d.failed
        }
        SendEffect::RemoveFetched => {
            is_fetch(d)
                && matches!(d.stage, SendStage::Remove)
                && d.authorized
                && d.consumed
                && d.delivered
                && !d.removed
                && !d.succeeded
                && !d.failed
        }
        SendEffect::DeleteLink(permit) => {
            is_delete(d)
                && matches!(d.stage, SendStage::Start)
                && d.authorized
                && d.wrote
                && permit.owner_bound
                && !d.consumed
                && !d.delivered
                && !d.succeeded
                && !d.failed
        }
        SendEffect::CompleteCreate => {
            is_create(d) && matches!(d.stage, SendStage::Done) && d.succeeded && !d.failed && d.wrote
        }
        SendEffect::CompleteFetch => {
            is_fetch(d)
                && matches!(d.stage, SendStage::Done)
                && d.succeeded
                && !d.failed
                && d.consumed
                && d.delivered
        }
        SendEffect::CompleteDelete { deleted } => {
            is_delete(d)
                && matches!(d.stage, SendStage::Done)
                && d.succeeded
                && !d.failed
                && d.wrote
                && d.deleted == deleted
        }
        SendEffect::Fail(_) => {
            matches!(d.stage, SendStage::Done)
                && d.failed
                && !d.succeeded
                && !d.deleted
                && !d.delivered
        }
        SendEffect::Idle => true,
    }
}

fn fresh_driver(request: SendRequestKind) -> SendDriver {
    SendDriver {
        request,
        stage: SendStage::Start,
        authorized: false,
        wrote: false,
        consumed: false,
        delivered: false,
        removed: false,
        deleted: false,
        succeeded: false,
        failed: false,
    }
}

fn transition(d: SendDriver, effect: SendEffect) -> SendTransition {
    SendTransition {
        driver: d,
        effect,
    }
}

fn idle(d: SendDriver) -> SendTransition {
    transition(d, SendEffect::Idle)
}

fn terminal(d: SendDriver, failure: SendFailure) -> SendTransition {
    transition(
        SendDriver {
            stage: SendStage::Done,
            failed: true,
            ..d
        },
        SendEffect::Fail(failure),
    )
}

fn complete(d: SendDriver, effect: SendEffect) -> SendTransition {
    transition(
        SendDriver {
            stage: SendStage::Done,
            succeeded: true,
            ..d
        },
        effect,
    )
}

// ── Create ──────────────────────────────────────────────────────────────────

/// Start `POST /send`. The handler has decoded nothing yet; the observation
/// carries the request's decoded lengths and decode failures. Every size, salt
/// and TTL bound is decided here, and the permit carries the clamped values the
/// insert must use.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_state_is_sound(result.driver)
        && send_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_create(observation: CreateObservation) -> SendTransition {
    let base = fresh_driver(SendRequestKind::Create);
    if !observation.owner_present {
        return terminal(base, SendFailure::Unauthenticated);
    }
    if observation.ciphertext_decode_failed {
        return terminal(base, SendFailure::MalformedCiphertext);
    }
    if observation.ciphertext_len == 0 {
        return terminal(base, SendFailure::EmptyCiphertext);
    }
    if observation.ciphertext_len > MAX_SEND_BYTES {
        return terminal(base, SendFailure::CiphertextTooLarge);
    }
    if observation.has_passphrase && !observation.kdf_salt_present {
        return terminal(base, SendFailure::MissingKdfSalt);
    }
    if observation.has_passphrase && observation.kdf_salt_decode_failed {
        return terminal(base, SendFailure::MalformedKdfSalt);
    }
    if observation.has_passphrase && observation.kdf_salt_len < MIN_KDF_SALT_LEN {
        return terminal(base, SendFailure::KdfSaltTooShort);
    }
    let ttl_secs = clamp_ttl(observation.has_ttl, observation.ttl_secs);
    let (max_views_present, max_views) = resolve_max_views(
        observation.view_once,
        observation.has_max_views,
        observation.max_views,
    );
    transition(
        SendDriver {
            authorized: true,
            wrote: true,
            ..base
        },
        SendEffect::InsertSend(CreatePermit {
            ttl_secs,
            max_views_present,
            max_views,
            view_once: observation.view_once,
        }),
    )
}

#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(d) && is_create(d) && matches!(d.stage, SendStage::Start) && d.wrote))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(d) || send_state_is_sound(result.driver))
}))]
fn on_send_inserted(d: SendDriver, observation: RowsObservation) -> SendTransition {
    if observation.failed {
        terminal(d, SendFailure::InsertStorage)
    } else {
        complete(d, SendEffect::CompleteCreate)
    }
}

// ── Fetch ───────────────────────────────────────────────────────────────────

/// Start `GET /send/:id`. The first effect is the atomic view consume.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_state_is_sound(result.driver)
        && send_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_fetch() -> SendTransition {
    transition(
        SendDriver {
            authorized: true,
            ..fresh_driver(SendRequestKind::Fetch)
        },
        SendEffect::ConsumeView,
    )
}

#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(d) && is_fetch(d) && matches!(d.stage, SendStage::Start) && d.authorized))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(d) || send_state_is_sound(result.driver))
}))]
fn on_view_consumed(d: SendDriver, observation: ConsumeObservation) -> SendTransition {
    match observation {
        ConsumeObservation::Consumed => transition(
            SendDriver {
                stage: SendStage::Read,
                consumed: true,
                ..d
            },
            SendEffect::ReadSend,
        ),
        ConsumeObservation::Unavailable => terminal(d, SendFailure::NotFound),
        ConsumeObservation::Error => terminal(d, SendFailure::ConsumeStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(d) && is_fetch(d) && matches!(d.stage, SendStage::Read) && d.consumed))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(d) || send_state_is_sound(result.driver))
}))]
fn on_send_read(d: SendDriver, observation: ReadObservation) -> SendTransition {
    match observation {
        ReadObservation::Payload { view_once } => {
            if view_once {
                transition(
                    SendDriver {
                        stage: SendStage::Remove,
                        delivered: true,
                        ..d
                    },
                    SendEffect::RemoveFetched,
                )
            } else {
                complete(
                    SendDriver {
                        delivered: true,
                        ..d
                    },
                    SendEffect::CompleteFetch,
                )
            }
        }
        ReadObservation::Missing => terminal(d, SendFailure::NotFound),
        ReadObservation::Unreadable => terminal(d, SendFailure::RowUnreadable),
    }
}

#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(d) && is_fetch(d) && matches!(d.stage, SendStage::Remove) && d.delivered))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(d) || send_state_is_sound(result.driver))
}))]
fn on_send_removed(d: SendDriver, observation: RemoveObservation) -> SendTransition {
    // The handler ignores the cleanup outcome: the payload is already served
    // and a failed remove must not turn a successful fetch into an error.
    let _ = observation;
    complete(
        SendDriver {
            removed: true,
            ..d
        },
        SendEffect::CompleteFetch,
    )
}

// ── Delete ──────────────────────────────────────────────────────────────────

/// Start `DELETE /send/:id`. Only an authenticated owner obtains the delete
/// permit; the SQL statement additionally carries the owner equality.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_state_is_sound(result.driver)
        && send_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_delete(owner_present: bool) -> SendTransition {
    let base = fresh_driver(SendRequestKind::Delete);
    if !owner_present {
        terminal(base, SendFailure::Unauthenticated)
    } else {
        transition(
            SendDriver {
                authorized: true,
                wrote: true,
                ..base
            },
            SendEffect::DeleteLink(DeletePermit { owner_bound: true }),
        )
    }
}

#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(d) && is_delete(d) && matches!(d.stage, SendStage::Start) && d.wrote))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(d) || send_state_is_sound(result.driver))
}))]
fn on_send_deleted(d: SendDriver, observation: RowsObservation) -> SendTransition {
    if observation.failed {
        return terminal(d, SendFailure::DeleteStorage);
    }
    let deleted = observation.rows > 0;
    complete(
        SendDriver {
            deleted,
            ..d
        },
        SendEffect::CompleteDelete { deleted },
    )
}

// ── The total transition relation ───────────────────────────────────────────

/// The complete, total transition relation. Events that do not match the
/// current request/stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(driver) || send_state_is_sound(result.driver))
}))]
pub fn step(driver: SendDriver, event: SendEvent) -> SendTransition {
    match event {
        SendEvent::SendInserted(observation) => {
            if is_create(driver)
                && matches!(driver.stage, SendStage::Start)
                && driver.wrote
            {
                on_send_inserted(driver, observation)
            } else {
                idle(driver)
            }
        }
        SendEvent::ViewConsumed(observation) => {
            if is_fetch(driver)
                && matches!(driver.stage, SendStage::Start)
                && driver.authorized
            {
                on_view_consumed(driver, observation)
            } else {
                idle(driver)
            }
        }
        SendEvent::SendRead(observation) => {
            if is_fetch(driver)
                && matches!(driver.stage, SendStage::Read)
                && driver.consumed
            {
                on_send_read(driver, observation)
            } else {
                idle(driver)
            }
        }
        SendEvent::SendRemoved(observation) => {
            if is_fetch(driver)
                && matches!(driver.stage, SendStage::Remove)
                && driver.delivered
            {
                on_send_removed(driver, observation)
            } else {
                idle(driver)
            }
        }
        SendEvent::SendDeleted(observation) => {
            if is_delete(driver)
                && matches!(driver.stage, SendStage::Start)
                && driver.wrote
            {
                on_send_deleted(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

// ── Per-effect wrappers for the evidence log and the proofs ─────────────────

/// Total wrapper: the handler feeds the insert outcome.
#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(driver) || send_state_is_sound(result.driver))
}))]
pub fn on_send_inserted_event(
    driver: SendDriver,
    observation: RowsObservation,
) -> SendTransition {
    step(driver, SendEvent::SendInserted(observation))
}

/// Total wrapper: the handler feeds the atomic consume outcome.
#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(driver) || send_state_is_sound(result.driver))
}))]
pub fn on_view_consumed_event(
    driver: SendDriver,
    observation: ConsumeObservation,
) -> SendTransition {
    step(driver, SendEvent::ViewConsumed(observation))
}

/// Total wrapper: the handler feeds the row read.
#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(driver) || send_state_is_sound(result.driver))
}))]
pub fn on_send_read_event(driver: SendDriver, observation: ReadObservation) -> SendTransition {
    step(driver, SendEvent::SendRead(observation))
}

/// Total wrapper: the handler feeds the cleanup outcome.
#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(driver) || send_state_is_sound(result.driver))
}))]
pub fn on_send_removed_event(
    driver: SendDriver,
    observation: RemoveObservation,
) -> SendTransition {
    step(driver, SendEvent::SendRemoved(observation))
}

/// Total wrapper: the handler feeds the owner-scoped delete outcome.
#[cfg_attr(hax, hax_lib::requires(send_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    send_effect_is_sound(result.driver, result.effect)
        && (!send_state_is_sound(driver) || send_state_is_sound(result.driver))
}))]
pub fn on_send_deleted_event(
    driver: SendDriver,
    observation: RowsObservation,
) -> SendTransition {
    step(driver, SendEvent::SendDeleted(observation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(start: SendTransition, events: &[SendEvent]) -> SendTransition {
        let mut t = start;
        for event in events {
            t = step(t.driver, *event);
            assert!(send_state_is_sound(t.driver), "{t:?}");
            assert!(send_effect_is_sound(t.driver, t.effect), "{t:?}");
        }
        t
    }

    fn create_obs() -> CreateObservation {
        CreateObservation {
            owner_present: true,
            ciphertext_decode_failed: false,
            ciphertext_len: 10,
            has_passphrase: false,
            kdf_salt_present: false,
            kdf_salt_decode_failed: false,
            kdf_salt_len: 0,
            has_ttl: false,
            ttl_secs: 0,
            has_max_views: false,
            max_views: 0,
            view_once: false,
        }
    }

    #[test]
    fn create_clamps_the_ttl_and_view_bounds_in_the_permit() {
        let base = create_obs();
        let cases = [
            (base, DEFAULT_TTL_SECS, false, 0, false),
            (
                CreateObservation {
                    has_ttl: true,
                    ttl_secs: 1,
                    ..base
                },
                MIN_TTL_SECS,
                false,
                0,
                false,
            ),
            (
                CreateObservation {
                    has_ttl: true,
                    ttl_secs: i64::MAX,
                    ..base
                },
                MAX_TTL_SECS,
                false,
                0,
                false,
            ),
            (
                CreateObservation {
                    has_max_views: true,
                    max_views: 0,
                    ..base
                },
                DEFAULT_TTL_SECS,
                true,
                1,
                false,
            ),
            (
                CreateObservation {
                    has_max_views: true,
                    max_views: i64::MAX,
                    ..base
                },
                DEFAULT_TTL_SECS,
                true,
                MAX_VIEWS_CEILING,
                false,
            ),
            (
                CreateObservation {
                    has_max_views: true,
                    max_views: 5,
                    view_once: true,
                    ..base
                },
                DEFAULT_TTL_SECS,
                true,
                1,
                true,
            ),
        ];
        for (obs, ttl, present, views, view_once) in cases {
            let t = begin_create(obs);
            let SendEffect::InsertSend(permit) = t.effect else {
                panic!("expected insert, got {:?}", t.effect);
            };
            assert_eq!(permit.ttl_secs(), ttl);
            assert_eq!(permit.max_views_present(), present);
            assert_eq!(permit.max_views(), views);
            assert_eq!(permit.view_once(), view_once);
        }
    }

    #[test]
    fn create_rejects_malformed_inputs_in_handler_order() {
        let base = create_obs();
        let cases = [
            (
                CreateObservation {
                    owner_present: false,
                    ..base
                },
                SendFailure::Unauthenticated,
            ),
            (
                CreateObservation {
                    ciphertext_decode_failed: true,
                    ..base
                },
                SendFailure::MalformedCiphertext,
            ),
            (
                CreateObservation {
                    ciphertext_len: 0,
                    ..base
                },
                SendFailure::EmptyCiphertext,
            ),
            (
                CreateObservation {
                    ciphertext_len: MAX_SEND_BYTES + 1,
                    ..base
                },
                SendFailure::CiphertextTooLarge,
            ),
            (
                CreateObservation {
                    has_passphrase: true,
                    ..base
                },
                SendFailure::MissingKdfSalt,
            ),
            (
                CreateObservation {
                    has_passphrase: true,
                    kdf_salt_present: true,
                    kdf_salt_decode_failed: true,
                    ..base
                },
                SendFailure::MalformedKdfSalt,
            ),
            (
                CreateObservation {
                    has_passphrase: true,
                    kdf_salt_present: true,
                    kdf_salt_len: MIN_KDF_SALT_LEN - 1,
                    ..base
                },
                SendFailure::KdfSaltTooShort,
            ),
        ];
        for (obs, failure) in cases {
            assert_eq!(begin_create(obs).effect, SendEffect::Fail(failure));
        }
    }

    #[test]
    fn a_view_once_fetch_delivers_then_removes_and_stops() {
        let t = run(
            begin_fetch(),
            &[
                SendEvent::ViewConsumed(ConsumeObservation::Consumed),
                SendEvent::SendRead(ReadObservation::Payload { view_once: true }),
                SendEvent::SendRemoved(RemoveObservation {
                    removed: true,
                    failed: false,
                }),
            ],
        );
        assert_eq!(t.effect, SendEffect::CompleteFetch);
        assert!(t.driver.consumed && t.driver.delivered && t.driver.removed);
        let after = step(t.driver, SendEvent::SendRead(ReadObservation::Payload { view_once: true }));
        assert_eq!(after.effect, SendEffect::Idle);
    }

    #[test]
    fn a_failed_cleanup_still_delivers_the_payload() {
        let t = run(
            begin_fetch(),
            &[
                SendEvent::ViewConsumed(ConsumeObservation::Consumed),
                SendEvent::SendRead(ReadObservation::Payload { view_once: true }),
                SendEvent::SendRemoved(RemoveObservation {
                    removed: false,
                    failed: true,
                }),
            ],
        );
        assert_eq!(t.effect, SendEffect::CompleteFetch);
        assert!(t.driver.succeeded);
    }

    #[test]
    fn an_unavailable_consume_is_a_404_and_performs_no_read() {
        let t = run(
            begin_fetch(),
            &[SendEvent::ViewConsumed(ConsumeObservation::Unavailable)],
        );
        assert_eq!(t.effect, SendEffect::Fail(SendFailure::NotFound));
        let after = step(t.driver, SendEvent::SendRead(ReadObservation::Payload { view_once: false }));
        assert_eq!(after.effect, SendEffect::Idle);
    }

    #[test]
    fn delete_requires_an_owner_and_reports_the_row_count() {
        assert_eq!(
            begin_delete(false).effect,
            SendEffect::Fail(SendFailure::Unauthenticated)
        );
        let t = run(
            begin_delete(true),
            &[SendEvent::SendDeleted(RowsObservation {
                rows: 0,
                failed: false,
            })],
        );
        assert_eq!(t.effect, SendEffect::CompleteDelete { deleted: false });
        assert!(t.driver.succeeded && !t.driver.deleted);

        let t = run(
            begin_delete(true),
            &[SendEvent::SendDeleted(RowsObservation {
                rows: 3,
                failed: false,
            })],
        );
        assert_eq!(t.effect, SendEffect::CompleteDelete { deleted: true });
        assert!(t.driver.deleted);
    }

    #[test]
    fn out_of_order_events_are_ignored() {
        let t = run(
            begin_create(create_obs()),
            &[SendEvent::ViewConsumed(ConsumeObservation::Consumed)],
        );
        assert_eq!(t.effect, SendEffect::Idle);
        assert!(!t.driver.consumed);
    }
}
