//! Pure per-request drivers for the remaining vault and device mutations.
//!
//! These handlers make few decisions, but each still reaches every effect
//! through an extracted driver so the refusal order and the effect order are
//! proved rather than inlined:
//!
//! - `DELETE /vault/chunk/:id` (`begin_chunk_delete`): the schema floor, the
//!   ACTIVE epoch route, the mutation permit, the version compare-and-swap,
//!   the guarded delete and the change publication;
//! - `PUT /vault/oram/:tree_id/path/:leaf` (`begin_oram`): the same route and
//!   permit for a path of buckets, the quota, one guarded write per bucket and
//!   the zero-row re-resolution after an update;
//! - `POST /vault/schema` (`begin_schema`): the device-scoped durable floor
//!   write;
//! - `POST /device/capsule/ack` (`begin_capsule_ack`): the guarded clear, then
//!   the pending-epoch inspection that distinguishes a lost-response replay
//!   from a different pending capsule;
//! - `POST /device/rekey-capable` (`begin_rekey_capable`): the device-scoped
//!   positive attestation.
//!
//! Every observation is produced by the handler. The drivers do not observe
//! the store or SQL database.

use crate::{
    plan_active_mutation, MutationAuthority, MutationDecision, MutationKind,
    MutationRequest, Phase, INITIAL_EPOCH,
};

// ── Shared observations ─────────────────────────────────────────────────────

/// Outcome of the vault write-schema floor check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaObservation {
    Allowed,
    Refused,
    Storage,
}

/// Outcome of resolving the write route (including the lazy timeout rollback).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteObservation {
    /// The account is ACTIVE at this epoch; writes and reads agree.
    Active { epoch: i64 },
    /// The account is FREEZING; whole-object mutations are refused.
    Freezing,
    /// The extracted resolver refused the declared epoch.
    Rejected,
    Storage,
}

/// Outcome of the ordinary storage quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaObservation {
    Allowed,
    Exceeded,
    Storage,
}

// ── DELETE /vault/chunk/:id ─────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkDeleteRequest {
    pub authenticated: bool,
    /// True for a temporary web-session token.
    pub web: bool,
    /// Web tokens pin the authority epoch; device tokens carry `None`.
    pub web_epoch: Option<i64>,
    /// The `If-Match` version the client believes it is deleting.
    pub if_match: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionObservation {
    Found { version: i64 },
    Missing,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteObservation {
    Deleted,
    Skipped,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkDeleteEvent {
    Schema(SchemaObservation),
    Route(RouteObservation),
    Version(VersionObservation),
    Delete(DeleteObservation),
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkDeleteFailure {
    SchemaRefused,
    SchemaStorage,
    Unauthenticated,
    EpochMismatch,
    RekeyInProgress,
    EpochStorage,
    AuthorityEpochMismatch,
    NotFound,
    VersionMismatch,
    Rekeyed,
    DeleteStorage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkDeleteEffect {
    CheckSchema,
    ResolveEpoch,
    ReadVersion,
    DeleteRow,
    Publish,
    Complete,
    Fail(ChunkDeleteFailure),
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkDeleteStage {
    Schema,
    Epoch,
    Version,
    Delete,
    Publish,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkDeleteDriver {
    pub stage: ChunkDeleteStage,
    pub authenticated: bool,
    pub web: bool,
    pub web_epoch: Option<i64>,
    pub if_match: i64,
    pub epoch: i64,
    pub permit_epoch: i64,
    pub current_version: i64,
    pub deleted: bool,
    pub published: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkDeleteTransition {
    pub driver: ChunkDeleteDriver,
    pub effect: ChunkDeleteEffect,
}

pub fn chunk_delete_state_is_sound(d: ChunkDeleteDriver) -> bool {
    // Before the verdict nothing is published or answered, and only the
    // publish stage follows the guarded delete.
    let clean = !d.deleted && !d.published && !d.responded && !d.failed;
    let fresh = d.epoch == 0 && d.permit_epoch == 0 && d.current_version == 0 && clean;
    let permitted = d.epoch >= INITIAL_EPOCH && d.permit_epoch == d.epoch;
    let done = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded || (permitted && d.deleted && d.published))
        && (!d.failed || !d.deleted);
    (!matches!(d.stage, ChunkDeleteStage::Schema) || (d.authenticated && fresh))
        && (!matches!(d.stage, ChunkDeleteStage::Epoch) || (d.authenticated && fresh))
        && (!matches!(d.stage, ChunkDeleteStage::Version) || (permitted && clean))
        && (!matches!(d.stage, ChunkDeleteStage::Delete)
            || (permitted && d.current_version >= 0 && clean))
        && (!matches!(d.stage, ChunkDeleteStage::Publish)
            || (permitted && d.deleted && !d.published && !d.responded && !d.failed))
        && (!matches!(d.stage, ChunkDeleteStage::Done) || done)
        && (!d.deleted || permitted)
        && (!d.published || d.deleted)
}

impl ChunkDeleteDriver {
    fn permitted(self) -> bool {
        self.epoch >= INITIAL_EPOCH && self.permit_epoch == self.epoch
    }
}

pub fn chunk_delete_effect_is_sound(d: ChunkDeleteDriver, effect: ChunkDeleteEffect) -> bool {
    match effect {
        ChunkDeleteEffect::CheckSchema => {
            matches!(d.stage, ChunkDeleteStage::Schema) && d.authenticated
        }
        ChunkDeleteEffect::ResolveEpoch => matches!(d.stage, ChunkDeleteStage::Epoch),
        ChunkDeleteEffect::ReadVersion => {
            matches!(d.stage, ChunkDeleteStage::Version) && d.permitted()
        }
        ChunkDeleteEffect::DeleteRow => {
            matches!(d.stage, ChunkDeleteStage::Delete) && d.permitted()
        }
        ChunkDeleteEffect::Publish => {
            matches!(d.stage, ChunkDeleteStage::Publish) && d.deleted
        }
        ChunkDeleteEffect::Complete => {
            matches!(d.stage, ChunkDeleteStage::Done) && d.responded && !d.failed
        }
        ChunkDeleteEffect::Fail(_) => {
            matches!(d.stage, ChunkDeleteStage::Done) && d.failed && !d.responded
        }
        ChunkDeleteEffect::Idle => true,
    }
}

fn chunk_transition(driver: ChunkDeleteDriver, effect: ChunkDeleteEffect) -> ChunkDeleteTransition {
    ChunkDeleteTransition { driver, effect }
}

/// A refusal before the guarded delete: sound from any state that has neither
/// deleted nor answered.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !(!driver.deleted && !driver.published && !driver.responded && !driver.failed)
        || (chunk_delete_state_is_sound(result.driver)
            && chunk_delete_effect_is_sound(result.driver, result.effect))
}))]
fn chunk_terminal(driver: ChunkDeleteDriver, failure: ChunkDeleteFailure) -> ChunkDeleteTransition {
    chunk_transition(
        ChunkDeleteDriver {
            stage: ChunkDeleteStage::Done,
            failed: true,
            ..driver
        },
        ChunkDeleteEffect::Fail(failure),
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    chunk_delete_state_is_sound(result.driver)
        && chunk_delete_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_chunk_delete(request: ChunkDeleteRequest) -> ChunkDeleteTransition {
    let driver = ChunkDeleteDriver {
        stage: ChunkDeleteStage::Schema,
        authenticated: request.authenticated,
        web: request.web,
        web_epoch: request.web_epoch,
        if_match: request.if_match,
        epoch: 0,
        permit_epoch: 0,
        current_version: 0,
        deleted: false,
        published: false,
        responded: false,
        failed: false,
    };
    if request.authenticated {
        chunk_transition(driver, ChunkDeleteEffect::CheckSchema)
    } else {
        chunk_terminal(driver, ChunkDeleteFailure::SchemaRefused)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| match result {
    Ok(epoch) => epoch == driver.epoch && epoch >= INITIAL_EPOCH,
    Err(_) => true,
}))]
fn chunk_permit(driver: ChunkDeleteDriver) -> Result<i64, ChunkDeleteFailure> {
    let authority = if driver.web {
        MutationAuthority::WebSession
    } else {
        MutationAuthority::Device
    };
    let authority_epoch = if driver.web {
        driver.web_epoch.unwrap_or(INITIAL_EPOCH)
    } else {
        driver.epoch
    };
    let request = MutationRequest {
        declared_epoch: driver.epoch,
        authority_epoch,
        kind: MutationKind::Vault,
        authority,
    };
    match plan_active_mutation(request) {
        MutationDecision::Permit(permit) => Ok(permit.epoch()),
        MutationDecision::Reject => Err(ChunkDeleteFailure::AuthorityEpochMismatch),
    }
}

// Each event has one contracted helper; `chunk_delete_step` only dispatches.
// Every helper is called in its own stage and preserves soundness.

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, ChunkDeleteStage::Schema)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !chunk_delete_state_is_sound(driver)
        || (chunk_delete_state_is_sound(result.driver)
            && chunk_delete_effect_is_sound(result.driver, result.effect))
}))]
fn chunk_on_schema(driver: ChunkDeleteDriver, observation: SchemaObservation) -> ChunkDeleteTransition {
    match observation {
        SchemaObservation::Allowed => chunk_transition(
            ChunkDeleteDriver {
                stage: ChunkDeleteStage::Epoch,
                ..driver
            },
            ChunkDeleteEffect::ResolveEpoch,
        ),
        SchemaObservation::Refused => chunk_terminal(driver, ChunkDeleteFailure::SchemaRefused),
        SchemaObservation::Storage => chunk_terminal(driver, ChunkDeleteFailure::SchemaStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, ChunkDeleteStage::Epoch)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !chunk_delete_state_is_sound(driver)
        || (chunk_delete_state_is_sound(result.driver)
            && chunk_delete_effect_is_sound(result.driver, result.effect))
}))]
fn chunk_on_route(driver: ChunkDeleteDriver, observation: RouteObservation) -> ChunkDeleteTransition {
    match observation {
        RouteObservation::Active { epoch } => {
            let routed = ChunkDeleteDriver { epoch, ..driver };
            match chunk_permit(routed) {
                Ok(permit_epoch) => chunk_transition(
                    ChunkDeleteDriver {
                        stage: ChunkDeleteStage::Version,
                        permit_epoch,
                        ..routed
                    },
                    ChunkDeleteEffect::ReadVersion,
                ),
                Err(failure) => chunk_terminal(routed, failure),
            }
        }
        RouteObservation::Freezing => chunk_terminal(driver, ChunkDeleteFailure::RekeyInProgress),
        RouteObservation::Rejected => chunk_terminal(driver, ChunkDeleteFailure::EpochMismatch),
        RouteObservation::Storage => chunk_terminal(driver, ChunkDeleteFailure::EpochStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, ChunkDeleteStage::Version)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !chunk_delete_state_is_sound(driver)
        || (chunk_delete_state_is_sound(result.driver)
            && chunk_delete_effect_is_sound(result.driver, result.effect))
}))]
fn chunk_on_version(
    driver: ChunkDeleteDriver,
    observation: VersionObservation,
) -> ChunkDeleteTransition {
    match observation {
        VersionObservation::Found { version } => {
            if version != driver.if_match || version < 0 {
                chunk_terminal(driver, ChunkDeleteFailure::VersionMismatch)
            } else {
                chunk_transition(
                    ChunkDeleteDriver {
                        stage: ChunkDeleteStage::Delete,
                        current_version: version,
                        ..driver
                    },
                    ChunkDeleteEffect::DeleteRow,
                )
            }
        }
        VersionObservation::Missing => chunk_terminal(driver, ChunkDeleteFailure::NotFound),
        VersionObservation::Storage => chunk_terminal(driver, ChunkDeleteFailure::DeleteStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, ChunkDeleteStage::Delete)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !chunk_delete_state_is_sound(driver)
        || (chunk_delete_state_is_sound(result.driver)
            && chunk_delete_effect_is_sound(result.driver, result.effect))
}))]
fn chunk_on_delete(driver: ChunkDeleteDriver, observation: DeleteObservation) -> ChunkDeleteTransition {
    match observation {
        DeleteObservation::Deleted => chunk_transition(
            ChunkDeleteDriver {
                stage: ChunkDeleteStage::Publish,
                deleted: true,
                ..driver
            },
            ChunkDeleteEffect::Publish,
        ),
        DeleteObservation::Skipped => chunk_terminal(driver, ChunkDeleteFailure::Rekeyed),
        DeleteObservation::Storage => chunk_terminal(driver, ChunkDeleteFailure::DeleteStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, ChunkDeleteStage::Publish)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !chunk_delete_state_is_sound(driver)
        || (chunk_delete_state_is_sound(result.driver)
            && chunk_delete_effect_is_sound(result.driver, result.effect))
}))]
fn chunk_on_published(driver: ChunkDeleteDriver) -> ChunkDeleteTransition {
    chunk_transition(
        ChunkDeleteDriver {
            stage: ChunkDeleteStage::Done,
            published: true,
            responded: true,
            ..driver
        },
        ChunkDeleteEffect::Complete,
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    !chunk_delete_state_is_sound(driver)
        || (chunk_delete_state_is_sound(result.driver)
            && chunk_delete_effect_is_sound(result.driver, result.effect))
}))]
pub fn chunk_delete_step(
    driver: ChunkDeleteDriver,
    event: ChunkDeleteEvent,
) -> ChunkDeleteTransition {
    match event {
        ChunkDeleteEvent::Schema(observation) => {
            if matches!(driver.stage, ChunkDeleteStage::Schema) {
                chunk_on_schema(driver, observation)
            } else {
                chunk_transition(driver, ChunkDeleteEffect::Idle)
            }
        }
        ChunkDeleteEvent::Route(observation) => {
            if matches!(driver.stage, ChunkDeleteStage::Epoch) {
                chunk_on_route(driver, observation)
            } else {
                chunk_transition(driver, ChunkDeleteEffect::Idle)
            }
        }
        ChunkDeleteEvent::Version(observation) => {
            if matches!(driver.stage, ChunkDeleteStage::Version) {
                chunk_on_version(driver, observation)
            } else {
                chunk_transition(driver, ChunkDeleteEffect::Idle)
            }
        }
        ChunkDeleteEvent::Delete(observation) => {
            if matches!(driver.stage, ChunkDeleteStage::Delete) {
                chunk_on_delete(driver, observation)
            } else {
                chunk_transition(driver, ChunkDeleteEffect::Idle)
            }
        }
        ChunkDeleteEvent::Published => {
            if matches!(driver.stage, ChunkDeleteStage::Publish) {
                chunk_on_published(driver)
            } else {
                chunk_transition(driver, ChunkDeleteEffect::Idle)
            }
        }
    }
}

// ── PUT /vault/oram/:tree_id/path/:leaf ─────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OramRequest {
    pub authenticated: bool,
    pub web: bool,
    pub web_epoch: Option<i64>,
    /// Number of buckets on the path (the handler validates the shape first).
    pub bucket_count: i64,
    /// Bit `i` is set when bucket `i` uses `if_match == 0` (create).
    pub create_mask: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BucketObservation {
    Written,
    /// Base64 or size validation refused the bucket.
    Invalid,
    /// A create found an existing row.
    Existing,
    /// The guarded write matched zero rows.
    Skipped,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BucketRecheckObservation {
    Unchanged,
    Changed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OramEvent {
    Route(RouteObservation),
    Quota(QuotaObservation),
    Bucket(BucketObservation),
    Recheck(BucketRecheckObservation),
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OramFailure {
    Unauthenticated,
    EpochMismatch,
    RekeyInProgress,
    EpochStorage,
    AuthorityEpochMismatch,
    QuotaExceeded,
    QuotaStorage,
    BucketInvalid,
    BucketExists,
    Rekeyed,
    BucketStorage,
    VersionMismatch,
    RecheckStorage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OramEffect {
    ResolveEpoch,
    EnforceQuota,
    WriteBucket { index: i64 },
    RecheckBucket { index: i64 },
    Publish,
    Complete,
    Fail(OramFailure),
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OramStage {
    Epoch,
    Quota,
    Bucket,
    Recheck,
    Publish,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OramDriver {
    pub stage: OramStage,
    pub authenticated: bool,
    pub web: bool,
    pub web_epoch: Option<i64>,
    pub bucket_count: i64,
    pub create_mask: u64,
    pub written: i64,
    pub recheck_index: i64,
    pub epoch: i64,
    pub permit_epoch: i64,
    pub quota_allowed: bool,
    pub published: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OramTransition {
    pub driver: OramDriver,
    pub effect: OramEffect,
}

/// Most buckets an ORAM path holds (tree height 32).
pub const ORAM_MAX_BUCKETS: i64 = 33;

pub fn oram_state_is_sound(d: OramDriver) -> bool {
    // Before the verdict nothing is published or answered, and the path has a
    // valid, non-empty shape.
    let clean = !d.published && !d.responded && !d.failed;
    let shaped = d.bucket_count > 0 && d.bucket_count <= ORAM_MAX_BUCKETS;
    let fresh = d.epoch == 0
        && d.permit_epoch == 0
        && d.written == 0
        && !d.quota_allowed
        && clean;
    let permitted = d.epoch >= INITIAL_EPOCH && d.permit_epoch == d.epoch;
    let done = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded || (permitted && d.written == d.bucket_count && d.published))
        && (!d.failed || !d.published);
    (!matches!(d.stage, OramStage::Epoch) || (d.authenticated && shaped && fresh))
        && (!matches!(d.stage, OramStage::Quota)
            || (permitted && shaped && d.written == 0 && !d.quota_allowed && clean))
        && (!matches!(d.stage, OramStage::Bucket)
            || (permitted
                && shaped
                && d.quota_allowed
                && d.written >= 0
                && d.written < d.bucket_count
                && clean))
        && (!matches!(d.stage, OramStage::Recheck)
            || (permitted
                && shaped
                && d.quota_allowed
                && d.recheck_index >= 0
                && d.recheck_index < d.bucket_count
                && d.written == d.recheck_index
                && clean))
        && (!matches!(d.stage, OramStage::Publish)
            || (permitted && shaped && d.written == d.bucket_count && d.quota_allowed && clean))
        && (!matches!(d.stage, OramStage::Done) || done)
        && (!d.published || d.written == d.bucket_count)
}

pub fn oram_effect_is_sound(d: OramDriver, effect: OramEffect) -> bool {
    match effect {
        OramEffect::ResolveEpoch => matches!(d.stage, OramStage::Epoch) && d.authenticated,
        OramEffect::EnforceQuota => matches!(d.stage, OramStage::Quota),
        OramEffect::WriteBucket { index } => {
            matches!(d.stage, OramStage::Bucket) && index == d.written && index < d.bucket_count
        }
        OramEffect::RecheckBucket { index } => {
            matches!(d.stage, OramStage::Recheck) && index == d.recheck_index
        }
        OramEffect::Publish => {
            matches!(d.stage, OramStage::Publish) && d.written == d.bucket_count
        }
        OramEffect::Complete => {
            matches!(d.stage, OramStage::Done) && d.responded && !d.failed
        }
        OramEffect::Fail(_) => matches!(d.stage, OramStage::Done) && d.failed && !d.responded,
        OramEffect::Idle => true,
    }
}

fn oram_transition(driver: OramDriver, effect: OramEffect) -> OramTransition {
    OramTransition { driver, effect }
}

/// A refusal: sound from any state that has not published or answered.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !(!driver.published && !driver.responded && !driver.failed)
        || (oram_state_is_sound(result.driver)
            && oram_effect_is_sound(result.driver, result.effect))
}))]
fn oram_terminal(driver: OramDriver, failure: OramFailure) -> OramTransition {
    oram_transition(
        OramDriver {
            stage: OramStage::Done,
            failed: true,
            ..driver
        },
        OramEffect::Fail(failure),
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    oram_state_is_sound(result.driver)
        && oram_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_oram(request: OramRequest) -> OramTransition {
    let driver = OramDriver {
        stage: OramStage::Epoch,
        authenticated: request.authenticated,
        web: request.web,
        web_epoch: request.web_epoch,
        bucket_count: request.bucket_count,
        create_mask: request.create_mask,
        written: 0,
        recheck_index: 0,
        epoch: 0,
        permit_epoch: 0,
        quota_allowed: false,
        published: false,
        responded: false,
        failed: false,
    };
    if !request.authenticated {
        return oram_terminal(driver, OramFailure::Unauthenticated);
    }
    // A path has between one and `ORAM_MAX_BUCKETS` buckets. A non-positive
    // count (never produced by the handler, which passes `len()`) is refused
    // rather than left to write bucket 0 until the loop budget runs out.
    if request.bucket_count <= 0 || request.bucket_count > ORAM_MAX_BUCKETS {
        return oram_terminal(driver, OramFailure::BucketInvalid);
    }
    oram_transition(driver, OramEffect::ResolveEpoch)
}

#[cfg_attr(hax, hax_lib::ensures(|result| match result {
    Ok(epoch) => epoch == driver.epoch && epoch >= INITIAL_EPOCH,
    Err(_) => true,
}))]
fn oram_permit(driver: OramDriver) -> Result<i64, OramFailure> {
    let authority = if driver.web {
        MutationAuthority::WebSession
    } else {
        MutationAuthority::Device
    };
    let authority_epoch = if driver.web {
        driver.web_epoch.unwrap_or(INITIAL_EPOCH)
    } else {
        driver.epoch
    };
    let request = MutationRequest {
        declared_epoch: driver.epoch,
        authority_epoch,
        kind: MutationKind::Vault,
        authority,
    };
    match plan_active_mutation(request) {
        MutationDecision::Permit(permit) => Ok(permit.epoch()),
        MutationDecision::Reject => Err(OramFailure::AuthorityEpochMismatch),
    }
}

fn oram_bucket_is_create(driver: OramDriver, index: i64) -> bool {
    index >= 0 && index < 64 && (driver.create_mask & (1u64 << index)) != 0
}

// Each event has one contracted helper; `oram_step` only dispatches.

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, OramStage::Epoch)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !oram_state_is_sound(driver)
        || (oram_state_is_sound(result.driver)
            && oram_effect_is_sound(result.driver, result.effect))
}))]
fn oram_on_route(driver: OramDriver, observation: RouteObservation) -> OramTransition {
    match observation {
        RouteObservation::Active { epoch } => {
            if epoch < INITIAL_EPOCH {
                return oram_terminal(driver, OramFailure::EpochMismatch);
            }
            let routed = OramDriver { epoch, ..driver };
            match oram_permit(routed) {
                Ok(permit_epoch) => oram_transition(
                    OramDriver {
                        stage: OramStage::Quota,
                        permit_epoch,
                        ..routed
                    },
                    OramEffect::EnforceQuota,
                ),
                Err(failure) => oram_terminal(routed, failure),
            }
        }
        RouteObservation::Freezing => oram_terminal(driver, OramFailure::RekeyInProgress),
        RouteObservation::Rejected => oram_terminal(driver, OramFailure::EpochMismatch),
        RouteObservation::Storage => oram_terminal(driver, OramFailure::EpochStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, OramStage::Quota)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !oram_state_is_sound(driver)
        || (oram_state_is_sound(result.driver)
            && oram_effect_is_sound(result.driver, result.effect))
}))]
fn oram_on_quota(driver: OramDriver, observation: QuotaObservation) -> OramTransition {
    match observation {
        QuotaObservation::Allowed => oram_transition(
            OramDriver {
                stage: OramStage::Bucket,
                quota_allowed: true,
                ..driver
            },
            OramEffect::WriteBucket { index: 0 },
        ),
        QuotaObservation::Exceeded => oram_terminal(driver, OramFailure::QuotaExceeded),
        QuotaObservation::Storage => oram_terminal(driver, OramFailure::QuotaStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, OramStage::Bucket)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !oram_state_is_sound(driver)
        || (oram_state_is_sound(result.driver)
            && oram_effect_is_sound(result.driver, result.effect))
}))]
fn oram_on_bucket(driver: OramDriver, observation: BucketObservation) -> OramTransition {
    let index = driver.written;
    match observation {
        BucketObservation::Written => {
            let next = if index < driver.bucket_count {
                index + 1
            } else {
                index
            };
            if next == driver.bucket_count {
                oram_transition(
                    OramDriver {
                        stage: OramStage::Publish,
                        written: next,
                        ..driver
                    },
                    OramEffect::Publish,
                )
            } else {
                oram_transition(
                    OramDriver {
                        written: next,
                        ..driver
                    },
                    OramEffect::WriteBucket { index: next },
                )
            }
        }
        BucketObservation::Skipped => {
            if oram_bucket_is_create(driver, index) {
                oram_terminal(driver, OramFailure::Rekeyed)
            } else {
                oram_transition(
                    OramDriver {
                        stage: OramStage::Recheck,
                        recheck_index: index,
                        ..driver
                    },
                    OramEffect::RecheckBucket { index },
                )
            }
        }
        BucketObservation::Existing => oram_terminal(driver, OramFailure::BucketExists),
        BucketObservation::Invalid => oram_terminal(driver, OramFailure::BucketInvalid),
        BucketObservation::Storage => oram_terminal(driver, OramFailure::BucketStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, OramStage::Recheck)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !oram_state_is_sound(driver)
        || (oram_state_is_sound(result.driver)
            && oram_effect_is_sound(result.driver, result.effect))
}))]
fn oram_on_recheck(driver: OramDriver, observation: BucketRecheckObservation) -> OramTransition {
    match observation {
        BucketRecheckObservation::Unchanged => oram_terminal(driver, OramFailure::VersionMismatch),
        BucketRecheckObservation::Changed => oram_terminal(driver, OramFailure::Rekeyed),
        BucketRecheckObservation::Failed => oram_terminal(driver, OramFailure::RecheckStorage),
    }
}

#[cfg_attr(hax, hax_lib::requires(matches!(driver.stage, OramStage::Publish)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    !oram_state_is_sound(driver)
        || (oram_state_is_sound(result.driver)
            && oram_effect_is_sound(result.driver, result.effect))
}))]
fn oram_on_published(driver: OramDriver) -> OramTransition {
    oram_transition(
        OramDriver {
            stage: OramStage::Done,
            published: true,
            responded: true,
            ..driver
        },
        OramEffect::Complete,
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    !oram_state_is_sound(driver)
        || (oram_state_is_sound(result.driver)
            && oram_effect_is_sound(result.driver, result.effect))
}))]
pub fn oram_step(driver: OramDriver, event: OramEvent) -> OramTransition {
    match event {
        OramEvent::Route(observation) => {
            if matches!(driver.stage, OramStage::Epoch) {
                oram_on_route(driver, observation)
            } else {
                oram_transition(driver, OramEffect::Idle)
            }
        }
        OramEvent::Quota(observation) => {
            if matches!(driver.stage, OramStage::Quota) {
                oram_on_quota(driver, observation)
            } else {
                oram_transition(driver, OramEffect::Idle)
            }
        }
        OramEvent::Bucket(observation) => {
            if matches!(driver.stage, OramStage::Bucket) {
                oram_on_bucket(driver, observation)
            } else {
                oram_transition(driver, OramEffect::Idle)
            }
        }
        OramEvent::Recheck(observation) => {
            if matches!(driver.stage, OramStage::Recheck) {
                oram_on_recheck(driver, observation)
            } else {
                oram_transition(driver, OramEffect::Idle)
            }
        }
        OramEvent::Published => {
            if matches!(driver.stage, OramStage::Publish) {
                oram_on_published(driver)
            } else {
                oram_transition(driver, OramEffect::Idle)
            }
        }
    }
}

// ── POST /vault/schema ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaRequest {
    pub authenticated: bool,
    pub device_scope: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaWriteObservation {
    Written,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaEvent {
    Write(SchemaWriteObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaFailure {
    Unauthenticated,
    WebSessionForbidden,
    WriteStorage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaEffect {
    WriteFloor,
    Complete,
    Fail(SchemaFailure),
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaStage {
    Write,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaDriver {
    pub stage: SchemaStage,
    pub authenticated: bool,
    pub device_scope: bool,
    pub written: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaTransition {
    pub driver: SchemaDriver,
    pub effect: SchemaEffect,
}

pub fn schema_state_is_sound(d: SchemaDriver) -> bool {
    (!matches!(d.stage, SchemaStage::Write)
        || (d.authenticated && d.device_scope && !d.written && !d.responded && !d.failed))
        && (!matches!(d.stage, SchemaStage::Done)
            || ((d.responded || d.failed)
                && !(d.responded && d.failed)
                && (!d.responded || d.written)))
        && (!d.written || (d.authenticated && d.device_scope))
}

pub fn schema_effect_is_sound(d: SchemaDriver, effect: SchemaEffect) -> bool {
    match effect {
        SchemaEffect::WriteFloor => {
            matches!(d.stage, SchemaStage::Write) && d.authenticated && d.device_scope
        }
        SchemaEffect::Complete => matches!(d.stage, SchemaStage::Done) && d.responded && !d.failed,
        SchemaEffect::Fail(_) => matches!(d.stage, SchemaStage::Done) && d.failed && !d.responded,
        SchemaEffect::Idle => true,
    }
}

fn schema_transition(driver: SchemaDriver, effect: SchemaEffect) -> SchemaTransition {
    SchemaTransition { driver, effect }
}

fn schema_terminal(driver: SchemaDriver, failure: SchemaFailure) -> SchemaTransition {
    schema_transition(
        SchemaDriver {
            stage: SchemaStage::Done,
            failed: true,
            ..driver
        },
        SchemaEffect::Fail(failure),
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    schema_state_is_sound(result.driver) && schema_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_schema(request: SchemaRequest) -> SchemaTransition {
    let driver = SchemaDriver {
        stage: SchemaStage::Write,
        authenticated: request.authenticated,
        device_scope: request.device_scope,
        written: false,
        responded: false,
        failed: false,
    };
    if !request.authenticated {
        schema_terminal(driver, SchemaFailure::Unauthenticated)
    } else if !request.device_scope {
        schema_terminal(driver, SchemaFailure::WebSessionForbidden)
    } else {
        schema_transition(driver, SchemaEffect::WriteFloor)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    !schema_state_is_sound(driver)
        || (schema_state_is_sound(result.driver)
            && schema_effect_is_sound(result.driver, result.effect))
}))]
pub fn schema_step(driver: SchemaDriver, event: SchemaEvent) -> SchemaTransition {
    match event {
        SchemaEvent::Write(observation) => {
            if !matches!(driver.stage, SchemaStage::Write) {
                return schema_transition(driver, SchemaEffect::Idle);
            }
            match observation {
                SchemaWriteObservation::Written => schema_transition(
                    SchemaDriver {
                        stage: SchemaStage::Done,
                        written: true,
                        responded: true,
                        ..driver
                    },
                    SchemaEffect::Complete,
                ),
                SchemaWriteObservation::Storage => {
                    schema_terminal(driver, SchemaFailure::WriteStorage)
                }
            }
        }
    }
}

// ── POST /device/capsule/ack ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapsuleAckRequest {
    pub authenticated: bool,
    pub device_scope: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckObservation {
    Cleared,
    Missed,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingObservation {
    /// The row exists with no pending capsule epoch: a lost-response replay.
    Replay,
    /// The row exists with a different pending epoch.
    Pending,
    Missing,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleAckEvent {
    Ack(AckObservation),
    Pending(PendingObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleAckFailure {
    Unauthenticated,
    WebSessionForbidden,
    AckStorage,
    NoLongerEligible,
    DifferentPending,
    PendingStorage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleAckEffect {
    Acknowledge,
    InspectPending,
    Complete,
    Fail(CapsuleAckFailure),
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleAckStage {
    Ack,
    Pending,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapsuleAckDriver {
    pub stage: CapsuleAckStage,
    pub authenticated: bool,
    pub device_scope: bool,
    pub cleared: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapsuleAckTransition {
    pub driver: CapsuleAckDriver,
    pub effect: CapsuleAckEffect,
}

pub fn capsule_ack_state_is_sound(d: CapsuleAckDriver) -> bool {
    let open = !d.responded && !d.failed;
    (!matches!(d.stage, CapsuleAckStage::Ack)
        || (d.authenticated && d.device_scope && !d.cleared && open))
        && (!matches!(d.stage, CapsuleAckStage::Pending)
            || (d.authenticated && d.device_scope && open))
        && (!matches!(d.stage, CapsuleAckStage::Done)
            || ((d.responded || d.failed)
                && !(d.responded && d.failed)
                && (!d.responded || d.cleared)))
        && (!d.cleared || (d.authenticated && d.device_scope))
}

pub fn capsule_ack_effect_is_sound(d: CapsuleAckDriver, effect: CapsuleAckEffect) -> bool {
    match effect {
        CapsuleAckEffect::Acknowledge => {
            matches!(d.stage, CapsuleAckStage::Ack) && d.authenticated && d.device_scope
        }
        CapsuleAckEffect::InspectPending => matches!(d.stage, CapsuleAckStage::Pending),
        CapsuleAckEffect::Complete => {
            matches!(d.stage, CapsuleAckStage::Done) && d.responded && !d.failed
        }
        CapsuleAckEffect::Fail(_) => {
            matches!(d.stage, CapsuleAckStage::Done) && d.failed && !d.responded
        }
        CapsuleAckEffect::Idle => true,
    }
}

fn ack_transition(driver: CapsuleAckDriver, effect: CapsuleAckEffect) -> CapsuleAckTransition {
    CapsuleAckTransition { driver, effect }
}

fn ack_terminal(driver: CapsuleAckDriver, failure: CapsuleAckFailure) -> CapsuleAckTransition {
    ack_transition(
        CapsuleAckDriver {
            stage: CapsuleAckStage::Done,
            failed: true,
            ..driver
        },
        CapsuleAckEffect::Fail(failure),
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    capsule_ack_state_is_sound(result.driver)
        && capsule_ack_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_capsule_ack(request: CapsuleAckRequest) -> CapsuleAckTransition {
    let driver = CapsuleAckDriver {
        stage: CapsuleAckStage::Ack,
        authenticated: request.authenticated,
        device_scope: request.device_scope,
        cleared: false,
        responded: false,
        failed: false,
    };
    if !request.authenticated {
        ack_terminal(driver, CapsuleAckFailure::Unauthenticated)
    } else if !request.device_scope {
        ack_terminal(driver, CapsuleAckFailure::WebSessionForbidden)
    } else {
        ack_transition(driver, CapsuleAckEffect::Acknowledge)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    !capsule_ack_state_is_sound(driver)
        || (capsule_ack_state_is_sound(result.driver)
            && capsule_ack_effect_is_sound(result.driver, result.effect))
}))]
pub fn capsule_ack_step(driver: CapsuleAckDriver, event: CapsuleAckEvent) -> CapsuleAckTransition {
    match event {
        CapsuleAckEvent::Ack(observation) => {
            if !matches!(driver.stage, CapsuleAckStage::Ack) {
                return ack_transition(driver, CapsuleAckEffect::Idle);
            }
            match observation {
                AckObservation::Cleared => ack_transition(
                    CapsuleAckDriver {
                        stage: CapsuleAckStage::Done,
                        cleared: true,
                        responded: true,
                        ..driver
                    },
                    CapsuleAckEffect::Complete,
                ),
                AckObservation::Missed => ack_transition(
                    CapsuleAckDriver {
                        stage: CapsuleAckStage::Pending,
                        ..driver
                    },
                    CapsuleAckEffect::InspectPending,
                ),
                AckObservation::Storage => ack_terminal(driver, CapsuleAckFailure::AckStorage),
            }
        }
        CapsuleAckEvent::Pending(observation) => {
            if !matches!(driver.stage, CapsuleAckStage::Pending) {
                return ack_transition(driver, CapsuleAckEffect::Idle);
            }
            match observation {
                PendingObservation::Replay => ack_transition(
                    CapsuleAckDriver {
                        stage: CapsuleAckStage::Done,
                        cleared: true,
                        responded: true,
                        ..driver
                    },
                    CapsuleAckEffect::Complete,
                ),
                PendingObservation::Pending => {
                    ack_terminal(driver, CapsuleAckFailure::DifferentPending)
                }
                PendingObservation::Missing => {
                    ack_terminal(driver, CapsuleAckFailure::NoLongerEligible)
                }
                PendingObservation::Storage => {
                    ack_terminal(driver, CapsuleAckFailure::PendingStorage)
                }
            }
        }
    }
}

// ── POST /device/rekey-capable ─────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyCapableRequest {
    pub authenticated: bool,
    pub device_scope: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestObservation {
    Attested,
    Missing,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyCapableEvent {
    Attest(AttestObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyCapableFailure {
    Unauthenticated,
    WebSessionForbidden,
    NotFound,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyCapableEffect {
    Attest,
    Complete,
    Fail(RekeyCapableFailure),
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyCapableStage {
    Attest,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyCapableDriver {
    pub stage: RekeyCapableStage,
    pub authenticated: bool,
    pub device_scope: bool,
    pub attested: bool,
    pub responded: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyCapableTransition {
    pub driver: RekeyCapableDriver,
    pub effect: RekeyCapableEffect,
}

pub fn rekey_capable_state_is_sound(d: RekeyCapableDriver) -> bool {
    (!matches!(d.stage, RekeyCapableStage::Attest)
        || (d.authenticated && d.device_scope && !d.attested && !d.responded && !d.failed))
        && (!matches!(d.stage, RekeyCapableStage::Done)
            || ((d.responded || d.failed)
                && !(d.responded && d.failed)
                && (!d.responded || d.attested)))
        && (!d.attested || (d.authenticated && d.device_scope))
}

pub fn rekey_capable_effect_is_sound(d: RekeyCapableDriver, effect: RekeyCapableEffect) -> bool {
    match effect {
        RekeyCapableEffect::Attest => {
            matches!(d.stage, RekeyCapableStage::Attest) && d.authenticated && d.device_scope
        }
        RekeyCapableEffect::Complete => {
            matches!(d.stage, RekeyCapableStage::Done) && d.responded && !d.failed
        }
        RekeyCapableEffect::Fail(_) => {
            matches!(d.stage, RekeyCapableStage::Done) && d.failed && !d.responded
        }
        RekeyCapableEffect::Idle => true,
    }
}

fn capable_transition(
    driver: RekeyCapableDriver,
    effect: RekeyCapableEffect,
) -> RekeyCapableTransition {
    RekeyCapableTransition { driver, effect }
}

fn capable_terminal(
    driver: RekeyCapableDriver,
    failure: RekeyCapableFailure,
) -> RekeyCapableTransition {
    capable_transition(
        RekeyCapableDriver {
            stage: RekeyCapableStage::Done,
            failed: true,
            ..driver
        },
        RekeyCapableEffect::Fail(failure),
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    rekey_capable_state_is_sound(result.driver)
        && rekey_capable_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_rekey_capable(request: RekeyCapableRequest) -> RekeyCapableTransition {
    let driver = RekeyCapableDriver {
        stage: RekeyCapableStage::Attest,
        authenticated: request.authenticated,
        device_scope: request.device_scope,
        attested: false,
        responded: false,
        failed: false,
    };
    if !request.authenticated {
        capable_terminal(driver, RekeyCapableFailure::Unauthenticated)
    } else if !request.device_scope {
        capable_terminal(driver, RekeyCapableFailure::WebSessionForbidden)
    } else {
        capable_transition(driver, RekeyCapableEffect::Attest)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    !rekey_capable_state_is_sound(driver)
        || (rekey_capable_state_is_sound(result.driver)
            && rekey_capable_effect_is_sound(result.driver, result.effect))
}))]
pub fn rekey_capable_step(
    driver: RekeyCapableDriver,
    event: RekeyCapableEvent,
) -> RekeyCapableTransition {
    match event {
        RekeyCapableEvent::Attest(observation) => {
            if !matches!(driver.stage, RekeyCapableStage::Attest) {
                return capable_transition(driver, RekeyCapableEffect::Idle);
            }
            match observation {
                AttestObservation::Attested => capable_transition(
                    RekeyCapableDriver {
                        stage: RekeyCapableStage::Done,
                        attested: true,
                        responded: true,
                        ..driver
                    },
                    RekeyCapableEffect::Complete,
                ),
                AttestObservation::Missing => {
                    capable_terminal(driver, RekeyCapableFailure::NotFound)
                }
                AttestObservation::Storage => capable_terminal(driver, RekeyCapableFailure::Storage),
            }
        }
    }
}

// ── Cross-driver structural helpers ────────────────────────────────────────

/// A route observation is only a valid ACTIVE route when the epoch is an
/// initial-or-later epoch, and a rejected/freezing route cannot carry one.
pub fn route_is_active(observation: RouteObservation) -> bool {
    match observation {
        RouteObservation::Active { epoch } => epoch >= INITIAL_EPOCH,
        _ => false,
    }
}

/// The phase a route observation names, used by the Rust tests and the F*
/// restatement of the resolver's decision.
pub fn route_phase(observation: RouteObservation) -> Option<Phase> {
    match observation {
        RouteObservation::Active { .. } => Some(Phase::Active),
        RouteObservation::Freezing => Some(Phase::Freezing),
        _ => None,
    }
}

// ── Rust conformance tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RekeyState, WriteDecision};

    fn device() -> ChunkDeleteRequest {
        ChunkDeleteRequest {
            authenticated: true,
            web: false,
            web_epoch: None,
            if_match: 3,
        }
    }

    fn chunk_events() -> Vec<ChunkDeleteEvent> {
        let mut out = vec![];
        for observation in [
            SchemaObservation::Allowed,
            SchemaObservation::Refused,
            SchemaObservation::Storage,
        ] {
            out.push(ChunkDeleteEvent::Schema(observation));
        }
        for observation in [
            RouteObservation::Active { epoch: 4 },
            RouteObservation::Freezing,
            RouteObservation::Rejected,
            RouteObservation::Storage,
        ] {
            out.push(ChunkDeleteEvent::Route(observation));
        }
        for observation in [
            VersionObservation::Found { version: 3 },
            VersionObservation::Found { version: 2 },
            VersionObservation::Missing,
            VersionObservation::Storage,
        ] {
            out.push(ChunkDeleteEvent::Version(observation));
        }
        for observation in [
            DeleteObservation::Deleted,
            DeleteObservation::Skipped,
            DeleteObservation::Storage,
        ] {
            out.push(ChunkDeleteEvent::Delete(observation));
        }
        out.push(ChunkDeleteEvent::Published);
        out
    }

    fn chunk_at(stage: ChunkDeleteStage) -> ChunkDeleteDriver {
        let mut driver = begin_chunk_delete(device()).driver;
        let mut guard = 0;
        while driver.stage != stage {
            let next = match driver.stage {
                ChunkDeleteStage::Schema => {
                    chunk_delete_step(driver, ChunkDeleteEvent::Schema(SchemaObservation::Allowed))
                }
                ChunkDeleteStage::Epoch => chunk_delete_step(
                    driver,
                    ChunkDeleteEvent::Route(RouteObservation::Active { epoch: 4 }),
                ),
                ChunkDeleteStage::Version => chunk_delete_step(
                    driver,
                    ChunkDeleteEvent::Version(VersionObservation::Found { version: 3 }),
                ),
                ChunkDeleteStage::Delete => chunk_delete_step(
                    driver,
                    ChunkDeleteEvent::Delete(DeleteObservation::Deleted),
                ),
                ChunkDeleteStage::Publish => {
                    chunk_delete_step(driver, ChunkDeleteEvent::Published)
                }
                ChunkDeleteStage::Done => break,
            };
            driver = next.driver;
            guard += 1;
            assert!(guard < 16);
        }
        assert_eq!(driver.stage, stage);
        driver
    }

    #[test]
    fn chunk_delete_exhaustive_stage_times_event_is_sound() {
        for stage in [
            ChunkDeleteStage::Schema,
            ChunkDeleteStage::Epoch,
            ChunkDeleteStage::Version,
            ChunkDeleteStage::Delete,
            ChunkDeleteStage::Publish,
            ChunkDeleteStage::Done,
        ] {
            let driver = chunk_at(stage);
            assert!(chunk_delete_state_is_sound(driver));
            for event in chunk_events() {
                let t = chunk_delete_step(driver, event);
                assert!(chunk_delete_state_is_sound(t.driver));
                assert!(chunk_delete_effect_is_sound(t.driver, t.effect));
            }
        }
    }

    #[test]
    fn chunk_delete_walks_schema_route_version_delete_publish() {
        let t = begin_chunk_delete(device());
        assert_eq!(t.effect, ChunkDeleteEffect::CheckSchema);
        let t = chunk_delete_step(t.driver, ChunkDeleteEvent::Schema(SchemaObservation::Allowed));
        assert_eq!(t.effect, ChunkDeleteEffect::ResolveEpoch);
        let t = chunk_delete_step(
            t.driver,
            ChunkDeleteEvent::Route(RouteObservation::Active { epoch: 4 }),
        );
        assert_eq!(t.effect, ChunkDeleteEffect::ReadVersion);
        assert_eq!(t.driver.permit_epoch, 4);
        let t = chunk_delete_step(
            t.driver,
            ChunkDeleteEvent::Version(VersionObservation::Found { version: 3 }),
        );
        assert_eq!(t.effect, ChunkDeleteEffect::DeleteRow);
        let t = chunk_delete_step(t.driver, ChunkDeleteEvent::Delete(DeleteObservation::Deleted));
        assert_eq!(t.effect, ChunkDeleteEffect::Publish);
        let t = chunk_delete_step(t.driver, ChunkDeleteEvent::Published);
        assert_eq!(t.effect, ChunkDeleteEffect::Complete);
        assert!(t.driver.responded && t.driver.deleted && t.driver.published);
    }

    #[test]
    fn chunk_delete_refuses_freezing_rekey_and_version_mismatch() {
        let at_route = chunk_at(ChunkDeleteStage::Epoch);
        assert_eq!(
            chunk_delete_step(at_route, ChunkDeleteEvent::Route(RouteObservation::Freezing)).effect,
            ChunkDeleteEffect::Fail(ChunkDeleteFailure::RekeyInProgress)
        );
        let at_version = chunk_at(ChunkDeleteStage::Version);
        assert_eq!(
            chunk_delete_step(
                at_version,
                ChunkDeleteEvent::Version(VersionObservation::Found { version: 2 })
            )
            .effect,
            ChunkDeleteEffect::Fail(ChunkDeleteFailure::VersionMismatch)
        );
        let at_delete = chunk_at(ChunkDeleteStage::Delete);
        assert_eq!(
            chunk_delete_step(at_delete, ChunkDeleteEvent::Delete(DeleteObservation::Skipped))
                .effect,
            ChunkDeleteEffect::Fail(ChunkDeleteFailure::Rekeyed)
        );
    }

    #[test]
    fn chunk_delete_web_token_must_be_pinned_to_the_route_epoch() {
        let request = ChunkDeleteRequest {
            web: true,
            web_epoch: Some(3),
            ..device()
        };
        let mut t = begin_chunk_delete(request);
        t = chunk_delete_step(t.driver, ChunkDeleteEvent::Schema(SchemaObservation::Allowed));
        let t = chunk_delete_step(
            t.driver,
            ChunkDeleteEvent::Route(RouteObservation::Active { epoch: 4 }),
        );
        assert_eq!(
            t.effect,
            ChunkDeleteEffect::Fail(ChunkDeleteFailure::AuthorityEpochMismatch)
        );
        let request = ChunkDeleteRequest {
            web: true,
            web_epoch: Some(4),
            ..device()
        };
        let mut t = begin_chunk_delete(request);
        t = chunk_delete_step(t.driver, ChunkDeleteEvent::Schema(SchemaObservation::Allowed));
        let t = chunk_delete_step(
            t.driver,
            ChunkDeleteEvent::Route(RouteObservation::Active { epoch: 4 }),
        );
        assert_eq!(t.effect, ChunkDeleteEffect::ReadVersion);
    }

    fn oram_request(buckets: i64) -> OramRequest {
        OramRequest {
            authenticated: true,
            web: false,
            web_epoch: None,
            bucket_count: buckets,
            create_mask: 0,
        }
    }

    fn oram_at(stage: OramStage) -> OramDriver {
        let mut driver = begin_oram(oram_request(2)).driver;
        let mut guard = 0;
        while driver.stage != stage {
            let next = match driver.stage {
                OramStage::Epoch => oram_step(
                    driver,
                    OramEvent::Route(RouteObservation::Active { epoch: 1 }),
                ),
                OramStage::Quota => oram_step(driver, OramEvent::Quota(QuotaObservation::Allowed)),
                OramStage::Bucket => {
                    oram_step(driver, OramEvent::Bucket(BucketObservation::Written))
                }
                OramStage::Recheck => {
                    oram_step(driver, OramEvent::Recheck(BucketRecheckObservation::Unchanged))
                }
                OramStage::Publish => oram_step(driver, OramEvent::Published),
                OramStage::Done => break,
            };
            driver = next.driver;
            guard += 1;
            assert!(guard < 16);
        }
        assert_eq!(driver.stage, stage);
        driver
    }

    fn oram_events() -> Vec<OramEvent> {
        let mut out = vec![];
        for observation in [
            RouteObservation::Active { epoch: 1 },
            RouteObservation::Freezing,
            RouteObservation::Rejected,
            RouteObservation::Storage,
        ] {
            out.push(OramEvent::Route(observation));
        }
        for observation in [
            QuotaObservation::Allowed,
            QuotaObservation::Exceeded,
            QuotaObservation::Storage,
        ] {
            out.push(OramEvent::Quota(observation));
        }
        for observation in [
            BucketObservation::Written,
            BucketObservation::Invalid,
            BucketObservation::Existing,
            BucketObservation::Skipped,
            BucketObservation::Storage,
        ] {
            out.push(OramEvent::Bucket(observation));
        }
        for observation in [
            BucketRecheckObservation::Unchanged,
            BucketRecheckObservation::Changed,
            BucketRecheckObservation::Failed,
        ] {
            out.push(OramEvent::Recheck(observation));
        }
        out.push(OramEvent::Published);
        out
    }

    #[test]
    fn oram_exhaustive_stage_times_event_is_sound() {
        for stage in [
            OramStage::Epoch,
            OramStage::Quota,
            OramStage::Bucket,
            OramStage::Publish,
            OramStage::Done,
        ] {
            let driver = oram_at(stage);
            assert!(oram_state_is_sound(driver));
            for event in oram_events() {
                let t = oram_step(driver, event);
                assert!(oram_state_is_sound(t.driver));
                assert!(oram_effect_is_sound(t.driver, t.effect));
            }
        }
    }

    #[test]
    fn oram_writes_every_bucket_then_publishes() {
        let mut t = begin_oram(oram_request(2));
        t = oram_step(t.driver, OramEvent::Route(RouteObservation::Active { epoch: 1 }));
        t = oram_step(t.driver, OramEvent::Quota(QuotaObservation::Allowed));
        assert_eq!(t.effect, OramEffect::WriteBucket { index: 0 });
        t = oram_step(t.driver, OramEvent::Bucket(BucketObservation::Written));
        assert_eq!(t.effect, OramEffect::WriteBucket { index: 1 });
        t = oram_step(t.driver, OramEvent::Bucket(BucketObservation::Written));
        assert_eq!(t.effect, OramEffect::Publish);
        t = oram_step(t.driver, OramEvent::Published);
        assert_eq!(t.effect, OramEffect::Complete);
        assert!(t.driver.responded && t.driver.published);
    }

    #[test]
    fn oram_update_miss_rechecks_but_create_miss_is_terminal() {
        let mut t = begin_oram(oram_request(2));
        t = oram_step(t.driver, OramEvent::Route(RouteObservation::Active { epoch: 1 }));
        t = oram_step(t.driver, OramEvent::Quota(QuotaObservation::Allowed));
        let updated = oram_step(t.driver, OramEvent::Bucket(BucketObservation::Skipped));
        assert_eq!(updated.effect, OramEffect::RecheckBucket { index: 0 });
        assert_eq!(
            oram_step(updated.driver, OramEvent::Recheck(BucketRecheckObservation::Unchanged))
                .effect,
            OramEffect::Fail(OramFailure::VersionMismatch)
        );

        let create = OramRequest {
            create_mask: 1,
            ..oram_request(2)
        };
        let mut t = begin_oram(create);
        t = oram_step(t.driver, OramEvent::Route(RouteObservation::Active { epoch: 1 }));
        t = oram_step(t.driver, OramEvent::Quota(QuotaObservation::Allowed));
        let skipped = oram_step(t.driver, OramEvent::Bucket(BucketObservation::Skipped));
        assert_eq!(skipped.effect, OramEffect::Fail(OramFailure::Rekeyed));
    }

    #[test]
    fn oram_refuses_freezing_and_oversized_paths() {
        let mut t = begin_oram(oram_request(2));
        t = oram_step(t.driver, OramEvent::Route(RouteObservation::Freezing));
        assert_eq!(t.effect, OramEffect::Fail(OramFailure::RekeyInProgress));
        assert_eq!(
            begin_oram(oram_request(40)).effect,
            OramEffect::Fail(OramFailure::BucketInvalid)
        );
    }

    fn schema_request() -> SchemaRequest {
        SchemaRequest {
            authenticated: true,
            device_scope: true,
        }
    }

    #[test]
    fn schema_writes_once_and_refuses_web_sessions() {
        let t = begin_schema(schema_request());
        assert_eq!(t.effect, SchemaEffect::WriteFloor);
        let t = schema_step(t.driver, SchemaEvent::Write(SchemaWriteObservation::Written));
        assert_eq!(t.effect, SchemaEffect::Complete);
        assert!(t.driver.written && t.driver.responded);
        let web = SchemaRequest {
            device_scope: false,
            ..schema_request()
        };
        assert_eq!(
            begin_schema(web).effect,
            SchemaEffect::Fail(SchemaFailure::WebSessionForbidden)
        );
        for event in [SchemaEvent::Write(SchemaWriteObservation::Written)] {
            assert_eq!(schema_step(begin_schema(web).driver, event).effect, SchemaEffect::Idle);
        }
    }

    fn ack_request() -> CapsuleAckRequest {
        CapsuleAckRequest {
            authenticated: true,
            device_scope: true,
        }
    }

    #[test]
    fn capsule_ack_clears_and_accepts_a_replay() {
        let t = begin_capsule_ack(ack_request());
        assert_eq!(t.effect, CapsuleAckEffect::Acknowledge);
        let t = capsule_ack_step(t.driver, CapsuleAckEvent::Ack(AckObservation::Cleared));
        assert_eq!(t.effect, CapsuleAckEffect::Complete);
        assert!(t.driver.cleared && t.driver.responded);

        let mut t = begin_capsule_ack(ack_request());
        t = capsule_ack_step(t.driver, CapsuleAckEvent::Ack(AckObservation::Missed));
        assert_eq!(t.effect, CapsuleAckEffect::InspectPending);
        let t = capsule_ack_step(t.driver, CapsuleAckEvent::Pending(PendingObservation::Replay));
        assert_eq!(t.effect, CapsuleAckEffect::Complete);
        assert!(t.driver.responded);
    }

    #[test]
    fn capsule_ack_refuses_a_different_pending_epoch_and_missing_device() {
        for (observation, failure) in [
            (PendingObservation::Pending, CapsuleAckFailure::DifferentPending),
            (PendingObservation::Missing, CapsuleAckFailure::NoLongerEligible),
            (PendingObservation::Storage, CapsuleAckFailure::PendingStorage),
        ] {
            let mut t = begin_capsule_ack(ack_request());
            t = capsule_ack_step(t.driver, CapsuleAckEvent::Ack(AckObservation::Missed));
            assert_eq!(
                capsule_ack_step(t.driver, CapsuleAckEvent::Pending(observation)).effect,
                CapsuleAckEffect::Fail(failure)
            );
        }
        let web = CapsuleAckRequest {
            device_scope: false,
            ..ack_request()
        };
        assert_eq!(
            begin_capsule_ack(web).effect,
            CapsuleAckEffect::Fail(CapsuleAckFailure::WebSessionForbidden)
        );
    }

    #[test]
    fn rekey_capable_attests_once_and_refuses_missing_devices() {
        let request = RekeyCapableRequest {
            authenticated: true,
            device_scope: true,
        };
        let t = begin_rekey_capable(request);
        assert_eq!(t.effect, RekeyCapableEffect::Attest);
        let t = rekey_capable_step(t.driver, RekeyCapableEvent::Attest(AttestObservation::Attested));
        assert_eq!(t.effect, RekeyCapableEffect::Complete);
        assert!(t.driver.attested && t.driver.responded);

        let t = begin_rekey_capable(request);
        assert_eq!(
            rekey_capable_step(t.driver, RekeyCapableEvent::Attest(AttestObservation::Missing)).effect,
            RekeyCapableEffect::Fail(RekeyCapableFailure::NotFound)
        );
        let web = RekeyCapableRequest {
            device_scope: false,
            ..request
        };
        assert_eq!(
            begin_rekey_capable(web).effect,
            RekeyCapableEffect::Fail(RekeyCapableFailure::WebSessionForbidden)
        );
    }

    const BOOLS: [bool; 2] = [false, true];

    /// Regression for the unprovable `chunk_delete_step` postcondition: every
    /// state the soundness predicate accepts (not only the reachable ones)
    /// must stay sound under every event. The predicate used to accept a
    /// pre-verdict stage that had already answered or deleted, from which a
    /// refusal produced a state both answered and failed.
    #[test]
    fn chunk_delete_every_sound_state_stays_sound() {
        let stages = [
            ChunkDeleteStage::Schema,
            ChunkDeleteStage::Epoch,
            ChunkDeleteStage::Version,
            ChunkDeleteStage::Delete,
            ChunkDeleteStage::Publish,
            ChunkDeleteStage::Done,
        ];
        let mut checked = 0;
        for stage in stages {
            for authenticated in BOOLS {
                for web in BOOLS {
                    for web_epoch in [None, Some(1), Some(4)] {
                        for epoch in [0, 1, 4] {
                            for permit_epoch in [0, 1, 4] {
                                for current_version in [-1, 0, 3] {
                                    for flags in 0..16u8 {
                                        let d = ChunkDeleteDriver {
                                            stage,
                                            authenticated,
                                            web,
                                            web_epoch,
                                            if_match: 3,
                                            epoch,
                                            permit_epoch,
                                            current_version,
                                            deleted: flags & 1 != 0,
                                            published: flags & 2 != 0,
                                            responded: flags & 4 != 0,
                                            failed: flags & 8 != 0,
                                        };
                                        if !chunk_delete_state_is_sound(d) {
                                            continue;
                                        }
                                        checked += 1;
                                        for event in chunk_events() {
                                            let t = chunk_delete_step(d, event);
                                            assert!(
                                                chunk_delete_state_is_sound(t.driver),
                                                "{d:?} {event:?} -> {t:?}"
                                            );
                                            assert!(
                                                chunk_delete_effect_is_sound(t.driver, t.effect),
                                                "{d:?} {event:?} -> {t:?}"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn oram_every_sound_state_stays_sound() {
        let stages = [
            OramStage::Epoch,
            OramStage::Quota,
            OramStage::Bucket,
            OramStage::Recheck,
            OramStage::Publish,
            OramStage::Done,
        ];
        let mut checked = 0;
        for stage in stages {
            for bucket_count in [-1, 0, 1, 2, 33, 34] {
                for written in [-1, 0, 1, 2, 33] {
                    for recheck_index in [-1, 0, 1, 33] {
                        for epoch in [0, 1] {
                            for permit_epoch in [0, 1] {
                                for create_mask in [0u64, 1, u64::MAX] {
                                    for flags in 0..32u8 {
                                        let d = OramDriver {
                                            stage,
                                            authenticated: flags & 16 != 0,
                                            web: false,
                                            web_epoch: None,
                                            bucket_count,
                                            create_mask,
                                            written,
                                            recheck_index,
                                            epoch,
                                            permit_epoch,
                                            quota_allowed: flags & 1 != 0,
                                            published: flags & 2 != 0,
                                            responded: flags & 4 != 0,
                                            failed: flags & 8 != 0,
                                        };
                                        if !oram_state_is_sound(d) {
                                            continue;
                                        }
                                        checked += 1;
                                        for event in oram_events() {
                                            let t = oram_step(d, event);
                                            assert!(
                                                oram_state_is_sound(t.driver),
                                                "{d:?} {event:?} -> {t:?}"
                                            );
                                            assert!(
                                                oram_effect_is_sound(t.driver, t.effect),
                                                "{d:?} {event:?} -> {t:?}"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn small_drivers_every_sound_state_stays_sound() {
        for stage in [SchemaStage::Write, SchemaStage::Done] {
            for flags in 0..32u8 {
                let d = SchemaDriver {
                    stage,
                    authenticated: flags & 1 != 0,
                    device_scope: flags & 2 != 0,
                    written: flags & 4 != 0,
                    responded: flags & 8 != 0,
                    failed: flags & 16 != 0,
                };
                if !schema_state_is_sound(d) {
                    continue;
                }
                for observation in [SchemaWriteObservation::Written, SchemaWriteObservation::Storage]
                {
                    let t = schema_step(d, SchemaEvent::Write(observation));
                    assert!(schema_state_is_sound(t.driver), "{d:?}");
                    assert!(schema_effect_is_sound(t.driver, t.effect), "{d:?}");
                }
            }
        }
        for stage in [CapsuleAckStage::Ack, CapsuleAckStage::Pending, CapsuleAckStage::Done] {
            for flags in 0..32u8 {
                let d = CapsuleAckDriver {
                    stage,
                    authenticated: flags & 1 != 0,
                    device_scope: flags & 2 != 0,
                    cleared: flags & 4 != 0,
                    responded: flags & 8 != 0,
                    failed: flags & 16 != 0,
                };
                if !capsule_ack_state_is_sound(d) {
                    continue;
                }
                let events = [
                    CapsuleAckEvent::Ack(AckObservation::Cleared),
                    CapsuleAckEvent::Ack(AckObservation::Missed),
                    CapsuleAckEvent::Ack(AckObservation::Storage),
                    CapsuleAckEvent::Pending(PendingObservation::Replay),
                    CapsuleAckEvent::Pending(PendingObservation::Pending),
                    CapsuleAckEvent::Pending(PendingObservation::Missing),
                    CapsuleAckEvent::Pending(PendingObservation::Storage),
                ];
                for event in events {
                    let t = capsule_ack_step(d, event);
                    assert!(capsule_ack_state_is_sound(t.driver), "{d:?} {event:?}");
                    assert!(capsule_ack_effect_is_sound(t.driver, t.effect), "{d:?} {event:?}");
                }
            }
        }
        for stage in [RekeyCapableStage::Attest, RekeyCapableStage::Done] {
            for flags in 0..32u8 {
                let d = RekeyCapableDriver {
                    stage,
                    authenticated: flags & 1 != 0,
                    device_scope: flags & 2 != 0,
                    attested: flags & 4 != 0,
                    responded: flags & 8 != 0,
                    failed: flags & 16 != 0,
                };
                if !rekey_capable_state_is_sound(d) {
                    continue;
                }
                for observation in [
                    AttestObservation::Attested,
                    AttestObservation::Missing,
                    AttestObservation::Storage,
                ] {
                    let t = rekey_capable_step(d, RekeyCapableEvent::Attest(observation));
                    assert!(rekey_capable_state_is_sound(t.driver), "{d:?}");
                    assert!(rekey_capable_effect_is_sound(t.driver, t.effect), "{d:?}");
                }
            }
        }
    }

    /// Regression: a non-positive bucket count used to start the ORAM driver,
    /// which then asked for bucket 0 on every turn and never reached a verdict.
    #[test]
    fn oram_refuses_a_non_positive_bucket_count() {
        for buckets in [0, -1, i64::MIN] {
            let t = begin_oram(oram_request(buckets));
            assert_eq!(t.effect, OramEffect::Fail(OramFailure::BucketInvalid));
            assert!(oram_state_is_sound(t.driver));
        }
    }

    #[test]
    fn route_observations_agree_with_the_phase_and_epoch_rules() {
        assert!(route_is_active(RouteObservation::Active { epoch: 1 }));
        assert!(!route_is_active(RouteObservation::Active { epoch: 0 }));
        assert!(!route_is_active(RouteObservation::Freezing));
        assert_eq!(
            route_phase(RouteObservation::Active { epoch: 2 }),
            Some(Phase::Active)
        );
        assert_eq!(
            route_phase(RouteObservation::Freezing),
            Some(Phase::Freezing)
        );
        assert_eq!(route_phase(RouteObservation::Rejected), None);
        // The extracted resolver's decisions on a well-formed state never
        // disagree with the observation.
        let state = RekeyState {
            epoch: 2,
            phase: Phase::Active,
        };
        assert!(matches!(
            crate::resolve_write_epoch(state, Some(2)),
            WriteDecision::Accept(_)
        ));
        assert!(matches!(
            crate::resolve_write_epoch(
                RekeyState {
                    epoch: 2,
                    phase: Phase::Freezing
                },
                Some(3)
            ),
            WriteDecision::Accept(_)
        ));
    }
}
