use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
mod executor;
mod sql;
#[cfg(test)]
mod conformance;

use executor::ShareExecutor;
use sql::{device_row_view, link_row_view, run_read, run_writes, PoolSql, ShareSql, TxSql};
use vela_share_policy::store::{self, DeviceVerdicts, ReadOutcome};
use vela_share_policy::driver::{
    CleanupObservation, EkDeviceObservation, EkRegistrationStartObservation, InboxDeletePermit,
    LinkUpdatePermit, LinkUpdateStartObservation, RowsObservation, SendInsertPermit,
    SendRequestObservation, SendResultObservation, ShareEffect, ShareFailure,
};
use vela_share_policy::{EkRegistrationPermit, LinkMutationObservation, SendObservation};

use crate::{
    db,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    sqldb::{Db as _, TursoDb, TursoValue},
    state::AppState,
};

const MAX_CAPSULE_BYTES: i64 = vela_share_policy::MAX_CAPSULE_BYTES;
const DEFAULT_INBOX_LIMIT: i64 = 50;
const MAX_INBOX_LIMIT: i64 = 200;
/// Max pending items in one recipient's inbox, owned by the verified driver.
const MAX_INBOX_ITEMS_PER_USER: i64 = vela_share_policy::driver::MAX_INBOX_ITEMS_PER_USER;
/// Max pending bytes one sender may push to a single recipient, owned by the
/// verified driver.
const MAX_SENDER_TO_RECIPIENT_BYTES: i64 = vela_share_policy::driver::MAX_SENDER_TO_RECIPIENT_BYTES;
/// Max total pending bytes in a recipient's inbox.
const MAX_RECIPIENT_INBOX_BYTES: i64 = vela_share_policy::MAX_RECIPIENT_INBOX_BYTES;

pub const INBOX_TTL_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Deserialize)]
pub struct SendRequest {
    pub recipient_user_id: Uuid,
    pub capsule: String,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub inbox_id: Uuid,
    pub share_id: Uuid,
}

/// One message for every "this recipient can't receive a share" case.
///
/// Distinguishing "no such user" from "user has no share key" let anyone with an
/// account probe which user ids exist — the ids are UUIDs, but they travel in
/// share links and audit entries, so confirming one is worth something to an
/// attacker (audit, share-recipient enumeration).
const SHARE_RECIPIENT_UNAVAILABLE: &str = "recipient cannot receive shares";

/// Render a non-parameterized driver failure with the handler's historical
/// status and message. The send storage/conflict and EK decode branches are
/// rendered at their call sites because they carry the original error text.
fn share_failure_error(failure: ShareFailure) -> AppError {
    match failure {
        ShareFailure::RecipientUnavailable => {
            AppError::NotFound(SHARE_RECIPIENT_UNAVAILABLE.into())
        }
        ShareFailure::MalformedCapsule => {
            AppError::BadRequest("capsule is not valid base64".into())
        }
        ShareFailure::CapsuleTooLarge => AppError::BadRequest(format!(
            "capsule exceeds maximum size of {MAX_CAPSULE_BYTES} bytes"
        )),
        ShareFailure::InboxItemLimit => AppError::Conflict(format!(
            "recipient inbox is full ({MAX_INBOX_ITEMS_PER_USER} items)"
        )),
        ShareFailure::SenderQuotaExceeded => AppError::PayloadTooLarge(format!(
            "pending shares to this recipient exceed {MAX_SENDER_TO_RECIPIENT_BYTES} bytes"
        )),
        ShareFailure::RecipientQuotaExceeded => AppError::PayloadTooLarge(format!(
            "recipient inbox exceeds {MAX_RECIPIENT_INBOX_BYTES} bytes"
        )),
        ShareFailure::CapsulePolicyRejected => {
            AppError::BadRequest("verified sharing policy rejected the capsule delivery".into())
        }
        ShareFailure::LinkNotFound => AppError::NotFound("linked share not found".into()),
        ShareFailure::SendStorage => AppError::Internal("share send storage failure".into()),
        ShareFailure::SendConflict => {
            AppError::Conflict("share send raced with a concurrent request".into())
        }
        ShareFailure::InboxNotFound => AppError::NotFound("inbox item not found".into()),
        ShareFailure::UserNotFound => AppError::NotFound("user not found".into()),
        ShareFailure::ShareEkDecode => AppError::BadRequest("share_ek is not valid base64".into()),
        ShareFailure::ShareEkSize => {
            AppError::BadRequest(format!("share_ek must be exactly {SHARE_EK_LEN} bytes"))
        }
        ShareFailure::SignedAtNotCanonical => AppError::BadRequest(
            "signed_at must be a canonical RFC 3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)".into(),
        ),
        ShareFailure::SignedAtUnparseable => {
            AppError::BadRequest("signed_at must be an RFC 3339 timestamp".into())
        }
        ShareFailure::SignedAtFuture => {
            AppError::BadRequest("signed_at is too far in the future".into())
        }
        ShareFailure::DeviceNotEnrolled => {
            AppError::BadRequest("signing device is not enrolled for this account".into())
        }
        ShareFailure::StoredIdentityKey => {
            AppError::BadRequest("signing device has no identity public key".into())
        }
        ShareFailure::SignatureDecode => {
            AppError::BadRequest("signature is not valid base64".into())
        }
        ShareFailure::EkPolicyRejected => AppError::Unauthorized(
            "verified sharing policy rejected the share-key registration".into(),
        ),
    }
}

/// The I/O behind one capsule send. The quota reads and the transaction begin
/// happen before the driver starts (they are its admission observations); the
/// driver owns the admission order and the one guarded transaction.
struct SendIo<S = TxSql> {
    recipient_user_id: Uuid,
    sender_user_id: Uuid,
    capsule_bytes: Vec<u8>,
    inbox_id: Uuid,
    now: String,
    tx: Option<S>,
    insert_error: Option<String>,
    commit_error: Option<String>,
}

impl<S: ShareSql> ShareExecutor for SendIo<S> {
    async fn insert_capsule(&mut self, _permit: SendInsertPermit) -> SendResultObservation {
        let Some(mut tx) = self.tx.take() else {
            self.insert_error = Some("share send driver authorized without a transaction".into());
            return SendResultObservation::StorageFailed;
        };
        let plan = store::plan_send_insert(
            self.inbox_id.to_string(),
            self.sender_user_id.to_string(),
            self.recipient_user_id.to_string(),
            db::encode_b64(&self.capsule_bytes),
            self.now.clone(),
        );
        let (outcomes, error) = run_writes(&mut tx, &plan).await;
        let observation = store::classify_send(&outcomes);
        if let Some(error) = error {
            if observation == SendResultObservation::CommitConflict {
                self.commit_error = Some(error.to_string());
            } else {
                self.insert_error = Some(error.to_string());
            }
        }
        // An uncommitted transaction rolls back when `tx` drops here.
        observation
    }
}

pub async fn post_send(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<SendRequest>,
) -> Result<(HeaderMap, Json<SendResponse>)> {
    crate::rate_limit::share_send_by_sender(&state.store, &session.user_id.to_string())?;

    // Gate on the share key, not on mere existence (red-team RT-3).
    let recipient_rows = state
        .sqldb
        .query(
            "SELECT share_ek FROM users WHERE id = ?",
            vec![TursoValue::Text(body.recipient_user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let recipient_can_receive = recipient_rows
        .first()
        .and_then(|r| r.text(0))
        .is_some_and(|ek| !ek.is_empty());

    // Preserve the historical precedence: recipient availability is decided
    // before the body is decoded. The verified driver renders every one of
    // these admission failures with the existing status/message.
    let decoded = if recipient_can_receive {
        B64.decode(&body.capsule).ok()
    } else {
        None
    };
    let decode_failed = recipient_can_receive && decoded.is_none();
    let capsule_bytes = decoded.unwrap_or_default();
    let capsule_len = capsule_bytes.len();

    let inbox_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();

    // Quota checks and the two inserts (shared_items + share_inbox, which must
    // share the same id) run inside one transaction so a crash/error between
    // them can never leave an orphaned row in one table without the other.
    let mut tx = None;
    let (inbox_count, pair_bytes, total_bytes) = if recipient_can_receive && !decode_failed {
        let guard = state
            .sqldb
            .tx()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let count_rows = guard
            .query(
                "SELECT COUNT(*) FROM share_inbox WHERE recipient_user_id = ?",
                vec![TursoValue::Text(body.recipient_user_id.to_string())],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let inbox_count = count_rows.first().and_then(|r| r.i64(0)).unwrap_or(0);

        // Anti-flooding: cap pending bytes per (sender → recipient) pair and
        // per recipient inbox, so a single sender cannot fill the victim's
        // disk.
        let pair_rows = guard
            .query(
                "SELECT COALESCE(SUM(LENGTH(capsule)), 0) FROM share_inbox
                 WHERE recipient_user_id = ? AND sender_user_id = ?",
                vec![
                    TursoValue::Text(body.recipient_user_id.to_string()),
                    TursoValue::Text(session.user_id.to_string()),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let pair_bytes = pair_rows.first().and_then(|r| r.i64(0)).unwrap_or(0);

        let total_rows = guard
            .query(
                "SELECT COALESCE(SUM(LENGTH(capsule)), 0) FROM share_inbox
                 WHERE recipient_user_id = ?",
                vec![TursoValue::Text(body.recipient_user_id.to_string())],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let total_bytes = total_rows.first().and_then(|r| r.i64(0)).unwrap_or(0);

        tx = Some(guard);
        (inbox_count, pair_bytes, total_bytes)
    } else {
        (0, 0, 0)
    };

    // Verified send gate (M19). Every fact comes from the real session,
    // recipient row, decoded capsule and inbox quota observations; the
    // constructor states those equalities to F*. The driver owns the whole
    // post-validation admission order and calls the real `send_facts` /
    // `plan_send` policy.
    let start = vela_share_policy::interpreter::start_send(SendRequestObservation {
        policy: SendObservation {
            session_user_id_present: !session.user_id.is_nil(),
            recipient_has_share_ek: recipient_can_receive,
            capsule_len: capsule_bytes.len() as i64,
            existing_inbox_bytes: total_bytes,
        },
        decode_failed,
        inbox_count,
        pair_bytes,
    });
    let mut io = SendIo {
        recipient_user_id: body.recipient_user_id,
        sender_user_id: session.user_id,
        capsule_bytes,
        inbox_id,
        now,
        tx: tx.map(|guard| TxSql(Some(guard))),
        insert_error: None,
        commit_error: None,
    };
    let transition = vela_share_policy::share_interpreter!(io, start, await);

    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(ShareFailure::SendStorage) => {
            return Err(AppError::Internal(
                io.insert_error
                    .take()
                    .unwrap_or_else(|| "share send storage failure".into()),
            ));
        }
        ShareEffect::Fail(ShareFailure::SendConflict) => {
            return Err(AppError::Conflict(format!(
                "share send raced with a concurrent request: {}",
                io.commit_error
                    .take()
                    .unwrap_or_else(|| "unknown commit error".into())
            )));
        }
        ShareEffect::Fail(failure) => return Err(share_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "share send driver produced an unexpected completion effect".into(),
            ));
        }
    }

    tracing::info!(
        inbox_id  = %inbox_id,
        sender    = %session.user_id,
        recipient = %body.recipient_user_id,
        bytes     = capsule_len,
        "share capsule delivered"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(SendResponse {
            inbox_id,
            share_id: inbox_id,
        }),
    ))
}

#[derive(Deserialize, Default)]
pub struct InboxQuery {
    pub limit: Option<i64>,
    pub before: Option<Uuid>,
}

#[derive(Serialize)]
pub struct InboxItem {
    pub id: Uuid,
    pub sender_user_id: Uuid,
    pub capsule: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct InboxResponse {
    pub items: Vec<InboxItem>,
    pub has_more: bool,
}

/// Lists the caller's inbox. A linked share's inbox copy is skipped once the
/// share is revoked: revocation deletes that copy in a separate cleanup step,
/// and a failed or interrupted cleanup must not leave the capsule fetchable.
pub async fn get_inbox(
    State(state): State<AppState>,
    session: AuthSession,
    axum::extract::Query(query): axum::extract::Query<InboxQuery>,
) -> Result<(HeaderMap, Json<InboxResponse>)> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_INBOX_LIMIT)
        .clamp(1, MAX_INBOX_LIMIT);

    let fetch_limit = limit + 1;

    let rows = if let Some(before_id) = query.before {
        let cursor_rows = state
            .sqldb
            .query(
                "SELECT created_at FROM share_inbox
             WHERE id = ? AND recipient_user_id = ?",
                vec![
                    TursoValue::Text(before_id.to_string()),
                    TursoValue::Text(session.user_id.to_string()),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let cursor_row = cursor_rows
            .first()
            .ok_or_else(|| AppError::NotFound("cursor inbox_id not found".into()))?;
        let cursor_ts = cursor_row
            .timestamp(0)
            .ok_or_else(|| AppError::Internal("expected timestamp".into()))?;

        state
            .sqldb
            .query(
                "SELECT id, sender_user_id, capsule, created_at
             FROM share_inbox
             WHERE recipient_user_id = ?
               AND created_at < ?
               AND NOT EXISTS (SELECT 1 FROM shared_items
                               WHERE shared_items.id = share_inbox.id
                                 AND shared_items.revoked = 1)
             ORDER BY created_at DESC
             LIMIT ?",
                vec![
                    TursoValue::Text(session.user_id.to_string()),
                    TursoValue::Text(cursor_ts.to_rfc3339()),
                    TursoValue::Integer(fetch_limit),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
    } else {
        state
            .sqldb
            .query(
                "SELECT id, sender_user_id, capsule, created_at
             FROM share_inbox
             WHERE recipient_user_id = ?
               AND NOT EXISTS (SELECT 1 FROM shared_items
                               WHERE shared_items.id = share_inbox.id
                                 AND shared_items.revoked = 1)
             ORDER BY created_at DESC
             LIMIT ?",
                vec![
                    TursoValue::Text(session.user_id.to_string()),
                    TursoValue::Integer(fetch_limit),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    let mut all_items: Vec<InboxItem> = Vec::new();
    for row in &rows {
        let id = row
            .uuid(0)
            .ok_or_else(|| AppError::Internal("uuid parse".into()))?;
        let sender_user_id = row
            .uuid(1)
            .ok_or_else(|| AppError::Internal("uuid parse".into()))?;
        let capsule_b64 = row
            .text(2)
            .map(String::from)
            .ok_or_else(|| AppError::Internal("expected text".into()))?;
        let created_at = row
            .timestamp(3)
            .ok_or_else(|| AppError::Internal("expected timestamp".into()))?;

        let capsule_bytes = db::decode_b64(&capsule_b64)?;

        all_items.push(InboxItem {
            id,
            sender_user_id,
            capsule: B64.encode(&capsule_bytes),
            created_at,
        });
    }

    let has_more = all_items.len() as i64 > limit;
    all_items.truncate(limit as usize);

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(InboxResponse {
            items: all_items,
            has_more,
        }),
    ))
}

/// The I/O behind the recipient-scoped inbox delete.
struct InboxDeleteIo<S> {
    sql: S,
    id: Uuid,
    user_id: Uuid,
    error: Option<AppError>,
}

impl<S: ShareSql> ShareExecutor for InboxDeleteIo<S> {
    async fn delete_inbox_item(&mut self, permit: InboxDeletePermit) -> RowsObservation {
        debug_assert!(permit.recipient_scoped);
        let plan = store::plan_inbox_delete(self.id.to_string(), self.user_id.to_string());
        let (outcomes, error) = run_writes(&mut self.sql, &plan).await;
        if let Some(error) = error {
            self.error = Some(AppError::Internal(error.to_string()));
        }
        store::classify_rows(&outcomes)
    }
}

pub async fn delete_inbox_item(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
) -> Result<(HeaderMap, StatusCode)> {
    // The driver owns the recipient-scoped delete authority and the row
    // classification. The handler performs exactly the one guarded effect.
    let start = vela_share_policy::interpreter::start_inbox_delete();
    let mut io = InboxDeleteIo {
        sql: PoolSql(&state.sqldb),
        id,
        user_id: session.user_id,
        error: None,
    };
    let transition = vela_share_policy::share_interpreter!(io, start, await);

    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(ShareFailure::InboxNotFound) => {
            if let Some(error) = io.error.take() {
                return Err(error);
            }
            return Err(AppError::NotFound(format!("inbox item {id} not found")));
        }
        ShareEffect::Fail(failure) => return Err(share_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "inbox delete driver produced an unexpected completion effect".into(),
            ));
        }
    }

    tracing::info!(inbox_id = %id, user_id = %session.user_id, "inbox item deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}

#[derive(Serialize)]
pub struct LinkedShareItem {
    pub id: Uuid,
    pub sender_user_id: Uuid,
    pub recipient_user_id: Uuid,
    pub capsule: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct LinkedSharesResponse {
    pub items: Vec<LinkedShareItem>,
}

pub async fn get_linked_items(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<LinkedSharesResponse>)> {
    let rows = state
        .sqldb
        .query(
            "SELECT id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked
         FROM shared_items
         WHERE (sender_user_id = ? OR recipient_user_id = ?)
           AND revoked = 0
         ORDER BY updated_at DESC
         LIMIT 1000",
            vec![
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut items = Vec::new();
    for row in &rows {
        let shared = db::parse_shared_item_row_turso(row)?;
        let id = Uuid::parse_str(&shared.id)
            .map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?;
        items.push(LinkedShareItem {
            id,
            sender_user_id: shared.sender_user_id,
            recipient_user_id: shared.recipient_user_id,
            capsule: B64.encode(&shared.capsule),
            created_at: shared.created_at,
            updated_at: shared.updated_at,
            revoked: shared.revoked,
        });
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(LinkedSharesResponse { items })))
}

#[derive(Deserialize)]
pub struct UpdateLinkedShareRequest {
    pub capsule: String,
}

/// The I/O behind a linked-item update: the linked-row observation and the one
/// guarded UPDATE.
struct LinkUpdateIo<S> {
    sql: S,
    id: Uuid,
    user_id: Uuid,
    capsule_bytes: Vec<u8>,
    /// The `updated_at` instant, read when the update runs.
    clock: fn() -> String,
    error: Option<AppError>,
}

impl<S: ShareSql> ShareExecutor for LinkUpdateIo<S> {
    async fn observe_link(&mut self) -> LinkMutationObservation {
        observe_link_row(&mut self.sql, self.id, self.user_id, &mut self.error).await
    }

    async fn update_linked_item(&mut self, permit: LinkUpdatePermit) -> RowsObservation {
        debug_assert_eq!(permit.capsule_len, self.capsule_bytes.len() as i64);
        let plan = store::plan_link_update(
            self.id.to_string(),
            self.user_id.to_string(),
            db::encode_b64(&self.capsule_bytes),
            (self.clock)(),
        );
        let (outcomes, error) = run_writes(&mut self.sql, &plan).await;
        if let Some(error) = error {
            self.error = Some(AppError::Internal(error.to_string()));
        }
        store::classify_rows(&outcomes)
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

pub async fn put_linked_item(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
    Json(body): Json<UpdateLinkedShareRequest>,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let decoded = B64.decode(&body.capsule);
    let decode_failed = decoded.is_err();
    let capsule_bytes = decoded.unwrap_or_default();

    // Verified linked-item mutation gate (M21): the caller is the original
    // sender and the row is a live item, observed from the stored row. The
    // driver owns the decode/length checks, the real `plan_link_mutation`
    // decision and the affected-row classification.
    let start = vela_share_policy::interpreter::start_link_update(LinkUpdateStartObservation {
        decode_failed,
        capsule_len: capsule_bytes.len() as i64,
    });
    let mut io = LinkUpdateIo {
        sql: PoolSql(&state.sqldb),
        id,
        user_id: session.user_id,
        capsule_bytes,
        clock: now_rfc3339,
        error: None,
    };
    let transition = vela_share_policy::share_interpreter!(io, start, await);

    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(ShareFailure::LinkNotFound) => {
            if let Some(error) = io.error.take() {
                return Err(error);
            }
            return Err(AppError::NotFound(format!("linked share {id} not found")));
        }
        ShareEffect::Fail(failure) => return Err(share_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "linked update driver produced an unexpected completion effect".into(),
            ));
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "updated": true }))))
}

/// The I/O behind a linked-item revoke: the linked-row observation, the one
/// guarded UPDATE and the post-revoke inbox cleanup.
struct LinkRevokeIo<S> {
    sql: S,
    id: Uuid,
    user_id: Uuid,
    /// The `updated_at` instant, read when the revoke runs.
    clock: fn() -> String,
    error: Option<AppError>,
}

impl<S: ShareSql> ShareExecutor for LinkRevokeIo<S> {
    async fn observe_link(&mut self) -> LinkMutationObservation {
        observe_link_row(&mut self.sql, self.id, self.user_id, &mut self.error).await
    }

    async fn revoke_linked_item(&mut self) -> RowsObservation {
        let plan =
            store::plan_link_revoke(self.id.to_string(), self.user_id.to_string(), (self.clock)());
        let (outcomes, error) = run_writes(&mut self.sql, &plan).await;
        if let Some(error) = error {
            self.error = Some(AppError::Internal(error.to_string()));
        }
        store::classify_rows(&outcomes)
    }

    async fn delete_linked_inbox(&mut self) -> CleanupObservation {
        let plan = store::plan_linked_inbox_cleanup(self.id.to_string());
        let (outcomes, _error) = run_writes(&mut self.sql, &plan).await;
        store::classify_cleanup(&outcomes)
    }
}

pub async fn delete_linked_item(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    // Verified linked-item mutation gate (M21): the caller is the original
    // sender and the row is a live item, observed from the stored row. The
    // driver owns the real `plan_link_mutation` decision, the affected-row
    // classification and the post-revoke inbox cleanup.
    let start = vela_share_policy::interpreter::start_link_revoke();
    let mut io = LinkRevokeIo {
        sql: PoolSql(&state.sqldb),
        id,
        user_id: session.user_id,
        clock: now_rfc3339,
        error: None,
    };
    let transition = vela_share_policy::share_interpreter!(io, start, await);

    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(ShareFailure::LinkNotFound) => {
            if let Some(error) = io.error.take() {
                return Err(error);
            }
            return Err(AppError::NotFound(format!("linked share {id} not found")));
        }
        ShareEffect::Fail(failure) => return Err(share_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "linked revoke driver produced an unexpected completion effect".into(),
            ));
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "deleted": true }))))
}

/// Observe the linked-share row that a mutation is about to touch.
///
/// A missing row, a row owned by another sender and a revoked row all leave the
/// verified policy in the same rejecting state, so the handler keeps one
/// indistinguishable "not found" response. A failed read rejects too and
/// leaves its error for the handler to report.
async fn observe_link_row<S: ShareSql>(
    sql: &mut S,
    id: Uuid,
    user_id: Uuid,
    error: &mut Option<AppError>,
) -> LinkMutationObservation {
    let outcome = match run_read(sql, &store::plan_link_read(id.to_string())).await {
        Ok(rows) => ReadOutcome::Row(link_row_view(&rows)),
        Err(e) => {
            *error = Some(AppError::Internal(e.to_string()));
            ReadOutcome::Failed
        }
    };
    store::classify_link(&user_id.to_string(), &outcome)
}

/// Return the share encapsulation key registered by a given user.
///
/// Used by senders to encrypt a share capsule for a specific recipient before
/// calling `POST /share/send`.
pub async fn get_recipient_ek(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let rows = state
        .sqldb
        .query(
            "SELECT share_ek, share_ek_since FROM users WHERE id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let share_ek = rows
        .first()
        .and_then(|r| r.text(0))
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or_else(|| AppError::NotFound(SHARE_RECIPIENT_UNAVAILABLE.into()))?;

    let signed_at = rows.first().and_then(|r| r.text(1));

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(serde_json::json!({
            "share_ek": share_ek,
            // M19: binding instant, so senders can pin and detect later
            // substitutions between fetch and seal.
            "signed_at": signed_at,
        })),
    ))
}

/// ML-KEM-1024 EK (1568) + X25519 PK (32). Shared with the verified policy.
const SHARE_EK_LEN: usize = vela_share_policy::SHARE_EK_LEN;

#[derive(Deserialize)]
pub struct PutShareEkRequest {
    pub share_ek: String,
    /// The enrolled device whose hybrid identity key made `signature`.
    pub device_id: Uuid,
    /// RFC 3339 instant covered by the binding signature. Registrations are
    /// monotonic: a signature older than the currently registered binding is
    /// a replay and is rejected.
    pub signed_at: String,
    /// Hybrid identity signature over
    /// `vela_crypto::signing::share_ek_binding_message(share_ek, signed_at)`.
    pub signature: String,
}

/// The I/O behind a share-EK registration: the signing-device row read and the
/// one guarded `users` update.
struct ShareEkIo<S> {
    sql: S,
    user_id: Uuid,
    device_id: Uuid,
    share_ek: String,
    signature: String,
    ek_bytes: Vec<u8>,
    canonical_signed_at: String,
    error: Option<AppError>,
    stored_vk_error: Option<AppError>,
    signature_decode_error: Option<AppError>,
}

impl<S: ShareSql> ShareExecutor for ShareEkIo<S> {
    async fn observe_device(&mut self) -> EkDeviceObservation {
        use crate::device::enroll::verify_hybrid_signature;

        let caller = self.user_id.to_string();
        let read = store::plan_device_read(self.device_id.to_string(), caller.clone());
        let row = match run_read(&mut self.sql, &read).await {
            Ok(rows) => device_row_view(&rows),
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                let unread = DeviceVerdicts {
                    signature_verified: false,
                    stored_vk_decode_failed: false,
                    signature_decode_failed: false,
                    signed_at_is_fresher: false,
                };
                return store::classify_device(
                    &caller,
                    self.ek_bytes.len(),
                    &ReadOutcome::Failed,
                    unread,
                );
            }
        };
        let current_since = row.as_ref().and_then(|r| r.share_ek_since.clone());
        let hybrid_vk = row.as_ref().and_then(|r| r.hybrid_vk.clone());

        let message =
            vela_crypto::signing::share_ek_binding_message(&self.ek_bytes, &self.canonical_signed_at);
        // Retain the original decode errors so the rejecting branch can
        // reproduce them in the same order, after the verified policy has seen
        // the real observations.
        let (stored_vk, stored_vk_error) = match hybrid_vk.as_deref() {
            Some(vk) => match crate::db::decode_b64(vk) {
                Ok(vk) => (Some(vk), None),
                Err(error) => (None, Some(error)),
            },
            None => (
                None,
                Some(AppError::BadRequest(
                    "signing device has no identity public key".into(),
                )),
            ),
        };
        let (signature_bytes, signature_decode_error) = match B64.decode(&self.signature) {
            Ok(signature) => (Some(signature), None),
            Err(_) => (
                None,
                Some(AppError::BadRequest(
                    "signature is not valid base64".into(),
                )),
            ),
        };
        let signature_verified = match (&stored_vk, &signature_bytes) {
            (Some(vk), Some(signature)) => verify_hybrid_signature(
                vk.as_slice(),
                &message,
                signature.as_slice(),
                "share-key binding signature invalid",
            )
            .is_ok(),
            _ => false,
        };

        // M25: the freshness relation lives in the verified policy layer. The
        // observation records that bytewise comparison unchanged.
        let signed_at_is_fresher = vela_share_policy::timestamp_is_fresher(
            self.canonical_signed_at.as_bytes(),
            current_since.as_deref().map(|c| c.as_bytes()),
        );
        let verdicts = DeviceVerdicts {
            signature_verified,
            stored_vk_decode_failed: stored_vk_error.is_some(),
            signature_decode_failed: signature_decode_error.is_some(),
            signed_at_is_fresher,
        };
        self.stored_vk_error = stored_vk_error;
        self.signature_decode_error = signature_decode_error;

        store::classify_device(&caller, self.ek_bytes.len(), &ReadOutcome::Row(row), verdicts)
    }

    async fn update_share_ek(&mut self, permit: EkRegistrationPermit) -> RowsObservation {
        if !permit.binds_device_signature() {
            self.error = Some(AppError::Internal(
                "share-key driver authorized without a device signature".into(),
            ));
            return RowsObservation { rows: 0 };
        }
        let plan = store::plan_share_ek_update(
            self.user_id.to_string(),
            self.share_ek.clone(),
            self.canonical_signed_at.clone(),
            self.device_id.to_string(),
        );
        let (outcomes, error) = run_writes(&mut self.sql, &plan).await;
        if let Some(error) = error {
            self.error = Some(AppError::Internal(error.to_string()));
        }
        store::classify_rows(&outcomes)
    }
}

/// Register (or update) the authenticated user's own share encapsulation key.
///
/// M19: the registration must be signed by one of the caller's enrolled
/// devices (`vela share-ek binding v1`), so substituting someone's sharing
/// key requires their device's private identity key — not merely database
/// write access or a stolen session token. Replay of an older binding fails
/// the monotonic timestamp check.
pub async fn put_my_ek(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<PutShareEkRequest>,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let ek_decoded = B64.decode(&body.share_ek);
    let ek_decode_failed = ek_decoded.is_err();
    let ek_bytes = ek_decoded.unwrap_or_default();

    // M-signed_at canonicalization (audit fix): the raw string previously went
    // into a lexicographic freshness compare and the stored `share_ek_since`,
    // so an offset form like `2026-01-01T01:00:00+01:00` could wind back the
    // monotonic clock. Require canonical UTC (`...:SSZ`, second precision) and
    // reject excessive future skew; store/pass only the verified canonical
    // instant. The driver owns the precedence of these checks.
    let signed_at_not_canonical =
        !body.signed_at.ends_with('Z') || body.signed_at.len() != 20;
    let parsed_signed_at = if signed_at_not_canonical {
        None
    } else {
        chrono::DateTime::parse_from_rfc3339(&body.signed_at).ok()
    };
    let signed_at_unparseable = !signed_at_not_canonical && parsed_signed_at.is_none();
    const MAX_FUTURE_SKEW_SECS: i64 = 300;
    let signed_at_future = parsed_signed_at
        .map(|parsed| parsed.timestamp() - chrono::Utc::now().timestamp() > MAX_FUTURE_SKEW_SECS)
        .unwrap_or(false);
    let canonical_signed_at = body.signed_at.clone();

    let start = vela_share_policy::interpreter::start_ek_registration(
        EkRegistrationStartObservation {
            ek_decode_failed,
            ek_len: ek_bytes.len(),
            signed_at_not_canonical,
            signed_at_unparseable,
            signed_at_future,
        },
    );
    let mut io = ShareEkIo {
        sql: PoolSql(&state.sqldb),
        user_id: session.user_id,
        device_id: body.device_id,
        share_ek: body.share_ek.clone(),
        signature: body.signature.clone(),
        ek_bytes,
        canonical_signed_at,
        error: None,
        stored_vk_error: None,
        signature_decode_error: None,
    };
    let transition = vela_share_policy::share_interpreter!(io, start, await);

    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(ShareFailure::DeviceNotEnrolled) => {
            if let Some(error) = io.error.take() {
                return Err(error);
            }
            return Err(AppError::BadRequest(
                "signing device is not enrolled for this account".into(),
            ));
        }
        ShareEffect::Fail(ShareFailure::StoredIdentityKey) => {
            return Err(io.stored_vk_error.take().unwrap_or_else(|| {
                AppError::BadRequest("signing device has no identity public key".into())
            }));
        }
        ShareEffect::Fail(ShareFailure::SignatureDecode) => {
            return Err(io
                .signature_decode_error
                .take()
                .unwrap_or_else(|| AppError::BadRequest("signature is not valid base64".into())));
        }
        ShareEffect::Fail(ShareFailure::UserNotFound) => {
            if let Some(error) = io.error.take() {
                return Err(error);
            }
            return Err(AppError::NotFound("user not found".into()));
        }
        ShareEffect::Fail(failure) => return Err(share_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "share-key driver produced an unexpected completion effect".into(),
            ));
        }
    }

    tracing::info!(user_id = %session.user_id, "share key registered (device-signed binding)");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "updated": true }))))
}

pub async fn inbox_cleanup_task(db: Arc<TursoDb>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 60 * 60));

    loop {
        interval.tick().await;

        let cutoff = Utc::now() - chrono::Duration::seconds(INBOX_TTL_SECS);

        match db
            .execute(
                "DELETE FROM share_inbox WHERE created_at < ?",
                vec![TursoValue::Text(cutoff.to_rfc3339())],
            )
            .await
        {
            Ok(n) => {
                if n > 0 {
                    tracing::info!(purged = n, "inbox cleanup: expired share items removed");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "inbox cleanup task failed");
            }
        }
    }
}
