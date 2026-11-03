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
use sql::{
    cursor_row_view, device_row_view, ek_row_view, link_row_view, run_handler_read,
    run_handler_write, run_read, run_writes, PoolSql, ShareSql, TxSql,
};
use vela_share_policy::store::{self, AdmissionStage, DeviceVerdicts, HandlerOutcome, ReadOutcome};
use vela_share_policy::driver::{
    CleanupObservation, EkDeviceObservation, EkRegistrationStartObservation, InboxDeletePermit,
    LinkUpdatePermit, LinkUpdateStartObservation, RowsObservation, SendInsertPermit,
    SendRequestObservation, SendResultObservation, ShareEffect, ShareFailure,
};
use vela_share_policy::{EkRegistrationPermit, LinkMutationObservation};

use crate::{
    db,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    sqldb::TursoDb,
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
/// The linked-items listing's page size, the number its SQL has always used.
const LINKED_ITEMS_LIMIT: usize = 1000;

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

/// The I/O behind one capsule send: the recipient probe, the short-circuited
/// admission reads (the driver asks for them only after the request-side
/// capsule check) and the one guarded transaction. The driver owns the order;
/// a rejected capsule never reaches this executor.
struct SendIo<'a, S = TxSql> {
    sqldb: &'a TursoDb,
    recipient_user_id: Uuid,
    sender_user_id: Uuid,
    capsule_bytes: Vec<u8>,
    inbox_id: Uuid,
    now: String,
    decode_failed: bool,
    tx: Option<S>,
    /// The transaction the admission step opened, adopted by the insert.
    pending_tx: Option<TxSql>,
    admission_error: Option<String>,
    insert_error: Option<String>,
    commit_error: Option<String>,
}

impl<'a, S: ShareSql> ShareExecutor for SendIo<'a, S> {
    async fn admit_send(&mut self) -> vela_share_policy::driver::SendAdmissionObservation {
        use vela_share_policy::driver::SendAdmissionObservation;

        let probe_stmt = store::plan_recipient_probe(self.recipient_user_id.to_string());
        let probe = match run_handler_read(&mut PoolSql(self.sqldb), &probe_stmt).await {
            Ok(rows) => store::classify_recipient_probe(&ReadOutcome::Row(ek_row_view(&rows))),
            Err(error) => {
                self.admission_error = Some(error.to_string());
                return SendAdmissionObservation {
                    failed: true,
                    recipient_can_receive: false,
                    inbox_count: 0,
                    pair_bytes: 0,
                    total_bytes: 0,
                    quota_read: false,
                };
            }
        };
        if probe.failed {
            self.admission_error = Some("share recipient probe failed".into());
            return SendAdmissionObservation {
                failed: true,
                recipient_can_receive: false,
                inbox_count: 0,
                pair_bytes: 0,
                total_bytes: 0,
                quota_read: false,
            };
        }
        // The historical handler decided recipient availability before it
        // decoded the body; keep that precedence even though the size gate
        // now runs first for a well-formed body.
        if !probe.can_receive || self.decode_failed {
            return SendAdmissionObservation {
                failed: false,
                recipient_can_receive: probe.can_receive,
                inbox_count: 0,
                pair_bytes: 0,
                total_bytes: 0,
                quota_read: false,
            };
        }
        let (admission, opened, error) =
            run_send_admission(self.sqldb, self.recipient_user_id, self.sender_user_id).await;
        self.pending_tx = opened;
        if let Some(error) = error {
            self.admission_error = Some(error);
            return SendAdmissionObservation {
                failed: true,
                recipient_can_receive: true,
                inbox_count: admission.inbox_count,
                pair_bytes: admission.pair_bytes,
                total_bytes: admission.total_bytes,
                quota_read: false,
            };
        }
        SendAdmissionObservation {
            failed: false,
            recipient_can_receive: true,
            inbox_count: admission.inbox_count,
            pair_bytes: admission.pair_bytes,
            total_bytes: admission.total_bytes,
            quota_read: admission.stage == AdmissionStage::Ready,
        }
    }

    async fn insert_capsule(&mut self, _permit: SendInsertPermit) -> SendResultObservation {
        let Some(mut tx) = self
            .tx
            .take()
            .or_else(|| self.pending_tx.take().and_then(S::adopt_tx))
        else {
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

/// Test-only instrumentation for the regression tests: how many send
/// admissions opened a transaction and how many byte sums ran.
#[cfg(test)]
static SEND_ADMISSION_BEGINS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static SEND_ADMISSION_BYTE_READS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Runs the send admission plan — the transaction begin, the item count and,
/// only when the item quota passed, the two byte sums — on the transaction it
/// opens, and classifies the per-statement outcomes. The caller keeps the open
/// transaction for the inserts on `Ready`; an item-limit stop drops it.
async fn run_send_admission(
    db: &TursoDb,
    recipient: Uuid,
    sender: Uuid,
) -> (
    store::AdmissionObservation,
    Option<TxSql>,
    Option<String>,
) {
    let mut outcomes = Vec::new();
    let mut tx: Option<TxSql> = None;
    let mut error: Option<String> = None;
    for stmt in &store::plan_send_admission(recipient.to_string(), sender.to_string()) {
        if let store::HandlerStmt::Begin = stmt {
            match db.tx().await {
                Ok(guard) => {
                    #[cfg(test)]
                    SEND_ADMISSION_BEGINS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tx = Some(TxSql(Some(guard)));
                    outcomes.push(HandlerOutcome::Ran);
                }
                Err(e) => {
                    outcomes.push(HandlerOutcome::Failed);
                    error = Some(e.to_string());
                    break;
                }
            }
            continue;
        }
        if matches!(
            stmt,
            store::HandlerStmt::SumPairBytes { .. } | store::HandlerStmt::SumRecipientBytes { .. }
        ) {
            #[cfg(test)]
            SEND_ADMISSION_BYTE_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let read = match tx.as_mut() {
            Some(sql) => run_handler_read(sql, stmt).await,
            None => Err(anyhow::anyhow!("quota read without an open transaction")),
        };
        match read {
            Ok(rows) => {
                let number = rows.first().and_then(|row| row.i64(0));
                outcomes.push(HandlerOutcome::Number(number));
                // The item quota is the first decision: when it already
                // fails, the two byte sums are not run.
                if matches!(stmt, store::HandlerStmt::CountInbox { .. })
                    && number.unwrap_or(0) >= MAX_INBOX_ITEMS_PER_USER
                {
                    break;
                }
            }
            Err(e) => {
                outcomes.push(HandlerOutcome::Failed);
                error = Some(e.to_string());
                break;
            }
        }
    }
    let admission = store::classify_send_admission(&outcomes);
    match admission.stage {
        AdmissionStage::Ready => (admission, tx, None),
        AdmissionStage::ItemLimit => {
            // Roll the count-only transaction back; nothing is published.
            drop(tx);
            (admission, None, None)
        }
        _ => (
            admission,
            None,
            Some(error.unwrap_or_else(|| "share send storage failure".into())),
        ),
    }
}

pub async fn post_send(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<SendRequest>,
) -> Result<(HeaderMap, Json<SendResponse>)> {
    crate::rate_limit::share_send_by_sender(&state.store, &session.user_id.to_string())?;

    // Decode the body first: the driver's request-side gate needs its length.
    // The empty/oversized check then runs before the recipient probe, the
    // transaction begin and the quota reads, exactly as the historical handler
    // did. A malformed body keeps its historical precedence: the driver carries
    // the decode failure past the recipient gate.
    let decoded = B64.decode(&body.capsule).ok();
    let decode_failed = decoded.is_none();
    let capsule_bytes = decoded.unwrap_or_default();
    let capsule_len = capsule_bytes.len();

    let inbox_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();

    // Verified send gate (M19). The request observation decides the capsule
    // size first; only an admitted body asks the handler for the recipient
    // probe and the short-circuited admission reads. The driver owns the whole
    // post-validation admission order and calls the real `send_facts` /
    // `plan_send` policy.
    let start = vela_share_policy::interpreter::start_send(SendRequestObservation {
        session_user_id_present: !session.user_id.is_nil(),
        decode_failed,
        capsule_len: capsule_len as i64,
    });
    let mut io: SendIo<'_, TxSql> = SendIo {
        sqldb: &state.sqldb,
        recipient_user_id: body.recipient_user_id,
        sender_user_id: session.user_id,
        capsule_bytes,
        inbox_id,
        now,
        decode_failed,
        tx: None,
        pending_tx: None,
        admission_error: None,
        insert_error: None,
        commit_error: None,
    };
    let transition = vela_share_policy::share_interpreter!(io, start, await);

    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(ShareFailure::SendStorage) => {
            return Err(AppError::Internal(
                io.admission_error
                    .take()
                    .or_else(|| io.insert_error.take())
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
        let cursor_stmt =
            store::plan_inbox_cursor(before_id.to_string(), session.user_id.to_string());
        let cursor = match run_handler_read(&mut PoolSql(&state.sqldb), &cursor_stmt).await {
            Ok(rows) => store::classify_inbox_cursor(&ReadOutcome::Row(cursor_row_view(&rows))),
            Err(error) => return Err(AppError::Internal(error.to_string())),
        };
        if cursor.absent {
            return Err(AppError::NotFound("cursor inbox_id not found".into()));
        }
        let stored = cursor
            .created_at
            .ok_or_else(|| AppError::Internal("expected timestamp".into()))?;
        // Keep the historical value: the stored cell parsed and re-rendered.
        let cursor_ts = DateTime::parse_from_rfc3339(&stored)
            .map_err(|_| AppError::Internal("expected timestamp".into()))?
            .with_timezone(&Utc)
            .to_rfc3339();

        let page_stmt = store::plan_inbox_page(
            session.user_id.to_string(),
            Some(cursor_ts),
            fetch_limit as usize,
        );
        match run_handler_read(&mut PoolSql(&state.sqldb), &page_stmt).await {
            Ok(rows) => rows,
            Err(error) => return Err(AppError::Internal(error.to_string())),
        }
    } else {
        let page_stmt =
            store::plan_inbox_page(session.user_id.to_string(), None, fetch_limit as usize);
        match run_handler_read(&mut PoolSql(&state.sqldb), &page_stmt).await {
            Ok(rows) => rows,
            Err(error) => return Err(AppError::Internal(error.to_string())),
        }
    };

    let page = store::classify_listing(rows.len(), false, limit as usize);

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

    let has_more = page.has_more;
    all_items.truncate(page.keep);

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
    let stmt = store::plan_linked_items(session.user_id.to_string(), LINKED_ITEMS_LIMIT);
    let rows = match run_handler_read(&mut PoolSql(&state.sqldb), &stmt).await {
        Ok(rows) => rows,
        Err(error) => return Err(AppError::Internal(error.to_string())),
    };
    let page = store::classify_listing(rows.len(), false, LINKED_ITEMS_LIMIT);

    let mut items = Vec::new();
    for row in &rows[..page.keep] {
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
    let stmt = store::plan_recipient_ek(user_id.to_string());
    let outcome = match run_handler_read(&mut PoolSql(&state.sqldb), &stmt).await {
        Ok(rows) => ReadOutcome::Row(ek_row_view(&rows)),
        Err(error) => return Err(AppError::Internal(error.to_string())),
    };
    let ek = store::classify_recipient_ek(&outcome);

    let share_ek =
        ek.share_ek
            .ok_or_else(|| AppError::NotFound(SHARE_RECIPIENT_UNAVAILABLE.into()))?;

    let signed_at = ek.signed_at;

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

        let stmt = store::plan_expired_inbox_cleanup(cutoff.to_rfc3339());
        let outcome = match run_handler_write(&mut PoolSql(&db), &stmt).await {
            Ok(purged) => HandlerOutcome::Written(purged),
            Err(e) => {
                tracing::error!(error = %e, "inbox cleanup task failed");
                HandlerOutcome::Failed
            }
        };
        let sweep = store::classify_sweep(&[outcome]);
        if !sweep.failed && sweep.purged > 0 {
            tracing::info!(
                purged = sweep.purged,
                "inbox cleanup: expired share items removed"
            );
        }
    }
}

#[cfg(test)]
mod handler_regression_tests {
    //! Regressions for `post_send`'s restored check order: the capsule size is
    //! decided before any store effect, and a full inbox stops before the byte
    //! sums.

    use super::*;
    use crate::auth::token::TokenScope;
    use crate::sqldb::{Db as _, TursoValue};
    use crate::state::AppStateInner;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn test_state() -> AppState {
        use std::sync::atomic::AtomicU64;
        static N: AtomicU64 = AtomicU64::new(0);
        let path = format!(
            "{}/vela-share-send-regression-{}-{}.db",
            std::env::temp_dir().display(),
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        let _ = std::fs::remove_file(&path);
        let turso = Arc::new(TursoDb::open(&path, 1).await.unwrap());
        let store = crate::store::Store::open_temp().unwrap();
        let cfg = crate::config::Config::from_env().expect("default config");
        Arc::new(AppStateInner::new(turso, store, cfg).await.unwrap())
    }

    fn session(user_id: Uuid) -> AuthSession {
        AuthSession {
            user_id,
            device_id: Uuid::new_v4(),
            jti: "share-send-regression".into(),
            key_epoch: None,
            new_token: None,
            scope: TokenScope::Device,
        }
    }

    async fn seed_user(state: &AppState, user_id: Uuid, share_ek: Option<&str>) {
        state
            .sqldb
            .execute(
                "INSERT INTO users (id, created_at, share_ek) VALUES (?, ?, ?)",
                vec![
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Text(Utc::now().to_rfc3339()),
                    share_ek.map(|ek| TursoValue::Text(ek.into())).unwrap_or(TursoValue::Null),
                ],
            )
            .await
            .unwrap();
    }

    async fn send(state: AppState, sender: Uuid, recipient: Uuid, capsule: String) -> AppError {
        match post_send(
            State(state),
            session(sender),
            Json(SendRequest {
                recipient_user_id: recipient,
                capsule,
            }),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("the send must be rejected"),
        }
    }

    async fn message(error: AppError) -> (StatusCode, String) {
        use axum::response::IntoResponse;
        let response = error.into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, value["message"].as_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn oversized_and_empty_capsules_are_rejected_before_any_store_effect() {
        let _guard = lock();
        let state = test_state().await;
        let sender = Uuid::new_v4();
        let recipient = Uuid::new_v4();
        seed_user(&state, sender, None).await;
        seed_user(&state, recipient, Some("share-ek")).await;

        for (capsule, expected) in [
            (
                B64.encode(vec![0u8; MAX_CAPSULE_BYTES as usize + 1]),
                format!("capsule exceeds maximum size of {MAX_CAPSULE_BYTES} bytes"),
            ),
            (
                String::new(),
                "verified sharing policy rejected the capsule delivery".to_string(),
            ),
        ] {
            let begins = SEND_ADMISSION_BEGINS.load(Ordering::Relaxed);
            let byte_reads = SEND_ADMISSION_BYTE_READS.load(Ordering::Relaxed);
            let error = send(state.clone(), sender, recipient, capsule).await;
            let (status, message) = message(error).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(message, expected);
            assert_eq!(
                SEND_ADMISSION_BEGINS.load(Ordering::Relaxed),
                begins,
                "a rejected capsule opened a transaction"
            );
            assert_eq!(
                SEND_ADMISSION_BYTE_READS.load(Ordering::Relaxed),
                byte_reads,
                "a rejected capsule ran a quota aggregate"
            );
        }

        let inbox: i64 = state
            .sqldb
            .query("SELECT COUNT(*) FROM share_inbox", vec![])
            .await
            .unwrap()
            .first()
            .and_then(|row| row.i64(0))
            .unwrap_or(0);
        assert_eq!(inbox, 0);
    }

    #[tokio::test]
    async fn a_full_inbox_returns_the_item_limit_before_the_byte_sums() {
        let _guard = lock();
        let state = test_state().await;
        let sender = Uuid::new_v4();
        let recipient = Uuid::new_v4();
        seed_user(&state, sender, None).await;
        seed_user(&state, recipient, Some("share-ek")).await;
        for n in 0..MAX_INBOX_ITEMS_PER_USER {
            state
                .sqldb
                .execute(
                    "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at) VALUES (?, ?, ?, ?, ?)",
                    vec![
                        TursoValue::Text(format!("full-{n}")),
                        TursoValue::Text(sender.to_string()),
                        TursoValue::Text(recipient.to_string()),
                        TursoValue::Text(B64.encode(b"cc")),
                        TursoValue::Text(Utc::now().to_rfc3339()),
                    ],
                )
                .await
                .unwrap();
        }

        let begins = SEND_ADMISSION_BEGINS.load(Ordering::Relaxed);
        let byte_reads = SEND_ADMISSION_BYTE_READS.load(Ordering::Relaxed);
        let error = send(state.clone(), sender, recipient, B64.encode(b"new")).await;
        let (status, message) = message(error).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            message,
            format!("recipient inbox is full ({MAX_INBOX_ITEMS_PER_USER} items)")
        );
        assert_eq!(
            SEND_ADMISSION_BEGINS.load(Ordering::Relaxed),
            begins + 1,
            "the count must run inside one transaction"
        );
        assert_eq!(
            SEND_ADMISSION_BYTE_READS.load(Ordering::Relaxed),
            byte_reads,
            "the byte sums must not run after the item quota failed"
        );
    }
}
