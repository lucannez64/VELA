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

use crate::{
    db,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    sqldb::{Db as _, TursoDb, TursoValue},
    state::AppState,
};

const MAX_CAPSULE_BYTES: usize = 1024 * 1024;
const DEFAULT_INBOX_LIMIT: i64 = 50;
const MAX_INBOX_LIMIT: i64 = 200;
const MAX_INBOX_ITEMS_PER_USER: i64 = 500;
/// Max pending bytes one sender may push to a single recipient.
const MAX_SENDER_TO_RECIPIENT_BYTES: i64 = 8 * 1024 * 1024;
/// Max total pending bytes in a recipient's inbox.
const MAX_RECIPIENT_INBOX_BYTES: i64 = 32 * 1024 * 1024;

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
    if !recipient_can_receive {
        return Err(AppError::NotFound(SHARE_RECIPIENT_UNAVAILABLE.into()));
    }

    let capsule_bytes = B64
        .decode(&body.capsule)
        .map_err(|_| AppError::BadRequest("capsule is not valid base64".into()))?;

    if capsule_bytes.len() > MAX_CAPSULE_BYTES {
        return Err(AppError::BadRequest(format!(
            "capsule exceeds maximum size of {MAX_CAPSULE_BYTES} bytes"
        )));
    }

    let inbox_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();

    // Quota checks and the two inserts (shared_items + share_inbox, which must
    // share the same id) run inside one transaction so a crash/error between
    // them can never leave an orphaned row in one table without the other.
    let tx = state
        .sqldb
        .tx()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let count_rows = tx
        .query(
            "SELECT COUNT(*) FROM share_inbox WHERE recipient_user_id = ?",
            vec![TursoValue::Text(body.recipient_user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let inbox_count = count_rows.first().and_then(|r| r.i64(0)).unwrap_or(0);
    if inbox_count >= MAX_INBOX_ITEMS_PER_USER {
        return Err(AppError::Conflict(format!(
            "recipient inbox is full ({MAX_INBOX_ITEMS_PER_USER} items)"
        )));
    }

    // Anti-flooding: cap pending bytes per (sender → recipient) pair and per
    // recipient inbox, so a single sender cannot fill the victim's disk.
    let pair_rows = tx
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
    if pair_bytes + capsule_bytes.len() as i64 > MAX_SENDER_TO_RECIPIENT_BYTES {
        return Err(AppError::PayloadTooLarge(format!(
            "pending shares to this recipient exceed {MAX_SENDER_TO_RECIPIENT_BYTES} bytes"
        )));
    }

    let total_rows = tx
        .query(
            "SELECT COALESCE(SUM(LENGTH(capsule)), 0) FROM share_inbox
             WHERE recipient_user_id = ?",
            vec![TursoValue::Text(body.recipient_user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let total_bytes = total_rows.first().and_then(|r| r.i64(0)).unwrap_or(0);
    if total_bytes + capsule_bytes.len() as i64 > MAX_RECIPIENT_INBOX_BYTES {
        return Err(AppError::PayloadTooLarge(format!(
            "recipient inbox exceeds {MAX_RECIPIENT_INBOX_BYTES} bytes"
        )));
    }

    tx.execute(
        "INSERT INTO shared_items (id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked)
         VALUES (?, ?, ?, ?, ?, ?, 0)",
        vec![
            TursoValue::Text(inbox_id.to_string()),
            TursoValue::Text(session.user_id.to_string()),
            TursoValue::Text(body.recipient_user_id.to_string()),
            TursoValue::Text(db::encode_b64(&capsule_bytes)),
            TursoValue::Text(now.clone()),
            TursoValue::Text(now.clone()),
        ],
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.execute(
        "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at)
         VALUES (?, ?, ?, ?, ?)",
        vec![
            TursoValue::Text(inbox_id.to_string()),
            TursoValue::Text(session.user_id.to_string()),
            TursoValue::Text(body.recipient_user_id.to_string()),
            TursoValue::Text(db::encode_b64(&capsule_bytes)),
            TursoValue::Text(now),
        ],
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Conflict(format!("share send raced with a concurrent request: {e}")))?;

    tracing::info!(
        inbox_id  = %inbox_id,
        sender    = %session.user_id,
        recipient = %body.recipient_user_id,
        bytes     = capsule_bytes.len(),
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

pub async fn delete_inbox_item(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
) -> Result<(HeaderMap, StatusCode)> {
    let n = state
        .sqldb
        .execute(
            "DELETE FROM share_inbox WHERE id = ? AND recipient_user_id = ?",
            vec![
                TursoValue::Text(id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if n == 0 {
        return Err(AppError::NotFound(format!("inbox item {id} not found")));
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

pub async fn put_linked_item(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
    Json(body): Json<UpdateLinkedShareRequest>,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let capsule_bytes = B64
        .decode(&body.capsule)
        .map_err(|_| AppError::BadRequest("capsule is not valid base64".into()))?;

    if capsule_bytes.len() > MAX_CAPSULE_BYTES {
        return Err(AppError::BadRequest(format!(
            "capsule exceeds maximum size of {MAX_CAPSULE_BYTES} bytes"
        )));
    }

    let n = state
        .sqldb
        .execute(
            "UPDATE shared_items
         SET capsule = ?, updated_at = ?
         WHERE id = ? AND sender_user_id = ? AND revoked = 0",
            vec![
                TursoValue::Text(db::encode_b64(&capsule_bytes)),
                TursoValue::Text(Utc::now().to_rfc3339()),
                TursoValue::Text(id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if n == 0 {
        return Err(AppError::NotFound(format!("linked share {id} not found")));
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "updated": true }))))
}

pub async fn delete_linked_item(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let n = state
        .sqldb
        .execute(
            "UPDATE shared_items
         SET revoked = 1, updated_at = ?
         WHERE id = ? AND sender_user_id = ? AND revoked = 0",
            vec![
                TursoValue::Text(Utc::now().to_rfc3339()),
                TursoValue::Text(id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if n == 0 {
        return Err(AppError::NotFound(format!("linked share {id} not found")));
    }

    let _ = state
        .sqldb
        .execute(
            "DELETE FROM share_inbox WHERE id = ?",
            vec![TursoValue::Text(id.to_string())],
        )
        .await;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "deleted": true }))))
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
            "SELECT share_ek FROM users WHERE id = ?",
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

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "share_ek": share_ek }))))
}

/// ML-KEM-1024 EK (1568) + X25519 PK (32). Matches `account::SHARE_EK_LEN`.
const SHARE_EK_LEN: usize = 1568 + 32;

#[derive(Deserialize)]
pub struct PutShareEkRequest {
    pub share_ek: String,
}

/// Register (or update) the authenticated user's own share encapsulation key.
///
/// Backfill path for accounts created before share keys existed: an already
/// registered client that detects an empty local share key generates a fresh
/// KEM keypair and uploads the public half here, keeping its device identity
/// and vault intact.
pub async fn put_my_ek(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<PutShareEkRequest>,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let ek_bytes = B64
        .decode(&body.share_ek)
        .map_err(|_| AppError::BadRequest("share_ek is not valid base64".into()))?;

    if ek_bytes.len() != SHARE_EK_LEN {
        return Err(AppError::BadRequest(format!(
            "share_ek must be exactly {SHARE_EK_LEN} bytes"
        )));
    }

    let n = state
        .sqldb
        .execute(
            "UPDATE users SET share_ek = ? WHERE id = ?",
            vec![
                TursoValue::Text(body.share_ek),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if n == 0 {
        return Err(AppError::NotFound("user not found".into()));
    }

    tracing::info!(user_id = %session.user_id, "share key registered (backfill)");

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
