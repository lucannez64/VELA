use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

const MAX_CAPSULE_BYTES: usize = 1024 * 1024;
const DEFAULT_INBOX_LIMIT: i64 = 50;
const MAX_INBOX_LIMIT: i64 = 200;
const MAX_INBOX_ITEMS_PER_USER: i64 = 500;

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

pub async fn post_send(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<SendRequest>,
) -> Result<(HeaderMap, Json<SendResponse>)> {
    let exists_rows = state
        .db
        .query(
            "SELECT 1 FROM users WHERE id = $1",
            stoolap::params![body.recipient_user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if exists_rows.into_iter().next().is_none() {
        return Err(AppError::NotFound("recipient user not found".into()));
    }

    let count_rows = state
        .db
        .query(
            "SELECT COUNT(*) FROM share_inbox WHERE recipient_user_id = $1",
            stoolap::params![body.recipient_user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let count_row = count_rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Internal("count query failed".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let cv = crate::db::row_val(&count_row, 0)?;
    let inbox_count: i64 = cv.as_int64().unwrap_or(0);

    if inbox_count >= MAX_INBOX_ITEMS_PER_USER {
        return Err(AppError::Conflict(format!(
            "recipient inbox is full ({MAX_INBOX_ITEMS_PER_USER} items)"
        )));
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

    state.db.execute(
        "INSERT INTO shared_items (id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked)
         VALUES ($1, $2, $3, $4, $5, $6, FALSE)",
        stoolap::params![
            inbox_id.to_string(),
            session.user_id.to_string(),
            body.recipient_user_id.to_string(),
            db::encode_b64(&capsule_bytes),
            now.clone(),
            now.clone(),
        ],
    ).map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .db
        .execute(
            "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule, created_at)
         VALUES ($1, $2, $3, $4, $5)",
            stoolap::params![
                inbox_id.to_string(),
                session.user_id.to_string(),
                body.recipient_user_id.to_string(),
                db::encode_b64(&capsule_bytes),
                now,
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

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
            .db
            .query(
                "SELECT created_at FROM share_inbox
             WHERE id = $1 AND recipient_user_id = $2",
                stoolap::params![before_id.to_string(), session.user_id.to_string()],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let cursor_row = cursor_rows
            .into_iter()
            .next()
            .ok_or_else(|| AppError::NotFound("cursor inbox_id not found".into()))?
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let cv = crate::db::row_val(&cursor_row, 0)?;
        let cursor_ts = cv
            .as_timestamp()
            .ok_or_else(|| AppError::Internal("expected timestamp".into()))?;

        state
            .db
            .query(
                "SELECT id, sender_user_id, capsule, created_at
             FROM share_inbox
             WHERE recipient_user_id = $1
               AND created_at < $2
             ORDER BY created_at DESC
             LIMIT $3",
                stoolap::params![
                    session.user_id.to_string(),
                    cursor_ts.to_rfc3339(),
                    fetch_limit,
                ],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?
    } else {
        state
            .db
            .query(
                "SELECT id, sender_user_id, capsule, created_at
             FROM share_inbox
             WHERE recipient_user_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
                stoolap::params![session.user_id.to_string(), fetch_limit],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    let mut all_items: Vec<InboxItem> = Vec::new();
    for row_result in rows {
        let row = row_result.map_err(|e| AppError::Internal(e.to_string()))?;
        let id_v = crate::db::row_val(&row, 0)?;
        let sender_v = crate::db::row_val(&row, 1)?;
        let capsule_v = crate::db::row_val(&row, 2)?;
        let ts_v = crate::db::row_val(&row, 3)?;

        let id = id_v
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AppError::Internal("uuid parse".into()))?;
        let sender_user_id = sender_v
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AppError::Internal("uuid parse".into()))?;
        let capsule_b64 = capsule_v
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AppError::Internal("expected text".into()))?;
        let created_at = ts_v
            .as_timestamp()
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
    let n: i64 = state
        .db
        .execute(
            "DELETE FROM share_inbox WHERE id = $1 AND recipient_user_id = $2",
            stoolap::params![id.to_string(), session.user_id.to_string()],
        )
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
        .db
        .query(
            "SELECT id, sender_user_id, recipient_user_id, capsule, created_at, updated_at, revoked
         FROM shared_items
         WHERE (sender_user_id = $1 OR recipient_user_id = $1)
           AND revoked = FALSE
         ORDER BY updated_at DESC",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut items = Vec::new();
    for row_result in rows {
        let row = row_result.map_err(|e| AppError::Internal(e.to_string()))?;
        let shared = db::parse_shared_item_row(&row)?;
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

    let n: i64 = state
        .db
        .execute(
            "UPDATE shared_items
         SET capsule = $1, updated_at = $2
         WHERE id = $3 AND sender_user_id = $4 AND revoked = FALSE",
            stoolap::params![
                db::encode_b64(&capsule_bytes),
                Utc::now().to_rfc3339(),
                id.to_string(),
                session.user_id.to_string(),
            ],
        )
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
    let n: i64 = state
        .db
        .execute(
            "UPDATE shared_items
         SET revoked = TRUE, updated_at = $1
         WHERE id = $2 AND sender_user_id = $3 AND revoked = FALSE",
            stoolap::params![
                Utc::now().to_rfc3339(),
                id.to_string(),
                session.user_id.to_string()
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if n == 0 {
        return Err(AppError::NotFound(format!("linked share {id} not found")));
    }

    let _ = state.db.execute(
        "DELETE FROM share_inbox WHERE id = $1",
        stoolap::params![id.to_string()],
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "deleted": true }))))
}

pub async fn inbox_cleanup_task(db: stoolap::Database) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 60 * 60));

    loop {
        interval.tick().await;

        let cutoff = Utc::now() - chrono::Duration::seconds(INBOX_TTL_SECS);

        match db.execute(
            "DELETE FROM share_inbox WHERE created_at < $1",
            stoolap::params![cutoff.to_rfc3339()],
        ) {
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
