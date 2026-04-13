//! Share endpoints — send encrypted vault-item capsules between users and
//! retrieve them from the inbox.
//!
//! ## Endpoints
//!
//! | Method | Route                | Auth     | Description                           |
//! |--------|----------------------|----------|---------------------------------------|
//! | POST   | /share/send          | PASETO   | Deliver an encrypted capsule to inbox |
//! | GET    | /share/inbox         | PASETO   | List pending inbox items              |
//! | DELETE | /share/inbox/:id     | PASETO   | Acknowledge / delete one inbox item   |
//!
//! The server stores capsules as opaque blobs — all encryption is client-side
//! (Hybrid KEM + XChaCha20-Poly1305).  The server cannot read any capsule.

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
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

const MAX_CAPSULE_BYTES: usize = 1024 * 1024; // 1 MiB
const DEFAULT_INBOX_LIMIT: i64 = 50;
const MAX_INBOX_LIMIT:     i64 = 200;
const MAX_INBOX_ITEMS_PER_USER: i64 = 500;

/// Inbox items older than this are eligible for automatic purge.
/// Set to 30 days (matches spec §5.3 conflict copy retention period).
pub const INBOX_TTL_SECS: i64 = 30 * 24 * 60 * 60;

// ── POST /share/send ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendRequest {
    pub recipient_user_id: Uuid,
    /// Base64-encoded Hybrid KEM capsule ‖ AEAD-encrypted vault item payload.
    pub capsule: String,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub inbox_id: Uuid,
}

pub async fn post_send(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<SendRequest>,
) -> Result<(HeaderMap, Json<SendResponse>)> {
    // ── Validate recipient ────────────────────────────────────────────────────
    let recipient_exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)",
    )
    .bind(body.recipient_user_id)
    .fetch_one(&state.db)
    .await?;

    if !recipient_exists.unwrap_or(false) {
        return Err(AppError::NotFound("recipient user not found".into()));
    }

    // ── Enforce inbox size limit ──────────────────────────────────────────────
    let inbox_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM share_inbox WHERE recipient_user_id = $1",
    )
    .bind(body.recipient_user_id)
    .fetch_one(&state.db)
    .await?;

    if inbox_count >= MAX_INBOX_ITEMS_PER_USER {
        return Err(AppError::Conflict(format!(
            "recipient inbox is full ({MAX_INBOX_ITEMS_PER_USER} items)"
        )));
    }

    // ── Decode and size-check capsule ─────────────────────────────────────────
    let capsule_bytes = B64
        .decode(&body.capsule)
        .map_err(|_| AppError::BadRequest("capsule is not valid base64".into()))?;

    if capsule_bytes.len() > MAX_CAPSULE_BYTES {
        return Err(AppError::BadRequest(format!(
            "capsule exceeds maximum size of {MAX_CAPSULE_BYTES} bytes"
        )));
    }

    // ── Persist ───────────────────────────────────────────────────────────────
    let inbox_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO share_inbox (id, sender_user_id, recipient_user_id, capsule)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(inbox_id)
    .bind(session.user_id)
    .bind(body.recipient_user_id)
    .bind(&capsule_bytes)
    .execute(&state.db)
    .await?;

    tracing::info!(
        inbox_id  = %inbox_id,
        sender    = %session.user_id,
        recipient = %body.recipient_user_id,
        bytes     = capsule_bytes.len(),
        "share capsule delivered"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(SendResponse { inbox_id })))
}

// ── GET /share/inbox ──────────────────────────────────────────────────────────

/// Query-string parameters for inbox pagination.
#[derive(Deserialize, Default)]
pub struct InboxQuery {
    /// Maximum number of items to return (default 50, max 200).
    pub limit: Option<i64>,
    /// Return items older than this inbox ID (cursor-based pagination).
    pub before: Option<Uuid>,
}

#[derive(Serialize)]
pub struct InboxItem {
    pub id:             Uuid,
    pub sender_user_id: Uuid,
    pub capsule:        String,  // base64-encoded
    pub created_at:     DateTime<Utc>,
}

#[derive(Serialize)]
pub struct InboxResponse {
    pub items:    Vec<InboxItem>,
    pub has_more: bool,
}

pub async fn get_inbox(
    State(state): State<AppState>,
    session: AuthSession,
    axum::extract::Query(query): axum::extract::Query<InboxQuery>,
) -> Result<(HeaderMap, Json<InboxResponse>)> {
    let limit = query.limit
        .unwrap_or(DEFAULT_INBOX_LIMIT)
        .clamp(1, MAX_INBOX_LIMIT);

    // Fetch one extra to determine has_more.
    let fetch_limit = limit + 1;

    #[derive(sqlx::FromRow)]
    struct Row {
        id:             Uuid,
        sender_user_id: Uuid,
        capsule:        Vec<u8>,
        created_at:     DateTime<Utc>,
    }

    let rows: Vec<Row> = if let Some(before_id) = query.before {
        // Cursor: find the created_at of the `before` item, then page.
        #[derive(sqlx::FromRow)]
        struct Cursor { created_at: DateTime<Utc> }

        let cursor = sqlx::query_as::<_, Cursor>(
            "SELECT created_at FROM share_inbox
             WHERE id = $1 AND recipient_user_id = $2",
        )
        .bind(before_id)
        .bind(session.user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("cursor inbox_id not found".into()))?;

        sqlx::query_as::<_, Row>(
            "SELECT id, sender_user_id, capsule, created_at
             FROM share_inbox
             WHERE recipient_user_id = $1
               AND created_at < $2
             ORDER BY created_at DESC
             LIMIT $3",
        )
        .bind(session.user_id)
        .bind(cursor.created_at)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, Row>(
            "SELECT id, sender_user_id, capsule, created_at
             FROM share_inbox
             WHERE recipient_user_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(session.user_id)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?
    };

    let has_more = rows.len() as i64 > limit;
    let items = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| InboxItem {
            id:             r.id,
            sender_user_id: r.sender_user_id,
            capsule:        B64.encode(&r.capsule),
            created_at:     r.created_at,
        })
        .collect();

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(InboxResponse { items, has_more })))
}

// ── DELETE /share/inbox/:id ───────────────────────────────────────────────────

/// Acknowledge and delete a received share capsule.
///
/// The client calls this after successfully decrypting and importing the item
/// into the local vault to prevent re-processing on future inbox fetches.
pub async fn delete_inbox_item(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
) -> Result<(HeaderMap, StatusCode)> {
    let result = sqlx::query(
        "DELETE FROM share_inbox WHERE id = $1 AND recipient_user_id = $2",
    )
    .bind(id)
    .bind(session.user_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("inbox item {id} not found")));
    }

    tracing::info!(inbox_id = %id, user_id = %session.user_id, "inbox item deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}

// ── Background inbox cleanup ──────────────────────────────────────────────────

/// Periodically purges expired share inbox items (older than `INBOX_TTL_SECS`).
/// Runs every 6 hours. Logs the number of purged rows.
pub async fn inbox_cleanup_task(pool: sqlx::PgPool) {
    use chrono::Utc;

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 60 * 60));

    loop {
        interval.tick().await;

        let cutoff = Utc::now() - chrono::Duration::seconds(INBOX_TTL_SECS);

        match sqlx::query(
            "DELETE FROM share_inbox WHERE created_at < $1",
        )
        .bind(cutoff)
        .execute(&pool)
        .await
        {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    tracing::info!(
                        purged = result.rows_affected(),
                        "inbox cleanup: expired share items removed"
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "inbox cleanup task failed");
            }
        }
    }
}
