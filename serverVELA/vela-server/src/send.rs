//! One-off share links — send a secret to someone who does not use VELA.
//!
//! Unlike cross-user sharing (M19), there is no recipient identity and so no
//! `share_ek` to seal a KEM capsule to. Instead the client generates a random
//! 256-bit *link key*, seals the item with it (plus an optional Argon2id-stretched
//! passphrase), and puts the key in the URL **fragment** of the link it hands
//! out. Browsers never transmit the fragment, so this server stores and serves
//! only ciphertext it can never open — the same zero-knowledge property as the
//! rest of the vault, extended to an anonymous reader.
//!
//! Access is bounded server-side: every link has an expiry, and optionally a
//! view count, a view-once flag, and a passphrase the recipient must also know.
//! `GET /send/:id` consumes one view atomically and reports every failure as the
//! same `404`, so the endpoint is not an existence oracle.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    db,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    net, rate_limit,
    sqldb::{Db as _, TursoDb, TursoValue},
    state::AppState,
};

/// A link carries one item (or note); generous for a large secure note, far
/// below inbox-sized payloads.
const MAX_SEND_BYTES: usize = 256 * 1024;
const MAX_TTL_SECS: i64 = 30 * 24 * 60 * 60; // 30 days
const MIN_TTL_SECS: i64 = 5 * 60; // 5 minutes
const DEFAULT_TTL_SECS: i64 = 24 * 60 * 60; // 24 hours
const MAX_VIEWS_CEILING: i64 = 1000;
/// Same message for missing, expired, revoked and exhausted, so a `404` never
/// confirms that a link id is (or was) live.
const SEND_NOT_FOUND: &str = "send not found";

fn clamp_ttl(ttl: Option<i64>) -> i64 {
    match ttl {
        Some(value) => value.clamp(MIN_TTL_SECS, MAX_TTL_SECS),
        None => DEFAULT_TTL_SECS,
    }
}

/// `view_once` pins the count to exactly one; otherwise clamp to a sane ceiling.
fn resolve_max_views(max_views: Option<i64>, view_once: bool) -> Option<i64> {
    if view_once {
        return Some(1);
    }
    max_views.map(|value| value.clamp(1, MAX_VIEWS_CEILING))
}

// ── POST /send (owner, authenticated) ────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSendRequest {
    /// The sealed item, base64 (standard). The server never sees the key.
    pub ciphertext: String,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default)]
    pub max_views: Option<i64>,
    #[serde(default)]
    pub view_once: bool,
    #[serde(default)]
    pub has_passphrase: bool,
    /// Argon2id salt (base64) required when `has_passphrase` is set.
    #[serde(default)]
    pub kdf_salt: Option<String>,
    /// Owner-side label; never returned to the recipient.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct CreateSendResponse {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}

pub async fn post_send(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<CreateSendRequest>,
) -> Result<(HeaderMap, Json<CreateSendResponse>)> {
    rate_limit::send_create_by_user(&state.store, &session.user_id.to_string())?;

    let ciphertext = B64
        .decode(&body.ciphertext)
        .map_err(|_| AppError::BadRequest("ciphertext is not valid base64".into()))?;
    if ciphertext.is_empty() {
        return Err(AppError::BadRequest("ciphertext is empty".into()));
    }
    if ciphertext.len() > MAX_SEND_BYTES {
        return Err(AppError::PayloadTooLarge(format!(
            "ciphertext exceeds maximum size of {MAX_SEND_BYTES} bytes"
        )));
    }

    let kdf_salt = match (body.has_passphrase, body.kdf_salt.as_deref()) {
        (true, Some(salt)) => {
            let bytes = B64
                .decode(salt.as_bytes())
                .map_err(|_| AppError::BadRequest("kdf_salt is not valid base64".into()))?;
            if bytes.len() < 8 {
                return Err(AppError::BadRequest("kdf_salt is too short".into()));
            }
            Some(db::encode_b64(&bytes))
        }
        (true, None) => {
            return Err(AppError::BadRequest(
                "has_passphrase requires kdf_salt".into(),
            ))
        }
        (false, _) => None,
    };

    let id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(clamp_ttl(body.ttl_secs));
    let max_views = resolve_max_views(body.max_views, body.view_once);
    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    state
        .sqldb
        .execute(
            "INSERT INTO sends
                (id, owner_user_id, ciphertext, has_passphrase, kdf_salt, label,
                 view_once, max_views, view_count, created_at, expires_at, revoked)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)",
            vec![
                TursoValue::Text(id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Text(db::encode_b64(&ciphertext)),
                TursoValue::Integer(if body.has_passphrase { 1 } else { 0 }),
                kdf_salt.map(TursoValue::Text).unwrap_or(TursoValue::Null),
                label.map(TursoValue::Text).unwrap_or(TursoValue::Null),
                TursoValue::Integer(if body.view_once { 1 } else { 0 }),
                max_views.map(TursoValue::Integer).unwrap_or(TursoValue::Null),
                TursoValue::Text(now.to_rfc3339()),
                TursoValue::Text(expires_at.to_rfc3339()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(
        send_id = %id,
        owner = %session.user_id,
        bytes = ciphertext.len(),
        "share link created"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(CreateSendResponse { id, expires_at })))
}

// ── GET /send/:id (anonymous recipient) ──────────────────────────────────────

#[derive(Serialize)]
pub struct FetchSendResponse {
    pub ciphertext: String,
    pub has_passphrase: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    pub view_once: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_views: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub views_remaining: Option<i64>,
    pub expires_at: DateTime<Utc>,
}

pub async fn get_send(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<FetchSendResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::send_fetch_by_ip(&state.store, &ip)?;

    let now = Utc::now().to_rfc3339();

    // Consume one view atomically. Revoked, expired and exhausted links all
    // match zero rows, so they are indistinguishable from a missing id.
    let affected = state
        .sqldb
        .execute(
            "UPDATE sends SET view_count = view_count + 1
             WHERE id = ? AND revoked = 0 AND expires_at > ?
               AND (max_views IS NULL OR view_count < max_views)",
            vec![
                TursoValue::Text(id.to_string()),
                TursoValue::Text(now),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if affected == 0 {
        return Err(AppError::NotFound(SEND_NOT_FOUND.into()));
    }

    let rows = state
        .sqldb
        .query(
            "SELECT ciphertext, has_passphrase, kdf_salt, view_once, max_views, view_count, expires_at
             FROM sends WHERE id = ?",
            vec![TursoValue::Text(id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound(SEND_NOT_FOUND.into()))?;

    let ciphertext = row
        .text(0)
        .ok_or_else(|| AppError::Internal("send row missing ciphertext".into()))?
        .to_string();
    let has_passphrase = row.bool_int(1).unwrap_or(false);
    let kdf_salt = row.text(2).map(String::from);
    let view_once = row.bool_int(3).unwrap_or(false);
    let max_views = row.i64(4);
    let view_count = row.i64(5).unwrap_or(0);
    let expires_at = row
        .timestamp(6)
        .ok_or_else(|| AppError::Internal("send row missing expires_at".into()))?;

    // A view-once link is deleted the moment it is served; the conditional
    // update above guarantees only one caller ever reaches this point.
    if view_once {
        let _ = state
            .sqldb
            .execute(
                "DELETE FROM sends WHERE id = ?",
                vec![TursoValue::Text(id.to_string())],
            )
            .await;
    }

    let views_remaining = max_views.map(|max| (max - view_count).max(0));

    Ok(Json(FetchSendResponse {
        ciphertext,
        has_passphrase,
        kdf_salt,
        view_once,
        max_views,
        views_remaining,
        expires_at,
    }))
}

// ── GET /sends (owner, authenticated) ────────────────────────────────────────

#[derive(Serialize)]
pub struct SendMeta {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub has_passphrase: bool,
    pub view_once: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_views: Option<i64>,
    pub view_count: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn list_sends(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    rate_limit::send_list_by_user(&state.store, &session.user_id.to_string())?;

    let rows = state
        .sqldb
        .query(
            "SELECT id, label, has_passphrase, view_once, max_views, view_count, created_at, expires_at
             FROM sends
             WHERE owner_user_id = ? AND revoked = 0 AND expires_at > ?
             ORDER BY created_at DESC LIMIT 200",
            vec![
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Text(Utc::now().to_rfc3339()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let items: Vec<SendMeta> = rows
        .iter()
        .filter_map(|row| {
            Some(SendMeta {
                id: row.uuid(0)?,
                label: row.text(1).map(String::from),
                has_passphrase: row.bool_int(2).unwrap_or(false),
                view_once: row.bool_int(3).unwrap_or(false),
                max_views: row.i64(4),
                view_count: row.i64(5).unwrap_or(0),
                created_at: row.timestamp(6)?,
                expires_at: row.timestamp(7)?,
            })
        })
        .collect();

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "sends": items }))))
}

// ── DELETE /send/:id (owner, authenticated) ──────────────────────────────────

pub async fn delete_send(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<Uuid>,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let affected = state
        .sqldb
        .execute(
            "DELETE FROM sends WHERE id = ? AND owner_user_id = ?",
            vec![
                TursoValue::Text(id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "deleted": affected > 0 }))))
}

/// Periodically delete expired links so ciphertext does not outlive its TTL.
pub async fn cleanup_task(db: Arc<TursoDb>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10 * 60));
    loop {
        interval.tick().await;
        match db
            .execute(
                "DELETE FROM sends WHERE expires_at < ?",
                vec![TursoValue::Text(Utc::now().to_rfc3339())],
            )
            .await
        {
            Ok(n) => {
                if n > 0 {
                    tracing::info!(purged = n, "send-link cleanup");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "send cleanup task failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_clamps_to_bounds() {
        assert_eq!(clamp_ttl(None), DEFAULT_TTL_SECS);
        assert_eq!(clamp_ttl(Some(1)), MIN_TTL_SECS);
        assert_eq!(clamp_ttl(Some(i64::MAX)), MAX_TTL_SECS);
        assert_eq!(clamp_ttl(Some(3600)), 3600);
    }

    #[test]
    fn view_once_pins_one_view_and_others_clamp() {
        assert_eq!(resolve_max_views(None, true), Some(1));
        assert_eq!(resolve_max_views(Some(5), true), Some(1));
        assert_eq!(resolve_max_views(None, false), None);
        assert_eq!(resolve_max_views(Some(0), false), Some(1));
        assert_eq!(resolve_max_views(Some(i64::MAX), false), Some(MAX_VIEWS_CEILING));
        assert_eq!(resolve_max_views(Some(7), false), Some(7));
    }
}
