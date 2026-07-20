use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

pub async fn get_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
) -> Result<impl IntoResponse> {
    let rows = state
        .db
        .query(
            "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext
         FROM vault_chunks
         WHERE chunk_id = $1 AND user_id = $2",
            stoolap::params![id.to_string(), session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound(format!("chunk {id} not found")))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let chunk = crate::db::parse_chunk_row(&row)?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    headers.insert(
        "X-Chunk-Version",
        chunk.version.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-Lamport-Clock",
        chunk.lamport_clock.to_string().parse().unwrap(),
    );
    if let Some(lw) = chunk.last_writer {
        headers.insert("X-Last-Writer", lw.to_string().parse().unwrap());
    }
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );

    Ok((StatusCode::OK, headers, chunk.ciphertext))
}

pub async fn put_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
    headers_in: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    if body.len() > state.config.max_chunk_bytes {
        return Err(AppError::BadRequest(format!(
            "chunk exceeds maximum size of {} bytes",
            state.config.max_chunk_bytes
        )));
    }

    let if_match: i64 = headers_in
        .get("if-match")
        .or_else(|| headers_in.get("If-Match"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest("If-Match header is required".into()))?;

    let lamport_clock: i64 = headers_in
        .get("x-lamport-clock")
        .or_else(|| headers_in.get("X-Lamport-Clock"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest("X-Lamport-Clock header is required".into()))?;

    let ciphertext = body.to_vec();
    crate::vault::enforce_storage_quota(&state, &session.user_id.to_string(), body.len() as u64)?;
    let now = Utc::now().to_rfc3339();

    if if_match == 0 {
        let existing = state
            .db
            .query(
                "SELECT 1 FROM vault_chunks WHERE chunk_id = $1 AND user_id = $2",
                stoolap::params![id.to_string(), session.user_id.to_string()],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if existing.into_iter().next().is_some() {
            return Err(AppError::Conflict(
                "chunk already exists; use If-Match with current version to update".into(),
            ));
        }

        state.db.execute(
            "INSERT INTO vault_chunks
             (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, created_at, updated_at)
             VALUES ($1, $2, 1, $3, $4, $5, $6, $7)",
            stoolap::params![
                id.to_string(),
                session.user_id.to_string(),
                lamport_clock,
                session.device_id.to_string(),
                crate::db::encode_b64(&ciphertext),
                now.clone(),
                now,
            ],
        ).map_err(|e| {
            // A concurrent If-Match:0 request can win the race between the
            // "does it exist" check above and this INSERT; the unique index
            // then reports it as a constraint violation instead of a plain
            // error. Surface that as the same 409 the pre-check gives, not 500.
            if matches!(
                e,
                stoolap::Error::UniqueConstraint { .. } | stoolap::Error::PrimaryKeyConstraint { .. }
            ) {
                AppError::Conflict(
                    "chunk already exists; use If-Match with current version to update".into(),
                )
            } else {
                AppError::Internal(e.to_string())
            }
        })?;
    } else {
        let n: i64 = state
            .db
            .execute(
                "UPDATE vault_chunks
             SET version       = version + 1,
                 lamport_clock = $1,
                 last_writer   = $2,
                 ciphertext    = $3,
                 updated_at    = $4
             WHERE chunk_id = $5
               AND user_id  = $6
               AND version  = $7",
                stoolap::params![
                    lamport_clock,
                    session.device_id.to_string(),
                    crate::db::encode_b64(&ciphertext),
                    now,
                    id.to_string(),
                    session.user_id.to_string(),
                    if_match,
                ],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if n == 0 {
            return Err(AppError::Conflict(
                "version mismatch — re-sync before retrying".into(),
            ));
        }
    }

    let ver_rows = state
        .db
        .query(
            "SELECT version FROM vault_chunks WHERE chunk_id = $1 AND user_id = $2",
            stoolap::params![id.to_string(), session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let ver_row = ver_rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Internal("failed to read new version".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let v = crate::db::row_val(&ver_row, 0)?;
    let new_version: i64 = v
        .as_int64()
        .ok_or_else(|| AppError::Internal("expected integer".into()))?;

    let mut resp_headers = HeaderMap::new();
    maybe_append_new_token(&mut resp_headers, &session);
    resp_headers.insert("X-Chunk-Version", new_version.to_string().parse().unwrap());

    Ok((
        StatusCode::OK,
        resp_headers,
        Json(serde_json::json!({ "version": new_version })),
    ))
}

pub async fn delete_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
    headers_in: HeaderMap,
) -> Result<impl IntoResponse> {
    let if_match: i64 = headers_in
        .get("if-match")
        .or_else(|| headers_in.get("If-Match"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest("If-Match header is required".into()))?;

    let rows = state
        .db
        .query(
            "SELECT version FROM vault_chunks WHERE chunk_id = $1 AND user_id = $2",
            stoolap::params![id.to_string(), session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = match rows.into_iter().next() {
        Some(r) => r.map_err(|e| AppError::Internal(e.to_string()))?,
        None => return Err(AppError::NotFound(format!("chunk {id} not found"))),
    };

    let v = crate::db::row_val(&row, 0)?;
    let current_version: i64 = v
        .as_int64()
        .ok_or_else(|| AppError::Internal("expected integer".into()))?;

    if current_version != if_match {
        return Err(AppError::Conflict(
            "version mismatch — re-sync before deleting".into(),
        ));
    }

    state
        .db
        .execute(
            "DELETE FROM vault_chunks WHERE chunk_id = $1 AND user_id = $2",
            stoolap::params![id.to_string(), session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(
        chunk_id = %id,
        user_id = %session.user_id,
        version = current_version,
        "vault chunk deleted"
    );

    let mut resp_headers = HeaderMap::new();
    maybe_append_new_token(&mut resp_headers, &session);

    Ok((
        StatusCode::OK,
        resp_headers,
        Json(serde_json::json!({ "deleted": true, "version": current_version })),
    ))
}
