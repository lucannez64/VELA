//! GET /vault/chunk/:id  — download one encrypted ORAM blob.
//! PUT /vault/chunk/:id  — upload / create one encrypted ORAM blob.
//!
//! ## PUT semantics
//!
//! * Requires `If-Match: <version>` header for optimistic concurrency.
//! * Returns `409 Conflict` if the stored version has advanced since the
//!   client's last fetch.
//! * On success, the server increments `version` and stores the new `lamport_clock`
//!   and `last_writer` supplied by the client in the request body.
//! * New chunks (first upload): `If-Match: 0` signals creation intent.
//!
//! ## Chunk size enforcement
//!
//! The server accepts ciphertext up to `config.max_chunk_bytes` (default 1 MiB).
//! Clients must pad to exactly 1 MiB before encryption.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

// ─── GET /vault/chunk/:id ─────────────────────────────────────────────────────

pub async fn get_chunk(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
) -> Result<impl IntoResponse> {
    let row = sqlx::query_as::<_, crate::db::ChunkRow>(
        "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext
         FROM vault_chunks
         WHERE chunk_id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(session.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("chunk {id} not found")))?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    // Expose the current version so clients can use it as the If-Match value.
    headers.insert(
        "X-Chunk-Version",
        row.version.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-Lamport-Clock",
        row.lamport_clock.to_string().parse().unwrap(),
    );
    if let Some(lw) = row.last_writer {
        headers.insert(
            "X-Last-Writer",
            lw.to_string().parse().unwrap(),
        );
    }
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );

    Ok((StatusCode::OK, headers, row.ciphertext))
}

// ─── PUT /vault/chunk/:id ─────────────────────────────────────────────────────

pub async fn put_chunk(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    session: AuthSession,
    headers_in: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    // ── Enforce chunk size ────────────────────────────────────────────────────
    if body.len() > state.config.max_chunk_bytes {
        return Err(AppError::BadRequest(format!(
            "chunk exceeds maximum size of {} bytes",
            state.config.max_chunk_bytes
        )));
    }

    // ── Extract If-Match version ──────────────────────────────────────────────
    let if_match: i64 = headers_in
        .get("if-match")
        .or_else(|| headers_in.get("If-Match"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest("If-Match header is required".into()))?;

    // ── Extract Lamport clock from X-Lamport-Clock header ────────────────────
    let lamport_clock: i64 = headers_in
        .get("x-lamport-clock")
        .or_else(|| headers_in.get("X-Lamport-Clock"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest("X-Lamport-Clock header is required".into()))?;

    let ciphertext = body.to_vec();

    // ── Upsert under optimistic locking ──────────────────────────────────────
    // if_match == 0 signals "create new chunk"; otherwise it must match the
    // current stored version exactly.
    let result = if if_match == 0 {
        // INSERT (new chunk) — fail if chunk already exists.
        sqlx::query(
            "INSERT INTO vault_chunks
             (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext)
             VALUES ($1, $2, 1, $3, $4, $5)",
        )
        .bind(id)
        .bind(session.user_id)
        .bind(lamport_clock)
        .bind(session.device_id)
        .bind(&ciphertext)
        .execute(&state.db)
        .await
    } else {
        // UPDATE with version check.
        sqlx::query(
            "UPDATE vault_chunks
             SET version       = version + 1,
                 lamport_clock = $1,
                 last_writer   = $2,
                 ciphertext    = $3,
                 updated_at    = NOW()
             WHERE chunk_id = $4
               AND user_id  = $5
               AND version  = $6",
        )
        .bind(lamport_clock)
        .bind(session.device_id)
        .bind(&ciphertext)
        .bind(id)
        .bind(session.user_id)
        .bind(if_match)
        .execute(&state.db)
        .await
    };

    match result {
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => {
            // Unique constraint violation on INSERT (chunk already exists).
            return Err(AppError::Conflict(
                "chunk already exists; use If-Match with current version to update".into(),
            ));
        }
        Err(e) => return Err(AppError::Database(e)),
        Ok(r) if r.rows_affected() == 0 => {
            // UPDATE matched no rows → version mismatch.
            return Err(AppError::Conflict(
                "version mismatch — re-sync before retrying".into(),
            ));
        }
        Ok(_) => {}
    }

    // ── Response ──────────────────────────────────────────────────────────────
    let new_version: i64 = sqlx::query_scalar(
        "SELECT version FROM vault_chunks WHERE chunk_id = $1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;

    let mut resp_headers = HeaderMap::new();
    maybe_append_new_token(&mut resp_headers, &session);
    resp_headers.insert(
        "X-Chunk-Version",
        new_version.to_string().parse().unwrap(),
    );

    Ok((StatusCode::OK, resp_headers, Json(serde_json::json!({ "version": new_version }))))
}
