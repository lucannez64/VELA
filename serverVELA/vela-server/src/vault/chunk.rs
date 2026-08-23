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
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

fn parse_declared_epoch(headers: &HeaderMap) -> Result<Option<i64>> {
    let Some(raw) = headers.get("x-vela-epoch") else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| AppError::BadRequest("X-Vela-Epoch must be an integer".into()))?;
    raw.parse::<i64>()
        .map(Some)
        .map_err(|_| AppError::BadRequest("X-Vela-Epoch must be an integer".into()))
}

async fn ensure_write_state_unchanged(
    state: &AppState,
    user_id: &str,
    declared_epoch: Option<i64>,
    expected: (i64, i64),
) -> Result<()> {
    let current = crate::vault::rekey::resolve_write_epoch(state, user_id, declared_epoch).await?;
    if current != expected {
        return Err(AppError::Rekeyed(
            "vault epoch changed before the write completed".into(),
        ));
    }
    Ok(())
}

pub async fn get_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
) -> Result<impl IntoResponse> {
    let id = crate::ids::validate_id("chunk_id", &id)?.to_string();
    // Serve only the account's current-epoch rows: shadow rows from an
    // in-flight rotation belong to nobody until commit, and superseded rows
    // are gone by the time anyone could ask (docs/VAULT_REKEYING_DESIGN.md §5).
    let read_epoch = crate::vault::rekey::read_epoch(&state, &session.user_id.to_string()).await?;
    let rows = state
        .sqldb
        .query(
            "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext
         FROM vault_chunks
         WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(read_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let chunk = rows
        .first()
        .map(|r| crate::db::parse_chunk_row_turso(r))
        .transpose()?
        .ok_or_else(|| AppError::NotFound(format!("chunk {id} not found")))?;

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
    let id = crate::ids::validate_id("chunk_id", &id)?.to_string();
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
    let now = Utc::now().to_rfc3339();

    // Which epoch this ciphertext claims to belong to. Absent header = the
    // current epoch (legacy-client tolerance, docs/VAULT_REKEYING_DESIGN.md §5);
    // anything else is resolved — or refused — by the re-key guard.
    let declared_epoch = parse_declared_epoch(&headers_in)?;
    let rotation_id = headers_in
        .get("x-vela-rekey-id")
        .and_then(|v| v.to_str().ok());
    let (write_epoch, read_epoch) = crate::vault::rekey::resolve_write_epoch(
        &state,
        &session.user_id.to_string(),
        declared_epoch,
    )
    .await?;
    crate::vault::rekey::ensure_shadow_writer(
        &state,
        &session,
        write_epoch,
        read_epoch,
        rotation_id,
    )
    .await?;
    if write_epoch != read_epoch {
        crate::vault::enforce_rekey_shadow_quota(
            &state,
            &session.user_id.to_string(),
            write_epoch,
            &id,
            crate::db::encode_b64(&ciphertext).len() as u64,
        )
        .await?;
    } else {
        crate::vault::enforce_storage_quota(
            &state,
            &session.user_id.to_string(),
            body.len() as u64,
        )
        .await?;
    }

    if if_match == 0 {
        // Shadow writes (epoch above the served one, i.e. a rotation in
        // flight) must tolerate replays: a crashed initiator restarts and
        // re-uploads the same chunks. Upsert instead of create-or-conflict.
        let is_shadow = write_epoch != read_epoch;
        if is_shadow {
            let written = state.sqldb.execute(
                "INSERT INTO vault_chunks
                 (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
                 SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
                 WHERE id = ? AND key_epoch = ? AND rekey_state = 'freezing'
                   AND rekey_starter = ? AND rekey_id = ?
                 ON CONFLICT(user_id, chunk_id, epoch) DO UPDATE SET
                     version       = version + 1,
                     lamport_clock = excluded.lamport_clock,
                     last_writer   = excluded.last_writer,
                     ciphertext    = excluded.ciphertext,
                     updated_at    = excluded.updated_at",
                vec![
                    TursoValue::Text(id.clone()),
                    TursoValue::Text(session.user_id.to_string()),
                    TursoValue::Integer(lamport_clock),
                    TursoValue::Text(session.device_id.to_string()),
                    TursoValue::Text(crate::db::encode_b64(&ciphertext)),
                    TursoValue::Integer(write_epoch),
                    TursoValue::Text(now.clone()),
                    TursoValue::Text(now),
                    TursoValue::Text(session.user_id.to_string()),
                    TursoValue::Integer(read_epoch),
                    TursoValue::Text(session.device_id.to_string()),
                    TursoValue::Text(rotation_id.unwrap_or_default().to_string()),
                ],
            ).await.map_err(|e| AppError::Internal(e.to_string()))?;
            if written != 1 {
                return Err(AppError::Conflict(
                    "re-key was aborted or committed before the shadow write".into(),
                ));
            }
        } else {
            let existing = state
                .sqldb
                .query(
                    "SELECT 1 FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                    vec![
                        TursoValue::Text(id.clone()),
                        TursoValue::Text(session.user_id.to_string()),
                        TursoValue::Integer(write_epoch),
                    ],
                )
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            if existing.first().is_some() {
                return Err(AppError::Conflict(
                    "chunk already exists; use If-Match with current version to update".into(),
                ));
            }

            let inserted = state.sqldb.execute(
            "INSERT INTO vault_chunks
             (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
             SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(lamport_clock),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(crate::db::encode_b64(&ciphertext)),
                TursoValue::Integer(write_epoch),
                TursoValue::Text(now.clone()),
                TursoValue::Text(now),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(write_epoch),
            ],
        ).await.map_err(|e| {
            // A concurrent If-Match:0 request can win the race between the
            // "does it exist" check above and this INSERT; the unique index
            // then reports it as a constraint violation instead of a plain
            // error. Surface that as the same 409 the pre-check gives, not 500.
            if e.to_string().to_lowercase().contains("constraint")
                || e.to_string().to_lowercase().contains("unique")
                || e.to_string().to_lowercase().contains("duplicate")
            {
                AppError::Conflict(
                    "chunk already exists; use If-Match with current version to update".into(),
                )
            } else {
                AppError::Internal(e.to_string())
            }
        })?;
            if inserted != 1 {
                return Err(AppError::Rekeyed(
                    "vault epoch changed before the chunk write completed".into(),
                ));
            }
        }
    } else {
        let n = state
            .sqldb
            .execute(
                "UPDATE vault_chunks
             SET version       = version + 1,
                 lamport_clock = ?,
                 last_writer   = ?,
                 ciphertext    = ?,
                 updated_at    = ?
             WHERE chunk_id = ?
               AND user_id  = ?
               AND version  = ?
               AND epoch    = ?
               AND EXISTS (
                 SELECT 1 FROM users
                 WHERE users.id = vault_chunks.user_id
                   AND users.key_epoch = ? AND users.rekey_state IS NULL
               )",
                vec![
                    TursoValue::Integer(lamport_clock),
                    TursoValue::Text(session.device_id.to_string()),
                    TursoValue::Text(crate::db::encode_b64(&ciphertext)),
                    TursoValue::Text(now),
                    TursoValue::Text(id.clone()),
                    TursoValue::Text(session.user_id.to_string()),
                    TursoValue::Integer(if_match),
                    TursoValue::Integer(write_epoch),
                    TursoValue::Integer(write_epoch),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if n == 0 {
            ensure_write_state_unchanged(
                &state,
                &session.user_id.to_string(),
                declared_epoch,
                (write_epoch, read_epoch),
            )
            .await?;
            return Err(AppError::Conflict(
                "version mismatch — re-sync before retrying".into(),
            ));
        }
    }

    let ver_rows = state
        .sqldb
        .query(
            "SELECT version FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(write_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let new_version: i64 = ver_rows
        .first()
        .and_then(|r| r.i64(0))
        .ok_or_else(|| AppError::Internal("failed to read new version".into()))?;

    crate::vault::rekey::record_shadow_activity(
        &state,
        &session,
        write_epoch,
        read_epoch,
        rotation_id,
    )
    .await?;

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
    let id = crate::ids::validate_id("chunk_id", &id)?.to_string();
    let if_match: i64 = headers_in
        .get("if-match")
        .or_else(|| headers_in.get("If-Match"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest("If-Match header is required".into()))?;

    let declared_epoch = parse_declared_epoch(&headers_in)?;
    let (write_epoch, read_epoch) = crate::vault::rekey::resolve_write_epoch(
        &state,
        &session.user_id.to_string(),
        declared_epoch,
    )
    .await?;
    if write_epoch != read_epoch {
        return Err(AppError::Rekeyed(
            "chunk deletes are unavailable while a re-key is in progress".into(),
        ));
    }

    let rows = state
        .sqldb
        .query(
            "SELECT version FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(write_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let current_version: i64 = rows
        .first()
        .and_then(|r| r.i64(0))
        .ok_or_else(|| AppError::NotFound(format!("chunk {id} not found")))?;

    if current_version != if_match {
        return Err(AppError::Conflict(
            "version mismatch — re-sync before deleting".into(),
        ));
    }

    let deleted = state
        .sqldb
        .execute(
            "DELETE FROM vault_chunks
             WHERE chunk_id = ? AND user_id = ? AND epoch = ?
               AND EXISTS (
                 SELECT 1 FROM users
                 WHERE users.id = vault_chunks.user_id
                   AND users.key_epoch = ? AND users.rekey_state IS NULL
               )",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(write_epoch),
                TursoValue::Integer(write_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if deleted != 1 {
        return Err(AppError::Rekeyed(
            "vault epoch changed before the chunk delete completed".into(),
        ));
    }

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
