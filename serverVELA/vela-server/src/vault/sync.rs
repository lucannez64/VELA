use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

#[derive(Serialize)]
pub struct ChunkMeta {
    pub chunk_id: String,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
}

#[derive(Serialize)]
pub struct SyncManifest {
    pub chunks: Vec<ChunkMeta>,
}

pub async fn get_sync(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<SyncManifest>)> {
    // The manifest lists only the currently-served epoch's rows: a device that
    // has not yet adopted sees the pre-rotation world; after adopting (and
    // commit), it sees the new one — never a mix of both.
    let read_epoch = crate::vault::rekey::read_epoch(&state, &session.user_id.to_string()).await?;
    let rows = state
        .sqldb
        .query(
            "SELECT chunk_id, version, lamport_clock, last_writer
         FROM vault_chunks
         WHERE user_id = ? AND epoch = ?
         ORDER BY chunk_id",
            vec![
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(read_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let chunks: Vec<ChunkMeta> = rows
        .iter()
        .map(|row| {
            let m = crate::db::parse_chunk_manifest_row_turso(row)?;
            Ok(ChunkMeta {
                chunk_id: m.chunk_id,
                version: m.version,
                lamport_clock: m.lamport_clock,
                last_writer: m.last_writer,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(SyncManifest { chunks })))
}
