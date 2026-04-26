use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
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
    let rows = state
        .db
        .query(
            "SELECT chunk_id, version, lamport_clock, last_writer
         FROM vault_chunks
         WHERE user_id = $1
         ORDER BY chunk_id",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let chunks: Vec<ChunkMeta> = rows
        .map(|r| {
            let row = r.map_err(|e| AppError::Internal(e.to_string()))?;
            let m = crate::db::parse_chunk_manifest_row(&row)?;
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
