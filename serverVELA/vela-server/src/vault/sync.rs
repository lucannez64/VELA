//! GET /vault/sync
//!
//! Returns the sync manifest for all vault chunks belonging to the
//! authenticated user:
//!
//! ```json
//! {
//!   "chunks": [
//!     { "chunk_id": "<uuid>", "version": 3, "lamport_clock": 7, "last_writer": "<uuid>" },
//!     ...
//!   ]
//! }
//! ```
//!
//! The client uses this to determine which chunks to download (server version
//! ahead of local) and which to upload (local Lamport clock ahead of server).
//! Conflict detection is done client-side by comparing the three fields
//! against locally cached last-seen values (see SPEC §5.3).

use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    error::Result,
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

#[derive(Serialize)]
pub struct ChunkMeta {
    pub chunk_id:      Uuid,
    pub version:       i64,
    pub lamport_clock: i64,
    pub last_writer:   Option<Uuid>,
}

#[derive(Serialize)]
pub struct SyncManifest {
    pub chunks: Vec<ChunkMeta>,
}

pub async fn get_sync(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<SyncManifest>)> {
    let rows = sqlx::query_as::<_, crate::db::ChunkManifestRow>(
        "SELECT chunk_id, version, lamport_clock, last_writer
         FROM vault_chunks
         WHERE user_id = $1
         ORDER BY chunk_id",
    )
    .bind(session.user_id)
    .fetch_all(&state.db)
    .await?;

    let chunks = rows
        .into_iter()
        .map(|r| ChunkMeta {
            chunk_id:      r.chunk_id,
            version:       r.version,
            lamport_clock: r.lamport_clock,
            last_writer:   r.last_writer,
        })
        .collect();

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(SyncManifest { chunks })))
}
