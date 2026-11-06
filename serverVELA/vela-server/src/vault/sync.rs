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
    /// Epoch whose rows are represented by this manifest. Web sessions cannot
    /// call the device-only epoch endpoint, so this is their authenticated
    /// source of truth for ciphertext AAD and write headers.
    pub epoch: i64,
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
    use vela_rekey_policy::executor::{classify_sync, plan_read_sync, ReadOutcome, SyncObservation};
    let plan = plan_read_sync(session.user_id.to_string(), read_epoch);
    let mut sql = crate::vault::sql::PoolSql(&state);
    let mut read_error: Option<anyhow::Error> = None;
    let rows = match crate::vault::sql::run_read(&mut sql, &plan).await {
        Ok(rows) => rows,
        Err(error) => {
            read_error = Some(error);
            Vec::new()
        }
    };
    let outcome = if read_error.is_some() {
        ReadOutcome::Failed
    } else {
        ReadOutcome::Rows(crate::vault::sql::sync_rows_view(&rows))
    };
    if let SyncObservation::Failed = classify_sync(&outcome) {
        return Err(AppError::Internal(match read_error {
            Some(error) => error.to_string(),
            None => "chunk manifest query failed".into(),
        }));
    }

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

    Ok((
        headers,
        Json(SyncManifest {
            epoch: read_epoch,
            chunks,
        }),
    ))
}
