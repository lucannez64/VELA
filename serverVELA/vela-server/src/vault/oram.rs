use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

const MAX_ORAM_HEIGHT: u32 = 32;

#[derive(Deserialize)]
pub struct PathQuery {
    pub height: u32,
}

#[derive(Serialize)]
pub struct OramBucket {
    pub bucket_index: u64,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
    pub ciphertext: Option<String>,
}

#[derive(Serialize)]
pub struct OramPathResponse {
    pub tree_id: String,
    pub leaf: u64,
    pub height: u32,
    pub buckets: Vec<OramBucket>,
}

#[derive(Deserialize)]
pub struct PutOramPathRequest {
    pub height: u32,
    pub buckets: Vec<PutOramBucket>,
}

#[derive(Deserialize)]
pub struct PutOramBucket {
    pub bucket_index: u64,
    pub if_match: i64,
    pub lamport_clock: i64,
    pub ciphertext: String,
}

#[derive(Serialize)]
pub struct PutOramPathResponse {
    pub buckets: Vec<PutOramBucketResponse>,
}

#[derive(Serialize)]
pub struct PutOramBucketResponse {
    pub bucket_index: u64,
    pub version: i64,
}

pub async fn get_path(
    State(state): State<AppState>,
    Path((tree_id, leaf)): Path<(String, u64)>,
    Query(query): Query<PathQuery>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<OramPathResponse>)> {
    let indices = path_bucket_indices(query.height, leaf)?;
    let mut buckets = Vec::with_capacity(indices.len());

    for bucket_index in indices {
        let rows = state
            .db
            .query(
                "SELECT version, lamport_clock, last_writer, ciphertext
             FROM oram_buckets
             WHERE user_id = $1 AND tree_id = $2 AND bucket_index = $3",
                stoolap::params![
                    session.user_id.to_string(),
                    tree_id.clone(),
                    bucket_index as i64,
                ],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if let Some(row) = rows.into_iter().next() {
            let row = row.map_err(|e| AppError::Internal(e.to_string()))?;
            let version = crate::db::row_val(&row, 0)?
                .as_int64()
                .ok_or_else(|| AppError::Internal("expected integer".into()))?;
            let lamport_clock = crate::db::row_val(&row, 1)?
                .as_int64()
                .ok_or_else(|| AppError::Internal("expected integer".into()))?;
            let last_writer = {
                let v = crate::db::row_val(&row, 2)?;
                if v.is_null() {
                    None
                } else {
                    Some(
                        Uuid::parse_str(
                            v.as_str()
                                .ok_or_else(|| AppError::Internal("expected text uuid".into()))?,
                        )
                        .map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?,
                    )
                }
            };
            let ciphertext = crate::db::row_val(&row, 3)?
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| AppError::Internal("expected ciphertext".into()))?;
            buckets.push(OramBucket {
                bucket_index,
                version,
                lamport_clock,
                last_writer,
                ciphertext: Some(ciphertext),
            });
        } else {
            buckets.push(OramBucket {
                bucket_index,
                version: 0,
                lamport_clock: 0,
                last_writer: None,
                ciphertext: None,
            });
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(OramPathResponse {
            tree_id,
            leaf,
            height: query.height,
            buckets,
        }),
    ))
}

pub async fn put_path(
    State(state): State<AppState>,
    Path((tree_id, leaf)): Path<(String, u64)>,
    session: AuthSession,
    Json(body): Json<PutOramPathRequest>,
) -> Result<(HeaderMap, Json<PutOramPathResponse>)> {
    let expected_indices = path_bucket_indices(body.height, leaf)?;

    if body.buckets.len() != expected_indices.len() {
        return Err(AppError::BadRequest(format!(
            "expected {} buckets for ORAM path, got {}",
            expected_indices.len(),
            body.buckets.len()
        )));
    }

    for bucket in &body.buckets {
        if !expected_indices.contains(&bucket.bucket_index) {
            return Err(AppError::BadRequest(format!(
                "bucket {} is not on path leaf {} height {}",
                bucket.bucket_index, leaf, body.height
            )));
        }
    }

    let now = Utc::now().to_rfc3339();
    let mut updated = Vec::with_capacity(body.buckets.len());

    for bucket in body.buckets {
        let ciphertext = B64
            .decode(&bucket.ciphertext)
            .map_err(|_| AppError::BadRequest("bucket ciphertext is not valid base64".into()))?;
        if ciphertext.len() > state.config.max_chunk_bytes {
            return Err(AppError::BadRequest(format!(
                "bucket exceeds maximum size of {} bytes",
                state.config.max_chunk_bytes
            )));
        }

        let bucket_index_i64 = i64::try_from(bucket.bucket_index)
            .map_err(|_| AppError::BadRequest("bucket index too large".into()))?;
        let version = if bucket.if_match == 0 {
            let existing = state
                .db
                .query(
                    "SELECT 1 FROM oram_buckets
                 WHERE user_id = $1 AND tree_id = $2 AND bucket_index = $3",
                    stoolap::params![
                        session.user_id.to_string(),
                        tree_id.clone(),
                        bucket_index_i64,
                    ],
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;

            if existing.into_iter().next().is_some() {
                return Err(AppError::Conflict(format!(
                    "ORAM bucket {} already exists",
                    bucket.bucket_index
                )));
            }

            state.db.execute(
                "INSERT INTO oram_buckets
                 (user_id, tree_id, bucket_index, version, lamport_clock, last_writer, ciphertext, created_at, updated_at)
                 VALUES ($1, $2, $3, 1, $4, $5, $6, $7, $8)",
                stoolap::params![
                    session.user_id.to_string(),
                    tree_id.clone(),
                    bucket_index_i64,
                    bucket.lamport_clock,
                    session.device_id.to_string(),
                    crate::db::encode_b64(&ciphertext),
                    now.clone(),
                    now.clone(),
                ],
            ).map_err(|e| AppError::Internal(e.to_string()))?;
            1
        } else {
            let n: i64 = state
                .db
                .execute(
                    "UPDATE oram_buckets
                 SET version = version + 1,
                     lamport_clock = $1,
                     last_writer = $2,
                     ciphertext = $3,
                     updated_at = $4
                 WHERE user_id = $5
                   AND tree_id = $6
                   AND bucket_index = $7
                   AND version = $8",
                    stoolap::params![
                        bucket.lamport_clock,
                        session.device_id.to_string(),
                        crate::db::encode_b64(&ciphertext),
                        now.clone(),
                        session.user_id.to_string(),
                        tree_id.clone(),
                        bucket_index_i64,
                        bucket.if_match,
                    ],
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;

            if n == 0 {
                return Err(AppError::Conflict(format!(
                    "ORAM bucket {} version mismatch",
                    bucket.bucket_index
                )));
            }
            bucket.if_match + 1
        };

        updated.push(PutOramBucketResponse {
            bucket_index: bucket.bucket_index,
            version,
        });
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(PutOramPathResponse { buckets: updated })))
}

fn path_bucket_indices(height: u32, leaf: u64) -> Result<Vec<u64>> {
    if height > MAX_ORAM_HEIGHT {
        return Err(AppError::BadRequest(format!(
            "ORAM height exceeds maximum of {MAX_ORAM_HEIGHT}"
        )));
    }

    let leaves = 1u64
        .checked_shl(height)
        .ok_or_else(|| AppError::BadRequest("invalid ORAM height".into()))?;
    if leaf >= leaves {
        return Err(AppError::BadRequest(format!(
            "leaf {leaf} is outside tree with {leaves} leaves"
        )));
    }

    let mut indices = Vec::with_capacity(height as usize + 1);
    for level in 0..=height {
        let bucket = (1u64 << level) + (leaf >> (height - level));
        indices.push(bucket);
    }
    Ok(indices)
}
