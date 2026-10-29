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
    sqldb::{Db as _, TursoValue},
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
    /// Epoch under whose RMS-derived key these buckets were sealed. Optional
    /// only for legacy epoch-1 clients.
    #[serde(default)]
    pub epoch: Option<i64>,
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
    let tree_id = crate::ids::validate_id("tree_id", &tree_id)?.to_string();
    let indices = path_bucket_indices(query.height, leaf)?;
    let mut buckets = Vec::with_capacity(indices.len());

    // Serve only the account's current-epoch rows (re-keying design §5).
    let read_epoch = crate::vault::rekey::read_epoch(&state, &session.user_id.to_string()).await?;

    for bucket_index in indices {
        let rows = state
            .sqldb
            .query(
                "SELECT version, lamport_clock, last_writer, ciphertext
             FROM oram_buckets
             WHERE user_id = ? AND tree_id = ? AND bucket_index = ? AND epoch = ?",
                vec![
                    TursoValue::Text(session.user_id.to_string()),
                    TursoValue::Text(tree_id.clone()),
                    TursoValue::Integer(bucket_index as i64),
                    TursoValue::Integer(read_epoch),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if let Some(row) = rows.first() {
            let version = row
                .i64(0)
                .ok_or_else(|| AppError::Internal("expected integer".into()))?;
            let lamport_clock = row
                .i64(1)
                .ok_or_else(|| AppError::Internal("expected integer".into()))?;
            let last_writer = row.uuid(2);
            let ciphertext = row
                .text(3)
                .map(String::from)
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

/// The I/O behind `PUT /vault/oram/:tree_id/path/:leaf`.
struct PutOramIo<'a> {
    state: &'a AppState,
    session: &'a AuthSession,
    tree_id: String,
    user_id: String,
    buckets: Vec<PutOramBucket>,
    now: String,
    declared: Option<i64>,
    epoch: i64,
    read_epoch: i64,
    current_index: i64,
    responses: Vec<PutOramBucketResponse>,
    error: Option<AppError>,
}

impl PutOramIo<'_> {
    async fn resolve_path_epoch(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::RouteObservation {
        use vela_rekey_policy::vault_mutation_driver::RouteObservation as O;
        match crate::vault::rekey::resolve_write_epoch(self.state, &self.user_id, self.declared)
            .await
        {
            Ok((write_epoch, read_epoch)) if write_epoch == read_epoch => {
                self.epoch = write_epoch;
                self.read_epoch = read_epoch;
                O::Active { epoch: write_epoch }
            }
            Ok(_) => O::Freezing,
            Err(error @ AppError::Rekeyed(_)) => {
                self.error = Some(error);
                O::Rejected
            }
            Err(error) => {
                self.error = Some(error);
                O::Storage
            }
        }
    }

    async fn enforce_quota(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::QuotaObservation {
        use vela_rekey_policy::vault_mutation_driver::QuotaObservation as O;
        let incoming: u64 = self
            .buckets
            .iter()
            .map(|b| b.ciphertext.len() as u64)
            .sum();
        match crate::vault::enforce_storage_quota(self.state, &self.user_id, incoming).await {
            Ok(()) => O::Allowed,
            Err(error) => {
                let observation = if matches!(error, AppError::PayloadTooLarge(_)) {
                    O::Exceeded
                } else {
                    O::Storage
                };
                self.error = Some(error);
                observation
            }
        }
    }

    async fn write_bucket(
        &mut self,
        index: i64,
    ) -> vela_rekey_policy::vault_mutation_driver::BucketObservation {
        use vela_rekey_policy::vault_mutation_driver::BucketObservation as O;
        self.current_index = index;
        let bucket = match self.buckets.get(index as usize) {
            Some(bucket) => bucket,
            None => {
                self.error = Some(AppError::Internal("missing ORAM bucket".into()));
                return O::Storage;
            }
        };
        let ciphertext = match B64.decode(&bucket.ciphertext) {
            Ok(ciphertext) => ciphertext,
            Err(_) => {
                self.error = Some(AppError::BadRequest(
                    "bucket ciphertext is not valid base64".into(),
                ));
                return O::Invalid;
            }
        };
        if ciphertext.len() > self.state.config.max_chunk_bytes {
            self.error = Some(AppError::BadRequest(format!(
                "bucket exceeds maximum size of {} bytes",
                self.state.config.max_chunk_bytes
            )));
            return O::Invalid;
        }
        let bucket_index_i64 = match i64::try_from(bucket.bucket_index) {
            Ok(index) => index,
            Err(_) => {
                self.error = Some(AppError::BadRequest("bucket index too large".into()));
                return O::Invalid;
            }
        };
        let if_match = bucket.if_match;
        let lamport_clock = bucket.lamport_clock;
        let bucket_index = bucket.bucket_index;

        if if_match == 0 {
            let existing = self
                .state
                .sqldb
                .query(
                    "SELECT 1 FROM oram_buckets
                 WHERE user_id = ? AND tree_id = ? AND bucket_index = ? AND epoch = ?",
                    vec![
                        TursoValue::Text(self.user_id.clone()),
                        TursoValue::Text(self.tree_id.clone()),
                        TursoValue::Integer(bucket_index_i64),
                        TursoValue::Integer(self.epoch),
                    ],
                )
                .await;
            match existing {
                Err(error) => {
                    self.error = Some(AppError::Internal(error.to_string()));
                    return O::Storage;
                }
                Ok(rows) if rows.first().is_some() => return O::Existing,
                Ok(_) => {}
            }
            let inserted = self
                .state
                .sqldb
                .execute(
                    "INSERT INTO oram_buckets
                 (user_id, tree_id, bucket_index, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
                 SELECT ?, ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
                 WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
                    vec![
                        TursoValue::Text(self.user_id.clone()),
                        TursoValue::Text(self.tree_id.clone()),
                        TursoValue::Integer(bucket_index_i64),
                        TursoValue::Integer(lamport_clock),
                        TursoValue::Text(self.session.device_id.to_string()),
                        TursoValue::Text(crate::db::encode_b64(&ciphertext)),
                        TursoValue::Integer(self.epoch),
                        TursoValue::Text(self.now.clone()),
                        TursoValue::Text(self.now.clone()),
                        TursoValue::Text(self.user_id.clone()),
                        TursoValue::Integer(self.epoch),
                    ],
                )
                .await;
            match inserted {
                Err(error) => {
                    self.error = Some(AppError::Internal(error.to_string()));
                    O::Storage
                }
                Ok(1) => {
                    self.responses.push(PutOramBucketResponse {
                        bucket_index,
                        version: 1,
                    });
                    O::Written
                }
                Ok(_) => O::Skipped,
            }
        } else {
            let updated = self
                .state
                .sqldb
                .execute(
                    "UPDATE oram_buckets
                 SET version = version + 1,
                     lamport_clock = ?,
                     last_writer = ?,
                     ciphertext = ?,
                     updated_at = ?
                 WHERE user_id = ?
                   AND tree_id = ?
                   AND bucket_index = ?
                   AND version = ?
                   AND epoch = ?
                   AND EXISTS (
                     SELECT 1 FROM users
                     WHERE users.id = oram_buckets.user_id
                       AND users.key_epoch = ? AND users.rekey_state IS NULL
                   )",
                    vec![
                        TursoValue::Integer(lamport_clock),
                        TursoValue::Text(self.session.device_id.to_string()),
                        TursoValue::Text(crate::db::encode_b64(&ciphertext)),
                        TursoValue::Text(self.now.clone()),
                        TursoValue::Text(self.user_id.clone()),
                        TursoValue::Text(self.tree_id.clone()),
                        TursoValue::Integer(bucket_index_i64),
                        TursoValue::Integer(if_match),
                        TursoValue::Integer(self.epoch),
                        TursoValue::Integer(self.epoch),
                    ],
                )
                .await;
            match updated {
                Err(error) => {
                    self.error = Some(AppError::Internal(error.to_string()));
                    O::Storage
                }
                Ok(0) => O::Skipped,
                Ok(_) => {
                    self.responses.push(PutOramBucketResponse {
                        bucket_index,
                        version: if_match + 1,
                    });
                    O::Written
                }
            }
        }
    }

    async fn recheck_bucket(
        &mut self,
        _index: i64,
    ) -> vela_rekey_policy::vault_mutation_driver::BucketRecheckObservation {
        use vela_rekey_policy::vault_mutation_driver::BucketRecheckObservation as O;
        match crate::vault::rekey::resolve_write_epoch(self.state, &self.user_id, self.declared)
            .await
        {
            Ok(current) if current == (self.epoch, self.read_epoch) => O::Unchanged,
            Ok(_) => O::Changed,
            Err(error @ AppError::Rekeyed(_)) => {
                self.error = Some(error);
                O::Changed
            }
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Failed
            }
        }
    }

    async fn publish_path(&mut self) {
        self.state.vault_events.publish(
            self.session.user_id,
            self.session.device_id,
            self.epoch,
            crate::vault::events::VaultChangeKind::Oram,
        );
    }
}

pub async fn put_path(
    State(state): State<AppState>,
    Path((tree_id, leaf)): Path<(String, u64)>,
    session: AuthSession,
    Json(body): Json<PutOramPathRequest>,
) -> Result<(HeaderMap, Json<PutOramPathResponse>)> {
    use vela_rekey_policy::vault_mutation_driver::{
        OramEffect, OramFailure, OramRequest,
    };
    let tree_id = crate::ids::validate_id("tree_id", &tree_id)?.to_string();
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
    let mut create_mask = 0u64;
    for (index, bucket) in body.buckets.iter().enumerate() {
        if bucket.if_match == 0 && index < 64 {
            create_mask |= 1u64 << index;
        }
    }
    let bucket_count = body.buckets.len() as i64;
    let mut io = PutOramIo {
        state: &state,
        session: &session,
        tree_id,
        user_id: session.user_id.to_string(),
        buckets: body.buckets,
        now,
        declared: body.epoch,
        epoch: 0,
        read_epoch: 0,
        current_index: 0,
        responses: Vec::new(),
        error: None,
    };
    let transition = vela_rekey_policy::oram_interpreter!(
        io,
        OramRequest {
            authenticated: true,
            web: session.scope == crate::auth::token::TokenScope::WebSession,
            web_epoch: session.key_epoch,
            bucket_count,
            create_mask,
        },
        await
    );
    match transition.effect {
        OramEffect::Complete => {
            let mut headers = HeaderMap::new();
            maybe_append_new_token(&mut headers, &session);
            Ok((
                headers,
                Json(PutOramPathResponse {
                    buckets: io.responses,
                }),
            ))
        }
        OramEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(recorded.unwrap_or_else(|| match failure {
                OramFailure::Unauthenticated => {
                    AppError::Unauthorized("not authenticated".into())
                }
                OramFailure::EpochMismatch => {
                    AppError::Rekeyed("vault epoch changed before the ORAM write completed".into())
                }
                OramFailure::RekeyInProgress => AppError::Rekeyed(
                    "ORAM writes are unavailable while a re-key is in progress".into(),
                ),
                OramFailure::EpochStorage => {
                    AppError::Internal("vault epoch lookup failed".into())
                }
                OramFailure::AuthorityEpochMismatch => {
                    let authority_epoch = if session.scope == crate::auth::token::TokenScope::WebSession
                    {
                        session.key_epoch.unwrap_or(1)
                    } else {
                        transition.driver.epoch
                    };
                    AppError::Rekeyed(format!(
                        "caller authority is at vault epoch {authority_epoch}, not write epoch {}",
                        transition.driver.epoch
                    ))
                }
                OramFailure::QuotaExceeded => {
                    AppError::PayloadTooLarge("storage quota exceeded".into())
                }
                OramFailure::QuotaStorage => {
                    AppError::Internal("storage quota query failed".into())
                }
                OramFailure::BucketInvalid => {
                    AppError::BadRequest("invalid ORAM bucket".into())
                }
                OramFailure::BucketExists => AppError::Conflict(format!(
                    "ORAM bucket {} already exists",
                    transition.driver.written
                )),
                OramFailure::Rekeyed => {
                    AppError::Rekeyed("vault epoch changed before the ORAM write completed".into())
                }
                OramFailure::BucketStorage => {
                    AppError::Internal("ORAM bucket write failed".into())
                }
                OramFailure::VersionMismatch => AppError::Conflict(format!(
                    "ORAM bucket {} version mismatch",
                    transition.driver.recheck_index
                )),
                OramFailure::RecheckStorage => {
                    AppError::Internal("ORAM write state recheck failed".into())
                }
            }))
        }
        _ => Err(AppError::Internal(
            "ORAM path write did not reach a terminal decision".into(),
        )),
    }
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
