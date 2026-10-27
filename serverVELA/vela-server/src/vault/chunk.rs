use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;

use vela_rekey_policy::{vault_upload_driver, Phase as PolicyPhase};

use crate::{
    auth::token::TokenScope,
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

/// The I/O behind `GET /vault/chunk/:id`. The driver decides which lookup runs
/// and whether the row may be served; each method only performs its effect and
/// reports the observation. A failed epoch read returns `None`, which the
/// driver turns into its `EpochStorage` verdict; the original error is kept for
/// the response.
struct GetChunkIo<'a> {
    state: &'a AppState,
    session: &'a AuthSession,
    id: String,
    /// The served epoch, established by the `ReadEpoch` effect.
    epoch: i64,
    chunk: Option<crate::db::ChunkRow>,
    error: Option<AppError>,
}

impl GetChunkIo<'_> {
    async fn read_epoch(&mut self) -> Option<vault_upload_driver::ReadEpochObservation> {
        match crate::vault::rekey::read_epoch(self.state, &self.session.user_id.to_string())
            .await
        {
            Ok(epoch) => {
                self.epoch = epoch;
                Some(vault_upload_driver::ReadEpochObservation { epoch })
            }
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    /// Serve only the account's current-epoch rows: shadow rows from an
    /// in-flight rotation belong to nobody until commit, and superseded rows
    /// are gone by the time anyone could ask (docs/VAULT_REKEYING_DESIGN.md §5).
    async fn lookup_chunk(&mut self) -> vault_upload_driver::ReadLookupObservation {
        let read_epoch = self.epoch;
        let rows = self
            .state
            .sqldb
            .query(
                "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch
         FROM vault_chunks
         WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                vec![
                    TursoValue::Text(self.id.clone()),
                    TursoValue::Text(self.session.user_id.to_string()),
                    TursoValue::Integer(read_epoch),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()));
        match rows {
            Err(error) => {
                self.error = Some(error);
                vault_upload_driver::ReadLookupObservation::QueryFailed
            }
            Ok(rows) => match rows.first() {
                None => vault_upload_driver::ReadLookupObservation::Missing,
                Some(row) => match crate::db::parse_chunk_row_turso(row) {
                    Ok(chunk) => {
                        let observation = vault_upload_driver::ReadLookupObservation::Found {
                            account_matches: chunk.user_id == self.session.user_id,
                            epoch_matches: row.i64(6) == Some(read_epoch),
                            version: chunk.version,
                            lamport_clock: chunk.lamport_clock,
                        };
                        self.chunk = Some(chunk);
                        observation
                    }
                    Err(error) => {
                        self.error = Some(error);
                        vault_upload_driver::ReadLookupObservation::Malformed
                    }
                },
            },
        }
    }
}

fn read_failure_error(
    failure: vela_rekey_policy::vault_upload_driver::ReadFailure,
    id: &str,
) -> AppError {
    use vela_rekey_policy::vault_upload_driver::ReadFailure as F;
    match failure {
        F::Unauthenticated => AppError::Unauthorized("not authenticated".into()),
        F::InvalidEpoch => AppError::Internal("invalid vault read epoch".into()),
        F::EpochStorage => AppError::Internal("vault epoch lookup failed".into()),
        F::NotFound => AppError::NotFound(format!("chunk {id} not found")),
        F::QueryStorage => AppError::Internal("chunk lookup failed".into()),
        F::ParseStorage => AppError::Internal("chunk row could not be decoded".into()),
        F::ScopeViolation => {
            AppError::Internal("chunk row outside the request's account/epoch scope".into())
        }
    }
}

pub async fn get_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
) -> Result<impl IntoResponse> {
    let id = crate::ids::validate_id("chunk_id", &id)?.to_string();
    let mut io = GetChunkIo {
        state: &state,
        session: &session,
        id: id.clone(),
        epoch: 0,
        chunk: None,
        error: None,
    };
    // The proved loop: the driver emits the served-epoch read and the row
    // lookup in that order, and nothing after its verdict.
    let transition = vela_rekey_policy::read_interpreter!(
        io,
        vault_upload_driver::ReadRequest { authenticated: true },
        await
    );

    let (version, lamport_clock) = match transition.effect {
        vault_upload_driver::ReadEffect::Serve {
            version,
            lamport_clock,
        } => (version, lamport_clock),
        vault_upload_driver::ReadEffect::Fail(failure) => {
            let recorded = io.error.take();
            return Err(recorded.unwrap_or_else(|| read_failure_error(failure, &io.id)));
        }
        _ => return Err(AppError::Internal("unexpected chunk read decision".into())),
    };

    let chunk = io
        .chunk
        .take()
        .ok_or_else(|| AppError::Internal("missing chunk row".into()))?;
    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    headers.insert("X-Chunk-Version", version.to_string().parse().unwrap());
    headers.insert("X-Lamport-Clock", lamport_clock.to_string().parse().unwrap());
    if let Some(lw) = chunk.last_writer {
        headers.insert("X-Last-Writer", lw.to_string().parse().unwrap());
    }
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );

    Ok((StatusCode::OK, headers, chunk.ciphertext))
}

/// The I/O behind `PUT /vault/chunk/:id`. The driver decides which effect runs
/// and when (through the shared `upload_interpreter!` loop, proved in F* as
/// `run_upload`); each method only performs its effect and reports the
/// observation. Lookups that fail return the storage-failure observation and
/// keep the original error for the response.
struct PutChunkIo<'a> {
    state: &'a AppState,
    session: &'a AuthSession,
    id: String,
    user_id: String,
    if_match: i64,
    lamport_clock: i64,
    ciphertext: Vec<u8>,
    now: String,
    declared_epoch: Option<i64>,
    rotation_id: Option<String>,
    /// The resolved route, established by the `ResolveEpoch` effect (and
    /// re-stated by the write permit).
    write_epoch: i64,
    read_epoch: i64,
    shadow: bool,
    error: Option<AppError>,
}

impl PutChunkIo<'_> {
    fn fail(&mut self, error: impl ToString) {
        if self.error.is_none() {
            self.error = Some(AppError::Internal(error.to_string()));
        }
    }

    async fn resolve_epoch(&mut self) -> vault_upload_driver::RekeyObservation {
        match crate::vault::rekey::resolve_write_epoch(
            self.state,
            &self.user_id,
            self.declared_epoch,
        )
        .await
        {
            Ok((write_epoch, read_epoch)) => {
                let phase = if write_epoch == read_epoch {
                    PolicyPhase::Active
                } else {
                    PolicyPhase::Freezing
                };
                self.write_epoch = write_epoch;
                self.read_epoch = read_epoch;
                self.shadow = write_epoch != read_epoch;
                vault_upload_driver::RekeyObservation::State {
                    epoch: read_epoch,
                    phase,
                }
            }
            Err(error) => {
                self.error = Some(error);
                vault_upload_driver::RekeyObservation::Rejected
            }
        }
    }

    /// Shadow writes must come from the device that started the rotation. The
    /// load can fail; `None` is the driver's `AttemptStorage` observation.
    async fn authorize_shadow(
        &mut self,
    ) -> Option<vela_rekey_policy::AttemptAuthority> {
        match crate::vault::rekey::shadow_authority(
            self.state,
            self.session,
            self.rotation_id.as_deref(),
        )
        .await
        {
            Ok(authority) => Some(authority),
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    async fn enforce_quota(&mut self) -> vault_upload_driver::QuotaObservation {
        let quota_result = if self.shadow {
            crate::vault::enforce_rekey_shadow_quota(
                self.state,
                &self.user_id,
                self.write_epoch,
                &self.id,
                crate::db::encode_b64(&self.ciphertext).len() as u64,
            )
            .await
        } else {
            crate::vault::enforce_storage_quota(
                self.state,
                &self.user_id,
                self.ciphertext.len() as u64,
            )
            .await
        };
        match quota_result {
            Ok(()) => vault_upload_driver::QuotaObservation::Allowed,
            Err(error) => {
                let observation = if matches!(error, AppError::PayloadTooLarge(_)) {
                    vault_upload_driver::QuotaObservation::Exceeded
                } else {
                    vault_upload_driver::QuotaObservation::StorageFailed
                };
                self.error = Some(error);
                observation
            }
        }
    }

    /// Exactly one guarded insert/update with the permit the driver emitted.
    async fn guarded_write(
        &mut self,
        permit: vault_upload_driver::UploadWritePermit,
    ) -> vault_upload_driver::WriteObservation {
        let write_epoch = permit.write_epoch;
        let read_epoch = permit.read_epoch;
        let is_shadow = permit.shadow;
        self.write_epoch = write_epoch;
        self.read_epoch = read_epoch;
        self.shadow = is_shadow;
        if self.if_match == 0 {
            if is_shadow {
                // Shadow writes (epoch above the served one, i.e. a rotation in
                // flight) must tolerate replays: a crashed initiator restarts and
                // re-uploads the same chunks. Upsert instead of create-or-conflict.
                let written = self.state.sqldb.execute(
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
                        TursoValue::Text(self.id.clone()),
                        TursoValue::Text(self.user_id.clone()),
                        TursoValue::Integer(self.lamport_clock),
                        TursoValue::Text(self.session.device_id.to_string()),
                        TursoValue::Text(crate::db::encode_b64(&self.ciphertext)),
                        TursoValue::Integer(write_epoch),
                        TursoValue::Text(self.now.clone()),
                        TursoValue::Text(self.now.clone()),
                        TursoValue::Text(self.user_id.clone()),
                        TursoValue::Integer(read_epoch),
                        TursoValue::Text(self.session.device_id.to_string()),
                        TursoValue::Text(self.rotation_id.clone().unwrap_or_default()),
                    ],
                ).await;
                return match written {
                    Ok(1) => vault_upload_driver::WriteObservation::Inserted,
                    Ok(_) => vault_upload_driver::WriteObservation::Skipped,
                    Err(error) => {
                        self.fail(error);
                        vault_upload_driver::WriteObservation::Failed
                    }
                };
            }
            let existing = self
                .state
                .sqldb
                .query(
                    "SELECT 1 FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                    vec![
                        TursoValue::Text(self.id.clone()),
                        TursoValue::Text(self.user_id.clone()),
                        TursoValue::Integer(write_epoch),
                    ],
                )
                .await;
            match existing {
                Err(error) => {
                    self.fail(error);
                    return vault_upload_driver::WriteObservation::Failed;
                }
                Ok(rows) if rows.first().is_some() => {
                    return vault_upload_driver::WriteObservation::Existing;
                }
                Ok(_) => {}
            }

            let inserted = self.state.sqldb.execute(
            "INSERT INTO vault_chunks
             (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
             SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            vec![
                TursoValue::Text(self.id.clone()),
                TursoValue::Text(self.user_id.clone()),
                TursoValue::Integer(self.lamport_clock),
                TursoValue::Text(self.session.device_id.to_string()),
                TursoValue::Text(crate::db::encode_b64(&self.ciphertext)),
                TursoValue::Integer(write_epoch),
                TursoValue::Text(self.now.clone()),
                TursoValue::Text(self.now.clone()),
                TursoValue::Text(self.user_id.clone()),
                TursoValue::Integer(permit.permit_epoch),
            ],
        ).await;
            return match inserted {
                Ok(1) => vault_upload_driver::WriteObservation::Inserted,
                Ok(_) => vault_upload_driver::WriteObservation::Skipped,
                Err(error) => {
                    // A concurrent If-Match:0 request can win the race between
                    // the "does it exist" check above and this INSERT; the
                    // unique index then reports it as a constraint violation
                    // instead of a plain error. Surface that as the same 409 the
                    // pre-check gives, not 500.
                    let message = error.to_string().to_lowercase();
                    if message.contains("constraint")
                        || message.contains("unique")
                        || message.contains("duplicate")
                    {
                        vault_upload_driver::WriteObservation::Duplicate
                    } else {
                        self.fail(error);
                        vault_upload_driver::WriteObservation::Failed
                    }
                }
            };
        }

        let updated = self
            .state
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
                    TursoValue::Integer(self.lamport_clock),
                    TursoValue::Text(self.session.device_id.to_string()),
                    TursoValue::Text(crate::db::encode_b64(&self.ciphertext)),
                    TursoValue::Text(self.now.clone()),
                    TursoValue::Text(self.id.clone()),
                    TursoValue::Text(self.user_id.clone()),
                    TursoValue::Integer(self.if_match),
                    TursoValue::Integer(write_epoch),
                    TursoValue::Integer(permit.permit_epoch),
                ],
            )
            .await;
        match updated {
            Err(error) => {
                self.fail(error);
                vault_upload_driver::WriteObservation::Failed
            }
            Ok(0) => vault_upload_driver::WriteObservation::Skipped,
            Ok(_) => vault_upload_driver::WriteObservation::Updated,
        }
    }

    /// Re-resolve the route after a zero-row update, to tell a stale version
    /// apart from a rotation that moved underneath the write.
    async fn recheck_state(&mut self) -> vault_upload_driver::RecheckObservation {
        match crate::vault::rekey::resolve_write_epoch(
            self.state,
            &self.user_id,
            self.declared_epoch,
        )
        .await
        {
            Ok(current) if current == (self.write_epoch, self.read_epoch) => {
                vault_upload_driver::RecheckObservation::Unchanged
            }
            Ok(_) => vault_upload_driver::RecheckObservation::Changed,
            Err(error @ AppError::Rekeyed(_)) => {
                self.error = Some(error);
                vault_upload_driver::RecheckObservation::Changed
            }
            Err(error) => {
                self.fail(error);
                vault_upload_driver::RecheckObservation::Failed
            }
        }
    }

    /// Read back the committed version.
    async fn reread_version(&mut self) -> vault_upload_driver::RereadObservation {
        let ver_rows = self
            .state
            .sqldb
            .query(
                "SELECT version FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                vec![
                    TursoValue::Text(self.id.clone()),
                    TursoValue::Text(self.user_id.clone()),
                    TursoValue::Integer(self.write_epoch),
                ],
            )
            .await;
        match ver_rows {
            Err(error) => {
                self.fail(error);
                vault_upload_driver::RereadObservation::Failed
            }
            Ok(rows) => match rows.first().and_then(|r| r.i64(0)) {
                Some(version) => vault_upload_driver::RereadObservation::Read { version },
                None => vault_upload_driver::RereadObservation::Missing,
            },
        }
    }

    /// Refresh the rotation deadline after a shadow write.
    async fn record_shadow_activity(&mut self) -> vault_upload_driver::ActivityObservation {
        match crate::vault::rekey::record_shadow_activity(
            self.state,
            self.session,
            self.write_epoch,
            self.read_epoch,
            self.rotation_id.as_deref(),
        )
        .await
        {
            Ok(true) => vault_upload_driver::ActivityObservation::Refreshed,
            Ok(false) => vault_upload_driver::ActivityObservation::Ended,
            Err(error) => {
                self.error = Some(error);
                vault_upload_driver::ActivityObservation::Failed
            }
        }
    }

    /// Let the account's other devices know a write landed. Shadow writes
    /// (epoch above the served one) are invisible to readers, so they stay
    /// silent until the commit publishes the epoch change.
    async fn publish(&mut self) {
        if !self.shadow {
            self.state.vault_events.publish(
                self.session.user_id,
                self.session.device_id,
                self.write_epoch,
                crate::vault::events::VaultChangeKind::Chunk,
            );
        }
    }
}

pub async fn put_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
    headers_in: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let _schema_guard = crate::vault::schema::lock(&session.user_id.to_string()).await;
    crate::vault::schema::check_write(&state, &session.user_id.to_string(), &headers_in)?;
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
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let user_id = session.user_id.to_string();

    let intent = if if_match == 0 {
        vault_upload_driver::WriteIntent::Create
    } else {
        vault_upload_driver::WriteIntent::Replace { version: if_match }
    };
    // One account id scopes the epoch resolution, the shadow attempt, the
    // quota, the guarded statement, the read-back and the publication. The
    // driver re-checks the writer's authority so a rewired caller cannot
    // authorize a write for another account or epoch.
    let request = vault_upload_driver::UploadRequest {
        writer: vault_upload_driver::UploadWriter {
            authenticated: true,
            web: session.scope == TokenScope::WebSession,
            web_epoch: session.key_epoch,
        },
        intent,
        declared_epoch,
    };
    let mut io = PutChunkIo {
        state: &state,
        session: &session,
        id,
        user_id,
        if_match,
        lamport_clock,
        ciphertext,
        now,
        declared_epoch,
        rotation_id,
        write_epoch: 0,
        read_epoch: 0,
        shadow: false,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_rekey_policy::upload_interpreter!(io, request, await);

    match transition.effect {
        vault_upload_driver::UploadEffect::Complete => {
            let new_version = transition.driver.version;
            let mut resp_headers = HeaderMap::new();
            maybe_append_new_token(&mut resp_headers, &session);
            resp_headers.insert("X-Chunk-Version", new_version.to_string().parse().unwrap());

            Ok((
                StatusCode::OK,
                resp_headers,
                Json(serde_json::json!({ "version": new_version })),
            ))
        }
        vault_upload_driver::UploadEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(recorded.unwrap_or_else(|| upload_error(failure, &transition.driver)))
        }
        _ => Err(AppError::Internal(
            "upload did not reach a terminal decision".into(),
        )),
    }
}

fn upload_error(
    failure: vela_rekey_policy::vault_upload_driver::UploadFailure,
    driver: &vela_rekey_policy::vault_upload_driver::UploadDriver,
) -> AppError {
    use vela_rekey_policy::vault_upload_driver::UploadFailure as F;
    match failure {
        F::Unauthenticated => AppError::Unauthorized("not authenticated".into()),
        F::EpochMismatch => {
            AppError::Rekeyed("vault epoch changed before the chunk write completed".into())
        }
        F::ShadowWebSessionForbidden => {
            AppError::Forbidden("temporary web sessions cannot write re-key shadows".into())
        }
        F::ShadowRotationIdRequired => {
            AppError::BadRequest("X-Vela-Rekey-Id header is required for shadow writes".into())
        }
        F::ShadowStarterForbidden => {
            AppError::Forbidden("only the device which started this re-key may write shadows".into())
        }
        F::AttemptStorage => AppError::Internal("re-key attempt lookup failed".into()),
        F::AuthorityEpochMismatch => AppError::Rekeyed(format!(
            "caller authority is at vault epoch {}, not write epoch {}",
            driver.authority_epoch, driver.write_epoch
        )),
        F::QuotaExceeded => AppError::PayloadTooLarge("storage quota exceeded".into()),
        F::QuotaStorage => AppError::Internal("storage quota query failed".into()),
        F::AlreadyExists => AppError::Conflict(
            "chunk already exists; use If-Match with current version to update".into(),
        ),
        F::RekeyEnded => AppError::Conflict(
            "re-key was aborted or committed before the shadow write".into(),
        ),
        F::VersionMismatch => {
            AppError::Conflict("version mismatch — re-sync before retrying".into())
        }
        F::Rekeyed => {
            AppError::Rekeyed("vault epoch changed before the chunk write completed".into())
        }
        F::WriteStorage => AppError::Internal("chunk write failed".into()),
        F::RecheckStorage => AppError::Internal("chunk write state recheck failed".into()),
        F::RereadStorage => AppError::Internal("failed to read new version".into()),
        F::ActivityStorage => AppError::Internal("shadow activity refresh failed".into()),
    }
}

pub async fn delete_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
    headers_in: HeaderMap,
) -> Result<impl IntoResponse> {
    let _schema_guard = crate::vault::schema::lock(&session.user_id.to_string()).await;
    crate::vault::schema::check_write(&state, &session.user_id.to_string(), &headers_in)?;
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
    let mutation_permit = session.write_mutation_permit(write_epoch)?;

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
                TursoValue::Integer(mutation_permit.epoch()),
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

    state.vault_events.publish(
        session.user_id,
        session.device_id,
        write_epoch,
        crate::vault::events::VaultChangeKind::Chunk,
    );

    let mut resp_headers = HeaderMap::new();
    maybe_append_new_token(&mut resp_headers, &session);

    Ok((
        StatusCode::OK,
        resp_headers,
        Json(serde_json::json!({ "deleted": true, "version": current_version })),
    ))
}
