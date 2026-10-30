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
        use vela_rekey_policy::executor::{classify_chunk_read, plan_read_chunk, ReadOutcome};
        let read_epoch = self.epoch;
        let caller = self.session.user_id.to_string();
        let plan = plan_read_chunk(self.id.clone(), caller.clone(), read_epoch);
        let mut sql = crate::vault::sql::PoolSql(self.state);
        let rows = match crate::vault::sql::run_read(&mut sql, &plan).await {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return classify_chunk_read(&caller, read_epoch, false, &ReadOutcome::Failed);
            }
            Ok(rows) => rows,
        };
        let view = crate::vault::sql::chunk_row_view(&rows);
        match rows.first() {
            None => classify_chunk_read(&caller, read_epoch, false, &ReadOutcome::Rows(view)),
            Some(raw) => match crate::db::parse_chunk_row_turso(raw) {
                Ok(chunk) => {
                    self.chunk = Some(chunk);
                    classify_chunk_read(&caller, read_epoch, false, &ReadOutcome::Rows(view))
                }
                Err(error) => {
                    self.error = Some(error);
                    classify_chunk_read(&caller, read_epoch, true, &ReadOutcome::Rows(view))
                }
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

    /// Records the failure that stopped the plan, keeping the historical error
    /// shape: a SQL error becomes `Internal(text)`, a store error is kept as is.
    fn record(&mut self, error: crate::vault::sql::RunError) {
        match error {
            crate::vault::sql::RunError::Sql(error) => self.fail(error),
            crate::vault::sql::RunError::Store(error) => {
                if self.error.is_none() {
                    self.error = Some(error);
                }
            }
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
        permit: vela_rekey_policy::vault_upload_driver::UploadWritePermit,
    ) -> vela_rekey_policy::vault_upload_driver::WriteObservation {
        use vela_rekey_policy::executor::{
            classify_chunk_create, classify_chunk_shadow, classify_chunk_update,
            plan_chunk_create, plan_chunk_exists, plan_chunk_shadow, plan_chunk_update,
            ReadOutcome,
        };
        let write_epoch = permit.write_epoch;
        let read_epoch = permit.read_epoch;
        let is_shadow = permit.shadow;
        self.write_epoch = write_epoch;
        self.read_epoch = read_epoch;
        self.shadow = is_shadow;
        let id = self.id.clone();
        let user = self.user_id.clone();
        let writer = self.session.device_id.to_string();
        let ciphertext = crate::db::encode_b64(&self.ciphertext);
        let now = self.now.clone();
        let lamport_clock = self.lamport_clock;
        let mut sql = crate::vault::sql::PoolSql(self.state);
        if self.if_match == 0 {
            if is_shadow {
                // Shadow writes (epoch above the served one, i.e. a rotation in
                // flight) must tolerate replays: a crashed initiator restarts and
                // re-uploads the same chunks. Upsert instead of create-or-conflict.
                let plan = plan_chunk_shadow(
                    id,
                    user,
                    lamport_clock,
                    writer.clone(),
                    ciphertext,
                    write_epoch,
                    now,
                    read_epoch,
                    writer,
                    self.rotation_id.clone().unwrap_or_default(),
                );
                let (outcomes, error) = crate::vault::sql::run_writes(&mut sql, &plan).await;
                if let Some(error) = error {
                    self.record(error);
                }
                return classify_chunk_shadow(&outcomes);
            }
            let probe_stmt = plan_chunk_exists(id.clone(), user.clone(), write_epoch);
            let probe = match crate::vault::sql::run_read(&mut sql, &probe_stmt).await {
                Err(error) => {
                    self.fail(error);
                    ReadOutcome::Failed
                }
                Ok(rows) => ReadOutcome::Rows(crate::vault::sql::exists_view(&rows)),
            };
            if !matches!(probe, ReadOutcome::Rows(false)) {
                return classify_chunk_create(&probe, false, &[]);
            }
            let plan = plan_chunk_create(
                id,
                user,
                lamport_clock,
                writer,
                ciphertext,
                write_epoch,
                now,
                permit.permit_epoch,
            );
            let (outcomes, error) = crate::vault::sql::run_writes(&mut sql, &plan).await;
            // A concurrent If-Match:0 request can win the race between the
            // "does it exist" check above and the INSERT; the unique index then
            // reports it as a constraint violation instead of a plain error.
            // Surface that as the same 409 the pre-check gives, not 500.
            let duplicate = match &error {
                Some(crate::vault::sql::RunError::Sql(error)) => {
                    let message = error.to_string().to_lowercase();
                    message.contains("constraint")
                        || message.contains("unique")
                        || message.contains("duplicate")
                }
                _ => false,
            };
            if let Some(error) = error {
                if !duplicate {
                    self.record(error);
                }
            }
            return classify_chunk_create(&probe, duplicate, &outcomes);
        }
        let plan = plan_chunk_update(
            id,
            user,
            self.if_match,
            lamport_clock,
            writer,
            ciphertext,
            write_epoch,
            now,
            permit.permit_epoch,
        );
        let (outcomes, error) = crate::vault::sql::run_writes(&mut sql, &plan).await;
        if let Some(error) = error {
            self.record(error);
        }
        classify_chunk_update(&outcomes)
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
        use vela_rekey_policy::executor::{classify_reread, plan_reread_version, ReadOutcome};
        let plan =
            plan_reread_version(self.id.clone(), self.user_id.clone(), self.write_epoch);
        let mut sql = crate::vault::sql::PoolSql(self.state);
        let outcome = match crate::vault::sql::run_read(&mut sql, &plan).await {
            Err(error) => {
                self.fail(error);
                ReadOutcome::Failed
            }
            Ok(rows) => ReadOutcome::Rows(crate::vault::sql::version_view(&rows)),
        };
        classify_reread(&outcome)
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

/// The I/O behind `DELETE /vault/chunk/:id`.
struct DeleteChunkIo<'a> {
    state: &'a AppState,
    session: &'a AuthSession,
    id: String,
    user_id: String,
    declared_epoch: Option<i64>,
    headers: &'a HeaderMap,
    epoch: i64,
    error: Option<AppError>,
}

impl DeleteChunkIo<'_> {
    async fn check_schema(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::SchemaObservation {
        use vela_rekey_policy::vault_mutation_driver::SchemaObservation as O;
        match crate::vault::schema::check_write(self.state, &self.user_id, self.headers) {
            Ok(()) => O::Allowed,
            Err(error) => {
                self.error = Some(error);
                O::Refused
            }
        }
    }

    async fn resolve_epoch(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::RouteObservation {
        use vela_rekey_policy::vault_mutation_driver::RouteObservation as O;
        match crate::vault::rekey::resolve_write_epoch(
            self.state,
            &self.user_id,
            self.declared_epoch,
        )
        .await
        {
            Ok((write_epoch, read_epoch)) if write_epoch == read_epoch => {
                self.epoch = write_epoch;
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

    async fn read_version(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::VersionObservation {
        use vela_rekey_policy::executor::{classify_version, plan_read_version, ReadOutcome};
        let plan = plan_read_version(self.id.clone(), self.user_id.clone(), self.epoch);
        let mut sql = crate::vault::sql::PoolSql(self.state);
        let outcome = match crate::vault::sql::run_read(&mut sql, &plan).await {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                ReadOutcome::Failed
            }
            Ok(rows) => ReadOutcome::Rows(crate::vault::sql::version_view(&rows)),
        };
        classify_version(&outcome)
    }

    async fn delete_row(&mut self) -> vela_rekey_policy::vault_mutation_driver::DeleteObservation {
        use vela_rekey_policy::executor::{classify_delete, plan_delete_chunk};
        let plan = plan_delete_chunk(self.id.clone(), self.user_id.clone(), self.epoch);
        let mut sql = crate::vault::sql::PoolSql(self.state);
        let (outcomes, error) = crate::vault::sql::run_writes(&mut sql, &plan).await;
        if let Some(error) = error {
            self.error = Some(error.into_internal());
        }
        classify_delete(&outcomes)
    }

    async fn publish(&mut self) {
        self.state.vault_events.publish(
            self.session.user_id,
            self.session.device_id,
            self.epoch,
            crate::vault::events::VaultChangeKind::Chunk,
        );
    }
}

pub async fn delete_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
    headers_in: HeaderMap,
) -> Result<impl IntoResponse> {
    use vela_rekey_policy::vault_mutation_driver::{
        ChunkDeleteEffect, ChunkDeleteFailure, ChunkDeleteRequest,
    };
    let _schema_guard = crate::vault::schema::lock(&session.user_id.to_string()).await;
    let id = crate::ids::validate_id("chunk_id", &id)?.to_string();
    let if_match: i64 = headers_in
        .get("if-match")
        .or_else(|| headers_in.get("If-Match"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest("If-Match header is required".into()))?;

    let declared_epoch = parse_declared_epoch(&headers_in)?;
    let mut io = DeleteChunkIo {
        state: &state,
        session: &session,
        id: id.clone(),
        user_id: session.user_id.to_string(),
        declared_epoch,
        headers: &headers_in,
        epoch: 0,
        error: None,
    };
    let transition = vela_rekey_policy::chunk_delete_interpreter!(
        io,
        ChunkDeleteRequest {
            authenticated: true,
            web: session.scope == TokenScope::WebSession,
            web_epoch: session.key_epoch,
            if_match,
        },
        await
    );
    match transition.effect {
        ChunkDeleteEffect::Complete => {
            let current_version = transition.driver.current_version;
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
        ChunkDeleteEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(recorded.unwrap_or_else(|| match failure {
                ChunkDeleteFailure::Unauthenticated => {
                    AppError::Unauthorized("not authenticated".into())
                }
                ChunkDeleteFailure::SchemaRefused => {
                    AppError::Conflict("This vault uses folders and richer fields. Upgrade this client before syncing changes.".into())
                }
                ChunkDeleteFailure::SchemaStorage => {
                    AppError::Internal("Invalid vault schema floor".into())
                }
                ChunkDeleteFailure::EpochMismatch => {
                    AppError::Rekeyed("vault epoch changed before the chunk delete completed".into())
                }
                ChunkDeleteFailure::RekeyInProgress => AppError::Rekeyed(
                    "chunk deletes are unavailable while a re-key is in progress".into(),
                ),
                ChunkDeleteFailure::EpochStorage => {
                    AppError::Internal("vault epoch lookup failed".into())
                }
                ChunkDeleteFailure::AuthorityEpochMismatch => AppError::Rekeyed(
                    "caller authority epoch does not match the vault epoch".into(),
                ),
                ChunkDeleteFailure::NotFound => {
                    AppError::NotFound(format!("chunk {id} not found"))
                }
                ChunkDeleteFailure::VersionMismatch => {
                    AppError::Conflict("version mismatch — re-sync before deleting".into())
                }
                ChunkDeleteFailure::Rekeyed => AppError::Rekeyed(
                    "vault epoch changed before the chunk delete completed".into(),
                ),
                ChunkDeleteFailure::DeleteStorage => {
                    AppError::Internal("chunk delete failed".into())
                }
            }))
        }
        _ => Err(AppError::Internal(
            "chunk delete did not reach a terminal decision".into(),
        )),
    }
}
