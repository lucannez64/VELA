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

pub async fn get_chunk(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: AuthSession,
) -> Result<impl IntoResponse> {
    let id = crate::ids::validate_id("chunk_id", &id)?.to_string();
    let mut decision = vault_upload_driver::begin_read(vault_upload_driver::ReadRequest {
        authenticated: true,
    });
    // Serve only the account's current-epoch rows: shadow rows from an
    // in-flight rotation belong to nobody until commit, and superseded rows
    // are gone by the time anyone could ask (docs/VAULT_REKEYING_DESIGN.md §5).
    let read_epoch = crate::vault::rekey::read_epoch(&state, &session.user_id.to_string()).await?;
    decision = vault_upload_driver::on_read_epoch(
        decision.driver,
        vault_upload_driver::ReadEpochObservation {
            epoch: read_epoch,
        },
    );
    let rows = state
        .sqldb
        .query(
            "SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch
         FROM vault_chunks
         WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(read_epoch),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()));

    let mut parsed = None;
    let mut parse_error = None;
    let observation = match &rows {
        Err(_) => vault_upload_driver::ReadLookupObservation::QueryFailed,
        Ok(rows) => match rows.first() {
            None => vault_upload_driver::ReadLookupObservation::Missing,
            Some(row) => match crate::db::parse_chunk_row_turso(row) {
                Ok(chunk) => {
                    let observation = vault_upload_driver::ReadLookupObservation::Found {
                        account_matches: chunk.user_id == session.user_id,
                        epoch_matches: row.i64(6) == Some(read_epoch),
                        version: chunk.version,
                        lamport_clock: chunk.lamport_clock,
                    };
                    parsed = Some(chunk);
                    observation
                }
                Err(error) => {
                    parse_error = Some(error);
                    vault_upload_driver::ReadLookupObservation::Malformed
                }
            },
        },
    };
    decision = vault_upload_driver::on_read_lookup(decision.driver, observation);

    let (version, lamport_clock) = match decision.effect {
        vault_upload_driver::ReadEffect::Serve {
            version,
            lamport_clock,
        } => (version, lamport_clock),
        vault_upload_driver::ReadEffect::Fail(vault_upload_driver::ReadFailure::NotFound) => {
            return Err(AppError::NotFound(format!("chunk {id} not found")));
        }
        vault_upload_driver::ReadEffect::Fail(vault_upload_driver::ReadFailure::QueryStorage) => {
            return Err(rows
                .err()
                .unwrap_or_else(|| AppError::Internal("chunk lookup failed".into())));
        }
        vault_upload_driver::ReadEffect::Fail(vault_upload_driver::ReadFailure::ParseStorage) => {
            return Err(parse_error
                .unwrap_or_else(|| AppError::Internal("chunk row could not be decoded".into())));
        }
        vault_upload_driver::ReadEffect::Fail(
            vault_upload_driver::ReadFailure::ScopeViolation,
        ) => {
            return Err(AppError::Internal(
                "chunk row outside the request's account/epoch scope".into(),
            ));
        }
        vault_upload_driver::ReadEffect::Fail(
            vault_upload_driver::ReadFailure::InvalidEpoch,
        ) => {
            return Err(AppError::Internal("invalid vault read epoch".into()));
        }
        vault_upload_driver::ReadEffect::Fail(
            vault_upload_driver::ReadFailure::Unauthenticated,
        ) => {
            return Err(AppError::Unauthorized("not authenticated".into()));
        }
        _ => return Err(AppError::Internal("unexpected chunk read decision".into())),
    };

    let chunk = parsed.ok_or_else(|| AppError::Internal("missing chunk row".into()))?;
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
        .and_then(|v| v.to_str().ok());
    let user_id = session.user_id.to_string();

    let intent = if if_match == 0 {
        vault_upload_driver::WriteIntent::Create
    } else {
        vault_upload_driver::WriteIntent::Replace { version: if_match }
    };
    let mut decision = vault_upload_driver::begin_upload(vault_upload_driver::UploadRequest {
        writer: vault_upload_driver::UploadWriter {
            authenticated: true,
            web: session.scope == TokenScope::WebSession,
            web_epoch: session.key_epoch,
        },
        intent,
        declared_epoch,
    });

    // ── Resolve the write/read epochs ──────────────────────────────────────
    match crate::vault::rekey::resolve_write_epoch(&state, &user_id, declared_epoch).await {
        Ok((write_epoch, read_epoch)) => {
            let phase = if write_epoch == read_epoch {
                PolicyPhase::Active
            } else {
                PolicyPhase::Freezing
            };
            decision = vault_upload_driver::on_rekey_observed(
                decision.driver,
                vault_upload_driver::RekeyObservation::State {
                    epoch: read_epoch,
                    phase,
                },
            );
        }
        Err(error) => {
            let _ = vault_upload_driver::on_rekey_observed(
                decision.driver,
                vault_upload_driver::RekeyObservation::Rejected,
            );
            return Err(error);
        }
    }

    // ── Shadow writes must come from the device that started the rotation ──
    if matches!(
        decision.effect,
        vault_upload_driver::UploadEffect::AuthorizeShadow
    ) {
        let authority =
            crate::vault::rekey::shadow_authority(&state, &session, rotation_id).await?;
        decision =
            vault_upload_driver::on_attempt_observed(decision.driver, authority);
    }
    match decision.effect {
        vault_upload_driver::UploadEffect::EnforceQuota => {}
        vault_upload_driver::UploadEffect::Fail(failure) => {
            return Err(upload_error(failure, &decision.driver));
        }
        _ => return Err(AppError::Internal("unexpected upload decision".into())),
    }

    // ── Quota ──────────────────────────────────────────────────────────────
    let quota_result = if decision.driver.shadow {
        crate::vault::enforce_rekey_shadow_quota(
            &state,
            &user_id,
            decision.driver.write_epoch,
            &id,
            crate::db::encode_b64(&ciphertext).len() as u64,
        )
        .await
    } else {
        crate::vault::enforce_storage_quota(&state, &user_id, body.len() as u64).await
    };
    match quota_result {
        Ok(()) => {
            decision = vault_upload_driver::on_quota_observed(
                decision.driver,
                vault_upload_driver::QuotaObservation::Allowed,
            );
        }
        Err(error) => {
            let observation = if matches!(error, AppError::PayloadTooLarge(_)) {
                vault_upload_driver::QuotaObservation::Exceeded
            } else {
                vault_upload_driver::QuotaObservation::StorageFailed
            };
            let _ = vault_upload_driver::on_quota_observed(decision.driver, observation);
            return Err(error);
        }
    }
    let permit = match decision.effect {
        vault_upload_driver::UploadEffect::Write(permit) => permit,
        _ => return Err(AppError::Internal("missing upload write permit".into())),
    };
    let write_epoch = permit.write_epoch;
    let read_epoch = permit.read_epoch;
    let is_shadow = permit.shadow;

    // ── The guarded insert/update ──────────────────────────────────────────
    let write_observation = if if_match == 0 {
        if is_shadow {
            // Shadow writes (epoch above the served one, i.e. a rotation in
            // flight) must tolerate replays: a crashed initiator restarts and
            // re-uploads the same chunks. Upsert instead of create-or-conflict.
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
                    TursoValue::Text(user_id.clone()),
                    TursoValue::Integer(lamport_clock),
                    TursoValue::Text(session.device_id.to_string()),
                    TursoValue::Text(crate::db::encode_b64(&ciphertext)),
                    TursoValue::Integer(write_epoch),
                    TursoValue::Text(now.clone()),
                    TursoValue::Text(now),
                    TursoValue::Text(user_id.clone()),
                    TursoValue::Integer(read_epoch),
                    TursoValue::Text(session.device_id.to_string()),
                    TursoValue::Text(rotation_id.unwrap_or_default().to_string()),
                ],
            ).await;
            match written {
                Ok(1) => vault_upload_driver::WriteObservation::Inserted,
                Ok(_) => vault_upload_driver::WriteObservation::Skipped,
                Err(error) => {
                    let _ = vault_upload_driver::on_write_observed(
                        decision.driver,
                        vault_upload_driver::WriteObservation::Failed,
                    );
                    return Err(AppError::Internal(error.to_string()));
                }
            }
        } else {
            let existing = state
                .sqldb
                .query(
                    "SELECT 1 FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
                    vec![
                        TursoValue::Text(id.clone()),
                        TursoValue::Text(user_id.clone()),
                        TursoValue::Integer(write_epoch),
                    ],
                )
                .await;
            match existing {
                Err(error) => {
                    let _ = vault_upload_driver::on_write_observed(
                        decision.driver,
                        vault_upload_driver::WriteObservation::Failed,
                    );
                    return Err(AppError::Internal(error.to_string()));
                }
                Ok(rows) if rows.first().is_some() => {
                    let _ = vault_upload_driver::on_write_observed(
                        decision.driver,
                        vault_upload_driver::WriteObservation::Existing,
                    );
                    return Err(AppError::Conflict(
                        "chunk already exists; use If-Match with current version to update"
                            .into(),
                    ));
                }
                Ok(_) => {}
            }

            let inserted = state.sqldb.execute(
            "INSERT INTO vault_chunks
             (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, epoch, created_at, updated_at)
             SELECT ?, ?, 1, ?, ?, ?, ?, ?, ? FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(lamport_clock),
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(crate::db::encode_b64(&ciphertext)),
                TursoValue::Integer(write_epoch),
                TursoValue::Text(now.clone()),
                TursoValue::Text(now),
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(permit.permit_epoch),
            ],
        ).await;
            match inserted {
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
                        let _ = vault_upload_driver::on_write_observed(
                            decision.driver,
                            vault_upload_driver::WriteObservation::Duplicate,
                        );
                        return Err(AppError::Conflict(
                            "chunk already exists; use If-Match with current version to update"
                                .into(),
                        ));
                    }
                    let _ = vault_upload_driver::on_write_observed(
                        decision.driver,
                        vault_upload_driver::WriteObservation::Failed,
                    );
                    return Err(AppError::Internal(error.to_string()));
                }
            }
        }
    } else {
        let updated = state
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
                    TursoValue::Text(user_id.clone()),
                    TursoValue::Integer(if_match),
                    TursoValue::Integer(write_epoch),
                    TursoValue::Integer(permit.permit_epoch),
                ],
            )
            .await;
        match updated {
            Err(error) => {
                let _ = vault_upload_driver::on_write_observed(
                    decision.driver,
                    vault_upload_driver::WriteObservation::Failed,
                );
                return Err(AppError::Internal(error.to_string()));
            }
            Ok(0) => {
                match crate::vault::rekey::resolve_write_epoch(
                    &state,
                    &user_id,
                    declared_epoch,
                )
                .await
                {
                    Ok(current) if current == (write_epoch, read_epoch) => {
                        let _ = vault_upload_driver::on_recheck_observed(
                            decision.driver,
                            vault_upload_driver::RecheckObservation::Unchanged,
                        );
                        return Err(AppError::Conflict(
                            "version mismatch — re-sync before retrying".into(),
                        ));
                    }
                    Ok(_) => {
                        let _ = vault_upload_driver::on_recheck_observed(
                            decision.driver,
                            vault_upload_driver::RecheckObservation::Changed,
                        );
                        return Err(AppError::Rekeyed(
                            "vault epoch changed before the chunk write completed".into(),
                        ));
                    }
                    Err(error @ AppError::Rekeyed(_)) => {
                        let _ = vault_upload_driver::on_recheck_observed(
                            decision.driver,
                            vault_upload_driver::RecheckObservation::Changed,
                        );
                        return Err(error);
                    }
                    Err(error) => {
                        let _ = vault_upload_driver::on_recheck_observed(
                            decision.driver,
                            vault_upload_driver::RecheckObservation::Failed,
                        );
                        return Err(error);
                    }
                }
            }
            Ok(_) => vault_upload_driver::WriteObservation::Updated,
        }
    };
    decision =
        vault_upload_driver::on_write_observed(decision.driver, write_observation);
    if let vault_upload_driver::UploadEffect::Fail(failure) = decision.effect {
        return Err(upload_error(failure, &decision.driver));
    }

    // ── Read back the committed version ────────────────────────────────────
    let ver_rows = state
        .sqldb
        .query(
            "SELECT version FROM vault_chunks WHERE chunk_id = ? AND user_id = ? AND epoch = ?",
            vec![
                TursoValue::Text(id.clone()),
                TursoValue::Text(user_id.clone()),
                TursoValue::Integer(write_epoch),
            ],
        )
        .await;
    let (reread_observation, reread_error) = match ver_rows {
        Err(error) => (vault_upload_driver::RereadObservation::Failed, Some(error)),
        Ok(rows) => match rows.first().and_then(|r| r.i64(0)) {
            Some(version) => (vault_upload_driver::RereadObservation::Read { version }, None),
            None => (vault_upload_driver::RereadObservation::Missing, None),
        },
    };
    decision =
        vault_upload_driver::on_reread_observed(decision.driver, reread_observation);
    if let Some(error) = reread_error {
        return Err(AppError::Internal(error.to_string()));
    }
    if let vault_upload_driver::UploadEffect::Fail(failure) = decision.effect {
        return Err(upload_error(failure, &decision.driver));
    }

    // ── Refresh the rotation deadline after a shadow write ────────────────
    if matches!(
        decision.effect,
        vault_upload_driver::UploadEffect::RecordShadowActivity
    ) {
        match crate::vault::rekey::record_shadow_activity(
            &state,
            &session,
            write_epoch,
            read_epoch,
            rotation_id,
        )
        .await
        {
            Ok(true) => {
                decision = vault_upload_driver::on_activity_observed(
                    decision.driver,
                    vault_upload_driver::ActivityObservation::Refreshed,
                );
            }
            Ok(false) => {
                decision = vault_upload_driver::on_activity_observed(
                    decision.driver,
                    vault_upload_driver::ActivityObservation::Ended,
                );
            }
            Err(error) => {
                let _ = vault_upload_driver::on_activity_observed(
                    decision.driver,
                    vault_upload_driver::ActivityObservation::Failed,
                );
                return Err(error);
            }
        }
    }
    match decision.effect {
        vault_upload_driver::UploadEffect::Publish => {
            // Let the account's other devices know a write landed. Shadow
            // writes (epoch above the served one) are invisible to readers,
            // so they stay silent until the commit publishes the epoch change.
            if !is_shadow {
                state.vault_events.publish(
                    session.user_id,
                    session.device_id,
                    write_epoch,
                    crate::vault::events::VaultChangeKind::Chunk,
                );
            }
            decision = vault_upload_driver::on_published_observed(decision.driver);
        }
        vault_upload_driver::UploadEffect::Complete => {}
        _ => return Err(AppError::Internal("unexpected upload decision".into())),
    }
    if !matches!(
        decision.effect,
        vault_upload_driver::UploadEffect::Complete
    ) {
        return Err(AppError::Internal("upload did not reach a terminal decision".into()));
    }

    let new_version = decision.driver.version;
    let mut resp_headers = HeaderMap::new();
    maybe_append_new_token(&mut resp_headers, &session);
    resp_headers.insert("X-Chunk-Version", new_version.to_string().parse().unwrap());

    Ok((
        StatusCode::OK,
        resp_headers,
        Json(serde_json::json!({ "version": new_version })),
    ))
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
