pub mod enroll_device;
pub mod initiate;
pub mod possess;
pub mod recover;
pub mod webauthn;

mod sql;
#[cfg(test)]
mod conformance;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::recovery_share_driver::{
    DeleteUpdateObservation, FinalizeAccountObservation, FinalizeUpdateObservation,
    ReadObservation, ShareActorObservation, ShareDeletePermit, ShareEffect, ShareFailure,
    ShareFinalizePermit, ShareOperation, ShareRequestObservation, ShareStagePermit,
    StageAccountObservation, StageUpdateObservation,
};
use vela_rekey_policy::{
    MutationAuthority, MutationDecision, MutationKind, MutationPermit, MutationRequest,
};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, DeviceSession},
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

const MAX_SHARE_BYTES: usize = 4096;

fn recovery_mutation_permit(epoch: i64) -> Result<MutationPermit> {
    let request = MutationRequest {
        declared_epoch: epoch,
        authority_epoch: epoch,
        kind: MutationKind::Recovery,
        authority: MutationAuthority::Device,
    };
    match vela_rekey_policy::plan_active_mutation(request) {
        MutationDecision::Permit(permit) => Ok(permit),
        MutationDecision::Reject => Err(AppError::BadRequest(
            "recovery mutation requires a positive device-authority epoch".into(),
        )),
    }
}

/// A deterministic token for the driver's own publication identity. It never
/// reaches SQL: the handlers keep using the exact UUID.
fn split_token(split_id: Uuid) -> i64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&split_id.as_bytes()[..8]);
    i64::from_be_bytes(bytes)
}

fn actor() -> ShareActorObservation {
    ShareActorObservation {
        authenticated: true,
        device_active: true,
        scoped_to_session_account: true,
    }
}

fn aborted_or(error: Option<AppError>) -> AppError {
    error.unwrap_or_else(|| AppError::Internal("recovery share interpreter aborted".into()))
}

fn common_failure(failure: ShareFailure) -> AppError {
    match failure {
        ShareFailure::Unauthenticated => AppError::Unauthorized("unauthorized".into()),
        ShareFailure::CrossAccount => {
            AppError::Forbidden("cannot act on another account".into())
        }
        ShareFailure::AccountMissing => {
            AppError::NotFound("account no longer exists".into())
        }
        ShareFailure::ShareMissing => {
            AppError::NotFound("no recovery share stored for this user".into())
        }
        ShareFailure::PolicyRejected => {
            AppError::BadRequest("verified recovery policy rejected the request".into())
        }
        ShareFailure::Rekeyed => AppError::Rekeyed(
            "vault epoch changed during recovery setup; adopt the current key and retry".into(),
        ),
        ShareFailure::Conflict => AppError::Conflict(
            "another recovery split replaced this staged publication; restart setup".into(),
        ),
    }
}

fn stage_failure(failure: ShareFailure) -> AppError {
    match failure {
        ShareFailure::PolicyRejected => {
            AppError::BadRequest("verified recovery policy rejected publication staging".into())
        }
        ShareFailure::Rekeyed => AppError::Rekeyed(
            "vault epoch changed during recovery setup; adopt the current key and retry".into(),
        ),
        ShareFailure::Conflict => AppError::Conflict(
            "recovery is already finalized for this epoch; delete it before publishing a new split"
                .into(),
        ),
        other => common_failure(other),
    }
}

fn finalize_failure(failure: ShareFailure) -> AppError {
    match failure {
        ShareFailure::PolicyRejected => AppError::BadRequest(
            "verified recovery policy rejected publication finalization".into(),
        ),
        ShareFailure::Rekeyed => AppError::Rekeyed(
            "vault epoch changed during recovery publication; retry setup".into(),
        ),
        ShareFailure::Conflict => AppError::Conflict(
            "another recovery split replaced this staged publication; restart setup".into(),
        ),
        other => common_failure(other),
    }
}

#[derive(Deserialize)]
pub struct PutShareRequest {
    pub share: String,
    /// Key epoch of the RMS which produced this Shamir share.
    pub key_epoch: i64,
    /// Fresh identifier shared by all three shares from this one polynomial.
    /// Optional only so pre-M16 clients receive an actionable 400 response.
    #[serde(default)]
    pub split_id: Option<Uuid>,
    /// Blind commitment to the RMS (`vela rms possession v1` KDF output).
    /// Staged and finalized atomically with the share (M18): it lets any
    /// two-share pair — including pairs that never touch this server share —
    /// prove RMS possession for enrollment without WebAuthn. Required so a
    /// share can never be finalized without it.
    pub possession_hash: String,
}

#[derive(Serialize)]
pub struct PutShareResponse {
    pub staged: bool,
    pub split_id: Uuid,
}

/// The I/O behind `PUT /recovery/share`. Only the stage effects are real; the
/// other trait methods refuse, because the driver never emits them for a Stage
/// request.
struct PutShareIo<'a> {
    state: &'a AppState,
    user_id: String,
    stored_share: String,
    stored_possession_hash: String,
    split_id_text: String,
    error: Option<AppError>,
}

impl PutShareIo<'_> {
    async fn stage_share(&mut self, permit: ShareStagePermit) -> Option<StageUpdateObservation> {
        let updated = self
            .state
            .sqldb
            .execute(
                "UPDATE users
             SET recovery_pending_share = ?, recovery_pending_split_id = ?,
                 recovery_pending_epoch = ?, recovery_pending_auth_hash = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_share IS NULL AND recovery_split_id IS NULL",
                vec![
                    TursoValue::Text(self.stored_share.clone()),
                    TursoValue::Text(self.split_id_text.clone()),
                    TursoValue::Integer(permit.epoch()),
                    TursoValue::Text(self.stored_possession_hash.clone()),
                    TursoValue::Text(self.user_id.clone()),
                    TursoValue::Integer(permit.epoch()),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()));
        match updated {
            Ok(1) => Some(StageUpdateObservation::Staged),
            Ok(_) => Some(StageUpdateObservation::NotStaged),
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    async fn stage_query_account(&mut self) -> Option<StageAccountObservation> {
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT key_epoch, rekey_state, recovery_share, recovery_split_id
                 FROM users WHERE id = ?",
                vec![TursoValue::Text(self.user_id.clone())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let Some(row) = rows.first() else {
            return Some(StageAccountObservation {
                account_present: false,
                stored_epoch: None,
                rotation_active: false,
                active_share_matches: false,
                active_split_matches: false,
            });
        };
        Some(StageAccountObservation {
            account_present: true,
            stored_epoch: row.i64(0),
            rotation_active: row.text(1).is_some(),
            active_share_matches: row.text(2) == Some(self.stored_share.as_str()),
            active_split_matches: row.text(3) == Some(self.split_id_text.as_str()),
        })
    }

    async fn promote_staged_split(
        &mut self,
        _permit: ShareFinalizePermit,
    ) -> Option<FinalizeUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected finalize effect in PUT /recovery/share".into(),
        ));
        None
    }

    async fn finalize_query_account(&mut self) -> Option<FinalizeAccountObservation> {
        self.error = Some(AppError::Internal(
            "unexpected finalize account query in PUT /recovery/share".into(),
        ));
        None
    }

    async fn delete_share(&mut self, _permit: ShareDeletePermit) -> Option<DeleteUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected delete effect in PUT /recovery/share".into(),
        ));
        None
    }

    async fn read_share(&mut self) -> Option<ReadObservation> {
        self.error = Some(AppError::Internal(
            "unexpected read effect in PUT /recovery/share".into(),
        ));
        None
    }
}

pub async fn put_share(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<PutShareRequest>,
) -> Result<(HeaderMap, Json<PutShareResponse>)> {
    let share_bytes = B64
        .decode(&body.share)
        .map_err(|_| AppError::BadRequest("share is not valid base64".into()))?;

    if share_bytes.len() > MAX_SHARE_BYTES {
        return Err(AppError::BadRequest(format!(
            "share exceeds maximum size of {MAX_SHARE_BYTES} bytes"
        )));
    }
    if body.key_epoch < 1 {
        return Err(AppError::BadRequest("key_epoch must be positive".into()));
    }
    let split_id = body.split_id.ok_or_else(|| {
        AppError::BadRequest(
            "split_id is required; update the client before setting up recovery".into(),
        )
    })?;
    let possession_hash_bytes = crate::db::decode_b64(&body.possession_hash)
        .map_err(|_| AppError::BadRequest("possession_hash is not valid base64".into()))?;
    if possession_hash_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "possession_hash must be exactly 32 bytes".into(),
        ));
    }
    // The rekey policy is the device-authority authority for every recovery
    // mutation; the driver records its permit as an observation.
    let _permit = recovery_mutation_permit(body.key_epoch)?;

    let split_id_text = split_id.to_string();
    let stored_share = crate::db::encode_b64(&share_bytes);
    let stored_possession_hash = crate::db::encode_b64(&possession_hash_bytes);
    let request = ShareRequestObservation {
        operation: ShareOperation::Stage,
        actor: actor(),
        declared_epoch: body.key_epoch,
        split_id_present: true,
        share_present: !share_bytes.is_empty(),
        device_authority: true,
        split: split_token(split_id),
    };
    let mut io = PutShareIo {
        state: &state,
        user_id: session.user_id.to_string(),
        stored_share: stored_share.clone(),
        stored_possession_hash,
        split_id_text: split_id_text.clone(),
        error: None,
    };
    let transition = vela_recovery_policy::recovery_share_interpreter!(io, request, await)
        .ok_or_else(|| aborted_or(io.error.take()))?;
    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(failure) => return Err(stage_failure(failure)),
        _ => {
            return Err(AppError::Internal(
                "recovery share interpreter did not reach a verdict".into(),
            ))
        }
    }

    tracing::info!(user_id = %session.user_id, %split_id, bytes = share_bytes.len(), "recovery share staged");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(PutShareResponse {
            staged: true,
            split_id,
        }),
    ))
}

#[derive(Deserialize)]
pub struct FinalizeShareRequest {
    pub key_epoch: i64,
    pub split_id: Uuid,
}

#[derive(Serialize)]
pub struct FinalizeShareResponse {
    pub finalized: bool,
    pub split_id: Uuid,
}

/// The I/O behind `POST /recovery/share/finalize`.
struct FinalizeShareIo<'a> {
    state: &'a AppState,
    user_id: String,
    split_id_text: String,
    error: Option<AppError>,
}

impl FinalizeShareIo<'_> {
    async fn stage_share(&mut self, _permit: ShareStagePermit) -> Option<StageUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected stage effect in POST /recovery/share/finalize".into(),
        ));
        None
    }

    async fn stage_query_account(&mut self) -> Option<StageAccountObservation> {
        self.error = Some(AppError::Internal(
            "unexpected stage account query in POST /recovery/share/finalize".into(),
        ));
        None
    }

    async fn promote_staged_split(
        &mut self,
        permit: ShareFinalizePermit,
    ) -> Option<FinalizeUpdateObservation> {
        let updated = self
            .state
            .sqldb
            .execute(
                "UPDATE users
             SET recovery_share = recovery_pending_share,
                 recovery_split_id = recovery_pending_split_id,
                 recovery_auth_hash = recovery_pending_auth_hash,
                 recovery_pending_share = NULL,
                 recovery_pending_split_id = NULL,
                 recovery_pending_epoch = NULL,
                 recovery_pending_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_pending_epoch = ?
               AND recovery_pending_split_id = ?
               AND recovery_pending_share IS NOT NULL
               AND recovery_pending_auth_hash IS NOT NULL
               AND recovery_share IS NULL AND recovery_split_id IS NULL",
                vec![
                    TursoValue::Text(self.user_id.clone()),
                    TursoValue::Integer(permit.epoch()),
                    TursoValue::Integer(permit.epoch()),
                    TursoValue::Text(self.split_id_text.clone()),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()));
        match updated {
            Ok(1) => Some(FinalizeUpdateObservation::Promoted),
            Ok(_) => Some(FinalizeUpdateObservation::NotPromoted),
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    async fn finalize_query_account(&mut self) -> Option<FinalizeAccountObservation> {
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT key_epoch, rekey_state, recovery_split_id
                 FROM users WHERE id = ?",
                vec![TursoValue::Text(self.user_id.clone())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let Some(row) = rows.first() else {
            return Some(FinalizeAccountObservation {
                account_present: false,
                stored_epoch: None,
                rotation_active: false,
                active_split_matches: false,
            });
        };
        Some(FinalizeAccountObservation {
            account_present: true,
            stored_epoch: row.i64(0),
            rotation_active: row.text(1).is_some(),
            active_split_matches: row.text(2) == Some(self.split_id_text.as_str()),
        })
    }

    async fn delete_share(&mut self, _permit: ShareDeletePermit) -> Option<DeleteUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected delete effect in POST /recovery/share/finalize".into(),
        ));
        None
    }

    async fn read_share(&mut self) -> Option<ReadObservation> {
        self.error = Some(AppError::Internal(
            "unexpected read effect in POST /recovery/share/finalize".into(),
        ));
        None
    }
}

/// Atomically promote only the exact staged split. The cloud candidate must be
/// durable before a client calls this endpoint; an idempotent retry succeeds
/// when this split is already active.
pub async fn finalize_share(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<FinalizeShareRequest>,
) -> Result<(HeaderMap, Json<FinalizeShareResponse>)> {
    // The rekey policy is the device-authority authority for every recovery
    // mutation; the driver records its permit as an observation.
    let _permit = recovery_mutation_permit(body.key_epoch)?;
    let request = ShareRequestObservation {
        operation: ShareOperation::Finalize,
        actor: actor(),
        declared_epoch: body.key_epoch,
        split_id_present: true,
        share_present: true,
        device_authority: true,
        split: split_token(body.split_id),
    };
    let mut io = FinalizeShareIo {
        state: &state,
        user_id: session.user_id.to_string(),
        split_id_text: body.split_id.to_string(),
        error: None,
    };
    let transition = vela_recovery_policy::recovery_share_interpreter!(io, request, await)
        .ok_or_else(|| aborted_or(io.error.take()))?;
    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(failure) => return Err(finalize_failure(failure)),
        _ => {
            return Err(AppError::Internal(
                "recovery share interpreter did not reach a verdict".into(),
            ))
        }
    }

    tracing::info!(user_id = %session.user_id, split_id = %body.split_id, "recovery share publication finalized");
    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(FinalizeShareResponse {
            finalized: true,
            split_id: body.split_id,
        }),
    ))
}

#[derive(Serialize)]
pub struct GetShareResponse {
    pub share: String,
    pub split_id: Option<String>,
    pub key_epoch: i64,
}

/// The I/O behind `GET /recovery/share`.
struct GetShareIo<'a> {
    state: &'a AppState,
    user_id: String,
    share_bytes: Vec<u8>,
    split_id: Option<String>,
    key_epoch: i64,
    error: Option<AppError>,
}

impl GetShareIo<'_> {
    async fn stage_share(&mut self, _permit: ShareStagePermit) -> Option<StageUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected stage effect in GET /recovery/share".into(),
        ));
        None
    }

    async fn stage_query_account(&mut self) -> Option<StageAccountObservation> {
        self.error = Some(AppError::Internal(
            "unexpected stage account query in GET /recovery/share".into(),
        ));
        None
    }

    async fn promote_staged_split(
        &mut self,
        _permit: ShareFinalizePermit,
    ) -> Option<FinalizeUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected finalize effect in GET /recovery/share".into(),
        ));
        None
    }

    async fn finalize_query_account(&mut self) -> Option<FinalizeAccountObservation> {
        self.error = Some(AppError::Internal(
            "unexpected finalize account query in GET /recovery/share".into(),
        ));
        None
    }

    async fn delete_share(&mut self, _permit: ShareDeletePermit) -> Option<DeleteUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected delete effect in GET /recovery/share".into(),
        ));
        None
    }

    async fn read_share(&mut self) -> Option<ReadObservation> {
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT recovery_share, recovery_split_id, key_epoch
             FROM users WHERE id = ?",
                vec![TursoValue::Text(self.user_id.clone())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let Some(account_row) = rows.first() else {
            return Some(ReadObservation {
                account_present: false,
                share_present: false,
            });
        };
        let Some(share_b64) = account_row.text(0) else {
            return Some(ReadObservation {
                account_present: true,
                share_present: false,
            });
        };
        let share_bytes = match crate::db::decode_b64(&share_b64) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        self.share_bytes = share_bytes;
        self.split_id = account_row.text(1).map(String::from);
        self.key_epoch = account_row.i64(2).unwrap_or(1).max(1);
        Some(ReadObservation {
            account_present: true,
            share_present: true,
        })
    }
}

pub async fn get_share(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<GetShareResponse>)> {
    let request = ShareRequestObservation {
        operation: ShareOperation::Read,
        actor: actor(),
        declared_epoch: 0,
        split_id_present: true,
        share_present: true,
        device_authority: true,
        split: 0,
    };
    let mut io = GetShareIo {
        state: &state,
        user_id: session.user_id.to_string(),
        share_bytes: Vec::new(),
        split_id: None,
        key_epoch: 1,
        error: None,
    };
    let transition = vela_recovery_policy::recovery_share_interpreter!(io, request, await)
        .ok_or_else(|| aborted_or(io.error.take()))?;
    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(failure) => return Err(common_failure(failure)),
        _ => {
            return Err(AppError::Internal(
                "recovery share interpreter did not reach a verdict".into(),
            ))
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(GetShareResponse {
            share: B64.encode(&io.share_bytes),
            split_id: io.split_id,
            key_epoch: io.key_epoch,
        }),
    ))
}

/// The I/O behind `DELETE /recovery/share`.
struct DeleteShareIo<'a> {
    state: &'a AppState,
    user_id: String,
    error: Option<AppError>,
}

impl DeleteShareIo<'_> {
    async fn stage_share(&mut self, _permit: ShareStagePermit) -> Option<StageUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected stage effect in DELETE /recovery/share".into(),
        ));
        None
    }

    async fn stage_query_account(&mut self) -> Option<StageAccountObservation> {
        self.error = Some(AppError::Internal(
            "unexpected stage account query in DELETE /recovery/share".into(),
        ));
        None
    }

    async fn promote_staged_split(
        &mut self,
        _permit: ShareFinalizePermit,
    ) -> Option<FinalizeUpdateObservation> {
        self.error = Some(AppError::Internal(
            "unexpected finalize effect in DELETE /recovery/share".into(),
        ));
        None
    }

    async fn finalize_query_account(&mut self) -> Option<FinalizeAccountObservation> {
        self.error = Some(AppError::Internal(
            "unexpected finalize account query in DELETE /recovery/share".into(),
        ));
        None
    }

    async fn delete_share(&mut self, permit: ShareDeletePermit) -> Option<DeleteUpdateObservation> {
        let updated = self
            .state
            .sqldb
            .execute(
                "UPDATE users
             SET recovery_share = NULL, recovery_split_id = NULL,
                 recovery_pending_share = NULL,
                 recovery_pending_split_id = NULL,
                 recovery_pending_epoch = NULL,
                 recovery_auth_hash = NULL,
                 recovery_pending_auth_hash = NULL
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL",
                vec![
                    TursoValue::Text(self.user_id.clone()),
                    TursoValue::Integer(permit.epoch()),
                ],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()));
        match updated {
            Ok(1) => Some(DeleteUpdateObservation::Deleted),
            Ok(_) => Some(DeleteUpdateObservation::NotDeleted),
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    async fn read_share(&mut self) -> Option<ReadObservation> {
        self.error = Some(AppError::Internal(
            "unexpected read effect in DELETE /recovery/share".into(),
        ));
        None
    }
}

pub async fn delete_share(
    State(state): State<AppState>,
    session: DeviceSession,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode)> {
    let key_epoch = headers
        .get("x-vela-epoch")
        .ok_or_else(|| AppError::BadRequest("X-Vela-Epoch header is required".into()))?
        .to_str()
        .ok()
        .and_then(|raw| raw.parse::<i64>().ok())
        .filter(|epoch| *epoch >= 1)
        .ok_or_else(|| AppError::BadRequest("X-Vela-Epoch must be a positive integer".into()))?;
    // The rekey policy is the device-authority authority for every recovery
    // mutation; the driver records its permit as an observation.
    let _permit = recovery_mutation_permit(key_epoch)?;

    let request = ShareRequestObservation {
        operation: ShareOperation::Delete,
        actor: actor(),
        declared_epoch: key_epoch,
        split_id_present: true,
        share_present: true,
        device_authority: true,
        split: 0,
    };
    let mut io = DeleteShareIo {
        state: &state,
        user_id: session.user_id.to_string(),
        error: None,
    };
    let transition = vela_recovery_policy::recovery_share_interpreter!(io, request, await)
        .ok_or_else(|| aborted_or(io.error.take()))?;
    match transition.effect {
        ShareEffect::Complete => {}
        ShareEffect::Fail(failure) => return Err(match failure {
            ShareFailure::PolicyRejected => AppError::BadRequest(
                "recovery mutation requires a positive device-authority epoch".into(),
            ),
            other => common_failure(other),
        }),
        _ => {
            return Err(AppError::Internal(
                "recovery share interpreter did not reach a verdict".into(),
            ))
        }
    }

    tracing::info!(user_id = %session.user_id, "recovery share deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}
