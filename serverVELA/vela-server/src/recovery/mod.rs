pub mod enroll_device;
pub mod initiate;
pub mod possess;
pub mod recover;
pub mod webauthn;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vela_recovery_policy::{
    PublicationFinalizeDecision, PublicationFinalizeRequest, PublicationStageDecision,
    PublicationStageRequest,
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
    let possession_hash_bytes = crate::db::decode_b64(&body.possession_hash).map_err(|_| {
        AppError::BadRequest("possession_hash is not valid base64".into())
    })?;
    if possession_hash_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "possession_hash must be exactly 32 bytes".into(),
        ));
    }
    let permit = recovery_mutation_permit(body.key_epoch)?;
    let publication = match vela_recovery_policy::plan_publication_stage(PublicationStageRequest {
        declared_epoch: body.key_epoch,
        split_id_present: true,
        server_share_present: !share_bytes.is_empty(),
        device_authority: true,
    }) {
        PublicationStageDecision::Stage(permit) => permit,
        PublicationStageDecision::Reject => {
            return Err(AppError::BadRequest(
                "verified recovery policy rejected publication staging".into(),
            ));
        }
    };
    debug_assert_eq!(publication.epoch(), permit.epoch());
    debug_assert!(publication.binds_split_and_share());
    let split_id_text = split_id.to_string();
    let stored_share = crate::db::encode_b64(&share_bytes);
    let stored_possession_hash = crate::db::encode_b64(&possession_hash_bytes);

    // Staging never changes the active recovery record. Concurrent devices may
    // replace this candidate, but only the exact candidate still present can
    // be promoted by `finalize_share` below.
    let updated = state
        .sqldb
        .execute(
            "UPDATE users
             SET recovery_pending_share = ?, recovery_pending_split_id = ?,
                 recovery_pending_epoch = ?, recovery_pending_auth_hash = ?
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               AND recovery_share IS NULL AND recovery_split_id IS NULL",
            vec![
                TursoValue::Text(stored_share.clone()),
                TursoValue::Text(split_id_text.clone()),
                TursoValue::Integer(publication.epoch()),
                TursoValue::Text(stored_possession_hash.clone()),
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(permit.epoch()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated != 1 {
        let rows = state
            .sqldb
            .query(
                "SELECT key_epoch, rekey_state, recovery_share, recovery_split_id
                 FROM users WHERE id = ?",
                vec![TursoValue::Text(session.user_id.to_string())],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let row = rows
            .first()
            .ok_or_else(|| AppError::NotFound("account no longer exists".into()))?;
        if row.i64(0) != Some(publication.epoch()) || row.text(1).is_some() {
            return Err(AppError::Rekeyed(
                "vault epoch changed during recovery setup; adopt the current key and retry".into(),
            ));
        }
        if row.text(2) == Some(stored_share.as_str())
            && row.text(3) == Some(split_id_text.as_str())
        {
            // The exact winning client is retrying after finalization. It may
            // safely continue its cloud promotion without restaging.
        } else {
            return Err(AppError::Conflict(
                "recovery is already finalized for this epoch; delete it before publishing a new split"
                    .into(),
            ));
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

/// Atomically promote only the exact staged split. The cloud candidate must be
/// durable before a client calls this endpoint; an idempotent retry succeeds
/// when this split is already active.
pub async fn finalize_share(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<FinalizeShareRequest>,
) -> Result<(HeaderMap, Json<FinalizeShareResponse>)> {
    let mutation = recovery_mutation_permit(body.key_epoch)?;
    let publication =
        match vela_recovery_policy::plan_publication_finalize(PublicationFinalizeRequest {
            declared_epoch: body.key_epoch,
            split_id_present: true,
            device_authority: true,
        }) {
            PublicationFinalizeDecision::Finalize(permit) => permit,
            PublicationFinalizeDecision::Reject => {
                return Err(AppError::BadRequest(
                    "verified recovery policy rejected publication finalization".into(),
                ));
            }
        };
    debug_assert_eq!(publication.epoch(), mutation.epoch());
    debug_assert!(publication.requires_exact_pending());
    debug_assert!(publication.requires_empty_active());

    let split_id = body.split_id.to_string();
    let updated = state
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
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(publication.epoch()),
                TursoValue::Integer(publication.epoch()),
                TursoValue::Text(split_id.clone()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if updated != 1 {
        let rows = state
            .sqldb
            .query(
                "SELECT key_epoch, rekey_state, recovery_split_id
                 FROM users WHERE id = ?",
                vec![TursoValue::Text(session.user_id.to_string())],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let row = rows
            .first()
            .ok_or_else(|| AppError::NotFound("account no longer exists".into()))?;
        if row.i64(0) != Some(publication.epoch()) || row.text(1).is_some() {
            return Err(AppError::Rekeyed(
                "vault epoch changed during recovery publication; retry setup".into(),
            ));
        }
        if row.text(2) != Some(split_id.as_str()) {
            return Err(AppError::Conflict(
                "another recovery split replaced this staged publication; restart setup".into(),
            ));
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

pub async fn get_share(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<GetShareResponse>)> {
    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share, recovery_split_id, key_epoch
             FROM users WHERE id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let share_b64 = rows
        .first()
        .and_then(|r| match r.get(0) {
            Some(TursoValue::Text(s)) => Some(s.clone()),
            _ => None,
        })
        .ok_or_else(|| AppError::NotFound("no recovery share stored for this user".into()))?;

    let share_bytes = crate::db::decode_b64(&share_b64)?;
    let split_id = rows.first().and_then(|row| row.text(1)).map(String::from);
    let key_epoch = rows.first().and_then(|row| row.i64(2)).unwrap_or(1).max(1);

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(GetShareResponse {
            share: B64.encode(&share_bytes),
            split_id,
            key_epoch,
        }),
    ))
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
    let permit = recovery_mutation_permit(key_epoch)?;

    let updated = state
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
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Integer(permit.epoch()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if updated != 1 {
        return Err(AppError::Rekeyed(
            "vault epoch changed during recovery setup; adopt the current key and retry".into(),
        ));
    }

    tracing::info!(user_id = %session.user_id, "recovery share deleted");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, StatusCode::NO_CONTENT))
}
