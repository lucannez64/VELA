use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, DeviceSession},
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

#[derive(serde::Serialize)]
pub struct CapsuleResponse {
    pub capsule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_id: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct CapsuleAck {
    pub epoch: i64,
}

pub async fn get_capsule(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<CapsuleResponse>)> {
    // Enrollment delivery remains atomic read-then-clear, so two concurrent
    // join polls cannot both consume the one-time capsule. Epoch-tagged re-key
    // capsules deliberately stay readable until `post_capsule_ack` confirms
    // that the adopter persisted its new RMS.
    let tx = state
        .sqldb
        .tx()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let rows = tx
        .query(
            "SELECT devices.rms_capsule, devices.rms_capsule_epoch,
                    CASE WHEN devices.rms_capsule_epoch = users.last_rekey_epoch
                         THEN users.last_rekey_id ELSE NULL END
             FROM devices JOIN users ON users.id = devices.user_id
             WHERE devices.id = ? AND devices.user_id = ?
               AND devices.revoked = 0 AND devices.rms_capsule IS NOT NULL",
            vec![
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let capsule_b64 = match rows.first().and_then(|r| r.get(0)) {
        Some(TursoValue::Text(s)) => s.clone(),
        _ => {
            return Err(AppError::NotFound(
                "no capsule available — device may be the first device, \
                 or the capsule has already been downloaded"
                    .into(),
            ));
        }
    };
    let capsule_epoch = rows.first().and_then(|r| r.i64(1));
    let rotation_id = rows.first().and_then(|r| r.text(2)).map(str::to_string);

    // Enrollment capsules retain their historical read-once behavior. Rekey
    // capsules carry an epoch and remain retryable until the adopter confirms
    // that local files and the platform RMS were durably migrated.
    if capsule_epoch.is_none() {
        tx.execute(
            "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
             WHERE id = ? AND user_id = ?",
            vec![
                TursoValue::Text(session.device_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    tx.commit().await.map_err(|e| {
        AppError::Conflict(format!(
            "capsule delivery raced with a concurrent request, please retry: {e}"
        ))
    })?;

    let capsule_bytes = crate::db::decode_b64(&capsule_b64)?;

    tracing::info!(
        device_id = %session.device_id,
        user_id   = %session.user_id,
        epoch = ?capsule_epoch,
        "RMS capsule downloaded"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Json(CapsuleResponse {
            capsule: B64.encode(&capsule_bytes),
            epoch: capsule_epoch,
            rotation_id,
        }),
    ))
}

/// The I/O behind `POST /device/capsule/ack`.
struct CapsuleAckIo<'a> {
    state: &'a AppState,
    device_id: String,
    user_id: String,
    epoch: i64,
    error: Option<AppError>,
}

impl CapsuleAckIo<'_> {
    async fn acknowledge(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::AckObservation {
        use vela_rekey_policy::vault_mutation_driver::AckObservation as O;
        let updated = self
            .state
            .sqldb
            .execute(
                "UPDATE devices SET rms_capsule = NULL, rms_capsule_epoch = NULL
             WHERE id = ? AND user_id = ? AND revoked = 0 AND rms_capsule_epoch = ?",
                vec![
                    TursoValue::Text(self.device_id.clone()),
                    TursoValue::Text(self.user_id.clone()),
                    TursoValue::Integer(self.epoch),
                ],
            )
            .await;
        match updated {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Storage
            }
            Ok(1) => O::Cleared,
            Ok(_) => O::Missed,
        }
    }

    async fn inspect_pending(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::PendingObservation {
        use vela_rekey_policy::vault_mutation_driver::PendingObservation as O;
        let rows = self
            .state
            .sqldb
            .query(
                "SELECT rms_capsule_epoch FROM devices
                 WHERE id = ? AND user_id = ? AND revoked = 0",
                vec![
                    TursoValue::Text(self.device_id.clone()),
                    TursoValue::Text(self.user_id.clone()),
                ],
            )
            .await;
        match rows {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                O::Storage
            }
            Ok(rows) => match rows.first() {
                None => O::Missing,
                // A lost successful ACK response is safe to retry. A
                // different pending epoch is not: clearing it would strand the
                // device on its old RMS.
                Some(row) if row.i64(0).is_some() => O::Pending,
                Some(_) => O::Replay,
            },
        }
    }
}

pub async fn post_capsule_ack(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<CapsuleAck>,
) -> Result<(HeaderMap, axum::http::StatusCode)> {
    use vela_rekey_policy::vault_mutation_driver::{
        CapsuleAckEffect, CapsuleAckFailure, CapsuleAckRequest,
    };
    let mut io = CapsuleAckIo {
        state: &state,
        device_id: session.device_id.to_string(),
        user_id: session.user_id.to_string(),
        epoch: body.epoch,
        error: None,
    };
    let transition = vela_rekey_policy::capsule_ack_interpreter!(
        io,
        CapsuleAckRequest {
            authenticated: true,
            device_scope: true,
        },
        await
    );
    match transition.effect {
        CapsuleAckEffect::Complete => {
            let mut headers = HeaderMap::new();
            maybe_append_new_token(&mut headers, &session);
            Ok((headers, axum::http::StatusCode::NO_CONTENT))
        }
        CapsuleAckEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(recorded.unwrap_or_else(|| match failure {
                CapsuleAckFailure::Unauthenticated => {
                    AppError::Unauthorized("not authenticated".into())
                }
                CapsuleAckFailure::WebSessionForbidden => {
                    AppError::Forbidden("a temporary web session cannot acknowledge capsules".into())
                }
                CapsuleAckFailure::AckStorage => {
                    AppError::Internal("capsule acknowledgement failed".into())
                }
                CapsuleAckFailure::NoLongerEligible => AppError::Conflict(
                    "device is no longer eligible to acknowledge capsules".into(),
                ),
                CapsuleAckFailure::DifferentPending => AppError::Conflict(
                    "a different re-key capsule is awaiting acknowledgement".into(),
                ),
                CapsuleAckFailure::PendingStorage => {
                    AppError::Internal("capsule pending-epoch lookup failed".into())
                }
            }))
        }
        _ => Err(AppError::Internal(
            "capsule acknowledgement did not reach a terminal decision".into(),
        )),
    }
}
