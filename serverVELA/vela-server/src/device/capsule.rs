use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, DeviceSession},
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
    use vela_rekey_policy::executor::{
        classify_capsule_clear, classify_capsule_read, classify_transaction,
        plan_begin_transaction, plan_clear_enrollment_capsule, plan_commit_transaction,
        plan_read_capsule, CapsuleClearObservation, CapsuleReadObservation, ReadOutcome,
    };
    // Enrollment delivery remains atomic read-then-clear, so two concurrent
    // join polls cannot both consume the one-time capsule. Epoch-tagged re-key
    // capsules deliberately stay readable until `post_capsule_ack` confirms
    // that the adopter persisted its new RMS.
    let mut pool = crate::vault::sql::PoolSql(&state);
    let (_begin, begin_error, guard) =
        crate::vault::sql::run_begin(&mut pool, &plan_begin_transaction()).await;
    if let Some(error) = begin_error {
        return Err(error.into_internal());
    }
    let Some(tx) = guard else {
        return Err(AppError::Internal("capsule transaction did not open".into()));
    };
    let mut sql = crate::vault::sql::TxSql(Some(tx));

    let plan = plan_read_capsule(session.device_id.to_string(), session.user_id.to_string());
    let outcome = match crate::vault::sql::run_read(&mut sql, &plan).await {
        Ok(rows) => ReadOutcome::Rows(crate::vault::sql::capsule_view(&rows)),
        Err(error) => {
            return Err(AppError::Internal(error.to_string()));
        }
    };
    let view = match classify_capsule_read(outcome) {
        CapsuleReadObservation::Found(view) => view,
        CapsuleReadObservation::Missing => {
            return Err(AppError::NotFound(
                "no capsule available — device may be the first device, \
                 or the capsule has already been downloaded"
                    .into(),
            ));
        }
        CapsuleReadObservation::Storage => {
            return Err(AppError::Internal("capsule lookup failed".into()));
        }
    };
    let capsule_b64 = match view.capsule {
        Some(capsule) => capsule,
        None => {
            return Err(AppError::NotFound(
                "no capsule available — device may be the first device, \
                 or the capsule has already been downloaded"
                    .into(),
            ));
        }
    };
    let capsule_epoch = view.capsule_epoch;
    let rotation_id = view.rotation_id;

    // Enrollment capsules retain their historical read-once behavior. Rekey
    // capsules carry an epoch and remain retryable until the adopter confirms
    // that local files and the platform RMS were durably migrated.
    if capsule_epoch.is_none() {
        let (outcomes, error) = crate::vault::sql::run_writes(
            &mut sql,
            &plan_clear_enrollment_capsule(
                session.device_id.to_string(),
                session.user_id.to_string(),
            ),
        )
        .await;
        if let Some(error) = error {
            return Err(error.into_internal());
        }
        if let CapsuleClearObservation::Storage = classify_capsule_clear(&outcomes) {
            return Err(AppError::Internal("capsule clear failed".into()));
        }
    }

    let (outcomes, error) =
        crate::vault::sql::run_writes(&mut sql, &plan_commit_transaction()).await;
    if let Some(error) = error {
        let detail = match error {
            crate::vault::sql::RunError::Sql(error) => error.to_string(),
            crate::vault::sql::RunError::Store(error) => error.to_string(),
        };
        return Err(AppError::Conflict(format!(
            "capsule delivery raced with a concurrent request, please retry: {detail}"
        )));
    }
    if let vela_rekey_policy::rekey_driver::TransactionObservation::Failed =
        classify_transaction(&outcomes)
    {
        return Err(AppError::Conflict(
            "capsule delivery raced with a concurrent request, please retry".into(),
        ));
    }

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
        use vela_rekey_policy::executor::{classify_ack, plan_ack_capsule};
        let plan = plan_ack_capsule(self.device_id.clone(), self.user_id.clone(), self.epoch);
        let mut sql = crate::vault::sql::PoolSql(self.state);
        let (outcomes, error) = crate::vault::sql::run_writes(&mut sql, &plan).await;
        if let Some(error) = error {
            self.error = Some(error.into_internal());
        }
        classify_ack(&outcomes)
    }

    async fn inspect_pending(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::PendingObservation {
        use vela_rekey_policy::executor::{
            classify_pending, plan_pending_capsule, ReadOutcome,
        };
        let plan = plan_pending_capsule(self.device_id.clone(), self.user_id.clone());
        let mut sql = crate::vault::sql::PoolSql(self.state);
        let outcome = match crate::vault::sql::run_read(&mut sql, &plan).await {
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                ReadOutcome::Failed
            }
            Ok(rows) => {
                ReadOutcome::Rows(crate::vault::sql::pending_row_view(&rows))
            }
        };
        classify_pending(&outcome)
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
