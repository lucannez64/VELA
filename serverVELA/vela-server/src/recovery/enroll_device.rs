//! Post-recovery device enrollment (SPEC.md §4.3).
//!
//! Normal device enrollment (`/device/enroll`) requires an already-authorized
//! device to sign the new device's key material (§4.2) — but a device going
//! through account recovery has, by definition, no other enrolled device
//! available. Authorization here instead comes from the single-use
//! `recovery_grant` issued by `/recovery/recover`, which only exists after
//! this caller passed a WebAuthn-gated assertion for `user_id`. The new
//! device already reconstructed the RMS locally from Share 1 + Share 2, so
//! unlike `/device/enroll` there is no `rms_capsule` to deliver — this
//! endpoint only needs to register the device's identity key so it can
//! authenticate normally afterwards via `/auth/challenge` + `/auth/verify`.

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;
use vela_recovery_policy::{
    driver::{
        AuthorityRecheckObservation, ConsumptionObservation, FinalPolicyObservation,
        InsertObservation, RedemptionEffect, RedemptionFailure, RedemptionInsertPermit,
        RekeyObservation,
    },
    observed_recovery_epoch, plan_enrollment_preflight, EnrollmentAccountFacts,
    EnrollmentAccountObservation, EnrollmentGrantFacts, EnrollmentObservation,
    EnrollmentPreflightDecision, EnrollmentPreflightObservation, EnrollmentPreflightRejection,
};
use vela_rekey_policy::{MutationAuthority, MutationDecision, MutationKind, MutationRequest};

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};
use vela_recovery_policy::redemption_store::{self, GrantGuard, GrantTake, GrantView, ReadOutcome};

use super::sql::{
    authority_row_view, put_grant, run_read, run_writes, take_grant, PoolSql, RecoveryKv,
    RecoverySql, StoreKv,
};

const HYBRID_EK_LEN: usize = vela_recovery_policy::HYBRID_EK_LEN;
const HYBRID_VK_LEN: usize = vela_recovery_policy::HYBRID_VK_LEN;
// Pin the policy constants to the actual crypto wire sizes and the enrollment
// ceremony's policy; drift is a build failure rather than a weaker admission.
const _: () = {
    assert!(HYBRID_EK_LEN == vela_crypto::kem::ML_KEM_EK_LEN + 32);
    assert!(HYBRID_VK_LEN == vela_crypto::signing::HYBRID_VK_LEN);
    assert!(HYBRID_EK_LEN == vela_enrollment_policy::HYBRID_EK_LEN);
    assert!(HYBRID_VK_LEN == vela_enrollment_policy::HYBRID_VK_LEN);
};
#[derive(Deserialize)]
pub struct EnrollDeviceRequest {
    pub user_id: Uuid,
    pub recovery_grant: Uuid,
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Serialize)]
pub struct EnrollDeviceResponse {
    pub device_id: Uuid,
}

pub async fn post_enroll_device(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<EnrollDeviceRequest>,
) -> Result<Json<EnrollDeviceResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::check(
        &state.store,
        &format!("rl:recover:enroll:ip:{ip}"),
        10,
        3600,
    )?;
    // Keyed on the caller as well as the target (red-team RT-1) — see the note
    // in `recover.rs`. This check also runs before the grant is verified, so the
    // per-user-only form was spendable with a garbage body.
    rate_limit::recovery_enroll_by_ip_user(&state.store, &ip, &body.user_id.to_string())?;
    rate_limit::recovery_enroll_by_user(&state.store, &body.user_id.to_string())?;

    let hybrid_ek = B64
        .decode(&body.hybrid_ek)
        .map_err(|_| AppError::BadRequest("hybrid_ek is not valid base64".into()))?;
    let hybrid_vk = B64
        .decode(&body.hybrid_vk)
        .map_err(|_| AppError::BadRequest("hybrid_vk is not valid base64".into()))?;

    if hybrid_ek.len() != HYBRID_EK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_ek must be {HYBRID_EK_LEN} bytes"
        )));
    }
    if hybrid_vk.len() != HYBRID_VK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_vk must be {HYBRID_VK_LEN} bytes"
        )));
    }

    // Do not reveal account or rotation state unless the caller possesses the
    // unguessable grant. This is only a non-consuming proof; redemption below
    // remains atomic and single-use. The checked preflight kernel owns the
    // account/epoch/rotation/credential/commitment decision and its precedence;
    // it neither consumes the grant nor authorizes a device insert.
    let observed_grant =
        crate::recovery::recover::observe_enroll_grant(&state, body.user_id, body.recovery_grant)?;
    let grant_present = observed_grant.is_some();

    // The grant already proved `user_id` exists and completed recovery, but
    // a deleted-account race between /recovery/recover and this call is
    // still possible in principle — fail closed rather than orphan a device
    // row under a FK that no longer resolves. When the grant is missing this
    // query is deliberately skipped and the policy sees `NotQueried`, so a
    // failed grant lookup cannot probe account state.
    let account_observation = match observed_grant.as_ref() {
        None => EnrollmentAccountObservation::NotQueried,
        Some(grant) => {
            let user_rows = state
                .sqldb
                .query(
                    "SELECT key_epoch, rekey_state, recovery_webauthn_cred_id, recovery_auth_hash
                     FROM users WHERE id = ?",
                    vec![TursoValue::Text(body.user_id.to_string())],
                )
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
            match user_rows.first() {
                None => EnrollmentAccountObservation::Absent,
                Some(user_row) => {
                    let stored_epoch = user_row.i64(0);
                    let epoch_active = user_row.text(1).is_none();
                    // Preserve epoch/rotation rejection before decoding a
                    // possibly malformed stored commitment. Its length is
                    // irrelevant when preflight rejects at either guard.
                    let commitment_len = if observed_recovery_epoch(stored_epoch) == grant.key_epoch
                        && epoch_active
                    {
                        match user_row.get(3) {
                            Some(TursoValue::Text(text)) => crate::db::decode_b64(text)?.len(),
                            _ => 0,
                        }
                    } else {
                        0
                    };
                    EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
                        stored_epoch,
                        epoch_active,
                        credential_id_matches: user_row.text(2)
                            == Some(grant.credential_id.as_str()),
                        commitment_len,
                    })
                }
            }
        }
    };
    let account_present = matches!(
        account_observation,
        EnrollmentAccountObservation::Present(_)
    );
    let grant_observation = match observed_grant.as_ref() {
        Some(grant) => Some(EnrollmentGrantFacts {
            epoch: grant.key_epoch,
            possession: grant.possession,
        }),
        None => None,
    };
    let (ready, grant, account) = match (
        plan_enrollment_preflight(EnrollmentPreflightObservation {
            grant: grant_observation,
            account: account_observation,
        }),
        observed_grant,
        account_observation,
    ) {
        (
            EnrollmentPreflightDecision::Ready(ready),
            Some(grant),
            EnrollmentAccountObservation::Present(account),
        ) => (ready, grant, account),
        (EnrollmentPreflightDecision::Reject(reason), _, _) => {
            return Err(preflight_rejection_error(reason));
        }
        _ => {
            // The policy cannot admit an unobserved account; keep this branch
            // fail-closed if the wiring ever drifts.
            return Err(AppError::Internal(
                "enrollment preflight admitted an unobserved account".into(),
            ));
        }
    };

    // Consume only after validation and the fast rotation check. The guarded
    // insert below remains the authority for a concurrent rotation; if that
    // race is lost, the grant is restored so the user can retry afterwards.
    // Every post-preflight decision and every effect between consumption and
    // the verdict goes through the proved `redemption_interpreter!` loop; this
    // handler only supplies the I/O and renders the terminal effect.
    let mut io = EnrollDeviceIo {
        sql: PoolSql(&state.sqldb),
        kv: StoreKv(&state.store),
        user_id: body.user_id,
        recovery_grant: body.recovery_grant,
        hybrid_ek,
        hybrid_vk,
        device_name: body
            .device_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Recovered Device".to_string()),
        device_type: body
            .device_type
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        now: None,
        grant,
        grant_present,
        account,
        account_present,
        consumed_grant: None,
        grant_consumed: false,
        consumed_matches_observed: false,
        new_device_id: None,
        insert_error: None,
        error: None,
    };
    let Some(transition) = vela_recovery_policy::redemption_interpreter!(io, ready, await) else {
        return Err(io.error.take().unwrap_or_else(|| {
            AppError::Internal("recovery enrollment aborted without an error".into())
        }));
    };

    match transition.effect {
        RedemptionEffect::Complete => {
            let new_device_id = io.new_device_id.ok_or_else(|| {
                AppError::Internal("redemption driver completed without a device id".into())
            })?;
            tracing::info!(
                new_device_id = %new_device_id,
                user_id = %body.user_id,
                "device enrolled via account recovery"
            );
            Ok(Json(EnrollDeviceResponse { device_id: new_device_id }))
        }
        // An insert error may hide a committed row, so the grant stays
        // consumed; the user restarts recovery instead of reusing it.
        RedemptionEffect::Fail(RedemptionFailure::InsertStorage)
            if io.insert_error.is_some() =>
        {
            Err(io.insert_error.take().expect("checked above"))
        }
        RedemptionEffect::Fail(failure) | RedemptionEffect::RestoreAndFail(failure) => {
            Err(redemption_failure_error(failure))
        }
        _ => Err(AppError::Internal(
            "redemption driver reached no verdict".into(),
        )),
    }
}

/// The I/O behind each enrollment-redemption effect. The driver decides which
/// method runs and when (through the shared `redemption_interpreter!` loop,
/// proved in F* as `run_redemption`); each method only performs its effect and
/// reports the observation. `None` aborts the request with `error`, which is
/// rendered unchanged.
pub(super) struct EnrollDeviceIo<S, K> {
    sql: S,
    kv: K,
    user_id: Uuid,
    recovery_grant: Uuid,
    hybrid_ek: Vec<u8>,
    hybrid_vk: Vec<u8>,
    device_name: String,
    device_type: String,
    /// A fixed enrollment instant for the conformance test; `None` takes the
    /// wall clock exactly when the insert runs, as the handler always has.
    now: Option<String>,
    /// The decoded grant from the non-consuming preflight lookup.
    grant: crate::recovery::recover::RecoveryEnrollGrant,
    grant_present: bool,
    account: EnrollmentAccountFacts,
    account_present: bool,
    /// The grant removed by the atomic consumption, when one was removed.
    consumed_grant: Option<crate::recovery::recover::RecoveryEnrollGrant>,
    grant_consumed: bool,
    consumed_matches_observed: bool,
    new_device_id: Option<Uuid>,
    insert_error: Option<AppError>,
    /// The first error from an effect that has no observation to report.
    error: Option<AppError>,
}

impl<S: RecoverySql, K: RecoveryKv> EnrollDeviceIo<S, K> {
    /// The atomic single-use consumption. A store failure has no observation:
    /// it aborts with the store's own error, exactly as the inline effect did.
    pub(super) async fn consume_grant(&mut self) -> Option<ConsumptionObservation> {
        let preflight = grant_view(&self.grant);
        let stmt = redemption_store::plan_take_grant(redemption_store::grant_key(
            &self.user_id.to_string(),
            &self.recovery_grant.to_string(),
        ));
        let bytes = match take_grant(&mut self.kv, &stmt) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        let observed = match bytes {
            None => None,
            Some(value) => match crate::recovery::recover::decode_enroll_grant(&value) {
                Ok(grant) => Some(grant),
                Err(error) => {
                    self.error = Some(error);
                    return None;
                }
            },
        };
        self.grant_consumed = observed.is_some();
        self.consumed_matches_observed = observed.as_ref() == Some(&self.grant);
        let taken = match observed.as_ref() {
            None => GrantTake::Missing,
            Some(consumed) => GrantTake::Taken(grant_view(consumed)),
        };
        let observation = redemption_store::classify_take(&taken, &preflight);
        self.consumed_grant = observed;
        Some(observation)
    }

    /// The final enrollment and rekey policy decision. It is pure: the driver
    /// still decides whether the returned permits may authorize an insert.
    async fn final_policy(&mut self) -> Option<FinalPolicyObservation> {
        let Some(consumed) = self.consumed_grant.as_ref() else {
            self.error = Some(AppError::Internal(
                "redemption driver admitted an unobserved grant".into(),
            ));
            return None;
        };
        let consumed_epoch = consumed.key_epoch;
        let rekey = match vela_rekey_policy::plan_active_mutation(MutationRequest {
            declared_epoch: consumed_epoch,
            authority_epoch: consumed_epoch,
            kind: MutationKind::Enrollment,
            authority: MutationAuthority::RecoveryGrant,
        }) {
            MutationDecision::Permit(permit) => RekeyObservation::Permit {
                epoch: permit.epoch(),
            },
            MutationDecision::Reject => RekeyObservation::Reject,
        };
        Some(FinalPolicyObservation {
            enrollment: EnrollmentObservation {
                grant_present: self.grant_present,
                grant_consumed: self.grant_consumed,
                consumed_matches_observed: self.consumed_matches_observed,
                account_present: self.account_present,
                grant_possession: consumed.possession,
                grant_epoch: consumed_epoch,
                stored_epoch: self.account.stored_epoch,
                account_epoch_active: self.account.epoch_active,
                credential_id_matches: self.account.credential_id_matches,
                commitment_len: self.account.commitment_len,
                hybrid_ek_len: self.hybrid_ek.len(),
                hybrid_vk_len: self.hybrid_vk.len(),
            },
            rekey,
        })
    }

    /// Exactly one guarded device insert with the driver's permit.
    pub(super) async fn insert_device(&mut self, permit: RedemptionInsertPermit) -> Option<InsertObservation> {
        let Some(consumed) = self.consumed_grant.as_ref() else {
            self.error = Some(AppError::Internal(
                "redemption driver admitted an unobserved grant".into(),
            ));
            return None;
        };
        let new_device_id = Uuid::new_v4();
        self.new_device_id = Some(new_device_id);
        let guard = if permit.possession {
            GrantGuard::Commitment
        } else {
            GrantGuard::Credential {
                credential_id: consumed.credential_id.clone(),
            }
        };
        let plan = redemption_store::plan_insert_device(
            new_device_id.to_string(),
            self.user_id.to_string(),
            self.device_name.clone(),
            self.device_type.clone(),
            crate::db::encode_b64(&self.hybrid_ek),
            crate::db::encode_b64(&self.hybrid_vk),
            self.now.clone().unwrap_or_else(|| Utc::now().to_rfc3339()),
            permit.epoch,
            guard,
        );
        let (outcomes, error) = run_writes(&mut self.sql, &plan).await;
        let observation = redemption_store::classify_insert(&outcomes);
        if let Some(error) = error {
            self.insert_error = Some(AppError::Internal(error.to_string()));
        }
        Some(observation)
    }

    /// The live authority recheck after a zero-row insert. A query failure is
    /// an observation (`QueryFailed`); the driver decides that it restores the
    /// grant, and the original error is kept for the response.
    pub(super) async fn recheck_authority(&mut self) -> Option<AuthorityRecheckObservation> {
        let Some(consumed) = self.consumed_grant.as_ref() else {
            self.error = Some(AppError::Internal(
                "redemption driver admitted an unobserved grant".into(),
            ));
            return None;
        };
        let stmt = redemption_store::plan_authority_read(self.user_id.to_string());
        let rows = match run_read(&mut self.sql, &stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return Some(AuthorityRecheckObservation::QueryFailed);
            }
        };
        Some(redemption_store::classify_authority(
            &ReadOutcome::Row(authority_row_view(&rows)),
            consumed.possession,
            &consumed.credential_id,
        ))
    }

    /// Restore the consumed grant before returning the driver's failure. A
    /// store error replaces the failure, exactly as the inline `?` did.
    pub(super) async fn restore_grant(&mut self) -> Option<()> {
        let Some(consumed) = self.consumed_grant.as_ref() else {
            return Some(());
        };
        let value = match serde_json::to_string(consumed) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(AppError::Internal(format!(
                    "failed to serialize recovery grant: {error}"
                )));
                return None;
            }
        };
        let plan = redemption_store::plan_restore_grant(
            redemption_store::grant_key(
                &self.user_id.to_string(),
                &self.recovery_grant.to_string(),
            ),
            value,
            grant_view(consumed),
        );
        match plan.first().map(|stmt| put_grant(&mut self.kv, stmt)) {
            Some(Ok(())) => Some(()),
            Some(Err(error)) => {
                self.error = Some(error);
                None
            }
            None => {
                self.error = Some(AppError::Internal(
                    "restore plan carried no statement".into(),
                ));
                None
            }
        }
    }
}

fn grant_view(grant: &crate::recovery::recover::RecoveryEnrollGrant) -> GrantView {
    GrantView {
        key_epoch: grant.key_epoch,
        credential_id: grant.credential_id.clone(),
        possession: grant.possession,
    }
}

/// Construction and side-channel access for the bounded real-database
/// conformance test (`recovery/conformance.rs`).
#[cfg(test)]
impl<S, K> EnrollDeviceIo<S, K> {
    pub(super) fn for_conformance(
        sql: S,
        kv: K,
        user_id: Uuid,
        recovery_grant: Uuid,
        grant: crate::recovery::recover::RecoveryEnrollGrant,
        consumed: Option<crate::recovery::recover::RecoveryEnrollGrant>,
    ) -> Self {
        let stored_epoch = grant.key_epoch;
        Self {
            sql,
            kv,
            user_id,
            recovery_grant,
            hybrid_ek: vec![1, 2, 3],
            hybrid_vk: vec![4, 5, 6],
            device_name: "conformance-device".into(),
            device_type: "conformance".into(),
            now: Some("2026-10-30T12:00:00+00:00".into()),
            grant,
            grant_present: true,
            account: EnrollmentAccountFacts {
                stored_epoch: Some(stored_epoch),
                epoch_active: true,
                credential_id_matches: false,
                commitment_len: 0,
            },
            account_present: true,
            consumed_grant: consumed,
            grant_consumed: false,
            consumed_matches_observed: false,
            new_device_id: None,
            insert_error: None,
            error: None,
        }
    }

    pub(super) fn insert_error_is_set(&self) -> bool {
        self.insert_error.is_some()
    }

    pub(super) fn error_is_set(&self) -> bool {
        self.error.is_some()
    }

    pub(super) fn new_device_id(&self) -> Option<Uuid> {
        self.new_device_id
    }

    pub(super) fn consumed_grant(&self) -> Option<&crate::recovery::recover::RecoveryEnrollGrant> {
        self.consumed_grant.as_ref()
    }

    pub(super) fn grant_consumed(&self) -> bool {
        self.grant_consumed
    }

    pub(super) fn consumed_matches_observed(&self) -> bool {
        self.consumed_matches_observed
    }
}

/// Map the checked preflight rejection to the handler's historical status and
/// message. The kernel decides which reason wins; this function only renders it.
fn preflight_rejection_error(reason: EnrollmentPreflightRejection) -> AppError {
    match reason {
        EnrollmentPreflightRejection::GrantUnavailable => {
            AppError::Unauthorized("recovery grant expired or already used".into())
        }
        // Unreachable through the production wiring: the account query either
        // errors, returns `Absent`, or returns `Present`. Keep it fail-closed.
        EnrollmentPreflightRejection::AccountUnavailable => {
            AppError::Internal("enrollment account was not observed".into())
        }
        EnrollmentPreflightRejection::AccountAbsent => {
            AppError::NotFound("account no longer exists".into())
        }
        EnrollmentPreflightRejection::EpochMismatch => {
            AppError::Unauthorized("recovery grant was invalidated by vault key rotation".into())
        }
        EnrollmentPreflightRejection::RotationPaused => {
            AppError::Conflict("device enrollment is paused during vault key rotation".into())
        }
        EnrollmentPreflightRejection::CredentialReplaced => AppError::Unauthorized(
            "recovery grant was invalidated by credential replacement".into(),
        ),
        EnrollmentPreflightRejection::CommitmentMissing => AppError::Unauthorized(
            "recovery grant was invalidated by recovery setup deletion or rotation".into(),
        ),
    }
}

/// Render a driver failure with the handler's historical status/message. The
/// storage variants carry the original database error text at the call site;
/// this fallback exists so the mapping stays total.
fn redemption_failure_error(failure: RedemptionFailure) -> AppError {
    match failure {
        RedemptionFailure::GrantUnavailable => {
            AppError::Unauthorized("recovery grant expired or already used".into())
        }
        RedemptionFailure::GrantChanged => {
            AppError::Unauthorized("recovery grant changed while redeeming".into())
        }
        RedemptionFailure::PolicyRejected => {
            AppError::Unauthorized("verified recovery policy rejected device enrollment".into())
        }
        RedemptionFailure::AccountAbsent => AppError::NotFound("account no longer exists".into()),
        RedemptionFailure::CommitmentRevoked => AppError::Unauthorized(
            "recovery grant was invalidated by recovery setup deletion or rotation".into(),
        ),
        RedemptionFailure::CredentialReplaced => AppError::Unauthorized(
            "recovery grant was invalidated by credential replacement".into(),
        ),
        RedemptionFailure::Rotating => {
            AppError::Conflict("device enrollment is paused during vault key rotation".into())
        }
        RedemptionFailure::InsertStorage | RedemptionFailure::RecheckStorage => {
            AppError::Internal("redemption storage observation failed".into())
        }
    }
}
