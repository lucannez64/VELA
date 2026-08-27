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
use vela_recovery_policy::{EnrollmentDecision, EnrollmentFacts, RecoveryPhase};
use vela_rekey_policy::{MutationAuthority, MutationDecision, MutationKind, MutationRequest};

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

const HYBRID_EK_LEN: usize = 1568 + 32;
const HYBRID_VK_LEN: usize = 2592 + 32;
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
    // remains atomic and single-use.
    let grant =
        crate::recovery::recover::load_enroll_grant(&state, body.user_id, body.recovery_grant)?;
    let grant_epoch = grant.key_epoch;

    // The grant already proved `user_id` exists and completed recovery, but
    // a deleted-account race between /recovery/recover and this call is
    // still possible in principle — fail closed rather than orphan a device
    // row under a FK that no longer resolves.
    let user_rows = state
        .sqldb
        .query(
            "SELECT key_epoch, rekey_state, recovery_webauthn_cred_id, recovery_auth_hash
             FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let Some(user_row) = user_rows.first() else {
        return Err(AppError::NotFound("account no longer exists".into()));
    };
    let account_epoch = user_row.i64(0).unwrap_or(1).max(1);
    if account_epoch != grant_epoch {
        return Err(AppError::Unauthorized(
            "recovery grant was invalidated by vault key rotation".into(),
        ));
    }
    if user_row.text(1).is_some() {
        return Err(AppError::Conflict(
            "device enrollment is paused during vault key rotation".into(),
        ));
    }
    // Credential-bound grants die when the passkey is replaced. Possession
    // grants (M18) are bound to no credential; they instead require the RMS
    // commitment that verified their proof to still be staged — deleting
    // recovery setup or rotating the RMS revokes them.
    let possession_hash_present = match user_row.get(3) {
        Some(TursoValue::Text(text)) => !crate::db::decode_b64(text)?.is_empty(),
        _ => false,
    };
    let credential_matches_current = if grant.possession {
        possession_hash_present
    } else {
        user_row.text(2) == Some(grant.credential_id.as_str())
    };
    if !credential_matches_current {
        return Err(AppError::Unauthorized(if grant.possession {
            "recovery grant was invalidated by recovery setup deletion or rotation".into()
        } else {
            "recovery grant was invalidated by credential replacement".into()
        }));
    }

    // Consume only after validation and the fast rotation check. The guarded
    // insert below remains the authority for a concurrent rotation; if that
    // race is lost, the grant is restored so the user can retry afterwards.
    let consumed_grant =
        crate::recovery::recover::take_enroll_grant(&state, body.user_id, body.recovery_grant)?;
    if consumed_grant != grant {
        crate::recovery::recover::restore_enroll_grant(
            &state,
            body.user_id,
            body.recovery_grant,
            &consumed_grant,
        )?;
        return Err(AppError::Unauthorized(
            "recovery grant changed while redeeming".into(),
        ));
    }
    let consumed_epoch = consumed_grant.key_epoch;
    let recovery_permit = match vela_recovery_policy::plan_enrollment(EnrollmentFacts {
        phase: RecoveryPhase::GrantIssued,
        // Both ids are part of the same unguessable sled key.
        user_matches: true,
        grant_live: true,
        grant_consumed: true,
        credential_matches_current,
        possession_grant: consumed_grant.possession,
        possession_hash_present,
        public_keys_valid: hybrid_ek.len() == HYBRID_EK_LEN && hybrid_vk.len() == HYBRID_VK_LEN,
        account_epoch_active: user_row.text(1).is_none(),
        grant_epoch: consumed_epoch,
        account_epoch,
    }) {
        EnrollmentDecision::Enroll(permit) => permit,
        EnrollmentDecision::Reject => {
            crate::recovery::recover::restore_enroll_grant(
                &state,
                body.user_id,
                body.recovery_grant,
                &consumed_grant,
            )?;
            return Err(AppError::Unauthorized(
                "verified recovery policy rejected device enrollment".into(),
            ));
        }
    };
    let permit = match vela_rekey_policy::plan_active_mutation(MutationRequest {
        declared_epoch: recovery_permit.epoch(),
        authority_epoch: consumed_epoch,
        kind: MutationKind::Enrollment,
        authority: MutationAuthority::RecoveryGrant,
    }) {
        MutationDecision::Permit(permit) => permit,
        MutationDecision::Reject => {
            crate::recovery::recover::restore_enroll_grant(
                &state,
                body.user_id,
                body.recovery_grant,
                &consumed_grant,
            )?;
            return Err(AppError::Unauthorized(
                "recovery grant changed while redeeming".into(),
            ));
        }
    };

    let new_device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let device_name = body
        .device_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Recovered Device".to_string());
    let device_type = body
        .device_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let inserted = if consumed_grant.possession {
        insert_recovered_device(
            &state,
            &InsertRecoveredDevice {
                device_id: new_device_id,
                user_id: body.user_id.clone(),
                device_name: &device_name,
                device_type: &device_type,
                hybrid_ek_b64: crate::db::encode_b64(&hybrid_ek),
                hybrid_vk_b64: crate::db::encode_b64(&hybrid_vk),
                created_at: now.clone(),
                epoch: permit.epoch(),
                guard_credential: None,
            },
        )
        .await
    } else {
        insert_recovered_device(
            &state,
            &InsertRecoveredDevice {
                device_id: new_device_id,
                user_id: body.user_id.clone(),
                device_name: &device_name,
                device_type: &device_type,
                hybrid_ek_b64: crate::db::encode_b64(&hybrid_ek),
                hybrid_vk_b64: crate::db::encode_b64(&hybrid_vk),
                created_at: now.clone(),
                epoch: permit.epoch(),
                guard_credential: Some(consumed_grant.credential_id.clone()),
            },
        )
        .await
    };
    let inserted = match inserted {
        Ok(inserted) => inserted,
        Err(error) => {
            crate::recovery::recover::restore_enroll_grant(
                &state,
                body.user_id,
                body.recovery_grant,
                &consumed_grant,
            )?;
            return Err(AppError::Internal(error.to_string()));
        }
    };
    if inserted == 0 {
        let current = match state
            .sqldb
            .query(
                "SELECT recovery_webauthn_cred_id, recovery_auth_hash FROM users WHERE id = ?",
                vec![TursoValue::Text(body.user_id.to_string())],
            )
            .await
        {
            Ok(current) => current,
            Err(error) => {
                crate::recovery::recover::restore_enroll_grant(
                    &state,
                    body.user_id,
                    body.recovery_grant,
                    &consumed_grant,
                )?;
                return Err(AppError::Internal(error.to_string()));
            }
        };
        let Some(row) = current.first() else {
            crate::recovery::recover::restore_enroll_grant(
                &state,
                body.user_id,
                body.recovery_grant,
                &consumed_grant,
            )?;
            return Err(AppError::NotFound("account no longer exists".into()));
        };
        if consumed_grant.possession {
            if !matches!(row.get(1), Some(TursoValue::Text(_))) {
                // Setup deletion is revocation, not a retryable rotation:
                // leave the old grant consumed.
                return Err(AppError::Unauthorized(
                    "recovery grant was invalidated by recovery setup deletion or rotation".into(),
                ));
            }
        } else if row.text(0) != Some(consumed_grant.credential_id.as_str()) {
            // Credential replacement is revocation, not a retryable rotation:
            // leave the old grant consumed.
            return Err(AppError::Unauthorized(
                "recovery grant was invalidated by credential replacement".into(),
            ));
        }
        crate::recovery::recover::restore_enroll_grant(
            &state,
            body.user_id,
            body.recovery_grant,
            &consumed_grant,
        )?;
        return Err(AppError::Conflict(
            "device enrollment is paused during vault key rotation".into(),
        ));
    }

    tracing::info!(
        new_device_id = %new_device_id,
        user_id = %body.user_id,
        "device enrolled via account recovery"
    );

    Ok(Json(EnrollDeviceResponse {
        device_id: new_device_id,
    }))
}

struct InsertRecoveredDevice<'a> {
    device_id: Uuid,
    user_id: Uuid,
    device_name: &'a str,
    device_type: &'a str,
    hybrid_ek_b64: String,
    hybrid_vk_b64: String,
    created_at: String,
    epoch: i64,
    /// `Some(credential_id)` for WebAuthn-bound grants: the insert only lands
    /// while that exact credential is still current. `None` for possession
    /// grants: the insert only lands while the RMS commitment still exists.
    guard_credential: Option<String>,
}

async fn insert_recovered_device(
    state: &AppState,
    body: &InsertRecoveredDevice<'_>,
) -> Result<u64> {
    let (guard_sql, guard_param) = match &body.guard_credential {
        Some(credential_id) => (
            "AND recovery_webauthn_cred_id = ?",
            Some(TursoValue::Text(credential_id.clone())),
        ),
        None => ("AND recovery_auth_hash IS NOT NULL", None),
    };
    let sql = format!(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, NULL, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
               {guard_sql}
         )"
    );
    let mut params = vec![
        TursoValue::Text(body.device_id.to_string()),
        TursoValue::Text(body.user_id.to_string()),
        TursoValue::Text(body.device_name.to_string()),
        TursoValue::Text(body.device_type.to_string()),
        TursoValue::Text(body.hybrid_ek_b64.clone()),
        TursoValue::Text(body.hybrid_vk_b64.clone()),
        TursoValue::Text(body.created_at.clone()),
        TursoValue::Text(body.user_id.to_string()),
        TursoValue::Integer(body.epoch),
    ];
    params.extend(guard_param);
    state
        .sqldb
        .execute(&sql, params)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
}
