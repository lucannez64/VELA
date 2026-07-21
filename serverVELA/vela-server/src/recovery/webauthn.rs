use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyRegistration,
    RegisterPublicKeyCredential,
};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    rate_limit,
    state::AppState,
};

fn cred_id_b64(passkey: &Passkey) -> String {
    B64.encode(passkey.cred_id().as_slice())
}

const REGISTER_STATE_TTL_SECS: u64 = 300;

#[derive(Deserialize)]
pub struct RegisterStartRequest {
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterStartResponse {
    pub public_key: CreationChallengeResponse,
}

#[derive(Serialize)]
pub struct RegisterFinishResponse {
    pub registered: bool,
}

pub async fn post_register_start(
    State(state): State<AppState>,
    session: AuthSession,
    Json(body): Json<RegisterStartRequest>,
) -> Result<(HeaderMap, Json<RegisterStartResponse>)> {
    let existing = recovery_passkey_for_user(&state, session.user_id)?;
    let exclude_credentials: Option<Vec<CredentialID>> =
        existing.map(|pk| vec![pk.cred_id().clone()]);
    let user_name = body
        .user_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| session.user_id.to_string());
    let user_display_name = body
        .user_display_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "VELA recovery key".to_string());

    let (challenge, reg_state) = state
        .webauthn
        .start_passkey_registration(
            session.user_id,
            &user_name,
            &user_display_name,
            exclude_credentials,
        )
        .map_err(|e| {
            AppError::BadRequest(format!("failed to start WebAuthn registration: {e:?}"))
        })?;

    store_register_state(&state, session.user_id, &reg_state)?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(RegisterStartResponse {
            public_key: challenge,
        }),
    ))
}

pub async fn post_register_finish(
    State(state): State<AppState>,
    session: AuthSession,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Result<(HeaderMap, Json<RegisterFinishResponse>)> {
    // Registration ceremonies are rare in normal use (one per recovery-key
    // setup); this bounds how often any single account can drive the
    // duplicate-credential lookup below, independent of the generic
    // per-JTI request limiter.
    rate_limit::webauthn_register_by_user(&state.store, &session.user_id.to_string())?;

    let reg_state = take_register_state(&state, session.user_id)?;
    let passkey = state
        .webauthn
        .finish_passkey_registration(&credential, &reg_state)
        .map_err(|e| AppError::Unauthorized(format!("WebAuthn registration failed: {e:?}")))?;

    assert_credential_not_registered_elsewhere(&state, session.user_id, &passkey)?;

    let passkey_json = serde_json::to_string(&passkey)
        .map_err(|e| AppError::Internal(format!("failed to serialize passkey: {e}")))?;
    let cred_id = cred_id_b64(&passkey);
    state
        .db
        .execute(
            "UPDATE users SET recovery_webauthn_credential = $1, recovery_webauthn_cred_id = $2 WHERE id = $3",
            stoolap::params![passkey_json, cred_id, session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(RegisterFinishResponse { registered: true })))
}

pub(crate) fn recovery_passkey_for_user(
    state: &AppState,
    user_id: Uuid,
) -> Result<Option<Passkey>> {
    let rows = state
        .db
        .query(
            "SELECT recovery_webauthn_credential FROM users WHERE id = $1",
            stoolap::params![user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound(crate::recovery::initiate::RECOVERY_UNAVAILABLE.into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let v = crate::db::row_val(&row, 0)?;
    if v.is_null() {
        return Ok(None);
    }

    let passkey_json = v
        .as_str()
        .ok_or_else(|| AppError::Internal("expected WebAuthn credential JSON".into()))?;
    serde_json::from_str(passkey_json)
        .map(Some)
        .map_err(|e| AppError::Internal(format!("invalid stored WebAuthn credential: {e}")))
}

pub(crate) fn update_recovery_passkey(
    state: &AppState,
    user_id: Uuid,
    passkey: &Passkey,
) -> Result<()> {
    let passkey_json = serde_json::to_string(passkey)
        .map_err(|e| AppError::Internal(format!("failed to serialize passkey: {e}")))?;
    let cred_id = cred_id_b64(passkey);
    state
        .db
        .execute(
            "UPDATE users SET recovery_webauthn_credential = $1, recovery_webauthn_cred_id = $2 WHERE id = $3",
            stoolap::params![passkey_json, cred_id, user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

/// One-time startup backfill: populate `recovery_webauthn_cred_id` for rows
/// that only have the legacy `recovery_webauthn_credential` JSON blob (i.e.
/// registered before the indexed column existed), so the duplicate-credential
/// check below covers them too instead of silently skipping pre-migration
/// passkeys. Cheap after the first run since the WHERE clause then matches
/// nothing.
pub(crate) fn backfill_webauthn_cred_ids(db: &stoolap::Database) -> anyhow::Result<()> {
    let rows = db.query(
        "SELECT id, recovery_webauthn_credential FROM users
         WHERE recovery_webauthn_credential IS NOT NULL AND recovery_webauthn_cred_id IS NULL",
        (),
    )?;

    for row in rows {
        let row = row?;
        let id = crate::db::row_val(&row, 0)?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("expected user id"))?
            .to_string();
        let passkey_json = crate::db::row_val(&row, 1)?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("expected passkey JSON"))?
            .to_string();
        let passkey: Passkey = match serde_json::from_str(&passkey_json) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!(
                    user_id = %id,
                    error = %e,
                    "skipping unparseable legacy WebAuthn credential during backfill"
                );
                continue;
            }
        };
        let cred_id = cred_id_b64(&passkey);
        if let Err(e) = db.execute(
            "UPDATE users SET recovery_webauthn_cred_id = $1 WHERE id = $2",
            stoolap::params![cred_id, id.clone()],
        ) {
            tracing::warn!(
                user_id = %id,
                error = %e,
                "failed to backfill recovery_webauthn_cred_id"
            );
        }
    }
    Ok(())
}

fn store_register_state(
    state: &AppState,
    user_id: Uuid,
    reg_state: &PasskeyRegistration,
) -> Result<()> {
    let state_json = serde_json::to_vec(reg_state)
        .map_err(|e| AppError::Internal(format!("failed to serialize registration state: {e}")))?;
    state.store.set_ex(
        &format!("recovery:webauthn:register:{user_id}"),
        &state_json,
        REGISTER_STATE_TTL_SECS,
    )
}

fn take_register_state(state: &AppState, user_id: Uuid) -> Result<PasskeyRegistration> {
    let bytes = state
        .store
        .get_del(&format!("recovery:webauthn:register:{user_id}"))?
        .ok_or_else(|| {
            AppError::BadRequest("registration challenge expired or already used".into())
        })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid registration state: {e}")))
}

fn assert_credential_not_registered_elsewhere(
    state: &AppState,
    user_id: Uuid,
    passkey: &Passkey,
) -> Result<()> {
    let cred_id = cred_id_b64(passkey);
    let rows = state
        .db
        .query(
            "SELECT id FROM users WHERE recovery_webauthn_cred_id = $1",
            stoolap::params![cred_id],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    for row in rows {
        let row = row.map_err(|e| AppError::Internal(e.to_string()))?;
        let id = crate::db::row_val(&row, 0)?
            .as_str()
            .ok_or_else(|| AppError::Internal("expected user id".into()))?
            .to_string();
        if id != user_id.to_string() {
            return Err(AppError::Conflict(
                "WebAuthn credential is already registered to another account".into(),
            ));
        }
    }
    Ok(())
}
