//! RMS-possession recovery (M18).
//!
//! A client holding any two shares of the current split — cloud + server,
//! cloud + trusted contact, or server + trusted contact — reconstructs the
//! RMS locally and proves that possession here. The server issues a single-use
//! device-enrollment grant *without* releasing its own share and without any
//! WebAuthn assertion: possession of two shares already implies everything
//! WebAuthn recovery would have established about the caller.
//!
//! The proof is a BLAKE3 keyed hash over the attempt id, a fresh per-attempt
//! challenge, and the live epoch, keyed by the blind commitment staged at
//! setup finalization (`recovery_auth_hash`). Captured proofs are worthless
//! outside their single-use attempt; the commitment leaks nothing usable
//! offline because verification only happens on this rate-limited endpoint.

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

use super::recover::{store_possession_grant};
use super::initiate::RECOVERY_UNAVAILABLE;

const PROOF_STATE_TTL_SECS: u64 = 300;
const CHALLENGE_LEN: usize = 32;

/// Everything `/recovery/recover/proof` re-derives the expected proof from.
#[derive(Serialize, Deserialize)]
pub(crate) struct PossessionProofState {
    pub user_id: Uuid,
    pub recovery_id: Uuid,
    pub challenge: Vec<u8>,
    pub key_epoch: i64,
}

fn proof_state_key(user_id: &Uuid, recovery_id: &Uuid) -> String {
    format!("recovery:possession:{user_id}:{recovery_id}")
}

pub(crate) fn store_proof_state(state: &AppState, envelope: &PossessionProofState) -> Result<()> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|e| AppError::Internal(format!("failed to serialize proof state: {e}")))?;
    state.store.set_ex(
        &proof_state_key(&envelope.user_id, &envelope.recovery_id),
        &bytes,
        PROOF_STATE_TTL_SECS,
    )
}

fn take_proof_state(state: &AppState, user_id: &Uuid, recovery_id: &Uuid) -> Result<PossessionProofState> {
    let bytes = state
        .store
        .get_del(&proof_state_key(user_id, recovery_id))?
        .ok_or_else(|| AppError::BadRequest("recovery challenge expired or already used".into()))?;
    let envelope: PossessionProofState = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid possession challenge state: {e}")))?;
    if &envelope.user_id != user_id || &envelope.recovery_id != recovery_id {
        return Err(AppError::Unauthorized(
            "possession challenge binding does not match this attempt".into(),
        ));
    }
    Ok(envelope)
}

pub(crate) fn expected_possession_proof(
    commitment: &[u8],
    attempt: &PossessionProofState,
) -> Result<[u8; 32]> {
    let commitment: [u8; 32] = commitment.try_into().map_err(|_| {
        AppError::Internal("stored possession commitment is malformed".into())
    })?;
    Ok(vela_crypto_recovery_mirror::possession_proof(
        &commitment,
        &attempt.user_id.to_string(),
        &attempt.recovery_id.to_string(),
        &attempt.challenge,
        attempt.key_epoch,
    ))
}

/// Server-side mirror of `vela_crypto::recovery::rms_possession_proof`. The
/// server does not depend on the client crypto crate, so the construction is
/// duplicated and pinned by cross-vector tests on both sides.
mod vela_crypto_recovery_mirror {
    pub fn possession_proof(
        possession_hash: &[u8; 32],
        user_id: &str,
        recovery_id: &str,
        challenge: &[u8],
        key_epoch: i64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(possession_hash);
        hasher.update(b"vela recovery possession proof v1");
        hasher.update(&(user_id.len() as u32).to_le_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(&(recovery_id.len() as u32).to_le_bytes());
        hasher.update(recovery_id.as_bytes());
        hasher.update(&(challenge.len() as u32).to_le_bytes());
        hasher.update(challenge);
        hasher.update(&key_epoch.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

#[derive(Deserialize)]
pub struct InitiateProofRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct InitiateProofResponse {
    pub recovery_id: Uuid,
    /// Fresh single-attempt nonce bound into the possession proof.
    pub challenge_b64: String,
    /// Epoch of the commitment being proven against.
    pub key_epoch: i64,
}

pub async fn post_initiate_proof(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<InitiateProofRequest>,
) -> Result<Json<InitiateProofResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::recovery_initiate_by_ip(&state.store, &ip)?;
    rate_limit::recovery_initiate_by_ip_user(&state.store, &ip, &body.user_id.to_string())?;
    rate_limit::recovery_initiate_by_user(&state.store, &body.user_id.to_string())?;

    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share, recovery_auth_hash, key_epoch, rekey_state
             FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound(RECOVERY_UNAVAILABLE.into()))?;

    // Rotation retires every share and the commitment alike; never hand out a
    // challenge that outlives them.
    if row.text(3).is_some() {
        return Err(AppError::Conflict(
            "account recovery is paused during vault key rotation".into(),
        ));
    }
    let key_epoch = row.i64(2).unwrap_or(1).max(1);
    let commitment = match row.get(1) {
        Some(TursoValue::Text(text)) => crate::db::decode_b64(&text)?,
        _ => return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into())),
    };
    if matches!(row.get(0), Some(TursoValue::Null) | None) {
        return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
    }

    match vela_recovery_policy::plan_proof_initiation(vela_recovery_policy::ProofInitiateFacts {
        phase: vela_recovery_policy::RecoveryPhase::Ready,
        account_exists: true,
        share_present: true,
        possession_hash_present: true,
        attempt_id_fresh: true,
        ttl_positive: PROOF_STATE_TTL_SECS > 0,
    }) {
        vela_recovery_policy::ProofInitiateDecision::Start => {}
        vela_recovery_policy::ProofInitiateDecision::Reject => {
            return Err(AppError::Internal(
                "verified recovery policy rejected possession initiation".into(),
            ));
        }
    }

    let mut challenge = vec![0u8; CHALLENGE_LEN];
    getrandom::getrandom(&mut challenge)
        .map_err(|e| AppError::Internal(format!("failed to draw challenge: {e}")))?;

    let recovery_id = Uuid::new_v4();
    store_proof_state(
        &state,
        &PossessionProofState {
            user_id: body.user_id,
            recovery_id,
            challenge: challenge.clone(),
            key_epoch,
        },
    )?;

    tracing::info!(user_id = %body.user_id, "possession-proof recovery initiated");

    Ok(Json(InitiateProofResponse {
        recovery_id,
        challenge_b64: B64.encode(&challenge),
        key_epoch,
    }))
}

#[derive(Deserialize)]
pub struct RecoverProofRequest {
    pub user_id: Uuid,
    pub recovery_id: Uuid,
    pub proof_b64: String,
}

#[derive(Serialize)]
pub struct RecoverProofResponse {
    /// Epoch of the split this grant enrolls against.
    pub key_epoch: i64,
    /// Single-use enrollment grant, exactly like the WebAuthn path's — but
    /// issued without releasing Share 2 or asserting a credential.
    pub recovery_grant: Uuid,
}

pub async fn post_recover_proof(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<RecoverProofRequest>,
) -> Result<Json<RecoverProofResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::recovery_recover_by_ip_user(&state.store, &ip, &body.user_id.to_string())?;
    rate_limit::recovery_recover_by_user(&state.store, &body.user_id.to_string())?;

    let proof_bytes = B64
        .decode(&body.proof_b64)
        .map_err(|_| AppError::BadRequest("proof is not valid base64".into()))?;
    let presented: [u8; 32] = proof_bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("possession proof must be exactly 32 bytes".into()))?;

    let attempt = take_proof_state(&state, &body.user_id, &body.recovery_id)?;

    let rows = state
        .sqldb
        .query(
            "SELECT recovery_auth_hash, key_epoch, rekey_state
             FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound(RECOVERY_UNAVAILABLE.into()))?;
    if row.text(2).is_some() {
        return Err(AppError::Conflict(
            "account recovery is paused during vault key rotation".into(),
        ));
    }
    let account_epoch = row.i64(1).unwrap_or(1).max(1);
    let commitment = match row.get(0) {
        Some(TursoValue::Text(text)) => crate::db::decode_b64(&text)?,
        _ => {
            return Err(AppError::Unauthorized(
                "no possession commitment is staged for this account".into(),
            ));
        }
    };

    let expected = expected_possession_proof(&commitment, &attempt)?;
    let proof_verified = possession_proofs_equal(&expected, &presented);

    let permit = match vela_recovery_policy::plan_possession_recovery(
        vela_recovery_policy::PossessionRecoverFacts {
            phase: vela_recovery_policy::RecoveryPhase::ChallengePending,
            user_matches: attempt.user_id == body.user_id,
            attempt_matches: attempt.recovery_id == body.recovery_id,
            challenge_consumed: true,
            proof_verified,
            account_epoch_active: row.text(2).is_none(),
            commitment_epoch_matches: attempt.key_epoch == account_epoch,
            epoch: account_epoch,
        },
    ) {
        vela_recovery_policy::PossessionRecoverDecision::Grant(permit) => permit,
        vela_recovery_policy::PossessionRecoverDecision::Reject => {
            return Err(AppError::Unauthorized(
                "RMS possession proof failed for this attempt".into(),
            ));
        }
    };
    debug_assert!(!permit.releases_server_share());

    let recovery_grant = Uuid::new_v4();
    store_possession_grant(&state, body.user_id, recovery_grant, permit.epoch())?;

    tracing::info!(user_id = %body.user_id, "recovery grant issued from RMS possession proof");

    Ok(Json(RecoverProofResponse {
        key_epoch: permit.epoch(),
        recovery_grant,
    }))
}

fn possession_proofs_equal(expected: &[u8; 32], presented: &[u8; 32]) -> bool {
    // Constant-time fold so a caller cannot learn how many leading bytes of a
    // proof matched.
    let mut diff = 0u8;
    for (x, y) in expected.iter().zip(presented.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
