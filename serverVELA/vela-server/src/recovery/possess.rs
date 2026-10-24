//! RMS-possession recovery (M18).
//!
//! A client holding any two shares of the current split — cloud + server,
//! cloud + trusted contact, or server + trusted contact — reconstructs the
//! RMS locally and proves that possession here. The server issues a single-use
//! device-enrollment grant *without* releasing its own share and without any
//! WebAuthn assertion: possession of two shares already implies everything
//! WebAuthn recovery would have established about the caller.
//!
//! The proof is a hybrid signature (ML-DSA-87 ‖ Ed25519) over the attempt id,
//! a fresh per-attempt challenge, and the live epoch, verified against the
//! *public* hybrid verifying-key commitment staged at setup finalization
//! (`recovery_auth_hash`). v2 invariant: the stored value cannot be used to
//! produce proofs — it is only the public half, so a database reader can no
//! longer forge them (the retired v1 scheme keyed a hash with the stored
//! value). Captured proofs are worthless outside their single-use attempt;
//! the commitment leaks nothing usable offline because verification only
//! happens on this rate-limited endpoint.

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

use super::initiate::RECOVERY_UNAVAILABLE;
use super::recover::store_possession_grant;
use vela_recovery_policy::{
    observed_recovery_epoch, plan_possession_recovery, plan_proof_initiation,
    possession_recover_facts, proof_initiate_facts, PossessionRecoverDecision,
    PossessionRecoverObservation, ProofInitiateDecision, ProofInitiateObservation,
    RecoveryAttemptSource,
};

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
    store_proof_state_bytes(
        &state.store,
        &envelope.user_id,
        &envelope.recovery_id,
        &bytes,
    )
}

/// Commit only while this exact user/attempt slot is free. A fresh v4 id makes
/// a collision negligible, but an observed-free slot is not authorization to
/// overwrite another writer's challenge.
fn store_proof_state_bytes(
    store: &crate::store::Store,
    user_id: &Uuid,
    recovery_id: &Uuid,
    bytes: &[u8],
) -> Result<()> {
    if store.set_ex_nx(
        &proof_state_key(user_id, recovery_id),
        bytes,
        PROOF_STATE_TTL_SECS,
    )? {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "possession challenge id is already in use".into(),
        ))
    }
}

/// Observation of one single-use proof attempt, before any row is read.
struct ObservedProofAttempt {
    /// Whether the exact user/attempt key was consumed by this request.
    source: RecoveryAttemptSource,
    /// The decoded envelope's user id equals the request user id.
    user_matches: bool,
    /// The decoded envelope's id equals the request attempt id.
    attempt_matches: bool,
    state: Option<PossessionProofState>,
}

/// Consume the exact attempt state once. `source` remains `Missing` when no
/// state matched, so the handler decides the original error class from the
/// observation instead of assuming the store returned something.
fn observe_proof_attempt(
    state: &AppState,
    user_id: &Uuid,
    recovery_id: &Uuid,
) -> Result<ObservedProofAttempt> {
    let Some(bytes) = state
        .store
        .get_del(&proof_state_key(user_id, recovery_id))?
    else {
        return Ok(ObservedProofAttempt {
            source: RecoveryAttemptSource::Missing,
            user_matches: false,
            attempt_matches: false,
            state: None,
        });
    };
    let envelope: PossessionProofState = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid possession challenge state: {e}")))?;
    Ok(ObservedProofAttempt {
        source: RecoveryAttemptSource::Consumed,
        user_matches: envelope.user_id == *user_id,
        attempt_matches: envelope.recovery_id == *recovery_id,
        state: Some(envelope),
    })
}

/// Verify the presented proof against the stored public commitment for one
/// exact attempt. Delegates to `vela_crypto::recovery::rms_possession_verify`
/// (the same construction used by every client), so sign and verify can never
/// drift.
pub(crate) fn verify_possession_proof(
    state: &AppState,
    commitment: &[u8],
    attempt: &PossessionProofState,
    presented: &[u8],
) -> bool {
    // The commitment length selects the scheme version (32-byte legacy v1
    // keyed-hash, or the 2624-byte hybrid v2 verifying key). The legacy gate
    // is operator-controlled and fails closed once migration completes.
    vela_crypto::recovery::rms_possession_verify_ex(
        commitment,
        &attempt.user_id.to_string(),
        &attempt.recovery_id.to_string(),
        &attempt.challenge,
        attempt.key_epoch,
        presented,
        state.config.allow_legacy_possession_v1,
    )
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
    let account_present = rows.first().is_some();
    let row = rows
        .first()
        .ok_or_else(|| AppError::NotFound(RECOVERY_UNAVAILABLE.into()))?;

    // Rotation retires every share and the commitment alike; never hand out a
    // challenge that outlives them.
    let rotation_active = row.text(3).is_some();
    if rotation_active {
        return Err(AppError::Conflict(
            "account recovery is paused during vault key rotation".into(),
        ));
    }
    let key_epoch = observed_recovery_epoch(row.i64(2));
    // Read-and-validate the stored commitment even though the proof policy
    // does not consume it here: a row whose commitment is not valid base64 is
    // a corrupted store and must fail closed, not surface later mid-proof.
    let commitment_len = match row.get(1) {
        Some(TursoValue::Text(text)) => crate::db::decode_b64(&text)?.len(),
        _ => return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into())),
    };
    let share_present = !matches!(row.get(0), Some(TursoValue::Null) | None);
    if !share_present {
        return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
    }

    let recovery_id = Uuid::new_v4();
    // Observe freshness for the policy; the insert below checks it atomically
    // again, because another request may win after this observation.
    let attempt_id_fresh = !state
        .store
        .exists(&proof_state_key(&body.user_id, &recovery_id))?;

    // The policy sees the decoded commitment length, the rotation column, the
    // share column, the observed slot and the real TTL; the early returns above
    // retain the original status classes and precedence.
    match plan_proof_initiation(proof_initiate_facts(ProofInitiateObservation {
        account_present,
        share_present,
        commitment_len,
        rotation_active,
        attempt_id_fresh,
        ttl_secs: PROOF_STATE_TTL_SECS,
    })) {
        ProofInitiateDecision::Start => {}
        ProofInitiateDecision::Reject if !attempt_id_fresh => {
            return Err(AppError::Conflict(
                "possession challenge id is already in use".into(),
            ));
        }
        ProofInitiateDecision::Reject if commitment_len == 0 => {
            // An empty commitment can never verify a proof, so there is
            // nothing to hand out; the uniform unavailable error avoids
            // distinguishing this corrupted row from an unknown account.
            return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
        }
        ProofInitiateDecision::Reject => {
            return Err(AppError::Internal(
                "verified recovery policy rejected possession initiation".into(),
            ));
        }
    }

    let mut challenge = vec![0u8; CHALLENGE_LEN];
    getrandom::getrandom(&mut challenge)
        .map_err(|e| AppError::Internal(format!("failed to draw challenge: {e}")))?;

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
    let presented = proof_bytes; // length checked by verify (v1: 32 B, v2: 4659 B)

    let observed_attempt = observe_proof_attempt(&state, &body.user_id, &body.recovery_id)?;
    let attempt = observed_attempt
        .state
        .ok_or_else(|| AppError::BadRequest("recovery challenge expired or already used".into()))?;
    if !observed_attempt.user_matches || !observed_attempt.attempt_matches {
        return Err(AppError::Unauthorized(
            "possession challenge binding does not match this attempt".into(),
        ));
    }

    let rows = state
        .sqldb
        .query(
            "SELECT recovery_auth_hash, key_epoch, rekey_state
             FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row_present = rows.first().is_some();
    let Some(row) = rows.first() else {
        return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
    };
    let account_epoch_active = row.text(2).is_none();
    if !account_epoch_active {
        return Err(AppError::Conflict(
            "account recovery is paused during vault key rotation".into(),
        ));
    }
    let commitment = match row.get(0) {
        Some(TursoValue::Text(text)) => crate::db::decode_b64(&text)?,
        _ => {
            return Err(AppError::Unauthorized(
                "no possession commitment is staged for this account".into(),
            ));
        }
    };

    let proof_verified = verify_possession_proof(&state, &commitment, &attempt, &presented);

    // Every value below is decoded from the consumed envelope and the live
    // row: identity equality, the staged commitment's decoded length and
    // epoch, and the verified cryptographic result.
    let observed = PossessionRecoverObservation {
        attempt_source: observed_attempt.source,
        account_present: row_present,
        user_matches: observed_attempt.user_matches,
        attempt_matches: observed_attempt.attempt_matches,
        proof_verified,
        account_epoch_active,
        commitment_len: commitment.len(),
        commitment_epoch: attempt.key_epoch,
        stored_epoch: row.i64(1),
    };
    let permit = match plan_possession_recovery(possession_recover_facts(observed)) {
        PossessionRecoverDecision::Grant(permit) => permit,
        PossessionRecoverDecision::Reject => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_possession_attempt_cannot_replace_the_winning_challenge() {
        let store = crate::store::Store::open_temp().unwrap();
        let user_id = Uuid::new_v4();
        let recovery_id = Uuid::new_v4();
        let key = proof_state_key(&user_id, &recovery_id);

        // Two requests may both observe an empty slot before either writes.
        assert!(!store.exists(&key).unwrap());
        assert!(!store.exists(&key).unwrap());
        store_proof_state_bytes(&store, &user_id, &recovery_id, b"original challenge").unwrap();
        assert!(matches!(
            store_proof_state_bytes(&store, &user_id, &recovery_id, b"replacement challenge"),
            Err(AppError::Conflict(_))
        ));
        assert_eq!(store.get(&key).unwrap().unwrap(), b"original challenge");
    }
}
