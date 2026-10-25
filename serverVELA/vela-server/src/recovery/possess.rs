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
//!
//! Every post-preflight decision of both handlers is delegated to the pure
//! drivers in `vela_recovery_policy::possession_driver`; the handlers below only
//! perform the effects those drivers return and render a failure with the
//! historical HTTP status and message.

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
    observed_recovery_epoch,
    possession_driver::{
        begin_initiation, begin_proof_recover, on_account_observed, on_attempt_consumed,
        on_attempt_counted, on_challenge_stored, on_grant_stored, on_initiation_observed,
        on_proof_observed, AttemptBudgetObservation, AttemptConsumptionObservation,
        ChallengeStoreObservation, CommitmentObservation, GrantStoreObservation, InitiateEffect,
        InitiateFailure, InitiateObservation, ProofAccountObservation, ProofObservation,
        ProofRecoverEffect, ProofRecoverFailure,
    },
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

pub(crate) fn store_proof_state(
    state: &AppState,
    envelope: &PossessionProofState,
) -> Result<ChallengeStoreObservation> {
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
) -> Result<ChallengeStoreObservation> {
    if store.set_ex_nx(
        &proof_state_key(user_id, recovery_id),
        bytes,
        PROOF_STATE_TTL_SECS,
    )? {
        Ok(ChallengeStoreObservation::Stored)
    } else {
        Ok(ChallengeStoreObservation::Lost)
    }
}

/// What the atomic single-use `get_del` of one proof attempt observed.
enum StoredProofAttempt {
    /// No live state matched the exact user/attempt key.
    Missing,
    /// The state was removed but its JSON envelope did not decode.
    Corrupt(String),
    /// The state was removed and decoded.
    Present(PossessionProofState),
}

/// Consume the exact attempt state once. A decode failure still consumed the
/// state: the driver records the corruption as terminal rather than assuming
/// the store returned nothing.
fn observe_proof_attempt(
    state: &AppState,
    user_id: &Uuid,
    recovery_id: &Uuid,
) -> Result<StoredProofAttempt> {
    let Some(bytes) = state
        .store
        .get_del(&proof_state_key(user_id, recovery_id))?
    else {
        return Ok(StoredProofAttempt::Missing);
    };
    match serde_json::from_slice::<PossessionProofState>(&bytes) {
        Ok(envelope) => Ok(StoredProofAttempt::Present(envelope)),
        Err(error) => Ok(StoredProofAttempt::Corrupt(error.to_string())),
    }
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

    // Effect: read the live row and decode the staged commitment. Decode
    // failures are observations (`Corrupt`), not decisions; the driver owns
    // the historical precedence and error class.
    let rows = state
        .sqldb
        .query(
            "SELECT recovery_share, recovery_auth_hash, key_epoch, rekey_state
             FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut commitment_decode_error = None;
    let (account_present, share_present, commitment, rotation_active, key_epoch) =
        match rows.first() {
            None => (
                false,
                false,
                CommitmentObservation::Missing,
                false,
                observed_recovery_epoch(None),
            ),
            Some(row) => {
                let rotation_active = row.text(3).is_some();
                let commitment = match row.get(1) {
                    Some(TursoValue::Text(text)) => match crate::db::decode_b64(&text) {
                        Ok(bytes) => CommitmentObservation::Present { len: bytes.len() },
                        Err(error) => {
                            commitment_decode_error = Some(error);
                            CommitmentObservation::Corrupt
                        }
                    },
                    _ => CommitmentObservation::Missing,
                };
                let share_present = !matches!(row.get(0), Some(TursoValue::Null) | None);
                (
                    true,
                    share_present,
                    commitment,
                    rotation_active,
                    observed_recovery_epoch(row.i64(2)),
                )
            }
        };

    let recovery_id = Uuid::new_v4();
    // Observe freshness for the policy; the insert below checks it atomically
    // again, because another request may win after this observation.
    let attempt_id_fresh = !state
        .store
        .exists(&proof_state_key(&body.user_id, &recovery_id))?;

    let start = begin_initiation();
    debug_assert_eq!(start.effect, InitiateEffect::Observe);
    let transition = on_initiation_observed(
        start.driver,
        InitiateObservation {
            account_present,
            share_present,
            commitment,
            rotation_active,
            attempt_id_fresh,
            ttl_secs: PROOF_STATE_TTL_SECS,
        },
    );
    let driver = transition.driver;
    match transition.effect {
        InitiateEffect::StoreChallenge => {}
        InitiateEffect::Fail(failure) => {
            return Err(initiate_failure_error(failure, commitment_decode_error))
        }
        _ => {
            return Err(AppError::Internal(
                "possession initiation driver produced an unexpected effect".into(),
            ))
        }
    }

    let mut challenge = vec![0u8; CHALLENGE_LEN];
    getrandom::getrandom(&mut challenge)
        .map_err(|e| AppError::Internal(format!("failed to draw challenge: {e}")))?;

    let stored = on_challenge_stored(
        driver,
        store_proof_state(
            &state,
            &PossessionProofState {
                user_id: body.user_id,
                recovery_id,
                challenge: challenge.clone(),
                key_epoch,
            },
        )?,
    );
    match stored.effect {
        InitiateEffect::Complete => {}
        InitiateEffect::Fail(failure) => {
            return Err(initiate_failure_error(failure, None));
        }
        _ => {
            return Err(AppError::Internal(
                "possession initiation driver produced an unexpected store effect".into(),
            ))
        }
    }

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

    // Effect: count the attempt. The checked driver requires an admitted
    // count before it will consume the single-use proof state; the limiter's
    // own error is rendered unchanged.
    let start = begin_proof_recover();
    debug_assert_eq!(start.effect, ProofRecoverEffect::CountAttempt);
    let limited_error =
        match rate_limit::recovery_recover_by_ip_user(&state.store, &ip, &body.user_id.to_string())
        {
            Ok(()) => {
                rate_limit::recovery_recover_by_user(&state.store, &body.user_id.to_string()).err()
            }
            Err(error) => Some(error),
        };
    let budget_observation = if limited_error.is_some() {
        AttemptBudgetObservation::Limited
    } else {
        AttemptBudgetObservation::Admitted
    };
    let transition = on_attempt_counted(start.driver, budget_observation);
    let mut driver = transition.driver;
    match (transition.effect, limited_error) {
        (ProofRecoverEffect::ConsumeAttempt, None) => {}
        (ProofRecoverEffect::Fail(ProofRecoverFailure::AttemptLimited), Some(error)) => {
            return Err(error);
        }
        _ => {
            return Err(AppError::Internal(
                "possession recovery driver produced an unexpected budget effect".into(),
            ))
        }
    }

    let proof_bytes = B64
        .decode(&body.proof_b64)
        .map_err(|_| AppError::BadRequest("proof is not valid base64".into()))?;
    let presented = proof_bytes; // length checked by verify (v1: 32 B, v2: 4659 B)

    let observed_attempt = observe_proof_attempt(&state, &body.user_id, &body.recovery_id)?;
    let (observation, attempt_state, attempt_decode_error) = match observed_attempt {
        StoredProofAttempt::Missing => (AttemptConsumptionObservation::Missing, None, None),
        StoredProofAttempt::Corrupt(message) => (
            AttemptConsumptionObservation::Corrupt,
            None,
            Some(AppError::BadRequest(format!(
                "invalid possession challenge state: {message}"
            ))),
        ),
        StoredProofAttempt::Present(envelope) => (
            AttemptConsumptionObservation::Present {
                user_matches: envelope.user_id == body.user_id,
                attempt_matches: envelope.recovery_id == body.recovery_id,
                key_epoch: envelope.key_epoch,
            },
            Some(envelope),
            None,
        ),
    };
    let transition = on_attempt_consumed(driver, observation);
    driver = transition.driver;
    match transition.effect {
        ProofRecoverEffect::QueryAccount => {}
        ProofRecoverEffect::Fail(ProofRecoverFailure::AttemptMissing) => {
            return Err(AppError::BadRequest(
                "recovery challenge expired or already used".into(),
            ));
        }
        ProofRecoverEffect::Fail(ProofRecoverFailure::AttemptCorrupt) => {
            return Err(attempt_decode_error.unwrap_or_else(|| {
                AppError::Internal("possession challenge state did not decode".into())
            }));
        }
        ProofRecoverEffect::Fail(ProofRecoverFailure::BindingMismatch) => {
            return Err(AppError::Unauthorized(
                "possession challenge binding does not match this attempt".into(),
            ));
        }
        _ => {
            return Err(AppError::Internal(
                "possession recovery driver produced an unexpected consumption effect".into(),
            ))
        }
    }
    let attempt = attempt_state.ok_or_else(|| {
        AppError::Internal("possession recovery driver admitted an undecoded attempt".into())
    })?;

    let rows = state
        .sqldb
        .query(
            "SELECT recovery_auth_hash, key_epoch, rekey_state
             FROM users WHERE id = ?",
            vec![TursoValue::Text(body.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut commitment_bytes = None;
    let mut commitment_decode_error = None;
    let (account_present, account_epoch_active, commitment, stored_epoch) = match rows.first() {
        None => (false, false, CommitmentObservation::Missing, None),
        Some(row) => {
            let account_epoch_active = row.text(2).is_none();
            let stored_epoch = row.i64(1);
            let commitment = match row.get(0) {
                Some(TursoValue::Text(text)) => match crate::db::decode_b64(&text) {
                    Ok(bytes) => {
                        commitment_bytes = Some(bytes.clone());
                        CommitmentObservation::Present { len: bytes.len() }
                    }
                    Err(error) => {
                        commitment_decode_error = Some(error);
                        CommitmentObservation::Corrupt
                    }
                },
                _ => CommitmentObservation::Missing,
            };
            (true, account_epoch_active, commitment, stored_epoch)
        }
    };
    let transition = on_account_observed(
        driver,
        ProofAccountObservation {
            account_present,
            account_epoch_active,
            commitment,
            stored_epoch,
        },
    );
    driver = transition.driver;
    match transition.effect {
        ProofRecoverEffect::VerifyProof => {}
        ProofRecoverEffect::Fail(ProofRecoverFailure::AccountAbsent) => {
            return Err(AppError::NotFound(RECOVERY_UNAVAILABLE.into()));
        }
        ProofRecoverEffect::Fail(ProofRecoverFailure::RotationPaused) => {
            return Err(AppError::Conflict(
                "account recovery is paused during vault key rotation".into(),
            ));
        }
        ProofRecoverEffect::Fail(ProofRecoverFailure::CommitmentMissing) => {
            return Err(AppError::Unauthorized(
                "no possession commitment is staged for this account".into(),
            ));
        }
        ProofRecoverEffect::Fail(ProofRecoverFailure::CommitmentCorrupt) => {
            return Err(commitment_decode_error.unwrap_or_else(|| {
                AppError::Internal("possession commitment did not decode".into())
            }));
        }
        _ => {
            return Err(AppError::Internal(
                "possession recovery driver produced an unexpected account effect".into(),
            ))
        }
    }
    let commitment = commitment_bytes.ok_or_else(|| {
        AppError::Internal("possession recovery driver admitted an undecoded commitment".into())
    })?;

    let proof_verified = verify_possession_proof(&state, &commitment, &attempt, &presented);
    let transition = on_proof_observed(
        driver,
        ProofObservation {
            verified: proof_verified,
        },
    );
    driver = transition.driver;
    let (key_epoch, recovery_grant) = match transition.effect {
        ProofRecoverEffect::IssueGrant(permit) => {
            let recovery_grant = Uuid::new_v4();
            let store_result =
                store_possession_grant(&state, body.user_id, recovery_grant, permit.epoch);
            let observation = if store_result.is_ok() {
                GrantStoreObservation::Stored
            } else {
                GrantStoreObservation::Failed
            };
            let stored = on_grant_stored(driver, observation);
            match (stored.effect, store_result) {
                (ProofRecoverEffect::Complete, Ok(())) => (permit.epoch, recovery_grant),
                (ProofRecoverEffect::Fail(ProofRecoverFailure::GrantStorage), Err(error)) => {
                    return Err(error);
                }
                _ => {
                    return Err(AppError::Internal(
                        "possession recovery driver produced an unexpected grant effect".into(),
                    ))
                }
            }
        }
        ProofRecoverEffect::Fail(ProofRecoverFailure::ProofRejected) => {
            return Err(AppError::Unauthorized(
                "RMS possession proof failed for this attempt".into(),
            ));
        }
        _ => {
            return Err(AppError::Internal(
                "possession recovery driver produced an unexpected proof effect".into(),
            ))
        }
    };

    tracing::info!(user_id = %body.user_id, "recovery grant issued from RMS possession proof");

    Ok(Json(RecoverProofResponse {
        key_epoch,
        recovery_grant,
    }))
}

/// Render an initiation driver failure with the handler's historical status and
/// message. The corrupt-commitment class carries the original decode error
/// captured while building the observation.
fn initiate_failure_error(failure: InitiateFailure, decode_error: Option<AppError>) -> AppError {
    match failure {
        InitiateFailure::AccountUnavailable
        | InitiateFailure::CommitmentMissing
        | InitiateFailure::ShareMissing => AppError::NotFound(RECOVERY_UNAVAILABLE.into()),
        InitiateFailure::RotationPaused => {
            AppError::Conflict("account recovery is paused during vault key rotation".into())
        }
        InitiateFailure::CommitmentCorrupt => decode_error
            .unwrap_or_else(|| AppError::Internal("possession commitment did not decode".into())),
        InitiateFailure::AttemptCollision => {
            AppError::Conflict("possession challenge id is already in use".into())
        }
        InitiateFailure::PolicyRejected => {
            AppError::Internal("verified recovery policy rejected possession initiation".into())
        }
    }
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
        assert_eq!(
            store_proof_state_bytes(&store, &user_id, &recovery_id, b"original challenge").unwrap(),
            ChallengeStoreObservation::Stored
        );
        assert_eq!(
            store_proof_state_bytes(&store, &user_id, &recovery_id, b"replacement challenge")
                .unwrap(),
            ChallengeStoreObservation::Lost
        );
        assert_eq!(store.get(&key).unwrap().unwrap(), b"original challenge");
    }
}
