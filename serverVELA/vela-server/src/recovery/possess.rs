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
        AttemptBudgetObservation, AttemptConsumptionObservation, ChallengeStoreObservation,
        CommitmentObservation, GrantStoreObservation, InitiateEffect, InitiateFailure,
        InitiateObservation, ProofAccountObservation, ProofGrantPermit, ProofObservation,
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

    // Effect: read the live row and decode the staged commitment, probe the
    // generated attempt slot, and (once the driver authorizes it) draw and
    // atomically store the challenge. Every post-preflight decision and effect
    // goes through the proved `possession_initiation_interpreter!` loop; this
    // handler only supplies the I/O and renders the terminal effect.
    let mut io = InitiateProofIo {
        state: &state,
        user_id: body.user_id,
        recovery_id: Uuid::new_v4(),
        key_epoch: observed_recovery_epoch(None),
        commitment_decode_error: None,
        challenge: None,
        error: None,
    };
    let Some(transition) = vela_recovery_policy::possession_initiation_interpreter!(io, await) else {
        return Err(io.error.take().unwrap_or_else(|| {
            AppError::Internal("possession initiation aborted without an error".into())
        }));
    };
    match transition.effect {
        InitiateEffect::Complete => {}
        InitiateEffect::Fail(failure) => {
            return Err(initiate_failure_error(
                failure,
                io.commitment_decode_error.take(),
            ))
        }
        _ => {
            return Err(AppError::Internal(
                "possession initiation driver reached no verdict".into(),
            ))
        }
    }
    let challenge = io.challenge.take().ok_or_else(|| {
        AppError::Internal("possession initiation completed without a challenge".into())
    })?;

    tracing::info!(user_id = %body.user_id, "possession-proof recovery initiated");

    Ok(Json(InitiateProofResponse {
        recovery_id: io.recovery_id,
        challenge_b64: B64.encode(&challenge),
        key_epoch: io.key_epoch,
    }))
}

/// The I/O behind each possession-initiation effect. The driver decides which
/// method runs and when (through the shared
/// `possession_initiation_interpreter!` loop, proved in F* as
/// `run_possession_initiation`); each method only performs its effect and
/// reports the observation. `None` aborts with `error`.
struct InitiateProofIo<'a> {
    state: &'a AppState,
    user_id: Uuid,
    recovery_id: Uuid,
    key_epoch: i64,
    commitment_decode_error: Option<AppError>,
    challenge: Option<Vec<u8>>,
    error: Option<AppError>,
}

impl InitiateProofIo<'_> {
    /// Read the live row, decode the staged commitment and probe the attempt
    /// slot. Decode failures are observations (`Corrupt`), not decisions.
    async fn observe(&mut self) -> Option<InitiateObservation> {
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT recovery_share, recovery_auth_hash, key_epoch, rekey_state
                 FROM users WHERE id = ?",
                vec![TursoValue::Text(self.user_id.to_string())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
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
                                self.commitment_decode_error = Some(error);
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
        self.key_epoch = key_epoch;
        // Observe freshness for the policy; the store below checks it
        // atomically again, because another request may win after this
        // observation.
        let attempt_id_fresh = match self
            .state
            .store
            .exists(&proof_state_key(&self.user_id, &self.recovery_id))
        {
            Ok(occupied) => !occupied,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        Some(InitiateObservation {
            account_present,
            share_present,
            commitment,
            rotation_active,
            attempt_id_fresh,
            ttl_secs: PROOF_STATE_TTL_SECS,
        })
    }

    /// Draw and atomically store the challenge the driver authorized.
    async fn store_challenge(&mut self) -> Option<ChallengeStoreObservation> {
        let mut challenge = vec![0u8; CHALLENGE_LEN];
        if let Err(error) = getrandom::getrandom(&mut challenge) {
            self.error = Some(AppError::Internal(format!(
                "failed to draw challenge: {error}"
            )));
            return None;
        }
        let stored = store_proof_state(
            self.state,
            &PossessionProofState {
                user_id: self.user_id,
                recovery_id: self.recovery_id,
                challenge: challenge.clone(),
                key_epoch: self.key_epoch,
            },
        );
        match stored {
            Ok(observation) => {
                self.challenge = Some(challenge);
                Some(observation)
            }
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }
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

    // Effect: count the attempt, consume the single-use proof state, query the
    // live row, verify the proof and issue the grant. Every post-preflight
    // decision and effect goes through the proved
    // `possession_recover_interpreter!` loop; this handler only supplies the
    // I/O and renders the terminal effect.
    let mut io = RecoverProofIo {
        state: &state,
        ip,
        user_id: body.user_id,
        recovery_id: body.recovery_id,
        proof_b64: body.proof_b64,
        presented: None,
        limited_error: None,
        attempt_state: None,
        attempt_decode_error: None,
        commitment_bytes: None,
        commitment_decode_error: None,
        grant: None,
        grant_error: None,
        error: None,
    };
    let Some(transition) = vela_recovery_policy::possession_recover_interpreter!(io, await) else {
        return Err(io.error.take().unwrap_or_else(|| {
            AppError::Internal("possession recovery aborted without an error".into())
        }));
    };
    match transition.effect {
        ProofRecoverEffect::Complete => {
            let (key_epoch, recovery_grant) = io.grant.take().ok_or_else(|| {
                AppError::Internal("possession recovery completed without a grant".into())
            })?;
            tracing::info!(
                user_id = %body.user_id,
                "recovery grant issued from RMS possession proof"
            );
            Ok(Json(RecoverProofResponse {
                key_epoch,
                recovery_grant,
            }))
        }
        ProofRecoverEffect::Fail(failure) => Err(match failure {
            ProofRecoverFailure::AttemptLimited => io.limited_error.take().unwrap_or_else(|| {
                AppError::Internal("possession recovery attempt was limited".into())
            }),
            ProofRecoverFailure::AttemptMissing => AppError::BadRequest(
                "recovery challenge expired or already used".into(),
            ),
            ProofRecoverFailure::AttemptCorrupt => {
                io.attempt_decode_error.take().unwrap_or_else(|| {
                    AppError::Internal("possession challenge state did not decode".into())
                })
            }
            ProofRecoverFailure::BindingMismatch => AppError::Unauthorized(
                "possession challenge binding does not match this attempt".into(),
            ),
            ProofRecoverFailure::AccountAbsent => {
                AppError::NotFound(RECOVERY_UNAVAILABLE.into())
            }
            ProofRecoverFailure::RotationPaused => AppError::Conflict(
                "account recovery is paused during vault key rotation".into(),
            ),
            ProofRecoverFailure::CommitmentMissing => AppError::Unauthorized(
                "no possession commitment is staged for this account".into(),
            ),
            ProofRecoverFailure::CommitmentCorrupt => {
                io.commitment_decode_error.take().unwrap_or_else(|| {
                    AppError::Internal("possession commitment did not decode".into())
                })
            }
            ProofRecoverFailure::ProofRejected => AppError::Unauthorized(
                "RMS possession proof failed for this attempt".into(),
            ),
            ProofRecoverFailure::GrantStorage => io.grant_error.take().unwrap_or_else(|| {
                AppError::Internal("failed to store the recovery grant".into())
            }),
        }),
        _ => Err(AppError::Internal(
            "possession recovery driver reached no verdict".into(),
        )),
    }
}

/// The I/O behind each proof-recovery effect. The driver decides which method
/// runs and when (through the shared `possession_recover_interpreter!` loop,
/// proved in F* as `run_possession_recover`); each method only performs its
/// effect and reports the observation. `None` aborts with `error`.
struct RecoverProofIo<'a> {
    state: &'a AppState,
    ip: String,
    user_id: Uuid,
    recovery_id: Uuid,
    proof_b64: String,
    presented: Option<Vec<u8>>,
    limited_error: Option<AppError>,
    attempt_state: Option<PossessionProofState>,
    attempt_decode_error: Option<AppError>,
    commitment_bytes: Option<Vec<u8>>,
    commitment_decode_error: Option<AppError>,
    grant: Option<(i64, Uuid)>,
    grant_error: Option<AppError>,
    error: Option<AppError>,
}

impl RecoverProofIo<'_> {
    /// Count one attempt. The limiter's own error is kept for the response.
    async fn count_attempt(&mut self) -> Option<AttemptBudgetObservation> {
        let limited_error = match rate_limit::recovery_recover_by_ip_user(
            &self.state.store,
            &self.ip,
            &self.user_id.to_string(),
        ) {
            Ok(()) => {
                rate_limit::recovery_recover_by_user(&self.state.store, &self.user_id.to_string())
                    .err()
            }
            Err(error) => Some(error),
        };
        let observation = if limited_error.is_some() {
            AttemptBudgetObservation::Limited
        } else {
            AttemptBudgetObservation::Admitted
        };
        self.limited_error = limited_error;
        Some(observation)
    }

    /// Decode the presented proof and consume the exact attempt state once. A
    /// decode failure still consumed the state: the driver records the
    /// corruption as terminal rather than assuming the store returned nothing.
    async fn consume_attempt(&mut self) -> Option<AttemptConsumptionObservation> {
        let proof_bytes = match B64.decode(&self.proof_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("proof is not valid base64".into()));
                return None;
            }
        };
        self.presented = Some(proof_bytes);
        let observed = match observe_proof_attempt(self.state, &self.user_id, &self.recovery_id) {
            Ok(observed) => observed,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        let observation = match observed {
            StoredProofAttempt::Missing => AttemptConsumptionObservation::Missing,
            StoredProofAttempt::Corrupt(message) => {
                self.attempt_decode_error = Some(AppError::BadRequest(format!(
                    "invalid possession challenge state: {message}"
                )));
                AttemptConsumptionObservation::Corrupt
            }
            StoredProofAttempt::Present(envelope) => {
                let observation = AttemptConsumptionObservation::Present {
                    user_matches: envelope.user_id == self.user_id,
                    attempt_matches: envelope.recovery_id == self.recovery_id,
                    key_epoch: envelope.key_epoch,
                };
                self.attempt_state = Some(envelope);
                observation
            }
        };
        Some(observation)
    }

    /// Query the live row and decode the staged commitment.
    async fn query_account(&mut self) -> Option<ProofAccountObservation> {
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT recovery_auth_hash, key_epoch, rekey_state
                 FROM users WHERE id = ?",
                vec![TursoValue::Text(self.user_id.to_string())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let (account_present, account_epoch_active, commitment, stored_epoch) = match rows.first() {
            None => (false, false, CommitmentObservation::Missing, None),
            Some(row) => {
                let account_epoch_active = row.text(2).is_none();
                let stored_epoch = row.i64(1);
                let commitment = match row.get(0) {
                    Some(TursoValue::Text(text)) => match crate::db::decode_b64(&text) {
                        Ok(bytes) => {
                            self.commitment_bytes = Some(bytes.clone());
                            CommitmentObservation::Present { len: bytes.len() }
                        }
                        Err(error) => {
                            self.commitment_decode_error = Some(error);
                            CommitmentObservation::Corrupt
                        }
                    },
                    _ => CommitmentObservation::Missing,
                };
                (true, account_epoch_active, commitment, stored_epoch)
            }
        };
        Some(ProofAccountObservation {
            account_present,
            account_epoch_active,
            commitment,
            stored_epoch,
        })
    }

    /// Verify the presented proof against the staged public commitment.
    async fn verify_proof(&mut self) -> Option<ProofObservation> {
        let (Some(commitment), Some(attempt), Some(presented)) = (
            self.commitment_bytes.as_ref(),
            self.attempt_state.as_ref(),
            self.presented.as_ref(),
        ) else {
            self.error = Some(AppError::Internal(
                "possession recovery driver admitted an unverified observation".into(),
            ));
            return None;
        };
        Some(ProofObservation {
            verified: verify_possession_proof(self.state, commitment, attempt, presented),
        })
    }

    /// Store exactly one single-use grant at the driver's epoch.
    async fn issue_grant(&mut self, permit: ProofGrantPermit) -> Option<GrantStoreObservation> {
        let recovery_grant = Uuid::new_v4();
        let store_result =
            store_possession_grant(self.state, self.user_id, recovery_grant, permit.epoch);
        let observation = if store_result.is_ok() {
            GrantStoreObservation::Stored
        } else {
            GrantStoreObservation::Failed
        };
        self.grant = Some((permit.epoch, recovery_grant));
        if let Err(error) = store_result {
            self.grant_error = Some(error);
        }
        Some(observation)
    }
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
