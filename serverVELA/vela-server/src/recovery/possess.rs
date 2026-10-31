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
    state::AppState,
};

use super::initiate::RECOVERY_UNAVAILABLE;
use super::sql::{
    probe_proof_slot, put_enrollment_grant, run_possession_read, store_proof_challenge,
    take_proof_attempt, PoolSql, RecoveryKv, RecoverySql, StoreKv,
};
use vela_recovery_policy::{
    observed_recovery_epoch,
    possession_driver::{
        AttemptBudgetObservation, AttemptConsumptionObservation, ChallengeStoreObservation,
        GrantStoreObservation, InitiateEffect, InitiateFailure, InitiateObservation,
        ProofAccountObservation, ProofGrantPermit, ProofObservation, ProofRecoverEffect,
        ProofRecoverFailure,
    },
    possession_store::{self, EnrollmentGrantView, ProofAttemptTake, ProofAttemptView},
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

/// Commit only while this exact user/attempt slot is free. A fresh v4 id makes
/// a collision negligible, but an observed-free slot is not authorization to
/// overwrite another writer's challenge.
#[cfg(test)]
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

/// Verify the presented proof against the stored public commitment for one
/// exact attempt. Delegates to `vela_crypto::recovery::rms_possession_verify`
/// (the same construction used by every client), so sign and verify can never
/// drift.
pub(crate) fn verify_possession_proof(
    allow_legacy_possession_v1: bool,
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
        allow_legacy_possession_v1,
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
        sql: PoolSql(&state.sqldb),
        kv: StoreKv(&state.store),
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
pub(super) struct InitiateProofIo<S, K> {
    sql: S,
    kv: K,
    user_id: Uuid,
    recovery_id: Uuid,
    key_epoch: i64,
    commitment_decode_error: Option<AppError>,
    challenge: Option<Vec<u8>>,
    error: Option<AppError>,
}

impl<S: RecoverySql, K: RecoveryKv> InitiateProofIo<S, K> {
    /// Read the live row, decode the staged commitment and probe the attempt
    /// slot. Decode failures are observations (`Corrupt`), not decisions.
    pub(super) async fn observe(&mut self) -> Option<InitiateObservation> {
        let stmt = possession_store::plan_initiate_account(self.user_id.to_string());
        let rows = match run_possession_read(&mut self.sql, &stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let (row, decode_error) = super::sql::initiate_row(&rows);
        if decode_error.is_some() {
            self.commitment_decode_error = decode_error;
        }
        self.key_epoch = possession_store::initiate_epoch(&row);
        // Observe freshness for the policy; the store below checks it
        // atomically again, because another request may win after this
        // observation.
        let stmt = possession_store::plan_proof_slot(proof_state_key(
            &self.user_id,
            &self.recovery_id,
        ));
        let occupied = match probe_proof_slot(&mut self.kv, &stmt) {
            Ok(occupied) => occupied,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        Some(possession_store::classify_initiate(
            row,
            occupied,
            PROOF_STATE_TTL_SECS,
        ))
    }

    /// Draw and atomically store the challenge the driver authorized.
    pub(super) async fn store_challenge(&mut self) -> Option<ChallengeStoreObservation> {
        let mut challenge = vec![0u8; CHALLENGE_LEN];
        if let Err(error) = getrandom::getrandom(&mut challenge) {
            self.error = Some(AppError::Internal(format!(
                "failed to draw challenge: {error}"
            )));
            return None;
        }
        let envelope = PossessionProofState {
            user_id: self.user_id,
            recovery_id: self.recovery_id,
            challenge: challenge.clone(),
            key_epoch: self.key_epoch,
        };
        let value = match serde_json::to_string(&envelope) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(AppError::Internal(format!(
                    "failed to serialize proof state: {error}"
                )));
                return None;
            }
        };
        let stmt = possession_store::plan_store_challenge(
            proof_state_key(&self.user_id, &self.recovery_id),
            value,
            ProofAttemptView {
                user: self.user_id.to_string(),
                attempt: self.recovery_id.to_string(),
                key_epoch: self.key_epoch,
            },
            PROOF_STATE_TTL_SECS,
        );
        let written = match store_proof_challenge(&mut self.kv, &stmt) {
            Ok(written) => written,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        self.challenge = Some(challenge);
        Some(possession_store::classify_store_challenge(written))
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
        store: &state.store,
        allow_legacy_possession_v1: state.config.allow_legacy_possession_v1,
        sql: PoolSql(&state.sqldb),
        kv: StoreKv(&state.store),
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
        grant_id: None,
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
pub(super) struct RecoverProofIo<'a, S, K> {
    store: &'a crate::store::Store,
    allow_legacy_possession_v1: bool,
    sql: S,
    kv: K,
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
    /// A fixed grant id for the conformance test; `None` draws a fresh one
    /// exactly when the grant is issued, as the handler always has.
    grant_id: Option<Uuid>,
    grant_error: Option<AppError>,
    error: Option<AppError>,
}

impl<S: RecoverySql, K: RecoveryKv> RecoverProofIo<'_, S, K> {
    /// Count one attempt. The limiter's own error is kept for the response.
    async fn count_attempt(&mut self) -> Option<AttemptBudgetObservation> {
        let limited_error = match rate_limit::recovery_recover_by_ip_user(
            self.store,
            &self.ip,
            &self.user_id.to_string(),
        ) {
            Ok(()) => {
                rate_limit::recovery_recover_by_user(self.store, &self.user_id.to_string()).err()
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
    pub(super) async fn consume_attempt(&mut self) -> Option<AttemptConsumptionObservation> {
        let proof_bytes = match B64.decode(&self.proof_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("proof is not valid base64".into()));
                return None;
            }
        };
        self.presented = Some(proof_bytes);
        let stmt = possession_store::plan_take_attempt(proof_state_key(
            &self.user_id,
            &self.recovery_id,
        ));
        let bytes = match take_proof_attempt(&mut self.kv, &stmt) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error = Some(error);
                return None;
            }
        };
        let taken = match bytes {
            None => ProofAttemptTake::Missing,
            Some(bytes) => match serde_json::from_slice::<PossessionProofState>(&bytes) {
                Ok(envelope) => {
                    let view = ProofAttemptView {
                        user: envelope.user_id.to_string(),
                        attempt: envelope.recovery_id.to_string(),
                        key_epoch: envelope.key_epoch,
                    };
                    self.attempt_state = Some(envelope);
                    ProofAttemptTake::Present(view)
                }
                Err(error) => {
                    self.attempt_decode_error = Some(AppError::BadRequest(format!(
                        "invalid possession challenge state: {error}"
                    )));
                    ProofAttemptTake::Corrupt
                }
            },
        };
        Some(possession_store::classify_attempt(
            &taken,
            &self.user_id.to_string(),
            &self.recovery_id.to_string(),
        ))
    }

    /// Query the live row and decode the staged commitment.
    pub(super) async fn query_account(&mut self) -> Option<ProofAccountObservation> {
        let stmt = possession_store::plan_proof_account(self.user_id.to_string());
        let rows = match run_possession_read(&mut self.sql, &stmt).await {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return None;
            }
        };
        let (row, decode_error, commitment_bytes) = super::sql::proof_account_row(&rows);
        if decode_error.is_some() {
            self.commitment_decode_error = decode_error;
        }
        self.commitment_bytes = commitment_bytes;
        Some(possession_store::classify_proof_account(row))
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
            verified: verify_possession_proof(
                self.allow_legacy_possession_v1,
                commitment,
                attempt,
                presented,
            ),
        })
    }

    /// Store exactly one single-use grant at the driver's epoch.
    pub(super) async fn issue_grant(&mut self, permit: ProofGrantPermit) -> Option<GrantStoreObservation> {
        let recovery_grant = self.grant_id.unwrap_or_else(Uuid::new_v4);
        let value = match serde_json::to_string(&super::recover::possession_grant(permit.epoch)) {
            Ok(value) => value,
            Err(error) => {
                self.grant_error = Some(AppError::Internal(format!(
                    "failed to serialize recovery grant: {error}"
                )));
                self.grant = Some((permit.epoch, recovery_grant));
                return Some(GrantStoreObservation::Failed);
            }
        };
        let stmt = possession_store::plan_issue_grant(
            super::recover::enroll_grant_key(self.user_id, recovery_grant),
            value,
            EnrollmentGrantView {
                key_epoch: permit.epoch,
            },
            super::recover::ENROLL_GRANT_TTL_SECS,
        );
        let stored = put_enrollment_grant(&mut self.kv, &stmt);
        let observation = possession_store::classify_grant_store(stored.is_ok());
        self.grant = Some((permit.epoch, recovery_grant));
        if let Err(error) = stored {
            self.grant_error = Some(error);
        }
        Some(observation)
    }
}

/// Construction and side-channel access for the bounded real-store
/// conformance test (`recovery/conformance.rs`).
#[cfg(test)]
impl<S, K> InitiateProofIo<S, K> {
    pub(super) fn for_conformance(
        sql: S,
        kv: K,
        user_id: Uuid,
        recovery_id: Uuid,
        key_epoch: i64,
    ) -> Self {
        Self {
            sql,
            kv,
            user_id,
            recovery_id,
            key_epoch,
            commitment_decode_error: None,
            challenge: None,
            error: None,
        }
    }

    pub(super) fn error_is_set(&self) -> bool {
        self.error.is_some()
    }

    pub(super) fn commitment_decode_error_is_set(&self) -> bool {
        self.commitment_decode_error.is_some()
    }

    pub(super) fn challenge(&self) -> Option<&Vec<u8>> {
        self.challenge.as_ref()
    }

    pub(super) fn key_epoch(&self) -> i64 {
        self.key_epoch
    }
}

#[cfg(test)]
impl<'a, S, K> RecoverProofIo<'a, S, K> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn for_conformance(
        store: &'a crate::store::Store,
        sql: S,
        kv: K,
        user_id: Uuid,
        recovery_id: Uuid,
        proof_b64: String,
    ) -> Self {
        Self {
            store,
            allow_legacy_possession_v1: false,
            sql,
            kv,
            ip: "127.0.0.1".into(),
            user_id,
            recovery_id,
            proof_b64,
            presented: None,
            limited_error: None,
            attempt_state: None,
            attempt_decode_error: None,
            commitment_bytes: None,
            commitment_decode_error: None,
            grant: None,
            grant_id: Some(Uuid::from_u128(0x2000)),
            grant_error: None,
            error: None,
        }
    }

    pub(super) fn error_is_set(&self) -> bool {
        self.error.is_some()
    }

    pub(super) fn attempt_decode_error_is_set(&self) -> bool {
        self.attempt_decode_error.is_some()
    }

    pub(super) fn commitment_decode_error_is_set(&self) -> bool {
        self.commitment_decode_error.is_some()
    }

    pub(super) fn commitment_bytes(&self) -> Option<&Vec<u8>> {
        self.commitment_bytes.as_ref()
    }

    pub(super) fn grant(&self) -> Option<(i64, Uuid)> {
        self.grant
    }

    pub(super) fn grant_error_is_set(&self) -> bool {
        self.grant_error.is_some()
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
