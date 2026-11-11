//! One implementation of the production chunk-download admission pipeline.
//!
//! The accept/refuse decisions themselves live in the hax-verified
//! [`vela_sync_policy`] kernels (`plan_sync_epoch_match` and
//! `plan_chunk_download`); the AEAD open lives in [`crate::rekey`]. This module
//! only fixes their order and carries the facts between them, so Android,
//! Apple and WASM cannot drift into three slightly different admission paths
//! (FFI inventory F2/F7). It owns no policy of its own: every branch is either
//! a policy call or the classification of that call's result into a typed
//! refusal a bridge can render.
//!
//! A bridge must not be able to set `aad_binding_verified`: it becomes true
//! only after [`rekey::open_sealed_fleet_chunk`] returned plaintext, inside
//! this function.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::rekey;

/// Facts of one server chunk download.
pub struct DownloadRequest<'a> {
    /// Per-chunk key derived from the RMS.
    pub key: &'a [u8; 32],
    /// Ciphertext exactly as the server returned it.
    pub ciphertext: &'a [u8],
    /// Vault key epoch the server's manifest claims. Untrusted.
    pub epoch: i64,
    /// Epoch this device authenticated, or the floor this tab pinned on first
    /// contact (`None` before the pin). Untrusted only in the sense that the
    /// caller observed it; it never comes from the download response.
    pub local_epoch: Option<i64>,
    pub chunk_id: &'a str,
    /// Revision the server claims for this chunk. Untrusted.
    pub lamport_clock: i64,
    /// Highest revision this device already admitted for the chunk, if any.
    pub last_seen_lamport: Option<i64>,
}

/// Why a download was refused.
///
/// The variants are data, not wording: each bridge renders them into its own
/// error envelope so existing client behaviour (including the legacy-unsealed
/// migration hint, FFI inventory F9) stays byte-compatible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadRefusal {
    /// The server offered an epoch below the one this device already pinned.
    EpochDowngrade { server: i64, seen: i64 },
    /// The server offered a different, higher epoch this device has not adopted.
    EpochChanged { server: i64, seen: i64 },
    /// No pinned epoch and the offered epoch is not positive.
    InvalidEpoch { server: i64 },
    /// The sealed AEAD open failed.
    OpenFailed {
        chunk_id: String,
        epoch: i64,
        lamport_clock: i64,
        /// The crypto layer's message. Uniform for attacker-chosen ciphertext
        /// (`decryption failed`); the pre-C-2 shape refusal is a public-header
        /// message clients key on.
        reason: String,
    },
    /// The verified rollback policy refused the revision.
    Rollback {
        chunk_id: String,
        server: i64,
        last_seen: Option<i64>,
    },
}

/// A chunk that passed every gate. Plaintext leaves only inside this value.
pub struct AdmittedDownload {
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The epoch that was actually authenticated (equal to the request's).
    pub epoch: i64,
    /// The revision the policy admitted, so the caller records exactly what
    /// passed rather than the manifest entry it asked for.
    pub lamport_clock: i64,
}

/// Run the production download pipeline once.
///
/// Order matters and is fixed here:
///
/// 1. exact epoch agreement with the locally authenticated/pinned epoch
///    ([`vela_sync_policy::plan_sync_epoch_match`]);
/// 2. the epoch must be representable as a positive `u64`;
/// 3. the real sealed AEAD open ([`rekey::open_sealed_fleet_chunk`]), which
///    refuses pre-C-2 unsealed shapes before decrypting;
/// 4. the verified rollback decision
///    ([`vela_sync_policy::plan_chunk_download`]).
pub fn admit_download(request: DownloadRequest<'_>) -> Result<AdmittedDownload, DownloadRefusal> {
    let local_epoch = request.local_epoch.unwrap_or(request.epoch);
    if !vela_sync_policy::plan_sync_epoch_match(vela_sync_policy::SyncEpochFacts {
        server_epoch: request.epoch,
        local_epoch,
    }) {
        return Err(match request.local_epoch {
            Some(seen) if request.epoch < seen => DownloadRefusal::EpochDowngrade {
                server: request.epoch,
                seen,
            },
            Some(seen) => DownloadRefusal::EpochChanged {
                server: request.epoch,
                seen,
            },
            None => DownloadRefusal::InvalidEpoch {
                server: request.epoch,
            },
        });
    }

    let epoch = u64::try_from(request.epoch).map_err(|_| DownloadRefusal::InvalidEpoch {
        server: request.epoch,
    })?;
    let plaintext = rekey::open_sealed_fleet_chunk(
        request.key,
        request.ciphertext,
        epoch,
        request.chunk_id,
        request.lamport_clock,
    )
    .map_err(|error| DownloadRefusal::OpenFailed {
        chunk_id: request.chunk_id.to_string(),
        epoch: request.epoch,
        lamport_clock: request.lamport_clock,
        reason: error.to_string(),
    })?;

    match vela_sync_policy::plan_chunk_download(vela_sync_policy::ChunkDownloadFacts {
        server_lamport: request.lamport_clock,
        last_seen_lamport: request.last_seen_lamport,
        // Only a sealed blob that opened under its epoch/chunk/revision AAD
        // reaches this line; no request field can set this fact.
        aad_binding_verified: true,
        key_epoch_positive: request.epoch >= vela_sync_policy::INITIAL_EPOCH,
    }) {
        vela_sync_policy::ChunkDownloadDecision::Accept(permit) => Ok(AdmittedDownload {
            plaintext,
            epoch: request.epoch,
            lamport_clock: permit.lamport(),
        }),
        vela_sync_policy::ChunkDownloadDecision::Reject => Err(DownloadRefusal::Rollback {
            chunk_id: request.chunk_id.to_string(),
            server: request.lamport_clock,
            last_seen: request.last_seen_lamport,
        }),
    }
}

/// Tab/session-local admission state for a caller with no durable store (the
/// web client). The mobile bridges keep the same two facts in Keystore/
/// Keychain-backed settings and pass them into [`admit_download`].
///
/// The state moves only in [`DownloadAdmissionState::record`], which a caller
/// invokes after the plaintext was produced and decoded, so a failed attempt
/// never pins the floor or raises a baseline.
#[derive(Default)]
pub struct DownloadAdmissionState {
    epoch_floor: Option<i64>,
    last_seen: BTreeMap<String, i64>,
}

impl DownloadAdmissionState {
    pub fn epoch_floor(&self) -> Option<i64> {
        self.epoch_floor
    }

    pub fn last_seen(&self, chunk_id: &str) -> Option<i64> {
        self.last_seen.get(chunk_id).copied()
    }

    /// Decide one download against this state, without moving it.
    pub fn admit(
        &self,
        key: &[u8; 32],
        ciphertext: &[u8],
        epoch: i64,
        chunk_id: &str,
        lamport_clock: i64,
    ) -> Result<AdmittedDownload, DownloadRefusal> {
        admit_download(DownloadRequest {
            key,
            ciphertext,
            epoch,
            local_epoch: self.epoch_floor,
            chunk_id,
            lamport_clock,
            last_seen_lamport: self.last_seen(chunk_id),
        })
    }

    /// Record an admission that already passed every gate and whose plaintext
    /// the caller decoded successfully.
    pub fn record(&mut self, admitted: &AdmittedDownload, chunk_id: &str) {
        if self.epoch_floor.is_none() {
            self.epoch_floor = Some(admitted.epoch);
        }
        self.last_seen
            .entry(chunk_id.to_string())
            .and_modify(|seen| *seen = (*seen).max(admitted.lamport_clock))
            .or_insert(admitted.lamport_clock);
    }
}
