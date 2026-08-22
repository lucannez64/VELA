//! Vault re-keying orchestration — the "Rotate keys" action
//! (`docs/VAULT_REKEYING_DESIGN.md` §6).
//!
//! This device drives the protocol end to end: freeze the account, re-encrypt
//! every server chunk under a freshly generated seed, migrate the local secret
//! files, seal the new seed to every device's KEM key, and commit. The server
//! never sees the seed; the other devices adopt it through their own sealed
//! capsules on their next sync (§7.1).
//!
//! Crash-safety comes from ordering, not from journalling here:
//!
//! 1. shadow uploads are idempotent (server-side upsert), so restart replays;
//! 2. capsules are stored *before* local migration, so from that point on any
//!    device — this one, on its next unlock+sync — can complete adoption even
//!    if this process dies;
//! 3. if nothing completes within the server's timeout, the rotation rolls
//!    back cleanly and can be retried.
//!
//! What is deliberately NOT done on this device: reseeding the platform RMS
//! store (TPM/Keychain/secret-service). That material is re-adopted through
//! the capsule path on the next unlock after the epoch moves, which keeps the
//! per-platform storage code out of the rotation's blast radius.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::AppState;

/// Everything succeeded; reported to the UI and written to the audit log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RotateSummary {
    pub from_epoch: i64,
    pub to_epoch: i64,
    /// Chunks re-encrypted and uploaded as shadow rows.
    pub chunks_rekeyed: usize,
    /// Devices the new seed was capsule-sealed to (including this one).
    pub devices_sealed: usize,
}

/// Rotate the account's Root Master Seed.
pub async fn rotate_vault_keys(state: &Arc<AppState>) -> Result<RotateSummary, String> {
    super::vault::require_unlocked(state)?;

    let token = {
        let session = state.session.read();
        session
            .get_server_token()
            .map(|s| s.to_string())
            .ok_or("Not signed in to a server — rotation needs an account")?
    };
    let client = state.api.clone();

    // 0. Probe: refuse politely when another rotation is already running.
    let (current_epoch, rotation_state) = client
        .get_key_epoch(&token)
        .await
        .map_err(|e| format!("Could not read the account's key epoch: {e}"))?;
    if rotation_state != "active" {
        return Err(
            "A key rotation is already in progress for this account. Try again in a few minutes."
                .to_string(),
        );
    }

    // 1. Start: freeze + fetch the work order.
    let (start, new_token) = client
        .rekey_start(&token)
        .await
        .map_err(|e| format!("Could not start the rotation: {e}"))?;
    let mut token = new_token.unwrap_or(token);
    let new_epoch = start.epoch;

    // 2. Fresh seed, locally generated.
    let old_crypto_snapshot = {
        let crypto = state.crypto.read();
        let rms = crypto.as_ref().ok_or("Vault is locked")?.rms();
        crate::crypto::Crypto::new(&rms)
    };
    let new_rms = vela_crypto::rekey::rotate()
        .map_err(|e| format!("Failed to generate a new seed: {e}"))?;
    let new_crypto = crate::crypto::Crypto::new(&new_rms);
    // `new_rms` is zeroized when this scope ends; the Crypto owns the value.

    // 3. Re-encrypt every chunk into a shadow row at the new epoch. Sequential
    //    and bounded-memory; replays are idempotent server-side.
    let mut uploaded = 0usize;
    for chunk in &start.chunks {
        let key_old = old_crypto_snapshot.chunk_key(chunk.chunk_id.as_bytes());
        let (ciphertext, version, lamport, tok) = client
            .get_chunk(&token, &chunk.chunk_id)
            .await
            .map_err(|e| format!("Failed to download chunk {}: {e}", chunk.chunk_id))?;
        if let Some(t) = tok {
            token = t;
        }
        let plaintext = vela_crypto::aead::open_vault_chunk(
            key_old.as_bytes(),
            &ciphertext,
            &chunk.chunk_id,
            lamport,
        )
        .map_err(|e| format!("Chunk {} cannot be decrypted under the current key: {e}", chunk.chunk_id))?;
        let _ = version;

        let key_new = new_crypto.chunk_key(chunk.chunk_id.as_bytes());
        let sealed = vela_crypto::rekey::seal_epoch_chunk(
            key_new.as_bytes(),
            &plaintext,
            new_epoch as u64,
            &chunk.chunk_id,
            lamport.max(chunk.lamport_clock),
        )
        .map_err(|e| format!("Failed to re-seal chunk {}: {e}", chunk.chunk_id))?;

        let effective_version = if chunk.version > 0 { chunk.version } else { 1 };
        let (_, tok) = client
            .put_chunk_with_epoch(
                &token,
                &chunk.chunk_id,
                effective_version,
                sealed,
                lamport.max(chunk.lamport_clock),
                Some(new_epoch),
            )
            .await
            .map_err(|e| format!("Failed to upload re-keyed chunk {}: {e}", chunk.chunk_id))?;
        if let Some(t) = tok {
            token = t;
        }
        uploaded += 1;
    }

    // 4. Capsule fan-out BEFORE touching local state: once every device has its
    //    sealed copy of the new seed, the rotation can always be completed by
    //    anyone who has adopted — including this device later.
    let (devices, _) = client
        .get_devices(&token)
        .await
        .map_err(|e| format!("Failed to list devices for capsule sealing: {e}"))?;
    let mut capsules = std::collections::HashMap::new();
    for device in &devices {
        if device.revoked {
            continue;
        }
        let ek_b64 = device.hybrid_ek.as_deref().ok_or(format!(
            "Device {} did not report its KEM public key; server may be older than this feature",
            device.id
        ))?;
        let ek = B64
            .decode(ek_b64)
            .map_err(|e| format!("Device {} has a malformed KEM key: {e}", device.id))?;
        let capsule =
            crate::crypto::seal_rms_to_device(&ek, &new_crypto.rms())
                .map_err(|e| format!("Failed to seal the new seed for {}: {e}", device.id))?;
        capsules.insert(device.id.to_string(), B64.encode(capsule));
    }
    if let Some(t) = client
        .rekey_store_capsules(&token, &capsules)
        .await
        .map_err(|e| format!("Failed to store the new-seed capsules: {e}"))?
    {
        token = t;
    }

    // 5. Local migration: rewrite every RMS-derived file under the new seed,
    //    then swap the live crypto context.
    state
        .store
        .rekey_secret_files(&old_crypto_snapshot, &new_crypto)
        .map_err(|e| format!("Failed to migrate the local vault files: {e}"))?;
    {
        let mut crypto = state.crypto.write();
        *crypto = Some(new_crypto);
    }

    // 6. Commit: flip the account epoch, sweep superseded rows, unfreeze.
    client
        .rekey_commit(&token)
        .await
        .map_err(|e| format!("Failed to commit the rotation: {e}"))?;

    // 7. Recovery shares of the OLD seed are worthless by construction — they
    //    reconstruct only the retired value. Minting fresh shares of the new
    //    seed and uploading them over the cloud backup rides on the existing
    //    rclone recovery flow and is wired at the UI layer as a follow-up
    //    prompt ("your backup shares were retired — re-back them up now");
    //    until that runs, the audit entry plus this summary tell the user
    //    exactly what state their backup is in.

    let summary = RotateSummary {
        from_epoch: current_epoch,
        to_epoch: new_epoch,
        chunks_rekeyed: uploaded,
        devices_sealed: capsules.len(),
    };

    crate::audit::record_audit_event(
        state,
        crate::audit::AuditAction::VaultRekeyed {
            from_epoch: summary.from_epoch,
            to_epoch: summary.to_epoch,
        },
    );

    tracing::info!(
        from = summary.from_epoch,
        to = summary.to_epoch,
        chunks = summary.chunks_rekeyed,
        devices = summary.devices_sealed,
        "vault re-keyed"
    );

    Ok(summary)
}
