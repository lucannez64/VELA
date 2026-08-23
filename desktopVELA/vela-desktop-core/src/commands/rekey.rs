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
//! 2. capsules are stored before commit, including a retryable self-capsule;
//! 3. the server commits while the initiator still retains its old local RMS.
//!    A pre-commit crash therefore rolls back cleanly; a post-commit crash is
//!    ordinary capsule adoption on the next sync.
//!
//! After commit, local files, platform storage, any master-password wrapper,
//! and the epoch marker move together. A failed local migration restores the
//! old state and leaves the capsule available for retry.

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

fn accept_new_token(state: &AppState, token: &mut String, refreshed: Option<String>) {
    if let Some(refreshed) = refreshed {
        state.session.write().set_server_token(refreshed.clone());
        *token = refreshed;
    }
}

/// Rotate the account's Root Master Seed.
pub async fn rotate_vault_keys(state: &Arc<AppState>) -> Result<RotateSummary, String> {
    super::vault::require_unlocked(state)?;
    let generation = state.session_generation();
    // Rotation and sync both rewrite the local secret store and touch the same
    // server chunks. Serialize them so neither can observe half-migrated files.
    let _sync_guard = state.sync_mutex.lock().await;

    let mut token = {
        let session = state.session.read();
        session
            .get_server_token()
            .map(|s| s.to_string())
            .ok_or("Not signed in to a server — rotation needs an account")?
    };
    let client = state.api.clone();

    // Only attest after proving this installation retained the private half
    // required to open a future capsule. Legacy pre-v3 devices fail here and
    // cannot trick the server into rotating them out of the account.
    let has_capsule_key = {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Vault is locked")?;
        state
            .store
            .load_identity_keys(crypto)
            .map_err(|e| format!("Failed to inspect this device's re-key capability: {e}"))?
            .map(|identity| !identity.hybrid_dk.is_empty())
            .unwrap_or(false)
    };
    if !has_capsule_key {
        return Err(
            "This legacy device cannot adopt rotated keys; re-enroll it before rotating the vault."
                .into(),
        );
    }
    let refreshed = client
        .mark_rekey_capable(&token)
        .await
        .map_err(|e| format!("Could not register this device's re-key capability: {e}"))?;
    accept_new_token(state, &mut token, refreshed);

    // Capture the current RMS and, for password-backed vaults, prove this
    // session was unlocked with that password before freezing the account.
    // The password wrapper is an independent persistence path and must move
    // with the platform RMS or password unlock would recover the retired key.
    let old_crypto_snapshot = {
        let crypto = state.crypto.read();
        let rms = crypto.as_ref().ok_or("Vault is locked")?.rms();
        crate::crypto::Crypto::new(&rms)
    };
    let rekey_password = crate::sync::password_for_rekey(state, &old_crypto_snapshot.rms())?;

    // 0. Probe: refuse politely when another rotation is already running.
    let (current_epoch, rotation_state, new_token) = client
        .get_key_epoch(&token)
        .await
        .map_err(|e| format!("Could not read the account's key epoch: {e}"))?;
    if rotation_state != "active" {
        return Err(
            "A key rotation is already in progress for this account. Try again in a few minutes."
                .to_string(),
        );
    }
    accept_new_token(state, &mut token, new_token);

    // 1. Start: freeze + fetch the work order.
    let (start, new_token) = client
        .rekey_start(&token)
        .await
        .map_err(|e| format!("Could not start the rotation: {e}"))?;
    accept_new_token(state, &mut token, new_token);
    let new_epoch = start.epoch;

    // Everything before commit runs inside one error boundary. Once `start`
    // has frozen writes, any ordinary preparation failure must explicitly
    // abort instead of leaving the account read-only until timeout.
    let preparation = async {
        // 2. Fresh seed, locally generated.
        let new_rms = zeroize::Zeroizing::new(
            vela_crypto::rekey::rotate()
                .map_err(|e| format!("Failed to generate a new seed: {e}"))?,
        );
        let new_crypto = crate::crypto::Crypto::new(&new_rms);

        // 3. Re-encrypt every chunk into a shadow row at the new epoch.
        let mut uploaded = 0usize;
        for chunk in &start.chunks {
            let key_old = old_crypto_snapshot.chunk_key(chunk.chunk_id.as_bytes());
            let (ciphertext, version, lamport, tok) = client
                .get_chunk(&token, &chunk.chunk_id)
                .await
                .map_err(|e| format!("Failed to download chunk {}: {e}", chunk.chunk_id))?;
            if let Some(t) = tok {
                accept_new_token(state, &mut token, Some(t));
            }
            let (_, plaintext) = vela_crypto::rekey::open_epoch_chunk(
                key_old.as_bytes(),
                &ciphertext,
                current_epoch as u64,
                &chunk.chunk_id,
                lamport,
            )
            .map_err(|e| {
                format!(
                    "Chunk {} cannot be decrypted under the current key: {e}",
                    chunk.chunk_id
                )
            })?;
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

            let (_, tok) = client
                .put_chunk_with_epoch(
                    &token,
                    &chunk.chunk_id,
                    // The N+1 shadow has no prior version; zero selects the
                    // server's idempotent create/replay path.
                    0,
                    sealed,
                    lamport.max(chunk.lamport_clock),
                    Some(new_epoch),
                )
                .await
                .map_err(|e| format!("Failed to upload re-keyed chunk {}: {e}", chunk.chunk_id))?;
            if let Some(t) = tok {
                accept_new_token(state, &mut token, Some(t));
            }
            uploaded += 1;
        }

        // 4. Capsule fan-out before commit.
        let (devices, refreshed) = client
            .get_devices(&token)
            .await
            .map_err(|e| format!("Failed to list devices for capsule sealing: {e}"))?;
        accept_new_token(state, &mut token, refreshed);
        let mut capsules = std::collections::HashMap::new();
        for device in &devices {
            if device.revoked {
                continue;
            }
            if !device.rekey_capable {
                return Err(format!(
                    "Device {} has not confirmed that it can adopt rotated keys; sync or re-enroll it first",
                    device.id
                ));
            }
            let ek_b64 = device.hybrid_ek.as_deref().ok_or(format!(
                "Device {} did not report its KEM public key; server may be older than this feature",
                device.id
            ))?;
            let ek = B64
                .decode(ek_b64)
                .map_err(|e| format!("Device {} has a malformed KEM key: {e}", device.id))?;
            let capsule = crate::crypto::seal_rms_to_device(&ek, &new_crypto.rms())
                .map_err(|e| format!("Failed to seal the new seed for {}: {e}", device.id))?;
            capsules.insert(device.id.to_string(), B64.encode(capsule));
        }
        if let Some(t) = client
            .rekey_store_capsules(&token, &capsules)
            .await
            .map_err(|e| format!("Failed to store the new-seed capsules: {e}"))?
        {
            accept_new_token(state, &mut token, Some(t));
        }

        Ok::<_, String>((new_crypto, uploaded, capsules.len()))
    }
    .await;

    let (new_crypto, uploaded, devices_sealed) = match preparation {
        Ok(prepared) => prepared,
        Err(preparation_err) => {
            let abort = client.rekey_abort(&token).await;
            let mut detail = preparation_err;
            if let Err(e) = abort {
                detail.push_str(&format!("; server abort also failed: {e}"));
            }
            return Err(detail);
        }
    };

    // Do not commit on behalf of a session which auto-locked while the network
    // work was running. The account is still at N, so abort is sufficient.
    if let Err(e) = state.ensure_unlocked_since(generation) {
        let _ = client.rekey_abort(&token).await;
        return Err(e);
    }

    // 5. Commit while this device still retains RMS1 locally. If the process
    // dies before this call, timeout rollback leaves both server and client at
    // N. If it dies after commit, the retryable self-capsule lets ordinary sync
    // adopt N+1. There is no state in which the only local key is ahead of a
    // server that can roll back behind it.
    let commit_token = match client.rekey_commit(&token).await {
        Ok(refreshed) => refreshed,
        Err(commit_err) => {
            // A lost response can mean commit actually won. Leave local state
            // at N either way: if abort wins it already matches; if commit won,
            // the next sync adopts the retained N+1 capsule.
            let abort = client.rekey_abort(&token).await;
            let mut detail = format!("Failed to commit the rotation: {commit_err}");
            if let Err(e) = abort {
                detail.push_str(&format!("; server abort failed: {e}"));
            }
            return Err(detail);
        }
    };
    accept_new_token(state, &mut token, commit_token);

    // 6. Now adopt locally using the same all-or-old migration as every other
    // device. Failure is recoverable: the server is already authoritative at
    // N+1 and retains this device's capsule until a later sync succeeds.
    state.ensure_unlocked_since(generation).map_err(|e| {
        format!(
            "The server committed epoch {new_epoch}, but this device locked before local adoption: {e}. Unlock and sync to adopt from its retained capsule."
        )
    })?;
    crate::sync::migrate_local_rms(
        state,
        &old_crypto_snapshot,
        new_crypto,
        new_epoch,
        rekey_password.as_ref().map(|p| p.as_str()),
    )
    .map_err(|e| {
        format!(
            "The server committed epoch {new_epoch}, but this device could not adopt it: {e}. Lock, unlock, and sync to retry from its retained capsule."
        )
    })?;

    // The initiator's capsule has served its crash-recovery purpose. Clear it
    // only after files, every RMS wrapper, and the local epoch are durable.
    match client.acknowledge_rekey_capsule(&token, new_epoch).await {
        Ok(Some(refreshed)) => accept_new_token(state, &mut token, Some(refreshed)),
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("Re-key committed locally, but self-capsule acknowledgement failed: {e}")
        }
    }

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
        devices_sealed,
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
