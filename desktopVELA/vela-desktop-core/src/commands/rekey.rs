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

const REKEY_CAPSULE_BATCH_SIZE: usize = 64;

fn into_capsule_batches(
    capsules: std::collections::HashMap<String, String>,
) -> Vec<std::collections::HashMap<String, String>> {
    let mut capsules = capsules.into_iter();
    let mut batches = Vec::new();
    loop {
        let batch = capsules
            .by_ref()
            .take(REKEY_CAPSULE_BATCH_SIZE)
            .collect::<std::collections::HashMap<_, _>>();
        if batch.is_empty() {
            return batches;
        }
        batches.push(batch);
    }
}

/// Everything succeeded; reported to the UI and written to the audit log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RotateSummary {
    pub from_epoch: i64,
    pub to_epoch: i64,
    /// Chunks re-encrypted and uploaded as shadow rows.
    pub chunks_rekeyed: usize,
    /// Devices the new seed was capsule-sealed to (including this one).
    pub devices_sealed: usize,
    /// Rotation invalidates every recovery share derived from the old RMS.
    /// Fresh shares of the new RMS are re-minted (and verified) automatically,
    /// but each delivery channel — cloud backup, security key, trusted
    /// contact — must still be redone by the user.
    pub recovery_setup_required: bool,
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
    // Fail fast before involving a human: an unsigned-in install can never
    // rotate, so do not make someone approve a dialog that only leads here.
    if state
        .session
        .read()
        .get_server_token()
        .is_none()
    {
        return Err("Not signed in to a server — rotation needs an account".into());
    }
    // Refuse legacy installations before asking the human to approve an
    // operation this device cannot complete.
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
    let state_for_confirmation = state.clone();
    tokio::task::spawn_blocking(move || {
        state_for_confirmation.confirm_with_human(
            "VELA — rotate vault keys",
            "Rotate this vault's master key? Existing recovery shares and backups will stop working. You must set up all recovery methods again after rotation.",
        )
    })
    .await
    .map_err(|e| format!("Confirmation task panicked: {e}"))??;
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
    // `password_for_rekey` runs the platform credential check (blocking
    // process I/O) — keep it off the async runtime.
    let rekey_password = {
        let state = state.clone();
        let current_rms = old_crypto_snapshot.rms();
        tokio::task::spawn_blocking(move || crate::sync::password_for_rekey(&state, &current_rms))
            .await
            .map_err(|e| format!("Password proof task panicked: {e}"))??
    };

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
    let rotation_id = start.rotation_id.clone();

    // Everything before commit runs inside one error boundary. Once `start`
    // has frozen writes, any ordinary preparation failure must explicitly
    // abort instead of leaving the account read-only until timeout.
    let preparation = async {
        // 2. Fresh seed, locally generated (already `Zeroizing`).
        let new_rms = vela_crypto::rekey::rotate()
            .map_err(|e| format!("Failed to generate a new seed: {e}"))?;
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
            let (bound_epoch, plaintext) = vela_crypto::rekey::open_epoch_chunk(
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
            if current_epoch > 1 && bound_epoch != Some(current_epoch as u64) {
                return Err(format!(
                    "Chunk {} is legacy ciphertext at epoch {current_epoch}",
                    chunk.chunk_id
                ));
            }
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
                .put_rekey_shadow(
                    &token,
                    &chunk.chunk_id,
                    sealed,
                    lamport.max(chunk.lamport_clock),
                    new_epoch,
                    &rotation_id,
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
        let devices_sealed = capsules.len();
        for batch in into_capsule_batches(capsules) {
            if let Some(t) = client
                .rekey_store_capsules(&token, &rotation_id, &batch)
                .await
                .map_err(|e| format!("Failed to store the new-seed capsules: {e}"))?
            {
                accept_new_token(state, &mut token, Some(t));
            }
        }

        Ok::<_, String>((new_crypto, uploaded, devices_sealed))
    }
    .await;

    let (new_crypto, uploaded, devices_sealed) = match preparation {
        Ok(prepared) => prepared,
        Err(preparation_err) => {
            let abort = client.rekey_abort(&token, &rotation_id).await;
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
        let _ = client.rekey_abort(&token, &rotation_id).await;
        return Err(e);
    }

    // 5. Commit while this device still retains RMS1 locally. If the process
    // dies before this call, timeout rollback leaves both server and client at
    // N. If it dies after commit, the retryable self-capsule lets ordinary sync
    // adopt N+1. There is no state in which the only local key is ahead of a
    // server that can roll back behind it.
    let commit_token = match client.rekey_commit(&token, &rotation_id, new_epoch).await {
        Ok(refreshed) => refreshed,
        Err(commit_err) => {
            // A lost response can mean commit actually won. Leave local state
            // at N either way: if abort wins it already matches; if commit won,
            // the next sync adopts the retained N+1 capsule.
            let abort = client.rekey_abort(&token, &rotation_id).await;
            let mut detail = format!("Failed to commit the rotation: {commit_err}");
            if let Err(e) = abort {
                detail.push_str(&format!("; server abort failed: {e}"));
            }
            return Err(detail);
        }
    };
    accept_new_token(state, &mut token, commit_token);

    // Record the rotation in the audit log immediately after the server
    // committed — before local adoption. A crash during migration must not
    // leave a completed rotation absent from the audit trail; the event is
    // written under the still-installed old key and rides the same RMS
    // migration as every other secret file.
    crate::audit::record_audit_event(
        state,
        crate::audit::AuditAction::VaultRekeyed {
            from_epoch: current_epoch,
            to_epoch: new_epoch,
        },
    );

    // 6. Now adopt locally using the same all-or-old migration as every other
    // device. Failure is recoverable: the server is already authoritative at
    // N+1 and retains this device's capsule until a later sync succeeds.
    // The migration is synchronous fs + platform-credential I/O, so it runs
    // on the blocking pool.
    state.ensure_unlocked_since(generation).map_err(|e| {
        format!(
            "The server committed epoch {new_epoch}, but this device locked before local adoption: {e}. Unlock and sync to adopt from its retained capsule."
        )
    })?;
    tokio::task::spawn_blocking({
        let state = state.clone();
        let password = rekey_password.clone();
        move || {
            crate::sync::migrate_local_rms(
                &state,
                &old_crypto_snapshot,
                new_crypto,
                new_epoch,
                password.as_ref().map(|p| p.as_str()),
                generation,
            )
        }
    })
    .await
    .map_err(|e| {
        format!(
            "The server committed epoch {new_epoch}, but this device could not adopt it (task failed): {e}. Lock, unlock, and sync to retry from its retained capsule."
        )
    })?
    .map_err(|e| {
        format!(
            "The server committed epoch {new_epoch}, but this device could not adopt it: {e}. Lock, unlock, and sync to retry from its retained capsule."
        )
    })?;

    // 7. Recovery shares of the OLD seed are worthless by construction — they
    //    reconstruct only the retired value. Re-mint shares of the new seed
    //    now, verified against the RMS this session unlocked before anything
    //    is delivered, so re-doing recovery setup starts from a proven split.
    //    The channels themselves (rclone upload, WebAuthn registration,
    //    trusted-contact handoff) still need their own ceremonies; the
    //    summary's `recovery_setup_required` keeps driving that prompt. A
    //    failed re-mint must not fail the rotation — it is already committed
    //    server-side and adopted locally — so log and surface it via the
    //    existing setup-required flag instead.
    if let Err(e) = tokio::task::spawn_blocking({
        let state = state.clone();
        move || crate::recovery::remint_recovery_setup(&state)
    })
    .await
    .map_err(|e| format!("Recovery share re-mint task panicked: {e}"))
    .and_then(|inner| inner)
    {
        tracing::warn!("Recovery share re-mint after rotation failed: {e}");
    }

    // The initiator's capsule has served its crash-recovery purpose. Clear it
    // only after files, every RMS wrapper, and the local epoch are durable.
    match client.acknowledge_rekey_capsule(&token, new_epoch).await {
        Ok(Some(refreshed)) => accept_new_token(state, &mut token, Some(refreshed)),
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("Re-key committed locally, but self-capsule acknowledgement failed: {e}")
        }
    }

    let summary = RotateSummary {
        from_epoch: current_epoch,
        to_epoch: new_epoch,
        chunks_rekeyed: uploaded,
        devices_sealed,
        recovery_setup_required: true,
    };

    tracing::info!(
        from = summary.from_epoch,
        to = summary.to_epoch,
        chunks = summary.chunks_rekeyed,
        devices = summary.devices_sealed,
        "vault re-keyed"
    );

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_fanout_is_split_at_the_server_request_limit() {
        let capsules = (0..129)
            .map(|index| (format!("device-{index}"), format!("capsule-{index}")))
            .collect();

        let batches = into_capsule_batches(capsules);

        assert_eq!(
            batches
                .iter()
                .map(|batch| batch.len())
                .collect::<Vec<_>>(),
            [64, 64, 1]
        );
        assert_eq!(
            batches.iter().flat_map(|batch| batch.keys()).count(),
            129
        );
    }
}
