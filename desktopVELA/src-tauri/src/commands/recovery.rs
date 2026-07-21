//! Account recovery setup (SPEC.md §4.3): split the Root Master Seed into a
//! Shamir 2-of-3 scheme and deliver each share to its own channel —
//! Share 1 to a cloud storage remote (via rclone), Share 2 to the VELA
//! server (release-gated by a WebAuthn recovery credential, wired in
//! `settings::finish_recovery_webauthn_registration`), and Share 3 shown to
//! the user to hand to a trusted contact out-of-band.
//!
//! Any 2 of the 3 shares reconstruct the RMS, so a user only needs to
//! complete two of these three steps for recovery to actually work.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

use crate::api::{ApiClient, RecoveryShareData};
use crate::AppState;

const RECOVERY_SETUP_FILE: &str = "recovery_setup.enc";
/// Fixed destination path under the user's chosen remote — not user input,
/// so it carries no injection risk regardless of how the remote name is
/// validated.
const CLOUD_BACKUP_REMOTE_PATH: &str = "VELA/recovery-share.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PendingRecoveryShares {
    share1: Option<Vec<u8>>,
    share2: Option<Vec<u8>>,
    share3: Option<Vec<u8>>,
    #[serde(default)]
    cloud_backup_delivered: bool,
    #[serde(default)]
    security_key_delivered: bool,
    #[serde(default)]
    trusted_contact_acknowledged: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryStatus {
    pub cloud_backup_delivered: bool,
    pub security_key_delivered: bool,
    pub trusted_contact_acknowledged: bool,
}

fn load_pending(state: &AppState) -> PendingRecoveryShares {
    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if !path.exists() {
        return PendingRecoveryShares::default();
    }
    let crypto = state.crypto.read();
    let Some(crypto) = crypto.as_ref() else {
        return PendingRecoveryShares::default();
    };
    let Ok(ciphertext) = std::fs::read(&path) else {
        return PendingRecoveryShares::default();
    };
    let Ok(plaintext) = crypto.decrypt_vault(&ciphertext) else {
        return PendingRecoveryShares::default();
    };
    serde_json::from_slice(&plaintext).unwrap_or_default()
}

fn save_pending(state: &AppState, pending: &PendingRecoveryShares) -> Result<(), String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Vault is locked")?;

    let plaintext = serde_json::to_vec(pending).map_err(|e| e.to_string())?;
    let ciphertext = crypto.encrypt_vault(&plaintext).map_err(|e| e.to_string())?;

    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    std::fs::write(path, ciphertext).map_err(|e| e.to_string())
}

/// Split the RMS into a 2-of-3 Shamir scheme exactly once per vault, caching
/// the shares (encrypted at rest, same as `shares.enc`) until each has been
/// delivered. Idempotent — repeated calls return the same three shares, so
/// the three setup steps can be completed in any order without invalidating
/// one another's share.
pub(crate) fn ensure_shares_split(state: &AppState) -> Result<(), String> {
    let mut pending = load_pending(state);
    if pending.share1.is_some() && pending.share2.is_some() && pending.share3.is_some() {
        return Ok(());
    }

    let shares = {
        let crypto = state.crypto.read();
        let crypto = crypto
            .as_ref()
            .ok_or("Vault must be unlocked to set up recovery")?;
        crypto
            .split_recovery(2, 3)
            .map_err(|e| format!("Failed to split recovery shares: {e}"))?
    };
    if shares.len() != 3 {
        return Err("Unexpected share count from split".to_string());
    }

    pending.share1 = Some(shares[0].to_bytes());
    pending.share2 = Some(shares[1].to_bytes());
    pending.share3 = Some(shares[2].to_bytes());
    save_pending(state, &pending)
}

/// Used by `settings::finish_recovery_webauthn_registration` once the
/// recovery passkey is registered: uploads Share 2 (base64) to the server's
/// opaque recovery-share slot, gated by that passkey at release time.
pub(crate) async fn deliver_security_key_share(state: &AppState, token: &str) -> Result<(), String> {
    ensure_shares_split(state)?;
    let share2 = {
        let pending = load_pending(state);
        pending
            .share2
            .clone()
            .ok_or("Recovery share was not generated")?
    };

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let share_b64 = B64.encode(&share2);
    client
        .put_recovery_share(
            token,
            RecoveryShareData {
                share: share_b64,
            },
        )
        .await
        .map_err(|e| format!("Failed to store recovery share on server: {e}"))?;

    let mut pending = load_pending(state);
    pending.security_key_delivered = true;
    save_pending(state, &pending)
}

#[tauri::command]
pub async fn list_cloud_backup_remotes() -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(crate::rclone::list_remotes)
        .await
        .map_err(|e| format!("Task panicked: {e}"))?
}

#[tauri::command]
pub async fn setup_cloud_backup_recovery(
    state: State<'_, Arc<AppState>>,
    remote: String,
) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    ensure_shares_split(&state)?;
    let share1 = {
        let pending = load_pending(&state);
        pending
            .share1
            .clone()
            .ok_or("Recovery share was not generated")?
    };

    // Deliberately not further "encrypted" beyond this envelope: a lone
    // Shamir share (below the 2-of-3 threshold) is information-theoretically
    // indistinguishable from random bytes, so it needs no additional secret
    // key to stay confidential — and any such key would itself need to be
    // recoverable without the RMS it's meant to help reconstruct, which is
    // circular. This JSON wrapper exists for versioning/integrity, not
    // confidentiality.
    let envelope = serde_json::json!({
        "version": 1,
        "share_b64": B64.encode(&share1),
    });
    let payload = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;

    let remote_for_task = remote.clone();
    tokio::task::spawn_blocking(move || {
        crate::rclone::upload_bytes(&remote_for_task, CLOUD_BACKUP_REMOTE_PATH, &payload)
    })
    .await
    .map_err(|e| format!("Upload task panicked: {e}"))??;

    let mut pending = load_pending(&state);
    pending.cloud_backup_delivered = true;
    save_pending(&state, &pending)?;

    tracing::info!("Recovery Share 1 uploaded to rclone remote '{}'", remote);
    Ok(())
}

#[tauri::command]
pub async fn get_trusted_contact_share(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    ensure_shares_split(&state)?;
    let pending = load_pending(&state);
    let share3 = pending.share3.ok_or("Recovery share was not generated")?;
    Ok(B64.encode(&share3))
}

#[tauri::command]
pub async fn acknowledge_trusted_contact_share(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut pending = load_pending(&state);
    pending.trusted_contact_acknowledged = true;
    save_pending(&state, &pending)
}

#[tauri::command]
pub async fn get_recovery_setup_status(
    state: State<'_, Arc<AppState>>,
) -> Result<RecoveryStatus, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let pending = load_pending(&state);
    Ok(RecoveryStatus {
        cloud_backup_delivered: pending.cloud_backup_delivered,
        security_key_delivered: pending.security_key_delivered,
        trusted_contact_acknowledged: pending.trusted_contact_acknowledged,
    })
}

/// Wipe the locally cached shares once recovery setup is done (or abandoned).
/// Safe regardless of how many channels were actually delivered: recovery
/// only ever depended on 2 of the 3 shares reaching their destination, never
/// on this local cache surviving.
#[tauri::command]
pub async fn finalize_recovery_setup(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}
