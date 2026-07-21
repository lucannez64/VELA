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
use vela_crypto::shamir::Share;

use crate::api::{
    ApiClient, EnrollDeviceViaRecoveryRequest, RecoveryRecoverRequest, RecoveryShareData,
    VerifyRequest,
};
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::crypto;
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
    let user_id = state
        .store
        .load_user_id()
        .map_err(|e| format!("Failed to load account ID: {e}"))?;

    // Deliberately not further "encrypted" beyond this envelope: a lone
    // Shamir share (below the 2-of-3 threshold) is information-theoretically
    // indistinguishable from random bytes, so it needs no additional secret
    // key to stay confidential — and any such key would itself need to be
    // recoverable without the RMS it's meant to help reconstruct, which is
    // circular. This JSON wrapper exists for versioning/integrity, not
    // confidentiality. `user_id` rides along so a recovering device can
    // identify the account from Share 1 alone, without the user having to
    // remember/re-enter their account ID.
    let envelope = serde_json::json!({
        "version": 1,
        "user_id": user_id,
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

// ─────────────────────────────────────────────────────────────────────────
// Recovery download (SPEC.md §4.3): reconstruct the RMS on a brand-new
// device from Share 1 (cloud) + Share 2 (server, WebAuthn-gated), then
// bootstrap this device the same way `import_enrollment_code` bootstraps a
// peer-enrolled one. Unlike that flow, there is no other enrolled device to
// authorize this one — authorization instead comes from the `recovery_grant`
// minted by `/recovery/recover` after a successful WebAuthn assertion.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CloudBackupEnvelope {
    #[allow(dead_code)]
    version: u8,
    user_id: String,
    share_b64: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudRecoveryShare {
    pub user_id: String,
    pub share_b64: String,
}

/// Download and parse the Share 1 envelope from a cloud remote. Runs before
/// any vault exists on this device (no unlock check — there is nothing to
/// unlock yet), so the caller can identify the account from the cloud file
/// alone before starting the WebAuthn ceremony.
#[tauri::command]
pub async fn fetch_cloud_recovery_share(remote: String) -> Result<CloudRecoveryShare, String> {
    let bytes = tokio::task::spawn_blocking(move || {
        crate::rclone::download_bytes(&remote, CLOUD_BACKUP_REMOTE_PATH)
    })
    .await
    .map_err(|e| format!("Download task panicked: {e}"))??;

    let envelope: CloudBackupEnvelope =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid cloud backup file: {e}"))?;

    Ok(CloudRecoveryShare {
        user_id: envelope.user_id,
        share_b64: envelope.share_b64,
    })
}

/// Complete account recovery: combine Share 1 (from the cloud, already
/// fetched via `fetch_cloud_recovery_share`) with Share 2 (released by
/// `/recovery/recover` after the caller's WebAuthn assertion verified),
/// reconstruct the RMS, register this device against the existing account,
/// then download the vault and unlock the session — mirroring
/// `import_enrollment_code`'s bootstrap sequence.
#[tauri::command]
pub async fn complete_account_recovery(
    state: State<'_, Arc<AppState>>,
    user_id: String,
    share1_b64: String,
    credential: serde_json::Value,
    recovery_id: Option<String>,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    let share1_bytes = B64
        .decode(&share1_b64)
        .map_err(|_| "Invalid Share 1 encoding".to_string())?;
    let share1 = Share::from_bytes(&share1_bytes).map_err(|e| format!("Invalid Share 1: {e}"))?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    // ── WebAuthn-gated release of Share 2 ──────────────────────────────────
    let recover_resp = client
        .recover_account(&RecoveryRecoverRequest {
            user_id: user_id.clone(),
            recovery_id,
            credential,
        })
        .await
        .map_err(|e| format!("Account recovery failed: {e}"))?;

    let share2_bytes = B64
        .decode(&recover_resp.share)
        .map_err(|_| "Invalid Share 2 encoding".to_string())?;
    let share2 = Share::from_bytes(&share2_bytes).map_err(|e| format!("Invalid Share 2: {e}"))?;

    // ── combine shares → RMS ────────────────────────────────────────────────
    let rms = crate::crypto::Crypto::reconstruct_recovery(&[share1, share2])
        .map_err(|e| format!("Failed to reconstruct vault key: {e}"))?;

    // ── generate this device's identity keypair ─────────────────────────────
    let new_identity = tokio::task::spawn_blocking(crypto::generate_identity_keypair)
        .await
        .map_err(|e| format!("Thread join error: {e}"))??;

    // ── register this device against the existing account ──────────────────
    let enroll_resp = client
        .enroll_device_via_recovery(&EnrollDeviceViaRecoveryRequest {
            user_id: user_id.clone(),
            recovery_grant: recover_resp.recovery_grant,
            hybrid_ek: B64.encode(&new_identity.hybrid_ek),
            hybrid_vk: B64.encode(&new_identity.hybrid_vk),
            device_name: device_name.or_else(|| Some("Recovered Device".to_string())),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Failed to register this device: {e}"))?;
    let device_id = enroll_resp.device_id;

    state
        .store
        .save_device_id_with_user_id(&device_id, &user_id)
        .map_err(|e| format!("Failed to save device ID: {e}"))?;

    // ── authenticate as the newly registered device ─────────────────────────
    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|_| "Invalid challenge encoding")?;

    let sk_for_sig = new_identity.hybrid_sk.clone();
    let device_id_for_sig = device_id.clone();
    let signature = tokio::task::spawn_blocking(move || {
        crypto::create_auth_signature(&sk_for_sig, &challenge_bytes, &device_id_for_sig)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("Challenge signature failed: {e}"))?;

    let verify_resp = client
        .verify_signature(&VerifyRequest {
            device_id: device_id.clone(),
            challenge: challenge_resp.challenge,
            signature,
            device_name: Some(crate::commands::devices::get_device_name()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Server authentication failed: {e}"))?;
    let token = verify_resp.token;

    // ── store RMS, build Crypto, download vault ─────────────────────────────
    crate::biometric::store_password_encrypted(&rms, &password)
        .map_err(|e| format!("Failed to store vault key: {e}"))?;

    let crypto_obj = crate::crypto::Crypto::new(&rms);
    state
        .store
        .save_identity_keys(
            &new_identity.hybrid_ek,
            &new_identity.hybrid_vk,
            &new_identity.hybrid_sk,
            &crypto_obj,
        )
        .map_err(|e| format!("Failed to save identity keys: {e}"))?;

    let vault =
        crate::commands::devices::download_vault_after_enrollment(&crypto_obj, &client, &token)
            .await?;
    state
        .store
        .save_vault(&vault, &crypto_obj)
        .map_err(|e| format!("Failed to save vault locally: {e}"))?;

    // ── unlock session ───────────────────────────────────────────────────────
    {
        let mut session = state.session.write();
        session.set_server_token(token);
        session.unlock(device_id.clone(), user_id, 15 * 60);
    }
    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto_obj);
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }

    record_audit_event(&state, AuditAction::VaultUnlocked);
    tracing::info!(device_id = %device_id, "Account recovery complete");
    Ok(())
}
