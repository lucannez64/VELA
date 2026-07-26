//! Toolkit-agnostic core of `src-tauri/src/commands/recovery.rs` — the
//! locally-cached-shares side of account recovery setup (SPEC.md §4.3): the
//! RMS is split into a Shamir 2-of-3 scheme and each share delivered to its
//! own channel (cloud remote / server, gated by a WebAuthn credential /
//! shown to the user for a trusted contact). Any 2 of 3 shares reconstruct
//! the RMS.
//!
//! Only the pieces `webauthn::register_security_key` and a real Settings UI
//! need are extracted here: `ensure_shares_split`, `deliver_security_key_
//! share`, and `get_recovery_setup_status`. Cloud-backup (rclone) and
//! trusted-contact delivery stay in `src-tauri` for now — deliberately out
//! of scope for the WebAuthn/FIDO2 effort this was extracted for.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::api::{ApiClient, RecoveryShareData};
use crate::AppState;

const RECOVERY_SETUP_FILE: &str = "recovery_setup.enc";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub cloud_backup_delivered: bool,
    pub security_key_delivered: bool,
    pub trusted_contact_acknowledged: bool,
    /// True while the split shares are still cached locally (setup started
    /// but not yet finalized) — remaining methods can be completed against
    /// the same split. Once finalized, starting any method again forces a
    /// fresh split that invalidates every previously delivered share.
    pub setup_in_progress: bool,
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
        let crypto = crypto.as_ref().ok_or("Vault must be unlocked to set up recovery")?;
        crypto.split_recovery(2, 3).map_err(|e| format!("Failed to split recovery shares: {e}"))?
    };
    if shares.len() != 3 {
        return Err("Unexpected share count from split".to_string());
    }

    pending.share1 = Some(shares[0].to_bytes());
    pending.share2 = Some(shares[1].to_bytes());
    pending.share3 = Some(shares[2].to_bytes());
    // A fresh split draws a new random polynomial, so shares delivered from
    // an earlier split can no longer combine with these — every channel has
    // to be redone against the new split.
    pending.cloud_backup_delivered = false;
    pending.security_key_delivered = false;
    pending.trusted_contact_acknowledged = false;
    save_pending(state, &pending)
}

/// Used by `webauthn::register_security_key` once the recovery passkey is
/// registered: uploads Share 2 (base64) to the server's opaque recovery-
/// share slot, gated by that passkey at release time. Registering the
/// credential without ever storing a share behind it would leave "security
/// key recovery" enabled in the UI but functionally inert.
pub(crate) async fn deliver_security_key_share(state: &AppState, token: &str) -> Result<(), String> {
    ensure_shares_split(state)?;
    let share2 = {
        let pending = load_pending(state);
        pending.share2.clone().ok_or("Recovery share was not generated")?
    };

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let share_b64 = B64.encode(&share2);
    client
        .put_recovery_share(token, RecoveryShareData { share: share_b64 })
        .await
        .map_err(|e| format!("Failed to store recovery share on server: {e}"))?;

    let mut pending = load_pending(state);
    pending.security_key_delivered = true;
    save_pending(state, &pending)
}

pub fn get_recovery_setup_status(state: &AppState) -> Result<RecoveryStatus, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let pending = load_pending(state);
    Ok(RecoveryStatus {
        cloud_backup_delivered: pending.cloud_backup_delivered,
        security_key_delivered: pending.security_key_delivered,
        trusted_contact_acknowledged: pending.trusted_contact_acknowledged,
        setup_in_progress: pending.share1.is_some(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Account recovery (the "every device lost" path, SPEC.md §4.3): reconstruct
// the RMS from Share 1 (cloud backup) + Share 2 (released by the server only
// after a WebAuthn assertion), register this device against the existing
// account, then pull the vault down. Moved from `src-tauri/src/commands/
// recovery.rs`; the WebAuthn half lives in `crate::webauthn`.
// ─────────────────────────────────────────────────────────────────────────────

const CLOUD_BACKUP_REMOTE_PATH: &str = "VELA/recovery-share.json";

#[derive(Debug, Clone, Deserialize)]
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

/// Configured rclone remotes, for the "where was Share 1 uploaded?" picker.
pub async fn list_cloud_backup_remotes() -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(crate::rclone::list_remotes)
        .await
        .map_err(|e| format!("Task panicked: {e}"))?
}

/// Download and parse the Share 1 envelope from a cloud remote. Runs before
/// any vault exists on this device (no unlock check — there is nothing to
/// unlock yet), so the caller can identify the account from the cloud file
/// alone before starting the WebAuthn ceremony.
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

/// Finish account recovery once Share 2 has already been released by the
/// server — i.e. after `crate::webauthn::recover_account_with_security_key`
/// has driven the real FIDO2 assertion and returned the response.
///
/// Split this way (rather than taking a browser-produced `credential` JSON
/// like the Tauri command does) because the native build performs the
/// ceremony itself; everything from "combine the shares" onward is identical.
pub async fn complete_account_recovery(
    state: &AppState,
    user_id: String,
    share1_b64: String,
    recover_resp: crate::api::RecoveryRecoverResponse,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    use crate::api::{EnrollDeviceViaRecoveryRequest, VerifyRequest};
    use crate::audit::{record_audit_event, AuditAction};
    use crate::crypto;
    use vela_crypto::shamir::Share;

    let share1_bytes = B64
        .decode(&share1_b64)
        .map_err(|_| "Invalid Share 1 encoding".to_string())?;
    let share1 = Share::from_bytes(&share1_bytes).map_err(|e| format!("Invalid Share 1: {e}"))?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let share2_bytes = B64
        .decode(&recover_resp.share)
        .map_err(|_| "Invalid Share 2 encoding".to_string())?;
    let share2 = Share::from_bytes(&share2_bytes).map_err(|e| format!("Invalid Share 2: {e}"))?;

    // ── combine shares → RMS ────────────────────────────────────────────────
    let rms = crypto::Crypto::reconstruct_recovery(&[share1, share2])
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
            device_name: Some(crate::audit::get_device_name()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Server authentication failed: {e}"))?;
    let token = verify_resp.token;

    // ── store RMS, build Crypto, download vault ─────────────────────────────
    crate::biometric::store_password_encrypted(&rms, &password)
        .map_err(|e| format!("Failed to store vault key: {e}"))?;

    let crypto_obj = crypto::Crypto::new(&rms);
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

    record_audit_event(state, AuditAction::VaultUnlocked);
    tracing::info!(device_id = %device_id, "Account recovery complete");
    Ok(())
}

/// Upload Share 1 to a configured rclone remote (recovery setup, method 1).
/// Requires an unlocked vault — the shares are derived from the RMS.
pub async fn setup_cloud_backup_recovery(state: &AppState, remote: String) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    ensure_shares_split(state)?;
    let share1 = {
        let pending = load_pending(state);
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

    let mut pending = load_pending(state);
    pending.cloud_backup_delivered = true;
    save_pending(state, &pending)?;

    tracing::info!("Recovery Share 1 uploaded to rclone remote '{}'", remote);
    Ok(())
}
