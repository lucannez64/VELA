//! Toolkit-agnostic core of `src-tauri/src/commands/recovery.rs` — the
//! locally-cached-shares side of account recovery setup (SPEC.md §4.3): the
//! RMS is split into a Shamir 2-of-3 scheme and each share delivered to its
//! own channel (cloud remote / server, gated by a WebAuthn credential /
//! shown to the user for a trusted contact). Any 2 of 3 shares reconstruct
//! the RMS.
//!
//! All three delivery channels live here, so either front end can drive a
//! complete 2-of-3 setup: cloud backup over rclone, the security-key share
//! the server holds behind a WebAuthn credential, and the trusted-contact
//! share the user carries out of band. `src-tauri` keeps only the
//! `#[tauri::command]` wrappers.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::api::{ApiClient, RecoveryRecoverRequest, RecoveryShareData};
use crate::AppState;

const RECOVERY_SETUP_FILE: &str = "recovery_setup.enc";

/// A new RMS makes every previously generated recovery share obsolete.
/// Remove both cached shares and delivery flags so the UI requires a complete
/// fresh setup and `ensure_shares_split` cannot redistribute old material.
pub(crate) fn retire_recovery_setup(state: &AppState) -> Result<(), String> {
    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

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
    let ciphertext = crypto
        .encrypt_vault(&plaintext)
        .map_err(|e| e.to_string())?;

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
pub(crate) async fn deliver_security_key_share(
    state: &AppState,
    token: &str,
) -> Result<(), String> {
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

/// Share 3, base64, for the user to hand to their trusted contact.
///
/// Splitting on demand (rather than at account creation) is what lets the
/// three methods be enabled in any order against one split: `ensure_shares_
/// split` is idempotent while a setup is in progress, so reading this does
/// not invalidate a share already delivered elsewhere.
///
/// This returns key material to the caller by design — that is the whole
/// mechanism — so it is the one recovery call a UI must not log, cache, or
/// leave on screen after the user has copied it.
pub async fn get_trusted_contact_share(state: &AppState) -> Result<String, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    ensure_shares_split(state)?;
    let pending = load_pending(state);
    let share3 = pending.share3.ok_or("Recovery share was not generated")?;
    Ok(B64.encode(&share3))
}

/// Mark the trusted-contact share as handed over. The app cannot verify that
/// it actually was — there is no channel to check — so this records the
/// user's word for it, which is what the 2-of-3 progress count reads.
pub async fn acknowledge_trusted_contact_share(state: &AppState) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut pending = load_pending(state);
    pending.trusted_contact_acknowledged = true;
    save_pending(state, &pending)
}

/// End setup by dropping the cached shares.
///
/// Until this runs, all three shares sit in `recovery_setup.enc` on this
/// device — which would defeat the point of splitting them across three
/// custodians if it were left that way. The delivered/acknowledged flags
/// survive; only the material goes.
pub async fn finalize_recovery_setup(state: &AppState) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if !path.exists() {
        return Ok(());
    }
    let mut pending = load_pending(state);
    pending.share1 = None;
    pending.share2 = None;
    pending.share3 = None;
    save_pending(state, &pending)
}

/// Queue a recovery-contact invitation locally.
///
/// Nothing sends it yet: this records who the user nominated so the UI can
/// list them, and no share travels with it. The share itself goes through
/// [`get_trusted_contact_share`], out of band, by hand.
pub async fn send_recovery_invite(state: &AppState, email: &str) -> Result<(), String> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 {
        return Err("Enter a valid recovery contact email address".to_string());
    }

    #[derive(Serialize, Deserialize)]
    struct RecoveryInvite {
        id: String,
        email: String,
        created_at: chrono::DateTime<chrono::Utc>,
        status: String,
    }

    let invites_path = state.store.store_path().join("recovery_invites.json");
    let mut invites: Vec<RecoveryInvite> = if invites_path.exists() {
        std::fs::read_to_string(&invites_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    invites.push(RecoveryInvite {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.clone(),
        created_at: chrono::Utc::now(),
        status: "pending".to_string(),
    });

    let json = serde_json::to_string_pretty(&invites).map_err(|e| e.to_string())?;
    std::fs::write(invites_path, json).map_err(|e| e.to_string())?;

    crate::audit::record_audit_event(state, crate::audit::AuditAction::SettingsChanged);
    tracing::info!("Recovery invite queued for: {}", email);
    Ok(())
}

/// Begin a browser-style WebAuthn registration for the recovery credential,
/// returning the `publicKey` options for the caller's ceremony.
///
/// This is the half a *renderer* drives through `navigator.credentials`. The
/// gpui build has no browser, so it runs the whole ceremony natively through
/// [`crate::webauthn::register_security_key`] instead — both paths end at the
/// same server routes and the same [`deliver_security_key_share`].
pub async fn start_recovery_webauthn_registration(
    state: &AppState,
) -> Result<serde_json::Value, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let (response, new_token) = client
        .start_recovery_webauthn_registration(&token, None, Some("VELA recovery key"))
        .await
        .map_err(|e| format!("Failed to start WebAuthn recovery setup: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    Ok(response.public_key)
}

/// Finish the browser-driven registration and, on success, immediately hand
/// the credential the share it exists to gate.
///
/// Registering without storing a share would leave "security key recovery"
/// enabled in the UI and functionally inert — a recovery method that cannot
/// recover anything.
pub async fn finish_recovery_webauthn_registration(
    state: &AppState,
    credential: serde_json::Value,
) -> Result<bool, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let (response, new_token) = client
        .finish_recovery_webauthn_registration(&token, credential)
        .await
        .map_err(|e| format!("Failed to finish WebAuthn recovery setup: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    if response.registered {
        let current_token = state
            .get_session_token()
            .ok_or_else(|| "No session token available".to_string())?;
        deliver_security_key_share(state, &current_token).await?;
    }

    Ok(response.registered)
}

/// Open a recovery attempt for an account, from hardware that has no session
/// — so this is deliberately unauthenticated, like the enrollment claim.
pub async fn initiate_account_recovery(
    state: &AppState,
    user_id: &str,
) -> Result<serde_json::Value, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let response = client
        .initiate_recovery(user_id)
        .await
        .map_err(|e| format!("Failed to initiate account recovery: {e}"))?;
    Ok(serde_json::json!({
        "recovery_id": response.recovery_id,
        "public_key": response.public_key,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Account recovery (the "every device lost" path, SPEC.md §4.3): reconstruct
// the RMS from Share 1 (cloud backup) + Share 2 (released by the server only
// after a WebAuthn assertion), register this device against the existing
// account, then pull the vault down. Moved from `src-tauri/src/commands/
// recovery.rs`; the WebAuthn half lives in `crate::webauthn`.
// ─────────────────────────────────────────────────────────────────────────────

// The backup used to live at one fixed path shared by every account, which
// meant a second VELA account backed up to the same rclone remote silently
// overwrote the first account's Shamir share (re-onboarding *to recover*
// could destroy the share being recovered). Shares now go to a per-account
// directory; the legacy path is still read for backups made by older builds,
// and cleaned up at the next setup once it's confirmed to be ours.

/// File name of the Share 1 envelope inside its per-account directory.
const CLOUD_BACKUP_FILE_NAME: &str = "recovery-share.json";

/// Pre-per-account path, shared by every account. Read for old backups;
/// deleted (only when it holds this account's share) at the next setup.
const LEGACY_CLOUD_BACKUP_REMOTE_PATH: &str = "VELA/recovery-share.json";

/// `user_id` becomes a remote path component, so it gets the same treatment
/// as an rclone remote name: an allowlist that keeps anything path- or
/// flag-like out (`..`, separators, leading dashes).
fn validate_user_id_for_path(user_id: &str) -> Result<(), String> {
    if user_id.is_empty() || user_id.len() > 128 {
        return Err("Invalid account ID".to_string());
    }
    if !user_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Invalid account ID: unexpected characters".to_string());
    }
    Ok(())
}

/// `<per-account dir>/<file>` under the VELA prefix on the chosen remote.
fn cloud_backup_remote_path(user_id: &str) -> Result<String, String> {
    validate_user_id_for_path(user_id)?;
    Ok(format!("VELA/{user_id}/{CLOUD_BACKUP_FILE_NAME}"))
}

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

/// Download and parse every Share 1 envelope on a cloud remote — the
/// per-account backups plus any legacy fixed-path backup from an older
/// build. Runs before any vault exists on this device (no unlock check —
/// there is nothing to unlock yet), so the caller can identify the account
/// from the envelope alone before starting the WebAuthn ceremony. One remote
/// may hold backups for several accounts; the caller lets the user pick.
///
/// Individual unreadable entries are skipped rather than failing the whole
/// scan: one corrupt file should not hide the healthy backup next to it.
pub async fn fetch_cloud_recovery_shares(
    remote: String,
) -> Result<Vec<CloudRecoveryShare>, String> {
    // Discover candidates first. If listing fails entirely (older rclone,
    // exotic remote), fall back to the two known locations instead of
    // refusing to recover at all.
    let remote_for_list = remote.clone();
    let listed =
        tokio::task::spawn_blocking(move || crate::rclone::list_files(&remote_for_list, "VELA"))
            .await
            .map_err(|e| format!("Listing task panicked: {e}"))?;
    let candidates: Vec<String> = match listed {
        Ok(entries) => {
            let mut paths: Vec<String> = entries
                .into_iter()
                .filter(|entry| entry.ends_with(CLOUD_BACKUP_FILE_NAME))
                .map(|entry| format!("VELA/{entry}"))
                .collect();
            if !paths.iter().any(|p| p == LEGACY_CLOUD_BACKUP_REMOTE_PATH) {
                paths.push(LEGACY_CLOUD_BACKUP_REMOTE_PATH.to_string());
            }
            paths
        }
        Err(e) => {
            tracing::warn!("Falling back to known recovery-backup paths after listing failed: {e}");
            vec![LEGACY_CLOUD_BACKUP_REMOTE_PATH.to_string()]
        }
    };

    let mut shares = Vec::new();
    for path in candidates {
        let remote_for_task = remote.clone();
        let path_for_task = path.clone();
        let bytes = tokio::task::spawn_blocking(move || {
            crate::rclone::download_bytes(&remote_for_task, &path_for_task)
        })
        .await
        .map_err(|e| format!("Download task panicked: {e}"))?;
        match bytes.and_then(|b| parse_cloud_backup_envelope(&b)) {
            Ok(share) => shares.push(share),
            Err(e) => tracing::info!("Skipping '{path}' on recovery-share scan: {e}"),
        }
    }

    if shares.is_empty() {
        return Err(
            "No VELA recovery backup was found on this remote. Pick the remote used during \
             recovery setup."
                .to_string(),
        );
    }
    Ok(shares)
}

fn parse_cloud_backup_envelope(bytes: &[u8]) -> Result<CloudRecoveryShare, String> {
    let envelope: CloudBackupEnvelope =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid cloud backup file: {e}"))?;

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
/// Recovery driven by a *renderer-produced* WebAuthn assertion: exchange the
/// credential for Share 2 at `/recovery/recover`, then run the shared
/// [`complete_account_recovery`].
///
/// The native path does the same thing from the other side —
/// [`crate::webauthn::recover_account_with_security_key`] runs a real CTAP2
/// ceremony itself and calls `complete_account_recovery` with the response it
/// gets back. Splitting at the response is what lets a browser ceremony and a
/// hardware ceremony share everything after it.
#[allow(clippy::too_many_arguments)]
pub async fn complete_account_recovery_with_credential(
    state: &AppState,
    user_id: String,
    share1_b64: String,
    credential: serde_json::Value,
    recovery_id: Option<String>,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let recover_resp = client
        .recover_account(&RecoveryRecoverRequest {
            user_id: user_id.clone(),
            recovery_id,
            credential,
        })
        .await
        .map_err(|e| format!("Account recovery failed: {e}"))?;

    complete_account_recovery(
        state,
        user_id,
        share1_b64,
        recover_resp,
        password,
        device_name,
    )
    .await
}

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

    let remote_path = cloud_backup_remote_path(&user_id)?;
    let remote_for_task = remote.clone();
    let path_for_task = remote_path.clone();
    tokio::task::spawn_blocking(move || {
        crate::rclone::upload_bytes(&remote_for_task, &path_for_task, &payload)
    })
    .await
    .map_err(|e| format!("Upload task panicked: {e}"))??;

    // Best-effort migration off the legacy shared path: if it currently
    // holds *this* account's share, delete it so a stale copy can't be
    // mistaken for the live backup. Another account's legacy file — or an
    // unreadable one — is left strictly alone.
    let remote_for_cleanup = remote.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        cleanup_legacy_cloud_backup(&remote_for_cleanup, &user_id)
    })
    .await
    .map_err(|e| format!("Cleanup task panicked: {e}"))?
    {
        tracing::warn!("Legacy recovery-share cleanup skipped: {e}");
    }

    let mut pending = load_pending(state);
    pending.cloud_backup_delivered = true;
    save_pending(state, &pending)?;

    tracing::info!(
        "Recovery Share 1 uploaded to rclone remote '{}' at '{remote_path}'",
        remote
    );
    Ok(())
}

/// Delete the legacy fixed-path backup iff it parses and belongs to
/// `user_id`. Blocking rclone I/O — call from `spawn_blocking`.
fn cleanup_legacy_cloud_backup(remote: &str, user_id: &str) -> Result<(), String> {
    let bytes = match crate::rclone::download_bytes(remote, LEGACY_CLOUD_BACKUP_REMOTE_PATH) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(()), // nothing there (or unreachable) — done
    };
    match parse_cloud_backup_envelope(&bytes) {
        Ok(share) if share.user_id == user_id => {
            crate::rclone::delete_file(remote, LEGACY_CLOUD_BACKUP_REMOTE_PATH)
        }
        Ok(_) => Ok(()), // someone else's backup — leave it alone
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_account_path_contains_the_user_id() {
        let path = cloud_backup_remote_path("9f1c3b2a-4d5e-4f60-8a71-b2c3d4e5f607").unwrap();
        assert_eq!(
            path,
            "VELA/9f1c3b2a-4d5e-4f60-8a71-b2c3d4e5f607/recovery-share.json"
        );
    }

    #[test]
    fn per_account_path_rejects_path_traversal_and_separators() {
        assert!(cloud_backup_remote_path("..").is_err());
        assert!(cloud_backup_remote_path("../other/recovery-share").is_err());
        assert!(cloud_backup_remote_path("a/b").is_err());
        assert!(cloud_backup_remote_path("a\\b").is_err());
        assert!(cloud_backup_remote_path("").is_err());
    }

    #[test]
    fn envelope_parses_back_into_a_share() {
        let json = serde_json::json!({
            "version": 1,
            "user_id": "user-y",
            "share_b64": "AAAA",
        });
        let share = parse_cloud_backup_envelope(serde_json::to_vec(&json).unwrap().as_slice())
            .expect("envelope should parse");
        assert_eq!(share.user_id, "user-y");
        assert_eq!(share.share_b64, "AAAA");
    }

    #[test]
    fn envelope_rejects_garbage() {
        assert!(parse_cloud_backup_envelope(b"not json").is_err());
        assert!(parse_cloud_backup_envelope(b"{}").is_err());
    }
}
