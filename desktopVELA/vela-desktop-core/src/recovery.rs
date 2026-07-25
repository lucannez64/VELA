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
