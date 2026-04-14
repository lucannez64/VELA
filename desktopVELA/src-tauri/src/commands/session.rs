use crate::api::{ApiClient, RegisterRequest, VerifyRequest};
use crate::biometric;
use crate::commands::audit::{AuditAction, record_audit_event};
use crate::crypto::{self, Crypto};
use crate::device::DeviceInfo;
use crate::session::{LockState, SessionStatus};
use crate::AppState;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::Digest;
use tauri::{command, State};
use std::sync::Arc;

fn get_device_info() -> (String, String) {
    let device_id = DeviceInfo::generate_device_id();
    let device_name = get_device_name();
    (device_id, device_name)
}

fn get_device_name() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Mac".to_string())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Desktop".to_string())
    }
}

/// Returns `(token, user_id)` on success.
async fn authenticate_with_server(
    state: &Arc<AppState>,
    device_id: &str,
    _device_name: &str,
    cyclo_pk: &[u8],
    cyclo_sk: &[u8],
) -> Result<(String, String), String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let challenge_resp = client.get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {}", e))?;

    let challenge_bytes = B64.decode(&challenge_resp.challenge)
        .map_err(|e| format!("Invalid challenge format: {}", e))?;

    let (proof, committed_hash_hex) = crypto::create_auth_proof(cyclo_pk, cyclo_sk, &challenge_bytes, device_id)
        .map_err(|e| format!("Failed to create auth proof: {}", e))?;

    let verify_resp = client.verify_proof(&VerifyRequest {
        device_id: device_id.to_string(),
        challenge: challenge_resp.challenge,
        committed_hash: committed_hash_hex,
        proof,
    })
    .await
    .map_err(|e| format!("Failed to verify proof: {}", e))?;

    Ok((verify_resp.token, verify_resp.user_id))
}

/// Registers this device with the server and returns `(user_id, device_id)`.
async fn register_with_server(
    state: &Arc<AppState>,
    _device_name: &str,
) -> Result<(String, String), String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let identity = crypto::generate_identity_keypair()?;

    let register_req = RegisterRequest {
        hybrid_ek: B64.encode(&identity.hybrid_ek),
        hybrid_vk: B64.encode(&identity.hybrid_vk),
        cyclo_pk: B64.encode(&identity.cyclo_pk),
    };

    let register_resp = client.register_account(&register_req)
        .await
        .map_err(|e| format!("Failed to register account: {}", e))?;

    state.store.save_identity_keys(&identity.hybrid_ek, &identity.hybrid_vk, &identity.cyclo_pk, &identity.cyclo_sk, &identity.hybrid_sk)
        .map_err(|e| format!("Failed to save identity keys: {}", e))?;

    Ok((register_resp.user_id, register_resp.device_id))
}

#[command]
pub async fn get_session_status(state: State<'_, Arc<AppState>>) -> Result<SessionStatus, String> {
    let session = state.session.read();
    let remaining = session.remaining_time();
    let lock_state = if !session.active {
        LockState::Locked
    } else if remaining == 0 {
        LockState::Locked
    } else {
        LockState::Unlocked
    };

    Ok(SessionStatus {
        active: session.active && remaining > 0,
        session_time_remaining_secs: remaining,
        device_name: Some(get_device_name()),
        device_id: session.device_id.clone(),
        lock_state,
    })
}

#[command]
pub async fn lock_session(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    record_audit_event(&state, AuditAction::VaultLocked);
    let mut session = state.session.write();
    session.lock();
    
    let mut crypto = state.crypto.write();
    *crypto = None;
    
    let mut vault = state.vault.write();
    *vault = crate::vault::VaultStore::new();
    
    biometric::clear_cached_rms();
    
    Ok(())
}

#[command]
pub async fn unlock_session(
    state: State<'_, Arc<AppState>>,
    _device_id: String,
    _user_id: String,
) -> Result<SessionStatus, String> {
    let auth_result = biometric::authenticate();
    
    if !auth_result.success {
        return Err(auth_result.error_message.unwrap_or_else(|| "Authentication failed".to_string()));
    }
    
    let rms = biometric::get_cached_rms()
        .ok_or_else(|| "Failed to retrieve vault key".to_string())?;
    
    let crypto = Crypto::new(&rms);
    
    let vault = state.store.load_vault(&crypto)
        .map_err(|e| format!("Failed to load vault: {}", e))?;
    
    let (local_device_id, device_name) = get_device_info();
    let device_id = state.store.load_device_id()
        .ok()
        .unwrap_or_else(|| local_device_id.clone());
    let mut user_id = state.store.load_user_id().unwrap_or_else(|_| format!("user-{}", &device_id[..8]));

    if let Some(identity_keys) = state.store.load_identity_keys().ok().flatten() {
        match authenticate_with_server(
            &state,
            &device_id,
            &device_name,
            &identity_keys.cyclo_pk,
            &identity_keys.cyclo_sk,
        ).await {
            Ok((token, server_user_id)) => {
                user_id = server_user_id.clone();
                state.store.save_device_id_with_user_id(&device_id, &server_user_id).ok();
                {
                    let mut session = state.session.write();
                    session.set_server_token(token);
                }
                tracing::info!("Server authentication successful");
            }
            Err(e) => {
                tracing::warn!("Server authentication failed (non-fatal): {}", e);
            }
        }
    }

    {
        let mut session = state.session.write();
        session.unlock(device_id.clone(), user_id.clone(), 15 * 60);
    }
    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto);
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }

    record_audit_event(&state, AuditAction::VaultUnlocked);

    Ok(SessionStatus {
        active: true,
        session_time_remaining_secs: 15 * 60,
        device_name: Some(device_name),
        device_id: Some(device_id),
        lock_state: LockState::Unlocked,
    })
}

#[command]
pub async fn unlock_session_with_password(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> Result<SessionStatus, String> {
    tracing::info!("Unlocking session with password");
    
    let rms = biometric::authenticate_with_password(&password)
        .ok_or_else(|| {
            tracing::warn!("Password authentication failed in unlock_session_with_password");
            "Invalid password".to_string()
        })?;
    
    tracing::info!("Password authenticated, creating crypto");
    tracing::info!("Retrieved RMS: hash={:x}", sha2::Sha256::digest(&rms));
    let crypto = Crypto::new(&rms);
    
    tracing::info!("Loading vault");
    tracing::info!("Store path: {:?}", state.store.store_path());
    if state.store.store_path().join("vault.enc").exists() {
        let size = std::fs::metadata(state.store.store_path().join("vault.enc"))
            .map(|m| m.len()).unwrap_or(0);
        tracing::info!("vault.enc exists, size: {} bytes", size);
    } else {
        tracing::error!("vault.enc NOT found!");
    }
    
    let vault = state.store.load_vault(&crypto)
        .map_err(|e| {
            tracing::error!("Failed to load vault: {}", e);
            format!("Failed to load vault: {}", e)
        })?;
    
    let (local_device_id, device_name) = get_device_info();
    let device_id = state.store.load_device_id()
        .ok()
        .unwrap_or_else(|| local_device_id.clone());
    let mut user_id = state.store.load_user_id().unwrap_or_else(|_| format!("user-{}", &device_id[..8]));

    tracing::info!("Vault loaded, unlocking session");
    {
        let mut session = state.session.write();
        session.unlock(device_id.clone(), user_id.clone(), 15 * 60);
    }
    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto);
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }

    if let Some(identity_keys) = state.store.load_identity_keys().ok().flatten() {
        match authenticate_with_server(
            &state,
            &device_id,
            &device_name,
            &identity_keys.cyclo_pk,
            &identity_keys.cyclo_sk,
        ).await {
            Ok((token, server_user_id)) => {
                user_id = server_user_id.clone();
                state.store.save_device_id_with_user_id(&device_id, &server_user_id).ok();
                {
                    let mut session = state.session.write();
                    session.set_server_token(token);
                    // Update user_id in the already-active session without re-running unlock().
                    session.user_id = Some(server_user_id);
                }
                tracing::info!("Server authentication successful (password unlock)");
            }
            Err(e) => {
                tracing::warn!("Server authentication failed after password unlock (non-fatal): {}", e);
            }
        }
    }

    record_audit_event(&state, AuditAction::VaultUnlocked);

    tracing::info!("Session unlocked successfully");
    Ok(SessionStatus {
        active: true,
        session_time_remaining_secs: 15 * 60,
        device_name: Some(device_name),
        device_id: Some(device_id),
        lock_state: LockState::Unlocked,
    })
}

#[command]
pub async fn create_vault(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let rms = Crypto::generate_rms();
    
    biometric::store_rms(&rms)
        .map_err(|e| format!("Failed to store vault key: {}", e))?;
    
    if !biometric::has_stored_rms() {
        return Err("Biometrics not available. Please use password setup instead.".to_string());
    }
    
    let crypto = Crypto::new(&rms);
    
    let vault = crate::vault::VaultStore::new();
    state.store.save_vault(&vault, &crypto)
        .map_err(|e| format!("Failed to create vault: {}", e))?;
    
    let (local_device_id, device_name) = get_device_info();

    let (device_id, mut user_id) = match register_with_server(&state, &device_name).await {
        Ok((server_user_id, server_device_id)) => {
            tracing::info!("Server registration successful, device_id={}, user_id={}", server_device_id, server_user_id);
            (server_device_id, server_user_id)
        }
        Err(e) => {
            tracing::warn!("Server registration failed (non-fatal): {}", e);
            let fallback_uid = format!("user-{}", &local_device_id[..8]);
            (local_device_id, fallback_uid)
        }
    };

    state.store.save_device_id_with_user_id(&device_id, &user_id).ok();

    if let Some(identity_keys) = state.store.load_identity_keys().ok().flatten() {
        match authenticate_with_server(
            &state,
            &device_id,
            &device_name,
            &identity_keys.cyclo_pk,
            &identity_keys.cyclo_sk,
        ).await {
            Ok((token, server_user_id)) => {
                user_id = server_user_id.clone();
                state.store.save_device_id_with_user_id(&device_id, &server_user_id).ok();
                let mut session = state.session.write();
                session.set_server_token(token);
                tracing::info!("Server authentication successful (vault creation)");
            }
            Err(e) => {
                tracing::warn!("Server authentication after registration failed (non-fatal): {}", e);
            }
        }
    }

    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto);
    }
    {
        let mut session = state.session.write();
        session.unlock(device_id, user_id, 15 * 60);
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }

    record_audit_event(&state, AuditAction::VaultCreated);

    Ok(())
}

#[command]
pub async fn create_vault_with_password(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> Result<(), String> {
    tracing::info!("Creating vault with password");
    
    let rms = Crypto::generate_rms();
    tracing::info!("Generated RMS: hash={:x}", sha2::Sha256::digest(&rms));
    
    biometric::delete_stored_rms()
        .map_err(|e| {
            tracing::warn!("Failed to delete old credentials (this is ok if none exist): {}", e);
            format!("Failed to clear old credentials: {}", e)
        })
        .ok();
    
    tracing::info!("Storing password-encrypted RMS");
    biometric::store_password_encrypted(&rms, &password)
        .map_err(|e| format!("Failed to store password recovery: {}", e))?;
    
    tracing::info!("Creating crypto and vault");
    let crypto = Crypto::new(&rms);
    
    let vault = crate::vault::VaultStore::new();
    state.store.save_vault(&vault, &crypto)
        .map_err(|e| format!("Failed to create vault: {}", e))?;
    tracing::info!("Vault saved to disk");
    
    tracing::info!("Store path: {:?}", state.store.store_path());
    if state.store.store_path().join("vault.enc").exists() {
        let size = std::fs::metadata(state.store.store_path().join("vault.enc"))
            .map(|m| m.len()).unwrap_or(0);
        tracing::info!("vault.enc exists, size: {} bytes", size);
    } else {
        tracing::error!("vault.enc NOT found after save!");
    }
    
    let (local_device_id, device_name) = get_device_info();

    let (device_id, mut user_id) = match register_with_server(&state, &device_name).await {
        Ok((server_user_id, server_device_id)) => {
            tracing::info!("Server registration successful, device_id={}, user_id={}", server_device_id, server_user_id);
            (server_device_id, server_user_id)
        }
        Err(e) => {
            tracing::warn!("Server registration failed (non-fatal): {}", e);
            let fallback_uid = format!("user-{}", &local_device_id[..8]);
            (local_device_id, fallback_uid)
        }
    };

    state.store.save_device_id_with_user_id(&device_id, &user_id).ok();

    if let Some(identity_keys) = state.store.load_identity_keys().ok().flatten() {
        match authenticate_with_server(
            &state,
            &device_id,
            &device_name,
            &identity_keys.cyclo_pk,
            &identity_keys.cyclo_sk,
        ).await {
            Ok((token, server_user_id)) => {
                user_id = server_user_id.clone();
                state.store.save_device_id_with_user_id(&device_id, &server_user_id).ok();
                let mut session = state.session.write();
                session.set_server_token(token);
                tracing::info!("Server authentication successful (password vault creation)");
            }
            Err(e) => {
                tracing::warn!("Server authentication after registration failed (non-fatal): {}", e);
            }
        }
    }

    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto);
    }
    {
        let mut session = state.session.write();
        session.unlock(device_id.clone(), user_id, 15 * 60);
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }
    
    record_audit_event(&state, AuditAction::VaultCreated);
    
    tracing::info!("Vault created and session unlocked");
    Ok(())
}

#[command]
pub async fn check_vault_exists(state: State<'_, Arc<AppState>>) -> Result<bool, String> {
    Ok(state.store.has_existing_vault())
}

#[command]
pub async fn reset_vault(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    biometric::delete_stored_rms()
        .map_err(|e| format!("Failed to delete credentials: {}", e))?;

    let vault_path = state.store.store_path().join("vault.enc");
    let rms_path = state.store.store_path().join("rms.enc");

    if vault_path.exists() {
        std::fs::remove_file(&vault_path)
            .map_err(|e| format!("Failed to delete vault file: {}", e))?;
    }

    if rms_path.exists() {
        std::fs::remove_file(&rms_path)
            .map_err(|e| format!("Failed to delete RMS file: {}", e))?;
    }

    if vault_path.exists() || rms_path.exists() {
        return Err("Vault files still exist after deletion".to_string());
    }

    Ok(())
}

#[command]
pub async fn get_device_id(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    state.store.load_device_id()
        .map_err(|e| e.to_string())
}
