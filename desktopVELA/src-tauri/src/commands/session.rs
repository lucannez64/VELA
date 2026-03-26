use crate::biometric;
use crate::crypto::Crypto;
use crate::device::DeviceInfo;
use crate::session::{LockState, SessionStatus};
use crate::AppState;
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
    
    let (device_id, device_name) = get_device_info();
    let user_id = format!("user-{}", &device_id[..8]);
    
    let mut session = state.session.write();
    session.unlock(device_id.clone(), user_id.clone(), 15 * 60);
    
    let mut crypto_state = state.crypto.write();
    *crypto_state = Some(crypto);
    
    let mut vault_state = state.vault.write();
    *vault_state = vault;
    
    state.store.save_device_id(&device_id).ok();
    
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
    
    let (device_id, device_name) = get_device_info();
    let user_id = format!("user-{}", &device_id[..8]);
    
    tracing::info!("Vault loaded, unlocking session");
    let mut session = state.session.write();
    session.unlock(device_id.clone(), user_id.clone(), 15 * 60);
    
    let mut crypto_state = state.crypto.write();
    *crypto_state = Some(crypto);
    
    let mut vault_state = state.vault.write();
    *vault_state = vault;
    
    state.store.save_device_id(&device_id).ok();
    
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
    
    let (device_id, _device_name) = get_device_info();
    let user_id = format!("user-{}", &device_id[..8]);
    
    let mut crypto_state = state.crypto.write();
    *crypto_state = Some(crypto);
    
    let mut session = state.session.write();
    session.unlock(device_id, user_id, 15 * 60);
    
    let mut vault_state = state.vault.write();
    *vault_state = vault;
    
    Ok(())
}

#[command]
pub async fn create_vault_with_password(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> Result<(), String> {
    tracing::info!("Creating vault with password");
    
    let rms = Crypto::generate_rms();
    tracing::info!("Generated RMS");
    
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
    
    let (device_id, _device_name) = get_device_info();
    let user_id = format!("user-{}", &device_id[..8]);
    
    let mut crypto_state = state.crypto.write();
    *crypto_state = Some(crypto);
    
    let mut session = state.session.write();
    session.unlock(device_id, user_id, 15 * 60);
    
    let mut vault_state = state.vault.write();
    *vault_state = vault;
    
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
