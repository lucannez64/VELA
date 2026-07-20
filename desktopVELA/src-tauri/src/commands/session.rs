use crate::api::{ApiClient, RegisterRequest, VerifyRequest};
use crate::biometric;
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::crypto::{self, Crypto};
use crate::device::DeviceInfo;
use crate::session::{LockState, SessionStatus};
use crate::AppState;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::sync::Arc;
use tauri::{async_runtime, command, State};

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

fn server_url_configured(state: &Arc<AppState>) -> bool {
    !state.server_url.read().trim().is_empty()
}

/// Session lifetime comes from the persisted `auto_lock_minutes` setting
/// (previously dead; the 15-minute hardcode is gone).
fn auto_lock_duration_secs(state: &AppState) -> u64 {
    let minutes = state
        .store
        .load_settings()
        .map(|s| s.auto_lock_minutes)
        .unwrap_or(15);
    (minutes.clamp(1, 24 * 60) as u64) * 60
}

/// Returns `(token, user_id)` on success.
async fn authenticate_with_server(
    state: &Arc<AppState>,
    device_id: &str,
    device_name: &str,
    hybrid_sk: &[u8],
) -> Result<(String, String), String> {
    let server_url = state.server_url.read().clone();
    if server_url.trim().is_empty() {
        return Err("No server URL configured".to_string());
    }

    let client = ApiClient::with_url(server_url);

    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {}", e))?;

    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|e| format!("Invalid challenge format: {}", e))?;

    let signature = crypto::create_auth_signature(hybrid_sk, &challenge_bytes, device_id)
        .map_err(|e| format!("Failed to create auth signature: {}", e))?;

    let verify_resp = client
        .verify_signature(&VerifyRequest {
            device_id: device_id.to_string(),
            challenge: challenge_resp.challenge,
            signature,
            device_name: Some(device_name.to_string()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Failed to verify signature: {}", e))?;

    Ok((verify_resp.token, verify_resp.user_id))
}

/// Registers this device with the server and returns `(user_id, device_id)`.
async fn register_with_server(
    state: &Arc<AppState>,
    device_name: &str,
    crypto: &Crypto,
) -> Result<(String, String), String> {
    let server_url = state.server_url.read().clone();
    if server_url.trim().is_empty() {
        return Err("No server URL configured".to_string());
    }

    let client = ApiClient::with_url(server_url);

    let identity = crypto::generate_identity_keypair()?;

    let register_req = RegisterRequest {
        hybrid_ek: B64.encode(&identity.hybrid_ek),
        hybrid_vk: B64.encode(&identity.hybrid_vk),
        device_name: Some(device_name.to_string()),
        device_type: Some("desktop".to_string()),
        share_ek: Some(B64.encode(&identity.share_ek)),
    };

    let register_resp = client
        .register_account(&register_req)
        .await
        .map_err(|e| format!("Failed to register account: {}", e))?;

    state
        .store
        .save_identity_keys_full(
            &identity.hybrid_ek,
            &identity.hybrid_vk,
            &identity.hybrid_sk,
            &identity.share_ek,
            &identity.share_dk,
            crypto,
        )
        .map_err(|e| format!("Failed to save identity keys: {}", e))?;

    Ok((register_resp.user_id, register_resp.device_id))
}

fn authenticate_with_server_in_background(
    state: Arc<AppState>,
    device_id: String,
    device_name: String,
    context: &'static str,
) {
    if !server_url_configured(&state) {
        return;
    }

    let Some(identity_keys) = state
        .crypto
        .read()
        .as_ref()
        .and_then(|crypto| state.store.load_identity_keys(crypto).ok().flatten())
    else {
        return;
    };

    async_runtime::spawn(async move {
        match authenticate_with_server(&state, &device_id, &device_name, &identity_keys.hybrid_sk)
            .await
        {
            Ok((token, server_user_id)) => {
                state
                    .store
                    .save_device_id_with_user_id(&device_id, &server_user_id)
                    .ok();
                {
                    let mut session = state.session.write();
                    if session.active && session.device_id.as_deref() == Some(device_id.as_str()) {
                        session.set_server_token(token);
                        session.user_id = Some(server_user_id);
                    }
                }
                tracing::info!("Server authentication successful ({context})");
            }
            Err(e) => {
                tracing::warn!("Server authentication failed ({context}, non-fatal): {e}");
            }
        }
    });
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
    state.bump_session_generation();

    Ok(())
}

#[command]
pub async fn unlock_session(
    state: State<'_, Arc<AppState>>,
    _device_id: String,
    _user_id: String,
) -> Result<SessionStatus, String> {
    state.check_unlock_throttle()?;

    // Fail-closed on expiry: when the previous session expired, do NOT silently
    // re-unlock from the in-memory cached RMS — force a fresh read from the
    // OS-backed credential store (TPM / Keychain / Credential Manager).
    let was_expired = {
        let session = state.session.read();
        session.is_expired()
    };
    if was_expired {
        biometric::clear_cached_rms();
    }

    let duration_secs = auto_lock_duration_secs(&state);
    let app_state = state.inner().clone();
    let app_state2 = app_state.clone();

    let (device_name, device_id) = tokio::task::spawn_blocking(move || {
        let rms = if let Some(rms) = biometric::get_cached_rms() {
            rms
        } else {
            let auth_result = biometric::authenticate();

            if !auth_result.success {
                return Err(auth_result
                    .error_message
                    .unwrap_or_else(|| "Authentication failed".to_string()));
            }

            biometric::get_cached_rms().ok_or_else(|| "Failed to retrieve vault key".to_string())?
        };

        let crypto = Crypto::new(&rms);

        let vault = app_state2
            .store
            .load_vault(&crypto)
            .map_err(|e| format!("Failed to load vault: {}", e))?;

        let (local_device_id, device_name) = get_device_info();
        let device_id = app_state2
            .store
            .load_device_id()
            .ok()
            .unwrap_or_else(|| local_device_id.clone());
        let user_id = app_state2
            .store
            .load_user_id()
            .unwrap_or_else(|_| format!("user-{}", &device_id[..8]));

        {
            let mut session = app_state2.session.write();
            session.unlock(device_id.clone(), user_id.clone(), duration_secs);
        }
        {
            let mut crypto_state = app_state2.crypto.write();
            *crypto_state = Some(crypto);
        }
        {
            let mut vault_state = app_state2.vault.write();
            *vault_state = vault;
        }

        record_audit_event(&app_state2, AuditAction::VaultUnlocked);

        Ok::<_, String>((device_name, device_id))
    })
    .await
    .map_err(|e| format!("Unlock task panicked: {}", e))??;

    state.record_unlock_success();
    state.bump_session_generation();

    authenticate_with_server_in_background(
        app_state,
        device_id.clone(),
        device_name.clone(),
        "biometric unlock",
    );

    Ok(SessionStatus {
        active: true,
        session_time_remaining_secs: duration_secs,
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
    // Throttle master-password guessing (persisted across restarts).
    state.check_unlock_throttle()?;

    let duration_secs = auto_lock_duration_secs(&state);
    let app_state = state.inner().clone();
    let app_state2 = app_state.clone();

    let unlock_result = tokio::task::spawn_blocking(move || {
        let Some(rms) = biometric::authenticate_with_password(&password) else {
            return Err("Invalid password".to_string());
        };

        let crypto = Crypto::new(&rms);

        let vault = app_state2.store.load_vault(&crypto).map_err(|e| {
            tracing::error!("Failed to load vault: {}", e);
            format!("Failed to load vault: {}", e)
        })?;

        let (local_device_id, device_name) = get_device_info();
        let device_id = app_state2
            .store
            .load_device_id()
            .ok()
            .unwrap_or_else(|| local_device_id.clone());
        let user_id = app_state2
            .store
            .load_user_id()
            .unwrap_or_else(|_| format!("user-{}", &device_id[..8]));

        {
            let mut session = app_state2.session.write();
            session.unlock(device_id.clone(), user_id.clone(), duration_secs);
        }
        {
            let mut crypto_state = app_state2.crypto.write();
            *crypto_state = Some(crypto);
        }
        {
            let mut vault_state = app_state2.vault.write();
            *vault_state = vault;
        }

        record_audit_event(&app_state2, AuditAction::VaultUnlocked);

        Ok::<_, String>((device_name, device_id))
    })
    .await
    .map_err(|e| format!("Unlock task panicked: {}", e))?;

    let (device_name, device_id) = match unlock_result {
        Ok(ok) => {
            state.record_unlock_success();
            ok
        }
        Err(e) => {
            state.record_unlock_failure();
            return Err(e);
        }
    };

    state.bump_session_generation();

    authenticate_with_server_in_background(
        app_state,
        device_id.clone(),
        device_name.clone(),
        "password unlock",
    );

    tracing::info!("Session unlocked successfully");
    Ok(SessionStatus {
        active: true,
        session_time_remaining_secs: duration_secs,
        device_name: Some(device_name),
        device_id: Some(device_id),
        lock_state: LockState::Unlocked,
    })
}

#[command]
pub async fn create_vault(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let rms = Crypto::generate_rms();

    biometric::store_rms(&rms).map_err(|e| format!("Failed to store vault key: {}", e))?;

    if !biometric::has_stored_rms() {
        return Err("Biometrics not available. Please use password setup instead.".to_string());
    }

    let crypto = Crypto::new(&rms);

    let vault = crate::vault::VaultStore::new();
    state
        .store
        .save_vault(&vault, &crypto)
        .map_err(|e| format!("Failed to create vault: {}", e))?;

    let (local_device_id, device_name) = get_device_info();

    let (device_id, mut user_id) = if server_url_configured(&state) {
        match register_with_server(&state, &device_name, &crypto).await {
            Ok((server_user_id, server_device_id)) => {
                tracing::info!(
                    "Server registration successful, device_id={}, user_id={}",
                    server_device_id,
                    server_user_id
                );
                (server_device_id, server_user_id)
            }
            Err(e) => {
                tracing::warn!("Server registration failed (non-fatal): {}", e);
                let fallback_uid = format!("user-{}", &local_device_id[..8]);
                (local_device_id, fallback_uid)
            }
        }
    } else {
        let fallback_uid = format!("user-{}", &local_device_id[..8]);
        (local_device_id, fallback_uid)
    };

    state
        .store
        .save_device_id_with_user_id(&device_id, &user_id)
        .ok();

    if server_url_configured(&state) {
        if let Some(identity_keys) = state.store.load_identity_keys(&crypto).ok().flatten() {
            match authenticate_with_server(
                &state,
                &device_id,
                &device_name,
                &identity_keys.hybrid_sk,
            )
            .await
            {
                Ok((token, server_user_id)) => {
                    user_id = server_user_id.clone();
                    state
                        .store
                        .save_device_id_with_user_id(&device_id, &server_user_id)
                        .ok();
                    let mut session = state.session.write();
                    session.set_server_token(token);
                    tracing::info!("Server authentication successful (vault creation)");
                }
                Err(e) => {
                    tracing::warn!(
                        "Server authentication after registration failed (non-fatal): {}",
                        e
                    );
                }
            }
        }
    }

    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto);
    }
    {
        let mut session = state.session.write();
        session.unlock(device_id, user_id, auto_lock_duration_secs(&state));
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }
    state.bump_session_generation();

    record_audit_event(&state, AuditAction::VaultCreated);

    Ok(())
}

#[command]
pub async fn create_vault_with_password(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> Result<(), String> {
    let rms = Crypto::generate_rms();

    biometric::delete_stored_rms()
        .map_err(|e| {
            tracing::warn!(
                "Failed to delete old credentials (this is ok if none exist): {}",
                e
            );
            format!("Failed to clear old credentials: {}", e)
        })
        .ok();

    biometric::store_password_encrypted(&rms, &password)
        .map_err(|e| format!("Failed to store password recovery: {}", e))?;

    let crypto = Crypto::new(&rms);

    let vault = crate::vault::VaultStore::new();
    state
        .store
        .save_vault(&vault, &crypto)
        .map_err(|e| format!("Failed to create vault: {}", e))?;

    let (local_device_id, device_name) = get_device_info();

    let (device_id, mut user_id) = if server_url_configured(&state) {
        match register_with_server(&state, &device_name, &crypto).await {
            Ok((server_user_id, server_device_id)) => {
                tracing::info!(
                    "Server registration successful, device_id={}, user_id={}",
                    server_device_id,
                    server_user_id
                );
                (server_device_id, server_user_id)
            }
            Err(e) => {
                tracing::warn!("Server registration failed (non-fatal): {}", e);
                let fallback_uid = format!("user-{}", &local_device_id[..8]);
                (local_device_id, fallback_uid)
            }
        }
    } else {
        let fallback_uid = format!("user-{}", &local_device_id[..8]);
        (local_device_id, fallback_uid)
    };

    state
        .store
        .save_device_id_with_user_id(&device_id, &user_id)
        .ok();

    if server_url_configured(&state) {
        if let Some(identity_keys) = state.store.load_identity_keys(&crypto).ok().flatten() {
            match authenticate_with_server(
                &state,
                &device_id,
                &device_name,
                &identity_keys.hybrid_sk,
            )
            .await
            {
                Ok((token, server_user_id)) => {
                    user_id = server_user_id.clone();
                    state
                        .store
                        .save_device_id_with_user_id(&device_id, &server_user_id)
                        .ok();
                    let mut session = state.session.write();
                    session.set_server_token(token);
                }
                Err(e) => {
                    tracing::warn!(
                        "Server authentication after registration failed (non-fatal): {}",
                        e
                    );
                }
            }
        }
    }

    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto);
    }
    {
        let mut session = state.session.write();
        session.unlock(device_id.clone(), user_id, auto_lock_duration_secs(&state));
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }
    state.bump_session_generation();

    record_audit_event(&state, AuditAction::VaultCreated);

    tracing::info!("Vault created and session unlocked");
    Ok(())
}

#[command]
pub async fn check_vault_exists(state: State<'_, Arc<AppState>>) -> Result<bool, String> {
    Ok(state.store.has_existing_vault())
}

/// Irreversibly wipe the local vault. Authentication ladder (strongest first):
///
/// 1. `password` — the current master password, verified by unwrapping the RMS
///    exactly like unlock does.
/// 2. `confirm == "DELETE"` **plus** a freshly verified server auth challenge —
///    available whenever the vault is unlocked and a server is configured
///    (proves possession of the device identity key).
/// 3. `confirm == "DELETE"` alone — only when the vault is locked (the
///    forgot-password recovery flow). A server challenge is cryptographically
///    impossible there: the identity signing key is RMS-encrypted and the RMS
///    is exactly what the user can no longer unwrap. Wiping local data is
///    recoverable via re-enrollment, so a typed confirmation is the strongest
///    check that does not break recovery.
#[command]
pub async fn reset_vault(
    state: State<'_, Arc<AppState>>,
    confirm: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    let app_state = state.inner().clone();
    let mut authorized = false;

    // Path 1: master-password proof.
    if let Some(password) = password {
        let verified = tokio::task::spawn_blocking(move || {
            biometric::authenticate_with_password(&password).is_some()
        })
        .await
        .map_err(|e| format!("Password verification task panicked: {}", e))?;
        if !verified {
            return Err("Invalid master password — vault reset refused".to_string());
        }
        authorized = true;
    }

    // Path 2/3: typed confirmation.
    if !authorized {
        if confirm.as_deref() != Some("DELETE") {
            return Err(
                "Reset requires the master password or typing DELETE to confirm".to_string(),
            );
        }

        // When the vault is unlocked and a server is configured, additionally
        // require a freshly verified server auth challenge — an unlocked UI
        // alone is not sufficient proof for destruction.
        if state.is_unlocked() && server_url_configured(&app_state) {
            let (identity_keys, device_id) = {
                let crypto_guard = state.crypto.read();
                let keys = crypto_guard
                    .as_ref()
                    .and_then(|crypto| state.store.load_identity_keys(crypto).ok().flatten())
                    .ok_or_else(|| {
                        "Cannot verify device identity for reset; provide the master password"
                            .to_string()
                    })?;
                let device_id = state
                    .store
                    .load_device_id()
                    .map_err(|e| format!("Failed to load device id: {}", e))?;
                (keys, device_id)
            };
            let device_name = get_device_name();
            authenticate_with_server(&app_state, &device_id, &device_name, &identity_keys.hybrid_sk)
                .await
                .map_err(|e| format!("Server re-authentication for reset failed: {}", e))?;
        }
        // Locked vault (forgot-password flow): typed DELETE is the strongest
        // available proof — see the doc comment above.
    }

    biometric::delete_stored_rms().map_err(|e| format!("Failed to delete credentials: {}", e))?;

    let vault_path = state.store.store_path().join("vault.enc");
    let rms_path = state.store.store_path().join("rms.enc");

    if vault_path.exists() {
        std::fs::remove_file(&vault_path)
            .map_err(|e| format!("Failed to delete vault file: {}", e))?;
    }

    if rms_path.exists() {
        std::fs::remove_file(&rms_path).map_err(|e| format!("Failed to delete RMS file: {}", e))?;
    }

    if vault_path.exists() || rms_path.exists() {
        return Err("Vault files still exist after deletion".to_string());
    }

    {
        let mut session = state.session.write();
        session.lock();
    }
    {
        let mut crypto = state.crypto.write();
        *crypto = None;
    }
    {
        let mut vault = state.vault.write();
        *vault = crate::vault::VaultStore::new();
    }
    biometric::clear_cached_rms();
    state.bump_session_generation();

    Ok(())
}

#[command]
pub async fn get_device_id(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    state.store.load_device_id().map_err(|e| e.to_string())
}
