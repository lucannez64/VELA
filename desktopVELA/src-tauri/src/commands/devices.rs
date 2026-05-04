use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

use crate::api::{ApiClient, EnrollDeviceRequest, NewDevicePayload, VerifyRequest};
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::crypto;
use crate::AppState;
use vela_crypto::aead::decrypt;

const VAULT_MAIN_CHUNK_ID: &str = "vault-main";
const VAULT_DATA_PREFIX: &str = "vault-data-";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub enrolled_at: DateTime<Utc>,
    pub last_active: Option<DateTime<Utc>>,
    pub this_device: bool,
    pub revoked: bool,
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Desktop,
    Mobile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub device_id: String,
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
struct ServerDeviceInfo {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub last_active: Option<String>,
    pub revoked: bool,
    pub pending: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
struct ServerDeviceListResponse {
    pub devices: Vec<ServerDeviceInfo>,
}

const LEGACY_VAULT_MAIN_CHUNK_ID: &str = "vault-main";
const VAULT_CHUNK_PREFIX: &str = "vault-data-";

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

async fn download_enrolled_vault(
    client: &ApiClient,
    token: &mut String,
    crypto_obj: &crate::crypto::Crypto,
) -> crate::vault::VaultStore {
    let Ok((manifest, new_tok)) = client.get_sync_manifest(token).await else {
        return crate::vault::VaultStore::new();
    };
    if let Some(t) = new_tok {
        *token = t;
    }

    let mut ids: Vec<String> = manifest
        .chunks
        .iter()
        .filter(|entry| entry.chunk_id.starts_with(VAULT_CHUNK_PREFIX))
        .map(|entry| entry.chunk_id.clone())
        .collect();
    ids.sort();

    if ids.is_empty()
        && manifest
            .chunks
            .iter()
            .any(|entry| entry.chunk_id == LEGACY_VAULT_MAIN_CHUNK_ID)
    {
        ids.push(LEGACY_VAULT_MAIN_CHUNK_ID.to_string());
    }

    let mut plaintext = Vec::new();
    for chunk_id in ids {
        let Ok((ciphertext, _, _, new_tok)) = client.get_chunk(token, &chunk_id).await else {
            continue;
        };
        if let Some(t) = new_tok {
            *token = t;
        }
        let key = *crypto_obj.chunk_key(chunk_id.as_bytes()).as_bytes();
        let Ok(mut chunk) = decrypt(&key, &ciphertext) else {
            continue;
        };
        plaintext.append(&mut chunk);
    }

    if plaintext.is_empty() {
        return crate::vault::VaultStore::new();
    }

    serde_json::from_slice::<crate::vault::VaultStore>(&plaintext).unwrap_or_else(|e| {
        tracing::warn!("Failed to parse downloaded vault JSON: {e}");
        crate::vault::VaultStore::new()
    })
}

#[tauri::command]
pub async fn get_devices(state: State<'_, Arc<AppState>>) -> Result<Vec<Device>, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state.get_session_token().ok_or("Not authenticated")?;

    let this_device_id = state.store.load_device_id().unwrap_or_default();

    let (resp, new_tok) = client
        .get_devices_raw(&token)
        .await
        .map_err(|e| format!("Failed to fetch devices: {}", e))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }

    let list: ServerDeviceListResponse =
        serde_json::from_str(&resp).map_err(|e| format!("Failed to parse device list: {}", e))?;

    let devices: Vec<Device> = list
        .devices
        .into_iter()
        .map(|d| {
            let enrolled_at = chrono::DateTime::parse_from_rfc3339(&d.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Device {
                id: d.id.clone(),
                name: if d.id == this_device_id {
                    format!("{} (This Device)", d.name)
                } else {
                    d.name
                },
                device_type: if d.device_type == "mobile" {
                    DeviceType::Mobile
                } else {
                    DeviceType::Desktop
                },
                enrolled_at,
                last_active: d
                    .last_active
                    .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
                this_device: d.id == this_device_id,
                revoked: d.revoked,
                pending: d.pending,
            }
        })
        .collect();

    Ok(devices)
}

/// Payload embedded in the enrollment invitation code (base64-encoded JSON).
#[derive(Debug, Serialize, Deserialize)]
struct EnrollmentCodePayload {
    device_id: String,
    hybrid_ek: String,    // base64
    hybrid_vk: String,    // base64
    cyclo_pk: String,     // base64
    cyclo_sk: String,     // base64
    hybrid_sk: String,    // base64 (signing key — keep this secret!)
    transfer_key: String, // base64, 32 B — decrypts rms_capsule on server
    server_url: String,
}

/// Generate an enrollment invitation code that a second device can import.
///
/// The existing (enrolled) device:
///   1. Generates a fresh keypair for the new device.
///   2. Creates an rms_capsule by AEAD-encrypting the RMS with a random transfer key.
///   3. Signs the new device's `hybrid_vk` with its own signing key.
///   4. Proves its identity to the server (ZKP challenge/response).
///   5. Calls `POST /device/enroll` → gets a server-assigned `device_id`.
///   6. Returns a base64-encoded JSON blob containing everything the new device needs.
///
/// The invitation code is ~20 KB. It contains a private signing key for the new
/// device, so it **must be transmitted securely** (e.g. shown on-screen and
/// scanned or typed on the new device directly).
#[tauri::command]
pub async fn generate_enrollment_code(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    // ── gate: session must be active ─────────────────────────────────────────
    if !state.session.read().active {
        return Err("Vault is locked. Please unlock before enrolling a new device.".to_string());
    }

    // ── get RMS ───────────────────────────────────────────────────────────────
    let rms: [u8; 32] = {
        let crypto = state.crypto.read();
        let c = crypto.as_ref().ok_or("Vault is locked")?;
        c.rms_as_bytes()
    };
    let crypto_for_keys = crate::crypto::Crypto::new(&rms);

    // ── load own identity keys ────────────────────────────────────────────────
    let own_keys = state
        .store
        .load_identity_keys(&crypto_for_keys)
        .map_err(|e| format!("Failed to load identity keys: {e}"))?
        .ok_or("No identity keys found. Please re-create your vault.")?;

    if own_keys.hybrid_sk.is_empty() {
        return Err(
            "This vault was created before enrollment support was added. \
             Please re-create the vault to enable device enrollment."
                .to_string(),
        );
    }

    let own_device_id = state
        .store
        .load_device_id()
        .map_err(|e| format!("Failed to load device ID: {e}"))?;

    // ── generate new device keypair ───────────────────────────────────────────
    // ML-DSA keygen is stack-heavy; spawn on a blocking thread with enough stack.
    let new_identity = tokio::task::spawn_blocking(|| crypto::generate_identity_keypair())
        .await
        .map_err(|e| format!("Thread join error: {e}"))?
        .map_err(|e| format!("Keypair generation failed: {e}"))?;

    // ── generate transfer key and create RMS capsule ──────────────────────────
    let mut transfer_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut transfer_key);

    let rms_capsule = crypto::create_rms_capsule(&transfer_key, &rms)
        .map_err(|e| format!("Failed to create RMS capsule: {e}"))?;

    // ── sign the new device's hybrid_vk ──────────────────────────────────────
    // Spawn on blocking thread — ML-DSA signing is compute-heavy.
    let (sk_bytes, vk_bytes) = (own_keys.hybrid_sk.clone(), new_identity.hybrid_vk.clone());
    let signature =
        tokio::task::spawn_blocking(move || crypto::sign_new_device_vk(&sk_bytes, &vk_bytes))
            .await
            .map_err(|e| format!("Thread join error: {e}"))?
            .map_err(|e| format!("Signing failed: {e}"))?;

    // ── get challenge and create ZKP proof ────────────────────────────────────
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url.clone());

    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|_| "Invalid challenge encoding from server")?;

    let (pk_bytes, sk_bytes2) = (own_keys.cyclo_pk.clone(), own_keys.cyclo_sk.clone());
    let dev_id_clone = own_device_id.clone();
    let (proof, committed_hash_hex) = tokio::task::spawn_blocking(move || {
        crypto::create_auth_proof(&pk_bytes, &sk_bytes2, &challenge_bytes, &dev_id_clone)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("ZKP proof failed: {e}"))?;

    // ── POST /device/enroll ───────────────────────────────────────────────────
    let enroll_req = EnrollDeviceRequest {
        enrolling_device_id: own_device_id.clone(),
        challenge: challenge_resp.challenge,
        committed_hash: committed_hash_hex,
        proof,
        new_device: NewDevicePayload {
            hybrid_ek: B64.encode(&new_identity.hybrid_ek),
            hybrid_vk: B64.encode(&new_identity.hybrid_vk),
            cyclo_pk: B64.encode(&new_identity.cyclo_pk),
            rms_capsule: B64.encode(&rms_capsule),
            signature: B64.encode(&signature),
            device_name: Some("Pending Desktop Enrollment".to_string()),
            device_type: Some("desktop".to_string()),
        },
    };

    let enroll_resp = client
        .enroll_device(&enroll_req)
        .await
        .map_err(|e| format!("Enrollment failed: {e}"))?;

    tracing::info!(
        new_device_id = %enroll_resp.device_id,
        enrolled_by   = %own_device_id,
        "New device enrolled"
    );

    record_audit_event(
        &state,
        AuditAction::DeviceEnrolled {
            device_id: enroll_resp.device_id.clone(),
            enrolling_device_id: Some(own_device_id.clone()),
        },
    );

    // ── package the invitation code ───────────────────────────────────────────
    let payload = EnrollmentCodePayload {
        device_id: enroll_resp.device_id,
        hybrid_ek: B64.encode(&new_identity.hybrid_ek),
        hybrid_vk: B64.encode(&new_identity.hybrid_vk),
        cyclo_pk: B64.encode(&new_identity.cyclo_pk),
        cyclo_sk: B64.encode(&new_identity.cyclo_sk),
        hybrid_sk: B64.encode(&new_identity.hybrid_sk),
        transfer_key: B64.encode(&transfer_key),
        server_url,
    };

    let json = serde_json::to_string(&payload).map_err(|e| format!("Serialization error: {e}"))?;
    Ok(B64.encode(json.as_bytes()))
}

/// Try to download and decrypt a single vault chunk by chunk_id.
/// Returns `Some(VaultStore)` on success, `None` if the chunk doesn't exist
/// or cannot be decrypted.
async fn try_download_chunk(
    crypto: &crate::crypto::Crypto,
    client: &ApiClient,
    token: &str,
    chunk_id: &str,
) -> Option<crate::vault::VaultStore> {
    let chunk_key_bytes: [u8; 32] = *crypto.chunk_key(chunk_id.as_bytes()).as_bytes();
    match client.get_chunk(token, chunk_id).await {
        Ok((ciphertext, _, _, _)) => match decrypt(&chunk_key_bytes, &ciphertext) {
            Ok(plaintext) => match serde_json::from_slice::<crate::vault::VaultStore>(&plaintext) {
                Ok(v) => {
                    tracing::info!("Vault downloaded from chunk '{}'", chunk_id);
                    Some(v)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse vault JSON from chunk '{}': {}",
                        chunk_id,
                        e
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to decrypt chunk '{}': {}", chunk_id, e);
                None
            }
        },
        Err(e) => {
            tracing::info!("Chunk '{}' not available: {}", chunk_id, e);
            None
        }
    }
}

/// Try to download the vault via the manifest, looking for the first
/// `vault-data-*` chunk.
async fn try_download_fallback_chunk(
    crypto: &crate::crypto::Crypto,
    client: &ApiClient,
    token: &str,
) -> Option<crate::vault::VaultStore> {
    let manifest = match client.get_sync_manifest(token).await {
        Ok((m, _)) => m,
        Err(e) => {
            tracing::warn!("Failed to fetch manifest for fallback: {}", e);
            return None;
        }
    };
    let fallback_id = manifest
        .chunks
        .iter()
        .find(|c| c.chunk_id.starts_with(VAULT_DATA_PREFIX))
        .map(|c| c.chunk_id.clone());
    match fallback_id {
        Some(id) => try_download_chunk(crypto, client, token, &id).await,
        None => None,
    }
}

/// Import an enrollment code on a new device.
///
/// The new device:
///   1. Decodes the invitation code.
///   2. Persists the device ID and identity keys.
///   3. Authenticates with the server (ZKP) → gets a session token.
///   4. Downloads and decrypts the RMS capsule from the server.
///   5. Stores the RMS encrypted with the provided password.
///   6. Downloads the vault and unlocks the session.
#[tauri::command]
pub async fn import_enrollment_code(
    state: State<'_, Arc<AppState>>,
    code: String,
    password: String,
) -> Result<(), String> {
    // ── decode invitation code ────────────────────────────────────────────────
    let json_bytes = B64
        .decode(&code)
        .map_err(|e| format!("Invalid enrollment code (base64 error): {e}"))?;
    let payload: EnrollmentCodePayload = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("Invalid enrollment code (JSON error): {e}"))?;

    // ── decode key material ───────────────────────────────────────────────────
    let hybrid_ek = B64
        .decode(&payload.hybrid_ek)
        .map_err(|_| "bad hybrid_ek")?;
    let hybrid_vk = B64
        .decode(&payload.hybrid_vk)
        .map_err(|_| "bad hybrid_vk")?;
    let cyclo_pk = B64.decode(&payload.cyclo_pk).map_err(|_| "bad cyclo_pk")?;
    let cyclo_sk = B64.decode(&payload.cyclo_sk).map_err(|_| "bad cyclo_sk")?;
    let hybrid_sk = B64
        .decode(&payload.hybrid_sk)
        .map_err(|_| "bad hybrid_sk")?;
    let transfer_key_vec = B64
        .decode(&payload.transfer_key)
        .map_err(|_| "bad transfer_key")?;

    if transfer_key_vec.len() != 32 {
        return Err("transfer_key must be 32 bytes".to_string());
    }
    let mut transfer_key = [0u8; 32];
    transfer_key.copy_from_slice(&transfer_key_vec);

    // ── persist device ID ─────────────────────────────────────────────────────
    state
        .store
        .save_device_id(&payload.device_id)
        .map_err(|e| format!("Failed to save device ID: {e}"))?;

    // ── set server URL ────────────────────────────────────────────────────────
    if !payload.server_url.is_empty() {
        *state.server_url.write() = payload.server_url.clone();
    }
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    // ── authenticate with server ──────────────────────────────────────────────
    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|_| "Invalid challenge encoding")?;

    let device_id_clone = payload.device_id.clone();
    let (pk2, sk2, cb2) = (cyclo_pk.clone(), cyclo_sk.clone(), challenge_bytes.clone());
    let (proof, committed_hash_hex) = tokio::task::spawn_blocking(move || {
        crypto::create_auth_proof(&pk2, &sk2, &cb2, &device_id_clone)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("ZKP proof failed: {e}"))?;

    let verify_resp = client
        .verify_proof(&VerifyRequest {
            device_id: payload.device_id.clone(),
            challenge: challenge_resp.challenge,
            committed_hash: committed_hash_hex,
            proof,
            device_name: Some(get_device_name()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Server authentication failed: {e}"))?;

    let mut token = verify_resp.token;
    let user_id = verify_resp.user_id;

    // ── download RMS capsule from server ──────────────────────────────────────
    let (capsule_resp, _) = client
        .get_capsule(&token)
        .await
        .map_err(|e| format!("Failed to download RMS capsule: {e}"))?;
    let capsule_bytes = B64
        .decode(&capsule_resp.capsule)
        .map_err(|_| "Invalid capsule encoding")?;

    // ── decrypt capsule → RMS ─────────────────────────────────────────────────
    let rms = crypto::decrypt_rms_capsule(&transfer_key, &capsule_bytes)
        .map_err(|e| format!("Failed to decrypt RMS capsule: {e}"))?;

    // ── store RMS encrypted with password ─────────────────────────────────────
    crate::biometric::store_password_encrypted(&rms, &password)
        .map_err(|e| format!("Failed to store vault key: {e}"))?;

    // ── build Crypto and download vault ───────────────────────────────────────
    let crypto_obj = crate::crypto::Crypto::new(&rms);
    state
        .store
        .save_identity_keys(
            &hybrid_ek,
            &hybrid_vk,
            &cyclo_pk,
            &cyclo_sk,
            &hybrid_sk,
            &crypto_obj,
        )
        .map_err(|e| format!("Failed to save identity keys: {e}"))?;

    // Download the vault chunk from the server.  Try the canonical name first,
    // then fall back to an ORAM-style vault-data-* chunk from the manifest.
    let vault = if let Some(v) =
        try_download_chunk(&crypto_obj, &client, &token, VAULT_MAIN_CHUNK_ID).await
    {
        v
    } else {
        tracing::info!(
            "No '{}' chunk found, trying vault-data-* fallback from manifest",
            VAULT_MAIN_CHUNK_ID
        );
        try_download_fallback_chunk(&crypto_obj, &client, &token)
            .await
            .unwrap_or_else(|| {
                tracing::info!("No vault chunk found on server, starting empty");
                crate::vault::VaultStore::new()
            })
    };

    state
        .store
        .save_vault(&vault, &crypto_obj)
        .map_err(|e| format!("Failed to save vault locally: {e}"))?;
    state
        .store
        .save_device_id_with_user_id(&payload.device_id, &user_id)
        .map_err(|e| format!("Failed to save user ID: {e}"))?;

    // ── unlock session ────────────────────────────────────────────────────────
    {
        let mut session = state.session.write();
        session.set_server_token(token);
        session.unlock(payload.device_id.clone(), user_id, 15 * 60);
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
    tracing::info!(device_id = %payload.device_id, "Enrollment import complete");
    Ok(())
}

#[tauri::command]
pub async fn revoke_device(
    state: State<'_, Arc<AppState>>,
    request: RevokeRequest,
) -> Result<(), String> {
    if !request.confirm {
        return Err("Revocation must be confirmed".to_string());
    }

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state.get_session_token().ok_or("Not authenticated")?;

    let new_tok = client
        .revoke_device(&token, &request.device_id)
        .await
        .map_err(|e| format!("Failed to revoke device: {}", e))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }

    let this_device_id = state.store.load_device_id().unwrap_or_default();
    record_audit_event(
        &state,
        AuditAction::DeviceRevoked {
            device_id: request.device_id.clone(),
            revoking_device_id: this_device_id,
        },
    );

    Ok(())
}
