//! Toolkit-agnostic core of `src-tauri/src/commands/devices.rs`. Read path
//! (`get_devices`) plus `revoke_device` and `generate_enrollment_code`/
//! `enrollment_verification_code`, all real.

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine as _,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::{ApiClient, EnrollDeviceRequest, NewDevicePayload};
use crate::audit::{record_audit_event, AuditAction};
use crate::crypto;
use crate::AppState;
use vela_crypto::aead::encrypt;

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

/// Real, read-only fetch of the account's enrolled devices from the server.
pub async fn get_devices(state: &AppState) -> Result<Vec<Device>, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state.get_session_token().ok_or("Not authenticated")?;

    let this_device_id = state.store.load_device_id().unwrap_or_default();

    let (resp, new_tok) = client
        .get_devices_raw(&token)
        .await
        .map_err(|e| format!("Failed to fetch devices: {e}"))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }

    let list: ServerDeviceListResponse =
        serde_json::from_str(&resp).map_err(|e| format!("Failed to parse device list: {e}"))?;

    let devices: Vec<Device> = list
        .devices
        .into_iter()
        .map(|d| {
            let enrolled_at = chrono::DateTime::parse_from_rfc3339(&d.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Device {
                id: d.id.clone(),
                name: if d.id == this_device_id { format!("{} (This Device)", d.name) } else { d.name },
                device_type: if d.device_type == "mobile" { DeviceType::Mobile } else { DeviceType::Desktop },
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

/// Revokes a device's server-side access for real. Refuses to revoke the
/// *current* device from itself (matches the original — that path should go
/// through "Reset vault" instead, since revoking your own only-active
/// session here would sign you out with no way to confirm it worked).
pub async fn revoke_device(state: &AppState, device_id: &str) -> Result<(), String> {
    let this_device_id = state.store.load_device_id().unwrap_or_default();
    if !this_device_id.is_empty() && device_id == this_device_id {
        return Err(
            "Cannot revoke this device from itself. Use \"Reset vault\" on this device instead."
                .to_string(),
        );
    }

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state.get_session_token().ok_or("Not authenticated")?;

    let new_tok = client
        .revoke_device(&token, device_id)
        .await
        .map_err(|e| format!("Failed to revoke device: {e}"))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }

    record_audit_event(
        state,
        AuditAction::DeviceRevoked {
            device_id: device_id.to_string(),
            revoking_device_id: this_device_id,
        },
    );

    Ok(())
}

/// Payload embedded in the enrollment invitation code (base64-encoded JSON).
#[derive(Debug, Serialize, Deserialize)]
struct EnrollmentCodePayload {
    device_id: String,
    hybrid_ek: String,    // base64
    hybrid_vk: String,    // base64
    hybrid_sk: String,    // base64 (signing key — keep this secret!)
    transfer_key: String, // base64, 32 B — decrypts rms_capsule on server
    server_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EnrollmentPackageLocator {
    v: u8,
    u: String,
    t: String,
    k: String,
}

const ENROLLMENT_CODE_V2_PREFIX: &str = "VELA-ENROLL:v2:";

/// Generate an enrollment invitation code that a second device can import.
/// Real cryptographic ceremony against the real account: generates a fresh
/// keypair for the new device, seals the RMS for transfer, signs the
/// enrollment with this device's own signing key, authenticates to the
/// server via a signed challenge, and registers the pending device. The
/// returned code is a compact locator (not the sensitive payload itself,
/// which is uploaded encrypted and fetched by the new device during import).
pub async fn generate_enrollment_code(state: &AppState) -> Result<String, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked. Please unlock before enrolling a new device.".to_string());
    }

    let rms: [u8; 32] = {
        let crypto_guard = state.crypto.read();
        let c = crypto_guard.as_ref().ok_or("Vault is locked")?;
        c.rms_as_bytes()
    };
    let crypto_for_keys = crypto::Crypto::new(&rms);

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

    let own_device_id = state.store.load_device_id().map_err(|e| format!("Failed to load device ID: {e}"))?;

    // ML-DSA keygen is stack-heavy; spawn on a blocking thread with enough stack.
    let new_identity = tokio::task::spawn_blocking(crypto::generate_identity_keypair)
        .await
        .map_err(|e| format!("Thread join error: {e}"))?
        .map_err(|e| format!("Keypair generation failed: {e}"))?;

    let mut transfer_key = [0u8; 32];
    getrandom::getrandom(&mut transfer_key).map_err(|e| format!("OS random source unavailable: {e}"))?;

    let rms_capsule =
        crypto::create_rms_capsule(&transfer_key, &rms).map_err(|e| format!("Failed to create RMS capsule: {e}"))?;

    // Spawn on blocking thread — ML-DSA signing is compute-heavy.
    let sk_bytes = own_keys.hybrid_sk.clone();
    let new_hybrid_ek = new_identity.hybrid_ek.clone();
    let new_hybrid_vk = new_identity.hybrid_vk.clone();
    let new_rms_capsule = rms_capsule.clone();
    let signature = tokio::task::spawn_blocking(move || {
        crypto::sign_enrollment(&sk_bytes, &new_hybrid_ek, &new_hybrid_vk, &new_rms_capsule)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("Signing failed: {e}"))?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url.clone());

    let challenge_resp = client.get_challenge().await.map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes =
        B64.decode(&challenge_resp.challenge).map_err(|_| "Invalid challenge encoding from server")?;

    let auth_sk = own_keys.hybrid_sk.clone();
    let dev_id_clone = own_device_id.clone();
    let auth_signature = tokio::task::spawn_blocking(move || {
        crypto::create_auth_signature(&auth_sk, &challenge_bytes, &dev_id_clone)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("Challenge signature failed: {e}"))?;

    let enroll_req = EnrollDeviceRequest {
        enrolling_device_id: own_device_id.clone(),
        challenge: challenge_resp.challenge,
        auth_signature,
        new_device: NewDevicePayload {
            hybrid_ek: B64.encode(&new_identity.hybrid_ek),
            hybrid_vk: B64.encode(&new_identity.hybrid_vk),
            rms_capsule: B64.encode(&rms_capsule),
            signature: B64.encode(&signature),
            device_name: Some("Pending Desktop Enrollment".to_string()),
            device_type: Some("desktop".to_string()),
        },
    };

    let enroll_resp = client.enroll_device(&enroll_req).await.map_err(|e| format!("Enrollment failed: {e}"))?;

    tracing::info!(
        new_device_id = %enroll_resp.device_id,
        enrolled_by   = %own_device_id,
        "New device enrolled"
    );

    record_audit_event(
        state,
        AuditAction::DeviceEnrolled {
            device_id: enroll_resp.device_id.clone(),
            enrolling_device_id: Some(own_device_id.clone()),
        },
    );

    let payload = EnrollmentCodePayload {
        device_id: enroll_resp.device_id,
        hybrid_ek: B64.encode(&new_identity.hybrid_ek),
        hybrid_vk: B64.encode(&new_identity.hybrid_vk),
        hybrid_sk: B64.encode(&new_identity.hybrid_sk),
        transfer_key: B64.encode(&transfer_key),
        server_url: server_url.clone(),
    };

    let json = serde_json::to_string(&payload).map_err(|e| format!("Serialization error: {e}"))?;

    let mut package_key = [0u8; 32];
    getrandom::getrandom(&mut package_key).map_err(|e| format!("OS random source unavailable: {e}"))?;
    let mut package_token = [0u8; 32];
    getrandom::getrandom(&mut package_token).map_err(|e| format!("OS random source unavailable: {e}"))?;

    let token = B64URL.encode(package_token);
    let ciphertext = encrypt(&package_key, json.as_bytes()).map_err(|e| format!("Failed to encrypt enrollment package: {e}"))?;
    client
        .store_enrollment_package(&token, &B64URL.encode(ciphertext))
        .await
        .map_err(|e| format!("Failed to store enrollment package: {e}"))?;

    let locator = EnrollmentPackageLocator { v: 2, u: server_url, t: token, k: B64URL.encode(package_key) };
    let locator_json = serde_json::to_string(&locator).map_err(|e| format!("Serialization error: {e}"))?;
    Ok(format!("{ENROLLMENT_CODE_V2_PREFIX}{}", B64URL.encode(locator_json.as_bytes())))
}

/// Compute the short out-of-band verification code for an enrollment code
/// string. The enrolling device displays this alongside the QR right after
/// generating the code; the importing device computes it again from the
/// scanned/pasted code and shows it for the user to confirm before import.
pub fn enrollment_verification_code(code: &str) -> String {
    vela_crypto::verification::enrollment_verification_code(code)
}

/// Matches the original's `createEnrollmentQrChunks` — splits an overlong
/// code into multiple QR-sized chunks, each self-describing its position so
/// the scanning side can reassemble them regardless of scan order.
pub fn create_enrollment_qr_chunks(code: &str) -> Vec<String> {
    const QR_CHUNK_SIZE: usize = 900;
    const QR_PREFIX: &str = "VELA-ENROLL";

    if code.len() <= QR_CHUNK_SIZE {
        return vec![code.to_string()];
    }

    let chunks: Vec<&str> = code.as_bytes().chunks(QR_CHUNK_SIZE).map(|b| std::str::from_utf8(b).unwrap_or("")).collect();
    let total = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| format!("{QR_PREFIX}:{}/{total}:{chunk}", i + 1))
        .collect()
}
