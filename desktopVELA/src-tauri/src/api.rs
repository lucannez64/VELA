//! HTTP client for serverVELA API.

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct ApiClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub cyclo_pk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub device_id: String,
    pub challenge: String,
    pub committed_hash: String,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub token: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkManifestEntry {
    pub chunk_id: String,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub chunks: Vec<ChunkManifestEntry>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            base_url: base_url.to_string(),
        }
    }

    pub fn with_url(base_url: String) -> Self {
        Self::new(&base_url)
    }

    pub async fn health_check(&self) -> Result<bool> {
        let resp = self.client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    pub async fn get_challenge(&self) -> Result<ChallengeResponse> {
        let resp = self.client
            .get(format!("{}/auth/challenge", self.base_url))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            anyhow::bail!("Challenge request failed: {}", resp.status());
        }
        
        let challenge: ChallengeResponse = resp.json().await?;
        Ok(challenge)
    }

    pub async fn verify_proof(&self, request: &VerifyRequest) -> Result<VerifyResponse> {
        let resp = self.client
            .post(format!("{}/auth/verify", self.base_url))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Verify request failed: {}", resp.status());
        }

        let verify_resp: VerifyResponse = resp.json().await?;
        Ok(verify_resp)
    }

    pub async fn get_sync_manifest(&self, token: &str) -> Result<SyncManifest> {
        let resp = self.client
            .get(format!("{}/vault/sync", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            anyhow::bail!("Sync manifest request failed: {}", resp.status());
        }
        
        let manifest: SyncManifest = resp.json().await?;
        Ok(manifest)
    }

    pub async fn get_chunk(&self, token: &str, chunk_id: &str) -> Result<(Vec<u8>, i64, i64)> {
        let resp = self.client
            .get(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Chunk request failed: {}", resp.status());
        }

        let version: i64 = resp.headers()
            .get("X-Chunk-Version")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let lamport_clock: i64 = resp.headers()
            .get("X-Lamport-Clock")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let ciphertext = resp.bytes().await?.to_vec();
        Ok((ciphertext, version, lamport_clock))
    }

    pub async fn put_chunk(
        &self,
        token: &str,
        chunk_id: &str,
        version: i64,
        ciphertext: Vec<u8>,
        lamport_clock: i64,
    ) -> Result<i64> {
        let resp = self.client
            .put(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
            .header("Authorization", format!("Bearer {}", token))
            .header("If-Match", format!("{}", version))
            .header("X-Lamport-Clock", format!("{}", lamport_clock))
            .body(ciphertext)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Chunk upload failed: {}", resp.status());
        }

        #[derive(Deserialize)]
        struct UploadResponse { version: i64 }
        let upload_resp: UploadResponse = resp.json().await?;
        Ok(upload_resp.version)
    }

    pub async fn get_devices(&self, token: &str) -> Result<Vec<DeviceInfo>> {
        let body = self.get_devices_raw(token).await?;
        let devices: Vec<DeviceInfo> = serde_json::from_str(&body)?;
        Ok(devices)
    }

    pub async fn get_devices_raw(&self, token: &str) -> Result<String> {
        let resp = self.client
            .get(format!("{}/devices", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            anyhow::bail!("Device list request failed: {}", resp.status());
        }
        
        let body = resp.text().await?;
        Ok(body)
    }

    pub async fn revoke_device(&self, token: &str, device_id: &str) -> Result<()> {
        let resp = self.client
            .post(format!("{}/device/revoke", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({ "device_id": device_id }))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            anyhow::bail!("Device revocation failed: {}", resp.status());
        }
        
        Ok(())
    }

    pub async fn register_account(&self, request: &RegisterRequest) -> Result<RegisterResponse> {
        let resp = self.client
            .post(format!("{}/account/register", self.base_url))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account registration failed: {}", resp.status());
        }

        let result: RegisterResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn delete_account(&self, token: &str) -> Result<()> {
        let resp = self.client
            .delete(format!("{}/account", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account deletion failed: {}", resp.status());
        }

        Ok(())
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        let resp = self.client
            .post(format!("{}/auth/logout", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Logout failed: {}", resp.status());
        }

        Ok(())
    }

    pub async fn enroll_device(&self, request: &EnrollDeviceRequest) -> Result<EnrollResponse> {
        let resp = self.client
            .post(format!("{}/device/enroll", self.base_url))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Device enrollment failed: {} — {}", status, body);
        }

        let result: EnrollResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn get_capsule(&self, token: &str) -> Result<CapsuleResponse> {
        let resp = self.client
            .get(format!("{}/device/capsule", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Capsule request failed: {}", resp.status());
        }

        let result: CapsuleResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn get_inbox(&self, token: &str) -> Result<Vec<InboxItem>> {
        let resp = self.client
            .get(format!("{}/share/inbox", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Inbox request failed: {}", resp.status());
        }

        let result: Vec<InboxItem> = resp.json().await?;
        Ok(result)
    }

    pub async fn send_share(&self, token: &str, item_id: &str, recipient: &str, allow_edit: bool, ciphertext: Vec<u8>) -> Result<ShareResponse> {
        let resp = self.client
            .post(format!("{}/share/send", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "item_id": item_id,
                "recipient": recipient,
                "allow_edit": allow_edit,
                "ciphertext": ciphertext,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Share send failed: {}", resp.status());
        }

        let result: ShareResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn delete_inbox_item(&self, token: &str, item_id: &str) -> Result<()> {
        let resp = self.client
            .delete(format!("{}/share/inbox/{}", self.base_url, item_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Delete inbox item failed: {}", resp.status());
        }

        Ok(())
    }

    pub async fn initiate_recovery(&self, email: &str) -> Result<RecoveryInitiateResponse> {
        let resp = self.client
            .post(format!("{}/recovery/initiate", self.base_url))
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Recovery initiation failed: {}", resp.status());
        }

        let result: RecoveryInitiateResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn recover_account(&self, request: &RecoveryRecoverRequest) -> Result<VerifyResponse> {
        let resp = self.client
            .post(format!("{}/recovery/recover", self.base_url))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account recovery failed: {}", resp.status());
        }

        let result: VerifyResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn get_recovery_share(&self, token: &str) -> Result<RecoveryShareResponse> {
        let resp = self.client
            .get(format!("{}/recovery/share", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Get recovery share failed: {}", resp.status());
        }

        let result: RecoveryShareResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn put_recovery_share(&self, token: &str, share: RecoveryShareData) -> Result<()> {
        let resp = self.client
            .put(format!("{}/recovery/share", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&share)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Put recovery share failed: {}", resp.status());
        }

        Ok(())
    }

    pub async fn delete_recovery_share(&self, token: &str) -> Result<()> {
        let resp = self.client
            .delete(format!("{}/recovery/share", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Delete recovery share failed: {}", resp.status());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub enrolled_at: String,
    pub last_active: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: String,
}

/// Request body for `POST /device/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollDeviceRequest {
    pub enrolling_device_id: String,
    pub challenge: String,
    pub committed_hash: String,
    pub proof: String,
    pub new_device: NewDevicePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDevicePayload {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub cyclo_pk: String,
    pub rms_capsule: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleResponse {
    pub capsule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub id: String,
    pub from: String,
    pub item_id: String,
    pub item_name: String,
    pub allow_edit: bool,
    pub encrypted_payload: Vec<u8>,
    pub shared_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResponse {
    pub share_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryInitiateResponse {
    pub recovery_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecoverRequest {
    pub recovery_id: String,
    pub device_id: String,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShareResponse {
    pub share: Option<RecoveryShareData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShareData {
    pub ciphertext: Vec<u8>,
    pub threshold: u8,
    pub participants: Vec<String>,
}
