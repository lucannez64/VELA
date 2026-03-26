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
pub struct VerifyRequest {
    pub device_id: String,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub token: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkManifestEntry {
    pub chunk_id: String,
    pub version: u64,
    pub lamport_clock: u64,
    pub last_writer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub chunks: Vec<ChunkManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkData {
    pub id: String,
    pub version: u64,
    pub lamport_clock: u64,
    pub last_writer: String,
    pub ciphertext: Vec<u8>,
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

    pub async fn get_chunk(&self, token: &str, chunk_id: &str) -> Result<ChunkData> {
        let resp = self.client
            .get(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            anyhow::bail!("Chunk request failed: {}", resp.status());
        }
        
        let chunk: ChunkData = resp.json().await?;
        Ok(chunk)
    }

    pub async fn put_chunk(
        &self,
        token: &str,
        chunk_id: &str,
        version: u64,
        ciphertext: Vec<u8>,
        lamport_clock: u64,
    ) -> Result<u64> {
        let resp = self.client
            .put(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
            .header("Authorization", format!("Bearer {}", token))
            .header("If-Match", format!("{}", version))
            .json(&serde_json::json!({
                "lamport_clock": lamport_clock,
                "ciphertext": ciphertext,
            }))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            anyhow::bail!("Chunk upload failed: {}", resp.status());
        }
        
        #[derive(Deserialize)]
        struct UploadResponse { version: u64 }
        let upload_resp: UploadResponse = resp.json().await?;
        Ok(upload_resp.version)
    }

    pub async fn get_devices(&self, token: &str) -> Result<Vec<DeviceInfo>> {
        let resp = self.client
            .get(format!("{}/device/list", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            anyhow::bail!("Device list request failed: {}", resp.status());
        }
        
        let devices: Vec<DeviceInfo> = resp.json().await?;
        Ok(devices)
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
