//! HTTP client for serverVELA API.

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct ApiClient {
    client: Client,
    base_url: String,
}

/// Extract the rotated token from `X-New-Token` response header, if present.
fn extract_new_token(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("X-New-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
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
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub device_id: String,
    pub challenge: String,
    pub committed_hash: String,
    pub proof: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
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
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    pub async fn get_challenge(&self) -> Result<ChallengeResponse> {
        let resp = self
            .client
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
        let resp = self
            .client
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

    pub async fn get_sync_manifest(&self, token: &str) -> Result<(SyncManifest, Option<String>)> {
        let resp = self
            .client
            .get(format!("{}/vault/sync", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Sync manifest request failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let manifest: SyncManifest = resp.json().await?;
        Ok((manifest, new_token))
    }

    pub async fn get_chunk(
        &self,
        token: &str,
        chunk_id: &str,
    ) -> Result<(Vec<u8>, i64, i64, Option<String>)> {
        let resp = self
            .client
            .get(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Chunk request failed: {}", resp.status());
        }

        let version: i64 = resp
            .headers()
            .get("X-Chunk-Version")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let lamport_clock: i64 = resp
            .headers()
            .get("X-Lamport-Clock")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let new_token = extract_new_token(&resp);
        let ciphertext = resp.bytes().await?.to_vec();
        Ok((ciphertext, version, lamport_clock, new_token))
    }

    pub async fn put_chunk(
        &self,
        token: &str,
        chunk_id: &str,
        version: i64,
        ciphertext: Vec<u8>,
        lamport_clock: i64,
    ) -> Result<(i64, Option<String>)> {
        let resp = self
            .client
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

        let new_token = extract_new_token(&resp);
        #[derive(Deserialize)]
        struct UploadResponse {
            version: i64,
        }
        let upload_resp: UploadResponse = resp.json().await?;
        Ok((upload_resp.version, new_token))
    }

    pub async fn delete_chunk(
        &self,
        token: &str,
        chunk_id: &str,
        version: i64,
    ) -> Result<Option<String>> {
        let resp = self
            .client
            .delete(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
            .header("Authorization", format!("Bearer {}", token))
            .header("If-Match", format!("{}", version))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Chunk delete failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn get_devices(&self, token: &str) -> Result<(Vec<DeviceInfo>, Option<String>)> {
        let (body, new_token) = self.get_devices_raw(token).await?;
        #[derive(Deserialize)]
        struct DeviceListResponse {
            devices: Vec<DeviceInfo>,
        }
        let devices: DeviceListResponse = serde_json::from_str(&body)?;
        Ok((devices.devices, new_token))
    }

    pub async fn get_devices_raw(&self, token: &str) -> Result<(String, Option<String>)> {
        let resp = self
            .client
            .get(format!("{}/devices", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Device list request failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let body = resp.text().await?;
        Ok((body, new_token))
    }

    pub async fn revoke_device(&self, token: &str, device_id: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .post(format!("{}/device/revoke", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({ "target_device_id": device_id }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Device revocation failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn register_account(&self, request: &RegisterRequest) -> Result<RegisterResponse> {
        let resp = self
            .client
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

    pub async fn delete_account(&self, token: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .delete(format!("{}/account", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account deletion failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn logout(&self, token: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .post(format!("{}/auth/logout", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Logout failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn enroll_device(&self, request: &EnrollDeviceRequest) -> Result<EnrollResponse> {
        let resp = self
            .client
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

    pub async fn get_capsule(&self, token: &str) -> Result<(CapsuleResponse, Option<String>)> {
        let resp = self
            .client
            .get(format!("{}/device/capsule", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Capsule request failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let result: CapsuleResponse = resp.json().await?;
        Ok((result, new_token))
    }

    pub async fn get_inbox(&self, token: &str) -> Result<(Vec<InboxItem>, Option<String>)> {
        let resp = self
            .client
            .get(format!("{}/share/inbox", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Inbox request failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        #[derive(serde::Deserialize)]
        struct InboxResponse {
            items: Vec<InboxItem>,
        }
        let result: InboxResponse = resp.json().await?;
        Ok((result.items, new_token))
    }

    /// `capsule` must be base64-encoded ciphertext; `recipient_user_id` must be a UUID string.
    pub async fn send_share(
        &self,
        token: &str,
        recipient_user_id: &str,
        capsule: &str,
    ) -> Result<(ShareResponse, Option<String>)> {
        let resp = self
            .client
            .post(format!("{}/share/send", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "recipient_user_id": recipient_user_id,
                "capsule": capsule,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Share send failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let result: ShareResponse = resp.json().await?;
        Ok((result, new_token))
    }

    pub async fn delete_inbox_item(&self, token: &str, item_id: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .delete(format!("{}/share/inbox/{}", self.base_url, item_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Delete inbox item failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn get_linked_shares(
        &self,
        token: &str,
    ) -> Result<(Vec<LinkedShareItem>, Option<String>)> {
        let resp = self
            .client
            .get(format!("{}/share/linked", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Get linked shares failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        #[derive(serde::Deserialize)]
        struct LinkedSharesResponse {
            items: Vec<LinkedShareItem>,
        }
        let result: LinkedSharesResponse = resp.json().await?;
        Ok((result.items, new_token))
    }

    pub async fn update_linked_share(
        &self,
        token: &str,
        share_id: &str,
        capsule: &str,
    ) -> Result<Option<String>> {
        let resp = self
            .client
            .put(format!("{}/share/linked/{}", self.base_url, share_id))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({ "capsule": capsule }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Update linked share failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn delete_linked_share(&self, token: &str, share_id: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .delete(format!("{}/share/linked/{}", self.base_url, share_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Delete linked share failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn start_recovery_webauthn_registration(
        &self,
        token: &str,
        user_name: Option<&str>,
        user_display_name: Option<&str>,
    ) -> Result<(WebAuthnRegisterStartResponse, Option<String>)> {
        let resp = self
            .client
            .post(format!(
                "{}/recovery/webauthn/register/start",
                self.base_url
            ))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "user_name": user_name,
                "user_display_name": user_display_name,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "WebAuthn recovery registration start failed: {}",
                resp.status()
            );
        }

        let new_token = extract_new_token(&resp);
        let result: WebAuthnRegisterStartResponse = resp.json().await?;
        Ok((result, new_token))
    }

    pub async fn finish_recovery_webauthn_registration(
        &self,
        token: &str,
        credential: serde_json::Value,
    ) -> Result<(WebAuthnRegisterFinishResponse, Option<String>)> {
        let resp = self
            .client
            .post(format!(
                "{}/recovery/webauthn/register/finish",
                self.base_url
            ))
            .header("Authorization", format!("Bearer {}", token))
            .json(&credential)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "WebAuthn recovery registration finish failed: {}",
                resp.status()
            );
        }

        let new_token = extract_new_token(&resp);
        let result: WebAuthnRegisterFinishResponse = resp.json().await?;
        Ok((result, new_token))
    }

    pub async fn initiate_recovery(&self, user_id: &str) -> Result<RecoveryInitiateResponse> {
        let resp = self
            .client
            .post(format!("{}/recovery/initiate", self.base_url))
            .json(&serde_json::json!({ "user_id": user_id }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Recovery initiation failed: {}", resp.status());
        }

        let result: RecoveryInitiateResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn recover_account(
        &self,
        request: &RecoveryRecoverRequest,
    ) -> Result<RecoveryRecoverResponse> {
        let resp = self
            .client
            .post(format!("{}/recovery/recover", self.base_url))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account recovery failed: {}", resp.status());
        }

        let result: RecoveryRecoverResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn get_oram_path(
        &self,
        token: &str,
        tree_id: &str,
        leaf: u64,
        height: u32,
    ) -> Result<(OramPathResponse, Option<String>)> {
        let resp = self
            .client
            .get(format!(
                "{}/vault/oram/{}/path/{}?height={}",
                self.base_url, tree_id, leaf, height
            ))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Get ORAM path failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let path: OramPathResponse = resp.json().await?;
        Ok((path, new_token))
    }

    pub async fn put_oram_path(
        &self,
        token: &str,
        tree_id: &str,
        leaf: u64,
        request: &PutOramPathRequest,
    ) -> Result<(PutOramPathResponse, Option<String>)> {
        let resp = self
            .client
            .put(format!(
                "{}/vault/oram/{}/path/{}",
                self.base_url, tree_id, leaf
            ))
            .header("Authorization", format!("Bearer {}", token))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Put ORAM path failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let result: PutOramPathResponse = resp.json().await?;
        Ok((result, new_token))
    }

    pub async fn get_recovery_share(
        &self,
        token: &str,
    ) -> Result<(RecoveryShareResponse, Option<String>)> {
        let resp = self
            .client
            .get(format!("{}/recovery/share", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Get recovery share failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let result: RecoveryShareResponse = resp.json().await?;
        Ok((result, new_token))
    }

    pub async fn put_recovery_share(
        &self,
        token: &str,
        share: RecoveryShareData,
    ) -> Result<Option<String>> {
        let resp = self
            .client
            .put(format!("{}/recovery/share", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({ "share": share.share }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Put recovery share failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn delete_recovery_share(&self, token: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .delete(format!("{}/recovery/share", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Delete recovery share failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub created_at: String,
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
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleResponse {
    pub capsule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub id: String,
    pub sender_user_id: String,
    /// Base64-encoded encrypted capsule (the shared vault item).
    pub capsule: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResponse {
    pub inbox_id: String,
    pub share_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedShareItem {
    pub id: String,
    pub sender_user_id: String,
    pub recipient_user_id: String,
    pub capsule: String,
    pub created_at: String,
    pub updated_at: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryInitiateResponse {
    pub public_key: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecoverRequest {
    pub user_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecoverResponse {
    pub share: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShareResponse {
    pub share: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShareData {
    pub share: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegisterStartResponse {
    pub public_key: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegisterFinishResponse {
    pub registered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OramBucket {
    pub bucket_index: u64,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<String>,
    pub ciphertext: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OramPathResponse {
    pub tree_id: String,
    pub leaf: u64,
    pub height: u32,
    pub buckets: Vec<OramBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutOramPathRequest {
    pub height: u32,
    pub buckets: Vec<PutOramBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutOramBucket {
    pub bucket_index: u64,
    pub if_match: i64,
    pub lamport_clock: i64,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutOramPathResponse {
    pub buckets: Vec<PutOramBucketResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutOramBucketResponse {
    pub bucket_index: u64,
    pub version: i64,
}
