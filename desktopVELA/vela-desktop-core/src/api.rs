//! HTTP client for serverVELA API.

use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error as _;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiClient {
    h3_client: Option<Client>,
    fallback_client: Client,
    base_url: String,
    preferred_protocol: Arc<RwLock<Option<PreferredProtocol>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreferredProtocol {
    Http3,
    Fallback,
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
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_ek: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub device_id: String,
    pub challenge: String,
    pub signature: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

fn describe_request_error(err: &reqwest::Error) -> String {
    let mut message = err.to_string();

    if err.is_timeout() {
        message.push_str("; request timed out");
    }
    if err.is_connect() {
        message.push_str(
            "; connection failed. Check that the VELA server is running, bound to a LAN address such as 0.0.0.0:8443, and allowed through the firewall",
        );
    }

    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str("; caused by: ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }

    message
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

/// What `POST /device/enrollment-grant` returns. The grant id is the whole
/// payload of a v3 enrollment code — there is nothing else in it, which is the
/// point of the change (audit P-1).
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentGrant {
    pub grant_id: String,
    pub expires_in: u64,
}

/// The joining device's *public* halves, as the server stored them. These are
/// what the fingerprint is computed over and what will be enrolled.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentClaim {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        let fallback_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        let h3_client = if base_url.starts_with("https://") {
            match Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .http3_prior_knowledge()
                .build()
            {
                Ok(client) => Some(client),
                Err(error) => {
                    tracing::warn!(error = %error, "HTTP/3 client unavailable; using TCP fallback");
                    None
                }
            }
        } else {
            None
        };

        Self {
            h3_client,
            fallback_client,
            base_url: base_url.to_string(),
            preferred_protocol: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_url(base_url: String) -> Self {
        Self::new(&base_url)
    }

    async fn select_protocol(&self) -> PreferredProtocol {
        if !self.base_url.starts_with("https://") {
            return PreferredProtocol::Fallback;
        }
        let Some(h3_client) = self.h3_client.as_ref() else {
            return PreferredProtocol::Fallback;
        };
        if let Some(protocol) = *self.preferred_protocol.read() {
            return protocol;
        }

        let protocol = match h3_client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => PreferredProtocol::Http3,
            _ => PreferredProtocol::Fallback,
        };
        *self.preferred_protocol.write() = Some(protocol);
        protocol
    }

    async fn send_request<F>(&self, safe: bool, build: F) -> Result<reqwest::Response>
    where
        F: Fn(&Client) -> reqwest::RequestBuilder,
    {
        let protocol = self.select_protocol().await;
        let client = match protocol {
            PreferredProtocol::Http3 => self.h3_client.as_ref().unwrap_or(&self.fallback_client),
            PreferredProtocol::Fallback => &self.fallback_client,
        };

        match build(client).send().await {
            Ok(resp) => Ok(resp),
            Err(_err) if protocol == PreferredProtocol::Http3 && safe => {
                *self.preferred_protocol.write() = Some(PreferredProtocol::Fallback);
                build(&self.fallback_client)
                    .send()
                    .await
                    .map_err(Into::into)
            }
            Err(err) if protocol == PreferredProtocol::Http3 => {
                *self.preferred_protocol.write() = Some(PreferredProtocol::Fallback);
                Err(anyhow!(describe_request_error(&err)))
            }
            Err(err) => Err(anyhow!(describe_request_error(&err))),
        }
    }

    pub async fn health_check(&self) -> Result<bool> {
        let resp = self
            .send_request(true, |client| {
                client.get(format!("{}/health", self.base_url))
            })
            .await?;
        Ok(resp.status().is_success())
    }

    pub async fn get_challenge(&self) -> Result<ChallengeResponse> {
        let resp = self
            .send_request(true, |client| {
                client.get(format!("{}/auth/challenge", self.base_url))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Challenge request failed: {}", resp.status());
        }

        let challenge: ChallengeResponse = resp.json().await?;
        Ok(challenge)
    }

    pub async fn verify_signature(&self, request: &VerifyRequest) -> Result<VerifyResponse> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/auth/verify", self.base_url))
                    .json(request)
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            let detail = detail.trim();
            if detail.is_empty() {
                anyhow::bail!("Verify request failed: {status}");
            }
            anyhow::bail!("Verify request failed: {status} ({detail})");
        }

        let verify_resp: VerifyResponse = resp.json().await?;
        Ok(verify_resp)
    }

    pub async fn get_sync_manifest(&self, token: &str) -> Result<(SyncManifest, Option<String>)> {
        let resp = self
            .send_request(true, |client| {
                client
                    .get(format!("{}/vault/sync", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            let detail = detail.trim();
            if detail.is_empty() {
                anyhow::bail!("Sync manifest request failed: {status}");
            }
            anyhow::bail!("Sync manifest request failed: {status} ({detail})");
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
            .send_request(true, |client| {
                client
                    .get(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            let detail = detail.trim();
            if detail.is_empty() {
                anyhow::bail!("Chunk request failed: {status}");
            }
            anyhow::bail!("Chunk request failed: {status} ({detail})");
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
        self.put_chunk_with_epoch(token, chunk_id, version, ciphertext, lamport_clock, None)
            .await
    }

    /// Upload a chunk declaring the key epoch its ciphertext is sealed under
    /// (vault re-keying, docs/VAULT_REKEYING_DESIGN.md §5). `None` keeps the
    /// legacy no-header shape, which the server treats as the current epoch.
    pub async fn put_chunk_with_epoch(
        &self,
        token: &str,
        chunk_id: &str,
        version: i64,
        ciphertext: Vec<u8>,
        lamport_clock: i64,
        epoch: Option<i64>,
    ) -> Result<(i64, Option<String>)> {
        self.put_chunk_with_epoch_and_rotation(
            token,
            chunk_id,
            version,
            ciphertext,
            lamport_clock,
            epoch,
            None,
        )
        .await
    }

    /// Upload one shadow row for a specific re-key attempt. The attempt nonce
    /// prevents a delayed upload from an aborted rotation being accepted by a
    /// later rotation which happens to target the same epoch.
    pub async fn put_rekey_shadow(
        &self,
        token: &str,
        chunk_id: &str,
        ciphertext: Vec<u8>,
        lamport_clock: i64,
        epoch: i64,
        rotation_id: &str,
    ) -> Result<(i64, Option<String>)> {
        self.put_chunk_with_epoch_and_rotation(
            token,
            chunk_id,
            0,
            ciphertext,
            lamport_clock,
            Some(epoch),
            Some(rotation_id),
        )
        .await
    }

    async fn put_chunk_with_epoch_and_rotation(
        &self,
        token: &str,
        chunk_id: &str,
        version: i64,
        ciphertext: Vec<u8>,
        lamport_clock: i64,
        epoch: Option<i64>,
        rotation_id: Option<&str>,
    ) -> Result<(i64, Option<String>)> {
        let resp = self
            .send_request(false, |client| {
                let mut b = client
                    .put(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
                    .header("Authorization", format!("Bearer {}", token))
                    .header("If-Match", format!("{}", version))
                    .header("X-Lamport-Clock", format!("{}", lamport_clock));
                if let Some(e) = epoch {
                    b = b.header("X-Vela-Epoch", format!("{}", e));
                }
                if let Some(id) = rotation_id {
                    b = b.header("X-Vela-Rekey-Id", id);
                }
                b.body(ciphertext.clone())
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            anyhow::bail!("Chunk upload failed: {status}");
        }

        let new_token = extract_new_token(&resp);
        #[derive(Deserialize)]
        struct UploadResponse {
            version: i64,
        }
        let upload_resp: UploadResponse = resp.json().await?;
        Ok((upload_resp.version, new_token))
    }

    /// Current key epoch and rotation state (`"active"` | `"freezing"`).
    pub async fn get_key_epoch(&self, token: &str) -> Result<(i64, String, Option<String>)> {
        #[derive(Deserialize)]
        struct EpochResponse {
            epoch: i64,
            state: String,
        }
        let resp = self
            .send_request(true, |client| {
                client
                    .get(format!("{}/vault/epoch", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;
        // Rolling-upgrade compatibility: servers predating key epochs have no
        // endpoint and can only contain epoch-1 data. A client which has ever
        // adopted a later epoch still rejects this as a rollback in sync.rs.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok((1, "active".to_string(), None));
        }
        if !resp.status().is_success() {
            anyhow::bail!("epoch request failed: {}", resp.status());
        }
        let new_token = extract_new_token(&resp);
        let body: EpochResponse = resp.json().await?;
        Ok((body.epoch, body.state, new_token))
    }

    /// Begin a rotation: freeze the account and fetch the re-encryption work.
    pub async fn rekey_start(&self, token: &str) -> Result<(RekeyStart, Option<String>)> {
        #[derive(Deserialize)]
        struct RawChunk {
            chunk_id: String,
            version: i64,
            lamport_clock: i64,
        }
        #[derive(Deserialize)]
        struct StartResponse {
            epoch: i64,
            rotation_id: String,
            chunks: Vec<RawChunk>,
        }
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/vault/rekey/start", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("re-key start failed: {}", resp.status());
        }
        let new_token = extract_new_token(&resp);
        let body: StartResponse = resp.json().await?;
        Ok((
            RekeyStart {
                epoch: body.epoch,
                rotation_id: body.rotation_id,
                chunks: body
                    .chunks
                    .into_iter()
                    .map(|c| RekeyChunk {
                        chunk_id: c.chunk_id,
                        version: c.version,
                        lamport_clock: c.lamport_clock,
                    })
                    .collect(),
            },
            new_token,
        ))
    }

    /// Store the KEM-sealed new-seed capsules for every device.
    pub async fn rekey_store_capsules(
        &self,
        token: &str,
        rotation_id: &str,
        capsules: &std::collections::HashMap<String, String>,
    ) -> Result<Option<String>> {
        let body = serde_json::json!({ "capsules": capsules });
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/vault/rekey/capsules", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .header("X-Vela-Rekey-Id", rotation_id)
                    .header("Content-Type", "application/json")
                    .body(body.to_string())
            })
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            anyhow::bail!("capsule upload failed: {} ({})", status, detail.trim());
        }
        Ok(extract_new_token(&resp))
    }

    /// Commit the rotation (flip epoch, sweep superseded rows).
    ///
    /// `target_epoch` rides in `X-Vela-Epoch` so a retry after a lost
    /// response is unambiguous: the server answers success when the rotation
    /// already committed, instead of a 409 indistinguishable from failure.
    pub async fn rekey_commit(
        &self,
        token: &str,
        rotation_id: &str,
        target_epoch: i64,
    ) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/vault/rekey/commit", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .header("X-Vela-Rekey-Id", rotation_id)
                    .header("X-Vela-Epoch", target_epoch.to_string())
            })
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("re-key commit failed: {}", resp.status());
        }
        Ok(extract_new_token(&resp))
    }

    /// Abort an in-flight rotation and discard its shadow rows.
    pub async fn rekey_abort(&self, token: &str, rotation_id: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/vault/rekey/abort", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .header("X-Vela-Rekey-Id", rotation_id)
            })
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("re-key abort failed: {}", resp.status());
        }
        Ok(extract_new_token(&resp))
    }

    pub async fn delete_chunk_with_epoch(
        &self,
        token: &str,
        chunk_id: &str,
        version: i64,
        epoch: Option<i64>,
    ) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                let mut request = client
                    .delete(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
                    .header("Authorization", format!("Bearer {}", token))
                    .header("If-Match", format!("{}", version));
                if let Some(epoch) = epoch {
                    request = request.header("X-Vela-Epoch", epoch.to_string());
                }
                request
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Chunk delete failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    /// Attest that this device retained the private capsule key and has an
    /// implementation capable of adopting future RMS rotations.
    pub async fn mark_rekey_capable(&self, token: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/device/rekey-capable", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // Older servers neither rotate keys nor track this capability.
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("Re-key capability update failed: {}", resp.status());
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
            .send_request(true, |client| {
                client
                    .get(format!("{}/devices", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
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
            .send_request(false, |client| {
                client
                    .post(format!("{}/device/revoke", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({ "target_device_id": device_id }))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Device revocation failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn register_account(&self, request: &RegisterRequest) -> Result<RegisterResponse> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/account/register", self.base_url))
                    .json(request)
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account registration failed: {}", resp.status());
        }

        let result: RegisterResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn delete_account(&self, token: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .delete(format!("{}/account", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account deletion failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn logout(&self, token: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/auth/logout", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Logout failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn enroll_device(&self, request: &EnrollDeviceRequest) -> Result<EnrollResponse> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/device/enroll", self.base_url))
                    .json(request)
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Device enrollment failed: {} — {}", status, body);
        }

        let result: EnrollResponse = resp.json().await?;
        Ok(result)
    }

    pub async fn store_enrollment_package(&self, token: &str, ciphertext: &str) -> Result<()> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/device/enrollment-package", self.base_url))
                    .json(&serde_json::json!({
                        "token": token,
                        "ciphertext": ciphertext,
                    }))
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Store enrollment package failed: {} — {}", status, body);
        }

        Ok(())
    }

    pub async fn fetch_enrollment_package(&self, token: &str) -> Result<String> {
        // Send the real token via a header, not the URL: URLs commonly end up
        // in access/proxy/CDN logs by default, while custom headers typically
        // don't. The path keeps a placeholder for route compatibility — the
        // server prefers the header when present (see get_enrollment_package).
        let token = token.to_string();
        let resp = self
            .send_request(true, move |client| {
                client
                    .get(format!("{}/device/enrollment-package/_", self.base_url))
                    .header("X-Enrollment-Token", &token)
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Fetch enrollment package failed: {} — {}", status, body);
        }

        #[derive(Deserialize)]
        struct FetchEnrollmentPackageResponse {
            ciphertext: String,
        }

        let result: FetchEnrollmentPackageResponse = resp.json().await?;
        Ok(result.ciphertext)
    }

    // ── Enrollment v3 (audit P-1) ───────────────────────────────────────────
    //
    // The v2 pair above ships the joining device's private key inside a package
    // the code decrypts. These four carry public keys only; what the joining
    // device keeps never leaves it.

    /// Open a grant. Authenticated: the server binds it to this user *and* this
    /// device, and only this device can read the claim or complete.
    pub async fn open_enrollment_grant(
        &self,
        token: &str,
    ) -> Result<(EnrollmentGrant, Option<String>)> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/device/enrollment-grant", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({}))
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Open enrollment grant failed: {} — {}", status, body);
        }
        let new_token = extract_new_token(&resp);
        let grant: EnrollmentGrant = resp.json().await?;
        Ok((grant, new_token))
    }

    /// Present this device's *public* keys under a grant.
    ///
    /// Unauthenticated because the joining device has no identity yet — the
    /// grant id is what it presents instead. A grant admits exactly one claim,
    /// so losing this race is reported (409) rather than silently overwriting
    /// whoever claimed first.
    pub async fn claim_enrollment_grant(
        &self,
        grant_id: &str,
        hybrid_ek_b64: &str,
        hybrid_vk_b64: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "hybrid_ek": hybrid_ek_b64,
            "hybrid_vk": hybrid_vk_b64,
            "device_name": device_name,
            "device_type": device_type,
        });
        let url = format!("{}/device/enrollment-grant/{}/claim", self.base_url, grant_id);
        let resp = self
            .send_request(false, move |client| client.post(&url).json(&body))
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Claim enrollment grant failed: {} — {}", status, body);
        }
        Ok(())
    }

    /// Read the claim, to show the user a fingerprint of the key that will be
    /// enrolled. Returns `None` while no device has claimed yet.
    pub async fn get_enrollment_claim(
        &self,
        token: &str,
        grant_id: &str,
    ) -> Result<(Option<EnrollmentClaim>, Option<String>)> {
        let url = format!("{}/device/enrollment-grant/{}", self.base_url, grant_id);
        let token = token.to_string();
        let resp = self
            .send_request(true, move |client| {
                client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        // 404 covers both "nobody has claimed yet" and "not your grant". The
        // server deliberately does not distinguish them, and neither does this.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok((None, None));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Read enrollment claim failed: {} — {}", status, body);
        }
        let new_token = extract_new_token(&resp);
        let claim: EnrollmentClaim = resp.json().await?;
        Ok((Some(claim), new_token))
    }

    /// Enrol the claimed device.
    ///
    /// Deliberately carries no key material: the server enrols the keys it
    /// stored at claim time, so the fingerprint the user just confirmed and the
    /// key that gets enrolled are the same object. There is no argument here
    /// through which a different key could be named.
    pub async fn complete_enrollment(
        &self,
        token: &str,
        grant_id: &str,
        rms_capsule_b64: &str,
        signature_b64: &str,
    ) -> Result<(String, Option<String>)> {
        let body = serde_json::json!({
            "rms_capsule": rms_capsule_b64,
            "signature": signature_b64,
        });
        let url = format!(
            "{}/device/enrollment-grant/{}/complete",
            self.base_url, grant_id
        );
        let token = token.to_string();
        let resp = self
            .send_request(false, move |client| {
                client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&body)
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Complete enrollment failed: {} — {}", status, body);
        }

        #[derive(Deserialize)]
        struct CompleteResponse {
            device_id: String,
        }
        let new_token = extract_new_token(&resp);
        let done: CompleteResponse = resp.json().await?;
        Ok((done.device_id, new_token))
    }

    /// Ask which device this one became.
    ///
    /// The joining side calls this while the user compares fingerprints on the
    /// other screen. It carries no session — the `device_id` it returns is what
    /// a session would need — so the proof is `signature_b64`, made with the
    /// private half of the key this device claimed under. `Ok(None)` means the
    /// primary has not confirmed yet.
    pub async fn collect_enrollment_result(
        &self,
        grant_id: &str,
        signature_b64: &str,
    ) -> Result<Option<String>> {
        let body = serde_json::json!({ "signature": signature_b64 });
        let url = format!(
            "{}/device/enrollment-grant/{}/result",
            self.base_url, grant_id
        );
        let resp = self
            .send_request(true, move |client| client.post(&url).json(&body))
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Collect enrollment result failed: {} — {}", status, body);
        }

        #[derive(Deserialize)]
        #[serde(tag = "status", rename_all = "snake_case")]
        enum ResultResponse {
            Pending,
            Enrolled { device_id: String },
        }
        match resp.json::<ResultResponse>().await? {
            ResultResponse::Pending => Ok(None),
            ResultResponse::Enrolled { device_id } => Ok(Some(device_id)),
        }
    }

    pub async fn get_capsule(&self, token: &str) -> Result<(CapsuleResponse, Option<String>)> {
        let resp = self
            .send_request(true, |client| {
                client
                    .get(format!("{}/device/capsule", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Capsule request failed: {}", resp.status());
        }

        let new_token = extract_new_token(&resp);
        let result: CapsuleResponse = resp.json().await?;
        Ok((result, new_token))
    }

    pub async fn acknowledge_rekey_capsule(
        &self,
        token: &str,
        epoch: i64,
    ) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/device/capsule/ack", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({ "epoch": epoch }))
            })
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("Capsule acknowledgement failed: {}", resp.status());
        }
        Ok(extract_new_token(&resp))
    }

    pub async fn get_inbox(&self, token: &str) -> Result<(Vec<InboxItem>, Option<String>)> {
        let resp = self
            .send_request(true, |client| {
                client
                    .get(format!("{}/share/inbox", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
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
            .send_request(false, |client| {
                client
                    .post(format!("{}/share/send", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({
                        "recipient_user_id": recipient_user_id,
                        "capsule": capsule,
                    }))
            })
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
            .send_request(false, |client| {
                client
                    .delete(format!("{}/share/inbox/{}", self.base_url, item_id))
                    .header("Authorization", format!("Bearer {}", token))
            })
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
            .send_request(true, |client| {
                client
                    .get(format!("{}/share/linked", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
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
            .send_request(false, |client| {
                client
                    .put(format!("{}/share/linked/{}", self.base_url, share_id))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({ "capsule": capsule }))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Update linked share failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn get_recipient_share_ek(&self, token: &str, user_id: &str) -> Result<String> {
        let resp = self
            .send_request(false, |client| {
                client
                    .get(format!(
                        "{}/share/recipient/{}/ek",
                        self.base_url, user_id
                    ))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Get recipient share key failed: {}", resp.status());
        }

        #[derive(serde::Deserialize)]
        struct EkResponse {
            share_ek: String,
        }
        let result: EkResponse = resp.json().await?;
        Ok(result.share_ek)
    }

    /// Look up a pending web session's ephemeral public keys (the QR carries only
    /// the session id). Returns `(ephemeral_pk_b64, web_vk_b64)`; `web_vk` is empty
    /// for read-only-only sessions.
    pub async fn get_web_session_keys(
        &self,
        token: &str,
        session_id: &str,
    ) -> Result<(String, String)> {
        let resp = self
            .send_request(false, |client| {
                client
                    .get(format!("{}/web-session/{}/keys", self.base_url, session_id))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Fetch web session keys failed: {}", resp.status());
        }

        #[derive(serde::Deserialize)]
        struct Keys {
            ephemeral_pk: String,
            web_vk: String,
        }
        let k: Keys = resp.json().await?;
        Ok((k.ephemeral_pk, k.web_vk))
    }

    /// Approve an ephemeral web session: deliver the sealed capsule (RO snapshot
    /// or RW RMS) with the chosen mode and TTL. `link_nonce` is echoed back from
    /// the link code so the server can bind the grant to the browser that started
    /// the session. Returns the server-clamped expiry.
    pub async fn grant_web_session(
        &self,
        token: &str,
        session_id: &str,
        mode: &str,
        capsule_b64: &str,
        ttl_secs: i64,
        link_nonce: &str,
        key_epoch: i64,
    ) -> Result<String> {
        #[derive(Serialize)]
        struct GrantBody<'a> {
            mode: &'a str,
            capsule: &'a str,
            ttl_secs: i64,
            link_nonce: &'a str,
            key_epoch: i64,
        }
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/web-session/{}/grant", self.base_url, session_id))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&GrantBody {
                        mode,
                        capsule: capsule_b64,
                        ttl_secs,
                        link_nonce,
                        key_epoch,
                    })
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Grant web session failed: {} — {}", status, body);
        }

        #[derive(serde::Deserialize)]
        struct GrantResp {
            expires_at: String,
        }
        let r: GrantResp = resp.json().await?;
        Ok(r.expires_at)
    }

    /// List the caller's active (granted, not-yet-expired) web sessions.
    pub async fn list_web_sessions(&self, token: &str) -> Result<Vec<WebSessionInfo>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .get(format!("{}/web-sessions", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("List web sessions failed: {}", resp.status());
        }

        #[derive(serde::Deserialize)]
        struct ListResp {
            sessions: Vec<WebSessionInfo>,
        }
        let r: ListResp = resp.json().await?;
        Ok(r.sessions)
    }

    /// Revoke an active web session.
    pub async fn revoke_web_session(&self, token: &str, session_id: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .delete(format!("{}/web-session/{}", self.base_url, session_id))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Revoke web session failed: {}", resp.status());
        }
        let new_token = resp
            .headers()
            .get("x-new-token")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        Ok(new_token)
    }

    /// Register (or update) the caller's own share encapsulation key. Backfill
    /// path for accounts created before share keys existed.
    pub async fn put_my_share_ek(&self, token: &str, share_ek: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .put(format!("{}/share/my-ek", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({ "share_ek": share_ek }))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Register share key failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn delete_linked_share(&self, token: &str, share_id: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .delete(format!("{}/share/linked/{}", self.base_url, share_id))
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Delete linked share failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    /// Fetches the server's configured WebAuthn relying-party id/origin —
    /// needed so a native ceremony (no browser "page origin" to derive this
    /// from) can build a `clientDataJSON` this server's `webauthn-rs`
    /// verifier will accept. No auth required (matches `/health`) — neither
    /// value is a secret. See `vela_desktop_core::webauthn` module doc.
    pub async fn get_webauthn_config(&self) -> Result<WebauthnConfigResponse> {
        let resp = self
            .send_request(true, |client| {
                client.get(format!("{}/recovery/webauthn/config", self.base_url))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Failed to fetch WebAuthn config: {}", resp.status());
        }

        Ok(resp.json().await?)
    }

    pub async fn start_recovery_webauthn_registration(
        &self,
        token: &str,
        user_name: Option<&str>,
        user_display_name: Option<&str>,
    ) -> Result<(WebAuthnRegisterStartResponse, Option<String>)> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!(
                        "{}/recovery/webauthn/register/start",
                        self.base_url
                    ))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({
                        "user_name": user_name,
                        "user_display_name": user_display_name,
                    }))
            })
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
            .send_request(false, |client| {
                client
                    .post(format!(
                        "{}/recovery/webauthn/register/finish",
                        self.base_url
                    ))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&credential)
            })
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
            .send_request(false, |client| {
                client
                    .post(format!("{}/recovery/initiate", self.base_url))
                    .json(&serde_json::json!({ "user_id": user_id }))
            })
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
            .send_request(false, |client| {
                client
                    .post(format!("{}/recovery/recover", self.base_url))
                    .json(request)
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Account recovery failed: {}", resp.status());
        }

        let result: RecoveryRecoverResponse = resp.json().await?;
        Ok(result)
    }

    /// Registers a new device's identity key against an existing account
    /// (SPEC.md §4.3) once its RMS has been reconstructed client-side from
    /// Share 1 + Share 2. Authorization comes from the single-use
    /// `recovery_grant` returned by `recover_account`, not an enrolling
    /// device's signature — there is no other enrolled device to provide one.
    pub async fn enroll_device_via_recovery(
        &self,
        request: &EnrollDeviceViaRecoveryRequest,
    ) -> Result<EnrollDeviceViaRecoveryResponse> {
        let resp = self
            .send_request(false, |client| {
                client
                    .post(format!("{}/recovery/enroll-device", self.base_url))
                    .json(request)
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Recovery device enrollment failed: {} — {}", status, body);
        }

        let result: EnrollDeviceViaRecoveryResponse = resp.json().await?;
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
            .send_request(true, |client| {
                client
                    .get(format!(
                        "{}/vault/oram/{}/path/{}?height={}",
                        self.base_url, tree_id, leaf, height
                    ))
                    .header("Authorization", format!("Bearer {}", token))
            })
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
            .send_request(false, |client| {
                client
                    .put(format!(
                        "{}/vault/oram/{}/path/{}",
                        self.base_url, tree_id, leaf
                    ))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(request)
            })
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
            .send_request(true, |client| {
                client
                    .get(format!("{}/recovery/share", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
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
            .send_request(false, |client| {
                client
                    .put(format!("{}/recovery/share", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({ "share": share.share }))
            })
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Put recovery share failed: {}", resp.status());
        }

        Ok(extract_new_token(&resp))
    }

    pub async fn delete_recovery_share(&self, token: &str) -> Result<Option<String>> {
        let resp = self
            .send_request(false, |client| {
                client
                    .delete(format!("{}/recovery/share", self.base_url))
                    .header("Authorization", format!("Bearer {}", token))
            })
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
    /// Base64 KEM public key; target for re-keying capsules. Present when the
    /// server exposes it (all current servers do); `None` tolerated so the
    /// client keeps working against an older deployment.
    #[serde(default)]
    pub hybrid_ek: Option<String>,
    #[serde(default)]
    pub rekey_capable: bool,
}

/// The rotation work order returned by `POST /vault/rekey/start`.
#[derive(Debug, Clone)]
pub struct RekeyStart {
    pub epoch: i64,
    pub rotation_id: String,
    pub chunks: Vec<RekeyChunk>,
}

#[derive(Debug, Clone)]
pub struct RekeyChunk {
    pub chunk_id: String,
    pub version: i64,
    pub lamport_clock: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSessionInfo {
    pub id: String,
    pub mode: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// Request body for `POST /device/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollDeviceRequest {
    pub enrolling_device_id: String,
    pub challenge: String,
    pub auth_signature: String,
    pub new_device: NewDevicePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDevicePayload {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub rms_capsule: String,
    pub signature: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleResponse {
    pub capsule: String,
    #[serde(default)]
    pub epoch: Option<i64>,
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
    #[serde(default)]
    pub recovery_id: Option<String>,
    pub public_key: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecoverRequest {
    pub user_id: String,
    #[serde(default)]
    pub recovery_id: Option<String>,
    pub credential: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecoverResponse {
    pub share: String,
    pub recovery_grant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollDeviceViaRecoveryRequest {
    pub user_id: String,
    pub recovery_grant: String,
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollDeviceViaRecoveryResponse {
    pub device_id: String,
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
pub struct WebauthnConfigResponse {
    pub rp_id: String,
    pub rp_origin: String,
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
    /// Epoch under whose RMS-derived ORAM key the buckets were sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn health_check_reflects_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        assert!(client.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn health_check_false_on_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        assert!(!client.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn get_challenge_parses_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "Y2hhbGxlbmdlLWJ5dGVz"
            })))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let challenge = client.get_challenge().await.unwrap();
        assert_eq!(challenge.challenge, "Y2hhbGxlbmdlLWJ5dGVz");
    }

    #[tokio::test]
    async fn get_challenge_errors_on_failure_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/challenge"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let err = client.get_challenge().await.unwrap_err().to_string();
        assert!(err.contains("Challenge request failed"), "{err}");
    }

    #[tokio::test]
    async fn verify_signature_roundtrip() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "srv-token",
                "user_id": "user-42"
            })))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let resp = client
            .verify_signature(&VerifyRequest {
                device_id: "dev".into(),
                challenge: "ch".into(),
                signature: "sig".into(),
                device_name: None,
                device_type: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.token, "srv-token");
        assert_eq!(resp.user_id, "user-42");
    }

    #[tokio::test]
    async fn sync_manifest_sends_bearer_and_captures_rotated_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vault/sync"))
            .and(header("Authorization", "Bearer old-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-New-Token", "rotated-token")
                    .set_body_json(serde_json::json!({
                        "chunks": [{
                            "chunk_id": "vault-main",
                            "version": 7,
                            "lamport_clock": 42,
                            "last_writer": "dev-1"
                        }]
                    })),
            )
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let (manifest, new_token) = client.get_sync_manifest("old-token").await.unwrap();
        assert_eq!(new_token.as_deref(), Some("rotated-token"));
        assert_eq!(manifest.chunks.len(), 1);
        assert_eq!(manifest.chunks[0].chunk_id, "vault-main");
        assert_eq!(manifest.chunks[0].lamport_clock, 42);
    }

    #[tokio::test]
    async fn sync_manifest_without_rotation_returns_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vault/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "chunks": [] })))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let (_manifest, new_token) = client.get_sync_manifest("t").await.unwrap();
        assert!(new_token.is_none());
    }

    #[tokio::test]
    async fn get_chunk_reads_version_headers_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vault/chunk/vault-main"))
            .and(header("Authorization", "Bearer t"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Chunk-Version", "12")
                    .insert_header("X-Lamport-Clock", "99")
                    .set_body_bytes(vec![1u8, 2, 3, 4]),
            )
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let (ciphertext, version, lamport, _new_token) =
            client.get_chunk("t", "vault-main").await.unwrap();
        assert_eq!(ciphertext, vec![1u8, 2, 3, 4]);
        assert_eq!(version, 12);
        assert_eq!(lamport, 99);
    }

    #[tokio::test]
    async fn put_chunk_sends_concurrency_headers() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/vault/chunk/c1"))
            .and(header("If-Match", "5"))
            .and(header("X-Lamport-Clock", "77"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "version": 6 })))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let (version, _token) = client.put_chunk("t", "c1", 5, vec![9u8; 4], 77).await.unwrap();
        assert_eq!(version, 6);
    }

    #[tokio::test]
    async fn shadow_chunk_upload_declares_epoch_and_create_semantics() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/vault/chunk/c1"))
            .and(header("If-Match", "0"))
            .and(header("X-Vela-Epoch", "2"))
            .and(header("X-Vela-Rekey-Id", "attempt-2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "version": 1 })),
            )
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let (version, _) = client
            .put_rekey_shadow("t", "c1", vec![9u8; 4], 77, 2, "attempt-2")
            .await
            .unwrap();
        assert_eq!(version, 1);
    }

    #[tokio::test]
    async fn chunk_delete_declares_the_ciphertext_epoch() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/vault/chunk/c1"))
            .and(header("If-Match", "4"))
            .and(header("X-Vela-Epoch", "3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "deleted": true, "version": 4 }),
            ))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        client
            .delete_chunk_with_epoch("t", "c1", 4, Some(3))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_epoch_endpoint_is_treated_as_legacy_epoch_one() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vault/epoch"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let (epoch, state, refreshed) = client.get_key_epoch("t").await.unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(state, "active");
        assert!(refreshed.is_none());
    }

    #[tokio::test]
    async fn conflict_status_surfaces_as_error() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/vault/chunk/c1"))
            .respond_with(ResponseTemplate::new(412))
            .mount(&server)
            .await;
        let client = ApiClient::new(&server.uri());
        let err = client.put_chunk("t", "c1", 5, vec![9u8; 4], 77).await.unwrap_err().to_string();
        assert!(err.contains("Chunk upload failed"), "{err}");
    }

    #[tokio::test]
    async fn http_base_url_uses_fallback_client() {
        // A plain http:// URL never gets an HTTP/3 client — nothing to probe.
        let client = ApiClient::new("http://127.0.0.1:1");
        assert!(client.h3_client.is_none());
        assert_eq!(client.select_protocol().await, PreferredProtocol::Fallback);
    }
}
