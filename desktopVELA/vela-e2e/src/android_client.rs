//! Headless stand-in for the Android client: replicates the sync algorithm of
//! `VaultSyncManager.kt` (merge / chunk split / lamport clock / stale-chunk
//! deletion) and the enrollment flow of `enrollWithCode`, using the *same*
//! crypto the real Android app runs via its JNI bridge (`libVELA`'s
//! `vela-crypto`, including the identical `"vela chunk key v1 || {:?}"`
//! derivation). The chunk layout and vault JSON are bit-compatible with what
//! the desktop core reads and writes, which is what makes the end-to-end
//! cross-client test meaningful.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use std::collections::HashMap;
use vela_core::vault::{Tombstone, VaultItem, VaultMeta, VaultStore};
use vela_crypto::aead;
use vela_crypto::signing;

const VAULT_CHUNK_PREFIX: &str = "vault-data-";
const LEGACY_VAULT_MAIN_CHUNK_ID: &str = "vault-main";
const VAULT_DATA_CHUNK_ID: &str = "vault-data-000000";
const VAULT_CHUNK_PLAINTEXT_SIZE: usize = 1024 * 1024 - 4096;
const ENROLLMENT_CODE_V2_PREFIX: &str = "VELA-ENROLL:v2:";

/// Server identity decrypted out of an enrollment code + package.
struct EnrolledIdentity {
    device_id: String,
    hybrid_sk_b64: String,
    transfer_key: [u8; 32],
    server_url: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SyncManifest {
    chunks: Vec<ManifestChunk>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ManifestChunk {
    chunk_id: String,
    version: i64,
    lamport_clock: i64,
    #[allow(dead_code)]
    last_writer: Option<String>,
}

/// Outcome of a sync run (mirrors Android's `SyncState` essentials).
#[derive(Debug, Clone)]
pub struct SyncOutcome {
    pub version: i64,
    pub lamport_clock: i64,
    pub last_synced_at: DateTime<Utc>,
    pub error: Option<String>,
}

pub struct AndroidClient {
    base_url: String,
    http: Client,
    device_id: String,
    user_id: String,
    token: String,
    rms: [u8; 32],
    vault: VaultStore,
    local_version: i64,
    local_lamport: i64,
}

fn chunk_key(rms: &[u8; 32], chunk_id: &str) -> [u8; 32] {
    let context = format!("{} || {:?}", "vela chunk key v1", chunk_id.as_bytes());
    *vela_crypto::kdf::derive(&context, rms).as_bytes()
}

fn vault_chunk_id(index: usize) -> String {
    format!("{VAULT_CHUNK_PREFIX}{index:06}")
}

/// `vela-core`'s `VaultItem` doesn't expose `updated_at()` (desktop's does);
/// extract it from the shared `meta` struct instead.
fn item_updated_at(item: &VaultItem) -> DateTime<Utc> {
    match item {
        VaultItem::Login { meta, .. }
        | VaultItem::CreditCard { meta, .. }
        | VaultItem::SecureNote { meta, .. }
        | VaultItem::Identity { meta, .. }
        | VaultItem::FileBlob { meta, .. }
        | VaultItem::BreachMonitor { meta, .. } => meta.updated_at,
    }
}

fn recognized_vault_chunk_ids(manifest: &SyncManifest) -> Vec<String> {
    let vault_chunk_ids: Vec<String> = manifest
        .chunks
        .iter()
        .map(|c| c.chunk_id.clone())
        .filter(|id| id.starts_with(VAULT_CHUNK_PREFIX))
        .collect();
    let mut sorted = vault_chunk_ids;
    sorted.sort();
    if !sorted.is_empty() {
        sorted
    } else if manifest.chunks.iter().any(|c| c.chunk_id == LEGACY_VAULT_MAIN_CHUNK_ID) {
        vec![LEGACY_VAULT_MAIN_CHUNK_ID.to_string()]
    } else {
        Vec::new()
    }
}

fn split_utf8_chunks(value: &str) -> Vec<String> {
    if value.is_empty() {
        return vec![String::new()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_bytes = 0usize;
    for ch in value.chars() {
        let ch_bytes = ch.len_utf8();
        if !current.is_empty() && current_bytes + ch_bytes > VAULT_CHUNK_PLAINTEXT_SIZE {
            chunks.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.push(ch);
        current_bytes += ch_bytes;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn merge_vault_stores(local: &VaultStore, remote: VaultStore) -> VaultStore {
    let tombstones = merge_tombstones(local.tombstones.iter().cloned().chain(remote.tombstones.iter().cloned()).collect());
    let tombstone_by_id: HashMap<String, Tombstone> = tombstones.iter().map(|t| (t.id.clone(), t.clone())).collect();

    let mut merged: HashMap<String, VaultItem> = HashMap::new();
    let apply = |item: VaultItem, tombstone_by_id: &HashMap<String, Tombstone>, merged: &mut HashMap<String, VaultItem>| {
        let id = item.id().to_string();
        if let Some(t) = tombstone_by_id.get(&id) {
            if t.deleted_at >= item_updated_at(&item) {
                merged.remove(&id);
                return;
            }
        }
        match merged.get(&id) {
            Some(existing) if item_updated_at(existing) > item_updated_at(&item) => {}
            _ => {
                merged.insert(id, item);
            }
        }
    };

    for item in local.items.iter().cloned() {
        apply(item, &tombstone_by_id, &mut merged);
    }
    for item in remote.items.into_iter() {
        apply(item, &tombstone_by_id, &mut merged);
    }

    let mut items: Vec<VaultItem> = merged.into_values().collect();
    items.sort_by_key(|a| a.name().to_lowercase());

    let mut out = VaultStore::new();
    for item in items {
        out.add_item(item);
    }
    out.tombstones = prune_tombstones(tombstones);
    out
}

fn merge_tombstones(values: Vec<Tombstone>) -> Vec<Tombstone> {
    let mut by_id: HashMap<String, Tombstone> = HashMap::new();
    for t in values {
        by_id
            .entry(t.id.clone())
            .and_modify(|existing| {
                if t.deleted_at > existing.deleted_at {
                    *existing = t.clone();
                }
            })
            .or_insert(t);
    }
    by_id.into_values().collect()
}

fn prune_tombstones(values: Vec<Tombstone>) -> Vec<Tombstone> {
    let cutoff = Utc::now() - Duration::days(30);
    values.into_iter().filter(|t| t.deleted_at >= cutoff).collect()
}

fn has_incomplete_cards(vault: &VaultStore) -> bool {
    vault.items.iter().any(|item| {
        matches!(item, VaultItem::CreditCard { meta: _, number, exp, .. } if number.is_empty() || exp.is_empty())
    })
}

struct RemoteVault {
    vault: VaultStore,
    version: i64,
    lamport_clock: i64,
}

struct UploadResult {
    version: i64,
    lamport_clock: i64,
}

impl AndroidClient {
    /// Parse a `VELA-ENROLL:v2:` code produced by the desktop's
    /// `generate_enrollment_code`, fetch + decrypt the enrollment package,
    /// authenticate the device, and recover the RMS from the server capsule.
    pub async fn enroll_with_code(code: &str) -> Result<Self, String> {
        let identity = decode_enrollment_code(code).await?;
        let base_url = identity.server_url.clone().unwrap_or_default();
        let base_url = if base_url.is_empty() { extract_locator_server_url(code)? } else { base_url };
        let base_url = base_url.trim_end_matches('/').to_string();

        let http = Client::new();
        let mut client = AndroidClient {
            base_url: base_url.clone(),
            http,
            device_id: String::new(),
            user_id: String::new(),
            token: String::new(),
            rms: [0u8; 32],
            vault: VaultStore::new(),
            local_version: 0,
            local_lamport: 0,
        };
        client.authenticate(&identity).await?;
        let rms = client.fetch_rms(identity.transfer_key).await?;
        client.rms = rms;
        Ok(client)
    }

    /// Authenticate an already-enrolled device (challenge + signature).
    async fn authenticate(&mut self, identity: &EnrolledIdentity) -> Result<(), String> {
        self.device_id = identity.device_id.clone();
        let challenge: serde_json::Value = self
            .http
            .get(format!("{}/auth/challenge", self.base_url))
            .send()
            .await
            .map_err(|e| format!("get challenge: {e}"))?
            .json()
            .await
            .map_err(|e| format!("parse challenge: {e}"))?;
        let challenge_b64 = challenge["challenge"].as_str().ok_or("challenge missing")?.to_string();
        let challenge_bytes = B64.decode(&challenge_b64).map_err(|e| format!("decode challenge: {e}"))?;

        let sk = signing::HybridSigningKey::from_bytes(
            &B64.decode(&identity.hybrid_sk_b64).map_err(|e| format!("decode signing key: {e}"))?,
        )
        .map_err(|e| format!("parse signing key: {e}"))?;
        let message = signing::auth_message(&self.device_id, &challenge_bytes);
        let signature = signing::sign(&sk, &message).map_err(|e| format!("sign challenge: {e}"))?;
        let signature_b64 = B64.encode(signature.to_bytes());

        let body = serde_json::json!({
            "device_id": self.device_id,
            "challenge": challenge_b64,
            "signature": signature_b64,
            "device_name": "Android E2E",
            "device_type": "android",
        });
        let verify: serde_json::Value = self
            .http
            .post(format!("{}/auth/verify", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("verify: {e}"))?
            .json()
            .await
            .map_err(|e| format!("parse verify: {e}"))?;
        self.token = verify["token"].as_str().ok_or("verify: no token")?.to_string();
        self.user_id = verify["user_id"].as_str().ok_or("verify: no user_id")?.to_string();
        Ok(())
    }

    async fn fetch_rms(&self, transfer_key: [u8; 32]) -> Result<[u8; 32], String> {
        let resp = self
            .http
            .get(format!("{}/device/capsule", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("get capsule: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("get capsule: {}", resp.status()));
        }
        let capsule: serde_json::Value = resp.json().await.map_err(|e| format!("parse capsule: {e}"))?;
        let capsule_b64 = capsule["capsule"].as_str().ok_or("capsule missing")?;
        let ciphertext = B64.decode(capsule_b64).map_err(|e| format!("decode capsule: {e}"))?;
        let plaintext = aead::decrypt(&transfer_key, &ciphertext).map_err(|e| format!("decrypt capsule: {e}"))?;
        let mut rms = [0u8; 32];
        if plaintext.len() < 32 {
            return Err("decrypted capsule too short".to_string());
        }
        rms.copy_from_slice(&plaintext[..32]);
        Ok(rms)
    }

    /// Full sync run, mirroring `VaultSyncManager.syncUnlocked`.
    pub async fn sync(&mut self) -> Result<SyncOutcome, String> {
        let manifest = self.fetch_manifest().await?;
        let download_ids = recognized_vault_chunk_ids(&manifest);
        let upload_chunk_id = VAULT_DATA_CHUNK_ID.to_string();
        let remote = manifest.chunks.iter().find(|c| c.chunk_id == upload_chunk_id).cloned();

        if download_ids.is_empty() && !manifest.chunks.is_empty() {
            return Err(
                "Server has no recognized vault data chunk. Cross-platform merge is not enabled yet; refusing to upload."
                    .to_string(),
            );
        }

        let local_snapshot = self.vault.clone();
        let local_empty_initial = self.local_version == 0 && local_snapshot.items.is_empty();

        if !download_ids.is_empty() && (local_empty_initial || has_incomplete_cards(&local_snapshot)) {
            let downloaded = self.download_remote_vault(&manifest, &download_ids).await?;
            self.vault = downloaded.vault;
            self.local_version = downloaded.version;
            self.local_lamport = downloaded.lamport_clock;
            return Ok(SyncOutcome {
                version: downloaded.version,
                lamport_clock: downloaded.lamport_clock,
                last_synced_at: Utc::now(),
                error: None,
            });
        }

        if let Some(remote) = &remote {
            if remote.version > self.local_version {
                let downloaded = self.download_remote_vault(&manifest, &download_ids).await?;
                self.vault = merge_vault_stores(&local_snapshot, downloaded.vault);
                let uploaded = self.upload_vault_chunks(&manifest, downloaded.lamport_clock).await?;
                self.local_version = uploaded.version;
                self.local_lamport = uploaded.lamport_clock;
                return Ok(SyncOutcome {
                    version: uploaded.version,
                    lamport_clock: uploaded.lamport_clock,
                    last_synced_at: Utc::now(),
                    error: None,
                });
            }
        }

        let uploaded = self.upload_vault_chunks(&manifest, self.local_lamport).await?;
        self.local_version = uploaded.version;
        self.local_lamport = uploaded.lamport_clock;
        Ok(SyncOutcome {
            version: uploaded.version,
            lamport_clock: uploaded.lamport_clock,
            last_synced_at: Utc::now(),
            error: None,
        })
    }

    async fn fetch_manifest(&self) -> Result<SyncManifest, String> {
        let resp = self
            .http
            .get(format!("{}/vault/sync", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("get manifest: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("get manifest: {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("parse manifest: {e}"))
    }

    async fn download_remote_vault(&self, manifest: &SyncManifest, chunk_ids: &[String]) -> Result<RemoteVault, String> {
        let mut json = String::new();
        let mut max_version = 0i64;
        let mut max_lamport = 0i64;
        for chunk_id in chunk_ids {
            let entry = manifest.chunks.iter().find(|c| c.chunk_id == *chunk_id);
            let resp = self
                .http
                .get(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|e| format!("get chunk {chunk_id}: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("get chunk {chunk_id}: {}", resp.status()));
            }
            let headers = resp.headers().clone();
            let ciphertext = resp.bytes().await.map_err(|e| format!("read chunk {chunk_id}: {e}"))?.to_vec();
            if let Some(entry) = entry {
                max_version = max_version.max(entry.version);
                max_lamport = max_lamport.max(entry.lamport_clock);
            }
            if let Some(h) = headers.get("x-lamport-clock").and_then(|v| v.to_str().ok()) {
                if let Ok(clock) = h.parse::<i64>() {
                    max_lamport = max_lamport.max(clock);
                }
            }
            let key = chunk_key(&self.rms, chunk_id);
            let plaintext = aead::decrypt(&key, &ciphertext).map_err(|e| format!("decrypt chunk {chunk_id}: {e}"))?;
            json.push_str(&String::from_utf8(plaintext.to_vec()).map_err(|e| format!("chunk {chunk_id} not utf8: {e}"))?);
        }
        let vault = serde_json::from_str::<VaultStore>(&json).map_err(|e| format!("parse vault: {e}"))?;
        Ok(RemoteVault { vault, version: max_version, lamport_clock: max_lamport })
    }

    async fn upload_vault_chunks(&self, manifest: &SyncManifest, base_lamport: i64) -> Result<UploadResult, String> {
        let plaintext = serde_json::to_string(&self.vault).map_err(|e| format!("serialize vault: {e}"))?;
        let chunks = split_utf8_chunks(&plaintext);
        let manifest_by_id: HashMap<String, ManifestChunk> =
            manifest.chunks.iter().map(|c| (c.chunk_id.clone(), c.clone())).collect();

        let mut lamport = base_lamport;
        let mut lamport_assignments = Vec::with_capacity(chunks.len());
        for (index, _) in chunks.iter().enumerate() {
            let chunk_id = vault_chunk_id(index);
            let previous = manifest_by_id.get(&chunk_id).map(|c| c.lamport_clock).unwrap_or(0);
            lamport = lamport.max(previous) + 1;
            lamport_assignments.push(lamport);
        }

        let mut first_version = 0i64;
        for (index, chunk) in chunks.iter().enumerate() {
            let chunk_id = vault_chunk_id(index);
            let chunk_lamport = lamport_assignments[index];
            let remote_version = manifest_by_id.get(&chunk_id).map(|c| c.version).unwrap_or(0);
            let key = chunk_key(&self.rms, &chunk_id);
            let ciphertext = aead::encrypt(&key, chunk.as_bytes()).map_err(|e| format!("encrypt chunk {chunk_id}: {e}"))?;
            let resp = self
                .http
                .put(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
                .bearer_auth(&self.token)
                .header("If-Match", remote_version.to_string())
                .header("X-Lamport-Clock", chunk_lamport.to_string())
                .body(ciphertext)
                .send()
                .await
                .map_err(|e| format!("put chunk {chunk_id}: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("put chunk {chunk_id}: {}", resp.status()));
            }
            #[derive(serde::Deserialize)]
            struct UploadResponse {
                version: i64,
            }
            let upload: UploadResponse = resp.json().await.map_err(|e| format!("parse upload {chunk_id}: {e}"))?;
            if index == 0 {
                first_version = upload.version;
            }
        }

        let stale_chunks: Vec<(String, i64)> = manifest
            .chunks
            .iter()
            .filter(|c| c.chunk_id.starts_with(VAULT_CHUNK_PREFIX))
            .filter_map(|c| {
                let idx = c.chunk_id.strip_prefix(VAULT_CHUNK_PREFIX)?.parse::<usize>().ok()?;
                if idx >= chunks.len() {
                    Some((c.chunk_id.clone(), c.version))
                } else {
                    None
                }
            })
            .collect();
        for (chunk_id, version) in stale_chunks {
            let resp = self
                .http
                .delete(format!("{}/vault/chunk/{}", self.base_url, chunk_id))
                .bearer_auth(&self.token)
                .header("If-Match", version.to_string())
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => eprintln!("android: stale chunk delete {chunk_id}: {}", r.status()),
                Err(e) => eprintln!("android: stale chunk delete {chunk_id}: {e}"),
            }
        }

        let final_lamport = lamport_assignments.last().copied().unwrap_or(base_lamport).max(base_lamport);
        Ok(UploadResult { version: first_version, lamport_clock: final_lamport })
    }

    // ── vault manipulation helpers (test-facing) ──

    pub fn add_login(&mut self, id: &str, name: &str, url: &str, username: &str, password: &str) {
        let meta = VaultMeta {
            id: id.to_string(),
            name: name.to_string(),
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_modified_device: Some(self.device_id.clone()),
            favorite: false,
            shared: false,
            share_recipient: None,
        };
        self.vault.add_item(VaultItem::Login {
            meta,
            url: url.to_string(),
            username: username.to_string(),
            pass: password.to_string(),
            totp: None,
            app_ids: Vec::new(),
        });
    }

    /// Tombstone-delete (so the deletion propagates to other devices).
    pub fn delete_item(&mut self, id: &str) {
        let tombstone = Tombstone {
            id: id.to_string(),
            deleted_at: Utc::now(),
            deleted_by: Some(self.device_id.clone()),
        };
        self.vault.tombstones.push(tombstone);
        self.vault.delete_item(id, Some(&self.device_id));
    }

    /// Rewrite `updated_at` (used to stage a concurrent-edit scenario).
    pub fn set_item_updated_at(&mut self, id: &str, ts: DateTime<Utc>) {
        let Some(item) = self.vault.items.iter_mut().find(|i| i.id() == id) else {
            return;
        };
        match item {
            VaultItem::Login { meta, .. }
            | VaultItem::CreditCard { meta, .. }
            | VaultItem::SecureNote { meta, .. }
            | VaultItem::Identity { meta, .. }
            | VaultItem::FileBlob { meta, .. }
            | VaultItem::BreachMonitor { meta, .. } => meta.updated_at = ts,
        }
    }

    pub fn item_ids(&self) -> Vec<String> {
        self.vault.items.iter().map(|i| i.id().to_string()).collect()
    }

    pub fn find_item(&self, id: &str) -> Option<&VaultItem> {
        self.vault.items.iter().find(|i| i.id() == id)
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }
}

fn extract_locator_server_url(code: &str) -> Result<String, String> {
    let locator: serde_json::Value =
        serde_json::from_slice(&url_safe_decode(code).map_err(|e| format!("decode locator: {e}"))?)
            .map_err(|e| format!("parse locator: {e}"))?;
    locator["u"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "locator has no server URL".to_string())
}

fn url_safe_decode(code: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let normalized: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let b64 = normalized
        .strip_prefix(ENROLLMENT_CODE_V2_PREFIX)
        .ok_or_else(|| "not a VELA-ENROLL:v2: code".to_string())?;
    URL_SAFE_NO_PAD.decode(b64).map_err(|e| format!("url-safe decode failed (len {}): {e}", b64.len()))
}

/// Decode a `VELA-ENROLL:v2:` code and fetch + decrypt the server-side
/// enrollment package, returning the payload (device identity + transfer key).
async fn decode_enrollment_code(code: &str) -> Result<EnrolledIdentity, String> {
    let locator: serde_json::Value =
        serde_json::from_slice(&url_safe_decode(code)?).map_err(|e| format!("parse locator: {e}"))?;
    let v = locator.get("v").and_then(|v| v.as_i64()).unwrap_or(1);
    if v != 2 {
        return Err(format!("unsupported enrollment code version: {v}"));
    }
    let package_token = locator["t"].as_str().ok_or("locator missing package token")?.to_string();
    let package_key_b64url = locator["k"].as_str().ok_or("locator missing package key")?.to_string();
    let server_url = locator["u"].as_str().map(|s| s.to_string());

    let package_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(package_key_b64url.as_bytes())
        .map_err(|e| format!("decode package key: {e}"))?;
    let mut key = [0u8; 32];
    if package_key.len() < 32 {
        return Err("package key too short".to_string());
    }
    key.copy_from_slice(&package_key[..32]);

    let base = server_url.clone().unwrap_or_default();
    let http = Client::new();
    let resp = http
        .get(format!("{}/device/enrollment-package/{}", base, package_token))
        .send()
        .await
        .map_err(|e| format!("fetch enrollment package: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("fetch enrollment package: {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse enrollment package: {e}"))?;
    let ciphertext_b64url = body["ciphertext"].as_str().ok_or("enrollment package missing ciphertext")?;
    let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ciphertext_b64url.as_bytes())
        .map_err(|e| format!("decode package ciphertext: {e}"))?;
    let plaintext = aead::decrypt(&key, &ciphertext).map_err(|e| format!("decrypt enrollment package: {e}"))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&plaintext).map_err(|e| format!("parse enrollment payload: {e}"))?;

    let transfer_key_b64 = payload["transfer_key"].as_str().ok_or("payload missing transfer_key")?;
    let transfer_key_bytes = B64.decode(transfer_key_b64).map_err(|e| format!("decode transfer_key: {e}"))?;
    let mut transfer_key = [0u8; 32];
    if transfer_key_bytes.len() < 32 {
        return Err("transfer_key too short".to_string());
    }
    transfer_key.copy_from_slice(&transfer_key_bytes[..32]);

    Ok(EnrolledIdentity {
        device_id: payload["device_id"].as_str().ok_or("payload missing device_id")?.to_string(),
        hybrid_sk_b64: payload["hybrid_sk"].as_str().ok_or("payload missing hybrid_sk")?.to_string(),
        transfer_key,
        server_url: payload["server_url"].as_str().map(|s| s.to_string()).or(server_url),
    })
}
