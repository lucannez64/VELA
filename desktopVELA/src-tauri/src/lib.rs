pub mod api;
pub mod biometric;
pub mod commands;
pub mod crypto;
pub mod device;
pub mod ipc;
pub mod session;
pub mod store;
pub mod token;
pub mod vault;

#[cfg(test)]
mod vault_lifecycle_test;

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::session::RateLimitEntry;
use crate::store::Store;

pub const DEFAULT_SERVER_URL: &str = "";

pub fn normalize_server_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// Validate a user-supplied server URL. Allows empty (offline mode), `https://`
/// anywhere, and plain `http://` only for loopback (`localhost` / `127.0.0.1`
/// / `::1`). Prevents a compromised renderer from redirecting sync traffic
/// (which carries encrypted chunks + a Bearer token) to a plaintext endpoint.
pub fn validate_server_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let parsed = url::Url::parse(trimmed).map_err(|e| format!("Invalid server URL: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(trimmed.to_string()),
        "http" => {
            let host = parsed.host_str().unwrap_or("");
            let is_loopback = host == "localhost"
                || host == "127.0.0.1"
                || host == "::1"
                || host == "[::1]";
            if !is_loopback {
                return Err(
                    "Insecure server URL: plain HTTP is only allowed for localhost / 127.0.0.1"
                        .to_string(),
                );
            }
            Ok(trimmed.to_string())
        }
        other => Err(format!(
            "Unsupported server URL scheme '{other}'; use https:// (or http://localhost)"
        )),
    }
}

pub struct AppState {
    pub session: RwLock<session::Session>,
    pub vault: RwLock<vault::VaultStore>,
    pub crypto: RwLock<Option<crypto::Crypto>>,
    pub store: Arc<Store>,
    pub api: Arc<api::ApiClient>,
    pub server_url: RwLock<String>,
    pub rate_limiter: RwLock<HashMap<String, RateLimitState>>,
    pub token_store: RwLock<token::TokenStore>,
    pub secret_key: token::SecretKey,
    pub ipc_capability: String,
    pub extension_connected: Arc<AtomicBool>,
    /// Serializes sync runs so local edits and merges cannot interleave.
    pub sync_mutex: tokio::sync::Mutex<()>,
    /// Bumped on every lock/unlock. Sync captures it and aborts if it changes
    /// mid-flight (vault locked during sync).
    pub session_generation: AtomicU64,
}

impl AppState {
    pub fn is_extension_connected(&self) -> bool {
        self.extension_connected.load(Ordering::Relaxed)
    }

    pub fn bump_session_generation(&self) {
        self.session_generation.fetch_add(1, Ordering::SeqCst);
    }

    pub fn session_generation(&self) -> u64 {
        self.session_generation.load(Ordering::SeqCst)
    }

    /// Proof that the vault is still unlocked: session active, unexpired, the
    /// crypto context present, and no lock/unlock happened since `generation`.
    pub fn ensure_unlocked_since(&self, generation: u64) -> Result<(), String> {
        if self.session_generation() != generation {
            return Err("Vault locked during sync — aborting".to_string());
        }
        let session = self.session.read();
        if !session.active || session.is_expired() {
            return Err("Vault locked during sync — aborting".to_string());
        }
        drop(session);
        if self.crypto.read().is_none() {
            return Err("Vault locked during sync — aborting".to_string());
        }
        Ok(())
    }

    /// True when the vault is currently unlocked and usable.
    pub fn is_unlocked(&self) -> bool {
        let session = self.session.read();
        session.active && !session.is_expired() && self.crypto.read().is_some()
    }
}

struct RateLimitState {
    entry: RateLimitEntry,
    ip_attempts: u32,
    last_ip_attempt: Instant,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            entry: RateLimitEntry::new(),
            ip_attempts: 0,
            last_ip_attempt: Instant::now(),
        }
    }
}

impl AppState {
    pub fn check_rate_limit(&self, device_id: &str, _ip: &str) -> RateLimitResult {
        let mut limiter = self.rate_limiter.write();
        let now = Instant::now();

        let state = limiter
            .entry(device_id.to_string())
            .or_insert_with(RateLimitState::new);

        if state.entry.is_blocked() {
            return RateLimitResult::Blocked;
        }

        if now.duration_since(state.last_ip_attempt).as_secs() > 60 {
            state.ip_attempts = 0;
        }

        RateLimitResult::Allowed
    }

    pub fn record_failed_attempt(&self, device_id: &str, _ip: &str) {
        let mut limiter = self.rate_limiter.write();
        let state = limiter
            .entry(device_id.to_string())
            .or_insert_with(RateLimitState::new);
        state.entry.record_failure();
        state.ip_attempts += 1;
        state.last_ip_attempt = Instant::now();
    }

    pub fn record_successful_auth(&self, device_id: &str) {
        let mut limiter = self.rate_limiter.write();
        if let Some(state) = limiter.get_mut(device_id) {
            state.entry.record_success();
        }
    }

    pub fn get_session_token(&self) -> Option<String> {
        let session = self.session.read();
        session.get_server_token().map(|s| s.to_string())
    }

    pub fn validate_session_token(&self, token: &str) -> Result<token::PasetoToken, String> {
        token::validate_local_token(token, &self.secret_key).map_err(|e| e.to_string())
    }

    // ── Persisted master-password unlock throttle (finding: unthrottled
    //    master-password guessing). Survives restarts; capped at 5 minutes;
    //    reset on success. ────────────────────────────────────────────────

    fn unlock_throttle_path(&self) -> std::path::PathBuf {
        self.store.store_path().join("unlock_throttle.json")
    }

    fn load_unlock_throttle(&self) -> RateLimitEntry {
        let path = self.unlock_throttle_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    fn save_unlock_throttle(&self, entry: &RateLimitEntry) {
        if let Ok(json) = serde_json::to_string(entry) {
            let _ = std::fs::write(self.unlock_throttle_path(), json);
        }
    }

    /// Err with a user-facing message when unlock attempts are throttled.
    pub fn check_unlock_throttle(&self) -> Result<(), String> {
        let entry = self.load_unlock_throttle();
        if entry.is_blocked() {
            return Err(format!(
                "Too many failed attempts. Try again in {}s.",
                entry.blocked_remaining_secs()
            ));
        }
        Ok(())
    }

    pub fn record_unlock_failure(&self) {
        let mut entry = self.load_unlock_throttle();
        entry.record_failure();
        self.save_unlock_throttle(&entry);
    }

    pub fn record_unlock_success(&self) {
        self.save_unlock_throttle(&RateLimitEntry::default());
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RateLimitResult {
    Allowed,
    Blocked,
}

impl Default for AppState {
    fn default() -> Self {
        let store = Store::new().expect("Failed to create store");
        let server_url = store
            .load_settings()
            .ok()
            .and_then(|s| {
                let server_url = normalize_server_url(&s.server_url);
                if server_url.is_empty() {
                    None
                } else {
                    Some(server_url)
                }
            })
            .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());
        Self {
            session: RwLock::new(session::Session::new()),
            vault: RwLock::new(vault::VaultStore::new()),
            crypto: RwLock::new(None),
            store: Arc::new(store),
            api: Arc::new(api::ApiClient::with_url(server_url.clone())),
            server_url: RwLock::new(server_url),
            rate_limiter: RwLock::new(HashMap::new()),
            token_store: RwLock::new(token::TokenStore::new()),
            secret_key: token::SecretKey::generate(),
            ipc_capability: ipc::generate_capability(),
            extension_connected: Arc::new(AtomicBool::new(false)),
            sync_mutex: tokio::sync::Mutex::new(()),
            session_generation: AtomicU64::new(0),
        }
    }
}
