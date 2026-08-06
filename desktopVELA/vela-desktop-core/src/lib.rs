pub mod api;
pub mod audit;
pub mod breach;
pub mod clipboard;
pub mod biometric;
pub mod commands;
pub mod crypto;
pub mod device;
pub mod favicon;
pub mod host;
pub mod ipc;
pub mod ipc_peer;
pub mod passkey;
pub mod presence;
pub mod rclone;
pub mod session;
pub mod settings;
pub mod sharing;
pub mod recovery;
pub mod store;
pub mod sync;
pub mod token;
pub mod totp;
pub mod vault;
pub mod webauthn;
#[cfg(target_os = "linux")]
pub mod wayland_shortcut;

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
    /// When the user last proved presence for a plaintext credential release
    /// over IPC, and to which caller (audit D-4). Not persisted: a restart
    /// should cost a fresh confirmation.
    plaintext_release: RwLock<Option<(Option<u32>, std::time::Instant)>>,
    /// An enrollment v3 grant this device opened and is waiting on, with the
    /// fingerprint the user has to pick. Deliberately not persisted: a restart
    /// mid-enrollment should mean starting over, not resuming a comparison the
    /// user never finished.
    pub pending_enrollment: RwLock<Option<commands::enrollment_v3::PendingEnrollment>>,
    /// The keypair this device generated to join an account, held between
    /// claiming a grant and opening the capsule sealed to it. The private
    /// halves in here never leave the process (audit P-1).
    pub pending_join: RwLock<Option<commands::enrollment_v3::PendingJoin>>,
}

/// How long one user-presence confirmation covers further plaintext releases to
/// the same caller.
///
/// A prompt per filled field would train people to approve without reading,
/// which is worse than no prompt; a window this short still means an idle
/// machine cannot be drained by something that read the capability file.
pub const PLAINTEXT_RELEASE_TTL: std::time::Duration = std::time::Duration::from_secs(120);

impl AppState {
    /// Whether `pid` already proved presence recently. Tied to the caller, so a
    /// second process cannot ride on a confirmation the user gave the browser.
    pub fn plaintext_release_is_fresh(&self, pid: Option<u32>) -> bool {
        match *self.plaintext_release.read() {
            Some((granted_to, at)) => {
                granted_to == pid && pid.is_some() && at.elapsed() < PLAINTEXT_RELEASE_TTL
            }
            None => false,
        }
    }

    pub fn record_plaintext_release(&self, pid: Option<u32>) {
        *self.plaintext_release.write() = Some((pid, std::time::Instant::now()));
    }

    /// Locking the vault must also end any standing release grant.
    pub fn clear_plaintext_release(&self) {
        *self.plaintext_release.write() = None;
    }

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

    /// Hermetic state for tests (unit and the headless `vela-e2e` integration
    /// tests): the store is rooted at `store_dir` (a tempdir) instead of the
    /// real app data dir, so tests never touch the developer's vault, OS
    /// keychain, or app config.
    pub fn for_test(store_dir: &std::path::Path) -> Self {
        let store = Store::new_at(store_dir.to_path_buf()).expect("test store");
        Self {
            session: RwLock::new(session::Session::new()),
            vault: RwLock::new(vault::VaultStore::new()),
            crypto: RwLock::new(None),
            store: Arc::new(store),
            api: Arc::new(api::ApiClient::with_url(String::new())),
            server_url: RwLock::new(String::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            token_store: RwLock::new(token::TokenStore::new()),
            secret_key: token::SecretKey::generate(),
            ipc_capability: ipc::generate_capability(),
            extension_connected: Arc::new(AtomicBool::new(false)),
            sync_mutex: tokio::sync::Mutex::new(()),
            session_generation: AtomicU64::new(0),
            plaintext_release: RwLock::new(None),
            pending_enrollment: RwLock::new(None),
            pending_join: RwLock::new(None),
        }
    }

    /// Put a `for_test` state into the unlocked condition (active session +
    /// crypto context) without going through biometric/password unlock.
    pub fn unlock_for_test(&self, rms: &[u8; 32]) {
        {
            let mut session = self.session.write();
            session.unlock("test-device".to_string(), "test-user".to_string(), 900);
        }
        *self.crypto.write() = Some(crypto::Crypto::new(rms));
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

    /// The cached server auth token, or `None` if the session is inactive,
    /// expired, or never authenticated. Callers must not bypass this by
    /// reading `session.get_server_token()` directly — a token surviving
    /// past auto-lock would let locked-vault commands keep hitting the
    /// server as if still unlocked.
    pub fn get_session_token(&self) -> Option<String> {
        let session = self.session.read();
        if !session.active || session.is_expired() {
            return None;
        }
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
}impl Default for AppState {
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
            plaintext_release: RwLock::new(None),
            pending_enrollment: RwLock::new(None),
            pending_join: RwLock::new(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_server_url_accepts_empty_and_https() {
        assert_eq!(validate_server_url("").unwrap(), "");
        assert_eq!(validate_server_url("   ").unwrap(), "");
        assert_eq!(
            validate_server_url("https://vault.example.com").unwrap(),
            "https://vault.example.com"
        );
        assert_eq!(
            validate_server_url("  https://vault.example.com:8443/sync ").unwrap(),
            "https://vault.example.com:8443/sync"
        );
    }

    #[test]
    fn validate_server_url_allows_http_only_for_loopback() {
        for ok in [
            "http://localhost",
            "http://localhost:8080",
            "http://127.0.0.1:8080/api",
            "http://[::1]:9000",
        ] {
            assert!(validate_server_url(ok).is_ok(), "{ok} should be allowed");
        }
        for rejected in [
            "http://example.com",
            "http://192.168.1.10",
            "http://vault.internal.lan",
        ] {
            let err = validate_server_url(rejected).unwrap_err();
            assert!(err.contains("Insecure"), "{rejected}: {err}");
        }
    }

    #[test]
    fn validate_server_url_rejects_other_schemes_and_garbage() {
        let err = validate_server_url("ftp://example.com").unwrap_err();
        assert!(err.contains("Unsupported"), "{err}");
        assert!(validate_server_url("not a url at all :::").is_err());
    }

    #[test]
    fn normalize_server_url_trims() {
        assert_eq!(normalize_server_url("  https://x.example  "), "https://x.example");
        assert_eq!(normalize_server_url("   "), "");
    }

    #[test]
    fn rate_limiter_blocks_after_repeated_failures() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::for_test(dir.path());

        assert!(matches!(state.check_rate_limit("dev-1", "ip"), RateLimitResult::Allowed));
        for _ in 0..5 {
            state.record_failed_attempt("dev-1", "ip");
        }
        // new() starts at 1 attempt + 5 recorded = 6 > FREE_ATTEMPTS → blocked.
        assert!(matches!(state.check_rate_limit("dev-1", "ip"), RateLimitResult::Blocked));
        // A different device is unaffected.
        assert!(matches!(state.check_rate_limit("dev-2", "ip"), RateLimitResult::Allowed));

        state.record_successful_auth("dev-1");
        assert!(matches!(state.check_rate_limit("dev-1", "ip"), RateLimitResult::Allowed));
    }

    #[test]
    fn session_token_is_none_when_locked_or_expired() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::for_test(dir.path());
        assert!(state.get_session_token().is_none());

        state.unlock_for_test(&crypto::Crypto::generate_rms());
        // Unlocked but no server token yet.
        assert!(state.get_session_token().is_none());

        state.session.write().set_server_token("srv".into());
        assert_eq!(state.get_session_token().as_deref(), Some("srv"));

        state.session.write().lock();
        assert!(state.get_session_token().is_none(), "locked vault must not hand out tokens");
    }

    #[test]
    fn is_unlocked_and_generation_guard() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::for_test(dir.path());
        assert!(!state.is_unlocked());

        state.unlock_for_test(&crypto::Crypto::generate_rms());
        assert!(state.is_unlocked());

        let generation = state.session_generation();
        assert!(state.ensure_unlocked_since(generation).is_ok());
        state.bump_session_generation();
        assert!(state.ensure_unlocked_since(generation).is_err());

        state.session.write().lock();
        assert!(!state.is_unlocked());
    }

    #[test]
    fn unlock_throttle_persists_across_restarts_and_resets_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let rms = crypto::Crypto::generate_rms();

        let state = AppState::for_test(dir.path());
        state.unlock_for_test(&rms);
        assert!(state.check_unlock_throttle().is_ok());
        for _ in 0..5 {
            state.record_unlock_failure();
        }
        assert!(state.check_unlock_throttle().is_err(), "6th attempt must throttle");

        // A "restarted" app (fresh AppState over the same store dir) still
        // sees the throttle — it is persisted to disk.
        let restarted = AppState::for_test(dir.path());
        assert!(restarted.check_unlock_throttle().is_err());

        restarted.record_unlock_success();
        assert!(restarted.check_unlock_throttle().is_ok());
    }
}
