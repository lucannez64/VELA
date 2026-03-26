pub mod biometric;
pub mod session;
pub mod vault;
pub mod commands;
pub mod ipc;
pub mod crypto;
pub mod store;
pub mod api;
pub mod device;
pub mod token;

use parking_lot::RwLock;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;

use crate::store::Store;
use crate::session::RateLimitEntry;

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
        
        let state = limiter.entry(device_id.to_string()).or_insert_with(RateLimitState::new);
        
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
        let state = limiter.entry(device_id.to_string()).or_insert_with(RateLimitState::new);
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
        session.get_token().map(|s| s.to_string())
    }
    
    pub fn validate_session_token(&self, token: &str) -> Result<token::PasetoToken, String> {
        token::validate_local_token(token, &self.secret_key)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RateLimitResult {
    Allowed,
    Blocked,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: RwLock::new(session::Session::new()),
            vault: RwLock::new(vault::VaultStore::new()),
            crypto: RwLock::new(None),
            store: Arc::new(Store::new().expect("Failed to create store")),
            api: Arc::new(api::ApiClient::with_url("http://localhost:8080".to_string())),
            server_url: RwLock::new("http://localhost:8080".to_string()),
            rate_limiter: RwLock::new(HashMap::new()),
            token_store: RwLock::new(token::TokenStore::new()),
            secret_key: token::SecretKey::generate(),
        }
    }
}
