use chrono::{DateTime, Utc};
use data_encoding::BASE64URL;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SESSION_DURATION_SECS: u64 = 15 * 60;
const MAX_SESSION_DURATION_SECS: u64 = 8 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub active: bool,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub session_time_remaining_secs: u64,
    pub session_token: Option<String>,
    /// Server-issued Bearer token, kept separate so `unlock()` cannot overwrite it.
    pub server_token: Option<String>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            active: false,
            device_id: None,
            user_id: None,
            started_at: None,
            expires_at: None,
            session_time_remaining_secs: 0,
            session_token: None,
            server_token: None,
        }
    }

    pub fn lock(&mut self) {
        self.active = false;
        self.device_id = None;
        self.user_id = None;
        self.started_at = None;
        self.expires_at = None;
        self.session_time_remaining_secs = 0;
        self.session_token = None;
        self.server_token = None;
    }

    pub fn unlock(&mut self, device_id: String, user_id: String, duration_secs: u64) {
        let now = Utc::now();
        let token = Self::generate_session_token();
        self.active = true;
        self.device_id = Some(device_id);
        self.user_id = Some(user_id);
        self.started_at = Some(now);
        let effective_duration = duration_secs.min(MAX_SESSION_DURATION_SECS);
        self.expires_at = Some(now + chrono::Duration::seconds(effective_duration as i64));
        self.session_time_remaining_secs = effective_duration;
        self.session_token = Some(token);
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            true
        }
    }

    pub fn refresh(&mut self) {
        if !self.active {
            return;
        }
        let now = Utc::now();

        let current_expiry = match self.expires_at {
            Some(e) => e,
            None => return,
        };

        // Fail-closed: once the local session has expired, refresh must never
        // silently resurrect it (e.g. a periodic background sync). The user
        // must re-unlock.
        if now >= current_expiry {
            return;
        }

        // Absolute cap measured from the original unlock time, so repeated
        // background refreshes cannot keep the session alive beyond
        // MAX_SESSION_DURATION_SECS.
        let started_at = self.started_at.unwrap_or(now);
        let absolute_cap =
            started_at + chrono::Duration::seconds(MAX_SESSION_DURATION_SECS as i64);
        // If we are already at/over the absolute cap, do not extend further.
        if now >= absolute_cap {
            return;
        }

        let desired = now + chrono::Duration::seconds(SESSION_DURATION_SECS as i64);
        let new_expiry = desired.min(absolute_cap);
        // Never shrink the expiry, and never extend past the absolute cap.
        if new_expiry <= current_expiry {
            return;
        }
        self.expires_at = Some(new_expiry);
        self.session_time_remaining_secs = (new_expiry - now).num_seconds().max(0) as u64;

        // Rotate the local session token only when close to expiry (≤ 5 min
        // left), to avoid churning a fresh token on every background sync.
        let time_until_expiry = (current_expiry - now).num_seconds();
        if time_until_expiry <= 300 {
            let new_token = Self::generate_session_token();
            self.session_token = Some(new_token);
        }
    }

    pub fn remaining_time(&self) -> u64 {
        if let Some(expires) = self.expires_at {
            let remaining = expires - Utc::now();
            remaining.num_seconds().max(0) as u64
        } else {
            0
        }
    }

    pub fn get_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }

    pub fn set_server_token(&mut self, token: String) {
        self.server_token = Some(token);
    }

    pub fn get_server_token(&self) -> Option<&str> {
        self.server_token.as_deref()
    }

    pub fn get_device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    pub fn get_user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    fn generate_session_token() -> String {
        let jti = Uuid::new_v4().to_string();
        format!("v2.local.{}", jti)
    }

    pub fn generate_local_token(device_id: &str, user_id: &str) -> Self {
        let now = Utc::now();
        let jti = Uuid::new_v4().to_string();
        let expires_at = now + chrono::Duration::seconds(SESSION_DURATION_SECS as i64);

        let mut token_payload = std::collections::HashMap::new();
        token_payload.insert("device_id".to_string(), device_id.to_string());
        token_payload.insert("user_id".to_string(), user_id.to_string());
        token_payload.insert("jti".to_string(), jti);
        token_payload.insert("exp".to_string(), expires_at.to_rfc3339());

        let token_string = serde_json::to_string(&token_payload).unwrap_or_default();

        Self {
            active: true,
            device_id: Some(device_id.to_string()),
            user_id: Some(user_id.to_string()),
            started_at: Some(now),
            expires_at: Some(expires_at),
            session_time_remaining_secs: SESSION_DURATION_SECS,
            session_token: Some(format!(
                "v2.local.{}",
                BASE64URL.encode(token_string.as_bytes())
            )),
            server_token: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub active: bool,
    pub session_time_remaining_secs: u64,
    pub device_name: Option<String>,
    pub device_id: Option<String>,
    pub lock_state: LockState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockState {
    Locked,
    Unlocked,
    Syncing,
    Error,
    Conflict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitEntry {
    pub attempts: u32,
    pub first_attempt: DateTime<Utc>,
    pub last_attempt: DateTime<Utc>,
    pub blocked_until: Option<DateTime<Utc>>,
}

impl Default for RateLimitEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitEntry {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            attempts: 1,
            first_attempt: now,
            last_attempt: now,
            blocked_until: None,
        }
    }

    /// Number of failed attempts tolerated before exponential backoff starts.
    const FREE_ATTEMPTS: u32 = 5;
    /// Hard cap on the backoff so the real user is never locked out long.
    const MAX_BACKOFF_SECS: u64 = 300;

    pub fn record_failure(&mut self) {
        self.attempts += 1;
        self.last_attempt = Utc::now();

        if self.attempts > Self::FREE_ATTEMPTS {
            let exponent = (self.attempts - Self::FREE_ATTEMPTS - 1).min(20);
            let backoff_secs = (15u64 * 2u64.pow(exponent)).min(Self::MAX_BACKOFF_SECS);
            self.blocked_until =
                Some(self.last_attempt + chrono::Duration::seconds(backoff_secs as i64));
        }
    }

    pub fn record_success(&mut self) {
        self.attempts = 0;
        self.blocked_until = None;
    }

    pub fn is_blocked(&self) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            Utc::now() < blocked_until
        } else {
            false
        }
    }

    /// Seconds until the block lifts (0 when not blocked).
    pub fn blocked_remaining_secs(&self) -> u64 {
        if let Some(blocked_until) = self.blocked_until {
            (blocked_until - Utc::now()).num_seconds().max(0) as u64
        } else {
            0
        }
    }
}
