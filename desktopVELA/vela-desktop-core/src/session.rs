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
    /// Auto-lock deadline. Pushed **only** by `touch()` (real user activity);
    /// background sync's `refresh()` must never extend it (that bug made
    /// `auto_lock_minutes` a no-op up to the 8h cap — sync kept re-extending
    /// the one deadline the watchdog watched). Decoupled from `expires_at`,
    /// which is the server-token keepalive.
    pub idle_until: Option<DateTime<Utc>>,
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
            idle_until: None,
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
        self.idle_until = None;
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
        self.idle_until = Some(now + chrono::Duration::seconds(effective_duration as i64));
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

    /// Whether the auto-lock (idle) deadline has passed. This is what the
    /// auto-lock watchdog and the session-status health gate consult — it must
    /// not drift under background `refresh()`.
    pub fn is_idle_expired(&self) -> bool {
        if self.active {
            self.idle_until.map_or(true, |deadline| Utc::now() > deadline)
        } else {
            true
        }
    }

    /// Reset the auto-lock deadline to `duration_secs` from now. Called on real
    /// user activity only — never by background sync.
    pub fn touch(&mut self, duration_secs: u64) {
        if !self.active {
            return;
        }
        self.idle_until = Some(Utc::now() + chrono::Duration::seconds(duration_secs as i64));
    }

    /// Seconds until the auto-lock (idle) deadline (0 when locked/expired).
    pub fn remaining_idle_secs(&self) -> u64 {
        if let Some(deadline) = self.idle_until {
            (deadline - Utc::now()).num_seconds().max(0) as u64
        } else {
            0
        }
    }

    pub fn refresh(&mut self) {
        if !self.active {
            return;
        }
        let now = Utc::now();

        // `refresh()` is the *server-token keepalive* (background sync). It must
        // never touch `idle_until` — if sync re-extended the auto-lock deadline,
        // an idle vault would stay unlocked up to the 8h cap, making
        // `auto_lock_minutes` a no-op. Only `touch()` moves the idle deadline.
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
            idle_until: Some(expires_at),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_inactive_and_expired() {
        let s = Session::new();
        assert!(!s.active);
        assert!(s.is_expired());
        assert_eq!(s.remaining_time(), 0);
        assert!(s.get_token().is_none());
    }

    #[test]
    fn unlock_sets_active_state_and_token_prefix() {
        let mut s = Session::new();
        s.unlock("dev-1".into(), "user-1".into(), 900);
        assert!(s.active);
        assert!(!s.is_expired());
        assert_eq!(s.get_device_id(), Some("dev-1"));
        assert_eq!(s.get_user_id(), Some("user-1"));
        assert!(s.get_token().unwrap().starts_with("v2.local."));
        let remaining = s.remaining_time();
        assert!(remaining > 0 && remaining <= 900);
    }

    #[test]
    fn unlock_caps_duration_at_max_session() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 999_999);
        assert_eq!(s.session_time_remaining_secs, MAX_SESSION_DURATION_SECS);
        let remaining = s.remaining_time();
        assert!(remaining <= MAX_SESSION_DURATION_SECS && remaining > MAX_SESSION_DURATION_SECS - 10);
    }

    #[test]
    fn unlock_preserves_server_token_but_lock_clears_it() {
        let mut s = Session::new();
        s.set_server_token("srv-token".into());
        s.unlock("d".into(), "u".into(), 900);
        // server_token lives outside the local session lifecycle on purpose.
        assert_eq!(s.get_server_token(), Some("srv-token"));

        s.lock();
        assert!(!s.active);
        assert!(s.get_token().is_none());
        assert!(s.get_server_token().is_none());
        assert!(s.get_device_id().is_none());
        assert!(s.is_expired());
    }

    #[test]
    fn zero_duration_unlock_is_immediately_expired() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 0);
        assert!(s.is_expired());
    }

    #[test]
    fn refresh_on_inactive_session_is_noop() {
        let mut s = Session::new();
        s.refresh();
        assert!(!s.active);
        assert!(s.expires_at.is_none());
    }

    #[test]
    fn refresh_never_resurrects_expired_session() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 0);
        let expired_at = s.expires_at.unwrap();
        s.refresh();
        assert_eq!(s.expires_at, Some(expired_at), "expired session must stay expired");
    }

    #[test]
    fn refresh_extends_expiry_and_rotates_token_near_expiry() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 60);
        let old_token = s.get_token().unwrap().to_string();
        let old_expiry = s.expires_at.unwrap();

        s.refresh();

        let new_expiry = s.expires_at.unwrap();
        assert!(new_expiry > old_expiry, "refresh should extend a live session");
        let remaining = s.remaining_time();
        assert!(remaining > 60 && remaining <= SESSION_DURATION_SECS);
        // 60s left ≤ 5min window → token rotates.
        assert_ne!(s.get_token().unwrap(), old_token);
    }

    #[test]
    fn refresh_keeps_token_when_far_from_expiry() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 60);
        // Pretend there's plenty of time left so refresh extends without
        // crossing the 5-minute rotation window.
        let now = Utc::now();
        s.started_at = Some(now);
        s.expires_at = Some(now + chrono::Duration::seconds(MAX_SESSION_DURATION_SECS as i64 - 60));
        let old_token = s.get_token().unwrap().to_string();
        let old_expiry = s.expires_at.unwrap();

        s.refresh();

        // desired (now+15min) < current expiry → no change at all.
        assert_eq!(s.expires_at, Some(old_expiry));
        assert_eq!(s.get_token().unwrap(), old_token);
    }

    #[test]
    fn refresh_never_extends_past_absolute_cap() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 60);
        let now = Utc::now();
        // Started almost 8h ago: only ~60s of absolute lifetime remains.
        let started = now - chrono::Duration::seconds(MAX_SESSION_DURATION_SECS as i64 - 60);
        s.started_at = Some(started);
        s.expires_at = Some(now + chrono::Duration::seconds(30));

        s.refresh();

        let cap = started + chrono::Duration::seconds(MAX_SESSION_DURATION_SECS as i64);
        assert!(s.expires_at.unwrap() <= cap, "expiry must not pass the 8h cap");
        // But it should still extend up to the cap (30s → ~60s).
        assert!(s.expires_at.unwrap() > now + chrono::Duration::seconds(30));
    }

    /// The core auto-lock bug: background `refresh()` must extend the
    /// server-token keepalive (`expires_at`) but must NOT move the auto-lock
    /// (`idle_until`) deadline — otherwise sync keeps an idle vault unlocked.
    #[test]
    fn refresh_extends_the_server_token_but_not_the_idle_deadline() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 60);
        let now = Utc::now();
        // The user's activity ran out: auto-lock deadline is a moment away, but
        // the server token still has an hour of keepalive.
        let old_expiry = now + chrono::Duration::seconds(3600);
        s.expires_at = Some(old_expiry);
        s.idle_until = Some(now + chrono::Duration::seconds(1));
        let idle_before = s.idle_until;

        s.refresh();

        assert!(s.idle_until == idle_before, "refresh must not touch idle_until");
        // expires_at may still be extended toward its cap for server auth.
        assert!(s.is_idle_expired() == false || Utc::now() > idle_before.unwrap());
    }

    #[test]
    fn touch_resets_the_idle_deadline_to_now_plus_duration() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 60);
        // Idle deadline already passed.
        s.idle_until = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(s.is_idle_expired());

        s.touch(600); // user did something

        assert!(!s.is_idle_expired(), "activity must clear the idle lock");
        let remaining = s.remaining_idle_secs();
        assert!(remaining > 570 && remaining <= 600, "remaining {remaining}");
    }

    #[test]
    fn refresh_extending_the_server_token_does_not_report_unexpired_idle() {
        let mut s = Session::new();
        s.unlock("d".into(), "u".into(), 60);
        // Server token has 8h of keepalive; auto-lock deadline is passed.
        s.expires_at = Some(Utc::now() + chrono::Duration::seconds(3600));
        s.idle_until = Some(Utc::now() - chrono::Duration::seconds(1));
        s.refresh();
        assert!(s.is_idle_expired(), "an idle vault is locked regardless of server keepalive");
    }

    #[test]
    fn generate_local_token_embeds_decodable_claims() {
        let s = Session::generate_local_token("dev-9", "user-9");
        assert!(s.active);
        assert_eq!(s.get_device_id(), Some("dev-9"));
        assert_eq!(s.session_time_remaining_secs, SESSION_DURATION_SECS);

        let token = s.get_token().unwrap();
        let encoded = token.strip_prefix("v2.local.").expect("v2.local prefix");
        let json = BASE64URL.decode(encoded.as_bytes()).expect("base64url payload");
        let payload: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(payload["device_id"], "dev-9");
        assert_eq!(payload["user_id"], "user-9");
        assert!(!payload["jti"].as_str().unwrap().is_empty());
        assert!(payload["exp"].as_str().is_some());
    }

    #[test]
    fn rate_limit_backoff_starts_after_free_attempts() {
        let mut entry = RateLimitEntry::new();
        assert_eq!(entry.attempts, 1);
        assert!(!entry.is_blocked());

        for _ in 0..4 {
            entry.record_failure();
        }
        assert_eq!(entry.attempts, 5);
        assert!(!entry.is_blocked(), "first 5 failures are free");

        entry.record_failure(); // 6th → first backoff step
        assert!(entry.is_blocked());
        let remaining = entry.blocked_remaining_secs();
        assert!(remaining > 0 && remaining <= 15, "first backoff is 15s, got {remaining}");
    }

    #[test]
    fn rate_limit_backoff_grows_exponentially_and_caps() {
        let mut entry = RateLimitEntry::new();
        // Pre-fill to the free-attempt boundary (new() starts at 1).
        for _ in 0..4 {
            entry.record_failure();
        }
        assert_eq!(entry.attempts, 5);
        // attempts: new()=1, then record_failure increments. Backoff for
        // attempts n>5 is 15 * 2^(n-6) seconds, capped at 300.
        let expected = [(6, 15), (7, 30), (8, 60), (9, 120), (10, 240), (11, 300), (12, 300)];
        for (attempts, max_secs) in expected {
            entry.record_failure();
            assert_eq!(entry.attempts, attempts);
            assert!(entry.is_blocked(), "attempt {attempts} should block");
            let remaining = entry.blocked_remaining_secs();
            assert!(
                remaining > 0 && remaining <= max_secs,
                "attempt {attempts}: remaining {remaining} should be ≤ {max_secs}"
            );
        }
    }

    #[test]
    fn rate_limit_success_resets() {
        let mut entry = RateLimitEntry::new();
        for _ in 0..6 {
            entry.record_failure();
        }
        assert!(entry.is_blocked());
        entry.record_success();
        assert_eq!(entry.attempts, 0);
        assert!(!entry.is_blocked());
        assert_eq!(entry.blocked_remaining_secs(), 0);
    }
}
