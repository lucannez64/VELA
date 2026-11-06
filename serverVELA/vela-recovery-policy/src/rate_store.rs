//! The fixed-window rate-limit counters behind the recovery handlers, split so
//! the admission decision can be proved (F-1).
//!
//! Every limiter in `vela-server/src/rate_limit.rs` that the recovery handlers
//! call is one `Store::incr_fixed_window(key, 1, window_secs)` on an exact key:
//! `POST /recovery/initiate` (three), `/recovery/recover` (two, shared by the
//! possession path), `/recovery/enroll-device` (three) and the WebAuthn
//! registration finish (one).
//!
//! 1. `plan_*` builds the typed statement ([`RateStmt`]) with the exact key and
//!    window;
//! 2. [`render`] gives the exact key and window the store has always used
//!    (pinned byte for byte by the unit tests below);
//! 3. [`classify_rate_limit`] decides admission from the counter's new value
//!    and the endpoint's documented limit.
//!
//! `proofs/fstar/rate-lemmas` proves, for every starting counter and every
//! failing store operation, that the counter grows by exactly one at the
//! plan's key (saturating), that a failure leaves it unchanged, and that the
//! verdict is exactly `new count <= limit`. TTL expiry is abstracted as a
//! scheduler choice, exactly as the other store models state.

#[cfg(not(hax))]
use crate::redemption_store::Rendered;

/// One statement a rate limiter runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RateStmt {
    /// `Store::incr_fixed_window(key, 1, window_secs)`.
    Incr { key: String, window_secs: u64 },
}

/// What one counter increment returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateOutcome {
    /// The store call itself failed; the counter did not grow.
    Failed,
    /// It ran; the counter now holds this count.
    Count(u64),
}

/// The limiter's verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateObservation {
    Admitted,
    Limited,
    StorageFailed,
}

// ── Plans ──────────────────────────────────────────────────────────────────

/// One fixed-window counter increment at the exact key and window.
pub fn plan_rate_limit(key: String, window_secs: u64) -> Vec<RateStmt> {
    vec![RateStmt::Incr { key, window_secs }]
}

/// `rate_limit::recovery_initiate_by_ip`.
#[cfg(not(hax))]
pub fn plan_initiate_by_ip(ip: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:init:ip:{ip}"), 3600)
}

/// `rate_limit::recovery_initiate_by_ip_user`.
#[cfg(not(hax))]
pub fn plan_initiate_by_ip_user(ip: &str, user: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:init:ip_user:{ip}:{user}"), 3600)
}

/// `rate_limit::recovery_initiate_by_user`.
#[cfg(not(hax))]
pub fn plan_initiate_by_user(user: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:init:user:{user}"), 3600)
}

/// `rate_limit::recovery_recover_by_ip_user`.
#[cfg(not(hax))]
pub fn plan_recover_by_ip_user(ip: &str, user: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:ip_user:{ip}:{user}"), 3600)
}

/// `rate_limit::recovery_recover_by_user`.
#[cfg(not(hax))]
pub fn plan_recover_by_user(user: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:user:{user}"), 3600)
}

/// `rate_limit::recovery_enroll_by_ip`.
#[cfg(not(hax))]
pub fn plan_enroll_by_ip(ip: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:enroll:ip:{ip}"), 3600)
}

/// `rate_limit::recovery_enroll_by_ip_user`.
#[cfg(not(hax))]
pub fn plan_enroll_by_ip_user(ip: &str, user: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:enroll:ip_user:{ip}:{user}"), 3600)
}

/// `rate_limit::recovery_enroll_by_user`.
#[cfg(not(hax))]
pub fn plan_enroll_by_user(user: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:recover:enroll:user:{user}"), 3600)
}

/// `rate_limit::webauthn_register_by_user`.
#[cfg(not(hax))]
pub fn plan_webauthn_register_by_user(user: &str) -> Vec<RateStmt> {
    plan_rate_limit(format!("rl:webauthn:register:user:{user}"), 3600)
}

// ── Classification ─────────────────────────────────────────────────────────

/// Whether a counter value is within an endpoint's limit.
pub fn under_limit(count: u64, limit: u64) -> bool {
    count <= limit
}

/// `Admitted` exactly while the counter's new value is within the limit.
pub fn classify_rate_limit(outcomes: &[RateOutcome], limit: u64) -> RateObservation {
    if outcomes.len() == 1 {
        match &outcomes[0] {
            RateOutcome::Count(count) => {
                if under_limit(*count, limit) {
                    RateObservation::Admitted
                } else {
                    RateObservation::Limited
                }
            }
            RateOutcome::Failed => RateObservation::StorageFailed,
        }
    } else {
        RateObservation::StorageFailed
    }
}

// ── Rendering (not extracted; pinned by the tests below) ───────────────────

/// The exact key and window each statement has always used.
#[cfg(not(hax))]
pub fn render(stmt: &RateStmt) -> Rendered {
    match stmt {
        RateStmt::Incr { key, window_secs } => Rendered::KvIncr {
            key: key.clone(),
            window_secs: *window_secs,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    fn key(stmt: &RateStmt) -> (String, u64) {
        match render(stmt) {
            Rendered::KvIncr { key, window_secs } => (key, window_secs),
            other => panic!("expected a counter, got {other:?}"),
        }
    }

    // The expected keys, windows and limits are copies of the constants the
    // handlers used before the split (vela-server/src/rate_limit.rs at
    // b9e3d67).

    #[test]
    fn plans_render_the_historical_keys_and_windows() {
        let one = |plan: Vec<RateStmt>| {
            assert_eq!(plan.len(), 1);
            key(&plan[0])
        };
        assert_eq!(
            one(plan_initiate_by_ip("203.0.113.1")),
            (s("rl:recover:init:ip:203.0.113.1"), 3600)
        );
        assert_eq!(
            one(plan_initiate_by_ip_user("203.0.113.1", "user-1")),
            (s("rl:recover:init:ip_user:203.0.113.1:user-1"), 3600)
        );
        assert_eq!(
            one(plan_initiate_by_user("user-1")),
            (s("rl:recover:init:user:user-1"), 3600)
        );
        assert_eq!(
            one(plan_recover_by_ip_user("203.0.113.1", "user-1")),
            (s("rl:recover:ip_user:203.0.113.1:user-1"), 3600)
        );
        assert_eq!(
            one(plan_recover_by_user("user-1")),
            (s("rl:recover:user:user-1"), 3600)
        );
        assert_eq!(
            one(plan_enroll_by_ip("203.0.113.1")),
            (s("rl:recover:enroll:ip:203.0.113.1"), 3600)
        );
        assert_eq!(
            one(plan_enroll_by_ip_user("203.0.113.1", "user-1")),
            (s("rl:recover:enroll:ip_user:203.0.113.1:user-1"), 3600)
        );
        assert_eq!(
            one(plan_enroll_by_user("user-1")),
            (s("rl:recover:enroll:user:user-1"), 3600)
        );
        assert_eq!(
            one(plan_webauthn_register_by_user("user-1")),
            (s("rl:webauthn:register:user:user-1"), 3600)
        );
    }

    #[test]
    fn classifier_keeps_the_historical_decision() {
        assert!(under_limit(5, 5));
        assert!(!under_limit(6, 5));
        assert_eq!(
            classify_rate_limit(&[RateOutcome::Count(5)], 5),
            RateObservation::Admitted
        );
        assert_eq!(
            classify_rate_limit(&[RateOutcome::Count(6)], 5),
            RateObservation::Limited
        );
        assert_eq!(
            classify_rate_limit(&[RateOutcome::Failed], 5),
            RateObservation::StorageFailed
        );
        assert_eq!(classify_rate_limit(&[], 5), RateObservation::StorageFailed);
    }
}
