//! sled-backed rate limiting (sliding-window counter) and JTI tracking.
//!
//! All limits are per-key, where "key" encodes `(endpoint, dimension, value)`.
//!
//! ## Implemented limits (from SPEC §6 Rate Limiting)
//!
//! | Endpoint               | Limit                                | Key pattern                         |
//! |------------------------|--------------------------------------|-------------------------------------|
//! | GET /auth/challenge    | 20 req/min per IP                    | `rl:challenge:ip:{ip}`              |
//! | POST /auth/verify      | 5 failed proofs/min per device_id    | `rl:verify:fail:dev:{device_id}`    |
//! | POST /auth/verify      | 10 attempts/min per IP               | `rl:verify:ip:{ip}`                 |
//! | Authenticated routes   | 300 req/min per JTI                  | `rl:auth:jti:{jti}`                 |
//!
//! ## JTI tracking for device revocation cascade (SPEC §6 Session Lifecycle)
//!
//! Every issued JTI is added to `device:jtis:{device_id}` (a sled set).
//! On `POST /device/revoke`, all JTIs in that set are individually written to
//! `jti:revoked:{jti}` — giving the middleware exact, per-token revocation.
//! The device-revoked sentinel is kept as a backstop for any JTIs that were
//! issued after the store was flushed or before tracking was in place.
//!
//! Key TTLs:
//!   `device:jtis:{device_id}` — 8 hours (= session hard cap)
//!   `jti:revoked:{jti}`       — TOKEN_MAX_LIFETIME_SECS (15 min)

use crate::error::{AppError, Result};
use crate::store::Store;

const WINDOW_SECS: i64 = 60;
/// Maximum PASETO token lifetime in seconds (15 minutes).
pub const TOKEN_MAX_LIFETIME_SECS: u64 = 15 * 60;
/// Session hard-cap in seconds (8 hours) — used as the device JTI-set TTL.
const SESSION_HARD_CAP_SECS: i64 = 8 * 60 * 60;

/// Generic sliding-window counter.
///
/// Increments `key` in sled and returns the new count.
/// The key is initialised with a TTL of `window_secs` on first touch.
/// Returns `Err(AppError::RateLimited)` if `count > limit`.
pub fn check(store: &Store, key: &str, limit: u64, window_secs: i64) -> Result<()> {
    let count = store.incr_expire(key, 1, window_secs)?;
    if count > limit {
        Err(AppError::RateLimited(format!(
            "limit of {limit} per {window_secs}s exceeded"
        )))
    } else {
        Ok(())
    }
}

// ─── Named helpers ────────────────────────────────────────────────────────────

/// 20 requests/min per IP for GET /auth/challenge.
pub fn challenge_by_ip(store: &Store, ip: &str) -> Result<()> {
    check(store, &format!("rl:challenge:ip:{ip}"), 20, WINDOW_SECS)
}

/// 10 attempts/min per IP for POST /auth/verify.
pub fn verify_by_ip(store: &Store, ip: &str) -> Result<()> {
    check(store, &format!("rl:verify:ip:{ip}"), 10, WINDOW_SECS)
}

/// 5 *failed* proofs/min per device_id for POST /auth/verify.
/// Call this only on verification failure.
pub fn verify_fail_by_device(store: &Store, device_id: &str) -> Result<()> {
    let key = format!("rl:verify:fail:dev:{device_id}");
    check(store, &key, 5, WINDOW_SECS)
}

/// 300 requests/min per session JTI for authenticated routes.
pub fn authenticated_by_jti(store: &Store, jti: &str) -> Result<()> {
    check(store, &format!("rl:auth:jti:{jti}"), 300, WINDOW_SECS)
}

/// Window for the hourly limiters below.
const HOUR_SECS: i64 = 3600;

/// 20 enrollment-package writes/hour per IP. The endpoint is unauthenticated,
/// so without this an attacker could fill the embedded store with 64 KiB blobs.
pub fn enrollment_package_store_by_ip(store: &Store, ip: &str) -> Result<()> {
    check(store, &format!("rl:enroll_pkg:store:ip:{ip}"), 20, HOUR_SECS)
}

/// 60 enrollment-package fetches/hour per IP (token-guessing throttle).
pub fn enrollment_package_fetch_by_ip(store: &Store, ip: &str) -> Result<()> {
    check(store, &format!("rl:enroll_pkg:fetch:ip:{ip}"), 60, HOUR_SECS)
}

/// 10 recovery initiations/hour per IP (anti-enumeration / WebAuthn state churn).
pub fn recovery_initiate_by_ip(store: &Store, ip: &str) -> Result<()> {
    check(store, &format!("rl:recover:init:ip:{ip}"), 10, HOUR_SECS)
}

/// 120 share sends/hour per sender (anti inbox-flooding of a targeted recipient).
pub fn share_send_by_sender(store: &Store, sender: &str) -> Result<()> {
    check(store, &format!("rl:share:send:user:{sender}"), 120, HOUR_SECS)
}

/// 30 ephemeral-web-session starts/hour per IP (the endpoint is unauthenticated).
pub fn web_session_start_by_ip(store: &Store, ip: &str) -> Result<()> {
    check(store, &format!("rl:websession:start:ip:{ip}"), 30, HOUR_SECS)
}

/// 120 polls/min per IP for GET /web-session/:id (browser polls every 2 s = 30/min normally;
/// 120 gives 4× headroom while still blocking enumeration attacks).
pub fn web_session_poll_by_ip(store: &Store, ip: &str) -> Result<()> {
    check(store, &format!("rl:websession:poll:ip:{ip}"), 120, WINDOW_SECS)
}

/// 60 key-fetches/min per authenticated user for GET /web-session/:id/keys
/// (anti-enumeration on the approver side).
pub fn web_session_keys_by_user(store: &Store, user_id: &str) -> Result<()> {
    check(store, &format!("rl:websession:keys:user:{user_id}"), 60, WINDOW_SECS)
}

/// 10 RW token attempts/min per session (throttle ephemeral-key proof guessing).
pub fn web_session_token_by_session(store: &Store, session_id: &str) -> Result<()> {
    check(
        store,
        &format!("rl:websession:token:{session_id}"),
        10,
        WINDOW_SECS,
    )
}

// ─── Exponential backoff enforcement ─────────────────────────────────────────

/// On consecutive failures (≥3) the spec mandates exponential backoff
/// (1s, 2s, 4s, … capped at 5 min).
///
/// Returns `Err(AppError::RateLimited)` if the device is still in a backoff window.
pub fn check_verify_backoff(store: &Store, device_id: &str) -> Result<()> {
    let backoff_key = format!("rl:verify:backoff:{device_id}");
    let ttl = store.ttl(&backoff_key)?;
    if ttl > 0 {
        return Err(AppError::RateLimited(format!(
            "exponential backoff active — retry after {ttl}s"
        )));
    }
    Ok(())
}

/// Record a failed authentication attempt and set/extend the backoff window.
pub fn record_verify_failure(store: &Store, device_id: &str) -> Result<()> {
    let fail_key = format!("rl:verify:fail:dev:{device_id}");
    let backoff_key = format!("rl:verify:backoff:{device_id}");
    let streak_key = format!("rl:verify:streak:{device_id}");

    let streak = store.incr_expire(&streak_key, 1, 300)?;

    let _ = store.incr_expire(&fail_key, 1, WINDOW_SECS);

    // Cap the effective streak: an attacker who knows a device_id can keep
    // failing proofs, but the backoff must never grow past the 300 s ceiling
    // and must not log-spam. The per-IP verify limit (rl:verify:ip) bites the
    // attacker long before this becomes a permanent device lockout.
    let eff_streak = streak.min(10);
    if eff_streak >= 3 {
        let exp = (eff_streak - 3).min(8); // cap at 2^8 = 256 s, below 5 min = 300 s
        let delay_secs: u64 = (1u64 << exp).min(300);
        store.set_ex(&backoff_key, &[1u8], delay_secs)?;
        if streak < 12 {
            tracing::warn!(device_id, streak, delay_secs, "auth verify backoff applied");
        }
    }
    Ok(())
}

/// Reset consecutive-failure streak after successful authentication.
pub fn reset_verify_streak(store: &Store, device_id: &str) -> Result<()> {
    let streak_key = format!("rl:verify:streak:{device_id}");
    let backoff_key = format!("rl:verify:backoff:{device_id}");
    let _ = store.del(&streak_key)?;
    let _ = store.del(&backoff_key)?;
    Ok(())
}

// ─── JTI tracking for device revocation cascade (SPEC §6) ────────────────────

/// Register a newly issued JTI against its device so revocation can enumerate it.
///
/// Adds `jti` to the set `device:jtis:{device_id}` and ensures the set's
/// TTL is at least the session hard cap (8 h).  The set self-cleans after 8 h
/// because no JTI can outlive the hard cap.
pub fn track_device_jti(store: &Store, device_id: &str, jti: &str) -> Result<()> {
    store.sadd(
        &format!("device:jtis:{device_id}"),
        jti,
        SESSION_HARD_CAP_SECS,
    )
}

/// Revoke every tracked JTI for `device_id` and delete the tracking set.
///
/// Called from `POST /device/revoke` to satisfy SPEC §6:
/// *"Revoking a device invalidates all active JTIs associated with that device_id."*
///
/// Each JTI is written to `jti:revoked:{jti}` with `TOKEN_MAX_LIFETIME_SECS` TTL
/// so the middleware rejects it on the next request.
pub fn revoke_all_device_jtis(store: &Store, device_id: &str) -> Result<()> {
    let jtis = store.smembers(&format!("device:jtis:{device_id}"))?;

    for jti in &jtis {
        store.set_ex(
            &format!("jti:revoked:{jti}"),
            &[1u8],
            TOKEN_MAX_LIFETIME_SECS,
        )?;
    }

    let _ = store.del_set(&format!("device:jtis:{device_id}"))?;
    Ok(())
}
