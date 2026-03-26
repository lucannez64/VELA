//! Redis-backed rate limiting (sliding-window counter) and JTI tracking.
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
//! Every issued JTI is added to `device:jtis:{device_id}` (a Redis Set).
//! On `POST /device/revoke`, all JTIs in that set are individually written to
//! `jti:revoked:{jti}` — giving the middleware exact, per-token revocation.
//! The device-revoked sentinel is kept as a backstop for any JTIs that were
//! issued after Redis was flushed or before tracking was in place.
//!
//! Key TTLs:
//!   `device:jtis:{device_id}` — 8 hours (= session hard cap)
//!   `jti:revoked:{jti}`       — TOKEN_MAX_LIFETIME_SECS (15 min)

use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::error::{AppError, Result};

const WINDOW_SECS: i64 = 60;
/// Maximum PASETO token lifetime in seconds (15 minutes).
pub const TOKEN_MAX_LIFETIME_SECS: u64 = 15 * 60;
/// Session hard-cap in seconds (8 hours) — used as the device JTI-set TTL.
const SESSION_HARD_CAP_SECS: i64 = 8 * 60 * 60;

/// Generic sliding-window counter.
///
/// Increments `key` in Redis and returns the new count.
/// The key is initialised with a TTL of `window_secs` on first touch.
/// Returns `Err(AppError::RateLimited)` if `count > limit`.
pub async fn check(
    redis: &mut ConnectionManager,
    key: &str,
    limit: u64,
    window_secs: i64,
) -> Result<()> {
    let count: u64 = redis::pipe()
        .atomic()
        .incr(key, 1_u64)
        .expire(key, window_secs)
        .ignore()
        .query_async::<_, (u64,)>(redis)
        .await
        .map(|(c,)| c)
        .map_err(AppError::Redis)?;

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
pub async fn challenge_by_ip(redis: &mut ConnectionManager, ip: &str) -> Result<()> {
    check(redis, &format!("rl:challenge:ip:{ip}"), 20, WINDOW_SECS).await
}

/// 10 attempts/min per IP for POST /auth/verify.
pub async fn verify_by_ip(redis: &mut ConnectionManager, ip: &str) -> Result<()> {
    check(redis, &format!("rl:verify:ip:{ip}"), 10, WINDOW_SECS).await
}

/// 5 *failed* proofs/min per device_id for POST /auth/verify.
/// Call this only on verification failure.
pub async fn verify_fail_by_device(
    redis: &mut ConnectionManager,
    device_id: &str,
) -> Result<()> {
    let key = format!("rl:verify:fail:dev:{device_id}");
    check(redis, &key, 5, WINDOW_SECS).await
}

/// 300 requests/min per session JTI for authenticated routes.
pub async fn authenticated_by_jti(redis: &mut ConnectionManager, jti: &str) -> Result<()> {
    check(redis, &format!("rl:auth:jti:{jti}"), 300, WINDOW_SECS).await
}

// ─── Exponential backoff enforcement ─────────────────────────────────────────

/// On consecutive failures (≥3) the spec mandates exponential backoff
/// (1s, 2s, 4s, … capped at 5 min).  We implement this as a Redis key that
/// carries the current backoff deadline.
///
/// Returns `Err(AppError::RateLimited)` if the device is still in a backoff window.
pub async fn check_verify_backoff(
    redis: &mut ConnectionManager,
    device_id: &str,
) -> Result<()> {
    let backoff_key = format!("rl:verify:backoff:{device_id}");
    let ttl: i64 = redis.ttl(&backoff_key).await.map_err(AppError::Redis)?;
    if ttl > 0 {
        return Err(AppError::RateLimited(format!(
            "exponential backoff active — retry after {ttl}s"
        )));
    }
    Ok(())
}

/// Record a failed proof attempt and set/extend the backoff window.
pub async fn record_verify_failure(
    redis: &mut ConnectionManager,
    device_id: &str,
) -> Result<()> {
    let fail_key   = format!("rl:verify:fail:dev:{device_id}");
    let backoff_key = format!("rl:verify:backoff:{device_id}");
    let streak_key = format!("rl:verify:streak:{device_id}");

    // Count consecutive failures (reset to 0 on success — see auth/verify.rs).
    let streak: i64 = redis.incr(&streak_key, 1_i64).await.map_err(AppError::Redis)?;
    let _: () = redis.expire(&streak_key, 300_i64).await.map_err(AppError::Redis)?;

    // Fail counter for the 5/min rate limit.
    let _: () = redis.incr(&fail_key, 1_u64).await.map_err(AppError::Redis)?;
    let _: () = redis.expire(&fail_key, WINDOW_SECS).await.map_err(AppError::Redis)?;

    // Backoff schedule: first two failures are within rate-limit only;
    // from the 3rd consecutive failure onward apply exponential backoff.
    if streak >= 3 {
        let exp = (streak - 3).min(8); // cap at 2^8 = 256 s, below 5 min = 300 s
        let delay_secs: i64 = (1_i64 << exp).min(300);
        let _: () = redis.set_ex(&backoff_key, 1_u8, delay_secs as u64).await.map_err(AppError::Redis)?;
        tracing::warn!(device_id, streak, delay_secs, "auth verify backoff applied");
    }
    Ok(())
}

/// Reset consecutive-failure streak after a successful proof.
pub async fn reset_verify_streak(
    redis: &mut ConnectionManager,
    device_id: &str,
) -> Result<()> {
    let streak_key  = format!("rl:verify:streak:{device_id}");
    let backoff_key = format!("rl:verify:backoff:{device_id}");
    let _: () = redis.del(&streak_key).await.map_err(AppError::Redis)?;
    let _: () = redis.del(&backoff_key).await.map_err(AppError::Redis)?;
    Ok(())
}

// ─── JTI tracking for device revocation cascade (SPEC §6) ────────────────────

/// Register a newly issued JTI against its device so revocation can enumerate it.
///
/// Adds `jti` to the Redis Set `device:jtis:{device_id}` and ensures the set's
/// TTL is at least the session hard cap (8 h).  The set self-cleans after 8 h
/// because no JTI can outlive the hard cap.
pub async fn track_device_jti(
    redis: &mut ConnectionManager,
    device_id: &str,
    jti: &str,
) -> Result<()> {
    let set_key = format!("device:jtis:{device_id}");
    let _: () = redis.sadd(&set_key, jti).await.map_err(AppError::Redis)?;
    // Reset the TTL to 8 h so the set survives at least as long as the newest JTI.
    let _: () = redis
        .expire(&set_key, SESSION_HARD_CAP_SECS)
        .await
        .map_err(AppError::Redis)?;
    Ok(())
}

/// Revoke every tracked JTI for `device_id` and delete the tracking set.
///
/// Called from `POST /device/revoke` to satisfy SPEC §6:
/// *"Revoking a device invalidates all active JTIs associated with that device_id."*
///
/// Each JTI is written to `jti:revoked:{jti}` with `TOKEN_MAX_LIFETIME_SECS` TTL
/// so the middleware rejects it on the next request — regardless of how much time
/// remains on the token's own `exp` claim.
pub async fn revoke_all_device_jtis(
    redis: &mut ConnectionManager,
    device_id: &str,
) -> Result<()> {
    let set_key = format!("device:jtis:{device_id}");
    let jtis: Vec<String> = redis.smembers(&set_key).await.map_err(AppError::Redis)?;

    if !jtis.is_empty() {
        let mut pipe = redis::pipe();
        pipe.atomic();
        for jti in &jtis {
            pipe.cmd("SET")
                .arg(format!("jti:revoked:{jti}"))
                .arg(1_u8)
                .arg("EX")
                .arg(TOKEN_MAX_LIFETIME_SECS)
                .ignore();
        }
        pipe.del(&set_key).ignore();
        let _: () = pipe.query_async(redis).await.map_err(AppError::Redis)?;
    } else {
        // No tracked JTIs (e.g., Redis was flushed) — the device-revoked sentinel
        // in the caller covers this case.
        let _: () = redis.del(&set_key).await.map_err(AppError::Redis)?;
    }
    Ok(())
}
