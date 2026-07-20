pub mod chunk;
pub mod oram;
pub mod sync;

use crate::{
    error::{AppError, Result},
    state::AppState,
};

const DEFAULT_MAX_USER_STORAGE_BYTES: u64 = 256 * 1024 * 1024;

/// Per-user storage ceiling in bytes (vault_chunks + oram_buckets payloads).
/// `MAX_USER_STORAGE_BYTES` overrides the 256 MiB default; the value is read
/// once and cached.
pub fn max_user_storage_bytes() -> u64 {
    static QUOTA: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *QUOTA.get_or_init(|| {
        std::env::var("MAX_USER_STORAGE_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MAX_USER_STORAGE_BYTES)
    })
}

/// Current on-disk payload usage for `user_id` across vault chunks and ORAM
/// buckets (base64-encoded ciphertext length, as stored).
fn current_usage_bytes(state: &AppState, user_id: &str) -> Result<u64> {
    let mut total: u64 = 0;
    for table in ["vault_chunks", "oram_buckets"] {
        let rows = state
            .db
            .query(
                &format!(
                    "SELECT COALESCE(SUM(LENGTH(ciphertext)), 0) FROM {table} WHERE user_id = $1"
                ),
                stoolap::params![user_id],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(row) = rows.into_iter().next() {
            let row = row.map_err(|e| AppError::Internal(e.to_string()))?;
            let v = crate::db::row_val(&row, 0)?;
            total = total.saturating_add(v.as_int64().unwrap_or(0).max(0) as u64);
        }
    }
    Ok(total)
}

/// Reject with 413 when `incoming` additional bytes would push the user past
/// their storage quota.
pub fn enforce_storage_quota(state: &AppState, user_id: &str, incoming: u64) -> Result<()> {
    let quota = max_user_storage_bytes();
    let usage = current_usage_bytes(state, user_id)?;
    if usage.saturating_add(incoming) > quota {
        return Err(AppError::PayloadTooLarge(format!(
            "storage quota of {quota} bytes exceeded (used {usage}, requested {incoming})"
        )));
    }
    Ok(())
}
