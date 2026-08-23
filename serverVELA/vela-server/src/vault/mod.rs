pub mod chunk;
pub mod oram;
pub mod rekey;
pub mod sync;

use crate::{
    error::{AppError, Result},
    sqldb::{Db as _, TursoValue},
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
async fn current_usage_bytes(state: &AppState, user_id: &str) -> Result<u64> {
    let mut total: u64 = 0;
    // Only rows at the account's served epoch are reachable by readers.
    // Superseded rows left behind by a failed commit sweep and future shadow
    // rows must not count against the user.
    for table in ["vault_chunks", "oram_buckets"] {
        let rows = state
            .sqldb
            .query(
                &format!(
                    "SELECT COALESCE(SUM(LENGTH(t.ciphertext)), 0) FROM {table} t
                     JOIN users u ON u.id = t.user_id
                     WHERE t.user_id = ? AND t.epoch = u.key_epoch"
                ),
                vec![TursoValue::Text(user_id.to_string())],
            )
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(row) = rows.first() {
            total = total.saturating_add(row.i64(0).unwrap_or(0).max(0) as u64);
        }
    }
    Ok(total)
}

/// Reject with 413 when `incoming` additional bytes would push the user past
/// their storage quota.
pub async fn enforce_storage_quota(state: &AppState, user_id: &str, incoming: u64) -> Result<()> {
    let quota = max_user_storage_bytes();
    let usage = current_usage_bytes(state, user_id).await?;
    if usage.saturating_add(incoming) > quota {
        return Err(AppError::PayloadTooLarge(format!(
            "storage quota of {quota} bytes exceeded (used {usage}, requested {incoming})"
        )));
    }
    Ok(())
}

/// Enforce quota against the state which would remain after a successful
/// rotation. Current-epoch rows are replacements, not permanent additional
/// usage, and a replay replaces its existing shadow rather than growing it.
pub(crate) async fn enforce_rekey_shadow_quota(
    state: &AppState,
    user_id: &str,
    shadow_epoch: i64,
    chunk_id: &str,
    incoming_stored: u64,
) -> Result<()> {
    let rows = state
        .sqldb
        .query(
            "SELECT
                (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0)
                   FROM vault_chunks
                  WHERE user_id = ? AND epoch = ? AND chunk_id != ?) +
                (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0)
                   FROM oram_buckets WHERE user_id = ?)",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Integer(shadow_epoch),
                TursoValue::Text(chunk_id.to_string()),
                TursoValue::Text(user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let projected = rows.first().and_then(|row| row.i64(0)).unwrap_or(0).max(0) as u64;
    let quota = max_user_storage_bytes();
    if projected.saturating_add(incoming_stored) > quota {
        return Err(AppError::PayloadTooLarge(format!(
            "storage quota of {quota} bytes exceeded by rotated vault"
        )));
    }
    Ok(())
}
