pub mod chunk;
pub mod events;
pub mod oram;
pub mod rekey;
pub mod sync;
#[cfg(test)]
mod conformance;
pub mod schema;
pub mod sql;

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
async fn current_usage_bytes(state: &AppState, user_id: &str) -> Result<u64> {
    use vela_rekey_policy::executor::{
        classify_usage, plan_usage_chunks, plan_usage_oram, ReadOutcome, UsageObservation,
    };
    // Only rows at the account's served epoch are reachable by readers.
    // Superseded rows left behind by a failed commit sweep and future shadow
    // rows must not count against the user.
    let user = user_id.to_string();
    let mut read_error: Option<anyhow::Error> = None;
    let mut sql = crate::vault::sql::PoolSql(state);
    let chunks = match crate::vault::sql::run_read(&mut sql, &plan_usage_chunks(user.clone())).await
    {
        Ok(rows) => ReadOutcome::Rows(crate::vault::sql::scalar_view(&rows)),
        Err(error) => {
            read_error = Some(error);
            ReadOutcome::Failed
        }
    };
    // The historical query loop stopped at the first failure.
    let oram = if matches!(chunks, ReadOutcome::Failed) {
        ReadOutcome::Failed
    } else {
        match crate::vault::sql::run_read(&mut sql, &plan_usage_oram(user)).await {
            Ok(rows) => ReadOutcome::Rows(crate::vault::sql::scalar_view(&rows)),
            Err(error) => {
                read_error = Some(error);
                ReadOutcome::Failed
            }
        }
    };
    match classify_usage(&chunks, &oram) {
        UsageObservation::Measured { chunks, oram } => {
            Ok((chunks as u64).saturating_add(oram as u64))
        }
        UsageObservation::Storage => Err(AppError::Internal(match read_error {
            Some(error) => error.to_string(),
            None => "storage quota query failed".into(),
        })),
    }
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
    use vela_rekey_policy::executor::{
        classify_projected_usage, plan_rekey_projection, ProjectedUsageObservation, ReadOutcome,
    };
    let plan = plan_rekey_projection(
        user_id.to_string(),
        shadow_epoch,
        chunk_id.to_string(),
    );
    let mut sql = crate::vault::sql::PoolSql(state);
    let mut read_error: Option<anyhow::Error> = None;
    let outcome = match crate::vault::sql::run_read(&mut sql, &plan).await {
        Ok(rows) => ReadOutcome::Rows(crate::vault::sql::scalar_view(&rows)),
        Err(error) => {
            read_error = Some(error);
            ReadOutcome::Failed
        }
    };
    let projected = match classify_projected_usage(&outcome) {
        ProjectedUsageObservation::Measured(projected) => projected as u64,
        ProjectedUsageObservation::Storage => {
            return Err(AppError::Internal(match read_error {
                Some(error) => error.to_string(),
                None => "storage quota query failed".into(),
            }));
        }
    };
    let quota = max_user_storage_bytes();
    if projected.saturating_add(incoming_stored) > quota {
        return Err(AppError::PayloadTooLarge(format!(
            "storage quota of {quota} bytes exceeded by rotated vault"
        )));
    }
    Ok(())
}
