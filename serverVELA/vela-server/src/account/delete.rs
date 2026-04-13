//! DELETE /account
//!
//! Permanently deletes the authenticated user's account and all associated data:
//! devices, vault chunks, share inbox items (both sent and received), and
//! the encrypted recovery share.
//!
//! All active session tokens (JTIs) for every enrolled device are revoked in
//! the sled store so no further API access is possible after deletion.
//!
//! ## Important
//!
//! This action is **irreversible**.  The client should confirm with the user
//! before calling this endpoint.  The server does not retain any data after
//! deletion completes.

use axum::{extract::State, http::HeaderMap, Json};

use crate::{
    error::Result,
    middleware::AuthSession,
    rate_limit,
    state::AppState,
};

pub async fn delete_account(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    // ── Fetch all device IDs for this user (to revoke JTIs) ──────────────
    #[derive(sqlx::FromRow)]
    struct IdRow {
        id: uuid::Uuid,
    }

    let devices: Vec<IdRow> = sqlx::query_as(
        "SELECT id FROM devices WHERE user_id = $1",
    )
    .bind(session.user_id)
    .fetch_all(&state.db)
    .await?;

    // ── Revoke all JTIs for every device ─────────────────────────────────
    for dev in &devices {
        let _ = rate_limit::revoke_all_device_jtis(&state.store, &dev.id.to_string());
    }

    // ── Delete the user (cascades to devices, vault_chunks, share_inbox) ─
    let result = sqlx::query(
        "DELETE FROM users WHERE id = $1",
    )
    .bind(session.user_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(crate::error::AppError::NotFound(
            "account not found".into(),
        ));
    }

    tracing::warn!(
        user_id = %session.user_id,
        device_count = devices.len(),
        "account permanently deleted"
    );

    Ok((
        HeaderMap::new(),
        Json(serde_json::json!({
            "deleted": true,
            "user_id": session.user_id.to_string(),
        })),
    ))
}
