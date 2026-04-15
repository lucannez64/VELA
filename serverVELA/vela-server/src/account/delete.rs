use axum::{extract::State, http::HeaderMap, Json};

use crate::{
    error::{AppError, Result},
    middleware::AuthSession,
    rate_limit,
    state::AppState,
};

pub async fn delete_account(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let rows = state
        .db
        .query(
            "SELECT id FROM devices WHERE user_id = $1",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    for row_result in rows {
        let row = row_result.map_err(|e| AppError::Internal(e.to_string()))?;
        let v = crate::db::row_val(&row, 0)?;
        if let Some(id_str) = v.as_str() {
            let _ = rate_limit::revoke_all_device_jtis(&state.store, id_str);
        }
    }

    state
        .db
        .execute(
            "DELETE FROM share_inbox WHERE recipient_user_id = $1 OR sender_user_id = $1",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .db
        .execute(
            "DELETE FROM vault_chunks WHERE user_id = $1",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let device_n: i64 = state
        .db
        .execute(
            "DELETE FROM devices WHERE user_id = $1",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .db
        .execute(
            "DELETE FROM users WHERE id = $1",
            stoolap::params![session.user_id.to_string()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if device_n == 0 {
        return Err(AppError::NotFound("account not found".into()));
    }

    tracing::warn!(
        user_id = %session.user_id,
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
