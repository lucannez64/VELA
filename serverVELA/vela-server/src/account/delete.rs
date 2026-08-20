use axum::{extract::State, http::HeaderMap, Json};

use crate::{
    error::{AppError, Result},
    middleware::DeviceSession,
    rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

pub async fn delete_account(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let rows = state
        .sqldb
        .query(
            "SELECT id FROM devices WHERE user_id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    for row in &rows {
        if let Some(id_str) = row.text(0) {
            let _ = rate_limit::revoke_all_device_jtis(&state.store, id_str);
        }
    }

    // Kill web sessions: revoke every issued RW token (device_id == session_id)
    // for the maximum possible remaining lifetime, drop tracked JTIs, then
    // delete the rows.
    let ws_rows = state
        .sqldb
        .query(
            "SELECT id FROM web_sessions WHERE user_id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    for row in &ws_rows {
        if let Some(id_str) = row.text(0) {
            let _ = state.store.set_ex(
                &format!("device:revoked:{id_str}"),
                &[1u8],
                crate::web_session::MAX_TTL_SECS as u64,
            );
            let _ = rate_limit::revoke_all_device_jtis(&state.store, id_str);
        }
    }

    state
        .sqldb
        .execute(
            "DELETE FROM web_sessions WHERE user_id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .sqldb
        .execute(
            "DELETE FROM share_inbox WHERE recipient_user_id = ? OR sender_user_id = ?",
            vec![
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .sqldb
        .execute(
            "DELETE FROM shared_items WHERE recipient_user_id = ? OR sender_user_id = ?",
            vec![
                TursoValue::Text(session.user_id.to_string()),
                TursoValue::Text(session.user_id.to_string()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .sqldb
        .execute(
            "DELETE FROM vault_chunks WHERE user_id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .sqldb
        .execute(
            "DELETE FROM oram_buckets WHERE user_id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .sqldb
        .execute(
            "DELETE FROM devices WHERE user_id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Web-session-only accounts legitimately have zero rows in `devices`
    // (a web-session RW token uses session_id as device_id and carries no
    // devices row — see the comment in middleware.rs), so device count is
    // not a valid existence signal: it previously reported "account not
    // found" for such accounts even though the delete above just genuinely
    // deleted them. Check the `users` delete's own affected-row count
    // instead, and check it before treating the operation as done — that
    // row is the actual account record.
    let users_n = state
        .sqldb
        .execute(
            "DELETE FROM users WHERE id = ?",
            vec![TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if users_n == 0 {
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
