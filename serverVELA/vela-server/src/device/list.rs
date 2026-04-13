//! GET /devices
//!
//! Lists all devices enrolled for the authenticated user.
//! Returns device metadata (no key material) so the client can display the
//! device list for management (e.g., revoking a lost device).

use axum::{extract::State, http::HeaderMap, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    db::DeviceRow,
    error::Result,
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

#[derive(Serialize)]
pub struct DeviceInfo {
    pub id: Uuid,
    pub enrolled_by: Option<Uuid>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<DeviceInfo>,
}

pub async fn list_devices(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<ListDevicesResponse>)> {
    let rows = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, user_id, hybrid_ek, hybrid_vk, cyclo_pk,
                enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at
         FROM devices
         WHERE user_id = $1
         ORDER BY created_at ASC",
    )
    .bind(session.user_id)
    .fetch_all(&state.db)
    .await?;

    let devices = rows
        .into_iter()
        .map(|r| DeviceInfo {
            id: r.id,
            enrolled_by: r.enrolled_by,
            revoked: r.revoked,
            revoked_at: r.revoked_at,
            revoked_by: r.revoked_by,
            created_at: r.created_at,
        })
        .collect();

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(ListDevicesResponse { devices })))
}
