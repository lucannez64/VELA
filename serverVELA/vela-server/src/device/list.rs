use axum::{extract::State, http::HeaderMap, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
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
    let rows = state.db.query(
        "SELECT id, user_id, hybrid_ek, hybrid_vk, cyclo_pk,
                enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at
         FROM devices
         WHERE user_id = $1
         ORDER BY created_at ASC",
        stoolap::params![session.user_id.to_string()],
    ).map_err(|e| AppError::Internal(e.to_string()))?;

    let devices: Vec<DeviceInfo> = rows
        .map(|r| {
            let row = r.map_err(|e| AppError::Internal(e.to_string()))?;
            let d = crate::db::parse_device_row(&row)?;
            Ok(DeviceInfo {
                id: d.id,
                enrolled_by: d.enrolled_by,
                revoked: d.revoked,
                revoked_at: d.revoked_at,
                revoked_by: d.revoked_by,
                created_at: d.created_at,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(ListDevicesResponse { devices })))
}
