use axum::{extract::State, http::HeaderMap, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    sqldb::Db as _,
    state::AppState,
};

#[derive(Serialize)]
pub struct DeviceInfo {
    pub id: Uuid,
    pub name: String,
    pub device_type: String,
    pub enrolled_by: Option<Uuid>,
    pub last_active: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub pending: bool,
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
    session: DeviceSession,
) -> Result<(HeaderMap, Json<ListDevicesResponse>)> {
    let rows = state
        .sqldb
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at
             FROM devices
             WHERE user_id = ?
             ORDER BY created_at ASC
             LIMIT 1000",
            vec![crate::sqldb::TursoValue::Text(session.user_id.to_string())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let devices: Vec<DeviceInfo> = rows
        .iter()
        .map(|row| {
            let d = crate::db::parse_device_row_turso(row)?;
            Ok(DeviceInfo {
                id: d.id,
                name: d.device_name,
                device_type: d.device_type,
                enrolled_by: d.enrolled_by,
                last_active: d.last_active,
                revoked: d.revoked,
                pending: d.last_active.is_none() && d.rms_capsule.is_some() && !d.revoked,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqldb::{Db as _, TursoDb, TursoValue};

    async fn temp_i64() -> i64 {
        use std::sync::atomic::{AtomicI64, Ordering};
        static N: AtomicI64 = AtomicI64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    async fn temp_db() -> TursoDb {
        let path = format!("{}/vela-list-test-{}.db", std::env::temp_dir().display(), temp_i64().await);
        let _ = std::fs::remove_file(&path);
        TursoDb::open(&path, 1).await.unwrap()
    }

    async fn insert_device(db: &TursoDb, id: &str, user: &str, name: &str, typ: &str, approved: bool) {
        let ek = crate::db::encode_b64(&[0u8; 32]);
        let vk = crate::db::encode_b64(&[1u8; 64]);
        let created = "2026-01-01T00:00:00Z".to_string();
        let _ = db
            .execute(
                "INSERT INTO devices (id, user_id, device_name, device_type, \
                 hybrid_ek, hybrid_vk, revoked, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    TursoValue::Text(id.into()),
                    TursoValue::Text(user.into()),
                    TursoValue::Text(name.into()),
                    TursoValue::Text(typ.into()),
                    TursoValue::Text(ek),
                    TursoValue::Text(vk),
                    TursoValue::Integer(if approved { 0 } else { 1 }),
                    TursoValue::Text(created),
                ],
            )
            .await;
    }

    // Exercise the ported list_devices query + parse_device_row_turso path
    // (same SQL/params the handler uses) against a real turso DB.
    #[tokio::test]
    async fn list_devices_query_returns_devices_for_user() {
        let db = temp_db().await;
        let u1 = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let u2 = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        insert_device(&db, "1111aaaa-1111-1111-1111-111111111111", u1, "Laptop", "desktop", true).await;
        insert_device(&db, "2222bbbb-2222-2222-2222-222222222222", u1, "Phone", "mobile", true).await;
        insert_device(&db, "3333cccc-3333-3333-3333-333333333333", u1, "Old", "desktop", false).await;
        insert_device(&db, "4444dddd-4444-4444-4444-444444444444", u2, "Other", "desktop", true).await;

        let rows = db
            .query(
                "SELECT id, user_id, device_name, device_type, last_active,
                    hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, revoked,
                    revoked_at, revoked_by, created_at
                 FROM devices WHERE user_id = ? ORDER BY created_at ASC LIMIT 1000",
                vec![TursoValue::Text(u1.into())],
            )
            .await
            .unwrap();

        let infos: Vec<_> = rows
            .iter()
            .map(|r| {
                let d = crate::db::parse_device_row_turso(r).unwrap();
                (d.id.to_string(), d.device_name, d.device_type, d.revoked)
            })
            .collect();

        assert_eq!(infos.len(), 3, "u1 has 3 devices");
        assert_eq!(infos[0].0, "1111aaaa-1111-1111-1111-111111111111");
        assert_eq!(infos[0].1, "Laptop");
        assert_eq!(infos[0].3, false);
        assert_eq!(infos[2].0, "3333cccc-3333-3333-3333-333333333333");
        assert_eq!(infos[2].3, true, "revoked device is revoked");
        // revoked integer 0/1 round-trips to bool via hybrid_ek/vk decode
        assert!(crate::db::parse_device_row_turso(&rows[0]).unwrap().hybrid_vk.len() == 64);
    }
}
