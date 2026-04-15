pub mod delete;

use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    rate_limit,
    state::AppState,
};

const HYBRID_EK_LEN: usize = 1568 + 32;
const HYBRID_VK_LEN: usize = 2592 + 32;
const CYCLO_PK_LEN: usize = 128 * 8;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub cyclo_pk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub device_id: Uuid,
}

pub async fn post_register(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    let ip = addr
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    rate_limit::check(&state.store, &format!("rl:register:ip:{ip}"), 5, 3600)?;

    let hybrid_ek = decode_b64_exact(&body.hybrid_ek, HYBRID_EK_LEN, "hybrid_ek")?;
    let hybrid_vk = decode_b64_exact(&body.hybrid_vk, HYBRID_VK_LEN, "hybrid_vk")?;
    let cyclo_pk = decode_b64_exact(&body.cyclo_pk, CYCLO_PK_LEN, "cyclo_pk")?;

    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let device_name = body
        .device_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Desktop Device".to_string());
    let device_type = body
        .device_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "desktop".to_string());

    state
        .db
        .execute(
            "INSERT INTO users (id, created_at) VALUES ($1, $2)",
            stoolap::params![user_id.to_string(), now.clone()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state.db.execute(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, cyclo_pk, enrolled_by, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9)",
        stoolap::params![
            device_id.to_string(),
            user_id.to_string(),
            device_name,
            device_type,
            now.clone(),
            crate::db::encode_b64(&hybrid_ek),
            crate::db::encode_b64(&hybrid_vk),
            crate::db::encode_b64(&cyclo_pk),
            now,
        ],
    ).map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(user_id = %user_id, device_id = %device_id, "account registered");

    Ok(Json(RegisterResponse { user_id, device_id }))
}

fn decode_b64_exact(encoded: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    let bytes = B64
        .decode(encoded)
        .map_err(|_| AppError::BadRequest(format!("{field} is not valid base64")))?;
    if bytes.len() != expected_len {
        return Err(AppError::BadRequest(format!(
            "{field} must be {expected_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}
