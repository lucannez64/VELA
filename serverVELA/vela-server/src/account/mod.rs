pub mod delete;

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    auth::token::TokenService,
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

const HYBRID_EK_LEN: usize = 1568 + 32;
const HYBRID_VK_LEN: usize = 2592 + 32;
const SHARE_EK_LEN: usize = 1568 + 32; // ML-KEM-1024 EK (1568) + X25519 PK (32)

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    /// M19: only accepted together with a binding signature under the
    /// presented `hybrid_vk` — an unsigned share key can no longer be
    /// provisioned at all, so substitution always requires a device's
    /// private identity key.
    #[serde(default)]
    pub share_ek: Option<String>,
    #[serde(default)]
    pub share_ek_signed_at: Option<String>,
    #[serde(default)]
    pub share_ek_signature: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub device_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

pub async fn post_register(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);

    rate_limit::check(&state.store, &format!("rl:register:ip:{ip}"), 5, 3600)?;

    // The per-IP limit bounds one source, not a botnet rotating through
    // addresses. An operator who set MAX_ACCOUNTS gets a hard ceiling too.
    if let Some(max_accounts) = state.config.max_accounts {
        let rows = state
            .sqldb
            .query("SELECT COUNT(*) FROM users", vec![])
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let count = rows
            .first()
            .and_then(|r| r.i64(0))
            .unwrap_or(0);
        if count as u64 >= max_accounts {
            // Deliberately not "the server is full with N accounts": how many
            // users a deployment has is not the caller's business.
            return Err(AppError::BadRequest(
                "this server is not accepting new accounts".into(),
            ));
        }
    }

    let hybrid_ek = decode_b64_exact(&body.hybrid_ek, HYBRID_EK_LEN, "hybrid_ek")?;
    let hybrid_vk = decode_b64_exact(&body.hybrid_vk, HYBRID_VK_LEN, "hybrid_vk")?;
    // M19: an initial share key must be signed by the very identity key this
    // account is being created with. Unsigned provisioning is refused so
    // every registered share key traces to a device signature.
    let share_ek_b64 = match body.share_ek.as_deref() {
        Some(s) => {
            let ek = decode_b64_exact(s, SHARE_EK_LEN, "share_ek")?;
            let signed_at = body
                .share_ek_signed_at
                .as_deref()
                .filter(|t| !t.is_empty() && (20..=64).contains(&t.len()))
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "share_ek_signed_at (RFC 3339) is required with share_ek".into(),
                    )
                })?;
            let signature = B64
                .decode(
                    body.share_ek_signature
                        .as_deref()
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "share_ek_signature is required with share_ek".into(),
                            )
                        })?
                        .as_bytes(),
                )
                .map_err(|_| AppError::BadRequest("share_ek_signature is not valid base64".into()))?;
            let message =
                vela_crypto::signing::share_ek_binding_message(&ek, signed_at);
            crate::device::enroll::verify_hybrid_signature(
                &hybrid_vk,
                &message,
                &signature,
                "share-key binding signature invalid",
            )?;
            s.to_string()
        }
        None => String::new(),
    };

    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let device_name = body
        .device_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Desktop Device".to_string());
    let device_type = body
        .device_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "desktop".to_string());

    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at, share_ek, share_ek_since)
             VALUES (?, ?, ?, ?)",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(now.clone()),
                TursoValue::Text(share_ek_b64.clone()),
                TursoValue::Text(
                    body.share_ek
                        .as_deref()
                        .map(|_| now.clone())
                        .unwrap_or_default(),
                ),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state.sqldb.execute(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
        vec![
            TursoValue::Text(device_id.to_string()),
            TursoValue::Text(user_id.to_string()),
            TursoValue::Text(device_name),
            TursoValue::Text(device_type),
            TursoValue::Text(now.clone()),
            TursoValue::Text(crate::db::encode_b64(&hybrid_ek)),
            TursoValue::Text(crate::db::encode_b64(&hybrid_vk)),
            TursoValue::Text(now),
        ],
    ).await.map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(user_id = %user_id, device_id = %device_id, "account registered");

    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let (token, jti) = ts.issue(user_id, device_id, None)?;
    rate_limit::track_device_jti(&state.store, &device_id.to_string(), &jti)?;

    Ok(Json(RegisterResponse {
        user_id,
        device_id,
        token: Some(token),
    }))
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
