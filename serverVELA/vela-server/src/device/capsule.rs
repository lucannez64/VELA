//! GET /device/capsule
//!
//! Allows a newly-enrolled device (Device B) to download the RMS capsule that
//! Device A stored for it during `POST /device/enroll`.  Device B must first
//! authenticate via `/auth/challenge` + `/auth/verify` to prove possession of
//! the Cyclo private key it registered with, then call this endpoint.
//!
//! ## Spec reference (§4.2, step 6)
//!
//! > "Device B downloads the capsule, decapsulates it to recover the RMS,
//! > provisions its own local Secure Enclave, and appends a signed entry to
//! > the encrypted device audit log."
//!
//! ## One-time semantics
//!
//! The capsule is cleared from the database after a successful download.
//! Subsequent calls return `404 Not Found`.  If the device loses the RMS
//! before writing it to its enclave it must be re-enrolled by Device A.
//!
//! ## Response
//!
//! ```json
//! { "capsule": "<base64>" }
//! ```

use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::Serialize;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

#[derive(Serialize)]
pub struct CapsuleResponse {
    /// Base64-encoded RMS capsule (Hybrid KEM ciphertext).
    pub capsule: String,
}

pub async fn get_capsule(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<(HeaderMap, Json<CapsuleResponse>)> {
    // ── Atomically fetch + clear capsule (one-time download) ──────────────
    // Uses UPDATE ... RETURNING so that concurrent requests cannot both read
    // the capsule before it is nulled.  The first request to hit this query
    // wins; all others see NULL and get 404.
    #[derive(sqlx::FromRow)]
    struct Row { rms_capsule: Option<Vec<u8>> }

    let row = sqlx::query_as::<_, Row>(
        r#"
        UPDATE devices
           SET rms_capsule = NULL
         WHERE id = $1
           AND user_id = $2
           AND revoked = FALSE
           AND rms_capsule IS NOT NULL
     RETURNING rms_capsule
        "#,
    )
    .bind(session.device_id)
    .bind(session.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(
        "no capsule available — device may be the first device, \
         or the capsule has already been downloaded".into(),
    ))?;

    let capsule_bytes = row.rms_capsule
        .ok_or_else(|| AppError::NotFound(
            "no capsule available — device may be the first device, \
             or the capsule has already been downloaded".into(),
        ))?;

    tracing::info!(
        device_id = %session.device_id,
        user_id   = %session.user_id,
        "RMS capsule downloaded and cleared"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((headers, Json(CapsuleResponse { capsule: B64.encode(&capsule_bytes) })))
}
