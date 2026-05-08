use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, Result},
    state::AppState,
};

const ENROLLMENT_PACKAGE_TTL_SECS: u64 = 15 * 60;
const MAX_ENROLLMENT_PACKAGE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
pub struct StoreEnrollmentPackageRequest {
    pub token: String,
    pub ciphertext: String,
}

#[derive(Serialize)]
pub struct FetchEnrollmentPackageResponse {
    pub ciphertext: String,
}

pub async fn post_enrollment_package(
    State(state): State<AppState>,
    Json(body): Json<StoreEnrollmentPackageRequest>,
) -> Result<Json<serde_json::Value>> {
    validate_token(&body.token)?;
    if body.ciphertext.is_empty() || body.ciphertext.len() > MAX_ENROLLMENT_PACKAGE_BYTES {
        return Err(AppError::BadRequest(
            "ciphertext must be between 1 byte and 64 KiB".into(),
        ));
    }

    state.store.set_ex(
        &package_key(&body.token),
        body.ciphertext.as_bytes(),
        ENROLLMENT_PACKAGE_TTL_SECS,
    )?;

    Ok(Json(serde_json::json!({
        "stored": true,
        "expires_in": ENROLLMENT_PACKAGE_TTL_SECS
    })))
}

pub async fn get_enrollment_package(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<FetchEnrollmentPackageResponse>> {
    validate_token(&token)?;
    let ciphertext = state
        .store
        .get_del(&package_key(&token))?
        .ok_or_else(|| AppError::NotFound("enrollment package not found or expired".into()))?;

    let ciphertext = String::from_utf8(ciphertext)
        .map_err(|_| AppError::Internal("stored enrollment package is not UTF-8".into()))?;

    Ok(Json(FetchEnrollmentPackageResponse { ciphertext }))
}

fn package_key(token: &str) -> String {
    format!("enrollment_package:{token}")
}

fn validate_token(token: &str) -> Result<()> {
    let valid = (32..=96).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        return Err(AppError::BadRequest(
            "invalid enrollment package token".into(),
        ));
    }
    Ok(())
}
