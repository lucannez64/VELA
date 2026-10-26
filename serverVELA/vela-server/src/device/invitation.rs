use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use vela_enrollment_policy::pairing_driver::{
    begin_redeem_package, begin_store_package, on_package_redeemed_event, on_package_written_event,
    PackageStoreObservation, PackageTokenObservation, PairingEffect, PairingFailure,
    RedeemObservation, StoreObservation,
};

use crate::{
    error::{AppError, Result},
    net, rate_limit,
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
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<StoreEnrollmentPackageRequest>,
) -> Result<Json<serde_json::Value>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enrollment_package_store_by_ip(&state.store, &ip)?;

    // Every post-validation decision below belongs to the extracted driver:
    // whether the request may write at all, and how the write outcome is
    // classified. The handler only performs the returned effect.
    let start = begin_store_package(PackageStoreObservation {
        token_valid: validate_token(&body.token).is_ok(),
        ciphertext_len_valid: !body.ciphertext.is_empty()
            && body.ciphertext.len() <= MAX_ENROLLMENT_PACKAGE_BYTES,
    });
    debug_assert!(matches!(
        start.effect,
        PairingEffect::StorePackage | PairingEffect::Fail(_)
    ));
    let stored_error = match start.effect {
        PairingEffect::StorePackage => match state.store.set_ex(
            &package_key(&body.token),
            body.ciphertext.as_bytes(),
            ENROLLMENT_PACKAGE_TTL_SECS,
        ) {
            Ok(()) => None,
            Err(error) => Some(error),
        },
        PairingEffect::Fail(failure) => return Err(invitation_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected package-store effect".into(),
            ))
        }
    };

    let observation = if stored_error.is_some() {
        StoreObservation::Failed
    } else {
        StoreObservation::Stored
    };
    let transition = on_package_written_event(start.driver, observation);
    match transition.effect {
        PairingEffect::Complete => Ok(Json(serde_json::json!({
            "stored": true,
            "expires_in": ENROLLMENT_PACKAGE_TTL_SECS
        }))),
        PairingEffect::Fail(PairingFailure::PackageStorage) => Err(stored_error.unwrap_or_else(|| {
            AppError::Internal("enrollment package store failed".into())
        })),
        PairingEffect::Fail(failure) => Err(invitation_failure_error(failure)),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected package-store observation effect".into(),
        )),
    }
}

pub async fn get_enrollment_package(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(path_token): Path<String>,
) -> Result<Json<FetchEnrollmentPackageResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enrollment_package_fetch_by_ip(&state.store, &ip)?;

    // Prefer the token from a header over the URL path: URLs are commonly
    // written to access/proxy/CDN logs by default, while custom headers
    // typically are not. The path segment stays for route compatibility and
    // as a fallback if something in between strips unrecognized headers.
    let token = headers
        .get("x-enrollment-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or(path_token);

    let start = begin_redeem_package(PackageTokenObservation {
        token_valid: validate_token(&token).is_ok(),
    });
    let removed = match start.effect {
        // The destructive read is the only way a package is handed out, and
        // the driver authorizes it at most once per request.
        PairingEffect::RedeemPackage => state.store.get_del(&package_key(&token))?,
        PairingEffect::Fail(failure) => return Err(invitation_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected package-redeem effect".into(),
            ))
        }
    };

    let observation = match &removed {
        None => RedeemObservation::Missing,
        Some(bytes) => RedeemObservation::Present {
            utf8_valid: std::str::from_utf8(bytes).is_ok(),
        },
    };
    let transition = on_package_redeemed_event(start.driver, observation);
    match transition.effect {
        PairingEffect::Complete => {
            let bytes = removed.ok_or_else(|| {
                AppError::Internal("redemption driver completed without a package".into())
            })?;
            let ciphertext = String::from_utf8(bytes)
                .map_err(|_| AppError::Internal("stored enrollment package is not UTF-8".into()))?;
            Ok(Json(FetchEnrollmentPackageResponse { ciphertext }))
        }
        PairingEffect::Fail(failure) => Err(invitation_failure_error(failure)),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected package-redeem observation effect".into(),
        )),
    }
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

/// Render the driver's failure with the handler's historical status/message.
fn invitation_failure_error(failure: PairingFailure) -> AppError {
    match failure {
        PairingFailure::InvalidToken => {
            AppError::BadRequest("invalid enrollment package token".into())
        }
        PairingFailure::InvalidCiphertext => {
            AppError::BadRequest("ciphertext must be between 1 byte and 64 KiB".into())
        }
        PairingFailure::PackageUnavailable => {
            AppError::NotFound("enrollment package not found or expired".into())
        }
        PairingFailure::PackageNotUtf8 => {
            AppError::Internal("stored enrollment package is not UTF-8".into())
        }
        // The storage variant is rendered from the retained store error at the
        // call site; keep a total fallback.
        PairingFailure::PackageStorage => {
            AppError::Internal("enrollment package store failed".into())
        }
        _ => AppError::Internal("pairing driver produced an unexpected failure".into()),
    }
}
