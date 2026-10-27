use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use vela_enrollment_policy::pairing_driver::{
    PackageStoreObservation, PackageTokenObservation, PairingEffect, PairingFailure,
    RedeemObservation, StoreObservation,
};

use super::pairing_executor::PairingExecutor;
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

/// The I/O behind the package-store ceremony. The driver decides whether the
/// write may happen at all and how its outcome is classified; this executor
/// performs only the one effect the proved loop hands it.
struct StorePackageIo<'a> {
    state: &'a AppState,
    token: String,
    ciphertext: String,
    error: Option<AppError>,
}

impl PairingExecutor for StorePackageIo<'_> {
    async fn store_package(&mut self) -> StoreObservation {
        match self.state.store.set_ex(
            &package_key(&self.token),
            self.ciphertext.as_bytes(),
            ENROLLMENT_PACKAGE_TTL_SECS,
        ) {
            Ok(()) => StoreObservation::Stored,
            Err(error) => {
                if self.error.is_none() {
                    self.error = Some(error);
                }
                StoreObservation::Failed
            }
        }
    }
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
    let start = vela_enrollment_policy::pairing_interpreter::start_store_package(
        PackageStoreObservation {
            token_valid: validate_token(&body.token).is_ok(),
            ciphertext_len_valid: !body.ciphertext.is_empty()
                && body.ciphertext.len() <= MAX_ENROLLMENT_PACKAGE_BYTES,
        },
    );
    let mut io = StorePackageIo {
        state: &state,
        token: body.token,
        ciphertext: body.ciphertext,
        error: None,
    };
    // The proved loop: only the effect the driver just emitted is performed,
    // and nothing after its verdict.
    let transition = vela_enrollment_policy::pairing_interpreter!(io, start, await);

    match transition.effect {
        PairingEffect::Complete => Ok(Json(serde_json::json!({
            "stored": true,
            "expires_in": ENROLLMENT_PACKAGE_TTL_SECS
        }))),
        PairingEffect::Fail(failure) => Err(io
            .error
            .take()
            .unwrap_or_else(|| invitation_failure_error(failure))),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected package-store effect".into(),
        )),
    }
}

/// The I/O behind the package-fetch ceremony. The destructive read is the only
/// way a package is handed out, and the driver authorizes it at most once per
/// request.
struct RedeemPackageIo<'a> {
    state: &'a AppState,
    token: String,
    removed: Option<Vec<u8>>,
    error: Option<AppError>,
}

impl PairingExecutor for RedeemPackageIo<'_> {
    async fn redeem_package(&mut self) -> RedeemObservation {
        match self.state.store.get_del(&package_key(&self.token)) {
            Ok(None) => RedeemObservation::Missing,
            Ok(Some(bytes)) => {
                let observation = RedeemObservation::Present {
                    utf8_valid: std::str::from_utf8(&bytes).is_ok(),
                };
                self.removed = Some(bytes);
                observation
            }
            Err(error) => {
                if self.error.is_none() {
                    self.error = Some(error);
                }
                RedeemObservation::Missing
            }
        }
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

    let start = vela_enrollment_policy::pairing_interpreter::start_redeem_package(
        PackageTokenObservation {
            token_valid: validate_token(&token).is_ok(),
        },
    );
    let mut io = RedeemPackageIo {
        state: &state,
        token,
        removed: None,
        error: None,
    };
    let transition = vela_enrollment_policy::pairing_interpreter!(io, start, await);

    match transition.effect {
        PairingEffect::Complete => {
            // The driver completes only for a present, UTF-8 package.
            let bytes = io.removed.take().ok_or_else(|| {
                AppError::Internal("redemption driver completed without a package".into())
            })?;
            let ciphertext = String::from_utf8(bytes)
                .map_err(|_| AppError::Internal("stored enrollment package is not UTF-8".into()))?;
            Ok(Json(FetchEnrollmentPackageResponse { ciphertext }))
        }
        PairingEffect::Fail(failure) => Err(io
            .error
            .take()
            .unwrap_or_else(|| invitation_failure_error(failure))),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected package-redeem effect".into(),
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
