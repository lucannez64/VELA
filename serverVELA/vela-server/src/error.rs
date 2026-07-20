use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("version conflict: {0}")]
    Conflict(String),

    #[error("unprocessable: {0}")]
    Unprocessable(String),

    #[error("rate limit exceeded: {0}")]
    RateLimited(String),

    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m.clone()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, "version_conflict", m.clone()),
            AppError::Unprocessable(m) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "unprocessable", m.clone())
            }
            AppError::RateLimited(m) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", m.clone()),
            AppError::PayloadTooLarge(m) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", m.clone())
            }
            AppError::Internal(m) => {
                // Never leak backend (stoolap/sled/serde) detail to clients — it
                // can disclose schema, paths, or internal state. Log it instead.
                tracing::error!(detail = %m, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".to_string(),
                )
            }
        };

        let body = Json(json!({ "error": code, "message": message }));
        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
