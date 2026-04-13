//! Unified application error type with `IntoResponse` for Axum.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    // ── 400 Bad Request ───────────────────────────────────────────────────────
    #[error("bad request: {0}")]
    BadRequest(String),

    // ── 401 Unauthorized ──────────────────────────────────────────────────────
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    // ── 403 Forbidden ─────────────────────────────────────────────────────────
    #[error("forbidden: {0}")]
    Forbidden(String),

    // ── 404 Not Found ─────────────────────────────────────────────────────────
    #[error("not found: {0}")]
    NotFound(String),

    // ── 409 Conflict ──────────────────────────────────────────────────────────
    #[error("version conflict: {0}")]
    Conflict(String),

    // ── 422 Unprocessable ─────────────────────────────────────────────────────
    #[error("unprocessable: {0}")]
    Unprocessable(String),

    // ── 429 Too Many Requests ─────────────────────────────────────────────────
    #[error("rate limit exceeded: {0}")]
    RateLimited(String),

    // ── 500 Internal ──────────────────────────────────────────────────────────
    #[error("internal error: {0}")]
    Internal(String),

    // ── Infrastructure pass-through ───────────────────────────────────────────
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
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
            AppError::Internal(m) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                m.clone(),
            ),
            AppError::Database(e) => {
                tracing::error!(error = %e, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "database error".into(),
                )
            }
        };

        let body = Json(json!({ "error": code, "message": message }));
        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
