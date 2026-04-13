//! Axum router construction.

use axum::{
    http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName},
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    trace::TraceLayer,
};

use crate::state::AppState;

static IF_MATCH: HeaderName = HeaderName::from_static("if-match");
static X_LAMPORT_CLOCK: HeaderName = HeaderName::from_static("x-lamport-clock");

pub fn build(state: AppState) -> Router {
    let allowed_headers = [AUTHORIZATION, CONTENT_TYPE, IF_MATCH.clone(), X_LAMPORT_CLOCK.clone()];

    let cors = if state.config.cors_origins == ["*"] {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(allowed_headers.to_vec())
            .allow_methods(Any)
    } else {
        let origins: Vec<_> = state
            .config
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_headers(allowed_headers.to_vec())
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ])
    };

    Router::new()
        // ── Account (bootstrap) ───────────────────────────────────────────────
        .route("/account/register", post(crate::account::post_register))
        .route("/account",          delete(crate::account::delete::delete_account))
        // ── Auth ──────────────────────────────────────────────────────────────
        .route("/auth/challenge",   get(crate::auth::challenge::get_challenge))
        .route("/auth/verify",      post(crate::auth::verify::post_verify))
        .route("/auth/logout",      post(crate::auth::logout::post_logout))
        // ── Device ────────────────────────────────────────────────────────────
        .route("/device/enroll",    post(crate::device::enroll::post_enroll))
        .route("/device/revoke",    post(crate::device::revoke::post_revoke))
        .route("/device/capsule",   get(crate::device::capsule::get_capsule))
        .route("/devices",          get(crate::device::list::list_devices))
        // ── Vault ─────────────────────────────────────────────────────────────
        .route("/vault/sync",            get(crate::vault::sync::get_sync))
        .route("/vault/chunk/:id",       get(crate::vault::chunk::get_chunk))
        .route("/vault/chunk/:id",       put(crate::vault::chunk::put_chunk))
        .route("/vault/chunk/:id",       delete(crate::vault::chunk::delete_chunk))
        // ── Share ─────────────────────────────────────────────────────────────
        .route("/share/send",            post(crate::share::post_send))
        .route("/share/inbox",           get(crate::share::get_inbox))
        .route("/share/inbox/:id",       delete(crate::share::delete_inbox_item))
        // ── Recovery ──────────────────────────────────────────────────────────
        .route("/recovery/share",        put(crate::recovery::put_share))
        .route("/recovery/share",        get(crate::recovery::get_share))
        .route("/recovery/share",        delete(crate::recovery::delete_share))
        .route("/recovery/initiate",     post(crate::recovery::initiate::post_initiate))
        .route("/recovery/recover",      post(crate::recovery::recover::post_recover))
        // ── Infra ─────────────────────────────────────────────────────────────
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<serde_json::Value> {
    let mut pg_ok = true;
    let mut sled_ok = true;

    let pg_result: Result<i64, sqlx::Error> =
        sqlx::query_scalar("SELECT 1").fetch_one(&state.db).await;
    if pg_result.is_err() {
        pg_ok = false;
        tracing::error!(error = ?pg_result.unwrap_err(), "health check: postgres failed");
    }

    let sled_check: std::result::Result<_, sled::Error> = state.store.inner().size_on_disk();
    if sled_check.is_err() {
        sled_ok = false;
        tracing::error!(error = ?sled_check.unwrap_err(), "health check: sled failed");
    }

    let all_ok = pg_ok && sled_ok;

    axum::Json(serde_json::json!({
        "status": if all_ok { "ok" } else { "degraded" },
        "postgres": if pg_ok { "ok" } else { "error" },
        "sled": if sled_ok { "ok" } else { "error" },
    }))
}
