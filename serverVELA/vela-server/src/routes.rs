//! Axum router construction.

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::state::AppState;

pub fn build(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    Router::new()
        // ── Account (bootstrap) ───────────────────────────────────────────────
        .route("/account/register", post(crate::account::post_register))
        // ── Auth ──────────────────────────────────────────────────────────────
        .route("/auth/challenge",   get(crate::auth::challenge::get_challenge))
        .route("/auth/verify",      post(crate::auth::verify::post_verify))
        // ── Device ────────────────────────────────────────────────────────────
        .route("/device/enroll",    post(crate::device::enroll::post_enroll))
        .route("/device/revoke",    post(crate::device::revoke::post_revoke))
        .route("/device/capsule",   get(crate::device::capsule::get_capsule))
        // ── Vault ─────────────────────────────────────────────────────────────
        .route("/vault/sync",            get(crate::vault::sync::get_sync))
        .route("/vault/chunk/:id",       get(crate::vault::chunk::get_chunk))
        .route("/vault/chunk/:id",       put(crate::vault::chunk::put_chunk))
        // ── Share ─────────────────────────────────────────────────────────────
        .route("/share/send",            post(crate::share::post_send))
        .route("/share/inbox",           get(crate::share::get_inbox))
        .route("/share/inbox/:id",       delete(crate::share::delete_inbox_item))
        // ── Recovery ──────────────────────────────────────────────────────────
        .route("/recovery/share",        put(crate::recovery::put_share))
        .route("/recovery/share",        get(crate::recovery::get_share))
        .route("/recovery/share",        delete(crate::recovery::delete_share))
        // ── Infra ─────────────────────────────────────────────────────────────
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
