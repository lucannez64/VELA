use axum::{
    extract::{ConnectInfo, Request},
    http::header::{HeaderName, AUTHORIZATION, CONTENT_TYPE},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post, put},
    Router,
};
use std::net::SocketAddr;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    trace::TraceLayer,
};

use crate::state::AppState;

static IF_MATCH: HeaderName = HeaderName::from_static("if-match");
static X_LAMPORT_CLOCK: HeaderName = HeaderName::from_static("x-lamport-clock");

#[derive(Clone, Copy, Debug)]
pub struct NativeHttps;

pub fn build(state: AppState) -> Router {
    let allowed_headers = [
        AUTHORIZATION,
        CONTENT_TYPE,
        IF_MATCH.clone(),
        X_LAMPORT_CLOCK.clone(),
    ];

    let cors = if state.config.cors_origins == ["*"] && state.config.allow_wildcard_cors {
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
        .route("/account/register", post(crate::account::post_register))
        .route("/account", delete(crate::account::delete::delete_account))
        .route(
            "/auth/challenge",
            get(crate::auth::challenge::get_challenge),
        )
        .route("/auth/verify", post(crate::auth::verify::post_verify))
        .route("/auth/logout", post(crate::auth::logout::post_logout))
        .route("/device/enroll", post(crate::device::enroll::post_enroll))
        .route(
            "/device/enrollment-package",
            post(crate::device::invitation::post_enrollment_package),
        )
        .route(
            "/device/enrollment-package/:token",
            get(crate::device::invitation::get_enrollment_package),
        )
        .route("/device/revoke", post(crate::device::revoke::post_revoke))
        .route("/device/capsule", get(crate::device::capsule::get_capsule))
        .route("/devices", get(crate::device::list::list_devices))
        .route("/vault/sync", get(crate::vault::sync::get_sync))
        .route("/vault/chunk/:id", get(crate::vault::chunk::get_chunk))
        .route("/vault/chunk/:id", put(crate::vault::chunk::put_chunk))
        .route(
            "/vault/chunk/:id",
            delete(crate::vault::chunk::delete_chunk),
        )
        .route(
            "/vault/oram/:tree_id/path/:leaf",
            get(crate::vault::oram::get_path),
        )
        .route(
            "/vault/oram/:tree_id/path/:leaf",
            put(crate::vault::oram::put_path),
        )
        .route("/share/send", post(crate::share::post_send))
        .route("/share/inbox", get(crate::share::get_inbox))
        .route("/share/inbox/:id", delete(crate::share::delete_inbox_item))
        .route("/share/linked", get(crate::share::get_linked_items))
        .route("/share/linked/:id", put(crate::share::put_linked_item))
        .route(
            "/share/linked/:id",
            delete(crate::share::delete_linked_item),
        )
        .route("/recovery/share", put(crate::recovery::put_share))
        .route("/recovery/share", get(crate::recovery::get_share))
        .route("/recovery/share", delete(crate::recovery::delete_share))
        .route(
            "/recovery/webauthn/register/start",
            post(crate::recovery::webauthn::post_register_start),
        )
        .route(
            "/recovery/webauthn/register/finish",
            post(crate::recovery::webauthn::post_register_finish),
        )
        .route(
            "/recovery/initiate",
            post(crate::recovery::initiate::post_initiate),
        )
        .route(
            "/recovery/recover",
            post(crate::recovery::recover::post_recover),
        )
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(state.clone(), enforce_https))
        .layer(cors)
        .with_state(state)
}

/// Reject cleartext requests in production.
///
/// VELA serves cleartext on `LISTEN_ADDR` (the loopback target behind a
/// TLS-terminating proxy / Cloudflare Tunnel). In production every request must
/// be proven HTTPS — either it arrived on the native TLS/HTTP-3 listener
/// (`NativeHttps`) or it came from a trusted proxy that set
/// `X-Forwarded-Proto: https`. Otherwise a bearer token could transit a LAN in
/// the clear. `/health` is exempt so a local liveness probe works over loopback.
async fn enforce_https(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    if state.config.production
        && !state.config.allow_insecure_lan
        && req.uri().path() != "/health"
        && !request_was_https(&req, &state)
    {
        return Err(axum::http::StatusCode::UPGRADE_REQUIRED);
    }

    Ok(next.run(req).await)
}

fn request_was_https(req: &Request, state: &AppState) -> bool {
    if req.extensions().get::<NativeHttps>().is_some() {
        return true;
    }

    if !state.config.trust_proxy_headers || !request_from_trusted_proxy(req, state) {
        return false;
    }

    let headers = req.headers();

    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .next()
                .is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https"))
        })
        .unwrap_or(false)
        || headers
            .get("forwarded")
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(';')
                    .any(|part| part.trim().eq_ignore_ascii_case("proto=https"))
            })
            .unwrap_or(false)
        || headers
            .get("x-forwarded-ssl")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("on"))
}

fn request_from_trusted_proxy(req: &Request, state: &AppState) -> bool {
    let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() else {
        return false;
    };

    crate::net::from_trusted_proxy(addr.ip(), &state.config)
}

async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<serde_json::Value> {
    let mut db_ok = true;
    let mut sled_ok = true;

    if let Err(e) = state.db.query("SELECT 1", ()) {
        db_ok = false;
        tracing::error!(error = %e, "health check: stoolap failed");
    }

    if let Err(e) = state.store.inner().size_on_disk() {
        sled_ok = false;
        tracing::error!(error = %e, "health check: sled failed");
    }

    let all_ok = db_ok && sled_ok;

    axum::Json(serde_json::json!({
        "status": if all_ok { "ok" } else { "degraded" },
        "stoolap": if db_ok { "ok" } else { "error" },
        "sled": if sled_ok { "ok" } else { "error" },
    }))
}
