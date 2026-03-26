//! VELA Protocol v2.0 — API Server
//!
//! Entry point: loads config, connects to Postgres + Redis, runs migrations,
//! and starts the Axum HTTP server.

use std::{net::SocketAddr, sync::Arc};

mod account;
mod auth;
mod config;
mod db;
mod device;
mod error;
mod middleware;
mod rate_limit;
mod recovery;
mod routes;
mod share;
mod state;
mod vault;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ───────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vela_server=info,tower_http=debug".into()),
        )
        .init();

    // ── Configuration ─────────────────────────────────────────────────────────
    let _ = dotenvy::dotenv(); // silently ignore missing .env
    let config = config::Config::from_env()?;
    tracing::info!(addr = %config.listen_addr, "VELA server starting");

    // ── Database ──────────────────────────────────────────────────────────────
    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool).await?;
    tracing::info!("database migrations applied");

    // ── Redis ─────────────────────────────────────────────────────────────────
    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let redis_mgr = redis::aio::ConnectionManager::new(redis_client).await?;
    tracing::info!(url = %config.redis_url, "redis connected");

    // ── State ─────────────────────────────────────────────────────────────────
    let state = Arc::new(state::AppStateInner::new(pool, redis_mgr, config.clone())?);

    // ── Router ────────────────────────────────────────────────────────────────
    let app = routes::build(state)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            config.max_body_bytes,
        ));

    // ── Serve ─────────────────────────────────────────────────────────────────
    let addr: SocketAddr = config.listen_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
