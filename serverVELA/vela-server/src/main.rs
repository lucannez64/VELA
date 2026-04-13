//! VELA Protocol v2.0 — API Server
//!
//! Entry point: loads config, connects to Postgres, opens the sled embedded
//! database, runs migrations, and starts the Axum HTTP server.

use std::{net::SocketAddr, sync::Arc};

use vela_server::{config, db, routes, share, state, store};

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

    // ── Embedded store (sled) ─────────────────────────────────────────────────
    let kv = store::Store::open(&config.sled_path)?;
    tracing::info!(path = %config.sled_path, "sled embedded store opened");

    // ── State ─────────────────────────────────────────────────────────────────
    let state = Arc::new(state::AppStateInner::new(pool, kv, config.clone())?);

    // ── Background tasks ──────────────────────────────────────────────────────
    {
        let bg_pool = state.db.clone();
        tokio::spawn(async move {
            share::inbox_cleanup_task(bg_pool).await;
        });
    }
    {
        let bg_store = state.store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                match bg_store.cleanup_expired() {
                    Ok(n) => {
                        if n > 0 {
                            tracing::info!(removed = n, "sled expired-key cleanup");
                        }
                    }
                    Err(e) => tracing::error!(error = %e, "sled cleanup error"),
                }
            }
        });
    }

    // ── Router ────────────────────────────────────────────────────────────────
    let app = routes::build(state.clone())
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
