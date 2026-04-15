use std::{net::SocketAddr, sync::Arc};

use vela_server::{config, db, routes, share, state, store};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vela_server=info,tower_http=debug".into()),
        )
        .init();

    let _ = dotenvy::dotenv();
    let config = config::Config::from_env()?;
    tracing::info!(addr = %config.listen_addr, "VELA server starting");

    let database = db::open_and_init(&config.db_path)?;
    tracing::info!(path = %config.db_path, "stoolap database opened");

    let kv = store::Store::open(&config.sled_path)?;
    tracing::info!(path = %config.sled_path, "sled embedded store opened");

    let state = Arc::new(state::AppStateInner::new(database, kv, config.clone())?);

    {
        let bg_db = state.db.clone();
        tokio::spawn(async move {
            share::inbox_cleanup_task(bg_db).await;
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

    let app = routes::build(state.clone()).layer(tower_http::limit::RequestBodyLimitLayer::new(
        config.max_body_bytes,
    ));

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
