use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::Request,
    http::{header::HeaderName, HeaderValue},
    middleware::{self, Next},
    response::Response,
};
use vela_server::{
    config, db, routes, share, state, store,
    transport::{
        http3, tcp_tls,
        tls::{load_rustls_server_config, TlsConfigPaths},
    },
};

static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
static ALT_SVC: HeaderName = HeaderName::from_static("alt-svc");

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

    let clear_addr: SocketAddr = config.listen_addr.parse()?;
    let clear_app = app.clone();

    let tls_paths = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            Some(TlsConfigPaths::from_strings(cert_path, key_path))
        }
        _ => None,
    };

    let tls_addr = config
        .tls_listen_addr
        .as_deref()
        .map(str::parse::<SocketAddr>)
        .transpose()?;
    let h3_addr = config
        .http3_listen_addr
        .as_deref()
        .map(str::parse::<SocketAddr>)
        .transpose()?;

    let tls_future = async {
        if let Some(addr) = tls_addr {
            let paths = tls_paths
                .as_ref()
                .expect("config validation requires TLS paths for TLS listener");
            let tls_config = Arc::new(load_rustls_server_config(paths, &[b"h2", b"http/1.1"])?);
            let alt_svc = if config.http3_enabled {
                h3_addr
                    .map(|addr| {
                        HeaderValue::from_str(&format!(
                            "h3=\":{}\"; ma={}",
                            addr.port(),
                            config.http3_alt_svc_max_age
                        ))
                    })
                    .transpose()?
            } else {
                None
            };
            let tls_app =
                app.clone()
                    .layer(middleware::from_fn(move |req: Request, next: Next| {
                        mark_native_https(req, next, alt_svc.clone())
                    }));
            tcp_tls::serve(addr, tls_app, tls_config).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let h3_future = async {
        if config.http3_enabled {
            let addr = h3_addr.expect("config validation requires HTTP3_LISTEN_ADDR");
            let paths = tls_paths
                .as_ref()
                .expect("config validation requires TLS paths for HTTP/3");
            let h3_tls_config = load_rustls_server_config(paths, &[b"h3"])?;
            let h3_app = app.clone();
            http3::serve(addr, h3_app, h3_tls_config, config.max_body_bytes).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(
        serve_cleartext(clear_addr, clear_app),
        tls_future,
        h3_future
    )?;

    Ok(())
}

async fn serve_cleartext(addr: SocketAddr, app: axum::Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "cleartext TCP listener active");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn mark_native_https(mut req: Request, next: Next, alt_svc: Option<HeaderValue>) -> Response {
    req.headers_mut()
        .insert(X_FORWARDED_PROTO.clone(), HeaderValue::from_static("https"));
    let mut response = next.run(req).await;
    if let Some(value) = alt_svc {
        response.headers_mut().insert(ALT_SVC.clone(), value);
    }
    response
}
