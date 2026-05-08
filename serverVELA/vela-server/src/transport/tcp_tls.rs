use std::{net::SocketAddr, sync::Arc};

use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub async fn serve(
    addr: SocketAddr,
    app: Router,
    tls_config: Arc<ServerConfig>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    tracing::info!(%addr, "TLS TCP listener active");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(app.clone());

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%peer, error = %error, "TLS handshake failed");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            if let Err(error) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!(%peer, error = %error, "TLS HTTP connection failed");
            }
        });
    }
}
