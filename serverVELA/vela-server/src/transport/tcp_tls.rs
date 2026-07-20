use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service as _;

pub async fn serve(
    addr: SocketAddr,
    app: Router,
    tls_config: Arc<ServerConfig>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    tracing::info!(%addr, "TLS TCP listener active");

    // Attach `ConnectInfo<SocketAddr>` per connection so rate limiters key on
    // the real peer (same as the cleartext listener via axum::serve).
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let per_connection = match make_service.call(peer).await {
            Ok(service) => service,
            Err(error) => match Infallible::from(error) {},
        };
        let service = TowerToHyperService::new(per_connection);

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
