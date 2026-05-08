use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    Router,
};
use bytes::{Buf, Bytes, BytesMut};
use h3::server::RequestResolver;
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};
use http_body_util::BodyExt;
use rustls::ServerConfig as RustlsServerConfig;
use tower::ServiceExt;

pub async fn serve(
    addr: SocketAddr,
    app: Router,
    tls_config: RustlsServerConfig,
    max_body_bytes: usize,
) -> anyhow::Result<()> {
    let quic_crypto = QuicServerConfig::try_from(tls_config)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    tracing::info!(%addr, "HTTP/3 UDP listener active");

    while let Some(incoming) = endpoint.accept().await {
        let app = app.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(error) = handle_connection(connection, app, max_body_bytes).await {
                        tracing::debug!(error = %error, "HTTP/3 connection failed");
                    }
                }
                Err(error) => tracing::debug!(error = %error, "HTTP/3 QUIC accept failed"),
            }
        });
    }

    endpoint.wait_idle().await;
    Ok(())
}

async fn handle_connection(
    connection: quinn::Connection,
    app: Router,
    max_body_bytes: usize,
) -> anyhow::Result<()> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_request(resolver, app, max_body_bytes).await {
                        tracing::debug!(error = %error, "HTTP/3 request failed");
                    }
                });
            }
            Ok(None) => break,
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

async fn handle_request(
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    app: Router,
    max_body_bytes: usize,
) -> anyhow::Result<()> {
    let (request, mut stream) = resolver.resolve_request().await?;
    let (parts, _) = request.into_parts();

    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        if body.len() + remaining > max_body_bytes {
            let response = Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .expect("static response");
            stream.send_response(response).await?;
            stream.finish().await?;
            return Ok(());
        }
        body.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
    }

    let mut axum_request = Request::from_parts(parts, Body::from(body.freeze()));
    axum_request.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-forwarded-proto"),
        axum::http::HeaderValue::from_static("https"),
    );

    let response = app.oneshot(axum_request).await?;
    send_response(stream, response).await
}

async fn send_response(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    response: Response<Body>,
) -> anyhow::Result<()> {
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let response = Response::from_parts(parts, ());

    stream.send_response(response).await?;
    if !bytes.is_empty() {
        stream.send_data(bytes).await?;
    }
    stream.finish().await?;
    Ok(())
}
