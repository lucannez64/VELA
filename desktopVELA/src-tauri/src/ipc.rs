use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::Manager;
use tracing::{error, info};

use crate::commands::totp::generate_totp_code;
use crate::vault::VaultItem;
use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcMessage {
    pub msg_type: IpcMessageType,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IpcMessageType {
    #[serde(alias = "AutofillRequest")]
    #[serde(alias = "autofillRequest")]
    AutofillRequest,
    #[serde(alias = "AutofillResponse")]
    #[serde(alias = "autofillResponse")]
    AutofillResponse,
    BiometricChallenge,
    BiometricResponse,
    SessionStatus,
    SyncStatus,
    Ping,
    Pong,
    Error,
}

impl IpcMessage {
    pub fn autofill_request(domain: String) -> Self {
        Self {
            msg_type: IpcMessageType::AutofillRequest,
            payload: serde_json::json!({ "domain": domain }),
        }
    }

    pub fn ping() -> Self {
        Self {
            msg_type: IpcMessageType::Ping,
            payload: serde_json::json!({}),
        }
    }

    pub fn pong() -> Self {
        Self {
            msg_type: IpcMessageType::Pong,
            payload: serde_json::json!({ "connected": true }),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            msg_type: IpcMessageType::Error,
            payload: serde_json::json!({ "message": message }),
        }
    }
}

pub mod server {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;

    pub const PORT: u16 = 14597;

    pub struct IpcServer;

    impl IpcServer {
        pub fn new() -> Self {
            Self
        }

        pub async fn start(&self, app_handle: tauri::AppHandle) {
            let addr = format!("127.0.0.1:{}", PORT);
            let _app_handle = app_handle.clone();

            match TcpListener::bind(&addr).await {
                Ok(listener) => {
                    info!("IPC server listening on {}", addr);

                    loop {
                        match listener.accept().await {
                            Ok((stream, client_addr)) => {
                                info!("IPC server: client connected from {}", client_addr);
                                let app_handle = _app_handle.clone();
                                {
                                    let state =
                                        app_handle.state::<std::sync::Arc<crate::AppState>>();
                                    state
                                        .extension_connected
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        handle_connection(stream, app_handle.clone()).await
                                    {
                                        error!("Connection error: {:?}", e);
                                    }
                                    info!("IPC server: client disconnected");
                                    let state =
                                        app_handle.state::<std::sync::Arc<crate::AppState>>();
                                    state
                                        .extension_connected
                                        .store(false, std::sync::atomic::Ordering::Relaxed);
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {:?}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind to {}: {}", addr, e);
                }
            }
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        app_handle: tauri::AppHandle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut rd, mut wr) = stream.split();
        let mut buffer = String::new();
        let mut content_length: Option<usize> = None;

        loop {
            let mut tmp_buf = vec![0u8; 4096];
            match rd.read(&mut tmp_buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = &tmp_buf[..n];
                    if let Ok(text) = std::str::from_utf8(data) {
                        buffer.push_str(text);
                    }

                    if let Some(cl) = content_length {
                        let header_end = buffer.find("\r\n\r\n").map(|p| p + 4);
                        let body_start = header_end.unwrap_or(buffer.len());
                        let current_body_len = buffer.len() - body_start;

                        if current_body_len >= cl {
                            let body = &buffer[body_start..body_start + cl];
                            handle_json_message(&mut wr, body, &app_handle).await?;
                            buffer.clear();
                            content_length = None;
                        }
                    } else {
                        if let Some(start) = buffer.find("Content-Length: ") {
                            let rest = &buffer[start + 16..];
                            if let Some(end) = rest.find("\r\n") {
                                if let Ok(cl) = rest[..end].trim().parse::<usize>() {
                                    content_length = Some(cl);
                                }
                            }
                        }

                        if buffer.contains("\r\n\r\n") {
                            if let Some(cl) = content_length {
                                let body_start = buffer.find("\r\n\r\n").unwrap() + 4;
                                let current_body_len = buffer.len() - body_start;

                                if current_body_len >= cl {
                                    let body = &buffer[body_start..body_start + cl];
                                    handle_json_message(&mut wr, body, &app_handle).await?;
                                    buffer.clear();
                                    content_length = None;
                                }
                            } else if buffer.starts_with("GET /ping") {
                                handle_ping_request(&mut wr, &app_handle).await?;
                                buffer.clear();
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Read error: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_ping_request(
        wr: &mut tokio::net::tcp::WriteHalf<'_>,
        app_handle: &tauri::AppHandle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = process_message(IpcMessage::ping(), app_handle).await;
        let body = serde_json::to_string(&response)?;

        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        wr.write_all(http_response.as_bytes()).await?;
        wr.flush().await?;

        Ok(())
    }

    async fn handle_json_message(
        wr: &mut tokio::net::tcp::WriteHalf<'_>,
        text: &str,
        app_handle: &tauri::AppHandle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }

        info!("Received: {}", text);

        let message: IpcMessage = match serde_json::from_str(text) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to parse message: {:?}", e);
                return Ok(());
            }
        };

        let response = process_message(message, app_handle).await;

        let body = serde_json::to_string(&response)?;

        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        wr.write_all(http_response.as_bytes()).await?;
        wr.flush().await?;

        Ok(())
    }

    async fn process_message(message: IpcMessage, app_handle: &tauri::AppHandle) -> IpcMessage {
        info!("Processing IPC message: {:?}", message.msg_type);

        match message.msg_type {
            IpcMessageType::Ping => IpcMessage::pong(),
            IpcMessageType::AutofillRequest => handle_autofill_request(&message, app_handle).await,
            _ => IpcMessage::error("Unknown message type".to_string()),
        }
    }

    async fn handle_autofill_request(
        message: &IpcMessage,
        app_handle: &tauri::AppHandle,
    ) -> IpcMessage {
        let url = message
            .payload
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        info!("Autofill request for URL: {}", url);

        let base_domain = extract_base_domain(&url);
        info!("Extracted base domain: {}", base_domain);

        let state = app_handle.state::<Arc<AppState>>();
        let vault = state.vault.read();
        let items = vault.search_by_domain(&base_domain);

        let items_clone: Vec<_> = items.into_iter().cloned().collect();

        IpcMessage {
            msg_type: IpcMessageType::AutofillResponse,
            payload: serde_json::json!({
                "items": items_clone,
                "requires_biometric": false
            }),
        }
    }
}

fn extract_base_domain(url: &str) -> String {
    let url = url.trim();

    if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("file://") {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let host = host.to_lowercase();

                if host.starts_with("www.") {
                    return host.strip_prefix("www.").unwrap_or(&host).to_string();
                }

                let parts: Vec<&str> = host.split('.').collect();
                if parts.len() >= 2 {
                    return parts[parts.len() - 2..].join(".");
                }

                return host;
            }
        }
    }

    url.to_lowercase()
}
