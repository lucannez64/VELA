use data_encoding::BASE64URL_NOPAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{error, info, warn};

use crate::vault::VaultItem;
use crate::AppState;

const IPC_AUTH_FILE: &str = "ipc_auth.json";
const MAX_IPC_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcMessage {
    pub msg_type: IpcMessageType,
    #[serde(default)]
    pub payload: serde_json::Value,
    #[serde(default)]
    pub capability: Option<String>,
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
    OpenVault,
    Ping,
    Pong,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpcAuthFile {
    version: u8,
    protocol: String,
    endpoint: String,
    capability: String,
}

impl IpcMessage {
    pub fn ping() -> Self {
        Self {
            msg_type: IpcMessageType::Ping,
            payload: serde_json::json!({}),
            capability: None,
        }
    }

    pub fn pong() -> Self {
        Self {
            msg_type: IpcMessageType::Pong,
            payload: serde_json::json!({ "connected": true }),
            capability: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            msg_type: IpcMessageType::Error,
            payload: serde_json::json!({ "message": message }),
            capability: None,
        }
    }
}

pub fn generate_capability() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    BASE64URL_NOPAD.encode(&bytes)
}

pub mod server {
    use super::*;
    use std::process::Command;

    pub struct IpcServer {
        capability: String,
    }

    impl IpcServer {
        pub fn new(capability: String) -> Self {
            Self { capability }
        }

        pub async fn start(&self, app_handle: tauri::AppHandle) {
            let state = app_handle.state::<Arc<AppState>>();
            let auth_path = state.store.store_path().join(IPC_AUTH_FILE);
            drop(state);
            let endpoint = platform_endpoint();

            if let Err(e) =
                write_auth_file(&auth_path, &self.capability, platform_protocol(), &endpoint)
            {
                error!("Failed to write IPC auth file: {}", e);
                return;
            }

            if let Err(e) =
                start_platform_server(app_handle, self.capability.clone(), endpoint).await
            {
                error!("IPC server stopped: {}", e);
            }
        }
    }

    fn write_auth_file(
        path: &PathBuf,
        capability: &str,
        protocol: &str,
        endpoint: &str,
    ) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let auth = IpcAuthFile {
            version: 1,
            protocol: protocol.to_string(),
            endpoint: endpoint.to_string(),
            capability: capability.to_string(),
        };
        let json = serde_json::to_vec(&auth)?;
        std::fs::write(path, json)?;
        restrict_file(path)?;
        Ok(())
    }

    fn restrict_file(path: &PathBuf) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        {
            restrict_file_windows(path)?;
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
        }
        Ok(())
    }

    #[cfg(windows)]
    fn restrict_file_windows(path: &PathBuf) -> std::io::Result<()> {
        let user = std::env::var("USERNAME").map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "USERNAME is not set")
        })?;
        let domain = std::env::var("USERDOMAIN")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_default();
        let principal = if domain.is_empty() {
            user
        } else {
            format!("{domain}\\{user}")
        };

        let status = Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{principal}:F"))
            .arg("/grant:r")
            .arg("*S-1-5-18:F")
            .arg("/grant:r")
            .arg("*S-1-5-32-544:F")
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "failed to restrict IPC auth file ACL",
            ))
        }
    }

    async fn handle_connection<S>(
        mut stream: S,
        app_handle: tauri::AppHandle,
        capability: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let message = read_frame(&mut stream).await?;
        let response = match serde_json::from_slice::<IpcMessage>(&message) {
            Ok(message) => process_message(message, &app_handle, &capability).await,
            Err(e) => {
                warn!("Rejected malformed IPC message: {}", e);
                IpcMessage::error("Malformed IPC message".to_string())
            }
        };
        let body = serde_json::to_vec(&response)?;
        write_frame(&mut stream, &body).await?;
        stream.shutdown().await?;
        Ok(())
    }

    async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_IPC_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid IPC frame length",
            ));
        }
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;
        Ok(body)
    }

    async fn write_frame<W: AsyncWrite + Unpin>(
        writer: &mut W,
        body: &[u8],
    ) -> std::io::Result<()> {
        writer.write_all(&(body.len() as u32).to_le_bytes()).await?;
        writer.write_all(body).await?;
        writer.flush().await
    }

    async fn process_message(
        message: IpcMessage,
        app_handle: &tauri::AppHandle,
        capability: &str,
    ) -> IpcMessage {
        info!("Processing IPC message: {:?}", message.msg_type);

        if message.capability.as_deref() != Some(capability) {
            warn!("Rejected IPC message with missing or invalid capability");
            return IpcMessage::error("Unauthorized IPC request".to_string());
        }

        match message.msg_type {
            IpcMessageType::Ping => IpcMessage::pong(),
            IpcMessageType::OpenVault => {
                focus_main_window(app_handle);
                IpcMessage::pong()
            }
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

        let base_domain = extract_base_domain(&url);
        let user_initiated = message
            .payload
            .get("user_initiated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let state = app_handle.state::<Arc<AppState>>();

        {
            let session = state.session.read();
            if !session.active || session.is_expired() {
                if user_initiated {
                    focus_main_window(app_handle);
                }
                return autofill_response(Vec::new(), true);
            }
        }

        let vault = state.vault.read();
        let items = vault.search_by_domain(&base_domain);
        if user_initiated {
            let items_clone: Vec<_> = items.into_iter().cloned().collect();
            return autofill_response(items_clone, false);
        }

        let metadata: Vec<_> = items
            .into_iter()
            .map(|item| {
                serde_json::json!({
                    "item_type": "login",
                    "id": item.id(),
                    "name": item.name(),
                    "username": item.username(),
                    "url": item.url(),
                })
            })
            .collect();
        autofill_value_response(serde_json::Value::Array(metadata), false)
    }

    fn focus_main_window(app_handle: &tauri::AppHandle) {
        if let Some(window) = app_handle.get_webview_window("main") {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
    }

    fn autofill_response(items: Vec<VaultItem>, requires_biometric: bool) -> IpcMessage {
        autofill_value_response(serde_json::json!(items), requires_biometric)
    }

    fn autofill_value_response(items: serde_json::Value, requires_biometric: bool) -> IpcMessage {
        IpcMessage {
            msg_type: IpcMessageType::AutofillResponse,
            payload: serde_json::json!({
                "items": items,
                "requires_biometric": requires_biometric
            }),
            capability: None,
        }
    }

    #[cfg(windows)]
    fn platform_protocol() -> &'static str {
        "windows_named_pipe"
    }

    #[cfg(windows)]
    fn platform_endpoint() -> String {
        format!(
            r"\\.\pipe\vela-desktop-{}-{}",
            std::process::id(),
            random_endpoint_suffix()
        )
    }

    #[cfg(unix)]
    fn platform_protocol() -> &'static str {
        "unix_socket"
    }

    #[cfg(unix)]
    fn platform_endpoint() -> String {
        let base = std::env::var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        base.join(format!(
            "vela-desktop-{}-{}.sock",
            std::process::id(),
            random_endpoint_suffix()
        ))
        .to_string_lossy()
        .to_string()
    }

    fn random_endpoint_suffix() -> String {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        BASE64URL_NOPAD.encode(&bytes)
    }

    #[cfg(windows)]
    async fn start_platform_server(
        app_handle: tauri::AppHandle,
        capability: String,
        endpoint: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::windows::named_pipe::ServerOptions;

        info!("IPC server listening on Windows named pipe");

        loop {
            let server = ServerOptions::new()
                .reject_remote_clients(true)
                .create(&endpoint)?;
            server.connect().await?;
            let app_handle = app_handle.clone();
            let capability = capability.clone();
            tokio::spawn(async move {
                let state = app_handle.state::<Arc<AppState>>();
                state
                    .extension_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = handle_connection(server, app_handle.clone(), capability).await {
                    error!("IPC connection error: {}", e);
                }
                let state = app_handle.state::<Arc<AppState>>();
                state
                    .extension_connected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    #[cfg(unix)]
    async fn start_platform_server(
        app_handle: tauri::AppHandle,
        capability: String,
        endpoint: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::UnixListener;

        let _ = std::fs::remove_file(&endpoint);
        let listener = UnixListener::bind(&endpoint)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))?;
        }
        info!("IPC server listening on Unix domain socket");

        loop {
            let (stream, _) = listener.accept().await?;
            let app_handle = app_handle.clone();
            let capability = capability.clone();
            tokio::spawn(async move {
                let state = app_handle.state::<Arc<AppState>>();
                state
                    .extension_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = handle_connection(stream, app_handle.clone(), capability).await {
                    error!("IPC connection error: {}", e);
                }
                let state = app_handle.state::<Arc<AppState>>();
                state
                    .extension_connected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    #[cfg(not(any(windows, unix)))]
    async fn start_platform_server(
        _app_handle: tauri::AppHandle,
        _capability: String,
        _endpoint: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("No supported local IPC transport for this platform".into())
    }
}

fn extract_base_domain(url: &str) -> String {
    let url = url.trim();

    if url.starts_with("http://") || url.starts_with("https://") {
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
