use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{error, info, warn};

use crate::host::Host;
use crate::vault::VaultItem;

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
    #[serde(alias = "SaveCredentials")]
    #[serde(alias = "saveCredentials")]
    SaveCredentials,
    #[serde(alias = "SaveResponse")]
    #[serde(alias = "saveResponse")]
    SaveResponse,
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
    getrandom::getrandom(&mut bytes).expect("OS random source unavailable");
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

        pub async fn start(&self, host: Arc<dyn Host>) {
            let auth_path = host.state().store.store_path().join(IPC_AUTH_FILE);
            let endpoint = platform_endpoint();

            if let Err(e) =
                write_auth_file(&auth_path, &self.capability, platform_protocol(), &endpoint)
            {
                error!("Failed to write IPC auth file: {}", e);
                return;
            }

            if let Err(e) = start_platform_server(host, self.capability.clone(), endpoint).await {
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
        host: Arc<dyn Host>,
        capability: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let message = read_frame(&mut stream).await?;
        let response = match serde_json::from_slice::<IpcMessage>(&message) {
            Ok(message) => process_message(message, &host, &capability).await,
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
        host: &Arc<dyn Host>,
        capability: &str,
    ) -> IpcMessage {
        info!("Processing IPC message: {:?}", message.msg_type);

        // Constant-time comparison so the capability token can't be recovered
        // byte-by-byte via response timing over the local socket/pipe.
        use subtle::ConstantTimeEq;
        let provided = message.capability.as_deref().unwrap_or("");
        if !bool::from(provided.as_bytes().ct_eq(capability.as_bytes())) {
            warn!("Rejected IPC message with missing or invalid capability");
            return IpcMessage::error("Unauthorized IPC request".to_string());
        }

        match message.msg_type {
            IpcMessageType::Ping => IpcMessage::pong(),
            IpcMessageType::OpenVault => {
                host.focus_main_window();
                IpcMessage::pong()
            }
            IpcMessageType::AutofillRequest => handle_autofill_request(&message, host).await,
            IpcMessageType::SaveCredentials => handle_save_credentials(&message, host).await,
            _ => IpcMessage::error("Unknown message type".to_string()),
        }
    }

    async fn handle_autofill_request(message: &IpcMessage, host: &Arc<dyn Host>) -> IpcMessage {
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
        let state = host.state();

        {
            let session = state.session.read();
            if !session.active || session.is_expired() {
                if user_initiated {
                    host.focus_main_window();
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

    async fn handle_save_credentials(message: &IpcMessage, host: &Arc<dyn Host>) -> IpcMessage {
        let payload = &message.payload;
        let username = payload
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let password = payload
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let url = payload
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = payload
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| extract_base_domain(&url));

        if password.is_empty() {
            return save_response(false, None, Some("Password is required".to_string()));
        }

        let state = host.state();

        // Require an active, unlocked session. If the vault is locked, surface the
        // window so the user can unlock, mirroring the autofill flow.
        let device_id = {
            let session = state.session.read();
            if !session.active || session.is_expired() {
                host.focus_main_window();
                return save_response(false, None, Some("Vault is locked".to_string()));
            }
            session.device_id.clone()
        };

        if state.crypto.read().is_none() {
            host.focus_main_window();
            return save_response(false, None, Some("Vault is locked".to_string()));
        }

        let now = chrono::Utc::now();
        let new_item = VaultItem::Login {
            meta: crate::vault::VaultMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name,
                notes: None,
                created_at: now,
                updated_at: now,
                last_modified_device: device_id,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            url,
            username,
            pass: password,
            totp: None,
            app_ids: Vec::new(),
        };

        {
            let mut vault = state.vault.write();
            vault.add_item(new_item.clone());
        }

        // Persist the encrypted vault to disk.
        {
            let vault = state.vault.read();
            let crypto = state.crypto.read();
            if let Some(crypto) = crypto.as_ref() {
                if let Err(e) = state.store.save_vault(&vault, crypto) {
                    error!("Failed to persist vault after save: {}", e);
                    return save_response(false, None, Some("Failed to save vault".to_string()));
                }
            }
        }

        crate::audit::record_audit_event(
            state,
            crate::audit::AuditAction::ItemAdded {
                item_type: "login".to_string(),
            },
        );

        host.notify_vault_items_changed();

        save_response(true, Some(new_item.id().to_string()), None)
    }

    fn save_response(success: bool, id: Option<String>, error: Option<String>) -> IpcMessage {
        IpcMessage {
            msg_type: IpcMessageType::SaveResponse,
            payload: serde_json::json!({
                "success": success,
                "id": id,
                "error": error,
            }),
            capability: None,
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
        getrandom::getrandom(&mut bytes).expect("OS random source unavailable");
        BASE64URL_NOPAD.encode(&bytes)
    }

    #[cfg(windows)]
    async fn start_platform_server(
        host: Arc<dyn Host>,
        capability: String,
        endpoint: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::windows::named_pipe::ServerOptions;
        use tokio::time::{sleep, Duration};

        info!("IPC server listening on Windows named pipe");

        loop {
            let server = match ServerOptions::new()
                .reject_remote_clients(true)
                .create(&endpoint)
            {
                Ok(server) => server,
                Err(e) => {
                    error!("Failed to create IPC named pipe server: {}", e);
                    sleep(Duration::from_millis(250)).await;
                    continue;
                }
            };

            if let Err(e) = server.connect().await {
                error!("IPC named pipe connect failed: {}", e);
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            let host = host.clone();
            let capability = capability.clone();
            tokio::spawn(async move {
                host.state()
                    .extension_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = handle_connection(server, host.clone(), capability).await {
                    error!("IPC connection error: {}", e);
                }
                host.state()
                    .extension_connected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    #[cfg(unix)]
    async fn start_platform_server(
        host: Arc<dyn Host>,
        capability: String,
        endpoint: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::UnixListener;
        use tokio::time::{sleep, Duration};

        let _ = std::fs::remove_file(&endpoint);
        let listener = UnixListener::bind(&endpoint)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))?;
        }
        info!("IPC server listening on Unix domain socket");

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(e) => {
                    error!("IPC unix socket accept failed: {}", e);
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let host = host.clone();
            let capability = capability.clone();
            tokio::spawn(async move {
                host.state()
                    .extension_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = handle_connection(stream, host.clone(), capability).await {
                    error!("IPC connection error: {}", e);
                }
                host.state()
                    .extension_connected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    #[cfg(not(any(windows, unix)))]
    async fn start_platform_server(
        _host: Arc<dyn Host>,
        _capability: String,
        _endpoint: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("No supported local IPC transport for this platform".into())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::Crypto;
        use crate::vault::{VaultItem, VaultMeta};
        use crate::AppState;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct MockHost {
            state: Arc<AppState>,
            focus_calls: AtomicUsize,
            quick_search_calls: AtomicUsize,
            notify_calls: AtomicUsize,
        }

        impl MockHost {
            fn new(unlocked: bool) -> (tempfile::TempDir, Arc<Self>) {
                let dir = tempfile::tempdir().unwrap();
                let state = Arc::new(AppState::for_test(dir.path()));
                if unlocked {
                    state.unlock_for_test(&Crypto::generate_rms());
                }
                let host = Arc::new(Self {
                    state,
                    focus_calls: AtomicUsize::new(0),
                    quick_search_calls: AtomicUsize::new(0),
                    notify_calls: AtomicUsize::new(0),
                });
                (dir, host)
            }

            fn focuses(&self) -> usize {
                self.focus_calls.load(Ordering::SeqCst)
            }

            fn notifies(&self) -> usize {
                self.notify_calls.load(Ordering::SeqCst)
            }
        }

        impl Host for MockHost {
            fn state(&self) -> &Arc<AppState> {
                &self.state
            }
            fn focus_main_window(&self) {
                self.focus_calls.fetch_add(1, Ordering::SeqCst);
            }
            fn app_identifier(&self) -> String {
                "com.vela.test".into()
            }
            fn open_quick_search(&self) {
                self.quick_search_calls.fetch_add(1, Ordering::SeqCst);
            }
            fn notify_vault_items_changed(&self) {
                self.notify_calls.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn message(msg_type: IpcMessageType, payload: serde_json::Value, capability: &str) -> IpcMessage {
            IpcMessage { msg_type, payload, capability: Some(capability.into()) }
        }

        #[tokio::test]
        async fn frames_roundtrip() {
            let (mut a, mut b) = tokio::io::duplex(64);
            write_frame(&mut a, b"hello ipc").await.unwrap();
            let got = read_frame(&mut b).await.unwrap();
            assert_eq!(got, b"hello ipc");
        }

        #[tokio::test]
        async fn frames_reject_bad_lengths() {
            // Zero-length frame.
            let (mut a, mut b) = tokio::io::duplex(64);
            a.write_all(&0u32.to_le_bytes()).await.unwrap();
            assert!(read_frame(&mut b).await.is_err());

            // Over the 1 MiB cap — rejected from the header alone.
            let (mut a, mut b) = tokio::io::duplex(64);
            a.write_all(&((MAX_IPC_MESSAGE_BYTES + 1) as u32).to_le_bytes())
                .await
                .unwrap();
            assert!(read_frame(&mut b).await.is_err());
        }

        #[tokio::test]
        async fn write_auth_file_creates_restricted_json() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("nested").join(IPC_AUTH_FILE);
            write_auth_file(&path, "cap-123", "unix_socket", "/tmp/x.sock").unwrap();

            let parsed: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(parsed["version"], 1);
            assert_eq!(parsed["capability"], "cap-123");
            assert_eq!(parsed["protocol"], "unix_socket");
            assert_eq!(parsed["endpoint"], "/tmp/x.sock");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        }

        #[tokio::test]
        async fn rejects_missing_or_wrong_capability() {
            let (_dir, host) = MockHost::new(false);
            let host: Arc<dyn Host> = host;

            let no_cap = IpcMessage { msg_type: IpcMessageType::Ping, payload: serde_json::json!({}), capability: None };
            let resp = process_message(no_cap, &host, "real-cap").await;
            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert_eq!(resp.payload["message"], "Unauthorized IPC request");

            let wrong = message(IpcMessageType::Ping, serde_json::json!({}), "nope");
            let resp = process_message(wrong, &host, "real-cap").await;
            assert_eq!(resp.payload["message"], "Unauthorized IPC request");
        }

        #[tokio::test]
        async fn ping_pong_and_open_vault() {
            let (_dir, mock) = MockHost::new(false);
            let host: Arc<dyn Host> = mock.clone();

            let resp = process_message(message(IpcMessageType::Ping, serde_json::json!({}), "cap"), &host, "cap").await;
            assert_eq!(resp.msg_type, IpcMessageType::Pong);
            assert_eq!(resp.payload["connected"], true);

            let resp = process_message(message(IpcMessageType::OpenVault, serde_json::json!({}), "cap"), &host, "cap").await;
            assert_eq!(resp.msg_type, IpcMessageType::Pong);
            assert_eq!(mock.focuses(), 1, "open_vault surfaces the main window");

            let resp = process_message(
                message(IpcMessageType::BiometricChallenge, serde_json::json!({}), "cap"),
                &host,
                "cap",
            )
            .await;
            assert_eq!(resp.payload["message"], "Unknown message type");
        }

        #[tokio::test]
        async fn autofill_locked_vault_requires_biometric() {
            let (_dir, mock) = MockHost::new(false);
            let host: Arc<dyn Host> = mock.clone();

            let req = message(
                IpcMessageType::AutofillRequest,
                serde_json::json!({ "domain": "https://github.com", "user_initiated": true }),
                "cap",
            );
            let resp = process_message(req, &host, "cap").await;
            assert_eq!(resp.msg_type, IpcMessageType::AutofillResponse);
            assert_eq!(resp.payload["requires_biometric"], true);
            assert_eq!(resp.payload["items"].as_array().unwrap().len(), 0);
            assert_eq!(mock.focuses(), 1, "user-initiated autofill surfaces the unlock UI");
        }

        #[tokio::test]
        async fn autofill_returns_full_items_when_user_initiated() {
            let (_dir, mock) = MockHost::new(true);
            {
                let now = chrono::Utc::now();
                mock.state.vault.write().add_item(VaultItem::Login {
                    meta: VaultMeta {
                        id: "1".into(),
                        name: "GH".into(),
                        notes: None,
                        created_at: now,
                        updated_at: now,
                        last_modified_device: None,
                        favorite: false,
                        shared: false,
                        share_recipient: None,
                    },
                    url: "https://github.com".into(),
                    username: "alice".into(),
                    pass: "s3cret".into(),
                    totp: None,
                    app_ids: Vec::new(),
                });
            }
            let host: Arc<dyn Host> = mock.clone();

            // user_initiated: full credentials (the extension will gate on
            // biometric itself).
            let req = message(
                IpcMessageType::AutofillRequest,
                serde_json::json!({ "domain": "https://github.com/login", "user_initiated": true }),
                "cap",
            );
            let resp = process_message(req, &host, "cap").await;
            let items = resp.payload["items"].as_array().unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["password"], "s3cret");

            // Passive (page-load) request: metadata only, never passwords.
            let req = message(
                IpcMessageType::AutofillRequest,
                serde_json::json!({ "domain": "https://github.com/login", "user_initiated": false }),
                "cap",
            );
            let resp = process_message(req, &host, "cap").await;
            let items = resp.payload["items"].as_array().unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["username"], "alice");
            assert!(items[0].get("password").is_none(), "passive autofill must not leak passwords");
        }

        #[tokio::test]
        async fn save_credentials_validates_and_persists() {
            let (_dir, mock) = MockHost::new(true);
            let host: Arc<dyn Host> = mock.clone();

            // Password is mandatory.
            let req = message(
                IpcMessageType::SaveCredentials,
                serde_json::json!({ "username": "alice", "password": "", "url": "https://github.com" }),
                "cap",
            );
            let resp = process_message(req, &host, "cap").await;
            assert_eq!(resp.payload["success"], false);
            assert_eq!(resp.payload["error"], "Password is required");

            // Happy path: item lands in the vault, UI notified, name defaults
            // to the domain.
            let req = message(
                IpcMessageType::SaveCredentials,
                serde_json::json!({ "username": "alice", "password": "pw", "url": "https://github.com/login", "name": "" }),
                "cap",
            );
            let resp = process_message(req, &host, "cap").await;
            assert_eq!(resp.payload["success"], true);
            assert!(!resp.payload["id"].as_str().unwrap().is_empty());
            assert_eq!(mock.notifies(), 1);

            let vault = mock.state.vault.read();
            assert_eq!(vault.items.len(), 1);
            assert_eq!(vault.items[0].name(), "github.com");
            assert_eq!(vault.items[0].password(), Some("pw"));
        }

        #[tokio::test]
        async fn save_credentials_locked_vault_surfaces_window() {
            let (_dir, mock) = MockHost::new(false);
            let host: Arc<dyn Host> = mock.clone();

            let req = message(
                IpcMessageType::SaveCredentials,
                serde_json::json!({ "username": "alice", "password": "pw", "url": "https://github.com" }),
                "cap",
            );
            let resp = process_message(req, &host, "cap").await;
            assert_eq!(resp.payload["success"], false);
            assert_eq!(resp.payload["error"], "Vault is locked");
            assert_eq!(mock.focuses(), 1);
        }
    }
}

/// Extract the host the autofill request is for.
///
/// We return the full host (not a naively truncated "last two labels") and let
/// `vault::urls_match` apply the Public Suffix List. The old last-two-labels
/// reduction both broke multi-label suffixes (e.g. `victim.co.uk` collapsed to
/// the public suffix `co.uk`, which never matches) and discarded the subdomain
/// that `urls_match` needs for correct, PSL-aware scoping.
fn extract_base_domain(url: &str) -> String {
    let url = url.trim();

    if url.starts_with("http://") || url.starts_with("https://") {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return host.to_lowercase();
            }
        }
    }

    url.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_tokens_are_unique_and_url_safe() {
        let a = generate_capability();
        let b = generate_capability();
        assert_ne!(a, b);
        // 32 random bytes → 43 base64url-nopad chars.
        assert_eq!(a.len(), 43);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn extract_base_domain_returns_full_lowercase_host() {
        assert_eq!(
            extract_base_domain("https://www.Example.COM/login?next=/x"),
            "www.example.com"
        );
        assert_eq!(extract_base_domain("http://localhost:3000/app"), "localhost");
        // Multi-label suffixes must NOT be collapsed to the public suffix.
        assert_eq!(extract_base_domain("https://sub.victim.co.uk/"), "sub.victim.co.uk");
        // Scheme-less input passes through lowercased.
        assert_eq!(extract_base_domain("  Gist.GitHub.com "), "gist.github.com");
    }

    #[test]
    fn ipc_message_type_serde_and_aliases() {
        let json = serde_json::to_string(&IpcMessageType::AutofillRequest).unwrap();
        assert_eq!(json, "\"autofill_request\"");

        // Legacy spellings from older extension builds still parse.
        for alias in ["\"autofill_request\"", "\"AutofillRequest\"", "\"autofillRequest\""] {
            let parsed: IpcMessageType = serde_json::from_str(alias).unwrap();
            assert_eq!(parsed, IpcMessageType::AutofillRequest, "alias {alias}");
        }

        let parsed: IpcMessageType = serde_json::from_str("\"open_vault\"").unwrap();
        assert_eq!(parsed, IpcMessageType::OpenVault);
    }

    #[test]
    fn message_constructors() {
        let ping = IpcMessage::ping();
        assert_eq!(ping.msg_type, IpcMessageType::Ping);

        let pong = IpcMessage::pong();
        assert_eq!(pong.msg_type, IpcMessageType::Pong);
        assert_eq!(pong.payload["connected"], true);

        let err = IpcMessage::error("boom".into());
        assert_eq!(err.msg_type, IpcMessageType::Error);
        assert_eq!(err.payload["message"], "boom");
    }
}
