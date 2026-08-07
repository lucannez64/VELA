use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{error, info, warn};

use crate::host::Host;
use crate::vault::VaultItem;
use crate::ipc_peer::PeerIdentity;

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
    #[serde(alias = "PasskeyCreate")]
    #[serde(alias = "passkeyCreate")]
    PasskeyCreate,
    #[serde(alias = "PasskeyCreateResponse")]
    #[serde(alias = "passkeyCreateResponse")]
    PasskeyCreateResponse,
    #[serde(alias = "PasskeyGet")]
    #[serde(alias = "passkeyGet")]
    PasskeyGet,
    #[serde(alias = "PasskeyGetResponse")]
    #[serde(alias = "passkeyGetResponse")]
    PasskeyGetResponse,
    #[serde(alias = "PasskeyList")]
    #[serde(alias = "passkeyList")]
    PasskeyList,
    #[serde(alias = "PasskeyListResponse")]
    #[serde(alias = "passkeyListResponse")]
    PasskeyListResponse,
    #[serde(alias = "InCoreLogin")]
    #[serde(alias = "inCoreLogin")]
    InCoreLogin,
    #[serde(alias = "InCoreLoginResponse")]
    #[serde(alias = "inCoreLoginResponse")]
    InCoreLoginResponse,
    #[serde(alias = "InCoreLoginCandidates")]
    #[serde(alias = "inCoreLoginCandidates")]
    InCoreLoginCandidates,
    #[serde(alias = "InCoreLoginCandidatesResponse")]
    #[serde(alias = "inCoreLoginCandidatesResponse")]
    InCoreLoginCandidatesResponse,
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
        peer: PeerIdentity,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let message = read_frame(&mut stream).await?;
        let response = match serde_json::from_slice::<IpcMessage>(&message) {
            Ok(message) => process_message(message, &host, &capability, &peer).await,
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

    /// May this caller be handed plaintext credentials right now?
    ///
    /// Two conditions, and the token is neither of them:
    ///
    ///  * the kernel says the peer runs as us — a token read out of
    ///    `ipc_auth.json` by something running as another user is not enough; and
    ///  * the user proved presence within [PLAINTEXT_RELEASE_TTL], where the
    ///    platform can ask. One prompt covers a short burst of fills, because a
    ///    prompt per field would train people to approve without reading, but it
    ///    does not cover an idle machine.
    ///
    /// Where the platform cannot ask, the release proceeds on the peer check
    /// and the unlocked session: an idle machine auto-locks, and a locked vault
    /// serves nothing on this path at all (the caller checks that first). See
    /// the `Unavailable` arm for why that is the trade rather than a refusal.
    fn authorize_plaintext_release(host: &Arc<dyn Host>, peer: &PeerIdentity) -> Result<(), String> {
        if !peer.is_same_user() {
            return Err("This request did not come from your own session.".to_string());
        }

        let state = host.state();
        if state.plaintext_release_is_fresh(peer.pid) {
            return Ok(());
        }

        match crate::biometric::verify_presence(&format!(
            "Confirm to let {} fill a saved password",
            peer.describe()
        )) {
            crate::biometric::PresenceOutcome::Confirmed => {
                state.record_plaintext_release(peer.pid);
                Ok(())
            }
            crate::biometric::PresenceOutcome::Denied(message) => Err(message),
            crate::biometric::PresenceOutcome::Unavailable => {
                // Nothing on this machine can ask whether a person is here:
                // no Windows Hello enrolment, no biometry, no fingerprint
                // reader. Release on the peer check and the unlocked session.
                //
                // This did fail closed for a while, with a polkit prompt on
                // Linux to keep that from meaning "no filling, ever". Both are
                // gone. What D-4 actually asks for is that a plaintext release
                // not rest on a long-lived bearer token, and the session
                // auto-lock delivers that: the vault relocks on idle, a locked
                // vault serves nothing here, and every relock clears any
                // standing grant. A machine sitting idle cannot be drained by
                // something that read `ipc_auth.json`.
                //
                // What is given up is narrower than it looks: code running as
                // the user, on an unlocked vault, in the same session. A prompt
                // only stops that if it names who is asking — polkit's could
                // not (fixed message, caller description discarded) and neither
                // can fprintd's, so malware timed to a fill the user just
                // requested was approved by the user's own hand. Hello and
                // Touch ID do name the caller, and still prompt here.
                Ok(())
            }
        }
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
        peer: &PeerIdentity,
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
            IpcMessageType::AutofillRequest => handle_autofill_request(&message, host, peer).await,
            IpcMessageType::SaveCredentials => handle_save_credentials(&message, host).await,
            IpcMessageType::PasskeyCreate => handle_passkey_create(&message, host, peer).await,
            IpcMessageType::PasskeyGet => handle_passkey_get(&message, host, peer).await,
            IpcMessageType::PasskeyList => handle_passkey_list(&message, host, peer),
            IpcMessageType::InCoreLogin => handle_in_core_login(&message, host, peer).await,
            IpcMessageType::InCoreLoginCandidates => {
                handle_in_core_login_candidates(&message, host, peer)
            }
            _ => IpcMessage::error("Unknown message type".to_string()),
        }
    }

    // ── Passkeys (M7) ────────────────────────────────────────────────────────
    //
    // The autofill path above hands over a reusable password and is bounded by
    // the working set as a result. These three hand over a signature and a
    // little public metadata, and nothing else: no code path below can emit a
    // credential key, which is what makes the model's `credential_never_leaks`
    // hold even for the credential in active use.
    //
    // Both ceremonies run inside `spawn_blocking` because the presence gate
    // puts a modal on screen and waits for a person.

    fn b64url_decode(value: Option<&str>) -> Option<Vec<u8>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
        B64URL.decode(value?).ok()
    }

    fn b64url_encode(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
        B64URL.encode(bytes)
    }

    fn client_data_hash_from(payload: &serde_json::Value) -> Option<[u8; 32]> {
        let raw = b64url_decode(payload.get("client_data_hash").and_then(|v| v.as_str()))?;
        <[u8; 32]>::try_from(raw.as_slice()).ok()
    }

    fn string_list(payload: &serde_json::Value, key: &str) -> Vec<String> {
        payload
            .get(key)
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Ask the human, then run `ceremony`. One token, one ceremony.
    async fn with_presence<T, F>(
        host: &Arc<dyn Host>,
        request: crate::presence::PresenceRequest,
        ceremony: F,
    ) -> Result<T, String>
    where
        F: FnOnce(&Arc<dyn Host>, crate::passkey::PresenceToken) -> Result<T, String>
            + Send
            + 'static,
        T: Send + 'static,
    {
        let host = host.clone();
        tokio::task::spawn_blocking(move || {
            let token = crate::presence::confirm(&host, &request).map_err(|e| e.to_string())?;
            ceremony(&host, token)
        })
        .await
        .unwrap_or_else(|e| Err(format!("Passkey ceremony did not complete: {e}")))
    }

    /// The peer check, restated for passkeys.
    ///
    /// The capability token is already checked in `process_message` and is not
    /// worth anything here for the same reason it is not worth anything for a
    /// plaintext release: anything running as this user can read it out of
    /// `ipc_auth.json`. What the token cannot forge is the kernel's answer to
    /// "who is on the other end of this socket".
    fn passkey_peer_is_ours(peer: &PeerIdentity) -> Result<(), String> {
        if !peer.is_same_user() {
            return Err("This request did not come from your own session.".to_string());
        }
        Ok(())
    }

    async fn handle_passkey_create(
        message: &IpcMessage,
        host: &Arc<dyn Host>,
        peer: &PeerIdentity,
    ) -> IpcMessage {
        if let Err(reason) = passkey_peer_is_ours(peer) {
            return IpcMessage::error(reason);
        }

        let payload = &message.payload;
        let Some(client_data_hash) = client_data_hash_from(payload) else {
            return IpcMessage::error("Missing or malformed client_data_hash".to_string());
        };
        let rp_id = payload.get("rp_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if rp_id.is_empty() {
            return IpcMessage::error("Missing rp_id".to_string());
        }

        let request = crate::passkey::MakeCredentialRequest {
            rp_id: rp_id.clone(),
            rp_name: payload.get("rp_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            user_handle: b64url_decode(payload.get("user_handle").and_then(|v| v.as_str()))
                .unwrap_or_default(),
            user_name: payload.get("user_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            user_display_name: payload
                .get("user_display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            client_data_hash,
            algorithms: payload
                .get("algorithms")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_i64().map(|n| n as i32)).collect())
                .unwrap_or_default(),
            excluded_credential_ids: string_list(payload, "exclude_credentials"),
            require_user_verification: payload
                .get("require_user_verification")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };

        let presence = crate::presence::PresenceRequest {
            rp_id,
            requester: peer.describe(),
            kind: crate::presence::CeremonyKind::Register,
        };

        let outcome = with_presence(host, presence, move |host, token| {
            crate::passkey::make_credential(host.state(), &request, token)
                .map_err(|e| e.to_string())
        })
        .await;

        match outcome {
            Ok(response) => {
                host.notify_vault_items_changed();
                IpcMessage {
                    msg_type: IpcMessageType::PasskeyCreateResponse,
                    payload: serde_json::json!({
                        "success": true,
                        "credential_id": response.credential_id,
                        "attestation_object": b64url_encode(&response.attestation_object),
                        "authenticator_data": b64url_encode(&response.authenticator_data),
                    }),
                    capability: None,
                }
            }
            Err(reason) => {
                warn!("Refused passkey registration for {}: {}", peer.describe(), reason);
                IpcMessage::error(reason)
            }
        }
    }

    async fn handle_passkey_get(
        message: &IpcMessage,
        host: &Arc<dyn Host>,
        peer: &PeerIdentity,
    ) -> IpcMessage {
        if let Err(reason) = passkey_peer_is_ours(peer) {
            return IpcMessage::error(reason);
        }

        let payload = &message.payload;
        let Some(client_data_hash) = client_data_hash_from(payload) else {
            return IpcMessage::error("Missing or malformed client_data_hash".to_string());
        };
        let rp_id = payload.get("rp_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if rp_id.is_empty() {
            return IpcMessage::error("Missing rp_id".to_string());
        }

        // Refuse before prompting when there is nothing to sign with, so a page
        // cannot make the vault nag its owner about sites they have no passkey
        // for. A user trained to dismiss prompts is a user who will dismiss the
        // one that mattered.
        {
            let state = host.state();
            let session_ok = {
                let session = state.session.read();
                session.active && !session.is_expired()
            };
            if !session_ok {
                return IpcMessage::error("Vault is locked".to_string());
            }
            if state.vault.read().passkeys_for_rp(&rp_id).is_empty() {
                return IpcMessage::error("No passkey for this site".to_string());
            }
        }

        let request = crate::passkey::GetAssertionRequest {
            rp_id: rp_id.clone(),
            client_data_hash,
            allow_credential_ids: string_list(payload, "allow_credentials"),
            require_user_verification: payload
                .get("require_user_verification")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };

        let presence = crate::presence::PresenceRequest {
            rp_id,
            requester: peer.describe(),
            kind: crate::presence::CeremonyKind::Authenticate,
        };

        let outcome = with_presence(host, presence, move |host, token| {
            crate::passkey::get_assertion(host.state(), &request, token).map_err(|e| e.to_string())
        })
        .await;

        match outcome {
            Ok(response) => IpcMessage {
                msg_type: IpcMessageType::PasskeyGetResponse,
                payload: serde_json::json!({
                    "success": true,
                    "credential_id": response.credential_id,
                    "authenticator_data": b64url_encode(&response.authenticator_data),
                    "signature": b64url_encode(&response.signature),
                    "user_handle": b64url_encode(&response.user_handle),
                }),
                capability: None,
            },
            Err(reason) => {
                warn!("Refused passkey assertion for {}: {}", peer.describe(), reason);
                IpcMessage::error(reason)
            }
        }
    }

    /// Which passkeys exist for a relying party — public metadata only.
    ///
    /// The shim uses this to decide whether to offer a passkey at all, without
    /// putting a prompt on screen. Nothing here is secret: the relying party
    /// already knows every field, having issued them.
    fn handle_passkey_list(
        message: &IpcMessage,
        host: &Arc<dyn Host>,
        peer: &PeerIdentity,
    ) -> IpcMessage {
        if let Err(reason) = passkey_peer_is_ours(peer) {
            return IpcMessage::error(reason);
        }

        let rp_id = message
            .payload
            .get("rp_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let state = host.state();
        {
            let session = state.session.read();
            if !session.active || session.is_expired() {
                return IpcMessage {
                    msg_type: IpcMessageType::PasskeyListResponse,
                    payload: serde_json::json!({ "credentials": [], "locked": true }),
                    capability: None,
                };
            }
        }

        let vault = state.vault.read();
        let credentials: Vec<_> = vault
            .passkeys_for_rp(rp_id)
            .into_iter()
            .map(|item| {
                serde_json::json!({
                    "credential_id": item.credential_id(),
                    "user_name": item.username(),
                    "rp_id": item.rp_id(),
                })
            })
            .collect();

        IpcMessage {
            msg_type: IpcMessageType::PasskeyListResponse,
            payload: serde_json::json!({ "credentials": credentials, "locked": false }),
            capability: None,
        }
    }

    // ── In-core login (M9a) ──────────────────────────────────────────────────
    //
    // The middle rung of the ladder, for sites that have no passkey to offer.
    // `AutofillRequest` below answers "give me the password"; this answers
    // "sign me in", and the difference is that the password stays here. What
    // goes back is the session the site issued — which the model
    // (`m9a_in_core_login.spthy`) is explicit about being in the domain, and
    // which the response therefore annotates with what it is worth.

    /// Which saved logins could sign in to this page — no secrets.
    ///
    /// The same shape as `handle_passkey_list`, and for the same reason: the
    /// caller has to be able to decide whether to offer in-core login at all
    /// without a prompt appearing, and it must be able to do that without the
    /// password. Usernames and item names are already on the user's screen.
    fn handle_in_core_login_candidates(
        message: &IpcMessage,
        host: &Arc<dyn Host>,
        peer: &PeerIdentity,
    ) -> IpcMessage {
        if let Err(reason) = passkey_peer_is_ours(peer) {
            return IpcMessage::error(reason);
        }

        let url = message.payload.get("url").and_then(|v| v.as_str()).unwrap_or("");
        let state = host.state();
        {
            let session = state.session.read();
            if !session.active || session.is_expired() {
                return IpcMessage {
                    msg_type: IpcMessageType::InCoreLoginCandidatesResponse,
                    payload: serde_json::json!({ "candidates": [], "locked": true }),
                    capability: None,
                };
            }
        }

        let vault = state.vault.read();
        let candidates: Vec<_> = vault
            .search_by_domain(url)
            .into_iter()
            .map(|item| {
                serde_json::json!({
                    "item_id": item.id(),
                    "name": item.name(),
                    "username": item.username().unwrap_or_default(),
                    "credential_change_needs_reauth": item.credential_change_needs_reauth(),
                })
            })
            .collect();

        IpcMessage {
            msg_type: IpcMessageType::InCoreLoginCandidatesResponse,
            payload: serde_json::json!({ "candidates": candidates, "locked": false }),
            capability: None,
        }
    }

    async fn handle_in_core_login(
        message: &IpcMessage,
        host: &Arc<dyn Host>,
        peer: &PeerIdentity,
    ) -> IpcMessage {
        if let Err(reason) = passkey_peer_is_ours(peer) {
            return IpcMessage::error(reason);
        }

        let payload = &message.payload;
        let item_id = payload
            .get("item_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if item_id.is_empty() {
            // Resolving "the login for this page" here would mean guessing when
            // a user has several accounts on a site, and guessing wrong means
            // signing them in as the wrong person. The caller asks for
            // candidates and picks one.
            return IpcMessage::error("Missing item_id".to_string());
        }
        let login_url = payload
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // Work out the site *before* prompting, and prompt about that site. A
        // prompt naming the item but not the destination would be answerable
        // without knowing where the password is going.
        let (site, item_name) = {
            let state = host.state();
            {
                let session = state.session.read();
                if !session.active || session.is_expired() {
                    return IpcMessage::error("Vault is locked".to_string());
                }
            }
            let vault = state.vault.read();
            let Some(item) = vault.get_item(&item_id) else {
                return IpcMessage::error("No such vault item".to_string());
            };
            match crate::login::site_for_item(item) {
                Some(site) => (site, item.name().to_string()),
                None => {
                    return IpcMessage::error(
                        "That login has no website address saved".to_string(),
                    )
                }
            }
        };

        let presence = crate::presence::PresenceRequest {
            rp_id: site,
            requester: peer.describe(),
            kind: crate::presence::CeremonyKind::SubmitPassword,
        };

        let grant = match with_login_grant(host, presence, item_id.clone()).await {
            Ok(grant) => grant,
            Err(reason) => {
                warn!("Refused in-core login for {}: {}", peer.describe(), reason);
                return IpcMessage::error(reason);
            }
        };

        let request = crate::login::LoginRequest { item_id, login_url };
        match crate::login::perform_login(host.state(), &request, grant).await {
            Ok(outcome) => {
                info!("In-core login to {} completed", item_name);
                // Serialising the outcome wholesale is deliberate: the type has
                // no field that can hold a credential, so there is nothing here
                // to filter, and hand-copying fields is how a future field
                // quietly stops being filtered.
                let mut payload = serde_json::to_value(&outcome)
                    .unwrap_or_else(|_| serde_json::json!({}));
                if let Some(object) = payload.as_object_mut() {
                    object.insert("success".to_string(), serde_json::json!(true));
                }
                IpcMessage {
                    msg_type: IpcMessageType::InCoreLoginResponse,
                    payload,
                    capability: None,
                }
            }
            Err(reason) => {
                warn!("In-core login failed for {}: {}", peer.describe(), reason);
                IpcMessage::error(reason.to_string())
            }
        }
    }

    /// Ask the human, then hand back the grant. One approval, one login.
    ///
    /// Separate from [`with_presence`] because the work that spends this token
    /// is `async` — it talks to a website — while the prompt itself blocks a
    /// thread waiting for a person. So the prompt runs in `spawn_blocking` and
    /// the grant is carried out of it, rather than the ceremony running inside.
    async fn with_login_grant(
        host: &Arc<dyn Host>,
        request: crate::presence::PresenceRequest,
        item_id: String,
    ) -> Result<crate::login::LoginGrant, String> {
        let host = host.clone();
        tokio::task::spawn_blocking(move || {
            crate::presence::confirm_login(&host, &request, &item_id).map_err(|e| e.to_string())
        })
        .await
        .unwrap_or_else(|e| Err(format!("Sign-in approval did not complete: {e}")))
    }

    async fn handle_autofill_request(
        message: &IpcMessage,
        host: &Arc<dyn Host>,
        peer: &PeerIdentity,
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

        // Releasing plaintext is the one thing on this socket that a stolen
        // capability file would be worth stealing for, so it is the one thing
        // the token alone does not buy (audit D-4). The caller has to be a
        // process the kernel says is ours, and the user has to have proved
        // presence recently — the token proves neither.
        let vault = state.vault.read();
        let items = vault.search_by_domain(&base_domain);
        if user_initiated {
            if let Err(reason) = authorize_plaintext_release(host, peer) {
                warn!("Refused plaintext credential release to {}", peer.describe());
                drop(vault);
                return IpcMessage::error(reason);
            }
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
            credential_change_needs_reauth: false,
            allow_second_factor_downgrade: false,
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
            let peer = crate::ipc_peer::identify_named_pipe(&server);
            tokio::spawn(async move {
                host.state()
                    .extension_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = handle_connection(server, host.clone(), capability, peer).await {
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
            let peer = crate::ipc_peer::identify_unix(&stream);
            // The socket is already 0600, so this should be unreachable — which
            // is exactly why it is cheap to enforce and worth enforcing.
            if !peer.is_same_user() {
                warn!("Refused IPC connection from another user: {}", peer.describe());
                continue;
            }
            let host = host.clone();
            let capability = capability.clone();
            tokio::spawn(async move {
                host.state()
                    .extension_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = handle_connection(stream, host.clone(), capability, peer).await {
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
        use std::sync::atomic::{AtomicI8, AtomicUsize, Ordering};

        /// A peer identical to what the kernel reports for a genuine local
        /// connection: this process, running as this user.
        fn test_peer() -> PeerIdentity {
            PeerIdentity {
                pid: Some(std::process::id()),
                uid: Some(crate::ipc_peer::current_uid()),
                exe: std::env::current_exe().ok(),
            }
        }

        struct MockHost {
            state: Arc<AppState>,
            focus_calls: AtomicUsize,
            quick_search_calls: AtomicUsize,
            notify_calls: AtomicUsize,
            /// What this host answers when asked to confirm presence:
            /// -1 = cannot ask at all, 0 = the user declined, 1 = approved.
            /// Defaults to "cannot ask", so a test that wants a ceremony to
            /// succeed has to say so.
            presence_answer: AtomicI8,
            presence_prompts: AtomicUsize,
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
                    presence_answer: AtomicI8::new(-1),
                    presence_prompts: AtomicUsize::new(0),
                });
                (dir, host)
            }

            fn focuses(&self) -> usize {
                self.focus_calls.load(Ordering::SeqCst)
            }

            fn notifies(&self) -> usize {
                self.notify_calls.load(Ordering::SeqCst)
            }

            fn set_presence_answer(&self, answer: Option<bool>) {
                self.presence_answer.store(
                    match answer {
                        None => -1,
                        Some(false) => 0,
                        Some(true) => 1,
                    },
                    Ordering::SeqCst,
                );
            }

            /// How many times the user was actually asked.
            fn presence_prompts(&self) -> usize {
                self.presence_prompts.load(Ordering::SeqCst)
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
            fn confirm_presence(&self, _prompt: &str) -> Option<bool> {
                self.presence_prompts.fetch_add(1, Ordering::SeqCst);
                match self.presence_answer.load(Ordering::SeqCst) {
                    1 => Some(true),
                    0 => Some(false),
                    _ => None,
                }
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
            let resp = process_message(no_cap, &host, "real-cap", &test_peer()).await;
            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert_eq!(resp.payload["message"], "Unauthorized IPC request");

            let wrong = message(IpcMessageType::Ping, serde_json::json!({}), "nope");
            let resp = process_message(wrong, &host, "real-cap", &test_peer()).await;
            assert_eq!(resp.payload["message"], "Unauthorized IPC request");
        }

        #[tokio::test]
        async fn ping_pong_and_open_vault() {
            let (_dir, mock) = MockHost::new(false);
            let host: Arc<dyn Host> = mock.clone();

            let resp = process_message(message(IpcMessageType::Ping, serde_json::json!({}), "cap"), &host, "cap", &test_peer()).await;
            assert_eq!(resp.msg_type, IpcMessageType::Pong);
            assert_eq!(resp.payload["connected"], true);

            let resp = process_message(message(IpcMessageType::OpenVault, serde_json::json!({}), "cap"), &host, "cap", &test_peer()).await;
            assert_eq!(resp.msg_type, IpcMessageType::Pong);
            assert_eq!(mock.focuses(), 1, "open_vault surfaces the main window");

            let resp = process_message(
                message(IpcMessageType::BiometricChallenge, serde_json::json!({}), "cap"),
                &host,
                "cap",
                &test_peer(),
            )
            .await;
            assert_eq!(resp.payload["message"], "Unknown message type");
        }

        #[tokio::test]
        async fn plaintext_is_refused_to_a_peer_the_kernel_says_is_someone_else() {
            let (_dir, mock) = MockHost::new(true);
            let host: Arc<dyn Host> = mock.clone();
            let stranger = PeerIdentity { pid: Some(1), uid: Some(crate::ipc_peer::current_uid() + 1), exe: None };

            let resp = process_message(
                message(
                    IpcMessageType::AutofillRequest,
                    serde_json::json!({ "domain": "https://github.com", "user_initiated": true }),
                    "cap",
                ),
                &host,
                "cap",
                &stranger,
            )
            .await;

            assert_eq!(resp.msg_type, IpcMessageType::Error, "a valid token must not be enough");
        }

        #[tokio::test]
        async fn plaintext_is_refused_when_the_peer_cannot_be_identified() {
            let (_dir, mock) = MockHost::new(true);
            let host: Arc<dyn Host> = mock.clone();

            let resp = process_message(
                message(
                    IpcMessageType::AutofillRequest,
                    serde_json::json!({ "domain": "https://github.com", "user_initiated": true }),
                    "cap",
                ),
                &host,
                "cap",
                &PeerIdentity::default(),
            )
            .await;

            assert_eq!(resp.msg_type, IpcMessageType::Error, "unknown peer must not read as ours");
        }

        /// The wire names are the contract with `vela-native-messaging-host.py`,
        /// which matches on these strings. A rename here that is not mirrored
        /// there breaks passkeys silently — the host just stops recognising the
        /// reply — so pin them.
        #[test]
        fn passkey_message_types_have_the_wire_names_the_native_host_expects() {
            let name = |t: IpcMessageType| serde_json::to_string(&t).unwrap();

            assert_eq!(name(IpcMessageType::PasskeyCreate), "\"passkey_create\"");
            assert_eq!(
                name(IpcMessageType::PasskeyCreateResponse),
                "\"passkey_create_response\""
            );
            assert_eq!(name(IpcMessageType::PasskeyGet), "\"passkey_get\"");
            assert_eq!(name(IpcMessageType::PasskeyGetResponse), "\"passkey_get_response\"");
            assert_eq!(name(IpcMessageType::PasskeyList), "\"passkey_list\"");
            assert_eq!(
                name(IpcMessageType::PasskeyListResponse),
                "\"passkey_list_response\""
            );

            for alias in ["\"passkey_get\"", "\"PasskeyGet\"", "\"passkeyGet\""] {
                let parsed: IpcMessageType = serde_json::from_str(alias).unwrap();
                assert_eq!(parsed, IpcMessageType::PasskeyGet, "alias {alias}");
            }
        }

        // ── M7: the passkey tier ─────────────────────────────────────────────
        //
        // These mirror the lemmas in
        // `security/formal/m7_oneshot_assertion.spthy`. The model's `Out()` is
        // this IPC boundary, so testing here is testing the same claim the
        // prover checks: what can a co-resident process obtain by asking?

        /// The vault the model calls `!Vault(cred, $O)`.
        fn seed_passkey(mock: &Arc<MockHost>, rp_id: &str) -> String {
            let request = crate::passkey::MakeCredentialRequest {
                rp_id: rp_id.to_string(),
                rp_name: rp_id.to_string(),
                user_handle: b"handle".to_vec(),
                user_name: "alice".to_string(),
                user_display_name: "Alice".to_string(),
                client_data_hash: [7u8; 32],
                algorithms: vec![-7],
                excluded_credential_ids: Vec::new(),
                require_user_verification: false,
            };
            let response = crate::passkey::make_credential(
                &mock.state,
                &request,
                crate::passkey::PresenceToken::mint(true),
            )
            .expect("seeding a credential should succeed");
            response.credential_id
        }

        fn passkey_get(rp_id: &str) -> IpcMessage {
            message(
                IpcMessageType::PasskeyGet,
                serde_json::json!({
                    "rp_id": rp_id,
                    "client_data_hash": b64url_encode(&[9u8; 32]),
                }),
                "cap",
            )
        }

        /// `credential_never_leaks`: the key is never in anything that crosses
        /// this boundary, even for the credential in active use.
        #[tokio::test]
        async fn an_assertion_response_never_carries_the_credential_key() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let resp = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::PasskeyGetResponse);
            // The stored secret, in the form it is stored in.
            let stored = {
                let vault = mock.state.vault.read();
                match vault.passkeys_for_rp("github.com")[0] {
                    crate::vault::VaultItem::Passkey { private_key, .. } => private_key.clone(),
                    _ => unreachable!(),
                }
            };
            let rendered = serde_json::to_string(&resp).unwrap();
            assert!(!rendered.contains(&stored), "credential key crossed the IPC boundary");
        }

        /// `assertion_requires_user_presence`: no human, no signature. This is
        /// the lemma that bounds the entire M7 residual — without it the
        /// assertion path is an oracle a resident process can call at will.
        #[tokio::test]
        async fn no_assertion_without_a_presence_confirmation() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(false));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let resp = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error, "{:?}", resp.payload);
            assert_eq!(mock.presence_prompts(), 1, "the user must actually have been asked");
        }

        /// Where nothing can ask a human, the ceremony is refused rather than
        /// assumed — the deliberate difference from `authorize_plaintext_release`.
        #[tokio::test]
        async fn no_assertion_where_there_is_no_way_to_ask() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(None);
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let resp = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
        }

        /// `assertions_bounded_by_presence`: n logins cost n human actions.
        #[tokio::test]
        async fn every_assertion_costs_its_own_confirmation() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            for _ in 0..3 {
                let resp = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;
                assert_eq!(resp.msg_type, IpcMessageType::PasskeyGetResponse);
            }

            assert_eq!(mock.presence_prompts(), 3, "one prompt per assertion, not one per burst");
        }

        /// `assertion_is_origin_bound`: the signature covers the RP ID hash, so
        /// a credential for one site cannot answer for another.
        #[tokio::test]
        async fn an_assertion_is_bound_to_the_relying_party_that_asked() {
            use sha2::{Digest, Sha256};
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let resp = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;

            let auth_data = b64url_decode(resp.payload["authenticator_data"].as_str()).unwrap();
            assert_eq!(&auth_data[..32], Sha256::digest(b"github.com").as_slice());
            assert_ne!(&auth_data[..32], Sha256::digest(b"evil-github.com").as_slice());
        }

        /// A lookalike origin gets nothing — and is refused before any prompt,
        /// so it cannot even be used to nag the user.
        #[tokio::test]
        async fn a_lookalike_relying_party_gets_no_assertion_and_no_prompt() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let resp =
                process_message(passkey_get("evil-github.com"), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert_eq!(mock.presence_prompts(), 0, "a site with no passkey must not prompt");
        }

        /// The capability token is not enough here either — same reasoning as
        /// the plaintext path, since anything running as this user can read it.
        #[tokio::test]
        async fn an_assertion_is_refused_to_a_peer_the_kernel_says_is_someone_else() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");
            let stranger = PeerIdentity {
                pid: Some(1),
                uid: Some(crate::ipc_peer::current_uid() + 1),
                exe: None,
            };

            let resp = process_message(passkey_get("github.com"), &host, "cap", &stranger).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert_eq!(mock.presence_prompts(), 0);
        }

        /// A relying party that demands user *verification* must not be told a
        /// dialog click was a biometric.
        #[tokio::test]
        async fn user_verification_is_not_satisfied_by_a_dialog_click() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let resp = process_message(
                message(
                    IpcMessageType::PasskeyGet,
                    serde_json::json!({
                        "rp_id": "github.com",
                        "client_data_hash": b64url_encode(&[9u8; 32]),
                        "require_user_verification": true,
                    }),
                    "cap",
                ),
                &host,
                "cap",
                &test_peer(),
            )
            .await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
        }

        /// The signature counter moves, so a relying party can still detect a
        /// cloned authenticator.
        #[tokio::test]
        async fn the_signature_counter_advances_per_assertion() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let first = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;
            let second = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;

            let count = |resp: &IpcMessage| {
                let d = b64url_decode(resp.payload["authenticator_data"].as_str()).unwrap();
                u32::from_be_bytes([d[33], d[34], d[35], d[36]])
            };
            assert!(count(&second) > count(&first), "counter did not advance");
        }

        /// A locked vault signs nothing, and does not ask.
        #[tokio::test]
        async fn a_locked_vault_produces_no_assertion() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(false);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();

            let resp = process_message(passkey_get("github.com"), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert_eq!(mock.presence_prompts(), 0);
        }

        /// The list endpoint is metadata only — it must never become a way to
        /// read a credential without a prompt.
        #[tokio::test]
        async fn listing_passkeys_returns_metadata_and_no_key() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            let host: Arc<dyn Host> = mock.clone();
            seed_passkey(&mock, "github.com");

            let resp = process_message(
                message(
                    IpcMessageType::PasskeyList,
                    serde_json::json!({ "rp_id": "github.com" }),
                    "cap",
                ),
                &host,
                "cap",
                &test_peer(),
            )
            .await;

            assert_eq!(resp.msg_type, IpcMessageType::PasskeyListResponse);
            assert_eq!(resp.payload["credentials"].as_array().unwrap().len(), 1);
            let rendered = serde_json::to_string(&resp).unwrap();
            assert!(!rendered.contains("private_key"), "{rendered}");
            assert_eq!(mock.presence_prompts(), 0, "listing must not prompt");
        }

        #[tokio::test]
        async fn metadata_does_not_need_a_presence_confirmation() {
            // Names and usernames are not the secret; only the plaintext path is
            // gated, so a locked-down machine still gets useful suggestions.
            let (_dir, mock) = MockHost::new(true);
            let host: Arc<dyn Host> = mock.clone();

            let resp = process_message(
                message(
                    IpcMessageType::AutofillRequest,
                    serde_json::json!({ "domain": "https://github.com", "user_initiated": false }),
                    "cap",
                ),
                &host,
                "cap",
                &PeerIdentity::default(),
            )
            .await;

            assert_ne!(resp.msg_type, IpcMessageType::Error);
        }

        /// CI has no Windows Hello and no fingerprint reader, so
        /// `verify_presence` reports `Unavailable` here — the same machine most
        /// Linux desktops are.
        ///
        /// Filling has to keep working there: the release rests on the peer
        /// check and the unlocked session, and the auto-lock is what keeps an
        /// idle machine from being drained. The locked-vault refusal is covered
        /// by `autofill_locked_vault_requires_biometric`, which is the half
        /// that actually holds this up.
        #[tokio::test]
        async fn plaintext_is_released_when_nothing_can_confirm_but_the_vault_is_open() {
            let (_dir, mock) = MockHost::new(true);
            let host: Arc<dyn Host> = mock.clone();
            let us = test_peer();

            let resp = process_message(
                message(
                    IpcMessageType::AutofillRequest,
                    serde_json::json!({ "domain": "https://github.com", "user_initiated": true }),
                    "cap",
                ),
                &host,
                "cap",
                &us,
            )
            .await;

            assert!(us.is_same_user());
            assert_eq!(
                resp.msg_type,
                IpcMessageType::AutofillResponse,
                "a machine with no presence factor must still be able to fill"
            );
        }

        #[test]
        fn a_release_grant_is_tied_to_one_caller_and_expires() {
            let dir = tempfile::tempdir().unwrap();
            let state = Arc::new(AppState::for_test(dir.path()));

            assert!(!state.plaintext_release_is_fresh(Some(42)), "nothing granted yet");

            state.record_plaintext_release(Some(42));
            assert!(state.plaintext_release_is_fresh(Some(42)));
            assert!(!state.plaintext_release_is_fresh(Some(43)), "another process cannot ride on it");
            assert!(!state.plaintext_release_is_fresh(None), "an unidentified caller cannot either");

            state.clear_plaintext_release();
            assert!(!state.plaintext_release_is_fresh(Some(42)), "locking revokes it");
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
            let resp = process_message(req, &host, "cap", &test_peer()).await;
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
                    credential_change_needs_reauth: false,
                    allow_second_factor_downgrade: false,
                });
            }
            let host: Arc<dyn Host> = mock.clone();

            // user_initiated: full credentials — but only once presence has
            // been confirmed. Standing in for a confirmation the user just
            // completed, because CI has no factor to complete one with; the
            // refusal when there is no factor at all is covered separately by
            // plaintext_is_refused_when_nothing_can_confirm_a_person_is_here.
            let peer = test_peer();
            mock.state.record_plaintext_release(peer.pid);

            let req = message(
                IpcMessageType::AutofillRequest,
                serde_json::json!({ "domain": "https://github.com/login", "user_initiated": true }),
                "cap",
            );
            let resp = process_message(req, &host, "cap", &peer).await;
            let items = resp.payload["items"].as_array().unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["password"], "s3cret");

            // Passive (page-load) request: metadata only, never passwords.
            let req = message(
                IpcMessageType::AutofillRequest,
                serde_json::json!({ "domain": "https://github.com/login", "user_initiated": false }),
                "cap",
            );
            let resp = process_message(req, &host, "cap", &peer).await;
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
            let resp = process_message(req, &host, "cap", &test_peer()).await;
            assert_eq!(resp.payload["success"], false);
            assert_eq!(resp.payload["error"], "Password is required");

            // Happy path: item lands in the vault, UI notified, name defaults
            // to the domain.
            let req = message(
                IpcMessageType::SaveCredentials,
                serde_json::json!({ "username": "alice", "password": "pw", "url": "https://github.com/login", "name": "" }),
                "cap",
            );
            let resp = process_message(req, &host, "cap", &test_peer()).await;
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
            let resp = process_message(req, &host, "cap", &test_peer()).await;
            assert_eq!(resp.payload["success"], false);
            assert_eq!(resp.payload["error"], "Vault is locked");
            assert_eq!(mock.focuses(), 1);
        }

        // ── M9a: the in-core login tier ──────────────────────────────────────
        //
        // `security/formal/m9a_in_core_login.spthy` puts the session artifact
        // in the domain and keeps the credential out of it. The IPC boundary is
        // that `Out()`, so the question these ask is the model's question: what
        // does a co-resident process get by asking for a login?

        /// A site with a login form, plus a vault item pointing at it.
        async fn seed_site_and_login(
            mock: &Arc<MockHost>,
        ) -> (wiremock::MockServer, String) {
            use wiremock::matchers::{method as http_method, path as http_path};
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;
            Mock::given(http_method("GET"))
                .and(http_path("/login"))
                .respond_with(ResponseTemplate::new(200).set_body_string(
                    r#"<form method="POST" action="/session">
                       <input type="text" name="user"><input type="password" name="pw"></form>"#,
                ))
                .mount(&server)
                .await;
            Mock::given(http_method("POST"))
                .and(http_path("/session"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .append_header("set-cookie", "sid=granted; Path=/; HttpOnly")
                        .set_body_string("<html>Welcome</html>"),
                )
                .mount(&server)
                .await;

            let now = chrono::Utc::now();
            let item = VaultItem::Login {
                meta: crate::vault::VaultMeta {
                    id: "login-1".to_string(),
                    name: "Test site".to_string(),
                    notes: None,
                    created_at: now,
                    updated_at: now,
                    last_modified_device: None,
                    favorite: false,
                    shared: false,
                    share_recipient: None,
                },
                url: format!("{}/login", server.uri()),
                username: "alice".to_string(),
                pass: "hunter2-not-in-any-response".to_string(),
                totp: None,
                app_ids: Vec::new(),
                credential_change_needs_reauth: false,
                allow_second_factor_downgrade: false,
            };
            mock.state.vault.write().add_item(item);
            (server, "login-1".to_string())
        }

        fn in_core_login(item_id: &str) -> IpcMessage {
            message(
                IpcMessageType::InCoreLogin,
                serde_json::json!({ "item_id": item_id }),
                "cap",
            )
        }

        /// `credential_never_leaks`, at the boundary the model draws it at. The
        /// caller gets a session; the password is not in the reply in any form.
        #[tokio::test]
        async fn an_in_core_login_returns_a_session_and_never_the_password() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            let (_server, item_id) = seed_site_and_login(&mock).await;

            let resp = process_message(in_core_login(&item_id), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::InCoreLoginResponse);
            let rendered = serde_json::to_string(&resp).unwrap();
            assert!(
                !rendered.contains("hunter2-not-in-any-response"),
                "the password crossed the IPC boundary: {rendered}"
            );
            assert_eq!(resp.payload["cookies"][0]["name"], "sid");
            assert_eq!(resp.payload["cookies"][0]["http_only"], true);
            assert_eq!(resp.payload["looks_authenticated"], true);
        }

        /// `Human_Approve_Login`: no approval, no login. Checked by asking the
        /// site whether it heard from us at all — an error reply would also be
        /// produced by a login that happened and then failed.
        #[tokio::test]
        async fn a_declined_in_core_login_never_contacts_the_site() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(false));
            let host: Arc<dyn Host> = mock.clone();
            let (server, item_id) = seed_site_and_login(&mock).await;

            let resp = process_message(in_core_login(&item_id), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert_eq!(mock.presence_prompts(), 1, "the user should have been asked");
            assert!(
                server.received_requests().await.unwrap().is_empty(),
                "a declined login still sent the password"
            );
        }

        /// A machine with no way to ask refuses rather than proceeding. This is
        /// the opposite of what `authorize_plaintext_release` does, and
        /// deliberately: a fill is bounded by the working set, a login that
        /// signs an attacker in as the user is not.
        #[tokio::test]
        async fn a_machine_that_cannot_ask_refuses_the_login() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(None);
            let host: Arc<dyn Host> = mock.clone();
            let (server, item_id) = seed_site_and_login(&mock).await;

            let resp = process_message(in_core_login(&item_id), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert!(server.received_requests().await.unwrap().is_empty());
        }

        /// A locked vault refuses before prompting, so a page cannot make the
        /// vault nag its owner.
        #[tokio::test]
        async fn a_locked_vault_refuses_an_in_core_login_without_asking() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(false);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();

            let resp = process_message(in_core_login("login-1"), &host, "cap", &test_peer()).await;

            assert_eq!(resp.msg_type, IpcMessageType::Error);
            assert_eq!(resp.payload["message"], "Vault is locked");
            assert_eq!(mock.presence_prompts(), 0);
        }

        /// The response says what the session is worth. `Site_Session_Escalate`
        /// is the reason: at a site where a session can rotate the credential,
        /// the takeover outlives the session, and the user is the only one who
        /// can be told that.
        #[tokio::test]
        async fn the_response_says_what_the_session_residual_is_worth() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            let (_server, item_id) = seed_site_and_login(&mock).await;

            let resp = process_message(in_core_login(&item_id), &host, "cap", &test_peer()).await;

            assert_eq!(resp.payload["site_mode"], "self_serve");
            assert!(
                resp.payload["residual_note"]
                    .as_str()
                    .unwrap()
                    .contains("change the account password"),
                "{}",
                resp.payload["residual_note"]
            );
        }

        /// Candidates are metadata. It must never become a way to read a
        /// password without a prompt.
        #[tokio::test]
        async fn listing_login_candidates_returns_no_password_and_does_not_prompt() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            let host: Arc<dyn Host> = mock.clone();
            let (server, _item_id) = seed_site_and_login(&mock).await;

            let resp = process_message(
                message(
                    IpcMessageType::InCoreLoginCandidates,
                    serde_json::json!({ "url": format!("{}/login", server.uri()) }),
                    "cap",
                ),
                &host,
                "cap",
                &test_peer(),
            )
            .await;

            assert_eq!(resp.msg_type, IpcMessageType::InCoreLoginCandidatesResponse);
            assert_eq!(resp.payload["candidates"].as_array().unwrap().len(), 1);
            assert_eq!(resp.payload["candidates"][0]["username"], "alice");
            let rendered = serde_json::to_string(&resp).unwrap();
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert_eq!(mock.presence_prompts(), 0, "listing must not prompt");
        }

        /// The payload keys are a contract too, and a quieter one than the
        /// message names: `vela-native-messaging-host.py` reads these strings
        /// out of the reply, and a rename here produces a login that "succeeds"
        /// with no cookies rather than an error anyone would notice. Pinning
        /// the exact key set means a field added, removed or renamed in
        /// `LoginOutcome` fails here, pointing at the Python that has to change
        /// with it. Also the last line of defence on secrecy: a key set that
        /// cannot grow without this failing cannot grow a password field.
        #[tokio::test]
        async fn the_login_response_payload_keys_are_the_ones_the_native_host_reads() {
            crate::presence::force_platform_presence_unavailable();
            let (_dir, mock) = MockHost::new(true);
            mock.set_presence_answer(Some(true));
            let host: Arc<dyn Host> = mock.clone();
            let (_server, item_id) = seed_site_and_login(&mock).await;

            let resp = process_message(in_core_login(&item_id), &host, "cap", &test_peer()).await;

            let mut keys: Vec<&str> = resp
                .payload
                .as_object()
                .expect("the payload is an object")
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "cookies",
                    "landing_url",
                    "looks_authenticated",
                    "residual_note",
                    "second_factor_downgraded",
                    "site_mode",
                    "success",
                    "used_second_factor",
                    "user_verified",
                ]
            );

            let mut cookie_keys: Vec<&str> = resp.payload["cookies"][0]
                .as_object()
                .expect("a cookie is an object")
                .keys()
                .map(String::as_str)
                .collect();
            cookie_keys.sort_unstable();
            // `same_site` and `expires_at` are skipped when absent, which this
            // site's cookie exercises: it sets neither.
            assert_eq!(
                cookie_keys,
                ["domain", "host_only", "http_only", "name", "path", "secure", "value"]
            );
        }

        /// Same contract as the passkey names: `vela-native-messaging-host.py`
        /// matches on these strings, so a silent rename breaks the feature.
        #[test]
        fn in_core_login_message_types_have_the_wire_names_the_native_host_expects() {
            let name = |t: IpcMessageType| serde_json::to_string(&t).unwrap();

            assert_eq!(name(IpcMessageType::InCoreLogin), "\"in_core_login\"");
            assert_eq!(
                name(IpcMessageType::InCoreLoginResponse),
                "\"in_core_login_response\""
            );
            assert_eq!(
                name(IpcMessageType::InCoreLoginCandidates),
                "\"in_core_login_candidates\""
            );
            assert_eq!(
                name(IpcMessageType::InCoreLoginCandidatesResponse),
                "\"in_core_login_candidates_response\""
            );
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
