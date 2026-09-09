//! The SSH agent: protocol framing, request handling, and the pipe/socket
//! server.
//!
//! Wire protocol per the agent draft (draft-miller-ssh-agent): each message
//! is a u32 big-endian length followed by the payload, whose first byte is
//! the message type. Only what an agent must speak is implemented:
//! `REQUEST_IDENTITIES` (list), `SIGN_REQUEST` (sign with the key whose
//! public blob the request echoes), and `FAILURE` for everything else.
//!
//! A sign request must name a key this agent actually holds — matching the
//! full public blob, not just the key type — so a client cannot ask one key
//! to sign under another's identity.

use ed25519_dalek::{Signer as _, SigningKey};
use std::sync::Arc;

use super::openssh_key::{put_string, put_u32, Reader};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Upper bound on a single framed message: agent messages are tiny; a
/// multi-gigabyte length prefix is an attack, not a request.
const MAX_MESSAGE_LEN: u32 = 1024 * 1024;

pub struct AgentKey {
    pub public_blob: Vec<u8>,
    pub comment: String,
    pub signing_key: SigningKey,
}

pub struct AgentState {
    pub keys: Vec<AgentKey>,
}

pub fn handle_request(state: &AgentState, msg: &[u8]) -> Vec<u8> {
    let Some((&msg_type, body)) = msg.split_first() else {
        return vec![SSH_AGENT_FAILURE];
    };

    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
            put_u32(&mut out, state.keys.len() as u32);
            for key in &state.keys {
                put_string(&mut out, &key.public_blob);
                put_string(&mut out, key.comment.as_bytes());
            }
            out
        }
        SSH_AGENTC_SIGN_REQUEST => {
            let mut r = Reader::new(body);
            let (Ok(req_blob), Ok(data)) = (r.read_string(), r.read_string()) else {
                return vec![SSH_AGENT_FAILURE];
            };
            let Some(key) = state.keys.iter().find(|k| k.public_blob == req_blob) else {
                // Not one of ours — refuse rather than sign with whatever
                // else happens to be loaded.
                return vec![SSH_AGENT_FAILURE];
            };
            let signature = key.signing_key.sign(data);
            let mut sig_blob = Vec::with_capacity(4 + 11 + 4 + 64);
            put_string(&mut sig_blob, b"ssh-ed25519");
            put_string(&mut sig_blob, &signature.to_bytes());
            let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
            put_string(&mut out, &sig_blob);
            out
        }
        _ => vec![SSH_AGENT_FAILURE],
    }
}

/// Frame, dispatch, and answer requests on one connection until EOF.
pub async fn serve_stream<S>(stream: &mut S, state: &AgentState) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let mut len_bytes = [0u8; 4];
        match stream.read_exact(&mut len_bytes).await {
            Ok(_) => {}
            // A clean disconnect lands here; not an error.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes(len_bytes);
        if len == 0 || len > MAX_MESSAGE_LEN {
            return Ok(());
        }

        let mut msg = vec![0u8; len as usize];
        stream.read_exact(&mut msg).await?;
        let reply = handle_request(state, &msg);

        stream
            .write_all(&(reply.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&reply).await?;
        stream.flush().await?;
    }
}

/// Serve until the process is interrupted.
pub async fn serve(state: Arc<AgentState>, listener: Listener) -> Result<(), String> {
    match listener {
        Listener::Pipe(name) => serve_pipe(&name, state).await,
        Listener::UnixSocket(path) => serve_unix(&path, state).await,
    }
}

pub enum Listener {
    /// Windows named pipe, full name (`\\.\pipe\...`).
    Pipe(String),
    /// Unix domain socket path.
    UnixSocket(std::path::PathBuf),
}

#[cfg(windows)]
async fn serve_pipe(name: &str, state: Arc<AgentState>) -> Result<(), String> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(name)
        .map_err(|e| format!("Could not create the agent pipe {name}: {e}"))?;

    println!("VELA SSH agent listening on {name}");
    println!("Point your SSH client at this pipe, or run with --pipe \\.\\pipe\\openssh-ssh-agent to take the standard OpenSSH pipe name (disable the built-in agent service first).");
    println!("Press Ctrl+C to stop.");

    loop {
        if let Err(e) = server.connect().await {
            // A client that vanished between create and connect surfaces
            // here; recreate the instance and keep serving.
            eprintln!("vela ssh-agent: pipe connect error: {e}");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            server = ServerOptions::new()
                .create(name)
                .map_err(|e| format!("Could not recreate the agent pipe: {e}"))?;
            continue;
        }
        let client = server;
        server = ServerOptions::new()
            .create(name)
            .map_err(|e| format!("Could not recreate the agent pipe: {e}"))?;
        let state = state.clone();
        tokio::spawn(async move {
            let mut client = client;
            let _ = serve_stream(&mut client, &state).await;
        });
    }
}

#[cfg(not(windows))]
async fn serve_pipe(_name: &str, _state: Arc<AgentState>) -> Result<(), String> {
    Err(
        "Named pipes are the Windows transport; on this platform the agent \
         uses a Unix socket"
            .to_string(),
    )
}

#[cfg(windows)]
async fn serve_unix(_path: &std::path::Path, _state: Arc<AgentState>) -> Result<(), String> {
    Err("Unix sockets are the Unix transport; on Windows the agent uses a named pipe".to_string())
}

#[cfg(unix)]
async fn serve_unix(path: &std::path::Path, state: Arc<AgentState>) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    // A stale socket file from a previous run would make bind() fail.
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Could not create {parent:?}: {e}"))?;
    }
    let listener = tokio::net::UnixListener::bind(path)
        .map_err(|e| format!("Could not bind the agent socket {path:?}: {e}"))?;
    // Only this user may talk to the agent.
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));

    println!("VELA SSH agent listening on {}", path.display());
    println!("export SSH_AUTH_SOCK={}", path.display());
    println!("Press Ctrl+C to stop.");

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = serve_stream(&mut stream, &state).await;
                });
            }
            Err(e) => eprintln!("vela ssh-agent: accept error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::openssh_key::{put_string, put_u32};

    fn agent_key(seed: [u8; 32], comment: &str) -> AgentKey {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = signing_key.verifying_key().to_bytes();
        let mut public_blob = Vec::new();
        put_string(&mut public_blob, b"ssh-ed25519");
        put_string(&mut public_blob, &vk);
        AgentKey {
            public_blob,
            comment: comment.to_string(),
            signing_key,
        }
    }

    #[test]
    fn identities_answer_lists_every_key() {
        let state = AgentState {
            keys: vec![agent_key([1; 32], "a@x"), agent_key([2; 32], "b@x")],
        };
        let reply = handle_request(&state, &[SSH_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(reply[0], SSH_AGENT_IDENTITIES_ANSWER);

        let mut r = Reader::new(&reply[1..]);
        assert_eq!(r.read_u32().unwrap(), 2);
        let blob1 = r.read_string().unwrap().to_vec();
        let comment1 = r.read_string().unwrap();
        let blob2 = r.read_string().unwrap().to_vec();
        let comment2 = r.read_string().unwrap();
        assert_eq!(comment1, b"a@x");
        assert_eq!(comment2, b"b@x");
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn sign_request_signs_with_the_requested_key_only() {
        let state = AgentState {
            keys: vec![agent_key([1; 32], "a@x"), agent_key([2; 32], "b@x")],
        };
        let to_sign = b"session-id-and-stuff";

        // Frame a sign request naming key #2's blob.
        let mut msg = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut msg, &state.keys[1].public_blob);
        put_string(&mut msg, to_sign);
        put_u32(&mut msg, 0);

        let reply = handle_request(&state, &msg);
        assert_eq!(reply[0], SSH_AGENT_SIGN_RESPONSE);
        let mut r = Reader::new(&reply[1..]);
        let sig_blob = r.read_string().unwrap();
        let mut sr = Reader::new(sig_blob);
        assert_eq!(sr.read_string().unwrap(), b"ssh-ed25519");
        let sig = sr.read_string().unwrap();
        assert_eq!(sig.len(), 64);

        // The signature verifies against key #2 — and only key #2.
        let vk2 = ed25519_dalek::SigningKey::from_bytes(&[2; 32]).verifying_key();
        let sig2 = ed25519_dalek::Signature::from_bytes(sig.try_into().unwrap());
        assert!(vk2.verify_strict(to_sign, &sig2).is_ok());
        let vk1 = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        assert!(vk1.verify_strict(to_sign, &sig2).is_err());
    }

    #[test]
    fn unknown_keys_and_messages_fail() {
        let state = AgentState {
            keys: vec![agent_key([1; 32], "a@x")],
        };

        // A sign request naming a key the agent does not hold → FAILURE.
        let mut other_blob = Vec::new();
        let other = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        put_string(&mut other_blob, b"ssh-ed25519");
        put_string(&mut other_blob, &other.verifying_key().to_bytes());
        let mut msg = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut msg, &other_blob);
        put_string(&mut msg, b"data");
        put_u32(&mut msg, 0);
        assert_eq!(handle_request(&state, &msg), vec![SSH_AGENT_FAILURE]);

        // Unknown message type → FAILURE.
        assert_eq!(handle_request(&state, &[99, 1, 2]), vec![SSH_AGENT_FAILURE]);
        // Empty message → FAILURE.
        assert_eq!(handle_request(&state, &[]), vec![SSH_AGENT_FAILURE]);
    }
}
