//! `vela ssh list` and `vela ssh-agent`.

pub mod agent;
pub mod openssh_key;

use base64::Engine;
use sha2::Digest;
use vela_desktop_core::vault::VaultItem;

use crate::session::open_vault;
use crate::Cli;

/// Collect agent-usable keys from the vault: every secure note whose content
/// holds an OpenSSH ed25519 private key.
pub fn collect_keys(
    vault: &vela_desktop_core::vault::VaultStore,
) -> Result<Vec<agent::AgentKey>, String> {
    let mut keys = Vec::new();
    for item in vault.items.iter() {
        let VaultItem::SecureNote { title, content, .. } = item else {
            continue;
        };
        for key in openssh_key::extract_keys(content, title)? {
            keys.push(agent::AgentKey {
                public_blob: key.public_blob,
                comment: key.comment,
                signing_key: key.signing_key,
            });
        }
    }
    Ok(keys)
}

/// `SHA256:<base64 unpadded>` — the same fingerprint shape `ssh -l` prints.
pub fn fingerprint(public_blob: &[u8]) -> String {
    let digest = sha2::Sha256::digest(public_blob);
    let engine = base64::engine::general_purpose::STANDARD;
    let b64 = engine.encode(digest);
    let b64 = b64.trim_end_matches('=');
    format!("SHA256:{b64}")
}

pub fn list(cli: &Cli) -> Result<(), String> {
    let vault = open_vault(cli)?;
    let keys = collect_keys(&vault.vault)?;
    if keys.is_empty() {
        println!("No agent-visible keys found.");
        println!("Add a secure note whose content is an unencrypted OpenSSH ed25519 private key");
        println!("(the `ssh-keygen -t ed25519` default format) and run this again.");
        return Ok(());
    }
    for key in &keys {
        let algo = String::from_utf8_lossy(
            &key.public_blob[..key.public_blob.iter().position(|&b| b == 0).unwrap_or(0)],
        );
        // The algorithm string is inside the first length-prefixed field;
        // recovering it here is only for display, so parse it properly.
        let mut r = openssh_key::Reader::new(&key.public_blob);
        let algo = r
            .read_string()
            .map(|s| String::from_utf8_lossy(s).to_string())
            .unwrap_or_else(|_| algo.to_string());
        println!(
            "{:<40}  {}  {}",
            fingerprint(&key.public_blob),
            algo,
            key.comment
        );
    }
    Ok(())
}

pub fn run_agent(cli: &Cli) -> Result<(), String> {
    let vault = open_vault(cli)?;
    let keys = collect_keys(&vault.vault)?;
    if keys.is_empty() {
        return Err(
            "No agent-visible keys: add a secure note holding an unencrypted OpenSSH \
             ed25519 private key, or run `vela ssh list` to check."
                .to_string(),
        );
    }
    println!("Loaded {} key(s) from the vault.", keys.len());
    for key in &keys {
        println!("  {} {}", fingerprint(&key.public_blob), key.comment);
    }

    let listener = resolve_listener(cli)?;
    let state = std::sync::Arc::new(agent::AgentState { keys });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Could not start the async runtime: {e}"))?;
    runtime.block_on(agent::serve(state, listener))
}

fn resolve_listener(cli: &Cli) -> Result<agent::Listener, String> {
    if cli.flag("help") {
        return Err("usage: vela ssh-agent [--socket PATH | --pipe NAME]".to_string());
    }
    if let Some(path) = cli.opt("socket") {
        return Ok(agent::Listener::UnixSocket(std::path::PathBuf::from(path)));
    }
    if let Some(name) = cli.opt("pipe") {
        let name = if name.starts_with("\\\\.\\") {
            name.to_string()
        } else {
            format!(r"\\.\pipe\{name}")
        };
        return Ok(agent::Listener::Pipe(name));
    }
    #[cfg(windows)]
    {
        Ok(agent::Listener::Pipe(
            r"\\.\pipe\vela-ssh-agent".to_string(),
        ))
    }
    #[cfg(not(windows))]
    {
        let dir = std::env::var("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        Ok(agent::Listener::UnixSocket(dir.join("vela-ssh-agent.sock")))
    }
}
