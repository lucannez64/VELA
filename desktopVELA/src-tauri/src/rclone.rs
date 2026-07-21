//! Minimal wrapper around the `rclone` CLI for cloud-backup recovery-share
//! uploads (SPEC.md §4.3, Share 1). Only two operations are needed: list the
//! user's already-configured remotes, and upload one opaque blob to a fixed
//! path under a chosen remote.
//!
//! Deliberately shells out via `std::process::Command` with argv arrays
//! (never a shell string) — same pattern as the macOS Secure Enclave probe
//! in `device.rs`. The frontend never gets direct process-execution access;
//! it can only call the two Tauri commands built on top of this module.

use std::io::Write;
use std::process::{Command, Stdio};

/// rclone remote names are user-chosen identifiers, never file paths — this
/// allowlist keeps the value from smuggling anything `rclone` might parse
/// as a separate flag or a different remote:path pair.
fn validate_remote_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 100 {
        return Err("Invalid remote name".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Invalid remote name: only letters, numbers, '-' and '_' are allowed".to_string(),
        );
    }
    Ok(())
}

/// List configured remotes (as shown by `rclone listremotes`, without the
/// trailing colon). Returns a clear error if `rclone` itself isn't
/// installed, rather than a confusing OS-level "not found" message.
pub fn list_remotes() -> Result<Vec<String>, String> {
    let output = Command::new("rclone")
        .arg("listremotes")
        .output()
        .map_err(|e| {
            format!(
                "Could not run rclone ({e}). Install rclone and configure at least one remote \
                 with `rclone config` first."
            )
        })?;

    if !output.status.success() {
        return Err(format!(
            "rclone listremotes failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let remotes = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().trim_end_matches(':');
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect();
    Ok(remotes)
}

/// Upload `data` to `<remote>:<dest_path>` via `rclone rcat` (streamed over
/// stdin — no temp file with plaintext-adjacent share material left behind).
/// `dest_path` must be a fixed, non-user-controlled constant; only `remote`
/// is caller-supplied and it is validated before use.
pub fn upload_bytes(remote: &str, dest_path: &str, data: &[u8]) -> Result<(), String> {
    validate_remote_name(remote)?;
    let target = format!("{remote}:{dest_path}");

    let mut child = Command::new("rclone")
        .arg("rcat")
        .arg(&target)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not run rclone ({e}). Is it installed?"))?;

    child
        .stdin
        .take()
        .ok_or("Failed to open rclone stdin")?
        .write_all(data)
        .map_err(|e| format!("Failed to write to rclone stdin: {e}"))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for rclone: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "rclone upload to '{remote}' failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}
