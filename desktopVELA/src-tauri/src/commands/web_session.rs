//! Approver side of ephemeral web access (`EPHEMERAL_WEB_ACCESS_DESIGN.md`).
//!
//! This enrolled device scans/pastes a browser's link QR, the user picks a mode
//! and duration, and we seal the appropriate capsule to the browser's ephemeral
//! KEM key and POST it to `/web-session/:id/grant`.
//!
//! Capsule envelope (sealed plaintext, JSON):
//! ```json
//! { "v": 1, "mode": "ro", "vault": <VaultStore> }   // read-only snapshot
//! { "v": 1, "mode": "rw", "rms_b64": "<base64 32B>" } // read-write live
//! ```

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;

use crate::api::{ApiClient, WebSessionInfo};
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::AppState;

/// Optional JSON form of the link code (older format). The current QR/code is
/// just the bare `session_id`; we still accept a JSON blob containing one.
#[derive(Debug, Deserialize)]
pub struct WebSessionQr {
    pub session_id: String,
}

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 encode (no padding).
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for &b in bytes {
        value = (value << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(BASE32_ALPHABET[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Compute the 13-char key fingerprint: base32(sha256(raw_key_bytes)[0:8]).
fn key_fingerprint(raw_key: &[u8]) -> String {
    let hash = Sha256::digest(raw_key);
    base32_encode(&hash[..8])
}

/// Extract the session id (and optional key fingerprint / link nonce) from the
/// scanned/pasted code. Formats accepted:
///   - `{session_id}#{fingerprint}#{link_nonce}` ← current QR format
///   - `{session_id}#{fingerprint}`              ← previous QR format
///   - bare UUID                                  ← old format (no fingerprint)
///   - JSON `{"session_id": "..."}`               ← legacy format
/// Returns `(session_id, fingerprint?, link_nonce?)`.
fn parse_session_id(input: &str) -> Result<(String, Option<String>, Option<String>), String> {
    let t = input.trim();
    if t.starts_with('{') {
        let qr: WebSessionQr =
            serde_json::from_str(t).map_err(|e| format!("Invalid web access code: {e}"))?;
        return Ok((qr.session_id, None, None));
    }
    if t.is_empty() {
        return Err("Empty web access code".into());
    }
    let mut parts = t.splitn(3, '#');
    let id = parts.next().unwrap_or_default().to_string();
    let fp = parts
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let link_nonce = parts
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Ok((id, fp, link_nonce))
}

#[derive(Debug, Serialize)]
pub struct GrantResult {
    pub expires_at: String,
    pub mode: String,
}

/// Approve a browser's ephemeral web-access request.
///
/// `qr_payload` is the raw JSON scanned/pasted from the browser's QR. `mode` is
/// `"ro"` or `"rw"`. `ttl_secs` is the requested lifetime (server clamps it).
#[tauri::command]
pub async fn grant_web_session(
    state: State<'_, Arc<AppState>>,
    qr_payload: String,
    mode: String,
    ttl_secs: i64,
) -> Result<GrantResult, String> {
    if mode != "ro" && mode != "rw" {
        return Err("mode must be 'ro' or 'rw'".into());
    }

    let (session_id, expected_fp, link_nonce) = parse_session_id(&qr_payload)?;

    let token = state
        .get_session_token()
        .ok_or("Not authenticated — unlock your vault first.")?;

    // Fetch the browser's ephemeral public key from the server (the QR only
    // carries the session id, so it stays scannable).
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let (ephemeral_pk_b64, web_vk) = client
        .get_web_session_keys(&token, &session_id)
        .await
        .map_err(|e| format!("Could not look up the web request: {e}"))?;
    let ephemeral_pk = B64
        .decode(ephemeral_pk_b64.as_bytes())
        .map_err(|_| "Invalid ephemeral key from server".to_string())?;

    // Verify the key fingerprint if one was embedded in the QR.
    // A mismatch means the server may have substituted a different key — abort.
    if let Some(fp) = expected_fp {
        let actual_fp = key_fingerprint(&ephemeral_pk);
        if actual_fp != fp {
            return Err(format!(
                "Key fingerprint mismatch — possible server-side key substitution. \
                 Expected {fp}, got {actual_fp}. Do not proceed."
            ));
        }
    }

    // Build the capsule plaintext from the current (unlocked) state.
    let plaintext = {
        let crypto_guard = state.crypto.read();
        let crypto = crypto_guard
            .as_ref()
            .ok_or("Vault is locked — unlock it to approve web access.")?;
        let envelope = match mode.as_str() {
            "rw" => {
                if web_vk.is_empty() {
                    return Err(
                        "This browser did not offer read-write access; choose read-only.".into(),
                    );
                }
                serde_json::json!({
                    "v": 1,
                    "mode": "rw",
                    "rms_b64": B64.encode(crypto.rms()),
                })
            }
            _ => {
                let vault = state.vault.read().clone();
                serde_json::json!({ "v": 1, "mode": "ro", "vault": vault })
            }
        };
        serde_json::to_vec(&envelope).map_err(|e| e.to_string())?
    };

    let capsule = crate::crypto::seal_share(&ephemeral_pk, &plaintext)
        .map_err(|e| format!("Failed to seal web access capsule: {e}"))?;
    let capsule_b64 = B64.encode(&capsule);

    let expires_at = client
        .grant_web_session(
            &token,
            &session_id,
            &mode,
            &capsule_b64,
            ttl_secs,
            link_nonce.as_deref(),
        )
        .await
        .map_err(|e| format!("Failed to grant web access: {e}"))?;

    record_audit_event(
        &state,
        AuditAction::WebSessionGranted {
            mode: mode.clone(),
            ttl_secs,
        },
    );

    Ok(GrantResult { expires_at, mode })
}

/// List the caller's active (granted, not-yet-expired) web sessions.
#[tauri::command]
pub async fn list_web_sessions(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<WebSessionInfo>, String> {
    let token = state
        .get_session_token()
        .ok_or("Not authenticated")?;
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    client
        .list_web_sessions(&token)
        .await
        .map_err(|e| e.to_string())
}

/// Revoke an active web session by its id.
#[tauri::command]
pub async fn revoke_web_session(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> Result<(), String> {
    let token = state
        .get_session_token()
        .ok_or("Not authenticated")?;
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    client
        .revoke_web_session(&token, &session_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
