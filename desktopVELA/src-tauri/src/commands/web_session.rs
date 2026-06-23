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
use tauri::State;

use crate::api::ApiClient;
use crate::commands::audit::{record_audit_event, AuditAction};
use crate::AppState;

/// Optional JSON form of the link code (older format). The current QR/code is
/// just the bare `session_id`; we still accept a JSON blob containing one.
#[derive(Debug, Deserialize)]
pub struct WebSessionQr {
    pub session_id: String,
}

/// Extract the session id from the scanned/pasted code (a bare UUID, or a JSON
/// object with a `session_id`).
fn parse_session_id(input: &str) -> Result<String, String> {
    let t = input.trim();
    if t.starts_with('{') {
        let qr: WebSessionQr =
            serde_json::from_str(t).map_err(|e| format!("Invalid web access code: {e}"))?;
        Ok(qr.session_id)
    } else if t.is_empty() {
        Err("Empty web access code".into())
    } else {
        Ok(t.to_string())
    }
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

    let session_id = parse_session_id(&qr_payload)?;

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
        .grant_web_session(&token, &session_id, &mode, &capsule_b64, ttl_secs)
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
