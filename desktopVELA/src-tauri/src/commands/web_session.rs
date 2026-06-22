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

/// The payload encoded in the browser's link QR.
#[derive(Debug, Deserialize)]
pub struct WebSessionQr {
    pub session_id: String,
    /// Ephemeral hybrid KEM public key (b64, 1600 B) — what we seal to.
    pub ephemeral_pk: String,
    /// Ephemeral signing verification key (b64, 2624 B); required for RW.
    #[serde(default)]
    pub web_vk: Option<String>,
    #[serde(default)]
    pub link_nonce: Option<String>,
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

    let qr: WebSessionQr = serde_json::from_str(qr_payload.trim())
        .map_err(|e| format!("Invalid web access code: {e}"))?;
    let ephemeral_pk = B64
        .decode(qr.ephemeral_pk.as_bytes())
        .map_err(|_| "Invalid ephemeral key in code".to_string())?;

    let token = state
        .get_session_token()
        .ok_or("Not authenticated — unlock your vault first.")?;

    // Build the capsule plaintext from the current (unlocked) state.
    let plaintext = {
        let crypto_guard = state.crypto.read();
        let crypto = crypto_guard
            .as_ref()
            .ok_or("Vault is locked — unlock it to approve web access.")?;
        let envelope = match mode.as_str() {
            "rw" => {
                if qr.web_vk.is_none() {
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

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let expires_at = client
        .grant_web_session(&token, &qr.session_id, &mode, &capsule_b64, ttl_secs)
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
