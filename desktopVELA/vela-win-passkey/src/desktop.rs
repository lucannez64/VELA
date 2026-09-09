//! The provider's client side of the desktop IPC pipe.
//!
//! Same endpoint, same framed-JSON protocol the browser extension uses —
//! the provider is just another front end on `passkey.rs`'s two ceremony
//! functions, which is the whole point of their transport-agnostic shape
//! (see `security/passkey-native-provider-adr.md`). Transport is borrowed
//! from `vela-nm-host` so both callers share the ERROR_PIPE_BUSY retry and
//! the same timeouts.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde_json::{json, Value};

/// A passkey's public metadata as the desktop reports it. No secret fields —
/// the private key never leaves the vault, and this struct is what the OS
/// autofill cache sees.
#[derive(Debug, Clone)]
pub struct CredentialMetadata {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

fn send(msg_type: &str, payload: Value, slow: bool) -> Option<Value> {
    // Quiet: the provider's stderr is either machine-readable `--json`
    // output or the OS's COM server log, and a missing pipe (desktop
    // closed or vault locked) is the normal case here — not an error the
    // user can act on.
    let response = vela_nm_host::send_to_desktop_quiet(
        json!({ "msg_type": msg_type, "payload": payload }),
        slow,
    )?;
    let expected = format!("{msg_type}_response");
    let got = response.get("msg_type").and_then(Value::as_str)?;
    if !got.eq_ignore_ascii_case(&expected) {
        return None;
    }
    Some(response.get("payload").cloned().unwrap_or(Value::Null))
}

fn b64url(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

fn b64url_decode(value: Option<&str>) -> Option<Vec<u8>> {
    B64URL.decode(value?).ok()
}

/// Is the desktop running, and is its vault unlocked? `Ok(None)` means the
/// desktop could not be reached at all; `Ok(Some(locked))` is its answer.
pub fn lock_state() -> Result<Option<bool>, String> {
    match send("provider_status", json!({}), false) {
        Some(payload) => Ok(Some(
            payload.get("locked").and_then(Value::as_bool).unwrap_or(true),
        )),
        None => Ok(None),
    }
}

pub struct MakeCredentialOutcome {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
}

/// Drive the desktop's `make_credential` — one ceremony, one human prompt.
pub fn make_credential(request: &Value) -> Result<MakeCredentialOutcome, String> {
    let payload = send(
        "passkey_create",
        request.clone(),
        true, // a human will answer a prompt; never time out under it
    )
    .ok_or_else(|| "Could not reach VELA Desktop".to_string())?;

    if payload.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(payload
            .get("message")
            .or_else(|| payload.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("VELA Desktop refused the request")
            .to_string());
    }

    Ok(MakeCredentialOutcome {
        credential_id: b64url_decode(payload.get("credential_id").and_then(Value::as_str))
            .ok_or_else(|| "Malformed credential_id".to_string())?,
        authenticator_data: b64url_decode(payload.get("authenticator_data").and_then(Value::as_str))
            .ok_or_else(|| "Malformed authenticator_data".to_string())?,
    })
}

pub struct GetAssertionOutcome {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

pub fn get_assertion(request: &Value) -> Result<GetAssertionOutcome, String> {
    let payload = send("passkey_get", request.clone(), true)
        .ok_or_else(|| "Could not reach VELA Desktop".to_string())?;

    if payload.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(payload
            .get("message")
            .or_else(|| payload.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("VELA Desktop refused the request")
            .to_string());
    }

    Ok(GetAssertionOutcome {
        credential_id: b64url_decode(payload.get("credential_id").and_then(Value::as_str))
            .ok_or_else(|| "Malformed credential_id".to_string())?,
        authenticator_data: b64url_decode(payload.get("authenticator_data").and_then(Value::as_str))
            .ok_or_else(|| "Malformed authenticator_data".to_string())?,
        signature: b64url_decode(payload.get("signature").and_then(Value::as_str))
            .ok_or_else(|| "Malformed signature".to_string())?,
        user_handle: b64url_decode(payload.get("user_handle").and_then(Value::as_str))
            .unwrap_or_default(),
    })
}

/// Every passkey in the vault, for pushing OS autofill metadata.
pub fn all_passkeys() -> Result<Vec<CredentialMetadata>, String> {
    let payload = send("provider_sync_credentials", json!({}), false)
        .ok_or_else(|| "Could not reach VELA Desktop".to_string())?;
    if payload.get("locked").and_then(Value::as_bool).unwrap_or(true) {
        return Err("Vault is locked".to_string());
    }
    let mut out = Vec::new();
    for item in payload.get("credentials").and_then(Value::as_array).into_iter().flatten() {
        let Some(credential_id) = b64url_decode(item.get("credential_id").and_then(Value::as_str))
        else {
            continue;
        };
        out.push(CredentialMetadata {
            credential_id,
            rp_id: item.get("rp_id").and_then(Value::as_str).unwrap_or("").to_string(),
            rp_name: item.get("rp_name").and_then(Value::as_str).unwrap_or("").to_string(),
            user_handle: b64url_decode(item.get("user_handle").and_then(Value::as_str))
                .unwrap_or_default(),
            user_name: item.get("user_name").and_then(Value::as_str).unwrap_or("").to_string(),
            user_display_name: item
                .get("user_display_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(out)
}

pub fn encode_b64url(bytes: &[u8]) -> String {
    b64url(bytes)
}
