//! VELA Native Messaging Host.
//!
//! The browser spawns this process over the native messaging stdio protocol.
//! Each request is relayed to VELA Desktop over a well-known per-user
//! endpoint (a Unix socket under `XDG_RUNTIME_DIR`, or a named pipe on
//! Windows) and the reply is written back to stdout.
//!
//! There is no capability file and no shared secret (issue #149, option B).
//! The desktop does not authenticate what this process *says* — it
//! authenticates what the kernel says about *who connected*: same user, the
//! VELA host binary, started by a browser. See `vela-desktop-core`'s
//! `ipc_gate`. This file deliberately holds no secrets, because anything it
//! could read, so could every other process running as this user — which is
//! exactly why the old `ipc_auth.json` scheme was removed.
//!
//! The wire protocol towards the extension is unchanged from the Python
//! host this replaces: length-prefixed JSON in, `{success: ...}` JSON out.

use std::io::{Read, Write};
use std::time::Duration;

use serde_json::{json, Value};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Most requests are answered from memory, so five seconds is generous. A
/// passkey or in-core login ceremony puts a confirmation in front of a person
/// and waits for them to decide — timing that out at five seconds fails every
/// login by someone who did not click instantly.
const DEFAULT_TIMEOUT_SECONDS: u64 = 5;
const SLOW_TIMEOUT_SECONDS: u64 = 120;

// ── Browser side (native messaging stdio framing) ──────────────────────────

fn read_browser_message(stdin: &mut impl Read) -> Option<Value> {
    let mut raw_length = [0u8; 4];
    if stdin.read_exact(&mut raw_length).is_err() {
        return None;
    }
    let length = u32::from_le_bytes(raw_length) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return None;
    }
    let mut payload = vec![0u8; length];
    if stdin.read_exact(&mut payload).is_err() {
        return None;
    }
    serde_json::from_slice(&payload).ok()
}

fn write_browser_message(stdout: &mut impl Write, message: &Value) {
    let payload = serde_json::to_vec(message).expect("serializable response");
    let _ = stdout.write_all(&(payload.len() as u32).to_le_bytes());
    let _ = stdout.write_all(&payload);
    let _ = stdout.flush();
}

// ── Desktop side (endpoint discovery + framed exchange) ────────────────────

/// Where the desktop listens. Must stay in sync with
/// `vela-desktop-core/src/ipc.rs`'s `well_known_endpoint`.
#[cfg(unix)]
fn desktop_endpoint() -> std::path::PathBuf {
    let uid = current_uid();
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return std::path::PathBuf::from(dir)
                .join(format!("vela-{uid}"))
                .join("desktop.sock");
        }
    }
    std::env::temp_dir().join(format!("vela-{uid}")).join("desktop.sock")
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid is always safe; it reads a process property and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(windows)]
fn desktop_endpoint() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let sanitized: String = user
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!(r"\\.\pipe\com.vela.VELA.native.{sanitized}")
}

/// One framed request, one framed response, one connection — the desktop's
/// per-connection gate runs on connect, so keeping exchanges stateless keeps
/// its job simple.
fn send_to_desktop(mut message: Value, slow: bool) -> Option<Value> {
    message["capability"] = Value::Null;

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let mut stream =
            UnixStream::connect(desktop_endpoint()).map_err(|e| eprintln!("Desktop IPC error: {e}")).ok()?;
        let timeout = Duration::from_secs(if slow { SLOW_TIMEOUT_SECONDS } else { DEFAULT_TIMEOUT_SECONDS });
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        return framed_exchange(&mut stream, &message);
    }

    #[cfg(windows)]
    {
        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(desktop_endpoint())
            .map_err(|e| eprintln!("Desktop IPC error: {e}"))
            .ok()?;
        framed_exchange(&mut stream, &message)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (message, slow);
        None
    }
}

fn framed_exchange(stream: &mut (impl Read + Write), message: &Value) -> Option<Value> {
    let payload = serde_json::to_vec(message).ok()?;
    stream.write_all(&(payload.len() as u32).to_le_bytes()).ok()?;
    stream.write_all(&payload).ok()?;
    stream.flush().ok()?;

    let mut raw_length = [0u8; 4];
    stream.read_exact(&mut raw_length).ok()?;
    let length = u32::from_le_bytes(raw_length) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return None;
    }
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response).ok()?;
    serde_json::from_slice(&response).ok()
}

// ── Extension action mapping ───────────────────────────────────────────────

fn error_of(response: Option<&Value>) -> String {
    response
        .and_then(|r| r.get("payload"))
        .map(|p| {
            p.get("message")
                .or_else(|| p.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("VELA Desktop refused the request")
                .to_string()
        })
        .unwrap_or_else(|| "Could not reach VELA Desktop".to_string())
}

fn passkey_payload(message: &Value, keys: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for key in keys {
        if let Some(v) = message.get(*key) {
            if !v.is_null() {
                out.insert((*key).to_string(), v.clone());
            }
        }
    }
    Value::Object(out)
}

fn handle_ping(_message: &Value) -> Value {
    match send_to_desktop(json!({ "msg_type": "ping", "payload": {} }), false) {
        Some(response)
            if response.get("msg_type").and_then(|v| v.as_str()) == Some("pong")
                || response.get("msg_type").and_then(|v| v.as_str()) == Some("Pong") =>
        {
            json!({ "success": true, "connected": true })
        }
        _ => json!({ "success": false, "connected": false }),
    }
}

fn handle_open_vault(_message: &Value) -> Value {
    match send_to_desktop(json!({ "msg_type": "open_vault", "payload": {} }), false) {
        Some(response)
            if response.get("msg_type").and_then(|v| v.as_str()) == Some("pong")
                || response.get("msg_type").and_then(|v| v.as_str()) == Some("Pong") =>
        {
            json!({ "success": true })
        }
        _ => json!({ "success": false, "error": "Could not open VELA Desktop" }),
    }
}

fn handle_get_logins(message: &Value) -> Value {
    let user_initiated = message.get("userInitiated").and_then(Value::as_bool).unwrap_or(false)
        || message.get("user_initiated").and_then(Value::as_bool).unwrap_or(false)
        || message.get("action").and_then(Value::as_str) == Some("getLogins");

    let response = send_to_desktop(
        json!({
            "msg_type": "autofill_request",
            "payload": { "domain": message.get("url").cloned().unwrap_or(Value::Null), "user_initiated": user_initiated },
        }),
        false,
    );

    let Some(response) = response else {
        return json!({ "success": false, "logins": [] });
    };
    if !matches!(
        response.get("msg_type").and_then(Value::as_str),
        Some("AutofillResponse") | Some("autofill_response")
    ) {
        return json!({ "success": false, "logins": [] });
    }

    let payload = response.get("payload").cloned().unwrap_or(Value::Null);
    if payload.get("requires_biometric").and_then(Value::as_bool).unwrap_or(false) {
        return json!({ "success": false, "requires_biometric": true, "logins": [] });
    }

    let mut logins = Vec::new();
    for item in payload.get("items").and_then(Value::as_array).into_iter().flatten() {
        if item.get("item_type").and_then(Value::as_str) != Some("login") {
            continue;
        }
        let mut login = json!({
            "id": item.get("id"),
            "name": item.get("name"),
            "username": item.get("username"),
            "url": item.get("url"),
        });
        if user_initiated {
            login["password"] = item.get("password").cloned().unwrap_or(Value::Null);
            login["totp"] = item.get("totp").cloned().unwrap_or(Value::Null);
        }
        logins.push(login);
    }
    json!({ "success": true, "logins": logins })
}

fn handle_save_credentials(message: &Value) -> Value {
    let response = send_to_desktop(
        json!({
            "msg_type": "save_credentials",
            "payload": {
                "name": message.get("name").cloned().unwrap_or(Value::Null),
                "username": message.get("username").cloned().unwrap_or(Value::Null),
                "password": message.get("password").cloned().unwrap_or(Value::Null),
                "url": message.get("url").cloned().unwrap_or(Value::Null),
            },
        }),
        false,
    );

    let Some(response) = response else {
        return json!({ "success": false, "error": "Could not reach VELA Desktop" });
    };
    if !matches!(
        response.get("msg_type").and_then(Value::as_str),
        Some("SaveResponse") | Some("save_response")
    ) {
        return json!({ "success": false, "error": "Could not reach VELA Desktop" });
    }

    let payload = response.get("payload").cloned().unwrap_or(Value::Null);
    if payload.get("success").and_then(Value::as_bool).unwrap_or(false) {
        json!({ "success": true, "id": payload.get("id") })
    } else {
        json!({
            "success": false,
            "error": payload.get("error").and_then(Value::as_str).unwrap_or("Save failed")
        })
    }
}

fn handle_passkey_create(message: &Value) -> Value {
    let response = send_to_desktop(
        json!({
            "msg_type": "passkey_create",
            "payload": passkey_payload(
                message,
                &[
                    "rp_id",
                    "rp_name",
                    "user_handle",
                    "user_name",
                    "user_display_name",
                    "client_data_hash",
                    "algorithms",
                    "exclude_credentials",
                    "require_user_verification",
                ],
            ),
        }),
        true,
    );

    let Some(response) = response else {
        return json!({ "success": false, "error": "Could not reach VELA Desktop" });
    };
    if !matches!(
        response.get("msg_type").and_then(Value::as_str),
        Some("PasskeyCreateResponse") | Some("passkey_create_response")
    ) {
        return json!({ "success": false, "error": error_of(Some(&response)) });
    }

    let payload = response.get("payload").cloned().unwrap_or(Value::Null);
    json!({
        "success": true,
        "credential_id": payload.get("credential_id"),
        "attestation_object": payload.get("attestation_object"),
        "authenticator_data": payload.get("authenticator_data"),
    })
}

fn handle_passkey_get(message: &Value) -> Value {
    let response = send_to_desktop(
        json!({
            "msg_type": "passkey_get",
            "payload": passkey_payload(
                message,
                &["rp_id", "client_data_hash", "allow_credentials", "require_user_verification"],
            ),
        }),
        true,
    );

    let Some(response) = response else {
        return json!({ "success": false, "error": "Could not reach VELA Desktop" });
    };
    if !matches!(
        response.get("msg_type").and_then(Value::as_str),
        Some("PasskeyGetResponse") | Some("passkey_get_response")
    ) {
        return json!({ "success": false, "error": error_of(Some(&response)) });
    }

    let payload = response.get("payload").cloned().unwrap_or(Value::Null);
    json!({
        "success": true,
        "credential_id": payload.get("credential_id"),
        "authenticator_data": payload.get("authenticator_data"),
        "signature": payload.get("signature"),
        "user_handle": payload.get("user_handle"),
    })
}

fn handle_passkey_list(message: &Value) -> Value {
    // Public metadata only, and never prompts — the shim calls this on every
    // WebAuthn request to decide whether it has anything to offer, so it must
    // be cheap and silent.
    let response = send_to_desktop(
        json!({
            "msg_type": "passkey_list",
            "payload": { "rp_id": message.get("rp_id").cloned().unwrap_or(Value::Null) },
        }),
        false,
    );

    let Some(response) = response else {
        return json!({ "success": false, "credentials": [] });
    };
    if !matches!(
        response.get("msg_type").and_then(Value::as_str),
        Some("PasskeyListResponse") | Some("passkey_list_response")
    ) {
        return json!({ "success": false, "credentials": [] });
    }

    let payload = response.get("payload").cloned().unwrap_or(Value::Null);
    json!({
        "success": true,
        "credentials": payload.get("credentials").cloned().unwrap_or_else(|| json!([])),
        "locked": payload.get("locked").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn handle_in_core_login_candidates(message: &Value) -> Value {
    // Which saved logins could sign in to this page. Metadata only, no
    // prompt — the popup calls it to decide whether to offer the button.
    let response = send_to_desktop(
        json!({
            "msg_type": "in_core_login_candidates",
            "payload": { "url": message.get("url").cloned().unwrap_or(Value::Null) },
        }),
        false,
    );

    let Some(response) = response else {
        return json!({ "success": false, "candidates": [] });
    };
    if !matches!(
        response.get("msg_type").and_then(Value::as_str),
        Some("InCoreLoginCandidatesResponse") | Some("in_core_login_candidates_response")
    ) {
        return json!({ "success": false, "candidates": [] });
    }

    let payload = response.get("payload").cloned().unwrap_or(Value::Null);
    json!({
        "success": true,
        "candidates": payload.get("candidates").cloned().unwrap_or_else(|| json!([])),
        "locked": payload.get("locked").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn handle_in_core_login(message: &Value) -> Value {
    // The M9a login itself. Two things make this slow: the desktop puts a
    // confirmation in front of a human, then talks to a website over its own
    // connection — hence the slow timeout. The reply carries cookies, not
    // the password; that is a property of the desktop's response type, not
    // of this function, but it is why the payload passes through filtered.
    let response = send_to_desktop(
        json!({
            "msg_type": "in_core_login",
            "payload": {
                "item_id": message.get("itemId").or_else(|| message.get("item_id")).cloned().unwrap_or(Value::Null),
                "url": message.get("url").cloned().unwrap_or(Value::Null),
                // Browser-minted artifacts for a recipe login: a CAPTCHA token
                // the human solved on the page, and the browser's cookie jar
                // for the tab. Used once, never persisted.
                "captcha_token": message.get("captchaToken").or_else(|| message.get("captcha_token")).cloned().unwrap_or(json!("")),
                "browser_cookies": message.get("browserCookies").or_else(|| message.get("browser_cookies")).cloned().unwrap_or_else(|| json!([])),
            },
        }),
        true,
    );

    let Some(response) = response else {
        return json!({ "success": false, "error": "Could not reach VELA Desktop" });
    };
    if !matches!(
        response.get("msg_type").and_then(Value::as_str),
        Some("InCoreLoginResponse") | Some("in_core_login_response")
    ) {
        return json!({ "success": false, "error": error_of(Some(&response)) });
    }

    let payload = response.get("payload").cloned().unwrap_or(Value::Null);
    json!({
        "success": true,
        "cookies": payload.get("cookies").cloned().unwrap_or_else(|| json!([])),
        "landingUrl": payload.get("landing_url").cloned().unwrap_or(json!("")),
        "looksAuthenticated": payload.get("looks_authenticated").and_then(Value::as_bool).unwrap_or(false),
        "siteMode": payload.get("site_mode").cloned().unwrap_or(json!("self_serve")),
        "residualNote": payload.get("residual_note").cloned().unwrap_or(json!("")),
        "userVerified": payload.get("user_verified").and_then(Value::as_bool).unwrap_or(false),
        "usedSecondFactor": payload.get("used_second_factor").and_then(Value::as_bool).unwrap_or(false),
        // Set when the site still wants something a vault cannot produce — a
        // security key, a push, an SMS. The password was accepted; the login
        // was not completed.
        "awaitingSecondFactor": payload.get("awaiting_second_factor").cloned().unwrap_or(Value::Null),
        // The site wanted a stronger factor and the item's opt-in let a TOTP
        // code stand in. The user turned that on once; they are still told
        // every time it is used.
        "secondFactorDowngraded": payload.get("second_factor_downgraded").and_then(Value::as_bool).unwrap_or(false),
        // The login ran in a disposable real browser window rather than over
        // the desktop's own TLS; surfaced so the popup can say a window appeared.
        "usedBrowser": payload.get("used_browser").and_then(Value::as_bool).unwrap_or(false),
        // The site's localStorage/sessionStorage from the disposable browser,
        // passed through for the extension to write into the user's own tab.
        "localSession": payload.get("local_session").cloned().unwrap_or_else(|| json!({})),
        // The auth SDK's IndexedDB records (Firebase local persistence).
        "cachedDb": payload.get("cached_db").cloned().unwrap_or_else(|| json!({})),
    })
}

fn handle_not_implemented(_message: &Value) -> Value {
    json!({ "success": false, "error": "Not implemented" })
}

fn handle_message(message: &Value) -> Value {
    let action = message.get("action").and_then(Value::as_str).unwrap_or("");
    let handler = match action {
        "ping" => handle_ping,
        "openVault" | "openSettings" => handle_open_vault,
        "getLogins" | "getAvailableLogins" => handle_get_logins,
        "saveCredentials" => handle_save_credentials,
        "passkeyCreate" => handle_passkey_create,
        "passkeyGet" => handle_passkey_get,
        "passkeyList" => handle_passkey_list,
        "inCoreLogin" => handle_in_core_login,
        "inCoreLoginCandidates" => handle_in_core_login_candidates,
        "getMasterKey" | "unlockVault" | "lockVault" | "getStatus" => handle_not_implemented,
        other => {
            eprintln!("Unknown action: {other}");
            return json!({ "success": false, "error": format!("Unknown action: {other}") });
        }
    };
    handler(message)
}

fn main() {
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    while let Some(message) = read_browser_message(&mut stdin) {
        let response = handle_message(&message);
        write_browser_message(&mut stdout, &response);
    }
}
