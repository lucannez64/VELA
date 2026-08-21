//! Firefox-family driver core for the browser-driven login tier.
//!
//! The Chromium tier substitutes the real password at the network layer via
//! CDP `Fetch`. Firefox family (Firefox, Zen, Waterfox, …) implements no CDP;
//! its cross-browser automation protocol is **WebDriver BiDi**, whose `network`
//! module provides the same interception primitive:
//! `network.addIntercept`/`network.beforeRequestSent`, then
//! **`network.continueRequest` with an overridable `body`**.
//!
//! This module holds the *decision* — given a paused
//! `network.beforeRequestSent` event whose request body carries the placeholder,
//! build the `network.continueRequest` parameters with the real credential
//! substituted, using the same rules as the Chromium tier (`check_same_site`,
//! which now also enforces the RT-12 scheme equality). The password therefore
//! never enters the page's JavaScript.
//!
//! Design: `security/firefox-browser-tier-adr.md`.

use base64::Engine as _;
use serde_json::{json, Value};
use url::Url;

use crate::js_login::{CapturedRequest, PLACEHOLDER_PASSWORD};

/// What to do with a paused request in a Firefox session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinueAction {
    /// No placeholder in the body — continue the request unchanged.
    PassThrough,
    /// Continue the request, overriding the body with the real credential.
    Substitute { body: String },
}

/// Decide what to do with a paused `network.beforeRequestSent` request.
///
/// `request` is the BiDi event's `params` (or just its `request` object): a
/// WebDriver `RequestData` with `url`/`method`/`headers`/`body`. A body whose
/// `NetworkBytesValue` carries the placeholder is the login request: it is
/// checked same-site (host + scheme, RT-12) and continued with the substituted
/// credential. Everything else passes through untouched.
pub fn decide_continue_request(
    request: &Value,
    page: Option<&Url>,
    password: &str,
) -> Result<ContinueAction, String> {
    // Accept either the full event (params.request) or a bare RequestData.
    let req = request.get("request").cloned().unwrap_or_else(|| request.clone());

    let url = req.get("url").and_then(Value::as_str).unwrap_or_default().to_string();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("POST").to_string();
    let headers = req
        .get("headers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|h| {
                    Some((
                        h.get("name")?.as_str()?.to_string(),
                        h.get("value")?.as_str()?.to_string(),
                    ))
                })
                .collect::<std::collections::BTreeMap<String, String>>()
        })
        .unwrap_or_default();
    let body = request_body_string(req.get("body"));

    if !body.contains(PLACEHOLDER_PASSWORD) {
        return Ok(ContinueAction::PassThrough);
    }

    let Some(page) = page else {
        return Err("the page was not resolvable; refusing to substitute".to_string());
    };
    let captured = CapturedRequest {
        url,
        method,
        headers,
        body,
    };
    // Same registrable host + same scheme (RT-12); the credential may not
    // travel to a different site or be downgraded to http — unless it is aimed
    // at a well-known identity provider the page legitimately authenticates
    // through (parity with the Chromium tier's allowlist).
    let target_host = Url::parse(&captured.url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()));
    let allowed_provider = target_host
        .as_deref()
        .is_some_and(|host| crate::browser::intercept::CREDENTIAL_ALLOWLIST_PUB.contains(&host));
    if !allowed_provider {
        captured.check_same_site(page).map_err(|e| e.to_string())?;
    }

    let ready = captured.substitute(password).map_err(|e| e.to_string())?;
    Ok(ContinueAction::Substitute { body: ready.body })
}

/// The `network.continueRequest` parameters for a decision.
pub fn continue_request_params(request_id: &str, action: &ContinueAction) -> Value {
    match action {
        ContinueAction::PassThrough => json!({ "request": request_id }),
        ContinueAction::Substitute { body } => json!({
            "request": request_id,
            "body": { "type": "string", "value": body },
        }),
    }
}

/// Extract the string form of a WebDriver `NetworkBytesValue`
/// (`{type:"string",value}` or `{type:"bytes",value:base64}`); `null` → "".
fn request_body_string(body_value: Option<&Value>) -> String {
    let Some(v) = body_value else {
        return String::new();
    };
    match v.get("type").and_then(Value::as_str) {
        Some("string") => v.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
        Some("bytes") => v
            .get("value")
            .and_then(Value::as_str)
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(url: &str) -> Url {
        Url::parse(url).unwrap()
    }

    fn before_request(url: &str, body: &str) -> Value {
        json!({
            "request": {
                "request": "foof",
                "url": url,
                "method": "POST",
                "headers": [{ "name": "content-type", "value": "application/x-www-form-urlencoded" }],
                "body": { "type": "string", "value": body },
            }
        })
    }

    #[test]
    fn a_placeholder_login_gets_the_real_password() {
        let page = site("https://monkeytype.com/login");
        let request = before_request(
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
            &format!("email=ada&password={PLACEHOLDER_PASSWORD}"),
        );
        let action = decide_continue_request(&request, Some(&page), "correct-horse").unwrap();
        assert_eq!(action, ContinueAction::Substitute { body: "email=ada&password=correct-horse".into() });
    }

    #[test]
    fn a_non_login_request_passes_through() {
        let page = site("https://monkeytype.com/login");
        let request = before_request("https://monkeytype.com/analytics", "{}");
        assert_eq!(decide_continue_request(&request, Some(&page), "x").unwrap(), ContinueAction::PassThrough);
    }

    /// RT-12: an http:// target must not be treated as same-site as an https
    /// page, so a downgraded credential request is refused.
    #[test]
    fn an_http_downgrade_is_refused() {
        let page = site("https://monkeytype.com/login");
        let request = before_request(
            "http://monkeytype.com/session",
            &format!("pw={PLACEHOLDER_PASSWORD}"),
        );
        assert!(decide_continue_request(&request, Some(&page), "x").is_err());
    }
}
