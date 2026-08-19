//! The substitution handler: the only code path that ever sees the real
//! password in the browser-driven login tier.
//!
//! The page fills and submits with `PLACEHOLDER_PASSWORD`; every outgoing
//! request pauses at the browser's network layer and is handed here. A request
//! whose body carries the placeholder gets the real credential substituted in
//! (the same `CapturedRequest::substitute` + `check_same_site` rules as
//! `js_login`), then continues. Every other request passes through untouched.
//!
//! This lives in the core process, not the browser: a compromised page cannot
//! read the substituted body — it only ever built the placeholder.

use base64::Engine;
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tracing::{debug, info};
use url::Url;

use crate::browser::cdp::{self, Cdp, Event};
use crate::js_login::{CapturedRequest, PLACEHOLDER_PASSWORD};

/// Why a browser-driven login could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptError {
    /// The page never produced a login request carrying the placeholder.
    Timeout,
    /// A login request was handled but the event stream went quiet before the
    /// settle window closed — not a failure of the login itself.
    Settle,
    /// The placeholder reached the network layer transformed, so substituting
    /// it would have sent a useless value — refused rather than guessed.
    SubstitutionFailed,
    /// A request carrying the placeholder was aimed off the site.
    CrossSite(String),
    /// The browser connection died.
    Transport(String),
}

impl std::fmt::Display for InterceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "the page did not submit a login request"),
            Self::Settle => write!(f, "the login request was sent"),
            Self::SubstitutionFailed => write!(
                f,
                "the page transformed the password field before sending it, so VELA \
                 refused rather than submit a value the site could not have meant"
            ),
            Self::CrossSite(host) => write!(
                f,
                "the page tried to send the password to {host}, which is a different \
                 site; nothing was sent"
            ),
            Self::Transport(reason) => write!(f, "the browser connection failed: {reason}"),
        }
    }
}

impl std::error::Error for InterceptError {}

/// Arm request interception for `session`.
pub async fn enable(cdp: &Cdp, session: &str) -> Result<(), InterceptError> {
    cdp.call_scoped(
        "Fetch.enable",
        json!({
            "patterns": [{ "urlPattern": "*", "requestStage": "Request" }],
            "handleAuthRequests": false,
        }),
        session,
    )
    .await
    .map_err(|e| InterceptError::Transport(e.to_string()))?;
    Ok(())
}

/// Stop pausing requests for `session`. Must be called once the login request
/// is handled, or the redirect it triggers stays paused forever.
pub async fn disable(cdp: &Cdp, session: &str) -> Result<(), InterceptError> {
    cdp.call_scoped("Fetch.disable", json!({}), session)
        .await
        .map_err(|e| InterceptError::Transport(e.to_string()))?;
    Ok(())
}

/// Drive the interception loop until the login has settled.
///
/// Every paused request is inspected. A request whose body carries the
/// placeholder is substituted with `password` and continued; everything else
/// passes through unchanged.
///
/// The loop does **not** stop at the first substituted request. A JS login can
/// submit the placeholder more than once — a native form POST to a no-JS
/// fallback endpoint, then the AJAX that actually logs in (RYM's `/httprequest/
/// Login` is exactly this). Substituting only the first would send the real
/// password to a request the site ignores and let the second go out with the
/// placeholder. So the loop keeps substituting every placeholder-carrying
/// request until none has arrived for a settle window, then returns.
pub async fn wait_for_login_request(
    cdp: &Cdp,
    session: &str,
    password: &str,
    events: &mut broadcast::Receiver<Event>,
    timeout: std::time::Duration,
) -> Result<(), InterceptError> {
    const SETTLE: std::time::Duration = std::time::Duration::from_secs(3);
    let deadline = std::time::Instant::now() + timeout;
    let mut last_login_request: Option<std::time::Instant> = None;

    loop {
        let now = std::time::Instant::now();
        if last_login_request.is_some_and(|at| now.duration_since(at) > SETTLE) {
            break;
        }
        if now > deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(now);
        let event = tokio::time::timeout(remaining, events.recv())
            .await
            .map_err(|_| {
                // The stream went quiet: if a login request was handled, that
                // is what matters; the settle window just never closed.
                if last_login_request.is_some() {
                    InterceptError::Settle
                } else {
                    InterceptError::Timeout
                }
            })?
            .map_err(|_| InterceptError::Transport("the browser connection closed".to_string()))?;
        if event.session_id.as_deref() != Some(session) || event.method != "Fetch.requestPaused" {
            continue;
        }
        let Some(request_id) = event.params.get("requestId").and_then(Value::as_str) else {
            continue;
        };
        let request = event.params.get("request").cloned().unwrap_or(Value::Null);
        // Fast path: a request that does not carry the placeholder is not the
        // login and is continued immediately. The page-url read is a CDP
        // round-trip and would stall the page if done for every request.
        let carries_placeholder = request
            .get("postData")
            .and_then(Value::as_str)
            .is_some_and(|b| b.contains(PLACEHOLDER_PASSWORD));
        if !carries_placeholder {
            cdp.call_scoped(
                "Fetch.continueRequest",
                json!({ "requestId": request_id }),
                session,
            )
            .await
            .map_err(|e| InterceptError::Transport(e.to_string()))?;
            continue;
        }
        // The page the user is actively submitting on — its registrable domain
        // is what a placeholder-carrying request must match. An OAuth login
        // (Riot via a sports site) legitimately posts to a different domain
        // than where the flow started, so pinning to a fixed start site is
        // wrong; pinning to the page the human can see is the honest control.
        let page_url = cdp::evaluate(cdp, session, "location.href")
            .await
            .ok()
            .and_then(|r| {
                r.get("result")
                    .and_then(|x| x.get("value"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| url::Url::parse(s).ok())
            });
        match handle_paused_request(&request, page_url.as_ref(), password)? {
            PausedAction::Continue => {
                cdp.call_scoped(
                    "Fetch.continueRequest",
                    json!({ "requestId": request_id }),
                    session,
                )
                .await
                .map_err(|e| InterceptError::Transport(e.to_string()))?;
            }
            PausedAction::ContinueWith { body } => {
                continue_with_post_data(cdp, session, request_id, &body).await?;
                last_login_request = Some(std::time::Instant::now());
            }
        }
    }

    if last_login_request.is_none() {
        return Err(InterceptError::Timeout);
    }
    // Stop pausing: the login is settled, and the response flow (redirects,
    // analytics) must proceed normally.
    disable(cdp, session).await?;
    Ok(())
}

/// Identity providers the page may legitimately forward the credential to.
///
/// Many modern sites (monkeytype is one) authenticate through Firebase Auth:
/// the login page's own JavaScript posts the password to
/// `identitytoolkit.googleapis.com/v1/accounts:signInWithPassword`, exactly as
/// it does in a normal browser — the credential already transits Google's
/// servers for the user's real login. Refusing that would make the login
/// impossible, and it is the site's own chosen backend, not a redirect to a
/// stranger. The allowlist is short and fixed — Google's Firebase endpoints —
/// so the core will never fill a credential into a request aimed at an
/// arbitrary host.
const CREDENTIAL_ALLOWLIST: &[&str] = &[
    "identitytoolkit.googleapis.com",
    "securetoken.googleapis.com",
];

/// What to do with one paused request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PausedAction {
    /// No placeholder in the body — pass through unchanged.
    Continue,
    /// The login request, with the real password substituted in.
    ContinueWith { body: String },
}

/// Decide what to do with a paused request.
///
/// Pure, and tested head-on: given a request whose body carries the
/// placeholder, substitute the real password (reusing `js_login`'s rules); any
/// other request passes through untouched; a request aimed off the page's own
/// site, or one where the placeholder was transformed out of existence, is
/// refused.
pub(crate) fn handle_paused_request(
    request: &Value,
    page: Option<&Url>,
    password: &str,
) -> Result<PausedAction, InterceptError> {
    let body = request
        .get("postData")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // No placeholder -> not the login request; let it through.
    if !body.contains(PLACEHOLDER_PASSWORD) {
        return Ok(PausedAction::Continue);
    }

    let url = request
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("POST")
        .to_string();
    let headers: std::collections::BTreeMap<String, String> = request
        .get("headers")
        .and_then(Value::as_object)
        .map(|headers| {
            headers
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|value| (k.clone(), value.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let captured = CapturedRequest {
        url,
        method,
        headers,
        body: body.clone(),
    };
    // Which fields the login request actually carried (names only — the
    // password value is never logged). If the username is missing here, the
    // fill missed it; if it is present and the site still rejects, the site's
    // own anti-abuse is refusing the request.
    let fields: Vec<String> = if captured
        .headers
        .get("content-type")
        .map(|c| c.contains("json"))
        .unwrap_or(false)
    {
        serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
            .unwrap_or_default()
    } else {
        body.split('&')
            .filter_map(|pair| pair.split_once('=').map(|(k, _)| k.to_string()))
            .collect()
    };
    info!(
        "login request to {} carries fields: {:?}",
        captured.url, fields
    );
    let content_length = captured
        .headers
        .get("content-length")
        .cloned()
        .unwrap_or_default();
    let sec_headers: Vec<String> = captured
        .headers
        .keys()
        .filter(|k| k.to_lowercase().contains("sec") || k.to_lowercase().contains("sonar"))
        .cloned()
        .collect();
    let original_len = captured.body.len();
    let content_length_clone = content_length.clone();
    let sec_headers_clone = sec_headers.clone();
    // The credential may go only to the site of the page the human is looking
    // at when they submit — or to a well-known identity provider the site
    // legitimately authenticates through. If the current page is not
    // resolvable (navigation in flight), refuse rather than guess.
    let Some(page) = page else {
        return Err(InterceptError::CrossSite("an unknown page".to_string()));
    };
    let target_host = Url::parse(&captured.url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()));
    let allowed_provider = target_host
        .as_deref()
        .is_some_and(|host| CREDENTIAL_ALLOWLIST.contains(&host));
    if !allowed_provider {
        captured
            .check_same_site(page)
            .map_err(|e| match e {
                crate::js_login::JsLoginError::CrossSiteRequest(host) => {
                    InterceptError::CrossSite(host)
                }
                other => InterceptError::Transport(other.to_string()),
            })?;
    }
    let ready = captured
        .substitute(password)
        .map_err(|_| InterceptError::SubstitutionFailed)?;
    info!(
        "login request headers: content-length={:?} sec_headers={:?} body_bytes {} -> {}",
        content_length_clone,
        sec_headers_clone,
        original_len,
        ready.body.len(),
    );
    Ok(PausedAction::ContinueWith { body: ready.body })
}

/// Continue a paused request with a replaced body.
///
/// Chrome's `Fetch.continueRequest` has version-dependent quirks about how a
/// replaced body must be presented: some accept the plain string, others
/// require it base64-encoded with `base64Encoded: true`. Try the plain form
/// first, then the base64 form.
async fn continue_with_post_data(
    cdp: &Cdp,
    session: &str,
    request_id: &str,
    body: &str,
) -> Result<(), InterceptError> {
    let plain = json!({ "requestId": request_id, "postData": body });
    match cdp.call_scoped("Fetch.continueRequest", plain, session).await {
        Ok(_) => return Ok(()),
        Err(first_error) => {
            let base64_body = base64::engine::general_purpose::STANDARD.encode(body);
            let encoded = json!({
                "requestId": request_id,
                "postData": base64_body,
                "base64Encoded": true,
            });
            match cdp.call_scoped("Fetch.continueRequest", encoded, session).await {
                Ok(_) => Ok(()),
                Err(second_error) => Err(InterceptError::Transport(format!(
                    "Fetch.continueRequest refused the substituted body (plain: {first_error}; \
                     base64: {second_error})"
                ))),
            }
        }
    }
}
