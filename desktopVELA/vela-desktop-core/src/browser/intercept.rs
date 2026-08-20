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
            PausedAction::ContinueWith { request, body } => {
                // Tier-3 (VELA_BROWSER_CORE_PERFORM=1): the core sends the
                // substituted credential over its own TLS and fulfils the
                // browser's paused request — the password never crosses into
                // the browser's address space. Default: hand it to the browser
                // (the documented residual, one request-instant in its memory).
                if core_perform_enabled() {
                    core_send_and_fulfill(cdp, session, request_id, &request, &body).await?;
                } else {
                    continue_with_post_data(cdp, session, request_id, &body).await?;
                }
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
    /// The login request, with the real password substituted in. Carries the
    /// substituted [`CapturedRequest`] so the caller can choose to send it
    /// from the core (Tier-3, password never enters the browser) instead of
    /// handing it to the browser via `Fetch.continueRequest`.
    ContinueWith {
        request: CapturedRequest,
        body: String,
    },
}

/// Whether the substituted credential is sent by the *core* over its own TLS
/// rather than pushed into the browser via `Fetch.continueRequest`.
///
/// This is the Tier-3 isolation (see `security/browser-driven-login-design.md`):
/// when it is on, the real password never enters the browser's address space —
/// the core performs the login POST itself and fulfils the browser's paused
/// request with the response. It is opt-in (`VELA_BROWSER_CORE_PERFORM=1`) and
/// off by default, because only sites whose *POST* is not itself bot-walled
/// will accept a core-client submission; when the site refuses the core's
/// client in this mode, the login is refused rather than silently falling back
/// to exposing the password in the browser.
fn core_perform_enabled() -> bool {
    std::env::var("VELA_BROWSER_CORE_PERFORM").as_deref() == Ok("1")
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
    let body = ready.body.clone();
    Ok(PausedAction::ContinueWith { request: ready, body })
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
    tracing::info!(
        "browser login: browser-send: handing the substituted body to the browser (the \
         password enters the browser's address space for this request)"
    );
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

/// Tier-3: perform the login POST from the *core*, and fulfil the browser's
/// paused request with the result.
///
/// Unlike [`continue_with_post_data`], this does **not** hand the substituted
/// body to the browser via `Fetch.continueRequest`, so the real password never
/// enters the browser's address space. [`core_send_credential`] sends the
/// credential over the core's own TLS (reusing the browser's pre-session
/// cookies/csrf from the paused request's headers); the session from the
/// response's `Set-Cookie` is injected into the browser's cookie jar (so
/// harvest and the page's own follow-up requests see it); and the browser's
/// paused request is told it is already-answered via `Fetch.fulfillRequest`.
///
/// Single-hop only: a redirect-based login POST is not supported in this mode
/// (the core refuses rather than guessing across hosts), and it only works
/// where the site accepts a non-browser-client POST (its bot check was over
/// the initial GET). When the site refuses the core's client, the caller
/// surfaces a login refusal rather than silently re-exposing the password in
/// the browser.
async fn core_send_and_fulfill(
    cdp: &Cdp,
    session: &str,
    request_id: &str,
    request: &CapturedRequest,
    body: &str,
) -> Result<(), InterceptError> {
    let login = core_send_credential(request, body).await?;

    // The session the site issued belongs to this browser session: inject each
    // Set-Cookie into the browser's jar (Network.setCookie) so harvest and the
    // page's own follow-up requests see it, then fulfil the browser's paused
    // request with the response body so the page continues seamlessly.
    for cookie in &login.set_cookies {
        inject_session_cookie(cdp, session, cookie, &login.url).await;
    }

    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&login.body);
    cdp.call_scoped(
        "Fetch.fulfillRequest",
        json!({
            "requestId": request_id,
            "responseCode": login.status,
            "responseHeaders": login.headers,
            "body": body_b64,
        }),
        session,
    )
    .await
    .map_err(|e| InterceptError::Transport(format!("Fetch.fulfillRequest failed: {e}")))?;
    Ok(())
}

/// The site's answer to the core-sent credential POST, plus what must be
/// relayed to the browser.
///
/// Kept free of any CDP dependency so the Tier-3 credential transport is
/// unit-testable against a plain HTTP mock (see `browser::tests`).
#[derive(Debug)]
pub(crate) struct CoreLoginResponse {
    pub(crate) status: u16,
    pub(crate) url: url::Url,
    pub(crate) set_cookies: Vec<crate::login::SessionCookie>,
    #[allow(dead_code)] // inspected via Debug in tests; serialised in the fulfill path
    pub(crate) headers: Vec<serde_json::Value>,
    pub(crate) body: Vec<u8>,
}

/// Send the substituted credential over the core's own TLS connection.
///
/// This is the whole point of Tier-3: the password travels the core's TLS
/// client here, and is **never** handed to the browser. Returns the site's
/// answer for the caller to relay; refuses (rather than fall back to exposing
/// the password in the browser) if the site does not accept a core-client
/// POST or tries to redirect it.
pub(crate) async fn core_send_credential(
    request: &CapturedRequest,
    body: &str,
) -> Result<CoreLoginResponse, InterceptError> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|e| InterceptError::Transport(format!("bad method: {e}")))?;
    let url = url::Url::parse(&request.url)
        .map_err(|e| InterceptError::Transport(format!("bad request URL: {e}")))?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(super::LOGIN_TIMEOUT)
        .user_agent(super::CORE_USER_AGENT)
        .build()
        .map_err(|e| InterceptError::Transport(e.to_string()))?;

    let mut builder = client.request(method, url);
    tracing::info!(
        "browser login: TIER-3 core-perform: sending the credential over the core's own \
         TLS to {} (the password is NOT pushed into the browser)",
        request.url
    );
    // Replay the page's own pre-session cookies / csrf that the browser
    // attached to the paused request, so the site sees the same session. We
    // do not set the transport headers the client owns.
    for (name, value) in &request.headers {
        let lowered = name.to_lowercase();
        if matches!(
            lowered.as_str(),
            "cookie" | "host" | "content-length" | "content-encoding" | "transfer-encoding"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }
    if !body.is_empty() {
        builder = builder.body(body.to_string());
    }

    // The credential crosses the core's own TLS connection. If the site refuses
    // this client (a bot-walled POST), or redirects it, that is a login refusal
    // — we do not fall back to handing the password to the browser in this mode.
    let response = builder
        .send()
        .await
        .map_err(|e| InterceptError::Transport(format!("core login POST failed: {e}")))?;
    let status = response.status();
    if status.is_server_error() || status.is_client_error() || status.is_redirection() {
        return Err(InterceptError::Transport(format!(
            "the site did not accept the core's login POST (HTTP {}); for a site whose \
             login POST must come from the browser, disable VELA_BROWSER_CORE_PERFORM",
            status.as_u16()
        )));
    }

    // The session the site issued, for injection into the browser's jar.
    let mut set_cookies = Vec::new();
    if let Some(host) = response.url().host_str() {
        for header in response.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(header) = header.to_str() {
                if let Some(cookie) =
                    crate::login::parse_set_cookie(header, &host.to_ascii_lowercase())
                {
                    set_cookies.push(cookie);
                }
            }
        }
    }
    // The final URL, captured before `bytes()` consumes the response.
    let final_url = response.url().clone();

    // Response headers the page may rely on (content-type etc.), minus the
    // ones the transport consumed. Captured before `bytes()`, which consumes
    // the response.
    let headers: Vec<serde_json::Value> = response
        .headers()
        .iter()
        .filter(|(name, _)| {
            !name.as_str().eq_ignore_ascii_case("set-cookie")
                && !name.as_str().eq_ignore_ascii_case("transfer-encoding")
        })
        .map(|(name, value)| {
            json!({ "name": name.as_str(), "value": value.to_str().unwrap_or_default() })
        })
        .collect();

    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| InterceptError::Transport(e.to_string()))?;

    Ok(CoreLoginResponse {
        status: status.as_u16(),
        url: final_url,
        set_cookies,
        headers,
        body: body_bytes.to_vec(),
    })
}

/// Inject one session cookie into the browser's jar, so the session the core
/// negotiated is visible to the browser and to harvest.
async fn inject_session_cookie(
    cdp: &Cdp,
    session: &str,
    cookie: &crate::login::SessionCookie,
    url: &url::Url,
) {
    let mut params = serde_json::json!({
        "name": cookie.name,
        "value": cookie.value,
        "path": cookie.path,
        "secure": cookie.secure,
        "httpOnly": cookie.http_only,
    });
    if cookie.host_only {
        params["url"] = serde_json::json!(url.as_str());
    } else {
        params["domain"] = serde_json::json!(cookie.domain);
    }
    if let Some(expires) = cookie.expires_at {
        params["expires"] = serde_json::json!(expires);
    }
    let _ = cdp.call_scoped("Network.setCookie", params, session).await;
}
