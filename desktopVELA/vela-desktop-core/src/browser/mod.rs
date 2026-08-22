//! The browser-driven login tier: a disposable real browser, driven by the
//! core over CDP, so bot-walled sites can be logged into while the password
//! never enters the page's JavaScript.
//!
//! Design and security analysis: `security/browser-driven-login-design.md`.
//! The one-line version: the page fills and submits with
//! [`crate::js_login::PLACEHOLDER_PASSWORD`]; the real credential is
//! substituted into the outgoing request at the browser's network layer, in
//! the core process (`crate::browser::intercept`). A compromised page can only
//! ever read the placeholder.
//!
//! Compiled only behind `--features browser-login`, off by default.

pub mod cdp;
pub mod fill;
pub mod firefox;
pub mod harvest;
pub mod host;
pub mod intercept;

use url::Url;

use crate::browser::cdp::Cdp;
use crate::login::{LoginError, LoginOutcome, SiteMode};
use crate::AppState;

/// The whole-ceremony budget for one browser-driven login.
const LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// What the core's own TLS client tells the site it is, for the Tier-3
/// core-perform path. Truthful, like the login tier's UA — never a disguise.
pub(crate) const CORE_USER_AGENT: &str = concat!(
    "VELA/",
    env!("CARGO_PKG_VERSION"),
    " (password manager; browser-login tier core client)"
);
/// How long the interception loop waits for the human to click the site's own
/// sign-in button after the credentials are filled.
const HUMAN_CLICK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// How long to keep the window open for a second factor (a phone approval, an
/// e-mailed code) after the password is accepted.
const POST_LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

/// Log in at a disposable real browser, returning only the session cookies.
///
/// `start_url` is where the browser navigates first. For an ordinary login
/// that is the login page itself; for an OAuth-bound login (Riot via a sports
/// site) it is the *origin* page, where the human clicks the site's own
/// "sign in with…" control so the OAuth challenge is minted for *this* browser
/// session — carrying a challenge from elsewhere never works. The credential is
/// only ever submitted to the site of the page the human is looking at when
/// they submit, which the interception loop pins.
///
/// `browser_cookies` are the tab's pre-session cookies, seeded before the
/// page loads.
pub async fn login(
    state: &AppState,
    start_url: &Url,
    username: &str,
    password: &str,
    browser_cookies: &[crate::login::BrowserCookie],
    site_mode: SiteMode,
    user_verified: bool,
) -> Result<LoginOutcome, LoginError> {
    // An owned try-lock makes this a process-local single-flight gate without
    // queueing a second human ceremony behind the first. The guard is held for
    // the whole disposable-browser lifetime and Tokio's RAII guard releases it
    // on success, every `?` error, future cancellation/timeout, and unwinding.
    let _single_flight = acquire_single_flight(state)?;

    let (browser, pipe) = host::spawn()
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;
    #[cfg(unix)]
    let cdp = {
        // OwnedFd ends of the CDP pipe -> tokio AsyncRead/AsyncWrite.
        let command = tokio::fs::File::from_std(std::fs::File::from(pipe.command));
        let message = tokio::fs::File::from_std(std::fs::File::from(pipe.message));
        cdp::Cdp::connect_pipe(command, message)
            .await
            .map_err(|e| LoginError::Http(e.to_string()))?
    };
    #[cfg(not(unix))]
    let cdp = {
        return Err(LoginError::Http(
            "the browser-driven login tier is unix-only".to_string(),
        ));
    };

    let (session, target_id) = cdp::create_page_session(&cdp)
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;

    // Seed the tab's pre-session cookies before the page loads, so a session-
    // bound login page renders the way it does for the user.
    seed_browser_cookies(&cdp, &session, browser_cookies)
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;

    // 1. Load the starting page. The real browser passes whatever bot check
    //    the site runs — that is the whole point of using one.
    cdp::navigate_and_wait(&cdp, &session, start_url.as_str(), LOGIN_TIMEOUT)
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;

    // 2. Arm request interception *before* the challenge completes, and start
    //    the handler immediately. `Fetch.enable` pauses every request; if the
    //    handler is not running while the page's bot check does its thing, the
    //    challenge's verification requests stay paused forever and the page
    //    spins on "verifying you are human". The handler runs concurrently with
    //    the fill below, continuing non-login requests as they come.
    intercept::enable(&cdp, &session)
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;
    let mut events = cdp.subscribe();
    let intercept_cdp = cdp.clone();
    let intercept_session = session.clone();
    let intercept_password = password.to_string();
    let intercept_task = tokio::spawn(async move {
        // Generous: the human has to click the site's own sign-in button after
        // the credentials are filled.
        intercept::wait_for_login_request(
            &intercept_cdp,
            &intercept_session,
            &intercept_password,
            &mut events,
            HUMAN_CLICK_TIMEOUT,
        )
        .await
    });

    // 3. Fill the page with the username and the placeholder. The *human*
    //    clicks the site's own sign-in button in the VELA window — auto-
    //    clicking is unreliable across sites. If no login form ever appears,
    //    fail fast rather than letting the interception loop burn its budget.
    let fill_result = fill::fill_and_submit(&cdp, &session, username).await;
    if let Err(error) = fill_result {
        intercept_task.abort();
        return Err(LoginError::Http(error.to_string()));
    }
    tracing::info!(
        "browser login: a VELA browser window is open at {start_url} with your \
         credentials filled — click the site's sign-in button there to finish"
    );

    // Some sites re-render their form (React re-mount, a bot-check reload) and
    // wipe the fields. Keep re-filling until the login request is handled.
    let keep_cdp = cdp.clone();
    let keep_session = session.clone();
    let keep_username = username.to_string();
    let keep_task = tokio::spawn(async move {
        fill::keep_filled(&keep_cdp, &keep_session, &keep_username).await;
    });

    // 4. The form was submitted; the login request carries the placeholder,
    //    and the handler above substitutes the real password and hands it
    //    back to the browser. The keep-filled loop is no longer needed.
    let intercept_result = intercept_task
        .await
        .map_err(|e| LoginError::Http(format!("the browser login task failed: {e}")))?;
    keep_task.abort();
    match intercept_result {
        Ok(()) => {}
        Err(intercept::InterceptError::CrossSite(host)) => {
            return Err(LoginError::CrossSiteRedirect(host));
        }
        // The login request was sent (the stream just went quiet). Not a
        // failure — what happened next is decided by the page, which we read
        // below.
        Err(intercept::InterceptError::Settle) => {}
        Err(other) => return Err(LoginError::Http(other.to_string())),
    }

    // 5. Hold the window open until the login flow completes. A second factor
    //    (a phone approval, an e-mailed code) happens after the password is
    //    accepted: the window must stay up for the human to finish it, then
    //    the final session is harvested. We wait until the page has left the
    //    login URL and a cookie exists, or a generous budget elapses.
    tracing::info!("browser login: login request handled; waiting for the session");
    let cookies = wait_for_cookies(&cdp, &session, start_url).await?;

    // 6. Did the site actually accept the login? The honest signal is whether
    //    the page moved off the login screen (a rejected password re-serves
    //    the login form) and whether a cookie appeared at all. Reported as a
    //    hint, like the form tier's heuristic — never asserted.
    let post_login_url = cdp::evaluate(&cdp, &session, "location.href")
        .await
        .ok()
        .and_then(|r| {
            r.get("result")
                .and_then(|x| x.get("value"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
    // What the page is showing after the attempt — an error message is the
    // difference between a rejected password and an anti-bot refusal.
    let page_after = cdp::evaluate(
        &cdp,
        &session,
        r#"(document.title + ' | ' + (document.body ? document.body.innerText.slice(0, 400) : ''))"#,
    )
    .await
    .ok()
    .and_then(|r| {
        r.get("result")
            .and_then(|x| x.get("value"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    });
    let left_login = post_login_url
        .as_deref()
        .map(|url| !url.contains("/login"))
        .unwrap_or(false);
    let looks_authenticated = !cookies.is_empty() && left_login;
    tracing::info!(
        "browser login: post-login url={:?} page={:?} cookies={} looks_authenticated={}",
        post_login_url,
        page_after,
        cookies.len(),
        looks_authenticated,
    );
    for cookie in &cookies {
        tracing::info!(
            "browser login: cookie {} (domain {}, http_only={})",
            cookie.name,
            cookie.domain,
            cookie.http_only
        );
    }

    // 7. Token-session sites (Firebase Auth — monkeytype is one) keep the
    //    session in localStorage, not cookies. Replicate it so the caller can
    //    write it into the user's own tab. Best-effort; a read failure loses
    //    the token-session but not a cookie-session.
    let local_session = harvest::harvest_local_storage(&cdp, &session)
        .await
        .unwrap_or_default();
    let cached_db = harvest::harvest_indexed_db(&cdp, &session)
        .await
        .unwrap_or_default();
    tracing::info!(
        "browser login: harvested {} cookies, {} storage keys, {} IndexedDB records",
        cookies.len(),
        local_session.len(),
        cached_db.len(),
    );

    let _ = cdp::close_page_session(&cdp, &target_id).await;
    drop(browser);

    Ok(LoginOutcome {
        landing_url: start_url.to_string(),
        cookies,
        looks_authenticated,
        site_mode,
        residual_note: site_mode.residual_note().to_string(),
        user_verified,
        used_second_factor: false,
        awaiting_second_factor: None,
        second_factor_downgraded: false,
        used_browser: true,
        local_session,
        cached_db,
    })
}

fn acquire_single_flight(
    state: &AppState,
) -> Result<tokio::sync::OwnedMutexGuard<()>, LoginError> {
    state
        .browser_login_mutex
        .clone()
        .try_lock_owned()
        .map_err(|_| LoginError::BrowserLoginInProgress)
}

/// Seed the browser's cookie jar with the tab's pre-session cookies before the
/// login page loads.
async fn seed_browser_cookies(
    cdp: &Cdp,
    session: &str,
    cookies: &[crate::login::BrowserCookie],
) -> Result<(), String> {
    for cookie in cookies {
        let mut params = serde_json::json!({
            "name": cookie.name,
            "value": cookie.value,
            "path": cookie.path,
            "secure": cookie.secure,
            "httpOnly": cookie.http_only,
        });
        if cookie.host_only {
            params["url"] = serde_json::json!(format!(
                "{}://{}{}",
                if cookie.secure { "https" } else { "http" },
                cookie.domain,
                cookie.path
            ));
        } else {
            params["domain"] = serde_json::json!(cookie.domain);
        }
        if let Some(expires) = cookie.expires_at {
            params["expires"] = serde_json::json!(expires);
        }
        if let Some(same_site) = &cookie.same_site {
            let mapped = match same_site.as_str() {
                "strict" => "Strict",
                "lax" => "Lax",
                "none" => "None",
                _ => continue,
            };
            params["sameSite"] = serde_json::json!(mapped);
        }
        let _ = cdp.call_scoped("Network.setCookie", params, session).await;
    }
    Ok(())
}

/// Hold the window open until the login flow completes, then take the session.
///
/// After the password is accepted, a site may demand a second factor — a phone
/// approval, an e-mailed code — that the human finishes in the window. We poll
/// for the flow to *finish* and keep the window open for the human until then:
///
///  * the page left the login page (a redirect-based login — rateyourmusic,
///    most server-rendered sites), or
///  * the login form was replaced in place (an SPA login — hardcover.app: the
///    session cookie lands via an XHR and the URL never changes), and no
///    second-factor field took the form's place.
///
/// When either fires, the session cookies are harvested and the function
/// returns, so the caller tears the browser down promptly.
///
/// The comparison is against `start_url` (the page the login actually started
/// on), never against a URL captured *after* the login request was handled:
/// by then the page may already have redirected to a success page, and
/// comparing to that would keep the window open for the whole budget.
async fn wait_for_cookies(
    cdp: &Cdp,
    session: &str,
    start_url: &Url,
) -> Result<Vec<crate::login::SessionCookie>, LoginError> {
    let deadline = std::time::Instant::now() + POST_LOGIN_TIMEOUT;
    let mut last_seen = std::time::Instant::now();
    loop {
        let current = cdp::evaluate(cdp, session, "location.href")
            .await
            .map_err(|e| LoginError::Http(format!("could not read the page after login: {e}")))?
            .get("result")
            .and_then(|x| x.get("value"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();

        if last_seen.elapsed() >= std::time::Duration::from_secs(5) {
            tracing::info!("browser login: still waiting for the session on {current}");
            last_seen = std::time::Instant::now();
        }

        // Still on the login page (or the page it started on)? Keep waiting
        // for the human to finish (a second factor, say). Anything else means
        // the flow completed one way or another.
        let path = current.to_lowercase();
        let on_login_page = path.contains("/login")
            || path.contains("/signin")
            || path == start_url.as_str().to_lowercase();
        let moved_past_login = !current.is_empty() && !on_login_page;

        // SPA login: the URL never changes, but the site swapped the login
        // form for the app view. The password field vanishing is that signal —
        // unless a second-factor field took its place, in which case the human
        // is still finishing and we keep the window open.
        let (password_gone, has_otp_field) = page_login_form_state(cdp, session).await;
        let spa_login_complete = password_gone && !has_otp_field;

        if moved_past_login || spa_login_complete {
            // The flow completed (or failed and redirected). Harvest the
            // session from both the page it ended on and the starting site.
            // A lost CDP connection here must not fail the whole login: the
            // page already said the flow moved on. Return what we have and let
            // the caller decide.
            let mut cookies = harvest::harvest(cdp, session, start_url.as_str()).await.unwrap_or_else(|e| {
                tracing::warn!(
                    "browser login: could not harvest the session ({e}); the page moved off \
                     the login page, so the login likely succeeded in the window"
                );
                Vec::new()
            });
            if !current.is_empty() {
                if let Ok(on_current) = harvest::harvest(cdp, session, &current).await {
                    cookies.extend(on_current);
                }
            }
            return Ok(cookies);
        }
        if std::time::Instant::now() > deadline {
            // The human never finished the second factor. Report the partial
            // session honestly rather than a lie.
            return harvest::harvest(cdp, session, start_url.as_str())
                .await
                .map_err(|e| LoginError::Http(e.to_string()));
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Is the login form gone from the page, and did a second-factor field take
/// its place? Both in one round-trip.
async fn page_login_form_state(cdp: &Cdp, session: &str) -> (bool, bool) {
    let script = r#"
        (() => {
          const deepAll = (selector, root = document) => {
            const out = [];
            const walk = (r) => {
              r.querySelectorAll(selector).forEach((el) => out.push(el));
              r.querySelectorAll('*').forEach((el) => {
                if (el.shadowRoot) walk(el.shadowRoot);
              });
            };
            walk(root);
            return out;
          };
          return {
            hasPassword: deepAll('input[type=password]').length > 0,
            hasOtp: deepAll(
              'input[autocomplete="one-time-code"], input[inputmode="numeric"], input[name*="otp" i], input[name*="2fa" i], input[name*="twofactor" i]'
            ).length > 0,
          };
        })()
    "#;
    let Ok(response) = cdp::evaluate(cdp, session, script).await else {
        return (false, false);
    };
    let value = response
        .get("result")
        .and_then(|x| x.get("value"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let password_gone = value.get("hasPassword").and_then(serde_json::Value::as_bool) == Some(false);
    let has_otp = value.get("hasOtp").and_then(serde_json::Value::as_bool) == Some(true);
    (password_gone, has_otp)
}

#[cfg(test)]
mod tests;
