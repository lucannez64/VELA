//! Fill the page's login fields with the username and the placeholder, and
//! submit.
//!
//! The password field receives `PLACEHOLDER_PASSWORD`, never the real value —
//! the real one is substituted at the network layer (`crate::browser::intercept`).
//! Values are written with the DOM's native value setter plus synthetic
//! `input`/`change` events, so framework-owned inputs (React, Vue) pick the
//! change up, and the form is submitted through `requestSubmit` so the page's
//! own validation and submit handlers run normally.

use crate::browser::cdp::{self, Cdp};
use crate::js_login::PLACEHOLDER_PASSWORD;

/// Why the page could not be filled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillError {
    /// No `input[type=password]` was found on the page, even after retrying.
    /// Carries a snapshot of what the page actually contained.
    NoPasswordField(String),
    /// The page's JavaScript threw while filling.
    Script(String),
    /// The browser connection died.
    Transport(String),
}

impl std::fmt::Display for FillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPasswordField(snapshot) => write!(
                f,
                "the page does not show a password field VELA could fill ({snapshot})"
            ),
            Self::Script(reason) => write!(f, "the page rejected the fill: {reason}"),
            Self::Transport(reason) => write!(f, "the browser connection failed: {reason}"),
        }
    }
}

/// How long to keep polling for the login form after navigation, and the
/// pause between attempts.
///
/// A bot-walled site answers a fresh browser with a challenge interstitial
/// (Cloudflare's JS check, occasionally an interactive checkbox in the visible
/// window) before it serves the actual login form. `loadEventFired` fires for
/// the interstitial, so the fill must keep polling until the real page — the
/// one with the password field — has rendered. 90 seconds covers a slow
/// challenge and gives the user time to tick an interactive checkbox.
const FILL_RETRIES: u32 = 300;
const FILL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// Fill the username and placeholder password, then submit the login form.
pub async fn fill_and_submit(
    cdp: &Cdp,
    session: &str,
    username: &str,
) -> Result<(), FillError> {
    let script = fill_script(username);
    for attempt in 0..FILL_RETRIES {
        match run_fill(cdp, session, &script).await? {
            FillOutcome::Ok => return Ok(()),
            FillOutcome::NoField => {
                // Log what the page is doing so a stalled challenge or a
                // wrong-page navigation is visible in the app log instead of
                // reading as a silent forever-wait.
                if attempt % 30 == 0 {
                    tracing::warn!(
                        "browser login: still waiting for a password field; page state: {}",
                        diagnose(cdp, session).await,
                    );
                }
                if attempt + 1 < FILL_RETRIES {
                    tokio::time::sleep(FILL_RETRY_DELAY).await;
                }
            }
        }
    }
    Err(FillError::NoPasswordField(diagnose(cdp, session).await))
}

async fn diagnose(cdp: &Cdp, session: &str) -> String {
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
            url: document.URL,
            title: document.title,
            hasForm: deepAll('form').length > 0,
            hasPassword: deepAll('input[type=password]').length > 0,
            bodySnippet: (document.body ? document.body.innerHTML : '').slice(0, 240),
          };
        })()
    "#;
    match cdp::evaluate(cdp, session, script).await {
        Ok(response) => response
            .get("result")
            .and_then(|r| r.get("value"))
            .map(|v| v.to_string())
            .unwrap_or_else(|| "no page state".to_string()),
        Err(e) => format!("could not read the page state: {e}"),
    }
}

enum FillOutcome {
    Ok,
    NoField,
}

async fn run_fill(cdp: &Cdp, session: &str, script: &str) -> Result<FillOutcome, FillError> {
    let response = cdp::evaluate(cdp, session, script)
        .await
        .map_err(|e| FillError::Transport(e.to_string()))?;
    if let Some(exception) = response.get("exceptionDetails") {
        let text = exception
            .get("exception")
            .and_then(|e| e.get("description"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown page error")
            .to_string();
        return Err(FillError::Script(text));
    }
    let verdict = response
        .get("result")
        .and_then(|r| r.get("value"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if verdict.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        tracing::info!(
            "browser login: filled form action={} user_field={} password_field={} password_filled_chars={}",
            verdict
                .get("formAction")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?"),
            verdict
                .get("userField")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("(none)"),
            verdict
                .get("passwordField")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?"),
            verdict
                .get("passwordFilledLength")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
        // The credentials are in the page (placeholder password). Submitting is
        // left to the human: auto-clicking is fragile across sites (a synthetic
        // click is untrusted and skipped by JS logins; a trusted CDP click
        // misses plain forms). The VELA window stays open; the user clicks the
        // site's own sign-in button, and the interception loop substitutes the
        // real password when the request fires.
        tracing::info!("browser login: credentials filled — waiting for the human to click sign-in");
        Ok(FillOutcome::Ok)
    } else {
        Ok(FillOutcome::NoField)
    }
}

/// Re-apply the fill if the page re-renders and clears the fields.
///
/// A site whose login is a JS app (or sits behind a bot check that reloads the
/// page) can re-mount its form and wipe programmatic values. This loop checks
/// every couple of seconds and re-fills if the password field is empty again.
/// It is aborted by the caller once the login request has been handled.
pub async fn keep_filled(cdp: &Cdp, session: &str, username: &str) {
    let script = format!(
        r#"
        (() => {{
          const deepAll = (selector, root = document) => {{
            const out = [];
            const walk = (r) => {{
              r.querySelectorAll(selector).forEach((el) => out.push(el));
              r.querySelectorAll('*').forEach((el) => {{
                if (el.shadowRoot) walk(el.shadowRoot);
              }});
            }};
            walk(root);
            return out;
          }};
          const pw = deepAll('input[type=password]')[0];
          if (!pw || pw.value) {{
            // If the form is hiding behind a cookie-consent dialog, dismiss it.
            const consent = deepAll('button, a[role="button"], [role="button"]').find((b) => {{
              const t = (b.textContent || '').trim().toLowerCase();
              return t.length > 0 && t.length < 60 &&
                /^(accept|agree|ok|accepter|j.?accepte|d.accord|allow|got it|consent)/.test(t) &&
                !/manage|settings|reject|decline|privacy|policy|more/.test(t);
            }});
            if (consent) consent.click();
            return;
          }}
          const setValue = (el, value) => {{
            const proto = el instanceof HTMLTextAreaElement
              ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
            Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
          }};
          setValue(pw, {placeholder:?});
          const scope = pw.closest('form') || pw.getRootNode() || document;
          const user = deepAll(
            'input[type=text], input[type=email], input[type=tel], input:not([type])',
            scope
          ).find((el) => !el.disabled);
          if (user) setValue(user, {username:?});
        }})()
        "#,
        placeholder = PLACEHOLDER_PASSWORD,
        username = username,
    );
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = cdp::evaluate(cdp, session, &script).await;
    }
}

fn fill_script(username: &str) -> String {
    format!(
        r##"
        (() => {{
          // Pierces shadow roots: modern login forms (Lit / web components,
          // Riot's included) render their fields inside `#shadow-root`, which
          // `document.querySelector` cannot see.
          const deepAll = (selector, root = document) => {{
            const out = [];
            const walk = (r) => {{
              r.querySelectorAll(selector).forEach((el) => out.push(el));
              r.querySelectorAll('*').forEach((el) => {{
                if (el.shadowRoot) walk(el.shadowRoot);
              }});
            }};
            walk(root);
            return out;
          }};
          const passwordFields = deepAll('input[type=password]');
          if (passwordFields.length === 0) {{
            // The login form may be hiding behind a cookie-consent dialog
            // (Osano/OneTrust on many sites). Dismiss it if present; the next
            // poll then finds the real form.
            const consent = deepAll('button, a[role="button"], [role="button"]').find((b) => {{
              const t = (b.textContent || '').trim().toLowerCase();
              return t.length > 0 && t.length < 60 &&
                /^(accept|agree|ok|accepter|j.?accepte|d.accord|allow|got it|consent)/.test(t) &&
                !/manage|settings|reject|decline|privacy|policy|more/.test(t);
            }});
            if (consent) {{
              consent.click();
              return {{ ok: false }};
            }}
            return {{ ok: false }};
          }}
          // Some pages (monkeytype, many SPA apps) show the login form and the
          // register form side by side, each with a password field. Picking
          // the first one can fill — and after substitution, send the real
          // password to — the register form. Score each candidate by what its
          // containing form *says*: a "log in" button and a single password
          // field are a login; a "sign up" button or a confirm-password field
          // are a registration. Take the highest-scoring login form.
          const scored = passwordFields.map((pw) => {{
            const form = pw.closest('form');
            const scope = form || pw.getRootNode() || document;
            const scopeAll = (sel) => deepAll(sel, scope);
            const buttons = form
              ? [...form.querySelectorAll('button, input[type=submit]')]
              : deepAll('button[type=submit], input[type=submit]');
            const btnText = buttons.map((b) => (b.textContent || '').trim().toLowerCase()).join(' ');
            const pwName = ((pw.name || '') + ' ' + (pw.id || '') + ' ' + (pw.placeholder || '')).toLowerCase();
            const passwordCount = scopeAll('input[type=password]').length;
            let score = 0;
            if (/log in|sign in|login|signin|connexion|connect/.test(btnText)) score += 3;
            if (/register|sign up|signup|create|join|subscribe/.test(btnText)) score -= 3;
            if (scopeAll('input[type=email], input[type=text], input[type=tel], input:not([type])')
                .some((el) => !el.disabled)) score += 1;
            if (passwordCount === 1) score += 1;
            if (passwordCount >= 2) score -= 1;
            if (/confirm|new password|register|signup/.test(pwName)) score -= 2;
            if (/login|password/.test(pwName) && !/confirm|new/.test(pwName)) score += 1;
            return {{ pw, form, scope, score }};
          }});
          scored.sort((a, b) => b.score - a.score);
          const chosen = scored[0];
          const pw = chosen.pw;
          const form = chosen.form;
          const scope = chosen.scope;
          const setValue = (el, value) => {{
            const proto = el instanceof HTMLTextAreaElement
              ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
            Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
          }};
          setValue(pw, {placeholder:?});
          const user = deepAll(
            'input[type=text], input[type=email], input[type=tel], input:not([type])',
            scope
          ).find((el) => !el.disabled);
          if (user) setValue(user, {username:?});
          // Deliberately do NOT tick "remember me". Sites that persist the
          // session through an auth SDK (monkeytype + Firebase) branch on that
          // checkbox: "remember me" on pushes the token to IndexedDB or
          // localStorage, off pushes it to sessionStorage — and only the
          // storage we harvest (localStorage + sessionStorage) survives the
          // transfer. So the unchecked state is the one we can actually carry.
          return {{
            ok: true,
            formAction: form ? form.action : '',
            userField: user ? user.name || user.id || user.type : null,
            passwordField: pw.name || pw.id || 'password',
            passwordFilledLength: pw.value.length,
          }};
        }})()
        "##,
        placeholder = PLACEHOLDER_PASSWORD,
        username = username,
    )
}
