//! Tests for the browser-driven login tier.
//!
//! The pure decision logic — what to do with a paused request, how to map CDP
//! cookies — is tested head-on. The end-to-end test that drives a *real*
//! browser is `#[ignore]`d: it needs Chrome/Chromium/Edge installed, which the
//! normal suite must not assume.

use serde_json::json;
use url::Url;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::intercept::{core_send_credential, handle_paused_request, InterceptError, PausedAction};
use super::*;
use crate::js_login::{CapturedRequest, PLACEHOLDER_PASSWORD};

const PASSWORD: &str = "correct-horse-battery-staple-9137";

fn site(url: &str) -> Url {
    Url::parse(url).unwrap()
}

// ── Interception decision ─────────────────────────────────────────────────────

#[test]
fn a_request_carrying_the_placeholder_gets_the_real_password() {
    let target = site("https://bank.example/login");
    let request = json!({
        "url": "https://bank.example/session",
        "method": "POST",
        "headers": { "content-type": "application/x-www-form-urlencoded" },
        "postData": format!("csrf=tok&user=ada&pw={PLACEHOLDER_PASSWORD}"),
    });
    let action = handle_paused_request(&request, Some(&target), PASSWORD).unwrap();
    let PausedAction::ContinueWith { request, body, .. } = action else {
        panic!("expected substitution");
    };
    assert!(body.contains("pw=correct-horse-battery-staple-9137"), "{body}");
    assert!(!body.contains(PLACEHOLDER_PASSWORD), "{body}");
    // The page's other fields survive untouched.
    assert!(body.contains("csrf=tok"), "{body}");
    assert!(body.contains("user=ada"), "{body}");
    // The substituted request payload is what the Tier-3 core-perform path
    // would send over the core's own TLS (never into the browser).
    assert_eq!(request.url, "https://bank.example/session");
    assert!(request.body.contains("pw=correct-horse-battery-staple-9137"));
    assert!(!request.body.contains(PLACEHOLDER_PASSWORD));
}

#[test]
fn a_json_login_body_is_substituted_too() {
    let target = site("https://example.com/login");
    let request = json!({
        "url": "https://example.com/api/session",
        "method": "POST",
        "headers": { "content-type": "application/json" },
        "postData": format!(r#"{{"email":"ada","password":"{PLACEHOLDER_PASSWORD}"}}"#),
    });
    let action = handle_paused_request(&request, Some(&target), PASSWORD).unwrap();
    let PausedAction::ContinueWith { body, .. } = action else {
        panic!("expected substitution");
    };
    assert!(body.contains(&format!("\"password\":\"{PASSWORD}\"")), "{body}");
    assert!(!body.contains(PLACEHOLDER_PASSWORD), "{body}");
}

#[test]
fn a_request_without_the_placeholder_passes_through() {
    let target = site("https://example.com/login");
    let request = json!({
        "url": "https://example.com/analytics",
        "method": "GET",
        "headers": {},
        "postData": "",
    });
    assert_eq!(
        handle_paused_request(&request, Some(&target), PASSWORD).unwrap(),
        PausedAction::Continue
    );
}

#[test]
fn a_credential_request_to_a_known_identity_provider_is_allowed() {
    // monkeytype (and many SPA sites) authenticate through Firebase Auth: the
    // login posts to identitytoolkit.googleapis.com, off the site itself.
    let page = site("https://monkeytype.com/login");
    let request = json!({
        "url": "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=abc",
        "method": "POST",
        "headers": { "content-type": "application/json" },
        "postData": format!(r#"{{"email":"ada","password":"{PLACEHOLDER_PASSWORD}","returnSecureToken":true}}"#),
    });
    let action = handle_paused_request(&request, Some(&page), PASSWORD).unwrap();
    let PausedAction::ContinueWith { body, .. } = action else {
        panic!("expected substitution");
    };
    assert!(body.contains(PASSWORD), "{body}");
    assert!(!body.contains(PLACEHOLDER_PASSWORD), "{body}");
}

#[test]
fn a_request_aimed_off_the_site_is_refused() {
    let target = site("https://bank.example/login");
    let request = json!({
        "url": "https://evil.example/collect",
        "method": "POST",
        "headers": {},
        "postData": format!("pw={PLACEHOLDER_PASSWORD}"),
    });
    assert!(matches!(
        handle_paused_request(&request, Some(&target), PASSWORD),
        Err(InterceptError::CrossSite(host)) if host == "evil.example"
    ));
}

#[test]
fn a_page_that_transformed_the_password_cannot_be_substituted() {
    let target = site("https://example.com/login");
    // The page hashed the placeholder client-side, so the outgoing body no
    // longer carries it verbatim. The handler cannot recognise this as the
    // login request, so it passes it through untouched — the site receives a
    // hash of the placeholder and the login fails honestly. Nothing is
    // injected and nothing leaks; the failure is the guard.
    let request = json!({
        "url": "https://example.com/session",
        "method": "POST",
        "headers": {},
        "postData": "pw=sha256$deadbeef",
    });
    assert_eq!(
        handle_paused_request(&request, Some(&target), PASSWORD).unwrap(),
        PausedAction::Continue
    );
}

// ── Tier-3 core-perform: the credential goes over the core's own TLS ──────────

/// Tier-3 is on by default; only `VELA_BROWSER_CORE_PERFORM=0` opts it out.
/// Pins the RT-10 mitigation so a later change doesn't silently flip the
/// default back to pushing the password through the browser.
#[test]
fn tier3_core_perform_is_default_on_and_opt_out_only() {
    std::env::remove_var("VELA_BROWSER_CORE_PERFORM");
    assert!(super::intercept::core_perform_enabled(), "default must be core-perform");
    std::env::set_var("VELA_BROWSER_CORE_PERFORM", "1");
    assert!(super::intercept::core_perform_enabled());
    std::env::set_var("VELA_BROWSER_CORE_PERFORM", "0");
    assert!(!super::intercept::core_perform_enabled(), "=0 must opt out");
    std::env::remove_var("VELA_BROWSER_CORE_PERFORM");
}

/// monkeytype (and many SPA sites) authenticate through Firebase Auth: the
/// login POST goes to the allow-listed `identitytoolkit.googleapis.com`, off
/// the page's own site, with a JSON body. The Tier-3 interception path lets it
/// through (`handle_paused_request`), then sends that credential from the
/// *core*. This pins what changes for those sites with `VELA_BROWSER_CORE_PERFORM`:
/// the password to the identity provider travels the core's own TLS, never the
/// browser.
#[tokio::test]
async fn tier3_sends_a_firebase_auth_credential_from_the_core() {
    // Allow-listed IdP standing in for identitytoolkit.googleapis.com.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/accounts:signInWithPassword"))
        .and(body_string_contains("\"password\":\"correct-horse-battery-staple-9137\""))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"idToken":"tok","refreshToken":"rt","localId":"ml","email":"ada"}"#,
        ))
        .mount(&server)
        .await;

    // The page (monkeytype) fills a form whose JS posts to the IdP. Build the
    // post-substitution request exactly as it reaches `core_send` in Tier-3:
    // the placeholder has already been replaced with the real password in the
    // core, so the body carries the actual credential.
    let url = format!("{}/v1/accounts:signInWithPassword", server.uri());
    let request = CapturedRequest {
        url,
        method: "POST".to_string(),
        headers: std::collections::BTreeMap::from([(
            "content-type".to_string(),
            "application/json".to_string(),
        )]),
        body: format!(
            r#"{{"email":"ada","password":"{PASSWORD}","returnSecureToken":true}}"#
        ),
    };

    let login = core_send_credential(&request, &request.body)
        .await
        .expect("the core should send the Firebase Auth credential");

    assert_eq!(login.status, 200);
    // The identity provider really received the real password from the core.
    let got = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&got[0].body);
    assert!(
        body.contains("\"password\":\"correct-horse-battery-staple-9137\""),
        "{body}"
    );
    // The token-session comes back to the core, for reinstatement in the tab.
    let text = String::from_utf8_lossy(&login.body);
    assert!(text.contains("idToken"), "{text}");
}

/// The heart of Tier-3: [`core_send_credential`] sends the *real* password
/// over the core's own connection — it is never handed to the browser. So a
/// wiremock standing in for the site must receive the real credential, and the
/// answered session cookie must come back for reinstatement in the browser.
#[tokio::test]
async fn tier3_sends_the_credential_over_the_cores_own_tls() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .and(body_string_contains("pw=correct-horse-battery-staple-9137"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=core-session-1; Path=/; HttpOnly")
                .set_body_string("<html>Welcome</html>"),
        )
        .mount(&server)
        .await;

    let url = format!("{}/session", server.uri());
    let request = CapturedRequest {
        url,
        method: "POST".to_string(),
        headers: std::collections::BTreeMap::from([(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )]),
        body: "user=ada&pw=correct-horse-battery-staple-9137".to_string(),
    };

    let login = core_send_credential(&request, &request.body)
        .await
        .expect("the core should be able to send the credential");

    assert_eq!(login.status, 200);
    assert!(
        login.set_cookies.iter().any(|c| c.name == "sid"),
        "the session cookie the site issued must be relayed back"
    );

    // The mock actually received the real password — proof the core carried it.
    let got = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&got[0].body);
    assert!(body.contains("pw=correct-horse-battery-staple-9137"), "{body}");
}

/// Tier-3 must *refuse* when the site will not accept the core's client (a
/// bot-walled POST, or a redirecting login) — it never silently falls back to
/// handing the password to the browser.
#[tokio::test]
async fn tier3_refuses_instead_of_re_exposing_the_password() {
    let server = MockServer::start().await;
    // A bot wall over the POST replies with a challenge status.
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let url = format!("{}/session", server.uri());
    let request = CapturedRequest {
        url,
        method: "POST".to_string(),
        headers: std::collections::BTreeMap::new(),
        body: "pw=correct-horse-battery-staple-9137".to_string(),
    };

    let error = core_send_credential(&request, &request.body)
        .await
        .expect_err("a bot-walled POST must refuse, not re-expose the password");
    assert!(error.to_string().contains("did not accept"), "{error:?}");
}

// ── Cookie mapping ────────────────────────────────────────────────────────────

#[test]
fn cdp_cookies_map_to_session_cookies() {
    let cookie = json!({
        "name": "sid",
        "value": "abc123",
        "domain": ".bank.example",
        "path": "/",
        "expires": 1_700_000_000.0,
        "size": 10,
        "httpOnly": true,
        "secure": true,
        "session": false,
        "sameSite": "Lax",
    });
    let mapped = harvest::to_session_cookie(cookie).unwrap();
    assert_eq!(mapped.name, "sid");
    assert_eq!(mapped.value, "abc123");
    assert_eq!(mapped.domain, ".bank.example");
    assert_eq!(mapped.path, "/");
    assert!(mapped.secure);
    assert!(mapped.http_only);
    assert_eq!(mapped.same_site.as_deref(), Some("lax"));
    assert_eq!(mapped.expires_at, Some(1_700_000_000));
    assert!(!mapped.host_only, "a domain cookie is not host-only");
}

#[test]
fn a_host_only_cookie_and_a_session_cookie_map_correctly() {
    let host_only = json!({
        "name": "hostonly",
        "value": "x",
        "domain": "127.0.0.1",
        "path": "/",
        "expires": -1.0,
        "httpOnly": false,
        "secure": false,
        "sameSite": "None",
    });
    let mapped = harvest::to_session_cookie(host_only).unwrap();
    assert!(mapped.host_only);
    assert_eq!(mapped.expires_at, None, "a session cookie has no expiry");
    assert_eq!(mapped.same_site.as_deref(), Some("none"));
}

// ── End-to-end, needs a real browser ──────────────────────────────────────────

/// The fallback wiring inside `perform_login`: a site that refuses the core's
/// own client (a bot wall) is handed to the browser tier instead of being
/// reported as `SiteRefused`. The browser tier is disabled via the test seam
/// so the proof is instant and windowless: the error the browser tier reports
/// when disabled proves the fallback fired, not the plain bot-wall refusal.
#[tokio::test]
async fn a_bot_wall_falls_back_to_the_browser_tier() {
    std::env::set_var("VELA_BROWSER_LOGIN_DISABLED", "1");

    // Prove the wiring without opening a real browser window against the mock
    // 403 page (which would sit on the URL doing nothing).
    std::env::set_var("VELA_BROWSER_LOGIN_DISABLED", "1");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = std::sync::Arc::new(crate::AppState::for_test(dir.path()));
    state.unlock_for_test(&crate::crypto::Crypto::generate_rms());
    let login_url = format!("{}/login", server.uri());
    let now = chrono::Utc::now();
    state.vault.write().add_item(crate::vault::VaultItem::Login {
        meta: crate::vault::VaultMeta {
            id: "i1".to_string(),
            name: "Bot-walled".to_string(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
        },
        url: login_url.clone(),
        username: "ada".to_string(),
        pass: PASSWORD.to_string(),
        totp: None,
        app_ids: Vec::new(),
        credential_change_needs_reauth: None,
        allow_second_factor_downgrade: None,
    });

    let error = crate::login::perform_login(
        &state,
        &crate::login::LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
            browser: None,
        },
        crate::login::LoginGrant::mint("i1".to_string(), "127.0.0.1".to_string(), true),
    )
    .await
    .expect_err("a 403 should not produce a login");

    // The browser tier reported its own error (the test seam), proving the
    // fallback fired rather than the plain bot-wall refusal.
    assert!(
        matches!(&error, crate::login::LoginError::Http(message)
            if message.contains("browser tier")),
        "expected the browser tier to be attempted, got {error:?}"
    );
    assert!(
        !matches!(error, crate::login::LoginError::SiteRefused { .. }),
        "the bot wall should have fallen through to the browser tier"
    );
}

/// The full Phase-1 proof, run on a machine that actually has Chrome/Chromium/
/// Edge. A wiremock login page is filled with the placeholder, the core
/// substitutes the real password at the network layer, and the mock receives
/// the real credential while the page's own JS never had it.
#[tokio::test]
#[ignore = "needs a real Chrome/Chromium/Edge browser installed"]
async fn a_real_browser_logs_in_without_the_page_seeing_the_password() {
    let server = MockServer::start().await;
    let login_page = format!(
        r#"<html><body>
        <form method="POST" action="/session">
          <input type="text" name="user">
          <input type="password" name="pw">
          <button type="submit">Sign in</button>
        </form></body></html>"#
    );
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(
            // `set_body_raw` sets the MIME too; `set_body_string` would let
            // wiremock default to text/plain and Chrome would render the HTML
            // as source text — no form, no password field.
            ResponseTemplate::new(200).set_body_raw(login_page, "text/html; charset=utf-8"),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=session-1; Path=/; HttpOnly")
                .set_body_string("<html>Welcome</html>"),
        )
        .mount(&server)
        .await;

    let login_url = Url::parse(&format!("{}/login", server.uri())).unwrap();
    let outcome = login(&login_url, "ada", PASSWORD, &[], SiteMode::SelfServe, true)
        .await
        .expect("the browser login should complete");

    assert!(outcome.looks_authenticated);
    assert!(
        outcome.cookies.iter().any(|c| c.name == "sid"),
        "expected the session cookie, got {:#?}",
        outcome.cookies
    );

    // The mock's /session endpoint received the REAL password, not the
    // placeholder the page filled.
    let requests = server.received_requests().await.unwrap_or_default();
    let session = requests
        .iter()
        .find(|r| r.url.path() == "/session")
        .expect("the login form should have been submitted");
    let body = String::from_utf8_lossy(&session.body);
    assert!(body.contains("pw=correct-horse-battery-staple-9137"), "{body}");
    assert!(!body.contains(PLACEHOLDER_PASSWORD), "{body}");
}
