//! Tests for the per-site login recipes.
//!
//! Two layers. The pure functions — marker substitution, cookie scoping, RSA —
//! are tested head-on. The two flows (`run_json`, `run_steam`) are tested
//! against a local mock server with the recipe URLs pointed at it, so the
//! whole ceremony is exercised without any live site.

use super::*;
use rsa::pkcs1v15::DecryptingKey;
use rsa::traits::{PublicKeyParts, RandomizedDecryptor};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PASSWORD: &str = "correct-horse-battery-staple-9137";
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn test_recipe(gate: Gate, flow: Flow) -> LoginRecipe {
    LoginRecipe {
        sites: &["127.0.0.1"],
        name: "Test site",
        gate,
        flow,
    }
}

fn captcha_artifacts(token: &str) -> BrowserArtifacts {
    BrowserArtifacts {
        captcha_token: Some(token.to_string()),
        cookies: vec![],
    }
}

fn target_for(server: &MockServer) -> Url {
    normalize_url(&server.uri()).unwrap()
}

/// Find the requests the mock server actually received for a path.
async fn requests_for(server: &MockServer, method_name: &str, path: &str) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| {
            request.method.as_str() == method_name && request.url.path() == path
        })
        .map(|request| String::from_utf8_lossy(&request.body).to_string())
        .collect()
}

// ── Registry ──────────────────────────────────────────────────────────────────

#[test]
fn the_registry_claims_the_expected_sites() {
    // Riot is deliberately absent: its login moved behind Cloudflare and the
    // old recipe shape is stale — see the registry's own note.
    assert!(for_site("riotgames.com").is_none());
    assert!(for_site("steampowered.com").is_some());
    assert!(for_site("steamcommunity.com").is_some());
    assert!(for_site("github.com").is_none());
    assert!(for_site("").is_none());
}

#[test]
fn for_url_matches_on_the_registrable_domain() {
    let url = normalize_url("https://login.steampowered.com/login").unwrap();
    let recipe = for_url(&url).expect("steam recipe");
    assert_eq!(recipe.name, "Steam");

    let url = normalize_url("https://store.steampowered.com/").unwrap();
    assert_eq!(for_url(&url).unwrap().name, "Steam");

    let url = normalize_url("https://github.com/login").unwrap();
    assert!(for_url(&url).is_none());
}

#[test]
fn mode_for_site_classifies_the_gate() {
    assert_eq!(mode_for_site(Some("riotgames.com".to_string())), "form");
    assert_eq!(mode_for_site(Some("steampowered.com".to_string())), "recipe");
    assert_eq!(mode_for_site(Some("github.com".to_string())), "form");
    assert_eq!(mode_for_site(None), "form");
}

#[test]
fn every_template_carries_the_markers_it_documents() {
    for recipe in RECIPES.iter() {
        if let Flow::Json(flow) = &recipe.flow {
            let body = serde_json::to_string(&flow.body).unwrap();
            if recipe.gate == Gate::HCaptcha {
                assert!(body.contains(MARKER_CAPTCHA), "{body}");
            }
            assert!(body.contains(MARKER_USERNAME), "{body}");
            assert!(body.contains(MARKER_PASSWORD), "{body}");
            if let Some(mfa) = &flow.mfa {
                let mfa_body = serde_json::to_string(&mfa.body).unwrap();
                assert!(mfa_body.contains(MARKER_OTP), "{mfa_body}");
            }
        }
    }
}

// ── Body templates ────────────────────────────────────────────────────────────

#[test]
fn fill_json_substitutes_every_marker() {
    let template = serde_json::json!({
        "type": "auth",
        "riot_identity": {
            "username": "$VELA_USERNAME",
            "password": "$VELA_PASSWORD",
            "captcha": "$VELA_CAPTCHA",
            "nested": { "list": ["$VELA_USERNAME", "plain"] },
        },
    });
    let filled = fill_json(&template, "ada", PASSWORD, Some("tok-1"), None).unwrap();
    let serialized = serde_json::to_string(&filled).unwrap();
    assert!(serialized.contains("\"ada\""));
    assert!(serialized.contains(PASSWORD));
    assert!(serialized.contains("tok-1"));
    assert!(!serialized.contains("$VELA_"), "{serialized}");
}

#[test]
fn optional_markers_substitute_empty_when_absent() {
    // The captcha and OTP markers are optional: when no token or code was
    // supplied, the field goes out empty and the site decides whether it
    // needed one. The password marker is never optional.
    let template = serde_json::json!({
        "captcha": "$VELA_CAPTCHA",
        "otp": "$VELA_OTP",
        "password": "$VELA_PASSWORD",
    });
    let filled = fill_json(&template, "ada", PASSWORD, None, None).unwrap();
    let serialized = serde_json::to_string(&filled).unwrap();
    assert!(serialized.contains("\"captcha\":\"\""), "{serialized}");
    assert!(serialized.contains("\"otp\":\"\""), "{serialized}");
    assert!(!serialized.contains("$VELA_"), "{serialized}");
}

// ── Cookie scoping ────────────────────────────────────────────────────────────

#[tokio::test]
async fn browser_cookies_are_scoped_before_they_are_seeded() {
    let server = MockServer::start().await;
    let target = target_for(&server);

    let mut jar = CookieJar::default();
    let artifacts = BrowserArtifacts {
        captcha_token: None,
        cookies: vec![
            BrowserCookie {
                name: "sessionid".to_string(),
                value: "steam-session".to_string(),
                domain: "127.0.0.1".to_string(),
                path: "/".to_string(),
                secure: false,
                http_only: true,
                same_site: None,
                expires_at: None,
                host_only: true,
            },
            // A cookie scoped to some other site must not ride along.
            BrowserCookie {
                name: "sid".to_string(),
                value: "phish".to_string(),
                domain: "evil.example".to_string(),
                path: "/".to_string(),
                secure: false,
                http_only: false,
                same_site: None,
                expires_at: None,
                host_only: false,
            },
        ],
    };
    jar.seed_browser(&artifacts.cookies, &target);

    let cookies = jar.snapshot();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "sessionid");
    assert_eq!(cookies[0].value, "steam-session");
    assert_eq!(jar.header_for(&target).as_deref(), Some("sessionid=steam-session"));
}

// ── Riot (JSON + hCaptcha) ────────────────────────────────────────────────────

fn riot_flow(server: &MockServer) -> JsonFlow {
    JsonFlow {
        url: format!("{}/api/v1/login", server.uri()),
        method: "PUT",
        body: serde_json::json!({
            "type": "auth",
            "remember": true,
            "language": "en_US",
            "riot_identity": {
                "username": "$VELA_USERNAME",
                "password": "$VELA_PASSWORD",
                "captcha": "$VELA_CAPTCHA",
            },
        }),
        mfa: Some(JsonMfa {
            url: format!("{}/api/v1/login", server.uri()),
            method: "PUT",
            body: serde_json::json!({
                "type": "multifactor",
                "language": "en_US",
                "multifactor": { "otp": "$VELA_OTP" },
            }),
        }),
    }
}

#[tokio::test]
async fn riot_login_submits_the_captcha_and_password_and_reports_success() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "asid=session-1; Path=/; HttpOnly")
                .set_body_string(r#"{"type":"auth","error":null}"#),
        )
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let flow = riot_flow(&server);
    let recipe = test_recipe(Gate::HCaptcha, Flow::Json(flow.clone()));
    let target = target_for(&server);

    let outcome = run_json(
        &recipe,
        &flow,
        &client,
        &mut jar,
        "ada",
        PASSWORD,
        None,
        Some(&captcha_artifacts("hcaptcha-tok-1")),
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await
    .expect("the login should complete");

    assert!(outcome.looks_authenticated);
    assert!(!outcome.used_second_factor);
    assert_eq!(outcome.cookies.len(), 1);
    assert_eq!(outcome.cookies[0].name, "asid");

    // The request that went out carries the credential and the lifted token,
    // and no marker survived into it.
    let bodies = requests_for(&server, "PUT", "/api/v1/login").await;
    assert_eq!(bodies.len(), 1);
    let sent: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(sent["riot_identity"]["username"], "ada");
    assert_eq!(sent["riot_identity"]["password"], PASSWORD);
    assert_eq!(sent["riot_identity"]["captcha"], "hcaptcha-tok-1");
    assert!(!bodies[0].contains("$VELA_"), "{}", bodies[0]);
}

#[tokio::test]
async fn riot_login_answers_the_multifactor_gate_with_the_vault_totp() {
    let server = MockServer::start().await;
    // First request (type=auth) is answered with a second-factor demand; the
    // follow-up (type=multifactor) is answered with success. Mounted first
    // wins, so the more specific matcher comes first.
    Mock::given(method("PUT"))
        .and(path("/api/v1/login"))
        .and(body_string_contains("\"type\":\"auth\""))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "asid=session-1; Path=/; HttpOnly")
                .set_body_string(r#"{"type":"multifactor","multifactor":{"method":"otp"}}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/login"))
        .and(body_string_contains("\"type\":\"multifactor\""))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "asid=session-2; Path=/; HttpOnly")
                .set_body_string(r#"{"type":"auth","error":null}"#),
        )
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let flow = riot_flow(&server);
    let recipe = test_recipe(Gate::HCaptcha, Flow::Json(flow.clone()));
    let target = target_for(&server);

    let outcome = run_json(
        &recipe,
        &flow,
        &client,
        &mut jar,
        "ada",
        PASSWORD,
        Some(TotpAnswer::Secret(TOTP_SECRET)),
        Some(&captcha_artifacts("hcaptcha-tok-1")),
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await
    .expect("the login should complete");

    assert!(outcome.used_second_factor, "the TOTP should have been sent");
    assert!(outcome.looks_authenticated);
    assert_eq!(outcome.cookies[0].value, "session-2");

    let bodies = requests_for(&server, "PUT", "/api/v1/login").await;
    assert_eq!(bodies.len(), 2);
    let second: serde_json::Value = serde_json::from_str(&bodies[1]).unwrap();
    assert_eq!(second["type"], "multifactor");
    let otp = second["multifactor"]["otp"].as_str().unwrap();
    assert_eq!(otp.len(), 6);
    assert!(otp.chars().all(|c| c.is_ascii_digit()));
}

#[tokio::test]
async fn riot_login_refuses_when_the_captcha_was_not_minted_in_the_browser() {
    let server = MockServer::start().await;
    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let flow = riot_flow(&server);
    let recipe = test_recipe(Gate::HCaptcha, Flow::Json(flow.clone()));
    let target = target_for(&server);

    let error = run_json(
        &recipe,
        &flow,
        &client,
        &mut jar,
        "ada",
        PASSWORD,
        None,
        None,
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, LoginError::NeedsBrowserArtifact(_)),
        "expected a missing-artifact refusal, got {error:?}"
    );
    // Nothing was sent at all.
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
}

#[tokio::test]
async fn a_recipe_cannot_move_the_password_off_the_domains_it_claims() {
    let server = MockServer::start().await;
    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let flow = riot_flow(&server);
    // The recipe claims a domain that is NOT where its endpoint lives — the
    // credential would be leaving the recipe's declared perimeter.
    let recipe = LoginRecipe {
        sites: &["example.com"],
        name: "Test site",
        gate: Gate::HCaptcha,
        flow: Flow::Json(flow.clone()),
    };
    let target = target_for(&server);

    let error = run_json(
        &recipe,
        &flow,
        &client,
        &mut jar,
        "ada",
        PASSWORD,
        None,
        Some(&captcha_artifacts("tok")),
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, LoginError::CrossSiteRedirect(_)));
}

/// Steam's login legitimately crosses registrable domains — the login page is
/// under `steampowered.com` while the RSA challenge/submit live under
/// `steamcommunity.com`. The endpoint check must honour that rather than
/// refusing the user's own login.
#[test]
fn endpoint_claimed_allows_steams_cross_domain_login() {
    let steam = LoginRecipe {
        sites: &["steampowered.com", "steamcommunity.com"],
        name: "Steam",
        gate: Gate::None,
        flow: Flow::Steam(SteamFlow {
            api_url: "https://api.steampowered.com/".to_string(),
            finalize_url: "https://login.steampowered.com/jwt/finalizelogin".to_string(),
        }),
    };
    let api = normalize_url("https://api.steampowered.com/").unwrap();
    assert!(endpoint_claimed(&steam, &api));
    let community = normalize_url("https://steamcommunity.com/login/home/").unwrap();
    assert!(endpoint_claimed(&steam, &community));
    let store = normalize_url("https://store.steampowered.com/").unwrap();
    assert!(endpoint_claimed(&steam, &store));
    let evil = normalize_url("https://evil.example/collect").unwrap();
    assert!(!endpoint_claimed(&steam, &evil));
}

// ── Steam (RSA challenge then submit) ─────────────────────────────────────────

fn steam_flow(server: &MockServer) -> SteamFlow {
    SteamFlow {
        api_url: format!("{}/", server.uri()),
        finalize_url: format!("{}/jwt/finalizelogin", server.uri()),
    }
}

fn steam_recipe(server: &MockServer) -> LoginRecipe {
    let flow = steam_flow(server);
    LoginRecipe {
        sites: &["127.0.0.1"],
        name: "Steam",
        gate: Gate::None,
        flow: Flow::Steam(flow),
    }
}

/// Mount the RSA-key fetch: the Web API answers it as plain JSON.
async fn mount_steam_key(server: &MockServer, private: &rsa::RsaPrivateKey) {
    let n = private.n().to_str_radix(16);
    let e = private.e().to_str_radix(16);
    Mock::given(method("GET"))
        .and(path("/IAuthenticationService/GetPasswordRSAPublicKey/v1/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "response": {
                    "publickey_mod": n,
                    "publickey_exp": e,
                    "timestamp": "1700000000000",
                }
            })),
        )
        .mount(server)
        .await;
}

/// A `BeginAuthSessionViaCredentials` protobuf response, `allow_guard` picking
/// whether Steam demands a device code (guard type 2) or nothing.
fn begin_auth_response(allow_guard: bool) -> Vec<u8> {
    let mut writer = super::steam_pb::Writer::default();
    writer.u64(1, 123); // client_id
    writer.bytes(2, b"req-1"); // request_id
    writer.u64(3, 5); // poll interval (seconds)
    writer.u64(5, 76561198000000001); // steamid
    writer.string(6, "weak-token"); // weak_token
    if allow_guard {
        let mut confirmation = super::steam_pb::Writer::default();
        confirmation.u64(1, 2); // DeviceCode
        writer.bytes(4, &confirmation.finish());
    }
    writer.finish()
}

fn poll_success_response() -> Vec<u8> {
    let mut writer = super::steam_pb::Writer::default();
    writer.string(3, "refresh-token-abc"); // refresh_token
    writer.finish()
}

/// Decrypt what the mock captured as the BeginAuth request's encrypted
/// password and check it is the plaintext. This is the whole point of the
/// Steam recipe: the password leaves this process only RSA-encrypted (base64,
/// inside a protobuf inside an `input_protobuf_encoded` form field).
async fn assert_begin_auth_carried_the_plaintext_encrypted(
    server: &MockServer,
    private: &rsa::RsaPrivateKey,
) {
    let bodies = requests_for(
        server,
        "POST",
        "/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
    )
    .await;
    assert!(!bodies.is_empty(), "BeginAuth was never called");
    let form: BTreeMap<String, String> = bodies[0]
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.to_string(), urlencoding::decode(v).ok()?.to_string()))
        })
        .collect();
    let encoded = form
        .get("input_protobuf_encoded")
        .expect("the request rides in input_protobuf_encoded");
    let request_pb = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("valid base64");
    let fields = super::steam_pb::parse(&request_pb);

    let encrypted_b64 = fields
        .iter()
        .find(|f| f.number == 3)
        .and_then(|f| f.bytes())
        .expect("field 3 is the encrypted password");
    let encrypted_b64 = String::from_utf8(encrypted_b64).unwrap();
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_b64)
        .expect("the password must be base64 of the RSA ciphertext");
    let decrypted = DecryptingKey::new(private.clone())
        .decrypt_with_rng(&mut OsRng, &ciphertext)
        .expect("the ciphertext must decrypt");
    assert_eq!(String::from_utf8(decrypted).unwrap(), PASSWORD);
}

async fn mount_begin_auth(server: &MockServer, eresult: &str, body: Vec<u8>) {
    Mock::given(method("POST"))
        .and(path("/IAuthenticationService/BeginAuthSessionViaCredentials/v1/"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("x-eresult", eresult)
                .set_body_raw(body, "application/octet-stream"),
        )
        .mount(server)
        .await;
}

async fn mount_poll(server: &MockServer, body: Vec<u8>) {
    Mock::given(method("POST"))
        .and(path("/IAuthenticationService/PollAuthSessionStatus/v1/"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("x-eresult", "1")
                .set_body_raw(body, "application/octet-stream"),
        )
        .mount(server)
        .await;
}

async fn mount_finalize(server: &MockServer, transfer_info: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/jwt/finalizelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transfer_info": transfer_info
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn steam_login_encrypts_the_password_in_the_core_and_completes() {
    let server = MockServer::start().await;
    let private = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    mount_steam_key(&server, &private).await;
    mount_begin_auth(&server, "1", begin_auth_response(false)).await;
    mount_poll(&server, poll_success_response()).await;
    mount_finalize(&server, serde_json::json!([])).await;

    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let recipe = steam_recipe(&server);
    let target = target_for(&server);

    let outcome = run_steam(
        &recipe,
        &steam_flow(&server),
        &client,
        &mut jar,
        "ada",
        PASSWORD,
        None,
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await
    .expect("the login should complete");

    assert!(outcome.looks_authenticated);
    assert!(!outcome.used_second_factor);

    assert_begin_auth_carried_the_plaintext_encrypted(&server, &private).await;

    // The finalize request carried the refresh token we polled for.
    let finalize_bodies = requests_for(&server, "POST", "/jwt/finalizelogin").await;
    assert_eq!(finalize_bodies.len(), 1);
    assert!(finalize_bodies[0].contains("refresh-token-abc"), "{}", finalize_bodies[0]);
}

#[tokio::test]
async fn steam_login_answers_a_device_code_inside_the_same_approval() {
    let server = MockServer::start().await;
    let private = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    mount_steam_key(&server, &private).await;
    mount_begin_auth(&server, "1", begin_auth_response(true)).await;
    // The guard-code submission is accepted...
    Mock::given(method("POST"))
        .and(path("/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("x-eresult", "1")
                .set_body_raw(Vec::new(), "application/octet-stream"),
        )
        .mount(&server)
        .await;
    mount_poll(&server, poll_success_response()).await;
    mount_finalize(&server, serde_json::json!([])).await;

    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let recipe = steam_recipe(&server);
    let target = target_for(&server);

    let outcome = run_steam(
        &recipe,
        &steam_flow(&server),
        &client,
        &mut jar,
        "ada",
        PASSWORD,
        Some(TotpAnswer::Secret(TOTP_SECRET)),
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await
    .expect("the login should complete");

    assert!(outcome.used_second_factor, "the device code should have been sent");
    assert!(outcome.looks_authenticated);

    // The guard-code request carried a six-digit code.
    let guard_bodies = requests_for(
        &server,
        "POST",
        "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/",
    )
    .await;
    assert_eq!(guard_bodies.len(), 1);
    assert!(guard_bodies[0].contains("code"), "{}", guard_bodies[0]);
}

#[tokio::test]
async fn steam_login_reports_a_wrong_password_honestly() {
    let server = MockServer::start().await;
    let private = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    mount_steam_key(&server, &private).await;
    // Steam answers the session begin with EResult 5 = InvalidPassword.
    mount_begin_auth(&server, "5", Vec::new()).await;

    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let recipe = steam_recipe(&server);
    let target = target_for(&server);

    let error = run_steam(
        &recipe,
        &steam_flow(&server),
        &client,
        &mut jar,
        "ada",
        PASSWORD,
        None,
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(&error, LoginError::Http(message) if message.contains("incorrect")),
        "expected a clean wrong-password refusal, got {error:?}"
    );
}
