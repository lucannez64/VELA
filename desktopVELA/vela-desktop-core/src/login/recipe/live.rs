//! Live-verification harness for the recipes, against the real sites.
//!
//! These tests are `#[ignore]`d: they talk to real services with real
//! credentials and are never part of the normal suite. Run them explicitly,
//! with credentials supplied through the environment (never on the command
//! line):
//!
//! ```text
//! # Steam — no captcha in the ordinary case:
//! VELA_LIVE_STEAM_USER='account-name' VELA_LIVE_STEAM_PASS='password' \
//!   [VELA_LIVE_STEAM_TOTP='otpauth://totp/Steam:name?secret=...'] \
//!   cargo test -p vela-desktop-core --lib -- --ignored live::steam --nocapture
//!
//! # Riot — a human must solve the hCaptcha (~2 min token TTL):
//! VELA_LIVE_RIOT_USER='email-or-riot-id' VELA_LIVE_RIOT_PASS='password' \
//!   [VELA_LIVE_RIOT_TOTP='otpauth://...'] \
//!   cargo test -p vela-desktop-core --lib -- --ignored live::riot --nocapture
//! #   ... the harness prompts for the token; solve it at
//! #   https://auth.riotgames.com/login and paste it in.
//! ```
//!
//! A clean `success:false` with the site's own message (wrong password, captcha
//! demand, two-factor demand) is treated as a *successful* run: it proves the
//! flow — encryption, headers, endpoint, response parsing — works, and the
//! credential was simply not accepted. A transport, parse or structural error
//! fails the test, because that is the recipe being wrong.

use std::io::{BufRead, Write};

use super::*;

fn live_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{name} is not set. Refusing to run a live login without credentials — \
             export it in the environment first."
        ),
    }
}

fn banner(text: &str) {
    println!("\n────────────────── {text} ──────────────────");
}

fn result_was_a_clean_refusal(error: &LoginError) -> bool {
    // These are the site saying "no", not the recipe being broken. A live run
    // that ends here has verified the flow end-to-end.
    matches!(
        error,
        LoginError::Http(m) if m.contains("refused the sign-in")
            || m.contains("Steam refused to issue a login key")
    ) || matches!(error, LoginError::TwoFactorRequired | LoginError::TwoFactorUnusable)
}

/// The real Steam recipe from the registry.
fn steam_recipe() -> &'static LoginRecipe {
    RECIPES
        .iter()
        .find(|recipe| recipe.name == "Steam")
        .expect("the Steam recipe is registered")
}

/// The Riot recipe as it stood when it was registered — kept here, off the
/// registry, so the JSON/captcha machinery stays re-verifiable if Riot ever
/// drops the Cloudflare wall it now sits behind.
fn riot_recipe() -> LoginRecipe {
    let flow = JsonFlow {
        url: "https://authenticate.riotgames.com/api/v1/login".to_string(),
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
            url: "https://authenticate.riotgames.com/api/v1/login".to_string(),
            method: "PUT",
            body: serde_json::json!({
                "type": "multifactor",
                "language": "en_US",
                "multifactor": { "otp": "$VELA_OTP" },
            }),
        }),
    };
    LoginRecipe {
        sites: &["riotgames.com"],
        name: "Riot Games",
        gate: Gate::OptionalCaptcha,
        flow: Flow::Json(flow.clone()),
    }
}

#[tokio::test]
#[ignore = "live verification against the real site (needs VELA_LIVE_STEAM_* credentials)"]
async fn steam() {
    let username = live_env("VELA_LIVE_STEAM_USER");
    let password = live_env("VELA_LIVE_STEAM_PASS");

    // Steam Guard is usually a phone app: a saved authenticator *secret* (from
    // which the code is derived) or, when none is saved, the code the app is
    // showing right now. Neither is required until Steam asks.
    let saved_secret = std::env::var("VELA_LIVE_STEAM_TOTP")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let typed_code = std::env::var("VELA_LIVE_STEAM_CODE")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let totp = match (saved_secret.as_deref(), typed_code.as_deref()) {
        (Some(secret), _) => Some(TotpAnswer::Secret(secret)),
        (None, Some(code)) => Some(TotpAnswer::Code(code)),
        _ => None,
    };

    let recipe = steam_recipe();
    let Flow::Steam(flow) = &recipe.flow else {
        unreachable!("the Steam recipe is a Steam flow")
    };
    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let target = normalize_url("https://store.steampowered.com/").unwrap();

    banner(&format!("Steam live login as {username}"));
    let started = std::time::Instant::now();
    let result = run_steam(
        recipe,
        flow,
        &client,
        &mut jar,
        &username,
        &password,
        totp,
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await;
    println!("  elapsed: {:?}", started.elapsed());

    match result {
        Ok(outcome) => {
            println!("  VERDICT: login completed");
            println!("  looks_authenticated: {}", outcome.looks_authenticated);
            println!("  landing_url: {}", outcome.landing_url);
            println!("  used_second_factor: {}", outcome.used_second_factor);
            println!("  cookies issued: {}", outcome.cookies.len());
            for cookie in &outcome.cookies {
                println!(
                    "    {} = {} (domain {}, {}http_only, {}secure)",
                    cookie.name,
                    cookie.value,
                    cookie.domain,
                    if cookie.http_only { "" } else { "not " },
                    if cookie.secure { "" } else { "not " },
                );
            }
        }
        Err(error) => {
            println!("  VERDICT: {error}");
            // A wrong password, a two-factor demand or a captcha demand proves
            // the mechanics; only a structural failure should fail the test.
            assert!(
                result_was_a_clean_refusal(&error),
                "this is a recipe or transport bug, not a credential refusal"
            );
        }
    }
}

#[tokio::test]
#[ignore = "live verification against the real site (needs VELA_LIVE_RIOT_* credentials + a solved captcha)"]
async fn riot() {
    let username = live_env("VELA_LIVE_RIOT_USER");
    let password = live_env("VELA_LIVE_RIOT_PASS");
    let saved_secret = std::env::var("VELA_LIVE_RIOT_TOTP")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let totp = saved_secret
        .as_deref()
        .map(TotpAnswer::Secret);

    // Riot's captcha is conditional — a normal browser session often gets
    // none. If the page never showed a widget, set VELA_LIVE_RIOT_NO_CAPTCHA=1
    // and the recipe proceeds without a token (the site decides if it wanted
    // one). Otherwise the token must be solved right before submission: it is
    // single-use and short-lived (~2 minutes).
    let no_captcha = std::env::var("VELA_LIVE_RIOT_NO_CAPTCHA")
        .map(|v| v == "1")
        .unwrap_or(false);
    let captcha = match std::env::var("VELA_LIVE_RIOT_CAPTCHA") {
        Ok(token) if !token.trim().is_empty() => Some(token.trim().to_string()),
        _ if no_captcha => None,
        _ => {
            banner("Riot captcha (optional)");
            println!("Open https://auth.riotgames.com/login in a browser.");
            println!("Enter your real credentials on the page and click Sign in.");
            println!("Riot's captcha is INVISIBLE hCaptcha: it auto-solves, so there may");
            println!("be no widget to click — the token is simply written into the page.");
            println!("Grab it from the console:");
            println!("  document.querySelector('[name=\"g-recaptcha-response\"], [name=\"h-captcha-response\"]')?.value");
            println!("Paste it here (or press Enter to proceed without one):");
            print!("token (or Enter)> ");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).unwrap();
            let token = line.trim().to_string();
            if token.is_empty() {
                None
            } else {
                Some(token)
            }
        }
    };
    if no_captcha && captcha.is_none() {
        println!("  proceeding without a captcha token (the site showed no widget)");
    }

    let recipe = riot_recipe();
    let Flow::Json(flow) = &recipe.flow else {
        unreachable!("the Riot recipe is a JSON flow")
    };
    let client = build_client().unwrap();
    let mut jar = CookieJar::default();
    let target = normalize_url("https://auth.riotgames.com/login").unwrap();
    let browser = BrowserArtifacts {
        captcha_token: captcha,
        cookies: vec![],
    };

    banner(&format!("Riot live login as {username}"));
    let started = std::time::Instant::now();
    let result = run_json(
        &recipe,
        flow,
        &client,
        &mut jar,
        &username,
        &password,
        totp,
        Some(&browser),
        &target,
        SiteMode::SelfServe,
        true,
    )
    .await;
    println!("  elapsed: {:?}", started.elapsed());

    match result {
        Ok(outcome) => {
            println!("  VERDICT: login completed");
            println!("  looks_authenticated: {}", outcome.looks_authenticated);
            println!("  used_second_factor: {}", outcome.used_second_factor);
            println!("  awaiting_second_factor: {:?}", outcome.awaiting_second_factor);
            println!("  cookies issued: {}", outcome.cookies.len());
            for cookie in &outcome.cookies {
                println!(
                    "    {} = {} (domain {}, {}http_only, {}secure)",
                    cookie.name,
                    cookie.value,
                    cookie.domain,
                    if cookie.http_only { "" } else { "not " },
                    if cookie.secure { "" } else { "not " },
                );
            }
        }
        Err(error) => {
            println!("  VERDICT: {error}");
            assert!(
                result_was_a_clean_refusal(&error),
                "this is a recipe or transport bug, not a credential refusal"
            );
        }
    }
}
