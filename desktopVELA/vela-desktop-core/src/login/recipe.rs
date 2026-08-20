//! Data-driven per-site login recipes, for sites whose login is not a plain
//! HTML form.
//!
//! This is the Tier A design from `security/in-core-login-future-work.md`: the
//! browser mints whatever the site's own rules demand — a CAPTCHA the human
//! solves on the real page, and the pre-session cookie set — and the core
//! composes the login request with the vault credential and submits it over
//! its own TLS. Only the resulting session returns to the browser.
//!
//! ## Why this exists, and what it is not
//!
//! The measured barrier to in-core login on hard sites is never "run more
//! JavaScript": it is the two things only a browser and a human can do — solve
//! a CAPTCHA and hold a live session. A recipe takes exactly those two things
//! in (from the browser), and nothing else. The password still never enters
//! the page; the [`super::LoginOutcome`] it produces still has no field that
//! can carry a credential. This preserves the M9a shape — credential transits
//! only the core→site private leg — while letting the *browser* supply the
//! presence proof the site demands.
//!
//! The honest limits are stated rather than hidden:
//!  * A CAPTCHA token is single-use and short-lived. The core will not guess
//!    one, and if the human took too long it says so.
//!  * A recipe is a maintained per-site contract. The site can change its API
//!    and the recipe silently stops working until someone updates it.
//!  * The dual-use concern is real and is recorded in the future-work doc; the
//!    artifacts here are lifted from the user's own tab and spent once on the
//!    user's own account, never persisted, never logged.
//!
//! Every recipe re-checks that its endpoint is on the registrable domain the
//! human approved (via [`super::same_site`]), so a recipe cannot become a way
//! to move the password sideways.

use base64::Engine;
use once_cell::sync::Lazy;
use rand_core::OsRng;
use rsa::pkcs1v15::EncryptingKey;
use rsa::traits::RandomizedEncryptor;
use rsa::{BigUint, RsaPublicKey};

use super::*;

/// Markers in a recipe's body template, replaced by the core just before the
/// request goes out. `$VELA_PASSWORD` is the only secret; the CAPTCHA marker
/// is only ever filled from the browser's own page.
const MARKER_USERNAME: &str = "$VELA_USERNAME";
const MARKER_PASSWORD: &str = "$VELA_PASSWORD";
const MARKER_CAPTCHA: &str = "$VELA_CAPTCHA";
const MARKER_OTP: &str = "$VELA_OTP";

/// What the browser has to do before the core may send the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Nothing: the site has no human-in-the-loop gate, or its gate is the
    /// ordinary one the core can satisfy itself.
    None,
    /// A person has to solve the site's hCaptcha widget in the tab before the
    /// login can proceed, and the core refuses rather than guess a token.
    HCaptcha,
    /// The site's captcha is *conditional*: it appears for some sessions and
    /// not others (Riot shows hCaptcha only when it wants one). The recipe
    /// includes the token the browser lifted when there is one, and proceeds
    /// without it when the page never asked — the core still never fabricates
    /// a token, and the site is the one that decides whether it was needed.
    OptionalCaptcha,
}

/// One site's login, keyed by registrable domain.
pub struct LoginRecipe {
    /// Registrable domains (PSL, lower-cased) this recipe claims. Steam's
    /// login lives under both `steampowered.com` and `steamcommunity.com`, and
    /// users store either in the vault.
    pub sites: &'static [&'static str],
    /// Human-readable name, for errors.
    pub name: &'static str,
    /// What a person must do in the browser first.
    pub gate: Gate,
    pub flow: Flow,
}

#[derive(Clone)]
pub enum Flow {
    /// One or two JSON requests, bodies built from a template. The shape of
    /// Riot's login.
    Json(JsonFlow),
    /// A challenge-then-submit flow with client-side cryptography: fetch an
    /// RSA public key, encrypt the password in the core, submit. The shape of
    /// Steam's login.
    Steam(SteamFlow),
}

/// A JSON API login.
#[derive(Clone)]
pub struct JsonFlow {
    /// Absolute URL of the login endpoint.
    pub url: String,
    /// `PUT` or `POST`.
    pub method: &'static str,
    /// JSON body template. String values equal to the `$VELA_*` markers are
    /// replaced with the real values; every other node passes through.
    pub body: serde_json::Value,
    /// How the site answers a second factor, if it has one. The follow-up is
    /// issued when the first response comes back flagged `multifactor`.
    pub mfa: Option<JsonMfa>,
}

#[derive(Clone)]
pub struct JsonMfa {
    pub url: String,
    pub method: &'static str,
    pub body: serde_json::Value,
}

/// Steam's modern Web API login (protobuf over HTTPS).
///
/// Steam retired the classic `login/dologin` form for real accounts; the
/// current protocol is the `IAuthenticationService` Web API, whose requests
/// travel as protobuf in an `input_protobuf_encoded` form field. See
/// [`run_steam`] for the ceremony.
#[derive(Clone)]
pub struct SteamFlow {
    /// Web API base, e.g. `https://api.steampowered.com/`.
    pub api_url: String,
    /// The `finalizelogin` endpoint that turns an authenticated session into
    /// transfer tokens, e.g. `https://login.steampowered.com/jwt/finalizelogin`.
    pub finalize_url: String,
}

static RECIPES: Lazy<Vec<LoginRecipe>> = Lazy::new(|| {
    vec![
    // NOTE: Riot is deliberately not here, and it used to be. Its login moved
    // to `xsso.riotgames.com` behind Cloudflare, which answers an honest
    // non-browser client with a 403 challenge; the recorded `api/v1/login`
    // shape is stale and gets `invalid_request`. The JSON/captcha machinery
    // below is still the template for a future CAPTCHA-gated site — the Riot
    // recipe is documented in the live harness and the future-work doc as the
    // example of a recipe the site outgrew.
    // Steam. No bot defence in the ordinary case, but the classic
    // `login/dologin` form no longer accepts real accounts — the current
    // protocol is the `IAuthenticationService` Web API (protobuf wire format),
    // including Steam Guard via either a device code or an in-app approval.
    // The client-side RSA is still done in the core in Rust, so the password
    // never has to enter a JavaScript runtime to be encrypted — design choice
    // #1 from the future-work doc survives.
    //
    // Steam's login legitimately crosses registrable domains (the login page
    // is under `steampowered.com`, the finalize hop under `steamcommunity.com`),
    // so endpoint checks are against this recipe's claimed domains rather than
    // the login target — see [`endpoint_claimed`].
    LoginRecipe {
        sites: &["steampowered.com", "steamcommunity.com"],
        name: "Steam",
        gate: Gate::None,
        flow: Flow::Steam(SteamFlow {
            api_url: "https://api.steampowered.com/".to_string(),
            finalize_url: "https://login.steampowered.com/jwt/finalizelogin".to_string(),
        }),
    },
    ]
});

/// Find the recipe claiming a registrable domain, if any.
pub fn for_site(site: &str) -> Option<&'static LoginRecipe> {
    RECIPES
        .iter()
        .find(|recipe| recipe.sites.iter().any(|candidate| *candidate == site))
}

/// Find the recipe for a login target URL.
pub fn for_url(url: &Url) -> Option<&'static LoginRecipe> {
    let site = site_key(url);
    if site.is_empty() {
        return None;
    }
    for_site(&site)
}

/// Is a request URL on a domain this recipe explicitly claims?
///
/// This is the recipe's substitute for the form path's `same_site` check, and
/// it is stricter in the way that matters: the credential may be sent only to
/// a host whose registrable domain the recipe declares up front. It is *not*
/// "same site as the login page", because Steam's login genuinely crosses
/// registrable domains (`store.steampowered.com` → `steamcommunity.com`) and a
/// check against the target would refuse the user's own login. The recipe —
/// static, audited data — is the authority on where the credential goes.
fn endpoint_claimed(recipe: &LoginRecipe, url: &Url) -> bool {
    let site = site_key(url);
    recipe.sites.iter().any(|claimed| *claimed == site)
}

/// What kind of login a site uses, for the caller to render and to know
/// whether a browser artifact must be minted first.
///
/// `"form"` is the default: no recipe, the ordinary page-fetch path. `"recipe"`
/// is a recipe with no human gate. `"recipe_captcha"` is a recipe the browser
/// has to sit through a CAPTCHA for before the core can act.
pub fn mode_for_site(site: Option<String>) -> &'static str {
    let Some(site) = site else {
        return "form";
    };
    let Some(recipe) = for_site(&site) else {
        return "form";
    };
    match recipe.gate {
        Gate::None => "recipe",
        Gate::HCaptcha | Gate::OptionalCaptcha => "recipe_captcha",
    }
}

/// How a site's second factor is answered.
///
/// A vault item usually carries the authenticator *secret*, from which the
/// core derives the code. Some users have no secret saved — Steam Guard on a
/// phone app, for example — and type the code the app shows instead; that is
/// a legitimate second path, surfaced here rather than hidden behind a fake
/// secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TotpAnswer<'a> {
    /// Derive the code from the vault's authenticator secret.
    Secret(&'a str),
    /// Use a code the human typed in from the site's own app.
    Code(&'a str),
}

impl TotpAnswer<'_> {
    fn code(self) -> Result<String, LoginError> {
        match self {
            Self::Secret(secret) => crate::totp::generate_totp_code(secret)
                .ok_or(LoginError::TwoFactorUnusable),
            Self::Code(code) => Ok(code.to_string()),
        }
    }
}

/// Run a recipe login, returning only the session.
pub(crate) async fn perform(
    username: &str,
    password: &str,
    totp_secret: Option<&str>,
    grant: &LoginGrant,
    target: &Url,
    recipe: &'static LoginRecipe,
    browser: Option<&BrowserArtifacts>,
    site_mode: SiteMode,
) -> Result<LoginOutcome, LoginError> {
    let client = build_client()?;
    let mut jar = CookieJar::default();
    // The browser's pre-session state first, so every request the recipe makes
    // carries the same cookie context the page has.
    if let Some(artifacts) = browser {
        jar.seed_browser(&artifacts.cookies, target);
    }

    let totp = totp_secret.map(TotpAnswer::Secret);
    match &recipe.flow {
        Flow::Json(flow) => {
            run_json(
                recipe,
                flow,
                &client,
                &mut jar,
                username,
                password,
                totp,
                browser,
                target,
                site_mode,
                grant.is_verified(),
            )
            .await
        }
        Flow::Steam(flow) => {
            run_steam(
                recipe,
                flow,
                &client,
                &mut jar,
                username,
                password,
                totp,
                target,
                site_mode,
                grant.is_verified(),
            )
            .await
        }
    }
}

// ── JSON API logins (Riot) ────────────────────────────────────────────────────

async fn run_json(
    recipe: &LoginRecipe,
    flow: &JsonFlow,
    client: &reqwest::Client,
    jar: &mut CookieJar,
    username: &str,
    password: &str,
    totp: Option<TotpAnswer<'_>>,
    browser: Option<&BrowserArtifacts>,
    target: &Url,
    site_mode: SiteMode,
    user_verified: bool,
) -> Result<LoginOutcome, LoginError> {
    let endpoint = normalize_url(&flow.url)
        .ok_or_else(|| LoginError::Http("the site recipe has a bad endpoint URL".to_string()))?;
    if !endpoint_claimed(recipe, &endpoint) {
        return Err(LoginError::CrossSiteRedirect(site_key(&endpoint)));
    }

    // The gate decides what the browser had to mint. For a mandatory captcha,
    // a missing token is a refusal before anything is sent — the token is
    // single-use and short-lived, a stale one is refused by the site, and a
    // guessed one would be an attack on the user's own account. For an
    // optional one, the site showed no widget, so the login proceeds without.
    let captcha = match recipe.gate {
        Gate::None => None,
        Gate::HCaptcha | Gate::OptionalCaptcha => browser
            .and_then(|b| b.captcha_token.as_deref())
            .filter(|token| !token.trim().is_empty())
            .map(str::to_string),
    };
    if recipe.gate == Gate::HCaptcha && captcha.is_none() {
        return Err(LoginError::NeedsBrowserArtifact(format!(
            "{} only signs in after you solve its captcha in the browser tab.",
            recipe.name
        )));
    }

    let body = fill_json(&flow.body, username, password, captcha.as_deref(), None)
        .map_err(|m| LoginError::UnsupportedForm(format!("the {} recipe body: {m}", recipe.name)))?;
    let mut response = send_json(client, jar, &endpoint, flow.method, &body).await?;
    let mut cookies_from_login = !response.set_cookie.is_empty();

    // The site answered "give me a code", which is what Riot does for an
    // account with a second factor. Same grant, same approval: the human said
    // "sign in to this site", and this is still that.
    let mut used_second_factor = false;
    let mut still_asking = false;
    if json_kind(&response.body).as_deref() == Some("multifactor") {
        let Some(mfa) = &flow.mfa else {
            return Err(LoginError::TwoFactorRequired);
        };
        let Some(totp) = totp else {
            return Err(LoginError::TwoFactorRequired);
        };
        let code = totp.code()?;

        let mfa_endpoint = normalize_url(&mfa.url)
            .ok_or_else(|| LoginError::Http("the site recipe has a bad MFA endpoint URL".to_string()))?;
        if !endpoint_claimed(recipe, &mfa_endpoint) {
            return Err(LoginError::CrossSiteRedirect(site_key(&mfa_endpoint)));
        }
        let mfa_body = fill_json(&mfa.body, username, password, None, Some(&code))
            .map_err(|m| LoginError::UnsupportedForm(format!("the {} MFA body: {m}", recipe.name)))?;
        response = send_json(client, jar, &mfa_endpoint, mfa.method, &mfa_body).await?;
        cookies_from_login |= !response.set_cookie.is_empty();
        used_second_factor = true;
        // A response still flagged `multifactor` is a wrong or stale code, and
        // reads the way a returned login form does: the site is still asking.
        still_asking = json_kind(&response.body).as_deref() == Some("multifactor");
    }

    // An HTTP >= 400 may still carry the site's own words about why — Riot
    // answers an invalid captcha with 400 + `{"error":"invalid_request"}`. Say
    // that rather than the generic "would not serve the sign-in page", which
    // reads like a bot-check when the real reason is a stale token.
    if response.status >= 400 {
        let (_kind, error) = json_kind_and_error(&response.body);
        if let Some(why) = error {
            return Err(LoginError::Http(format!(
                "{} refused the sign-in: {why}",
                recipe.name
            )));
        }
        return Err(LoginError::SiteRefused {
            status: response.status,
        });
    }
    let (_kind, error) = json_kind_and_error(&response.body);
    if let Some(why) = error {
        return Err(LoginError::Http(format!("{} refused the sign-in: {why}", recipe.name)));
    }

    let cookies = jar.snapshot();
    if cookies.is_empty() {
        warn!("In-core login to {} produced no cookies", site_key(target));
    }

    // Land the browser back where it started rather than on the API endpoint:
    // a JSON-recipe site (Riot) continues its own session handoff from the
    // page, and reloading the login page after a successful API login is where
    // that handoff picks up.
    Ok(LoginOutcome {
        landing_url: target.to_string(),
        cookies,
        looks_authenticated: LoginOutcome::infer(
            cookies_from_login,
            still_asking,
            response.status,
            None,
        ),
        site_mode,
        residual_note: site_mode.residual_note().to_string(),
        user_verified,
        used_second_factor,
        awaiting_second_factor: if still_asking {
            Some("a code the site did not accept".to_string())
        } else {
            None
        },
        second_factor_downgraded: false,
        used_browser: false,
        local_session: std::collections::BTreeMap::new(),
        cached_db: std::collections::BTreeMap::new(),
    })
}

// ── Steam's modern Web API login ──────────────────────────────────────────────

/// EResult codes Steam answers the Web API with.
mod eresult {
    pub const OK: u64 = 1;
    pub const INVALID_PASSWORD: u64 = 5;
    pub const ACCESS_DENIED: u64 = 9;
    pub const RATE_LIMIT: u64 = 29;
    pub const TWO_FACTOR_CODE_MISMATCH: u64 = 50;
    pub const NOT_LOGGED_ON: u64 = 81;
}

/// The `EAuthSessionGuardType` values Steam's `allowed_confirmations` can carry.
mod guard_type {
    pub const NONE: u64 = 0;
    pub const EMAIL_CODE: u64 = 1;
    pub const DEVICE_CODE: u64 = 2;
    pub const DEVICE_CONFIRMATION: u64 = 3;
    pub const EMAIL_CONFIRMATION: u64 = 4;
}

/// The `EAuthTokenPlatformType` value for a web login.
const PLATFORM_WEB: u64 = 2;

/// How long to keep polling Steam while waiting on a human (a device
/// confirmation can sit on the phone for a while before it is approved).
const STEAM_POLL_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

async fn run_steam(
    recipe: &LoginRecipe,
    flow: &SteamFlow,
    client: &reqwest::Client,
    jar: &mut CookieJar,
    username: &str,
    password: &str,
    totp: Option<TotpAnswer<'_>>,
    target: &Url,
    site_mode: SiteMode,
    user_verified: bool,
) -> Result<LoginOutcome, LoginError> {
    let api = normalize_url(&flow.api_url)
        .ok_or_else(|| LoginError::Http("the Steam recipe has a bad Web API URL".to_string()))?;
    let finalize = normalize_url(&flow.finalize_url).ok_or_else(|| {
        LoginError::Http("the Steam recipe has a bad finalize URL".to_string())
    })?;
    if !endpoint_claimed(recipe, &api) || !endpoint_claimed(recipe, &finalize) {
        let offender = if endpoint_claimed(recipe, &api) {
            site_key(&finalize)
        } else {
            site_key(&api)
        };
        return Err(LoginError::CrossSiteRedirect(offender));
    }

    // 1. The per-request RSA public key. This is the same `getrsakey` shape,
    //    served by the Web API as plain JSON.
    let mut key_url = api
        .join("IAuthenticationService/GetPasswordRSAPublicKey/v1/")
        .map_err(|e| LoginError::Http(format!("bad Steam Web API URL: {e}")))?;
    key_url.query_pairs_mut().append_pair("account_name", username);
    let (key_status, key_json) = steam_json_get(client, jar, &key_url).await?;
    if key_status >= 400 {
        return Err(LoginError::SiteRefused {
            status: key_status,
        });
    }
    let key: SteamRsaKey = serde_json::from_value(
        key_json.get("response").cloned().unwrap_or(key_json),
    )
    .map_err(|e| {
        LoginError::Http(format!("Steam's key response was not the expected JSON: {e}"))
    })?;

    // 2. Encrypt the password in the core. This is the whole point of the
    //    recipe: Steam's client-side RSA is done here, in Rust, so the
    //    plaintext never has to enter a JavaScript runtime to be encrypted.
    let encrypted = rsa_encrypt_pkcs1v15(password, &key.publickey_mod, &key.publickey_exp)
        .map_err(LoginError::Http)?;

    // 3. Begin the auth session. The Web API reads this as protobuf in an
    //    `input_protobuf_encoded` form field; the password travels as base64 of
    //    the RSA ciphertext (not hex — the modern protocol switched encodings).
    let mut begin = steam_pb::Writer::default();
    begin.string(2, username);
    begin.string(3, &encrypted);
    begin.u64(4, key.timestamp.parse::<u64>().unwrap_or(0));
    begin.bool(5, true); // remember_login
    begin.u64(7, 2); // persistence = Persistent
    begin.string(8, "Community");
    let mut device = steam_pb::Writer::default();
    device.string(1, USER_AGENT_STEAM);
    device.u64(2, PLATFORM_WEB);
    begin.message(9, &device.finish());
    let (eresult, fields) = steam_webapi(client, jar, &api, "BeginAuthSessionViaCredentials", None, &begin.finish()).await?;
    if eresult != eresult::OK {
        return Err(steam_eresult_error(eresult));
    }
    let begin_msg = SteamBeginSession::parse(&fields);
    let Some(client_id) = begin_msg.client_id else {
        return Err(LoginError::Http(
            "Steam began the session without a client id".to_string(),
        ));
    };
    let Some(request_id) = begin_msg.request_id.clone() else {
        return Err(LoginError::Http(
            "Steam began the session without a request id".to_string(),
        ));
    };
    let Some(steam_id) = begin_msg.steam_id else {
        return Err(LoginError::Http(
            "Steam began the session without an account id".to_string(),
        ));
    };
    let weak_token = begin_msg.weak_token.clone();
    let poll_interval = begin_msg.interval.max(1);

    // 4. Answer the guard Steam asks for.
    let mut used_second_factor = false;
    match begin_msg.first_confirmation() {
        guard_type::NONE => {}
        guard_type::DEVICE_CODE => {
            // A rotating code from the Steam Guard phone app.
            let Some(totp) = totp else {
                return Err(LoginError::TwoFactorRequired);
            };
            let code = totp.code()?;
            used_second_factor = true;
            let mut update = steam_pb::Writer::default();
            update.u64(1, client_id);
            update.u64(2, steam_id);
            update.string(3, &code);
            update.u64(4, guard_type::DEVICE_CODE);
            let (eresult, _) = steam_webapi(
                client,
                jar,
                &api,
                "UpdateAuthSessionWithSteamGuardCode",
                weak_token.as_deref(),
                &update.finish(),
            )
            .await?;
            if eresult != eresult::OK {
                return Err(steam_eresult_error(eresult));
            }
        }
        guard_type::DEVICE_CONFIRMATION => {
            // The human approves the login on their phone. Nothing to send;
            // we poll until Steam says it is done.
            warn!(
                "Steam login for {username} waits on an approval in the Steam mobile app"
            );
        }
        _ => {
            // An e-mailed code or an e-mailed confirmation link: nothing a
            // vault can produce.
            return Err(LoginError::TwoFactorRequired);
        }
    }

    // 5. Poll until Steam reports the session authenticated (the human
    //    approved it, or the code was accepted).
    let started = std::time::Instant::now();
    let mut poll = steam_pb::Writer::default();
    poll.u64(1, client_id);
    poll.bytes(2, &request_id);
    let poll_pb = poll.finish();
    let refresh_token = loop {
        if started.elapsed() > STEAM_POLL_BUDGET {
            return Err(LoginError::Http(format!(
                "Steam did not finish the sign-in within {} seconds; \
                 check the approval in the Steam app and try again",
                STEAM_POLL_BUDGET.as_secs()
            )));
        }
        let (eresult, fields) = steam_webapi(
            client,
            jar,
            &api,
            "PollAuthSessionStatus",
            weak_token.as_deref(),
            &poll_pb,
        )
        .await?;
        if eresult != eresult::OK && eresult != eresult::NOT_LOGGED_ON {
            return Err(steam_eresult_error(eresult));
        }
        let status = SteamPollStatus::parse(&fields);
        if let Some(token) = status.refresh_token {
            break token;
        }
        tokio::time::sleep(std::time::Duration::from_secs(poll_interval)).await;
    };

    // 6. finalizelogin turns the refresh token into per-sub-service transfer
    //    tokens, which we POST back to mint the session cookies.
    let session_id = format!(
        "{:x}",
        uuid::Uuid::new_v4().simple()
    );
    let mut login_host = finalize.clone();
    login_host.set_path("/");
    jar.seed_browser(
        &[BrowserCookie {
            name: "sessionid".to_string(),
            value: session_id.clone(),
            domain: login_host.host_str().unwrap_or_default().to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: true,
            same_site: None,
            expires_at: None,
            host_only: true,
        }],
        &login_host,
    );

    let mut finalize_body = BTreeMap::new();
    finalize_body.insert("nonce".to_string(), refresh_token.clone());
    finalize_body.insert("sessionid".to_string(), session_id.clone());
    finalize_body.insert(
        "redir".to_string(),
        "https://steamcommunity.com/login/home/?goto=".to_string(),
    );
    let finalize_response = steam_post_form(client, jar, &finalize, &finalize_body).await?;
    if finalize_response.status >= 400 {
        return Err(LoginError::SiteRefused {
            status: finalize_response.status,
        });
    }
    let transfer_info: Vec<SteamTransfer> = finalize_response
        .json
        .get("transfer_info")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // 7. Complete each sub-service transfer, scoped to Steam's own domains.
    for transfer in &transfer_info {
        complete_steam_transfer(recipe, client, jar, transfer, steam_id).await;
    }

    let cookies = jar.snapshot();
    if cookies.is_empty() {
        warn!("Steam login produced no cookies");
    }

    Ok(LoginOutcome {
        landing_url: target.to_string(),
        cookies,
        looks_authenticated: true,
        site_mode,
        residual_note: site_mode.residual_note().to_string(),
        user_verified,
        used_second_factor,
        awaiting_second_factor: None,
        second_factor_downgraded: false,
        used_browser: false,
        local_session: std::collections::BTreeMap::new(),
        cached_db: std::collections::BTreeMap::new(),
    })
}

/// The Web API's RSA key answer (same shape as the classic `getrsakey`).
#[derive(serde::Deserialize)]
struct SteamRsaKey {
    #[serde(rename = "publickey_mod")]
    publickey_mod: String,
    #[serde(rename = "publickey_exp")]
    publickey_exp: String,
    timestamp: String,
}

/// A parsed `BeginAuthSessionViaCredentials` response.
struct SteamBeginSession {
    client_id: Option<u64>,
    request_id: Option<Vec<u8>>,
    interval: u64,
    steam_id: Option<u64>,
    weak_token: Option<String>,
    confirmations: Vec<u64>,
}

impl SteamBeginSession {
    fn parse(fields: &[steam_pb::Field]) -> Self {
        let mut out = Self {
            client_id: None,
            request_id: None,
            interval: 1,
            steam_id: None,
            weak_token: None,
            confirmations: Vec::new(),
        };
        for field in fields {
            match (field.number, field.wire_type) {
                (1, 0) => out.client_id = field.varint(),
                (2, 2) => out.request_id = field.bytes(),
                (3, 0) => {
                    // interval as a varint.
                    out.interval = field.varint().unwrap_or(1).max(1);
                }
                (3, 5) => {
                    // Steam actually encodes the poll interval as a float32 in
                    // fixed32 wire type — 5.0 seconds showed up in a real
                    // response as bytes `00 00 a0 40`.
                    if let steam_pb::Value::Fixed32(bits) = &field.value {
                        out.interval = (f32::from_bits(*bits) as u64).max(1);
                    }
                }
                (4, 2) => {
                    // repeated AllowedConfirmation { confirmation_type(1) }
                    if let Some(raw) = field.bytes() {
                        for inner in steam_pb::parse(&raw) {
                            if inner.number == 1 && inner.wire_type == 0 {
                                if let Some(t) = inner.varint() {
                                    out.confirmations.push(t);
                                }
                            }
                        }
                    }
                }
                (5, 0) => out.steam_id = field.varint(),
                (6, 2) => out.weak_token = field.bytes().map(|b| String::from_utf8_lossy(&b).into_owned()),
                _ => {}
            }
        }
        out
    }

    fn first_confirmation(&self) -> u64 {
        self.confirmations.first().copied().unwrap_or(guard_type::NONE)
    }
}

/// A parsed `PollAuthSessionStatus` response.
struct SteamPollStatus {
    refresh_token: Option<String>,
}

impl SteamPollStatus {
    fn parse(fields: &[steam_pb::Field]) -> Self {
        let mut refresh_token = None;
        for field in fields {
            if field.number == 3 && field.wire_type == 2 {
                if let Some(bytes) = field.bytes() {
                    refresh_token = Some(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
        }
        Self { refresh_token }
    }
}

/// Map a Steam EResult to the honest login error.
fn steam_eresult_error(eresult: u64) -> LoginError {
    match eresult {
        eresult::INVALID_PASSWORD => LoginError::Http(
            "Steam refused the sign-in: The account name or password that you have entered \
             is incorrect."
                .to_string(),
        ),
        eresult::TWO_FACTOR_CODE_MISMATCH => LoginError::Http(
            "Steam refused the sign-in: the authentication code was not accepted".to_string(),
        ),
        eresult::RATE_LIMIT => LoginError::Http(
            "Steam is rate-limiting login attempts right now; wait a little and try again"
                .to_string(),
        ),
        eresult::ACCESS_DENIED | eresult::NOT_LOGGED_ON => {
            LoginError::Http("Steam refused the sign-in".to_string())
        }
        other => LoginError::Http(format!("Steam refused the sign-in (error {other})")),
    }
}

/// One sub-service session Steam asks the client to complete.
#[derive(serde::Deserialize)]
struct SteamTransfer {
    url: String,
    #[serde(default)]
    params: BTreeMap<String, String>,
}

/// POST a Steam session-transfer back to its sub-service, absorbing the
/// cookies it sets.
///
/// The transfer URL comes from Steam's own server, but it is still scoped to
/// the recipe's claimed domains before anything is sent: a transfer to a host
/// outside Steam's own perimeter is dropped rather than followed.
async fn complete_steam_transfer(
    recipe: &LoginRecipe,
    client: &reqwest::Client,
    jar: &mut CookieJar,
    transfer: &SteamTransfer,
    steam_id: u64,
) {
    let Some(url) = normalize_url(&transfer.url) else {
        warn!("Steam returned an unparseable transfer URL; skipping it");
        return;
    };
    if !endpoint_claimed(recipe, &url) {
        warn!(
            "Steam asked for a session transfer to {} which its recipe does not claim; skipping",
            site_key(&url)
        );
        return;
    }
    let mut body = BTreeMap::new();
    body.insert("steamID".to_string(), steam_id.to_string());
    body.extend(transfer.params.iter().map(|(k, v)| (k.clone(), v.clone())));
    match steam_post_form(client, jar, &url, &body).await {
        Ok(_) => {}
        Err(error) => warn!(
            "Could not complete a Steam session transfer to {}: {error}",
            site_key(&url)
        ),
    }
}

/// What we tell sites we are, for the Steam Web API's device description.
const USER_AGENT_STEAM: &str = concat!(
    "VELA/",
    env!("CARGO_PKG_VERSION"),
    " (password manager; signing in on behalf of the account owner)"
);

/// Encrypt `password` with Steam's public key, PKCS#1 v1.5, base64-encoded.
///
/// Steam hands out a fresh modulus/exponent per request and expects the
/// password encrypted with them; the modern Web API takes the ciphertext as
/// base64 (the classic form took hex). Done with the audited `rsa` crate —
/// this is not hand-rolled big-number code — and the random padding is
/// sourced from `OsRng`.
///
/// The `rsa` 0.9 line carries RUSTSEC-2023-0071 (the "Marvin Attack", a timing
/// side-channel in PKCS#1 v1.5 *decryption*). It is accepted for this call
/// site deliberately: the private key never exists in this process, so the
/// decryption oracle the advisory describes is not reachable — only the
/// public-key encryption path is used. See the entry in
/// `security/deny.toml`.
fn rsa_encrypt_pkcs1v15(password: &str, modulus_hex: &str, exponent_hex: &str) -> Result<String, String> {
    let modulus = BigUint::parse_bytes(modulus_hex.trim().as_bytes(), 16)
        .ok_or_else(|| "Steam sent an RSA modulus that was not hex".to_string())?;
    let exponent = BigUint::parse_bytes(exponent_hex.trim().as_bytes(), 16)
        .ok_or_else(|| "Steam sent an RSA exponent that was not hex".to_string())?;
    let public = RsaPublicKey::new(modulus, exponent)
        .map_err(|e| format!("Steam's RSA key was unusable: {e}"))?;
    let encrypting = EncryptingKey::new(public);
    let encrypted = encrypting
        .encrypt_with_rng(&mut OsRng, password.as_bytes())
        .map_err(|e| format!("could not encrypt the password: {e}"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
}

// ── The Steam Web API transport ───────────────────────────────────────────────

/// `GET` a Web API method that answers JSON (the RSA key fetch).
async fn steam_json_get(
    client: &reqwest::Client,
    jar: &CookieJar,
    url: &Url,
) -> Result<(u16, serde_json::Value), LoginError> {
    let mut builder = client.get(url.clone());
    if let Some(header) = jar.header_for(url) {
        builder = builder.header(reqwest::header::COOKIE, header);
    }
    let response = builder
        .send()
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let json = serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({}));
    Ok((status, json))
}

/// `POST` a Web API method whose request body is protobuf, returning the
/// `x-eresult` header and the parsed response fields.
///
/// The Web API reads the protobuf from an `input_protobuf_encoded` form field
/// (base64), and answers with either a protobuf body or an empty one plus the
/// `x-eresult` header. The `access_token` is required by the authenticated
/// methods (polling, guard updates) and comes from the session's `weak_token`.
async fn steam_webapi(
    client: &reqwest::Client,
    jar: &mut CookieJar,
    api: &Url,
    method: &str,
    access_token: Option<&str>,
    request_pb: &[u8],
) -> Result<(u64, Vec<steam_pb::Field>), LoginError> {
    let mut url = api.join(&format!("IAuthenticationService/{method}/v1/")).map_err(|e| {
        LoginError::Http(format!("bad Steam Web API URL: {e}"))
    })?;
    if let Some(token) = access_token {
        url.query_pairs_mut().append_pair("access_token", token);
    }

    let mut body = BTreeMap::new();
    body.insert(
        "input_protobuf_encoded".to_string(),
        base64::engine::general_purpose::STANDARD.encode(request_pb),
    );
    let response = steam_post_form(client, jar, &url, &body).await?;
    if response.status >= 400 {
        return Err(LoginError::SiteRefused {
            status: response.status,
        });
    }
    let eresult = response
        .eresult
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(eresult::OK);
    Ok((eresult, response.fields))
}

/// `POST` a form body, keeping the raw bytes and the `x-eresult` header.
async fn steam_post_form(
    client: &reqwest::Client,
    jar: &mut CookieJar,
    url: &Url,
    form: &BTreeMap<String, String>,
) -> Result<SteamRawResponse, LoginError> {
    let mut builder = client.post(url.clone());
    if let Some(header) = jar.header_for(url) {
        builder = builder.header(reqwest::header::COOKIE, header);
    }
    builder = builder.form(form);

    let response = builder
        .send()
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;

    let status = response.status().as_u16();
    let eresult = response
        .headers()
        .get("x-eresult")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let set_cookie: Vec<String> = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    jar.absorb(&set_cookie, url);

    let bytes = response.bytes().await.unwrap_or_default();
    let json = serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}));
    let fields = steam_pb::parse(&bytes);

    Ok(SteamRawResponse {
        status,
        eresult,
        json,
        fields,
    })
}

struct SteamRawResponse {
    status: u16,
    eresult: Option<String>,
    json: serde_json::Value,
    fields: Vec<steam_pb::Field>,
}

/// A bare-bones protobuf wire-format encoder/decoder, just big enough for the
/// handful of `CAuthentication_*` messages Steam's login uses.
///
/// Deliberately tiny and explicit: only varint, fixed32/fixed64 and
/// length-delimited wire types, no reflection, no generated code. Field
/// numbers are the ones Steam publishes in `steammessages_auth.proto`, pinned
/// by unit tests against known byte sequences.
mod steam_pb {
    /// A parsed protobuf field.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Field {
        pub number: u64,
        pub wire_type: u8,
        pub value: Value,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        Varint(u64),
        Fixed32(u32),
        Fixed64(u64),
        Bytes(Vec<u8>),
    }

    impl Field {
        pub fn varint(&self) -> Option<u64> {
            match &self.value {
                Value::Varint(v) => Some(*v),
                _ => None,
            }
        }

        pub fn bytes(&self) -> Option<Vec<u8>> {
            match &self.value {
                Value::Bytes(v) => Some(v.clone()),
                _ => None,
            }
        }
    }

    /// A minimal encoder.
    #[derive(Default)]
    pub struct Writer {
        buf: Vec<u8>,
    }

    impl Writer {
        fn tag(&mut self, field: u64, wire: u8) {
            self.uvarint((field << 3) | (wire as u64));
        }

        fn uvarint(&mut self, mut n: u64) {
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    self.buf.push(byte);
                    break;
                }
                self.buf.push(byte | 0x80);
            }
        }

        pub fn u64(&mut self, field: u64, value: u64) {
            self.tag(field, 0);
            self.uvarint(value);
        }

        pub fn bool(&mut self, field: u64, value: bool) {
            self.u64(field, u64::from(value));
        }

        pub fn string(&mut self, field: u64, value: &str) {
            self.bytes(field, value.as_bytes());
        }

        pub fn bytes(&mut self, field: u64, value: &[u8]) {
            self.tag(field, 2);
            self.uvarint(value.len() as u64);
            self.buf.extend_from_slice(value);
        }

        pub fn message(&mut self, field: u64, value: &[u8]) {
            self.bytes(field, value);
        }

        pub fn finish(self) -> Vec<u8> {
            self.buf
        }
    }

    /// Parse a buffer into fields. Malformed input yields whatever parses and
    /// stops; the callers read what they need and ignore the rest.
    pub fn parse(buf: &[u8]) -> Vec<Field> {
        let mut fields = Vec::new();
        let mut pos = 0usize;
        while pos < buf.len() {
            let Some(tag) = read_uvarint(buf, &mut pos) else {
                break;
            };
            let number = tag >> 3;
            let wire = (tag & 7) as u8;
            let value = match wire {
                0 => match read_uvarint(buf, &mut pos) {
                    Some(v) => Value::Varint(v),
                    None => break,
                },
                1 => {
                    if pos + 8 > buf.len() {
                        break;
                    }
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&buf[pos..pos + 8]);
                    pos += 8;
                    Value::Fixed64(u64::from_le_bytes(bytes))
                }
                2 => {
                    let Some(len) = read_uvarint(buf, &mut pos) else {
                        break;
                    };
                    let len = len as usize;
                    if pos + len > buf.len() {
                        break;
                    }
                    let bytes = buf[pos..pos + len].to_vec();
                    pos += len;
                    Value::Bytes(bytes)
                }
                5 => {
                    if pos + 4 > buf.len() {
                        break;
                    }
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(&buf[pos..pos + 4]);
                    pos += 4;
                    Value::Fixed32(u32::from_le_bytes(bytes))
                }
                _ => break,
            };
            fields.push(Field {
                number,
                wire_type: wire,
                value,
            });
        }
        fields
    }

    fn read_uvarint(buf: &[u8], pos: &mut usize) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *buf.get(*pos)?;
            *pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips_our_own_encodings() {
            let mut writer = Writer::default();
            writer.u64(1, 123);
            writer.string(2, "abc");
            writer.bool(5, true);
            writer.bytes(3, &[1, 2, 3]);
            let fields = parse(&writer.finish());
            assert_eq!(fields.len(), 4);
            assert_eq!(fields[0].number, 1);
            assert_eq!(fields[0].varint(), Some(123));
            assert_eq!(fields[1].number, 2);
            assert_eq!(fields[1].bytes(), Some(b"abc".to_vec()));
            assert_eq!(fields[2].number, 5);
            assert_eq!(fields[2].varint(), Some(1));
            assert_eq!(fields[3].number, 3);
            assert_eq!(fields[3].bytes(), Some(vec![1, 2, 3]));
        }

        #[test]
        fn parses_a_real_steam_response() {
            // The bytes Steam's Web API actually returned for a failed
            // BeginAuthSessionViaCredentials: field 3 (fixed32) and an empty
            // field 8 (string).
            let fields = parse(&[0x1d, 0x00, 0x00, 0xa0, 0x40, 0x42, 0x00]);
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].number, 3);
            assert!(matches!(fields[0].value, Value::Fixed32(v) if v == 0x40a0_0000));
            assert_eq!(fields[1].number, 8);
            assert_eq!(fields[1].bytes(), Some(vec![]));
        }
    }
}

// ── Body templates and response interpretation ────────────────────────────────

/// Deep-replace the `$VELA_*` markers in a JSON body template.
///
/// Returns an error if any marker survives: a body still carrying `$VELA_`
/// would go out with a placeholder where a real value belongs, which for the
/// password marker is the same failure the JS runtime's substitution refuses.
fn fill_json(
    template: &serde_json::Value,
    username: &str,
    password: &str,
    captcha: Option<&str>,
    otp: Option<&str>,
) -> Result<serde_json::Value, String> {
    fn walk(
        node: &mut serde_json::Value,
        username: &str,
        password: &str,
        captcha: Option<&str>,
        otp: Option<&str>,
    ) {
        match node {
            serde_json::Value::String(s) => {
                let replacement = if s == MARKER_USERNAME {
                    Some(username.to_string())
                } else if s == MARKER_PASSWORD {
                    Some(password.to_string())
                } else if s == MARKER_CAPTCHA {
                    // Optional: the browser may not have minted a token (the
                    // site showed no widget), in which case the field goes out
                    // empty and the site decides whether it needed one.
                    Some(captcha.unwrap_or("").to_string())
                } else if s == MARKER_OTP {
                    Some(otp.unwrap_or("").to_string())
                } else {
                    None
                };
                if let Some(value) = replacement {
                    *s = value;
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, username, password, captcha, otp);
                }
            }
            serde_json::Value::Object(map) => {
                for value in map.values_mut() {
                    walk(value, username, password, captcha, otp);
                }
            }
            _ => {}
        }
    }

    let mut value = template.clone();
    walk(&mut value, username, password, captcha, otp);

    let serialized = serde_json::to_string(&value).map_err(|e| e.to_string())?;
    for marker in [MARKER_USERNAME, MARKER_PASSWORD, MARKER_CAPTCHA, MARKER_OTP] {
        if serialized.contains(marker) {
            return Err(format!("the marker {marker} survived into the request body"));
        }
    }
    Ok(value)
}

/// The `type` field of a JSON answer, if it is JSON and has one.
fn json_kind(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
}

/// The `type` and `error` fields of a JSON answer.
///
/// An `error` node that is null, false, empty or absent is not an error; a
/// real error is surfaced to the user with the site's own wording.
fn json_kind_and_error(body: &str) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return (None, None);
    };
    let kind = value
        .get("type")
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let error = value.get("error").and_then(|error| match error {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(false) => None,
        serde_json::Value::String(s) if s.is_empty() => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) if map.is_empty() => None,
        other => Some(other.to_string()),
    });
    (kind, error)
}

/// Send one JSON request with the browser cookie context.
async fn send_json(
    client: &reqwest::Client,
    jar: &mut CookieJar,
    url: &Url,
    method: &str,
    body: &serde_json::Value,
) -> Result<Fetched, LoginError> {
    let serialized = serde_json::to_string(body)
        .map_err(|e| LoginError::Http(format!("could not build the request body: {e}")))?;
    let request = crate::js_login::CapturedRequest {
        url: url.to_string(),
        method: method.to_string(),
        headers: [("Content-Type".to_string(), "application/json".to_string())]
            .into_iter()
            .collect(),
        body: serialized,
    };
    let response = fetch_raw(client, jar, &request, url).await?;
    jar.absorb(&response.set_cookie, url);
    Ok(response)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod live;
