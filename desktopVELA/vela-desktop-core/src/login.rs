//! In-core login: the desktop submits the password, the browser gets a session.
//!
//! This is the M9a tier of the release ladder
//! (`security/formal/m9a_in_core_login.spthy`), and it exists for the sites
//! that M7 cannot help: a legacy password site the user logs into daily. The
//! autofill path in [`crate::ipc`] answers "give me the password" and is
//! bounded by the working set as a result — every site the user visits is one
//! more plaintext credential that has been in the browser's address space. This
//! path answers a different question. The desktop opens its *own* TLS
//! connection to the site, posts the credential itself, and hands back only
//! what the site issued in return: cookies.
//!
//! The model's `credential_never_leaks` is the claim, and the thing that makes
//! it true here is structural rather than careful: [`LoginOutcome`] has no field
//! that can hold a password. There is no code path from a vault item's
//! plaintext to an IPC response, so the property holds even for the credential
//! in active use — the same shape as [`crate::passkey`], where the signing key
//! never crosses the boundary either.
//!
//! ## What the browser does get, and what that is worth
//!
//! Cookies. The model is explicit that these reach the domain (`Out(<'session',
//! O, sid>)`) and treats the adversary as holding them, so nothing here is
//! claiming otherwise. What changes is the *shape* of the residual: a session
//! expires, can be revoked from the site's own "sign out everywhere", and is
//! scoped to one origin, where a password is none of those things.
//!
//! That improvement is real but it is not unconditional, and the model refuses
//! to pretend otherwise. `Site_Session_Escalate` says that at a site where a
//! live session can change the account password without re-proving the old one,
//! the adversary converts the session into a credential *it* chose, and the
//! takeover outlives the session. So the honest claim is per-site, and
//! [`SiteMode`] carries it: the tier's "nothing persists" story holds at
//! `Hardened` sites and does not hold at `SelfServe` ones. The default is
//! `SelfServe`, because assuming a site is careful is not a security argument.
//!
//! ## Limits worth knowing before trusting this
//!
//!  * **Bot protection beats this, and often.** Pointed at six real login
//!    pages, GitHub and Wikipedia parsed cleanly; GitLab answered a Cloudflare
//!    interstitial (403) and Hacker News a 429, neither of which is a login
//!    page at all. VELA identifies itself honestly rather than impersonating a
//!    browser (see [`USER_AGENT`]), so any site that only talks to real
//!    browsers is out of reach here and says so via
//!    [`LoginError::SiteRefused`]. Treat in-core login as something that works
//!    on some sites, not as a general replacement for autofill.
//!  * **Form logins only.** [`discover_form`] reads the login page's HTML and
//!    finds the form containing the password input. A site that logs in via
//!    XHR from JavaScript has no such form, and this refuses rather than
//!    guessing. Of the six pages above, Reddit and Fastmail are genuinely in
//!    this category.
//!  * **No cross-domain hops.** The credential POST will not follow a redirect
//!    off the registrable domain, so SSO flows fail here instead of quietly
//!    sending the user's password to a third party that may or may not be their
//!    identity provider.
//!  * **Second factors: TOTP only.** Where the site answers the password with a
//!    code prompt, the item's saved authenticator secret answers it, inside the
//!    same approval — see the note on that in [`perform_login`]. A site that
//!    wants a security key, a push notification or an SMS cannot be satisfied
//!    from a vault at all, and stops at [`LoginError::TwoFactorRequired`],
//!    which says that the password was accepted so the user knows which half
//!    worked.
//!  * **Success is inferred.** The site does not tell us "that password was
//!    right"; [`LoginOutcome::looks_authenticated`] is a heuristic over what
//!    came back, and it is reported as one.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use url::Url;
use zeroize::Zeroizing;

use crate::vault::VaultItem;
use crate::AppState;

/// The per-site login recipes that let in-core login reach sites whose login
/// is not a plain HTML form. See [`recipe`] for the design.
pub mod recipe;

/// How many redirects to follow before giving up.
const MAX_REDIRECTS: usize = 8;
/// Whole-ceremony budget. A login that has not finished by now is not going to.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Proof that a human authorised exactly one login, for one item, at one site.
///
/// The direct analogue of the `LoginGrant(cred, $O)` linear fact in
/// `m9a_in_core_login.spthy`, and the same device [`crate::passkey`] uses:
/// minted only by [`crate::presence`], neither `Clone` nor `Copy`, consumed by
/// value. Two things follow, both checked by the compiler rather than by
/// comment. One approval buys one login, so this is not an oracle a co-resident
/// process can drive in a loop. And the grant names the origin the human agreed
/// to, so an approval for `bank.example` cannot be spent posting that password
/// somewhere else — the target-redefinition case, refused in
/// [`perform_login`] by comparing the grant against the resolved URL.
#[must_use = "a login grant that is not spent on a login wasted a prompt"]
pub struct LoginGrant {
    item_id: String,
    /// Registrable domain the human approved, lower-cased.
    site: String,
    /// Whether the human proved presence with a real verification factor.
    verified: bool,
}

impl LoginGrant {
    /// Mint a grant. Crate-private: [`crate::presence`] is the only thing that
    /// may decide a human approved something.
    pub(crate) fn mint(item_id: String, site: String, verified: bool) -> Self {
        Self {
            item_id,
            site: site.to_lowercase(),
            verified,
        }
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }
}

/// Whether a live session at this site can mint a new credential.
///
/// The model's per-site `SiteMode`, and the reason M9a's "nothing persists"
/// claim is stated per site instead of globally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteMode {
    /// Changing the password needs the old one, a second factor, or a step-up.
    /// The residual really is bounded by the session's lifetime.
    Hardened,
    /// A session can rotate the credential unilaterally, so whoever holds the
    /// session can lock the owner out permanently. The default, because a site
    /// has to be shown to be careful, not assumed to be.
    SelfServe,
}

impl SiteMode {
    fn from_item(item: &VaultItem) -> Self {
        if item.credential_change_needs_reauth() {
            Self::Hardened
        } else {
            Self::SelfServe
        }
    }

    /// What the caller should tell the user this session is worth.
    pub fn residual_note(self) -> &'static str {
        match self {
            Self::Hardened => {
                "This site was marked as requiring re-authentication to change the password, \
                 so signing out ends this session's power."
            }
            Self::SelfServe => {
                "Anyone holding this session may be able to change the account password, \
                 which would outlast the session. Sign out when finished."
            }
        }
    }
}

/// What the caller is asking for.
#[derive(Debug, Clone)]
pub struct LoginRequest {
    /// The vault item to log in with.
    pub item_id: String,
    /// Page to log in at. Defaults to the item's stored URL, and must in any
    /// case be on the same registrable domain as it.
    pub login_url: Option<String>,
    /// Artifacts minted in the browser, for sites whose login demands more than
    /// a password — see [`BrowserArtifacts`]. Absent for the plain-form path.
    pub browser: Option<BrowserArtifacts>,
}

/// Things only a browser can mint, lifted from the page and carried to the
/// core so it can complete a login the browser alone started.
///
/// Both fields are short-lived secrets: a CAPTCHA token is single-use and dies
/// in minutes, and the cookie jar is the page's pre-session state. They are
/// never persisted, never logged, and they do not survive this request — the
/// core uses them for one submission and drops them.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BrowserArtifacts {
    /// A CAPTCHA a human solved on the page (`h-captcha-response` /
    /// `g-recaptcha-response`). The core will not guess one, because a login
    /// attempt carrying a stale or missing token both fails and looks like the
    /// user trying to automate the site.
    #[serde(default)]
    pub captcha_token: Option<String>,
    /// The browser's cookie jar for the tab, so the core's request carries the
    /// same pre-session state the page has — CSRF tokens, and the
    /// per-request `sessionid` sites like Steam tie their login to.
    #[serde(default)]
    pub cookies: Vec<BrowserCookie>,
}

/// One cookie from the browser's jar, with the attributes needed to re-use it.
///
/// The same shape as [`SessionCookie`], kept separate so the two are not
/// confused: a [`SessionCookie`] is what the site *issued* to us, while this
/// is what the browser already *held*.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BrowserCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub host_only: bool,
}

/// One cookie the site issued, with the attributes needed to reinstall it.
///
/// This is the session artifact — the thing the model puts in the domain. The
/// field set is deliberately the one `chrome.cookies.set` takes, so the browser
/// end reinstalls exactly what the site sent rather than a lossy summary of it;
/// dropping `HttpOnly` in transit, in particular, would hand page JavaScript a
/// cookie the site meant to keep away from it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    /// Unix seconds. `None` is a session cookie — it dies with the browser.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// True when the site sent no `Domain`, i.e. the cookie is for this exact
    /// host and not its subdomains.
    pub host_only: bool,
}

/// The result of a login. Note what is absent: there is no field here that
/// could carry the credential, which is what makes the model's secrecy claim a
/// property of the type rather than of the implementation.
#[derive(Debug, Clone, Serialize)]
pub struct LoginOutcome {
    /// Where the site left us after the login. The caller navigates here.
    pub landing_url: String,
    /// The session artifact.
    pub cookies: Vec<SessionCookie>,
    /// Best-effort read on whether the credential was accepted. The site did
    /// not say; see [`Self::looks_authenticated`].
    pub looks_authenticated: bool,
    /// What this session is worth if it leaks.
    pub site_mode: SiteMode,
    pub residual_note: String,
    /// Whether the human proved presence with a verification factor.
    pub user_verified: bool,
    /// Whether the site asked for a second factor and the vault answered it.
    pub used_second_factor: bool,
    /// Set when the site is still holding a gate the vault could not open —
    /// a security key, a push, an SMS. Describes what it wants, for the user.
    ///
    /// This exists because the first real GitHub login reported success while
    /// sitting on `/sessions/two-factor/webauthn`: the password had been
    /// accepted, cookies had been issued, and neither of the two "is the site
    /// still asking?" signals fired, because a security-key page has no
    /// password field and no code field. A partial session that says "signed
    /// in" is worse than a failure, so when this is set
    /// [`Self::looks_authenticated`] is false regardless of what else looked
    /// encouraging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awaiting_second_factor: Option<String>,
    /// True when the site wanted a stronger factor and this item's opt-in let
    /// VELA answer with a TOTP code instead. Surfaced rather than hidden: the
    /// user turned this on once, and should still be told each time it is used.
    pub second_factor_downgraded: bool,
    /// True when the login was completed in a disposable real browser (the
    /// `browser-login` tier) rather than by the core submitting over its own
    /// TLS. Surfaced so the caller can tell the user a window appeared.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub used_browser: bool,
    /// The site's `localStorage`/`sessionStorage` from the disposable browser,
    /// for token-session sites (Firebase Auth stores it in sessionStorage when
    /// "remember me" is off). The caller replicates these keys in the user's
    /// own tab so the session carries over. Treated like the session cookies: a
    /// short-lived secret, never logged, never persisted.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub local_session: std::collections::BTreeMap<String, String>,
    /// The auth SDK's IndexedDB records, for sites whose token-session lives
    /// there (Firebase's `indexedDBLocalPersistence` — monkeytype with
    /// "remember me" on). Keyed by the record key (`firebase:authUser:…`), so
    /// the caller can write them straight back into the user's own tab's
    /// IndexedDB. Same secrecy handling as `local_session`.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub cached_db: std::collections::BTreeMap<String, serde_json::Value>,
}

impl LoginOutcome {
    /// Why this is a heuristic and not a fact.
    ///
    /// A form login has no machine-readable "yes, that was the right password".
    /// What we can see is that the site set at least one cookie during the
    /// credential POST and did not answer by serving the login form again —
    /// which is what a rejected password almost always looks like. Reported as
    /// a hint so the caller can say "check the page" instead of asserting
    /// something it does not know.
    fn infer(
        set_a_cookie: bool,
        site_still_asking: bool,
        final_status: u16,
        awaiting: Option<&str>,
    ) -> bool {
        set_a_cookie && !site_still_asking && final_status < 400 && awaiting.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    VaultLocked,
    NoSuchItem,
    NotALogin,
    /// The item has no usable URL, so there is nowhere to log in.
    NoUrl,
    /// The requested target is not on the item's site, or not on the site the
    /// human approved.
    TargetMismatch { approved: String, requested: String },
    /// No password form on the page — a JavaScript login, most likely.
    NoLoginForm,
    /// The site wants a second factor and this item has no TOTP secret saved.
    ///
    /// Worth its own variant rather than a generic failure: the user can fix it
    /// (save the TOTP secret on the item) and the message should say so. It
    /// also means the password *was* accepted, which is the one thing a bare
    /// "login failed" would hide.
    TwoFactorRequired,
    /// A TOTP secret is saved but no code could be derived from it.
    TwoFactorUnusable,
    /// The site would not serve us the login page at all.
    ///
    /// Distinct from [`Self::NoLoginForm`] on purpose, and the distinction was
    /// not there until real sites were tried: GitLab answers a non-browser
    /// client with a Cloudflare interstitial (403) and Hacker News with a 429,
    /// and both were being reported as "this site signs in with JavaScript".
    /// That sends the user to look for a problem that isn't there.
    SiteRefused { status: u16 },
    /// A form we found but will not use, e.g. one that submits by GET.
    UnsupportedForm(String),
    /// The site tried to send the credential somewhere else.
    CrossSiteRedirect(String),
    /// The site's login is gated by something only the browser can provide — a
    /// CAPTCHA the human must solve on the page — and it was not provided.
    ///
    /// Not a failure of the site or of the credential; the login was not
    /// attempted, because attempting it with a missing artifact would both fail
    /// and look like an automated attack.
    NeedsBrowserArtifact(String),
    Http(String),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VaultLocked => write!(f, "Vault is locked"),
            Self::NoSuchItem => write!(f, "No such vault item"),
            Self::NotALogin => write!(f, "That item is not a login"),
            Self::NoUrl => write!(f, "That login has no website address saved"),
            Self::TargetMismatch { approved, requested } => write!(
                f,
                "You approved a login at {approved}, but the request was for {requested}"
            ),
            Self::NoLoginForm => write!(
                f,
                "No password form found on that page. Sites that sign in with JavaScript \
                 are not supported by in-app login yet."
            ),
            Self::TwoFactorRequired => write!(
                f,
                "Your password was accepted, but this site then asked for a two-factor \
                 code and this login has no authenticator secret saved. Add one to the \
                 item, or finish signing in here in the browser."
            ),
            Self::TwoFactorUnusable => write!(
                f,
                "This login's saved authenticator secret could not produce a code. \
                 Only time-based (TOTP) authenticator codes work here."
            ),
            Self::SiteRefused { status } => write!(
                f,
                "The site would not serve the sign-in page to VELA (HTTP {status}). \
                 Sites behind a bot check usually only answer a real browser; \
                 sign in there in the browser instead."
            ),
            Self::UnsupportedForm(why) => write!(f, "Cannot use that login form: {why}"),
            Self::CrossSiteRedirect(host) => write!(
                f,
                "The site redirected the sign-in to {host}, which is a different site. \
                 Your password was not sent there."
            ),
            Self::NeedsBrowserArtifact(what) => write!(
                f,
                "{what} Complete the captcha in the browser tab first, then try again \
                 — VELA picks the token up from the page and finishes the sign-in."
            ),
            Self::Http(message) => write!(f, "Could not reach the site: {message}"),
        }
    }
}

impl std::error::Error for LoginError {}

/// The JS runtime's refusals are login refusals, and the user should read them
/// as such rather than as a second vocabulary.
impl From<crate::js_login::JsLoginError> for LoginError {
    fn from(e: crate::js_login::JsLoginError) -> Self {
        use crate::js_login::JsLoginError as J;
        match e {
            // A page with no form and no runtime to read its script is the
            // original NoLoginForm case, worded the way it already was.
            J::Unavailable | J::NoRequestCaptured => LoginError::NoLoginForm,
            J::CrossSiteRequest(host) => LoginError::CrossSiteRedirect(host),
            other => LoginError::UnsupportedForm(other.to_string()),
        }
    }
}

// ── The ceremony ──────────────────────────────────────────────────────────────

/// Log in to the site as the user, and return only the session.
///
/// Takes the grant by value: this consumes the human's approval, and the caller
/// must go back to [`crate::presence`] for another one.
pub async fn perform_login(
    state: &Arc<AppState>,
    request: &LoginRequest,
    grant: LoginGrant,
) -> Result<LoginOutcome, LoginError> {
    // Everything that touches the vault happens here, in one short block, and
    // nothing borrowed from it survives into the awaits below — an RwLock guard
    // held across an await is a deadlock waiting for a slow site.
    let (username, password, totp_secret, item_url, site_mode, allow_downgrade) = {
        {
            let session = state.session.read();
            if !session.active || session.is_expired() {
                return Err(LoginError::VaultLocked);
            }
        }
        let vault = state.vault.read();
        let item = vault.get_item(&request.item_id).ok_or(LoginError::NoSuchItem)?;
        let VaultItem::Login {
            totp,
            allow_second_factor_downgrade,
            ..
        } = item
        else {
            return Err(LoginError::NotALogin);
        };
        (
            item.username().unwrap_or_default().to_string(),
            Zeroizing::new(item.password().unwrap_or_default().to_string()),
            totp.clone().map(Zeroizing::new),
            item.url().unwrap_or_default().to_string(),
            SiteMode::from_item(item),
            allow_second_factor_downgrade.unwrap_or(false),
        )
    };

    let item_url = normalize_url(&item_url).ok_or(LoginError::NoUrl)?;
    let target = match request.login_url.as_deref().filter(|u| !u.trim().is_empty()) {
        Some(raw) => normalize_url(raw).ok_or(LoginError::NoUrl)?,
        None => item_url.clone(),
    };

    // The tab's pre-session cookies, for the browser tier's disposable window
    // to seed before it loads the starting page.
    let browser_cookies: &[crate::login::BrowserCookie] = request
        .browser
        .as_ref()
        .map(|b| b.cookies.as_slice())
        .unwrap_or(&[]);

    // Two independent checks, and both have to pass. The first says the caller
    // is not redirecting this item's password to another site; the second says
    // the human's approval was for this site and not merely for this item. They
    // catch different lies: a caller that names a legitimate-looking item, and
    // a caller that swaps the target after the prompt was answered.
    //
    // Where the browser tier is compiled in, a mismatch is *not* automatically
    // a refusal: a site whose login is an OAuth flow initiated from another
    // domain (Riot via a sports site) legitimately starts on a page outside
    // the item's site. The browser tier handles that — it starts at the tab's
    // page, the human initiates the flow there, and the credential is only
    // ever submitted to the page the human is submitting on. So a mismatch
    // falls through to the browser tier instead.
    let browser_tier_available = cfg!(feature = "browser-login");
    if !same_site(&item_url, &target) && !browser_tier_available {
        return Err(LoginError::TargetMismatch {
            approved: site_key(&item_url),
            requested: site_key(&target),
        });
    }
    if (grant.item_id != request.item_id || grant.site != site_key(&target)) && !browser_tier_available {
        return Err(LoginError::TargetMismatch {
            approved: grant.site.clone(),
            requested: site_key(&target),
        });
    }

    // A site with a recipe skips the page-fetch and form-discovery flow
    // entirely: its login is a JSON API or a challenge-then-submit dance, and
    // the browser minted whatever artifact the site demands (a solved CAPTCHA,
    // the pre-session cookie set). See `crate::login::recipe` for the shape and
    // for why each recipe re-checks that its endpoint is on the approved site.
    if let Some(recipe) = crate::login::recipe::for_url(&target) {
        return crate::login::recipe::perform(
            &username,
            &password,
            totp_secret.as_deref().map(String::as_str),
            &grant,
            &target,
            recipe,
            request.browser.as_ref(),
            site_mode,
        )
        .await;
    }

    let client = build_client()?;
    let mut jar = CookieJar::default();

    // 1. Fetch the login page, for the form layout and for whatever pre-session
    //    cookie the CSRF token is tied to.
    let page = fetch(&client, &jar, Method::Get, &target, None).await?;
    jar.absorb(&page.set_cookie, &target);
    // Follow the site to wherever the login page actually lives. Netflix sends
    // /login to /fr-en/login, and plenty of sites redirect for a locale, a
    // trailing slash, or www — with `Policy::none()` on the client, not
    // following meant reading an empty 302 body, finding no form in it, and
    // telling the user their bank signs in with JavaScript.
    let page = follow_redirects(&client, &mut jar, &target, page).await?;
    // Say "the site would not talk to us" when that is what happened. A bot
    // check answers with a challenge page that has no password field, and
    // calling that a JavaScript login sends the user after the wrong problem.
    if page.status >= 400 {
        // Where the browser tier is compiled in, hand the whole login to a
        // disposable real browser instead of refusing: the site gets the real
        // browser it demanded, and the password still never enters the page's
        // JavaScript (the placeholder is substituted at the network layer by
        // the core). A visible window appears, so the user sees it happen and
        // can finish a second factor in it.
        #[cfg(feature = "browser-login")]
        {
            let outcome = crate::browser::login(
                &target,
                &username,
                &password,
                browser_cookies,
                site_mode,
                grant.verified,
            )
            .await?;
            return Ok(LoginOutcome {
                used_browser: true,
                ..outcome
            });
        }
        #[cfg(not(feature = "browser-login"))]
        return Err(LoginError::SiteRefused {
            status: page.status,
        });
    }
    // Relative form actions resolve against where the page ended up, not where
    // it was asked for.
    // 2. Post the credential over our own connection. This is the only place
    //    the plaintext is used, and it does not leave this function.
    let response = match discover_form(&page.body, &page.url) {
        Ok(form) => {
            let body = form.fill(&username, &password);
            let response = fetch(&client, &jar, Method::Post, &form.action, Some(&body)).await?;
            jar.absorb(&response.set_cookie, &form.action);
            response
        }
        // No form. Where the JS runtime is built in, let the page's own script
        // say what request it would have made — see `crate::js_login`, and
        // `security/formal/m9c_inprocess_sandbox.spthy` for what that costs.
        // The credential is not handed to the runtime; it is substituted into
        // the captured request afterwards, out here.
        Err(LoginError::NoLoginForm) => {
            match crate::js_login::capture_login_request(&page.body, &page.url, &username) {
                Ok(captured) => {
                    captured
                        .check_same_site(&target)
                        .map_err(LoginError::from)?;
                    let ready = captured.substitute(&password).map_err(LoginError::from)?;
                    let action = Url::parse(&ready.url)
                        .map_err(|e| LoginError::Http(format!("bad request URL: {e}")))?;
                    let response = fetch_raw(&client, &jar, &ready, &action).await?;
                    jar.absorb(&response.set_cookie, &action);
                    response
                }
                Err(js_error) => {
                    // Neither a form nor a runnable inline script. Where the
                    // browser tier is compiled in, hand the whole login to a
                    // disposable real browser: a bundled-JS login page (Riot's
                    // app) is exactly what it is for, and the password still
                    // never enters the page's JavaScript. A visible window
                    // appears and the user clicks the site's sign-in button.
                    #[cfg(feature = "browser-login")]
                    {
                        let outcome = crate::browser::login(
                            &target,
                            &username,
                            &password,
                            browser_cookies,
                            site_mode,
                            grant.verified,
                        )
                        .await?;
                        return Ok(LoginOutcome {
                            used_browser: true,
                            ..outcome
                        });
                    }
                    #[cfg(not(feature = "browser-login"))]
                    return Err(LoginError::from(js_error));
                }
            }
        }
        Err(other) => return Err(other),
    };
    let mut cookies_from_login = !response.set_cookie.is_empty();

    // 3. Follow the site home, staying on the site.
    let mut response = follow_redirects(&client, &mut jar, &target, response).await?;

    // 4. The second factor, if the site asks for one.
    //
    //    Deliberately inside the same grant. The human approved "sign in to
    //    this site", and a two-step site has not asked them a second question —
    //    prompting again would be an extra click that buys nothing, because
    //    whoever obtained the first approval obtains the second the same way.
    //    The linear resource authorises one *login*, which is what the model's
    //    `LoginGrant` means; it was never one HTTP request.
    let mut used_second_factor = false;
    let mut downgraded = false;

    // 4a. The site may be holding a factor no vault can produce — a security
    //     key, typically — while also offering "use your authenticator app
    //     instead". Taking that offer completes the login by deliberately
    //     using the *weaker* of the two factors the site presented, which is
    //     a security decision belonging to the account owner and nobody else.
    //     Hence opt-in per item, defaulting off: VELA does not quietly undo a
    //     site's choice of a phishing-resistant factor.
    if allow_downgrade
        && totp_secret.is_some()
        && discover_second_factor_form(&response.body, &response.url).is_none()
        && unanswered_second_factor(&response.url, &response.body).is_some()
    {
        if let Some(link) = find_totp_alternative_link(&response.body, &response.url) {
            if same_site(&target, &link) {
                let alternative = fetch(&client, &jar, Method::Get, &link, None).await?;
                jar.absorb(&alternative.set_cookie, &link);
                let alternative =
                    follow_redirects(&client, &mut jar, &target, alternative).await?;
                // Only switch if the alternative really is a code prompt;
                // otherwise stay where we were and report the gate honestly.
                if discover_second_factor_form(&alternative.body, &alternative.url).is_some() {
                    warn!(
                        "In-core login to {} used the weaker second factor this item opts into",
                        site_key(&target)
                    );
                    response = alternative;
                    downgraded = true;
                }
            }
        }
    }

    if let Some(second) = discover_second_factor_form(&response.body, &response.url) {
        let Some(secret) = totp_secret.as_deref() else {
            return Err(LoginError::TwoFactorRequired);
        };
        let Some(code) = crate::totp::generate_totp_code(secret) else {
            return Err(LoginError::TwoFactorUnusable);
        };
        let code = Zeroizing::new(code);

        if !same_site(&target, &second.action) {
            return Err(LoginError::CrossSiteRedirect(site_key(&second.action)));
        }

        let body = second.fill(&code);
        response = fetch(&client, &jar, Method::Post, &second.action, Some(&body)).await?;
        jar.absorb(&response.set_cookie, &second.action);
        cookies_from_login |= !response.set_cookie.is_empty();
        response = follow_redirects(&client, &mut jar, &target, response).await?;
        used_second_factor = true;
    }

    let landing_url = response.url.to_string();
    // A second-factor page that comes back is a wrong or stale code, and reads
    // the same way a returned login form does: the site is still asking.
    let still_asking = html_has_password_field(&response.body)
        || discover_second_factor_form(&response.body, &response.url).is_some();
    let awaiting = unanswered_second_factor(&response.url, &response.body);
    let cookies = jar.into_cookies();

    if cookies.is_empty() {
        warn!("In-core login to {} produced no cookies", site_key(&target));
    }
    if let Some(what) = &awaiting {
        warn!(
            "In-core login to {} stopped at a gate needing {}",
            site_key(&target),
            what
        );
    }

    Ok(LoginOutcome {
        landing_url,
        cookies,
        looks_authenticated: LoginOutcome::infer(
            cookies_from_login,
            still_asking,
            response.status,
            awaiting.as_deref(),
        ),
        site_mode,
        residual_note: site_mode.residual_note().to_string(),
        user_verified: grant.verified,
        used_second_factor,
        awaiting_second_factor: awaiting,
        second_factor_downgraded: downgraded,
        used_browser: false,
        local_session: std::collections::BTreeMap::new(),
        cached_db: std::collections::BTreeMap::new(),
    })
}

/// A link offering a code-based alternative to the factor the site is demanding.
///
/// Only ever followed when the item opted in. Matched on both the link target
/// and its text, because sites split the signal between them — GitHub puts the
/// method in the path (`/sessions/two-factor/app`) and the meaning in the words
/// ("Use your authenticator app").
fn find_totp_alternative_link(html: &str, base: &Url) -> Option<Url> {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").expect("static selector");

    for anchor in document.select(&selector) {
        let href = anchor.value().attr("href")?.trim();
        if href.is_empty() || href.starts_with('#') {
            continue;
        }
        let text = anchor.text().collect::<String>().to_lowercase();
        let haystack = format!("{} {}", href.to_lowercase(), text);

        let offers_a_code = [
            "two-factor/app",
            "two_factor/app",
            "authenticator app",
            "authenticator",
            "/totp",
            "totp",
            "authentication code",
            "verification code",
            "use a code",
            "enter a code",
        ]
        .iter()
        .any(|marker| haystack.contains(marker));
        // "recovery code" is a different thing entirely — a one-shot backup the
        // vault does not hold and must not spend.
        if offers_a_code && !haystack.contains("recovery") && !haystack.contains("backup") {
            return base.join(href).ok();
        }
    }
    None
}

/// Is the site still holding a gate we did not open?
///
/// Detection is by *markup*, not by URL, and that is deliberate. The obvious
/// implementation — look for `two-factor` in the path — reports failure after a
/// successful TOTP login, because the page a site serves when the code is
/// accepted is very often still under `/sessions/two-factor`. The URL only gets
/// a vote when the page also shows a form we did not submit.
///
/// Heuristic, and it will not name every gate. What it must not do is the thing
/// the old code did: let a page we cannot satisfy pass for a signed-in one.
fn unanswered_second_factor(url: &Url, html: &str) -> Option<String> {
    // A gate for the *second* factor comes after the first one was accepted, so
    // a page still asking for a password is not one — it is a rejected login.
    // Netflix taught this the expensive way: its sign-in page offers "use a
    // passkey" alongside the password box, the word appears in the markup, and
    // a failed login was reported as "your password was accepted, now use your
    // security key". Wrong about both halves.
    //
    // This is the same rule `discover_second_factor_form` applies, written down
    // there and then not applied here.
    if html_has_password_field(html) {
        return None;
    }

    let lowered = html.to_lowercase();

    // A security key or passkey. Nothing in a vault can answer this — the whole
    // point of the factor is that it is bound to hardware.
    if ["webauthn", "security key", "publickey-credentials", "u2f", "passkey"]
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return Some("a security key or passkey".to_string());
    }
    if lowered.contains("push notification") || lowered.contains("approve the sign-in") {
        return Some("an approval in another app".to_string());
    }
    // An SMS or e-mailed code is a code, but not one the vault holds.
    if (lowered.contains("sent you a code") || lowered.contains("text message"))
        && discover_second_factor_form(html, url).is_none()
    {
        return Some("a code sent to you by the site".to_string());
    }

    // Last resort: the URL says we are mid-challenge and the page is still
    // showing a form. On its own the URL means nothing, hence the conjunction.
    let path = url.path().to_lowercase();
    let gated = ["two-factor", "two_factor", "２fa", "/2fa", "/mfa", "challenge", "verify"]
        .iter()
        .any(|marker| path.contains(marker));
    if gated && lowered.contains("<form") {
        return Some("another sign-in step".to_string());
    }
    None
}

/// Follow a redirect chain, staying on the site.
///
/// A 302 drops the body, but 307/308 would replay it, so a cross-site hop is
/// refused rather than followed — that is the difference between the site
/// knowing the credential and an arbitrary third party knowing it. Shared by
/// both POSTs, because the second factor deserves the same rule as the first.
async fn follow_redirects(
    client: &reqwest::Client,
    jar: &mut CookieJar,
    site: &Url,
    mut response: Fetched,
) -> Result<Fetched, LoginError> {
    let mut hops = 0;
    while let Some(location) = response.redirect_to.clone() {
        if hops >= MAX_REDIRECTS {
            break;
        }
        hops += 1;

        let next = response
            .url
            .join(&location)
            .map_err(|e| LoginError::Http(format!("bad redirect target: {e}")))?;
        if !same_site(site, &next) {
            return Err(LoginError::CrossSiteRedirect(site_key(&next)));
        }

        // 303 always becomes GET; 301/302 become GET in every real browser;
        // only 307/308 preserve the method, and we do not resend the body.
        response = fetch(client, jar, Method::Get, &next, None).await?;
        jar.absorb(&response.set_cookie, &next);
    }
    Ok(response)
}

// ── HTTP, kept deliberately small ─────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
}

struct Fetched {
    url: Url,
    status: u16,
    body: String,
    set_cookie: Vec<String>,
    redirect_to: Option<String>,
}

/// A client that does not follow redirects on its own.
///
/// `reqwest`'s automatic redirect handling is fine for an API client and wrong
/// here: it would carry the credential POST across a 307 to whatever host the
/// site named, and it would swallow the `Set-Cookie` headers on the hops we
/// need. Following them by hand is a few lines and makes both decisions ours.
fn build_client() -> Result<reqwest::Client, LoginError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| LoginError::Http(e.to_string()))
}

/// What we tell sites we are.
///
/// Truthfully, and knowing it costs us. Copying a Chrome UA string would get
/// past more bot checks, and that is exactly the reason not to: a site that
/// blocks non-browser clients has made a decision about who may talk to it, and
/// dressing up as a browser to get around it is evading a control rather than
/// satisfying one. It would also be brittle in a way the user pays for — the
/// disguise stops working and the failure looks like a bug in VELA.
///
/// The cost is real. Sites behind Cloudflare and friends will answer this with
/// a challenge, and in-core login will not work there; [`LoginError::SiteRefused`]
/// says so plainly instead of blaming the site's JavaScript.
const USER_AGENT: &str = concat!(
    "VELA/",
    env!("CARGO_PKG_VERSION"),
    " (password manager; signing in on behalf of the account owner)"
);

async fn fetch(
    client: &reqwest::Client,
    jar: &CookieJar,
    method: Method,
    url: &Url,
    form_body: Option<&BTreeMap<String, String>>,
) -> Result<Fetched, LoginError> {
    let mut builder = match method {
        Method::Get => client.get(url.clone()),
        Method::Post => client.post(url.clone()),
    };

    if let Some(header) = jar.header_for(url) {
        builder = builder.header(reqwest::header::COOKIE, header);
    }
    if let Some(body) = form_body {
        builder = builder.form(body);
    }

    let response = builder
        .send()
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;

    let status = response.status();
    let final_url = response.url().clone();
    let set_cookie = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let redirect_to = if status.is_redirection() {
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    } else {
        None
    };

    // A redirect body is not worth reading, and a login page can be large.
    let body = if redirect_to.is_some() {
        String::new()
    } else {
        response.text().await.unwrap_or_default()
    };

    Ok(Fetched {
        url: final_url,
        status: status.as_u16(),
        body,
        set_cookie,
        redirect_to,
    })
}

/// Send a request the page's script composed, rather than a form we built.
///
/// Separate from [`fetch`] because the shapes differ: a form is name/value
/// pairs and a known content type, while this carries whatever body and headers
/// the script chose. The headers are the script's, minus the ones that are ours
/// to set — a page that sets its own Cookie or Host header is not something to
/// honour.
async fn fetch_raw(
    client: &reqwest::Client,
    jar: &CookieJar,
    request: &crate::js_login::CapturedRequest,
    url: &Url,
) -> Result<Fetched, LoginError> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|e| LoginError::Http(format!("bad method: {e}")))?;
    let mut builder = client.request(method, url.clone());

    for (name, value) in &request.headers {
        let lowered = name.to_lowercase();
        if matches!(lowered.as_str(), "cookie" | "host" | "content-length") {
            continue;
        }
        builder = builder.header(name, value);
    }
    if let Some(header) = jar.header_for(url) {
        builder = builder.header(reqwest::header::COOKIE, header);
    }
    if !request.body.is_empty() {
        builder = builder.body(request.body.clone());
    }

    let response = builder
        .send()
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;
    let status = response.status();
    let final_url = response.url().clone();
    let set_cookie = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let redirect_to = if status.is_redirection() {
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    } else {
        None
    };
    let body = if redirect_to.is_some() {
        String::new()
    } else {
        response.text().await.unwrap_or_default()
    };

    Ok(Fetched {
        url: final_url,
        status: status.as_u16(),
        body,
        set_cookie,
        redirect_to,
    })
}

// ── Cookies ───────────────────────────────────────────────────────────────────

/// A jar just big enough for one login.
///
/// Not `reqwest`'s: its store is opaque, and the attributes it discards
/// (`HttpOnly`, `SameSite`, the exact `Domain`) are precisely the ones the
/// browser end needs to reinstall the session faithfully. Keyed by
/// `(domain, path, name)`, which is the tuple the RFC says identifies a cookie.
#[derive(Default)]
struct CookieJar {
    cookies: BTreeMap<(String, String, String), SessionCookie>,
}

impl CookieJar {
    /// Take in a response's `Set-Cookie` headers, dropping ones the sending
    /// host is not allowed to set.
    fn absorb(&mut self, headers: &[String], url: &Url) {
        let Some(host) = url.host_str().map(str::to_lowercase) else {
            return;
        };
        for header in headers {
            match parse_set_cookie(header, &host) {
                Some(cookie) => {
                    let key = (
                        cookie.domain.clone(),
                        cookie.path.clone(),
                        cookie.name.clone(),
                    );
                    // An empty value with a past expiry is the site deleting a
                    // cookie; carrying that to the browser would be pointless
                    // but harmless, and dropping it keeps the artifact tidy.
                    if cookie.value.is_empty() && cookie.expires_at.is_some_and(|t| t <= 0) {
                        self.cookies.remove(&key);
                    } else {
                        self.cookies.insert(key, cookie);
                    }
                }
                None => debug!("Dropped a Set-Cookie header {host} was not entitled to set"),
            }
        }
    }

    fn header_for(&self, url: &Url) -> Option<String> {
        let host = url.host_str()?.to_lowercase();
        let path = url.path();
        let pairs: Vec<String> = self
            .cookies
            .values()
            .filter(|c| domain_matches(&host, &c.domain, c.host_only) && path_matches(path, &c.path))
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        if pairs.is_empty() {
            None
        } else {
            Some(pairs.join("; "))
        }
    }

    /// Seed the jar from the browser's cookies, for a recipe login.
    ///
    /// The same rule applies here as when [`SessionCookie`]s go back to the
    /// browser: a cookie is only carried when its scope covers the request
    /// host. The browser's jar is for the page the user is looking at; a
    /// cookie scoped to a site that host is not under is refused rather than
    /// replayed, so a page cannot quietly get a sibling domain's pre-session
    /// state submitted on its behalf.
    fn seed_browser(&mut self, cookies: &[BrowserCookie], url: &Url) {
        let Some(host) = url.host_str().map(str::to_lowercase) else {
            return;
        };
        for cookie in cookies {
            let domain = cookie.domain.to_lowercase();
            let scoped = if cookie.host_only {
                host == domain
            } else {
                host == domain || host.ends_with(&format!(".{domain}"))
            };
            if !scoped {
                debug!("Refused to seed a browser cookie scoped to {domain} for {host}");
                continue;
            }
            self.cookies.insert(
                (domain.clone(), cookie.path.clone(), cookie.name.clone()),
                SessionCookie {
                    name: cookie.name.clone(),
                    value: cookie.value.clone(),
                    domain,
                    path: cookie.path.clone(),
                    secure: cookie.secure,
                    http_only: cookie.http_only,
                    same_site: cookie.same_site.clone(),
                    expires_at: cookie.expires_at,
                    host_only: cookie.host_only,
                },
            );
        }
    }

    fn into_cookies(self) -> Vec<SessionCookie> {
        self.cookies.into_values().collect()
    }

    /// A copy of the jar's contents, for a caller that holds the jar by
    /// reference and must hand the session out without consuming it.
    fn snapshot(&self) -> Vec<SessionCookie> {
        self.cookies.values().cloned().collect()
    }
}

/// Parse one `Set-Cookie`, refusing what `host` may not set.
///
/// The check that matters is on `Domain`: without it a compromised page on one
/// host could hand us a cookie scoped to a sibling it does not control, and we
/// would dutifully install it in the user's browser. A cookie may widen its
/// scope to a parent domain, but only one that is still a real registrable
/// domain — `Domain=com` is refused, as is any domain the sending host is not
/// itself under.
fn parse_set_cookie(header: &str, host: &str) -> Option<SessionCookie> {
    let mut parts = header.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut cookie = SessionCookie {
        name,
        value: value.trim().to_string(),
        domain: host.to_string(),
        path: "/".to_string(),
        secure: false,
        http_only: false,
        same_site: None,
        expires_at: None,
        host_only: true,
    };
    let mut max_age: Option<i64> = None;

    for attribute in parts {
        let (key, val) = match attribute.split_once('=') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim().to_string()),
            None => (attribute.trim().to_lowercase(), String::new()),
        };
        match key.as_str() {
            "domain" => {
                let declared = val.trim_start_matches('.').to_lowercase();
                if declared.is_empty() || !host_may_set_domain(host, &declared) {
                    return None;
                }
                cookie.domain = declared;
                cookie.host_only = false;
            }
            "path" if val.starts_with('/') => cookie.path = val,
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => cookie.same_site = Some(val.to_lowercase()),
            "max-age" => max_age = val.parse::<i64>().ok(),
            "expires" => cookie.expires_at = parse_http_date(&val),
            _ => {}
        }
    }

    // Max-Age wins over Expires where both are present (RFC 6265 §5.3).
    if let Some(seconds) = max_age {
        cookie.expires_at = Some(chrono::Utc::now().timestamp() + seconds);
    }

    Some(cookie)
}

/// May a response from `host` set a cookie scoped to `domain`?
fn host_may_set_domain(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    if !host.ends_with(&format!(".{domain}")) {
        return false;
    }
    // `Domain=co.uk` from `evil.co.uk` would otherwise be accepted. A domain a
    // cookie may widen to has to have a registrable part of its own.
    !is_ip(domain) && psl::domain_str(domain).is_some_and(|d| d == domain || domain.ends_with(&d))
}

fn domain_matches(host: &str, cookie_domain: &str, host_only: bool) -> bool {
    if host_only {
        host == cookie_domain
    } else {
        host == cookie_domain || host.ends_with(&format!(".{cookie_domain}"))
    }
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if cookie_path == "/" || request_path == cookie_path {
        return true;
    }
    request_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/'))
}

fn parse_http_date(value: &str) -> Option<i64> {
    use chrono::{DateTime, NaiveDateTime, Utc};

    if let Ok(parsed) = DateTime::parse_from_rfc2822(value) {
        return Some(parsed.timestamp());
    }
    // The two other formats RFC 6265 tells parsers to accept.
    for format in ["%a, %d %b %Y %H:%M:%S GMT", "%a, %d-%b-%y %H:%M:%S GMT"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Some(naive.and_utc().timestamp());
        }
    }
    let _ = Utc::now();
    None
}

// ── Finding the login form ────────────────────────────────────────────────────

/// Safe to `Debug`: this describes the *shape* of a form — field names, the
/// action, the site's own hidden inputs. The credential is never stored here;
/// [`LoginForm::fill`] combines the two into a body that is used and dropped.
#[derive(Debug)]
struct LoginForm {
    action: Url,
    username_field: Option<String>,
    password_field: String,
    /// Hidden inputs and submit buttons, carried through untouched. A CSRF
    /// token lives here, and a login that drops it is a login that fails.
    extras: BTreeMap<String, String>,
}

impl LoginForm {
    fn fill(&self, username: &str, password: &str) -> BTreeMap<String, String> {
        let mut body = self.extras.clone();
        if let Some(field) = &self.username_field {
            body.insert(field.clone(), username.to_string());
        }
        body.insert(self.password_field.clone(), password.to_string());
        body
    }
}

/// Read the page and work out how to submit it.
///
/// Deliberately conservative. Every branch that cannot be sure refuses, because
/// the failure mode of guessing is posting the user's password into a field
/// that was not the password field, on a site that logs its inputs.
fn discover_form(html: &str, base: &Url) -> Result<LoginForm, LoginError> {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form").expect("static selector");
    let password_selector = Selector::parse("input[type=password]").expect("static selector");
    let input_selector = Selector::parse("input").expect("static selector");
    let button_selector = Selector::parse("button[type=submit]").expect("static selector");

    let form = document
        .select(&form_selector)
        .find(|form| form.select(&password_selector).next().is_some())
        .ok_or(LoginError::NoLoginForm)?;

    let password_field = form
        .select(&password_selector)
        .find_map(|input| input.value().attr("name"))
        .ok_or_else(|| {
            LoginError::UnsupportedForm("its password field has no name".to_string())
        })?
        .to_string();

    let method = form
        .value()
        .attr("method")
        .unwrap_or("get")
        .trim()
        .to_lowercase();
    if method != "post" {
        // A GET form puts the password in the URL, where it lands in the site's
        // access log, the browser's history and every proxy in between.
        return Err(LoginError::UnsupportedForm(
            "it submits by GET, which would put the password in the URL".to_string(),
        ));
    }

    let action = match form.value().attr("action").map(str::trim) {
        Some(a) if !a.is_empty() => base
            .join(a)
            .map_err(|e| LoginError::UnsupportedForm(format!("its action is not a URL: {e}")))?,
        // An absent or empty action posts back to the page itself.
        _ => base.clone(),
    };

    let mut extras = BTreeMap::new();
    let mut username_field = None;
    let mut first_text_field = None;

    for input in form.select(&input_selector) {
        let element = input.value();
        let Some(name) = element.attr("name").filter(|n| !n.is_empty()) else {
            continue;
        };
        let input_type = element.attr("type").unwrap_or("text").to_lowercase();
        let value = element.attr("value").unwrap_or("").to_string();

        match input_type.as_str() {
            "password" => {}
            "hidden" | "submit" => {
                extras.insert(name.to_string(), value);
            }
            "checkbox" | "radio" => {
                // Only pre-checked ones are submitted; "remember me" is the
                // common case and honouring the page's own default is the least
                // surprising thing to do.
                if element.attr("checked").is_some() {
                    extras.insert(name.to_string(), if value.is_empty() { "on".into() } else { value });
                }
            }
            "text" | "email" | "tel" | "" => {
                if looks_like_username_field(name, element.attr("id"), element.attr("autocomplete"))
                {
                    username_field.get_or_insert_with(|| name.to_string());
                }
                first_text_field.get_or_insert_with(|| name.to_string());
            }
            _ => {}
        }
    }

    for button in form.select(&button_selector) {
        if let Some(name) = button.value().attr("name").filter(|n| !n.is_empty()) {
            let value = button.value().attr("value").unwrap_or("").to_string();
            extras.insert(name.to_string(), value);
        }
    }

    Ok(LoginForm {
        action,
        // A site that asks for the username on an earlier page has none here,
        // and posting a stray value into whatever text field it does have would
        // be worse than posting nothing.
        username_field: username_field.or(first_text_field),
        password_field,
        extras,
    })
}

fn looks_like_username_field(name: &str, id: Option<&str>, autocomplete: Option<&str>) -> bool {
    if autocomplete.is_some_and(|a| {
        let a = a.to_lowercase();
        a.contains("username") || a.contains("email")
    }) {
        return true;
    }
    let haystack = format!("{} {}", name.to_lowercase(), id.unwrap_or("").to_lowercase());
    ["user", "email", "login", "account", "ident", "mail"]
        .iter()
        .any(|needle| haystack.contains(needle))
}

/// The page a site shows after the password, when it wants a code too.
#[derive(Debug)]
struct SecondFactorForm {
    action: Url,
    code_field: String,
    extras: BTreeMap<String, String>,
}

impl SecondFactorForm {
    fn fill(&self, code: &str) -> BTreeMap<String, String> {
        let mut body = self.extras.clone();
        body.insert(self.code_field.clone(), code.to_string());
        body
    }
}

/// Find a two-factor prompt, if that is what came back.
///
/// Recognised by the field, not by the page: a form with a code-shaped input
/// and *no* password input. Requiring the password field to be absent is what
/// keeps this from firing on a returned login form — a wrong password and a
/// two-factor prompt both come back as "a form", and mistaking the first for
/// the second would spend a TOTP code on a page that never asked for one.
///
/// Returns `None` rather than an error when nothing matches, because "the site
/// did not ask for a second factor" is the ordinary case.
fn discover_second_factor_form(html: &str, base: &Url) -> Option<SecondFactorForm> {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form").expect("static selector");
    let password_selector = Selector::parse("input[type=password]").expect("static selector");
    let input_selector = Selector::parse("input").expect("static selector");

    for form in document.select(&form_selector) {
        if form.select(&password_selector).next().is_some() {
            continue;
        }
        if !form
            .value()
            .attr("method")
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("post"))
        {
            continue;
        }

        let mut code_field = None;
        let mut extras = BTreeMap::new();
        for input in form.select(&input_selector) {
            let element = input.value();
            let Some(name) = element.attr("name").filter(|n| !n.is_empty()) else {
                continue;
            };
            let kind = element.attr("type").unwrap_or("text").to_lowercase();
            match kind.as_str() {
                "hidden" | "submit" => {
                    extras.insert(name.to_string(), element.attr("value").unwrap_or("").to_string());
                }
                "text" | "tel" | "number" | "" => {
                    if looks_like_otp_field(
                        name,
                        element.attr("id"),
                        element.attr("autocomplete"),
                        element.attr("inputmode"),
                    ) {
                        code_field.get_or_insert_with(|| name.to_string());
                    }
                }
                _ => {}
            }
        }

        let code_field = code_field?;
        let action = match form.value().attr("action").map(str::trim) {
            Some(a) if !a.is_empty() => base.join(a).ok()?,
            _ => base.clone(),
        };
        return Some(SecondFactorForm {
            action,
            code_field,
            extras,
        });
    }
    None
}

fn looks_like_otp_field(
    name: &str,
    id: Option<&str>,
    autocomplete: Option<&str>,
    inputmode: Option<&str>,
) -> bool {
    // `autocomplete="one-time-code"` is the spec's own answer and the only
    // unambiguous signal here; everything below it is a guess about wording.
    if autocomplete.is_some_and(|a| a.to_lowercase().contains("one-time-code")) {
        return true;
    }
    let haystack = format!("{} {}", name.to_lowercase(), id.unwrap_or("").to_lowercase());
    let named = [
        "otp", "totp", "2fa", "twofactor", "two_factor", "two-factor", "authenticator",
        "auth_code", "authcode", "security_code", "verification", "mfa",
    ]
    .iter()
    .any(|needle| haystack.contains(needle));
    if named {
        return true;
    }
    // A bare "code"/"token" field is only convincing when the markup also says
    // it takes digits — "code" alone matches promo-code and postcode boxes.
    (haystack.contains("code") || haystack.contains("token"))
        && inputmode.is_some_and(|m| matches!(m.to_lowercase().as_str(), "numeric" | "tel"))
}

fn html_has_password_field(html: &str) -> bool {
    use scraper::{Html, Selector};
    let selector = Selector::parse("input[type=password]").expect("static selector");
    Html::parse_document(html).select(&selector).next().is_some()
}

// ── Site identity ─────────────────────────────────────────────────────────────

fn normalize_url(raw: &str) -> Option<Url> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = if trimmed.contains("://") {
        Url::parse(trimmed).ok()?
    } else {
        Url::parse(&format!("https://{trimmed}")).ok()?
    };
    // A `file://` or `javascript:` "login page" is not one.
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    parsed.host_str()?;
    Some(parsed)
}

/// The identity a login is scoped to: the registrable domain, or the bare host
/// where there isn't one (an IP, or `localhost`).
pub(crate) fn site_key(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().to_lowercase();
    if is_ip(&host) {
        return host;
    }
    psl::domain_str(&host).map(str::to_lowercase).unwrap_or(host)
}

fn same_site(a: &Url, b: &Url) -> bool {
    let (ka, kb) = (site_key(a), site_key(b));
    !ka.is_empty() && ka == kb
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || (host.starts_with('[') && host.ends_with(']'))
}

/// The site a login for this item would go to, for the presence prompt.
pub fn site_for_item(item: &VaultItem) -> Option<String> {
    normalize_url(item.url()?).as_ref().map(site_key)
}

#[cfg(test)]
mod tests;
