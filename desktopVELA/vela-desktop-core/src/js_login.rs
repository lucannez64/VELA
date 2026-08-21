//! A JS runtime inside the core, for sites that submit a login by `fetch`.
//!
//! This is the M9c design (`security/formal/m9c_inprocess_sandbox.spthy`), built
//! deliberately and behind an off-by-default feature. The model is worth reading
//! first: it says the top-level secrecy claim falsifies, and that the reason is
//! worse than M9b's rather than better — an engine escape yields the credential
//! in flight, bounded by the working set, while an in-process escape yields the
//! store, including items never used and the key that unseals them.
//!
//! Two choices make *this* variant defensible against that finding, and both are
//! structural rather than careful:
//!
//! 1. **The credential never enters the runtime.** The page's script runs
//!    against a [`PLACEHOLDER_PASSWORD`], purely to find out what request the
//!    login would make. The core then substitutes the real credential and sends
//!    the request itself. `SandboxSawCred` — the action the model's escape rules
//!    hang off — has no counterpart here, because no code path passes a vault
//!    plaintext into [`Sandbox`]. There is no function that would let you.
//!
//! 2. **A memory-safe interpreter.** M9c's escape rule models a C engine, where
//!    a JS bug becomes memory corruption in the process holding the vault. Boa
//!    is pure Rust: a bug is a wrong answer, not a read of the heap next door.
//!    Not a proof — logic bugs and host-binding mistakes are still real — but a
//!    different order of risk from the one the model assumed.
//!
//! What is deliberately absent from the sandbox: the network, the filesystem,
//! the clock beyond a fixed value, and any handle to [`crate::AppState`]. The
//! script can compute a request. It cannot send one, and it has nothing to send
//! one *to*.
//!
//! ## What this can actually do
//!
//! Sites whose login page carries its script inline or same-origin, builds a
//! request from field values, and calls `fetch`. That is a real category — it is
//! what most small and mid-sized JS logins look like.
//!
//! It will not do the sites that motivated the question. Netflix, Riot, Discord
//! and anything behind Akamai or DataDome fingerprint the client: canvas, WebGL,
//! an audio stack, font enumeration, timing. There is no DOM shim that answers
//! those, because the honest answer requires a renderer, and a renderer is an
//! engine. Failing those checks is also worse than not trying, since it is the
//! user's account that gets flagged.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use url::Url;

/// What the sandbox is told the password is.
///
/// Deliberately conspicuous. If this string ever appears in an outgoing request
/// body, the substitution below did not happen, and the request must not be
/// sent — see [`CapturedRequest::substitute`].
pub const PLACEHOLDER_PASSWORD: &str = "__VELA_PLACEHOLDER_PASSWORD_DO_NOT_SEND__";

/// Ceiling on how long a page's script may run before it is abandoned.
const SCRIPT_STEP_LIMIT: usize = 2_000_000;

/// A request the page's script asked to make.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapturedRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsLoginError {
    /// The page ran but never asked to send anything.
    NoRequestCaptured,
    /// The script asked to send somewhere off the site.
    CrossSiteRequest(String),
    /// The placeholder survived into the body, so substitution failed and the
    /// request would have gone out with a marker where the password belongs.
    SubstitutionFailed,
    /// The runtime refused or gave up.
    Script(String),
    /// Built without the feature.
    Unavailable,
}

impl std::fmt::Display for JsLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRequestCaptured => write!(
                f,
                "This page's sign-in script did not produce a request VELA could \
                 send. Sign in here in the browser instead."
            ),
            Self::CrossSiteRequest(host) => write!(
                f,
                "This page's sign-in script tried to send your details to {host}, \
                 which is a different site. Nothing was sent."
            ),
            Self::SubstitutionFailed => write!(
                f,
                "VELA could not place your password into the request this page \
                 builds, so it sent nothing."
            ),
            Self::Script(why) => write!(f, "This page's sign-in script could not be run: {why}"),
            Self::Unavailable => write!(f, "In-app login for JavaScript sites is not enabled"),
        }
    }
}

impl std::error::Error for JsLoginError {}

impl CapturedRequest {
    /// Put the real credential in, and refuse if it did not land.
    ///
    /// Taking `password` here and nowhere else is what keeps the plaintext out
    /// of the runtime: by the time this is called the sandbox has been dropped,
    /// and the only thing left is a string with a marker in it. The check that
    /// the marker is gone is not defensive politeness — a body still carrying it
    /// means the script encoded, hashed or re-encoded the field, and sending it
    /// would put a useless value where the site expects a password while looking
    /// to the user like a login was attempted.
    pub fn substitute(mut self, password: &str) -> Result<Self, JsLoginError> {
        if !self.body.contains(PLACEHOLDER_PASSWORD) {
            return Err(JsLoginError::SubstitutionFailed);
        }
        self.body = self.body.replace(PLACEHOLDER_PASSWORD, password);
        if self.body.contains(PLACEHOLDER_PASSWORD) {
            return Err(JsLoginError::SubstitutionFailed);
        }
        Ok(self)
    }

    /// Refuse a request aimed off the site, before anything is sent.
    pub fn check_same_site(&self, site: &Url) -> Result<(), JsLoginError> {
        let target = Url::parse(&self.url)
            .map_err(|e| JsLoginError::Script(format!("bad request URL: {e}")))?;
        // Same registrable host *and* same scheme — an http:// target must not be
        // treated as the same site as an https:// page (RT-12 http downgrade).
        if crate::login::site_key(&target) != crate::login::site_key(site)
            || target.scheme() != site.scheme()
        {
            return Err(JsLoginError::CrossSiteRequest(crate::login::site_key(
                &target,
            )));
        }
        Ok(())
    }
}

/// Run a page's login script and report the request it would have sent.
///
/// `username` is passed through because it is not a secret — the site is about
/// to be told it, and a script that branches on it (an e-mail domain check, say)
/// needs the real value to take the same branch. The password is not, and is not
/// available to this function by design: it takes no such argument.
#[cfg(feature = "js-login")]
pub fn capture_login_request(
    html: &str,
    page_url: &Url,
    username: &str,
) -> Result<CapturedRequest, JsLoginError> {
    use boa_engine::{js_string, Context, JsValue, NativeFunction, Source};

    let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));

    let mut context = Context::default();
    context
        .runtime_limits_mut()
        .set_loop_iteration_limit(SCRIPT_STEP_LIMIT as u64);

    // The DOM the script gets. Small on purpose: every API added here is another
    // thing a hostile page can reach, and the shim exists to let a login form
    // read its own fields, not to be a browser.
    let bootstrap = format!(
        r##"
        globalThis.__vela = {{ request: null, fields: {{}} }};

        // Field values the script will read back. The password is a marker; the
        // real one is substituted outside the runtime, after this has exited.
        __vela.fields["password"] = {password:?};
        __vela.fields["username"] = {username:?};

        // Built from the page's own inputs, so a script can look its fields up
        // however it likes — by id, by name, or by CSS.
        __vela.inputs = {inputs};

        function __velaSeed(type) {{
          if (type === "password") return __vela.fields["password"];
          if (type === "text" || type === "email" || type === "tel" || type === "")
            return __vela.fields["username"];
          return "";
        }}

        __vela.elements = __vela.inputs.map(function (spec) {{
          var el = {{
            id: spec.id, name: spec.name, type: spec.type, tagName: "INPUT",
            _value: __velaSeed(spec.type),
            addEventListener: function () {{}},
            removeEventListener: function () {{}},
            setAttribute: function () {{}},
            getAttribute: function (a) {{ return spec[a] !== undefined ? spec[a] : null; }},
            focus: function () {{}}, blur: function () {{}}, click: function () {{}},
            dispatchEvent: function () {{ return true; }},
          }};
          Object.defineProperty(el, "value", {{
            get: function () {{ return el._value; }},
            set: function (v) {{ el._value = String(v); }},
          }});
          return el;
        }});

        function __velaMatch(sel) {{
          var s = String(sel).trim();
          var found = null;
          __vela.elements.forEach(function (el) {{
            if (found) return;
            if (s.charAt(0) === "#" && el.id === s.slice(1)) found = el;
            else if (el.name && s === "[name=" + el.name + "]") found = el;
            else if (el.name && s === "[name='" + el.name + "']") found = el;
            else if (el.name && s === 'input[name="' + el.name + '"]') found = el;
            else if (s.toLowerCase().indexOf("type=password") >= 0 && el.type === "password") found = el;
            else if (s.toLowerCase().indexOf("type=email") >= 0 && el.type === "email") found = el;
          }});
          if (found) return found;
          // Last resort, for scripts that select by a class or a wrapper: fall
          // back on intent, the way the form parser does.
          var lowered = String(sel).toLowerCase();
          if (lowered.indexOf("pass") >= 0) return __velaByType("password");
          if (lowered.indexOf("user") >= 0 || lowered.indexOf("email") >= 0
              || lowered.indexOf("login") >= 0) return __velaByType("text");
          return null;
        }}

        function __velaByType(type) {{
          var found = null;
          __vela.elements.forEach(function (el) {{
            if (!found && el.type === type) found = el;
          }});
          if (!found && type === "text") {{
            __vela.elements.forEach(function (el) {{
              if (!found && el.type !== "password") found = el;
            }});
          }}
          return found;
        }}

        function __velaElement(name, type) {{
          return {{
            name: name, type: type, tagName: "DIV", value: "",
            addEventListener: function () {{}}, setAttribute: function () {{}},
            getAttribute: function () {{ return null; }},
            appendChild: function () {{}},
            focus: function () {{}}, blur: function () {{}}, click: function () {{}},
          }};
        }}

        globalThis.document = {{
          location: {{ href: {href:?}, origin: {origin:?} }},
          querySelector: __velaMatch,
          querySelectorAll: function (sel) {{ var e = __velaMatch(sel); return e ? [e] : []; }},
          getElementById: function (id) {{
            var found = null;
            __vela.elements.forEach(function (el) {{ if (!found && el.id === id) found = el; }});
            return found;
          }},
          getElementsByName: function (n) {{
            return __vela.elements.filter(function (el) {{ return el.name === n; }});
          }},
          createElement: function (tag) {{ return __velaElement("", String(tag)); }},
          addEventListener: function () {{}},
          body: __velaElement("", "BODY"),
          forms: [],
          cookie: "",
        }};
        globalThis.window = globalThis;
        globalThis.location = document.location;
        globalThis.navigator = {{ userAgent: "VELA", language: "en" }};
        globalThis.localStorage = {{
          getItem: function () {{ return null; }},
          setItem: function () {{}}, removeItem: function () {{}},
        }};
        globalThis.sessionStorage = globalThis.localStorage;
        globalThis.setTimeout = function (fn) {{ if (typeof fn === "function") fn(); return 0; }};
        globalThis.clearTimeout = function () {{}};
        globalThis.console = {{ log: function () {{}}, warn: function () {{}}, error: function () {{}} }};

        // The only way out. It records and resolves; it does not send. There is
        // no socket behind this and nothing in the runtime that could open one.
        globalThis.fetch = function (url, init) {{
          init = init || {{}};
          var headers = {{}};
          if (init.headers) {{
            for (var k in init.headers) headers[k] = String(init.headers[k]);
          }}
          var body = init.body;
          if (body && typeof body !== "string") body = JSON.stringify(body);
          __vela_capture(String(url), String(init.method || "GET"),
                         JSON.stringify(headers), String(body || ""));
          return Promise.resolve({{
            ok: true, status: 200,
            json: function () {{ return Promise.resolve({{}}); }},
            text: function () {{ return Promise.resolve(""); }},
          }});
        }};
        globalThis.XMLHttpRequest = function () {{
          var self = this;
          this.open = function (m, u) {{ self._m = m; self._u = u; }};
          this.setRequestHeader = function (k, v) {{ (self._h = self._h || {{}})[k] = v; }};
          this.send = function (b) {{
            __vela_capture(String(self._u), String(self._m || "GET"),
                           JSON.stringify(self._h || {{}}), String(b || ""));
          }};
        }};
        "##,
        password = PLACEHOLDER_PASSWORD,
        username = username,
        href = page_url.as_str(),
        origin = page_url.origin().ascii_serialization(),
        inputs = serde_json::to_string(
            &extract_inputs(html)
                .into_iter()
                .map(|(id, name, kind)| {
                    serde_json::json!({ "id": id, "name": name, "type": kind })
                })
                .collect::<Vec<_>>()
        )
        .unwrap_or_else(|_| "[]".to_string()),
    );

    let sink = captured.clone();
    let capture_fn = move |_this: &JsValue, args: &[JsValue], ctx: &mut Context| {
        let mut text = |i: usize| -> String {
            args.get(i)
                .and_then(|v| v.to_string(ctx).ok())
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default()
        };
        let headers: BTreeMap<String, String> =
            serde_json::from_str(&text(2)).unwrap_or_default();
        let request = CapturedRequest {
            url: text(0),
            method: text(1).to_uppercase(),
            headers,
            body: text(3),
        };
        // First one wins: a login page that fires analytics after the login
        // should not overwrite what we came for.
        let mut slot = sink.lock().expect("capture mutex");
        if slot.is_none() {
            *slot = Some(request);
        }
        Ok(JsValue::undefined())
    };

    context
        .register_global_builtin_callable(
            js_string!("__vela_capture"),
            4,
            unsafe { NativeFunction::from_closure(capture_fn) },
        )
        .map_err(|e| JsLoginError::Script(e.to_string()))?;

    context
        .eval(Source::from_bytes(&bootstrap))
        .map_err(|e| JsLoginError::Script(format!("shim failed: {e}")))?;

    for script in inline_scripts(html) {
        // A page's scripts are written for a browser and will hit things this
        // shim does not have. One throwing is ordinary; it is only fatal if
        // nothing gets captured, which the caller finds out below.
        let _ = context.eval(Source::from_bytes(script.as_bytes()));
    }

    // Then the submit handlers, if the script registered its work behind one.
    for attempt in [
        "if (typeof onLoginSubmit === 'function') onLoginSubmit();",
        "if (typeof login === 'function') login();",
        "if (typeof signIn === 'function') signIn();",
        "if (typeof submitLogin === 'function') submitLogin();",
    ] {
        if captured.lock().expect("capture mutex").is_some() {
            break;
        }
        let _ = context.eval(Source::from_bytes(attempt.as_bytes()));
    }

    let request = captured
        .lock()
        .expect("capture mutex")
        .clone()
        .ok_or(JsLoginError::NoRequestCaptured)?;

    // Resolve a relative URL against the page before the caller sees it, so the
    // same-site check has something absolute to judge.
    let absolute = page_url
        .join(&request.url)
        .map_err(|e| JsLoginError::Script(format!("bad request URL: {e}")))?;

    Ok(CapturedRequest {
        url: absolute.to_string(),
        ..request
    })
}

#[cfg(not(feature = "js-login"))]
pub fn capture_login_request(
    _html: &str,
    _page_url: &Url,
    _username: &str,
) -> Result<CapturedRequest, JsLoginError> {
    Err(JsLoginError::Unavailable)
}

/// The inputs the page actually has.
///
/// The first version of the shim guessed from the selector string — if it
/// contained "password", hand back a password field. That fails on the ordinary
/// case of `getElementById("p")`, because the meaning is in the *page*, not in
/// the selector. So the element table is built from the HTML and the script
/// looks things up in it, which is also what a browser does.
#[cfg(feature = "js-login")]
fn extract_inputs(html: &str) -> Vec<(String, String, String)> {
    use scraper::{Html, Selector};
    let document = Html::parse_document(html);
    let selector = Selector::parse("input, textarea").expect("static selector");
    document
        .select(&selector)
        .map(|e| {
            let v = e.value();
            (
                v.attr("id").unwrap_or("").to_string(),
                v.attr("name").unwrap_or("").to_string(),
                v.attr("type").unwrap_or("text").to_lowercase(),
            )
        })
        .collect()
}

/// Pull `<script>` bodies out of the page.
///
/// Inline only. A `src=` script is another fetch and another decision about what
/// the runtime is allowed to load, and a prototype should not quietly acquire
/// the ability to pull arbitrary code off the network.
fn inline_scripts(html: &str) -> Vec<String> {
    use scraper::{Html, Selector};
    let document = Html::parse_document(html);
    let selector = Selector::parse("script").expect("static selector");
    document
        .select(&selector)
        .filter(|s| s.value().attr("src").is_none())
        .map(|s| s.text().collect::<String>())
        .filter(|s| !s.trim().is_empty())
        .collect()
}

#[cfg(test)]
mod tests;
