//! Tests for the M9c prototype.
//!
//! The ones that matter are not "does it work" but "does the credential stay
//! out of it", because that is the single property that separates this from the
//! design `m9c_inprocess_sandbox.spthy` falsifies.

use super::*;

fn page(script: &str) -> String {
    format!(
        r#"<html><body>
        <form id="login">
          <input type="text" name="username" id="username">
          <input type="password" name="password" id="password">
        </form>
        <script>{script}</script></body></html>"#
    )
}

/// The shape this exists for: a page that reads its fields and posts JSON.
#[cfg(feature = "js-login")]
#[test]
fn a_fetch_login_is_captured() {
    let html = page(
        r#"
        function onLoginSubmit() {
          fetch("/api/session", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Csrf": "tok-77" },
            body: JSON.stringify({
              user: document.getElementById("username").value,
              pass: document.getElementById("password").value,
            }),
          });
        }
        "#,
    );

    let url = Url::parse("https://site.example/login").unwrap();
    let request = capture_login_request(&html, &url, "ada").unwrap();

    assert_eq!(request.url, "https://site.example/api/session");
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers.get("X-Csrf").map(String::as_str), Some("tok-77"));
    assert!(request.body.contains("\"user\":\"ada\""), "{}", request.body);
    // The marker, not a password — there was none to have.
    assert!(request.body.contains(PLACEHOLDER_PASSWORD), "{}", request.body);
}

/// The property the whole design rests on, checked at the boundary rather than
/// argued: there is no way to hand a credential to the runtime, because
/// `capture_login_request` takes no password. This test states that in a form
/// that would fail if the signature ever grew one.
#[cfg(feature = "js-login")]
#[test]
fn the_runtime_is_never_given_a_password() {
    let real = "correct-horse-battery-staple-9137";
    let html = page(
        r#"
        function onLoginSubmit() {
          fetch("/api/session", { method: "POST",
            body: JSON.stringify({ p: document.getElementById("password").value }) });
        }
        "#,
    );

    let url = Url::parse("https://site.example/login").unwrap();
    let captured = capture_login_request(&html, &url, "ada").unwrap();

    // Nothing the sandbox produced can contain a secret it was never given.
    let rendered = serde_json::to_string(&captured).unwrap();
    assert!(!rendered.contains(real), "{rendered}");

    // The credential meets the request only here, after the runtime is gone.
    let sent = captured.substitute(real).unwrap();
    assert!(sent.body.contains(real));
    assert!(!sent.body.contains(PLACEHOLDER_PASSWORD));
}

/// A script that hashes or re-encodes the field destroys the marker, and the
/// request would then go out with a wrong value where the password belongs —
/// looking, to the user, like a login that was attempted and refused. Better to
/// send nothing and say so.
#[test]
fn a_body_that_lost_the_marker_is_not_sent() {
    let mangled = CapturedRequest {
        url: "https://site.example/api/session".to_string(),
        method: "POST".to_string(),
        headers: BTreeMap::new(),
        body: r#"{"p":"5f4dcc3b5aa765d61d8327deb882cf99"}"#.to_string(),
    };
    assert_eq!(
        mangled.substitute("hunter2").unwrap_err(),
        JsLoginError::SubstitutionFailed
    );
}

/// Same origin rule as everywhere else in M9a, applied before anything is sent.
#[test]
fn a_request_aimed_off_the_site_is_refused() {
    let site = Url::parse("https://site.example/login").unwrap();
    let elsewhere = CapturedRequest {
        url: "https://collector.example/take".to_string(),
        method: "POST".to_string(),
        headers: BTreeMap::new(),
        body: format!("p={PLACEHOLDER_PASSWORD}"),
    };
    assert_eq!(
        elsewhere.check_same_site(&site).unwrap_err(),
        JsLoginError::CrossSiteRequest("collector.example".to_string())
    );

    let same = CapturedRequest {
        url: "https://api.site.example/session".to_string(),
        ..elsewhere
    };
    assert!(same.check_same_site(&site).is_ok());
}

/// An `http://` target is not the same site as an `https://` page — a scheme
/// change on the same host must not let a credential be sent in cleartext
/// (RT-12 http downgrade).
#[test]
fn an_http_request_is_refused_for_an_https_page() {
    let site = Url::parse("https://site.example/login").unwrap();
    let downgraded = CapturedRequest {
        url: "http://site.example/session".to_string(),
        method: "POST".to_string(),
        headers: BTreeMap::new(),
        body: format!("p={PLACEHOLDER_PASSWORD}"),
    };
    assert_eq!(
        downgraded.check_same_site(&site).unwrap_err(),
        JsLoginError::CrossSiteRequest("site.example".to_string())
    );
}

/// A page that never calls `fetch` gets an honest answer rather than a guess.
#[cfg(feature = "js-login")]
#[test]
fn a_page_that_sends_nothing_says_so() {
    let html = page("var x = 1;");
    let url = Url::parse("https://site.example/login").unwrap();
    assert_eq!(
        capture_login_request(&html, &url, "ada").unwrap_err(),
        JsLoginError::NoRequestCaptured
    );
}

/// The shim is small, so real scripts will throw on things it does not have.
/// One throwing must not lose a request another already captured.
#[cfg(feature = "js-login")]
#[test]
fn a_script_that_throws_does_not_discard_what_was_captured() {
    let html = format!(
        r#"<html><body>
        <script>
          fetch("/api/session", {{ method: "POST", body: "p={PLACEHOLDER_PASSWORD}" }});
        </script>
        <script>
          document.body.appendChild(document.createElement("div"));  // no such thing here
        </script></body></html>"#
    );
    let url = Url::parse("https://site.example/login").unwrap();
    let request = capture_login_request(&html, &url, "ada").expect("the first script's request");
    assert_eq!(request.url, "https://site.example/api/session");
}

/// XHR is still how plenty of older login pages submit.
#[cfg(feature = "js-login")]
#[test]
fn an_xhr_login_is_captured_too() {
    let html = page(
        r#"
        function onLoginSubmit() {
          var x = new XMLHttpRequest();
          x.open("POST", "/session");
          x.setRequestHeader("X-Requested-With", "XMLHttpRequest");
          x.send("password=" + document.getElementById("password").value);
        }
        "#,
    );
    let url = Url::parse("https://site.example/login").unwrap();
    let request = capture_login_request(&html, &url, "ada").unwrap();

    assert_eq!(request.url, "https://site.example/session");
    assert_eq!(request.method, "POST");
    assert!(request.body.contains(PLACEHOLDER_PASSWORD));
}

/// Analytics firing after the login must not replace the request we came for.
#[cfg(feature = "js-login")]
#[test]
fn the_first_request_wins() {
    let html = page(
        r#"
        function onLoginSubmit() {
          fetch("/api/session", { method: "POST", body: "real" });
          fetch("/api/telemetry", { method: "POST", body: "noise" });
        }
        "#,
    );
    let url = Url::parse("https://site.example/login").unwrap();
    let request = capture_login_request(&html, &url, "ada").unwrap();
    assert!(request.url.ends_with("/api/session"), "{}", request.url);
}
