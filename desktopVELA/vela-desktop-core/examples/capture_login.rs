//! Capture the login request a *manual* login produces in a fresh browser.
//!
//! Debugging tool: launches a disposable fresh-profile browser, arms request
//! interception, and logs every login-shaped request (fields, headers, body
//! size — password value redacted) while continuing it untouched. A human logs
//! in by hand in the window; the logged request shows exactly what the site
//! expects, to compare against the automated tier.
//!
//!   cargo run --features browser-login --example capture_login -- <login-url>

use std::time::Duration;

use serde_json::Value;
use url::Url;

use vela_desktop_core::browser::{cdp, host, intercept};

#[tokio::main]
async fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://rateyourmusic.com/account/login".to_string());

    let (browser, pipe) = host::spawn().await.expect("could not spawn the browser");
    let cdp = {
        let command = tokio::fs::File::from_std(std::fs::File::from(pipe.command));
        let message = tokio::fs::File::from_std(std::fs::File::from(pipe.message));
        cdp::Cdp::connect_pipe(command, message).await.expect("could not connect")
    };
    let (session, target_id) = cdp::create_page_session(&cdp).await.expect("session");

    cdp::navigate_and_wait(&cdp, &session, &url, Duration::from_secs(90))
        .await
        .expect("could not load the login page");
    intercept::enable(&cdp, &session).await.expect("could not enable interception");

    let target = Url::parse(&url).expect("bad url");
    println!(
        "CAPTURE READY: a fresh browser is open at {url}. Log in manually now. \
         (Ctrl+C or close the window when done.)"
    );

    let mut events = cdp.subscribe();
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    while std::time::Instant::now() < deadline {
        let event = match events.recv().await {
            Ok(e) => e,
            Err(_) => break,
        };
        if event.session_id.as_deref() != Some(&session) || event.method != "Fetch.requestPaused" {
            continue;
        }
        let Some(request_id) = event.params.get("requestId").and_then(Value::as_str) else {
            continue;
        };
        let request = event.params.get("request").cloned().unwrap_or(Value::Null);
        let req_url = request.get("url").and_then(Value::as_str).unwrap_or("?");
        let method = request.get("method").and_then(Value::as_str).unwrap_or("?");
        let body = request.get("postData").and_then(Value::as_str).unwrap_or("").to_string();
        let headers = request
            .get("headers")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let is_login = body.contains("password") || req_url.contains("login");
        if is_login {
            let redacted = body
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((k, _)) if k == "password" => format!("{k}=<REDACTED>"),
                    _ => pair.to_string(),
                })
                .collect::<Vec<_>>()
                .join("&");
            println!("=== LOGIN REQUEST ===");
            println!("method={method} url={req_url}");
            println!("headers={:?}", headers.keys().collect::<Vec<_>>());
            println!("content-length header={:?}", headers.get("content-length"));
            println!("sec-ch-ua header={:?}", headers.get("sec-ch-ua"));
            println!("body({} bytes)={}", body.len(), redacted);
        }

        // Continue it untouched so the manual login completes.
        let _ = cdp
            .call_scoped("Fetch.continueRequest", serde_json::json!({ "requestId": request_id }), &session)
            .await;
    }

    let _ = cdp::close_page_session(&cdp, &target_id).await;
    drop(browser);
    println!("capture window closed");
}
