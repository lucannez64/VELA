//! Dump the DOM/shadow structure of a login page, to see why the fill cannot
//! find the password field (closed shadow root? email-first form? late render?).
//!
//!   cargo run --features browser-login --example inspect_page -- <url>

use std::time::Duration;

use serde_json::Value;

use vela_desktop_core::browser::{cdp, host};

#[tokio::main]
async fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://authenticate.riotgames.com/login".to_string());

    let browser = host::spawn().await.expect("spawn");
    let ws = host::websocket_url(browser.debug_port()).await.expect("ws");
    let cdp = cdp::Cdp::connect(&ws).await.expect("cdp");
    let (session, _target) = cdp::create_page_session(&cdp).await.expect("session");
    cdp::navigate_and_wait(&cdp, &session, &url, Duration::from_secs(90)).await.expect("nav");

    // Let any app JS settle, then dump.
    for wait in [0u64, 3, 8] {
        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
        println!("=== after {wait}s ===");
        let script = r#"
            (() => {
              const report = { inputs: [], customElements: [], shadowDepths: {}, buttons: [], pageText: '' };
              const walk = (root, depth) => {
                root.querySelectorAll('*').forEach((el) => {
                  if (el.matches && el.matches('input, textarea, select, button')) {
                    report.inputs.push({
                      tag: el.tagName, type: el.type || null, name: el.name || null,
                      id: el.id || null, shadowDepth: depth,
                      text: (el.textContent || el.value || '').trim().slice(0, 60),
                    });
                  }
                  const tag = el.tagName || '';
                  if (tag.includes('-')) report.customElements.push(tag);
                  if (el.shadowRoot) {
                    report.shadowDepths[tag] = (report.shadowDepths[tag] || 0) + 1;
                    walk(el.shadowRoot, depth + 1);
                  }
                });
              };
              walk(document, 0);
              report.pageText = (document.body ? document.body.innerText : '').slice(0, 800);
              return report;
            })()
        "#;
        let response = cdp::evaluate(&cdp, &session, script).await;
        if let Ok(r) = response {
            let value = r.get("result").and_then(|x| x.get("value")).cloned().unwrap_or(Value::Null);
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
        }
    }

    drop(browser);
}
