//! A minimal Chrome DevTools Protocol client, just enough for the
//! browser-driven login tier.
//!
//! Two layers. The transport is JSON-RPC over a WebSocket to a real browser
//! (`tokio-tungstenite`): a reader task resolves pending `call`s by `id` and
//! broadcasts events. On top of that, the handful of CDP domains the login
//! flow needs are wrapped with typed helpers — `Target`, `Page`, `Runtime`,
//! `Network`, `Fetch`.
//!
//! Deliberately hand-rolled rather than pulling in a full CDP crate: the
//! subset is small, the wire format is plain JSON, and a ~400-line auditable
//! client beats a heavyweight dependency in the process that holds the vault.
//! See `security/browser-driven-login-design.md` §4.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio_tungstenite::tungstenite::Message;

/// How long a CDP command may go unanswered before it is treated as a broken
/// connection. The login flow runs these against a real browser a human is
/// looking at; 30s per command is generous for any response and far short of
/// the multi-minute timeouts that let a wedged flow block the IPC handler.
const CDP_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A CDP event delivered to subscribers.
#[derive(Debug, Clone)]
pub struct Event {
    pub method: String,
    pub params: Value,
    pub session_id: Option<String>,
}

/// A live connection to a browser's debugging endpoint.
///
/// Cloning shares the same connection; dropping the last clone closes it.
#[derive(Clone)]
pub struct Cdp {
    outbound: mpsc::Sender<Outbound>,
    events: broadcast::Sender<Event>,
    next_id: Arc<AtomicU64>,
}

struct Outbound {
    id: u64,
    reply: oneshot::Sender<Result<Value, String>>,
    method: String,
    params: Value,
    session_id: Option<String>,
}

impl Cdp {
    /// Connect to a browser debugging WebSocket URL.
    pub async fn connect(ws_url: &str) -> Result<Self, String> {
        let (stream, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .map_err(|e| format!("could not connect to the browser's debug port: {e}"))?;
        let (mut write, mut read) = stream.split();
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(64);
        let (events_tx, _) = broadcast::channel::<Event>(256);
        let next_id = Arc::new(AtomicU64::new(1));
        let pending: Arc<RwLock<HashMap<u64, oneshot::Sender<Result<Value, String>>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Reader: responses resolve their pending call; events broadcast.
        let reader_pending = pending.clone();
        let reader_events = events_tx.clone();
        let reader = tokio::spawn(async move {
            while let Some(message) = read.next().await {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        tracing::warn!(
                            "browser login: the CDP connection errored: {error}"
                        );
                        break;
                    }
                };
                // A Close frame ends the connection — the browser dropped us.
                // Other non-text frames (the browser's own pings) are noise.
                if let Message::Close(_) = message {
                    tracing::warn!("browser login: the login browser closed the CDP connection");
                    break;
                }
                let Message::Text(text) = message else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                if let Some(id) = value.get("id").and_then(Value::as_u64) {
                    if let Some(reply) = reader_pending.write().await.remove(&id) {
                        let result = if let Some(error) = value.get("error") {
                            Err(error
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("CDP error")
                                .to_string())
                        } else {
                            Ok(value.get("result").cloned().unwrap_or(Value::Null))
                        };
                        let _ = reply.send(result);
                    }
                } else if let Some(method) = value.get("method").and_then(Value::as_str) {
                    let _ = reader_events.send(Event {
                        method: method.to_string(),
                        params: value.get("params").cloned().unwrap_or(Value::Null),
                        session_id: value
                            .get("sessionId")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    });
                }
            }
            tracing::warn!("browser login: the CDP connection to the login browser ended");
        });

        // Writer: send outbound calls, hold the oneshot by id for the reader.
        // The reply is parked *before* the message goes out, so a fast
        // response cannot arrive and be dropped as an unknown id.
        let writer_pending = pending;
        let writer = tokio::spawn(async move {
            while let Some(outbound) = outbound_rx.recv().await {
                let mut message = json!({
                    "id": outbound.id,
                    "method": outbound.method,
                    "params": outbound.params,
                });
                if let Some(session_id) = &outbound.session_id {
                    message["sessionId"] = json!(session_id);
                }
                let text = serde_json::to_string(&message).unwrap_or_default();
                writer_pending
                    .write()
                    .await
                    .insert(outbound.id, outbound.reply);
                if write.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        });

        let _ = (reader, writer);
        Ok(Self {
            outbound: outbound_tx,
            events: events_tx,
            next_id,
        })
    }

    /// A browser-scoped command.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.call_inner(method, params, None).await
    }

    /// A session-scoped command (a command against a specific page target).
    pub async fn call_scoped(
        &self,
        method: &str,
        params: Value,
        session_id: &str,
    ) -> Result<Value, String> {
        self.call_inner(method, params, Some(session_id.to_string()))
            .await
    }

    async fn call_inner(
        &self,
        method: &str,
        params: Value,
        session_id: Option<String>,
    ) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (reply, rx) = oneshot::channel();
        self.outbound
            .send(Outbound {
                id,
                reply,
                method: method.to_string(),
                params,
                session_id,
            })
            .await
            .map_err(|_| "the browser connection closed".to_string())?;
        // A browser that stopped answering (the debug websocket stalled or the
        // window was closed) must surface as an error, not wedge the login flow
        // — and behind it the IPC handler — forever. The reader task only
        // notices a *clean* close; a hung connection is indistinguishable from
        // a slow page without a per-call deadline.
        tokio::time::timeout(CDP_CALL_TIMEOUT, rx)
            .await
            .map_err(|_| {
                format!("{method}: the browser did not answer within {CDP_CALL_TIMEOUT:?}")
            })?
            .map_err(|_| "the browser connection closed".to_string())?
            .map_err(|e| format!("{method}: {e}"))
    }

    /// Subscribe to CDP events.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

/// Navigate a page target to `url` and wait for it to finish loading.
pub async fn navigate_and_wait(
    cdp: &Cdp,
    session: &str,
    url: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    cdp.call_scoped("Page.enable", json!({}), session).await?;
    let mut events = cdp.subscribe();
    cdp.call_scoped("Page.navigate", json!({ "url": url }), session).await?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() > deadline {
            return Err(format!("the page did not finish loading within {timeout:?}"));
        }
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
            .await
            .map_err(|_| "timed out waiting for the page".to_string())?
            .map_err(|_| "the browser connection closed".to_string())?;
        if event.session_id.as_deref() == Some(session) && event.method == "Page.loadEventFired" {
            return Ok(());
        }
    }
}

/// Run a JavaScript expression in the page and await its promise.
pub async fn evaluate(cdp: &Cdp, session: &str, expression: &str) -> Result<Value, String> {
    cdp.call_scoped(
        "Runtime.evaluate",
        json!({
            "expression": expression,
            "awaitPromise": true,
            "returnByValue": true,
        }),
        session,
    )
    .await
}

/// Create a fresh page target and attach to it, returning `(session_id,
/// target_id)`.
pub async fn create_page_session(cdp: &Cdp) -> Result<(String, String), String> {
    let created = cdp
        .call(
            "Target.createTarget",
            json!({ "url": "about:blank", "newWindow": false }),
        )
        .await?;
    let target_id = created
        .get("targetId")
        .and_then(Value::as_str)
        .ok_or_else(|| "the browser did not return a target id".to_string())?
        .to_string();
    let attached = cdp
        .call(
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
        )
        .await?;
    let session_id = attached
        .get("sessionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "the browser did not return a session id".to_string())?
        .to_string();
    Ok((session_id, target_id))
}

/// Close a page target.
pub async fn close_page_session(cdp: &Cdp, target_id: &str) {
    let _ = cdp.call("Target.closeTarget", json!({ "targetId": target_id })).await;
}
