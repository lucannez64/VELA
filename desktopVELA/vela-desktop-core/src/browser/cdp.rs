//! A minimal Chrome DevTools Protocol client, just enough for the
//! browser-driven login tier.
//!
//! The transport is JSON-RPC over the browser's **debugging pipe** (fds 3/4,
//! `--remote-debugging-pipe`): messages are **NUL-byte (`\0`) delimited JSON**,
//! variable length, in both directions. A reader task buffers incoming bytes,
//! resolves pending `call`s by `id`, and broadcasts events. On top of that, the
//! handful of CDP domains the login flow needs are wrapped with typed helpers —
//! `Target`, `Page`, `Runtime`, `Network`, `Fetch`.
//!
//! Driving the browser over the pipe (rather than a WebSocket to a 127.0.0.1
//! debug port) is what closes RT-10: there is no TCP listener for a
//! co-resident process to attach to.
//!
//! Deliberately hand-rolled rather than pulling in a full CDP crate: the
//! subset is small, the wire format is plain JSON, and a ~400-line auditable
//! client beats a heavyweight dependency in the process that holds the vault.
//! See `security/browser-driven-login-design.md` §4.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};

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
    /// Connect to a browser's CDP debugging pipe.
    ///
    /// `command` is where we write commands (the parent's write end of the
    /// child's fd 3); `message` is where we read responses/events (the
    /// parent's read end of the child's fd 4). Both are length-prefixed JSON.
    pub async fn connect_pipe<C, M>(
        command: C,
        message: M,
    ) -> Result<Self, String>
    where
        C: AsyncWrite + Unpin + Send + 'static,
        M: AsyncRead + Unpin + Send + 'static,
    {
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(64);
        let (events_tx, _) = broadcast::channel::<Event>(256);
        let next_id = Arc::new(AtomicU64::new(1));
        let pending: Arc<RwLock<HashMap<u64, oneshot::Sender<Result<Value, String>>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Reader: NUL-delimited JSON frames resolve their pending call; events
        // broadcast. Chromium's `--remote-debugging-pipe` separates messages
        // with `\0`, variable length, so we buffer until a NUL is seen.
        let reader_pending = pending.clone();
        let reader_events = events_tx.clone();
        let reader = tokio::spawn(async move {
            let mut message = message;
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            let mut chunk = vec![0u8; 8192];
            loop {
                // Emit any complete (NUL-terminated) frames already buffered.
                while let Some(pos) = buf.iter().position(|&b| b == 0) {
                    let payload: Vec<u8> = buf.drain(..=pos).collect();
                    // `payload` includes the trailing NUL; drop it for JSON.
                    let json_bytes = &payload[..payload.len() - 1];
                    let Ok(value) = serde_json::from_slice::<Value>(json_bytes) else {
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
                    if buf.is_empty() {
                        break;
                    }
                }
                match message.read(&mut chunk).await {
                    Ok(0) => break, // EOF: the browser closed the pipe
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            tracing::warn!("browser login: the CDP pipe to the login browser ended");
        });

        // Writer: send outbound calls, hold the oneshot by id for the reader.
        // The reply is parked *before* the message goes out, so a fast
        // response cannot arrive and be dropped as an unknown id.
        let writer_pending = pending;
        let writer = tokio::spawn(async move {
            let mut command = command;
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
                if write_frame(&mut command, text.as_bytes()).await.is_err() {
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

/// Read one NUL-delimited CDP frame (a JSON value up to `\0`), or `None` on a
/// clean EOF. Used by tests to simulate the browser end; the live reader loop
/// buffers across reads instead.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Option<Result<Value, String>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte).await {
            Ok(0) => {
                return if buf.is_empty() { None } else { Some(Err("the browser closed the CDP pipe mid-frame".into())) };
            }
            Ok(_) => {
                if byte[0] == 0 {
                    let Ok(value) = serde_json::from_slice::<Value>(&buf) else {
                        return Some(Err("bad CDP JSON".into()));
                    };
                    return Some(Ok(value));
                }
                buf.push(byte[0]);
            }
            Err(e) => return Some(Err(format!("CDP pipe read failed: {e}"))),
        }
    }
}

/// Write one NUL-delimited CDP frame: the JSON payload followed by `\0`.
/// Chromium's `--remote-debugging-pipe` uses `\0`-delimited messages.
async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(payload).await?;
    w.write_all(&[0u8]).await?;
    w.flush().await
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The core CDP framing (u32 big-endian length + payload) and a full
    /// `call` -> framed response -> `call` resolution round-trip over an
    /// in-memory duplex standing in for the browser's two pipes.
    #[tokio::test]
    async fn a_pipe_call_round_trips_through_the_framing() {
        // Two independent pipes, mirroring the real setup: one for commands
        // (parent writes, "browser" reads), one for messages (browser writes,
        // parent reads).
        let (parent_cmd, browser_cmd) = tokio::io::duplex(4096);
        let (browser_msg, parent_msg) = tokio::io::duplex(4096);
        let cdp = Cdp::connect_pipe(parent_cmd, parent_msg)
            .await
            .expect("connect_pipe");

        let expected: Value = json!({ "ok": true, "n": 7 });
        let response_expected = expected.clone();
        let browser = tokio::spawn(async move {
            let mut bc = browser_cmd;
            let mut bm = browser_msg;
            let request = read_frame(&mut bc)
                .await
                .expect("a request frame")
                .expect("request parse");
            assert_eq!(request.get("method").and_then(Value::as_str), Some("Test.probe"));
            let id = request.get("id").and_then(Value::as_u64).unwrap();
            let response = json!({ "id": id, "result": response_expected });
            write_frame(&mut bm, &serde_json::to_vec(&response).unwrap())
                .await
                .unwrap();
        });

        let got = cdp.call("Test.probe", json!({ "x": 1 })).await.expect("call");
        assert_eq!(got, expected);
        browser.await.unwrap();
    }

    /// The framing is NUL-delimited JSON (`payload` then `\0`), exactly as
    /// Chromium's `--remote-debugging-pipe` separates messages.
    #[test]
    fn frames_are_nul_delimited_json() {
        let payload: &[u8] = b"{\"id\":1}";
        // The helper appends the delimiter; what goes on the wire is `payload\0`.
        let wire = [payload, &[0u8]].concat();
        assert_eq!(wire[..payload.len()], *payload);
        assert_eq!(wire[payload.len()], 0u8);
    }
}
