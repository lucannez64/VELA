//! Server→client vault change notifications (SSE).
//!
//! Without this, a client only learns about another device's write on its next
//! scheduled sync. `GET /vault/events` is an authenticated, long-lived
//! `text/event-stream` that says "something in your vault changed" the moment a
//! write lands, so an open client can pull immediately instead of waiting.
//!
//! The event is deliberately content-free: it names the writing device, the
//! epoch and a per-server revision, never a chunk id, version or ciphertext.
//! The manifest (`GET /vault/sync`) remains the only way to learn *what*
//! changed, which keeps the server's access-pattern story unchanged — the
//! stream leaks timing (a write happened) only to the account that owns it.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use axum::{
    extract::State,
    http::HeaderMap,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures_util::{stream, StreamExt};
use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession},
    state::AppState,
};

/// How many unconsumed events a slow stream may lag before it is told to
/// resynchronise. Payloads are tiny; this only bounds per-subscriber memory.
const EVENT_BUFFER: usize = 256;

/// Cap on concurrent streams per account. Each stream is a few KB of state,
/// but an authenticated token must not be able to pin unbounded memory.
const MAX_STREAMS_PER_USER: usize = 8;

/// What kind of write produced an event. Kept coarse on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultChangeKind {
    Chunk,
    Oram,
    /// The account's served key epoch moved (a re-key committed).
    Epoch,
}

/// One vault change, fanned out to every stream of the owning account.
#[derive(Clone, Debug, Serialize)]
pub struct VaultChangeEvent {
    /// Monotonic across the server; lets a client notice gaps after a lag.
    pub revision: u64,
    /// Routed on; never serialised to a subscriber.
    #[serde(skip_serializing)]
    pub user_id: Uuid,
    /// The device that wrote. Receivers may ignore their own writes.
    pub writer: Uuid,
    pub epoch: i64,
    pub kind: VaultChangeKind,
}

/// Fan-out point for vault change notifications, one per server process.
pub struct VaultEventBus {
    tx: broadcast::Sender<VaultChangeEvent>,
    revision: AtomicU64,
    /// Live streams per account, so one token cannot open unbounded streams.
    active: Mutex<HashMap<Uuid, usize>>,
}

impl Default for VaultEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultEventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(EVENT_BUFFER);
        Self {
            tx,
            revision: AtomicU64::new(0),
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Publish a change and return its revision. No subscribers is normal
    /// (nobody has a stream open) and is not an error.
    pub fn publish(
        &self,
        user_id: Uuid,
        writer: Uuid,
        epoch: i64,
        kind: VaultChangeKind,
    ) -> u64 {
        let revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.tx.send(VaultChangeEvent {
            revision,
            user_id,
            writer,
            epoch,
            kind,
        });
        revision
    }

    pub fn subscribe(&self) -> broadcast::Receiver<VaultChangeEvent> {
        self.tx.subscribe()
    }

    /// Latest revision any stream has been told about. Sent in the opening
    /// `hello` so a reconnecting client can tell it missed changes.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    /// Reserve one of this account's stream slots. `false` means the cap is
    /// reached; the caller refuses the connection instead of piling up state.
    pub fn try_acquire_stream(&self, user: Uuid) -> bool {
        let mut active = self.active.lock().expect("event bus mutex poisoned");
        let count = active.entry(user).or_insert(0);
        if *count >= MAX_STREAMS_PER_USER {
            return false;
        }
        *count += 1;
        true
    }

    fn release_stream(&self, user: Uuid) {
        let mut active = self.active.lock().expect("event bus mutex poisoned");
        if let Some(count) = active.get_mut(&user) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&user);
            }
        }
    }
}

/// Releases a stream slot when the SSE connection ends for any reason: client
/// disconnect, handler drop, or broadcast channel close.
struct StreamLease {
    state: AppState,
    user_id: Uuid,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.state.vault_events.release_stream(self.user_id);
    }
}

/// `GET /vault/events` — the authenticated change stream.
///
/// Sends `hello` first (current revision + served epoch), then one `change`
/// per write by any device on the account, or `resync` if the subscriber fell
/// behind the broadcast buffer. Clients react by running their normal sync.
pub async fn get_events(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<impl IntoResponse> {
    let user_id = session.user_id;

    // A device whose local epoch is stale still gets events; `read_epoch` is
    // only informational here, and the sync it triggers does the adoption.
    let read_epoch = crate::vault::rekey::read_epoch(&state, &user_id.to_string()).await?;
    let revision = state.vault_events.revision();

    let hello = Event::default().event("hello").data(
        serde_json::json!({ "revision": revision, "epoch": read_epoch }).to_string(),
    );

    if !state.vault_events.try_acquire_stream(user_id) {
        return Err(AppError::RateLimited(
            "too many open vault event streams for this account".into(),
        ));
    }
    let lease = StreamLease {
        state: state.clone(),
        user_id,
    };

    let rx = state.vault_events.subscribe();
    let live = stream::unfold((rx, lease), move |(mut rx, lease)| async move {
        loop {
            match rx.recv().await {
                Ok(event) if event.user_id == user_id => {
                    let event = match event.kind {
                        VaultChangeKind::Epoch => {
                            // Not a write, so the writer/epoch of the CAS are
                            // not necessarily the writer of every old row.
                            Event::default().event("resync").data(
                                serde_json::json!({
                                    "revision": event.revision,
                                    "kind": "epoch",
                                })
                                .to_string(),
                            )
                        }
                        kind => Event::default().event("change").data(
                            serde_json::json!({
                                "revision": event.revision,
                                "writer": event.writer,
                                "epoch": event.epoch,
                                "kind": kind,
                            })
                            .to_string(),
                        ),
                    };
                    return Some((Ok::<Event, Infallible>(event), (rx, lease)));
                }
                // Another account's event is not addressable from this stream.
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    return Some((
                        Ok(Event::default().event("resync").data("{\"kind\":\"lagged\"}")),
                        (rx, lease),
                    ));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    let events_stream = stream::once(async move { Ok::<_, Infallible>(hello) }).chain(live);

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);

    Ok((
        headers,
        Sse::new(events_stream).keep_alive(
            // More frequent than any client's read timeout so a healthy idle
            // stream is never mistaken for a dead one.
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        ),
    ))
}

/// Parse errors from framing are impossible here (the payloads are built with
/// `json!`), so this is only useful for tests.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_bus_numbers_revisions_monotonically() {
        let bus = VaultEventBus::new();
        let user = Uuid::new_v4();
        let device = Uuid::new_v4();

        assert_eq!(bus.revision(), 0);
        let first = bus.publish(user, device, 1, VaultChangeKind::Chunk);
        let second = bus.publish(user, device, 1, VaultChangeKind::Oram);
        assert_eq!((first, second), (1, 2));
        assert_eq!(bus.revision(), 2);
    }

    #[tokio::test]
    async fn subscribers_only_see_their_own_accounts_events() {
        let bus = VaultEventBus::new();
        let user = Uuid::new_v4();
        let other = Uuid::new_v4();
        let device = Uuid::new_v4();

        let mut rx = bus.subscribe();
        bus.publish(other, device, 1, VaultChangeKind::Chunk);
        let mine = bus.publish(user, device, 7, VaultChangeKind::Chunk);

        // The bus delivers every account's events; `get_events` filters to the
        // authenticated user. Both arrive in publish order.
        let first = rx.recv().await.expect("event");
        assert_eq!(first.user_id, other);
        let event = rx.recv().await.expect("event");
        assert_eq!(event.revision, mine);
        assert_eq!(event.user_id, user);
        assert_eq!(event.epoch, 7);
        assert_eq!(event.kind, VaultChangeKind::Chunk);
    }

    #[test]
    fn wire_payload_never_carries_the_owner_id() {
        let event = VaultChangeEvent {
            revision: 4,
            user_id: Uuid::new_v4(),
            writer: Uuid::new_v4(),
            epoch: 2,
            kind: VaultChangeKind::Chunk,
        };
        let json = serde_json::to_value(&event).expect("serialize");
        assert!(json.get("user_id").is_none());
        assert_eq!(json["revision"], 4);
        assert_eq!(json["epoch"], 2);
        assert_eq!(json["kind"], "chunk");
        assert_eq!(json["writer"].as_str().unwrap().len(), 36);
    }

    #[test]
    fn stream_slots_are_capped_per_account_and_released() {
        let bus = VaultEventBus::new();
        let user = Uuid::new_v4();
        for _ in 0..MAX_STREAMS_PER_USER {
            assert!(bus.try_acquire_stream(user));
        }
        assert!(!bus.try_acquire_stream(user), "cap must be enforced");
        // Other accounts are unaffected by this account's streams.
        assert!(bus.try_acquire_stream(Uuid::new_v4()));
        // Releasing one frees exactly one slot.
        bus.release_stream(user);
        assert!(bus.try_acquire_stream(user));
    }
}
