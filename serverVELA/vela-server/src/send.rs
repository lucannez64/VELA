//! One-off share links — send a secret to someone who does not use VELA.
//!
//! Unlike cross-user sharing (M19), there is no recipient identity and so no
//! `share_ek` to seal a KEM capsule to. Instead the client generates a random
//! 256-bit *link key*, seals the item with it (plus an optional Argon2id-stretched
//! passphrase), and puts the key in the URL **fragment** of the link it hands
//! out. Browsers never transmit the fragment, so this server stores and serves
//! only ciphertext it can never open — the same zero-knowledge property as the
//! rest of the vault, extended to an anonymous reader.
//!
//! Access is bounded server-side: every link has an expiry, and optionally a
//! view count, a view-once flag, and a passphrase the recipient must also know.
//! `GET /send/:id` consumes one view atomically and reports every failure as the
//! same `404`, so the endpoint is not an existence oracle.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    db,
    error::{AppError, Result},
    middleware::{maybe_append_new_token, DeviceSession},
    net, rate_limit,
    sqldb::TursoDb,
    state::AppState,
};
use vela_share_policy::send_driver::SendFailure;
use vela_share_policy::store::{self, ReadOutcome, SendCell};

#[cfg(test)]
mod conformance;
mod sql;

use sql::SendSql;

/// A link carries one item (or note); generous for a large secure note, far
/// below inbox-sized payloads.
const MAX_SEND_BYTES: usize = 256 * 1024;
/// The owner listing's page size, the number its SQL has always used.
const OWN_SENDS_LIMIT: usize = 200;
/// Same message for missing, expired, revoked and exhausted, so a `404` never
/// confirms that a link id is (or was) live.
const SEND_NOT_FOUND: &str = "send not found";

// ── POST /send (owner, authenticated) ────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSendRequest {
    /// The sealed item, base64 (standard). The server never sees the key.
    pub ciphertext: String,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default)]
    pub max_views: Option<i64>,
    #[serde(default)]
    pub view_once: bool,
    #[serde(default)]
    pub has_passphrase: bool,
    /// Argon2id salt (base64) required when `has_passphrase` is set.
    #[serde(default)]
    pub kdf_salt: Option<String>,
    /// Owner-side label; never returned to the recipient.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct CreateSendResponse {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// The I/O behind one create request. Decoding is a request observation (the
/// driver decides whether it is admissible); the insert uses only the driver's
/// permit, so the clamped TTL/view bounds cannot drift from the proof.
struct CreateSendIo<S> {
    sql: S,
    owner_user_id: Uuid,
    ciphertext: Vec<u8>,
    has_passphrase: bool,
    kdf_salt: Option<String>,
    label: Option<String>,
    id: Uuid,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    error: Option<AppError>,
}

impl<S: SendSql> CreateSendIo<S> {
    async fn insert_send(
        &mut self,
        permit: vela_share_policy::send_driver::CreatePermit,
    ) -> vela_share_policy::send_driver::RowsObservation {
        self.expires_at = self.now + chrono::Duration::seconds(permit.ttl_secs());
        let max_views = if permit.max_views_present() {
            Some(permit.max_views())
        } else {
            None
        };
        let plan = store::plan_send_create(
            self.id.to_string(),
            self.owner_user_id.to_string(),
            db::encode_b64(&self.ciphertext),
            self.has_passphrase,
            self.kdf_salt.clone(),
            self.label.clone(),
            permit.view_once(),
            max_views,
            self.now.to_rfc3339(),
            self.expires_at.to_rfc3339(),
        );
        let (outcomes, error) = sql::run_writes(&mut self.sql, &plan).await;
        let observation = store::classify_send_create(&outcomes);
        if let Some(error) = error {
            self.error = Some(AppError::Internal(error.to_string()));
        }
        observation
    }

    /// Unreachable for a create request: the driver's request kind never emits
    /// a fetch/delete effect. Reported as a storage failure rather than a panic.
    async fn consume_view(&mut self) -> vela_share_policy::send_driver::ConsumeObservation {
        self.error = Some(AppError::Internal(
            "send create driver emitted a fetch effect".into(),
        ));
        vela_share_policy::send_driver::ConsumeObservation::Error
    }

    async fn read_send(&mut self) -> vela_share_policy::send_driver::ReadObservation {
        self.error = Some(AppError::Internal(
            "send create driver emitted a read effect".into(),
        ));
        vela_share_policy::send_driver::ReadObservation::Unreadable
    }

    async fn remove_fetched(&mut self) -> vela_share_policy::send_driver::RemoveObservation {
        self.error = Some(AppError::Internal(
            "send create driver emitted a cleanup effect".into(),
        ));
        vela_share_policy::send_driver::RemoveObservation {
            removed: false,
            failed: true,
        }
    }

    async fn delete_link(
        &mut self,
        _permit: vela_share_policy::send_driver::DeletePermit,
    ) -> vela_share_policy::send_driver::RowsObservation {
        self.error = Some(AppError::Internal(
            "send create driver emitted a delete effect".into(),
        ));
        vela_share_policy::send_driver::RowsObservation {
            rows: 0,
            failed: true,
        }
    }
}

pub async fn post_share_link(
    State(state): State<AppState>,
    session: DeviceSession,
    Json(body): Json<CreateSendRequest>,
) -> Result<(HeaderMap, Json<CreateSendResponse>)> {
    rate_limit::send_create_by_user(&state.store, &session.user_id.to_string())?;

    let (ciphertext_decode_failed, ciphertext) = match B64.decode(&body.ciphertext) {
        Ok(bytes) => (false, bytes),
        Err(_) => (true, Vec::new()),
    };
    let (kdf_salt_present, kdf_salt_decode_failed, kdf_salt_len, kdf_salt) =
        match (body.has_passphrase, body.kdf_salt.as_deref()) {
            (true, Some(salt)) => match B64.decode(salt.as_bytes()) {
                Ok(bytes) => (true, false, bytes.len() as i64, Some(db::encode_b64(&bytes))),
                Err(_) => (true, true, 0, None),
            },
            (true, None) => (false, false, 0, None),
            (false, _) => (false, false, 0, None),
        };

    let id = Uuid::new_v4();
    let now = Utc::now();
    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let start = vela_share_policy::send_interpreter::start_create(
        vela_share_policy::send_driver::CreateObservation {
            owner_present: !session.user_id.is_nil(),
            ciphertext_decode_failed,
            ciphertext_len: ciphertext.len() as i64,
            has_passphrase: body.has_passphrase,
            kdf_salt_present,
            kdf_salt_decode_failed,
            kdf_salt_len,
            has_ttl: body.ttl_secs.is_some(),
            ttl_secs: body.ttl_secs.unwrap_or(0),
            has_max_views: body.max_views.is_some(),
            max_views: body.max_views.unwrap_or(0),
            view_once: body.view_once,
        },
    );
    let mut io = CreateSendIo {
        sql: sql::PoolSql(&state.sqldb),
        owner_user_id: session.user_id,
        ciphertext,
        has_passphrase: body.has_passphrase,
        kdf_salt,
        label,
        id,
        now,
        expires_at: now,
        error: None,
    };
    let transition = vela_share_policy::send_interpreter!(io, start, await);

    match transition.effect {
        vela_share_policy::send_driver::SendEffect::CompleteCreate => {}
        vela_share_policy::send_driver::SendEffect::Fail(failure) => {
            return Err(send_failure_error(failure, io.error.take()));
        }
        _ => {
            return Err(AppError::Internal(
                "send create driver produced an unexpected completion effect".into(),
            ))
        }
    }

    tracing::info!(
        send_id = %id,
        owner = %session.user_id,
        bytes = io.ciphertext.len(),
        "share link created"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(CreateSendResponse {
            id,
            expires_at: io.expires_at,
        }),
    ))
}

#[derive(Serialize)]
pub struct FetchSendResponse {
    pub ciphertext: String,
    pub has_passphrase: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    pub view_once: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_views: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub views_remaining: Option<i64>,
    pub expires_at: DateTime<Utc>,
}

/// The I/O behind one anonymous fetch. The atomic consume, the row read and the
/// view-once cleanup are the driver's effects; the response data is what the
/// read returned.
struct FetchSendIo<S> {
    sql: S,
    id: Uuid,
    ciphertext: Option<String>,
    has_passphrase: bool,
    kdf_salt: Option<String>,
    view_once: bool,
    max_views: Option<i64>,
    view_count: i64,
    expires_at: Option<DateTime<Utc>>,
    error: Option<AppError>,
}

impl<S: SendSql> FetchSendIo<S> {
    async fn consume_view(&mut self) -> vela_share_policy::send_driver::ConsumeObservation {
        let now = Utc::now().to_rfc3339();
        let plan = store::plan_send_consume(self.id.to_string(), now);
        let (outcomes, error) = sql::run_writes(&mut self.sql, &plan).await;
        let observation = store::classify_send_consume(&outcomes);
        if let Some(error) = error {
            self.error = Some(AppError::Internal(error.to_string()));
        }
        observation
    }

    async fn read_send(&mut self) -> vela_share_policy::send_driver::ReadObservation {
        let plan = store::plan_send_read(self.id.to_string());
        let outcome = match sql::run_read(&mut self.sql, &plan).await {
            Ok(rows) => ReadOutcome::Row(sql::send_row_view(&rows)),
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                ReadOutcome::Failed
            }
        };
        let observation = store::classify_send_read(&outcome);
        if let Some(cell) = observation.missing_cell {
            let message = match cell {
                SendCell::Ciphertext => "send row missing ciphertext",
                SendCell::ExpiresAt => "send row missing expires_at",
            };
            self.error = Some(AppError::Internal(message.into()));
        }
        self.ciphertext = observation.ciphertext;
        self.has_passphrase = observation.has_passphrase;
        self.kdf_salt = observation.kdf_salt;
        self.view_once = observation.view_once;
        self.max_views = observation.max_views;
        self.view_count = observation.view_count;
        self.expires_at = observation
            .expires_at
            .as_deref()
            .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
            .map(|at| at.with_timezone(&Utc));
        observation.read
    }

    async fn remove_fetched(&mut self) -> vela_share_policy::send_driver::RemoveObservation {
        // A view-once link is deleted the moment it is served; the conditional
        // update above guarantees only one caller ever reaches this point. The
        // handler ignores the cleanup outcome.
        let plan = store::plan_send_remove(self.id.to_string());
        let (outcomes, _error) = sql::run_writes(&mut self.sql, &plan).await;
        store::classify_send_remove(&outcomes)
    }

    /// Unreachable for a fetch request: the driver's request kind never emits
    /// an insert/delete-owner effect.
    async fn insert_send(
        &mut self,
        _permit: vela_share_policy::send_driver::CreatePermit,
    ) -> vela_share_policy::send_driver::RowsObservation {
        self.error = Some(AppError::Internal(
            "send fetch driver emitted an insert effect".into(),
        ));
        vela_share_policy::send_driver::RowsObservation {
            rows: 0,
            failed: true,
        }
    }

    async fn delete_link(
        &mut self,
        _permit: vela_share_policy::send_driver::DeletePermit,
    ) -> vela_share_policy::send_driver::RowsObservation {
        self.error = Some(AppError::Internal(
            "send fetch driver emitted a delete effect".into(),
        ));
        vela_share_policy::send_driver::RowsObservation {
            rows: 0,
            failed: true,
        }
    }
}

pub async fn get_share_link(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<FetchSendResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::send_fetch_by_ip(&state.store, &ip)?;

    let start = vela_share_policy::send_interpreter::start_fetch();
    let mut io = FetchSendIo {
        sql: sql::PoolSql(&state.sqldb),
        id,
        ciphertext: None,
        has_passphrase: false,
        kdf_salt: None,
        view_once: false,
        max_views: None,
        view_count: 0,
        expires_at: None,
        error: None,
    };
    let transition = vela_share_policy::send_interpreter!(io, start, await);

    match transition.effect {
        vela_share_policy::send_driver::SendEffect::CompleteFetch => {}
        vela_share_policy::send_driver::SendEffect::Fail(failure) => {
            return Err(send_failure_error(failure, io.error.take()));
        }
        _ => {
            return Err(AppError::Internal(
                "send fetch driver produced an unexpected completion effect".into(),
            ))
        }
    }

    let Some(ciphertext) = io.ciphertext.take() else {
        return Err(AppError::Internal("send row missing ciphertext".into()));
    };
    let Some(expires_at) = io.expires_at else {
        return Err(AppError::Internal("send row missing expires_at".into()));
    };
    let views_remaining = io.max_views.map(|max| (max - io.view_count).max(0));

    Ok(Json(FetchSendResponse {
        ciphertext,
        has_passphrase: io.has_passphrase,
        kdf_salt: io.kdf_salt,
        view_once: io.view_once,
        max_views: io.max_views,
        views_remaining,
        expires_at,
    }))
}

// ── GET /sends (owner, authenticated, read-only) ─────────────────────────────

#[derive(Serialize)]
pub struct SendMeta {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub has_passphrase: bool,
    pub view_once: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_views: Option<i64>,
    pub view_count: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn list_share_links(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    rate_limit::send_list_by_user(&state.store, &session.user_id.to_string())?;

    let stmt = store::plan_own_sends(
        session.user_id.to_string(),
        Utc::now().to_rfc3339(),
        OWN_SENDS_LIMIT,
    );
    let rows = match sql::run_handler_read(&mut sql::PoolSql(&state.sqldb), &stmt).await {
        Ok(rows) => rows,
        Err(error) => return Err(AppError::Internal(error.to_string())),
    };
    let page = store::classify_listing(rows.len(), false, OWN_SENDS_LIMIT);

    let items: Vec<SendMeta> = rows[..page.keep]
        .iter()
        .filter_map(|row| {
            Some(SendMeta {
                id: row.uuid(0)?,
                label: row.text(1).map(String::from),
                has_passphrase: row.bool_int(2).unwrap_or(false),
                view_once: row.bool_int(3).unwrap_or(false),
                max_views: row.i64(4),
                view_count: row.i64(5).unwrap_or(0),
                created_at: row.timestamp(6)?,
                expires_at: row.timestamp(7)?,
            })
        })
        .collect();

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "sends": items }))))
}

/// The I/O behind one owner delete.
struct DeleteSendIo<S> {
    sql: S,
    id: Uuid,
    owner_user_id: Uuid,
    error: Option<AppError>,
}

impl<S: SendSql> DeleteSendIo<S> {
    async fn delete_link(
        &mut self,
        _permit: vela_share_policy::send_driver::DeletePermit,
    ) -> vela_share_policy::send_driver::RowsObservation {
        let plan =
            store::plan_send_delete(self.id.to_string(), self.owner_user_id.to_string());
        let (outcomes, error) = sql::run_writes(&mut self.sql, &plan).await;
        let observation = store::classify_send_delete(&outcomes);
        if let Some(error) = error {
            self.error = Some(AppError::Internal(error.to_string()));
        }
        observation
    }

    /// Unreachable for a delete request: the driver's request kind never emits
    /// a create/fetch effect.
    async fn insert_send(
        &mut self,
        _permit: vela_share_policy::send_driver::CreatePermit,
    ) -> vela_share_policy::send_driver::RowsObservation {
        self.error = Some(AppError::Internal(
            "send delete driver emitted an insert effect".into(),
        ));
        vela_share_policy::send_driver::RowsObservation {
            rows: 0,
            failed: true,
        }
    }

    async fn consume_view(&mut self) -> vela_share_policy::send_driver::ConsumeObservation {
        self.error = Some(AppError::Internal(
            "send delete driver emitted a consume effect".into(),
        ));
        vela_share_policy::send_driver::ConsumeObservation::Error
    }

    async fn read_send(&mut self) -> vela_share_policy::send_driver::ReadObservation {
        self.error = Some(AppError::Internal(
            "send delete driver emitted a read effect".into(),
        ));
        vela_share_policy::send_driver::ReadObservation::Unreadable
    }

    async fn remove_fetched(&mut self) -> vela_share_policy::send_driver::RemoveObservation {
        self.error = Some(AppError::Internal(
            "send delete driver emitted a cleanup effect".into(),
        ));
        vela_share_policy::send_driver::RemoveObservation {
            removed: false,
            failed: true,
        }
    }
}

pub async fn delete_share_link(
    State(state): State<AppState>,
    session: DeviceSession,
    Path(id): Path<Uuid>,
) -> Result<(HeaderMap, Json<serde_json::Value>)> {
    let start =
        vela_share_policy::send_interpreter::start_delete(!session.user_id.is_nil());
    let mut io = DeleteSendIo {
        sql: sql::PoolSql(&state.sqldb),
        id,
        owner_user_id: session.user_id,
        error: None,
    };
    let transition = vela_share_policy::send_interpreter!(io, start, await);

    let deleted = match transition.effect {
        vela_share_policy::send_driver::SendEffect::CompleteDelete { deleted } => deleted,
        vela_share_policy::send_driver::SendEffect::Fail(failure) => {
            return Err(send_failure_error(failure, io.error.take()));
        }
        _ => {
            return Err(AppError::Internal(
                "send delete driver produced an unexpected completion effect".into(),
            ))
        }
    };

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(serde_json::json!({ "deleted": deleted }))))
}

/// Render a driver failure with the handler's historical status and message.
/// Branches whose original error is request-dependent return the stored error.
fn send_failure_error(failure: SendFailure, error: Option<AppError>) -> AppError {
    let stored = |fallback: AppError| error.unwrap_or(fallback);
    match failure {
        SendFailure::Unauthenticated => AppError::Unauthorized("authentication required".into()),
        SendFailure::MalformedCiphertext => {
            AppError::BadRequest("ciphertext is not valid base64".into())
        }
        SendFailure::EmptyCiphertext => AppError::BadRequest("ciphertext is empty".into()),
        SendFailure::CiphertextTooLarge => AppError::PayloadTooLarge(format!(
            "ciphertext exceeds maximum size of {MAX_SEND_BYTES} bytes"
        )),
        SendFailure::MissingKdfSalt => {
            AppError::BadRequest("has_passphrase requires kdf_salt".into())
        }
        SendFailure::MalformedKdfSalt => {
            AppError::BadRequest("kdf_salt is not valid base64".into())
        }
        SendFailure::KdfSaltTooShort => AppError::BadRequest("kdf_salt is too short".into()),
        SendFailure::InsertStorage => {
            stored(AppError::Internal("send link insert failure".into()))
        }
        SendFailure::NotFound => AppError::NotFound(SEND_NOT_FOUND.into()),
        SendFailure::ConsumeStorage => {
            stored(AppError::Internal("send view consume failure".into()))
        }
        SendFailure::RowUnreadable => {
            stored(AppError::Internal("send row unreadable".into()))
        }
        SendFailure::DeleteStorage => {
            stored(AppError::Internal("send link delete failure".into()))
        }
    }
}

/// Periodically delete expired links so ciphertext does not outlive its TTL.
pub async fn cleanup_task(db: Arc<TursoDb>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10 * 60));
    loop {
        interval.tick().await;
        let stmt = store::plan_expired_sends_cleanup(Utc::now().to_rfc3339());
        let outcome = match sql::run_handler_write(&mut sql::PoolSql(&db), &stmt).await {
            Ok(purged) => store::HandlerOutcome::Written(purged),
            Err(e) => {
                tracing::error!(error = %e, "send cleanup task failed");
                store::HandlerOutcome::Failed
            }
        };
        let sweep = store::classify_sweep(&[outcome]);
        if !sweep.failed && sweep.purged > 0 {
            tracing::info!(purged = sweep.purged, "send-link cleanup");
        }
    }
}
