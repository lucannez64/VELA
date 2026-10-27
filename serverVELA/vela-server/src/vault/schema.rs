//! Account-wide compatibility floor. Serialized with chunk writes so activation
//! cannot race an older client's previously-admitted upload or deletion.
use crate::{
    error::{AppError, Result},
    middleware::{AuthSession, DeviceSession},
    state::AppState,
};
use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};

type AccountLock = tokio::sync::Mutex<()>;

pub async fn lock(user: &str) -> tokio::sync::OwnedMutexGuard<()> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<AccountLock>>>> = OnceLock::new();
    let mutex = {
        let mut locks = LOCKS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        locks.retain(|_, weak| weak.strong_count() > 0);
        let mutex = locks
            .get(user)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| Arc::new(AccountLock::new(())));
        locks.insert(user.into(), Arc::downgrade(&mutex));
        mutex
    };
    mutex.lock_owned().await
}

pub fn minimum(state: &AppState, user: &str) -> Result<u32> {
    match state.store.get(&format!("vault-schema:{user}"))? {
        None => Ok(1),
        Some(bytes) if bytes == b"2" => Ok(2),
        _ => Err(AppError::Internal("Invalid vault schema floor".into())),
    }
}

pub fn check_write(state: &AppState, user: &str, headers: &HeaderMap) -> Result<()> {
    let supported = headers
        .get("x-vela-write-schema")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1);
    if supported < minimum(state, user)? {
        return Err(AppError::Conflict("This vault uses folders and richer fields. Upgrade this client before syncing changes.".into()));
    }
    Ok(())
}

#[derive(Serialize)]
pub struct SchemaStatus {
    pub minimum_write_schema: u32,
    pub supported_schema: u32,
}

pub async fn get_schema(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<SchemaStatus>> {
    Ok(Json(SchemaStatus {
        minimum_write_schema: minimum(&state, &session.user_id.to_string())?,
        supported_schema: 2,
    }))
}

/// The I/O behind `POST /vault/schema`. The extracted driver decides that the
/// one durable write runs; the method only performs it and reports the
/// observation, keeping the original error for the response.
struct ActivateIo<'a> {
    state: &'a AppState,
    user: String,
    error: Option<AppError>,
}

impl ActivateIo<'_> {
    async fn write_floor(
        &mut self,
    ) -> vela_rekey_policy::vault_mutation_driver::SchemaWriteObservation {
        use vela_rekey_policy::vault_mutation_driver::SchemaWriteObservation as O;
        match self
            .state
            .store
            .set_durable(&format!("vault-schema:{}", self.user), b"2")
        {
            Ok(()) => O::Written,
            Err(error) => {
                self.error = Some(error);
                O::Storage
            }
        }
    }
}

pub async fn activate(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<Json<SchemaStatus>> {
    use vela_rekey_policy::vault_mutation_driver::{
        SchemaEffect, SchemaFailure, SchemaRequest,
    };
    let user = session.0.user_id.to_string();
    let _guard = lock(&user).await;
    let mut io = ActivateIo {
        state: &state,
        user: user.clone(),
        error: None,
    };
    let transition = vela_rekey_policy::schema_interpreter!(
        io,
        SchemaRequest {
            authenticated: true,
            device_scope: true,
        },
        await
    );
    match transition.effect {
        SchemaEffect::Complete => Ok(Json(SchemaStatus {
            minimum_write_schema: 2,
            supported_schema: 2,
        })),
        SchemaEffect::Fail(failure) => {
            let recorded = io.error.take();
            Err(recorded.unwrap_or_else(|| match failure {
                SchemaFailure::Unauthenticated => {
                    AppError::Unauthorized("not authenticated".into())
                }
                SchemaFailure::WebSessionForbidden => {
                    AppError::Forbidden("a temporary web session cannot activate the vault schema".into())
                }
                SchemaFailure::WriteStorage => {
                    AppError::Internal("vault schema write failed".into())
                }
            }))
        }
        _ => Err(AppError::Internal(
            "schema activation did not reach a terminal decision".into(),
        )),
    }
}
