use crate::AppState;
use std::sync::Arc;
use tauri::{command, AppHandle, Emitter, State};
use vela_desktop_core::commands::session as core;
use vela_desktop_core::session::SessionStatus;

#[command]
pub async fn get_session_status(state: State<'_, Arc<AppState>>) -> Result<SessionStatus, String> {
    core::get_session_status(&state).await
}

#[command]
pub async fn lock_session(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    core::lock_session(&state);
    // Emit the same event the tray "Lock Now" path emits, so every caller of
    // this command — the UI lock buttons and the idle-timeout effect, not
    // just the tray — triggers one consistent frontend cleanup (clipboard,
    // in-memory items/selectedItem) instead of each call site reimplementing
    // its own subset.
    let _ = app.emit("session-locked", ());
    Ok(())
}

#[command]
pub async fn unlock_session(
    state: State<'_, Arc<AppState>>,
    _device_id: String,
    _user_id: String,
) -> Result<SessionStatus, String> {
    core::unlock_session(&state).await
}

#[command]
pub async fn unlock_session_with_password(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> Result<SessionStatus, String> {
    core::unlock_session_with_password(&state, password).await
}

#[command]
pub async fn create_vault(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    core::create_vault(&state).await
}

#[command]
pub async fn create_vault_with_password(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> Result<(), String> {
    core::create_vault_with_password(&state, password).await
}

#[command]
pub async fn check_vault_exists(state: State<'_, Arc<AppState>>) -> Result<bool, String> {
    Ok(core::check_vault_exists(&state))
}

#[command]
pub async fn reset_vault(
    state: State<'_, Arc<AppState>>,
    confirm: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    core::reset_vault(&state, confirm, password).await
}

#[command]
pub async fn get_device_id(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    core::get_device_id(&state)
}
