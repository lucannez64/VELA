//! `#[tauri::command]` wrappers for the vault: items, search, health,
//! generator, Bitwarden import/export, favicons and breach checks.
//!
//! Everything they do lives in [`vela_desktop_core::commands::vault`],
//! [`vela_desktop_core::breach`] and [`vela_desktop_core::favicon`]. The one
//! genuinely Tauri-shaped thing is [`emit_vault_items_changed`]: the webview
//! is a separate process holding its own copy of the item list, so every
//! mutation has to tell it to re-fetch. gpui has no renderer and re-reads
//! state directly after the awaited call returns.

use std::sync::Arc;

use tauri::{command, AppHandle, Emitter, State};

use crate::vault::{BreachEntry, PasswordGeneratorOptions, VaultItem};
use crate::AppState;

pub use vela_desktop_core::breach::PasswordBreachResult;
pub use vela_desktop_core::commands::vault::{
    ImportResult, PasswordStrength, PasswordWithStrength, VaultHealth,
};

pub const VAULT_ITEMS_CHANGED_EVENT: &str = "vault-items-changed";

pub fn emit_vault_items_changed(app: &AppHandle) {
    let _ = app.emit(VAULT_ITEMS_CHANGED_EVENT, ());
}

// ── items ────────────────────────────────────────────────────────────────

#[command]
pub async fn get_items(state: State<'_, Arc<AppState>>) -> Result<Vec<VaultItem>, String> {
    vela_desktop_core::commands::vault::get_items(&state)
}

#[command]
pub async fn get_item(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<Option<VaultItem>, String> {
    vela_desktop_core::commands::vault::get_item(&state, &id)
}

#[command]
pub async fn get_items_by_type(
    state: State<'_, Arc<AppState>>,
    item_type: String,
) -> Result<Vec<VaultItem>, String> {
    vela_desktop_core::commands::vault::get_items_by_type(&state, &item_type)
}

#[command]
pub async fn search_items(
    state: State<'_, Arc<AppState>>,
    query: String,
) -> Result<Vec<VaultItem>, String> {
    vela_desktop_core::commands::vault::search_items(&state, &query)
}

#[command]
pub async fn add_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item: VaultItem,
) -> Result<VaultItem, String> {
    // Delegates to the core (the thin-layer refactor on main), which applies
    // the same M9a unlock guard, typing, audit and persist internally.
    let added = vela_desktop_core::commands::vault::add_item(&state, item).await?;
    emit_vault_items_changed(&app);
    Ok(added)
}

#[command]
pub async fn update_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item: VaultItem,
) -> Result<VaultItem, String> {
    let updated = vela_desktop_core::commands::vault::update_item(&state, item).await?;
    emit_vault_items_changed(&app);
    Ok(updated)
}

#[command]
pub async fn delete_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), String> {
    vela_desktop_core::commands::vault::delete_item(&state, &id).await?;
    emit_vault_items_changed(&app);
    Ok(())
}

#[command]
pub async fn get_vault_health(state: State<'_, Arc<AppState>>) -> Result<VaultHealth, String> {
    vela_desktop_core::commands::vault::get_vault_health(&state)
}

// ── password generator ───────────────────────────────────────────────────

#[command]
pub async fn generate_password(
    options: PasswordGeneratorOptions,
) -> Result<PasswordWithStrength, String> {
    vela_desktop_core::commands::vault::generate_password(options)
}

#[command]
pub async fn log_password_generated(
    state: State<'_, Arc<AppState>>,
    length: usize,
) -> Result<(), String> {
    vela_desktop_core::commands::vault::log_password_generated(&state, length);
    Ok(())
}

// ── import / export ──────────────────────────────────────────────────────

#[command]
pub async fn export_vault_bitwarden_json(
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    vela_desktop_core::commands::vault::export_vault_bitwarden_json(&state)
}

/// Writes an export to a renderer-supplied path.
///
/// The path arrives over IPC, so it is untrusted here in a way it is not in
/// the gpui build (native save dialog). `save_vault_export_file` validates it
/// before writing — absolute, `.json`, no `..`, never inside the app data
/// directory — so this command cannot be turned into an arbitrary
/// file-overwrite primitive.
#[command]
pub async fn save_vault_export_file(
    state: State<'_, Arc<AppState>>,
    path: String,
    data: String,
) -> Result<(), String> {
    vela_desktop_core::commands::vault::save_vault_export_file(&state, &path, &data)
}

#[command]
pub async fn import_vault_bitwarden_json(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    data: String,
) -> Result<ImportResult, String> {
    // Delegates to the core, which sets the M9a fields and the unlock guard.
    let result = vela_desktop_core::commands::vault::import_vault_bitwarden_json(&state, &data)?;
    emit_vault_items_changed(&app);
    Ok(result)
}

// ── favicon ──────────────────────────────────────────────────────────────

#[command]
pub async fn fetch_favicon(url: String) -> Result<Option<String>, String> {
    vela_desktop_core::favicon::fetch_favicon(url).await
}

// ── breach checks ────────────────────────────────────────────────────────

#[command]
pub async fn check_email_breach(email: String) -> Result<Vec<BreachEntry>, String> {
    vela_desktop_core::breach::check_email_breach(&email).await
}

#[command]
pub async fn check_all_vault_emails(state: State<'_, Arc<AppState>>) -> Result<u32, String> {
    vela_desktop_core::breach::check_all_vault_emails(&state).await
}

#[command]
pub async fn check_password_breach(password: String) -> Result<PasswordBreachResult, String> {
    vela_desktop_core::breach::check_password_breach(&password).await
}

#[command]
pub async fn check_all_vault_passwords(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PasswordBreachResult>, String> {
    vela_desktop_core::breach::check_all_vault_passwords(&state).await
}
