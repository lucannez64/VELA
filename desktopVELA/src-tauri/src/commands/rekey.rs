//! Vault re-keying ("Rotate keys") — thin Tauri wrapper over the core
//! orchestrator in `vela_desktop_core::commands::rekey`.

use crate::AppState;
use std::sync::Arc;
use tauri::{command, State};
use vela_desktop_core::commands::rekey as core;

#[command]
pub async fn rotate_vault_keys(
    state: State<'_, Arc<AppState>>,
) -> Result<core::RotateSummary, String> {
    core::rotate_vault_keys(&state).await
}
