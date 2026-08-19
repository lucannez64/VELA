use std::sync::Arc;
use tauri::State;
pub use vela_desktop_core::audit::{
    get_device_name, load_audit_log, merge_audit_from_plaintext, record_audit_event,
    replace_audit_from_plaintext, save_audit_log, serialize_audit_plaintext, AuditAction,
    AuditEntry, AuditLog, AuditSubject, AUDIT_CHUNK_ID,
};
use vela_desktop_core::AppState;

#[tauri::command]
pub async fn get_audit_log(state: State<'_, Arc<AppState>>) -> Result<Vec<AuditEntry>, String> {
    let log = load_audit_log(&state).unwrap_or_default();
    Ok(log.entries)
}

/// The audit log is written by the backend, at the moment the audited thing
/// happens.
///
/// There used to be a `log_audit_event` command letting the renderer append
/// entries: the action was whitelisted but `details` was arbitrary, so anything
/// that could reach the IPC could write plausible history into the one record a
/// user would consult after a compromise — or bury a real entry under noise.
/// Nothing in either frontend called it. Like the `nativeMessage` handlers in
/// E-1, it was attack surface and nothing else, so it is gone rather than
/// hardened (audit, desktop hardening).
#[tauri::command]
pub async fn clear_audit_log(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    vela_desktop_core::audit::clear_audit_log(&state)
}
