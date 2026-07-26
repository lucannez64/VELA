use chrono::Utc;
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;
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

#[tauri::command]
pub async fn log_audit_event(
    state: State<'_, Arc<AppState>>,
    action: String,
    details: Option<serde_json::Value>,
) -> Result<(), String> {
    let mut log = load_audit_log(&state).unwrap_or_default();
    let device_name = get_device_name();

    let entry = match action.as_str() {
        "vault_created" => AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: AuditAction::VaultCreated,
            subject: AuditSubject::Device { device_name },
        },
        "vault_unlocked" => AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: AuditAction::VaultUnlocked,
            subject: AuditSubject::Session { device_name },
        },
        "vault_locked" => AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: AuditAction::VaultLocked,
            subject: AuditSubject::Session { device_name },
        },
        "vault_synced" => {
            let chunk_count = details
                .as_ref()
                .and_then(|d| d.get("chunk_count"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(0);
            AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                action: AuditAction::VaultSync { chunk_count },
                subject: AuditSubject::Device { device_name },
            }
        }
        "device_enrolled" => {
            let device_id = details
                .as_ref()
                .and_then(|d| d.get("device_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let enrolling_device_id = details
                .as_ref()
                .and_then(|d| d.get("enrolling_device_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                action: AuditAction::DeviceEnrolled {
                    device_id,
                    enrolling_device_id,
                },
                subject: AuditSubject::Device { device_name },
            }
        }
        "device_revoked" => {
            let device_id = details
                .as_ref()
                .and_then(|d| d.get("device_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let revoking_device_id = details
                .as_ref()
                .and_then(|d| d.get("revoking_device_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                action: AuditAction::DeviceRevoked {
                    device_id,
                    revoking_device_id,
                },
                subject: AuditSubject::Device { device_name },
            }
        }
        "share_sent" => {
            let recipient_user_id = details
                .as_ref()
                .and_then(|d| d.get("recipient_user_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                action: AuditAction::ShareSent { recipient_user_id },
                subject: AuditSubject::Device { device_name },
            }
        }
        "share_received" => {
            let sender_user_id = details
                .as_ref()
                .and_then(|d| d.get("sender_user_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                action: AuditAction::ShareReceived { sender_user_id },
                subject: AuditSubject::Device { device_name },
            }
        }
        "password_generated" => {
            let length = details
                .as_ref()
                .and_then(|d| d.get("length"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(20);
            AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                action: AuditAction::PasswordGenerated { length },
                subject: AuditSubject::Device { device_name },
            }
        }
        "item_added" | "item_updated" | "item_deleted" => {
            let item_type = details
                .as_ref()
                .and_then(|d| d.get("item_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let audit_action = match action.as_str() {
                "item_added" => AuditAction::ItemAdded { item_type },
                "item_updated" => AuditAction::ItemUpdated { item_type },
                _ => AuditAction::ItemDeleted { item_type },
            };
            AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                action: audit_action,
                subject: AuditSubject::Device { device_name },
            }
        }
        "settings_changed" => AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: AuditAction::SettingsChanged,
            subject: AuditSubject::Device { device_name },
        },
        _ => return Err(format!("Unknown audit action: {}", action)),
    };

    log.add_entry(entry);
    save_audit_log(&state, &log)?;

    Ok(())
}

#[tauri::command]
pub async fn clear_audit_log(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let log = AuditLog::default();
    save_audit_log(&state, &log)
}
