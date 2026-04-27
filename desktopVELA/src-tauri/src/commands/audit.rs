use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::AppState;

pub const AUDIT_CHUNK_ID: &str = "audit-log";
const AUDIT_FILE: &str = "audit.enc";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    #[serde(flatten)]
    pub subject: AuditSubject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action_type", rename_all = "snake_case")]
pub enum AuditAction {
    DeviceEnrolled {
        device_id: String,
        enrolling_device_id: Option<String>,
    },
    DeviceRevoked {
        device_id: String,
        revoking_device_id: String,
    },
    VaultSync {
        chunk_count: usize,
    },
    ShareSent {
        recipient_user_id: String,
    },
    ShareReceived {
        sender_user_id: String,
    },
    VaultCreated,
    VaultUnlocked,
    VaultLocked,
    PasswordGenerated {
        length: usize,
    },
    ItemAdded {
        item_type: String,
    },
    ItemUpdated {
        item_type: String,
    },
    ItemDeleted {
        item_type: String,
    },
    SettingsChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuditSubject {
    Device { device_name: String },
    Session { device_name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl AuditLog {
    fn add_entry(&mut self, entry: AuditEntry) {
        self.entries.push(entry);

        if self.entries.len() > 1000 {
            self.entries = self.entries.split_off(self.entries.len() - 1000);
        }
    }
}

fn get_device_name() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Mac".to_string())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Desktop".to_string())
    }
}

pub fn record_audit_event(state: &AppState, action: AuditAction) {
    let mut log = load_audit_log(state).unwrap_or_default();
    let device_name = get_device_name();
    let entry = AuditEntry {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        action,
        subject: AuditSubject::Device { device_name },
    };
    log.add_entry(entry);
    let _ = save_audit_log(state, &log);
}

pub fn load_audit_log(state: &AppState) -> Option<AuditLog> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref()?;

    let audit_path = state.store.store_path().join(AUDIT_FILE);
    if !audit_path.exists() {
        return Some(AuditLog::default());
    }

    let ciphertext = std::fs::read(&audit_path).ok()?;
    let plaintext = crypto.decrypt_vault(&ciphertext).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

pub fn save_audit_log(state: &AppState, log: &AuditLog) -> Result<(), String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Crypto not initialized")?;

    let plaintext = serde_json::to_vec(log).map_err(|e| e.to_string())?;
    let ciphertext = crypto
        .encrypt_vault(&plaintext)
        .map_err(|e| e.to_string())?;

    let audit_path = state.store.store_path().join(AUDIT_FILE);
    std::fs::write(audit_path, ciphertext).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn serialize_audit_plaintext(state: &AppState) -> Option<Vec<u8>> {
    let log = load_audit_log(state).unwrap_or_default();
    serde_json::to_vec(&log).ok()
}

pub fn replace_audit_from_plaintext(state: &AppState, plaintext: &[u8]) -> Result<(), String> {
    let log: AuditLog = serde_json::from_slice(plaintext).map_err(|e| e.to_string())?;
    save_audit_log(state, &log)
}

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
