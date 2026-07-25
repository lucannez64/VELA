use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    WebSessionGranted {
        mode: String,
        ttl_secs: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuditSubject {
    Device { device_name: String },
    Session { device_name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl AuditLog {
    pub fn add_entry(&mut self, entry: AuditEntry) {
        self.entries.push(entry);

        if self.entries.len() > 1000 {
            self.entries = self.entries.split_off(self.entries.len() - 1000);
        }
    }
}

pub fn get_device_name() -> String {
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

/// Merge server-side audit events into the local log: union by event id,
/// sorted by timestamp, local history is never discarded.
pub fn merge_audit_from_plaintext(state: &AppState, plaintext: &[u8]) -> Result<(), String> {
    let server_log: AuditLog = serde_json::from_slice(plaintext).map_err(|e| e.to_string())?;
    let mut local_log = load_audit_log(state).unwrap_or_default();

    let mut seen: std::collections::HashSet<String> =
        local_log.entries.iter().map(|e| e.id.clone()).collect();
    for entry in server_log.entries {
        if seen.insert(entry.id.clone()) {
            local_log.entries.push(entry);
        }
    }
    local_log
        .entries
        .sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.id.cmp(&b.id)));
    if local_log.entries.len() > 1000 {
        local_log.entries = local_log.entries.split_off(local_log.entries.len() - 1000);
    }

    save_audit_log(state, &local_log)
}
