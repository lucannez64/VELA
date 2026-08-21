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
    /// This install was found storing its device signing keys in cleartext and
    /// they have now been encrypted.
    ///
    /// Recorded rather than only logged: whoever had read access to the data
    /// directory before this ran had those keys, and re-encrypting them does not
    /// undo that. The user is the only one who can decide whether to re-enroll
    /// the device, and they cannot decide it from a `warn!` they never see
    /// (audit, desktop hardening).
    PlaintextIdentityKeysMigrated,
    /// A saved credential's plaintext crossed the IPC boundary to a caller
    /// (browser autofill). Recorded with the caller named, so a same-uid
    /// drain shows up in this log as an attributable list of fills rather
    /// than silence (issue #149, option D).
    CredentialReleased {
        caller: String,
        domain: String,
    },
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

        let excess = self.entries.len().saturating_sub(1000);
        if excess > 0 {
            // `split_off` allocated a fresh 1000-entry vector and dropped the
            // old one on every event once the log was full; draining the front
            // shifts in place and keeps the capacity.
            self.entries.drain(..excess);
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
    let _ = record_audit_event_checked(state, action);
}

/// Like [`record_audit_event`], but reports failure instead of swallowing it.
///
/// Most callers treat the audit log as best-effort bookkeeping. The plaintext
/// IPC release does not: its guarantee is that every release leaves a durable
/// entry, so it must know when one could not be written and decline to
/// release rather than hand out a secret nobody can later account for.
pub fn record_audit_event_checked(
    state: &AppState,
    action: AuditAction,
) -> Result<(), String> {
    // Unreadable counts as unwritable here: an entry we cannot verify went
    // into the log is not an entry.
    let mut log = load_audit_log(state)
        .ok_or_else(|| "the activity log could not be read (locked or corrupt)".to_string())?;
    let device_name = get_device_name();
    let entry = AuditEntry {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        action,
        subject: AuditSubject::Device { device_name },
    };
    log.add_entry(entry);
    save_audit_log(state, &log)
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

/// Wipe the local audit log.
///
/// There is deliberately no "append one entry" counterpart: entries are
/// written by the backend at the moment the audited thing happens. A command
/// letting a caller append arbitrary `details` would let anything that
/// reaches the IPC write plausible history into the one record a user
/// consults after a compromise — or bury a real entry under noise.
pub fn clear_audit_log(state: &AppState) -> Result<(), String> {
    save_audit_log(state, &AuditLog::default())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;
    use crate::AppState;

    fn entry(id: &str, secs_offset: i64) -> AuditEntry {
        AuditEntry {
            id: id.into(),
            timestamp: DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
                + chrono::Duration::seconds(secs_offset),
            action: AuditAction::VaultUnlocked,
            subject: AuditSubject::Device { device_name: "test".into() },
        }
    }

    fn unlocked_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::for_test(dir.path());
        state.unlock_for_test(&Crypto::generate_rms());
        (dir, state)
    }

    #[test]
    fn audit_action_serde_uses_snake_case_tag() {
        let json = serde_json::to_value(AuditAction::VaultLocked).unwrap();
        assert_eq!(json, serde_json::json!({ "action_type": "vault_locked" }));

        // Both frontends key their label tables off this string, so it is part
        // of the contract, not an implementation detail.
        assert_eq!(
            serde_json::to_value(AuditAction::PlaintextIdentityKeysMigrated).unwrap(),
            serde_json::json!({ "action_type": "plaintext_identity_keys_migrated" })
        );

        let json = serde_json::to_value(AuditAction::ItemAdded { item_type: "login".into() }).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "action_type": "item_added", "item_type": "login" })
        );

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert_eq!(back, AuditAction::ItemAdded { item_type: "login".into() });
    }

    #[test]
    fn add_entry_caps_log_at_1000_keeping_newest() {
        let mut log = AuditLog::default();
        for i in 0..1005 {
            log.add_entry(entry(&format!("e{i:04}"), i));
        }
        assert_eq!(log.entries.len(), 1000);
        assert_eq!(log.entries[0].id, "e0005", "oldest entries are dropped first");
        assert_eq!(log.entries[999].id, "e1004");
    }

    #[test]
    fn record_and_load_roundtrip_encrypted() {
        let (_dir, state) = unlocked_state();
        record_audit_event(&state, AuditAction::VaultCreated);
        record_audit_event(&state, AuditAction::ItemDeleted { item_type: "login".into() });

        // On disk it must be ciphertext.
        let raw = std::fs::read(state.store.store_path().join(AUDIT_FILE)).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"action".as_slice()));

        let log = load_audit_log(&state).unwrap();
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.entries[0].action, AuditAction::VaultCreated);
        assert_eq!(
            log.entries[1].action,
            AuditAction::ItemDeleted { item_type: "login".into() }
        );
    }

    #[test]
    fn load_audit_log_requires_crypto() {
        let dir = tempfile::tempdir().unwrap();
        let locked = AppState::for_test(dir.path());
        assert!(load_audit_log(&locked).is_none());
    }

    #[test]
    fn merge_unions_by_id_sorted_and_keeps_local() {
        let (_dir, state) = unlocked_state();
        save_audit_log(
            &state,
            &AuditLog { entries: vec![entry("b", 20), entry("a", 10)] },
        )
        .unwrap();

        let server = AuditLog {
            // "a" duplicates a local id (must not be re-added), "c" is new.
            entries: vec![entry("c", 5), entry("a", 10)],
        };
        merge_audit_from_plaintext(&state, &serde_json::to_vec(&server).unwrap()).unwrap();

        let log = load_audit_log(&state).unwrap();
        let ids: Vec<&str> = log.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["c", "a", "b"], "union, sorted by timestamp");
    }

    #[test]
    fn merge_caps_at_1000_entries() {
        let (_dir, state) = unlocked_state();
        let server = AuditLog {
            entries: (0..1100).map(|i| entry(&format!("s{i:04}"), i)).collect(),
        };
        merge_audit_from_plaintext(&state, &serde_json::to_vec(&server).unwrap()).unwrap();
        let log = load_audit_log(&state).unwrap();
        assert_eq!(log.entries.len(), 1000);
        assert_eq!(log.entries[0].id, "s0100");
    }

    #[test]
    fn replace_audit_from_plaintext_validates_json() {
        let (_dir, state) = unlocked_state();
        assert!(replace_audit_from_plaintext(&state, b"garbage").is_err());
        replace_audit_from_plaintext(
            &state,
            &serde_json::to_vec(&AuditLog { entries: vec![entry("x", 1)] }).unwrap(),
        )
        .unwrap();
        assert_eq!(load_audit_log(&state).unwrap().entries.len(), 1);
    }
}
