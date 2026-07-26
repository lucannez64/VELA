//! Core of `src-tauri/src/commands/vault.rs` — item listing, lookup,
//! search, the vault-health score, add/update/delete, and Bitwarden-JSON
//! import/export. Toolkit-agnostic (`&AppState`, no `tauri::State`).
//!
//! The original's `export_vault_bitwarden_json` + `save_vault_export_file`
//! + a strict `validate_export_path` (guarding against a compromised
//! *renderer* using the IPC command as an arbitrary file-overwrite
//! primitive) collapse here into one `export_vault_bitwarden_json` that
//! also takes the destination path directly: gpui has no separate
//! renderer process, so the caller (`SettingsScreen`, via a native
//! `rfd` save dialog) already only ever supplies a path the user
//! themselves picked through the OS — there's no untrusted IPC boundary
//! left to defend against.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{record_audit_event, AuditAction};
use crate::vault::{ItemType, PasswordGeneratorOptions, VaultItem};
use crate::AppState;

pub fn require_unlocked(state: &AppState) -> Result<(), String> {
    if state.is_unlocked() {
        Ok(())
    } else {
        Err("Vault is locked".to_string())
    }
}

fn save_vault(state: &AppState) -> Result<(), String> {
    let vault = state.vault.read();
    let crypto = state.crypto.read();

    if let Some(crypto) = crypto.as_ref() {
        state
            .store
            .save_vault(&vault, crypto)
            .map_err(|e| format!("Failed to save vault: {}", e))?;
    }

    Ok(())
}

pub async fn add_item(state: &Arc<AppState>, item: VaultItem) -> Result<VaultItem, String> {
    // Without this, a locked vault silently no-ops the persist step below
    // (save_vault is a no-op with no crypto key) while still mutating the
    // in-memory vault, recording an audit event, and returning success — the
    // item is then lost on next unlock/reload with no error surfaced.
    require_unlocked(state)?;

    let mut vault = state.vault.write();
    let now = Utc::now();
    let new_id = Uuid::new_v4().to_string();
    let new_item = item.with_id(new_id).with_updated_at(now);
    vault.add_item(new_item.clone());
    drop(vault);

    save_vault(state)?;

    record_audit_event(
        state,
        AuditAction::ItemAdded {
            item_type: format!("{:?}", new_item.item_type()).to_lowercase(),
        },
    );

    tracing::info!("Item added: id={}", new_item.id());

    Ok(new_item)
}

pub async fn update_item(state: &Arc<AppState>, item: VaultItem) -> Result<VaultItem, String> {
    // See add_item: without this, a locked vault silently drops the update
    // (save_vault no-ops) while still returning success.
    require_unlocked(state)?;

    // Block edits on items received via share (shared=true, no share_recipient).
    {
        let vault = state.vault.read();
        if let Some(existing) = vault.get_item(item.id()) {
            if existing.is_received_share() {
                return Err("Cannot modify a received shared item".to_string());
            }
        }
    }
    let (updated, item_type) = {
        let mut vault = state.vault.write();
        let updated = item.with_updated_at(Utc::now());
        let item_type = format!("{:?}", updated.item_type()).to_lowercase();
        vault.update_item(updated.clone());
        (updated, item_type)
    };

    save_vault(state)?;
    let _ = crate::sharing::push_sent_share_update_inner(state, &updated).await;

    record_audit_event(state, AuditAction::ItemUpdated { item_type });

    Ok(updated)
}

pub async fn delete_item(state: &Arc<AppState>, id: &str) -> Result<(), String> {
    // See add_item: without this, a locked vault silently drops the delete
    // (save_vault no-ops) while still returning success.
    require_unlocked(state)?;

    let item_type = {
        let vault = state.vault.read();
        if let Some(item) = vault.get_item(id) {
            if item.is_received_share() {
                return Err("Cannot delete a received shared item".to_string());
            }
            format!("{:?}", item.item_type()).to_lowercase()
        } else {
            "unknown".to_string()
        }
    };

    let device_id = {
        let session = state.session.read();
        session.get_device_id().map(|s| s.to_string())
    };

    let mut vault = state.vault.write();
    vault.delete_item(id, device_id.as_deref());
    drop(vault);

    save_vault(state)?;

    record_audit_event(state, AuditAction::ItemDeleted { item_type });

    Ok(())
}

pub fn get_items(state: &Arc<AppState>) -> Result<Vec<VaultItem>, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    Ok(vault.items.clone())
}

pub fn get_item(state: &Arc<AppState>, id: &str) -> Result<Option<VaultItem>, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    Ok(vault.get_item(id).cloned())
}

pub fn search_items(state: &Arc<AppState>, query: &str) -> Result<Vec<VaultItem>, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    Ok(vault.search(query).into_iter().cloned().collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrength {
    pub entropy: f64,
    pub score: String,
    pub crack_time: String,
}

pub fn calculate_password_strength(password: &str) -> PasswordStrength {
    let charset_size = if password.chars().any(|c| c.is_ascii_lowercase()) {
        26
    } else {
        0
    } + if password.chars().any(|c| c.is_ascii_uppercase()) {
        26
    } else {
        0
    } + if password.chars().any(|c| c.is_ascii_digit()) {
        10
    } else {
        0
    } + if password.chars().any(|c| !c.is_alphanumeric()) {
        32
    } else {
        0
    };

    let entropy = if charset_size > 0 {
        (password.len() as f64) * (charset_size as f64).log2()
    } else {
        0.0
    };

    let (score, crack_time) = if entropy < 28.0 {
        ("weak".to_string(), "instant".to_string())
    } else if entropy < 36.0 {
        ("fair".to_string(), "minutes".to_string())
    } else if entropy < 60.0 {
        ("good".to_string(), "months".to_string())
    } else {
        ("strong".to_string(), "centuries".to_string())
    };

    PasswordStrength {
        entropy,
        score,
        crack_time,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordWithStrength {
    pub password: String,
    pub strength: PasswordStrength,
}

/// No `AppState` dependency at all — pure generation, no vault write.
pub fn generate_password(options: PasswordGeneratorOptions) -> Result<PasswordWithStrength, String> {
    let mut charset = String::new();

    if options.uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if options.lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if options.numbers {
        charset.push_str("0123456789");
    }
    if options.symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
    }

    if options.easy_to_type {
        charset = charset.replace(|c: char| !c.is_alphanumeric(), "");
    }

    if charset.is_empty() {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }

    let charset: Vec<char> = charset.chars().collect();

    let password: String = (0..options.length)
        .map(|_| {
            let mut buf = [0u8; 4];
            getrandom::getrandom(&mut buf).expect("OS random source unavailable");
            let idx = (buf[0] as usize
                | (buf[1] as usize) << 8
                | (buf[2] as usize) << 16
                | (buf[3] as usize) << 24)
                % charset.len();
            charset[idx]
        })
        .collect();

    let strength = calculate_password_strength(&password);

    Ok(PasswordWithStrength { password, strength })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealth {
    pub weak_passwords: usize,
    pub reused_passwords: usize,
    pub total_logins: usize,
    pub health_score: f64,
    pub status: String,
}

pub fn get_vault_health(state: &Arc<AppState>) -> Result<VaultHealth, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();

    let login_items: Vec<&VaultItem> = vault
        .items
        .iter()
        .filter(|i| i.item_type() == ItemType::Login && i.password().is_some())
        .collect();

    let total_logins = login_items.len();

    let mut weak_passwords = 0;
    let mut password_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for item in &login_items {
        if let Some(password) = item.password() {
            let strength = calculate_password_strength(password);
            if strength.score == "weak" || strength.score == "fair" {
                weak_passwords += 1;
            }

            *password_counts.entry(password.to_string()).or_insert(0) += 1;
        }
    }

    let reused_passwords = password_counts.values().filter(|&&count| count > 1).count();

    let health_score = if total_logins == 0 {
        100.0
    } else {
        let weak_pct = (weak_passwords as f64 / total_logins as f64) * 100.0;
        let reused_pct = (reused_passwords as f64 / total_logins as f64) * 100.0;
        100.0 - (weak_pct * 0.6 + reused_pct * 0.4)
    };

    let status = if health_score >= 90.0 {
        "OPTIMAL".to_string()
    } else if health_score >= 70.0 {
        "GOOD".to_string()
    } else if health_score >= 50.0 {
        "FAIR".to_string()
    } else {
        "POOR".to_string()
    };

    Ok(VaultHealth {
        weak_passwords,
        reused_passwords,
        total_logins,
        health_score,
        status,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct BitwardenExport {
    version: u32,
    timestamp: String,
    user_id: String,
    passwords: Vec<BitwardenPasswordEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BitwardenPasswordEntry {
    id: String,
    username: String,
    password: String,
    #[serde(rename = "app_id")]
    app_id: Option<String>,
    description: Option<String>,
    url: Option<String>,
    otp: Option<String>,
}

/// Serializes all Login items as Bitwarden-compatible JSON. The caller
/// (a native save dialog) is responsible for writing the returned string
/// to whatever path the user picked.
pub fn export_vault_bitwarden_json(state: &Arc<AppState>) -> Result<String, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    let user_id = state.store.load_device_id().map_err(|e| e.to_string())?;

    let passwords: Vec<BitwardenPasswordEntry> = vault
        .items
        .iter()
        .filter(|item| matches!(item.item_type(), ItemType::Login))
        .map(|item| BitwardenPasswordEntry {
            id: item.id().to_string(),
            username: item.username().unwrap_or("").to_string(),
            password: item.password().unwrap_or("").to_string(),
            app_id: None,
            description: item.notes().map(|n| n.to_string()),
            url: item.url().map(|u| u.to_string()),
            otp: None,
        })
        .collect();

    let export = BitwardenExport { version: 1, timestamp: Utc::now().to_rfc3339(), user_id, passwords };

    serde_json::to_string_pretty(&export).map_err(|e| format!("Failed to serialize export: {}", e))
}

#[derive(Debug, Deserialize)]
struct BitwardenImport {
    version: u32,
    #[allow(dead_code)]
    timestamp: Option<String>,
    #[allow(dead_code)]
    user_id: Option<String>,
    passwords: Vec<BitwardenPasswordEntry>,
}

fn normalize_import_url(url: Option<&str>) -> String {
    let url = url.unwrap_or_default().trim();
    if url.is_empty() {
        return String::new();
    }

    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_string();
    }

    if url.parse::<std::net::IpAddr>().is_ok() {
        return format!("http://{}", url);
    }

    if url.contains(':') && !url.contains('/') {
        if let Some(host_part) = url.split(':').next() {
            if host_part.parse::<std::net::IpAddr>().is_ok() {
                return format!("http://{}", url);
            }
        }
    }

    format!("https://{}", url)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub added: u32,
    pub skipped: u32,
    pub total: u32,
}

/// Imports a Bitwarden-compatible JSON export (as read from a file the user
/// picked via a native open dialog) as new Login items.
pub fn import_vault_bitwarden_json(state: &Arc<AppState>, data: &str) -> Result<ImportResult, String> {
    let import: BitwardenImport = serde_json::from_str(data).map_err(|e| format!("Failed to parse import data: {}", e))?;

    if import.version != 1 {
        return Err(format!("Unsupported export version: {}", import.version));
    }

    require_unlocked(state)?;

    let now = Utc::now();
    let total_count = import.passwords.len() as u32;
    let mut added_count = 0u32;
    let skipped_count = 0u32;

    {
        let mut vault = state.vault.write();

        for entry in import.passwords {
            let name = entry.url.clone().filter(|u| !u.is_empty()).unwrap_or_else(|| entry.username.clone());
            let url = normalize_import_url(entry.url.as_deref());

            let item = VaultItem::Login {
                meta: crate::vault::VaultMeta {
                    id: Uuid::new_v4().to_string(),
                    name,
                    notes: entry.description,
                    created_at: now,
                    updated_at: now,
                    last_modified_device: None,
                    favorite: false,
                    shared: false,
                    share_recipient: None,
                },
                url,
                username: entry.username,
                pass: entry.password,
                totp: entry.otp,
            };

            vault.add_item(item);
            added_count += 1;
        }

        tracing::info!("Total items in vault after import: {}", vault.items.len());
    }

    save_vault(state)?;

    tracing::info!("Imported {} items, {} total", added_count, total_count);

    Ok(ImportResult { added: added_count, skipped: skipped_count, total: total_count })
}
