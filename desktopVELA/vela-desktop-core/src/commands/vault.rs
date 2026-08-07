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

    // Block edits on items received via share (shared=true, no share_recipient),
    // and carry forward fields this client has no UI for.
    let item = {
        let vault = state.vault.read();
        match vault.get_item(item.id()) {
            Some(existing) if existing.is_received_share() => {
                return Err("Cannot modify a received shared item".to_string());
            }
            Some(existing) => item.preserving_app_ids(existing),
            None => item,
        }
    };
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

/// Map a random 32-bit draw onto `0..n`, or `None` if it falls in the biased
/// tail and must be redrawn. The bound is computed over the 2^32 possible
/// draws, so a charset whose size divides evenly never rejects anything.
fn index_from(value: u32, n: u32) -> Option<u32> {
    const SPAN: u64 = 1 << 32;
    let bound = SPAN - (SPAN % n as u64);
    ((value as u64) < bound).then(|| value % n)
}

fn uniform_index(n: usize) -> Result<usize, String> {
    let n = n as u32;
    loop {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf)
            .map_err(|_| "OS random source unavailable".to_string())?;
        if let Some(index) = index_from(u32::from_le_bytes(buf), n) {
            return Ok(index as usize);
        }
    }
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

    // Two fixes over the previous draw loop: a failing RNG returns instead of
    // panicking, and the index is drawn without modulo bias — `value % n`
    // favours the low indices whenever `n` does not divide 2^32.
    let mut password = String::with_capacity(options.length);
    for _ in 0..options.length {
        password.push(charset[uniform_index(charset.len())?]);
    }

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
                app_ids: Vec::new(),
                credential_change_needs_reauth: false,
                allow_second_factor_downgrade: false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;
    use crate::vault::VaultMeta;

    fn unlocked_state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&Crypto::generate_rms());
        (dir, state)
    }

    fn login(name: &str, url: &str, user: &str, pass: &str) -> VaultItem {
        let now = Utc::now();
        VaultItem::Login {
            meta: VaultMeta {
                id: Uuid::new_v4().to_string(),
                name: name.into(),
                notes: None,
                created_at: now,
                updated_at: now,
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            url: url.into(),
            username: user.into(),
            pass: pass.into(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: false,
            allow_second_factor_downgrade: false,
        }
    }

    const STRONG: &str = "X9#mQ2$vL8&pZ4!wK7yN";

    #[test]
    fn password_strength_bands() {
        let weak = calculate_password_strength("");
        assert_eq!(weak.score, "weak");
        assert_eq!(weak.entropy, 0.0);
        assert_eq!(weak.crack_time, "instant");

        // 5 lowercase: 5 * log2(26) ≈ 23.5 → weak.
        assert_eq!(calculate_password_strength("abcde").score, "weak");
        // 6 lowercase: ≈ 28.2 → fair.
        let fair = calculate_password_strength("abcdef");
        assert_eq!(fair.score, "fair");
        assert_eq!(fair.crack_time, "minutes");
        // 8 mixed upper/lower/digit: 8 * log2(62) ≈ 47.6 → good.
        let good = calculate_password_strength("Abcdef12");
        assert_eq!(good.score, "good");
        assert_eq!(good.crack_time, "months");
        // 21 chars all classes: ≥ 60 → strong.
        let strong = calculate_password_strength(STRONG);
        assert_eq!(strong.score, "strong");
        assert_eq!(strong.crack_time, "centuries");
    }

    #[test]
    fn index_from_rejects_the_biased_tail() {
        let n = 3u32;
        let bound = ((1u64 << 32) - ((1u64 << 32) % n as u64)) as u32;
        assert_eq!(index_from(bound - 1, n), Some((bound - 1) % n));
        assert_eq!(index_from(bound, n), None);
        // A charset size that divides 2^32 never rejects.
        assert_eq!(index_from(u32::MAX, 32), Some(31));
    }

    #[test]
    fn generate_password_respects_options() {
        let pw = generate_password(PasswordGeneratorOptions::default()).unwrap();
        assert_eq!(pw.password.len(), 20);
        assert!(pw.strength.entropy > 0.0);

        let pw = generate_password(PasswordGeneratorOptions {
            length: 8,
            uppercase: false,
            lowercase: true,
            numbers: false,
            symbols: false,
            easy_to_type: false,
            pronounceable: false,
        })
        .unwrap();
        assert_eq!(pw.password.len(), 8);
        assert!(pw.password.chars().all(|c| c.is_ascii_lowercase()));

        // easy_to_type strips the symbol class from the charset.
        let pw = generate_password(PasswordGeneratorOptions {
            length: 64,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            easy_to_type: true,
            pronounceable: false,
        })
        .unwrap();
        assert!(pw.password.chars().all(|c| c.is_alphanumeric()));

        // No classes at all → falls back to lowercase rather than failing.
        let pw = generate_password(PasswordGeneratorOptions {
            length: 10,
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false,
            easy_to_type: false,
            pronounceable: false,
        })
        .unwrap();
        assert_eq!(pw.password.len(), 10);
        assert!(pw.password.chars().all(|c| c.is_ascii_lowercase()));

        // Two generations are (overwhelmingly) distinct.
        let a = generate_password(PasswordGeneratorOptions::default()).unwrap();
        let b = generate_password(PasswordGeneratorOptions::default()).unwrap();
        assert_ne!(a.password, b.password);
    }

    #[test]
    fn require_unlocked_gates_on_state() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::for_test(dir.path());
        assert_eq!(require_unlocked(&state).unwrap_err(), "Vault is locked");
        state.unlock_for_test(&Crypto::generate_rms());
        assert!(require_unlocked(&state).is_ok());
    }

    #[test]
    fn vault_health_counts_weak_and_reused() {
        let (_dir, state) = unlocked_state();
        assert_eq!(
            get_vault_health(&state).unwrap().health_score,
            100.0,
            "empty vault is perfectly healthy"
        );

        {
            let mut vault = state.vault.write();
            vault.add_item(login("Weak one", "https://a.example", "u", "abc"));
            vault.add_item(login("Reused A", "https://b.example", "u", STRONG));
            vault.add_item(login("Reused B", "https://c.example", "u", STRONG));
            vault.add_item(login("Unique", "https://d.example", "u", "Z7!qW3#eR9&tY6^uI2*o"));
        }

        let health = get_vault_health(&state).unwrap();
        assert_eq!(health.total_logins, 4);
        assert_eq!(health.weak_passwords, 1);
        assert_eq!(health.reused_passwords, 1, "one password shared by two items");
        // score = 100 - (25%*0.6 + 25%*0.4) = 75 → GOOD.
        assert_eq!(health.health_score, 75.0);
        assert_eq!(health.status, "GOOD");
    }

    #[tokio::test]
    async fn add_update_delete_roundtrip_through_disk() {
        let (_dir, state) = unlocked_state();

        // Locked vault rejects mutations.
        let locked_dir = tempfile::tempdir().unwrap();
        let locked = Arc::new(AppState::for_test(locked_dir.path()));
        assert!(add_item(&locked, login("x", "u", "u", "p")).await.is_err());
        assert!(delete_item(&locked, "anything").await.is_err());

        let added = add_item(&state, login("GitHub", "https://github.com", "alice", "pw"))
            .await
            .unwrap();
        assert_ne!(added.id(), "", "server-style id assigned");
        assert_eq!(get_items(&state).unwrap().len(), 1);

        // Persisted encrypted to disk — reload through the store.
        let rms = state.crypto.read().as_ref().unwrap().rms();
        let on_disk = state.store.load_vault(&Crypto::new(&rms)).unwrap();
        assert_eq!(on_disk.items.len(), 1);
        assert_eq!(on_disk.get_item(added.id()).unwrap().username(), Some("alice"));

        let updated = update_item(
            &state,
            added.with_name("GitHub work".into()),
        )
        .await
        .unwrap();
        assert_eq!(updated.name(), "GitHub work");
        assert!(updated.updated_at() >= added.updated_at());

        delete_item(&state, added.id()).await.unwrap();
        assert!(get_item(&state, added.id()).unwrap().is_none());
        let vault = state.vault.read();
        assert_eq!(vault.tombstones.len(), 1);
        assert_eq!(vault.tombstones[0].deleted_by.as_deref(), Some("test-device"));
    }

    #[tokio::test]
    async fn received_shares_are_immutable() {
        let (_dir, state) = unlocked_state();
        let shared = login("Shared", "https://s.example", "u", "p").with_shared_status(true, None);
        let id = shared.id().to_string();
        state.vault.write().add_item(shared);

        let err = update_item(&state, login("Shared", "https://s.example", "u", "p2").with_id(id.clone()))
            .await
            .unwrap_err();
        assert!(err.contains("received shared"), "{err}");

        let err = delete_item(&state, &id).await.unwrap_err();
        assert!(err.contains("received shared"), "{err}");
    }

    #[test]
    fn normalize_import_url_schemes() {
        assert_eq!(normalize_import_url(None), "");
        assert_eq!(normalize_import_url(Some("  ")), "");
        assert_eq!(normalize_import_url(Some("https://x.example")), "https://x.example");
        assert_eq!(normalize_import_url(Some("http://x.example")), "http://x.example");
        assert_eq!(normalize_import_url(Some("example.com")), "https://example.com");
        // IPs get plain http (no TLS on most IP-targeted services).
        assert_eq!(normalize_import_url(Some("192.168.1.1")), "http://192.168.1.1");
        assert_eq!(normalize_import_url(Some("192.168.1.1:8080")), "http://192.168.1.1:8080");
        // host:port (non-IP) keeps https.
        assert_eq!(normalize_import_url(Some("example.com:8443")), "https://example.com:8443");
    }

    #[test]
    fn import_rejects_bad_input_before_touching_vault() {
        let (_dir, state) = unlocked_state();
        assert!(import_vault_bitwarden_json(&state, "not json").is_err());
        let v2 = serde_json::json!({"version": 2, "passwords": []}).to_string();
        let err = import_vault_bitwarden_json(&state, &v2).unwrap_err();
        assert!(err.contains("Unsupported export version"), "{err}");
    }

    #[test]
    fn import_adds_login_items_and_normalizes_urls() {
        let (_dir, state) = unlocked_state();
        let data = serde_json::json!({
            "version": 1,
            "timestamp": null,
            "user_id": "whoever",
            "passwords": [
                {"id": "a", "username": "alice", "password": "pw1", "app_id": null,
                 "description": "note", "url": "github.com", "otp": null},
                {"id": "b", "username": "bob", "password": "pw2", "app_id": null,
                 "description": null, "url": null, "otp": "JBSWY3DPEHPK3PXP"}
            ]
        })
        .to_string();

        let result = import_vault_bitwarden_json(&state, &data).unwrap();
        assert_eq!((result.added, result.skipped, result.total), (2, 0, 2));

        let items = get_items(&state).unwrap();
        assert_eq!(items.len(), 2);
        let alice = items.iter().find(|i| i.username() == Some("alice")).unwrap();
        assert_eq!(alice.url(), Some("https://github.com"));
        assert_eq!(alice.name(), "github.com");
        assert_eq!(alice.notes(), Some("note"));
        // No URL → falls back to the username as the display name.
        let bob = items.iter().find(|i| i.username() == Some("bob")).unwrap();
        assert_eq!(bob.name(), "bob");
        assert_eq!(bob.url(), Some(""));
    }

    #[test]
    fn export_import_roundtrip_preserves_login_fields() {
        let (_dir_a, state_a) = unlocked_state();
        {
            let mut vault = state_a.vault.write();
            vault.add_item(login("GH", "https://github.com", "alice", "s3cret"));
            // Non-login items are excluded from the export.
            vault.add_item(VaultItem::SecureNote {
                meta: crate::vault::VaultMeta {
                    id: "n1".into(),
                    name: "note".into(),
                    notes: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    last_modified_device: None,
                    favorite: false,
                    shared: false,
                    share_recipient: None,
                },
                title: "t".into(),
                content: "c".into(),
            });
        }

        let exported = export_vault_bitwarden_json(&state_a).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["passwords"].as_array().unwrap().len(), 1);

        let (_dir_b, state_b) = unlocked_state();
        let result = import_vault_bitwarden_json(&state_b, &exported).unwrap();
        assert_eq!(result.added, 1);
        let items = get_items(&state_b).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].username(), Some("alice"));
        assert_eq!(items[0].password(), Some("s3cret"));
        assert_eq!(items[0].url(), Some("https://github.com"));
    }
}
