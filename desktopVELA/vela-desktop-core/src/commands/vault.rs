//! Core of `src-tauri/src/commands/vault.rs` — item listing, lookup,
//! search, the vault-health score, add/update/delete, and Bitwarden-JSON
//! import/export. Toolkit-agnostic (`&AppState`, no `tauri::State`).
//!
//! Export comes in two halves. [`export_vault_bitwarden_json`] serializes
//! and returns the JSON; [`save_vault_export_file`] writes it to a path,
//! through [`validate_export_path`].
//!
//! gpui hands that path straight from a native `rfd` dialog, so the user
//! picked it themselves and there is no untrusted boundary to defend. The
//! Tauri build's path arrives over IPC from a renderer, where a compromised
//! one could otherwise use the command as an arbitrary file-overwrite
//! primitive. The guard therefore lives here rather than in either front
//! end: absolute, `.json`, no `..`, an existing directory, and never inside
//! the app's own data directory.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
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

/// Items of a single type, selected by the string tag both front ends use.
/// An unrecognised tag returns the whole vault, which is what the Tauri
/// command has always done — the sidebar sends "all" for the unfiltered view.
pub fn get_items_by_type(state: &Arc<AppState>, item_type: &str) -> Result<Vec<VaultItem>, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    let itype = match item_type.to_lowercase().as_str() {
        "login" => ItemType::Login,
        "creditcard" | "card" => ItemType::CreditCard,
        "securenote" | "note" => ItemType::SecureNote,
        "identity" => ItemType::Identity,
        "file" | "fileblob" => ItemType::FileBlob,
        _ => return Ok(vault.items.clone()),
    };
    Ok(vault.by_type(&itype).into_iter().cloned().collect())
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

/// Shannon-style entropy estimate for `password`.
///
/// One pass over the characters rather than the four independent
/// `chars().any(..)` scans this used to run, and no `String` at all — the vault
/// health scan calls this once per login, and the two allocated verdict strings
/// were pure garbage on that path.
fn password_entropy(password: &str) -> f64 {
    let (mut lower, mut upper, mut digit, mut other) = (false, false, false, false);

    for c in password.chars() {
        // The four predicates are mutually exclusive, so `else if` matches what
        // the separate scans decided.
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if !c.is_alphanumeric() {
            other = true;
        }

        if lower && upper && digit && other {
            break;
        }
    }

    let charset_size = u32::from(lower) * 26
        + u32::from(upper) * 26
        + u32::from(digit) * 10
        + u32::from(other) * 32;

    if charset_size > 0 {
        // `len()` is the byte length, as it always was here.
        (password.len() as f64) * (charset_size as f64).log2()
    } else {
        0.0
    }
}

/// The verdict for an entropy value, as borrowed strings.
fn strength_verdict(entropy: f64) -> (&'static str, &'static str) {
    if entropy < 28.0 {
        ("weak", "instant")
    } else if entropy < 36.0 {
        ("fair", "minutes")
    } else if entropy < 60.0 {
        ("good", "months")
    } else {
        ("strong", "centuries")
    }
}

pub fn calculate_password_strength(password: &str) -> PasswordStrength {
    let entropy = password_entropy(password);
    let (score, crack_time) = strength_verdict(entropy);

    PasswordStrength {
        entropy,
        score: score.to_string(),
        crack_time: crack_time.to_string(),
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

/// A refilled block of OS randomness, handing out one 32-bit draw at a time.
///
/// Generation used to call `getrandom` once per character — a syscall per
/// character of every password, plus one more for each rejected draw. One call
/// now covers sixteen draws.
struct RandomDraws {
    buf: [u8; 64],
    next: usize,
}

impl RandomDraws {
    fn new() -> Self {
        // Starting past the end forces a fill on the first draw.
        Self { buf: [0u8; 64], next: 64 }
    }

    fn draw(&mut self) -> Result<u32, String> {
        if self.next == self.buf.len() {
            getrandom::getrandom(&mut self.buf)
                .map_err(|_| "OS random source unavailable".to_string())?;
            self.next = 0;
        }
        let bytes: [u8; 4] = self.buf[self.next..self.next + 4]
            .try_into()
            .expect("4 bytes");
        self.next += 4;
        Ok(u32::from_le_bytes(bytes))
    }
}

impl Drop for RandomDraws {
    /// The unconsumed tail still selects characters of the password that was
    /// just generated; it does not outlive the call.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buf.zeroize();
    }
}

fn uniform_index(draws: &mut RandomDraws, n: usize) -> Result<usize, String> {
    let n = n as u32;
    loop {
        if let Some(index) = index_from(draws.draw()?, n) {
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
    let mut draws = RandomDraws::new();
    let mut password = String::with_capacity(options.length);
    for _ in 0..options.length {
        password.push(charset[uniform_index(&mut draws, charset.len())?]);
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

/// Record that the generator produced a password.
///
/// [`generate_password`] is pure — it takes options, not state — so nothing
/// in it can write the audit entry. Whichever front end ran it has to say so
/// here, or the log quietly loses the event (which is exactly what the gpui
/// build did before this existed).
pub fn log_password_generated(state: &Arc<AppState>, length: usize) {
    record_audit_event(state, AuditAction::PasswordGenerated { length });
}

pub fn get_vault_health(state: &Arc<AppState>) -> Result<VaultHealth, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();

    // One pass, borrowing each password as a map key instead of cloning it, and
    // scoring it without building the two verdict strings per login that
    // `calculate_password_strength` returns.
    let mut total_logins = 0usize;
    let mut weak_passwords = 0usize;
    let mut password_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();

    for item in vault.items.iter().filter(|i| i.item_type() == ItemType::Login) {
        let Some(password) = item.password() else {
            continue;
        };
        total_logins += 1;

        let (score, _) = strength_verdict(password_entropy(password));
        if score == "weak" || score == "fair" {
            weak_passwords += 1;
        }

        *password_counts.entry(password).or_insert(0) += 1;
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
/// Where an export is allowed to land.
///
/// Absolute, `.json`, no `..` component, an existing and accessible parent
/// directory, and never inside the app's own data directory — writing there
/// would let a caller overwrite `vault.enc` / `ipc_auth.json` through the
/// export command. The returned path is the *canonicalized* parent joined
/// with the original file name, so a symlinked directory is resolved before
/// the containment check rather than after it.
pub fn validate_export_path(store_path: &Path, raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Export path is empty".to_string());
    }
    let path = PathBuf::from(trimmed);

    if !path.is_absolute() {
        return Err("Export path must be absolute".to_string());
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("Export path must not contain parent-directory components".to_string());
    }
    let is_json = path.extension().map(|e| e.eq_ignore_ascii_case("json")).unwrap_or(false);
    if !is_json {
        return Err("Export path must have a .json extension".to_string());
    }

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Err("Export path has no parent directory".to_string()),
    };
    let canon_parent =
        std::fs::canonicalize(parent).map_err(|e| format!("Export directory is not accessible: {e}"))?;
    if !canon_parent.is_dir() {
        return Err("Export path parent is not a directory".to_string());
    }

    if let Ok(store_canon) = std::fs::canonicalize(store_path) {
        if canon_parent.starts_with(&store_canon) {
            return Err("Cannot export into the application data directory".to_string());
        }
    }

    let file_name = path.file_name().ok_or_else(|| "Export path has no file name".to_string())?;
    Ok(canon_parent.join(file_name))
}

/// Write an export to a user-chosen path, after [`validate_export_path`].
pub fn save_vault_export_file(state: &Arc<AppState>, path: &str, data: &str) -> Result<(), String> {
    require_unlocked(state)?;
    let validated = validate_export_path(state.store.store_path(), path)?;
    std::fs::write(validated, data).map_err(|e| format!("Failed to write export file: {}", e))
}

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
                credential_change_needs_reauth: None,
                allow_second_factor_downgrade: None,
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
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
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

    // ── export path guard (moved from src-tauri/src/commands/vault.rs) ──

    fn store_and_export_dirs() -> (tempfile::TempDir, tempfile::TempDir) {
        let store = tempfile::tempdir().unwrap();
        let export = tempfile::tempdir().unwrap();
        (store, export)
    }

    #[test]
    fn export_path_accepts_absolute_json_under_real_dir() {
        let (store, export) = store_and_export_dirs();
        let raw = export.path().join("vault-backup.json");
        let validated = validate_export_path(store.path(), raw.to_str().unwrap()).unwrap();
        assert_eq!(validated, std::fs::canonicalize(export.path()).unwrap().join("vault-backup.json"));
    }

    #[test]
    fn export_path_rejects_relative_and_empty() {
        let (store, _export) = store_and_export_dirs();
        let err = validate_export_path(store.path(), "backup.json").unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        let err = validate_export_path(store.path(), "   ").unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn export_path_rejects_parent_traversal() {
        let (store, export) = store_and_export_dirs();
        let raw = export.path().join("..").join("evil.json");
        let err = validate_export_path(store.path(), raw.to_str().unwrap()).unwrap_err();
        assert!(err.contains("parent-directory"), "{err}");
    }

    #[test]
    fn export_path_requires_json_extension() {
        let (store, export) = store_and_export_dirs();
        for name in ["vault.json.bak", "vault.txt", "vault", ".json_hidden"] {
            let raw = export.path().join(name);
            let err = validate_export_path(store.path(), raw.to_str().unwrap()).unwrap_err();
            assert!(err.contains(".json"), "{name}: {err}");
        }
        // Case-insensitive extension is accepted.
        let raw = export.path().join("vault.JSON");
        assert!(validate_export_path(store.path(), raw.to_str().unwrap()).is_ok());
    }

    #[test]
    fn export_path_rejects_missing_directory() {
        let (store, _export) = store_and_export_dirs();
        let err = validate_export_path(store.path(), "/nonexistent-dir-xyz/a.json").unwrap_err();
        assert!(err.contains("not accessible"), "{err}");
    }

    #[test]
    fn export_path_never_writes_into_app_data_dir() {
        let (store, _export) = store_and_export_dirs();
        // Directly inside the store dir...
        let raw = store.path().join("export.json");
        let err = validate_export_path(store.path(), raw.to_str().unwrap()).unwrap_err();
        assert!(err.contains("application data directory"), "{err}");
        // ...or a nested subdirectory of it.
        let nested = store.path().join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        let raw = nested.join("export.json");
        let err = validate_export_path(store.path(), raw.to_str().unwrap()).unwrap_err();
        assert!(err.contains("application data directory"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn export_path_canonicalizes_symlinked_parents() {
        // A symlinked directory must resolve to its real path, which also
        // means a symlink INTO the data dir is caught by the data-dir guard.
        let (store, export) = store_and_export_dirs();
        let link = export.path().join("link-to-store");
        std::os::unix::fs::symlink(store.path(), &link).unwrap();
        let raw = link.join("export.json");
        let err = validate_export_path(store.path(), raw.to_str().unwrap()).unwrap_err();
        assert!(err.contains("application data directory"), "{err}");
    }
}
