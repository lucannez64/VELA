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

use chrono::{DateTime, Utc};
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
    state
        .persist_current_vault()
        .map_err(|e| format!("Failed to save vault: {e}"))
}

fn validate_rich_item(state: &AppState, item: &VaultItem) -> Result<(), String> {
    let vault = state.vault.read();
    if vault.schema_version.unwrap_or(1) > 2 { return Err("Upgrade VELA to edit this vault".into()); }
    let rich = &item.meta().rich;
    if rich.has_data() && vault.schema_version != Some(2) { return Err("Enable folders and richer items first".into()); }
    let mut checked = rich.clone();
    let existing = vault.get_item(item.id()).map(|i| &i.meta().rich);
    // Future field types are read-only, but an unrelated edit must preserve them.
    if let Some(fields) = &mut checked.custom_fields {
        fields.retain(|f| !matches!(f.kind, vela_core::rich_items::CustomFieldType::Unknown(_))
            || !existing.and_then(|r| r.custom_fields.as_ref()).is_some_and(|old| old.contains(f)));
    }
    if let Some(urls) = &mut checked.additional_urls {
        urls.retain(|u| !matches!(u.match_mode, vela_core::rich_items::UrlMatch::Unknown(_))
            || !existing.and_then(|r| r.additional_urls.as_ref()).is_some_and(|old| old.contains(u)));
    }
    checked.validate_for_write().map_err(|e| e.to_string())?;
    if let Some(folder) = rich.folder_id.as_ref().filter(|s| !s.is_empty()) {
        if uuid::Uuid::parse_str(folder).ok().and_then(|id| vault.organization.folder(id)).is_none() { return Err("Folder no longer exists".into()); }
    }
    if rich.tag_ids.as_ref().is_some_and(|tags| tags.iter().any(|id| vault.organization.tag(*id).is_none())) { return Err("A selected tag no longer exists".into()); }
    Ok(())
}

pub async fn add_item(state: &Arc<AppState>, item: VaultItem) -> Result<VaultItem, String> {
    // Without this, a locked vault silently no-ops the persist step below
    // (save_vault is a no-op with no crypto key) while still mutating the
    // in-memory vault, recording an audit event, and returning success — the
    // item is then lost on next unlock/reload with no error surfaced.
    require_unlocked(state)?;

    validate_rich_item(state, &item)?;
    let now = Utc::now();
    let new_id = Uuid::new_v4().to_string();
    let new_item = item.with_id(new_id).with_updated_at(now);
    super::organization::transaction(state, |vault| {
        vault.add_item(new_item.clone());
        Ok(())
    })?;

    record_audit_event(
        state,
        AuditAction::ItemAdded {
            item_type: format!("{:?}", new_item.item_type()).to_lowercase(),
        },
    );

    tracing::info!("Item added: id={}", new_item.id());

    if new_item.item_type() == crate::vault::ItemType::Passkey {
        crate::commands::provider::schedule_autofill_sync(state);
    }

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
            // An edit never changes what an item is. Replacing a passkey with
            // a login of the same ID would destroy its private key.
            Some(existing) if existing.item_type() != item.item_type() => {
                return Err("This item's type cannot be changed".to_string());
            }
            Some(existing) => item.preserving_app_ids(existing),
            None => item,
        }
    };

    // A passkey's round-trip through the UI carries metadata only — the
    // private key is deliberately never sent to a front end. So an incoming
    // passkey update never trusts its own crypto fields: take the stored
    // credential back wholesale and keep only what the user actually edited
    // (name/notes/favorite, via `meta`).
    let item = {
        let vault = state.vault.read();
        let item_id = item.id().to_string();
        let incoming_meta = match &item {
            VaultItem::Passkey { meta, .. } => Some(meta.clone()),
            _ => None,
        };
        match incoming_meta {
            Some(meta) => match vault.get_item(&item_id) {
                Some(existing @ VaultItem::Passkey { .. }) => {
                    let mut restored = existing.clone();
                    if let VaultItem::Passkey { meta: existing_meta, .. } = &mut restored {
                        *existing_meta = meta;
                    }
                    restored
                }
                _ => item,
            },
            None => item,
        }
    };
    validate_rich_item(state, &item)?;
    let (updated, item_type) = super::organization::transaction(state, |vault| {
        let updated = item.with_updated_at(Utc::now());
        let item_type = format!("{:?}", updated.item_type()).to_lowercase();
        vault.update_item(updated.clone());
        Ok((updated, item_type))
    })?;
    let _ = crate::sharing::push_sent_share_update_inner(state, &updated).await;

    record_audit_event(state, AuditAction::ItemUpdated { item_type });

    if updated.item_type() == crate::vault::ItemType::Passkey {
        crate::commands::provider::schedule_autofill_sync(state);
    }

    Ok(updated)
}

pub async fn delete_item(state: &Arc<AppState>, id: &str) -> Result<(), String> {
    // See add_item: without this, a locked vault silently drops the delete
    // (save_vault no-ops) while still returning success.
    require_unlocked(state)?;

    let item_type = {
        let vault = state.vault.read();
        // Re-saving a newer-schema vault here would drop fields this build
        // does not know, exactly like an edit would.
        if vault.schema_version.unwrap_or(1) > 2 {
            return Err("Upgrade VELA to edit this vault".to_string());
        }
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

    super::organization::transaction(state, |vault| {
        vault.delete_item(id, device_id.as_deref());
        Ok(())
    })?;

    record_audit_event(state, AuditAction::ItemDeleted { item_type: item_type.clone() });

    if item_type == "passkey" {
        // The OS autofill cache is add-only from the provider's side, so a
        // deleted passkey must trigger the full clear-and-re-add refresh.
        crate::commands::provider::schedule_autofill_sync(state);
    }

    Ok(())
}

pub fn get_items(state: &Arc<AppState>) -> Result<Vec<VaultItem>, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    Ok(vault.items.clone())
}

/// Same as [`get_items`] but shares the store's snapshot instead of
/// deep-cloning: repeated calls between mutations cost one refcount bump.
/// Prefer this for in-process readers (the gpui front end); out-of-process
/// consumers (the Tauri renderer) need owned data for IPC anyway.
pub fn get_items_arc(state: &Arc<AppState>) -> Result<std::sync::Arc<Vec<VaultItem>>, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    Ok(vault.items_snapshot())
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
        "passkey" => ItemType::Passkey,
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
///
/// `length` is clamped, not trusted: the options arrive as JSON straight from
/// the webview (or any future caller), and only the UI slider caps them at 64.
/// A compromised page could otherwise ask for a multi-megabyte password on
/// every keystroke — bounded work from an untrusted source (fuzzing pass,
/// issue #149 family). The UI's own 8–64 range stays untouched; this is only
/// the ceiling a hostile caller cannot push past.
pub fn generate_password(options: PasswordGeneratorOptions) -> Result<PasswordWithStrength, String> {
    const MAX_LENGTH: usize = 1024;
    let length = options.length.min(MAX_LENGTH);
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
    let mut password = String::with_capacity(length);
    for _ in 0..length {
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
    /// Rows recognized but not imported at all (unknown item types).
    #[serde(default)]
    pub skipped: u32,
    /// Rows that matched an item already in the vault (or earlier in the same
    /// file) by site + username, and were left alone.
    #[serde(default)]
    pub duplicates: u32,
    pub total: u32,
    /// Items whose folders, tags, custom fields, extra URLs or identity
    /// details were stored as first-class rich data.
    #[serde(default)]
    pub preserved: u32,
    /// Attributes that had to be flattened into notes (vault not upgraded to
    /// collections yet, or a field the vault cannot represent).
    #[serde(default)]
    pub converted: u32,
    /// Human-readable field-level losses, e.g. `attachments ×3`.
    #[serde(default)]
    pub unsupported: Vec<String>,
    /// Which export format the file was detected as.
    #[serde(default)]
    pub source: String,
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
    let allowed = ["json", "csv", "vela"];
    let ext_ok = path
        .extension()
        .map(|e| allowed.iter().any(|a| e.eq_ignore_ascii_case(a)))
        .unwrap_or(false);
    if !ext_ok {
        return Err("Export path must have a .json, .csv or .vela extension".to_string());
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
                rich: Default::default(),
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

    Ok(ImportResult {
        added: added_count,
        skipped: skipped_count,
        duplicates: 0,
        total: total_count,
        preserved: 0,
        converted: 0,
        unsupported: Vec::new(),
        source: "Bitwarden JSON (legacy)".to_string(),
    })
}

/// The dedup key for a login: site + username. The host is stripped of
/// scheme/path/www so `https://www.GitHub.com/login` and `github.com` land on
/// the same key; a login without a URL falls back to its name so entries from
/// the same "site" still collide with each other rather than all importing.
fn login_dedup_key(url: &str, name: &str, username: &str) -> (String, String) {
    let host = if url.trim().is_empty() {
        name.trim().to_lowercase()
    } else {
        let rest = url.trim();
        let rest = rest.split_once("://").map(|(_, r)| r).unwrap_or(rest);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);
        let host = host.trim().to_lowercase();
        host.strip_prefix("www.")
            .map(str::to_string)
            .unwrap_or(host)
    };
    (host, username.trim().to_lowercase())
}

/// Import from any supported source (Bitwarden, 1Password, KeePass/KeePassXC,
/// Chrome/Edge/Safari, Proton Pass, or a VELA export) with automatic format
/// detection, field mapping, and deduplication.
///
/// Duplicates — same site + username as an item already in the vault, or as
/// an earlier row of this same file — are counted and skipped, not merged:
/// import must never silently overwrite an existing password. Running the
/// same import twice therefore reports the second run as all-duplicates
/// rather than doubling the vault.
pub fn import_vault_file(state: &Arc<AppState>, data: &str) -> Result<ImportResult, String> {
    let parsed = crate::import::parse_import(data)?;
    import_parsed(state, parsed)
}

/// Same as [`import_vault_file`], but accepts binary exports too
/// (1Password `.1pux` is a ZIP archive, not text).
pub fn import_vault_bytes(state: &Arc<AppState>, data: &[u8]) -> Result<ImportResult, String> {
    let parsed = crate::import::parse_import_bytes(data)?;
    import_parsed(state, parsed)
}

/// Map a parsed export onto vault items, preserving everything the vault can
/// represent and reporting what it cannot.
fn import_parsed(
    state: &Arc<AppState>,
    parsed: crate::import::ParsedImport,
) -> Result<ImportResult, String> {
    use crate::import::{EntryKind, ImportedEntry};
    use std::collections::HashMap;

    require_unlocked(state)?;

    let now = Utc::now();
    let total_count = parsed.entries.len() as u32 + parsed.skipped_unsupported;
    let source = parsed.source.to_string();
    let skipped_rows = parsed.skipped_unsupported;
    let unsupported: Vec<String> = parsed
        .unsupported
        .iter()
        .map(|(label, count)| format!("{label} ×{count}"))
        .collect();

    let mut added_count = 0u32;
    let mut duplicates_count = 0u32;
    let mut preserved_count = 0u32;
    let mut converted_count = 0u32;

    {
        let mut vault = state.vault.write();
        let collections = vault.schema_version == Some(2);
        let device = state
            .store
            .load_device_id()
            .unwrap_or_else(|_| "import".to_string());
        let mut folder_cache: HashMap<String, Uuid> = HashMap::new();
        let mut tag_cache: HashMap<String, Uuid> = HashMap::new();

        let mut seen_logins: std::collections::HashSet<(String, String)> = vault
            .items
            .iter()
            .filter(|item| matches!(item, VaultItem::Login { .. }))
            .map(|item| {
                login_dedup_key(
                    item.url().unwrap_or(""),
                    item.name(),
                    item.username().unwrap_or(""),
                )
            })
            .collect();
        let mut seen_cards: std::collections::HashSet<String> = vault
            .items
            .iter()
            .filter_map(|item| match item {
                VaultItem::CreditCard { number, .. } => Some(card_dedup_key(number, item.name())),
                _ => None,
            })
            .collect();
        let mut seen_identities: std::collections::HashSet<String> = vault
            .items
            .iter()
            .filter_map(|item| match item {
                VaultItem::Identity { .. } => Some(identity_dedup_key(item.name(), item.notes().unwrap_or(""))),
                _ => None,
            })
            .collect();

        for mut entry in parsed.entries {
            // Attachments are stored after the item itself, so a duplicate
            // login does not leave orphaned notes behind.
            let attachments = std::mem::take(&mut entry.attachments);
            let name = fallback_name(&entry);

            // Rich data is only first-class once the vault has collections.
            // Otherwise it is folded into notes and counted as converted, so
            // nothing the export carried is silently dropped.
            let mut rich = vela_core::rich_items::RichItemData::default();
            let mut item_preserved = false;
            if collections {
                if let Some(folder) = entry.folder.as_deref().filter(|f| !f.trim().is_empty()) {
                    match ensure_folder_path(&mut vault.organization, folder, &device, now, &mut folder_cache) {
                        Ok(id) => {
                            rich.folder_id = Some(id.to_string());
                            item_preserved = true;
                        }
                        Err(_) => converted_count += 1,
                    }
                }
                if !entry.tags.is_empty() {
                    let mut ids = Vec::new();
                    for tag in &entry.tags {
                        match ensure_tag(&mut vault.organization, tag, &device, now, &mut tag_cache) {
                            Ok(id) => ids.push(id),
                            Err(_) => converted_count += 1,
                        }
                    }
                    if !ids.is_empty() {
                        rich.tag_ids = Some(ids);
                        item_preserved = true;
                    }
                }
                if !entry.fields.is_empty() {
                    let fields: Vec<_> = entry.fields.iter().filter_map(to_custom_field).collect();
                    converted_count += (entry.fields.len() - fields.len()) as u32;
                    if !fields.is_empty() {
                        rich.custom_fields = Some(fields);
                        item_preserved = true;
                    }
                }
                if !entry.extra_urls.is_empty() {
                    let urls: Vec<_> = entry.extra_urls.iter().filter_map(|u| to_additional_url(u)).collect();
                    converted_count += (entry.extra_urls.len() - urls.len()) as u32;
                    if !urls.is_empty() {
                        rich.additional_urls = Some(urls);
                        item_preserved = true;
                    }
                }
                if entry.kind == EntryKind::Identity {
                    let details = to_identity_details(&entry.identity);
                    if identity_details_present(&details) {
                        rich.identity_details = Some(details);
                        item_preserved = true;
                    }
                }
                if rich.validate_for_write().is_err() {
                    rich = vela_core::rich_items::RichItemData::default();
                    converted_count += 1;
                    item_preserved = false;
                }
            }
            if item_preserved {
                preserved_count += 1;
            }

            let mut notes = entry.notes.clone();
            if !collections || !item_preserved {
                let folded = fold_into_notes(&entry);
                if !folded.is_empty() {
                    if !notes.is_empty() {
                        notes.push('\n');
                    }
                    notes.push_str(&folded);
                    converted_count += 1;
                }
            }
            let notes = notes.trim().to_string();

            match entry.kind {
                EntryKind::Login => {
                    let key = login_dedup_key(&entry.url, &name, &entry.username);
                    if !seen_logins.insert(key) {
                        duplicates_count += 1;
                        continue;
                    }
                    let url = if entry.url.is_empty() { None } else { Some(entry.url.as_str()) };
                    let totp = if entry.totp.is_empty() { None } else { Some(entry.totp) };
                    vault.add_item(VaultItem::Login {
                        meta: import_meta(&name, empty_to_none(notes), entry.favorite, rich),
                        url: normalize_import_url(url),
                        username: entry.username,
                        pass: entry.password,
                        totp,
                        app_ids: Vec::new(),
                        credential_change_needs_reauth: None,
                        allow_second_factor_downgrade: None,
                    });
                    added_count += 1;
                }
                EntryKind::Note => {
                    // Notes have no natural identity key; importing the same
                    // note twice yields two notes rather than a lost one.
                    vault.add_item(VaultItem::SecureNote {
                        meta: import_meta(&name, None, entry.favorite, rich),
                        title: entry.name.clone(),
                        content: notes,
                    });
                    added_count += 1;
                }
                EntryKind::Card => {
                    let key = card_dedup_key(&entry.card.number, &name);
                    if !seen_cards.insert(key) {
                        duplicates_count += 1;
                        continue;
                    }
                    vault.add_item(VaultItem::CreditCard {
                        meta: import_meta(&name, empty_to_none(notes), entry.favorite, rich),
                        number: entry.card.number,
                        exp: entry.card.expiry,
                        cvv: entry.card.cvv,
                        pin: empty_to_none(entry.card.pin),
                        cardholder_name: empty_to_none(entry.card.cardholder),
                    });
                    added_count += 1;
                }
                EntryKind::Identity => {
                    let key = identity_dedup_key(&name, &notes);
                    if !seen_identities.insert(key) {
                        duplicates_count += 1;
                        continue;
                    }
                    vault.add_item(VaultItem::Identity {
                        meta: import_meta(&name, empty_to_none(notes), entry.favorite, rich),
                        first_name: entry.identity.first.clone(),
                        last_name: entry.identity.last.clone(),
                        ssn: entry.identity.ssn.clone(),
                    });
                    added_count += 1;
                }
            }

            // 1Password attachments: the vault has no file-blob viewer yet, so
            // keep the bytes in an encrypted note with a decodable header.
            for attachment in attachments {
                let content = crate::import::encode_attachment_note(
                    &attachment.file_name,
                    &attachment.mime,
                    &attachment.bytes,
                );
                vault.add_item(VaultItem::SecureNote {
                    meta: import_meta(
                        &format!("{} — {}", name, attachment.file_name),
                        None,
                        false,
                        vela_core::rich_items::RichItemData::default(),
                    ),
                    title: attachment.file_name.clone(),
                    content,
                });
                added_count += 1;
                preserved_count += 1;
            }
        }

        tracing::info!(
            "Import ({source}): {added_count} added, {duplicates_count} duplicates, {preserved_count} preserved, {converted_count} converted, {total_count} total"
        );
    }

    save_vault(state)?;

    Ok(ImportResult {
        added: added_count,
        skipped: skipped_rows,
        duplicates: duplicates_count,
        total: total_count,
        preserved: preserved_count,
        converted: converted_count,
        unsupported,
        source,
    })
}

fn import_meta(
    name: &str,
    notes: Option<String>,
    favorite: bool,
    rich: vela_core::rich_items::RichItemData,
) -> crate::vault::VaultMeta {
    crate::vault::VaultMeta {
        rich,
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        notes,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_modified_device: None,
        favorite,
        shared: false,
        share_recipient: None,
    }
}

fn empty_to_none(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn fallback_name(entry: &crate::import::ImportedEntry) -> String {
    if !entry.name.is_empty() {
        entry.name.clone()
    } else if !entry.url.is_empty() {
        entry.url.clone()
    } else if !entry.username.is_empty() {
        entry.username.clone()
    } else {
        match entry.kind {
            crate::import::EntryKind::Card => "Imported card".to_string(),
            crate::import::EntryKind::Identity => "Imported identity".to_string(),
            crate::import::EntryKind::Note => "Imported note".to_string(),
            crate::import::EntryKind::Login => "Imported login".to_string(),
        }
    }
}

fn card_dedup_key(number: &str, name: &str) -> String {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    let tail: String = digits.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("{}|{}", tail.to_lowercase(), name.trim().to_lowercase())
}

fn identity_dedup_key(name: &str, notes: &str) -> String {
    format!("{}|{}", name.trim().to_lowercase(), notes.trim().to_lowercase())
}

fn unsupported_total(unsupported: &[String]) -> u32 {
    unsupported
        .iter()
        .filter_map(|entry| entry.rsplit('×').next()?.trim().parse::<u32>().ok())
        .sum()
}

/// Create (or reuse) every segment of a folder path.
fn ensure_folder_path(
    organization: &mut vela_core::rich_items::OrganizationData,
    path: &str,
    device: &str,
    now: DateTime<Utc>,
    cache: &mut std::collections::HashMap<String, Uuid>,
) -> Result<Uuid, String> {
    let mut parent: Option<Uuid> = None;
    let mut accumulated = String::new();
    for segment in path.split('/').map(str::trim).filter(|s| !s.is_empty()) {
        if !accumulated.is_empty() {
            accumulated.push('/');
        }
        accumulated.push_str(segment);
        if let Some(id) = cache.get(&accumulated) {
            parent = Some(*id);
            continue;
        }
        let existing = organization
            .folders
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(segment) && f.parent_id == parent)
            .map(|f| f.id);
        let id = match existing {
            Some(id) => id,
            None => organization
                .create_folder(segment, parent, device, now)
                .map_err(|e| e.to_string())?,
        };
        cache.insert(accumulated.clone(), id);
        parent = Some(id);
    }
    parent.ok_or_else(|| "Empty folder path".to_string())
}

fn ensure_tag(
    organization: &mut vela_core::rich_items::OrganizationData,
    name: &str,
    device: &str,
    now: DateTime<Utc>,
    cache: &mut std::collections::HashMap<String, Uuid>,
) -> Result<Uuid, String> {
    let key = name.trim().to_lowercase();
    if let Some(id) = cache.get(&key) {
        return Ok(*id);
    }
    if let Some(existing) = organization
        .tags
        .iter()
        .find(|t| t.name.eq_ignore_ascii_case(name.trim()))
    {
        cache.insert(key, existing.id);
        return Ok(existing.id);
    }
    let id = organization
        .create_tag(name, device, now)
        .map_err(|e| e.to_string())?;
    cache.insert(key, id);
    Ok(id)
}

fn to_custom_field(field: &crate::import::ImportedField) -> Option<vela_core::rich_items::CustomField> {
    use vela_core::rich_items::{CustomField, CustomFieldType, SensitiveValue};
    let label = field.label.trim();
    if label.is_empty() {
        return None;
    }
    let (kind, value) = match field.kind {
        crate::import::FieldKind::Text => (CustomFieldType::Text, serde_json::Value::String(field.value.clone())),
        crate::import::FieldKind::Concealed => (CustomFieldType::Concealed, serde_json::Value::String(field.value.clone())),
        crate::import::FieldKind::Boolean => (
            CustomFieldType::Boolean,
            serde_json::Value::Bool(matches!(field.value.trim().to_lowercase().as_str(), "true" | "1" | "yes")),
        ),
    };
    let field = CustomField {
        id: Uuid::new_v4(),
        label: label.to_string(),
        kind,
        value: SensitiveValue(value),
        extra: Default::default(),
    };
    field.validate_for_write().ok()?;
    Some(field)
}

fn to_additional_url(url: &str) -> Option<vela_core::rich_items::AdditionalUrl> {
    use vela_core::rich_items::{AdditionalUrl, UrlMatch};
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let record = AdditionalUrl {
        id: Uuid::new_v4(),
        url: url.to_string(),
        match_mode: UrlMatch::Exact,
        extra: Default::default(),
    };
    record.validate_for_write().ok()?;
    Some(record)
}

fn to_identity_details(identity: &crate::import::ImportedIdentity) -> vela_core::rich_items::IdentityDetails {
    use vela_core::rich_items::{IdentityDetails, PostalAddress};
    IdentityDetails {
        middle_name: empty_to_none(identity.middle.clone()),
        preferred_name: None,
        email: empty_to_none(identity.email.clone()),
        phone: empty_to_none(identity.phone.clone()),
        company: empty_to_none(identity.company.clone()),
        job_title: empty_to_none(identity.job_title.clone()),
        addresses: identity
            .addresses
            .iter()
            .filter(|a| !a.line1.is_empty() || !a.city.is_empty())
            .map(|a| PostalAddress {
                id: Uuid::new_v4(),
                label: empty_to_none(a.label.clone()),
                line1: empty_to_none(a.line1.clone()),
                line2: empty_to_none(a.line2.clone()),
                city: empty_to_none(a.city.clone()),
                region: empty_to_none(a.region.clone()),
                postal_code: empty_to_none(a.postal.clone()),
                country_code: empty_to_none(a.country.clone()),
                extra: Default::default(),
            })
            .collect(),
        extra: Default::default(),
    }
}

fn identity_details_present(details: &vela_core::rich_items::IdentityDetails) -> bool {
    details.email.is_some()
        || details.phone.is_some()
        || details.company.is_some()
        || details.job_title.is_some()
        || details.middle_name.is_some()
        || !details.addresses.is_empty()
}

/// Everything the vault cannot hold as rich data is appended to notes, so the
/// import report can honestly say it was converted rather than lost.
fn fold_into_notes(entry: &crate::import::ImportedEntry) -> String {
    use crate::import::EntryKind;
    let mut lines = Vec::new();
    if let Some(folder) = entry.folder.as_deref().filter(|f| !f.trim().is_empty()) {
        lines.push(format!("Folder: {folder}"));
    }
    if !entry.tags.is_empty() {
        lines.push(format!("Tags: {}", entry.tags.join(", ")));
    }
    if !entry.fields.is_empty() {
        lines.push("Custom fields:".to_string());
        for field in &entry.fields {
            lines.push(format!("  {}: {}", field.label, field.value));
        }
    }
    if !entry.extra_urls.is_empty() {
        lines.push("Additional websites:".to_string());
        for url in &entry.extra_urls {
            lines.push(format!("  {url}"));
        }
    }
    if entry.kind == EntryKind::Identity {
        let identity = &entry.identity;
        let mut detail = Vec::new();
        for (label, value) in [
            ("Email", &identity.email),
            ("Phone", &identity.phone),
            ("Company", &identity.company),
            ("Job title", &identity.job_title),
        ] {
            if !value.is_empty() {
                detail.push(format!("  {label}: {value}"));
            }
        }
        for address in &identity.addresses {
            let joined = [
                address.line1.as_str(),
                address.line2.as_str(),
                address.city.as_str(),
                address.region.as_str(),
                address.postal.as_str(),
                address.country.as_str(),
            ]
            .iter()
            .filter(|part| !part.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
            if !joined.is_empty() {
                detail.push(format!("  Address: {joined}"));
            }
        }
        if !detail.is_empty() {
            lines.push("Identity:".to_string());
            lines.extend(detail);
        }
    }
    lines.join("\n")
}

// ── Export: encrypted archive (.vela) and CSV ────────────────────────────────
//
// Three export shapes, three purposes:
// - `.vela` — a full backup of every item (logins, notes, cards, passkeys,
//   …) encrypted under a passphrase chosen at export time. Self-contained:
//   it restores without the master key, on this device or a fresh one.
// - CSV — the migration-OUT format. Bitwarden's CSV schema is written
//   because every other manager imports it.
// - JSON (see [`export_vault_bitwarden_json`]) — the pre-existing plaintext
//   login export.
//
// People do not commit to a vault they cannot leave: the plaintext exports
// are deliberate, and the archive keeps passkey material and TOTP seeds —
// the things CSV cannot represent — out of plaintext.

#[derive(Debug, Serialize, Deserialize)]
struct VelaArchive {
    #[serde(default, rename = "schemaVersion")]
    schema_version: Option<u32>,
    #[serde(default, flatten)]
    organization: vela_core::rich_items::OrganizationData,
    #[serde(default)]
    tombstones: Vec<crate::vault::Tombstone>,
    kind: String,
    version: u32,
    items: Vec<VaultItem>,
}

const ARCHIVE_KIND: &str = "vela-archive";
const ARCHIVE_VERSION: u32 = 1;
const ARCHIVE_MIN_PASSPHRASE_LEN: usize = 8;

/// Serialize every vault item and seal it under `passphrase` (Argon2id +
/// AEAD, per-blob salt — the same machinery the vault file itself uses).
///
/// The archive is deliberately independent of the master key: a backup that
/// needed the RMS would be useless after "lost device, new install".
pub fn export_vault_encrypted(state: &Arc<AppState>, passphrase: &str) -> Result<Vec<u8>, String> {
    require_unlocked(state)?;

    // Deliberately not trimmed: spaces may be intentional parts of a
    // passphrase, and silent normalization would lock out anyone who typed
    // leading/trailing whitespace.
    if passphrase.chars().count() < ARCHIVE_MIN_PASSPHRASE_LEN {
        return Err(format!(
            "Passphrase must be at least {ARCHIVE_MIN_PASSPHRASE_LEN} characters"
        ));
    }

    let vault = state.vault.read().clone();
    let payload = VelaArchive {
        schema_version: vault.schema_version,
        organization: vault.organization,
        tombstones: vault.tombstones,
        kind: ARCHIVE_KIND.to_string(),
        version: ARCHIVE_VERSION,
        items: vault.items,
    };
    let plaintext =
        serde_json::to_vec(&payload).map_err(|e| format!("Failed to serialize export: {e}"))?;

    vela_crypto::password_kdf::seal_with_password(passphrase.as_bytes(), &plaintext)
        .map_err(|e| format!("Failed to encrypt export: {e}"))
}

/// Open a `.vela` archive and return its items without touching the vault —
/// separated from [`import_vela_archive`] so the UI can validate the
/// passphrase before choosing what to do with the contents.
fn open_archive(data: &[u8], passphrase: &str) -> Result<VelaArchive, String> {
    let plaintext = zeroize::Zeroizing::new(
        vela_crypto::password_kdf::open_with_password(passphrase.as_bytes(), data)
            .map_err(|_| "Wrong passphrase, or not a VELA archive".to_string())?,
    );
    let archive: VelaArchive = serde_json::from_slice(&plaintext)
        .map_err(|_| "This file is not a VELA archive".to_string())?;
    if archive.kind != ARCHIVE_KIND || archive.version != ARCHIVE_VERSION {
        return Err(format!(
            "Unsupported archive (kind {}, version {})",
            archive.kind, archive.version
        ));
    }
    Ok(archive)
}

pub fn open_vela_archive(data: &[u8], passphrase: &str) -> Result<Vec<VaultItem>, String> {
    Ok(open_archive(data, passphrase)?.items)
}

/// Restore a `.vela` archive. Dedup is by item id: the archive is the same
/// vault's own backup, so a present id means the item is already here —
/// restoring into an existing vault is idempotent, and importing over a
/// fresh vault lands every item with its original metadata intact.
pub fn import_vela_archive(
    state: &Arc<AppState>,
    data: &[u8],
    passphrase: &str,
) -> Result<ImportResult, String> {
    let archive = open_archive(data, passphrase)?;
    if archive.schema_version.unwrap_or(1) > 2 { return Err("Upgrade VELA to restore this archive".into()); }
    if archive.schema_version == Some(2) && state.vault.read().schema_version != Some(2) { return Err("Enable folders and richer items before restoring this archive".into()); }
    let items = archive.items;
    require_unlocked(state)?;

    // Report every archived item that carries organization or rich fields.
    let preserved_count = items
        .iter()
        .filter(|item| {
            let rich = &item.meta().rich;
            rich.folder_id.is_some()
                || rich.tag_ids.as_ref().is_some_and(|tags| !tags.is_empty())
                || rich.custom_fields.as_ref().is_some_and(|fields| !fields.is_empty())
                || rich.additional_urls.as_ref().is_some_and(|urls| !urls.is_empty())
                || rich.identity_details.is_some()
        })
        .count() as u32;
    let total_count = items.len() as u32;
    let mut added_count = 0u32;
    let mut duplicates_count = 0u32;
    {
        let mut vault = state.vault.write();
        vault.organization = vault.organization.merged(&archive.organization).map_err(|e| e.to_string())?;
        vault.schema_version = vault.schema_version.max(archive.schema_version);
        if vault.items.is_empty() { vault.tombstones = archive.tombstones; }
        for item in items {
            if vault.get_item(item.id()).is_some() {
                duplicates_count += 1;
                continue;
            }
            vault.add_item(item);
            added_count += 1;
        }
    }

    save_vault(state)?;

    Ok(ImportResult {
        added: added_count,
        skipped: 0,
        duplicates: duplicates_count,
        total: total_count,
        preserved: preserved_count,
        converted: 0,
        unsupported: Vec::new(),
        source: "VELA archive (.vela)".to_string(),
    })
}

/// Serialize all Login items as Bitwarden-schema CSV — the format every
/// other manager imports, so this is the door OUT of VELA.
///
/// Cells that spreadsheet apps would execute as formulas (`=`, `+`, `-`,
/// `@`, tab leads) are prefixed with a single quote, the standard mitigation
/// (Bitwarden does the same): site-controlled names otherwise become live
/// formulas the moment the user opens the file in Excel.
pub fn export_vault_csv(state: &Arc<AppState>) -> Result<String, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();

    let mut out = Vec::new();
    {
        let mut writer = csv::WriterBuilder::new().from_writer(&mut out);
        writer
            .write_record([
                "folder",
                "favorite",
                "type",
                "name",
                "notes",
                "fields",
                "reprompt",
                "login_uri",
                "login_username",
                "login_password",
                "login_totp",
            ])
            .map_err(|e| format!("Failed to write export: {e}"))?;

        for item in vault.items.iter() {
            let VaultItem::Login {
                meta,
                url,
                username,
                pass,
                totp,
                ..
            } = item
            else {
                continue;
            };
            let notes = meta.notes.as_deref().unwrap_or("");
            writer
                .write_record([
                    csv_export_safe(""),
                    csv_export_safe(if meta.favorite { "true" } else { "" }),
                    csv_export_safe("login"),
                    csv_export_safe(&meta.name),
                    csv_export_safe(notes),
                    csv_export_safe(""),
                    csv_export_safe(""),
                    csv_export_safe(url),
                    csv_export_safe(username),
                    csv_export_safe(pass),
                    csv_export_safe(totp.as_deref().unwrap_or("")),
                ])
                .map_err(|e| format!("Failed to write export: {e}"))?;
        }
        writer.flush().map_err(|e| format!("Failed to write export: {e}"))?;
    }

    String::from_utf8(out).map_err(|_| "Export produced invalid UTF-8".to_string())
}

fn csv_export_safe(cell: &str) -> String {
    if cell.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{cell}")
    } else {
        cell.to_string()
    }
}

/// Write raw export bytes to a validated path (for the binary `.vela`
/// archive; text exports keep flowing through [`save_vault_export_file`]).
pub fn save_vault_export_bytes(state: &Arc<AppState>, path: &str, data: &[u8]) -> Result<(), String> {
    require_unlocked(state)?;
    let validated = validate_export_path(state.store.store_path(), path)?;
    std::fs::write(validated, data).map_err(|e| format!("Failed to write export file: {e}"))
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

    fn passkey(id: &str) -> VaultItem {
        serde_json::from_value(serde_json::json!({
            "item_type": "passkey", "id": id, "name": "Key", "rp_id": "example.test",
            "private_key": "never-lose-this"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn an_edit_cannot_turn_a_passkey_into_another_type() {
        let (_dir, state) = unlocked_state();
        state.vault.write().add_item(passkey("pk"));
        let replacement = login("Key", "https://example.test", "user", "pass").with_id("pk".into());
        assert!(update_item(&state, replacement).await.is_err());
        let vault = state.vault.read();
        match vault.get_item("pk") {
            Some(VaultItem::Passkey { private_key, .. }) => assert_eq!(private_key, "never-lose-this"),
            other => panic!("passkey was replaced: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_desktop_edit_does_not_pin_later_remote_changes_as_conflicts() {
        let (_dir, state) = unlocked_state();
        state.store.save_device_id("desktop-test-device").unwrap();
        let item = add_item(&state, login("Original", "https://example.test", "u", "p")).await.unwrap();
        let edited = update_item(&state, item.with_name("Desktop edit".into())).await.unwrap();
        let mut local = state.vault.read().clone();
        let mut remote = crate::vault::VaultStore::new();
        remote.add_item(edited.with_name("Later remote edit".into())
            .with_updated_at(edited.updated_at() + chrono::Duration::seconds(1)));
        let conflicts = crate::sync::merge_server_vaults(&mut local, remote, "desktop-test-device").unwrap();
        assert!(conflicts.is_empty());
        assert_eq!(local.get_item(edited.id()).unwrap().name(), "Later remote edit");
    }

    #[tokio::test]
    async fn deleting_a_future_schema_vault_is_rejected() {
        let (_dir, state) = unlocked_state();
        state.vault.write().add_item(passkey("pk"));
        state.vault.write().schema_version = Some(3);
        assert!(delete_item(&state, "pk").await.unwrap_err().contains("Upgrade VELA"));
        assert!(state.vault.read().get_item("pk").is_some());
    }

    #[tokio::test]
    async fn passkeys_cannot_be_shared() {
        let (_dir, state) = unlocked_state();
        state.vault.write().add_item(passkey("pk"));
        let error = crate::sharing::send_share(&state, "pk", "recipient", false).await.unwrap_err();
        assert!(error.contains("Passkeys cannot be shared"));
    }

    fn login(name: &str, url: &str, user: &str, pass: &str) -> VaultItem {
        let now = Utc::now();
        VaultItem::Login {
            meta: VaultMeta {
                rich: Default::default(),
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

    /// The options arrive as JSON from the webview, past the UI slider's
    /// 8–64 range. Whatever a hostile page asks for, the work done stays
    /// bounded (fuzzing pass).
    #[test]
    fn generate_password_clamps_an_absurd_length() {
        let pw = generate_password(PasswordGeneratorOptions {
            length: 100_000_000,
            ..PasswordGeneratorOptions::default()
        })
        .unwrap();
        assert!(pw.password.len() <= 1024, "untrusted length must be clamped");

        // Zero and the exact ceiling still behave.
        assert_eq!(
            generate_password(PasswordGeneratorOptions { length: 0, ..Default::default() })
                .unwrap()
                .password
                .len(),
            0
        );
        assert_eq!(
            generate_password(PasswordGeneratorOptions { length: 1024, ..Default::default() })
                .unwrap()
                .password
                .len(),
            1024
        );
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
    async fn passkey_update_preserves_the_stored_credential() {
        // The UI round-trips passkey metadata only — the private key never
        // crosses IPC (there is no getter for it). An incoming update that
        // carries an empty key must therefore merge against the stored
        // credential, not overwrite it.
        let (_dir, state) = unlocked_state();

        let now = Utc::now();
        let stored_key = "c2VjcmV0LXNjYWxhcg";
        let added = add_item(&state, VaultItem::Passkey {
            meta: VaultMeta {
                rich: Default::default(),
                id: Uuid::new_v4().to_string(),
                name: "github.com".into(),
                notes: None,
                created_at: now,
                updated_at: now,
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            rp_id: "github.com".into(),
            rp_name: "GitHub".into(),
            credential_id: "Y3JlZC1pZA".into(),
            user_handle: "aGFuZGxl".into(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            private_key: stored_key.into(),
            sign_count: 7,
        })
        .await
        .unwrap();

        // What the UI sends back: same id, no key, edited favorite.
        let incoming = {
            let vault = state.vault.read();
            let item = vault.get_item(added.id()).cloned().unwrap();
            let meta = match &item {
                VaultItem::Passkey { meta, .. } => {
                    let mut meta = meta.clone();
                    meta.favorite = true;
                    meta
                }
                _ => panic!("seeded item must be a passkey"),
            };
            match &item {
                VaultItem::Passkey {
                    rp_id,
                    rp_name,
                    credential_id,
                    user_handle,
                    user_name,
                    user_display_name,
                    sign_count,
                    ..
                } => VaultItem::Passkey {
                    meta,
                    rp_id: rp_id.clone(),
                    rp_name: rp_name.clone(),
                    credential_id: credential_id.clone(),
                    user_handle: user_handle.clone(),
                    user_name: user_name.clone(),
                    user_display_name: user_display_name.clone(),
                    private_key: String::new(), // the UI has no key
                    sign_count: *sign_count,
                },
                _ => unreachable!(),
            }
        };

        let updated = update_item(&state, incoming).await.unwrap();
        match &updated {
            VaultItem::Passkey { meta, private_key, sign_count, rp_id, .. } => {
                assert!(meta.favorite, "the edit the user made is kept");
                assert_eq!(private_key, stored_key, "the stored key survives the update");
                assert_eq!(*sign_count, 7);
                assert_eq!(rp_id, "github.com");
            }
            _ => panic!("update must not change the item type"),
        }
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
    #[test]
    fn import_preserves_rich_fields_when_collections_are_enabled() {
        let (_dir, state) = unlocked_state();
        state.vault.write().schema_version = Some(2);
        let json = r#"{
            "encrypted": false,
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [{
                "type": 1, "name": "GitHub", "folderId": "f1",
                "login": { "username": "octo", "password": "pw",
                           "uris": [{ "uri": "https://github.com" },
                                    { "uri": "https://gist.github.com" }] },
                "fields": [{ "name": "Recovery", "value": "R-1", "type": 0 }]
            }]
        }"#;
        let report = import_vault_file(&state, json).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(report.preserved, 1);
        assert_eq!(report.converted, 0);

        let vault = state.vault.read();
        assert!(vault.organization.folders.iter().any(|f| f.name == "Work"));
        let item = vault.items.iter().find(|i| i.name() == "GitHub").unwrap();
        let rich = item.meta().rich.clone();
        assert!(rich.folder_id.is_some());
        assert_eq!(rich.custom_fields.as_ref().map(Vec::len), Some(1));
        assert_eq!(rich.additional_urls.as_ref().map(Vec::len), Some(1));
        assert!(item.notes().is_none());
    }

    #[test]
    fn import_folds_rich_fields_into_notes_before_collections() {
        let (_dir, state) = unlocked_state();
        let json = r#"{
            "encrypted": false,
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [{
                "type": 1, "name": "GitHub", "folderId": "f1",
                "login": { "username": "octo", "password": "pw" },
                "fields": [{ "name": "Recovery", "value": "R-1", "type": 0 }]
            }]
        }"#;
        let report = import_vault_file(&state, json).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(report.preserved, 0);
        assert!(report.converted >= 1);
        let vault = state.vault.read();
        assert!(vault.organization.folders.is_empty());
        let item = vault.items.iter().find(|i| i.name() == "GitHub").unwrap();
        let notes = item.notes().unwrap_or("");
        assert!(notes.contains("Folder: Work"), "{notes}");
        assert!(notes.contains("Recovery: R-1"), "{notes}");
    }

    #[test]
    fn imported_attachments_become_encrypted_notes() {
        let (_dir, state) = unlocked_state();
        let mut entry = crate::import::ImportedEntry {
            name: "GitHub".into(),
            kind: crate::import::EntryKind::Login,
            ..Default::default()
        };
        entry.attachments.push(crate::import::ImportedAttachment {
            file_name: "notes.txt".into(),
            mime: "text/plain".into(),
            bytes: b"attachment body".to_vec(),
        });
        let parsed = crate::import::ParsedImport {
            entries: vec![entry],
            skipped_unsupported: 0,
            unsupported: Default::default(),
            source: "test",
        };
        let report = import_parsed(&state, parsed).unwrap();
        assert_eq!(report.added, 2);
        assert_eq!(report.preserved, 1);
        let vault = state.vault.read();
        assert!(vault.items.iter().any(|item| matches!(
            item,
            VaultItem::SecureNote { content, .. } if content.contains("VELA IMPORTED ATTACHMENT")
        )));
    }

    #[test]
    fn import_creates_cards_and_identities_with_a_report() {
        let (_dir, state) = unlocked_state();
        let json = r#"{
            "encrypted": false,
            "items": [
                { "type": 3, "name": "Visa",
                  "card": { "cardholderName": "Alex", "number": "4111111111111111",
                            "expMonth": "08", "expYear": "2029", "code": "123" } },
                { "type": 4, "name": "Alex Demo",
                  "identity": { "firstName": "Alex", "lastName": "Demo", "email": "a@b.c" } }
            ]
        }"#;
        let report = import_vault_file(&state, json).unwrap();
        assert_eq!((report.added, report.skipped, report.duplicates), (2, 0, 0));
        assert_eq!(report.source, "Bitwarden JSON");
        let vault = state.vault.read();
        assert!(vault.items.iter().any(|i| matches!(i, VaultItem::CreditCard { .. })));
        assert!(vault.items.iter().any(|i| matches!(i, VaultItem::Identity { .. })));
    }

    #[test]
    fn import_vault_file_dedups_against_vault_and_within_file() {
        let (_dir, state) = unlocked_state();
        {
            let mut vault = state.vault.write();
            vault.add_item(login("GH", "https://github.com", "alice", "s3cret"));
        }

        // Row 1: same site+user as the vault item, case-insensitively, with a
        // different password → duplicate (import must not overwrite).
        // Row 2: matches row 1's key within this file → duplicate.
        // Row 3: different site, same user → added.
        // Row 4: different user, same site → added.
        let csv = "name,url,username,password\n\
                   GitHub,https://github.com/settings,ALICE,newpw\n\
                   GitHub,https://github.com,alice,other\n\
                   GitLab,gitlab.com,alice,pw3\n\
                   GitHub,https://github.com,octo,pw4";
        let result = import_vault_file(&state, csv).unwrap();
        assert_eq!((result.added, result.duplicates, result.skipped), (2, 2, 0), "{result:?}");

        let items = get_items(&state).unwrap();
        assert_eq!(items.len(), 3, "vault item + 2 new, no duplicates imported");
        // The pre-existing password must not have been touched.
        let gh = items.iter().find(|i| i.name() == "GH").unwrap();
        assert_eq!(gh.password(), Some("s3cret"));

        // Re-importing the same file reports duplicates instead of doubling
        // the vault.
        let again = import_vault_file(&state, csv).unwrap();
        assert_eq!((again.added, again.duplicates), (0, 4), "{again:?}");
        assert_eq!(get_items(&state).unwrap().len(), 3);
    }

    #[test]
    fn import_vault_file_creates_secure_notes_and_reports_skipped_types() {
        let (_dir, state) = unlocked_state();
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,,login,GitHub,,\"\",0,github.com,octo,hunter2,\n\
                   ,,note,Codes,abc123,,0,,,\n\
                   ,,card,Visa,,,,,,,";
        let result = import_vault_file(&state, csv).unwrap();
        assert_eq!((result.added, result.duplicates, result.skipped), (2, 0, 1), "{result:?}");

        let items = get_items(&state).unwrap();
        let gh = items.iter().find(|i| i.username() == Some("octo")).unwrap();
        assert_eq!(gh.password(), Some("hunter2"));
        let note = items.iter().find(|i| i.name() == "Codes").unwrap();
        assert!(matches!(note, VaultItem::SecureNote { .. }));
        assert!(matches!(note, VaultItem::SecureNote { content, .. } if content == "abc123"));
    }

    #[test]
    fn import_vault_file_requires_unlocked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState::for_test(dir.path()));
        let csv = "name,url,username,password\nA,a.com,u,p";
        let err = import_vault_file(&state, csv).unwrap_err();
        assert!(err.contains("locked"), "{err}");
    }

    #[test]
    fn encrypted_archive_roundtrips_every_item_type() {
        let (_dir, state) = unlocked_state();
        {
            let mut vault = state.vault.write();
            vault.add_item(login("GH", "https://github.com", "alice", "s3cret"));
            let now = Utc::now();
            vault.add_item(VaultItem::SecureNote {
                meta: VaultMeta {
                rich: Default::default(),
                    id: "note-1".into(),
                    name: "Recovery codes".into(),
                    notes: None,
                    created_at: now,
                    updated_at: now,
                    last_modified_device: None,
                    favorite: false,
                    shared: false,
                    share_recipient: None,
                },
                title: "Recovery codes".into(),
                content: "abc-def-123".into(),
            });
            vault.add_item(VaultItem::Passkey {
                meta: VaultMeta {
                rich: Default::default(),
                    id: "pk-1".into(),
                    name: "github".into(),
                    notes: None,
                    created_at: now,
                    updated_at: now,
                    last_modified_device: None,
                    favorite: false,
                    shared: false,
                    share_recipient: None,
                },
                rp_id: "github.com".into(),
                rp_name: "GitHub".into(),
                credential_id: "Y3JlZC1pZA".into(),
                user_handle: "aGFuZGxl".into(),
                user_name: "alice".into(),
                user_display_name: "Alice".into(),
                private_key: "c2VjcmV0LXNjYWxhcg".into(),
                sign_count: 7,
            });
        }

        let blob = export_vault_encrypted(&state, "correct horse battery").unwrap();

        // The archive must not contain plaintext secrets.
        let blob_str = String::from_utf8_lossy(&blob);
        assert!(!blob_str.contains("s3cret"), "password visible in archive");
        assert!(!blob_str.contains("abc-def-123"), "note visible in archive");

        // Wrong passphrase is refused without a confusing message.
        let err = open_vela_archive(&blob, "wrong passphrase").unwrap_err();
        assert!(err.contains("Wrong passphrase"), "{err}");

        // The right passphrase restores every item, metadata intact.
        let restored = open_vela_archive(&blob, "correct horse battery").unwrap();
        assert_eq!(restored.len(), 3);
        let passkey = restored
            .iter()
            .find(|i| matches!(i, VaultItem::Passkey { .. }))
            .expect("passkey material must survive the backup");

        // Restoring into this same vault is idempotent.
        let result = import_vela_archive(&state, &blob, "correct horse battery").unwrap();
        assert_eq!((result.added, result.duplicates), (0, 3), "{result:?}");
        assert_eq!(state.vault.read().items.len(), 3);

        // Restoring into a fresh vault lands everything, keys included.
        let (dir_b, state_b) = unlocked_state();
        let result = import_vela_archive(&state_b, &blob, "correct horse battery").unwrap();
        assert_eq!((result.added, result.duplicates), (3, 0), "{result:?}");
        drop(dir_b);
        let vault_b = state_b.vault.read();
        let pk = vault_b.get_item("pk-1").unwrap();
        assert_eq!(pk.credential_id(), Some("Y3JlZC1pZA"));
        let _ = passkey;
    }

    #[test]
    fn archive_passphrase_is_enforced() {
        let (_dir, state) = unlocked_state();
        let err = export_vault_encrypted(&state, "short").unwrap_err();
        assert!(err.contains("at least 8"), "{err}");
    }

    #[test]
    fn csv_export_is_bitwarden_schema_and_formula_safe() {
        let (_dir, state) = unlocked_state();
        {
            let mut vault = state.vault.write();
            vault.add_item(login("GH", "https://github.com", "alice", "hunter2"));
            // A site name that Excel would execute as a formula.
            vault.add_item(login("=HYPERLINK(evil)", "https://evil.example", "bob", "+1234"));
            vault.add_item(VaultItem::SecureNote {
                meta: VaultMeta {
                rich: Default::default(),
                    id: "note-1".into(),
                    name: "note".into(),
                    notes: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    last_modified_device: None,
                    favorite: false,
                    shared: false,
                    share_recipient: None,
                },
                title: "note".into(),
                content: "c".into(),
            });
        }

        let csv_data = export_vault_csv(&state).unwrap();
        // Non-login items are excluded; two logins = header + 2 rows.
        let rows: Vec<&str> = csv_data.lines().collect();
        assert_eq!(rows.len(), 3, "{csv_data}");
        assert!(rows[0].starts_with("folder,favorite,type,name,notes,"));
        assert!(rows[1].contains("alice"));
        assert!(rows[1].contains("hunter2"));
        // Formula-leading cells are neutralized with a leading quote.
        assert!(rows[2].contains("'=HYPERLINK(evil)"), "{csv_data}");
        assert!(rows[2].contains("'+1234"), "{csv_data}");
        // The CSV must round-trip through our own importer (2 rows, no dups).
        let (_dir2, state2) = unlocked_state();
        let result = import_vault_file(&state2, &csv_data).unwrap();
        assert_eq!((result.added, result.duplicates), (2, 0), "{result:?}");
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
                rich: Default::default(),
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
