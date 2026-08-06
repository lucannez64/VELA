use crate::commands::audit::{record_audit_event, AuditAction};
use crate::vault::{ItemType, PasswordGeneratorOptions, VaultItem};
use crate::AppState;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use once_cell::sync::Lazy;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{command, AppHandle, Emitter, State};
use url::Url;
use uuid::Uuid;

pub const VAULT_ITEMS_CHANGED_EVENT: &str = "vault-items-changed";

pub fn emit_vault_items_changed(app: &AppHandle) {
    let _ = app.emit(VAULT_ITEMS_CHANGED_EVENT, ());
}

#[command]
pub async fn fetch_favicon(url: String) -> Result<Option<String>, String> {
    vela_desktop_core::favicon::fetch_favicon(url).await
}

fn save_vault(state: &State<'_, Arc<AppState>>) -> Result<(), String> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrength {
    pub entropy: f64,
    pub score: String,
    pub crack_time: String,
}

fn calculate_password_strength(password: &str) -> PasswordStrength {
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

fn require_unlocked(state: &State<'_, Arc<AppState>>) -> Result<(), String> {
    if state.is_unlocked() {
        Ok(())
    } else {
        Err("Vault is locked".to_string())
    }
}

#[command]
pub async fn get_items(state: State<'_, Arc<AppState>>) -> Result<Vec<VaultItem>, String> {
    require_unlocked(&state)?;
    let vault = state.vault.read();
    let items = vault.items.clone();
    tracing::debug!("get_items: {} items in vault", items.len());
    Ok(items)
}

#[command]
pub async fn get_item(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<Option<VaultItem>, String> {
    require_unlocked(&state)?;
    let vault = state.vault.read();
    Ok(vault.get_item(&id).cloned())
}

#[command]
pub async fn add_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item: VaultItem,
) -> Result<VaultItem, String> {
    // Without this, a locked vault silently no-ops the persist step below
    // (save_vault is a no-op with no crypto key) while still mutating the
    // in-memory vault, recording an audit event, and returning success —
    // the item is then lost on next unlock/reload with no error surfaced.
    require_unlocked(&state)?;

    tracing::info!(
        "Adding item type: {:?}",
        match &item {
            VaultItem::Login { .. } => "login",
            VaultItem::CreditCard { .. } => "creditcard",
            VaultItem::SecureNote { .. } => "securenote",
            VaultItem::Identity { .. } => "identity",
            VaultItem::FileBlob { .. } => "fileblob",
            VaultItem::BreachMonitor { .. } => "breachmonitor",
            VaultItem::Passkey { .. } => "passkey",
        }
    );

    let mut vault = state.vault.write();
    let now = Utc::now();
    let new_id = Uuid::new_v4().to_string();
    let new_item = item.with_id(new_id).with_updated_at(now);
    vault.add_item(new_item.clone());

    drop(vault);
    save_vault(&state)?;

    record_audit_event(
        &state,
        AuditAction::ItemAdded {
            item_type: format!("{:?}", new_item.item_type()).to_lowercase(),
        },
    );

    tracing::info!("Item added: id={}", new_item.id());

    emit_vault_items_changed(&app);

    Ok(new_item)
}

#[command]
pub async fn update_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item: VaultItem,
) -> Result<VaultItem, String> {
    // See add_item: without this, a locked vault silently drops the update
    // (save_vault no-ops) while still returning success.
    require_unlocked(&state)?;

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

    save_vault(&state)?;
    let _ = crate::commands::sharing::push_sent_share_update_inner(&state, &updated).await;

    record_audit_event(&state, AuditAction::ItemUpdated { item_type });

    emit_vault_items_changed(&app);

    Ok(updated)
}

#[command]
pub async fn delete_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), String> {
    // See add_item: without this, a locked vault silently drops the delete
    // (save_vault no-ops) while still returning success.
    require_unlocked(&state)?;

    let item_type = {
        let vault = state.vault.read();
        if let Some(item) = vault.get_item(&id) {
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
    vault.delete_item(&id, device_id.as_deref());
    drop(vault);
    save_vault(&state)?;

    record_audit_event(&state, AuditAction::ItemDeleted { item_type });

    emit_vault_items_changed(&app);

    Ok(())
}

#[command]
pub async fn search_items(
    state: State<'_, Arc<AppState>>,
    query: String,
) -> Result<Vec<VaultItem>, String> {
    require_unlocked(&state)?;
    let vault = state.vault.read();
    Ok(vault.search(&query).into_iter().cloned().collect())
}

#[command]
pub async fn generate_password(
    options: PasswordGeneratorOptions,
) -> Result<PasswordWithStrength, String> {
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

#[command]
pub async fn log_password_generated(
    state: State<'_, Arc<AppState>>,
    length: usize,
) -> Result<(), String> {
    record_audit_event(&state, AuditAction::PasswordGenerated { length });
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordWithStrength {
    pub password: String,
    pub strength: PasswordStrength,
}

#[command]
pub async fn get_items_by_type(
    state: State<'_, Arc<AppState>>,
    item_type: String,
) -> Result<Vec<VaultItem>, String> {
    require_unlocked(&state)?;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealth {
    pub weak_passwords: usize,
    pub reused_passwords: usize,
    pub total_logins: usize,
    pub health_score: f64,
    pub status: String,
}

#[command]
pub async fn get_vault_health(state: State<'_, Arc<AppState>>) -> Result<VaultHealth, String> {
    require_unlocked(&state)?;
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

#[command]
pub async fn export_vault_bitwarden_json(
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    require_unlocked(&state)?;
    let vault = state.vault.read();
    let store = state.store.load_device_id().map_err(|e| e.to_string())?;

    let user_id = store;

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

    let export = BitwardenExport {
        version: 1,
        timestamp: Utc::now().to_rfc3339(),
        user_id,
        passwords,
    };

    serde_json::to_string_pretty(&export).map_err(|e| format!("Failed to serialize export: {}", e))
}

#[command]
pub async fn save_vault_export_file(
    state: State<'_, Arc<AppState>>,
    path: String,
    data: String,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let validated = validate_export_path(&state, &path)?;
    std::fs::write(validated, data).map_err(|e| format!("Failed to write export file: {}", e))
}

/// Strictly validate a user-chosen export path. The native save dialog always
/// returns an absolute path under an existing directory with a `.json`
/// extension; enforcing the same here prevents a compromised renderer from
/// using this command as an arbitrary file-overwrite primitive (e.g. clobbering
/// `~/.bashrc`, startup files, or the in-data-dir IPC auth file).
fn validate_export_path(
    state: &State<'_, Arc<AppState>>,
    raw: &str,
) -> Result<std::path::PathBuf, String> {
    validate_export_path_inner(state.store.store_path(), raw)
}

/// The `State`-free core of [`validate_export_path`] so the rules can be
/// unit-tested without a running Tauri app.
fn validate_export_path_inner(
    store_path: &std::path::Path,
    raw: &str,
) -> Result<std::path::PathBuf, String> {
    use std::path::{Component, PathBuf};

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Export path is empty".to_string());
    }
    let path = PathBuf::from(trimmed);

    if !path.is_absolute() {
        return Err("Export path must be absolute".to_string());
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("Export path must not contain parent-directory components".to_string());
    }
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if !is_json {
        return Err("Export path must have a .json extension".to_string());
    }

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Err("Export path has no parent directory".to_string()),
    };
    let canon_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("Export directory is not accessible: {e}"))?;
    if !canon_parent.is_dir() {
        return Err("Export path parent is not a directory".to_string());
    }

    // Never allow writing inside the app's own data directory — that would let
    // a compromised renderer overwrite vault.enc / ipc_auth.json / etc.
    if let Some(store_canon) = std::fs::canonicalize(store_path).ok() {
        if canon_parent.starts_with(&store_canon) {
            return Err("Cannot export into the application data directory".to_string());
        }
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| "Export path has no file name".to_string())?;
    Ok(canon_parent.join(file_name))
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

#[command]
pub async fn import_vault_bitwarden_json(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    data: String,
) -> Result<ImportResult, String> {
    let import: BitwardenImport =
        serde_json::from_str(&data).map_err(|e| format!("Failed to parse import data: {}", e))?;

    if import.version != 1 {
        return Err(format!("Unsupported export version: {}", import.version));
    }

    if !state.is_unlocked() {
        return Err("Session not unlocked. Please unlock the vault first.".to_string());
    }

    let now = Utc::now();
    let total_count = import.passwords.len() as u32;
    let mut added_count = 0u32;
    let skipped_count = 0u32;

    {
        let mut vault = state.vault.write();

        for entry in import.passwords {
            let name = entry
                .url
                .clone()
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| entry.username.clone());

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
            };

            vault.add_item(item);
            added_count += 1;
        }

        tracing::info!("Total items in vault after import: {}", vault.items.len());
    }

    save_vault(&state)?;

    tracing::info!("Imported {} items, {} total", added_count, total_count);

    if added_count > 0 {
        emit_vault_items_changed(&app);
    }

    Ok(ImportResult {
        added: added_count,
        skipped: skipped_count,
        total: total_count,
    })
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub added: u32,
    pub skipped: u32,
    pub total: u32,
}

#[derive(Debug, Deserialize)]
struct HibpBreach {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Title")]
    title: String,
    #[serde(rename = "Domain")]
    domain: String,
    #[serde(rename = "BreachDate")]
    breach_date: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "DataClasses")]
    data_classes: Vec<String>,
    #[serde(rename = "IsVerified")]
    is_verified: bool,
    #[serde(rename = "IsFabricated")]
    is_fabricated: bool,
    #[serde(rename = "IsSensitive")]
    is_sensitive: bool,
    #[serde(rename = "IsRetired")]
    is_retired: bool,
    #[serde(rename = "IsSpamList")]
    is_spam_list: bool,
}

impl From<HibpBreach> for crate::vault::BreachEntry {
    fn from(h: HibpBreach) -> Self {
        crate::vault::BreachEntry {
            name: h.name,
            title: h.title,
            domain: h.domain,
            breach_date: h.breach_date,
            description: h.description,
            data_classes: h.data_classes,
            is_verified: h.is_verified,
            is_fabricated: h.is_fabricated,
            is_sensitive: h.is_sensitive,
            is_retired: h.is_retired,
            is_spam_list: h.is_spam_list,
        }
    }
}

#[command]
pub async fn check_email_breach(email: String) -> Result<Vec<crate::vault::BreachEntry>, String> {
    tracing::info!("Checking breaches for one account");

    let client = reqwest::Client::new();
    let api_key = std::env::var("HIBP_API_KEY").unwrap_or_default();

    if api_key.is_empty() {
        tracing::warn!("HIBP_API_KEY not set, using anonymous API");
    }

    let mut request = client.get(&format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
        urlencoding::encode(&email)
    ));

    if !api_key.is_empty() {
        request = request.header("hibp-api-key", &api_key);
    }

    request = request.header("User-Agent", "VELA-Desktop-App");

    match request.send().await {
        Ok(response) => match response.status().as_u16() {
            200 => {
                let breaches: Vec<HibpBreach> = response
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse breach data: {}", e))?;
                tracing::info!("Found {} breaches", breaches.len());
                Ok(breaches.into_iter().map(|b| b.into()).collect())
            }
            404 => {
                tracing::info!("No breaches found");
                Ok(vec![])
            }
            429 => Err("Rate limited by HaveIBeenPwned. Please try again later.".to_string()),
            status => Err(format!("HIBP API error: HTTP {}", status)),
        },
        Err(e) => {
            tracing::error!("Failed to check breaches: {}", e);
            Err(format!("Network error: {}", e))
        }
    }
}

#[command]
pub async fn check_all_vault_emails(state: State<'_, Arc<AppState>>) -> Result<u32, String> {
    require_unlocked(&state)?;
    let emails: Vec<String> = {
        let vault = state.vault.read();
        let mut seen = std::collections::HashSet::new();
        vault
            .items
            .iter()
            .filter_map(|item| {
                if let VaultItem::Login { username, .. } = item {
                    if !username.is_empty()
                        && username.contains('@')
                        && seen.insert(username.clone())
                    {
                        return Some(username.clone());
                    }
                }
                None
            })
            .collect()
    };

    tracing::info!("Unique emails to check: {}", emails.len());

    let client = reqwest::Client::new();
    let api_key = std::env::var("HIBP_API_KEY").unwrap_or_default();
    let mut total_breaches = 0u32;

    for email in emails {
        let mut request = client.get(&format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
            urlencoding::encode(&email)
        ));

        if !api_key.is_empty() {
            request = request.header("hibp-api-key", &api_key);
        }
        request = request.header("User-Agent", "VELA-Desktop-App");

        if let Ok(response) = request.send().await {
            if response.status().as_u16() == 200 {
                if let Ok(breaches) = response.json::<Vec<HibpBreach>>().await {
                    total_breaches += breaches.len() as u32;
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(1600)).await;
    }

    tracing::info!("Total breaches found: {}", total_breaches);
    Ok(total_breaches)
}

#[derive(Debug, Serialize)]
pub struct PasswordBreachResult {
    pub breached: bool,
    pub count: u32,
    pub description: String,
}

#[command]
pub async fn check_password_breach(password: String) -> Result<PasswordBreachResult, String> {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash).to_uppercase();

    let prefix = &hash_hex[..5];
    let suffix = &hash_hex[5..];

    let client = reqwest::Client::new();
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    match client
        .get(&url)
        .header("User-Agent", "VELA-Desktop-App")
        .send()
        .await
    {
        Ok(response) => {
            if response.status().as_u16() == 200 {
                let body = response.text().await.unwrap_or_default();

                for line in body.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() == 2 {
                        let hash_suffix = parts[0];
                        let count: u32 = parts[1].parse().unwrap_or(0);

                        if hash_suffix == suffix {
                            return Ok(PasswordBreachResult {
                                breached: true,
                                count,
                                description: format!(
                                    "This password has been exposed in {} data breaches. It appears {} times in breached password databases.",
                                    if count == 1 { "a" } else { "" },
                                    count
                                ),
                            });
                        }
                    }
                }

                Ok(PasswordBreachResult {
                    breached: false,
                    count: 0,
                    description: "This password has not been found in any known data breaches."
                        .to_string(),
                })
            } else {
                Err(format!(
                    "Pwned Passwords API error: HTTP {}",
                    response.status().as_u16()
                ))
            }
        }
        Err(e) => Err(format!("Network error: {}", e)),
    }
}

#[command]
pub async fn check_all_vault_passwords(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PasswordBreachResult>, String> {
    require_unlocked(&state)?;
    let passwords: Vec<(String, String)> = {
        let vault = state.vault.read();
        let mut seen = std::collections::HashSet::new();
        vault
            .items
            .iter()
            .filter_map(|item| {
                if let VaultItem::Login { meta, pass, .. } = item {
                    if !pass.is_empty() && seen.insert(pass.clone()) {
                        return Some((meta.name.clone(), pass.clone()));
                    }
                }
                None
            })
            .collect()
    };

    let client = reqwest::Client::new();
    let mut results: Vec<PasswordBreachResult> = Vec::new();

    for (name, password) in passwords {
        use sha1::{Digest, Sha1};

        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash).to_uppercase();

        let prefix = &hash_hex[..5];
        let suffix = &hash_hex[5..];

        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        if let Ok(response) = client
            .get(&url)
            .header("User-Agent", "VELA-Desktop-App")
            .send()
            .await
        {
            if response.status().as_u16() == 200 {
                let body = response.text().await.unwrap_or_default();
                let mut found = false;

                for line in body.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() == 2 {
                        let hash_suffix = parts[0];
                        let count: u32 = parts[1].parse().unwrap_or(0);

                        if hash_suffix == suffix {
                            let result = PasswordBreachResult {
                                breached: true,
                                count,
                                description: format!(
                                    "Password for '{}' found {} times in breaches",
                                    name, count
                                ),
                            };
                            tracing::info!("{}", result.description);
                            results.push(result);
                            found = true;
                            break;
                        }
                    }
                }

                if !found {
                    results.push(PasswordBreachResult {
                        breached: false,
                        count: 0,
                        description: format!("Password for '{}' is safe", name),
                    });
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_and_export_dirs() -> (tempfile::TempDir, tempfile::TempDir) {
        let store = tempfile::tempdir().unwrap();
        let export = tempfile::tempdir().unwrap();
        (store, export)
    }

    #[test]
    fn export_path_accepts_absolute_json_under_real_dir() {
        let (store, export) = store_and_export_dirs();
        let raw = export.path().join("vault-backup.json");
        let validated = validate_export_path_inner(store.path(), raw.to_str().unwrap()).unwrap();
        assert_eq!(validated, std::fs::canonicalize(export.path()).unwrap().join("vault-backup.json"));
    }

    #[test]
    fn export_path_rejects_relative_and_empty() {
        let (store, _export) = store_and_export_dirs();
        let err = validate_export_path_inner(store.path(), "backup.json").unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        let err = validate_export_path_inner(store.path(), "   ").unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn export_path_rejects_parent_traversal() {
        let (store, export) = store_and_export_dirs();
        let raw = export.path().join("..").join("evil.json");
        let err = validate_export_path_inner(store.path(), raw.to_str().unwrap()).unwrap_err();
        assert!(err.contains("parent-directory"), "{err}");
    }

    #[test]
    fn export_path_requires_json_extension() {
        let (store, export) = store_and_export_dirs();
        for name in ["vault.json.bak", "vault.txt", "vault", ".json_hidden"] {
            let raw = export.path().join(name);
            let err = validate_export_path_inner(store.path(), raw.to_str().unwrap()).unwrap_err();
            assert!(err.contains(".json"), "{name}: {err}");
        }
        // Case-insensitive extension is accepted.
        let raw = export.path().join("vault.JSON");
        assert!(validate_export_path_inner(store.path(), raw.to_str().unwrap()).is_ok());
    }

    #[test]
    fn export_path_rejects_missing_directory() {
        let (store, _export) = store_and_export_dirs();
        let err = validate_export_path_inner(store.path(), "/nonexistent-dir-xyz/a.json").unwrap_err();
        assert!(err.contains("not accessible"), "{err}");
    }

    #[test]
    fn export_path_never_writes_into_app_data_dir() {
        let (store, _export) = store_and_export_dirs();
        // Directly inside the store dir...
        let raw = store.path().join("export.json");
        let err = validate_export_path_inner(store.path(), raw.to_str().unwrap()).unwrap_err();
        assert!(err.contains("application data directory"), "{err}");
        // ...or a nested subdirectory of it.
        let nested = store.path().join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        let raw = nested.join("export.json");
        let err = validate_export_path_inner(store.path(), raw.to_str().unwrap()).unwrap_err();
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
        let err = validate_export_path_inner(store.path(), raw.to_str().unwrap()).unwrap_err();
        assert!(err.contains("application data directory"), "{err}");
    }
}
