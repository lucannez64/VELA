use crate::commands::audit::{record_audit_event, AuditAction};
use crate::vault::{ItemType, PasswordGeneratorOptions, VaultItem};
use crate::AppState;
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{command, AppHandle, Emitter, State};
use uuid::Uuid;

pub const VAULT_ITEMS_CHANGED_EVENT: &str = "vault-items-changed";

pub fn emit_vault_items_changed(app: &AppHandle) {
    let _ = app.emit(VAULT_ITEMS_CHANGED_EVENT, ());
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

#[command]
pub async fn get_items(state: State<'_, Arc<AppState>>) -> Result<Vec<VaultItem>, String> {
    let vault = state.vault.read();
    let items = vault.items.clone();
    tracing::info!("get_items: {} items in vault", items.len());
    Ok(items)
}

#[command]
pub async fn get_item(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<Option<VaultItem>, String> {
    let vault = state.vault.read();
    Ok(vault.get_item(&id).cloned())
}

#[command]
pub async fn add_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item: VaultItem,
) -> Result<VaultItem, String> {
    tracing::info!(
        "Adding item type: {:?}",
        match &item {
            VaultItem::Login { .. } => "login",
            VaultItem::CreditCard { .. } => "creditcard",
            VaultItem::SecureNote { .. } => "securenote",
            VaultItem::Identity { .. } => "identity",
            VaultItem::FileBlob { .. } => "fileblob",
            VaultItem::BreachMonitor { .. } => "breachmonitor",
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

    tracing::info!(
        "Returning item: {:?}",
        serde_json::to_string(&new_item).unwrap_or_default()
    );

    emit_vault_items_changed(&app);

    Ok(new_item)
}

#[command]
pub async fn update_item(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    item: VaultItem,
) -> Result<VaultItem, String> {
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
    let mut rng = rand::rngs::OsRng;

    let password: String = (0..options.length)
        .map(|_| {
            let mut buf = [0u8; 4];
            rng.fill_bytes(&mut buf);
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
pub async fn save_vault_export_file(path: String, data: String) -> Result<(), String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("Export path is empty".to_string());
    }

    std::fs::write(path, data).map_err(|e| format!("Failed to write export file: {}", e))
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

    {
        let crypto = state.crypto.read();
        if crypto.is_none() {
            return Err("Session not unlocked. Please unlock the vault first.".to_string());
        }
    }

    let now = Utc::now();
    let total_count = import.passwords.len() as u32;
    let mut added_count = 0u32;
    let mut skipped_count = 0u32;

    {
        let mut vault = state.vault.write();

        for entry in import.passwords {
            let name = entry
                .url
                .clone()
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| entry.username.clone());

            let url = normalize_import_url(entry.url.as_deref());

            tracing::info!(
                "Importing: name={}, username={}, password_len={}, description={:?}, url={}",
                name,
                entry.username,
                entry.password.len(),
                entry.description,
                url
            );

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
    tracing::info!("Checking breaches for email: {}", email);

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
                tracing::info!("Found {} breaches for {}", breaches.len(), email);
                Ok(breaches.into_iter().map(|b| b.into()).collect())
            }
            404 => {
                tracing::info!("No breaches found for {}", email);
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
        tracing::info!("Checking breaches for: {}", email);

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
                    tracing::info!("Found {} breaches for {}", breaches.len(), email);
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
