use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

fn default_created_at() -> DateTime<Utc> {
    Utc::now()
}

fn default_updated_at() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    Login,
    CreditCard,
    SecureNote,
    Identity,
    FileBlob,
    BreachMonitor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default = "default_created_at", alias = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_updated_at", alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
    #[serde(default, alias = "last_modified_device")]
    pub last_modified_device: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub shared: bool,
    #[serde(default, alias = "share_recipient")]
    pub share_recipient: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "item_type", rename_all = "camelCase")]
pub enum VaultItem {
    Login {
        #[serde(flatten)]
        meta: VaultMeta,
        url: String,
        username: String,
        #[serde(rename = "password")]
        pass: String,
        #[serde(default)]
        totp: Option<String>,
    },
    CreditCard {
        #[serde(flatten)]
        meta: VaultMeta,
        number: String,
        exp: String,
        cvv: String,
        #[serde(default)]
        pin: Option<String>,
        #[serde(default, alias = "cardholder_name")]
        cardholder_name: Option<String>,
    },
    SecureNote {
        #[serde(flatten)]
        meta: VaultMeta,
        title: String,
        content: String,
    },
    Identity {
        #[serde(flatten)]
        meta: VaultMeta,
        #[serde(alias = "first_name")]
        first_name: String,
        #[serde(alias = "last_name")]
        last_name: String,
        ssn: String,
    },
    FileBlob {
        #[serde(flatten)]
        meta: VaultMeta,
        #[serde(alias = "file_name")]
        filename: String,
        #[serde(alias = "mime_type")]
        mime: String,
        #[serde(default)]
        chunks: Vec<Uuid>,
    },
    BreachMonitor {
        #[serde(flatten)]
        meta: VaultMeta,
        email: String,
        #[serde(default, alias = "checked_at")]
        checked_at: Option<DateTime<Utc>>,
        #[serde(default, alias = "breach_count")]
        breach_count: u32,
        #[serde(default)]
        breaches: Vec<BreachEntry>,
    },
}

/// Record of a deleted item, propagated via sync so that deletions
/// are honoured on all devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub id: String,
    #[serde(default = "default_created_at")]
    pub deleted_at: DateTime<Utc>,
    #[serde(default)]
    pub deleted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub breach_date: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub data_classes: Vec<String>,
    #[serde(default)]
    pub is_verified: bool,
    #[serde(default)]
    pub is_fabricated: bool,
    #[serde(default)]
    pub is_sensitive: bool,
    #[serde(default)]
    pub is_retired: bool,
    #[serde(default)]
    pub is_spam_list: bool,
}

impl VaultItem {
    fn meta(&self) -> &VaultMeta {
        match self {
            VaultItem::Login { meta, .. }
            | VaultItem::CreditCard { meta, .. }
            | VaultItem::SecureNote { meta, .. }
            | VaultItem::Identity { meta, .. }
            | VaultItem::FileBlob { meta, .. }
            | VaultItem::BreachMonitor { meta, .. } => meta,
        }
    }

    fn meta_mut(&mut self) -> &mut VaultMeta {
        match self {
            VaultItem::Login { meta, .. }
            | VaultItem::CreditCard { meta, .. }
            | VaultItem::SecureNote { meta, .. }
            | VaultItem::Identity { meta, .. }
            | VaultItem::FileBlob { meta, .. }
            | VaultItem::BreachMonitor { meta, .. } => meta,
        }
    }

    pub fn id(&self) -> &str {
        &self.meta().id
    }

    pub fn name(&self) -> &str {
        &self.meta().name
    }

    pub fn item_type(&self) -> ItemType {
        match self {
            VaultItem::Login { .. } => ItemType::Login,
            VaultItem::CreditCard { .. } => ItemType::CreditCard,
            VaultItem::SecureNote { .. } => ItemType::SecureNote,
            VaultItem::Identity { .. } => ItemType::Identity,
            VaultItem::FileBlob { .. } => ItemType::FileBlob,
            VaultItem::BreachMonitor { .. } => ItemType::BreachMonitor,
        }
    }

    pub fn notes(&self) -> Option<&str> {
        self.meta().notes.as_deref()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.meta().created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.meta().updated_at
    }

    pub fn last_modified_device(&self) -> Option<&str> {
        self.meta().last_modified_device.as_deref()
    }

    pub fn favorite(&self) -> bool {
        self.meta().favorite
    }

    pub fn shared(&self) -> bool {
        self.meta().shared
    }

    pub fn share_recipient(&self) -> Option<&str> {
        self.meta().share_recipient.as_deref()
    }

    pub fn is_received_share(&self) -> bool {
        self.shared() && self.share_recipient().is_none()
    }

    pub fn url(&self) -> Option<&str> {
        match self {
            VaultItem::Login { url, .. } => Some(url),
            _ => None,
        }
    }

    pub fn username(&self) -> Option<&str> {
        match self {
            VaultItem::Login { username, .. } => Some(username),
            VaultItem::Identity { first_name, .. } => Some(first_name),
            _ => None,
        }
    }

    pub fn password(&self) -> Option<&str> {
        match self {
            VaultItem::Login { pass, .. } => Some(pass),
            _ => None,
        }
    }

    pub fn display_value(&self) -> String {
        match self {
            VaultItem::Login { pass, .. } => pass.clone(),
            VaultItem::CreditCard { number, .. } => number.clone(),
            VaultItem::SecureNote { .. } => "Secure Note".to_string(),
            VaultItem::Identity { first_name, .. } => first_name.clone(),
            VaultItem::FileBlob { filename, .. } => filename.clone(),
            VaultItem::BreachMonitor { email, .. } => email.clone(),
        }
    }

    pub fn masked_value(&self) -> String {
        match self {
            VaultItem::Login { .. } => "••••••••••••".to_string(),
            VaultItem::CreditCard { number, .. } => {
                if number.len() >= 4 {
                    format!("•••• •••• •••• {}", &number[number.len() - 4..])
                } else {
                    "•••• •••• •••• ••••".to_string()
                }
            }
            VaultItem::SecureNote { .. } => "••••••••••••".to_string(),
            VaultItem::Identity { .. } => "••••••••".to_string(),
            VaultItem::FileBlob { filename, .. } => filename.clone(),
            VaultItem::BreachMonitor { email, .. } => email.clone(),
        }
    }

    pub fn with_id(&self, new_id: String) -> Self {
        let mut new = self.clone();
        new.meta_mut().id = new_id;
        new
    }

    pub fn with_updated_at(&self, new_updated_at: DateTime<Utc>) -> Self {
        let mut new = self.clone();
        new.meta_mut().updated_at = new_updated_at;
        new
    }

    pub fn with_shared_status(&self, shared: bool, share_recipient: Option<String>) -> Self {
        let mut new = self.clone();
        let meta = new.meta_mut();
        meta.shared = shared;
        meta.share_recipient = share_recipient;
        new
    }
}

fn extract_base_domain(url: &str) -> String {
    let url = url.trim();

    if url.starts_with("http://") || url.starts_with("https://") {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let host = host.to_lowercase();

                if host.starts_with("www.") {
                    return host.strip_prefix("www.").unwrap_or(&host).to_string();
                }

                let parts: Vec<&str> = host.split('.').collect();
                if parts.len() >= 2 {
                    return parts[parts.len() - 2..].join(".");
                }

                return host;
            }
        }
    }

    url.to_lowercase()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStore {
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(skip, default = "HashMap::new")]
    item_index: HashMap<String, usize>,
}

impl Default for VaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            tombstones: Vec::new(),
            item_index: HashMap::new(),
        }
    }

    fn reindex(&mut self) {
        self.item_index.clear();
        for (i, item) in self.items.iter().enumerate() {
            self.item_index.insert(item.id().to_string(), i);
        }
    }

    fn ensure_index(&mut self) {
        if self.item_index.is_empty() && !self.items.is_empty() {
            self.reindex();
        }
    }

    pub fn add_item(&mut self, item: VaultItem) {
        self.ensure_index();
        let id = item.id().to_string();
        let idx = self.items.len();
        self.items.push(item);
        self.item_index.insert(id, idx);
    }

    pub fn update_item(&mut self, item: VaultItem) {
        self.ensure_index();
        let id = item.id().to_string();
        if let Some(&idx) = self.item_index.get(&id) {
            self.items[idx] = item;
        } else if let Some(existing) = self.items.iter_mut().find(|i| i.id() == id) {
            *existing = item;
            self.reindex();
            return;
        } else {
            self.add_item(item);
            return;
        }
    }

    pub fn delete_item(&mut self, id: &str, device_id: Option<&str>) {
        self.ensure_index();
        if let Some(&idx) = self.item_index.get(id) {
            self.items.remove(idx);
            self.item_index.remove(id);
            self.reindex();
        } else {
            self.items.retain(|item| item.id() != id);
        }
        self.tombstones.push(Tombstone {
            id: id.to_string(),
            deleted_at: Utc::now(),
            deleted_by: device_id.map(|s| s.to_string()),
        });
    }

    pub fn prune_tombstones(&mut self, max_age: chrono::Duration) {
        let cutoff = Utc::now() - max_age;
        self.tombstones.retain(|t| t.deleted_at >= cutoff);
    }

    pub fn get_item(&self, id: &str) -> Option<&VaultItem> {
        if let Some(&idx) = self.item_index.get(id) {
            return self.items.get(idx);
        }
        self.items.iter().find(|item| item.id() == id)
    }

    pub fn search(&self, query: &str) -> Vec<&VaultItem> {
        let query_lower = query.to_lowercase();
        self.items
            .iter()
            .filter(|item| {
                item.name().to_lowercase().contains(&query_lower)
                    || item
                        .username()
                        .map(|u| u.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
                    || item
                        .url()
                        .map(|u| u.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
                    || item
                        .notes()
                        .map(|n| n.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
            })
            .collect()
    }

    pub fn search_by_domain(&self, base_domain: &str) -> Vec<&VaultItem> {
        if base_domain.is_empty() {
            return Vec::new();
        }

        let base_domain_lower = base_domain.to_lowercase();

        self.items
            .iter()
            .filter(|item| {
                if item.item_type() != ItemType::Login {
                    return false;
                }

                let Some(item_url) = item.url() else {
                    return false;
                };

                if !urls_match(&base_domain_lower, item_url) {
                    return false;
                }

                true
            })
            .collect()
    }

    pub fn by_type(&self, item_type: &ItemType) -> Vec<&VaultItem> {
        self.items
            .iter()
            .filter(|item| &item.item_type() == item_type)
            .collect()
    }

    pub fn count_by_type(&self) -> (usize, usize, usize, usize, usize) {
        let logins = self
            .items
            .iter()
            .filter(|i| matches!(i.item_type(), ItemType::Login))
            .count();
        let cards = self
            .items
            .iter()
            .filter(|i| matches!(i.item_type(), ItemType::CreditCard))
            .count();
        let notes = self
            .items
            .iter()
            .filter(|i| matches!(i.item_type(), ItemType::SecureNote))
            .count();
        let identities = self
            .items
            .iter()
            .filter(|i| matches!(i.item_type(), ItemType::Identity))
            .count();
        let files = self
            .items
            .iter()
            .filter(|i| matches!(i.item_type(), ItemType::FileBlob))
            .count();
        (logins, cards, notes, identities, files)
    }
}

fn urls_match(current_url: &str, stored_url: &str) -> bool {
    let current_lower = current_url.to_lowercase();
    let stored_lower = stored_url.to_lowercase();

    let (current_host, current_port) = extract_host_and_port(&current_lower);
    let (stored_host, stored_port) = extract_host_and_port(&stored_lower);

    if let (Some(cp), Some(sp)) = (current_port, stored_port) {
        if cp != sp {
            return false;
        }
    }

    if current_host == stored_host {
        return true;
    }

    if is_ip_address(&current_host) {
        return false;
    }

    let current_parts: Vec<&str> = current_host.split('.').collect();
    let stored_parts: Vec<&str> = stored_host.split('.').collect();

    if stored_parts.len() < 2 || current_parts.len() < 2 {
        return stored_host == current_host;
    }

    if stored_parts.len() > current_parts.len() {
        return false;
    }

    if stored_parts.len() == current_parts.len() {
        return stored_host == current_host;
    }

    let current_ends_with_stored = current_parts.len() >= stored_parts.len()
        && current_parts[current_parts.len() - stored_parts.len()..] == stored_parts[..];

    if !current_ends_with_stored {
        return false;
    }

    stored_parts.len() >= 2
}

fn extract_host_and_port(url: &str) -> (String, Option<u16>) {
    let url = url.trim();

    let url_obj = if url.starts_with("http://") || url.starts_with("https://") {
        url::Url::parse(url).ok()
    } else {
        url::Url::parse(&format!("https://{}", url)).ok()
    };

    if let Some(parsed) = url_obj {
        let host = parsed.host_str().unwrap_or("").to_string();
        let port = parsed.port();
        return (host, port);
    }

    if let Some(colon_pos) = url.rfind(':') {
        let host = url[..colon_pos].to_string();
        if let Ok(port) = url[colon_pos + 1..].parse::<u16>() {
            return (host, Some(port));
        }
    }

    (url.to_string(), None)
}

fn is_ip_address(host: &str) -> bool {
    host.split('.').all(|part| part.parse::<u8>().is_ok())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub easy_to_type: bool,
    pub pronounceable: bool,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            easy_to_type: false,
            pronounceable: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictItem {
    pub item_id: String,
    pub local_version: VaultItem,
    pub server_version: VaultItem,
    pub conflict_detected_at: DateTime<Utc>,
}
