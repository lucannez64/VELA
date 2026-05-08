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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub id: String,
    #[serde(default = "default_created_at")]
    pub deleted_at: DateTime<Utc>,
    #[serde(default)]
    pub deleted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

    pub fn notes(&self) -> Option<&str> {
        self.meta().notes.as_deref()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.meta().created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.meta().updated_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
            deleted_by: device_id.map(ToOwned::to_owned),
        });
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
        if base_domain.trim().is_empty() {
            return Vec::new();
        }

        let base_domain_lower = base_domain.to_lowercase();
        self.items
            .iter()
            .filter(|item| {
                item.item_type() == ItemType::Login
                    && item
                        .url()
                        .map(|url| urls_match(&base_domain_lower, url))
                        .unwrap_or(false)
            })
            .collect()
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

    current_parts[current_parts.len() - stored_parts.len()..] == stored_parts[..]
        && stored_parts.len() >= 2
}

fn extract_host_and_port(url: &str) -> (String, Option<u16>) {
    let url = url.trim();
    let parsed = if url.starts_with("http://") || url.starts_with("https://") {
        url::Url::parse(url).ok()
    } else {
        url::Url::parse(&format!("https://{url}")).ok()
    };

    if let Some(parsed) = parsed {
        return (parsed.host_str().unwrap_or("").to_string(), parsed.port());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: &str, url: &str, username: &str) -> VaultItem {
        let now = Utc::now();
        VaultItem::Login {
            meta: VaultMeta {
                id: id.to_string(),
                name: url.to_string(),
                notes: Some("note".to_string()),
                created_at: now,
                updated_at: now,
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            url: url.to_string(),
            username: username.to_string(),
            pass: "secret".to_string(),
            totp: None,
        }
    }

    #[test]
    fn search_matches_name_username_url_and_notes() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://example.com", "alice@example.com"));

        assert_eq!(store.search("example").len(), 1);
        assert_eq!(store.search("alice").len(), 1);
        assert_eq!(store.search("note").len(), 1);
        assert_eq!(store.search("missing").len(), 0);
    }

    #[test]
    fn domain_search_matches_subdomains_and_rejects_ports() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://eduid.ch", "alice"));
        store.add_item(login("2", "http://127.0.0.1:3000", "local"));

        assert_eq!(store.search_by_domain("epfl.login.eduid.ch").len(), 1);
        assert_eq!(store.search_by_domain("127.0.0.1:4000").len(), 0);
    }

    #[test]
    fn serialization_uses_desktop_compatible_item_tag() {
        let json = serde_json::to_string(&login("1", "https://example.com", "alice")).unwrap();
        assert!(json.contains("\"item_type\":\"login\""));
        assert!(json.contains("\"password\":\"secret\""));
    }

    #[test]
    fn serialization_roundtrips_through_old_format() {
        let old_json = r#"{"item_type":"login","id":"abc","name":"test","url":"https://example.com","username":"user","password":"pwd","createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-01T00:00:00Z"}"#;
        let item: VaultItem = serde_json::from_str(old_json).unwrap();
        assert_eq!(item.id(), "abc");
        assert_eq!(item.name(), "test");
        let roundtrip = serde_json::to_string(&item).unwrap();
        let re_read: VaultItem = serde_json::from_str(&roundtrip).unwrap();
        assert_eq!(re_read, item);
    }

    #[test]
    fn get_item_is_o1_with_index() {
        let mut store = VaultStore::new();
        for i in 0..100 {
            let id = format!("id-{:03}", i);
            store.add_item(login(&id, "https://x.com", "user"));
        }
        assert!(store.get_item("id-050").is_some());
        assert!(store.get_item("id-000").is_some());
        assert!(store.get_item("id-099").is_some());
        assert!(store.get_item("nonexistent").is_none());
    }

    #[test]
    fn update_item_maintains_index() {
        let mut store = VaultStore::new();
        let item = login("1", "https://old.com", "alice");
        store.add_item(item);
        let updated = login("1", "https://new.com", "bob");
        store.update_item(updated);
        let found = store.get_item("1").unwrap();
        assert_eq!(found.url(), Some("https://new.com"));
        assert_eq!(found.username(), Some("bob"));
    }

    #[test]
    fn delete_item_removes_from_index() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://x.com", "user"));
        store.delete_item("1", None);
        assert!(store.get_item("1").is_none());
    }
}
