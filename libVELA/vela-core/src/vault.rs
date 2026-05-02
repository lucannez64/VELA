use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "item_type", rename_all = "camelCase")]
pub enum VaultItem {
    Login {
        id: String,
        name: String,
        url: String,
        username: String,
        #[serde(rename = "password")]
        pass: String,
        totp: Option<String>,
        notes: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        last_modified_device: Option<String>,
        favorite: bool,
        shared: bool,
        share_recipient: Option<String>,
    },
    CreditCard {
        id: String,
        name: String,
        number: String,
        exp: String,
        cvv: String,
        pin: Option<String>,
        cardholder_name: Option<String>,
        notes: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        last_modified_device: Option<String>,
        favorite: bool,
        shared: bool,
        share_recipient: Option<String>,
    },
    SecureNote {
        id: String,
        name: String,
        title: String,
        content: String,
        notes: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        last_modified_device: Option<String>,
        favorite: bool,
        shared: bool,
        share_recipient: Option<String>,
    },
    Identity {
        id: String,
        name: String,
        first_name: String,
        last_name: String,
        ssn: String,
        notes: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        last_modified_device: Option<String>,
        favorite: bool,
        shared: bool,
        share_recipient: Option<String>,
    },
    FileBlob {
        id: String,
        name: String,
        filename: String,
        mime: String,
        chunks: Vec<Uuid>,
        notes: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        last_modified_device: Option<String>,
        favorite: bool,
        shared: bool,
        share_recipient: Option<String>,
    },
    BreachMonitor {
        id: String,
        email: String,
        checked_at: Option<DateTime<Utc>>,
        breach_count: u32,
        breaches: Vec<BreachEntry>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        last_modified_device: Option<String>,
        favorite: bool,
        shared: bool,
        share_recipient: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub id: String,
    pub deleted_at: DateTime<Utc>,
    pub deleted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BreachEntry {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breach_date: String,
    pub description: String,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
    pub is_fabricated: bool,
    pub is_sensitive: bool,
    pub is_retired: bool,
    pub is_spam_list: bool,
}

impl VaultItem {
    pub fn id(&self) -> &str {
        match self {
            VaultItem::Login { id, .. }
            | VaultItem::CreditCard { id, .. }
            | VaultItem::SecureNote { id, .. }
            | VaultItem::Identity { id, .. }
            | VaultItem::FileBlob { id, .. }
            | VaultItem::BreachMonitor { id, .. } => id,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            VaultItem::Login { name, .. }
            | VaultItem::CreditCard { name, .. }
            | VaultItem::SecureNote { name, .. }
            | VaultItem::Identity { name, .. }
            | VaultItem::FileBlob { name, .. } => name,
            VaultItem::BreachMonitor { email, .. } => email,
        }
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
        match self {
            VaultItem::Login { notes, .. }
            | VaultItem::CreditCard { notes, .. }
            | VaultItem::SecureNote { notes, .. }
            | VaultItem::Identity { notes, .. }
            | VaultItem::FileBlob { notes, .. } => notes.as_deref(),
            VaultItem::BreachMonitor { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultStore {
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
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
        }
    }

    pub fn add_item(&mut self, item: VaultItem) {
        self.items.push(item);
    }

    pub fn update_item(&mut self, item: VaultItem) {
        if let Some(existing) = self.items.iter_mut().find(|i| i.id() == item.id()) {
            *existing = item;
        }
    }

    pub fn delete_item(&mut self, id: &str, device_id: Option<&str>) {
        self.items.retain(|item| item.id() != id);
        self.tombstones.push(Tombstone {
            id: id.to_string(),
            deleted_at: Utc::now(),
            deleted_by: device_id.map(ToOwned::to_owned),
        });
    }

    pub fn get_item(&self, id: &str) -> Option<&VaultItem> {
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
            id: id.to_string(),
            name: url.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            pass: "secret".to_string(),
            totp: None,
            notes: Some("note".to_string()),
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
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
}
