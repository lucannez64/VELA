use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    Login,
    CreditCard,
    SecureNote,
    Identity,
    FileBlob,
    BreachMonitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            VaultItem::Login { id, .. } => id,
            VaultItem::CreditCard { id, .. } => id,
            VaultItem::SecureNote { id, .. } => id,
            VaultItem::Identity { id, .. } => id,
            VaultItem::FileBlob { id, .. } => id,
            VaultItem::BreachMonitor { id, .. } => id,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            VaultItem::Login { name, .. } => name,
            VaultItem::CreditCard { name, .. } => name,
            VaultItem::SecureNote { name, .. } => name,
            VaultItem::Identity { name, .. } => name,
            VaultItem::FileBlob { name, .. } => name,
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

    pub fn notes(&self) -> Option<&str> {
        match self {
            VaultItem::Login { notes, .. } => notes.as_deref(),
            VaultItem::CreditCard { notes, .. } => notes.as_deref(),
            VaultItem::SecureNote { notes, .. } => notes.as_deref(),
            VaultItem::Identity { notes, .. } => notes.as_deref(),
            VaultItem::FileBlob { notes, .. } => notes.as_deref(),
            VaultItem::BreachMonitor { .. } => None,
        }
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        match self {
            VaultItem::Login { created_at, .. } => *created_at,
            VaultItem::CreditCard { created_at, .. } => *created_at,
            VaultItem::SecureNote { created_at, .. } => *created_at,
            VaultItem::Identity { created_at, .. } => *created_at,
            VaultItem::FileBlob { created_at, .. } => *created_at,
            VaultItem::BreachMonitor { created_at, .. } => *created_at,
        }
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        match self {
            VaultItem::Login { updated_at, .. } => *updated_at,
            VaultItem::CreditCard { updated_at, .. } => *updated_at,
            VaultItem::SecureNote { updated_at, .. } => *updated_at,
            VaultItem::Identity { updated_at, .. } => *updated_at,
            VaultItem::FileBlob { updated_at, .. } => *updated_at,
            VaultItem::BreachMonitor { updated_at, .. } => *updated_at,
        }
    }

    pub fn last_modified_device(&self) -> Option<&str> {
        match self {
            VaultItem::Login {
                last_modified_device,
                ..
            } => last_modified_device.as_deref(),
            VaultItem::CreditCard {
                last_modified_device,
                ..
            } => last_modified_device.as_deref(),
            VaultItem::SecureNote {
                last_modified_device,
                ..
            } => last_modified_device.as_deref(),
            VaultItem::Identity {
                last_modified_device,
                ..
            } => last_modified_device.as_deref(),
            VaultItem::FileBlob {
                last_modified_device,
                ..
            } => last_modified_device.as_deref(),
            VaultItem::BreachMonitor {
                last_modified_device,
                ..
            } => last_modified_device.as_deref(),
        }
    }

    pub fn favorite(&self) -> bool {
        match self {
            VaultItem::Login { favorite, .. } => *favorite,
            VaultItem::CreditCard { favorite, .. } => *favorite,
            VaultItem::SecureNote { favorite, .. } => *favorite,
            VaultItem::Identity { favorite, .. } => *favorite,
            VaultItem::FileBlob { favorite, .. } => *favorite,
            VaultItem::BreachMonitor { favorite, .. } => *favorite,
        }
    }

    pub fn shared(&self) -> bool {
        match self {
            VaultItem::Login { shared, .. } => *shared,
            VaultItem::CreditCard { shared, .. } => *shared,
            VaultItem::SecureNote { shared, .. } => *shared,
            VaultItem::Identity { shared, .. } => *shared,
            VaultItem::FileBlob { shared, .. } => *shared,
            VaultItem::BreachMonitor { shared, .. } => *shared,
        }
    }

    pub fn share_recipient(&self) -> Option<&str> {
        match self {
            VaultItem::Login {
                share_recipient, ..
            } => share_recipient.as_deref(),
            VaultItem::CreditCard {
                share_recipient, ..
            } => share_recipient.as_deref(),
            VaultItem::SecureNote {
                share_recipient, ..
            } => share_recipient.as_deref(),
            VaultItem::Identity {
                share_recipient, ..
            } => share_recipient.as_deref(),
            VaultItem::FileBlob {
                share_recipient, ..
            } => share_recipient.as_deref(),
            VaultItem::BreachMonitor {
                share_recipient, ..
            } => share_recipient.as_deref(),
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
        match self {
            VaultItem::Login {
                id: _,
                name,
                url,
                username,
                pass,
                totp,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::Login {
                id: new_id,
                name: name.clone(),
                url: url.clone(),
                username: username.clone(),
                pass: pass.clone(),
                totp: totp.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::CreditCard {
                id: _,
                name,
                number,
                exp,
                cvv,
                pin,
                cardholder_name,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::CreditCard {
                id: new_id,
                name: name.clone(),
                number: number.clone(),
                exp: exp.clone(),
                cvv: cvv.clone(),
                pin: pin.clone(),
                cardholder_name: cardholder_name.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::SecureNote {
                id: _,
                name,
                title,
                content,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::SecureNote {
                id: new_id,
                name: name.clone(),
                title: title.clone(),
                content: content.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::Identity {
                id: _,
                name,
                first_name,
                last_name,
                ssn,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::Identity {
                id: new_id,
                name: name.clone(),
                first_name: first_name.clone(),
                last_name: last_name.clone(),
                ssn: ssn.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::FileBlob {
                id: _,
                name,
                filename,
                mime,
                chunks,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::FileBlob {
                id: new_id,
                name: name.clone(),
                filename: filename.clone(),
                mime: mime.clone(),
                chunks: chunks.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::BreachMonitor {
                id: _,
                email,
                checked_at,
                breach_count,
                breaches,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::BreachMonitor {
                id: new_id,
                email: email.clone(),
                checked_at: checked_at.clone(),
                breach_count: *breach_count,
                breaches: breaches.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
        }
    }

    pub fn with_updated_at(&self, new_updated_at: DateTime<Utc>) -> Self {
        match self {
            VaultItem::Login {
                id,
                name,
                url,
                username,
                pass,
                totp,
                notes,
                created_at,
                updated_at: _,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::Login {
                id: id.clone(),
                name: name.clone(),
                url: url.clone(),
                username: username.clone(),
                pass: pass.clone(),
                totp: totp.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: new_updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::CreditCard {
                id,
                name,
                number,
                exp,
                cvv,
                pin,
                cardholder_name,
                notes,
                created_at,
                updated_at: _,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::CreditCard {
                id: id.clone(),
                name: name.clone(),
                number: number.clone(),
                exp: exp.clone(),
                cvv: cvv.clone(),
                pin: pin.clone(),
                cardholder_name: cardholder_name.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: new_updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::SecureNote {
                id,
                name,
                title,
                content,
                notes,
                created_at,
                updated_at: _,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::SecureNote {
                id: id.clone(),
                name: name.clone(),
                title: title.clone(),
                content: content.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: new_updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::Identity {
                id,
                name,
                first_name,
                last_name,
                ssn,
                notes,
                created_at,
                updated_at: _,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::Identity {
                id: id.clone(),
                name: name.clone(),
                first_name: first_name.clone(),
                last_name: last_name.clone(),
                ssn: ssn.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: new_updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::FileBlob {
                id,
                name,
                filename,
                mime,
                chunks,
                notes,
                created_at,
                updated_at: _,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::FileBlob {
                id: id.clone(),
                name: name.clone(),
                filename: filename.clone(),
                mime: mime.clone(),
                chunks: chunks.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: new_updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
            VaultItem::BreachMonitor {
                id,
                email,
                checked_at,
                breach_count,
                breaches,
                created_at,
                updated_at: _,
                last_modified_device,
                favorite,
                shared,
                share_recipient,
            } => VaultItem::BreachMonitor {
                id: id.clone(),
                email: email.clone(),
                checked_at: checked_at.clone(),
                breach_count: *breach_count,
                breaches: breaches.clone(),
                created_at: *created_at,
                updated_at: new_updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared: *shared,
                share_recipient: share_recipient.clone(),
            },
        }
    }

    pub fn with_shared_status(&self, shared: bool, share_recipient: Option<String>) -> Self {
        match self {
            VaultItem::Login {
                id,
                name,
                url,
                username,
                pass,
                totp,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared: _,
                share_recipient: _,
            } => VaultItem::Login {
                id: id.clone(),
                name: name.clone(),
                url: url.clone(),
                username: username.clone(),
                pass: pass.clone(),
                totp: totp.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared,
                share_recipient,
            },
            VaultItem::CreditCard {
                id,
                name,
                number,
                exp,
                cvv,
                pin,
                cardholder_name,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared: _,
                share_recipient: _,
            } => VaultItem::CreditCard {
                id: id.clone(),
                name: name.clone(),
                number: number.clone(),
                exp: exp.clone(),
                cvv: cvv.clone(),
                pin: pin.clone(),
                cardholder_name: cardholder_name.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared,
                share_recipient,
            },
            VaultItem::SecureNote {
                id,
                name,
                title,
                content,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared: _,
                share_recipient: _,
            } => VaultItem::SecureNote {
                id: id.clone(),
                name: name.clone(),
                title: title.clone(),
                content: content.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared,
                share_recipient,
            },
            VaultItem::Identity {
                id,
                name,
                first_name,
                last_name,
                ssn,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared: _,
                share_recipient: _,
            } => VaultItem::Identity {
                id: id.clone(),
                name: name.clone(),
                first_name: first_name.clone(),
                last_name: last_name.clone(),
                ssn: ssn.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared,
                share_recipient,
            },
            VaultItem::FileBlob {
                id,
                name,
                filename,
                mime,
                chunks,
                notes,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared: _,
                share_recipient: _,
            } => VaultItem::FileBlob {
                id: id.clone(),
                name: name.clone(),
                filename: filename.clone(),
                mime: mime.clone(),
                chunks: chunks.clone(),
                notes: notes.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared,
                share_recipient,
            },
            VaultItem::BreachMonitor {
                id,
                email,
                checked_at,
                breach_count,
                breaches,
                created_at,
                updated_at,
                last_modified_device,
                favorite,
                shared: _,
                share_recipient: _,
            } => VaultItem::BreachMonitor {
                id: id.clone(),
                email: email.clone(),
                checked_at: checked_at.clone(),
                breach_count: *breach_count,
                breaches: breaches.clone(),
                created_at: *created_at,
                updated_at: *updated_at,
                last_modified_device: last_modified_device.clone(),
                favorite: *favorite,
                shared,
                share_recipient,
            },
        }
    }
}

fn extract_base_domain(url: &str) -> String {
    let url = url.trim();

    if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("file://") {
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
}

impl Default for VaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultStore {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn add_item(&mut self, item: VaultItem) {
        self.items.push(item);
    }

    pub fn update_item(&mut self, item: VaultItem) {
        if let Some(existing) = self.items.iter_mut().find(|i| i.id() == item.id()) {
            *existing = item;
        }
    }

    pub fn delete_item(&mut self, id: &str) {
        self.items.retain(|item| item.id() != id);
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

    if current_host != stored_host {
        return false;
    }

    if let (Some(cp), Some(sp)) = (current_port, stored_port) {
        if cp != sp {
            return false;
        }
    }

    if is_ip_address(&current_host) {
        return true;
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

    let stored_is_subdomain_of_current =
        current_parts[current_parts.len() - stored_parts.len()..] == stored_parts[..];

    if !stored_is_subdomain_of_current {
        return false;
    }

    stored_parts.len() >= current_parts.len() - 1
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
