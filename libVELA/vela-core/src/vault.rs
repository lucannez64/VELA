use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
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

#[derive(Clone, Serialize, Deserialize, PartialEq)]
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
        /// Mobile apps the user has linked to this login, as `androidapp://<package>`.
        ///
        /// A package name cannot be turned into a domain by rule — `com.ubercab`
        /// is not `ubercab.com`, and anyone can publish `com.paypal.anything` —
        /// so the association is recorded when the user confirms it, the way
        /// every other password manager does it (audit A-2). Defaulted and
        /// preserved on round trip so a client that predates the field does not
        /// silently drop someone's links.
        #[serde(default, alias = "appIds")]
        app_ids: Vec<String>,
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

/// Redacted `Debug`, because the derived one printed the secrets.
///
/// A single `tracing::debug!("{item:?}")` anywhere — in this crate, in a
/// consumer, in a test someone leaves in — put passwords, card numbers, CVVs and
/// SSNs into a log file. Logs get shipped, attached to bug reports and read by
/// people who are not the vault's owner, so the fix is at the type: there is no
/// formatting of a `VaultItem` that reveals a secret, whoever writes it (audit,
/// crypto hardening).
///
/// The non-secret metadata is kept — an item you cannot identify is useless to
/// debug with.
impl VaultItem {
    /// Wipe the secret fields in place.
    ///
    /// Called from `Drop`, so every path that lets an item go — locking the
    /// vault, replacing the store after a sync, a temporary clone falling out of
    /// scope — clears the plaintext rather than handing the allocator a buffer
    /// that still holds a password. That is the whole point of doing it in
    /// `Drop` and not at chosen call sites: the ones you forget are exactly the
    /// ones that matter.
    ///
    /// Only the secrets. Names, URLs and usernames are not wiped: they are not
    /// what this protects, and zeroing them would cost on every drop for nothing.
    fn zeroize_secrets(&mut self) {
        use zeroize::Zeroize;
        match self {
            VaultItem::Login { pass, totp, .. } => {
                pass.zeroize();
                if let Some(totp) = totp {
                    totp.zeroize();
                }
            }
            VaultItem::CreditCard { number, cvv, pin, .. } => {
                number.zeroize();
                cvv.zeroize();
                if let Some(pin) = pin {
                    pin.zeroize();
                }
            }
            VaultItem::SecureNote { content, .. } => content.zeroize(),
            VaultItem::Identity { ssn, .. } => ssn.zeroize(),
            // Nothing secret: a file blob's bytes live in chunks, and a breach
            // monitor holds an address the user already published.
            VaultItem::FileBlob { .. } | VaultItem::BreachMonitor { .. } => {}
        }
    }
}

impl Drop for VaultItem {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl std::fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "[REDACTED]";
        let mut out = f.debug_struct("VaultItem");
        out.field("kind", &self.item_type())
            .field("id", &self.id())
            .field("name", &self.name());
        match self {
            VaultItem::Login { url, username, totp, .. } => {
                out.field("url", url)
                    .field("username", username)
                    .field("password", &REDACTED)
                    // Whether a login *has* a TOTP secret is metadata; the seed
                    // is not.
                    .field("totp", &totp.as_ref().map(|_| REDACTED));
            }
            VaultItem::CreditCard { exp, .. } => {
                out.field("number", &REDACTED)
                    .field("exp", exp)
                    .field("cvv", &REDACTED)
                    .field("pin", &REDACTED);
            }
            VaultItem::SecureNote { .. } => {
                out.field("content", &REDACTED);
            }
            VaultItem::Identity { first_name, last_name, .. } => {
                out.field("first_name", first_name)
                    .field("last_name", last_name)
                    .field("ssn", &REDACTED);
            }
            VaultItem::FileBlob { filename, mime, .. } => {
                out.field("filename", filename).field("mime", mime);
            }
            VaultItem::BreachMonitor { email, breach_count, .. } => {
                out.field("email", email).field("breach_count", breach_count);
            }
        }
        out.finish()
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "VaultStoreRepr")]
pub struct VaultStore {
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(skip, default = "HashMap::new")]
    item_index: HashMap<String, usize>,
}

/// Two stores hold the same vault when they hold the same items and tombstones.
///
/// Derived, `item_index` counted: a store just read off disk compared unequal
/// to the identical store built by `add_item`, purely because one had had its
/// index built and the other had not. The index is derived state, so it is not
/// part of the value.
impl PartialEq for VaultStore {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items && self.tombstones == other.tombstones
    }
}

/// The wire shape of a `VaultStore`, so that deserializing one also builds its
/// lookup index.
///
/// `item_index` is `#[serde(skip)]`, so a store read back from storage or off
/// the sync wire arrived with an empty index and kept it until the first
/// mutation — every `get_item` before that was a linear scan of the whole
/// vault. Building it here costs one pass at load and makes the lookups after
/// it O(1).
#[derive(Deserialize)]
struct VaultStoreRepr {
    items: Vec<VaultItem>,
    #[serde(default)]
    tombstones: Vec<Tombstone>,
}

impl From<VaultStoreRepr> for VaultStore {
    fn from(repr: VaultStoreRepr) -> Self {
        let mut store = Self {
            items: repr.items,
            tombstones: repr.tombstones,
            item_index: HashMap::new(),
        };
        store.reindex();
        store
    }
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
        self.item_index.reserve(self.items.len());
        for (i, item) in self.items.iter().enumerate() {
            self.item_index.insert(item.id().to_string(), i);
        }
    }

    /// Rebuild the index whenever it can no longer describe `items`.
    ///
    /// "The index is empty" was never a sufficient staleness test: `items` is
    /// public, so a caller that replaces it wholesale left the index holding the
    /// *old* positions and `get_item` handed back whichever item had moved into
    /// that slot. Comparing lengths catches a wholesale replacement, and
    /// `get_item` re-checks the id at the position it lands on for the rest.
    fn ensure_index(&mut self) {
        if self.item_index.len() != self.items.len() {
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
        if let Some(idx) = self.item_index.remove(id) {
            self.items.remove(idx);
            // Only the entries after the hole moved. A full `reindex()` here
            // re-hashed and re-allocated the id of every item in the vault on
            // every single delete.
            for position in self.item_index.values_mut() {
                if *position > idx {
                    *position -= 1;
                }
            }
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
            // The index is only refreshed on the `&mut self` paths, so a caller
            // that wrote straight into the public `items` vector can leave it
            // pointing at the wrong slot; trust it only when the id still
            // matches, and fall back to the scan when it does not.
            if let Some(item) = self.items.get(idx) {
                if item.id() == id {
                    return Some(item);
                }
            }
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
                        .is_some_and(|u| u.to_lowercase().contains(&query_lower))
                    || item
                        .url()
                        .is_some_and(|u| u.to_lowercase().contains(&query_lower))
                    || item
                        .notes()
                        .is_some_and(|n| n.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    pub fn search_by_domain(&self, base_domain: &str) -> Vec<&VaultItem> {
        if base_domain.trim().is_empty() {
            return Vec::new();
        }

        // Parsed once instead of once per item: the query side of `urls_match`
        // re-lowercased the domain, re-parsed it as a URL and re-ran the
        // public-suffix lookup for every entry in the vault, on the path
        // autofill hits for each page load.
        let query = DomainQuery::new(base_domain);
        self.items
            .iter()
            .filter(|item| {
                item.item_type() == ItemType::Login
                    && item.url().is_some_and(|url| query.matches(url))
            })
            .collect()
    }
}

/// The pre-parsed left-hand side of a URL match: everything `urls_match` used
/// to recompute for the query on each candidate it was handed.
struct DomainQuery {
    host: String,
    port: Option<u16>,
    is_ip: bool,
    registrable_domain: Option<String>,
}

impl DomainQuery {
    fn new(url: &str) -> Self {
        let lowered = to_lowercase_cow(url);
        let (host, port) = extract_host_and_port(&lowered);
        let host = normalize_host(&host).into_owned();
        Self {
            is_ip: is_ip_address(&host),
            registrable_domain: psl::domain_str(&host).map(str::to_string),
            host,
            port,
        }
    }

    fn matches(&self, stored_url: &str) -> bool {
        let lowered = to_lowercase_cow(stored_url);
        let (stored_host, stored_port) = extract_host_and_port(&lowered);
        let stored_host = normalize_host(&stored_host);

        if let (Some(query_port), Some(stored_port)) = (self.port, stored_port) {
            if query_port != stored_port {
                return false;
            }
        }

        if self.host == stored_host.as_ref() {
            return true;
        }

        if self.is_ip || is_ip_address(&stored_host) {
            return false;
        }

        let (Some(query_domain), Some(stored_domain)) = (
            self.registrable_domain.as_deref(),
            psl::domain_str(&stored_host),
        ) else {
            return false;
        };

        query_domain == stored_domain && is_subdomain_of(&self.host, &stored_host)
    }
}

/// `host.ends_with(&format!(".{suffix}"))`, without building the string.
fn is_subdomain_of(host: &str, suffix: &str) -> bool {
    let host = host.as_bytes();
    let suffix = suffix.as_bytes();
    let Some(dot) = host.len().checked_sub(suffix.len() + 1) else {
        return false;
    };
    host[dot] == b'.' && &host[dot + 1..] == suffix
}

/// Lowercase only when it changes something, so the common already-lowercase
/// URL is borrowed rather than copied.
fn to_lowercase_cow(s: &str) -> Cow<'_, str> {
    if s.is_ascii() && !s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.to_lowercase())
    }
}

/// Split `url` into host and port without going through the full URL parser.
///
/// `search_by_domain` parses one URL per login on every autofill lookup, and
/// `url::Url::parse` — scheme handling, percent-decoding, IDNA — dominated that
/// scan. `None` means "not obviously simple": userinfo, IPv6 literals,
/// percent-encoding, backslashes, whitespace, non-ASCII and anything the parser
/// would rewrite fall through to it, so it stays the authority on what those
/// mean. Callers pass an already-lowercased URL.
fn extract_host_and_port_fast(url: &str) -> Option<(&str, Option<u16>)> {
    if !url.is_ascii() {
        return None;
    }

    // `url::Url` elides a scheme's default port, so this has to as well.
    let (rest, default_port) = if let Some(rest) = url.strip_prefix("https://") {
        (rest, 443)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (rest, 80)
    } else {
        // The slow path prepends `https://` to a bare host, so that is the
        // scheme this would have been parsed under.
        (url, 443)
    };

    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
        None => (authority, None),
    };

    // Only hosts the parser would hand back unchanged. The last label must
    // start with a letter, which is what keeps the parser's IPv4 rewriting
    // (`0x7f.1`, `127.1`, `2130706433`) out of the fast path.
    let last_label = host.rsplit('.').find(|label| !label.is_empty())?;
    if !last_label.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }

    Some((host, port.filter(|p| *p != default_port)))
}

fn extract_host_and_port(url: &str) -> (Cow<'_, str>, Option<u16>) {
    let url = url.trim();

    if let Some((host, port)) = extract_host_and_port_fast(url) {
        return (Cow::Borrowed(host), port);
    }

    let parsed = if url.starts_with("http://") || url.starts_with("https://") {
        url::Url::parse(url).ok()
    } else {
        url::Url::parse(&format!("https://{url}")).ok()
    };

    if let Some(parsed) = parsed {
        return (
            Cow::Owned(parsed.host_str().unwrap_or("").to_string()),
            parsed.port(),
        );
    }

    if let Some(colon_pos) = url.rfind(':') {
        if let Ok(port) = url[colon_pos + 1..].parse::<u16>() {
            return (Cow::Borrowed(&url[..colon_pos]), Some(port));
        }
    }

    (Cow::Borrowed(url), None)
}

fn is_ip_address(host: &str) -> bool {
    host.split('.').all(|part| part.parse::<u8>().is_ok())
}

fn normalize_host(host: &str) -> Cow<'_, str> {
    to_lowercase_cow(host.trim_matches('.'))
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
            app_ids: Vec::new(),
        }
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let now = Utc::now();
        let meta = |id: &str| VaultMeta {
            id: id.to_string(),
            name: "Bank".into(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
        };

        let items = vec![
            VaultItem::Login {
                meta: meta("1"),
                url: "https://bank.example".into(),
                username: "ada".into(),
                pass: "hunter2-SECRET".into(),
                totp: Some("JBSWY3DPEHPK3PXP".into()),
                app_ids: Vec::new(),
            },
            VaultItem::CreditCard {
                meta: meta("2"),
                number: "4111111111111111".into(),
                exp: "12/30".into(),
                cvv: "987".into(),
                pin: Some("4242".into()),
                cardholder_name: None,
            },
            VaultItem::SecureNote {
                meta: meta("3"),
                title: "t".into(),
                content: "the recovery phrase is SECRET".into(),
            },
            VaultItem::Identity {
                meta: meta("4"),
                first_name: "Ada".into(),
                last_name: "Lovelace".into(),
                ssn: "078-05-1120".into(),
            },
        ];

        for item in &items {
            let rendered = format!("{item:?}");
            for secret in [
                "hunter2-SECRET",
                "JBSWY3DPEHPK3PXP",
                "4111111111111111",
                "987",
                "4242",
                "the recovery phrase is SECRET",
                "078-05-1120",
            ] {
                assert!(
                    !rendered.contains(secret),
                    "Debug leaked {secret:?} in {rendered}"
                );
            }
            // Still identifiable, or it would be useless for debugging.
            assert!(rendered.contains("Bank"), "lost the name: {rendered}");
        }

        // Whether a TOTP exists is metadata worth keeping; the seed is not.
        let with_totp = format!("{:?}", items[0]);
        assert!(with_totp.contains("totp: Some"), "{with_totp}");
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
    fn domain_search_respects_public_suffix_boundaries() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://victim.github.io", "alice"));
        store.add_item(login("2", "https://example.co.uk", "bob"));

        assert_eq!(store.search_by_domain("login.victim.github.io").len(), 1);
        assert_eq!(store.search_by_domain("evil.github.io").len(), 0);
        assert_eq!(store.search_by_domain("login.example.co.uk").len(), 1);
        assert_eq!(store.search_by_domain("attacker.co.uk").len(), 0);
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
    fn app_links_survive_a_json_round_trip_and_default_to_none() {
        // Written by an older client: no app_ids at all.
        let old = r#"{"item_type":"login","id":"abc","name":"t","url":"https://uber.com","username":"u","password":"p","createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-01T00:00:00Z"}"#;
        let item: VaultItem = serde_json::from_str(old).unwrap();
        match &item {
            VaultItem::Login { app_ids, .. } => assert!(app_ids.is_empty()),
            _ => panic!("expected a login"),
        }

        let mut linked = login("1", "https://uber.com", "ada");
        if let VaultItem::Login { app_ids, .. } = &mut linked {
            app_ids.push("androidapp://com.ubercab".to_string());
        }
        let json = serde_json::to_string(&linked).unwrap();
        assert!(json.contains("\"app_ids\":[\"androidapp://com.ubercab\"]"));
        assert_eq!(serde_json::from_str::<VaultItem>(&json).unwrap(), linked);

        // camelCase, as a JS client would write it.
        let camel = r#"{"item_type":"login","id":"abc","name":"t","url":"https://uber.com","username":"u","password":"p","appIds":["androidapp://com.ubercab"],"createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-01T00:00:00Z"}"#;
        match &serde_json::from_str::<VaultItem>(camel).unwrap() {
            VaultItem::Login { app_ids, .. } => {
                assert_eq!(app_ids, &vec!["androidapp://com.ubercab".to_string()])
            }
            _ => panic!("expected a login"),
        }
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
    fn deleting_from_the_middle_keeps_every_other_lookup_correct() {
        let mut store = VaultStore::new();
        for i in 0..6 {
            store.add_item(login(&i.to_string(), "https://x.com", "user"));
        }
        store.delete_item("2", None);

        assert!(store.get_item("2").is_none());
        // The index entries after the hole are shifted rather than rebuilt, so
        // an off-by-one there would surface as the wrong item coming back.
        for id in ["0", "1", "3", "4", "5"] {
            assert_eq!(store.get_item(id).map(|i| i.id()), Some(id));
        }
    }

    /// A sync merge replaces `items` wholesale, which used to leave the index
    /// pointing at the previous positions — `get_item` then returned whichever
    /// item had moved into the slot.
    #[test]
    fn replacing_items_directly_does_not_return_the_wrong_item() {
        let mut store = VaultStore::new();
        store.add_item(login("a", "https://a.com", "alice"));
        store.add_item(login("b", "https://b.com", "bob"));

        store.items = vec![
            login("b", "https://b.com", "bob"),
            login("a", "https://a.com", "alice"),
        ];

        assert_eq!(store.get_item("a").unwrap().username(), Some("alice"));
        assert_eq!(store.get_item("b").unwrap().username(), Some("bob"));

        // And the next mutation repairs the index instead of building on a lie.
        store.add_item(login("c", "https://c.com", "carol"));
        assert_eq!(store.get_item("a").unwrap().username(), Some("alice"));
        assert_eq!(store.get_item("c").unwrap().username(), Some("carol"));
    }

    #[test]
    fn deserializing_a_vault_indexes_it() {
        let mut store = VaultStore::new();
        for i in 0..4 {
            store.add_item(login(&i.to_string(), "https://x.com", "user"));
        }
        let json = serde_json::to_vec(&store).unwrap();
        let loaded: VaultStore = serde_json::from_slice(&json).unwrap();

        assert_eq!(
            loaded.item_index.len(),
            4,
            "index is built at load, not on the first write"
        );
        for i in 0..4 {
            let id = i.to_string();
            assert_eq!(loaded.get_item(&id).map(|i| i.id()), Some(id.as_str()));
        }
        assert!(loaded.get_item("nope").is_none());
        // The index is derived state, so it plays no part in equality.
        assert_eq!(loaded, store);
    }

    #[test]
    fn fast_host_split_agrees_with_the_url_parser() {
        fn slow(url: &str) -> Option<(String, Option<u16>)> {
            let parsed = if url.starts_with("http://") || url.starts_with("https://") {
                url::Url::parse(url).ok()
            } else {
                url::Url::parse(&format!("https://{url}")).ok()
            }?;
            Some((parsed.host_str().unwrap_or("").to_string(), parsed.port()))
        }

        let corpus = [
            "https://example.com",
            "http://example.com",
            "example.com",
            "https://example.com/",
            "https://example.com/login?next=/a#frag",
            "https://login.sub.example.co.uk/path",
            "https://example.com:8443",
            "http://example.com:8080/x",
            "https://example.com:443",
            "http://example.com:80",
            "http://example.com:443",
            "https://example.com:80",
            "example.com:8443",
            "example.com:443",
            "https://xn--bcher-kva.example",
            "https://my-host.example-site.com",
            "https://a.b.c.d.e.example.org",
            "https://example.com.",
            // Shapes the fast path is expected to decline on; when it does not,
            // it still has to be right.
            "https://user:pw@example.com",
            "https://127.0.0.1:3000",
            "http://0x7f.1",
            "http://127.1",
            "http://2130706433",
            "https://[::1]:8080",
            "https://exa mple.com",
            "https://éxample.com",
            "https://example.com:99999",
            "https://example.com:",
            "https://",
            "",
            "not a url at all",
            "ftp://example.com",
            "https://a..b",
            "https://-example.com",
        ];

        // Plus every combination of the pieces that make up a stored URL, so
        // the agreement is not just checked on hand-picked strings.
        let mut generated = Vec::new();
        for scheme in ["", "http://", "https://"] {
            for host in [
                "example.com", "a.example.com", "example.co.uk", "localhost",
                "127.0.0.1", "0x7f.1", "2130706433", "ex-ample.com", "example.com.",
                "a..b", "1example.com", "example.1",
            ] {
                for port in ["", ":80", ":443", ":8080", ":0", ":65535", ":65536"] {
                    for path in ["", "/", "/login", "/a?b=c#d", "?q=1"] {
                        generated.push(format!("{scheme}{host}{port}{path}"));
                    }
                }
            }
        }

        for url in corpus.iter().map(|u| u.to_string()).chain(generated) {
            let Some((host, port)) = extract_host_and_port_fast(&url) else {
                continue;
            };
            assert_eq!(
                Some((host.to_string(), port)),
                slow(&url),
                "fast path disagreed on {url:?}"
            );
        }
    }

    #[test]
    fn subdomain_suffix_check_matches_the_formatted_version() {
        for (host, suffix) in [
            ("login.example.com", "example.com"),
            ("example.com", "example.com"),
            ("notexample.com", "example.com"),
            ("a.b", "b"),
            ("b", "b"),
            ("", "example.com"),
            ("example.com", ""),
        ] {
            assert_eq!(
                is_subdomain_of(host, suffix),
                host.ends_with(&format!(".{suffix}")),
                "{host:?} / {suffix:?}"
            );
        }
    }

    #[test]
    fn delete_item_removes_from_index() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://x.com", "user"));
        store.delete_item("1", None);
        assert!(store.get_item("1").is_none());
    }
}
