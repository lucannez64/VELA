//! Structured import from other password managers.
//!
//! The onboarding reality: nobody switches password managers without their
//! old vault, so every common export format gets read here into
//! [`ImportedEntry`] values, which [`crate::commands::vault::import_vault_file`]
//! maps onto `VaultItem`s, deduplicates, and adds.
//!
//! Supported sources:
//! - Bitwarden — JSON export (unencrypted) and CSV export
//! - 1Password — CSV export and `.1pif` (JSON lines)
//! - KeePass / KeePassXC — CSV export
//! - Chrome / Edge / Safari — CSV password export
//! - Proton Pass — JSON export and CSV export
//! - VELA's own legacy JSON export (the pre-existing importer's schema)
//!
//! Detection is content-based, not filename-based: JSON is sniffed by its
//! top-level shape, CSV by its header row. That keeps the UI a single
//! "pick a file" affordance, and survives users renaming files.
//!
//! Parsing is deliberately value-based (`serde_json::Value`) for the JSON
//! formats rather than strict structs: these formats evolve independently of
//! us, and a partial import with a clear skipped-count beats a hard parse
//! error over one unknown field.

use serde_json::Value;

/// What a parsed row becomes. Every source is normalized onto these four
/// shapes; anything else is counted as unsupported instead of dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Login,
    Note,
    Card,
    Identity,
}

/// A custom field as the source spelled it. Concealed values are never logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FieldKind {
    #[default]
    Text,
    Concealed,
    Boolean,
}

#[derive(Debug, Clone, Default)]
pub struct ImportedField {
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImportedCard {
    pub number: String,
    pub cardholder: String,
    pub expiry: String,
    pub cvv: String,
    pub pin: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImportedAddress {
    pub label: String,
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub region: String,
    pub postal: String,
    pub country: String,
}

/// A file carried by the export (1Password `.1pux` attachments). Bytes are
/// only kept long enough to be sealed into the vault; never logged.
#[derive(Clone, Default)]
pub struct ImportedAttachment {
    pub file_name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for ImportedAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ImportedAttachment({}, {} bytes)", self.file_name, self.bytes.len())
    }
}

/// Larger attachments are reported instead of inflating the vault silently.
pub const MAX_IMPORTED_ATTACHMENT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct ImportedIdentity {
    pub first: String,
    pub last: String,
    pub middle: String,
    pub email: String,
    pub phone: String,
    pub company: String,
    pub job_title: String,
    pub ssn: String,
    pub addresses: Vec<ImportedAddress>,
}

/// One normalized row from any source.
#[derive(Debug, Clone, Default)]
pub struct ImportedEntry {
    pub name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp: String,
    pub kind: EntryKind,
    pub favorite: bool,
    /// Folder path as the source wrote it ("Work/Clients"); created as nested
    /// folders when the vault supports collections.
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub fields: Vec<ImportedField>,
    /// Alternate sites that should match this login.
    pub extra_urls: Vec<String>,
    pub card: ImportedCard,
    pub identity: ImportedIdentity,
    pub attachments: Vec<ImportedAttachment>,
}

impl Default for EntryKind {
    fn default() -> Self {
        EntryKind::Login
    }
}

/// Parse output before vault mapping: the entries plus what could not be
/// represented, so the import report can name it.
#[derive(Debug, Default)]
pub struct ParsedImport {
    pub entries: Vec<ImportedEntry>,
    /// Rows recognized but not imported (unsupported item types).
    pub skipped_unsupported: u32,
    /// Field-level losses, keyed by a human-readable label.
    pub unsupported: std::collections::BTreeMap<String, u32>,
    pub source: &'static str,
}

impl ParsedImport {
    fn empty(source: &'static str) -> Self {
        ParsedImport { entries: Vec::new(), skipped_unsupported: 0, unsupported: Default::default(), source }
    }

    fn unsupported(&mut self, label: &str) {
        *self.unsupported.entry(label.to_string()).or_insert(0) += 1;
    }
}

/// Detect the format from content and parse it.
pub fn parse_import(data: &str) -> Result<ParsedImport, String> {
    let trimmed = data.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err("The import file is empty".to_string());
    }

    // A 1Password .1pux export is a ZIP archive, not text — name the fix in
    // the error rather than failing with a baffling parse message.
    if trimmed.starts_with("PK\u{3}\u{4}") {
        return Err(
            "This looks like a 1Password .1pux export (a ZIP archive). \
             Use Import vault in the app, which reads the archive directly."
                .to_string(),
        );
    }

    // .1pif: one JSON object per line between `***…***` marker lines. Its
    // first line is usually a marker, never a bare `{`.
    if trimmed.starts_with("***") {
        return parse_1pif(trimmed);
    }

    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        // Try a single JSON document first (pretty-printed exports have many
        // `{`-starting lines, so line counts prove nothing). Only if that
        // fails, fall back to .1pif's JSON-lines shape.
        match parse_json_import(trimmed) {
            Ok(parsed) => return Ok(parsed),
            Err(json_err) => {
                let as_1pif = parse_1pif(trimmed);
                if as_1pif.as_ref().map(|p| !p.entries.is_empty()).unwrap_or(false) {
                    return as_1pif;
                }
                return Err(json_err);
            }
        }
    }

    parse_csv_import(trimmed)
}

// ── JSON formats ─────────────────────────────────────────────────────────────

fn parse_json_import(text: &str) -> Result<ParsedImport, String> {
    let root: Value =
        serde_json::from_str(text).map_err(|e| format!("Failed to parse JSON: {e}"))?;
    let obj = root
        .as_object()
        .ok_or_else(|| "The JSON file is not an export object".to_string())?;

    // Both Bitwarden and Proton can export encrypted payloads. Without the
    // user's account key they are opaque — say so instead of reporting
    // "0 items imported".
    for (key, manager) in [("encrypted", "Bitwarden"), ("encrypted", "Proton Pass")] {
        if obj.get(key).and_then(Value::as_bool) == Some(true) {
            return Err(format!(
                "This {} export is encrypted. Export it again unencrypted (or disable 'account encryption' in the export options) to import it.",
                manager
            ));
        }
    }

    // VELA's own legacy export: { "version": 1, "passwords": [...] }.
    if obj.contains_key("passwords") {
        return parse_legacy_vela_json(obj);
    }

    // Proton Pass wraps items per vault: { "vaults": { "<id>": { "items": [...] } } }.
    if let Some(vaults) = obj.get("vaults").and_then(Value::as_object) {
        let mut parsed = ParsedImport::empty("Proton Pass JSON");
        for (vault_id, vault) in vaults {
            let vault_name = vault
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(vault_id);
            if let Some(items) = vault.get("items").and_then(Value::as_array) {
                for item in items {
                    push_proton_item(&mut parsed, item, vault_name);
                }
            }
        }
        return Ok(parsed);
    }

    if let Some(items) = obj.get("items").and_then(Value::as_array) {
        // Bitwarden items carry a numeric "type" and a "login" object;
        // Proton's flat exports carry a string "type" ("login"/"alias"/…).
        let bitwarden_shaped = items
            .first()
            .map(|i| i.get("login").is_some() || i.get("type").and_then(Value::as_i64).is_some())
            .unwrap_or(false);
        if bitwarden_shaped {
            return parse_bitwarden_json(items, obj.get("folders"));
        }
        let mut parsed = ParsedImport::empty("Proton Pass JSON");
        for item in items {
            push_proton_item(&mut parsed, item, "");
        }
        return Ok(parsed);
    }

    Err(
        "Unrecognized JSON export. Supported: Bitwarden JSON, Proton Pass JSON, \
         or a VELA export file."
            .to_string(),
    )
}

fn parse_legacy_vela_json(obj: &serde_json::Map<String, Value>) -> Result<ParsedImport, String> {
    let mut parsed = ParsedImport::empty("VELA JSON");
    if let Some(passwords) = obj.get("passwords").and_then(Value::as_array) {
        for entry in passwords {
            // The legacy schema derives the item name from url/username at
            // import time; keep the raw fields and let the import path apply
            // the same fallback.
            parsed.entries.push(ImportedEntry {
                name: String::new(),
                url: str_field(entry, &["url"]),
                username: str_field(entry, &["username"]),
                password: str_field(entry, &["password"]),
                notes: str_field(entry, &["description"]),
                totp: str_field(entry, &["otp"]),
                kind: EntryKind::Login,
                ..ImportedEntry::default()
            });
        }
    }
    Ok(parsed)
}

fn parse_bitwarden_json(
    items: &[Value],
    folders: Option<&Value>,
) -> Result<ParsedImport, String> {
    let mut parsed = ParsedImport::empty("Bitwarden JSON");

    // Bitwarden folders: { "id", "name" } — resolve each item's folderId to
    // the folder's name so organization survives the move.
    let mut folder_names = std::collections::HashMap::new();
    if let Some(list) = folders.and_then(Value::as_array) {
        for folder in list {
            if let (Some(id), Some(name)) = (
                folder.get("id").and_then(Value::as_str),
                folder.get("name").and_then(Value::as_str),
            ) {
                folder_names.insert(id.to_string(), name.to_string());
            }
        }
    }

    for item in items {
        let name = item.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let notes = item
            .get("notes")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let favorite = item.get("favorite").and_then(Value::as_bool).unwrap_or(false);
        let folder = item
            .get("folderId")
            .and_then(Value::as_str)
            .and_then(|id| folder_names.get(id))
            .cloned();
        let fields = bitwarden_fields(item.get("fields"));
        if item.get("collectionIds").and_then(Value::as_array).is_some_and(|c| !c.is_empty()) {
            parsed.unsupported("collections");
        }

        match item.get("type").and_then(Value::as_i64) {
            Some(1) => {
                let login = item.get("login").cloned().unwrap_or(Value::Null);
                let mut urls = Vec::new();
                if let Some(uris) = login.get("uris").and_then(Value::as_array) {
                    for uri in uris {
                        if let Some(u) = uri.get("uri").and_then(Value::as_str) {
                            let u = u.trim();
                            if !u.is_empty() {
                                urls.push(u.to_string());
                            }
                        }
                    }
                }
                let primary = urls.first().cloned().unwrap_or_default();
                if !urls.is_empty() {
                    urls.remove(0);
                }
                parsed.entries.push(ImportedEntry {
                    name: name.clone(),
                    url: primary,
                    username: login.get("username").and_then(Value::as_str).unwrap_or("").into(),
                    password: login.get("password").and_then(Value::as_str).unwrap_or("").into(),
                    notes,
                    totp: login.get("totp").and_then(Value::as_str).unwrap_or("").into(),
                    kind: EntryKind::Login,
                    favorite,
                    folder,
                    fields,
                    extra_urls: urls,
                    ..ImportedEntry::default()
                });
            }
            Some(2) => {
                parsed.entries.push(ImportedEntry {
                    name,
                    notes,
                    kind: EntryKind::Note,
                    favorite,
                    folder,
                    fields,
                    ..ImportedEntry::default()
                });
            }
            Some(3) => {
                let card = item.get("card").cloned().unwrap_or(Value::Null);
                let exp_month = card.get("expMonth").and_then(Value::as_str).unwrap_or("").trim();
                let exp_year = card.get("expYear").and_then(Value::as_str).unwrap_or("").trim();
                let expiry = match (exp_month.is_empty(), exp_year.is_empty()) {
                    (false, false) => format!("{exp_month}/{exp_year}"),
                    (false, true) => exp_month.to_string(),
                    _ => String::new(),
                };
                if card.get("brand").and_then(Value::as_str).is_some_and(|b| !b.is_empty()) {
                    parsed.unsupported("card brand");
                }
                parsed.entries.push(ImportedEntry {
                    name,
                    notes,
                    kind: EntryKind::Card,
                    favorite,
                    folder,
                    fields,
                    card: ImportedCard {
                        number: card.get("number").and_then(Value::as_str).unwrap_or("").into(),
                        cardholder: card.get("cardholderName").and_then(Value::as_str).unwrap_or("").into(),
                        expiry,
                        cvv: card.get("code").and_then(Value::as_str).unwrap_or("").into(),
                        pin: String::new(),
                    },
                    ..ImportedEntry::default()
                });
            }
            Some(4) => {
                let identity = item.get("identity").cloned().unwrap_or(Value::Null);
                let mut addresses = Vec::new();
                let address1 = identity.get("address1").and_then(Value::as_str).unwrap_or("").trim();
                if !address1.is_empty() {
                    addresses.push(ImportedAddress {
                        label: "Home".into(),
                        line1: address1.to_string(),
                        line2: identity.get("address2").and_then(Value::as_str).unwrap_or("").into(),
                        city: identity.get("city").and_then(Value::as_str).unwrap_or("").into(),
                        region: identity.get("state").and_then(Value::as_str).unwrap_or("").into(),
                        postal: identity.get("postalCode").and_then(Value::as_str).unwrap_or("").into(),
                        country: identity.get("country").and_then(Value::as_str).unwrap_or("").into(),
                    });
                }
                for field in ["passportNumber", "licenseNumber"] {
                    if identity.get(field).and_then(Value::as_str).is_some_and(|v| !v.is_empty()) {
                        parsed.unsupported(field);
                    }
                }
                parsed.entries.push(ImportedEntry {
                    name,
                    notes,
                    kind: EntryKind::Identity,
                    favorite,
                    folder,
                    fields,
                    identity: ImportedIdentity {
                        first: identity.get("firstName").and_then(Value::as_str).unwrap_or("").into(),
                        last: identity.get("lastName").and_then(Value::as_str).unwrap_or("").into(),
                        middle: identity.get("middleName").and_then(Value::as_str).unwrap_or("").into(),
                        email: identity.get("email").and_then(Value::as_str).unwrap_or("").into(),
                        phone: identity.get("phone").and_then(Value::as_str).unwrap_or("").into(),
                        company: identity.get("company").and_then(Value::as_str).unwrap_or("").into(),
                        job_title: identity.get("title").and_then(Value::as_str).unwrap_or("").into(),
                        ssn: identity.get("ssn").and_then(Value::as_str).unwrap_or("").into(),
                        addresses,
                    },
                    ..ImportedEntry::default()
                });
            }
            _ => parsed.skipped_unsupported += 1, // unknown/unsupported Bitwarden type
        }
    }
    Ok(parsed)
}

/// Bitwarden custom fields: `{ name, value, type }` with 0 = text,
/// 1 = hidden, 2 = boolean.
fn bitwarden_fields(fields: Option<&Value>) -> Vec<ImportedField> {
    let mut out = Vec::new();
    for field in fields.and_then(Value::as_array).into_iter().flatten() {
        let label = field.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if label.is_empty() {
            continue;
        }
        let kind = match field.get("type").and_then(Value::as_i64) {
            Some(1) => FieldKind::Concealed,
            Some(2) => FieldKind::Boolean,
            _ => FieldKind::Text,
        };
        let value = match kind {
            FieldKind::Boolean => field
                .get("value")
                .map(|v| v.as_bool().map(|b| b.to_string()).unwrap_or_else(|| v.to_string()))
                .unwrap_or_else(|| "false".into()),
            _ => field.get("value").and_then(Value::as_str).unwrap_or("").to_string(),
        };
        out.push(ImportedField { label, kind, value });
    }
    out
}

fn first_uri(login: &Value) -> String {
    if let Some(uris) = login.get("uris").and_then(Value::as_array) {
        for uri in uris {
            if let Some(u) = uri.get("uri").and_then(Value::as_str) {
                if !u.trim().is_empty() {
                    return u.trim().to_string();
                }
            }
        }
    }
    login.get("uri").and_then(Value::as_str).unwrap_or("").trim().to_string()
}

fn push_proton_item(parsed: &mut ParsedImport, item: &Value, vault_name: &str) {
    // Proton has shipped both a flat shape and a `data`-wrapped shape; read
    // whichever is present instead of guessing from the version.
    let data = item.get("data").unwrap_or(item);
    let metadata = data.get("metadata").or_else(|| item.get("metadata"));
    let item_type = data
        .get("type")
        .and_then(Value::as_str)
        .or_else(|| item.get("type").and_then(Value::as_str))
        .unwrap_or("login")
        .to_lowercase();
    let name = metadata
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .or_else(|| data.get("name").and_then(Value::as_str))
        .or_else(|| item.get("name").and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string();
    let notes = metadata
        .and_then(|m| m.get("note"))
        .and_then(Value::as_str)
        .or_else(|| data.get("note").and_then(Value::as_str))
        .or_else(|| item.get("note").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    let folder = if vault_name.is_empty() { None } else { Some(vault_name.to_string()) };
    let content = data.get("content").unwrap_or(&Value::Null);
    let fields = proton_fields(data.get("extraFields").or_else(|| item.get("extraFields")));
    let pick = |keys: &[&str]| -> String {
        for key in keys {
            if let Some(value) = content.get(*key).or_else(|| data.get(*key)).or_else(|| item.get(*key)) {
                if let Some(text) = value.as_str() {
                    if !text.trim().is_empty() {
                        return text.trim().to_string();
                    }
                }
            }
        }
        String::new()
    };

    match item_type.as_str() {
        "login" | "alias" => {
            let mut urls: Vec<String> = Vec::new();
            for source in [content, data, item] {
                if let Some(list) = source.get("urls").and_then(Value::as_array) {
                    for entry in list {
                        if let Some(url) = entry.as_str().map(str::to_string).or_else(|| {
                            entry.get("url").and_then(Value::as_str).map(str::to_string)
                        }) {
                            if !url.trim().is_empty() {
                                urls.push(url.trim().to_string());
                            }
                        }
                    }
                    if !urls.is_empty() {
                        break;
                    }
                }
            }
            if urls.is_empty() {
                let single = pick(&["itemUrl", "url", "aliasEmail"]);
                if !single.is_empty() {
                    urls.push(single);
                }
            }
            let primary = urls.first().cloned().unwrap_or_default();
            if !urls.is_empty() {
                urls.remove(0);
            }
            let username = if item_type == "alias" {
                pick(&["aliasEmail", "username"])
            } else {
                pick(&["username", "email"])
            };
            parsed.entries.push(ImportedEntry {
                name,
                url: primary,
                username,
                password: pick(&["password"]),
                notes,
                totp: pick(&["totpUri", "totp"]),
                kind: EntryKind::Login,
                folder,
                fields,
                extra_urls: urls,
                ..ImportedEntry::default()
            });
        }
        "note" => {
            let body = pick(&["note", "content"]);
            parsed.entries.push(ImportedEntry {
                name,
                notes: if body.is_empty() { notes } else { body },
                kind: EntryKind::Note,
                folder,
                fields,
                ..ImportedEntry::default()
            });
        }
        "credit_card" | "creditcard" => {
            let expiry = proton_expiry(content, data, item);
            parsed.entries.push(ImportedEntry {
                name,
                notes,
                kind: EntryKind::Card,
                folder,
                fields,
                card: ImportedCard {
                    number: pick(&["number", "cardNumber"]),
                    cardholder: pick(&["cardholderName", "cardholder"]),
                    expiry,
                    cvv: pick(&["verificationNumber", "cvv", "securityCode"]),
                    pin: pick(&["pin"]),
                },
                ..ImportedEntry::default()
            });
        }
        "identity" => {
            let mut identity = ImportedIdentity {
                first: pick(&["firstName"]),
                last: pick(&["lastName"]),
                middle: pick(&["middleName"]),
                email: pick(&["email"]),
                phone: pick(&["phoneNumber", "phone"]),
                company: pick(&["company", "organization"]),
                job_title: pick(&["jobTitle", "title"]),
                ssn: pick(&["socialSecurityNumber", "ssn"]),
                addresses: Vec::new(),
            };
            for key in [
                "personalAddress",
                "workAddress",
                "address",
            ] {
                if let Some(address) = content.get(key).or_else(|| data.get(key)) {
                    if let Some(address) = proton_address(address, key) {
                        identity.addresses.push(address);
                    }
                }
            }
            for key in ["extraPersonalAddresses", "extraWorkAddresses"] {
                for address in content
                    .get(key)
                    .or_else(|| data.get(key))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(address) = proton_address(address, key) {
                        identity.addresses.push(address);
                    }
                }
            }
            parsed.entries.push(ImportedEntry {
                name,
                notes,
                kind: EntryKind::Identity,
                folder,
                fields,
                identity,
                ..ImportedEntry::default()
            });
        }
        other => {
            parsed.skipped_unsupported += 1;
            parsed.unsupported(if other.is_empty() { "Proton item type" } else { other });
        }
    }
}

fn proton_expiry(content: &Value, data: &Value, item: &Value) -> String {
    for source in [content, data, item] {
        for key in ["expirationDate", "expiration", "expiryDate"] {
            if let Some(value) = source.get(key) {
                if let Some(text) = value.as_str() {
                    if !text.trim().is_empty() {
                        return text.trim().to_string();
                    }
                }
                if let Some(object) = value.as_object() {
                    let month = object.get("month").map(Value::to_string).unwrap_or_default();
                    let year = object.get("year").map(Value::to_string).unwrap_or_default();
                    if !month.is_empty() && !year.is_empty() {
                        return format!("{}/{}", month.trim_matches('"'), year.trim_matches('"'));
                    }
                }
            }
        }
    }
    String::new()
}

fn proton_address(value: &Value, label: &str) -> Option<ImportedAddress> {
    let object = value.as_object()?;
    let get = |keys: &[&str]| -> String {
        for key in keys {
            if let Some(text) = object.get(*key).and_then(Value::as_str) {
                if !text.trim().is_empty() {
                    return text.trim().to_string();
                }
            }
        }
        String::new()
    };
    let address = ImportedAddress {
        label: label.to_string(),
        line1: get(&["line1", "street", "address"]),
        line2: get(&["line2", "apartment"]),
        city: get(&["city"]),
        region: get(&["region", "state"]),
        postal: get(&["postalCode", "zip"]),
        country: get(&["countryCode", "country"]),
    };
    if address.line1.is_empty() && address.city.is_empty() && address.postal.is_empty() {
        None
    } else {
        Some(address)
    }
}

fn proton_fields(fields: Option<&Value>) -> Vec<ImportedField> {
    let mut out = Vec::new();
    for field in fields.and_then(Value::as_array).into_iter().flatten() {
        let label = field
            .get("fieldName")
            .and_then(Value::as_str)
            .or_else(|| field.get("name").and_then(Value::as_str))
            .or_else(|| field.get("title").and_then(Value::as_str))
            .unwrap_or("")
            .trim()
            .to_string();
        if label.is_empty() {
            continue;
        }
        let field_type = field.get("type").and_then(Value::as_str).unwrap_or("text").to_lowercase();
        let kind = match field_type.as_str() {
            "hidden" | "totp" => FieldKind::Concealed,
            "boolean" => FieldKind::Boolean,
            _ => FieldKind::Text,
        };
        let value = field
            .get("data")
            .and_then(|d| d.get("content"))
            .and_then(Value::as_str)
            .or_else(|| field.get("value").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        out.push(ImportedField { label, kind, value });
    }
    out
}

// ── CSV formats ──────────────────────────────────────────────────────────────

/// One canonical column per concept; every manager's spelling maps onto it.
const COL_NAME: usize = 0;
const COL_URL: usize = 1;
const COL_USERNAME: usize = 2;
const COL_PASSWORD: usize = 3;
const COL_NOTES: usize = 4;
const COL_TOTP: usize = 5;
const COL_GROUP: usize = 6;
const COL_TYPE: usize = 7;
const COL_FIELDS: usize = 8;
const COL_FAVORITE: usize = 9;
const COL_COUNT: usize = 10;

fn canonical_column(header: &str) -> Option<usize> {
    let h = header.trim().to_lowercase();
    // Bitwarden's CSV prefixes login columns; strip it so "login_username"
    // and Chrome's "username" land in the same place.
    let h = h.strip_prefix("login_").unwrap_or(&h).to_string();
    match h.as_str() {
        "name" | "title" | "account" | "item name" | "itemname" => Some(COL_NAME),
        "url" | "uri" | "website" | "web site" | "websites" | "itemurl" | "site"
        | "site url" | "html" => Some(COL_URL),
        "username" | "user name" | "user" | "email" | "e-mail" | "email address" | "login"
        | "login username" => Some(COL_USERNAME),
        "password" | "pass" | "login password" => Some(COL_PASSWORD),
        "notes" | "note" | "description" | "comments" | "comment" | "extra" => Some(COL_NOTES),
        "totp" | "otpauth" | "otp" | "one-time code" | "one time code" | "one time password"
        | "one-time password" => Some(COL_TOTP),
        "group" | "groups" | "folder" | "group title" | "group/folder" | "grouping" => {
            Some(COL_GROUP)
        }
        "type" => Some(COL_TYPE),
        "fields" | "custom fields" => Some(COL_FIELDS),
        "favorite" | "favourite" => Some(COL_FAVORITE),
        _ => None,
    }
}

fn parse_csv_import(text: &str) -> Result<ParsedImport, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| format!("Failed to read CSV header: {e}"))?
        .clone();
    if headers.is_empty() {
        return Err("The CSV file has no header row".to_string());
    }

    let mut column_map = [None; COL_COUNT];
    for (idx, header) in headers.iter().enumerate() {
        if let Some(col) = canonical_column(header) {
            // First match wins: a file with both "url" and "login_uri" keeps
            // the leftmost column, which matches what every exporter writes.
            if column_map[col].is_none() {
                column_map[col] = Some(idx);
            }
        }
    }
    // A CSV without a password column is not a password export — a stray
    // contacts CSV (which has "email") would otherwise import as a pile of
    // empty logins. Every supported manager's export carries one.
    if column_map[COL_PASSWORD].is_none() {
        return Err(
            "Unrecognized CSV export. Expected columns from Bitwarden, 1Password, \
             KeePass/KeePassXC, Chrome/Edge/Safari, or Proton Pass."
                .to_string(),
        );
    }

    let source = csv_source_label(&column_map);
    let mut parsed = ParsedImport::empty(source);

    for (line_no, record) in reader.records().enumerate() {
        let record =
            record.map_err(|e| format!("CSV parse error on line {}: {e}", line_no + 2))?;
        let cell = |col: usize| -> String {
            column_map[col]
                .and_then(|idx| record.get(idx))
                .unwrap_or("")
                .trim()
                .to_string()
        };

        // Bitwarden's CSV tags every row with a type. Notes become notes;
        // cards and identities have no payload in a CSV (no number, no
        // address columns), so they are counted rather than half-imported.
        let row_type = cell(COL_TYPE).to_lowercase();
        if row_type == "card" || row_type == "identity" {
            parsed.skipped_unsupported += 1;
            parsed.unsupported("card/identity row (not representable in CSV)");
            continue;
        }
        let is_note = row_type == "note";

        let name = cell(COL_NAME);
        let url = cell(COL_URL);
        let username = cell(COL_USERNAME);
        let password = cell(COL_PASSWORD);
        let notes = cell(COL_NOTES);
        let totp = cell(COL_TOTP);
        let group = cell(COL_GROUP);
        let favorite = matches!(
            cell(COL_FAVORITE).to_lowercase().as_str(),
            "1" | "true" | "yes"
        );
        let fields = bitwarden_fields_json(&cell(COL_FIELDS));

        if name.is_empty() && url.is_empty() && username.is_empty() && password.is_empty() {
            continue; // blank padding row, not data
        }

        // KeePass-family group paths ("Email/Personal") carry real structure;
        // keep them as a folder path rather than flattening them away.
        let folder = if group.is_empty() { None } else { Some(group) };

        let fallback_name = if !url.is_empty() {
            url.clone()
        } else {
            username.clone()
        };

        parsed.entries.push(ImportedEntry {
            name: if name.is_empty() { fallback_name } else { name },
            url,
            username,
            password,
            notes,
            totp,
            kind: if is_note { EntryKind::Note } else { EntryKind::Login },
            favorite,
            folder,
            fields,
            ..ImportedEntry::default()
        });
    }

    Ok(parsed)
}

fn csv_source_label(column_map: &[Option<usize>; COL_COUNT]) -> &'static str {
    let has = |col: usize| column_map[col].is_some();
    if has(COL_TYPE) {
        "Bitwarden CSV" // the only exporter that tags each row with a type
    } else if has(COL_GROUP) {
        "KeePass/KeePassXC CSV"
    } else if has(COL_TOTP) && has(COL_NOTES) {
        "CSV" // Safari / 1Password / Proton — identical mapping
    } else {
        "Browser CSV" // Chrome / Edge / generic
    }
}

// ── 1Password .1pif (JSON lines) ─────────────────────────────────────────────

/// `.1pif` is one JSON object per line, with `***…***` separator/markup lines
/// between records. Parsing is best-effort by design: the format has drifted
/// across 1Password versions, so unrecognized records are skipped, not fatal.
pub fn parse_1pif(text: &str) -> Result<ParsedImport, String> {
    let mut parsed = ParsedImport::empty("1Password (.1pif)");

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("***") {
            continue;
        }
        let Ok(item) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(item) = item.as_object() else { continue };
        let type_name = item
            .get("typeName")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();

        // Folder records organize 1Password's tree; VELA keeps folders in
        // notes at most, so a folder line is metadata, not data.
        if type_name.contains("folder") {
            continue;
        }

        let title = item
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let fields = item.get("fields").and_then(Value::as_array);

        if type_name.contains("login") {
            let mut username = String::new();
            let mut password = String::new();
            let mut url = String::new();
            if let Some(fields) = fields {
                for field in fields {
                    let designation = field
                        .get("designation")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_lowercase();
                    let name = field
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_lowercase();
                    let value = field
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if username.is_empty()
                        && (designation == "username" || name == "username" || name == "email")
                    {
                        username = value;
                    } else if password.is_empty()
                        && (designation == "password" || name == "password")
                    {
                        password = value;
                    } else if url.is_empty() && (name == "website" || name == "url" || name == "site")
                    {
                        url = value;
                    }
                }
            }
            if url.is_empty() {
                url = item
                    .get("location")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        item.get("urls")
                            .and_then(Value::as_array)
                            .and_then(|u| u.first())
                            .and_then(|u| {
                                u.as_str().map(str::to_string).or_else(|| {
                                    u.get("url").and_then(Value::as_str).map(str::to_string)
                                })
                            })
                    })
                    .unwrap_or_default()
                    .trim()
                    .to_string();
            }
            parsed.entries.push(ImportedEntry {
                name: if title.is_empty() { url.clone() } else { title },
                url,
                username,
                password,
                notes: String::new(),
                totp: String::new(),
                kind: EntryKind::Login,
                ..ImportedEntry::default()
            });
        } else if type_name.contains("note") {
            let content = item
                .get("notesPlain")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            parsed.entries.push(ImportedEntry {
                name: title,
                url: String::new(),
                username: String::new(),
                password: String::new(),
                notes: content,
                totp: String::new(),
                kind: EntryKind::Note,
                ..ImportedEntry::default()
            });
        } else {
            parsed.skipped_unsupported += 1;
        }
    }

    if parsed.entries.is_empty() {
        return Err("No logins or notes found in this .1pif export".to_string());
    }
    Ok(parsed)
}

/// Wrap attachment bytes as an encrypted note body. The vault has no file-blob
/// viewer yet, so a base64 note is the honest way to keep the bytes rather
/// than lose them; mobile and desktop decode the same header.
pub fn encode_attachment_note(file_name: &str, mime: &str, bytes: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = String::with_capacity(encoded.len() + 128);
    out.push_str("VELA IMPORTED ATTACHMENT\n");
    out.push_str(&format!("File: {file_name}\n"));
    out.push_str(&format!("Type: {}\n", if mime.is_empty() { "application/octet-stream" } else { mime }));
    out.push_str(&format!("Size: {} bytes\n", bytes.len()));
    out.push_str("Encoding: base64\n\n");
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out
}

/// Detect a binary archive (1Password `.1pux`) or fall back to text parsing.
pub fn parse_import_bytes(data: &[u8]) -> Result<ParsedImport, String> {
    if data.starts_with(&[0x50, 0x4b, 0x03, 0x04]) {
        return parse_1pux(data);
    }
    let text = std::str::from_utf8(data)
        .map_err(|e| format!("Import file is not valid UTF-8: {e}"))?;
    parse_import(text)
}

/// 1Password `.1pux` is a ZIP containing `export.data` (JSON) and attachment
/// files. Only the structured data is imported; attachments are counted.
pub fn parse_1pux(data: &[u8]) -> Result<ParsedImport, String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))
        .map_err(|e| format!("Could not read the .1pux archive: {e}"))?;
    let mut export = None;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|e| format!("Could not read .1pux entry: {e}"))?;
        let entry_name = file
            .name()
            .map_err(|e| format!("Could not read .1pux entry name: {e}"))?
            .to_string();
        if entry_name.ends_with("export.data") {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut file, &mut text)
                .map_err(|e| format!("Could not read .1pux export.data: {e}"))?;
            export = Some(text);
            break;
        }
    }
    let text = export.ok_or_else(|| "This .1pux archive has no export.data".to_string())?;
    let root: Value = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse .1pux export.data: {e}"))?;
    let accounts = root
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| "Unrecognized .1pux export.data".to_string())?;

    let mut parsed = ParsedImport::empty("1Password (.1pux)");
    for account in accounts {
        for vault in account
            .get("vaults")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let vault_name = vault
                .get("attrs")
                .and_then(|a| a.get("name"))
                .and_then(Value::as_str)
                .or_else(|| vault.get("name").and_then(Value::as_str))
                .map(str::to_string);
            for item in vault
                .get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                push_1pux_item(&mut parsed, item, vault_name.as_deref(), &mut archive);
            }
        }
    }
    Ok(parsed)
}

fn op_scalar(value: &Value) -> (String, FieldKind) {
    if let Some(text) = value.as_str() {
        return (text.to_string(), FieldKind::Text);
    }
    if let Some(flag) = value.as_bool() {
        return (flag.to_string(), FieldKind::Boolean);
    }
    if let Some(object) = value.as_object() {
        if let Some(text) = object.get("concealed").and_then(Value::as_str) {
            return (text.to_string(), FieldKind::Concealed);
        }
        for key in ["string", "email", "url", "phone", "date", "monthYear", "menu", "number"] {
            if let Some(text) = object.get(key) {
                if let Some(text) = text.as_str() {
                    return (text.to_string(), FieldKind::Text);
                }
                if text.is_number() {
                    return (text.to_string(), FieldKind::Text);
                }
            }
        }
        if let Some(address) = object.get("address").and_then(Value::as_object) {
            let joined = ["street", "city", "state", "zip", "country"]
                .iter()
                .filter_map(|key| address.get(*key).and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(", ");
            return (joined, FieldKind::Text);
        }
    }
    (String::new(), FieldKind::Text)
}

fn push_1pux_item(
    parsed: &mut ParsedImport,
    item: &Value,
    vault_name: Option<&str>,
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
) {
    let type_name = item
        .get("typeName")
        .or_else(|| item.get("type_name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let title = item
        .get("title")
        .and_then(Value::as_str)
        .or_else(|| item.get("overview").and_then(|o| o.get("title")).and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string();
    let note = item
        .get("note")
        .and_then(Value::as_str)
        .or_else(|| item.get("details").and_then(|d| d.get("notesPlain")).and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    let tags: Vec<String> = item
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| t.as_str().map(str::to_string))
        .collect();
    let folder = vault_name.map(str::to_string);

    // Login fields are `{designation, value}`; sections carry everything else.
    let mut custom: Vec<ImportedField> = Vec::new();
    let mut username = String::new();
    let mut password = String::new();
    let mut totp = String::new();
    let mut website = String::new();
    let mut card = ImportedCard::default();
    let mut identity = ImportedIdentity::default();
    let mut attachment_meta: Vec<(String, String, String)> = Vec::new();

    let mut consume = |field: &Value, known: bool| {
        let label = field
            .get("title")
            .and_then(Value::as_str)
            .or_else(|| field.get("name").and_then(Value::as_str))
            .or_else(|| field.get("id").and_then(Value::as_str))
            .unwrap_or("")
            .trim()
            .to_string();
        let designation = field
            .get("designation")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let raw = field.get("value").cloned().unwrap_or(Value::Null);
        if let Some(file) = raw.get("file") {
            let file_name = file
                .get("fileName")
                .and_then(Value::as_str)
                .or_else(|| file.get("name").and_then(Value::as_str))
                .unwrap_or(&label)
                .to_string();
            let mime = file
                .get("contentType")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let document_id = file
                .get("documentId")
                .and_then(Value::as_str)
                .or_else(|| file.get("id").and_then(Value::as_str))
                .unwrap_or("")
                .to_string();
            if !document_id.is_empty() || !file_name.is_empty() {
                attachment_meta.push((file_name, mime, document_id));
            }
            return;
        }
        let (value, kind) = op_scalar(&raw);
        if value.is_empty() {
            return;
        }
        let lowered = label.to_lowercase();
        let key = if !designation.is_empty() { designation } else { lowered.clone() };
        match key.as_str() {
            "username" => username = value,
            "password" => password = value,
            "totp" | "one-time password" | "one time password" | "otp" => totp = value,
            "url" | "website" => website = value,
            _ if key.contains("card number") || lowered == "number" => card.number = value,
            _ if key.contains("cardholder") => card.cardholder = value,
            _ if key.contains("expir") => card.expiry = value,
            _ if key.contains("cvv") || key.contains("verification") || key.contains("security code") => card.cvv = value,
            _ if lowered == "pin" => card.pin = value,
            _ if key.contains("first name") || lowered == "firstname" => identity.first = value,
            _ if key.contains("last name") || lowered == "lastname" => identity.last = value,
            _ if key.contains("middle") => identity.middle = value,
            _ if key == "email" => identity.email = value,
            _ if key == "phone" || key.contains("phone") => identity.phone = value,
            _ if key.contains("company") || key.contains("organization") => identity.company = value,
            _ if key.contains("job title") || key == "title" => identity.job_title = value,
            _ if key.contains("social security") || lowered == "ssn" => identity.ssn = value,
            _ if key.contains("address") => {
                identity.addresses.push(ImportedAddress {
                    label: if label.is_empty() { "Address".into() } else { label },
                    line1: value,
                    ..ImportedAddress::default()
                });
            }
            _ => {
                if !known && !label.is_empty() {
                    custom.push(ImportedField { label, kind, value });
                }
            }
        }
    };

    if let Some(login_fields) = item
        .get("details")
        .and_then(|d| d.get("loginFields"))
        .and_then(Value::as_array)
    {
        for field in login_fields {
            consume(field, true);
        }
    }
    if let Some(sections) = item
        .get("details")
        .and_then(|d| d.get("sections"))
        .and_then(Value::as_array)
    {
        for section in sections {
            for field in section.get("fields").and_then(Value::as_array).into_iter().flatten() {
                consume(field, false);
            }
        }
    }
    // Alternate URLs live on the overview in 1Password's export.
    if let Some(urls) = item.get("overview").and_then(|o| o.get("URLs")).and_then(Value::as_array) {
        for entry in urls {
            if let Some(url) = entry.as_str().map(str::to_string).or_else(|| {
                entry.get("url").and_then(Value::as_str).map(str::to_string)
            }) {
                if website.is_empty() {
                    website = url;
                }
            }
        }
    }

    let attachments: Vec<ImportedAttachment> = attachment_meta
        .into_iter()
        .filter_map(|(file_name, mime, document_id)| {
            match read_attachment(archive, &document_id, &file_name) {
                Some(bytes) if bytes.len() <= MAX_IMPORTED_ATTACHMENT_BYTES => {
                    Some(ImportedAttachment { file_name, mime, bytes })
                }
                Some(_) => {
                    parsed.unsupported("attachment over 8 MiB");
                    None
                }
                None => {
                    parsed.unsupported("attachment file missing from archive");
                    None
                }
            }
        })
        .collect();

    match type_name.as_str() {
        "login" | "password" => {
            parsed.entries.push(ImportedEntry {
                name: if title.is_empty() { website.clone() } else { title },
                url: website,
                username,
                password,
                notes: note,
                totp,
                kind: EntryKind::Login,
                folder,
                tags,
                fields: custom,
                attachments,
                ..ImportedEntry::default()
            });
        }
        "securenote" | "note" => {
            parsed.entries.push(ImportedEntry {
                name: title,
                notes: note,
                kind: EntryKind::Note,
                folder,
                tags,
                fields: custom,
                attachments,
                ..ImportedEntry::default()
            });
        }
        "creditcard" => {
            parsed.entries.push(ImportedEntry {
                name: title,
                notes: note,
                kind: EntryKind::Card,
                folder,
                tags,
                fields: custom,
                card,
                attachments,
                ..ImportedEntry::default()
            });
        }
        "identity" => {
            parsed.entries.push(ImportedEntry {
                name: title,
                notes: note,
                kind: EntryKind::Identity,
                folder,
                tags,
                fields: custom,
                identity,
                attachments,
                ..ImportedEntry::default()
            });
        }
        _ => {
            parsed.skipped_unsupported += 1;
            parsed.unsupported(if type_name.is_empty() { "unknown item type" } else { "1Password item type" });
        }
    }
}

/// Bitwarden's CSV packs custom fields as a JSON array in one cell.
fn bitwarden_fields_json(raw: &str) -> Vec<ImportedField> {
    let raw = raw.trim();
    if !raw.starts_with('[') {
        return Vec::new();
    }
    let Ok(parsed) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    bitwarden_fields(Some(&parsed))
}

/// Read an attachment out of the `.1pux` archive. 1Password stores files
/// under `files/<documentId>`; fall back to matching the file name.
fn read_attachment(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    document_id: &str,
    file_name: &str,
) -> Option<Vec<u8>> {
    let mut candidate = None;
    for index in 0..archive.len() {
        let Ok(file) = archive.by_index(index) else {
            continue;
        };
        let Ok(name) = file.name() else {
            continue;
        };
        let name = name.to_string();
        if !name.starts_with("files/") {
            continue;
        }
        if (!document_id.is_empty() && name.contains(document_id))
            || (!file_name.is_empty() && name.ends_with(file_name))
        {
            candidate = Some(name);
            break;
        }
    }
    let name = candidate?;
    let mut file = archive.by_name(&name).ok()?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).ok()?;
    Some(bytes)
}

/// Pick `field`/`field[0]`-style string values off a JSON object.
fn str_field(value: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(s) = value.get(key).and_then(Value::as_str) {
            return s.trim().to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_bitwarden_json_imports_logins_notes_and_skips_cards() {
        let data = r#"{
            "encrypted": false,
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [
                {
                    "type": 1,
                    "name": "GitHub",
                    "notes": "code hosting",
                    "login": {
                        "username": "octocat",
                        "password": "hunter2",
                        "totp": "otpauth://totp/x",
                        "uris": [{ "uri": "https://github.com/login" }]
                    },
                    "folderId": "f1"
                },
                {
                    "type": 2,
                    "name": "Recovery codes",
                    "notes": "abc-123"
                },
                {
                    "type": 3,
                    "name": "Visa",
                    "card": { "number": "4111" }
                }
            ]
        }"#;
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.source, "Bitwarden JSON");
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.skipped_unsupported, 0);

        let login = &parsed.entries[0];
        assert_eq!(login.kind, EntryKind::Login);
        assert_eq!(login.name, "GitHub");
        assert_eq!(login.username, "octocat");
        assert_eq!(login.password, "hunter2");
        assert_eq!(login.url, "https://github.com/login");
        assert_eq!(login.totp, "otpauth://totp/x");
        assert_eq!(login.folder.as_deref(), Some("Work"));
        assert_eq!(login.notes, "code hosting");

        let note = &parsed.entries[1];
        assert_eq!(note.kind, EntryKind::Note);
        assert_eq!(note.notes, "abc-123");

        let card = &parsed.entries[2];
        assert_eq!(card.kind, EntryKind::Card);
        assert_eq!(card.card.number, "4111");
    }

    #[test]
    fn encrypted_bitwarden_json_is_named_as_such() {
        let data = r#"{ "encrypted": true, "items": [] }"#;
        let err = parse_import(data).unwrap_err();
        assert!(err.contains("encrypted"), "{err}");
    }

    #[test]
    fn proton_pass_vault_json_imports_logins_and_aliases() {
        let data = r#"{
            "encrypted": false,
            "version": "1.24.0",
            "vaults": {
                "v1": {
                    "name": "Personal",
                    "items": [
                        {
                            "type": "login",
                            "metadata": { "name": "Example", "note": "n" },
                            "itemUrl": "https://example.com",
                            "username": "user@example.com",
                            "password": "pw",
                            "totp": ""
                        },
                        {
                            "type": "alias",
                            "metadata": { "name": "Newsletter alias" },
                            "aliasEmail": "news-abc@simplelogin.fr"
                        },
                        {
                            "type": "credit_card",
                            "metadata": { "name": "Card" }
                        }
                    ]
                }
            }
        }"#;
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.source, "Proton Pass JSON");
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.skipped_unsupported, 0);
        assert_eq!(parsed.entries[0].url, "https://example.com");
        assert_eq!(parsed.entries[0].folder.as_deref(), Some("Personal"));
        assert_eq!(parsed.entries[1].username, "news-abc@simplelogin.fr");
        assert_eq!(parsed.entries[2].kind, EntryKind::Card);
    }

    #[test]
    fn bitwarden_csv_maps_prefixed_columns_and_row_types() {
        let data = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                    Work,1,login,GitHub,,\"[{\"\"name\"\":\"\"Recovery\"\",\"\"value\"\":\"\"R-1\"\",\"\"type\"\":0}]\",0,https://github.com,octo,hunter2,otpauth://x\n\
                    ,,note,Codes,abc,,0,,,\n\
                    ,,card,Visa,,,,,,,";
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.source, "Bitwarden CSV");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.skipped_unsupported, 1);
        assert!(parsed.unsupported.contains_key("card/identity row (not representable in CSV)"));
        let login = &parsed.entries[0];
        assert_eq!(login.url, "https://github.com");
        assert_eq!(login.username, "octo");
        assert_eq!(login.password, "hunter2");
        assert_eq!(login.totp, "otpauth://x");
        assert_eq!(login.folder.as_deref(), Some("Work"));
        assert!(login.favorite);
        assert_eq!(login.fields.len(), 1);
        assert_eq!(login.fields[0].label, "Recovery");
        assert_eq!(parsed.entries[1].kind, EntryKind::Note);
    }

    #[test]
    fn browser_csv_chrome_edge_safari_and_proton_share_one_mapping() {
        let chrome = "name,url,username,password\nGitHub,github.com,octo,pw";
        let parsed = parse_import(chrome).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].username, "octo");
        assert_eq!(parsed.entries[0].password, "pw");

        let safari = "Title,URL,Username,Password,Notes,OTPAuth\nGitHub,https://github.com,octo,pw,my notes,JBSWY3DP";
        let parsed = parse_import(safari).unwrap();
        assert_eq!(parsed.entries[0].totp, "JBSWY3DP");
        assert_eq!(parsed.entries[0].notes, "my notes");

        let proton = "name,url,username,password,note,totp\nGitHub,https://github.com,octo,pw,note,JBSWY3DP";
        let parsed = parse_import(proton).unwrap();
        assert_eq!(parsed.entries[0].notes, "note");

        // A CSV with none of the credential columns is refused, not imported
        // as a pile of empty logins.
        let contacts = "first_name,last_name,email\nAda,Lovelace,ada@example.com";
        assert!(parse_import(contacts).is_err());
    }

    #[test]
    fn keepass_csv_group_becomes_a_folder_path() {
        let data = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\
                    \"Email/Personal\",\"Fastmail\",\"ada\",\"pw\",\"https://fastmail.com\",\"\",\"\"\n\
                    \"\",\"Loose\",\"bob\",\"pw2\",\"https://example.com\",\"\",\"\"";
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.source, "KeePass/KeePassXC CSV");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].folder.as_deref(), Some("Email/Personal"));
        assert!(parsed.entries[1].folder.is_none());
    }

    #[test]
    fn quoted_csv_with_embedded_quotes_and_commas_parses() {
        // RFC 4180 escaping: quotes inside a quoted field are doubled, and
        // commas/newlines inside quotes stay within the field.
        let data = "name,url,username,password,notes\n\
                    \"Acme, Inc.\",https://acme.com,ada,\"p\"\"w\",\"a \"\"quoted\"\" note\"";
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.entries[0].name, "Acme, Inc.");
        assert_eq!(parsed.entries[0].password, "p\"w");
        assert_eq!(parsed.entries[0].notes, "a \"quoted\" note");
    }

    #[test]
    fn onepassword_1pif_parses_logins_and_skips_others() {
        let data = "***8a1b***8\n\
                    {\"uuid\":\"1\",\"typeName\":\"system.folder.Group\",\"title\":\"Email\"}\n\
                    {\"uuid\":\"2\",\"typeName\":\"passwords.Login\",\"title\":\"GitHub\",\
                     \"location\":\"https://github.com\",\
                     \"fields\":[{\"designation\":\"username\",\"name\":\"username\",\"value\":\"octo\"},\
                                {\"designation\":\"password\",\"name\":\"password\",\"value\":\"hunter2\"}]}\n\
                    {\"uuid\":\"3\",\"typeName\":\"passwords.Login\",\"title\":\"No location\",\
                     \"fields\":[{\"name\":\"email\",\"value\":\"a@b.c\"},{\"designation\":\"password\",\"value\":\"p2\"}]}\n\
                    {\"uuid\":\"4\",\"typeName\":\"wallet.com.apple.CreditCard\",\"title\":\"Visa\"}";
        let parsed = parse_1pif(data).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.skipped_unsupported, 1); // credit card; the folder is metadata
        assert_eq!(parsed.entries[0].url, "https://github.com");
        assert_eq!(parsed.entries[0].username, "octo");
        assert_eq!(parsed.entries[0].password, "hunter2");
        assert_eq!(parsed.entries[1].username, "a@b.c");
    }

    #[test]
    fn legacy_vela_json_still_imports() {
        let data = r#"{
            "version": 1,
            "timestamp": "2025-01-01T00:00:00Z",
            "user_id": "dev",
            "passwords": [
                { "id": "a", "username": "octo", "password": "pw", "app_id": null,
                  "description": "note", "url": "github.com", "otp": null }
            ]
        }"#;
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.source, "VELA JSON");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].totp, "");
        assert_eq!(parsed.entries[0].notes, "note");
    }

    #[test]
    fn bitwarden_cards_identities_fields_and_extra_urls_survive() {
        let data = r#"{
            "encrypted": false,
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [
                { "type": 3, "name": "Visa", "favorite": true, "folderId": "f1",
                  "card": { "cardholderName": "Alex", "number": "4111111111111111",
                            "expMonth": "08", "expYear": "2029", "code": "123", "brand": "Visa" },
                  "fields": [{ "name": "PIN", "value": "4321", "type": 1 }] },
                { "type": 4, "name": "Alex Demo",
                  "identity": { "firstName": "Alex", "lastName": "Demo", "email": "a@b.c",
                                "phone": "+1", "address1": "1 Test St", "city": "X",
                                "state": "Y", "postalCode": "123", "country": "US" } },
                { "type": 1, "name": "GitHub",
                  "login": { "username": "octo", "password": "pw",
                             "uris": [{ "uri": "https://github.com" },
                                      { "uri": "https://gist.github.com" }] },
                  "fields": [{ "name": "Recovery", "value": "R-1", "type": 0 },
                             { "name": "Hidden", "value": "H", "type": 1 },
                             { "name": "Flag", "value": "true", "type": 2 }] }
            ]
        }"#;
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.source, "Bitwarden JSON");
        assert!(parsed.unsupported.contains_key("card brand"));

        let card = &parsed.entries[0];
        assert_eq!(card.kind, EntryKind::Card);
        assert!(card.favorite);
        assert_eq!(card.folder.as_deref(), Some("Work"));
        assert_eq!(card.card.number, "4111111111111111");
        assert_eq!(card.card.expiry, "08/2029");
        assert_eq!(card.fields.len(), 1);
        assert_eq!(card.fields[0].kind, FieldKind::Concealed);

        let identity = &parsed.entries[1];
        assert_eq!(identity.kind, EntryKind::Identity);
        assert_eq!(identity.identity.email, "a@b.c");
        assert_eq!(identity.identity.addresses.len(), 1);
        assert_eq!(identity.identity.addresses[0].line1, "1 Test St");

        let login = &parsed.entries[2];
        assert_eq!(login.extra_urls, vec!["https://gist.github.com"]);
        assert_eq!(login.fields.len(), 3);
        assert_eq!(login.fields[1].kind, FieldKind::Concealed);
        assert_eq!(login.fields[2].kind, FieldKind::Boolean);
    }

    #[test]
    fn one_password_1pux_reads_logins_cards_identities_and_tags() {
        use std::io::Write;
        let export = serde_json::json!({
            "accounts": [{
                "vaults": [{
                    "attrs": { "name": "Personal" },
                    "items": [
                        {
                            "typeName": "Login", "title": "GitHub", "tags": ["dev"],
                            "overview": { "URLs": [{ "url": "https://github.com" }] },
                            "details": {
                                "loginFields": [
                                    { "designation": "username", "value": "octo" },
                                    { "designation": "password", "value": "pw" }
                                ],
                                "sections": [{ "title": "Extra", "fields": [
                                    { "title": "Recovery", "value": { "string": "R-1" } },
                                    { "title": "Secret", "value": { "concealed": "S" } },
                                    { "title": "Attachment", "value": { "file": {
                                        "fileName": "notes.txt", "documentId": "doc-1",
                                        "contentType": "text/plain"
                                    } } }
                                ] }]
                            }
                        },
                        {
                            "typeName": "CreditCard", "title": "Visa",
                            "details": { "sections": [{ "title": "Card", "fields": [
                                { "title": "number", "value": { "string": "4111" } },
                                { "title": "cardholder name", "value": { "string": "Alex" } },
                                { "title": "expiry date", "value": { "monthYear": "08/2029" } },
                                { "title": "cvv", "value": { "concealed": "123" } }
                            ] }] }
                        },
                        {
                            "typeName": "Identity", "title": "Me",
                            "details": { "sections": [{ "title": "Identity", "fields": [
                                { "title": "first name", "value": { "string": "Alex" } },
                                { "title": "last name", "value": { "string": "Demo" } },
                                { "title": "email", "value": { "email": "a@b.c" } },
                                { "title": "address", "value": { "address": {
                                    "street": "1 Test St", "city": "X", "zip": "123", "country": "US"
                                } } }
                            ] }] }
                        }
                    ]
                }]
            }]
        });
        let mut bytes = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
            writer.start_file("export.data", zip::write::SimpleFileOptions::default()).unwrap();
            writer.write_all(export.to_string().as_bytes()).unwrap();
            writer.start_file("files/doc-1", zip::write::SimpleFileOptions::default()).unwrap();
            writer.write_all(b"attachment body").unwrap();
            writer.finish().unwrap();
        }
        let parsed = parse_import_bytes(&bytes).unwrap();
        assert_eq!(parsed.source, "1Password (.1pux)");
        assert_eq!(parsed.entries.len(), 3);

        let login = &parsed.entries[0];
        assert_eq!(login.url, "https://github.com");
        assert_eq!(login.username, "octo");
        assert_eq!(login.folder.as_deref(), Some("Personal"));
        assert_eq!(login.tags, vec!["dev"]);
        assert_eq!(login.fields.len(), 2);
        assert_eq!(login.fields[1].kind, FieldKind::Concealed);
        assert_eq!(login.attachments.len(), 1);
        assert_eq!(login.attachments[0].file_name, "notes.txt");
        assert_eq!(login.attachments[0].bytes, b"attachment body");
        let note = encode_attachment_note(
            &login.attachments[0].file_name,
            &login.attachments[0].mime,
            &login.attachments[0].bytes,
        );
        assert!(note.starts_with("VELA IMPORTED ATTACHMENT"));
        assert!(note.contains("Encoding: base64"));

        let card = &parsed.entries[1];
        assert_eq!(card.kind, EntryKind::Card);
        assert_eq!(card.card.number, "4111");
        assert_eq!(card.card.expiry, "08/2029");
        assert_eq!(card.card.cvv, "123");

        let identity = &parsed.entries[2];
        assert_eq!(identity.identity.first, "Alex");
        assert_eq!(identity.identity.email, "a@b.c");
        assert_eq!(identity.identity.addresses[0].line1, "1 Test St, X, 123, US");
    }

    #[test]
    fn a_1pux_zip_is_named_as_such() {
        let err = parse_import("PK\u{3}\u{4}binary-ish").unwrap_err();
        assert!(err.contains("1pux"), "{err}");
    }
}
