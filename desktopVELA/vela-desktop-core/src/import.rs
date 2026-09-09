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

/// What a parsed row becomes. Logins and secure notes exist in every source;
/// cards and identities are deliberately out of scope (they are counted and
/// reported, not silently dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Login,
    Note,
}

/// One normalized row from any source.
#[derive(Debug, Clone)]
pub struct ImportedEntry {
    pub name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp: String,
    pub kind: EntryKind,
}

/// Parse output before vault mapping: the entries plus a count of rows that
/// were recognized but deliberately not imported (cards, identities, …).
#[derive(Debug, Default)]
pub struct ParsedImport {
    pub entries: Vec<ImportedEntry>,
    pub skipped_unsupported: u32,
    pub source: &'static str,
}

impl ParsedImport {
    fn empty(source: &'static str) -> Self {
        ParsedImport { entries: Vec::new(), skipped_unsupported: 0, source }
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
             Export as CSV from 1Password and import that instead."
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
    // the folder's name and keep it in the notes, or organization is lost.
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
        let folder_note = item
            .get("folderId")
            .and_then(Value::as_str)
            .and_then(|id| folder_names.get(id))
            .map(|f| format!("Folder: {f}\n"))
            .unwrap_or_default();

        match item.get("type").and_then(Value::as_i64) {
            Some(1) => {
                let login = item.get("login").cloned().unwrap_or(Value::Null);
                parsed.entries.push(ImportedEntry {
                    name: name.clone(),
                    url: first_uri(&login),
                    username: login.get("username").and_then(Value::as_str).unwrap_or("").into(),
                    password: login.get("password").and_then(Value::as_str).unwrap_or("").into(),
                    notes: format!("{folder_note}{notes}"),
                    totp: login.get("totp").and_then(Value::as_str).unwrap_or("").into(),
                    kind: EntryKind::Login,
                });
            }
            Some(2) => {
                parsed.entries.push(ImportedEntry {
                    name,
                    url: String::new(),
                    username: String::new(),
                    password: String::new(),
                    notes: format!("{folder_note}{notes}"),
                    totp: String::new(),
                    kind: EntryKind::Note,
                });
            }
            _ => parsed.skipped_unsupported += 1, // card (3), identity (4)
        }
    }
    Ok(parsed)
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
    let item_type = item.get("type").and_then(Value::as_str).unwrap_or("login");
    let name = item
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .or_else(|| item.get("name").and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string();
    let notes = item
        .get("metadata")
        .and_then(|m| m.get("note"))
        .and_then(Value::as_str)
        .or_else(|| item.get("note").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    let vault_note = if vault_name.is_empty() {
        String::new()
    } else {
        format!("Vault: {vault_name}\n")
    };

    match item_type {
        "login" | "alias" => {
            let username = item
                .get("username")
                .and_then(Value::as_str)
                .or_else(|| item.get("aliasEmail").and_then(Value::as_str))
                .unwrap_or("");
            let url = item
                .get("itemUrl")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    item.get("urls").and_then(Value::as_array).and_then(|urls| {
                        urls.first().map(|u| match u {
                            Value::String(s) => s.clone(),
                            other => other
                                .get("referrer")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                        })
                    })
                })
                .unwrap_or_default();
            // Aliases have no password of their own; an empty password keeps
            // the address importable rather than dropping it.
            parsed.entries.push(ImportedEntry {
                name,
                url,
                username: username.into(),
                password: item.get("password").and_then(Value::as_str).unwrap_or("").into(),
                notes: format!("{vault_note}{notes}"),
                totp: item.get("totp").and_then(Value::as_str).unwrap_or("").into(),
                kind: EntryKind::Login,
            });
        }
        "note" => {
            parsed.entries.push(ImportedEntry {
                name,
                url: String::new(),
                username: String::new(),
                password: String::new(),
                notes: format!("{vault_note}{}", item.get("note").and_then(Value::as_str).unwrap_or(notes.as_str())),
                totp: String::new(),
                kind: EntryKind::Note,
            });
        }
        _ => parsed.skipped_unsupported += 1, // credit_card, identity, ssh_key, …
    }
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
const COL_COUNT: usize = 8;

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
        // cards and identities are counted so the user sees they were not
        // silently swallowed.
        let row_type = cell(COL_TYPE).to_lowercase();
        if row_type == "card" || row_type == "identity" {
            parsed.skipped_unsupported += 1;
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

        if name.is_empty() && url.is_empty() && username.is_empty() && password.is_empty() {
            continue; // blank padding row, not data
        }

        // KeePass-family group paths ("Email/Personal") carry real structure;
        // keep them visible rather than flattening them away.
        let group_note = if group.is_empty() {
            String::new()
        } else {
            format!("Folder: {group}\n")
        };

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
            notes: format!("{group_note}{notes}"),
            totp,
            kind: if is_note { EntryKind::Note } else { EntryKind::Login },
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
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.skipped_unsupported, 1);

        let login = &parsed.entries[0];
        assert_eq!(login.kind, EntryKind::Login);
        assert_eq!(login.name, "GitHub");
        assert_eq!(login.username, "octocat");
        assert_eq!(login.password, "hunter2");
        assert_eq!(login.url, "https://github.com/login");
        assert_eq!(login.totp, "otpauth://totp/x");
        assert!(login.notes.contains("Folder: Work"));
        assert!(login.notes.contains("code hosting"));

        let note = &parsed.entries[1];
        assert_eq!(note.kind, EntryKind::Note);
        assert_eq!(note.notes, "abc-123");
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
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.skipped_unsupported, 1);
        assert_eq!(parsed.entries[0].url, "https://example.com");
        assert!(parsed.entries[0].notes.contains("Vault: Personal"));
        assert_eq!(parsed.entries[1].username, "news-abc@simplelogin.fr");
    }

    #[test]
    fn bitwarden_csv_maps_prefixed_columns_and_row_types() {
        let data = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                    ,,login,GitHub,,\"\",0,https://github.com,octo,hunter2,otpauth://x\n\
                    ,,note,Codes,abc,,0,,,\n\
                    ,,card,Visa,,,,,,,";
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.source, "Bitwarden CSV");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.skipped_unsupported, 1);
        let login = &parsed.entries[0];
        assert_eq!(login.url, "https://github.com");
        assert_eq!(login.username, "octo");
        assert_eq!(login.password, "hunter2");
        assert_eq!(login.totp, "otpauth://x");
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
    fn keepass_csv_group_lands_in_notes() {
        let data = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\
                    \"Email/Personal\",\"Fastmail\",\"ada\",\"pw\",\"https://fastmail.com\",\"\",\"\"\n\
                    \"\",\"Loose\",\"bob\",\"pw2\",\"https://example.com\",\"\",\"\"";
        let parsed = parse_import(data).unwrap();
        assert_eq!(parsed.source, "KeePass/KeePassXC CSV");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].notes, "Folder: Email/Personal\n");
        assert_eq!(parsed.entries[1].notes, "");
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
    fn a_1pux_zip_is_named_as_such() {
        let err = parse_import("PK\u{3}\u{4}binary-ish").unwrap_err();
        assert!(err.contains("1pux"), "{err}");
    }
}
