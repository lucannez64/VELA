//! Toolkit-agnostic core of `src-tauri/src/commands/vault.rs`'s breach-check
//! functions — real HaveIBeenPwned / Pwned-Passwords network calls. None of
//! these write to the vault themselves (the single-email "check & add" flow
//! in the UI separately calls the real `commands::vault::add_item` with the
//! result), so unlike most of this module's siblings there was no vault-
//! mutation reason to leave them stubbed — only inertia.

use serde::{Deserialize, Serialize};

use crate::commands::vault::require_unlocked;
use crate::vault::{BreachEntry, VaultItem};
use crate::AppState;

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

impl From<HibpBreach> for BreachEntry {
    fn from(h: HibpBreach) -> Self {
        BreachEntry {
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

/// Checks a single email against HaveIBeenPwned. Real network call.
pub async fn check_email_breach(email: &str) -> Result<Vec<BreachEntry>, String> {
    tracing::info!("Checking breaches for one account");

    let client = reqwest::Client::new();
    let api_key = std::env::var("HIBP_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        tracing::warn!("HIBP_API_KEY not set, using anonymous API");
    }

    let mut request = client.get(format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
        urlencoding::encode(email)
    ));
    if !api_key.is_empty() {
        request = request.header("hibp-api-key", &api_key);
    }
    request = request.header("User-Agent", "VELA-Desktop-App");

    match request.send().await {
        Ok(response) => match response.status().as_u16() {
            200 => {
                let breaches: Vec<HibpBreach> =
                    response.json().await.map_err(|e| format!("Failed to parse breach data: {e}"))?;
                tracing::info!("Found {} breaches", breaches.len());
                Ok(breaches.into_iter().map(Into::into).collect())
            }
            404 => {
                tracing::info!("No breaches found");
                Ok(vec![])
            }
            429 => Err("Rate limited by HaveIBeenPwned. Please try again later.".to_string()),
            status => Err(format!("HIBP API error: HTTP {status}")),
        },
        Err(e) => {
            tracing::error!("Failed to check breaches: {}", e);
            Err(format!("Network error: {e}"))
        }
    }
}

/// Checks every distinct login email in the vault against HIBP, rate-
/// limited to match HIBP's own free-tier limit. Real network calls, no
/// vault writes.
pub async fn check_all_vault_emails(state: &AppState) -> Result<u32, String> {
    require_unlocked(state)?;
    let emails: Vec<String> = {
        let vault = state.vault.read();
        let mut seen = std::collections::HashSet::new();
        vault
            .items
            .iter()
            .filter_map(|item| {
                if let VaultItem::Login { username, .. } = item {
                    if !username.is_empty() && username.contains('@') && seen.insert(username.clone()) {
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
        let mut request = client.get(format!(
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

#[derive(Debug, Clone, Serialize)]
pub struct PasswordBreachResult {
    pub breached: bool,
    pub count: u32,
    pub description: String,
}

/// SHA-1 of the password, uppercased, split into the k-anonymity prefix (the
/// only part that ever leaves the device) and the suffix matched locally
/// against the Pwned Passwords range response.
fn pwned_hash_parts(password: &str) -> (String, String) {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash_hex = hex::encode(hasher.finalize()).to_uppercase();
    let (prefix, suffix) = hash_hex.split_at(5);
    (prefix.to_string(), suffix.to_string())
}

/// Parse a Pwned Passwords range response (`HASH_SUFFIX:COUNT` lines) for our
/// suffix. Returns the breach count when the password appears in the corpus.
fn parse_pwned_range(body: &str, suffix: &str) -> Option<u32> {
    for line in body.lines() {
        if let Some((hash_suffix, count_str)) = line.split_once(':') {
            if hash_suffix == suffix {
                return Some(count_str.trim().parse().unwrap_or(0));
            }
        }
    }
    None
}

/// Checks one password against Pwned Passwords via k-anonymity — only the
/// first five hash characters leave the device, and the suffix match happens
/// here. Unlike [`check_all_vault_passwords`], which skips a failing lookup
/// and moves on, a single explicit check reports the failure: the caller
/// asked about one password and "no result" must not read as "not breached".
pub async fn check_password_breach(password: &str) -> Result<PasswordBreachResult, String> {
    let (prefix, suffix) = pwned_hash_parts(password);
    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

    let response = reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "VELA-Desktop-App")
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if response.status().as_u16() != 200 {
        return Err(format!("Pwned Passwords API error: HTTP {}", response.status().as_u16()));
    }

    let body = response.text().await.unwrap_or_default();
    Ok(match parse_pwned_range(&body, &suffix) {
        Some(count) => PasswordBreachResult {
            breached: true,
            count,
            description: format!(
                "This password has been exposed in {} data breaches. It appears {} times in breached password databases.",
                if count == 1 { "a" } else { "" },
                count
            ),
        },
        None => PasswordBreachResult {
            breached: false,
            count: 0,
            description: "This password has not been found in any known data breaches.".to_string(),
        },
    })
}

/// Checks every distinct vault password against Pwned Passwords via
/// k-anonymity (only the first 5 hash chars ever leave the device). Real
/// network calls, no vault writes.
pub async fn check_all_vault_passwords(state: &AppState) -> Result<Vec<PasswordBreachResult>, String> {
    require_unlocked(state)?;
    let passwords: Vec<(String, String)> = {
        let vault = state.vault.read();
        let mut seen = std::collections::HashSet::new();
        vault
            .items
            .iter()
            .filter_map(|item| {
                if let VaultItem::Login { pass, .. } = item {
                    if !pass.is_empty() && seen.insert(pass.clone()) {
                        return Some((item.name().to_string(), pass.clone()));
                    }
                }
                None
            })
            .collect()
    };

    let client = reqwest::Client::new();
    let mut results: Vec<PasswordBreachResult> = Vec::new();

    for (name, password) in passwords {
        let (prefix, suffix) = pwned_hash_parts(&password);

        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
        if let Ok(response) = client.get(&url).header("User-Agent", "VELA-Desktop-App").send().await {
            if response.status().as_u16() == 200 {
                let body = response.text().await.unwrap_or_default();
                match parse_pwned_range(&body, &suffix) {
                    Some(count) => {
                        let result = PasswordBreachResult {
                            breached: true,
                            count,
                            description: format!("Password for '{name}' found {count} times in breaches"),
                        };
                        tracing::info!("{}", result.description);
                        results.push(result);
                    }
                    None => {
                        results.push(PasswordBreachResult {
                            breached: false,
                            count: 0,
                            description: format!("Password for '{name}' is safe"),
                        });
                    }
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwned_hash_parts_splits_uppercase_sha1() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = pwned_hash_parts("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn parse_pwned_range_finds_suffix_and_count() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2\n";
        let (_prefix, suffix) = pwned_hash_parts("password");
        assert_eq!(parse_pwned_range(body, &suffix), Some(3861493));
    }

    #[test]
    fn parse_pwned_range_misses_unknown_suffix() {
        let body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:7";
        assert_eq!(parse_pwned_range(body, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"), None);
    }

    #[test]
    fn parse_pwned_range_tolerates_malformed_lines() {
        let body = "not-a-hash-line\n:5\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:notanumber\n";
        let (_prefix, suffix) = pwned_hash_parts("password");
        // Matching line with an unparseable count degrades to 0, not a panic.
        assert_eq!(parse_pwned_range(body, &suffix), Some(0));
    }

    #[test]
    fn hibp_json_deserializes_into_breach_entry() {
        let json = serde_json::json!({
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "Description": "In October 2013...",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": true,
            "IsFabricated": false,
            "IsSensitive": false,
            "IsRetired": false,
            "IsSpamList": false
        });
        let breach: HibpBreach = serde_json::from_value(json).unwrap();
        let entry: BreachEntry = breach.into();
        assert_eq!(entry.name, "Adobe");
        assert_eq!(entry.domain, "adobe.com");
        assert_eq!(entry.breach_date, "2013-10-04");
        assert_eq!(entry.data_classes, vec!["Email addresses", "Passwords"]);
        assert!(entry.is_verified);
        assert!(!entry.is_spam_list);
    }
}
