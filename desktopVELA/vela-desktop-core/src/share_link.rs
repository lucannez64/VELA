//! One-off share links to recipients who do not use VELA.
//!
//! The client seals the selected item under a random 256-bit link key (plus an
//! optional Argon2id-stretched passphrase), uploads only the ciphertext, and
//! hands out `…/send.html?id=<id>#<key>`. The key lives in the URL fragment, so
//! the server never sees it. The owner's copy of each link — including the key —
//! is kept in an encrypted local file so the URL can be re-copied later; it is
//! never sent to the server.

use base64::{engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::ApiClient;
use crate::audit::{record_audit_event, AuditAction};
use crate::vault::VaultItem;
use crate::AppState;

const SHARE_LINKS_FILE: &str = "share_links.enc";

/// The sealed payload the recipient page renders. Versioned so the page can
/// evolve; unknown fields are ignored there.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LinkSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<vela_core::rich_items::CustomField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_urls: Option<Vec<vela_core::rich_items::AdditionalUrl>>,
    pub v: u32,
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLinkRecord {
    pub id: String,
    pub item_id: String,
    pub item_name: String,
    /// Full URL including the fragment key. Stored encrypted, never uploaded.
    pub url: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub has_passphrase: bool,
    pub view_once: bool,
    #[serde(default)]
    pub max_views: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ShareLinkStore {
    links: Vec<ShareLinkRecord>,
}

fn load_store(state: &AppState) -> ShareLinkStore {
    let crypto = state.crypto.read();
    let Some(crypto) = crypto.as_ref() else {
        return ShareLinkStore::default();
    };
    let path = state.store.store_path().join(SHARE_LINKS_FILE);
    if !path.exists() {
        return ShareLinkStore::default();
    }
    let Ok(ciphertext) = std::fs::read(&path) else {
        return ShareLinkStore::default();
    };
    let Ok(plaintext) = crypto.decrypt_vault(&ciphertext) else {
        return ShareLinkStore::default();
    };
    serde_json::from_slice(&plaintext).unwrap_or_default()
}

fn save_store(state: &AppState, store: &ShareLinkStore) -> Result<(), String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Vault is locked")?;
    let plaintext = serde_json::to_vec(store).map_err(|e| e.to_string())?;
    let ciphertext = crypto.encrypt_vault(&plaintext).map_err(|e| e.to_string())?;
    let path = state.store.store_path().join(SHARE_LINKS_FILE);
    std::fs::write(path, ciphertext).map_err(|e| e.to_string())?;
    Ok(())
}

/// Normalize a vault item into the payload the recipient page understands.
fn link_secret_for(item: &VaultItem) -> Result<LinkSecret, String> {
    match item {
        VaultItem::Login {
            meta,
            url,
            username,
            pass,
            totp,
            ..
        } => Ok(LinkSecret {
            custom_fields: meta.rich.custom_fields.clone(),
            additional_urls: meta.rich.additional_urls.clone(),
            v: 1,
            kind: "login".to_string(),
            name: if meta.name.is_empty() {
                url.clone()
            } else {
                meta.name.clone()
            },
            username: non_empty(username),
            password: non_empty(pass),
            url: non_empty(url),
            notes: meta.notes.clone().and_then(|n| non_empty(&n)),
            totp: totp.clone().and_then(|t| non_empty(&t)),
        }),
        VaultItem::SecureNote {
            meta, title, content, ..
        } => Ok(LinkSecret {
            custom_fields: meta.rich.custom_fields.clone(),
            additional_urls: meta.rich.additional_urls.clone(),
            v: 1,
            kind: "note".to_string(),
            name: if !title.is_empty() {
                title.clone()
            } else {
                meta.name.clone()
            },
            username: None,
            password: None,
            url: None,
            notes: non_empty(content),
            totp: None,
        }),
        _ => Err("Only logins and secure notes can be shared as a link".to_string()),
    }
}

fn non_empty(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateShareLinkRequest {
    pub item_id: String,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default)]
    pub max_views: Option<i64>,
    #[serde(default)]
    pub view_once: bool,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareLinkCreated {
    pub id: String,
    pub url: String,
    pub expires_at: DateTime<Utc>,
    pub has_passphrase: bool,
    pub view_once: bool,
    pub max_views: Option<i64>,
}

pub async fn create_share_link(
    state: &AppState,
    req: CreateShareLinkRequest,
) -> Result<ShareLinkCreated, String> {
    let token = state
        .get_session_token()
        .ok_or_else(|| "Unlock and sign in to create a share link".to_string())?;

    let base = state.server_url.read().trim_end_matches('/').to_string();
    if base.is_empty() {
        return Err("Set a server URL before creating a share link".to_string());
    }

    // Seal under the vault lock, then drop it before any network call.
    let (item_name, ciphertext_b64, salt_b64, link_key_b64, has_passphrase) = {
        let vault = state.vault.read();
        let item = vault
            .get_item(&req.item_id)
            .ok_or_else(|| "Item not found".to_string())?;
        if item.is_received_share() {
            return Err("Cannot share a received copy".to_string());
        }
        let secret = link_secret_for(item)?;
        let payload = serde_json::to_vec(&secret).map_err(|e| e.to_string())?;

        let passphrase = req
            .passphrase
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty());
        let salt = vela_crypto::link::generate_salt();
        let link_key = vela_crypto::link::generate_link_key();
        let ciphertext = vela_crypto::link::seal_link(
            &link_key,
            passphrase.map(|p| p.as_bytes()),
            &salt,
            &payload,
        )
        .map_err(|e| format!("Failed to seal the share link: {e}"))?;

        (
            secret.name,
            B64.encode(&ciphertext),
            B64.encode(salt),
            URL_SAFE_NO_PAD.encode(link_key),
            passphrase.is_some(),
        )
    };

    let body = serde_json::json!({
        "ciphertext": ciphertext_b64,
        "ttl_secs": req.ttl_secs,
        "max_views": req.max_views,
        "view_once": req.view_once,
        "has_passphrase": has_passphrase,
        "kdf_salt": if has_passphrase { Some(salt_b64) } else { None },
        "label": req.label.clone().filter(|l| !l.trim().is_empty()),
    });

    let client = ApiClient::with_url(base.clone());
    let (id, expires_at, new_token) = client
        .create_send(&token, &body)
        .await
        .map_err(|e| format!("Failed to create the share link: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }
    let expires_at = DateTime::parse_from_rfc3339(&expires_at)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| "Server returned an invalid expiry".to_string())?;

    let url = format!("{base}/send.html?id={id}#{link_key_b64}");
    let record = ShareLinkRecord {
        id: id.clone(),
        item_id: req.item_id.clone(),
        item_name,
        url: url.clone(),
        created_at: Utc::now(),
        expires_at,
        has_passphrase,
        view_once: req.view_once,
        max_views: req.max_views,
    };
    let mut store = load_store(state);
    store.links.retain(|link| link.id != id);
    store.links.insert(0, record);
    save_store(state, &store)?;

    record_audit_event(
        state,
        AuditAction::ShareLinkCreated {
            has_passphrase,
            view_once: req.view_once,
        },
    );

    Ok(ShareLinkCreated {
        id,
        url,
        expires_at,
        has_passphrase,
        view_once: req.view_once,
        max_views: req.max_views,
    })
}

pub fn list_share_links(state: &AppState) -> Result<Vec<ShareLinkRecord>, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut store = load_store(state);
    let now = Utc::now();
    // Hide links the server has already expired; they are unusable.
    store.links.retain(|link| link.expires_at > now);
    Ok(store.links)
}

pub async fn revoke_share_link(state: &AppState, link_id: &str) -> Result<(), String> {
    let token = state
        .get_session_token()
        .ok_or_else(|| "Unlock and sign in to revoke a share link".to_string())?;

    let base = state.server_url.read().trim_end_matches('/').to_string();
    if !base.is_empty() {
        let client = ApiClient::with_url(base);
        match client.delete_send(&token, link_id).await {
            Ok(new_token) => {
                if let Some(t) = new_token {
                    state.session.write().set_server_token(t);
                }
            }
            // A link the server already dropped (expired) is still revoked
            // locally; the end state is the same.
            Err(e) => {
                tracing::warn!(link_id, error = %e, "revoke share link: server delete failed");
            }
        }
    }

    let mut store = load_store(state);
    store.links.retain(|link| link.id != link_id);
    save_store(state, &store)?;

    record_audit_event(
        state,
        AuditAction::ShareLinkRevoked {
            link_id: link_id.to_string(),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{VaultItem, VaultMeta};

    fn login(name: &str) -> VaultItem {
        VaultItem::Login {
            meta: VaultMeta {
                rich: Default::default(),
                id: "id-1".into(),
                name: name.into(),
                notes: Some("note".into()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            url: "https://github.com".into(),
            username: "octo".into(),
            pass: "hunter2".into(),
            totp: Some("GEZDGNBVGY3TQOJQ".into()),
            app_ids: vec![],
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        }
    }

    #[test]
    fn link_secret_maps_login_fields() {
        let secret = link_secret_for(&login("GitHub")).unwrap();
        assert_eq!(secret.kind, "login");
        assert_eq!(secret.name, "GitHub");
        assert_eq!(secret.username.as_deref(), Some("octo"));
        assert_eq!(secret.password.as_deref(), Some("hunter2"));
        assert_eq!(secret.url.as_deref(), Some("https://github.com"));
        assert_eq!(secret.notes.as_deref(), Some("note"));
        assert_eq!(secret.totp.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
    }

    #[test]
    fn link_secret_rejects_unsupported_types() {
        let card = VaultItem::CreditCard {
            meta: VaultMeta {
                rich: Default::default(),
                id: "c".into(),
                name: "Visa".into(),
                notes: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            number: "4111".into(),
            exp: "01/30".into(),
            cvv: "123".into(),
            pin: None,
            cardholder_name: None,
        };
        assert!(link_secret_for(&card).is_err());
    }

    #[test]
    fn sealed_payload_roundtrips_through_the_link_crypto() {
        let secret = link_secret_for(&login("GitHub")).unwrap();
        let payload = serde_json::to_vec(&secret).unwrap();
        let key = vela_crypto::link::generate_link_key();
        let salt = vela_crypto::link::generate_salt();

        let blob = vela_crypto::link::seal_link(&key, Some(b"pw"), &salt, &payload).unwrap();
        let opened = vela_crypto::link::open_link(&key, Some(b"pw"), &salt, &blob).unwrap();
        let decoded: LinkSecret = serde_json::from_slice(&opened).unwrap();
        assert_eq!(decoded, secret);
    }
}
