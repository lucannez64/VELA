//! Toolkit-agnostic core of `src-tauri/src/commands/sharing.rs` — the read
//! path (`get_shares`) plus `send_share`/`accept_share`/`decline_share`/
//! `delete_share`, all real account-level mutations now wired for real.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vela_crypto::{kem, share_envelope, signing};

use crate::api::ApiClient;
use crate::audit::{record_audit_event, AuditAction};
use crate::vault::VaultItem;
use crate::AppState;

const SHARES_FILE: &str = "shares.enc";
/// Revision of the first envelope of a share (share envelope v2).
const FIRST_REVISION: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub id: String,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    pub direction: ShareDirection,
    pub from: String,
    pub to: Option<String>,
    pub shared_at: DateTime<Utc>,
    pub accepted: Option<bool>,
    pub allow_edit: bool,
    pub encrypted_payload: Option<Vec<u8>>,
    #[serde(default)]
    pub recipient_share_ek: Option<String>,
    /// Sent shares: the lineage id signed into every envelope of this share.
    #[serde(default)]
    pub lineage_id: Option<String>,
    /// Sent shares: the last revision sealed (1 at first send).
    #[serde(default)]
    pub revision: u64,
    /// Received shares: the sender key, lineage and revision pinned when the
    /// share was accepted. Updates must match it (share envelope v2).
    #[serde(default)]
    pub pin: Option<StoredSharePin>,
    /// Received shares: fingerprint of the sending device's key, for the user
    /// to compare out of band. `None` when the envelope could not be verified.
    #[serde(default)]
    pub sender_fingerprint: Option<String>,
}

/// Serialized form of [`vela_crypto::share_envelope::SharePin`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredSharePin {
    pub sender_user_id: String,
    pub sender_vk_b64: String,
    pub lineage_id: String,
    pub revision: u64,
}

impl StoredSharePin {
    fn from_pin(pin: &share_envelope::SharePin) -> Self {
        Self {
            sender_user_id: pin.sender_user_id.clone(),
            sender_vk_b64: B64.encode(&pin.sender_vk),
            lineage_id: pin.lineage_id.clone(),
            revision: pin.revision,
        }
    }

    fn to_pin(&self) -> Option<share_envelope::SharePin> {
        Some(share_envelope::SharePin {
            sender_user_id: self.sender_user_id.clone(),
            sender_vk: B64.decode(&self.sender_vk_b64).ok()?,
            lineage_id: self.lineage_id.clone(),
            revision: self.revision,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ShareDirection {
    Received,
    Sent,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ShareStore {
    sent_shares: Vec<Share>,
    received_shares: Vec<Share>,
}

impl ShareStore {
    fn get_all_shares(&self) -> Vec<Share> {
        let mut all = Vec::with_capacity(self.sent_shares.len() + self.received_shares.len());
        all.extend(self.sent_shares.clone());
        all.extend(self.received_shares.clone());
        all.sort_by(|a, b| b.shared_at.cmp(&a.shared_at));
        all
    }

    fn add_sent_share(&mut self, share: Share) {
        self.sent_shares.push(share);
    }

    fn remove_share(&mut self, share_id: &str) {
        self.sent_shares.retain(|s| s.id != share_id);
        self.received_shares.retain(|s| s.id != share_id);
    }
}

fn load_share_store(state: &AppState) -> Option<ShareStore> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref()?;

    let shares_path = state.store.store_path().join(SHARES_FILE);
    if !shares_path.exists() {
        return Some(ShareStore::default());
    }

    let ciphertext = std::fs::read(&shares_path).ok()?;
    let plaintext = crypto.decrypt_vault(&ciphertext).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

fn save_share_store(state: &AppState, store: &ShareStore) -> Result<(), String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Crypto not initialized")?;

    let plaintext = serde_json::to_vec(store).map_err(|e| e.to_string())?;
    let ciphertext = crypto.encrypt_vault(&plaintext).map_err(|e| e.to_string())?;

    let shares_path = state.store.store_path().join(SHARES_FILE);
    std::fs::write(shares_path, ciphertext).map_err(|e| e.to_string())?;

    Ok(())
}

fn current_user_id(state: &AppState) -> String {
    {
        let session = state.session.read();
        if let Some(user_id) = session.get_user_id() {
            return user_id.to_string();
        }
    }
    state.store.load_user_id().unwrap_or_else(|_| "unknown".to_string())
}

/// Refreshes shares whose payload was updated after the initial send/accept
/// (e.g. the sender edited the item and re-sealed it for the recipient).
pub(crate) async fn refresh_linked_shares_inner(state: &AppState) -> Result<(), String> {
    let mut store = load_share_store(state).unwrap_or_default();
    let token = match state.get_session_token() {
        Some(token) => token,
        None => return Ok(()),
    };

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let (linked_items, new_tok) = client
        .get_linked_shares(&token)
        .await
        .map_err(|e| format!("Failed to fetch linked shares: {e}"))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }

    let user_id = current_user_id(state);

    for linked in linked_items {
        let payload = B64.decode(&linked.capsule).unwrap_or_default();
        if linked.sender_user_id == user_id {
            if let Some(existing) = store.sent_shares.iter_mut().find(|s| s.id == linked.id) {
                existing.encrypted_payload = Some(payload.clone());
                existing.shared_at = linked.updated_at.parse().unwrap_or_else(|_| Utc::now());
            }
        } else if linked.recipient_user_id == user_id {
            if let Some(existing) = store.received_shares.iter_mut().find(|s| s.id == linked.id) {
                existing.encrypted_payload = Some(payload.clone());
                existing.shared_at = linked.updated_at.parse().unwrap_or_else(|_| Utc::now());
            } else {
                let (item_name, item_type, sender_fingerprint) =
                    preview_received(state, &payload, &linked.sender_user_id);
                store.received_shares.push(Share {
                    id: linked.id.clone(),
                    item_id: linked.id.clone(),
                    item_name,
                    item_type,
                    direction: ShareDirection::Received,
                    from: linked.sender_user_id,
                    to: None,
                    shared_at: linked.updated_at.parse().unwrap_or_else(|_| Utc::now()),
                    accepted: None,
                    allow_edit: false,
                    encrypted_payload: Some(payload),
                    recipient_share_ek: None,
                    lineage_id: None,
                    revision: 0,
                    pin: None,
                    sender_fingerprint,
                });
            }
        }
    }

    sync_received_linked_items(state, &mut store)?;
    save_share_store(state, &store)?;
    Ok(())
}

fn load_identity(state: &AppState) -> Result<crate::store::IdentityKeysStore, String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Session not unlocked")?;
    state
        .store
        .load_identity_keys(crypto)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No identity keys found".to_string())
}

/// Open and verify a received envelope and run the admission policy.
fn admit_received(
    keys: &crate::store::IdentityKeysStore,
    capsule: &[u8],
    recipient_user_id: &str,
    attributed_sender_user_id: &str,
    pin: Option<&share_envelope::SharePin>,
) -> Result<share_envelope::AdmittedShare, String> {
    let share_dk = kem::HybridSecretKey::from_bytes(&keys.share_dk).map_err(|e| e.to_string())?;
    share_envelope::admit(
        &share_dk,
        capsule,
        share_envelope::AdmissionContext {
            recipient_user_id,
            attributed_sender_user_id,
            pin,
        },
    )
    .map_err(|e| e.to_string())
}

/// Name, type and sender fingerprint for a not-yet-accepted share. An
/// envelope that does not verify is listed, but cannot be accepted.
fn preview_received(
    state: &AppState,
    capsule: &[u8],
    attributed_sender_user_id: &str,
) -> (String, String, Option<String>) {
    let user_id = current_user_id(state);
    let admitted = load_identity(state)
        .and_then(|keys| admit_received(&keys, capsule, &user_id, attributed_sender_user_id, None));
    match admitted {
        Ok(admitted) => match serde_json::from_slice::<VaultItem>(&admitted.opened.item) {
            Ok(item) => (
                item.name().to_string(),
                format!("{:?}", item.item_type()).to_lowercase(),
                Some(vela_crypto::verification::signing_key_fingerprint(&admitted.pin.sender_vk)),
            ),
            Err(_) => ("Shared item".to_string(), "login".to_string(), None),
        },
        Err(e) => {
            tracing::warn!("Received share does not verify: {e}");
            ("Unverified share".to_string(), "login".to_string(), None)
        }
    }
}

/// Sign and seal `item_json` for one recipient (share envelope v2).
#[allow(clippy::too_many_arguments)]
fn seal_for_recipient(
    keys: &crate::store::IdentityKeysStore,
    sender_user_id: &str,
    sender_device_id: &str,
    recipient_user_id: &str,
    recipient_share_ek: &[u8],
    lineage_id: &str,
    revision: u64,
    item_json: &[u8],
) -> Result<Vec<u8>, String> {
    if keys.hybrid_sk.is_empty() {
        return Err("This device has no signing key and cannot share items. Re-enroll it to share.".into());
    }
    let signing_key = signing::HybridSigningKey::from_bytes(&keys.hybrid_sk).map_err(|e| e.to_string())?;
    let recipient = kem::HybridPublicKey::from_bytes(recipient_share_ek)
        .map_err(|_| "Invalid recipient share key".to_string())?;
    let header = share_envelope::ShareHeader {
        sender_user_id: sender_user_id.to_string(),
        sender_device_id: sender_device_id.to_string(),
        sender_vk: signing_key.verifying_key().to_bytes().to_vec(),
        recipient_user_id: recipient_user_id.to_string(),
        recipient_ek_digest: share_envelope::recipient_ek_digest(recipient_share_ek),
        lineage_id: lineage_id.to_string(),
        revision,
    };
    share_envelope::seal_signed_item(&signing_key, &header, &recipient, item_json)
        .map_err(|e| format!("Failed to seal share: {e}"))
}

/// Applies any accepted received shares whose sender re-sealed a newer
/// version onto the local vault (so an accepted share reflects edits made
/// after acceptance, without needing a separate "sync" action).
///
/// Only envelopes the admission policy accepts as an *update* are applied:
/// signed by the pinned sender key, in the pinned lineage, with a strictly
/// newer revision. Anything else — a capsule the server forged, replayed, or
/// re-attributed — is ignored. Shares accepted before envelope v2 have no pin
/// and are never updated; the sender has to share them again.
fn sync_received_linked_items(state: &AppState, store: &mut ShareStore) -> Result<(), String> {
    let keys = match load_identity(state) {
        Ok(keys) => keys,
        Err(_) => return Ok(()),
    };
    let user_id = current_user_id(state);

    let mut vault = state.vault.write();
    let mut changed = false;

    for share in store.received_shares.iter_mut().filter(|s| s.accepted == Some(true)) {
        let Some(payload) = &share.encrypted_payload else {
            continue;
        };
        let Some(pin) = share.pin.as_ref().and_then(StoredSharePin::to_pin) else {
            continue;
        };
        let admitted = match admit_received(&keys, payload, &user_id, &share.from, Some(&pin)) {
            Ok(admitted) => admitted,
            Err(e) => {
                // The capsule the server still holds for an accepted share is
                // normally the one already applied; only other rejections are
                // worth a warning.
                if !e.contains("not newer") {
                    tracing::warn!("Ignoring linked-share update for {}: {e}", share.id);
                }
                continue;
            }
        };
        let Ok(item) = serde_json::from_slice::<VaultItem>(&admitted.opened.item) else {
            continue;
        };
        if vault.get_item(&share.item_id).is_some() {
            let refreshed = item.with_id(share.item_id.clone()).with_shared_status(true, None);
            vault.update_item(refreshed);
            changed = true;
        }
        share.pin = Some(StoredSharePin::from_pin(&admitted.pin));
    }

    drop(vault);

    if changed {
        state.persist_current_vault().map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Real, read-only fetch of all shares (sent + received), merging the local
/// encrypted share store with the server's inbox/linked-shares state — the
/// same pipeline `src-tauri`'s `get_shares` command uses.
pub async fn get_shares(state: &AppState) -> Result<Vec<Share>, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let _ = refresh_linked_shares_inner(state).await;
    let mut store = load_share_store(state).unwrap_or_default();

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        match client.get_inbox(&token).await {
            Ok((inbox_items, new_tok)) => {
                if let Some(t) = new_tok {
                    state.session.write().set_server_token(t);
                }
                for inbox_item in inbox_items {
                    if store.received_shares.iter().any(|s| s.id == inbox_item.id) {
                        continue;
                    }
                    let capsule_bytes = B64.decode(&inbox_item.capsule).unwrap_or_default();
                    let (item_name, item_type, sender_fingerprint) =
                        preview_received(state, &capsule_bytes, &inbox_item.sender_user_id);
                    store.received_shares.push(Share {
                        id: inbox_item.id.clone(),
                        item_id: inbox_item.id.clone(),
                        item_name,
                        item_type,
                        direction: ShareDirection::Received,
                        from: inbox_item.sender_user_id,
                        to: None,
                        shared_at: inbox_item.created_at.parse().unwrap_or_else(|_| Utc::now()),
                        accepted: None,
                        allow_edit: false,
                        encrypted_payload: Some(capsule_bytes),
                        recipient_share_ek: None,
                        lineage_id: None,
                        revision: 0,
                        pin: None,
                        sender_fingerprint,
                    });
                }
                let _ = save_share_store(state, &store);
            }
            Err(e) => {
                tracing::warn!("Failed to fetch inbox from server (returning local shares): {}", e);
            }
        }
    }

    Ok(store.get_all_shares())
}

/// Re-encrypts and pushes an updated item to every recipient it's currently
/// shared with. Called from `update_item` — keeps a recipient's copy of a
/// shared item in sync when the owner edits it.
pub async fn push_sent_share_update_inner(
    state: &AppState,
    item: &crate::vault::VaultItem,
) -> Result<(), String> {
    let mut store = load_share_store(state).unwrap_or_default();

    let token = match state.get_session_token() {
        Some(token) => token,
        None => return Ok(()),
    };
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let item_json = serde_json::to_vec(&item.without_personal_organization()).map_err(|e| e.to_string())?;
    let keys = load_identity(state)?;
    let sender_user_id = current_user_id(state);
    let sender_device_id = state.store.load_device_id().map_err(|e| e.to_string())?;

    let shares_for_item: Vec<usize> = store
        .sent_shares
        .iter()
        .enumerate()
        .filter(|(_, s)| s.item_id == item.id())
        .map(|(i, _)| i)
        .collect();

    for idx in shares_for_item {
        let share = &store.sent_shares[idx];
        let Some(recipient_share_ek_b64) = &share.recipient_share_ek else {
            continue;
        };
        let (Some(recipient_user_id), Some(lineage_id)) = (&share.to, &share.lineage_id) else {
            // Sent before share envelope v2: the recipient will not accept an
            // update to it. The user has to share the item again.
            continue;
        };
        let recipient_share_ek = B64
            .decode(recipient_share_ek_b64.as_bytes())
            .map_err(|e| e.to_string())?;
        let revision = share.revision.checked_add(1).ok_or("share revision overflow")?;
        let capsule = seal_for_recipient(
            &keys,
            &sender_user_id,
            &sender_device_id,
            recipient_user_id,
            &recipient_share_ek,
            lineage_id,
            revision,
            &item_json,
        )?;
        let capsule_b64 = B64.encode(&capsule);

        let share_id = share.id.clone();
        let new_tok = client
            .update_linked_share(&token, &share_id, &capsule_b64)
            .await
            .map_err(|e| format!("Failed to update linked share: {e}"))?;
        if let Some(t) = new_tok {
            state.session.write().set_server_token(t);
        }

        let share = &mut store.sent_shares[idx];
        share.encrypted_payload = Some(capsule);
        share.revision = revision;
        share.shared_at = Utc::now();
    }

    save_share_store(state, &store)?;
    Ok(())
}

/// Sends a real share of `item_id` to `recipient` (a VELA user ID) — fetches
/// their share public key from the server, seals the item with it (real
/// KEM), and delivers it.
pub async fn send_share(
    state: &AppState,
    item_id: &str,
    recipient: &str,
    allow_edit: bool,
) -> Result<Share, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let (item_json, device_id) = {
        let vault = state.vault.read();
        let item = vault.get_item(item_id).ok_or("Item not found")?.clone();
        // Guard the exact snapshot being serialized, under the same read lock.
        // A passkey's private key must never enter a share capsule.
        if matches!(item, VaultItem::Passkey { .. }) {
            return Err("Passkeys cannot be shared".to_string());
        }
        drop(vault);
        let item_json = serde_json::to_vec(&item.without_personal_organization()).map_err(|e| e.to_string())?;
        let device_id = state.store.load_device_id().unwrap_or_else(|_| "unknown".to_string());
        (item_json, device_id)
    };

    let token = state
        .get_session_token()
        .ok_or("Not authenticated — please unlock your vault and try again.")?;
    let item: VaultItem = serde_json::from_slice(&item_json).map_err(|e| e.to_string())?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let recipient_share_ek_b64 = client
        .get_recipient_share_ek(&token, recipient)
        .await
        .map_err(|e| format!("Could not fetch recipient share key: {e}. Check the recipient's user ID."))?;

    let recipient_share_ek =
        B64.decode(recipient_share_ek_b64.as_bytes()).map_err(|_| "Invalid recipient share key encoding")?;
    let keys = load_identity(state)?;
    let lineage_id = Uuid::new_v4().to_string();
    let capsule = seal_for_recipient(
        &keys,
        &current_user_id(state),
        &device_id,
        recipient,
        &recipient_share_ek,
        &lineage_id,
        FIRST_REVISION,
        &item_json,
    )?;

    let mut share = Share {
        id: String::new(),
        item_id: item_id.to_string(),
        item_name: item.name().to_string(),
        item_type: format!("{:?}", item.item_type()).to_lowercase(),
        direction: ShareDirection::Sent,
        from: format!("user-{}", &device_id[..device_id.len().min(8)]),
        to: Some(recipient.to_string()),
        shared_at: Utc::now(),
        accepted: None,
        allow_edit,
        encrypted_payload: Some(capsule.clone()),
        recipient_share_ek: Some(recipient_share_ek_b64),
        lineage_id: Some(lineage_id),
        revision: FIRST_REVISION,
        pin: None,
        sender_fingerprint: None,
    };

    let mut store = load_share_store(state).unwrap_or_default();
    let capsule_b64 = B64.encode(&capsule);

    let (resp, new_tok) = client
        .send_share(&token, recipient, &capsule_b64)
        .await
        .map_err(|e| format!("Could not deliver share: {e}. Check the recipient's user ID."))?;
    if let Some(t) = new_tok {
        state.session.write().set_server_token(t);
    }
    share.id = resp.share_id;

    {
        let mut vault = state.vault.write();
        if let Some(existing) = vault.get_item(item_id).cloned() {
            let marked = existing.with_shared_status(true, Some(recipient.to_string()));
            vault.update_item(marked);
        }
    }
    let _ = state.persist_current_vault();

    store.add_sent_share(share.clone());
    save_share_store(state, &store)?;

    record_audit_event(state, AuditAction::ShareSent { recipient_user_id: recipient.to_string() });
    tracing::info!("Share sent: {} to {}", share.item_name, recipient);

    Ok(share)
}

/// Accepts a received share for real — decrypts the sealed item with our
/// own share private key and adds it to the vault as a new, distinct item.
pub async fn accept_share(state: &AppState, share_id: &str) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut store = load_share_store(state).ok_or("Failed to load share store")?;
    let mut received_item_id: Option<String> = None;

    let share = store
        .received_shares
        .iter()
        .find(|s| s.id == share_id)
        .ok_or("Share not found")?
        .clone();

    let mut pin = None;
    if let Some(capsule) = &share.encrypted_payload {
        let keys = load_identity(state)?;
        let admitted = admit_received(&keys, capsule, &current_user_id(state), &share.from, None)
            .map_err(|e| format!("This share cannot be verified and was not added: {e}"))?;
        let item: VaultItem = serde_json::from_slice(&admitted.opened.item).map_err(|e| e.to_string())?;
        if matches!(item, VaultItem::Passkey { .. }) {
            return Err("Passkeys cannot be shared".to_string());
        }

        // Always give the received copy a fresh ID so it is a distinct vault
        // item, even when the sender and recipient are the same user.
        let received_item = item.with_id(Uuid::new_v4().to_string()).with_shared_status(true, None);
        received_item_id = Some(received_item.id().to_string());
        {
            let mut vault = state.vault.write();
            vault.add_item(received_item);
        }
        state.persist_current_vault().map_err(|e| e.to_string())?;
        pin = Some(StoredSharePin::from_pin(&admitted.pin));
    }

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        if let Ok(new_tok) = client.delete_inbox_item(&token, share_id).await {
            if let Some(t) = new_tok {
                state.session.write().set_server_token(t);
            }
        }
    }

    if let Some(existing) = store.received_shares.iter_mut().find(|s| s.id == share_id) {
        existing.accepted = Some(true);
        existing.pin = pin;
        if let Some(item_id) = received_item_id {
            existing.item_id = item_id;
        }
    }
    save_share_store(state, &store)?;
    record_audit_event(state, AuditAction::ShareReceived { sender_user_id: share.from.clone() });
    tracing::info!("Share accepted: {}", share_id);

    Ok(())
}

/// Declines a received share for real — removes it from the server inbox
/// and the local share store without ever adding it to the vault.
pub async fn decline_share(state: &AppState, share_id: &str) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut store = load_share_store(state).ok_or("Failed to load share store")?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        if let Ok(new_tok) = client.delete_inbox_item(&token, share_id).await {
            if let Some(t) = new_tok {
                state.session.write().set_server_token(t);
            }
        }
    }

    store.remove_share(share_id);
    save_share_store(state, &store)?;
    tracing::info!("Share declined: {}", share_id);

    Ok(())
}

/// Deletes/revokes a share for real. For a sent share, this also clears the
/// `shared` flag on the original vault item and removes the recipient's
/// copy from their inbox. For a received share, just removes the local
/// record (the item itself, already added to the vault on accept, stays).
pub async fn delete_share(state: &AppState, share_id: &str) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut store = load_share_store(state).ok_or("Failed to load share store")?;

    let is_received = store.received_shares.iter().any(|s| s.id == share_id);
    if is_received {
        let server_url = state.server_url.read().clone();
        let client = ApiClient::with_url(server_url);
        if let Some(token) = state.get_session_token() {
            match client.delete_inbox_item(&token, share_id).await {
                Ok(new_tok) => {
                    if let Some(t) = new_tok {
                        state.session.write().set_server_token(t);
                    }
                }
                Err(e) => tracing::warn!("Failed to delete inbox item on server: {}", e),
            }
        }
    } else if let Some(sent) = store.sent_shares.iter().find(|s| s.id == share_id).cloned() {
        let server_url = state.server_url.read().clone();
        let client = ApiClient::with_url(server_url);
        if let Some(token) = state.get_session_token() {
            match client.delete_linked_share(&token, share_id).await {
                Ok(new_tok) => {
                    if let Some(t) = new_tok {
                        state.session.write().set_server_token(t);
                    }
                }
                Err(e) => tracing::warn!("Failed to delete linked share on server: {}", e),
            }
        }

        let revoked_payload = sent.encrypted_payload.clone();
        let device_id = {
            let session = state.session.read();
            session.get_device_id().map(|s| s.to_string())
        };

        let mut vault = state.vault.write();
        if let Some(existing) = vault.get_item(&sent.item_id).cloned() {
            let unmarked = existing.with_shared_status(false, None);
            vault.update_item(unmarked);
        }

        if let Some(received_index) =
            store.received_shares.iter().position(|s| s.accepted == Some(true) && s.encrypted_payload == revoked_payload)
        {
            let received_share = store.received_shares[received_index].clone();
            vault.delete_item(&received_share.item_id, device_id.as_deref());
            store.received_shares.remove(received_index);
        } else {
            store.received_shares.retain(|s| s.encrypted_payload != revoked_payload);
        }

        drop(vault);
        let _ = state.persist_current_vault();
    }

    store.remove_share(share_id);
    save_share_store(state, &store)?;
    tracing::info!("Share deleted: {}", share_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{VaultItem, VaultMeta};
    use chrono::Duration;

    fn meta(id: &str, name: &str, updated_at: DateTime<Utc>) -> VaultMeta {
        VaultMeta {
                rich: Default::default(),
            id: id.to_string(),
            name: name.to_string(),
            notes: None,
            created_at: updated_at,
            updated_at,
            last_modified_device: None,
            favorite: false,
            shared: true,
            share_recipient: None,
        }
    }

    fn login(id: &str, name: &str, pass: &str, updated_at: DateTime<Utc>) -> VaultItem {
        VaultItem::Login {
            meta: meta(id, name, updated_at),
            url: "https://example.com".into(),
            username: "ada".into(),
            pass: pass.into(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        }
    }

    fn identity() -> crate::store::IdentityKeysStore {
        let keys = crate::crypto::generate_identity_keypair().unwrap();
        crate::store::IdentityKeysStore {
            hybrid_ek: keys.hybrid_ek,
            hybrid_vk: keys.hybrid_vk,
            hybrid_sk: keys.hybrid_sk,
            share_ek: keys.share_ek,
            share_dk: keys.share_dk,
            hybrid_dk: keys.hybrid_dk,
        }
    }

    fn seal(sender: &crate::store::IdentityKeysStore, bob: &crate::store::IdentityKeysStore, revision: u64, item: &VaultItem) -> Vec<u8> {
        seal_for_recipient(
            sender,
            "alice",
            "alice-laptop",
            "bob",
            &bob.share_ek,
            "lineage-1",
            revision,
            &serde_json::to_vec(item).unwrap(),
        )
        .unwrap()
    }

    /// The server holds every share capsule and the recipient's public share
    /// key. Under envelope v1 it could seal a new capsule with any content and
    /// a later `updated_at`, and the recipient applied it as the sender's edit.
    /// With v2 the update must be signed by the key pinned at acceptance.
    #[test]
    fn a_server_forged_update_is_not_applied() {
        let alice = identity();
        let mallory = identity();
        let bob = identity();
        let now = Utc::now();

        let original = login("item-1", "Example", "real-password", now);
        let accepted = admit_received(&bob, &seal(&alice, &bob, 1, &original), "bob", "alice", None).unwrap();
        assert!(accepted.first_contact);

        // A forger with its own key, claiming Alice and a later edit time.
        let forged_item = login("item-1", "Example", "attacker-password", now + Duration::days(1));
        let forged = seal(&mallory, &bob, 99, &forged_item);
        let err = admit_received(&bob, &forged, "bob", "alice", Some(&accepted.pin)).unwrap_err();
        assert!(err.contains("not signed by the device"), "{err}");

        // Under v1 the forger did not even need a key: an unsigned capsule.
        let unsigned = crate::crypto::seal_share(&bob.share_ek, &serde_json::to_vec(&forged_item).unwrap()).unwrap();
        assert!(admit_received(&bob, &unsigned, "bob", "alice", Some(&accepted.pin)).is_err());
    }

    /// A capsule the server kept and replays later must not undo a newer edit.
    #[test]
    fn a_replayed_share_capsule_cannot_revert_a_newer_item() {
        let alice = identity();
        let bob = identity();
        let now = Utc::now();
        let v1 = seal(&alice, &bob, 1, &login("item-1", "Example", "old-password", now));
        let v2 = seal(&alice, &bob, 2, &login("item-1", "Example", "new-password", now));

        let pin1 = admit_received(&bob, &v1, "bob", "alice", None).unwrap().pin;
        let pin2 = admit_received(&bob, &v2, "bob", "alice", Some(&pin1)).unwrap().pin;
        assert_eq!(pin2.revision, 2);
        assert!(admit_received(&bob, &v1, "bob", "alice", Some(&pin2)).is_err());
        assert!(admit_received(&bob, &v2, "bob", "alice", Some(&pin2)).is_err());
    }

    #[test]
    fn stored_pins_round_trip() {
        let alice = identity();
        let bob = identity();
        let capsule = seal(&alice, &bob, 1, &login("item-1", "Example", "pw", Utc::now()));
        let pin = admit_received(&bob, &capsule, "bob", "alice", None).unwrap().pin;
        assert_eq!(StoredSharePin::from_pin(&pin).to_pin(), Some(pin));
    }
}
