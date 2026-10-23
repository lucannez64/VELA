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
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    pending_items: Vec<PendingShareItem>,
    sent_shares: Vec<Share>,
    received_shares: Vec<Share>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingShareItem {
    before: Option<VaultItem>,
    after: VaultItem,
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

/// Decode errors must never erase the pins used for admission.
fn read_share_store(
    store: &crate::store::Store,
    crypto: &crate::crypto::Crypto,
) -> Result<ShareStore, String> {
    let path = store.store_path().join(SHARES_FILE);
    let ciphertext = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ShareStore::default()),
        Err(e) => return Err(format!("Failed to read share store: {e}")),
    };
    let plaintext = crypto
        .decrypt_vault(&ciphertext)
        .map_err(|e| format!("Failed to decrypt share store: {e}"))?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("Invalid share store: {e}"))
}

fn write_share_store(
    store: &crate::store::Store,
    crypto: &crate::crypto::Crypto,
    snapshot: &ShareStore,
) -> Result<(), String> {
    let plaintext =
        zeroize::Zeroizing::new(serde_json::to_vec(snapshot).map_err(|e| e.to_string())?);
    let ciphertext = crypto
        .encrypt_vault(&plaintext)
        .map_err(|e| e.to_string())?;
    crate::store::write_secret_file(&store.store_path().join(SHARES_FILE), &ciphertext)
        .map_err(|e| e.to_string())?;
    #[cfg(test)]
    share_commit_checkpoint("share-write")?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_SHARE_COMMIT_AT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn share_commit_checkpoint(phase: &'static str) -> Result<(), String> {
    FAIL_SHARE_COMMIT_AT.with(|point| {
        if point.get() == Some(phase) {
            point.set(None);
            Err(format!("Injected interruption after {phase}"))
        } else {
            Ok(())
        }
    })
}

/// The encrypted share file is the write-ahead record: new pins and their
/// pending item changes reach disk together, BEFORE any vault changes.
/// Recovery never lowers a pin. Replaying an already applied item is harmless;
/// a later local edit/deletion wins over a pending replacement.
fn finish_pending_items(
    store: &crate::store::Store,
    crypto: &crate::crypto::Crypto,
    vault: &mut crate::vault::VaultStore,
    snapshot: &mut ShareStore,
) -> Result<(), String> {
    if snapshot.pending_items.is_empty() {
        return Ok(());
    }
    // A prior replacement may be visible even though its directory sync
    // reported failure. Reading it is not a durability acknowledgment. Re-arm
    // the journal before touching the vault, including on in-process retries.
    write_share_store(store, crypto, snapshot)?;
    for change in &snapshot.pending_items {
        let current = vault.get_item(change.after.id());
        let deleted = vault.tombstones.iter().any(|t| t.id == change.after.id());
        if vela_client_share_policy::recovery_should_apply(
            current == change.before.as_ref(),
            current.is_some(),
            deleted,
        ) {
            if current.is_some() {
                vault.update_item(change.after.clone());
            } else {
                vault.add_item(change.after.clone());
            }
        }
    }
    // Also persist when the in-memory replay is a no-op: a prior write may
    // have failed after mutating memory but before reaching durable storage.
    store.save_vault(vault, crypto).map_err(|e| e.to_string())?;
    #[cfg(test)]
    share_commit_checkpoint("vault")?;
    let mut finished = snapshot.clone();
    finished.pending_items.clear();
    write_share_store(store, crypto, &finished)?;
    *snapshot = finished;
    Ok(())
}

/// Called while opening the vault, before exposing its contents after restart.
/// A corrupt share store fails closed rather than silently forgetting pins.
pub(crate) fn recover_share_commit(
    store: &crate::store::Store,
    crypto: &crate::crypto::Crypto,
    vault: &mut crate::vault::VaultStore,
) -> Result<(), String> {
    let mut snapshot = read_share_store(store, crypto)?;
    finish_pending_items(store, crypto, vault, &mut snapshot)
}

fn load_share_store(state: &AppState) -> Result<ShareStore, String> {
    let _transition = state
        .key_transition_lock
        .read()
        .map_err(|_| "Key transition lock unavailable")?;
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Crypto not initialized")?;
    let mut snapshot = read_share_store(&state.store, crypto)?;
    if !snapshot.pending_items.is_empty() {
        finish_pending_items(
            &state.store,
            crypto,
            &mut state.vault.write(),
            &mut snapshot,
        )?;
        state.vault_changed.notify_one();
    }
    Ok(snapshot)
}

/// All callers hold sharing_mutex for their entire read/modify/write operation.
/// Generation checks additionally reject a stale snapshot rather than silently
/// overwriting a newer pin. key_transition_lock binds all writes to one RMS.
fn save_share_store(state: &AppState, snapshot: &mut ShareStore) -> Result<(), String> {
    let _transition = state
        .key_transition_lock
        .read()
        .map_err(|_| "Key transition lock unavailable")?;
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Crypto not initialized")?;
    let current = read_share_store(&state.store, crypto)?;
    let next_generation = vela_client_share_policy::next_store_generation(
        current.generation,
        snapshot.generation,
        !current.pending_items.is_empty(),
    )
    .ok_or("Share store changed or exhausted; reload before saving")?;
    let mut committed = snapshot.clone();
    committed.generation = next_generation;
    // Pin and intended content become durable in this one atomic replacement.
    write_share_store(&state.store, crypto, &committed)?;
    *snapshot = committed;
    #[cfg(test)]
    share_commit_checkpoint("journal")?;
    if !snapshot.pending_items.is_empty() {
        finish_pending_items(&state.store, crypto, &mut state.vault.write(), snapshot)?;
        state.vault_changed.notify_one();
    }
    Ok(())
}

fn current_user_id(state: &AppState) -> String {
    {
        let session = state.session.read();
        if let Some(user_id) = session.get_user_id() {
            return user_id.to_string();
        }
    }
    state
        .store
        .load_user_id()
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Refreshes shares whose payload was updated after the initial send/accept
/// (e.g. the sender edited the item and re-sealed it for the recipient).
pub(crate) async fn refresh_linked_shares_inner(state: &AppState) -> Result<(), String> {
    let _share_guard = state.sharing_mutex.lock().await;
    let mut store = load_share_store(state)?;
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
    save_share_store(state, &mut store)?;
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
                Some(vela_crypto::verification::signing_key_fingerprint(
                    &admitted.pin.sender_vk,
                )),
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
        return Err(
            "This device has no signing key and cannot share items. Re-enroll it to share.".into(),
        );
    }
    let signing_key =
        signing::HybridSigningKey::from_bytes(&keys.hybrid_sk).map_err(|e| e.to_string())?;
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

    let vault = state.vault.read();

    for share in store
        .received_shares
        .iter_mut()
        .filter(|s| s.accepted == Some(true))
    {
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
        if matches!(item, VaultItem::Passkey { .. }) {
            continue;
        }
        if let Some(before) = vault.get_item(&share.item_id) {
            let refreshed = item
                .with_id(share.item_id.clone())
                .with_shared_status(true, None);
            store.pending_items.push(PendingShareItem {
                before: Some(before.clone()),
                after: refreshed,
            });
            share.pin = Some(StoredSharePin::from_pin(&admitted.pin));
        }
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
    if let Err(e) = refresh_linked_shares_inner(state).await {
        tracing::warn!("Could not refresh linked shares: {e}");
    }
    // Network failure may use cached records; unreadable local pins never may.
    let _share_guard = state.sharing_mutex.lock().await;
    let mut store = load_share_store(state)?;

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
                save_share_store(state, &mut store)?;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch inbox from server (returning local shares): {}",
                    e
                );
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
    let _share_guard = state.sharing_mutex.lock().await;
    let mut store = load_share_store(state)?;

    let token = match state.get_session_token() {
        Some(token) => token,
        None => return Ok(()),
    };
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let item_json =
        serde_json::to_vec(&item.without_personal_organization()).map_err(|e| e.to_string())?;
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
        let revision = share
            .revision
            .checked_add(1)
            .ok_or("share revision overflow")?;
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

    save_share_store(state, &mut store)?;
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
    let _share_guard = state.sharing_mutex.lock().await;
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
        let item_json =
            serde_json::to_vec(&item.without_personal_organization()).map_err(|e| e.to_string())?;
        let device_id = state
            .store
            .load_device_id()
            .unwrap_or_else(|_| "unknown".to_string());
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
        .map_err(|e| {
            format!("Could not fetch recipient share key: {e}. Check the recipient's user ID.")
        })?;

    let recipient_share_ek = B64
        .decode(recipient_share_ek_b64.as_bytes())
        .map_err(|_| "Invalid recipient share key encoding")?;
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

    let mut store = load_share_store(state)?;
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
    save_share_store(state, &mut store)?;

    record_audit_event(
        state,
        AuditAction::ShareSent {
            recipient_user_id: recipient.to_string(),
        },
    );
    tracing::info!("Share sent: {} to {}", share.item_name, recipient);

    Ok(share)
}

/// Accepts a received share for real — decrypts the sealed item with our
/// own share private key and adds it to the vault as a new, distinct item.
pub async fn accept_share(state: &AppState, share_id: &str) -> Result<(), String> {
    let _share_guard = state.sharing_mutex.lock().await;
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut store = load_share_store(state)?;

    let share = store
        .received_shares
        .iter()
        .find(|s| s.id == share_id)
        .ok_or("Share not found")?
        .clone();

    if !vela_client_share_policy::initial_acceptance_is_authorized(
        share.accepted.is_some(),
        share.pin.is_some(),
        share.encrypted_payload.is_some(),
    ) {
        return Err(if share.accepted.is_some() || share.pin.is_some() {
            "Share has already been accepted or declined"
        } else {
            "Share has no encrypted payload"
        }
        .into());
    }
    let capsule = share
        .encrypted_payload
        .as_deref()
        .ok_or("Share has no encrypted payload")?;
    let keys = load_identity(state)?;
    let admitted = admit_received(&keys, capsule, &current_user_id(state), &share.from, None)
        .map_err(|e| format!("This share cannot be verified and was not added: {e}"))?;
    let item: VaultItem =
        serde_json::from_slice(&admitted.opened.item).map_err(|e| e.to_string())?;
    if matches!(item, VaultItem::Passkey { .. }) {
        return Err("Passkeys cannot be shared".into());
    }
    // A stable new ID is recorded in the journal BEFORE adding the received copy.
    let received_item = item
        .with_id(Uuid::new_v4().to_string())
        .with_shared_status(true, None);
    let received_item_id = received_item.id().to_string();
    store.pending_items.push(PendingShareItem {
        before: None,
        after: received_item,
    });
    let existing = store
        .received_shares
        .iter_mut()
        .find(|s| s.id == share_id)
        .expect("share loaded above");
    existing.accepted = Some(true);
    existing.pin = Some(StoredSharePin::from_pin(&admitted.pin));
    existing.item_id = received_item_id;
    save_share_store(state, &mut store)?;
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    if let Some(token) = state.get_session_token() {
        if let Ok(new_tok) = client.delete_inbox_item(&token, share_id).await {
            if let Some(t) = new_tok {
                state.session.write().set_server_token(t);
            }
        }
    }

    record_audit_event(
        state,
        AuditAction::ShareReceived {
            sender_user_id: share.from.clone(),
        },
    );
    tracing::info!("Share accepted: {}", share_id);

    Ok(())
}

/// Declines a received share for real — removes it from the server inbox
/// and the local share store without ever adding it to the vault.
pub async fn decline_share(state: &AppState, share_id: &str) -> Result<(), String> {
    let _share_guard = state.sharing_mutex.lock().await;
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut store = load_share_store(state)?;
    let share = store
        .received_shares
        .iter()
        .find(|s| s.id == share_id)
        .ok_or("Share not found")?;
    if share.accepted.is_some() || share.pin.is_some() {
        return Err("Share has already been accepted or declined".into());
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

    store.remove_share(share_id);
    save_share_store(state, &mut store)?;
    tracing::info!("Share declined: {}", share_id);

    Ok(())
}

/// Deletes/revokes a share for real. For a sent share, this also clears the
/// `shared` flag on the original vault item and removes the recipient's
/// copy from their inbox. For a received share, just removes the local
/// record (the item itself, already added to the vault on accept, stays).
pub async fn delete_share(state: &AppState, share_id: &str) -> Result<(), String> {
    let _share_guard = state.sharing_mutex.lock().await;
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let mut store = load_share_store(state)?;

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

        if let Some(received_index) = store
            .received_shares
            .iter()
            .position(|s| s.accepted == Some(true) && s.encrypted_payload == revoked_payload)
        {
            let received_share = store.received_shares[received_index].clone();
            vault.delete_item(&received_share.item_id, device_id.as_deref());
            store.received_shares.remove(received_index);
        } else {
            store
                .received_shares
                .retain(|s| s.encrypted_payload != revoked_payload);
        }

        drop(vault);
        let _ = state.persist_current_vault();
    }

    store.remove_share(share_id);
    save_share_store(state, &mut store)?;
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

    pub(super) fn login(id: &str, name: &str, pass: &str, updated_at: DateTime<Utc>) -> VaultItem {
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

    pub(super) fn identity() -> crate::store::IdentityKeysStore {
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

    fn seal(
        sender: &crate::store::IdentityKeysStore,
        bob: &crate::store::IdentityKeysStore,
        revision: u64,
        item: &VaultItem,
    ) -> Vec<u8> {
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
        let accepted = admit_received(
            &bob,
            &seal(&alice, &bob, 1, &original),
            "bob",
            "alice",
            None,
        )
        .unwrap();
        assert!(accepted.first_contact);

        // A forger with its own key, claiming Alice and a later edit time.
        let forged_item = login(
            "item-1",
            "Example",
            "attacker-password",
            now + Duration::days(1),
        );
        let forged = seal(&mallory, &bob, 99, &forged_item);
        let err = admit_received(&bob, &forged, "bob", "alice", Some(&accepted.pin)).unwrap_err();
        assert!(err.contains("not signed by the device"), "{err}");

        // Under v1 the forger did not even need a key: an unsigned capsule.
        let unsigned =
            crate::crypto::seal_share(&bob.share_ek, &serde_json::to_vec(&forged_item).unwrap())
                .unwrap();
        assert!(admit_received(&bob, &unsigned, "bob", "alice", Some(&accepted.pin)).is_err());
    }

    /// A capsule the server kept and replays later must not undo a newer edit.
    #[test]
    fn a_replayed_share_capsule_cannot_revert_a_newer_item() {
        let alice = identity();
        let bob = identity();
        let now = Utc::now();
        let v1 = seal(
            &alice,
            &bob,
            1,
            &login("item-1", "Example", "old-password", now),
        );
        let v2 = seal(
            &alice,
            &bob,
            2,
            &login("item-1", "Example", "new-password", now),
        );

        let pin1 = admit_received(&bob, &v1, "bob", "alice", None).unwrap().pin;
        let pin2 = admit_received(&bob, &v2, "bob", "alice", Some(&pin1))
            .unwrap()
            .pin;
        assert_eq!(pin2.revision, 2);
        assert!(admit_received(&bob, &v1, "bob", "alice", Some(&pin2)).is_err());
        assert!(admit_received(&bob, &v2, "bob", "alice", Some(&pin2)).is_err());
    }

    #[test]
    fn stored_pins_round_trip() {
        let alice = identity();
        let bob = identity();
        let capsule = seal(
            &alice,
            &bob,
            1,
            &login("item-1", "Example", "pw", Utc::now()),
        );
        let pin = admit_received(&bob, &capsule, "bob", "alice", None)
            .unwrap()
            .pin;
        assert_eq!(StoredSharePin::from_pin(&pin).to_pin(), Some(pin));
    }
}

// Regression coverage for BR-1/BR-2/BR-3: real encrypted files and admission.
#[cfg(test)]
mod assurance_boundary_review {
    use super::*;

    fn fixture() -> (
        tempfile::TempDir,
        AppState,
        crate::store::IdentityKeysStore,
        crate::store::IdentityKeysStore,
        ShareStore,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::for_test(dir.path());
        state.unlock_for_test(&[71; 32]);
        let bob = super::tests::identity();
        state
            .store
            .save_identity_keys_full(&bob, state.crypto.read().as_ref().unwrap())
            .unwrap();
        let alice = super::tests::identity();
        let capsule = capsule(&alice, &bob, 2, "original");
        let admitted = admit_received(&bob, &capsule, "test-user", "alice", None).unwrap();
        let item: VaultItem = serde_json::from_slice(&admitted.opened.item).unwrap();
        state
            .vault
            .write()
            .add_item(item.with_id("local-copy".into()));
        state.persist_current_vault().unwrap();
        let mut store = ShareStore {
            generation: 0,
            pending_items: vec![],
            sent_shares: vec![],
            received_shares: vec![Share {
                id: "share-1".into(),
                item_id: "local-copy".into(),
                item_name: "original".into(),
                item_type: "login".into(),
                direction: ShareDirection::Received,
                from: "alice".into(),
                to: None,
                shared_at: Utc::now(),
                accepted: Some(true),
                allow_edit: false,
                encrypted_payload: Some(capsule),
                recipient_share_ek: None,
                lineage_id: None,
                revision: 0,
                pin: Some(StoredSharePin::from_pin(&admitted.pin)),
                sender_fingerprint: None,
            }],
        };
        save_share_store(&state, &mut store).unwrap();
        (dir, state, bob, alice, store)
    }

    fn capsule(
        sender: &crate::store::IdentityKeysStore,
        bob: &crate::store::IdentityKeysStore,
        revision: u64,
        name: &str,
    ) -> Vec<u8> {
        let item = super::tests::login("remote-item", name, name, Utc::now());
        seal_for_recipient(
            sender,
            "alice",
            "sender-device",
            "test-user",
            &bob.share_ek,
            "lineage-1",
            revision,
            &serde_json::to_vec(&item).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn repeated_acceptance_keeps_the_existing_signer_and_item() {
        let (_dir, state, bob, _alice, mut store) = fixture();
        let original_pin = store.received_shares[0].pin.clone().unwrap();
        let mallory = super::tests::identity();
        store.received_shares[0].encrypted_payload = Some(capsule(&mallory, &bob, 1, "attacker"));
        save_share_store(&state, &mut store).unwrap();
        assert!(accept_share(&state, "share-1")
            .await
            .unwrap_err()
            .contains("already"));
        assert!(decline_share(&state, "share-1")
            .await
            .unwrap_err()
            .contains("already"));
        let after = load_share_store(&state).unwrap();
        assert_eq!(
            after.received_shares[0].pin.as_ref().unwrap(),
            &original_pin
        );
        assert_eq!(state.vault.read().items_snapshot().len(), 1);
    }

    #[test]
    fn a_stale_snapshot_cannot_overwrite_a_newer_pin() {
        let (_dir, state, _bob, _alice, mut stale) = fixture();
        let mut newer = load_share_store(&state).unwrap();
        newer.received_shares[0].pin.as_mut().unwrap().revision = 10;
        save_share_store(&state, &mut newer).unwrap();
        assert!(save_share_store(&state, &mut stale)
            .unwrap_err()
            .contains("changed"));
        assert_eq!(
            load_share_store(&state).unwrap().received_shares[0]
                .pin
                .as_ref()
                .unwrap()
                .revision,
            10
        );
    }

    #[test]
    fn interrupted_linked_update_recovers_content_and_pin_on_open() {
        for phase in ["journal", "vault"] {
            let (dir, state, bob, alice, mut store) = fixture();
            store.received_shares[0].encrypted_payload =
                Some(capsule(&alice, &bob, 3, "new-revision"));
            sync_received_linked_items(&state, &mut store).unwrap();
            // Preparing changes alone must not expose or persist the new item.
            assert_eq!(
                state.vault.read().get_item("local-copy").unwrap().name(),
                "original"
            );
            FAIL_SHARE_COMMIT_AT.with(|p| p.set(Some(phase)));
            assert!(save_share_store(&state, &mut store).is_err());
            let reopened = crate::store::Store::new_at(dir.path().to_path_buf()).unwrap();
            let crypto = crate::crypto::Crypto::new(&[71; 32]);
            // Startup recovery finishes before returning the vault to callers.
            let vault = reopened.load_vault(&crypto).unwrap();
            let persisted = read_share_store(&reopened, &crypto).unwrap();
            assert_eq!(vault.get_item("local-copy").unwrap().name(), "new-revision");
            assert_eq!(
                persisted.received_shares[0].pin.as_ref().unwrap().revision,
                3
            );
            assert!(persisted.pending_items.is_empty());
            let pin = persisted.received_shares[0]
                .pin
                .as_ref()
                .unwrap()
                .to_pin()
                .unwrap();
            assert!(admit_received(
                &bob,
                &capsule(&alice, &bob, 2, "replay"),
                "test-user",
                "alice",
                Some(&pin)
            )
            .is_err());
            // Reopening again is idempotent.
            assert_eq!(
                reopened.load_vault(&crypto).unwrap().items_snapshot().len(),
                1
            );
        }
    }

    #[tokio::test]
    async fn interrupted_first_acceptance_recovers_exactly_one_item() {
        for phase in ["journal", "vault"] {
            let (dir, state, _bob, _alice, mut store) = fixture();
            store.received_shares[0].accepted = None;
            store.received_shares[0].pin = None;
            save_share_store(&state, &mut store).unwrap();
            FAIL_SHARE_COMMIT_AT.with(|p| p.set(Some(phase)));
            assert!(accept_share(&state, "share-1").await.is_err());
            let reopened = crate::store::Store::new_at(dir.path().to_path_buf()).unwrap();
            let crypto = crate::crypto::Crypto::new(&[71; 32]);
            let vault = reopened.load_vault(&crypto).unwrap();
            let persisted = read_share_store(&reopened, &crypto).unwrap();
            let accepted = &persisted.received_shares[0];
            assert_eq!(accepted.accepted, Some(true));
            assert!(accepted.pin.is_some());
            assert!(vault.get_item(&accepted.item_id).is_some());
            assert_eq!(vault.items_snapshot().len(), 2); // original fixture + one new copy
            assert!(accept_share(&state, "share-1")
                .await
                .unwrap_err()
                .contains("already"));
        }
    }

    #[tokio::test]
    async fn concurrent_acceptance_adds_only_one_copy() {
        let (_dir, state, _bob, _alice, mut store) = fixture();
        store.received_shares[0].accepted = None;
        store.received_shares[0].pin = None;
        save_share_store(&state, &mut store).unwrap();
        let state = std::sync::Arc::new(state);
        let guard = state.sharing_mutex.lock().await;
        let first = state.clone();
        let a = tokio::spawn(async move { accept_share(&first, "share-1").await });
        let second = state.clone();
        let b = tokio::spawn(async move { accept_share(&second, "share-1").await });
        tokio::task::yield_now().await;
        assert!(!a.is_finished() && !b.is_finished());
        assert_eq!(state.vault.read().items_snapshot().len(), 1);
        drop(guard);
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert_eq!(state.vault.read().items_snapshot().len(), 2);
    }

    #[tokio::test]
    async fn corrupt_store_is_preserved_and_fails_closed() {
        let (dir, state, _bob, _alice, _store) = fixture();
        let path = dir.path().join(SHARES_FILE);
        std::fs::write(&path, b"damaged encrypted store").unwrap();
        assert!(get_shares(&state).await.is_err());
        assert!(accept_share(&state, "share-1").await.is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"damaged encrypted store");
    }

    #[tokio::test]
    async fn missing_payload_cannot_be_marked_accepted() {
        let (_dir, state, _bob, _alice, mut store) = fixture();
        store.received_shares[0].accepted = None;
        store.received_shares[0].pin = None;
        store.received_shares[0].encrypted_payload = None;
        save_share_store(&state, &mut store).unwrap();
        assert!(accept_share(&state, "share-1").await.is_err());
        assert_eq!(
            load_share_store(&state).unwrap().received_shares[0].accepted,
            None
        );
        assert_eq!(state.vault.read().items_snapshot().len(), 1);
    }

    #[test]
    fn legacy_share_store_is_read_without_resetting_history() {
        let (_dir, state, _bob, _alice, store) = fixture();
        let mut encoded = serde_json::to_value(store).unwrap();
        encoded.as_object_mut().unwrap().remove("generation");
        encoded.as_object_mut().unwrap().remove("pending_items");
        let crypto = state.crypto.read();
        let bytes = crypto
            .as_ref()
            .unwrap()
            .encrypt_vault(&serde_json::to_vec(&encoded).unwrap())
            .unwrap();
        std::fs::write(state.store.store_path().join(SHARES_FILE), bytes).unwrap();
        drop(crypto);
        assert_eq!(
            load_share_store(&state).unwrap().received_shares[0]
                .pin
                .as_ref()
                .unwrap()
                .revision,
            2
        );
    }
    #[test]
    fn recovery_preserves_a_local_edit_after_an_interrupted_commit() {
        let (dir, state, bob, alice, mut store) = fixture();
        store.received_shares[0].encrypted_payload = Some(capsule(&alice, &bob, 3, "remote-edit"));
        sync_received_linked_items(&state, &mut store).unwrap();
        FAIL_SHARE_COMMIT_AT.with(|p| p.set(Some("journal")));
        assert!(save_share_store(&state, &mut store).is_err());
        state.vault.write().update_item(super::tests::login(
            "local-copy",
            "local-edit",
            "local-secret",
            Utc::now(),
        ));
        state.persist_current_vault().unwrap();
        let reopened = crate::store::Store::new_at(dir.path().to_path_buf()).unwrap();
        let crypto = crate::crypto::Crypto::new(&[71; 32]);
        let vault = reopened.load_vault(&crypto).unwrap();
        assert_eq!(vault.get_item("local-copy").unwrap().name(), "local-edit");
        let persisted = read_share_store(&reopened, &crypto).unwrap();
        assert_eq!(
            persisted.received_shares[0].pin.as_ref().unwrap().revision,
            3
        );
        assert!(persisted.pending_items.is_empty());
    }

    #[test]
    fn unreadable_store_never_changes_vault_contents() {
        let (dir, state, bob, alice, mut store) = fixture();
        store.received_shares[0].encrypted_payload = Some(capsule(&alice, &bob, 3, "remote-edit"));
        sync_received_linked_items(&state, &mut store).unwrap();
        // An unreadable destination must stop the commit before any vault mutation.
        let path = dir.path().join(SHARES_FILE);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(save_share_store(&state, &mut store).is_err());
        assert_eq!(
            state.vault.read().get_item("local-copy").unwrap().name(),
            "original"
        );
        let crypto = crate::crypto::Crypto::new(&[71; 32]);
        // Read the persisted vault bytes directly: the corrupt store fails closed on open.
        let bytes = std::fs::read(dir.path().join("vault.enc")).unwrap();
        let vault: crate::vault::VaultStore =
            serde_json::from_slice(&crypto.decrypt_vault(&bytes).unwrap()).unwrap();
        assert_eq!(vault.get_item("local-copy").unwrap().name(), "original");
    }
    #[tokio::test]
    async fn recovery_does_not_resurrect_a_deleted_received_copy() {
        let (dir, state, _bob, _alice, mut store) = fixture();
        store.received_shares[0].accepted = None;
        store.received_shares[0].pin = None;
        save_share_store(&state, &mut store).unwrap();
        FAIL_SHARE_COMMIT_AT.with(|p| p.set(Some("vault")));
        assert!(accept_share(&state, "share-1").await.is_err());
        let crypto = crate::crypto::Crypto::new(&[71; 32]);
        let pending = read_share_store(&state.store, &crypto).unwrap();
        let id = pending.received_shares[0].item_id.clone();
        state.vault.write().delete_item(&id, None);
        state.persist_current_vault().unwrap();
        let reopened = crate::store::Store::new_at(dir.path().to_path_buf()).unwrap();
        assert!(reopened
            .load_vault(&crypto)
            .unwrap()
            .get_item(&id)
            .is_none());
        assert!(read_share_store(&reopened, &crypto)
            .unwrap()
            .pending_items
            .is_empty());
    }
    #[tokio::test]
    async fn offline_refresh_still_returns_authenticated_local_records() {
        let (_dir, state, _bob, _alice, _store) = fixture();
        state
            .session
            .write()
            .set_server_token("offline-token".into());
        let shares = get_shares(&state).await.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].pin.as_ref().unwrap().revision, 2);
    }
    #[test]
    fn pending_commit_survives_rms_rotation() {
        let (dir, state, bob, alice, mut store) = fixture();
        store.received_shares[0].encrypted_payload = Some(capsule(&alice, &bob, 3, "new-revision"));
        sync_received_linked_items(&state, &mut store).unwrap();
        FAIL_SHARE_COMMIT_AT.with(|p| p.set(Some("journal")));
        assert!(save_share_store(&state, &mut store).is_err());
        let old = crate::crypto::Crypto::new(&[71; 32]);
        let new = crate::crypto::Crypto::new(&[72; 32]);
        state.store.rekey_secret_files(&old, &new).unwrap();
        let reopened = crate::store::Store::new_at(dir.path().to_path_buf()).unwrap();
        let vault = reopened.load_vault(&new).unwrap();
        assert_eq!(vault.get_item("local-copy").unwrap().name(), "new-revision");
        let persisted = read_share_store(&reopened, &new).unwrap();
        assert_eq!(
            persisted.received_shares[0].pin.as_ref().unwrap().revision,
            3
        );
        assert!(persisted.pending_items.is_empty());
        assert!(read_share_store(&reopened, &old).is_err());
    }
    #[test]
    fn uncertain_journal_write_is_rearmed_before_recovery_changes_vault() {
        let (_dir, state, bob, alice, mut store) = fixture();
        store.received_shares[0].encrypted_payload = Some(capsule(&alice, &bob, 3, "new-revision"));
        sync_received_linked_items(&state, &mut store).unwrap();
        // Simulate an error after replacement became visible. Reading the
        // journal cannot establish that the failed operation made it durable.
        FAIL_SHARE_COMMIT_AT.with(|p| p.set(Some("share-write")));
        assert!(save_share_store(&state, &mut store).is_err());
        assert_eq!(
            state.vault.read().get_item("local-copy").unwrap().name(),
            "original"
        );
        // A failed durability re-arm must stop recovery BEFORE any vault write.
        FAIL_SHARE_COMMIT_AT.with(|p| p.set(Some("share-write")));
        assert!(load_share_store(&state).is_err());
        assert_eq!(
            state.vault.read().get_item("local-copy").unwrap().name(),
            "original"
        );
        let recovered = load_share_store(&state).unwrap();
        assert_eq!(
            recovered.received_shares[0].pin.as_ref().unwrap().revision,
            3
        );
        assert_eq!(
            state.vault.read().get_item("local-copy").unwrap().name(),
            "new-revision"
        );
    }
}
