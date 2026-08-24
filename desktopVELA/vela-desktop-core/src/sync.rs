//! Toolkit-agnostic core of `src-tauri/src/commands/sync.rs` — the chunked,
//! encrypted, lamport-clocked vault sync protocol with tombstone-aware
//! conflict detection. Extracted verbatim except for two things: the
//! `tauri::{AppHandle, State}` parameter types became `&AppState`, and the
//! trailing `emit_vault_items_changed(&app)` calls (a Tauri IPC event
//! telling the React frontend "re-fetch the vault") were dropped — gpui has
//! no separate renderer process, so the caller (`SettingsScreen`, in this
//! port) just re-reads state directly after the awaited call returns.

use crate::api::{ApiClient, VerifyRequest};
use crate::audit::{self, record_audit_event, AuditAction};
use crate::crypto;
use crate::vault::VaultItem;
use crate::{normalize_server_url, AppState};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use vela_crypto::oram::CHUNK_SIZE;

const LEGACY_VAULT_MAIN_CHUNK_ID: &str = "vault-main";
const VAULT_CHUNK_PREFIX: &str = "vault-data-";
const VAULT_CHUNK_PLAINTEXT_SIZE: usize = CHUNK_SIZE - 4096;

/// Encrypted conflict store (ciphertext of `Vec<ConflictItem>` under the vault
/// key, same envelope as `audit.enc` / `shares.enc`).
const CONFLICTS_FILE: &str = "sync_conflicts.enc";
/// Pre-encryption plaintext conflict store; read once for migration, then removed.
const LEGACY_CONFLICTS_FILE: &str = "sync_conflicts.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub syncing: bool,
    pub last_synced: Option<DateTime<Utc>>,
    pub conflicts: Vec<ConflictItem>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictItem {
    pub item_id: String,
    pub local_version: VaultItem,
    pub server_version: VaultItem,
    pub conflict_detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalSyncMeta {
    #[serde(default = "default_key_epoch")]
    key_epoch: i64,
    chunks: HashMap<String, LocalChunkMeta>,
}

fn default_key_epoch() -> i64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalChunkMeta {
    version: i64,
    lamport_clock: i64,
}

fn load_plaintext_sync_chunks(state: &AppState) -> HashMap<String, LocalChunkMeta> {
    std::fs::read_to_string(state.store.store_path().join("sync_meta.json"))
        .ok()
        .and_then(|json| serde_json::from_str::<LocalSyncMeta>(&json).ok())
        .map(|meta| meta.chunks)
        .unwrap_or_default()
}

fn load_local_sync_meta(state: &AppState) -> Result<LocalSyncMeta, String> {
    // `key_epoch.enc` is the sole epoch authority. Authentication, I/O and
    // parse errors must propagate: treating an unreadable marker as absent
    // lets attacker-controlled plaintext metadata relabel a stale RMS.
    let durable_epoch = {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Vault is locked")?;
        state
            .store
            .load_key_epoch(crypto)
            .map_err(|e| format!("Failed to authenticate the local vault epoch: {e}"))?
    };
    // Absence is the one supported legacy shape and means epoch 1 exactly.
    let authenticated_epoch = durable_epoch.unwrap_or_else(default_key_epoch);
    Ok(LocalSyncMeta {
        key_epoch: authenticated_epoch,
        chunks: load_plaintext_sync_chunks(state),
    })
}

pub(crate) fn local_key_epoch(state: &AppState) -> Result<i64, String> {
    Ok(load_local_sync_meta(state)?.key_epoch)
}

fn save_local_sync_meta(state: &AppState, meta: &LocalSyncMeta) -> Result<(), String> {
    let store = &state.store;
    let meta_path = store.store_path().join("sync_meta.json");
    let json = serde_json::to_string(meta).map_err(|e| e.to_string())?;
    crate::store::write_secret_file(&meta_path, json.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn set_local_key_epoch(state: &AppState, epoch: i64) -> Result<(), String> {
    if epoch < 1 {
        return Err("Local key epoch must be positive".into());
    }
    // Preserve only the non-authoritative chunk clocks from plaintext. Do not
    // require or rewrite the authenticated marker here: migration callers may
    // be between old and new RMS installation. Authority is established only
    // by Store::save_key_epoch and enforced by load_local_sync_meta.
    let chunks = load_plaintext_sync_chunks(state);
    let meta = LocalSyncMeta {
        key_epoch: epoch,
        chunks,
    };
    save_local_sync_meta(state, &meta)
}

/// Return the master password needed to carry a password-backed RMS wrapper
/// across a rotation. It exists only after a password unlock and is zeroized
/// with the session. Refuse before changing either local or server state when
/// a biometric-unlocked password vault cannot safely update that wrapper.
pub(crate) fn password_for_rekey(
    state: &AppState,
    current_rms: &[u8; 32],
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    if !crate::biometric::has_password_encrypted_rms() {
        return Ok(None);
    }
    let password = state.rekey_password().ok_or_else(|| {
        "This vault also has a master-password key. Lock it, unlock with the master password, then retry key rotation or sync."
            .to_string()
    })?;
    let opened = crate::biometric::authenticate_with_password(password.as_str())
        .ok_or("The cached master password no longer opens this vault")?;
    if &opened != current_rms {
        return Err("The master-password key does not match the currently unlocked vault".into());
    }
    Ok(Some(password))
}

fn install_migrated_session_crypto(
    state: &AppState,
    new_crypto: crate::crypto::Crypto,
    new_rms: &[u8; 32],
    expected_generation: u64,
) -> Result<(), String> {
    // Hold the session read lock across the crypto/cache install. `lock_session`
    // takes these locks in the same order, so it either happens wholly before
    // this operation (and fails the checks) or wholly afterwards (and clears
    // the freshly installed values).
    let session = state.session.read();
    if state.session_generation() != expected_generation || !session.active || session.is_expired()
    {
        return Err(
            "Vault locked during key migration; unlock again to finish adoption".to_string(),
        );
    }
    *state.crypto.write() = Some(new_crypto);
    crate::biometric::set_cached_rms(*new_rms);
    Ok(())
}

/// Move all local RMS consumers together. This includes the platform key and,
/// when present, the independent master-password wrapper. Any persistence
/// failure leaves the journal in place so the next unlock can finish or safely
/// recover the migration while the server capsule remains a retry path.
pub(crate) fn migrate_local_rms(
    state: &AppState,
    old_crypto: &crate::crypto::Crypto,
    new_crypto: crate::crypto::Crypto,
    new_epoch: i64,
    password: Option<&str>,
    expected_generation: u64,
) -> Result<(), String> {
    let _transition = state
        .key_transition_lock
        .write()
        .map_err(|_| "Key transition lock is unavailable".to_string())?;
    // Held in `Zeroizing` so the seeds do not linger in plain stack arrays
    // after the migration completes.
    let old_rms = zeroize::Zeroizing::new(old_crypto.rms());
    let new_rms = zeroize::Zeroizing::new(new_crypto.rms());
    let has_platform_rms = crate::biometric::has_platform_stored_rms();
    if !has_platform_rms && password.is_none() {
        return Err("No durable RMS store is available for the rotated key".into());
    }

    // This journal is written before the first consumer changes. It bridges
    // old<->new in both directions, so startup can finish after a process or
    // power failure regardless of which files/wrappers reached the new RMS.
    state
        .store
        .begin_rms_migration(&old_rms, &new_rms, new_epoch)
        .map_err(|e| format!("Failed to create the RMS migration journal: {e}"))?;

    state
        .store
        .rekey_secret_files(old_crypto, &new_crypto)
        .map_err(|e| format!("Failed to migrate local vault files: {e}"))?;

    if has_platform_rms {
        crate::biometric::store_rms(&new_rms)
            .map_err(|e| format!("Failed to persist the rotated vault key: {e}"))?;
    }

    if let Some(password) = password {
        crate::biometric::store_password_encrypted(&new_rms, password)
            .map_err(|e| format!("Failed to update the master-password vault key: {e}"))?;
    }

    state
        .store
        .save_key_epoch(&new_crypto, new_epoch)
        .map_err(|e| format!("Failed to persist the authenticated key epoch: {e}"))?;
    crate::recovery::retire_recovery_setup(state)
        .map_err(|e| format!("Failed to retire old recovery shares: {e}"))?;
    // Auto-lock does not take sync_mutex and may win while the blocking file /
    // credential migration is running. If it already won, leave the durable
    // journal in place and let the next real unlock finish.
    install_migrated_session_crypto(state, new_crypto, &new_rms, expected_generation)?;
    set_local_key_epoch(state, new_epoch)
        .map_err(|e| format!("Failed to persist the new key epoch: {e}"))?;

    state
        .store
        .finish_rms_migration()
        .map_err(|e| format!("Migration completed but its journal could not be removed: {e}"))?;

    Ok(())
}

/// Complete a migration interrupted between any two local writes. Called by
/// both unlock paths before loading `vault.enc`, because that file may already
/// be under the new RMS even while the platform/password wrapper is still old.
pub(crate) fn recover_pending_rms_migration(
    state: &AppState,
    current_rms: [u8; 32],
    password: Option<&str>,
) -> Result<[u8; 32], String> {
    let _transition = state
        .key_transition_lock
        .write()
        .map_err(|_| "Key transition lock is unavailable".to_string())?;
    let Some((old_rms, new_rms, new_epoch)) = state
        .store
        .load_rms_migration(&current_rms)
        .map_err(|e| format!("Failed to open the pending RMS migration: {e}"))?
    else {
        return Ok(current_rms);
    };

    let old_crypto = crate::crypto::Crypto::new(&old_rms);
    let new_crypto = crate::crypto::Crypto::new(&new_rms);
    state
        .store
        .recover_rekey_secret_files(&old_crypto, &new_crypto)
        .map_err(|e| format!("Failed to resume local vault migration: {e}"))?;

    let has_platform_rms = crate::biometric::has_platform_stored_rms();
    let has_password_rms = crate::biometric::has_password_encrypted_rms();
    if has_platform_rms {
        crate::biometric::store_rms(&new_rms)
            .map_err(|e| format!("Failed to finish platform RMS migration: {e}"))?;
    }
    let password_pending = if has_password_rms {
        if let Some(password) = password {
            crate::biometric::store_password_encrypted(&new_rms, password)
                .map_err(|e| format!("Failed to finish password RMS migration: {e}"))?;
            false
        } else {
            true
        }
    } else {
        false
    };
    if !has_platform_rms && password_pending {
        return Err("The interrupted key migration requires the master password to finish".into());
    }

    set_local_key_epoch(state, new_epoch)
        .map_err(|e| format!("Failed to persist the recovered key epoch: {e}"))?;
    state
        .store
        .save_key_epoch(&new_crypto, new_epoch)
        .map_err(|e| format!("Failed to persist the authenticated key epoch: {e}"))?;
    crate::recovery::retire_recovery_setup(state)
        .map_err(|e| format!("Failed to retire old recovery shares: {e}"))?;
    crate::biometric::set_cached_rms(new_rms);

    // A biometric unlock cannot rewrite an independent password wrapper. Keep
    // the two-way journal until the next password unlock; meanwhile the new
    // platform RMS and all local files are already usable.
    if !password_pending {
        state
            .store
            .finish_rms_migration()
            .map_err(|e| format!("Failed to remove the completed migration journal: {e}"))?;
    }

    Ok(new_rms)
}

/// Adopt a server epoch before fetching or writing any vault data. The capsule
/// is opened with the current identity key, then every local RMS-derived file
/// and the platform RMS are moved together to the new seed.
fn open_epoch_adoption_capsule(
    response: &crate::api::CapsuleResponse,
    hybrid_dk: &[u8],
    previous_rms: &[u8; 32],
    server_epoch: i64,
) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    if response.epoch != Some(server_epoch) {
        return Err(format!(
            "Server returned a capsule for epoch {:?}, expected {server_epoch}",
            response.epoch
        ));
    }
    let rotation_id = response.rotation_id.as_deref().ok_or(
        "Server returned an epoch adoption capsule without its committed rotation id",
    )?;
    let capsule = B64
        .decode(&response.capsule)
        .map_err(|e| format!("Malformed epoch adoption capsule: {e}"))?;
    crate::crypto::open_rekey_capsule(
        hybrid_dk,
        &capsule,
        previous_rms,
        server_epoch,
        rotation_id,
    )
}

async fn adopt_server_epoch(
    state: &Arc<AppState>,
    client: &ApiClient,
    token: &mut String,
) -> Result<i64, String> {
    let generation = state.session_generation();
    let (server_epoch, rotation_state, new_token) = client
        .get_key_epoch(token)
        .await
        .map_err(|e| format!("Failed to read server key epoch: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t.clone());
        *token = t;
    }
    let local_epoch = load_local_sync_meta(state)?.key_epoch;

    if rotation_state != "active" {
        return Err(
            "A vault key rotation is in progress; sync will retry after it commits.".into(),
        );
    }
    if server_epoch == local_epoch {
        // ACK is idempotent. Retrying it here heals a lost response from a
        // previous adoption; the server will not allow another rotation while
        // any active device still has an unacknowledged transition capsule.
        if server_epoch > 1 {
            match client.acknowledge_rekey_capsule(token, server_epoch).await {
                Ok(Some(refreshed)) => {
                    state.session.write().set_server_token(refreshed.clone());
                    *token = refreshed;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    "Could not retry the epoch {server_epoch} capsule acknowledgement: {e}"
                ),
            }
        }
        return Ok(server_epoch);
    }
    if server_epoch < local_epoch {
        return Err(format!(
            "Server key epoch {server_epoch} is older than local epoch {local_epoch}; refusing rollback"
        ));
    }
    if local_epoch.checked_add(1) != Some(server_epoch) {
        return Err(format!(
            "Server key epoch {server_epoch} skips this device's authenticated local epoch {local_epoch}; refusing to bypass a re-key transition"
        ));
    }

    let (old_crypto, hybrid_dk) = {
        let guard = state.crypto.read();
        let crypto = guard.as_ref().ok_or("Vault is locked")?;
        let identity = state
            .store
            .load_identity_keys(crypto)
            .map_err(|e| format!("Failed to load identity keys for epoch adoption: {e}"))?
            .ok_or("No identity keys available for epoch adoption")?;
        (
            crate::crypto::Crypto::new(&crypto.rms()),
            identity.hybrid_dk,
        )
    };
    if hybrid_dk.is_empty() {
        return Err("This device has no capsule decryption key; re-enrollment is required".into());
    }
    // Blocking platform-credential check — off the async runtime.
    let password = {
        let state = state.clone();
        let current_rms = old_crypto.rms();
        tokio::task::spawn_blocking(move || password_for_rekey(&state, &current_rms))
            .await
            .map_err(|e| format!("Password proof task panicked: {e}"))??
    };

    let (capsule, new_token) = client
        .get_capsule(token)
        .await
        .map_err(|e| format!("Failed to fetch the epoch adoption capsule: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t.clone());
        *token = t;
    }
    let new_rms = open_epoch_adoption_capsule(
        &capsule,
        &hybrid_dk,
        &old_crypto.rms(),
        server_epoch,
    )?;
    let new_crypto = crate::crypto::Crypto::new(&new_rms);

    state.ensure_unlocked_since(generation)?;
    // Synchronous fs + platform-credential I/O — run it on the blocking pool
    // so a slow disk cannot stall the reactor.
    let state_for_migration = state.clone();
    let password_ref = password.clone();
    tokio::task::spawn_blocking(move || {
        migrate_local_rms(
            &state_for_migration,
            &old_crypto,
            new_crypto,
            server_epoch,
            password_ref.as_ref().map(|p| p.as_str()),
            generation,
        )
    })
    .await
    .map_err(|e| format!("Epoch adoption task failed: {e}"))??;

    // Migration retires the cached split of the old RMS. Immediately create
    // and verify a replacement split so an adopting device has the same
    // recovery-setup state as the rotation initiator. Delivery ceremonies are
    // still required, and a re-mint failure must not undo an already-durable
    // epoch adoption.
    if let Err(e) = tokio::task::spawn_blocking({
        let state = state.clone();
        move || crate::recovery::remint_recovery_setup(&state)
    })
    .await
    .map_err(|e| format!("Recovery share re-mint task panicked: {e}"))
    .and_then(|inner| inner)
    {
        tracing::warn!("Recovery share re-mint after epoch adoption failed: {e}");
    }

    match client.acknowledge_rekey_capsule(token, server_epoch).await {
        Ok(Some(refreshed)) => {
            state.session.write().set_server_token(refreshed.clone());
            *token = refreshed;
        }
        Ok(None) => {}
        Err(e) => {
            // Adoption is already durable; retaining an encrypted retry
            // capsule is harmless and a later rotation overwrites it.
            tracing::warn!("Adopted epoch {server_epoch}, but capsule acknowledgement failed: {e}");
        }
    }
    Ok(server_epoch)
}

/// Refuse a chunk the server hands back at an older revision than we last saw.
///
/// The sync server is untrusted by design, and nothing in the protocol stopped
/// it from replaying an earlier ciphertext for a chunk: deleted credentials
/// reappear, rotated passwords revert, and the client cannot tell (audit C-2).
/// Lamport clocks only ever increase for a given chunk — each writer sets
/// `max(previous, local) + 1` — so a value below what this device already
/// recorded is not a stale cache, it is a rollback.
///
/// This is the half that needs no format change. The other half, binding the
/// revision into the ciphertext so a *relabelled* blob also fails, needs every
/// client to seal and open with the same associated data; see
/// `vela_crypto::aead::vault_chunk_aad`.
fn reject_rollback(
    chunk_id: &str,
    server_lamport: i64,
    last_seen: Option<i64>,
) -> Result<(), String> {
    // Never synced this chunk on this device: nothing to compare against.
    let Some(seen) = last_seen else { return Ok(()) };
    if server_lamport < seen {
        return Err(format!(
            "Server returned an older revision of {chunk_id} (clock {server_lamport}, \
             last seen {seen}). Refusing to overwrite newer local data."
        ));
    }
    Ok(())
}

fn chunk_key_bytes(state: &AppState, chunk_id: &str) -> Result<[u8; 32], String> {
    let crypto_guard = state.crypto.read();
    let crypto = crypto_guard
        .as_ref()
        .ok_or_else(|| "Crypto not initialized".to_string())?;
    Ok(*crypto.chunk_key(chunk_id.as_bytes()).as_bytes())
}

/// Epoch 1 remains wire-compatible with mobile/web clients which have not yet
/// shipped epoch-tagged AAD. Once an account rotates, the capability gate has
/// proved every active device understands the new format, so later epochs are
/// bound explicitly.
fn seal_sync_chunk(
    key: &[u8; 32],
    plaintext: &[u8],
    key_epoch: i64,
    chunk_id: &str,
    lamport_clock: i64,
) -> Result<Vec<u8>, vela_crypto::VelaError> {
    if key_epoch == 1 {
        vela_crypto::aead::seal(
            key,
            plaintext,
            &vela_crypto::aead::vault_chunk_aad(chunk_id, lamport_clock),
        )
    } else {
        vela_crypto::rekey::seal_epoch_chunk(
            key,
            plaintext,
            key_epoch as u64,
            chunk_id,
            lamport_clock,
        )
    }
}

fn log_sync_audit(state: &AppState, chunk_count: usize) {
    record_audit_event(state, AuditAction::VaultSync { chunk_count });
}

pub(crate) async fn authenticate_for_sync(
    state: &AppState,
    client: &ApiClient,
    device_id: &str,
) -> Result<String, String> {
    let identity_keys = state
        .crypto
        .read()
        .as_ref()
        .ok_or_else(|| "Vault is locked".to_string())
        .and_then(|crypto| {
            state.store.load_identity_keys(crypto).map_err(|e| format!("Failed to load identity keys: {e}"))
        })?
        .ok_or_else(|| {
            "No server identity keys found. Re-enroll this vault or create it with a server URL configured."
                .to_string()
        })?;

    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|e| format!("Invalid challenge format: {e}"))?;

    let signature =
        crypto::create_auth_signature(&identity_keys.hybrid_sk, &challenge_bytes, device_id)
            .map_err(|e| format!("Failed to create auth signature: {e}"))?;

    let verify_resp = client
        .verify_signature(&VerifyRequest {
            device_id: device_id.to_string(),
            challenge: challenge_resp.challenge,
            signature,
            device_name: Some(audit::get_device_name()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Failed to verify signature: {e}"))?;

    state
        .store
        .save_device_id_with_user_id(device_id, &verify_resp.user_id)
        .map_err(|e| format!("Failed to save server user ID: {e}"))?;
    {
        let mut session = state.session.write();
        session.user_id = Some(verify_resp.user_id);
        session.set_server_token(verify_resp.token.clone());
    }

    Ok(verify_resp.token)
}

/// True when a server error is an authentication failure (expired or revoked
/// token) rather than a network or storage problem.
///
/// The server PASETO token lives ~15 minutes; an unlocked-but-idle app can
/// outlive it while the local session stays open, and every subsequent request
/// would be rejected. Callers must re-authenticate and retry once instead of
/// reporting a misleading "server unavailable".
fn is_auth_error(err: &str) -> bool {
    err.contains("401")
}

/// Fetch the sync manifest, re-authenticating once when the cached token was
/// rejected (401 — expired, renewed elsewhere, or revoked). The challenge
/// handshake runs with the persisted identity keys, so a healthy device gets
/// a fresh token instead of a dead end.
async fn fetch_manifest_with_reauth(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    device_id: &str,
) -> Result<crate::api::SyncManifest, String> {
    let mut reauthed = false;
    loop {
        match client.get_sync_manifest(token).await {
            Ok((m, new_tok)) => {
                if let Some(t) = new_tok {
                    state.session.write().set_server_token(t.clone());
                    *token = t;
                }
                return Ok(m);
            }
            Err(e) => {
                let msg = e.to_string();
                if !reauthed && is_auth_error(&msg) {
                    match authenticate_for_sync(state, client, device_id).await {
                        Ok(new_token) => {
                            *token = new_token;
                            reauthed = true;
                            continue;
                        }
                        Err(auth_err) => {
                            return Err(format!(
                                "{msg} (re-authentication also failed: {auth_err})"
                            ));
                        }
                    }
                }
                return Err(msg);
            }
        }
    }
}

/// Backfill a share keypair for identities created before sharing existed.
///
/// Generates the keypair locally, registers the public half with the server, and
/// persists both into the identity key store. Best-effort: a no-op once a share
/// key is present, and failures are logged without aborting the sync.
async fn ensure_share_key(state: &AppState, client: &ApiClient, token: &str) {
    let keys = {
        let crypto = state.crypto.read();
        match crypto
            .as_ref()
            .and_then(|c| state.store.load_identity_keys(c).ok().flatten())
        {
            Some(keys) => keys,
            None => return,
        }
    };
    if !keys.share_ek.is_empty() {
        return;
    }

    let (share_ek, share_dk) = crypto::generate_share_keypair();
    if let Err(e) = client.put_my_share_ek(token, &B64.encode(&share_ek)).await {
        tracing::warn!("Share key backfill: server registration failed: {}", e);
        return;
    }

    let crypto = state.crypto.read();
    let Some(crypto) = crypto.as_ref() else {
        return;
    };
    // Only the share keypair is being backfilled; everything else is carried
    // over untouched, `hybrid_dk` included — a device that has one must not
    // lose it to a share-key backfill.
    let updated = crate::store::IdentityKeysStore {
        share_ek: share_ek.clone(),
        share_dk: share_dk.clone(),
        ..keys.clone()
    };
    if let Err(e) = state.store.save_identity_keys_full(&updated, crypto) {
        tracing::warn!("Share key backfill: failed to persist keys: {}", e);
    } else {
        tracing::info!("Share key backfilled for existing identity");
    }
}

/// Advertise capsule-adoption support only when this installation actually
/// retained the matching private key. Best-effort during ordinary sync; the
/// explicit rotation path repeats it and treats failure as fatal.
async fn advertise_rekey_capability(state: &AppState, client: &ApiClient, token: &mut String) {
    let capable = {
        let crypto = state.crypto.read();
        crypto
            .as_ref()
            .and_then(|crypto| state.store.load_identity_keys(crypto).ok().flatten())
            .map(|identity| !identity.hybrid_dk.is_empty())
            .unwrap_or(false)
    };
    if !capable {
        return;
    }
    match client.mark_rekey_capable(token).await {
        Ok(Some(refreshed)) => {
            state.session.write().set_server_token(refreshed.clone());
            *token = refreshed;
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("Could not advertise re-key capability: {e}"),
    }
}

/// How long tombstones are retained before pruning.
const TOMBSTONE_RETENTION_DAYS: i64 = 30;

/// Merge server vault into the local vault, honouring tombstones so that
/// deletions propagate across devices.
pub(crate) fn merge_server_vaults(
    local: &mut crate::vault::VaultStore,
    server: crate::vault::VaultStore,
    device_id: &str,
) -> Vec<ConflictItem> {
    use crate::vault::Tombstone;

    let mut conflicts = Vec::new();

    // ── 1. Build the set of all tombstoned IDs (both sides) ────────────────
    let mut tombstone_map: HashMap<String, DateTime<Utc>> = HashMap::new();
    for t in &local.tombstones {
        tombstone_map.insert(t.id.clone(), t.deleted_at);
    }
    for t in &server.tombstones {
        tombstone_map
            .entry(t.id.clone())
            .and_modify(|d| *d = (*d).max(t.deleted_at))
            .or_insert(t.deleted_at);
    }
    // ── 2. Detect conflicts for items that exist on both sides ──────────────
    let server_map: HashMap<String, crate::vault::VaultItem> = server
        .items
        .into_iter()
        .map(|item| (item.id().to_string(), item))
        .collect();

    for local_item in &local.items {
        let id = local_item.id().to_string();
        if let Some(server_item) = server_map.get(&id) {
            let local_updated = local_item.updated_at();
            let server_updated = server_item.updated_at();

            // Conflict = the server has a newer version AND the local copy was
            // last modified by THIS device (an unsynced local edit). If the
            // local copy was last touched by another device, the server's newer
            // version is just that device's edit propagating — no conflict.
            if server_updated > local_updated {
                let local_modified = local_item.last_modified_device();
                if local_modified.is_some() && local_modified == Some(device_id) {
                    conflicts.push(ConflictItem {
                        item_id: id.clone(),
                        local_version: local_item.clone(),
                        server_version: server_item.clone(),
                        conflict_detected_at: Utc::now(),
                    });
                }
            }
        }
    }

    let conflicted_ids: std::collections::HashSet<String> =
        conflicts.iter().map(|c| c.item_id.clone()).collect();

    // ── 3. Merge items, filtering out tombstoned IDs ───────────────────────
    let mut final_items: HashMap<String, crate::vault::VaultItem> = local
        .items
        .drain(..)
        .filter(|item| {
            tombstone_map
                .get(item.id())
                .map(|deleted_at| *deleted_at >= item.updated_at())
                .unwrap_or(false)
                == false
        })
        .map(|item| (item.id().to_string(), item))
        .collect();

    for (id, server_item) in server_map {
        if tombstone_map
            .get(&id)
            .map(|deleted_at| *deleted_at >= server_item.updated_at())
            .unwrap_or(false)
        {
            continue; // deleted item stays deleted
        }
        if let Some(existing) = final_items.get(&id) {
            // Never silently overwrite a conflicted local edit: it stays local
            // until the user resolves it in the ConflictResolution UI.
            if server_item.updated_at() > existing.updated_at() && !conflicted_ids.contains(&id) {
                final_items.insert(id, server_item);
            }
        } else {
            final_items.insert(id, server_item);
        }
    }

    local.replace_items(final_items.into_values().collect());

    // ── 4. Merge tombstones, keeping newest timestamp per ID ────────────────
    let mut merged_tombstones: HashMap<String, Tombstone> = HashMap::new();
    for t in local.tombstones.drain(..) {
        merged_tombstones.insert(t.id.clone(), t);
    }
    for t in server.tombstones {
        merged_tombstones
            .entry(t.id.clone())
            .and_modify(|existing| {
                if t.deleted_at > existing.deleted_at {
                    *existing = t.clone();
                }
            })
            .or_insert(t);
    }
    local.tombstones = merged_tombstones.into_values().collect();

    // ── 5. Prune old tombstones to prevent unbounded growth ────────────────
    local.prune_tombstones(chrono::Duration::days(TOMBSTONE_RETENTION_DAYS));

    conflicts
}

fn is_vault_data_chunk(chunk_id: &str) -> bool {
    chunk_id.starts_with(VAULT_CHUNK_PREFIX)
}

fn vault_chunk_id(index: usize) -> String {
    format!("{VAULT_CHUNK_PREFIX}{index:06}")
}

fn ordered_vault_chunk_ids(manifest: &crate::api::SyncManifest) -> Vec<String> {
    let mut ids: Vec<String> = manifest
        .chunks
        .iter()
        .filter(|entry| is_vault_data_chunk(&entry.chunk_id))
        .map(|entry| entry.chunk_id.clone())
        .collect();
    ids.sort();
    ids
}

fn manifest_versions(manifest: &crate::api::SyncManifest) -> HashMap<String, LocalChunkMeta> {
    manifest
        .chunks
        .iter()
        .map(|entry| {
            (
                entry.chunk_id.clone(),
                LocalChunkMeta {
                    version: entry.version,
                    lamport_clock: entry.lamport_clock,
                },
            )
        })
        .collect()
}

fn split_plaintext_chunks(plaintext: &[u8]) -> Vec<Vec<u8>> {
    if plaintext.is_empty() {
        return vec![Vec::new()];
    }

    plaintext
        .chunks(VAULT_CHUNK_PLAINTEXT_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect()
}

fn save_conflicts(state: &AppState, conflicts: &[ConflictItem]) -> Result<(), String> {
    let dir = state.store.store_path();
    let enc_path = dir.join(CONFLICTS_FILE);
    let legacy_path = dir.join(LEGACY_CONFLICTS_FILE);

    if conflicts.is_empty() {
        let _ = std::fs::remove_file(&enc_path);
        let _ = std::fs::remove_file(&legacy_path);
        return Ok(());
    }

    // Conflict items contain full VaultItems (passwords, card CVV/PIN, identity
    // SSN, secure-note content), so they must never be persisted as plaintext.
    // Seal them under the vault key via the same envelope used for audit.enc.
    let crypto_guard = state.crypto.read();
    let crypto = crypto_guard
        .as_ref()
        .ok_or("Cannot save conflicts: vault is locked")?;

    let plaintext = serde_json::to_vec(conflicts).map_err(|e| e.to_string())?;
    let ciphertext = crypto
        .encrypt_vault(&plaintext)
        .map_err(|e| e.to_string())?;

    crate::store::write_secret_file(&enc_path, &ciphertext).map_err(|e| e.to_string())?;

    // Remove any pre-encryption plaintext file left by older versions so no
    // secrets linger on disk after the first encrypted save.
    let _ = std::fs::remove_file(&legacy_path);

    Ok(())
}

/// Load persisted conflicts, decrypting the current `.enc` store. Falls back to
/// the legacy plaintext file once (transparent migration), and returns an empty
/// list when the vault is locked — encrypted conflicts cannot be surfaced (or
/// resolved) while locked.
fn load_conflicts(state: &AppState) -> Vec<ConflictItem> {
    let dir = state.store.store_path();
    let enc_path = dir.join(CONFLICTS_FILE);
    let legacy_path = dir.join(LEGACY_CONFLICTS_FILE);

    if enc_path.exists() {
        let crypto_guard = state.crypto.read();
        if let Some(crypto) = crypto_guard.as_ref() {
            if let Ok(ciphertext) = std::fs::read(&enc_path) {
                if let Ok(plaintext) = crypto.decrypt_vault(&ciphertext) {
                    if let Ok(conflicts) = serde_json::from_slice::<Vec<ConflictItem>>(&plaintext) {
                        return conflicts;
                    }
                }
            }
        }
        // Locked or corrupt: cannot surface encrypted conflict data.
        return vec![];
    }

    if legacy_path.exists() {
        return std::fs::read_to_string(&legacy_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
    }

    vec![]
}

/// What the server's vault chunks yielded on download.
#[derive(Debug)]
enum ServerVault {
    /// The chunks decrypted and reassembled into a vault.
    Available(crate::vault::VaultStore, i64),
    /// The server holds vault chunks this account's key cannot open — server-
    /// side corruption, a foreign chunk, or an authority mismatch. Nothing can
    /// safely be merged or overwritten automatically in this state.
    Unreadable(String),
    /// The server has no vault chunks.
    Empty,
}

/// One chunk's outcome from the concurrent download.
enum ChunkOutcome {
    Decrypted(usize, zeroize::Zeroizing<Vec<u8>>, i64),
    Corrupt(usize, String),
}

async fn download_vault_from_manifest(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    manifest: &crate::api::SyncManifest,
    key_epoch: i64,
) -> Result<ServerVault, String> {
    // What this device last accepted for each chunk, to catch a server that
    // serves an older revision back (audit C-2).
    let local_meta = load_local_sync_meta(state)?;
    let ids = ordered_vault_chunk_ids(manifest);
    let ids = if ids.is_empty()
        && manifest
            .chunks
            .iter()
            .any(|entry| entry.chunk_id == LEGACY_VAULT_MAIN_CHUNK_ID)
    {
        vec![LEGACY_VAULT_MAIN_CHUNK_ID.to_string()]
    } else {
        ids
    };

    if ids.is_empty() {
        return Ok(ServerVault::Empty);
    }

    let shared_token = Arc::new(Mutex::new(token.clone()));
    let client = client.clone();

    let mut handles = Vec::with_capacity(ids.len());
    for (idx, chunk_id) in ids.iter().enumerate() {
        let chunk_id = chunk_id.clone();
        let client = client.clone();
        let token = shared_token.clone();
        let key = chunk_key_bytes(state, &chunk_id)?;
        let seen_lamport = local_meta
            .chunks
            .get(&chunk_id)
            .map(|meta| meta.lamport_clock);

        handles.push(tokio::spawn(async move {
            let t = token.lock().await.clone();
            let (ciphertext, _version, lamport, new_tok) = client
                .get_chunk(&t, &chunk_id)
                .await
                .map_err(|e| format!("Failed to download chunk {chunk_id}: {e}"))?;
            if let Some(new_t) = new_tok {
                *token.lock().await = new_t;
            }
            reject_rollback(&chunk_id, lamport, seen_lamport)?;
            // A chunk this account's key cannot open is corruption (or a
            // foreign chunk). Report it distinctly, but never turn an
            // authentication failure into permission to overwrite the server.
            match vela_crypto::rekey::open_epoch_chunk(
                &key,
                &ciphertext,
                key_epoch as u64,
                &chunk_id,
                lamport,
            ) {
                Ok((bound_epoch, chunk)) => {
                    if key_epoch > 1 && bound_epoch != Some(key_epoch as u64) {
                        return Ok::<_, String>(ChunkOutcome::Corrupt(
                            idx,
                            format!("chunk {chunk_id}: legacy ciphertext at epoch {key_epoch}"),
                        ));
                    }
                    Ok::<_, String>(ChunkOutcome::Decrypted(idx, chunk, lamport))
                }
                Err(e) => {
                    Ok::<_, String>(ChunkOutcome::Corrupt(idx, format!("chunk {chunk_id}: {e}")))
                }
            }
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        results.push(
            handle
                .await
                .map_err(|e| format!("Download task panicked: {e}"))??,
        );
    }
    results.sort_by_key(|outcome| match outcome {
        ChunkOutcome::Decrypted(idx, ..) | ChunkOutcome::Corrupt(idx, ..) => *idx,
    });

    *token = shared_token.lock().await.clone();

    let mut plaintext = Vec::new();
    let mut max_lamport = 0;
    let mut corrupt = Vec::new();
    for outcome in results {
        match outcome {
            ChunkOutcome::Decrypted(_, chunk, lamport) => {
                max_lamport = max_lamport.max(lamport);
                plaintext.extend_from_slice(&chunk);
            }
            ChunkOutcome::Corrupt(_, why) => corrupt.push(why),
        }
    }
    if !corrupt.is_empty() {
        return Ok(ServerVault::Unreadable(corrupt.join("; ")));
    }

    let vault: crate::vault::VaultStore = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Failed to deserialize synced vault: {e}"))?;
    Ok(ServerVault::Available(vault, max_lamport))
}

async fn upload_vault_chunks(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    manifest: &crate::api::SyncManifest,
    local_meta: &mut LocalSyncMeta,
    plaintext: &[u8],
    base_lamport: i64,
    key_epoch: i64,
) -> Result<usize, String> {
    let chunks = split_plaintext_chunks(plaintext);
    let manifest_meta = manifest_versions(manifest);
    let client = client.clone();

    // Pre-compute lamport clocks sequentially (fast, no I/O)
    let mut lamport_assignments = Vec::with_capacity(chunks.len());
    let mut lamport = base_lamport;
    for idx in 0..chunks.len() {
        let chunk_id = vault_chunk_id(idx);
        let previous_lamport = manifest_meta
            .get(&chunk_id)
            .map(|m| m.lamport_clock)
            .or_else(|| local_meta.chunks.get(&chunk_id).map(|m| m.lamport_clock))
            .unwrap_or(0);
        lamport = lamport.max(previous_lamport) + 1;
        lamport_assignments.push(lamport);
    }

    // Encrypt and upload in parallel
    let shared_token = Arc::new(Mutex::new(token.clone()));
    let mut handles = Vec::with_capacity(chunks.len());

    for (idx, (chunk, &chunk_lamport)) in chunks.iter().zip(lamport_assignments.iter()).enumerate()
    {
        let chunk_id = vault_chunk_id(idx);
        let version = manifest_meta.get(&chunk_id).map(|m| m.version).unwrap_or(0);
        let key = chunk_key_bytes(state, &chunk_id)?;
        // Sealed against this chunk's id and the clock it is about to be stored
        // under, so the server cannot hand any of it back later as if it were
        // current (audit C-2).
        let ciphertext = seal_sync_chunk(&key, chunk, key_epoch, &chunk_id, chunk_lamport)
            .map_err(|e| format!("Failed to encrypt chunk {chunk_id}: {e}"))?;
        let client = client.clone();
        let token = shared_token.clone();
        let chunk_id_clone = chunk_id.clone();

        handles.push(tokio::spawn(async move {
            let t = token.lock().await.clone();
            let (new_version, new_tok) = client
                .put_chunk_with_epoch(
                    &t,
                    &chunk_id_clone,
                    version,
                    ciphertext,
                    chunk_lamport,
                    Some(key_epoch),
                )
                .await
                .map_err(|e| format!("Failed to upload chunk {chunk_id_clone}: {e}"))?;
            if let Some(new_t) = new_tok {
                *token.lock().await = new_t;
            }
            Ok::<_, String>((chunk_id, new_version))
        }));
    }

    let mut next_meta = HashMap::new();
    for handle in handles {
        let (chunk_id, new_version) = handle
            .await
            .map_err(|e| format!("Upload task panicked: {e}"))??;
        let chunk_lamport = lamport_assignments[next_meta.len()]; // results collected in order
        next_meta.insert(
            chunk_id,
            LocalChunkMeta {
                version: new_version,
                lamport_clock: chunk_lamport,
            },
        );
    }

    *token = shared_token.lock().await.clone();

    // Delete stale chunks in parallel
    let stale_chunks: Vec<_> = manifest
        .chunks
        .iter()
        .filter(|entry| is_vault_data_chunk(&entry.chunk_id))
        .filter_map(|entry| {
            let index_str = entry.chunk_id.strip_prefix(VAULT_CHUNK_PREFIX)?;
            let index = index_str.parse::<usize>().ok()?;
            if index >= chunks.len() {
                Some((entry.chunk_id.clone(), entry.version))
            } else {
                None
            }
        })
        .collect();

    if !stale_chunks.is_empty() {
        let delete_token = shared_token.clone();
        let delete_client = client.clone();
        let _ = tokio::spawn(async move {
            for (chunk_id, version) in stale_chunks {
                let t = delete_token.lock().await.clone();
                match delete_client
                    .delete_chunk_with_epoch(&t, &chunk_id, version, Some(key_epoch))
                    .await
                {
                    Ok(new_tok) => {
                        if let Some(new_t) = new_tok {
                            *delete_token.lock().await = new_t;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to delete stale sync chunk {}: {}", chunk_id, e)
                    }
                }
            }
        })
        .await;

        *token = shared_token.lock().await.clone();
    }

    local_meta.chunks = next_meta;
    Ok(chunks.len())
}

async fn sync_audit_chunk(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    manifest: &crate::api::SyncManifest,
    key_epoch: i64,
) {
    let Some(plaintext) = audit::serialize_audit_plaintext(state) else {
        return;
    };

    if let Some(entry) = manifest
        .chunks
        .iter()
        .find(|entry| entry.chunk_id == audit::AUDIT_CHUNK_ID)
    {
        if let Ok(key) = chunk_key_bytes(state, audit::AUDIT_CHUNK_ID) {
            match client.get_chunk(token, audit::AUDIT_CHUNK_ID).await {
                Ok((ciphertext, _, _, new_tok)) => {
                    if let Some(t) = new_tok {
                        *token = t;
                    }
                    // Reads both formats: sealed against the chunk's id and
                    // clock, or the legacy unbound envelope written before this
                    // (audit C-2). Unlike vault chunks, the audit log is only
                    // ever read and written by the desktop, so there is no other
                    // client to wait for — an older desktop that cannot open a
                    // sealed chunk skips the merge, which is what it already
                    // does on any decrypt failure.
                    let entry_clock = entry.lamport_clock;
                    if let Ok((bound_epoch, server_plaintext)) =
                        vela_crypto::rekey::open_epoch_chunk(
                            &key,
                            &ciphertext,
                            key_epoch as u64,
                            audit::AUDIT_CHUNK_ID,
                            entry_clock,
                        )
                    {
                        if key_epoch > 1 && bound_epoch != Some(key_epoch as u64) {
                            tracing::warn!(
                                "Refusing legacy audit ciphertext after rotation to epoch {key_epoch}"
                            );
                        } else {
                            // Merge server events into the local log (union by
                            // event id) — never replace local history.
                            let _ = audit::merge_audit_from_plaintext(state, &server_plaintext);
                        }
                    }
                }
                Err(e) => tracing::warn!("Failed to pull audit chunk: {}", e),
            }
        }

        if let Ok(key) = chunk_key_bytes(state, audit::AUDIT_CHUNK_ID) {
            if let Some(updated_plaintext) = audit::serialize_audit_plaintext(state) {
                // Sealed to the id and the clock it is stored under, so the
                // server cannot replay an older audit log — which is exactly the
                // record a user consults after a compromise (audit C-2).
                let next_clock = entry.lamport_clock + 1;
                match seal_sync_chunk(
                    &key,
                    &updated_plaintext,
                    key_epoch,
                    audit::AUDIT_CHUNK_ID,
                    next_clock,
                ) {
                    Ok(ciphertext) => {
                        let _ = client
                            .put_chunk_with_epoch(
                                token,
                                audit::AUDIT_CHUNK_ID,
                                entry.version,
                                ciphertext,
                                next_clock,
                                Some(key_epoch),
                            )
                            .await
                            .map(|(_, new_tok)| {
                                if let Some(t) = new_tok {
                                    *token = t;
                                }
                            })
                            .map_err(|e| tracing::warn!("Failed to push audit chunk: {}", e));
                    }
                    Err(e) => tracing::warn!("Failed to encrypt audit chunk: {}", e),
                }
            }
        }
    } else if let Ok(key) = chunk_key_bytes(state, audit::AUDIT_CHUNK_ID) {
        match seal_sync_chunk(&key, &plaintext, key_epoch, audit::AUDIT_CHUNK_ID, 1) {
            Ok(ciphertext) => {
                let _ = client
                    .put_chunk_with_epoch(
                        token,
                        audit::AUDIT_CHUNK_ID,
                        0,
                        ciphertext,
                        1,
                        Some(key_epoch),
                    )
                    .await
                    .map(|(_, new_tok)| {
                        if let Some(t) = new_tok {
                            *token = t;
                        }
                    })
                    .map_err(|e| tracing::warn!("Failed to create audit chunk: {}", e));
            }
            Err(e) => tracing::warn!("Failed to encrypt audit chunk: {}", e),
        }
    }
}

pub async fn trigger_sync(state: &Arc<AppState>) -> Result<SyncStatus, String> {
    // Serialize sync runs: local writes and merges must not interleave.
    let _sync_guard = state.sync_mutex.lock().await;

    // Capture the session generation now; after every await below we prove the
    // vault was not locked (and crypto not swapped) in between.
    let generation = state.session_generation();

    let session_active = {
        let session = state.session.read();
        session.active
    };

    if !session_active {
        return Err("Session not active".to_string());
    }

    {
        let mut session = state.session.write();
        session.refresh();
    }

    let device_id = {
        let session = state.session.read();
        session.get_device_id().unwrap_or("unknown").to_string()
    };

    let server_url = normalize_server_url(&state.server_url.read());
    if server_url.is_empty() {
        return Ok(SyncStatus {
            syncing: false,
            last_synced: None,
            conflicts: vec![],
            error: Some("No server URL configured. Add one in Settings to enable sync.".into()),
        });
    }

    let client = ApiClient::with_url(server_url);

    let mut token = match state.get_session_token() {
        Some(token) => token,
        None => match authenticate_for_sync(state, &client, &device_id).await {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!("Sync: server authentication failed: {}", e);
                return Ok(SyncStatus {
                    syncing: false,
                    last_synced: None,
                    conflicts: vec![],
                    error: Some(format!("Server authentication failed: {e}")),
                });
            }
        },
    };
    state.ensure_unlocked_since(generation)?;

    // Backfill a share keypair for identities created before sharing existed.
    ensure_share_key(state, &client, &token).await;
    state.ensure_unlocked_since(generation)?;
    advertise_rekey_capability(state, &client, &mut token).await;
    state.ensure_unlocked_since(generation)?;

    // Epoch adoption must happen before even fetching the manifest: otherwise
    // a stale client could mistake new-key ciphertext for corruption and push
    // its old-key local vault over the rotated account.
    let key_epoch = match adopt_server_epoch(state, &client, &mut token).await {
        Ok(epoch) => epoch,
        Err(e) => {
            return Ok(SyncStatus {
                syncing: false,
                last_synced: Some(Utc::now()),
                conflicts: vec![],
                error: Some(e),
            });
        }
    };
    state.ensure_unlocked_since(generation)?;

    let manifest = match fetch_manifest_with_reauth(state, &client, &mut token, &device_id).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Sync: server unavailable, using local vault: {}", e);
            return Ok(SyncStatus {
                syncing: false,
                last_synced: Some(Utc::now()),
                conflicts: vec![],
                error: Some(format!(
                    "Server unavailable: {}. Using local vault only.",
                    e
                )),
            });
        }
    };
    state.ensure_unlocked_since(generation)?;

    let mut merged_conflicts: Vec<ConflictItem> = Vec::new();
    let mut max_server_lamport = 0;

    let mut downloaded =
        download_vault_from_manifest(state, &client, &mut token, &manifest, key_epoch).await;
    if let Err(e) = &downloaded {
        if is_auth_error(e) {
            // main's addition: a stale auth token should be refreshed and the
            // chunk download retried once, so a long-lived session does not
            // fail a sync it could have recovered from.
            match authenticate_for_sync(state, &client, &device_id).await {
                Ok(new_token) => {
                    token = new_token;
                    downloaded = download_vault_from_manifest(
                        state, &client, &mut token, &manifest, key_epoch,
                    )
                    .await;
                }
                Err(auth_err) => {
                    tracing::warn!(
                        "Sync: re-authentication before chunk download failed: {}",
                        auth_err
                    );
                }
            }
        }
    }

    match downloaded? {
        ServerVault::Available(server_vault, server_lamport) => {
            state.ensure_unlocked_since(generation)?;
            max_server_lamport = max_server_lamport.max(server_lamport);

            // Merge + write-back atomically with respect to local edits: the vault
            // write guard is held across the whole section (no awaits inside), so
            // a concurrent add/update/delete either lands before the clone (and is
            // merged) or after the write-back (and survives).
            let conflicts = {
                let mut vault_guard = state.vault.write();
                let mut local_vault = vault_guard.clone();
                let conflicts = merge_server_vaults(&mut local_vault, server_vault, &device_id);
                *vault_guard = local_vault;
                conflicts
            };
            merged_conflicts.extend(conflicts);

            // Persist only while holding proof the vault never locked in between.
            state.ensure_unlocked_since(generation)?;
            {
                let crypto_guard = state.crypto.read();
                if let Some(crypto) = crypto_guard.as_ref() {
                    let vault_snapshot = state.vault.read().clone();
                    let _ = state.store.save_vault(&vault_snapshot, crypto);
                }
            }
        }
        ServerVault::Unreadable(why) => {
            // Authentication failure is not a repair authorization. An
            // automatic upload here could destroy genuine server data when a
            // stale/mismatched key or a malicious server caused the failure.
            tracing::error!(
                "Sync: refusing to overwrite server vault chunks that could not be decrypted ({why})"
            );
            return Ok(SyncStatus {
                syncing: false,
                last_synced: Some(Utc::now()),
                conflicts: merged_conflicts,
                error: Some(format!(
                    "Server vault data could not be authenticated ({why}). No server data was overwritten."
                )),
            });
        }
        ServerVault::Empty => {}
    }

    let mut current_meta = load_local_sync_meta(state)?;
    let local_vault_snapshot = state.vault.read().clone();
    let local_count = local_vault_snapshot.items.len();

    // Safety guard: never upload an empty vault when the server has data.
    // This prevents overwriting server vault with empty data in the rare case
    // where the local vault is corrupt but sync metadata is stale.
    if local_count == 0 && !current_meta.chunks.is_empty() {
        tracing::warn!(
            "Sync: refusing to upload empty vault (sync meta has {} chunks). \
             Server data may be intact — re-sync or re-enroll to recover.",
            current_meta.chunks.len()
        );
        return Ok(SyncStatus {
            syncing: false,
            last_synced: Some(Utc::now()),
            conflicts: merged_conflicts,
            error: Some(
                "Local vault is empty but server may have data. \
                         Please re-enroll or trigger a force-pull to recover."
                    .into(),
            ),
        });
    }

    let plaintext = serde_json::to_vec(&local_vault_snapshot)
        .map_err(|e| format!("Failed to serialize vault: {}", e))?;

    tracing::info!(
        "Sync: uploading vault as chunked trivial ORAM payload ({} bytes)",
        plaintext.len()
    );

    // Upload, then check for local edits that landed while the upload was in
    // flight; if the vault changed, push the fresh snapshot once more so no
    // local mutation is silently discarded.
    let mut plaintext_to_upload = plaintext;
    let mut uploaded_chunks = 0usize;
    for attempt in 0..2 {
        state.ensure_unlocked_since(generation)?;
        match upload_vault_chunks(
            state,
            &client,
            &mut token,
            &manifest,
            &mut current_meta,
            &plaintext_to_upload,
            max_server_lamport,
            key_epoch,
        )
        .await
        {
            Ok(count) => {
                uploaded_chunks = count;
                save_local_sync_meta(state, &current_meta)?;
            }
            Err(e) => {
                tracing::error!("Sync: failed to upload vault chunks: {}", e);
                return Ok(SyncStatus {
                    syncing: false,
                    last_synced: Some(Utc::now()),
                    conflicts: merged_conflicts,
                    error: Some(format!("Upload failed: {}", e)),
                });
            }
        }

        state.ensure_unlocked_since(generation)?;
        let fresh_plaintext = serde_json::to_vec(&*state.vault.read())
            .map_err(|e| format!("Failed to serialize vault: {}", e))?;
        if fresh_plaintext == plaintext_to_upload || attempt == 1 {
            break;
        }
        tracing::info!("Sync: local edits landed during upload — pushing follow-up");
        plaintext_to_upload = fresh_plaintext;
    }

    save_conflicts(state, &merged_conflicts)?;
    log_sync_audit(state, uploaded_chunks);
    let _ = crate::sharing::refresh_linked_shares_inner(state).await;
    sync_audit_chunk(state, &client, &mut token, &manifest, key_epoch).await;
    state.session.write().set_server_token(token);

    tracing::info!(
        "Sync complete: {} items, {} uploaded chunks, {} conflicts",
        state.vault.read().items.len(),
        uploaded_chunks,
        merged_conflicts.len()
    );

    Ok(SyncStatus {
        syncing: false,
        last_synced: Some(Utc::now()),
        conflicts: merged_conflicts,
        error: None,
    })
}

pub async fn get_sync_status(state: &AppState) -> Result<SyncStatus, String> {
    // Status needs only the non-secret chunk clocks. Keep it available while
    // locked without parsing or exposing plaintext epoch metadata as authority.
    let has_meta = !load_plaintext_sync_chunks(state).is_empty();

    let last_synced_path = state.store.store_path().join("sync_meta.json");
    let last_synced = if has_meta {
        std::fs::metadata(&last_synced_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(DateTime::<Utc>::from)
    } else {
        None
    };

    let conflicts: Vec<ConflictItem> = load_conflicts(state);

    Ok(SyncStatus {
        syncing: false,
        last_synced,
        conflicts,
        error: None,
    })
}

pub async fn resolve_conflict(
    state: &Arc<AppState>,
    item_id: String,
    use_local: bool,
) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }

    // Serialize against `trigger_sync`: the "use server" branch below can
    // adopt a new server epoch, which migrates every RMS-derived file and
    // swaps `state.crypto`. Letting that interleave with an in-flight sync
    // would let the sync continue writing files under the retired key after
    // the migration journal is consumed — stranding them unopenable.
    let _sync_guard = state.sync_mutex.lock().await;

    // Read the stored conflict (if any) up-front: its server_version snapshot
    // is the authoritative "server side" for resolution.
    let stored_conflicts: Vec<ConflictItem> = load_conflicts(state);
    let stored_conflict = stored_conflicts
        .iter()
        .find(|c| c.item_id == item_id)
        .cloned();

    if use_local {
        // If the merged vault currently holds the server version, restore the
        // stored local version so "keep local" always wins.
        if let Some(conflict) = &stored_conflict {
            let mut vault = state.vault.write();
            if let Some(local_item) = vault.items.iter_mut().find(|i| i.id() == item_id) {
                if local_item.updated_at() != conflict.local_version.updated_at() {
                    *local_item = conflict.local_version.clone().with_updated_at(Utc::now());
                    vault.touch_generation();
                }
            }
            drop(vault);
            let crypto_guard = state.crypto.read();
            if let Some(crypto) = crypto_guard.as_ref() {
                let _ = state.store.save_vault(&state.vault.read(), crypto);
            }
        }
        tracing::info!(
            "Conflict resolved for item {}: keeping local version",
            item_id
        );
    } else if let Some(conflict) = stored_conflict {
        // Resolve from the stored snapshot — immune to any intermediate syncs.
        let mut vault = state.vault.write();
        let resolved = conflict.server_version.clone().with_updated_at(Utc::now());
        if let Some(local_item) = vault.items.iter_mut().find(|i| i.id() == item_id) {
            *local_item = resolved;
        } else {
            vault.items.push(resolved);
        }
        vault.touch_generation();
        drop(vault);
        let crypto_guard = state.crypto.read();
        if let Some(crypto) = crypto_guard.as_ref() {
            let _ = state.store.save_vault(&state.vault.read(), crypto);
        }
        tracing::info!(
            "Conflict resolved for item {}: using server version",
            item_id
        );
    } else {
        let server_url = state.server_url.read().clone();
        let client = ApiClient::with_url(server_url);

        let mut token = state
            .get_session_token()
            .ok_or("No session token available")?;
        let key_epoch = adopt_server_epoch(state, &client, &mut token).await?;

        let (manifest, new_tok) = client
            .get_sync_manifest(&token)
            .await
            .map_err(|e| format!("Failed to fetch sync manifest: {}", e))?;
        if let Some(t) = new_tok {
            token = t;
        }
        let ServerVault::Available(server_vault, _) =
            download_vault_from_manifest(state, &client, &mut token, &manifest, key_epoch).await?
        else {
            return Err(
                "The server's vault is unavailable (empty or could not be decrypted); \
                 cannot resolve the conflict against it"
                    .to_string(),
            );
        };
        state.session.write().set_server_token(token);

        if let Some(server_item) = server_vault.items.iter().find(|i| i.id() == item_id) {
            let mut vault = state.vault.write();
            if let Some(local_item) = vault.items.iter_mut().find(|i| i.id() == item_id) {
                let resolved = server_item.clone().with_updated_at(Utc::now());
                *local_item = resolved;
            } else {
                vault.items.push(server_item.clone());
            }
            vault.touch_generation();
            drop(vault);

            let crypto_guard = state.crypto.read();
            if let Some(crypto) = crypto_guard.as_ref() {
                let _ = state.store.save_vault(&state.vault.read(), crypto);
            }
            drop(crypto_guard);
        }

        tracing::info!(
            "Conflict resolved for item {}: using server version",
            item_id
        );
    }

    let mut conflicts: Vec<ConflictItem> = load_conflicts(state);
    conflicts.retain(|conflict| conflict.item_id.as_str() != item_id);

    save_conflicts(state, &conflicts)?;

    Ok(())
}

pub fn set_server_url(state: &AppState, url: String) -> Result<(), String> {
    let url = crate::validate_server_url(&url)?;
    {
        let mut server_url = state.server_url.write();
        *server_url = url.clone();
    }
    if let Ok(mut settings) = state.store.load_settings() {
        settings.server_url = url;
        let _ = state.store.save_settings(&settings);
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn adoption_validates_every_authenticated_capsule_authority() {
        let (hybrid_ek, hybrid_dk) = crate::crypto::generate_share_keypair();
        let previous_rms = [40u8; 32];
        let stale_rms = [41u8; 32];
        let current_rms = [42u8; 32];
        let current = crate::crypto::seal_rekey_capsule(
            &hybrid_ek,
            &previous_rms,
            &current_rms,
            3,
            "rotation-current",
        )
        .unwrap();
        let current_response = crate::api::CapsuleResponse {
            capsule: B64.encode(current),
            epoch: Some(3),
            rotation_id: Some("rotation-current".into()),
        };
        assert_eq!(
            open_epoch_adoption_capsule(
                &current_response,
                &hybrid_dk,
                &previous_rms,
                3,
            )
            .unwrap()
            .as_ref(),
            &current_rms
        );

        let stale = crate::crypto::seal_rekey_capsule(
            &hybrid_ek,
            &previous_rms,
            &stale_rms,
            2,
            "rotation-old",
        )
        .unwrap();
        let relabelled = crate::api::CapsuleResponse {
            capsule: B64.encode(stale),
            epoch: Some(3),
            rotation_id: Some("rotation-current".into()),
        };

        let error = open_epoch_adoption_capsule(
            &relabelled,
            &hybrid_dk,
            &previous_rms,
            3,
        )
        .expect_err("server metadata cannot relabel an authenticated stale capsule");
        assert!(error.contains("authenticated re-key capsule epoch"), "{error}");

        let mut missing_attempt = current_response.clone();
        missing_attempt.rotation_id = None;
        assert!(open_epoch_adoption_capsule(
            &missing_attempt,
            &hybrid_dk,
            &previous_rms,
            3,
        )
        .is_err());

        let mut wrong_attempt = current_response.clone();
        wrong_attempt.rotation_id = Some("rotation-other".into());
        assert!(open_epoch_adoption_capsule(
            &wrong_attempt,
            &hybrid_dk,
            &previous_rms,
            3,
        )
        .is_err());

        let mut wrong_outer_epoch = current_response;
        wrong_outer_epoch.epoch = Some(2);
        assert!(open_epoch_adoption_capsule(
            &wrong_outer_epoch,
            &hybrid_dk,
            &previous_rms,
            3,
        )
        .is_err());
    }

    #[test]
    fn completed_migration_cannot_resurrect_a_locked_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = std::sync::Arc::new(crate::AppState::for_test(dir.path()));
        let old_rms = [11u8; 32];
        let new_rms = [12u8; 32];
        state.unlock_for_test(&old_rms);
        let generation = state.session_generation();

        crate::commands::session::lock_session(&state);
        let error = install_migrated_session_crypto(
            &state,
            crate::crypto::Crypto::new(&new_rms),
            &new_rms,
            generation,
        )
        .expect_err("migration tail must not reinstall secrets after auto-lock");

        assert!(error.contains("locked during key migration"));
        assert!(state.crypto.read().is_none());
        assert!(!state.session.read().active);
    }

    #[test]
    fn authenticated_epoch_overrides_missing_or_legacy_sync_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        let crypto = crate::crypto::Crypto::new(&[12u8; 32]);
        state.store.save_key_epoch(&crypto, 4).unwrap();
        *state.crypto.write() = Some(crypto);

        assert_eq!(load_local_sync_meta(&state).unwrap().key_epoch, 4);

        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":999,"chunks":{}}"#,
        )
        .unwrap();
        assert_eq!(load_local_sync_meta(&state).unwrap().key_epoch, 4);
    }

    #[test]
    fn missing_authenticated_epoch_is_strictly_legacy_epoch_one() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&[13u8; 32]);
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":42,"chunks":{"vault-data-000000":{"version":7,"lamport_clock":9}}}"#,
        )
        .unwrap();

        let meta = load_local_sync_meta(&state).expect("missing marker is legacy epoch 1");
        assert_eq!(meta.key_epoch, 1, "plaintext must never supply epoch authority");
        assert_eq!(meta.chunks["vault-data-000000"].version, 7);
    }

    #[test]
    fn unreadable_authenticated_epoch_never_falls_back_to_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&[14u8; 32]);
        state
            .store
            .save_key_epoch(&crate::crypto::Crypto::new(&[15u8; 32]), 6)
            .unwrap();
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":6,"chunks":{}}"#,
        )
        .unwrap();

        let error = load_local_sync_meta(&state)
            .expect_err("wrong-RMS epoch marker must fail closed");
        assert!(error.contains("authenticate the local vault epoch"), "{error}");
        assert!(local_key_epoch(&state).is_err());
    }

    #[test]
    fn malformed_authenticated_epoch_never_falls_back_to_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&[16u8; 32]);
        std::fs::write(
            state.store.store_path().join("key_epoch.enc"),
            b"not an authenticated envelope",
        )
        .unwrap();
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":8,"chunks":{}}"#,
        )
        .unwrap();

        assert!(load_local_sync_meta(&state).is_err());
    }

    #[test]
    fn invalid_authenticated_epoch_never_falls_back_to_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&[21u8; 32]);
        let ciphertext = {
            let crypto = state.crypto.read();
            crypto
                .as_ref()
                .unwrap()
                .encrypt_vault(&serde_json::to_vec(&0i64).unwrap())
                .unwrap()
        };
        std::fs::write(state.store.store_path().join("key_epoch.enc"), ciphertext).unwrap();
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":7,"chunks":{}}"#,
        )
        .unwrap();

        let error = load_local_sync_meta(&state).expect_err("epoch zero must fail closed");
        assert!(error.contains("invalid local key epoch"), "{error}");
    }

    #[test]
    fn epoch_marker_io_errors_never_fall_back_to_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&[22u8; 32]);
        std::fs::create_dir(state.store.store_path().join("key_epoch.enc")).unwrap();
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":7,"chunks":{}}"#,
        )
        .unwrap();

        assert!(load_local_sync_meta(&state).is_err());
    }

    #[test]
    fn malformed_plaintext_metadata_cannot_hide_a_valid_marker() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&[17u8; 32]);
        {
            let crypto = state.crypto.read();
            state.store.save_key_epoch(crypto.as_ref().unwrap(), 9).unwrap();
        }
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            b"not json",
        )
        .unwrap();

        let meta = load_local_sync_meta(&state).unwrap();
        assert_eq!(meta.key_epoch, 9);
        assert!(meta.chunks.is_empty());
    }

    #[tokio::test]
    async fn locked_sync_status_uses_chunk_clocks_without_trusting_plaintext_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":999,"chunks":{"vault-data-000000":{"version":2,"lamport_clock":3}}}"#,
        )
        .unwrap();

        let status = get_sync_status(&state)
            .await
            .expect("locked status only reads non-secret chunk clocks");
        assert!(status.last_synced.is_some());
        assert!(local_key_epoch(&state).is_err());
    }

    #[test]
    fn plaintext_epoch_updates_cannot_change_authenticated_authority() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&[18u8; 32]);
        {
            let crypto = state.crypto.read();
            state.store.save_key_epoch(crypto.as_ref().unwrap(), 3).unwrap();
        }

        set_local_key_epoch(&state, 77).unwrap();
        assert_eq!(load_local_sync_meta(&state).unwrap().key_epoch, 3);
        assert!(set_local_key_epoch(&state, 0).is_err());
    }

    #[tokio::test]
    async fn unreadable_epoch_marker_aborts_sync_before_manifest_or_repair_upload() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::AppState::for_test(dir.path()));
        state.unlock_for_test(&[19u8; 32]);
        state.session.write().set_server_token("token".into());
        state
            .store
            .save_key_epoch(&crate::crypto::Crypto::new(&[20u8; 32]), 5)
            .unwrap();
        std::fs::write(
            state.store.store_path().join("sync_meta.json"),
            r#"{"key_epoch":5,"chunks":{}}"#,
        )
        .unwrap();

        let server = MockServer::start().await;
        *state.server_url.write() = server.uri();
        Mock::given(method("GET"))
            .and(path("/vault/epoch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "epoch": 5,
                "state": "active",
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/vault/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chunks": []
            })))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/vault/chunk/vault-data-000000"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let status = trigger_sync(&state).await.expect("sync returns a surfaced status error");
        let error = status.error.expect("unreadable marker must stop sync");
        assert!(error.contains("authenticate the local vault epoch"), "{error}");
        server.verify().await;
    }

    #[tokio::test]
    async fn unreadable_server_chunk_aborts_sync_without_any_upload() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::AppState::for_test(dir.path()));
        state.unlock_for_test(&[23u8; 32]);
        state.session.write().set_server_token("token".into());
        state.vault.write().items.push(login(
            "local-must-not-overwrite-server",
            Utc::now(),
            Some("test-device"),
        ));

        let foreign = vela_crypto::aead::seal(
            &[0x42u8; 32],
            b"{\"items\":[]}",
            &vela_crypto::aead::vault_chunk_aad("vault-data-000000", 1),
        )
        .unwrap();
        let server = MockServer::start().await;
        *state.server_url.write() = server.uri();
        Mock::given(method("GET"))
            .and(path("/vault/epoch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "epoch": 1,
                "state": "active",
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/vault/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chunks": [{
                    "chunk_id": "vault-data-000000",
                    "version": 1,
                    "lamport_clock": 1,
                    "last_writer": null,
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/vault/chunk/vault-data-000000"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("X-Chunk-Version", "1")
                    .append_header("X-Lamport-Clock", "1")
                    .set_body_raw(foreign, "application/octet-stream"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let status = trigger_sync(&state).await.expect("sync returns a surfaced status error");
        let error = status.error.expect("unreadable server data must stop sync");
        assert!(error.contains("could not be authenticated"), "{error}");
        assert!(error.contains("No server data was overwritten"), "{error}");
        server.verify().await;
    }

    /// Audit C-2: the sync server is untrusted, and replaying an older
    /// ciphertext for a chunk used to be invisible — deleted credentials
    /// reappear, rotated passwords revert.
    #[test]
    fn a_server_serving_an_older_revision_is_refused() {
        // Same or newer is normal: another device wrote, or nothing changed.
        assert!(reject_rollback("vault-data-000000", 7, Some(7)).is_ok());
        assert!(reject_rollback("vault-data-000000", 8, Some(7)).is_ok());

        // Lower than what this device already accepted is a rollback, not a
        // stale cache: per-chunk lamport clocks only ever increase.
        let error = reject_rollback("vault-data-000000", 6, Some(7))
            .expect_err("must refuse to overwrite newer local data");
        assert!(error.contains("older revision"), "{error}");
        assert!(error.contains("vault-data-000000"), "{error}");

        // A chunk this device has never synced has nothing to compare against.
        assert!(reject_rollback("vault-data-000009", 1, None).is_ok());
    }
    use super::*;
    use crate::vault::{VaultMeta, VaultStore};

    fn login(id: &str, updated_at: DateTime<Utc>, last_modified_device: Option<&str>) -> VaultItem {
        VaultItem::Login {
            meta: VaultMeta {
                id: id.to_string(),
                name: format!("item-{id}"),
                notes: None,
                created_at: updated_at,
                updated_at,
                last_modified_device: last_modified_device.map(|s| s.to_string()),
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            url: "https://example.com".to_string(),
            username: "user".to_string(),
            pass: "pw".to_string(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        }
    }

    fn store_with(items: Vec<VaultItem>) -> VaultStore {
        let mut store = VaultStore::new();
        store.replace_items(items);
        store
    }

    /// Unsynced local edit (modified by THIS device) + newer server version
    /// must produce a conflict and must NOT silently overwrite the local item.
    #[test]
    fn local_unsynced_edit_produces_conflict_not_overwrite() {
        let t_old = Utc::now() - chrono::Duration::hours(2);
        let t_new = Utc::now() - chrono::Duration::hours(1);

        let mut local = store_with(vec![login("a", t_old, Some("this-device"))]);
        let server = store_with(vec![login("a", t_new, Some("other-device"))]);

        let conflicts = merge_server_vaults(&mut local, server, "this-device");

        assert_eq!(conflicts.len(), 1, "unsynced local edit must conflict");
        assert_eq!(conflicts[0].item_id, "a");
        let kept = local
            .items
            .iter()
            .find(|i| i.id() == "a")
            .expect("item kept");
        assert_eq!(
            kept.updated_at(),
            t_old,
            "conflicted local edit must not be overwritten by the server version"
        );
    }

    /// Server-newer item last modified by ANOTHER device is ordinary
    /// replication: no conflict, server version wins.
    #[test]
    fn remote_newer_from_other_device_merges_without_conflict() {
        let t_old = Utc::now() - chrono::Duration::hours(2);
        let t_new = Utc::now() - chrono::Duration::hours(1);

        let mut local = store_with(vec![login("a", t_old, Some("other-device"))]);
        let server = store_with(vec![login("a", t_new, Some("other-device"))]);

        let conflicts = merge_server_vaults(&mut local, server, "this-device");

        assert!(conflicts.is_empty(), "remote edit must not conflict");
        let kept = local
            .items
            .iter()
            .find(|i| i.id() == "a")
            .expect("item kept");
        assert_eq!(kept.updated_at(), t_new, "newer server version must win");
    }

    /// Local-newer items are kept as-is with no conflict.
    #[test]
    fn local_newer_is_kept_without_conflict() {
        let t_old = Utc::now() - chrono::Duration::hours(2);
        let t_new = Utc::now() - chrono::Duration::hours(1);

        let mut local = store_with(vec![login("a", t_new, Some("this-device"))]);
        let server = store_with(vec![login("a", t_old, Some("other-device"))]);

        let conflicts = merge_server_vaults(&mut local, server, "this-device");

        assert!(conflicts.is_empty());
        assert_eq!(
            local
                .items
                .iter()
                .find(|i| i.id() == "a")
                .unwrap()
                .updated_at(),
            t_new
        );
    }

    /// An item tombstoned after its last update must stay deleted even when
    /// the server still holds a copy — deletions propagate.
    #[test]
    fn tombstoned_item_stays_deleted_despite_server_copy() {
        use crate::vault::Tombstone;
        let t_item = Utc::now() - chrono::Duration::hours(2);
        let t_deleted = Utc::now() - chrono::Duration::hours(1);

        let mut local = store_with(vec![]);
        local.tombstones.push(Tombstone {
            id: "a".into(),
            deleted_at: t_deleted,
            deleted_by: Some("this-device".into()),
        });
        let server = store_with(vec![login("a", t_item, Some("other-device"))]);

        let conflicts = merge_server_vaults(&mut local, server, "this-device");

        assert!(conflicts.is_empty());
        assert!(
            local.items.iter().all(|i| i.id() != "a"),
            "tombstoned item must not resurrect"
        );
        assert_eq!(
            local.tombstones.len(),
            1,
            "tombstone is retained for other devices"
        );
    }

    /// A server edit NEWER than the tombstone means the item was deliberately
    /// re-created after the deletion — it comes back.
    #[test]
    fn server_edit_newer_than_tombstone_resurrects_item() {
        use crate::vault::Tombstone;
        let t_deleted = Utc::now() - chrono::Duration::hours(2);
        let t_recreated = Utc::now() - chrono::Duration::hours(1);

        let mut local = store_with(vec![]);
        local.tombstones.push(Tombstone {
            id: "a".into(),
            deleted_at: t_deleted,
            deleted_by: None,
        });
        let server = store_with(vec![login("a", t_recreated, Some("other-device"))]);

        let conflicts = merge_server_vaults(&mut local, server, "this-device");

        assert!(conflicts.is_empty());
        let kept = local
            .items
            .iter()
            .find(|i| i.id() == "a")
            .expect("re-created item resurrected");
        assert_eq!(kept.updated_at(), t_recreated);
    }

    /// Both sides tombstoned the same id — the newest deletion time wins so
    /// pruning is consistent across devices.
    #[test]
    fn duplicate_tombstones_keep_newest_timestamp() {
        use crate::vault::Tombstone;
        let t_old = Utc::now() - chrono::Duration::hours(3);
        let t_new = Utc::now() - chrono::Duration::hours(1);

        let mut local = store_with(vec![]);
        local.tombstones.push(Tombstone {
            id: "a".into(),
            deleted_at: t_old,
            deleted_by: None,
        });
        let mut server = store_with(vec![]);
        server.tombstones.push(Tombstone {
            id: "a".into(),
            deleted_at: t_new,
            deleted_by: Some("srv".into()),
        });

        merge_server_vaults(&mut local, server, "this-device");

        assert_eq!(local.tombstones.len(), 1);
        assert_eq!(local.tombstones[0].deleted_at, t_new);
    }

    /// Items present on only one side are unioned into the merged vault.
    #[test]
    fn one_sided_items_are_unioned() {
        let t = Utc::now() - chrono::Duration::hours(1);
        let mut local = store_with(vec![login("local-only", t, Some("this-device"))]);
        let server = store_with(vec![login("server-only", t, Some("other-device"))]);

        let conflicts = merge_server_vaults(&mut local, server, "this-device");

        assert!(conflicts.is_empty());
        assert_eq!(local.items.len(), 2);
        assert!(local.items.iter().any(|i| i.id() == "local-only"));
        assert!(local.items.iter().any(|i| i.id() == "server-only"));
    }

    /// Identical timestamps on both sides: no conflict, local copy kept.
    #[test]
    fn equal_timestamps_are_not_a_conflict() {
        let t = Utc::now() - chrono::Duration::hours(1);
        let mut local = store_with(vec![login("a", t, Some("this-device"))]);
        let server = store_with(vec![login("a", t, Some("other-device"))]);

        let conflicts = merge_server_vaults(&mut local, server, "this-device");

        assert!(conflicts.is_empty());
        let kept = local.items.iter().find(|i| i.id() == "a").unwrap();
        assert_eq!(kept.last_modified_device(), Some("this-device"));
    }

    /// A server chunk this account's key cannot open must surface as
    /// `ServerVault::Unreadable`; its caller fails closed rather than treating
    /// an authentication failure as repair authorization.
    #[tokio::test]
    async fn a_chunk_this_account_cannot_decrypt_is_unreadable() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&crate::crypto::Crypto::generate_rms());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vault/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chunks": [{
                    "chunk_id": "vault-data-000000",
                    "version": 1,
                    "lamport_clock": 1,
                    "last_writer": null,
                }]
            })))
            .mount(&server)
            .await;

        // The chunk is sealed under a key this device does not hold — exactly
        // what a concurrent-writer incident leaves on the server.
        let foreign_key = [0x42u8; 32];
        let bogus = vela_crypto::aead::seal(
            &foreign_key,
            b"{\"items\":[]}",
            &vela_crypto::aead::vault_chunk_aad("vault-data-000000", 1),
        )
        .unwrap();
        Mock::given(method("GET"))
            .and(path("/vault/chunk/vault-data-000000"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("X-Chunk-Version", "1")
                    .append_header("X-Lamport-Clock", "1")
                    .set_body_raw(bogus, "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let client = ApiClient::with_url(server.uri());
        let manifest: crate::api::SyncManifest = serde_json::from_value(serde_json::json!({
            "chunks": [{
                "chunk_id": "vault-data-000000",
                "version": 1,
                "lamport_clock": 1,
                "last_writer": null,
            }]
        }))
        .unwrap();
        let mut token = "tok".to_string();

        let result = download_vault_from_manifest(&state, &client, &mut token, &manifest, 1)
            .await
            .expect("a corrupt chunk must not abort the download");
        assert!(
            matches!(&result, ServerVault::Unreadable(why) if why.contains("vault-data-000000")),
            "expected Unreadable, got {result:?}"
        );
    }

    /// The matching happy path: a chunk sealed under this device's own key
    /// comes back `Available` and reassembles.
    #[tokio::test]
    async fn a_chunk_sealed_under_this_devices_key_is_available() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let state = crate::AppState::for_test(dir.path());
        state.unlock_for_test(&crate::crypto::Crypto::generate_rms());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vault/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chunks": [{
                    "chunk_id": "vault-data-000000",
                    "version": 1,
                    "lamport_clock": 1,
                    "last_writer": null,
                }]
            })))
            .mount(&server)
            .await;

        let key = {
            let crypto = state.crypto.read();
            let crypto = crypto.as_ref().unwrap();
            *crypto.chunk_key(b"vault-data-000000").as_bytes()
        };
        let sealed = vela_crypto::rekey::seal_epoch_chunk(
            &key,
            b"{\"items\":[]}",
            7,
            "vault-data-000000",
            1,
        )
        .unwrap();
        Mock::given(method("GET"))
            .and(path("/vault/chunk/vault-data-000000"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("X-Chunk-Version", "1")
                    .append_header("X-Lamport-Clock", "1")
                    .set_body_raw(sealed, "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let client = ApiClient::with_url(server.uri());
        let manifest: crate::api::SyncManifest = serde_json::from_value(serde_json::json!({
            "chunks": [{
                "chunk_id": "vault-data-000000",
                "version": 1,
                "lamport_clock": 1,
                "last_writer": null,
            }]
        }))
        .unwrap();
        let mut token = "tok".to_string();

        let result = download_vault_from_manifest(&state, &client, &mut token, &manifest, 7)
            .await
            .expect("a good chunk must download");
        assert!(matches!(result, ServerVault::Available(_, 1)));
    }
}
