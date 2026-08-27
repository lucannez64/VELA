//! Toolkit-agnostic core of `src-tauri/src/commands/recovery.rs` — the
//! locally-cached-shares side of account recovery setup (SPEC.md §4.3): the
//! RMS is split into a Shamir 2-of-3 scheme and each share delivered to its
//! own channel (cloud remote / server, gated by a WebAuthn credential /
//! sealed into an authenticated envelope for the trusted contact's key).
//! Any two distinct channels reconstruct the RMS (M18).
//!
//! All three delivery channels live here, so either front end can drive a
//! complete 2-of-3 setup: cloud backup over rclone, the security-key share
//! the server holds behind a WebAuthn credential, and the trusted-contact
//! share the user carries out of band. `src-tauri` keeps only the
//! `#[tauri::command]` wrappers.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::api::{ApiClient, RecoveryRecoverRequest, RecoveryShareData};
use crate::AppState;
use vela_crypto::recovery::RecoveryShareChannel;

const RECOVERY_SETUP_FILE: &str = "recovery_setup.enc";

/// A new RMS makes every previously generated recovery share obsolete.
/// Remove both cached shares and delivery flags so the UI requires a complete
/// fresh setup and `ensure_shares_split` cannot redistribute old material.
pub(crate) fn retire_recovery_setup(state: &AppState) -> Result<(), String> {
    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Abandon an incomplete setup without claiming that its publication reached
/// the active server/cloud state. Immutable cloud candidates and a staged
/// server candidate are harmless: readers ignore them and a later setup may
/// replace the pending server slot.
pub fn discard_recovery_setup(state: &AppState) -> Result<(), String> {
    if state.is_unlocked() {
        let pending = load_pending_checked(state)?;
        if pending.server_finalized || pending.cloud_active {
            return Err(
                "Recovery publication was already finalized; resume cloud promotion instead of discarding it"
                    .into(),
            );
        }
    }
    retire_recovery_setup(state)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PendingRecoveryShares {
    /// Account which owns this journal. A copied journal must never publish
    /// shares into whichever account happens to be signed in now.
    #[serde(default)]
    account_id: Option<String>,
    /// Authenticated local key epoch whose RMS produced all three shares.
    /// `None` is the pre-epoch on-disk shape and is accepted only at epoch 1.
    #[serde(default)]
    key_epoch: Option<i64>,
    /// Fresh identifier for this exact Shamir polynomial (M16).
    #[serde(default)]
    split_id: Option<String>,
    share1: Option<Vec<u8>>,
    share2: Option<Vec<u8>>,
    share3: Option<Vec<u8>>,
    #[serde(default)]
    cloud_backup_delivered: bool,
    /// Remote holding the immutable candidate, needed to publish the active
    /// pointer only after the server finalizes this exact split.
    #[serde(default)]
    cloud_remote: Option<String>,
    #[serde(default)]
    security_key_delivered: bool,
    #[serde(default)]
    trusted_contact_acknowledged: bool,
    /// KEM public key the Share 3 envelope was sealed for (M18). Presence is
    /// what distinguishes an authenticated handoff from a raw manual copy.
    #[serde(default)]
    contact_recipient_key: Option<String>,
    /// Post-prerequisite commits used to resume the same split after a crash.
    #[serde(default)]
    server_finalized: bool,
    #[serde(default)]
    cloud_active: bool,
}

fn publication_facts(
    pending: &PendingRecoveryShares,
    account_id: &str,
    current_epoch: i64,
    account_epoch_active: bool,
) -> vela_client_recovery_policy::PublicationFacts {
    vela_client_recovery_policy::PublicationFacts {
        journal_present: pending.share1.is_some()
            || pending.server_finalized
            || pending.cloud_active,
        account_matches: pending.account_id.as_deref() == Some(account_id),
        split_id_present: pending.split_id.is_some(),
        cloud_share_present: pending.share1.is_some(),
        server_share_present: pending.share2.is_some(),
        journal_epoch: pending.key_epoch.unwrap_or(0),
        current_epoch,
        account_epoch_active,
        server_staged: pending.security_key_delivered,
        cloud_candidate_durable: pending.cloud_backup_delivered,
        server_finalized: pending.server_finalized,
        cloud_active: pending.cloud_active,
    }
}

fn authorize_publication_action(
    pending: &PendingRecoveryShares,
    account_id: &str,
    current_epoch: i64,
    action: vela_client_recovery_policy::PublicationAction,
) -> Result<(), String> {
    let facts = publication_facts(pending, account_id, current_epoch, true);
    vela_client_recovery_policy::publication_action_is_authorized(facts, action)
        .then_some(())
        .ok_or_else(|| format!("Recovery publication journal rejected {action:?}"))
}

/// Epoch authenticated by the currently unlocked RMS, rather than the
/// plaintext sync metadata. Epoch-1 vaults created before `key_epoch.enc`
/// existed have no marker; 1 is the only safe legacy default.
fn authenticated_local_epoch(state: &AppState) -> Result<i64, String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Vault is locked")?;
    state
        .store
        .load_key_epoch(crypto)
        .map_err(|e| format!("Failed to read the authenticated vault epoch: {e}"))
        .and_then(|epoch| {
            let epoch = epoch.unwrap_or(1);
            (epoch >= 1)
                .then_some(epoch)
                .ok_or_else(|| "Authenticated vault epoch must be positive".to_string())
        })
}

fn require_pending_epoch(
    pending: &PendingRecoveryShares,
    expected_epoch: i64,
) -> Result<(), String> {
    if pending.key_epoch == Some(expected_epoch) {
        Ok(())
    } else {
        Err(
            "Recovery setup belongs to a retired vault epoch; sync and start recovery setup again"
                .into(),
        )
    }
}

/// Confirm that an external recovery delivery still belongs to the account's
/// active epoch. Called before a channel receives material and again before
/// its local delivered flag is committed, catching a rotation by another
/// device while cloud/FIDO2/human work was in progress.
async fn revalidate_recovery_epoch(
    state: &AppState,
    client: &ApiClient,
    token: &mut String,
    expected_epoch: i64,
    generation: u64,
) -> Result<(), String> {
    let (server_epoch, rotation_state, refreshed) = client
        .get_key_epoch(token)
        .await
        .map_err(|e| format!("Failed to validate the recovery setup epoch: {e}"))?;
    if let Some(refreshed) = refreshed {
        state.session.write().set_server_token(refreshed.clone());
        *token = refreshed;
    }
    state.ensure_unlocked_since(generation)?;
    let local_epoch = authenticated_local_epoch(state)?;
    if rotation_state != "active" || server_epoch != expected_epoch || local_epoch != expected_epoch
    {
        return Err(format!(
            "Vault key rotation changed recovery setup epoch {expected_epoch} \
             (local {local_epoch}, server {server_epoch}, state {rotation_state}); \
             sync and start recovery setup again"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub cloud_backup_delivered: bool,
    pub security_key_delivered: bool,
    pub trusted_contact_acknowledged: bool,
    /// True while the split shares are still cached locally (setup started
    /// but not yet finalized) — remaining methods can be completed against
    /// the same split. Once finalized, starting any method again forces a
    /// fresh split that invalidates every previously delivered share.
    pub setup_in_progress: bool,
}

fn load_pending(state: &AppState) -> PendingRecoveryShares {
    load_pending_checked(state).unwrap_or_default()
}

fn load_pending_checked(state: &AppState) -> Result<PendingRecoveryShares, String> {
    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if !path.exists() {
        return Ok(PendingRecoveryShares::default());
    }
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Vault is locked")?;
    let ciphertext = std::fs::read(&path)
        .map_err(|e| format!("Failed to read recovery publication journal: {e}"))?;
    let plaintext = crypto
        .decrypt_vault(&ciphertext)
        .map_err(|e| format!("Recovery publication journal could not be decrypted: {e}"))?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Recovery publication journal is malformed: {e}"))
}

fn save_pending(state: &AppState, pending: &PendingRecoveryShares) -> Result<(), String> {
    let crypto = state.crypto.read();
    let crypto = crypto.as_ref().ok_or("Vault is locked")?;

    let plaintext = serde_json::to_vec(pending).map_err(|e| e.to_string())?;
    let ciphertext = crypto
        .encrypt_vault(&plaintext)
        .map_err(|e| e.to_string())?;

    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    crate::store::write_secret_file(&path, &ciphertext).map_err(|e| e.to_string())?;
    // This journal is an ordering boundary, not a cache: commit the phase to
    // stable storage before the next external effect can begin. The file must
    // be opened with write access — a read-only handle fails sync_all on
    // Windows (ERROR_ACCESS_DENIED).
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    std::fs::File::open(state.store.store_path())
        .and_then(|directory| directory.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Split the RMS into a 2-of-3 Shamir scheme exactly once per vault, caching
/// the shares (encrypted at rest, same as `shares.enc`) until each has been
/// delivered. Idempotent — repeated calls return the same three shares, so
/// the three setup steps can be completed in any order without invalidating
/// one another's share.
pub(crate) fn ensure_shares_split(state: &AppState) -> Result<(), String> {
    let current_epoch = authenticated_local_epoch(state)?;
    let account_id = state
        .store
        .load_user_id()
        .map_err(|e| format!("Failed to load account ID: {e}"))?;
    let mut pending = load_pending_checked(state)?;
    if pending.share1.is_some() && pending.share2.is_some() && pending.share3.is_some() {
        let legacy_account = pending.account_id.is_none();
        if pending.key_epoch == Some(current_epoch)
            && (legacy_account || pending.account_id.as_deref() == Some(account_id.as_str()))
        {
            pending.account_id = Some(account_id.clone());
            if pending.split_id.is_some() {
                if legacy_account {
                    save_pending(state, &pending)?;
                }
                return Ok(());
            }
            // A cached pre-M16 split has no publication identity. Reuse the
            // share material but require every channel to be republished.
            pending.split_id = Some(uuid::Uuid::new_v4().to_string());
            pending.cloud_backup_delivered = false;
            pending.cloud_remote = None;
            pending.security_key_delivered = false;
            pending.trusted_contact_acknowledged = false;
            pending.server_finalized = false;
            pending.cloud_active = false;
            return save_pending(state, &pending);
        }
        if pending.key_epoch.is_none() && current_epoch == 1 {
            pending.account_id = Some(account_id.clone());
            pending.key_epoch = Some(1);
            pending.split_id = Some(uuid::Uuid::new_v4().to_string());
            pending.cloud_backup_delivered = false;
            pending.cloud_remote = None;
            pending.security_key_delivered = false;
            pending.trusted_contact_acknowledged = false;
            pending.server_finalized = false;
            pending.cloud_active = false;
            return save_pending(state, &pending);
        }
        // Never redistribute a complete split derived from another epoch.
        pending = PendingRecoveryShares::default();
    }

    let shares = {
        let crypto = state.crypto.read();
        let crypto = crypto
            .as_ref()
            .ok_or("Vault must be unlocked to set up recovery")?;
        crypto
            .split_recovery(2, 3)
            .map_err(|e| format!("Failed to split recovery shares: {e}"))?
    };
    if shares.len() != 3 {
        return Err("Unexpected share count from split".to_string());
    }

    pending.share1 = Some(shares[0].to_bytes());
    pending.share2 = Some(shares[1].to_bytes());
    pending.share3 = Some(shares[2].to_bytes());
    pending.account_id = Some(account_id);
    pending.key_epoch = Some(current_epoch);
    pending.split_id = Some(uuid::Uuid::new_v4().to_string());
    // A fresh split draws a new random polynomial, so shares delivered from
    // an earlier split can no longer combine with these — every channel has
    // to be redone against the new split.
    pending.cloud_backup_delivered = false;
    pending.cloud_remote = None;
    pending.security_key_delivered = false;
    pending.trusted_contact_acknowledged = false;
    pending.server_finalized = false;
    pending.cloud_active = false;
    save_pending(state, &pending)
}

/// Used by `webauthn::register_security_key` once the recovery passkey is
/// registered: uploads Share 2 (base64) to the server's opaque recovery-
/// share slot, gated by that passkey at release time. Registering the
/// credential without ever storing a share behind it would leave "security
/// key recovery" enabled in the UI but functionally inert.
pub(crate) async fn deliver_security_key_share(
    state: &AppState,
    token: &str,
) -> Result<(), String> {
    // Rotation takes the same mutex. This closes the same-device race; the
    // epoch-CAS on PUT and the postflight probe close the other-device race.
    let _delivery_guard = state.sync_mutex.lock().await;
    let generation = state.session_generation();
    state.ensure_unlocked_since(generation)?;
    ensure_shares_split(state)?;
    let key_epoch = authenticated_local_epoch(state)?;
    let (share2, split_id) = {
        let pending = load_pending(state);
        require_pending_epoch(&pending, key_epoch)?;
        (
            pending
                .share2
                .clone()
                .ok_or("Recovery share was not generated")?,
            pending
                .split_id
                .clone()
                .ok_or("Recovery split ID was not generated")?,
        )
    };

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let mut current_token = token.to_string();
    revalidate_recovery_epoch(state, &client, &mut current_token, key_epoch, generation).await?;
    let account_id = state
        .store
        .load_user_id()
        .map_err(|e| format!("Failed to load account ID: {e}"))?;
    authorize_publication_action(
        &load_pending_checked(state)?,
        &account_id,
        key_epoch,
        vela_client_recovery_policy::PublicationAction::StageServer,
    )?;
    // M18: stage the blind RMS commitment together with the share. Once the
    // split is finalized, any two-share pair — not just this server share —
    // can prove possession of the RMS for enrollment without WebAuthn. The
    // commitment is only the Ed25519 *verifying* half derived from the RMS,
    // so it cannot itself be used to produce proofs (v2 invariant).
    let possession_commitment = {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Vault is locked")?;
        vela_crypto::recovery::rms_possession_commitment(&crypto.rms())
    };
    let share_b64 = B64.encode(&share2);
    let refreshed = client
        .put_recovery_share(
            &current_token,
            RecoveryShareData {
                share: share_b64,
                key_epoch,
                split_id,
                possession_hash: B64.encode(possession_commitment),
            },
        )
        .await
        .map_err(|e| format!("Failed to store recovery share on server: {e}"))?;
    if let Some(refreshed) = refreshed {
        state.session.write().set_server_token(refreshed.clone());
        current_token = refreshed;
    }
    revalidate_recovery_epoch(state, &client, &mut current_token, key_epoch, generation).await?;

    let mut pending = load_pending_checked(state)?;
    require_pending_epoch(&pending, key_epoch)?;
    pending.security_key_delivered = true;
    save_pending(state, &pending)
}

pub fn get_recovery_setup_status(state: &AppState) -> Result<RecoveryStatus, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let pending = load_pending(state);
    let current_epoch = authenticated_local_epoch(state)?;
    let legacy_epoch_one = pending.key_epoch.is_none() && current_epoch == 1;
    if pending.key_epoch != Some(current_epoch) && !legacy_epoch_one {
        return Ok(RecoveryStatus {
            cloud_backup_delivered: false,
            security_key_delivered: false,
            trusted_contact_acknowledged: false,
            setup_in_progress: false,
        });
    }
    Ok(RecoveryStatus {
        cloud_backup_delivered: pending.cloud_backup_delivered,
        security_key_delivered: pending.security_key_delivered,
        trusted_contact_acknowledged: pending.trusted_contact_acknowledged,
        setup_in_progress: pending.share1.is_some(),
    })
}

/// Mint fresh shares of the CURRENT seed immediately after a key rotation.
///
/// Rotation retires every old share by construction (they reconstruct only
/// the retired RMS), but until now nothing re-minted replacements: the local
/// split was deleted and every channel had to be redone from scratch against
/// a lazily-created split nobody had verified. This runs right after local
/// adoption so all three channels can be re-delivered against one split that
/// is *proven* to reconstruct the new seed — checked here, before any share
/// is overwritten or handed out. A split that fails verification is deleted,
/// never delivered (verify-before-overwrite; `vela_crypto::rekey::
/// shares_reconstruct_to`).
///
/// The channels still need their own ceremonies afterwards (WebAuthn
/// registration for the security key, an out-of-band handoff for the trusted
/// contact) — this only guarantees the cached split is good.
pub(crate) fn remint_recovery_setup(state: &AppState) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    ensure_shares_split(state)?;
    let expected = {
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Vault is locked")?;
        crypto.rms()
    };
    let pending = load_pending(state);
    let mut shares = Vec::with_capacity(3);
    for raw in [&pending.share1, &pending.share2, &pending.share3] {
        let bytes = raw.as_deref().ok_or("Recovery shares were not generated")?;
        let share = vela_crypto::shamir::Share::from_bytes(bytes)
            .map_err(|e| format!("Fresh recovery share is malformed: {e}"))?;
        shares.push(share);
    }
    if !vela_crypto::rekey::shares_reconstruct_to(&shares, &expected) {
        // Fail closed: a split that does not reconstruct the unlocked seed
        // must never reach a delivery channel. Drop it so the UI starts a
        // clean setup instead of distributing something useless.
        retire_recovery_setup(state)?;
        return Err(
            "Fresh recovery shares failed verification against the rotated key; \
             recovery setup was reset and must be redone"
                .to_string(),
        );
    }
    tracing::info!("Recovery shares re-minted after key rotation (verified 2-of-3)");
    Ok(())
}

/// Share 3 sealed into an authenticated, recipient-bound envelope.
///
/// Replaces the manual copy flow: the caller supplies the trusted contact's
/// KEM public key, and the result is a self-describing JSON handoff that only
/// the holder of that key can open. It is bound to this exact account, epoch,
/// Shamir split, and share coordinate; nothing useful leaks if it is forwarded
/// or stored anywhere.
///
/// Splitting on demand (rather than at account creation) is what lets the
/// three methods be enabled in any order against one split: `ensure_shares_
/// split` is idempotent while a setup is in progress, so sealing this does
/// not invalidate a share already delivered elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactShareHandoff {
    pub version: u32,
    pub account_id: String,
    pub key_epoch: i64,
    pub split_id: String,
    pub coordinate: u8,
    pub envelope_b64: String,
}

pub async fn seal_trusted_contact_share(
    state: &AppState,
    contact_public_key_b64: &str,
) -> Result<ContactShareHandoff, String> {
    use vela_crypto::kem::HybridPublicKey;
    let _delivery_guard = state.sync_mutex.lock().await;
    let generation = state.session_generation();
    state.ensure_unlocked_since(generation)?;
    ensure_shares_split(state)?;
    let key_epoch = authenticated_local_epoch(state)?;
    let mut pending = load_pending_checked(state)?;
    require_pending_epoch(&pending, key_epoch)?;

    let pk_bytes = B64
        .decode(contact_public_key_b64)
        .map_err(|_| "Contact public key is not valid base64".to_string())?;
    let recipient = HybridPublicKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("Invalid contact public key: {e}"))?;

    // Rotation takes the same mutex; re-check external state before handing
    // out key material, exactly like every other channel delivery.
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let mut token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;
    revalidate_recovery_epoch(state, &client, &mut token, key_epoch, generation).await?;

    let account_id = state
        .store
        .load_user_id()
        .map_err(|e| format!("Failed to load account ID: {e}"))?;
    let split_id = pending
        .split_id
        .clone()
        .ok_or("Recovery split ID was not generated")?;
    let share3_bytes = pending
        .share3
        .clone()
        .ok_or("Recovery share was not generated")?;
    let share3 = vela_crypto::shamir::Share::from_bytes(&share3_bytes)
        .map_err(|e| format!("Cached recovery share is malformed: {e}"))?;

    let context = vela_crypto::recovery::ContactShareContext {
        account_id: account_id.as_str(),
        key_epoch,
        split_id: Some(split_id.as_str()),
        coordinate: share3.x,
    };
    let envelope = vela_crypto::recovery::seal_contact_share(&recipient, &context, &share3)
        .map_err(|e| format!("Failed to seal the trusted-contact envelope: {e}"))?;

    // Record the recipient binding so status/planners can see the channel is
    // no longer a manual copy flow.
    pending.contact_recipient_key = Some(contact_public_key_b64.to_string());
    save_pending(state, &pending)?;

    Ok(ContactShareHandoff {
        version: 1,
        account_id,
        key_epoch,
        split_id,
        coordinate: share3.x,
        envelope_b64: B64.encode(&envelope),
    })
}

/// Mark the trusted-contact envelope as handed over. The app cannot verify
/// that it actually was — there is no channel to check — so this records the
/// user's word for it, which is what the 2-of-3 progress count reads.
pub async fn acknowledge_trusted_contact_share(state: &AppState) -> Result<(), String> {
    let _delivery_guard = state.sync_mutex.lock().await;
    let generation = state.session_generation();
    state.ensure_unlocked_since(generation)?;
    let mut pending = load_pending_checked(state)?;
    let key_epoch = authenticated_local_epoch(state)?;
    require_pending_epoch(&pending, key_epoch)?;
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let mut token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;
    revalidate_recovery_epoch(state, &client, &mut token, key_epoch, generation).await?;
    pending.trusted_contact_acknowledged = true;
    save_pending(state, &pending)
}

/// Generate the ephemeral request keypair shown to a trusted contact during
/// recovery. The requester keeps the secret key in memory only; the public
/// key is handed to the contact, who re-seals their held share to it.
#[derive(serde::Serialize)]
pub struct RecoveryRequest {
    pub public_key_b64: String,
    pub secret_key_b64: String,
}

pub fn generate_recovery_request() -> Result<RecoveryRequest, String> {
    use vela_crypto::kem::{self};
    let (pk, sk) = kem::generate_keypair();
    Ok(RecoveryRequest {
        public_key_b64: B64.encode(pk.to_bytes()),
        secret_key_b64: B64.encode(sk.to_bytes()),
    })
}

/// End setup by dropping the cached shares.
///
/// Until this runs, all three shares sit in `recovery_setup.enc` on this
/// device — which would defeat the point of splitting them across three
/// custodians if it were left that way. The delivered/acknowledged flags
/// survive; only the material goes.
pub async fn finalize_recovery_setup(state: &AppState) -> Result<(), String> {
    let _delivery_guard = state.sync_mutex.lock().await;
    let generation = state.session_generation();
    state.ensure_unlocked_since(generation)?;
    let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
    if !path.exists() {
        return Ok(());
    }
    let mut pending = load_pending_checked(state)?;
    let current_epoch = authenticated_local_epoch(state)?;
    if pending.key_epoch.is_none() && current_epoch == 1 {
        pending.key_epoch = Some(1);
    }
    require_pending_epoch(&pending, current_epoch)?;
    if pending.cloud_active
        && pending.share1.is_none()
        && pending.share2.is_none()
        && pending.share3.is_none()
    {
        return Ok(());
    }
    if !pending.security_key_delivered || !pending.cloud_backup_delivered {
        return Err(
            "Publish both the server share and cloud backup before finalizing recovery".into(),
        );
    }
    let split_id = pending
        .split_id
        .clone()
        .ok_or("Recovery split ID was not generated")?;
    let share1 = pending
        .share1
        .clone()
        .ok_or("Recovery cloud share was not generated")?;
    let remote = pending
        .cloud_remote
        .clone()
        .ok_or("Recovery cloud remote was not recorded")?;
    let user_id = state
        .store
        .load_user_id()
        .map_err(|e| format!("Failed to load account ID: {e}"))?;
    if pending.account_id.is_none() {
        pending.account_id = Some(user_id.clone());
        save_pending(state, &pending)?;
    }
    let client = ApiClient::with_url(state.server_url.read().clone());
    let mut token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;
    revalidate_recovery_epoch(state, &client, &mut token, current_epoch, generation).await?;
    if !pending.server_finalized {
        authorize_publication_action(
            &pending,
            &user_id,
            current_epoch,
            vela_client_recovery_policy::PublicationAction::FinalizeServer,
        )?;
        if let Some(refreshed) = client
            .finalize_recovery_share(&token, current_epoch, &split_id)
            .await
            .map_err(|e| format!("Failed to finalize recovery publication: {e}"))?
        {
            state.session.write().set_server_token(refreshed.clone());
            token = refreshed;
        }
        // Commit this before cloud promotion. A restart now must promote this
        // exact split and is no longer allowed to discard the journal.
        pending.server_finalized = true;
        save_pending(state, &pending)?;
    }

    if !pending.cloud_active {
        authorize_publication_action(
            &pending,
            &user_id,
            current_epoch,
            vela_client_recovery_policy::PublicationAction::PromoteCloudActive,
        )?;
        // Only the winner writes the mutable active pointer. Losing candidates
        // remain at immutable split-specific paths and are ignored by recovery.
        let active_envelope = serde_json::json!({
            "version": 3,
            "user_id": user_id,
            "key_epoch": current_epoch,
            "split_id": split_id,
            "status": "active",
            "share_b64": B64.encode(&share1),
        });
        let active_payload = serde_json::to_vec(&active_envelope).map_err(|e| e.to_string())?;
        let active_path = cloud_backup_active_remote_path(&user_id)?;
        tokio::task::spawn_blocking(move || {
            crate::rclone::upload_bytes(&remote, &active_path, &active_payload)
        })
        .await
        .map_err(|e| format!("Active recovery pointer upload panicked: {e}"))??;
        revalidate_recovery_epoch(state, &client, &mut token, current_epoch, generation).await?;
        pending.cloud_active = true;
        save_pending(state, &pending)?;
    }

    authorize_publication_action(
        &pending,
        &user_id,
        current_epoch,
        vela_client_recovery_policy::PublicationAction::Complete,
    )?;

    pending.share1 = None;
    pending.share2 = None;
    pending.share3 = None;
    save_pending(state, &pending)
}

/// Queue a recovery-contact invitation locally.
///
/// Nothing sends it yet: this records who the user nominated so the UI can
/// list them, and no share travels with it. The share itself goes through
/// [`seal_trusted_contact_share`], sealed to the contact's KEM public key
/// and handed over as an authenticated envelope.
pub async fn send_recovery_invite(state: &AppState, email: &str) -> Result<(), String> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 {
        return Err("Enter a valid recovery contact email address".to_string());
    }

    #[derive(Serialize, Deserialize)]
    struct RecoveryInvite {
        id: String,
        email: String,
        created_at: chrono::DateTime<chrono::Utc>,
        status: String,
    }

    let invites_path = state.store.store_path().join("recovery_invites.json");
    let mut invites: Vec<RecoveryInvite> = if invites_path.exists() {
        std::fs::read_to_string(&invites_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    invites.push(RecoveryInvite {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.clone(),
        created_at: chrono::Utc::now(),
        status: "pending".to_string(),
    });

    let json = serde_json::to_string_pretty(&invites).map_err(|e| e.to_string())?;
    std::fs::write(invites_path, json).map_err(|e| e.to_string())?;

    crate::audit::record_audit_event(state, crate::audit::AuditAction::SettingsChanged);
    tracing::info!("Recovery invite queued for: {}", email);
    Ok(())
}

/// Begin a browser-style WebAuthn registration for the recovery credential,
/// returning the `publicKey` options for the caller's ceremony.
///
/// This is the half a *renderer* drives through `navigator.credentials`. The
/// gpui build has no browser, so it runs the whole ceremony natively through
/// [`crate::webauthn::register_security_key`] instead — both paths end at the
/// same server routes and the same [`deliver_security_key_share`].
pub async fn start_recovery_webauthn_registration(
    state: &AppState,
) -> Result<serde_json::Value, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let (response, new_token) = client
        .start_recovery_webauthn_registration(&token, None, Some("VELA recovery key"))
        .await
        .map_err(|e| format!("Failed to start WebAuthn recovery setup: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    Ok(response.public_key)
}

/// Finish the browser-driven registration and, on success, immediately hand
/// the credential the share it exists to gate.
///
/// Registering without storing a share would leave "security key recovery"
/// enabled in the UI and functionally inert — a recovery method that cannot
/// recover anything.
pub async fn finish_recovery_webauthn_registration(
    state: &AppState,
    credential: serde_json::Value,
) -> Result<bool, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;

    let (response, new_token) = client
        .finish_recovery_webauthn_registration(&token, credential)
        .await
        .map_err(|e| format!("Failed to finish WebAuthn recovery setup: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    if response.registered {
        let current_token = state
            .get_session_token()
            .ok_or_else(|| "No session token available".to_string())?;
        deliver_security_key_share(state, &current_token).await?;
    }

    Ok(response.registered)
}

/// Open a recovery attempt for an account, from hardware that has no session
/// — so this is deliberately unauthenticated, like the enrollment claim.
pub async fn initiate_account_recovery(
    state: &AppState,
    user_id: &str,
) -> Result<serde_json::Value, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let response = client
        .initiate_recovery(user_id)
        .await
        .map_err(|e| format!("Failed to initiate account recovery: {e}"))?;
    Ok(serde_json::json!({
        "recovery_id": response.recovery_id,
        "public_key": response.public_key,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Account recovery (the "every device lost" path, SPEC.md §4.3): reconstruct
// the RMS from Share 1 (cloud backup) + Share 2 (released by the server only
// after a WebAuthn assertion), register this device against the existing
// account, then pull the vault down. Moved from `src-tauri/src/commands/
// recovery.rs`; the WebAuthn half lives in `crate::webauthn`.
// ─────────────────────────────────────────────────────────────────────────────

// The backup used to live at one fixed path shared by every account, which
// meant a second VELA account backed up to the same rclone remote silently
// overwrote the first account's Shamir share (re-onboarding *to recover*
// could destroy the share being recovered). Shares now go to a per-account
// directory and epoch-specific object; both older fixed paths remain readable.
// The pre-account global path is cleaned at the next setup once confirmed ours.

/// Pre-epoch file name inside a per-account directory. It remains readable,
/// but new writes use an epoch-specific name so a slow stale device can never
/// overwrite the replacement uploaded after a rotation.
const LEGACY_ACCOUNT_CLOUD_BACKUP_FILE_NAME: &str = "recovery-share.json";

/// Pre-per-account path, shared by every account. Read for old backups;
/// deleted (only when it holds this account's share) at the next setup.
const LEGACY_CLOUD_BACKUP_REMOTE_PATH: &str = "VELA/recovery-share.json";

/// `user_id` becomes a remote path component, so it gets the same treatment
/// as an rclone remote name: an allowlist that keeps anything path- or
/// flag-like out (`..`, separators, leading dashes).
fn validate_user_id_for_path(user_id: &str) -> Result<(), String> {
    if user_id.is_empty() || user_id.len() > 128 {
        return Err("Invalid account ID".to_string());
    }
    if !user_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Invalid account ID: unexpected characters".to_string());
    }
    Ok(())
}

/// `<per-account dir>/<file>` under the VELA prefix on the chosen remote.
fn cloud_backup_candidate_remote_path(
    user_id: &str,
    key_epoch: i64,
    split_id: &str,
) -> Result<String, String> {
    validate_user_id_for_path(user_id)?;
    if key_epoch < 1 {
        return Err("Invalid recovery-share key epoch".to_string());
    }
    let split_id =
        uuid::Uuid::parse_str(split_id).map_err(|_| "Invalid recovery split ID".to_string())?;
    Ok(format!(
        "VELA/{user_id}/recovery-share-{key_epoch}-{split_id}.json"
    ))
}

fn cloud_backup_active_remote_path(user_id: &str) -> Result<String, String> {
    validate_user_id_for_path(user_id)?;
    Ok(format!("VELA/{user_id}/recovery-share-active.json"))
}

fn is_cloud_backup_file(entry: &str) -> bool {
    let Some(file_name) = entry.rsplit('/').next() else {
        return false;
    };
    file_name == LEGACY_ACCOUNT_CLOUD_BACKUP_FILE_NAME
        || file_name == "recovery-share-active.json"
        || file_name
            .strip_prefix("recovery-share-")
            .and_then(|suffix| suffix.strip_suffix(".json"))
            .is_some_and(|epoch| !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()))
}

#[derive(Debug, Clone, Deserialize)]
struct CloudBackupEnvelope {
    version: u8,
    user_id: String,
    #[serde(default = "default_recovery_key_epoch")]
    key_epoch: i64,
    #[serde(default)]
    split_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    share_b64: String,
}

fn default_recovery_key_epoch() -> i64 {
    1
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudRecoveryShare {
    pub user_id: String,
    pub key_epoch: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_id: Option<String>,
    pub share_b64: String,
}

/// Configured rclone remotes, for the "where was Share 1 uploaded?" picker.
pub async fn list_cloud_backup_remotes() -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(crate::rclone::list_remotes)
        .await
        .map_err(|e| format!("Task panicked: {e}"))?
}

/// Download and parse every Share 1 envelope on a cloud remote — the
/// per-account backups plus any legacy fixed-path backup from an older
/// build. Runs before any vault exists on this device (no unlock check —
/// there is nothing to unlock yet), so the caller can identify the account
/// from the envelope alone before starting the WebAuthn ceremony. One remote
/// may hold backups for several accounts; the caller lets the user pick.
///
/// Individual unreadable entries are skipped rather than failing the whole
/// scan: one corrupt file should not hide the healthy backup next to it.
pub async fn fetch_cloud_recovery_shares(
    remote: String,
) -> Result<Vec<CloudRecoveryShare>, String> {
    // Discover candidates first. If listing fails entirely (older rclone,
    // exotic remote), fall back to the two known locations instead of
    // refusing to recover at all.
    let remote_for_list = remote.clone();
    let listed =
        tokio::task::spawn_blocking(move || crate::rclone::list_files(&remote_for_list, "VELA"))
            .await
            .map_err(|e| format!("Listing task panicked: {e}"))?;
    let candidates: Vec<String> = match listed {
        Ok(entries) => {
            let mut paths: Vec<String> = entries
                .into_iter()
                .filter(|entry| is_cloud_backup_file(entry))
                .map(|entry| format!("VELA/{entry}"))
                .collect();
            if !paths.iter().any(|p| p == LEGACY_CLOUD_BACKUP_REMOTE_PATH) {
                paths.push(LEGACY_CLOUD_BACKUP_REMOTE_PATH.to_string());
            }
            paths
        }
        Err(e) => {
            tracing::warn!("Falling back to known recovery-backup paths after listing failed: {e}");
            vec![LEGACY_CLOUD_BACKUP_REMOTE_PATH.to_string()]
        }
    };

    let mut shares = Vec::new();
    for path in candidates {
        let remote_for_task = remote.clone();
        let path_for_task = path.clone();
        let bytes = tokio::task::spawn_blocking(move || {
            crate::rclone::download_bytes(&remote_for_task, &path_for_task)
        })
        .await
        .map_err(|e| format!("Download task panicked: {e}"))?;
        match bytes.and_then(|b| parse_cloud_backup_envelope(&b)) {
            Ok(share) => shares.push(share),
            Err(e) => tracing::info!("Skipping '{path}' on recovery-share scan: {e}"),
        }
    }

    // Epoch-specific paths deliberately retain older objects. Present only
    // the newest object for each account so existing recovery UIs keep their
    // one-row-per-account behavior; the server response is still the final
    // authority and is checked before reconstruction below.
    let shares = newest_cloud_shares(shares);

    if shares.is_empty() {
        return Err(
            "No VELA recovery backup was found on this remote. Pick the remote used during \
             recovery setup."
                .to_string(),
        );
    }
    Ok(shares)
}

fn parse_cloud_backup_envelope(bytes: &[u8]) -> Result<CloudRecoveryShare, String> {
    let envelope: CloudBackupEnvelope =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid cloud backup file: {e}"))?;
    if envelope.key_epoch < 1 {
        return Err("Invalid cloud backup file: key_epoch must be positive".into());
    }
    let split_id = envelope
        .split_id
        .as_deref()
        .map(|raw| {
            uuid::Uuid::parse_str(raw)
                .map(|id| id.to_string())
                .map_err(|_| "Invalid cloud backup file: split_id is not a UUID".to_string())
        })
        .transpose()?;
    match envelope.version {
        1 | 2 => {
            if envelope.status.as_deref() == Some("candidate") {
                return Err("staged recovery candidate is not active".into());
            }
        }
        3 => {
            if envelope.status.as_deref() != Some("active") {
                return Err("version 3 cloud backup is not the active pointer".into());
            }
            let split_id = split_id
                .as_deref()
                .ok_or("version 3 cloud backup has no split_id")?;
            debug_assert!(uuid::Uuid::parse_str(split_id).is_ok());
        }
        _ => return Err("Unsupported cloud backup version".into()),
    }

    Ok(CloudRecoveryShare {
        user_id: envelope.user_id,
        key_epoch: envelope.key_epoch,
        split_id,
        share_b64: envelope.share_b64,
    })
}

fn newest_cloud_shares(shares: Vec<CloudRecoveryShare>) -> Vec<CloudRecoveryShare> {
    let mut newest_by_account = std::collections::BTreeMap::new();
    for share in shares {
        let replace =
            newest_by_account
                .get(&share.user_id)
                .map_or(true, |current: &CloudRecoveryShare| {
                    current.key_epoch < share.key_epoch
                        || (current.key_epoch == share.key_epoch
                            && current.split_id.is_none()
                            && share.split_id.is_some())
                });
        if replace {
            newest_by_account.insert(share.user_id.clone(), share);
        }
    }
    newest_by_account.into_values().collect()
}

/// Finish account recovery once Share 2 has already been released by the
/// server — i.e. after `crate::webauthn::recover_account_with_security_key`
/// has driven the real FIDO2 assertion and returned the response.
///
/// Split this way (rather than taking a browser-produced `credential` JSON
/// like the Tauri command does) because the native build performs the
/// ceremony itself; everything from "combine the shares" onward is identical.
/// Recovery driven by a *renderer-produced* WebAuthn assertion: exchange the
/// credential for Share 2 at `/recovery/recover`, then run the shared
/// [`complete_account_recovery`].
///
/// The native path does the same thing from the other side —
/// [`crate::webauthn::recover_account_with_security_key`] runs a real CTAP2
/// ceremony itself and calls `complete_account_recovery` with the response it
/// gets back. Splitting at the response is what lets a browser ceremony and a
/// hardware ceremony share everything after it.
#[allow(clippy::too_many_arguments)]
pub async fn complete_account_recovery_with_credential(
    state: &AppState,
    user_id: String,
    share1_b64: String,
    share1_key_epoch: i64,
    share1_split_id: Option<String>,
    credential: serde_json::Value,
    recovery_id: Option<String>,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let recover_resp = client
        .recover_account(&RecoveryRecoverRequest {
            user_id: user_id.clone(),
            recovery_id,
            credential,
        })
        .await
        .map_err(|e| format!("Account recovery failed: {e}"))?;

    complete_account_recovery(
        state,
        user_id,
        share1_b64,
        share1_key_epoch,
        share1_split_id,
        recover_resp,
        password,
        device_name,
    )
    .await
}

pub async fn complete_account_recovery(
    state: &AppState,
    user_id: String,
    share1_b64: String,
    share1_key_epoch: i64,
    share1_split_id: Option<String>,
    recover_resp: crate::api::RecoveryRecoverResponse,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    use vela_crypto::shamir::Share;

    if share1_key_epoch != recover_resp.key_epoch {
        return Err(format!(
            "Cloud recovery share belongs to vault epoch {share1_key_epoch}, but the account is at epoch {}; choose the newest backup",
            recover_resp.key_epoch
        ));
    }

    let share1_bytes = B64
        .decode(&share1_b64)
        .map_err(|_| "Invalid Share 1 encoding".to_string())?;
    let share1 = Share::from_bytes(&share1_bytes).map_err(|e| format!("Invalid Share 1: {e}"))?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let share2_bytes = B64
        .decode(&recover_resp.share)
        .map_err(|_| "Invalid Share 2 encoding".to_string())?;
    let share2 = Share::from_bytes(&share2_bytes).map_err(|e| format!("Invalid Share 2: {e}"))?;

    // ── combine shares → RMS ────────────────────────────────────────────────
    // The shared verified boundary checks account, epoch, channel, distinct
    // coordinates, and authenticated share format before interpolation. The
    // Shamir implementation then authenticates both shares under the same RMS.
    let recovered = vela_crypto::recovery::reconstruct_account_recovery(
        &user_id,
        vela_crypto::recovery::BoundRecoveryShare {
            account_id: &user_id,
            key_epoch: share1_key_epoch,
            split_id: share1_split_id.as_deref(),
            channel: vela_crypto::recovery::RecoveryShareChannel::Cloud,
            recipient_bound: false,
            share: &share1,
        },
        vela_crypto::recovery::BoundRecoveryShare {
            account_id: &user_id,
            key_epoch: recover_resp.key_epoch,
            split_id: recover_resp.split_id.as_deref(),
            channel: vela_crypto::recovery::RecoveryShareChannel::Server,
            recipient_bound: false,
            share: &share2,
        },
    )
    .map_err(|e| format!("Failed to reconstruct vault key: {e}"))?;
    let rms = recovered.rms;
    debug_assert_eq!(recovered.key_epoch, recover_resp.key_epoch);

    finish_recovered_device_setup(
        state,
        &client,
        &user_id,
        rms,
        recover_resp
            .recovery_grant
            .parse()
            .map_err(|e| format!("Invalid recovery grant: {e}"))?,
        password,
        device_name,
    )
    .await
}

/// Complete a recovery that used a trusted-contact share instead of the
/// WebAuthn-released server share (M18): cloud + contact, or server + contact
/// when the caller already holds Share 2 out of band.
///
/// The server never releases its share on this path. Instead the reconstructed
/// RMS proves itself: the client fetches a fresh challenge
/// (`/recovery/initiate-proof`), opens the contact's response envelope with
/// this device's ephemeral request key, reconstructs through the verified
/// pair-selection policy, and redeems a challenge-bound possession proof for
/// a single-use enrollment grant.
pub async fn complete_account_recovery_with_contact(
    state: &AppState,
    user_id: String,
    first_share_b64: String,
    first_share_key_epoch: i64,
    first_share_split_id: Option<String>,
    first_share_channel: RecoveryShareChannelParam,
    request_secret_key_b64: String,
    contact_response_json: String,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    use vela_crypto::kem::HybridSecretKey;
    use vela_crypto::shamir::Share;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let attempt = client
        .initiate_possession_recovery(&user_id)
        .await
        .map_err(|e| format!("Failed to start possession recovery: {e}"))?;
    let challenge = B64
        .decode(&attempt.challenge_b64)
        .map_err(|_| "Invalid possession challenge encoding".to_string())?;

    // The contact's response carries plaintext context metadata next to the
    // sealed envelope. The metadata is untrusted input: it is bound as AEAD
    // associated data, so any relabelling simply fails to open.
    #[derive(Deserialize)]
    struct ContactResponse {
        account_id: String,
        key_epoch: i64,
        split_id: Option<String>,
        coordinate: u8,
        envelope_b64: String,
    }
    let response: ContactResponse = serde_json::from_str(&contact_response_json)
        .map_err(|e| format!("Invalid trusted-contact response: {e}"))?;
    let sk_bytes = B64
        .decode(&request_secret_key_b64)
        .map_err(|_| "Invalid recovery request secret key encoding".to_string())?;
    let request_sk = HybridSecretKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("Invalid recovery request secret key: {e}"))?;
    let envelope_bytes = B64
        .decode(&response.envelope_b64)
        .map_err(|_| "Invalid contact envelope encoding".to_string())?;
    let context = vela_crypto::recovery::ContactShareContext {
        account_id: response.account_id.as_str(),
        key_epoch: response.key_epoch,
        split_id: response.split_id.as_deref(),
        coordinate: response.coordinate,
    };
    let contact_share =
        vela_crypto::recovery::open_contact_share_response(&request_sk, &context, &envelope_bytes)
            .map_err(|e| format!("The trusted-contact response could not be authenticated: {e}"))?;

    let first_bytes = B64
        .decode(&first_share_b64)
        .map_err(|_| "Invalid Share encoding".to_string())?;
    let first_share =
        Share::from_bytes(&first_bytes).map_err(|e| format!("Invalid recovery share: {e}"))?;
    let channel = match first_share_channel {
        RecoveryShareChannelParam::Cloud => RecoveryShareChannel::Cloud,
        RecoveryShareChannelParam::Server => RecoveryShareChannel::Server,
    };

    // The verified boundary enforces same account/epoch/split, distinct
    // channels and coordinates, and an envelope-bound contact share.
    let recovered = vela_crypto::recovery::reconstruct_account_recovery(
        &user_id,
        vela_crypto::recovery::BoundRecoveryShare {
            account_id: &user_id,
            key_epoch: first_share_key_epoch,
            split_id: first_share_split_id.as_deref(),
            channel,
            recipient_bound: false,
            share: &first_share,
        },
        vela_crypto::recovery::BoundRecoveryShare {
            account_id: response.account_id.as_str(),
            key_epoch: response.key_epoch,
            split_id: response.split_id.as_deref(),
            channel: RecoveryShareChannel::TrustedContact,
            recipient_bound: true,
            share: &contact_share,
        },
    )
    .map_err(|e| format!("Failed to reconstruct vault key: {e}"))?;
    if recovered.key_epoch != attempt.key_epoch {
        return Err(format!(
            "Recovery shares belong to vault epoch {}, but the account commitment is at epoch {}; ask your contact for the current split",
            recovered.key_epoch, attempt.key_epoch
        ));
    }

    // Prove possession of the reconstructed RMS for exactly this attempt.
    // The proof is a signature under the RMS-derived private key, verifiable
    // by the server against the public commitment alone.
    let proof = vela_crypto::recovery::rms_possession_sign(
        &recovered.rms,
        &user_id,
        &attempt.recovery_id.to_string(),
        &challenge,
        attempt.key_epoch,
    );
    let grant = client
        .recover_with_possession_proof(
            &user_id,
            &attempt.recovery_id.to_string(),
            &B64.encode(proof),
        )
        .await
        .map_err(|e| format!("Possession proof rejected: {e}"))?;

    finish_recovered_device_setup(
        state,
        &client,
        &user_id,
        recovered.rms,
        grant.recovery_grant,
        password,
        device_name,
    )
    .await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
pub enum RecoveryShareChannelParam {
    Cloud,
    Server,
}

/// Everything both completion paths share after the RMS exists and a single-use
/// recovery grant is in hand: enroll this device, authenticate it, adopt the
/// RMS, and download the vault.
async fn finish_recovered_device_setup(
    state: &AppState,
    client: &ApiClient,
    user_id: &str,
    rms: [u8; 32],
    recovery_grant: uuid::Uuid,
    password: String,
    device_name: Option<String>,
) -> Result<(), String> {
    use crate::api::{EnrollDeviceViaRecoveryRequest, VerifyRequest};
    use crate::audit::{record_audit_event, AuditAction};
    use crate::crypto;

    let user_id = user_id.to_string();
    let recovery_grant = recovery_grant.to_string();

    // ── generate this device's identity keypair ─────────────────────────────
    let new_identity = tokio::task::spawn_blocking(crypto::generate_identity_keypair)
        .await
        .map_err(|e| format!("Thread join error: {e}"))??;

    // ── register this device against the existing account ──────────────────
    let enroll_resp = client
        .enroll_device_via_recovery(&EnrollDeviceViaRecoveryRequest {
            user_id: user_id.clone(),
            recovery_grant,
            hybrid_ek: B64.encode(&new_identity.hybrid_ek),
            hybrid_vk: B64.encode(&new_identity.hybrid_vk),
            device_name: device_name.or_else(|| Some("Recovered Device".to_string())),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Failed to register this device: {e}"))?;
    let device_id = enroll_resp.device_id;

    state
        .store
        .save_device_id_with_user_id(&device_id, &user_id)
        .map_err(|e| format!("Failed to save device ID: {e}"))?;

    // ── authenticate as the newly registered device ─────────────────────────
    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|_| "Invalid challenge encoding")?;

    let sk_for_sig = new_identity.hybrid_sk.clone();
    let device_id_for_sig = device_id.clone();
    let signature = tokio::task::spawn_blocking(move || {
        crypto::create_auth_signature(&sk_for_sig, &challenge_bytes, &device_id_for_sig)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("Challenge signature failed: {e}"))?;

    let verify_resp = client
        .verify_signature(&VerifyRequest {
            device_id: device_id.clone(),
            challenge: challenge_resp.challenge,
            signature,
            device_name: Some(crate::audit::get_device_name()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Server authentication failed: {e}"))?;
    let token = verify_resp.token;

    // ── store RMS, build Crypto, download vault ─────────────────────────────
    crate::biometric::store_password_encrypted(&rms, &password)
        .map_err(|e| format!("Failed to store vault key: {e}"))?;

    let crypto_obj = crypto::Crypto::new(&rms);
    state
        .store
        .save_identity_keys(
            &new_identity.hybrid_ek,
            &new_identity.hybrid_vk,
            &new_identity.hybrid_sk,
            &crypto_obj,
        )
        .map_err(|e| format!("Failed to save identity keys: {e}"))?;

    let (vault, key_epoch) =
        crate::commands::devices::download_vault_after_enrollment(&crypto_obj, &client, &token)
            .await?;
    state
        .store
        .save_vault(&vault, &crypto_obj)
        .map_err(|e| format!("Failed to save vault locally: {e}"))?;
    state
        .store
        .save_key_epoch(&crypto_obj, key_epoch)
        .map_err(|e| format!("Failed to save the recovered vault epoch: {e}"))?;
    crate::sync::set_local_key_epoch(state, key_epoch)?;

    // ── unlock session ───────────────────────────────────────────────────────
    {
        let mut session = state.session.write();
        session.set_server_token(token);
        session.unlock(device_id.clone(), user_id, 15 * 60);
    }
    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto_obj);
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }

    record_audit_event(state, AuditAction::VaultUnlocked);
    tracing::info!(device_id = %device_id, "Account recovery complete");
    Ok(())
}

/// Upload Share 1 to a configured rclone remote (recovery setup, method 1).
/// Requires an unlocked vault — the shares are derived from the RMS.
pub async fn setup_cloud_backup_recovery(state: &AppState, remote: String) -> Result<(), String> {
    let _delivery_guard = state.sync_mutex.lock().await;
    let generation = state.session_generation();
    state.ensure_unlocked_since(generation)?;
    ensure_shares_split(state)?;
    let key_epoch = authenticated_local_epoch(state)?;
    let (share1, split_id) = {
        let pending = load_pending(state);
        require_pending_epoch(&pending, key_epoch)?;
        (
            pending
                .share1
                .clone()
                .ok_or("Recovery share was not generated")?,
            pending
                .split_id
                .clone()
                .ok_or("Recovery split ID was not generated")?,
        )
    };
    let user_id = state
        .store
        .load_user_id()
        .map_err(|e| format!("Failed to load account ID: {e}"))?;
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let mut token = state
        .get_session_token()
        .ok_or_else(|| "No session token available".to_string())?;
    revalidate_recovery_epoch(state, &client, &mut token, key_epoch, generation).await?;
    authorize_publication_action(
        &load_pending_checked(state)?,
        &user_id,
        key_epoch,
        vela_client_recovery_policy::PublicationAction::UploadCloudCandidate,
    )?;

    // Deliberately not further "encrypted" beyond this envelope: a lone
    // Shamir share (below the 2-of-3 threshold) is information-theoretically
    // indistinguishable from random bytes, so it needs no additional secret
    // key to stay confidential — and any such key would itself need to be
    // recoverable without the RMS it's meant to help reconstruct, which is
    // circular. This JSON wrapper exists for versioning/integrity, not
    // confidentiality. `user_id` rides along so a recovering device can
    // identify the account from Share 1 alone, without the user having to
    // remember/re-enter their account ID.
    let envelope = serde_json::json!({
        "version": 3,
        "user_id": user_id,
        "key_epoch": key_epoch,
        "split_id": split_id,
        "status": "candidate",
        "share_b64": B64.encode(&share1),
    });
    let payload = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;

    let remote_path = cloud_backup_candidate_remote_path(&user_id, key_epoch, &split_id)?;
    let remote_for_task = remote.clone();
    let path_for_task = remote_path.clone();
    tokio::task::spawn_blocking(move || {
        crate::rclone::upload_bytes(&remote_for_task, &path_for_task, &payload)
    })
    .await
    .map_err(|e| format!("Upload task panicked: {e}"))??;

    // A different device can rotate while rclone is blocked on network I/O.
    // Do not claim this upload is a live recovery method unless the account is
    // still active at the epoch which produced it.
    revalidate_recovery_epoch(state, &client, &mut token, key_epoch, generation).await?;

    let mut pending = load_pending_checked(state)?;
    require_pending_epoch(&pending, key_epoch)?;
    if pending.split_id.as_deref() != Some(split_id.as_str()) {
        return Err("Another local recovery split replaced this cloud candidate".into());
    }
    pending.cloud_backup_delivered = true;
    pending.cloud_remote = Some(remote.clone());
    save_pending(state, &pending)?;

    // Best-effort migration off the legacy shared path: if it currently
    // holds *this* account's share, delete it so a stale copy can't be
    // mistaken for the live backup. Another account's legacy file — or an
    // unreadable one — is left strictly alone.
    let remote_for_cleanup = remote.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        cleanup_legacy_cloud_backup(&remote_for_cleanup, &user_id)
    })
    .await
    .map_err(|e| format!("Cleanup task panicked: {e}"))?
    {
        tracing::warn!("Legacy recovery-share cleanup skipped: {e}");
    }

    tracing::info!(
        "Recovery Share 1 uploaded to rclone remote '{}' at '{remote_path}'",
        remote
    );
    Ok(())
}

/// Delete the legacy fixed-path backup iff it parses and belongs to
/// `user_id`. Blocking rclone I/O — call from `spawn_blocking`.
fn cleanup_legacy_cloud_backup(remote: &str, user_id: &str) -> Result<(), String> {
    let bytes = match crate::rclone::download_bytes(remote, LEGACY_CLOUD_BACKUP_REMOTE_PATH) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(()), // nothing there (or unreachable) — done
    };
    match parse_cloud_backup_envelope(&bytes) {
        Ok(share) if share.user_id == user_id => {
            crate::rclone::delete_file(remote, LEGACY_CLOUD_BACKUP_REMOTE_PATH)
        }
        Ok(_) => Ok(()), // someone else's backup — leave it alone
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn corrupt_publication_journal_never_mints_a_replacement_split() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&[41u8; 32]);
        let path = state.store.store_path().join(RECOVERY_SETUP_FILE);
        std::fs::write(&path, b"not-an-encrypted-journal").expect("corrupt fixture");

        let error = ensure_shares_split(&state)
            .expect_err("corruption must not be treated as an absent journal");
        assert!(error.contains("could not be decrypted"));
        assert_eq!(
            std::fs::read(path).expect("journal retained"),
            b"not-an-encrypted-journal"
        );
    }

    #[test]
    fn per_account_path_contains_the_user_id() {
        let path = cloud_backup_candidate_remote_path(
            "9f1c3b2a-4d5e-4f60-8a71-b2c3d4e5f607",
            7,
            "11111111-1111-1111-1111-111111111111",
        )
        .unwrap();
        assert_eq!(
            path,
            "VELA/9f1c3b2a-4d5e-4f60-8a71-b2c3d4e5f607/recovery-share-7-11111111-1111-1111-1111-111111111111.json"
        );
    }

    #[test]
    fn per_account_path_rejects_path_traversal_and_separators() {
        let split = "11111111-1111-1111-1111-111111111111";
        assert!(cloud_backup_candidate_remote_path("..", 1, split).is_err());
        assert!(cloud_backup_candidate_remote_path("../other/recovery-share", 1, split).is_err());
        assert!(cloud_backup_candidate_remote_path("a/b", 1, split).is_err());
        assert!(cloud_backup_candidate_remote_path("a\\b", 1, split).is_err());
        assert!(cloud_backup_candidate_remote_path("", 1, split).is_err());
        assert!(cloud_backup_candidate_remote_path("valid-user", 0, split).is_err());
    }

    #[test]
    fn cloud_scan_accepts_only_legacy_or_epoch_named_share_files() {
        assert!(is_cloud_backup_file("user/recovery-share.json"));
        assert!(is_cloud_backup_file("user/recovery-share-12.json"));
        assert!(!is_cloud_backup_file("user/recovery-share-next.json"));
        assert!(!is_cloud_backup_file("user/not-a-recovery-share.json"));
    }

    #[tokio::test]
    async fn recovery_refuses_cloud_and_server_shares_from_different_epochs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        let response = crate::api::RecoveryRecoverResponse {
            share: "unused".into(),
            key_epoch: 8,
            split_id: None,
            recovery_grant: "unused".into(),
        };

        let error = complete_account_recovery(
            &state,
            "user".into(),
            "unused".into(),
            7,
            None,
            response,
            "password".into(),
            None,
        )
        .await
        .expect_err("mixed-epoch shares must fail before reconstruction");
        assert!(error.contains("epoch 7"), "unexpected error: {error}");
        assert!(error.contains("epoch 8"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn contact_pair_recovery_rejects_unauthenticated_contact_envelopes() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        // Server: only the possession initiation is mocked. A legitimate
        // ceremony would then authenticate the contact envelope locally —
        // which fails here before any further network call can happen.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/recovery/initiate-proof"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "recovery_id": "22222222-2222-2222-2222-222222222222",
                "challenge_b64": B64.encode([9u8; 32]),
                "key_epoch": 4,
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        *state.server_url.write() = server.uri();

        let (_request_pk, request_sk) = vela_crypto::kem::generate_keypair();
        // An envelope that was never sealed by the trusted contact: the
        // AEAD binding to account/epoch/split/coordinate must reject it.
        let contact_response = serde_json::json!({
            "account_id": "user",
            "key_epoch": 4,
            "split_id": "33333333-3333-3333-3333-333333333333",
            "coordinate": 3,
            "envelope_b64": B64.encode([1u8; 64]),
        });

        let error = complete_account_recovery_with_contact(
            &state,
            "user".into(),
            "AAAA".into(),
            4,
            Some("33333333-3333-3333-3333-333333333333".into()),
            RecoveryShareChannelParam::Cloud,
            B64.encode(request_sk.to_bytes()),
            contact_response.to_string(),
            "password".into(),
            None,
        )
        .await
        .expect_err("forged contact envelope must fail closed");
        assert!(
            error.contains("could not be authenticated"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn delivery_epoch_probe_requires_matching_active_server_state() {
        async fn probe(server_epoch: i64, server_state: &str) -> Result<(), String> {
            let dir = tempfile::tempdir().expect("tempdir");
            let state = Arc::new(AppState::for_test(dir.path()));
            state.unlock_for_test(&[31u8; 32]);
            {
                let crypto = state.crypto.read();
                state
                    .store
                    .save_key_epoch(crypto.as_ref().unwrap(), 3)
                    .expect("authenticated epoch marker");
            }

            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/vault/epoch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "epoch": server_epoch,
                    "state": server_state,
                })))
                .mount(&server)
                .await;
            let client = ApiClient::new(&server.uri());
            let mut token = "token".to_string();
            revalidate_recovery_epoch(&state, &client, &mut token, 3, state.session_generation())
                .await
        }

        probe(3, "active").await.expect("matching active epoch");
        assert!(probe(3, "freezing").await.is_err());
        assert!(probe(4, "active").await.is_err());
        assert!(probe(2, "active").await.is_err());
    }

    #[test]
    fn envelope_parses_back_into_a_share() {
        let json = serde_json::json!({
            "version": 2,
            "user_id": "user-y",
            "key_epoch": 7,
            "share_b64": "AAAA",
        });
        let share = parse_cloud_backup_envelope(serde_json::to_vec(&json).unwrap().as_slice())
            .expect("envelope should parse");
        assert_eq!(share.user_id, "user-y");
        assert_eq!(share.key_epoch, 7);
        assert_eq!(share.share_b64, "AAAA");
    }

    #[test]
    fn legacy_cloud_envelope_defaults_to_epoch_one() {
        let json = serde_json::json!({
            "version": 1,
            "user_id": "legacy-user",
            "share_b64": "AAAA",
        });
        let share = parse_cloud_backup_envelope(serde_json::to_vec(&json).unwrap().as_slice())
            .expect("legacy envelope should remain recoverable");
        assert_eq!(share.key_epoch, 1);
    }

    #[test]
    fn envelope_rejects_garbage() {
        assert!(parse_cloud_backup_envelope(b"not json").is_err());
        assert!(parse_cloud_backup_envelope(b"{}").is_err());
    }

    #[test]
    fn version_three_requires_an_active_split_bound_pointer() {
        let valid = serde_json::json!({
            "version": 3,
            "user_id": "user-y",
            "key_epoch": 7,
            "split_id": "35E9710A-938B-4A95-AE25-61F8C3C71B97",
            "status": "active",
            "share_b64": "AAAA",
        });
        let parsed = parse_cloud_backup_envelope(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(
            parsed.split_id.as_deref(),
            Some("35e9710a-938b-4a95-ae25-61f8c3c71b97")
        );

        for invalid in [
            serde_json::json!({
                "version": 3, "user_id": "user-y", "key_epoch": 7,
                "status": "active", "share_b64": "AAAA",
            }),
            serde_json::json!({
                "version": 3, "user_id": "user-y", "key_epoch": 7,
                "split_id": "11111111-1111-1111-1111-111111111111",
                "status": "candidate", "share_b64": "AAAA",
            }),
        ] {
            assert!(parse_cloud_backup_envelope(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
    }

    #[test]
    fn cloud_scan_keeps_only_the_highest_epoch_per_account() {
        let share = |user_id: &str, key_epoch: i64| CloudRecoveryShare {
            user_id: user_id.into(),
            key_epoch,
            split_id: None,
            share_b64: format!("share-{key_epoch}"),
        };
        let shares = newest_cloud_shares(vec![
            share("alice", 3),
            share("bob", 2),
            share("alice", 1),
            share("alice", 4),
        ]);
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].user_id, "alice");
        assert_eq!(shares[0].key_epoch, 4);
        assert_eq!(shares[1].user_id, "bob");
        assert_eq!(shares[1].key_epoch, 2);
    }

    /// The re-mint must produce a cached split that provably reconstructs the
    /// currently-unlocked seed — the verify-before-overwrite property, checked
    /// end to end against a real AppState.
    #[test]
    fn remint_produces_shares_that_reconstruct_the_unlocked_seed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        let rms = [9u8; 32];
        state.unlock_for_test(&rms);

        remint_recovery_setup(&state).expect("re-mint succeeds on an unlocked vault");

        // Any 2 of the 3 cached shares reconstruct exactly the unlocked RMS.
        let pending = load_pending(&state);
        assert_eq!(pending.key_epoch, Some(1));
        let shares: Vec<vela_crypto::shamir::Share> = [&pending.share1, &pending.share2]
            .iter()
            .map(|s| vela_crypto::shamir::Share::from_bytes(s.as_deref().unwrap()).unwrap())
            .collect();
        assert!(vela_crypto::rekey::shares_reconstruct_to(&shares, &rms));
    }

    #[test]
    fn cached_split_is_never_reused_across_key_epochs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&[17u8; 32]);
        ensure_shares_split(&state).expect("epoch-one split");
        let first = load_pending(&state);
        let first_share = first.share1.clone().unwrap();
        assert_eq!(first.key_epoch, Some(1));

        {
            let crypto = state.crypto.read();
            state
                .store
                .save_key_epoch(crypto.as_ref().unwrap(), 2)
                .expect("authenticated epoch marker");
        }
        ensure_shares_split(&state).expect("epoch-two split");
        let second = load_pending(&state);
        assert_eq!(second.key_epoch, Some(2));
        assert_ne!(
            second.share1.as_deref(),
            Some(first_share.as_slice()),
            "an old-epoch split must be replaced, not relabelled"
        );
        assert!(!second.cloud_backup_delivered);
        assert!(!second.security_key_delivered);
        assert!(!second.trusted_contact_acknowledged);
    }

    #[test]
    fn recovery_status_never_reports_delivery_from_a_retired_epoch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&[23u8; 32]);
        ensure_shares_split(&state).expect("epoch-one split");
        let mut pending = load_pending(&state);
        pending.cloud_backup_delivered = true;
        pending.security_key_delivered = true;
        pending.trusted_contact_acknowledged = true;
        save_pending(&state, &pending).expect("save delivery flags");
        {
            let crypto = state.crypto.read();
            state
                .store
                .save_key_epoch(crypto.as_ref().unwrap(), 2)
                .expect("advance authenticated epoch marker");
        }

        let status = get_recovery_setup_status(&state).expect("status");
        assert!(!status.cloud_backup_delivered);
        assert!(!status.security_key_delivered);
        assert!(!status.trusted_contact_acknowledged);
        assert!(!status.setup_in_progress);
    }

    #[tokio::test]
    async fn incomplete_legacy_epoch_one_setup_cannot_be_finalized() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&[29u8; 32]);
        ensure_shares_split(&state).expect("split");
        let mut pending = load_pending(&state);
        pending.key_epoch = None;
        save_pending(&state, &pending).expect("save legacy shape");

        let error = finalize_recovery_setup(&state)
            .await
            .expect_err("an incomplete legacy split must not be reported finalized");
        assert!(error.contains("server share and cloud backup"));
        let retained = load_pending(&state);
        assert_eq!(retained.key_epoch, None);
        assert!(retained.share1.is_some());
        assert!(retained.share2.is_some());
        assert!(retained.share3.is_some());
        discard_recovery_setup(&state).expect("discard incomplete setup");
        assert!(!state.store.store_path().join(RECOVERY_SETUP_FILE).exists());
    }

    #[test]
    fn invalid_authenticated_epoch_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&[37u8; 32]);
        let invalid_marker = {
            let crypto = state.crypto.read();
            crypto
                .as_ref()
                .unwrap()
                .encrypt_vault(&serde_json::to_vec(&0i64).unwrap())
                .expect("seal invalid authenticated marker fixture")
        };
        std::fs::write(
            state.store.store_path().join("key_epoch.enc"),
            invalid_marker,
        )
        .expect("write invalid authenticated marker fixture");
        assert!(ensure_shares_split(&state).is_err());
    }

    /// A tampered split must fail closed: no delivery from it, and the bad
    /// cache is dropped so the UI starts clean instead of distributing junk.
    #[test]
    fn remint_fails_closed_and_resets_on_a_corrupt_split() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(AppState::for_test(dir.path()));
        let rms = [11u8; 32];
        state.unlock_for_test(&rms);

        ensure_shares_split(&state).expect("initial split");
        let mut pending = load_pending(&state);
        // Byte 3 sits inside the share's y payload ([marker, version, x, y…]),
        // so the tamper keeps the wire format parseable and must be caught by
        // the reconstruction check, not by deserialization.
        pending.share2.as_mut().unwrap()[3] ^= 0xff;
        save_pending(&state, &pending).expect("save tampered split");

        let err = remint_recovery_setup(&state).expect_err("verification must refuse");
        assert!(
            err.contains("failed verification"),
            "unexpected error: {err}"
        );
        assert!(
            !state.store.store_path().join(RECOVERY_SETUP_FILE).exists(),
            "the unverified split must be deleted, not kept for delivery"
        );
    }
}
