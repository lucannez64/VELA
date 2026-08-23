//! Persistent encrypted storage for VELA vault.

use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};
use vela_crypto::aead::{decrypt, encrypt};
use vela_crypto::kdf;

use crate::crypto::Crypto;
use crate::vault::VaultStore;

const STORE_DIR: &str = "vela";
const VAULT_FILE: &str = "vault.enc";
const RMS_FILE: &str = "rms.enc";
const SETTINGS_FILE: &str = "settings.json";
const DEVICE_ID_FILE: &str = "device_id.json";
const IDENTITY_KEYS_FILE: &str = "identity_keys.enc";
const KEY_EPOCH_FILE: &str = "key_epoch.enc";
const DEVICE_KEY_CONTEXT: &str = "vela device rms protection v1";
const IDENTITY_KEY_FILE_CONTEXT: &str = "vela desktop identity key file v1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeviceIdStore {
    device_id: String,
    user_id: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IdentityKeysStore {
    pub hybrid_ek: Vec<u8>,
    pub hybrid_vk: Vec<u8>,
    /// ML-DSA-87 sk (4896 B) ‖ Ed25519 sk (32 B). Empty for legacy vaults created
    /// before enrollment support; those devices cannot enroll other devices.
    #[serde(default)]
    pub hybrid_sk: Vec<u8>,
    /// ML-KEM-1024 + X25519 share public key (1600 B). Used by others to seal shares for us.
    #[serde(default)]
    pub share_ek: Vec<u8>,
    /// ML-KEM-1024 DK seed (64 B) ‖ X25519 sk (32 B) = 96 B. Used to open shares addressed to us.
    #[serde(default)]
    pub share_dk: Vec<u8>,
    /// The private half of `hybrid_ek`, in the same shape as `share_dk`.
    ///
    /// Empty for every device enrolled before v3: `hybrid_ek` was registered
    /// with its secret discarded, because nothing encapsulated under it. It does
    /// now — the enrollment v3 RMS capsule is sealed to it (audit P-1) — so
    /// devices that join from here on keep it. The old ones do not need it: a
    /// capsule is only ever sealed to a device that is *joining*.
    #[serde(default)]
    pub hybrid_dk: Vec<u8>,
}

pub struct Store {
    store_path: PathBuf,
    /// Set when a legacy plaintext identity-keys file was found and migrated.
    /// Read once by the unlock path, which turns it into an audit entry the
    /// user can actually see.
    plaintext_identity_migrated: std::sync::atomic::AtomicBool,
    /// Last-known Settings. The file is small but `load_settings` used to hit
    /// disk + JSON-parse on *every* call — including once per user-input
    /// event (auto-lock deadline resets) and per scheduler tick — and the
    /// parsed value is what every caller wants. Writes go through
    /// [`Store::save_settings`], which refreshes the cache, so staleness
    /// would require the settings file to be edited out-of-band by another
    /// process while the app is running.
    settings_cache: std::sync::RwLock<Option<std::sync::Arc<crate::settings::Settings>>>,
}

impl Store {
    /// Whether a plaintext identity-keys file was migrated since the last call,
    /// clearing the flag. Consumed by the unlock path so the user is told once
    /// per occurrence rather than on every read.
    pub fn take_plaintext_identity_migration(&self) -> bool {
        self.plaintext_identity_migrated
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn new() -> anyhow::Result<Self> {
        let project_dirs = ProjectDirs::from("com", "vela", "VELA")
            .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;

        let data_dir = project_dirs.data_dir().join(STORE_DIR);
        fs::create_dir_all(&data_dir)?;
        restrict_directory(&data_dir)?;

        Ok(Self {
            store_path: data_dir,
            plaintext_identity_migrated: std::sync::atomic::AtomicBool::new(false),
            settings_cache: std::sync::RwLock::new(None),
        })
    }

    /// A store rooted at an explicit directory instead of the platform app
    /// data dir — used by tests (hermetic, no touching the developer's real
    /// vault) and any future portable/CLI tooling.
    pub fn new_at(path: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&path)?;
        restrict_directory(&path)?;
        Ok(Self {
            store_path: path,
            plaintext_identity_migrated: std::sync::atomic::AtomicBool::new(false),
            settings_cache: std::sync::RwLock::new(None),
        })
    }

    pub fn store_path(&self) -> &PathBuf {
        &self.store_path
    }

    fn derive_device_key(device_key: &[u8; 32]) -> [u8; 32] {
        kdf::derive(DEVICE_KEY_CONTEXT, device_key)
            .as_bytes()
            .clone()
    }

    fn derive_identity_file_key(crypto: &Crypto) -> [u8; 32] {
        kdf::derive(IDENTITY_KEY_FILE_CONTEXT, crypto.identity_key().as_bytes())
            .as_bytes()
            .clone()
    }

    /// Re-seal every RMS-derived secret file across a seed rotation
    /// (docs/VAULT_REKEYING_DESIGN.md §6 step 5).
    ///
    /// Each file is decrypted under its old derivation and re-encrypted under
    /// the new one with a fresh nonce — the ciphertext bytes on disk change,
    /// the plaintext never touches anything but a `Zeroizing` buffer inside
    /// `vela_crypto::rekey::rekey_blob`. Files are rewritten atomically via
    /// [`write_secret_file`]. Missing files (no audit log yet, no shares) are
    /// skipped; a corrupt one is an error, because silently leaving a file on
    /// the old key would strand it after the rotation completes.
    pub fn rekey_secret_files(&self, old: &Crypto, new: &Crypto) -> anyhow::Result<()> {
        use vela_crypto::rekey;

        let old_rms = old.rms();
        let new_rms = new.rms();
        let mut rewrites: Vec<(PathBuf, Vec<u8>, Vec<u8>)> = Vec::new();

        // These files all use the vault envelope. Build every replacement
        // before touching disk so a corrupt late file cannot leave an earlier
        // file stranded under the new seed.
        for file in [
            VAULT_FILE,
            "audit.enc",
            "shares.enc",
            "sync_conflicts.enc",
            "recovery_setup.enc",
            KEY_EPOCH_FILE,
        ] {
            let path = self.store_path.join(file);
            if !path.exists() {
                continue;
            }
            let ct = fs::read(&path)?;
            // A process may have died after replacing this file but before the
            // rest of the migration completed. Treat an already-new file as a
            // successful no-op so the durable RMS migration journal can resume
            // a mixed on-disk state safely.
            if new.decrypt_vault(&ct).is_ok() {
                continue;
            }
            let rekeyed =
                rekey::rekey_blob(&old_rms, &new_rms, kdf::contexts::VAULT_ENCRYPTION, &ct)?;
            rewrites.push((path, ct, rekeyed));
        }

        // identity_keys.enc has its own derivation context off the identity key.
        let identity_path = self.store_path.join(IDENTITY_KEYS_FILE);
        if identity_path.exists() {
            let ct = fs::read(&identity_path)?;
            let old_key = Self::derive_identity_file_key(old);
            let new_key = Self::derive_identity_file_key(new);
            if crate::crypto::Crypto::decrypt_with_key(&new_key, &ct).is_err() {
                let plaintext = crate::crypto::Crypto::decrypt_with_key(&old_key, &ct)?;
                let rekeyed = crate::crypto::Crypto::encrypt_with_key(&new_key, &plaintext)?;
                drop(plaintext);
                rewrites.push((identity_path, ct, rekeyed));
            }
        }

        self.apply_rekey_rewrites(rewrites)
    }

    fn apply_rekey_rewrites(
        &self,
        rewrites: Vec<(PathBuf, Vec<u8>, Vec<u8>)>,
    ) -> anyhow::Result<()> {
        // Each individual write is temp+rename atomic. If a later rename or
        // permission update fails, restore every file already replaced before
        // returning. This gives the caller an all-old or all-new local store.
        let mut replaced = 0usize;
        for (path, _, rekeyed) in &rewrites {
            if let Err(write_err) = write_secret_file(path, rekeyed) {
                let mut rollback_errors = Vec::new();
                for (rollback_path, original, _) in rewrites[..replaced].iter().rev() {
                    if let Err(e) = write_secret_file(rollback_path, original) {
                        rollback_errors.push(format!("{}: {e}", rollback_path.display()));
                    }
                }
                if rollback_errors.is_empty() {
                    return Err(write_err);
                }
                anyhow::bail!(
                    "{write_err}; rollback also failed for {}",
                    rollback_errors.join(", ")
                );
            }
            replaced += 1;
        }

        Ok(())
    }

    const RMS_MIGRATION_FILE: &'static str = "rms_migration.json";
    const RMS_MIGRATION_CONTEXT: &'static str = "vela rms migration journal v1";

    /// Persist a two-way, encrypted bridge between the old and new RMS before
    /// changing any consumer. Whichever RMS the OS/password store yields after
    /// a crash can open exactly one side and recover the other.
    pub(crate) fn begin_rms_migration(
        &self,
        old_rms: &[u8; 32],
        new_rms: &[u8; 32],
        new_epoch: i64,
    ) -> anyhow::Result<()> {
        #[derive(serde::Serialize)]
        struct Journal<'a> {
            version: u8,
            new_epoch: i64,
            new_under_old: &'a [u8],
            old_under_new: &'a [u8],
        }

        let old_key = kdf::derive(Self::RMS_MIGRATION_CONTEXT, old_rms);
        let new_key = kdf::derive(Self::RMS_MIGRATION_CONTEXT, new_rms);
        let new_under_old = crate::crypto::Crypto::encrypt_with_key(old_key.as_bytes(), new_rms)?;
        let old_under_new = crate::crypto::Crypto::encrypt_with_key(new_key.as_bytes(), old_rms)?;
        let bytes = serde_json::to_vec(&Journal {
            version: 1,
            new_epoch,
            new_under_old: &new_under_old,
            old_under_new: &old_under_new,
        })?;
        let path = self.store_path.join(Self::RMS_MIGRATION_FILE);
        write_secret_file(&path, &bytes)?;
        // Ordering is the safety property: the journal must reach stable
        // storage before any file can reach the new key. Rename alone is
        // atomic but does not guarantee persistence across power loss.
        fs::File::open(&path)?.sync_all()?;
        #[cfg(unix)]
        fs::File::open(&self.store_path)?.sync_all()?;
        Ok(())
    }

    /// Open a pending migration journal with either endpoint RMS. Returns the
    /// complete `(old, new, epoch)` tuple after cross-checking both capsules.
    pub(crate) fn load_rms_migration(
        &self,
        current_rms: &[u8; 32],
    ) -> anyhow::Result<Option<([u8; 32], [u8; 32], i64)>> {
        #[derive(serde::Deserialize)]
        struct Journal {
            version: u8,
            new_epoch: i64,
            new_under_old: Vec<u8>,
            old_under_new: Vec<u8>,
        }

        let path = self.store_path.join(Self::RMS_MIGRATION_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let journal: Journal = serde_json::from_slice(&fs::read(path)?)?;
        anyhow::ensure!(
            journal.version == 1,
            "unsupported RMS migration journal version"
        );
        let current_key = kdf::derive(Self::RMS_MIGRATION_CONTEXT, current_rms);

        let (old, new) = if let Ok(opened) =
            crate::crypto::Crypto::decrypt_with_key(current_key.as_bytes(), &journal.new_under_old)
        {
            let new: [u8; 32] = opened
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid new RMS in migration journal"))?;
            (*current_rms, new)
        } else {
            let opened = crate::crypto::Crypto::decrypt_with_key(
                current_key.as_bytes(),
                &journal.old_under_new,
            )?;
            let old: [u8; 32] = opened
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid old RMS in migration journal"))?;
            (old, *current_rms)
        };

        // Authenticate the opposite direction too. This detects a corrupt or
        // mismatched journal before any file is rewritten during recovery.
        let old_key = kdf::derive(Self::RMS_MIGRATION_CONTEXT, &old);
        let check_new =
            crate::crypto::Crypto::decrypt_with_key(old_key.as_bytes(), &journal.new_under_old)?;
        anyhow::ensure!(
            check_new.as_slice() == new,
            "RMS migration journal mismatch"
        );
        let new_key = kdf::derive(Self::RMS_MIGRATION_CONTEXT, &new);
        let check_old =
            crate::crypto::Crypto::decrypt_with_key(new_key.as_bytes(), &journal.old_under_new)?;
        anyhow::ensure!(
            check_old.as_slice() == old,
            "RMS migration journal mismatch"
        );

        Ok(Some((old, new, journal.new_epoch)))
    }

    pub(crate) fn finish_rms_migration(&self) -> anyhow::Result<()> {
        let path = self.store_path.join(Self::RMS_MIGRATION_FILE);
        // Do not let the journal deletion become durable ahead of any consumer
        // rewrite or the epoch marker. If power fails before this barrier, the
        // journal remains the recovery authority; after it, every local file is
        // guaranteed to match the new RMS.
        for file in [
            VAULT_FILE,
            "audit.enc",
            "shares.enc",
            "sync_conflicts.enc",
            "recovery_setup.enc",
            IDENTITY_KEYS_FILE,
            KEY_EPOCH_FILE,
            "sync_meta.json",
        ] {
            let consumer = self.store_path.join(file);
            if consumer.exists() {
                fs::File::open(consumer)?.sync_all()?;
            }
        }
        #[cfg(unix)]
        fs::File::open(&self.store_path)?.sync_all()?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        #[cfg(unix)]
        fs::File::open(&self.store_path)?.sync_all()?;
        Ok(())
    }

    /// Persist the adopted key epoch under the RMS itself. `sync_meta.json` is
    /// useful merge metadata but is not an authority boundary: if it is lost
    /// or corrupt, this redundant authenticated marker lets a device prove
    /// that its current RMS already belongs to the server's epoch.
    pub(crate) fn save_key_epoch(&self, crypto: &Crypto, epoch: i64) -> anyhow::Result<()> {
        let plaintext = serde_json::to_vec(&epoch)?;
        let ciphertext = crypto.encrypt_vault(&plaintext)?;
        write_secret_file(&self.store_path.join(KEY_EPOCH_FILE), &ciphertext)
    }

    pub(crate) fn load_key_epoch(&self, crypto: &Crypto) -> anyhow::Result<Option<i64>> {
        let path = self.store_path.join(KEY_EPOCH_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let plaintext = crypto.decrypt_vault(&fs::read(path)?)?;
        let epoch: i64 = serde_json::from_slice(&plaintext)?;
        anyhow::ensure!(epoch >= 1, "invalid local key epoch");
        Ok(Some(epoch))
    }

    pub fn save_vault(&self, vault: &VaultStore, crypto: &Crypto) -> anyhow::Result<()> {
        let plaintext = serde_json::to_vec(vault)?;
        let ciphertext = crypto.encrypt_vault(&plaintext)?;

        let vault_path = self.store_path.join(VAULT_FILE);

        if let Some(parent) = vault_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        write_secret_file(&vault_path, &ciphertext)?;

        Ok(())
    }

    pub fn load_vault(&self, crypto: &Crypto) -> anyhow::Result<VaultStore> {
        let vault_path = self.store_path.join(VAULT_FILE);

        if !vault_path.exists() {
            tracing::info!("No vault file found, returning empty vault");
            return Ok(VaultStore::new());
        }

        let ciphertext = fs::read(&vault_path)?;
        if ciphertext.len() < 40 {
            return Err(anyhow::anyhow!("Vault file corrupted: too small"));
        }

        let plaintext = crypto.decrypt_vault(&ciphertext)?;
        let vault: VaultStore = serde_json::from_slice(&plaintext)?;
        Ok(vault)
    }

    pub fn save_rms(&self, rms: &[u8; 32], device_key: &[u8; 32]) -> anyhow::Result<()> {
        let derived_key = Self::derive_device_key(device_key);
        let ciphertext = encrypt(&derived_key, rms)?;

        let rms_path = self.store_path.join(RMS_FILE);

        if let Some(parent) = rms_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        write_secret_file(&rms_path, &ciphertext)?;

        Ok(())
    }

    pub fn load_rms(&self, device_key: &[u8; 32]) -> anyhow::Result<Option<[u8; 32]>> {
        let rms_path = self.store_path.join(RMS_FILE);

        if !rms_path.exists() {
            return Ok(None);
        }

        let derived_key = Self::derive_device_key(device_key);
        let ciphertext = fs::read(rms_path)?;
        let plaintext = decrypt(&derived_key, &ciphertext)?;

        if plaintext.len() != 32 {
            anyhow::bail!(
                "Corrupt RMS file: expected 32 bytes, got {}",
                plaintext.len()
            );
        }
        let mut rms = [0u8; 32];
        rms.copy_from_slice(&plaintext[..32]);
        Ok(Some(rms))
    }

    pub fn has_existing_vault(&self) -> bool {
        self.store_path.join(RMS_FILE).exists() || self.store_path.join(VAULT_FILE).exists()
    }

    pub fn save_settings(&self, settings: &crate::settings::Settings) -> anyhow::Result<()> {
        let settings_path = self.store_path.join(SETTINGS_FILE);

        if let Some(parent) = settings_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let json = serde_json::to_string_pretty(settings)?;
        write_secret_file(&settings_path, json.as_bytes())?;
        // Only refresh the cache after the write has actually succeeded —
        // a failed save must not make the cache claim a state that never
        // reached disk.
        *self.settings_cache.write().unwrap() = Some(std::sync::Arc::new(settings.clone()));
        Ok(())
    }

    pub fn load_settings(&self) -> anyhow::Result<crate::settings::Settings> {
        if let Some(cached) = self.settings_cache.read().unwrap().as_ref() {
            return Ok((**cached).clone());
        }

        let settings_path = self.store_path.join(SETTINGS_FILE);

        let settings = if !settings_path.exists() {
            crate::settings::Settings::default()
        } else {
            let json = fs::read_to_string(settings_path)?;
            serde_json::from_str(&json)?
        };

        *self.settings_cache.write().unwrap() = Some(std::sync::Arc::new(settings.clone()));
        Ok(settings)
    }

    pub fn save_device_id(&self, device_id: &str) -> anyhow::Result<()> {
        self.save_device_id_with_user_id(device_id, &format!("user-{}", &device_id[..8]))
    }

    pub fn save_device_id_with_user_id(
        &self,
        device_id: &str,
        user_id: &str,
    ) -> anyhow::Result<()> {
        let device_path = self.store_path.join(DEVICE_ID_FILE);

        if let Some(parent) = device_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let store = DeviceIdStore {
            device_id: device_id.to_string(),
            user_id: user_id.to_string(),
        };
        let json = serde_json::to_string_pretty(&store)?;
        write_secret_file(&device_path, json.as_bytes())?;
        Ok(())
    }

    pub fn load_device_id(&self) -> anyhow::Result<String> {
        let device_path = self.store_path.join(DEVICE_ID_FILE);

        if !device_path.exists() {
            let new_id = crate::device::DeviceInfo::generate_device_id();
            self.save_device_id(&new_id)?;
            return Ok(new_id);
        }

        let json = fs::read_to_string(device_path)?;
        let store: DeviceIdStore = serde_json::from_str(&json)?;
        Ok(store.device_id)
    }

    pub fn load_user_id(&self) -> anyhow::Result<String> {
        let device_path = self.store_path.join(DEVICE_ID_FILE);

        if !device_path.exists() {
            let device_id = crate::device::DeviceInfo::generate_device_id();
            let user_id = format!("user-{}", &device_id[..8]);
            self.save_device_id(&device_id)?;
            return Ok(user_id);
        }

        let json = fs::read_to_string(device_path)?;
        let store: DeviceIdStore = serde_json::from_str(&json)?;
        Ok(store.user_id)
    }

    pub fn save_identity_keys(
        &self,
        hybrid_ek: &[u8],
        hybrid_vk: &[u8],
        hybrid_sk: &[u8],
        crypto: &Crypto,
    ) -> anyhow::Result<()> {
        self.save_identity_keys_full(
            &IdentityKeysStore {
                hybrid_ek: hybrid_ek.to_vec(),
                hybrid_vk: hybrid_vk.to_vec(),
                hybrid_sk: hybrid_sk.to_vec(),
                ..Default::default()
            },
            crypto,
        )
    }

    /// Write the whole identity.
    ///
    /// Takes the record by name rather than as a row of byte slices: there are
    /// now three secret keys in here of similar length and confusable name
    /// (`hybrid_sk` signs, `share_dk` opens shares, `hybrid_dk` opens this
    /// device's own capsule), and a positional call site that transposed two of
    /// them would compile and produce a device broken in a way only visible
    /// much later.
    pub fn save_identity_keys_full(
        &self,
        keys: &IdentityKeysStore,
        crypto: &Crypto,
    ) -> anyhow::Result<()> {
        let identity_path = self.store_path.join(IDENTITY_KEYS_FILE);

        if let Some(parent) = identity_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let plaintext = serde_json::to_vec(keys)?;
        let key = Self::derive_identity_file_key(crypto);
        let ciphertext = encrypt(&key, &plaintext)?;
        write_secret_file(&identity_path, &ciphertext)?;
        Ok(())
    }

    pub fn load_identity_keys(&self, crypto: &Crypto) -> anyhow::Result<Option<IdentityKeysStore>> {
        let identity_path = self.store_path.join(IDENTITY_KEYS_FILE);

        if !identity_path.exists() {
            return Ok(None);
        }

        let bytes = fs::read(&identity_path)?;

        // Try to decrypt before assuming anything about the format.
        //
        // This used to sniff the first byte for '{'. An encrypted blob opens
        // with a 24-byte random nonce, so once every 256 writes that byte *is*
        // '{' (0x7B) — and the loader then took a perfectly good ciphertext for
        // a legacy plaintext file, failed to parse it as JSON, and the vault
        // could not load its identity keys at all. CI caught it as a flaky
        // test; it was a real 1-in-256 failure in this function.
        //
        // Decryption is a decision, not a guess: a legacy plaintext file will
        // never satisfy the AEAD tag, and a real ciphertext always will.
        let key = Self::derive_identity_file_key(crypto);
        let store: IdentityKeysStore = match decrypt(&key, &bytes) {
            Ok(plaintext) => serde_json::from_slice(&plaintext)?,
            Err(decrypt_error) => {
                // Not ours to decrypt. Either a legacy plaintext file (private
                // signing keys in the clear!) or a file we have no key for.
                match serde_json::from_slice::<IdentityKeysStore>(&bytes) {
                    Ok(legacy) => {
                        tracing::warn!(
                            "Identity keys file is plaintext; migrating to encrypted format now"
                        );
                        self.plaintext_identity_migrated
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        legacy
                    }
                    // Report the decryption failure, not the JSON one: the file
                    // is encrypted and we could not open it, which is the
                    // actionable half.
                    Err(_) => return Err(decrypt_error.into()),
                }
            }
        };
        self.save_identity_keys_full(&store, crypto)?;
        Ok(Some(store))
    }
}

pub fn write_secret_file(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        restrict_directory(parent)?;
    }
    // Atomic write: tmp file + rename, so a crash mid-write can never leave a
    // truncated secret file behind.
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, bytes)?;
    restrict_file(&tmp_path)?;
    fs::rename(&tmp_path, path)?;
    restrict_file(path)?;
    Ok(())
}

fn restrict_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn restrict_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

impl Default for Store {
    fn default() -> Self {
        Self::new().expect("Failed to create store")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;
    use crate::vault::{VaultItem, VaultMeta, VaultStore};
    use chrono::Utc;

    fn test_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new_at(dir.path().join("vela")).unwrap();
        (dir, store)
    }

    fn test_crypto() -> Crypto {
        Crypto::new(&Crypto::generate_rms())
    }

    fn test_identity_keys(share_dk: &[u8]) -> IdentityKeysStore {
        IdentityKeysStore {
            hybrid_ek: b"ek".to_vec(),
            hybrid_vk: b"vk".to_vec(),
            hybrid_sk: b"sk".to_vec(),
            share_ek: b"share-ek".to_vec(),
            share_dk: share_dk.to_vec(),
            hybrid_dk: b"hybrid-dk".to_vec(),
        }
    }

    fn sample_vault() -> VaultStore {
        let now = Utc::now();
        let mut vault = VaultStore::new();
        vault.add_item(VaultItem::Login {
            meta: VaultMeta {
                id: "1".into(),
                name: "GitHub".into(),
                notes: None,
                created_at: now,
                updated_at: now,
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            url: "https://github.com".into(),
            username: "alice".into(),
            pass: "hunter2pw".into(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        });
        vault
    }

    #[test]
    fn vault_save_load_roundtrip() {
        let (_dir, store) = test_store();
        let crypto = test_crypto();
        let vault = sample_vault();

        store.save_vault(&vault, &crypto).unwrap();

        // The file on disk must be ciphertext, not JSON.
        let raw = fs::read(store.store_path().join(VAULT_FILE)).unwrap();
        assert!(
            !raw.windows(8).any(|w| w == b"github.com".as_slice()),
            "plaintext must not appear in vault.enc"
        );

        let loaded = store.load_vault(&crypto).unwrap();
        assert_eq!(loaded.items.len(), 1);
        assert_eq!(loaded.get_item("1").unwrap().username(), Some("alice"));
    }

    #[test]
    fn vault_file_permissions_are_owner_only() {
        let (_dir, store) = test_store();
        store.save_vault(&sample_vault(), &test_crypto()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.store_path().join(VAULT_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "vault.enc must be 0600");
        }
    }

    #[test]
    fn load_vault_without_file_returns_empty() {
        let (_dir, store) = test_store();
        let loaded = store.load_vault(&test_crypto()).unwrap();
        assert!(loaded.items.is_empty());
    }

    #[test]
    fn load_vault_rejects_truncated_file() {
        let (_dir, store) = test_store();
        fs::write(store.store_path().join(VAULT_FILE), b"tiny").unwrap();
        let err = store.load_vault(&test_crypto()).unwrap_err().to_string();
        assert!(err.contains("corrupted"), "unexpected error: {err}");
    }

    #[test]
    fn rms_roundtrip_and_wrong_key_rejection() {
        let (_dir, store) = test_store();
        let rms = Crypto::generate_rms();
        let device_key = [7u8; 32];

        assert!(store.load_rms(&device_key).unwrap().is_none());
        store.save_rms(&rms, &device_key).unwrap();
        assert_eq!(store.load_rms(&device_key).unwrap(), Some(rms));

        let wrong_key = [9u8; 32];
        assert!(store.load_rms(&wrong_key).is_err());
    }

    #[test]
    fn has_existing_vault_tracks_files() {
        let (_dir, store) = test_store();
        assert!(!store.has_existing_vault());
        store.save_rms(&Crypto::generate_rms(), &[1u8; 32]).unwrap();
        assert!(store.has_existing_vault());
    }

    #[test]
    fn settings_roundtrip_and_default_when_missing() {
        let (_dir, store) = test_store();
        let defaults = store.load_settings().unwrap();
        assert_eq!(defaults.auto_lock_minutes, 5);

        let mut settings = crate::settings::Settings::default();
        settings.auto_lock_minutes = 42;
        settings.theme = crate::settings::Theme::Gruvbox;
        store.save_settings(&settings).unwrap();

        let loaded = store.load_settings().unwrap();
        assert_eq!(loaded.auto_lock_minutes, 42);
        assert_eq!(loaded.theme, crate::settings::Theme::Gruvbox);
    }

    #[test]
    fn device_id_is_generated_once_and_stable() {
        let (_dir, store) = test_store();
        let first = store.load_device_id().unwrap();
        let second = store.load_device_id().unwrap();
        assert_eq!(first, second, "device id must persist across loads");

        store
            .save_device_id_with_user_id("dev-x", "user-y")
            .unwrap();
        assert_eq!(store.load_device_id().unwrap(), "dev-x");
        assert_eq!(store.load_user_id().unwrap(), "user-y");
    }

    #[test]
    fn identity_keys_roundtrip_encrypted() {
        let (_dir, store) = test_store();
        let crypto = test_crypto();
        store
            .save_identity_keys_full(&test_identity_keys(b"share-dk"), &crypto)
            .unwrap();

        let raw = fs::read(store.store_path().join(IDENTITY_KEYS_FILE)).unwrap();
        assert_ne!(
            raw.first(),
            Some(&b'{'),
            "identity keys must not be plaintext"
        );

        let loaded = store.load_identity_keys(&crypto).unwrap().unwrap();
        assert_eq!(loaded.hybrid_ek, b"ek");
        assert_eq!(loaded.hybrid_vk, b"vk");
        assert_eq!(loaded.hybrid_sk, b"sk");
        assert_eq!(loaded.share_ek, b"share-ek");
        assert_eq!(loaded.share_dk, b"share-dk");

        // A different RMS cannot read them.
        assert!(store.load_identity_keys(&test_crypto()).is_err());
    }

    #[test]
    fn the_plaintext_migration_flag_is_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new_at(dir.path().to_path_buf()).unwrap();

        assert!(
            !store.take_plaintext_identity_migration(),
            "nothing migrated yet"
        );
        store
            .plaintext_identity_migrated
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(store.take_plaintext_identity_migration());
        assert!(
            !store.take_plaintext_identity_migration(),
            "taking it clears it, so the user is told once rather than on every read"
        );
    }

    #[test]
    fn an_encrypted_file_that_happens_to_start_with_a_brace_still_loads() {
        // The loader used to decide "is this plaintext?" from the first byte.
        // An encrypted blob opens with a random nonce, so once every 256 writes
        // that byte is '{' and a perfectly good ciphertext was taken for legacy
        // JSON — the vault then failed to load its identity keys at all.
        //
        // Rewriting until the nonce starts with '{' makes that case certain
        // instead of one-in-256, so this fails deterministically if the sniffing
        // ever comes back.
        let (_dir, store) = test_store();
        let crypto = test_crypto();
        let path = store.store_path().join(IDENTITY_KEYS_FILE);

        let mut attempts = 0;
        loop {
            store
                .save_identity_keys_full(&test_identity_keys(b"sdk"), &crypto)
                .unwrap();
            if fs::read(&path).unwrap().first() == Some(&b'{') {
                break;
            }
            attempts += 1;
            assert!(
                attempts < 10_000,
                "never produced a nonce starting with '{{'"
            );
        }

        let loaded = store.load_identity_keys(&crypto).unwrap().unwrap();
        assert_eq!(loaded.hybrid_sk, b"sk");
        assert!(
            !store.take_plaintext_identity_migration(),
            "a ciphertext must not be reported as a plaintext migration"
        );
    }

    #[test]
    fn legacy_plaintext_identity_file_is_migrated_to_encrypted() {
        let (_dir, store) = test_store();
        let crypto = test_crypto();
        // Distinctive enough that finding it in the file below means it is
        // really there, rather than two bytes of ciphertext coinciding.
        const SECRET: &[u8] = b"PRIVATE-SIGNING-KEY-MATERIAL";
        let legacy = IdentityKeysStore {
            hybrid_ek: b"ek".to_vec(),
            hybrid_vk: b"vk".to_vec(),
            hybrid_sk: SECRET.to_vec(),
            share_ek: vec![],
            share_dk: vec![],
            // A file this old predates the identity KEM secret entirely, which
            // is what `#[serde(default)]` on the field is for.
            hybrid_dk: vec![],
        };
        fs::write(
            store.store_path().join(IDENTITY_KEYS_FILE),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();

        let loaded = store.load_identity_keys(&crypto).unwrap().unwrap();
        assert_eq!(loaded.hybrid_ek, b"ek");

        // After load, the file must have been re-encrypted in place.
        //
        // Testing the *first byte* for '{' was a 1-in-256 flake: an encrypted
        // blob opens with a random nonce, which is '{' (0x7B) once every 256
        // runs. It also was not the property that matters. These are: the key
        // material is no longer readable in the file, the file no longer parses
        // as the plaintext format, and the encrypted form still loads.
        let raw = fs::read(store.store_path().join(IDENTITY_KEYS_FILE)).unwrap();
        assert!(
            !raw.windows(SECRET.len()).any(|window| window == SECRET),
            "private key is still in the clear after migration"
        );
        assert!(
            serde_json::from_slice::<IdentityKeysStore>(&raw).is_err(),
            "file still parses as the plaintext format"
        );
        assert_eq!(
            store
                .load_identity_keys(&crypto)
                .unwrap()
                .unwrap()
                .hybrid_sk,
            SECRET,
            "the migrated file must still load"
        );
    }

    #[test]
    fn write_secret_file_is_complete_and_restricted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("secret.bin");
        write_secret_file(&path, b"top secret").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"top secret");
        // No tmp file left behind after the atomic rename.
        assert!(!path.with_extension("tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn rekey_migrates_every_rms_derived_file() {
        let (_dir, store) = test_store();
        let old = Crypto::new(&[1u8; 32]);
        let new = Crypto::new(&[2u8; 32]);

        for file in [
            VAULT_FILE,
            "audit.enc",
            "shares.enc",
            "sync_conflicts.enc",
            "recovery_setup.enc",
        ] {
            let ciphertext = old.encrypt_vault(file.as_bytes()).unwrap();
            write_secret_file(&store.store_path().join(file), &ciphertext).unwrap();
        }
        store
            .save_identity_keys_full(&test_identity_keys(b"share-secret"), &old)
            .unwrap();

        store.rekey_secret_files(&old, &new).unwrap();

        for file in [
            VAULT_FILE,
            "audit.enc",
            "shares.enc",
            "sync_conflicts.enc",
            "recovery_setup.enc",
        ] {
            let ciphertext = fs::read(store.store_path().join(file)).unwrap();
            assert_eq!(
                new.decrypt_vault(&ciphertext).unwrap().as_slice(),
                file.as_bytes()
            );
            assert!(
                old.decrypt_vault(&ciphertext).is_err(),
                "{file} still opens under old RMS"
            );
        }
        assert_eq!(
            store.load_identity_keys(&new).unwrap().unwrap().hybrid_dk,
            b"hybrid-dk"
        );
        assert!(store.load_identity_keys(&old).is_err());
    }

    #[test]
    fn rms_migration_journal_recovers_from_either_key_and_mixed_files() {
        let (_dir, store) = test_store();
        let old_rms = [3u8; 32];
        let new_rms = [4u8; 32];
        let old = Crypto::new(&old_rms);
        let new = Crypto::new(&new_rms);

        store.begin_rms_migration(&old_rms, &new_rms, 7).unwrap();
        assert_eq!(
            store.load_rms_migration(&old_rms).unwrap(),
            Some((old_rms, new_rms, 7))
        );
        assert_eq!(
            store.load_rms_migration(&new_rms).unwrap(),
            Some((old_rms, new_rms, 7))
        );

        // Model a crash after only the first file reached the new key.
        write_secret_file(
            &store.store_path().join(VAULT_FILE),
            &new.encrypt_vault(b"vault").unwrap(),
        )
        .unwrap();
        write_secret_file(
            &store.store_path().join("audit.enc"),
            &old.encrypt_vault(b"audit").unwrap(),
        )
        .unwrap();

        store.rekey_secret_files(&old, &new).unwrap();
        for (file, expected) in [(VAULT_FILE, b"vault".as_slice()), ("audit.enc", b"audit")] {
            let ciphertext = fs::read(store.store_path().join(file)).unwrap();
            assert_eq!(new.decrypt_vault(&ciphertext).unwrap().as_slice(), expected);
        }

        store.finish_rms_migration().unwrap();
        assert!(store.load_rms_migration(&new_rms).unwrap().is_none());
    }

    #[test]
    fn key_epoch_marker_is_authenticated_by_the_current_rms() {
        let (_dir, store) = test_store();
        let current = Crypto::new(&[8u8; 32]);
        let wrong = Crypto::new(&[9u8; 32]);

        assert_eq!(store.load_key_epoch(&current).unwrap(), None);
        store.save_key_epoch(&current, 6).unwrap();
        assert_eq!(store.load_key_epoch(&current).unwrap(), Some(6));
        assert!(store.load_key_epoch(&wrong).is_err());
    }
}
