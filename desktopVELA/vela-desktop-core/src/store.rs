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

    pub fn save_settings(
        &self,
        settings: &crate::settings::Settings,
    ) -> anyhow::Result<()> {
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

        store.save_device_id_with_user_id("dev-x", "user-y").unwrap();
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
        assert_ne!(raw.first(), Some(&b'{'), "identity keys must not be plaintext");

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

        assert!(!store.take_plaintext_identity_migration(), "nothing migrated yet");
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
            assert!(attempts < 10_000, "never produced a nonce starting with '{{'");
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
            store.load_identity_keys(&crypto).unwrap().unwrap().hybrid_sk,
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
}
