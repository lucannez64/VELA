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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
}

pub struct Store {
    store_path: PathBuf,
}

impl Store {
    pub fn new() -> anyhow::Result<Self> {
        let project_dirs = ProjectDirs::from("com", "vela", "VELA")
            .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;

        let data_dir = project_dirs.data_dir().join(STORE_DIR);
        fs::create_dir_all(&data_dir)?;
        restrict_directory(&data_dir)?;

        Ok(Self {
            store_path: data_dir,
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

        let mut rms = [0u8; 32];
        rms.copy_from_slice(&plaintext[..32]);
        Ok(Some(rms))
    }

    pub fn has_existing_vault(&self) -> bool {
        self.store_path.join(RMS_FILE).exists() || self.store_path.join(VAULT_FILE).exists()
    }

    pub fn save_settings(
        &self,
        settings: &crate::commands::settings::Settings,
    ) -> anyhow::Result<()> {
        let settings_path = self.store_path.join(SETTINGS_FILE);

        if let Some(parent) = settings_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let json = serde_json::to_string_pretty(settings)?;
        write_secret_file(&settings_path, json.as_bytes())?;
        Ok(())
    }

    pub fn load_settings(&self) -> anyhow::Result<crate::commands::settings::Settings> {
        let settings_path = self.store_path.join(SETTINGS_FILE);

        if !settings_path.exists() {
            return Ok(crate::commands::settings::Settings::default());
        }

        let json = fs::read_to_string(settings_path)?;
        let settings: crate::commands::settings::Settings = serde_json::from_str(&json)?;
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
        self.save_identity_keys_full(hybrid_ek, hybrid_vk, hybrid_sk, &[], &[], crypto)
    }

    pub fn save_identity_keys_full(
        &self,
        hybrid_ek: &[u8],
        hybrid_vk: &[u8],
        hybrid_sk: &[u8],
        share_ek: &[u8],
        share_dk: &[u8],
        crypto: &Crypto,
    ) -> anyhow::Result<()> {
        let identity_path = self.store_path.join(IDENTITY_KEYS_FILE);

        if let Some(parent) = identity_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let store = IdentityKeysStore {
            hybrid_ek: hybrid_ek.to_vec(),
            hybrid_vk: hybrid_vk.to_vec(),
            hybrid_sk: hybrid_sk.to_vec(),
            share_ek: share_ek.to_vec(),
            share_dk: share_dk.to_vec(),
        };
        let plaintext = serde_json::to_vec(&store)?;
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
        let store: IdentityKeysStore = if bytes.first() == Some(&b'{') {
            // Legacy plaintext identity file (private signing keys in the
            // clear!). Load it, then immediately re-encrypt below — never
            // silently keep using plaintext.
            tracing::warn!(
                "Identity keys file is plaintext; migrating to encrypted format now"
            );
            serde_json::from_slice(&bytes)?
        } else {
            let key = Self::derive_identity_file_key(crypto);
            let plaintext = decrypt(&key, &bytes)?;
            serde_json::from_slice(&plaintext)?
        };
        self.save_identity_keys_full(
            &store.hybrid_ek,
            &store.hybrid_vk,
            &store.hybrid_sk,
            &store.share_ek,
            &store.share_dk,
            crypto,
        )?;
        Ok(Some(store))
    }
}

pub(crate) fn write_secret_file(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
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
