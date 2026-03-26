//! Persistent encrypted storage for VELA vault.

use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;
use vela_crypto::aead::{decrypt, encrypt};
use vela_crypto::kdf;

use crate::crypto::Crypto;
use crate::vault::VaultStore;

const STORE_DIR: &str = "vela";
const VAULT_FILE: &str = "vault.enc";
const RMS_FILE: &str = "rms.enc";
const SETTINGS_FILE: &str = "settings.json";
const DEVICE_ID_FILE: &str = "device_id.json";
const DEVICE_KEY_CONTEXT: &str = "vela device rms protection v1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeviceIdStore {
    device_id: String,
    user_id: String,
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

    pub fn save_vault(&self, vault: &VaultStore, crypto: &Crypto) -> anyhow::Result<()> {
        let plaintext = serde_json::to_vec(vault)?;
        tracing::info!("Vault plaintext size: {} bytes", plaintext.len());

        if let Ok(json_str) = std::str::from_utf8(&plaintext) {
            tracing::debug!(
                "Vault JSON (first 500 chars): {}",
                &json_str[..json_str.len().min(500)]
            );
        }

        let ciphertext = crypto.encrypt_vault(&plaintext)?;
        tracing::info!("Vault ciphertext size: {} bytes", ciphertext.len());

        let vault_path = self.store_path.join(VAULT_FILE);

        if let Some(parent) = vault_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        fs::write(&vault_path, ciphertext)?;
        tracing::info!("Vault saved to {:?}", vault_path);

        Ok(())
    }

    pub fn load_vault(&self, crypto: &Crypto) -> anyhow::Result<VaultStore> {
        let vault_path = self.store_path.join(VAULT_FILE);

        if !vault_path.exists() {
            tracing::info!("No vault file found, returning empty vault");
            return Ok(VaultStore::new());
        }

        let ciphertext = fs::read(&vault_path)?;
        tracing::info!("Vault file size: {} bytes", ciphertext.len());

        if ciphertext.len() < 40 {
            tracing::error!("Vault file too small: {} bytes", ciphertext.len());
            return Err(anyhow::anyhow!("Vault file corrupted: too small"));
        }

        let plaintext = crypto.decrypt_vault(&ciphertext)?;

        if let Ok(json_str) = std::str::from_utf8(&plaintext) {
            tracing::debug!(
                "Loaded vault JSON (first 500 chars): {}",
                &json_str[..json_str.len().min(500)]
            );
        }

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

        fs::write(rms_path, ciphertext)?;

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
        fs::write(settings_path, json)?;
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
        let device_path = self.store_path.join(DEVICE_ID_FILE);

        if let Some(parent) = device_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let store = DeviceIdStore {
            device_id: device_id.to_string(),
            user_id: format!("user-{}", &device_id[..8]),
        };
        let json = serde_json::to_string_pretty(&store)?;
        fs::write(device_path, json)?;
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
}

impl Default for Store {
    fn default() -> Self {
        Self::new().expect("Failed to create store")
    }
}
