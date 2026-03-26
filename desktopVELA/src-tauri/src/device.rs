use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: DeviceType,
    pub enrolled_at: chrono::DateTime<chrono::Utc>,
    pub last_active: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Desktop,
    Mobile,
    WebExtension,
}

impl DeviceInfo {
    pub fn new_desktop(name: String) -> Self {
        Self {
            device_id: Self::generate_device_id(),
            device_name: name,
            device_type: DeviceType::Desktop,
            enrolled_at: chrono::Utc::now(),
            last_active: Some(chrono::Utc::now()),
            revoked: false,
        }
    }

    pub fn generate_device_id() -> String {
        let machine_id = get_machine_unique_id();
        let mut hasher = Sha256::new();
        hasher.update(machine_id.as_bytes());
        let result = hasher.finalize();
        Uuid::from_bytes(result[..16].try_into().unwrap()).to_string()
    }

    pub fn mark_active(&mut self) {
        self.last_active = Some(chrono::Utc::now());
    }
}

#[cfg(windows)]
fn get_machine_unique_id() -> String {
    use std::process::Command;

    if let Ok(output) = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
        ])
        .output()
    {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
            return uuid;
        }
    }

    format!(
        "vela-desktop-{}-{}",
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
        std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string())
    )
}

#[cfg(target_os = "macos")]
fn get_machine_unique_id() -> String {
    use std::process::Command;

    if let Ok(output) = Command::new("sh")
        .args([
            "-c",
            "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID",
        ])
        .output()
    {
        let uuid = String::from_utf8_lossy(&output.stdout)
            .split('"')
            .nth(3)
            .unwrap_or("unknown")
            .to_string();
        if !uuid.is_empty() {
            return uuid;
        }
    }

    format!("vela-desktop-unknown")
}

#[cfg(not(any(windows, target_os = "macos")))]
fn get_machine_unique_id() -> String {
    format!(
        "vela-desktop-{}-{}",
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
        std::env::var("USER").unwrap_or_else(|_| "user".to_string())
    )
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct DeviceKeys {
    pub signing_secret: [u8; 32],
    pub signing_public: [u8; 32],
}

impl DeviceKeys {
    pub fn from_rms(rms: &[u8; 32]) -> Self {
        use vela_crypto::kdf;
        let identity_signing_key = kdf::derive("vela identity signing v1", rms);
        let signing_secret = *identity_signing_key.as_bytes();

        let mut hasher = Sha256::new();
        hasher.update(&signing_secret);
        let result = hasher.finalize();

        let mut signing_public = [0u8; 32];
        signing_public.copy_from_slice(&result[..32]);

        Self {
            signing_secret,
            signing_public,
        }
    }

    #[deprecated(since = "0.1.0", note = "Use from_rms() instead for RMS-derived keys")]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut signing_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut signing_secret);

        let mut hasher = Sha256::new();
        hasher.update(&signing_secret);
        let result = hasher.finalize();

        let mut signing_public = [0u8; 32];
        signing_public.copy_from_slice(&result[..32]);

        Self {
            signing_secret,
            signing_public,
        }
    }
}

#[cfg(windows)]
pub mod tpm {
    use std::process::Command;

    const TPM_KEY_FILE: &str = "rms.tpm";

    fn is_tpm_20_present() -> bool {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-Tpm).TpmPresent"])
            .output();
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout)
                .trim()
                .eq_ignore_ascii_case("true"),
            Err(_) => false,
        }
    }

    fn is_tpm_20_ready() -> bool {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-Tpm).TpmReady"])
            .output();
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout)
                .trim()
                .eq_ignore_ascii_case("true"),
            Err(_) => false,
        }
    }

    pub fn is_tpm_available() -> bool {
        is_tpm_20_present() && is_tpm_20_ready()
    }

    pub fn is_tpm_key_available() -> bool {
        if !is_tpm_available() {
            return false;
        }
        let encrypted_path = get_encrypted_rms_path();
        encrypted_path.exists()
    }

    fn get_encrypted_rms_path() -> std::path::PathBuf {
        let project_dirs = directories::ProjectDirs::from("com", "vela", "VELA")
            .expect("Failed to get project directories");
        let data_dir = project_dirs.data_dir().join("vela");
        std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");
        data_dir.join(TPM_KEY_FILE)
    }

    pub fn store_in_tpm(key: &[u8; 32]) -> anyhow::Result<()> {
        if !is_tpm_available() {
            anyhow::bail!("TPM 2.0 not available");
        }

        let protected_bytes = protect_with_tpm(key)?;

        let encrypted_path = get_encrypted_rms_path();
        std::fs::write(&encrypted_path, &protected_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to write TPM-protected key: {}", e))?;

        tracing::info!("RMS sealed to TPM 2.0 successfully");
        Ok(())
    }

    pub fn retrieve_from_tpm() -> anyhow::Result<[u8; 32]> {
        if !is_tpm_available() {
            anyhow::bail!("TPM 2.0 not available");
        }

        let encrypted_path = get_encrypted_rms_path();
        let protected_bytes = std::fs::read(&encrypted_path)
            .map_err(|e| anyhow::anyhow!("Failed to read TPM-protected key: {}", e))?;

        let key = unprotect_with_tpm(&protected_bytes)?;

        if key.len() != 32 {
            anyhow::bail!("TPM-protected key is not 32 bytes");
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&key);

        tracing::info!("RMS unsealed from TPM 2.0 successfully");
        Ok(result)
    }

    pub fn delete_tpm_key() -> anyhow::Result<()> {
        let encrypted_path = get_encrypted_rms_path();
        if encrypted_path.exists() {
            std::fs::remove_file(&encrypted_path)
                .map_err(|e| anyhow::anyhow!("Failed to delete TPM key file: {}", e))?;
        }
        Ok(())
    }

    fn protect_with_tpm(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let b64_plaintext = STANDARD.encode(plaintext);

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "ConvertTo-SecureString -String '{}' -AsPlainText -Force | ConvertFrom-SecureString",
                    b64_plaintext
                ),
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to invoke PowerShell for TPM protection: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("PowerShell TPM protection failed: {}", stderr);
        }

        let protected = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(protected.into_bytes())
    }

    fn unprotect_with_tpm(protected: &[u8]) -> anyhow::Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let protected_str = String::from_utf8_lossy(protected).trim().to_string();

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "ConvertTo-SecureString '{}' | ForEach-Object {{ [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }}",
                    protected_str
                ),
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to invoke PowerShell for TPM unprotection: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("PowerShell TPM unprotection failed: {}", stderr);
        }

        let b64_plaintext = String::from_utf8_lossy(&output.stdout).trim().to_string();
        STANDARD
            .decode(&b64_plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to decode base64 plaintext: {}", e))
    }
}

#[cfg(target_os = "macos")]
pub mod tpm {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::process::Command;

    pub fn is_tpm_available() -> bool {
        is_secure_enclave_available()
    }

    pub fn is_tpm_key_available() -> bool {
        is_sec_key_available()
    }

    pub fn store_in_tpm(key: &[u8; 32]) -> anyhow::Result<()> {
        store_in_secure_enclave(key, "VELA_RMS_Store")
            .map_err(|e| anyhow::anyhow!("Failed to store in Secure Enclave: {}", e))
    }

    pub fn retrieve_from_tpm() -> anyhow::Result<[u8; 32]> {
        retrieve_from_secure_enclave("VELA_RMS_Store")
            .map_err(|e| anyhow::anyhow!("Failed to retrieve from Secure Enclave: {}", e))
    }

    pub fn delete_tpm_key() -> anyhow::Result<()> {
        delete_from_secure_enclave("VELA_RMS_Store")
    }

    fn is_secure_enclave_available() -> bool {
        let output = Command::new("sh")
            .args(["-c", "ioreg -l | grep -c 'AppleSecureEnclave'"])
            .output();
        match output {
            Ok(out) => {
                let count = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse::<i32>()
                    .unwrap_or(0);
                count > 0
            }
            Err(_) => false,
        }
    }

    fn is_sec_key_available() -> bool {
        let result = Command::new("sh")
            .args(["-c", "security find-generic-password -s VELA_RMS_Store -w"])
            .output();
        matches!(result, Ok(o) if o.status.success())
    }

    fn store_in_secure_enclave(
        key: &[u8; 32],
        _service: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key_b64 = STANDARD.encode(key);

        let output = Command::new("sh")
            .args([
                "-c",
                &format!(
                    "security add-generic-password -a {} -s VELA_RMS_Store -w {} -U",
                    "vela-user", key_b64
                ),
            ])
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "Failed to store: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into())
        }
    }

    fn retrieve_from_secure_enclave(
        _service: &str,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let output = Command::new("sh")
            .args([
                "-c",
                "security find-generic-password -a vela-user -s VELA_RMS_Store -w",
            ])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to retrieve: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        let key_b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let key = STANDARD.decode(&key_b64)?;

        if key.len() != 32 {
            return Err(format!("Invalid key length: {}", key.len()).into());
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&key);
        Ok(result)
    }

    fn delete_from_secure_enclave(_service: &str) -> anyhow::Result<()> {
        Command::new("sh")
            .args([
                "-c",
                "security delete-generic-password -a vela-user -s VELA_RMS_Store",
            ])
            .output()
            .ok();
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
pub mod tpm {
    pub fn is_tpm_available() -> bool {
        false
    }

    pub fn is_tpm_key_available() -> bool {
        false
    }

    pub fn store_in_tpm(_key: &[u8; 32]) -> anyhow::Result<()> {
        anyhow::bail!("TPM/Secure Enclave not available on this platform")
    }

    pub fn retrieve_from_tpm() -> anyhow::Result<[u8; 32]> {
        anyhow::bail!("TPM/Secure Enclave not available on this platform")
    }

    pub fn delete_tpm_key() -> anyhow::Result<()> {
        Ok(())
    }
}
