use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

#[cfg(windows)]
fn hide_command_window(command: &mut std::process::Command) -> &mut std::process::Command {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    command.creation_flags(CREATE_NO_WINDOW)
}

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

    let mut command = Command::new("powershell");
    if let Ok(output) = hide_command_window(command.args([
        "-NoProfile",
        "-Command",
        "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
    ]))
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
        let mut command = Command::new("powershell");
        let output = super::hide_command_window(command.args([
            "-NoProfile",
            "-Command",
            "(Get-Tpm).TpmPresent",
        ]))
        .output();
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout)
                .trim()
                .eq_ignore_ascii_case("true"),
            Err(_) => false,
        }
    }

    fn is_tpm_20_ready() -> bool {
        let mut command = Command::new("powershell");
        let output = super::hide_command_window(command.args([
            "-NoProfile",
            "-Command",
            "(Get-Tpm).TpmReady",
        ]))
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

        let mut command = Command::new("powershell");
        let output = super::hide_command_window(command.args([
                "-NoProfile",
                "-Command",
                &format!(
                    "ConvertTo-SecureString -String '{}' -AsPlainText -Force | ConvertFrom-SecureString",
                    b64_plaintext
                ),
            ]))
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

        let mut command = Command::new("powershell");
        let output = super::hide_command_window(command.args([
                "-NoProfile",
                "-Command",
                &format!(
                    "ConvertTo-SecureString '{}' | ForEach-Object {{ [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }}",
                    protected_str
                ),
            ]))
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

#[cfg(target_os = "linux")]
pub mod tpm {
    use std::path::PathBuf;
    use std::process::Command;

    const TPM_KEY_FILE: &str = "rms.tpm";
    const TPM_CONTEXT_FILE: &str = "tpm_context";
    const TPM_PERSISTENT_HANDLE: &str = "0x81000001";

    fn get_data_dir() -> std::path::PathBuf {
        let project_dirs = directories::ProjectDirs::from("com", "vela", "VELA")
            .expect("Failed to get project directories");
        let data_dir = project_dirs.data_dir().join("vela");
        std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");
        data_dir
    }

    fn get_sealed_blob_path() -> PathBuf {
        get_data_dir().join(TPM_KEY_FILE)
    }

    fn get_tpm_context_path() -> PathBuf {
        get_data_dir().join(TPM_CONTEXT_FILE)
    }

    fn check_tpm_device() -> bool {
        std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/dev/tpmrm0").exists()
    }

    fn check_tpm2_tools() -> bool {
        Command::new("tpm2_getcap")
            .args(["properties-fixed"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn is_tpm_available() -> bool {
        if !check_tpm_device() {
            tracing::debug!("TPM device not found (/dev/tpm0 or /dev/tpmrm0)");
            return false;
        }
        if !check_tpm2_tools() {
            tracing::debug!("tpm2-tools not available or TPM not ready");
            return false;
        }
        true
    }

    pub fn is_tpm_key_available() -> bool {
        if !is_tpm_available() {
            return false;
        }
        let sealed_path = get_sealed_blob_path();
        sealed_path.exists()
    }

    fn create_primary_key() -> anyhow::Result<PathBuf> {
        let context_path = get_tpm_context_path();
        let output = Command::new("tpm2_createprimary")
            .args([
                "-c",
                context_path.to_str().unwrap(),
                "-g",
                "sha256",
                "-G",
                "ecc",
            ])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                tracing::debug!("TPM primary key created");
                Ok(context_path)
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                anyhow::bail!("Failed to create TPM primary key: {}", stderr);
            }
            Err(e) => {
                anyhow::bail!("Failed to execute tpm2_createprimary: {}", e);
            }
        }
    }

    pub fn store_in_tpm(key: &[u8; 32]) -> anyhow::Result<()> {
        if !is_tpm_available() {
            anyhow::bail!("TPM 2.0 not available");
        }

        let context_path = create_primary_key()?;
        let sealed_path = get_sealed_blob_path();

        let temp_input = get_data_dir().join("tpm_input.tmp");
        std::fs::write(&temp_input, key)?;

        let output = Command::new("tpm2_create")
            .args([
                "-C",
                context_path.to_str().unwrap(),
                "-i",
                temp_input.to_str().unwrap(),
                "-u",
                sealed_path.with_extension("pub").to_str().unwrap(),
                "-r",
                sealed_path.with_extension("priv").to_str().unwrap(),
            ])
            .output();

        let _ = std::fs::remove_file(&temp_input);

        match output {
            Ok(o) if o.status.success() => {
                std::fs::write(&sealed_path, b"sealed")?;
                tracing::info!("RMS sealed to TPM 2.0 successfully");
                Ok(())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                anyhow::bail!("Failed to seal data to TPM: {}", stderr);
            }
            Err(e) => {
                anyhow::bail!("Failed to execute tpm2_create: {}", e);
            }
        }
    }

    pub fn retrieve_from_tpm() -> anyhow::Result<[u8; 32]> {
        if !is_tpm_available() {
            anyhow::bail!("TPM 2.0 not available");
        }

        let sealed_path = get_sealed_blob_path();
        let pub_path = sealed_path.with_extension("pub");
        let priv_path = sealed_path.with_extension("priv");

        if !pub_path.exists() || !priv_path.exists() {
            anyhow::bail!("TPM sealed key files not found");
        }

        let context_path = create_primary_key()?;

        let load_output = Command::new("tpm2_load")
            .args([
                "-C",
                context_path.to_str().unwrap(),
                "-u",
                pub_path.to_str().unwrap(),
                "-r",
                priv_path.to_str().unwrap(),
                "-c",
                get_data_dir().join("loaded_key.ctx").to_str().unwrap(),
            ])
            .output();

        match load_output {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                anyhow::bail!("Failed to load TPM key: {}", stderr);
            }
            Err(e) => {
                anyhow::bail!("Failed to execute tpm2_load: {}", e);
            }
            _ => {}
        }

        let unseal_output = Command::new("tpm2_unseal")
            .args([
                "-c",
                get_data_dir().join("loaded_key.ctx").to_str().unwrap(),
                "-o",
                get_data_dir().join("tpm_output.tmp").to_str().unwrap(),
            ])
            .output();

        let loaded_ctx = get_data_dir().join("loaded_key.ctx");
        let _ = std::fs::remove_file(&loaded_ctx);

        match unseal_output {
            Ok(o) if o.status.success() => {
                let output_path = get_data_dir().join("tpm_output.tmp");
                let data = std::fs::read(&output_path)?;
                let _ = std::fs::remove_file(&output_path);

                if data.len() != 32 {
                    anyhow::bail!("TPM unsealed key is not 32 bytes");
                }

                let mut result = [0u8; 32];
                result.copy_from_slice(&data);

                tracing::info!("RMS unsealed from TPM 2.0 successfully");
                Ok(result)
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                anyhow::bail!("Failed to unseal TPM key: {}", stderr);
            }
            Err(e) => {
                anyhow::bail!("Failed to execute tpm2_unseal: {}", e);
            }
        }
    }

    pub fn delete_tpm_key() -> anyhow::Result<()> {
        let sealed_path = get_sealed_blob_path();
        let pub_path = sealed_path.with_extension("pub");
        let priv_path = sealed_path.with_extension("priv");
        let context_path = get_tpm_context_path();
        let loaded_ctx = get_data_dir().join("loaded_key.ctx");

        for path in [sealed_path, pub_path, priv_path, context_path, loaded_ctx] {
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
        }

        tracing::info!("TPM sealed key deleted");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_check_tpm_device() {
            let _ = check_tpm_device();
        }

        #[test]
        fn test_is_tpm_available() {
            let available = is_tpm_available();
            if std::env::var("CI").is_ok() {
                assert!(!available, "TPM should not be available in CI");
            }
        }
    }

    pub mod fallback {
        use super::*;

        fn get_fallback_key_path() -> PathBuf {
            get_data_dir().join("rms_software.enc")
        }

        pub fn is_fallback_available() -> bool {
            get_fallback_key_path().exists()
        }

        pub fn store_with_password(key: &[u8; 32], password: &str) -> anyhow::Result<()> {
            use rand::RngCore;
            use vela_crypto::{aead::encrypt, kdf};

            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);

            let key_material = kdf::derive("vela fallback key v1", password.as_bytes());
            let derived_key = kdf::derive("vela fallback encryption v1", key_material.as_bytes());
            let ciphertext = encrypt(derived_key.as_bytes(), key)?;

            let mut blob = Vec::with_capacity(16 + ciphertext.len());
            blob.extend_from_slice(&salt);
            blob.extend_from_slice(&ciphertext);

            let path = get_fallback_key_path();
            std::fs::write(&path, &blob)?;

            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

            tracing::info!("Key stored with software encryption");
            Ok(())
        }

        pub fn retrieve_with_password(password: &str) -> anyhow::Result<[u8; 32]> {
            use vela_crypto::{aead::decrypt, kdf};

            let path = get_fallback_key_path();
            let blob = std::fs::read(&path)?;

            if blob.len() < 48 {
                anyhow::bail!("Fallback key file too small");
            }

            let salt = &blob[0..16];
            let ciphertext = &blob[16..];

            let key_material = kdf::derive("vela fallback key v1", password.as_bytes());
            let derived_key = kdf::derive("vela fallback encryption v1", key_material.as_bytes());
            let decrypted = decrypt(derived_key.as_bytes(), ciphertext)?;

            if decrypted.len() < 32 {
                anyhow::bail!("Decrypted data too short");
            }

            let mut result = [0u8; 32];
            result.copy_from_slice(&decrypted[..32]);

            tracing::info!("Key retrieved from software encryption");
            Ok(result)
        }

        pub fn delete_fallback() -> anyhow::Result<()> {
            let path = get_fallback_key_path();
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            Ok(())
        }
    }

    pub mod fprint {
        use std::process::Command;

        pub fn is_fprint_available() -> bool {
            Command::new("fprintd-list")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }

        pub fn has_enrolled_fingers() -> bool {
            let output = Command::new("fprintd-list").output();
            match output {
                Ok(o) if o.status.success() => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    stdout
                        .lines()
                        .any(|line| line.contains("has enrolled fingers"))
                }
                _ => false,
            }
        }

        pub fn verify() -> anyhow::Result<()> {
            let output = Command::new("fprintd-verify").output();

            match output {
                Ok(o) if o.status.success() => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    if stdout.contains("Verify result: verify-match") {
                        tracing::info!("Fingerprint verification successful");
                        Ok(())
                    } else {
                        anyhow::bail!("Fingerprint did not match")
                    }
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    anyhow::bail!("Fingerprint verification failed: {}", stderr.trim())
                }
                Err(e) => {
                    anyhow::bail!("Failed to run fprintd-verify: {}", e)
                }
            }
        }
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
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
