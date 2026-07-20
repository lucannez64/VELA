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
        let mut signing_secret = [0u8; 32];
        getrandom::getrandom(&mut signing_secret).expect("OS random source unavailable");

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
        use std::io::Write;
        use std::process::Stdio;

        let b64_plaintext = STANDARD.encode(plaintext);

        // The secret is piped via stdin — never placed on the command line,
        // where it would be visible in `ps`/WMI process listings.
        let mut command = Command::new("powershell");
        let mut child = super::hide_command_window(command.args([
                "-NoProfile",
                "-Command",
                "$in = [Console]::In.ReadToEnd().Trim(); \
                 ConvertTo-SecureString -String $in -AsPlainText -Force | ConvertFrom-SecureString",
            ]))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to invoke PowerShell for TPM protection: {}", e))?;

        child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Failed to open PowerShell stdin"))?
            .write_all(b64_plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to write secret to PowerShell stdin: {}", e))?;
        drop(child.stdin.take());

        let output = child
            .wait_with_output()
            .map_err(|e| anyhow::anyhow!("Failed to wait for PowerShell: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("PowerShell TPM protection failed: {}", stderr);
        }

        let protected = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(protected.into_bytes())
    }

    fn unprotect_with_tpm(protected: &[u8]) -> anyhow::Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use std::io::Write;
        use std::process::Stdio;

        let protected_str = String::from_utf8_lossy(protected).trim().to_string();

        // The protected blob is piped via stdin, not the command line.
        let mut command = Command::new("powershell");
        let mut child = super::hide_command_window(command.args([
                "-NoProfile",
                "-Command",
                "$in = [Console]::In.ReadToEnd().Trim(); \
                 ConvertTo-SecureString $in | ForEach-Object { \
                   [Runtime.InteropServices.Marshal]::PtrToStringAuto( \
                     [Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }",
            ]))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to invoke PowerShell for TPM unprotection: {}", e))?;

        child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Failed to open PowerShell stdin"))?
            .write_all(protected_str.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to write to PowerShell stdin: {}", e))?;
        drop(child.stdin.take());

        let output = child
            .wait_with_output()
            .map_err(|e| anyhow::anyhow!("Failed to wait for PowerShell: {}", e))?;

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
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    const KEYCHAIN_SERVICE: &str = "VELA_RMS_Store";
    const KEYCHAIN_ACCOUNT: &str = "vela-user";

    pub fn is_tpm_available() -> bool {
        is_secure_enclave_available()
    }

    pub fn is_tpm_key_available() -> bool {
        is_sec_key_available()
    }

    pub fn store_in_tpm(key: &[u8; 32]) -> anyhow::Result<()> {
        store_in_secure_enclave(key)
            .map_err(|e| anyhow::anyhow!("Failed to store in Secure Enclave: {}", e))
    }

    pub fn retrieve_from_tpm() -> anyhow::Result<[u8; 32]> {
        retrieve_from_secure_enclave()
            .map_err(|e| anyhow::anyhow!("Failed to retrieve from Secure Enclave: {}", e))
    }

    pub fn delete_tpm_key() -> anyhow::Result<()> {
        delete_from_secure_enclave()
    }

    fn is_secure_enclave_available() -> bool {
        let output = std::process::Command::new("sh")
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
        get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).is_ok()
    }

    // The RMS is passed to the Security framework in memory — it never
    // appears on a command line (unlike `security add-generic-password -w`).
    fn store_in_secure_enclave(key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        // Replace any existing item so behaviour matches the old `-U` update.
        let _ = delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
        set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key)?;
        Ok(())
    }

    fn retrieve_from_secure_enclave() -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let key = get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;

        if key.len() == 32 {
            let mut result = [0u8; 32];
            result.copy_from_slice(&key);
            return Ok(result);
        }

        // Legacy migration: older versions stored the RMS base64-encoded via
        // `security add-generic-password -w`. Decode and re-store as raw bytes.
        use base64::{engine::general_purpose::STANDARD, Engine};
        let b64 = String::from_utf8(key.clone())?;
        let decoded = STANDARD.decode(b64.trim())?;
        if decoded.len() != 32 {
            return Err(format!("Invalid key length: {}", key.len()).into());
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(&decoded);
        store_in_secure_enclave(&result)?;
        Ok(result)
    }

    fn delete_from_secure_enclave() -> anyhow::Result<()> {
        let _ = delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
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

    /// Private scratch directory (0700) for non-secret TPM context files.
    fn get_private_dir() -> std::path::PathBuf {
        let dir = get_data_dir().join("tpm-private");
        std::fs::create_dir_all(&dir).expect("Failed to create TPM private directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        dir
    }

    /// Overwrite a file with zeros before deleting it (best effort).
    fn shred_and_remove(path: &std::path::Path) {
        use std::io::Write;
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let zeros = vec![0u8; meta.len() as usize];
                let _ = f.write_all(&zeros);
                let _ = f.flush();
            }
        }
        let _ = std::fs::remove_file(path);
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
        let context_path = get_private_dir().join(TPM_CONTEXT_FILE);
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
        use std::io::Write;
        use std::process::Stdio;

        if !is_tpm_available() {
            anyhow::bail!("TPM 2.0 not available");
        }

        let context_path = create_primary_key()?;
        let sealed_path = get_sealed_blob_path();

        // The plaintext key is piped to tpm2_create via stdin (`-i -`) — no
        // plaintext RMS ever touches the filesystem.
        let mut child = Command::new("tpm2_create")
            .args([
                "-C",
                context_path.to_str().unwrap(),
                "-i",
                "-",
                "-u",
                sealed_path.with_extension("pub").to_str().unwrap(),
                "-r",
                sealed_path.with_extension("priv").to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to execute tpm2_create: {}", e))?;

        let stdin_result = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Failed to open tpm2_create stdin"))
            .and_then(|stdin| {
                stdin
                    .write_all(key)
                    .map_err(|e| anyhow::anyhow!("Failed to pipe key to tpm2_create: {}", e))
            });
        drop(child.stdin.take());
        if let Err(e) = stdin_result {
            let _ = child.kill();
            return Err(e);
        }

        let output = child
            .wait_with_output()
            .map_err(|e| anyhow::anyhow!("Failed to wait for tpm2_create: {}", e))?;

        if output.status.success() {
            std::fs::write(&sealed_path, b"sealed")?;
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to seal data to TPM: {}", stderr);
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
        let loaded_ctx = get_private_dir().join("loaded_key.ctx");

        let load_output = Command::new("tpm2_load")
            .args([
                "-C",
                context_path.to_str().unwrap(),
                "-u",
                pub_path.to_str().unwrap(),
                "-r",
                priv_path.to_str().unwrap(),
                "-c",
                loaded_ctx.to_str().unwrap(),
            ])
            .output();

        match load_output {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                shred_and_remove(&loaded_ctx);
                anyhow::bail!("Failed to load TPM key: {}", stderr);
            }
            Err(e) => {
                anyhow::bail!("Failed to execute tpm2_load: {}", e);
            }
            _ => {}
        }

        // Write the unsealed key to a temp file in the private (0700) dir, then
        // shred it immediately. We CANNOT use `-o -` here: tpm2_unseal's `-o`
        // flag treats `-` as a literal filename, not stdout — using it silently
        // drops the key and locks the user out.
        let unseal_out = get_private_dir().join("unsealed.tmp");
        let unseal_output = Command::new("tpm2_unseal")
            .args([
                "-c",
                loaded_ctx.to_str().unwrap(),
                "-o",
                unseal_out.to_str().unwrap(),
            ])
            .output();

        let data = match unseal_output {
            Ok(o) if o.status.success() => {
                let data = std::fs::read(&unseal_out);
                shred_and_remove(&unseal_out);
                data.unwrap_or_default()
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                shred_and_remove(&unseal_out);
                shred_and_remove(&loaded_ctx);
                anyhow::bail!("Failed to unseal TPM key: {}", stderr);
            }
            Err(e) => {
                shred_and_remove(&unseal_out);
                shred_and_remove(&loaded_ctx);
                anyhow::bail!("Failed to execute tpm2_unseal: {}", e);
            }
        };
        shred_and_remove(&loaded_ctx);

        if data.len() != 32 {
            anyhow::bail!("TPM unsealed key is not 32 bytes (got {})", data.len());
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&data);
        Ok(result)
    }

    pub fn delete_tpm_key() -> anyhow::Result<()> {
        let sealed_path = get_sealed_blob_path();
        let pub_path = sealed_path.with_extension("pub");
        let priv_path = sealed_path.with_extension("priv");
        let context_path = get_private_dir().join(TPM_CONTEXT_FILE);
        let loaded_ctx = get_private_dir().join("loaded_key.ctx");
        // Legacy locations from older versions.
        let legacy_context = get_tpm_context_path();
        let legacy_loaded_ctx = get_data_dir().join("loaded_key.ctx");
        let legacy_temps = [
            get_data_dir().join("tpm_input.tmp"),
            get_data_dir().join("tpm_output.tmp"),
        ];

        for path in [sealed_path, pub_path, priv_path, context_path, loaded_ctx] {
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
        }
        for path in [legacy_context, legacy_loaded_ctx] {
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
        }
        for path in legacy_temps {
            if path.exists() {
                shred_and_remove(&path);
            }
        }

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

        fn get_fallback_backup_path() -> PathBuf {
            get_data_dir().join("rms_software.enc.bak")
        }

        pub fn is_fallback_available() -> bool {
            get_fallback_key_path().exists()
        }

        /// Atomically write `blob` to the fallback path (tmp file + rename),
        /// then verify by reading it back. 0600 permissions throughout.
        fn write_blob_atomic(blob: &[u8]) -> anyhow::Result<()> {
            use std::os::unix::fs::PermissionsExt;

            let path = get_fallback_key_path();
            let tmp_path = get_data_dir().join("rms_software.enc.tmp");

            std::fs::write(&tmp_path, blob)?;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
            std::fs::rename(&tmp_path, &path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

            let verified = std::fs::read(&path)?;
            if verified != blob {
                anyhow::bail!("Fallback key file verification failed after write");
            }
            Ok(())
        }

        pub fn store_with_password(key: &[u8; 32], password: &str) -> anyhow::Result<()> {
            let blob = crate::biometric::seal_rms_with_password(key, password)?;
            write_blob_atomic(&blob)?;
            tracing::info!("Key stored with software encryption (Argon2id)");
            Ok(())
        }

        /// Legacy KDF variants retained ONLY to open pre-Argon2id blobs so they
        /// can be migrated. The legacy file layout is `salt16 ‖ ciphertext`.
        /// Two historical derivations are tried in turn:
        ///   1. two-step unsalted BLAKE3 (older Linux fallback writer), and
        ///   2. salted single-step BLAKE3 (the shared password helper).
        fn retrieve_legacy(password: &str, blob: &[u8]) -> anyhow::Result<[u8; 32]> {
            use vela_crypto::{aead::decrypt, kdf};

            if blob.len() < 48 {
                anyhow::bail!("Fallback key file too small");
            }
            let salt = &blob[0..16];
            let ciphertext = &blob[16..];

            let try_extract = |decrypted: &[u8]| -> Option<[u8; 32]> {
                if decrypted.len() >= 32 {
                    let mut result = [0u8; 32];
                    result.copy_from_slice(&decrypted[..32]);
                    Some(result)
                } else {
                    None
                }
            };

            // Variant 1: two-step unsalted BLAKE3.
            let key_material = kdf::derive("vela fallback key v1", password.as_bytes());
            let derived_key = kdf::derive("vela fallback encryption v1", key_material.as_bytes());
            if let Ok(decrypted) = decrypt(derived_key.as_bytes(), ciphertext) {
                if let Some(rms) = try_extract(&decrypted) {
                    return Ok(rms);
                }
            }

            // Variant 2: salted single-step BLAKE3 ("vela master password rms v1").
            #[allow(deprecated)]
            {
                let key = crate::biometric::derive_key_from_password_legacy(password, salt);
                if let Ok(decrypted) = decrypt(&key, ciphertext) {
                    if let Some(rms) = try_extract(&decrypted) {
                        return Ok(rms);
                    }
                }
            }

            anyhow::bail!("Could not unlock the software RMS blob with the supplied password");
        }

        /// Re-seal a legacy blob with Argon2id, keeping a backup of the old
        /// file until the new one is verified written. Best effort: failures
        /// are logged, never fatal — the legacy file still opens.
        fn migrate_legacy_blob(password: &str, rms: &[u8; 32], old_blob: &[u8]) {
            let path = get_fallback_key_path();
            let backup = get_fallback_backup_path();

            if let Err(e) = std::fs::write(&backup, old_blob) {
                tracing::warn!("RMS KDF migration: could not write backup: {}", e);
                return;
            }

            match crate::biometric::seal_rms_with_password(rms, password)
                .map_err(|e| e.into())
                .and_then(|blob| write_blob_atomic(&blob))
            {
                Ok(()) => {
                    // New file verified — the backup is no longer needed.
                    let _ = std::fs::remove_file(&backup);
                    tracing::info!("RMS software blob migrated to Argon2id KDF");
                }
                Err(e) => {
                    tracing::warn!(
                        "RMS KDF migration failed (legacy blob kept, backup retained): {}",
                        e
                    );
                }
            }
            let _ = path;
        }

        pub fn retrieve_with_password(password: &str) -> anyhow::Result<[u8; 32]> {
            let path = get_fallback_key_path();
            let blob = std::fs::read(&path)?;

            // Current format: versioned Argon2id blob (salt embedded and used).
            if vela_crypto::password_kdf::is_current_format(&blob) {
                let opened = crate::biometric::open_rms_with_password(password, &blob)
                    .ok_or_else(|| anyhow::anyhow!("Invalid password"))?;
                tracing::info!("Key retrieved from software encryption (Argon2id)");
                return Ok(opened.rms);
            }

            // Legacy format: unsalted BLAKE3 blob — open, then lazily migrate.
            let rms = retrieve_legacy(password, &blob)?;
            migrate_legacy_blob(password, &rms, &blob);

            tracing::info!("Key retrieved from software encryption (legacy, migrated)");
            Ok(rms)
        }

        pub fn delete_fallback() -> anyhow::Result<()> {
            let path = get_fallback_key_path();
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            let backup = get_fallback_backup_path();
            if backup.exists() {
                std::fs::remove_file(&backup)?;
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
