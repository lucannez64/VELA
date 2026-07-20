use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use vela_crypto::{aead::decrypt, kdf, password_kdf};

static CACHED_RMS: Mutex<Option<[u8; 32]>> = Mutex::new(None);

const PASSWORD_CREDENTIAL_NAME: &str = "VELA_RMS_PASSWORD";
const PASSWORD_KEY_CONTEXT: &str = "vela master password rms v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricAuthResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub retry_count: Option<u32>,
    pub uses_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricEnrollmentStatus {
    pub enrolled: bool,
    pub provider: BiometricProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BiometricProvider {
    WindowsHello,
    TouchId,
    MasterPassword,
    LinuxTpm,
    LinuxFprint,
    LinuxSecretService,
    None,
}

impl Default for BiometricEnrollmentStatus {
    fn default() -> Self {
        Self {
            enrolled: false,
            provider: BiometricProvider::None,
        }
    }
}

#[cfg(windows)]
pub mod windows_biometric {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::*;
    use windows::Win32::Security::Credentials::*;

    const CREDENTIAL_NAME: &str = "VELA_RMS";
    const TPM_CREDENTIAL_NAME: &str = "VELA_RMS_TPM";

    fn to_wide_string(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn to_wide_string_mut(s: &str) -> Vec<u16> {
        to_wide_string(s)
    }

    pub fn check_availability() -> BiometricEnrollmentStatus {
        if crate::device::tpm::is_tpm_key_available() {
            return BiometricEnrollmentStatus {
                enrolled: true,
                provider: BiometricProvider::WindowsHello,
            };
        }

        unsafe {
            let target = to_wide_string(CREDENTIAL_NAME);
            let mut credential: *mut CREDENTIALW = std::ptr::null_mut();

            if CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            )
            .is_ok()
            {
                if !credential.is_null() {
                    CredFree(credential as *mut _);
                }
                BiometricEnrollmentStatus {
                    enrolled: true,
                    provider: BiometricProvider::WindowsHello,
                }
            } else {
                let pwd_target = to_wide_string(PASSWORD_CREDENTIAL_NAME);
                let mut pwd_credential: *mut CREDENTIALW = std::ptr::null_mut();
                if CredReadW(
                    PCWSTR(pwd_target.as_ptr()),
                    CRED_TYPE_GENERIC,
                    0,
                    &mut pwd_credential,
                )
                .is_ok()
                {
                    if !pwd_credential.is_null() {
                        CredFree(pwd_credential as *mut _);
                    }
                    return BiometricEnrollmentStatus {
                        enrolled: true,
                        provider: BiometricProvider::MasterPassword,
                    };
                }
                BiometricEnrollmentStatus {
                    enrolled: false,
                    provider: BiometricProvider::None,
                }
            }
        }
    }

    pub fn authenticate() -> BiometricAuthResult {
        if crate::device::tpm::is_tpm_key_available() {
            match crate::device::tpm::retrieve_from_tpm() {
                Ok(rms) => {
                    if let Ok(mut guard) = CACHED_RMS.lock() {
                        *guard = Some(rms);
                    }
                    return BiometricAuthResult {
                        success: true,
                        error_message: None,
                        retry_count: None,
                        uses_password: false,
                    };
                }
                Err(e) => {
                    tracing::warn!(
                        "TPM retrieval failed, falling back to Credential Manager: {}",
                        e
                    );
                }
            }
        }

        unsafe {
            let target = to_wide_string(CREDENTIAL_NAME);
            let mut credential: *mut CREDENTIALW = std::ptr::null_mut();

            let result = CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            );

            if result.is_ok() && !credential.is_null() {
                let cred = &*credential;
                if cred.CredentialBlobSize > 0 && !cred.CredentialBlob.is_null() {
                    let blob_size = cred.CredentialBlobSize as usize;
                    let blob = std::slice::from_raw_parts(cred.CredentialBlob, blob_size);

                    if blob.len() >= 32 {
                        let mut rms = [0u8; 32];
                        rms.copy_from_slice(&blob[..32]);

                        if let Ok(mut guard) = CACHED_RMS.lock() {
                            *guard = Some(rms);
                        }

                        CredFree(credential as *mut _);
                        return BiometricAuthResult {
                            success: true,
                            error_message: None,
                            retry_count: None,
                            uses_password: false,
                        };
                    }
                }
                CredFree(credential as *mut _);
            }

            BiometricAuthResult {
                success: false,
                error_message: Some(
                    "No VELA vault found. Please set up your vault first.".to_string(),
                ),
                retry_count: None,
                uses_password: false,
            }
        }
    }

    pub fn store_rms(rms: &[u8; 32]) -> anyhow::Result<()> {
        if crate::device::tpm::is_tpm_available() {
            match crate::device::tpm::store_in_tpm(rms) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        "TPM storage failed, falling back to Credential Manager: {}",
                        e
                    );
                }
            }
        }

        unsafe {
            let mut target = to_wide_string_mut(CREDENTIAL_NAME);
            let mut username = to_wide_string_mut("VELA");

            let credential_blob = rms.as_slice();

            let cred = CREDENTIALW {
                Flags: CRED_FLAGS(0),
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target.as_mut_ptr()),
                Comment: PWSTR::null(),
                LastWritten: FILETIME::default(),
                CredentialBlobSize: credential_blob.len() as u32,
                CredentialBlob: credential_blob.as_ptr() as *mut u8,
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut(),
                TargetAlias: PWSTR::null(),
                UserName: PWSTR(username.as_mut_ptr()),
            };

            CredWriteW(&cred, 0)?;
            Ok(())
        }
    }

    pub fn has_stored_rms() -> bool {
        crate::device::tpm::is_tpm_key_available() || check_availability().enrolled
    }

    pub fn delete_stored_rms() -> anyhow::Result<()> {
        if crate::device::tpm::is_tpm_available() {
            let _ = crate::device::tpm::delete_tpm_key();
        }

        unsafe {
            let target = to_wide_string(CREDENTIAL_NAME);
            let _ = CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0);
            let pwd_target = to_wide_string(PASSWORD_CREDENTIAL_NAME);
            let _ = CredDeleteW(PCWSTR(pwd_target.as_ptr()), CRED_TYPE_GENERIC, 0);
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub mod linux_biometric {
    use super::*;
    use crate::device::tpm;
    use std::collections::HashMap;

    const SECRET_SERVICE_LABEL: &str = "VELA_RMS";

    fn retrieve_rms_from_any_source() -> Option<[u8; 32]> {
        if tpm::is_tpm_available() && tpm::is_tpm_key_available() {
            if let Ok(rms) = tpm::retrieve_from_tpm() {
                return Some(rms);
            }
        }

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                    .await
                {
                    Ok(ss) => match ss.get_default_collection().await {
                        Ok(collection) => {
                            let mut attrs = HashMap::new();
                            attrs.insert("label", SECRET_SERVICE_LABEL);
                            match collection.search_items(attrs).await {
                                Ok(items) => {
                                    if let Some(item) = items.first() {
                                        match item.get_secret().await {
                                            Ok(secret) => {
                                                if secret.len() >= 32 {
                                                    let mut rms = [0u8; 32];
                                                    rms.copy_from_slice(&secret[..32]);
                                                    return Some(rms);
                                                }
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
                None
            })
        })
    }

    fn check_secret_service_sync() -> bool {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                    .await
                    .is_ok()
            })
        })
    }

    pub fn check_availability() -> BiometricEnrollmentStatus {
        if tpm::fprint::is_fprint_available() && tpm::fprint::has_enrolled_fingers() {
            return BiometricEnrollmentStatus {
                enrolled: true,
                provider: BiometricProvider::LinuxFprint,
            };
        }

        if tpm::is_tpm_key_available() {
            return BiometricEnrollmentStatus {
                enrolled: true,
                provider: BiometricProvider::LinuxTpm,
            };
        }

        if check_secret_service_sync() {
            let enrolled = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    match secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                        .await
                    {
                        Ok(ss) => match ss.get_default_collection().await {
                            Ok(collection) => {
                                let mut attrs = HashMap::new();
                                attrs.insert("label", SECRET_SERVICE_LABEL);
                                let search = collection.search_items(attrs).await;
                                search.map(|items| !items.is_empty()).unwrap_or(false)
                            }
                            Err(_) => false,
                        },
                        Err(_) => false,
                    }
                })
            });

            if enrolled {
                return BiometricEnrollmentStatus {
                    enrolled: true,
                    provider: BiometricProvider::LinuxSecretService,
                };
            }
        }

        if tpm::fallback::is_fallback_available() {
            return BiometricEnrollmentStatus {
                enrolled: true,
                provider: BiometricProvider::MasterPassword,
            };
        }

        BiometricEnrollmentStatus {
            enrolled: false,
            provider: BiometricProvider::None,
        }
    }

    pub fn authenticate() -> BiometricAuthResult {
        if tpm::fprint::is_fprint_available() && tpm::fprint::has_enrolled_fingers() {
            match tpm::fprint::verify() {
                Ok(()) => {
                    if let Some(rms) = retrieve_rms_from_any_source() {
                        if let Ok(mut guard) = CACHED_RMS.lock() {
                            *guard = Some(rms);
                        }
                        return BiometricAuthResult {
                            success: true,
                            error_message: None,
                            retry_count: None,
                            uses_password: false,
                        };
                    }
                    return BiometricAuthResult {
                        success: false,
                        error_message: Some(
                            "Fingerprint matched but no vault data found".to_string(),
                        ),
                        retry_count: None,
                        uses_password: false,
                    };
                }
                Err(e) => {
                    return BiometricAuthResult {
                        success: false,
                        error_message: Some(format!("Fingerprint verification failed: {}", e)),
                        retry_count: None,
                        uses_password: false,
                    };
                }
            }
        }

        BiometricAuthResult {
            success: false,
            error_message: Some("No biometric available. Please use master password.".to_string()),
            retry_count: None,
            uses_password: false,
        }
    }

    pub fn store_rms(rms: &[u8; 32]) -> anyhow::Result<()> {
        if tpm::is_tpm_available() {
            match tpm::store_in_tpm(rms) {
                Ok(_) => {
                    return Ok(());
                }
                Err(_) => {}
            }
        }

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await {
                    Ok(ss) => match ss.get_default_collection().await {
                        Ok(collection) => {
                            let mut attrs = HashMap::new();
                            attrs.insert("label", SECRET_SERVICE_LABEL);
                            attrs.insert("application", "vela-desktop");

                            match collection
                                .create_item("VELA Root Master Seed", attrs, rms, true, "application/vnd.vela.rms")
                                .await
                            {
                                Ok(_) => {
                                    return Ok(());
                                }
                                Err(e) => {
                                    tracing::warn!("Secret Service storage failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to get default collection: {}", e);
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to connect to Secret Service: {}", e);
                    }
                }

                Err(anyhow::anyhow!(
                    "No secure storage available on Linux. Please install tpm2-tools for TPM support, \
                     or ensure GNOME Keyring/KWallet is running for Secret Service support."
                ))
            })
        })
    }

    pub fn has_stored_rms() -> bool {
        if tpm::is_tpm_key_available() {
            return true;
        }

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                    .await
                {
                    Ok(ss) => match ss.get_default_collection().await {
                        Ok(collection) => {
                            let mut attrs = HashMap::new();
                            attrs.insert("label", SECRET_SERVICE_LABEL);
                            match collection.search_items(attrs).await {
                                Ok(items) => {
                                    if !items.is_empty() {
                                        return true;
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
                false
            })
        }) || tpm::fallback::is_fallback_available()
    }

    pub fn delete_stored_rms() -> anyhow::Result<()> {
        let _ = tpm::delete_tpm_key();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                    .await
                {
                    Ok(ss) => match ss.get_default_collection().await {
                        Ok(collection) => {
                            let mut attrs = HashMap::new();
                            attrs.insert("label", SECRET_SERVICE_LABEL);
                            if let Ok(items) = collection.search_items(attrs).await {
                                for item in items {
                                    let _ = item.delete().await;
                                }
                            }
                        }
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
            })
        });

        let _ = tpm::fallback::delete_fallback();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub mod linux_password {
    use crate::device::tpm;

    pub fn store_password_encrypted(rms: &[u8; 32], password: &str) -> anyhow::Result<()> {
        if tpm::is_tpm_available() {
            return tpm::store_in_tpm(rms);
        }
        tpm::fallback::store_with_password(rms, password)
    }

    pub fn authenticate_with_password(password: &str) -> Option<[u8; 32]> {
        if tpm::is_tpm_key_available() {
            return tpm::retrieve_from_tpm().ok();
        }

        if tpm::fallback::is_fallback_available() {
            return tpm::fallback::retrieve_with_password(password).ok();
        }

        None
    }
}

pub fn check_enrollment() -> BiometricEnrollmentStatus {
    #[cfg(windows)]
    {
        windows_biometric::check_availability()
    }
    #[cfg(target_os = "macos")]
    {
        BiometricEnrollmentStatus {
            enrolled: crate::device::tpm::is_tpm_key_available(),
            provider: BiometricProvider::TouchId,
        }
    }
    #[cfg(target_os = "linux")]
    {
        linux_biometric::check_availability()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        BiometricEnrollmentStatus {
            enrolled: false,
            provider: BiometricProvider::None,
        }
    }
}

pub fn authenticate() -> BiometricAuthResult {
    #[cfg(windows)]
    {
        windows_biometric::authenticate()
    }
    #[cfg(target_os = "linux")]
    {
        linux_biometric::authenticate()
    }
    #[cfg(target_os = "macos")]
    {
        // macOS has no Touch ID integration yet; the honest capability is a
        // Keychain read, which is gated by the OS keychain ACL prompt. The
        // enrollment probe below reports exactly this capability.
        match crate::device::tpm::retrieve_from_tpm() {
            Ok(rms) => {
                if let Ok(mut guard) = CACHED_RMS.lock() {
                    *guard = Some(rms);
                }
                BiometricAuthResult {
                    success: true,
                    error_message: None,
                    retry_count: None,
                    uses_password: false,
                }
            }
            Err(_) => BiometricAuthResult {
                success: false,
                error_message: Some(
                    "No vault key in Keychain. Please use your master password.".to_string(),
                ),
                retry_count: None,
                uses_password: false,
            },
        }
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        BiometricAuthResult {
            success: false,
            error_message: Some("No biometrics available on this platform".to_string()),
            retry_count: None,
            uses_password: false,
        }
    }
}

pub fn store_rms(rms: &[u8; 32]) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_biometric::store_rms(rms)
    }
    #[cfg(target_os = "macos")]
    {
        crate::device::tpm::store_in_tpm(rms)
    }
    #[cfg(target_os = "linux")]
    {
        linux_biometric::store_rms(rms)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = rms;
        Ok(())
    }
}

pub fn has_stored_rms() -> bool {
    #[cfg(windows)]
    {
        windows_biometric::has_stored_rms()
    }
    #[cfg(target_os = "macos")]
    {
        crate::device::tpm::is_tpm_key_available()
    }
    #[cfg(target_os = "linux")]
    {
        linux_biometric::has_stored_rms()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

pub fn delete_stored_rms() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_biometric::delete_stored_rms()
    }
    #[cfg(target_os = "macos")]
    {
        crate::device::tpm::delete_tpm_key()
    }
    #[cfg(target_os = "linux")]
    {
        linux_biometric::delete_stored_rms()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Ok(())
    }
}

pub fn get_cached_rms() -> Option<[u8; 32]> {
    CACHED_RMS.lock().ok().and_then(|guard| *guard)
}

pub fn clear_cached_rms() {
    if let Ok(mut guard) = CACHED_RMS.lock() {
        if let Some(ref mut rms) = *guard {
            for byte in rms.iter_mut() {
                *byte = 0;
            }
        }
        *guard = None;
    }
}

/// LEGACY key derivation (unsalted-then-salted BLAKE3). Retained ONLY to open
/// password blobs written by older versions so they can be migrated to
/// Argon2id. Do not use for new blobs.
#[deprecated(note = "legacy BLAKE3 KDF kept only for reading pre-Argon2id blobs")]
pub fn derive_key_from_password_legacy(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key_input = Vec::with_capacity(password.len() + salt.len());
    key_input.extend_from_slice(password.as_bytes());
    key_input.extend_from_slice(salt);
    kdf::derive(PASSWORD_KEY_CONTEXT, &key_input)
        .as_bytes()
        .clone()
}

/// Seal the RMS under the master password using the current Argon2id format.
pub fn seal_rms_with_password(rms: &[u8; 32], password: &str) -> anyhow::Result<Vec<u8>> {
    Ok(password_kdf::seal_with_password(password.as_bytes(), rms)?)
}

/// Outcome of opening a password-sealed RMS blob.
pub struct OpenedRms {
    pub rms: [u8; 32],
    /// True when the blob used a legacy format and must be re-sealed with
    /// [`seal_rms_with_password`] (lazy migration, no user action required).
    pub needs_migration: bool,
}

/// Open a password-sealed RMS blob in any supported format.
///
/// Tries the current Argon2id format first, then the legacy salted-BLAKE3
/// layout (`salt16 ‖ ciphertext`). Returns `None` on wrong password/corruption.
pub fn open_rms_with_password(password: &str, blob: &[u8]) -> Option<OpenedRms> {
    if password_kdf::is_current_format(blob) {
        let plaintext = password_kdf::open_with_password(password.as_bytes(), blob).ok()?;
        if plaintext.len() < 32 {
            return None;
        }
        let mut rms = [0u8; 32];
        rms.copy_from_slice(&plaintext[..32]);
        return Some(OpenedRms {
            rms,
            needs_migration: false,
        });
    }

    // Legacy: 16-byte salt ‖ XChaCha20-Poly1305 ciphertext, BLAKE3 KDF.
    if blob.len() < 48 {
        return None;
    }
    let salt = &blob[0..16];
    let ciphertext = &blob[16..];
    #[allow(deprecated)]
    let key = derive_key_from_password_legacy(password, salt);
    let decrypted = decrypt(&key, ciphertext).ok()?;
    if decrypted.len() < 32 {
        return None;
    }
    let mut rms = [0u8; 32];
    rms.copy_from_slice(&decrypted[..32]);
    Some(OpenedRms {
        rms,
        needs_migration: true,
    })
}

#[cfg(windows)]
pub mod windows_password {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::*;
    use windows::Win32::Security::Credentials::*;

    fn to_wide_string(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn to_wide_string_mut(s: &str) -> Vec<u16> {
        to_wide_string(s)
    }

    pub fn store_password_encrypted(rms: &[u8; 32], password: &str) -> anyhow::Result<()> {
        let blob = seal_rms_with_password(rms, password)?;

        unsafe {
            let mut target = to_wide_string_mut(PASSWORD_CREDENTIAL_NAME);
            let mut username = to_wide_string_mut("VELA");

            let cred = CREDENTIALW {
                Flags: CRED_FLAGS(0),
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target.as_mut_ptr()),
                Comment: PWSTR::null(),
                LastWritten: FILETIME::default(),
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_ptr() as *mut u8,
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut(),
                TargetAlias: PWSTR::null(),
                UserName: PWSTR(username.as_mut_ptr()),
            };

            CredWriteW(&cred, 0)?;
            Ok(())
        }
    }

    pub fn authenticate_with_password(password: &str) -> Option<[u8; 32]> {
        unsafe {
            let target = to_wide_string(PASSWORD_CREDENTIAL_NAME);
            let mut credential: *mut CREDENTIALW = std::ptr::null_mut();

            let result = CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            );

            if result.is_ok() && !credential.is_null() {
                let cred = &*credential;
                if cred.CredentialBlobSize > 0 && !cred.CredentialBlob.is_null() {
                    let blob_size = cred.CredentialBlobSize as usize;
                    let blob = std::slice::from_raw_parts(cred.CredentialBlob, blob_size);

                    if let Some(opened) = open_rms_with_password(password, blob) {
                        CredFree(credential as *mut _);
                        if opened.needs_migration {
                            // Lazy migration: re-seal with Argon2id. Failure is
                            // non-fatal — the legacy blob still opens.
                            let _ = store_password_encrypted(&opened.rms, password);
                        }
                        if let Ok(mut guard) = CACHED_RMS.lock() {
                            *guard = Some(opened.rms);
                        }
                        return Some(opened.rms);
                    }
                }
                CredFree(credential as *mut _);
            }
            None
        }
    }
}

#[cfg(target_os = "macos")]
pub mod default_password {
    use super::*;

    const PASSWORD_FILE: &str = "password_recovery.bin";

    fn password_file_path() -> std::path::PathBuf {
        let project_dirs = directories::ProjectDirs::from("com", "vela", "VELA")
            .expect("Failed to determine data directory");
        let data_dir = project_dirs.data_dir().join("vela");
        std::fs::create_dir_all(&data_dir).ok();
        data_dir.join(PASSWORD_FILE)
    }

    pub fn store_password_encrypted(rms: &[u8; 32], password: &str) -> anyhow::Result<()> {
        let blob = seal_rms_with_password(rms, password)?;

        let path = password_file_path();
        std::fs::write(&path, &blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    pub fn authenticate_with_password(password: &str) -> Option<[u8; 32]> {
        let path = password_file_path();
        let blob = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                return None;
            }
        };

        let opened = open_rms_with_password(password, &blob)?;

        if opened.needs_migration {
            // Lazy migration: re-seal with Argon2id (non-fatal on failure).
            let _ = store_password_encrypted(&opened.rms, password);
        }

        if let Ok(mut guard) = CACHED_RMS.lock() {
            *guard = Some(opened.rms);
        }
        tracing::info!("Password authentication successful");
        Some(opened.rms)
    }
}

pub fn store_password_encrypted(rms: &[u8; 32], password: &str) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_password::store_password_encrypted(rms, password)
    }
    #[cfg(target_os = "linux")]
    {
        linux_password::store_password_encrypted(rms, password)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        default_password::store_password_encrypted(rms, password)
    }
}

pub fn authenticate_with_password(password: &str) -> Option<[u8; 32]> {
    #[cfg(windows)]
    {
        windows_password::authenticate_with_password(password)
    }
    #[cfg(target_os = "linux")]
    {
        linux_password::authenticate_with_password(password)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        default_password::authenticate_with_password(password)
    }
}
