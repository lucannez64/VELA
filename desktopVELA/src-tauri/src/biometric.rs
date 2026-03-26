use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use vela_crypto::{
    aead::{decrypt, encrypt},
    kdf,
};

static CACHED_RMS: OnceLock<[u8; 32]> = OnceLock::new();

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
                    if CACHED_RMS.set(rms).is_err() || CACHED_RMS.get().is_some() {
                        if let Some(cached) = CACHED_RMS.get() {
                            return BiometricAuthResult {
                                success: true,
                                error_message: None,
                                retry_count: None,
                                uses_password: false,
                            };
                        }
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

                        if CACHED_RMS.set(rms).is_err() {}

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
                    tracing::info!("RMS stored in TPM 2.0");
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

#[cfg(not(windows))]
pub mod default_biometric {
    use super::*;

    pub fn check_availability() -> BiometricEnrollmentStatus {
        BiometricEnrollmentStatus {
            enrolled: false,
            provider: BiometricProvider::None,
        }
    }

    pub fn authenticate() -> BiometricAuthResult {
        BiometricAuthResult {
            success: false,
            error_message: Some("No biometrics available on this platform".to_string()),
            retry_count: None,
            uses_password: false,
        }
    }

    pub fn store_rms(_rms: &[u8; 32]) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn has_stored_rms() -> bool {
        false
    }
}

pub fn check_enrollment() -> BiometricEnrollmentStatus {
    #[cfg(windows)]
    {
        windows_biometric::check_availability()
    }
    #[cfg(not(windows))]
    {
        default_biometric::check_availability()
    }
}

pub fn authenticate() -> BiometricAuthResult {
    #[cfg(windows)]
    {
        windows_biometric::authenticate()
    }
    #[cfg(not(windows))]
    {
        default_biometric::authenticate()
    }
}

pub fn store_rms(rms: &[u8; 32]) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_biometric::store_rms(rms)
    }
    #[cfg(not(windows))]
    {
        default_biometric::store_rms(rms)
    }
}

pub fn has_stored_rms() -> bool {
    #[cfg(windows)]
    {
        windows_biometric::has_stored_rms()
    }
    #[cfg(not(windows))]
    {
        default_biometric::has_stored_rms()
    }
}

pub fn delete_stored_rms() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_biometric::delete_stored_rms()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

pub fn get_cached_rms() -> Option<[u8; 32]> {
    CACHED_RMS.get().copied()
}

pub fn clear_cached_rms() {
    if let Some(rms) = CACHED_RMS.get() {
        let mut mutable_rms = *rms;
        for byte in &mut mutable_rms {
            *byte = 0;
        }
    }
}

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key_input = Vec::with_capacity(password.len() + salt.len());
    key_input.extend_from_slice(password.as_bytes());
    key_input.extend_from_slice(salt);
    kdf::derive(PASSWORD_KEY_CONTEXT, &key_input)
        .as_bytes()
        .clone()
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
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);

        let key = derive_key_from_password(password, &salt);
        let ciphertext = encrypt(&key, rms)?;

        let mut blob = Vec::with_capacity(16 + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&ciphertext);

        tracing::info!(
            "Storing password-encrypted RMS: salt len={}, ciphertext len={}, total blob len={}",
            salt.len(),
            ciphertext.len(),
            blob.len()
        );

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
            tracing::info!("Successfully stored VELA_RMS_PASSWORD credential");
            Ok(())
        }
    }

    pub fn authenticate_with_password(password: &str) -> Option<[u8; 32]> {
        tracing::info!("Attempting to authenticate with password");
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
                tracing::info!("Found VELA_RMS_PASSWORD credential");
                let cred = &*credential;
                if cred.CredentialBlobSize > 0 && !cred.CredentialBlob.is_null() {
                    let blob_size = cred.CredentialBlobSize as usize;
                    tracing::info!("Credential blob size: {}", blob_size);
                    let blob = std::slice::from_raw_parts(cred.CredentialBlob, blob_size);

                    if blob_size >= 48 {
                        let salt = &blob[0..16];
                        let ciphertext = &blob[16..];
                        tracing::info!("Extracted salt and ciphertext");

                        let key = derive_key_from_password(password, salt);
                        let Ok(decrypted) = decrypt(&key, ciphertext) else {
                            tracing::warn!("Decryption failed - wrong password?");
                            CredFree(credential as *mut _);
                            return None;
                        };

                        if decrypted.len() >= 32 {
                            tracing::info!("Successfully decrypted RMS");
                            let mut rms = [0u8; 32];
                            rms.copy_from_slice(&decrypted[..32]);
                            CredFree(credential as *mut _);

                            if CACHED_RMS.set(rms).is_ok() || CACHED_RMS.get().is_some() {
                                return CACHED_RMS.get().copied();
                            }
                        } else {
                            tracing::warn!("Decrypted data too short: {} bytes", decrypted.len());
                        }
                    } else {
                        tracing::warn!(
                            "Blob size too small: {} bytes (need at least 48)",
                            blob_size
                        );
                    }
                }
                CredFree(credential as *mut _);
            } else {
                tracing::warn!("VELA_RMS_PASSWORD credential not found");
            }
            None
        }
    }
}

#[cfg(not(windows))]
pub mod default_password {
    pub fn store_password_encrypted(_rms: &[u8; 32], _password: &str) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn authenticate_with_password(_password: &str) -> Option<[u8; 32]> {
        None
    }
}

pub fn store_password_encrypted(rms: &[u8; 32], password: &str) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_password::store_password_encrypted(rms, password)
    }
    #[cfg(not(windows))]
    {
        default_password::store_password_encrypted(rms, password)
    }
}

pub fn authenticate_with_password(password: &str) -> Option<[u8; 32]> {
    #[cfg(windows)]
    {
        windows_password::authenticate_with_password(password)
    }
    #[cfg(not(windows))]
    {
        default_password::authenticate_with_password(password)
    }
}
