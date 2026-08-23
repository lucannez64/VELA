use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use vela_crypto::{aead::decrypt, kdf, password_kdf};
use zeroize::Zeroize;

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
    FaceId,
    /// Optic ID (Vision Pro). Listed so the enum matches what
    /// `LAContext.biometryType` can report rather than mislabelling it.
    OpticId,
    /// Apple Watch confirmation — a real user-presence factor, but not biometry.
    AppleWatch,
    MasterPassword,
    LinuxTpm,
    LinuxFprint,
    LinuxSecretService,
    None,
}

/// Result of asking the user to prove they are there, right now.
///
/// Distinct from [BiometricAuthResult] because this proves *presence* and
/// nothing else: it never reads or caches the RMS. It exists for decisions that
/// are not unlocking — releasing a plaintext credential over IPC, say — where
/// reusing the unlock path would both be wrong and have the side effect of
/// caching a key.
#[derive(Debug, Clone, PartialEq)]
pub enum PresenceOutcome {
    Confirmed,
    /// The user said no, or the prompt failed. Carries something showable.
    Denied(String),
    /// This machine has no user-presence factor. Callers must decide what that
    /// means for them rather than reading it as either answer.
    Unavailable,
}

/// Ask the OS to confirm the user is present, with `reason` shown to them.
///
/// Blocking: it puts a system prompt on screen and waits. Call it off any
/// thread that must stay responsive.
pub fn verify_presence(reason: &str) -> PresenceOutcome {
    #[cfg(windows)]
    {
        windows_biometric::verify_presence_for(reason)
    }
    #[cfg(target_os = "macos")]
    {
        macos_biometric::verify_presence_for(reason)
    }
    #[cfg(target_os = "linux")]
    {
        linux_biometric::verify_presence_for(reason)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = reason;
        PresenceOutcome::Unavailable
    }
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

    /// Prove the user is present, for something other than unlocking.
    pub fn verify_presence_for(reason: &str) -> PresenceOutcome {
        if !hello_available() {
            return PresenceOutcome::Unavailable;
        }
        match prompt_user_presence(reason) {
            Ok(()) => PresenceOutcome::Confirmed,
            Err(message) => PresenceOutcome::Denied(message),
        }
    }

    /// Ask Windows Hello to verify the device owner.
    ///
    /// Reading the credential or the TPM-sealed key is not an authentication:
    /// both are handed to anything running in the user's session, so
    /// `authenticate()` used to report success without the user being present at
    /// all — the same gap the audit filed against macOS (D-3), and the reason
    /// the provider was reported as "Windows Hello" while Hello was never
    /// invoked. Nothing reads a key until this returns `Ok`.
    fn verify_user_presence() -> Result<(), String> {
        prompt_user_presence("Verify your identity to unlock your VELA vault")
    }

    fn prompt_user_presence(reason: &str) -> Result<(), String> {
        use windows::core::{factory, HSTRING};
        use windows::Foundation::IAsyncOperation;
        use windows::Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier,
        };
        use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

        let message = HSTRING::from(reason);

        // A non-packaged desktop app has to parent the prompt to a window of
        // its own, or it can end up behind the app (or refuse to show).
        let for_window = || -> windows::core::Result<UserConsentVerificationResult> {
            let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
            let hwnd = unsafe { GetForegroundWindow() };
            let operation: IAsyncOperation<UserConsentVerificationResult> =
                unsafe { interop.RequestVerificationForWindowAsync(hwnd, &message)? };
            operation.get()
        };

        let outcome = for_window().or_else(|_| {
            UserConsentVerifier::RequestVerificationAsync(&message).and_then(|op| op.get())
        });

        match outcome {
            Ok(UserConsentVerificationResult::Verified) => Ok(()),
            Ok(UserConsentVerificationResult::DeviceNotPresent) => Err(
                "Windows Hello is not set up on this device. Please use your master password."
                    .to_string(),
            ),
            Ok(UserConsentVerificationResult::NotConfiguredForUser) => Err(
                "Windows Hello is not configured for this account. Please use your master password."
                    .to_string(),
            ),
            Ok(UserConsentVerificationResult::DeviceBusy) => {
                Err("Windows Hello is busy. Try again in a moment.".to_string())
            }
            Ok(UserConsentVerificationResult::RetriesExhausted) => {
                Err("Too many failed Windows Hello attempts. Please use your master password."
                    .to_string())
            }
            Ok(UserConsentVerificationResult::Canceled) => {
                Err("Windows Hello was cancelled.".to_string())
            }
            Ok(_) => Err("Windows Hello could not verify you.".to_string()),
            Err(e) => Err(format!("Windows Hello failed: {}", e.message())),
        }
    }

    /// Whether Hello can verify the user right now (hardware present + enrolled).
    fn hello_available() -> bool {
        use windows::Security::Credentials::UI::{
            UserConsentVerifier, UserConsentVerifierAvailability,
        };
        matches!(
            UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.get()),
            Ok(UserConsentVerifierAvailability::Available)
        )
    }

    pub fn check_availability() -> BiometricEnrollmentStatus {
        // Report Windows Hello only when Hello can actually verify the user;
        // otherwise the stored key is a master-password vault, not a biometric
        // one, and the UI should say so.
        let hello = hello_available();

        if crate::device::tpm::is_tpm_key_available() {
            return BiometricEnrollmentStatus {
                enrolled: true,
                provider: if hello {
                    BiometricProvider::WindowsHello
                } else {
                    BiometricProvider::MasterPassword
                },
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
        // Verify the user *before* any key is read (audit D-3, Windows half).
        if let Err(message) = verify_user_presence() {
            return BiometricAuthResult {
                success: false,
                error_message: Some(message),
                retry_count: None,
                uses_password: false,
            };
        }

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

    pub fn has_platform_rms() -> bool {
        if crate::device::tpm::is_tpm_key_available() {
            return true;
        }
        unsafe {
            let target = to_wide_string(CREDENTIAL_NAME);
            let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
            let found = CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            )
            .is_ok();
            if !credential.is_null() {
                CredFree(credential as *mut _);
            }
            found
        }
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

    /// Drive a Secret Service future to completion from synchronous code.
    ///
    /// `secret-service` is built on zbus's async-io backend, so these futures
    /// need no tokio reactor — only somewhere to be polled. These functions are
    /// called from whatever thread happens to be handy: gpui's background
    /// executor, tokio's blocking pool, tokio worker threads, plain std
    /// threads. So drive the future on the calling thread, and only hand the
    /// thread back to tokio (via `block_in_place`) when we are actually sitting
    /// on a multi-threaded runtime worker. Reaching for `Handle::current()`
    /// here instead would panic on every non-tokio thread.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use tokio::runtime::{Handle, RuntimeFlavor};

        match Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                // The one place this is safe: we just proved we're on a
                // multi-threaded runtime, which is exactly what it requires.
                #[allow(clippy::disallowed_methods)]
                tokio::task::block_in_place(|| async_io::block_on(fut))
            }
            _ => async_io::block_on(fut),
        }
    }

    /// Retrieve the device-bound RMS from whichever store holds it (TPM
    /// first, then Secret Service). Callers must have verified the user
    /// first (fingerprint, or the master-password migration path): these
    /// stores gate on device possession and login session, NOT on user
    /// presence — no OS prompt is shown when they are read.
    pub(super) fn retrieve_rms_from_any_source() -> Option<[u8; 32]> {
        if tpm::is_tpm_available() && tpm::is_tpm_key_available() {
            if let Ok(rms) = tpm::retrieve_from_tpm() {
                return Some(rms);
            }
        }

        block_on(async {
            match secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await {
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
    }

    fn check_secret_service_sync() -> bool {
        block_on(async {
            secret_service::SecretService::connect(secret_service::EncryptionType::Dh)
                .await
                .is_ok()
        })
    }

    pub(super) fn secret_service_has_stored_item() -> bool {
        if !check_secret_service_sync() {
            return false;
        }
        block_on(async {
            match secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await {
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
    }

    pub fn check_availability() -> BiometricEnrollmentStatus {
        // A fingerprint verify is the only Linux path that actually proves
        // the user's presence. TPM-sealed keys and Secret Service items are
        // STORAGE, not verification: the OS shows no prompt when they are
        // read, so reporting them as an enrolled biometric makes every UI
        // layer auto-trigger a "biometric" unlock that silently succeeds for
        // anyone who opens the app. They only count below as evidence that a
        // master password can be offered (see authenticate_with_password).
        if tpm::fprint::is_fprint_available() && tpm::fprint::has_enrolled_fingers() {
            return BiometricEnrollmentStatus {
                enrolled: true,
                provider: BiometricProvider::LinuxFprint,
            };
        }

        // Any stored credential means the vault can be opened with the
        // master password: the Argon2id blob directly; a TPM/keyring-stored
        // key via the one-time migration in authenticate_with_password.
        if tpm::fallback::is_fallback_available()
            || tpm::is_tpm_key_available()
            || secret_service_has_stored_item()
        {
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

    /// Prove the user is present, for something other than unlocking.
    ///
    /// Linux has no general user-presence API, so this is fprintd or nothing: a
    /// reader with enrolled fingers, or `Unavailable`.
    ///
    /// There used to be a polkit fallback here for machines without a reader.
    /// It asked the user's own desktop agent for the account password on every
    /// release — a password prompt in front of filling a password — and it
    /// gated less than it appeared to: the dialog text came from the `.policy`
    /// file, so the `reason` below was dropped and the prompt never said who
    /// was asking. Malware only had to time its request to a fill the user had
    /// just clicked, and the user approved it themselves. The one thing it did
    /// buy — no drain off an idle machine — the session auto-lock already
    /// provides, so it was removed rather than made optional.
    ///
    /// The same blind-prompt caveat applies to fprintd below. It is kept
    /// because it is a swipe rather than a password, it is already there, and
    /// it still costs an attacker the idle machine.
    pub fn verify_presence_for(reason: &str) -> PresenceOutcome {
        let _ = reason; // fprintd renders its own prompt.
        if tpm::fprint::is_fprint_available() && tpm::fprint::has_enrolled_fingers() {
            return match tpm::fprint::verify() {
                Ok(()) => PresenceOutcome::Confirmed,
                Err(e) => PresenceOutcome::Denied(format!("Fingerprint verification failed: {e}")),
            };
        }
        PresenceOutcome::Unavailable
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

        // No fingerprint reader (or no enrolled fingers): there is no Linux
        // path that verifies the user, so there is nothing to authenticate
        // against here. Reading the TPM-sealed or keyring-stored key without
        // a verify is NOT an authentication — those reads are ungated (the
        // seal has no auth policy; the keyring is unlocked at login), which
        // is what made the app unlock itself on launch for anyone.
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

        block_on(async {
            match secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await {
                Ok(ss) => match ss.get_default_collection().await {
                    Ok(collection) => {
                        let mut attrs = HashMap::new();
                        attrs.insert("label", SECRET_SERVICE_LABEL);
                        attrs.insert("application", "vela-desktop");

                        match collection
                            .create_item(
                                "VELA Root Master Seed",
                                attrs,
                                rms,
                                true,
                                "application/vnd.vela.rms",
                            )
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
    }

    pub fn has_stored_rms() -> bool {
        tpm::is_tpm_key_available()
            || secret_service_has_stored_item()
            || tpm::fallback::is_fallback_available()
    }

    pub fn has_platform_rms() -> bool {
        tpm::is_tpm_key_available() || secret_service_has_stored_item()
    }

    pub fn delete_stored_rms() -> anyhow::Result<()> {
        let _ = tpm::delete_tpm_key();

        block_on(async {
            match secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await {
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
        });

        let _ = tpm::fallback::delete_fallback();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub mod linux_password {
    use super::linux_biometric;
    use crate::device::tpm;

    pub fn store_password_encrypted(rms: &[u8; 32], password: &str) -> anyhow::Result<()> {
        // The Argon2id password blob is the ONLY store that lets a later
        // unlock actually verify the master password — always write it.
        // Previously a TPM machine kept only the TPM-sealed key and the
        // password was discarded, so "password unlock" unsealed the TPM key
        // without ever checking what was typed: any password opened the
        // vault.
        tpm::fallback::store_with_password(rms, password)?;

        // Best-effort second copy, sealed to the TPM: it is what the
        // fingerprint path retrieves after a successful verify on machines
        // that have both a reader and a TPM. Failure here only costs that
        // convenience — the password blob above is authoritative.
        if tpm::is_tpm_available() {
            if let Err(e) = tpm::store_in_tpm(rms) {
                tracing::warn!(
                    "TPM copy of the vault key failed (password blob is authoritative): {}",
                    e
                );
            }
        }
        Ok(())
    }

    pub fn authenticate_with_password(password: &str) -> Option<[u8; 32]> {
        // Normal path: verify the typed password against the Argon2id blob.
        // A wrong password fails the unwrap and returns None.
        if tpm::fallback::is_fallback_available() {
            return tpm::fallback::retrieve_with_password(password).ok();
        }

        // One-time migration: vaults created while the TPM short-circuit
        // existed have no password blob — the RMS is only sealed in the TPM
        // (or sitting in the keyring) and the password chosen at setup was
        // never recorded, so there is nothing to verify against. Retrieve
        // the device-bound key and seal it under the password just typed, so
        // every later unlock is verified for real. This trusts device
        // possession exactly once, which is strictly better than what it
        // replaces: those installs unlocked for anyone, silently, at launch.
        let rms = linux_biometric::retrieve_rms_from_any_source()?;
        match tpm::fallback::store_with_password(&rms, password) {
            Ok(()) => {
                tracing::info!("Vault key re-sealed under the master password (one-time migration)")
            }
            Err(e) => tracing::warn!(
                "Password verification blob could not be written; \
                 the next unlock will migrate again: {}",
                e
            ),
        }
        Some(rms)
    }
}

/// Run a platform backend probe, turning a panic into `fallback` instead of
/// letting it unwind out of the calling thread.
///
/// These entry points run on background threads where a panic is not
/// survivable: gpui's `background_spawn` closes the task, and the foreground
/// `.await` then panics with "Task polled after completion", taking the whole
/// app down. A misbehaving keyring/TPM/D-Bus backend should degrade to "no
/// biometrics available" — the master password path still works.
fn guard<T>(what: &str, f: impl FnOnce() -> T, fallback: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => {
            tracing::error!("biometric backend panicked during {what}; treating it as unavailable");
            fallback()
        }
    }
}

pub fn check_enrollment() -> BiometricEnrollmentStatus {
    guard(
        "enrollment check",
        check_enrollment_inner,
        BiometricEnrollmentStatus::default,
    )
}

fn check_enrollment_inner() -> BiometricEnrollmentStatus {
    #[cfg(windows)]
    {
        windows_biometric::check_availability()
    }
    #[cfg(target_os = "macos")]
    {
        macos_biometric::check_availability()
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

/// macOS: Touch ID / Face ID through LocalAuthentication.
///
/// The vault key sits in the Keychain under a user-presence ACL, but an ACL on
/// its own only makes macOS prompt *whenever something reads the item* — it is
/// not an authentication this app performs, and `authenticate()` used to report
/// success for what was really just a Keychain read (audit D-3). Here the app
/// asks LocalAuthentication to verify the device owner with biometrics, and then
/// hands that *same evaluated context* to the Keychain read via
/// `kSecUseAuthenticationContext`, so the user sees exactly one prompt and the
/// OS still enforces the ACL underneath.
#[cfg(target_os = "macos")]
pub mod macos_biometric {
    use super::*;
    use block2::StackBlock;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};
    use security_framework_sys::base::errSecSuccess;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecReturnData,
        kSecUseAuthenticationContext,
    };
    use security_framework_sys::keychain_item::SecItemCopyMatching;
    use std::ffi::c_void;
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::device::tpm::{parse_stored_key, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE};

    /// How long to wait for the user to answer the prompt.
    const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

    const REASON: &str = "unlock your VELA vault";

    /// What this Mac can actually verify the owner with.
    ///
    /// `DeviceOwnerAuthenticationWithBiometrics` already means "whatever biometry
    /// this device has" — Touch ID, Face ID or Optic ID — so the policy never
    /// hardcodes one. What the type is for is telling the truth in the UI and in
    /// error messages, and knowing when to fall back to the Apple Watch policy on
    /// Macs with no biometric sensor at all.
    #[derive(Clone, Copy, PartialEq)]
    enum Factor {
        Biometry(LABiometryType),
        Watch,
        None,
    }

    impl Factor {
        fn policy(self) -> Option<LAPolicy> {
            match self {
                Factor::Biometry(_) => Some(LAPolicy::DeviceOwnerAuthenticationWithBiometrics),
                Factor::Watch => Some(LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrWatch),
                Factor::None => None,
            }
        }

        fn provider(self) -> BiometricProvider {
            match self {
                Factor::Biometry(LABiometryType::FaceID) => BiometricProvider::FaceId,
                Factor::Biometry(LABiometryType::OpticID) => BiometricProvider::OpticId,
                Factor::Biometry(_) => BiometricProvider::TouchId,
                Factor::Watch => BiometricProvider::AppleWatch,
                Factor::None => BiometricProvider::None,
            }
        }

        fn name(self) -> &'static str {
            match self {
                Factor::Biometry(LABiometryType::FaceID) => "Face ID",
                Factor::Biometry(LABiometryType::OpticID) => "Optic ID",
                Factor::Biometry(_) => "Touch ID",
                Factor::Watch => "Apple Watch",
                Factor::None => "Biometric unlock",
            }
        }
    }

    /// Ask the OS what it can verify with, preferring biometry over the watch.
    fn available_factor() -> Factor {
        unsafe {
            let context = LAContext::new();
            if context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .is_ok()
            {
                let biometry = context.biometryType();
                if biometry != LABiometryType::None {
                    return Factor::Biometry(biometry);
                }
            }
            // No sensor (an Intel Mac, an external display setup): a paired,
            // unlocked Apple Watch on the wrist is still a presence proof, and
            // it is what macOS itself accepts for unlock and for keychain items.
            let context = LAContext::new();
            if context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrWatch)
                .is_ok()
            {
                return Factor::Watch;
            }
            Factor::None
        }
    }

    pub fn check_availability() -> BiometricEnrollmentStatus {
        // "Enrolled" means both halves are in place: a key to unlock, and a
        // biometric to unlock it with. Claiming Touch ID without the second is
        // how the old capability probe misled the UI.
        let factor = available_factor();
        if crate::device::tpm::is_tpm_key_available() && factor != Factor::None {
            return BiometricEnrollmentStatus {
                enrolled: true,
                provider: factor.provider(),
            };
        }
        // A key with no usable biometric (no Touch ID hardware, none enrolled,
        // or biometry locked out) is still openable — with the master password.
        if crate::device::tpm::is_tpm_key_available()
            || crate::device::tpm::has_unprotected_stored_rms()
            || default_password::has_stored_blob()
        {
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

    /// Prove the user is present, for something other than unlocking.
    ///
    /// Deliberately drops the evaluated `LAContext` instead of reusing it: this
    /// path must not be able to read a key, only to answer "is the owner here".
    pub fn verify_presence_for(reason: &str) -> PresenceOutcome {
        let factor = available_factor();
        if factor.policy().is_none() {
            return PresenceOutcome::Unavailable;
        }
        match evaluate_presence_with_reason(factor, reason) {
            Ok(_context) => PresenceOutcome::Confirmed,
            Err(message) => PresenceOutcome::Denied(message),
        }
    }

    /// Verify the device owner with whatever factor this Mac has, returning the
    /// evaluated context so the caller can read the Keychain without prompting
    /// a second time.
    fn evaluate_presence(factor: Factor) -> Result<Retained<LAContext>, String> {
        evaluate_presence_with_reason(factor, REASON)
    }

    fn evaluate_presence_with_reason(
        factor: Factor,
        reason: &str,
    ) -> Result<Retained<LAContext>, String> {
        let policy = factor
            .policy()
            .ok_or_else(|| "No biometric is available on this Mac.".to_string())?;
        let context = unsafe { LAContext::new() };
        unsafe {
            context
                .canEvaluatePolicy_error(policy)
                .map_err(|e| e.localizedDescription().to_string())?;
        }

        let reason = NSString::from_str(reason);
        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        let name = factor.name();
        let reply = StackBlock::new(move |granted: Bool, error: *mut NSError| {
            let outcome = if granted.as_bool() {
                Ok(())
            } else if error.is_null() {
                Err(format!("{name} was not confirmed"))
            } else {
                Err(unsafe { &*error }.localizedDescription().to_string())
            };
            // The receiver may be gone if we timed out; that is not an error.
            let _ = tx.send(outcome);
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply);
        }

        match rx.recv_timeout(PROMPT_TIMEOUT) {
            Ok(Ok(())) => Ok(context),
            Ok(Err(message)) => Err(message),
            Err(_) => Err(format!("{} prompt timed out", factor.name())),
        }
    }

    /// Read the RMS, reusing `context` so the ACL is satisfied by the evaluation
    /// the user already completed.
    fn retrieve_with_context(context: &Retained<LAContext>) -> Result<[u8; 32], String> {
        unsafe {
            // An LAContext is an Objective-C object, which CFDictionary stores
            // as any other CF type.
            let context_value: CFType =
                CFType::wrap_under_get_rule(Retained::as_ptr(context) as *const c_void as _);
            let query = CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFType::wrap_under_get_rule(kSecClassGenericPassword as _),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrService),
                    CFString::from(KEYCHAIN_SERVICE).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccount),
                    CFString::from(KEYCHAIN_ACCOUNT).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecReturnData),
                    CFBoolean::true_value().as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecUseAuthenticationContext),
                    context_value,
                ),
            ]);

            let mut item: *const c_void = std::ptr::null();
            let status = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut item);
            if status != errSecSuccess || item.is_null() {
                return Err(format!("Keychain read failed (OSStatus {status})"));
            }
            let data = CFData::wrap_under_create_rule(item as _);
            parse_stored_key(&data.to_vec()).map_err(|e| e.to_string())
        }
    }

    pub fn authenticate() -> BiometricAuthResult {
        if !crate::device::tpm::is_tpm_key_available() {
            // Fail closed on a pre-ACL item rather than reading it: that read
            // would prove nothing. One master-password unlock re-stores the key
            // under the ACL (`migrate_unprotected_stored_rms`), after which
            // Touch ID works.
            let message = if crate::device::tpm::has_unprotected_stored_rms() {
                "Biometric protection for this vault needs to be set up. Unlock with your \
                 master password once, then biometric unlock will work."
            } else {
                "No vault key in the Keychain. Please use your master password."
            };
            return BiometricAuthResult {
                success: false,
                error_message: Some(message.to_string()),
                retry_count: None,
                uses_password: false,
            };
        }

        let factor = available_factor();
        if factor == Factor::None {
            return BiometricAuthResult {
                success: false,
                error_message: Some(
                    "No biometric is available on this Mac. Please use your master password."
                        .to_string(),
                ),
                retry_count: None,
                uses_password: false,
            };
        }

        let context = match evaluate_presence(factor) {
            Ok(context) => context,
            Err(message) => {
                return BiometricAuthResult {
                    success: false,
                    error_message: Some(message),
                    retry_count: None,
                    uses_password: false,
                }
            }
        };

        match retrieve_with_context(&context) {
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
            Err(message) => BiometricAuthResult {
                success: false,
                error_message: Some(message),
                retry_count: None,
                uses_password: false,
            },
        }
    }
}

pub fn authenticate() -> BiometricAuthResult {
    guard("authentication", authenticate_inner, || {
        BiometricAuthResult {
            success: false,
            error_message: Some(
                "Biometric authentication is unavailable on this system. Please use your master \
             password."
                    .to_string(),
            ),
            retry_count: None,
            uses_password: false,
        }
    })
}

fn authenticate_inner() -> BiometricAuthResult {
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
        macos_biometric::authenticate()
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

/// Re-store the RMS under the OS's user-presence protection if the platform is
/// still holding an older, unprotected copy.
///
/// Only macOS has such a copy: items written before the user-presence ACL
/// existed are readable by anything running as the user. Call this after an
/// unlock that authenticated the user by other means (master password), which is
/// what makes the one unprotected read on the migration path acceptable. No-op
/// everywhere else.
pub fn migrate_unprotected_stored_rms(rms: &[u8; 32]) {
    #[cfg(target_os = "macos")]
    {
        if crate::device::tpm::has_unprotected_stored_rms() {
            match crate::device::tpm::store_in_tpm(rms) {
                Ok(()) => tracing::info!("Migrated Keychain RMS to a user-presence ACL"),
                Err(e) => tracing::warn!("Could not migrate the Keychain RMS: {e}"),
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = rms;
    }
}

pub fn has_stored_rms() -> bool {
    guard("stored-key probe", has_stored_rms_inner, || false)
}

fn has_stored_rms_inner() -> bool {
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

pub(crate) fn set_cached_rms(rms: [u8; 32]) {
    if let Ok(mut guard) = CACHED_RMS.lock() {
        if let Some(ref mut previous) = *guard {
            previous.zeroize();
        }
        *guard = Some(rms);
    }
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
            // A v2 blob opens fine but was sealed at the old, lower Argon2id
            // cost. Re-sealing on the way through upgrades it without asking
            // the user for anything — the same lazy path legacy blobs use.
            needs_migration: password_kdf::needs_reseal(blob),
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

    pub fn has_stored_blob() -> bool {
        unsafe {
            let target = to_wide_string(PASSWORD_CREDENTIAL_NAME);
            let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
            let found = CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            )
            .is_ok();
            if !credential.is_null() {
                CredFree(credential as *mut _);
            }
            found
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

    /// Whether a master-password blob exists, without reading or opening it.
    pub fn has_stored_blob() -> bool {
        password_file_path().exists()
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

/// Whether this installation has an RMS wrapper protected by the master
/// password. A rotation must update this wrapper as well as the OS-backed RMS,
/// or the next password unlock would recover the retired seed.
pub fn has_password_encrypted_rms() -> bool {
    #[cfg(windows)]
    {
        windows_password::has_stored_blob()
    }
    #[cfg(target_os = "linux")]
    {
        crate::device::tpm::fallback::is_fallback_available()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        default_password::has_stored_blob()
    }
}

/// Whether an RMS copy exists in an OS/device-backed store independently of
/// the master-password wrapper. Password-only Linux/macOS installations must
/// not be made to fail rotation merely because no such optional copy exists.
pub fn has_platform_stored_rms() -> bool {
    #[cfg(windows)]
    {
        windows_biometric::has_platform_rms()
    }
    #[cfg(target_os = "linux")]
    {
        linux_biometric::has_platform_rms()
    }
    #[cfg(target_os = "macos")]
    {
        crate::device::tpm::is_tpm_key_available()
            || crate::device::tpm::has_unprotected_stored_rms()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    /// Regression: the Secret Service probes run on gpui's background executor
    /// and on tokio's blocking pool, neither of which has an ambient tokio
    /// runtime. They used to reach for `Handle::current()`, which panicked the
    /// worker thread — and that panic killed the app, because the foreground
    /// task awaiting the now-closed task panicked in turn.
    ///
    /// Deliberately calls the backend directly rather than the public wrappers,
    /// which swallow panics and would hide the regression. `authenticate()` is
    /// left out on purpose: it can block on a real fingerprint prompt.
    #[test]
    fn secret_service_probes_run_without_a_tokio_runtime() {
        std::thread::spawn(|| {
            let _ = super::linux_biometric::check_availability();
            let _ = super::linux_biometric::has_stored_rms();
            // Called directly because the two public probes above may
            // short-circuit on a stored credential before ever reaching the
            // Secret Service check.
            let _ = super::linux_biometric::secret_service_has_stored_item();
        })
        .join()
        .expect("Secret Service probes must not panic off a tokio runtime");
    }
}
