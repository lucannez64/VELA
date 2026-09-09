//! Raw Windows WebAuthn plugin-authenticator ABI.
//!
//! Windows 11 (24H2 + KB5068861, finalized APIs in 26100/26200.8524 +
//! KB5089573) lets a third-party credential manager register as a *plugin
//! passkey authenticator*: the OS routes WebAuthn ceremonies it does not hold
//! to a COM object implementing `IPluginAuthenticator`, speaking CTAP2 CBOR.
//!
//! Microsoft publishes the ABI in the `microsoft/webauthn` repo
//! (`webauthnplugin.h`, `pluginauthenticator.idl`, `webauthn.h`) rather than
//! in the Windows SDK, and there is no import library — so every entry point
//! is resolved from `webauthn.dll` at runtime, and every struct here is a
//! hand-verified `#[repr(C)]` mirror of the C header. When bumping anything
//! in this file, diff against that repo's headers: the layouts are the
//! contract, and the OS will corrupt memory (not return an error) if we get
//! a field wrong.

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{BOOL, HWND};

// ── Constants (webauthnplugin.h / webauthn.h) ───────────────────────────────

pub const WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR: u32 = 0x01;

pub const WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
pub const WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION: u32 = 1;
pub const WEBAUTHN_CREDENTIAL_CURRENT_VERSION: u32 = 1;
pub const WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION: u32 = 8;
pub const WEBAUTHN_ASSERTION_CURRENT_VERSION: u32 = 6;
pub const WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS_CURRENT_VERSION: u32 = 1;

/// `L"public-key"` (webauthn.h).
pub const WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY: PCWSTR =
    PCWSTR::from_raw(w!("public-key").as_ptr());

/// `L"none"` (webauthn.h) — VELA emits self-attestation only.
pub const WEBAUTHN_ATTESTATION_TYPE_NONE: PCWSTR = PCWSTR::from_raw(w!("none").as_ptr());

use windows::core::w;

/// CTAP2 authenticatorGetAssertion/authenticatorMakeCredential error codes we
/// surface as HRESULTs. Values from winerror.h — the platform maps them onto
/// CTAP statuses for the browser.
pub mod hresult {
    /// Another ceremony is already in flight (ERROR_BUSY).
    pub const ERROR_BUSY: i32 = 0x8007_00AAu32 as i32; // HRESULT_FROM_WIN32(170)
    /// No credential for this RP (NTE_NOT_FOUND).
    pub const NTE_NOT_FOUND: i32 = 0x8009_0011u32 as i32;
    /// Unsupported algorithm / operation (NTE_NOT_SUPPORTED).
    pub const NTE_NOT_SUPPORTED: i32 = 0x8009_0029u32 as i32;
    /// The user said no (NTE_USER_CANCELLED) — Windows tells the RP "allowed
    /// but not completed", not an error, which is the only honest answer.
    pub const NTE_USER_CANCELLED: i32 = 0x8009_0036u32 as i32;
    /// Credential already registered (NTE_EXISTS).
    pub const NTE_EXISTS: i32 = 0x8009_000Fu32 as i32;
    /// Vault locked / keyset unavailable (NTE_BAD_KEYSET).
    pub const NTE_BAD_KEYSET: i32 = 0x8009_0016u32 as i32;
    /// The OS request signature did not verify (NTE_BAD_SIGNATURE).
    pub const NTE_BAD_SIGNATURE: i32 = 0x8009_0006u32 as i32;
    /// The caller cancelled via CancelOperation.
    pub const E_ABORT: i32 = 0x8000_0004u32 as i32;
    /// Generic failure.
    pub const E_FAIL: i32 = 0x8000_0005u32 as i32;
}

// ── Structs (webauthnplugin.h) ──────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WEBAUTHN_PLUGIN_OPERATION_REQUEST {
    pub hWnd: HWND,
    pub transactionId: GUID,
    pub cbRequestSignature: u32,
    pub pbRequestSignature: *mut u8,
    pub requestType: u32,
    pub cbEncodedRequest: u32,
    pub pbEncodedRequest: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
    pub cbEncodedResponse: u32,
    pub pbEncodedResponse: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST {
    pub transactionId: GUID,
    pub cbRequestSignature: u32,
    pub pbRequestSignature: *mut u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PLUGIN_LOCK_STATUS {
    PluginLocked = 0,
    PluginUnlocked = 1,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
    pub pwszAuthenticatorName: PCWSTR,
    pub rclsid: *const GUID,
    pub pwszPluginRpId: PCWSTR,
    pub pwszLightThemeLogoSvg: PCWSTR,
    pub pwszDarkThemeLogoSvg: PCWSTR,
    pub cbAuthenticatorInfo: u32,
    pub pbAuthenticatorInfo: *const u8,
    pub cSupportedRpIds: u32,
    pub ppwszSupportedRpIds: *const PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS {
    pub pwszAuthenticatorName: PCWSTR,
    pub rclsid: *const GUID,
    pub rclsidNew: *const GUID,
    pub pwszLightThemeLogoSvg: PCWSTR,
    pub pwszDarkThemeLogoSvg: PCWSTR,
    pub cbAuthenticatorInfo: u32,
    pub pbAuthenticatorInfo: *const u8,
    pub cSupportedRpIds: u32,
    pub ppwszSupportedRpIds: *const PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE {
    pub cbOpSignPubKey: u32,
    pub pbOpSignPubKey: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
    pub cbCredentialId: u32,
    pub pbCredentialId: *const u8,
    pub pwszRpId: PCWSTR,
    pub pwszRpName: PCWSTR,
    pub cbUserId: u32,
    pub pbUserId: *const u8,
    pub pwszUserName: PCWSTR,
    pub pwszUserDisplayName: PCWSTR,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS {
    pub dwVersion: u32,
    /// +1 = true, 0 = undefined, -1 = false.
    pub lUp: i32,
    pub lUv: i32,
    pub lRequireResidentKey: i32,
}

// ── Structs (webauthn.h, the decoded-CTAP view of requests) ─────────────────

#[repr(C)]
pub struct WEBAUTHN_RP_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub pwszId: PCWSTR,
    pub pwszName: PCWSTR,
    pub pwszIcon: PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_USER_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *mut u8,
    pub pwszName: PCWSTR,
    pub pwszIcon: PCWSTR,
    pub pwszDisplayName: PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    pub dwVersion: u32,
    pub pwszCredentialType: PCWSTR,
    pub lAlg: i32,
}

#[repr(C)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
    pub cCredentialParameters: u32,
    pub pCredentialParameters: *mut WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_EX {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *mut u8,
    pub pwszCredentialType: PCWSTR,
    pub dwTransports: u32,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_LIST {
    pub cCredentials: u32,
    pub ppCredentials: *mut *mut WEBAUTHN_CREDENTIAL_EX,
}

#[repr(C)]
pub struct WEBAUTHN_EXTENSIONS {
    pub cExtensions: u32,
    pub pExtensions: *mut std::ffi::c_void,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_ATTESTATION {
    pub dwVersion: u32,
    pub pwszFormatType: PCWSTR,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *mut u8,
    pub cbAttestation: u32,
    pub pbAttestation: *mut u8,
    pub dwAttestationDecodeType: u32,
    pub pvAttestationDecode: *mut std::ffi::c_void,
    pub cbAttestationObject: u32,
    pub pbAttestationObject: *mut u8,
    pub cbCredentialId: u32,
    pub pbCredentialId: *mut u8,
    // VERSION_2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    // VERSION_3
    pub dwUsedTransport: u32,
    // VERSION_4
    pub bEpAtt: BOOL,
    pub bLargeBlobSupported: BOOL,
    pub bResidentKey: BOOL,
    // VERSION_5
    pub bPrfEnabled: BOOL,
    // VERSION_6
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *mut u8,
    // VERSION_7
    pub pHmacSecret: *mut std::ffi::c_void,
    pub bThirdPartyPayment: BOOL,
    // VERSION_8
    pub dwTransports: u32,
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: *mut u8,
    pub cbRegistrationResponseJSON: u32,
    pub pbRegistrationResponseJSON: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *mut u8,
    pub pwszCredentialType: PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_ASSERTION {
    pub dwVersion: u32,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *mut u8,
    pub cbSignature: u32,
    pub pbSignature: *mut u8,
    pub Credential: WEBAUTHN_CREDENTIAL,
    pub cbUserId: u32,
    pub pbUserId: *mut u8,
    // VERSION_2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub cbCredLargeBlob: u32,
    pub pbCredLargeBlob: *mut u8,
    pub dwCredLargeBlobStatus: u32,
    // VERSION_3
    pub pHmacSecret: *mut std::ffi::c_void,
    // VERSION_4
    pub dwUsedTransport: u32,
    // VERSION_5
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *mut u8,
    // VERSION_6
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: *mut u8,
    pub cbAuthenticationResponseJSON: u32,
    pub pbAuthenticationResponseJSON: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST {
    pub dwVersion: u32,
    pub cbRpId: u32,
    pub pbRpId: *mut u8,
    pub cbClientDataHash: u32,
    pub pbClientDataHash: *mut u8,
    pub pRpInformation: *mut WEBAUTHN_RP_ENTITY_INFORMATION,
    pub pUserInformation: *mut WEBAUTHN_USER_ENTITY_INFORMATION,
    pub WebAuthNCredentialParameters: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    pub CredentialList: WEBAUTHN_CREDENTIAL_LIST,
    pub cbCborExtensionsMap: u32,
    pub pbCborExtensionsMap: *mut u8,
    pub pAuthenticatorOptions: *mut WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS,
    pub fEmptyPinAuth: BOOL,
    pub cbPinAuth: u32,
    pub pbPinAuth: *mut u8,
    pub lHmacSecretExt: i32,
    pub pHmacSecretMcExtension: *mut std::ffi::c_void,
    pub lPrfExt: i32,
    pub cbHmacSecretSaltValues: u32,
    pub pbHmacSecretSaltValues: *mut u8,
    pub dwCredProtect: u32,
    pub dwPinProtocol: u32,
    pub dwEnterpriseAttestation: u32,
    pub cbCredBlobExt: u32,
    pub pbCredBlobExt: *mut u8,
    pub lLargeBlobKeyExt: i32,
    pub dwLargeBlobSupport: u32,
    pub lMinPinLengthExt: i32,
    pub cbJsonExt: u32,
    pub pbJsonExt: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST {
    pub dwVersion: u32,
    pub pwszRpId: PCWSTR,
    pub cbRpId: u32,
    pub pbRpId: *mut u8,
    pub cbClientDataHash: u32,
    pub pbClientDataHash: *mut u8,
    pub CredentialList: WEBAUTHN_CREDENTIAL_LIST,
    pub cbCborExtensionsMap: u32,
    pub pbCborExtensionsMap: *mut u8,
    pub pAuthenticatorOptions: *mut WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS,
    pub fEmptyPinAuth: BOOL,
    pub cbPinAuth: u32,
    pub pbPinAuth: *mut u8,
    pub pHmacSaltExtension: *mut std::ffi::c_void,
    pub cbHmacSecretSaltValues: u32,
    pub pbHmacSecretSaltValues: *mut u8,
    pub dwPinProtocol: u32,
    pub lCredBlobExt: i32,
    pub lLargeBlobKeyExt: i32,
    pub dwCredLargeBlobOperation: u32,
    pub cbCredLargeBlobCompressed: u32,
    pub pbCredLargeBlobCompressed: *mut u8,
    pub dwCredLargeBlobOriginalSize: u32,
    pub cbJsonExt: u32,
    pub pbJsonExt: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
    pub WebAuthNAssertion: WEBAUTHN_ASSERTION,
    pub pUserInformation: *mut WEBAUTHN_USER_ENTITY_INFORMATION,
    pub dwNumberOfCredentials: u32,
    pub lUserSelected: i32,
    pub cbLargeBlobKey: u32,
    pub pbLargeBlobKey: *mut u8,
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *mut u8,
}

// ── webauthn.dll dynamic binding ────────────────────────────────────────────

type WebAuthNPluginAddAuthenticatorFn =
    unsafe extern "system" fn(*const WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS, *mut *mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE) -> i32;
type WebAuthNPluginUpdateAuthenticatorDetailsFn = unsafe extern "system" fn(*const WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS) -> i32;
type WebAuthNPluginFreeAddAuthenticatorResponseFn = unsafe extern "system" fn(*mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE);
type WebAuthNPluginRemoveAuthenticatorFn = unsafe extern "system" fn(*const GUID) -> i32;
type WebAuthNPluginGetAuthenticatorStateFn = unsafe extern "system" fn(*const GUID, *mut i32) -> i32;
type WebAuthNPluginAuthenticatorAddCredentialsFn = unsafe extern "system" fn(*const GUID, u32, *const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS) -> i32;
type WebAuthNPluginAuthenticatorRemoveCredentialsFn = unsafe extern "system" fn(*const GUID, u32, *const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS) -> i32;
type WebAuthNPluginAuthenticatorRemoveAllCredentialsFn = unsafe extern "system" fn(*const GUID) -> i32;
type WebAuthNPluginGetOperationSigningPublicKeyFn = unsafe extern "system" fn(*const GUID, *mut u32, *mut *mut u8) -> i32;
type WebAuthNPluginFreePublicKeyResponseFn = unsafe extern "system" fn(*mut u8);
type WebAuthNDecodeMakeCredentialRequestFn = unsafe extern "system" fn(u32, *const u8, *mut *mut WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST) -> i32;
type WebAuthNFreeDecodedMakeCredentialRequestFn = unsafe extern "system" fn(*mut WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST);
type WebAuthNEncodeMakeCredentialResponseFn = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION, *mut u32, *mut *mut u8) -> i32;
type WebAuthNDecodeGetAssertionRequestFn = unsafe extern "system" fn(u32, *const u8, *mut *mut WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST) -> i32;
type WebAuthNFreeDecodedGetAssertionRequestFn = unsafe extern "system" fn(*mut WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST);
type WebAuthNEncodeGetAssertionResponseFn = unsafe extern "system" fn(*const WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE, *mut u32, *mut *mut u8) -> i32;

/// Every `webauthn.dll` entry point this crate uses. Loaded once per process;
/// a missing export (old Windows build) disables the provider rather than
/// crashing the desktop.
#[derive(Clone, Copy)]
pub struct WebAuthn {
    pub plugin_add_authenticator: WebAuthNPluginAddAuthenticatorFn,
    pub plugin_update_authenticator_details: WebAuthNPluginUpdateAuthenticatorDetailsFn,
    pub plugin_free_add_authenticator_response: WebAuthNPluginFreeAddAuthenticatorResponseFn,
    pub plugin_remove_authenticator: WebAuthNPluginRemoveAuthenticatorFn,
    pub plugin_get_authenticator_state: WebAuthNPluginGetAuthenticatorStateFn,
    pub plugin_add_credentials: WebAuthNPluginAuthenticatorAddCredentialsFn,
    pub plugin_remove_credentials: WebAuthNPluginAuthenticatorRemoveCredentialsFn,
    pub plugin_remove_all_credentials: WebAuthNPluginAuthenticatorRemoveAllCredentialsFn,
    pub plugin_get_operation_signing_public_key: WebAuthNPluginGetOperationSigningPublicKeyFn,
    pub plugin_free_public_key_response: WebAuthNPluginFreePublicKeyResponseFn,
    pub decode_make_credential_request: WebAuthNDecodeMakeCredentialRequestFn,
    pub free_decoded_make_credential_request: WebAuthNFreeDecodedMakeCredentialRequestFn,
    pub encode_make_credential_response: WebAuthNEncodeMakeCredentialResponseFn,
    pub decode_get_assertion_request: WebAuthNDecodeGetAssertionRequestFn,
    pub free_decoded_get_assertion_request: WebAuthNFreeDecodedGetAssertionRequestFn,
    pub encode_get_assertion_response: WebAuthNEncodeGetAssertionResponseFn,
}

impl WebAuthn {
    /// Resolve all exports from `webauthn.dll`. `None` means the installed
    /// Windows predates the plugin API — the caller must treat the provider
    /// as unavailable, never as registered.
    pub fn load() -> Option<Self> {
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        use windows::core::{s, HSTRING};

        unsafe {
            let module = LoadLibraryW(&HSTRING::from("webauthn.dll")).ok()?;
            // Resolve one export; a missing symbol aborts the whole load so a
            // half-updated Windows can never hand us a partial provider.
            let l = |name: windows::core::PCSTR| -> Option<*const std::ffi::c_void> {
                let p = GetProcAddress(module, name)?;
                Some(p as *const std::ffi::c_void)
            };

            Some(Self {
                plugin_add_authenticator: std::mem::transmute(l(s!("WebAuthNPluginAddAuthenticator"))?),
                plugin_update_authenticator_details: std::mem::transmute(l(s!("WebAuthNPluginUpdateAuthenticatorDetails"))?),
                plugin_free_add_authenticator_response: std::mem::transmute(l(s!("WebAuthNPluginFreeAddAuthenticatorResponse"))?),
                plugin_remove_authenticator: std::mem::transmute(l(s!("WebAuthNPluginRemoveAuthenticator"))?),
                plugin_get_authenticator_state: std::mem::transmute(l(s!("WebAuthNPluginGetAuthenticatorState"))?),
                plugin_add_credentials: std::mem::transmute(l(s!("WebAuthNPluginAuthenticatorAddCredentials"))?),
                plugin_remove_credentials: std::mem::transmute(l(s!("WebAuthNPluginAuthenticatorRemoveCredentials"))?),
                plugin_remove_all_credentials: std::mem::transmute(l(s!("WebAuthNPluginAuthenticatorRemoveAllCredentials"))?),
                plugin_get_operation_signing_public_key: std::mem::transmute(l(s!("WebAuthNPluginGetOperationSigningPublicKey"))?),
                plugin_free_public_key_response: std::mem::transmute(l(s!("WebAuthNPluginFreePublicKeyResponse"))?),
                decode_make_credential_request: std::mem::transmute(l(s!("WebAuthNDecodeMakeCredentialRequest"))?),
                free_decoded_make_credential_request: std::mem::transmute(l(s!("WebAuthNFreeDecodedMakeCredentialRequest"))?),
                encode_make_credential_response: std::mem::transmute(l(s!("WebAuthNEncodeMakeCredentialResponse"))?),
                decode_get_assertion_request: std::mem::transmute(l(s!("WebAuthNDecodeGetAssertionRequest"))?),
                free_decoded_get_assertion_request: std::mem::transmute(l(s!("WebAuthNFreeDecodedGetAssertionRequest"))?),
                encode_get_assertion_response: std::mem::transmute(l(s!("WebAuthNEncodeGetAssertionResponse"))?),
            })
        }
    }
}

// ── CNG: verify the OS's request signature (webauthnplugin.h contract) ──────

/// Magic in the first DWORD of a `BCRYPT_RSAKEY_BLOB` for an RSA public key
/// (`BCRYPT_RSAPUBLIC_MAGIC`). Anything else is treated as an ECC public key,
/// which NCrypt verifies with no padding parameters.
const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5352;

/// Verify `signature` over SHA-256(`data`) using a CNG public-key blob.
///
/// This is the platform's own scheme: at registration the OS returns
/// `pbOpSignPubKey` and then signs every request buffer it sends the plugin.
/// Verifying it here is what stops a hostile local process from feeding the
/// provider a forged ceremony — the same reason the desktop checks the pipe
/// peer's kernel identity.
///
/// RSA keys are verified with PSS (SHA-256, 32-byte salt), matching the
/// sample's handling; ECC keys use the provider default.
pub fn verify_request_signature(
    data: &[u8],
    key_blob: &[u8],
    signature: &[u8],
) -> Result<(), i32> {
    use windows::Win32::Foundation::NTSTATUS;
    use windows::Win32::Security::Cryptography::{
        BCryptCreateHash, BCryptFinishHash, BCryptGetProperty, BCryptHashData,
        NCryptImportKey, NCryptOpenStorageProvider, NCryptVerifySignature,
        BCRYPT_HASH_HANDLE, BCRYPT_PSS_PADDING_INFO,
        BCRYPT_PUBLIC_KEY_BLOB, BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA256_ALGORITHM,
        NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    };

    const SHA256_LEN: usize = 32;

    /// bcrypt.dll reports errors as NTSTATUS; 0x8009xxxx security statuses
    /// arrive here too (e.g. a bad signature), so propagate the raw value.
    fn nt(status: NTSTATUS) -> Result<(), i32> {
        if status.0 >= 0 {
            Ok(())
        } else {
            Err(status.0)
        }
    }

    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        // Null provider name = the default (software) key storage provider,
        // exactly as the reference implementation does.
        NCryptOpenStorageProvider(&mut provider, windows::core::PCWSTR::null(), 0)
            .map_err(|e| e.code().0)?;

        let mut key = NCRYPT_KEY_HANDLE::default();
        NCryptImportKey(
            provider,
            NCRYPT_KEY_HANDLE::default(),
            BCRYPT_PUBLIC_KEY_BLOB,
            None,
            &mut key,
            key_blob,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| e.code().0)?;

        // Hash the request buffer. Hash object allocation is two-step: query
        // the object length, then create the hash into that scratch space.
        let mut obj_len_bytes = [0u8; 4];
        let mut written = 0u32;
        nt(BCryptGetProperty(
            BCRYPT_SHA256_ALG_HANDLE,
            windows::core::w!("ObjectLength"),
            Some(&mut obj_len_bytes),
            &mut written,
            0,
        ))?;
        let obj_len = u32::from_le_bytes(obj_len_bytes) as usize;
        if obj_len > 1 << 20 {
            return Err(hresult::E_FAIL);
        }

        let mut hash = BCRYPT_HASH_HANDLE::default();
        let mut obj = vec![0u8; obj_len];
        nt(BCryptCreateHash(
            BCRYPT_SHA256_ALG_HANDLE,
            &mut hash,
            Some(&mut obj),
            None,
            0,
        ))?;
        nt(BCryptHashData(hash, data, 0))?;

        let mut hash_len_bytes = [0u8; 4];
        nt(BCryptGetProperty(
            hash,
            windows::core::w!("HashDigestLength"),
            Some(&mut hash_len_bytes),
            &mut written,
            0,
        ))?;
        let hash_len = u32::from_le_bytes(hash_len_bytes) as usize;
        if hash_len != SHA256_LEN {
            return Err(hresult::E_FAIL);
        }

        let mut digest = vec![0u8; SHA256_LEN];
        nt(BCryptFinishHash(hash, &mut digest, 0))?;

        // RSA needs explicit PSS parameters; ECC takes the default path.
        let is_rsa = key_blob.len() >= 4
            && u32::from_le_bytes([key_blob[0], key_blob[1], key_blob[2], key_blob[3]])
                == BCRYPT_RSAPUBLIC_MAGIC;

        let result = if is_rsa {
            let padding = BCRYPT_PSS_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
                cbSalt: SHA256_LEN as u32,
            };
            NCryptVerifySignature(
                key,
                Some(&padding as *const BCRYPT_PSS_PADDING_INFO as *const std::ffi::c_void),
                &digest,
                signature,
                NCRYPT_SILENT_FLAG,
            )
        } else {
            NCryptVerifySignature(
                key,
                None,
                &digest,
                signature,
                NCRYPT_SILENT_FLAG,
            )
        };
        result.map_err(|e| e.code().0)
    }
}

// ── small helpers shared by callers ─────────────────────────────────────────

/// Read a null-terminated UTF-16 string at `p`, tolerating nulls as empty.
pub unsafe fn pwstr_to_string(p: PCWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(p.0, len);
    String::from_utf16_lossy(slice)
}

/// Hand out an owned wide string valid as a `PCWSTR` for `'static` usage —
/// only for string literals; use `PWSTR` allocations for runtime strings.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

